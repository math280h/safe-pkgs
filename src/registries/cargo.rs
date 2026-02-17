use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::registries::client::{
    PackageAdvisory, PackageRecord, PackageVersion, RegistryClient, RegistryEcosystem,
    RegistryError,
};
use crate::registries::osv::query_advisories;

const CRATES_IO_USER_AGENT: &str = "safe-pkgs/0.1.0";
const CRATES_PAGE_SIZE: usize = 100;

#[derive(Clone)]
pub struct CargoRegistryClient {
    http: Client,
    api_base_url: String,
    popular_names_cache: Arc<RwLock<Option<Vec<String>>>>,
}

impl CargoRegistryClient {
    pub fn new() -> Self {
        Self {
            http: Client::new(),
            api_base_url: "https://crates.io/api/v1".to_string(),
            popular_names_cache: Arc::new(RwLock::new(None)),
        }
    }
}

#[async_trait]
impl RegistryClient for CargoRegistryClient {
    fn ecosystem(&self) -> RegistryEcosystem {
        RegistryEcosystem::CratesIo
    }

    async fn fetch_package(&self, package: &str) -> Result<PackageRecord, RegistryError> {
        let url = format!(
            "{}/crates/{}",
            self.api_base_url.trim_end_matches('/'),
            package
        );
        let response = self
            .http
            .get(&url)
            .header("User-Agent", CRATES_IO_USER_AGENT)
            .send()
            .await
            .map_err(|e| RegistryError::Transport {
                message: format!("unable to query crates.io API: {e}"),
            })?;

        if response.status() == StatusCode::NOT_FOUND {
            return Err(RegistryError::NotFound {
                registry: "cargo",
                package: package.to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(RegistryError::Transport {
                message: format!("crates.io API returned status {}", response.status()),
            });
        }

        let body: CrateDetailResponse =
            response
                .json()
                .await
                .map_err(|e| RegistryError::InvalidResponse {
                    message: format!("failed to parse crates.io response JSON: {e}"),
                })?;

        let latest = body
            .krate
            .max_stable_version
            .filter(|version| !version.is_empty())
            .or(body.krate.max_version)
            .ok_or_else(|| RegistryError::InvalidResponse {
                message: "missing crate latest version".to_string(),
            })?;

        let versions = body
            .versions
            .into_iter()
            .map(|version| {
                let published = DateTime::parse_from_rfc3339(&version.created_at)
                    .ok()
                    .map(|value| value.with_timezone(&Utc));
                (
                    version.num.clone(),
                    PackageVersion {
                        version: version.num,
                        published,
                        // Cargo equivalent: yanked release should be avoided.
                        deprecated: version.yanked,
                        install_scripts: Vec::new(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        Ok(PackageRecord {
            name: package.to_string(),
            latest,
            publishers: Vec::new(),
            versions,
        })
    }

    async fn fetch_weekly_downloads(&self, package: &str) -> Result<Option<u64>, RegistryError> {
        let url = format!(
            "{}/crates/{}",
            self.api_base_url.trim_end_matches('/'),
            package
        );
        let response = self
            .http
            .get(&url)
            .header("User-Agent", CRATES_IO_USER_AGENT)
            .send()
            .await
            .map_err(|e| RegistryError::Transport {
                message: format!("unable to query crates.io API: {e}"),
            })?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(RegistryError::Transport {
                message: format!("crates.io API returned status {}", response.status()),
            });
        }

        let body: CrateDownloadsResponse =
            response
                .json()
                .await
                .map_err(|e| RegistryError::InvalidResponse {
                    message: format!("failed to parse crates.io response JSON: {e}"),
                })?;

        Ok(body.krate.recent_downloads)
    }

    async fn fetch_popular_package_names(
        &self,
        limit: usize,
    ) -> Result<Vec<String>, RegistryError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        {
            let cache_guard = self.popular_names_cache.read().await;
            if let Some(cached) = cache_guard.as_ref()
                && cached.len() >= limit
            {
                return Ok(cached.iter().take(limit).cloned().collect());
            }
        }

        let mut names = Vec::new();
        let mut page = 1usize;

        while names.len() < limit {
            let url = format!("{}/crates", self.api_base_url.trim_end_matches('/'));
            let per_page = CRATES_PAGE_SIZE.min(limit.saturating_sub(names.len()));
            let response = self
                .http
                .get(&url)
                .header("User-Agent", CRATES_IO_USER_AGENT)
                .query(&[
                    ("page", page.to_string()),
                    ("per_page", per_page.to_string()),
                    ("sort", "downloads".to_string()),
                ])
                .send()
                .await
                .map_err(|e| RegistryError::Transport {
                    message: format!("unable to query crates.io popular crates index: {e}"),
                })?;

            if !response.status().is_success() {
                return Err(RegistryError::Transport {
                    message: format!(
                        "crates.io popular crates index returned status {}",
                        response.status()
                    ),
                });
            }

            let body: CratesListResponse =
                response
                    .json()
                    .await
                    .map_err(|e| RegistryError::InvalidResponse {
                        message: format!("failed to parse crates.io list response JSON: {e}"),
                    })?;

            if body.crates.is_empty() {
                break;
            }

            for krate in body.crates {
                names.push(krate.id);
                if names.len() >= limit {
                    break;
                }
            }

            page = page.saturating_add(1);
        }

        if names.is_empty() {
            return Err(RegistryError::InvalidResponse {
                message: "crates.io popular crates index returned no crate names".to_string(),
            });
        }

        let mut cache_guard = self.popular_names_cache.write().await;
        *cache_guard = Some(names.clone());

        Ok(names.into_iter().take(limit).collect())
    }

    async fn fetch_advisories(
        &self,
        package: &str,
        version: &str,
    ) -> Result<Vec<PackageAdvisory>, RegistryError> {
        query_advisories(package, version, self.ecosystem()).await
    }
}

#[derive(Debug, Deserialize)]
struct CrateDetailResponse {
    #[serde(rename = "crate")]
    krate: CrateSummary,
    #[serde(default)]
    versions: Vec<CrateVersion>,
}

#[derive(Debug, Deserialize)]
struct CrateDownloadsResponse {
    #[serde(rename = "crate")]
    krate: CrateSummary,
}

#[derive(Debug, Deserialize)]
struct CrateSummary {
    max_stable_version: Option<String>,
    max_version: Option<String>,
    recent_downloads: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct CrateVersion {
    num: String,
    created_at: String,
    yanked: bool,
}

#[derive(Debug, Deserialize)]
struct CratesListResponse {
    #[serde(default)]
    crates: Vec<CrateListItem>,
}

#[derive(Debug, Deserialize)]
struct CrateListItem {
    id: String,
}
