use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::registries::client::{
    PackageAdvisory, PackageRecord, PackageVersion, RegistryClient, RegistryEcosystem,
    RegistryError, reqwest_transport_error,
};
use crate::registries::osv::query_advisories_with_client;

const NPMS_POPULAR_QUERY: &str = "not:deprecated";
const NPMS_PAGE_SIZE: usize = 250;
const NPM_BULK_DOWNLOAD_MAX_PACKAGES: usize = 128;

#[derive(Clone)]
pub struct NpmRegistryClient {
    http: Client,
    base_url: String,
    downloads_api_base_url: String,
    popular_index_api_base_url: String,
    popular_names_cache: Arc<RwLock<Option<Vec<String>>>>,
    prefetched_downloads: Arc<RwLock<HashMap<String, Option<u64>>>>,
}

impl NpmRegistryClient {
    pub fn new() -> Self {
        Self::with_http_client(Client::new())
    }

    pub fn with_http_client(http: Client) -> Self {
        Self {
            http,
            base_url: env::var("SAFE_PKGS_NPM_REGISTRY_BASE_URL")
                .unwrap_or_else(|_| "https://registry.npmjs.org".to_string()),
            downloads_api_base_url: env::var("SAFE_PKGS_NPM_DOWNLOADS_API_BASE_URL")
                .unwrap_or_else(|_| "https://api.npmjs.org".to_string()),
            popular_index_api_base_url: env::var("SAFE_PKGS_NPM_POPULAR_INDEX_API_BASE_URL")
                .unwrap_or_else(|_| "https://api.npms.io".to_string()),
            popular_names_cache: Arc::new(RwLock::new(None)),
            prefetched_downloads: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn encode_package_name(package: &str) -> String {
        package.replace('@', "%40").replace('/', "%2f")
    }

    pub async fn prefetch_weekly_downloads(
        &self,
        packages: &[String],
    ) -> Result<(), RegistryError> {
        let mut unique_unscoped = Vec::new();
        let mut seen = HashSet::new();
        {
            let cache = self.prefetched_downloads.read().await;
            for package in packages {
                if package.starts_with('@') {
                    continue;
                }
                if cache.contains_key(package) {
                    continue;
                }
                if seen.insert(package.clone()) {
                    unique_unscoped.push(package.clone());
                }
            }
        }

        for chunk in unique_unscoped.chunks(NPM_BULK_DOWNLOAD_MAX_PACKAGES) {
            let joined = chunk
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",");
            let url = format!(
                "{}/downloads/point/last-week/{}",
                self.downloads_api_base_url.trim_end_matches('/'),
                joined
            );

            let response = self.http.get(&url).send().await.map_err(|e| {
                reqwest_transport_error("unable to query npm bulk downloads API", &url, e)
            })?;

            if !response.status().is_success() {
                return Err(RegistryError::Transport {
                    message: format!(
                        "npm bulk downloads API returned status {}",
                        response.status()
                    ),
                });
            }

            let body: NpmBulkDownloadsResponse =
                response
                    .json()
                    .await
                    .map_err(|e| RegistryError::InvalidResponse {
                        message: format!("failed to parse npm bulk downloads response JSON: {e}"),
                    })?;

            let mut cache = self.prefetched_downloads.write().await;
            for item in body.downloads {
                cache.insert(item.package, item.downloads);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl RegistryClient for NpmRegistryClient {
    fn ecosystem(&self) -> RegistryEcosystem {
        RegistryEcosystem::Npm
    }

    async fn fetch_package(&self, package: &str) -> Result<PackageRecord, RegistryError> {
        let encoded_name = Self::encode_package_name(package);
        let url = format!("{}/{}", self.base_url.trim_end_matches('/'), encoded_name);

        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| reqwest_transport_error("unable to query npm registry", &url, e))?;

        if response.status() == StatusCode::NOT_FOUND {
            return Err(RegistryError::NotFound {
                registry: "npm",
                package: package.to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(RegistryError::Transport {
                message: format!("npm registry returned status {}", response.status()),
            });
        }

        let body: NpmPackageResponse =
            response
                .json()
                .await
                .map_err(|e| RegistryError::InvalidResponse {
                    message: format!("failed to parse npm response JSON: {e}"),
                })?;

        let latest = body
            .dist_tags
            .latest
            .ok_or_else(|| RegistryError::InvalidResponse {
                message: "missing dist-tags.latest".to_string(),
            })?;

        let versions = body
            .versions
            .into_iter()
            .map(|(version, metadata)| {
                let published = body
                    .time
                    .as_ref()
                    .and_then(|times| times.get(&version))
                    .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
                    .map(|value| value.with_timezone(&Utc));

                let package_version = PackageVersion {
                    version: version.clone(),
                    published,
                    deprecated: metadata.deprecated.is_some(),
                    install_scripts: metadata.install_scripts(),
                };

                (version, package_version)
            })
            .collect();

        Ok(PackageRecord {
            name: package.to_string(),
            latest,
            publishers: body.maintainers.into_iter().map(|m| m.name).collect(),
            versions,
        })
    }

    async fn fetch_weekly_downloads(&self, package: &str) -> Result<Option<u64>, RegistryError> {
        {
            let cache = self.prefetched_downloads.read().await;
            if let Some(downloads) = cache.get(package) {
                return Ok(*downloads);
            }
        }

        let encoded_name = Self::encode_package_name(package);
        let url = format!(
            "{}/downloads/point/last-week/{}",
            self.downloads_api_base_url.trim_end_matches('/'),
            encoded_name
        );

        let mut attempts = 0u8;
        let response = loop {
            attempts = attempts.saturating_add(1);
            let response = self.http.get(&url).send().await.map_err(|e| {
                reqwest_transport_error("unable to query npm downloads API", &url, e)
            })?;

            if response.status() == StatusCode::TOO_MANY_REQUESTS && attempts < 2 {
                let retry_seconds = parse_retry_after_seconds(response.headers())
                    .unwrap_or(1)
                    .clamp(1, 5);
                tokio::time::sleep(Duration::from_secs(retry_seconds)).await;
                continue;
            }

            break response;
        };

        if response.status() == StatusCode::NOT_FOUND {
            let mut cache = self.prefetched_downloads.write().await;
            cache.insert(package.to_string(), None);
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(RegistryError::Transport {
                message: format!("npm downloads API returned status {}", response.status()),
            });
        }

        let body: NpmDownloadsResponse =
            response
                .json()
                .await
                .map_err(|e| RegistryError::InvalidResponse {
                    message: format!("failed to parse npm downloads response JSON: {e}"),
                })?;

        let mut cache = self.prefetched_downloads.write().await;
        cache.insert(package.to_string(), body.downloads);

        Ok(body.downloads)
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
        let mut seen = HashSet::new();
        let mut from = 0usize;

        while names.len() < limit {
            let url = format!(
                "{}/v2/search",
                self.popular_index_api_base_url.trim_end_matches('/')
            );
            let size = NPMS_PAGE_SIZE.min(limit.saturating_sub(names.len()));
            let response = self
                .http
                .get(&url)
                .query(&[
                    ("q", NPMS_POPULAR_QUERY.to_string()),
                    ("size", size.to_string()),
                    ("from", from.to_string()),
                ])
                .send()
                .await
                .map_err(|e| {
                    reqwest_transport_error("unable to query npms popularity index", &url, e)
                })?;

            if !response.status().is_success() {
                return Err(RegistryError::Transport {
                    message: format!(
                        "npms popularity index returned status {}",
                        response.status()
                    ),
                });
            }

            let body: NpmsSearchResponse =
                response
                    .json()
                    .await
                    .map_err(|e| RegistryError::InvalidResponse {
                        message: format!("failed to parse npms search response JSON: {e}"),
                    })?;

            if body.results.is_empty() {
                break;
            }

            for result in body.results {
                if seen.insert(result.package.name.clone()) {
                    names.push(result.package.name);
                    if names.len() >= limit {
                        break;
                    }
                }
            }

            from = from.saturating_add(size);
        }

        if names.is_empty() {
            return Err(RegistryError::InvalidResponse {
                message: "npms popularity index returned no package names".to_string(),
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
        query_advisories_with_client(&self.http, package, version, self.ecosystem()).await
    }
}

#[derive(Debug, Deserialize)]
struct NpmPackageResponse {
    #[serde(rename = "dist-tags")]
    dist_tags: NpmDistTags,
    #[serde(default)]
    maintainers: Vec<NpmMaintainer>,
    #[serde(default)]
    versions: BTreeMap<String, NpmVersionMetadata>,
    time: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct NpmMaintainer {
    name: String,
}

#[derive(Debug, Deserialize)]
struct NpmDistTags {
    latest: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NpmVersionMetadata {
    deprecated: Option<String>,
    #[serde(default)]
    scripts: BTreeMap<String, String>,
}

impl NpmVersionMetadata {
    fn install_scripts(&self) -> Vec<String> {
        const INSTALL_HOOKS: [&str; 3] = ["preinstall", "install", "postinstall"];
        INSTALL_HOOKS
            .iter()
            .filter_map(|hook| self.scripts.get(*hook).map(|cmd| format!("{hook}: {cmd}")))
            .collect()
    }
}

#[derive(Debug, Deserialize)]
struct NpmDownloadsResponse {
    downloads: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct NpmsSearchResponse {
    #[serde(default)]
    results: Vec<NpmsSearchResult>,
}

#[derive(Debug, Deserialize)]
struct NpmsSearchResult {
    package: NpmsPackage,
}

#[derive(Debug, Deserialize)]
struct NpmsPackage {
    name: String,
}

fn parse_retry_after_seconds(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let raw = headers.get("retry-after")?.to_str().ok()?;
    raw.parse::<u64>().ok()
}

#[derive(Debug, Deserialize)]
struct NpmBulkDownloadsResponse {
    #[serde(default)]
    downloads: Vec<NpmBulkDownloadItem>,
}

#[derive(Debug, Deserialize)]
struct NpmBulkDownloadItem {
    package: String,
    downloads: Option<u64>,
}
