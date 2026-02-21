use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use safe_pkgs_core::{
    PackageAdvisory, PackageRecord, PackageVersion, RegistryClient, RegistryEcosystem,
    RegistryError,
};
use safe_pkgs_osv::query_advisories;

const CRATES_IO_USER_AGENT: &str = concat!("safe-pkgs/", env!("CARGO_PKG_VERSION"));
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

impl Default for CargoRegistryClient {
    fn default() -> Self {
        Self::new()
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_client(base_url: &str) -> CargoRegistryClient {
        CargoRegistryClient {
            http: Client::new(),
            api_base_url: base_url.to_string(),
            popular_names_cache: Arc::new(RwLock::new(None)),
        }
    }

    #[tokio::test]
    async fn fetch_package_returns_not_found_on_404() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/crates/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;
        let client = test_client(&mock_server.uri());

        let err = client
            .fetch_package("missing")
            .await
            .expect_err("404 should map to not found");
        assert!(matches!(err, RegistryError::NotFound { .. }));
    }

    #[tokio::test]
    async fn fetch_package_parses_latest_and_versions() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/crates/demo"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{
                  "crate": {
                    "max_stable_version": "1.2.3",
                    "max_version": "1.2.4",
                    "recent_downloads": 1234
                  },
                  "versions": [
                    { "num": "1.2.3", "created_at": "2024-01-01T00:00:00Z", "yanked": false },
                    { "num": "1.2.2", "created_at": "2023-12-01T00:00:00Z", "yanked": true }
                  ]
                }"#,
                "application/json",
            ))
            .mount(&mock_server)
            .await;
        let client = test_client(&mock_server.uri());

        let record = client.fetch_package("demo").await.expect("valid record");
        assert_eq!(record.latest, "1.2.3");
        assert_eq!(record.versions.len(), 2);
        assert!(!record.versions["1.2.3"].deprecated);
        assert!(record.versions["1.2.2"].deprecated);
    }

    #[tokio::test]
    async fn fetch_package_requires_latest_version_in_payload() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/crates/demo"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{
                  "crate": {
                    "max_stable_version": null,
                    "max_version": null,
                    "recent_downloads": null
                  },
                  "versions": []
                }"#,
                "application/json",
            ))
            .mount(&mock_server)
            .await;
        let client = test_client(&mock_server.uri());

        let err = client
            .fetch_package("demo")
            .await
            .expect_err("missing latest must fail");
        assert!(matches!(err, RegistryError::InvalidResponse { .. }));
    }

    #[tokio::test]
    async fn fetch_weekly_downloads_handles_not_found_and_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/crates/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/crates/demo"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{
                  "crate": {
                    "max_stable_version": "1.0.0",
                    "max_version": "1.0.0",
                    "recent_downloads": 999
                  }
                }"#,
                "application/json",
            ))
            .mount(&mock_server)
            .await;
        let client = test_client(&mock_server.uri());

        assert_eq!(
            client
                .fetch_weekly_downloads("missing")
                .await
                .expect("404 should map to none"),
            None
        );
        assert_eq!(
            client
                .fetch_weekly_downloads("demo")
                .await
                .expect("valid downloads"),
            Some(999)
        );
    }

    #[tokio::test]
    async fn fetch_popular_package_names_uses_cache_after_first_call() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/crates"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{
                  "crates": [
                    { "id": "serde" },
                    { "id": "tokio" }
                  ]
                }"#,
                "application/json",
            ))
            .expect(1)
            .mount(&mock_server)
            .await;
        let client = test_client(&mock_server.uri());

        let first = client
            .fetch_popular_package_names(1)
            .await
            .expect("first lookup");
        let second = client
            .fetch_popular_package_names(1)
            .await
            .expect("cached lookup");
        assert_eq!(first, vec!["serde"]);
        assert_eq!(second, vec!["serde"]);
    }

    #[tokio::test]
    async fn fetch_popular_package_names_rejects_empty_index() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/crates"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(r#"{ "crates": [] }"#, "application/json"),
            )
            .mount(&mock_server)
            .await;
        let client = test_client(&mock_server.uri());

        let err = client
            .fetch_popular_package_names(10)
            .await
            .expect_err("empty popularity index should fail");
        assert!(matches!(err, RegistryError::InvalidResponse { .. }));
    }
}
