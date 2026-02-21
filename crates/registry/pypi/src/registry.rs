use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::sync::Arc;
use tokio::sync::RwLock;

use safe_pkgs_core::{
    PackageAdvisory, PackageRecord, PackageVersion, RegistryClient, RegistryEcosystem,
    RegistryError,
};
use safe_pkgs_osv::query_advisories;

const PYPI_USER_AGENT: &str = concat!("safe-pkgs/", env!("CARGO_PKG_VERSION"));
const DEFAULT_PYPI_API_BASE_URL: &str = "https://pypi.org/pypi";
const DEFAULT_PYPI_DOWNLOADS_API_BASE_URL: &str = "https://pypistats.org/api/packages";
const DEFAULT_PYPI_POPULAR_INDEX_URL: &str =
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json";

#[derive(Clone)]
pub struct PypiRegistryClient {
    http: Client,
    package_api_base_url: String,
    downloads_api_base_url: String,
    popular_index_url: String,
    popular_names_cache: Arc<RwLock<Option<Vec<String>>>>,
}

impl PypiRegistryClient {
    pub fn new() -> Self {
        Self {
            http: Client::new(),
            package_api_base_url: env::var("SAFE_PKGS_PYPI_PACKAGE_API_BASE_URL")
                .unwrap_or_else(|_| DEFAULT_PYPI_API_BASE_URL.to_string()),
            downloads_api_base_url: env::var("SAFE_PKGS_PYPI_DOWNLOADS_API_BASE_URL")
                .unwrap_or_else(|_| DEFAULT_PYPI_DOWNLOADS_API_BASE_URL.to_string()),
            popular_index_url: env::var("SAFE_PKGS_PYPI_POPULAR_INDEX_URL")
                .unwrap_or_else(|_| DEFAULT_PYPI_POPULAR_INDEX_URL.to_string()),
            popular_names_cache: Arc::new(RwLock::new(None)),
        }
    }
}

impl Default for PypiRegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RegistryClient for PypiRegistryClient {
    fn ecosystem(&self) -> RegistryEcosystem {
        RegistryEcosystem::PyPI
    }

    async fn fetch_package(&self, package: &str) -> Result<PackageRecord, RegistryError> {
        let url = format!(
            "{}/{}/json",
            self.package_api_base_url.trim_end_matches('/'),
            package
        );
        let response = self
            .http
            .get(&url)
            .header("User-Agent", PYPI_USER_AGENT)
            .send()
            .await
            .map_err(|e| RegistryError::Transport {
                message: format!("unable to query PyPI API: {e}"),
            })?;

        if response.status() == StatusCode::NOT_FOUND {
            return Err(RegistryError::NotFound {
                registry: "pypi",
                package: package.to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(RegistryError::Transport {
                message: format!("PyPI API returned status {}", response.status()),
            });
        }

        let body: PypiPackageResponse =
            response
                .json()
                .await
                .map_err(|e| RegistryError::InvalidResponse {
                    message: format!("failed to parse PyPI response JSON: {e}"),
                })?;

        let latest = body
            .info
            .version
            .as_ref()
            .filter(|version| !version.trim().is_empty())
            .cloned()
            .ok_or_else(|| RegistryError::InvalidResponse {
                message: "missing package latest version".to_string(),
            })?;

        let mut versions = body
            .releases
            .into_iter()
            .map(|(version, files)| {
                let published = files
                    .iter()
                    .filter_map(|file| file.upload_time_iso_8601.as_deref())
                    .filter_map(parse_rfc3339_utc)
                    .min();
                let deprecated = !files.is_empty() && files.iter().all(|file| file.yanked);
                (
                    version.clone(),
                    PackageVersion {
                        version,
                        published,
                        deprecated,
                        install_scripts: Vec::new(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        versions
            .entry(latest.clone())
            .or_insert_with(|| PackageVersion {
                version: latest.clone(),
                published: None,
                deprecated: false,
                install_scripts: Vec::new(),
            });

        Ok(PackageRecord {
            name: package.to_string(),
            latest,
            publishers: collect_publishers(&body.info),
            versions,
        })
    }

    async fn fetch_weekly_downloads(&self, package: &str) -> Result<Option<u64>, RegistryError> {
        let url = format!(
            "{}/{}/recent",
            self.downloads_api_base_url.trim_end_matches('/'),
            package
        );
        let response = self
            .http
            .get(&url)
            .header("User-Agent", PYPI_USER_AGENT)
            .send()
            .await
            .map_err(|e| RegistryError::Transport {
                message: format!("unable to query PyPI downloads API: {e}"),
            })?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(RegistryError::Transport {
                message: format!("PyPI downloads API returned status {}", response.status()),
            });
        }

        let body: PypiDownloadsResponse =
            response
                .json()
                .await
                .map_err(|e| RegistryError::InvalidResponse {
                    message: format!("failed to parse PyPI downloads response JSON: {e}"),
                })?;

        Ok(body.data.last_week)
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

        let response = self
            .http
            .get(&self.popular_index_url)
            .header("User-Agent", PYPI_USER_AGENT)
            .send()
            .await
            .map_err(|e| RegistryError::Transport {
                message: format!("unable to query PyPI popularity index: {e}"),
            })?;

        if !response.status().is_success() {
            return Err(RegistryError::Transport {
                message: format!(
                    "PyPI popularity index returned status {}",
                    response.status()
                ),
            });
        }

        let body: TopPypiResponse =
            response
                .json()
                .await
                .map_err(|e| RegistryError::InvalidResponse {
                    message: format!("failed to parse PyPI popularity index JSON: {e}"),
                })?;

        let mut names = Vec::new();
        let mut seen = HashSet::new();
        for row in body.rows {
            if seen.insert(row.project.clone()) {
                names.push(row.project);
            }
        }

        if names.is_empty() {
            return Err(RegistryError::InvalidResponse {
                message: "PyPI popularity index returned no package names".to_string(),
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

fn parse_rfc3339_utc(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn collect_publishers(info: &PypiInfo) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut publishers = Vec::new();

    for raw in [&info.maintainer, &info.author].into_iter().flatten() {
        let value = raw.trim();
        if value.is_empty() {
            continue;
        }

        let normalized = value.to_ascii_lowercase();
        if seen.insert(normalized) {
            publishers.push(value.to_string());
        }
    }

    publishers
}

#[derive(Debug, Deserialize)]
struct PypiPackageResponse {
    info: PypiInfo,
    #[serde(default)]
    releases: BTreeMap<String, Vec<PypiReleaseFile>>,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    version: Option<String>,
    author: Option<String>,
    maintainer: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PypiReleaseFile {
    upload_time_iso_8601: Option<String>,
    #[serde(default)]
    yanked: bool,
}

#[derive(Debug, Deserialize)]
struct PypiDownloadsResponse {
    data: PypiRecentDownloads,
}

#[derive(Debug, Deserialize)]
struct PypiRecentDownloads {
    last_week: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct TopPypiResponse {
    #[serde(default)]
    rows: Vec<TopPypiRow>,
}

#[derive(Debug, Deserialize)]
struct TopPypiRow {
    project: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_client(base_url: &str) -> PypiRegistryClient {
        PypiRegistryClient {
            http: Client::new(),
            package_api_base_url: base_url.to_string(),
            downloads_api_base_url: base_url.to_string(),
            popular_index_url: format!("{}/top.json", base_url.trim_end_matches('/')),
            popular_names_cache: Arc::new(RwLock::new(None)),
        }
    }

    #[test]
    fn parse_rfc3339_utc_handles_valid_and_invalid_values() {
        assert!(parse_rfc3339_utc("2024-01-01T00:00:00Z").is_some());
        assert!(parse_rfc3339_utc("not-a-date").is_none());
    }

    #[test]
    fn collect_publishers_deduplicates_and_skips_empty_values() {
        let info = PypiInfo {
            version: Some("1.0.0".to_string()),
            author: Some("Alice".to_string()),
            maintainer: Some(" alice ".to_string()),
        };
        assert_eq!(collect_publishers(&info), vec!["alice"]);
    }

    #[tokio::test]
    async fn fetch_package_maps_404_to_not_found() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing/json"))
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
    async fn fetch_package_parses_releases_and_publishers() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/demo/json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{
                  "info": {
                    "version": "1.2.0",
                    "author": "Alice",
                    "maintainer": "alice"
                  },
                  "releases": {
                    "1.2.0": [
                      { "upload_time_iso_8601": "2024-01-01T00:00:00Z", "yanked": false }
                    ],
                    "1.1.0": [
                      { "upload_time_iso_8601": "2023-01-01T00:00:00Z", "yanked": true }
                    ]
                  }
                }"#,
                "application/json",
            ))
            .mount(&mock_server)
            .await;
        let client = test_client(&mock_server.uri());

        let record = client.fetch_package("demo").await.expect("valid package");
        assert_eq!(record.latest, "1.2.0");
        assert_eq!(record.publishers, vec!["alice"]);
        assert!(record.versions.contains_key("1.2.0"));
        assert!(record.versions["1.1.0"].deprecated);
    }

    #[tokio::test]
    async fn fetch_package_requires_non_empty_latest_version() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/demo/json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{
                  "info": { "version": "   ", "author": null, "maintainer": null },
                  "releases": {}
                }"#,
                "application/json",
            ))
            .mount(&mock_server)
            .await;
        let client = test_client(&mock_server.uri());

        let err = client
            .fetch_package("demo")
            .await
            .expect_err("empty latest version must fail");
        assert!(matches!(err, RegistryError::InvalidResponse { .. }));
    }

    #[tokio::test]
    async fn fetch_weekly_downloads_handles_not_found_and_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing/recent"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/demo/recent"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{
                  "data": { "last_week": 321 }
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
                .expect("not found downloads"),
            None
        );
        assert_eq!(
            client
                .fetch_weekly_downloads("demo")
                .await
                .expect("download count"),
            Some(321)
        );
    }

    #[tokio::test]
    async fn fetch_popular_package_names_deduplicates_and_caches() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/top.json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{
                  "rows": [
                    { "project": "requests" },
                    { "project": "requests" },
                    { "project": "numpy" }
                  ]
                }"#,
                "application/json",
            ))
            .expect(1)
            .mount(&mock_server)
            .await;
        let client = test_client(&mock_server.uri());

        let first = client
            .fetch_popular_package_names(2)
            .await
            .expect("first lookup");
        let second = client
            .fetch_popular_package_names(2)
            .await
            .expect("cached lookup");
        assert_eq!(first, vec!["requests", "numpy"]);
        assert_eq!(second, vec!["requests", "numpy"]);
    }
}
