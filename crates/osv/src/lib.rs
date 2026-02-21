use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::env;

use safe_pkgs_core::{PackageAdvisory, RegistryEcosystem, RegistryError};

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

pub async fn query_advisories(
    package_name: &str,
    version: &str,
    ecosystem: RegistryEcosystem,
) -> Result<Vec<PackageAdvisory>, RegistryError> {
    let api_url =
        env::var("SAFE_PKGS_OSV_API_BASE_URL").unwrap_or_else(|_| OSV_API_URL.to_string());
    query_advisories_with_url(package_name, version, ecosystem, &api_url).await
}

async fn query_advisories_with_url(
    package_name: &str,
    version: &str,
    ecosystem: RegistryEcosystem,
    api_url: &str,
) -> Result<Vec<PackageAdvisory>, RegistryError> {
    let body = OsvQueryRequest {
        package: OsvPackage {
            name: package_name.to_string(),
            ecosystem: ecosystem.osv_name().to_string(),
        },
        version: version.to_string(),
    };

    let response = Client::new()
        .post(api_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| RegistryError::Transport {
            message: format!("unable to query OSV advisory API: {e}"),
        })?;

    if response.status() == StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }

    if response.status().is_server_error() {
        return Err(RegistryError::Transport {
            message: format!("OSV advisory API server error {}", response.status()),
        });
    }

    if !response.status().is_success() {
        return Err(RegistryError::Transport {
            message: format!("OSV advisory API returned status {}", response.status()),
        });
    }

    let body: OsvQueryResponse =
        response
            .json()
            .await
            .map_err(|e| RegistryError::InvalidResponse {
                message: format!("failed to parse OSV advisory response JSON: {e}"),
            })?;

    Ok(body
        .vulns
        .into_iter()
        .map(|vuln| {
            let fixed_versions = vuln.fixed_versions();
            PackageAdvisory {
                id: vuln.id,
                aliases: vuln.aliases,
                fixed_versions,
            }
        })
        .collect())
}

#[derive(Debug, Serialize)]
struct OsvQueryRequest {
    package: OsvPackage,
    version: String,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

impl OsvVulnerability {
    fn fixed_versions(&self) -> Vec<String> {
        self.affected
            .iter()
            .flat_map(|affected| affected.ranges.iter())
            .flat_map(|range| range.events.iter())
            .filter_map(|event| event.fixed.clone())
            .collect()
    }
}

#[derive(Debug, Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize)]
struct OsvEvent {
    fixed: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn returns_empty_on_404() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let result = query_advisories_with_url(
            "demo",
            "1.0.0",
            RegistryEcosystem::Npm,
            &format!("{}/v1/query", mock_server.uri()),
        )
        .await
        .expect("404 should map to empty advisory list");
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn returns_transport_error_on_5xx() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let err = query_advisories_with_url(
            "demo",
            "1.0.0",
            RegistryEcosystem::Npm,
            &format!("{}/v1/query", mock_server.uri()),
        )
        .await
        .expect_err("500 should be treated as transport error");
        assert!(matches!(err, RegistryError::Transport { .. }));
        assert!(err.to_string().contains("server error 500"));
    }

    #[tokio::test]
    async fn parses_vulnerabilities_with_fixed_versions() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                r#"{
                    "vulns": [{
                        "id": "OSV-2024-123",
                        "aliases": ["CVE-2024-9999"],
                        "affected": [{
                            "ranges": [{
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "1.2.3"},
                                    {"fixed": "2.0.0"}
                                ]
                            }]
                        }]
                    }]
                }"#,
                "application/json",
            ))
            .mount(&mock_server)
            .await;

        let advisories = query_advisories_with_url(
            "demo",
            "1.0.0",
            RegistryEcosystem::Npm,
            &format!("{}/v1/query", mock_server.uri()),
        )
        .await
        .expect("valid OSV response");

        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id, "OSV-2024-123");
        assert_eq!(advisories[0].aliases, vec!["CVE-2024-9999"]);
        assert_eq!(advisories[0].fixed_versions, vec!["1.2.3", "2.0.0"]);
    }

    #[tokio::test]
    async fn returns_invalid_response_when_json_is_malformed() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(r#"{"vulns": [}"#, "application/json"),
            )
            .mount(&mock_server)
            .await;

        let err = query_advisories_with_url(
            "demo",
            "1.0.0",
            RegistryEcosystem::Npm,
            &format!("{}/v1/query", mock_server.uri()),
        )
        .await
        .expect_err("malformed JSON should fail parsing");
        assert!(matches!(err, RegistryError::InvalidResponse { .. }));
    }
}
