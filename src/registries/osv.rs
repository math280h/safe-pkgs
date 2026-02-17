use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;

use crate::registries::{PackageAdvisory, RegistryEcosystem, RegistryError};

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

pub async fn query_advisories(
    package_name: &str,
    version: &str,
    ecosystem: RegistryEcosystem,
) -> Result<Vec<PackageAdvisory>, RegistryError> {
    let body = OsvQueryRequest {
        package: OsvPackage {
            name: package_name.to_string(),
            ecosystem: ecosystem.osv_name().to_string(),
        },
        version: version.to_string(),
    };
    let api_url = env::var("SAFE_PKGS_OSV_API_URL").unwrap_or_else(|_| OSV_API_URL.to_string());

    let response = Client::new()
        .post(api_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| RegistryError::Transport {
            message: format!("unable to query OSV advisory API: {e}"),
        })?;

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
