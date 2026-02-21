use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use std::error::Error as StdError;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryKind {
    Npm,
    Cargo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryEcosystem {
    Npm,
    CratesIo,
}

impl RegistryEcosystem {
    pub fn osv_name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::CratesIo => "crates.io",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackageVersion {
    pub version: String,
    pub published: Option<DateTime<Utc>>,
    pub deprecated: bool,
    pub install_scripts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PackageRecord {
    pub name: String,
    pub latest: String,
    pub publishers: Vec<String>,
    pub versions: BTreeMap<String, PackageVersion>,
}

#[derive(Debug, Clone)]
pub struct PackageAdvisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub fixed_versions: Vec<String>,
}

impl PackageRecord {
    pub fn resolve_version(&self, requested: Option<&str>) -> Option<&PackageVersion> {
        match requested {
            Some("latest") | None => self.versions.get(&self.latest),
            Some(version) => self.versions.get(version),
        }
    }
}

#[derive(Debug, Clone, Error)]
pub enum RegistryError {
    #[error("package '{package}' was not found in {registry}")]
    NotFound {
        registry: &'static str,
        package: String,
    },
    #[error("registry request failed: {message}")]
    Transport { message: String },
    #[error("registry returned invalid data: {message}")]
    InvalidResponse { message: String },
}

pub fn reqwest_transport_error(
    context: &str,
    request_url: &str,
    error: reqwest::Error,
) -> RegistryError {
    let mut details = Vec::new();

    let effective_url = error
        .url()
        .map(|url| url.as_str().to_string())
        .unwrap_or_else(|| request_url.to_string());
    details.push(format!("request_url={effective_url}"));

    let mut kinds = Vec::new();
    if error.is_timeout() {
        kinds.push("timeout");
    }
    if error.is_connect() {
        kinds.push("connect");
    }
    if error.is_request() {
        kinds.push("request");
    }
    if error.is_body() {
        kinds.push("body");
    }
    if error.is_decode() {
        kinds.push("decode");
    }
    if error.is_builder() {
        kinds.push("builder");
    }
    if error.is_redirect() {
        kinds.push("redirect");
    }
    if let Some(status) = error.status() {
        kinds.push(if status.is_client_error() {
            "http4xx"
        } else if status.is_server_error() {
            "http5xx"
        } else {
            "http"
        });
        details.push(format!("http_status={status}"));
    }
    if kinds.is_empty() {
        kinds.push("unknown");
    }
    details.push(format!("kinds={}", kinds.join(",")));

    let mut sources = Vec::new();
    let mut current = error.source();
    while let Some(source) = current {
        sources.push(source.to_string());
        if sources.len() >= 6 {
            break;
        }
        current = source.source();
    }
    if !sources.is_empty() {
        details.push(format!("source_chain={}", sources.join(" | ")));
    }

    details.push("hint=verify sandbox domain allowlist permits this host over HTTPS".to_string());
    details.push(
        "hint=for CLI usage, pass --https-proxy http://<host>:<port> when required".to_string(),
    );
    details.push(
        "hint=for TLS interception/UnknownIssuer, pass --ca-cert /path/to/corp-root.pem"
            .to_string(),
    );
    details.push("hint=debug-only escape hatch: --insecure-skip-tls-verify (unsafe)".to_string());
    details.push(
        "hint=if a corporate proxy is required, set HTTPS_PROXY/HTTP_PROXY/NO_PROXY".to_string(),
    );
    details.push(
        "hint=if DNS is blocked, requests fail before any HTTP status is returned".to_string(),
    );

    RegistryError::Transport {
        message: format!("{context}: {error}; {}", details.join("; ")),
    }
}

#[async_trait]
pub trait RegistryClient: Send + Sync {
    fn ecosystem(&self) -> RegistryEcosystem;
    async fn fetch_package(&self, package: &str) -> Result<PackageRecord, RegistryError>;
    async fn fetch_weekly_downloads(&self, package: &str) -> Result<Option<u64>, RegistryError>;
    async fn fetch_popular_package_names(&self, limit: usize)
    -> Result<Vec<String>, RegistryError>;
    async fn fetch_advisories(
        &self,
        package: &str,
        version: &str,
    ) -> Result<Vec<PackageAdvisory>, RegistryError>;
}
