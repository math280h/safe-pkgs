use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
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
