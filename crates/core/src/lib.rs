use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

pub type CheckId = &'static str;
pub type CheckFactory = fn() -> Box<dyn Check>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weekly_downloads: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct CheckFinding {
    pub severity: Severity,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct StalenessPolicy {
    pub warn_major_versions_behind: u64,
    pub warn_minor_versions_behind: u64,
    pub warn_age_days: i64,
    pub ignore_for: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CheckPolicy {
    pub min_version_age_days: i64,
    pub min_weekly_downloads: u64,
    pub staleness: StalenessPolicy,
}

pub struct CheckExecutionContext<'a> {
    pub package_name: &'a str,
    pub requested_version: Option<&'a str>,
    pub package: Option<&'a PackageRecord>,
    pub resolved_version: Option<&'a PackageVersion>,
    pub weekly_downloads: Option<u64>,
    pub advisories: &'a [PackageAdvisory],
    pub registry_client: &'a dyn RegistryClient,
    pub policy: &'a CheckPolicy,
}

#[async_trait]
pub trait Check: Send + Sync {
    fn id(&self) -> CheckId;
    fn description(&self) -> &'static str;
    fn always_enabled(&self) -> bool {
        false
    }
    fn priority(&self) -> u16 {
        100
    }
    fn runs_on_missing_package(&self) -> bool {
        false
    }
    fn runs_on_missing_version(&self) -> bool {
        false
    }
    fn needs_weekly_downloads(&self) -> bool {
        false
    }
    fn needs_advisories(&self) -> bool {
        false
    }
    async fn run(
        &self,
        context: &CheckExecutionContext<'_>,
    ) -> Result<Vec<CheckFinding>, RegistryError>;
}

pub fn normalize_check_id(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace('-', "_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct DummyParser;

    impl LockfileParser for DummyParser {
        fn supported_files(&self) -> &'static [&'static str] {
            &["package-lock.json", "requirements.txt"]
        }

        fn parse_dependencies(&self, _path: &Path) -> Result<Vec<DependencySpec>, LockfileError> {
            Ok(vec![DependencySpec {
                name: "demo".to_string(),
                version: Some("1.0.0".to_string()),
            }])
        }
    }

    struct DummyClient;

    #[async_trait]
    impl RegistryClient for DummyClient {
        fn ecosystem(&self) -> RegistryEcosystem {
            RegistryEcosystem::Npm
        }

        async fn fetch_package(&self, package: &str) -> Result<PackageRecord, RegistryError> {
            Err(RegistryError::NotFound {
                registry: "test",
                package: package.to_string(),
            })
        }
    }

    struct DummyPlugin {
        client: Arc<DummyClient>,
    }

    impl RegistryPlugin for DummyPlugin {
        fn key(&self) -> &'static str {
            "dummy"
        }

        fn client(&self) -> &dyn RegistryClient {
            self.client.as_ref()
        }
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("safe-pkgs-core-{nanos}-{name}"))
    }

    #[test]
    fn normalize_check_id_converts_hyphens_to_underscores() {
        assert_eq!(normalize_check_id("check-id"), "check_id");
    }

    #[test]
    fn normalize_check_id_normalizes_case() {
        assert_eq!(normalize_check_id("MiXeD-Case-Id"), "mixed_case_id");
    }

    #[test]
    fn normalize_check_id_trims_whitespace() {
        assert_eq!(normalize_check_id("  Check-ID  "), "check_id");
    }

    #[test]
    fn registry_ecosystem_osv_names_are_stable() {
        assert_eq!(RegistryEcosystem::Npm.osv_name(), "npm");
        assert_eq!(RegistryEcosystem::CratesIo.osv_name(), "crates.io");
        assert_eq!(RegistryEcosystem::PyPI.osv_name(), "PyPI");
    }

    #[test]
    fn resolve_version_prefers_latest_when_omitted_or_latest_literal() {
        let mut versions = BTreeMap::new();
        versions.insert(
            "1.0.0".to_string(),
            PackageVersion {
                version: "1.0.0".to_string(),
                published: None,
                deprecated: false,
                install_scripts: Vec::new(),
            },
        );
        versions.insert(
            "2.0.0".to_string(),
            PackageVersion {
                version: "2.0.0".to_string(),
                published: None,
                deprecated: false,
                install_scripts: Vec::new(),
            },
        );
        let record = PackageRecord {
            name: "demo".to_string(),
            latest: "2.0.0".to_string(),
            publishers: Vec::new(),
            versions,
        };

        assert_eq!(
            record.resolve_version(None).map(|v| v.version.as_str()),
            Some("2.0.0")
        );
        assert_eq!(
            record
                .resolve_version(Some("latest"))
                .map(|v| v.version.as_str()),
            Some("2.0.0")
        );
        assert_eq!(
            record
                .resolve_version(Some("1.0.0"))
                .map(|v| v.version.as_str()),
            Some("1.0.0")
        );
        assert!(record.resolve_version(Some("9.9.9")).is_none());
    }

    #[test]
    fn validate_dependency_file_accepts_supported_file() {
        let dir = unique_temp_path("validate-supported");
        fs::create_dir_all(&dir).expect("create dir");
        let path = dir.join("package-lock.json");
        fs::write(&path, "{}").expect("write file");

        let validated =
            validate_dependency_file(path.as_path(), &["package-lock.json", "package.json"])
                .expect("supported file");
        assert_eq!(validated, path.as_path());

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn validate_dependency_file_rejects_unsupported_file() {
        let dir = unique_temp_path("validate-unsupported");
        fs::create_dir_all(&dir).expect("create dir");
        let path = dir.join("Cargo.toml");
        fs::write(&path, "[package]").expect("write file");

        let err = validate_dependency_file(path.as_path(), &["package-lock.json"])
            .expect_err("unsupported file should error");
        match err {
            LockfileError::UnsupportedFile {
                file_name,
                expected,
            } => {
                assert_eq!(file_name, "Cargo.toml");
                assert_eq!(expected, "package-lock.json");
            }
            other => panic!("unexpected error variant: {other}"),
        }

        let _ = fs::remove_file(path);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn validate_dependency_file_rejects_directory_paths() {
        let dir = unique_temp_path("supported-dir-as-dir");
        fs::create_dir_all(&dir).expect("create dir");
        let candidate = dir.join("package-lock.json");
        fs::create_dir_all(&candidate).expect("create nested dir");

        let err = validate_dependency_file(candidate.as_path(), &["package-lock.json"])
            .expect_err("directories are not valid dependency files");
        assert!(matches!(err, LockfileError::InvalidInputPath { .. }));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_input_accepts_supported_file_path() {
        let parser = DummyParser;
        let dir = unique_temp_path("resolve-file");
        fs::create_dir_all(&dir).expect("create dir");
        let file_path = dir.join("package-lock.json");
        fs::write(&file_path, "{}").expect("write file");

        let resolved = parser
            .resolve_input(Some(file_path.to_string_lossy().as_ref()))
            .expect("resolve supported file");
        assert_eq!(resolved, file_path);

        let _ = fs::remove_file(file_path);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_input_rejects_missing_path() {
        let parser = DummyParser;
        let missing = unique_temp_path("missing-dir");
        let err = parser
            .resolve_input(Some(missing.to_string_lossy().as_ref()))
            .expect_err("missing path should fail");
        match err {
            LockfileError::InputPathDoesNotExist { path } => {
                assert!(path.contains("missing-dir"));
            }
            other => panic!("unexpected error variant: {other}"),
        }
    }

    #[test]
    fn resolve_input_rejects_directory_without_supported_files() {
        let parser = DummyParser;
        let dir = unique_temp_path("empty-dir");
        fs::create_dir_all(&dir).expect("create dir");

        let err = parser
            .resolve_input(Some(dir.to_string_lossy().as_ref()))
            .expect_err("missing dependency files");
        match err {
            LockfileError::NoSupportedDependencyFile { expected, path } => {
                assert!(expected.contains("package-lock.json"));
                assert!(expected.contains("requirements.txt"));
                assert!(path.contains("empty-dir"));
            }
            other => panic!("unexpected error variant: {other}"),
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_input_picks_first_supported_file_in_directory() {
        let parser = DummyParser;
        let dir = unique_temp_path("supported-dir");
        fs::create_dir_all(&dir).expect("create dir");
        let expected_file = dir.join("package-lock.json");
        fs::write(&expected_file, "{}").expect("write file");

        let resolved = parser
            .resolve_input(Some(dir.to_string_lossy().as_ref()))
            .expect("resolve supported file in dir");
        assert_eq!(resolved, expected_file);

        let _ = fs::remove_file(expected_file);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_input_ignores_supported_names_that_are_directories() {
        let parser = DummyParser;
        let dir = unique_temp_path("supported-name-dir");
        fs::create_dir_all(&dir).expect("create dir");
        fs::create_dir_all(dir.join("package-lock.json")).expect("create nested dir");

        let err = parser
            .resolve_input(Some(dir.to_string_lossy().as_ref()))
            .expect_err("supported filename must be a regular file");
        assert!(matches!(
            err,
            LockfileError::NoSupportedDependencyFile { .. }
        ));

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn registry_client_default_methods_return_empty_values() {
        let client = DummyClient;
        client
            .prefetch_weekly_downloads(&["a".to_string(), "b".to_string()])
            .await
            .expect("default prefetch should succeed");
        assert_eq!(
            client
                .fetch_weekly_downloads("demo")
                .await
                .expect("default downloads call"),
            None
        );
        assert!(
            client
                .fetch_popular_package_names(5)
                .await
                .expect("default popular names")
                .is_empty()
        );
        assert!(
            client
                .fetch_advisories("demo", "1.0.0")
                .await
                .expect("default advisories")
                .is_empty()
        );
    }

    #[test]
    fn registry_plugin_default_methods_are_empty() {
        let plugin = DummyPlugin {
            client: Arc::new(DummyClient),
        };
        assert_eq!(plugin.key(), "dummy");
        assert!(plugin.supported_checks().is_empty());
        assert!(plugin.lockfile_parser().is_none());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryEcosystem {
    Npm,
    CratesIo,
    PyPI,
}

impl RegistryEcosystem {
    pub fn osv_name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::CratesIo => "crates.io",
            Self::PyPI => "PyPI",
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

#[derive(Debug, Clone)]
pub struct DependencySpec {
    pub name: String,
    pub version: Option<String>,
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

#[derive(Debug, Error)]
pub enum LockfileError {
    #[error("failed to determine current directory: {source}")]
    CurrentDirectory {
        #[source]
        source: std::io::Error,
    },
    #[error("invalid dependency input path: {path}")]
    InvalidInputPath { path: String },
    #[error("dependency input path does not exist: {path}")]
    InputPathDoesNotExist { path: String },
    #[error("unsupported file '{file_name}' (expected one of: {expected})")]
    UnsupportedFile { file_name: String, expected: String },
    #[error("no supported dependency file ({expected}) found at {path}")]
    NoSupportedDependencyFile { expected: String, path: String },
    #[error("failed to read dependency file {path}: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse dependency file {path}: {message}")]
    ParseFile { path: String, message: String },
}

#[async_trait]
pub trait RegistryClient: Send + Sync {
    fn ecosystem(&self) -> RegistryEcosystem;
    async fn fetch_package(&self, package: &str) -> Result<PackageRecord, RegistryError>;
    async fn prefetch_weekly_downloads(&self, _packages: &[String]) -> Result<(), RegistryError> {
        Ok(())
    }
    async fn fetch_weekly_downloads(&self, _package: &str) -> Result<Option<u64>, RegistryError> {
        Ok(None)
    }
    async fn fetch_popular_package_names(
        &self,
        _limit: usize,
    ) -> Result<Vec<String>, RegistryError> {
        Ok(Vec::new())
    }
    async fn fetch_advisories(
        &self,
        _package: &str,
        _version: &str,
    ) -> Result<Vec<PackageAdvisory>, RegistryError> {
        Ok(Vec::new())
    }
}

pub trait LockfileParser: Send + Sync {
    fn supported_files(&self) -> &'static [&'static str];
    fn parse_dependencies(&self, path: &Path) -> Result<Vec<DependencySpec>, LockfileError>;

    fn resolve_input(&self, path: Option<&str>) -> Result<PathBuf, LockfileError> {
        let candidate = match path {
            Some(value) => PathBuf::from(value),
            None => std::env::current_dir()
                .map_err(|source| LockfileError::CurrentDirectory { source })?,
        };

        if candidate.is_file() {
            return validate_dependency_file(candidate.as_path(), self.supported_files());
        }

        if candidate.exists() && !candidate.is_dir() {
            return Err(LockfileError::InvalidInputPath {
                path: candidate.display().to_string(),
            });
        }

        if !candidate.is_dir() {
            return Err(LockfileError::InputPathDoesNotExist {
                path: candidate.display().to_string(),
            });
        }

        for file_name in self.supported_files() {
            let file_path = candidate.join(file_name);
            if file_path.is_file() {
                return Ok(file_path);
            }
        }

        Err(LockfileError::NoSupportedDependencyFile {
            expected: self.supported_files().join(", "),
            path: candidate.display().to_string(),
        })
    }
}

#[derive(Clone, Copy)]
pub struct RegistryDefinition {
    pub key: &'static str,
    pub create_client: fn() -> Arc<dyn RegistryClient>,
    pub create_lockfile_parser: Option<fn() -> Arc<dyn LockfileParser>>,
}

pub trait RegistryPlugin: Send + Sync {
    fn key(&self) -> &'static str;
    fn client(&self) -> &dyn RegistryClient;
    fn supported_checks(&self) -> &[CheckId] {
        &[]
    }
    fn lockfile_parser(&self) -> Option<&dyn LockfileParser> {
        None
    }
}

fn validate_dependency_file(
    path: &Path,
    supported_files: &[&str],
) -> Result<PathBuf, LockfileError> {
    if !path.is_file() {
        return Err(LockfileError::InvalidInputPath {
            path: path.display().to_string(),
        });
    }

    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(LockfileError::InvalidInputPath {
            path: path.display().to_string(),
        });
    };

    if supported_files.contains(&file_name) {
        return Ok(path.to_path_buf());
    }

    Err(LockfileError::UnsupportedFile {
        file_name: file_name.to_string(),
        expected: supported_files.join(", "),
    })
}
