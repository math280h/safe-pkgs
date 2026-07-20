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
    /// Severity classification used for aggregation and gating.
    pub severity: Severity,
    /// Human-readable finding text intended for users and logs.
    ///
    /// This may evolve for wording clarity and should not be treated as a
    /// stable machine contract.
    pub reason: String,
    /// Stable machine-readable identifier for this finding variant.
    ///
    /// This is the durable code for automation and evidence IDs (for example,
    /// `too_new`, `missing_package`, `known_advisory`) and should remain
    /// backward-compatible once published.
    pub reason_code: String,
    /// Structured machine-readable context attached to the finding.
    pub facts: BTreeMap<String, FindingValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingValue {
    String(String),
    Integer(i128),
    Unsigned(u64),
    Bool(bool),
    StringList(Vec<String>),
}

impl CheckFinding {
    pub fn new(
        severity: Severity,
        reason: impl Into<String>,
        reason_code: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            reason: reason.into(),
            reason_code: reason_code.into(),
            facts: BTreeMap::new(),
        }
    }

    pub fn with_fact(mut self, key: impl Into<String>, value: impl Into<FindingValue>) -> Self {
        self.facts.insert(key.into(), value.into());
        self
    }
}

impl From<String> for FindingValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<&str> for FindingValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<i64> for FindingValue {
    fn from(value: i64) -> Self {
        Self::Integer(i128::from(value))
    }
}

impl From<i128> for FindingValue {
    fn from(value: i128) -> Self {
        Self::Integer(value)
    }
}

impl From<u64> for FindingValue {
    fn from(value: u64) -> Self {
        Self::Unsigned(value)
    }
}

impl From<usize> for FindingValue {
    fn from(value: usize) -> Self {
        Self::Unsigned(u64::try_from(value).unwrap_or(u64::MAX))
    }
}

impl From<bool> for FindingValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<Vec<String>> for FindingValue {
    fn from(value: Vec<String>) -> Self {
        Self::StringList(value)
    }
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
    pub registry_key: &'a str,
    pub package_name: &'a str,
    pub requested_version: Option<&'a str>,
    pub evaluation_time: DateTime<Utc>,
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
    fn needs_popular_package_names(&self) -> bool {
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

/// Canonicalizes a package name for equivalence comparisons (denylist, allowlist,
/// dependency-confusion), using each ecosystem's name-equivalence rules.
///
/// Registries treat differently-spelled names as the same package, so a policy control
/// must compare canonical forms — otherwise denylisting `evil-pkg` fails to block the
/// equivalent `evil_pkg` (PyPI) or `Evil_Pkg` (crates.io).
///
/// - npm: case-folded (npm names are effectively lowercase).
/// - crates.io: case-folded and `_` unified to `-` (crates.io treats them equivalent).
/// - PyPI: PEP 503 — case-folded with runs of `-`, `_`, `.` collapsed to a single `-`.
pub fn canonicalize_package_name(name: &str, ecosystem: RegistryEcosystem) -> String {
    let name = name.trim();
    match ecosystem {
        RegistryEcosystem::Npm => name.to_ascii_lowercase(),
        RegistryEcosystem::CratesIo => name.to_ascii_lowercase().replace('_', "-"),
        RegistryEcosystem::PyPI => {
            let mut out = String::with_capacity(name.len());
            let mut prev_separator = false;
            for ch in name.chars() {
                if matches!(ch, '-' | '_' | '.') {
                    if !prev_separator {
                        out.push('-');
                        prev_separator = true;
                    }
                } else {
                    out.extend(ch.to_lowercase());
                    prev_separator = false;
                }
            }
            out.trim_matches('-').to_string()
        }
    }
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
                dependency_paths: vec![vec!["demo".to_string()]],
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

    fn record_with_versions(versions: &[&str], latest: &str) -> PackageRecord {
        let mut map = BTreeMap::new();
        for v in versions {
            map.insert(
                (*v).to_string(),
                PackageVersion {
                    version: (*v).to_string(),
                    published: None,
                    deprecated: false,
                    install_scripts: Vec::new(),
                },
            );
        }
        PackageRecord {
            name: "demo".to_string(),
            latest: latest.to_string(),
            publishers: Vec::new(),
            versions: map,
        }
    }

    #[test]
    fn resolve_version_for_semver_ranges_and_partials_resolve_to_best_match() {
        let record = record_with_versions(&["18.1.0", "18.2.0", "17.0.2", "19.0.0"], "19.0.0");
        let r = |req| {
            record
                .resolve_version_for(Some(req), RegistryEcosystem::Npm)
                .map(|v| v.version.as_str())
        };
        // Exact present.
        assert_eq!(r("18.2.0"), Some("18.2.0"));
        // Partial major → highest matching 18.x (not a "hallucinated version").
        assert_eq!(r("18"), Some("18.2.0"));
        // Caret / tilde / comparator ranges.
        assert_eq!(r("^18.0.0"), Some("18.2.0"));
        assert_eq!(r("~18.1"), Some("18.1.0"));
        assert_eq!(r(">=18"), Some("19.0.0"));
        // Leading v is tolerated.
        assert_eq!(r("v18.1.0"), Some("18.1.0"));
        // A concrete exact version that is absent stays a genuine miss.
        assert_eq!(r("99.99.99"), None);
        // cargo uses the same semver path.
        assert_eq!(
            record
                .resolve_version_for(Some("^17"), RegistryEcosystem::CratesIo)
                .map(|v| v.version.as_str()),
            Some("17.0.2")
        );
    }

    #[test]
    fn resolve_version_for_pep440_specifiers_resolve_to_latest() {
        let record = record_with_versions(&["2.30.0", "2.31.0", "2.32.3"], "2.32.3");
        let r = |req| {
            record
                .resolve_version_for(Some(req), RegistryEcosystem::PyPI)
                .map(|v| v.version.as_str())
        };
        // Specifiers → latest published.
        assert_eq!(r(">=2"), Some("2.32.3"));
        assert_eq!(r("~=2.30"), Some("2.32.3"));
        assert_eq!(r("!=2.30.0,>=2.30"), Some("2.32.3"));
        // Explicit equality pins.
        assert_eq!(r("==2.31.0"), Some("2.31.0"));
        assert_eq!(r("2.31.0"), Some("2.31.0"));
        // Bare, absent version is a genuine miss.
        assert_eq!(r("2.99.0"), None);
        assert_eq!(r("==2.99.0"), None);
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
    pub dependency_paths: Vec<Vec<String>>,
}

impl PackageRecord {
    pub fn resolve_version(&self, requested: Option<&str>) -> Option<&PackageVersion> {
        match requested {
            Some("latest") | None => self.versions.get(&self.latest),
            Some(version) => self.versions.get(version),
        }
    }

    /// Resolves a requested version requirement to a concrete published version to
    /// evaluate, taking the ecosystem's version semantics into account.
    ///
    /// - `None` / `"latest"` → the latest published version.
    /// - An exact version present in the registry → that version.
    /// - A range or partial requirement (for example `"^4"`, `"18"`, `">=2"`,
    ///   `"~=1.4"`) → the highest published version satisfying it, falling back to
    ///   latest. This keeps a legitimate range from being misreported as a
    ///   nonexistent ("hallucinated") version.
    /// - A concrete exact version that is not published → `None`, so the existence
    ///   check can still flag a genuinely hallucinated or mistyped version.
    pub fn resolve_version_for(
        &self,
        requested: Option<&str>,
        ecosystem: RegistryEcosystem,
    ) -> Option<&PackageVersion> {
        let raw = match requested {
            None => return self.versions.get(&self.latest),
            Some(value) => value.trim(),
        };
        if raw.is_empty() || raw.eq_ignore_ascii_case("latest") {
            return self.versions.get(&self.latest);
        }
        // Exact match first (covers lockfile pins and exact user requests).
        if let Some(found) = self.versions.get(raw) {
            return Some(found);
        }
        match ecosystem {
            RegistryEcosystem::Npm | RegistryEcosystem::CratesIo => {
                self.resolve_semver_requirement(raw)
            }
            RegistryEcosystem::PyPI => self.resolve_pep440_requirement(raw),
        }
    }

    fn resolve_semver_requirement(&self, raw: &str) -> Option<&PackageVersion> {
        let candidate = raw.strip_prefix(['v', 'V']).unwrap_or(raw);
        // A fully specified, concrete version that is absent is a genuine miss
        // (hallucination / typo) — never silently fall back to another version.
        if semver::Version::parse(candidate).is_ok() {
            return self.versions.get(candidate);
        }
        // Otherwise treat the value as a range/partial requirement and select the
        // highest published version that satisfies it.
        if let Ok(req) = semver::VersionReq::parse(raw) {
            let best = self
                .versions
                .values()
                .filter_map(|version| {
                    semver::Version::parse(&version.version)
                        .ok()
                        .map(|parsed| (parsed, version))
                })
                .filter(|(parsed, _)| req.matches(parsed))
                .max_by(|(a, _), (b, _)| a.cmp(b))
                .map(|(_, version)| version);
            if best.is_some() {
                return best;
            }
        }
        // Unparseable, or a range no published version satisfies: treat as unpinned
        // (evaluate latest) rather than reporting a nonexistent version.
        self.versions.get(&self.latest)
    }

    fn resolve_pep440_requirement(&self, raw: &str) -> Option<&PackageVersion> {
        // An explicit equality operator pins an exact version.
        if let Some(exact) = raw
            .strip_prefix("===")
            .or_else(|| raw.strip_prefix("=="))
            .or_else(|| raw.strip_prefix('='))
            .map(str::trim)
        {
            return self.versions.get(exact);
        }
        // A PEP 440 specifier / range resolves to the latest published version.
        if raw.contains(['<', '>', '~', '!', '*', ',', ' ']) {
            return self.versions.get(&self.latest);
        }
        // A bare version that is not published is a genuine miss.
        None
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
    async fn prefetch_popular_package_names(&self) -> Result<(), RegistryError> {
        Ok(())
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
    /// Check IDs this registry does not support.
    pub excluded_checks: &'static [CheckId],
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
