use rmcp::{
    ErrorData as McpError, ServerHandler, handler::server::tool::ToolRouter,
    handler::server::wrapper::Parameters, model::*, tool, tool_handler, tool_router,
};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use semver::Version;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::audit_log::{AuditLogger, AuditRecord};
use crate::cache::SqliteCache;
use crate::checks;
use crate::config::SafePkgsConfig;
use crate::registries::{CargoRegistryClient, NpmRegistryClient, RegistryKind};
use crate::types::{LockfilePackageResult, LockfileResponse, Metadata, Severity, ToolResponse};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PackageRegistry {
    #[schemars(description = "Node.js packages from npmjs.com")]
    Npm,
    #[schemars(description = "Rust crates from crates.io")]
    Cargo,
}

fn default_package_registry() -> PackageRegistry {
    PackageRegistry::Npm
}

fn package_registry_schema(generator: &mut SchemaGenerator) -> Schema {
    let mut schema = String::json_schema(generator);
    schema.insert("enum".into(), serde_json::json!(["npm", "cargo"]));
    schema.insert("default".into(), serde_json::json!("npm"));
    schema
}

impl From<PackageRegistry> for RegistryKind {
    fn from(value: PackageRegistry) -> Self {
        match value {
            PackageRegistry::Npm => RegistryKind::Npm,
            PackageRegistry::Cargo => RegistryKind::Cargo,
        }
    }
}

impl PackageRegistry {
    fn cache_segment(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Cargo => "cargo",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Cargo => "cargo",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PackageQuery {
    #[schemars(description = "Package name, e.g. \"lodash\"")]
    pub name: String,

    #[schemars(description = "Specific version or \"latest\". Defaults to \"latest\" if omitted.")]
    pub version: Option<String>,

    #[schemars(
        description = "Package registry. Defaults to \"npm\". Supported: \"npm\", \"cargo\"."
    )]
    #[serde(default = "default_package_registry")]
    #[schemars(schema_with = "package_registry_schema")]
    pub registry: PackageRegistry,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LockfileQuery {
    #[schemars(
        description = "Path to a package-lock.json/package.json file or a project directory. Defaults to current working directory."
    )]
    pub path: Option<String>,

    #[schemars(description = "Registry for dependency checks. Defaults to npm.")]
    #[serde(default = "default_package_registry")]
    #[schemars(schema_with = "package_registry_schema")]
    pub registry: PackageRegistry,
}

#[derive(Debug, Clone)]
struct PackageSpec {
    name: String,
    version: Option<String>,
}

#[derive(Clone)]
pub struct SafePkgsServer {
    tool_router: ToolRouter<Self>,
    npm_client: Arc<NpmRegistryClient>,
    cargo_client: Arc<CargoRegistryClient>,
    config: Arc<SafePkgsConfig>,
    cache: Arc<SqliteCache>,
    audit_logger: Arc<AuditLogger>,
}

#[tool_router]
impl SafePkgsServer {
    pub fn new() -> anyhow::Result<Self> {
        let config = SafePkgsConfig::load()?;
        let cache = SqliteCache::new(config.cache.ttl_minutes)?;
        let audit_logger = AuditLogger::new()?;
        Ok(Self::with_cache(config, cache, audit_logger))
    }

    #[cfg(test)]
    pub fn with_config(config: SafePkgsConfig) -> Self {
        let cache = SqliteCache::in_memory(config.cache.ttl_minutes)
            .expect("in-memory sqlite cache for test server");
        let audit_logger = AuditLogger::new().expect("audit logger");
        Self::with_cache(config, cache, audit_logger)
    }

    fn with_cache(config: SafePkgsConfig, cache: SqliteCache, audit_logger: AuditLogger) -> Self {
        Self {
            tool_router: Self::tool_router(),
            npm_client: Arc::new(NpmRegistryClient::new()),
            cargo_client: Arc::new(CargoRegistryClient::new()),
            config: Arc::new(config),
            cache: Arc::new(cache),
            audit_logger: Arc::new(audit_logger),
        }
    }

    #[tool(
        name = "check_package",
        description = "Check whether a package is safe to install from a supported registry (currently npm and cargo). Call this before package installation. Returns allow/deny, a risk level, and human-readable reasons."
    )]
    async fn check_package(
        &self,
        Parameters(query): Parameters<PackageQuery>,
    ) -> Result<CallToolResult, McpError> {
        let response = self
            .evaluate_package(
                &query.name,
                query.version.as_deref(),
                query.registry,
                "check_package",
            )
            .await?;

        let json = serde_json::to_string_pretty(&response)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(
        name = "check_lockfile",
        description = "Batch-check dependencies from package-lock.json or package.json. Returns aggregate allow/risk and per-package findings."
    )]
    async fn check_lockfile(
        &self,
        Parameters(query): Parameters<LockfileQuery>,
    ) -> Result<CallToolResult, McpError> {
        let response = self
            .run_lockfile_audit(query.path.as_deref(), query.registry, "check_lockfile")
            .await?;

        let json = serde_json::to_string_pretty(&response)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    pub async fn audit_lockfile_path(&self, path: &str) -> anyhow::Result<LockfileResponse> {
        self.run_lockfile_audit(Some(path), PackageRegistry::Npm, "cli_audit")
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    async fn run_lockfile_audit(
        &self,
        path: Option<&str>,
        registry: PackageRegistry,
        context: &str,
    ) -> Result<LockfileResponse, McpError> {
        if registry != PackageRegistry::Npm {
            return Err(McpError::internal_error(
                "check_lockfile currently supports npm lockfiles/package manifests only"
                    .to_string(),
                None,
            ));
        }

        let input_path = resolve_dependency_input(path)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let package_specs = parse_npm_dependencies(&input_path)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let package_names = package_specs
            .iter()
            .map(|spec| spec.name.clone())
            .collect::<Vec<_>>();

        if let Err(err) = self
            .npm_client
            .prefetch_weekly_downloads(&package_names)
            .await
        {
            tracing::warn!("bulk npm downloads prefetch failed: {err}");
        }

        let mut risk = Severity::Low;
        let mut denied = 0usize;
        let mut packages = Vec::with_capacity(package_specs.len());

        for spec in package_specs {
            match self
                .evaluate_package(&spec.name, spec.version.as_deref(), registry, context)
                .await
            {
                Ok(response) => {
                    if response.risk > risk {
                        risk = response.risk;
                    }
                    if !response.allow {
                        denied = denied.saturating_add(1);
                    }

                    packages.push(LockfilePackageResult {
                        name: spec.name,
                        requested: spec.version,
                        allow: response.allow,
                        risk: response.risk,
                        reasons: response.reasons,
                    });
                }
                Err(err) => {
                    denied = denied.saturating_add(1);
                    risk = Severity::Critical;
                    let reason = format!("package check failed: {err}");
                    packages.push(LockfilePackageResult {
                        name: spec.name.clone(),
                        requested: spec.version.clone(),
                        allow: false,
                        risk: Severity::Critical,
                        reasons: vec![reason.clone()],
                    });
                    self.log_decision(
                        context,
                        registry,
                        spec.name.as_str(),
                        spec.version.as_deref(),
                        false,
                        Severity::Critical,
                        vec![reason],
                        None,
                        false,
                    );
                }
            }
        }

        let response = LockfileResponse {
            allow: denied == 0,
            risk,
            total: packages.len(),
            denied,
            packages,
        };

        Ok(response)
    }

    async fn evaluate_package(
        &self,
        package_name: &str,
        requested_version: Option<&str>,
        registry: PackageRegistry,
        context: &str,
    ) -> Result<ToolResponse, McpError> {
        let cache_key = cache_key_for_package(registry, package_name, requested_version);

        if let Some(cached) = self
            .cache
            .get(&cache_key)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            && let Ok(response) = serde_json::from_str::<ToolResponse>(&cached)
        {
            self.log_decision(
                context,
                registry,
                package_name,
                requested_version,
                response.allow,
                response.risk,
                response.reasons.clone(),
                Some(response.metadata.clone()),
                true,
            );
            return Ok(response);
        }

        let registry_kind: RegistryKind = registry.into();
        let report = match registry_kind {
            RegistryKind::Npm => {
                checks::run_all_checks(
                    package_name,
                    requested_version,
                    self.npm_client.as_ref(),
                    self.config.as_ref(),
                )
                .await
            }
            RegistryKind::Cargo => {
                checks::run_all_checks(
                    package_name,
                    requested_version,
                    self.cargo_client.as_ref(),
                    self.config.as_ref(),
                )
                .await
            }
        }
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let response = ToolResponse {
            allow: report.allow,
            risk: report.risk,
            reasons: report.reasons,
            metadata: report.metadata,
        };

        let encoded = serde_json::to_string(&response)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        self.cache
            .set(&cache_key, &encoded)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        self.log_decision(
            context,
            registry,
            package_name,
            requested_version,
            response.allow,
            response.risk,
            response.reasons.clone(),
            Some(response.metadata.clone()),
            false,
        );

        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    fn log_decision(
        &self,
        context: &str,
        registry: PackageRegistry,
        package_name: &str,
        requested_version: Option<&str>,
        allow: bool,
        risk: Severity,
        reasons: Vec<String>,
        metadata: Option<Metadata>,
        cached: bool,
    ) {
        let record = AuditRecord::package_decision(
            context,
            package_name,
            requested_version,
            registry.as_str(),
            allow,
            risk,
            reasons,
            metadata,
            cached,
        );
        if let Err(err) = self.audit_logger.log(record) {
            tracing::warn!("failed to append audit log record: {err}");
        }
    }
}

#[tool_handler]
impl ServerHandler for SafePkgsServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Package safety checker for supported registries (currently npm and cargo). Call check_package before package installation or check_lockfile for batch dependency review.".into(),
            ),
        }
    }
}

fn cache_key_for_package(
    registry: PackageRegistry,
    package_name: &str,
    requested_version: Option<&str>,
) -> String {
    let version = requested_version.unwrap_or("latest");
    format!(
        "check_package:{}:{}@{}",
        registry.cache_segment(),
        package_name,
        version
    )
}

fn resolve_dependency_input(path: Option<&str>) -> anyhow::Result<PathBuf> {
    let candidate = match path {
        Some(value) => PathBuf::from(value),
        None => std::env::current_dir()?,
    };

    if candidate.is_file() {
        return validate_dependency_file(candidate.as_path());
    }

    if !candidate.is_dir() {
        anyhow::bail!(
            "dependency input path does not exist: {}",
            candidate.display()
        );
    }

    let lockfile_path = candidate.join("package-lock.json");
    if lockfile_path.exists() {
        return Ok(lockfile_path);
    }

    let manifest_path = candidate.join("package.json");
    if manifest_path.exists() {
        return Ok(manifest_path);
    }

    anyhow::bail!(
        "no package-lock.json or package.json found at {}",
        candidate.display()
    )
}

fn validate_dependency_file(path: &Path) -> anyhow::Result<PathBuf> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        anyhow::bail!("invalid dependency input path: {}", path.display());
    };

    if file_name == "package-lock.json" || file_name == "package.json" {
        return Ok(path.to_path_buf());
    }

    anyhow::bail!(
        "unsupported file '{}' (expected package-lock.json or package.json)",
        file_name
    )
}

fn parse_npm_dependencies(path: &Path) -> anyhow::Result<Vec<PackageSpec>> {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        anyhow::bail!("invalid dependency input path: {}", path.display());
    };

    match file_name {
        "package-lock.json" => parse_package_lock(path),
        "package.json" => parse_package_manifest(path),
        _ => anyhow::bail!("unsupported dependency input file '{}'", file_name),
    }
}

fn parse_package_lock(path: &Path) -> anyhow::Result<Vec<PackageSpec>> {
    let raw = fs::read_to_string(path)?;
    let root: serde_json::Value = serde_json::from_str(&raw)?;
    let mut dependencies = BTreeMap::<String, Option<String>>::new();

    if let Some(top_level) = root.get("dependencies").and_then(|value| value.as_object()) {
        for (name, value) in top_level {
            let raw_version = value
                .as_object()
                .and_then(|obj| obj.get("version"))
                .and_then(|version| version.as_str())
                .or_else(|| value.as_str());
            dependencies.insert(
                name.to_string(),
                raw_version.and_then(normalize_requested_version),
            );
        }
    }

    if dependencies.is_empty()
        && let Some(packages) = root.get("packages").and_then(|value| value.as_object())
    {
        for (module_path, value) in packages {
            let Some(name) = extract_package_name_from_node_modules_path(module_path) else {
                continue;
            };
            let raw_version = value
                .as_object()
                .and_then(|obj| obj.get("version"))
                .and_then(|version| version.as_str());
            dependencies
                .entry(name)
                .or_insert_with(|| raw_version.and_then(normalize_requested_version));
        }
    }

    Ok(dependencies
        .into_iter()
        .map(|(name, version)| PackageSpec { name, version })
        .collect())
}

fn parse_package_manifest(path: &Path) -> anyhow::Result<Vec<PackageSpec>> {
    let raw = fs::read_to_string(path)?;
    let root: serde_json::Value = serde_json::from_str(&raw)?;
    let mut dependencies = BTreeMap::<String, Option<String>>::new();

    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(items) = root.get(section).and_then(|value| value.as_object()) else {
            continue;
        };
        for (name, raw_version) in items {
            dependencies.insert(
                name.to_string(),
                raw_version.as_str().and_then(normalize_requested_version),
            );
        }
    }

    Ok(dependencies
        .into_iter()
        .map(|(name, version)| PackageSpec { name, version })
        .collect())
}

fn extract_package_name_from_node_modules_path(module_path: &str) -> Option<String> {
    let marker = "node_modules/";
    let idx = module_path.rfind(marker)?;
    let remainder = &module_path[idx + marker.len()..];
    if remainder.is_empty() {
        return None;
    }

    Some(remainder.to_string())
}

fn normalize_requested_version(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.eq_ignore_ascii_case("latest") {
        return Some("latest".to_string());
    }

    let candidate = trimmed.strip_prefix('=').unwrap_or(trimmed);
    if Version::parse(candidate).is_ok() {
        return Some(candidate.to_string());
    }

    None
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
