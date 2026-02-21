//! Shared application service for package and lockfile evaluation.

use std::sync::Arc;

use anyhow::{Context, anyhow};

use crate::audit_log::{AuditLogger, AuditRecord, PackageDecision};
use crate::cache::SqliteCache;
use crate::checks;
use crate::config::SafePkgsConfig;
use crate::registries::{RegistryCatalog, register_default_catalog};
use crate::types::{LockfilePackageResult, LockfileResponse, Metadata, Severity, ToolResponse};

const AUDIT_LOG_FAILURE_CONTEXT: &str = "failed to append audit log record";

/// Core runtime service for package and lockfile evaluation.
#[derive(Clone)]
pub struct SafePkgsService {
    registries: RegistryCatalog,
    config: Arc<SafePkgsConfig>,
    cache: Arc<SqliteCache>,
    audit_logger: Arc<AuditLogger>,
}

impl SafePkgsService {
    /// Creates a service using default config, on-disk cache, and audit log.
    ///
    /// # Errors
    ///
    /// Returns an error if config, cache, or audit logger initialization fails.
    pub fn new() -> anyhow::Result<Self> {
        let config = SafePkgsConfig::load()?;
        let cache = SqliteCache::new(config.cache.ttl_minutes)?;
        let audit_logger = AuditLogger::new()?;
        Ok(Self::with_cache(config, cache, audit_logger))
    }

    #[cfg(test)]
    /// Creates a service for tests using in-memory cache.
    pub fn with_config(config: SafePkgsConfig) -> Self {
        let cache = SqliteCache::in_memory(config.cache.ttl_minutes)
            .expect("in-memory sqlite cache for test service");
        let audit_logger = AuditLogger::new().expect("audit logger");
        Self::with_cache(config, cache, audit_logger)
    }

    fn with_cache(config: SafePkgsConfig, cache: SqliteCache, audit_logger: AuditLogger) -> Self {
        Self {
            registries: register_default_catalog(),
            config: Arc::new(config),
            cache: Arc::new(cache),
            audit_logger: Arc::new(audit_logger),
        }
    }

    /// Runs a lockfile audit for a dependency file or project path.
    ///
    /// # Errors
    ///
    /// Returns an error when parser or package evaluation fails.
    pub async fn run_lockfile_audit(
        &self,
        path: Option<&str>,
        registry: &str,
        context: &str,
    ) -> anyhow::Result<LockfileResponse> {
        let Some(plugin) = self.registries.lockfile_plugin(registry) else {
            return Err(invalid_registry_error(
                "lockfile",
                registry,
                self.registries.lockfile_registry_keys(),
            ));
        };
        let Some(lockfile_parser) = plugin.lockfile_parser() else {
            return Err(invalid_registry_error(
                "lockfile",
                registry,
                self.registries.lockfile_registry_keys(),
            ));
        };
        let registry_key = plugin.key();

        let input_path = lockfile_parser.resolve_input(path)?;
        let package_specs = lockfile_parser.parse_dependencies(&input_path)?;
        let package_names = package_specs
            .iter()
            .map(|spec| spec.name.clone())
            .collect::<Vec<_>>();

        let requirements = checks::runtime_requirements_for_registry(
            registry_key,
            plugin.supported_checks(),
            self.config.as_ref(),
        );

        if requirements.needs_weekly_downloads
            && let Err(err) = plugin
                .client()
                .prefetch_weekly_downloads(&package_names)
                .await
        {
            tracing::warn!("registry prefetch failed for {registry}: {err}");
        }

        let mut risk = Severity::Low;
        let mut denied = 0usize;
        let mut packages = Vec::with_capacity(package_specs.len());

        for spec in package_specs {
            match self
                .evaluate_package(&spec.name, spec.version.as_deref(), registry_key, context)
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
                    if is_audit_log_failure(&err) {
                        return Err(err);
                    }

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
                    self.log_decision(DecisionLogInput {
                        context,
                        registry: registry_key,
                        package_name: spec.name.as_str(),
                        requested_version: spec.version.as_deref(),
                        allow: false,
                        risk: Severity::Critical,
                        reasons: vec![reason],
                        metadata: None,
                        cached: false,
                    })?;
                }
            }
        }

        Ok(LockfileResponse {
            allow: denied == 0,
            risk,
            total: packages.len(),
            denied,
            packages,
        })
    }

    /// Runs a lockfile audit with an explicit path and registry.
    ///
    /// # Errors
    ///
    /// Returns an error when parser or package evaluation fails.
    pub async fn audit_lockfile_path_with_registry(
        &self,
        path: &str,
        registry: &str,
    ) -> anyhow::Result<LockfileResponse> {
        self.run_lockfile_audit(Some(path), registry, "cli_audit")
            .await
    }

    /// Evaluates one package request and returns its decision payload.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid registries, cache failures, or check/runtime failures.
    pub async fn evaluate_package(
        &self,
        package_name: &str,
        requested_version: Option<&str>,
        registry: &str,
        context: &str,
    ) -> anyhow::Result<ToolResponse> {
        let Some(plugin) = self.registries.package_plugin(registry) else {
            return Err(invalid_registry_error(
                "package",
                registry,
                self.registries.package_registry_keys(),
            ));
        };
        let registry_key = plugin.key();
        let cache_key = cache_key_for_package(registry_key, package_name, requested_version);

        if let Some(cached) = self.cache.get(&cache_key)?
            && let Ok(response) = serde_json::from_str::<ToolResponse>(&cached)
        {
            self.log_decision(DecisionLogInput {
                context,
                registry: registry_key,
                package_name,
                requested_version,
                allow: response.allow,
                risk: response.risk,
                reasons: response.reasons.clone(),
                metadata: Some(response.metadata.clone()),
                cached: true,
            })?;
            return Ok(response);
        }

        let report = checks::run_all_checks(
            package_name,
            requested_version,
            registry_key,
            plugin.supported_checks(),
            plugin.client(),
            self.config.as_ref(),
        )
        .await?;

        let response = ToolResponse {
            allow: report.allow,
            risk: report.risk,
            reasons: report.reasons,
            metadata: report.metadata,
        };

        let encoded = serde_json::to_string(&response)?;
        self.cache.set(&cache_key, &encoded)?;

        self.log_decision(DecisionLogInput {
            context,
            registry: registry_key,
            package_name,
            requested_version,
            allow: response.allow,
            risk: response.risk,
            reasons: response.reasons.clone(),
            metadata: Some(response.metadata.clone()),
            cached: false,
        })?;

        Ok(response)
    }

    fn log_decision(&self, input: DecisionLogInput<'_>) -> anyhow::Result<()> {
        let record = AuditRecord::package_decision(PackageDecision {
            context: input.context,
            package: input.package_name,
            requested: input.requested_version,
            registry: input.registry,
            allow: input.allow,
            risk: input.risk,
            reasons: input.reasons,
            metadata: input.metadata,
            cached: input.cached,
        });
        self.audit_logger
            .log(record)
            .context(AUDIT_LOG_FAILURE_CONTEXT)
    }
}

fn cache_key_for_package(
    registry: &str,
    package_name: &str,
    requested_version: Option<&str>,
) -> String {
    let version = requested_version.unwrap_or("latest");
    format!("check_package:{}:{}@{}", registry, package_name, version)
}

fn invalid_registry_error(kind: &str, registry: &str, supported: &[&str]) -> anyhow::Error {
    anyhow!(
        "unsupported {kind} registry '{}'; supported registries: {}",
        registry,
        supported.join(", ")
    )
}

fn is_audit_log_failure(err: &anyhow::Error) -> bool {
    err.to_string().contains(AUDIT_LOG_FAILURE_CONTEXT)
}

struct DecisionLogInput<'a> {
    context: &'a str,
    registry: &'a str,
    package_name: &'a str,
    requested_version: Option<&'a str>,
    allow: bool,
    risk: Severity,
    reasons: Vec<String>,
    metadata: Option<Metadata>,
    cached: bool,
}

#[cfg(test)]
#[path = "tests/service.rs"]
mod tests;
