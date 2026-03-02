//! Shared application service for package and lockfile evaluation.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use tokio::task::JoinSet;

use safe_pkgs_core::DependencySpec;

use crate::audit_log::{AuditLogger, AuditRecord, PackageDecision};
use crate::cache::SqliteCache;
use crate::checks;
use crate::config::SafePkgsConfig;
use crate::policy_snapshot::{RegistryPolicySnapshot, build_registry_policy_snapshot};
use crate::registries::{RegistryCatalog, register_default_catalog};
use crate::types::{
    DecisionFingerprints, DependencyAncestry, DependencyAncestryPath, Evidence, EvidenceKind,
    LockfilePackageResult, LockfileResponse, Severity, ToolResponse,
};

/// Maximum number of packages evaluated concurrently during a lockfile audit.
const LOCKFILE_EVAL_CONCURRENCY: usize = 10;

/// Marker error type that distinguishes audit log failures from check failures.
///
/// This allows callers to detect audit log errors via typed downcast rather than
/// fragile string matching on the error chain.
#[derive(Debug)]
struct AuditLogError(String);

impl std::fmt::Display for AuditLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to append audit log record: {}", self.0)
    }
}

impl std::error::Error for AuditLogError {}

/// Core runtime service for package and lockfile evaluation.
#[derive(Clone)]
pub struct SafePkgsService {
    registries: RegistryCatalog,
    config: Arc<SafePkgsConfig>,
    config_fingerprint: String,
    policy_snapshots: Arc<BTreeMap<String, RegistryPolicySnapshot>>,
    evaluation_time_override: Option<DateTime<Utc>>,
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
        Self::with_cache(config, cache, audit_logger)
    }

    #[cfg(test)]
    /// Creates a service for tests using in-memory cache.
    pub fn with_config(config: SafePkgsConfig) -> Self {
        let cache = SqliteCache::in_memory(config.cache.ttl_minutes)
            .expect("in-memory sqlite cache for test service");
        let audit_logger = AuditLogger::new().expect("audit logger");
        Self::with_cache(config, cache, audit_logger).expect("service init for tests")
    }

    fn with_cache(
        config: SafePkgsConfig,
        cache: SqliteCache,
        audit_logger: AuditLogger,
    ) -> anyhow::Result<Self> {
        let registries = register_default_catalog();
        let config_fingerprint = compute_config_fingerprint(&config)?;
        let policy_snapshots = build_policy_snapshots_by_registry(&registries, &config)?;
        let evaluation_time_override = load_evaluation_time_override()?;
        Ok(Self {
            registries,
            config: Arc::new(config),
            config_fingerprint,
            policy_snapshots: Arc::new(policy_snapshots),
            evaluation_time_override,
            cache: Arc::new(cache),
            audit_logger: Arc::new(audit_logger),
        })
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
        crate::registries::validate_lockfile_request(registry, path).map_err(anyhow::Error::msg)?;

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
        let registry_policy = self.policy_snapshot_for_registry(registry_key)?;
        let evaluation_time = self.current_evaluation_time();
        let evaluation_time_rfc3339 = evaluation_time.to_rfc3339();

        if !package_names.is_empty() {
            if requirements.needs_weekly_downloads
                && let Err(err) = plugin
                    .client()
                    .prefetch_weekly_downloads(&package_names)
                    .await
            {
                tracing::warn!("registry prefetch failed for {registry}: {err}");
            }

            if requirements.needs_popular_package_names
                && let Err(err) = plugin.client().prefetch_popular_package_names().await
            {
                tracing::warn!("popular package prefetch failed for {registry}: {err}");
            }
        }

        // Evaluate packages concurrently with a bounded pool, preserving lockfile order.
        let total = package_specs.len();
        let mut queue = package_specs.into_iter().enumerate();
        let mut join_set: JoinSet<(usize, DependencySpec, anyhow::Result<ToolResponse>)> =
            JoinSet::new();
        let mut ordered: Vec<Option<(DependencySpec, anyhow::Result<ToolResponse>)>> =
            (0..total).map(|_| None).collect();

        // Seed the initial batch of concurrent tasks.
        for (idx, spec) in queue.by_ref().take(LOCKFILE_EVAL_CONCURRENCY) {
            let svc = self.clone();
            let ctx = context.to_string();
            let reg = registry_key.to_string();
            join_set.spawn(async move {
                let result = svc
                    .evaluate_package_at_time(
                        &spec.name,
                        spec.version.as_deref(),
                        &reg,
                        &ctx,
                        evaluation_time,
                    )
                    .await;
                (idx, spec, result)
            });
        }

        while let Some(task_result) = join_set.join_next().await {
            let (idx, spec, result) = task_result.expect("lockfile eval task panicked");

            // Audit log failures are fatal — abort the entire audit immediately.
            if let Err(ref err) = result {
                if is_audit_log_failure(err) {
                    return Err(result.unwrap_err());
                }
            }

            ordered[idx] = Some((spec, result));

            // Keep the concurrency pool full as slots open up.
            if let Some((next_idx, next_spec)) = queue.next() {
                let svc = self.clone();
                let ctx = context.to_string();
                let reg = registry_key.to_string();
                join_set.spawn(async move {
                    let result = svc
                        .evaluate_package_at_time(
                            &next_spec.name,
                            next_spec.version.as_deref(),
                            &reg,
                            &ctx,
                            evaluation_time,
                        )
                        .await;
                    (next_idx, next_spec, result)
                });
            }
        }

        // Aggregate results in original lockfile order.
        let mut risk = Severity::Low;
        let mut denied = 0usize;
        let mut packages = Vec::with_capacity(total);

        for item in ordered {
            let Some((spec, result)) = item else { continue };
            match result {
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
                        evidence: response.evidence,
                        dependency_ancestry: dependency_ancestry_for(&spec.dependency_paths),
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
                        evidence: vec![runtime_error_evidence(&reason)],
                        dependency_ancestry: dependency_ancestry_for(&spec.dependency_paths),
                    });
                    self.log_decision(PackageDecision {
                        context,
                        registry: registry_key,
                        package: spec.name.as_str(),
                        requested: spec.version.as_deref(),
                        allow: false,
                        risk: Severity::Critical,
                        reasons: vec![reason],
                        evidence: vec![runtime_error_evidence(&err.to_string())],
                        metadata: None,
                        policy_snapshot_version: registry_policy.version,
                        config_fingerprint: self.config_fingerprint.as_str(),
                        policy_fingerprint: registry_policy.policy_fingerprint.as_str(),
                        enabled_checks: registry_policy.enabled_checks.clone(),
                        evaluation_time: evaluation_time_rfc3339.clone(),
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
            fingerprints: DecisionFingerprints {
                config: self.config_fingerprint.clone(),
                policy: registry_policy.policy_fingerprint.clone(),
            },
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
        let evaluation_time = self.current_evaluation_time();
        self.evaluate_package_at_time(
            package_name,
            requested_version,
            registry,
            context,
            evaluation_time,
        )
        .await
    }

    async fn evaluate_package_at_time(
        &self,
        package_name: &str,
        requested_version: Option<&str>,
        registry: &str,
        context: &str,
        evaluation_time: DateTime<Utc>,
    ) -> anyhow::Result<ToolResponse> {
        let Some(plugin) = self.registries.package_plugin(registry) else {
            return Err(invalid_registry_error(
                "package",
                registry,
                self.registries.package_registry_keys(),
            ));
        };
        let registry_key = plugin.key();
        let policy_snapshot = self.policy_snapshot_for_registry(registry_key)?;
        let cache_key = cache_key_for_package(
            policy_snapshot.policy_fingerprint.as_str(),
            registry_key,
            package_name,
            requested_version,
        );
        let evaluation_time_rfc3339 = evaluation_time.to_rfc3339();

        if let Some(cached) = self.cache.get(&cache_key)?
            && let Ok(response) = serde_json::from_str::<ToolResponse>(&cached)
        {
            self.log_decision(PackageDecision {
                context,
                registry: registry_key,
                package: package_name,
                requested: requested_version,
                allow: response.allow,
                risk: response.risk,
                reasons: response.reasons.clone(),
                evidence: response.evidence.clone(),
                metadata: Some(response.metadata.clone()),
                policy_snapshot_version: policy_snapshot.version,
                config_fingerprint: self.config_fingerprint.as_str(),
                policy_fingerprint: policy_snapshot.policy_fingerprint.as_str(),
                enabled_checks: policy_snapshot.enabled_checks.clone(),
                evaluation_time: evaluation_time_rfc3339.clone(),
                cached: true,
            })?;
            return Ok(response);
        }

        let report = checks::run_all_checks_at_time(
            package_name,
            requested_version,
            registry_key,
            plugin.supported_checks(),
            plugin.client(),
            self.config.as_ref(),
            evaluation_time,
        )
        .await?;

        let response = ToolResponse {
            allow: report.allow,
            risk: report.risk,
            reasons: report.reasons,
            evidence: report.evidence,
            metadata: report.metadata,
            fingerprints: DecisionFingerprints {
                config: self.config_fingerprint.clone(),
                policy: policy_snapshot.policy_fingerprint.clone(),
            },
        };

        let encoded = serde_json::to_string(&response)?;
        self.cache.set(&cache_key, &encoded)?;

        self.log_decision(PackageDecision {
            context,
            registry: registry_key,
            package: package_name,
            requested: requested_version,
            allow: response.allow,
            risk: response.risk,
            reasons: response.reasons.clone(),
            evidence: response.evidence.clone(),
            metadata: Some(response.metadata.clone()),
            policy_snapshot_version: policy_snapshot.version,
            config_fingerprint: self.config_fingerprint.as_str(),
            policy_fingerprint: policy_snapshot.policy_fingerprint.as_str(),
            enabled_checks: policy_snapshot.enabled_checks.clone(),
            evaluation_time: evaluation_time_rfc3339,
            cached: false,
        })?;

        Ok(response)
    }

    fn policy_snapshot_for_registry(
        &self,
        registry_key: &str,
    ) -> anyhow::Result<&RegistryPolicySnapshot> {
        let normalized = registry_key.to_ascii_lowercase();
        self.policy_snapshots
            .get(normalized.as_str())
            .ok_or_else(|| anyhow!("missing policy snapshot for registry '{registry_key}'"))
    }

    fn current_evaluation_time(&self) -> DateTime<Utc> {
        self.evaluation_time_override.unwrap_or_else(Utc::now)
    }

    fn log_decision(&self, decision: PackageDecision<'_>) -> anyhow::Result<()> {
        let record = AuditRecord::package_decision(decision);
        self.audit_logger
            .log(record)
            .map_err(|source| anyhow::Error::new(AuditLogError(source.to_string())))
    }
}

fn cache_key_for_package(
    policy_fingerprint: &str,
    registry: &str,
    package_name: &str,
    requested_version: Option<&str>,
) -> String {
    // Policy fingerprint is part of the key so policy changes naturally cold-miss
    // old cache entries and rebuild them under the new policy scope.
    let version = requested_version.unwrap_or("latest");
    format!(
        "check_package:{}:{}:{}@{}",
        policy_fingerprint, registry, package_name, version
    )
}

fn compute_config_fingerprint(config: &SafePkgsConfig) -> anyhow::Result<String> {
    crate::policy_snapshot::compute_config_fingerprint(config)
}

fn build_policy_snapshots_by_registry(
    registries: &RegistryCatalog,
    config: &SafePkgsConfig,
) -> anyhow::Result<BTreeMap<String, RegistryPolicySnapshot>> {
    let mut snapshots = BTreeMap::new();
    for registry_key in registries.package_registry_keys() {
        let Some(plugin) = registries.package_plugin(registry_key) else {
            return Err(anyhow!(
                "registry '{}' missing from catalog when building policy snapshots",
                registry_key
            ));
        };

        let enabled_checks =
            checks::enabled_check_ids_for_registry(plugin.key(), plugin.supported_checks(), config);
        let snapshot = build_registry_policy_snapshot(config, plugin.key(), &enabled_checks)?;
        snapshots.insert(plugin.key().to_string(), snapshot);
    }
    Ok(snapshots)
}

fn load_evaluation_time_override() -> anyhow::Result<Option<DateTime<Utc>>> {
    let Some(raw) = std::env::var_os("SAFE_PKGS_EVALUATION_TIME") else {
        return Ok(None);
    };
    let raw = raw.to_string_lossy();
    let parsed = chrono::DateTime::parse_from_rfc3339(raw.as_ref())
        .with_context(|| {
            format!(
                "failed to parse SAFE_PKGS_EVALUATION_TIME='{}' as RFC3339 timestamp",
                raw
            )
        })?
        .with_timezone(&Utc);
    Ok(Some(parsed))
}

fn invalid_registry_error(kind: &str, registry: &str, supported: &[&str]) -> anyhow::Error {
    anyhow!(
        "unsupported {kind} registry '{}'; supported registries: {}",
        registry,
        supported.join(", ")
    )
}

fn is_audit_log_failure(err: &anyhow::Error) -> bool {
    err.downcast_ref::<AuditLogError>().is_some()
}

fn runtime_error_evidence(message: &str) -> Evidence {
    Evidence {
        kind: EvidenceKind::Runtime,
        id: "lockfile.package_check_failed".to_string(),
        severity: Severity::Critical,
        message: message.to_string(),
        facts: std::collections::BTreeMap::new(),
    }
}

/// Converts raw ancestry path vectors into the named response object.
///
/// Returns `None` when no ancestry is present (direct dependencies).
fn dependency_ancestry_for(dependency_paths: &[Vec<String>]) -> Option<DependencyAncestry> {
    if dependency_paths.is_empty() {
        return None;
    }

    Some(DependencyAncestry {
        paths: dependency_paths
            .iter()
            .cloned()
            .map(|ancestors| DependencyAncestryPath { ancestors })
            .collect(),
    })
}

#[cfg(test)]
#[path = "tests/service.rs"]
mod tests;
