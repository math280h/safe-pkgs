//! Check orchestration for single-package evaluations.

use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use safe_pkgs_core::{
    Check, CheckExecutionContext, CheckId, CheckPolicy, FindingValue, Metadata, PackageRecord,
    PackageVersion, RegistryClient, RegistryError, Severity, StalenessPolicy, normalize_check_id,
};
use serde_json::json;

use crate::config::SafePkgsConfig;
use crate::custom_rules;
use crate::types::{Evidence, EvidenceKind};

/// Lightweight metadata about each registered check.
#[derive(Debug, Clone, Copy)]
pub struct CheckDescriptor {
    /// Stable check id (for config and support maps).
    pub id: CheckId,
    /// Short description of what the check does.
    pub description: &'static str,
    /// Whether the check needs weekly download data.
    pub needs_weekly_downloads: bool,
    /// Whether the check needs advisory data.
    pub needs_advisories: bool,
}

/// Data-fetch requirements derived from enabled checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct CheckRuntimeRequirements {
    /// True when at least one enabled check needs weekly downloads.
    pub needs_weekly_downloads: bool,
    /// True when at least one enabled check needs advisories.
    pub needs_advisories: bool,
    /// True when at least one enabled check needs popular package name data.
    pub needs_popular_package_names: bool,
}

/// Final result produced by running all enabled checks.
#[derive(Debug)]
pub struct CheckReport {
    /// Whether install is allowed under configured risk policy.
    pub allow: bool,
    /// Aggregated risk level across all findings.
    pub risk: Severity,
    /// Human-readable reasons for the decision.
    pub reasons: Vec<String>,
    /// Machine-readable evidence for each emitted finding/policy outcome.
    pub evidence: Vec<Evidence>,
    /// Collected metadata included in the response.
    pub metadata: Metadata,
}

/// Returns descriptors for all checks registered by the application.
pub fn check_descriptors() -> Vec<CheckDescriptor> {
    // Used by support-map and external tooling.
    registered_checks()
        .iter()
        .map(|check| CheckDescriptor {
            id: check.id(),
            description: check.description(),
            needs_weekly_downloads: check.needs_weekly_downloads(),
            needs_advisories: check.needs_advisories(),
        })
        .collect()
}

/// Computes prefetch requirements for checks enabled on a registry.
pub fn runtime_requirements_for_registry(
    registry_key: &str,
    supported_checks: &[CheckId],
    config: &SafePkgsConfig,
) -> CheckRuntimeRequirements {
    // Compute what extra data this registry run may need to prefetch.
    let checks = enabled_checks(
        registry_key,
        supported_checks,
        PackageLookupState::Ready,
        config,
    );
    let custom_requirements = custom_rules::runtime_requirements_for_registry(config, registry_key);
    CheckRuntimeRequirements {
        needs_weekly_downloads: checks.iter().any(|check| check.needs_weekly_downloads()),
        needs_advisories: checks.iter().any(|check| check.needs_advisories()),
        needs_popular_package_names: checks
            .iter()
            .any(|check| check.needs_popular_package_names()),
    }
    .merge(custom_requirements)
}

/// Returns deterministic enabled check ids for a registry under current config.
pub fn enabled_check_ids_for_registry(
    registry_key: &str,
    supported_checks: &[CheckId],
    config: &SafePkgsConfig,
) -> Vec<String> {
    let mut ids = enabled_checks(
        registry_key,
        supported_checks,
        PackageLookupState::Ready,
        config,
    )
    .into_iter()
    .map(|check| normalize_check_id(check.id()))
    .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

/// Runs policy checks for a single package and version request.
///
/// # Errors
///
/// Returns a registry error when required upstream calls fail.
#[cfg(test)]
pub async fn run_all_checks(
    package_name: &str,
    requested_version: Option<&str>,
    registry_key: &str,
    supported_checks: &[CheckId],
    registry_client: &dyn RegistryClient,
    config: &SafePkgsConfig,
) -> Result<CheckReport, RegistryError> {
    run_all_checks_at_time(
        package_name,
        requested_version,
        registry_key,
        supported_checks,
        registry_client,
        config,
        Utc::now(),
    )
    .await
}

/// Runs policy checks for a single package and version request at a fixed timestamp.
///
/// # Errors
///
/// Returns a registry error when required upstream calls fail.
pub async fn run_all_checks_at_time(
    package_name: &str,
    requested_version: Option<&str>,
    registry_key: &str,
    supported_checks: &[CheckId],
    registry_client: &dyn RegistryClient,
    config: &SafePkgsConfig,
    evaluation_time: DateTime<Utc>,
) -> Result<CheckReport, RegistryError> {
    // Fast path: denylist package rules always block before any registry calls.
    if let Some(rule) = matching_package_rule(
        &config.denylist.packages,
        package_name,
        requested_version,
        None,
    ) {
        let reason = format!("{package_name} matched denylist package rule '{rule}'");
        return Ok(deny_report(
            reason.clone(),
            vec![policy_evidence(
                "denylist.package",
                Severity::Critical,
                reason,
                [
                    ("package", json!(package_name)),
                    ("matched_rule", json!(rule)),
                ],
            )],
            Metadata {
                latest: None,
                requested: requested_version.map(ToOwned::to_owned),
                published: None,
                weekly_downloads: None,
            },
        ));
    }

    let package = match registry_client.fetch_package(package_name).await {
        Ok(package) => Some(package),
        // Missing package is handled by checks (primarily existence), not as a transport error.
        Err(RegistryError::NotFound { .. }) => None,
        Err(err) => return Err(err),
    };
    let resolved_version = package
        .as_ref()
        .and_then(|record| record.resolve_version(requested_version));

    if let (Some(package), Some(resolved_version)) = (package.as_ref(), resolved_version) {
        // Re-evaluate package rules with resolved version metadata when available.
        if let Some(rule) = matching_package_rule(
            &config.denylist.packages,
            package_name,
            requested_version,
            Some(&resolved_version.version),
        ) {
            let reason = format!("{package_name} matched denylist package rule '{rule}'");
            return Ok(deny_report(
                reason.clone(),
                vec![policy_evidence(
                    "denylist.package",
                    Severity::Critical,
                    reason,
                    [
                        ("package", json!(package_name)),
                        ("matched_rule", json!(rule)),
                        ("resolved_version", json!(resolved_version.version.as_str())),
                    ],
                )],
                Metadata {
                    latest: Some(package.latest.clone()),
                    requested: requested_version.map(ToOwned::to_owned),
                    published: resolved_version.published.map(|ts| ts.to_rfc3339()),
                    weekly_downloads: None,
                },
            ));
        }

        if let Some(publisher) =
            matching_publisher(&config.denylist.publishers, &package.publishers)
        {
            let reason =
                format!("{package_name} is published by denylisted publisher '{publisher}'");
            return Ok(deny_report(
                reason.clone(),
                vec![policy_evidence(
                    "denylist.publisher",
                    Severity::Critical,
                    reason,
                    [
                        ("package", json!(package_name)),
                        ("publisher", json!(publisher)),
                    ],
                )],
                Metadata {
                    latest: Some(package.latest.clone()),
                    requested: requested_version.map(ToOwned::to_owned),
                    published: resolved_version.published.map(|ts| ts.to_rfc3339()),
                    weekly_downloads: None,
                },
            ));
        }

        if let Some(rule) = matching_package_rule(
            &config.allowlist.packages,
            package_name,
            requested_version,
            Some(&resolved_version.version),
        ) {
            let reason = format!("{package_name} matched allowlist package rule '{rule}'");
            return Ok(allow_report(
                reason.clone(),
                vec![policy_evidence(
                    "allowlist.package",
                    Severity::Low,
                    reason,
                    [
                        ("package", json!(package_name)),
                        ("matched_rule", json!(rule)),
                        ("resolved_version", json!(resolved_version.version.as_str())),
                    ],
                )],
                Metadata {
                    latest: Some(package.latest.clone()),
                    requested: requested_version.map(ToOwned::to_owned),
                    published: resolved_version.published.map(|ts| ts.to_rfc3339()),
                    weekly_downloads: None,
                },
            ));
        }
    }

    let lookup_state = package_lookup_state(package.as_ref(), resolved_version);
    let checks = enabled_checks(registry_key, supported_checks, lookup_state, config);
    let requirements = CheckRuntimeRequirements {
        needs_weekly_downloads: checks.iter().any(|check| check.needs_weekly_downloads()),
        needs_advisories: checks.iter().any(|check| check.needs_advisories()),
        needs_popular_package_names: checks
            .iter()
            .any(|check| check.needs_popular_package_names()),
    }
    .merge(custom_rules::runtime_requirements_for_registry(
        config,
        registry_key,
    ));

    let metadata = Metadata {
        latest: package.as_ref().map(|record| record.latest.clone()),
        requested: requested_version.map(ToOwned::to_owned),
        published: resolved_version.and_then(|version| version.published.map(|ts| ts.to_rfc3339())),
        // Avoid extra registry calls when no enabled check depends on downloads.
        weekly_downloads: if resolved_version.is_some() && requirements.needs_weekly_downloads {
            registry_client.fetch_weekly_downloads(package_name).await?
        } else {
            None
        },
    };

    let advisories = if requirements.needs_advisories {
        // Advisory checks only run when a concrete version exists.
        if let Some(version) = resolved_version {
            registry_client
                .fetch_advisories(package_name, &version.version)
                .await?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let policy = check_policy_from_config(config);
    // Shared execution context passed to each check implementation.
    let execution_context = CheckExecutionContext {
        registry_key,
        package_name,
        requested_version,
        evaluation_time,
        package: package.as_ref(),
        resolved_version,
        weekly_downloads: metadata.weekly_downloads,
        advisories: &advisories,
        registry_client,
        policy: &policy,
    };

    let mut findings = Vec::new();
    for check in checks {
        let check_id = check.id();
        findings.extend(
            check
                .run(&execution_context)
                .await?
                .into_iter()
                .map(|finding| {
                    let severity = finding.severity;
                    let reason = finding.reason.clone();
                    let evidence_id = format!("{check_id}.{}", finding.reason_code);
                    StructuredFinding {
                        severity,
                        reason: reason.clone(),
                        evidence: Evidence {
                            kind: EvidenceKind::Check,
                            id: evidence_id,
                            severity,
                            message: reason,
                            facts: finding
                                .facts
                                .into_iter()
                                .map(|(key, value)| (key, finding_value_to_json(value)))
                                .collect(),
                        },
                    }
                }),
        );
    }
    findings.extend(
        custom_rules::findings_for_package(config, &execution_context)
            .into_iter()
            .map(|custom| {
                let severity = custom.finding.severity;
                let reason = custom.finding.reason.clone();
                let evidence_id = format!("custom_rule.{}", custom.rule_id);
                StructuredFinding {
                    severity,
                    reason: reason.clone(),
                    evidence: Evidence {
                        kind: EvidenceKind::CustomRule,
                        id: evidence_id,
                        severity,
                        message: reason,
                        facts: custom
                            .finding
                            .facts
                            .into_iter()
                            .map(|(key, value)| (key, finding_value_to_json(value)))
                            .collect(),
                    },
                }
            }),
    );

    Ok(report_from_findings(findings, metadata, config.max_risk))
}

impl CheckRuntimeRequirements {
    fn merge(self, custom: custom_rules::CustomRuleRuntimeRequirements) -> Self {
        Self {
            needs_weekly_downloads: self.needs_weekly_downloads || custom.needs_weekly_downloads,
            needs_advisories: self.needs_advisories || custom.needs_advisories,
            needs_popular_package_names: self.needs_popular_package_names,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageLookupState {
    MissingPackage,
    MissingVersion,
    Ready,
}

fn package_lookup_state(
    package: Option<&PackageRecord>,
    resolved_version: Option<&PackageVersion>,
) -> PackageLookupState {
    // Allows checks to declare whether they can run with partial package data.
    if package.is_none() {
        return PackageLookupState::MissingPackage;
    }

    if resolved_version.is_none() {
        return PackageLookupState::MissingVersion;
    }

    PackageLookupState::Ready
}

fn registered_checks() -> &'static [Box<dyn Check>] {
    static CHECKS: OnceLock<Vec<Box<dyn Check>>> = OnceLock::new();
    CHECKS
        .get_or_init(|| {
            // Build once from app wiring and guard against duplicate IDs.
            let mut checks = Vec::new();
            let mut registered_ids = HashSet::new();
            for create_check in crate::app_check_factories() {
                let check = create_check();
                if !registered_ids.insert(check.id()) {
                    panic!("duplicate check registration for '{}'", check.id());
                }
                checks.push(check);
            }
            checks
        })
        .as_slice()
}

fn enabled_checks(
    registry_key: &str,
    supported_checks: &[CheckId],
    lookup_state: PackageLookupState,
    config: &SafePkgsConfig,
) -> Vec<&'static dyn Check> {
    let mut checks = registered_checks()
        .iter()
        .filter(|check| {
            // Some checks may opt to always run even if disabled in config.
            check.always_enabled()
                || config
                    .checks
                    .is_enabled_for_registry(registry_key, check.id(), supported_checks)
        })
        .filter(|check| match lookup_state {
            // Let checks opt into missing-data scenarios.
            PackageLookupState::MissingPackage => check.runs_on_missing_package(),
            PackageLookupState::MissingVersion => check.runs_on_missing_version(),
            PackageLookupState::Ready => true,
        })
        .map(|check| check.as_ref())
        .collect::<Vec<_>>();

    // Lower priority number runs first.
    checks.sort_by_key(|check| check.priority());
    checks
}

fn check_policy_from_config(config: &SafePkgsConfig) -> CheckPolicy {
    CheckPolicy {
        min_version_age_days: config.min_version_age_days,
        min_weekly_downloads: config.min_weekly_downloads,
        staleness: StalenessPolicy {
            warn_major_versions_behind: config.staleness.warn_major_versions_behind,
            warn_minor_versions_behind: config.staleness.warn_minor_versions_behind,
            warn_age_days: config.staleness.warn_age_days,
            ignore_for: config.staleness.ignore_for.clone(),
        },
    }
}

#[derive(Debug)]
/// Internal intermediate finding that keeps user-facing reason text aligned
/// with machine-readable evidence during aggregation.
struct StructuredFinding {
    severity: Severity,
    reason: String,
    evidence: Evidence,
}

fn report_from_findings(
    findings: Vec<StructuredFinding>,
    metadata: Metadata,
    max_risk: Severity,
) -> CheckReport {
    let mut risk = Severity::Low;
    let mut medium_count = 0u32;
    let mut reasons = Vec::with_capacity(findings.len());
    let mut evidence = Vec::with_capacity(findings.len().saturating_add(1));
    for structured in findings {
        if structured.severity == Severity::Medium {
            medium_count = medium_count.saturating_add(1);
        }
        if structured.severity > risk {
            risk = structured.severity;
        }
        reasons.push(structured.reason);
        evidence.push(structured.evidence);
    }

    // Two medium signals are treated as high overall risk.
    if medium_count >= 2 && risk < Severity::High {
        risk = Severity::High;
        evidence.push(policy_evidence(
            "risk.medium_pair_escalation",
            Severity::High,
            "two medium findings escalated risk to high".to_string(),
            [("medium_count", json!(medium_count))],
        ));
    }

    CheckReport {
        allow: risk <= max_risk,
        risk,
        reasons,
        evidence,
        metadata,
    }
}

fn finding_value_to_json(value: FindingValue) -> serde_json::Value {
    match value {
        FindingValue::String(value) => json!(value),
        FindingValue::Integer(value) => json!(value),
        FindingValue::Unsigned(value) => json!(value),
        FindingValue::Bool(value) => json!(value),
        FindingValue::StringList(value) => json!(value),
    }
}

fn policy_evidence<const N: usize>(
    id: &str,
    severity: Severity,
    message: String,
    facts: [(&str, serde_json::Value); N],
) -> Evidence {
    let facts = facts
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect::<BTreeMap<_, _>>();
    Evidence {
        kind: EvidenceKind::Policy,
        id: id.to_string(),
        severity,
        message,
        facts,
    }
}

fn deny_report(reason: String, evidence: Vec<Evidence>, metadata: Metadata) -> CheckReport {
    CheckReport {
        allow: false,
        risk: Severity::Critical,
        reasons: vec![reason],
        evidence,
        metadata,
    }
}

fn allow_report(reason: String, evidence: Vec<Evidence>, metadata: Metadata) -> CheckReport {
    CheckReport {
        allow: true,
        risk: Severity::Low,
        reasons: vec![reason],
        evidence,
        metadata,
    }
}

fn matching_package_rule<'a>(
    rules: &'a [String],
    package_name: &str,
    requested_version: Option<&str>,
    resolved_version: Option<&str>,
) -> Option<&'a str> {
    for rule in rules {
        // Supports either "package" or "package@version".
        // rsplit_once keeps npm-style scoped names intact (e.g. "@scope/pkg@1.2.3").
        if let Some((rule_package, rule_version)) = rule.rsplit_once('@')
            && !rule_package.is_empty()
        {
            if rule_package == package_name
                && (requested_version == Some(rule_version)
                    || resolved_version == Some(rule_version))
            {
                return Some(rule.as_str());
            }
            continue;
        }

        if rule == package_name {
            return Some(rule.as_str());
        }
    }

    None
}

fn matching_publisher<'a>(
    denylist_publishers: &'a [String],
    publishers: &[String],
) -> Option<&'a str> {
    // Publisher match is case-insensitive.
    denylist_publishers.iter().find_map(|denylisted| {
        publishers
            .iter()
            .any(|publisher| publisher.eq_ignore_ascii_case(denylisted))
            .then_some(denylisted.as_str())
    })
}

#[cfg(test)]
#[path = "tests/checks.rs"]
mod tests;
