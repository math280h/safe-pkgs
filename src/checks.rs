//! Check orchestration for single-package evaluations.

use std::collections::HashSet;
use std::sync::OnceLock;

use safe_pkgs_core::{
    Check, CheckExecutionContext, CheckFinding, CheckId, CheckPolicy, Metadata, PackageRecord,
    PackageVersion, RegistryClient, RegistryError, Severity, StalenessPolicy,
};

use crate::config::SafePkgsConfig;

/// Lightweight metadata about each registered check.
#[derive(Debug, Clone, Copy)]
pub struct CheckDescriptor {
    /// Stable check id (for config and support maps).
    pub id: CheckId,
    /// Human-facing key shown in CLI output.
    pub key: &'static str,
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
            key: check.id(),
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
    CheckRuntimeRequirements {
        needs_weekly_downloads: checks.iter().any(|check| check.needs_weekly_downloads()),
        needs_advisories: checks.iter().any(|check| check.needs_advisories()),
    }
}

/// Runs policy checks for a single package and version request.
///
/// # Errors
///
/// Returns a registry error when required upstream calls fail.
pub async fn run_all_checks(
    package_name: &str,
    requested_version: Option<&str>,
    registry_key: &str,
    supported_checks: &[CheckId],
    registry_client: &dyn RegistryClient,
    config: &SafePkgsConfig,
) -> Result<CheckReport, RegistryError> {
    // Fast path: denylist package rules always block before any registry calls.
    if let Some(rule) = matching_package_rule(
        &config.denylist.packages,
        package_name,
        requested_version,
        None,
    ) {
        return Ok(deny_report(
            format!("{package_name} matched denylist package rule '{rule}'"),
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
            return Ok(deny_report(
                format!("{package_name} matched denylist package rule '{rule}'"),
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
            return Ok(deny_report(
                format!("{package_name} is published by denylisted publisher '{publisher}'"),
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
            return Ok(allow_report(
                format!("{package_name} matched allowlist package rule '{rule}'"),
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
    };

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
        package_name,
        requested_version,
        package: package.as_ref(),
        resolved_version,
        weekly_downloads: metadata.weekly_downloads,
        advisories: &advisories,
        registry_client,
        policy: &policy,
    };

    let mut findings = Vec::new();
    for check in checks {
        findings.extend(check.run(&execution_context).await?);
    }

    Ok(report_from_findings(findings, metadata, config.max_risk))
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

fn report_from_findings(
    findings: Vec<CheckFinding>,
    metadata: Metadata,
    max_risk: Severity,
) -> CheckReport {
    let mut risk = Severity::Low;
    let mut medium_count = 0u32;
    let reasons = findings
        .into_iter()
        .map(|finding| {
            if finding.severity == Severity::Medium {
                medium_count = medium_count.saturating_add(1);
            }
            if finding.severity > risk {
                risk = finding.severity;
            }
            finding.reason
        })
        .collect::<Vec<_>>();

    // Two medium signals are treated as high overall risk.
    if medium_count >= 2 && risk < Severity::High {
        risk = Severity::High;
    }

    CheckReport {
        allow: risk <= max_risk,
        risk,
        reasons,
        metadata,
    }
}

fn deny_report(reason: String, metadata: Metadata) -> CheckReport {
    CheckReport {
        allow: false,
        risk: Severity::Critical,
        reasons: vec![reason],
        metadata,
    }
}

fn allow_report(reason: String, metadata: Metadata) -> CheckReport {
    CheckReport {
        allow: true,
        risk: Severity::Low,
        reasons: vec![reason],
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
