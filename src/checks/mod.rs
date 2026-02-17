mod advisory;
mod existence;
mod install_script;
mod popularity;
mod staleness;
mod typosquat;
mod version_age;

use crate::config::SafePkgsConfig;
use crate::registries::{RegistryClient, RegistryError};
use crate::types::{Metadata, Severity};

const DEFAULT_YOUNG_PACKAGE_AGE_DAYS: i64 = 30;

#[derive(Debug, Clone)]
pub struct CheckFinding {
    pub severity: Severity,
    pub reason: String,
}

#[derive(Debug)]
pub struct CheckReport {
    pub allow: bool,
    pub risk: Severity,
    pub reasons: Vec<String>,
    pub metadata: Metadata,
}

pub async fn run_all_checks(
    package_name: &str,
    requested_version: Option<&str>,
    registry_client: &dyn RegistryClient,
    config: &SafePkgsConfig,
) -> Result<CheckReport, RegistryError> {
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
        Ok(package) => package,
        Err(RegistryError::NotFound { .. }) => {
            return Ok(report_from_findings(
                vec![existence::missing_package(package_name)],
                Metadata {
                    latest: None,
                    requested: requested_version.map(ToOwned::to_owned),
                    published: None,
                    weekly_downloads: None,
                },
                config.max_risk,
            ));
        }
        Err(err) => return Err(err),
    };

    let resolved_version = match package.resolve_version(requested_version) {
        Some(version) => version,
        None => {
            return Ok(report_from_findings(
                vec![existence::missing_version(
                    package_name,
                    requested_version.unwrap_or("latest"),
                )],
                Metadata {
                    latest: Some(package.latest.clone()),
                    requested: requested_version.map(ToOwned::to_owned),
                    published: None,
                    weekly_downloads: None,
                },
                config.max_risk,
            ));
        }
    };

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

    if let Some(publisher) = matching_publisher(&config.denylist.publishers, &package.publishers) {
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

    let metadata = Metadata {
        latest: Some(package.latest.clone()),
        requested: requested_version.map(ToOwned::to_owned),
        published: resolved_version.published.map(|ts| ts.to_rfc3339()),
        weekly_downloads: registry_client.fetch_weekly_downloads(package_name).await?,
    };

    let advisories = registry_client
        .fetch_advisories(package_name, &resolved_version.version)
        .await?;

    let (
        version_age_result,
        staleness_results,
        popularity_result,
        install_script_result,
        typosquat_result,
        advisory_result,
    ) = tokio::join!(
        version_age::run(package_name, resolved_version, config.min_version_age_days),
        staleness::run(&package, resolved_version, &config.staleness),
        popularity::run(
            package_name,
            resolved_version,
            metadata.weekly_downloads,
            config.min_weekly_downloads,
            DEFAULT_YOUNG_PACKAGE_AGE_DAYS
        ),
        install_script::run(package_name, resolved_version),
        typosquat::run(package_name, metadata.weekly_downloads, registry_client),
        advisory::run(
            package_name,
            &resolved_version.version,
            &package.latest,
            &advisories,
        ),
    );

    let mut findings = Vec::new();
    if let Some(finding) = version_age_result {
        findings.push(finding);
    }
    findings.extend(staleness_results);
    if let Some(finding) = popularity_result {
        findings.push(finding);
    }
    if let Some(finding) = install_script_result {
        findings.push(finding);
    }
    if let Some(finding) = typosquat_result? {
        findings.push(finding);
    }
    if let Some(finding) = advisory_result {
        findings.push(finding);
    }

    Ok(report_from_findings(findings, metadata, config.max_risk))
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
    denylist_publishers.iter().find_map(|denylisted| {
        publishers
            .iter()
            .any(|publisher| publisher.eq_ignore_ascii_case(denylisted))
            .then_some(denylisted.as_str())
    })
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
