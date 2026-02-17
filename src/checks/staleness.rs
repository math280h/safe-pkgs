use semver::Version;

use crate::checks::CheckFinding;
use crate::config::StalenessConfig;
use crate::registries::{PackageRecord, PackageVersion};
use crate::types::Severity;

pub async fn run(
    package: &PackageRecord,
    requested: &PackageVersion,
    config: &StalenessConfig,
) -> Vec<CheckFinding> {
    let mut findings = Vec::new();
    let ignored = is_ignored(package.name.as_str(), requested.version.as_str(), config);

    if requested.deprecated {
        findings.push(CheckFinding {
            severity: Severity::High,
            reason: format!(
                "{}@{} is marked deprecated",
                package.name, requested.version
            ),
        });
    }

    if !ignored && let Some(published) = requested.published {
        let age_days = chrono::Utc::now()
            .signed_duration_since(published)
            .num_days();
        if age_days >= config.warn_age_days {
            findings.push(CheckFinding {
                severity: Severity::Low,
                reason: format!(
                    "{}@{} is {} day(s) old (>= {} days)",
                    package.name, requested.version, age_days, config.warn_age_days
                ),
            });
        }
    }

    if ignored {
        return findings;
    }

    let Ok(requested_semver) = Version::parse(&requested.version) else {
        return findings;
    };
    let Ok(latest_semver) = Version::parse(&package.latest) else {
        return findings;
    };

    if latest_semver <= requested_semver {
        return findings;
    }

    let major_gap = latest_semver.major.saturating_sub(requested_semver.major);
    let minor_gap = if latest_semver.major == requested_semver.major {
        latest_semver.minor.saturating_sub(requested_semver.minor)
    } else {
        0
    };

    if major_gap >= config.warn_major_versions_behind {
        findings.push(CheckFinding {
            severity: Severity::Medium,
            reason: format!(
                "{}@{} is {} major version(s) behind latest ({})",
                package.name, requested.version, major_gap, package.latest
            ),
        });
    } else if major_gap >= 1 || minor_gap >= config.warn_minor_versions_behind {
        findings.push(CheckFinding {
            severity: Severity::Low,
            reason: format!(
                "{}@{} is behind latest ({})",
                package.name, requested.version, package.latest
            ),
        });
    }

    findings
}

fn is_ignored(package_name: &str, version: &str, config: &StalenessConfig) -> bool {
    config.ignore_for.iter().any(|rule| {
        if rule == package_name {
            return true;
        }

        let Some((rule_package, rule_version)) = rule.rsplit_once('@') else {
            return false;
        };
        if rule_package != package_name {
            return false;
        }

        if rule_version == version {
            return true;
        }

        let Some(major_prefix) = rule_version.strip_suffix(".x") else {
            return false;
        };
        let Ok(rule_major) = major_prefix.parse::<u64>() else {
            return false;
        };
        let Ok(parsed_version) = Version::parse(version) else {
            return false;
        };

        parsed_version.major == rule_major
    })
}

#[cfg(test)]
#[path = "staleness_tests.rs"]
mod tests;
