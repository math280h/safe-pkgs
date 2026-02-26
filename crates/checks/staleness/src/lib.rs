use async_trait::async_trait;
use safe_pkgs_core::{
    Check, CheckExecutionContext, CheckFinding, CheckId, PackageRecord, PackageVersion,
    RegistryError, Severity, StalenessPolicy,
};
use semver::Version;

const CHECK_ID: CheckId = "staleness";

pub fn create_check() -> Box<dyn Check> {
    Box::new(StalenessCheck)
}

pub struct StalenessCheck;

#[async_trait]
impl Check for StalenessCheck {
    fn id(&self) -> CheckId {
        CHECK_ID
    }

    fn description(&self) -> &'static str {
        "Flags deprecated or stale package versions based on age and semver distance."
    }

    async fn run(
        &self,
        context: &CheckExecutionContext<'_>,
    ) -> Result<Vec<CheckFinding>, RegistryError> {
        let Some(package) = context.package else {
            return Ok(Vec::new());
        };
        let Some(resolved_version) = context.resolved_version else {
            return Ok(Vec::new());
        };

        Ok(run(package, resolved_version, &context.policy.staleness).await)
    }
}

async fn run(
    package: &PackageRecord,
    requested: &PackageVersion,
    policy: &StalenessPolicy,
) -> Vec<CheckFinding> {
    let mut findings = Vec::new();
    let ignored = is_ignored(package.name.as_str(), requested.version.as_str(), policy);

    if requested.deprecated {
        findings.push(
            CheckFinding::new(
                Severity::High,
                format!(
                    "{}@{} is marked deprecated",
                    package.name, requested.version
                ),
                "deprecated_version",
            )
            .with_fact("package_name", package.name.as_str())
            .with_fact("resolved_version", requested.version.as_str()),
        );
    }

    if !ignored && let Some(published) = requested.published {
        let age_days = chrono::Utc::now()
            .signed_duration_since(published)
            .num_days();
        if age_days >= policy.warn_age_days {
            findings.push(
                CheckFinding::new(
                    Severity::Low,
                    format!(
                        "{}@{} is {} day(s) old (>= {} days)",
                        package.name, requested.version, age_days, policy.warn_age_days
                    ),
                    "old_release_age",
                )
                .with_fact("package_name", package.name.as_str())
                .with_fact("resolved_version", requested.version.as_str())
                .with_fact("age_days", age_days)
                .with_fact("warn_age_days", policy.warn_age_days),
            );
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

    if major_gap >= policy.warn_major_versions_behind {
        findings.push(
            CheckFinding::new(
                Severity::Medium,
                format!(
                    "{}@{} is {} major version(s) behind latest ({})",
                    package.name, requested.version, major_gap, package.latest
                ),
                "major_versions_behind",
            )
            .with_fact("package_name", package.name.as_str())
            .with_fact("resolved_version", requested.version.as_str())
            .with_fact("latest_version", package.latest.as_str())
            .with_fact("major_gap", major_gap)
            .with_fact(
                "warn_major_versions_behind",
                policy.warn_major_versions_behind,
            ),
        );
    } else if major_gap >= 1 || minor_gap >= policy.warn_minor_versions_behind {
        findings.push(
            CheckFinding::new(
                Severity::Low,
                format!(
                    "{}@{} is behind latest ({})",
                    package.name, requested.version, package.latest
                ),
                "behind_latest",
            )
            .with_fact("package_name", package.name.as_str())
            .with_fact("resolved_version", requested.version.as_str())
            .with_fact("latest_version", package.latest.as_str())
            .with_fact("major_gap", major_gap)
            .with_fact("minor_gap", minor_gap)
            .with_fact(
                "warn_minor_versions_behind",
                policy.warn_minor_versions_behind,
            ),
        );
    }

    findings
}

fn is_ignored(package_name: &str, version: &str, policy: &StalenessPolicy) -> bool {
    policy.ignore_for.iter().any(|rule| {
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
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::collections::BTreeMap;

    fn default_policy() -> StalenessPolicy {
        StalenessPolicy {
            warn_major_versions_behind: 2,
            warn_minor_versions_behind: 3,
            warn_age_days: 365,
            ignore_for: Vec::new(),
        }
    }

    #[tokio::test]
    async fn major_gap_is_medium() {
        let mut versions = BTreeMap::new();
        versions.insert(
            "1.0.0".to_string(),
            PackageVersion {
                version: "1.0.0".to_string(),
                published: Some(Utc::now() - Duration::days(100)),
                deprecated: false,
                install_scripts: Vec::new(),
            },
        );
        versions.insert(
            "3.0.0".to_string(),
            PackageVersion {
                version: "3.0.0".to_string(),
                published: Some(Utc::now() - Duration::days(10)),
                deprecated: false,
                install_scripts: Vec::new(),
            },
        );
        let package = PackageRecord {
            name: "demo".to_string(),
            latest: "3.0.0".to_string(),
            publishers: Vec::new(),
            versions,
        };

        let requested = package.versions.get("1.0.0").expect("version exists");
        let findings = run(&package, requested, &default_policy()).await;
        assert!(findings.iter().any(|f| f.severity == Severity::Medium));
    }

    #[tokio::test]
    async fn ignore_for_package_version_suppresses_staleness_gap() {
        let mut versions = BTreeMap::new();
        versions.insert(
            "1.0.0".to_string(),
            PackageVersion {
                version: "1.0.0".to_string(),
                published: Some(Utc::now() - Duration::days(1000)),
                deprecated: false,
                install_scripts: Vec::new(),
            },
        );
        versions.insert(
            "3.0.0".to_string(),
            PackageVersion {
                version: "3.0.0".to_string(),
                published: Some(Utc::now() - Duration::days(10)),
                deprecated: false,
                install_scripts: Vec::new(),
            },
        );
        let package = PackageRecord {
            name: "demo".to_string(),
            latest: "3.0.0".to_string(),
            publishers: Vec::new(),
            versions,
        };

        let policy = StalenessPolicy {
            ignore_for: vec!["demo@1.x".to_string()],
            ..default_policy()
        };

        let requested = package.versions.get("1.0.0").expect("version exists");
        let findings = run(&package, requested, &policy).await;
        assert!(
            findings
                .iter()
                .all(|finding| !finding.reason.contains("behind latest"))
        );
    }
}
