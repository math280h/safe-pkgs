use async_trait::async_trait;
use safe_pkgs_core::{
    Check, CheckExecutionContext, CheckFinding, CheckId, PackageAdvisory, RegistryError, Severity,
};
use semver::Version;

const CHECK_ID: CheckId = "advisory";

pub fn create_check() -> Box<dyn Check> {
    Box::new(AdvisoryCheck)
}

pub struct AdvisoryCheck;

#[async_trait]
impl Check for AdvisoryCheck {
    fn id(&self) -> CheckId {
        CHECK_ID
    }

    fn description(&self) -> &'static str {
        "Flags vulnerability advisories and suggests fixed versions when known."
    }

    fn needs_advisories(&self) -> bool {
        true
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

        Ok(run(
            context.package_name,
            &resolved_version.version,
            &package.latest,
            context.advisories,
        )
        .await
        .into_iter()
        .collect())
    }
}

async fn run(
    package_name: &str,
    requested_version: &str,
    latest_version: &str,
    advisories: &[PackageAdvisory],
) -> Option<CheckFinding> {
    if advisories.is_empty() {
        return None;
    }

    let identifiers = advisories
        .iter()
        .flat_map(advisory_identifiers)
        .take(3)
        .collect::<Vec<_>>();
    let identifiers = if identifiers.is_empty() {
        "OSV advisory".to_string()
    } else {
        identifiers.join(", ")
    };

    let fixed_versions = advisories
        .iter()
        .flat_map(|advisory| advisory.fixed_versions.iter())
        .filter(|fixed| is_version_newer(fixed, requested_version))
        .cloned()
        .collect::<Vec<_>>();

    let reason = if let Some(fixed) = best_fixed_version(&fixed_versions) {
        format!(
            "{package_name}@{requested_version} is affected by {identifiers}; known CVEs are fixed in newer version {fixed} (latest is {latest_version})"
        )
    } else {
        format!("{package_name}@{requested_version} is affected by {identifiers}")
    };

    Some(CheckFinding {
        severity: Severity::High,
        reason,
    })
}

fn advisory_identifiers(advisory: &PackageAdvisory) -> Vec<String> {
    let aliases = advisory
        .aliases
        .iter()
        .filter(|alias| alias.starts_with("CVE-"))
        .cloned()
        .collect::<Vec<_>>();
    if aliases.is_empty() {
        vec![advisory.id.clone()]
    } else {
        aliases
    }
}

fn is_version_newer(candidate: &str, baseline: &str) -> bool {
    match (Version::parse(candidate), Version::parse(baseline)) {
        (Ok(lhs), Ok(rhs)) => lhs > rhs,
        _ => candidate > baseline,
    }
}

fn best_fixed_version(candidates: &[String]) -> Option<&str> {
    candidates
        .iter()
        .min_by(|left, right| {
            match (
                Version::parse(left.as_str()),
                Version::parse(right.as_str()),
            ) {
                (Ok(lhs), Ok(rhs)) => lhs.cmp(&rhs),
                _ => left.cmp(right),
            }
        })
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_advisories_has_no_finding() {
        let finding = run("demo", "1.0.0", "1.2.0", &[]).await;
        assert!(finding.is_none());
    }

    #[tokio::test]
    async fn advisory_with_cve_alias_and_fixed_version_is_high_risk() {
        let advisories = vec![PackageAdvisory {
            id: "OSV-123".to_string(),
            aliases: vec!["CVE-2025-1234".to_string()],
            fixed_versions: vec!["1.1.0".to_string(), "2.0.0".to_string()],
        }];

        let finding = run("demo", "1.0.0", "2.0.0", &advisories)
            .await
            .expect("finding");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.reason.contains("CVE-2025-1234"));
        assert!(finding.reason.contains("newer version 1.1.0"));
    }

    #[tokio::test]
    async fn advisory_without_alias_uses_advisory_id() {
        let advisories = vec![PackageAdvisory {
            id: "OSV-999".to_string(),
            aliases: Vec::new(),
            fixed_versions: Vec::new(),
        }];

        let finding = run("demo", "1.0.0", "1.0.0", &advisories)
            .await
            .expect("finding");
        assert!(finding.reason.contains("OSV-999"));
    }
}
