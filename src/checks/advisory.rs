use semver::Version;

use crate::checks::CheckFinding;
use crate::registries::PackageAdvisory;
use crate::types::Severity;

pub async fn run(
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
#[path = "advisory_tests.rs"]
mod tests;
