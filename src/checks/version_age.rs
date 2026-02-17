use chrono::Utc;

use crate::checks::CheckFinding;
use crate::registries::PackageVersion;
use crate::types::Severity;

pub async fn run(
    package_name: &str,
    version: &PackageVersion,
    min_version_age_days: i64,
) -> Option<CheckFinding> {
    let published = version.published?;
    let age_days = (Utc::now() - published).num_days();
    if age_days >= min_version_age_days {
        return None;
    }

    Some(CheckFinding {
        severity: Severity::High,
        reason: format!(
            "{package_name}@{} was published {} day(s) ago (< {min_version_age_days} days)",
            version.version, age_days
        ),
    })
}

#[cfg(test)]
#[path = "version_age_tests.rs"]
mod tests;
