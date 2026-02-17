use chrono::Utc;

use crate::checks::CheckFinding;
use crate::registries::PackageVersion;
use crate::types::Severity;

pub async fn run(
    package_name: &str,
    version: &PackageVersion,
    weekly_downloads: Option<u64>,
    min_weekly_downloads: u64,
    young_package_age_days: i64,
) -> Option<CheckFinding> {
    let published = version.published?;
    let downloads = weekly_downloads?;
    let age_days = (Utc::now() - published).num_days();

    if downloads >= min_weekly_downloads || age_days > young_package_age_days {
        return None;
    }

    Some(CheckFinding {
        severity: Severity::High,
        reason: format!(
            "{package_name}@{} has low adoption ({downloads} weekly downloads) and is only {age_days} day(s) old",
            version.version
        ),
    })
}

#[cfg(test)]
#[path = "popularity_tests.rs"]
mod tests;
