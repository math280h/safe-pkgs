use async_trait::async_trait;
use chrono::Utc;
use safe_pkgs_core::{
    Check, CheckExecutionContext, CheckFinding, CheckId, PackageVersion, RegistryError, Severity,
};

const CHECK_ID: CheckId = "popularity";
const DEFAULT_YOUNG_PACKAGE_AGE_DAYS: i64 = 30;

pub fn create_check() -> Box<dyn Check> {
    Box::new(PopularityCheck)
}

pub struct PopularityCheck;

#[async_trait]
impl Check for PopularityCheck {
    fn id(&self) -> CheckId {
        CHECK_ID
    }

    fn description(&self) -> &'static str {
        "Flags very new packages with low adoption based on weekly downloads."
    }

    fn needs_weekly_downloads(&self) -> bool {
        true
    }

    async fn run(
        &self,
        context: &CheckExecutionContext<'_>,
    ) -> Result<Vec<CheckFinding>, RegistryError> {
        let Some(resolved_version) = context.resolved_version else {
            return Ok(Vec::new());
        };

        Ok(run(
            context.package_name,
            resolved_version,
            context.weekly_downloads,
            context.policy.min_weekly_downloads,
            DEFAULT_YOUNG_PACKAGE_AGE_DAYS,
        )
        .await
        .into_iter()
        .collect())
    }
}

async fn run(
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
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn version(days_ago: i64) -> PackageVersion {
        PackageVersion {
            version: "0.1.0".to_string(),
            published: Some(Utc::now() - Duration::days(days_ago)),
            deprecated: false,
            install_scripts: Vec::new(),
        }
    }

    #[tokio::test]
    async fn low_downloads_and_young_package_is_high_risk() {
        let finding = run("new-lib", &version(3), Some(10), 50, 30)
            .await
            .expect("finding");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.reason.contains("low adoption"));
    }

    #[tokio::test]
    async fn high_downloads_has_no_finding() {
        let finding = run("new-lib", &version(3), Some(5000), 50, 30).await;
        assert!(finding.is_none());
    }

    #[tokio::test]
    async fn old_package_has_no_finding_even_if_downloads_low() {
        let finding = run("old-lib", &version(180), Some(10), 50, 30).await;
        assert!(finding.is_none());
    }

    #[tokio::test]
    async fn missing_downloads_or_publish_date_has_no_finding() {
        let no_downloads = run("lib", &version(3), None, 50, 30).await;
        assert!(no_downloads.is_none());

        let version = PackageVersion {
            version: "0.1.0".to_string(),
            published: None,
            deprecated: false,
            install_scripts: Vec::new(),
        };
        let no_publish_date = run("lib", &version, Some(10), 50, 30).await;
        assert!(no_publish_date.is_none());
    }
}
