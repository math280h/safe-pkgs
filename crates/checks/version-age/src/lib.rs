use async_trait::async_trait;
use chrono::Utc;
use safe_pkgs_core::{
    Check, CheckExecutionContext, CheckFinding, CheckId, PackageVersion, RegistryError, Severity,
};

const CHECK_ID: CheckId = "version_age";

pub fn create_check() -> Box<dyn Check> {
    Box::new(VersionAgeCheck)
}

pub struct VersionAgeCheck;

#[async_trait]
impl Check for VersionAgeCheck {
    fn id(&self) -> CheckId {
        CHECK_ID
    }

    fn description(&self) -> &'static str {
        "Flags versions newer than the configured minimum package age."
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
            context.policy.min_version_age_days,
        )
        .await
        .into_iter()
        .collect())
    }
}

async fn run(
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
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    fn version(days_ago: i64) -> PackageVersion {
        PackageVersion {
            version: "1.2.3".to_string(),
            published: Some(Utc::now() - Duration::days(days_ago)),
            deprecated: false,
            install_scripts: Vec::new(),
        }
    }

    #[tokio::test]
    async fn recent_release_is_high_risk() {
        let finding = run("demo", &version(2), 7).await.expect("finding");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.reason.contains("demo@1.2.3"));
        assert!(finding.reason.contains("< 7 days"));
    }

    #[tokio::test]
    async fn old_enough_release_has_no_finding() {
        let finding = run("demo", &version(30), 7).await;
        assert!(finding.is_none());
    }

    #[tokio::test]
    async fn missing_publish_date_has_no_finding() {
        let version = PackageVersion {
            version: "1.2.3".to_string(),
            published: None,
            deprecated: false,
            install_scripts: Vec::new(),
        };
        let finding = run("demo", &version, 7).await;
        assert!(finding.is_none());
    }
}
