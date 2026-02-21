use async_trait::async_trait;
use safe_pkgs_core::{
    Check, CheckExecutionContext, CheckFinding, CheckId, RegistryError, Severity,
};

const CHECK_ID: CheckId = "existence";

pub fn create_check() -> Box<dyn Check> {
    Box::new(ExistenceCheck)
}

pub struct ExistenceCheck;

#[async_trait]
impl Check for ExistenceCheck {
    fn id(&self) -> CheckId {
        CHECK_ID
    }

    fn description(&self) -> &'static str {
        "Ensures package and requested version exist in the selected registry."
    }

    fn always_enabled(&self) -> bool {
        true
    }

    fn priority(&self) -> u16 {
        0
    }

    fn runs_on_missing_package(&self) -> bool {
        true
    }

    fn runs_on_missing_version(&self) -> bool {
        true
    }

    async fn run(
        &self,
        context: &CheckExecutionContext<'_>,
    ) -> Result<Vec<CheckFinding>, RegistryError> {
        if context.package.is_none() {
            return Ok(vec![missing_package(context.package_name)]);
        }

        if context.resolved_version.is_none() {
            return Ok(vec![missing_version(
                context.package_name,
                context.requested_version.unwrap_or("latest"),
            )]);
        }

        Ok(Vec::new())
    }
}

fn missing_package(package_name: &str) -> CheckFinding {
    CheckFinding {
        severity: Severity::Critical,
        reason: format!("{package_name} does not exist (possible hallucination / slopsquatting)"),
    }
}

fn missing_version(package_name: &str, version: &str) -> CheckFinding {
    CheckFinding {
        severity: Severity::Critical,
        reason: format!("{package_name}@{version} does not exist (possible hallucinated version)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_package_is_critical_with_expected_reason() {
        let finding = missing_package("imaginary-pkg");
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.reason.contains("imaginary-pkg"));
        assert!(finding.reason.contains("does not exist"));
    }

    #[test]
    fn missing_version_is_critical_with_expected_reason() {
        let finding = missing_version("real-pkg", "9.9.9");
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.reason.contains("real-pkg@9.9.9"));
        assert!(finding.reason.contains("hallucinated version"));
    }
}
