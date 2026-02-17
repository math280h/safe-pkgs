use super::*;
use crate::registries::PackageAdvisory;

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
