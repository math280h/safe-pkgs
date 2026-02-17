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
