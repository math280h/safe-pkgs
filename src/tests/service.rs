use super::*;
use crate::config::SafePkgsConfig;

#[test]
fn cache_key_uses_latest_when_version_is_missing() {
    assert_eq!(
        cache_key_for_package("npm", "demo", None),
        "check_package:npm:demo@latest"
    );
    assert_eq!(
        cache_key_for_package("npm", "demo", Some("1.2.3")),
        "check_package:npm:demo@1.2.3"
    );
}

#[test]
fn invalid_registry_error_mentions_supported_registries() {
    let err = invalid_registry_error("package", "unknown", &["npm", "cargo"]);
    let text = err.to_string();
    assert!(text.contains("unsupported package registry 'unknown'"));
    assert!(text.contains("npm, cargo"));
}

#[test]
fn audit_log_failure_detector_matches_context_string() {
    let err = anyhow::anyhow!("failed to append audit log record: permission denied");
    assert!(is_audit_log_failure(&err));

    let other = anyhow::anyhow!("some unrelated failure");
    assert!(!is_audit_log_failure(&other));
}

#[tokio::test]
async fn evaluate_package_rejects_unsupported_registry() {
    let service = SafePkgsService::with_config(SafePkgsConfig::default());
    let err = service
        .evaluate_package("demo", Some("1.0.0"), "unknown", "test")
        .await
        .expect_err("unsupported registry should error");
    assert!(err.to_string().contains("unsupported package registry"));
}

#[tokio::test]
async fn run_lockfile_audit_rejects_unsupported_registry() {
    let service = SafePkgsService::with_config(SafePkgsConfig::default());
    let err = service
        .run_lockfile_audit(None, "unknown", "test")
        .await
        .expect_err("unsupported lockfile registry should error");
    assert!(err.to_string().contains("unsupported lockfile registry"));
}

#[tokio::test]
async fn evaluate_package_denylist_result_is_cached() {
    let mut config = SafePkgsConfig::default();
    config.denylist.packages = vec!["demo".to_string()];
    let service = SafePkgsService::with_config(config);

    let first = service
        .evaluate_package("demo", Some("1.0.0"), "npm", "test")
        .await
        .expect("first evaluation");
    assert!(!first.allow);
    assert_eq!(first.risk, Severity::Critical);

    let cache_key = cache_key_for_package("npm", "demo", Some("1.0.0"));
    let cached_raw = service.cache.get(&cache_key).expect("cache lookup");
    assert!(cached_raw.is_some());

    let second = service
        .evaluate_package("demo", Some("1.0.0"), "npm", "test")
        .await
        .expect("second evaluation");
    assert_eq!(second.allow, first.allow);
    assert_eq!(second.risk, first.risk);
    assert_eq!(second.reasons, first.reasons);
}
