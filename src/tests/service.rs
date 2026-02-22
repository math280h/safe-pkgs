use super::*;
use crate::config::SafePkgsConfig;

#[test]
fn cache_key_uses_latest_when_version_is_missing() {
    assert_eq!(
        cache_key_for_package("abc123", "npm", "demo", None),
        "check_package:abc123:npm:demo@latest"
    );
    assert_eq!(
        cache_key_for_package("abc123", "npm", "demo", Some("1.2.3")),
        "check_package:abc123:npm:demo@1.2.3"
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
async fn run_lockfile_audit_rejects_unsupported_existing_file_for_registry() {
    let service = SafePkgsService::with_config(SafePkgsConfig::default());
    let dir = std::env::temp_dir().join(format!(
        "safe-pkgs-service-tests-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let file = dir.join("requirements.txt");
    std::fs::write(&file, "requests==2.31.0").expect("write file");

    let err = service
        .run_lockfile_audit(Some(file.to_string_lossy().as_ref()), "cargo", "test")
        .await
        .expect_err("unsupported file should be rejected");
    assert!(err.to_string().contains("unsupported dependency file"));

    let _ = std::fs::remove_file(file);
    let _ = std::fs::remove_dir_all(dir);
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

    let cache_key = cache_key_for_package(
        service.config_fingerprint.as_str(),
        "npm",
        "demo",
        Some("1.0.0"),
    );
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

#[test]
fn config_fingerprint_changes_when_policy_changes() {
    let first = compute_config_fingerprint(&SafePkgsConfig::default()).expect("fingerprint");

    let changed = SafePkgsConfig {
        max_risk: Severity::High,
        ..SafePkgsConfig::default()
    };
    let second = compute_config_fingerprint(&changed).expect("fingerprint");

    assert_ne!(first, second);
    assert_eq!(first.len(), 64);
    assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
}
