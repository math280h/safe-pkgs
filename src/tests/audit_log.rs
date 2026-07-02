use super::*;
use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn unique_temp_path(file_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!("safe-pkgs-{nanos}-{file_name}"))
}

fn sample_record() -> AuditRecord {
    AuditRecord::package_decision(PackageDecision {
        policy_snapshot_version: 1,
        config_fingerprint: "cfg123",
        policy_fingerprint: "pol123",
        enabled_checks: vec!["existence".to_string()],
        evaluation_time: "2026-01-01T00:00:00Z".to_string(),
        context: "check_package",
        package: "demo",
        requested: Some("latest"),
        registry: "npm",
        allow: false,
        risk: Severity::High,
        reasons: vec!["reason".to_string()],
        evidence: Vec::new(),
        metadata: Some(Metadata {
            latest: Some("2.0.0".to_string()),
            requested: Some("latest".to_string()),
            published: None,
            weekly_downloads: Some(10),
        }),
        cached: true,
    })
}

#[test]
fn package_decision_contains_expected_fields() {
    let record = AuditRecord::package_decision(PackageDecision {
        policy_snapshot_version: 1,
        config_fingerprint: "cfg123",
        policy_fingerprint: "pol123",
        enabled_checks: vec!["advisory".to_string(), "existence".to_string()],
        evaluation_time: "2026-01-01T00:00:00Z".to_string(),
        context: "check_package",
        package: "demo",
        requested: Some("1.0.0"),
        registry: "npm",
        allow: true,
        risk: Severity::Low,
        reasons: vec!["ok".to_string()],
        evidence: Vec::new(),
        metadata: None,
        cached: false,
    });

    let json = serde_json::to_value(record).expect("serialize record");
    assert_eq!(json["policy_snapshot_version"], 1);
    assert_eq!(json["config_fingerprint"], "cfg123");
    assert_eq!(json["policy_fingerprint"], "pol123");
    assert_eq!(json["evaluation_time"], "2026-01-01T00:00:00Z");
    assert!(json["enabled_checks"].is_array());
    assert_eq!(json["context"], "check_package");
    assert_eq!(json["package"], "demo");
    assert_eq!(json["requested"], "1.0.0");
    assert_eq!(json["registry"], "npm");
    assert_eq!(json["allow"], true);
    assert_eq!(json["risk"], "low");
    assert_eq!(json["cached"], false);
    assert!(json["evidence"].is_array());
}

#[tokio::test]
async fn file_sink_writes_one_json_line() {
    let path = unique_temp_path("audit.log");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("create audit log file");
    let sink = FileAuditSink {
        file: Arc::new(Mutex::new(file)),
    };

    sink.log(&sample_record())
        .await
        .expect("write audit record");

    let raw = fs::read_to_string(&path).expect("read audit file");
    let lines = raw.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("valid json line");
    assert_eq!(parsed["package"], "demo");
    assert_eq!(parsed["cached"], true);
    assert_eq!(parsed["policy_fingerprint"], "pol123");

    // Release the open file handle before deleting (required on Windows).
    drop(sink);
    let _ = fs::remove_file(path);
}

#[tokio::test]
async fn http_sink_posts_record() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/audit"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let sink =
        HttpAuditSink::new(format!("{}/audit", mock_server.uri()), None).expect("build http sink");
    sink.log(&sample_record()).await.expect("post audit record");
}

#[tokio::test]
async fn http_sink_sends_bearer_token() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/audit"))
        .and(header("Authorization", "Bearer secret-token"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    let sink = HttpAuditSink::new(
        format!("{}/audit", mock_server.uri()),
        Some("secret-token".to_string()),
    )
    .expect("build http sink");
    sink.log(&sample_record())
        .await
        .expect("post authenticated audit record");
}

#[tokio::test]
async fn http_sink_errors_on_non_success_status() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/audit"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&mock_server)
        .await;

    let sink =
        HttpAuditSink::new(format!("{}/audit", mock_server.uri()), None).expect("build http sink");
    let result = sink.log(&sample_record()).await;
    assert!(result.is_err());
}

#[test]
fn build_http_sink_requires_endpoint() {
    // Empty endpoint is rejected by build_audit_sink itself.
    let config = AuditConfig {
        backend: AuditBackend::Http,
        endpoint: None,
        token_env: None,
    };
    assert!(build_audit_sink(&config).is_err());
}

#[test]
fn build_http_sink_requires_present_token_env() {
    // Use a uniquely-named, unset env var so this does not race other tests.
    let var_name = format!("SAFE_PKGS_TEST_MISSING_TOKEN_{}", std::process::id());
    // SAFETY: single-threaded test access; we set and immediately remove a uniquely-named var.
    unsafe {
        std::env::remove_var(&var_name);
    }
    let config = AuditConfig {
        backend: AuditBackend::Http,
        endpoint: Some("https://example.com/audit".to_string()),
        token_env: Some(var_name.clone()),
    };
    let result = build_audit_sink(&config);
    assert!(result.is_err());

    // Also reject an empty (but present) env var.
    // SAFETY: single-threaded test access to a uniquely-named var.
    unsafe {
        std::env::set_var(&var_name, "");
    }
    let empty_result = build_audit_sink(&config);
    // SAFETY: clean up the uniquely-named var we set above.
    unsafe {
        std::env::remove_var(&var_name);
    }
    assert!(empty_result.is_err());
}
