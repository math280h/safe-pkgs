use super::*;
use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_path(file_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    std::env::temp_dir().join(format!("safe-pkgs-{nanos}-{file_name}"))
}

#[test]
fn package_decision_contains_expected_fields() {
    let record = AuditRecord::package_decision(PackageDecision {
        context: "check_package",
        package: "demo",
        requested: Some("1.0.0"),
        registry: "npm",
        allow: true,
        risk: Severity::Low,
        reasons: vec!["ok".to_string()],
        metadata: None,
        cached: false,
    });

    let json = serde_json::to_value(record).expect("serialize record");
    assert_eq!(json["context"], "check_package");
    assert_eq!(json["package"], "demo");
    assert_eq!(json["requested"], "1.0.0");
    assert_eq!(json["registry"], "npm");
    assert_eq!(json["allow"], true);
    assert_eq!(json["risk"], "low");
    assert_eq!(json["cached"], false);
}

#[test]
fn log_writes_one_json_line() {
    let path = unique_temp_path("audit.log");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("create audit log file");
    let logger = AuditLogger {
        file: Mutex::new(file),
    };

    logger
        .log(AuditRecord::package_decision(PackageDecision {
            context: "check_package",
            package: "demo",
            requested: Some("latest"),
            registry: "npm",
            allow: false,
            risk: Severity::High,
            reasons: vec!["reason".to_string()],
            metadata: Some(Metadata {
                latest: Some("2.0.0".to_string()),
                requested: Some("latest".to_string()),
                published: None,
                weekly_downloads: Some(10),
            }),
            cached: true,
        }))
        .expect("write audit record");

    let raw = fs::read_to_string(&path).expect("read audit file");
    let lines = raw.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("valid json line");
    assert_eq!(parsed["package"], "demo");
    assert_eq!(parsed["cached"], true);

    let _ = fs::remove_file(path);
}
