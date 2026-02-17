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
