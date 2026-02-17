use super::*;
use chrono::{Duration, Utc};

fn version(days_ago: i64) -> PackageVersion {
    PackageVersion {
        version: "0.1.0".to_string(),
        published: Some(Utc::now() - Duration::days(days_ago)),
        deprecated: false,
        install_scripts: Vec::new(),
    }
}

#[tokio::test]
async fn low_downloads_and_young_package_is_high_risk() {
    let finding = run("new-lib", &version(3), Some(10), 50, 30)
        .await
        .expect("finding");
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.reason.contains("low adoption"));
}

#[tokio::test]
async fn high_downloads_has_no_finding() {
    let finding = run("new-lib", &version(3), Some(5000), 50, 30).await;
    assert!(finding.is_none());
}

#[tokio::test]
async fn old_package_has_no_finding_even_if_downloads_low() {
    let finding = run("old-lib", &version(180), Some(10), 50, 30).await;
    assert!(finding.is_none());
}

#[tokio::test]
async fn missing_downloads_or_publish_date_has_no_finding() {
    let no_downloads = run("lib", &version(3), None, 50, 30).await;
    assert!(no_downloads.is_none());

    let version = PackageVersion {
        version: "0.1.0".to_string(),
        published: None,
        deprecated: false,
        install_scripts: Vec::new(),
    };
    let no_publish_date = run("lib", &version, Some(10), 50, 30).await;
    assert!(no_publish_date.is_none());
}
