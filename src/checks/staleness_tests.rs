use super::*;
use crate::config::StalenessConfig;
use chrono::{Duration, Utc};
use std::collections::BTreeMap;

#[tokio::test]
async fn major_gap_is_medium() {
    let mut versions = BTreeMap::new();
    versions.insert(
        "1.0.0".to_string(),
        PackageVersion {
            version: "1.0.0".to_string(),
            published: Some(Utc::now() - Duration::days(100)),
            deprecated: false,
            install_scripts: Vec::new(),
        },
    );
    versions.insert(
        "3.0.0".to_string(),
        PackageVersion {
            version: "3.0.0".to_string(),
            published: Some(Utc::now() - Duration::days(10)),
            deprecated: false,
            install_scripts: Vec::new(),
        },
    );
    let package = PackageRecord {
        name: "demo".to_string(),
        latest: "3.0.0".to_string(),
        publishers: Vec::new(),
        versions,
    };

    let requested = package.versions.get("1.0.0").expect("version exists");
    let findings = run(&package, requested, &StalenessConfig::default()).await;
    assert!(findings.iter().any(|f| f.severity == Severity::Medium));
}

#[tokio::test]
async fn ignore_for_package_version_suppresses_staleness_gap() {
    let mut versions = BTreeMap::new();
    versions.insert(
        "1.0.0".to_string(),
        PackageVersion {
            version: "1.0.0".to_string(),
            published: Some(Utc::now() - Duration::days(1000)),
            deprecated: false,
            install_scripts: Vec::new(),
        },
    );
    versions.insert(
        "3.0.0".to_string(),
        PackageVersion {
            version: "3.0.0".to_string(),
            published: Some(Utc::now() - Duration::days(10)),
            deprecated: false,
            install_scripts: Vec::new(),
        },
    );
    let package = PackageRecord {
        name: "demo".to_string(),
        latest: "3.0.0".to_string(),
        publishers: Vec::new(),
        versions,
    };

    let config = StalenessConfig {
        ignore_for: vec!["demo@1.x".to_string()],
        ..StalenessConfig::default()
    };

    let requested = package.versions.get("1.0.0").expect("version exists");
    let findings = run(&package, requested, &config).await;
    assert!(
        findings
            .iter()
            .all(|finding| !finding.reason.contains("behind latest"))
    );
}
