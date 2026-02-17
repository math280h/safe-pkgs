use super::*;
use crate::config::SafePkgsConfig;
use crate::registries::{PackageRecord, PackageVersion, RegistryError};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::collections::BTreeMap;

struct FakeRegistryClient {
    result: Result<PackageRecord, RegistryError>,
    weekly_downloads: Option<u64>,
    popular_packages: Vec<String>,
    advisories: Vec<crate::registries::PackageAdvisory>,
}

#[async_trait]
impl RegistryClient for FakeRegistryClient {
    fn ecosystem(&self) -> crate::registries::RegistryEcosystem {
        crate::registries::RegistryEcosystem::Npm
    }

    async fn fetch_package(&self, _package: &str) -> Result<PackageRecord, RegistryError> {
        self.result.clone()
    }

    async fn fetch_weekly_downloads(&self, _package: &str) -> Result<Option<u64>, RegistryError> {
        Ok(self.weekly_downloads)
    }

    async fn fetch_popular_package_names(
        &self,
        limit: usize,
    ) -> Result<Vec<String>, RegistryError> {
        Ok(self
            .popular_packages
            .iter()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>())
    }

    async fn fetch_advisories(
        &self,
        _package: &str,
        _version: &str,
    ) -> Result<Vec<crate::registries::PackageAdvisory>, RegistryError> {
        Ok(self.advisories.clone())
    }
}

fn package_record(latest: &str, requested: &str, published_days_ago: i64) -> PackageRecord {
    let mut versions = BTreeMap::new();
    versions.insert(
        requested.to_string(),
        PackageVersion {
            version: requested.to_string(),
            published: Some(Utc::now() - Duration::days(published_days_ago)),
            deprecated: false,
            install_scripts: Vec::new(),
        },
    );
    versions.insert(
        latest.to_string(),
        PackageVersion {
            version: latest.to_string(),
            published: Some(Utc::now() - Duration::days(100)),
            deprecated: false,
            install_scripts: Vec::new(),
        },
    );

    PackageRecord {
        name: "demo".to_string(),
        latest: latest.to_string(),
        publishers: Vec::new(),
        versions,
    }
}

fn default_config() -> SafePkgsConfig {
    SafePkgsConfig::default()
}

#[tokio::test]
async fn not_found_is_critical_and_denied() {
    let client = FakeRegistryClient {
        result: Err(RegistryError::NotFound {
            registry: "npm",
            package: "missing-pkg".to_string(),
        }),
        weekly_downloads: None,
        popular_packages: Vec::new(),
        advisories: Vec::new(),
    };

    let report = run_all_checks("missing-pkg", None, &client, &default_config())
        .await
        .expect("check report");
    assert_eq!(report.risk, Severity::Critical);
    assert!(!report.allow);
    assert!(report.reasons[0].contains("does not exist"));
}

#[tokio::test]
async fn very_new_version_is_high_risk() {
    let client = FakeRegistryClient {
        result: Ok(package_record("1.0.1", "1.0.0", 1)),
        weekly_downloads: Some(1_000_000),
        popular_packages: Vec::new(),
        advisories: Vec::new(),
    };

    let report = run_all_checks("demo", Some("1.0.0"), &client, &default_config())
        .await
        .expect("check report");
    assert_eq!(report.risk, Severity::High);
    assert!(!report.allow);
    assert!(
        report
            .reasons
            .iter()
            .any(|reason| reason.contains("published"))
    );
}

#[tokio::test]
async fn typosquat_signal_is_high_risk() {
    let client = FakeRegistryClient {
        result: Ok(package_record("1.0.0", "1.0.0", 30)),
        weekly_downloads: Some(10),
        popular_packages: vec!["react".to_string(), "lodash".to_string()],
        advisories: Vec::new(),
    };

    let report = run_all_checks("raect", Some("1.0.0"), &client, &default_config())
        .await
        .expect("check report");
    assert_eq!(report.risk, Severity::High);
    assert!(report.reasons.iter().any(|reason| reason.contains("react")));
}

#[test]
fn multiple_medium_findings_escalate_to_high() {
    let report = report_from_findings(
        vec![
            CheckFinding {
                severity: Severity::Medium,
                reason: "signal a".to_string(),
            },
            CheckFinding {
                severity: Severity::Medium,
                reason: "signal b".to_string(),
            },
        ],
        Metadata {
            latest: None,
            requested: None,
            published: None,
            weekly_downloads: None,
        },
        Severity::Medium,
    );
    assert_eq!(report.risk, Severity::High);
    assert!(!report.allow);
}

#[tokio::test]
async fn denylist_package_rule_denies_immediately() {
    let client = FakeRegistryClient {
        result: Ok(package_record("1.0.0", "1.0.0", 30)),
        weekly_downloads: Some(100),
        popular_packages: Vec::new(),
        advisories: Vec::new(),
    };
    let mut config = default_config();
    config.denylist.packages = vec!["demo".to_string()];

    let report = run_all_checks("demo", Some("1.0.0"), &client, &config)
        .await
        .expect("check report");

    assert_eq!(report.risk, Severity::Critical);
    assert!(!report.allow);
    assert!(
        report
            .reasons
            .iter()
            .any(|reason| reason.contains("denylist"))
    );
}

#[tokio::test]
async fn allowlist_package_rule_allows_immediately() {
    let client = FakeRegistryClient {
        result: Ok(package_record("1.0.0", "1.0.0", 1)),
        weekly_downloads: Some(0),
        popular_packages: Vec::new(),
        advisories: Vec::new(),
    };
    let mut config = default_config();
    config.allowlist.packages = vec!["demo".to_string()];

    let report = run_all_checks("demo", Some("1.0.0"), &client, &config)
        .await
        .expect("check report");

    assert_eq!(report.risk, Severity::Low);
    assert!(report.allow);
    assert!(
        report
            .reasons
            .iter()
            .any(|reason| reason.contains("allowlist"))
    );
}

#[tokio::test]
async fn denylist_publisher_rule_denies_immediately() {
    let mut record = package_record("1.0.0", "1.0.0", 30);
    record.publishers = vec!["suspicious-user".to_string()];
    let client = FakeRegistryClient {
        result: Ok(record),
        weekly_downloads: Some(1_000_000),
        popular_packages: Vec::new(),
        advisories: Vec::new(),
    };
    let mut config = default_config();
    config.denylist.publishers = vec!["suspicious-user".to_string()];

    let report = run_all_checks("demo", Some("1.0.0"), &client, &config)
        .await
        .expect("check report");

    assert_eq!(report.risk, Severity::Critical);
    assert!(!report.allow);
    assert!(
        report
            .reasons
            .iter()
            .any(|reason| reason.contains("publisher"))
    );
}
