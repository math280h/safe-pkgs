use super::*;
use async_trait::async_trait;

struct FakeRegistryClient {
    popular_packages: Vec<String>,
}

#[async_trait]
impl RegistryClient for FakeRegistryClient {
    fn ecosystem(&self) -> crate::registries::RegistryEcosystem {
        crate::registries::RegistryEcosystem::Npm
    }

    async fn fetch_package(
        &self,
        _package: &str,
    ) -> Result<crate::registries::PackageRecord, RegistryError> {
        Err(RegistryError::InvalidResponse {
            message: "not used in typosquat tests".to_string(),
        })
    }

    async fn fetch_weekly_downloads(&self, _package: &str) -> Result<Option<u64>, RegistryError> {
        Ok(None)
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
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn low_download_close_name_is_flagged() {
    let client = FakeRegistryClient {
        popular_packages: vec!["react".to_string(), "lodash".to_string()],
    };

    let result = run("raect", Some(10), &client).await.expect("typosquat");
    let finding = result.expect("finding expected");
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.reason.contains("react"));
}

#[tokio::test]
async fn high_download_package_is_not_flagged() {
    let client = FakeRegistryClient {
        popular_packages: vec!["react".to_string(), "lodash".to_string()],
    };

    let result = run("raect", Some(1000), &client).await.expect("typosquat");
    assert!(result.is_none());
}

#[test]
fn bounded_distance_respects_limit() {
    assert_eq!(bounded_levenshtein("react", "raect", 2), Some(2));
    assert_eq!(bounded_levenshtein("react", "qwerty", 2), None);
}
