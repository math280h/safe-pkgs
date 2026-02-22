use std::collections::BTreeMap;

use serde::Deserialize;

use crate::types::Severity;

use super::{AllowlistConfig, CustomRuleConfig, DenylistConfig};

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct ConfigOverlay {
    pub min_version_age_days: Option<i64>,
    pub min_weekly_downloads: Option<u64>,
    pub max_risk: Option<Severity>,
    pub allowlist: Option<AllowlistConfig>,
    pub denylist: Option<DenylistConfig>,
    pub staleness: Option<StalenessOverlay>,
    pub checks: Option<ChecksOverlay>,
    pub cache: Option<CacheOverlay>,
    pub custom_rules: Vec<CustomRuleConfig>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub(super) struct StalenessOverlay {
    pub warn_major_versions_behind: Option<u64>,
    pub warn_minor_versions_behind: Option<u64>,
    pub warn_age_days: Option<i64>,
    pub ignore_for: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub(super) struct ChecksOverlay {
    pub disable: Option<Vec<String>>,
    pub registry: BTreeMap<String, RegistryChecksOverlay>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub(super) struct RegistryChecksOverlay {
    pub disable: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub(super) struct CacheOverlay {
    pub ttl_minutes: Option<u64>,
}
