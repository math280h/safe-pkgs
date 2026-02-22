//! Configuration loading and merge logic for `safe-pkgs`.
//!
//! Global config and project-local config are merged with project values taking precedence.

mod custom_rules;
mod overlay;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::registries::{CheckId, normalize_check_id};
use crate::types::Severity;

pub use self::custom_rules::{
    CustomRuleCondition, CustomRuleConfig, CustomRuleField, CustomRuleMatchMode, CustomRuleOperator,
};
use self::overlay::ConfigOverlay;

/// Default minimum age (in days) required for a package version.
pub const DEFAULT_MIN_VERSION_AGE_DAYS: i64 = 7;
/// Default minimum weekly downloads used by popularity checks.
pub const DEFAULT_MIN_WEEKLY_DOWNLOADS: u64 = 50;
/// Default maximum risk allowed before denying install.
pub const DEFAULT_MAX_RISK: Severity = Severity::Medium;
/// Default major-version staleness threshold.
pub const DEFAULT_WARN_MAJOR_VERSIONS_BEHIND: u64 = 2;
/// Default minor-version staleness threshold.
pub const DEFAULT_WARN_MINOR_VERSIONS_BEHIND: u64 = 3;
/// Default staleness age threshold in days.
pub const DEFAULT_WARN_AGE_DAYS: i64 = 365;
/// Default cache TTL in minutes.
pub const DEFAULT_CACHE_TTL_MINUTES: u64 = 30;

/// Top-level runtime configuration for package evaluation.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SafePkgsConfig {
    /// Minimum version age accepted by the version-age check.
    pub min_version_age_days: i64,
    /// Minimum weekly downloads expected by popularity-related checks.
    pub min_weekly_downloads: u64,
    /// Maximum risk threshold that still allows installation.
    pub max_risk: Severity,
    /// Package allowlist rules.
    pub allowlist: AllowlistConfig,
    /// Package and publisher denylist rules.
    pub denylist: DenylistConfig,
    /// Settings for staleness checks.
    pub staleness: StalenessConfig,
    /// Global and registry-specific check toggles.
    pub checks: ChecksConfig,
    /// Cache configuration.
    pub cache: CacheConfig,
    /// User-defined custom policy rules evaluated against package metadata.
    pub custom_rules: Vec<CustomRuleConfig>,
}

/// Allowlist configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct AllowlistConfig {
    /// Package rules in `name` or `name@version` form.
    pub packages: Vec<String>,
}

/// Denylist configuration.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DenylistConfig {
    /// Package rules in `name` or `name@version` form.
    pub packages: Vec<String>,
    /// Publisher names blocked regardless of package name.
    pub publishers: Vec<String>,
}

/// Staleness-check tuning parameters.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct StalenessConfig {
    /// Warn when package is this many major versions behind latest.
    pub warn_major_versions_behind: u64,
    /// Warn when package is this many minor versions behind latest.
    pub warn_minor_versions_behind: u64,
    /// Warn when latest release is older than this many days.
    pub warn_age_days: i64,
    /// Package patterns ignored by staleness checks.
    pub ignore_for: Vec<String>,
}

/// Cache settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Cache entry TTL in minutes.
    pub ttl_minutes: u64,
}

/// Check enable/disable policy.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ChecksConfig {
    /// Checks disabled for all registries.
    pub disable: Vec<String>,
    /// Per-registry check toggles keyed by registry id.
    pub registry: BTreeMap<String, RegistryChecksConfig>,
}

/// Registry-specific check toggles.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct RegistryChecksConfig {
    /// Checks disabled for this registry.
    pub disable: Vec<String>,
}

impl ChecksConfig {
    /// Returns whether a check should run for a registry.
    ///
    /// A check is enabled only when it is supported by the registry and not disabled
    /// globally or per registry.
    pub fn is_enabled_for_registry(
        &self,
        registry_key: &str,
        check: CheckId,
        supported_checks: &[CheckId],
    ) -> bool {
        let normalized_check = normalize_check_id(check);
        let is_supported = supported_checks
            .iter()
            .any(|candidate| normalize_check_id(candidate) == normalized_check);
        if !is_supported {
            return false;
        }

        let normalized_registry_key = normalize_registry_key(registry_key);
        let registry_entry = self.registry.get(normalized_registry_key.as_str());
        !self
            .disable
            .iter()
            .chain(
                registry_entry
                    .into_iter()
                    .flat_map(|entry| entry.disable.iter()),
            )
            .map(|value| normalize_check_id(value))
            .any(|disabled| disabled == normalized_check)
    }
}

impl Default for StalenessConfig {
    fn default() -> Self {
        Self {
            warn_major_versions_behind: DEFAULT_WARN_MAJOR_VERSIONS_BEHIND,
            warn_minor_versions_behind: DEFAULT_WARN_MINOR_VERSIONS_BEHIND,
            warn_age_days: DEFAULT_WARN_AGE_DAYS,
            ignore_for: Vec::new(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            ttl_minutes: DEFAULT_CACHE_TTL_MINUTES,
        }
    }
}

impl Default for SafePkgsConfig {
    fn default() -> Self {
        Self {
            min_version_age_days: DEFAULT_MIN_VERSION_AGE_DAYS,
            min_weekly_downloads: DEFAULT_MIN_WEEKLY_DOWNLOADS,
            max_risk: DEFAULT_MAX_RISK,
            allowlist: AllowlistConfig::default(),
            denylist: DenylistConfig::default(),
            staleness: StalenessConfig::default(),
            checks: ChecksConfig::default(),
            cache: CacheConfig::default(),
            custom_rules: Vec::new(),
        }
    }
}

impl SafePkgsConfig {
    /// Loads and merges global + project configuration from default paths.
    ///
    /// # Errors
    ///
    /// Returns an error if any discovered config file cannot be read or parsed.
    pub fn load() -> anyhow::Result<Self> {
        Self::load_with_paths(global_config_path(), project_config_path())
    }

    #[cfg(test)]
    fn load_from_path(path: &Path) -> anyhow::Result<Self> {
        Self::load_with_paths(Some(path.to_path_buf()), None)
    }

    fn load_with_paths(global: Option<PathBuf>, project: Option<PathBuf>) -> anyhow::Result<Self> {
        let mut config = Self::default();
        if let Some(path) = global {
            config.merge_from_path(&path)?;
        }
        if let Some(path) = project {
            config.merge_from_path(&path)?;
        }
        config.validate()?;
        Ok(config)
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        custom_rules::validate_rules(&self.custom_rules)
    }

    fn merge_from_path(&mut self, path: &Path) -> anyhow::Result<()> {
        if !path.exists() {
            return Ok(());
        }

        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file at {}", path.display()))?;
        let overlay: ConfigOverlay = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file at {}", path.display()))?;
        self.apply_overlay(overlay);
        Ok(())
    }

    fn apply_overlay(&mut self, overlay: ConfigOverlay) {
        if let Some(value) = overlay.min_version_age_days {
            self.min_version_age_days = sanitize_positive_i64(value, DEFAULT_MIN_VERSION_AGE_DAYS);
        }
        if let Some(value) = overlay.min_weekly_downloads {
            self.min_weekly_downloads = value;
        }
        if let Some(value) = overlay.max_risk {
            self.max_risk = value;
        }
        if let Some(value) = overlay.allowlist {
            append_unique(&mut self.allowlist.packages, value.packages);
        }
        if let Some(value) = overlay.denylist {
            append_unique(&mut self.denylist.packages, value.packages);
            append_unique(&mut self.denylist.publishers, value.publishers);
        }
        if let Some(value) = overlay.staleness {
            if let Some(major) = value.warn_major_versions_behind {
                self.staleness.warn_major_versions_behind =
                    sanitize_positive_u64(major, DEFAULT_WARN_MAJOR_VERSIONS_BEHIND);
            }
            if let Some(minor) = value.warn_minor_versions_behind {
                self.staleness.warn_minor_versions_behind =
                    sanitize_positive_u64(minor, DEFAULT_WARN_MINOR_VERSIONS_BEHIND);
            }
            if let Some(age_days) = value.warn_age_days {
                self.staleness.warn_age_days =
                    sanitize_positive_i64(age_days, DEFAULT_WARN_AGE_DAYS);
            }
            append_unique(
                &mut self.staleness.ignore_for,
                value.ignore_for.unwrap_or_default(),
            );
        }
        if let Some(value) = overlay.checks {
            append_unique(&mut self.checks.disable, value.disable.unwrap_or_default());
            for (registry_key, registry_checks) in value.registry {
                let normalized_registry_key = normalize_registry_key(&registry_key);
                let entry = self
                    .checks
                    .registry
                    .entry(normalized_registry_key)
                    .or_default();
                append_unique(
                    &mut entry.disable,
                    registry_checks.disable.unwrap_or_default(),
                );
            }
        }
        if let Some(value) = overlay.cache
            && let Some(ttl_minutes) = value.ttl_minutes
        {
            self.cache.ttl_minutes = sanitize_positive_u64(ttl_minutes, DEFAULT_CACHE_TTL_MINUTES);
        }
        if !overlay.custom_rules.is_empty() {
            custom_rules::merge_rules(&mut self.custom_rules, overlay.custom_rules);
        }
    }
}

fn global_config_path() -> Option<PathBuf> {
    if let Some(explicit) = env::var_os("SAFE_PKGS_CONFIG_GLOBAL_PATH") {
        return Some(PathBuf::from(explicit));
    }

    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)?;

    Some(home.join(".config").join("safe-pkgs").join("config.toml"))
}

fn project_config_path() -> Option<PathBuf> {
    if let Some(explicit) = env::var_os("SAFE_PKGS_CONFIG_PROJECT_PATH") {
        return Some(PathBuf::from(explicit));
    }

    let cwd = env::current_dir().ok()?;
    Some(cwd.join(".safe-pkgs.toml"))
}

fn append_unique(target: &mut Vec<String>, values: Vec<String>) {
    for value in values {
        if !target.iter().any(|existing| existing == &value) {
            target.push(value);
        }
    }
}

fn sanitize_positive_u64(value: u64, fallback: u64) -> u64 {
    if value == 0 { fallback } else { value }
}

fn sanitize_positive_i64(value: i64, fallback: i64) -> i64 {
    if value <= 0 { fallback } else { value }
}

fn normalize_registry_key(raw: &str) -> String {
    raw.to_ascii_lowercase()
}

#[cfg(test)]
#[path = "../tests/config.rs"]
mod tests;
