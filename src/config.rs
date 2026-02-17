use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Deserialize;

use crate::types::Severity;

pub const DEFAULT_MIN_VERSION_AGE_DAYS: i64 = 7;
pub const DEFAULT_MIN_WEEKLY_DOWNLOADS: u64 = 50;
pub const DEFAULT_MAX_RISK: Severity = Severity::Medium;
pub const DEFAULT_WARN_MAJOR_VERSIONS_BEHIND: u64 = 2;
pub const DEFAULT_WARN_MINOR_VERSIONS_BEHIND: u64 = 3;
pub const DEFAULT_WARN_AGE_DAYS: i64 = 365;
pub const DEFAULT_CACHE_TTL_MINUTES: u64 = 30;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SafePkgsConfig {
    pub min_version_age_days: i64,
    pub min_weekly_downloads: u64,
    pub max_risk: Severity,
    pub allowlist: AllowlistConfig,
    pub denylist: DenylistConfig,
    pub staleness: StalenessConfig,
    pub cache: CacheConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AllowlistConfig {
    pub packages: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DenylistConfig {
    pub packages: Vec<String>,
    pub publishers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StalenessConfig {
    pub warn_major_versions_behind: u64,
    pub warn_minor_versions_behind: u64,
    pub warn_age_days: i64,
    pub ignore_for: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    pub ttl_minutes: u64,
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
            cache: CacheConfig::default(),
        }
    }
}

impl SafePkgsConfig {
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
        Ok(config)
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
        if let Some(value) = overlay.cache
            && let Some(ttl_minutes) = value.ttl_minutes
        {
            self.cache.ttl_minutes = sanitize_positive_u64(ttl_minutes, DEFAULT_CACHE_TTL_MINUTES);
        }
    }
}

fn global_config_path() -> Option<PathBuf> {
    if let Some(explicit) = env::var_os("SAFE_PKGS_CONFIG_PATH") {
        return Some(PathBuf::from(explicit));
    }

    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)?;

    Some(home.join(".config").join("safe-pkgs").join("config.toml"))
}

fn project_config_path() -> Option<PathBuf> {
    if let Some(explicit) = env::var_os("SAFE_PKGS_PROJECT_CONFIG_PATH") {
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

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ConfigOverlay {
    min_version_age_days: Option<i64>,
    min_weekly_downloads: Option<u64>,
    max_risk: Option<Severity>,
    allowlist: Option<AllowlistConfig>,
    denylist: Option<DenylistConfig>,
    staleness: Option<StalenessOverlay>,
    cache: Option<CacheOverlay>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct StalenessOverlay {
    warn_major_versions_behind: Option<u64>,
    warn_minor_versions_behind: Option<u64>,
    warn_age_days: Option<i64>,
    ignore_for: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct CacheOverlay {
    ttl_minutes: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(file_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("safe-pkgs-{nanos}-{file_name}"))
    }

    #[test]
    fn missing_config_uses_defaults() {
        let path = unique_temp_path("missing-config.toml");
        let config = SafePkgsConfig::load_from_path(&path).expect("default config");

        assert_eq!(config.min_version_age_days, DEFAULT_MIN_VERSION_AGE_DAYS);
        assert_eq!(config.min_weekly_downloads, DEFAULT_MIN_WEEKLY_DOWNLOADS);
        assert_eq!(config.max_risk, DEFAULT_MAX_RISK);
        assert_eq!(
            config.staleness.warn_major_versions_behind,
            DEFAULT_WARN_MAJOR_VERSIONS_BEHIND
        );
        assert_eq!(
            config.staleness.warn_minor_versions_behind,
            DEFAULT_WARN_MINOR_VERSIONS_BEHIND
        );
        assert_eq!(config.staleness.warn_age_days, DEFAULT_WARN_AGE_DAYS);
        assert_eq!(config.cache.ttl_minutes, DEFAULT_CACHE_TTL_MINUTES);
    }

    #[test]
    fn parses_config_values_and_lists() {
        let path = unique_temp_path("config.toml");
        let raw = r#"
min_version_age_days = 14
min_weekly_downloads = 250
max_risk = "high"

[allowlist]
packages = ["internal-lib", "internal-lib@1.2.3"]

[denylist]
packages = ["bad-lib", "danger-lib@0.1.0"]
publishers = ["suspicious-user"]

[staleness]
warn_major_versions_behind = 4
warn_minor_versions_behind = 8
warn_age_days = 500
ignore_for = ["legacy-pkg@1.x"]

[cache]
ttl_minutes = 45
"#;
        fs::write(&path, raw).expect("write config");

        let config = SafePkgsConfig::load_from_path(&path).expect("parsed config");
        let _ = fs::remove_file(path);

        assert_eq!(config.min_version_age_days, 14);
        assert_eq!(config.min_weekly_downloads, 250);
        assert_eq!(config.max_risk, Severity::High);
        assert_eq!(
            config.allowlist.packages,
            vec!["internal-lib", "internal-lib@1.2.3"]
        );
        assert_eq!(
            config.denylist.packages,
            vec!["bad-lib", "danger-lib@0.1.0"]
        );
        assert_eq!(config.denylist.publishers, vec!["suspicious-user"]);
        assert_eq!(config.staleness.warn_major_versions_behind, 4);
        assert_eq!(config.staleness.warn_minor_versions_behind, 8);
        assert_eq!(config.staleness.warn_age_days, 500);
        assert_eq!(config.staleness.ignore_for, vec!["legacy-pkg@1.x"]);
        assert_eq!(config.cache.ttl_minutes, 45);
    }

    #[test]
    fn project_overrides_global_config() {
        let global_path = unique_temp_path("global-config.toml");
        let project_path = unique_temp_path("project-config.toml");
        fs::write(
            &global_path,
            r#"
min_version_age_days = 10
min_weekly_downloads = 100

[allowlist]
packages = ["global-allow"]

[staleness]
warn_minor_versions_behind = 6
ignore_for = ["legacy-one@1.x"]
"#,
        )
        .expect("write global config");
        fs::write(
            &project_path,
            r#"
min_version_age_days = 2

[allowlist]
packages = ["project-allow"]

[denylist]
packages = ["project-deny"]

[staleness]
warn_major_versions_behind = 5
warn_age_days = 730
ignore_for = ["legacy-two@2.x"]

[cache]
ttl_minutes = 5
"#,
        )
        .expect("write project config");

        let config =
            SafePkgsConfig::load_with_paths(Some(global_path.clone()), Some(project_path.clone()))
                .expect("merged config");

        let _ = fs::remove_file(global_path);
        let _ = fs::remove_file(project_path);

        assert_eq!(config.min_version_age_days, 2);
        assert_eq!(config.min_weekly_downloads, 100);
        assert_eq!(
            config.allowlist.packages,
            vec!["global-allow".to_string(), "project-allow".to_string()]
        );
        assert_eq!(config.denylist.packages, vec!["project-deny".to_string()]);
        assert_eq!(config.staleness.warn_major_versions_behind, 5);
        assert_eq!(config.staleness.warn_minor_versions_behind, 6);
        assert_eq!(config.staleness.warn_age_days, 730);
        assert_eq!(
            config.staleness.ignore_for,
            vec!["legacy-one@1.x".to_string(), "legacy-two@2.x".to_string()]
        );
        assert_eq!(config.cache.ttl_minutes, 5);
    }
}
