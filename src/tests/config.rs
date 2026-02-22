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
    assert!(config.checks.disable.is_empty());
    assert!(config.checks.registry.is_empty());
    assert_eq!(config.cache.ttl_minutes, DEFAULT_CACHE_TTL_MINUTES);
    assert!(config.custom_rules.is_empty());
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

[checks]
disable = ["typosquat"]

[checks.registry.NPM]
disable = ["install_script"]

[cache]
ttl_minutes = 45

[[custom_rules]]
id = "block-new-packages"
severity = "high"
reason = "recent package versions are blocked"
registries = ["npm"]
match = "all"
conditions = [
  { field = "version_age_days", op = "lt", value = 3 },
  { field = "weekly_downloads", op = "lt", value = 100 }
]
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
    assert_eq!(config.checks.disable, vec!["typosquat"]);
    assert_eq!(
        config
            .checks
            .registry
            .get("npm")
            .expect("npm checks override")
            .disable,
        vec!["install_script"]
    );
    assert_eq!(config.cache.ttl_minutes, 45);
    assert_eq!(config.custom_rules.len(), 1);
    assert_eq!(config.custom_rules[0].id, "block-new-packages");
    assert_eq!(config.custom_rules[0].conditions.len(), 2);
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

[checks]
disable = ["advisory"]

[checks.registry.npm]
disable = ["install_script"]

[[custom_rules]]
id = "global-rule"
severity = "low"
conditions = [
  { field = "registry", op = "eq", value = "cargo" }
]
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

[checks]
disable = ["typosquat"]

[checks.registry.npm]
disable = ["version_age"]

[checks.registry.cargo]
disable = ["popularity"]

[cache]
ttl_minutes = 5

[[custom_rules]]
id = "global-rule"
severity = "medium"
conditions = [
  { field = "registry", op = "eq", value = "npm" }
]

[[custom_rules]]
id = "project-only"
severity = "high"
conditions = [
  { field = "weekly_downloads", op = "lt", value = 1000 }
]
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
    assert_eq!(
        config.checks.disable,
        vec!["advisory".to_string(), "typosquat".to_string()]
    );
    assert_eq!(
        config
            .checks
            .registry
            .get("npm")
            .expect("npm overrides")
            .disable,
        vec!["install_script".to_string(), "version_age".to_string()]
    );
    assert_eq!(
        config
            .checks
            .registry
            .get("cargo")
            .expect("cargo overrides")
            .disable,
        vec!["popularity".to_string()]
    );
    assert_eq!(config.cache.ttl_minutes, 5);
    assert_eq!(config.custom_rules.len(), 2);
    assert_eq!(config.custom_rules[0].id, "global-rule");
    assert_eq!(config.custom_rules[0].severity, Severity::Medium);
    assert_eq!(config.custom_rules[1].id, "project-only");
    assert_eq!(config.custom_rules[1].severity, Severity::High);
}

#[test]
fn checks_config_honors_global_and_registry_disables() {
    let mut checks = ChecksConfig {
        disable: vec!["typosquat".to_string(), "unknown-check".to_string()],
        ..ChecksConfig::default()
    };
    checks.registry.insert(
        "cargo".to_string(),
        RegistryChecksConfig {
            disable: vec!["popularity".to_string()],
        },
    );
    let supported = [
        "existence",
        "version_age",
        "staleness",
        "popularity",
        "typosquat",
        "advisory",
    ];

    assert!(!checks.is_enabled_for_registry("cargo", "typosquat", &supported));
    assert!(!checks.is_enabled_for_registry("cargo", "popularity", &supported));
    assert!(!checks.is_enabled_for_registry("CARGO", "popularity", &supported));
    assert!(checks.is_enabled_for_registry("cargo", "advisory", &supported));
    assert!(!checks.is_enabled_for_registry("cargo", "install_script", &supported));
}

#[test]
fn invalid_custom_rule_is_rejected() {
    let path = unique_temp_path("invalid-custom-rule.toml");
    let raw = r#"
[[custom_rules]]
id = "broken"
severity = "high"
conditions = [
  { field = "weekly_downloads", op = "contains", value = "10" }
]
"#;
    fs::write(&path, raw).expect("write config");

    let err = SafePkgsConfig::load_from_path(&path).expect_err("invalid rule should fail");
    let _ = fs::remove_file(path);
    assert!(
        err.to_string()
            .contains("contains supports string or string-list fields")
    );
}

#[test]
fn float_numeric_custom_rule_value_is_rejected() {
    let path = unique_temp_path("float-custom-rule.toml");
    let raw = r#"
[[custom_rules]]
id = "float-threshold"
severity = "high"
conditions = [
  { field = "weekly_downloads", op = "lt", value = 10.5 }
]
"#;
    fs::write(&path, raw).expect("write config");

    let err = SafePkgsConfig::load_from_path(&path).expect_err("float threshold should fail");
    let _ = fs::remove_file(path);
    assert!(
        err.to_string()
            .contains("requires integer value (floats are not supported)")
    );
}
