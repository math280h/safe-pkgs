use super::*;
use crate::config::{
    CustomRuleCondition, CustomRuleConfig, CustomRuleField, CustomRuleMatchMode,
    CustomRuleOperator, RegistryChecksConfig, SafePkgsConfig,
};
use crate::types::Severity;
use serde_json::json;

#[test]
fn config_fingerprint_is_stable_for_equivalent_policy_inputs() {
    let mut first = SafePkgsConfig::default();
    first.allowlist.packages = vec!["zeta".to_string(), "alpha".to_string()];
    first.denylist.packages = vec!["blocked@1.0.0".to_string(), "bad".to_string()];
    first.denylist.publishers = vec!["Foo".to_string(), "bar".to_string()];
    first.staleness.ignore_for = vec!["legacy@2.x".to_string(), "legacy@1.x".to_string()];
    first.checks.disable = vec!["Typosquat".to_string(), "install-script".to_string()];
    first.checks.registry.insert(
        "NPM".to_string(),
        RegistryChecksConfig {
            disable: vec!["Version-Age".to_string(), "typosquat".to_string()],
        },
    );
    first.custom_rules = vec![CustomRuleConfig {
        id: "low-downloads".to_string(),
        enabled: true,
        registries: vec!["NPM".to_string(), "cargo".to_string()],
        match_mode: CustomRuleMatchMode::Any,
        severity: Severity::High,
        reason: Some("test".to_string()),
        conditions: vec![
            CustomRuleCondition {
                field: CustomRuleField::WeeklyDownloads,
                op: CustomRuleOperator::In,
                value: Some(json!([20, 10])),
            },
            CustomRuleCondition {
                field: CustomRuleField::Registry,
                op: CustomRuleOperator::In,
                value: Some(json!(["cargo", "npm"])),
            },
        ],
    }];

    let mut second = SafePkgsConfig::default();
    second.allowlist.packages = vec!["alpha".to_string(), "zeta".to_string()];
    second.denylist.packages = vec!["bad".to_string(), "blocked@1.0.0".to_string()];
    second.denylist.publishers = vec!["bar".to_string(), "Foo".to_string()];
    second.staleness.ignore_for = vec!["legacy@1.x".to_string(), "legacy@2.x".to_string()];
    second.checks.disable = vec!["install_script".to_string(), "typosquat".to_string()];
    second.checks.registry.insert(
        "npm".to_string(),
        RegistryChecksConfig {
            disable: vec!["typosquat".to_string(), "version_age".to_string()],
        },
    );
    second.custom_rules = vec![CustomRuleConfig {
        id: "low-downloads".to_string(),
        enabled: true,
        registries: vec!["cargo".to_string(), "npm".to_string()],
        match_mode: CustomRuleMatchMode::Any,
        severity: Severity::High,
        reason: Some("test".to_string()),
        conditions: vec![
            CustomRuleCondition {
                field: CustomRuleField::Registry,
                op: CustomRuleOperator::In,
                value: Some(json!(["npm", "cargo"])),
            },
            CustomRuleCondition {
                field: CustomRuleField::WeeklyDownloads,
                op: CustomRuleOperator::In,
                value: Some(json!([10, 20])),
            },
        ],
    }];

    let first_fingerprint = compute_config_fingerprint(&first).expect("first fingerprint");
    let second_fingerprint = compute_config_fingerprint(&second).expect("second fingerprint");
    assert_eq!(first_fingerprint, second_fingerprint);
}

#[test]
fn policy_fingerprint_changes_when_enabled_checks_change() {
    let config = SafePkgsConfig::default();
    let first = build_registry_policy_snapshot(
        &config,
        "npm",
        &["existence".to_string(), "version_age".to_string()],
    )
    .expect("first policy snapshot");
    let second = build_registry_policy_snapshot(&config, "npm", &["existence".to_string()])
        .expect("second policy snapshot");

    assert_ne!(first.policy_fingerprint, second.policy_fingerprint);
    assert_eq!(first.version, POLICY_SNAPSHOT_VERSION);
}
