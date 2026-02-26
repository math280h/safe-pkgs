//! Deterministic policy snapshot and fingerprint helpers.

use std::collections::BTreeMap;

use anyhow::Context;
use serde::Serialize;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::config::{
    CustomRuleCondition, CustomRuleConfig, CustomRuleMatchMode, CustomRuleOperator, SafePkgsConfig,
};
use crate::registries::normalize_check_id;
use crate::types::Severity;

/// Increment when canonical snapshot format changes.
pub const POLICY_SNAPSHOT_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize)]
struct ConfigSnapshot {
    version: u8,
    min_version_age_days: i64,
    min_weekly_downloads: u64,
    max_risk: Severity,
    allowlist_packages: Vec<String>,
    denylist_packages: Vec<String>,
    denylist_publishers: Vec<String>,
    staleness: StalenessSnapshot,
    checks: ChecksSnapshot,
    custom_rules: Vec<CustomRuleSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct StalenessSnapshot {
    warn_major_versions_behind: u64,
    warn_minor_versions_behind: u64,
    warn_age_days: i64,
    ignore_for: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ChecksSnapshot {
    disable: Vec<String>,
    registry: BTreeMap<String, RegistryChecksSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct RegistryChecksSnapshot {
    disable: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CustomRuleSnapshot {
    id: String,
    enabled: bool,
    registries: Vec<String>,
    match_mode: CustomRuleMatchMode,
    severity: Severity,
    reason: Option<String>,
    conditions: Vec<CustomRuleConditionSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
struct CustomRuleConditionSnapshot {
    field: crate::config::CustomRuleField,
    op: CustomRuleOperator,
    value: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize)]
struct PolicySnapshotForHash {
    version: u8,
    registry: String,
    config_fingerprint: String,
    enabled_checks: Vec<String>,
}

/// Registry-scoped deterministic policy materialization.
#[derive(Debug, Clone)]
pub struct RegistryPolicySnapshot {
    pub version: u8,
    pub policy_fingerprint: String,
    pub enabled_checks: Vec<String>,
}

/// Computes canonical config fingerprint from policy-related config fields.
///
/// This intentionally excludes runtime operational settings such as cache TTL.
pub fn compute_config_fingerprint(config: &SafePkgsConfig) -> anyhow::Result<String> {
    let snapshot = canonical_config_snapshot(config);
    fingerprint_json(
        &snapshot,
        "failed to serialize config for policy fingerprint",
    )
}

/// Builds a registry-scoped policy snapshot with deterministic fingerprints.
pub fn build_registry_policy_snapshot(
    config: &SafePkgsConfig,
    registry_key: &str,
    enabled_checks: &[String],
) -> anyhow::Result<RegistryPolicySnapshot> {
    let config_fingerprint = compute_config_fingerprint(config)?;
    let mut normalized_checks = enabled_checks
        .iter()
        .map(|value| normalize_check_id(value))
        .collect::<Vec<_>>();
    normalized_checks.sort();
    normalized_checks.dedup();

    let hash_input = PolicySnapshotForHash {
        version: POLICY_SNAPSHOT_VERSION,
        registry: registry_key.to_ascii_lowercase(),
        config_fingerprint: config_fingerprint.clone(),
        enabled_checks: normalized_checks.clone(),
    };
    let policy_fingerprint = fingerprint_json(
        &hash_input,
        "failed to serialize policy snapshot for policy fingerprint",
    )?;

    Ok(RegistryPolicySnapshot {
        version: POLICY_SNAPSHOT_VERSION,
        policy_fingerprint,
        enabled_checks: normalized_checks,
    })
}

fn canonical_config_snapshot(config: &SafePkgsConfig) -> ConfigSnapshot {
    let mut checks_registry = BTreeMap::new();
    for (registry_key, registry_checks) in &config.checks.registry {
        checks_registry.insert(
            registry_key.to_ascii_lowercase(),
            RegistryChecksSnapshot {
                disable: normalize_check_id_list(registry_checks.disable.clone()),
            },
        );
    }

    let mut custom_rules = config
        .custom_rules
        .iter()
        .map(canonical_custom_rule)
        .collect::<Vec<_>>();
    custom_rules.sort_by(|left, right| {
        (
            left.id.as_str(),
            left.enabled,
            left.severity,
            left.reason.as_deref(),
        )
            .cmp(&(
                right.id.as_str(),
                right.enabled,
                right.severity,
                right.reason.as_deref(),
            ))
    });

    ConfigSnapshot {
        version: POLICY_SNAPSHOT_VERSION,
        min_version_age_days: config.min_version_age_days,
        min_weekly_downloads: config.min_weekly_downloads,
        max_risk: config.max_risk,
        allowlist_packages: sort_and_dedup(config.allowlist.packages.clone()),
        denylist_packages: sort_and_dedup(config.denylist.packages.clone()),
        denylist_publishers: sort_and_dedup(config.denylist.publishers.clone()),
        staleness: StalenessSnapshot {
            warn_major_versions_behind: config.staleness.warn_major_versions_behind,
            warn_minor_versions_behind: config.staleness.warn_minor_versions_behind,
            warn_age_days: config.staleness.warn_age_days,
            ignore_for: sort_and_dedup(config.staleness.ignore_for.clone()),
        },
        checks: ChecksSnapshot {
            disable: normalize_check_id_list(config.checks.disable.clone()),
            registry: checks_registry,
        },
        custom_rules,
    }
}

fn canonical_custom_rule(rule: &CustomRuleConfig) -> CustomRuleSnapshot {
    let mut registries = rule
        .registries
        .iter()
        .map(|registry| registry.to_ascii_lowercase())
        .collect::<Vec<_>>();
    registries.sort();
    registries.dedup();

    let mut conditions = rule
        .conditions
        .iter()
        .map(canonical_custom_rule_condition)
        .collect::<Vec<_>>();
    conditions.sort_by_cached_key(|condition| {
        (
            custom_rule_field_key(condition.field),
            custom_rule_operator_key(condition.op),
            condition.value.as_ref().map(JsonValue::to_string),
        )
    });

    CustomRuleSnapshot {
        id: rule.id.clone(),
        enabled: rule.enabled,
        registries,
        match_mode: rule.match_mode,
        severity: rule.severity,
        reason: rule.reason.clone(),
        conditions,
    }
}

fn canonical_custom_rule_condition(condition: &CustomRuleCondition) -> CustomRuleConditionSnapshot {
    CustomRuleConditionSnapshot {
        field: condition.field,
        op: condition.op,
        value: canonical_condition_value(condition.op, condition.value.as_ref()),
    }
}

fn canonical_condition_value(
    op: CustomRuleOperator,
    value: Option<&JsonValue>,
) -> Option<JsonValue> {
    let value = value.map(canonicalize_json)?;
    if op != CustomRuleOperator::In {
        return Some(value);
    }

    match value {
        JsonValue::Array(mut values) => {
            values.sort_by_cached_key(JsonValue::to_string);
            Some(JsonValue::Array(values))
        }
        other => Some(other),
    }
}

fn canonicalize_json(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Array(items) => {
            JsonValue::Array(items.iter().map(canonicalize_json).collect::<Vec<_>>())
        }
        JsonValue::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (key, nested) in map {
                sorted.insert(key.clone(), canonicalize_json(nested));
            }
            let mut output = serde_json::Map::new();
            for (key, nested) in sorted {
                output.insert(key, nested);
            }
            JsonValue::Object(output)
        }
        _ => value.clone(),
    }
}

fn custom_rule_field_key(field: crate::config::CustomRuleField) -> &'static str {
    use crate::config::CustomRuleField as Field;

    match field {
        Field::Registry => "registry",
        Field::PackageName => "package_name",
        Field::RequestedVersion => "requested_version",
        Field::LatestVersion => "latest_version",
        Field::ResolvedVersion => "resolved_version",
        Field::VersionAgeDays => "version_age_days",
        Field::VersionDeprecated => "version_deprecated",
        Field::HasInstallScripts => "has_install_scripts",
        Field::InstallScriptCount => "install_script_count",
        Field::PublisherCount => "publisher_count",
        Field::Publishers => "publishers",
        Field::WeeklyDownloads => "weekly_downloads",
        Field::AdvisoryCount => "advisory_count",
        Field::AdvisoryIds => "advisory_ids",
    }
}

fn custom_rule_operator_key(op: CustomRuleOperator) -> &'static str {
    use crate::config::CustomRuleOperator as Op;

    match op {
        Op::Eq => "eq",
        Op::Ne => "ne",
        Op::Gt => "gt",
        Op::Gte => "gte",
        Op::Lt => "lt",
        Op::Lte => "lte",
        Op::Contains => "contains",
        Op::StartsWith => "starts_with",
        Op::EndsWith => "ends_with",
        Op::In => "in",
        Op::Exists => "exists",
    }
}

fn normalize_check_id_list(values: Vec<String>) -> Vec<String> {
    let mut normalized = values
        .into_iter()
        .map(|value| normalize_check_id(&value))
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn sort_and_dedup(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn fingerprint_json<T: Serialize>(value: &T, context: &str) -> anyhow::Result<String> {
    let encoded = serde_json::to_vec(value).context(context.to_string())?;
    let digest = Sha256::digest(encoded);
    Ok(encode_hex_lower(digest.as_slice()))
}

fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(*byte >> 4)]));
        output.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
#[path = "tests/policy_snapshot.rs"]
mod tests;
