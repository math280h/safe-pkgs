use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::types::Severity;

/// Custom rule condition field selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomRuleField {
    Registry,
    PackageName,
    RequestedVersion,
    LatestVersion,
    ResolvedVersion,
    VersionAgeDays,
    VersionDeprecated,
    HasInstallScripts,
    InstallScriptCount,
    PublisherCount,
    Publishers,
    WeeklyDownloads,
    AdvisoryCount,
    AdvisoryIds,
}

impl CustomRuleField {
    fn is_numeric(self) -> bool {
        matches!(
            self,
            Self::VersionAgeDays
                | Self::InstallScriptCount
                | Self::PublisherCount
                | Self::WeeklyDownloads
                | Self::AdvisoryCount
        )
    }

    fn is_bool(self) -> bool {
        matches!(self, Self::VersionDeprecated | Self::HasInstallScripts)
    }

    fn is_string(self) -> bool {
        matches!(
            self,
            Self::Registry
                | Self::PackageName
                | Self::RequestedVersion
                | Self::LatestVersion
                | Self::ResolvedVersion
        )
    }

    fn is_string_list(self) -> bool {
        matches!(self, Self::Publishers | Self::AdvisoryIds)
    }
}

/// Supported operators for custom rule conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomRuleOperator {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    StartsWith,
    EndsWith,
    In,
    Exists,
}

/// Condition for matching a custom rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomRuleCondition {
    pub field: CustomRuleField,
    pub op: CustomRuleOperator,
    #[serde(default)]
    pub value: Option<JsonValue>,
}

/// Condition aggregation mode for a custom rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CustomRuleMatchMode {
    #[default]
    All,
    Any,
}

/// User-defined custom rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CustomRuleConfig {
    /// Stable rule identifier.
    pub id: String,
    /// Whether this rule is active.
    pub enabled: bool,
    /// Registry keys this rule applies to (`npm`, `cargo`, `pypi`); empty means all.
    pub registries: Vec<String>,
    /// Condition aggregation mode.
    #[serde(rename = "match")]
    pub match_mode: CustomRuleMatchMode,
    /// Severity emitted when this rule matches.
    pub severity: Severity,
    /// Human-readable reason fragment.
    pub reason: Option<String>,
    /// Match conditions.
    pub conditions: Vec<CustomRuleCondition>,
}

impl Default for CustomRuleConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            enabled: true,
            registries: Vec::new(),
            match_mode: CustomRuleMatchMode::All,
            severity: Severity::Medium,
            reason: None,
            conditions: Vec::new(),
        }
    }
}

impl CustomRuleConfig {
    /// Returns whether this rule applies to the provided registry key.
    pub fn matches_registry(&self, registry_key: &str) -> bool {
        if self.registries.is_empty() {
            return true;
        }

        self.registries
            .iter()
            .any(|value| value.eq_ignore_ascii_case(registry_key))
    }
}

pub(super) fn merge_rules(target: &mut Vec<CustomRuleConfig>, values: Vec<CustomRuleConfig>) {
    for rule in values {
        if let Some(index) = target
            .iter()
            .position(|existing| existing.id.eq_ignore_ascii_case(rule.id.as_str()))
        {
            target.remove(index);
        }
        target.push(rule);
    }
}

pub(super) fn validate_rules(rules: &[CustomRuleConfig]) -> anyhow::Result<()> {
    let mut seen_ids = Vec::<String>::new();

    for rule in rules {
        let rule_id = rule.id.trim();
        if rule_id.is_empty() {
            anyhow::bail!("custom rule id must not be empty");
        }
        if seen_ids
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(rule_id))
        {
            anyhow::bail!("duplicate custom rule id '{}'", rule.id);
        }
        seen_ids.push(rule_id.to_ascii_lowercase());

        if let Some(reason) = rule.reason.as_deref()
            && reason.trim().is_empty()
        {
            anyhow::bail!("custom rule '{}' reason must not be empty", rule.id);
        }
        if rule.conditions.is_empty() {
            anyhow::bail!(
                "custom rule '{}' must define at least one condition",
                rule.id
            );
        }

        for condition in &rule.conditions {
            validate_condition(rule_id, condition)?;
        }
    }

    Ok(())
}

fn validate_condition(rule_id: &str, condition: &CustomRuleCondition) -> anyhow::Result<()> {
    use CustomRuleOperator as Op;

    match condition.op {
        Op::Exists => {
            if let Some(value) = condition.value.as_ref()
                && !value.is_boolean()
            {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} exists value must be boolean",
                    rule_id,
                    condition.field
                );
            }
            Ok(())
        }
        Op::Eq | Op::Ne => {
            let Some(value) = condition.value.as_ref() else {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} {:?} requires value",
                    rule_id,
                    condition.field,
                    condition.op
                );
            };
            if condition.field.is_numeric() {
                if parse_json_number(value).is_some() {
                    return Ok(());
                }
                if value.is_number() {
                    anyhow::bail!(
                        "custom rule '{}' condition {:?} {:?} requires integer value (floats are not supported)",
                        rule_id,
                        condition.field,
                        condition.op
                    );
                }
            }
            if condition.field.is_bool() && value.is_boolean() {
                return Ok(());
            }
            if condition.field.is_string() && value.is_string() {
                return Ok(());
            }
            anyhow::bail!(
                "custom rule '{}' condition {:?} {:?} has incompatible value type",
                rule_id,
                condition.field,
                condition.op
            );
        }
        Op::Gt | Op::Gte | Op::Lt | Op::Lte => {
            if !condition.field.is_numeric() {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} {:?} only supports numeric fields",
                    rule_id,
                    condition.field,
                    condition.op
                );
            }
            let Some(value) = condition.value.as_ref() else {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} {:?} requires value",
                    rule_id,
                    condition.field,
                    condition.op
                );
            };
            if parse_json_number(value).is_none() {
                if value.is_number() {
                    anyhow::bail!(
                        "custom rule '{}' condition {:?} {:?} requires integer value (floats are not supported)",
                        rule_id,
                        condition.field,
                        condition.op
                    );
                }
                anyhow::bail!(
                    "custom rule '{}' condition {:?} {:?} requires numeric value",
                    rule_id,
                    condition.field,
                    condition.op
                );
            }
            Ok(())
        }
        Op::Contains => {
            if !(condition.field.is_string() || condition.field.is_string_list()) {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} contains supports string or string-list fields",
                    rule_id,
                    condition.field
                );
            }
            let Some(value) = condition.value.as_ref() else {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} contains requires value",
                    rule_id,
                    condition.field
                );
            };
            if !value.is_string() {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} contains requires string value",
                    rule_id,
                    condition.field
                );
            }
            Ok(())
        }
        Op::StartsWith | Op::EndsWith => {
            if !condition.field.is_string() {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} {:?} only supports string fields",
                    rule_id,
                    condition.field,
                    condition.op
                );
            }
            let Some(value) = condition.value.as_ref() else {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} {:?} requires value",
                    rule_id,
                    condition.field,
                    condition.op
                );
            };
            if !value.is_string() {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} {:?} requires string value",
                    rule_id,
                    condition.field,
                    condition.op
                );
            }
            Ok(())
        }
        Op::In => {
            if condition.field.is_string_list() {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} in does not support list fields",
                    rule_id,
                    condition.field
                );
            }
            let Some(value) = condition.value.as_ref() else {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} in requires value",
                    rule_id,
                    condition.field
                );
            };
            let Some(items) = value.as_array() else {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} in requires array value",
                    rule_id,
                    condition.field
                );
            };
            if items.is_empty() {
                anyhow::bail!(
                    "custom rule '{}' condition {:?} in array must not be empty",
                    rule_id,
                    condition.field
                );
            }
            for item in items {
                if condition.field.is_numeric() {
                    if parse_json_number(item).is_some() {
                        continue;
                    }
                    if item.is_number() {
                        anyhow::bail!(
                            "custom rule '{}' condition {:?} in requires integer array items (floats are not supported)",
                            rule_id,
                            condition.field
                        );
                    }
                }
                if condition.field.is_bool() && item.is_boolean() {
                    continue;
                }
                if condition.field.is_string() && item.is_string() {
                    continue;
                }
                anyhow::bail!(
                    "custom rule '{}' condition {:?} in contains incompatible item",
                    rule_id,
                    condition.field
                );
            }
            Ok(())
        }
    }
}

fn parse_json_number(value: &JsonValue) -> Option<i128> {
    // Numeric custom-rule comparisons are intentionally integer-only.
    if let Some(number) = value.as_i64() {
        return Some(i128::from(number));
    }
    value.as_u64().map(i128::from)
}
