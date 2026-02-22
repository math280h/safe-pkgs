//! Custom user-defined rule evaluation over package/registry metadata.

use chrono::Utc;
use safe_pkgs_core::{CheckExecutionContext, CheckFinding};
use serde_json::Value as JsonValue;

use crate::config::{
    CustomRuleConfig, CustomRuleField, CustomRuleMatchMode, CustomRuleOperator, SafePkgsConfig,
};

/// Runtime requirements implied by enabled custom rules.
#[derive(Debug, Clone, Copy, Default)]
pub struct CustomRuleRuntimeRequirements {
    pub needs_weekly_downloads: bool,
    pub needs_advisories: bool,
}

/// Computes data-fetch requirements for enabled custom rules in a registry.
pub fn runtime_requirements_for_registry(
    config: &SafePkgsConfig,
    registry_key: &str,
) -> CustomRuleRuntimeRequirements {
    let mut requirements = CustomRuleRuntimeRequirements::default();

    for rule in config
        .custom_rules
        .iter()
        .filter(|rule| rule.enabled && rule.matches_registry(registry_key))
    {
        for condition in &rule.conditions {
            match condition.field {
                CustomRuleField::WeeklyDownloads => requirements.needs_weekly_downloads = true,
                CustomRuleField::AdvisoryCount | CustomRuleField::AdvisoryIds => {
                    requirements.needs_advisories = true
                }
                _ => {}
            }
        }
    }

    requirements
}

/// Evaluates enabled custom rules for a package execution context.
pub fn findings_for_package(
    config: &SafePkgsConfig,
    context: &CheckExecutionContext<'_>,
) -> Vec<CheckFinding> {
    config
        .custom_rules
        .iter()
        .filter(|rule| rule.enabled && rule.matches_registry(context.registry_key))
        .filter(|rule| rule_matches(rule, context))
        .map(|rule| CheckFinding {
            severity: rule.severity,
            reason: custom_rule_reason(rule),
        })
        .collect()
}

fn custom_rule_reason(rule: &CustomRuleConfig) -> String {
    if let Some(reason) = rule.reason.as_deref() {
        return format!("custom rule '{}' matched: {}", rule.id, reason);
    }
    format!("custom rule '{}' matched", rule.id)
}

fn rule_matches(rule: &CustomRuleConfig, context: &CheckExecutionContext<'_>) -> bool {
    match rule.match_mode {
        CustomRuleMatchMode::All => rule
            .conditions
            .iter()
            .all(|condition| condition_matches(condition, context)),
        CustomRuleMatchMode::Any => rule
            .conditions
            .iter()
            .any(|condition| condition_matches(condition, context)),
    }
}

fn condition_matches(
    condition: &crate::config::CustomRuleCondition,
    context: &CheckExecutionContext<'_>,
) -> bool {
    use CustomRuleOperator as Op;

    let actual = actual_value(condition.field, context);
    match condition.op {
        Op::Exists => {
            let expected = condition
                .value
                .as_ref()
                .and_then(JsonValue::as_bool)
                .unwrap_or(true);
            actual.is_some() == expected
        }
        Op::Eq => compare_eq(actual.as_ref(), condition.value.as_ref()),
        Op::Ne => !compare_eq(actual.as_ref(), condition.value.as_ref()),
        Op::Gt => compare_number(actual.as_ref(), condition.value.as_ref(), |a, b| a > b),
        Op::Gte => compare_number(actual.as_ref(), condition.value.as_ref(), |a, b| a >= b),
        Op::Lt => compare_number(actual.as_ref(), condition.value.as_ref(), |a, b| a < b),
        Op::Lte => compare_number(actual.as_ref(), condition.value.as_ref(), |a, b| a <= b),
        Op::Contains => compare_contains(actual.as_ref(), condition.value.as_ref()),
        Op::StartsWith => compare_string_prefix(actual.as_ref(), condition.value.as_ref(), true),
        Op::EndsWith => compare_string_prefix(actual.as_ref(), condition.value.as_ref(), false),
        Op::In => compare_in(actual.as_ref(), condition.value.as_ref()),
    }
}

fn compare_eq(actual: Option<&RuntimeValue>, expected: Option<&JsonValue>) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    let Some(expected) = expected else {
        return false;
    };

    match actual {
        RuntimeValue::String(value) => expected.as_str() == Some(value.as_str()),
        RuntimeValue::Bool(value) => expected.as_bool() == Some(*value),
        RuntimeValue::Number(value) => parse_json_number(expected) == Some(*value),
        RuntimeValue::StringList(_) => false,
    }
}

fn compare_number<F>(
    actual: Option<&RuntimeValue>,
    expected: Option<&JsonValue>,
    predicate: F,
) -> bool
where
    F: Fn(i128, i128) -> bool,
{
    let Some(RuntimeValue::Number(actual_number)) = actual else {
        return false;
    };
    let Some(expected) = expected else {
        return false;
    };
    let Some(expected_number) = parse_json_number(expected) else {
        return false;
    };
    predicate(*actual_number, expected_number)
}

fn compare_contains(actual: Option<&RuntimeValue>, expected: Option<&JsonValue>) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    let Some(expected) = expected.and_then(JsonValue::as_str) else {
        return false;
    };

    match actual {
        RuntimeValue::String(value) => value.contains(expected),
        RuntimeValue::StringList(values) => values.iter().any(|value| value == expected),
        RuntimeValue::Bool(_) | RuntimeValue::Number(_) => false,
    }
}

fn compare_string_prefix(
    actual: Option<&RuntimeValue>,
    expected: Option<&JsonValue>,
    starts_with: bool,
) -> bool {
    let Some(RuntimeValue::String(actual_string)) = actual else {
        return false;
    };
    let Some(expected) = expected.and_then(JsonValue::as_str) else {
        return false;
    };

    if starts_with {
        actual_string.starts_with(expected)
    } else {
        actual_string.ends_with(expected)
    }
}

fn compare_in(actual: Option<&RuntimeValue>, expected: Option<&JsonValue>) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    let Some(values) = expected.and_then(JsonValue::as_array) else {
        return false;
    };

    match actual {
        RuntimeValue::String(value) => values.iter().any(|item| item.as_str() == Some(value)),
        RuntimeValue::Bool(value) => values.iter().any(|item| item.as_bool() == Some(*value)),
        RuntimeValue::Number(value) => values
            .iter()
            .filter_map(parse_json_number)
            .any(|item| item == *value),
        RuntimeValue::StringList(_) => false,
    }
}

fn actual_value(
    field: CustomRuleField,
    context: &CheckExecutionContext<'_>,
) -> Option<RuntimeValue> {
    match field {
        CustomRuleField::Registry => Some(RuntimeValue::String(context.registry_key.to_string())),
        CustomRuleField::PackageName => {
            Some(RuntimeValue::String(context.package_name.to_string()))
        }
        CustomRuleField::RequestedVersion => context
            .requested_version
            .map(|value| RuntimeValue::String(value.to_string())),
        CustomRuleField::LatestVersion => context
            .package
            .map(|package| RuntimeValue::String(package.latest.clone())),
        CustomRuleField::ResolvedVersion => context
            .resolved_version
            .map(|version| RuntimeValue::String(version.version.clone())),
        CustomRuleField::VersionAgeDays => context.resolved_version.and_then(|version| {
            version.published.map(|published| {
                let age_days = Utc::now().signed_duration_since(published).num_days();
                RuntimeValue::Number(i128::from(age_days))
            })
        }),
        CustomRuleField::VersionDeprecated => context
            .resolved_version
            .map(|version| RuntimeValue::Bool(version.deprecated)),
        CustomRuleField::HasInstallScripts => context
            .resolved_version
            .map(|version| RuntimeValue::Bool(!version.install_scripts.is_empty())),
        CustomRuleField::InstallScriptCount => context.resolved_version.map(|version| {
            RuntimeValue::Number(i128::try_from(version.install_scripts.len()).unwrap_or(i128::MAX))
        }),
        CustomRuleField::PublisherCount => context.package.map(|package| {
            RuntimeValue::Number(i128::try_from(package.publishers.len()).unwrap_or(i128::MAX))
        }),
        CustomRuleField::Publishers => context
            .package
            .map(|package| RuntimeValue::StringList(package.publishers.clone())),
        CustomRuleField::WeeklyDownloads => context
            .weekly_downloads
            .map(|downloads| RuntimeValue::Number(i128::from(downloads))),
        CustomRuleField::AdvisoryCount => Some(RuntimeValue::Number(
            i128::try_from(context.advisories.len()).unwrap_or(i128::MAX),
        )),
        CustomRuleField::AdvisoryIds => Some(RuntimeValue::StringList(
            context
                .advisories
                .iter()
                .map(|advisory| advisory.id.clone())
                .collect(),
        )),
    }
}

#[derive(Debug, Clone)]
enum RuntimeValue {
    String(String),
    Bool(bool),
    Number(i128),
    StringList(Vec<String>),
}

fn parse_json_number(value: &JsonValue) -> Option<i128> {
    if let Some(number) = value.as_i64() {
        return Some(i128::from(number));
    }
    value.as_u64().map(i128::from)
}
