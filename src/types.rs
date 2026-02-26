//! Shared response types used by CLI and MCP tool handlers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Core metadata and risk severity types re-exported for consumers of this crate.
///
/// These types are defined and primarily documented in the `safe_pkgs_core` crate;
/// they are re-exported here so CLI commands and MCP tools can depend only on this
/// crate while still using the same canonical representations.
pub use safe_pkgs_core::{Metadata, Severity};

/// Deterministic fingerprints for correlating decision outputs with audit records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionFingerprints {
    /// Canonical hash of policy-relevant config.
    pub config: String,
    /// Registry-scoped hash of config fingerprint plus enabled checks.
    pub policy: String,
}

/// Source category for a machine-readable evidence item.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Evidence emitted by a built-in check that is part of the core tool.
    ///
    /// Use this for findings produced by standard, versioned checks that ship
    /// with `safe-pkgs`. The `id` on [`Evidence`] should typically use the
    /// check identifier and reason code (for example, `staleness.behind_latest`).
    Check,
    /// Evidence emitted by a user- or organization-defined rule.
    ///
    /// Use this for findings produced by extension points such as custom rule
    /// configuration. The `id` on [`Evidence`] should identify the custom rule
    /// (for example, `custom_rule.low-downloads`).
    CustomRule,
    /// Evidence produced by higher-level policy evaluation.
    ///
    /// Use this for decisions made by policy logic that is not a single check
    /// finding, such as allow/deny list matches or aggregation escalations. The
    /// `id` on [`Evidence`] should refer to the policy fragment (for example,
    /// `denylist.package` or `risk.medium_pair_escalation`).
    Policy,
    /// Evidence representing runtime failure details.
    ///
    /// Use this for operational failures surfaced as decision evidence (for
    /// example, per-package lockfile evaluation errors). The `id` on [`Evidence`]
    /// should identify the runtime failure category.
    Runtime,
}

/// Structured evidence record attached to package decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Broad category for evidence origin.
    pub kind: EvidenceKind,
    /// Stable machine-readable identifier (e.g., check id or policy code).
    pub id: String,
    /// Severity associated with this evidence.
    pub severity: Severity,
    /// Human-readable summary for this evidence item.
    pub message: String,
    /// Optional structured fields for deterministic downstream handling.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facts: BTreeMap<String, JsonValue>,
}

/// Decision result returned by package checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResponse {
    /// Whether installation is allowed under current policy.
    pub allow: bool,
    /// Aggregated risk level from all enabled checks.
    pub risk: Severity,
    /// Human-readable findings that explain the decision.
    pub reasons: Vec<String>,
    /// Machine-readable evidence from checks and policy evaluation.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Additional package metadata collected during evaluation.
    pub metadata: Metadata,
    /// Fingerprints for correlation with audit log records.
    pub fingerprints: DecisionFingerprints,
}

/// Per-package result in a lockfile audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockfilePackageResult {
    /// Package name as parsed from the lockfile or manifest.
    pub name: String,
    /// Requested version string from the lockfile when present.
    pub requested: Option<String>,
    /// Whether this package passed policy checks.
    pub allow: bool,
    /// Risk level for this specific package.
    pub risk: Severity,
    /// Findings for this package only.
    pub reasons: Vec<String>,
    /// Machine-readable evidence for this package decision.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Structured transitive ancestry representation for this package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_ancestry: Option<DependencyAncestry>,
}

/// One ancestry chain entry for a package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyAncestryPath {
    /// Ordered ancestors from root dependency to immediate parent.
    #[serde(default)]
    pub ancestors: Vec<String>,
}

/// Named dependency path container for lockfile package results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyAncestry {
    /// One or more ancestry chains for this package.
    #[serde(default)]
    pub paths: Vec<DependencyAncestryPath>,
}

/// Aggregate response returned by lockfile audits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockfileResponse {
    /// Whether all packages were allowed.
    pub allow: bool,
    /// Highest risk observed in the package set.
    pub risk: Severity,
    /// Total number of packages processed.
    pub total: usize,
    /// Number of packages denied by policy or errors.
    pub denied: usize,
    /// Per-package outcomes.
    pub packages: Vec<LockfilePackageResult>,
    /// Fingerprints for correlation with audit log records.
    pub fingerprints: DecisionFingerprints,
}
