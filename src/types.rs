//! Shared response types used by CLI and MCP tool handlers.

use serde::{Deserialize, Serialize};

/// Core metadata and risk severity types re-exported for consumers of this crate.
///
/// These types are defined and primarily documented in the `safe_pkgs_core` crate;
/// they are re-exported here so CLI commands and MCP tools can depend only on this
/// crate while still using the same canonical representations.
pub use safe_pkgs_core::{Metadata, Severity};

/// Decision result returned by package checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResponse {
    /// Whether installation is allowed under current policy.
    pub allow: bool,
    /// Aggregated risk level from all enabled checks.
    pub risk: Severity,
    /// Human-readable findings that explain the decision.
    pub reasons: Vec<String>,
    /// Additional package metadata collected during evaluation.
    pub metadata: Metadata,
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
}
