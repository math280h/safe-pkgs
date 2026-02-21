//! Append-only audit log for package and lockfile decisions.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::Utc;
use serde::Serialize;

use crate::types::{Metadata, Severity};

/// File-backed logger that writes one JSON record per line.
pub struct AuditLogger {
    file: Mutex<File>,
}

/// Serialized audit event written to the local audit log.
#[derive(Debug, Serialize)]
pub struct AuditRecord {
    timestamp: String,
    context: String,
    package: String,
    requested: Option<String>,
    registry: String,
    allow: bool,
    risk: Severity,
    reasons: Vec<String>,
    metadata: Option<Metadata>,
    cached: bool,
}

/// Input payload for constructing an [`AuditRecord`] package decision.
pub struct PackageDecision<'a> {
    pub context: &'a str,
    pub package: &'a str,
    pub requested: Option<&'a str>,
    pub registry: &'a str,
    pub allow: bool,
    pub risk: Severity,
    pub reasons: Vec<String>,
    pub metadata: Option<Metadata>,
    pub cached: bool,
}

impl AuditLogger {
    /// Creates or opens the audit log file at the default path.
    ///
    /// # Errors
    ///
    /// Returns an error if directories cannot be created or the file cannot be opened.
    pub fn new() -> anyhow::Result<Self> {
        let log_path = audit_log_path();
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Appends a single JSON record followed by newline.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails, writing fails, or the mutex is poisoned.
    pub fn log(&self, record: AuditRecord) -> anyhow::Result<()> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| anyhow::anyhow!("audit log mutex poisoned"))?;
        let json = serde_json::to_string(&record)?;
        file.write_all(json.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }
}

impl AuditRecord {
    /// Builds an audit record for a package decision event.
    pub fn package_decision(input: PackageDecision<'_>) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            context: input.context.to_string(),
            package: input.package.to_string(),
            requested: input.requested.map(ToOwned::to_owned),
            registry: input.registry.to_string(),
            allow: input.allow,
            risk: input.risk,
            reasons: input.reasons,
            metadata: input.metadata,
            cached: input.cached,
        }
    }
}

fn audit_log_path() -> PathBuf {
    if let Some(explicit) = env::var_os("SAFE_PKGS_AUDIT_LOG_FILE_PATH") {
        return PathBuf::from(explicit);
    }

    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .or_else(|| env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));

    home.join(".local")
        .join("share")
        .join("safe-pkgs")
        .join("audit.log")
}

#[cfg(test)]
#[path = "tests/audit_log.rs"]
mod tests;
