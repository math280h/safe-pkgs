//! Append-only audit log for package and lockfile decisions.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use serde::Serialize;

use crate::config::{AuditBackend, AuditConfig};
use crate::types::{Evidence, Metadata, Severity};

/// Audit destination for decision records.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Persists a single audit record.
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be persisted.
    async fn log(&self, record: &AuditRecord) -> anyhow::Result<()>;
}

/// Default request timeout for the HTTP audit backend, in seconds.
const HTTP_AUDIT_TIMEOUT_SECS: u64 = 20;

/// File-backed sink that writes one JSON record per line.
pub struct FileAuditSink {
    file: Arc<Mutex<File>>,
}

/// HTTP-backed sink that POSTs each record as JSON to a configured endpoint.
pub struct HttpAuditSink {
    client: reqwest::Client,
    endpoint: String,
    token: Option<String>,
}

/// Serialized audit event written to the audit log.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    timestamp: String,
    policy_snapshot_version: u8,
    config_fingerprint: String,
    policy_fingerprint: String,
    enabled_checks: Vec<String>,
    evaluation_time: String,
    context: String,
    package: String,
    requested: Option<String>,
    registry: String,
    allow: bool,
    risk: Severity,
    reasons: Vec<String>,
    #[serde(default)]
    evidence: Vec<Evidence>,
    metadata: Option<Metadata>,
    cached: bool,
}

/// Input payload for constructing an [`AuditRecord`] package decision.
pub struct PackageDecision<'a> {
    pub policy_snapshot_version: u8,
    pub config_fingerprint: &'a str,
    pub policy_fingerprint: &'a str,
    pub enabled_checks: Vec<String>,
    pub evaluation_time: String,
    pub context: &'a str,
    pub package: &'a str,
    pub requested: Option<&'a str>,
    pub registry: &'a str,
    pub allow: bool,
    pub risk: Severity,
    pub reasons: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub metadata: Option<Metadata>,
    pub cached: bool,
}

impl FileAuditSink {
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
            file: Arc::new(Mutex::new(file)),
        })
    }
}

#[async_trait]
impl AuditSink for FileAuditSink {
    async fn log(&self, record: &AuditRecord) -> anyhow::Result<()> {
        // Serialize before moving the write onto a blocking thread pool.
        let mut bytes = serde_json::to_vec(record)?;
        bytes.push(b'\n');
        let file = Arc::clone(&self.file);
        // Avoid blocking Tokio worker threads on file I/O and the mutex.
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            let mut file = file
                .lock()
                .map_err(|_| anyhow::anyhow!("audit log mutex poisoned"))?;
            file.write_all(&bytes)?;
            file.flush()?;
            Ok(())
        })
        .await??;
        Ok(())
    }
}

impl HttpAuditSink {
    /// Creates an HTTP sink that POSTs records to `endpoint` with optional bearer auth.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be constructed.
    pub fn new(endpoint: String, token: Option<String>) -> anyhow::Result<Self> {
        // Audit failures are fatal, so bound requests with a timeout to avoid hangs.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(HTTP_AUDIT_TIMEOUT_SECS))
            .build()?;
        Ok(Self {
            client,
            endpoint,
            token,
        })
    }
}

#[async_trait]
impl AuditSink for HttpAuditSink {
    async fn log(&self, record: &AuditRecord) -> anyhow::Result<()> {
        let mut request = self.client.post(&self.endpoint).json(record);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "audit endpoint returned non-success status: {status}"
            ));
        }
        Ok(())
    }
}

/// Builds the configured audit sink (file or HTTP).
///
/// # Errors
///
/// Returns an error if the file sink cannot be opened or the HTTP backend is misconfigured.
pub fn build_audit_sink(config: &AuditConfig) -> anyhow::Result<Arc<dyn AuditSink>> {
    match config.backend {
        AuditBackend::File => Ok(Arc::new(FileAuditSink::new()?)),
        AuditBackend::Http => {
            let endpoint = config
                .endpoint
                .clone()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("audit.endpoint is required for the http backend")
                })?;
            // When token_env names a variable, require it to be set and non-empty
            // rather than silently falling back to unauthenticated requests.
            let token = match config.token_env.as_deref() {
                Some(name) => {
                    let value = env::var(name).ok().filter(|value| !value.is_empty());
                    Some(value.ok_or_else(|| {
                        anyhow::anyhow!(
                            "audit.token_env points to environment variable `{name}`, but it is missing or empty"
                        )
                    })?)
                }
                None => None,
            };
            Ok(Arc::new(HttpAuditSink::new(endpoint, token)?))
        }
    }
}

impl AuditRecord {
    /// Builds an audit record for a package decision event.
    pub fn package_decision(input: PackageDecision<'_>) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            policy_snapshot_version: input.policy_snapshot_version,
            config_fingerprint: input.config_fingerprint.to_string(),
            policy_fingerprint: input.policy_fingerprint.to_string(),
            enabled_checks: input.enabled_checks,
            evaluation_time: input.evaluation_time,
            context: input.context.to_string(),
            package: input.package.to_string(),
            requested: input.requested.map(ToOwned::to_owned),
            registry: input.registry.to_string(),
            allow: input.allow,
            risk: input.risk,
            reasons: input.reasons,
            evidence: input.evidence,
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
