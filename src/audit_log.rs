use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::Utc;
use serde::Serialize;

use crate::types::{Metadata, Severity};

pub struct AuditLogger {
    file: Mutex<File>,
}

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

impl AuditLogger {
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
    #[allow(clippy::too_many_arguments)]
    pub fn package_decision(
        context: &str,
        package: &str,
        requested: Option<&str>,
        registry: &str,
        allow: bool,
        risk: Severity,
        reasons: Vec<String>,
        metadata: Option<Metadata>,
        cached: bool,
    ) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            context: context.to_string(),
            package: package.to_string(),
            requested: requested.map(ToOwned::to_owned),
            registry: registry.to_string(),
            allow,
            risk,
            reasons,
            metadata,
            cached,
        }
    }
}

fn audit_log_path() -> PathBuf {
    if let Some(explicit) = env::var_os("SAFE_PKGS_AUDIT_LOG_PATH") {
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
