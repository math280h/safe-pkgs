use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow};
use rusqlite::{Connection, OptionalExtension, params};

pub struct SqliteCache {
    conn: Mutex<Connection>,
    ttl: Duration,
}

impl SqliteCache {
    pub fn new(ttl_minutes: u64) -> anyhow::Result<Self> {
        let db_path = cache_db_path();
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create cache directory {}", parent.display())
            })?;
        }
        let conn = Connection::open(&db_path)
            .with_context(|| format!("failed to open sqlite cache at {}", db_path.display()))?;
        Self::from_connection(conn, ttl_minutes)
    }

    #[cfg(test)]
    pub fn in_memory(ttl_minutes: u64) -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory sqlite cache")?;
        Self::from_connection(conn, ttl_minutes)
    }

    fn from_connection(conn: Connection, ttl_minutes: u64) -> anyhow::Result<Self> {
        conn.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS cache_entries (
  cache_key TEXT PRIMARY KEY,
  cache_value TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_entries_expires_at ON cache_entries (expires_at);
"#,
        )
        .context("failed to initialize sqlite cache schema")?;

        Ok(Self {
            conn: Mutex::new(conn),
            ttl: Duration::from_secs(ttl_minutes.max(1) * 60),
        })
    }

    pub fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
        let now = unix_now();
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow!("sqlite cache mutex poisoned"))?;

        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT cache_value, expires_at FROM cache_entries WHERE cache_key = ?1",
                params![key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context("failed to query sqlite cache entry")?;

        let Some((value, expires_at)) = row else {
            return Ok(None);
        };

        if expires_at <= now {
            conn.execute(
                "DELETE FROM cache_entries WHERE cache_key = ?1",
                params![key],
            )
            .context("failed to delete expired sqlite cache entry")?;
            return Ok(None);
        }

        Ok(Some(value))
    }

    pub fn set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let now = unix_now();
        let expires_at = now + self.ttl.as_secs() as i64;
        let conn = self
            .conn
            .lock()
            .map_err(|_| anyhow!("sqlite cache mutex poisoned"))?;

        conn.execute(
            r#"
INSERT INTO cache_entries (cache_key, cache_value, expires_at)
VALUES (?1, ?2, ?3)
ON CONFLICT(cache_key) DO UPDATE SET
  cache_value = excluded.cache_value,
  expires_at = excluded.expires_at
"#,
            params![key, value, expires_at],
        )
        .context("failed to upsert sqlite cache entry")?;

        Ok(())
    }
}

fn cache_db_path() -> PathBuf {
    if let Some(explicit) = env::var_os("SAFE_PKGS_CACHE_PATH") {
        return PathBuf::from(explicit);
    }

    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .or_else(|| env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));

    home.join(".cache").join("safe-pkgs").join("cache.db")
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_then_get_round_trip() {
        let cache = SqliteCache::in_memory(30).expect("in-memory cache");
        cache.set("key", "{\"ok\":true}").expect("set cache value");
        let value = cache.get("key").expect("get cache value");
        assert_eq!(value.as_deref(), Some("{\"ok\":true}"));
    }
}
