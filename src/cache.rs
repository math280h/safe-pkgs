//! SQLite-backed cache for package check responses.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow};
use rusqlite::{Connection, OptionalExtension, params};

/// Cache storage backed by a local SQLite database.
pub struct SqliteCache {
    conn: Mutex<Connection>,
    ttl: Duration,
}

impl SqliteCache {
    /// Opens the default on-disk cache database and initializes schema if needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache directory cannot be created, the database cannot
    /// be opened, or schema initialization fails.
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

    /// Reads a cache entry by key.
    ///
    /// Expired entries are deleted on read and treated as cache misses.
    ///
    /// # Errors
    ///
    /// Returns an error if the clock read fails, the SQLite query fails,
    /// or the cache mutex is poisoned.
    pub fn get(&self, key: &str) -> anyhow::Result<Option<String>> {
        let now = unix_now()?;
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

    /// Upserts a cache entry with a fresh expiry timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error if clock math overflows, the SQLite write fails,
    /// or the cache mutex is poisoned.
    pub fn set(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let now = unix_now()?;
        let ttl_seconds =
            i64::try_from(self.ttl.as_secs()).context("cache ttl seconds exceeds i64 range")?;
        let expires_at = now
            .checked_add(ttl_seconds)
            .ok_or_else(|| anyhow!("cache expiry timestamp overflow"))?;
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
    if let Some(explicit) = env::var_os("SAFE_PKGS_CACHE_DB_PATH") {
        return PathBuf::from(explicit);
    }

    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .or_else(|| env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));

    home.join(".cache").join("safe-pkgs").join("cache.db")
}

fn unix_now() -> anyhow::Result<i64> {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?;
    i64::try_from(since_epoch.as_secs()).context("unix timestamp exceeds i64 range")
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

    #[test]
    fn expired_entries_are_treated_as_cache_miss() {
        let mut cache = SqliteCache::in_memory(1).expect("in-memory cache");
        cache.ttl = Duration::from_secs(1);
        cache
            .set("expiring-key", "{\"ok\":true}")
            .expect("set cache value");
        std::thread::sleep(Duration::from_millis(1_100));
        let value = cache.get("expiring-key").expect("get cache value");
        assert!(value.is_none());
    }

    #[test]
    fn set_returns_error_when_ttl_math_overflows() {
        let mut cache = SqliteCache::in_memory(1).expect("in-memory cache");
        cache.ttl = Duration::from_secs(u64::MAX);
        let err = cache
            .set("overflow", "{\"ok\":true}")
            .expect_err("expected ttl overflow error");
        assert!(
            err.to_string()
                .contains("cache ttl seconds exceeds i64 range")
        );
    }
}
