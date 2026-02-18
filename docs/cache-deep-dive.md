---
hide:
  - title
  - toc
---

<div class="docs-hero docs-hero--cache">
  <h1>Check cache.</h1>
  <p>
    safe-pkgs caches package decisions locally so repeated requests avoid unnecessary registry lookups
    while still honoring configurable TTL expiration.
  </p>
  <div class="chip-grid">
    <span>SQLite-backed</span>
    <span>TTL-based expiry</span>
    <span>Deterministic keying</span>
  </div>
</div>

## What is cached

<div class="card-grid two">
  <article class="sp-card">
    <h4>check_package responses</h4>
    <p>Serialized JSON tool decisions are stored directly and reused until TTL expiry.</p>
  </article>
  <article class="sp-card">
    <h4>check_lockfile package evaluations</h4>
    <p>Lockfile audits call the same package evaluation path, so they automatically benefit from cache hits.</p>
  </article>
</div>

## Storage path

- `SAFE_PKGS_CACHE_PATH` if set (full SQLite file path).
- Otherwise: `~/.cache/safe-pkgs/cache.db`.

Parent directories are created automatically when missing.

## Cache key format

```text
check_package:{registry}:{package}@{version}
```

Examples:

- `check_package:npm:lodash@4.17.21`
- `check_package:cargo:serde@1.0.217`
- Omitted version is normalized to `latest`:
  - `check_package:npm:lodash@latest`

## Lifecycle behavior

1. Build key from registry, package name, and requested version.
2. Attempt `get` from SQLite.
3. If entry is expired, delete it and treat as miss.
4. On miss, run live checks and serialize result.
5. Upsert into cache with refreshed `expires_at`.

## TTL and schema

- Config key: `[cache].ttl_minutes`
- Default: `30`
- Expiry validation happens on read (`get`).

```sql
CREATE TABLE IF NOT EXISTS cache_entries (
  cache_key TEXT PRIMARY KEY,
  cache_value TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_entries_expires_at ON cache_entries (expires_at);
```

<div class="sp-card docs-note">
  <h4>Operations note</h4>
  <p>Deleting the cache DB is safe; it will be recreated on next run.</p>
</div>
