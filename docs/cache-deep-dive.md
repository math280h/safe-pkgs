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

- `SAFE_PKGS_CACHE_DB_PATH` if set (full SQLite file path).
- Otherwise: `~/.cache/safe-pkgs/cache.db`.

Parent directories are created automatically when missing.

## Cache key format

```text
check_package:{policy_fingerprint}:{registry}:{package}@{version}
```

Examples:

- `check_package:fca103...f7a6f:npm:lodash@4.17.21`
- `check_package:2de8d2...44d9a:cargo:serde@1.0.217`
- `check_package:90f5aa...ab302:pypi:requests@2.31.0`
- Omitted version is normalized to `latest`:
  - `check_package:fca103...f7a6f:npm:lodash@latest`

`policy_fingerprint` in the key means policy changes naturally cold-miss older
entries and repopulate cache under the new policy scope.

## Fingerprint calculation

Both fingerprints are lowercase SHA-256 hex strings (64 chars):

- `config_fingerprint = sha256(canonical_policy_config_json)`
- `policy_fingerprint = sha256({ policy_snapshot_version, registry, config_fingerprint, enabled_checks })`

Canonicalization rules:

- Normalize check IDs.
- Lowercase registry keys.
- Sort and deduplicate list-like fields.
- Use stable map ordering.

Operational-only settings like `cache.ttl_minutes` are intentionally excluded
from `config_fingerprint` because they do not change policy semantics.

## Lifecycle behavior

1. Resolve enabled checks for the registry.
2. Compute canonical config and policy fingerprints.
3. Build key from policy fingerprint, registry, package name, and requested version.
4. Attempt `get` from SQLite.
5. If entry is expired, delete it and treat as miss.
6. On miss, run live checks and serialize result.
7. Upsert into cache with refreshed `expires_at`.

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
