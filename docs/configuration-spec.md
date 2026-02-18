---
hide:
  - title
  - toc
---

<div class="docs-hero docs-hero--config">
  <h1>Define policy once, enforce it everywhere.</h1>
  <p>
    safe-pkgs loads typed config from global and project scopes, merges values deterministically,
    and sanitizes invalid thresholds back to secure defaults.
  </p>
  <div class="chip-grid">
    <span>Global + project overlay</span>
    <span>Typed config</span>
    <span>Safe defaults</span>
  </div>
</div>

## Load order

<div class="card-grid two">
  <article class="sp-card">
    <h4>1. Global config</h4>
    <p><code>SAFE_PKGS_CONFIG_PATH</code> if set, otherwise <code>~/.config/safe-pkgs/config.toml</code>.</p>
  </article>
  <article class="sp-card">
    <h4>2. Project override</h4>
    <p><code>SAFE_PKGS_PROJECT_CONFIG_PATH</code> if set, otherwise <code>./.safe-pkgs.toml</code>.</p>
  </article>
</div>

Project values overlay global values.

## Full schema

| Key | Type | Default | Behavior |
| --- | --- | --- | --- |
| `min_version_age_days` | integer | `7` | Versions newer than this raise risk. `<= 0` is reset to default. |
| `min_weekly_downloads` | integer | `50` | Packages below this threshold raise risk. |
| `max_risk` | enum | `medium` | `low \| medium \| high \| critical`. Above this threshold means deny. |
| `allowlist.packages` | string[] | `[]` | Package entries that should be explicitly allowed. |
| `denylist.packages` | string[] | `[]` | Package entries that should be explicitly denied. |
| `denylist.publishers` | string[] | `[]` | Publisher identities to deny. |
| `staleness.warn_major_versions_behind` | integer | `2` | Major-version gap warning threshold. `0` resets to default. |
| `staleness.warn_minor_versions_behind` | integer | `3` | Minor-version gap warning threshold. `0` resets to default. |
| `staleness.warn_age_days` | integer | `365` | Warn if release age exceeds this value. `<= 0` resets to default. |
| `staleness.ignore_for` | string[] | `[]` | Package/version patterns excluded from staleness warnings. |
| `cache.ttl_minutes` | integer | `30` | Cache TTL in minutes. `0` resets to default. |

## Merge rules

<div class="card-grid three">
  <article class="sp-card">
    <h4>Scalar fields</h4>
    <p>Later sources overwrite earlier values (for example <code>max_risk</code> and numeric thresholds).</p>
  </article>
  <article class="sp-card">
    <h4>List fields</h4>
    <p>Lists are appended with de-duplication, so global and project entries combine cleanly.</p>
  </article>
  <article class="sp-card">
    <h4>Invalid values</h4>
    <p>Non-positive values for positive thresholds are reset to defaults to avoid unsafe settings.</p>
  </article>
</div>

## Example

```toml
min_version_age_days = 7
min_weekly_downloads = 50
max_risk = "medium"

[cache]
ttl_minutes = 30

[staleness]
warn_major_versions_behind = 2
warn_minor_versions_behind = 3
warn_age_days = 365
ignore_for = ["legacy-pkg@1.x"]

[allowlist]
packages = ["my-internal-pkg"]

[denylist]
packages = ["event-stream@3.3.6"]
publishers = ["suspicious-user-123"]
```

<div class="sp-card docs-note">
  <h4>Apply changes</h4>
  <p>Config is loaded at process start. Restart <code>safe-pkgs serve --mcp</code> after edits.</p>
</div>
