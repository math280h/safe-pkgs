---
hide:
  - title
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
    <p><code>SAFE_PKGS_CONFIG_GLOBAL_PATH</code> if set, otherwise <code>~/.config/safe-pkgs/config.toml</code>.</p>
  </article>
  <article class="sp-card">
    <h4>2. Project override</h4>
    <p><code>SAFE_PKGS_CONFIG_PROJECT_PATH</code> if set, otherwise <code>./.safe-pkgs.toml</code>.</p>
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
| `checks.disable` | string[] | `[]` | Globally disable selected checks (`version_age`, `staleness`, `popularity`, `install_script`, `typosquat`, `advisory`). |
| `checks.registry.<key>.disable` | string[] | `[]` | Disable checks only for a specific registry key (for example `npm` or `cargo`). |
| `cache.ttl_minutes` | integer | `30` | Cache TTL in minutes. `0` resets to default. |
| `lockfile.eval_concurrency` | integer | `5` | Number of packages evaluated in parallel during lockfile audits. Lower values reduce API burst load. `0` resets to default. |
| `lockfile.inter_batch_delay_ms` | integer | `100` | Milliseconds to wait before spawning each replacement evaluation task after one completes. The initial batch is spawned immediately. Helps avoid rate limiting by spacing requests over time. Set to `0` for no delay. |
| `custom_rules` | array(table) | `[]` | User-defined rule set evaluated alongside built-in checks. Invalid rules fail config load. |

## Merge rules

<div class="card-grid three">
  <article class="sp-card">
    <h4>Scalar fields</h4>
    <p>Later sources overwrite earlier values (for example <code>max_risk</code> and numeric thresholds).</p>
  </article>
  <article class="sp-card">
    <h4>List fields</h4>
    <p>Lists are appended with de-duplication, so global and project entries combine cleanly (including <code>checks.disable</code> and per-registry disable lists).</p>
  </article>
  <article class="sp-card">
    <h4>Invalid values</h4>
    <p>Non-positive values for positive thresholds are reset to defaults to avoid unsafe settings.</p>
  </article>
</div>

## Rate limiting defaults

The `lockfile` configuration defaults are intentionally conservative to minimize the risk of triggering registry API rate limits during large dependency audits.

<div class="sp-card docs-note">
  <h4>Conservative by design</h4>
  <p>Default settings (<code>eval_concurrency = 5</code>, <code>inter_batch_delay_ms = 100</code>) prioritize reliability over speed. These values work well for most users and registries without hitting rate limits.</p>
</div>

**Default behavior:**
- **5 concurrent evaluations** reduces peak API load by 50% compared to higher concurrency
- **100ms inter-batch delay** distributes requests over time instead of bursting
- For a 100-package lockfile: ~261 total API calls spread across ~20 seconds (vs. ~10 seconds with no rate limiting)

**When to adjust:**

| Scenario | Recommended Settings | Rationale |
| --- | --- | --- |
| Default (most users) | `eval_concurrency = 5`<br>`inter_batch_delay_ms = 100` | Balanced speed and rate limit safety |
| Strict rate limits | `eval_concurrency = 3`<br>`inter_batch_delay_ms = 200` | Further reduced burst load for restrictive APIs |
| Generous rate limits | `eval_concurrency = 10`<br>`inter_batch_delay_ms = 0` | Faster audits when rate limits are not a concern |
| CI/CD pipelines | `eval_concurrency = 3-5`<br>`inter_batch_delay_ms = 100-200` | Conservative to avoid build failures |

<div class="sp-card docs-warning">
  <h4>Avoid aggressive settings in shared environments</h4>
  <p>High concurrency with no delay can trigger 429 (Too Many Requests) errors, especially in CI/CD where multiple builds may run concurrently. Start with defaults and increase only if you confirm rate limits are not an issue.</p>
</div>

## Example

```toml
min_version_age_days = 7
min_weekly_downloads = 50
max_risk = "medium"

[cache]
ttl_minutes = 30

[lockfile]
eval_concurrency = 5        # Number of packages evaluated in parallel
inter_batch_delay_ms = 100  # Delay between spawning evaluation tasks (helps with rate limiting)

[[custom_rules]]
id = "deny-very-new-low-downloads"
severity = "high"
reason = "package is too new and has low adoption"
registries = ["npm"]
match = "all"
conditions = [
  { field = "version_age_days", op = "lt", value = 7 },
  { field = "weekly_downloads", op = "lt", value = 100 }
]

[staleness]
warn_major_versions_behind = 2
warn_minor_versions_behind = 3
warn_age_days = 365
ignore_for = ["legacy-pkg@1.x"]

[checks]
disable = ["typosquat"]

[checks.registry.npm]
disable = ["install_script"]

[allowlist]
packages = ["my-internal-pkg"]

[denylist]
packages = ["event-stream@3.3.6"]
publishers = ["suspicious-user-123"]
```

<div class="sp-card docs-note">
  <h4>Apply changes</h4>
  <p>Config is loaded at process start. Restart <code>safe-pkgs serve</code> after edits.</p>
</div>

## Custom rule fields and operators

`custom_rules[].conditions[].field` supports:
- `registry`
- `package_name`
- `requested_version`
- `latest_version`
- `resolved_version`
- `version_age_days`
- `version_deprecated`
- `has_install_scripts`
- `install_script_count`
- `publisher_count`
- `publishers`
- `weekly_downloads`
- `advisory_count`
- `advisory_ids`

`custom_rules[].conditions[].op` supports:
- `eq`, `ne`
- `gt`, `gte`, `lt`, `lte`
- `contains`
- `starts_with`, `ends_with`
- `in`
- `exists`
