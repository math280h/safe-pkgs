# AGENTS.md — safe-pkgs Agent Engineering Protocol

Scope: entire repository.

---

## Core Principles

Apply these to every task.

### 1. Think Before Coding

**Don't assume. Surface trade-offs. Ask when uncertain.**

- State assumptions explicitly. If a request is ambiguous, name the ambiguity and ask.
- If multiple valid approaches exist, present them — don't pick silently.
- If a simpler approach solves the problem, say so.

### 2. Minimum Viable Change

**Write the least code that correctly solves the problem.**

- No features beyond what was asked.
- No abstractions built for hypothetical future use.
- No error handling for scenarios that can't happen.
- No clean-up of adjacent code that isn't broken.

**The test:** Would a reviewer ask "why is this here?" If yes, remove it.

### 3. Surgical Edits Only

**Touch only what you must. Match existing style.**

- Don't reformat or refactor code you didn't change.
- If you notice unrelated dead code, mention it — don't delete it.
- Remove imports/variables that **your** changes made unused; leave pre-existing ones alone.

### 4. Documentation Stays in Sync

**Code and docs are one unit. Update both or update neither.**

When changing CLI flags, tool signatures, config fields, or behavior:
- Update `README.md`, `docs/`, and this file in the same change.
- Search for all references before renaming or removing anything:

  ```bash
  grep -r "old-flag-name" src/ tests/ docs/ README.md AGENTS.md
  ```

- Stale flag names in docs or test harnesses cause hard-to-diagnose failures at runtime.

### 5. Never Silently Allow

**Security decisions must be explicit.**

- If a check fails, surface the error — don't fall back to allow.
- If an audit log write fails, propagate the error — don't swallow it.
- If a registry lookup fails, fail the decision — don't guess.

---

## Project Snapshot

`safe-pkgs` is a Rust MCP server and CLI that checks package safety before install.

**User-facing entry points:**

| Surface | Command / Tool |
|---------|---------------|
| MCP tool | `check_package(name, version?, registry?)` |
| MCP tool | `check_lockfile(path?, registry?)` |
| CLI | `safe-pkgs serve` |
| CLI | `safe-pkgs audit <path>` |

**Decision output shape:**

```json
{
  "allow": true,
  "risk": "low",
  "reasons": ["lodash@3.10.1 is 1 major version behind latest (4.17.21)"],
  "metadata": {
    "latest": "4.17.21",
    "requested": "3.10.1",
    "published": "2015-08-31T00:00:00Z",
    "weekly_downloads": 45000000
  }
}
```

`risk` values: `low | medium | high | critical`
`allow` is `false` when final risk exceeds configured `max_risk`.

---

## Runtime Architecture

```text
CLI (serve or audit <path>)
  -> MCP Server (rmcp over stdio)
    -> Config loader (global + project overlay)
    -> SQLite cache (~/.cache/safe-pkgs/cache.db, default TTL 30 minutes)
    -> Check pipeline (async, concurrent)
    -> Risk aggregator
    -> Audit logger (~/.local/share/safe-pkgs/audit.log)
```

Key behaviors:
- Checks run concurrently and are aggregated into one decision.
- Cache is keyed by package + version + registry.
- Failed checks are surfaced as errors; no silent allow fallback.

---

## MCP + rmcp Notes

- Use `rmcp` 0.15 tool macros:
  - `#[tool_router]` on `impl SafePkgsServer`
  - `#[tool(...)]` on async tool methods
  - `#[tool_handler]` on `impl ServerHandler`
- Keep `schemars` at v1.x — rmcp depends on it internally; do not downgrade.
- **Never write to stdout from MCP server logic** — stdout is the transport.
- Tool params use `Parameters<T>` from rmcp wrappers.

---

## Code Conventions

| Concern | Approach |
|---------|----------|
| Error handling | `anyhow` for app flow; `thiserror` where typed errors are needed |
| Logging | `tracing`, stderr only — never stdout |
| Naming | Standard Rust conventions |
| Config | Typed structs with defaults; backward-compatible additions only |
| Safety | No `unwrap` in production code |

---

## Change Playbooks

### Adding a check

1. Add `src/checks/<name>.rs`.
2. Register it in `src/checks/mod.rs` orchestrator.
3. Add/extend module tests (`*_tests.rs`).
4. Return clear severity + reason strings.
5. Update `docs/check-support-map.md` if the check is registry-specific.

### Adding an MCP tool

1. Add tool method in `src/mcp/server.rs` with `#[tool(...)]`.
2. Define parameter type with `Deserialize + JsonSchema`.
3. Add integration coverage in `tests/`.
4. Update the Project Snapshot table in this file and `README.md`.

### Modifying config

1. Update `src/config.rs` structures and overlay handling.
2. Ensure defaults preserve backward compatibility.
3. Update `README.md`, `docs/configuration-spec.md`, the Configuration Reference section below, and any inline examples.

### Removing or renaming a CLI flag or subcommand

1. Search all references before touching anything:
   ```bash
   grep -r "old-name" src/ tests/ docs/ README.md AGENTS.md
   ```
2. Update every reference in the same PR.
3. Update this file, `README.md`, and `docs/getting-started.md`.

---

## Validation

Run before finishing any change:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

A pre-commit hook that runs fmt and clippy is available — set it up once with:

```bash
git config core.hooksPath .githooks
```

---

## Do's and Don'ts

### Do

- ✅ Fail fast on lookup/check failures — propagate errors explicitly
- ✅ Keep defaults secure and usable with zero config
- ✅ Write to stderr (tracing) for server-side logs
- ✅ Update docs and this file whenever CLI flags, tools, or config fields change
- ✅ Search for all references before renaming or removing anything
- ✅ Keep changes small and focused on the stated task

### Don't

- ❌ Silently allow packages when checks fail
- ❌ Write to stdout from MCP server logic (it is the transport)
- ❌ Add speculative flags or config options with no immediate use case
- ❌ Mix unrelated refactors into feature changes
- ❌ Leave docs or test harnesses referencing removed flags or stale command names
- ❌ Use `unwrap` in production code paths

---

## Agent Integration Protocol

When integrating `safe-pkgs` as a tool:

1. Call `check_package` before installing any package.
2. If `allow: false`, do not install — report `reasons` to the user.
3. Use `metadata.latest` to suggest a safer or current version.
4. For batch audits use `check_lockfile` (MCP) or `safe-pkgs audit <path>` (CLI).

---

## Configuration Reference

**Global config:** `~/.config/safe-pkgs/config.toml`
**Project override:** `.safe-pkgs.toml` (merged on top of global)

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
