# AGENTS.md - safe-pkgs Agent Engineering Protocol

Scope: entire repository.

## 1) Project Snapshot

`safe-pkgs` is a Rust MCP server and CLI that checks package safety before install.

Current user-facing entry points:
- MCP tool: `check_package(name, version?, registry?)`
- MCP tool: `check_lockfile(path?, registry?)` (npm manifests/lockfiles)
- CLI: `safe-pkgs serve --mcp`
- CLI: `safe-pkgs audit <path>`

Decision output shape:
- `allow` (boolean)
- `risk` (`low | medium | high | critical`)
- `reasons` (array of findings)
- `metadata` (latest version, publish data, downloads, etc.)

## 2) Runtime Architecture

```text
CLI (serve --mcp or audit <path>)
  -> MCP Server (rmcp over stdio)
    -> Config loader (global + project overlay)
    -> SQLite cache (~/.cache/safe-pkgs/cache.db, default TTL 30 minutes)
    -> Check pipeline (async checks)
    -> Risk aggregator
    -> Audit logger (~/.local/share/safe-pkgs/audit.log)
```

High-level behavior:
- Checks run concurrently and are aggregated into one decision.
- `allow` is `false` when final risk exceeds configured `max_risk`.
- Cache is keyed by package + version + registry segment.
- Failed checks are surfaced as errors; no silent allow fallback.

## 3) Repository Map

```text
src/
  main.rs           - CLI entry point (`serve`, `audit`)
  mcp/
    mod.rs          - MCP exports
    server.rs       - tool schemas, handlers, lockfile parsing, dispatch
  checks/
    mod.rs          - orchestrator + check report aggregation
    existence.rs
    version_age.rs
    staleness.rs
    typosquat.rs
    popularity.rs
    install_script.rs
    advisory.rs
    *_tests.rs      - unit tests per check module
  registries/
    mod.rs
    client.rs       - registry trait + shared metadata types
    npm.rs          - npm implementation
    cargo.rs        - crates.io implementation
    osv.rs          - OSV advisory integration
  config.rs         - typed config + global/project merge
  cache.rs          - SQLite cache with TTL
  audit_log.rs      - append-only decision logging
  types.rs          - shared API/tool result types

tests/
  mcp_stdio.rs      - stdio MCP integration round-trip
```

## 4) Engineering Principles

- Keep security decisions auditable and explicit.
- Prefer small, focused changes over broad refactors.
- Fail fast on lookup/check failures; do not silently allow.
- Keep defaults secure and usable with zero config.
- Avoid heavy dependencies for minor convenience.

## 5) MCP + rmcp Notes

- Use `rmcp` 0.15 tool macros:
  - `#[tool_router]` on `impl SafePkgsServer`
  - `#[tool(...)]` on async tool methods
  - `#[tool_handler]` on `impl ServerHandler`
- Keep `schemars` at v1.x compatibility.
- Never write logs to stdout in MCP mode; stdout is transport.
- Tool params use `Parameters<T>` from rmcp wrappers.

## 6) Code Conventions

- Error handling: `anyhow` for app flow, `thiserror` where typed errors are needed.
- Logging: `tracing`, stderr only for server logs.
- Naming: standard Rust conventions.
- Config: typed structs with defaults for backward-compatible additions.
- No `unwrap` in production code.

## 7) Change Playbooks

Adding a check:
1. Add `src/checks/<name>.rs`.
2. Register it in `src/checks/mod.rs` orchestrator.
3. Add/extend module tests (`*_tests.rs`).
4. Return clear severity + reason strings.

Adding an MCP tool:
1. Add tool method in `src/mcp/server.rs` with `#[tool(...)]`.
2. Define parameter type with `Deserialize + JsonSchema`.
3. Add integration coverage in `tests/`.

Modifying config:
1. Update `src/config.rs` structures and overlay handling.
2. Ensure defaults preserve compatibility.
3. Update `README.md` and this file config references.

## 8) Validation

Run before finishing work:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## 9) Anti-Patterns

- Do not silently allow packages when checks fail.
- Do not write to stdout from MCP server logic.
- Do not add speculative flags with no immediate use case.
- Do not mix unrelated refactors into feature changes.

## 10) Tool Response Example

```json
{
  "allow": true,
  "risk": "low",
  "reasons": [
    "lodash@3.10.1 is 1 major version behind latest (4.17.21)"
  ],
  "metadata": {
    "latest": "4.17.21",
    "requested": "3.10.1",
    "published": "2015-08-31T00:00:00Z",
    "weekly_downloads": 45000000
  }
}
```

## 11) Agent Integration Protocol

1. Call `check_package` before install.
2. If `allow: false`, do not install; report reasons.
3. Use `metadata.latest` to suggest safer/current versions.
4. Use `check_lockfile` or `safe-pkgs audit <path>` for batch audits.

## 12) Configuration Reference

Global file:
- `~/.config/safe-pkgs/config.toml`

Project override:
- `.safe-pkgs.toml` (merged on top of global)

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
