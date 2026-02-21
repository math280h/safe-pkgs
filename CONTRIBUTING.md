# Contributing to safe-pkgs

This project is a Rust CLI + MCP server for package safety checks.

## Development Setup

1. Install stable Rust toolchain.
2. Clone the repo.
3. Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Core Rules

- Do not write to stdout from MCP server logic (`src/mcp/server.rs`) except tool responses.
- Prefer explicit failure over silent fallback when checks/registry calls fail.
- Keep changes focused; avoid unrelated refactors in feature PRs.

## Add a New Registry

### 1) Create a new crate

Use the same shape as existing registry crates:

```text
crates/registry/<name>/
  Cargo.toml
  src/
    lib.rs
    registry.rs
    lockfile.rs
```

- `registry.rs`: implement `RegistryClient`.
- `lockfile.rs`: implement `LockfileParser` if lockfile auditing is supported; otherwise return no parser.
- `lib.rs`: export client/parser types and implement `registry_definition() -> RegistryDefinition`.

### 2) Define crate-owned registry metadata

In your crate `src/lib.rs`, implement `registry_definition()` using `safe_pkgs_core::RegistryDefinition`:

- `key` (string used by MCP/CLI)
- `create_client`
- optional `create_lockfile_parser`

### 3) Add crate tests

- Add crate-level tests (`registry.rs` and `lockfile.rs` as needed).

### 4) Verify lockfile parser behavior

- If lockfile/manifests are supported, validate parser behavior.
- If not, ensure parser is absent (`None`) in `registry_definition()`.

### 5) Wire the crate into the workspace

- Add member in root `Cargo.toml` `[workspace].members`.
- Add dependency in root `Cargo.toml` `[dependencies]`.

### 6) Add crate to the app registry list.

Update `app_registry_definitions()` in `src/main.rs` to include your crate's `registry_definition()`.

### 7) Update central check-support policy only if needed

If your registry cannot support specific checks, add exclusions in `app_registry_check_support()` in `src/main.rs`.
Do not duplicate support rules across registry crates.

## Add a New Check

Checks are separate crates under `crates/checks/`, and the app enables them via a single list in `src/main.rs`.

### 1) Create a new check crate

Use this shape:

```text
crates/checks/<name>/
  Cargo.toml
  src/
    lib.rs
```

### 2) Define crate-owned check metadata and behavior

In your crate `src/lib.rs`:

- Define your check type and ID constant.
- Implement `safe_pkgs_core::Check` with:
  - `id()`
  - `description()`
  - optional `priority()` (lower runs earlier, default `100`)
  - optional `runs_on_missing_package()` / `runs_on_missing_version()`
  - optional `needs_weekly_downloads()` / `needs_advisories()`
  - `run(&CheckExecutionContext) -> Result<Vec<CheckFinding>, RegistryError>`
- Export `pub fn create_check() -> Box<dyn Check>`.

### 3) Add crate tests

- Add unit tests in the check crate (`src/lib.rs` with `#[cfg(test)]` or `tests/`).

### 4) Verify runtime behavior

- Validate missing-data behavior for your check (`missing package`, `missing version`, and normal path where relevant).
- Run tests before enabling the check in app wiring.

### 5) Wire the crate into the workspace

- Add dependency in root `Cargo.toml` `[dependencies]`.
  Note: workspace member glob `crates/checks/*` is already enabled.

### 6) Add crate to the app check list

- Update `app_check_factories()` in `src/main.rs` to include `safe_pkgs_check_<name>::create_check`.

### 7) Declare registry support in one place

If a registry cannot support your new check, update central policy in `app_registry_check_support()` in `src/main.rs`.
If no override is needed, no registry changes are required.

### 8) Verify support map

Run:

```bash
cargo run -- support-map
```

Confirm the new check appears with expected support and runtime requirement flags.

### 9) Update support-map docs (SVG)

If your change affects checks, registries, or support policy, update the docs support map:

- `docs/assets/check-support-map.svg`
- `docs/check-support-map.md` (if labels/text need to change)

Use `cargo run -- support-map` as the runtime source of truth while updating the SVG.

## Validation Before PR

Run all:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

If your change affects docs, also preview/update docs under `docs/` and `mkdocs.yml`.
