# Checks Workspace Layout

Checks are implemented as independent crates under `crates/checks/`.

Structure:

- `advisory/`
- `existence/`
- `install-script/`
- `popularity/`
- `staleness/`
- `typosquat/`
- `version-age/`

Conventions:

- Package name: `safe-pkgs-check-<name>`
- Entry point: `create_check() -> Box<dyn safe_pkgs_core::Check>`
- Check ID string is owned by the check crate
- Unit tests for check behavior live inside each check crate

App wiring:

- The binary chooses enabled checks in `src/main.rs` via `app_check_factories()`.
- Registry check-support compatibility is centralized in `app_registry_check_support()` in `src/main.rs`.
- The orchestrator in `src/checks.rs` runs factories and handles ordering/config gating.
