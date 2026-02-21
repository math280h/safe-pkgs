# Crate Layout

This workspace keeps crate types grouped to stay maintainable as the number of providers/checks grows.

Top-level crates:

- `core/` shared traits and domain types used across app/plugins
- `osv/` OSV advisory client integration
- `registry/` registry providers (`npm`, `cargo`, `pypi`)

Grouped crates:

- `checks/*` one crate per check implementation
- `registry/*` one crate per registry provider implementation

Guideline:

- New registries: add `crates/registry/<name>/`
- New checks: add `crates/checks/<name>/`
