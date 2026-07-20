# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-20

First stable release. This release focuses on correctness of version and dependency
handling across all three ecosystems, plus security and release hardening.

### Fixed

- **`check_package` now accepts ranged and partial versions.** A request such as
  `check_package(name="react", version="18")`, `"^4.17.0"`, `serde "1"`, or
  `requests ">=2"` was previously denied as a nonexistent ("hallucinated") version.
  Version requirements are now resolved per ecosystem to the best matching published
  version; only a concrete exact version that is genuinely absent is flagged.
- **npm/PyPI manifests no longer flag local, git, and URL dependencies.** `file:`,
  `git`/`github:`, tarball URL, `workspace:`/`link:` (npm) and `path`/`git`/`url`
  (Poetry) and PEP 508 `name @ url` dependencies are skipped rather than looked up on
  the public registry and reported as nonexistent. npm aliases (`npm:real-pkg@1.2.3`)
  now audit the real target.
- **PyPI requirement lines with multiple specifiers are no longer dropped.** Lines such
  as `torch>1.9,<2.0` and `numpy!=1.24.0,>=1.20` are now split on the leftmost
  operator and audited instead of being silently skipped.
- **Denylist, allowlist, and dependency-confusion matching now compare canonical
  names.** An equivalent spelling (case, and `-`/`_`/`.` per PyPI/crates.io rules) can
  no longer bypass a rule (for example, a denylisted `evil-pkg` now also blocks
  `evil_pkg`).
- **The MCP server now advertises its own identity** (`safe-pkgs`/version) instead of
  the underlying `rmcp` crate name and version.
- Private-registry bearer tokens are no longer sent over cleartext `http://` (except to
  loopback hosts), matching the audit and remote-config guards.

### Changed

- Version bumped to `1.0.0`.
- Package metadata added for distribution: `license = "MIT"`, `rust-version = "1.85"`,
  `repository`, `description`; the workspace is marked `publish = false` (distributed as
  a binary via release artifacts and `cargo install --path .`).
- CI now runs `clippy` and `test` with `--workspace`, so all crates are gated.
- README: corrected the rmcp version badge and the decision-payload `metadata` note.

### Known limitations

- A lockfile that pins the same package at multiple versions (for example
  `windows-sys` 0.48 and 0.52 in a `Cargo.lock`) is currently audited at a single
  version; the other pinned version is not evaluated. This is tracked for a follow-up
  release.
