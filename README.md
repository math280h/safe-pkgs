# safe-pkgs

<p align="center">
  <strong>Package safety checks for AI agents before install.</strong><br />
  Rust MCP server + CLI with allow/deny decisions, risk scoring, and audit logs.
</p>

<p align="center">
  <a href="https://math280h.github.io/safe-pkgs/">Documentation</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-stable-orange" alt="Rust" />
  <img src="https://img.shields.io/badge/MCP-rmcp%200.15-blue" alt="MCP" />
  <img src="https://img.shields.io/badge/cache-SQLite-green" alt="Cache" />
</p>

<table>
  <tr>
    <td valign="top" width="50%">
      <img src="./docs/assets/vscode.png" alt="VSCode Extension example 1" width="100%" />
    </td>
    <td valign="top" width="50%">
      <img src="./docs/assets/vscode2.png" alt="VSCode Extension example 2" width="100%" />
    </td>
  </tr>
</table>

## At a Glance

`safe-pkgs` returns machine-readable decisions:
- `allow`: `true` or `false`
- `risk`: `low | medium | high | critical`
- `reasons`: human-readable findings
- `metadata`: package context (latest, publish date, downloads, advisories)

Supported registries:
- `npm` (default)
- `cargo` (crates.io)

<<<<<<< feat/skills
## Tools and Commands

| Surface | Name | Purpose |
|---|---|---|
| MCP tool | `check_package(name, version?, registry?)` | Check a single package before install |
| MCP tool | `check_lockfile(path?, registry?)` | Batch-check npm `package-lock.json` / `package.json` |
| CLI | `safe-pkgs serve --mcp` | Run MCP server over stdio |
| CLI | `safe-pkgs audit <path>` | Run one-off dependency audit |

## Skills Support

This repository includes an Agent Skills-compatible skill at:
- `skills/safe-pkgs/SKILL.md`

This format is compatible with:
- Agent Skills-compatible clients that support `SKILL.md` directories

If your agent expects a different skills root, copy the `safe-pkgs` folder into that root.

GitHub Releases also publish one prebuilt cross-platform skill bundle:
- `safe-pkgs-skill.zip`

Each bundle contains:
- `safe-pkgs/SKILL.md`
- `safe-pkgs/scripts/built/linux/safe-pkgs`
- `safe-pkgs/scripts/built/macos/safe-pkgs`
- `safe-pkgs/scripts/built/windows/safe-pkgs.exe`
- `safe-pkgs/LICENSE.txt`

## Checks Pipeline

- Existence check
- Version age check
- Staleness check
- Typosquat check
- Popularity check
- Install script check
- Advisory/CVE check

=======
>>>>>>> main
## Roadmap

These features are "planned" but not yet implemented:

- [ ] PyPI registry support
- [ ] NVD advisory enrichment
- [ ] Optional Snyk advisory provider
- [ ] Socket.dev integration
- [ ] GitHub Actions integration for CI auditing
- [ ] Rate-limit aware registry client with backoff
- [ ] Custom Rules
- [ ] HTTP Streamable MCP server option
- [ ] More validated editor config examples
- [ ] Git hook integration for pre-commit checks
- [ ] Support for private registries

## Quick Start

Build and run MCP server:

```bash
cargo build --release
./target/release/safe-pkgs serve --mcp
```

Windows PowerShell:

```powershell
.\target\release\safe-pkgs.exe serve --mcp
```

Run a local audit:

```bash
safe-pkgs audit /path/to/project-or-package.json
```

## MCP Config Example

```json
{
  "servers": {
    "safe-pkgs": {
      "type": "stdio",
      "command": "/path/to/safe-pkgs",
      "args": [
        "serve",
        "--mcp"
      ]
    }
  },
  "inputs": []
}
```

## Decision Output Example

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

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Coverage

Install:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov
```

Summary:

```bash
cargo llvm-cov --workspace --all-features --summary-only
```

HTML report:

```bash
cargo llvm-cov --workspace --all-features --html
```

Report path:
- `target/llvm-cov/html/index.html`

## Local docs

```bash
pip install mkdocs mkdocs-material
mkdocs serve
```