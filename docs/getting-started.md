---
hide:
  - title
  - toc
---

<div class="docs-hero docs-hero--start">
  <h1>Choose a path.</h1>
  <p>
    Use MCP mode for always-on gating before installs, or run CLI audits for one-off dependency checks.
    Both paths use binaries from the same release build.
  </p>
  <div class="chip-grid">
    <span>MCP integration</span>
    <span>CLI audit mode</span>
    <span>Windows + macOS/Linux</span>
  </div>
</div>

<div class="path-tabs" markdown="1">

=== "MCP Integration (Recommended)"

    Use this when an editor or agent should call `safe-pkgs` before installs.

    #### 1. Build release binary

      ```sh
      cargo build --release
      ```

    #### 2. Run MCP server

    === "macOS / Linux"

        ```bash
        ./target/release/safe-pkgs serve --mcp
        ```

    === "Windows PowerShell"

        ```powershell
        .\target\release\safe-pkgs-mcp.exe
        ```

    #### 3. Add MCP client config

    ```json
    {
      "servers": {
        "safe-pkgs": {
          "type": "stdio",
          "command": "/path/to/safe-pkgs",
          "args": ["serve", "--mcp"]
        }
      },
      "inputs": []
    }
    ```

    Windows MCP config (no console window):

    ```json
    {
      "servers": {
        "safe-pkgs": {
          "type": "stdio",
          "command": "safe-pkgs-mcp.exe"
        }
      },
      "inputs": []
    }
    ```

=== "CLI Audit Only"

    Use this when you only want local dependency checks without running MCP transport.

    #### 1. Build release binary

    === "macOS / Linux"

        ```bash
        cargo build --release
        ```

    === "Windows PowerShell"

        ```powershell
        cargo build --release
        ```

    #### 2. Run audit

    === "macOS / Linux"

        ```bash
        ./target/release/safe-pkgs audit /path/to/project-or-lockfile
        ./target/release/safe-pkgs audit /path/to/requirements.txt --registry pypi
        ```

    === "Windows PowerShell"

        ```powershell
        .\target\release\safe-pkgs.exe audit C:\path\to\project-or-lockfile
        .\target\release\safe-pkgs.exe audit C:\path\to\requirements.txt --registry pypi
        ```

</div>

## Install once (recommended)

Use a stable install path instead of `target/...`:

```bash
cargo install --path . --locked
```

Installed binaries:

- `safe-pkgs` for CLI usage and `serve --mcp`
- `safe-pkgs-mcp` for Windows MCP hosts (no console window)

Default install directory:

- macOS/Linux: `~/.cargo/bin`
- Windows: `%USERPROFILE%\.cargo\bin`
