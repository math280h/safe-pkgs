---
hide:
  - title
  - toc
---

<div class="docs-hero docs-hero--start">
  <h1>Choose a path.</h1>
  <p>
    Use MCP mode for always-on gating before installs, or run CLI audits for one-off dependency checks.
    Both paths use the same release binary.
  </p>
  <div class="chip-grid">
    <span>MCP integration</span>
    <span>CLI audit mode</span>
    <span>Windows + macOS/Linux</span>
  </div>
</div>

<div class="path-tabs" markdown="1">

=== "MCP Integration"

    Use this when an editor or agent can call an MCP server over stdio.

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
        .\target\release\safe-pkgs.exe serve --mcp
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

=== "Agent Skill (ZIP Upload)"

    Quick path (Linux-only bundle via Docker):

    === "Windows PowerShell"

        ```powershell
        .\scripts\build-skill-bundle-docker.ps1
        ```

    === "macOS / Linux"

        ```bash
        bash ./scripts/build-skill-bundle-docker.sh
        ```

    Output: `dist/safe-pkgs-skill.zip`

    #### 1. Verify zip layout before upload

    ```bash
    tar -tf dist/safe-pkgs-skill.zip
    ```
    Expected entries include:
    - `safe-pkgs/SKILL.md`
    - `safe-pkgs/scripts/built/linux/safe-pkgs`

    #### 2. Run binary in Claude Linux runtime

    Skill binary path:
    - `/mnt/skills/user/safe-pkgs/scripts/built/linux/safe-pkgs`

    Example single-package check:
    ```bash
    /mnt/skills/user/safe-pkgs/scripts/built/linux/safe-pkgs check lodash 1.0.2
    ```

    Example lockfile/manifest audit:
    ```bash
    /mnt/skills/user/safe-pkgs/scripts/built/linux/safe-pkgs audit /path/to/package.json
    ```

    In Claude Desktop: `Settings -> Capabilities -> Skills`, upload `dist/safe-pkgs-skill.zip`.

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
        ./target/release/safe-pkgs check lodash 1.0.2
        ```

    === "Windows PowerShell"

        ```powershell
        .\target\release\safe-pkgs.exe audit C:\path\to\project-or-lockfile
        .\target\release\safe-pkgs.exe check lodash 1.0.2
        ```

</div>
