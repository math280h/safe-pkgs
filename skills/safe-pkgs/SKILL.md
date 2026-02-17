---
name: safe-pkgs
description: Use this skill whenever a user asks to install, add, update, approve, or audit dependencies (npm or cargo). It performs pre-install safety checks with safe-pkgs, enforces fail-closed allow/deny decisions, and reports risk/reasons/metadata with safer version guidance.
license: MIT
---

# safe-pkgs dependency safety checks

Use this workflow before dependency installs and for lockfile/manifest audits.

## Quick flow

1. Check each dependency before install.
2. For projects, run a batch lockfile/manifest check.
3. Block installs when `allow` is `false`.
4. Return concise findings and safer version guidance.

## CLI usage

On Linux:
```bash
./scripts/built/linux/safe-pkgs audit <path>
```
On macOS:
```bash
./scripts/built/macos/safe-pkgs audit <path>
```
On Windows:
```powershell
.\scripts\built\windows\safe-pkgs.exe audit <path>
```

## Decision policy

- If `allow` is `false`, do not install.
- If check execution fails, treat as blocked and report the error.
- Do not silently allow on lookup/check failures.

## Response format

Always report:
- `allow`: `true | false`
- `risk`: `low | medium | high | critical`
- `reasons`: concrete findings
- `metadata`: context such as latest version, publish date, downloads, advisories

When blocked, suggest safer/current versions using `metadata.latest` when present.
