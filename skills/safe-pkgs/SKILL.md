---
name: safe-pkgs
description: Use when a user asks to install, update, approve, or audit npm/cargo dependencies. Run safe-pkgs checks first, enforce fail-closed allow/deny decisions, and report risk, reasons, and metadata.
---

# safe-pkgs dependency safety checks

Use this workflow before dependency installs and for lockfile/manifest audits.

## Quick flow

1. Check each dependency before install.
2. For projects, run a batch lockfile/manifest check.
3. Block installs when `allow` is `false`.
4. Return concise findings and safer version guidance.

## CLI usage (Linux Agent Skill runtime only)

Default binary path inside Claude skill runtime:
```bash
/mnt/skills/user/safe-pkgs/scripts/built/linux/safe-pkgs
```

If DNS fails in Claude sandbox, pass an explicit proxy URL:
```bash
/mnt/skills/user/safe-pkgs/scripts/built/linux/safe-pkgs --https-proxy "http://<proxy-host>:<proxy-port>" check lodash 1.0.2
```

If TLS fails with `UnknownIssuer`, pass a PEM CA bundle:
```bash
/mnt/skills/user/safe-pkgs/scripts/built/linux/safe-pkgs --ca-cert "/path/to/corp-root.pem" check lodash 1.0.2
```

Last-resort debug only (unsafe):
```bash
/mnt/skills/user/safe-pkgs/scripts/built/linux/safe-pkgs --insecure-skip-tls-verify check lodash 1.0.2
```

Run lockfile/manifest audits:
```bash
/mnt/skills/user/safe-pkgs/scripts/built/linux/safe-pkgs audit <path-to-package.json-or-package-lock.json>
```

Run a single package check:
```bash
/mnt/skills/user/safe-pkgs/scripts/built/linux/safe-pkgs check lodash 1.0.2
```

You can also pass inline package specs:
```bash
/mnt/skills/user/safe-pkgs/scripts/built/linux/safe-pkgs check lodash@1.0.2
```

For Rust crates:
```bash
/mnt/skills/user/safe-pkgs/scripts/built/linux/safe-pkgs check serde 1.0.100 --registry cargo
```

Fallback path (manifest-based audit) if needed:
```bash
tmpdir="$(mktemp -d)"
cat > "$tmpdir/package.json" << 'EOF'
{
  "name": "pkg-check",
  "dependencies": {
    "lodash": "1.0.2"
  }
}
EOF
/mnt/skills/user/safe-pkgs/scripts/built/linux/safe-pkgs audit "$tmpdir/package.json"
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
