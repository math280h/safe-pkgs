Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

<#
.SYNOPSIS
Build a Linux Agent Skill binary in Docker and package a Claude Skill zip.

.DESCRIPTION
Builds:
- Linux: x86_64-unknown-linux-gnu

Outputs:
- dist/safe-pkgs-skill.zip
#>

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
$distDir = Join-Path $repoRoot "dist"
$binDir = Join-Path $distDir "binaries"
$skillRoot = Join-Path $distDir "safe-pkgs"
$outputZip = Join-Path $distDir "safe-pkgs-skill.zip"

function Assert-Command([string]$CommandName) {
    if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        throw "Missing required command: $CommandName"
    }
}

function Invoke-DockerBash([string]$Image, [string]$ScriptBody) {
    $mount = "${repoRoot}:/work"
    $args = @(
        "run", "--rm",
        "-v", $mount,
        "-w", "/work",
        $Image,
        "bash", "-c", $ScriptBody
    )
    & docker @args
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed for image '$Image'."
    }
}

Assert-Command "docker"
& docker info | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Docker daemon is not reachable."
}

New-Item -ItemType Directory -Path $binDir -Force | Out-Null

Write-Host "Building Linux binary (x86_64-unknown-linux-gnu) in Docker..."
Invoke-DockerBash "rust:1-bookworm" @"
set -euo pipefail
export CARGO_PROFILE_RELEASE_STRIP=symbols
export CARGO_PROFILE_RELEASE_OPT_LEVEL=z
export CARGO_PROFILE_RELEASE_LTO=thin
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu
strip target/x86_64-unknown-linux-gnu/release/safe-pkgs || true
cp target/x86_64-unknown-linux-gnu/release/safe-pkgs dist/binaries/safe-pkgs-linux
"@

Write-Host "Packaging Claude Skill zip..."
if (Test-Path $skillRoot) {
    Remove-Item $skillRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $skillRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $skillRoot "scripts/built/linux") -Force | Out-Null

Copy-Item (Join-Path $repoRoot "skills/safe-pkgs/SKILL.md") (Join-Path $skillRoot "SKILL.md") -Force
Copy-Item (Join-Path $repoRoot "LICENSE") (Join-Path $skillRoot "LICENSE.txt") -Force
Copy-Item (Join-Path $binDir "safe-pkgs-linux") (Join-Path $skillRoot "scripts/built/linux/safe-pkgs") -Force

if (Test-Path $outputZip) {
    Remove-Item $outputZip -Force
}

# Use tar to ensure zip entries use forward slashes.
& tar -a -cf $outputZip -C $distDir "safe-pkgs"
if ($LASTEXITCODE -ne 0) {
    throw "Failed to create zip at $outputZip"
}

Write-Host "Done: $outputZip"
