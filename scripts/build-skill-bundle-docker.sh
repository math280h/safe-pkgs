#!/usr/bin/env bash
set -euo pipefail

# Build the Linux skill binary in Docker and package a Claude Skill zip.
# Output: dist/safe-pkgs-skill.zip

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"
BIN_DIR="${DIST_DIR}/binaries"
SKILL_ROOT="${DIST_DIR}/safe-pkgs"
OUTPUT_ZIP="${DIST_DIR}/safe-pkgs-skill.zip"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

run_docker_bash() {
  local image="$1"
  local script="$2"
  docker run --rm \
    -v "${REPO_ROOT}:/work" \
    -w /work \
    "${image}" \
    bash -c "${script}"
}

require_cmd docker
require_cmd zip
docker info >/dev/null

mkdir -p "${BIN_DIR}"

echo "Building Linux binary (x86_64-unknown-linux-gnu) in Docker..."
run_docker_bash "rust:1-bookworm" \
  "set -euo pipefail; \
   export CARGO_PROFILE_RELEASE_STRIP=symbols; \
   export CARGO_PROFILE_RELEASE_OPT_LEVEL=z; \
   export CARGO_PROFILE_RELEASE_LTO=thin; \
   export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1; \
   rustup target add x86_64-unknown-linux-gnu; \
   cargo build --release --target x86_64-unknown-linux-gnu; \
   strip target/x86_64-unknown-linux-gnu/release/safe-pkgs || true; \
   cp target/x86_64-unknown-linux-gnu/release/safe-pkgs dist/binaries/safe-pkgs-linux"

echo "Packaging Claude Skill zip..."
rm -rf "${SKILL_ROOT}"
mkdir -p "${SKILL_ROOT}/scripts/built/linux"

cp "${REPO_ROOT}/skills/safe-pkgs/SKILL.md" "${SKILL_ROOT}/SKILL.md"
cp "${REPO_ROOT}/LICENSE" "${SKILL_ROOT}/LICENSE.txt"
cp "${BIN_DIR}/safe-pkgs-linux" "${SKILL_ROOT}/scripts/built/linux/safe-pkgs"
chmod +x "${SKILL_ROOT}/scripts/built/linux/safe-pkgs"

rm -f "${OUTPUT_ZIP}"
(
  cd "${DIST_DIR}"
  zip -r "safe-pkgs-skill.zip" "safe-pkgs"
)

echo "Done: ${OUTPUT_ZIP}"
