#!/usr/bin/env bash
# Create the Mopro Rust project for the PQ-Identity v4 circuit (macOS; also runs on Linux).
#
# Usage: bash mobile/mopro/scripts/scaffold.sh [work-dir]
#   work-dir defaults to mobile/mopro/_work (gitignored by mobile/.gitignore).
#
# Steps: check the pinned artifacts, run `mopro init --adapter circom`, then patch the fresh
# project with patch_template.py (v4 circuit glue, build.rs that reads the repo wasm in place,
# Config.toml). The Mopro template's own files (src/circom.rs, src/error.rs, src/stubs.rs,
# src/bin/*) come from the installed CLI and are not copied into this repo.
#
# Needs: mopro-cli (cargo install mopro-cli --version 0.3.7 --locked), python3 >= 3.11.
# UNTESTED: written on a Windows host without mopro-cli (docs/v4/PHONE_PROTOCOL.md).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KIT="$REPO_ROOT/mobile/mopro"
WORK="${1:-$KIT/_work}"
PROJECT_NAME="pqid_v4_mopro"
EXPECTED_CLI="${PQID_MOPRO_CLI_VERSION:-0.3.7}"

command -v mopro >/dev/null || { echo "mopro-cli not found: cargo install mopro-cli --version $EXPECTED_CLI --locked" >&2; exit 1; }
CLI_VERSION="$(mopro --version 2>/dev/null | awk '{print $NF}')"
if [ "$CLI_VERSION" != "$EXPECTED_CLI" ]; then
  echo "warning: mopro-cli $CLI_VERSION, kit written for $EXPECTED_CLI (record this in the log)" >&2
fi

python3 "$KIT/scripts/check_pins.py"

mkdir -p "$WORK"
if [ -e "$WORK/$PROJECT_NAME" ]; then
  echo "[scaffold] $WORK/$PROJECT_NAME exists; patching it again (idempotent)"
else
  (cd "$WORK" && mopro init --adapter circom --project-name "$PROJECT_NAME")
fi
python3 "$KIT/scripts/patch_template.py" "$WORK/$PROJECT_NAME"
echo "$CLI_VERSION" > "$WORK/$PROJECT_NAME/PQID_MOPRO_CLI_VERSION"
echo "[scaffold] project ready: $WORK/$PROJECT_NAME"
echo "[scaffold] next: bash mobile/mopro/scripts/build_bindings.sh $WORK/$PROJECT_NAME <sim|device|both>"
