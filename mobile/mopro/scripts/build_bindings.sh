#!/usr/bin/env bash
# Build the Mopro iOS bindings for the v4 circuit and put them where the Xcode project expects
# them (mobile/mopro/ios/MoproiOSBindings/, gitignored). macOS with Xcode only.
#
# Usage: bash mobile/mopro/scripts/build_bindings.sh <project-dir> <sim|device|both>
#   sim     aarch64-apple-ios-sim  (Apple-silicon simulator, e.g. the GitHub macOS runner)
#   device  aarch64-apple-ios      (a physical iPhone)
#   both    both slices in one xcframework
#
# The Rust side is always built in release mode (the proving code); the Swift app's build
# configuration is chosen in Xcode (use Release for device timing, docs/v4/PHONE_PROTOCOL.md).
# UNTESTED: written on a Windows host without Xcode or mopro-cli.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROJECT="${1:?usage: build_bindings.sh <project-dir> <sim|device|both>}"
TARGET="${2:-both}"
case "$TARGET" in
  sim) ARCHS=(aarch64-apple-ios-sim) ;;
  device) ARCHS=(aarch64-apple-ios) ;;
  both) ARCHS=(aarch64-apple-ios aarch64-apple-ios-sim) ;;
  *) echo "target must be sim, device or both" >&2; exit 1 ;;
esac

python3 "$REPO_ROOT/mobile/mopro/scripts/check_pins.py"
for a in "${ARCHS[@]}"; do rustup target add "$a"; done

# build.rs of the patched project reads the v4 wasm in place from here (no copy)
export PQID_V4_WASM_DIR="$REPO_ROOT/circuits/build/v4/credential_auth_v4_js"
cd "$PROJECT"
grep -q PQID_V4_GLUE_BEGIN src/lib.rs || { echo "project not patched: run scaffold.sh first" >&2; exit 1; }

mopro build --mode release --platforms ios --architectures "${ARCHS[@]}" --no-auto-update

test -f MoproiOSBindings/mopro.swift || { echo "MoproiOSBindings/mopro.swift missing after mopro build" >&2; exit 1; }
test -d MoproiOSBindings/MoproBindings.xcframework || { echo "MoproBindings.xcframework missing after mopro build" >&2; exit 1; }
DEST="$REPO_ROOT/mobile/mopro/ios/MoproiOSBindings"
rm -rf "$DEST"
cp -R MoproiOSBindings "$DEST"
{
  echo "mopro-cli $(cat PQID_MOPRO_CLI_VERSION 2>/dev/null || echo unknown)"
  echo "archs ${ARCHS[*]}"
  echo "rustc $(rustc --version | awk '{print $2}')"
  echo "built $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$DEST/PQID_BUILD_INFO.txt"
echo "[build_bindings] bindings -> $DEST"
echo "[build_bindings] next: cd mobile/mopro/ios && xcodegen generate && open PQIDPhone.xcodeproj"
