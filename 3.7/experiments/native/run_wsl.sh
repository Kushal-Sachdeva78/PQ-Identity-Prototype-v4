#!/usr/bin/env bash
set -euo pipefail
mode="${1:-}"
case "$mode" in smoke|run|preflight|typecheck) ;; *) echo 'usage: run_wsl.sh {preflight|typecheck|smoke|run}'; exit 2;; esac
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
repo="$(cd -- "$script_dir/../../.." && pwd)"
win_repo="${PQID_WINDOWS_REPO:-$repo}"
source_repo="${PQID_SOURCE_ROOT:-$repo}"
win_repo="$(cd -- "$win_repo" && pwd)"
source_repo="$(cd -- "$source_repo" && pwd)"
resolve_binary() {
  local selected
  selected="$(command -v "$1")" || { echo "Executable unavailable: $1" >&2; return 2; }
  printf '%s/%s\n' "$(cd -- "$(dirname "$selected")" && pwd)" "$(basename "$selected")"
}
node_bin="${PQID_NODE_BIN:-$(command -v node || true)}"
if [ -z "$node_bin" ]; then echo 'Node is unavailable; set PQID_NODE_BIN'; exit 2; fi
node_bin="$(resolve_binary "$node_bin")"
native_bin="${PQID_NATIVE_RAW:-${PQID_NATIVE_BIN:-}}"
anvil_bin="${PQID_ANVIL_BIN:-${ANVIL_BIN:-$(command -v anvil || true)}}"
if [ "$mode" != typecheck ]; then
  if [ -z "$native_bin" ]; then echo 'Set PQID_NATIVE_RAW to the rapidsnark prover executable'; exit 2; fi
  native_bin="$(resolve_binary "$native_bin")"
  if [ -z "$anvil_bin" ]; then echo 'Anvil is unavailable; set PQID_ANVIL_BIN'; exit 2; fi
  anvil_bin="$(resolve_binary "$anvil_bin")"
fi
export PATH="$(dirname "$node_bin")${anvil_bin:+:$(dirname "$anvil_bin")}:$PATH"
export PQID_NATIVE_RAW="$native_bin"
export PQID_WINDOWS_REPO="$win_repo"
export PQID_SOURCE_ROOT="$source_repo"
export PQID_NATIVE_SOURCE="$script_dir"
export PQID_ANVIL_BIN="$anvil_bin"
stage="$(mktemp -d /tmp/pqid37-native.XXXXXXXX)"
mkdir -p "$stage/3.7/experiments/native" "$stage/tmp"
export TMPDIR="$stage/tmp"
for entry in harness node_modules packages setup circuits onchain types; do ln -s "$source_repo/$entry" "$stage/$entry"; done
cp "$source_repo/package.json" "$stage/package.json"
cp "$source_repo/tsconfig.json" "$stage/tsconfig.json"
cp "$script_dir/runner.ts" "$stage/3.7/experiments/native/runner.ts"
cp "$script_dir/tsconfig.json" "$stage/3.7/experiments/native/tsconfig.json"
cp "$script_dir/native_adapter.py" "$stage/3.7/experiments/native/native_adapter.py"
chmod 700 "$stage/3.7/experiments/native/native_adapter.py"
export PQID_RAPIDSNARK="$stage/3.7/experiments/native/native_adapter.py"
export PQID_NATIVE_ADAPTER_META="$stage/tmp/adapter-metadata.json"
export PQID_STAGE_ROOT="$stage"
cd "$stage"
cleanup() {
  case "$stage" in /tmp/pqid37-native.*) rm -rf -- "$stage" ;; esac
}
trap cleanup EXIT
if [ "$mode" = typecheck ]; then
  "$node_bin" node_modules/typescript/bin/tsc -p 3.7/experiments/native/tsconfig.json --noEmit
else
  "$node_bin" --import tsx 3.7/experiments/native/runner.ts "$mode"
fi
