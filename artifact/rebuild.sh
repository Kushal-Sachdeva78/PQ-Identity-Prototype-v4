#!/usr/bin/env bash
# Validate the publication code and committed artifacts from the repository root.
# Default/--quick: locked install, integrity, typecheck, v4 and portable v2/v3 tests.
# --full/--ci: also check the environment, recompile v4, audit the key, compare suite verdicts.
# --no-install: retain an already installed node_modules directory.
set -u
cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"
OUT="$ROOT/artifact/out"
MODE="validation"
NO_INSTALL=0
for arg in "$@"; do
  case "$arg" in
    --quick) MODE="validation" ;;
    --full|--ci) MODE="full" ;;
    --no-install) NO_INSTALL=1 ;;
    *) echo "unknown option: $arg" >&2; exit 64 ;;
  esac
done
for marker in results/v4/bench/RUNNING results/v4/BUSY; do
  if [ -e "$marker" ]; then
    echo "refusing validation while $marker exists" >&2
    exit 3
  fi
done
PY="${PQID_PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
mkdir -p "$OUT" || exit 2
FAILED=0
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"
step() {
  local name="$1"; shift
  local log="$OUT/$name.log"
  local started=$SECONDS
  echo "== $name"
  if "$@" > "$log" 2>&1; then
    echo "ok    $name ($((SECONDS - started)) s)" | tee -a "$SUMMARY"
  else
    echo "FAIL  $name ($((SECONDS - started)) s): artifact/out/$name.log" | tee -a "$SUMMARY"
    tail -20 "$log"
    FAILED=$((FAILED + 1))
  fi
}

if [ "$NO_INSTALL" != "1" ]; then
  step npm-ci npm ci --no-audit --no-fund
fi
if [ -f MANIFEST.sha256.tsv ]; then
  step publication-integrity "$PY" scripts/verify_artifacts.py --manifest
else
  step setup-pins "$PY" scripts/verify_artifacts.py
fi
step typecheck npx tsc -p tsconfig.json --noEmit
step tests-v4 npx vitest run tests/v4
step tests-v2v3 npx vitest run tests/circuit.test.ts tests/determinism.test.ts tests/circuit_v3.test.ts

if [ "$MODE" = "full" ]; then
  step environment bash artifact/check_toolchain.sh
  step circuit-v4-matches-pins bash artifact/check_circuit_v4.sh
  step audit-v4-devkey npx tsx setup/groth16_setup_v4.ts
  # Keep the output path relative so it is usable from Node on Windows and POSIX hosts.
  cat > "$OUT/suite_config.json" <<'EOF'
{ "name": "publication-validation", "port": 8590, "out": "artifact/out/suite" }
EOF
  step security-suite-v4 npx tsx harness/v4/security_suite.ts --config artifact/out/suite_config.json
  step suite-verdicts-match "$PY" artifact/compare_suite.py results/v4/security_suite.json artifact/out/suite/security_suite.json
fi

echo
echo "rebuild ($MODE): $FAILED failed step(s)"
cat "$SUMMARY"
exit "$FAILED"
