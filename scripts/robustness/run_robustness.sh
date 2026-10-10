#!/usr/bin/env bash
# Drivers of the robustness row (DECISIONS D-034; docs/v4/ROBUSTNESS.md). Run from Git Bash on
# the Windows host (the primary environment), from the repository root.
#
#   bash scripts/robustness/run_robustness.sh fuzz  --campaign <name>
#       Untimed, CPU-heavy: holds results/v4/BUSY for all three steps (markers.ts run --kind BUSY;
#       the runners use that hold): package fuzzing with coverage (fuzz.ts --coverage, all targets,
#       chain targets on Anvil 8781), the circuit and witness fuzz (circuit_fuzz.ts), the registry
#       fuzz and invariant tests (forge_fuzz.ts). Then the results index (summarize.py).
#       About 60 to 75 min [S] (docs/v4/ROBUSTNESS.md section 9). Run before any timed series
#       (D-034 order).
#   bash scripts/robustness/run_robustness.sh load  --campaign <name> --confirm-quiet
#       The timed load test (load.ts, Anvil 8780) under results/v4/bench/RUNNING
#       (markers.ts run --kind RUNNING), then, after the marker is released, analyze_load.py and
#       summarize.py. About 60 to 90 min [S] (docs/v4/ROBUSTNESS.md 3.13); needs a quiet window on
#       AC power.
#   bash scripts/robustness/run_robustness.sh smoke [--campaign <name>]
#       Every runner at smoke size, no marker (refuses while one exists), output under
#       results/v4/robustness/_smoke/ (gitignored, never quoted). A few minutes.
#
# Full runs (fuzz, load) refuse to start unless the protocol, the harness and the code under test
# are committed and unchanged against HEAD (the runners check it with read-only git commands).
#
# Toolchain (D-034; docs/v4/ROBUSTNESS.md 3.2):
#   Windows: node from PATH must be v24.18.0, tools/foundry/anvil.exe 1.5.1.
#   Linux or WSL: PQID_NODE=<absolute path of the Node 24.21.0 binary (nvm)> and
#   PQID_ANVIL_DIR=<directory holding the Anvil 1.5.1 binary taken from the pqid-v4 Docker image>
#   are required for fuzz and load (the directory is put first on PATH, so the runners' Anvil is
#   that one); PQID_WINDOWS_REPO=/mnt/c/.../PQ-Identity-v4 makes markers.ts hold the marker in
#   the Windows repository. Analyses need python3 with numpy (PQID_PYTHON may name it); on WSL
#   numpy is not installed system-wide, so run the analysis on the Windows host or in a user-space
#   environment that has it.
# Logs: results/v4/robustness/logs/<mode>_<campaign>/<step>.log and steps.log (scrubbed: no user
# name, host name, home or temp path; a log that cannot be scrubbed is withheld and the step
# fails); smoke logs under results/v4/robustness/_smoke/logs/.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELF="$REPO/scripts/robustness/run_robustness.sh"
cd "$REPO" || exit 2
die() { echo "run_robustness: $*" >&2; exit 2; }

MODE="${1:-}"; [ $# -gt 0 ] && shift
CAMPAIGN=""; CONFIRM=0; INNER=0
ORIG_ARGS=("$@")
while [ $# -gt 0 ]; do
  case "$1" in
    --campaign) CAMPAIGN="$2"; shift 2 ;;
    --confirm-quiet) CONFIRM=1; shift ;;
    --inner) INNER=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
case "$MODE" in fuzz|load|smoke) ;; *) die "usage: run_robustness.sh fuzz|load|smoke --campaign <name> [--confirm-quiet]" ;; esac
[ "$MODE" = smoke ] && [ -z "$CAMPAIGN" ] && CAMPAIGN="smoke"
[ -n "$CAMPAIGN" ] || die "--campaign <name> is required"
echo "$CAMPAIGN" | grep -Eq '^[A-Za-z0-9_.-]{1,64}$' || die "campaign must match ^[A-Za-z0-9_.-]{1,64}$"
[ "$MODE" != load ] || [ "$CONFIRM" = 1 ] || die "the load test is a timed series: pass --confirm-quiet (AC power, other applications closed, no other agent jobs, no WSL work)"

# ---------------------------------------------------------------- toolchain
OS_KIND=linux
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) OS_KIND=windows ;; esac
if [ "$OS_KIND" = linux ]; then
  if [ "$MODE" != smoke ]; then
    [ -n "${PQID_NODE:-}" ] || die "Linux/WSL: set PQID_NODE to the absolute path of the D-034 Node 24.21.0 binary"
    [ -n "${PQID_ANVIL_DIR:-}" ] || die "Linux/WSL: set PQID_ANVIL_DIR to the directory of the D-034 Anvil 1.5.1 binary"
  fi
  if [ -n "${PQID_ANVIL_DIR:-}" ]; then
    [ -x "$PQID_ANVIL_DIR/anvil" ] || die "PQID_ANVIL_DIR has no executable anvil"
    PATH="$PQID_ANVIL_DIR:$PATH"; export PATH
  fi
fi
NODE_BIN="${PQID_NODE:-node}"
command -v "$NODE_BIN" > /dev/null 2>&1 || [ -x "$NODE_BIN" ] || die "node not found ($NODE_BIN); on Linux/WSL set PQID_NODE"
[ -n "${PQID_NODE:-}" ] && export PQID_NODE
TSX=("$NODE_BIN" --import tsx)
pick_python() { # a python 3 that runs (on Windows "python3" may be the Microsoft Store stub)
  local c
  if [ -n "${PQID_PYTHON:-}" ]; then set -- "$PQID_PYTHON"; else set -- python3 python; fi
  for c in "$@"; do
    command -v "$c" > /dev/null 2>&1 || [ -x "$c" ] || continue
    "$c" -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" > /dev/null 2>&1 && { echo "$c"; return 0; }
  done
  return 1
}
PY="$(pick_python)" || die "no working python 3.9+ found (python3, python; or set PQID_PYTHON)"
if [ "$MODE" != fuzz ] && ! "$PY" -c "import numpy" > /dev/null 2>&1; then
  echo "run_robustness: warning: $PY has no numpy, so analyze_load.py will fail; run it later where numpy exists (docs/v4/ROBUSTNESS.md 3.2)" >&2
fi

check_toolchain() { # the D-034 toolchain of this OS, before a full fuzz or load step
  local nv; nv="$("$NODE_BIN" --version)"
  if [ "$OS_KIND" = windows ]; then
    [ "$nv" = "v24.18.0" ] || die "Node is $nv; the Windows campaigns use v24.18.0 (E4 comparability)"
    tools/foundry/anvil.exe --version | grep -q "Version: 1.5.1-" || die "tools/foundry/anvil.exe is not 1.5.1"
  else
    [ "$nv" = "v24.21.0" ] || die "Node ($NODE_BIN) is $nv; the WSL campaigns use v24.21.0 (D-034)"
    anvil --version | grep -q "Version: 1.5.1-" || die "anvil on PATH ($(command -v anvil)) is not 1.5.1; set PQID_ANVIL_DIR to the D-034 binary"
  fi
}

if [ "$MODE" = smoke ]; then LOGS="results/v4/robustness/_smoke/logs/${CAMPAIGN}"; else LOGS="results/v4/robustness/logs/${MODE}_${CAMPAIGN}"; fi
STEPS="$LOGS/steps.log"
stamp() { date -u "+%Y-%m-%dT%H:%M:%SZ"; }
win() { cygpath -w "$1" 2>/dev/null || echo "$1"; }
mix() { cygpath -m "$1" 2>/dev/null || echo "$1"; }
TMP_UNIX="${TMPDIR:-${TEMP:-/tmp}}"
scrub() { # fails closed: a log that cannot be scrubbed is replaced by a notice (scrub_log.py)
  # MSYS_NO_PATHCONV: Git Bash would otherwise rewrite /c/... arguments before python sees them
  if ! MSYS_NO_PATHCONV=1 "$PY" scripts/robustness/scrub_log.py "$(mix "$1")" \
      "$REPO=<repo>" "$(win "$REPO")=<repo>" "$(mix "$REPO")=<repo>" \
      "$TMP_UNIX=<tmp>" "$(win "$TMP_UNIX")=<tmp>" "$(mix "$TMP_UNIX")=<tmp>" "${TEMP:-}=<tmp>" "${TMP:-}=<tmp>" \
      "$HOME=~" "$(win "$HOME")=~" "$(mix "$HOME")=~" \
      "${USERNAME:-}=<user>" "${USER:-}=<user>" "${COMPUTERNAME:-}=<host>" "${HOSTNAME:-}=<host>" "$(hostname 2>/dev/null)=<host>"; then
    echo "log withheld: scrub failed" > "$1"
    return 1
  fi
}
FAILED=0
step() { # step <name> <command...>
  local name="$1"; shift
  mkdir -p "$LOGS"
  echo "== $(stamp) start $name" >> "$STEPS"
  "$@" > "$LOGS/$name.log" 2>&1
  local rc=$?
  if ! scrub "$LOGS/$name.log"; then
    echo "   $(stamp) $name: log scrub failed, log withheld" >> "$STEPS"
    [ "$rc" = 0 ] && rc=97
  fi
  echo "   $(stamp) end $name exit $rc" >> "$STEPS"
  [ "$rc" = 0 ] || FAILED=1
  return $rc
}
bash_path() { if command -v cygpath > /dev/null 2>&1; then cygpath -w "$BASH"; else echo "$BASH"; fi; }
markers_free() { # exit 3 = a marker exists; any other failure is reported as it is
  local extra=()
  [ "$MODE" = smoke ] && extra=(--allow-local-only)
  local out rc
  out="$("${TSX[@]}" harness/v4/lib/markers.ts status ${extra[@]+"${extra[@]}"} 2>&1)"; rc=$?
  [ "$rc" = 0 ] && return 0
  [ "$rc" = 3 ] && die "a RUNNING or BUSY marker exists (markers.ts status); $MODE refuses"
  echo "$out" >&2
  die "markers.ts status failed (exit $rc), see above (in WSL set PQID_WINDOWS_REPO to the Windows repository)"
}

# ---------------------------------------------------------------- outer: take the marker, then analyse
if [ "$INNER" = 0 ] && [ "$MODE" != smoke ]; then
  check_toolchain
  KIND=BUSY; [ "$MODE" = load ] && KIND=RUNNING
  mkdir -p "$LOGS"
  echo "# robustness $MODE $CAMPAIGN started $(stamp); HEAD $(GIT_OPTIONAL_LOCKS=0 git rev-parse HEAD); node $("$NODE_BIN" --version)" >> "$STEPS"
  "${TSX[@]}" harness/v4/lib/markers.ts run --kind "$KIND" --campaign "robustness/$MODE/$CAMPAIGN" \
    --runner scripts/robustness/run_robustness.sh --owner "operator" --note "robustness row ($MODE), docs/v4/ROBUSTNESS.md" \
    -- "$(bash_path)" "$SELF" "$MODE" "${ORIG_ARGS[@]}" --inner
  rc=$?
  echo "   $(stamp) marker released; inner exit $rc" >> "$STEPS"
  [ "$rc" = 0 ] || FAILED=1
  # analyses run only after the marker is gone (they refuse while RUNNING or BUSY exists)
  if [ "$MODE" = load ]; then step analyze_load "$PY" scripts/robustness/analyze_load.py --campaign "$CAMPAIGN"; fi
  step summarize "$PY" scripts/robustness/summarize.py
  echo "# finished $(stamp), failed=$FAILED" >> "$STEPS"
  exit "$FAILED"
fi

# ---------------------------------------------------------------- inner (marker held) and smoke
if [ "$MODE" = smoke ]; then
  markers_free
  rm -rf "$LOGS"
  mkdir -p "$LOGS"
  echo "# robustness smoke $CAMPAIGN started $(stamp); HEAD $(GIT_OPTIONAL_LOCKS=0 git rev-parse HEAD); node $("$NODE_BIN" --version)" >> "$STEPS"
  for d in fuzz circuit_fuzz forge load; do rm -rf "results/v4/robustness/_smoke/$d/$CAMPAIGN"; done
  step fuzz "${TSX[@]}" harness/v4/robustness/fuzz.ts --smoke --campaign "$CAMPAIGN" --targets all --coverage
  step circuit "${TSX[@]}" harness/v4/robustness/circuit_fuzz.ts --smoke --campaign "$CAMPAIGN"
  step forge "${TSX[@]}" harness/v4/robustness/forge_fuzz.ts --smoke --campaign "$CAMPAIGN"
  step load "${TSX[@]}" harness/v4/robustness/load.ts --smoke --campaign "$CAMPAIGN"
  step analyze_load "$PY" scripts/robustness/analyze_load.py --smoke --campaign "$CAMPAIGN"
  step summarize "$PY" scripts/robustness/summarize.py --smoke
  echo "# finished $(stamp), failed=$FAILED" >> "$STEPS"
  exit "$FAILED"
fi

check_toolchain
if [ "$MODE" = fuzz ]; then
  step fuzz "${TSX[@]}" harness/v4/robustness/fuzz.ts --campaign "$CAMPAIGN" --targets all --coverage
  step circuit "${TSX[@]}" harness/v4/robustness/circuit_fuzz.ts --campaign "$CAMPAIGN"
  step forge "${TSX[@]}" harness/v4/robustness/forge_fuzz.ts --campaign "$CAMPAIGN"
  exit "$FAILED"
fi

# load (inner, RUNNING held by the outer markers.ts run)
step load "${TSX[@]}" harness/v4/robustness/load.ts --campaign "$CAMPAIGN"
exit "$FAILED"
