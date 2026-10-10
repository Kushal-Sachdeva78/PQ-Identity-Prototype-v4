#!/usr/bin/env bash
# Quiet window of the comparable benchmark series (docs/v4/CMP.md, "Order of work and commands").
# Windows host, Git Bash, from the repository root, on AC power, with nothing else running (no
# agents, tests, builds or WSL work). Run it after the key ceremony, after
# `harness/v4/cmp/inputs.ts` has pinned the inputs with the same v4 key, and after the code, the
# addendum, the pins and the input lock are committed (the runners refuse otherwise).
#
# v4 key (D-034: the ceremony key): set PQID_CMP_V4_ZKEY, PQID_CMP_V4_VKEY, PQID_CMP_V4_LABEL and
# PQID_CMP_V4_PINS (repository-relative). With none set the window stops at once unless
# PQID_CMP_ALLOW_DEV_KEY=1 (then the runners use the dev key and its rows are labelled dev).
# PQID_CMP_WITH_CURVE=1 adds the optional curve condition to cold_cmp (+30 runs, about 5 h).
# Campaign names: PQID_CMP_COLD_CAMPAIGN, PQID_CMP_WARM_CAMPAIGN, PQID_CMP_WALLET_CAMPAIGN (default
# cold_cmp, warm_cmp, wallet_cmp); the analysis reads the names this window ran.
#
# Steps: marker check (always; a marker stops the window), inputs_check (holds results/v4/BUSY; a
# failure stops the window), then warm_cmp, wallet_cmp and cold_cmp inside ONE hold of
# results/v4/bench/RUNNING (`harness/v4/lib/markers.ts run`; the runners borrow it, so no other
# work can start between them), then analyze and check (no user name, host name or home path in
# results/v4/cmp). A failed timed step is recorded and the next step still runs (each runner
# guards its own preconditions); the analysis marks an incomplete series PARTIAL.
# Each step writes results/v4/cmp/logs/qw_cmp_<step>.log, scrubbed of paths, user and host names
# after the step exits (harness/v4/cmp/log_scrub.ts); the step list with exit codes and times goes
# to results/v4/cmp/logs/quiet_window_cmp.log.
#
# PQID_CMP_SMOKE=1: the smoke test of this script (not a result). It first moves the earlier smoke
# output aside (harness/v4/cmp/smoke_reset.ts), then runs inputs (--smoke, same v4 key environment
# as the window), inputs_check, warm_cmp, wallet_cmp and cold_cmp with --smoke inside ONE hold of
# results/v4/BUSY, then analyze and check; output and logs under results/v4/cmp/_smoke/.
# PQID_CMP_SMOKE_NO_MARKER=1 adds --smoke-no-marker (only the smoke lock, no BUSY; for agent tasks
# that may not write markers).
#
# Usage: bash scripts/cmp/quiet_window_cmp.sh [--from STEP]
#   STEP: inputs_check | warm_cmp | wallet_cmp | cold_cmp | analyze | check (not with PQID_CMP_SMOKE=1)
set -u
cd "$(dirname "$0")/../.."
SELF=scripts/cmp/quiet_window_cmp.sh
ORDER="inputs inputs_check warm_cmp wallet_cmp cold_cmp analyze check"

SMOKE=()
NOMARK=()
LOGDIR=results/v4/cmp/logs
CHECKROOT=results/v4/cmp
CHECKSKIP=(--skip _smoke)
if [ "${PQID_CMP_SMOKE:-0}" = "1" ]; then
  SMOKE=(--smoke)
  LOGDIR=results/v4/cmp/_smoke/logs
  CHECKROOT=results/v4/cmp/_smoke
  CHECKSKIP=(--skip 'old_*')
  [ "${PQID_CMP_SMOKE_NO_MARKER:-0}" = "1" ] && NOMARK=(--smoke-no-marker)
fi
LOG="$LOGDIR/quiet_window_cmp.log"

INNER=""
FROM="${PQID_CMP_FROM:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --inner) INNER="${2:-}"; shift 2 ;;
    --from) FROM="${2:-}"; shift 2 ;;
    *) echo "unknown argument $1 (usage: bash $SELF [--from STEP])" >&2; exit 2 ;;
  esac
done
if [ -n "$FROM" ]; then
  case " $ORDER " in *" $FROM "*) ;; *) echo "--from: unknown step $FROM (steps: $ORDER)" >&2; exit 2 ;; esac
  if [ ${#SMOKE[@]} -gt 0 ]; then echo "--from is not used with PQID_CMP_SMOKE=1: a smoke always starts fresh" >&2; exit 2; fi
fi

PY="${PQID_PYTHON:-python}"
V4=()
[ -n "${PQID_CMP_V4_ZKEY:-}" ] && V4+=(--v4-zkey "$PQID_CMP_V4_ZKEY")
[ -n "${PQID_CMP_V4_VKEY:-}" ] && V4+=(--v4-vkey "$PQID_CMP_V4_VKEY")
[ -n "${PQID_CMP_V4_LABEL:-}" ] && V4+=(--v4-key-label "$PQID_CMP_V4_LABEL")
[ -n "${PQID_CMP_V4_PINS:-}" ] && V4+=(--v4-pins "$PQID_CMP_V4_PINS")
DEV=()
[ "${PQID_CMP_ALLOW_DEV_KEY:-0}" = "1" ] && DEV=(--allow-dev-key)
CONDS="v2,v2o2,v3,v4,eddsa"
[ "${PQID_CMP_WITH_CURVE:-0}" = "1" ] && CONDS="$CONDS,curve"
COLD_C="${PQID_CMP_COLD_CAMPAIGN:-cold_cmp}"
WARM_C="${PQID_CMP_WARM_CAMPAIGN:-warm_cmp}"
WALLET_C="${PQID_CMP_WALLET_CAMPAIGN:-wallet_cmp}"

stamp() { date -u "+%Y-%m-%dT%H:%M:%SZ"; }
log() { echo "$*" >> "$LOG"; }
idx() { local i=0 s; for s in $ORDER; do [ "$s" = "$1" ] && { echo $i; return; }; i=$((i + 1)); done; echo 99; }
want() { [ -z "$FROM" ] || [ "$(idx "$1")" -ge "$(idx "$FROM")" ]; }
scrub() { node --import tsx harness/v4/cmp/log_scrub.ts scrub "$@" >> "$LOG" 2>&1; }

RC=0
FAILED=""
step() {
  local name="$1"; shift
  if ! want "$name"; then log "skip $name (--from $FROM)"; RC=0; return 0; fi
  log "== $(stamp) start $name: $*"
  "$@" > "$LOGDIR/qw_cmp_${name}.log" 2>&1
  RC=$?
  # scrub after the step exits, so no extra process runs next to a timed run
  scrub "$LOGDIR/qw_cmp_${name}.log"
  log "   $(stamp) end $name exit $RC"
  [ "$RC" != 0 ] && FAILED="$FAILED $name"
  return 0
}

# ---------------------------------------------------------------- inner phases (inside one marker hold)
if [ -n "$INNER" ]; then
  case "$INNER" in
    smoke)
      step inputs       node --import tsx harness/v4/cmp/inputs.ts --smoke ${NOMARK[@]+"${NOMARK[@]}"} ${V4[@]+"${V4[@]}"}
      if [ "$RC" != 0 ]; then log "# smoke inputs failed (exit $RC): smoke stopped $(stamp)"; exit 1; fi
      step inputs_check node --import tsx harness/v4/cmp/inputs.ts --check --smoke ${NOMARK[@]+"${NOMARK[@]}"} ${V4[@]+"${V4[@]}"}
      if [ "$RC" != 0 ]; then log "# smoke inputs check failed (exit $RC): smoke stopped $(stamp)"; exit 1; fi
      ;;
    timed) ;;
    *) echo "unknown inner phase $INNER" >&2; exit 2 ;;
  esac
  step warm_cmp   node --import tsx harness/v4/cmp/warm.ts --campaign "$WARM_C" ${SMOKE[@]+"${SMOKE[@]}"} ${NOMARK[@]+"${NOMARK[@]}"} ${V4[@]+"${V4[@]}"} ${DEV[@]+"${DEV[@]}"}
  step wallet_cmp node --import tsx harness/v4/cmp/cold.ts --kind wallet --campaign "$WALLET_C" ${SMOKE[@]+"${SMOKE[@]}"} ${NOMARK[@]+"${NOMARK[@]}"}
  step cold_cmp   node --import tsx harness/v4/cmp/cold.ts --kind prove --campaign "$COLD_C" --conditions "$CONDS" ${SMOKE[@]+"${SMOKE[@]}"} ${NOMARK[@]+"${NOMARK[@]}"} ${V4[@]+"${V4[@]}"} ${DEV[@]+"${DEV[@]}"}
  if [ -n "$FAILED" ]; then log "# inner phase $INNER: failed steps:$FAILED"; exit 1; fi
  exit 0
fi

# ---------------------------------------------------------------- outer
# fail fast: without a v4 key the warm and cold runners refuse (D-034), and the wallet step alone
# would take the window's first 3.5 h
if [ ${#SMOKE[@]} -eq 0 ] && [ ${#V4[@]} -eq 0 ] && [ ${#DEV[@]} -eq 0 ]; then
  mkdir -p "$LOGDIR"
  log "# $(stamp) no v4 key given (PQID_CMP_V4_ZKEY, _VKEY, _LABEL, _PINS) and PQID_CMP_ALLOW_DEV_KEY is not 1: window stopped"
  echo "no v4 key given and PQID_CMP_ALLOW_DEV_KEY is not 1: window stopped" >&2
  exit 1
fi

RESET_OUT=""
if [ ${#SMOKE[@]} -gt 0 ]; then
  # a smoke always starts fresh: earlier smoke output (and its logs) moves to _smoke/old_<stamp>/
  RESET_OUT=$(node --import tsx harness/v4/cmp/smoke_reset.ts ${NOMARK[@]+"${NOMARK[@]}"} 2>&1)
  RESET_RC=$?
  mkdir -p "$LOGDIR"
  echo "$RESET_OUT" > "$LOGDIR/qw_cmp_smoke_reset.log"
  scrub "$LOGDIR/qw_cmp_smoke_reset.log"
  if [ "$RESET_RC" != 0 ]; then log "# $(stamp) smoke reset failed (exit $RESET_RC): smoke stopped"; exit 1; fi
fi
mkdir -p "$LOGDIR"
# logs of an interrupted earlier window are scrubbed before anything else
for f in "$LOGDIR"/qw_cmp_*.log; do [ -e "$f" ] && scrub "$f"; done

log "# cmp quiet window started $(stamp)${SMOKE[@]+ (smoke)}${FROM:+ from $FROM}"
# marker check: always runs, also with --from
log "== $(stamp) start markers (always run)"
node --import tsx harness/v4/lib/markers.ts status > "$LOGDIR/qw_cmp_markers.log" 2>&1
RC=$?
scrub "$LOGDIR/qw_cmp_markers.log"
log "   $(stamp) end markers exit $RC"
if [ "$RC" != 0 ]; then
  log "# a RUNNING or BUSY marker exists or the check failed (exit $RC): window stopped $(stamp)"
  exit 1
fi

# The wrapper spawns bash by its absolute path (markers.ts refuses the WSL bash launcher).
BASH_EXE="$BASH"
command -v cygpath > /dev/null 2>&1 && BASH_EXE="$(cygpath -w "$BASH")"
export PQID_CMP_FROM="$FROM"

if [ ${#SMOKE[@]} -gt 0 ]; then
  if [ ${#NOMARK[@]} -gt 0 ]; then
    log "== $(stamp) start smoke steps (inputs, inputs_check, warm_cmp, wallet_cmp, cold_cmp) without a marker (--smoke-no-marker)"
    bash "$SELF" --inner smoke >> "$LOG" 2>&1
  else
    log "== $(stamp) start smoke steps (inputs, inputs_check, warm_cmp, wallet_cmp, cold_cmp) inside one hold of results/v4/BUSY"
    node --import tsx harness/v4/lib/markers.ts run --kind BUSY --campaign cmp_smoke_window --runner "$SELF" --note "cmp smoke test (untimed)" -- "$BASH_EXE" "$SELF" --inner smoke >> "$LOG" 2>&1
  fi
  WRC=$?
  log "   $(stamp) end smoke steps exit $WRC"
  [ "$WRC" != 0 ] && FAILED="$FAILED smoke_steps"
else
  step inputs_check node --import tsx harness/v4/cmp/inputs.ts --check ${V4[@]+"${V4[@]}"}
  if [ "$RC" != 0 ]; then
    log "# inputs check failed (exit $RC): window stopped $(stamp)"
    exit 1
  fi
  if want warm_cmp || want wallet_cmp || want cold_cmp; then
    log "== $(stamp) start timed steps inside one hold of results/v4/bench/RUNNING (warm_cmp, wallet_cmp, cold_cmp)"
    node --import tsx harness/v4/lib/markers.ts run --kind RUNNING --campaign cmp_window --runner "$SELF" --note "cmp quiet window (warm_cmp, wallet_cmp, cold_cmp)" -- "$BASH_EXE" "$SELF" --inner timed >> "$LOG" 2>&1
    WRC=$?
    log "   $(stamp) end timed steps exit $WRC"
    if [ "$WRC" = 3 ] || [ "$WRC" = 2 ] || [ "$WRC" = 127 ]; then
      log "# the RUNNING hold could not be taken or the inner script not started (exit $WRC): window stopped $(stamp)"
      exit 1
    fi
    [ "$WRC" != 0 ] && FAILED="$FAILED timed_steps"
  fi
fi

step analyze "$PY" scripts/cmp/analyze_cmp.py ${SMOKE[@]+"${SMOKE[@]}"} --cold "$COLD_C" --warm "$WARM_C" --wallet "$WALLET_C"
step check   node --import tsx harness/v4/cmp/log_scrub.ts check "$CHECKROOT" "${CHECKSKIP[@]}"
if [ "$RC" != 0 ] && want check; then log "# user name, host name or home path found under $CHECKROOT (see qw_cmp_check.log): fix before committing"; fi
if [ -n "$FAILED" ]; then
  log "# cmp quiet window finished $(stamp) with failed steps:$FAILED"
  echo "failed:$FAILED" > "$LOGDIR/quiet_window_cmp.DONE"
  exit 1
fi
log "# cmp quiet window finished $(stamp)"
echo "ok" > "$LOGDIR/quiet_window_cmp.DONE"
