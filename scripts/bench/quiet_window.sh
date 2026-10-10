#!/usr/bin/env bash
# Unattended quiet window (TASKS D, E2, E3, E4): every timed measurement, one after another,
# in the order of docs/v4/BENCH_PROTOCOL.md and PLAN.md. Start it only after the B7 freeze,
# with nothing else running (no tests, builds, agents or campaigns). Each step writes
# verification/v4/qw_<step>.log; the step list with exit codes and times goes to
# verification/v4/quiet_window.log. A failed step is recorded and the next step still runs
# (each runner guards its own preconditions). While a bench runner holds
# results/v4/bench/RUNNING, other work must be limited to editing files (docs/BENCHMARK_POLICY.md).
#
# Usage: bash scripts/bench/quiet_window.sh [--from STEP]
set -u
cd "$(dirname "$0")/../.."
LOG=verification/v4/quiet_window.log
FROM="${2:-}"
[ "${1:-}" = "--from" ] || FROM=""
started=0
[ -z "$FROM" ] && started=1
PY="${PQID_PYTHON:-python}"
stamp() { date -u "+%Y-%m-%dT%H:%M:%SZ"; }
step() {
  local name="$1"; shift
  if [ "$started" = 0 ]; then
    [ "$name" = "$FROM" ] && started=1 || { echo "skip $name" >> "$LOG"; return 0; }
  fi
  echo "== $(stamp) start $name: $*" >> "$LOG"
  "$@" > "verification/v4/qw_${name}.log" 2>&1
  local rc=$?
  echo "   $(stamp) end $name exit $rc" >> "$LOG"
  return 0
}
echo "# quiet window started $(stamp)" >> "$LOG"
step inputs        node --import tsx harness/v4/bench/inputs.ts
step inputs_check  node --import tsx harness/v4/bench/inputs.ts --check
step warm          node --import tsx harness/v4/bench/warm.ts --campaign warm --versions v2,v3,v4 --provers snarkjs,rapidsnark
step cold_v4       node --import tsx harness/v4/bench/cold_campaign.ts --campaign cold_v4 --versions v4 --provers snarkjs,rapidsnark
step e2_baselines  node --import tsx harness/v4/baselines_measure.ts
step e3_timing     node --import tsx harness/v4/privacy.ts --timing
step e4_trees      node --import tsx harness/v4/scale.ts trees
step e4_anchor     node --import tsx harness/v4/scale.ts anchor
step e4_verifier   node --import tsx harness/v4/scale.ts verifier --no-pin
step besu_up       bash -c "bash scripts/besu/setup_qbft.sh clean && bash scripts/besu/setup_qbft.sh up"
step e4_besu       node --import tsx harness/v4/scale.ts besu
step besu_down     bash scripts/besu/setup_qbft.sh clean
step cold_v2v3     node --import tsx harness/v4/bench/cold_campaign.ts --campaign cold_v2v3 --versions v2,v3 --provers snarkjs,rapidsnark
step analyze       "$PY" scripts/bench/analyze.py
echo "# quiet window finished $(stamp)" >> "$LOG"
touch verification/v4/quiet_window.DONE
