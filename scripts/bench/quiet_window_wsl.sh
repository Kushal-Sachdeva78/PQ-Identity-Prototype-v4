#!/usr/bin/env bash
# Second quiet window (TASKS D, DECISIONS D-031): the rapidsnark series inside WSL2 Ubuntu on
# the same laptop. Run from the WSL clone (~/pqid-v4) with PQID_RAPIDSNARK set, nothing else
# running. Campaigns (docs/v4/BENCH_PROTOCOL.md, Deviations, 2026-09-29):
#   warm_wsl     v2, v3, v4 x snarkJS, rapidsnark, interleaved blocks (same-environment speedups)
#   cold_rs_wsl  v2, v3, v4 x rapidsnark, 30 cold runs each after the fixed 600 s idle
# Each step writes verification/v4/qw2_<step>.log; the step list with exit codes and times goes
# to verification/v4/quiet_window_wsl.log; verification/v4/quiet_window_wsl.DONE marks the end.
# The campaign folders are then moved to results/v4/bench_wsl/ in the Windows repository and
# analysed there on their own (scripts/bench/analyze.py --root results/v4/bench_wsl).
#
# Usage (inside WSL): bash scripts/bench/quiet_window_wsl.sh [--from STEP]
set -u
cd "$(dirname "$0")/../.."
LOG=verification/v4/quiet_window_wsl.log
FROM="${2:-}"
[ "${1:-}" = "--from" ] || FROM=""
started=0
[ -z "$FROM" ] && started=1
: "${PQID_RAPIDSNARK:?set PQID_RAPIDSNARK to the rapidsnark prover binary}"
stamp() { date -u "+%Y-%m-%dT%H:%M:%SZ"; }
step() {
  local name="$1"; shift
  if [ "$started" = 0 ]; then
    [ "$name" = "$FROM" ] && started=1 || { echo "skip $name" >> "$LOG"; return 0; }
  fi
  echo "== $(stamp) start $name: $*" >> "$LOG"
  "$@" > "verification/v4/qw2_${name}.log" 2>&1
  local rc=$?
  echo "   $(stamp) end $name exit $rc" >> "$LOG"
  return 0
}
echo "# quiet window (WSL) started $(stamp)" >> "$LOG"
step inputs_check  node --import tsx harness/v4/bench/inputs.ts --check
step warm_wsl      node --import tsx harness/v4/bench/warm.ts --campaign warm_wsl --versions v2,v3,v4 --provers snarkjs,rapidsnark
step cold_rs_wsl   node --import tsx harness/v4/bench/cold_campaign.ts --campaign cold_rs_wsl --versions v2,v3,v4 --provers rapidsnark
echo "# quiet window (WSL) finished $(stamp)" >> "$LOG"
touch verification/v4/quiet_window_wsl.DONE
