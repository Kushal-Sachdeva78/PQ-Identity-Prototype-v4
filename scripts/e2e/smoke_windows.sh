#!/usr/bin/env bash
# Windows smoke test of the end-to-end harness (docs/v4/E2E.md section 14): checks the runner,
# never a result. Git Bash, repository root, Anvil only (tools/foundry/anvil.exe on the D-034 port
# 8790), dev key. Cold n 1 and warm 1 + 2 blocks by default; output under results/v4/e2e/_smoke/
# (gitignored, never quoted); no marker held, refuses while results/v4/bench/RUNNING or
# results/v4/BUSY exists. Then the smoke analysis.
#
# Usage: bash scripts/e2e/smoke_windows.sh [--cold-n N] [--warm-n N] [--keep]
#   --keep: keep earlier smoke output of the same campaign names (default: replace it)
set -u
cd "$(dirname "$0")/../.." || exit 2
COLD_N=1; WARM_N=2; KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --cold-n) COLD_N="$2"; shift 2 ;;
    --warm-n) WARM_N="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    *) echo "smoke_windows: unknown option $1" >&2; exit 2 ;;
  esac
done
PY="${PQID_PYTHON:-python}"
SMOKE_ROOT=results/v4/e2e/_smoke
if [ "$KEEP" = 0 ]; then rm -rf "$SMOKE_ROOT/e2e_cold_win" "$SMOKE_ROOT/e2e_warm_win" "$SMOKE_ROOT/summary.json" "$SMOKE_ROOT/summary.md"; fi
RC=0
node --import tsx harness/v4/e2e/campaign.ts --smoke --mode cold --campaign e2e_cold_win --endpoints anvil --n "$COLD_N" || RC=1
node --import tsx harness/v4/e2e/campaign.ts --smoke --mode warm --campaign e2e_warm_win --endpoints anvil --n "$WARM_N" || RC=1
"$PY" scripts/e2e/analyze_e2e.py --smoke || RC=1
echo "smoke_windows: exit $RC (smoke output is never quoted)"
exit "$RC"
