#!/usr/bin/env bash
# Ceremony follow-up (TASKS I; docs/v4/CEREMONY_FOLLOWUP.md). Run from Git Bash on the Windows
# host, from any folder; it changes to the repository root. Driver:
# harness/v4/ceremony/followup.ts (this script only checks the basics and passes the arguments on).
#
# After Kushal's ceremony (ceremony/HANDOFF_STEPS.md steps 1 to 5 done, ceremony/v4/final/ present):
# 1. Check only (first; verify and key checks on the ceremony outputs, writes only under
#    results/v4/ceremony/_smoke/, holds results/v4/BUSY, a few minutes; not a result):
#      bash scripts/ceremony/followup.sh --check-only --external <index[,index]>
# 2. Real run (the follow-up code committed; ports 8800 to 8899 are recorded in DECISIONS D-041):
#      bash scripts/ceremony/followup.sh --external <index[,index]>
#    --external   1-based index(es) of the contributions made by people outside the project on
#                 their own computers (the coordinator's declaration; the transcript cannot show it)
#    Steps: verify, keys, install, suite, mutation. Holds results/v4/BUSY for the whole run
#    (about 1 h 40 min [S]: dev suite run 10 took 148 s, dev mutation campaign 5 took 91 min).
#    Writes results/v4/ceremony/followup_<date>/, verification/v4/ceremony_followup_<date>/,
#    setup/out/v4/*_ceremony.*, setup/pins_v4_ceremony.json, setup/key_spec_v4_ceremony.json,
#    and the gitignored mutants under circuits/build/v4/mutants/ (shared with campaign 5).
#
# Dry run on the rehearsal outputs (run `node ceremony/rehearse.mjs` first if
# ceremony/rehearsal/_out/ is missing); results only under results/v4/ceremony/_smoke/:
#   bash scripts/ceremony/followup.sh --dry-run                                  (seconds, no marker)
#   bash scripts/ceremony/followup.sh --dry-run --steps suite                    (about 3 min, holds BUSY)
#   bash scripts/ceremony/followup.sh --dry-run --steps suite,mutation --only governance   (about 6 min, holds BUSY)
#
# Other options: --final-dir <dir> (default ceremony/v4/final), --steps <list>, --only <kind[:name],...>,
# --jobs <1-4> (default 2), --baseline <suite json> (mutation without the suite step),
# --date YYYY-MM-DD, --allow-uncommitted (recorded), --owner <label for the marker>.
#
# Post-fix rerun with the dev key (D-034: a packages/v4 fix of a fuzz-found defect gets the
# security suite and the mutation campaign again before any timed series). Skips verify, keys
# and install; uses the pinned dev key without the rekey loader; ports 8800 and 8801+; compares
# with dev run 10 and campaign 5 (any difference is REVIEW). Refuses uncommitted code (no
# override). Writes results/v4/fixcheck/<date>[_rN]/ and verification/v4/fixcheck_<date>[_rN]/:
#   bash scripts/ceremony/followup.sh --dev-rerun --dry-run   (preflight and key probe, seconds, writes nothing)
#   bash scripts/ceremony/followup.sh --dev-rerun             (holds results/v4/BUSY, about 1 h 35 min [S])
#   options (no others; a misspelt or valued --dry-run is a usage error): --steps suite|mutation|suite,mutation,
#   --only <kind[:name],...> (mutation step only), --jobs, --date (within a day of today, UTC), --owner,
#   --baseline results/v4/fixcheck/<run>/suite/security_suite.json (with --steps mutation only; that run's
#   suite step must have passed on the same code). Only both steps with every defence complete D-034.
#
# Exit codes: 0 pass, 1 fail, 2 usage, 3 refused before the start (marker, uncommitted code, busy
# port, an install conflict; nothing written; for --dev-rerun --dry-run: the real rerun would
# refuse), 4 stopped after the start (a refusal during the run; the run folder, logs and possibly
# installed files exist), 5 review.
set -u
cd "$(dirname "$0")/../.." || exit 2

case "${1:-}" in
  -h|--help)
    sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac

[ -f docs/v4/BENCH_PROTOCOL.md ] && [ -f harness/v4/ceremony/followup.ts ] || { echo "followup.sh: not a PQ-Identity-v4 repository" >&2; exit 2; }
command -v node >/dev/null 2>&1 || { echo "followup.sh: node not found on PATH" >&2; exit 2; }
[ -d node_modules/tsx ] && [ -d node_modules/snarkjs ] || { echo "followup.sh: node_modules missing (npm ci)" >&2; exit 2; }

# The post-fix rerun logs to fixcheck.log; its dry run reports whether the real rerun would start.
devrerun=0
dryrun=0
for a in "$@"; do
  case "$a" in
    --dev-rerun) devrerun=1 ;;
    --dry-run) dryrun=1 ;;
  esac
done
mainlog=followup.log
[ "$devrerun" = 1 ] && mainlog=fixcheck.log

echo "followup.sh: node $(node --version), repository root $(basename "$PWD"), $(date -u +%Y-%m-%dT%H:%M:%SZ)"
node --import tsx harness/v4/ceremony/followup.ts "$@"
rc=$?
if [ "$devrerun" = 1 ] && [ "$dryrun" = 1 ] && { [ $rc -eq 0 ] || [ $rc -eq 3 ]; }; then
  if [ $rc -eq 0 ]; then
    echo "followup.sh: DRY RUN OK: the real post-fix rerun would start now (preflight and key probe only; nothing written; not a result)"
  else
    echo "followup.sh: DRY RUN: the real post-fix rerun would refuse now (reasons above; nothing written)"
  fi
  exit $rc
fi
case $rc in
  0) echo "followup.sh: PASS" ;;
  5) echo "followup.sh: REVIEW (finished; see the warnings and vs_dev.json in the run folder)" ;;
  3) echo "followup.sh: REFUSED before the start (nothing written)" ;;
  4) echo "followup.sh: STOPPED after the start (see $mainlog in the log folder; the run folder and possibly installed files exist)" ;;
  2) echo "followup.sh: USAGE" ;;
  *) echo "followup.sh: FAIL (exit $rc)" ;;
esac
exit $rc
