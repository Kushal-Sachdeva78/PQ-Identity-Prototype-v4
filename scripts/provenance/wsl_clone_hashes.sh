#!/usr/bin/env bash
# Read-only: sha256 of the WSL clone's bench campaign files (cold_rs_wsl, warm_wsl), the input of
# the byte-for-byte copy check in scripts/provenance/audit.py (results/v4/bench_wsl holds copies
# of these files). Run inside WSL, operated from the Windows side, for example from Git Bash:
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash /mnt/c/<repo>/scripts/provenance/wsl_clone_hashes.sh
# The clone is ~/pqid-v4 unless PQID_WSL_CLONE names another folder. Nothing in the clone is
# written (sha256sum, git rev-parse with GIT_OPTIONAL_LOCKS=0). Output:
# results/v4/provenance/wsl_clone_bench_sha256.txt of the repository that holds this script
# (through its /mnt/c path). Paths in the output are relative to the clone root; no user name,
# host name or home path is written.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CLONE="${PQID_WSL_CLONE:-$HOME/pqid-v4}"
OUT="$REPO/results/v4/provenance/wsl_clone_bench_sha256.txt"
export GIT_OPTIONAL_LOCKS=0
cd "$CLONE"
mkdir -p "$(dirname "$OUT")"
{
  echo "# sha256 of the WSL clone's bench campaign files (read-only); paths relative to the clone root"
  echo "# clone HEAD $(git rev-parse HEAD)"
  echo "# read $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for d in results/v4/bench/cold_rs_wsl results/v4/bench/warm_wsl; do
    if [ -d "$d" ]; then
      find "$d" -maxdepth 1 -type f -print0 | sort -z | xargs -0 -r sha256sum
    else
      echo "# missing $d"
    fi
  done
} > "$OUT.tmp"
mv "$OUT.tmp" "$OUT"
echo "wrote results/v4/provenance/wsl_clone_bench_sha256.txt ($(grep -vc '^#' "$OUT") files)"
