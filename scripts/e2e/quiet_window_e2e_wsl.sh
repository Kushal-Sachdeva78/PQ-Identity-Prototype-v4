#!/usr/bin/env bash
# End-to-end presentation series in WSL2: the quiet window of docs/v4/E2E.md ("Commands"),
# DECISIONS D-034 conventions.
#
# Usage, from Git Bash on Windows (the operator's one call into WSL; v4 code never calls wsl.exe):
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash /mnt/c/<repo>/scripts/e2e/quiet_window_e2e_wsl.sh \
#       --confirm-quiet --key-spec <repo-relative key spec> [--from STEP] [--cold-only | --warm-only]
#   ... --allow-dev-key instead of --key-spec: a run labelled "dev key" (D-034 runs this series
#       after the key ceremony; a dev-key run is repeated with the ceremony key)
#   ... --smoke [--with-besu]: tiny n, no marker (refuses while one exists), output under
#       results/v4/e2e/_smoke/ (gitignored, never quoted)
#   other options: --prover rapidsnark (needs PQID_RAPIDSNARK; then name the campaigns with
#       --cold-campaign e2e_cold_wsl_rs and so on), --anvil-only, --windows-repo <the /mnt/c path>
#   --from warm: only the warm campaign (Besu is reset and started again); the cold folder is not
#       copied again.
#   --replace-copy: a campaign folder that already exists in the Windows repository (a resumed cold
#       campaign) is updated, after a check that the clone's copy only appends to it (jsonl and
#       log files extended, schedule.json unchanged, env.json with the same stable part and more
#       sessions). Without it such a folder is reported and left as it is.
#   --copy-only [--window-stamp STAMP] [--replace-copy]: only the copy step (no Besu, no campaign,
#       no marker); refuses while RUNNING or BUSY exists.
#
# - Runs in the Linux clone (~/pqid-v4, or PQID_WSL_CLONE) with the D-034 toolchain: Node 24.21.0 by
#   its absolute nvm path (PQID_NODE overrides), Anvil 1.5.1 from ~/pqid-tools/anvil-1.5.1 (the
#   pqid-v4 Docker image's binary), Besu 26.9.0 on Linux JDK 25 (scripts/wsl/besu_wsl_setup.sh).
# - The clone must be at the Windows repository's commit, and the e2e code and the code it runs must
#   be byte-identical in both; otherwise the driver refuses.
# - Real window: re-runs itself under `harness/v4/lib/markers.ts run`, which holds
#   results/v4/bench/RUNNING in the Windows repository (through its /mnt/c path) and in the clone
#   for the whole window; the two campaigns use that hold. Nothing else may run on Windows during
#   the window (the WSL quiet check cannot see Windows load).
# - Steps: besu_reset, besu_up (scripts/besu/setup_qbft.sh clean + up), cold (campaign.ts --mode
#   cold), warm (campaign.ts --mode warm), besu_clean, then copy_back: the campaign folders and the
#   window logs go to the same paths in the Windows repository with a sha256 manifest; an existing
#   folder there is never overwritten (smoke output is replaced); an identical folder counts as
#   copied; a resumed campaign is updated only with --replace-copy after the append-only check.
# - Logs: results/v4/e2e/logs/<window stamp>/ (steps.log and one log per step), scrubbed of user
#   name, host name and home paths.
set -u

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
SCRIPT_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLONE="${PQID_WSL_CLONE:-$HOME/pqid-v4}"
EXPECT_NODE="24.21.0"
EXPECT_ANVIL="1.5.1"
NODE="${PQID_NODE:-$HOME/.nvm/versions/node/v$EXPECT_NODE/bin/node}"
ANVIL="$HOME/pqid-tools/anvil-$EXPECT_ANVIL/anvil"
BESU_HOME_D034="$HOME/pqid-tools/besu/besu-26.9.0"

CONFIRM=0; SMOKE=0; WITH_BESU=0; ANVIL_ONLY=0; COLD=1; WARM=1; FROM=""; WIN=""; KEYSPEC=""; DEVKEY=0; PROVER="snarkjs"
REPLACE_COPY=0; COPY_ONLY=0
COLD_CAMPAIGN="e2e_cold_wsl"; WARM_CAMPAIGN="e2e_warm_wsl"; STAMP=""
ORIG_ARGS=("$@")
while [ $# -gt 0 ]; do
  case "$1" in
    --confirm-quiet) CONFIRM=1; shift ;;
    --smoke) SMOKE=1; shift ;;
    --with-besu) WITH_BESU=1; shift ;;
    --anvil-only) ANVIL_ONLY=1; shift ;;
    --cold-only) WARM=0; shift ;;
    --warm-only) COLD=0; shift ;;
    --from) FROM="$2"; shift 2 ;;
    --windows-repo) WIN="$2"; shift 2 ;;
    --key-spec) KEYSPEC="$2"; shift 2 ;;
    --allow-dev-key) DEVKEY=1; shift ;;
    --prover) PROVER="$2"; shift 2 ;;
    --cold-campaign) COLD_CAMPAIGN="$2"; shift 2 ;;
    --warm-campaign) WARM_CAMPAIGN="$2"; shift 2 ;;
    --window-stamp) STAMP="$2"; shift 2 ;;
    --replace-copy) REPLACE_COPY=1; shift ;;
    --copy-only) COPY_ONLY=1; shift ;;
    *) echo "quiet_window_e2e_wsl: unknown option $1" >&2; exit 2 ;;
  esac
done
die() { echo "quiet_window_e2e_wsl: $*" >&2; exit 2; }
for c in "$COLD_CAMPAIGN" "$WARM_CAMPAIGN"; do echo "$c" | grep -Eq '^[a-z][a-z0-9_]{0,39}$' || die "campaign names must match ^[a-z][a-z0-9_]{0,39}$"; done
case "$FROM" in ""|cold) ;; warm) COLD=0 ;; *) die "--from takes cold or warm (Besu is always reset and started first when it is used)" ;; esac
[ "$COPY_ONLY" = 1 ] || [ "$SMOKE" = 1 ] || [ "$CONFIRM" = 1 ] || die "a real window needs --confirm-quiet (AC power, sleep and Windows Update off, every Windows application closed, nothing else running on Windows or in WSL)"
[ "$COPY_ONLY" = 1 ] || [ "$SMOKE" = 1 ] || [ -n "$KEYSPEC" ] || [ "$DEVKEY" = 1 ] || die "pass --key-spec <ceremony key spec> (D-034) or --allow-dev-key"
[ "$PROVER" = snarkjs ] || [ "$PROVER" = rapidsnark ] || die "--prover snarkjs|rapidsnark"
grep -qi microsoft /proc/version 2>/dev/null || die "run inside WSL2"
if [ -z "$WIN" ]; then
  case "$SCRIPT_REPO" in /mnt/*) WIN="$SCRIPT_REPO" ;; *) die "call this script through the Windows repository's /mnt/<drive>/ path or pass --windows-repo" ;; esac
fi
[ -f "$WIN/docs/v4/E2E.md" ] || die "the Windows repository has no docs/v4/E2E.md"
[ -d "$CLONE/.git" ] || die "no clone at ~/pqid-v4 (set PQID_WSL_CLONE)"
cd "$CLONE" || die "cannot enter the clone"

if [ "$COPY_ONLY" = 1 ]; then
  for m in "$WIN/results/v4/bench/RUNNING" "$WIN/results/v4/BUSY" "$CLONE/results/v4/bench/RUNNING" "$CLONE/results/v4/BUSY"; do
    [ -e "$m" ] && die "--copy-only: a marker exists ($m); copy after the timed run or heavy work ends"
  done
fi

USE_BESU=0; ENDPOINTS="anvil"; CLONE_HEAD="unknown"
if [ "$COPY_ONLY" = 0 ]; then
  # ------------------------------------------------------------------ toolchain (D-034)
  [ -x "$NODE" ] || die "Node $EXPECT_NODE not found at ~/.nvm/versions/node/v$EXPECT_NODE (set PQID_NODE)"
  [ "$("$NODE" --version)" = "v$EXPECT_NODE" ] || die "Node is $("$NODE" --version), D-034 fixes v$EXPECT_NODE"
  [ -x "$ANVIL" ] || die "no ~/pqid-tools/anvil-$EXPECT_ANVIL/anvil (run scripts/wsl/besu_wsl_setup.sh)"
  "$ANVIL" --version | grep -q "Version: $EXPECT_ANVIL-" || die "~/pqid-tools/anvil-$EXPECT_ANVIL/anvil does not report $EXPECT_ANVIL"
  USE_BESU=1
  if [ "$ANVIL_ONLY" = 1 ] || { [ "$SMOKE" = 1 ] && [ "$WITH_BESU" = 0 ]; }; then USE_BESU=0; fi
  if [ "$USE_BESU" = 1 ]; then
    [ -x "$BESU_HOME_D034/bin/besu" ] || die "Besu 26.9.0 missing (run scripts/wsl/besu_wsl_setup.sh)"
    JDK="$(ls -d "$HOME"/pqid-tools/jdk25/jdk-25* 2>/dev/null | head -1)"
    [ -n "$JDK" ] && [ -x "$JDK/bin/java" ] || die "JDK 25 missing (run scripts/wsl/besu_wsl_setup.sh)"
    export JAVA_HOME="$JDK" PQID_BESU_HOME="$BESU_HOME_D034"
    ENDPOINTS="anvil,besu"
  else
    ENDPOINTS="anvil"
  fi
  if [ "$PROVER" = rapidsnark ]; then
    [ -n "${PQID_RAPIDSNARK:-}" ] && [ -x "$PQID_RAPIDSNARK" ] || die "--prover rapidsnark needs PQID_RAPIDSNARK (the native prover binary)"
  fi

  # ------------------------------------------------------------------ the clone runs the committed code
  export GIT_OPTIONAL_LOCKS=0
  CLONE_HEAD="$(git rev-parse HEAD)"
  WIN_HEAD="$(git -C "$WIN" rev-parse HEAD 2>/dev/null || echo unknown)"
  [ "$CLONE_HEAD" = "$WIN_HEAD" ] || die "clone HEAD $CLONE_HEAD differs from the Windows repository's $WIN_HEAD (fast-forward the clone first)"
  manifest() { # sha256 of the e2e code and the code it runs, relative paths
    ( cd "$1" && sha256sum harness/v4/e2e/*.ts harness/v4/lib/*.ts harness/v4/bench/lib.ts harness/v4/bench/guard.ts \
        scripts/e2e/*.sh scripts/e2e/*.py docs/v4/E2E.md scripts/besu/setup_qbft.sh packages/v4/src/*.ts \
        onchain/contracts/v4/RegistriesV4.sol 2>&1 )
  }
  [ "$(manifest "$CLONE")" = "$(manifest "$WIN")" ] || die "the e2e code differs between the clone and the Windows repository"
fi

# ------------------------------------------------------------------ markers (D-034)
STAMP_GIVEN=1; [ -n "$STAMP" ] || { STAMP="$(date -u +%Y%m%dT%H%M%SZ)"; STAMP_GIVEN=0; }
if [ "$SMOKE" = 0 ] && [ "$COPY_ONLY" = 0 ] && [ -z "${PQID_MARKER_TOKEN:-}" ]; then
  exec "$NODE" --import tsx harness/v4/lib/markers.ts run --kind RUNNING --campaign e2e_wsl_window \
    --runner scripts/e2e/quiet_window_e2e_wsl.sh --owner "operator" --note "end-to-end WSL window $STAMP" \
    --windows-repo "$WIN" -- "$BASH" "$SELF" "${ORIG_ARGS[@]}" --windows-repo "$WIN" --window-stamp "$STAMP"
fi

if [ "$SMOKE" = 1 ]; then OUTROOT="results/v4/e2e/_smoke"; else OUTROOT="results/v4/e2e"; fi
LOGS="$OUTROOT/logs/$STAMP"
[ "$COPY_ONLY" = 1 ] || mkdir -p "$LOGS"
STEPS="$LOGS/steps.log"
stamp() { date -u "+%Y-%m-%dT%H:%M:%SZ"; }
scrub() { # logs carry no user name, host name or home path
  python3 - "$1" "$HOME" "$CLONE" "$WIN" "$(id -un)" "$(hostname)" <<'PY'
import sys
f, home, clone, win, user, host = sys.argv[1:7]
subs = [(clone, "<clone>"), (win, "<repo>"), (home, "~"), (user, "<user>"), (host, "<host>")]
t = open(f, encoding="utf8", errors="replace").read()
for a, b in sorted(subs, key=lambda x: -len(x[0])):
    if len(a) >= 3:
        t = t.replace(a, b)
open(f, "w", encoding="utf8").write(t)
PY
}
started=1; [ -n "$FROM" ] && started=0
FAILED=0
run_step() { # run_step <name> <command...> (never skipped)
  local name="$1"; shift
  echo "== $(stamp) start $name" >> "$STEPS"
  "$@" > "$LOGS/$name.log" 2>&1
  local rc=$?
  scrub "$LOGS/$name.log"
  echo "   $(stamp) end $name exit $rc" >> "$STEPS"
  return $rc
}
step() { # step <name> <command...> (skipped before the --from step)
  local name="$1"; shift
  if [ "$started" = 0 ]; then
    if [ "$name" = "$FROM" ]; then started=1; else echo "skip $name" >> "$STEPS"; return 0; fi
  fi
  run_step "$name" "$@"
}

RUN=("$NODE" --import tsx harness/v4/e2e/campaign.ts --endpoints "$ENDPOINTS" --windows-repo "$WIN"
     --anvil-bin "$ANVIL" --expect-anvil "$EXPECT_ANVIL" --expect-node "$EXPECT_NODE" --prover "$PROVER")
[ -n "$KEYSPEC" ] && RUN+=(--key-spec "$KEYSPEC")
[ "$DEVKEY" = 1 ] && RUN+=(--allow-dev-key)
COLD_N=(); WARM_N=()
if [ "$SMOKE" = 1 ]; then RUN+=(--smoke); COLD_N=(--n 1); WARM_N=(--n 2); fi

if [ "$COPY_ONLY" = 0 ]; then
  echo "# end-to-end window $STAMP (WSL) started $(stamp); clone HEAD $CLONE_HEAD; endpoints $ENDPOINTS; prover $PROVER; smoke $SMOKE; from ${FROM:-start}" >> "$STEPS"
  if [ "$USE_BESU" = 1 ]; then
    run_step besu_reset bash scripts/besu/setup_qbft.sh clean && run_step besu_up bash scripts/besu/setup_qbft.sh up || FAILED=1
  fi
  if [ "$FAILED" = 0 ] && [ "$COLD" = 1 ]; then
    step cold "${RUN[@]}" --mode cold --campaign "$COLD_CAMPAIGN" ${COLD_N[@]+"${COLD_N[@]}"} || FAILED=1
  fi
  if [ "$FAILED" = 0 ] && [ "$WARM" = 1 ]; then
    step warm "${RUN[@]}" --mode warm --campaign "$WARM_CAMPAIGN" ${WARM_N[@]+"${WARM_N[@]}"} || FAILED=1
  fi
  if [ "$USE_BESU" = 1 ]; then
    run_step besu_clean bash scripts/besu/setup_qbft.sh clean
  fi
  echo "# finished $(stamp), failed=$FAILED" >> "$STEPS"
fi

# ------------------------------------------------------------------ copy back to the Windows repository
src_manifest() { ( cd "$1" && find . -type f ! -name 'COPY_MANIFEST*' -print0 | sort -z | xargs -0 -r sha256sum ); }
append_only_ok() { # append_only_ok <clone folder> <Windows folder>: the clone's copy only extends the Windows one
  python3 - "$1" "$2" <<'PY'
import json, os, sys
src, dest = sys.argv[1:3]
problems = []
for dirpath, _, files in os.walk(dest):
    for f in files:
        if f.startswith("COPY_MANIFEST"):
            continue
        d = os.path.join(dirpath, f)
        r = os.path.relpath(d, dest)
        s = os.path.join(src, r)
        if not os.path.exists(s):
            problems.append(f"{r}: missing in the clone")
            continue
        db = open(d, "rb").read()
        sb = open(s, "rb").read()
        if f == "env.json":
            dj, sj = json.loads(db), json.loads(sb)
            ds, ss = dj.pop("sessions", []), sj.pop("sessions", [])
            if dj != sj or ss[: len(ds)] != ds:
                problems.append(f"{r}: not the same campaign with more sessions")
        elif f.endswith(".jsonl") or f.endswith(".log"):
            if not sb.startswith(db):
                problems.append(f"{r}: not append-only")
        elif db != sb:
            problems.append(f"{r}: differs")
for p in problems:
    print("  " + p, file=sys.stderr)
sys.exit(1 if problems else 0)
PY
}
copy_one() { # copy_one <relative folder>
  local rel="$1" dest="$WIN/$1"
  [ -d "$rel" ] || { echo "quiet_window_e2e_wsl: $rel does not exist in the clone; nothing to copy"; return 0; }
  if [ "$SMOKE" = 1 ]; then rm -rf "$dest"; fi
  if [ -e "$dest" ]; then
    if [ -f "$dest/COPY_MANIFEST.sha256" ] && [ "$(src_manifest "$rel")" = "$(cat "$dest/COPY_MANIFEST.sha256")" ]; then
      echo "quiet_window_e2e_wsl: $rel already copied and unchanged; skipped"
      return 0
    fi
    if [ "$REPLACE_COPY" = 0 ]; then
      echo "quiet_window_e2e_wsl: $rel exists in the Windows repository and differs (a resumed campaign?); not copied. Rerun with --copy-only --replace-copy --window-stamp $STAMP to update it after the append-only check" >&2
      return 1
    fi
    append_only_ok "$rel" "$dest" || { echo "quiet_window_e2e_wsl: $rel: the clone's copy does not only append to the Windows one; not copied (check by hand)" >&2; return 1; }
    echo "quiet_window_e2e_wsl: $rel: append-only check passed; updating the Windows copy"
  fi
  mkdir -p "$dest"
  cp -r "$rel/." "$dest/"
  src_manifest "$rel" > "$dest/COPY_MANIFEST.sha256"
  ( cd "$dest" && sha256sum --quiet -c COPY_MANIFEST.sha256 ) || { echo "quiet_window_e2e_wsl: copy check failed for $rel" >&2; return 1; }
  echo "quiet_window_e2e_wsl: copied $rel ($(wc -l < "$dest/COPY_MANIFEST.sha256") files, sha256 checked)"
}
if [ "$SMOKE" = 1 ] && [ ! -e "$WIN/$OUTROOT" ]; then
  mkdir -p "$WIN/$OUTROOT"
  printf '# smoke output of harness/v4/e2e: never committed, never quoted\n*\n' > "$WIN/$OUTROOT/.gitignore"
fi
COPY_FAILED=0
if [ "$COLD" = 1 ]; then copy_one "$OUTROOT/$COLD_CAMPAIGN" || COPY_FAILED=1; else echo "quiet_window_e2e_wsl: $OUTROOT/$COLD_CAMPAIGN not copied by design (--from warm or --warm-only)"; fi
if [ "$WARM" = 1 ]; then copy_one "$OUTROOT/$WARM_CAMPAIGN" || COPY_FAILED=1; else echo "quiet_window_e2e_wsl: $OUTROOT/$WARM_CAMPAIGN not copied by design (--cold-only)"; fi
if [ "$COPY_ONLY" = 0 ] || [ "$STAMP_GIVEN" = 1 ]; then copy_one "$LOGS" || COPY_FAILED=1; else echo "quiet_window_e2e_wsl: logs not copied (--copy-only without --window-stamp)"; fi
echo "quiet_window_e2e_wsl: window $STAMP finished, failed=$FAILED, copy failed=$COPY_FAILED; analyse in the Windows repository: python scripts/e2e/analyze_e2e.py$( [ "$SMOKE" = 1 ] && echo ' --smoke')"
[ "$FAILED" = 0 ] && [ "$COPY_FAILED" = 0 ]
