#!/usr/bin/env bash
# Chain-read comparison campaign on the native Windows host, unpinned (D-021), from Git Bash
# (docs/v4/CHAINREAD.md, DECISIONS D-034).
#
# Usage (repository root, Git Bash):
#   bash scripts/chainread/run_windows.sh --campaign cr_win --confirm-quiet [--from STEP] [--deviation "<text>"] [--allow-source-drift]
#   bash scripts/chainread/run_windows.sh --campaign smoke_win --smoke [--with-besu]
#
# - Toolchain: Node 24.18.0 from PATH (checked), tools/foundry/anvil.exe 1.5.1 (startAnvil uses it on
#   Windows; checked), Besu 26.9.0 on the Windows JDK 25 through scripts/besu/setup_qbft.sh.
# - Markers (D-034): the driver re-runs itself under `harness/v4/lib/markers.ts run`, which refuses
#   while RUNNING or BUSY exists and holds results/v4/bench/RUNNING (timed campaign) or
#   results/v4/BUSY (smoke: untimed, CPU-heavy) for the whole run; the runner (run.ts) uses that
#   hold (PQID_MARKER_TOKEN).
# - Steps: anvil (S1-S5 on Anvil 8771), besu_reset + besu_up (setup_qbft.sh clean, up), besu (S1-S5
#   on Besu), then setup_qbft.sh clean (also on exit or interrupt once Besu was started).
# - The Besu phase is required in a timed campaign; --anvil-only there needs --deviation "<text>"
#   (written to steps.log and passed to run.ts, which records it in env.json) after a dated
#   CHAINREAD.md Deviations entry.
# - Resume (CHAINREAD.md section 14): --from <step> on the same campaign. Steps before it must have
#   completed (besu_reset and besu_up run again before the besu step); output of a step that runs again and did not complete (target folder, step log) is
#   moved aside to <name>.failed-<UTC> (kept, never analysed); a completed target is never redone.
# - --smoke: tiny sizes, Anvil only unless --with-besu; output under results/v4/chainread/_smoke/
#   (gitignored, never cited), replaced on a new smoke without --from.
# - Calls no Windows program besides what the harness and setup_qbft.sh already call (the guard's
#   power query; taskkill only when a Besu JVM outlives its stop). The child bash is started by its
#   absolute path (never the WSL launcher bash.exe of System32).
# Logs: results/v4/chainread/<campaign>/logs/<step>.log, steps.log and toolchain.<UTC>.txt (no user
# name, host name or home path).
set -u

case "$(uname -s)" in MINGW*|MSYS*) ;; *) echo "run_windows: run from Git Bash on the Windows host" >&2; exit 2 ;; esac
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELF="$REPO/scripts/chainread/run_windows.sh"
cd "$REPO" || exit 2
EXPECT_NODE="24.18.0"
EXPECT_ANVIL="1.5.1"
PORT=8771
STEP_NAMES=(anvil besu_reset besu_up besu)

CAMPAIGN=""; CONFIRM=0; SMOKE=0; ANVIL_ONLY=0; WITH_BESU=0; FROM=""; DEVIATION=""; SRC_DRIFT=0
ORIG_ARGS=("$@")
die() { echo "run_windows: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --campaign) CAMPAIGN="${2:-}"; shift 2 ;;
    --confirm-quiet) CONFIRM=1; shift ;;
    --smoke) SMOKE=1; shift ;;
    --anvil-only) ANVIL_ONLY=1; shift ;;
    --with-besu) WITH_BESU=1; shift ;;
    --from) FROM="${2:-}"; shift 2 ;;
    --deviation) DEVIATION="${2:-}"; shift 2 ;;
    --allow-source-drift) SRC_DRIFT=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
[ -n "$CAMPAIGN" ] || die "--campaign <name> is required"
echo "$CAMPAIGN" | grep -Eq '^[a-z][a-z0-9_]{0,39}$' || die "campaign must match ^[a-z][a-z0-9_]{0,39}$"
[ "$SMOKE" = 1 ] || [ "$CONFIRM" = 1 ] || die "a timed campaign needs --confirm-quiet (AC power, other applications closed, no other agent jobs, no WSL work)"
if [ -n "$FROM" ]; then
  case " ${STEP_NAMES[*]} " in *" $FROM "*) ;; *) die "--from must be one of: ${STEP_NAMES[*]} (got '$FROM')" ;; esac
fi
if [ "$SMOKE" = 0 ]; then
  [ "$WITH_BESU" = 0 ] || die "--with-besu is a smoke option (a timed campaign always runs the Besu phase)"
  if [ "$SRC_DRIFT" = 1 ] && [ -z "$DEVIATION" ]; then
    die "--allow-source-drift departs from docs/v4/CHAINREAD.md (the code under test must equal E4's): add a dated entry to its Deviations list and pass --deviation \"<text>\""
  fi
  if [ "$ANVIL_ONLY" = 1 ] && [ -z "$DEVIATION" ]; then
    die "--anvil-only departs from docs/v4/CHAINREAD.md (the Besu phase is required): add a dated entry to its Deviations list and pass --deviation \"<text>\""
  fi
fi

[ "$(node --version)" = "v$EXPECT_NODE" ] || die "Node is $(node --version), the Windows campaign uses v$EXPECT_NODE (E4)"
[ -x tools/foundry/anvil.exe ] || die "tools/foundry/anvil.exe missing"
tools/foundry/anvil.exe --version | grep -q "Version: $EXPECT_ANVIL-" || die "tools/foundry/anvil.exe is not $EXPECT_ANVIL"
BESU_STEPS=0
if [ "$ANVIL_ONLY" = 0 ] && { [ "$SMOKE" = 0 ] || [ "$WITH_BESU" = 1 ]; }; then BESU_STEPS=1; fi
pick_first_dir() { for d in "$@"; do [ -d "$d" ] && { echo "$d"; return 0; }; done; return 1; }
BESU_HOME_DIR=""; JDK_DIR=""
if [ "$BESU_STEPS" = 1 ]; then
  # the same choice as scripts/besu/setup_qbft.sh find_tools
  BESU_HOME_DIR="${PQID_BESU_HOME:-$(pick_first_dir "$HOME"/pqid-tools/besu/besu-* || true)}"
  JDK_DIR="${JAVA_HOME:-$(pick_first_dir "$HOME"/pqid-tools/jdk25/jdk-* || true)}"
  [ -n "$BESU_HOME_DIR" ] && [ -f "$BESU_HOME_DIR/bin/besu" ] || die "Besu 26.9.0 missing in ~/pqid-tools/besu (or PQID_BESU_HOME)"
  [ -n "$JDK_DIR" ] && [ -d "$JDK_DIR" ] || die "JDK 25 missing in ~/pqid-tools/jdk25 (or JAVA_HOME)"
fi

if [ -z "${PQID_MARKER_TOKEN:-}" ]; then
  # markers.ts resolves the command on Windows and refuses the WSL launcher; Git's bash.exe is
  # passed by its absolute path
  BASH_WIN="$(cygpath -w "$BASH")"
  KIND=RUNNING; NOTE="chain-read campaign (docs/v4/CHAINREAD.md)"
  [ "$SMOKE" = 1 ] && { KIND=BUSY; NOTE="chain-read smoke (untimed)"; }
  exec node --import tsx harness/v4/lib/markers.ts run --kind "$KIND" --campaign "$CAMPAIGN" \
    --runner scripts/chainread/run_windows.sh --owner "operator" --note "$NOTE" \
    -- "$BASH_WIN" "$SELF" "${ORIG_ARGS[@]}"
fi

# ------------------------------------------------------------------ output folders, resume
ATTEMPT="$(date -u +%Y%m%dT%H%M%SZ)"
if [ "$SMOKE" = 1 ]; then OUT="results/v4/chainread/_smoke/$CAMPAIGN"; else OUT="results/v4/chainread/$CAMPAIGN"; fi
LOGS="$OUT/logs"
STEPS="$LOGS/steps.log"
stamp() { date -u "+%Y-%m-%dT%H:%M:%SZ"; }
if [ -z "$FROM" ]; then
  if [ "$SMOKE" = 1 ]; then rm -rf "$OUT"
  elif [ -e "$OUT" ]; then die "$OUT exists: resume with --from <step> or use a new campaign name"
  fi
elif [ "$SMOKE" = 0 ] && [ ! -e "$OUT" ]; then
  die "--from resumes an existing campaign, and $OUT does not exist"
fi
mkdir -p "$LOGS"

step_index() { local i; for i in "${!STEP_NAMES[@]}"; do [ "${STEP_NAMES[$i]}" = "$1" ] && { echo "$i"; return; }; done; echo 99; }
FROM_INDEX=0; [ -n "$FROM" ] && FROM_INDEX="$(step_index "$FROM")"
should_run() { # a step at or after --from; the Besu network steps also run before any later Besu step
  case "$1" in
    besu_reset|besu_up) [ "$FROM_INDEX" -le "$(step_index besu)" ] ;;
    *) [ "$(step_index "$1")" -ge "$FROM_INDEX" ] ;;
  esac
}
target_status() { # target_status <dir>: the env.json status, or "missing"
  [ -f "$1/env.json" ] || { echo missing; return; }
  python -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf8")).get("status"))' "$1/env.json" 2>/dev/null || echo unreadable
}
step_enabled() { case "$1" in anvil) return 0 ;; *) [ "$BESU_STEPS" = 1 ] ;; esac; }
step_output() { case "$1" in anvil) echo anvil ;; besu) echo besu ;; esac; }
step_done() { case "$1" in anvil|besu) [ "$(target_status "$OUT/$1")" = completed ] ;; *) return 0 ;; esac; }
move_aside() { # move_aside <relpath under OUT> -> <dir>.failed-<UTC> or <stem>.failed-<UTC>.<ext>
  local rel="$1" base to
  base="$(basename "$rel")"
  case "$base" in *.*) to="$(dirname "$rel")/${base%.*}.failed-$ATTEMPT.${base##*.}" ;; *) to="$rel.failed-$ATTEMPT" ;; esac
  to="${to#./}"
  mv "$OUT/$rel" "$OUT/$to" || die "could not move $rel aside"
  echo "   $(stamp) moved $rel to $to" >> "$STEPS"
}

# resume checks first (nothing is written when the driver refuses), then the moves
ASIDE=()
if [ -n "$FROM" ]; then
  for s in "${STEP_NAMES[@]}"; do
    step_enabled "$s" || continue
    o="$(step_output "$s")"
    if ! should_run "$s"; then
      step_done "$s" || die "--from $FROM: the earlier step $s has not completed (${o:-no output}); resume from an earlier step"
    else
      if [ -n "$o" ] && [ -e "$OUT/$o" ]; then
        step_done "$s" && die "--from $FROM: $s already completed ($OUT/$o); a completed step is never redone (resume from a later step)"
        ASIDE+=("$o")
      fi
      [ -e "$LOGS/$s.log" ] && ASIDE+=("logs/$s.log")
    fi
  done
fi
echo "# chain-read campaign $CAMPAIGN (Windows) attempt $ATTEMPT started $(stamp); HEAD $(GIT_OPTIONAL_LOCKS=0 git rev-parse HEAD); smoke $SMOKE; from ${FROM:-start}" >> "$STEPS"
[ -n "$DEVIATION" ] && echo "# deviation: $DEVIATION" >> "$STEPS"
for x in ${ASIDE[@]+"${ASIDE[@]}"}; do move_aside "$x"; done

scrub() { # logs carry no user name, host name or home path
  python - "$1" "$HOME" "$REPO" "$(cygpath -w "$REPO")" "$(cygpath -m "$REPO")" "$(cygpath -w "$HOME")" "$(cygpath -m "$HOME")" "${USERNAME:-}" "${COMPUTERNAME:-}" <<'PY'
import sys
f = sys.argv[1]
home, repo, repo_w, repo_m, home_w, home_m, user, host = sys.argv[2:10]
subs = [(repo, "<repo>"), (repo_w, "<repo>"), (repo_m, "<repo>"), (home, "~"), (home_w, "~"), (home_m, "~"), (user, "<user>"), (host, "<host>")]
t = open(f, encoding="utf8", errors="replace").read()
for a, b in sorted(subs, key=lambda x: -len(x[0])):
    if len(a) >= 3:
        t = t.replace(a, b)
open(f, "w", encoding="utf8").write(t)
PY
}

# ------------------------------------------------------------------ toolchain record (no user, host or home path)
tilde() { local p="$1"; echo "${p/#$HOME/\~}"; }
TOOLS_LOG="$LOGS/toolchain.$ATTEMPT.txt"
{
  echo "# toolchain of attempt $ATTEMPT (scripts/chainread/run_windows.sh)"
  echo "recorded_utc: $(stamp)"
  echo "environment: windows (Git Bash $(uname -r)), $(node -p 'require("os").cpus().length') logical CPUs"
  echo "node: node on PATH ($(node --version), openssl $(node -p process.versions.openssl))"
  echo "anvil: tools/foundry/anvil.exe"
  echo "anvil_version: $(tools/foundry/anvil.exe --version 2>&1 | tr -d '\r' | tr '\n' ' ')"
  echo "anvil_sha256: $(sha256sum tools/foundry/anvil.exe | awk '{print $1}')"
  if [ "$BESU_STEPS" = 1 ]; then
    echo "jdk: $(tilde "$JDK_DIR") (JAVA_HOME as scripts/besu/setup_qbft.sh picks it)"
    echo "jdk_version: $("$JDK_DIR/bin/java" -version 2>&1 | tr -d '\r' | tr '\n' ' ')"
    echo "besu: $(tilde "$BESU_HOME_DIR")"
    echo "besu_version: $(JAVA_HOME="$JDK_DIR" "$BESU_HOME_DIR/bin/besu" --version 2>&1 | tr -d '\r' | tail -n 1)"
  fi
  echo "python: $(python --version 2>&1 | tr -d '\r')"
} > "$TOOLS_LOG"
scrub "$TOOLS_LOG"

FAILED=0
step() { # step <name> <command...>
  local name="$1"; shift
  if ! should_run "$name"; then echo "skip $name (before --from $FROM)" >> "$STEPS"; return 0; fi
  echo "== $(stamp) start $name" >> "$STEPS"
  "$@" > "$LOGS/$name.log" 2>&1
  local rc=$?
  scrub "$LOGS/$name.log"
  echo "   $(stamp) end $name exit $rc" >> "$STEPS"
  return $rc
}

RUN=(node --import tsx harness/v4/chainread/run.ts --campaign "$CAMPAIGN" --port "$PORT" --expect-anvil "$EXPECT_ANVIL" --expect-node "$EXPECT_NODE")
if [ "$SMOKE" = 1 ]; then RUN+=(--smoke); else RUN+=(--confirm-quiet); fi
[ -n "$DEVIATION" ] && RUN+=(--deviation "$DEVIATION")
[ "$SRC_DRIFT" = 1 ] && RUN+=(--allow-source-drift)

BESU_STARTED=0
besu_cleanup() {
  local log="$LOGS/besu_clean.$ATTEMPT.log"
  bash scripts/besu/setup_qbft.sh clean > "$log" 2>&1; local rc=$?
  scrub "$log"
  echo "   $(stamp) besu_clean exit $rc" >> "$STEPS"
  BESU_STARTED=0
}
on_exit() { [ "$BESU_STARTED" = 1 ] && { echo "   $(stamp) exit with Besu up: cleaning" >> "$STEPS"; besu_cleanup; }; }
trap on_exit EXIT
trap 'echo "   $(stamp) interrupted" >> "$STEPS"; exit 130' INT TERM HUP

step anvil "${RUN[@]}" --target anvil || FAILED=1
if [ "$FAILED" = 0 ] && [ "$BESU_STEPS" = 1 ]; then
  BESU_STARTED=1
  if step besu_reset bash scripts/besu/setup_qbft.sh clean && step besu_up bash scripts/besu/setup_qbft.sh up; then
    step besu "${RUN[@]}" --target besu || FAILED=1
  else
    FAILED=1
  fi
  besu_cleanup
fi
echo "# attempt $ATTEMPT finished $(stamp), failed=$FAILED" >> "$STEPS"
exit "$FAILED"
