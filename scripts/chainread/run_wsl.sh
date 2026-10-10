#!/usr/bin/env bash
# Chain-read campaign in WSL2, the primary pinned campaign (docs/v4/CHAINREAD.md, DECISIONS D-034).
#
# Usage, from Git Bash on Windows (the only call into WSL is this one, made by the operator):
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash /mnt/c/<repo>/scripts/chainread/run_wsl.sh \
#       --campaign cr_wsl --confirm-quiet [--from STEP] [--deviation "<text>"] [--allow-source-drift]
#   ... --campaign smoke_wsl --smoke [--with-besu]
#
# - Runs in the Linux clone (~/pqid-v4, or PQID_WSL_CLONE) with the D-034 toolchain: Node 24.21.0 by
#   its absolute nvm path (PQID_NODE overrides), Anvil 1.5.1 first on PATH
#   (~/pqid-tools/anvil-1.5.1), Besu 26.9.0 on JDK 25 (scripts/wsl/besu_wsl_setup.sh). Never calls
#   wsl.exe; the only Windows program it reaches is the guard's read-only power query
#   (powershell.exe through WSL interop, BENCH_PROTOCOL.md "Power").
# - The Windows repository is the one holding this script when it is called through /mnt/<drive>/
#   (or --windows-repo). The clone must be at the same commit, its chain-read code must equal its
#   own HEAD (no local change) and the Windows repository's files byte for byte, otherwise the
#   driver refuses.
# - Markers (D-034): the driver re-runs itself under `harness/v4/lib/markers.ts run --write
#   explicit-only --windows-repo <Windows repository>`, which checks both repositories for RUNNING
#   and BUSY and holds the marker only in the Windows repository: results/v4/bench/RUNNING for a
#   timed campaign, results/v4/BUSY for a smoke run (untimed, CPU-heavy). The clone gets no copy
#   (the unchanged scale.ts of R0 refuses while the clone's own RUNNING exists). The runner
#   (run.ts) uses that hold (PQID_MARKER_TOKEN).
# - Steps: anvil (S1-S5 on Anvil 8770), r0_verifier (scale.ts verifier, pinned at launch by
#   scale.ts; its Anvil runs unpinned in scale.ts's parent), besu_reset + besu_up (setup_qbft.sh
#   clean, up), besu (S1-S5 on Besu), r0_besu (scale.ts besu; the Besu JVMs keep the CPU 4-7 mask
#   of the besu step), then setup_qbft.sh clean (also on exit or interrupt once Besu was started),
#   then the copy back to the Windows repository.
# - R0 is required and the run is pinned (CHAINREAD.md). --skip-r0 and --anvil-only in a timed
#   campaign need --deviation "<text>" (written to steps.log and passed to run.ts, which records it
#   in env.json); a dated CHAINREAD.md Deviations entry is written before such a run.
# - Resume (CHAINREAD.md section 14): --from <step> on the same campaign. Steps before it must have
#   completed (target env.json status "completed", R0 file present); besu_reset and besu_up run
#   again before any Besu step that runs (a fresh QBFT network). Output of a step that runs
#   again and did not complete (a target folder, an R0 file, a step log) is moved aside, in the
#   clone and in the Windows copy, to <name>.failed-<UTC> (kept, never analysed); a completed one
#   is never redone (the driver refuses).
# - Copy back: results/v4/chainread/<campaign>/ of the clone into the Windows repository, adding
#   files that are missing there; an identical file is skipped, logs/steps.log may only grow, any
#   other difference is a conflict (nothing is overwritten; exit 1). Every attempt writes
#   COPY_MANIFEST.<UTC>.sha256 and checks it.
# - --smoke: tiny sizes, Anvil target, pinned (run.ts --pin: harness, Anvil and with --with-besu the
#   4 Besu JVMs, every thread read back), R0 verifier --dry (and Besu plus R0 besu --dry with
#   --with-besu); output under results/v4/chainread/_smoke/<campaign>/ (gitignored, never cited),
#   replaced on a new smoke without --from.
# Logs: results/v4/chainread/<campaign>/logs/<step>.log, steps.log and toolchain.txt (no user name,
# host name or home path).
set -u

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
SCRIPT_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLONE="${PQID_WSL_CLONE:-$HOME/pqid-v4}"
NODE="${PQID_NODE:-$HOME/.nvm/versions/node/v24.21.0/bin/node}"
ANVIL_DIR="$HOME/pqid-tools/anvil-1.5.1"
EXPECT_NODE="24.21.0"
EXPECT_ANVIL="1.5.1"
PORT=8770
BESU_RPC="http://127.0.0.1:18545"
STEP_NAMES=(anvil r0_verifier besu_reset besu_up besu r0_besu)

CAMPAIGN=""; CONFIRM=0; SMOKE=0; ANVIL_ONLY=0; SKIP_R0=0; WITH_BESU=0; FROM=""; WIN=""; DEVIATION=""; SRC_DRIFT=0
ORIG_ARGS=("$@")
die() { echo "run_wsl: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --campaign) CAMPAIGN="${2:-}"; shift 2 ;;
    --confirm-quiet) CONFIRM=1; shift ;;
    --smoke) SMOKE=1; shift ;;
    --anvil-only) ANVIL_ONLY=1; shift ;;
    --skip-r0) SKIP_R0=1; shift ;;
    --with-besu) WITH_BESU=1; shift ;;
    --from) FROM="${2:-}"; shift 2 ;;
    --windows-repo) WIN="${2:-}"; shift 2 ;;
    --deviation) DEVIATION="${2:-}"; shift 2 ;;
    --allow-source-drift) SRC_DRIFT=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
[ -n "$CAMPAIGN" ] || die "--campaign <name> is required"
echo "$CAMPAIGN" | grep -Eq '^[a-z][a-z0-9_]{0,39}$' || die "campaign must match ^[a-z][a-z0-9_]{0,39}$"
[ "$SMOKE" = 1 ] || [ "$CONFIRM" = 1 ] || die "a timed campaign needs --confirm-quiet (AC power, Windows applications closed, nothing else running on Windows or in WSL)"
if [ -n "$FROM" ]; then
  case " ${STEP_NAMES[*]} " in *" $FROM "*) ;; *) die "--from must be one of: ${STEP_NAMES[*]} (got '$FROM')" ;; esac
fi
if [ "$SMOKE" = 0 ]; then
  [ "$WITH_BESU" = 0 ] || die "--with-besu is a smoke option (a timed campaign always runs the Besu phase)"
  if [ "$SRC_DRIFT" = 1 ] && [ -z "$DEVIATION" ]; then
    die "--allow-source-drift departs from docs/v4/CHAINREAD.md (the code under test must equal E4's): add a dated entry to its Deviations list and pass --deviation \"<text>\""
  fi
  if { [ "$SKIP_R0" = 1 ] || [ "$ANVIL_ONLY" = 1 ]; } && [ -z "$DEVIATION" ]; then
    die "--skip-r0 and --anvil-only depart from docs/v4/CHAINREAD.md (R0 and the Besu phase are required): add a dated entry to its Deviations list and pass --deviation \"<text>\""
  fi
fi
grep -qi microsoft /proc/version 2>/dev/null || die "run inside WSL2"
if [ -z "$WIN" ]; then
  case "$SCRIPT_REPO" in /mnt/*) WIN="$SCRIPT_REPO" ;; *) die "call this script through the Windows repository's /mnt/<drive>/ path or pass --windows-repo" ;; esac
fi
[ -f "$WIN/docs/v4/CHAINREAD.md" ] || die "the Windows repository has no docs/v4/CHAINREAD.md"
[ -d "$CLONE/.git" ] || die "no clone at ~/pqid-v4 (set PQID_WSL_CLONE)"
cd "$CLONE" || die "cannot enter the clone"

BESU_STEPS=0
if [ "$ANVIL_ONLY" = 0 ] && { [ "$SMOKE" = 0 ] || [ "$WITH_BESU" = 1 ]; }; then BESU_STEPS=1; fi
R0=1; [ "$SKIP_R0" = 1 ] && R0=0

# ------------------------------------------------------------------ toolchain (D-034)
[ -x "$NODE" ] || die "Node $EXPECT_NODE not found at ~/.nvm/versions/node/v$EXPECT_NODE (set PQID_NODE)"
[ "$("$NODE" --version)" = "v$EXPECT_NODE" ] || die "Node is $("$NODE" --version), D-034 fixes v$EXPECT_NODE"
[ -x "$ANVIL_DIR/anvil" ] || die "no ~/pqid-tools/anvil-1.5.1/anvil (run scripts/wsl/besu_wsl_setup.sh)"
export PATH="$ANVIL_DIR:$(dirname "$NODE"):$PATH"
anvil --version | grep -q "Version: $EXPECT_ANVIL-" || die "anvil on PATH is not $EXPECT_ANVIL"
command -v taskset > /dev/null || die "taskset missing"
[ "$(nproc)" -ge 8 ] || die "the pinned topology needs 8 vCPUs (found $(nproc))"
pick_first_dir() { for d in "$@"; do [ -d "$d" ] && { echo "$d"; return 0; }; done; return 1; }
BESU_HOME_DIR=""; JDK_DIR=""
if [ "$BESU_STEPS" = 1 ]; then
  # the same choice as scripts/besu/setup_qbft.sh find_tools
  BESU_HOME_DIR="${PQID_BESU_HOME:-$(pick_first_dir "$HOME"/pqid-tools/besu/besu-* || true)}"
  JDK_DIR="${JAVA_HOME:-$(pick_first_dir "$HOME"/pqid-tools/jdk25/jdk-* || true)}"
  [ -n "$BESU_HOME_DIR" ] && [ -x "$BESU_HOME_DIR/bin/besu" ] || die "Besu 26.9.0 missing (run scripts/wsl/besu_wsl_setup.sh)"
  [ -n "$JDK_DIR" ] && [ -x "$JDK_DIR/bin/java" ] || die "JDK 25 missing (run scripts/wsl/besu_wsl_setup.sh)"
fi

# ------------------------------------------------------------------ the clone runs the committed code
export GIT_OPTIONAL_LOCKS=0
# tracked file types only (never __pycache__ or other generated files); expanded in each repository
CODE_GLOBS="harness/v4/chainread/*.ts harness/v4/chainread/*.sol harness/v4/lib/*.ts scripts/chainread/*.sh scripts/chainread/*.py
  docs/v4/CHAINREAD.md harness/v4/scale.ts harness/v4/scale_lib.ts harness/v4/bench/guard.ts harness/v4/bench/lib.ts
  scripts/besu/setup_qbft.sh scripts/wsl/besu_wsl_setup.sh"
CLONE_HEAD="$(git rev-parse HEAD)"
WIN_HEAD="$(git -c safe.directory="$WIN" -C "$WIN" rev-parse HEAD 2>/dev/null || echo unknown)"
[ "$CLONE_HEAD" = "$WIN_HEAD" ] || die "clone HEAD $CLONE_HEAD differs from the Windows repository's $WIN_HEAD (fast-forward the clone first)"
# shellcheck disable=SC2086 # CODE_GLOBS is expanded on purpose
[ -z "$(git status --porcelain --untracked-files=all -- $CODE_GLOBS 2>&1)" ] \
  || die "the clone's chain-read code differs from its HEAD (git status in the clone); the campaign runs committed code only"
manifest() { # sha256 of the chain-read code and the shared code it runs, relative paths, globs expanded in <repo>
  # shellcheck disable=SC2086
  ( cd "$1" && for f in $CODE_GLOBS; do if [ -f "$f" ]; then sha256sum "$f"; else echo "missing $f"; fi; done )
}
[ "$(manifest "$CLONE")" = "$(manifest "$WIN")" ] || die "the chain-read code differs between the clone and the Windows repository (compare sha256sum of: $(echo $CODE_GLOBS))"

# ------------------------------------------------------------------ markers (D-034)
if [ -z "${PQID_MARKER_TOKEN:-}" ]; then
  KIND=RUNNING; NOTE="chain-read campaign (docs/v4/CHAINREAD.md)"
  [ "$SMOKE" = 1 ] && { KIND=BUSY; NOTE="chain-read smoke (untimed)"; }
  exec "$NODE" --import tsx harness/v4/lib/markers.ts run --kind "$KIND" --campaign "$CAMPAIGN" \
    --runner scripts/chainread/run_wsl.sh --owner "operator" --note "$NOTE" \
    --windows-repo "$WIN" --write explicit-only -- "$BASH" "$SELF" "${ORIG_ARGS[@]}" --windows-repo "$WIN"
fi

# ------------------------------------------------------------------ output folders, resume
ATTEMPT="$(date -u +%Y%m%dT%H%M%SZ)"
if [ "$SMOKE" = 1 ]; then OUT="results/v4/chainread/_smoke/$CAMPAIGN"; else OUT="results/v4/chainread/$CAMPAIGN"; fi
DEST="$WIN/$OUT"
LOGS="$OUT/logs"
R0_DIR="$OUT/r0"
STEPS="$LOGS/steps.log"
stamp() { date -u "+%Y-%m-%dT%H:%M:%SZ"; }

if [ -z "$FROM" ]; then
  if [ "$SMOKE" = 1 ]; then
    rm -rf "$OUT" "$DEST"
  elif [ -e "$OUT" ] || [ -e "$DEST" ]; then
    die "$OUT exists (clone or Windows repository): resume with --from <step> or use a new campaign name"
  fi
elif [ "$SMOKE" = 0 ] && [ ! -e "$OUT" ]; then
  die "--from resumes an existing campaign, and $OUT does not exist in the clone"
fi
mkdir -p "$LOGS" "$R0_DIR"

step_index() { local i; for i in "${!STEP_NAMES[@]}"; do [ "${STEP_NAMES[$i]}" = "$1" ] && { echo "$i"; return; }; done; echo 99; }
FROM_INDEX=0; [ -n "$FROM" ] && FROM_INDEX="$(step_index "$FROM")"
should_run() { # a step at or after --from; the Besu network steps also run before any later Besu step
  case "$1" in
    besu_reset|besu_up) [ "$FROM_INDEX" -le "$(step_index r0_besu)" ] ;;
    *) [ "$(step_index "$1")" -ge "$FROM_INDEX" ] ;;
  esac
}
target_status() { # target_status <dir>: the env.json status, or "missing"
  [ -f "$1/env.json" ] || { echo missing; return; }
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf8")).get("status"))' "$1/env.json" 2>/dev/null || echo unreadable
}
step_enabled() { # step_enabled <name>: whether the campaign runs this step at all
  case "$1" in
    anvil) return 0 ;;
    r0_verifier) [ "$R0" = 1 ] ;;
    besu_reset|besu_up|besu) [ "$BESU_STEPS" = 1 ] ;;
    r0_besu) [ "$BESU_STEPS" = 1 ] && [ "$R0" = 1 ] ;;
  esac
}
step_output() { # the result a step leaves (relative to OUT), or nothing
  case "$1" in
    anvil) echo anvil ;; besu) echo besu ;;
    r0_verifier) echo r0/e4_verifier.json ;; r0_besu) echo r0/e4_besu.json ;;
  esac
}
step_done() { # step_done <name>: the step's output says it completed
  local o; o="$(step_output "$1")"
  case "$1" in
    anvil|besu) [ "$(target_status "$OUT/$o")" = completed ] ;;
    r0_verifier|r0_besu) [ -f "$OUT/$o" ] ;;
    *) return 0 ;;
  esac
}
aside_name() { # aside_name <relpath>: <dir>.failed-<UTC> or <file stem>.failed-<UTC>.<ext>
  local rel="$1" base
  base="$(basename "$rel")"
  case "$base" in
    *.*) echo "$(dirname "$rel")/${base%.*}.failed-$ATTEMPT.${base##*.}" ;;
    *) echo "$rel.failed-$ATTEMPT" ;;
  esac
}
move_aside() { # move_aside <relpath under OUT>: in the clone and in the Windows copy
  local rel="$1" to root
  to="$(aside_name "$rel")"; to="${to#./}"
  for root in "$OUT" "$DEST"; do
    if [ -e "$root/$rel" ]; then
      mv "$root/$rel" "$root/$to" || die "could not move $rel aside"
      echo "   $(stamp) moved $rel to $to ($([ "$root" = "$OUT" ] && echo clone || echo Windows copy))" >> "$STEPS"
    fi
  done
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
echo "# chain-read campaign $CAMPAIGN (WSL) attempt $ATTEMPT started $(stamp); clone HEAD $CLONE_HEAD; smoke $SMOKE; from ${FROM:-start}" >> "$STEPS"
[ -n "$DEVIATION" ] && echo "# deviation: $DEVIATION" >> "$STEPS"
for x in ${ASIDE[@]+"${ASIDE[@]}"}; do move_aside "$x"; done

# ------------------------------------------------------------------ toolchain record (no user, host or home path)
tilde() { local p="$1"; echo "${p/#$HOME/\~}"; }
{
  echo "# toolchain of attempt $ATTEMPT (scripts/chainread/run_wsl.sh)"
  echo "recorded_utc: $(stamp)"
  echo "environment: wsl2, kernel $(uname -r), $(nproc) vCPUs"
  echo "node: $(tilde "$NODE") ($("$NODE" --version), openssl $("$NODE" -p process.versions.openssl))"
  echo "anvil: $(tilde "$ANVIL_DIR/anvil")"
  echo "anvil_version: $(anvil --version 2>&1 | tr '\n' ' ')"
  echo "anvil_sha256: $(sha256sum "$ANVIL_DIR/anvil" | awk '{print $1}')"
  if [ "$BESU_STEPS" = 1 ]; then
    echo "jdk: $(tilde "$JDK_DIR") (JAVA_HOME as scripts/besu/setup_qbft.sh picks it)"
    echo "jdk_version: $("$JDK_DIR/bin/java" -version 2>&1 | tr '\n' ' ')"
    echo "besu: $(tilde "$BESU_HOME_DIR")"
    echo "besu_version: $(JAVA_HOME="$JDK_DIR" "$BESU_HOME_DIR/bin/besu" --version 2>&1 | tail -n 1)"
  fi
  echo "python3: $(python3 --version 2>&1)"
} > "$LOGS/toolchain.$ATTEMPT.txt"

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
scrub "$LOGS/toolchain.$ATTEMPT.txt"

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

RUN=("$NODE" --import tsx harness/v4/chainread/run.ts --campaign "$CAMPAIGN" --port "$PORT" --windows-repo "$WIN" \
     --expect-anvil "$EXPECT_ANVIL" --expect-node "$EXPECT_NODE")
if [ "$SMOKE" = 1 ]; then RUN+=(--smoke --pin); else RUN+=(--confirm-quiet); fi
[ -n "$DEVIATION" ] && RUN+=(--deviation "$DEVIATION")
[ "$SRC_DRIFT" = 1 ] && RUN+=(--allow-source-drift)
DRY=(); [ "$SMOKE" = 1 ] && DRY=(--dry)

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
if [ "$FAILED" = 0 ] && [ "$R0" = 1 ]; then
  step r0_verifier "$NODE" --import tsx harness/v4/scale.ts verifier "${DRY[@]}" --port "$PORT" --out "$R0_DIR/e4_verifier.json" || FAILED=1
fi
if [ "$FAILED" = 0 ] && [ "$BESU_STEPS" = 1 ]; then
  BESU_STARTED=1
  if step besu_reset bash scripts/besu/setup_qbft.sh clean && step besu_up bash scripts/besu/setup_qbft.sh up; then
    step besu "${RUN[@]}" --target besu || FAILED=1
    if [ "$FAILED" = 0 ] && [ "$R0" = 1 ] && should_run r0_besu; then
      # R0 besu runs against the Besu JVMs as the besu step left them (pinned to CPUs 4-7): record their masks
      for f in .scratch-v4/besu/node-*.pid; do
        [ -f "$f" ] && echo "   $(stamp) before r0_besu: $(basename "$f" .pid) $(taskset -cp "$(cat "$f")" 2>&1 | sed 's/^pid [0-9]*.s //')" >> "$STEPS"
      done
      step r0_besu "$NODE" --import tsx harness/v4/scale.ts besu "${DRY[@]}" --port "$PORT" --besu-rpc "$BESU_RPC" --out "$R0_DIR/e4_besu.json" || FAILED=1
    fi
  else
    FAILED=1
  fi
  besu_cleanup
fi
echo "# attempt $ATTEMPT finished $(stamp), failed=$FAILED" >> "$STEPS"

# ------------------------------------------------------------------ copy back to the Windows repository
sync_back() {
  local f src dst n_new=0 n_same=0 n_grown=0 conflicts=()
  mkdir -p "$DEST" || return 1
  while IFS= read -r -d '' f; do
    f="${f#./}"; src="$OUT/$f"; dst="$DEST/$f"
    if [ ! -e "$dst" ]; then
      mkdir -p "$(dirname "$dst")" && cp -p "$src" "$dst" && n_new=$((n_new + 1)) || conflicts+=("$f (copy failed)")
    elif cmp -s "$src" "$dst"; then
      n_same=$((n_same + 1))
    elif [ "$f" = "logs/steps.log" ] && [ "$(head -c "$(stat -c %s "$dst")" "$src" | sha256sum)" = "$(sha256sum < "$dst")" ]; then
      cp -p "$src" "$dst" && n_grown=$((n_grown + 1)) || conflicts+=("$f (copy failed)")
    else
      conflicts+=("$f")
    fi
  done < <(cd "$OUT" && find . -type f ! -name 'COPY_MANIFEST.*' -print0 | sort -z)
  local man="COPY_MANIFEST.$ATTEMPT.sha256"
  ( cd "$OUT" && find . -type f ! -name 'COPY_MANIFEST.*' -print0 | sort -z | xargs -0 sha256sum ) > "$DEST/$man"
  if [ "${#conflicts[@]}" -gt 0 ]; then
    echo "run_wsl: copy back: ${#conflicts[@]} file(s) differ in the Windows copy and were NOT overwritten: ${conflicts[*]}" >&2
    return 1
  fi
  ( cd "$DEST" && sha256sum --quiet -c "$man" ) || { echo "run_wsl: copy check failed ($man)" >&2; return 1; }
  echo "run_wsl: copied $OUT to the Windows repository: $n_new new, $n_same unchanged, $n_grown grown (steps.log); $man checked; failed=$FAILED"
}
sync_back || exit 1
exit "$FAILED"
