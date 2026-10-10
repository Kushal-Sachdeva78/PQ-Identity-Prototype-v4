#!/usr/bin/env bash
# End-to-end series against a public testnet (approval A4; docs/v4/A4_TESTNET.md). KUSHAL RUNS THIS;
# operator never transacts on a public network (docs/BENCHMARK_POLICY.md).
#
# In the WSL clone (or any Linux or macOS clone), in an interactive terminal:
#   read -rs PQID_E2E_RPC_URL; export PQID_E2E_RPC_URL           # the HTTPS RPC URL (it may hold an API key)
#   read -rs PQID_E2E_FUNDER_KEY; export PQID_E2E_FUNDER_KEY     # a fresh test-only private key (hex)
#   bash scripts/e2e/testnet_window.sh --endpoint-label sepolia-<provider> --expect-chain-id 11155111 \
#        --max-fee-gwei 10 --max-total-eth 0.1 --key-spec <repo-relative key spec> \
#        [--windows-repo /mnt/c/<Windows repository>] [--cold-only | --warm-only]
#   unset PQID_E2E_RPC_URL PQID_E2E_FUNDER_KEY
# (--allow-dev-key instead of --key-spec for a run labelled "dev key".)
#
# Steps: (1) harness/v4/e2e/testnet_check.ts, read-only (sends nothing): chain, fees, balance, cost
# estimate, batch and eth_getLogs support; the window stops when it reports a problem. (2) You type
# YES to start; from here transactions are sent from the funder account. (3) Under
# `harness/v4/lib/markers.ts run` (results/v4/bench/RUNNING held, in WSL also in the Windows
# repository): e2e_cold_testnet (30 cold runs, one set-up of about 5.2 M gas) then e2e_warm_testnet
# (5 warm-up + 30 blocks, a second set-up). Each campaign sweeps the role balances back to the funder
# at its end. (4) In WSL with --windows-repo: the two campaign folders and the logs are copied to the
# Windows repository with a sha256 manifest.
# Secrets: the URL and the key are read from the environment only, never printed and never written;
# every result line is scanned for them before it is written. The terminal must stay open; the
# laptop must stay on AC and awake (about 6 to 6.5 h).
set -u

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LABEL=""; CHAIN=""; MAXFEE=""; MAXETH=""; WIN=""; KEYSPEC=""; DEVKEY=0; COLD=1; WARM=1; CONFIRMED=0; STAMP=""
RPC_ENV="PQID_E2E_RPC_URL"; FUNDER_ENV="PQID_E2E_FUNDER_KEY"
COLD_CAMPAIGN="e2e_cold_testnet"; WARM_CAMPAIGN="e2e_warm_testnet"
ORIG_ARGS=("$@")
while [ $# -gt 0 ]; do
  case "$1" in
    --endpoint-label) LABEL="$2"; shift 2 ;;
    --expect-chain-id) CHAIN="$2"; shift 2 ;;
    --max-fee-gwei) MAXFEE="$2"; shift 2 ;;
    --max-total-eth) MAXETH="$2"; shift 2 ;;
    --windows-repo) WIN="$2"; shift 2 ;;
    --key-spec) KEYSPEC="$2"; shift 2 ;;
    --allow-dev-key) DEVKEY=1; shift ;;
    --cold-only) WARM=0; shift ;;
    --warm-only) COLD=0; shift ;;
    --cold-campaign) COLD_CAMPAIGN="$2"; shift 2 ;;
    --warm-campaign) WARM_CAMPAIGN="$2"; shift 2 ;;
    --confirmed-by-prompt) CONFIRMED=1; shift ;;
    --window-stamp) STAMP="$2"; shift 2 ;;
    *) echo "testnet_window: unknown option $1 (the RPC URL is never an argument here; use the environment)" >&2; exit 2 ;;
  esac
done
die() { echo "testnet_window: $*" >&2; exit 2; }
[ -t 0 ] || die "run this in an interactive terminal (Kushal starts the public testnet run himself, approval A4)"
echo "$LABEL" | grep -Eq '^[A-Za-z0-9._-]{1,60}$' || die "--endpoint-label <label> is required ([A-Za-z0-9._-], never the URL)"
echo "$CHAIN" | grep -Eq '^[0-9]+$' || die "--expect-chain-id N is required (Sepolia: 11155111)"
[ -n "$MAXFEE" ] && [ -n "$MAXETH" ] || die "--max-fee-gwei and --max-total-eth are required"
[ -n "$KEYSPEC" ] || [ "$DEVKEY" = 1 ] || die "pass --key-spec <ceremony key spec> (D-034) or --allow-dev-key"
for c in "$COLD_CAMPAIGN" "$WARM_CAMPAIGN"; do echo "$c" | grep -Eq '^[a-z][a-z0-9_]{0,39}$' || die "campaign names must match ^[a-z][a-z0-9_]{0,39}$"; done
[ -n "${!RPC_ENV:-}" ] || die "$RPC_ENV is not set (read -rs $RPC_ENV; export $RPC_ENV)"
[ -n "${!FUNDER_ENV:-}" ] || die "$FUNDER_ENV is not set (read -rs $FUNDER_ENV; export $FUNDER_ENV)"
cd "$REPO" || die "cannot enter the repository"

# Node: the D-034 WSL path when present, else PQID_NODE or node on PATH (Node 24 with OpenSSL 3.5+)
if [ -n "${PQID_NODE:-}" ]; then NODE="$PQID_NODE"
elif [ -x "$HOME/.nvm/versions/node/v24.21.0/bin/node" ]; then NODE="$HOME/.nvm/versions/node/v24.21.0/bin/node"
else NODE="$(command -v node || true)"; fi
[ -n "$NODE" ] && [ -x "$NODE" ] || die "node not found (set PQID_NODE)"
"$NODE" -e 'const [a,b]=process.versions.openssl.split(".").map(Number); process.exit(process.versions.node.startsWith("24.") && (a>3||(a===3&&b>=5)) ? 0 : 1)' \
  || die "Node 24 with OpenSSL 3.5 or later is required ($("$NODE" --version), OpenSSL $("$NODE" -p process.versions.openssl))"
IN_WSL=0; grep -qi microsoft /proc/version 2>/dev/null && IN_WSL=1
if [ "$IN_WSL" = 1 ] && [ -z "$WIN" ]; then die "in WSL pass --windows-repo /mnt/c/<Windows repository> (D-034: the RUNNING marker is held there too)"; fi
[ -z "$WIN" ] || [ -f "$WIN/docs/v4/E2E.md" ] || die "--windows-repo has no docs/v4/E2E.md"
[ -n "$STAMP" ] || STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

if [ "$CONFIRMED" = 0 ]; then
  echo "testnet_window: step 1, read-only check (nothing is sent or signed)"
  "$NODE" --import tsx harness/v4/e2e/testnet_check.ts --expect-chain-id "$CHAIN" --max-fee-gwei "$MAXFEE" --max-total-eth "$MAXETH" \
    --rpc-env "$RPC_ENV" --funder-env "$FUNDER_ENV"
  rc=$?
  [ "$rc" = 0 ] || die "the check reported problems (exit $rc); nothing was sent"
  echo
  echo "testnet_window: step 2. From here the funder account deploys four contracts, funds three role"
  echo "accounts and the issuer and verifier write their records on chain $CHAIN (two set-ups, one per"
  echo "campaign; caps: maxFeePerGas $MAXFEE gwei, $MAXETH ETH per set-up). Type YES to start:"
  read -r answer < /dev/tty
  [ "$answer" = "YES" ] || die "not confirmed; nothing was sent"
  WINARGS=(); [ -n "$WIN" ] && WINARGS=(--windows-repo "$WIN")
  exec "$NODE" --import tsx harness/v4/lib/markers.ts run --kind RUNNING --campaign e2e_testnet_window \
    --runner scripts/e2e/testnet_window.sh --owner Kushal --note "public testnet window $STAMP (approval A4)" \
    ${WINARGS[@]+"${WINARGS[@]}"} -- "$BASH" "$SELF" "${ORIG_ARGS[@]}" --confirmed-by-prompt --window-stamp "$STAMP"
fi
[ -n "${PQID_MARKER_TOKEN:-}" ] || die "internal: --confirmed-by-prompt is set by the script itself under its marker"

OUTROOT="results/v4/e2e"
LOGS="$OUTROOT/logs/$STAMP"
mkdir -p "$LOGS"
STEPS="$LOGS/steps.log"
stamp() { date -u "+%Y-%m-%dT%H:%M:%SZ"; }
scrub() { # logs carry no user name, host name or home path (secrets never reach them: the campaign redacts)
  python3 - "$1" "$HOME" "$REPO" "${WIN:-}" "$(id -un)" "$(hostname)" <<'PY'
import sys
f, home, repo, win, user, host = sys.argv[1:7]
subs = [(repo, "<clone>"), (win, "<repo>"), (home, "~"), (user, "<user>"), (host, "<host>")]
t = open(f, encoding="utf8", errors="replace").read()
for a, b in sorted(subs, key=lambda x: -len(x[0])):
    if len(a) >= 3:
        t = t.replace(a, b)
open(f, "w", encoding="utf8").write(t)
PY
}
FAILED=0
step() { # step <name> <command...>: output to the terminal and the log
  local name="$1"; shift
  echo "== $(stamp) start $name" >> "$STEPS"
  # tee ignores Ctrl-C, so the campaign can still stop cleanly (sweep, marker release) and print
  "$@" 2>&1 | (trap '' INT; tee "$LOGS/$name.log")
  local rc=${PIPESTATUS[0]}
  scrub "$LOGS/$name.log"
  echo "   $(stamp) end $name exit $rc" >> "$STEPS"
  return "$rc"
}
RUN=("$NODE" --import tsx harness/v4/e2e/campaign.ts --endpoints custom --endpoint-label "$LABEL" --expect-chain-id "$CHAIN"
     --max-fee-gwei "$MAXFEE" --max-total-eth "$MAXETH" --rpc-env "$RPC_ENV" --funder-env "$FUNDER_ENV" --confirm-public-testnet)
[ -n "$WIN" ] && RUN+=(--windows-repo "$WIN")
[ -n "$KEYSPEC" ] && RUN+=(--key-spec "$KEYSPEC")
[ "$DEVKEY" = 1 ] && RUN+=(--allow-dev-key)

echo "# public testnet window $STAMP started $(stamp); label $LABEL; chain $CHAIN" >> "$STEPS"
if [ "$COLD" = 1 ]; then step cold "${RUN[@]}" --mode cold --campaign "$COLD_CAMPAIGN" || FAILED=1; fi
if [ "$FAILED" = 0 ] && [ "$WARM" = 1 ]; then step warm "${RUN[@]}" --mode warm --campaign "$WARM_CAMPAIGN" || FAILED=1; fi
echo "# finished $(stamp), failed=$FAILED" >> "$STEPS"

COPY_FAILED=0
if [ -n "$WIN" ] && [ "$(cd "$WIN" && pwd -P)" != "$(pwd -P)" ]; then
  copy_one() {
    local rel="$1" dest="$WIN/$1"
    [ -d "$rel" ] || return 0
    if [ -e "$dest" ]; then echo "testnet_window: $rel already exists in the Windows repository; not overwritten" >&2; return 1; fi
    mkdir -p "$dest"
    cp -r "$rel/." "$dest/"
    ( cd "$rel" && find . -type f ! -name COPY_MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) > "$dest/COPY_MANIFEST.sha256"
    ( cd "$dest" && sha256sum --quiet -c COPY_MANIFEST.sha256 ) || { echo "testnet_window: copy check failed for $rel" >&2; return 1; }
    echo "testnet_window: copied $rel to the Windows repository"
  }
  [ "$COLD" = 1 ] && { copy_one "$OUTROOT/$COLD_CAMPAIGN" || COPY_FAILED=1; }
  [ "$WARM" = 1 ] && { copy_one "$OUTROOT/$WARM_CAMPAIGN" || COPY_FAILED=1; }
  copy_one "$LOGS" || COPY_FAILED=1
fi
echo "testnet_window: finished, failed=$FAILED, copy failed=$COPY_FAILED. Now run: unset $RPC_ENV $FUNDER_ENV"
[ "$FAILED" = 0 ] && [ "$COPY_FAILED" = 0 ]
