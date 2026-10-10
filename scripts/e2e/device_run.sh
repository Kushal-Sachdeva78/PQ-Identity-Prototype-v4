#!/usr/bin/env bash
# End-to-end series on a device (DECISIONS D-031 K3 and D-034; docs/v4/A4_TESTNET.md "Devices").
# KUSHAL RUNS THIS ON THE DEVICE: an ARM64 Linux board, an Apple Silicon Mac, or an Android phone
# under Termux. Emulation is never a device measurement: the orchestrator refuses a non-smoke run
# when the process architecture disagrees with the CPU the OS reports.
#
# From the repository root on the device (Node 24 with OpenSSL 3.5+, Python 3, `npm ci` done):
#   bash scripts/e2e/device_run.sh --label <id> --device-label "<model, RAM>" --anvil-bin <path to anvil> \
#        --key-spec <repo-relative key spec>          # or --allow-dev-key (records labelled "dev key")
#   options: --power-rule ac|record-only (phones: record-only; laptops and boards on mains: ac)
#            --smoke (a short check first: cold n 1, warm 1 + 2 blocks, output under _smoke/)
#            --endpoint custom -- <custom-endpoint flags of campaign.ts> (a phone without Anvil: the
#              public testnet, approval A4, or a laptop node on the local network). The read-only
#              harness/v4/e2e/testnet_check.ts runs first with the same flags; for an internet
#              endpoint you then type YES before anything is sent from the funder account.
# Output: results/v4/e2e_device_<id>/ (cold and warm campaigns, logs scrubbed of user name, host
# name and home paths) and e2e_device_<id>.tar.gz with its .sha256 in the repository root: send
# those two files back.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ID=""; DLABEL=""; ANVIL=""; KEYSPEC=""; DEVKEY=0; POWER="ac"; SMOKE=0; ENDPOINT="anvil"; EXPECT_ANVIL="1.5.1"
EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --label) ID="$2"; shift 2 ;;
    --device-label) DLABEL="$2"; shift 2 ;;
    --anvil-bin) ANVIL="$2"; shift 2 ;;
    --expect-anvil) EXPECT_ANVIL="$2"; shift 2 ;;
    --key-spec) KEYSPEC="$2"; shift 2 ;;
    --allow-dev-key) DEVKEY=1; shift ;;
    --power-rule) POWER="$2"; shift 2 ;;
    --smoke) SMOKE=1; shift ;;
    --endpoint) ENDPOINT="$2"; shift 2 ;;
    --) shift; EXTRA=("$@"); break ;;
    *) echo "device_run: unknown option $1" >&2; exit 2 ;;
  esac
done
die() { echo "device_run: $*" >&2; exit 2; }
echo "$ID" | grep -Eq '^[a-z][a-z0-9_]{0,30}$' || die "--label <id> is required ([a-z][a-z0-9_], for example m2_air or rpi5)"
[ -n "$DLABEL" ] || die "--device-label \"<model, RAM>\" is required (no serial numbers, no names)"
[ -n "$KEYSPEC" ] || [ "$DEVKEY" = 1 ] || die "pass --key-spec <ceremony key spec> (D-034) or --allow-dev-key"
[ "$POWER" = ac ] || [ "$POWER" = record-only ] || die "--power-rule ac|record-only"
[ "$ENDPOINT" = anvil ] || [ "$ENDPOINT" = custom ] || die "--endpoint anvil|custom"
cd "$REPO" || die "cannot enter the repository"
grep -qi microsoft /proc/version 2>/dev/null && die "this is WSL on the laptop, not a device; use scripts/e2e/quiet_window_e2e_wsl.sh"
command -v python3 > /dev/null || die "python3 is required (the logs are scrubbed of user name, host name and home paths before they are packed)"

NODE="${PQID_NODE:-$(command -v node || true)}"
[ -n "$NODE" ] && [ -x "$NODE" ] || die "node not found (install Node 24; set PQID_NODE)"
"$NODE" -e 'const [a,b]=process.versions.openssl.split(".").map(Number); process.exit(process.versions.node.startsWith("24.") && (a>3||(a===3&&b>=5)) ? 0 : 1)' \
  || die "Node 24 with OpenSSL 3.5 or later is required (found $("$NODE" --version), OpenSSL $("$NODE" -p process.versions.openssl)): ML-KEM and ML-DSA need it"
"$NODE" -e 'const c=require("node:crypto"); c.generateKeyPairSync("ml-kem-768"); c.generateKeyPairSync("ml-dsa-44"); if (typeof c.encapsulate !== "function") process.exit(1)' \
  || die "this Node cannot make ML-KEM-768 or ML-DSA-44 keys (blocked: the presentation needs both)"
echo "device_run: node $("$NODE" --version), OpenSSL $("$NODE" -p process.versions.openssl), arch $("$NODE" -p process.arch), platform $("$NODE" -p process.platform)"

scrub() { # logs carry no user name, host name or home path (secrets never reach them: the campaign redacts)
  python3 - "$1" "$HOME" "$REPO" "$(id -un)" "$(hostname 2>/dev/null || uname -n)" <<'PY'
import sys
f, home, repo, user, host = sys.argv[1:6]
subs = [(repo, "<repo>"), (home, "~"), (user, "<user>"), (host, "<host>")]
t = open(f, encoding="utf8", errors="replace").read()
for a, b in sorted(subs, key=lambda x: -len(x[0])):
    if len(a) >= 3:
        t = t.replace(a, b)
open(f, "w", encoding="utf8").write(t)
PY
}

# value of a campaign flag among the custom-endpoint flags after --
xget() {
  local name="$1" i
  for ((i = 0; i < ${#EXTRA[@]}; i++)); do
    if [ "${EXTRA[$i]}" = "--$name" ]; then echo "${EXTRA[$((i + 1))]:-}"; return 0; fi
  done
  echo ""
}

ARGS=(--device-label "$DLABEL" --power-rule "$POWER" --results-root "results/v4/e2e_device_$ID")
[ -n "$KEYSPEC" ] && ARGS+=(--key-spec "$KEYSPEC")
[ "$DEVKEY" = 1 ] && ARGS+=(--allow-dev-key)
if [ "$ENDPOINT" = anvil ]; then
  [ -n "$ANVIL" ] && [ -x "$ANVIL" ] || die "--anvil-bin <path to Foundry anvil $EXPECT_ANVIL for this device> is required with --endpoint anvil"
  ARGS+=(--endpoints anvil --anvil-bin "$ANVIL" --expect-anvil "$EXPECT_ANVIL")
else
  [ -t 0 ] || die "--endpoint custom needs an interactive terminal"
  # read-only check first (sends and signs nothing), with the same endpoint, chain and caps
  CHECK=()
  for f in rpc rpc-env funder-env expect-chain-id max-fee-gwei max-total-eth; do
    v="$(xget "$f")"; [ -n "$v" ] && CHECK+=("--$f" "$v")
  done
  echo "device_run: read-only check of the custom endpoint (nothing is sent or signed)"
  REPORT="$("$NODE" --import tsx harness/v4/e2e/testnet_check.ts ${CHECK[@]+"${CHECK[@]}"} --allow-local)"; rc=$?
  printf '%s\n' "$REPORT"
  [ "$rc" = 0 ] || die "the check reported problems (exit $rc); nothing was sent"
  REACH="$(printf '%s' "$REPORT" | "$NODE" -e 'let s="";process.stdin.on("data",(d)=>(s+=d)).on("end",()=>{try{process.stdout.write(String(JSON.parse(s).endpoint.reach))}catch{process.stdout.write("unknown")}})')"
  if [ "$REACH" != loopback ] && [ "$REACH" != lan ]; then
    echo
    echo "device_run: from here the funder account deploys four contracts, funds three role accounts and the"
    echo "issuer and verifier write their records on chain $(xget expect-chain-id) (one set-up per campaign, cold and warm;"
    echo "caps: maxFeePerGas $(xget max-fee-gwei) gwei, $(xget max-total-eth) ETH per set-up). Type YES to start:"
    read -r answer < /dev/tty
    [ "$answer" = "YES" ] || die "not confirmed; nothing was sent"
  fi
  ARGS+=(--endpoints custom ${EXTRA[@]+"${EXTRA[@]}"})
fi
COLD_N=(); WARM_N=()
if [ "$SMOKE" = 1 ]; then ARGS+=(--smoke); COLD_N=(--n 1); WARM_N=(--n 2); fi

ROOT="results/v4/e2e_device_$ID"; [ "$SMOKE" = 1 ] && ROOT="$ROOT/_smoke"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOGS="$ROOT/logs/$STAMP"
mkdir -p "$LOGS"
FAILED=0
for MODE in cold warm; do
  N=(); [ "$MODE" = cold ] && N=(${COLD_N[@]+"${COLD_N[@]}"}); [ "$MODE" = warm ] && N=(${WARM_N[@]+"${WARM_N[@]}"})
  echo "device_run: $MODE campaign e2e_${MODE}_$ID ($(date -u +%H:%M:%S) UTC); log $LOGS/$MODE.log"
  # tee ignores Ctrl-C, so the campaign can still stop cleanly (sweep, marker release) and print
  "$NODE" --import tsx harness/v4/e2e/campaign.ts --mode "$MODE" --campaign "e2e_${MODE}_$ID" "${ARGS[@]}" ${N[@]+"${N[@]}"} 2>&1 | (trap '' INT; tee "$LOGS/$MODE.log")
  rc=${PIPESTATUS[0]}
  scrub "$LOGS/$MODE.log"
  echo "device_run: $MODE exit $rc"
  [ "$rc" = 0 ] || { FAILED=1; break; }
done

# pack what to send back (results only: no keys, no URL; the campaign scanned every line, the
# logs are scrubbed above)
if [ "$SMOKE" = 0 ]; then
  for f in "results/v4/e2e_device_$ID"/logs/*/*.log; do [ -f "$f" ] && scrub "$f"; done
  TGZ="e2e_device_$ID.tar.gz"
  tar --exclude=_smoke -czf "$TGZ" "results/v4/e2e_device_$ID"
  if command -v sha256sum > /dev/null; then sha256sum "$TGZ" > "$TGZ.sha256"; else shasum -a 256 "$TGZ" > "$TGZ.sha256"; fi
  echo "device_run: send back $TGZ and $TGZ.sha256 (failed=$FAILED)"
fi
exit "$FAILED"
