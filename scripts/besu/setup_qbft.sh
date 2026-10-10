#!/usr/bin/env bash
# E4 (TASKS S57): throwaway 4-validator Hyperledger Besu QBFT network on 127.0.0.1.
# See docs/v4/E4_SCALE.md. Follows the Besu tutorial "Create a QBFT network"
# (https://docs.besu-eth.org/private-networks/tutorials/qbft; research/TOOLS_iris_rules_and_feasibility.md 2.4).
#
# Usage: scripts/besu/setup_qbft.sh up|status|down|clean
#   up      create .scratch-v4/besu/ (config, genesis, node keys) if absent, start 4 nodes,
#           wait until blocks are produced and every node has 3 peers
#   status  pids, block number and peer count of each node
#   down    stop the 4 nodes (data is kept)
#   clean   down, then delete .scratch-v4/besu/ (node keys included)
#
# Security: `besu operator generate-blockchain-config` writes the 4 validator node PRIVATE
# keys to .scratch-v4/besu/networkFiles/keys/*/key and .scratch-v4/besu/Node-*/data/key.
# They are dev keys for this local throwaway network only. .scratch-v4/ is gitignored:
# never commit, copy or publish anything under it. The only funded account is Anvil's
# public dev account #0 (LedgerV4 hard-codes it as deployer and faucet); no other key is made.
#
# Everything binds to 127.0.0.1 (P2P listen interface, P2P advertised host, JSON-RPC), NAT is
# off, and no port is opened on other interfaces.
#
# Environment overrides: PQID_BESU_HOME (unzipped besu-X.Y.Z folder), JAVA_HOME (JDK 25+),
# PQID_BESU_RPC_BASE (default 18545; nodes use BASE..BASE+3), PQID_BESU_P2P_BASE (default 30313).
set -euo pipefail

cmd="${1:-up}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NET="$REPO/.scratch-v4/besu"
RPC_BASE="${PQID_BESU_RPC_BASE:-18545}"
P2P_BASE="${PQID_BESU_P2P_BASE:-30313}"
CHAIN_ID=1337
NODES=4
# Anvil dev account #0 (publicly known test key): LedgerV4.deploy uses it as deployer/faucet.
DEPLOYER_ADDR="f39fd6e51aad88f6f4ce6ab8827279cfffb92266"

pick_first_dir() { for d in "$@"; do [ -d "$d" ] && { echo "$d"; return 0; }; done; return 1; }

find_tools() {
  if [ -z "${PQID_BESU_HOME:-}" ]; then
    PQID_BESU_HOME="$(pick_first_dir "$HOME"/pqid-tools/besu/besu-* || true)"
  fi
  if [ -z "${JAVA_HOME:-}" ]; then
    JAVA_HOME="$(pick_first_dir "$HOME"/pqid-tools/jdk25/jdk-* || true)"
  fi
  [ -n "${PQID_BESU_HOME:-}" ] && [ -x "$PQID_BESU_HOME/bin/besu" ] || { echo "setup_qbft: Besu not found (set PQID_BESU_HOME)" >&2; exit 2; }
  [ -n "${JAVA_HOME:-}" ] && [ -d "$JAVA_HOME" ] || { echo "setup_qbft: JDK 25 not found (set JAVA_HOME)" >&2; exit 2; }
  export JAVA_HOME
  BESU="$PQID_BESU_HOME/bin/besu"
}

rpc() { # rpc <port> <method> [params-json]
  curl -s -m 5 -X POST -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"method\":\"$2\",\"params\":${3:-[]},\"id\":1}" "http://127.0.0.1:$1" 2>/dev/null || true
}

hex_result() { sed -n 's/.*"result":"0x\([0-9a-fA-F]*\)".*/\1/p'; }

port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

node_alive() { # node_alive <i>
  local f="$NET/node-$1.pid"
  [ -f "$f" ] && kill -0 "$(cat "$f")" 2>/dev/null
}

write_config() {
  cat > "$NET/qbftConfigFile.json" <<EOF
{
  "genesis": {
    "config": {
      "chainId": $CHAIN_ID,
      "berlinBlock": 0,
      "londonBlock": 0,
      "shanghaiTime": 0,
      "cancunTime": 0,
      "zeroBaseFee": true,
      "qbft": {
        "blockperiodseconds": 2,
        "epochlength": 30000,
        "requesttimeoutseconds": 4
      }
    },
    "nonce": "0x0",
    "timestamp": "0x58ee40ba",
    "gasLimit": "0x1c9c380",
    "difficulty": "0x1",
    "mixHash": "0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365",
    "coinbase": "0x0000000000000000000000000000000000000000",
    "alloc": {
      "$DEPLOYER_ADDR": { "balance": "0x33b2e3c9fd0803ce8000000" }
    }
  },
  "blockchain": {
    "nodes": { "generate": true, "count": $NODES }
  }
}
EOF
}

generate() {
  mkdir -p "$NET"
  if [ -f "$NET/networkFiles/genesis.json" ]; then
    echo "setup_qbft: reusing $NET/networkFiles (run 'clean' for a fresh network)"
    return 0
  fi
  write_config
  echo "setup_qbft: generating genesis and $NODES validator node keys (dev keys, gitignored)"
  (cd "$NET" && "$BESU" operator generate-blockchain-config --config-file=qbftConfigFile.json \
      --to=networkFiles --private-key-file-name=key > generate.log 2>&1) || {
    echo "setup_qbft: generate-blockchain-config failed; see $NET/generate.log" >&2; exit 1; }
  local i=1
  for k in "$NET"/networkFiles/keys/*/; do
    mkdir -p "$NET/Node-$i/data"
    cp "$k/key" "$k/key.pub" "$NET/Node-$i/data/"
    i=$((i + 1))
  done
  [ "$i" -eq $((NODES + 1)) ] || { echo "setup_qbft: expected $NODES key folders" >&2; exit 1; }
}

enode_of() { # enode_of <i>
  local pub
  pub="$(tr -d ' \r\n' < "$NET/Node-$1/data/key.pub")"
  echo "enode://${pub#0x}@127.0.0.1:$((P2P_BASE + $1 - 1))"
}

write_static_nodes() {
  # Peers are wired with static-nodes.json and discovery is off: on Windows, Besu 26.9 refuses
  # --bootnodes=enode://... ("Illegal char <:>", it parses the value as a file path), and with
  # discovery off no UDP socket is opened.
  for i in $(seq 1 $NODES); do
    local list="" sep=""
    for j in $(seq 1 $NODES); do
      [ "$j" -eq "$i" ] && continue
      list="$list$sep\"$(enode_of "$j")\""
      sep=","
    done
    echo "[$list]" > "$NET/Node-$i/data/static-nodes.json"
  done
}

start_node() { # start_node <i>
  local i="$1"
  local rpc_port=$((RPC_BASE + i - 1)) p2p_port=$((P2P_BASE + i - 1))
  local args=(--data-path=data --genesis-file=../networkFiles/genesis.json
    --static-nodes-file=data/static-nodes.json --discovery-enabled=false
    --p2p-host=127.0.0.1 --p2p-interface=127.0.0.1 --p2p-port="$p2p_port" --nat-method=NONE
    --rpc-http-enabled --rpc-http-host=127.0.0.1 --rpc-http-port="$rpc_port"
    --rpc-http-api=ETH,NET,WEB3,QBFT,TXPOOL --host-allowlist=localhost,127.0.0.1
    --profile=enterprise --min-gas-price=0 --logging=INFO)
  pushd "$NET/Node-$i" > /dev/null
  nohup "$BESU" "${args[@]}" > "$NET/node-$i.log" 2>&1 < /dev/null &
  echo $! > "$NET/node-$i.pid"
  popd > /dev/null
  echo "setup_qbft: node $i started (pid $(cat "$NET/node-$i.pid"), rpc 127.0.0.1:$rpc_port, p2p 127.0.0.1:$p2p_port)"
}

up() {
  find_tools
  local any=0
  for i in $(seq 1 $NODES); do node_alive "$i" && any=1; done
  if [ "$any" -eq 1 ]; then echo "setup_qbft: nodes already running (use status/down)"; exit 1; fi
  for i in $(seq 1 $NODES); do
    for p in $((RPC_BASE + i - 1)) $((P2P_BASE + i - 1)); do
      if port_in_use "$p"; then echo "setup_qbft: port $p on 127.0.0.1 is in use" >&2; exit 1; fi
    done
  done
  generate
  write_static_nodes
  for i in $(seq 1 $NODES); do start_node "$i"; done
  echo "setup_qbft: waiting for block production (timeout ${PQID_BESU_WAIT_SEC:-420} s)"
  local deadline=$(( $(date +%s) + ${PQID_BESU_WAIT_SEC:-420} ))
  while :; do
    local bn peers
    bn="$(rpc "$RPC_BASE" eth_blockNumber | hex_result)"
    peers="$(rpc "$RPC_BASE" net_peerCount | hex_result)"
    if [ -n "$bn" ] && [ $((16#$bn)) -ge 3 ] && [ -n "$peers" ] && [ $((16#$peers)) -ge $((NODES - 1)) ]; then
      echo "setup_qbft: up: block $((16#$bn)), node-1 peers $((16#$peers))"
      break
    fi
    for i in $(seq 1 $NODES); do
      node_alive "$i" || { echo "setup_qbft: node $i exited; see $NET/node-$i.log" >&2; down; exit 1; }
    done
    if [ "$(date +%s)" -gt "$deadline" ]; then
      echo "setup_qbft: no block production before the timeout; see $NET/node-*.log" >&2
      down; exit 1
    fi
    sleep 3
  done
}

status() {
  for i in $(seq 1 $NODES); do
    local port=$((RPC_BASE + i - 1)) state="stopped" bn peers
    node_alive "$i" && state="running pid $(cat "$NET/node-$i.pid")"
    bn="$(rpc "$port" eth_blockNumber | hex_result)"
    peers="$(rpc "$port" net_peerCount | hex_result)"
    echo "node $i: $state; rpc 127.0.0.1:$port block ${bn:+$((16#$bn))} peers ${peers:+$((16#$peers))}"
  done
}

down() {
  for i in $(seq 1 $NODES); do
    local f="$NET/node-$i.pid"
    [ -f "$f" ] || continue
    local pid; pid="$(cat "$f")"
    if kill -0 "$pid" 2>/dev/null; then
      local winpid=""
      [ -r "/proc/$pid/winpid" ] && winpid="$(cat "/proc/$pid/winpid")"
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
      if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null || true
        [ -n "$winpid" ] && command -v taskkill > /dev/null && taskkill //F //T //PID "$winpid" > /dev/null 2>&1 || true
      fi
      echo "setup_qbft: node $i stopped"
    fi
    rm -f "$f"
  done
  # a JVM that outlived its launcher still holds its RPC port: report it
  for i in $(seq 1 $NODES); do
    if port_in_use $((RPC_BASE + i - 1)); then
      echo "setup_qbft: WARNING port $((RPC_BASE + i - 1)) still answers after stop (orphan java.exe?)" >&2
    fi
  done
}

clean() {
  down
  case "$NET" in
    */.scratch-v4/besu) rm -rf "$NET"; echo "setup_qbft: removed $NET" ;;
    *) echo "setup_qbft: refusing to delete unexpected path $NET" >&2; exit 1 ;;
  esac
}

case "$cmd" in
  up) up ;;
  status) status ;;
  down) down ;;
  clean) clean ;;
  *) echo "usage: $0 up|status|down|clean" >&2; exit 2 ;;
esac
