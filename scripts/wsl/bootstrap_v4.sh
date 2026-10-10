#!/usr/bin/env bash
# Bootstrap the Linux-native v4 toolchain inside WSL2 Ubuntu (HANDOFF K1).
# Run from the repo root inside Ubuntu:   bash scripts/wsl/bootstrap_v4.sh
#
# What it does (everything except the apt line installs in user space under ~/pqid-native):
#   1. apt packages needed to build rapidsnark and liboqs (asks for your Linux password once)
#   2. Node 24 (nvm, user space), circom 2.2.3 (Linux release binary), Foundry (anvil)
#   3. rapidsnark v0.0.8 (commit 81eddf1) and liboqs 0.15.0 via the v2 provisioning script
#      (docker/provision-wsl.sh, read-only reuse; same pins as the published paper)
#   4. prints the environment line the v4 benchmark runner needs:
#        export PQID_RAPIDSNARK=$HOME/pqid-native/rapidsnark/bin/prover
# It never calls wsl.exe and never touches the Windows side except reading this repo.
# Afterwards tell operator "Resume v4": it runs the rapidsnark benchmark series
# (docs/v4/BENCH_PROTOCOL.md) with PQID_RAPIDSNARK set.
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO="$(pwd)"
PREFIX="${PQID_PREFIX:-$HOME/pqid-native}"
mkdir -p "$PREFIX/logs"
log() { echo "[bootstrap_v4 $(date +%H:%M:%S)] $*"; }

if command -v gcc >/dev/null && command -v cmake >/dev/null && command -v nasm >/dev/null \
  && command -v m4 >/dev/null && command -v pkg-config >/dev/null && command -v ninja >/dev/null; then
  log "1/4 apt packages: already installed (scripts/wsl/sudo_setup_v4.sh), no sudo needed"
else
  log "1/4 apt packages (sudo)"
  sudo apt-get update
  sudo apt-get install -y build-essential cmake ninja-build nasm m4 git curl xz-utils \
    python3-venv python3-dev libssl-dev pkg-config
fi

log "2/4 Node 24 via nvm, circom 2.2.3, Foundry"
if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 24 ]; then
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
  export NVM_DIR="$HOME/.nvm"
  # nvm.sh is not written for set -eu; relax the flags only while it runs
  set +eu; . "$NVM_DIR/nvm.sh"; nvm install 24; set -eu
fi
mkdir -p "$HOME/.local/bin"
if ! command -v circom >/dev/null; then
  curl -fsSL -o "$HOME/.local/bin/circom" https://github.com/iden3/circom/releases/download/v2.2.3/circom-linux-amd64
  chmod +x "$HOME/.local/bin/circom"
fi
if ! command -v anvil >/dev/null; then
  curl -fsSL https://foundry.paradigm.xyz | bash
  "$HOME/.foundry/bin/foundryup"
fi
export PATH="$HOME/.local/bin:$HOME/.foundry/bin:$PATH"

log "3/4 rapidsnark v0.0.8 + liboqs 0.15.0 (docker/provision-wsl.sh, same pins as the paper)"
PQID_PREFIX="$PREFIX" bash "$REPO/docker/provision-wsl.sh" 2>&1 | tee "$PREFIX/logs/provision.log"

log "4/4 checks"
"$PREFIX/rapidsnark/bin/prover" 2>&1 | head -2 || true
circom --version
anvil --version | head -1
node --version
node -p "'openssl ' + process.versions.openssl"
cat <<EOF

Done. Add to ~/.bashrc (or export before each benchmark):
  export PQID_RAPIDSNARK=$PREFIX/rapidsnark/bin/prover
  export PATH=\$HOME/.local/bin:\$HOME/.foundry/bin:\$PATH
Note: a Linux checkout needs its own node_modules. Run "npm ci" in a Linux copy of the repo
(for example ~/PQ-Identity-v4, cloned from the Windows copy with git clone) rather than in the
Windows folder, so the Windows node_modules stay untouched.
EOF
