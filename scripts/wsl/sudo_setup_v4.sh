#!/usr/bin/env bash
# One-time system packages for the v4 work inside WSL2 Ubuntu (HANDOFF K1, K5, TASKS D, H1).
# Kushal runs this once, himself, because it needs his Linux password:
#   sudo bash "/mnt/c/Users/kusha/Downloads/IRIS 26-27/Kushal/PQ-Identity-v4/scripts/wsl/sudo_setup_v4.sh"
# Everything else (Node, circom, Foundry, rapidsnark, liboqs, Rust, zkVM toolchains, the repo
# clone) is installed later in user space by scripts/wsl/bootstrap_v4.sh without sudo.
# What this installs: compilers and build tools for rapidsnark, GMP and liboqs; clang and
# protobuf for the zkVM toolchains (H1); Docker Engine for the artifact image (K5). It adds
# the calling user to the docker group so Docker works without sudo afterwards.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "run with sudo: sudo bash $0" >&2
  exit 1
fi
TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
  echo "run it as your normal user with sudo (so the docker group goes to that user)" >&2
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  build-essential cmake ninja-build nasm m4 git curl xz-utils ca-certificates \
  python3-venv python3-dev libssl-dev pkg-config \
  clang libclang-dev protobuf-compiler \
  docker.io docker-buildx
usermod -aG docker "$TARGET_USER"
if command -v systemctl >/dev/null && systemctl is-system-running >/dev/null 2>&1; then
  systemctl enable --now docker
else
  service docker start || true
fi
echo
echo "Done. Docker version: $(docker --version 2>/dev/null || echo 'not found')"
echo "User $TARGET_USER is in the docker group (takes effect in new WSL sessions)."
echo "Tell operator: done."
