#!/usr/bin/env bash
# H1 (TASKS H1): STARK zkVM prototype with ML-DSA-44 verification inside the proof.
# Runs inside WSL2 Ubuntu from the repository root, in user space (no sudo):
#   1. rustup (stable) and the RISC Zero toolchain via rzup, if missing
#   2. the official project template (cargo risczero new) in stretch/h1/project, with the guest
#      named h1_guest; our sources and dependencies are dropped in
#   3. a fixture signed by Node's OpenSSL (make_fixture.mjs), then the measurement run
#      (cycles, prove time, receipt size, verify time, negative controls) into
#      results/v4/h1/zkvm_mldsa.json
#   4. provenance (added after the 2026-10-01 audit), written into zkvm_mldsa.json: startedUtc
#      (before the fixture is made), finishedUtc (after the measurement exits), the tool versions
#      (rustc, cargo, cargo-risczero, r0vm, node) and the sha256 of this script, the guest, host
#      and fixture sources, the host and guest Cargo.toml (cargo add rewrites them), the fixture,
#      and copies of the two Cargo.lock files. The lock files are gitignored in stretch/h1/project,
#      so they are copied to results/v4/h1/project.Cargo.lock (workspace: host and methods) and
#      results/v4/h1/guest.Cargo.lock (the guest, built on its own), which are committed with the
#      result and can be checked from git.
# Usage: bash stretch/h1/run_h1.sh [runs]
set -euo pipefail
cd "$(dirname "$0")/../.."
REPO="$(pwd)"
RUNS="${1:-3}"
H1="$REPO/stretch/h1"
PROJ="$H1/project"
log() { echo "[h1 $(date -u +%H:%M:%S)] $*"; }
ver() { "$@" 2>/dev/null | head -1 || true; }  # first line of a version query; empty if the tool is missing

if ! command -v cargo >/dev/null 2>&1; then
  [ -x "$HOME/.cargo/bin/cargo" ] || { log "installing rustup (stable)"; curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal; }
fi
export PATH="$HOME/.cargo/bin:$HOME/.risc0/bin:$PATH"
if ! command -v rzup >/dev/null 2>&1; then
  log "installing rzup"
  curl -fsSL https://risczero.com/install | bash
fi
if ! cargo risczero --version >/dev/null 2>&1; then
  log "rzup install (RISC Zero toolchain)"
  rzup install
fi
log "$(cargo --version); $(cargo risczero --version 2>/dev/null | head -1)"

if [ ! -d "$PROJ" ]; then
  log "template: cargo risczero new"
  (cd "$H1" && cargo risczero new project --guest-name h1_guest)
  rm -rf "$PROJ/.git"  # the template may start its own git repository; this repo tracks it
fi
cp "$H1/guest_main.rs" "$PROJ/methods/guest/src/main.rs"
cp "$H1/host_main.rs" "$PROJ/host/src/main.rs"
(cd "$PROJ/methods/guest" && cargo add fips204@0.4.6 --no-default-features --features ml-dsa-44 >/dev/null \
  && cargo add serde@1 --no-default-features --features derive,alloc >/dev/null)
(cd "$PROJ/host" && cargo add serde@1 --features derive >/dev/null && cargo add serde_json@1 hex@0.4 anyhow@1 bincode@1 >/dev/null)

log "build (release)"
(cd "$PROJ" && cargo build --release 2>&1 | tail -5)

mkdir -p "$REPO/results/v4/h1"
export NVM_DIR="$HOME/.nvm"; set +eu; . "$NVM_DIR/nvm.sh"; nvm use 24 >/dev/null; set -eu
STARTED_UTC="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
node "$H1/make_fixture.mjs" "$REPO/results/v4/h1/fixture.json"
log "measure ($RUNS runs)"
(cd "$PROJ" && RISC0_DEV_MODE=0 cargo run --release -- "$REPO/results/v4/h1/fixture.json" "$REPO/results/v4/h1/zkvm_mldsa.json" "$RUNS")
FINISHED_UTC="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
log "provenance (times, tool versions, sha256 of the code, manifests, lock files and fixture) -> results/v4/h1/zkvm_mldsa.json"
# provenance-begin
for lock in "Cargo.lock:project.Cargo.lock" "methods/guest/Cargo.lock:guest.Cargo.lock"; do
  if [ -f "$PROJ/${lock%%:*}" ]; then cp "$PROJ/${lock%%:*}" "$REPO/results/v4/h1/${lock##*:}"; fi
done
H1_T_RUSTC="$(cd "$PROJ" && ver rustc --version)"
H1_T_CARGO="$(cd "$PROJ" && ver cargo --version)"
H1_T_RISCZERO="$(ver cargo risczero --version)"
H1_T_R0VM="$(ver r0vm --version)"
H1_T_NODE="$(ver node --version)"
export H1_T_RUSTC H1_T_CARGO H1_T_RISCZERO H1_T_R0VM H1_T_NODE
node - "$REPO" "$STARTED_UTC" "$FINISHED_UTC" <<'JS'
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const [repo, startedUtc, finishedUtc] = process.argv.slice(2);
const out = path.join(repo, "results/v4/h1/zkvm_mldsa.json");
const files = [
  "stretch/h1/run_h1.sh",
  "stretch/h1/guest_main.rs",
  "stretch/h1/host_main.rs",
  "stretch/h1/make_fixture.mjs",
  "stretch/h1/project/host/Cargo.toml",
  "stretch/h1/project/methods/guest/Cargo.toml",
  "results/v4/h1/project.Cargo.lock",
  "results/v4/h1/guest.Cargo.lock",
  "results/v4/h1/fixture.json",
];
const sha256 = {};
for (const f of files) {
  const p = path.join(repo, f);
  sha256[f] = fs.existsSync(p) ? crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex") : null;
}
const tool = (name) => process.env[name] || "unavailable";
const res = JSON.parse(fs.readFileSync(out, "utf8"));
res.startedUtc = startedUtc;
res.finishedUtc = finishedUtc;
res.provenance = {
  script: "stretch/h1/run_h1.sh",
  times: "startedUtc before the fixture is made, finishedUtc after the measurement exits (UTC)",
  lockCopies: {
    "results/v4/h1/project.Cargo.lock": "copy of stretch/h1/project/Cargo.lock (gitignored there; workspace: host and methods)",
    "results/v4/h1/guest.Cargo.lock": "copy of stretch/h1/project/methods/guest/Cargo.lock (gitignored there; the guest)",
  },
  tools: {
    rustc: tool("H1_T_RUSTC"),
    cargo: tool("H1_T_CARGO"),
    cargoRisczero: tool("H1_T_RISCZERO"),
    r0vm: tool("H1_T_R0VM"),
    node: tool("H1_T_NODE"),
  },
  sha256,
};
const sorted = Object.fromEntries(Object.keys(res).sort().map((k) => [k, res[k]]));
fs.writeFileSync(out, JSON.stringify(sorted, null, 2) + "\n");
JS
# provenance-end
log "done"
