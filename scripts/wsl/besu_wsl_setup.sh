#!/usr/bin/env bash
# WSL2 toolchain for the D-034 series (chain reads, end-to-end): user space only, no sudo, one
# script shared by every WSL series (DECISIONS D-034, docs/v4/CHAINREAD.md section 3).
#
#   1. Linux Temurin JDK 25.0.4.1+1 x64 from the official Adoptium release (download approved by
#      Kushal in D-034). The tarball must match BOTH the sha256 that Adoptium publishes next to the
#      asset (<asset>.sha256.txt) and the value pinned below (read from api.adoptium.net on
#      2026-10-01). Extracted to ~/pqid-tools/jdk25/jdk-25.0.4.1+1.
#   2. Besu 26.9.0: copied from the Windows download <Windows home>/pqid-tools/dl/besu.zip through
#      /mnt/c and checked against its recorded sha256 (besu.zip.sha256 next to it) and the pin below;
#      extracted with python3 zipfile (no unzip in this distro) to ~/pqid-tools/besu/besu-26.9.0,
#      file modes kept. No download.
#   3. Anvil 1.5.1: copied out of the local pqid-v4 Docker image (/usr/local/bin/anvil; the image
#      build checked the Foundry release asset against artifact/toolchain.env) into
#      ~/pqid-tools/anvil-1.5.1/anvil and checked to report 1.5.1 with the commit of the Windows
#      tools/foundry/anvil.exe (b0a9dd9; the Linux asset prints "1.5.1-v1.5.1", the Windows build
#      "1.5.1-stable"). No download.
#
# Idempotent: a tool already in place with the expected version is checked and kept.
# Record: ~/pqid-tools/TOOLCHAIN_pqid_v4_wsl.txt and results/v4/chainread/toolchain_wsl.txt in the
# repository that holds this script (versions and sha256 only; no user name, host name or home path).
#
# Run inside WSL, for example from Git Bash on Windows:
#   MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash /mnt/c/<repo>/scripts/wsl/besu_wsl_setup.sh
# The Windows home is derived from this script's /mnt/<drive>/Users/<name>/ path, or set
# PQID_WIN_HOME (the /mnt/c path of the Windows home folder).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOLS="$HOME/pqid-tools"
DL="$TOOLS/dl"

JDK_VERSION="25.0.4.1+1"
JDK_FILE="OpenJDK25U-jdk_x64_linux_hotspot_25.0.4.1_1.tar.gz"
JDK_URL="https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/$JDK_FILE"
JDK_SHA256_PIN="dbb698396d478e7fa2b1e50f4103324b2a99b90569ee27c33f2261f9215cf41e"
JDK_DIR="$TOOLS/jdk25/jdk-$JDK_VERSION"

BESU_VERSION="26.9.0"
BESU_SHA256_PIN="749f90b0b29b8138f5d58b949d19eed721826cab66bfb8d983f86e15831d22b2"
BESU_DIR="$TOOLS/besu/besu-$BESU_VERSION"

ANVIL_VERSION="1.5.1"
ANVIL_COMMIT="b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2"
ANVIL_IMAGE="${PQID_DOCKER_IMAGE:-pqid-v4:latest}"
ANVIL_DIR="$TOOLS/anvil-$ANVIL_VERSION"

log() { echo "[besu_wsl_setup $(date -u +%H:%M:%S)] $*"; }
die() { echo "[besu_wsl_setup] ERROR: $*" >&2; exit 1; }
tilde() { local p="$1"; echo "${p/#$HOME/\~}"; }
sha() { sha256sum "$1" | awk '{print $1}'; }

[ "$(uname -s)" = "Linux" ] || die "run inside WSL2 Linux"
grep -qi microsoft /proc/version || die "not WSL2 (this script sets up the WSL toolchain)"
[ "$(uname -m)" = "x86_64" ] || die "x86_64 only"
for t in curl sha256sum tar python3 docker; do command -v "$t" > /dev/null || die "$t missing"; done
mkdir -p "$DL" "$TOOLS/jdk25" "$TOOLS/besu" "$ANVIL_DIR"

# ------------------------------------------------------------------ Windows home (for besu.zip)
if [ -n "${PQID_WIN_HOME:-}" ]; then
  WIN_HOME="$PQID_WIN_HOME"
else
  case "$REPO" in
    /mnt/[a-z]/Users/*/*) WIN_HOME="$(echo "$REPO" | cut -d/ -f1-5)" ;;
    *) die "cannot derive the Windows home from this script's location; set PQID_WIN_HOME to its /mnt/c path" ;;
  esac
fi
[ -d "$WIN_HOME/pqid-tools/dl" ] || die "no pqid-tools/dl in the Windows home (set PQID_WIN_HOME)"

# ------------------------------------------------------------------ 1. JDK 25 (approved download)
jdk_ok() { [ -x "$JDK_DIR/bin/java" ] && "$JDK_DIR/bin/java" -version 2>&1 | grep -q "\"25.0.4.1\""; }
if jdk_ok; then
  log "1/3 JDK $JDK_VERSION already in $(tilde "$JDK_DIR")"
else
  log "1/3 JDK $JDK_VERSION: published sha256 from the Adoptium release"
  published="$(curl -fsSL -m 60 "$JDK_URL.sha256.txt" | awk '{print $1}')"
  [ "$published" = "$JDK_SHA256_PIN" ] || die "Adoptium's published sha256 ($published) differs from the pin ($JDK_SHA256_PIN)"
  if [ ! -f "$DL/$JDK_FILE" ] || [ "$(sha "$DL/$JDK_FILE")" != "$JDK_SHA256_PIN" ]; then
    log "1/3 downloading $JDK_FILE (about 141 MB) from github.com/adoptium/temurin25-binaries"
    curl -fL -m 1800 --retry 2 -o "$DL/$JDK_FILE.part" "$JDK_URL"
    mv "$DL/$JDK_FILE.part" "$DL/$JDK_FILE"
  fi
  got="$(sha "$DL/$JDK_FILE")"
  [ "$got" = "$JDK_SHA256_PIN" ] || { rm -f "$DL/$JDK_FILE"; die "JDK tarball sha256 $got does not match $JDK_SHA256_PIN (file removed)"; }
  log "1/3 sha256 OK; extracting"
  rm -rf "$JDK_DIR"
  tar -xzf "$DL/$JDK_FILE" -C "$TOOLS/jdk25"
  jdk_ok || die "extracted JDK does not report 25.0.4.1"
fi
JDK_TAR_SHA="$( [ -f "$DL/$JDK_FILE" ] && sha "$DL/$JDK_FILE" || echo "not kept")"
JAVA_V="$("$JDK_DIR/bin/java" -version 2>&1 | head -2 | tr '\n' ' ')"

# ------------------------------------------------------------------ 2. Besu 26.9.0 (no download)
besu_ok() { [ -x "$BESU_DIR/bin/besu" ] && JAVA_HOME="$JDK_DIR" "$BESU_DIR/bin/besu" --version 2>/dev/null | grep -q "v$BESU_VERSION"; }
SRC_ZIP="$WIN_HOME/pqid-tools/dl/besu.zip"
SRC_REC="$WIN_HOME/pqid-tools/dl/besu.zip.sha256"
if besu_ok; then
  log "2/3 Besu $BESU_VERSION already in $(tilde "$BESU_DIR")"
else
  [ -f "$SRC_ZIP" ] && [ -f "$SRC_REC" ] || die "Windows download pqid-tools/dl/besu.zip or its .sha256 record is missing"
  recorded="$(awk '{print $1}' "$SRC_REC" | tr -d '\r')"
  [ "$recorded" = "$BESU_SHA256_PIN" ] || die "recorded Besu sha256 ($recorded) differs from the pin ($BESU_SHA256_PIN)"
  log "2/3 copying besu.zip from the Windows download"
  cp "$SRC_ZIP" "$DL/besu-$BESU_VERSION.zip.part"
  mv "$DL/besu-$BESU_VERSION.zip.part" "$DL/besu-$BESU_VERSION.zip"
  got="$(sha "$DL/besu-$BESU_VERSION.zip")"
  [ "$got" = "$BESU_SHA256_PIN" ] || { rm -f "$DL/besu-$BESU_VERSION.zip"; die "copied besu.zip sha256 $got does not match $BESU_SHA256_PIN"; }
  log "2/3 sha256 OK; extracting with python3 zipfile (modes kept)"
  rm -rf "$BESU_DIR"
  python3 - "$DL/besu-$BESU_VERSION.zip" "$TOOLS/besu" <<'PY'
import os, sys, zipfile
src, dest = sys.argv[1], sys.argv[2]
root = os.path.realpath(dest)
with zipfile.ZipFile(src) as z:
    for info in z.infolist():
        target = os.path.realpath(os.path.join(dest, info.filename))
        if not (target == root or target.startswith(root + os.sep)):
            raise SystemExit(f"unsafe path in zip: {info.filename}")
        z.extract(info, dest)
        mode = (info.external_attr >> 16) & 0o777
        if mode and not info.is_dir():
            os.chmod(target, mode)
PY
  chmod +x "$BESU_DIR/bin/besu"
  besu_ok || die "extracted Besu does not report v$BESU_VERSION"
fi
BESU_V="$(JAVA_HOME="$JDK_DIR" "$BESU_DIR/bin/besu" --version 2>/dev/null | head -1)"
BESU_ZIP_SHA="$( [ -f "$DL/besu-$BESU_VERSION.zip" ] && sha "$DL/besu-$BESU_VERSION.zip" || echo "$BESU_SHA256_PIN (checked at copy)")"

# ------------------------------------------------------------------ 3. Anvil 1.5.1 from the image (no download)
# The Linux release asset reports "1.5.1-v1.5.1", the Windows anvil.exe "1.5.1-stable": same commit.
anvil_ok() { [ -x "$ANVIL_DIR/anvil" ] && "$ANVIL_DIR/anvil" --version 2>/dev/null | grep -q "Version: $ANVIL_VERSION-" && "$ANVIL_DIR/anvil" --version | grep -q "$ANVIL_COMMIT"; }
IMAGE_ID="$(docker image inspect "$ANVIL_IMAGE" --format '{{.Id}}' 2>/dev/null || true)"
if anvil_ok; then
  log "3/3 Anvil $ANVIL_VERSION already in $(tilde "$ANVIL_DIR")"
else
  [ -n "$IMAGE_ID" ] || die "Docker image $ANVIL_IMAGE not found (build it as in artifact/Dockerfile; no download here)"
  log "3/3 copying /usr/local/bin/anvil out of $ANVIL_IMAGE"
  cid="$(docker create "$ANVIL_IMAGE" true)"
  trap 'docker rm -f "$cid" > /dev/null 2>&1 || true' EXIT
  docker cp "$cid:/usr/local/bin/anvil" "$ANVIL_DIR/anvil.part"
  docker rm -f "$cid" > /dev/null
  trap - EXIT
  mv "$ANVIL_DIR/anvil.part" "$ANVIL_DIR/anvil"
  chmod +x "$ANVIL_DIR/anvil"
  anvil_ok || die "the copied anvil does not report $ANVIL_VERSION with commit $ANVIL_COMMIT"
fi
ANVIL_V="$("$ANVIL_DIR/anvil" --version | head -2 | tr '\n' ' ')"
ANVIL_SHA="$(sha "$ANVIL_DIR/anvil")"

NODE_BIN="$HOME/.nvm/versions/node/v24.21.0/bin/node"
NODE_V="$( [ -x "$NODE_BIN" ] && "$NODE_BIN" -p 'process.version + " openssl " + process.versions.openssl' || echo "missing (D-034 expects ~/.nvm/versions/node/v24.21.0)")"

# ------------------------------------------------------------------ record
REC="$(cat <<EOF
# WSL toolchain for the D-034 series (scripts/wsl/besu_wsl_setup.sh); paths relative to the WSL home
recorded_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
kernel: $(uname -r)
jdk: ~/pqid-tools/jdk25/jdk-$JDK_VERSION
jdk_version: $JAVA_V
jdk_source: $JDK_URL
jdk_tarball_sha256: $JDK_TAR_SHA (pinned $JDK_SHA256_PIN; Adoptium published value checked)
besu: ~/pqid-tools/besu/besu-$BESU_VERSION
besu_version: $BESU_V
besu_zip_sha256: $BESU_ZIP_SHA (pinned $BESU_SHA256_PIN; copied from the Windows download, no download)
anvil: ~/pqid-tools/anvil-$ANVIL_VERSION/anvil
anvil_version: $ANVIL_V
anvil_sha256: $ANVIL_SHA
anvil_source: /usr/local/bin/anvil of Docker image $ANVIL_IMAGE ($IMAGE_ID)
node: ~/.nvm/versions/node/v24.21.0/bin/node ($NODE_V)
EOF
)"
echo "$REC" > "$TOOLS/TOOLCHAIN_pqid_v4_wsl.txt"
if [ -d "$REPO/results/v4" ]; then
  mkdir -p "$REPO/results/v4/chainread"
  echo "$REC" > "$REPO/results/v4/chainread/toolchain_wsl.txt"
fi
echo "$REC"
log "done"
