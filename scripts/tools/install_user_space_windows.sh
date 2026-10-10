#!/usr/bin/env bash
# User-space tool installs used by the v4 run on the native Windows host (DECISIONS D-001, D-009).
# No admin, no installers: portable archives into ~/pqid-tools. Re-runnable (skips existing).
# Rust, circomspect and Tectonic were installed earlier the same way (WORKLOG 2026-09-27 08:59).
set -euo pipefail
T="$HOME/pqid-tools"; D="$T/dl"; mkdir -p "$D"
get() { # url file
  [ -s "$D/$2" ] || curl -sSfL --retry 3 -o "$D/$2" "$1"
  echo "$(sha256sum "$D/$2" | cut -c1-64)  $2" >> "$T/downloads.sha256"
}
# Racket Minimal 9.3 (portable tgz) for Picus
get https://download.racket-lang.org/releases/9.3/installers/racket-minimal-9.3-x86_64-win32-cs.tgz racket-minimal.tgz
[ -d "$T/racket" ] || { mkdir -p "$T/racket" && tar -xzf "$D/racket-minimal.tgz" -C "$T/racket"; }
# z3 5.1.0 (Picus fallback solver; no finite-field theory)
get https://github.com/Z3Prover/z3/releases/download/z3-5.1.0/z3-5.1.0-x64-win.zip z3.zip
[ -d "$T/z3" ] || { mkdir -p "$T/z3" && unzip -q -o "$D/z3.zip" -d "$T/z3"; }
# Picus (source, main branch; commit recorded)
[ -d "$T/Picus" ] || git clone --depth 1 https://github.com/Veridise/Picus "$T/Picus"
git -C "$T/Picus" rev-parse HEAD > "$T/Picus.commit"
# Temurin JDK 25 (Besu 26.9 needs Java 25) and Besu 26.9.0
get "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/OpenJDK25U-jdk_x64_windows_hotspot_25.0.4.1_1.zip" jdk25.zip
[ -d "$T/jdk25" ] || { mkdir -p "$T/jdk25" && unzip -q -o "$D/jdk25.zip" -d "$T/jdk25"; }
get https://github.com/besu-eth/besu/releases/download/26.9.0/besu-26.9.0.zip besu.zip
get https://github.com/besu-eth/besu/releases/download/26.9.0/besu-26.9.0.zip.sha256 besu.zip.sha256 || true
[ -d "$T/besu" ] || { mkdir -p "$T/besu" && unzip -q -o "$D/besu.zip" -d "$T/besu"; }
# ffmpeg 9.0 essentials (static) for the demo MP4
get https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip ffmpeg.zip
[ -d "$T/ffmpeg" ] || { mkdir -p "$T/ffmpeg" && unzip -q -o "$D/ffmpeg.zip" -d "$T/ffmpeg"; }
echo "done"; ls "$T"
