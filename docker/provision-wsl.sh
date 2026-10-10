#!/usr/bin/env bash
# Provision the native (Linux) half of the prototype inside WSL2 Ubuntu (or any
# Debian-ish host). Mirrors docker/Dockerfile.native and docker/Dockerfile.liboqs.
#
# Pinned versions (see RESULTS.md "Toolchain" section for what was actually used):
#   liboqs        0.15.0           (two builds: generic [paper-matching, no AVX2]
#                                    and dist/AVX2 [upgrades the paper's [A] note])
#   GMP           6.3.0            (static, --with-pic)
#   rapidsnark    v0.0.8, commit 81eddf1
#   dilithium-py  1.4.0            (E2E issuance only; excluded from timing tables)
#
# Everything lands under $PREFIX (default /root/pqid-native).
set -euo pipefail

PREFIX="${PQID_PREFIX:-$HOME/pqid-native}"
JOBS="$(nproc)"
mkdir -p "$PREFIX/src" "$PREFIX/logs"
cd "$PREFIX/src"

log() { echo "[provision $(date +%H:%M:%S)] $*"; }

# ---------------------------------------------------------------- liboqs 0.15.0
if [ ! -f "$PREFIX/liboqs-generic/lib/liboqs.so" ] || [ ! -f "$PREFIX/liboqs-avx2/lib/liboqs.so" ]; then
  log "fetching liboqs 0.15.0"
  rm -rf liboqs
  git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git
  cd liboqs
  git rev-parse HEAD > "$PREFIX/logs/liboqs.commit"

  # Build 1: reference optimized-C, AVX2 NOT enabled — matches the paper's
  # Table IV configuration ("reference optimized-C; AVX2 not enabled").
  log "building liboqs (generic, no AVX2)"
  cmake -S . -B build-generic -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=OFF \
    -DOQS_OPT_TARGET=generic \
    -DOQS_MINIMAL_BUILD="KEM_ml_kem_512;SIG_ml_dsa_44" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX/liboqs-generic" > "$PREFIX/logs/liboqs-generic-cmake.log" 2>&1
  ninja -C build-generic > "$PREFIX/logs/liboqs-generic-build.log" 2>&1
  ninja -C build-generic install >> "$PREFIX/logs/liboqs-generic-build.log" 2>&1

  # Build 2: default dist build (runtime CPU dispatch incl. AVX2) — measures the
  # paper's "[A] an AVX2 Linux build would be faster" as [M].
  log "building liboqs (dist/AVX2)"
  cmake -S . -B build-avx2 -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_DIST_BUILD=ON \
    -DOQS_MINIMAL_BUILD="KEM_ml_kem_512;SIG_ml_dsa_44" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX/liboqs-avx2" > "$PREFIX/logs/liboqs-avx2-cmake.log" 2>&1
  ninja -C build-avx2 > "$PREFIX/logs/liboqs-avx2-build.log" 2>&1
  ninja -C build-avx2 install >> "$PREFIX/logs/liboqs-avx2-build.log" 2>&1
  cd "$PREFIX/src"
else
  log "liboqs already built — skipping"
fi

# ---------------------------------------------------------------- GMP 6.3.0 (static)
if [ ! -f "$PREFIX/gmp/lib/libgmp.a" ]; then
  log "fetching GMP 6.3.0"
  curl -fsSLO https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz
  sha256sum gmp-6.3.0.tar.xz | tee "$PREFIX/logs/gmp.sha256"
  tar xf gmp-6.3.0.tar.xz
  cd gmp-6.3.0
  log "building GMP 6.3.0 (static)"
  # GCC 15 defaults to C23, which breaks GMP 6.3.0's configure-time compiler
  # tests ("long long reliability test 1"); pin the C dialect to gnu17.
  ./configure --prefix="$PREFIX/gmp" --enable-static --disable-shared --with-pic \
    CC=gcc CFLAGS="-O2 -fomit-frame-pointer -std=gnu17" \
    > "$PREFIX/logs/gmp-configure.log" 2>&1
  make -j"$JOBS" > "$PREFIX/logs/gmp-build.log" 2>&1
  make install >> "$PREFIX/logs/gmp-build.log" 2>&1
  cd "$PREFIX/src"
else
  log "GMP already built — skipping"
fi

# ---------------------------------------------------------------- rapidsnark v0.0.8 (81eddf1)
if [ ! -x "$PREFIX/rapidsnark/bin/prover" ]; then
  log "fetching rapidsnark v0.0.8 (commit 81eddf1)"
  rm -rf rapidsnark
  git clone https://github.com/iden3/rapidsnark.git
  cd rapidsnark
  git checkout 81eddf1
  git describe --tags > "$PREFIX/logs/rapidsnark.version" || true
  git rev-parse HEAD >> "$PREFIX/logs/rapidsnark.version"
  git submodule update --init --recursive > "$PREFIX/logs/rapidsnark-submodules.log" 2>&1

  # Pin GMP 6.3.0: rapidsnark's build_gmp.sh fetches its own GMP tarball; force 6.3.0.
  if grep -q "gmp-6" build_gmp.sh; then
    CUR=$(grep -oE 'gmp-6\.[0-9]+\.[0-9]+' build_gmp.sh | head -1)
    log "build_gmp.sh references $CUR — pinning to gmp-6.3.0"
    sed -i "s/${CUR}/gmp-6.3.0/g" build_gmp.sh
  fi
  # Same GCC-15/C23 workaround for the GMP that rapidsnark builds internally.
  export CFLAGS="-O2 -fomit-frame-pointer -std=gnu17"
  ./build_gmp.sh host > "$PREFIX/logs/rapidsnark-gmp.log" 2>&1
  unset CFLAGS

  # GCC 15 / newer libstdc++ no longer includes <cstdint> transitively;
  # rapidsnark v0.0.8 sources assume it does. Recorded as a toolchain patch
  # in RESULTS.md (no functional change).
  for hdr in src/binfile_utils.hpp src/wtns_utils.hpp src/zkey_utils.hpp src/fileloader.hpp; do
    if [ -f "$hdr" ] && ! grep -q "#include <cstdint>" "$hdr"; then
      sed -i '1i #include <cstdint>' "$hdr"
    fi
  done

  log "building rapidsnark prover"
  cmake -S . -B build_prover \
    -DTARGET_PLATFORM=host \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_INSTALL_PREFIX="$PREFIX/rapidsnark" > "$PREFIX/logs/rapidsnark-cmake.log" 2>&1
  cmake --build build_prover -j"$JOBS" > "$PREFIX/logs/rapidsnark-build.log" 2>&1
  cmake --install build_prover >> "$PREFIX/logs/rapidsnark-build.log" 2>&1
  cd "$PREFIX/src"
else
  log "rapidsnark already built — skipping"
fi

# ---------------------------------------------------------------- Python venv
if [ ! -x "$PREFIX/venv/bin/python" ]; then
  log "creating python venv"
  python3 -m venv "$PREFIX/venv"
  "$PREFIX/venv/bin/pip" install --quiet --upgrade pip
  "$PREFIX/venv/bin/pip" install --quiet pytest "dilithium-py==1.4.0"
  log "installing liboqs-python (matched to liboqs 0.15.0)"
  rm -rf liboqs-python
  git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs-python.git \
    || git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git
  ( cd liboqs-python && git rev-parse HEAD > "$PREFIX/logs/liboqs-python.commit" )
  "$PREFIX/venv/bin/pip" install --quiet ./liboqs-python
else
  log "python venv already present — skipping"
fi

log "DONE"
echo "---- versions ----"
gcc --version | head -1
cmake --version | head -1
"$PREFIX/venv/bin/python" --version
ls -la "$PREFIX/rapidsnark/bin" 2>/dev/null || true
ls "$PREFIX/liboqs-generic/lib" "$PREFIX/liboqs-avx2/lib" 2>/dev/null || true
