#!/usr/bin/env bash
# Check that the tools on this host match artifact/toolchain.env. Prints versions only
# (no usernames, hostnames or paths). Exit 1 on any mismatch.
set -u
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
. artifact/toolchain.env
bad=0
check() {
  local name="$1" want="$2" got="$3"
  if [ "$got" = "$want" ]; then echo "ok   $name $got"; else echo "BAD  $name: want $want, got ${got:-missing}"; bad=1; fi
}
check node "v$NODE_VERSION" "$(node --version 2>/dev/null)"
node -e 'const c=require("crypto");for(const a of ["ml-dsa-44","ml-kem-768"])c.generateKeyPairSync(a);console.log("ok   openssl",process.versions.openssl,"(ML-DSA-44, ML-KEM-768 available)")' || { echo "BAD  node crypto lacks ML-DSA-44 or ML-KEM-768"; bad=1; }
if [ -x tools/circom.exe ] && [ "${OS:-}" = "Windows_NT" ]; then CIRCOM=tools/circom.exe; else CIRCOM=circom; fi
check circom "$CIRCOM_VERSION" "$($CIRCOM --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
if [ -x tools/foundry/anvil.exe ] && [ "${OS:-}" = "Windows_NT" ]; then ANVIL=tools/foundry/anvil.exe; else ANVIL=anvil; fi
check anvil "$FOUNDRY_VERSION" "$($ANVIL --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
PY="${PQID_PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
"$PY" - "$PYTHON_MIN" <<'EOF' || bad=1
import sys
want = tuple(int(x) for x in sys.argv[1].split("."))
ok = sys.version_info[:2] >= want
print(("ok  " if ok else "BAD ") + f" python {sys.version.split()[0]} (min {sys.argv[1]})")
for m in ("numpy", "matplotlib", "fitz"):
    try:
        mod = __import__(m)
        print(f"ok   {m} {getattr(mod, '__version__', getattr(mod, 'VersionBind', '?'))}")
    except Exception as e:  # noqa: BLE001
        print(f"BAD  python module {m}: {e}")
        ok = False
sys.exit(0 if ok else 1)
EOF
exit $bad
