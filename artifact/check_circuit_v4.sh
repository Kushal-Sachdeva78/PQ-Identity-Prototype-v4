#!/usr/bin/env bash
# Recompile relation R4 into artifact/out/circuit (never over the committed build) and
# compare the r1cs and wasm SHA-256 with setup/pins_v4.json. Exit 1 on any difference.
set -eu
cd "$(dirname "$0")/.."
if [ -x tools/circom.exe ] && [ "${OS:-}" = "Windows_NT" ]; then CIRCOM=tools/circom.exe; else CIRCOM=circom; fi
OUT=artifact/out/circuit
rm -rf "$OUT" && mkdir -p "$OUT"
"$CIRCOM" circuits/credential_auth_v4.circom --O2 --r1cs --wasm -o "$OUT" > "$OUT/circom.log" 2>&1 || { cat "$OUT/circom.log"; exit 1; }
PY="${PQID_PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
"$PY" - "$OUT" <<'EOF'
import hashlib, json, sys
from pathlib import Path
out = Path(sys.argv[1])
pins = json.loads(Path("setup/pins_v4.json").read_text(encoding="utf-8"))
bad = 0
for key, built in (("v4/credential_auth_v4.r1cs", out / "credential_auth_v4.r1cs"),
                   ("v4/credential_auth_v4.wasm", out / "credential_auth_v4_js" / "credential_auth_v4.wasm")):
    got = hashlib.sha256(built.read_bytes()).hexdigest()
    want = pins[key]["sha256"]
    ok = got == want
    bad |= not ok
    print(f"{'ok  ' if ok else 'BAD '} {key}: rebuilt {got[:16]} pinned {want[:16]}")
sys.exit(1 if bad else 0)
EOF
