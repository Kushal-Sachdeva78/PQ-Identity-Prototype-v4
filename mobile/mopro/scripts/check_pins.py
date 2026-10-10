#!/usr/bin/env python3
"""Check the phone kit's inputs before a native build or a Safari session.

Usage: python3 mobile/mopro/scripts/check_pins.py [--json]

Checks (exit 1 on any failure):
  - circuits/build/v4/credential_auth_v4_js/credential_auth_v4.wasm and
    setup/out/v4/credential_auth_v4_dev.zkey match setup/pins_v4.json;
  - mobile/inputs/v4_input.meta.json was made against those same wasm and zkey hashes;
  - mobile/inputs/v4_input.json and v4_input.mopro.json hash to the values in the meta file
    (compact text without the trailing newline).
Standard library only; reads files, writes nothing.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WASM = "circuits/build/v4/credential_auth_v4_js/credential_auth_v4.wasm"
ZKEY = "setup/out/v4/credential_auth_v4_dev.zkey"
META = "mobile/inputs/v4_input.meta.json"


def sha256_file(rel: str) -> str:
    h = hashlib.sha256()
    with open(REPO / rel, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text_file(rel: str) -> str:
    text = (REPO / rel).read_bytes().decode("utf-8").rstrip("\r\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main() -> int:
    pins = json.loads((REPO / "setup" / "pins_v4.json").read_text(encoding="utf-8"))
    pin_by_path = {v["path"]: v["sha256"] for v in pins.values()}
    meta = json.loads((REPO / META).read_text(encoding="utf-8"))
    checks = []

    for rel in (WASM, ZKEY):
        got = sha256_file(rel)
        checks.append({"check": f"pin {rel}", "ok": pin_by_path.get(rel) == got, "sha256": got})
    checks.append({"check": "input made against the pinned wasm",
                   "ok": meta["artifacts"]["wasm"]["sha256"] == pin_by_path.get(WASM)})
    checks.append({"check": "input made against the pinned zkey",
                   "ok": meta["artifacts"]["zkey"]["sha256"] == pin_by_path.get(ZKEY)})
    checks.append({"check": "v4_input.json hash", "ok": sha256_text_file(meta["inputFile"]) == meta["inputSha256"]})
    checks.append({"check": "v4_input.mopro.json hash",
                   "ok": sha256_text_file(meta["moproInputFile"]) == meta["moproInputSha256"]})
    checks.append({"check": "key label is dev", "ok": meta.get("keyLabel") == "dev"})

    ok = all(c["ok"] for c in checks)
    if "--json" in sys.argv:
        print(json.dumps({"ok": ok, "checks": checks}, indent=2))
    else:
        for c in checks:
            print(f"[check_pins] {'ok  ' if c['ok'] else 'FAIL'} {c['check']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
