"""dilithium-py side of the v4 ML-DSA-44 interop test (tests/v4/pqc_session.test.ts).

Run with the repository venv: .venv/Scripts/python.exe (Windows) or .venv/bin/python.
Reads one JSON object from stdin and writes one JSON object to stdout. All byte
strings are lower-case hex. Keys made here stay in this process's memory; nothing is
written to disk and no secret key is printed.

Request:  {"ops": [op, ...]}
  {"op": "verify", "pk": hex, "msg": hex, "sig": hex}
      -> {"valid": bool, "error": str | null}   (ML_DSA_44.verify, empty context)
  {"op": "sign", "msgs": [hex, ...]}
      -> {"pk": hex, "sigs": [hex, ...]}          (fresh keygen, hedged signing, empty context)
Response: {"impl": "dilithium-py <version>", "results": [result, ...]}
"""
from __future__ import annotations

import json
import sys
from importlib.metadata import version

from dilithium_py.ml_dsa import ML_DSA_44


def run(op: dict) -> dict:
    kind = op.get("op")
    if kind == "verify":
        try:
            ok = ML_DSA_44.verify(bytes.fromhex(op["pk"]), bytes.fromhex(op["msg"]), bytes.fromhex(op["sig"]))
            return {"valid": bool(ok), "error": None}
        except Exception as e:  # malformed key or signature encoding
            return {"valid": False, "error": f"{type(e).__name__}: {e}"}
    if kind == "sign":
        pk, sk = ML_DSA_44.keygen()
        sigs = [ML_DSA_44.sign(sk, bytes.fromhex(m)).hex() for m in op["msgs"]]
        del sk
        return {"pk": pk.hex(), "sigs": sigs}
    raise ValueError(f"unknown op {kind!r}")


def main() -> None:
    req = json.load(sys.stdin)
    out = {"impl": f"dilithium-py {version('dilithium-py')}", "results": [run(op) for op in req["ops"]]}
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
