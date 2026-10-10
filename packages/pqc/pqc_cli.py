"""One-shot PQC operation CLI used by the Node packages via the WSL bridge.

Reads a single JSON request on stdin, writes a JSON response on stdout.
Keys and messages are hex-encoded. Secret keys never touch argv or logs.

Requests:
  {"op": "sig-keygen"}                          -> {publicKey, secretKey}
  {"op": "sig-sign",   "secretKey", "message"}  -> {signature}
  {"op": "sig-verify", "publicKey", "message", "signature"} -> {valid}
  {"op": "kem-keygen"}                          -> {publicKey, secretKey}
  {"op": "kem-encap",  "publicKey"}             -> {ciphertext, sharedSecret}
  {"op": "kem-decap",  "secretKey", "ciphertext"} -> {sharedSecret}

Algorithms are fixed to the paper's parameter sets: ML-DSA-44 (Dilithium-II)
and ML-KEM-512 (Kyber-512).

liboqs is imported lazily so the dilithium-py ops ("*-dpy") also run on a
host without the liboqs build (the "local" backend in packages/pqc/src).
"""
from __future__ import annotations

import json
import sys

SIG_ALG = "ML-DSA-44"
KEM_ALG = "ML-KEM-512"

# ML-DSA-44 hint encoding (FIPS 204): the last OMEGA + K bytes of a signature.
_OMEGA = 80
_K = 4
_SIG_BYTES = 2420


def _hints_canonical(sig: bytes) -> bool:
    """FIPS 204 Alg. 21 (HintBitUnpack) strictness that dilithium-py 1.4.0 lacks.

    Within each polynomial the hint indices must be strictly increasing and the
    unused tail must be zero. dilithium-py only rejects DECREASING indices, so
    it accepts a repeated index that liboqs rejects: a malleable signature.
    """
    if len(sig) != _SIG_BYTES:
        return False
    y = sig[-(_OMEGA + _K):]
    idx = 0
    for i in range(_K):
        end = y[_OMEGA + i]
        if end < idx or end > _OMEGA:
            return False
        first = idx
        while idx < end:
            if idx > first and y[idx - 1] >= y[idx]:
                return False
            idx += 1
    return all(b == 0 for b in y[idx:_OMEGA])


def main() -> None:
    req = json.load(sys.stdin)
    op = req["op"]
    if not op.endswith("-dpy"):
        import oqs  # liboqs ops only
    if op == "sig-keygen":
        with oqs.Signature(SIG_ALG) as s:
            pk = s.generate_keypair()
            sk = s.export_secret_key()
        out = {"publicKey": pk.hex(), "secretKey": sk.hex()}
    elif op == "sig-sign":
        sk = bytes.fromhex(req["secretKey"])
        msg = bytes.fromhex(req["message"])
        with oqs.Signature(SIG_ALG, secret_key=sk) as s:
            sig = s.sign(msg)
        out = {"signature": sig.hex()}
    elif op == "sig-verify":
        pk = bytes.fromhex(req["publicKey"])
        msg = bytes.fromhex(req["message"])
        sig = bytes.fromhex(req["signature"])
        with oqs.Signature(SIG_ALG) as s:
            valid = s.verify(msg, sig, pk)
        out = {"valid": bool(valid)}
    elif op == "kem-keygen":
        with oqs.KeyEncapsulation(KEM_ALG) as k:
            pk = k.generate_keypair()
            sk = k.export_secret_key()
        out = {"publicKey": pk.hex(), "secretKey": sk.hex()}
    elif op == "kem-encap":
        pk = bytes.fromhex(req["publicKey"])
        with oqs.KeyEncapsulation(KEM_ALG) as k:
            ct, ss = k.encap_secret(pk)
        out = {"ciphertext": ct.hex(), "sharedSecret": ss.hex()}
    elif op == "kem-decap":
        sk = bytes.fromhex(req["secretKey"])
        ct = bytes.fromhex(req["ciphertext"])
        with oqs.KeyEncapsulation(KEM_ALG, secret_key=sk) as k:
            ss = k.decap_secret(ct)
        out = {"sharedSecret": ss.hex()}
    elif op == "sig-keygen-dpy":
        # dilithium-py 1.4.0 — E2E harness issuance step ONLY (paper A.5).
        # Interop with liboqs is enforced by tests/interop/test_mldsa_interop.py
        # and excluded from all timing tables.
        from dilithium_py.ml_dsa import ML_DSA_44

        pk, sk = ML_DSA_44.keygen()
        out = {"publicKey": pk.hex(), "secretKey": sk.hex(), "impl": "dilithium-py 1.4.0"}
    elif op == "sig-sign-dpy":
        from dilithium_py.ml_dsa import ML_DSA_44

        sk = bytes.fromhex(req["secretKey"])
        msg = bytes.fromhex(req["message"])
        sig = ML_DSA_44.sign(sk, msg)
        out = {"signature": sig.hex(), "impl": "dilithium-py 1.4.0"}
    elif op == "sig-verify-dpy":
        from dilithium_py.ml_dsa import ML_DSA_44

        pk = bytes.fromhex(req["publicKey"])
        msg = bytes.fromhex(req["message"])
        sig = bytes.fromhex(req["signature"])
        try:
            valid = _hints_canonical(sig) and bool(ML_DSA_44.verify(pk, msg, sig))
        except Exception:  # malformed key or signature encoding -> invalid
            valid = False
        out = {"valid": valid, "impl": "dilithium-py 1.4.0"}
    else:
        raise SystemExit(f"unknown op: {op}")
    # Sentinel separates the JSON payload from any import-time library notices.
    sys.stdout.write("\n===PQID_JSON===\n")
    json.dump(out, sys.stdout)


if __name__ == "__main__":
    main()
