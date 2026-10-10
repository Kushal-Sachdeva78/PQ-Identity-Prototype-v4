"""Cross-implementation interop for ML-DSA-44 (Gap 7 requirement).

dilithium-py 1.4.0 is allowed in the E2E harness issuance step only; this test
enforces that its ML-DSA-44 is byte-compatible with liboqs 0.15.0 in both
directions, so mixing the implementations cannot silently diverge.

Run inside the WSL venv:
  OQS_INSTALL_PATH=/root/pqid-native/liboqs-generic \
    /root/pqid-native/venv/bin/python -m pytest tests/interop -q
"""
from __future__ import annotations

import os

import oqs
from dilithium_py.ml_dsa import ML_DSA_44

MSG = b"interop test message: credID placeholder 32B"


def test_dilithium_py_signs_liboqs_verifies() -> None:
    pk, sk = ML_DSA_44.keygen()
    sig = ML_DSA_44.sign(sk, MSG)
    with oqs.Signature("ML-DSA-44") as verifier:
        assert verifier.verify(MSG, sig, pk), "liboqs rejected dilithium-py signature"


def test_liboqs_signs_dilithium_py_verifies() -> None:
    with oqs.Signature("ML-DSA-44") as signer:
        pk = signer.generate_keypair()
        sig = signer.sign(MSG)
    assert ML_DSA_44.verify(pk, MSG, sig), "dilithium-py rejected liboqs signature"


def test_tampered_signature_rejected_by_both() -> None:
    pk, sk = ML_DSA_44.keygen()
    sig = bytearray(ML_DSA_44.sign(sk, MSG))
    sig[0] ^= 0xFF
    sig = bytes(sig)
    assert not ML_DSA_44.verify(pk, MSG, sig)
    with oqs.Signature("ML-DSA-44") as verifier:
        assert not verifier.verify(MSG, sig, pk)


def test_sizes_match_fips204() -> None:
    pk, sk = ML_DSA_44.keygen()
    sig = ML_DSA_44.sign(sk, MSG)
    assert len(pk) == 1312
    assert len(sk) == 2560
    assert len(sig) == 2420
    with oqs.Signature("ML-DSA-44") as s:
        assert s.details["length_public_key"] == 1312
        assert s.details["length_secret_key"] == 2560
        assert s.details["length_signature"] == 2420
