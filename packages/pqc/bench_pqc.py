"""PQC primitive benchmark over liboqs (Table IV reproduction).

Methodology mirrors the paper (Appendix A.4): N iterations (default 1000)
after `warmup` discarded iterations (default 5); per-operation wall time via
time.perf_counter_ns; mean / median / sample standard deviation (n-1) / min /
max / p95 reported in milliseconds. Messages are fresh 32-byte random digests
per iteration (the protocol signs the 32-byte credID).

Run inside the WSL venv:
  OQS_INSTALL_PATH=<liboqs install> python bench_pqc.py --n 1000 --warmup 5
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from typing import Callable

import oqs  # liboqs-python


def _stats_ms(samples_ns: list[int]) -> dict[str, float]:
    ms = [s / 1e6 for s in samples_ns]
    ms_sorted = sorted(ms)
    n = len(ms)
    p95 = ms_sorted[min(n - 1, max(0, -(-95 * n // 100) - 1))]
    return {
        "n": n,
        "meanMs": round(statistics.fmean(ms), 6),
        "medianMs": round(statistics.median(ms), 6),
        "stddevMs": round(statistics.stdev(ms) if n > 1 else 0.0, 6),
        "minMs": round(ms_sorted[0], 6),
        "maxMs": round(ms_sorted[-1], 6),
        "p95Ms": round(p95, 6),
    }


def _timed_loop(fn: Callable[[], None], n: int, warmup: int) -> list[int]:
    for _ in range(warmup):
        fn()
    samples: list[int] = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        samples.append(time.perf_counter_ns() - t0)
    return samples


def bench_sig(alg: str, n: int, warmup: int) -> dict[str, object]:
    with oqs.Signature(alg) as signer:
        details = signer.details

        keygen_samples = _timed_loop(lambda: signer.generate_keypair(), n, warmup)

        pk = signer.generate_keypair()
        msgs = [os.urandom(32) for _ in range(n + warmup)]
        sigs: list[bytes] = []
        idx = {"i": 0}

        def do_sign() -> None:
            sigs.append(signer.sign(msgs[idx["i"]]))
            idx["i"] += 1

        sign_samples = _timed_loop(do_sign, n, warmup)

        with oqs.Signature(alg) as verifier:
            vidx = {"i": 0}

            def do_verify() -> None:
                i = vidx["i"]
                ok = verifier.verify(msgs[i], sigs[i], pk)
                if not ok:
                    raise RuntimeError("verification failed during benchmark")
                vidx["i"] += 1

            verify_samples = _timed_loop(do_verify, n, warmup)

        sig_len = len(sigs[0])
        return {
            "keygen": _stats_ms(keygen_samples),
            "sign": _stats_ms(sign_samples),
            "verify": _stats_ms(verify_samples),
            "sizes": {
                "publicKeyBytes": details["length_public_key"],
                "secretKeyBytes": details["length_secret_key"],
                "signatureBytesMax": details["length_signature"],
                "signatureBytesObserved": sig_len,
            },
        }


def bench_kem(alg: str, n: int, warmup: int) -> dict[str, object]:
    with oqs.KeyEncapsulation(alg) as kem:
        details = kem.details

        keygen_samples = _timed_loop(lambda: kem.generate_keypair(), n, warmup)

        pk = kem.generate_keypair()
        cts: list[bytes] = []

        def do_encap() -> None:
            ct, _ss = kem.encap_secret(pk)
            cts.append(ct)

        encap_samples = _timed_loop(do_encap, n, warmup)

        didx = {"i": 0}

        def do_decap() -> None:
            kem.decap_secret(cts[didx["i"]])
            didx["i"] += 1

        decap_samples = _timed_loop(do_decap, n, warmup)

        # correctness spot-check: encap/decap round-trip shared secrets match
        ct, ss_enc = kem.encap_secret(pk)
        ss_dec = kem.decap_secret(ct)
        if ss_enc != ss_dec:
            raise RuntimeError("KEM round-trip mismatch")

        return {
            "keygen": _stats_ms(keygen_samples),
            "encap": _stats_ms(encap_samples),
            "decap": _stats_ms(decap_samples),
            "sizes": {
                "publicKeyBytes": details["length_public_key"],
                "secretKeyBytes": details["length_secret_key"],
                "ciphertextBytes": details["length_ciphertext"],
                "sharedSecretBytes": details["length_shared_secret"],
            },
        }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--build-label", default=os.environ.get("PQID_LIBOQS_BUILD", "unknown"))
    args = ap.parse_args()

    result = {
        "schema": "pqid/pqc-bench/v1",
        "config": {
            "liboqsVersion": oqs.oqs_version(),
            "liboqsPythonCommit": os.environ.get("PQID_LIBOQS_PYTHON_COMMIT", "unknown"),
            "buildLabel": args.build_label,
            "n": args.n,
            "warmup": args.warmup,
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "timerResolutionNs": time.get_clock_info("perf_counter").resolution * 1e9,
        },
        "algorithms": {
            "ML-DSA-44": bench_sig("ML-DSA-44", args.n, args.warmup),
            "ML-KEM-512": bench_kem("ML-KEM-512", args.n, args.warmup),
        },
    }
    # Sentinel separates the JSON payload from any import-time library notices.
    sys.stdout.write("\n===PQID_JSON===\n")
    json.dump(result, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
