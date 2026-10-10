# Testing Guide

The test suite validates **correctness and soundness** (as opposed to the
benchmarks, which measure performance). It runs against the committed,
SHA-256-pinned circuit build and proving key, so the JavaScript/TypeScript
suites work on any platform after `npm ci`. The cross-implementation interop
test additionally needs the native liboqs + dilithium-py environment.

## Run everything

```bash
npm test          # vitest: all *.test.ts suites
# interop (needs the WSL/Linux native venv):
OQS_INSTALL_PATH=$HOME/pqid-native/liboqs-generic \
  $HOME/pqid-native/venv/bin/python -m pytest tests/interop -q
```

`make test` runs both (vitest + pytest interop).

## Test suites

| File | Focus | Key assertions |
|---|---|---|
| [`tests/circuit.test.ts`](../tests/circuit.test.ts) | The Groth16 circuit + SMT | valid witness proves & verifies; public-signal order is canonical (5 signals); rejects stale non-membership openings, wrong holder secret, failing policy predicate, threshold/policyHash mismatch, `predicateCode ∉ {1,2}`, and cross-verifier `stmtCode` replay; both `age_gte` and `age_lt` predicates work |
| [`tests/protocol.test.ts`](../tests/protocol.test.ts) | Issuer + wallet (off-circuit) | `credID == SHA3-256(cred ‖ pk_issuer)`; liboqs Dilithium verify passes; FIPS-204 sizes; `did:pq` derivation; wallet rejects tampered claim / wrong holder / inapplicable policy; **dual prover** (snarkJS + rapidsnark) on byte-identical zkey + witness both verify |
| [`tests/ledger_verifier.test.ts`](../tests/ledger_verifier.test.ts) | Registries + verifier (needs `anvil`) | DID resolution from the EVM; accreditation + revRoot reads; verifier accepts a valid presentation (all 7 checks); rejects stale nonce, outdated revRoot, policy mismatch, and cross-verifier replay |
| [`tests/kyber.test.ts`](../tests/kyber.test.ts) | ML-KEM-512 session demo | shared-secret agreement; AES-256-GCM channel round-trip; ciphertext tampering detected; FIPS-203 sizes |
| [`tests/determinism.test.ts`](../tests/determinism.test.ts) | Pins + determinism | ptau/zkey/vkey match `setup/pins.json`; identical inputs ⇒ byte-identical witnesses and verifying proofs; the beacon setup reproduces the pinned zkey byte-for-byte |
| [`tests/bench_env.test.ts`](../tests/bench_env.test.ts) | Benchmark harness internals | stats/inter-run/headline helpers behave as specified |
| [`tests/interop/test_mldsa_interop.py`](../tests/interop/test_mldsa_interop.py) | dilithium-py ↔ liboqs | signatures from each implementation verify under the other; tampered signatures rejected by both; FIPS-204 sizes |

## The required negative test

The paper's soundness requirement — *a revoked credential must never produce an
accepted proof* — is exercised by [`harness/negative_test.ts`](../harness/negative_test.ts)
(`npm run negative`, output `results/negative.json`). It tries all three
adversary strategies and requires that **none** yields an accepted proof:

1. **Honest wallet** — the revocation service refuses to issue a non-membership
   opening for a revoked credID.
2. **Stale opening + current root** — the witness violates the `SMTVerifier`
   constraints, so no proof can even be generated.
3. **Stale opening + stale root** — a cryptographically valid proof *is*
   generated, but the verifier's on-chain `revRoot` equality check rejects it
   (demonstrating why that check is mandatory: Groth16 validity ≠ freshness).

## The Assumption-5 probe (a deliberate "pass = gap reproduces")

[`harness/malicious_wallet_probe.ts`](../harness/malicious_wallet_probe.ts)
(`npm run probe`) demonstrates the paper's stated wallet-honesty assumption: a
wallet that skips the off-circuit Dilithium check can prove possession of a
**forged** credential that the verifier accepts. The probe **passes when the
forged proof is accepted** — this is the documented gap reproducing exactly as
the paper describes, not a bug. Mitigations (in-circuit ML-DSA, TEE attestation)
are `[F]`.

## Prerequisites by suite

- **No native toolchain needed (just `npm ci`):** `circuit`, `determinism`, and
  `bench_env`. These run entirely on snarkJS/circomlibjs against the committed,
  pinned circuit build, proving key, and powers-of-tau.
- **Needs the WSL/Linux liboqs bridge:** `protocol` (Dilithium keygen/sign),
  `kyber` (ML-KEM encap/decap), `ledger_verifier` (generates real keys), and the
  `interop` pytest.
- **Needs `anvil` (Foundry):** `ledger_verifier`, and `npm run gas`.

Timeouts are generous (300 s per test / hook) because real proving and EVM
round-trips are involved (see `vitest.config.ts`).
