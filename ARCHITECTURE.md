# ARCHITECTURE

Reference prototype for *A Privacy-Focused, Post-Quantum-Oriented Digital Identity
System Using Blockchain and Zero-Knowledge Proofs* (IEEE Access-2026-15409).

This document describes the subsystems, the data flow, the in-circuit/off-circuit
trust boundary (Figure 1 of the paper), the five public signals, and Assumption 5
(wallet honesty). It is the executable counterpart to §III of the manuscript.

---

## 1. Subsystems

| Package | Role (paper §) | Key responsibility |
|---|---|---|
| `packages/common` | shared | field encodings, hashing, `did:pq`, host/WSL metadata, stats |
| `packages/pqc` | Crypto Service (A) | liboqs 0.15.0 ML-DSA-44 + ML-KEM-512 bridge + bench; dilithium-py path |
| `packages/issuer` | Issuer (B) | `cred` → `credID = SHA3-256(cred ‖ pk_issuer)` → Dilithium sign |
| `packages/revocation` | Accumulator (H) | depth-32 Poseidon SMT: insert / root / non-membership opening |
| `packages/wallet` | Wallet/Prover (C) | off-circuit checks → witness → Groth16 prove (snarkJS \| rapidsnark) |
| `packages/verifier` | Verifier (D) | resolve + equality + Groth16.verify + nonce freshness |
| `packages/ledger` | Registries (F) | DID/Issuer/Revocation/Schema contracts on a single-node EVM |
| `packages/baseline` | Baseline (I) | OAuth2 + ECDSA P-256 + PostgreSQL (Table VI) |
| `circuits/` | ZK Circuit (E) | `credential_auth.circom` — relation R′ (Poseidon) |
| `onchain/` | On-chain verifier (G) | snarkJS Solidity verifier + gas measurement |
| `harness/` | Report harness (J) | benches, e2e, negative test, malicious-wallet probe, RESULTS.md |
| `cli/` | demo | one-command lifecycle |

---

## 2. Data flow (Figure 2 of the paper)

```
            ┌──────────────────────── PERMISSIONED LEDGER (single-node EVM) ───────────────────────┐
            │   DID Registry  │  Issuer Registry  │  Revocation Registry  │  Schema Registry        │
            └──────▲───────────────────▲───────────────────▲───────────────────────▲────────────────┘
        register DID│        accredit  │      publish revRoot │          resolve pk_I │
                    │                   │                      │                       │
   ┌────────────┐   │   issue VC    ┌───┴──────────────┐  prove │   (π, pub)   ┌──────┴───────────┐
   │  ISSUER    │───┼──────────────►│ WALLET / PROVER   │────────┼─────────────►│   VERIFIER        │
   │ ML-DSA-44  │   │  credID =     │ phase 1 (off-cir):│        │              │ resolve pk_I,     │
   │ signer     │   │  SHA3-256(    │  Dilithium.Verify │        │              │ revRoot on-chain; │
   └────────────┘   │  cred‖pk_I)   │  holder binding   │        │              │ equality checks;  │
                    │               │  policy check     │        │              │ Groth16.verify;   │
                    │               │ phase 2 (in-cir): │        │              │ nonce freshness   │
                    │               │  Groth16 relation │        │              └───────────────────┘
                    │               │  R′ (Poseidon)    │
                    │               └───────────────────┘
                    │                         │ in-circuit relation R′
                    │            ┌─────────────▼──────────────────────────────────┐
                    │            │  ZK TRUST BOUNDARY (Groth16, BN254)              │
                    │            │  depth-32 Poseidon SMT non-membership(revRoot)   │
                    │            │  ∧ holder binding ∧ age ≥ threshold ∧ stmtCode   │
                    │            │  (issuer Dilithium signature NOT checked here)   │
                    │            └──────────────────────────────────────────────────┘
```

Lifecycle, end to end (see `harness/e2e_core.ts`):

1. **DID registration** (Algorithm 1) — issuer and holder generate ML-DSA-44 keypairs;
   `did:pq:<base58(SHA3-256(pk)[:20])>`; DID Documents written to the DID Registry.
2. **Issuance** (Algorithm 2) — issuer builds `cred = {subject, claims, issuer, issuedAt,
   holderCommit, schema}`, computes `credID = SHA3-256(canonicalJson(cred) ‖ pk_issuer)`,
   signs `credID` with ML-DSA-44, returns `VC = {credential, credID, signature}`.
3. **Authentication, phase 1 (off-circuit)** — the wallet recomputes `credID`, runs
   `Dilithium.Verify(pk_issuer, credID, σ)`, checks holder binding (`Poseidon(holderSecret)
   == cred.holderCommit` ∧ `cred.subject == wallet.did`) and policy applicability.
4. **Authentication, phase 2 (in-circuit)** — the wallet builds the witness (including the
   depth-32 non-membership opening) and runs `Groth16.Prove` (snarkJS or rapidsnark).
5. **Verification** — the verifier resolves `pk_issuer` and `revRoot` on-chain, checks
   `Poseidon(pk_issuer) == signal[0]` and `revRoot == signal[1]`, runs `Groth16.verify`,
   and checks nonce freshness.
6. **Revocation** (Algorithm 4) — the issuer inserts `credID` into the SMT and publishes a
   new `revRoot`; the previously valid proof now fails the verifier's `revRoot` equality.

---

## 3. The in-circuit / off-circuit trust boundary (Figure 1)

The central security boundary is **what the Groth16 relation does and does not prove.**

**In-circuit (relation R′, `circuits/credential_auth.circom`, v2):**

1. **Revocation non-membership** — `smtKey = Poseidon(credIDHi, credIDLo)` is *not* a member
   of the depth-32 Poseidon SMT anchored at the public `revRoot`.
2. **Holder binding** — `Poseidon(holderSecret) == holderCommit`, where `holderCommit` is
   carried inside the issuer-signed credential.
3. **Policy predicate (generalized, V6)** — the predicate selected by `predicateCode` holds:
   `1` = `claimAge ≥ threshold` (`GreaterEqThan`), `2` = `claimAge < threshold` (`LessThan`);
   `(predicateCode, threshold)` are bound to the public `policyHash = Poseidon(predicateCode,
   threshold)` and `predicateCode ∈ {1,2}` is circuit-enforced. Two working predicate types
   back the selective-disclosure generality claim.
4. **Verifier-domain separation (V6 §F3)** — `stmtCode == Poseidon(STMT_V1, domainTag)`, where
   `domainTag = PoseidonFold(utf8(verifierId))`. A proof produced for verifier A carries A's
   domain in its statement; verifier B computes its own expected `stmtCode` and rejects the
   replay — cryptographically, even for stateless verifiers without a nonce registry.

**Off-circuit (NOT a constraint), establishing the issuer binding:**

- `credID = SHA3-256(cred ‖ pk_issuer)` is computed off-circuit. Its binding to the issuer
  key is enforced by **(a)** the wallet's off-circuit `Dilithium.Verify` and **(b)** the
  verifier's on-chain `pk_issuer` resolution + `Poseidon(pk_issuer) == signal[0]` equality.
- The issuer's ML-DSA-44 signature is verified **off-circuit only**.

### Why Poseidon, not SHA-3, in-circuit (Gap 1)

The manuscript's relation-R prose says `credID = SHA3-256(cred ‖ pk_issuer)` is proven
in-circuit. That is inconsistent with a ~21k-constraint circuit: one Keccak sponge block
compiles to **239,176 R1CS constraints** (measured — `circuits/research/sha3_incircuit.circom`),
so the full `credID` binding plus a depth-32 SHA-3 Merkle path would exceed ten million
constraints. The prototype therefore uses **Poseidon** for the in-circuit Merkle tree and
enforces the SHA-3 `credID`↔issuer-key binding **off-circuit** (mechanisms (a) and (b) above).
The research circuit exists solely to quantify the rejected alternative and is never
benchmarked or given a trusted setup. This is recorded as a manuscript divergence.

---

## 4. The five public signals

Groth16 public inputs are field elements, so the paper's protocol-level inputs are encoded
(Gap 2). Order is canonical and shared by the circuit, the witness builder, and the verifier:

```
publicSignals = [ issuerKeyHash, revRoot, policyHash, nonce, stmtCode ]
```

| # | Signal | Encoding | Resolved/checked by the verifier |
|---|---|---|---|
| 0 | `issuerKeyHash` | Poseidon fold of the 1,312-byte ML-DSA-44 `pk_issuer` (domain-separated, 31-byte chunks) | resolve `pk_issuer` on-chain; assert `Poseidon(pk_issuer) == signal[0]` |
| 1 | `revRoot` | BN254 field element; SMT root (0 = empty) | resolve current `revRoot` on-chain; assert equality |
| 2 | `policyHash` | `Poseidon(predicateCode, threshold)`; predicateCode 1 = AGE_GTE, 2 = AGE_LT | recompute for the requested policy; assert equality |
| 3 | `nonce` | 128-bit **verifier-chosen** session nonce, sent in the request | single-use freshness (TTL) check |
| 4 | `stmtCode` | `Poseidon(STMT_V1=1, domainTag(verifierId))` — domain-bound statement (V6 §F3) | recompute for own `verifierId`; assert equality (rejects cross-verifier replay) |

`credID` field packing (Gap 11): the 256-bit SHA3-256 digest does not fit one BN254 element
(~254-bit field), so it is carried in the **private** witness as two 128-bit big-endian limbs
`credIDHi`/`credIDLo`, and the SMT key is `Poseidon(credIDHi, credIDLo)` — used identically in
the JS tree (`packages/revocation`) and the Circom `SMTVerifier(32)`.

Field encodings for `claims`/`policy`/`stmt`:
- `claims.age` — uint32, range-checked in-circuit (`Num2Bits(32)`).
- `policy` — `(predicateCode ∈ {age_gte=1, age_lt=2}, threshold)` → `policyHash =
  Poseidon(predicateCode, threshold)`; both code and threshold are private witness values
  pinned by the public hash.
- `stmt` — `stmtCode = Poseidon(STMT_V1, domainTag)`: the statement version AND the requesting
  verifier's identity, computed by the wallet from `request.verifierId` and recomputed
  independently by the verifier.

Private witness (43 signals): `credIDHi, credIDLo, holderSecret, holderCommit, claimAge,
threshold, predicateCode, domainTag, smtSiblings[32], smtOldKey, smtOldValue, smtIsOld0`.
(The paper's v1 interface had 41; `predicateCode` and `domainTag` are the V6 additions —
recorded in the divergence table.)

---

## 5. Assumption 5 — wallet honesty (load-bearing)

End-to-end credential unforgeability depends on the wallet **actually performing** the
off-circuit Dilithium check before proving. Relation R′ does not constrain `cred*` to have a
valid issuer signature, so a malicious wallet that skips the check can construct
`(cred*, credID* = SHA3-256(cred* ‖ pk_issuer), holderSecret)` for an arbitrary `cred*` and
produce a Groth16 proof that **the verifier accepts** — both verifier-side checks (on-chain
`pk_issuer` resolution and `Groth16.verify`) pass because neither examines the issuer signature.

`harness/malicious_wallet_probe.ts` demonstrates this concretely: with
`dangerouslySkipOffCircuitChecks: true`, a forged credential yields an accepted proof
(`results/malicious_probe.json` → `forgedProofAccepted: true`). This is **not a bug** — it is
the paper's stated Assumption 5 reproduced honestly. The mitigations are future work `[F]`:

- **in-circuit ML-DSA verification** — estimated in the millions of R1CS constraints, currently
  impractical; or
- **TEE / remote-attestation-bound wallets** (Intel SGX, ARM TrustZone).

The honest path is what the rest of the prototype exercises; the threat model (paper §IV-A) is
restricted to honest-but-protected wallets.

---

## 6. What is real vs mocked (`[M]`/`[S]`/`[A]`/`[F]`)

**Real (`[M]`):** liboqs ML-DSA-44 + ML-KEM-512; the Circom circuit + Groth16 setup; both
provers (snarkJS + rapidsnark) on byte-identical inputs; the depth-32 SMT non-membership +
negative test; on-chain gas on a local EVM; the ECDSA/PostgreSQL baseline.

**Single-node / mocked (`[A]`/`[S]`):** the ledger is a single-node EVM (Anvil), not a
multi-node permissioned BFT network; the trusted setup reuses the Hermez ptau rather than a
per-circuit MPC ceremony; network transport is in-process/localhost.

**Out of scope (`[F]`, not built):** on-device ARM/mobile proving; in-circuit Dilithium
verification; TEE/secure-enclave wallet attestation; real Kyber PQ-TLS (only a raw encap/decap
session-key demo is included); a live public-testnet/multi-node deployment.
