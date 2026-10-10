# circuits

## `credential_auth.circom` (production)

The relation R′ proven in-circuit (Groth16, BN254). See `ARCHITECTURE.md §3–4` for the
trust boundary and the five public signals.

Gadgets are sourced from **circomlib** (pinned `2.0.5`) via `node_modules/circomlib/circuits`:

| Gadget | Source | Used for |
|---|---|---|
| `Poseidon` | `poseidon.circom` | SMT hashing, holder commitment, policy hash, credID→key fold |
| `SMTVerifier(32)` | `smt/smtverifier.circom` | depth-32 sparse-Merkle **non-membership** (`fnc = 1`) |
| `GreaterEqThan(32)` | `comparators.circom` | policy predicate `age ≥ threshold` |
| `Num2Bits` | `bitify.circom` | uint32 / 128-bit range checks |

Public signals (order): `[issuerKeyHash, revRoot, policyHash, nonce, stmtCode]`.
Private inputs: `credIDHi, credIDLo, holderSecret, holderCommit, claimAge, threshold,
smtSiblings[32], smtOldKey, smtOldValue, smtIsOld0`.

The JS side that must stay byte-compatible with this circuit lives in
`packages/common/src/encoding.ts` (Poseidon folds, credID limbs, policy/holder hashing) and
`packages/revocation` (the matching circomlibjs SMT). `packages/wallet/src/witness.ts` assembles
the inputs in the exact signal names/order.

Build + report the real constraint counts:
```bash
npx tsx setup/build_circuit.ts   # -> circuits/build/circuit_info.json
```

## `credential_auth_v3.circom` (issuance-bound, side by side with v2)

Closes review findings 9.1–9.3: the prover must open a leaf
`Poseidon(1003, issuerKeyHash, credIDHi, credIDLo, Poseidon(holderSecret), claimAge)` of the
issuer's depth-32 Poseidon issuance tree, whose root the verifier checks against the issuer's
current on-chain epoch anchor (which also fixes revRoot) and ML-DSA-44 signature; the revocation key comes from the same credID
limbs, and `smtIsOld0` is constrained boolean (circomlib's `SMTVerifier` omits this, which also
leaves v2's revocation check forgeable). Public signals:
`[issuerKeyHash, revRoot, policyHash, nonce, stmtCode, issRoot]`; 18,683 constraints at `--O2`.
Design, results and limits: [`../docs/CIRCUIT_V3.md`](../docs/CIRCUIT_V3.md).

```bash
npx tsx setup/build_circuit_v3.ts   # -> circuits/build/v3/circuit_info.json
```

## `research/sha3_incircuit.circom` ([F] — report only)

Compiles one Keccak sponge block to quantify why SHA-3 cannot live in the production circuit
(Gap 1). **Never** benchmarked, **never** given a trusted setup. Run:
```bash
npx tsx setup/research_sha3_report.ts   # -> circuits/build/research/sha3_research_info.json
```
Measured: 239,176 R1CS constraints per block — extrapolated to >10M for the full SHA-3 relation,
vs ~21k for the Poseidon production circuit.

## `lib/`

Reserved for any project-specific gadgets. The current circuit composes circomlib gadgets
directly (above), so no custom templates are needed for v1; additional policy predicates would
be added here.
