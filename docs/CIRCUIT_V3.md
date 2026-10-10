# Circuit v3: issuance-bound credentials

Circuit v3 (`circuits/credential_auth_v3.circom`) ties every attribute a proof uses
to a commitment the issuer signed. It is built side by side with the published v2
circuit: v2's artifacts, pins and results are unchanged, so the numbers in the
paper stay reproducible. v2 is kept for reproduction only; it is not sound (below).

## Why v3 exists

| Finding | v2 behaviour (reproduced on 26 Sep 2026) | v3 behaviour |
|---|---|---|
| 9.1 Credential not bound to the issuer | `claimAge`, `holderCommit` and `credIDHi/Lo` are private inputs that no public value constrains. A wallet that skips its own Dilithium check gets a forged, never-issued credential accepted; a 16-year-old's credential proves age 42. | The prover must open a leaf of the issuer's issuance tree. The verifier checks that the tree's root is in the issuer's current on-chain epoch anchor and that the issuer's ML-DSA-44 signature on it verifies. |
| 9.2 Revocation bypass (fresh credID) | A revoked holder proves non-membership for a fresh, random credID and is accepted. | The revocation key is derived from the credID opened from the issued leaf, so a fresh credID has no leaf. |
| 9.3 Public setup trapdoor | v2's only phase-2 contribution is a beacon with a hard-coded hash, so δ is computable from public data. A proof built from α, β and δ⁻¹, with no credential and no witness, is accepted. | One secret contribution precedes the beacon; the beacon-derived value no longer matches δ. |
| New: revocation bypass (same credID) | circomlib's `SMTVerifier` never constrains `isOld0` to {0,1}. A revoked holder solves for a non-boolean `isOld0` that turns its own revoked leaf into an "empty" slot, and is accepted with its real credential. Found by the v3 review; present in v2. | `smtIsOld0 * (smtIsOld0 - 1) === 0` is added in the circuit. |

## Relation R3

Public signals, in order: `[issuerKeyHash, revRoot, policyHash, nonce, stmtCode, issRoot]`.

In-circuit (Poseidon over BN254):

1. `holderCommit = Poseidon(holderSecret)`, computed in-circuit (v2 took it as a free input).
2. `leaf = Poseidon(1003, issuerKeyHash, credIDHi, credIDLo, holderCommit, claimAge)`.
3. `MerkleRoot(leaf, issLeafIndex, issPathElements) == issRoot` (binary Poseidon tree, depth 32;
   `issLeafIndex` range-checked to 32 bits).
4. `Poseidon(credIDHi, credIDLo)` is not in the revoked-set SMT at `revRoot`, with `smtIsOld0`
   constrained boolean.
5. The policy predicate (`age >= t` or `age < t`) holds for the committed `claimAge`, with
   `(predicateCode, threshold)` bound by `policyHash` (as v2).
6. `stmtCode = Poseidon(3, domainTag)` (v2's verifier-domain binding, new statement version).

**The issuer's epoch statement.** For each epoch the issuer signs, with ML-DSA-44, the canonical
JSON `{type: "pqid:issuer-epoch:v1", issuer, epoch, root, revRoot}`: its issuance-tree root and its
revocation root. It anchors `(root, revRoot, epoch, SHA3-256(signature))` in
`IssuanceRootRegistry`. Epochs advance by exactly one and at most once per `minAnchorInterval`.
Revocations take effect at the next epoch.

Checked by the verifier off-circuit (`packages/verifier`, `new Verifier(ledger, { circuit: "v3" })`),
on a plain-data copy of the presentation taken before any check:

- Public signals are six canonical decimal strings below the field modulus; the policy is known.
- (ii) The issuer DID resolves, is accredited, and its registered ML-DSA key hashes to the `did:pq`
  identifier; `issuerKeyHash` matches that key. (iii) `revRoot` equals the anchored epoch's revocation
  root (v2 reads `RevocationRegistry` instead). The policy hash, (iv) the single-use nonce and
  `stmtCode` as in v2. (i) Groth16 against the pinned v3 key.
- (v-a) `issuanceRootCurrent`: the attestation has exactly `issuerDid, epoch, root, revRoot,
  signature`; `issRoot`, `revRoot`, the epoch and the SHA3-256 of the signature bytes equal the
  issuer's current anchor.
- (v-b) `issuanceRootSigned`: `ML-DSA-44.Verify(pk_issuer, epoch statement, σ)`. It runs last and
  only for the one copy of a presentation that passed every other check and spent the nonce, on
  every such presentation (no cache).
- The nonce is spent only by a presentation that passed every other check.

## Protocol changes

- **Issuer** (`packages/issuer`): `createIssuerV3`; `issueCredentialV3` adds a random 32-byte
  `salt` to the credential and appends its leaf; `signIssuanceRoot(issuer, revRoot)` signs the next
  epoch statement (an unchanged pair is not re-signed; an unanchored one is superseded);
  `syncIssuanceAnchor` makes the chain the source of truth for which statement is served;
  `issuanceWitness` serves a holder's path against the ANCHORED statement (also while newer leaves are
  unsigned or a newer statement is signed but not anchored) and refuses credentials issued after it.
  Revocation openings are served from the `RevocationTree.snapshot()` whose root is anchored.
- **Ledger**: `onchain/contracts/IssuanceRootRegistry.sol` (separate file, so `Registries.sol`
  and every v2 gas figure are unchanged) stores `(root, revRoot, epoch, sigHash, publishedAt)` per
  issuer. Writes are authorized by the issuer DID's controller, like `publishRevRoot`; each epoch must
  be the previous one + 1, and a second anchor within `minAnchorInterval` seconds (default one hour)
  is refused. Ledger writes are serialized and re-read the nonce after a failure, so a reverted write
  neither stalls nor reorders later ones; `publishIssuanceRoot` is idempotent and adds a gas margin.
- **Wallet** (`packages/wallet`): `readChainViewV3` reads the anchor, the registry interval and
  the issuer's registry state itself. `buildProofInputV3` refuses to present unless the issuer is
  accredited, active and holds the credential's key; the registry interval meets the holder's floor
  (`WALLET_MIN_ANCHOR_INTERVAL_SEC`, one hour); and the attestation's exact shape, roots, epoch,
  signature bytes, path and revocation opening all match the anchor. `presentationV3` sends a freshly
  built attestation in a fixed key order. On the snarkJS path the witness (which contains
  `holderSecret`) stays in memory.
- **ML-DSA backend** (`packages/pqc`): `PQID_PQC_BACKEND=local` runs ML-DSA-44 through dilithium-py
  1.4.0 in `.venv` when the WSL liboqs build is absent (auto-selected in that case). Its verify op
  rejects non-canonical hint encodings, as FIPS 204 requires and dilithium-py 1.4.0 does not. The
  published PQC timings still come only from liboqs.

## Trusted setup

`setup/groth16_setup_v3.ts --rekey` runs `newZKey`, one snarkjs contribution with fresh OS
entropy (never written to disk), then the same public beacon as v2. The key is randomized, so
it is not byte-reproducible. Instead, `npm run setup:v3` (and `tests/circuit_v3.test.ts`, also in CI)
audits it: `snarkjs zkey verify` against the committed r1cs and ptau, a secret contribution before
the beacon, contribution hashes equal to `setup/out/v3/setup_transcript.json`, and
`verification_key.json` and `Groth16Verifier.sol` exactly as the zkey exports them. Six v3 files
are pinned in `setup/pins.json`. Soundness now rests on that one contribution staying secret; a
deployment should run a multi-party ceremony.

## Results

### Security suite (`npm run security:v3` → `results/v3/security_suite.json`)

Same host, same local chain, same accredited issuers; every attack that produces a proof is
checked by the real verifier. The attacker controls its wallet and prover completely: any
witness, hand-edited witness files, its own witness generator compiled from the circuit minus a
defence line, its own trees, ML-DSA key and DID. It cannot sign with an accredited issuer's key.

| ID | Attack | v2 | v3 |
|---|---|---|---|
| A1 | Forged credential the issuer never issued (the malicious-wallet probe) | accepted | rejected (5 routes) |
| A2 | Genuine age-16 credential claims age 42 | accepted | rejected (3 routes) |
| A3-D | Revoked holder switches to a fresh credID (9.2) | accepted | rejected (3 routes) |
| A3-E | Revoked holder keeps its credID; forged non-boolean `isOld0` | accepted | rejected (reference and attacker witness generators) |
| A3-B/C/F/G | Revoked holder: stale opening, stale root, other hand-built openings | rejected | rejected |
| A4 | Thief has the victim's credential and path but not the holder secret | accepted | rejected (2 routes) |
| A5 | Issuer B's credential presented as issuer A's | accepted | rejected (3 routes) |
| A6 | Honest proof with a tampered, foreign, missing or re-encoded root attestation | – | rejected (4 routes) |
| A7 | Attacker registers an accredited issuer's DID string with its own key first | – | rejected |
| A8 | Adversary able to write the issuer's on-chain anchor (models 9.4) anchors its own root | – | rejected by the ML-DSA check |
| T1 | Proof forged from the setup trapdoor, no credential at all (9.3) | accepted | rejected |
| R1 | Replay, cross-verifier replay, policy mismatch | – | rejected (3 routes) |
| C0–C2 | Honest holders, incl. presenting during an open batch and a signed-but-unanchored window | accepted (1/1) | accepted (7/7) |

v3: 0 of 32 attack routes accepted; v2: 7 of 11. What stopped the 32 v3 routes: a verifier
check in 17 (named per route as `failedChecks` in the JSON); the proof system in 6 (5 feed an
attacker-made witness to the real proving key and fail the R1CS, and T1's forged proof fails
Groth16 under the secret δ); and the reference witness generator's assertion in 9. Of those 9, six
stop at the issuance binding or the `isOld0` constraint, which other routes show holding at R1CS
level; three (A3-B, F, G, circomlib's `SMTVerifier` checks) are not demonstrated at R1CS level. The
suite fails closed: an unexpected exception, a non-assertion witness error, or a refusal with any
reason other than the one expected is an invalid test and fails the run. B0/B1 (an honest
revocation or issuance service refusing) are baselines, not defences.

**Privacy checks.** The defence is the holder's own wallet, since a colluding verifier reads
whatever it receives.

- PV1: four holders produce byte-identical verifier views (public signals except the nonce, plus
  the attestation) under v2 and v3.
- The honest wallet refuses all of these:
  - PV2: a re-signed signature for the current statement;
  - PV3: a path to an older statement once a newer one is anchored;
  - PV4: an attestation with an extra field, and a root that is not the anchor;
  - PV7: an opening against a per-holder revocation root;
  - PV8: a credential from an unaccredited, per-holder issuer DID.
- PV5: a permuted attestation reaches the verifier in canonical form.
- PV6 and PV7: the registry refuses an immediate re-anchor, whether meant to give one holder its
  own epoch or its own revocation root.

**Known limitation, accepted in both versions (KL1).** A relay: an intermediary opens a session
at a verifier and forwards the request to a victim's honest wallet. The fix is channel binding
(the wallet takes `verifierId` from the authenticated origin).

### Cost (`npm run compare:v3` → `results/v3/compare_v2_v3.json`)

One laptop (Intel Core Ultra 7 355, 8 logical CPUs, Windows 11, Node 24.18), one session, AC
power, benchmark guard passed; 15 interleaved rounds after 2 warm-up rounds; snarkJS only. This
is not the i7-1355U / Node 22.16 host behind the paper's numbers, so compare the columns with
each other, not with the paper.

| | v2 published (`--O1`) | v2 at `--O2` | v3 (`--O2`) |
|---|---|---|---|
| R1CS constraints | 21,715 | 10,588 | 18,683 |
| Public signals | 5 | 5 | 6 |
| snarkJS prove, median (IQR) | 714 ms (710–732) | 513 ms (495–527) | 879 ms (864–922) |
| Witness generation, median | 70 ms | 64 ms | 93 ms |
| On-chain `verifyProof` gas | 242,919 | – | 250,078 |

v3 adds 8,095 constraints over v2 at the same optimisation level (the depth-32 Merkle path is
about 250 per level) and proves 1.71× slower than it. It is compiled with `--O2` because at
circom's default `--O1` it has about 39,000 constraints, beyond the 2^15 powers-of-tau the
repository commits. The `v2 at --O2` column uses a throwaway key for timing only. `verifyProof`
gas varies by a few dozen units between proofs (calldata zero bytes).

Anchoring an epoch statement costs the issuer 120,504 gas for its first epoch and 52,330 gas for
each later one, once per epoch rather than per presentation.

## Adversarial review

Three review rounds ran against v3: independent attackers with separate focus areas, a skeptic
re-checking every finding, and (round 1) a completeness critic. None found a way to make v3 accept
a forged, never-issued, other-holder or other-issuer credential after the round-1 fixes.

- **Round 1 (27 confirmed).** Fixed:
  - the `isOld0` revocation forgery (critical);
  - DID-to-key binding;
  - the per-holder issuance root that let colluding verifiers link presentations (fixed by the
    on-chain anchor);
  - the issuer's path service locking holders out during batching;
  - non-canonical public-signal parsing;
  - rejected presentations burning the nonce;
  - the unvalidated circuit option;
  - dilithium-py's lax hint decoding;
  - the plaintext witness temp file;
  - blind spots in the setup audit;
  - a vacuous predicate test;
  - test routes that counted an attacker-controlled refusal as a defence.
- **Round 2 (25 confirmed, no circuit break).** Fixed:
  - issuer tagging through unchecked attestation data (the honest wallet now checks it against the
    chain; the verifier checks the exact shape);
  - per-holder epochs through rapid re-anchoring (registry cadence);
  - ML-DSA work reachable by junk requests, and its cache acting as a timing oracle;
  - one reverted anchor stalling every later ledger write;
  - the gap between signing and anchoring in what holders are served;
  - no snapshot of mutable input before checking;
  - unbounded nonce storage;
  - suite verdicts that failed open;
  - CI not running v3;
  - lint.
- **Round 3 (17 confirmed, no circuit break).** Fixed:
  - per-holder revocation roots (`revRoot` now belongs to the anchored, ML-DSA-signed epoch
    statement, so it follows the cadence and cannot be rolled back);
  - credentials from unaccredited per-holder DIDs (the wallet checks accreditation);
  - the cadence being off by default (now one hour, and the wallet checks it);
  - a stale revocation write overtaking a newer one (serialized ledger writes);
  - concurrent or replayed copies re-running ML-DSA (the nonce is spent first);
  - issuer state never reconciled with the chain;
  - refusal routes that could pass on any exception;
  - the gas margin on anchors;
  - sparse-array and unknown-policy input handling;
  - several reporting inaccuracies.
  These round-3 fixes were verified by the suite and tests above, but not by a further independent round.

## What v3 does not solve

- **Issuer trust.** Issuers must insert only leaves for credentials they issued, with correct attributes.
- **Registry layer (9.4 and front-running).** DID registration, accreditation, the v2 `revRoot` and
  the epoch anchor are ECDSA-authorized, and `registerDID` is first-come-first-served, with no proof
  that the registrant holds the ML-DSA key.
  - A squatter using its OWN key is rejected (A7).
  - A squatter who front-runs an issuer's registration with the issuer's GENUINE public key controls
    that DID's anchor and can keep a revoked credential accepted.
  - A8 shows that the ML-DSA check stops forged anchors.
  - The fix is a proof of possession that binds the controller account to the ML-DSA key, checked
    by governance before accreditation and by verifiers.
  - In this prototype every write uses Anvil's public dev key #0, including governance.
- **Revocation latency.** A revocation takes effect at the next epoch, so up to one
  `minAnchorInterval` later. This is the price of stopping per-holder revocation roots.
- **Age is fixed at issuance.** The leaf commits `claimAge`, so an age-16 credential proves
  "under 18" forever and never proves "18+". A sound design commits a birth date and has the
  verifier bind a cutoff date through `policyHash`; credentials should also expire.
- **Relay (KL1)**, as above.
- **Remaining metadata.**
  - Verifiers see which epoch is current.
  - Wallets that fetch paths and openings from the issuer reveal when they are about to present;
    publishing the tree and the revoked set avoids this.
  - An issuer can still spend its one epoch per interval on targeting a single holder.
  - A verifier that asks the same holder many thresholds can binary-search the committed age.
- **On-chain verification.** `Groth16Verifier.sol` checks only the Groth16 relation. A contract
  would also need to check `pub[1]` and `pub[5]` against `IssuanceRootRegistry`, and it cannot run
  the ML-DSA check.
- **Other open items.**
  - ML-KEM is still only benchmarked (9.5).
  - The depth-32 revocation SMT capacity limit (9.9) is unchanged; non-membership works to depth 31.
  - The `Verifier` still defaults to v2 so the published results reproduce; any real use must pass
    `circuit: "v3"`.

## Reproduce

```bash
npm ci
npm run setup:v3              # compile v3 and audit the committed key (no regeneration)
npx vitest run tests/circuit_v3.test.ts tests/protocol_v3.test.ts
npm run security:v3           # needs Anvil + an ML-DSA backend (see packages/pqc)
npm run compare:v3            # benchmark guard applies
```

`npx tsx setup/groth16_setup_v3.ts --rekey` generates a new v3 key with your own contribution
and re-pins it.
