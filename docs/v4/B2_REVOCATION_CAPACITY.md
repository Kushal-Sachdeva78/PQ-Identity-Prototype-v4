# B2: revocation capacity (indexed Merkle tree vs deeper SMT)

Engineering record for TASKS item B2 and review finding T8. Facts and pointers only.

- Results: `results/v4/revocation_capacity.json` (schema `pqid.v4.revocation_capacity/1`).
- Script: `harness/v4/revocation_capacity.ts`. Rerun: `npx tsx harness/v4/revocation_capacity.ts`
  (about 2 minutes; refuses to run while `results/v4/bench/RUNNING` exists).
- Gadget sources: `circuits/v4/research/*.circom` (shared templates in
  `revocation_gadgets.circom`; the IMT templates come from `circuits/v4/lib_v4.circom`).
- Compiled `.r1cs` files: `circuits/build/v4/research/<gadget>_O1.r1cs`, `_O2.r1cs` (gitignored).
- JS tree: `packages/v4/src/imt.ts`. Tests: `tests/v4/imt.test.ts`.
- Labels: [M] measured on this host, [S] computed from the stated model, [A] assumption.
- Toolchain: circom 2.2.3, snarkjs 0.7.4, circomlib 2.0.5, circomlibjs 0.1.7 (recorded in the JSON).

## Target and decision rule

- Target: at least 10^9 revocations per issuer, failure probability at most 2^-40 at that load.
- Criterion A: per-insertion failure probability at load 10^9 is at most 2^-40.
- Criterion B: cumulative failure probability over 10^9 insertions is at most 2^-40.
  B is stricter and is used for the decision.
- Rule: among options meeting B, adopt the one with the fewest constraints at `--O2`
  (the setting v4 compiles with). `--O1` is recorded too (T9).

## Gadgets measured [M]

Both sides take the same private credID limbs and pay for their own key derivation
("full" variant, public input `root` only):

- IMT: Num2Bits(128) on credIDHi and credIDLo, revKey as a linear combination of the bits
  (V4_DESIGN 1, G05), then `ImtNonMembership(d)`: Poseidon(3) leaf, MerkleRootV4(d) with
  Num2Bits(d) on lowIndex, two LessThan(252).
- SMT: the same Num2Bits(128) limb checks, key = Poseidon(credIDHi, credIDLo) as in v3,
  circomlib `SMTVerifier(d)` with fnc = 1, enabled = 1, value = 0, plus the v3 revocation-gadget
  fix (details under embargo, D-008).
- "bare" variants: tree part only, key as a public input (public inputs `key`, `root`).

| Gadget | Variant | Constraints --O2 | Constraints --O1 (non-linear + linear) |
|---|---|---:|---:|
| imt_d30 | full | 8,278 | 17,007 (8,376 + 8,631) |
| imt_d32 | full | 8,762 | 18,049 (8,866 + 9,183) |
| smt_d32 | full | 9,764 | 20,122 (10,156 + 9,966) |
| smt_d70 | full | 19,226 | 40,414 (19,770 + 20,644) |
| smt_d71 | full | 19,475 | 40,948 (20,023 + 20,925) |
| smt_d99 | full | 26,447 | 55,900 (27,107 + 28,793) |
| smt_d100 | full | 26,696 | 56,434 (27,360 + 29,074) |
| smt_d128 | full | 33,668 | 71,386 (34,444 + 36,942) |
| imt_bare_d30 | bare | 8,022 | 16,748 |
| imt_bare_d32 | bare | 8,506 | 17,790 |
| smt_bare_d32 | bare | 9,268 | 19,347 |
| smt_bare_d70 | bare | 18,730 | 39,639 |
| smt_bare_d71 | bare | 18,979 | 40,173 |
| smt_bare_d99 | bare | 25,951 | 55,125 |
| smt_bare_d100 | bare | 26,200 | 55,659 |
| smt_bare_d128 | bare | 33,172 | 70,611 |

Derived from the counts above (`perLevelConstraintsO2` in the JSON) [M]:

- Cost per tree level at --O2: IMT 242, SMT 249 (the SMT step is 249 between every
  measured pair: 70 to 71, 99 to 100, and on average from 32 to 128).
- Key derivation at --O2: IMT 256 (the two Num2Bits(128)), SMT 496 (the two
  Num2Bits(128) plus Poseidon(2)).
- At --O2 every gadget has 0 linear constraints left.

Depths 71 and 100 were added to the planned set (32, 70, 99, 128) because of the depth
limit below.

## Depth boundary checks on the compiled circuits [M]

- circomlib `SMTLevIns(nLevels)` requires the last sibling to be 0, so `SMTVerifier(d)`
  only verifies leaves at depth d - 1 or less. Effective path bits: b = d - 1.
  - Check (`smtDepthBoundary`, circuit `smt_nonmembership_bare_d32`): revoked keys 1 and
    1 + 2^30 (30 shared low bits, leaves at depth 31): witness accepted, R1CS satisfied.
    Revoked keys 1 and 1 + 2^31 (31 shared low bits, leaves at depth 32): the witness
    generator rejects (Assert Failed in SMTLevIns).
  - Same check at depth 4 in `tests/v4/imt.test.ts` (paths of 3 levels accepted, paths of
    4 levels rejected).
- The IMT uses all 2^d slots: `imtIndexBoundary` (circuit `imt_nonmembership_d30`)
  accepts lowIndex = 2^30 - 1 and rejects lowIndex = 2^30. Index 0 is the sentinel, so
  depth d holds 2^d - 1 keys.

## Capacity model [S]

- IMT, depth d: capacity 2^d - 1 keys. Insertion is deterministic (the low leaf always
  exists), so the insertion failure probability is 0 below capacity. The only
  probabilistic event is two credentials with the same 251-bit revKey: union bound
  n(n-1) / 2^252 [A: revKey behaves as uniform].
- SMT with b effective path bits: circomlibjs places a key at the first level where its
  path prefix (key bits, least significant first) is unique; two keys sharing their low
  j bits sit at depth j + 1. A failure is two keys sharing all b path bits.
  - Per insertion at load n: at most n / 2^b.
  - Cumulative over n insertions: at most n(n-1) / 2^(b+1) (birthday union bound;
    Poisson approximation 1 - exp(-n(n-1) / 2^(b+1)) also recorded).
  - Expected failed insertions among n inserts: n - 2^b (1 - (1 - 2^-b)^n).
- Two models are reported for the SMT: "nominal" b = d (the review's model and the B2
  task text) and "circuit limit" b = d - 1 (measured above). The decision uses the
  circuit limit.
- Minimum path bits at n = 10^9:
  - A: ceil(log2(10^9) + 40) = 70.
  - B: ceil(log2(10^9 (10^9 - 1)) - 1 + 40) = 99.
  - As circomlib SMTVerifier depth: A needs d = 71, B needs d = 100 (nominal model: 70 and 99).

## Capacity per option at n = 10^9 [S]

| Option | --O2 | Capacity or max load at 2^-40 (B) | Per-insertion failure at 10^9 | Cumulative failure at 10^9 | Meets A | Meets B |
|---|---:|---|---|---|---|---|
| imt_d30 | 8,278 | 2^30 - 1 = 1,073,741,823 keys | 0 (revKey collision 2^-192.2) | 0 (revKey collision 2^-192.2) | yes | yes |
| imt_d32 | 8,762 | 2^32 - 1 = 4,294,967,295 keys | 0 (revKey collision 2^-192.2) | 0 (revKey collision 2^-192.2) | yes | yes |
| smt_d32 | 9,764 | 1 key | 2^-1.10 | about 1 (bound 2^27.8) | no | no |
| smt_d70 | 19,226 | 32,768 keys | 2^-39.10 | 2^-10.21 | no | no |
| smt_d71 | 19,475 | 46,341 keys | 2^-40.10 | 2^-11.21 | yes | no |
| smt_d99 | 26,447 | 759,250,125 keys | 2^-68.10 | 2^-39.21 | yes | no |
| smt_d100 | 26,696 | 1,073,741,824 keys | 2^-69.10 | 2^-40.21 | yes | yes |
| smt_d128 | 33,668 | about 1.76 x 10^13 keys | 2^-97.10 | 2^-68.21 | yes | yes |

SMT rows use the circuit limit b = d - 1. Under the nominal model (b = d), smt_d99 meets B
and smt_d70 meets A; everything else is unchanged.

## Decision

- Qualifying (B): imt_d30, imt_d32, smt_d100, smt_d128.
- Adopted: **IMT, depth 30**, 8,278 constraints at --O2 (17,007 at --O1).
- Smallest qualifying SMT: smt_d100, 26,696 at --O2, 3.22 times the IMT (3.32 times at --O1).
- The choice is the same at --O1 and under the nominal SMT model (`sameChoiceAtO1`,
  `sameChoiceUnderNominalSmtModel` in the JSON).
- `REV_DEPTH = 30` in `packages/v4/src/constants.ts` matches (`revDepthConstantMatches`).
- Headroom at depth 30: 2^30 - 1 is 1.0737 times 10^9 (about 7.4 percent spare).

## Cross-check of review finding T8 (v3, depth-32 SMT) [S]

Review figures (2.0/Review.txt, T8): 50 percent failure chance at about 77,000
revocations; about 116 failed insertions per million.

| Quantity | Review | Nominal model, b = 32 | Circuit limit, b = 31 |
|---|---:|---:|---:|
| Revocations at 50 percent failure chance (exact product) | about 77,000 | 77,164 | 54,563 |
| Same, approximation sqrt(2 ln 2 x 2^b) | | 77,163 | 54,562 |
| Expected failed insertions per 10^6 (occupancy) | about 116 | 116.41 | 232.79 |
| Simulation: mean failures per 10^6 (50 runs) | | 116.96 | 235.58 |
| Simulation: median first failure (2,000 runs) | | 75,554 | 55,210 |

- The review's numbers match the 32-bit model. v3's circuit, `SMTVerifier(32)`, only
  verifies paths of 31 levels (measured above), so for v3 as built the figures are about
  54,600 (50 percent point) and about 233 failures per million.
- Simulation: seeded xoshiro128** draws of b-bit prefixes (seeds in the JSON), so the
  numbers are reproducible.

## Machine evidence for the IMT gadget (for C4)

`tests/v4/imt.test.ts` (16 tests, all passing):

- JS tree at depth 4 and at REV_DEPTH: insert, linked-list invariant, dense reference
  root, non-membership witnesses verify, revoked keys have no witness, duplicates and
  out-of-range keys rejected, capacity 2^d - 1 enforced, tampering of every witness field
  rejected by `verifyNonMembership`.
- bulkBuild root equals incremental insertion in the same order (depth 30 with 120 keys,
  depth 10 with 700 keys; also sorted order), and both stay equal on later inserts.
- Predecessor search across the 65,536 buckets agrees with a linear scan (clustered and
  spread keys, empty groups).
- Exhaustive at depth 3: all 255 key sets of up to 7 keys from an 8-key universe, 35
  probe keys each: a witness exists iff the key is absent, every leaf opening is a valid
  Merkle path, and `verifyNonMembership` accepts exactly the one bracketing low leaf
  (none for revoked or out-of-range keys).
- Circuit `circuits/v4/research/imt_nonmembership_d4.circom` (compiled --O2 in a temp dir):
  - honest witnesses (revKey from real credID limbs; low leaf at the last slot 15 of a full
    tree) pass `snarkjs wtns calculate` and `wtns check`;
  - for 3 non-members and 3 revoked keys against every occupied leaf, the witness
    generator accepts exactly the bracketing leaf and agrees with the JS twin in every case;
  - credID limbs of 2^128 are rejected;
  - an honest witness with the lowNext wire set to the key, or with a different root wire,
    fails `wtns check` (R1CS level).

## Open items and limits

- The JS tree is in memory. 10^9 keys would need a disk-backed store and about 2 x 10^9
  Poseidon calls to build [F]. Unit tests use up to 700 keys; a one-off functional check
  (not a benchmark, not recorded) built 2 x 10^5 keys. Timed scale runs belong to E4.
- The published-tree format (`serialize()`): 48-byte header plus 32 bytes per key,
  nextValues rebuilt on load, root checked. 10^6 keys is 32,000,048 bytes [S: formula].
- LessThan(252) soundness needs lowValue and lowNext below 2^252; this holds for trees
  built by the issuer code (values below 2^251, sentinel 2^251). `verifyNonMembership`
  rejects larger values.
- The measured counts depend on `circuits/v4/lib_v4.circom`; its SHA-256 at measurement
  time is in the JSON (`sources`). Rerun the script if the IMT templates change.
- v3's JS (`packages/revocation`) accepts sibling paths of length 32, which its
  `SMTVerifier(32)` rejects (see the depth check). v3 is frozen; recorded here only.
