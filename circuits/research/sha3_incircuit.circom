pragma circom 2.2.3;

// ============================================================================
// [F] RESEARCH CIRCUIT — constraint-count report ONLY. Never benchmarked,
// never part of the production protocol, never given a trusted setup.
//
// Purpose: quantify why the paper's relation R cannot verify
// credID = SHA3-256(cred ‖ pk_issuer) in-circuit within the ~21k-constraint
// budget (Gap 1). This instantiates ONE Keccak-f[1600] sponge absorption
// (up to 1,088 input bits = one rate block) producing a 256-bit digest.
//
// Notes:
//   - Keccak-256 is used as the constraint-count proxy for SHA3-256: the
//     permutation and rate are identical; FIPS-202 SHA3 differs only in the
//     padding domain bits, which does not change the constraint count class.
//   - The real preimage cred ‖ pk_issuer is ≥ 1,312 + |cred| bytes
//     (≥ 11 rate blocks → ≥ 11 permutations), and a depth-32 SHA-3 Merkle
//     path would add 32 more permutations. Multiply accordingly.
// ============================================================================

include "../../node_modules/keccak256-circom/circuits/keccak.circom";

// One sponge absorption (single Keccak-f[1600] permutation): 512 input bits
// -> 256 output bits. The library's Pad template requires input < rate
// (1,088 bits), so 512 bits is used; the constraint count is dominated by the
// permutation and is the per-block figure used for extrapolation.
component main = Keccak(512, 256);
