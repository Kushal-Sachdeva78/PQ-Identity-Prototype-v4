pragma circom 2.2.3;

// ============================================================================
// credential_auth v3 — issuance-bound credential circuit for the PQ-ID prototype
//
// What changed from v2 (circuits/credential_auth.circom):
//   In v2, claimAge, holderCommit and credIDHi/Lo were private inputs that no
//   public value constrained, so any prover could pick them freely and the
//   issuer's Dilithium signature was checked only by the (possibly malicious)
//   wallet (Assumption 5). results/malicious_probe.json records a forged,
//   never-issued credential being ACCEPTED under v2.
//
//   v3 ties every attribute the proof uses to an ISSUER-SIGNED commitment:
//     - the issuer keeps an append-only Poseidon Merkle tree of issued
//       credential leaves and signs each root with ML-DSA-44 (Dilithium);
//     - the VERIFIER checks that signature against pk_issuer resolved on-chain
//       and checks it signs exactly the public signal issRoot;
//     - in-circuit, the prover must open a leaf of that tree, and holderCommit,
//       claimAge and credID are read from the opened leaf — not chosen freely;
//     - the revocation key is derived from the SAME credID limbs, so a revoked
//       holder cannot switch to a fresh credID (finding 9.2).
//
// In-circuit relation R3 (Poseidon over BN254):
//   (1) holderCommit = Poseidon(holderSecret)                (holder binding)
//   (2) leaf = Poseidon(CRED_LEAF_V1, issuerKeyHash, credIDHi, credIDLo,
//                       holderCommit, claimAge)              (credential leaf)
//   (3) MerkleRoot(leaf, issLeafIndex, issPathElements) == issRoot
//                                                  (issued by the signing issuer)
//   (4) Poseidon(credIDHi, credIDLo) is NOT in the revoked-set SMT at revRoot
//       (depth-32 non-membership; smtIsOld0 constrained boolean, which
//        circomlib's SMTVerifier omits)
//   (5) policy: predicateCode 1 (AGE_GTE): claimAge >= threshold
//               predicateCode 2 (AGE_LT) : claimAge <  threshold
//       with (predicateCode, threshold) bound by policyHash
//   (6) stmtCode = Poseidon(STMT_V3, domainTag)       (verifier-domain binding)
//
// Checked by the verifier OFF-circuit (packages/verifier, circuit "v3"):
//   - ML-DSA-44.Verify(pk_issuer, issuanceRootMessage(issuerDid, epoch,
//     issRoot), sigma_root) with pk_issuer resolved from the DID Registry;
//   - issuerKeyHash == PoseidonFold(pk_issuer); revRoot == on-chain root;
//     policyHash, nonce freshness and stmtCode as in v2.
//
// Public signals, in order (6):
//   [issuerKeyHash, revRoot, policyHash, nonce, stmtCode, issRoot]
// Private inputs (75):
//   credIDHi, credIDLo, holderSecret, claimAge, threshold, predicateCode,
//   domainTag, issLeafIndex, issPathElements[32], smtSiblings[32], smtOldKey,
//   smtOldValue, smtIsOld0
// ============================================================================

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";

// Binary Poseidon Merkle path from a leaf at position leafIndex to the root.
// Bit i of leafIndex selects the order at level i: 0 -> (cur, sibling),
// 1 -> (sibling, cur). Num2Bits range-checks leafIndex < 2^nLevels, so the
// leaf sits at exactly depth nLevels (an internal node cannot pose as a leaf).
template MerkleRoot(nLevels) {
    signal input leaf;
    signal input leafIndex;
    signal input pathElements[nLevels];
    signal output root;

    component idxBits = Num2Bits(nLevels);
    idxBits.in <== leafIndex;

    component h[nLevels];
    signal cur[nLevels + 1];
    signal swap[nLevels];
    cur[0] <== leaf;
    for (var i = 0; i < nLevels; i++) {
        swap[i] <== (pathElements[i] - cur[i]) * idxBits.out[i];
        h[i] = Poseidon(2);
        h[i].inputs[0] <== cur[i] + swap[i];
        h[i].inputs[1] <== pathElements[i] - swap[i];
        cur[i + 1] <== h[i].out;
    }
    root <== cur[nLevels];
}

template CredentialAuthV3(revLevels, issLevels) {
    // ------------------------------------------------------------ public (6)
    // Declaration order is the public-signal order.
    signal input issuerKeyHash; // PoseidonFold(pk_issuer), checked by the verifier
    signal input revRoot;       // issuer's current revocation SMT root (on-chain)
    signal input policyHash;    // Poseidon(predicateCode, threshold)
    signal input nonce;         // verifier-chosen session nonce (freshness)
    signal input stmtCode;      // Poseidon(STMT_V3, domainTag)
    signal input issRoot;       // issuance-tree root signed by the issuer (ML-DSA-44)

    // ----------------------------------------------------------- private (75)
    signal input credIDHi;      // SHA3-256(cred ‖ pk_issuer) bytes  0..15, < 2^128
    signal input credIDLo;      // SHA3-256(cred ‖ pk_issuer) bytes 16..31, < 2^128
    signal input holderSecret;  // wallet-held secret behind holderCommit
    signal input claimAge;      // committed in the issued leaf
    signal input threshold;     // request.policy.threshold
    signal input predicateCode; // 1 = AGE_GTE, 2 = AGE_LT (bound via policyHash)
    signal input domainTag;     // verifier identifier fold (bound via stmtCode)
    signal input issLeafIndex;  // position of the credential leaf in the issuance tree
    signal input issPathElements[issLevels];
    signal input smtSiblings[revLevels];
    signal input smtOldKey;     // non-membership witness: key of the leaf found (or 0)
    signal input smtOldValue;   //                          value of the leaf found (or 0)
    signal input smtIsOld0;     // 1 iff the addressed slot is empty

    var STMT_V3 = 3;
    var CRED_LEAF_V1 = 1003;

    // (0) canonical 128-bit packing of the SHA3-256 credID limbs
    component hiBits = Num2Bits(128);
    hiBits.in <== credIDHi;
    component loBits = Num2Bits(128);
    loBits.in <== credIDLo;

    // (1) holder binding, computed in-circuit (v2 took holderCommit as a free input)
    component holder = Poseidon(1);
    holder.inputs[0] <== holderSecret;

    // 32-bit range checks make the comparators sound over the field
    component ageBits = Num2Bits(32);
    ageBits.in <== claimAge;
    component thrBits = Num2Bits(32);
    thrBits.in <== threshold;

    // (2) the credential leaf the issuer inserted at issuance
    component leaf = Poseidon(6);
    leaf.inputs[0] <== CRED_LEAF_V1;
    leaf.inputs[1] <== issuerKeyHash;
    leaf.inputs[2] <== credIDHi;
    leaf.inputs[3] <== credIDLo;
    leaf.inputs[4] <== holder.out;
    leaf.inputs[5] <== claimAge;

    // (3) membership in the issuer-signed issuance tree
    component iss = MerkleRoot(issLevels);
    iss.leaf <== leaf.out;
    iss.leafIndex <== issLeafIndex;
    for (var i = 0; i < issLevels; i++) {
        iss.pathElements[i] <== issPathElements[i];
    }
    iss.root === issRoot;

    // (4) revocation non-membership; the key comes from the SAME credID limbs
    // that were opened from the issued leaf, so it cannot be swapped
    component keyHash = Poseidon(2);
    keyHash.inputs[0] <== credIDHi;
    keyHash.inputs[1] <== credIDLo;

    // circomlib's SMTVerifier never constrains isOld0 to {0,1}. With a
    // non-boolean isOld0 the level-L node becomes Hash1(oldKey,oldValue)*(1-isOld0),
    // which a prover can set to the REVOKED leaf and so "prove" non-membership
    // of a revoked key (found in the v3 review; v2 has the same gap).
    smtIsOld0 * (smtIsOld0 - 1) === 0;

    component smt = SMTVerifier(revLevels);
    smt.enabled <== 1;
    smt.root <== revRoot;
    for (var i = 0; i < revLevels; i++) {
        smt.siblings[i] <== smtSiblings[i];
    }
    smt.oldKey <== smtOldKey;
    smt.oldValue <== smtOldValue;
    smt.isOld0 <== smtIsOld0;
    smt.key <== keyHash.out;
    smt.value <== 0;
    smt.fnc <== 1; // 1 = exclusion (non-membership) proof

    // (5) policy: (predicateCode, threshold) pinned by the public policyHash
    component pol = Poseidon(2);
    pol.inputs[0] <== predicateCode;
    pol.inputs[1] <== threshold;
    pol.out === policyHash;

    // predicateCode ∈ {1, 2}
    (predicateCode - 1) * (predicateCode - 2) === 0;

    component ge = GreaterEqThan(32);
    ge.in[0] <== claimAge;
    ge.in[1] <== threshold;
    component lt = LessThan(32);
    lt.in[0] <== claimAge;
    lt.in[1] <== threshold;

    // select the predicate result: code 1 -> ge, code 2 -> lt; require it holds
    signal geTerm;
    geTerm <== ge.out * (2 - predicateCode);
    signal ltTerm;
    ltTerm <== lt.out * (predicateCode - 1);
    geTerm + ltTerm === 1;

    // (6) verifier-domain separation (as v2, with the v3 statement version)
    component stmt = Poseidon(2);
    stmt.inputs[0] <== STMT_V3;
    stmt.inputs[1] <== domainTag;
    stmt.out === stmtCode;

    // The nonce enters no other constraint; square it so it is not dangling.
    // (issuerKeyHash is now bound through the leaf, so v2's square is dropped.)
    signal nonceSq;
    nonceSq <== nonce * nonce;
}

component main {public [issuerKeyHash, revRoot, policyHash, nonce, stmtCode, issRoot]} =
    CredentialAuthV3(32, 32);
