pragma circom 2.2.3;

// ============================================================================
// credential_auth v2 — production circuit for the PQ-ID prototype
// (IEEE Access-2026-15409, Section III-B; relation R with the Gap-1 resolution;
//  V6 revision: verifier-domain separation + generalized policy predicate)
//
// In-circuit relation R′ (Poseidon-based; see ARCHITECTURE.md):
//   (1) smtKey = Poseidon(credIDHi, credIDLo) is NOT a member of the revoked-set
//       sparse Merkle tree anchored at public revRoot (depth-32 non-membership);
//   (2) holder binding: Poseidon(holderSecret) == holderCommit, where
//       holderCommit is carried inside the issuer-signed credential;
//   (3) policy: the predicate selected by predicateCode holds —
//         predicateCode 1 (AGE_GTE): claimAge >= threshold
//         predicateCode 2 (AGE_LT) : claimAge <  threshold
//       with (predicateCode, threshold) bound to the public
//       policyHash = Poseidon(predicateCode, threshold);
//   (4) verifier-domain separation: stmtCode = Poseidon(STMT_V1, domainTag),
//       where domainTag identifies the requesting verifier — a proof produced
//       for one verifier cannot be replayed at another (V6 §F3).
//
// Explicitly NOT in-circuit (trust boundary, Figure 1 of the paper):
//   - credID = SHA3-256(cred ‖ pk_issuer) is computed OFF-circuit; its binding
//     to the issuer key is enforced by (a) the wallet's off-circuit Dilithium
//     verification and (b) the verifier's on-chain pk_issuer resolution +
//     equality check against public signal issuerKeyHash.
//   - The issuer's Dilithium signature is verified OFF-circuit (Assumption 5).
//
// Public signals, in order (5):
//   [issuerKeyHash, revRoot, policyHash, nonce, stmtCode]
// Private inputs (43):
//   credIDHi, credIDLo, holderSecret, holderCommit, claimAge, threshold,
//   predicateCode, domainTag, smtSiblings[32], smtOldKey, smtOldValue, smtIsOld0
// ============================================================================

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/smt/smtverifier.circom";

template CredentialAuth(nLevels) {
    // ------------------------------------------------------------ public (5)
    signal input issuerKeyHash; // Poseidon fold of pk_issuer (1312 B), computed off-circuit
    signal input revRoot;       // issuer's current revocation SMT root
    signal input policyHash;    // Poseidon(predicateCode, threshold)
    signal input nonce;         // verifier-chosen session nonce (freshness)
    signal input stmtCode;      // Poseidon(STMT_V1, domainTag) — domain-bound statement

    // ----------------------------------------------------------- private (43)
    signal input credIDHi;      // SHA3-256(cred ‖ pk_issuer) bytes  0..15, big-endian, < 2^128
    signal input credIDLo;      // SHA3-256(cred ‖ pk_issuer) bytes 16..31, big-endian, < 2^128
    signal input holderSecret;  // wallet-held secret
    signal input holderCommit;  // = cred.holderCommit from the signed VC
    signal input claimAge;      // cred.claims.age
    signal input threshold;     // request.policy.threshold
    signal input predicateCode; // 1 = AGE_GTE, 2 = AGE_LT (bound via policyHash)
    signal input domainTag;     // verifier/context identifier (bound via stmtCode)
    signal input smtSiblings[nLevels];
    signal input smtOldKey;     // non-membership witness: key of the leaf found (or 0)
    signal input smtOldValue;   //                          value of the leaf found (or 0)
    signal input smtIsOld0;     // 1 iff the addressed slot is empty

    var STMT_V1 = 1;

    // (0) canonical 128-bit packing of the SHA3-256 credID limbs
    component hiBits = Num2Bits(128);
    hiBits.in <== credIDHi;
    component loBits = Num2Bits(128);
    loBits.in <== credIDLo;

    // (1) revocation non-membership: smtKey = Poseidon(credIDHi, credIDLo)
    component keyHash = Poseidon(2);
    keyHash.inputs[0] <== credIDHi;
    keyHash.inputs[1] <== credIDLo;

    component smt = SMTVerifier(nLevels);
    smt.enabled <== 1;
    smt.root <== revRoot;
    for (var i = 0; i < nLevels; i++) {
        smt.siblings[i] <== smtSiblings[i];
    }
    smt.oldKey <== smtOldKey;
    smt.oldValue <== smtOldValue;
    smt.isOld0 <== smtIsOld0;
    smt.key <== keyHash.out;
    smt.value <== 0;
    smt.fnc <== 1; // 1 = exclusion (non-membership) proof

    // (2) holder binding: knowledge of the secret behind the VC's commitment
    component holder = Poseidon(1);
    holder.inputs[0] <== holderSecret;
    holder.out === holderCommit;

    // (3) policy: (predicateCode, threshold) pinned by the public policyHash
    component pol = Poseidon(2);
    pol.inputs[0] <== predicateCode;
    pol.inputs[1] <== threshold;
    pol.out === policyHash;

    // predicateCode ∈ {1, 2}
    (predicateCode - 1) * (predicateCode - 2) === 0;

    // 32-bit range checks make the comparators sound over the field
    component ageBits = Num2Bits(32);
    ageBits.in <== claimAge;
    component thrBits = Num2Bits(32);
    thrBits.in <== threshold;

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

    // (4) verifier-domain separation: stmtCode binds the statement version AND
    // the verifier identity, so a proof for one verifier is unusable at another
    component stmt = Poseidon(2);
    stmt.inputs[0] <== STMT_V1;
    stmt.inputs[1] <== domainTag;
    stmt.out === stmtCode;

    // Bind the remaining public signals into the constraint system so no
    // public input is dangling (they are statement-binding inputs; the
    // verifier checks their values off-circuit against on-chain state).
    signal issuerKeyHashSq;
    issuerKeyHashSq <== issuerKeyHash * issuerKeyHash;
    signal nonceSq;
    nonceSq <== nonce * nonce;
}

component main {public [issuerKeyHash, revRoot, policyHash, nonce, stmtCode]} =
    CredentialAuth(32);
