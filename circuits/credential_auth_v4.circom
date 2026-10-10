pragma circom 2.2.3;

// ============================================================================
// credential_auth v4 (development circuit; spec: docs/v4/V4_DESIGN.md section 2)
//
// Relation R4 over BN254 (Poseidon). Public signals, in order (8):
//   [issuerKeyHash, revRoot, policyHash, nonce, stmtCode, issRoot,
//    epochFromDate, epochToDate]
//
// What changed from v3 (circuits/credential_auth_v3.circom):
//   - the issued leaf commits birthDate, expiryDate and credType instead of an age;
//   - the verifier chooses today's date, the predicate, the threshold and the
//     required credential type, all bound through policyHash;
//   - the age predicate is evaluated as of `today`; the credential must not be
//     expired on `today`; its type must equal the required type; `today` must lie
//     in the issuer-signed epoch window [epochFromDate, epochToDate];
//   - the threshold must be one of the standard thresholds;
//   - revocation uses an indexed Merkle tree (non-membership through the low
//     leaf that brackets the revocation key) instead of circomlib's SMTVerifier.
//
// Dates are YYYYMMDD integers (UTC). "age >= t on day D" iff birth + 10000*t <= D.
//
// Mutation markers (used by harness/v4/mutate.ts; this file compiles as is):
//   - each constraint group is wrapped in `// @@<group>` ... `// @@end`;
//   - a line ending in `// @check` is a check constraint (an `===` whose failure means
//     the defence stopped the witness);
//   - an optional `// @@mutant` section holds commented replacement lines.
// Group mutant (mutation table, C3): use the @@mutant replacement if the group has one,
// else drop the group's @check lines, else drop the whole group (G11 ranges, G17 nonce).
// Attacker generator (R1CS-level routes, C1): drop EVERY @check line and compile at
// --O0; its witness is mapped into this circuit's --O2 wire layout by signal name
// (.sym files), and the real R1CS then names exactly the checks the attack violates.
// Range checks inside circomlib's Num2Bits remain in the attacker generator.
// ============================================================================

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "v4/lib_v4.circom";

template CredentialAuthV4(issLevels, revLevels) {
    // ------------------------------------------------------------- public (8)
    signal input issuerKeyHash;  // PoseidonFold(pk_issuer); checked by the verifier
    signal input revRoot;        // IMT root in the issuer's anchored epoch statement
    signal input policyHash;     // Poseidon(1006, predicateCode, threshold, today, requiredType)
    signal input nonce;          // derived from the ML-KEM session transcript
    signal input stmtCode;       // Poseidon(4, domainTag)
    signal input issRoot;        // issuance-tree root in the anchored epoch statement
    signal input epochFromDate;  // first date of the epoch statement's validity window
    signal input epochToDate;    // last date of the epoch statement's validity window

    // ---------------------------------------------------------------- private
    signal input credIDHi;       // SHA3-256 credID bytes 0..15
    signal input credIDLo;       // SHA3-256 credID bytes 16..31
    signal input holderSecret;
    signal input birthDate;      // committed in the issued leaf
    signal input expiryDate;     // committed in the issued leaf
    signal input credType;       // committed in the issued leaf
    signal input predicateCode;  // 1 = AGE_GTE, 2 = AGE_LT
    signal input threshold;      // years
    signal input today;          // verifier's current date
    signal input requiredType;   // credential type the verifier requires
    signal input domainTag;      // verifier identifier fold
    signal input issLeafIndex;
    signal input issPathElements[issLevels];
    signal input revLowIndex;
    signal input revLowValue;
    signal input revLowNext;
    signal input revLowPath[revLevels];

    signal holderCommit;
    signal leafHash;
    signal revKey;

    // @@G02_holder_commit
    component holder = Poseidon(1);
    holder.inputs[0] <== holderSecret;
    holderCommit <== holder.out;
    // @@mutant
    // signal input mutHolderCommit;
    // holderCommit <== mutHolderCommit;
    // @@end

    // @@G03_leaf
    component leaf = Poseidon(8);
    leaf.inputs[0] <== 1004; // CRED_LEAF_V4
    leaf.inputs[1] <== issuerKeyHash;
    leaf.inputs[2] <== credIDHi;
    leaf.inputs[3] <== credIDLo;
    leaf.inputs[4] <== holderCommit;
    leaf.inputs[5] <== birthDate;
    leaf.inputs[6] <== expiryDate;
    leaf.inputs[7] <== credType;
    leafHash <== leaf.out;
    // @@mutant
    // signal input mutLeaf;
    // leafHash <== mutLeaf;
    // @@end

    // @@G04_issuance_membership
    component iss = MerkleRootV4(issLevels);
    iss.leaf <== leafHash;
    iss.leafIndex <== issLeafIndex;
    for (var i = 0; i < issLevels; i++) {
        iss.pathElements[i] <== issPathElements[i];
    }
    iss.root === issRoot; // @check
    // @@end

    // @@G05_revkey
    // Canonical 128-bit limbs; revKey = credIDHi * 2^123 + floor(credIDLo / 2^5) < 2^251,
    // a linear combination of the bits, so it is tied to the credID opened from the leaf.
    component hiBits = Num2Bits(128);
    hiBits.in <== credIDHi;
    component loBits = Num2Bits(128);
    loBits.in <== credIDLo;
    var rk = 0;
    for (var i = 0; i < 128; i++) {
        rk += hiBits.out[i] * (2 ** (123 + i));
    }
    for (var i = 5; i < 128; i++) {
        rk += loBits.out[i] * (2 ** (i - 5));
    }
    revKey <== rk;
    // @@mutant
    // signal input mutRevKey;
    // revKey <== mutRevKey;
    // @@end

    // @@G06_rev_low_membership
    component revMember = ImtLowLeafRoot(revLevels);
    revMember.lowIndex <== revLowIndex;
    revMember.lowValue <== revLowValue;
    revMember.lowNext <== revLowNext;
    for (var i = 0; i < revLevels; i++) {
        revMember.lowPath[i] <== revLowPath[i];
    }
    revMember.root === revRoot; // @check
    // @@end

    // @@G07_rev_bracket
    component revBracket = ImtBracket();
    revBracket.key <== revKey;
    revBracket.lowValue <== revLowValue;
    revBracket.lowNext <== revLowNext;
    revBracket.belowOk === 1; // @check
    revBracket.aboveOk === 1; // @check
    // @@end

    // @@G08_policy_hash
    component pol = Poseidon(5);
    pol.inputs[0] <== 1006; // POLICY_V4
    pol.inputs[1] <== predicateCode;
    pol.inputs[2] <== threshold;
    pol.inputs[3] <== today;
    pol.inputs[4] <== requiredType;
    pol.out === policyHash; // @check
    // @@end

    // @@G09_predicate_code
    (predicateCode - 1) * (predicateCode - 2) === 0; // @check
    // @@end

    // @@G10_standard_threshold
    // threshold in {13, 14, 15, 16, 18, 21, 65} (constants STANDARD_THRESHOLDS)
    var std[7] = [13, 14, 15, 16, 18, 21, 65];
    signal thrAcc[7];
    thrAcc[0] <== threshold - std[0];
    for (var i = 1; i < 7; i++) {
        thrAcc[i] <== thrAcc[i - 1] * (threshold - std[i]);
    }
    thrAcc[6] === 0; // @check
    // @@end

    // @@G11_ranges
    // Comparator preconditions: dates < 2^27, threshold < 2^8.
    component rBirth = Num2Bits(27);
    rBirth.in <== birthDate;
    component rExpiry = Num2Bits(27);
    rExpiry.in <== expiryDate;
    component rToday = Num2Bits(27);
    rToday.in <== today;
    component rFrom = Num2Bits(27);
    rFrom.in <== epochFromDate;
    component rTo = Num2Bits(27);
    rTo.in <== epochToDate;
    component rThr = Num2Bits(8);
    rThr.in <== threshold;
    // @@end

    // @@G12_age
    // reached = (birthDate + 10000*threshold <= today); code 1 needs reached = 1,
    // code 2 needs reached = 0: reached == 2 - predicateCode.
    component reached = LessEqThan(28);
    reached.in[0] <== birthDate + 10000 * threshold;
    reached.in[1] <== today;
    reached.out === 2 - predicateCode; // @check
    // @@end

    // @@G13_expiry
    component notExpired = LessEqThan(27);
    notExpired.in[0] <== today;
    notExpired.in[1] <== expiryDate;
    notExpired.out === 1; // @check
    // @@end

    // @@G14_type
    credType === requiredType; // @check
    // @@end

    // @@G15_epoch_window
    component afterFrom = LessEqThan(27);
    afterFrom.in[0] <== epochFromDate;
    afterFrom.in[1] <== today;
    afterFrom.out === 1; // @check
    component beforeTo = LessEqThan(27);
    beforeTo.in[0] <== today;
    beforeTo.in[1] <== epochToDate;
    beforeTo.out === 1; // @check
    // @@end

    // @@G16_stmt
    component stmt = Poseidon(2);
    stmt.inputs[0] <== 4; // STMT_V4
    stmt.inputs[1] <== domainTag;
    stmt.out === stmtCode; // @check
    // @@end

    // @@G17_nonce
    // The nonce enters no other constraint; square it so it is part of the system.
    signal nonceSq;
    nonceSq <== nonce * nonce;
    // @@end
}

component main {public [issuerKeyHash, revRoot, policyHash, nonce, stmtCode, issRoot, epochFromDate, epochToDate]} =
    CredentialAuthV4(32, 30);
