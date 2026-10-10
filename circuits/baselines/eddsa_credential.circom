pragma circom 2.2.3;
// ============================================================================
// Baseline E2b: classical ZK credential with the issuer's EdDSA signature
// checked in-circuit (the pattern of Polygon ID "Sig" mode and of zk-creds'
// signature-issued mode). NOT part of PQ-Identity v4; a comparison baseline.
//
// Credential (signed by the issuer, never revealed):
//   credHash = Poseidon4(holderCommit, birthDate, expiryDate, credType)
//   sig      = EdDSA-Poseidon over BabyJubJub on credHash (circomlib / circomlibjs)
//
// Public signals, in order (4): [Ax, Ay, policyHash, nonce]
//   Ax, Ay      issuer BabyJubJub public key (the verifier checks it is a known issuer)
//   policyHash  Poseidon5(1006, predicateCode, threshold, today, requiredType)
//               (same encoding as v4 V4_DESIGN 1.2; verifier recomputes it)
//   nonce       verifier challenge (kept in the system by squaring)
//
// In-circuit groups (names used by tests and the README):
//   E01_holder_commit  holderCommit = Poseidon1(holderSecret)
//   E02_cred_hash      credHash = Poseidon4(...)
//   E03_on_curve       R8 and A on BabyJubJub (the fix idea of TOB-IDEN3-2; circomlib's
//                      verifier does not check R8 itself)
//   E04_signature      EdDSAPoseidonVerifier(enabled = 1)(A, R8, S, credHash)
//   E05_policy_hash    Poseidon5 == policyHash
//   E06_predicate_code (predicateCode - 1)(predicateCode - 2) == 0
//   E07_ranges         Num2Bits(27) on birthDate, expiryDate, today; Num2Bits(8) on threshold
//   E08_age            birthDate + 10000*threshold <= today  selected by predicateCode
//   E09_expiry         today <= expiryDate
//   E10_type           credType == requiredType
//   E11_nonce          nonceSq <== nonce * nonce
//
// Deliberately absent (see baselines/eddsa/README.md):
//   - revocation (Polygon ID adds an SMT non-revocation proof against the issuer's
//     revocation tree root, bound to the issuer's on-chain identity state);
//   - issuer key membership in the issuer's claims tree (Polygon ID Sig mode);
//   - v4-only defences: standard-threshold set, epoch window, verifier stmtCode.
// ============================================================================

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/babyjub.circom";
include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";

template EdDSACredentialBaseline() {
    // ------------------------------------------------------------- public (4)
    signal input Ax;
    signal input Ay;
    signal input policyHash;
    signal input nonce;

    // ---------------------------------------------------------------- private
    signal input holderSecret;
    signal input birthDate;      // YYYYMMDD, signed by the issuer
    signal input expiryDate;     // YYYYMMDD, signed by the issuer
    signal input credType;       // field element, signed by the issuer
    signal input sigR8x;
    signal input sigR8y;
    signal input sigS;
    signal input predicateCode;  // 1 = AGE_GTE, 2 = AGE_LT
    signal input threshold;      // years
    signal input today;          // verifier's date (bound by policyHash)
    signal input requiredType;   // bound by policyHash

    signal holderCommit;
    signal credHash;

    // E01_holder_commit
    component holder = Poseidon(1);
    holder.inputs[0] <== holderSecret;
    holderCommit <== holder.out;

    // E02_cred_hash
    component cred = Poseidon(4);
    cred.inputs[0] <== holderCommit;
    cred.inputs[1] <== birthDate;
    cred.inputs[2] <== expiryDate;
    cred.inputs[3] <== credType;
    credHash <== cred.out;

    // E03_on_curve
    component r8OnCurve = BabyCheck();
    r8OnCurve.x <== sigR8x;
    r8OnCurve.y <== sigR8y;
    component aOnCurve = BabyCheck();
    aOnCurve.x <== Ax;
    aOnCurve.y <== Ay;

    // E04_signature
    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== Ax;
    sig.Ay <== Ay;
    sig.S <== sigS;
    sig.R8x <== sigR8x;
    sig.R8y <== sigR8y;
    sig.M <== credHash;

    // E05_policy_hash
    component pol = Poseidon(5);
    pol.inputs[0] <== 1006; // same tag as POLICY_V4
    pol.inputs[1] <== predicateCode;
    pol.inputs[2] <== threshold;
    pol.inputs[3] <== today;
    pol.inputs[4] <== requiredType;
    pol.out === policyHash;

    // E06_predicate_code
    (predicateCode - 1) * (predicateCode - 2) === 0;

    // E07_ranges (comparator preconditions)
    component rBirth = Num2Bits(27);
    rBirth.in <== birthDate;
    component rExpiry = Num2Bits(27);
    rExpiry.in <== expiryDate;
    component rToday = Num2Bits(27);
    rToday.in <== today;
    component rThr = Num2Bits(8);
    rThr.in <== threshold;

    // E08_age: reached = (birthDate + 10000*threshold <= today);
    // code 1 needs reached = 1, code 2 needs reached = 0.
    component reached = LessEqThan(28);
    reached.in[0] <== birthDate + 10000 * threshold;
    reached.in[1] <== today;
    reached.out === 2 - predicateCode;

    // E09_expiry
    component notExpired = LessEqThan(27);
    notExpired.in[0] <== today;
    notExpired.in[1] <== expiryDate;
    notExpired.out === 1;

    // E10_type
    credType === requiredType;

    // E11_nonce
    signal nonceSq;
    nonceSq <== nonce * nonce;
}

component main {public [Ax, Ay, policyHash, nonce]} = EdDSACredentialBaseline();
