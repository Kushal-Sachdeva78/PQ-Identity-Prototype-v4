pragma circom 2.2.3;

// B2 research gadgets (docs/v4/B2_REVOCATION_CAPACITY.md). These templates are NOT part
// of relation R4; they exist to measure the two revocation designs like for like:
//   - IMT: indexed Merkle tree non-membership (ImtNonMembership from ../lib_v4.circom),
//     key = revKey formed linearly from the Num2Bits(128) bits of credIDHi, credIDLo
//     (V4_DESIGN 1, group G05).
//   - SMT: circomlib SMTVerifier(nLevels) exclusion proof (fnc = 1, enabled = 1,
//     value = 0) keyed by Poseidon(credIDHi, credIDLo) as in v3, with the same
//     Num2Bits(128) limb checks and the isOld0 booleanity fix.
// Both *FromLimbs templates take the same private limbs and the same public root, so
// each side pays for its own key derivation.

include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/smt/smtverifier.circom";
include "../lib_v4.circom";

// revKey = credIDHi * 2^123 + floor(credIDLo / 2^5) < 2^251 (JS: revKeyFromCredId).
template RevKeyFromLimbs() {
    signal input credIDHi;
    signal input credIDLo;
    signal output revKey;

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
}

// v3 SMT key: Poseidon(credIDHi, credIDLo), limbs range-checked to 128 bits as in v3.
template SmtKeyFromLimbs() {
    signal input credIDHi;
    signal input credIDLo;
    signal output key;

    component hiBits = Num2Bits(128);
    hiBits.in <== credIDHi;
    component loBits = Num2Bits(128);
    loBits.in <== credIDLo;
    component h = Poseidon(2);
    h.inputs[0] <== credIDHi;
    h.inputs[1] <== credIDLo;
    key <== h.out;
}

// circomlib SMT exclusion proof as used in v3 (credential_auth_v3.circom step 4),
// including the isOld0 booleanity constraint that SMTVerifier itself omits.
template SmtNonMembershipFixed(nLevels) {
    signal input key;
    signal input root;
    signal input siblings[nLevels];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;

    isOld0 * (isOld0 - 1) === 0;

    component smt = SMTVerifier(nLevels);
    smt.enabled <== 1;
    smt.root <== root;
    for (var i = 0; i < nLevels; i++) {
        smt.siblings[i] <== siblings[i];
    }
    smt.oldKey <== oldKey;
    smt.oldValue <== oldValue;
    smt.isOld0 <== isOld0;
    smt.key <== key;
    smt.value <== 0;
    smt.fnc <== 1; // exclusion (non-membership)
}

// SMT side of the like-for-like comparison: limbs -> Poseidon key -> exclusion proof.
template SmtNonMembershipFromLimbs(nLevels) {
    signal input credIDHi;
    signal input credIDLo;
    signal input root;
    signal input siblings[nLevels];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;

    component k = SmtKeyFromLimbs();
    k.credIDHi <== credIDHi;
    k.credIDLo <== credIDLo;

    component nm = SmtNonMembershipFixed(nLevels);
    nm.key <== k.key;
    nm.root <== root;
    for (var i = 0; i < nLevels; i++) {
        nm.siblings[i] <== siblings[i];
    }
    nm.oldKey <== oldKey;
    nm.oldValue <== oldValue;
    nm.isOld0 <== isOld0;
}

// IMT side of the like-for-like comparison: limbs -> revKey -> low-leaf opening + bracket.
template ImtNonMembershipFromLimbs(nLevels) {
    signal input credIDHi;
    signal input credIDLo;
    signal input root;
    signal input lowIndex;
    signal input lowValue;
    signal input lowNext;
    signal input lowPath[nLevels];

    component k = RevKeyFromLimbs();
    k.credIDHi <== credIDHi;
    k.credIDLo <== credIDLo;

    component nm = ImtNonMembership(nLevels);
    nm.key <== k.revKey;
    nm.root <== root;
    nm.lowIndex <== lowIndex;
    nm.lowValue <== lowValue;
    nm.lowNext <== lowNext;
    for (var i = 0; i < nLevels; i++) {
        nm.lowPath[i] <== lowPath[i];
    }
}
