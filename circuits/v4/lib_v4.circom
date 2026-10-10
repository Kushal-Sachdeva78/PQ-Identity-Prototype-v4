pragma circom 2.2.3;

// Gadgets for circuits/credential_auth_v4.circom (docs/v4/V4_DESIGN.md sections 1.3, 1.4).

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// Binary Poseidon Merkle path from a leaf at position leafIndex to the root (same
// construction as v3's MerkleRoot). Bit i of leafIndex selects the order at level i:
// 0 -> (cur, sibling), 1 -> (sibling, cur). Num2Bits range-checks leafIndex < 2^nLevels,
// so the leaf sits at exactly depth nLevels.
template MerkleRootV4(nLevels) {
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

// Indexed Merkle tree (Aztec-style sorted linked list) low leaf: computes the root
// that the leaf Poseidon(1007, lowValue, lowNext) at lowIndex opens to. The caller
// constrains it to the expected root (kept in the caller so every check is visible
// in one place for the mutation tool).
template ImtLowLeafRoot(nLevels) {
    signal input lowIndex;
    signal input lowValue;
    signal input lowNext;
    signal input lowPath[nLevels];
    signal output root;

    component leaf = Poseidon(3);
    leaf.inputs[0] <== 1007; // IMT_LEAF_V4
    leaf.inputs[1] <== lowValue;
    leaf.inputs[2] <== lowNext;

    component mr = MerkleRootV4(nLevels);
    mr.leaf <== leaf.out;
    mr.leafIndex <== lowIndex;
    for (var i = 0; i < nLevels; i++) {
        mr.pathElements[i] <== lowPath[i];
    }
    root <== mr.root;
}

// Strict bracketing flags lowValue < key and key < lowNext (the caller requires both
// to be 1). Inputs must be < 2^252 for LessThan(252) to be sound: key < 2^251 by
// construction (revKey); lowValue and lowNext are pinned by the tree to values the
// issuer inserted (< 2^251, or IMT_MAX = 2^251).
template ImtBracket() {
    signal input key;
    signal input lowValue;
    signal input lowNext;
    signal output belowOk;
    signal output aboveOk;

    component below = LessThan(252);
    below.in[0] <== lowValue;
    below.in[1] <== key;
    belowOk <== below.out;

    component above = LessThan(252);
    above.in[0] <== key;
    above.in[1] <== lowNext;
    aboveOk <== above.out;
}

// Standalone IMT non-membership (low-leaf membership + bracket), used by the B2
// measurement. Same interface as before.
template ImtNonMembership(nLevels) {
    signal input key;
    signal input root;
    signal input lowIndex;
    signal input lowValue;
    signal input lowNext;
    signal input lowPath[nLevels];

    component m = ImtLowLeafRoot(nLevels);
    m.lowIndex <== lowIndex;
    m.lowValue <== lowValue;
    m.lowNext <== lowNext;
    for (var i = 0; i < nLevels; i++) {
        m.lowPath[i] <== lowPath[i];
    }
    m.root === root;

    component b = ImtBracket();
    b.key <== key;
    b.lowValue <== lowValue;
    b.lowNext <== lowNext;
    b.belowOk === 1;
    b.aboveOk === 1;
}
