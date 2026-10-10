pragma circom 2.2.3;
// C2 harness (embargoed material, DECISIONS D-008): the minimal non-membership caller of
// circomlib's SMTVerifier with a prover-chosen isOld0, as in v2. Variant "plain":
// plain = isOld0 unconstrained (v2 pattern); fixed = isOld0 * (isOld0 - 1) === 0 (v3 fix).
include "../../../node_modules/circomlib/circuits/smt/smtverifier.circom";
template SmtExclusionHarness(n) {
    signal input root;
    signal input key;
    signal input siblings[n];
    signal input oldKey;
    signal input oldValue;
    signal input isOld0;

    component v = SMTVerifier(n);
    v.enabled <== 1;
    v.fnc <== 1;
    v.root <== root;
    for (var i = 0; i < n; i++) { v.siblings[i] <== siblings[i]; }
    v.oldKey <== oldKey;
    v.oldValue <== oldValue;
    v.isOld0 <== isOld0;
    v.key <== key;
    v.value <== 0;
}
component main {public [root, key]} = SmtExclusionHarness(4);
