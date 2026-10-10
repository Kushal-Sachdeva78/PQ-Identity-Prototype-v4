pragma circom 2.2.3;

// B2 gadget, tree part only: circomlib SMTVerifier(4) exclusion proof with the isOld0
// fix, key given as a public input (no key derivation). Public: key, root.
include "revocation_gadgets.circom";

component main {public [key, root]} = SmtNonMembershipFixed(4);
