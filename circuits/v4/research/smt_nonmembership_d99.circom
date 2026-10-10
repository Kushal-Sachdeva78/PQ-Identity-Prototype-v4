pragma circom 2.2.3;

// B2 gadget: circomlib SMTVerifier(99) exclusion proof (fnc 1, enabled 1, value 0) with
// the isOld0 booleanity fix, key = Poseidon(credIDHi, credIDLo) from range-checked
// limbs (like-for-like with imt_nonmembership_dNN). Public: root.
include "revocation_gadgets.circom";

component main {public [root]} = SmtNonMembershipFromLimbs(99);
