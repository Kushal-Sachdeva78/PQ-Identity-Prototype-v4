pragma circom 2.2.3;

// B2 gadget: IMT non-membership at depth 32, revKey derived from range-checked credID
// limbs (like-for-like with smt_nonmembership_dNN). Public: root.
include "revocation_gadgets.circom";

component main {public [root]} = ImtNonMembershipFromLimbs(32);
