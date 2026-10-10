pragma circom 2.2.3;

// B2 gadget, tree part only: ImtNonMembership(30) from ../lib_v4.circom with the key
// given as a public input (no key derivation). Public: key, root.
include "../lib_v4.circom";

component main {public [key, root]} = ImtNonMembership(30);
