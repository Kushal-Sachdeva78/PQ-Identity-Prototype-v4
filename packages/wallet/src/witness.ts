import type { NonMembershipProof } from "@pqid/revocation";
import { credIdLimbs } from "@pqid/common/encoding";

/**
 * Circuit input assembly for circuits/credential_auth.circom.
 * Field names MUST match the circom signal names exactly; values are decimal
 * strings as expected by snarkjs' witness calculator.
 */
export interface PublicInputs {
  issuerKeyHash: bigint;
  revRoot: bigint;
  policyHash: bigint;
  nonce: bigint;
  stmtCode: bigint;
}

export interface PrivateInputs {
  credId: Uint8Array; // 32-byte SHA3-256 digest
  holderSecret: bigint;
  holderCommit: bigint;
  claimAge: bigint;
  threshold: bigint;
  predicateCode: bigint; // 1 = AGE_GTE, 2 = AGE_LT (bound via policyHash)
  domainTag: bigint; // verifier identifier fold (bound via stmtCode)
  nonMembership: NonMembershipProof;
}

export type CircuitInput = Record<string, string | string[]>;

export function buildCircuitInput(pub: PublicInputs, priv: PrivateInputs): CircuitInput {
  const { hi, lo } = credIdLimbs(priv.credId);
  return {
    issuerKeyHash: pub.issuerKeyHash.toString(),
    revRoot: pub.revRoot.toString(),
    policyHash: pub.policyHash.toString(),
    nonce: pub.nonce.toString(),
    stmtCode: pub.stmtCode.toString(),
    credIDHi: hi.toString(),
    credIDLo: lo.toString(),
    holderSecret: priv.holderSecret.toString(),
    holderCommit: priv.holderCommit.toString(),
    claimAge: priv.claimAge.toString(),
    threshold: priv.threshold.toString(),
    predicateCode: priv.predicateCode.toString(),
    domainTag: priv.domainTag.toString(),
    smtSiblings: priv.nonMembership.siblings,
    smtOldKey: priv.nonMembership.oldKey,
    smtOldValue: priv.nonMembership.oldValue,
    smtIsOld0: priv.nonMembership.isOld0,
  };
}

/** Public-signal order produced by the circuit (and checked by the verifier). */
export const PUBLIC_SIGNAL_ORDER = [
  "issuerKeyHash",
  "revRoot",
  "policyHash",
  "nonce",
  "stmtCode",
] as const;

export function publicSignalsFromInputs(pub: PublicInputs): string[] {
  return [
    pub.issuerKeyHash.toString(),
    pub.revRoot.toString(),
    pub.policyHash.toString(),
    pub.nonce.toString(),
    pub.stmtCode.toString(),
  ];
}

// ============================================================================
// Circuit v3 (circuits/credential_auth_v3.circom)
// ============================================================================

export interface PublicInputsV3 extends PublicInputs {
  /** Issuer-signed issuance-tree root the credential leaf opens to. */
  issRoot: bigint;
}

/**
 * v3 private inputs. holderCommit is no longer an input (the circuit computes
 * Poseidon(holderSecret) itself), and the issuance path replaces the free
 * choice of credID / claimAge.
 */
export interface PrivateInputsV3 {
  credId: Uint8Array;
  holderSecret: bigint;
  claimAge: bigint;
  threshold: bigint;
  predicateCode: bigint;
  domainTag: bigint;
  issLeafIndex: string;
  issPathElements: string[];
  nonMembership: NonMembershipProof;
}

export function buildCircuitInputV3(pub: PublicInputsV3, priv: PrivateInputsV3): CircuitInput {
  const { hi, lo } = credIdLimbs(priv.credId);
  return {
    issuerKeyHash: pub.issuerKeyHash.toString(),
    revRoot: pub.revRoot.toString(),
    policyHash: pub.policyHash.toString(),
    nonce: pub.nonce.toString(),
    stmtCode: pub.stmtCode.toString(),
    issRoot: pub.issRoot.toString(),
    credIDHi: hi.toString(),
    credIDLo: lo.toString(),
    holderSecret: priv.holderSecret.toString(),
    claimAge: priv.claimAge.toString(),
    threshold: priv.threshold.toString(),
    predicateCode: priv.predicateCode.toString(),
    domainTag: priv.domainTag.toString(),
    issLeafIndex: priv.issLeafIndex,
    issPathElements: priv.issPathElements,
    smtSiblings: priv.nonMembership.siblings,
    smtOldKey: priv.nonMembership.oldKey,
    smtOldValue: priv.nonMembership.oldValue,
    smtIsOld0: priv.nonMembership.isOld0,
  };
}

/** v3 public-signal order (declaration order in the circuit). */
export const PUBLIC_SIGNAL_ORDER_V3 = [...PUBLIC_SIGNAL_ORDER, "issRoot"] as const;
