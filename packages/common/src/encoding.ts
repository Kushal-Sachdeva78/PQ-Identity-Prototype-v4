import { buildPoseidon, type Poseidon } from "circomlibjs";
import { canonicalJsonBytes } from "./hash.ts";

/**
 * Field-element encodings shared by the JS protocol code and the Circom
 * circuit. Every encoding here is documented in ARCHITECTURE.md §Public
 * signals; the circuit (circuits/credential_auth.circom) must stay in sync.
 *
 * BN254 scalar field prime (the snark field of circom/snarkjs):
 */
export const BN254_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Policy predicate codes (bound into policyHash; circuit-enforced set). */
export const PREDICATE_AGE_GTE = 1n; // claims.age >= threshold
export const PREDICATE_AGE_LT = 2n; // claims.age <  threshold
/** v1 statement version: possession ∧ policy ∧ issuer-bound ∧ not-revoked. */
export const STMT_V1 = 1n;
/** Domain tag for the Poseidon fold of issuer public keys. */
export const DOMAIN_ISSUER_KEY = 1001n;
/** Domain tag for the Poseidon fold of verifier identifiers (V6 §F3). */
export const DOMAIN_VERIFIER_ID = 1002n;
/**
 * v3 statement version: possession ∧ policy ∧ membership in an issuer-signed
 * issuance tree ∧ not-revoked (circuits/credential_auth_v3.circom).
 */
export const STMT_V3 = 3n;
/** Domain tag of v3 credential leaves (first Poseidon input of every leaf). */
export const CRED_LEAF_V1 = 1003n;
/** Depth of the v3 issuance tree (append-only, 2^32 leaves per issuer). */
export const ISSUANCE_TREE_DEPTH = 32;

let poseidonSingleton: Poseidon | null = null;

export async function getPoseidon(): Promise<Poseidon> {
  if (!poseidonSingleton) poseidonSingleton = await buildPoseidon();
  return poseidonSingleton;
}

export function poseidonBig(
  poseidon: Poseidon,
  inputs: ReadonlyArray<bigint>
): bigint {
  return poseidon.F.toObject(poseidon(inputs as Array<bigint>));
}

/** Interpret ≤31 big-endian bytes as a field element (always < p). */
export function fieldFromBytesBE(bytes: Uint8Array): bigint {
  if (bytes.length > 31) throw new Error("chunk too large for one field element");
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

/**
 * Poseidon fold of an arbitrary byte string (used for issuerKeyHash over the
 * 1,312-byte ML-DSA-44 public key):
 *   chunks = 31-byte big-endian chunks of `bytes` (last chunk may be short)
 *   h0 = Poseidon(domainTag, len(bytes))
 *   h_{i+1} = Poseidon(h_i, chunk_i)
 * Computed OFF-circuit only (wallet + verifier); the circuit sees the result
 * as the public signal issuerKeyHash.
 */
export function poseidonFoldBytes(
  poseidon: Poseidon,
  bytes: Uint8Array,
  domainTag: bigint
): bigint {
  let h = poseidonBig(poseidon, [domainTag, BigInt(bytes.length)]);
  for (let i = 0; i < bytes.length; i += 31) {
    const chunk = bytes.subarray(i, Math.min(i + 31, bytes.length));
    h = poseidonBig(poseidon, [h, fieldFromBytesBE(chunk)]);
  }
  return h;
}

/** issuerKeyHash = PoseidonFold(pk_issuer) with the issuer-key domain tag. */
export function issuerKeyHash(poseidon: Poseidon, pkIssuer: Uint8Array): bigint {
  return poseidonFoldBytes(poseidon, pkIssuer, DOMAIN_ISSUER_KEY);
}

/**
 * credID field packing (Gap 11): the 256-bit SHA3-256 digest does not fit one
 * BN254 field element, so it is carried as two 128-bit big-endian limbs.
 */
export function credIdLimbs(credId: Uint8Array): { hi: bigint; lo: bigint } {
  if (credId.length !== 32) throw new Error("credID must be 32 bytes");
  return {
    hi: fieldFromBytesBE(credId.subarray(0, 16)),
    lo: fieldFromBytesBE(credId.subarray(16, 32)),
  };
}

/** SMT key derivation: smtKey = Poseidon(credIDHi, credIDLo). */
export function smtKeyFromCredId(poseidon: Poseidon, credId: Uint8Array): bigint {
  const { hi, lo } = credIdLimbs(credId);
  return poseidonBig(poseidon, [hi, lo]);
}

/** policyHash = Poseidon(predicateCode, threshold). */
export function policyHash(
  poseidon: Poseidon,
  predicateCode: bigint,
  threshold: bigint
): bigint {
  return poseidonBig(poseidon, [predicateCode, threshold]);
}

/** holderCommit = Poseidon(holderSecret). */
export function holderCommit(poseidon: Poseidon, holderSecret: bigint): bigint {
  return poseidonBig(poseidon, [holderSecret]);
}

/**
 * Verifier-domain separation (V6 §F3):
 *   domainTag = PoseidonFold(utf8(verifierId)) with the verifier domain tag;
 *   stmtCode  = Poseidon(STMT_V1, domainTag)
 * The wallet folds the requesting verifier's identifier into the statement, so
 * a proof generated for verifier A cannot be replayed at verifier B — B's
 * expected stmtCode differs. Works even for stateless verifiers (no nonce
 * registry needed for this property).
 */
export function verifierDomainTag(poseidon: Poseidon, verifierId: string): bigint {
  return poseidonFoldBytes(
    poseidon,
    new TextEncoder().encode(verifierId),
    DOMAIN_VERIFIER_ID
  );
}

export function stmtCodeForDomain(poseidon: Poseidon, domainTag: bigint): bigint {
  return poseidonBig(poseidon, [STMT_V1, domainTag]);
}

/** v3: stmtCode = Poseidon(STMT_V3, domainTag). */
export function stmtCodeForDomainV3(poseidon: Poseidon, domainTag: bigint): bigint {
  return poseidonBig(poseidon, [STMT_V3, domainTag]);
}

/**
 * v3 credential leaf, inserted into the issuance tree by the issuer:
 *   leaf = Poseidon(CRED_LEAF_V1, issuerKeyHash, credIDHi, credIDLo,
 *                   holderCommit, claimAge)
 * The circuit recomputes this leaf from the prover's private inputs and must
 * find it under the issuer-signed root, so none of these values can be chosen
 * freely by the prover.
 */
export function credentialLeaf(
  poseidon: Poseidon,
  args: { issuerKeyHash: bigint; credId: Uint8Array; holderCommit: bigint; claimAge: bigint }
): bigint {
  const { hi, lo } = credIdLimbs(args.credId);
  return poseidonBig(poseidon, [
    CRED_LEAF_V1,
    args.issuerKeyHash,
    hi,
    lo,
    args.holderCommit,
    args.claimAge,
  ]);
}

/**
 * Bytes the issuer signs (ML-DSA-44) for one epoch: its issuance-tree root AND
 * its revocation root, so one anchored, PQ-signed statement fixes both public
 * roots every holder must present. The verifier rebuilds these bytes and
 * checks the signature against pk_issuer resolved on-chain. Canonical JSON
 * keeps the encoding unambiguous; the type string separates it from every
 * other signed message.
 */
export function issuanceRootMessage(issuerDid: string, epoch: number, root: bigint, revRoot: bigint): Buffer {
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new Error("epoch must be a non-negative integer");
  return canonicalJsonBytes({
    type: "pqid:issuer-epoch:v1",
    issuer: issuerDid,
    epoch,
    root: root.toString(),
    revRoot: revRoot.toString(),
  });
}
