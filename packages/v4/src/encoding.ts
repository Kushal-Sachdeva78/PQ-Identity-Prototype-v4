import type { Poseidon } from "circomlibjs";
import {
  getPoseidon,
  poseidonBig,
  poseidonFoldBytes,
  issuerKeyHash,
  verifierDomainTag,
  credIdLimbs,
} from "@pqid/common/encoding";
import {
  BN254_P,
  STMT_V4,
  CRED_LEAF_V4,
  DOMAIN_CRED_TYPE,
  POLICY_V4,
  IMT_LEAF_V4,
  REV_KEY_BITS,
  PREDICATE_AGE_GTE,
  PREDICATE_AGE_LT,
  STANDARD_THRESHOLDS,
} from "./constants.ts";
import { assertValidYmd } from "./dates.ts";

/**
 * v4 field encodings shared by the JS protocol code and circuits/credential_auth_v4.circom
 * (docs/v4/V4_DESIGN.md section 1). Changing anything here changes the relation.
 */
export { getPoseidon, poseidonBig, issuerKeyHash, verifierDomainTag, credIdLimbs };

export type PredicateName = "age_gte" | "age_lt";

export function predicateCode(p: PredicateName): bigint {
  if (p === "age_gte") return PREDICATE_AGE_GTE;
  if (p === "age_lt") return PREDICATE_AGE_LT;
  throw new Error(`unknown predicate ${String(p)}`);
}

export function isStandardThreshold(t: unknown): t is number {
  return typeof t === "number" && STANDARD_THRESHOLDS.includes(t);
}

/** credType = PoseidonFold(utf8(typeId), DOMAIN_CRED_TYPE). */
export function credTypeField(poseidon: Poseidon, typeId: string): bigint {
  if (typeof typeId !== "string" || typeId.length === 0) throw new Error("typeId must be a non-empty string");
  return poseidonFoldBytes(poseidon, new TextEncoder().encode(typeId), DOMAIN_CRED_TYPE);
}

/** stmtCode = Poseidon(STMT_V4, domainTag). */
export function stmtCodeV4(poseidon: Poseidon, domainTag: bigint): bigint {
  return poseidonBig(poseidon, [STMT_V4, domainTag]);
}

/** Leaf of the issuance tree (V4_DESIGN 1.1). */
export function credentialLeafV4(
  poseidon: Poseidon,
  a: {
    issuerKeyHash: bigint;
    credId: Uint8Array;
    holderCommit: bigint;
    birthDate: number;
    expiryDate: number;
    credType: bigint;
  }
): bigint {
  const { hi, lo } = credIdLimbs(a.credId);
  return poseidonBig(poseidon, [
    CRED_LEAF_V4,
    a.issuerKeyHash,
    hi,
    lo,
    a.holderCommit,
    BigInt(assertValidYmd(a.birthDate, "birthDate")),
    BigInt(assertValidYmd(a.expiryDate, "expiryDate")),
    a.credType,
  ]);
}

/** policyHash = Poseidon(POLICY_V4, predicateCode, threshold, today, requiredType) (V4_DESIGN 1.2). */
export function policyHashV4(
  poseidon: Poseidon,
  a: { predicate: PredicateName; threshold: number; today: number; requiredType: bigint }
): bigint {
  if (!Number.isSafeInteger(a.threshold) || a.threshold < 0 || a.threshold > 255) {
    throw new Error("threshold must be an integer in [0, 255]");
  }
  return poseidonBig(poseidon, [
    POLICY_V4,
    predicateCode(a.predicate),
    BigInt(a.threshold),
    BigInt(assertValidYmd(a.today, "today")),
    a.requiredType,
  ]);
}

/**
 * Revocation key (251 bits): credIDHi * 2^123 + floor(credIDLo / 2^5). The circuit forms
 * the same value from the Num2Bits(128) bits of the two limbs (group G05).
 */
export function revKeyFromCredId(credId: Uint8Array): bigint {
  const { hi, lo } = credIdLimbs(credId);
  const key = (hi << 123n) + (lo >> 5n);
  if (key >= 1n << BigInt(REV_KEY_BITS)) throw new Error("internal: revKey out of range");
  return key;
}

/** IMT leaf at an occupied index: Poseidon(IMT_LEAF_V4, value, nextValue). */
export function imtLeafHash(poseidon: Poseidon, value: bigint, nextValue: bigint): bigint {
  return poseidonBig(poseidon, [IMT_LEAF_V4, value, nextValue]);
}

/** Canonical decimal string of a field element (throws if out of range). */
export function fieldDec(x: bigint): string {
  if (x < 0n || x >= BN254_P) throw new Error("field element out of range");
  return x.toString();
}

/** Nonce from 31 bytes (248 bits, always < p). */
export function fieldFrom31Bytes(b: Uint8Array): bigint {
  if (b.length !== 31) throw new Error("need exactly 31 bytes");
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

export async function poseidon(): Promise<Poseidon> {
  return getPoseidon();
}

/** Convenience: every shared field value for one verifier id. */
export async function verifierStmtCode(verifierId: string): Promise<{ domainTag: bigint; stmtCode: bigint }> {
  const p = await getPoseidon();
  const domainTag = verifierDomainTag(p, verifierId);
  return { domainTag, stmtCode: stmtCodeV4(p, domainTag) };
}
