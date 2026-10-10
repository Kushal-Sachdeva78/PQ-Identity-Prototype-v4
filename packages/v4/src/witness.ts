import { credIdLimbs } from "@pqid/common/encoding";
import { BN254_P, ISSUANCE_DEPTH, REV_DEPTH } from "./constants.ts";
import { predicateCode, type PredicateName } from "./encoding.ts";

/**
 * Circuit input assembly for circuits/credential_auth_v4.circom (V4_DESIGN section 2).
 * Keys are the exact circom signal names; values are canonical decimal strings, as
 * snarkjs' witness calculator expects.
 *
 * This layer checks shape only (types, field range, path lengths). It does NOT check that
 * the statement is true (predicate, standard threshold, expiry, window, type): the honest
 * wallet does that before proving (V4_DESIGN 6.2), and the circuit enforces it. Attack
 * harnesses rely on being able to assemble inputs for false statements here.
 */

export type FieldLike = bigint | number;
export type CircuitInputV4 = Record<string, string | string[]>;

/** Public signals, in circuit order (V4_DESIGN section 2). */
export const PUBLIC_SIGNAL_ORDER_V4 = [
  "issuerKeyHash",
  "revRoot",
  "policyHash",
  "nonce",
  "stmtCode",
  "issRoot",
  "epochFromDate",
  "epochToDate",
] as const;
export type PublicSignalNameV4 = (typeof PUBLIC_SIGNAL_ORDER_V4)[number];

export type PublicInputsV4 = Record<PublicSignalNameV4, FieldLike>;

/**
 * Low-leaf opening of the revocation IMT (the witness shape of packages/v4/src/imt.ts):
 * the leaf (lowValue, lowNext) at lowIndex, its sibling path, and optionally the root.
 */
export interface RevLowLeafWitnessV4 {
  lowIndex: string;
  lowValue: string;
  lowNext: string;
  lowPath: string[];
  root?: string;
}

export interface PrivateInputsV4 {
  /** 32-byte credID (SHA3-256); split into two 128-bit big-endian limbs. */
  credId: Uint8Array;
  holderSecret: bigint;
  birthDate: FieldLike;
  expiryDate: FieldLike;
  credType: bigint;
  predicate: PredicateName;
  threshold: FieldLike;
  today: FieldLike;
  requiredType: bigint;
  domainTag: bigint;
  issLeafIndex: string;
  issPathElements: string[];
  rev: RevLowLeafWitnessV4;
}

/** Canonical decimal of a field element given as bigint or safe integer. */
function dec(x: FieldLike, what: string): string {
  let v: bigint;
  if (typeof x === "bigint") v = x;
  else if (typeof x === "number" && Number.isSafeInteger(x)) v = BigInt(x);
  else throw new Error(`${what} must be a bigint or a safe integer`);
  if (v < 0n || v >= BN254_P) throw new Error(`${what} is not a field element`);
  return v.toString();
}

const DECIMAL = /^(0|[1-9][0-9]*)$/;

/** A canonical decimal string that is a field element. */
function decStr(s: unknown, what: string): string {
  if (typeof s !== "string" || !DECIMAL.test(s)) throw new Error(`${what} must be a canonical decimal string`);
  if (BigInt(s) >= BN254_P) throw new Error(`${what} is not a field element`);
  return s;
}

function decPath(p: unknown, len: number, what: string): string[] {
  if (!Array.isArray(p) || p.length !== len) {
    throw new Error(`${what} must have ${len} elements, got ${Array.isArray(p) ? p.length : typeof p}`);
  }
  return p.map((e, i) => decStr(e, `${what}[${i}]`));
}

export function buildCircuitInputV4(pub: PublicInputsV4, priv: PrivateInputsV4): CircuitInputV4 {
  const { hi, lo } = credIdLimbs(priv.credId);
  const out: CircuitInputV4 = {};
  for (const name of PUBLIC_SIGNAL_ORDER_V4) out[name] = dec(pub[name], name);
  out["credIDHi"] = hi.toString();
  out["credIDLo"] = lo.toString();
  out["holderSecret"] = dec(priv.holderSecret, "holderSecret");
  out["birthDate"] = dec(priv.birthDate, "birthDate");
  out["expiryDate"] = dec(priv.expiryDate, "expiryDate");
  out["credType"] = dec(priv.credType, "credType");
  out["predicateCode"] = predicateCode(priv.predicate).toString();
  out["threshold"] = dec(priv.threshold, "threshold");
  out["today"] = dec(priv.today, "today");
  out["requiredType"] = dec(priv.requiredType, "requiredType");
  out["domainTag"] = dec(priv.domainTag, "domainTag");
  out["issLeafIndex"] = decStr(priv.issLeafIndex, "issLeafIndex");
  out["issPathElements"] = decPath(priv.issPathElements, ISSUANCE_DEPTH, "issPathElements");
  out["revLowIndex"] = decStr(priv.rev.lowIndex, "rev.lowIndex");
  out["revLowValue"] = decStr(priv.rev.lowValue, "rev.lowValue");
  out["revLowNext"] = decStr(priv.rev.lowNext, "rev.lowNext");
  out["revLowPath"] = decPath(priv.rev.lowPath, REV_DEPTH, "rev.lowPath");
  return out;
}

/** The eight public signals the circuit outputs for these public inputs, in order. */
export function publicSignalsFromInputsV4(pub: PublicInputsV4): string[] {
  return PUBLIC_SIGNAL_ORDER_V4.map((name) => dec(pub[name], name));
}

/** The public signals of an assembled circuit input, in order. */
export function publicSignalsOfInputV4(input: CircuitInputV4): string[] {
  return PUBLIC_SIGNAL_ORDER_V4.map((name) => {
    const v = input[name];
    if (typeof v !== "string") throw new Error(`input has no scalar ${name}`);
    return v;
  });
}
