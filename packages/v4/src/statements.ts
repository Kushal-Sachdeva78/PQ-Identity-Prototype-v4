import type { KeyObject } from "node:crypto";
import { canonicalJsonBytes } from "@pqid/common/hash";
import {
  BN254_P,
  KEM_ALG,
  MAX_ACCREDITATION_SEC,
  MAX_EPOCH_WINDOW_SEC,
  TYPE_ACCREDITATION,
  TYPE_DID_POP,
  TYPE_EPOCH,
  TYPE_VERIFIER_KEM,
} from "./constants.ts";
import { isValidYmd, utcDateOf } from "./dates.ts";
import { ML_DSA_44_SIZES, mlDsaSign, mlDsaVerify } from "./pqc.ts";

/**
 * The four ML-DSA-44 signed statements of V4_DESIGN section 3. A statement's signed
 * bytes are canonicalJsonBytes(statement) from @pqid/common/hash (sorted keys, no
 * whitespace, UTF-8). All `type` strings differ, so no statement verifies as another.
 *
 * Format rules enforced by every validator (section 3):
 *  - exactly the listed fields, no extra and none missing; `type` is the fixed string;
 *  - did, issuerDid, issuer, verifier: did:pq identifiers (base58 suffix);
 *  - controller, registry: lower-case 0x hex EVM addresses (40 hex digits);
 *  - chainId: positive safe integer; epoch, serial: non-negative safe integers;
 *  - nonce, pkSha3, kemPkSha3: 64 lower-case hex characters;
 *  - origin (DID PoP): "" or at most MAX_ORIGIN_LENGTH printable ASCII characters (0x21 to
 *    0x7e, no spaces); the wallet compares it byte for byte with the caller's origin;
 *  - root, revRoot: canonical decimal strings of BN254 field elements (no sign, no
 *    leading zeros, < p);
 *  - notBefore, notAfter: unix seconds (non-negative safe integers), notBefore < notAfter;
 *  - fromDate, toDate (epoch): valid YYYYMMDD equal to utcDateOf(notBefore/notAfter).
 * Window-length bounds enforced here: accreditation at most MAX_ACCREDITATION_SEC
 * (D-014); epoch at most MAX_EPOCH_WINDOW_SEC (the registry's windowBounds limit);
 * verifier KEM key at most MAX_VERIFIER_KEM_SEC.
 * Deployment binding: the PoP, accreditation, epoch and KEM statements all carry chainId
 * and the address of the registry they are posted to, so none can be moved to another
 * deployment.
 * Honest issuers use exactly EPOCH_WINDOW_SEC; shorter epoch windows are well formed
 * (tests use them) and are not rejected here.
 *
 * Parsing from bytes also requires the bytes to be the canonical encoding of the parsed
 * value (so duplicate keys, whitespace, "-0", key reordering and bad UTF-8 are rejected).
 */

// ---- shared field predicates (also used by session.ts) ----
export const ADDRESS_RE = /^0x[0-9a-f]{40}$/;
export const HEX64_RE = /^[0-9a-f]{64}$/;
export const DECIMAL_RE = /^(0|[1-9][0-9]*)$/;
/** did:pq:<base58> (Bitcoin alphabet, as @pqid/common/did). */
export const DID_PQ_RE = /^did:pq:[1-9A-HJ-NP-Za-km-z]{1,64}$/;
const SIG_HEX_RE = new RegExp(`^[0-9a-f]{${2 * ML_DSA_44_SIZES.signature}}$`);
/** Longest registered origin a DID PoP statement may carry. */
export const MAX_ORIGIN_LENGTH = 256;
const ORIGIN_RE = /^[\x21-\x7e]*$/;
/**
 * Longest verifier KEM statement window notAfter - notBefore (s). Bounds how long a
 * superseded KEM statement stays usable where rollback is not otherwise stopped.
 */
export const MAX_VERIFIER_KEM_SEC = 400 * 24 * 3600;

export function isLowerAddress(v: unknown): v is string {
  return typeof v === "string" && ADDRESS_RE.test(v);
}
export function isHex64(v: unknown): v is string {
  return typeof v === "string" && HEX64_RE.test(v);
}
export function isDidPq(v: unknown): v is string {
  return typeof v === "string" && DID_PQ_RE.test(v);
}
export function isUint(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}
export function isPositiveInt(v: unknown): v is number {
  return isUint(v) && v > 0;
}
/** "" or a printable-ASCII origin string (no spaces) of at most MAX_ORIGIN_LENGTH characters. */
export function isPopOrigin(v: unknown): v is string {
  return typeof v === "string" && v.length <= MAX_ORIGIN_LENGTH && ORIGIN_RE.test(v);
}
/** Canonical decimal string of a BN254 scalar field element. */
export function isFieldDecimal(v: unknown): v is string {
  return typeof v === "string" && v.length <= 78 && DECIMAL_RE.test(v) && BigInt(v) < BN254_P;
}

// ---- statement types ----
export interface DidPopStatement {
  type: typeof TYPE_DID_POP;
  did: string;
  controller: string;
  chainId: number;
  registry: string;
  nonce: string;
  /** Web origin registered with the record ("" for issuers); signed so the controller cannot pick it. */
  origin: string;
}

export interface AccreditationStatement {
  type: typeof TYPE_ACCREDITATION;
  issuerDid: string;
  controller: string;
  pkSha3: string;
  chainId: number;
  /** AccreditationRegistryV4 address the statement is published in. */
  registry: string;
  serial: number;
  status: "accredited" | "revoked";
  notBefore: number;
  notAfter: number;
}

export interface EpochStatement {
  type: typeof TYPE_EPOCH;
  issuer: string;
  controller: string;
  chainId: number;
  registry: string;
  epoch: number;
  root: string;
  revRoot: string;
  notBefore: number;
  notAfter: number;
  fromDate: number;
  toDate: number;
}

export interface VerifierKemStatement {
  type: typeof TYPE_VERIFIER_KEM;
  verifier: string;
  controller: string;
  chainId: number;
  registry: string;
  kemAlg: typeof KEM_ALG;
  kemPkSha3: string;
  notBefore: number;
  notAfter: number;
}

export type Statement = DidPopStatement | AccreditationStatement | EpochStatement | VerifierKemStatement;
export type StatementType = Statement["type"];
export const STATEMENT_TYPES: readonly StatementType[] = [TYPE_DID_POP, TYPE_ACCREDITATION, TYPE_EPOCH, TYPE_VERIFIER_KEM];

/** Builder inputs: the fields without `type` (a `type` equal to the right one is tolerated). */
type WithOptionalType<T extends Statement> = Omit<T, "type"> & { type?: T["type"] };
export type DidPopFields = WithOptionalType<DidPopStatement>;
export type AccreditationFields = WithOptionalType<AccreditationStatement>;
/** fromDate/toDate default to the UTC dates of notBefore/notAfter; if given they must match. */
export type EpochFields = Omit<WithOptionalType<EpochStatement>, "fromDate" | "toDate"> & { fromDate?: number; toDate?: number };
export type VerifierKemFields = WithOptionalType<VerifierKemStatement>;

export type Validation<T> = { ok: true; value: T } | { ok: false; errors: string[] };

export class StatementError extends Error {
  constructor(readonly errors: string[]) {
    super(`invalid statement: ${errors.join("; ")}`);
    this.name = "StatementError";
  }
}

// ---- schema-driven validation ----
type Check = (v: unknown) => string | null;

const lit =
  (x: string): Check =>
  (v) =>
    v === x ? null : `must be "${x}"`;
const did: Check = (v) => (isDidPq(v) ? null : "must be a did:pq identifier");
const address: Check = (v) => (isLowerAddress(v) ? null : "must be a lower-case 0x EVM address");
const chainId: Check = (v) => (isPositiveInt(v) ? null : "must be a positive safe integer");
const uint: Check = (v) => (isUint(v) ? null : "must be a non-negative safe integer");
const hex64: Check = (v) => (isHex64(v) ? null : "must be 64 lower-case hex characters");
const field: Check = (v) => (isFieldDecimal(v) ? null : "must be a canonical decimal string of a BN254 field element");
const ymd: Check = (v) => (isValidYmd(v) ? null : "must be a valid YYYYMMDD date");
const popOrigin: Check = (v) =>
  isPopOrigin(v) ? null : `must be "" or at most ${MAX_ORIGIN_LENGTH} printable ASCII characters without spaces`;
const oneOf =
  (...xs: string[]): Check =>
  (v) =>
    typeof v === "string" && xs.includes(v) ? null : `must be one of ${xs.map((x) => `"${x}"`).join(", ")}`;

type Schema = Record<string, Check>;

const SCHEMAS: Record<StatementType, Schema> = {
  [TYPE_DID_POP]: {
    type: lit(TYPE_DID_POP),
    did,
    controller: address,
    chainId,
    registry: address,
    nonce: hex64,
    origin: popOrigin,
  },
  [TYPE_ACCREDITATION]: {
    type: lit(TYPE_ACCREDITATION),
    issuerDid: did,
    controller: address,
    pkSha3: hex64,
    chainId,
    registry: address,
    serial: uint,
    status: oneOf("accredited", "revoked"),
    notBefore: uint,
    notAfter: uint,
  },
  [TYPE_EPOCH]: {
    type: lit(TYPE_EPOCH),
    issuer: did,
    controller: address,
    chainId,
    registry: address,
    epoch: uint,
    root: field,
    revRoot: field,
    notBefore: uint,
    notAfter: uint,
    fromDate: ymd,
    toDate: ymd,
  },
  [TYPE_VERIFIER_KEM]: {
    type: lit(TYPE_VERIFIER_KEM),
    verifier: did,
    controller: address,
    chainId,
    registry: address,
    kemAlg: lit(KEM_ALG),
    kemPkSha3: hex64,
    notBefore: uint,
    notAfter: uint,
  },
};

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null;
}

/** Exact-key and per-field checks; returns error strings (empty when valid). */
export function schemaErrors(v: unknown, schema: Schema, what: string): string[] {
  if (!isPlainObject(v)) return [`${what} must be a plain JSON object`];
  const errors: string[] = [];
  for (const k of Object.keys(schema)) {
    if (!Object.prototype.hasOwnProperty.call(v, k)) errors.push(`${what}.${k} is missing`);
  }
  for (const k of Object.keys(v)) {
    const check = Object.prototype.hasOwnProperty.call(schema, k) ? schema[k] : undefined;
    if (!check) {
      errors.push(`${what}.${k} is not an allowed field`);
      continue;
    }
    const e = check(v[k]);
    if (e) errors.push(`${what}.${k} ${e}`);
  }
  return errors;
}

function windowErrors(s: { notBefore: number; notAfter: number }, maxSec: number, what: string): string[] {
  if (!(s.notBefore < s.notAfter)) return [`${what}: notBefore must be < notAfter`];
  if (s.notAfter - s.notBefore > maxSec) return [`${what}: window longer than ${maxSec} s`];
  return [];
}

function crossErrors(s: Statement): string[] {
  switch (s.type) {
    case TYPE_DID_POP:
      return [];
    case TYPE_ACCREDITATION:
      return windowErrors(s, MAX_ACCREDITATION_SEC, "accreditation");
    case TYPE_VERIFIER_KEM:
      return windowErrors(s, MAX_VERIFIER_KEM_SEC, "verifier-kem");
    case TYPE_EPOCH: {
      const errors = windowErrors(s, MAX_EPOCH_WINDOW_SEC, "issuer-epoch");
      if (s.fromDate !== utcDateOf(s.notBefore)) errors.push("issuer-epoch: fromDate is not the UTC date of notBefore");
      if (s.toDate !== utcDateOf(s.notAfter)) errors.push("issuer-epoch: toDate is not the UTC date of notAfter");
      return errors;
    }
  }
}

/** Validate any of the four statements (dispatch on `type`). */
export function validateStatement(v: unknown, expectedType?: StatementType): Validation<Statement> {
  if (!isPlainObject(v)) return { ok: false, errors: ["statement must be a plain JSON object"] };
  const t = v["type"];
  if (typeof t !== "string" || !(STATEMENT_TYPES as readonly string[]).includes(t)) {
    return { ok: false, errors: [`statement.type must be one of ${STATEMENT_TYPES.join(", ")}`] };
  }
  if (expectedType !== undefined && t !== expectedType) {
    return { ok: false, errors: [`statement.type is "${t}", expected "${expectedType}"`] };
  }
  const type = t as StatementType;
  const errors = schemaErrors(v, SCHEMAS[type], type);
  if (errors.length > 0) return { ok: false, errors };
  const s = v as unknown as Statement;
  const cross = crossErrors(s);
  if (cross.length > 0) return { ok: false, errors: cross };
  return { ok: true, value: s };
}

export const validateDidPop = (v: unknown) => validateStatement(v, TYPE_DID_POP) as Validation<DidPopStatement>;
export const validateAccreditation = (v: unknown) => validateStatement(v, TYPE_ACCREDITATION) as Validation<AccreditationStatement>;
export const validateEpoch = (v: unknown) => validateStatement(v, TYPE_EPOCH) as Validation<EpochStatement>;
export const validateVerifierKem = (v: unknown) => validateStatement(v, TYPE_VERIFIER_KEM) as Validation<VerifierKemStatement>;

/** Canonical signed bytes of a statement; throws StatementError when it is not valid. */
export function statementBytes(stmt: unknown, expectedType?: StatementType): Buffer {
  const r = validateStatement(stmt, expectedType);
  if (!r.ok) throw new StatementError(r.errors);
  return canonicalJsonBytes(r.value);
}

function withType<T extends StatementType>(fields: object, type: T): Record<string, unknown> {
  if (!isPlainObject(fields)) throw new StatementError([`${type} fields must be a plain object`]);
  if (Object.prototype.hasOwnProperty.call(fields, "type") && fields["type"] !== type) {
    throw new StatementError([`fields carry type "${String(fields["type"])}", expected "${type}"`]);
  }
  return { ...fields, type };
}

// ---- typed builders (return the canonical bytes to sign or verify) ----
export function didPopMessage(f: DidPopFields): Buffer {
  return statementBytes(withType(f, TYPE_DID_POP), TYPE_DID_POP);
}

export function accreditationMessage(f: AccreditationFields): Buffer {
  return statementBytes(withType(f, TYPE_ACCREDITATION), TYPE_ACCREDITATION);
}

export function epochMessage(f: EpochFields): Buffer {
  const s = withType(f, TYPE_EPOCH);
  if (s["fromDate"] === undefined && isUint(s["notBefore"])) s["fromDate"] = utcDateOf(s["notBefore"]);
  if (s["toDate"] === undefined && isUint(s["notAfter"])) s["toDate"] = utcDateOf(s["notAfter"]);
  return statementBytes(s, TYPE_EPOCH);
}

export function verifierKemMessage(f: VerifierKemFields): Buffer {
  return statementBytes(withType(f, TYPE_VERIFIER_KEM), TYPE_VERIFIER_KEM);
}

// ---- parsing signed bytes ----
const UTF8_STRICT = new TextDecoder("utf-8", { fatal: true });

/** Parse signed bytes back into a statement; requires valid, canonical bytes. */
export function tryParseStatement(bytes: Uint8Array, expectedType?: StatementType): Validation<Statement> {
  if (!(bytes instanceof Uint8Array)) return { ok: false, errors: ["statement bytes must be a Uint8Array"] };
  let value: unknown;
  try {
    value = JSON.parse(UTF8_STRICT.decode(bytes));
  } catch {
    return { ok: false, errors: ["statement bytes are not UTF-8 JSON"] };
  }
  const r = validateStatement(value, expectedType);
  if (!r.ok) return r;
  if (!canonicalJsonBytes(r.value).equals(bytes)) return { ok: false, errors: ["statement bytes are not in canonical form"] };
  return r;
}

export function parseStatement(bytes: Uint8Array, expectedType?: StatementType): Statement {
  const r = tryParseStatement(bytes, expectedType);
  if (!r.ok) throw new StatementError(r.errors);
  return r.value;
}

// ---- signing ----
/**
 * Sign statement bytes with ML-DSA-44. Refuses (throws) unless the bytes are a valid,
 * canonical statement, so a signing key never signs anything else through this call.
 * (mlDsaSign in ./pqc.ts is the raw primitive.)
 */
export function signStatement(privateKey: KeyObject, msgBytes: Uint8Array): Buffer {
  parseStatement(msgBytes);
  return mlDsaSign(privateKey, msgBytes);
}

/**
 * True iff `msgBytes` is a valid canonical statement (of `expectedType`, if given) and
 * `sig` is a valid ML-DSA-44 signature on it under `pkRaw`. Never throws.
 */
export function verifyStatement(pkRaw: Uint8Array, msgBytes: Uint8Array, sig: Uint8Array, expectedType?: StatementType): boolean {
  try {
    if (!tryParseStatement(msgBytes, expectedType).ok) return false;
    return mlDsaVerify(pkRaw, msgBytes, sig);
  } catch {
    return false;
  }
}

/** True iff notBefore <= nowSec <= notAfter. */
export function statementInWindow(s: { notBefore: number; notAfter: number }, nowSec: number): boolean {
  return s.notBefore <= nowSec && nowSec <= s.notAfter;
}

// ---- statement plus signature as one JSON object (e.g. the presentation's epochStatement) ----
export type SignedStatement<T extends Statement = Statement> = T & { signature: string };

export function attachSignature<T extends Statement>(stmt: T, sig: Uint8Array): SignedStatement<T> {
  statementBytes(stmt);
  if (!(sig instanceof Uint8Array) || sig.length !== ML_DSA_44_SIZES.signature) {
    throw new StatementError([`signature must be ${ML_DSA_44_SIZES.signature} bytes`]);
  }
  return { ...stmt, signature: Buffer.from(sig).toString("hex") };
}

/**
 * Split `{...statement fields, signature}` into the statement, its canonical bytes and
 * the signature bytes. The signature must be 4,840 lower-case hex characters.
 */
export function detachSignature(
  v: unknown,
  expectedType?: StatementType
): Validation<{ statement: Statement; bytes: Buffer; signature: Buffer }> {
  if (!isPlainObject(v)) return { ok: false, errors: ["signed statement must be a plain JSON object"] };
  const { signature, ...rest } = v;
  if (typeof signature !== "string" || !SIG_HEX_RE.test(signature)) {
    return { ok: false, errors: [`signature must be ${2 * ML_DSA_44_SIZES.signature} lower-case hex characters`] };
  }
  const r = validateStatement(rest, expectedType);
  if (!r.ok) return r;
  return { ok: true, value: { statement: r.value, bytes: canonicalJsonBytes(r.value), signature: Buffer.from(signature, "hex") } };
}
