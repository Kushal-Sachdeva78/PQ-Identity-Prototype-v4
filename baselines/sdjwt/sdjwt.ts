/**
 * Baseline E2a: a minimal but faithful SD-JWT (RFC 9901) with key binding, signed with
 * ML-DSA-44 (RFC 9964 JOSE identifier) for both the issuer JWT and the KB-JWT.
 *
 * Wire format (RFC 9901 Sec. 4, 5):
 *   issuance:     <issuer-signed JWT>~<disclosure 1>~...~<disclosure N>~
 *   presentation: <issuer-signed JWT>~<selected disclosure>~...~<KB-JWT>
 * - Disclosure = BASE64URL(JSON [salt, claim name, claim value]); salt = 128 random bits.
 * - Digest = BASE64URL(SHA-256(US-ASCII(disclosure))); digests go into the "_sd" array,
 *   sorted so the claim order is hidden; "_sd_alg" = "sha-256".
 * - Holder key in "cnf": {"jwk": ...} (RFC 7800); for ML-DSA-44 a JWK of kty "AKP".
 * - KB-JWT header typ "kb+jwt"; claims iat, aud, nonce, sd_hash, where sd_hash is the
 *   SHA-256 of everything before the KB-JWT (issuer JWT, "~", each disclosure and "~").
 * - Issuer JWT header typ "dc+sd-jwt" and claim "vct" follow SD-JWT VC
 *   (draft-ietf-oauth-sd-jwt-vc-19); iss, iat, exp, vct, cnf are always visible.
 * Facts and section numbers: research/F5d_sdjwt_mdoc_shadowpath.md sections 1.2 to 1.8.
 *
 * Linkability: the issuer-signed JWT (signature, digests, cnf key) is byte-identical in
 * every presentation of one SD-JWT (RFC 9901 Sec. 10.1). Unlinkability across verifiers
 * therefore needs single-use credentials from a batch (./batch.ts). iat and exp are
 * rounded to the UTC day by default so they are shared by everyone issued that day.
 *
 * Private keys stay in memory (KeyObject); nothing here writes or logs one.
 */
import crypto, { type KeyObject } from "node:crypto";
import {
  type Alg,
  type KeyPair,
  type PublicJwk,
  b64u,
  b64uDecode,
  importPublicJwk,
  isAlg,
  isPlainObject,
  keygen,
  keyMatchesAlg,
  parseJws,
  publicJwk,
  sha256,
  signJws,
  verifyBytes,
} from "./jose.ts";

export const SD_ALG = "sha-256";
export const TYP_SDJWT = "dc+sd-jwt";
export const TYP_KB = "kb+jwt";
export const DEFAULT_VCT = "urn:pqid:baseline:sd-jwt-age:v1";
export const DEFAULT_ISS = "https://issuer.baseline.invalid";
export const SALT_BYTES = 16;
export const DAY_SEC = 86400;
/** Same default lifetime as v4 credentials (DEFAULT_CREDENTIAL_DAYS = 90). */
export const DEFAULT_VALIDITY_SEC = 90 * DAY_SEC;

/** Claims that must stay visible (SD-JWT VC) or are SD-JWT syntax; never disclosable. */
export const NON_DISCLOSABLE: ReadonlySet<string> = new Set([
  "_sd",
  "...",
  "_sd_alg",
  "iss",
  "nbf",
  "exp",
  "cnf",
  "vct",
  "vct#integrity",
  "status",
]);

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

/** The JOSE alg a key object is used with, or throws. */
export function algOfKey(key: KeyObject): Alg {
  if (keyMatchesAlg(key, "ML-DSA-44")) return "ML-DSA-44";
  if (keyMatchesAlg(key, "ES256")) return "ES256";
  throw new Error(`unsupported key type ${String(key.asymmetricKeyType)}`);
}

// ---------------------------------------------------------------- disclosures

export interface Disclosure {
  encoded: string;
  digest: string;
  salt: string;
  /** Claim name for an object-property disclosure; null for an array-element disclosure. */
  name: string | null;
  value: unknown;
}

export function digestOf(encodedDisclosure: string): string {
  return b64u(sha256(encodedDisclosure));
}

export function makeDisclosure(name: string, value: unknown, salt?: string): Disclosure {
  const s = salt ?? b64u(crypto.randomBytes(SALT_BYTES));
  const encoded = b64u(JSON.stringify([s, name, value]));
  return { encoded, digest: digestOf(encoded), salt: s, name, value };
}

/** Decodes one disclosure string. Throws on a malformed disclosure. */
export function decodeDisclosure(encoded: string): Disclosure {
  if (encoded.length === 0) throw new Error("empty disclosure");
  const arr: unknown = JSON.parse(b64uDecode(encoded).toString("utf8"));
  if (!Array.isArray(arr)) throw new Error("disclosure is not a JSON array");
  if (arr.length === 3) {
    const [salt, name, value] = arr as [unknown, unknown, unknown];
    if (typeof salt !== "string" || typeof name !== "string") throw new Error("disclosure salt/name must be strings");
    return { encoded, digest: digestOf(encoded), salt, name, value };
  }
  if (arr.length === 2) {
    const [salt, value] = arr as [unknown, unknown];
    if (typeof salt !== "string") throw new Error("disclosure salt must be a string");
    return { encoded, digest: digestOf(encoded), salt, name: null, value };
  }
  throw new Error("disclosure must have 2 or 3 elements");
}

// ---------------------------------------------------------------- split / join

export interface SplitSdJwt {
  issuerJwt: string;
  disclosures: string[];
  /** null for the issuance form (trailing "~"). */
  kbJwt: string | null;
}

export function splitSdJwt(s: string): SplitSdJwt {
  if (typeof s !== "string" || !s.includes("~")) throw new Error("not an SD-JWT (no '~')");
  const parts = s.split("~");
  const issuerJwt = parts[0] as string;
  const last = parts[parts.length - 1] as string;
  const disclosures = parts.slice(1, -1);
  if (issuerJwt.length === 0) throw new Error("empty issuer-signed JWT");
  if (disclosures.some((d) => d.length === 0)) throw new Error("empty disclosure segment");
  return { issuerJwt, disclosures, kbJwt: last.length === 0 ? null : last };
}

/** The string sd_hash covers: issuer JWT, "~", then each disclosure followed by "~". */
export function sdHashInput(issuerJwt: string, disclosures: readonly string[]): string {
  return `${issuerJwt}~${disclosures.map((d) => `${d}~`).join("")}`;
}

export function sdHashOf(issuerJwt: string, disclosures: readonly string[]): string {
  return b64u(sha256(sdHashInput(issuerJwt, disclosures)));
}

// ---------------------------------------------------------------- issuer

export interface IssueOptions {
  /** Issuance time, unix seconds (default: now). */
  now?: number;
  validitySec?: number;
  /** Round iat down to 00:00 UTC and set exp = iat + validity (default true). */
  roundToDay?: boolean;
  vct?: string;
  /** Number of decoy digests (RFC 9901 Sec. 4.2.5); default 0. */
  decoys?: number;
}

export interface IssuerKey {
  alg: Alg;
  iss: string;
  publicKey: KeyObject;
  privateKey: KeyObject;
}

export function newIssuerKey(alg: Alg = "ML-DSA-44", iss: string = DEFAULT_ISS): IssuerKey {
  const kp = keygen(alg);
  return { alg, iss, publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/**
 * Issues one SD-JWT whose every entry of `claims` is selectively disclosable, bound to
 * `holderPk` through cnf.jwk. Returns the issuance form "<jwt>~<d1>~...~<dN>~".
 */
export function issue(issuer: IssuerKey, claims: Record<string, unknown>, holderPk: KeyObject, opts: IssueOptions = {}): string {
  const now = opts.now ?? nowSec();
  const validity = opts.validitySec ?? DEFAULT_VALIDITY_SEC;
  const iat = opts.roundToDay === false ? now : now - (now % DAY_SEC);
  const holderAlg = algOfKey(holderPk);
  const disclosures: Disclosure[] = [];
  for (const [name, value] of Object.entries(claims)) {
    if (NON_DISCLOSABLE.has(name)) throw new Error(`claim ${name} must not be selectively disclosable`);
    disclosures.push(makeDisclosure(name, value));
  }
  const digests = disclosures.map((d) => d.digest);
  for (let i = 0; i < (opts.decoys ?? 0); i++) digests.push(b64u(sha256(crypto.randomBytes(SALT_BYTES))));
  digests.sort();
  const payload: Record<string, unknown> = {
    iss: issuer.iss,
    iat,
    exp: iat + validity,
    vct: opts.vct ?? DEFAULT_VCT,
    cnf: { jwk: publicJwk(holderPk, holderAlg) },
    _sd_alg: SD_ALG,
    _sd: digests,
  };
  const jwt = signJws(issuer.alg, issuer.privateKey, { typ: TYP_SDJWT }, payload);
  return `${jwt}~${disclosures.map((d) => `${d.encoded}~`).join("")}`;
}

/** Issuer object with the call shape issue(claims, holderPk). */
export class SdJwtIssuer {
  readonly alg: Alg;
  readonly iss: string;
  readonly publicKey: KeyObject;
  readonly #key: IssuerKey;
  constructor(alg: Alg = "ML-DSA-44", iss: string = DEFAULT_ISS) {
    this.#key = newIssuerKey(alg, iss);
    this.alg = alg;
    this.iss = iss;
    this.publicKey = this.#key.publicKey;
  }
  issue(claims: Record<string, unknown>, holderPk: KeyObject, opts: IssueOptions = {}): string {
    return issue(this.#key, claims, holderPk, opts);
  }
  /** For tests only: the issuer key (in memory). */
  get keyForTests(): IssuerKey {
    return this.#key;
  }
}

// ---------------------------------------------------------------- holder

export interface PresentOptions {
  nonce: string;
  aud: string;
  /** Holder private key matching the credential's cnf.jwk. */
  holderKey: KeyObject;
  /** KB-JWT iat, unix seconds (default: now). */
  iat?: number;
}

/**
 * Builds a presentation that reveals only the named claims and ends in a KB-JWT over
 * {iat, aud, nonce, sd_hash}. Throws if a requested claim has no disclosure or the
 * holder key does not match cnf.
 */
export function present(sdjwt: string, disclose: readonly string[], opts: PresentOptions): string {
  const parts = splitSdJwt(sdjwt);
  if (parts.kbJwt !== null) throw new Error("input already carries a KB-JWT; present from the issuance form");
  const decoded = parts.disclosures.map(decodeDisclosure);
  const wanted = [...new Set(disclose)];
  const selected: string[] = [];
  for (const name of wanted) {
    const d = decoded.find((x) => x.name === name);
    if (!d) throw new Error(`no disclosure for claim ${name}`);
    selected.push(d.encoded);
  }
  const alg = algOfKey(opts.holderKey);
  const { payload } = parseJws(parts.issuerJwt);
  const cnf = payload.cnf;
  const holderPub = crypto.createPublicKey(opts.holderKey);
  if (!isPlainObject(cnf) || JSON.stringify(cnf.jwk) !== JSON.stringify(publicJwk(holderPub, alg))) {
    throw new Error("holder key does not match the credential's cnf.jwk");
  }
  const kb = signJws(alg, opts.holderKey, { typ: TYP_KB }, {
    iat: opts.iat ?? nowSec(),
    aud: opts.aud,
    nonce: opts.nonce,
    sd_hash: sdHashOf(parts.issuerJwt, selected),
  });
  return `${sdHashInput(parts.issuerJwt, selected)}${kb}`;
}

/** Holder object with the call shape present(sdjwt, disclose, {nonce, aud}). */
export class SdJwtHolder {
  readonly alg: Alg;
  readonly publicKey: KeyObject;
  readonly #keys: KeyPair;
  constructor(alg: Alg = "ML-DSA-44", keys?: KeyPair) {
    this.#keys = keys ?? keygen(alg);
    if (this.#keys.alg !== alg) throw new Error("key pair alg mismatch");
    this.alg = alg;
    this.publicKey = this.#keys.publicKey;
  }
  present(sdjwt: string, disclose: readonly string[], opts: { nonce: string; aud: string; iat?: number }): string {
    return present(sdjwt, disclose, { ...opts, holderKey: this.#keys.privateKey });
  }
  /** For tests only (e.g. to model a stolen credential used with another key). */
  get privateKeyForTests(): KeyObject {
    return this.#keys.privateKey;
  }
}

// ---------------------------------------------------------------- verifier

export type VerifyError =
  | "format"
  | "issuer_alg"
  | "issuer_typ"
  | "issuer_crit"
  | "issuer_key"
  | "issuer_signature"
  | "issuer_iss"
  | "claims_shape"
  | "sd_alg"
  | "expired"
  | "not_yet_valid"
  | "disclosure_format"
  | "disclosure_duplicate"
  | "disclosure_shape"
  | "digest_reused"
  | "claim_name"
  | "claim_exists"
  | "disclosure_unreferenced"
  | "kb_missing"
  | "kb_format"
  | "kb_typ"
  | "kb_alg"
  | "kb_cnf"
  | "kb_signature"
  | "kb_sd_hash"
  | "kb_nonce"
  | "kb_aud"
  | "kb_iat"
  | "required_claim_missing";

export interface VerifyOptions {
  nonce: string;
  aud: string;
  /** Verifier's current time, unix seconds. */
  now: number;
  /** Accepted JOSE algs for both JWTs (default: ML-DSA-44 only). "none" is never accepted. */
  allowedAlgs?: readonly Alg[];
  expectedIss?: string;
  expectedVct?: string;
  /** Default true: a presentation without a KB-JWT is rejected. */
  requireKeyBinding?: boolean;
  /** Maximum KB-JWT age in seconds (default 300). */
  kbMaxAgeSec?: number;
  /** Clock tolerance in seconds (default 60). */
  clockSkewSec?: number;
  /** Claims that must be disclosed. */
  required?: readonly string[];
}

export type VerifyResult =
  | { ok: true; issuer: string; vct: string; disclosed: Record<string, unknown>; claims: Record<string, unknown> }
  | { ok: false; error: VerifyError; detail: string };

class Reject extends Error {
  constructor(
    readonly code: VerifyError,
    detail: string
  ) {
    super(detail);
  }
}

function fail(code: VerifyError, detail: string): never {
  throw new Reject(code, detail);
}

/**
 * Replaces digests by the disclosed claims (RFC 9901 Sec. 7.1 step 3), recursively over
 * objects ("_sd") and arrays ({"...": digest}); marks every used digest.
 */
function processNode(
  node: unknown,
  byDigest: ReadonlyMap<string, Disclosure>,
  used: Set<string>,
  topLevelDisclosed: Record<string, unknown> | null
): unknown {
  if (Array.isArray(node)) {
    const out: unknown[] = [];
    for (const el of node) {
      if (isPlainObject(el) && Object.keys(el).length === 1 && "..." in el) {
        const dg = el["..."];
        if (typeof dg !== "string") fail("claims_shape", "array digest is not a string");
        if (used.has(dg)) fail("digest_reused", "digest appears more than once");
        used.add(dg);
        const d = byDigest.get(dg);
        if (!d) continue; // undisclosed element or decoy: dropped
        if (d.name !== null) fail("disclosure_shape", "object-property disclosure referenced from an array");
        out.push(processNode(d.value, byDigest, used, null));
      } else {
        out.push(processNode(el, byDigest, used, null));
      }
    }
    return out;
  }
  if (!isPlainObject(node)) return node;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(node)) {
    if (k === "_sd") continue;
    out[k] = processNode(v, byDigest, used, null);
  }
  if ("_sd" in node) {
    const sd = node._sd;
    if (!Array.isArray(sd) || sd.some((x) => typeof x !== "string")) fail("claims_shape", "_sd is not an array of strings");
    for (const dg of sd as string[]) {
      if (used.has(dg)) fail("digest_reused", "digest appears more than once");
      used.add(dg);
      const d = byDigest.get(dg);
      if (!d) continue; // undisclosed claim or decoy
      if (d.name === null) fail("disclosure_shape", "array-element disclosure referenced from _sd");
      if (NON_DISCLOSABLE.has(d.name)) fail("claim_name", `claim name ${d.name} may not be disclosed`);
      if (Object.prototype.hasOwnProperty.call(out, d.name)) fail("claim_exists", `claim ${d.name} already present`);
      const value = processNode(d.value, byDigest, used, null);
      out[d.name] = value;
      if (topLevelDisclosed) topLevelDisclosed[d.name] = value;
    }
  }
  return out;
}

function verifyInner(presentation: string, issuerPk: KeyObject, opts: VerifyOptions): VerifyResult {
  const allowed = opts.allowedAlgs ?? ["ML-DSA-44"];
  const skew = opts.clockSkewSec ?? 60;
  const kbMaxAge = opts.kbMaxAgeSec ?? 300;

  let parts: SplitSdJwt;
  try {
    parts = splitSdJwt(presentation);
  } catch (e) {
    fail("format", (e as Error).message);
  }

  // 1. issuer-signed JWT
  let jws: ReturnType<typeof parseJws>;
  try {
    jws = parseJws(parts.issuerJwt);
  } catch (e) {
    fail("format", `issuer JWT: ${(e as Error).message}`);
  }
  const alg = jws.header.alg;
  if (!isAlg(alg) || !allowed.includes(alg)) fail("issuer_alg", `issuer alg ${String(alg)} not accepted`);
  if (jws.header.typ !== TYP_SDJWT) fail("issuer_typ", `issuer typ ${String(jws.header.typ)}`);
  if ("crit" in jws.header) fail("issuer_crit", "crit header not supported");
  if (!keyMatchesAlg(issuerPk, alg)) fail("issuer_key", "issuer key does not match alg");
  if (!verifyBytes(alg, issuerPk, Buffer.from(jws.signingInput, "ascii"), jws.signature)) {
    fail("issuer_signature", "issuer signature invalid");
  }
  const p = jws.payload;
  if (typeof p.iss !== "string" || typeof p.vct !== "string" || typeof p.exp !== "number") {
    fail("claims_shape", "iss, vct (string) and exp (number) are required");
  }
  if (opts.expectedIss !== undefined && p.iss !== opts.expectedIss) fail("issuer_iss", "unexpected iss");
  if (opts.expectedVct !== undefined && p.vct !== opts.expectedVct) fail("claims_shape", "unexpected vct");
  const sdAlg = p._sd_alg ?? SD_ALG;
  if (sdAlg !== SD_ALG) fail("sd_alg", `_sd_alg ${String(sdAlg)} not supported`);
  if (p.exp <= opts.now - skew) fail("expired", "credential expired");
  if (typeof p.nbf === "number" && p.nbf > opts.now + skew) fail("not_yet_valid", "nbf in the future");
  if (typeof p.iat === "number" && p.iat > opts.now + skew) fail("not_yet_valid", "iat in the future");

  // 2. disclosures
  const byDigest = new Map<string, Disclosure>();
  for (const enc of parts.disclosures) {
    let d: Disclosure;
    try {
      d = decodeDisclosure(enc);
    } catch (e) {
      fail("disclosure_format", (e as Error).message);
    }
    if (byDigest.has(d.digest)) fail("disclosure_duplicate", "same disclosure twice");
    byDigest.set(d.digest, d);
  }
  const used = new Set<string>();
  const disclosed: Record<string, unknown> = {};
  const processed = processNode(p, byDigest, used, disclosed) as Record<string, unknown>;
  delete processed._sd_alg;
  for (const dg of byDigest.keys()) {
    if (!used.has(dg)) fail("disclosure_unreferenced", "a disclosure is not referenced by any digest");
  }

  // 3. key binding
  if (parts.kbJwt === null) {
    if (opts.requireKeyBinding !== false) fail("kb_missing", "KB-JWT required");
  } else {
    let kb: ReturnType<typeof parseJws>;
    try {
      kb = parseJws(parts.kbJwt);
    } catch (e) {
      fail("kb_format", (e as Error).message);
    }
    if (kb.header.typ !== TYP_KB) fail("kb_typ", `KB-JWT typ ${String(kb.header.typ)}`);
    const kbAlg = kb.header.alg;
    if (!isAlg(kbAlg) || !allowed.includes(kbAlg)) fail("kb_alg", `KB-JWT alg ${String(kbAlg)} not accepted`);
    // cnf is read from the signed payload itself, never from a disclosure
    const cnf = p.cnf;
    let holderPk: KeyObject;
    try {
      if (!isPlainObject(cnf)) throw new Error("cnf missing");
      holderPk = importPublicJwk(cnf.jwk, kbAlg);
    } catch (e) {
      fail("kb_cnf", (e as Error).message);
    }
    if (!verifyBytes(kbAlg, holderPk, Buffer.from(kb.signingInput, "ascii"), kb.signature)) {
      fail("kb_signature", "KB-JWT signature invalid");
    }
    const k = kb.payload;
    if (k.sd_hash !== sdHashOf(parts.issuerJwt, parts.disclosures)) fail("kb_sd_hash", "sd_hash mismatch");
    if (k.nonce !== opts.nonce) fail("kb_nonce", "nonce mismatch");
    if (k.aud !== opts.aud) fail("kb_aud", "aud mismatch");
    if (typeof k.iat !== "number" || k.iat > opts.now + skew || k.iat < opts.now - kbMaxAge - skew) {
      fail("kb_iat", "KB-JWT iat outside the accepted window");
    }
  }

  for (const r of opts.required ?? []) {
    if (!(r in disclosed)) fail("required_claim_missing", `claim ${r} not disclosed`);
  }
  return { ok: true, issuer: p.iss, vct: p.vct, disclosed, claims: processed };
}

/** Verifies an SD-JWT+KB presentation (RFC 9901 Sec. 7.1 and 7.3). Never throws. */
export function verify(presentation: string, issuerPk: KeyObject, opts: VerifyOptions): VerifyResult {
  try {
    return verifyInner(presentation, issuerPk, opts);
  } catch (e) {
    if (e instanceof Reject) return { ok: false, error: e.code, detail: e.message };
    return { ok: false, error: "format", detail: (e as Error).message };
  }
}

// ---------------------------------------------------------------- sizes

export interface SdJwtSizes {
  /** Every size is in bytes; the serialization is ASCII, so bytes = characters. */
  totalBytes: number;
  issuerJwt: {
    totalBytes: number;
    headerB64Bytes: number;
    payloadB64Bytes: number;
    signatureB64Bytes: number;
    signatureRawBytes: number;
    payloadJsonBytes: number;
    cnfJwkJsonBytes: number;
    sdDigestCount: number;
  };
  disclosures: { count: number; bytes: number; each: number[] };
  separatorBytes: number;
  kbJwt: { totalBytes: number; signatureRawBytes: number; payloadJsonBytes: number } | null;
}

export function sizesOf(s: string): SdJwtSizes {
  const parts = splitSdJwt(s);
  const jws = parseJws(parts.issuerJwt);
  const [h, pl, sg] = jws.segments;
  const cnf = jws.payload.cnf;
  const sd = jws.payload._sd;
  const each = parts.disclosures.map((d) => d.length);
  let kb: SdJwtSizes["kbJwt"] = null;
  if (parts.kbJwt !== null) {
    const k = parseJws(parts.kbJwt);
    kb = {
      totalBytes: parts.kbJwt.length,
      signatureRawBytes: k.signature.length,
      payloadJsonBytes: Buffer.from(k.segments[1], "base64url").length,
    };
  }
  return {
    totalBytes: s.length,
    issuerJwt: {
      totalBytes: parts.issuerJwt.length,
      headerB64Bytes: h.length,
      payloadB64Bytes: pl.length,
      signatureB64Bytes: sg.length,
      signatureRawBytes: jws.signature.length,
      payloadJsonBytes: Buffer.from(pl, "base64url").length,
      cnfJwkJsonBytes: isPlainObject(cnf) ? JSON.stringify(cnf.jwk).length : 0,
      sdDigestCount: Array.isArray(sd) ? sd.length : 0,
    },
    disclosures: { count: each.length, bytes: each.reduce((a, b) => a + b, 0), each },
    separatorBytes: s.split("~").length - 1,
    kbJwt: kb,
  };
}

// ---------------------------------------------------------------- linkability handles

export interface LinkHandles {
  /**
   * Values specific to one credential (or one holder key). Any value shared by two
   * presentations links them: "jwt:" issuer-signed JWT hash, "sig:" issuer signature
   * hash, "digest:" each _sd entry, "cnf:" hash of the holder JWK, "salt:" each disclosed salt.
   */
  perCredential: string[];
  /**
   * Values that are the same for every credential of this type issued by this issuer
   * on the same day (not holder handles): header, iss, vct, iat, exp, _sd_alg, digest count.
   */
  population: Record<string, unknown>;
}

export function linkHandles(presentation: string): LinkHandles {
  const parts = splitSdJwt(presentation);
  const jws = parseJws(parts.issuerJwt);
  const p = jws.payload;
  const h = (x: Buffer | string): string => b64u(sha256(typeof x === "string" ? Buffer.from(x, "utf8") : x));
  const out: string[] = [`jwt:${h(parts.issuerJwt)}`, `sig:${h(jws.signature)}`];
  if (Array.isArray(p._sd)) for (const d of p._sd) out.push(`digest:${String(d)}`);
  if (isPlainObject(p.cnf)) out.push(`cnf:${h(JSON.stringify(p.cnf.jwk as PublicJwk))}`);
  for (const d of parts.disclosures) out.push(`salt:${decodeDisclosure(d).salt}`);
  return {
    perCredential: out,
    population: {
      header: jws.header,
      iss: p.iss,
      vct: p.vct,
      iat: p.iat,
      exp: p.exp,
      _sd_alg: p._sd_alg,
      sdDigestCount: Array.isArray(p._sd) ? p._sd.length : 0,
    },
  };
}

/** perCredential handles two presentations have in common (empty = no shared handle). */
export function sharedHandles(a: string, b: string): string[] {
  const hb = new Set(linkHandles(b).perCredential);
  return linkHandles(a).perCredential.filter((x) => hb.has(x));
}
