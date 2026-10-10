/**
 * Minimal JOSE layer for the SD-JWT baseline (track E2a).
 *
 * - JWS compact serialization: BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(sig),
 *   signature computed over the US-ASCII bytes of the signing input (RFC 7515).
 * - "ML-DSA-44": pure ML-DSA-44 (FIPS 204), empty context, raw 2420-byte signature, JWK kty
 *   "AKP" with "alg" and "pub" (RFC 9964; facts in research/F5d_sdjwt_mdoc_shadowpath.md 1.8).
 *   Provided by Node 24.18 / OpenSSL 3.5.7 (DECISIONS D-003).
 * - "ES256": ECDSA P-256 with SHA-256, raw r||s (64 bytes, RFC 7518 3.4). Classical reference
 *   only, used to measure the PQ cost against a classical SD-JWT on the same code path.
 *
 * Keys live only in memory (KeyObject). Nothing here writes or logs a private key.
 */
import crypto, { type KeyObject } from "node:crypto";

export type Alg = "ML-DSA-44" | "ES256";
export const SUPPORTED_ALGS: readonly Alg[] = ["ML-DSA-44", "ES256"];

/** RFC 9964 sizes for ML-DSA-44 (bytes), checked against OpenSSL at runtime by the tests. */
export const ML_DSA_44_PUBLIC_KEY_BYTES = 1312;
export const ML_DSA_44_SIGNATURE_BYTES = 2420;
export const ES256_SIGNATURE_BYTES = 64;

export interface KeyPair {
  alg: Alg;
  publicKey: KeyObject;
  privateKey: KeyObject;
}

export function isAlg(x: unknown): x is Alg {
  return typeof x === "string" && (SUPPORTED_ALGS as readonly string[]).includes(x);
}

export function keygen(alg: Alg): KeyPair {
  if (alg === "ML-DSA-44") {
    const { publicKey, privateKey } = (crypto.generateKeyPairSync as unknown as (t: string) => { publicKey: KeyObject; privateKey: KeyObject })("ml-dsa-44");
    return { alg, publicKey, privateKey };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { alg, publicKey, privateKey };
}

/** True iff the key object is of the type `alg` needs (prevents algorithm/key confusion). */
export function keyMatchesAlg(key: KeyObject, alg: Alg): boolean {
  if (alg === "ML-DSA-44") return (key.asymmetricKeyType as string | undefined) === "ml-dsa-44";
  return key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1";
}

export function signBytes(alg: Alg, privateKey: KeyObject, data: Buffer): Buffer {
  if (!keyMatchesAlg(privateKey, alg)) throw new Error(`key does not match alg ${alg}`);
  if (alg === "ML-DSA-44") return crypto.sign(null, data, privateKey);
  return crypto.sign("sha256", data, { key: privateKey, dsaEncoding: "ieee-p1363" });
}

export function verifyBytes(alg: Alg, publicKey: KeyObject, data: Buffer, sig: Buffer): boolean {
  if (!keyMatchesAlg(publicKey, alg)) return false;
  const expectLen = alg === "ML-DSA-44" ? ML_DSA_44_SIGNATURE_BYTES : ES256_SIGNATURE_BYTES;
  if (sig.length !== expectLen) return false;
  try {
    if (alg === "ML-DSA-44") return crypto.verify(null, data, publicKey, sig);
    return crypto.verify("sha256", data, { key: publicKey, dsaEncoding: "ieee-p1363" }, sig);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- base64url, JSON

const B64U_RE = /^[A-Za-z0-9_-]*$/;

export function b64u(data: Buffer | string): string {
  return (typeof data === "string" ? Buffer.from(data, "utf8") : data).toString("base64url");
}

/** Strict base64url decode: alphabet only, no padding, canonical (re-encodes identically). */
export function b64uDecode(s: string): Buffer {
  if (!B64U_RE.test(s)) throw new Error("invalid base64url alphabet");
  const out = Buffer.from(s, "base64url");
  if (out.toString("base64url") !== s) throw new Error("non-canonical base64url");
  return out;
}

export function b64uJson(s: string): unknown {
  return JSON.parse(b64uDecode(s).toString("utf8"));
}

export function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

export function sha256(data: Buffer | string): Buffer {
  return crypto.createHash("sha256").update(typeof data === "string" ? Buffer.from(data, "ascii") : data).digest();
}

// ---------------------------------------------------------------- JWK (public keys only)

export type PublicJwk = Record<string, string>;

/** Public JWK of a public key: AKP {kty, alg, pub} for ML-DSA-44, EC {kty, crv, x, y} for ES256. */
export function publicJwk(publicKey: KeyObject, alg: Alg): PublicJwk {
  if (publicKey.type !== "public") throw new Error("publicJwk needs a public key");
  if (!keyMatchesAlg(publicKey, alg)) throw new Error(`key does not match alg ${alg}`);
  const j = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  if (alg === "ML-DSA-44") {
    if (j.kty !== "AKP" || j.alg !== "ML-DSA-44" || typeof j.pub !== "string") throw new Error("unexpected AKP JWK export");
    return { kty: "AKP", alg: "ML-DSA-44", pub: j.pub };
  }
  if (j.kty !== "EC" || j.crv !== "P-256" || typeof j.x !== "string" || typeof j.y !== "string") throw new Error("unexpected EC JWK export");
  return { kty: "EC", crv: "P-256", x: j.x, y: j.y };
}

/**
 * Imports a public JWK for use with `alg`. Rejects private members, unknown shapes and
 * a JWK whose type does not match the algorithm. Throws on any problem.
 */
export function importPublicJwk(jwk: unknown, alg: Alg): KeyObject {
  if (!isPlainObject(jwk)) throw new Error("jwk is not an object");
  if ("priv" in jwk || "d" in jwk) throw new Error("jwk carries private key material");
  if (alg === "ML-DSA-44") {
    if (jwk.kty !== "AKP" || jwk.alg !== "ML-DSA-44" || typeof jwk.pub !== "string") throw new Error("jwk is not an ML-DSA-44 AKP key");
    if (b64uDecode(jwk.pub).length !== ML_DSA_44_PUBLIC_KEY_BYTES) throw new Error("ML-DSA-44 pub has wrong length");
    const k = crypto.createPublicKey({ key: { kty: "AKP", alg: "ML-DSA-44", pub: jwk.pub }, format: "jwk" });
    if (!keyMatchesAlg(k, alg)) throw new Error("imported key type mismatch");
    return k;
  }
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") throw new Error("jwk is not a P-256 EC key");
  const k = crypto.createPublicKey({ key: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, format: "jwk" });
  if (!keyMatchesAlg(k, alg)) throw new Error("imported key type mismatch");
  return k;
}

// ---------------------------------------------------------------- JWS compact

export interface ParsedJws {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Buffer;
  /** The three base64url segments as received. */
  segments: [string, string, string];
}

export function signJws(alg: Alg, privateKey: KeyObject, header: Record<string, unknown>, payload: Record<string, unknown>): string {
  const h = { ...header, alg };
  const signingInput = `${b64u(JSON.stringify(h))}.${b64u(JSON.stringify(payload))}`;
  const sig = signBytes(alg, privateKey, Buffer.from(signingInput, "ascii"));
  return `${signingInput}.${b64u(sig)}`;
}

/** Parses a JWS compact string. Throws on malformed input; checks no signature. */
export function parseJws(jws: string): ParsedJws {
  const segs = jws.split(".");
  if (segs.length !== 3) throw new Error("JWS must have three segments");
  const [h, p, s] = segs as [string, string, string];
  const header = b64uJson(h);
  const payload = b64uJson(p);
  if (!isPlainObject(header)) throw new Error("JWS header is not an object");
  if (!isPlainObject(payload)) throw new Error("JWS payload is not an object");
  return { header, payload, signingInput: `${h}.${p}`, signature: b64uDecode(s), segments: [h, p, s] };
}
