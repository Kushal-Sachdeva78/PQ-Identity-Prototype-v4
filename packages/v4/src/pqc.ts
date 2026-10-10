import nodeCrypto, { type KeyObject } from "node:crypto";

/**
 * v4 post-quantum and symmetric primitives, all from Node's built-in OpenSSL 3.5
 * (DECISIONS D-003). In process, no subprocess, same code on Windows and Linux.
 *
 *  - ML-DSA-44 (FIPS 204), pure mode, empty context: identity keys and signed statements.
 *  - ML-KEM-768 (FIPS 203): the wallet to verifier session (V4_DESIGN section 5).
 *  - SHA3-256, HKDF-SHA-256 (RFC 5869), AES-256-GCM (16-byte tag, 12-byte IV).
 *
 * Public keys cross module boundaries as raw bytes (the FIPS encodings: 1,312 bytes for
 * ML-DSA-44, 1,184 bytes for ML-KEM-768). Private keys stay Node KeyObjects in memory;
 * nothing in this module exports or writes a private key.
 *
 * @types/node in this repo (22.x) does not yet declare ML-DSA / ML-KEM key types or
 * crypto.encapsulate/decapsulate, so the few untyped calls go through the narrow
 * interfaces below.
 */

export const ML_DSA_44_SIZES = { publicKey: 1312, signature: 2420 } as const;
export const ML_KEM_768_SIZES = { publicKey: 1184, ciphertext: 1088, sharedSecret: 32 } as const;
export const AES_GCM_SIZES = { key: 32, iv: 12, tag: 16 } as const;
export const SHA256_LEN = 32;

/**
 * DER SubjectPublicKeyInfo headers (RFC 5280 SPKI with the NIST OIDs
 * 2.16.840.1.101.3.4.3.17 id-ml-dsa-44 and 2.16.840.1.101.3.4.4.2 id-alg-ml-kem-768,
 * no parameters). SPKI = header || raw public key. Checked against OpenSSL's own export
 * in tests/v4/pqc_session.test.ts.
 */
export const ML_DSA_44_SPKI_PREFIX = Buffer.from("30820532300b06096086480165030403110382052100", "hex");
export const ML_KEM_768_SPKI_PREFIX = Buffer.from("308204b2300b0609608648016503040402038204a100", "hex");

const ALG_ML_DSA_44 = "ml-dsa-44";
const ALG_ML_KEM_768 = "ml-kem-768";

// ---- untyped Node 24 APIs (see header) ----
type GenerateKeyPairSyncNoOpts = (type: string) => { publicKey: KeyObject; privateKey: KeyObject };
interface NodeKemApi {
  encapsulate?: (key: KeyObject) => { sharedKey: Buffer; ciphertext: Buffer };
  decapsulate?: (key: KeyObject, ciphertext: Uint8Array) => Buffer;
}
const generateKeyPairSyncNoOpts = nodeCrypto.generateKeyPairSync as unknown as GenerateKeyPairSyncNoOpts;
const kemApi = nodeCrypto as unknown as NodeKemApi;

function isBytes(x: unknown): x is Uint8Array {
  return x instanceof Uint8Array;
}

function asBuffer(b: Uint8Array): Buffer {
  return Buffer.isBuffer(b) ? b : Buffer.from(b.buffer, b.byteOffset, b.byteLength);
}

function toBytes(x: Uint8Array | string): Buffer {
  return typeof x === "string" ? Buffer.from(x, "utf8") : asBuffer(x);
}

/**
 * Raw public keys derived from private KeyObjects, cached per KeyObject (KeyObjects are
 * immutable; the cache holds public data only and callers get a copy).
 */
const publicRawCache = new WeakMap<KeyObject, Buffer>();

function cachedPublicRaw(privateKey: KeyObject, prefix: Buffer, rawLen: number, alg: string): Buffer {
  let raw = publicRawCache.get(privateKey);
  if (!raw) {
    raw = rawFromSpki(nodeCrypto.createPublicKey(privateKey), prefix, rawLen, alg);
    publicRawCache.set(privateKey, raw);
  }
  return Buffer.from(raw);
}

/** Raw public key bytes of a KeyObject (strips and checks the known SPKI header). */
function rawFromSpki(pub: KeyObject, prefix: Buffer, rawLen: number, alg: string): Buffer {
  const spki = pub.export({ format: "der", type: "spki" });
  if (spki.length !== prefix.length + rawLen || !spki.subarray(0, prefix.length).equals(prefix)) {
    throw new Error(`unexpected ${alg} SPKI encoding (length ${spki.length})`);
  }
  return Buffer.from(spki.subarray(prefix.length));
}

function assertKeyType(key: unknown, type: "private" | "public", alg: string): asserts key is KeyObject {
  if (!(key instanceof nodeCrypto.KeyObject) || key.type !== type || (key.asymmetricKeyType as string | undefined) !== alg) {
    throw new Error(`expected a ${alg} ${type} KeyObject`);
  }
}

// ============================================================================
// ML-DSA-44
// ============================================================================

export interface MlDsaKeyPair {
  /** Raw FIPS 204 public key, 1,312 bytes. */
  publicKey: Buffer;
  /** In-memory private key; never exported. */
  privateKey: KeyObject;
}

export function mlDsaKeygen(): MlDsaKeyPair {
  const { publicKey, privateKey } = generateKeyPairSyncNoOpts(ALG_ML_DSA_44);
  return {
    publicKey: rawFromSpki(publicKey, ML_DSA_44_SPKI_PREFIX, ML_DSA_44_SIZES.publicKey, ALG_ML_DSA_44),
    privateKey,
  };
}

/** Raw public key (1,312 bytes) of an ML-DSA-44 private KeyObject. */
export function mlDsaPublicKeyRawOf(privateKey: KeyObject): Buffer {
  assertKeyType(privateKey, "private", ALG_ML_DSA_44);
  return cachedPublicRaw(privateKey, ML_DSA_44_SPKI_PREFIX, ML_DSA_44_SIZES.publicKey, ALG_ML_DSA_44);
}

/**
 * Import a raw ML-DSA-44 public key. `via: "spki"` (default) prepends the fixed DER
 * header; `via: "jwk"` uses the JOSE AKP form {kty:"AKP", alg:"ML-DSA-44", pub}.
 * Throws on a wrong length or an encoding OpenSSL refuses.
 */
export function mlDsaImportPublicKey(raw: Uint8Array, via: "spki" | "jwk" = "spki"): KeyObject {
  if (!isBytes(raw) || raw.length !== ML_DSA_44_SIZES.publicKey) {
    throw new Error(`ML-DSA-44 public key must be ${ML_DSA_44_SIZES.publicKey} bytes`);
  }
  if (via === "jwk") {
    return nodeCrypto.createPublicKey({
      key: { kty: "AKP", alg: "ML-DSA-44", pub: asBuffer(raw).toString("base64url") } as unknown as nodeCrypto.JsonWebKey,
      format: "jwk",
    });
  }
  return nodeCrypto.createPublicKey({ key: Buffer.concat([ML_DSA_44_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

/** ML-DSA-44 signature (pure, empty context, OpenSSL's default hedged signing). 2,420 bytes. */
export function mlDsaSign(privateKey: KeyObject, msg: Uint8Array): Buffer {
  assertKeyType(privateKey, "private", ALG_ML_DSA_44);
  if (!isBytes(msg)) throw new Error("message must be bytes");
  const sig = nodeCrypto.sign(null, msg, privateKey);
  if (sig.length !== ML_DSA_44_SIZES.signature) throw new Error(`internal: ML-DSA-44 signature length ${sig.length}`);
  return sig;
}

/**
 * Verify an ML-DSA-44 signature under a raw public key. Never throws: a wrong type,
 * wrong length, key OpenSSL refuses or failed verification all return false.
 * Each call imports the raw key (no hidden cache, so its cost is import + verify);
 * callers that verify many signatures under one key can import once with
 * mlDsaImportPublicKey and use mlDsaVerifyKey.
 */
export function mlDsaVerify(publicKeyRaw: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    if (!isBytes(publicKeyRaw) || !isBytes(msg) || !isBytes(sig)) return false;
    if (publicKeyRaw.length !== ML_DSA_44_SIZES.publicKey || sig.length !== ML_DSA_44_SIZES.signature) return false;
    const key = mlDsaImportPublicKey(publicKeyRaw);
    return nodeCrypto.verify(null, msg, key, sig) === true;
  } catch {
    return false;
  }
}

/** As mlDsaVerify, for an already imported ML-DSA-44 public KeyObject. Never throws. */
export function mlDsaVerifyKey(publicKey: KeyObject, msg: Uint8Array, sig: Uint8Array): boolean {
  try {
    assertKeyType(publicKey, "public", ALG_ML_DSA_44);
    if (!isBytes(msg) || !isBytes(sig) || sig.length !== ML_DSA_44_SIZES.signature) return false;
    return nodeCrypto.verify(null, msg, publicKey, sig) === true;
  } catch {
    return false;
  }
}

// ============================================================================
// ML-KEM-768
// ============================================================================

export interface MlKemKeyPair {
  /** Raw FIPS 203 encapsulation key, 1,184 bytes. */
  publicKey: Buffer;
  /** In-memory decapsulation key; never exported. */
  privateKey: KeyObject;
}

export interface MlKemEncapsulation {
  ciphertext: Buffer;
  sharedSecret: Buffer;
}

function kemFns(): Required<NodeKemApi> {
  if (typeof kemApi.encapsulate !== "function" || typeof kemApi.decapsulate !== "function") {
    throw new Error("this Node build has no crypto.encapsulate/decapsulate (needs Node 24.7+ with OpenSSL 3.5)");
  }
  return { encapsulate: kemApi.encapsulate, decapsulate: kemApi.decapsulate };
}

export function mlKemKeygen(): MlKemKeyPair {
  const { publicKey, privateKey } = generateKeyPairSyncNoOpts(ALG_ML_KEM_768);
  return {
    publicKey: rawFromSpki(publicKey, ML_KEM_768_SPKI_PREFIX, ML_KEM_768_SIZES.publicKey, ALG_ML_KEM_768),
    privateKey,
  };
}

/** Raw encapsulation key (1,184 bytes) of an ML-KEM-768 private KeyObject. */
export function mlKemPublicKeyRawOf(privateKey: KeyObject): Buffer {
  assertKeyType(privateKey, "private", ALG_ML_KEM_768);
  return cachedPublicRaw(privateKey, ML_KEM_768_SPKI_PREFIX, ML_KEM_768_SIZES.publicKey, ALG_ML_KEM_768);
}

/** Import a raw ML-KEM-768 encapsulation key (throws on a wrong length or a key OpenSSL refuses). */
export function mlKemImportPublicKey(raw: Uint8Array): KeyObject {
  if (!isBytes(raw) || raw.length !== ML_KEM_768_SIZES.publicKey) {
    throw new Error(`ML-KEM-768 public key must be ${ML_KEM_768_SIZES.publicKey} bytes`);
  }
  return nodeCrypto.createPublicKey({ key: Buffer.concat([ML_KEM_768_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

/** Encapsulate to a raw ML-KEM-768 key. Throws on a malformed key. */
export function mlKemEncaps(publicKeyRaw: Uint8Array): MlKemEncapsulation {
  const { encapsulate } = kemFns();
  const key = mlKemImportPublicKey(publicKeyRaw);
  const r = encapsulate(key);
  const ciphertext = Buffer.from(r.ciphertext);
  const sharedSecret = Buffer.from(r.sharedKey);
  if (ciphertext.length !== ML_KEM_768_SIZES.ciphertext || sharedSecret.length !== ML_KEM_768_SIZES.sharedSecret) {
    throw new Error("internal: unexpected ML-KEM-768 output sizes");
  }
  return { ciphertext, sharedSecret };
}

/**
 * Decapsulate. Throws on a wrong-length ciphertext. A well-formed but wrong or tampered
 * ciphertext does NOT throw: FIPS 203 implicit rejection returns an unrelated secret,
 * so the failure shows up later as an AEAD failure.
 */
export function mlKemDecaps(privateKey: KeyObject, ciphertext: Uint8Array): Buffer {
  const { decapsulate } = kemFns();
  assertKeyType(privateKey, "private", ALG_ML_KEM_768);
  if (!isBytes(ciphertext) || ciphertext.length !== ML_KEM_768_SIZES.ciphertext) {
    throw new Error(`ML-KEM-768 ciphertext must be ${ML_KEM_768_SIZES.ciphertext} bytes`);
  }
  const ss = Buffer.from(decapsulate(privateKey, ciphertext));
  if (ss.length !== ML_KEM_768_SIZES.sharedSecret) throw new Error("internal: unexpected ML-KEM-768 shared secret size");
  return ss;
}

// ============================================================================
// Hashes, HKDF, AEAD
// ============================================================================

/** SHA3-256 (FIPS 202) over the concatenation of the parts. */
export function sha3_256(...parts: Uint8Array[]): Buffer {
  const h = nodeCrypto.createHash("sha3-256");
  for (const p of parts) {
    if (!isBytes(p)) throw new Error("sha3_256 takes byte arrays");
    h.update(p);
  }
  return h.digest();
}

export function sha3_256Hex(...parts: Uint8Array[]): string {
  return sha3_256(...parts).toString("hex");
}

/** HKDF-Extract with SHA-256 (RFC 5869 section 2.2): PRK = HMAC-SHA-256(salt, IKM). */
export function hkdfSha256Extract(salt: Uint8Array, ikm: Uint8Array): Buffer {
  if (!isBytes(salt) || !isBytes(ikm)) throw new Error("HKDF-Extract takes byte arrays");
  // RFC 5869: an absent salt is HashLen zero bytes.
  const key = salt.length === 0 ? Buffer.alloc(SHA256_LEN) : salt;
  return nodeCrypto.createHmac("sha256", key).update(ikm).digest();
}

/**
 * HKDF-Expand with SHA-256 (RFC 5869 section 2.3). `info` is bytes or a UTF-8 string.
 * T(0) = empty, T(i) = HMAC(PRK, T(i-1) || info || i), OKM = first `len` bytes.
 */
export function hkdfSha256Expand(prk: Uint8Array, info: Uint8Array | string, len: number): Buffer {
  if (!isBytes(prk) || prk.length < SHA256_LEN) throw new Error(`HKDF PRK must be at least ${SHA256_LEN} bytes`);
  if (!Number.isSafeInteger(len) || len < 1 || len > 255 * SHA256_LEN) throw new Error("HKDF output length must be in [1, 8160]");
  const infoBytes = toBytes(info);
  const blocks: Buffer[] = [];
  let prev: Buffer = Buffer.alloc(0);
  for (let i = 1; blocks.length * SHA256_LEN < len; i++) {
    prev = nodeCrypto.createHmac("sha256", prk).update(prev).update(infoBytes).update(Uint8Array.of(i)).digest();
    blocks.push(prev);
  }
  return Buffer.concat(blocks).subarray(0, len);
}

export interface AeadBox {
  ciphertext: Buffer;
  tag: Buffer;
}

function checkAeadParams(key: Uint8Array, iv: Uint8Array, aad: Uint8Array): void {
  if (!isBytes(key) || key.length !== AES_GCM_SIZES.key) throw new Error("AES-256-GCM key must be 32 bytes");
  if (!isBytes(iv) || iv.length !== AES_GCM_SIZES.iv) throw new Error("AES-256-GCM IV must be 12 bytes");
  if (!isBytes(aad)) throw new Error("AES-256-GCM AAD must be bytes");
}

/** AES-256-GCM encryption with a 16-byte tag. The caller must never reuse (key, iv). */
export function aes256gcmSeal(key: Uint8Array, iv: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): AeadBox {
  checkAeadParams(key, iv, aad);
  if (!isBytes(plaintext)) throw new Error("plaintext must be bytes");
  const c = nodeCrypto.createCipheriv("aes-256-gcm", key, iv, { authTagLength: AES_GCM_SIZES.tag });
  c.setAAD(aad);
  const ciphertext = Buffer.concat([c.update(plaintext), c.final()]);
  return { ciphertext, tag: c.getAuthTag() };
}

/** AES-256-GCM decryption. Returns null on any failure (bad tag, wrong sizes, wrong types). */
export function aes256gcmOpen(key: Uint8Array, iv: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Buffer | null {
  try {
    checkAeadParams(key, iv, aad);
    if (!isBytes(ciphertext) || !isBytes(tag) || tag.length !== AES_GCM_SIZES.tag) return null;
    const d = nodeCrypto.createDecipheriv("aes-256-gcm", key, iv, { authTagLength: AES_GCM_SIZES.tag });
    d.setAAD(aad);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ciphertext), d.final()]);
  } catch {
    return null;
  }
}

/** Provenance label for results files, e.g. "OpenSSL 3.5.7 via Node 24.18.0". */
export function implementationLabel(): string {
  return `OpenSSL ${process.versions.openssl} via Node ${process.versions.node}`;
}
