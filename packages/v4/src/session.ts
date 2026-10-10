import { randomBytes, type KeyObject } from "node:crypto";
import { canonicalJsonBytes } from "@pqid/common/hash";
import { SESSION_TTL_MS, TYPE_REPLY, TYPE_REQUEST, TYPE_TRANSCRIPT, WALLET_CLOCK_SKEW_SEC } from "./constants.ts";
import { isValidYmd } from "./dates.ts";
import { fieldFrom31Bytes, type PredicateName } from "./encoding.ts";
import {
  AES_GCM_SIZES,
  ML_KEM_768_SIZES,
  aes256gcmOpen,
  aes256gcmSeal,
  hkdfSha256Expand,
  hkdfSha256Extract,
  mlKemDecaps,
  mlKemEncaps,
  mlKemPublicKeyRawOf,
  sha3_256,
} from "./pqc.ts";
import { isDidPq, isHex64, isLowerAddress, isPlainObject, isPositiveInt, isUint, schemaErrors } from "./statements.ts";

/**
 * v4 wallet to verifier session (V4_DESIGN section 5; DECISIONS D-015, D-016).
 *
 *   1. verifier -> wallet: request (ProofRequestV4), stored by the verifier under sessionId.
 *   2. wallet: (ct, ss) = ML-KEM-768.Encaps(kemPk), where kemPk is the verifier's key
 *      resolved FROM CHAIN by the caller (never taken from the request).
 *   3. T = SHA3-256(canonicalJson({type:"pqid:transcript:v4", request, kemPkSha3, ctSha3}))
 *      prk = HKDF-Extract(SHA-256, salt = T, ikm = ss)
 *      nonce = int(HKDF-Expand(prk, "pqid:v4:nonce", 31))   (248 bits, < p)
 *      key = HKDF-Expand(prk, "pqid:v4:aead-key", 32), iv = HKDF-Expand(prk, "pqid:v4:aead-iv", 12)
 *   4. wallet proves with public `nonce`, then sends
 *      reply = {type:"pqid:reply:v4", sessionId, ct, box = AES-256-GCM(key, iv, aad = T,
 *      canonicalJson(presentation))}.
 *   5. verifier: stored request by sessionId, Decaps, recompute T, prk, nonce, key, iv,
 *      decrypt. The caller runs the remaining checks and consumes the session on success.
 *
 * Wire encoding (implementation choice, not fixed by V4_DESIGN): `ct` is the ML-KEM
 * ciphertext as lower-case hex (2,176 characters); `box` is lower-case hex of
 * AES-GCM ciphertext || 16-byte tag. The plaintext is at most MAX_PRESENTATION_BYTES.
 *
 * Because the wallet's proof needs the nonce before sealing, the wallet side is two
 * steps: walletOpenSession (encapsulate, derive) then walletSealReply (encrypt once).
 */

/** Upper bound on the sealed presentation (implementation limit against oversized replies). */
export const MAX_PRESENTATION_BYTES = 1 << 20;
/** Upper bound on policy.typeId length (characters). */
export const MAX_TYPE_ID_LENGTH = 256;

export const HKDF_INFO_NONCE = "pqid:v4:nonce";
export const HKDF_INFO_KEY = "pqid:v4:aead-key";
export const HKDF_INFO_IV = "pqid:v4:aead-iv";

export interface RequestPolicyV4 {
  predicate: PredicateName;
  threshold: number;
  typeId: string;
  /** Verifier's current UTC date, YYYYMMDD. */
  today: number;
}

export interface ProofRequestV4 {
  type: typeof TYPE_REQUEST;
  /** 32 random bytes, lower-case hex. */
  sessionId: string;
  verifierDid: string;
  /** Lower-case 0x EVM address of the verifier's DID record. */
  verifierController: string;
  chainId: number;
  policy: RequestPolicyV4;
  /** Unix seconds. */
  issuedAt: number;
}

export interface SessionReplyV4 {
  type: typeof TYPE_REPLY;
  sessionId: string;
  /** ML-KEM-768 ciphertext, lower-case hex. */
  ct: string;
  /** AES-256-GCM ciphertext || tag, lower-case hex. */
  box: string;
}

export interface NewRequestParams {
  verifierDid: string;
  verifierController: string;
  chainId: number;
  policy: RequestPolicyV4;
  /** Unix seconds; defaults to now. */
  issuedAt?: number;
}

export interface SessionSecrets {
  /** Public proof nonce (248-bit field element). */
  nonce: bigint;
  /** AES-256-GCM key (32 bytes). */
  key: Buffer;
  /** AES-256-GCM IV (12 bytes). */
  iv: Buffer;
}

export interface WalletSession extends SessionSecrets {
  readonly request: ProofRequestV4;
  /** ML-KEM ciphertext (1,088 bytes) that goes into the reply. */
  readonly ciphertext: Buffer;
  /** Transcript hash T (32 bytes), also the AEAD associated data. */
  readonly transcript: Buffer;
}

// ============================================================================
// Shapes
// ============================================================================

type Check = (v: unknown) => string | null;
const REQUEST_SCHEMA: Record<string, Check> = {
  type: (v) => (v === TYPE_REQUEST ? null : `must be "${TYPE_REQUEST}"`),
  sessionId: (v) => (isHex64(v) ? null : "must be 64 lower-case hex characters"),
  verifierDid: (v) => (isDidPq(v) ? null : "must be a did:pq identifier"),
  verifierController: (v) => (isLowerAddress(v) ? null : "must be a lower-case 0x EVM address"),
  chainId: (v) => (isPositiveInt(v) ? null : "must be a positive safe integer"),
  policy: () => null, // checked below
  issuedAt: (v) => (isUint(v) ? null : "must be a non-negative safe integer (unix seconds)"),
};
const POLICY_SCHEMA: Record<string, Check> = {
  predicate: (v) => (v === "age_gte" || v === "age_lt" ? null : 'must be "age_gte" or "age_lt"'),
  // Shape only; the wallet's `thresholdStandard` check decides whether it answers.
  threshold: (v) => (isUint(v) && v <= 255 ? null : "must be an integer in [0, 255]"),
  typeId: (v) => (typeof v === "string" && v.length > 0 && v.length <= MAX_TYPE_ID_LENGTH ? null : `must be a non-empty string of at most ${MAX_TYPE_ID_LENGTH} characters`),
  today: (v) => (isValidYmd(v) ? null : "must be a valid YYYYMMDD date"),
};

/** Shape errors of a request (empty when well formed). Exact keys, types and encodings. */
export function requestShapeErrors(v: unknown): string[] {
  const errors = schemaErrors(v, REQUEST_SCHEMA, "request");
  if (isPlainObject(v) && Object.prototype.hasOwnProperty.call(v, "policy")) {
    // One push per error: spreading an unbounded list into push() overflows the call stack
    // (RangeError) at about 125,000 policy keys (fuzz triage of fz1).
    for (const e of schemaErrors(v["policy"], POLICY_SCHEMA, "request.policy")) errors.push(e);
  }
  return errors;
}

export function isProofRequestV4(v: unknown): v is ProofRequestV4 {
  return requestShapeErrors(v).length === 0;
}

const HEX_RE = /^(?:[0-9a-f]{2})*$/;
const CT_HEX_LEN = 2 * ML_KEM_768_SIZES.ciphertext;
const REPLY_SCHEMA: Record<string, Check> = {
  type: (v) => (v === TYPE_REPLY ? null : `must be "${TYPE_REPLY}"`),
  sessionId: (v) => (isHex64(v) ? null : "must be 64 lower-case hex characters"),
  ct: (v) => (typeof v === "string" && v.length === CT_HEX_LEN && HEX_RE.test(v) ? null : `must be ${CT_HEX_LEN} lower-case hex characters`),
  box: (v) =>
    typeof v === "string" &&
    v.length >= 2 * AES_GCM_SIZES.tag &&
    v.length <= 2 * (MAX_PRESENTATION_BYTES + AES_GCM_SIZES.tag) &&
    HEX_RE.test(v)
      ? null
      : "must be lower-case hex of AES-GCM ciphertext || 16-byte tag",
};

export function replyShapeErrors(v: unknown): string[] {
  return schemaErrors(v, REPLY_SCHEMA, "reply");
}

export function isSessionReplyV4(v: unknown): v is SessionReplyV4 {
  return replyShapeErrors(v).length === 0;
}

function deepFreeze<T>(x: T): T {
  if (x !== null && typeof x === "object") {
    for (const v of Object.values(x)) deepFreeze(v);
    Object.freeze(x);
  }
  return x;
}

/** A fresh, validated request with a random 32-byte sessionId. Throws on bad parameters. */
export function newRequest(p: NewRequestParams): ProofRequestV4 {
  const request = {
    type: TYPE_REQUEST,
    sessionId: randomBytes(32).toString("hex"),
    verifierDid: p.verifierDid,
    verifierController: p.verifierController,
    chainId: p.chainId,
    policy: { predicate: p.policy.predicate, threshold: p.policy.threshold, typeId: p.policy.typeId, today: p.policy.today },
    issuedAt: p.issuedAt ?? Math.floor(Date.now() / 1000),
  };
  const errors = requestShapeErrors(request);
  if (errors.length > 0) throw new Error(`invalid request parameters: ${errors.join("; ")}`);
  return request as ProofRequestV4;
}

// ============================================================================
// Transcript and key schedule
// ============================================================================

/**
 * T = SHA3-256(canonicalJson({type:"pqid:transcript:v4", request, kemPkSha3, ctSha3})).
 * Throws if the request is not well formed or the key/ciphertext lengths are wrong.
 */
export function transcriptHash(request: ProofRequestV4, kemPk: Uint8Array, ciphertext: Uint8Array): Buffer {
  const errors = requestShapeErrors(request);
  if (errors.length > 0) throw new Error(`invalid request: ${errors.join("; ")}`);
  if (!(kemPk instanceof Uint8Array) || kemPk.length !== ML_KEM_768_SIZES.publicKey) throw new Error("transcript: bad ML-KEM-768 public key length");
  if (!(ciphertext instanceof Uint8Array) || ciphertext.length !== ML_KEM_768_SIZES.ciphertext) throw new Error("transcript: bad ML-KEM-768 ciphertext length");
  return sha3_256(
    canonicalJsonBytes({
      type: TYPE_TRANSCRIPT,
      request,
      kemPkSha3: sha3_256(kemPk).toString("hex"),
      ctSha3: sha3_256(ciphertext).toString("hex"),
    })
  );
}

/** prk = HKDF-Extract(salt = T, ikm = ss); nonce, key and iv by HKDF-Expand with fixed labels. */
export function deriveSessionSecrets(sharedSecret: Uint8Array, transcript: Uint8Array): SessionSecrets {
  if (!(sharedSecret instanceof Uint8Array) || sharedSecret.length !== ML_KEM_768_SIZES.sharedSecret) throw new Error("shared secret must be 32 bytes");
  if (!(transcript instanceof Uint8Array) || transcript.length !== 32) throw new Error("transcript hash must be 32 bytes");
  const prk = hkdfSha256Extract(transcript, sharedSecret);
  return {
    nonce: fieldFrom31Bytes(hkdfSha256Expand(prk, HKDF_INFO_NONCE, 31)),
    key: hkdfSha256Expand(prk, HKDF_INFO_KEY, AES_GCM_SIZES.key),
    iv: hkdfSha256Expand(prk, HKDF_INFO_IV, AES_GCM_SIZES.iv),
  };
}

// ============================================================================
// Wallet side
// ============================================================================

const sealedSessions = new WeakSet<WalletSession>();

/**
 * Wallet step 1: encapsulate to `kemPkRaw` and derive the session values. The caller
 * must pass the verifier's ML-KEM key resolved from chain, never one from the request.
 * Throws on a malformed request or key.
 */
export function walletOpenSession(request: ProofRequestV4, kemPkRaw: Uint8Array): WalletSession {
  const errors = requestShapeErrors(request);
  if (errors.length > 0) throw new Error(`invalid request: ${errors.join("; ")}`);
  const req = deepFreeze(structuredClone(request));
  const { ciphertext, sharedSecret } = mlKemEncaps(kemPkRaw);
  const transcript = transcriptHash(req, kemPkRaw, ciphertext);
  const secrets = deriveSessionSecrets(sharedSecret, transcript);
  sharedSecret.fill(0);
  return { request: req, ciphertext, transcript, ...secrets };
}

/** Throws unless `v` is plain JSON data (null, booleans, finite numbers, strings, arrays, plain objects). */
function assertPlainJson(v: unknown, path = "presentation"): void {
  if (v === null || typeof v === "boolean" || typeof v === "string") return;
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error(`${path} is not a finite number`);
    return;
  }
  if (Array.isArray(v)) {
    v.forEach((x, i) => assertPlainJson(x, `${path}[${i}]`));
    return;
  }
  if (isPlainObject(v)) {
    for (const [k, x] of Object.entries(v)) assertPlainJson(x, `${path}.${k}`);
    return;
  }
  throw new Error(`${path} is not plain JSON data (${typeof v})`);
}

/**
 * Wallet step 2: seal the presentation (a plain JSON object) under the session key.
 * A session seals exactly once (AES-GCM must never reuse key and IV); a second call throws.
 */
export function walletSealReply(session: WalletSession, presentation: unknown): SessionReplyV4 {
  if (sealedSessions.has(session)) throw new Error("this wallet session has already sealed a reply");
  if (!isPlainObject(presentation)) throw new Error("presentation must be a plain JSON object");
  assertPlainJson(presentation);
  const plaintext = canonicalJsonBytes(presentation);
  if (plaintext.length > MAX_PRESENTATION_BYTES) throw new Error(`presentation larger than ${MAX_PRESENTATION_BYTES} bytes`);
  sealedSessions.add(session);
  const { ciphertext, tag } = aes256gcmSeal(session.key, session.iv, session.transcript, plaintext);
  return {
    type: TYPE_REPLY,
    sessionId: session.request.sessionId,
    ct: session.ciphertext.toString("hex"),
    box: Buffer.concat([ciphertext, tag]).toString("hex"),
  };
}

/**
 * Both wallet steps around a presentation builder that needs the nonce (for example
 * the Groth16 prover): open, build(nonce), seal.
 */
export async function walletSeal(
  request: ProofRequestV4,
  kemPkRaw: Uint8Array,
  buildPresentation: (nonce: bigint) => unknown | Promise<unknown>
): Promise<{ reply: SessionReplyV4; nonce: bigint }> {
  const session = walletOpenSession(request, kemPkRaw);
  const presentation = await buildPresentation(session.nonce);
  return { reply: walletSealReply(session, presentation), nonce: session.nonce };
}

// ============================================================================
// Verifier side
// ============================================================================

export type SessionStatus = "open" | "expired" | "unknown";

interface StoredSession {
  request: ProofRequestV4;
  createdAtMs: number;
  expiresAtMs: number;
}

export interface VerifierSessionStoreOptions {
  /** Session lifetime (ms); default SESSION_TTL_MS. */
  ttlMs?: number;
  /** Clock in ms (tests inject one); default Date.now. */
  nowMs?: () => number;
  /** Maximum number of stored sessions; default 100,000. */
  maxSessions?: number;
}

/**
 * The verifier's open sessions. A session is usable (get) until its TTL passes and is
 * consumed at most once. Expired entries are kept for one more TTL so a late reply is
 * reported as "expiredSession" rather than "unknownSession", then pruned.
 */
export class VerifierSessionStore {
  readonly ttlMs: number;
  private readonly nowMs: () => number;
  private readonly maxSessions: number;
  private readonly sessions = new Map<string, StoredSession>();

  constructor(opts: VerifierSessionStoreOptions = {}) {
    this.ttlMs = opts.ttlMs ?? SESSION_TTL_MS;
    this.nowMs = opts.nowMs ?? Date.now;
    this.maxSessions = opts.maxSessions ?? 100_000;
    if (!(this.ttlMs > 0)) throw new Error("ttlMs must be positive");
  }

  /**
   * Create, store and return a fresh request (issuedAt defaults to the store's clock).
   * A session ends at its TTL or at the end of its issue day plus the wallet clock skew,
   * whichever comes first, so a proof about day D is never accepted long after D ended
   * (B5 VER-4).
   */
  open(params: NewRequestParams): ProofRequestV4 {
    const now = this.nowMs();
    this.prune(now);
    if (this.sessions.size >= this.maxSessions) this.evictExpired(now);
    if (this.sessions.size >= this.maxSessions) throw new Error("too many open sessions");
    const request = deepFreeze(newRequest({ ...params, issuedAt: params.issuedAt ?? Math.floor(now / 1000) }));
    const dayEndMs = (Math.floor(request.issuedAt / 86400) + 1) * 86400_000 + WALLET_CLOCK_SKEW_SEC * 1000;
    this.sessions.set(request.sessionId, { request, createdAtMs: now, expiresAtMs: Math.min(now + this.ttlMs, dayEndMs) });
    return request;
  }

  status(sessionId: string): SessionStatus {
    const s = this.sessions.get(sessionId);
    if (!s) return "unknown";
    return this.nowMs() < s.expiresAtMs ? "open" : "expired";
  }

  /** The stored (frozen) request of an open session, else undefined. */
  get(sessionId: string): ProofRequestV4 | undefined {
    const s = this.sessions.get(sessionId);
    return s && this.nowMs() < s.expiresAtMs ? s.request : undefined;
  }

  /** Consume an open session: true exactly once, and only before it expires. */
  consume(sessionId: string): boolean {
    const s = this.sessions.get(sessionId);
    if (!s || this.nowMs() >= s.expiresAtMs) return false;
    this.sessions.delete(sessionId);
    return true;
  }

  get size(): number {
    return this.sessions.size;
  }

  /**
   * Drop sessions expired for more than one TTL (kept that long only to report "expired"
   * rather than "unknown"). Entries are in insertion order and expiry never exceeds
   * creation + TTL, so the scan stops at the first entry created within the last 2 x TTL
   * (B5 VER-3: amortised O(1) instead of a full scan per call).
   */
  private prune(now: number): void {
    for (const [id, s] of this.sessions) {
      if (now >= s.expiresAtMs + this.ttlMs) {
        this.sessions.delete(id);
        continue;
      }
      if (now < s.createdAtMs + 2 * this.ttlMs) break;
    }
  }

  /** When full, drop every expired session (live ones are never evicted: fail closed). */
  private evictExpired(now: number): void {
    for (const [id, s] of this.sessions) if (now >= s.expiresAtMs) this.sessions.delete(id);
  }
}

export type OpenReplyError = "unknownSession" | "expiredSession" | "decryptFailed" | "malformed";

/**
 * Discriminated on `ok`. Each branch declares the other branch's fields as optional
 * `undefined`, so callers may read `result.error` or `result.nonce` without narrowing.
 */
export type OpenReplyResult =
  | {
      ok: true;
      sessionId: string;
      request: ProofRequestV4;
      /** Transcript-derived proof nonce the verifier must see as public signal 3. */
      nonce: bigint;
      transcript: Buffer;
      /** The decrypted presentation, parsed into plain JSON data. */
      presentation: Record<string, unknown>;
      error?: undefined;
      detail?: undefined;
    }
  | {
      ok: false;
      error: OpenReplyError;
      detail: string;
      sessionId?: string;
      request?: undefined;
      nonce?: undefined;
      transcript?: undefined;
      presentation?: undefined;
    };

const UTF8_STRICT = new TextDecoder("utf-8", { fatal: true });

/** A v4 presentation nests 4 levels (proof.pi_b is an array of arrays); allow some slack. */
export const MAX_PRESENTATION_DEPTH = 8;

/** Iterative depth check (no recursion, so hostile input cannot overflow the stack). */
export function jsonDepthExceeds(v: unknown, max: number): boolean {
  const stack: Array<[unknown, number]> = [[v, 1]];
  while (stack.length) {
    const [x, d] = stack.pop() as [unknown, number];
    if (x === null || typeof x !== "object") continue;
    if (d > max) return true;
    for (const y of Array.isArray(x) ? x : Object.values(x as Record<string, unknown>)) stack.push([y, d + 1]);
  }
  return false;
}

/**
 * Verifier transport step: shape, session lookup, Decaps, key schedule, AEAD open,
 * JSON parse. Does NOT consume the session (the caller consumes it after its checks).
 * `reply` may be an object, a JSON string or JSON bytes. Throws only on caller
 * misconfiguration (a KEM private key that does not match kemPkRaw).
 */
export function verifierOpenReply(store: VerifierSessionStore, kemPrivateKey: KeyObject, kemPkRaw: Uint8Array, reply: unknown): OpenReplyResult {
  if (!(kemPkRaw instanceof Uint8Array) || !mlKemPublicKeyRawOf(kemPrivateKey).equals(kemPkRaw)) {
    throw new Error("verifierOpenReply: kemPkRaw is not the public key of kemPrivateKey");
  }
  let r: unknown = reply;
  if (typeof reply === "string" || reply instanceof Uint8Array) {
    try {
      r = JSON.parse(typeof reply === "string" ? reply : UTF8_STRICT.decode(reply));
    } catch {
      return { ok: false, error: "malformed", detail: "reply is not JSON" };
    }
  }
  const shape = replyShapeErrors(r);
  if (shape.length > 0) return { ok: false, error: "malformed", detail: shape.join("; ") };
  const rep = r as SessionReplyV4;
  const sessionId = rep.sessionId;

  const status = store.status(sessionId);
  if (status === "unknown") return { ok: false, error: "unknownSession", detail: "no open session with this id", sessionId };
  if (status === "expired") return { ok: false, error: "expiredSession", detail: "session expired", sessionId };
  const request = store.get(sessionId);
  if (!request) return { ok: false, error: "expiredSession", detail: "session expired", sessionId };

  const ct = Buffer.from(rep.ct, "hex");
  const boxBytes = Buffer.from(rep.box, "hex");
  let transcript: Buffer;
  let secrets: SessionSecrets;
  try {
    const ss = mlKemDecaps(kemPrivateKey, ct);
    transcript = transcriptHash(request, kemPkRaw, ct);
    secrets = deriveSessionSecrets(ss, transcript);
    ss.fill(0);
  } catch (e) {
    return { ok: false, error: "decryptFailed", detail: `decapsulation failed: ${(e as Error).message}`, sessionId };
  }
  const tagAt = boxBytes.length - AES_GCM_SIZES.tag;
  const plaintext = aes256gcmOpen(secrets.key, secrets.iv, transcript, boxBytes.subarray(0, tagAt), boxBytes.subarray(tagAt));
  if (!plaintext) return { ok: false, error: "decryptFailed", detail: "AES-256-GCM authentication failed", sessionId };

  let presentation: unknown;
  try {
    presentation = JSON.parse(UTF8_STRICT.decode(plaintext));
  } catch {
    return { ok: false, error: "malformed", detail: "decrypted presentation is not UTF-8 JSON", sessionId };
  }
  if (!isPlainObject(presentation)) return { ok: false, error: "malformed", detail: "presentation is not a JSON object", sessionId };
  // Bound nesting before the recursive canonicaliser (B5 VER-2: deep nesting threw).
  if (jsonDepthExceeds(presentation, MAX_PRESENTATION_DEPTH)) return { ok: false, error: "malformed", detail: `presentation nests deeper than ${MAX_PRESENTATION_DEPTH}`, sessionId };
  let canonical: Buffer;
  try {
    canonical = canonicalJsonBytes(presentation);
  } catch (e) {
    return { ok: false, error: "malformed", detail: `presentation cannot be canonicalised: ${(e as Error).message}`, sessionId };
  }
  if (!canonical.equals(plaintext)) {
    return { ok: false, error: "malformed", detail: "presentation is not canonical JSON", sessionId };
  }
  return { ok: true, sessionId, request, nonce: secrets.nonce, transcript, presentation };
}
