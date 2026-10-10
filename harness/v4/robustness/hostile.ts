import { canonicalJsonBytes } from "@pqid/common/hash";
import { aes256gcmSeal } from "@pqid/v4/pqc";
import { MAX_PRESENTATION_BYTES, type SessionReplyV4 } from "@pqid/v4/session";
import type { PresentationV4 } from "@pqid/v4/verifier";
import type { Rng } from "./rng.ts";
import { Q_BIG } from "./oracles.ts";
import type { HostileClass } from "./load_lib.ts";

/**
 * Hostile replies for the load test (docs/v4/ROBUSTNESS.md section 3.6). The harness acts as a
 * wallet: it seals presentations under session secrets it holds in memory (its own sessions
 * opened with walletOpenSession against the verifier's registered KEM key, or the secrets of an
 * honest session captured while the holder's wallet presented). Re-sealing under an honest
 * session's key and IV reuses an AES-GCM nonce: acceptable in a test harness, never in a wallet.
 * Session secrets are never written or logged.
 */

export interface SessionKeys {
  sessionId: string;
  /** ML-KEM ciphertext of the session (raw bytes). */
  ct: Buffer;
  key: Buffer;
  iv: Buffer;
  transcript: Buffer;
}

/** Seal raw plaintext bytes into the session (no canonicalisation, no size cap: harness only). */
export function sealRaw(s: SessionKeys, plaintext: Buffer): SessionReplyV4 {
  const box = aes256gcmSeal(s.key, s.iv, s.transcript, plaintext);
  return { type: "pqid:reply:v4", sessionId: s.sessionId, ct: s.ct.toString("hex"), box: Buffer.concat([box.ciphertext, box.tag]).toString("hex") };
}

/** Seal a presentation as canonical JSON (what an honest wallet sends). */
export function sealCanonical(s: SessionKeys, presentation: unknown): SessionReplyV4 {
  return sealRaw(s, canonicalJsonBytes(presentation));
}

export function wire(reply: SessionReplyV4 | Record<string, unknown>): Buffer {
  return Buffer.from(JSON.stringify(reply), "utf8");
}

/** Flip one bit of one byte of a hex string (lower case kept). */
export function flipHexByte(hex: string, rng: Rng): string {
  const i = rng.int(0, hex.length / 2 - 1);
  const b = (parseInt(hex.slice(2 * i, 2 * i + 2), 16) ^ (1 << rng.int(0, 7))).toString(16).padStart(2, "0");
  return hex.slice(0, 2 * i) + b + hex.slice(2 * i + 2);
}

/** HC1: bytes that are not JSON (invalid UTF-8, truncated JSON, or empty). */
export function notJson(rng: Rng, honestWire: Buffer): Buffer {
  const k = rng.int(0, 2);
  if (k === 0) return Buffer.concat([Buffer.from([0xc0, 0xaf, 0xff]), rng.bytes(rng.int(1, 64))]);
  if (k === 1) return Buffer.from(honestWire.subarray(0, rng.int(1, Math.max(1, honestWire.length - 1))));
  return Buffer.from("{", "utf8");
}

/** HC2: a well-formed reply for a session the verifier never opened. */
export function unknownSession(rng: Rng, boxBytes: number): Buffer {
  return wire({ type: "pqid:reply:v4", sessionId: rng.bytes(32).toString("hex"), ct: rng.bytes(1088).toString("hex"), box: rng.bytes(boxBytes).toString("hex") });
}

/** HC3: a known session's sealed reply with one bit of the box flipped (AES-GCM fails). */
export function tamperedBox(s: SessionKeys, presentation: unknown, rng: Rng): Buffer {
  const r = sealCanonical(s, presentation);
  return wire({ ...r, box: flipHexByte(r.box, rng) });
}

/** HC4: an honest presentation of ANOTHER session sealed into this one (nonce signal wrong; every check runs). */
export function wrongNonce(s: SessionKeys, otherPresentation: PresentationV4): Buffer {
  return wire(sealCanonical(s, otherPresentation));
}

/**
 * HC5: a presentation with in-range random proof coordinates (base field F_q). In the load test
 * it is sealed into the honest session the presentation was proved for, so every check except
 * Groth16 passes (nonce, policy, statement code and chain reads are the honest ones).
 */
export function garbageProof(s: SessionKeys, presentation: PresentationV4, rng: Rng): Buffer {
  const r = () => rng.bigBelow(Q_BIG).toString();
  const p = structuredClone(presentation) as unknown as Record<string, unknown>;
  p["proof"] = { pi_a: [r(), r(), "1"], pi_b: [[r(), r()], [r(), r()], ["1", "0"]], pi_c: [r(), r(), "1"], protocol: "groth16", curve: "bn128" };
  return wire(sealCanonical(s, p));
}

/** A decimal string of exactly n digits with no leading zero. */
export function longDecimal(rng: Rng, n: number): string {
  const digits = rng.bytes(n);
  let out = String(1 + (digits[0] as number) % 9);
  for (let i = 1; i < n; i++) out += String((digits[i] as number) % 10);
  return out;
}

/** HC6: public signal 0 replaced by a decimal string sized so the canonical plaintext is just under 1 MiB. */
export function longDecimalSignal(s: SessionKeys, presentation: PresentationV4, rng: Rng, marginBytes = 64): { wire: Buffer; digits: number; plaintextBytes: number } {
  const base = canonicalJsonBytes(presentation).length - presentation.publicSignals[0]!.length;
  const digits = MAX_PRESENTATION_BYTES - base - marginBytes;
  const p = structuredClone(presentation) as unknown as { publicSignals: string[] };
  p.publicSignals[0] = longDecimal(rng, digits);
  const plaintext = canonicalJsonBytes(p);
  return { wire: wire(sealRaw(s, plaintext)), digits, plaintextBytes: plaintext.length };
}

/** HC7: a wide JSON object just under 1 MiB whose keys are not in canonical order (rejected after parsing and canonicalising). */
export function wideNonCanonical(s: SessionKeys, rng: Rng, targetBytes = MAX_PRESENTATION_BYTES - 64): { wire: Buffer; members: number; plaintextBytes: number } {
  const parts: string[] = [];
  let size = 2;
  let n = 0;
  for (;;) {
    // keys k<random hex>: random order is non-canonical with overwhelming probability
    const member = `"k${rng.bytes(6).toString("hex")}":"${rng.bytes(12).toString("hex")}"`;
    if (size + member.length + 1 > targetBytes) break;
    parts.push(member);
    size += member.length + 1;
    n++;
  }
  // make sure the order is not sorted (swap the first two if they happen to be)
  if (parts.length >= 2 && (parts[0] as string) < (parts[1] as string)) [parts[0], parts[1]] = [parts[1] as string, parts[0] as string];
  const plaintext = Buffer.from("{" + parts.join(",") + "}", "utf8");
  return { wire: wire(sealRaw(s, plaintext)), members: n, plaintextBytes: plaintext.length };
}

/** A non-canonical but otherwise honest plaintext (pretty-printed): rejected as malformed. */
export function prettyPrinted(s: SessionKeys, presentation: unknown): Buffer {
  return wire(sealRaw(s, Buffer.from(JSON.stringify(presentation, null, 1), "utf8")));
}

export interface HostileBuildInputs {
  rng: Rng;
  /** Harness-owned session secrets, one per hostile item that needs a known session. */
  newSession: () => SessionKeys;
  /** Honest pool presentations (decrypted; public data) and their wire replies. */
  presentations: readonly PresentationV4[];
  honestWires: readonly Buffer[];
  /** Captured secrets of the honest pool sessions (index-aligned with presentations; in memory only). */
  honestKeys: readonly SessionKeys[];
  /**
   * Pool indices HC5 may seal into (sessions no correctness item uses; load_lib.ts freeIndices),
   * cycled. Rejected replies consume nothing, so these honest sessions stay usable.
   */
  hc5Indices: readonly number[];
}

export interface HostileItem {
  cls: HostileClass;
  wire: Buffer;
  /** The session the reply names when the verifier knows it (public: it is in the reply); else null. */
  sessionId: string | null;
  /** Facts about the item (sizes, which honest presentation it reuses); no secrets. */
  note: Record<string, unknown>;
}

/** N items of one hostile class (HC1 to HC7); HC0 uses the honest pool directly. */
export function buildHostile(cls: Exclude<HostileClass, "HC0">, n: number, distinctLarge: number, inp: HostileBuildInputs): HostileItem[] {
  const out: HostileItem[] = [];
  const P = inp.presentations.length;
  const pres = (i: number) => inp.presentations[i % P] as PresentationV4;
  const distinct = cls === "HC6" || cls === "HC7" ? Math.max(1, Math.min(n, distinctLarge)) : n;
  for (let i = 0; i < distinct; i++) {
    const rng = inp.rng.fork(`${cls}:${i}`);
    switch (cls) {
      case "HC1":
        out.push({ cls, wire: notJson(rng, inp.honestWires[i % P] as Buffer), sessionId: null, note: {} });
        break;
      case "HC2":
        out.push({ cls, wire: unknownSession(rng, 4096), sessionId: null, note: {} });
        break;
      case "HC3": {
        const s = inp.newSession();
        out.push({ cls, wire: tamperedBox(s, pres(i), rng), sessionId: s.sessionId, note: { presentation: i % P } });
        break;
      }
      case "HC4": {
        const s = inp.newSession();
        out.push({ cls, wire: wrongNonce(s, pres(i)), sessionId: s.sessionId, note: { presentation: i % P } });
        break;
      }
      case "HC5": {
        if (inp.hc5Indices.length === 0) throw new Error("HC5 needs at least one pool index outside the correctness batch");
        const j = inp.hc5Indices[i % inp.hc5Indices.length] as number;
        const s = inp.honestKeys[j];
        if (!s) throw new Error(`HC5: no captured session secrets for pool reply ${j}`);
        out.push({ cls, wire: garbageProof(s, pres(j), rng), sessionId: s.sessionId, note: { honestSessionOfPoolIndex: j } });
        break;
      }
      case "HC6": {
        const s = inp.newSession();
        const r = longDecimalSignal(s, pres(i), rng);
        out.push({ cls, wire: r.wire, sessionId: s.sessionId, note: { presentation: i % P, digits: r.digits, plaintextBytes: r.plaintextBytes } });
        break;
      }
      case "HC7": {
        const s = inp.newSession();
        const r = wideNonCanonical(s, rng);
        out.push({ cls, wire: r.wire, sessionId: s.sessionId, note: { members: r.members, plaintextBytes: r.plaintextBytes } });
        break;
      }
    }
  }
  // the large classes cycle their distinct replies up to n (rejected replies consume nothing)
  for (let i = distinct; i < n; i++) out.push(out[i % distinct] as HostileItem);
  return out;
}
