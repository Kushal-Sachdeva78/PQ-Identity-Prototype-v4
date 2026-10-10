/**
 * Batch issuance for the SD-JWT baseline: n independent SD-JWTs with the same claims,
 * fresh salts and a distinct holder key per credential, so that single-use presentations
 * share no per-credential value (RFC 9901 Sec. 10.1 mitigation; research/F5d 1.4).
 * The EU age-verification blueprint recommends 30 attestations per batch
 * (research/F5d 4.3, Architecture Sec. 3.4.1, fetch-summary level).
 *
 * Key proof: OpenID4VCI-style issuance asks the wallet to prove possession of each key.
 * This file models that step with a small JWT per key ({aud, nonce, iat} signed by the
 * key, public key in the header). Its format is an assumption [A], not checked against
 * the OpenID4VCI text; the measurement reports batch cost with and without it.
 *
 * Private keys stay in memory only.
 */
import type { KeyObject } from "node:crypto";
import { type Alg, type KeyPair, importPublicJwk, isAlg, keygen, parseJws, publicJwk, signJws, verifyBytes } from "./jose.ts";
import { type IssueOptions, type IssuerKey, issue } from "./sdjwt.ts";

export const TYP_KEY_PROOF = "pqid-baseline-key-proof+jwt";

export interface BatchCredential {
  sdjwt: string;
  holder: KeyPair;
}

/** Holder side: n fresh key pairs. */
export function holderKeys(n: number, alg: Alg = "ML-DSA-44"): KeyPair[] {
  if (!Number.isSafeInteger(n) || n < 1) throw new Error("n must be a positive integer");
  return Array.from({ length: n }, () => keygen(alg));
}

/** Issuer side: one SD-JWT per holder public key, same claims, independent salts. */
export function issueForKeys(issuer: IssuerKey, claims: Record<string, unknown>, holderPks: readonly KeyObject[], opts: IssueOptions = {}): string[] {
  return holderPks.map((pk) => issue(issuer, claims, pk, opts));
}

/** issueBatch(n): n independent SD-JWTs, each bound to its own fresh holder key. */
export function issueBatch(
  issuer: IssuerKey,
  claims: Record<string, unknown>,
  n: number,
  opts: IssueOptions & { holderAlg?: Alg } = {}
): BatchCredential[] {
  const keys = holderKeys(n, opts.holderAlg ?? issuer.alg);
  const sdjwts = issueForKeys(issuer, claims, keys.map((k) => k.publicKey), opts);
  return sdjwts.map((sdjwt, i) => ({ sdjwt, holder: keys[i] as KeyPair }));
}

// ---------------------------------------------------------------- key proofs [A]

export function makeKeyProof(holder: KeyPair, aud: string, nonce: string, iat: number): string {
  return signJws(holder.alg, holder.privateKey, { typ: TYP_KEY_PROOF, jwk: publicJwk(holder.publicKey, holder.alg) }, { aud, nonce, iat });
}

/** Issuer side: checks one key proof and returns the proven public key (throws on failure). */
export function checkKeyProof(proof: string, aud: string, nonce: string, allowed: readonly Alg[] = ["ML-DSA-44"]): KeyObject {
  const j = parseJws(proof);
  const alg = j.header.alg;
  if (!isAlg(alg) || !allowed.includes(alg)) throw new Error("key proof alg not accepted");
  if (j.header.typ !== TYP_KEY_PROOF) throw new Error("key proof typ");
  const pk = importPublicJwk(j.header.jwk, alg);
  if (!verifyBytes(alg, pk, Buffer.from(j.signingInput, "ascii"), j.signature)) throw new Error("key proof signature");
  if (j.payload.aud !== aud || j.payload.nonce !== nonce) throw new Error("key proof aud/nonce");
  return pk;
}

// ---------------------------------------------------------------- sizes

export interface BatchSizes {
  n: number;
  /** Sum of the n issuance-form SD-JWT strings (issuer to holder), bytes. */
  issuerToHolderBytes: number;
  /** Sum of the n public JWKs as compact JSON (holder to issuer, key only), bytes. */
  holderToIssuerJwkBytes: number;
  /** Sum of the n key-proof JWT strings, if given (holder to issuer, key plus signature) [A]. */
  holderToIssuerKeyProofBytes: number | null;
  /** Mean issuance-form SD-JWT length, bytes. */
  meanSdJwtBytes: number;
}

export function batchSizes(batch: readonly BatchCredential[], keyProofs?: readonly string[]): BatchSizes {
  const n = batch.length;
  const issuerToHolderBytes = batch.reduce((a, c) => a + c.sdjwt.length, 0);
  const holderToIssuerJwkBytes = batch.reduce((a, c) => a + JSON.stringify(publicJwk(c.holder.publicKey, c.holder.alg)).length, 0);
  return {
    n,
    issuerToHolderBytes,
    holderToIssuerJwkBytes,
    holderToIssuerKeyProofBytes: keyProofs ? keyProofs.reduce((a, p) => a + p.length, 0) : null,
    meanSdJwtBytes: n === 0 ? 0 : issuerToHolderBytes / n,
  };
}
