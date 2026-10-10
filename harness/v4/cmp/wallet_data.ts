import { createHash } from "node:crypto";

/**
 * Deterministic wallet-rebuild data for the cmp series (docs/v4/CMP.md, "Wallet rebuild").
 *
 * results/v4/privacy.json timed the rebuild on random leaves (31 random bytes each) and random
 * revocation keys (31 random bytes mod IMT_MAX), one run per size. Here the same distribution
 * comes from a counter: value_i = the first 31 bytes of SHA-256(prefix + i), big-endian, so the
 * rebuilt roots can be pinned and every run re-checked. Node built-ins only.
 */

export const WALLET_LEAF_PREFIX = "pqid-bench-wallet-leaf/";
export const WALLET_REV_PREFIX = "pqid-bench-wallet-rev/";
/** IMT key bound of packages/v4/src/constants.ts (IMT_MAX = 2^251); restated so this file needs no package import. */
export const WALLET_IMT_MAX = 1n << 251n;

export const WALLET_GENERATOR = Object.freeze({
  leaf: `first 31 bytes of SHA-256(UTF-8 "${WALLET_LEAF_PREFIX}" + i), big-endian, i = 0..n-1`,
  revocationKey: `first 31 bytes of SHA-256(UTF-8 "${WALLET_REV_PREFIX}" + j), big-endian, mod 2^251, j = 0..r-1 (must be non-zero and distinct)`,
});

/** First 31 bytes of SHA-256(text) as a big-endian integer (< 2^248). */
export function hash31(text: string): bigint {
  const d = createHash("sha256").update(text, "utf8").digest();
  return BigInt("0x" + d.subarray(0, 31).toString("hex"));
}

export function walletLeaves(n: number): bigint[] {
  if (!Number.isInteger(n) || n < 0) throw new Error("walletLeaves: n must be a non-negative integer");
  const out: bigint[] = new Array<bigint>(n);
  for (let i = 0; i < n; i++) out[i] = hash31(WALLET_LEAF_PREFIX + i);
  return out;
}

export function walletRevKeys(r: number, imtMax: bigint = WALLET_IMT_MAX): bigint[] {
  if (!Number.isInteger(r) || r < 0) throw new Error("walletRevKeys: r must be a non-negative integer");
  const out: bigint[] = new Array<bigint>(r);
  const seen = new Set<bigint>();
  for (let j = 0; j < r; j++) {
    const k = hash31(WALLET_REV_PREFIX + j) % imtMax;
    if (k === 0n) throw new Error(`revocation key ${j} is zero`);
    if (seen.has(k)) throw new Error(`revocation key ${j} repeats an earlier key`);
    seen.add(k);
    out[j] = k;
  }
  return out;
}
