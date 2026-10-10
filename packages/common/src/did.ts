import bs58 from "bs58";
import { sha3_256 } from "./hash.ts";

/**
 * did:pq method (Gap 6 resolution):
 *   did:pq:<base58( SHA3-256(publicKey)[0..19] )>
 * The 20-byte truncated SHA3-256 of the ML-DSA-44 public key is base58-encoded
 * (Bitcoin alphabet). DID Documents live in the on-chain DID Registry.
 */
export const DID_PQ_PREFIX = "did:pq:";

export function didFromPublicKey(publicKey: Uint8Array): string {
  const digest = sha3_256(publicKey);
  return DID_PQ_PREFIX + bs58.encode(digest.subarray(0, 20));
}

export interface DidDocument {
  id: string;
  /** hex-encoded ML-DSA-44 public key (1,312 bytes) */
  publicKeyDilithium: string;
  endpoints: string[];
}

export function isDidPq(did: string): boolean {
  return did.startsWith(DID_PQ_PREFIX) && did.length > DID_PQ_PREFIX.length;
}

/** Stable 32-byte registry key for a DID (used as the contracts' mapping key). */
export function didRegistryKey(did: string): Buffer {
  return sha3_256(Buffer.from(did, "utf8"));
}
