import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";

/** SHA3-256 (FIPS 202, the Keccak variant with 0x06 domain padding). */
export function sha3_256(...inputs: Uint8Array[]): Buffer {
  const h = createHash("sha3-256");
  for (const b of inputs) h.update(b);
  return h.digest();
}

export function sha256File(filePath: string): string {
  const h = createHash("sha256");
  h.update(fs.readFileSync(filePath));
  return h.digest("hex");
}

export function sha256Bytes(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
}

export function randomFieldBelow(bits: number): bigint {
  // Uniform random bigint < 2^bits (bits must be a multiple of 8).
  return BigInt("0x" + randomBytes(bits / 8).toString("hex"));
}

/**
 * Canonical JSON serialization (JCS-lite): recursively sorted object keys,
 * no whitespace, UTF-8. Used to define the byte string `cred` hashed into
 * credID = SHA3-256(cred ‖ pk_issuer).
 */
export function canonicalJsonBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts = keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k]));
  return "{" + parts.join(",") + "}";
}
