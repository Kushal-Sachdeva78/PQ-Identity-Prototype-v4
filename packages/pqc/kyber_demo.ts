import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { kyberKeygen, kyberEncap, kyberDecap } from "./src/index.ts";

/**
 * Raw Kyber-512 (ML-KEM-512) encap/decap session-key demo (allowed scope).
 * NOT PQ-TLS — a real Kyber-based TLS handshake is [F]. This shows the KEM
 * establishing a shared secret that keys an AES-256-GCM channel, and that
 * tampering with the ciphertext breaks decapsulation agreement.
 */
export interface KyberDemoResult {
  sharedSecretsAgree: boolean;
  channelRoundTripOk: boolean;
  tamperDetected: boolean;
  sizes: { publicKey: number; ciphertext: number; sharedSecret: number };
}

export function runKyberSessionDemo(verbose = false): KyberDemoResult {
  const log = (s: string): void => {
    if (verbose) console.log(s);
  };

  // Bob publishes a KEM public key; Alice encapsulates a fresh shared secret.
  const bob = kyberKeygen();
  const { ciphertext, sharedSecret: ssAlice } = kyberEncap(bob.publicKey);
  const ssBob = kyberDecap(bob.secretKey, ciphertext);
  const agree = ssAlice.equals(ssBob);
  log(`[kyber] shared secrets agree: ${agree}`);

  // Derive an AES-256 key from the KEM shared secret and exchange a message.
  const key = createHash("sha256").update(ssAlice).digest();
  const iv = randomBytes(12);
  const plaintext = Buffer.from("post-quantum session established", "utf8");
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const keyBob = createHash("sha256").update(ssBob).digest();
  const decipher = createDecipheriv("aes-256-gcm", keyBob, iv);
  decipher.setAuthTag(tag);
  let roundTripOk = false;
  try {
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    roundTripOk = pt.equals(plaintext);
  } catch {
    roundTripOk = false;
  }
  log(`[kyber] AES-256-GCM channel round trip: ${roundTripOk}`);

  // Tamper with the KEM ciphertext: ML-KEM's implicit rejection yields a
  // DIFFERENT shared secret on decap, so the derived key won't match.
  const tampered = Buffer.from(ciphertext);
  tampered[0] = (tampered[0] ?? 0) ^ 0xff;
  const ssTampered = kyberDecap(bob.secretKey, tampered);
  const tamperDetected = !ssTampered.equals(ssAlice);
  log(`[kyber] tampered ciphertext -> different shared secret (detected): ${tamperDetected}`);

  return {
    sharedSecretsAgree: agree,
    channelRoundTripOk: roundTripOk,
    tamperDetected,
    sizes: {
      publicKey: bob.publicKey.length,
      ciphertext: ciphertext.length,
      sharedSecret: ssAlice.length,
    },
  };
}

// Allow `tsx packages/pqc/kyber_demo.ts` as a standalone demo.
if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}`) {
  const r = runKyberSessionDemo(true);
  console.log(JSON.stringify(r, null, 2));
  process.exit(r.sharedSecretsAgree && r.channelRoundTripOk && r.tamperDetected ? 0 : 1);
}
