import { describe, it, expect } from "vitest";
import { runKyberSessionDemo } from "@pqid/pqc/kyber-demo";
import { ML_KEM_512_SIZES } from "@pqid/pqc";

describe("Kyber-512 session-key demo (raw encap/decap; PQ-TLS is [F])", () => {
  it("establishes an agreeing shared secret and an AES-256-GCM channel", () => {
    const r = runKyberSessionDemo();
    expect(r.sharedSecretsAgree).toBe(true);
    expect(r.channelRoundTripOk).toBe(true);
    expect(r.tamperDetected).toBe(true);
    expect(r.sizes.publicKey).toBe(ML_KEM_512_SIZES.publicKey);
    expect(r.sizes.ciphertext).toBe(ML_KEM_512_SIZES.ciphertext);
    expect(r.sizes.sharedSecret).toBe(ML_KEM_512_SIZES.sharedSecret);
  });
});
