import { describe, it, expect, beforeAll } from "vitest";
import fs from "node:fs";
import { sha3_256, canonicalJsonBytes } from "@pqid/common/hash";
import { VKEY_FILE } from "@pqid/common/paths";
import { createIssuer, issueCredential, type Issuer, type VerifiableCredential } from "@pqid/issuer";
import { dilithiumVerify, ML_DSA_44_SIZES } from "@pqid/pqc";
import { createWallet, walletCheckCredential, buildProofInput, proveBoth, type HolderWallet, type PolicyV1 } from "@pqid/wallet";
import { RevocationTree } from "@pqid/revocation";

/**
 * M4 (issuer) + M5 (wallet dual-prover) acceptance tests.
 * Uses the real liboqs ML-DSA-44 via the WSL bridge and the real rapidsnark
 * native prover on byte-identical zkey + witness.
 */
let issuer: Issuer;
let wallet: HolderWallet;
let vc: VerifiableCredential;
const policy: PolicyV1 = { type: "age_gte", attribute: "age", threshold: 18 };

beforeAll(async () => {
  issuer = createIssuer();
  wallet = await createWallet();
  vc = issueCredential({
    issuer,
    subjectDid: wallet.did,
    claims: { age: 42, name: "Fixture Holder" },
    holderCommit: wallet.holderCommit,
    issuedAt: "2026-01-01T00:00:00.000Z",
  });
}, 300_000);

describe("issuer (M4)", () => {
  it("credID == SHA3-256(cred ‖ pk_issuer)", () => {
    const expected = sha3_256(
      canonicalJsonBytes(vc.credential),
      issuer.keys.publicKey
    ).toString("hex");
    expect(vc.credID).toBe(expected);
  });

  it("Dilithium.Verify(pk_issuer, credID, σ) passes under liboqs", () => {
    expect(
      dilithiumVerify(
        issuer.keys.publicKey,
        Buffer.from(vc.credID, "hex"),
        Buffer.from(vc.signature, "hex")
      )
    ).toBe(true);
  });

  it("key and signature sizes match FIPS 204 (ML-DSA-44)", () => {
    expect(issuer.keys.publicKey.length).toBe(ML_DSA_44_SIZES.publicKey);
    expect(issuer.keys.secretKey.length).toBe(ML_DSA_44_SIZES.secretKey);
    expect(Buffer.from(vc.signature, "hex").length).toBe(ML_DSA_44_SIZES.signature);
  });

  it("did:pq identifiers derive from the Dilithium public keys", () => {
    expect(vc.credential.issuer).toMatch(/^did:pq:[1-9A-HJ-NP-Za-km-z]+$/);
    expect(vc.credential.subject).toBe(wallet.did);
  });
});

describe("wallet off-circuit checks (M5)", () => {
  it("accepts a valid credential", () => {
    const res = walletCheckCredential(wallet, vc, issuer.keys.publicKey, policy);
    expect(res).toEqual({
      credIdConsistent: true,
      dilithiumValid: true,
      holderBound: true,
      policyApplicable: true,
      ok: true,
    });
  });

  it("rejects a tampered claim (credID recomputation catches it)", () => {
    const tampered: VerifiableCredential = {
      ...vc,
      credential: { ...vc.credential, claims: { ...vc.credential.claims, age: 99 } },
    };
    const res = walletCheckCredential(wallet, tampered, issuer.keys.publicKey, policy);
    expect(res.credIdConsistent).toBe(false);
    expect(res.ok).toBe(false);
  });

  it("rejects a credential bound to a different holder", async () => {
    const otherWallet = await createWallet();
    const res = walletCheckCredential(otherWallet, vc, issuer.keys.publicKey, policy);
    expect(res.holderBound).toBe(false);
    expect(res.ok).toBe(false);
  });

  it("rejects an inapplicable policy (threshold above claim)", () => {
    const res = walletCheckCredential(wallet, vc, issuer.keys.publicKey, {
      ...policy,
      threshold: 65,
    });
    expect(res.policyApplicable).toBe(false);
    expect(res.ok).toBe(false);
  });
});

describe("dual prover on byte-identical inputs (M5)", () => {
  it("snarkjs and rapidsnark proofs both verify against the same vkey", async () => {
    const tree = await RevocationTree.create();
    const revoked = JSON.parse(
      fs.readFileSync(new URL("../fixtures/revoked-set.json", import.meta.url), "utf8")
    ) as { labels: string[] };
    for (const label of revoked.labels) {
      await tree.insert(sha3_256(Buffer.from(label, "utf8")));
    }
    const credIdBytes = Buffer.from(vc.credID, "hex");
    const nonMembership = await tree.getNonMembershipProof(credIdBytes);

    const input = await buildProofInput({
      wallet,
      vc,
      request: { policy, nonce: 991199n, verifierId: "pqid:verifier:demo" },
      pkIssuer: issuer.keys.publicKey,
      revRoot: tree.root(),
      nonMembership,
    });

    const both = await proveBoth(input);
    expect(both.inputsIdentical).toBe(true);
    expect(both.snarkjs.zkeySha256).toBe(both.rapidsnark.zkeySha256);
    expect(both.snarkjs.witnessSha256).toBe(both.rapidsnark.witnessSha256);
    // Same statement from both provers
    expect(both.rapidsnark.publicSignals).toEqual(both.snarkjs.publicSignals);

    const snarkjs = await import("snarkjs");
    const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, "utf8")) as unknown;
    expect(
      await snarkjs.groth16.verify(vkey, both.snarkjs.publicSignals, both.snarkjs.proof)
    ).toBe(true);
    expect(
      await snarkjs.groth16.verify(vkey, both.rapidsnark.publicSignals, both.rapidsnark.proof)
    ).toBe(true);
  }, 300_000);
});
