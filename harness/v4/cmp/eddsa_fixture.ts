import { createHash } from "node:crypto";
import * as ed from "../../../baselines/eddsa/lib.ts";

/**
 * Fixed input of the EdDSA-in-circuit baseline for the cmp series (docs/v4/CMP.md, "Inputs").
 *
 * baselines/eddsa/lib.ts createIssuer() draws a random issuer key, so its proofs are not
 * reproducible. This fixture uses the same circuit, encodings and signing code (imported
 * unchanged) with published constants only, mirroring the v2/v3/v4 bench inputs (holder secret
 * 123456789, birth date 19840315, expiry 20261226, age_gte 18, today 20260927, nonce 424242).
 *
 * The issuer key is SHA-256 of a public string. It is a FIXTURE key: anyone can derive it, it is
 * never written anywhere, and it is valid only for the throwaway baseline circuit. EdDSA-Poseidon
 * signing in circomlibjs is deterministic, so the input is byte-reproducible.
 */

export const EDDSA_FIXTURE = Object.freeze({
  issuerKeyString: "pqid-bench-eddsa-fixture-issuer",
  holderSecret: 123456789n,
  birthDate: 19840315,
  expiryDate: 20261226,
  threshold: 18,
  today: 20260927,
  nonce: 424242n,
  typeId: ed.DEFAULT_TYPE_ID,
  predicate: "age_gte",
});

export interface EddsaFixture {
  input: ed.CircuitInput;
  publicSignals: string[];
  /** Off-circuit EdDSA-Poseidon check of the fixture signature. */
  signatureVerifies: boolean;
  issuerPublic: { Ax: string; Ay: string };
  /** The signed message (Poseidon credential hash), decimal. */
  credHash: string;
}

export async function buildEddsaFixture(): Promise<EddsaFixture> {
  const eddsa = await ed.getEddsa();
  const F = eddsa.F;
  const prv = createHash("sha256").update(EDDSA_FIXTURE.issuerKeyString, "utf8").digest();
  const A = eddsa.prv2pub(prv);
  const Ax = F.toObject(A[0]);
  const Ay = F.toObject(A[1]);
  const credType = await ed.credTypeField(EDDSA_FIXTURE.typeId);
  const attrs: ed.CredentialAttrs = {
    holderCommit: await ed.holderCommitOf(EDDSA_FIXTURE.holderSecret),
    birthDate: EDDSA_FIXTURE.birthDate,
    expiryDate: EDDSA_FIXTURE.expiryDate,
    credType,
  };
  const credHash = await ed.credHashOf(attrs);
  const s = eddsa.signPoseidon(prv, F.e(credHash));
  const sig: ed.Signature = { R8x: F.toObject(s.R8[0]), R8y: F.toObject(s.R8[1]), S: s.S };
  const cred: ed.SignedCredential = { ...attrs, credHash, sig };
  const policy: ed.Policy = { predicateCode: ed.PREDICATE_AGE_GTE, threshold: EDDSA_FIXTURE.threshold, today: EDDSA_FIXTURE.today, requiredType: credType };
  const input = await ed.buildInput({ Ax, Ay, cred, holderSecret: EDDSA_FIXTURE.holderSecret, policy, nonce: EDDSA_FIXTURE.nonce });
  const publicSignals = await ed.expectedPublicSignals(Ax, Ay, policy, EDDSA_FIXTURE.nonce);
  const signatureVerifies = await ed.verifySignature(Ax, Ay, credHash, sig);
  return { input, publicSignals, signatureVerifies, issuerPublic: { Ax: Ax.toString(), Ay: Ay.toString() }, credHash: credHash.toString() };
}
