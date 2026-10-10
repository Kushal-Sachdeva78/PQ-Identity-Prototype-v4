import { describe, it, expect, beforeAll } from "vitest";
import fs from "node:fs";
import { sha256File } from "@pqid/common/hash";
import {
  CIRCUIT_INFO_FILE,
  CIRCUIT_SRC,
  KEY_LABEL,
  PREDICATE_AGE_GTE,
  PREDICATE_AGE_LT,
  R1CS_FILE,
  SETUP_RECORD_FILE,
  SYM_FILE,
  VKEY_FILE,
  WASM_FILE,
  ZKEY_FILE,
  DEFAULT_TYPE_ID,
  buildInput,
  computeWitness,
  createIssuer,
  credTypeField,
  encodeWitness,
  expectedPublicSignals,
  holderCommitOf,
  issueCredential,
  loadVkey,
  r1csSatisfied,
  randomField,
  snarkjsLib,
  verifySignature,
  witnessValues,
  type BaselineIssuer,
  type Policy,
  type SignedCredential,
} from "../../baselines/eddsa/lib.ts";

/**
 * Baseline E2b (classical ZK credential, issuer EdDSA-Poseidon signature checked in-circuit).
 * Uses the THROWAWAY baseline key made by `npx tsx baselines/eddsa/build.ts`.
 *
 * Honest presentation: witness, R1CS check, one Groth16 prove + verify.
 * Forged signatures are rejected (a) by the reference witness generator and (b) at R1CS level:
 * a witness that is fully consistent for a rogue issuer key, with the public key wires set to
 * the real issuer's key, does not satisfy the R1CS and its Groth16 proof does not verify.
 */

const TODAY = 20260927;
const ADULT_BIRTH = 20000115; // 26 on TODAY
const TEEN_BIRTH = 20100101; // 16 on TODAY
const YOUNG_ADULT_BIRTH = 20070601; // 19 on TODAY
const EXPIRY = 20261231;
// Order of the BabyJubJub prime subgroup (circomlib CompConstant bound is (l-1)/2 style check on S).
const SUBGROUP_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;

let issuer: BaselineIssuer;
let rogue: BaselineIssuer;
let credType: bigint;
let holderSecret: bigint;
let adultCred: SignedCredential;
let nonce: bigint;
let gte18: Policy;

async function cred(iss: BaselineIssuer, over: Partial<{ birthDate: number; expiryDate: number; credType: bigint; secret: bigint }> = {}): Promise<SignedCredential> {
  return issueCredential(iss, {
    holderCommit: await holderCommitOf(over.secret ?? holderSecret),
    birthDate: over.birthDate ?? ADULT_BIRTH,
    expiryDate: over.expiryDate ?? EXPIRY,
    credType: over.credType ?? credType,
  });
}

beforeAll(async () => {
  for (const f of [R1CS_FILE, WASM_FILE, SYM_FILE, ZKEY_FILE, VKEY_FILE, CIRCUIT_INFO_FILE, SETUP_RECORD_FILE]) {
    if (!fs.existsSync(f)) throw new Error(`missing ${f}: run npx tsx baselines/eddsa/build.ts`);
  }
  issuer = await createIssuer();
  rogue = await createIssuer();
  credType = await credTypeField(DEFAULT_TYPE_ID);
  holderSecret = randomField();
  adultCred = await cred(issuer);
  nonce = randomField();
  gte18 = { predicateCode: PREDICATE_AGE_GTE, threshold: 18, today: TODAY, requiredType: credType };
});

describe("E2b artifacts (throwaway baseline key)", () => {
  it("circuit info matches the compiled R1CS and source", async () => {
    const info = JSON.parse(fs.readFileSync(CIRCUIT_INFO_FILE, "utf8")) as {
      nConstraints: number;
      optimization: string;
      r1csSha256: string;
      sourceSha256: string;
      ptau: { fits: boolean };
    };
    const snarkjs = await snarkjsLib();
    const r = await snarkjs.r1cs.info(R1CS_FILE);
    expect(info.optimization).toBe("--O2");
    expect(info.nConstraints).toBe(r.nConstraints);
    expect(r.nPubInputs).toBe(4);
    expect(r.nOutputs).toBe(0);
    expect(info.r1csSha256).toBe(sha256File(R1CS_FILE));
    expect(info.sourceSha256).toBe(sha256File(CIRCUIT_SRC));
    expect(info.ptau.fits).toBe(true);
  });

  it("the key is labelled throwaway and matches the R1CS it was made from", () => {
    const rec = JSON.parse(fs.readFileSync(SETUP_RECORD_FILE, "utf8")) as {
      label: string;
      r1csSha256: string;
      zkeySha256: string;
      vkeySha256: string;
      zkeyVerifyFromR1cs: boolean;
    };
    expect(rec.label).toBe(KEY_LABEL);
    expect(rec.r1csSha256).toBe(sha256File(R1CS_FILE));
    expect(rec.zkeySha256).toBe(sha256File(ZKEY_FILE));
    expect(rec.vkeySha256).toBe(sha256File(VKEY_FILE));
    expect(rec.zkeyVerifyFromR1cs).toBe(true);
  });
});

describe("E2b honest presentation", () => {
  it("issuer signature verifies off-circuit", async () => {
    expect(await verifySignature(issuer.Ax, issuer.Ay, adultCred.credHash, adultCred.sig)).toBe(true);
    expect(await verifySignature(rogue.Ax, rogue.Ay, adultCred.credHash, adultCred.sig)).toBe(false);
  });

  it("age >= 18: witness satisfies the R1CS, Groth16 proof verifies, public signals are the expected four", async () => {
    const snarkjs = await snarkjsLib();
    const input = await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: adultCred, holderSecret, policy: gte18, nonce });
    const w = await computeWitness(input);
    expect(await r1csSatisfied(w)).toBe(true);
    const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY_FILE, w);
    const expected = await expectedPublicSignals(issuer.Ax, issuer.Ay, gte18, nonce);
    expect(publicSignals).toEqual(expected);
    const vkey = await loadVkey();
    expect(await snarkjs.groth16.verify(vkey, expected, proof)).toBe(true);

    // verifier-side substitutions are rejected
    const otherKey = await expectedPublicSignals(rogue.Ax, rogue.Ay, gte18, nonce);
    expect(await snarkjs.groth16.verify(vkey, otherKey, proof)).toBe(false);
    const otherPolicy = await expectedPublicSignals(issuer.Ax, issuer.Ay, { ...gte18, threshold: 21 }, nonce);
    expect(await snarkjs.groth16.verify(vkey, otherPolicy, proof)).toBe(false);
    const otherNonce = await expectedPublicSignals(issuer.Ax, issuer.Ay, gte18, nonce + 1n);
    expect(await snarkjs.groth16.verify(vkey, otherNonce, proof)).toBe(false);
  });

  it("age < 21 for a 19-year-old: witness satisfies the R1CS", async () => {
    const c = await cred(issuer, { birthDate: YOUNG_ADULT_BIRTH });
    const lt21: Policy = { predicateCode: PREDICATE_AGE_LT, threshold: 21, today: TODAY, requiredType: credType };
    const w = await computeWitness(await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: c, holderSecret, policy: lt21, nonce }));
    expect(await r1csSatisfied(w)).toBe(true);
  });
});

describe("E2b forged signatures are rejected", () => {
  it("signature on a different message (valid R8 point, wrong credential): witness generator refuses", async () => {
    const other = await cred(issuer, { birthDate: TEEN_BIRTH });
    const forged: SignedCredential = { ...adultCred, sig: other.sig };
    const input = await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: forged, holderSecret, policy: gte18, nonce });
    await expect(computeWitness(input)).rejects.toThrow(/Assert Failed/);
  });

  it("attributes changed after signing (teen claims an adult birth date with the teen's signature): refused", async () => {
    const teen = await cred(issuer, { birthDate: TEEN_BIRTH });
    const tampered: SignedCredential = { ...teen, birthDate: ADULT_BIRTH };
    const input = await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: tampered, holderSecret, policy: gte18, nonce });
    await expect(computeWitness(input)).rejects.toThrow(/Assert Failed/);
  });

  it("random S and a random-message R8: refused", async () => {
    const junk = await cred(rogue, { birthDate: 19991231 });
    const forged: SignedCredential = { ...adultCred, sig: { R8x: junk.sig.R8x, R8y: junk.sig.R8y, S: randomField() % SUBGROUP_ORDER } };
    const input = await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: forged, holderSecret, policy: gte18, nonce });
    await expect(computeWitness(input)).rejects.toThrow(/Assert Failed/);
  });

  it("malleated S + l (subgroup order): refused by the S range check", async () => {
    const mall: SignedCredential = { ...adultCred, sig: { ...adultCred.sig, S: adultCred.sig.S + SUBGROUP_ORDER } };
    const input = await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: mall, holderSecret, policy: gte18, nonce });
    await expect(computeWitness(input)).rejects.toThrow(/Assert Failed/);
  });

  it("R8 off the curve: refused by the on-curve check", async () => {
    const off: SignedCredential = { ...adultCred, sig: { ...adultCred.sig, R8x: adultCred.sig.R8x + 1n } };
    const input = await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: off, holderSecret, policy: gte18, nonce });
    await expect(computeWitness(input)).rejects.toThrow(/Assert Failed/);
  });

  it("R1CS level: a rogue-key signature relabelled with the real issuer key fails the R1CS and Groth16 verify", async () => {
    const snarkjs = await snarkjsLib();
    // A teen gets a self-made "adult" credential signed by a rogue key.
    const fake = await cred(rogue, { birthDate: ADULT_BIRTH });
    // Presented under the real issuer key, the reference witness generator refuses.
    await expect(
      computeWitness(await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: fake, holderSecret, policy: gte18, nonce }))
    ).rejects.toThrow(/Assert Failed/);
    // Attacker witness: fully consistent for the rogue key, then public wires 1, 2 (Ax, Ay per the .sym file)
    // are set to the real issuer's key.
    const sym = fs.readFileSync(SYM_FILE, "utf8");
    expect(sym).toMatch(/^1,1,\d+,main\.Ax$/m);
    expect(sym).toMatch(/^2,2,\d+,main\.Ay$/m);
    const wRogue = await computeWitness(await buildInput({ Ax: rogue.Ax, Ay: rogue.Ay, cred: fake, holderSecret, policy: gte18, nonce }));
    expect(await r1csSatisfied(wRogue)).toBe(true); // it is a valid statement about the rogue key
    const values = await witnessValues(wRogue);
    values[1] = issuer.Ax;
    values[2] = issuer.Ay;
    const wAttack = encodeWitness(values);
    expect(await r1csSatisfied(wAttack)).toBe(false);
    const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY_FILE, wAttack);
    const expected = await expectedPublicSignals(issuer.Ax, issuer.Ay, gte18, nonce);
    expect(publicSignals).toEqual(expected);
    expect(await snarkjs.groth16.verify(await loadVkey(), expected, proof)).toBe(false);
    // Control: the unmodified re-encoded witness still satisfies the R1CS (encoder is faithful).
    expect(await r1csSatisfied(encodeWitness(await witnessValues(wRogue)))).toBe(true);
  });
});

describe("E2b predicate, binding and policy checks", () => {
  it("under-age holder (16) cannot prove age >= 18", async () => {
    const teen = await cred(issuer, { birthDate: TEEN_BIRTH });
    const input = await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: teen, holderSecret, policy: gte18, nonce });
    await expect(computeWitness(input)).rejects.toThrow(/Assert Failed/);
  });

  it("expired credential is refused", async () => {
    const old = await cred(issuer, { expiryDate: TODAY - 1 });
    const input = await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: old, holderSecret, policy: gte18, nonce });
    await expect(computeWitness(input)).rejects.toThrow(/Assert Failed/);
  });

  it("wrong credential type is refused", async () => {
    const other = await cred(issuer, { credType: await credTypeField("pqid:type:other:v1") });
    const input = await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: other, holderSecret, policy: gte18, nonce });
    await expect(computeWitness(input)).rejects.toThrow(/Assert Failed/);
  });

  it("another holder's credential (wrong holder secret) is refused", async () => {
    const input = await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: adultCred, holderSecret: holderSecret + 1n, policy: gte18, nonce });
    await expect(computeWitness(input)).rejects.toThrow(/Assert Failed/);
  });

  it("policyHash that does not match the private policy is refused", async () => {
    const input = await buildInput({
      Ax: issuer.Ax,
      Ay: issuer.Ay,
      cred: adultCred,
      holderSecret,
      policy: gte18,
      nonce,
      policyHashOverride: 12345n,
    });
    await expect(computeWitness(input)).rejects.toThrow(/Assert Failed/);
  });

  it("predicate code outside {1, 2} is refused", async () => {
    const bad: Policy = { ...gte18, predicateCode: 3n };
    const input = await buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred: adultCred, holderSecret, policy: bad, nonce });
    await expect(computeWitness(input)).rejects.toThrow(/Assert Failed/);
  });
});
