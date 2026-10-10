import { describe, it, expect, beforeAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { sha3_256 } from "@pqid/common/hash";
import {
  getPoseidon,
  issuerKeyHash,
  policyHash,
  holderCommit,
  verifierDomainTag,
  stmtCodeForDomain,
  PREDICATE_AGE_GTE,
  PREDICATE_AGE_LT,
} from "@pqid/common/encoding";
import { WASM_FILE, ZKEY_FILE, VKEY_FILE } from "@pqid/common/paths";
import { RevocationTree, SMT_DEPTH } from "@pqid/revocation";
import { buildCircuitInput, type PublicInputs, type PrivateInputs } from "@pqid/wallet/witness";

/**
 * Circuit witness correctness + SMT membership/non-membership parity tests
 * (M2/M3 acceptance). Uses constant fixtures only; proving uses the pinned
 * zkey from setup/out.
 */
const FIXTURE_PK_ISSUER = Buffer.alloc(1312, 0xa7); // deterministic stand-in key bytes
const HOLDER_SECRET = 123456789n;
const NONCE = 424242n;

let poseidon: Awaited<ReturnType<typeof getPoseidon>>;
let tree: RevocationTree;
let subjectCredId: Buffer;

function fixtureCredId(i: number): Buffer {
  return sha3_256(Buffer.from(`pqid-fixture-revoked-${i}`, "utf8"));
}

const VERIFIER_ID = "pqid:verifier:demo";

async function makeInput(
  overrides: Partial<PublicInputs & PrivateInputs> = {}
): Promise<ReturnType<typeof buildCircuitInput>> {
  const nonMembership =
    overrides.nonMembership ?? (await tree.getNonMembershipProof(subjectCredId));
  const predicateCode = overrides.predicateCode ?? PREDICATE_AGE_GTE;
  const domainTag = overrides.domainTag ?? verifierDomainTag(poseidon, VERIFIER_ID);
  const pub: PublicInputs = {
    issuerKeyHash: overrides.issuerKeyHash ?? issuerKeyHash(poseidon, FIXTURE_PK_ISSUER),
    revRoot: overrides.revRoot ?? BigInt(nonMembership.root),
    policyHash:
      overrides.policyHash ??
      policyHash(poseidon, predicateCode, overrides.threshold ?? 18n),
    nonce: overrides.nonce ?? NONCE,
    stmtCode: overrides.stmtCode ?? stmtCodeForDomain(poseidon, domainTag),
  };
  const priv: PrivateInputs = {
    credId: overrides.credId ?? subjectCredId,
    holderSecret: overrides.holderSecret ?? HOLDER_SECRET,
    holderCommit: overrides.holderCommit ?? holderCommit(poseidon, HOLDER_SECRET),
    claimAge: overrides.claimAge ?? 42n,
    threshold: overrides.threshold ?? 18n,
    predicateCode,
    domainTag,
    nonMembership,
  };
  return buildCircuitInput(pub, priv);
}

async function calcWitness(input: ReturnType<typeof buildCircuitInput>): Promise<string> {
  const snarkjs = await import("snarkjs");
  const wtnsFile = path.join(os.tmpdir(), `pqid-test-${Date.now()}-${Math.random()}.wtns`);
  await snarkjs.wtns.calculate(input, WASM_FILE, wtnsFile);
  return wtnsFile;
}

beforeAll(async () => {
  poseidon = await getPoseidon();
  tree = await RevocationTree.create();
  for (let i = 0; i < 8; i++) await tree.insert(fixtureCredId(i));
  subjectCredId = sha3_256(Buffer.from("pqid-fixture-subject", "utf8"));
});

describe("revocation SMT", () => {
  it("empty slots yield non-membership proofs that respect depth 32", async () => {
    const proof = await tree.getNonMembershipProof(subjectCredId);
    expect(proof.siblings).toHaveLength(SMT_DEPTH);
    expect(await tree.isRevoked(subjectCredId)).toBe(false);
  });

  it("rejects non-membership proof requests for revoked credIDs", async () => {
    const revoked = fixtureCredId(3);
    expect(await tree.isRevoked(revoked)).toBe(true);
    await expect(tree.getNonMembershipProof(revoked)).rejects.toThrow(/revoked/);
  });
});

describe("credential_auth circuit", () => {
  it("valid witness proves and verifies; public signal order is canonical", async () => {
    const snarkjs = await import("snarkjs");
    const input = await makeInput();
    const wtnsFile = await calcWitness(input);
    const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY_FILE, wtnsFile);
    fs.rmSync(wtnsFile);

    expect(publicSignals).toHaveLength(5);
    expect(publicSignals[0]).toBe(input["issuerKeyHash"]);
    expect(publicSignals[1]).toBe(input["revRoot"]);
    expect(publicSignals[2]).toBe(input["policyHash"]);
    expect(publicSignals[3]).toBe(input["nonce"]);
    expect(publicSignals[4]).toBe(input["stmtCode"]);

    const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, "utf8")) as unknown;
    expect(await snarkjs.groth16.verify(vkey, publicSignals, proof)).toBe(true);
  });

  it("rejects a stale non-membership opening after the credID is revoked", async () => {
    // Fresh tree so the module-level one is untouched.
    const t2 = await RevocationTree.create();
    for (let i = 0; i < 8; i++) await t2.insert(fixtureCredId(i));
    const staleOpening = await t2.getNonMembershipProof(subjectCredId);
    const newRoot = await t2.insert(subjectCredId); // revoke it

    // Stale opening against the NEW root must not satisfy the circuit.
    const staleWithNewRoot = { ...staleOpening, root: newRoot.toString() };
    const input = await makeInput({ nonMembership: staleWithNewRoot });
    await expect(calcWitness(input)).rejects.toThrow();
  });

  it("rejects a wrong holder secret", async () => {
    const input = await makeInput({ holderSecret: 999n });
    await expect(calcWitness(input)).rejects.toThrow();
  });

  it("rejects a claim that fails the policy predicate (age 16 < 18)", async () => {
    const input = await makeInput({ claimAge: 16n });
    await expect(calcWitness(input)).rejects.toThrow();
  });

  it("rejects a threshold that does not match the public policyHash", async () => {
    const input = await makeInput();
    input["threshold"] = "21"; // policyHash still commits to 18
    await expect(calcWitness(input)).rejects.toThrow();
  });

  it("supports the second predicate: age_lt (claimAge 16 < threshold 18)", async () => {
    const snarkjs = await import("snarkjs");
    const input = await makeInput({
      predicateCode: PREDICATE_AGE_LT,
      claimAge: 16n,
      threshold: 18n,
    });
    const wtnsFile = await calcWitness(input);
    const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY_FILE, wtnsFile);
    fs.rmSync(wtnsFile);
    const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, "utf8")) as unknown;
    expect(await snarkjs.groth16.verify(vkey, publicSignals, proof)).toBe(true);
  });

  it("rejects age_lt when the claim does not satisfy it (42 < 18 is false)", async () => {
    const input = await makeInput({ predicateCode: PREDICATE_AGE_LT });
    await expect(calcWitness(input)).rejects.toThrow();
  });

  it("rejects a predicateCode outside {1,2}", async () => {
    const input = await makeInput();
    input["predicateCode"] = "3";
    await expect(calcWitness(input)).rejects.toThrow();
  });

  it("rejects a stmtCode that binds a DIFFERENT verifier's domain (cross-verifier replay)", async () => {
    // witness claims domain A in the private input, but the public stmtCode
    // was computed for verifier B — the Poseidon binding fails in-circuit
    const otherDomain = verifierDomainTag(poseidon, "pqid:verifier:other");
    const input = await makeInput({
      stmtCode: stmtCodeForDomain(poseidon, otherDomain),
    });
    await expect(calcWitness(input)).rejects.toThrow();
  });
});
