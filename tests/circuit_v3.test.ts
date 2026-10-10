import { describe, it, expect, beforeAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { sha3_256, sha256File } from "@pqid/common/hash";
import {
  getPoseidon,
  issuerKeyHash,
  policyHash,
  holderCommit,
  credentialLeaf,
  verifierDomainTag,
  stmtCodeForDomain,
  stmtCodeForDomainV3,
  PREDICATE_AGE_GTE,
  PREDICATE_AGE_LT,
  ISSUANCE_TREE_DEPTH,
} from "@pqid/common/encoding";
import {
  REPO_ROOT,
  CIRCUIT_BUILD_DIR_V3,
  R1CS_FILE_V3,
  WASM_FILE_V3,
  ZKEY_FILE_V3,
  VKEY_FILE,
  VKEY_FILE_V3,
  SOLIDITY_VERIFIER_FILE_V3,
  SETUP_OUT_DIR_V3,
} from "@pqid/common/paths";
import { IssuanceTree } from "@pqid/issuer";
import { RevocationTree } from "@pqid/revocation";
import {
  buildCircuitInputV3,
  type PublicInputsV3,
  type PrivateInputsV3,
  type CircuitInput,
} from "@pqid/wallet/witness";
import { readPins } from "../setup/pins.ts";
import { auditKey } from "../setup/groth16_setup_v3.ts";
import { compileV3Without } from "../harness/v3/attacker_circuit.ts";
import {
  revokedInclusion,
  forgedIsOld0Opening,
  sameKeyOpening,
  truncatedEmptyOpening,
} from "../harness/v3/smt_forgery.ts";
import { deriveBeaconTrapdoor } from "../harness/v3/trapdoor.ts";
import { patchWitnessWire, r1csSatisfied } from "../harness/v3/wtns_tamper.ts";

/**
 * Circuit v3 (circuits/credential_auth_v3.circom): witness correctness, the
 * new issuance binding, and the setup properties. Constant fixtures only; no
 * PQC keys or chain (tests/protocol_v3.test.ts covers the verifier).
 */
const PK_ISSUER = Buffer.alloc(1312, 0xa7);
const OTHER_PK = Buffer.alloc(1312, 0x5c);
const HOLDER_SECRET = 123456789n;
const AGE = 42n;
const NONCE = 424242n;
const VERIFIER_ID = "pqid:verifier:demo";
const BEACON = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

let poseidon: Awaited<ReturnType<typeof getPoseidon>>;
let revTree: RevocationTree;
let issTree: IssuanceTree;
let subjectCredId: Buffer;
let subjectIndex: number;

function fixtureCredId(i: number): Buffer {
  return sha3_256(Buffer.from(`pqid-fixture-revoked-${i}`, "utf8"));
}

function leafFor(credId: Uint8Array, age: bigint, secret = HOLDER_SECRET, pk = PK_ISSUER): bigint {
  return credentialLeaf(poseidon, {
    issuerKeyHash: issuerKeyHash(poseidon, pk),
    credId,
    holderCommit: holderCommit(poseidon, secret),
    claimAge: age,
  });
}

async function makeInput(
  overrides: Partial<PublicInputsV3 & PrivateInputsV3> = {}
): Promise<CircuitInput> {
  const credId = overrides.credId ?? subjectCredId;
  const nonMembership = overrides.nonMembership ?? (await revTree.getNonMembershipProof(credId));
  const predicateCode = overrides.predicateCode ?? PREDICATE_AGE_GTE;
  const domainTag = overrides.domainTag ?? verifierDomainTag(poseidon, VERIFIER_ID);
  const issPath = issTree.path(subjectIndex);
  const pub: PublicInputsV3 = {
    issuerKeyHash: overrides.issuerKeyHash ?? issuerKeyHash(poseidon, PK_ISSUER),
    revRoot: overrides.revRoot ?? BigInt(nonMembership.root),
    policyHash:
      overrides.policyHash ?? policyHash(poseidon, predicateCode, overrides.threshold ?? 18n),
    nonce: overrides.nonce ?? NONCE,
    stmtCode: overrides.stmtCode ?? stmtCodeForDomainV3(poseidon, domainTag),
    issRoot: overrides.issRoot ?? issTree.root(),
  };
  const priv: PrivateInputsV3 = {
    credId,
    holderSecret: overrides.holderSecret ?? HOLDER_SECRET,
    claimAge: overrides.claimAge ?? AGE,
    threshold: overrides.threshold ?? 18n,
    predicateCode,
    domainTag,
    issLeafIndex: overrides.issLeafIndex ?? issPath.leafIndex,
    issPathElements: overrides.issPathElements ?? issPath.pathElements,
    nonMembership,
  };
  return buildCircuitInputV3(pub, priv);
}

async function calcWitness(input: CircuitInput): Promise<string> {
  const snarkjs = await import("snarkjs");
  const wtnsFile = path.join(os.tmpdir(), `pqid-v3-test-${Date.now()}-${randomBytes(4).toString("hex")}.wtns`);
  try {
    await snarkjs.wtns.calculate(input, WASM_FILE_V3, wtnsFile);
  } catch (e) {
    fs.rmSync(wtnsFile, { force: true }); // a refused witness may leave a partial file
    throw e;
  }
  return wtnsFile;
}

async function proveAndVerify(input: CircuitInput): Promise<{ ok: boolean; publicSignals: string[] }> {
  const snarkjs = await import("snarkjs");
  const wtnsFile = await calcWitness(input);
  const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY_FILE_V3, wtnsFile);
  fs.rmSync(wtnsFile, { force: true });
  const vkey = JSON.parse(fs.readFileSync(VKEY_FILE_V3, "utf8")) as unknown;
  return { ok: await snarkjs.groth16.verify(vkey, publicSignals, proof), publicSignals };
}

beforeAll(async () => {
  poseidon = await getPoseidon();
  revTree = await RevocationTree.create();
  for (let i = 0; i < 8; i++) await revTree.insert(fixtureCredId(i));
  subjectCredId = sha3_256(Buffer.from("pqid-fixture-subject", "utf8"));
  issTree = await IssuanceTree.create();
  // other holders' leaves around the subject so the path is non-trivial
  for (let i = 0; i < 5; i++) issTree.insert(leafFor(sha3_256(Buffer.from(`other-${i}`)), 20n + BigInt(i), 1000n + BigInt(i)));
  subjectIndex = issTree.insert(leafFor(subjectCredId, AGE));
  issTree.insert(leafFor(sha3_256(Buffer.from("other-late")), 70n, 2000n));
});

describe("issuance tree (JS twin of MerkleRoot)", () => {
  it("has depth 32 and paths that recompute the root", () => {
    expect(issTree.depth).toBe(ISSUANCE_TREE_DEPTH);
    const p = issTree.path(subjectIndex);
    expect(p.pathElements).toHaveLength(ISSUANCE_TREE_DEPTH);
    expect(IssuanceTree.rootFromPath(poseidon, issTree.leaf(subjectIndex), p, ISSUANCE_TREE_DEPTH)).toBe(issTree.root());
  });

  it("rejects the reserved zero leaf, out-of-range indices, and paths the circuit would reject", async () => {
    const t = await IssuanceTree.create(4);
    expect(() => t.insert(0n)).toThrow(/zero leaf/);
    expect(() => t.path(0)).toThrow(/no leaf/);
    t.insert(5n);
    const p = t.path(0);
    expect(() => IssuanceTree.rootFromPath(poseidon, 5n, { ...p, pathElements: p.pathElements.slice(1) }, 4)).toThrow(/siblings/);
    expect(() => IssuanceTree.rootFromPath(poseidon, 5n, { ...p, leafIndex: "16" }, 4)).toThrow(/out of range/);
  });

  it("snapshot paths (pathAt/rootAt) equal paths of a tree that only ever held those leaves", async () => {
    const leaves = Array.from({ length: 11 }, (_, i) => BigInt(1000 + i));
    const full = await IssuanceTree.create(6);
    for (const l of leaves) full.insert(l);
    for (const size of [1, 2, 5, 8, 11]) {
      const prefix = await IssuanceTree.create(6);
      for (const l of leaves.slice(0, size)) prefix.insert(l);
      expect(full.rootAt(size)).toBe(prefix.root());
      for (let i = 0; i < size; i++) {
        expect(full.pathAt(i, size)).toEqual(prefix.path(i));
      }
    }
    expect(() => full.pathAt(5, 5)).toThrow(/not among/);
  });
});

describe("credential_auth_v3 circuit", () => {
  it("valid witness proves and verifies; six public signals in canonical order", async () => {
    const input = await makeInput();
    const { ok, publicSignals } = await proveAndVerify(input);
    expect(ok).toBe(true);
    expect(publicSignals).toEqual([
      input["issuerKeyHash"],
      input["revRoot"],
      input["policyHash"],
      input["nonce"],
      input["stmtCode"],
      input["issRoot"],
    ]);
  });

  it("supports age_lt against the same issued leaf only when the committed age satisfies it", async () => {
    await expect(calcWitness(await makeInput({ predicateCode: PREDICATE_AGE_LT }))).rejects.toThrow();
    // a 16-year-old's own leaf proves age < 18
    const minorId = sha3_256(Buffer.from("pqid-minor", "utf8"));
    const t = await IssuanceTree.create();
    const idx = t.insert(leafFor(minorId, 16n));
    const p = t.path(idx);
    const input = await makeInput({
      credId: minorId,
      claimAge: 16n,
      predicateCode: PREDICATE_AGE_LT,
      issRoot: t.root(),
      issLeafIndex: p.leafIndex,
      issPathElements: p.pathElements,
    });
    expect((await proveAndVerify(input)).ok).toBe(true);
  });

  // ---- the v3 binding (review 9.1 / 9.2): nothing the leaf commits to is free
  it("rejects a forged age (claimAge differs from the issued leaf)", async () => {
    await expect(calcWitness(await makeInput({ claimAge: 43n }))).rejects.toThrow(/Assert Failed/);
  });

  it("rejects a fresh credID (9.2: revoked holder switching IDs)", async () => {
    const fresh = randomBytes(32);
    await expect(calcWitness(await makeInput({ credId: fresh }))).rejects.toThrow(/Assert Failed/);
  });

  it("rejects a holder secret that does not open the leaf's holderCommit", async () => {
    await expect(calcWitness(await makeInput({ holderSecret: 999n }))).rejects.toThrow(/Assert Failed/);
  });

  it("rejects another issuer's key hash against this issuer's leaf", async () => {
    await expect(
      calcWitness(await makeInput({ issuerKeyHash: issuerKeyHash(poseidon, OTHER_PK) }))
    ).rejects.toThrow(/Assert Failed/);
  });

  it("rejects a wrong leaf position and an index outside [0, 2^32)", async () => {
    await expect(calcWitness(await makeInput({ issLeafIndex: String(subjectIndex + 1) }))).rejects.toThrow();
    await expect(
      calcWitness(await makeInput({ issLeafIndex: (2n ** 32n + BigInt(subjectIndex)).toString() }))
    ).rejects.toThrow();
  });

  it("rejects an issRoot the leaf is not under (e.g. an unsigned or unrelated root)", async () => {
    await expect(calcWitness(await makeInput({ issRoot: issTree.root() + 1n }))).rejects.toThrow(/Assert Failed/);
  });

  it("R1CS (not only the witness generator) rejects a leaf opened to a swapped root", async () => {
    // Self-consistent witness for an attacker tree holding a forged age-99 leaf…
    const t = await IssuanceTree.create();
    const idx = t.insert(leafFor(subjectCredId, 99n));
    const p = t.path(idx);
    const wtnsFile = await calcWitness(
      await makeInput({ claimAge: 99n, issRoot: t.root(), issLeafIndex: p.leafIndex, issPathElements: p.pathElements })
    );
    try {
      expect(await r1csSatisfied(R1CS_FILE_V3, wtnsFile)).toBe(true);
      // …then the public issRoot wire (index 6) is overwritten with the real root.
      patchWitnessWire(wtnsFile, 6, issTree.root());
      expect(await r1csSatisfied(R1CS_FILE_V3, wtnsFile)).toBe(false);
    } finally {
      fs.rmSync(wtnsFile, { force: true });
    }
  });

  // ---- v2 properties that must survive
  it("rejects a stale revocation opening after the credID is revoked", async () => {
    const t2 = await RevocationTree.create();
    for (let i = 0; i < 8; i++) await t2.insert(fixtureCredId(i));
    const stale = await t2.getNonMembershipProof(subjectCredId);
    const newRoot = await t2.insert(subjectCredId);
    const input = await makeInput({ nonMembership: { ...stale, root: newRoot.toString() } });
    await expect(calcWitness(input)).rejects.toThrow();
  });

  it("rejects a threshold that does not match policyHash", async () => {
    const a = await makeInput();
    a["threshold"] = "21";
    await expect(calcWitness(a)).rejects.toThrow(/Assert Failed/);
  });

  it("rejects a predicateCode outside {1,2} even when policyHash commits to it", async () => {
    // policyHash is derived from the same code, so the range constraint itself is reached
    await expect(calcWitness(await makeInput({ predicateCode: 3n }))).rejects.toThrow(/Assert Failed/);
  });

  it("rejects a v2-version or other-verifier stmtCode", async () => {
    const domain = verifierDomainTag(poseidon, VERIFIER_ID);
    await expect(calcWitness(await makeInput({ stmtCode: stmtCodeForDomain(poseidon, domain) }))).rejects.toThrow();
    const other = verifierDomainTag(poseidon, "pqid:verifier:other");
    await expect(calcWitness(await makeInput({ stmtCode: stmtCodeForDomainV3(poseidon, other) }))).rejects.toThrow();
  });
});

describe("revocation opening forgery (v3 review circuit-1)", () => {
  let inc: Awaited<ReturnType<typeof revokedInclusion>>;
  const revokedId = sha3_256(Buffer.from("pqid-revoked-subject", "utf8"));

  beforeAll(async () => {
    inc = await revokedInclusion([...Array.from({ length: 8 }, (_, i) => fixtureCredId(i)), revokedId], revokedId);
  });

  const revokedInput = async (nonMembership: Awaited<ReturnType<typeof forgedIsOld0Opening>>) => {
    const t = await IssuanceTree.create();
    const idx = t.insert(leafFor(revokedId, AGE));
    const p = t.path(idx);
    return makeInput({
      credId: revokedId,
      nonMembership,
      issRoot: t.root(),
      issLeafIndex: p.leafIndex,
      issPathElements: p.pathElements,
    });
  };

  it("the witness generator refuses a non-boolean smtIsOld0 at the booleanity constraint", async () => {
    const err = await calcWitness(await revokedInput(await forgedIsOld0Opening(inc))).catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    const line = /CredentialAuthV3_\d+ line: (\d+)/.exec((err as Error).message)?.[1];
    const src = fs.readFileSync(path.join(REPO_ROOT, "circuits", "credential_auth_v3.circom"), "utf8").split(/\r?\n/);
    expect(src[Number(line) - 1]).toContain("smtIsOld0 * (smtIsOld0 - 1) === 0");
  });

  it("the R1CS rejects the forged witness produced by the attacker's own generator", async () => {
    const attacker = compileV3Without("smtIsOld0 * (smtIsOld0 - 1) === 0;");
    const wtnsFile = path.join(os.tmpdir(), `pqid-v3-forged-${randomBytes(4).toString("hex")}.wtns`);
    try {
      expect(attacker.sameWireLayout).toBe(true);
      const snarkjs = await import("snarkjs");
      await snarkjs.wtns.calculate(await revokedInput(await forgedIsOld0Opening(inc)), attacker.wasm, wtnsFile);
      expect(await r1csSatisfied(R1CS_FILE_V3, wtnsFile)).toBe(false);
    } finally {
      fs.rmSync(wtnsFile, { force: true });
      attacker.cleanup();
    }
  }, 120_000);

  it("other hand-built openings for a revoked key are refused", async () => {
    await expect(calcWitness(await revokedInput(sameKeyOpening(inc)))).rejects.toThrow(/Assert Failed/);
    await expect(calcWitness(await revokedInput(truncatedEmptyOpening(inc)))).rejects.toThrow(/Assert Failed/);
  });
});

describe("v3 trusted setup", () => {
  it("r1cs, wasm, zkey, vkey and Solidity verifier match their pins", () => {
    const pins = readPins();
    expect(sha256File(R1CS_FILE_V3)).toBe(pins["v3/credential_auth_v3.r1cs"]?.sha256);
    expect(sha256File(WASM_FILE_V3)).toBe(pins["v3/credential_auth_v3.wasm"]?.sha256);
    expect(sha256File(ZKEY_FILE_V3)).toBe(pins["v3/credential_auth_v3_final.zkey"]?.sha256);
    expect(sha256File(VKEY_FILE_V3)).toBe(pins["v3/verification_key.json"]?.sha256);
    expect(sha256File(SOLIDITY_VERIFIER_FILE_V3)).toBe(pins["v3/Groth16Verifier.sol"]?.sha256);
    expect(sha256File(path.join(SETUP_OUT_DIR_V3, "setup_transcript.json"))).toBe(pins["v3/setup_transcript.json"]?.sha256);
  });

  it("the R1CS itself constrains smtIsOld0 to {0,1}", async () => {
    const snarkjs = await import("snarkjs");
    const sym = fs.readFileSync(path.join(CIRCUIT_BUILD_DIR_V3, "credential_auth_v3.sym"), "utf8");
    const wire = /^\d+,(\d+),\d+,main\.smtIsOld0$/m.exec(sym)?.[1];
    expect(wire).toBeDefined();
    const r1cs = (await snarkjs.r1cs.exportJson(R1CS_FILE_V3)) as { constraints: Array<Array<Record<string, string>>> };
    const onlyWire = (lc: Record<string, string>) => Object.keys(lc).every((k) => k === wire || k === "0");
    const booleanity = r1cs.constraints.some(
      ([a, b, c]) => a && b && c && wire! in a && wire! in b && onlyWire(a) && onlyWire(b) && onlyWire(c)
    );
    expect(booleanity).toBe(true);
  }, 120_000);

  it("the public beacon determines v2's delta but not v3's (review 9.3)", async () => {
    const v2 = await deriveBeaconTrapdoor(JSON.parse(fs.readFileSync(VKEY_FILE, "utf8")), BEACON, 10);
    const v3 = await deriveBeaconTrapdoor(JSON.parse(fs.readFileSync(VKEY_FILE_V3, "utf8")), BEACON, 10);
    expect(v2.matchesDelta).toBe(true);
    expect(v3.matchesDelta).toBe(false);
  });

  it("audit: zkey derives from r1cs + ptau, has a secret contribution before the beacon, and exports the committed vkey and Solidity verifier", async () => {
    const audit = await auditKey();
    expect(audit.secretContributions).toBeGreaterThanOrEqual(1);
    expect(audit.contributions.at(-1)?.beacon).toBe(true);
    expect(audit.contributions[0]?.beacon).toBe(false);
    expect(audit.vkeyMatchesZkey).toBe(true);
    expect(audit.solidityMatchesZkey).toBe(true);
  }, 600_000);
});
