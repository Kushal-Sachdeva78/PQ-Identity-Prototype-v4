import fs from "node:fs";
import path from "node:path";
import { sha3_256 } from "@pqid/common/hash";
import { IssuanceTree } from "@pqid/issuer";
import {
  getPoseidon,
  poseidonBig,
  issuerKeyHash,
  verifierDomainTag,
  credTypeField,
  credentialLeafV4,
  policyHashV4,
  stmtCodeV4,
  revKeyFromCredId,
} from "@pqid/v4/encoding";
import { DEFAULT_TYPE_ID, ISSUANCE_DEPTH, REV_DEPTH } from "@pqid/v4/constants";
import { IndexedMerkleTree } from "@pqid/v4/imt";
import { buildCircuitInputV4, publicSignalsOfInputV4, type CircuitInputV4 } from "@pqid/v4/witness";
import {
  buildFixtureProofInput,
  buildFixtureProofInputV3,
  fixtureRevokedCredIds,
  FIXTURE_PK_ISSUER,
  FIXTURE_HOLDER_SECRET,
  FIXTURE_NONCE,
  FIXTURE_THRESHOLD,
  FIXTURE_VERIFIER_ID,
} from "../../fixture.ts";
import {
  ALL_VERSIONS,
  VERSIONS,
  abs,
  checkVersionArtifacts,
  inputsDir,
  inputsLockFile,
  optList,
  flag,
  rel,
  sha256Hex,
  utcNow,
  writeJson,
  type InputLockEntry,
  type InputsLock,
  type Version,
} from "./lib.ts";

/**
 * Phase D inputs (docs/v4/BENCH_PROTOCOL.md, "Inputs"): one fixed honest input per circuit
 * version, generated once, SHA-256 pinned in <root>/inputs/inputs.lock.json together with
 * the artifact hashes it was validated against and its expected public signals.
 *
 *   v2: harness/fixture.ts buildFixtureProofInput()     (read-only reuse; the published v2 input)
 *   v3: harness/fixture.ts buildFixtureProofInputV3()   (read-only reuse; compare_v2_v3.ts input)
 *   v4: buildFixtureProofInputV4() below: the same subject, holder secret, revoked set,
 *       verifier, nonce and threshold as v2/v3, an 8-leaf depth-32 issuance tree with the
 *       subject at index 5 (as v3), and the revoked set in the depth-30 revocation IMT.
 *
 * All values are published fixture constants (no key generation, no randomness), so the
 * inputs are byte-reproducible; they hold no real holder secret.
 *
 * Usage: node --import tsx harness/v4/bench/inputs.ts [--smoke] [--check] [--force] [--versions v2,v3,v4]
 *   default: write the inputs and the lock; refuses to replace a DIFFERENT existing pin
 *            unless --force (an identical rebuild is reported and left as is)
 *   --check: rebuild in memory and compare with the existing lock (exit 1 on mismatch)
 */

/** Fixed calendar values of the v4 fixture (a true statement on TODAY). */
export const V4_FIXTURE = {
  today: 20260927,
  epochFromDate: 20260927,
  epochToDate: 20260928,
  birthDate: 19840315, // age 42 on TODAY, as the v2/v3 fixture's claimAge 42
  expiryDate: 20261226, // TODAY + 90 days (DEFAULT_CREDENTIAL_DAYS)
  leaves: 8,
  subjectIndex: 5,
} as const;

export async function buildFixtureProofInputV4(): Promise<CircuitInputV4> {
  const poseidon = await getPoseidon();
  const subjectCredId = sha3_256(Buffer.from("pqid-fixture-subject", "utf8"));
  const ikh = issuerKeyHash(poseidon, FIXTURE_PK_ISSUER);
  const credType = credTypeField(poseidon, DEFAULT_TYPE_ID);
  const domainTag = verifierDomainTag(poseidon, FIXTURE_VERIFIER_ID);

  const iss = await IssuanceTree.create(ISSUANCE_DEPTH);
  let subjectIndex = -1;
  for (let i = 0; i < V4_FIXTURE.leaves; i++) {
    const isSubject = i === V4_FIXTURE.subjectIndex;
    const idx = iss.insert(
      credentialLeafV4(poseidon, {
        issuerKeyHash: ikh,
        credId: isSubject ? subjectCredId : sha3_256(Buffer.from(`pqid-fixture-holder-${i}`, "utf8")),
        holderCommit: poseidonBig(poseidon, [isSubject ? FIXTURE_HOLDER_SECRET : 1000n + BigInt(i)]),
        birthDate: isSubject ? V4_FIXTURE.birthDate : 19900101 + i * 10000,
        expiryDate: V4_FIXTURE.expiryDate,
        credType,
      })
    );
    if (isSubject) subjectIndex = idx;
  }
  const issPath = iss.path(subjectIndex);

  const rev = await IndexedMerkleTree.create(REV_DEPTH);
  for (const c of fixtureRevokedCredIds()) rev.insert(revKeyFromCredId(c));
  const nm = rev.nonMembershipWitness(revKeyFromCredId(subjectCredId));

  return buildCircuitInputV4(
    {
      issuerKeyHash: ikh,
      revRoot: BigInt(nm.root),
      policyHash: policyHashV4(poseidon, {
        predicate: "age_gte",
        threshold: Number(FIXTURE_THRESHOLD),
        today: V4_FIXTURE.today,
        requiredType: credType,
      }),
      nonce: FIXTURE_NONCE,
      stmtCode: stmtCodeV4(poseidon, domainTag),
      issRoot: BigInt(issPath.root),
      epochFromDate: V4_FIXTURE.epochFromDate,
      epochToDate: V4_FIXTURE.epochToDate,
    },
    {
      credId: subjectCredId,
      holderSecret: FIXTURE_HOLDER_SECRET,
      birthDate: V4_FIXTURE.birthDate,
      expiryDate: V4_FIXTURE.expiryDate,
      credType,
      predicate: "age_gte",
      threshold: Number(FIXTURE_THRESHOLD),
      today: V4_FIXTURE.today,
      requiredType: credType,
      domainTag,
      issLeafIndex: issPath.leafIndex,
      issPathElements: issPath.pathElements,
      rev: { lowIndex: nm.lowIndex, lowValue: nm.lowValue, lowNext: nm.lowNext, lowPath: nm.lowPath },
    }
  );
}

async function buildInput(v: Version): Promise<Record<string, unknown>> {
  if (v === "v2") return (await buildFixtureProofInput()) as unknown as Record<string, unknown>;
  if (v === "v3") return (await buildFixtureProofInputV3()) as unknown as Record<string, unknown>;
  return (await buildFixtureProofInputV4()) as unknown as Record<string, unknown>;
}

/** One untimed reference proof: checks the artifacts and yields the expected public signals. */
async function referenceProof(v: Version, input: Record<string, unknown>): Promise<{ publicSignals: string[]; verified: boolean }> {
  const snarkjs = await import("snarkjs");
  const s = VERSIONS[v];
  const wtns: { type: "mem"; data?: Uint8Array } = { type: "mem" };
  await snarkjs.wtns.calculate(input as never, abs(s.wasm.rel), wtns);
  const { proof, publicSignals } = await snarkjs.groth16.prove(abs(s.zkey.rel), wtns as never);
  const vkey = JSON.parse(fs.readFileSync(abs(s.vkey.rel), "utf8")) as unknown;
  const verified = await snarkjs.groth16.verify(vkey as never, publicSignals, proof);
  return { publicSignals: publicSignals as string[], verified };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const smoke = flag(argv, "smoke");
  const check = flag(argv, "check");
  const force = flag(argv, "force");
  const versions = optList(argv, "versions", ALL_VERSIONS, ALL_VERSIONS);
  const lockFile = inputsLockFile(smoke);
  const existing: InputsLock | null = fs.existsSync(lockFile) ? (JSON.parse(fs.readFileSync(lockFile, "utf8")) as InputsLock) : null;
  if (check && !existing) throw new Error(`--check: ${rel(lockFile)} does not exist`);

  const lock: InputsLock = existing && !force
    ? existing
    : { schema: "pqid/v4-bench-inputs/v1", createdUtc: utcNow(), generator: "harness/v4/bench/inputs.ts", versions: {} };
  let mismatches = 0;

  for (const v of versions) {
    const input = await buildInput(v);
    const text = JSON.stringify(input);
    const inputSha256 = sha256Hex(text);
    const artifacts = checkVersionArtifacts(v);
    const ref = await referenceProof(v, input);
    if (!ref.verified) throw new Error(`${v}: the reference proof on the fixed input does not verify`);
    if (v === "v4") {
      const expect = publicSignalsOfInputV4(input as CircuitInputV4);
      if (JSON.stringify(expect) !== JSON.stringify(ref.publicSignals)) throw new Error("v4: public signals differ from the input's public fields");
    }
    const file = path.join(inputsDir(smoke), `${v}_input.json`);
    const entry: InputLockEntry = {
      version: v,
      file: rel(file),
      inputSha256,
      publicSignals: ref.publicSignals,
      publicSignalsSha256: sha256Hex(JSON.stringify(ref.publicSignals)),
      source: VERSIONS[v].inputSource,
      keyLabel: VERSIONS[v].keyLabel,
      artifacts,
      referenceProofVerified: ref.verified,
    };
    const prev = existing?.versions[v];
    const same =
      prev !== undefined &&
      prev.inputSha256 === entry.inputSha256 &&
      prev.publicSignalsSha256 === entry.publicSignalsSha256 &&
      (["wasm", "zkey", "vkey"] as const).every((k) => prev.artifacts[k].sha256 === entry.artifacts[k].sha256);

    if (check) {
      console.log(`[inputs] ${v}: ${same ? "matches the pin" : "DIFFERS from the pin"} (input ${inputSha256.slice(0, 16)}...)`);
      if (!same) mismatches++;
      continue;
    }
    if (prev && !same && !force) {
      throw new Error(`${v}: a different input/artifact pin exists in ${rel(lockFile)}; pins are made once (use --force only after a re-key, and record why)`);
    }
    if (same && !force) {
      console.log(`[inputs] ${v}: already pinned, rebuild identical (input ${inputSha256})`);
      continue;
    }
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text + "\n");
    lock.versions[v] = entry;
    console.log(`[inputs] ${v}: wrote ${entry.file} input sha256 ${inputSha256}, ${ref.publicSignals.length} public signals, reference proof verifies`);
  }

  if (check) {
    if (mismatches > 0) {
      console.error(`[inputs] --check: ${mismatches} version(s) differ from ${rel(lockFile)}`);
      process.exit(1);
    }
    console.log(`[inputs] --check: all requested versions match ${rel(lockFile)}`);
    process.exit(0);
  }
  writeJson(lockFile, lock);
  console.log(`[inputs] lock -> ${rel(lockFile)}`);
  process.exit(0);
}

const self = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (self.endsWith(path.join("harness", "v4", "bench", "inputs.ts"))) {
  main().catch((e: unknown) => {
    console.error(e instanceof Error ? e.message : e);
    process.exit(1);
  });
}
