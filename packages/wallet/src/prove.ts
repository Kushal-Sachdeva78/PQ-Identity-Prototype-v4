import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import type { Groth16Proof, PublicSignals } from "snarkjs";
import {
  WASM_FILE,
  ZKEY_FILE,
  WASM_FILE_V3,
  ZKEY_FILE_V3,
  RAPIDSNARK_PROVER_WSL,
  toWslPath,
} from "@pqid/common/paths";
import { sha256File, sha256Bytes } from "@pqid/common/hash";
import type { CircuitInput } from "./witness.ts";

export type ProverBackend = "snarkjs" | "rapidsnark";

/** Witness generator + proving key of one circuit version. */
export interface CircuitArtifacts {
  wasm: string;
  zkey: string;
}
export const V2_ARTIFACTS: CircuitArtifacts = { wasm: WASM_FILE, zkey: ZKEY_FILE };
export const V3_ARTIFACTS: CircuitArtifacts = { wasm: WASM_FILE_V3, zkey: ZKEY_FILE_V3 };

export interface ProveResult {
  backend: ProverBackend;
  proof: Groth16Proof;
  publicSignals: PublicSignals;
  /** SHA-256 of the proving key actually used. */
  zkeySha256: string;
  /** SHA-256 of the witness file actually used. */
  witnessSha256: string;
  timings: {
    witnessMs?: number;
    proveMs: number;
    /** rapidsnark: subprocess wall time incl. process start + file I/O
     *  (slight over-estimate of pure proving, as in the paper, A.2). */
    proveIsSubprocessWall: boolean;
  };
  proofJsonBytes: number;
}

/**
 * Compute the witness for `input` into a fresh temp .wtns file (benchmarks,
 * rapidsnark and tests; the wallet's snarkJS path keeps it in memory, see
 * prove()). The file holds the holder's secrets; callers delete it.
 */
export async function computeWitness(
  input: CircuitInput,
  wasmFile: string = WASM_FILE
): Promise<{ wtnsFile: string; witnessMs: number }> {
  const snarkjs = await import("snarkjs");
  const wtnsFile = path.join(
    os.tmpdir(),
    `pqid-${Date.now()}-${randomBytes(4).toString("hex")}.wtns`
  );
  const t0 = process.hrtime.bigint();
  try {
    await snarkjs.wtns.calculate(input, wasmFile, wtnsFile);
  } catch (e) {
    fs.rmSync(wtnsFile, { force: true }); // a refused witness may leave a partial file
    throw e;
  }
  const witnessMs = Number(process.hrtime.bigint() - t0) / 1e6;
  return { wtnsFile, witnessMs };
}

/**
 * snarkJS witness + proof with the witness held in memory only, so the
 * holder secret, credID and path never reach the disk. Zeroing the buffer
 * afterwards is best-effort: snarkjs and the wasm runtime keep their own
 * transient copies until garbage collection.
 */
async function proveSnarkjsInMemory(
  input: CircuitInput,
  artifacts: CircuitArtifacts
): Promise<ProveResult> {
  const snarkjs = await import("snarkjs");
  const wtns: { type: "mem"; data?: Uint8Array } = { type: "mem" };
  const t0 = process.hrtime.bigint();
  await snarkjs.wtns.calculate(input, artifacts.wasm, wtns);
  const witnessMs = Number(process.hrtime.bigint() - t0) / 1e6;
  if (!wtns.data) throw new Error("snarkjs produced no in-memory witness");
  try {
    const t1 = process.hrtime.bigint();
    const { proof, publicSignals } = await snarkjs.groth16.prove(artifacts.zkey, wtns);
    const proveMs = Number(process.hrtime.bigint() - t1) / 1e6;
    return {
      backend: "snarkjs",
      proof,
      publicSignals,
      zkeySha256: sha256File(artifacts.zkey),
      witnessSha256: sha256Bytes(wtns.data),
      timings: { witnessMs, proveMs, proveIsSubprocessWall: false },
      proofJsonBytes: Buffer.byteLength(JSON.stringify(proof), "utf8"),
    };
  } finally {
    wtns.data.fill(0);
  }
}

/** snarkJS 0.7.4 JS prover on a prepared witness file. */
export async function proveSnarkjsOnWitness(
  wtnsFile: string,
  zkeyFile: string = ZKEY_FILE
): Promise<ProveResult> {
  const snarkjs = await import("snarkjs");
  const t0 = process.hrtime.bigint();
  const { proof, publicSignals } = await snarkjs.groth16.prove(zkeyFile, wtnsFile);
  const proveMs = Number(process.hrtime.bigint() - t0) / 1e6;
  return {
    backend: "snarkjs",
    proof,
    publicSignals,
    zkeySha256: sha256File(zkeyFile),
    witnessSha256: sha256File(wtnsFile),
    timings: { proveMs, proveIsSubprocessWall: false },
    proofJsonBytes: Buffer.byteLength(JSON.stringify(proof), "utf8"),
  };
}

/** rapidsnark v0.0.8 native prover (inside WSL) on the same zkey + witness. */
export function proveRapidsnarkOnWitness(
  wtnsFile: string,
  zkeyFile: string = ZKEY_FILE
): ProveResult {
  const tag = randomBytes(4).toString("hex");
  const proofFile = path.join(os.tmpdir(), `pqid-proof-${tag}.json`);
  const publicFile = path.join(os.tmpdir(), `pqid-public-${tag}.json`);
  const cmd = [
    RAPIDSNARK_PROVER_WSL,
    toWslPath(zkeyFile),
    toWslPath(wtnsFile),
    toWslPath(proofFile),
    toWslPath(publicFile),
  ].join(" ");

  const t0 = process.hrtime.bigint();
  const res = spawnSync("wsl", ["-u", "root", "-e", "bash", "-c", cmd], {
    encoding: "utf8",
  });
  const proveMs = Number(process.hrtime.bigint() - t0) / 1e6;
  if (res.status !== 0) {
    throw new Error(`rapidsnark prover failed (${res.status}): ${res.stderr} ${res.stdout}`);
  }
  const proof = JSON.parse(fs.readFileSync(proofFile, "utf8")) as Groth16Proof;
  const publicSignals = JSON.parse(
    fs.readFileSync(publicFile, "utf8")
  ) as PublicSignals;
  const proofJsonBytes = fs.statSync(proofFile).size;
  fs.rmSync(proofFile);
  fs.rmSync(publicFile);
  return {
    backend: "rapidsnark",
    proof,
    publicSignals,
    zkeySha256: sha256File(zkeyFile),
    witnessSha256: sha256File(wtnsFile),
    timings: { proveMs, proveIsSubprocessWall: true },
    proofJsonBytes,
  };
}

/**
 * Full pipeline: witness + prove with the chosen backend. snarkJS keeps the
 * witness in memory; rapidsnark (a separate process) needs a temp file.
 */
export async function prove(
  input: CircuitInput,
  backend: ProverBackend,
  artifacts: CircuitArtifacts = V2_ARTIFACTS
): Promise<ProveResult> {
  if (backend === "snarkjs") return proveSnarkjsInMemory(input, artifacts);
  const { wtnsFile, witnessMs } = await computeWitness(input, artifacts.wasm);
  try {
    const result = proveRapidsnarkOnWitness(wtnsFile, artifacts.zkey);
    result.timings.witnessMs = witnessMs;
    return result;
  } finally {
    fs.rmSync(wtnsFile, { force: true });
  }
}

/**
 * Dual-prover run on byte-identical zkey + witness (Table V integrity crux):
 * computes ONE witness, proves with both backends, and asserts SHA-256
 * equality of the inputs both provers consumed.
 */
export async function proveBoth(
  input: CircuitInput,
  artifacts: CircuitArtifacts = V2_ARTIFACTS
): Promise<{
  snarkjs: ProveResult;
  rapidsnark: ProveResult;
  witnessMs: number;
  inputsIdentical: true;
}> {
  const { wtnsFile, witnessMs } = await computeWitness(input, artifacts.wasm);
  try {
    const sj = await proveSnarkjsOnWitness(wtnsFile, artifacts.zkey);
    const rs = proveRapidsnarkOnWitness(wtnsFile, artifacts.zkey);
    if (sj.zkeySha256 !== rs.zkeySha256 || sj.witnessSha256 !== rs.witnessSha256) {
      throw new Error("prover inputs diverged — zkey/witness SHA-256 mismatch");
    }
    return { snarkjs: sj, rapidsnark: rs, witnessMs, inputsIdentical: true };
  } finally {
    fs.rmSync(wtnsFile, { force: true });
  }
}
