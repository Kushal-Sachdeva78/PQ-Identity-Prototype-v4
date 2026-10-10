import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import type { Groth16Proof, PublicSignals } from "snarkjs";
import { sha256File, sha256Bytes } from "@pqid/common/hash";
import { WASM_V4, ZKEY_V4, VKEY_V4, KEY_LABEL_V4, rapidsnarkBinary } from "./paths.ts";
import type { CircuitInputV4 } from "./witness.ts";

/**
 * v4 Groth16 proving and verification (circuit credential_auth_v4, dev key).
 *
 * - snarkJS: the wallet path keeps the witness in memory (as v3's proveSnarkjsInMemory).
 * - rapidsnark: only when PQID_RAPIDSNARK names a native binary; it is spawned directly
 *   with an argv array (no shell, never wsl.exe). On this Windows host it is unavailable
 *   (DECISIONS D-001, D-002) and the functions throw.
 */

export type ProverBackendV4 = "snarkjs" | "rapidsnark";

export interface CircuitArtifactsV4 {
  wasm: string;
  zkey: string;
  /** Key label recorded with every result ("dev" until the ceremony key exists). */
  keyLabel: string;
}
export const V4_DEV_ARTIFACTS: CircuitArtifactsV4 = { wasm: WASM_V4, zkey: ZKEY_V4, keyLabel: KEY_LABEL_V4 };

export interface ProveResultV4 {
  backend: ProverBackendV4;
  keyLabel: string;
  proof: Groth16Proof;
  publicSignals: PublicSignals;
  /** SHA-256 of the proving key actually used. */
  zkeySha256: string;
  /** SHA-256 of the witness actually used. */
  witnessSha256: string;
  timings: {
    witnessMs?: number;
    proveMs: number;
    /** rapidsnark: subprocess wall time incl. process start and file I/O. */
    proveIsSubprocessWall: boolean;
  };
  proofJsonBytes: number;
}

export const RAPIDSNARK_UNAVAILABLE = "rapidsnark unavailable on this host (needs WSL2/Linux build)";

function ms(t0: bigint): number {
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

function tmpName(prefix: string, ext: string): string {
  return path.join(os.tmpdir(), `${prefix}-${Date.now()}-${randomBytes(6).toString("hex")}${ext}`);
}

/**
 * Witness for `input` in a fresh temp .wtns file (rapidsnark, benchmarks and attacker
 * routes). The file holds the holder's secrets: the CALLER deletes it.
 */
export async function computeWitnessV4(
  input: CircuitInputV4,
  wasmFile: string = WASM_V4
): Promise<{ wtnsFile: string; witnessMs: number }> {
  const snarkjs = await import("snarkjs");
  const wtnsFile = tmpName("pqid-v4", ".wtns");
  const t0 = process.hrtime.bigint();
  try {
    await snarkjs.wtns.calculate(input, wasmFile, wtnsFile);
  } catch (e) {
    fs.rmSync(wtnsFile, { force: true }); // a refused witness may leave a partial file
    throw e;
  }
  return { wtnsFile, witnessMs: ms(t0) };
}

/**
 * snarkJS witness + proof with the witness in memory only, so the holder secret, credID
 * and paths never reach the disk. Zeroing the buffer is best-effort: snarkjs and the wasm
 * runtime keep transient copies until garbage collection.
 */
async function proveSnarkjsInMemory(input: CircuitInputV4, artifacts: CircuitArtifactsV4): Promise<ProveResultV4> {
  const snarkjs = await import("snarkjs");
  const wtns: { type: "mem"; data?: Uint8Array } = { type: "mem" };
  const t0 = process.hrtime.bigint();
  await snarkjs.wtns.calculate(input, artifacts.wasm, wtns);
  const witnessMs = ms(t0);
  if (!wtns.data) throw new Error("snarkjs produced no in-memory witness");
  try {
    const t1 = process.hrtime.bigint();
    const { proof, publicSignals } = await snarkjs.groth16.prove(artifacts.zkey, wtns);
    const proveMs = ms(t1);
    return {
      backend: "snarkjs",
      keyLabel: artifacts.keyLabel,
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

/** snarkJS 0.7.4 prover on a prepared witness file. */
export async function proveSnarkjsOnWitness(
  wtnsFile: string,
  zkeyFile: string = ZKEY_V4,
  keyLabel: string = KEY_LABEL_V4
): Promise<ProveResultV4> {
  const snarkjs = await import("snarkjs");
  const t0 = process.hrtime.bigint();
  const { proof, publicSignals } = await snarkjs.groth16.prove(zkeyFile, wtnsFile);
  const proveMs = ms(t0);
  return {
    backend: "snarkjs",
    keyLabel,
    proof,
    publicSignals,
    zkeySha256: sha256File(zkeyFile),
    witnessSha256: sha256File(wtnsFile),
    timings: { proveMs, proveIsSubprocessWall: false },
    proofJsonBytes: Buffer.byteLength(JSON.stringify(proof), "utf8"),
  };
}

/** The rapidsnark binary to run, or a thrown RAPIDSNARK_UNAVAILABLE. */
function requireRapidsnark(): string {
  const bin = rapidsnarkBinary();
  if (!bin) throw new Error(RAPIDSNARK_UNAVAILABLE);
  if (/^wsl(\.exe)?$/i.test(path.basename(bin))) {
    throw new Error("PQID_RAPIDSNARK must name a native prover binary, not wsl.exe");
  }
  if (!fs.existsSync(bin)) throw new Error(`${RAPIDSNARK_UNAVAILABLE}: PQID_RAPIDSNARK does not exist`);
  return bin;
}

/**
 * rapidsnark native prover on the same zkey + witness. Spawned directly with argv
 * (`prover <zkey> <wtns> <proof.json> <public.json>`), no shell.
 */
export function proveRapidsnarkOnWitness(
  wtnsFile: string,
  zkeyFile: string = ZKEY_V4,
  keyLabel: string = KEY_LABEL_V4
): ProveResultV4 {
  const bin = requireRapidsnark();
  const proofFile = tmpName("pqid-v4-proof", ".json");
  const publicFile = tmpName("pqid-v4-public", ".json");
  try {
    const t0 = process.hrtime.bigint();
    const res = spawnSync(bin, [zkeyFile, wtnsFile, proofFile, publicFile], { encoding: "utf8", shell: false });
    const proveMs = ms(t0);
    if (res.error) throw res.error;
    if (res.status !== 0) throw new Error(`rapidsnark prover failed (${res.status}): ${res.stderr} ${res.stdout}`);
    const proof = JSON.parse(fs.readFileSync(proofFile, "utf8")) as Groth16Proof;
    const publicSignals = JSON.parse(fs.readFileSync(publicFile, "utf8")) as PublicSignals;
    return {
      backend: "rapidsnark",
      keyLabel,
      proof,
      publicSignals,
      zkeySha256: sha256File(zkeyFile),
      witnessSha256: sha256File(wtnsFile),
      timings: { proveMs, proveIsSubprocessWall: true },
      proofJsonBytes: fs.statSync(proofFile).size,
    };
  } finally {
    fs.rmSync(proofFile, { force: true });
    fs.rmSync(publicFile, { force: true });
  }
}

/**
 * Witness + proof with the chosen backend. snarkJS keeps the witness in memory;
 * rapidsnark (a separate process) needs a temp file, deleted here.
 */
export async function proveV4(
  input: CircuitInputV4,
  backend: ProverBackendV4 = "snarkjs",
  artifacts: CircuitArtifactsV4 = V4_DEV_ARTIFACTS
): Promise<ProveResultV4> {
  if (backend === "snarkjs") return proveSnarkjsInMemory(input, artifacts);
  requireRapidsnark(); // fail before writing any witness file
  const { wtnsFile, witnessMs } = await computeWitnessV4(input, artifacts.wasm);
  try {
    const result = proveRapidsnarkOnWitness(wtnsFile, artifacts.zkey, artifacts.keyLabel);
    result.timings.witnessMs = witnessMs;
    return result;
  } finally {
    fs.rmSync(wtnsFile, { force: true });
  }
}

/**
 * Both provers on ONE witness and ONE zkey, asserting that both consumed byte-identical
 * inputs (as v3's proveBoth). Throws RAPIDSNARK_UNAVAILABLE on hosts without rapidsnark.
 */
export async function proveBothV4(
  input: CircuitInputV4,
  artifacts: CircuitArtifactsV4 = V4_DEV_ARTIFACTS
): Promise<{ snarkjs: ProveResultV4; rapidsnark: ProveResultV4; witnessMs: number; inputsIdentical: true }> {
  requireRapidsnark();
  const { wtnsFile, witnessMs } = await computeWitnessV4(input, artifacts.wasm);
  try {
    const sj = await proveSnarkjsOnWitness(wtnsFile, artifacts.zkey, artifacts.keyLabel);
    const rs = proveRapidsnarkOnWitness(wtnsFile, artifacts.zkey, artifacts.keyLabel);
    if (sj.zkeySha256 !== rs.zkeySha256 || sj.witnessSha256 !== rs.witnessSha256) {
      throw new Error("prover inputs diverged: zkey/witness SHA-256 mismatch");
    }
    return { snarkjs: sj, rapidsnark: rs, witnessMs, inputsIdentical: true };
  } finally {
    fs.rmSync(wtnsFile, { force: true });
  }
}

/** The v4 dev verification key (setup/out/v4/verification_key_dev.json). */
export function loadVkeyV4(file: string = VKEY_V4): unknown {
  return JSON.parse(fs.readFileSync(file, "utf8")) as unknown;
}

/**
 * Groth16 verification (snarkjs). Returns false (never throws) on malformed input. The
 * number of public signals must equal the key's nPublic: snarkjs itself would accept a
 * shorter list (the missing inputs then count as 0).
 */
export async function verifyV4(vkey: unknown, publicSignals: PublicSignals, proof: Groth16Proof): Promise<boolean> {
  const snarkjs = await import("snarkjs");
  const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined, debug: () => undefined };
  const nPublic = (vkey as { nPublic?: unknown } | null)?.nPublic;
  if (typeof nPublic !== "number" || !Array.isArray(publicSignals) || publicSignals.length !== nPublic) return false;
  if (!publicSignals.every((s) => typeof s === "string" && /^(0|[1-9][0-9]*)$/.test(s))) return false;
  try {
    return await snarkjs.groth16.verify(vkey, publicSignals, proof, quiet);
  } catch {
    return false;
  }
}
