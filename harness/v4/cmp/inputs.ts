import fs from "node:fs";
import path from "node:path";
import { abs, flag, opt, rel, sanitize, sha256FileHex, sha256Hex, utcNow, writeJson } from "../bench/lib.ts";
import { buildEddsaFixture, EDDSA_FIXTURE } from "./eddsa_fixture.ts";
import { WALLET_GENERATOR, walletLeaves, walletRevKeys } from "./wallet_data.ts";
import { holdWork } from "./runner.ts";
import {
  BENCH_LOCK_REL,
  CIRCUITS,
  WALLET_CONDITIONS,
  checkCircuitArtifacts,
  circuitSpecs,
  cmpInputsDir,
  cmpLockFile,
  cmpRoot,
  parseList,
  v4KeyFromArgs,
  walletSize,
  type Circuit,
  type CircuitArtifacts,
  type CircuitSpec,
  type WalletCondition,
} from "./spec.ts";

/**
 * Inputs of the cmp series (docs/v4/CMP.md, "Inputs"), pinned once in
 * results/v4/cmp/inputs/inputs_cmp.lock.json (smoke: results/v4/cmp/_smoke/inputs/):
 *   v2, v2o2   results/v4/bench/inputs/v2_input.json (Phase D pin, re-verified)
 *   v3         results/v4/bench/inputs/v3_input.json
 *   v4         results/v4/bench/inputs/v4_input.json (key-independent; re-proved with the v4 key
 *              given by --v4-zkey/--v4-vkey/--v4-key-label/--v4-pins, default the dev key)
 *   eddsa      results/v4/cmp/inputs/eddsa_input.json from harness/v4/cmp/eddsa_fixture.ts
 *   wallet1e5, wallet1e6: the rebuilt issuance and revocation roots of the deterministic data
 * Each circuit gets one untimed reference proof that must verify and give the expected public
 * signals (the Phase D pin for v2/v2o2/v3/v4, the fixture's for eddsa).
 *
 *   node --import tsx harness/v4/cmp/inputs.ts [--smoke [--smoke-no-marker]] [--check] [--force] [--conditions ...] [v4 key flags]
 *   default : write missing entries; an identical rebuild is kept; a DIFFERENT existing entry is
 *             replaced only with --force (for example v4 after the ceremony; record why)
 *   --check : rebuild in memory and compare with the lock (exit 1 on any difference)
 * Holds results/v4/BUSY (untimed CPU-heavy work, D-034), also with --smoke (plus the smoke lock);
 * --smoke --smoke-no-marker holds only the smoke lock.
 */

export interface CmpInputEntry {
  condition: Circuit;
  file: string;
  inputSha256: string;
  publicSignals: string[];
  publicSignalsSha256: string;
  source: string;
  keyLabel: string;
  artifacts: CircuitArtifacts;
  referenceProofVerified: boolean;
  crossCheck: string;
}

export interface WalletLockEntry {
  condition: WalletCondition;
  credentials: number;
  revocations: number;
  issuanceDepth: number;
  revocationDepth: number;
  generator: typeof WALLET_GENERATOR;
  issuanceRoot: string;
  revocationRoot: string;
  /** Untimed, one in-process build (informational only, never a result). */
  buildWallMs: number;
}

export interface CmpLock {
  schema: "pqid/v4-cmp-inputs/v1";
  createdUtc: string;
  generator: "harness/v4/cmp/inputs.ts";
  smoke: boolean;
  benchLock: { path: string; sha256: string };
  circuits: Partial<Record<Circuit, CmpInputEntry>>;
  wallet: Partial<Record<WalletCondition, WalletLockEntry>>;
}

interface BenchLockEntry {
  file: string;
  inputSha256: string;
  publicSignals: string[];
  artifacts: Record<"wasm" | "zkey" | "vkey", { sha256: string }>;
}

function readBenchLock(): Record<"v2" | "v3" | "v4", BenchLockEntry> {
  const lock = JSON.parse(fs.readFileSync(abs(BENCH_LOCK_REL), "utf8")) as { versions: Record<string, BenchLockEntry> };
  const out = {} as Record<"v2" | "v3" | "v4", BenchLockEntry>;
  for (const v of ["v2", "v3", "v4"] as const) {
    const e = lock.versions[v];
    if (!e) throw new Error(`${BENCH_LOCK_REL} has no ${v} entry`);
    out[v] = e;
  }
  return out;
}

async function referenceProof(s: CircuitSpec, input: Record<string, unknown>): Promise<{ publicSignals: string[]; verified: boolean }> {
  const snarkjs = await import("snarkjs");
  const wtns: { type: "mem"; data?: Uint8Array } = { type: "mem" };
  await snarkjs.wtns.calculate(input, abs(s.wasm.rel), wtns);
  const { proof, publicSignals } = await snarkjs.groth16.prove(abs(s.zkey.rel), wtns);
  const vkey = JSON.parse(fs.readFileSync(abs(s.vkey.rel), "utf8")) as unknown;
  return { publicSignals, verified: await snarkjs.groth16.verify(vkey, publicSignals, proof) };
}

/** Build (in memory) the lock entry of one circuit; `eddsaFile` is where its input lives. */
export async function buildCircuitEntry(s: CircuitSpec, eddsaFile: string): Promise<{ entry: CmpInputEntry; text: string | null }> {
  const artifacts = checkCircuitArtifacts(s);
  let input: Record<string, unknown>;
  let file: string;
  let expected: string[];
  let crossCheck: string;
  let text: string | null = null;
  if (s.input.kind === "bench-lock") {
    const b = readBenchLock()[s.input.version];
    file = b.file;
    input = JSON.parse(fs.readFileSync(abs(b.file), "utf8")) as Record<string, unknown>;
    if (sha256Hex(JSON.stringify(input)) !== b.inputSha256) throw new Error(`${s.circuit}: ${b.file} does not match its pin in ${BENCH_LOCK_REL}`);
    expected = b.publicSignals;
    if (s.circuit === "v2" || s.circuit === "v3") {
      for (const k of ["wasm", "zkey", "vkey"] as const) {
        if (artifacts[k].sha256 !== b.artifacts[k].sha256) throw new Error(`${s.circuit} ${k} differs from the artifact pinned with its input in ${BENCH_LOCK_REL}`);
      }
      crossCheck = `reference proof gives the public signals pinned for ${s.circuit} in ${BENCH_LOCK_REL}; artifacts equal that lock's`;
    } else if (s.circuit === "v4") {
      if (artifacts.wasm.sha256 !== b.artifacts.wasm.sha256) throw new Error(`v4 wasm differs from ${BENCH_LOCK_REL}`);
      crossCheck = `reference proof with the ${s.keyLabel} gives the public signals pinned for v4 in ${BENCH_LOCK_REL} (they depend on the input only)`;
    } else {
      crossCheck = `reference proof of the --O2 build gives the public signals pinned for v2 in ${BENCH_LOCK_REL}`;
    }
  } else {
    const fx = await buildEddsaFixture();
    if (!fx.signatureVerifies) throw new Error("eddsa fixture: the issuer signature does not verify off-circuit");
    input = fx.input;
    expected = fx.publicSignals;
    file = eddsaFile;
    text = JSON.stringify(input);
    crossCheck = "issuer signature verifies off-circuit; reference proof gives baselines/eddsa/lib.ts expectedPublicSignals()";
  }
  const ref = await referenceProof(s, input);
  if (!ref.verified) throw new Error(`${s.circuit}: the reference proof on the fixed input does not verify`);
  if (JSON.stringify(ref.publicSignals) !== JSON.stringify(expected)) throw new Error(`${s.circuit}: reference proof public signals differ from the expected ones`);
  return {
    entry: {
      condition: s.circuit,
      file,
      inputSha256: sha256Hex(JSON.stringify(input)),
      publicSignals: ref.publicSignals,
      publicSignalsSha256: sha256Hex(JSON.stringify(ref.publicSignals)),
      source: s.inputSource,
      keyLabel: s.keyLabel,
      artifacts,
      referenceProofVerified: true,
      crossCheck,
    },
    text,
  };
}

/** Rebuild the two published trees from the deterministic data (untimed). */
export async function buildWalletEntry(c: WalletCondition, smoke: boolean): Promise<WalletLockEntry> {
  const { IssuanceSnapshot } = await import("@pqid/v4/published");
  const { IndexedMerkleTree } = await import("@pqid/v4/imt");
  const k = await import("@pqid/v4/constants");
  const size = walletSize(c, smoke);
  const t0 = process.hrtime.bigint();
  const iss = await IssuanceSnapshot.build(walletLeaves(size.credentials), k.ISSUANCE_DEPTH);
  const rev = await IndexedMerkleTree.bulkBuild(walletRevKeys(size.revocations, k.IMT_MAX), k.REV_DEPTH);
  return {
    condition: c,
    credentials: size.credentials,
    revocations: size.revocations,
    issuanceDepth: k.ISSUANCE_DEPTH,
    revocationDepth: k.REV_DEPTH,
    generator: WALLET_GENERATOR,
    issuanceRoot: iss.root().toString(),
    revocationRoot: rev.root().toString(),
    buildWallMs: Math.round(Number(process.hrtime.bigint() - t0) / 1e6),
  };
}

function sameCircuitEntry(a: CmpInputEntry | undefined, b: CmpInputEntry): boolean {
  return (
    a !== undefined &&
    a.file === b.file &&
    a.inputSha256 === b.inputSha256 &&
    a.publicSignalsSha256 === b.publicSignalsSha256 &&
    a.keyLabel === b.keyLabel &&
    (["wasm", "zkey", "vkey"] as const).every((k) => a.artifacts[k].sha256 === b.artifacts[k].sha256)
  );
}

function sameWalletEntry(a: WalletLockEntry | undefined, b: WalletLockEntry): boolean {
  return (
    a !== undefined &&
    a.credentials === b.credentials &&
    a.revocations === b.revocations &&
    a.issuanceRoot === b.issuanceRoot &&
    a.revocationRoot === b.revocationRoot &&
    JSON.stringify(a.generator) === JSON.stringify(b.generator)
  );
}

export function readCmpLock(smoke: boolean): CmpLock {
  const f = cmpLockFile(smoke);
  if (!fs.existsSync(f)) throw new Error(`${rel(f)} missing: run \`node --import tsx harness/v4/cmp/inputs.ts${smoke ? " --smoke" : ""}\` first`);
  return JSON.parse(fs.readFileSync(f, "utf8")) as CmpLock;
}

type Cond = Circuit | WalletCondition;
const ALL: readonly Cond[] = [...CIRCUITS, ...WALLET_CONDITIONS];

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const smoke = flag(argv, "smoke");
  const check = flag(argv, "check");
  const force = flag(argv, "force");
  const conds = parseList(opt(argv, "conditions"), ALL, "--conditions") ?? [...ALL];
  const specs = circuitSpecs(v4KeyFromArgs(argv));
  const lockFile = cmpLockFile(smoke);
  const eddsaFile = rel(path.join(cmpInputsDir(smoke), "eddsa_input.json"));

  const smokeNoMarker = flag(argv, "smoke-no-marker");
  if (smokeNoMarker && !smoke) throw new Error("--smoke-no-marker goes with --smoke");
  const hold = holdWork({ kind: "BUSY", smoke, smokeNoMarker, smokeRoot: cmpRoot(true), campaign: check ? "cmp_inputs_check" : "cmp_inputs", runner: "harness/v4/cmp/inputs.ts", argv, note: "untimed: reference proofs and wallet roots (cmp series)" });
  try {
    const existing: CmpLock | null = fs.existsSync(lockFile) ? (JSON.parse(fs.readFileSync(lockFile, "utf8")) as CmpLock) : null;
    if (check && !existing) throw new Error(`--check: ${rel(lockFile)} does not exist`);
    const lock: CmpLock = existing ?? {
      schema: "pqid/v4-cmp-inputs/v1",
      createdUtc: utcNow(),
      generator: "harness/v4/cmp/inputs.ts",
      smoke,
      benchLock: { path: BENCH_LOCK_REL, sha256: sha256FileHex(abs(BENCH_LOCK_REL)) },
      circuits: {},
      wallet: {},
    };
    let mismatches = 0;
    let changed = false;
    for (const c of conds) {
      if (c === "wallet1e5" || c === "wallet1e6") {
        const e = await buildWalletEntry(c, smoke);
        const prev = existing?.wallet[c];
        const same = sameWalletEntry(prev, e);
        if (check) {
          console.log(`[cmp-inputs] ${c}: ${same ? "matches the pin" : "DIFFERS from the pin"} (${e.credentials} leaves, ${e.revocations} keys, ${e.buildWallMs} ms untimed)`);
          if (!same) mismatches++;
          continue;
        }
        if (prev && !same && !force) throw new Error(`${c}: a different pin exists in ${rel(lockFile)} (use --force only with a recorded reason)`);
        if (same && !force) {
          console.log(`[cmp-inputs] ${c}: already pinned, rebuild identical`);
          continue;
        }
        lock.wallet[c] = e;
        changed = true;
        console.log(`[cmp-inputs] ${c}: ${e.credentials} leaves, ${e.revocations} keys; roots pinned (${e.buildWallMs} ms untimed)`);
        continue;
      }
      const s = specs[c];
      const { entry, text } = await buildCircuitEntry(s, eddsaFile);
      const prev = existing?.circuits[c];
      const same = sameCircuitEntry(prev, entry);
      if (check) {
        console.log(`[cmp-inputs] ${c}: ${same ? "matches the pin" : "DIFFERS from the pin"} (${s.keyLabel}; input ${entry.inputSha256.slice(0, 16)}...)`);
        if (!same) mismatches++;
        if (text !== null && (!fs.existsSync(abs(entry.file)) || sha256Hex(JSON.stringify(JSON.parse(fs.readFileSync(abs(entry.file), "utf8")))) !== entry.inputSha256)) {
          console.log(`[cmp-inputs] ${c}: ${entry.file} on disk is missing or DIFFERS from the rebuilt input`);
          mismatches++;
        }
        continue;
      }
      if (prev && !same && !force) throw new Error(`${c}: a different pin exists in ${rel(lockFile)} (key or artifact changed? use --force only with a recorded reason)`);
      if (same && !force) {
        console.log(`[cmp-inputs] ${c}: already pinned, rebuild identical`);
        continue;
      }
      if (text !== null) {
        fs.mkdirSync(path.dirname(abs(entry.file)), { recursive: true });
        fs.writeFileSync(abs(entry.file), text + "\n");
      }
      lock.circuits[c] = entry;
      changed = true;
      console.log(`[cmp-inputs] ${c}: ${entry.file} (${s.keyLabel}) input ${entry.inputSha256.slice(0, 16)}..., reference proof verifies`);
    }
    if (check) {
      if (mismatches > 0) {
        console.error(`[cmp-inputs] --check: ${mismatches} difference(s) from ${rel(lockFile)}`);
        process.exitCode = 1;
      } else console.log(`[cmp-inputs] --check: every requested condition matches ${rel(lockFile)}`);
      return;
    }
    if (changed) {
      lock.benchLock = { path: BENCH_LOCK_REL, sha256: sha256FileHex(abs(BENCH_LOCK_REL)) };
      writeJson(lockFile, lock);
      console.log(`[cmp-inputs] lock -> ${rel(lockFile)}`);
    }
    console.log(`[cmp-inputs] eddsa fixture constants: ${JSON.stringify({ ...EDDSA_FIXTURE, holderSecret: String(EDDSA_FIXTURE.holderSecret), nonce: String(EDDSA_FIXTURE.nonce) })}`);
  } finally {
    hold.release();
  }
}

const self = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (self.endsWith(path.join("harness", "v4", "cmp", "inputs.ts"))) {
  main().then(
    () => process.exit(process.exitCode ?? 0),
    (e: unknown) => {
      console.error(`[cmp-inputs] ${sanitize(e instanceof Error ? e.message : String(e))}`);
      process.exit(1);
    }
  );
}
