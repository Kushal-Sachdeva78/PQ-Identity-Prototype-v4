import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { sha256File } from "@pqid/common/hash";
import { hostMeta } from "@pqid/common/meta";
import {
  REPO_ROOT,
  CIRCUIT_V4_SRC,
  CIRCUIT_V4_LIB,
  BUILD_DIR_V4,
  R1CS_V4,
  WASM_V4,
  SYM_V4,
  CIRCUIT_INFO_V4,
  circomBinary,
} from "@pqid/v4/paths";

/**
 * Compile circuits/credential_auth_v4.circom (V4_DESIGN section 2) with circom 2.2.3.
 *
 * - The build used by the dev key and every v4 prover: --O2 --r1cs --wasm --sym --inspect
 *   into circuits/build/v4.
 * - A second compile at --O1 (r1cs only, temp dir, deleted afterwards) records the
 *   constraint count without full linear simplification (TASKS T9).
 *
 * Writes circuits/build/v4/circuit_info.json: O2 and O1 counts, public/private input
 * counts, the r1cs SHA-256, the 2^15 ptau fit and the constraint groups found by scanning
 * the sources for "// @@G" markers. The record holds no absolute paths and no ANSI codes.
 *
 * Usage: tsx setup/build_circuit_v4.ts
 */

const esc = String.fromCharCode(27);

/** Strip ANSI colour codes and this machine's absolute paths (as v3's build script). */
function clean(s: string): string {
  const tmp = os.tmpdir();
  return s
    .split(esc)
    .map((part, i) => (i === 0 ? part : part.replace(/^\[[0-9;]*m/, "")))
    .join("")
    .split(REPO_ROOT)
    .join("<repo>")
    .split(REPO_ROOT.replace(/\\/g, "/"))
    .join("<repo>")
    .split(tmp)
    .join("<tmp>")
    .split(tmp.replace(/\\/g, "/"))
    .join("<tmp>");
}

function rel(p: string): string {
  return path.relative(REPO_ROOT, p).split(path.sep).join("/");
}

interface CompileRun {
  stdout: string;
  stderr: string;
  wallMs: number;
}

function runCircom(args: string[]): CompileRun {
  const bin = circomBinary();
  console.log(`[circom] ${path.basename(bin)} ${args.map((a) => clean(a)).join(" ")}`);
  const t0 = process.hrtime.bigint();
  const res = spawnSync(bin, args, { cwd: REPO_ROOT, encoding: "utf8", maxBuffer: 256 * 1024 * 1024 });
  const wallMs = Number(process.hrtime.bigint() - t0) / 1e6;
  if (res.error) throw res.error;
  if (res.status !== 0) {
    throw new Error(`circom failed (exit ${res.status}):\n${clean(res.stdout ?? "")}\n${clean(res.stderr ?? "")}`);
  }
  return { stdout: res.stdout ?? "", stderr: res.stderr ?? "", wallMs };
}

/** Parse circom's summary lines ("non-linear constraints: N", ...). */
function parseSummary(stdout: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const line of clean(stdout).split(/\r?\n/)) {
    const m = /^(template instances|non-linear constraints|linear constraints|public inputs|private inputs|public outputs|wires|labels):\s*(\d+)/.exec(line.trim());
    if (m) out[m[1] as string] = Number(m[2]);
  }
  return out;
}

/** Constraint-group markers ("// @@Gxx_name") in a circuit source, in file order. */
function constraintGroupsIn(sourceFile: string): string[] {
  const src = fs.readFileSync(sourceFile, "utf8");
  const groups: string[] = [];
  const re = /^\s*\/\/\s*@@(G\d+_[A-Za-z0-9_]+)\s*$/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) groups.push(m[1] as string);
  return groups;
}

function circomVersion(): string {
  const res = spawnSync(circomBinary(), ["--version"], { encoding: "utf8" });
  return (res.stdout ?? "").trim() || "unknown";
}

async function main(): Promise<void> {
  const snarkjs = await import("snarkjs");
  fs.mkdirSync(BUILD_DIR_V4, { recursive: true });
  const sourceSha256 = (): Record<string, string> => ({
    [rel(CIRCUIT_V4_SRC)]: sha256File(CIRCUIT_V4_SRC),
    [rel(CIRCUIT_V4_LIB)]: sha256File(CIRCUIT_V4_LIB),
  });
  const sourcesBefore = sourceSha256();

  // ---- O2 build (the one every v4 artifact uses) ----
  const o2 = runCircom([CIRCUIT_V4_SRC, "--O2", "--r1cs", "--wasm", "--sym", "--inspect", "-o", BUILD_DIR_V4]);
  console.log(clean(o2.stdout));
  if (o2.stderr.trim()) console.log(clean(o2.stderr));
  for (const f of [R1CS_V4, WASM_V4, SYM_V4]) {
    if (!fs.existsSync(f)) throw new Error(`circom did not write ${rel(f)}`);
  }
  const infoO2 = await snarkjs.r1cs.info(R1CS_V4);
  if (JSON.stringify(sourceSha256()) !== JSON.stringify(sourcesBefore)) {
    throw new Error("a circuit source changed during the build; run the build again");
  }

  // ---- O1 build (constraint count only; temp dir, removed afterwards) ----
  const tmpDir = path.join(os.tmpdir(), `pqid-v4-o1-${randomBytes(4).toString("hex")}`);
  fs.mkdirSync(tmpDir, { recursive: true });
  let infoO1: Awaited<ReturnType<typeof snarkjs.r1cs.info>>;
  let o1: CompileRun;
  try {
    o1 = runCircom([CIRCUIT_V4_SRC, "--O1", "--r1cs", "-o", tmpDir]);
    infoO1 = await snarkjs.r1cs.info(path.join(tmpDir, "credential_auth_v4.r1cs"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  // ---- --inspect findings (circom's own static warnings on the O2 build) ----
  const inspectText = clean(o2.stdout + "\n" + o2.stderr);
  const inspectWarnings = inspectText.split(/\r?\n/).filter((l) => /^warning\[/i.test(l.trim())).length;

  const nPublic = infoO2.nPubInputs + infoO2.nOutputs;
  const ptauNeeded = infoO2.nConstraints + nPublic + 1;
  const groups = {
    [rel(CIRCUIT_V4_SRC)]: constraintGroupsIn(CIRCUIT_V4_SRC),
    [rel(CIRCUIT_V4_LIB)]: constraintGroupsIn(CIRCUIT_V4_LIB),
  };

  const circuitInfo = {
    schema: "pqid/v4-circuit-info/v1",
    source: rel(CIRCUIT_V4_SRC),
    includes: [rel(CIRCUIT_V4_LIB), "node_modules/circomlib/circuits (circomlib 2.0.5)"],
    sourceSha256: sourcesBefore,
    compiler: circomVersion(),
    curve: "BN254",
    optimization: "--O2",
    nConstraints: infoO2.nConstraints,
    nWires: infoO2.nVars,
    nPubInputs: infoO2.nPubInputs,
    nPrvInputs: infoO2.nPrvInputs,
    nOutputs: infoO2.nOutputs,
    nLabels: Number(infoO2.nLabels),
    r1csSha256: sha256File(R1CS_V4),
    wasmSha256: sha256File(WASM_V4),
    symSha256: sha256File(SYM_V4),
    circomSummaryO2: parseSummary(o2.stdout),
    compileWallMsO2: Math.round(o2.wallMs),
    o1: {
      optimization: "--O1",
      nConstraints: infoO1.nConstraints,
      nWires: infoO1.nVars,
      circomSummary: parseSummary(o1.stdout),
      note: "compiled to a temp dir only to record the count (TASKS T9); the O1 build is not used",
    },
    ptau: {
      power: 15,
      capacity: 2 ** 15,
      needed: ptauNeeded,
      fits: ptauNeeded <= 2 ** 15,
      rule: "nConstraints + nPublic + 1 <= 2^power (snarkjs newZKey)",
    },
    constraintGroups: groups,
    inspect: {
      flag: "--inspect",
      warningLines: inspectWarnings,
    },
    circomStdoutO2: clean(o2.stdout),
    host: hostMeta(),
  };
  fs.writeFileSync(CIRCUIT_INFO_V4, JSON.stringify(circuitInfo, null, 2) + "\n");
  console.log(
    `[circom] v4 --O2 constraints=${infoO2.nConstraints} wires=${infoO2.nVars} public=${infoO2.nPubInputs} ` +
      `private=${infoO2.nPrvInputs}; --O1 constraints=${infoO1.nConstraints}; ptau 2^15 needed=${ptauNeeded} ` +
      `(${ptauNeeded <= 2 ** 15 ? "fits" : "DOES NOT FIT"}) -> ${rel(CIRCUIT_INFO_V4)}`
  );
  process.exit(0); // snarkjs keeps worker threads alive
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
