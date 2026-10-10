/**
 * Baseline E2b build: compile circuits/baselines/eddsa_credential.circom and make a
 * THROWAWAY Groth16 key for timing and tests only ("throwaway baseline key").
 *
 *   npx tsx baselines/eddsa/build.ts            compile (--O2, plus an --O1 count) and make the key
 *   npx tsx baselines/eddsa/build.ts --no-key   compile only
 *
 * Outputs (all generated):
 *   circuits/build/baselines/eddsa_credential.{r1cs,sym}, eddsa_credential_js/, eddsa_credential_info.json
 *   setup/out/baselines/eddsa_credential_throwaway.zkey, _vkey.json, _setup.json
 *
 * Key: newZKey(r1cs, committed 2^15 ptau) then ONE contribution whose entropy (64 bytes of
 * OS randomness, plus snarkjs's own) exists only in this process's memory. No beacon, no
 * ceremony: it is not a production key and must never verify anything but this baseline.
 * The intermediate zkey goes to an OS temp dir and is deleted.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { sha256File } from "@pqid/common/hash";
import { hostMeta } from "@pqid/common/meta";
import {
  BUILD_DIR,
  CIRCUIT_INFO_FILE,
  CIRCUIT_SRC,
  KEY_LABEL,
  PINS_FILE,
  PTAU_FILE,
  R1CS_FILE,
  REPO_ROOT,
  SETUP_DIR,
  SETUP_RECORD_FILE,
  SYM_FILE,
  VKEY_FILE,
  WASM_FILE,
  ZKEY_FILE,
  circomBinary,
  rel,
} from "./lib.ts";

const PTAU_POWER = 15;

function clean(stdout: string): string {
  const esc = String.fromCharCode(27);
  return stdout
    .split(esc)
    .map((part, i) => (i === 0 ? part : part.replace(/^\[[0-9;]*m/, "")))
    .join("")
    .split(REPO_ROOT)
    .join("<repo>")
    .split(REPO_ROOT.replace(/\\/g, "/"))
    .join("<repo>")
    .split(os.tmpdir())
    .join("<tmp>")
    .split(os.tmpdir().replace(/\\/g, "/"))
    .join("<tmp>");
}

function summary(stdout: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of clean(stdout).split(/\r?\n/)) {
    const m = /^(template instances|non-linear constraints|linear constraints|public inputs|private inputs|public outputs|wires|labels): (.*)$/.exec(
      line.trim()
    );
    if (m) out[m[1] as string] = (m[2] as string).trim();
  }
  return out;
}

function circomVersion(): string {
  return execFileSync(circomBinary(), ["--version"], { encoding: "utf8" }).trim();
}

function pkgVersion(name: string): string {
  const p = path.join(REPO_ROOT, "node_modules", name, "package.json");
  return (JSON.parse(fs.readFileSync(p, "utf8")) as { version: string }).version;
}

async function main(): Promise<void> {
  const makeKey = !process.argv.includes("--no-key");
  const snarkjs = await import("snarkjs");
  fs.mkdirSync(BUILD_DIR, { recursive: true });

  // ---- --O2 build (the one used)
  const argsO2 = [CIRCUIT_SRC, "--O2", "--r1cs", "--wasm", "--sym", "-o", BUILD_DIR];
  const t0 = process.hrtime.bigint();
  const outO2 = execFileSync(circomBinary(), argsO2, { cwd: REPO_ROOT, encoding: "utf8" });
  const compileMsO2 = Number(process.hrtime.bigint() - t0) / 1e6;
  const infoO2 = await snarkjs.r1cs.info(R1CS_FILE);

  // ---- --O1 count only (temp dir, deleted)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-e2b-o1-"));
  let o1: Record<string, unknown>;
  try {
    const outO1 = execFileSync(circomBinary(), [CIRCUIT_SRC, "--O1", "--r1cs", "-o", tmp], {
      cwd: REPO_ROOT,
      encoding: "utf8",
    });
    const infoO1 = await snarkjs.r1cs.info(path.join(tmp, "eddsa_credential.r1cs"));
    o1 = {
      optimization: "--O1",
      nConstraints: infoO1.nConstraints,
      nWires: infoO1.nVars,
      circomSummary: summary(outO1),
      note: "compiled to an OS temp dir only to record the count; not used",
    };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  const nPublic = infoO2.nPubInputs + infoO2.nOutputs;
  const needed = infoO2.nConstraints + nPublic + 1;
  const info = {
    schema: "pqid/baseline-eddsa-circuit-info/v1",
    label: "baseline E2b (not PQ-Identity v4); [M] compiler counts",
    source: rel(CIRCUIT_SRC),
    sourceSha256: sha256File(CIRCUIT_SRC),
    includes: "node_modules/circomlib/circuits (poseidon, bitify, comparators, babyjub, eddsaposeidon)",
    compiler: circomVersion(),
    circomlib: pkgVersion("circomlib"),
    snarkjs: pkgVersion("snarkjs"),
    curve: "BN254",
    optimization: "--O2",
    nConstraints: infoO2.nConstraints,
    nWires: infoO2.nVars,
    nPubInputs: infoO2.nPubInputs,
    nPrvInputs: infoO2.nPrvInputs,
    nOutputs: infoO2.nOutputs,
    nLabels: Number(infoO2.nLabels),
    publicSignals: ["Ax", "Ay", "policyHash", "nonce"],
    circomSummaryO2: summary(outO2),
    compileWallMsO2: Math.round(compileMsO2),
    r1csSha256: sha256File(R1CS_FILE),
    wasmSha256: sha256File(WASM_FILE),
    symSha256: sha256File(SYM_FILE),
    o1,
    ptau: {
      file: rel(PTAU_FILE),
      power: PTAU_POWER,
      capacity: 2 ** PTAU_POWER,
      needed,
      fits: needed <= 2 ** PTAU_POWER,
      rule: "nConstraints + nPublic + 1 <= 2^power (snarkjs newZKey)",
    },
    host: hostMeta(),
  };
  fs.writeFileSync(CIRCUIT_INFO_FILE, JSON.stringify(info, null, 2) + "\n");
  console.log(`[e2b] --O2 constraints=${infoO2.nConstraints} wires=${infoO2.nVars} public=${nPublic}; --O1 constraints=${String(o1["nConstraints"])}`);
  console.log(`[e2b] ptau 2^${PTAU_POWER}: needed ${needed}, fits=${info.ptau.fits} -> ${rel(CIRCUIT_INFO_FILE)}`);

  if (!makeKey) {
    process.exit(0);
  }
  if (!info.ptau.fits) {
    console.error(`[e2b] circuit needs 2^${Math.ceil(Math.log2(needed))} ptau; not downloading anything`);
    process.exit(2);
  }

  // ---- ptau pin check (read-only use of setup/pins.json)
  const pins = JSON.parse(fs.readFileSync(PINS_FILE, "utf8")) as Record<string, { sha256?: string }>;
  const ptauSha = sha256File(PTAU_FILE);
  if (pins["powersOfTau28_hez_final_15.ptau"]?.sha256 !== ptauSha) {
    throw new Error("committed ptau does not match setup/pins.json; aborting");
  }

  // ---- throwaway key
  fs.mkdirSync(SETUP_DIR, { recursive: true });
  const tmpKey = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-e2b-key-"));
  const z0 = path.join(tmpKey, "eddsa_credential_0000.zkey");
  const messages: string[] = [];
  const logger = {
    info: (m: unknown) => messages.push(String(m)),
    warn: (m: unknown) => messages.push(String(m)),
    error: (m: unknown) => messages.push(String(m)),
    debug: () => undefined,
  };
  const tk = process.hrtime.bigint();
  try {
    await snarkjs.zKey.newZKey(R1CS_FILE, PTAU_FILE, z0);
    // entropy: never stored, never logged
    await snarkjs.zKey.contribute(z0, ZKEY_FILE, "e2b throwaway baseline contribution", randomBytes(64).toString("hex"));
  } finally {
    fs.rmSync(tmpKey, { recursive: true, force: true });
  }
  const keyMs = Number(process.hrtime.bigint() - tk) / 1e6;
  const ok = await snarkjs.zKey.verifyFromR1cs(R1CS_FILE, PTAU_FILE, ZKEY_FILE, logger);
  if (!ok) throw new Error("throwaway zkey does not verify against r1cs + ptau:\n" + messages.join("\n"));
  const contribHashes = messages
    .map((m) => /^contribution #(\d+) (.*):\n([\s\S]*)$/.exec(m))
    .filter((m): m is RegExpExecArray => m !== null)
    .map((m) => ({ index: Number(m[1]), name: (m[2] as string).trim(), hash: (m[3] as string).replace(/[^0-9a-f]/gi, "").toLowerCase() }));
  const vkey = await snarkjs.zKey.exportVerificationKey(ZKEY_FILE);
  fs.writeFileSync(VKEY_FILE, JSON.stringify(vkey, null, 2) + "\n");

  const record = {
    schema: "pqid/baseline-eddsa-setup/v1",
    label: KEY_LABEL,
    warning:
      "Timing and tests of baseline E2b only. One local contribution, no beacon, no ceremony. Not a dev or production key of PQ-Identity.",
    r1cs: rel(R1CS_FILE),
    r1csSha256: sha256File(R1CS_FILE),
    ptau: rel(PTAU_FILE),
    ptauSha256: ptauSha,
    ptauPinnedIn: "setup/pins.json (read-only)",
    zkey: rel(ZKEY_FILE),
    zkeySha256: sha256File(ZKEY_FILE),
    zkeyBytes: fs.statSync(ZKEY_FILE).size,
    vkey: rel(VKEY_FILE),
    vkeySha256: sha256File(VKEY_FILE),
    vkeyBytes: fs.statSync(VKEY_FILE).size,
    zkeyVerifyFromR1cs: ok,
    contributions: contribHashes,
    entropy: "64 bytes of OS randomness plus snarkjs's own; held in memory only, never written or logged",
    setupWallMs: Math.round(keyMs),
    host: hostMeta(),
  };
  fs.writeFileSync(SETUP_RECORD_FILE, JSON.stringify(record, null, 2) + "\n");
  console.log(`[e2b] ${KEY_LABEL}: ${rel(ZKEY_FILE)} (${record.zkeyBytes} B), zkey verify=${ok}`);
  process.exit(0); // snarkjs leaves worker threads alive
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
