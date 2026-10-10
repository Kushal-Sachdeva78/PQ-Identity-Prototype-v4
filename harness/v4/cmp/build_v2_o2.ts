import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { abs, envInfo, flag, opt, sanitize, sha256FileHex, sha256Hex, snarkjsVersion, utcNow, writeJson } from "../bench/lib.ts";
import { acquireMarker } from "../lib/markers.ts";
import {
  BENCH_LOCK_REL,
  EDDSA_FILES,
  PINS_CMP_REL,
  PIN_KEYS,
  REPO_ROOT,
  V2O2_DIR_REL,
  V2O2_EXPECTED,
  V2O2_FILES,
  V2O2_KEY_LABEL,
  V2_BEACON,
} from "./spec.ts";

/**
 * Untimed build for the cmp series (docs/v4/CMP.md, "Conditions"): the FROZEN v2 circuit
 * source (circuits/credential_auth.circom, read only) compiled at --O2 into NEW paths, with a
 * timing key made by the committed v2 recipe, and the pin file of the series.
 *
 *   node --import tsx harness/v4/cmp/build_v2_o2.ts [--no-recipe-check] [--owner <label>]
 *
 * Steps (holds results/v4/BUSY, DECISIONS D-034):
 *  1. hash every frozen v2/v3/v4 artifact (and compare the pinned ones with setup/pins.json and
 *     setup/pins_v4.json); the same list is hashed again at the end and must be unchanged;
 *  2. circom 2.2.3 circuits/credential_auth.circom --O2 --r1cs --wasm -o results/v4/cmp/artifacts/v2_O2;
 *     stop unless 10,588 constraints and 10,620 wires (results/v3/compare_v2_v3.json);
 *  3. key: snarkjs newZKey(r1cs, pinned 2^15 ptau) then beacon("pqid dev beacon",
 *     0102...20, iterExp 10), exactly setup/groth16_setup.ts; verifyFromR1cs; vkey export;
 *  4. determinism: the key is made a second time (OS temp dir) and must be byte-identical;
 *  5. recipe check (default on): the same recipe on the committed v2 r1cs, compared with the
 *     pinned v2 key (setup/pins.json); recorded either way;
 *  6. reference proof on the pinned v2 input (results/v4/bench/inputs): must verify and give the
 *     pinned v2 public signals;
 *  7. EdDSA baseline artifacts: hashes cross-checked with their committed records;
 *  8. results/v4/cmp/artifacts/pins_cmp.json (v2o2 and eddsa pins).
 * When pins_cmp.json already pins a v2o2 build, nothing is overwritten: the build is redone in
 * an OS temp dir and compared with the pins ("verify" mode).
 */

const PTAU_REL = "setup/ptau/powersOfTau28_hez_final_15.ptau";
const V2_SOURCE_REL = "circuits/credential_auth.circom";
const V2_R1CS_REL = "circuits/build/credential_auth.r1cs";

/** Frozen files: pinned ones are compared with their pin; all are hashed before and after. */
function frozenFiles(): Array<{ rel: string; pin: string | null; pinFile: string | null }> {
  const out: Array<{ rel: string; pin: string | null; pinFile: string | null }> = [];
  const pins = JSON.parse(fs.readFileSync(abs("setup/pins.json"), "utf8")) as Record<string, { sha256: string }>;
  const v2v3Paths: Record<string, string> = {
    "powersOfTau28_hez_final_15.ptau": PTAU_REL,
    "credential_auth_final.zkey": "setup/out/credential_auth_final.zkey",
    "verification_key.json": "setup/out/verification_key.json",
    "v3/credential_auth_v3.r1cs": "circuits/build/v3/credential_auth_v3.r1cs",
    "v3/credential_auth_v3.wasm": "circuits/build/v3/credential_auth_v3_js/credential_auth_v3.wasm",
    "v3/credential_auth_v3_final.zkey": "setup/out/v3/credential_auth_v3_final.zkey",
    "v3/verification_key.json": "setup/out/v3/verification_key.json",
    "v3/Groth16Verifier.sol": "setup/out/v3/Groth16Verifier.sol",
    "v3/setup_transcript.json": "setup/out/v3/setup_transcript.json",
  };
  for (const [k, e] of Object.entries(pins)) {
    const p = v2v3Paths[k];
    if (!p) throw new Error(`setup/pins.json entry ${k} has no known path; update build_v2_o2.ts frozenFiles()`);
    out.push({ rel: p, pin: e.sha256, pinFile: "setup/pins.json" });
  }
  const pins4 = JSON.parse(fs.readFileSync(abs("setup/pins_v4.json"), "utf8")) as Record<string, { sha256: string; path?: string }>;
  for (const [k, e] of Object.entries(pins4)) {
    if (!e.path) throw new Error(`setup/pins_v4.json entry ${k} has no path`);
    out.push({ rel: e.path, pin: e.sha256, pinFile: "setup/pins_v4.json" });
  }
  for (const r of [
    V2_SOURCE_REL,
    V2_R1CS_REL,
    "circuits/build/credential_auth_js/credential_auth.wasm",
    "circuits/build/circuit_info.json",
    "setup/out/Groth16Verifier.sol",
    "setup/pins.json",
    "setup/pins_v4.json",
    EDDSA_FILES.wasm,
    EDDSA_FILES.zkey,
    EDDSA_FILES.vkey,
    EDDSA_FILES.info,
    EDDSA_FILES.setup,
    BENCH_LOCK_REL,
    "results/v3/compare_v2_v3.json",
  ]) {
    out.push({ rel: r, pin: null, pinFile: null });
  }
  return out;
}

function hashFrozen(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of frozenFiles()) {
    const sha = sha256FileHex(abs(f.rel));
    if (f.pin !== null && f.pin !== sha) throw new Error(`frozen artifact ${f.rel} does not match ${f.pinFile} (${sha} != ${f.pin}); stopping`);
    out[f.rel] = sha;
  }
  return out;
}

function circomBinary(): string {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  return process.platform === "win32" && fs.existsSync(win) ? win : "circom";
}

function summary(stdout: string): Record<string, string> {
  // eslint-disable-next-line no-control-regex
  const plain = stdout.replace(/\u001b\[[0-9;]*m/g, "");
  const out: Record<string, string> = {};
  for (const line of plain.split(/\r?\n/)) {
    const m = /^(template instances|non-linear constraints|linear constraints|public inputs|private inputs|public outputs|wires|labels): (.*)$/.exec(line.trim());
    if (m) out[m[1] as string] = (m[2] as string).trim();
  }
  return out;
}

type Snarkjs = typeof import("snarkjs");
type Beacon = (oldZkey: string, newZkey: string, name: string, beaconHash: string, numIterExp: number, logger?: unknown) => Promise<unknown>;

const QUIET = { info: () => undefined, warn: () => undefined, error: () => undefined, debug: () => undefined };

/** The committed v2 recipe: newZKey from the pinned ptau, then the fixed public beacon. */
async function v2Recipe(snarkjs: Snarkjs, r1cs: string, out: string, tmpDir: string): Promise<void> {
  const z0 = path.join(tmpDir, `${path.basename(out, ".zkey")}_0000.zkey`);
  await snarkjs.zKey.newZKey(r1cs, abs(PTAU_REL), z0, QUIET);
  const beacon = (snarkjs.zKey as unknown as { beacon: Beacon }).beacon;
  await beacon(z0, out, V2_BEACON.name, V2_BEACON.hash, V2_BEACON.iterExp, QUIET);
  fs.rmSync(z0, { force: true });
}

function fileRec(r: string): { path: string; sha256: string; bytes: number } {
  return { path: r, sha256: sha256FileHex(abs(r)), bytes: fs.statSync(abs(r)).size };
}

interface PinEntry {
  sha256: string;
  bytes: number;
  path: string;
  label: string;
  note: string;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const recipeCheck = !flag(argv, "no-recipe-check");
  const owner = opt(argv, "owner");
  const marker = acquireMarker({
    kind: "BUSY",
    campaign: "cmp_build_v2_O2",
    runner: "harness/v4/cmp/build_v2_o2.ts",
    ...(owner !== undefined ? { owner } : {}),
    note: "untimed build: v2 --O2 compile and timing key (cmp series)",
  });
  const snarkjs = await import("snarkjs");
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-cmp-v2o2-"));
  try {
    const frozenBefore = hashFrozen();
    const ptauSha = frozenBefore[PTAU_REL] as string;

    const pinsFile = abs(PINS_CMP_REL);
    const existingPins: Record<string, PinEntry> | null = fs.existsSync(pinsFile) ? (JSON.parse(fs.readFileSync(pinsFile, "utf8")) as Record<string, PinEntry>) : null;
    const verifyMode = existingPins !== null && PIN_KEYS.v2o2.zkey in existingPins;
    const outDir = verifyMode ? path.join(tmp, "v2_O2") : abs(V2O2_DIR_REL);
    if (!verifyMode && fs.existsSync(outDir) && fs.readdirSync(outDir).length > 0) {
      throw new Error(`${V2O2_DIR_REL} exists without pins in ${PINS_CMP_REL} (an interrupted build?): inspect it and remove it by hand, then re-run`);
    }
    fs.mkdirSync(outDir, { recursive: true });
    const inOut = (r: string) => (verifyMode ? path.join(outDir, path.relative(abs(V2O2_DIR_REL), abs(r))) : abs(r));

    // ---- 2. compile
    const circomVersion = execFileSync(circomBinary(), ["--version"], { encoding: "utf8", windowsHide: true }).trim();
    if (!/\b2\.2\.3\b/.test(circomVersion)) throw new Error(`circom 2.2.3 required (got ${circomVersion})`);
    const tC = process.hrtime.bigint();
    const stdout = execFileSync(circomBinary(), [abs(V2_SOURCE_REL), "--O2", "--r1cs", "--wasm", "-o", outDir], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      windowsHide: true,
    });
    const compileWallMs = Math.round(Number(process.hrtime.bigint() - tC) / 1e6);
    const r1csAbs = inOut(V2O2_FILES.r1cs);
    const wasmAbs = inOut(V2O2_FILES.wasm);
    const info = await snarkjs.r1cs.info(r1csAbs, QUIET);
    const counts = { nConstraints: info.nConstraints, nWires: info.nVars, nPubInputs: info.nPubInputs, nPrvInputs: info.nPrvInputs, nOutputs: info.nOutputs, nLabels: Number(info.nLabels) };
    console.log(`[v2o2] --O2 constraints=${counts.nConstraints} wires=${counts.nWires} public=${counts.nPubInputs} private=${counts.nPrvInputs} (${compileWallMs} ms)`);
    if (counts.nConstraints !== V2O2_EXPECTED.nConstraints || counts.nWires !== V2O2_EXPECTED.nWires) {
      throw new Error(
        `stop rule: --O2 build gives ${counts.nConstraints} constraints / ${counts.nWires} wires, expected ${V2O2_EXPECTED.nConstraints} / ${V2O2_EXPECTED.nWires} (${V2O2_EXPECTED.source}); no key made`
      );
    }

    // ---- 3. key (v2 recipe), verifyFromR1cs, vkey
    const zkeyAbs = inOut(V2O2_FILES.zkey);
    const vkeyAbs = inOut(V2O2_FILES.vkey);
    const tK = process.hrtime.bigint();
    await v2Recipe(snarkjs, r1csAbs, zkeyAbs, tmp);
    const setupWallMs = Math.round(Number(process.hrtime.bigint() - tK) / 1e6);
    const verifyFromR1cs = await snarkjs.zKey.verifyFromR1cs(r1csAbs, abs(PTAU_REL), zkeyAbs, QUIET);
    if (!verifyFromR1cs) throw new Error("v2o2 zkey does not verify against the r1cs and the pinned ptau");
    const vkey = await snarkjs.zKey.exportVerificationKey(zkeyAbs, QUIET);
    fs.writeFileSync(vkeyAbs, JSON.stringify(vkey, null, 2) + "\n");
    console.log(`[v2o2] key: beacon recipe, verifyFromR1cs=${verifyFromR1cs} (${setupWallMs} ms)`);

    // ---- 4. determinism
    const again = path.join(tmp, "again.zkey");
    await v2Recipe(snarkjs, r1csAbs, again, tmp);
    const zkeySha = sha256FileHex(zkeyAbs);
    const againSha = sha256FileHex(again);
    fs.rmSync(again, { force: true });
    if (againSha !== zkeySha) throw new Error(`the v2 recipe is not deterministic here (${zkeySha} vs ${againSha})`);
    console.log(`[v2o2] determinism: a second run of the recipe gives the same zkey (${zkeySha.slice(0, 16)}...)`);

    // ---- 5. recipe check on the committed v2 r1cs
    let recipe: Record<string, unknown> = { run: false, reason: "--no-recipe-check" };
    if (recipeCheck) {
      const v2Pin = (JSON.parse(fs.readFileSync(abs("setup/pins.json"), "utf8")) as Record<string, { sha256: string }>)["credential_auth_final.zkey"]?.sha256;
      const out = path.join(tmp, "v2_recipe_check.zkey");
      const tR = process.hrtime.bigint();
      await v2Recipe(snarkjs, abs(V2_R1CS_REL), out, tmp);
      const sha = sha256FileHex(out);
      fs.rmSync(out, { force: true });
      recipe = {
        run: true,
        input: V2_R1CS_REL,
        resultSha256: sha,
        pinnedV2ZkeySha256: v2Pin ?? null,
        reproducesPinnedV2Key: sha === v2Pin,
        wallMs: Math.round(Number(process.hrtime.bigint() - tR) / 1e6),
        meaning: "the recipe above, run on the committed v2 r1cs, reproduces the committed v2 key byte for byte (true) or not (false)",
      };
      console.log(`[v2o2] recipe check on the committed v2 r1cs: reproduces the pinned v2 key = ${String(recipe["reproducesPinnedV2Key"])}`);
    }

    // ---- 6. reference proof on the pinned v2 input
    const lock = JSON.parse(fs.readFileSync(abs(BENCH_LOCK_REL), "utf8")) as { versions: { v2?: { file: string; inputSha256: string; publicSignals: string[] } } };
    const v2 = lock.versions.v2;
    if (!v2) throw new Error(`${BENCH_LOCK_REL} has no v2 entry`);
    const input = JSON.parse(fs.readFileSync(abs(v2.file), "utf8")) as Record<string, unknown>;
    if (sha256Hex(JSON.stringify(input)) !== v2.inputSha256) throw new Error(`${v2.file} does not match its pin in ${BENCH_LOCK_REL}`);
    const wtns: { type: "mem"; data?: Uint8Array } = { type: "mem" };
    await snarkjs.wtns.calculate(input, wasmAbs, wtns);
    const proved = await snarkjs.groth16.prove(zkeyAbs, wtns);
    const refVerified = await snarkjs.groth16.verify(vkey, proved.publicSignals, proved.proof);
    const signalsEqual = JSON.stringify(proved.publicSignals) === JSON.stringify(v2.publicSignals);
    if (!refVerified || !signalsEqual) throw new Error(`reference proof: verified=${refVerified}, public signals equal to the v2 pin=${signalsEqual}`);
    console.log("[v2o2] reference proof on the pinned v2 input: verifies, public signals equal the v2 pin");

    // ---- 7. EdDSA baseline cross-check
    const eInfo = JSON.parse(fs.readFileSync(abs(EDDSA_FILES.info), "utf8")) as { wasmSha256: string; nConstraints: number };
    const eSetup = JSON.parse(fs.readFileSync(abs(EDDSA_FILES.setup), "utf8")) as { zkeySha256: string; vkeySha256: string; label: string };
    const eW = fileRec(EDDSA_FILES.wasm);
    const eZ = fileRec(EDDSA_FILES.zkey);
    const eV = fileRec(EDDSA_FILES.vkey);
    if (eW.sha256 !== eInfo.wasmSha256) throw new Error(`${EDDSA_FILES.wasm} does not match ${EDDSA_FILES.info}`);
    if (eZ.sha256 !== eSetup.zkeySha256) throw new Error(`${EDDSA_FILES.zkey} does not match ${EDDSA_FILES.setup}`);
    if (eV.sha256 !== eSetup.vkeySha256) throw new Error(`${EDDSA_FILES.vkey} does not match ${EDDSA_FILES.setup}`);

    // ---- records
    const rec = (r: string, absPath: string) => ({ path: r, sha256: sha256FileHex(absPath), bytes: fs.statSync(absPath).size });
    const built = {
      r1cs: rec(V2O2_FILES.r1cs, r1csAbs),
      wasm: rec(V2O2_FILES.wasm, wasmAbs),
      zkey: rec(V2O2_FILES.zkey, zkeyAbs),
      vkey: rec(V2O2_FILES.vkey, vkeyAbs),
    };
    const pins: Record<string, PinEntry> = {
      [PIN_KEYS.v2o2.r1cs]: { ...built.r1cs, label: "cmp timing build", note: "frozen v2 circuit source, circom 2.2.3 --O2 (harness/v4/cmp/build_v2_o2.ts)" },
      [PIN_KEYS.v2o2.wasm]: { ...built.wasm, label: "cmp timing build", note: "witness generator of the --O2 build" },
      [PIN_KEYS.v2o2.zkey]: { ...built.zkey, label: V2O2_KEY_LABEL, note: "newZKey(pinned 2^15 ptau) + public beacon of setup/groth16_setup.ts; deterministic, timing only, no soundness" },
      [PIN_KEYS.v2o2.vkey]: { ...built.vkey, label: V2O2_KEY_LABEL, note: "exported from the timing key" },
      [PIN_KEYS.eddsa.wasm]: { ...eW, label: "throwaway baseline key", note: `committed; equals ${EDDSA_FILES.info} wasmSha256` },
      [PIN_KEYS.eddsa.zkey]: { ...eZ, label: "throwaway baseline key", note: `committed; equals ${EDDSA_FILES.setup} zkeySha256` },
      [PIN_KEYS.eddsa.vkey]: { ...eV, label: "throwaway baseline key", note: `committed; equals ${EDDSA_FILES.setup} vkeySha256` },
    };

    if (verifyMode) {
      const diffs = Object.entries(pins).filter(([k, e]) => existingPins?.[k]?.sha256 !== e.sha256).map(([k]) => k);
      if (diffs.length > 0) throw new Error(`verify mode: a fresh build differs from ${PINS_CMP_REL} for ${diffs.join(", ")}`);
      console.log(`[v2o2] verify mode: a fresh build in an OS temp dir equals every pin in ${PINS_CMP_REL}; nothing written`);
    } else {
      writeJson(abs(V2O2_FILES.info), {
        schema: "pqid/v4-cmp-v2o2-circuit/v1",
        label: "[M] compiler counts of the frozen v2 circuit at --O2 (cmp series build; not a v2 artifact)",
        createdUtc: utcNow(),
        source: V2_SOURCE_REL,
        sourceSha256: frozenBefore[V2_SOURCE_REL],
        compiler: circomVersion,
        optimization: "--O2",
        command: `circom ${V2_SOURCE_REL} --O2 --r1cs --wasm -o ${V2O2_DIR_REL}`,
        ...counts,
        expected: V2O2_EXPECTED,
        matchesExpected: true,
        circomSummary: summary(stdout),
        r1cs: built.r1cs,
        wasm: built.wasm,
        noSym: "no .sym file: not needed to prove or verify",
        compileWallMs,
        env: envInfo(),
      });
      writeJson(abs(V2O2_FILES.setup), {
        schema: "pqid/v4-cmp-v2o2-setup/v1",
        label: V2O2_KEY_LABEL,
        warning:
          "Timing key of the cmp series only. Made by a public, deterministic recipe (no secret contribution), so anyone can recompute it and it gives no soundness. It verifies nothing but this benchmark's proofs.",
        createdUtc: utcNow(),
        recipe: { ...V2_BEACON, phase2Init: `snarkjs zKey.newZKey(r1cs, ${PTAU_REL})`, ptauSha256: ptauSha, ptauPinnedIn: "setup/pins.json" },
        snarkjs: snarkjsVersion(),
        r1cs: built.r1cs,
        zkey: built.zkey,
        vkey: built.vkey,
        verifyFromR1cs,
        deterministic: { secondRunSha256: againSha, equal: true },
        recipeCheck: recipe,
        referenceProof: { input: v2.file, inputSha256: v2.inputSha256, verified: refVerified, publicSignalsEqualV2Pin: signalsEqual },
        setupWallMs,
        env: envInfo(),
      });
      writeJson(pinsFile, pins);
      console.log(`[v2o2] wrote ${V2O2_DIR_REL}/ and ${PINS_CMP_REL}`);
    }

    // ---- 1 (again). frozen files unchanged
    const frozenAfter = hashFrozen();
    const changed = Object.keys(frozenBefore).filter((k) => frozenBefore[k] !== frozenAfter[k]);
    if (changed.length > 0) throw new Error(`frozen files changed during the build: ${changed.join(", ")}`);
    console.log(`[v2o2] ${Object.keys(frozenAfter).length} frozen files hashed before and after: unchanged`);
    for (const [k, e] of Object.entries(pins)) console.log(`[v2o2] pin ${k}: ${e.bytes} B sha256 ${e.sha256}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
    marker.release();
  }
  process.exit(0); // snarkjs leaves worker threads alive
}

main().catch((e: unknown) => {
  console.error(`[v2o2] ${sanitize(e instanceof Error ? e.message : String(e))}`);
  process.exit(1);
});
