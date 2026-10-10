import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";
import {
  R1CS_FILE_V3,
  WASM_FILE_V3,
  PTAU_FILE,
  SETUP_OUT_DIR_V3,
  ZKEY_FILE_V3,
  VKEY_FILE_V3,
  SOLIDITY_VERIFIER_FILE_V3,
  REPO_ROOT,
} from "@pqid/common/paths";
import { sha256File } from "@pqid/common/hash";
import { hostMeta } from "@pqid/common/meta";
import { readPins, writePins } from "./pins.ts";

/**
 * Groth16 phase-2 setup for circuit v3.
 *
 * v2's setup (setup/groth16_setup.ts) finalizes with a beacon whose hash is
 * hard-coded, so the only phase-2 secret (delta) is derivable from public
 * data and anyone can forge v2 proofs for arbitrary public inputs (review
 * finding 9.3; reproduced by harness/v3/security_suite.ts, attack T1).
 *
 * v3 therefore runs:
 *   r1cs + ptau --newZKey--> 0000 --contribute(fresh secret entropy)--> 0001
 *               --beacon(public hash)--> final
 * The contribution's entropy (64 bytes of OS randomness inside snarkjs plus
 * 64 more from this script) exists only in this process's memory and is never
 * written anywhere. Groth16 soundness then holds unless that single
 * contribution is recovered; a deployment should still run a multi-party
 * ceremony (1-of-N honesty) instead of a single contributor.
 *
 * Because the key is randomized it is NOT byte-reproducible. Instead, both
 * modes AUDIT it: snarkjs zkey verify (the key derives from the committed
 * r1cs + ptau), a non-beacon contribution precedes the beacon, the
 * contribution hashes match setup_transcript.json, and verification_key.json
 * and Groth16Verifier.sol are exactly what the zkey exports. Pins cover the
 * five artifacts and the setup transcript.
 *
 * Usage:
 *   tsx setup/groth16_setup_v3.ts           audit the committed v3 key only
 *   tsx setup/groth16_setup_v3.ts --rekey   generate a NEW key and re-pin it
 */
const BEACON_HASH =
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const BEACON_ITER_EXP = 10;
const TRANSCRIPT_FILE = path.join(SETUP_OUT_DIR_V3, "setup_transcript.json");
const PIN_NAMES = {
  r1cs: "v3/credential_auth_v3.r1cs",
  wasm: "v3/credential_auth_v3.wasm",
  zkey: "v3/credential_auth_v3_final.zkey",
  vkey: "v3/verification_key.json",
  sol: "v3/Groth16Verifier.sol",
  transcript: "v3/setup_transcript.json",
} as const;
const PIN_FILES: Record<keyof typeof PIN_NAMES, string> = {
  r1cs: R1CS_FILE_V3,
  wasm: WASM_FILE_V3,
  zkey: ZKEY_FILE_V3,
  vkey: VKEY_FILE_V3,
  sol: SOLIDITY_VERIFIER_FILE_V3,
  transcript: TRANSCRIPT_FILE,
};

function rel(p: string): string {
  return path.relative(REPO_ROOT, p).split(path.sep).join("/");
}

function solidityTemplates(): Record<string, string> {
  const templatePath = path.join(REPO_ROOT, "node_modules", "snarkjs", "templates", "verifier_groth16.sol.ejs");
  return { groth16: fs.readFileSync(templatePath, "utf8") };
}

export interface ContributionRecord {
  index: number;
  name: string;
  contributionHash: string;
  beacon: boolean;
  beaconHash?: string;
}

export interface KeyAudit {
  contributions: ContributionRecord[];
  secretContributions: number;
  vkeyMatchesZkey: boolean;
  solidityMatchesZkey: boolean;
}

/** snarkjs zkey verify with its log parsed into the contribution list. */
async function verifyAndListContributions(): Promise<ContributionRecord[]> {
  const snarkjs = await import("snarkjs");
  const messages: string[] = [];
  const logger = {
    info: (m: unknown) => messages.push(String(m)),
    warn: (m: unknown) => messages.push(String(m)),
    error: (m: unknown) => messages.push(String(m)),
    debug: () => undefined,
  };
  console.log("[setup:v3] snarkjs zkey verify (r1cs + ptau -> zkey)…");
  const ok = await snarkjs.zKey.verifyFromR1cs(R1CS_FILE_V3, PTAU_FILE, ZKEY_FILE_V3, logger);
  if (!ok) throw new Error("v3 zkey does NOT verify against r1cs + ptau:\n" + messages.join("\n"));
  const out: ContributionRecord[] = [];
  for (const m of messages) {
    const head = /^contribution #(\d+) (.*):\n([\s\S]*)$/.exec(m);
    if (head) {
      const [, idx, name, body] = head as unknown as [string, string, string, string];
      out.push({
        index: Number(idx),
        name: name.trim(),
        contributionHash: body.replace(/[^0-9a-f]/gi, "").toLowerCase(),
        beacon: false,
      });
      continue;
    }
    const beacon = /^Beacon generator: ([0-9a-f]+)$/i.exec(m);
    const last = out[out.length - 1];
    if (beacon && last) {
      last.beacon = true;
      last.beaconHash = (beacon[1] as string).toLowerCase();
    }
  }
  return out.sort((a, b) => a.index - b.index);
}

export async function auditKey(): Promise<KeyAudit> {
  const snarkjs = await import("snarkjs");
  const contributions = await verifyAndListContributions();
  const secretContributions = contributions.filter((c) => !c.beacon).length;
  if (secretContributions < 1) throw new Error("v3 zkey has no non-beacon contribution: its trapdoor is public");

  if (!fs.existsSync(TRANSCRIPT_FILE)) throw new Error("setup_transcript.json missing");
  const t = JSON.parse(fs.readFileSync(TRANSCRIPT_FILE, "utf8")) as {
    phase2: Array<{ contributionHash: string | null }>;
  };
  const recorded = t.phase2.map((p) => p.contributionHash);
  const actual = contributions.map((c) => c.contributionHash);
  if (!isDeepStrictEqual(recorded, actual)) {
    throw new Error(`contribution hashes differ from setup_transcript.json:\n  recorded ${recorded}\n  actual   ${actual}`);
  }

  const vkeyExported = await snarkjs.zKey.exportVerificationKey(ZKEY_FILE_V3);
  const vkeyMatchesZkey = isDeepStrictEqual(
    JSON.parse(JSON.stringify(vkeyExported)),
    JSON.parse(fs.readFileSync(VKEY_FILE_V3, "utf8"))
  );
  if (!vkeyMatchesZkey) throw new Error("verification_key.json is not the key exported by the v3 zkey");
  const solExported = await snarkjs.zKey.exportSolidityVerifier(ZKEY_FILE_V3, solidityTemplates());
  const solidityMatchesZkey = solExported === fs.readFileSync(SOLIDITY_VERIFIER_FILE_V3, "utf8");
  if (!solidityMatchesZkey) throw new Error("Groth16Verifier.sol is not the verifier exported by the v3 zkey");

  return { contributions, secretContributions, vkeyMatchesZkey, solidityMatchesZkey };
}

function checkPins(): void {
  const pins = readPins();
  for (const [k, name] of Object.entries(PIN_NAMES) as Array<[keyof typeof PIN_NAMES, string]>) {
    const sha = sha256File(PIN_FILES[k]);
    const pinned = pins[name]?.sha256;
    if (pinned !== sha) {
      throw new Error(`PIN MISMATCH for ${name}: pinned ${pinned ?? "(none)"}, actual ${sha}`);
    }
    console.log(`[pins] ${name} OK (${sha.slice(0, 16)}…)`);
  }
}

function report(a: KeyAudit): void {
  for (const c of a.contributions) {
    console.log(`[setup:v3] contribution #${c.index} "${c.name}" ${c.beacon ? "(public beacon)" : "(secret)"} ${c.contributionHash.slice(0, 16)}…`);
  }
  console.log("[setup:v3] vkey and Groth16Verifier.sol match the zkey");
}

async function main(): Promise<void> {
  const rekey = process.argv.includes("--rekey");
  if (!fs.existsSync(R1CS_FILE_V3)) throw new Error("v3 r1cs missing — run setup/build_circuit_v3.ts first");
  if (!fs.existsSync(PTAU_FILE)) throw new Error("ptau missing — run setup/download_ptau.ts first");

  const pins = readPins();
  const ptauPin = pins["powersOfTau28_hez_final_15.ptau"];
  if (!ptauPin || sha256File(PTAU_FILE) !== ptauPin.sha256) {
    throw new Error("ptau missing from pins or drifted — aborting");
  }

  if (!rekey) {
    if (!fs.existsSync(ZKEY_FILE_V3)) {
      throw new Error("no v3 zkey yet — run with --rekey to generate one");
    }
    checkPins();
    report(await auditKey());
    console.log("[setup:v3] committed v3 key audited; nothing regenerated");
    process.exit(0);
  }

  fs.mkdirSync(SETUP_OUT_DIR_V3, { recursive: true });
  fs.rmSync(TRANSCRIPT_FILE, { force: true }); // rewritten below for the new key
  const snarkjs = await import("snarkjs");
  const zkey0 = path.join(SETUP_OUT_DIR_V3, "credential_auth_v3_0000.zkey");
  const zkey1 = path.join(SETUP_OUT_DIR_V3, "credential_auth_v3_0001.zkey");

  console.log("[setup:v3] groth16 newZKey (phase 2 init)…");
  await snarkjs.zKey.newZKey(R1CS_FILE_V3, PTAU_FILE, zkey0);

  console.log("[setup:v3] secret contribution (entropy kept in memory only)…");
  const zKeyAny = snarkjs.zKey as unknown as {
    contribute(o: string, n: string, name: string, entropy: string): Promise<Uint8Array>;
    beacon(o: string, n: string, name: string, hash: string, iter: number): Promise<Uint8Array>;
  };
  const contributionHash = await zKeyAny.contribute(
    zkey0,
    zkey1,
    "pqid v3 contribution 1",
    randomBytes(64).toString("hex")
  );
  fs.rmSync(zkey0);

  console.log("[setup:v3] public beacon finalization…");
  const beaconHash = await zKeyAny.beacon(
    zkey1,
    ZKEY_FILE_V3,
    "pqid v3 beacon",
    BEACON_HASH,
    BEACON_ITER_EXP
  );
  fs.rmSync(zkey1);

  console.log("[setup:v3] exporting verification key + Solidity verifier…");
  const vkey = await snarkjs.zKey.exportVerificationKey(ZKEY_FILE_V3);
  fs.writeFileSync(VKEY_FILE_V3, JSON.stringify(vkey, null, 2));
  fs.writeFileSync(
    SOLIDITY_VERIFIER_FILE_V3,
    await snarkjs.zKey.exportSolidityVerifier(ZKEY_FILE_V3, solidityTemplates())
  );

  const hex = (b: Uint8Array | undefined): string | null =>
    b ? Buffer.from(b).toString("hex") : null;
  const sha = Object.fromEntries(
    (Object.keys(PIN_FILES) as Array<keyof typeof PIN_FILES>)
      .filter((k) => k !== "transcript")
      .map((k) => [k, sha256File(PIN_FILES[k])])
  ) as Record<Exclude<keyof typeof PIN_FILES, "transcript">, string>;
  const transcript = {
    schema: "pqid/v3-setup-transcript/v1",
    circuit: rel(R1CS_FILE_V3),
    ptau: rel(PTAU_FILE),
    phase2: [
      {
        step: "contribution",
        name: "pqid v3 contribution 1",
        entropy: "OS randomness (snarkjs getRandomBytes, 64 B) + crypto.randomBytes(64); never written",
        contributionHash: hex(contributionHash),
      },
      {
        step: "beacon",
        name: "pqid v3 beacon",
        beaconHash: BEACON_HASH,
        numIterationsExp: BEACON_ITER_EXP,
        contributionHash: hex(beaconHash),
      },
    ],
    sha256: sha,
    host: hostMeta(),
  };
  fs.writeFileSync(TRANSCRIPT_FILE, JSON.stringify(transcript, null, 2));

  const audit = await auditKey();
  report(audit);

  const next = readPins();
  next[PIN_NAMES.r1cs] = { sha256: sha.r1cs, note: "circuit v3, circom 2.2.3 --O2" };
  next[PIN_NAMES.wasm] = { sha256: sha.wasm };
  next[PIN_NAMES.zkey] = {
    sha256: sha.zkey,
    note:
      "v3 key: one secret phase-2 contribution (entropy discarded) + public beacon; " +
      "not byte-reproducible — audited by setup/groth16_setup_v3.ts",
  };
  next[PIN_NAMES.vkey] = { sha256: sha.vkey };
  next[PIN_NAMES.sol] = { sha256: sha.sol };
  next[PIN_NAMES.transcript] = { sha256: sha256File(TRANSCRIPT_FILE) };
  writePins(next);

  console.log(`[setup:v3] zkey  ${rel(ZKEY_FILE_V3)}\n[setup:v3] sha256 ${sha.zkey}`);
  console.log(`[setup:v3] vkey  ${rel(VKEY_FILE_V3)}\n[setup:v3] sha256 ${sha.vkey}`);
  process.exit(0);
}

// Run only as a script (tests import auditKey).
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e: unknown) => {
    console.error(e);
    process.exit(1);
  });
}
