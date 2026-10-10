import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";
import { sha256File } from "@pqid/common/hash";
import { hostMeta } from "@pqid/common/meta";
import {
  REPO_ROOT,
  R1CS_V4,
  WASM_V4,
  PTAU,
  PTAU_16,
  SETUP_OUT_DIR_V4,
  ZKEY_V4,
  VKEY_V4,
  SOL_V4,
  TRANSCRIPT_V4,
  PINS_V4,
  CIRCUIT_INFO_V4,
  CIRCUIT_V4_SRC,
  CIRCUIT_V4_LIB,
  KEY_LABEL_V4,
} from "@pqid/v4/paths";
import { readPins } from "./pins.ts";

/**
 * Groth16 phase-2 setup for circuit v4: the DEV key (V4_DESIGN section 7).
 *
 * Made the v3 way (setup/groth16_setup_v3.ts):
 *   r1cs + ptau --newZKey--> 0000 --contribute(fresh OS entropy)--> 0001
 *               --beacon(public hash)--> final
 * The contribution's entropy (64 bytes inside snarkjs plus crypto.randomBytes(64) from
 * this script) exists only in this process's memory and is never written or logged.
 * Soundness of this key rests on that single contribution staying unknown; it is a dev
 * key, labelled "dev" in every file name, pin and transcript, and is replaced by the
 * ceremony key later (TASKS B8, K items).
 *
 * The key is randomized, so it is not byte-reproducible. Audit mode checks instead:
 *   - snarkjs zkey verify: the zkey derives from the built r1cs and the pinned ptau;
 *   - at least one non-beacon (secret) contribution precedes the beacon;
 *   - the contribution hashes equal the transcript's;
 *   - the vkey and Solidity verifier are exactly what the zkey exports;
 *   - setup/pins_v4.json matches every artifact and labels each one "dev".
 *
 * setup/pins.json (v2/v3) is only read, for the ptau pin (DECISIONS D-006).
 *
 * Usage:
 *   tsx setup/groth16_setup_v4.ts           audit the existing v4 dev key (default)
 *   tsx setup/groth16_setup_v4.ts --rekey   make a NEW dev key and re-pin it
 */
export const BEACON_HASH_V4 = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
export const BEACON_ITER_EXP_V4 = 10;
const CONTRIBUTION_NAME = "pqid v4 dev contribution 1";
const BEACON_NAME = "pqid v4 dev beacon";
const PTAU_PIN_NAME = "powersOfTau28_hez_final_15.ptau";
const PTAU_POWER = 15;

export const PIN_NAMES_V4 = {
  r1cs: "v4/credential_auth_v4.r1cs",
  wasm: "v4/credential_auth_v4.wasm",
  zkey: "v4/credential_auth_v4_dev.zkey",
  vkey: "v4/verification_key_dev.json",
  sol: "v4/Groth16VerifierV4_dev.sol",
  transcript: "v4/setup_transcript_dev.json",
} as const;
type PinKey = keyof typeof PIN_NAMES_V4;
const PIN_FILES: Record<PinKey, string> = {
  r1cs: R1CS_V4,
  wasm: WASM_V4,
  zkey: ZKEY_V4,
  vkey: VKEY_V4,
  sol: SOL_V4,
  transcript: TRANSCRIPT_V4,
};

export interface PinEntryV4 {
  sha256: string;
  label: string;
  path: string;
  note?: string;
}
export type PinsV4 = Record<string, PinEntryV4>;

export function readPinsV4(): PinsV4 {
  if (!fs.existsSync(PINS_V4)) return {};
  return JSON.parse(fs.readFileSync(PINS_V4, "utf8")) as PinsV4;
}

function writePinsV4(pins: PinsV4): void {
  fs.writeFileSync(PINS_V4, JSON.stringify(pins, null, 2) + "\n");
}

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

export interface KeyAuditV4 {
  label: string;
  contributions: ContributionRecord[];
  secretContributions: number;
  secretBeforeBeacon: boolean;
  transcriptMatches: boolean;
  vkeyMatchesZkey: boolean;
  solidityMatchesZkey: boolean;
  pinsMatch: boolean;
}

/** Fail unless the circuit fits the committed 2^15 powers of tau. */
async function checkPtauCapacity(): Promise<{ needed: number; capacity: number }> {
  const snarkjs = await import("snarkjs");
  const info = await snarkjs.r1cs.info(R1CS_V4);
  const needed = info.nConstraints + info.nPubInputs + info.nOutputs + 1;
  const capacity = 2 ** PTAU_POWER;
  if (needed > capacity) {
    throw new Error(
      `circuit v4 needs ${needed} > 2^${PTAU_POWER} = ${capacity} (nConstraints + nPublic + 1). ` +
        `The committed ${PTAU_PIN_NAME} is too small. Operator action (not done by this script): ` +
        `fetch the Hermez powersOfTau28_hez_final_16.ptau to ${rel(PTAU_16)}, check its SHA-256 ` +
        `against the hash published by the Hermez/iden3 ceremony, pin it, and point this script at it (TASKS S23).`
    );
  }
  return { needed, capacity };
}

/** The ptau must be the one pinned in setup/pins.json (read-only here). */
function checkPtauPin(): string {
  if (!fs.existsSync(PTAU)) throw new Error("ptau missing: run setup/download_ptau.ts first");
  const pin = readPins()[PTAU_PIN_NAME];
  const sha = sha256File(PTAU);
  if (!pin || pin.sha256 !== sha) throw new Error(`ptau missing from setup/pins.json or drifted (${sha}); aborting`);
  return sha;
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
  console.log("[setup:v4] snarkjs zkey verify (r1cs + ptau -> dev zkey)...");
  const ok = await snarkjs.zKey.verifyFromR1cs(R1CS_V4, PTAU, ZKEY_V4, logger);
  if (!ok) throw new Error("v4 dev zkey does NOT verify against r1cs + ptau:\n" + messages.join("\n"));
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

function pinsMatch(verbose: boolean): boolean {
  const pins = readPinsV4();
  for (const [k, name] of Object.entries(PIN_NAMES_V4) as Array<[PinKey, string]>) {
    const pin = pins[name];
    if (!fs.existsSync(PIN_FILES[k])) throw new Error(`${rel(PIN_FILES[k])} missing`);
    const sha = sha256File(PIN_FILES[k]);
    if (!pin || pin.sha256 !== sha) {
      throw new Error(`PIN MISMATCH for ${name}: pinned ${pin?.sha256 ?? "(none)"}, actual ${sha}`);
    }
    if (pin.label !== KEY_LABEL_V4) throw new Error(`pin ${name} is not labelled "${KEY_LABEL_V4}"`);
    if (pin.path !== rel(PIN_FILES[k])) throw new Error(`pin ${name} names ${pin.path}, expected ${rel(PIN_FILES[k])}`);
    if (verbose) console.log(`[pins_v4] ${name} OK (${sha.slice(0, 16)}...) label=${pin.label}`);
  }
  return true;
}

/**
 * The build must come from the current circuit sources: circuit_info.json records their
 * SHA-256 at build time and the r1cs SHA-256 it produced.
 */
function checkBuildMatchesSources(): void {
  if (!fs.existsSync(CIRCUIT_INFO_V4)) throw new Error(`${rel(CIRCUIT_INFO_V4)} missing: run setup/build_circuit_v4.ts`);
  const info = JSON.parse(fs.readFileSync(CIRCUIT_INFO_V4, "utf8")) as {
    r1csSha256?: string;
    sourceSha256?: Record<string, string>;
  };
  if (info.r1csSha256 !== sha256File(R1CS_V4)) throw new Error("r1cs differs from the one recorded in circuit_info.json");
  for (const f of [CIRCUIT_V4_SRC, CIRCUIT_V4_LIB]) {
    const recorded = info.sourceSha256?.[rel(f)];
    if (recorded !== sha256File(f)) {
      throw new Error(`${rel(f)} changed since the build: run setup/build_circuit_v4.ts, then this script with --rekey`);
    }
  }
}

/** Full audit of the v4 dev key (both modes run it). */
export async function auditKeyV4(opts: { checkPins?: boolean; verbose?: boolean } = {}): Promise<KeyAuditV4> {
  const snarkjs = await import("snarkjs");
  for (const f of [R1CS_V4, ZKEY_V4, VKEY_V4, SOL_V4, TRANSCRIPT_V4]) {
    if (!fs.existsSync(f)) throw new Error(`${rel(f)} missing: run setup/groth16_setup_v4.ts --rekey`);
  }
  checkBuildMatchesSources();
  const contributions = await verifyAndListContributions();
  const secret = contributions.filter((c) => !c.beacon);
  if (secret.length < 1) throw new Error("v4 dev zkey has no non-beacon contribution: its trapdoor is public");
  const firstBeacon = contributions.findIndex((c) => c.beacon);
  const secretBeforeBeacon = firstBeacon > 0 && contributions.slice(0, firstBeacon).some((c) => !c.beacon);
  if (!secretBeforeBeacon) throw new Error("v4 dev zkey: no secret contribution precedes the beacon");
  const beacon = contributions[firstBeacon] as ContributionRecord;
  if (beacon.beaconHash !== BEACON_HASH_V4) throw new Error(`beacon hash ${beacon.beaconHash} is not the published v4 beacon`);

  const t = JSON.parse(fs.readFileSync(TRANSCRIPT_V4, "utf8")) as {
    key_label?: string;
    phase2: Array<{ contributionHash: string | null }>;
  };
  if (t.key_label !== KEY_LABEL_V4) throw new Error(`transcript key_label is ${String(t.key_label)}, expected "${KEY_LABEL_V4}"`);
  const recorded = t.phase2.map((p) => p.contributionHash);
  const actual = contributions.map((c) => c.contributionHash);
  if (!isDeepStrictEqual(recorded, actual)) {
    throw new Error(`contribution hashes differ from the transcript:\n  recorded ${recorded}\n  actual   ${actual}`);
  }

  const vkeyExported = await snarkjs.zKey.exportVerificationKey(ZKEY_V4);
  const vkeyMatchesZkey = isDeepStrictEqual(
    JSON.parse(JSON.stringify(vkeyExported)),
    JSON.parse(fs.readFileSync(VKEY_V4, "utf8"))
  );
  if (!vkeyMatchesZkey) throw new Error(`${rel(VKEY_V4)} is not the key exported by the v4 dev zkey`);
  const solExported = await snarkjs.zKey.exportSolidityVerifier(ZKEY_V4, solidityTemplates());
  const solidityMatchesZkey = solExported === fs.readFileSync(SOL_V4, "utf8");
  if (!solidityMatchesZkey) throw new Error(`${rel(SOL_V4)} is not the verifier exported by the v4 dev zkey`);

  const doPins = opts.checkPins ?? true;
  const pinsOk = doPins ? pinsMatch(opts.verbose ?? false) : false;

  return {
    label: KEY_LABEL_V4,
    contributions,
    secretContributions: secret.length,
    secretBeforeBeacon,
    transcriptMatches: true,
    vkeyMatchesZkey,
    solidityMatchesZkey,
    pinsMatch: pinsOk,
  };
}

function report(a: KeyAuditV4): void {
  for (const c of a.contributions) {
    console.log(
      `[setup:v4] contribution #${c.index} "${c.name}" ${c.beacon ? "(public beacon)" : "(secret)"} ${c.contributionHash.slice(0, 16)}...`
    );
  }
  console.log(`[setup:v4] key label: ${a.label}`);
  console.log("[setup:v4] transcript hashes, vkey and Solidity verifier match the zkey");
  if (a.pinsMatch) console.log("[setup:v4] setup/pins_v4.json matches every artifact");
}

async function rekey(): Promise<void> {
  const snarkjs = await import("snarkjs");
  checkBuildMatchesSources(); // never key a stale build
  const ptauSha = checkPtauPin();
  const fit = await checkPtauCapacity();
  console.log(`[setup:v4] ptau 2^${PTAU_POWER} fits: needs ${fit.needed} of ${fit.capacity}`);

  fs.mkdirSync(SETUP_OUT_DIR_V4, { recursive: true });
  fs.rmSync(TRANSCRIPT_V4, { force: true }); // rewritten below for the new key
  const zkey0 = path.join(SETUP_OUT_DIR_V4, "credential_auth_v4_dev_0000.zkey");
  const zkey1 = path.join(SETUP_OUT_DIR_V4, "credential_auth_v4_dev_0001.zkey");
  const zKeyAny = snarkjs.zKey as unknown as {
    newZKey(r1cs: string, ptau: string, out: string, logger?: unknown): Promise<unknown>;
    contribute(o: string, n: string, name: string, entropy: string): Promise<Uint8Array>;
    beacon(o: string, n: string, name: string, hash: string, iter: number): Promise<Uint8Array>;
  };

  const timings: Record<string, number> = {};
  const tick = (): bigint => process.hrtime.bigint();
  const ms = (t0: bigint): number => Math.round(Number(process.hrtime.bigint() - t0) / 1e6);
  try {
    console.log("[setup:v4] groth16 newZKey (phase 2 init)...");
    let t0 = tick();
    await zKeyAny.newZKey(R1CS_V4, PTAU, zkey0);
    timings["newZKeyMs"] = ms(t0);

    console.log("[setup:v4] secret contribution (entropy kept in memory only)...");
    t0 = tick();
    const contributionHash = await zKeyAny.contribute(zkey0, zkey1, CONTRIBUTION_NAME, randomBytes(64).toString("hex"));
    timings["contributeMs"] = ms(t0);
    fs.rmSync(zkey0, { force: true });

    console.log("[setup:v4] public beacon finalization...");
    t0 = tick();
    const beaconHash = await zKeyAny.beacon(zkey1, ZKEY_V4, BEACON_NAME, BEACON_HASH_V4, BEACON_ITER_EXP_V4);
    timings["beaconMs"] = ms(t0);
    fs.rmSync(zkey1, { force: true });

    console.log("[setup:v4] exporting verification key + Solidity verifier...");
    const vkey = await snarkjs.zKey.exportVerificationKey(ZKEY_V4);
    fs.writeFileSync(VKEY_V4, JSON.stringify(vkey, null, 2));
    fs.writeFileSync(SOL_V4, await snarkjs.zKey.exportSolidityVerifier(ZKEY_V4, solidityTemplates()));

    const hex = (b: Uint8Array | undefined): string | null => (b ? Buffer.from(b).toString("hex") : null);
    const sha = Object.fromEntries(
      (Object.keys(PIN_FILES) as PinKey[]).filter((k) => k !== "transcript").map((k) => [k, sha256File(PIN_FILES[k])])
    ) as Record<Exclude<PinKey, "transcript">, string>;
    let circuitInfoSha: string | null = null;
    if (fs.existsSync(CIRCUIT_INFO_V4)) circuitInfoSha = sha256File(CIRCUIT_INFO_V4);

    const transcript = {
      schema: "pqid/v4-dev-setup-transcript/v1",
      key_label: KEY_LABEL_V4,
      note:
        "Development key. One secret phase-2 contribution (entropy discarded) followed by a public beacon, " +
        "made the v3 way. It is replaced by the ceremony key later; nothing proven with it is ceremony evidence.",
      circuit: rel(R1CS_V4),
      circuitInfo: rel(CIRCUIT_INFO_V4),
      circuitInfoSha256: circuitInfoSha,
      ptau: { file: rel(PTAU), sha256: ptauSha, pin: `setup/pins.json:${PTAU_PIN_NAME}`, power: PTAU_POWER, needed: fit.needed },
      phase2: [
        {
          step: "contribution",
          name: CONTRIBUTION_NAME,
          entropy: "OS randomness (snarkjs getRandomBytes, 64 B) + crypto.randomBytes(64) passed in memory; never written",
          contributionHash: hex(contributionHash),
        },
        {
          step: "beacon",
          name: BEACON_NAME,
          beaconHash: BEACON_HASH_V4,
          numIterationsExp: BEACON_ITER_EXP_V4,
          contributionHash: hex(beaconHash),
        },
      ],
      sha256: sha,
      timingsMs: timings,
      tools: { snarkjs: "0.7.4" },
      host: hostMeta(),
    };
    fs.writeFileSync(TRANSCRIPT_V4, JSON.stringify(transcript, null, 2) + "\n");

    const pins: PinsV4 = {
      [PIN_NAMES_V4.r1cs]: { sha256: sha.r1cs, label: KEY_LABEL_V4, path: rel(R1CS_V4), note: "circuit v4, circom 2.2.3 --O2" },
      [PIN_NAMES_V4.wasm]: { sha256: sha.wasm, label: KEY_LABEL_V4, path: rel(WASM_V4) },
      [PIN_NAMES_V4.zkey]: {
        sha256: sha.zkey,
        label: KEY_LABEL_V4,
        path: rel(ZKEY_V4),
        note:
          "v4 dev key: one secret phase-2 contribution (entropy discarded) + public beacon; not byte-reproducible; " +
          "audited by setup/groth16_setup_v4.ts; replaced by the ceremony key later",
      },
      [PIN_NAMES_V4.vkey]: { sha256: sha.vkey, label: KEY_LABEL_V4, path: rel(VKEY_V4) },
      [PIN_NAMES_V4.sol]: { sha256: sha.sol, label: KEY_LABEL_V4, path: rel(SOL_V4), note: "contract Groth16Verifier (snarkjs 0.7.4 template)" },
      [PIN_NAMES_V4.transcript]: { sha256: sha256File(TRANSCRIPT_V4), label: KEY_LABEL_V4, path: rel(TRANSCRIPT_V4) },
    };
    writePinsV4(pins);
  } finally {
    fs.rmSync(zkey0, { force: true });
    fs.rmSync(zkey1, { force: true });
  }

  const audit = await auditKeyV4({ verbose: true });
  report(audit);
  console.log(`[setup:v4] zkey ${rel(ZKEY_V4)} sha256 ${sha256File(ZKEY_V4)}`);
  console.log(`[setup:v4] vkey ${rel(VKEY_V4)} sha256 ${sha256File(VKEY_V4)}`);
}

async function main(): Promise<void> {
  if (!fs.existsSync(R1CS_V4)) throw new Error("v4 r1cs missing: run setup/build_circuit_v4.ts first");
  if (process.argv.includes("--rekey")) {
    await rekey();
    process.exit(0);
  }
  checkPtauPin();
  const fit = await checkPtauCapacity();
  console.log(`[setup:v4] ptau 2^${PTAU_POWER} fits: needs ${fit.needed} of ${fit.capacity}`);
  if (!fs.existsSync(ZKEY_V4)) throw new Error("no v4 dev zkey yet: run with --rekey to make one");
  report(await auditKeyV4({ verbose: true }));
  console.log("[setup:v4] v4 dev key audited; nothing regenerated");
  process.exit(0); // snarkjs keeps worker threads alive
}

// Run only as a script (tests import auditKeyV4 / readPinsV4).
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e: unknown) => {
    console.error(e);
    process.exit(1);
  });
}
