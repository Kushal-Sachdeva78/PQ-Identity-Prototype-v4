import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { REPO_ROOT, WASM_V4, ZKEY_V4, VKEY_V4, R1CS_V4, PINS_V4, KEY_LABEL_V4 } from "@pqid/v4/paths";
import { publicSignalsOfInputV4, type CircuitInputV4 } from "@pqid/v4/witness";
import { buildFixtureProofInputV4, V4_FIXTURE } from "../../harness/v4/bench/inputs.ts";

/**
 * Honest v4 circuit input for the phone kit (docs/v4/PHONE_PROTOCOL.md, TASKS E1).
 *
 * The input is the Phase D laptop input: buildFixtureProofInputV4() of
 * harness/v4/bench/inputs.ts, imported read-only. So the phone (native Mopro and Safari)
 * and the laptop prove the same statement with the same witness. No Anvil, no key
 * generation, no randomness: every value is a published fixture constant (the fixture
 * holder secret is 123456789, harness/fixture.ts), not a real secret.
 *
 * Writes (default directory mobile/inputs/):
 *   v4_input.json       compact JSON + "\n" (snarkjs form; the Safari page loads it)
 *   v4_input.mopro.json the same values with every signal as an array of decimal strings
 *                       (scalars become one-element arrays), the flat form of Mopro's iOS
 *                       example (https://zkmopro.org/docs/setup/ios-setup); the app loads it
 *   v4_input.meta.json  SHA-256 of the input (same convention as the bench lock: compact
 *                       text without the trailing newline), the 8 expected public signals,
 *                       the artifact hashes it was made against, pin and bench-lock checks
 *
 * Usage (repo root):
 *   node --import tsx mobile/scripts/make_input.ts [--check-witness] [--out-dir <dir>]
 *   --check-witness  compute the witness with the circuit wasm (in memory) and check it
 *                    against the R1CS (snarkjs wtns.check). No proof, no timing.
 */

interface ArtifactInfo {
  path: string;
  sha256: string;
  bytes: number;
  pinned: boolean;
  pinMatch: boolean | null;
}

interface LockView {
  file: string;
  exists: boolean;
  inputSha256Matches: boolean | null;
  publicSignalsMatch: boolean | null;
  zkeyMatches: boolean | null;
  referenceProofVerified: boolean | null;
}

const rel = (p: string): string => path.relative(REPO_ROOT, p).split(path.sep).join("/");
const sha256 = (b: string | Uint8Array): string => createHash("sha256").update(b).digest("hex");

function argValue(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  if (i < 0) return undefined;
  const v = argv[i + 1];
  if (!v || v.startsWith("--")) throw new Error(`--${name} needs a value`);
  return v;
}

function artifact(file: string, pins: Record<string, { sha256: string; path: string }>): ArtifactInfo {
  if (!fs.existsSync(file)) throw new Error(`${rel(file)} missing: build the v4 circuit and dev key first`);
  const data = fs.readFileSync(file);
  const r = rel(file);
  const pin = Object.values(pins).find((p) => p.path === r);
  return { path: r, sha256: sha256(data), bytes: data.length, pinned: pin !== undefined, pinMatch: pin ? pin.sha256 === sha256(data) : null };
}

interface LockEntry {
  inputSha256: string;
  publicSignals: string[];
  artifacts: { zkey: { sha256: string } };
  referenceProofVerified?: boolean;
}

function lockView(file: string, inputSha256: string, publicSignals: string[], zkeySha256: string): LockView {
  if (!fs.existsSync(file)) {
    return { file: rel(file), exists: false, inputSha256Matches: null, publicSignalsMatch: null, zkeyMatches: null, referenceProofVerified: null };
  }
  const lock = JSON.parse(fs.readFileSync(file, "utf8")) as { versions?: Record<string, LockEntry> };
  const v4 = lock.versions?.["v4"];
  if (!v4) {
    return { file: rel(file), exists: true, inputSha256Matches: null, publicSignalsMatch: null, zkeyMatches: null, referenceProofVerified: null };
  }
  return {
    file: rel(file),
    exists: true,
    inputSha256Matches: v4.inputSha256 === inputSha256,
    publicSignalsMatch: JSON.stringify(v4.publicSignals) === JSON.stringify(publicSignals),
    zkeyMatches: v4.artifacts.zkey.sha256 === zkeySha256,
    referenceProofVerified: v4.referenceProofVerified ?? null,
  };
}

async function witnessCheck(input: CircuitInputV4): Promise<{ ran: true; r1csSatisfied: boolean; witnessSha256: string }> {
  const snarkjs = await import("snarkjs");
  const wtns: { type: "mem"; data?: Uint8Array } = { type: "mem" };
  await snarkjs.wtns.calculate(input, WASM_V4, wtns);
  if (!wtns.data) throw new Error("snarkjs produced no in-memory witness");
  const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined, debug: () => undefined };
  const ok = await snarkjs.wtns.check(R1CS_V4, wtns as never, quiet);
  return { ran: true, r1csSatisfied: ok, witnessSha256: sha256(wtns.data) };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const outDir = path.resolve(REPO_ROOT, argValue(argv, "out-dir") ?? path.join("mobile", "inputs"));
  const doCheck = argv.includes("--check-witness");

  const input = await buildFixtureProofInputV4();
  const text = JSON.stringify(input);
  const inputSha256 = sha256(text);
  const publicSignals = publicSignalsOfInputV4(input);
  const moproForm: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(input)) moproForm[k] = Array.isArray(v) ? [...v] : [v];
  const moproText = JSON.stringify(moproForm);

  const pins = JSON.parse(fs.readFileSync(PINS_V4, "utf8")) as Record<string, { sha256: string; path: string }>;
  const wasm = artifact(WASM_V4, pins);
  const zkey = artifact(ZKEY_V4, pins);
  const vkey = artifact(VKEY_V4, pins);

  const benchLock = lockView(path.join(REPO_ROOT, "results", "v4", "bench", "inputs", "inputs.lock.json"), inputSha256, publicSignals, zkey.sha256);
  const smokeLock = lockView(path.join(REPO_ROOT, "results", "v4", "bench", "_tmp", "inputs", "inputs.lock.json"), inputSha256, publicSignals, zkey.sha256);
  const witness = doCheck ? await witnessCheck(input) : { ran: false as const };

  const meta = {
    schema: "pqid/v4-phone-input/v1",
    generator: "mobile/scripts/make_input.ts",
    source: "harness/v4/bench/inputs.ts buildFixtureProofInputV4() (Phase D laptop input, read-only reuse)",
    fixture: V4_FIXTURE,
    note: "all values are published fixture constants (holder secret 123456789, harness/fixture.ts); no real secret",
    keyLabel: KEY_LABEL_V4,
    inputFile: rel(path.join(outDir, "v4_input.json")),
    inputSha256,
    inputSha256Convention: "SHA-256 of the compact JSON text without the trailing newline (bench lock convention)",
    moproInputFile: rel(path.join(outDir, "v4_input.mopro.json")),
    moproInputSha256: sha256(moproText),
    moproInputForm: "every signal as an array of decimal strings; same values and order as inputFile",
    publicSignalOrder: ["issuerKeyHash", "revRoot", "policyHash", "nonce", "stmtCode", "issRoot", "epochFromDate", "epochToDate"],
    publicSignals,
    publicSignalsSha256: sha256(JSON.stringify(publicSignals)),
    artifacts: { wasm, zkey, vkey },
    benchLock,
    smokeBenchLock: { ...smokeLock, note: "smoke lock (results/v4/bench/_tmp, gitignored): a check of the input only, never a result" },
    witnessCheck: witness,
    createdUtc: new Date().toISOString(),
  };

  if (!wasm.pinMatch || !zkey.pinMatch || !vkey.pinMatch) {
    throw new Error("an artifact does not match setup/pins_v4.json; refusing to write a phone input for unpinned artifacts");
  }
  if (doCheck && "r1csSatisfied" in witness && !witness.r1csSatisfied) {
    throw new Error("the witness of the fixture input does not satisfy the R1CS");
  }

  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "v4_input.json"), text + "\n");
  fs.writeFileSync(path.join(outDir, "v4_input.mopro.json"), moproText + "\n");
  fs.writeFileSync(path.join(outDir, "v4_input.meta.json"), JSON.stringify(meta, null, 2) + "\n");
  console.log(`[make_input] wrote ${meta.inputFile} (sha256 ${inputSha256})`);
  console.log(`[make_input] public signals sha256 ${meta.publicSignalsSha256}`);
  console.log(`[make_input] bench lock: ${benchLock.exists ? `input ${benchLock.inputSha256Matches ? "matches" : "DIFFERS"}` : "not made yet"}; smoke lock: ${smokeLock.exists ? `input ${smokeLock.inputSha256Matches ? "matches" : "DIFFERS"}` : "absent"}`);
  if (doCheck && "r1csSatisfied" in witness) console.log(`[make_input] witness satisfies the R1CS: ${witness.r1csSatisfied}`);
  process.exit(0);
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
