import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import {
  REPO_ROOT,
  VERSIONS,
  abs,
  checkArtifact,
  opt,
  protocolSha,
  sha256FileHex,
  sha256Hex,
  type ArtifactRecord,
  type ArtifactSpec,
} from "../bench/lib.ts";
import { SEEDS, assertUnusedSeed } from "../lib/seeds.ts";

/**
 * Comparable benchmark series ("cmp", DECISIONS D-034 row "Make benchmarks comparable";
 * protocol addendum docs/v4/CMP.md). Paths, conditions, seeds and the checks every cmp
 * script shares. Nothing here writes a file.
 *
 * Conditions (one results root, one OS: Windows 11, snarkJS 0.7.4):
 *   v2     committed v2 circuit as published (circom default --O1) and committed v2 key
 *   v2o2   the frozen v2 circuit compiled at --O2 into results/v4/cmp/artifacts/v2_O2/, with a
 *          timing key made by the committed v2 beacon recipe (setup/groth16_setup.ts)
 *   v3     committed v3 artifacts
 *   v4     committed v4 circuit; the key is an input (dev key now, the ceremony key later)
 *   eddsa  committed EdDSA-in-circuit baseline (throwaway key), fixed fixture input
 *   curve  optional: a fresh process that only builds the bn128 curve (ffjavascript 0.3.0, the
 *          copy snarkjs uses), the work snarkJS prove does first in a fresh process
 *   wallet1e5, wallet1e6: wallet-side rebuild of the published trees (separate campaign)
 */

export { REPO_ROOT };

// ------------------------------------------------------------------ roots

export const CMP_ROOT_REL = "results/v4/cmp";
export const CMP_ROOT = abs(CMP_ROOT_REL);
export const SMOKE_DIR = "_smoke";

export function cmpRoot(smoke: boolean): string {
  return smoke ? path.join(CMP_ROOT, SMOKE_DIR) : CMP_ROOT;
}
/** Prover campaigns (cold_cmp, warm_cmp): readable by scripts/bench/analyze.py --root. */
export function proveRoot(smoke: boolean): string {
  return path.join(cmpRoot(smoke), "prove");
}
/** Wallet rebuild campaign (wallet_cmp). */
export function walletRoot(smoke: boolean): string {
  return path.join(cmpRoot(smoke), "wallet");
}
export function cmpInputsDir(smoke: boolean): string {
  return path.join(cmpRoot(smoke), "inputs");
}
export function cmpLockFile(smoke: boolean): string {
  return path.join(cmpInputsDir(smoke), "inputs_cmp.lock.json");
}

/** Phase D input lock (read only): the v2, v3 and v4 inputs are reused from there. */
export const BENCH_LOCK_REL = "results/v4/bench/inputs/inputs.lock.json";

// ------------------------------------------------------------------ artifacts

export const ARTIFACTS_REL = "results/v4/cmp/artifacts";
export const V2O2_DIR_REL = `${ARTIFACTS_REL}/v2_O2`;
export const PINS_CMP_REL = `${ARTIFACTS_REL}/pins_cmp.json`;

export const V2O2_FILES = Object.freeze({
  r1cs: `${V2O2_DIR_REL}/credential_auth.r1cs`,
  wasm: `${V2O2_DIR_REL}/credential_auth_js/credential_auth.wasm`,
  zkey: `${V2O2_DIR_REL}/credential_auth_v2_O2_timing.zkey`,
  vkey: `${V2O2_DIR_REL}/verification_key_v2_O2_timing.json`,
  info: `${V2O2_DIR_REL}/circuit_info.json`,
  setup: `${V2O2_DIR_REL}/setup_v2_O2_timing.json`,
});

/** Stop rule of the --O2 build: the counts of the frozen v3-era measurement. */
export const V2O2_EXPECTED = Object.freeze({
  nConstraints: 10588,
  nWires: 10620,
  source: "results/v3/compare_v2_v3.json $.constraints.v2_O2",
});

/** The committed v2 key recipe (setup/groth16_setup.ts): newZKey from the pinned 2^15 ptau, then this beacon. */
export const V2_BEACON = Object.freeze({
  hash: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  iterExp: 10,
  name: "pqid dev beacon",
  source: "setup/groth16_setup.ts (BEACON_HASH, BEACON_ITER_EXP, beacon name)",
});

export const V2O2_KEY_LABEL = "v2 --O2 dev timing key (v2 beacon recipe)";

export const EDDSA_FILES = Object.freeze({
  wasm: "circuits/build/baselines/eddsa_credential_js/eddsa_credential.wasm",
  zkey: "setup/out/baselines/eddsa_credential_throwaway.zkey",
  vkey: "setup/out/baselines/eddsa_credential_throwaway_vkey.json",
  info: "circuits/build/baselines/eddsa_credential_info.json",
  setup: "setup/out/baselines/eddsa_credential_throwaway_setup.json",
});

export const PIN_KEYS = Object.freeze({
  v2o2: Object.freeze({
    r1cs: "v2o2/credential_auth.r1cs",
    wasm: "v2o2/credential_auth.wasm",
    zkey: "v2o2/credential_auth_v2_O2_timing.zkey",
    vkey: "v2o2/verification_key_v2_O2_timing.json",
  }),
  eddsa: Object.freeze({
    wasm: "eddsa/eddsa_credential.wasm",
    zkey: "eddsa/eddsa_credential_throwaway.zkey",
    vkey: "eddsa/eddsa_credential_throwaway_vkey.json",
  }),
});

// ------------------------------------------------------------------ protocol

export const CMP_PROTOCOL_REL = "docs/v4/CMP.md";
/** Publication BENCH_PROTOCOL.md text above "## Deviations" (checked at every start). */
export const BENCH_PROTOCOL_NORMATIVE_SHA256 = "fe4f88284db9c858b30939b994394194d1f9de930fb229587789842b98ad51f8";

/** SHA-256 of a protocol file above its "## Deviations" heading (LF line ends), and of the whole file. */
export function normativeSha(fileRel: string): { normative: string; file: string } {
  const file = abs(fileRel);
  if (!fs.existsSync(file)) throw new Error(`${fileRel} missing: the protocol must exist before any timed run`);
  const text = fs.readFileSync(file, "utf8").replace(/\r\n/g, "\n");
  const cut = text.indexOf("\n## Deviations");
  if (cut < 0) throw new Error(`${fileRel} has no '## Deviations' section`);
  return { normative: sha256Hex(text.slice(0, cut)), file: sha256FileHex(file) };
}

export interface ProtocolRecord {
  benchProtocol: string;
  benchProtocolSha256: string;
  benchProtocolFileSha256: string;
  cmpProtocol: string;
  cmpProtocolSha256: string;
  cmpProtocolFileSha256: string;
  shaBasis: string;
}

/** Both protocol hashes; throws when BENCH_PROTOCOL.md's normative part is not the one this series extends. */
export function protocolRecord(): ProtocolRecord {
  const bench = protocolSha();
  if (bench.normative !== BENCH_PROTOCOL_NORMATIVE_SHA256) {
    throw new Error(
      `docs/v4/BENCH_PROTOCOL.md above '## Deviations' changed (${bench.normative} != ${BENCH_PROTOCOL_NORMATIVE_SHA256}); the cmp addendum extends the old text: review docs/v4/CMP.md first`
    );
  }
  const cmp = normativeSha(CMP_PROTOCOL_REL);
  return {
    benchProtocol: "docs/v4/BENCH_PROTOCOL.md",
    benchProtocolSha256: bench.normative,
    benchProtocolFileSha256: bench.file,
    cmpProtocol: CMP_PROTOCOL_REL,
    cmpProtocolSha256: cmp.normative,
    cmpProtocolFileSha256: cmp.file,
    shaBasis: "SHA-256 of each file above '## Deviations' with LF line ends (normative); *FileSha256 hashes the whole file",
  };
}

// ------------------------------------------------------------------ seeds (DECISIONS D-034)

export const CMP_SEEDS = Object.freeze({
  cold: SEEDS.comparable.coldOrder,
  wallet: SEEDS.comparable.walletRebuilds,
  warm: SEEDS.comparable.warm,
});
// registered in D-034 for this row and not used by an earlier series (throws when the module loads otherwise)
for (const s of Object.values(CMP_SEEDS)) {
  if (assertUnusedSeed(s).row !== "comparable") throw new Error(`seed ${s} is not a comparable-benchmark seed of D-034`);
}

// ------------------------------------------------------------------ conditions

export type Circuit = "v2" | "v2o2" | "v3" | "v4" | "eddsa";
export const CIRCUITS: readonly Circuit[] = ["v2", "v2o2", "v3", "v4", "eddsa"];
export const CURVE_CONDITION = "curve" as const;
export type ProveCondition = Circuit | typeof CURVE_CONDITION;
export const PROVE_CONDITIONS: readonly ProveCondition[] = [...CIRCUITS, CURVE_CONDITION];
/** Default cold conditions: the five circuits. `curve` is opt-in (+30 cold runs, about 5 h). */
export const DEFAULT_COLD_CONDITIONS: readonly ProveCondition[] = CIRCUITS;

export type WalletCondition = "wallet1e5" | "wallet1e6";
export const WALLET_CONDITIONS: readonly WalletCondition[] = ["wallet1e5", "wallet1e6"];
export interface WalletSize {
  credentials: number;
  revocations: number;
}
/** Same sizes as results/v4/privacy.json $.publishedTree.timing (revocations = 1 % of credentials). */
export const WALLET_SIZES: Readonly<Record<WalletCondition, WalletSize>> = Object.freeze({
  wallet1e5: { credentials: 100_000, revocations: 1_000 },
  wallet1e6: { credentials: 1_000_000, revocations: 10_000 },
});
/** Smoke sizes (checks the runner only). */
export const WALLET_SIZES_SMOKE: Readonly<Record<WalletCondition, WalletSize>> = Object.freeze({
  wallet1e5: { credentials: 1_000, revocations: 10 },
  wallet1e6: { credentials: 4_000, revocations: 40 },
});
export function walletSize(c: WalletCondition, smoke: boolean): WalletSize {
  return (smoke ? WALLET_SIZES_SMOKE : WALLET_SIZES)[c];
}

/** Condition id written to schedules and records (as Phase D: "<version>/<prover>"). */
export function conditionIdOf(c: ProveCondition | WalletCondition): string {
  if (c === "wallet1e5" || c === "wallet1e6") return `${c}/node`;
  return `${c}/snarkjs`;
}

// ------------------------------------------------------------------ v4 key (an input of the series)

export interface V4KeyOptions {
  /** Repo-relative zkey path (default: the dev key of lib.ts VERSIONS.v4). */
  zkey?: string;
  /** Repo-relative vkey path. */
  vkey?: string;
  /** Key label written to every record; required for a non-default key. */
  label?: string;
  /** Pin file whose entries carry a `path` field equal to the zkey and vkey paths (default setup/pins_v4.json). */
  pins?: string;
}

/** --v4-zkey, --v4-vkey, --v4-key-label, --v4-pins (repo-relative paths, forward slashes). */
export function v4KeyFromArgs(argv: readonly string[]): V4KeyOptions {
  const o: V4KeyOptions = {};
  const z = opt(argv, "v4-zkey");
  const v = opt(argv, "v4-vkey");
  const l = opt(argv, "v4-key-label");
  const p = opt(argv, "v4-pins");
  if (z !== undefined) o.zkey = z;
  if (v !== undefined) o.vkey = v;
  if (l !== undefined) o.label = l;
  if (p !== undefined) o.pins = p;
  return o;
}

export const DEV_KEY_LABEL = VERSIONS.v4.keyLabel;

function cleanRel(p: string, what: string): string {
  const r = p.replace(/\\/g, "/").replace(/^\.\//, "");
  if (path.isAbsolute(p) || /^[A-Za-z]:/.test(r) || r.startsWith("/") || r.split("/").includes("..")) {
    throw new Error(`${what} must be a repository-relative path without '..' (got ${JSON.stringify(p)})`);
  }
  return r;
}

/** The pin entry whose `path` equals rel (pins_v4.json style). */
export function pinKeyForPath(pinsRel: string, rel: string): string {
  const file = abs(pinsRel);
  if (!fs.existsSync(file)) throw new Error(`pin file ${pinsRel} missing`);
  const pins = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, { path?: string; sha256?: string }>;
  const hits = Object.entries(pins).filter(([, e]) => e.path === rel && typeof e.sha256 === "string");
  if (hits.length !== 1) throw new Error(`${rel}: ${hits.length === 0 ? "no" : "more than one"} pin entry with this path in ${pinsRel}; an unpinned key is never timed`);
  return (hits[0] as [string, unknown])[0];
}

export interface V4KeyResolved {
  zkey: ArtifactSpec;
  vkey: ArtifactSpec;
  keyLabel: string;
  isDevKey: boolean;
}

export function resolveV4Key(o: V4KeyOptions = {}): V4KeyResolved {
  const dev = VERSIONS.v4;
  const zkeyRel = o.zkey === undefined ? dev.zkey.rel : cleanRel(o.zkey, "--v4-zkey");
  const vkeyRel = o.vkey === undefined ? dev.vkey.rel : cleanRel(o.vkey, "--v4-vkey");
  if ((o.zkey === undefined) !== (o.vkey === undefined)) throw new Error("--v4-zkey and --v4-vkey go together");
  const isDevKey = zkeyRel === dev.zkey.rel && vkeyRel === dev.vkey.rel;
  if (!isDevKey && (o.label === undefined || o.label.trim() === "")) throw new Error("a non-default v4 key needs --v4-key-label (for example 'ceremony key')");
  if (!isDevKey && o.label !== undefined && /\bdev\b/i.test(o.label)) throw new Error("a non-default v4 key must not carry a dev label");
  const keyLabel = isDevKey ? DEV_KEY_LABEL : (o.label as string).trim();
  if (keyLabel.length > 80 || /[\\/:]/.test(keyLabel)) throw new Error("--v4-key-label: short text without slashes or colons");
  const pinsRel = o.pins === undefined ? "setup/pins_v4.json" : cleanRel(o.pins, "--v4-pins");
  if (isDevKey && pinsRel === "setup/pins_v4.json") return { zkey: dev.zkey, vkey: dev.vkey, keyLabel, isDevKey };
  return {
    zkey: { rel: zkeyRel, pin: { file: pinsRel, key: pinKeyForPath(pinsRel, zkeyRel) } },
    vkey: { rel: vkeyRel, pin: { file: pinsRel, key: pinKeyForPath(pinsRel, vkeyRel) } },
    keyLabel,
    isDevKey,
  };
}

// ------------------------------------------------------------------ circuit specs

export type InputSource = { kind: "bench-lock"; version: "v2" | "v3" | "v4" } | { kind: "eddsa-fixture" };

export interface CircuitSpec {
  circuit: Circuit;
  keyLabel: string;
  wasm: ArtifactSpec;
  zkey: ArtifactSpec;
  vkey: ArtifactSpec;
  input: InputSource;
  inputSource: string;
  note: string;
  /** circom optimisation level of the build that is timed. */
  optimization: string;
  /** Repo-relative circuit info record with nConstraints and nWires. */
  infoRel: string;
}

export function circuitSpecs(v4: V4KeyOptions = {}): Record<Circuit, CircuitSpec> {
  const k4 = resolveV4Key(v4);
  return {
    v2: {
      circuit: "v2",
      keyLabel: VERSIONS.v2.keyLabel,
      wasm: VERSIONS.v2.wasm,
      zkey: VERSIONS.v2.zkey,
      vkey: VERSIONS.v2.vkey,
      input: { kind: "bench-lock", version: "v2" },
      inputSource: `${BENCH_LOCK_REL} v2 (harness/fixture.ts buildFixtureProofInput())`,
      note: "v2 as published (committed build and key)",
      optimization: "--O1 (circom 2.2.3 default, the published v2 build)",
      infoRel: "circuits/build/circuit_info.json",
    },
    v2o2: {
      circuit: "v2o2",
      keyLabel: V2O2_KEY_LABEL,
      wasm: { rel: V2O2_FILES.wasm, pin: { file: PINS_CMP_REL, key: PIN_KEYS.v2o2.wasm } },
      zkey: { rel: V2O2_FILES.zkey, pin: { file: PINS_CMP_REL, key: PIN_KEYS.v2o2.zkey } },
      vkey: { rel: V2O2_FILES.vkey, pin: { file: PINS_CMP_REL, key: PIN_KEYS.v2o2.vkey } },
      input: { kind: "bench-lock", version: "v2" },
      inputSource: `${BENCH_LOCK_REL} v2 (the v2 input; same circuit source)`,
      note: "the frozen v2 circuit source compiled at --O2 (harness/v4/cmp/build_v2_o2.ts): a build variant that was never shipped, with a timing key",
      optimization: "--O2",
      infoRel: V2O2_FILES.info,
    },
    v3: {
      circuit: "v3",
      keyLabel: VERSIONS.v3.keyLabel,
      wasm: VERSIONS.v3.wasm,
      zkey: VERSIONS.v3.zkey,
      vkey: VERSIONS.v3.vkey,
      input: { kind: "bench-lock", version: "v3" },
      inputSource: `${BENCH_LOCK_REL} v3 (harness/fixture.ts buildFixtureProofInputV3())`,
      note: "committed v3 artifacts",
      optimization: "--O2",
      infoRel: "circuits/build/v3/circuit_info.json",
    },
    v4: {
      circuit: "v4",
      keyLabel: k4.keyLabel,
      wasm: VERSIONS.v4.wasm,
      zkey: k4.zkey,
      vkey: k4.vkey,
      input: { kind: "bench-lock", version: "v4" },
      inputSource: `${BENCH_LOCK_REL} v4 (harness/v4/bench/inputs.ts buildFixtureProofInputV4(); key-independent)`,
      note: k4.isDevKey ? "committed v4 circuit, dev key" : `committed v4 circuit, ${k4.keyLabel}`,
      optimization: "--O2",
      infoRel: "circuits/build/v4/circuit_info.json",
    },
    eddsa: {
      circuit: "eddsa",
      keyLabel: "throwaway baseline key",
      wasm: { rel: EDDSA_FILES.wasm, pin: { file: PINS_CMP_REL, key: PIN_KEYS.eddsa.wasm } },
      zkey: { rel: EDDSA_FILES.zkey, pin: { file: PINS_CMP_REL, key: PIN_KEYS.eddsa.zkey } },
      vkey: { rel: EDDSA_FILES.vkey, pin: { file: PINS_CMP_REL, key: PIN_KEYS.eddsa.vkey } },
      input: { kind: "eddsa-fixture" },
      inputSource: "harness/v4/cmp/eddsa_fixture.ts buildEddsaFixture() (fixture issuer key from a public string)",
      note: "EdDSA-in-circuit baseline (not PQ, not v4), committed throwaway key",
      optimization: "--O2",
      infoRel: EDDSA_FILES.info,
    },
  };
}

export interface CircuitArtifacts {
  wasm: ArtifactRecord;
  zkey: ArtifactRecord;
  vkey: ArtifactRecord;
}

/** Hash the three artifacts and compare each with its pin (throws on drift or a missing pin file entry). */
export function checkCircuitArtifacts(s: CircuitSpec): CircuitArtifacts {
  for (const a of [s.wasm, s.zkey, s.vkey]) {
    if (a.pin) {
      const pf = abs(a.pin.file);
      if (!fs.existsSync(pf)) throw new Error(`${s.circuit}: pin file ${a.pin.file} missing (run harness/v4/cmp/build_v2_o2.ts first)`);
      const pins = JSON.parse(fs.readFileSync(pf, "utf8")) as Record<string, unknown>;
      if (!(a.pin.key in pins)) throw new Error(`${s.circuit}: no pin '${a.pin.key}' in ${a.pin.file}`);
    }
  }
  return { wasm: checkArtifact(s.wasm), zkey: checkArtifact(s.zkey), vkey: checkArtifact(s.vkey) };
}

// ------------------------------------------------------------------ condition notes (env.json, summary)

export interface ConditionNote {
  note: string;
  /** circom optimisation level of the timed build (null: no circuit). */
  optimization: string | null;
  nConstraints: number | null;
  nWires: number | null;
  /** Where nConstraints and nWires come from (repo-relative), or the code the condition runs. */
  source: string | null;
  keyLabel: string;
}

export const CURVE_NOTE =
  "no circuit: one fresh process that only builds the bn128 curve as snarkJS prove does first (ffjavascript 0.3.0, the copy nested under snarkjs, buildBn128(): wasm plus one worker thread per logical core)";
export const WALLET_NOTE =
  "wallet rebuild of the two published trees in a fresh process; poseidonInit = the first getPoseidon() (circomlibjs buildPoseidon on its own ffjavascript: a single-thread bn128 build plus the Poseidon constants), not the prover's multi-threaded curve build of the curve condition";

/** Per-condition notes for env.json and the summary: what each condition is, its optimisation level and constraint count. */
export function conditionNotes(names: readonly string[], specs: Record<Circuit, CircuitSpec>, smoke: boolean): Record<string, ConditionNote> {
  const out: Record<string, ConditionNote> = {};
  for (const n of names) {
    if (n === CURVE_CONDITION) {
      out[n] = { note: CURVE_NOTE, optimization: null, nConstraints: null, nWires: null, source: "harness/v4/cmp/child_curve.ts", keyLabel: "none (no key)" };
      continue;
    }
    if (n === "wallet1e5" || n === "wallet1e6") {
      const z = walletSize(n, smoke);
      out[n] = {
        note: `${WALLET_NOTE}; ${z.credentials} credentials, ${z.revocations} revocation keys`,
        optimization: null,
        nConstraints: null,
        nWires: null,
        source: "harness/v4/cmp/child_wallet.ts",
        keyLabel: "none (no key)",
      };
      continue;
    }
    const s = specs[n as Circuit];
    if (!s) throw new Error(`no circuit spec for condition ${n}`);
    let nConstraints: number | null = null;
    let nWires: number | null = null;
    try {
      const info = JSON.parse(fs.readFileSync(abs(s.infoRel), "utf8")) as { nConstraints?: unknown; nWires?: unknown };
      if (typeof info.nConstraints === "number") nConstraints = info.nConstraints;
      if (typeof info.nWires === "number") nWires = info.nWires;
    } catch {
      /* recorded as null */
    }
    out[n] = { note: s.note, optimization: s.optimization, nConstraints, nWires, source: s.infoRel, keyLabel: s.keyLabel };
  }
  return out;
}

/** The given names in the canonical order of `all`, so the typed order of --conditions never changes the schedule. */
export function canonicalOrder<T extends string>(names: readonly T[], all: readonly T[]): T[] {
  for (const n of names) if (!all.includes(n)) throw new Error(`unknown condition ${n}`);
  return all.filter((c) => names.includes(c));
}

// ------------------------------------------------------------------ code identity

/**
 * Code whose change alters what a timed run measures; a resumed campaign (and a new warm session
 * of an existing warm campaign) refuses if any of it changed.
 */
export const TIMED_CODE: Readonly<Record<"prove" | "curve" | "wallet" | "warm", readonly string[]>> = Object.freeze({
  prove: ["harness/v4/bench/child_prove.ts"],
  /** The warm series times its own iterate() (the calls of child_prove.ts, snarkJS path). */
  warm: ["harness/v4/cmp/warm.ts"],
  curve: ["harness/v4/cmp/child_curve.ts"],
  wallet: [
    "harness/v4/cmp/child_wallet.ts",
    "harness/v4/cmp/wallet_data.ts",
    "packages/v4/src/published.ts",
    "packages/v4/src/imt.ts",
    "packages/v4/src/encoding.ts",
    "packages/v4/src/constants.ts",
    "packages/common/src/encoding.ts",
  ],
});

/** Runner code (recorded, not compared on resume; part of the committed check of a real run). */
export const RUNNER_CODE: readonly string[] = [
  "harness/v4/cmp/spec.ts",
  "harness/v4/cmp/runner.ts",
  "harness/v4/cmp/cold.ts",
  "harness/v4/cmp/warm.ts",
  "harness/v4/cmp/inputs.ts",
  "harness/v4/cmp/eddsa_fixture.ts",
  "harness/v4/cmp/wallet_data.ts",
  "harness/v4/cmp/child_wallet.ts",
  "harness/v4/cmp/child_curve.ts",
  "harness/v4/cmp/log_scrub.ts",
  "harness/v4/cmp/smoke_reset.ts",
  "harness/v4/bench/child_prove.ts",
  "harness/v4/bench/lib.ts",
  "harness/v4/bench/guard.ts",
  "harness/v4/lib/quiesce.ts",
  "harness/v4/lib/markers.ts",
  "harness/v4/lib/seeds.ts",
];

/**
 * Files besides the code that the committed check of a real run covers: the protocol addendum,
 * the pins, the input lock folder, the analysis and the window script.
 */
export function committedExtras(smoke: boolean): string[] {
  return [CMP_PROTOCOL_REL, PINS_CMP_REL, repoRel(cmpInputsDir(smoke)), "scripts/cmp/analyze_cmp.py", "scripts/cmp/quiet_window_cmp.sh"];
}

function repoRel(p: string): string {
  return path.relative(REPO_ROOT, p).split(path.sep).join("/");
}

function git(args: readonly string[]): string {
  return execFileSync("git", [...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" },
    stdio: ["ignore", "pipe", "ignore"],
    windowsHide: true,
  });
}

/**
 * true when every given path is tracked and unchanged at HEAD (read-only `git status --porcelain`
 * and `git ls-files`; a folder needs at least one tracked file and no untracked or changed one);
 * null when git is unavailable.
 */
export function gitClean(files: readonly string[]): boolean | null {
  try {
    if (git(["status", "--porcelain", "--untracked-files=all", "--", ...files]).trim() !== "") return false;
    const tracked = new Set(
      git(["ls-files", "--", ...files])
        .split(/\r?\n/)
        .filter(Boolean)
    );
    for (const f of files) {
      const isDir = fs.existsSync(abs(f)) && fs.statSync(abs(f)).isDirectory();
      const ok = isDir ? [...tracked].some((t) => t.startsWith(`${f}/`)) : tracked.has(f);
      if (!ok) return false;
    }
    return true;
  } catch {
    return null;
  }
}

export interface CodeRecord {
  timed: Record<string, string>;
  runner: Record<string, string>;
  /** Every path of the committed check (code, protocol addendum, pins, input lock, analysis, window script). */
  committedCheck: string[];
  /** true when every path of committedCheck is tracked and unchanged at gitHead (read-only git). */
  committedAtHead: boolean | null;
  basis: string;
}

export function codeRecord(timedFiles: readonly string[], smoke: boolean): CodeRecord {
  const h = (r: string) => sha256FileHex(abs(r));
  const timed = Object.fromEntries(timedFiles.map((f) => [f, h(f)]));
  const runner = Object.fromEntries(RUNNER_CODE.filter((f) => fs.existsSync(abs(f))).map((f) => [f, h(f)]));
  const committedCheck = [...new Set([...timedFiles, ...Object.keys(runner), ...committedExtras(smoke)])];
  return {
    timed,
    runner,
    committedCheck,
    committedAtHead: gitClean(committedCheck),
    basis: "SHA-256 of each file; committedAtHead from read-only `git status --porcelain` and `git ls-files` of committedCheck",
  };
}

// ------------------------------------------------------------------ real-mode rules (docs/v4/CMP.md)

/** Fixed parameters of a real (not smoke) run; the runners refuse any other value. */
export const REAL_MODE = Object.freeze({
  prove: Object.freeze({ n: 30, idleSec: 600, leadSec: 20, maxPostpone: 10, postponeStepSec: 60, childTimeoutSec: 900 }),
  wallet: Object.freeze({ n: 10, idleSec: 600, leadSec: 20, maxPostpone: 10, postponeStepSec: 60, childTimeoutSec: 900 }),
  warm: Object.freeze({ n: 30, warmup: 5, settleSec: 600, blockGapSec: 2 }),
});

export interface RealModeParams {
  series: "prove" | "wallet" | "warm";
  platform: string;
  /** Run parameters as given (the keys of REAL_MODE[series] are compared). */
  params: Readonly<Record<string, number>>;
  /** v4 is among the conditions. */
  v4Included: boolean;
  isDevKey: boolean;
  allowDevKey: boolean;
  committedAtHead: boolean | null;
  allowUncommitted: boolean;
}

/** Everything that stops a real run (empty when it may start). Pure: no file, clock or git access. */
export function realModeProblems(p: RealModeParams): string[] {
  const out: string[] = [];
  if (p.platform !== "win32") out.push(`the cmp series runs on native Windows only (platform ${p.platform}; D-034 skips the WSL cmp campaign)`);
  const want = REAL_MODE[p.series] as Readonly<Record<string, number>>;
  for (const [k, v] of Object.entries(want)) {
    if (p.params[k] !== v) out.push(`${k} must be ${v} in a real ${p.series} series (got ${String(p.params[k])})`);
  }
  if (p.v4Included && p.isDevKey && !p.allowDevKey) {
    out.push("v4 with the dev key: D-034 runs this series after the key ceremony; pass the ceremony key (--v4-zkey/--v4-vkey/--v4-key-label/--v4-pins) or --allow-dev-key (rows labelled dev)");
  }
  if (p.committedAtHead !== true && !p.allowUncommitted) {
    out.push(
      `the code, docs/v4/CMP.md, the pins, the input lock, the analysis and the window script are not all committed and unchanged at HEAD (committedAtHead ${String(p.committedAtHead)}); commit first, or pass --allow-uncommitted (recorded in env.json)`
    );
  }
  return out;
}

// ------------------------------------------------------------------ CLI helpers

/** Comma list of allowed values (no default handling). */
export function parseList<T extends string>(raw: string | undefined, allowed: readonly T[], what: string): T[] | undefined {
  if (raw === undefined) return undefined;
  const xs = raw.split(",").map((s) => s.trim()).filter(Boolean) as T[];
  if (xs.length === 0) throw new Error(`${what}: empty list`);
  for (const x of xs) if (!allowed.includes(x)) throw new Error(`${what}: unknown value ${x} (allowed: ${allowed.join(", ")})`);
  if (new Set(xs).size !== xs.length) throw new Error(`${what}: duplicate value`);
  return xs;
}
