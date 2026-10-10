import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { newMemEmptyTrie } from "circomlibjs";
import { REPO_ROOT } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";
import { REV_DEPTH, REV_KEY_BITS } from "@pqid/v4/constants";
import { getPoseidon, poseidonBig, imtLeafHash } from "@pqid/v4/encoding";

/**
 * B2 (TASKS B2, review finding T8; docs/v4/B2_REVOCATION_CAPACITY.md).
 *
 * 1. Compiles every revocation gadget in circuits/v4/research/ with circom 2.2.3 at --O2
 *    and --O1 and reads the constraint counts with snarkjs r1cs info [M]. The .r1cs files
 *    are kept in circuits/build/v4/research/ (gitignored).
 * 2. Checks two depth boundaries on the compiled circuits [M]:
 *    - circomlib SMTVerifier(32) accepts a non-membership path of 31 levels and rejects
 *      one of 32 levels (its SMTLevIns requires the last sibling to be 0);
 *    - ImtNonMembership(30) accepts lowIndex = 2^30 - 1 and rejects lowIndex = 2^30.
 * 3. Computes the capacity of each option against the target (10^9 revocations per
 *    issuer, failure probability at most 2^-40) [S], cross-checks the review's T8 numbers
 *    for v3's depth-32 SMT with the formulas and a seeded simulation [S], and picks the
 *    option with the fewest constraints among those that meet the target.
 * Writes results/v4/revocation_capacity.json.
 */

const RESEARCH_DIR = path.join(REPO_ROOT, "circuits", "v4", "research");
const BUILD_DIR = path.join(REPO_ROOT, "circuits", "build", "v4", "research");
const RESULTS_FILE = path.join(REPO_ROOT, "results", "v4", "revocation_capacity.json");
const BENCH_RUNNING = path.join(REPO_ROOT, "results", "v4", "bench", "RUNNING");

const TARGET_REVOCATIONS = 1e9;
const TARGET_LOG2_FAILURE = -40;

function circomBinary(): string {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  if (process.platform === "win32" && fs.existsSync(win)) return win;
  return "circom";
}

function rel(p: string): string {
  return path.relative(REPO_ROOT, p).split(path.sep).join("/");
}

function sha256File(p: string): string {
  return createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

function stripAnsi(s: string): string {
  const esc = String.fromCharCode(27);
  return s
    .split(esc)
    .map((part, i) => (i === 0 ? part : part.replace(/^\[[0-9;]*m/, "")))
    .join("");
}

const quietLogger = { info: () => undefined, warn: () => undefined, error: () => undefined, debug: () => undefined };

// ------------------------------------------------------------------ gadgets

type Family = "imt" | "smt";
type Variant = "full" | "bare";
interface GadgetSpec {
  id: string;
  file: string;
  family: Family;
  depth: number;
  variant: Variant;
}

const IMT_DEPTHS = [30, 32];
const SMT_DEPTHS = [32, 70, 71, 99, 100, 128];

function specs(): GadgetSpec[] {
  const out: GadgetSpec[] = [];
  for (const variant of ["full", "bare"] as const) {
    const tag = variant === "bare" ? "bare_" : "";
    for (const d of IMT_DEPTHS) {
      out.push({ id: `imt_${tag}d${d}`, file: `imt_nonmembership_${tag}d${d}.circom`, family: "imt", depth: d, variant });
    }
    for (const d of SMT_DEPTHS) {
      out.push({ id: `smt_${tag}d${d}`, file: `smt_nonmembership_${tag}d${d}.circom`, family: "smt", depth: d, variant });
    }
  }
  return out;
}

interface CompileStats {
  optimization: "--O1" | "--O2";
  nConstraints: number;
  nonLinearConstraints: number;
  linearConstraints: number;
  nWires: number;
  nPubInputs: number;
  nPrvInputs: number;
  nOutputs: number;
  templateInstances: number | null;
  r1cs: string;
  r1csSha256: string;
  label: "[M]";
}

function grabInt(text: string, re: RegExp): number | null {
  const m = re.exec(text);
  return m && m[1] ? Number(m[1]) : null;
}

async function compileCount(spec: GadgetSpec, opt: "O1" | "O2"): Promise<CompileStats> {
  const src = path.join(RESEARCH_DIR, spec.file);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-b2-"));
  try {
    const stdout = stripAnsi(
      execFileSync(circomBinary(), [src, `--${opt}`, "--r1cs", "-o", tmp], { cwd: REPO_ROOT, encoding: "utf8" })
    );
    const base = spec.file.replace(/\.circom$/, "");
    const built = path.join(tmp, `${base}.r1cs`);
    const kept = path.join(BUILD_DIR, `${base}_${opt}.r1cs`);
    fs.copyFileSync(built, kept);
    const snarkjs = await import("snarkjs");
    const info = await snarkjs.r1cs.info(kept);
    const nonLinear = grabInt(stdout, /^non-linear constraints:\s*(\d+)/m);
    const linear = grabInt(stdout, /^linear constraints:\s*(\d+)/m);
    if (nonLinear === null || linear === null) throw new Error(`cannot parse circom output for ${spec.file}`);
    if (nonLinear + linear !== info.nConstraints) {
      throw new Error(`${spec.file} ${opt}: circom reports ${nonLinear}+${linear}, r1cs has ${info.nConstraints}`);
    }
    return {
      optimization: opt === "O1" ? "--O1" : "--O2",
      nConstraints: info.nConstraints,
      nonLinearConstraints: nonLinear,
      linearConstraints: linear,
      nWires: info.nVars,
      nPubInputs: info.nPubInputs,
      nPrvInputs: info.nPrvInputs,
      nOutputs: info.nOutputs,
      templateInstances: grabInt(stdout, /^template instances:\s*(\d+)/m),
      r1cs: rel(kept),
      r1csSha256: sha256File(kept),
      label: "[M]",
    };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

interface Compiled {
  dir: string;
  r1cs: string;
  wasm: string;
}

function compileWasm(file: string, tmpRoot: string): Compiled {
  const base = file.replace(/\.circom$/, "");
  const dir = path.join(tmpRoot, base);
  fs.mkdirSync(dir, { recursive: true });
  execFileSync(circomBinary(), [path.join(RESEARCH_DIR, file), "--O2", "--r1cs", "--wasm", "-o", dir], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  return { dir, r1cs: path.join(dir, `${base}.r1cs`), wasm: path.join(dir, `${base}_js`, `${base}.wasm`) };
}

/** Run the witness generator; returns whether it accepted and, if so, whether the R1CS holds. */
async function tryWitness(c: Compiled, input: Record<string, unknown>, name: string): Promise<{ witnessAccepted: boolean; r1csSatisfied: boolean | null; error?: string }> {
  const snarkjs = await import("snarkjs");
  const out = path.join(c.dir, `${name}.wtns`);
  // The witness calculator prints failed asserts on stderr; keep the harness log readable.
  const origErr = console.error;
  const origLog = console.log;
  console.error = () => undefined;
  console.log = () => undefined;
  try {
    await snarkjs.wtns.calculate(input, c.wasm, out);
  } catch (e) {
    const msg = String(e);
    return { witnessAccepted: false, r1csSatisfied: null, error: /Assert Failed/.test(msg) ? "Assert Failed" : msg.slice(0, 200) };
  } finally {
    console.error = origErr;
    console.log = origLog;
  }
  const ok = await snarkjs.wtns.check(c.r1cs, out, quietLogger);
  return { witnessAccepted: true, r1csSatisfied: ok };
}

// ------------------------------------------------------------ boundary checks

async function smtDepthBoundary(tmpRoot: string): Promise<Record<string, unknown>> {
  const nLevels = 32;
  const c = compileWasm(`smt_nonmembership_bare_d${nLevels}.circom`, tmpRoot);
  const run = async (keys: bigint[], probe: bigint, name: string): Promise<Record<string, unknown>> => {
    const tree = await newMemEmptyTrie();
    for (const k of keys) await tree.insert(k, 1n); // v3 revoked-leaf value
    const res = await tree.find(probe);
    if (res.found) throw new Error("probe unexpectedly in the tree");
    const F = tree.F;
    const siblings = res.siblings.map((s) => F.toObject(s).toString());
    const pathLength = siblings.length;
    while (siblings.length < nLevels) siblings.push("0");
    const input = {
      key: probe.toString(),
      root: F.toObject(tree.root).toString(),
      siblings,
      oldKey: res.isOld0 ? "0" : F.toObject(res.notFoundKey as Uint8Array).toString(),
      oldValue: res.isOld0 ? "0" : F.toObject(res.notFoundValue as Uint8Array).toString(),
      isOld0: res.isOld0 ? "1" : "0",
    };
    const r = await tryWitness(c, input, name);
    return {
      revokedKeys: keys.map((k) => k.toString()),
      probeKey: probe.toString(),
      sharedLowBits: sharedLowBits(keys[0] as bigint, keys[1] as bigint),
      pathLength,
      lastSiblingNonZero: pathLength === nLevels,
      ...r,
    };
  };
  // Two keys sharing their low j bits sit at depth j + 1 (circomlibjs splits on key bits, LSB first).
  const shallow = await run([1n, 1n + (1n << 30n)], 1n + (1n << 31n), "smt_leaf_depth_31");
  const deep = await run([1n, 1n + (1n << 31n)], 1n + (1n << 32n), "smt_leaf_depth_32");
  const ok = shallow["witnessAccepted"] === true && shallow["r1csSatisfied"] === true && deep["witnessAccepted"] === false;
  return {
    circuit: `circuits/v4/research/smt_nonmembership_bare_d${nLevels}.circom (--O2)`,
    nLevels,
    leafAtDepth31: shallow,
    leafAtDepth32: deep,
    conclusion: ok
      ? `SMTVerifier(${nLevels}) proves non-membership only on paths of at most ${nLevels - 1} levels: effective path bits = nLevels - 1`
      : "UNEXPECTED: boundary did not behave as nLevels - 1",
    effectivePathBits: ok ? nLevels - 1 : null,
    label: "[M]",
  };
}

function sharedLowBits(a: bigint, b: bigint): number {
  let x = a ^ b;
  let n = 0;
  while ((x & 1n) === 0n && n < 256) {
    x >>= 1n;
    n++;
  }
  return n;
}

async function imtIndexBoundary(tmpRoot: string): Promise<Record<string, unknown>> {
  const depth = REV_DEPTH;
  const c = compileWasm(`imt_nonmembership_d${depth}.circom`, tmpRoot);
  const poseidon = await getPoseidon();
  // A leaf (lowValue, lowNext) at the last slot, all other slots empty: the circuit only
  // rebuilds the path, so this isolates the lowIndex range check Num2Bits(depth).
  const lowValue = 5n << 200n;
  const lowNext = 7n << 200n;
  const key = 6n << 200n;
  const zeros: bigint[] = [0n];
  for (let l = 0; l < depth; l++) zeros.push(poseidonBig(poseidon, [zeros[l] as bigint, zeros[l] as bigint]));
  const lowPath = zeros.slice(0, depth).map((z) => z.toString());
  const rootAt = (index: bigint): bigint => {
    let cur = imtLeafHash(poseidon, lowValue, lowNext);
    let i = index;
    for (let l = 0; l < depth; l++) {
      const z = zeros[l] as bigint;
      cur = (i & 1n) === 0n ? poseidonBig(poseidon, [cur, z]) : poseidonBig(poseidon, [z, cur]);
      i >>= 1n;
    }
    return cur;
  };
  const limbs = { credIDHi: (key >> 123n).toString(), credIDLo: ((key & ((1n << 123n) - 1n)) << 5n).toString() };
  const last = (1n << BigInt(depth)) - 1n;
  const beyond = 1n << BigInt(depth);
  const inputFor = (index: bigint) => ({
    ...limbs,
    root: rootAt(index).toString(),
    lowIndex: index.toString(),
    lowValue: lowValue.toString(),
    lowNext: lowNext.toString(),
    lowPath,
  });
  const a = await tryWitness(c, inputFor(last), "imt_index_last");
  const b = await tryWitness(c, inputFor(beyond), "imt_index_beyond");
  return {
    circuit: `circuits/v4/research/imt_nonmembership_d${depth}.circom (--O2)`,
    depth,
    lowIndexLastSlot: { lowIndex: last.toString(), ...a },
    lowIndexBeyond: { lowIndex: beyond.toString(), ...b },
    conclusion:
      a.witnessAccepted && a.r1csSatisfied && !b.witnessAccepted
        ? `all 2^${depth} slots are addressable (lowIndex < 2^${depth}); with the sentinel at index 0 the tree holds 2^${depth} - 1 keys`
        : "UNEXPECTED: index boundary did not behave as 2^depth",
    label: "[M]",
  };
}

// ------------------------------------------------------------ capacity model [S]

const LN2 = Math.log(2);

/** log2 of the union bound n / 2^b: some existing key shares all b path bits with the new one. */
function perInsertionLog2(n: number, b: number): number {
  return Math.log2(n) - b;
}
/** log2 of the union bound n(n-1) / 2^(b+1): some pair among n keys shares all b path bits. */
function cumulativeLog2(n: number, b: number): number {
  return Math.log2(n) + Math.log2(n - 1) - b - 1;
}
function isqrt(v: bigint): bigint {
  if (v < 2n) return v;
  let x = BigInt(Math.floor(Math.sqrt(Number(v))));
  while (x * x > v) x -= 1n;
  while ((x + 1n) * (x + 1n) <= v) x += 1n;
  return x;
}
/** Largest n with n(n-1)/2^(b+1) <= 2^-40, i.e. n(n-1) <= 2^(b-39). */
function maxLoadCumulative(b: number): bigint {
  const e = b + 1 + TARGET_LOG2_FAILURE; // exponent of 2 bounding n(n-1)
  if (e < 1) return 1n; // n(n-1) must be < 2: one key
  const m = 1n << BigInt(e);
  let n = (1n + isqrt(1n + 4n * m)) / 2n;
  while (n * (n - 1n) > m) n -= 1n;
  while ((n + 1n) * n <= m) n += 1n;
  return n;
}
/** Largest existing load n with n/2^b <= 2^-40 (the next insertion still meets the target). */
function maxLoadPerInsertion(b: number): bigint {
  const e = b + TARGET_LOG2_FAILURE;
  return e < 0 ? 0n : 1n << BigInt(e);
}

function fmtLog2(x: number): string {
  return `2^${x.toFixed(3)}`;
}

function smtCapacity(bits: number): Record<string, unknown> {
  const n = TARGET_REVOCATIONS;
  const pi = perInsertionLog2(n, bits);
  const cu = cumulativeLog2(n, bits);
  return {
    pathBits: bits,
    perInsertionFailureAt1e9: { log2: pi, value: Math.pow(2, pi), text: fmtLog2(pi) },
    cumulativeFailureAt1e9: {
      log2: cu,
      unionBound: Math.pow(2, cu),
      poissonApprox: -Math.expm1(-Math.pow(2, cu)),
      text: fmtLog2(cu),
    },
    meetsA_perInsertion: pi <= TARGET_LOG2_FAILURE,
    meetsB_cumulative: cu <= TARGET_LOG2_FAILURE,
    maxLoadPerInsertionAt2m40: maxLoadPerInsertion(bits).toString(),
    maxLoadCumulativeAt2m40: maxLoadCumulative(bits).toString(),
    label: "[S]",
  };
}

// ------------------------------------------------------------ v3 cross-check [S]

/** Smallest n with P(some pair among n keys shares all b bits) >= 1/2 (exact product). */
function fiftyPercentPoint(b: number): number {
  const N = Math.pow(2, b);
  let logNone = 0;
  let n = 1;
  while (logNone > -LN2) {
    logNone += Math.log1p(-n / N); // adding key n+1 to n keys without collision
    n++;
  }
  return n;
}

/** Expected failed insertions among n inserts into 2^b prefixes (occupancy): n - N(1 - (1 - 1/N)^n). */
function expectedFailures(n: number, b: number): number {
  const N = Math.pow(2, b);
  return n + N * Math.expm1(n * Math.log1p(-1 / N));
}

/** xoshiro128** (seeded, reproducible 32-bit output). */
function xoshiro128ss(seed: [number, number, number, number]): () => number {
  let [a, b, c, d] = seed;
  return () => {
    const r = Math.imul(rotl(Math.imul(b, 5), 7), 9) >>> 0;
    const t = b << 9;
    c ^= a;
    d ^= b;
    b ^= c;
    a ^= d;
    c ^= t;
    d = rotl(d, 11);
    return r;
  };
}
function rotl(x: number, k: number): number {
  return (x << k) | (x >>> (32 - k));
}

function simulate(bits: number, seed: [number, number, number, number]): Record<string, unknown> {
  const rnd = xoshiro128ss(seed);
  const draw = bits === 32 ? () => rnd() : () => rnd() >>> (32 - bits);
  const perMillionTrials = 50;
  const fails: number[] = [];
  for (let t = 0; t < perMillionTrials; t++) {
    const seen = new Set<number>();
    let f = 0;
    for (let i = 0; i < 1_000_000; i++) {
      const v = draw();
      if (seen.has(v)) f++;
      else seen.add(v);
    }
    fails.push(f);
  }
  const firstTrials = 2000;
  const firsts: number[] = [];
  for (let t = 0; t < firstTrials; t++) {
    const seen = new Set<number>();
    for (;;) {
      const v = draw();
      if (seen.has(v)) {
        firsts.push(seen.size + 1); // the failing insertion is number seen.size + 1
        break;
      }
      seen.add(v);
    }
  }
  firsts.sort((x, y) => x - y);
  const median = ((firsts[firstTrials / 2 - 1] as number) + (firsts[firstTrials / 2] as number)) / 2;
  const mean = fails.reduce((s, x) => s + x, 0) / fails.length;
  return {
    pathBits: bits,
    prng: "xoshiro128** (32-bit), seed " + seed.map((s) => "0x" + (s >>> 0).toString(16)).join(","),
    failuresPerMillion: { trials: perMillionTrials, mean, min: Math.min(...fails), max: Math.max(...fails) },
    firstFailure: { trials: firstTrials, median, min: firsts[0], max: firsts[firsts.length - 1] },
    label: "[S]",
  };
}

// ------------------------------------------------------------------- main

async function main(): Promise<void> {
  if (fs.existsSync(BENCH_RUNNING)) {
    console.error("results/v4/bench/RUNNING exists: a timed benchmark is active, no compiles now (docs/BENCHMARK_POLICY.md).");
    process.exit(2);
  }
  fs.mkdirSync(BUILD_DIR, { recursive: true });
  fs.mkdirSync(path.dirname(RESULTS_FILE), { recursive: true });

  const circomVersion = execFileSync(circomBinary(), ["--version"], { encoding: "utf8" }).trim();
  const pkgVersion = (name: string): string =>
    (JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "node_modules", name, "package.json"), "utf8")) as { version: string }).version;

  // 1. constraint counts
  const gadgets: Array<Record<string, unknown>> = [];
  const counts = new Map<string, { O1: CompileStats; O2: CompileStats }>();
  for (const s of specs()) {
    const O2 = await compileCount(s, "O2");
    const O1 = await compileCount(s, "O1");
    counts.set(s.id, { O1, O2 });
    console.log(`[b2] ${s.id.padEnd(16)} O2=${O2.nConstraints} O1=${O1.nConstraints}`);
    gadgets.push({
      id: s.id,
      source: `circuits/v4/research/${s.file}`,
      sourceSha256: sha256File(path.join(RESEARCH_DIR, s.file)),
      family: s.family,
      depth: s.depth,
      variant: s.variant,
      publicInputs: s.variant === "full" ? ["root"] : ["key", "root"],
      keyDerivation:
        s.variant === "bare"
          ? "none (key is a public input)"
          : s.family === "imt"
            ? "Num2Bits(128) on credIDHi and credIDLo; revKey = linear combination of the bits"
            : "Num2Bits(128) on credIDHi and credIDLo; key = Poseidon(credIDHi, credIDLo)",
      tree:
        s.family === "imt"
          ? `ImtNonMembership(${s.depth}): Poseidon(3) leaf, MerkleRootV4(${s.depth}) with Num2Bits(${s.depth}) on lowIndex, 2 x LessThan(252)`
          : `circomlib SMTVerifier(${s.depth}) with fnc = 1, enabled = 1, value = 0, plus isOld0 * (isOld0 - 1) === 0`,
      O2,
      O1,
    });
  }
  const c = (id: string, opt: "O1" | "O2"): number => {
    const v = counts.get(id);
    if (!v) throw new Error(`missing gadget ${id}`);
    return v[opt].nConstraints;
  };

  // 2. boundary checks on compiled circuits
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-b2-wasm-"));
  let smtBoundary: Record<string, unknown>;
  let imtBoundary: Record<string, unknown>;
  try {
    smtBoundary = await smtDepthBoundary(tmpRoot);
    imtBoundary = await imtIndexBoundary(tmpRoot);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
  const measuredOffset = smtBoundary["effectivePathBits"] === 31 ? 1 : null;
  if (measuredOffset === null) throw new Error("SMT depth boundary check failed; see smtBoundary");
  console.log(`[b2] ${String(smtBoundary["conclusion"])}`);
  console.log(`[b2] ${String(imtBoundary["conclusion"])}`);

  // 3. capacity per option
  const minBitsA = Math.ceil(Math.log2(TARGET_REVOCATIONS) - TARGET_LOG2_FAILURE);
  const minBitsB = Math.ceil(Math.log2(TARGET_REVOCATIONS) + Math.log2(TARGET_REVOCATIONS - 1) - 1 - TARGET_LOG2_FAILURE);
  const options: Array<Record<string, unknown>> = [];
  for (const d of IMT_DEPTHS) {
    const capacity = 2 ** d - 1;
    const collLog2 = Math.log2(TARGET_REVOCATIONS) + Math.log2(TARGET_REVOCATIONS - 1) - (REV_KEY_BITS + 1);
    const meets = capacity >= TARGET_REVOCATIONS && collLog2 <= TARGET_LOG2_FAILURE;
    options.push({
      id: `imt_d${d}`,
      family: "imt",
      depth: d,
      constraintsO2: c(`imt_d${d}`, "O2"),
      constraintsO1: c(`imt_d${d}`, "O1"),
      treeOnlyConstraintsO2: c(`imt_bare_d${d}`, "O2"),
      capacityKeys: capacity,
      insertionFailureBelowCapacity: 0,
      keyCollisionAt1e9: { log2: collLog2, value: Math.pow(2, collLog2), text: fmtLog2(collLog2), label: "[S]" },
      keyCollisionPerInsertionAt1e9: {
        log2: Math.log2(TARGET_REVOCATIONS) - REV_KEY_BITS,
        text: fmtLog2(Math.log2(TARGET_REVOCATIONS) - REV_KEY_BITS),
        label: "[S]",
      },
      meetsA_perInsertion: meets,
      meetsB_cumulative: meets,
      nominal: { meetsA_perInsertion: meets, meetsB_cumulative: meets },
      qualifies: meets,
      label: "capacity [M] from the index boundary check; collision probability [S]",
    });
  }
  for (const d of SMT_DEPTHS) {
    const measured = smtCapacity(d - measuredOffset);
    const nominal = smtCapacity(d);
    options.push({
      id: `smt_d${d}`,
      family: "smt",
      depth: d,
      constraintsO2: c(`smt_d${d}`, "O2"),
      constraintsO1: c(`smt_d${d}`, "O1"),
      treeOnlyConstraintsO2: c(`smt_bare_d${d}`, "O2"),
      circuitLimit: measured,
      nominal,
      meetsA_perInsertion: measured["meetsA_perInsertion"],
      meetsB_cumulative: measured["meetsB_cumulative"],
      qualifies: measured["meetsB_cumulative"] === true,
    });
  }

  // 4. decision: fewest constraints among qualifying options
  const pick = (opt: "constraintsO2" | "constraintsO1", pred: (o: Record<string, unknown>) => boolean): Record<string, unknown> | null => {
    const q = options.filter(pred);
    if (q.length === 0) return null;
    return q.reduce((best, o) => ((o[opt] as number) < (best[opt] as number) ? o : best));
  };
  const qualB = (o: Record<string, unknown>): boolean => o["qualifies"] === true;
  const qualBNominal = (o: Record<string, unknown>): boolean =>
    (o["nominal"] as Record<string, unknown>)["meetsB_cumulative"] === true;
  const chosen = pick("constraintsO2", qualB);
  const chosenO1 = pick("constraintsO1", qualB);
  const chosenNominal = pick("constraintsO2", qualBNominal);
  if (!chosen) throw new Error("no option meets the target");
  const bestSmt = pick("constraintsO2", (o) => o["family"] === "smt" && qualB(o));
  const chosenId = chosen["id"] as string;
  const chosenDepth = chosen["depth"] as number;

  // 5. v3 cross-check (depth-32 SMT)
  const review = { fiftyPercentPoint: 77_000, failedInsertionsPerMillion: 116, source: "2.0/Review.txt finding T8 (specialist quote)" };
  const v3 = (bits: number, seed: [number, number, number, number]): Record<string, unknown> => ({
    pathBits: bits,
    fiftyPercentPointExact: fiftyPercentPoint(bits),
    fiftyPercentPointApprox: Math.sqrt(2 * LN2 * Math.pow(2, bits)),
    expectedFailuresPerMillionOccupancy: expectedFailures(1e6, bits),
    expectedFailuresPerMillionUnionBound: (1e6 * (1e6 - 1)) / Math.pow(2, bits + 1),
    simulation: simulate(bits, seed),
    label: "[S]",
  });

  const result = {
    schema: "pqid.v4.revocation_capacity/1",
    item: "B2 (TASKS.md), review finding T8",
    generatedBy: "harness/v4/revocation_capacity.ts",
    labels: {
      "[M]": "measured: circom/snarkjs constraint counts and witness-generator/R1CS checks on this host",
      "[S]": "computed from the stated probability model (union bounds, occupancy formula, seeded simulation)",
      "[A]": "assumption: credIDs (SHA3-256) and Poseidon keys behave as uniformly random bit strings",
    },
    host: hostMeta(),
    tools: {
      circom: circomVersion,
      snarkjs: pkgVersion("snarkjs"),
      circomlib: pkgVersion("circomlib"),
      circomlibjs: pkgVersion("circomlibjs"),
    },
    sources: {
      "circuits/v4/lib_v4.circom": sha256File(path.join(REPO_ROOT, "circuits", "v4", "lib_v4.circom")),
      "circuits/v4/research/revocation_gadgets.circom": sha256File(path.join(RESEARCH_DIR, "revocation_gadgets.circom")),
    },
    target: {
      revocationsPerIssuer: TARGET_REVOCATIONS,
      maxFailureProbability: "2^-40",
      criterionA: "per-insertion failure probability at load 10^9 <= 2^-40",
      criterionB: "cumulative failure probability over 10^9 insertions <= 2^-40 (stricter; used for the decision)",
      rule: "among options meeting criterion B, adopt the one with the fewest constraints (--O2, the setting v4 compiles with)",
    },
    formulas: {
      imt: {
        capacity: "depth d holds 2^d - 1 keys (index 0 is the sentinel (0, 2^251)); insertion is deterministic: failure probability 0 below capacity",
        keyCollision: "two credentials with the same 251-bit revKey: union bound n(n-1)/2^252 [A: revKey uniform]",
      },
      smt: {
        placement: "circomlibjs stores a key at the first level where its path prefix (key bits, least significant first) is unique; two keys sharing their low j bits sit at depth j + 1",
        circuitLimit:
          "circomlib SMTLevIns(nLevels) requires siblings[nLevels-1] = 0, so SMTVerifier(d) handles leaves at depth <= d - 1: effective path bits b = d - 1 (measured, see smtDepthBoundary)",
        nominalModel: "b = d path bits (the model in the review and in the B2 task text)",
        perInsertion: "P(new key shares all b path bits with one of n existing keys) <= n / 2^b",
        cumulative: "P(some pair among n keys shares all b path bits) <= n(n-1) / 2^(b+1); Poisson approximation 1 - exp(-n(n-1)/2^(b+1))",
        expectedFailures: "expected failed insertions among n inserts = n - 2^b (1 - (1 - 2^-b)^n) (occupancy)",
        keyCollision: "Poseidon(credIDHi, credIDLo) keys are field elements; two equal keys: about n(n-1)/(2p), negligible",
      },
      minimumPathBits: {
        criterionA: `ceil(log2(10^9) + 40) = ${minBitsA}`,
        criterionB: `ceil(log2(10^9 (10^9 - 1)) - 1 + 40) = ${minBitsB}`,
        smtDepthNominal: { criterionA: minBitsA, criterionB: minBitsB },
        smtDepthCircuitLimit: { criterionA: minBitsA + measuredOffset, criterionB: minBitsB + measuredOffset },
        label: "[S]",
      },
    },
    gadgets,
    smtDepthBoundary: smtBoundary,
    imtIndexBoundary: imtBoundary,
    perLevelConstraintsO2: {
      imt: (c("imt_d32", "O2") - c("imt_d30", "O2")) / 2,
      smt: (c("smt_d128", "O2") - c("smt_d32", "O2")) / 96,
      smtStep70to71: c("smt_d71", "O2") - c("smt_d70", "O2"),
      smtStep99to100: c("smt_d100", "O2") - c("smt_d99", "O2"),
      keyDerivationImt: c("imt_d30", "O2") - c("imt_bare_d30", "O2"),
      keyDerivationSmt: c("smt_d32", "O2") - c("smt_bare_d32", "O2"),
      label: "[M] (differences of measured counts)",
    },
    options,
    v3CrossCheck: {
      review,
      nominalModel32Bits: v3(32, [0x9e3779b9, 0x243f6a88, 0xb7e15162, 0x71374491]),
      circuitLimit31Bits: v3(31, [0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c]),
      note: "v3's SMTVerifier(32) handles 31 path bits (smtDepthBoundary). The review's figures match the 32-bit model; the circuit limit gives the 31-bit figures.",
    },
    decision: {
      chosen: chosenId,
      family: chosen["family"],
      depth: chosenDepth,
      constraintsO2: chosen["constraintsO2"],
      qualifyingOptions: options.filter(qualB).map((o) => ({ id: o["id"], constraintsO2: o["constraintsO2"], constraintsO1: o["constraintsO1"] })),
      nonQualifyingOptions: options.filter((o) => !qualB(o)).map((o) => o["id"]),
      bestQualifyingSmt: bestSmt ? { id: bestSmt["id"], constraintsO2: bestSmt["constraintsO2"] } : null,
      ratioBestSmtToChosenO2: bestSmt ? (bestSmt["constraintsO2"] as number) / (chosen["constraintsO2"] as number) : null,
      sameChoiceAtO1: chosenO1 ? chosenO1["id"] === chosenId : false,
      sameChoiceUnderNominalSmtModel: chosenNominal ? chosenNominal["id"] === chosenId : false,
      revDepthConstant: REV_DEPTH,
      revDepthConstantMatches: chosen["family"] === "imt" && chosenDepth === REV_DEPTH,
      headroomAtChosenDepth: chosen["family"] === "imt" ? (2 ** chosenDepth - 1) / TARGET_REVOCATIONS : null,
    },
  };

  fs.writeFileSync(RESULTS_FILE, JSON.stringify(result, null, 2) + "\n");
  console.log(
    `[b2] decision: ${chosenId} (${String(chosen["constraintsO2"])} constraints at --O2); ` +
      `best qualifying SMT: ${bestSmt ? `${String(bestSmt["id"])} (${String(bestSmt["constraintsO2"])})` : "none"} -> ${rel(RESULTS_FILE)}`
  );
  process.exit(0); // snarkjs keeps worker threads alive
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
