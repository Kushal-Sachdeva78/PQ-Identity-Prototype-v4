import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawn, execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { REPO_ROOT } from "@pqid/common/paths";

/**
 * Shared helpers for the Phase D benchmark runner (docs/v4/BENCH_PROTOCOL.md).
 * Node built-ins only (plus REPO_ROOT), so every runner script loads the same small code.
 */

export { REPO_ROOT };

export type Version = "v2" | "v3" | "v4";
export type Prover = "snarkjs" | "rapidsnark";
export const ALL_VERSIONS: readonly Version[] = ["v2", "v3", "v4"];
export const ALL_PROVERS: readonly Prover[] = ["snarkjs", "rapidsnark"];

export const BENCH_ROOT = path.join(REPO_ROOT, "results", "v4", "bench");
export const SMOKE_ROOT = path.join(BENCH_ROOT, "_tmp");
export const PROTOCOL_FILE = path.join(REPO_ROOT, "docs", "v4", "BENCH_PROTOCOL.md");
export const CHILD_SCRIPT = path.join(REPO_ROOT, "harness", "v4", "bench", "child_prove.ts");

/** Label written with every blocked rapidsnark condition. */
export const RAPIDSNARK_BLOCKED = "blocked: rapidsnark unavailable (D-002)";

/** Pre-registered shuffle seeds (docs/v4/BENCH_PROTOCOL.md, "Randomisation"). */
export const DEFAULT_SEEDS: Record<string, number> = {
  warm: 20260929,
  cold_v4: 20260930,
  cold_v2v3: 20261001,
};

export function benchRoot(smoke: boolean): string {
  return smoke ? SMOKE_ROOT : BENCH_ROOT;
}

export function inputsDir(smoke: boolean): string {
  return path.join(benchRoot(smoke), "inputs");
}

export function inputsLockFile(smoke: boolean): string {
  return path.join(inputsDir(smoke), "inputs.lock.json");
}

// ------------------------------------------------------------------ artifacts

export interface ArtifactSpec {
  /** Repo-relative path, forward slashes. */
  rel: string;
  /** Pin file (repo-relative) and key inside it, when the artifact is pinned. */
  pin?: { file: string; key: string };
}

export interface VersionSpec {
  version: Version;
  keyLabel: string;
  wasm: ArtifactSpec;
  zkey: ArtifactSpec;
  vkey: ArtifactSpec;
  /** Where the fixed honest input comes from (recorded in the lock file). */
  inputSource: string;
}

/** The COMMITTED artifacts of each version (v4: the dev key). */
export const VERSIONS: Record<Version, VersionSpec> = {
  v2: {
    version: "v2",
    keyLabel: "committed v2 key",
    wasm: { rel: "circuits/build/credential_auth_js/credential_auth.wasm" },
    zkey: { rel: "setup/out/credential_auth_final.zkey", pin: { file: "setup/pins.json", key: "credential_auth_final.zkey" } },
    vkey: { rel: "setup/out/verification_key.json", pin: { file: "setup/pins.json", key: "verification_key.json" } },
    inputSource: "harness/fixture.ts buildFixtureProofInput() (the published v2 benchmark input)",
  },
  v3: {
    version: "v3",
    keyLabel: "committed v3 key",
    wasm: {
      rel: "circuits/build/v3/credential_auth_v3_js/credential_auth_v3.wasm",
      pin: { file: "setup/pins.json", key: "v3/credential_auth_v3.wasm" },
    },
    zkey: { rel: "setup/out/v3/credential_auth_v3_final.zkey", pin: { file: "setup/pins.json", key: "v3/credential_auth_v3_final.zkey" } },
    vkey: { rel: "setup/out/v3/verification_key.json", pin: { file: "setup/pins.json", key: "v3/verification_key.json" } },
    inputSource: "harness/fixture.ts buildFixtureProofInputV3() (the input of harness/v3/compare_v2_v3.ts)",
  },
  v4: {
    version: "v4",
    keyLabel: "dev key",
    wasm: {
      rel: "circuits/build/v4/credential_auth_v4_js/credential_auth_v4.wasm",
      pin: { file: "setup/pins_v4.json", key: "v4/credential_auth_v4.wasm" },
    },
    zkey: { rel: "setup/out/v4/credential_auth_v4_dev.zkey", pin: { file: "setup/pins_v4.json", key: "v4/credential_auth_v4_dev.zkey" } },
    vkey: { rel: "setup/out/v4/verification_key_dev.json", pin: { file: "setup/pins_v4.json", key: "v4/verification_key_dev.json" } },
    inputSource: "harness/v4/bench/inputs.ts buildFixtureProofInputV4() (fixture twin of the v2/v3 inputs, @pqid/v4 encodings)",
  },
};

export function abs(rel: string): string {
  return path.join(REPO_ROOT, ...rel.split("/"));
}

export function sha256FileHex(file: string): string {
  const h = createHash("sha256");
  const fd = fs.openSync(file, "r");
  try {
    const buf = Buffer.allocUnsafe(1 << 20);
    let n: number;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n));
  } finally {
    fs.closeSync(fd);
  }
  return h.digest("hex");
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

export interface ArtifactRecord {
  path: string;
  sha256: string;
  bytes: number;
  pinned: boolean;
  pinMatch: boolean | null;
}

function readPin(spec: ArtifactSpec): string | null {
  if (!spec.pin) return null;
  const pins = JSON.parse(fs.readFileSync(abs(spec.pin.file), "utf8")) as Record<string, { sha256?: string }>;
  return pins[spec.pin.key]?.sha256 ?? null;
}

/** Hash one artifact and compare it with its committed pin. Throws on drift. */
export function checkArtifact(spec: ArtifactSpec): ArtifactRecord {
  const file = abs(spec.rel);
  if (!fs.existsSync(file)) throw new Error(`artifact missing: ${spec.rel}`);
  const sha = sha256FileHex(file);
  const pin = readPin(spec);
  if (pin !== null && pin !== sha) {
    throw new Error(`artifact drift: ${spec.rel} sha256 ${sha} != pinned ${pin} (${spec.pin?.file})`);
  }
  return { path: spec.rel, sha256: sha, bytes: fs.statSync(file).size, pinned: pin !== null, pinMatch: pin === null ? null : true };
}

export function checkVersionArtifacts(v: Version): { wasm: ArtifactRecord; zkey: ArtifactRecord; vkey: ArtifactRecord } {
  const s = VERSIONS[v];
  return { wasm: checkArtifact(s.wasm), zkey: checkArtifact(s.zkey), vkey: checkArtifact(s.vkey) };
}

// ------------------------------------------------------------------ inputs lock

export interface InputLockEntry {
  version: Version;
  file: string; // repo-relative
  inputSha256: string; // SHA-256 of the compact JSON text (JSON.stringify of the parsed file)
  publicSignals: string[];
  publicSignalsSha256: string; // SHA-256 of JSON.stringify(publicSignals)
  source: string;
  keyLabel: string;
  artifacts: { wasm: ArtifactRecord; zkey: ArtifactRecord; vkey: ArtifactRecord };
  referenceProofVerified: boolean;
}

export interface InputsLock {
  schema: "pqid/v4-bench-inputs/v1";
  createdUtc: string;
  generator: string;
  versions: Partial<Record<Version, InputLockEntry>>;
}

export function readInputsLock(smoke: boolean): InputsLock {
  const f = inputsLockFile(smoke);
  if (!fs.existsSync(f)) {
    throw new Error(
      `${rel(f)} missing: run \`node --import tsx harness/v4/bench/inputs.ts${smoke ? " --smoke" : ""}\` first`
    );
  }
  return JSON.parse(fs.readFileSync(f, "utf8")) as InputsLock;
}

/** Re-hash an input file the way the lock does (robust to line-ending conversion). */
export function inputFileSha(file: string): string {
  return sha256Hex(JSON.stringify(JSON.parse(fs.readFileSync(file, "utf8"))));
}

/**
 * Everything a run needs for one version: the lock entry, re-checked against the current
 * artifacts and the input file on disk. Throws on any mismatch.
 */
export function resolveVersion(v: Version, smoke: boolean): { spec: VersionSpec; lock: InputLockEntry; artifacts: ReturnType<typeof checkVersionArtifacts> } {
  const lockAll = readInputsLock(smoke);
  const lock = lockAll.versions[v];
  if (!lock) throw new Error(`no pinned input for ${v} in ${rel(inputsLockFile(smoke))}`);
  const artifacts = checkVersionArtifacts(v);
  for (const k of ["wasm", "zkey", "vkey"] as const) {
    if (artifacts[k].sha256 !== lock.artifacts[k].sha256) {
      throw new Error(`${v} ${k} changed since the input was pinned (${lock.artifacts[k].sha256} -> ${artifacts[k].sha256}); re-run inputs.ts`);
    }
  }
  const sha = inputFileSha(abs(lock.file));
  if (sha !== lock.inputSha256) throw new Error(`${v} input file hash ${sha} != pinned ${lock.inputSha256}`);
  return { spec: VERSIONS[v], lock, artifacts };
}

// ------------------------------------------------------------------ schedule

/** mulberry32: small seeded PRNG (32-bit state); enough for shuffling a schedule. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Fisher-Yates shuffle (in place, from the end) with the given PRNG. */
export function shuffle<T>(xs: T[], rng: () => number): T[] {
  for (let i = xs.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const t = xs[i] as T;
    xs[i] = xs[j] as T;
    xs[j] = t;
  }
  return xs;
}

export function conditionId(v: Version, p: Prover): string {
  return `${v}/${p}`;
}

export function parseCondition(c: string): { version: Version; prover: Prover } {
  const [v, p] = c.split("/") as [Version, Prover];
  return { version: v, prover: p };
}

export interface Slot {
  slot: number;
  /** Block index; negative blocks are warm-up blocks (warm series only). */
  block: number;
  pos: number;
  condition: string;
}

/**
 * Blocked randomised order: in every block each condition appears exactly once, in an
 * order drawn from ONE seeded PRNG stream (block after block).
 */
export function buildSchedule(conditions: readonly string[], blocks: number, seed: number, firstBlock = 0): Slot[] {
  const rng = mulberry32(seed);
  const out: Slot[] = [];
  for (let b = 0; b < blocks; b++) {
    const order = shuffle([...conditions], rng);
    order.forEach((c, pos) => out.push({ slot: out.length, block: firstBlock + b, pos, condition: c }));
  }
  return out;
}

// ------------------------------------------------------------------ rapidsnark

export interface RapidsnarkState {
  available: boolean;
  reason?: string;
  /** Absolute binary path (used to spawn; never written to results). */
  bin?: string;
  sha256?: string;
  basename?: string;
}

/**
 * rapidsnark comes only from PQID_RAPIDSNARK: a native Linux prover binary spawned directly
 * with argv (never wsl.exe). Unset on this Windows host (DECISIONS D-002).
 */
export function rapidsnarkState(): RapidsnarkState {
  const bin = process.env["PQID_RAPIDSNARK"]?.trim();
  if (!bin) return { available: false, reason: RAPIDSNARK_BLOCKED };
  if (/^(wsl|bash|sh|cmd|powershell|pwsh)(\.exe)?$/i.test(path.basename(bin))) {
    throw new Error("PQID_RAPIDSNARK must name the native prover binary itself, not a shell or wsl.exe");
  }
  if (!fs.existsSync(bin) || !fs.statSync(bin).isFile()) throw new Error("PQID_RAPIDSNARK does not name an existing file");
  return { available: true, bin, sha256: sha256FileHex(bin), basename: path.basename(bin) };
}

// ------------------------------------------------------------------ environment

export interface EnvInfo {
  cpuModel: string;
  logicalCores: number;
  ramGiB: number;
  platform: string;
  arch: string;
  osName: string;
  osBuild: string;
  node: string;
  openssl: string;
  v8: string;
}

/** Host description with no usernames, hostnames or home paths. */
export function envInfo(): EnvInfo {
  const cpus = os.cpus();
  return {
    cpuModel: (cpus[0]?.model ?? "unknown").trim(),
    logicalCores: typeof os.availableParallelism === "function" ? os.availableParallelism() : cpus.length,
    ramGiB: Math.round((os.totalmem() / 2 ** 30) * 10) / 10,
    platform: process.platform,
    arch: process.arch,
    osName: process.platform === "win32" ? os.version() : os.type(),
    osBuild: os.release(),
    node: process.version,
    openssl: process.versions.openssl ?? "unknown",
    v8: process.versions.v8 ?? "unknown",
  };
}

export function snarkjsVersion(): string {
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "node_modules", "snarkjs", "package.json"), "utf8")) as { version: string };
  return pkg.version;
}

/** Commit the working copy is on (read-only; GIT_OPTIONAL_LOCKS=0). */
export function gitHead(): string | null {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" },
      stdio: ["ignore", "pipe", "ignore"],
      windowsHide: true,
    }).trim();
  } catch {
    return null;
  }
}

/** Strip anything that could identify the user or host (paths, names) from free text. */
export function sanitize(text: string): string {
  let out = text;
  const needles: Array<[string, string]> = [];
  const add = (s: string | undefined, tag: string) => {
    if (s && s.length >= 3) needles.push([s, tag]);
  };
  add(REPO_ROOT, "<repo>");
  add(REPO_ROOT.replace(/\\/g, "/"), "<repo>");
  add(os.homedir(), "<home>");
  add(os.homedir().replace(/\\/g, "/"), "<home>");
  add(os.tmpdir(), "<tmp>");
  add(os.tmpdir().replace(/\\/g, "/"), "<tmp>");
  try {
    add(os.userInfo().username, "<user>");
  } catch {
    /* no user info */
  }
  add(os.hostname(), "<host>");
  needles.sort((a, b) => b[0].length - a[0].length);
  for (const [s, tag] of needles) out = out.split(s).join(tag);
  return out;
}

export function rel(file: string): string {
  return path.relative(REPO_ROOT, file).split(path.sep).join("/");
}

export function utcNow(): string {
  return new Date().toISOString();
}

// ------------------------------------------------------------------ files

export function appendJsonl(file: string, rec: unknown): void {
  fs.appendFileSync(file, JSON.stringify(rec) + "\n");
}

export function readJsonl<T>(file: string): T[] {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, "utf8")
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as T);
}

export function writeJson(file: string, data: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n");
}

/**
 * The protocol must exist before any timed run; its hash ties results to its text.
 * `normative` hashes the text above the "## Deviations" heading (with LF line ends), so dated
 * deviation entries can be appended without changing it; `file` hashes the whole file.
 */
export function protocolSha(): { normative: string; file: string } {
  if (!fs.existsSync(PROTOCOL_FILE)) throw new Error("docs/v4/BENCH_PROTOCOL.md missing: the protocol must exist before any timed run");
  const text = fs.readFileSync(PROTOCOL_FILE, "utf8").replace(/\r\n/g, "\n");
  const cut = text.indexOf("\n## Deviations");
  if (cut < 0) throw new Error("docs/v4/BENCH_PROTOCOL.md has no '## Deviations' section");
  return { normative: sha256Hex(text.slice(0, cut)), file: sha256FileHex(PROTOCOL_FILE) };
}

// ------------------------------------------------------------------ RUNNING marker

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Create <root>/RUNNING for the duration of a timed series (docs/BENCHMARK_POLICY.md, Benchmarks).
 * Refuses when another live runner holds it; a stale marker (dead pid) is replaced.
 * Returns the release function (also run on exit and on SIGINT/SIGTERM).
 */
export function acquireRunning(root: string, campaign: string): () => void {
  fs.mkdirSync(root, { recursive: true });
  const marker = path.join(root, "RUNNING");
  if (fs.existsSync(marker)) {
    let other: { pid?: number; campaign?: string } = {};
    try {
      other = JSON.parse(fs.readFileSync(marker, "utf8")) as typeof other;
    } catch {
      /* unreadable marker: treat as stale */
    }
    if (typeof other.pid === "number" && other.pid !== process.pid && pidAlive(other.pid)) {
      throw new Error(`${rel(marker)} held by a live runner (campaign ${other.campaign ?? "?"}); refusing to start`);
    }
    console.log(`[bench] replacing stale ${rel(marker)} (campaign ${other.campaign ?? "?"})`);
  }
  fs.writeFileSync(
    marker,
    JSON.stringify({ campaign, pid: process.pid, startedUtc: utcNow(), rule: "timed run active: only file editing and web research (docs/BENCHMARK_POLICY.md)" }, null, 2) + "\n"
  );
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    try {
      const cur = JSON.parse(fs.readFileSync(marker, "utf8")) as { pid?: number };
      if (cur.pid === process.pid) fs.rmSync(marker, { force: true });
    } catch {
      /* already gone */
    }
  };
  process.on("exit", release);
  for (const sig of ["SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"] as const) {
    process.on(sig, () => {
      release();
      process.exit(130);
    });
  }
  return release;
}

// ------------------------------------------------------------------ child process

/** File URL of the tsx ESM loader, so children start as `node --import <tsx> child.ts`. */
export function tsxImportUrl(): string {
  return pathToFileURL(path.join(REPO_ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;
}

export interface ChildOutcome {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  /** Parent-side wall time from spawn() to the child's exit. */
  wallMs: number;
  timedOut: boolean;
}

/** Spawn a Node child with the tsx loader (argv array, no shell) and collect its output. */
export function runNodeChild(script: string, args: string[], timeoutMs: number, env: NodeJS.ProcessEnv = process.env): Promise<ChildOutcome> {
  return new Promise((resolve, reject) => {
    const t0 = process.hrtime.bigint();
    const child = spawn(process.execPath, ["--import", tsxImportUrl(), script, ...args], {
      cwd: REPO_ROOT,
      env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      shell: false,
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    child.stdout.setEncoding("utf8").on("data", (d: string) => (stdout += d));
    child.stderr.setEncoding("utf8").on("data", (d: string) => (stderr += d));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr, wallMs: Number(process.hrtime.bigint() - t0) / 1e6, timedOut });
    });
  });
}

/** Last stdout line that parses as a JSON object. */
export function lastJsonLine<T>(stdout: string): T | null {
  const lines = stdout.split(/\r?\n/).filter((l) => l.trim().startsWith("{"));
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      return JSON.parse(lines[i] as string) as T;
    } catch {
      /* keep looking */
    }
  }
  return null;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, Math.max(0, ms)));
}

// ------------------------------------------------------------------ CLI

export function flag(argv: readonly string[], name: string): boolean {
  return argv.includes(`--${name}`);
}

export function opt(argv: readonly string[], name: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  if (i >= 0) return argv[i + 1];
  const pre = `--${name}=`;
  const hit = argv.find((a) => a.startsWith(pre));
  return hit ? hit.slice(pre.length) : undefined;
}

export function optNum(argv: readonly string[], name: string, dflt: number): number {
  const v = opt(argv, name);
  if (v === undefined) return dflt;
  const n = Number(v);
  if (!Number.isFinite(n)) throw new Error(`--${name} must be a number`);
  return n;
}

export function optList<T extends string>(argv: readonly string[], name: string, allowed: readonly T[], dflt: readonly T[]): T[] {
  const v = opt(argv, name);
  if (v === undefined) return [...dflt];
  const xs = v.split(",").map((s) => s.trim()).filter(Boolean) as T[];
  for (const x of xs) if (!allowed.includes(x)) throw new Error(`--${name}: unknown value ${x}`);
  return xs;
}
