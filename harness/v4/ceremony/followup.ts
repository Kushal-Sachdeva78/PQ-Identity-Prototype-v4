import fs from "node:fs";
import path from "node:path";
import { spawn, execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { REPO_ROOT, PTAU_FILE } from "@pqid/common/paths";
import { VERIFIER_CHECKS } from "@pqid/v4/verifier";
import { WALLET_CHECKS } from "@pqid/v4/wallet";
import { REGISTRY_CHECKS, CONTRACTS_V4_FILE } from "@pqid/v4/ledger";
import { allGroups, buildMutant } from "../mutate.ts";
import { envInfo, sanitize, gitHead, snarkjsVersion, tsxImportUrl, lastJsonLine, opt, flag, sha256FileHex, inputFileSha } from "../bench/lib.ts";
import { acquireMarker, assertMarkersFree, markerRoots, MarkerHeldError, type MarkerHandle } from "../lib/markers.ts";
import { probePort, openPorts } from "../lib/quiesce.ts";
import * as L from "./followup_lib.ts";
import type { KeyChecksResult } from "./key_checks.ts";
import type { RekeyProbe } from "./rekey_probe.ts";

/**
 * Ceremony follow-up (TASKS I; docs/v4/CEREMONY_FOLLOWUP.md). After Kushal's multi-party
 * ceremony (ceremony/HANDOFF_STEPS.md), from the repository root on Windows (Git Bash):
 *
 *   bash scripts/ceremony/followup.sh --check-only --external <i[,j]>   (first: verify and keys only, minutes)
 *   bash scripts/ceremony/followup.sh --external <i[,j]>                (real run, about 1 h 40 min [S])
 *   bash scripts/ceremony/followup.sh --dry-run                         (rehearsal outputs, seconds)
 *
 * Steps (all by default; --steps picks a subset):
 *   verify    transcript rules (followup_lib.checkTranscript), the kit's own `coordinator.mjs
 *             audit`, and plain `snarkjs zkey verify <frozen r1cs> <pinned ptau> <final zkey>`
 *             whose contribution list must equal the transcript;
 *   keys      key_checks.ts in a child: vkey = export of the zkey, proof round trip with the
 *             pinned Phase D v4 input and the pinned frozen wasm, rejected by the dev key, same
 *             circuit and phase 1 as the dev key, no public-beacon trapdoor (control: the
 *             beacon-only v2 key);
 *   install   copies the final files to NEW paths setup/out/v4/*_<label>.* (never over an
 *             existing different file, never over the dev key, never a text file with CR
 *             bytes), writes the NEW pins file setup/pins_v4_<label>.json (entries labelled
 *             <label>) and the e2e key spec setup/key_spec_v4_<label>.json, then loads the key
 *             through the cmp and e2e loaders;
 *   suite     harness/v4/security_suite.ts, unchanged, under the rekey loader (rekey.mjs) with a
 *             config whose output folder is the dated run folder; compared with the dev suite;
 *   mutation  the C3 campaign (the rules of harness/v4/mutation.ts, re-implemented here only to
 *             change the output paths, the ports and the loader), compared with campaign 5.
 *
 * Output: results/v4/ceremony/followup_<date>[_rN]/ and logs in
 * verification/v4/ceremony_followup_<date>[_rN]/. Nothing existing is overwritten:
 * results/v4/security_suite.json, results/v4/mutation.json and results/v4/mutation/ are read only
 * (their SHA-256 is checked before and after). The mutation step also writes the gitignored
 * mutant circuits, throwaway keys and mutant contracts under circuits/build/v4/mutants/ (shared
 * with campaign 5). The dry run and the check-only run write their outputs only under
 * results/v4/ceremony/_smoke/ (gitignored).
 *
 * Markers (D-034): the real run and the check-only run hold results/v4/BUSY; the dry run holds
 * it while a suite or mutation step runs. Every run refuses to start while a marker exists.
 *
 * Post-fix rerun with the dev key (D-034 exception for a packages/v4 fix of a fuzz-found defect):
 *
 *   bash scripts/ceremony/followup.sh --dev-rerun --dry-run   (preflight and key probe only, seconds; writes nothing)
 *   bash scripts/ceremony/followup.sh --dev-rerun             (suite and mutation, about 1 h 35 min [S])
 *
 * Skips verify, keys and install; uses the pinned dev key (setup/out/v4/*_dev.*, checked against
 * setup/pins_v4.json) without the rekey loader; runs the suite and mutation steps as above (same
 * re-implemented mutation, ports 8800 and 8801+) and compares with dev run 10 and campaign 5:
 * verdicts, every summary field, failed-check lists, the attack matrix and every mutation row
 * with its exit code. Any difference is review. Output results/v4/fixcheck/<date>[_rN]/, logs
 * verification/v4/fixcheck_<date>[_rN]/ (every run output passes outputGuardFor before it is
 * written); holds results/v4/BUSY; refuses uncommitted code. Only its own options are accepted
 * (a misspelt --dry-run is a usage error). A run without both steps, or with --only, is labelled
 * PARTIAL and its `next` says what D-034 still needs; a mutation-only run checks that its
 * baseline's run passed the suite step on the same code.
 *
 * Exit codes: 0 pass, 1 fail, 2 usage, 3 refused before the start (nothing written), 4 stopped
 * after the start (a refusal during the run; the run folder and logs exist), 5 review
 * (finished; a difference from the dev-key run needs a person to look).
 */

type StepName = "verify" | "keys" | "install" | "suite" | "mutation";
const ALL_STEPS: readonly StepName[] = ["verify", "keys", "install", "suite", "mutation"];

export interface Options {
  kind: L.RunKind;
  /** Transcript mode of verify and keys (not used by the post-fix rerun, which runs neither). */
  mode: L.Mode;
  dry: boolean;
  checkOnly: boolean;
  /** `--dev-rerun --dry-run`: preflight and key probe of the post-fix rerun, then stop (nothing written). */
  preview: boolean;
  label: string;
  finalDirRel: string;
  external: number[];
  steps: StepName[];
  only: Set<string> | null;
  jobs: number;
  date: string;
  allowUncommitted: boolean;
  baselineRel: string | null;
  owner: string | null;
}

class Refused extends Error {}

const rel = (p: string): string => path.relative(REPO_ROOT, path.resolve(REPO_ROOT, p)).split(path.sep).join("/");
const abs = (r: string): string => path.join(REPO_ROOT, ...r.split("/"));
const readJson = <T>(r: string): T => JSON.parse(fs.readFileSync(abs(r), "utf8")) as T;
const shaOrNull = (r: string): string | null => (fs.existsSync(abs(r)) ? sha256FileHex(abs(r)) : null);
const fileRec = (r: string) => ({ file: r, sha256: shaOrNull(r) });

/**
 * The output rule of a run kind, applied to every run output before it is written (records,
 * logs, configs, probes, tables, the folders): the post-fix rerun writes only under
 * results/v4/fixcheck/<run>/ and verification/v4/fixcheck_<run>/ and never a ledger-cited path
 * (L.assertFixcheckOutput, which throws). The ceremony modes have no such rule (null).
 */
export function outputGuardFor(kind: L.RunKind): ((rel: string) => string) | null {
  return kind === "devrerun" ? L.assertFixcheckOutput : null;
}

/** Set by main from outputGuardFor before anything is written. */
let OUTPUT_GUARD: ((rel: string) => string) | null = null;

function guardOut(r: string): void {
  if (OUTPUT_GUARD) OUTPUT_GUARD(rel(r));
}

function mkdirRel(r: string): void {
  guardOut(r);
  fs.mkdirSync(abs(r), { recursive: true });
}

function writeJsonRel(r: string, data: unknown): void {
  guardOut(r);
  fs.mkdirSync(path.dirname(abs(r)), { recursive: true });
  fs.writeFileSync(abs(r), JSON.stringify(data, null, 2) + "\n");
}

function writeTextNew(r: string, text: string): void {
  guardOut(r);
  fs.mkdirSync(path.dirname(abs(r)), { recursive: true });
  fs.writeFileSync(abs(r), sanitize(L.stripAnsi(text)), { flag: "wx" });
}

// ------------------------------------------------------------------ options

/** Options of the ceremony modes that the post-fix rerun refuses (it reads no ceremony input and never runs uncommitted code). */
const NOT_WITH_DEV_RERUN = ["check-only", "allow-uncommitted", "external", "label", "final-dir"] as const;

function given(argv: readonly string[], name: string): boolean {
  return argv.some((a) => a === `--${name}` || a.startsWith(`--${name}=`));
}

function parseJobs(argv: readonly string[]): number {
  const jobs = Number(opt(argv, "jobs") ?? 2);
  if (!Number.isInteger(jobs) || jobs < 1 || jobs > 4) throw new Error("--jobs must be 1 to 4");
  return jobs;
}

function parseOnly(argv: readonly string[]): Set<string> | null {
  const onlyArg = opt(argv, "only");
  return onlyArg ? new Set(onlyArg.split(",").map((s) => s.trim()).filter(Boolean)) : null;
}

/** The only options of `--dev-rerun` (anything else, or a boolean with a value, is a usage error). */
export const DEV_RERUN_FLAGS: readonly string[] = Object.freeze(["dev-rerun", "dry-run"]);
export const DEV_RERUN_VALUES: readonly string[] = Object.freeze(["steps", "only", "jobs", "date", "baseline", "owner"]);

/** `--dev-rerun`: the post-fix rerun with the pinned dev key (D-034). Steps suite and mutation only. */
function parseDevRerun(argv: readonly string[], now: Date): Options {
  for (const f of NOT_WITH_DEV_RERUN) {
    if (given(argv, f)) throw new Error(`--${f} does not apply to --dev-rerun (${f === "allow-uncommitted" ? "the post-fix rerun always refuses uncommitted code" : "the post-fix rerun reads no ceremony input and uses the pinned dev key"})`);
  }
  // Strict: a misspelt --dry-run (--dryrun, --dry-run=yes) must never start the real rerun.
  const a = L.parseStrictArgs(argv, DEV_RERUN_FLAGS, DEV_RERUN_VALUES);
  const stepsArg = a.values.get("steps");
  const steps = stepsArg !== undefined ? stepsArg.split(",").map((s) => s.trim()).filter(Boolean) : ["suite", "mutation"];
  if (steps.length === 0) throw new Error("--steps: no step named");
  for (const s of steps) if (s !== "suite" && s !== "mutation") throw new Error(`--steps: --dev-rerun runs only the suite and mutation steps (verify, keys and install do not apply to the pinned dev key); got ${s}`);
  const baselineArg = a.values.get("baseline");
  const baselineRel = baselineArg !== undefined ? L.checkFixcheckBaseline(baselineArg) : null;
  if (baselineRel !== null && steps.includes("suite")) throw new Error("--baseline is only for --dev-rerun --steps mutation (with the suite step the baseline is this run's own suite output)");
  if (baselineRel === null && !steps.includes("suite")) throw new Error(`--dev-rerun --steps mutation needs --baseline <${L.FIXCHECK_RESULTS_REL}/<date>[_rN]/suite/security_suite.json>`);
  const onlyArg = a.values.get("only");
  let only: Set<string> | null = null;
  if (onlyArg !== undefined) {
    if (!steps.includes("mutation")) throw new Error("--only selects mutation defences: it needs the mutation step");
    only = new Set(onlyArg.split(",").map((s) => s.trim()).filter(Boolean));
    if (only.size === 0) throw new Error("--only: no defence named");
    const all = allDefences();
    for (const x of only) if (!all.some((d) => x === d.kind || x === `${d.kind}:${d.name}`)) throw new Error(`--only: ${x} is no defence kind or kind:name`);
  }
  const jobsArg = a.values.get("jobs");
  const jobs = jobsArg === undefined ? 2 : Number(jobsArg);
  if (!Number.isInteger(jobs) || jobs < 1 || jobs > 4) throw new Error("--jobs must be 1 to 4");
  const dateArg = a.values.get("date");
  const date = dateArg === undefined ? L.utcDate(now) : L.checkRunDate(dateArg, now);
  return {
    kind: "devrerun",
    mode: "ceremony",
    dry: false,
    checkOnly: false,
    preview: a.flags.has("dry-run"),
    label: L.DEV_LABEL,
    finalDirRel: L.DEFAULT_FINAL_DIR_REL,
    external: [],
    steps: ALL_STEPS.filter((s) => steps.includes(s)),
    only,
    jobs,
    date,
    allowUncommitted: false,
    baselineRel,
    owner: a.values.get("owner") ?? null,
  };
}

/** `now` fixes today's date for the --date check of the post-fix rerun (tests). */
export function parseOptions(argv: readonly string[], now: Date = new Date()): Options {
  if (argv.some((x) => x === "--dev-rerun" || x.startsWith("--dev-rerun="))) return parseDevRerun(argv, now);
  const dry = flag(argv, "dry-run");
  const checkOnly = flag(argv, "check-only");
  if (dry && checkOnly) throw new Error("--dry-run and --check-only exclude each other");
  const kind: L.RunKind = dry ? "dry" : checkOnly ? "check" : "real";
  const mode: L.Mode = dry ? "rehearsal" : "ceremony";
  const label = opt(argv, "label") ?? (dry ? "rehearsal" : "ceremony");
  const stepsArg = opt(argv, "steps");
  const steps = (stepsArg ? stepsArg.split(",").map((s) => s.trim()) : dry ? ["verify", "keys", "install"] : checkOnly ? ["verify", "keys"] : [...ALL_STEPS]) as StepName[];
  for (const s of steps) if (!ALL_STEPS.includes(s)) throw new Error(`--steps: unknown step ${s} (${ALL_STEPS.join(", ")})`);
  if (checkOnly && steps.some((s) => s !== "verify" && s !== "keys")) throw new Error("--check-only runs only the verify and keys steps");
  const ext = L.parseIndexList(opt(argv, "external"));
  const date = opt(argv, "date") ?? L.utcDate();
  const jobs = parseJobs(argv);
  const o: Options = {
    kind,
    mode,
    dry,
    checkOnly,
    preview: false,
    label,
    finalDirRel: L.cleanRel(opt(argv, "final-dir") ?? (dry ? L.REHEARSAL_FINAL_DIR_REL : L.DEFAULT_FINAL_DIR_REL), "--final-dir"),
    external: dry && ext.length === 0 ? [1] : ext,
    steps: ALL_STEPS.filter((s) => steps.includes(s)),
    only: parseOnly(argv),
    jobs,
    date,
    allowUncommitted: flag(argv, "allow-uncommitted"),
    baselineRel: opt(argv, "baseline") ? L.cleanRel(opt(argv, "baseline") as string, "--baseline") : null,
    owner: opt(argv, "owner") ?? null,
  };
  L.installTargets(o.label); // label rules of the rekey loader: lower case, never "dev"
  if (!dry && o.label !== "ceremony" && !/^ceremony/.test(o.label)) throw new Error("--label: a real or check-only run's label starts with 'ceremony'");
  if (dry && /^ceremony/.test(o.label)) throw new Error("--label: the dry run never uses a ceremony label");
  if (o.steps.includes("install") && !(o.steps.includes("verify") && o.steps.includes("keys"))) throw new Error("--steps: install runs only together with verify and keys (an unverified key is never installed)");
  if (o.steps.includes("mutation") && !o.steps.includes("suite") && o.baselineRel === null) throw new Error("--steps: mutation without suite needs --baseline <this key's security_suite.json>");
  if (!dry && o.steps.includes("verify") && o.external.length === 0) throw new Error("--external <index[,index]> is required: the contribution(s) made by people outside the project on their own computers (ceremony/HANDOFF_STEPS.md)");
  return o;
}

// ------------------------------------------------------------------ run folders and logging

export interface RunDirs {
  runId: string;
  /** Repo-relative results folder of this run. */
  out: string;
  /** Repo-relative log folder of this run. */
  logs: string;
  /** Folder of the installed key, its pins file and key spec. */
  keyDir: string;
  pinsRel: string;
  /** Key spec of the e2e series; null for the post-fix rerun (no key is installed). */
  specRel: string | null;
}

/** Names only; nothing is created here. */
export function runDirs(o: Pick<Options, "kind" | "label" | "date">): RunDirs {
  if (o.kind === "devrerun") {
    // results/v4/fixcheck/<date>[_rN]/ and verification/v4/fixcheck_<date>[_rN]/, never a ledger-cited path
    const f = L.fixcheckDirs(o.date, (r) => fs.existsSync(abs(r)));
    return { runId: `fixcheck_${f.name}`, out: L.assertFixcheckOutput(f.out), logs: L.assertFixcheckOutput(f.logs), keyDir: L.KEY_DIR_REL, pinsRel: L.DEV_PINS_REL, specRel: null };
  }
  if (o.kind !== "real") {
    const runId = `${o.kind === "dry" ? "dryrun" : "checkonly"}_${L.utcStamp()}_${randomBytes(2).toString("hex")}`;
    const out = `${L.CEREMONY_SMOKE_REL}/${runId}`;
    const keyDir = `${out}/key`;
    return { runId, out, logs: `${out}/logs`, keyDir, pinsRel: L.pinsFileRel(o.label, keyDir), specRel: L.keySpecRel(o.label, keyDir) };
  }
  const name = L.pickDatedName("followup", o.date, "", (n) => fs.existsSync(abs(`${L.CEREMONY_RESULTS_REL}/${n}`)) || fs.existsSync(abs(`${L.LOG_DIR_REL}/ceremony_${n}`)));
  return { runId: name, out: `${L.CEREMONY_RESULTS_REL}/${name}`, logs: `${L.LOG_DIR_REL}/ceremony_${name}`, keyDir: L.KEY_DIR_REL, pinsRel: L.pinsFileRel(o.label), specRel: L.keySpecRel(o.label) };
}

let MAIN_LOG: string | null = null;

function log(msg: string): void {
  const line = `${new Date().toISOString()} ${msg}`;
  console.log(line);
  if (MAIN_LOG) fs.appendFileSync(abs(MAIN_LOG), sanitize(line) + "\n");
}

// ------------------------------------------------------------------ child processes

interface Outcome {
  code: number | null;
  stdout: string;
  stderr: string;
  ms: number;
  timedOut: boolean;
}

function runChild(cmd: string, args: string[], env: NodeJS.ProcessEnv, timeoutMs: number): Promise<Outcome> {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const child = spawn(cmd, args, { cwd: REPO_ROOT, env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true, shell: false });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    child.stdout.setEncoding("utf8").on("data", (d: string) => (stdout += d));
    child.stderr.setEncoding("utf8").on("data", (d: string) => (stderr += d));
    const timer = setTimeout(() => {
      timedOut = true;
      // On Windows this ends the node child only; a node it started can stay (checked after exit).
      child.kill();
    }, timeoutMs);
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, ms: Date.now() - t0, timedOut });
    });
  });
}

/**
 * After a suite child exits: true when its port still answers after 5 probes 1 s apart (a chain
 * node it started is left running; the quiet checks do not list the follow-up ports yet).
 */
async function portLeftOpen(port: number): Promise<boolean> {
  for (let i = 0; i < 5; i++) {
    if (!(await probePort(port))) return false;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return true;
}

const REKEY_URL = pathToFileURL(path.join(REPO_ROOT, "harness", "v4", "ceremony", "rekey.mjs")).href;

/** Environment of a child that must use the given key through the rekey loader. */
function rekeyEnv(label: string, keyDirRel: string, extra: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, PQID_V4_REKEY_LABEL: label, PQID_V4_REKEY_DIR: keyDirRel };
  delete env["PQID_V4_CONTRACTS"];
  delete env["PQID_RAPIDSNARK"];
  delete env["PQID_SUITE_PORT"];
  for (const [k, v] of Object.entries(extra)) {
    if (v === undefined) delete env[k];
    else env[k] = v;
  }
  return env;
}

function nodeTsx(script: string, args: string[], rekey: boolean): string[] {
  return ["--import", tsxImportUrl(), ...(rekey ? ["--import", REKEY_URL] : []), script, ...args];
}

// ------------------------------------------------------------------ git (read only)

function gitText(args: string[]): string | null {
  try {
    return execFileSync("git", args, { cwd: REPO_ROOT, encoding: "utf8", env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" }, stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
  } catch {
    return null;
  }
}

function gitBytes(args: string[]): Buffer | null {
  try {
    return execFileSync("git", args, { cwd: REPO_ROOT, env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" }, stdio: ["ignore", "pipe", "ignore"], windowsHide: true, maxBuffer: 64 * 1024 * 1024 });
  } catch {
    return null;
  }
}

/** Uncommitted files under L.CODE_PATHS (git status, read only); null when git status cannot be read. */
export function uncommittedCode(): string[] | null {
  const out = gitText(["status", "--porcelain", "--untracked-files=all", "--", ...L.CODE_PATHS]);
  if (out === null) return null;
  return out
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0)
    .map((l) => l.slice(3).trim());
}

/** Files under L.CODE_PATHS that differ between commit `from` and HEAD (git diff, read only); null when git cannot tell. */
export function codeChangedSince(from: string): string[] | null {
  if (!/^[0-9a-f]{40,64}$/.test(from)) return null;
  const out = gitText(["diff", "--name-only", "--no-renames", from, "HEAD", "--", ...L.CODE_PATHS]);
  if (out === null) return null;
  return out
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

export interface CodeFileRecord {
  /** SHA-256 of the working-tree bytes. */
  sha256: string | null;
  /** `git hash-object` of the file (after git's line-end normalization): the blob a commit would hold. */
  gitBlob: string | null;
  /** Blob id at HEAD (`git ls-tree HEAD`), null when the file is not committed. */
  headBlob: string | null;
  /** gitBlob equals headBlob (null when either is unknown). */
  matchesHead: boolean | null;
}

/** SHA-256 and git blob ids of the code files, so the record names a version a commit holds. */
export function codeRecord(files: readonly string[] = L.CODE_FILES): Record<string, CodeFileRecord> {
  const list = [...new Set(files)];
  const present = list.filter((f) => fs.existsSync(abs(f)));
  const blobsText = present.length ? gitText(["hash-object", "--", ...present]) : "";
  const blobs = (blobsText ?? "").split(/\r?\n/).filter((x) => x.length > 0);
  const blobOf = new Map<string, string>();
  if (blobs.length === present.length) present.forEach((f, i) => blobOf.set(f, blobs[i] as string));
  const head = new Map<string, string>();
  for (const line of (gitText(["ls-tree", "HEAD", "--", ...list]) ?? "").split(/\r?\n/)) {
    const m = /^\d+ blob ([0-9a-f]{40,64})\t(.+)$/.exec(line);
    if (m) head.set(m[2] as string, m[1] as string);
  }
  const out: Record<string, CodeFileRecord> = {};
  for (const f of list) {
    const gitBlob = blobOf.get(f) ?? null;
    const headBlob = head.get(f) ?? null;
    out[f] = { sha256: shaOrNull(f), gitBlob, headBlob, matchesHead: gitBlob !== null && headBlob !== null ? gitBlob === headBlob : null };
  }
  return out;
}

/**
 * Every source file of every package (packages/<name>/src/**, without __pycache__, node_modules
 * or dot folders) and every packages/<name>/package.json, sorted and repo-relative. The suite runs
 * packages/v4, common, issuer, ledger, pqc and others through their imports, so the post-fix rerun
 * records each file by SHA-256 and blob id; HEAD pins the rest of the tree.
 */
export function packageSourceFiles(): string[] {
  const out: string[] = [];
  const skip = (name: string) => name === "__pycache__" || name === "node_modules" || name.startsWith(".");
  const walk = (r: string): void => {
    for (const e of fs.readdirSync(abs(r), { withFileTypes: true })) {
      if (skip(e.name)) continue;
      const x = `${r}/${e.name}`;
      if (e.isDirectory()) walk(x);
      else if (e.isFile()) out.push(x);
    }
  };
  if (!fs.existsSync(abs("packages"))) return out;
  for (const p of fs.readdirSync(abs("packages"), { withFileTypes: true })) {
    if (!p.isDirectory() || skip(p.name)) continue;
    if (fs.existsSync(abs(`packages/${p.name}/src`))) walk(`packages/${p.name}/src`);
    if (fs.existsSync(abs(`packages/${p.name}/package.json`))) out.push(`packages/${p.name}/package.json`);
  }
  return out.sort();
}

/** Accepted SHA-256 per kit file: the working-tree file and the committed blob (HEAD). */
export function kitAccepted(): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const f of L.KIT_FILES) {
    const r = `ceremony/${f}`;
    const hs = new Set<string>();
    const w = shaOrNull(r);
    if (w) hs.add(w);
    const b = gitBytes(["show", `HEAD:${r}`]);
    if (b) hs.add(createHash("sha256").update(b).digest("hex"));
    if (hs.size > 0) out[f] = [...hs];
  }
  return out;
}

/** SHA-256 of the dev-key results the ledger cites; checked again at the end. */
function devResultHashes(): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const f of [L.DEV_SUITE_REL, L.DEV_MUTATION_REL, "results/v4/attack_matrix.json", "results/v4/mutation_progress.json", L.DEV_PINS_REL, "setup/pins.json"]) out[f] = shaOrNull(f);
  const dir = abs("results/v4/mutation");
  if (fs.existsSync(dir)) {
    for (const d of fs.readdirSync(dir).sort()) {
      const f = `results/v4/mutation/${d}/security_suite.json`;
      if (fs.existsSync(abs(f))) out[f] = shaOrNull(f);
    }
  }
  for (const f of ["credential_auth_v4_dev.zkey", "verification_key_dev.json", "Groth16VerifierV4_dev.sol", "setup_transcript_dev.json"]) out[`setup/out/v4/${f}`] = shaOrNull(`setup/out/v4/${f}`);
  return out;
}

// ------------------------------------------------------------------ inputs of the run

interface CeremonyInputs {
  transcriptRel: string;
  transcript: L.CeremonyTranscript;
  zkeyRel: string;
  vkeyRel: string;
  solRel: string;
  r1csRel: string;
  ptauRel: string;
  wasmRel: string;
  frozenR1csSha: string | null;
  pinnedPtauSha: string | null;
  /** SHA-256 of the frozen wasm when FREEZE.md, setup/pins_v4.json and the file agree (ceremony mode). */
  frozenWasmSha: string | null;
  kitFiles: Record<string, string[]>;
  notes: string[];
}

/**
 * The frozen r1cs and wasm SHA-256 when docs/v4/FREEZE.md, setup/pins_v4.json and the file
 * agree, and the pinned ptau SHA-256 when setup/pins.json and the file agree; null (with a
 * note) otherwise.
 */
export function frozenInputs(): { frozenR1csSha: string | null; frozenWasmSha: string | null; pinnedPtauSha: string | null; notes: string[] } {
  const notes: string[] = [];
  const freezeTable = L.parseFreezeTable(fs.readFileSync(abs(L.FREEZE_REL), "utf8"));
  const devPins = readJson<Record<string, { sha256?: string; path?: string }>>(L.DEV_PINS_REL);
  const freeze = freezeTable.get(L.FROZEN_R1CS_REL) ?? null;
  const pinV4 = devPins["v4/credential_auth_v4.r1cs"]?.sha256 ?? null;
  const onDisk = shaOrNull(L.FROZEN_R1CS_REL);
  const frozenR1csSha = freeze !== null && freeze === pinV4 && freeze === onDisk ? freeze : null;
  if (frozenR1csSha === null) notes.push(`frozen r1cs does not agree: FREEZE.md ${freeze}, pins_v4.json ${pinV4}, file ${onDisk}`);
  const wasmFreeze = freezeTable.get(L.FROZEN_WASM_REL) ?? null;
  const wasmPin = devPins["v4/credential_auth_v4.wasm"];
  const wasmOnDisk = shaOrNull(L.FROZEN_WASM_REL);
  const frozenWasmSha = wasmFreeze !== null && wasmPin?.sha256 === wasmFreeze && wasmPin?.path === L.FROZEN_WASM_REL && wasmOnDisk === wasmFreeze ? wasmFreeze : null;
  if (frozenWasmSha === null) notes.push(`frozen wasm does not agree: FREEZE.md ${wasmFreeze}, pins_v4.json ${wasmPin?.sha256 ?? null} (${wasmPin?.path ?? "no path"}), file ${wasmOnDisk}`);
  const pin = readJson<Record<string, { sha256?: string }>>(L.PINS_REL)[L.PTAU_PIN_NAME]?.sha256 ?? null;
  const ptauOnDisk = shaOrNull(L.PTAU_REL);
  const pinnedPtauSha = pin !== null && pin === ptauOnDisk && path.resolve(PTAU_FILE) === path.resolve(abs(L.PTAU_REL)) ? pin : null;
  if (pinnedPtauSha === null) notes.push(`pinned ptau does not agree: setup/pins.json ${pin}, file ${ptauOnDisk}`);
  return { frozenR1csSha, frozenWasmSha, pinnedPtauSha, notes };
}

export function loadInputs(o: Pick<Options, "mode" | "dry" | "finalDirRel">): CeremonyInputs {
  const transcriptRel = `${o.finalDirRel}/ceremony_transcript.json`;
  if (!fs.existsSync(abs(transcriptRel))) {
    throw new Error(
      o.dry ? `${transcriptRel} missing: run \`node ceremony/rehearse.mjs\` first (it writes the gitignored rehearsal outputs)` : `${transcriptRel} missing: the ceremony is finished when ceremony/HANDOFF_STEPS.md step 4 (finalize) has run`
    );
  }
  const t = readJson<L.CeremonyTranscript>(transcriptRel);
  const inFinal = (f: string | undefined, what: string) => {
    if (!f) throw new Error(`transcript has no ${what} file`);
    return `${o.finalDirRel}/${path.basename(f.replace(/\\/g, "/"))}`;
  };
  const notes: string[] = [];
  let r1csRel: string;
  let ptauRel: string;
  let wasmRel: string;
  let frozenR1csSha: string | null = null;
  let pinnedPtauSha: string | null = null;
  let frozenWasmSha: string | null = null;
  if (o.mode === "ceremony") {
    r1csRel = L.FROZEN_R1CS_REL;
    ptauRel = L.PTAU_REL;
    wasmRel = L.FROZEN_WASM_REL;
    const f = frozenInputs();
    frozenR1csSha = f.frozenR1csSha;
    pinnedPtauSha = f.pinnedPtauSha;
    frozenWasmSha = f.frozenWasmSha;
    notes.push(...f.notes);
  } else {
    r1csRel = L.cleanRel(t.circuit?.r1cs?.file ?? "", "transcript r1cs");
    ptauRel = L.cleanRel(t.ptau?.file ?? "", "transcript ptau");
    wasmRel = L.REHEARSAL_WASM_REL;
    notes.push("dry run: rehearsal transcript, throwaway tiny circuit and local ptau (REHEARSAL ONLY); not a result");
  }
  return {
    transcriptRel,
    transcript: t,
    zkeyRel: inFinal(t.final?.zkey?.file, "final zkey"),
    vkeyRel: inFinal(t.final?.verificationKey?.file, "verification key"),
    solRel: inFinal(t.final?.solidityVerifier?.file, "Solidity verifier"),
    r1csRel,
    ptauRel,
    wasmRel,
    frozenR1csSha,
    pinnedPtauSha,
    frozenWasmSha,
    kitFiles: kitAccepted(),
    notes,
  };
}

// ------------------------------------------------------------------ step: verify

interface VerifyResult {
  status: L.StepStatus;
  transcriptChecks: L.Check[];
  audit: { exit: number | null; passed: boolean; failedChecks: string[]; passedChecks: number; log: string };
  zkeyVerify: { exit: number | null; parsed: L.ParsedCliVerify; checks: L.Check[]; log: string };
}

async function stepVerify(o: Options, d: RunDirs, inp: CeremonyInputs): Promise<VerifyResult> {
  log(`[verify] transcript ${inp.transcriptRel}`);
  const checks = L.checkTranscript(inp.transcript, {
    mode: o.mode,
    frozenR1csSha: inp.frozenR1csSha,
    pinnedPtauSha: inp.pinnedPtauSha,
    external: o.external,
    files: { zkeySha: shaOrNull(inp.zkeyRel), vkeySha: shaOrNull(inp.vkeyRel), solSha: shaOrNull(inp.solRel) },
    kitFiles: inp.kitFiles,
  });
  for (const c of checks) if (c.status !== "pass") log(`[verify]   ${c.status.toUpperCase()} ${c.id}: ${c.detail}`);
  log(`[verify] transcript rules: ${checks.filter((c) => c.status === "pass").length} pass, ${L.failed(checks).length} fail, ${checks.filter((c) => c.status === "warn").length} warn, ${checks.filter((c) => c.status === "skipped").length} skipped`);

  log("[verify] coordinator.mjs audit (the kit's own check, from r1cs + ptau)");
  const auditArgs = ["ceremony/coordinator.mjs", "audit", "--transcript", inp.transcriptRel, "--zkey", inp.zkeyRel, "--r1cs", inp.r1csRel, "--ptau", inp.ptauRel, "--vkey", inp.vkeyRel, "--sol", inp.solRel];
  const a = await runChild(process.execPath, auditArgs, process.env, 30 * 60_000);
  const auditLog = `${d.logs}/audit.log`;
  writeTextNew(auditLog, `$ node ${auditArgs.join(" ")}\n${a.stdout}${a.stderr ? `\n[stderr]\n${a.stderr}` : ""}\n[exit ${a.code}${a.timedOut ? ", timed out" : ""}, ${a.ms} ms]\n`);
  const audit = { exit: a.code, ...L.parseAuditLog(a.stdout), log: auditLog };
  log(`[verify] audit: ${audit.passed ? "ALL CHECKS PASSED" : `FAILED (${audit.failedChecks.join("; ") || `exit ${a.code}`})`}`);

  log("[verify] snarkjs zkey verify <r1cs> <ptau> <final zkey> (plain snarkjs 0.7.4 CLI)");
  const cli = "node_modules/snarkjs/build/cli.cjs";
  const vArgs = [cli, "zkey", "verify", inp.r1csRel, inp.ptauRel, inp.zkeyRel];
  const v = await runChild(process.execPath, vArgs, process.env, 30 * 60_000);
  const vLog = `${d.logs}/zkey_verify.log`;
  writeTextNew(vLog, `$ node ${vArgs.join(" ")}\n${v.stdout}${v.stderr ? `\n[stderr]\n${v.stderr}` : ""}\n[exit ${v.code}${v.timedOut ? ", timed out" : ""}, ${v.ms} ms]\n`);
  const parsed = L.parseCliVerify(v.stdout + "\n" + v.stderr);
  const vChecks = L.compareVerifyWithTranscript(inp.transcript, parsed);
  vChecks.push({ id: "zkeyVerify.exit", status: v.code === 0 ? "pass" : "fail", detail: `exit ${v.code}` });
  for (const c of vChecks) log(`[verify]   ${c.status.toUpperCase()} ${c.id}: ${c.detail}`);

  const all = [...checks, ...vChecks];
  const status: L.StepStatus = L.failed(all).length > 0 || !audit.passed ? "fail" : all.some((c) => c.status === "warn") ? "review" : "pass";
  const res: VerifyResult = { status, transcriptChecks: checks, audit, zkeyVerify: { exit: v.code, parsed, checks: vChecks, log: vLog } };
  writeJsonRel(`${d.out}/verify/verify.json`, { schema: "pqid/v4-ceremony-verify/v1", mode: o.mode, inputs: { transcript: inp.transcriptRel, zkey: inp.zkeyRel, r1cs: inp.r1csRel, ptau: inp.ptauRel }, ...res, zkeyVerify: { ...res.zkeyVerify, parsed: { ok: parsed.ok, circuitHash: parsed.circuitHash, entries: parsed.contributions.map((c) => ({ index: c.index, type: c.type, contributionHash: c.contributionHash, beaconHash: c.beaconHash ?? null, numIterationsExp: c.numIterationsExp ?? null })) } } });
  log(`[verify] ${status.toUpperCase()}`);
  return res;
}

// ------------------------------------------------------------------ step: keys

async function stepKeys(o: Options, d: RunDirs, inp: CeremonyInputs): Promise<{ status: L.StepStatus; result: KeyChecksResult | null; config: Record<string, unknown> }> {
  let input: Record<string, unknown>;
  let expectPublic: string[] | null;
  let otherVkey: string | null;
  if (o.mode === "ceremony") {
    if (inp.frozenWasmSha === null) {
      const why = `the frozen wasm ${L.FROZEN_WASM_REL} does not agree with FREEZE.md and its pin in ${L.DEV_PINS_REL}; no proof is made with it`;
      writeJsonRel(`${d.out}/keys/key_checks.json`, { error: why });
      log(`[keys] FAIL: ${why}`);
      return { status: "fail", result: null, config: { wasm: fileRec(L.FROZEN_WASM_REL), wasmPinned: false } };
    }
    const lock = readJson<{ versions: Record<string, { file: string; inputSha256: string; publicSignals: string[] }> }>(L.BENCH_LOCK_REL).versions["v4"];
    if (!lock) throw new Error(`${L.BENCH_LOCK_REL} has no v4 entry`);
    if (inputFileSha(abs(lock.file)) !== lock.inputSha256) throw new Error(`${lock.file} does not match its pin in ${L.BENCH_LOCK_REL}`);
    input = readJson<Record<string, unknown>>(lock.file);
    expectPublic = lock.publicSignals;
    otherVkey = L.DEV_VKEY_REL;
  } else {
    input = { ...L.REHEARSAL_INPUT };
    expectPublic = null;
    const other = `${L.REHEARSAL_OTHER_FINAL_DIR_REL}/verification_key.json`;
    otherVkey = fs.existsSync(abs(other)) ? other : null;
  }
  const config = {
    zkey: inp.zkeyRel,
    vkey: inp.vkeyRel,
    wasm: inp.wasmRel,
    input,
    expectPublic,
    beacon: { value: inp.transcript.beacon.value, iterExp: inp.transcript.beacon.numIterationsExp },
    otherVkey,
    control: { vkey: L.CONTROL_V2_VKEY_REL, beacon: L.CONTROL_V2_BEACON, iterExp: L.CONTROL_V2_ITER_EXP },
  };
  const cfgRel = `${d.out}/keys/key_checks_config.json`;
  writeJsonRel(cfgRel, config);
  log(`[keys] key_checks.ts (wasm ${inp.wasmRel}${o.mode === "ceremony" ? ", pinned" : ""}; other key ${otherVkey ?? "none"}; control ${L.CONTROL_V2_VKEY_REL})`);
  const r = await runChild(process.execPath, nodeTsx("harness/v4/ceremony/key_checks.ts", ["--config", cfgRel], false), process.env, 30 * 60_000);
  writeTextNew(`${d.logs}/key_checks.log`, `${r.stdout}${r.stderr ? `\n[stderr]\n${r.stderr}` : ""}\n[exit ${r.code}, ${r.ms} ms]\n`);
  const result = lastJsonLine<KeyChecksResult>(r.stdout);
  writeJsonRel(`${d.out}/keys/key_checks.json`, result ?? { error: `no result (exit ${r.code})` });
  const status: L.StepStatus = result?.pass === true && r.code === 0 ? "pass" : "fail";
  if (result) {
    log(`[keys] vkey = zkey export: ${result.vkeyMatchesZkeyExport}; proof verifies: ${result.proof.verifies}; public signals as pinned: ${result.proof.publicSignalsMatch}; rejected by the other key: ${result.proof.rejectedByOtherKey}`);
    log(`[keys] same circuit as the other key: ${JSON.stringify(result.sameCircuitAsOther)}; beacon-derived delta matches: ${result.trapdoor.beaconDerivedDeltaMatchesKey}; forged proof verifies: ${result.trapdoor.forgedProofVerifies}; control ${JSON.stringify(result.trapdoor.control)}`);
  }
  log(`[keys] ${status.toUpperCase()}`);
  return { status, result, config: { file: cfgRel, otherVkey, wasm: fileRec(inp.wasmRel), wasmPinned: o.mode === "ceremony" ? true : null, expectPublicFrom: o.mode === "ceremony" ? L.BENCH_LOCK_REL : null } };
}

// ------------------------------------------------------------------ step: install

interface InstallRecord {
  status: L.StepStatus;
  keyDir: string;
  files: Array<{ role: string; file: string; source: string; sha256: string; bytes: number; action: "copied" | "unchanged" }>;
  pins: { file: string; added: string[]; unchanged: string[] };
  keySpec: { file: string; action: "written" | "unchanged" | "not written" };
  consumers: { cmp: string; e2e: string };
  problems: string[];
}

type Sources = Record<L.InstallTarget["role"], { src: string; want: string }>;

function installSources(inp: CeremonyInputs): Sources {
  const t = inp.transcript;
  return {
    zkey: { src: inp.zkeyRel, want: t.final.zkey.sha256 },
    vkey: { src: inp.vkeyRel, want: t.final.verificationKey.sha256 },
    sol: { src: inp.solRel, want: t.final.solidityVerifier.sha256 },
    transcript: { src: inp.transcriptRel, want: sha256FileHex(abs(inp.transcriptRel)) },
  };
}

function textSourcesWithCR(targets: readonly L.InstallTarget[], sources: Sources): string[] {
  return L.crProblems(targets.filter((tg) => tg.role !== "zkey").map((tg) => ({ rel: sources[tg.role].src, bytes: fs.readFileSync(abs(sources[tg.role].src)) })));
}

function pinEntriesFor(label: string, targets: readonly L.InstallTarget[], sources: Sources): Record<string, L.PinEntry> {
  const out: Record<string, L.PinEntry> = {};
  for (const tg of targets) out[tg.pinKey] = { sha256: sources[tg.role].want, label, path: tg.rel };
  return out;
}

/**
 * Everything the install step would refuse, checked before the run starts: a dev overlap, a
 * target that exists with other content, a ceremony pin or key spec with other content, a text
 * source with CR bytes. Reads only.
 */
export function installConflicts(o: Pick<Options, "label">, inp: CeremonyInputs, d: Pick<RunDirs, "keyDir" | "pinsRel" | "specRel">): string[] {
  const problems: string[] = [];
  const specRel = keySpecOf(d);
  const targets = L.installTargets(o.label, d.keyDir);
  try {
    L.assertNoDevOverlap(targets, readJson<Record<string, { path?: string }>>(L.DEV_PINS_REL), d.pinsRel);
  } catch (e) {
    problems.push((e as Error).message);
  }
  const sources = installSources(inp);
  for (const tg of targets) {
    const have = shaOrNull(tg.rel);
    if (have !== null && have !== sources[tg.role].want) problems.push(`${tg.rel} exists with other content (${have}); the follow-up never overwrites a key file`);
  }
  problems.push(...textSourcesWithCR(targets, sources));
  if (fs.existsSync(abs(d.pinsRel))) {
    try {
      L.addPinEntries(fs.readFileSync(abs(d.pinsRel), "utf8"), pinEntriesFor(o.label, targets, sources));
    } catch (e) {
      problems.push(`${d.pinsRel}: ${(e as Error).message}`);
    }
  }
  if (fs.existsSync(abs(specRel)) && fs.readFileSync(abs(specRel), "utf8") !== JSON.stringify(L.e2eKeySpec(o.label, d.keyDir, d.pinsRel), null, 2) + "\n") problems.push(`${specRel} exists with other content`);
  return problems;
}

/** The e2e key spec path of a run that installs a key (never the post-fix rerun). */
function keySpecOf(d: Pick<RunDirs, "specRel">): string {
  if (d.specRel === null) throw new Error("internal: this run installs no key and has no key spec");
  return d.specRel;
}

async function stepInstall(o: Options, d: RunDirs, inp: CeremonyInputs): Promise<InstallRecord> {
  const targets = L.installTargets(o.label, d.keyDir);
  const specRel = keySpecOf(d);
  const devPins = readJson<Record<string, { path?: string }>>(L.DEV_PINS_REL);
  L.assertNoDevOverlap(targets, devPins, d.pinsRel);
  const t = inp.transcript;
  const sources = installSources(inp);
  // Text files with CR bytes would be committed with other bytes than their pins: nothing is copied.
  const cr = textSourcesWithCR(targets, sources);
  if (cr.length > 0) {
    for (const p of cr) log(`[install] FAIL: ${p}`);
    const rec: InstallRecord = { status: "fail", keyDir: d.keyDir, files: [], pins: { file: d.pinsRel, added: [], unchanged: [] }, keySpec: { file: specRel, action: "not written" }, consumers: { cmp: "not checked", e2e: "not checked" }, problems: cr };
    writeJsonRel(`${d.out}/install.json`, rec);
    return rec;
  }
  // Refuse before writing anything when any target exists with other content.
  for (const tg of targets) {
    const have = shaOrNull(tg.rel);
    if (have !== null && have !== sources[tg.role].want) throw new Refused(`${tg.rel} exists with other content (${have}); the follow-up never overwrites a key file`);
    if (shaOrNull(sources[tg.role].src) !== sources[tg.role].want) throw new Error(`${sources[tg.role].src} does not match the transcript (${sources[tg.role].want})`);
  }
  const files: InstallRecord["files"] = [];
  for (const tg of targets) {
    const s = sources[tg.role];
    let action: "copied" | "unchanged" = "unchanged";
    if (!fs.existsSync(abs(tg.rel))) {
      fs.mkdirSync(path.dirname(abs(tg.rel)), { recursive: true });
      fs.copyFileSync(abs(s.src), abs(tg.rel), fs.constants.COPYFILE_EXCL);
      action = "copied";
    }
    const sha = sha256FileHex(abs(tg.rel));
    if (sha !== s.want) throw new Error(`${tg.rel}: SHA-256 after the copy is ${sha}, expected ${s.want}`);
    files.push({ role: tg.role, file: tg.rel, source: s.src, sha256: sha, bytes: fs.statSync(abs(tg.rel)).size, action });
    log(`[install] ${tg.rel} ${action} (${sha.slice(0, 16)}...)`);
  }
  const ext = o.external.map((i) => `#${i}`).join(", ");
  const n = t.contributions.length;
  const source = t.beacon.source.kind === "drand" ? `drand round ${t.beacon.source.round}` : t.beacon.source.kind === "bitcoin" ? `Bitcoin block ${t.beacon.source.height}` : `${t.beacon.source.kind} beacon`;
  const transcriptTarget = targets.find((x) => x.role === "transcript") as L.InstallTarget;
  const entries = pinEntriesFor(o.label, targets, sources);
  for (const tg of targets) {
    const e = entries[tg.pinKey] as L.PinEntry;
    if (tg.role === "zkey") e.note = `${o.label} key: ${n} contributions (declared external: ${ext}) then the ${source}, 2^${t.beacon.numIterationsExp} iterations; transcript ${transcriptTarget.rel}; checked by harness/v4/ceremony/followup.ts run ${d.runId}`;
    if (tg.role === "sol") e.note = "contract Groth16Verifier (snarkjs 0.7.4 template), exported by the ceremony coordinator";
  }
  const existing = fs.existsSync(abs(d.pinsRel)) ? fs.readFileSync(abs(d.pinsRel), "utf8") : L.EMPTY_PINS_TEXT;
  const pins = L.addPinEntries(existing, entries);
  if (pins.added.length > 0) {
    fs.mkdirSync(path.dirname(abs(d.pinsRel)), { recursive: true });
    fs.writeFileSync(abs(d.pinsRel), pins.text);
  }
  log(`[install] ${d.pinsRel}: added ${pins.added.length}, unchanged ${pins.unchanged.length}`);
  const specText = JSON.stringify(L.e2eKeySpec(o.label, d.keyDir, d.pinsRel), null, 2) + "\n";
  let specAction: "written" | "unchanged" = "unchanged";
  if (fs.existsSync(abs(specRel))) {
    if (fs.readFileSync(abs(specRel), "utf8") !== specText) throw new Refused(`${specRel} exists with other content`);
  } else {
    fs.writeFileSync(abs(specRel), specText, { flag: "wx" });
    specAction = "written";
  }
  log(`[install] ${specRel} ${specAction}`);
  // The key must load through the loaders of the campaigns that will use it.
  const problems: string[] = [];
  let cmp = "not checked";
  let e2e = "not checked";
  const zkeyT = targets.find((x) => x.role === "zkey") as L.InstallTarget;
  const vkeyT = targets.find((x) => x.role === "vkey") as L.InstallTarget;
  try {
    const { resolveV4Key } = await import("../cmp/spec.ts");
    const k = resolveV4Key({ zkey: zkeyT.rel, vkey: vkeyT.rel, label: L.cmpKeyLabel(o.label), pins: d.pinsRel });
    cmp = `ok: resolveV4Key -> label '${k.keyLabel}', zkey pin ${k.zkey.pin?.file}#${k.zkey.pin?.key}, vkey pin ${k.vkey.pin?.file}#${k.vkey.pin?.key}`;
  } catch (e) {
    cmp = `error: ${(e as Error).message}`;
    problems.push(`cmp loader: ${(e as Error).message}`);
  }
  try {
    const { loadKeySpec } = await import("../e2e/lib.ts");
    const k = loadKeySpec(specRel);
    e2e = `ok: loadKeySpec -> label '${k.spec.label}', zkey ${k.artifacts.zkey.sha256.slice(0, 16)}..., vkey ${k.artifacts.vkey.sha256.slice(0, 16)}..., wasm ${k.artifacts.wasm.sha256.slice(0, 16)}...`;
  } catch (e) {
    e2e = `error: ${(e as Error).message}`;
    problems.push(`e2e loader: ${(e as Error).message}`);
  }
  log(`[install] cmp loader: ${cmp}`);
  log(`[install] e2e loader: ${e2e}`);
  // A loader problem is a change in the campaign code, not in the key: flagged for review.
  const rec: InstallRecord = { status: problems.length ? "review" : "pass", keyDir: d.keyDir, files, pins: { file: d.pinsRel, added: pins.added, unchanged: pins.unchanged }, keySpec: { file: specRel, action: specAction }, consumers: { cmp, e2e }, problems };
  writeJsonRel(`${d.out}/install.json`, rec);
  log(`[install] ${rec.status.toUpperCase()}`);
  return rec;
}

// ------------------------------------------------------------------ the key the suite uses

export interface SuiteKey {
  label: string;
  keyDir: string;
  zkey: { file: string; sha256: string };
  vkey: { file: string; sha256: string };
  note: string;
  /** Dry run only: how the throwaway key was made and how it compares with the dev key. */
  derivation?: { from: string; fromSha256: string | null; step: string; vsDevKey: ReturnType<typeof L.compareVkeys> };
  /** Post-fix rerun only: the six dev files with their setup/pins_v4.json entries (checked). */
  pinned?: L.PinnedFile[];
}

/**
 * Post-fix rerun: the pinned dev key, unchanged (setup/out/v4/*_dev.* and the frozen r1cs and
 * wasm, each checked against setup/pins_v4.json). It is the package default, so no loader.
 */
export function devPinnedKey(): SuiteKey & { pinned: L.PinnedFile[] } {
  const r = L.checkDevKeyPins(readJson<Record<string, { sha256?: string; label?: string; path?: string }>>(L.DEV_PINS_REL), shaOrNull);
  if (r.problems.length > 0) throw new Refused(`the dev key does not match its pins: ${r.problems.join("; ")}`);
  const get = (role: string) => {
    const f = r.files.find((x) => x.role === role) as L.PinnedFile;
    return { file: f.file, sha256: f.sha256 };
  };
  return { label: L.DEV_LABEL, keyDir: L.KEY_DIR_REL, zkey: get("zkey"), vkey: get("vkey"), note: `the pinned dev key (${L.DEV_PINS_REL}): the package default, no rekey loader; ${L.FIXCHECK_RUN_LABEL}`, pinned: r.files };
}

/** The rekey loader serves every key but the dev key (it refuses the dev label); the dev key is the package default. */
function usesLoader(k: Pick<SuiteKey, "label">): boolean {
  return k.label !== L.DEV_LABEL;
}

/** Environment of a child without the loader: no rekey, contracts, prover or port override from the parent. */
function devEnv(extra: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const v of ["PQID_V4_REKEY_LABEL", "PQID_V4_REKEY_DIR", "PQID_V4_CONTRACTS", "PQID_RAPIDSNARK", "PQID_SUITE_PORT"]) delete env[v];
  for (const [k, v] of Object.entries(extra)) {
    if (v === undefined) delete env[k];
    else env[k] = v;
  }
  return env;
}

/** Environment of a suite, mutant or probe child for this key. */
function childEnv(k: Pick<SuiteKey, "label" | "keyDir">, extra: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return usesLoader(k) ? rekeyEnv(k.label, k.keyDir, extra) : devEnv(extra);
}

/** Real run: the installed key, checked against its pins file. */
export function installedKey(o: Pick<Options, "label">, d: Pick<RunDirs, "keyDir" | "pinsRel">): SuiteKey {
  const t = L.installTargets(o.label, d.keyDir);
  const pins = fs.existsSync(abs(d.pinsRel)) ? readJson<Record<string, { sha256?: string; label?: string; path?: string }>>(d.pinsRel) : {};
  const get = (role: L.InstallTarget["role"]) => {
    const tg = t.find((x) => x.role === role) as L.InstallTarget;
    const pin = pins[tg.pinKey];
    const sha = shaOrNull(tg.rel);
    if (!pin || pin.path !== tg.rel || pin.label !== o.label) throw new Refused(`${tg.rel}: no '${o.label}' pin in ${d.pinsRel} (run the install step first)`);
    if (sha !== pin.sha256) throw new Refused(`${tg.rel}: SHA-256 ${sha} differs from its pin ${pin.sha256}`);
    return { file: tg.rel, sha256: sha as string };
  };
  return { label: o.label, keyDir: d.keyDir, zkey: get("zkey"), vkey: get("vkey"), note: `the installed ${o.label} key (pins ${d.pinsRel})` };
}

const QUIET = { info: () => undefined, warn: () => undefined, error: () => undefined, debug: () => undefined };

/**
 * Dry run: the rehearsal key belongs to a tiny circuit, so the suite and mutation steps use a
 * throwaway key of the v4 circuit with the label "dryrun": the dev zkey plus one phase-2
 * contribution with random entropy (not kept). It has the dev key's alpha, beta, gamma and IC
 * and a delta of its own, so a prover or verifier that still read the dev key would break the
 * suite's honest controls, while the verdicts must equal the dev run's. Written under the
 * smoke folder; pinned there like an installed key.
 */
export async function dryrunKey(d: Pick<RunDirs, "out">): Promise<SuiteKey> {
  const label = "dryrun";
  const dir = `${d.out}/dryrun_key`;
  const names = L.installTargets(label, dir);
  const t = (role: L.InstallTarget["role"]) => names.find((x) => x.role === role) as L.InstallTarget;
  if (names.some((tg) => fs.existsSync(abs(tg.rel)))) throw new Error(`${dir} already holds key files`);
  fs.mkdirSync(abs(dir), { recursive: true });
  const snarkjs = await import("snarkjs");
  const t0 = Date.now();
  await snarkjs.zKey.contribute(abs(L.DEV_ZKEY_REL), abs(t("zkey").rel), "DRY RUN throwaway contribution (harness/v4/ceremony/followup.ts)", randomBytes(32).toString("hex"), QUIET);
  const vkey = (await snarkjs.zKey.exportVerificationKey(abs(t("zkey").rel), QUIET)) as L.VkeyLike;
  fs.writeFileSync(abs(t("vkey").rel), JSON.stringify(vkey, null, 2) + "\n", { flag: "wx" });
  const template = fs.readFileSync(path.join(REPO_ROOT, "node_modules", "snarkjs", "templates", "verifier_groth16.sol.ejs"), "utf8");
  fs.writeFileSync(abs(t("sol").rel), await snarkjs.zKey.exportSolidityVerifier(abs(t("zkey").rel), { groth16: template }, QUIET), { flag: "wx" });
  const vsDevKey = L.compareVkeys(readJson<L.VkeyLike>(L.DEV_VKEY_REL), vkey);
  const step = "one phase-2 contribution with 32 random bytes of entropy (not kept) on top of the dev zkey (snarkjs zKey.contribute)";
  const derivation = { from: L.DEV_ZKEY_REL, fromSha256: shaOrNull(L.DEV_ZKEY_REL), step, vsDevKey };
  writeJsonRel(t("transcript").rel, { schema: "pqid/v4-ceremony-dryrun-key/v1", label: "DRY RUN throwaway key of the v4 circuit; not a key of the project; pinned only inside this smoke folder", ...derivation });
  log(`[dryrun-key] made in ${Math.round((Date.now() - t0) / 1000)} s: same alpha/beta/gamma ${vsDevKey.sameAlphaBetaGamma}, same IC ${vsDevKey.sameIC}, delta differs ${vsDevKey.deltaDiffers}`);
  if (!(vsDevKey.sameAlphaBetaGamma && vsDevKey.sameIC && vsDevKey.deltaDiffers)) throw new Error(`dry-run key: expected the dev key's alpha, beta, gamma and IC with another delta, got ${JSON.stringify(vsDevKey)}`);
  // Pinned like an installed key, so the dry run goes through the same pin check as a real run.
  const pinsRel = L.pinsFileRel(label, dir);
  const entries: Record<string, L.PinEntry> = {};
  for (const tg of names) entries[tg.pinKey] = { sha256: sha256FileHex(abs(tg.rel)), label, path: tg.rel, note: "DRY RUN throwaway key (dev zkey plus one random contribution); not a key of the project" };
  fs.writeFileSync(abs(pinsRel), L.addPinEntries(L.EMPTY_PINS_TEXT, entries).text, { flag: "wx" });
  const k = installedKey({ label }, { keyDir: dir, pinsRel });
  return { ...k, note: "DRY RUN: a throwaway key of the v4 circuit (dev zkey plus one random phase-2 contribution: same circuit and phase 1, its own delta) under the label 'dryrun'; checks the loader, the pin check and the output paths; not a result", derivation };
}

/**
 * Dry run with `--steps mutation --baseline <smoke run>/suite/security_suite.json`: the throwaway
 * key that made that baseline (read only, checked against its pins in that smoke folder).
 */
function dryrunKeyOfBaseline(baselineRel: string): SuiteKey {
  const zkeyFile = readJson<{ artifacts?: { zkey?: { file?: string } } }>(baselineRel).artifacts?.zkey?.file;
  if (!zkeyFile) throw new Refused(`baseline ${baselineRel} names no zkey`);
  const dir = L.cleanRel(path.posix.dirname(zkeyFile), "baseline key folder");
  if (!dir.startsWith(`${L.CEREMONY_SMOKE_REL}/`)) throw new Refused(`baseline ${baselineRel} was not made by a dry run (its key is in ${dir})`);
  const k = installedKey({ label: "dryrun" }, { keyDir: dir, pinsRel: L.pinsFileRel("dryrun", dir) });
  return { ...k, note: `DRY RUN: the throwaway 'dryrun' key of the baseline's smoke folder (${dir}); not a result` };
}

/** The post-fix rerun's two label texts, on every record it writes (empty for any other key). */
const FIXCHECK_TEXT = (k: Pick<SuiteKey, "label">) => (k.label === L.DEV_LABEL ? { run: L.FIXCHECK_RUN_LABEL, key: L.DEV_KEY_TEXT } : {});

/** File name of the key probe in a step folder: key_probe.json for the dev key (no rekey happens), rekey_probe.json under the loader. */
export function probeFileName(k: Pick<SuiteKey, "label">): string {
  return usesLoader(k) ? "rekey_probe.json" : "key_probe.json";
}

/**
 * Runs rekey_probe.ts the way the suite children run (with the rekey loader, or without it for
 * the dev key) and checks that it resolves this key. `outRel` null: nothing is written.
 */
export async function probeKey(k: SuiteKey, outRel: string | null): Promise<RekeyProbe> {
  const loader = usesLoader(k);
  const r = await runChild(process.execPath, nodeTsx("harness/v4/ceremony/rekey_probe.ts", [], loader), childEnv(k), 120_000);
  const p = lastJsonLine<RekeyProbe>(r.stdout);
  if (outRel !== null) writeJsonRel(outRel, { ...FIXCHECK_TEXT(k), ...(p ?? { error: sanitize(`no probe result (exit ${r.code}): ${r.stderr.slice(0, 2000)}`) }) });
  if (!p) throw new Error(`key probe failed (exit ${r.code}): ${sanitize(r.stderr.slice(0, 500))}`);
  if (!L.probeResolvesKey(p, k, loader)) throw new Error(`key probe: the child does not resolve the ${k.label} key ${loader ? "under the rekey loader" : "without the loader"}: ${JSON.stringify(p)}`);
  return p;
}

async function assertPortFree(port: number): Promise<void> {
  if (await probePort(port)) throw new Refused(`port ${port} on 127.0.0.1 already answers; the follow-up never starts its Anvil next to another node (startAnvil would talk to it)`);
}

// ------------------------------------------------------------------ step: suite

interface SuiteResult {
  status: L.StepStatus;
  out: string;
  file: string | null;
  exit: number | null;
  seconds: number;
  pass: boolean | null;
  keyLabel: string | null;
  summary: Record<string, unknown> | null;
  keyMatches: boolean;
  /** "still answers" when a node stayed on the suite's port after the child exited (an error). */
  portAfterExit: "closed" | "still answers";
  /** The frozen suite writes a fixed label text that names the dev key; this note says which fields are authoritative. */
  labelTextNote: string | null;
  keySwitch: L.KeySwitch;
  vsDev: L.SuiteComparison | null;
  /** Post-fix rerun: attack_matrix.json of the run deep-equals results/v4/attack_matrix.json (null: not compared). */
  attackMatrixEqual: boolean | null;
  compareSuitePy: { exit: number | null; log: string } | null;
  probe: RekeyProbe;
}

async function stepSuite(o: Options, d: RunDirs, k: SuiteKey): Promise<SuiteResult> {
  // The post-fix rerun is strict: a different failed-check list, summary field, top-level output,
  // record list or attack matrix is review too.
  const strict = o.kind === "devrerun";
  const out = `${d.out}/suite`;
  const port = L.CEREMONY_PORTS.suite;
  if (fs.existsSync(abs(`${out}/security_suite.json`))) throw new Refused(`${out}/security_suite.json exists; a suite output is never overwritten`);
  const probe = await probeKey(k, `${out}/${probeFileName(k)}`);
  log(`[suite] key probe (${usesLoader(k) ? "rekey loader" : "no loader: the pinned dev key"}): the child resolves ${probe.zkey} (label ${probe.keyLabel})`);
  await assertPortFree(port);
  const cfgRel = `${out}/config.json`;
  // The frozen suite copies the config name into its output's `config` field: the post-fix rerun's output carries both labels there.
  writeJsonRel(cfgRel, { name: strict ? L.fixcheckConfigName("v4") : `v4:${k.label}-key`, port, out });
  log(`[suite] harness/v4/security_suite.ts --config ${cfgRel} (port ${port}; ${k.note})`);
  const t0 = Date.now();
  const r = await runChild(process.execPath, nodeTsx("harness/v4/security_suite.ts", ["--config", cfgRel], usesLoader(k)), childEnv(k), 40 * 60_000);
  const seconds = Math.round((Date.now() - t0) / 1000);
  writeTextNew(`${d.logs}/suite.log`, `${r.stdout}${r.stderr ? `\n[stderr]\n${r.stderr}` : ""}\n[exit ${r.code}${r.timedOut ? ", timed out" : ""}, ${seconds} s]\n`);
  const portAfterExit = (await portLeftOpen(port)) ? "still answers" : "closed";
  if (portAfterExit !== "closed") log(`[suite] ERROR: port ${port} still answers after the suite exited; a chain node it started may be running (stop it before any timed series)`);
  const file = `${out}/security_suite.json`;
  if (!fs.existsSync(abs(file))) {
    log(`[suite] FAIL: no output (exit ${r.code})`);
    return { status: "fail", out, file: null, exit: r.code, seconds, pass: null, keyLabel: null, summary: null, keyMatches: false, portAfterExit, labelTextNote: null, keySwitch: L.keySwitchFor(k.label), vsDev: null, attackMatrixEqual: null, compareSuitePy: null, probe };
  }
  const s = readJson<L.SuiteFile & { artifacts?: Record<string, { file?: string; sha256?: string; keyLabel?: string } | undefined> }>(file);
  let keyMatches = s.keyLabel === k.label && s.artifacts?.["zkey"]?.file === k.zkey.file && s.artifacts?.["zkey"]?.sha256 === k.zkey.sha256 && s.artifacts?.["zkey"]?.keyLabel === k.label && s.artifacts?.["vkey"]?.file === k.vkey.file && s.artifacts?.["vkey"]?.sha256 === k.vkey.sha256;
  // The dev key is pinned with its circuit: the r1cs and wasm the suite read must be the pinned ones too.
  for (const p of (k.pinned ?? []).filter((x) => x.role === "r1cs" || x.role === "wasm")) keyMatches &&= s.artifacts?.[p.role]?.file === p.file && s.artifacts?.[p.role]?.sha256 === p.sha256;
  const labelText = (s as { label?: string }).label ?? "";
  const labelTextNote = /dev key/.test(labelText) && k.label !== "dev" ? L.suiteLabelNote(labelText, k.label) : null;
  const vsDev = L.compareSuites(readJson<L.SuiteFile>(L.DEV_SUITE_REL), s, { strict });
  let attackMatrixEqual: boolean | null = null;
  if (strict) {
    const mine = `${out}/attack_matrix.json`;
    attackMatrixEqual = fs.existsSync(abs(mine)) && fs.existsSync(abs(L.DEV_ATTACK_MATRIX_REL)) && isDeepStrictEqual(readJson<unknown>(mine), readJson<unknown>(L.DEV_ATTACK_MATRIX_REL));
  }
  const rule = strict
    ? `per (record id, route): accepted, valid and stopping layer (artifact/compare_suite.py); ${L.FIXCHECK_RUN_LABEL}: the failed-check lists, every summary field, pass, the top-level ${L.SUITE_STRICT_FIELDS.join(", ")}, the record list (id, kind, number of attempts) and the attack matrix too; any difference is review`
    : "per (record id, route): accepted, valid and stopping layer (artifact/compare_suite.py); failed-check lists reported separately";
  writeJsonRel(`${out}/vs_dev.json`, {
    schema: "pqid/v4-suite-comparison/v1",
    ...FIXCHECK_TEXT(k),
    base: { file: L.DEV_SUITE_REL, sha256: shaOrNull(L.DEV_SUITE_REL), keyLabel: "dev", run: "dev run 10" },
    next: { file, sha256: shaOrNull(file), keyLabel: s.keyLabel, labelTextNote },
    keySwitch: L.keySwitchFor(k.label),
    rule,
    ...vsDev,
    ...(strict ? { attackMatrix: { base: L.DEV_ATTACK_MATRIX_REL, next: `${out}/attack_matrix.json`, equal: attackMatrixEqual } } : {}),
  });
  const py = process.env["PQID_PYTHON"] ?? (process.platform === "win32" ? "python" : "python3");
  let compareSuitePy: SuiteResult["compareSuitePy"] = null;
  try {
    const c = await runChild(py, ["artifact/compare_suite.py", L.DEV_SUITE_REL, file], process.env, 120_000);
    const lg = `${d.logs}/compare_suite.log`;
    writeTextNew(lg, `$ ${path.basename(py)} artifact/compare_suite.py ${L.DEV_SUITE_REL} ${file}\n${c.stdout}${c.stderr}\n[exit ${c.code}]\n`);
    compareSuitePy = { exit: c.code, log: lg };
  } catch {
    compareSuitePy = null;
  }
  const status = L.suiteStepStatus({ exit: r.code, pass: s.pass, keyMatches, portClosed: portAfterExit === "closed", vsDev, compareSuitePy, strict, attackMatrixEqual });
  log(`[suite] pass ${s.pass}; key in the output = the ${k.label} key: ${keyMatches}; verdicts vs dev run 10: ${vsDev.verdictsNew} vs ${vsDev.verdictsBase}, ${vsDev.verdictDiffs.length} differ, ${vsDev.summaryDiffs.length} summary differences, ${vsDev.checkDiffs.length} check-list differences${strict ? `; attack matrix equal: ${attackMatrixEqual}` : ""}; compare_suite.py exit ${compareSuitePy?.exit ?? "not run"}; port after exit ${portAfterExit}`);
  if (strict) for (const x of [...vsDev.verdictDiffs, ...vsDev.summaryDiffs, ...vsDev.checkDiffs].slice(0, 50)) log(`[suite]   REVIEW difference: ${x}`);
  log(`[suite] ${status.toUpperCase()} (${seconds} s)`);
  return { status, out, file, exit: r.code, seconds, pass: s.pass ?? null, keyLabel: s.keyLabel ?? null, summary: s.summary ?? null, keyMatches, portAfterExit, labelTextNote, keySwitch: L.keySwitchFor(k.label), vsDev, attackMatrixEqual, compareSuitePy, probe };
}

// ------------------------------------------------------------------ step: mutation

export interface Defence {
  kind: L.DefenceKind;
  name: string;
  index: number;
}

/** The defence list of harness/v4/mutation.ts, in its order; the index fixes the port. */
export function allDefences(): Defence[] {
  const xs: Array<Omit<Defence, "index">> = [
    ...allGroups().map((name) => ({ kind: "circuit" as const, name })),
    ...VERIFIER_CHECKS.map((name) => ({ kind: "verifier" as const, name })),
    ...WALLET_CHECKS.map((name) => ({ kind: "wallet" as const, name })),
    ...REGISTRY_CHECKS.map((name) => ({ kind: "registry" as const, name })),
    { kind: "governance" as const, name: "issuerPopBeforeAccreditation" },
  ];
  return xs.map((x, index) => ({ ...x, index }));
}

/** The defences a run selects (--only kind or kind:name). */
export function selectDefences(only: ReadonlySet<string> | null): Defence[] {
  const all = allDefences();
  if (!only) return all;
  const out = all.filter((x) => only.has(`${x.kind}:${x.name}`) || only.has(x.kind));
  if (out.length === 0) throw new Error(`--only ${[...only].join(",")} matches no defence`);
  return out;
}

/** harness/v4/mutation.ts mutantKey(), unchanged: throwaway key per mutant circuit, cached by r1cs SHA-256. */
async function mutantKey(dir: string, r1cs: string): Promise<{ zkey: string; vkeyFile: string; cached: boolean }> {
  const zkey = path.join(dir, "mutant_throwaway.zkey");
  const vkeyFile = path.join(dir, "mutant_throwaway_vkey.json");
  const stamp = path.join(dir, "mutant_throwaway.r1cs.sha256");
  const sha = sha256FileHex(r1cs);
  if (fs.existsSync(zkey) && fs.existsSync(vkeyFile) && fs.existsSync(stamp) && fs.readFileSync(stamp, "utf8") === sha) return { zkey, vkeyFile, cached: true };
  const snarkjs = await import("snarkjs");
  const z0 = path.join(dir, "m0.zkey");
  await snarkjs.zKey.newZKey(r1cs, PTAU_FILE, z0, QUIET);
  await snarkjs.zKey.contribute(z0, zkey, "mutant throwaway", randomBytes(32).toString("hex"), QUIET);
  fs.rmSync(z0, { force: true });
  fs.writeFileSync(vkeyFile, JSON.stringify(await snarkjs.zKey.exportVerificationKey(zkey), null, 1));
  fs.writeFileSync(stamp, sha);
  return { zkey, vkeyFile, cached: false };
}

/** harness/v4/mutation.ts mutantContracts(): the same text rule (followup_lib.mutantContractsSource) and file name. */
function mutantContracts(check: string): string {
  const { text } = L.mutantContractsSource(fs.readFileSync(CONTRACTS_V4_FILE, "utf8"), check);
  const r = L.mutantContractsRel(check);
  if (!r.startsWith(`${L.MUTANTS_DIR_REL}/`)) throw new Error(`${r}: mutant contracts are written only under ${L.MUTANTS_DIR_REL}/`);
  fs.mkdirSync(path.dirname(abs(r)), { recursive: true });
  fs.writeFileSync(abs(r), text);
  return r;
}

interface MutationResult {
  status: L.StepStatus;
  table: string | null;
  rows: number;
  errors: string[];
  /** Rows with harness errors (information: campaign 5 has one, governance:issuerPopBeforeAccreditation). */
  harnessErrorRows: string[];
  vsDev: L.MutationComparison | null;
  seconds: number;
}

async function stepMutation(o: Options, d: RunDirs, k: SuiteKey, baselineRel: string, defences: readonly Defence[]): Promise<MutationResult> {
  // The post-fix rerun is strict: the exit code of each mutant run is compared with campaign 5 too.
  const strict = o.kind === "devrerun";
  const outRoot = `${d.out}/mutation`;
  const tableRel = `${outRoot}/${o.only ? "mutation_partial.json" : "mutation.json"}`;
  if (fs.existsSync(abs(tableRel))) throw new Refused(`${tableRel} exists; a mutation table is never overwritten`);
  if (!fs.existsSync(abs(baselineRel))) throw new Refused(`baseline ${baselineRel} missing (run the suite step first or pass --baseline)`);
  const baseFile = readJson<L.SuiteFile & { artifacts?: { zkey?: { sha256?: string } } }>(baselineRel);
  if (baseFile.keyLabel !== k.label) throw new Refused(`baseline ${baselineRel} was made with key '${baseFile.keyLabel}', not '${k.label}'`);
  if (baseFile.artifacts?.zkey?.sha256 !== k.zkey.sha256) throw new Refused(`baseline ${baselineRel} was made with another '${k.label}' zkey (${baseFile.artifacts?.zkey?.sha256 ?? "none"}, this run ${k.zkey.sha256})`);
  const base = L.mutationVerdicts(baseFile);
  if (defences.length === 0) throw new Error("no defence selected");
  for (const x of defences) L.defencePort(x.index);
  await probeKey(k, `${outRoot}/${probeFileName(k)}`);
  log(`[mutation] ${defences.length} defence(s), ${o.jobs} at a time, ports ${L.defencePort(defences[0]?.index ?? 0)}+; baseline ${baselineRel}`);
  const queue = [...defences];
  const rows: L.MutationTableRow[] = [];
  const errors: string[] = [];
  const t0 = Date.now();
  const worker = async () => {
    for (;;) {
      const x = queue.shift();
      if (!x) return;
      const port = L.defencePort(x.index);
      const tag = `${x.kind}__${x.name}`;
      const out = `${outRoot}/${tag}`;
      const t1 = Date.now();
      let row: L.MutationTableRow;
      try {
        await assertPortFree(port);
        mkdirRel(out);
        const built: L.MutantBuilt = {};
        const traced: Record<string, unknown> = {};
        if (x.kind === "circuit") {
          const m = buildMutant(x.name);
          const p = L.mutantPaths(x.name);
          // The throwaway key is written next to the mutant: check the folder before it is made.
          if (rel(m.dir) !== p.dir) throw new Error("harness/v4/mutate.ts mutant folder changed; update followup_lib.mutantPaths");
          const mk = await mutantKey(m.dir, m.r1cs);
          if (rel(m.r1cs) !== p.r1cs || rel(m.sym) !== p.sym || rel(m.wasm) !== p.wasm || rel(mk.zkey) !== p.zkey || rel(mk.vkeyFile) !== p.vkeyFile) throw new Error("harness/v4/mutate.ts or the mutant key names changed; update followup_lib.mutantPaths");
          built.circuit = { r1cs: p.r1cs, sym: p.sym, wasm: p.wasm, src: p.src, attackerDir: p.attackerDir, zkey: p.zkey, vkeyFile: p.vkeyFile };
          traced["throwawayKey"] = mk.cached ? "cached (same r1cs SHA-256 as the stamp)" : "made";
          traced["artifacts"] = { r1cs: fileRec(p.r1cs), zkey: fileRec(p.zkey), vkey: fileRec(p.vkeyFile) };
        } else if (x.kind === "registry") {
          const c = mutantContracts(x.name);
          built.contractsFile = abs(c);
          traced["contracts"] = fileRec(c);
        }
        const { cfg, env } = L.mutantConfig(x, port, out, built);
        // The post-fix rerun labels the mutant output too (its `config` field); nothing reads that name.
        if (strict) cfg["name"] = L.fixcheckConfigName(String(cfg["name"]));
        const cfgRel = `${out}/config.json`;
        writeJsonRel(cfgRel, cfg);
        const r = await runChild(process.execPath, nodeTsx("harness/v4/security_suite.ts", ["--config", cfgRel], usesLoader(k)), childEnv(k, env), 40 * 60_000);
        writeTextNew(`${d.logs}/mutation/${tag}.log`, `${r.stdout}${r.stderr ? `\n[stderr]\n${r.stderr}` : ""}\n[exit ${r.code}${r.timedOut ? ", timed out" : ""}, ${r.ms} ms]\n`);
        if (await portLeftOpen(port)) {
          traced["portAfterExit"] = "still answers";
          errors.push(`${x.kind}:${x.name}: port ${port} still answers after the suite exited (a chain node may be left running)`);
          log(`[mutation] ERROR: port ${port} still answers after ${x.kind}:${x.name}`);
        }
        const file = `${out}/security_suite.json`;
        if (!fs.existsSync(abs(file))) throw new Error(`suite produced no output (exit ${r.code})`);
        const v = L.mutationVerdicts(readJson<L.SuiteFile>(file));
        row = { kind: x.kind, name: x.name, exit: r.code, seconds: Math.round((Date.now() - t1) / 1000), port, ...L.mutationRow(base, v), ...traced };
      } catch (e) {
        const msg = sanitize((e as Error).message).slice(0, 500);
        row = { kind: x.kind, name: x.name, error: msg, seconds: Math.round((Date.now() - t1) / 1000), port };
        errors.push(`${x.kind}:${x.name}: ${msg}`);
      }
      rows.push(row);
      log(`[mutation] ${x.kind}:${x.name} -> ${JSON.stringify({ accepted: row.routesNowAccepted?.length ?? "ERR", controlsBroken: row.controlsBroken?.length ?? "-", s: row["seconds"] })}`);
      writeJsonRel(`${outRoot}/progress.json`, rows);
    }
  };
  await Promise.all(Array.from({ length: o.jobs }, () => worker()));
  const seconds = Math.round((Date.now() - t0) / 1000);
  rows.sort((a, b) => `${a.kind}:${a.name}`.localeCompare(`${b.kind}:${b.name}`));
  const harnessErrorRows = L.harnessErrorRows(rows);
  const table = {
    schema: "pqid/v4-mutation-table/v1",
    label: L.mutationTableLabel(o.kind, k.label, o.only),
    ...FIXCHECK_TEXT(k),
    keyLabel: k.label,
    key: { zkey: k.zkey, vkey: k.vkey },
    keySwitch: L.keySwitchFor(k.label),
    rules: `harness/v4/mutation.ts (defence list, configs, verdict rules), re-implemented in harness/v4/ceremony/followup.ts and followup_lib.ts (mutantConfig, mutationRow) for new output paths, ports 8801+ and ${usesLoader(k) ? "the rekey loader" : "no loader (the pinned dev key is the package default)"}`,
    baseline: { file: baselineRel, sha256: sha256FileHex(abs(baselineRel)) },
    partial: o.only ? [...o.only].sort() : null,
    rows,
    noEffect: rows.filter((r) => Array.isArray(r.routesNowAccepted) && r.routesNowAccepted.length === 0).map((r) => `${r.kind}:${r.name}`),
    harnessErrorRows,
    seconds,
    env: envInfo(),
  };
  writeJsonRel(tableRel, table);
  const vsDev = L.compareMutationTables(readJson<L.MutationTable>(L.DEV_MUTATION_REL), table, o.only ?? undefined, { exit: strict });
  writeJsonRel(`${outRoot}/vs_dev.json`, {
    schema: "pqid/v4-mutation-comparison/v1",
    ...FIXCHECK_TEXT(k),
    base: { file: L.DEV_MUTATION_REL, sha256: shaOrNull(L.DEV_MUTATION_REL), keyLabel: "dev", run: "campaign 5" },
    next: { file: tableRel, keyLabel: k.label },
    keySwitch: L.keySwitchFor(k.label),
    rule: strict
      ? `per defence: routes let through, controls broken, routes stopped elsewhere, harness errors, run errors and the exit code; ${L.FIXCHECK_RUN_LABEL}: any difference is review`
      : "per defence: routes let through, controls broken, routes stopped elsewhere, harness errors and run errors",
    ...vsDev,
  });
  const status = L.mutationStatus(errors, vsDev);
  log(`[mutation] ${rows.length} rows, ${errors.length} errors, ${table.noEffect.length} no-effect, harness errors in ${harnessErrorRows.length} row(s) (${harnessErrorRows.join(", ") || "none"}); vs dev: ${vsDev.differing.length} differing fields, missing ${vsDev.missing.length}, extra ${vsDev.extra.length}, identical ${vsDev.identical}`);
  if (strict) {
    const diffs = [...vsDev.differing.map((x) => `${x.defence} ${x.field}: campaign 5 ${JSON.stringify(x.base)}, now ${JSON.stringify(x.new)}`), ...vsDev.missing.map((x) => `${x}: no row`), ...vsDev.extra.map((x) => `${x}: not in campaign 5`)];
    if (!isDeepStrictEqual(vsDev.noEffectBase, vsDev.noEffectNew)) diffs.push(`no-effect list: campaign 5 ${JSON.stringify(vsDev.noEffectBase)}, now ${JSON.stringify(vsDev.noEffectNew)}`);
    for (const x of diffs.slice(0, 100)) log(`[mutation]   REVIEW difference: ${sanitize(x).slice(0, 400)}`);
  }
  log(`[mutation] ${status.toUpperCase()} (${seconds} s)`);
  return { status, table: tableRel, rows: rows.length, errors, harnessErrorRows, vsDev, seconds };
}

// ------------------------------------------------------------------ preflight

interface Prepared {
  d: RunDirs;
  inp: CeremonyInputs | null;
  defences: Defence[];
  /** Post-fix rerun with --steps mutation: the earlier run that made the baseline. */
  baselineRun?: BaselineRun | null;
}

/** The earlier post-fix rerun whose suite output a mutation-only rerun uses (checked before the start). */
interface BaselineRun {
  file: string;
  sha256: string | null;
  record: string;
  gitHead: string | null;
  suiteStatus: string | null;
  codeChangedSince: string[] | null;
}

/** Planned post-fix rerun: what the preflight found. Writes nothing. */
interface DevPlan {
  d: RunDirs;
  key: (SuiteKey & { pinned: L.PinnedFile[] }) | null;
  defences: Defence[];
  baselineRun: BaselineRun | null;
  /** Every reason the real rerun would refuse (empty: it would start). */
  problems: string[];
}

function readJsonOrNull<T>(r: string): T | null {
  try {
    return fs.existsSync(abs(r)) ? readJson<T>(r) : null;
  } catch {
    return null;
  }
}

/**
 * Preflight of the post-fix rerun with the dev key. A marker refuses at once (throws); every
 * other finding is collected, so the dry run can list them all: snarkjs, uncommitted code (no
 * override), the dev key against its pins, the comparison basis (run 10 made with that key,
 * campaign 5 on run 10), a mutation-only baseline (its key, and the earlier run's record: suite
 * step passed, same code as HEAD, file unchanged), the output names and the ports.
 */
async function planDevRerun(o: Options, dirty: string[] | null): Promise<DevPlan> {
  assertMarkersFree(markerRoots(), "BUSY");
  const problems: string[] = [];
  if (snarkjsVersion() !== L.EXPECTED_SNARKJS) problems.push(`snarkjs ${snarkjsVersion()} installed; ${L.EXPECTED_SNARKJS} pinned`);
  problems.push(...L.devRerunCodeProblems(dirty));
  let key: DevPlan["key"] = null;
  try {
    key = devPinnedKey();
  } catch (e) {
    problems.push((e as Error).message);
  }
  if (key) problems.push(...L.comparisonBasisProblems(readJsonOrNull(L.DEV_SUITE_REL), shaOrNull(L.DEV_SUITE_REL), readJsonOrNull(L.DEV_MUTATION_REL), key.pinned));
  let baselineRun: BaselineRun | null = null;
  if (o.baselineRel !== null) {
    const b = readJsonOrNull<{ keyLabel?: string; artifacts?: { zkey?: { sha256?: string } } }>(o.baselineRel);
    if (!b) problems.push(`baseline ${o.baselineRel} missing`);
    else if (b.keyLabel !== L.DEV_LABEL || (key && b.artifacts?.zkey?.sha256 !== key.zkey.sha256)) problems.push(`baseline ${o.baselineRel} was not made with the pinned dev key`);
    const f = L.fixcheckBaselineFiles(o.baselineRel);
    const rec = readJsonOrNull<L.FixcheckRecordLike>(f.record);
    const recordedSha = readJsonOrNull<{ next?: { file?: string; sha256?: string } }>(f.vsDev)?.next;
    const head = rec?.code?.gitHead ?? null;
    const changed = head ? codeChangedSince(head) : null;
    const fileSha = shaOrNull(o.baselineRel);
    baselineRun = { file: o.baselineRel, sha256: fileSha, record: f.record, gitHead: head, suiteStatus: rec?.steps?.["suite"] ?? null, codeChangedSince: changed };
    problems.push(...L.fixcheckBaselineProblems(o.baselineRel, rec, recordedSha?.file === o.baselineRel ? (recordedSha.sha256 ?? null) : null, fileSha, changed));
  }
  const d = runDirs(o);
  const defences = o.steps.includes("mutation") ? selectDefences(o.only) : [];
  const busy = await openPorts(L.portsForSteps(o.steps, defences.map((x) => x.index)));
  if (busy.length > 0) problems.push(`port(s) ${busy.join(", ")} on 127.0.0.1 already answer; the rerun never starts its Anvil next to another node`);
  return { d, key, defences, baselineRun, problems };
}

/**
 * `--dev-rerun --dry-run`: the preflight of the post-fix rerun and the key probe without the
 * loader, then stop before the suite. Writes nothing and holds no marker (seconds); refuses
 * while a marker exists. Exit 0 when the real rerun would start now, 3 when it would refuse.
 */
async function devRerunPreview(o: Options, dirty: string[] | null): Promise<number> {
  let plan: DevPlan;
  try {
    plan = await planDevRerun(o, dirty);
  } catch (e) {
    console.error(`[fixcheck] REFUSED (nothing written): ${sanitize((e as Error).message)}`);
    return L.EXIT.refused;
  }
  let probe: RekeyProbe | null = null;
  if (plan.key) {
    try {
      probe = await probeKey(plan.key, null);
    } catch (e) {
      plan.problems.push(sanitize((e as Error).message));
    }
  }
  const ready = plan.problems.length === 0;
  const steps = o.steps.join(",");
  const preview = {
    schema: "pqid/v4-fixcheck-preview/v1",
    label: `DRY RUN of the ${L.FIXCHECK_RUN_LABEL}, ${L.DEV_KEY_TEXT}: preflight and key probe only, stopped before the suite; nothing written; not a result`,
    run: L.FIXCHECK_RUN_LABEL,
    key: L.DEV_KEY_TEXT,
    keyLabel: L.DEV_LABEL,
    keySwitch: L.DEV_KEY_SWITCH,
    pinned: plan.key?.pinned ?? null,
    probe,
    steps: o.steps,
    partial: L.fixcheckPartial(o),
    baselineRun: plan.baselineRun,
    defences: plan.defences.length,
    ports: L.portsForSteps(o.steps, plan.defences.map((x) => x.index)),
    outputs: { results: plan.d.out, logs: plan.d.logs, note: "names as of now; the real rerun picks the first free name again when it starts" },
    compareWith: { suite: `${L.DEV_SUITE_REL} (dev run 10)`, attackMatrix: L.DEV_ATTACK_MATRIX_REL, mutation: `${L.DEV_MUTATION_REL} (campaign 5)` },
    code: { gitHead: gitHead(), uncommitted: dirty },
    realRunWouldStart: ready,
    problems: plan.problems,
    command: `bash scripts/ceremony/followup.sh --dev-rerun${steps === "suite,mutation" ? "" : ` --steps ${steps}`}${o.only ? ` --only ${[...o.only].join(",")}` : ""}${o.baselineRel ? ` --baseline ${o.baselineRel}` : ""}`,
  };
  for (const p of plan.problems) console.log(`[fixcheck] the real rerun would refuse: ${sanitize(p)}`);
  if (probe) console.log(`[fixcheck] key probe without the loader: ${probe.zkey} (label ${probe.keyLabel}, rekey ${probe.rekeyLabel ?? "none"})`);
  console.log(`[fixcheck] dry run of the ${L.FIXCHECK_RUN_LABEL} (${L.DEV_KEY_TEXT}): ${ready ? "the real rerun would start now" : "the real rerun would refuse now"}; would write ${plan.d.out}/ and ${plan.d.logs}/; nothing written`);
  console.log(sanitize(JSON.stringify(preview)));
  return ready ? L.EXIT.pass : L.EXIT.refused;
}

/** Every refusal that can be known before the start; writes nothing (no folder, no log, no marker). */
async function preflight(o: Options, dirty: string[] | null): Promise<Prepared> {
  if (o.kind === "devrerun") {
    const p = await planDevRerun(o, dirty);
    if (p.problems.length > 0) throw new Refused(p.problems.join("; "));
    return { d: p.d, inp: null, defences: p.defences, baselineRun: p.baselineRun };
  }
  assertMarkersFree(markerRoots(), "BUSY");
  if (snarkjsVersion() !== L.EXPECTED_SNARKJS) throw new Refused(`snarkjs ${snarkjsVersion()} installed; ${L.EXPECTED_SNARKJS} pinned`);
  if (o.kind === "real" && dirty !== null && dirty.length > 0 && !o.allowUncommitted) {
    throw new Refused(`the code the suite and mutation campaign run has uncommitted changes (${dirty.join(", ")}); commit first (or pass --allow-uncommitted, which the record states)`);
  }
  if (o.kind === "real" && dirty === null && !o.allowUncommitted) throw new Refused("git status could not be read, so the code state is unknown; pass --allow-uncommitted to run anyway (recorded)");
  const d = runDirs(o);
  const inp = o.steps.some((x) => x === "verify" || x === "keys" || x === "install") ? loadInputs(o) : null;
  if (inp && o.steps.includes("install")) {
    const p = installConflicts(o, inp, d);
    if (p.length > 0) throw new Refused(`install would stop: ${p.join("; ")}`);
  }
  if (o.kind === "real" && (o.steps.includes("suite") || o.steps.includes("mutation")) && !o.steps.includes("install")) installedKey(o, d);
  if (o.baselineRel !== null && !fs.existsSync(abs(o.baselineRel))) throw new Refused(`baseline ${o.baselineRel} missing`);
  const defences = o.steps.includes("mutation") ? selectDefences(o.only) : [];
  const busy = await openPorts(L.portsForSteps(o.steps, defences.map((x) => x.index)));
  if (busy.length > 0) throw new Refused(`port(s) ${busy.join(", ")} on 127.0.0.1 already answer; the follow-up never starts its Anvil next to another node`);
  return { d, inp, defences };
}

// ------------------------------------------------------------------ main

/**
 * The marker a run holds (D-034): results/v4/BUSY for the whole of a real, check-only or post-fix
 * run; the ceremony dry run only while it runs a suite or mutation step (null otherwise).
 */
export function markerSpec(o: Pick<Options, "kind" | "steps">, d: Pick<RunDirs, "runId">): { kind: "BUSY"; campaign: string; note: string } | null {
  const heavy = o.steps.includes("suite") || o.steps.includes("mutation");
  if (o.kind === "dry" && !heavy) return null;
  const note =
    o.kind === "real"
      ? "ceremony follow-up: verify, key checks, install, security suite and mutation campaign (untimed, CPU-heavy)"
      : o.kind === "check"
        ? "ceremony follow-up, check only (not a result): zkey recomputation from r1cs and ptau, key checks (untimed, CPU-heavy)"
        : o.kind === "devrerun"
          ? `${L.FIXCHECK_RUN_LABEL}, ${L.DEV_KEY_TEXT}: ${o.steps.map((s) => (s === "suite" ? "security suite" : s === "mutation" ? "mutation campaign" : s)).join(" and ")} after the packages/v4 fix (untimed, CPU-heavy)`
          : "ceremony follow-up dry run (not a result): security suite or mutation smoke on a throwaway key (untimed, CPU-heavy)";
  // d.runId of the post-fix rerun is fixcheck_<date>[_rN]; the ceremony runs are named ceremony_<run>.
  return { kind: "BUSY", campaign: o.kind === "devrerun" ? d.runId : `ceremony_${d.runId}`, note };
}

async function main(argv: readonly string[]): Promise<number> {
  let o: Options;
  try {
    o = parseOptions(argv);
  } catch (e) {
    console.error(`[followup] ${(e as Error).message}`);
    return L.EXIT.usage;
  }
  const dirty = uncommittedCode();
  if (o.kind === "devrerun" && o.preview) return devRerunPreview(o, dirty);
  const dev = o.kind === "devrerun";
  let prep: Prepared;
  try {
    prep = await preflight(o, dirty);
  } catch (e) {
    console.error(`[followup] REFUSED before start (nothing written): ${sanitize((e as Error).message)}`);
    return L.EXIT.refused;
  }
  const { d, defences } = prep;
  const started = new Date().toISOString();
  let marker: MarkerHandle | null = null;
  let wrote = false;
  const steps: Record<string, L.StepStatus> = {};
  const heavy = o.steps.includes("suite") || o.steps.includes("mutation");
  // Every run output of the post-fix rerun goes through this rule (it throws before a write elsewhere).
  OUTPUT_GUARD = outputGuardFor(o.kind);
  const recordFile = `${d.out}/${dev ? "fixcheck.json" : "followup.json"}`;
  const record: Record<string, unknown> = dev
    ? {
        schema: "pqid/v4-fixcheck/v1",
        label: L.recordLabel(o.kind, o.label, [], o),
        mode: `${L.FIXCHECK_RUN_LABEL}, ${L.DEV_KEY_TEXT}`,
        run: L.FIXCHECK_RUN_LABEL,
        key: L.DEV_KEY_TEXT,
        purpose: L.FIXCHECK_PURPOSE,
        expected: L.FIXCHECK_EXPECTED,
        partial: L.fixcheckPartial(o),
        runId: d.runId,
        keyLabel: o.label,
        startedUtc: started,
        options: { devRerun: true, steps: o.steps, only: o.only ? [...o.only] : null, jobs: o.jobs, date: o.date, baseline: o.baselineRel },
        baselineRun: prep.baselineRun ?? null,
        outputs: { results: d.out, logs: d.logs, keyDir: d.keyDir, pins: d.pinsRel },
        compareWith: { suite: L.DEV_SUITE_REL, suiteRun: "dev run 10", attackMatrix: L.DEV_ATTACK_MATRIX_REL, mutation: L.DEV_MUTATION_REL, mutationRun: "campaign 5" },
        keySwitch: L.DEV_KEY_SWITCH,
      }
    : {
        schema: "pqid/v4-ceremony-followup/v1",
        label: L.recordLabel(o.kind, o.label, []),
        mode: o.kind === "dry" ? "dry-run (rehearsal)" : o.kind === "check" ? "check-only (ceremony outputs)" : "ceremony",
        runId: d.runId,
        keyLabel: o.label,
        startedUtc: started,
        options: { finalDir: o.finalDirRel, external: o.external, externalSource: "declared by the coordinator with --external [A]; the transcript cannot show who is outside the project", steps: o.steps, only: o.only ? [...o.only] : null, jobs: o.jobs, allowUncommitted: o.allowUncommitted },
        outputs: { results: d.out, logs: d.logs, keyDir: d.keyDir, pins: d.pinsRel, keySpec: d.specRel },
        ...(heavy ? { keySwitch: L.KEY_SWITCH } : {}),
      };
  const devBefore = devResultHashes();
  try {
    // Markers (D-034): the real, check-only and post-fix runs hold results/v4/BUSY for the whole
    // run; the dry run holds it while it runs a suite or mutation step (Anvil plus the whole suite).
    const ms = markerSpec(o, d);
    if (ms) marker = acquireMarker({ ...ms, runner: "harness/v4/ceremony/followup.ts", owner: o.owner ?? undefined });
    mkdirRel(d.out);
    mkdirRel(d.logs);
    wrote = true;
    const mainLog = `${d.logs}/${dev ? "fixcheck.log" : "followup.log"}`;
    guardOut(mainLog);
    MAIN_LOG = mainLog;
    log(`[followup] ${record["mode"]} run ${d.runId}; steps ${o.steps.join(",")}; results ${d.out}; logs ${d.logs}`);
    record["marker"] = marker ? { kind: marker.kind, copies: marker.copies, campaign: marker.record.campaign } : { kind: null, note: "dry run without a suite or mutation step: no marker written; refused to start while any marker existed" };

    // code state
    // The post-fix rerun also names every packages/v4 and packages/common source file (the fixed version).
    record["code"] = { gitHead: gitHead(), uncommitted: dirty, files: codeRecord(dev ? [...L.CODE_FILES, ...packageSourceFiles()] : L.CODE_FILES), snarkjs: snarkjsVersion(), node: process.version };
    if (dirty === null) log("[followup] git status could not be read; code state unknown");
    else if (dirty.length > 0) log(`[followup] uncommitted code${o.kind === "real" ? " (--allow-uncommitted)" : ""}: ${dirty.join(", ")}`);
    record["env"] = envInfo();

    const inp = prep.inp;
    if (inp) {
      record["inputs"] = { transcript: fileRec(inp.transcriptRel), zkey: fileRec(inp.zkeyRel), vkey: fileRec(inp.vkeyRel), sol: fileRec(inp.solRel), r1cs: { ...fileRec(inp.r1csRel), frozen: inp.frozenR1csSha !== null }, ptau: { ...fileRec(inp.ptauRel), pinned: inp.pinnedPtauSha !== null }, wasm: { ...fileRec(inp.wasmRel), pinned: inp.frozenWasmSha !== null }, notes: inp.notes };
      record["ceremony"] = { contributions: L.contributionsForRecord(inp.transcript, o.external), contributors: L.contributorCounts(inp.transcript, o.external), beacon: L.beaconForRecord(inp.transcript), circuitHash: inp.transcript.circuit?.circuitHash ?? null, transcriptDates: inp.transcript.dates ?? null };
      for (const n of inp.notes) log(`[followup] ${n}`);
    }

    if (o.steps.includes("verify") && inp) {
      const v = await stepVerify(o, d, inp);
      steps["verify"] = v.status;
      record["verify"] = { status: v.status, file: `${d.out}/verify/verify.json`, failed: L.failed([...v.transcriptChecks, ...v.zkeyVerify.checks]).map((c) => c.id), warnings: [...v.transcriptChecks, ...v.zkeyVerify.checks].filter((c) => c.status === "warn").map((c) => c.id), auditPassed: v.audit.passed, logs: [v.audit.log, v.zkeyVerify.log] };
    }
    if (o.steps.includes("keys") && inp) {
      const kc = await stepKeys(o, d, inp);
      steps["keys"] = kc.status;
      record["keys"] = { status: kc.status, file: `${d.out}/keys/key_checks.json`, result: kc.result, config: kc.config };
    }
    if (o.steps.includes("install") && inp) {
      if (steps["verify"] === "fail" || steps["keys"] === "fail") {
        steps["install"] = "skipped";
        record["install"] = { status: "skipped", reason: "verify or keys failed: an unverified key is never installed" };
        log("[install] SKIPPED: verify or keys failed");
      } else {
        const ins = await stepInstall(o, d, inp);
        steps["install"] = ins.status;
        record["install"] = ins;
      }
    }

    const wantSuite = o.steps.includes("suite");
    const wantMutation = o.steps.includes("mutation");
    if (wantSuite || wantMutation) {
      if (Object.values(steps).includes("fail")) {
        if (wantSuite) steps["suite"] = "skipped";
        if (wantMutation) steps["mutation"] = "skipped";
        if (wantSuite) record["suite"] = { status: "skipped", reason: "an earlier step failed" };
        if (wantMutation) record["mutation"] = { status: "skipped", reason: "an earlier step failed" };
        log("[suite/mutation] SKIPPED: an earlier step failed");
      } else {
        const k = dev ? devPinnedKey() : o.kind !== "dry" ? installedKey(o, d) : !wantSuite && o.baselineRel ? dryrunKeyOfBaseline(o.baselineRel) : await dryrunKey(d);
        record["suiteKey"] = k;
        let baselineRel = o.baselineRel;
        if (wantSuite) {
          const s = await stepSuite(o, d, k);
          steps["suite"] = s.status;
          record["suite"] = s;
          baselineRel = s.file;
          if (s.status === "fail" && wantMutation) {
            steps["mutation"] = "skipped";
            record["mutation"] = { status: "skipped", reason: "the suite (the mutation baseline) failed" };
          }
        }
        if (wantMutation && steps["mutation"] !== "skipped") {
          if (!baselineRel) throw new Refused("the mutation step needs a baseline: run it with the suite step or pass --baseline <this key's security_suite.json>");
          const m = await stepMutation(o, d, k, baselineRel, defences);
          steps["mutation"] = m.status;
          record["mutation"] = m;
        }
      }
    }
  } catch (e) {
    const refused = e instanceof Refused || e instanceof MarkerHeldError;
    const msg = sanitize((e as Error).message);
    if (wrote) log(`[followup] ${refused ? "STOPPED (refused after the start)" : "ERROR"}: ${msg}`);
    else console.error(`[followup] ${refused ? "REFUSED" : "ERROR"}: ${msg}`);
    record["error"] = { refused, afterStart: wrote, message: msg };
    steps["run"] = "fail";
  } finally {
    const devAfter = devResultHashes();
    const changed = Object.keys({ ...devBefore, ...devAfter }).filter((k) => devBefore[k] !== devAfter[k]);
    record["devResultsUnchanged"] = { checked: Object.keys(devBefore).length, changed };
    if (changed.length > 0) {
      steps["devResults"] = "fail";
      log(`[followup] FAIL: dev-key files changed during the run: ${changed.join(", ")}`);
    }
    record["label"] = L.recordLabel(
      o.kind,
      o.label,
      o.steps.filter((s) => steps[s] === "pass" || steps[s] === "review"),
      dev ? o : undefined
    );
    record["steps"] = steps;
    record["status"] = L.overallStatus(steps);
    record["finishedUtc"] = new Date().toISOString();
    if (!dev) record["keyUsers"] = L.keyUsers(o.label);
    record["next"] = dev
      ? L.fixcheckNext(d.out, d.logs, String(record["status"]), o)
      : o.kind === "dry"
        ? ["dry run only: delete the smoke folder when done (results/v4/ceremony/_smoke/ is gitignored)"]
        : o.kind === "check"
          ? [`check only: if it passed, start the real follow-up with the same indexes: bash scripts/ceremony/followup.sh --external ${o.external.join(",")}`, "delete the smoke folder when done (it holds no result)"]
          : [
              `commit the key files (${d.keyDir}/*_${o.label}.*), ${d.pinsRel}, ${d.specRel}, ${d.out}/ and ${d.logs}/`,
              "ledger: new keys for the ceremony-key suite and mutation rows; the dev-key keys stay",
              "WSL clone: bring it to that commit before the e2e WSL campaigns and the WSL v4 Phase D repeat",
              ...L.keyUsers(o.label)
                .filter((u) => u.how !== "-")
                .map((u) => `${u.series}: ${u.how}`),
            ];
    try {
      if (fs.existsSync(abs(d.out))) writeJsonRel(recordFile, record);
    } catch (e) {
      console.error(`[followup] could not write the record: ${(e as Error).message}`);
    }
    if (wrote) log(`[followup] steps ${JSON.stringify(steps)} -> ${String(record["status"]).toUpperCase()}; record ${recordFile}`);
    marker?.release();
  }
  const err = record["error"] as { refused?: boolean } | undefined;
  if (err?.refused) return wrote ? L.EXIT.stopped : L.EXIT.refused;
  return L.exitCode(record["status"] as L.StepStatus, false);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // Exit explicitly: snarkjs keeps worker threads alive.
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e: unknown) => {
      console.error(e);
      process.exit(1);
    }
  );
}
