import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { REPO_ROOT, envInfo, gitHead, sanitize, rel, utcNow, writeJson, flag, opt, optNum, tsxImportUrl, sha256FileHex } from "../bench/lib.ts";
import { acquireMarker, assertMarkersFree, markerRoots, windowsRepoFromArgs } from "../lib/markers.ts";
import { SEEDS } from "../lib/seeds.ts";
import { PORTS } from "../lib/ports.ts";
import { caseRng, caseSeed, targetSeed } from "./rng.ts";
import { encodeTyped, typedJsonCapped } from "./typed_json.ts";
import { PURE_TARGETS } from "./fuzz_targets.ts";
import { summariseCoverage, coverageMarkdown } from "./coverage.ts";
import { robustnessRoot, protocolRecord, assertCommitted, budgetDeviation } from "./common.ts";
import { errClass, errMsg, type FuzzCase, type FuzzTarget, type CaseOutcome, type Violation } from "./fuzz_types.ts";

/**
 * Fuzz runner of the robustness row (DECISIONS D-034; pre-registration in docs/v4/ROBUSTNESS.md).
 *
 *   node --import tsx harness/v4/robustness/fuzz.ts --campaign <name> [--targets all|pure|chain|T-a,T-b]
 *        [--coverage] [--windows-repo <dir>] [--deviation "<text>" --scale <f> --case-cap-sec <s> --target-cap-min <m>]
 *   node --import tsx harness/v4/robustness/fuzz.ts --smoke [--campaign <name>] [...]
 *   node --import tsx harness/v4/robustness/fuzz.ts --replay <failure.json>
 *
 * Untimed but CPU-heavy: a full campaign holds results/v4/BUSY (D-034) and refuses to start while
 * results/v4/bench/RUNNING or results/v4/BUSY exists, or while the protocol, the harness or the
 * code under test is not committed. A full run uses the pre-registered budgets and watchdog
 * settings (scale 1, 120 s, 90 min); another value needs --deviation (recorded in plan.json and
 * appended to the protocol's Deviations). A smoke run (--smoke) holds no marker, refuses while
 * either exists, uses the small smoke budgets and writes only under results/v4/robustness/_smoke/
 * (gitignored); smoke output is never quoted. --replay also refuses while a marker exists.
 *
 * Each target (the chain targets together) runs in its own child process with a watchdog: no
 * progress line for --case-cap-sec seconds is a hang, and the child is stopped at --target-cap-min
 * minutes ("interrupted at N"). Before every case of a chain target, every one of the first 200
 * cases of a pure target, and every case of a pure target whose median call time exceeds 100 ms,
 * the child announces the case index, so a hang is saved as failures/<id>/hang_<index>.json with
 * the case regenerated in the parent; for a fast pure target past case 200 the hang file names
 * the last completed case instead. When the watchdog stops the chain child, the parent also stops
 * the child's Anvil and checks that its port is free. Every case is generated from (master seed
 * 20261022, target id, case index) alone, so a recorded failure regenerates exactly.
 * Results: results/v4/robustness/fuzz/<campaign>/ plan.json, env.json, targets/<id>.json,
 * failures/<id>/<signature>.json, failures/<id>/hang_*.json, slow/<id>/<index>.json,
 * observations/<id>/, coverage/summary.(json|md) (with --coverage; NODE_V8_COVERAGE of the fuzz
 * child processes, raw files in the OS temp directory, deleted after summarising), summary.json,
 * summary.md.
 *
 * Exit code (since 2026-10-03, after the fz1 triage; docs/v4/ROBUSTNESS.md, Deviations): the
 * parent exits 1 when a child exits non-zero, the watchdog stops a child, or a target is not
 * complete, and records why under `step` in summary.json. A target whose child code throws keeps a
 * record with its true casesRun (`crash`); a target with no final record is labelled "result lost"
 * with any count that is known. Property violations alone do not change the exit code (they are
 * findings, saved under failures/).
 */
const REGISTERED = Object.freeze({ scale: 1, caseCapSec: 120, targetCapMin: 90 });
/** A pure target whose median call time exceeds this announces every case (hang files with the exact index). */
const WATCH_MEDIAN_MS = 100;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const MASTER = SEEDS.robustness.fuzz;
const MAX_SIGNATURES = 20;
const MAX_SLOW = 20;
const MAX_OBS_EXAMPLES = 5;
const INPUT_CAP = 4 * 1024 * 1024;

const sha256 = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");

async function loadChainTargets(): Promise<readonly FuzzTarget[]> {
  const m = (await import("./fuzz_chain.ts")) as { CHAIN_TARGETS: readonly FuzzTarget[] };
  return m.CHAIN_TARGETS;
}

async function allTargets(): Promise<FuzzTarget[]> {
  return [...PURE_TARGETS, ...(await loadChainTargets())];
}

function sourceHashes(): Record<string, string> {
  const out: Record<string, string> = {};
  const add = (dir: string) => {
    for (const f of fs.readdirSync(dir).sort()) if (f.endsWith(".ts")) out[rel(path.join(dir, f))] = sha256FileHex(path.join(dir, f));
  };
  add(HERE);
  add(path.join(REPO_ROOT, "packages", "v4", "src"));
  return out;
}

// ------------------------------------------------------------------ child

/**
 * targets/<id>.json. v2 (2026-10-03) adds `crash`: a target whose child code threw keeps a
 * record with its true casesRun (v1, used by fz1, wrote nothing in that case).
 */
export interface TargetResult {
  schema: "pqid/v4-fuzz-target/v2";
  target: string;
  title: string;
  entryPoints: string[];
  property: string;
  documentedErrors: string[];
  masterSeed: number;
  targetSeed: number;
  budget: number;
  casesRun: number;
  complete: boolean;
  stoppedBy: string | null;
  /** Set when the target stopped on an exception of the child's own code (setup, bookkeeping, a result write); single-case generator and run errors are counted in harnessErrors instead. */
  crash: { errorClass: string; message: string; atCase: number | null; utc: string } | null;
  outcomes: Record<string, number>;
  casesWithViolations: number;
  harnessErrors: number;
  signatures: Array<{ signature: string; predicate: string; errorClass: string | null; occurrences: number; firstIndices: number[]; file: string | null; example: string }>;
  observations: Array<{ id: string; count: number; examples: Array<{ index: number; detail: string; file: string | null }> }>;
  slow: { thresholdMs: number; basis: string; cases: Array<{ index: number; ms: number; file: string }> };
  callTimeMs: { note: string; median: number | null; p99: number | null; max: number | null };
  startedUtc: string;
  finishedUtc: string;
}

function quantile(xs: readonly number[], q: number): number | null {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const pos = (s.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return (s[lo] as number) + ((s[hi] as number) - (s[lo] as number)) * (pos - lo);
}

/**
 * The same value as Math.max(...xs) (NaN and -0 included; -Infinity for no elements), by a loop.
 * A spread passes every element as a call argument and overflows V8's stack above about 125,000
 * elements: in fz1 that crashed the result write of the three 200,000-case targets
 * (docs/v4/ROBUSTNESS.md, Deviations, 2026-10-03).
 */
export function maxOf(xs: readonly number[]): number {
  let m = -Infinity;
  for (const x of xs) m = Math.max(m, x);
  return m;
}

/** Writes targets/<id>.json: the counters in `res`, the signatures and observations, and the call-time summary of `times` (one entry per case run). */
export function writeTargetResult(
  outDir: string,
  res: TargetResult,
  sigs: Iterable<TargetResult["signatures"][number]>,
  obs: Iterable<TargetResult["observations"][number]>,
  times: readonly number[]
): void {
  res.signatures = [...sigs];
  res.observations = [...obs];
  res.callTimeMs.median = quantile(times, 0.5);
  res.callTimeMs.p99 = quantile(times, 0.99);
  res.callTimeMs.max = times.length ? maxOf(times) : null;
  res.finishedUtc = utcNow();
  writeJson(path.join(outDir, "targets", `${res.target}.json`), res);
}

function caseRecord(t: FuzzTarget, index: number, c: FuzzCase): Record<string, unknown> {
  const inp = typedJsonCapped(c.input, INPUT_CAP, (s) => sha256(s));
  return {
    target: t.id,
    masterSeed: MASTER,
    targetSeed: targetSeed(MASTER, t.id),
    caseIndex: index,
    caseSeed: caseSeed(targetSeed(MASTER, t.id), index),
    family: c.family,
    recipe: c.recipe.map((s) => sanitize(s)),
    meta: encodeTyped(c.meta ?? {}),
    input: inp.typed,
    inputTypedJsonBytes: inp.bytes,
    inputTypedJsonSha256: inp.sha256,
    inputTruncated: inp.truncated,
  };
}

/**
 * The child processes of a campaign: one per pure target (in the order chosen), then one for the
 * chain targets, which share a world. The chain ids are listed in CHAIN_TARGETS order (T-verify,
 * T-wallet-req, T-wallet-iss) whatever the order of --targets, which is the order fz1's child ran
 * them in. A child runs its ids in the order given (targetsInOrder), so the order of a child's ids
 * is the order its targets run, which targetStatus relies on to name the target that was running
 * when a child failed.
 */
export function childGroups(all: readonly Pick<FuzzTarget, "id" | "kind">[], chosen: readonly Pick<FuzzTarget, "id" | "kind">[]): string[][] {
  const ids = new Set(chosen.map((t) => t.id));
  const groups = chosen.filter((t) => t.kind === "pure").map((t) => [t.id]);
  const chain = all.filter((t) => t.kind === "chain" && ids.has(t.id)).map((t) => t.id);
  if (chain.length) groups.push(chain);
  return groups;
}

/** The targets named by `ids`, in the order of `ids` (the order a child runs them). */
export function targetsInOrder<T extends Pick<FuzzTarget, "id">>(all: readonly T[], ids: readonly string[]): T[] {
  return ids.map((id) => {
    const t = all.find((x) => x.id === id);
    if (!t) throw new Error(`unknown target ${id}`);
    return t;
  });
}

async function runChild(ids: string[], outDir: string, budgets: Record<string, number>, smoke: boolean): Promise<void> {
  const targets = targetsInOrder(await allTargets(), ids);
  await runTargets(targets, outDir, budgets, smoke, (o: unknown) => process.stdout.write(JSON.stringify(o) + "\n"));
}

/**
 * Runs the targets of one child in order and writes targets/<id>.json for each. When the child's
 * own code throws (setup, bookkeeping, a result write), the target still gets a record (`crash`,
 * the true casesRun), a {crashed} line goes to the parent, and the error is rethrown so the child
 * exits non-zero. `hb` sends one JSON line to the parent (exported for the unit tests).
 */
export async function runTargets(targets: readonly FuzzTarget[], outDir: string, budgets: Record<string, number>, smoke: boolean, hb: (o: unknown) => void): Promise<void> {
  const ctx = { smoke, log: (s: string) => hb({ log: sanitize(s) }), emit: (o: Record<string, unknown>) => hb(o) };
  const setupDone = new Set<FuzzTarget>();
  try {
    for (const t of targets) {
      const budget = budgets[t.id] ?? (smoke ? t.smokeBudget : t.budget);
      const res: TargetResult = {
        schema: "pqid/v4-fuzz-target/v2",
        target: t.id,
        title: t.title,
        entryPoints: t.entryPoints,
        property: t.property,
        documentedErrors: t.documentedErrors,
        masterSeed: MASTER,
        targetSeed: targetSeed(MASTER, t.id),
        budget,
        casesRun: 0,
        complete: false,
        stoppedBy: null,
        crash: null,
        outcomes: {},
        casesWithViolations: 0,
        harnessErrors: 0,
        signatures: [],
        observations: [],
        slow: { thresholdMs: 1000, basis: "max(1000 ms, 100 x median call time of the first 200 cases); not a timing result", cases: [] },
        callTimeMs: { note: "time of the call(s) under test, for the slow-input detector only; not a timing result (untimed series, no quiet-machine protocol)", median: null, p99: null, max: null },
        startedUtc: utcNow(),
        finishedUtc: "",
      };
      const failDir = path.join(outDir, "failures", t.id);
      const slowDir = path.join(outDir, "slow", t.id);
      const sigs = new Map<string, TargetResult["signatures"][number]>();
      const obs = new Map<string, TargetResult["observations"][number]>();
      const times: number[] = [];
      const writeResult = () => writeTargetResult(outDir, res, sigs.values(), obs.values(), times);
      /** The case being run, for a crash record (null outside the case loop). */
      const pos: { current: number | null } = { current: null };
      try {
        if (t.setup && !setupDone.has(t)) {
          await t.setup(ctx);
          setupDone.add(t);
        }
        res.startedUtc = utcNow();
        await runTargetCases(t, budget, res, { outDir, failDir, slowDir, sigs, obs, times, smoke, hb, writeResult, setCurrent: (i) => (pos.current = i) });
        pos.current = null;
        res.complete = res.casesRun === budget;
        writeResult();
        // final occurrence counts into the failure files
        for (const s of sigs.values()) {
          if (!s.file) continue;
          const f = path.join(REPO_ROOT, s.file);
          const j = JSON.parse(fs.readFileSync(f, "utf8")) as Record<string, unknown>;
          j["occurrences"] = s.occurrences;
          j["firstIndices"] = s.firstIndices;
          writeJson(f, j);
        }
      } catch (e) {
        // the child's own code threw: keep a record with the true casesRun, then stop the child
        // with a non-zero exit (the parent fails the step; the summary labels the row)
        res.complete = false;
        const atCase = pos.current;
        res.crash = { errorClass: errClass(e), message: sanitize(errMsg(e)).slice(0, 500), atCase, utc: utcNow() };
        res.stoppedBy = `crashed ${atCase === null ? "outside the case loop" : `at case ${atCase}`} (${res.crash.errorClass})`;
        try {
          writeResult();
        } catch (e2) {
          try {
            writeJson(path.join(outDir, "targets", `${t.id}.json`), { ...res, signatures: [...sigs.values()], observations: [...obs.values()], finishedUtc: utcNow(), recordNote: sanitize(`call-time summary not written: ${errClass(e2)}: ${errMsg(e2)}`) });
          } catch {
            /* nothing more to keep: the parent labels the row "result lost (child crashed)" with the count from the crash line below */
          }
        }
        hb({ crashed: t.id, cases: res.casesRun, atCase, error: `${res.crash.errorClass}: ${res.crash.message}` });
        throw e;
      }
      hb({ done: t.id, cases: res.casesRun, violations: res.casesWithViolations, signatures: sigs.size });
    }
  } finally {
    for (const t of targets) if (t.teardown) await t.teardown().catch(() => undefined);
  }
}

interface CaseLoopContext {
  outDir: string;
  failDir: string;
  slowDir: string;
  sigs: Map<string, TargetResult["signatures"][number]>;
  obs: Map<string, TargetResult["observations"][number]>;
  times: number[];
  smoke: boolean;
  hb: (o: unknown) => void;
  writeResult: () => void;
  setCurrent: (i: number) => void;
}

/** The case loop of one target (as in fz1; the periodic result write is writeTargetResult). */
async function runTargetCases(t: FuzzTarget, budget: number, res: TargetResult, k: CaseLoopContext): Promise<void> {
  const { outDir, failDir, slowDir, sigs, obs, times, smoke, hb, writeResult } = k;
  let lastBeat = Date.now();
  let lastWrite = Date.now();
  let slowTarget = false;
  for (let i = 0; i < budget; i++) {
    k.setCurrent(i);
    let c: FuzzCase;
    let out: CaseOutcome;
    // announce the case before it runs, so the parent knows the exact index of a hang
    if (t.kind === "chain" || i < 200 || slowTarget) hb({ start: i, target: t.id });
    try {
      c = await t.gen(caseRng(MASTER, t.id, i), i);
    } catch (e) {
      res.harnessErrors++;
      res.outcomes["harness:gen-error"] = (res.outcomes["harness:gen-error"] ?? 0) + 1;
      res.casesRun = i + 1; // the index was processed (fz1 left it out, so a generator error on the last index made a full run incomplete)
      if (res.harnessErrors <= 3) hb({ log: sanitize(`generator error at ${t.id}#${i}: ${errClass(e)} ${errMsg(e)}`) });
      continue;
    }
    try {
      out = await t.run(c);
    } catch (e) {
      out = { outcome: "harness:run-error", violations: [{ predicate: "harness:runError", detail: `${errClass(e)}: ${errMsg(e)}`, errorClass: errClass(e) }], observations: [], callMs: 0 };
      res.harnessErrors++;
    }
    res.casesRun = i + 1;
    const key = `${c.family}/${out.outcome}`;
    res.outcomes[key] = (res.outcomes[key] ?? 0) + 1;
    times.push(out.callMs);
    if (i === 199) {
      res.slow.thresholdMs = Math.max(1000, 100 * (quantile(times, 0.5) ?? 0));
      slowTarget = (quantile(times, 0.5) ?? 0) > WATCH_MEDIAN_MS;
    }
    if (out.callMs > res.slow.thresholdMs && res.slow.cases.length < MAX_SLOW) {
      const file = path.join(slowDir, `${i}.json`);
      writeJson(file, { schema: "pqid/v4-fuzz-slow/v1", ...caseRecord(t, i, c), callMs: out.callMs, thresholdMs: res.slow.thresholdMs, note: "slow-input candidate (availability), not a correctness failure; time it only as a load class of a load campaign under docs/v4/ROBUSTNESS.md section 3" });
      res.slow.cases.push({ index: i, ms: Math.round(out.callMs * 10) / 10, file: rel(file) });
    }
    for (const o of out.observations) {
      const e = obs.get(o.id) ?? { id: o.id, count: 0, examples: [] };
      e.count++;
      if (e.examples.length < MAX_OBS_EXAMPLES) {
        let file: string | null = null;
        if (e.examples.length === 0) {
          file = path.join(outDir, "observations", t.id, `${o.id.replace(/[^A-Za-z0-9_.-]/g, "_")}.json`);
          writeJson(file, { schema: "pqid/v4-fuzz-observation/v1", observation: o.id, detail: sanitize(o.detail), ...caseRecord(t, i, c) });
          file = rel(file);
        }
        e.examples.push({ index: i, detail: sanitize(o.detail), file });
      }
      obs.set(o.id, e);
    }
    if (out.violations.length > 0) {
      res.casesWithViolations++;
      const seen = new Set<string>();
      for (const v of out.violations) {
        const sig = `${t.id}|${v.predicate}|${v.errorClass ?? ""}`;
        if (seen.has(sig)) continue;
        seen.add(sig);
        const sigSha = sha256(sig).slice(0, 12);
        const e = sigs.get(sig);
        if (e) {
          e.occurrences++;
          if (e.firstIndices.length < 10) e.firstIndices.push(i);
          continue;
        }
        let file: string | null = null;
        if (sigs.size < MAX_SIGNATURES) {
          file = path.join(failDir, `${sigSha}.json`);
          writeJson(file, failureRecord(t, i, c, sig, sigSha, v, out.violations, smoke));
          file = rel(file);
        }
        sigs.set(sig, { signature: sigSha, predicate: v.predicate, errorClass: v.errorClass ?? null, occurrences: 1, firstIndices: [i], file, example: sanitize(v.detail).slice(0, 300) });
      }
    }
    if (Date.now() - lastBeat > 2000) {
      hb({ hb: i, target: t.id, violations: res.casesWithViolations });
      lastBeat = Date.now();
    }
    if (Date.now() - lastWrite > 30_000) {
      writeResult();
      lastWrite = Date.now();
    }
  }
}

function failureRecord(t: FuzzTarget, i: number, c: FuzzCase, sig: string, sigSha: string, v: Violation, all: Violation[], smoke: boolean): Record<string, unknown> {
  return {
    schema: "pqid/v4-fuzz-failure/v1",
    smoke,
    signature: sig,
    signatureSha12: sigSha,
    predicate: v.predicate,
    errorClass: v.errorClass ?? null,
    violations: all.map((x) => ({ ...x, detail: sanitize(x.detail) })),
    ...caseRecord(t, i, c),
    occurrences: 1,
    firstIndices: [i],
    replay: `node --import tsx harness/v4/robustness/fuzz.ts --replay <this file>`,
    regeneration:
      t.kind === "chain" || ["T-stmt-sig", "T-open", "T-pqc"].includes(t.id)
        ? "keys are generated in memory per run: replay regenerates the case from (master seed, target, index) with fresh keys; mutation positions and choices are identical, key-dependent bytes differ"
        : "the case regenerates byte-identically from (master seed, target, index)",
    gitHead: gitHead(),
    node: process.version,
    openssl: process.versions.openssl ?? null,
    platform: process.platform,
    sources: sourceHashes(),
    writtenUtc: utcNow(),
  };
}

// ------------------------------------------------------------------ parent

export interface ChildRun {
  ids: string[];
  code: number | null;
  stoppedBy: string | null;
  lastHeartbeat: unknown;
  wallSec: number;
  /** Set when the watchdog stopped a hung child: the case being run (exact) or the last completed one. */
  hang: { target: string; caseIndex: number | null; afterCase: number | null } | null;
  /** The child's own Anvil (chain targets), stopped by the parent when the child did not exit cleanly. */
  anvil: { pid: number; port: number; stoppedByParent: boolean; portFreeAfter: boolean | null } | null;
  /** The hang file the parent wrote (repo-relative), if any. */
  hangFile: string | null;
  /** Targets of this child that reported done (their records are final). */
  doneTargets: string[];
  /** The child's crash line, if any: the target, its true casesRun and the case being run. */
  crash: { target: string; cases: number; atCase: number | null; error: string } | null;
}

function portIsFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once("error", () => resolve(false));
    srv.listen(port, "127.0.0.1", () => srv.close(() => resolve(true)));
  });
}

async function waitPortFree(port: number, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  for (;;) {
    if (await portIsFree(port)) return true;
    if (Date.now() > end) return false;
    await new Promise((r) => setTimeout(r, 250));
  }
}

function spawnChild(ids: string[], outDir: string, budgets: Record<string, number>, smoke: boolean, caseCapSec: number, targetCapMin: number, covDir: string | null, port: number): Promise<ChildRun> {
  return new Promise((resolve) => {
    const args = ["--import", tsxImportUrl(), SELF, "--child", "--target", ids.join(","), "--out", outDir, "--budgets", JSON.stringify(budgets), "--port", String(port)];
    if (smoke) args.push("--smoke");
    const env = { ...process.env, ...(covDir ? { NODE_V8_COVERAGE: covDir } : {}) };
    const t0 = Date.now();
    const child = spawn(process.execPath, args, { cwd: REPO_ROOT, env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true, shell: false });
    let last: unknown = null;
    let lastAt = Date.now();
    let stoppedBy: string | null = null;
    let hung = false;
    let lastStart: { target: string; i: number } | null = null;
    let lastTarget: string = ids[0] as string;
    const lastDone = new Map<string, number>();
    const doneTargets: string[] = [];
    let crash: ChildRun["crash"] = null;
    let anvil: ChildRun["anvil"] = null;
    let buf = "";
    child.stdout.setEncoding("utf8").on("data", (d: string) => {
      buf += d;
      let k: number;
      while ((k = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, k).trim();
        buf = buf.slice(k + 1);
        if (!line) continue;
        lastAt = Date.now();
        try {
          const j = JSON.parse(line) as Record<string, unknown>;
          if (typeof j["start"] === "number") {
            lastStart = { target: String(j["target"]), i: j["start"] };
            lastTarget = String(j["target"]);
            continue;
          }
          last = j;
          if (typeof j["hb"] === "number") {
            lastTarget = String(j["target"]);
            lastDone.set(lastTarget, j["hb"]);
          }
          if (typeof j["anvilPid"] === "number") anvil = { pid: j["anvilPid"], port: Number(j["anvilPort"] ?? port), stoppedByParent: false, portFreeAfter: null };
          if (j["log"]) console.log(`[fuzz ${ids.join(",")}] ${String(j["log"])}`);
          if (j["done"]) {
            lastStart = null;
            doneTargets.push(String(j["done"]));
            console.log(`[fuzz] ${String(j["done"])}: ${String(j["cases"])} cases, ${String(j["violations"])} with violations, ${String(j["signatures"])} distinct signatures`);
          }
          if (j["crashed"]) {
            crash = { target: String(j["crashed"]), cases: Number(j["cases"]), atCase: typeof j["atCase"] === "number" ? j["atCase"] : null, error: sanitize(String(j["error"] ?? "")) };
            console.error(`[fuzz] ${crash.target} crashed after ${crash.cases} cases${crash.atCase === null ? "" : ` (at case ${crash.atCase})`}: ${crash.error}`);
          }
        } catch {
          console.log(`[fuzz ${ids.join(",")}] ${sanitize(line)}`);
        }
      }
    });
    let errTail = "";
    child.stderr.setEncoding("utf8").on("data", (d: string) => {
      errTail = (errTail + d).slice(-4000);
    });
    const timer = setInterval(() => {
      if (stoppedBy) return;
      if (Date.now() - lastAt > caseCapSec * 1000) {
        hung = true;
        stoppedBy = `no progress for ${caseCapSec} s (hang candidate) after ${JSON.stringify(lastStart ?? last)}`;
        child.kill();
      } else if (Date.now() - t0 > targetCapMin * 60_000) {
        stoppedBy = `target wall-clock cap ${targetCapMin} min reached (interrupted)`;
        child.kill();
      }
    }, 1000);
    child.on("close", (code) => {
      clearInterval(timer);
      if (code !== 0 && errTail) console.error(sanitize(`[fuzz ${ids.join(",")}] child stderr tail:\n${errTail}`));
      void (async () => {
        // a killed or crashed chain child cannot stop its own Anvil (on Windows the kill does not reach grandchildren)
        const a = anvil as ChildRun["anvil"];
        if (a && (stoppedBy !== null || code !== 0)) {
          try {
            process.kill(a.pid);
            a.stoppedByParent = true;
          } catch {
            /* already gone */
          }
          a.portFreeAfter = await waitPortFree(a.port, 15_000);
          if (!a.portFreeAfter) console.error(`[fuzz] 127.0.0.1:${a.port} is still in use after stopping the chain child's Anvil`);
        }
        let hang: ChildRun["hang"] = null;
        if (hung) {
          const ls = lastStart as { target: string; i: number } | null;
          hang = ls ? { target: ls.target, caseIndex: ls.i, afterCase: null } : { target: lastTarget, caseIndex: null, afterCase: lastDone.get(lastTarget) ?? null };
        }
        resolve({ ids, code, stoppedBy, lastHeartbeat: last, wallSec: Math.round((Date.now() - t0) / 100) / 10, hang, anvil: a, hangFile: null, doneTargets, crash });
      })();
    });
  });
}

/** Save a hang as failures/<id>/hang_<index>.json, the case regenerated in this process from (seed, target, index). */
export async function writeHang(outDir: string, run: Pick<ChildRun, "hang" | "stoppedBy">, smoke: boolean): Promise<string | null> {
  if (!run.hang) return null;
  const id = run.hang.target;
  const t = PURE_TARGETS.find((x) => x.id === id) ?? (await loadChainTargets()).find((x) => x.id === id);
  if (!t) return null;
  const dir = path.join(outDir, "failures", t.id);
  const base = { schema: "pqid/v4-fuzz-hang/v1", smoke, target: t.id, stoppedBy: run.stoppedBy ? sanitize(run.stoppedBy) : null, masterSeed: MASTER, targetSeed: targetSeed(MASTER, t.id), gitHead: gitHead(), sources: sourceHashes(), writtenUtc: utcNow() };
  if (run.hang.caseIndex === null) {
    const file = path.join(dir, `hang_after_${run.hang.afterCase ?? "start"}.json`);
    writeJson(file, { ...base, caseIndex: null, lastCompletedCase: run.hang.afterCase, note: "a fast target past its first 200 cases does not announce each case: the hung case is after lastCompletedCase (rerun the target from there)" });
    return rel(file);
  }
  const i = run.hang.caseIndex;
  // pure targets may need their setup (Poseidon, in-memory keys) to generate; chain targets generate a plan only
  if (t.kind === "pure" && t.setup) await t.setup({ smoke, log: () => undefined });
  try {
    const c = await t.gen(caseRng(MASTER, t.id, i), i);
    const file = path.join(dir, `hang_${i}.json`);
    writeJson(file, { ...base, ...caseRecord(t, i, c), replay: "node --import tsx harness/v4/robustness/fuzz.ts --replay <this file> (runs the case once more, without a watchdog)" });
    return rel(file);
  } finally {
    if (t.kind === "pure" && t.teardown) await t.teardown().catch(() => undefined);
  }
}

async function parent(argv: string[]): Promise<number> {
  const smoke = flag(argv, "smoke");
  const campaign = opt(argv, "campaign") ?? (smoke ? "smoke" : undefined);
  if (!campaign || !/^[A-Za-z0-9_.-]{1,64}$/.test(campaign)) throw new Error("--campaign <name> is required (letters, digits, _ . -)");
  const scale = optNum(argv, "scale", REGISTERED.scale);
  if (!(scale > 0)) throw new Error("--scale must be > 0");
  const caseCapSec = optNum(argv, "case-cap-sec", smoke ? 60 : REGISTERED.caseCapSec);
  const targetCapMin = optNum(argv, "target-cap-min", smoke ? 10 : REGISTERED.targetCapMin);
  const deviation = budgetDeviation(argv, smoke, [
    { flag: "scale", value: scale, registered: REGISTERED.scale },
    { flag: "case-cap-sec", value: caseCapSec, registered: REGISTERED.caseCapSec },
    { flag: "target-cap-min", value: targetCapMin, registered: REGISTERED.targetCapMin },
  ]);
  const port = optNum(argv, "port", PORTS.fuzzing);
  if (!smoke && port !== PORTS.fuzzing) throw new Error(`chain fuzz targets use port ${PORTS.fuzzing} (DECISIONS D-034)`);
  const wantCoverage = flag(argv, "coverage");
  const sel = opt(argv, "targets") ?? "all";
  const all = await allTargets();
  const chosen = sel === "all" ? all : sel === "pure" ? all.filter((t) => t.kind === "pure") : sel === "chain" ? all.filter((t) => t.kind === "chain") : sel.split(",").map((id) => {
    const t = all.find((x) => x.id === id.trim());
    if (!t) throw new Error(`unknown target ${id}; known: ${all.map((x) => x.id).join(", ")}`);
    return t;
  });
  if (new Set(chosen.map((t) => t.id)).size !== chosen.length) throw new Error("--targets names a target more than once");
  const root = path.join(robustnessRoot(smoke), "fuzz", campaign);
  if (fs.existsSync(path.join(root, "plan.json"))) throw new Error(`${rel(root)} already holds a campaign; choose a new --campaign name (no resume)`);
  const commit = assertCommitted(smoke);
  const roots = markerRoots({ ...(windowsRepoFromArgs(argv) ? { windowsRepo: windowsRepoFromArgs(argv) as string } : {}), allowLocalOnlyInWsl: smoke });
  let release: () => void = () => undefined;
  let step: StepResult;
  if (smoke) assertMarkersFree(roots, "BUSY");
  else {
    const h = acquireMarker({ kind: "BUSY", campaign: `robustness/fuzz/${campaign}`, runner: "harness/v4/robustness/fuzz.ts", owner: "operator", roots });
    release = () => h.release();
  }
  try {
    fs.mkdirSync(root, { recursive: true });
    const budgets: Record<string, number> = {};
    for (const t of chosen) budgets[t.id] = Math.max(1, Math.round((smoke ? t.smokeBudget : t.budget) * scale));
    writeJson(path.join(root, "plan.json"), {
      schema: "pqid/v4-fuzz-plan/v1",
      campaign,
      smoke,
      preRegistration: "docs/v4/ROBUSTNESS.md",
      protocol: protocolRecord(smoke),
      masterSeed: MASTER,
      seedRule: "target seed = (master XOR crc32(targetId)) >>> 0; case i draws from caseSeed(targetSeed, i) (harness/v4/robustness/rng.ts)",
      generator: "in-repo seeded generator (sfc32 seeded by splitmix32), no shrinking (D-034: no property-testing package)",
      scale,
      caseCapSec,
      targetCapMin,
      registered: REGISTERED,
      deviation,
      gitClean: commit.gitClean,
      commitChecked: commit.paths,
      chainPort: port,
      targets: chosen.map((t) => ({ id: t.id, kind: t.kind, title: t.title, entryPoints: t.entryPoints, property: t.property, documentedErrors: t.documentedErrors, budget: budgets[t.id], targetSeed: targetSeed(MASTER, t.id) })),
      coverage: wantCoverage,
      createdUtc: utcNow(),
    });
    writeJson(path.join(root, "env.json"), {
      schema: "pqid/v4-fuzz-env/v2",
      env: envInfo(),
      gitHead: gitHead(),
      commit,
      sources: sourceHashes(),
      keyLabel: "dev (chain targets prove with setup/out/v4/credential_auth_v4_dev.zkey)",
      marker: smoke ? "none (smoke run; markers checked free)" : "results/v4/BUSY held for the whole campaign (D-034)",
    });
    // raw V8 coverage files are large (tens of MB): they go to the OS temp directory and are
    // deleted once summarised; only coverage/summary.json and summary.md are kept
    const covDir = wantCoverage ? fs.mkdtempSync(path.join(os.tmpdir(), "pqid-v4-fuzzcov-")) : null;
    const groups = childGroups(all, chosen);
    const runs: ChildRun[] = [];
    for (const g of groups) {
      console.log(`[fuzz] ${g.join(", ")}: ${g.map((id) => budgets[id]).join(", ")} cases`);
      const gb: Record<string, number> = {};
      for (const id of g) gb[id] = budgets[id] as number;
      const run = await spawnChild(g, root, gb, smoke, caseCapSec, targetCapMin, covDir, port);
      run.hangFile = await writeHang(root, run, smoke).catch((e: unknown) => {
        console.error(sanitize(`[fuzz] could not write the hang file: ${errMsg(e)}`));
        return null;
      });
      if (run.hangFile) console.log(`[fuzz] hang saved: ${run.hangFile}`);
      runs.push(run);
      if (run.anvil && run.anvil.portFreeAfter === false) throw new Error(`the chain child's Anvil still holds 127.0.0.1:${run.anvil.port}; stop it before any other run`);
    }
    let coverage: ReturnType<typeof summariseCoverage> | null = null;
    if (covDir) {
      try {
        coverage = summariseCoverage([covDir]);
      } finally {
        fs.rmSync(covDir, { recursive: true, force: true });
      }
      writeJson(path.join(root, "coverage", "summary.json"), coverage);
      fs.writeFileSync(path.join(root, "coverage", "summary.md"), coverageMarkdown(coverage, `Fuzz coverage of packages/v4/src (campaign ${campaign})`));
    }
    step = writeSummary(root, campaign, smoke, chosen, runs, coverage, budgets);
  } finally {
    release();
  }
  // a child that exited non-zero or was stopped, or a target that is not complete, fails the step
  // (fz1's parent returned 0 in that case, so the driver logged success)
  if (step.failed) console.error(sanitize(`[fuzz] step failed (exit 1): ${step.reasons.join("; ")}`));
  return step.exitCode;
}

/** The step's verdict: it fails (runner exit 1) when a child exits non-zero, a child is stopped by the watchdog, or a target is not complete. Property violations do not fail the step (they are findings). */
export interface StepResult {
  exitCode: 0 | 1;
  failed: boolean;
  reasons: string[];
}

/** How a target ended, from its record and its child's exit (summary rows). */
export interface TargetStatus {
  /** "complete"; "crashed at case <i> (<class>), record kept"; "result lost (child crashed)" or "result lost (child stopped by the watchdog)", with any count known; "not run (...)". */
  status: string;
  complete: boolean;
  /** The target's counters are not known (no final record): its row must not be read as 0 cases or as no violations. */
  resultLost: boolean;
  /** Cases run when known exactly (a final record or the child's crash line); null when lost. */
  casesRun: number | null;
  /** casesRun of the last 30 s checkpoint record of a lost result (a lower bound), else null. */
  checkpointCasesRun: number | null;
}

export function targetStatus(id: string, r: Pick<TargetResult, "complete" | "casesRun" | "crash"> | null, run: Pick<ChildRun, "ids" | "code" | "stoppedBy" | "doneTargets" | "crash"> | undefined): TargetStatus {
  if (r?.complete) return { status: "complete", complete: true, resultLost: false, casesRun: r.casesRun, checkpointCasesRun: null };
  if (r?.crash) {
    const where = r.crash.atCase === null ? "outside the case loop" : `at case ${r.crash.atCase}`;
    return { status: `crashed ${where} (${r.crash.errorClass}), record kept`, complete: false, resultLost: false, casesRun: r.casesRun, checkpointCasesRun: null };
  }
  if (!run) return { status: "not run (no child)", complete: false, resultLost: false, casesRun: 0, checkpointCasesRun: null };
  if (run.code === 0 && run.stoppedBy === null) return { status: "incomplete (the child exited 0 without a final record)", complete: false, resultLost: true, casesRun: null, checkpointCasesRun: r ? r.casesRun : null };
  // the child failed: the first of its targets that did not report done was running; later ones never started
  // (a child runs its targets in the order of run.ids: childGroups, targetsInOrder)
  const running = run.ids.find((x) => !run.doneTargets.includes(x)) ?? null;
  if (!r && running !== null && running !== id && run.ids.indexOf(id) > run.ids.indexOf(running)) {
    return { status: `not run (the child stopped during ${running})`, complete: false, resultLost: false, casesRun: 0, checkpointCasesRun: null };
  }
  const crashCount = run.crash?.target === id ? run.crash.cases : null;
  const checkpoint = r ? r.casesRun : null;
  const status =
    `result lost (${run.stoppedBy !== null ? "child stopped by the watchdog" : "child crashed"})` +
    (crashCount !== null ? `, ${crashCount} cases run (the child's crash line)` : "") +
    (checkpoint !== null ? `, last checkpoint at ${checkpoint} cases` : "");
  return { status, complete: false, resultLost: true, casesRun: crashCount, checkpointCasesRun: checkpoint };
}

/** The files a target left in the campaign directory (written inside the case loop, so they survive a crash). */
function filesOnDisk(root: string, id: string): { failures: string[]; observations: string[]; slow: string[] } {
  const list = (d: string): string[] => {
    const dir = path.join(root, d, id);
    return fs.existsSync(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort().map((f) => rel(path.join(dir, f))) : [];
  };
  return { failures: list("failures"), observations: list("observations"), slow: list("slow") };
}

export function writeSummary(
  root: string,
  campaign: string,
  smoke: boolean,
  chosen: readonly Pick<FuzzTarget, "id" | "kind">[],
  runs: ChildRun[],
  coverage: ReturnType<typeof summariseCoverage> | null,
  budgets: Record<string, number>
): StepResult {
  const rows = chosen.map((t) => {
    const f = path.join(root, "targets", `${t.id}.json`);
    // a record cut short by a killed child, or otherwise unreadable, counts as no record
    let r: TargetResult | null = null;
    let recordUnreadable = false;
    if (fs.existsSync(f)) {
      try {
        r = JSON.parse(fs.readFileSync(f, "utf8")) as TargetResult;
      } catch {
        recordUnreadable = true;
      }
    }
    const run = runs.find((x) => x.ids.includes(t.id));
    const st = targetStatus(t.id, r, run);
    // counters are final for a complete record and for a crash record (true counts up to the crash)
    const fr = st.complete || r?.crash ? r : null;
    const kept = st.resultLost || Boolean(r?.crash);
    return {
      target: t.id,
      kind: t.kind,
      budget: budgets[t.id] ?? r?.budget ?? null,
      status: st.status,
      complete: st.complete,
      resultLost: st.resultLost,
      casesRun: st.casesRun,
      checkpointCasesRun: st.checkpointCasesRun,
      stoppedBy: st.complete ? null : (r?.stoppedBy ?? run?.stoppedBy ?? (run && run.code !== 0 ? `child exit code ${String(run.code)}` : null)),
      childExitCode: run ? run.code : null,
      recordUnreadable,
      crash: r?.crash ?? null,
      /** The child's crash line for this target (it carries the count and the error when the crash record itself could not be written). */
      childCrashLine: run?.crash?.target === t.id ? run.crash : null,
      hangFile: run?.hang?.target === t.id ? run.hangFile : null,
      anvilCleanup: run?.anvil && (run.stoppedBy !== null || run.code !== 0) ? { stoppedByParent: run.anvil.stoppedByParent, portFreeAfter: run.anvil.portFreeAfter, note: "stoppedByParent false means the Anvil process had already exited when the parent tried to stop it" } : null,
      casesWithViolations: fr ? fr.casesWithViolations : null,
      distinctSignatures: fr ? fr.signatures.length : null,
      signatures: (fr?.signatures ?? []).map((s) => ({ predicate: s.predicate, errorClass: s.errorClass, occurrences: s.occurrences, file: s.file })),
      observations: (fr?.observations ?? []).map((o) => ({ id: o.id, count: o.count })),
      slowCases: fr ? fr.slow.cases.length : null,
      harnessErrors: fr ? fr.harnessErrors : null,
      /** The last checkpoint of a lost result: lower bounds, never final counts. */
      checkpoint:
        st.resultLost && r
          ? { note: "last 30 s checkpoint before the child failed: lower bounds, not final counts", casesRun: r.casesRun, casesWithViolations: r.casesWithViolations, distinctSignatures: r.signatures.length, observations: r.observations.map((o) => ({ id: o.id, count: o.count })) }
          : null,
      /** Failure, observation and slow files of a lost or crashed target (written inside the case loop, so kept). */
      filesOnDisk: kept ? filesOnDisk(root, t.id) : null,
    };
  });
  const reasons: string[] = [];
  for (const run of runs) {
    if (run.code !== 0) reasons.push(`child ${run.ids.join(",")}: exit code ${String(run.code)}`);
    if (run.stoppedBy !== null) reasons.push(`child ${run.ids.join(",")}: ${sanitize(run.stoppedBy)}`);
  }
  for (const r of rows) if (!r.complete) reasons.push(`${r.target}: ${r.status}`);
  const step: StepResult = { exitCode: reasons.length ? 1 : 0, failed: reasons.length > 0, reasons };
  const lost = rows.filter((r) => r.resultLost);
  type Row = (typeof rows)[number];
  const sawViolations = (r: Row) => (r.casesWithViolations ?? r.checkpoint?.casesWithViolations ?? 0) > 0;
  const summary = {
    schema: "pqid/v4-fuzz-summary/v2",
    campaign,
    smoke,
    note: smoke ? "smoke run: checks the runner only; never quoted" : "untimed fuzz campaign; counts only (no timing results)",
    step,
    totals: {
      targets: rows.length,
      casesRun: rows.reduce((s, r) => s + (r.casesRun ?? r.checkpointCasesRun ?? 0), 0),
      casesRunIsLowerBound: lost.length > 0,
      targetsWithViolations: rows.filter(sawViolations).length,
      distinctSignatures: rows.reduce((s, r) => s + (r.distinctSignatures ?? r.checkpoint?.distinctSignatures ?? 0), 0),
      incompleteTargets: rows.filter((r) => !r.complete).map((r) => r.target),
      resultLostTargets: lost.map((r) => r.target),
      hangs: rows.filter((r) => r.hangFile).map((r) => r.hangFile),
    },
    coverage: coverage ? { ...coverage.totals, scope: coverage.totalsScope, unloadedFiles: coverage.unloadedFiles } : null,
    targets: rows,
    finishedUtc: utcNow(),
  };
  writeJson(path.join(root, "summary.json"), summary);
  const casesCell = (r: Row): string => {
    const b = r.budget ?? "not known";
    if (r.casesRun !== null) return `${r.casesRun} / ${b}`;
    if (r.checkpointCasesRun !== null) return `at least ${r.checkpointCasesRun} / ${b}`;
    return `not known / ${b}`;
  };
  const lostCell = (r: Row, v: number | null): string => (v !== null ? String(v) : r.resultLost ? "lost" : "n/a");
  const obsCell = (r: Row): string => {
    if (r.resultLost) return `lost (${r.filesOnDisk?.observations.length ?? 0} observation file(s) kept)`;
    return r.observations.map((o) => `${o.id} x${o.count}`).join("; ") || "none";
  };
  const lostLine = (r: Row): string => {
    const fd = r.filesOnDisk ?? { failures: [], observations: [], slow: [] };
    const files = [...fd.failures, ...fd.observations, ...fd.slow];
    const cp = r.checkpoint
      ? ` Last checkpoint (lower bounds): ${r.checkpoint.casesRun} cases, ${r.checkpoint.casesWithViolations} with violations, observations ${r.checkpoint.observations.map((o) => `${o.id} x${o.count}`).join("; ") || "none"}.`
      : "";
    return `- ${r.target}: ${r.status}.${cp} Files kept: ${files.length ? files.map((x) => "`" + x + "`").join(", ") : "none"}.`;
  };
  const md = [
    `# Fuzz campaign ${campaign}${smoke ? " (smoke: never quoted)" : ""}`,
    "",
    "Generated by harness/v4/robustness/fuzz.ts. Pre-registration: docs/v4/ROBUSTNESS.md. Counts only.",
    "",
    step.failed ? `Step result: failed (runner exit 1). ${step.reasons.map((x) => x.slice(0, 200)).join("; ")}.` : "Step result: every target complete (runner exit 0).",
    "",
    `Cases run: ${summary.totals.casesRun}${lost.length ? ` (a lower bound: the result of ${lost.length} target(s) was lost)` : ""}.`,
    "",
    "| Target | Status | Cases run / budget | Cases with violations | Distinct signatures | Observations | Slow cases |",
    "|---|---|---|---|---|---|---|",
    ...rows.map((r) => `| ${r.target} | ${r.status.slice(0, 160)} | ${casesCell(r)} | ${lostCell(r, r.casesWithViolations)} | ${lostCell(r, r.distinctSignatures)} | ${obsCell(r)} | ${lostCell(r, r.slowCases)} |`),
    "",
    ...(rows.some((r) => r.signatures.length)
      ? ["## Failure signatures", "", ...rows.flatMap((r) => r.signatures.map((s) => `- ${r.target}: \`${s.predicate}\`${s.errorClass ? ` (${s.errorClass})` : ""} x${s.occurrences}${s.file ? `, input in \`${s.file}\`` : ""}`)), ""]
      : [lost.length ? "No property violations in the targets whose results were kept." : "No property violations.", ""]),
    ...(rows.some((r) => r.filesOnDisk) ? ["## Lost or crashed targets", "", ...rows.filter((r) => r.filesOnDisk).map(lostLine), ""] : []),
    ...(rows.some((r) => r.hangFile) ? ["## Hangs", "", ...rows.filter((r) => r.hangFile).map((r) => `- ${r.target}: \`${r.hangFile}\``), ""] : []),
    ...(coverage ? [`Coverage of the packages/v4/src modules the fuzz processes loaded (fuzz processes only; ${coverage.unloadedFiles.length} package file(s) not loaded and not counted): lines ${coverage.totals.linesCovered}/${coverage.totals.linesExecutable} (${coverage.totals.linePercent} %), functions ${coverage.totals.functionsCovered}/${coverage.totals.functions} (${coverage.totals.functionPercent} %). Details: coverage/summary.md.`, ""] : []),
  ].join("\n");
  fs.writeFileSync(path.join(root, "summary.md"), md);
  console.log(`[fuzz] summary: ${rel(path.join(root, "summary.md"))}`);
  return step;
}

// ------------------------------------------------------------------ replay

async function replay(file: string, argv: string[]): Promise<number> {
  // D-034: every runner refuses while RUNNING or BUSY exists (a replay starts Anvil and proves)
  assertMarkersFree(markerRoots({ ...(windowsRepoFromArgs(argv) ? { windowsRepo: windowsRepoFromArgs(argv) as string } : {}), allowLocalOnlyInWsl: true }), "BUSY");
  const j = JSON.parse(fs.readFileSync(path.resolve(file), "utf8")) as Record<string, unknown>;
  const id = String(j["target"]);
  const index = Number(j["caseIndex"]);
  if (Number(j["masterSeed"]) !== MASTER) throw new Error(`failure was recorded with master seed ${String(j["masterSeed"])}, this runner uses ${MASTER}`);
  const t = (await allTargets()).find((x) => x.id === id);
  if (!t) throw new Error(`unknown target ${id}`);
  process.env["PQID_FUZZ_PORT"] = String(optNum(argv, "port", PORTS.fuzzing));
  // chain targets build a smaller world in smoke runs (case draws depend on it): replay with the recorded setting
  if (t.setup) await t.setup({ smoke: j["smoke"] === true, log: (s) => console.log(sanitize(s)), emit: () => undefined });
  try {
    const c = await t.gen(caseRng(MASTER, id, index), index);
    const regenerated = JSON.stringify(encodeTyped(c.input));
    // a null input is stored as null: targets that build their input inside run() from the case's sub-seed (T-open, the chain targets) store none
    const stored = j["inputTruncated"] === true ? null : JSON.stringify(j["input"] ?? null);
    const same =
      stored === null
        ? "not stored (input above the size cap)"
        : regenerated !== stored
          ? "DIFFERENT (generator or sources changed since the failure was recorded)"
          : stored === "null"
            ? "identical (null: this target builds the input inside run() from the case's sub-seed)"
            : "identical";
    let out: CaseOutcome;
    try {
      out = await t.run(c);
    } catch (e) {
      // as in the campaign loop: a throw of the target's own code is a harness run error
      out = { outcome: "harness:run-error", violations: [{ predicate: "harness:runError", detail: `${errClass(e)}: ${errMsg(e)}`, errorClass: errClass(e) }], observations: [], callMs: 0 };
    }
    console.log(JSON.stringify({ target: id, caseIndex: index, regeneratedInput: same, outcome: out.outcome, violations: out.violations.map((v) => ({ ...v, detail: sanitize(v.detail) })), observations: out.observations.length }, null, 2));
    return out.violations.length > 0 ? 1 : 0;
  } finally {
    if (t.teardown) await t.teardown();
  }
}

// ------------------------------------------------------------------ main

async function main(argv: string[]): Promise<number> {
  if (flag(argv, "child")) {
    const ids = (opt(argv, "target") ?? "").split(",").filter(Boolean);
    process.env["PQID_FUZZ_PORT"] = String(optNum(argv, "port", PORTS.fuzzing));
    await runChild(ids, opt(argv, "out") as string, JSON.parse(opt(argv, "budgets") ?? "{}") as Record<string, number>, flag(argv, "smoke"));
    return 0;
  }
  const rf = opt(argv, "replay");
  if (rf) return replay(rf, argv);
  return parent(argv);
}

if (process.argv[1] && path.resolve(process.argv[1]) === SELF) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e: unknown) => {
      console.error(sanitize(e instanceof Error ? (e.stack ?? e.message) : String(e)));
      process.exit(1);
    }
  );
}
