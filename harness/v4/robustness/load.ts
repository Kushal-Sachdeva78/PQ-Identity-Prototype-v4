import fs from "node:fs";
import path from "node:path";
import v8 from "node:v8";
import vm from "node:vm";
import nodeCrypto, { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { Worker } from "node:worker_threads";
import { fileURLToPath } from "node:url";
import { version as ETHERS_VERSION } from "ethers";
import { canonicalJsonBytes } from "@pqid/common/hash";
import { startAnvil, type AnvilHandle } from "@pqid/ledger";
import type { World } from "@pqid/v4/world";
import type { HolderWalletV4 } from "@pqid/v4/wallet";
import type { VerifierV4, PresentationV4 } from "@pqid/v4/verifier";
import { transcriptHash, deriveSessionSecrets, walletOpenSession, VerifierSessionStore, type ProofRequestV4, type SessionReplyV4 } from "@pqid/v4/session";
import { DEFAULT_TYPE_ID, SESSION_TTL_MS } from "@pqid/v4/constants";
import { VKEY_V4, PINS_V4 } from "@pqid/v4/paths";
import {
  REPO_ROOT,
  envInfo,
  gitHead,
  sanitize,
  rel,
  utcNow,
  writeJson,
  appendJsonl,
  flag,
  opt,
  optNum,
  protocolSha,
  sha256FileHex,
  snarkjsVersion,
  sleep,
} from "../bench/lib.ts";
import { readPower, type PowerReading } from "../bench/guard.ts";
import { acquireMarker, assertMarkersFree, markerRoots, windowsRepoFromArgs } from "../lib/markers.ts";
import { readQuiesceExcluding, type QuiesceRecord } from "../lib/quiesce.ts";
import { SEEDS } from "../lib/seeds.ts";
import { PORTS } from "../lib/ports.ts";
import { ROUND_TRIP_DEFINITION } from "../lib/rpc_trace.ts";
import { worldOnRpc, snapshotSessions, restoreSessions, replaceSessionStore, assertPortFree } from "../scale_lib.ts";
import { Rng } from "./rng.ts";
import { robustnessRoot, protocolRecord, assertCommitted } from "./common.ts";
import { buildHostile, tamperedBox, wrongNonce, garbageProof, prettyPrinted, wire, type SessionKeys, type HostileItem } from "./hostile.ts";
import {
  FULL_LEVELS,
  SMOKE_LEVELS,
  HOSTILE_CLASSES,
  HOSTILE_DESCRIPTIONS,
  HOSTILE_EXPECTED_CHECKS,
  CORRECTNESS_EXPECTED_CHECKS,
  expectedOutcome,
  sameCheckSet,
  freeIndices,
  buildLoadSchedule,
  cellsOf,
  correctnessIndices,
  rotation,
  passRates,
  linuxThreads,
  linuxCpuTicks,
  r3,
  ClockWatch,
  CLOCK_GAP_LIMIT_MS,
  TICK_GAP_LIMIT_MS,
  type ClockRecord,
  type Cell,
  type HostileClass,
  type LoadLevels,
  type ScheduledBlock,
} from "./load_lib.ts";

/**
 * Load test "verifier library under concurrent load" (robustness row, DECISIONS D-034;
 * protocol and pre-registered levels in docs/v4/ROBUSTNESS.md section 3). A timed series: a
 * full campaign holds results/v4/bench/RUNNING for its whole length and refuses to start while
 * RUNNING or BUSY exists, or while the protocol, harness or code under test is not committed.
 * Library-level calls (VerifierV4.verifyReply on wire bytes) in worker threads against one local
 * Anvil (port 8780, "loopback, same host"), no HTTP front end.
 *
 *   node --import tsx harness/v4/robustness/load.ts --campaign <name> [--windows-repo <dir>]
 *   node --import tsx harness/v4/robustness/load.ts --smoke [--campaign <name>] [--p 12 --r 8 ... --timeout-ms 30000]
 *        [--inject-fault worker-exit]
 *
 * --inject-fault worker-exit (smoke only) makes the last worker exit at the start of block 1, to
 * check the error-block path (drain, replacement, warm-up, repeat); a short --timeout-ms (smoke
 * only) checks the timeout and late-settlement path. Both are recorded in env.json.
 *
 * Results: results/v4/robustness/load/<campaign>/ (smoke: results/v4/robustness/_smoke/load/):
 * schedule.json (before the first block), env.json, inputs/pool.json, inputs/presentations.jsonl,
 * inputs/hostile.json, auxiliary.json, runs.jsonl, hostile.jsonl, correctness.jsonl, blocks.jsonl,
 * saturation.json. Statistics: scripts/robustness/analyze_load.py. No resume: a stopped campaign
 * is rerun under a new name. Secrets (the verifier's KEM private key, session keys) live in
 * memory only.
 */

/** The auxiliary record; not "aux.json": AUX is a reserved device name on Windows (ROBUSTNESS.md Deviations 2026-10-03). */
const AUX_FILE = "auxiliary.json";

const SELF = fileURLToPath(import.meta.url);
const WORKER_BOOT = new URL("./load_worker_boot.mjs", import.meta.url);
const WORKER_ENTRY = new URL("./load_worker.ts", import.meta.url).href;
const SEED = SEEDS.robustness.load;
const POLICY = { predicate: "age_gte" as const, threshold: 18, typeId: DEFAULT_TYPE_ID };
const EPOCH_NS = process.hrtime.bigint();
/** How long a worker waits for timed-out calls to finish before it restores its sessions. */
const LATE_BOUND_MS = 120_000;
/** A block discarded this many times stops the campaign (docs/v4/ROBUSTNESS.md 3.9). */
const MAX_ATTEMPTS = 5;
/** Toolchain of each OS (D-034; docs/v4/ROBUSTNESS.md 3.2): full runs refuse anything else. */
const TOOLCHAIN: Readonly<Record<string, { node: string; anvil: string }>> = Object.freeze({
  win32: { node: "v24.18.0", anvil: "1.5.1-" },
  linux: { node: "v24.21.0", anvil: "1.5.1-" },
});
const msOf = (ns: bigint) => Number(ns - EPOCH_NS) / 1e6;
const log = (s: string) => console.log(`[load ${new Date().toISOString().slice(11, 19)}] ${sanitize(s)}`);
const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

function harnessFiles(): string[] {
  const dir = (d: string, re: RegExp) =>
    fs.existsSync(path.join(REPO_ROOT, ...d.split("/")))
      ? fs
          .readdirSync(path.join(REPO_ROOT, ...d.split("/")))
          .filter((f) => re.test(f))
          .sort()
          .map((f) => `${d}/${f}`)
      : [];
  return [...dir("harness/v4/robustness", /\.(ts|mjs)$/), ...dir("harness/v4/lib", /\.ts$/), "harness/v4/scale_lib.ts", "harness/v4/bench/lib.ts", "harness/v4/bench/guard.ts", ...dir("scripts/robustness", /\.(py|sh)$/)];
}

function sourceFiles(): string[] {
  return [
    "onchain/contracts/v4/RegistriesV4.sol",
    ...fs
      .readdirSync(path.join(REPO_ROOT, "packages", "v4", "src"))
      .filter((f) => f.endsWith(".ts"))
      .sort()
      .map((f) => `packages/v4/src/${f}`),
    "setup/out/v4/verification_key_dev.json",
  ];
}

function shaOf(files: string[]): Record<string, string> {
  return Object.fromEntries(files.map((f) => [f, sha256FileHex(path.join(REPO_ROOT, ...f.split("/")))]));
}

/** The Anvil the run starts (packages/ledger startAnvil: tools/foundry/anvil.exe on Windows, else anvil from PATH). */
function anvilVersion(): string | null {
  const bin = process.platform === "win32" ? path.join(REPO_ROOT, "tools", "foundry", "anvil.exe") : "anvil";
  const r = spawnSync(bin, ["--version"], { encoding: "utf8", windowsHide: true });
  if (r.status !== 0) return null;
  const lines = String(r.stdout).split(/\r?\n/).filter((l) => l.trim().length > 0);
  return sanitize(lines.join(" | ")).slice(0, 300);
}

/** Full runs: Node and Anvil must be the D-034 toolchain of this OS. */
function checkToolchain(smoke: boolean): { expected: { node: string; anvil: string } | null; node: string; anvil: string | null; ok: boolean } {
  const expected = TOOLCHAIN[process.platform] ?? null;
  const anvil = anvilVersion();
  const ok = expected !== null && process.version === expected.node && anvil !== null && anvil.includes(expected.anvil);
  if (!smoke && !ok) {
    throw new Error(
      `the load test runs on the D-034 toolchain only (docs/v4/ROBUSTNESS.md 3.2): ${process.platform} needs Node ${expected?.node ?? "(no toolchain registered for this OS)"} and Anvil ${expected?.anvil ?? "?"}x; found Node ${process.version}, Anvil ${anvil ?? "not found"}` +
        (process.platform === "linux" ? " (WSL: run through scripts/robustness/run_robustness.sh with PQID_NODE and PQID_ANVIL_DIR)" : "")
    );
  }
  return { expected, node: process.version, anvil, ok };
}

function gcFn(): (() => void) | null {
  try {
    v8.setFlagsFromString("--expose_gc");
    return vm.runInNewContext("gc") as () => void;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ worker pool

interface Pending {
  resolve: (m: Record<string, unknown>) => void;
  reject: (e: Error) => void;
}

class WorkerHandle {
  worker: Worker;
  pending = new Map<string, Pending>();
  dead: string | null = null;
  constructor(
    readonly id: number,
    data: Record<string, unknown>
  ) {
    this.worker = new Worker(WORKER_BOOT, { workerData: { ...data, __entry: WORKER_ENTRY }, resourceLimits: { maxOldGenerationSizeMb: 4096 } });
    this.worker.on("message", (m: Record<string, unknown>) => {
      const key = `${String(m["type"])}:${String(m["passId"] ?? "")}`;
      if (m["type"] === "error") {
        const err = new Error(`worker ${id}: ${String(m["error"])}`);
        // no pass id (setup failed) or a fatal error (a call outlived its bound): the worker is unusable
        if (m["passId"] === null || m["fatal"] === true) this.dead = String(m["error"]).slice(0, 300);
        for (const [k, p] of [...this.pending]) {
          if (k.endsWith(`:${String(m["passId"] ?? "")}`) || m["passId"] === null) {
            this.pending.delete(k);
            p.reject(err);
          }
        }
        return;
      }
      const p = this.pending.get(key);
      if (p) {
        this.pending.delete(key);
        p.resolve(m);
      }
    });
    const fail = (why: string) => {
      this.dead = why;
      for (const p of this.pending.values()) p.reject(new Error(`worker ${id} ${why}`));
      this.pending.clear();
    };
    this.worker.on("error", (e) => fail(`error: ${sanitize(e.message)}`));
    this.worker.on("exit", (code) => fail(`exited with code ${code}`));
  }
  waitFor(type: string, passId: string, timeoutMs: number): Promise<Record<string, unknown>> {
    if (this.dead) return Promise.reject(new Error(`worker ${this.id} is dead: ${this.dead}`));
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        this.pending.delete(`${type}:${passId}`);
        reject(new Error(`worker ${this.id}: no ${type} for ${passId} within ${timeoutMs} ms`));
      }, timeoutMs);
      this.pending.set(`${type}:${passId}`, {
        resolve: (m) => {
          clearTimeout(t);
          resolve(m);
        },
        reject: (e) => {
          clearTimeout(t);
          reject(e);
        },
      });
    });
  }
}

// ------------------------------------------------------------------ main

interface PoolItem {
  request: ProofRequestV4;
  reply: SessionReplyV4;
  wire: Buffer;
  presentation: PresentationV4;
  keys: SessionKeys;
}

function levelsFrom(argv: readonly string[], smoke: boolean): LoadLevels {
  const base: LoadLevels = smoke ? { ...SMOKE_LEVELS, workers: [...SMOKE_LEVELS.workers], conc: [...SMOKE_LEVELS.conc], variants: [...SMOKE_LEVELS.variants] } : { ...FULL_LEVELS, workers: [...FULL_LEVELS.workers], conc: [...FULL_LEVELS.conc], variants: [...FULL_LEVELS.variants] };
  const overrides = ["p", "h", "r", "workers", "conc", "hostile-n", "blocks", "settle-sec", "saturation-cap", "timeout-ms"].filter((k) => opt(argv, k) !== undefined);
  if (!smoke && overrides.length > 0) throw new Error(`levels are pre-registered (docs/v4/ROBUSTNESS.md section 3.4); --${overrides.join(", --")} is allowed with --smoke only`);
  const list = (k: string, d: number[]) => (opt(argv, k) ? (opt(argv, k) as string).split(",").map((x) => Number(x)) : d);
  const L: LoadLevels = {
    ...base,
    P: optNum(argv, "p", base.P),
    H: optNum(argv, "h", base.H),
    R: optNum(argv, "r", base.R),
    workers: list("workers", base.workers),
    conc: list("conc", base.conc),
    hostileN: optNum(argv, "hostile-n", base.hostileN),
    measuredBlocks: optNum(argv, "blocks", base.measuredBlocks),
    settleSec: optNum(argv, "settle-sec", base.settleSec),
    saturationCap: optNum(argv, "saturation-cap", base.saturationCap),
    timeoutMs: optNum(argv, "timeout-ms", base.timeoutMs),
  };
  if (L.R > L.P || L.hostileN > L.P) throw new Error("R and hostileN must not exceed P");
  if (freeIndices(L).length === 0) throw new Error("the pool needs at least one reply outside every worker's correctness batch (HC5 and the first verification use it)");
  return L;
}

/** Count of each failedChecks set (joined with "+"). */
function bump(rec: Record<string, number>, checks: readonly string[]): void {
  const k = checks.length ? [...checks].join("+") : "none (exception or accepted)";
  rec[k] = (rec[k] ?? 0) + 1;
}

async function main(argv: string[]): Promise<number> {
  const smoke = flag(argv, "smoke");
  const campaign = opt(argv, "campaign") ?? (smoke ? "smoke" : undefined);
  if (!campaign || !/^[A-Za-z0-9_.-]{1,64}$/.test(campaign)) throw new Error("--campaign <name> is required (letters, digits, _ . -)");
  const levels = levelsFrom(argv, smoke);
  const fault = opt(argv, "inject-fault") ?? null;
  if (fault !== null && (!smoke || fault !== "worker-exit")) throw new Error("--inject-fault worker-exit is a smoke-only check of the error-block path");
  const port = optNum(argv, "port", PORTS.loadTest);
  if (!smoke && port !== PORTS.loadTest) throw new Error(`the load test uses port ${PORTS.loadTest} (DECISIONS D-034)`);
  const root = path.join(robustnessRoot(smoke), "load", campaign);
  if (fs.existsSync(path.join(root, "schedule.json"))) throw new Error(`${rel(root)} already holds a campaign; no resume (choose a new --campaign name)`);
  const robustnessSha = protocolRecord(smoke);
  const commit = assertCommitted(smoke);
  const toolchain = checkToolchain(smoke);
  const roots = markerRoots({ ...(windowsRepoFromArgs(argv) ? { windowsRepo: windowsRepoFromArgs(argv) as string } : {}), allowLocalOnlyInWsl: smoke });
  let release: () => void = () => undefined;
  let markerRecord: unknown = "none (smoke run; markers checked free; no RUNNING marker)";
  if (smoke) assertMarkersFree(roots, "RUNNING");
  else {
    const h = acquireMarker({ kind: "RUNNING", campaign: `robustness/load/${campaign}`, runner: "harness/v4/robustness/load.ts", owner: "operator", roots });
    release = () => h.release();
    markerRecord = { held: h.record, copies: h.copies };
  }
  const pins = JSON.parse(fs.readFileSync(PINS_V4, "utf8")) as Record<string, { sha256: string }>;
  const vkeySha = sha256FileHex(VKEY_V4);
  if (vkeySha !== pins["v4/verification_key_dev.json"]?.sha256) throw new Error("setup/out/v4/verification_key_dev.json differs from its pin in setup/pins_v4.json");

  let anvil: AnvilHandle | null = null;
  let world: World | null = null;
  const workers: WorkerHandle[] = [];
  const stopWorkers = async () => {
    for (const h of workers) {
      try {
        h.worker.postMessage({ type: "stop" });
      } catch {
        /* already gone */
      }
    }
    await sleep(200);
    for (const h of workers) await h.worker.terminate().catch(() => undefined);
  };
  try {
    fs.mkdirSync(path.join(root, "inputs"), { recursive: true });
    await assertPortFree(port);
    log(`Anvil on 127.0.0.1:${port}`);
    anvil = await startAnvil(port);
    const anvilPid = anvil.proc.pid ?? null;
    world = await worldOnRpc(anvil.rpcUrl);
    log(`world: issuer, ${levels.H} holders, epoch, verifier`);
    const issuer = await world.addIssuer("load-issuer");
    const holders: HolderWalletV4[] = [];
    for (let h = 0; h < levels.H; h++) {
      const w = await world.addHolder();
      await world.issue(issuer, w, { birthDate: 19900101 + h });
      holders.push(w);
    }
    await world.publishEpoch(issuer);
    const V: VerifierV4 = await world.addVerifier("load-verifier");
    const kemPk = V.opts.identity.kem.publicKey;
    const chainId = await world.ledger.chainId();

    // ---- pool (untimed): honest replies, with each session's secrets captured in memory
    log(`pool: ${levels.P} honest replies (proving, untimed)`);
    const tPool = process.hrtime.bigint();
    const pool: PoolItem[] = [];
    const c = nodeCrypto as unknown as Record<string, unknown>;
    const orig = c["encapsulate"] as (key: unknown) => { sharedKey: Buffer; ciphertext: Buffer };
    let captured: { ss: Buffer; ct: Buffer } | null = null;
    c["encapsulate"] = (key: unknown) => {
      const r = orig(key);
      captured = { ss: Buffer.from(r.sharedKey), ct: Buffer.from(r.ciphertext) };
      return r;
    };
    try {
      for (let i = 0; i < levels.P; i++) {
        captured = null;
        const request = await V.newRequest(POLICY);
        const { reply, presentation } = await (holders[i % levels.H] as HolderWalletV4).present(request);
        const cap = captured as { ss: Buffer; ct: Buffer } | null;
        if (!cap || !cap.ct.equals(Buffer.from(reply.ct, "hex"))) throw new Error("could not capture the session secret of a presentation");
        const transcript = transcriptHash(request, kemPk, cap.ct);
        const s = deriveSessionSecrets(cap.ss, transcript);
        cap.ss.fill(0);
        pool.push({ request, reply, wire: wire(reply), presentation, keys: { sessionId: request.sessionId, ct: cap.ct, key: s.key, iv: s.iv, transcript } });
        if ((i + 1) % 25 === 0 || i + 1 === levels.P) log(`pool: ${i + 1}/${levels.P}`);
      }
    } finally {
      c["encapsulate"] = orig;
    }
    const poolMs = Number(process.hrtime.bigint() - tPool) / 1e6;

    // ---- hostile replies (untimed): harness-owned sessions (HC3, HC4, HC6, HC7), HC5 in honest sessions outside the correctness batch
    const rngH = new Rng(SEED).fork("hostile");
    const free = freeIndices(levels);
    const harnessSessions: SessionKeys[] = [];
    const needSessions = 2 * levels.hostileN + 2 * levels.hostileLargeDistinct;
    for (let i = 0; i < needSessions; i++) {
      const req = await V.newRequest(POLICY);
      const ws = walletOpenSession(req, kemPk);
      harnessSessions.push({ sessionId: req.sessionId, ct: ws.ciphertext, key: ws.key, iv: ws.iv, transcript: ws.transcript });
    }
    let nextSession = 0;
    const newSession = () => {
      const s = harnessSessions[nextSession++];
      if (!s) throw new Error("ran out of harness sessions");
      return s;
    };
    const hostile: Record<string, HostileItem[]> = {};
    for (const cls of HOSTILE_CLASSES) {
      if (cls === "HC0") continue;
      hostile[cls] = buildHostile(cls, levels.hostileN, levels.hostileLargeDistinct, {
        rng: rngH,
        newSession,
        presentations: pool.map((p) => p.presentation),
        honestWires: pool.map((p) => p.wire),
        honestKeys: pool.map((p) => p.keys),
        hc5Indices: free,
      });
    }
    // correctness: hostile variants sealed into honest pool sessions (targets), then the honest reply must still be accepted
    const Wmax = Math.max(...levels.workers);
    const corrItems: Array<{ worker: number; target: number; kind: string; wire: Buffer }> = [];
    for (let w = 0; w < Wmax; w++) {
      for (const t of correctnessIndices(levels, w).targets) {
        const it = pool[t] as PoolItem;
        const other = pool[(t + 1) % levels.P] as PoolItem;
        const r = rngH.fork(`corr:${w}:${t}`);
        corrItems.push({ worker: w, target: t, kind: "HC3-on-session", wire: tamperedBox(it.keys, it.presentation, r) });
        corrItems.push({ worker: w, target: t, kind: "HC4-on-session", wire: wrongNonce(it.keys, other.presentation) });
        corrItems.push({ worker: w, target: t, kind: "HC5-on-session", wire: garbageProof(it.keys, it.presentation, r) });
        corrItems.push({ worker: w, target: t, kind: "noncanonical-on-session", wire: prettyPrinted(it.keys, it.presentation) });
      }
    }

    // ---- pre-pass (untimed): every honest reply accepted; every hostile reply rejected with exactly its class's failedChecks set
    const snap = snapshotSessions(V.sessions);
    log("pre-pass: every honest reply must be accepted, every hostile reply rejected with its expected checks");
    for (const [i, p] of pool.entries()) {
      const d = await V.verifyReply(p.wire as unknown as SessionReplyV4);
      if (!d.accepted) throw new Error(`pre-pass: honest reply ${i} rejected: ${d.reasons.join("; ")}`);
    }
    restoreSessions(V.sessions, snap);
    const prePassHostile: Record<string, Record<string, number>> = {};
    const mismatches: string[] = [];
    for (const [cls, items] of Object.entries(hostile)) {
      const want = HOSTILE_EXPECTED_CHECKS[cls as Exclude<HostileClass, "HC0">];
      const seen = new Set<Buffer>();
      for (const it of items) {
        if (seen.has(it.wire)) continue;
        seen.add(it.wire);
        const d = await V.verifyReply(it.wire as unknown as SessionReplyV4);
        prePassHostile[cls] ??= {};
        bump(prePassHostile[cls] as Record<string, number>, d.failedChecks);
        if (d.accepted) throw new Error(`pre-pass: a hostile reply of ${cls} was accepted`);
        if (!sameCheckSet(d.failedChecks, want)) mismatches.push(`${cls}: failedChecks [${d.failedChecks.join(", ")}], expected [${want.join(", ")}] (${(d.reasons[0] ?? "").slice(0, 160)})`);
      }
    }
    const prePassCorr: Record<string, Record<string, number>> = {};
    for (const it of corrItems) {
      const d = await V.verifyReply(it.wire as unknown as SessionReplyV4);
      prePassCorr[it.kind] ??= {};
      bump(prePassCorr[it.kind] as Record<string, number>, d.failedChecks);
      if (d.accepted) throw new Error(`pre-pass: correctness item ${it.kind} was accepted`);
      const want = CORRECTNESS_EXPECTED_CHECKS[it.kind] ?? [];
      if (!sameCheckSet(d.failedChecks, want)) mismatches.push(`${it.kind}: failedChecks [${d.failedChecks.join(", ")}], expected [${want.join(", ")}]`);
    }
    // every honest reply is still accepted after the hostile pre-pass (rejected replies consume nothing)
    for (const [i, p] of pool.entries()) {
      const d = await V.verifyReply(p.wire as unknown as SessionReplyV4);
      if (!d.accepted) mismatches.push(`honest reply ${i} rejected after the hostile pre-pass: ${d.failedChecks.join(", ")}`);
    }
    restoreSessions(V.sessions, snap);

    // ---- inputs (public data only: no keys, no session secrets)
    writeJson(path.join(root, "inputs", "pool.json"), {
      schema: "pqid/v4-load-pool/v1",
      P: levels.P,
      H: levels.H,
      holders: holders.map((_, h) => ({ index: h, birthDate: 19900101 + h, note: "synthetic test holder (fixture)" })),
      policy: POLICY,
      generationMs: Math.round(poolMs),
      generationNote: "untimed setup (proving); not a result",
      replies: pool.map((p, i) => ({ index: i, sessionId: p.request.sessionId, replySha256: sha256(p.wire), presentationSha256: sha256(canonicalJsonBytes(p.presentation)), publicSignals: p.presentation.publicSignals })),
      freeIndices: free,
      note: "the verifier's KEM private key and the session keys lived in memory only, so the reply bytes cannot be replayed after the run; reproducibility comes from the script, the seed and these hashes",
    });
    fs.writeFileSync(path.join(root, "inputs", "presentations.jsonl"), pool.map((p) => JSON.stringify(p.presentation)).join("\n") + "\n");
    writeJson(path.join(root, "inputs", "hostile.json"), {
      schema: "pqid/v4-load-hostile/v2",
      classes: Object.fromEntries(HOSTILE_CLASSES.map((cls) => [cls, HOSTILE_DESCRIPTIONS[cls]])),
      expectedFailedChecks: HOSTILE_EXPECTED_CHECKS,
      expectedOutcome: Object.fromEntries(HOSTILE_CLASSES.map((cls) => [cls, expectedOutcome(cls)])),
      perClass: Object.fromEntries(
        Object.entries(hostile).map(([cls, items]) => {
          const distinct = [...new Set(items)];
          return [cls, { items: items.length, distinct: distinct.length, wireBytes: distinct.map((x) => x.wire.length), sha256: distinct.map((x) => sha256(x.wire)), notes: distinct.map((x) => x.note) }];
        })
      ),
      correctness: corrItems.map((x) => ({ worker: x.worker, target: x.target, kind: x.kind, sha256: sha256(x.wire), wireBytes: x.wire.length })),
      correctnessExpectedFailedChecks: CORRECTNESS_EXPECTED_CHECKS,
      prePassFailedChecks: prePassHostile,
      prePassCorrectnessFailedChecks: prePassCorr,
      prePassMismatches: mismatches,
    });
    if (mismatches.length > 0) throw new Error(`pre-pass: ${mismatches.length} hostile or correctness item(s) failed at other checks than registered (inputs/hostile.json prePassMismatches); first: ${mismatches[0]}`);

    // ---- schedule (written before the first block)
    const schedule = buildLoadSchedule(levels, SEED);
    const cells = new Map(cellsOf(levels).map((x) => [x.id, x]));
    writeJson(path.join(root, "schedule.json"), {
      schema: "pqid/v4-load-schedule/v1",
      campaign,
      smoke,
      seed: SEED,
      seedId: "robustness.load (DECISIONS D-034)",
      levels,
      cells: [...cells.values()],
      blocks: schedule,
      createdUtc: utcNow(),
    });
    writeJson(path.join(root, "env.json"), {
      schema: "pqid/v4-load-env/v2",
      name: "verifier library under concurrent load",
      campaign,
      smoke,
      env: envInfo(),
      runtime: { node: process.version, openssl: process.versions.openssl ?? null, v8: process.versions.v8 ?? null, ethers: ETHERS_VERSION, snarkjs: snarkjsVersion(), anvil: toolchain.anvil },
      toolchain,
      gitHead: gitHead(),
      commit,
      protocol: { benchProtocol: protocolSha(), robustness: robustnessSha },
      harnessSha256: shaOf(harnessFiles()),
      sourceSha256: shaOf(sourceFiles()),
      vkey: { file: rel(VKEY_V4), sha256: vkeySha, pinned: true, keyLabel: "dev" },
      chain: { node: "Anvil, automine, fresh deployment", port, networkLabel: "loopback, same host (D-034)", chainId },
      clients: {
        asShipped: "LedgerV4.connect as committed (ethers 6.13.4 default batching, no staticNetwork), traced for counts (harness/v4/lib/rpc_trace.ts)",
        cachedReads: "harness/v4/scale_lib.ts cachedLedger over a second traced LedgerV4.connect: a harness read cache, variant, not shipped; never verifier capacity",
      },
      roundTripDefinition: ROUND_TRIP_DEFINITION,
      replicas: "each worker thread is an independent verifier replica with its own session store (sticky load balancing); exactly-once across replicas is not modelled",
      pinning: process.platform === "win32" ? "unpinned (D-021)" : "unpinned",
      threadAndAnvilCpu: process.platform === "linux" ? "recorded per pass from /proc" : "not recorded on Windows (host rule D-021)",
      timer: "process.hrtime.bigint() (one monotonic clock for all threads), ms",
      clockGapRule: `a block (or the saturation fill) whose wall-clock and monotonic elapsed times differ by more than ${CLOCK_GAP_LIMIT_MS} ms, or during which the parent's event loop missed its 100 ms tick for more than ${TICK_GAP_LIMIT_MS} ms, is discarded (discarded-clock-gap) and repeated`,
      lateBoundMs: LATE_BOUND_MS,
      injectedFault: fault,
      marker: markerRecord,
      poolGenerationMs: Math.round(poolMs),
    });

    // ---- workers (start untimed)
    const barrier = new SharedArrayBuffer(4);
    const gate = new Int32Array(barrier);
    const sessions = [...(snap as Map<string, unknown>).entries()];
    const idCore = { label: V.opts.identity.label, did: V.opts.identity.did, pk: V.opts.identity.pk, controller: V.opts.identity.controller, origin: V.opts.identity.origin, kemPublic: kemPk, kemPrivate: V.opts.identity.kem.privateKey };
    const small = (cls: string) => (hostile[cls] ?? []).map((x) => x.wire);
    const spawnWorker = (w: number): WorkerHandle =>
      new WorkerHandle(w, {
        workerId: w,
        epochNs: EPOCH_NS.toString(),
        rpcUrl: anvil?.rpcUrl,
        addresses: world?.ledger.addresses,
        fromBlock: 0,
        chainId,
        governancePk: world?.governance.pk,
        identity: idCore,
        clockSec: world?.clock.nowSec(),
        sessions,
        pool: pool.map((p) => p.wire),
        // every worker: the small classes and one item of each large class (correctness batch); worker 0: all (hostile-cost cells)
        hostile: Object.fromEntries(Object.keys(hostile).map((cls) => [cls, w === 0 || !["HC6", "HC7"].includes(cls) ? [...new Set(small(cls))] : small(cls).slice(0, 1)])),
        corr: corrItems.map((x) => x.wire),
        barrier,
      });
    log(`workers: starting ${Wmax} (untimed)`);
    for (let w = 0; w < Wmax; w++) workers.push(spawnWorker(w));
    await Promise.all(workers.map((h) => h.waitFor("ready", "", 120_000)));
    // the hostile arrays the workers hold were de-duplicated: map class item j to index j mod distinct
    const distinctCount = (w: number, cls: string) => (w === 0 || !["HC6", "HC7"].includes(cls) ? new Set(small(cls)).size : 1);
    // session ids of the correctness batch's hostile items (HC3 to HC7 item 0): each must stay open
    const hostileSessionIds = ["HC3", "HC4", "HC5", "HC6", "HC7"].map((cls) => hostile[cls]?.[0]?.sessionId ?? null).filter((x): x is string => x !== null);

    let passSeq = 0;
    // ---- each worker's first verification (aux, untimed setup step whose time is recorded once): one at a time
    const aux: { schema: string; firstVerificationInWorker: Record<string, unknown>; replacements: unknown[]; note: string } = {
      schema: "pqid/v4-load-aux/v1",
      firstVerificationInWorker: {},
      replacements: [],
      note: "each worker's first verification: one honest reply outside the correctness batch, asShipped, c = 1, workers one at a time before the settle; recorded once, never analysed as a series, never compared with Phase D cold",
    };
    const firstVerification = async (w: number): Promise<Record<string, unknown>> => {
      const passId = `f${++passSeq}`;
      const ref = ["pool", free[w % free.length] as number];
      const p = (workers[w] as WorkerHandle).waitFor("result", passId, levels.timeoutMs + LATE_BOUND_MS + 60_000);
      (workers[w] as WorkerHandle).worker.postMessage({ type: "first", passId, ref, timeoutMs: levels.timeoutMs, lateBoundMs: LATE_BOUND_MS });
      const r = await p;
      return { ...(r["result"] as Record<string, unknown>), poolIndex: ref[1], utc: utcNow() };
    };
    for (let w = 0; w < Wmax; w++) aux.firstVerificationInWorker[String(w)] = await firstVerification(w);
    writeJson(path.join(root, AUX_FILE), aux);

    log(`settle ${levels.settleSec} s`);
    await sleep(levels.settleSec * 1000);

    // ---- blocks
    let gen = 0;
    const runPass = async (
      active: number[],
      build: (w: number, passId: string, gen: number) => Record<string, unknown>,
      items: number,
      lanes: number
    ): Promise<{ releaseMs: number; results: Array<Record<string, unknown>>; clock: ClockRecord }> => {
      const myGen = ++gen;
      const passId = `p${++passSeq}`;
      const waitMs = (Math.ceil(items / Math.max(1, lanes)) + 2) * levels.timeoutMs + LATE_BOUND_MS + 60_000;
      const watch = new ClockWatch(EPOCH_NS);
      let clock: ClockRecord | null = null;
      const armed = active.map((w) => (workers[w] as WorkerHandle).waitFor("armed", passId, 120_000));
      const results = active.map((w) => (workers[w] as WorkerHandle).waitFor("result", passId, waitMs));
      // a pass abandoned on the first failure leaves the other promises to settle later: never unhandled
      for (const p of [...armed, ...results]) p.catch(() => undefined);
      let releaseNs = process.hrtime.bigint();
      try {
        try {
          for (const w of active) (workers[w] as WorkerHandle).worker.postMessage(build(w, passId, myGen));
          await Promise.all(armed);
        } finally {
          // release even when arming failed, so no armed worker stays blocked on the barrier
          releaseNs = process.hrtime.bigint();
          Atomics.store(gate, 0, myGen);
          Atomics.notify(gate, 0);
        }
        const res = await Promise.all(results);
        clock = watch.stop();
        return { releaseMs: msOf(releaseNs), results: res, clock };
      } finally {
        if (!clock) watch.stop();
      }
    };

    /** After an error block: every live worker answers a ping queued behind its current work; the rest are replaced. */
    const drainWorkers = async (): Promise<number[]> => {
      const bad: number[] = [];
      await Promise.all(
        workers.map(async (h, w) => {
          if (h.dead) {
            bad.push(w);
            return;
          }
          const passId = `ping${++passSeq}`;
          const p = h.waitFor("pong", passId, 120_000);
          try {
            h.worker.postMessage({ type: "ping", passId });
            await p;
          } catch {
            bad.push(w);
          }
        })
      );
      bad.sort((a, b) => a - b);
      for (const w of bad) {
        log(`worker ${w}: ${(workers[w] as WorkerHandle).dead ?? "no answer to a drain ping within 120 s"}; replacing it`);
        await (workers[w] as WorkerHandle).worker.terminate().catch(() => undefined);
        workers[w] = spawnWorker(w);
        await (workers[w] as WorkerHandle).waitFor("ready", "", 120_000);
      }
      return bad;
    };

    /** A replaced worker: first verification, then one untimed-for-analysis pass per variant of R items at c = 1 (blocks.jsonl, never analysed). */
    const replacementWarmup = async (w: number, afterBlock: number, afterAttempt: number): Promise<void> => {
      const first = await firstVerification(w);
      aux.replacements.push({ worker: w, afterBlock, afterAttempt, firstVerification: first });
      writeJson(path.join(root, AUX_FILE), aux);
      for (const variant of levels.variants) {
        const refs = rotation(levels.P, levels.R, 0).map((i) => ["pool", i]);
        const { results, clock } = await runPass([w], (_w, passId, g) => ({ type: "pass", passId, gen: g, variant, lanes: 1, refs, timeoutMs: levels.timeoutMs, lateBoundMs: LATE_BOUND_MS }), refs.length, 1);
        const rr = (results[0] as Record<string, unknown>)["result"] as { latMs: number[]; outcomes: string[] };
        appendJsonl(path.join(root, "blocks.jsonl"), {
          record: "replacementWarmup",
          worker: w,
          afterBlock,
          afterAttempt,
          variant,
          items: rr.outcomes.length,
          accepted: rr.outcomes.filter((o) => o === "accepted").length,
          latMs: rr.latMs,
          clock,
          analysed: false,
          utc: utcNow(),
        });
      }
    };

    const quietReading = async (what: string): Promise<{ quiet: QuiesceRecord; postponed: number }> => {
      let quiet = await readQuiesceExcluding({ ownPids: anvilPid ? [anvilPid] : [], ownPorts: [port] });
      let postponed = 0;
      while (!smoke && !quiet.quiesced && postponed < 10) {
        postponed++;
        log(`${what}: machine busy (${quiet.reasons.join("; ")}); postponing 60 s (${postponed}/10)`);
        await sleep(60_000);
        quiet = await readQuiesceExcluding({ ownPids: anvilPid ? [anvilPid] : [], ownPorts: [port] });
      }
      return { quiet, postponed };
    };

    let nonAcRun = 0;
    let errorBlocks = 0;
    let replacedBefore: number[] = [];
    const blockQueue: Array<ScheduledBlock & { attempt: number }> = schedule.map((b) => ({ ...b, attempt: 0 }));
    while (blockQueue.length > 0) {
      const sb = blockQueue[0] as ScheduledBlock & { attempt: number };
      // power and quiet machine before the block
      const pre: PowerReading = readPower();
      if (!pre.ac && !smoke) {
        nonAcRun++;
        appendJsonl(path.join(root, "blocks.jsonl"), { record: "block", block: sb.block, attempt: sb.attempt, status: "postponed-battery", power: pre, utc: utcNow() });
        if (nonAcRun >= 36) throw new Error("36 consecutive non-AC power readings: campaign stopped (rerun under a new name)");
        await sleep(60_000);
        continue;
      }
      nonAcRun = 0;
      const { quiet, postponed } = await quietReading(`block ${sb.block}`);
      log(`block ${sb.block}${sb.measured ? "" : " (warm-up)"} attempt ${sb.attempt}: ${sb.order.length} cells`);
      let injected: string | null = null;
      if (fault === "worker-exit" && sb.block === 1 && sb.attempt === 0) {
        injected = `worker ${Wmax - 1} told to exit (smoke fault injection)`;
        log(injected);
        (workers[Wmax - 1] as WorkerHandle).worker.postMessage({ type: "exit" });
        await sleep(500);
      }
      const buffered: Array<[string, unknown]> = [];
      let blockError: string | null = null;
      const tBlock = utcNow();
      const blockWatch = new ClockWatch(EPOCH_NS);
      for (const cellId of sb.order) {
        const cell = cells.get(cellId) as Cell;
        const head = { block: sb.block, attempt: sb.attempt, measured: sb.measured, cell: cell.id, kind: cell.kind, variant: cell.variant, W: cell.W, c: cell.c };
        const threads0 = linuxThreads(process.pid);
        const anvilTicks0 = anvilPid ? linuxCpuTicks(anvilPid) : null;
        try {
          if (cell.kind === "throughput") {
            const active = Array.from({ length: cell.W }, (_, w) => w);
            const { releaseMs, results, clock } = await runPass(
              active,
              (w, passId, g) => ({ type: "pass", passId, gen: g, variant: cell.variant, lanes: cell.c, refs: rotation(levels.P, levels.R, sb.offsets[w] as number).map((i) => ["pool", i]), timeoutMs: levels.timeoutMs, lateBoundMs: LATE_BOUND_MS }),
              levels.R,
              cell.c
            );
            const ends = results.flatMap((r) => (r["result"] as { endMs: number[] }).endMs);
            const rates = passRates(ends, releaseMs);
            for (const r of results) {
              const rr = r["result"] as { latMs: number[]; startMs: number[]; endMs: number[]; outcomes: string[]; errors: unknown[]; rpc: { posts: number; requests: number } };
              buffered.push(["runs.jsonl", { type: "worker", ...head, worker: r["workerId"], R: levels.R, latMs: rr.latMs, startMs: rr.startMs, endMs: rr.endMs, outcomes: rr.outcomes, expected: "accepted", errors: rr.errors, rpc: rr.rpc, loop: r["loop"], lateSettled: r["lateSettled"] }]);
            }
            buffered.push(["runs.jsonl", { type: "pass", ...head, releaseMs: r3(releaseMs), completions: ends.length, ...Object.fromEntries(Object.entries(rates).map(([k, v]) => [k, v === null ? null : r3(v)])), clock, threads: { before: threads0, after: linuxThreads(process.pid) }, anvilCpuTicks: anvilTicks0 !== null && anvilPid ? (linuxCpuTicks(anvilPid) ?? 0) - anvilTicks0 : null }]);
          } else if (cell.kind === "hostile") {
            const cls = cell.cls;
            const refs = cls === "HC0" ? rotation(levels.P, levels.hostileN, sb.offsets[0] as number).map((i) => ["pool", i]) : Array.from({ length: levels.hostileN }, (_, j) => ["hostile", cls, j % distinctCount(0, cls)]);
            const { releaseMs, results, clock } = await runPass([0], (_w, passId, g) => ({ type: "pass", passId, gen: g, variant: cell.variant, lanes: 1, refs, timeoutMs: levels.timeoutMs, lateBoundMs: LATE_BOUND_MS }), refs.length, 1);
            const r = results[0] as Record<string, unknown>;
            const rr = r["result"] as { latMs: number[]; outcomes: string[]; errors: unknown[]; rpc: { posts: number; requests: number } };
            buffered.push(["hostile.jsonl", { ...head, cls, description: HOSTILE_DESCRIPTIONS[cls], expected: expectedOutcome(cls), releaseMs: r3(releaseMs), latMs: rr.latMs, outcomes: rr.outcomes, errors: rr.errors, rpc: rr.rpc, items: refs.length, loop: r["loop"], lateSettled: r["lateSettled"], clock }]);
          } else {
            const active = Array.from({ length: cell.W }, (_, w) => w);
            const plan = new Map<number, { phaseA: unknown[]; expectA: string[]; phaseB: unknown[]; checkSessions: string[]; targetSessions: number }>();
            const rngC = new Rng(SEED).fork(`corr:${sb.block}:${sb.attempt}`);
            for (const w of active) {
              const ix = correctnessIndices(levels, w);
              const units: Array<{ refs: unknown[]; expect: string[] }> = [];
              for (const h of ix.honest) units.push({ refs: [["pool", h]], expect: ["accepted"] });
              ix.dupGroups.forEach((g, gi) => {
                const k = rngC.int(2, 4);
                units.push({ refs: Array.from({ length: k }, () => ["pool", g]), expect: Array.from({ length: k }, () => `dup:${gi}`) });
              });
              for (const cls of ["HC1", "HC2", "HC3", "HC4", "HC5", "HC6", "HC7"]) units.push({ refs: [["hostile", cls, 0]], expect: [`rejected:${cls}`] });
              corrItems.forEach((x, j) => {
                if (x.worker === w) units.push({ refs: [["corr", j]], expect: [`rejected:${x.kind}`] });
              });
              rngC.shuffle(units);
              const targetIds = ix.targets.map((t) => (pool[t] as PoolItem).request.sessionId);
              plan.set(w, {
                phaseA: units.flatMap((u) => u.refs),
                expectA: units.flatMap((u) => u.expect),
                phaseB: ix.targets.map((t) => ["pool", t]),
                // every session a rejected reply of phase A names must still be open: the targets and the hostile items' own sessions
                checkSessions: [...targetIds, ...hostileSessionIds],
                targetSessions: targetIds.length,
              });
            }
            const maxItems = Math.max(...[...plan.values()].map((p) => p.phaseA.length + p.phaseB.length));
            const { releaseMs, results, clock } = await runPass(
              active,
              (w, passId, g) => {
                const p = plan.get(w) as { phaseA: unknown[]; phaseB: unknown[]; checkSessions: string[] };
                return { type: "correctness", passId, gen: g, lanes: cell.c, phaseA: p.phaseA, checkSessions: p.checkSessions, phaseB: p.phaseB, timeoutMs: levels.timeoutMs, lateBoundMs: LATE_BOUND_MS };
              },
              maxItems,
              cell.c
            );
            for (const r of results) {
              const w = Number(r["workerId"]);
              const p = plan.get(w) as { expectA: string[]; phaseB: unknown[]; checkSessions: string[]; targetSessions: number };
              const rr = r["result"] as { phaseA: { outcomes: string[]; latMs: number[] }; sessionStatusAfterA: Array<[string, string]>; phaseB: { outcomes: string[]; latMs: number[] } };
              const groups = new Map<string, number>();
              let misclassified = 0;
              rr.phaseA.outcomes.forEach((o, i) => {
                const e = p.expectA[i] as string;
                if (e.startsWith("dup:")) {
                  groups.set(e, (groups.get(e) ?? 0) + (o === "accepted" ? 1 : 0));
                  // a copy that lost must be rejected as a used session (sessionFresh, or sessionKnown once consumed)
                  if (o !== "accepted" && o !== "rejected:sessionFresh" && o !== "rejected:sessionKnown") misclassified++;
                } else if (e === "accepted" ? o !== "accepted" : o === "accepted" || o.startsWith("error:")) misclassified++;
              });
              const honestAfter = rr.phaseB.outcomes.filter((o) => o === "accepted").length;
              misclassified += rr.phaseB.outcomes.length - honestAfter;
              const notOpen = rr.sessionStatusAfterA.filter(([, st]) => st !== "open").length;
              buffered.push([
                "correctness.jsonl",
                {
                  ...head,
                  worker: w,
                  releaseMs: r3(releaseMs),
                  items: rr.phaseA.outcomes.length + rr.phaseB.outcomes.length,
                  expectA: p.expectA,
                  outcomesA: rr.phaseA.outcomes,
                  latMsA: rr.phaseA.latMs,
                  outcomesB: rr.phaseB.outcomes,
                  latMsB: rr.phaseB.latMs,
                  sessionStatusAfterA: rr.sessionStatusAfterA,
                  metrics: {
                    acceptedCopiesPerDuplicateGroup: [...groups.values()],
                    misclassifiedItems: misclassified,
                    sessionsChecked: p.checkSessions.length,
                    targetSessionsChecked: p.targetSessions,
                    sessionsConsumedByRejectedReplies: notOpen,
                    honestAfterHostileAccepted: honestAfter,
                    honestAfterHostileTotal: rr.phaseB.outcomes.length,
                  },
                  required: { acceptedCopiesPerDuplicateGroup: 1, misclassifiedItems: 0, sessionsConsumedByRejectedReplies: 0, honestAfterHostileAccepted: "all" },
                  loop: r["loop"],
                  lateSettled: r["lateSettled"],
                  clock,
                },
              ]);
            }
          }
        } catch (e) {
          blockError = sanitize((e as Error).message).slice(0, 500);
          log(`block ${sb.block}: error in ${cell.id}: ${blockError}`);
          break;
        }
      }
      const blockClock = blockWatch.stop();
      const post = readPower();
      const status = blockError ? "error" : !post.ac && !smoke ? "discarded-battery" : blockClock.clockGap ? "discarded-clock-gap" : "ok";
      for (const [file, rec] of buffered) appendJsonl(path.join(root, file), { ...(rec as Record<string, unknown>), blockStatus: status });
      appendJsonl(path.join(root, "blocks.jsonl"), {
        record: "block",
        block: sb.block,
        attempt: sb.attempt,
        measured: sb.measured,
        status,
        error: blockError,
        startedUtc: tBlock,
        finishedUtc: utcNow(),
        clock: blockClock,
        power: { pre, post },
        quiesce: quiet,
        postponedSteps: postponed,
        flaggedBusy: !quiet.quiesced,
        replacedWorkers: replacedBefore,
        injectedFault: injected,
      });
      replacedBefore = [];
      if (blockClock.clockGap) log(`block ${sb.block}: clock gap (${blockClock.clockGapMs} ms between wall and monotonic time, longest tick gap ${blockClock.maxTickGapMs} ms)`);
      // stop rule (docs/v4/ROBUSTNESS.md 3.13): a warm-up block longer than 15 min stops the campaign
      if (!smoke && !sb.measured && Date.parse(utcNow()) - Date.parse(tBlock) > 15 * 60_000) {
        throw new Error("the warm-up block took more than 15 min (stop rule, docs/v4/ROBUSTNESS.md 3.13): record a deviation before rerunning");
      }
      if (status === "ok") {
        blockQueue.shift();
        continue;
      }
      if (status === "error") {
        errorBlocks++;
        if (errorBlocks >= 3) throw new Error("3 error blocks: campaign stopped (all records kept)");
        // drain: abandoned passes finish (or their worker is replaced) before anything else runs
        const replaced = await drainWorkers();
        for (const w of replaced) await replacementWarmup(w, sb.block, sb.attempt);
        replacedBefore = replaced;
        if (sb.attempt >= 1) {
          blockQueue.shift();
          continue;
        }
      } else await sleep(60_000);
      sb.attempt++;
      if (sb.attempt >= MAX_ATTEMPTS) throw new Error(`block ${sb.block} was not completed in ${MAX_ATTEMPTS} attempts: campaign stopped (all records kept)`);
    }

    // ---- saturation (once, after the blocks; n = 1). The workers are stopped first.
    log("saturation: stopping the workers");
    await stopWorkers();
    workers.length = 0;
    restoreSessions(V.sessions, snap);
    if (levels.saturationCap !== 100_000) {
      const store = new VerifierSessionStore({ nowMs: () => (world as World).clock.nowSec() * 1000, maxSessions: levels.saturationCap });
      replaceSessionStore(V, store);
      restoreSessions(store, snap);
    }
    const satBase = {
      schema: "pqid/v4-load-saturation/v2",
      n: 1,
      label: "single timed run (n = 1): no distribution, no confidence interval",
      cap: levels.saturationCap,
      capIsPackageDefault: levels.saturationCap === 100_000,
      workersStoppedBefore: true,
    };
    const satPower = readPower();
    if (!satPower.ac && !smoke) {
      writeJson(path.join(root, "saturation.json"), { ...satBase, status: "discarded-battery", power: { pre: satPower }, note: "not timed: the machine was not on AC power after the blocks" });
      log("saturation: skipped (not on AC power)");
      log(`done: ${rel(root)}`);
      return 0;
    }
    const satQuiet = await quietReading("saturation");
    log(`saturation: newRequest until the session cap (${levels.saturationCap})`);
    const gc = gcFn();
    gc?.();
    const m0 = process.memoryUsage();
    const startSize = V.sessions.size;
    let opened = 0;
    let capError: string | null = null;
    const satWatch = new ClockWatch(EPOCH_NS);
    const t0 = process.hrtime.bigint();
    for (;;) {
      try {
        await V.newRequest(POLICY);
        opened++;
      } catch (e) {
        capError = sanitize((e as Error).message);
        break;
      }
      if (opened > levels.saturationCap + 10) break;
    }
    const fillMs = Number(process.hrtime.bigint() - t0) / 1e6;
    const satClock = satWatch.stop();
    const satPowerPost = readPower();
    gc?.();
    const m1 = process.memoryUsage();
    const sizeFull = V.sessions.size;
    const early = await V.verifyReply((pool[0] as PoolItem).wire as unknown as SessionReplyV4);
    let afterConsume: string;
    try {
      await V.newRequest(POLICY);
      afterConsume = "opened (the accepted reply freed one slot)";
    } catch (e) {
      afterConsume = `refused: ${sanitize((e as Error).message)}`;
    }
    let refusedAgain: string | null = null;
    try {
      await V.newRequest(POLICY);
    } catch (e) {
      refusedAgain = sanitize((e as Error).message);
    }
    world.clock.set(world.clock.nowSec() + SESSION_TTL_MS / 1000 + 1);
    let afterTtl: string;
    try {
      await V.newRequest(POLICY);
      afterTtl = `opened; store size now ${V.sessions.size} (expired sessions evicted)`;
    } catch (e) {
      afterTtl = `refused: ${sanitize((e as Error).message)}`;
    }
    const mib = (x: number) => Math.round((x / 2 ** 20) * 100) / 100;
    const satStatus = !satPowerPost.ac && !smoke ? "discarded-battery" : satClock.clockGap ? "discarded-clock-gap" : "ok";
    writeJson(path.join(root, "saturation.json"), {
      ...satBase,
      status: satStatus,
      power: { pre: satPower, post: satPowerPost },
      quiesce: satQuiet.quiet,
      postponedSteps: satQuiet.postponed,
      flaggedBusy: !satQuiet.quiet.quiesced,
      clock: satClock,
      storeSizeBefore: startSize,
      opened,
      storeSizeFull: sizeFull,
      fillMs: Math.round(fillMs * 10) / 10,
      fillTimed: "VerifierV4.newRequest calls from the first to the refused one (process.hrtime.bigint())",
      exceptionAtCap: capError,
      memory: {
        gcBeforeReads: gc !== null,
        heapUsedDeltaMiB: mib(m1.heapUsed - m0.heapUsed),
        rssDeltaMiB: mib(m1.rss - m0.rss),
        heapUsedBytesPerSession: opened > 0 ? Math.round((m1.heapUsed - m0.heapUsed) / opened) : null,
        note: "approximate: whole-process memory before and after the fill",
      },
      sessionOpenedBeforeSaturation: { accepted: early.accepted, failedChecks: early.failedChecks },
      openAfterOneConsume: afterConsume,
      openWhenFullAgain: refusedAgain ?? "not refused",
      openAfterTtl: afterTtl,
    });
    log(`done: ${rel(root)}`);
    return 0;
  } finally {
    await stopWorkers();
    try {
      world?.ledger.destroy();
    } catch {
      /* closed */
    }
    anvil?.stop();
    release();
  }
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
