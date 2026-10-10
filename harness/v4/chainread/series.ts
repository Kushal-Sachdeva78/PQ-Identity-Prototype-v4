import path from "node:path";
import http from "node:http";
import { createHash } from "node:crypto";
import type { VerifyDecisionV4 } from "@pqid/v4/verifier";
import { VerifierV4 } from "@pqid/v4/verifier";
import type { HolderWalletV4 } from "@pqid/v4/wallet";
import type { LedgerV4 } from "@pqid/v4/ledger";
import type { ProofRequestV4 } from "@pqid/v4/session";
import { readPower, type PowerReading } from "../bench/guard.ts";
import { mulberry32, shuffle, sleep } from "../bench/lib.ts";
import { SEEDS, SEED_REGISTRY } from "../lib/seeds.ts";
import { readQuiesceExcluding, type QuiesceRecord } from "../lib/quiesce.ts";
import { summarize, connectClientLedger, type PostRecord, type RpcTrace } from "../lib/rpc_trace.ts";
import { cachedLedger, hookPqcCrypto, snapshotSessions, restoreSessions, replaceSessionStore } from "../scale_lib.ts";
import { appendJsonl, appendJsonlGz, errText } from "./io.ts";
import { checkAffinity, PassClock, type AffinityCheck, type ClockRecord } from "./host.ts";
import { ReadPlan, verifierTable, walletTable, SIX_READS, sixRead, type PlanReport, type SixRead } from "./plans.ts";
import { PRESENTATION_VARIANTS, READ_CLIENTS, READSET_VARIANTS, type PresentationVariant, type ReadSetVariant, type ClientName } from "./variants.ts";
import { compareMultisets, multiset, readKeys, stableJson, methodCounts, type Multiset, type WireRequest } from "./wire.ts";
import { RawClient, rpcPayload, type RawTransport, type RpcRequest } from "./raw.ts";
import { agentLikeGlobal, makeClient, type Client, type TargetNode, type TargetWorld, type Pregenerated } from "./target.ts";

/**
 * The five series of the chain-read campaign (docs/v4/CHAINREAD.md):
 *   S1 raw JSON-RPC (no ethers), S2 fresh connection, S3 the six reads and the read set,
 *   S4 verifier (VerifierV4.verifyReply), S5 wallet read phase (checkRequest + checkIssuerData).
 * Every series runs in passes; before a pass: power (wait while not on AC), quiet-machine reading
 * that excludes the run's own chain processes, and (when pinned) the affinity of every thread;
 * after a pass: power (not AC: the pass is written as discarded-battery and repeated, at most
 * 3 times) and the affinity again (a mismatch flags the pass). Records are written at the end of
 * each pass, outside every timed region; a pass that stops (3-error rule, a failure or a signal)
 * is written with status "stopped" before the stop goes on.
 */

export interface RunSizes {
  /** S1 timed rounds, total, and passes. */
  r1: number;
  s1Passes: number;
  /** S2 samples per cell. */
  n2: number;
  s2SpacingMs: number;
  /** S3 timed rounds, total, and passes. */
  r3: number;
  s3Passes: number;
  /** S4 and S5: presentations per pass, passes. */
  p: number;
  passes: number;
  warmupRounds: number;
  warmupPresentations: number;
}

export const FULL_SIZES: RunSizes = Object.freeze({ r1: 300, s1Passes: 3, n2: 30, s2SpacingMs: 2000, r3: 200, s3Passes: 2, p: 200, passes: 3, warmupRounds: 2, warmupPresentations: 5 });
export const SMOKE_SIZES: RunSizes = Object.freeze({ r1: 4, s1Passes: 2, n2: 2, s2SpacingMs: 200, r3: 4, s3Passes: 2, p: 3, passes: 1, warmupRounds: 1, warmupPresentations: 1 });

export interface GuardOptions {
  /** Apply the power rules (wait while not AC; discard a pass that ends off AC). Smoke: record only. */
  enforcePower: boolean;
  powerWaitMs: number;
  maxPowerWaits: number;
  maxPassRepeats: number;
  quiesceWindowMs: number;
  maxSeriesErrors: number;
}

export const FULL_GUARD: GuardOptions = Object.freeze({ enforcePower: true, powerWaitMs: 60_000, maxPowerWaits: 36, maxPassRepeats: 3, quiesceWindowMs: 3000, maxSeriesErrors: 3 });
export const SMOKE_GUARD: GuardOptions = Object.freeze({ enforcePower: false, powerWaitMs: 0, maxPowerWaits: 0, maxPassRepeats: 0, quiesceWindowMs: 300, maxSeriesErrors: 3 });

export interface PinExpectation {
  pid: number;
  role: string;
  cpus: string;
}

/** What the pass guard reads; the defaults read the machine, tests inject stubs. */
export interface GuardIo {
  readPower: () => PowerReading;
  readQuiesce: (o: { ownPids: number[]; ownPorts: number[]; windowMs: number }) => Promise<QuiesceRecord>;
  readAffinity: (pid: number, role: string, cpus: string) => AffinityCheck;
  sleep: (ms: number) => Promise<void>;
  /** Wall clock of the pass clock (Date.now). */
  wallNow: () => number;
}

export const DEFAULT_GUARD_IO: GuardIo = Object.freeze({
  readPower,
  readQuiesce: (o: { ownPids: number[]; ownPorts: number[]; windowMs: number }) => readQuiesceExcluding(o),
  readAffinity: checkAffinity,
  sleep,
  wallNow: () => Date.now(),
});

/** The parts of the run a pass needs (SeriesContext without the chain world). */
export interface PassContext {
  dir: string;
  targetNode: Pick<TargetNode, "name" | "ownPids" | "ownPorts">;
  guard: GuardOptions;
  pins: PinExpectation[] | null;
  log: (s: string) => void;
  io?: GuardIo;
}

export interface SeriesContext extends PassContext {
  targetNode: TargetNode;
  tw: TargetWorld;
  pre: Pregenerated;
  sizes: RunSizes;
  schedule: Schedule;
  refs: References;
}

/**
 * Per series: samples and error records of the kept passes (ok, or stopped), and of the
 * discarded-battery passes apart. The 3-error rule counts the kept passes' errors only; samples
 * of a stopped pass are kept with status "stopped" and never analysed.
 */
export interface SeriesCounts {
  samples: number;
  errors: number;
  discardedSamples: number;
  discardedErrors: number;
  stoppedSamples: number;
}

export function newCounts(): SeriesCounts {
  return { samples: 0, errors: 0, discardedSamples: 0, discardedErrors: 0, stoppedSamples: 0 };
}

export class SeriesStop extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SeriesStop";
  }
}

// ---------------------------------------------------------------------------------------
// schedule
// ---------------------------------------------------------------------------------------

export interface Schedule {
  schema: "pqid/v4-chainread-schedule/v1";
  seeds: Record<string, number>;
  /** What each seed's stream orders here, next to the registry's own wording (harness/v4/lib/seeds.ts). */
  streamUse: Record<string, { seed: number; registryUse: string; usedFor: string }>;
  streams: string;
  warmup: string;
  s1: { cells: string[]; rounds: string[][]; passes: number };
  s2: { cells: string[]; rounds: string[][] };
  s3: { cells: string[]; rounds: string[][]; passes: number };
  s4: { variants: string[]; passes: Array<{ order: number[]; blocks: string[][] }> };
  s5: { variants: string[]; passes: Array<{ order: number[]; blocks: string[][] }> };
}

export const S1_METHODS = ["eth_blockNumber", "eth_chainId", "eth_call_resolve", "eth_getLogs_registered"] as const;
export const S1_TRANSPORTS: readonly RawTransport[] = ["fetch", "httpKeepAlive", "tcpRawNoDelay"];
export function s1CellIds(): string[] {
  const out: string[] = [];
  for (const m of S1_METHODS) for (const t of S1_TRANSPORTS) out.push(`single:${m}:${t}`);
  out.push("array:2:httpKeepAlive", "array:7:httpKeepAlive", "array:14:httpKeepAlive", "concurrent:2:httpPool", "concurrent:7:httpPool");
  return out;
}
export const S2_CELLS = ["raw:httpFresh:eth_call_resolve", "ethers:asShipped:resolveDidRecord", "ethers:staticNetwork:resolveDidRecord"] as const;
export function s3CellIds(): string[] {
  const out: string[] = [];
  for (const c of READ_CLIENTS) for (const r of SIX_READS) out.push(`read:${c}:${r}`);
  for (const rs of READSET_VARIANTS) out.push(`set:${rs.name}`);
  return out;
}

/** What each D-034 chain-read seed orders in this harness (docs/v4/CHAINREAD.md section 9). */
export const STREAM_USE: Readonly<Record<keyof typeof SEEDS.chainRead, string>> = Object.freeze({
  conditionOrder:
    "order of the conditions within every round or block: S1 cell (method x transport) order per round, then S2 cell order per round, then the S4 variant order of every block (pass by pass), then the S5 variant order of every block",
  readOrder: "S3 cell (client x read, and the read sets) order per round",
  verifierPool: "S4 presentation (pre-generated reply) order per pass",
  walletReads: "S5 presentation (wallet request) order per pass",
});

/**
 * Blocked random orders from the D-034 seeds (one mulberry32 stream per seed, drawn in the
 * order written in `streams`). Warm-up rounds and presentations use the canonical order and
 * draw nothing, so the timed schedule does not depend on the warm-up size.
 */
export function buildSchedule(sizes: RunSizes): Schedule {
  const cond = mulberry32(SEEDS.chainRead.conditionOrder);
  const read = mulberry32(SEEDS.chainRead.readOrder);
  const pool = mulberry32(SEEDS.chainRead.verifierPool);
  const wal = mulberry32(SEEDS.chainRead.walletReads);
  const s1cells = s1CellIds();
  const s1rounds = Array.from({ length: sizes.r1 }, () => shuffle([...s1cells], cond));
  const s2cells = [...S2_CELLS];
  const s2rounds = Array.from({ length: sizes.n2 }, () => shuffle([...s2cells], cond));
  const s3cells = s3CellIds();
  const s3rounds = Array.from({ length: sizes.r3 }, () => shuffle([...s3cells], read));
  const ids = PRESENTATION_VARIANTS.map((v) => v.id as string);
  // presentation order from the series' own stream; the variant order of every block from conditionOrder
  const presentationPasses = (orderRng: () => number) =>
    Array.from({ length: sizes.passes }, () => {
      const order = shuffle(
        Array.from({ length: sizes.p }, (_, i) => i),
        orderRng
      );
      const blocks = order.map(() => shuffle([...ids], cond));
      return { order, blocks };
    });
  const s4passes = presentationPasses(pool);
  const s5passes = presentationPasses(wal);
  const registryUse = (id: string) => SEED_REGISTRY.find((e) => e.id === `chainRead.${id}`)?.use ?? "";
  const streamUse = Object.fromEntries(
    (Object.keys(STREAM_USE) as Array<keyof typeof STREAM_USE>).map((k) => [k, { seed: SEEDS.chainRead[k], registryUse: registryUse(k), usedFor: STREAM_USE[k] }])
  );
  return {
    schema: "pqid/v4-chainread-schedule/v1",
    seeds: { ...SEEDS.chainRead, bootstrap: SEEDS.analysis.bootstrap },
    streamUse,
    streams:
      "conditionOrder (20261011): S1 cell order per round, then S2 cell order per round, then the S4 variant order of every block (pass by pass), then the S5 variant order of every block; readOrder (20261012): S3 cell order per round; verifierPool (20261013): S4 presentation order per pass; walletReads (20261014): S5 presentation order per pass. mulberry32 with a Fisher-Yates shuffle from the end (harness/v4/bench/lib.ts).",
    warmup: "S1 and S3: warm-up rounds in the canonical cell order; S4 and S5: warm-up presentations 0..w-1 per variant in the order A to I; S2: none (each sample is a fresh connection)",
    s1: { cells: s1cells, rounds: s1rounds, passes: sizes.s1Passes },
    s2: { cells: s2cells, rounds: s2rounds },
    s3: { cells: s3cells, rounds: s3rounds, passes: sizes.s3Passes },
    s4: { variants: ids, passes: s4passes },
    s5: { variants: ids, passes: s5passes },
  };
}

// ---------------------------------------------------------------------------------------
// passes
// ---------------------------------------------------------------------------------------

export type PassStatus = "ok" | "discarded-battery" | "stopped";

export interface PassRecord {
  series: string;
  pass: number;
  attempt: number;
  status: PassStatus;
  /** Why a pass stopped (status "stopped"), else null. */
  stopReason: string | null;
  startedUtc: string;
  finishedUtc: string;
  powerPre: PowerReading;
  powerWaits: number;
  /** null when the pass stopped on a signal (no reading taken). */
  powerPost: PowerReading | null;
  quiesce: QuiesceRecord;
  affinity: AffinityCheck[] | null;
  /** Affinity of every thread read again after the pass (pinned runs; null when not pinned or stopped). */
  affinityPost: AffinityCheck[] | null;
  /** true when a thread had another mask after the pass: the pass is kept, flagged and counted. */
  affinityMismatchPost: boolean;
  clock: ClockRecord;
  samples: number;
  errors: number;
}

export interface PassSink {
  samples: unknown[];
  posts: unknown[];
  errors: number;
  clock: PassClock;
  /**
   * Write an error record (errors.jsonl) and count it; throws SeriesStop when the errors of the
   * kept passes and of this pass reach the series limit (guard.maxSeriesErrors, 3).
   */
  recordError: (idRec: Record<string, unknown>, problems: string[]) => void;
}

async function prePass(ctx: PassContext, io: GuardIo): Promise<{ power: PowerReading; waits: number; quiesce: QuiesceRecord; affinity: AffinityCheck[] | null }> {
  let power = io.readPower();
  let waits = 0;
  while (ctx.guard.enforcePower && !power.ac) {
    if (waits >= ctx.guard.maxPowerWaits) throw new SeriesStop(`not on AC power after ${waits} waits (code ${power.code}); resume when on AC`);
    ctx.log(`power ${power.code}: not AC, waiting ${ctx.guard.powerWaitMs / 1000} s`);
    await io.sleep(ctx.guard.powerWaitMs);
    waits++;
    power = io.readPower();
  }
  const quiesce = await io.readQuiesce({ ownPids: ctx.targetNode.ownPids, ownPorts: ctx.targetNode.ownPorts, windowMs: ctx.guard.quiesceWindowMs });
  let affinity: AffinityCheck[] | null = null;
  if (ctx.pins) {
    affinity = ctx.pins.map((p) => io.readAffinity(p.pid, p.role, p.cpus));
    const bad = affinity.filter((a) => !a.ok);
    if (bad.length > 0) throw new SeriesStop(`affinity read-back mismatch: ${describeAffinity(bad)}`);
  }
  return { power, waits, quiesce, affinity };
}

function describeAffinity(bad: readonly AffinityCheck[]): string {
  return bad.map((b) => `${b.role} pid ${b.pid}: ${b.error ?? b.mismatches.map((m) => `tid ${m.tid} on ${m.cpus}`).join(", ")}`).join("; ");
}

/** The pass in progress, so a signal handler can write its samples before the process exits. */
let currentPass: { flush: (reason: string) => void } | null = null;

/** Write the samples of the pass in progress with status "stopped" (for a signal handler). No-op when no pass runs. */
export function flushCurrentPass(reason: string): void {
  const c = currentPass;
  currentPass = null;
  c?.flush(reason);
}

/**
 * Run one pass with the power, quiet and affinity rules; `body` fills the sink. A pass that ends
 * off AC is written as discarded-battery and repeated (at most guard.maxPassRepeats times); a
 * pass whose body throws (3-error rule, failure) is written as stopped, then the error goes on.
 */
export async function runPass(
  ctx: PassContext,
  series: string,
  file: string,
  pass: number,
  plannedGapMs: number,
  counts: SeriesCounts,
  body: (sink: PassSink, attempt: number) => Promise<void>
): Promise<void> {
  const io = ctx.io ?? DEFAULT_GUARD_IO;
  for (let attempt = 1; ; attempt++) {
    const pre = await prePass(ctx, io);
    const startedUtc = new Date().toISOString();
    const sink: PassSink = {
      samples: [],
      posts: [],
      errors: 0,
      clock: new PassClock(plannedGapMs, undefined, io.wallNow),
      recordError: (idRec, problems) => {
        sink.errors++;
        appendJsonl(path.join(ctx.dir, "errors.jsonl"), { ...idRec, problems, utc: new Date().toISOString() });
        const n = counts.errors + sink.errors;
        if (n >= ctx.guard.maxSeriesErrors) throw new SeriesStop(`${series}: ${n} errors (rule: ${ctx.guard.maxSeriesErrors} errors stop the campaign); last: ${problems.join("; ")}`);
      },
    };
    let written = false;
    const finish = (status: PassStatus, powerPost: PowerReading | null, stopReason: string | null): void => {
      if (written) return;
      written = true;
      const clock = sink.clock.finish();
      const affinityPost = ctx.pins && status !== "stopped" ? ctx.pins.map((p) => io.readAffinity(p.pid, p.role, p.cpus)) : null;
      const affinityMismatchPost = affinityPost?.some((a) => !a.ok) ?? false;
      const mark = (r: unknown) => (status === "ok" ? r : { ...(r as object), status, sampleStatus: (r as { status?: unknown }).status ?? null });
      const markPost = (p: unknown) => (status === "ok" ? p : { ...(p as object), ...(status === "stopped" ? { stopped: true } : { discarded: true }) });
      appendJsonlGz(path.join(ctx.dir, file), sink.samples.map(mark));
      appendJsonlGz(path.join(ctx.dir, "posts.jsonl.gz"), sink.posts.map(markPost));
      const rec: PassRecord = {
        series,
        pass,
        attempt,
        status,
        stopReason,
        startedUtc,
        finishedUtc: new Date().toISOString(),
        powerPre: pre.power,
        powerWaits: pre.waits,
        powerPost,
        quiesce: pre.quiesce,
        affinity: pre.affinity,
        affinityPost,
        affinityMismatchPost,
        clock,
        samples: sink.samples.length,
        errors: sink.errors,
      };
      appendJsonl(path.join(ctx.dir, "passes.jsonl"), rec);
      if (status === "discarded-battery") {
        counts.discardedSamples += sink.samples.length;
        counts.discardedErrors += sink.errors;
      } else {
        if (status === "stopped") counts.stoppedSamples += sink.samples.length;
        else counts.samples += sink.samples.length;
        counts.errors += sink.errors;
      }
      const flags = [
        pre.quiesce.quiesced ? null : `busy (${pre.quiesce.reasons.join("; ")})`,
        clock.hostPauseSuspected ? `host pause suspected (${clock.reasons.join("; ")})` : null,
        affinityMismatchPost && affinityPost ? `affinity changed during the pass (${describeAffinity(affinityPost.filter((a) => !a.ok))})` : null,
        stopReason ? `stopped: ${stopReason}` : null,
      ].filter(Boolean);
      ctx.log(`${series} pass ${pass} attempt ${attempt}: ${status}, ${sink.samples.length} samples, ${sink.errors} errors${flags.length ? "; " + flags.join("; ") : ""}`);
    };
    currentPass = { flush: (reason) => finish("stopped", null, reason) };
    try {
      await body(sink, attempt);
    } catch (e) {
      currentPass = null;
      finish("stopped", io.readPower(), errText(e));
      throw e;
    }
    currentPass = null;
    const powerPost = io.readPower();
    const discarded = ctx.guard.enforcePower && !powerPost.ac;
    finish(discarded ? "discarded-battery" : "ok", powerPost, null);
    if (!discarded) return;
    if (attempt > ctx.guard.maxPassRepeats) throw new SeriesStop(`${series} pass ${pass}: ended off AC power ${attempt} times`);
  }
}

// ---------------------------------------------------------------------------------------
// shared record helpers
// ---------------------------------------------------------------------------------------

function postLines(series: string, ids: Record<string, unknown>, posts: readonly PostRecord[], t0TraceMs: number): unknown[] {
  return [...posts]
    .sort((a, b) => a.seq - b.seq)
    .map((r, k) => ({
      s: series,
      ...ids,
      k,
      t0: r.tStartMs - t0TraceMs,
      t1: r.tEndMs - t0TraceMs,
      ms: r.ms,
      n: r.size,
      b: r.batch,
      m: r.methods,
      q: r.queueMs,
      d: r.direct,
      ok: r.ok,
      re: r.rpcErrors,
      h: r.http ? { at: r.http.attempts, st: r.http.statuses, ms: r.http.ms, bo: r.http.bytesOut, bi: r.http.bytesIn, cn: r.http.connects ?? null, nc: r.http.newConnection ?? null } : null,
      err: r.error,
    }));
}

/**
 * Math.max(...xs) by a loop: the same value (NaN and -0 included), without passing every element
 * as a call argument (a spread throws a RangeError past about 125,000 elements; fz1 triage).
 */
function maxOfNumbers(xs: readonly number[]): number {
  let m = -Infinity;
  for (const x of xs) m = Math.max(m, x);
  return m;
}

function traceFacts(posts: readonly PostRecord[]) {
  const s = summarize(posts);
  const qs = posts.flatMap((p) => p.queueMs).filter((q): q is number => q !== null);
  return {
    posts: s.posts,
    requests: s.requests,
    byMethod: s.byMethod,
    postsBySize: s.postsBySize,
    batchPosts: s.batchPosts,
    directPosts: s.directPosts,
    failedPosts: s.failedPosts,
    rpcErrors: s.rpcErrors,
    httpAttempts: s.httpAttempts,
    /** New TCP connections opened by the POSTs (per attempt, harness/v4/lib/rpc_trace.ts). */
    tcpConnects: s.connects,
    tcpConnectsUnknown: s.connectsUnknown,
    postMsSum: s.postMs,
    spanMs: s.spanMs,
    depth: s.sequentialDepth,
    maxInFlight: s.maxInFlight,
    queueMsMax: qs.length ? maxOfNumbers(qs) : null,
    queueMsSum: qs.reduce((a, b) => a + b, 0),
    httpMsSum: posts.reduce((a, p) => a + (p.http?.ms ?? 0), 0),
  };
}

const traceMsNow = (trace: RpcTrace) => Number(process.hrtime.bigint() - trace.epochNs) / 1e6;

function outerByMethod(rep: PlanReport): Record<string, number> {
  const o: Record<string, number> = {};
  for (const c of rep.outerCalls) o[c.method] = (o[c.method] ?? 0) + 1;
  return o;
}

function hashOf(x: unknown): string {
  return createHash("sha256").update(stableJson(x)).digest("hex");
}

// ---------------------------------------------------------------------------------------
// references (equivalence rules)
// ---------------------------------------------------------------------------------------

export interface References {
  verifierChecks: string;
  verifierReads: Multiset;
  verifierRequests: WireRequest[];
  walletOutput: string;
  walletReads: Multiset;
  readResults: Record<SixRead, string>;
  readSetReads: Multiset;
}

export interface EquivalenceRow {
  role: "verifier" | "wallet" | "readSet";
  variant: string;
  ok: boolean;
  problems: string[];
  posts: number;
  requests: number;
  depth: number;
  multicall: { aggregates: number; subCalls: number; fallbacks: number } | null;
}

// ---------------------------------------------------------------------------------------
// S4 / S5 runtime
// ---------------------------------------------------------------------------------------

export interface RoleVariant {
  v: PresentationVariant;
  client: Client;
  plan: ReadPlan;
  verifier: VerifierV4 | null;
}

export interface Roles {
  verifier: RoleVariant[];
  wallet: RoleVariant[];
  hooks: ReturnType<typeof hookPqcCrypto>;
  snap: ReturnType<typeof snapshotSessions>;
  /** Per role and variant: client, effective ethers options, label (for env.json). */
  describe: () => Record<string, unknown>;
  close: () => void;
}

/** Build the 9 variants for the verifier and for the wallet (separate client ledgers per role). */
export async function buildRoles(tn: TargetNode, tw: TargetWorld): Promise<Roles> {
  const made: Client[] = [];
  const mk = async (v: PresentationVariant, role: "verifier" | "wallet"): Promise<RoleVariant> => {
    const client = await makeClient(tn.url, tw, v.client, { multicall: v.multicall });
    made.push(client);
    const base: LedgerV4 = v.cached ? cachedLedger(client.ledger).proxy : client.ledger;
    const plan = new ReadPlan(base, v.plan);
    let verifier: VerifierV4 | null = null;
    if (role === "verifier") {
      verifier = new VerifierV4({ ...tw.verifier.opts, ledger: plan.proxy });
      replaceSessionStore(verifier, tw.verifier.sessions);
    }
    return { v, client, plan, verifier };
  };
  const verifier: RoleVariant[] = [];
  const wallet: RoleVariant[] = [];
  for (const v of PRESENTATION_VARIANTS) verifier.push(await mk(v, "verifier"));
  for (const v of PRESENTATION_VARIANTS) wallet.push(await mk(v, "wallet"));
  const hooks = hookPqcCrypto();
  const describeRole = (rvs: RoleVariant[]) =>
    Object.fromEntries(
      rvs.map((rv) => [
        rv.v.id,
        {
          name: rv.v.name,
          label: rv.v.label,
          client: rv.client.name,
          plan: rv.v.plan,
          multicall: rv.v.multicall,
          cached: rv.v.cached,
          ethersOptions: rv.client.options,
          chainIdCheckedAgainstNode: rv.client.chainIdCheckedAgainstNode,
          agent: rv.client.agent,
        },
      ])
    );
  return {
    verifier,
    wallet,
    hooks,
    snap: snapshotSessions(tw.verifier.sessions),
    describe: () => ({ verifier: describeRole(verifier), wallet: describeRole(wallet) }),
    close: () => {
      hooks.uninstall();
      for (const c of made) c.close();
    },
  };
}

export interface PresentationOutcome {
  record: Record<string, unknown>;
  posts: PostRecord[];
  t0: bigint;
  t1: bigint;
  t0TraceMs: number;
  ok: boolean;
  problems: string[];
  reqs: WireRequest[];
  checksJson: string | null;
  walletJson: string | null;
}

export async function runVerifierOnce(ctx: { tw: TargetWorld; pre: Pregenerated }, roles: Roles, rv: RoleVariant, index: number, refs: References | null): Promise<PresentationOutcome> {
  const reply = ctx.pre.replies[index];
  if (!reply || !rv.verifier) throw new Error(`no reply ${index}`);
  restoreSessions(ctx.tw.verifier.sessions, roles.snap);
  rv.client.trace.drain();
  rv.client.capture.reset();
  rv.client.multicall?.reset();
  roles.hooks.reset();
  rv.plan.begin(rv.v.plan === "concurrent" ? verifierTable() : null);
  const wall0 = Date.now();
  const t0TraceMs = traceMsNow(rv.client.trace);
  const t0 = process.hrtime.bigint();
  let d: VerifyDecisionV4 | null = null;
  let thrown: string | null = null;
  try {
    d = await rv.verifier.verifyReply(reply);
  } catch (e) {
    thrown = errText(e);
  }
  const t1 = process.hrtime.bigint();
  const wallMs = Date.now() - wall0;
  const rep = await rv.plan.end();
  const posts = rv.client.trace.drain();
  const reqs = rv.client.capture.take();
  const mc = rv.client.multicall?.stats() ?? null;
  const hk = { ...roles.hooks.stats };
  const totalMs = Number(t1 - t0) / 1e6;
  const tf = traceFacts(posts);
  const problems: string[] = [];
  if (thrown) problems.push(`verifyReply threw: ${thrown}`);
  if (d && !d.accepted) problems.push(`rejected: ${d.reasons.join("; ").slice(0, 300)}`);
  const checksJson = d ? stableJson(d.checks) : null;
  if (refs && checksJson !== refs.verifierChecks) problems.push("check vector differs from the as-shipped reference");
  if (rep.leftOver.length > 0) problems.push(`prefetched reads left over: ${rep.leftOver.join(", ").slice(0, 300)}`);
  if (rep.unplanned.length > 0) problems.push(`unplanned reads in the concurrent plan: ${rep.unplanned.join(", ").slice(0, 300)}`);
  if (tf.failedPosts > 0 || tf.rpcErrors > 0) problems.push(`failed POSTs ${tf.failedPosts}, JSON-RPC errors ${tf.rpcErrors}`);
  if (refs && !rv.v.cached) {
    const cmp = compareMultisets(refs.verifierReads, multiset(readKeys(reqs)));
    if (!cmp.equal) problems.push(`JSON-RPC multiset differs (missing ${cmp.missing.length}, extra ${cmp.extra.length})`);
  }
  if (mc && mc.fallbacks > 0) problems.push(`multicall fallbacks ${mc.fallbacks}`);
  const mlDsaMs = hk.mlDsaVerifyMs + hk.mlDsaImportMs;
  const record = {
    totalMs,
    chainSumMs: rep.chainSumMs,
    chainUnionMs: rep.chainUnionMs,
    mlDsaMs,
    mlDsaVerifyCalls: hk.mlDsaVerifyCalls,
    mlKemMs: hk.mlKemDecapsMs,
    otherMs: totalMs - rep.chainUnionMs - mlDsaMs - hk.mlKemDecapsMs,
    outerCalls: rep.outerCalls.length,
    outerByMethod: outerByMethod(rep),
    prefetched: rep.prefetchConsumed,
    groupsFired: rep.groupsFired,
    ...tf,
    requestsSeen: methodCounts(reqs),
    multicall: mc ? { aggregates: mc.aggregates, subCalls: mc.subCalls, fallbacks: mc.fallbacks, sizes: mc.sizes } : null,
    accepted: d?.accepted ?? false,
    wallMs,
  };
  return { record, posts, t0, t1, t0TraceMs, ok: problems.length === 0, problems, reqs, checksJson, walletJson: null };
}

function walletOutputJson(r1: { kemPk: Buffer }, r2: { statement: unknown; path: unknown; rev: unknown; controller: string }): string {
  return stableJson({ kemPk: r1.kemPk.toString("hex"), statement: r2.statement, path: r2.path, rev: r2.rev, controller: r2.controller });
}

export async function runWalletOnce(ctx: { tw: TargetWorld; pre: Pregenerated }, roles: Roles, rv: RoleVariant, index: number, refs: References | null): Promise<PresentationOutcome> {
  const H = ctx.tw.holders.length;
  const w = ctx.tw.holders[index % H] as HolderWalletV4;
  const req = ctx.pre.walletRequests[index] as ProofRequestV4;
  const held = w.credentials[0];
  if (!req || !held) throw new Error(`no wallet request or credential for ${index}`);
  rv.client.trace.drain();
  rv.client.capture.reset();
  rv.client.multicall?.reset();
  roles.hooks.reset();
  const original = w.cfg.ledger;
  w.cfg.ledger = rv.plan.proxy;
  rv.plan.begin(rv.v.plan === "concurrent" ? walletTable(req.verifierDid) : null);
  const wall0 = Date.now();
  const t0TraceMs = traceMsNow(rv.client.trace);
  const t0 = process.hrtime.bigint();
  let out: string | null = null;
  let thrown: string | null = null;
  try {
    if (rv.v.plan === "concurrent") {
      const [r1, r2] = await Promise.all([w.checkRequest(req), w.checkIssuerData(held)]);
      out = walletOutputJson(r1, r2);
    } else {
      const r1 = await w.checkRequest(req);
      const r2 = await w.checkIssuerData(held);
      out = walletOutputJson(r1, r2);
    }
  } catch (e) {
    thrown = errText(e);
  } finally {
    w.cfg.ledger = original;
  }
  const t1 = process.hrtime.bigint();
  const wallMs = Date.now() - wall0;
  const rep = await rv.plan.end();
  const posts = rv.client.trace.drain();
  const reqs = rv.client.capture.take();
  const mc = rv.client.multicall?.stats() ?? null;
  const hk = { ...roles.hooks.stats };
  const totalMs = Number(t1 - t0) / 1e6;
  const tf = traceFacts(posts);
  const problems: string[] = [];
  if (thrown) problems.push(`wallet refused or failed: ${thrown}`);
  // the output depends on the holder (path, revocation opening): compare within the holder
  const refOut = refs ? walletRefFor(refs, index % H) : null;
  if (refs && out !== null && refOut !== null && out !== refOut) problems.push("wallet output differs from the as-shipped reference");
  if (rep.leftOver.length > 0) problems.push(`prefetched reads left over: ${rep.leftOver.join(", ").slice(0, 300)}`);
  if (rep.unplanned.length > 0) problems.push(`unplanned reads in the concurrent plan: ${rep.unplanned.join(", ").slice(0, 300)}`);
  if (tf.failedPosts > 0 || tf.rpcErrors > 0) problems.push(`failed POSTs ${tf.failedPosts}, JSON-RPC errors ${tf.rpcErrors}`);
  if (refs && !rv.v.cached) {
    const cmp = compareMultisets(refs.walletReads, multiset(readKeys(reqs)));
    if (!cmp.equal) problems.push(`JSON-RPC multiset differs (missing ${cmp.missing.length}, extra ${cmp.extra.length})`);
  }
  if (mc && mc.fallbacks > 0) problems.push(`multicall fallbacks ${mc.fallbacks}`);
  const mlDsaMs = hk.mlDsaVerifyMs + hk.mlDsaImportMs;
  const record = {
    totalMs,
    chainSumMs: rep.chainSumMs,
    chainUnionMs: rep.chainUnionMs,
    mlDsaMs,
    mlDsaVerifyCalls: hk.mlDsaVerifyCalls,
    otherMs: totalMs - rep.chainUnionMs - mlDsaMs,
    outerCalls: rep.outerCalls.length,
    outerByMethod: outerByMethod(rep),
    prefetched: rep.prefetchConsumed,
    groupsFired: rep.groupsFired,
    ...tf,
    requestsSeen: methodCounts(reqs),
    multicall: mc ? { aggregates: mc.aggregates, subCalls: mc.subCalls, fallbacks: mc.fallbacks, sizes: mc.sizes } : null,
    holder: index % H,
    wallMs,
  };
  return { record, posts, t0, t1, t0TraceMs, ok: problems.length === 0, problems, reqs, checksJson: null, walletJson: out };
}

const walletRefs = new WeakMap<References, Map<number, string>>();
function walletRefFor(refs: References, holder: number): string | null {
  return walletRefs.get(refs)?.get(holder) ?? null;
}

/**
 * Equivalence pre-check (untimed, before pinning): the as-shipped variant A on presentation 0
 * (and the wallet read phase of every holder) gives the references; every other variant must
 * then give the same decision and check vector (verifier) or the same outputs (wallet), the
 * same JSON-RPC multiset (eth_chainId dropped, multicall sub-calls expanded), drained FIFOs and
 * no unplanned read. Also fixes the S1 request bodies and the S3 result hashes.
 */
export async function equivalenceCheck(tn: TargetNode, tw: TargetWorld, pre: Pregenerated, roles: Roles, log: (s: string) => void): Promise<{ refs: References; rows: EquivalenceRow[] }> {
  const ctx = { tw, pre };
  const rows: EquivalenceRow[] = [];
  const A = roles.verifier[0] as RoleVariant;
  const a0 = await runVerifierOnce(ctx, roles, A, 0, null);
  if (!a0.ok || a0.checksJson === null) throw new SeriesStop(`as-shipped verifier reference failed: ${a0.problems.join("; ")}`);
  const verifierRequests = a0.reqs.filter((r) => r.method !== "eth_chainId");
  const byM = methodCounts(verifierRequests);
  if (verifierRequests.length !== 7 || byM["eth_call"] !== 5 || byM["eth_getLogs"] !== 2) {
    throw new SeriesStop(`the shipped verifier made ${JSON.stringify(byM)} (expected 5 eth_call and 2 eth_getLogs besides eth_chainId): update the chain-read harness`);
  }
  const AW = roles.wallet[0] as RoleVariant;
  const H = tw.holders.length;
  const refByHolder = new Map<number, string>();
  let walletReads: Multiset | null = null;
  let walletA: PresentationOutcome | null = null;
  for (let h = 0; h < Math.min(H, pre.walletRequests.length); h++) {
    const w0 = await runWalletOnce(ctx, roles, AW, h, null);
    if (!w0.ok || w0.walletJson === null) throw new SeriesStop(`as-shipped wallet reference failed: ${w0.problems.join("; ")}`);
    refByHolder.set(h, w0.walletJson);
    walletA ??= w0;
    const ms = multiset(readKeys(w0.reqs));
    if (walletReads === null) walletReads = ms;
    else if (!compareMultisets(walletReads, ms).equal) throw new SeriesStop("the shipped wallet's reads differ between holders: update the chain-read harness");
  }
  const refs: References = {
    verifierChecks: a0.checksJson,
    verifierReads: multiset(readKeys(a0.reqs)),
    verifierRequests,
    walletOutput: refByHolder.get(0) ?? "",
    walletReads: walletReads ?? new Map(),
    readResults: {} as Record<SixRead, string>,
    readSetReads: new Map(),
  };
  walletRefs.set(refs, refByHolder);
  rows.push({ role: "verifier", variant: "A", ok: true, problems: [], posts: Number(a0.record["posts"]), requests: Number(a0.record["requests"]), depth: Number(a0.record["depth"]), multicall: null });
  for (const rv of roles.verifier) {
    if (rv.v.id === "A") continue;
    // the cached variant's first run fills its cache; its second run makes no request
    const o = await runVerifierOnce(ctx, roles, rv, 0, refs);
    const o2 = rv.v.cached ? await runVerifierOnce(ctx, roles, rv, 0, refs) : o;
    const mc = o.record["multicall"] as EquivalenceRow["multicall"];
    rows.push({ role: "verifier", variant: rv.v.id, ok: o.ok && o2.ok, problems: [...o.problems, ...(o2 === o ? [] : o2.problems)], posts: Number(o.record["posts"]), requests: Number(o.record["requests"]), depth: Number(o.record["depth"]), multicall: mc });
  }
  rows.push({ role: "wallet", variant: "A", ok: true, problems: [], posts: Number(walletA?.record["posts"] ?? 0), requests: Number(walletA?.record["requests"] ?? 0), depth: Number(walletA?.record["depth"] ?? 0), multicall: null });
  for (const rv of roles.wallet) {
    if (rv.v.id === "A") continue;
    const o = await runWalletOnce(ctx, roles, rv, 0, refs);
    const mc = o.record["multicall"] as EquivalenceRow["multicall"];
    rows.push({ role: "wallet", variant: rv.v.id, ok: o.ok, problems: o.problems, posts: Number(o.record["posts"]), requests: Number(o.record["requests"]), depth: Number(o.record["depth"]), multicall: mc });
  }
  // multicall must actually aggregate on the honest path
  for (const r of rows) {
    if (r.variant === "H" && !(r.multicall && r.multicall.aggregates > 0 && r.multicall.subCalls > r.multicall.aggregates)) {
      r.ok = false;
      r.problems.push("the multicall transport aggregated nothing");
    }
  }
  // six reads: result hashes from the shipped client
  const c = await makeClient(tn.url, tw, "asShipped", { multicall: false });
  try {
    for (const r of SIX_READS) refs.readResults[r] = hashOf(await sixRead(c.ledger, r, tw.ids));
    c.capture.reset();
    for (const r of SIX_READS) await sixRead(c.ledger, r, tw.ids);
    refs.readSetReads = multiset(readKeys(c.capture.take()));
  } finally {
    c.close();
  }
  const bad = rows.filter((r) => !r.ok);
  log(`equivalence pre-check: ${rows.length - bad.length}/${rows.length} rows equal${bad.length ? `; FAILED: ${bad.map((b) => `${b.role} ${b.variant}: ${b.problems.join(", ")}`).join(" | ")}` : ""}`);
  return { refs, rows };
}

// ---------------------------------------------------------------------------------------
// S4 and S5
// ---------------------------------------------------------------------------------------

async function presentationSeries(ctx: SeriesContext, roles: Roles, which: "s4" | "s5"): Promise<SeriesCounts> {
  const role = which === "s4" ? roles.verifier : roles.wallet;
  const run = which === "s4" ? runVerifierOnce : runWalletOnce;
  const file = which === "s4" ? "s4_verifier.jsonl.gz" : "s5_wallet.jsonl.gz";
  const sched = which === "s4" ? ctx.schedule.s4 : ctx.schedule.s5;
  const byId = new Map(role.map((rv) => [rv.v.id as string, rv]));
  const w = Math.min(ctx.sizes.warmupPresentations, ctx.pre.replies.length);
  ctx.log(`${which}: warm-up, ${w} presentations per variant (not recorded)`);
  for (const rv of role) {
    for (let i = 0; i < w; i++) {
      const o = await run(ctx, roles, rv, i, ctx.refs);
      if (!o.ok) throw new SeriesStop(`${which} warm-up ${rv.v.id}/${i}: ${o.problems.join("; ")}`);
    }
  }
  const counts = newCounts();
  for (let pi = 0; pi < sched.passes.length; pi++) {
    const ps = sched.passes[pi] as { order: number[]; blocks: string[][] };
    await runPass(ctx, which, file, pi + 1, 0, counts, async (sink, attempt) => {
      for (let b = 0; b < ps.order.length; b++) {
        const index = ps.order[b] as number;
        const ids = ps.blocks[b] as string[];
        for (let pos = 0; pos < ids.length; pos++) {
          const rv = byId.get(ids[pos] as string) as RoleVariant;
          for (let tryNo = 1; tryNo <= 2; tryNo++) {
            const o = await run(ctx, roles, rv, index, ctx.refs);
            sink.clock.sample(o.t0, o.t1);
            const idRec = { series: which, target: ctx.targetNode.name, variant: rv.v.id, name: rv.v.name, label: rv.v.label, pass: pi + 1, attempt, block: b, pos, index, try: tryNo };
            sink.samples.push({ ...o.record, ...idRec, status: o.ok ? "ok" : "error", problems: o.problems });
            sink.posts.push(...postLines(which, { v: rv.v.id, p: pi + 1, a: attempt, i: index, tr: tryNo }, o.posts, o.t0TraceMs));
            if (o.ok) break;
            sink.recordError(idRec, o.problems);
          }
        }
      }
    });
  }
  return counts;
}

export const runS4 = (ctx: SeriesContext, roles: Roles) => presentationSeries(ctx, roles, "s4");
export const runS5 = (ctx: SeriesContext, roles: Roles) => presentationSeries(ctx, roles, "s5");

// ---------------------------------------------------------------------------------------
// S3: the six reads and the read set
// ---------------------------------------------------------------------------------------

interface S3Runtime {
  readClients: Map<ClientName, Client>;
  setClients: Map<string, { rs: ReadSetVariant; client: Client }>;
  close: () => void;
}

async function buildS3(tn: TargetNode, tw: TargetWorld): Promise<S3Runtime> {
  const readClients = new Map<ClientName, Client>();
  const setClients = new Map<string, { rs: ReadSetVariant; client: Client }>();
  for (const c of READ_CLIENTS) readClients.set(c, await makeClient(tn.url, tw, c, { multicall: false }));
  for (const rs of READSET_VARIANTS) setClients.set(rs.name, { rs, client: await makeClient(tn.url, tw, rs.client, { multicall: rs.multicall }) });
  return {
    readClients,
    setClients,
    close: () => {
      for (const c of readClients.values()) c.close();
      for (const s of setClients.values()) s.client.close();
    },
  };
}

async function s3Cell(ctx: SeriesContext, rt: S3Runtime, cell: string) {
  const [kind, a, b] = cell.split(":") as [string, string, string | undefined];
  let client: Client;
  let fn: () => Promise<unknown[]>;
  let meta: Record<string, unknown>;
  if (kind === "read") {
    client = rt.readClients.get(a as ClientName) as Client;
    const r = b as SixRead;
    fn = async () => [await sixRead(client.ledger, r, ctx.tw.ids)];
    meta = { kind, client: a, read: r, label: client.label };
  } else {
    const s = rt.setClients.get(a) as { rs: ReadSetVariant; client: Client };
    client = s.client;
    fn = s.rs.concurrent
      ? () => Promise.all(SIX_READS.map((r) => sixRead(client.ledger, r, ctx.tw.ids)))
      : async () => {
          const out: unknown[] = [];
          for (const r of SIX_READS) out.push(await sixRead(client.ledger, r, ctx.tw.ids));
          return out;
        };
    meta = { kind: "readSet", variant: a, client: s.rs.client, concurrent: s.rs.concurrent, multicall: s.rs.multicall, label: s.rs.label };
  }
  client.trace.drain();
  client.capture.reset();
  client.multicall?.reset();
  const t0TraceMs = traceMsNow(client.trace);
  const t0 = process.hrtime.bigint();
  let res: unknown[] | null = null;
  let thrown: string | null = null;
  try {
    res = await fn();
  } catch (e) {
    thrown = errText(e);
  }
  const t1 = process.hrtime.bigint();
  const posts = client.trace.drain();
  const reqs = client.capture.take();
  const mc = client.multicall?.stats() ?? null;
  const tf = traceFacts(posts);
  const problems: string[] = [];
  if (thrown) problems.push(`read failed: ${thrown}`);
  if (res) {
    const names: readonly SixRead[] = kind === "read" ? [b as SixRead] : SIX_READS;
    names.forEach((r, i) => {
      if (hashOf(res?.[i]) !== ctx.refs.readResults[r]) problems.push(`${r}: result differs from the as-shipped reference`);
    });
  }
  if (kind !== "read" && !compareMultisets(ctx.refs.readSetReads, multiset(readKeys(reqs))).equal) problems.push("read-set JSON-RPC multiset differs from the sequential reference");
  if (tf.failedPosts > 0 || tf.rpcErrors > 0) problems.push(`failed POSTs ${tf.failedPosts}, JSON-RPC errors ${tf.rpcErrors}`);
  if (mc && mc.fallbacks > 0) problems.push(`multicall fallbacks ${mc.fallbacks}`);
  return {
    t0,
    t1,
    posts,
    t0TraceMs,
    ok: problems.length === 0,
    problems,
    record: { ...meta, ms: Number(t1 - t0) / 1e6, ...tf, requestsSeen: methodCounts(reqs), multicall: mc ? { aggregates: mc.aggregates, subCalls: mc.subCalls, fallbacks: mc.fallbacks, sizes: mc.sizes } : null },
  };
}

export async function runS3(ctx: SeriesContext): Promise<SeriesCounts> {
  const rt = await buildS3(ctx.targetNode, ctx.tw);
  try {
    const sch = ctx.schedule.s3;
    ctx.log(`s3: warm-up, ${ctx.sizes.warmupRounds} rounds x ${sch.cells.length} cells (not recorded)`);
    for (let r = 0; r < ctx.sizes.warmupRounds; r++) {
      for (const cell of sch.cells) {
        const o = await s3Cell(ctx, rt, cell);
        if (!o.ok) throw new SeriesStop(`s3 warm-up ${cell}: ${o.problems.join("; ")}`);
      }
    }
    return await roundSeries(ctx, "s3", "s3_reads.jsonl.gz", sch.rounds, sch.passes, 0, (cell) => s3Cell(ctx, rt, cell));
  } finally {
    rt.close();
  }
}

/** Rounds of cells split into passes; each cell is retried once on error. */
export async function roundSeries(
  ctx: PassContext,
  series: string,
  file: string,
  rounds: string[][],
  passes: number,
  spacingMs: number,
  cellFn: (cell: string) => Promise<{ t0: bigint; t1: bigint; posts: PostRecord[]; t0TraceMs: number; ok: boolean; problems: string[]; record: Record<string, unknown> }>
): Promise<SeriesCounts> {
  const per = Math.ceil(rounds.length / Math.max(1, passes));
  const counts = newCounts();
  const io = ctx.io ?? DEFAULT_GUARD_IO;
  for (let pi = 0; pi * per < rounds.length; pi++) {
    const slice = rounds.slice(pi * per, (pi + 1) * per);
    await runPass(ctx, series, file, pi + 1, spacingMs, counts, async (sink, attempt) => {
      for (let ri = 0; ri < slice.length; ri++) {
        const round = pi * per + ri;
        const cells = slice[ri] as string[];
        for (let pos = 0; pos < cells.length; pos++) {
          const cell = cells[pos] as string;
          for (let tryNo = 1; tryNo <= 2; tryNo++) {
            if (spacingMs > 0) await io.sleep(spacingMs);
            const o = await cellFn(cell);
            sink.clock.sample(o.t0, o.t1);
            const idRec = { series, target: ctx.targetNode.name, cell, pass: pi + 1, attempt, round, pos, try: tryNo };
            sink.samples.push({ ...o.record, ...idRec, status: o.ok ? "ok" : "error", problems: o.problems });
            if (o.posts.length) sink.posts.push(...postLines(series, { c: cell, p: pi + 1, a: attempt, r: round, tr: tryNo }, o.posts, o.t0TraceMs));
            if (o.ok) break;
            sink.recordError(idRec, o.problems);
          }
        }
      }
    });
  }
  return counts;
}

// ---------------------------------------------------------------------------------------
// S1: raw JSON-RPC
// ---------------------------------------------------------------------------------------

export interface RawBodies {
  single: Record<(typeof S1_METHODS)[number], RpcRequest>;
  verifier7: RpcRequest[];
}

/** The raw requests, taken from the as-shipped verifier's own requests (equivalence pre-check). */
export function rawBodies(refs: References, tw: TargetWorld): RawBodies {
  const did = tw.world.ledger.addresses.didRegistry.toLowerCase();
  const reqs = refs.verifierRequests;
  const call = reqs.find((r) => r.method === "eth_call" && String((r.params as Array<{ to?: string }>)[0]?.to ?? "").toLowerCase() === did);
  const logs = reqs.find((r) => r.method === "eth_getLogs" && String((r.params as Array<{ address?: string }>)[0]?.address ?? "").toLowerCase() === did);
  if (!call || !logs) throw new SeriesStop("could not find the resolve eth_call and the DIDRegisteredV4 eth_getLogs among the verifier's requests");
  return {
    single: {
      eth_blockNumber: { method: "eth_blockNumber", params: [] },
      eth_chainId: { method: "eth_chainId", params: [] },
      eth_call_resolve: { method: call.method, params: call.params },
      eth_getLogs_registered: { method: logs.method, params: logs.params },
    },
    verifier7: reqs.map((r) => ({ method: r.method, params: r.params })),
  };
}

/** Label of every raw sample (S1, and the raw cell of S2). */
export const RAW_LABEL = "raw transport (no ethers), not the shipped client";

export async function runS1(ctx: SeriesContext): Promise<SeriesCounts> {
  const raw = new RawClient(ctx.targetNode.url);
  const bodies = rawBodies(ctx.refs, ctx.tw);
  const chain: RpcRequest = { method: "eth_chainId", params: [] };
  const arrays: Record<string, RpcRequest[]> = {
    "2": [chain, bodies.single.eth_call_resolve],
    "7": bodies.verifier7,
    "14": bodies.verifier7.flatMap((r) => [chain, r]),
  };
  const conc: Record<string, RpcRequest[]> = { "2": [chain, bodies.single.eth_call_resolve], "7": bodies.verifier7 };
  const cellFn = async (cell: string) => {
    const [kind, a, b] = cell.split(":") as [string, string, string];
    const t0 = process.hrtime.bigint();
    let record: Record<string, unknown>;
    let ok: boolean;
    let problems: string[] = [];
    if (kind === "single") {
      const req = bodies.single[a as (typeof S1_METHODS)[number]];
      const r = await raw.single(b as RawTransport, rpcPayload(req), 1);
      record = { kind, label: RAW_LABEL, method: a, transport: b, ms: r.ms, httpStatus: r.status, bytesOut: r.bytesOut, bytesIn: r.bytesIn, responses: r.responses, rpcErrors: r.rpcErrors, newConnections: r.newConnections };
      ok = r.ok;
      if (!ok) problems = [r.error ?? "not ok"];
    } else if (kind === "array") {
      const reqs = arrays[a] as RpcRequest[];
      const r = await raw.single("httpKeepAlive", rpcPayload(reqs), reqs.length);
      record = { kind, label: RAW_LABEL, size: reqs.length, transport: b, methods: methodCounts(reqs.map((x) => ({ method: x.method, params: x.params }))), ms: r.ms, httpStatus: r.status, bytesOut: r.bytesOut, bytesIn: r.bytesIn, responses: r.responses, rpcErrors: r.rpcErrors, newConnections: r.newConnections, note: a === "7" || a === "14" ? "one-POST transport lower bound, not an implementable read plan (the verifier's getLogs depend on its eth_call results)" : null };
      ok = r.ok;
      if (!ok) problems = [r.error ?? "not ok"];
    } else {
      const reqs = conc[a] as RpcRequest[];
      const r = await raw.concurrent(reqs.map((x, i) => rpcPayload(x, i + 1)));
      record = { kind, label: RAW_LABEL, k: reqs.length, transport: b, ms: r.spanMs, eachMs: r.each.map((e) => e.ms), bytesOut: r.each.reduce((s, e) => s + e.bytesOut, 0), bytesIn: r.each.reduce((s, e) => s + e.bytesIn, 0), newConnections: r.newConnections };
      ok = r.ok;
      if (!ok) problems = r.each.filter((e) => !e.ok).map((e) => e.error ?? "not ok");
    }
    const t1 = process.hrtime.bigint();
    return { t0, t1, posts: [] as PostRecord[], t0TraceMs: 0, ok, problems, record };
  };
  try {
    const sch = ctx.schedule.s1;
    ctx.log(`s1: warm-up, ${ctx.sizes.warmupRounds} rounds x ${sch.cells.length} cells (not recorded)`);
    for (let r = 0; r < ctx.sizes.warmupRounds; r++) {
      for (const cell of sch.cells) {
        const o = await cellFn(cell);
        if (!o.ok) throw new SeriesStop(`s1 warm-up ${cell}: ${o.problems.join("; ")}`);
      }
    }
    return await roundSeries(ctx, "s1", "s1_raw.jsonl.gz", sch.rounds, sch.passes, 0, cellFn);
  } finally {
    raw.close();
  }
}

// ---------------------------------------------------------------------------------------
// S2: fresh connection
// ---------------------------------------------------------------------------------------

/**
 * The fresh-connection guard of an S2 ethers sample: the read must open at least one new TCP
 * connection, and every HTTP attempt must be classified as new or reused.
 */
export function freshConnectionProblems(tf: { tcpConnects: number; tcpConnectsUnknown: number }): string[] {
  const problems: string[] = [];
  if (tf.tcpConnects < 1) problems.push("no new TCP connection was opened (not a fresh connection)");
  if (tf.tcpConnectsUnknown > 0) problems.push(`${tf.tcpConnectsUnknown} HTTP attempts could not be classified as new or reused connections`);
  return problems;
}

export async function runS2(ctx: SeriesContext): Promise<SeriesCounts> {
  const raw = new RawClient(ctx.targetNode.url);
  const bodies = rawBodies(ctx.refs, ctx.tw);
  const tw = ctx.tw;
  const cellFn = async (cell: string) => {
    const [kind, variant] = cell.split(":") as [string, string];
    if (kind === "raw") {
      const t0 = process.hrtime.bigint();
      const r = await raw.single("httpFresh", rpcPayload(bodies.single.eth_call_resolve), 1);
      const t1 = process.hrtime.bigint();
      const problems = r.ok ? [] : [r.error ?? "not ok"];
      if (r.newConnections !== 1) problems.push(`expected one new TCP connection, saw ${String(r.newConnections)}`);
      return {
        t0,
        t1,
        posts: [] as PostRecord[],
        t0TraceMs: 0,
        ok: problems.length === 0,
        problems,
        record: { kind, label: RAW_LABEL, transport: "httpFresh", method: "eth_call_resolve", ms: r.ms, httpStatus: r.status, bytesOut: r.bytesOut, bytesIn: r.bytesIn, newConnections: r.newConnections },
      };
    }
    // a new client per sample (untimed construction); its first read is timed
    const shipped = variant === "asShipped";
    // a new agent with the global agent's options (target.ts agentLikeGlobal) for the variant
    const own = shipped ? null : agentLikeGlobal();
    const agent = own?.agent ?? null;
    const cl = await connectClientLedger(ctx.targetNode.url, tw.world.ledger.addresses, tw.fromBlock, shipped ? "asShipped" : "staticNetwork", {
      ...(shipped ? {} : { chainId: tw.chainId }),
      ...(agent ? { agent } : {}),
      trace: { keepRecords: true },
    });
    const trace = cl.trace as RpcTrace;
    // the shipped client uses Node's global agent: close its pooled sockets so the read opens a new connection
    if (shipped) http.globalAgent.destroy();
    const mark = trace.mark();
    const t0TraceMs = traceMsNow(trace);
    const t0 = process.hrtime.bigint();
    let thrown: string | null = null;
    let value: unknown = null;
    try {
      value = await cl.ledger.resolveDidRecord(tw.ids.issuerDid, tw.ids.issuerController);
    } catch (e) {
      thrown = errText(e);
    }
    const t1 = process.hrtime.bigint();
    const posts = trace.since(mark);
    const connectEvents = trace.connectEvents(mark);
    trace.drain();
    trace.detach();
    cl.ledger.destroy();
    agent?.destroy();
    const tf = traceFacts(posts);
    const problems: string[] = [];
    if (thrown) problems.push(`read failed: ${thrown}`);
    if (!thrown && hashOf(value) !== ctx.refs.readResults.resolveDidRecord) problems.push("result differs from the as-shipped reference");
    problems.push(...freshConnectionProblems(tf));
    return {
      t0,
      t1,
      posts,
      t0TraceMs,
      ok: problems.length === 0,
      problems,
      record: {
        kind,
        client: variant,
        read: "resolveDidRecord",
        label: shipped ? "as shipped" : "variant, not shipped",
        ms: Number(t1 - t0) / 1e6,
        ...tf,
        /** TCP connect time of each new connection (socket creation to connect), ms. */
        connectMs: connectEvents.map((c) => c.connectMs),
      },
    };
  };
  try {
    return await roundSeries(ctx, "s2", "s2_fresh.jsonl.gz", ctx.schedule.s2.rounds, 1, ctx.sizes.s2SpacingMs, cellFn);
  } finally {
    raw.close();
  }
}
