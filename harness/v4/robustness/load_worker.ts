import { parentPort, workerData, threadId } from "node:worker_threads";
import { monitorEventLoopDelay, performance } from "node:perf_hooks";
import type { KeyObject } from "node:crypto";
import { ManualClock } from "@pqid/v4/clock";
import { VerifierV4, type VerifierIdentity, type VerifyDecisionV4 } from "@pqid/v4/verifier";
import type { SessionReplyV4 } from "@pqid/v4/session";
import type { RegistryAddressesV4 } from "@pqid/v4/ledger";
import { cachedLedger, restoreSessions, replaceSessionStore } from "../scale_lib.ts";
import { connectClientLedger, type ClientLedger } from "../lib/rpc_trace.ts";
import { sanitize } from "../bench/lib.ts";
import { closedLoop, nsToMs, r3, settleLate, type Variant } from "./load_lib.ts";

/**
 * One verifier replica of the load test (worker thread; docs/v4/ROBUSTNESS.md section 3).
 *
 * Each worker is an independent replica with its own VerifierSessionStore (sticky load
 * balancing; exactly-once across replicas is not modelled). It builds:
 *  - asShipped: VerifierV4 on LedgerV4.connect (the shipped ethers client, traced for counts);
 *  - cachedReads: VerifierV4 on harness/v4/scale_lib.ts cachedLedger over a second traced
 *    LedgerV4.connect (a harness read cache: never verifier capacity);
 * both on a ManualClock fixed at the parent's clock (sessions never expire during the run) and
 * sharing one store loaded with the parent's session snapshot. The verifier's KEM private key
 * arrives in memory (workerData, a cloned KeyObject) and is never written.
 *
 * Commands (postMessage), handled one at a time in arrival order:
 *  - pass {passId, gen, variant, lanes, refs, timeoutMs, lateBoundMs} and correctness {passId,
 *    gen, lanes, phaseA, checkSessions, phaseB, timeoutMs, lateBoundMs}: answer "armed", wait on
 *    the shared barrier (Atomics) for generation `gen`, run, wait up to lateBoundMs for calls that
 *    outlived their timeout (so none can consume a session after the restore), restore the
 *    sessions (untimed) and answer "result". A call still running after lateBoundMs makes the
 *    worker report a fatal error (the parent replaces it);
 *  - first {passId, ref}: the worker's first verification (one honest reply, asShipped, c = 1),
 *    recorded once as aux.firstVerificationInWorker, then the sessions are restored;
 *  - ping {passId}: answered with "pong" once every earlier command has finished (drain);
 *  - exit: ends the thread (smoke-only fault injection);
 *  - stop: closes the clients.
 */

type Ref = ["pool", number] | ["hostile", string, number] | ["corr", number];

interface WorkerInit {
  workerId: number;
  epochNs: string;
  rpcUrl: string;
  addresses: RegistryAddressesV4;
  fromBlock: number;
  chainId: number;
  governancePk: Uint8Array;
  identity: { label: string; did: string; pk: Uint8Array; controller: string; origin: string; kemPublic: Uint8Array; kemPrivate: KeyObject };
  clockSec: number;
  sessions: Array<[string, { request: unknown; createdAtMs: number; expiresAtMs: number }]>;
  pool: Uint8Array[];
  hostile: Record<string, Uint8Array[]>;
  corr: Uint8Array[];
  barrier: SharedArrayBuffer;
}

const init = workerData as WorkerInit;
const port = parentPort;
if (!port) throw new Error("load_worker.ts must run as a worker thread");
const EPOCH = BigInt(init.epochNs);
const gate = new Int32Array(init.barrier);

const buf = (u: Uint8Array) => Buffer.from(u.buffer, u.byteOffset, u.byteLength);
function deepFreeze<T>(v: T): T {
  if (v && typeof v === "object" && !Object.isFrozen(v)) {
    for (const x of Object.values(v as Record<string, unknown>)) deepFreeze(x);
    Object.freeze(v);
  }
  return v;
}

const pool = init.pool.map(buf);
const hostile: Record<string, Buffer[]> = Object.fromEntries(Object.entries(init.hostile).map(([k, v]) => [k, v.map(buf)]));
const corr = init.corr.map(buf);
const snapshot = new Map(init.sessions.map(([id, s]) => [id, { ...s, request: deepFreeze(s.request) }]));

let shipped: ClientLedger | null = null;
let cachedClient: ClientLedger | null = null;
let vShipped: VerifierV4 | null = null;
let vCached: VerifierV4 | null = null;

async function setup(): Promise<void> {
  const identity = {
    label: init.identity.label,
    did: init.identity.did,
    pk: buf(init.identity.pk),
    controller: init.identity.controller,
    origin: init.identity.origin,
    kem: { publicKey: buf(init.identity.kemPublic), privateKey: init.identity.kemPrivate },
    // not needed to verify (publishing only); never sent to workers
    sk: null,
    account: null,
  } as unknown as VerifierIdentity;
  const clock = new ManualClock(init.clockSec);
  shipped = await connectClientLedger(init.rpcUrl, init.addresses, init.fromBlock, "asShipped", { trace: { keepRecords: false } });
  cachedClient = await connectClientLedger(init.rpcUrl, init.addresses, init.fromBlock, "asShipped", { trace: { keepRecords: false } });
  const opts = { identity, pinnedGovernancePk: buf(init.governancePk), clock };
  vShipped = new VerifierV4({ ...opts, ledger: shipped.ledger });
  vCached = new VerifierV4({ ...opts, ledger: cachedLedger(cachedClient.ledger).proxy });
  replaceSessionStore(vCached, vShipped.sessions);
  restoreSessions(vShipped.sessions, snapshot as never);
  const chainId = await shipped.ledger.chainId();
  if (chainId !== init.chainId) throw new Error(`worker sees chain id ${chainId}, parent ${init.chainId}`);
}

function bytesOf(ref: Ref): Buffer {
  if (ref[0] === "pool") return pool[ref[1]] as Buffer;
  if (ref[0] === "corr") return corr[ref[1]] as Buffer;
  const list = hostile[ref[1]];
  if (!list) throw new Error(`no hostile items of class ${ref[1]} in this worker`);
  return list[ref[2] % list.length] as Buffer;
}

function outcomeOf(d: VerifyDecisionV4): string {
  if (d.accepted) return "accepted";
  if (d.failedChecks.length > 0) return `rejected:${d.failedChecks[0]}`;
  return d.reasons.some((r) => r.startsWith("verifier error on hostile input")) ? "rejected:exception" : "rejected:?";
}

function waitBarrier(gen: number): void {
  for (;;) {
    const cur = Atomics.load(gate, 0);
    if (cur === gen) return;
    Atomics.wait(gate, 0, cur, 60_000);
  }
}

interface RunOut {
  latMs: number[];
  startMs: number[];
  endMs: number[];
  outcomes: string[];
  errors: Array<{ i: number; error: string }>;
}

async function runItems(variant: Variant, refs: Ref[], lanes: number, timeoutMs: number, late: Array<Promise<unknown>>): Promise<RunOut> {
  const v = variant === "cachedReads" ? (vCached as VerifierV4) : (vShipped as VerifierV4);
  const recs = await closedLoop(
    refs,
    lanes,
    async (ref) => {
      // the reply as UTF-8 JSON bytes, so wire parsing is part of the timed call
      const d = await v.verifyReply(bytesOf(ref) as unknown as SessionReplyV4);
      return d;
    },
    timeoutMs,
    late
  );
  const out: RunOut = { latMs: [], startMs: [], endMs: [], outcomes: [], errors: [] };
  for (const r of recs) {
    const lat = nsToMs(r.endNs - r.startNs);
    out.latMs.push(r3(lat));
    out.startMs.push(r3(nsToMs(r.startNs - EPOCH)));
    out.endMs.push(r3(nsToMs(r.endNs - EPOCH)));
    if (r.error !== undefined) {
      out.outcomes.push(r.timedOut ? "error:timeout" : "error:throw");
      out.errors.push({ i: r.index, error: sanitize(r.error).slice(0, 300) });
    } else out.outcomes.push(outcomeOf(r.value as VerifyDecisionV4));
  }
  return out;
}

function counters(): { shipped: { posts: number; requests: number }; cached: { posts: number; requests: number } } {
  const a = shipped?.trace?.counts();
  const b = cachedClient?.trace?.counts();
  return { shipped: { posts: a?.posts ?? 0, requests: a?.requests ?? 0 }, cached: { posts: b?.posts ?? 0, requests: b?.requests ?? 0 } };
}

function diffCounts(before: ReturnType<typeof counters>, after: ReturnType<typeof counters>, variant: Variant): { posts: number; requests: number } {
  const k = variant === "cachedReads" ? "cached" : "shipped";
  return { posts: after[k].posts - before[k].posts, requests: after[k].requests - before[k].requests };
}

type Msg =
  | { type: "pass"; passId: string; gen: number; variant: Variant; lanes: number; refs: Ref[]; timeoutMs: number; lateBoundMs: number }
  | { type: "correctness"; passId: string; gen: number; lanes: number; phaseA: Ref[]; checkSessions: string[]; phaseB: Ref[]; timeoutMs: number; lateBoundMs: number }
  | { type: "first"; passId: string; ref: Ref; timeoutMs: number; lateBoundMs: number }
  | { type: "ping"; passId: string }
  | { type: "exit" }
  | { type: "stop" };

/** A pass left a call running past lateBoundMs: the worker's session state is no longer known. */
class FatalWorkerError extends Error {}

async function settleOrDie(late: Array<Promise<unknown>>, boundMs: number, acc: { timedOut: number; settled: number; unsettled: number }): Promise<void> {
  const r = await settleLate(late.splice(0), boundMs);
  acc.timedOut += r.timedOut;
  acc.settled += r.settled;
  acc.unsettled += r.unsettled;
  if (r.unsettled > 0) throw new FatalWorkerError(`${r.unsettled} timed-out verification(s) still running after ${boundMs} ms: session state unknown, worker must be replaced`);
}

async function onMessage(m: Msg): Promise<void> {
  if (m.type === "stop") {
    shipped?.trace?.detach();
    cachedClient?.trace?.detach();
    shipped?.ledger.destroy();
    cachedClient?.ledger.destroy();
    port?.postMessage({ type: "stopped" });
    return;
  }
  if (m.type === "exit") {
    // smoke-only fault injection (load.ts --inject-fault worker-exit): end this worker thread
    process.exit(3);
  }
  if (m.type === "ping") {
    port?.postMessage({ type: "pong", passId: m.passId, workerId: init.workerId });
    return;
  }
  const late: Array<Promise<unknown>> = [];
  const lateRec = { timedOut: 0, settled: 0, unsettled: 0 };
  if (m.type === "first") {
    // untimed setup step whose time is recorded once (aux): one honest reply, asShipped, c = 1
    const r = await runItems("asShipped", [m.ref], 1, m.timeoutMs, late);
    await settleOrDie(late, m.lateBoundMs, lateRec);
    restoreSessions((vShipped as VerifierV4).sessions, snapshot as never);
    port?.postMessage({ type: "result", passId: m.passId, workerId: init.workerId, threadId, result: { ms: r.latMs[0] ?? null, variant: "asShipped", lanes: 1, outcome: r.outcomes[0] ?? null, accepted: r.outcomes[0] === "accepted" } });
    return;
  }
  const eld = monitorEventLoopDelay({ resolution: 10 });
  const before = counters();
  port?.postMessage({ type: "armed", passId: m.passId });
  waitBarrier(m.gen);
  eld.enable();
  const elu0 = performance.eventLoopUtilization();
  let result: Record<string, unknown>;
  if (m.type === "pass") {
    const r = await runItems(m.variant, m.refs, m.lanes, m.timeoutMs, late);
    result = { ...r, rpc: diffCounts(before, counters(), m.variant) };
  } else {
    const a = await runItems("asShipped", m.phaseA, m.lanes, m.timeoutMs, late);
    // a phase-A call that timed out must finish before the session states are read
    await settleOrDie(late, m.lateBoundMs, lateRec);
    const status = m.checkSessions.map((id) => [id.slice(0, 12), (vShipped as VerifierV4).sessions.status(id)]);
    const b = await runItems("asShipped", m.phaseB, m.lanes, m.timeoutMs, late);
    result = { phaseA: a, sessionStatusAfterA: status, phaseB: b, rpc: diffCounts(before, counters(), "asShipped") };
  }
  const elu = performance.eventLoopUtilization(elu0);
  eld.disable();
  const pct = (p: number) => r3(eld.percentile(p) / 1e6);
  const loop = { utilization: r3(elu.utilization), eventLoopDelayMs: { min: r3(eld.min / 1e6), p50: pct(50), p99: pct(99), max: r3(eld.max / 1e6), mean: r3(eld.mean / 1e6) } };
  // untimed: calls that outlived their timeout finish first, then the consumed sessions go back
  await settleOrDie(late, m.lateBoundMs, lateRec);
  restoreSessions((vShipped as VerifierV4).sessions, snapshot as never);
  port?.postMessage({ type: "result", passId: m.passId, workerId: init.workerId, threadId, result, loop, lateSettled: lateRec });
}

let queue: Promise<void> = Promise.resolve();
setup().then(
  () => {
    port.on("message", (m: Msg) => {
      queue = queue.then(() =>
        onMessage(m).catch((e: unknown) => {
          const fatal = e instanceof FatalWorkerError;
          port.postMessage({ type: "error", passId: (m as { passId?: string }).passId ?? null, fatal, error: sanitize(e instanceof Error ? (e.stack ?? e.message) : String(e)).slice(0, 2000) });
        })
      );
    });
    port.postMessage({ type: "ready", workerId: init.workerId, threadId });
  },
  (e: unknown) => {
    port.postMessage({ type: "error", passId: null, error: sanitize(e instanceof Error ? (e.stack ?? e.message) : String(e)).slice(0, 2000) });
  }
);
