import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import nodeCrypto, { createHash, type KeyObject } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import type { JsonRpcProvider } from "ethers";
import type { AnvilHandle } from "@pqid/ledger";
import { World, type WorldOptions } from "@pqid/v4/world";
import { LedgerV4, RoleAccount, type WriteResult } from "@pqid/v4/ledger";
import { ManualClock } from "@pqid/v4/clock";
import { createGovernance, type Governance } from "@pqid/v4/governance";
import { MIN_ANCHOR_INTERVAL_SEC, MAX_EPOCH_WINDOW_SEC, BN254_P, IMT_MAX } from "@pqid/v4/constants";
import { ML_DSA_44_SPKI_PREFIX } from "@pqid/v4/pqc";
import { VerifierSessionStore } from "@pqid/v4/session";

/**
 * Shared machinery for harness/v4/scale.ts (experiment E4, docs/v4/E4_SCALE.md).
 * Nothing here changes package code: instrumentation wraps objects at run time (Proxy on a
 * LedgerV4 instance, wrappers on node:crypto functions) and is removed after use.
 */

// ---------------------------------------------------------------------------------------
// statistics
// ---------------------------------------------------------------------------------------

export interface Distribution {
  n: number;
  median: number;
  q1: number;
  q3: number;
  iqr: number;
  mean: number;
  min: number;
  max: number;
  p95: number;
}

/** Quantile with linear interpolation between order statistics (Hyndman-Fan type 7). */
function quantile(sorted: readonly number[], q: number): number {
  const h = (sorted.length - 1) * q;
  const lo = Math.floor(h);
  const hi = Math.ceil(h);
  const a = sorted[lo] as number;
  const b = sorted[hi] as number;
  return a + (h - lo) * (b - a);
}

function r4(x: number): number {
  return Math.round(x * 10000) / 10000;
}

/** Median, quartiles (type 7), IQR, mean, min, max, p95 of the samples (units unchanged). */
export function distribution(samples: readonly number[]): Distribution {
  if (samples.length === 0) throw new Error("no samples");
  const s = [...samples].sort((a, b) => a - b);
  const q1 = quantile(s, 0.25);
  const q3 = quantile(s, 0.75);
  return {
    n: s.length,
    median: r4(quantile(s, 0.5)),
    q1: r4(q1),
    q3: r4(q3),
    iqr: r4(q3 - q1),
    mean: r4(s.reduce((x, y) => x + y, 0) / s.length),
    min: r4(s[0] as number),
    max: r4(s[s.length - 1] as number),
    p95: r4(quantile(s, 0.95)),
  };
}

export function nowNs(): bigint {
  return process.hrtime.bigint();
}

export function msSince(t0: bigint): number {
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

export async function timeMs<T>(fn: () => Promise<T> | T): Promise<{ ms: number; value: T }> {
  const t0 = nowNs();
  const value = await fn();
  return { ms: msSince(t0), value };
}

// ---------------------------------------------------------------------------------------
// deterministic pseudo-random inputs (public test data; seeds are recorded)
// ---------------------------------------------------------------------------------------

function sha256Big(seed: string, i: number): bigint {
  return BigInt("0x" + createHash("sha256").update(`${seed}:${i}`).digest("hex"));
}

/** `count` field elements in [1, p), from SHA-256(seed:i). Stand-ins for credential leaves [A]. */
export function fieldElements(seed: string, count: number): bigint[] {
  const out = new Array<bigint>(count);
  for (let i = 0; i < count; i++) {
    const v = sha256Big(seed, i) % BN254_P;
    out[i] = v === 0n ? 1n : v;
  }
  return out;
}

/**
 * `count` distinct revocation keys in (0, 2^251), from the top 251 bits of SHA-256(seed:i).
 * Real revKeys are 251 bits of a SHA3-256 credID, so they have the same distribution [A].
 */
export function revocationKeys(seed: string, count: number): bigint[] {
  const out = new Array<bigint>(count);
  const seen = new Set<bigint>();
  let j = 0;
  for (let i = 0; i < count; i++) {
    for (;;) {
      const v = sha256Big(seed, j++) >> 5n;
      if (v > 0n && v < IMT_MAX && !seen.has(v)) {
        seen.add(v);
        out[i] = v;
        break;
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------
// memory
// ---------------------------------------------------------------------------------------

export interface MemorySnapshot {
  heapUsedMiB: number;
  heapTotalMiB: number;
  rssMiB: number;
  externalMiB: number;
  arrayBuffersMiB: number;
  gcBeforeRead: boolean;
}

export function memory(): MemorySnapshot {
  const gc = (globalThis as { gc?: () => void }).gc;
  if (gc) gc();
  const m = process.memoryUsage();
  const mib = (x: number) => Math.round((x / 2 ** 20) * 10) / 10;
  return {
    heapUsedMiB: mib(m.heapUsed),
    heapTotalMiB: mib(m.heapTotal),
    rssMiB: mib(m.rss),
    externalMiB: mib(m.external),
    arrayBuffersMiB: mib(m.arrayBuffers),
    gcBeforeRead: !!gc,
  };
}

// ---------------------------------------------------------------------------------------
// ports and processes
// ---------------------------------------------------------------------------------------

/** Throws if something already listens on 127.0.0.1:port (never attach to another run's node). */
export async function assertPortFree(port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", (e: NodeJS.ErrnoException) =>
      reject(new Error(`127.0.0.1:${port} is in use (${e.code ?? e.message}); pick another --port`))
    );
    srv.listen(port, "127.0.0.1", () => srv.close(() => resolve()));
  });
}

export async function rawRpc(url: string, method: string, params: unknown[] = []): Promise<unknown> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const j = (await res.json()) as { result?: unknown; error?: { message?: string } };
  if (j.error) throw new Error(`${method}: ${j.error.message ?? "rpc error"}`);
  return j.result;
}

// ---------------------------------------------------------------------------------------
// CPU affinity (DECISIONS D-001 host: native Windows; Linux uses taskset)
// ---------------------------------------------------------------------------------------

export interface AffinityReadBack {
  pid: number;
  method: string;
  /** Hex mask (Windows ProcessorAffinity) or the Linux Cpus_allowed_list. */
  value: string | null;
  cpus: number[] | null;
  error?: string;
}

function cpusFromList(list: string): number[] {
  const out: number[] = [];
  for (const part of list.split(",")) {
    const [a, b] = part.trim().split("-");
    const lo = Number(a);
    const hi = b === undefined ? lo : Number(b);
    for (let i = lo; i <= hi; i++) out.push(i);
  }
  return out;
}

/**
 * Read back the CPU affinity actually applied to process `pid` (Linux: /proc/<pid>/status;
 * not read on the Windows host, see docs/BENCHMARK_POLICY.md).
 */
export function readAffinity(pid: number): AffinityReadBack {
  if (process.platform === "win32") {
    // docs/BENCHMARK_POLICY.md: the only Windows call v4 tooling may make is the power-state query.
    return { pid, method: "not read on Windows (host policy)", value: null, cpus: null, error: "affinity is not read on the Windows host (docs/BENCHMARK_POLICY.md host rule)" };
  }
  try {
    if (process.platform === "linux") {
      const status = fs.readFileSync(`/proc/${pid}/status`, "utf8");
      const m = /^Cpus_allowed_list:\s*(.+)$/m.exec(status);
      if (!m || !m[1]) throw new Error("no Cpus_allowed_list in /proc status");
      return { pid, method: "/proc/<pid>/status Cpus_allowed_list", value: m[1].trim(), cpus: cpusFromList(m[1]) };
    }
    return { pid, method: "unsupported platform", value: null, cpus: null, error: `no affinity read-back on ${process.platform}` };
  } catch (e) {
    return { pid, method: "/proc", value: null, cpus: null, error: (e as Error).message };
  }
}

export interface PinnedLaunch {
  method: string;
  exitCode: number | null;
}

/**
 * Re-launch this Node script pinned to CPU 0 and wait for it.
 *  - Windows host: refused (docs/BENCHMARK_POLICY.md allows only the power-state query as a Windows call).
 *  - Linux: taskset -c 0 <node> ...
 * Children of the pinned process (for example snarkjs worker threads) inherit the mask.
 */
export async function relaunchPinned(script: string, args: string[], env: NodeJS.ProcessEnv): Promise<PinnedLaunch> {
  const nodeArgs = [...process.execArgv, script, ...args];
  let child: ChildProcess;
  let method: string;
  if (process.platform === "win32") {
    // docs/BENCHMARK_POLICY.md allows v4 tooling one Windows-specific call (the power-state query), so the
    // Windows host does not pin; the pinned verifier series runs on Linux (HANDOFF K1).
    throw new Error("CPU pinning is not used on the Windows host (docs/BENCHMARK_POLICY.md host rule): run with --no-pin (labelled unpinned) or on Linux");
  }
  if (process.platform === "linux") {
    method = "taskset -c 0 node ...";
    child = spawn("taskset", ["-c", "0", process.execPath, ...nodeArgs], { stdio: "inherit", env });
  } else {
    throw new Error(`no CPU pinning method on ${process.platform}; use --no-pin`);
  }
  const exitCode = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => resolve(code));
  });
  return { method, exitCode };
}

// ---------------------------------------------------------------------------------------
// World on an external node
// ---------------------------------------------------------------------------------------

/**
 * A World (packages/v4/src/world.ts) on a node the caller runs (an Anvil started by the parent
 * process, or Besu). It does exactly what World.create does after starting Anvil: fresh random
 * governance EVM account, LedgerV4.deploy, fund it, ManualClock at the chain time, governance
 * ML-DSA key. world.stop() leaves the node running (the caller stops it). Uses World's private
 * constructor at run time, so all World methods are the package's own.
 * Methods that move time (advance, syncChainTime) use Anvil dev RPCs: use them on Anvil only.
 */
export async function worldOnRpc(rpcUrl: string, opts: WorldOptions = {}): Promise<World> {
  const governanceAccount = RoleAccount.random("governance");
  const ledger = await LedgerV4.deploy(rpcUrl, {
    governanceAddress: governanceAccount.address,
    minAnchorIntervalSec: opts.minAnchorIntervalSec ?? MIN_ANCHOR_INTERVAL_SEC,
    maxWindowSec: opts.maxWindowSec ?? MAX_EPOCH_WINDOW_SEC,
  });
  try {
    await ledger.fund(governanceAccount);
    const clock = new ManualClock(await ledger.blockTimestamp());
    const governance = await createGovernance(ledger, governanceAccount);
    const external = { proc: null, rpcUrl, stop: () => undefined } as unknown as AnvilHandle;
    const Ctor = World as unknown as new (a: AnvilHandle, l: LedgerV4, c: ManualClock, g: Governance) => World;
    const w = new Ctor(external, ledger, clock, governance);
    w.opts = opts;
    return w;
  } catch (e) {
    ledger.destroy();
    throw e;
  }
}

/** Replace a World's ledger with a wrapper (World.ledger is readonly in TypeScript only). */
export function swapWorldLedger(world: World, ledger: LedgerV4): void {
  (world as unknown as { ledger: LedgerV4 }).ledger = ledger;
}

/** The ethers provider inside a LedgerV4 (TypeScript-private field). */
export function providerOf(ledger: LedgerV4): JsonRpcProvider {
  const p = (ledger as unknown as { provider?: JsonRpcProvider }).provider;
  if (!p) throw new Error("LedgerV4 has no provider field: update harness/v4/scale_lib.ts");
  return p;
}

/**
 * Client variant for measurements only: make this provider send each JSON-RPC request at once
 * instead of waiting ethers' default batchStallTime (10 ms) to batch requests. The shipped
 * client (ledger.ts makeProvider) keeps the default; results label which one was used.
 */
export function disableBatchStall(provider: JsonRpcProvider): void {
  const orig = provider._getOption.bind(provider);
  (provider as unknown as { _getOption: (k: string) => unknown })._getOption = (k: string) =>
    k === "batchStallTime" ? 0 : orig(k as never);
}

/** Count JSON-RPC requests sent by a provider, by method (ethers "debug" events; a batch counts each element). */
export function countRpc(provider: JsonRpcProvider): {
  get: () => number;
  byMethod: () => Record<string, number>;
  reset: () => void;
  stop: () => void;
} {
  let n = 0;
  let methods: Record<string, number> = {};
  const listener = (e: { action?: string; payload?: unknown }) => {
    if (e?.action !== "sendRpcPayload") return;
    const items = Array.isArray(e.payload) ? e.payload : [e.payload];
    for (const p of items) {
      n++;
      const m = String((p as { method?: unknown } | null)?.method ?? "?");
      methods[m] = (methods[m] ?? 0) + 1;
    }
  };
  void provider.on("debug", listener);
  return {
    get: () => n,
    byMethod: () => ({ ...methods }),
    reset: () => {
      n = 0;
      methods = {};
    },
    stop: () => void provider.off("debug", listener),
  };
}

/** EVM fork facts of a node: Anvil's hardFork (anvil_nodeInfo) and eth_config (EIP-7910) when served. */
export async function evmInfo(url: string): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = {};
  try {
    out["anvilHardFork"] = ((await rawRpc(url, "anvil_nodeInfo")) as { hardFork?: string }).hardFork ?? null;
  } catch {
    /* not Anvil */
  }
  try {
    const c = (await rawRpc(url, "eth_config")) as { current?: { forkId?: string; activationTime?: number; blobSchedule?: unknown } };
    out["ethConfigCurrent"] = { forkId: c.current?.forkId ?? null, activationTime: c.current?.activationTime ?? null, blobSchedule: c.current?.blobSchedule ?? null };
  } catch (e) {
    out["ethConfigCurrent"] = `unavailable: ${(e as Error).message}`;
  }
  return out;
}

/**
 * Calldata facts of a mined transaction: zero / non-zero byte counts, the pre-Prague calldata
 * gas (4 per zero byte, 16 per non-zero byte) and the EIP-7623 (Prague) floor
 * 21000 + 10 * (zero + 4 * non-zero). floorBinds: the receipt's gasUsed equals the floor.
 */
export async function calldataInfo(url: string, txHash: string, gasUsed: number): Promise<Record<string, unknown>> {
  const tx = (await rawRpc(url, "eth_getTransactionByHash", [txHash])) as { input?: string } | null;
  const hex = (tx?.input ?? "0x").replace(/^0x/, "");
  let zero = 0;
  let nonZero = 0;
  for (let i = 0; i < hex.length; i += 2) {
    if (hex.slice(i, i + 2) === "00") zero++;
    else nonZero++;
  }
  const tokens = zero + 4 * nonZero;
  const floor = 21000 + 10 * tokens;
  return {
    calldataBytes: zero + nonZero,
    zeroBytes: zero,
    nonZeroBytes: nonZero,
    calldataGasPrePrague: 4 * zero + 16 * nonZero,
    eip7623FloorGas: floor,
    floorBinds: gasUsed === floor,
  };
}

// ---------------------------------------------------------------------------------------
// LedgerV4 wrappers (Proxy on the instance; package code unchanged)
// ---------------------------------------------------------------------------------------

/** The read methods a verifier or wallet calls (V4_DESIGN 6.1, 6.2). */
export const LEDGER_READS = [
  "resolveDidRecord",
  "getPopSignature",
  "latestAccreditation",
  "currentEpoch",
  "latestKemKey",
  "getMinAnchorInterval",
  "getMaxWindow",
  "chainId",
  "blockTimestamp",
  "blockNumber",
] as const;
const READ_SET = new Set<string>(LEDGER_READS);

export interface ReadStats {
  calls: number;
  ms: number;
  byMethod: Record<string, { calls: number; ms: number }>;
}

/**
 * Time every outermost LedgerV4 read made through the proxy (a read that another read calls
 * internally, such as resolveDidRecord inside getPopSignature, counts once, in the outer call).
 */
export function timedLedger(ledger: LedgerV4): { proxy: LedgerV4; stats: ReadStats; reset: () => void } {
  const stats: ReadStats = { calls: 0, ms: 0, byMethod: {} };
  let depth = 0;
  const proxy = new Proxy(ledger, {
    get(target, prop, receiver) {
      const v = Reflect.get(target, prop, receiver) as unknown;
      if (typeof prop !== "string" || typeof v !== "function" || !READ_SET.has(prop)) return v;
      const fn = v as (...a: unknown[]) => Promise<unknown>;
      return async function (this: unknown, ...args: unknown[]) {
        const outer = depth === 0;
        depth++;
        const t0 = nowNs();
        try {
          return await fn.apply(this, args);
        } finally {
          depth--;
          if (outer) {
            const ms = msSince(t0);
            stats.calls++;
            stats.ms += ms;
            const b = (stats.byMethod[prop] ??= { calls: 0, ms: 0 });
            b.calls++;
            b.ms += ms;
          }
        }
      };
    },
  });
  return {
    proxy,
    stats,
    reset: () => {
      stats.calls = 0;
      stats.ms = 0;
      stats.byMethod = {};
    },
  };
}

/**
 * Serve LedgerV4 reads from an in-memory cache keyed by method and arguments (first call per
 * key reads the chain). Isolates the verifier's non-chain cost; nothing is written through it.
 */
export function cachedLedger(ledger: LedgerV4): { proxy: LedgerV4; misses: () => number } {
  const cache = new Map<string, unknown>();
  let misses = 0;
  const proxy = new Proxy(ledger, {
    get(target, prop, receiver) {
      const v = Reflect.get(target, prop, receiver) as unknown;
      if (typeof prop !== "string" || typeof v !== "function" || !READ_SET.has(prop)) return v;
      const fn = v as (...a: unknown[]) => Promise<unknown>;
      return async function (this: unknown, ...args: unknown[]) {
        const key = `${prop}:${JSON.stringify(args)}`;
        if (cache.has(key)) return cache.get(key);
        misses++;
        const r = await fn.apply(this, args);
        cache.set(key, r);
        return r;
      };
    },
  });
  return { proxy, misses: () => misses };
}

export interface RecordedWrite extends WriteResult {
  contract: string;
  method: string;
  /** rawWrite wall time: gas estimation (unless a gas limit is given), submit, receipt. */
  ms: number;
}

/** Record every registry write (LedgerV4.rawWrite) made through the proxy, with its gas. */
export function recordingLedger(ledger: LedgerV4): { proxy: LedgerV4; writes: RecordedWrite[] } {
  const writes: RecordedWrite[] = [];
  const proxy = new Proxy(ledger, {
    get(target, prop, receiver) {
      const v = Reflect.get(target, prop, receiver) as unknown;
      if (prop !== "rawWrite" || typeof v !== "function") return v;
      const fn = v as (...a: unknown[]) => Promise<WriteResult>;
      return async function (this: unknown, ...args: unknown[]) {
        const t0 = nowNs();
        const r = await fn.apply(this, args);
        writes.push({ ...r, contract: String(args[1]), method: String(args[2]), ms: msSince(t0) });
        return r;
      };
    },
  });
  return { proxy, writes };
}

// ---------------------------------------------------------------------------------------
// node:crypto hooks (ML-DSA verify, ML-KEM decapsulate) for the verifier split
// ---------------------------------------------------------------------------------------

export interface CryptoStats {
  mlDsaVerifyCalls: number;
  mlDsaVerifyMs: number;
  mlDsaImportCalls: number;
  mlDsaImportMs: number;
  mlKemDecapsCalls: number;
  mlKemDecapsMs: number;
}

type CryptoMut = Record<string, unknown>;

/**
 * Wrap node:crypto verify / createPublicKey / decapsulate (packages/v4/src/pqc.ts calls them
 * through the module object at call time) and time the ML-DSA-44 and ML-KEM calls.
 * Returns the counters and an uninstall function.
 */
export function hookPqcCrypto(): { stats: CryptoStats; reset: () => void; uninstall: () => void } {
  const c = nodeCrypto as unknown as CryptoMut;
  const origVerify = c["verify"] as (...a: unknown[]) => unknown;
  const origCreatePublicKey = c["createPublicKey"] as (...a: unknown[]) => unknown;
  const origDecaps = c["decapsulate"] as ((...a: unknown[]) => unknown) | undefined;
  const stats: CryptoStats = { mlDsaVerifyCalls: 0, mlDsaVerifyMs: 0, mlDsaImportCalls: 0, mlDsaImportMs: 0, mlKemDecapsCalls: 0, mlKemDecapsMs: 0 };
  const isMlDsaKey = (k: unknown) => k instanceof nodeCrypto.KeyObject && (k as KeyObject).asymmetricKeyType === ("ml-dsa-44" as never);
  const isMlDsaDer = (a: unknown) => {
    const key = (a as { key?: unknown } | null)?.key;
    return Buffer.isBuffer(key) && key.length > ML_DSA_44_SPKI_PREFIX.length && key.subarray(0, ML_DSA_44_SPKI_PREFIX.length).equals(ML_DSA_44_SPKI_PREFIX);
  };
  c["verify"] = function (...a: unknown[]) {
    if (!isMlDsaKey(a[2])) return origVerify.apply(this, a);
    const t0 = nowNs();
    try {
      return origVerify.apply(this, a);
    } finally {
      stats.mlDsaVerifyCalls++;
      stats.mlDsaVerifyMs += msSince(t0);
    }
  };
  c["createPublicKey"] = function (...a: unknown[]) {
    if (!isMlDsaDer(a[0])) return origCreatePublicKey.apply(this, a);
    const t0 = nowNs();
    try {
      return origCreatePublicKey.apply(this, a);
    } finally {
      stats.mlDsaImportCalls++;
      stats.mlDsaImportMs += msSince(t0);
    }
  };
  if (origDecaps) {
    c["decapsulate"] = function (...a: unknown[]) {
      const t0 = nowNs();
      try {
        return origDecaps.apply(this, a);
      } finally {
        stats.mlKemDecapsCalls++;
        stats.mlKemDecapsMs += msSince(t0);
      }
    };
  }
  return {
    stats,
    reset: () => {
      for (const k of Object.keys(stats) as Array<keyof CryptoStats>) stats[k] = 0;
    },
    uninstall: () => {
      c["verify"] = origVerify;
      c["createPublicKey"] = origCreatePublicKey;
      if (origDecaps) c["decapsulate"] = origDecaps;
    },
  };
}

// ---------------------------------------------------------------------------------------
// verifier sessions
// ---------------------------------------------------------------------------------------

type SessionMap = Map<string, unknown>;

function sessionMapOf(store: VerifierSessionStore): SessionMap {
  const m = (store as unknown as { sessions?: SessionMap }).sessions;
  if (!(m instanceof Map)) throw new Error("VerifierSessionStore internals changed: update harness/v4/scale_lib.ts");
  return m;
}

/** Copy of the open sessions (so the same replies can be verified again in a later pass). */
export function snapshotSessions(store: VerifierSessionStore): SessionMap {
  return new Map(sessionMapOf(store));
}

/** Put the snapshot back (sessions consumed by a pass become open again). */
export function restoreSessions(store: VerifierSessionStore, snap: SessionMap): void {
  const m = sessionMapOf(store);
  m.clear();
  for (const [k, v] of snap) m.set(k, v);
}

/** Make a verifier use another store (the cached-reads verifier shares the measured verifier's sessions). */
export function replaceSessionStore(verifier: object, store: VerifierSessionStore): void {
  (verifier as { sessions: VerifierSessionStore }).sessions = store;
}

// ---------------------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------------------

export function sha256OfFile(p: string): string {
  return createHash("sha256").update(fs.readFileSync(p)).digest("hex");
}

export function writeJson(file: string, obj: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(obj, (_k, v: unknown) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");
}

export function osInfo(): { freeMemGiB: number; uptimeSec: number } {
  return { freeMemGiB: Math.round((os.freemem() / 2 ** 30) * 10) / 10, uptimeSec: Math.round(os.uptime()) };
}
