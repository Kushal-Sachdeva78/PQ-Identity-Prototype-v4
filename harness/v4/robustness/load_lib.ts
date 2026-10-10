import fs from "node:fs";
import { mulberry32, shuffle } from "../bench/lib.ts";

/**
 * Pure helpers of the load test "verifier library under concurrent load" (robustness row,
 * DECISIONS D-034; protocol in docs/v4/ROBUSTNESS.md section 3). No I/O except the Linux
 * /proc readers at the end and ClockWatch (timers only). Unit-tested in tests/v4/robustness_load.test.ts.
 */

export type Variant = "asShipped" | "cachedReads";
export const VARIANTS: readonly Variant[] = ["asShipped", "cachedReads"];

/** Hostile-input classes (HC0 is the honest reference). */
export const HOSTILE_CLASSES = ["HC0", "HC1", "HC2", "HC3", "HC4", "HC5", "HC6", "HC7"] as const;
export type HostileClass = (typeof HOSTILE_CLASSES)[number];

export const HOSTILE_DESCRIPTIONS: Readonly<Record<HostileClass, string>> = Object.freeze({
  HC0: "honest reply (reference)",
  HC1: "reply bytes that are not JSON",
  HC2: "well-formed reply for an unknown session",
  HC3: "known session, tampered box (AES-GCM fails after ML-KEM decapsulation)",
  HC4: "valid AES-GCM seal, honest presentation of another session (wrong nonce signal): full evaluation with chain reads and Groth16",
  HC5: "valid AES-GCM seal in an honest session, that session's own presentation with in-range garbage proof coordinates (only Groth16 fails)",
  HC6: "valid AES-GCM seal, presentation near 1 MiB with one very long decimal string (unbounded BigInt parse)",
  HC7: "valid AES-GCM seal, presentation near 1 MiB of wide, non-canonical JSON",
});

/**
 * The exact failedChecks set VerifierV4.verifyReply must return for each hostile class (the
 * untimed pre-pass aborts the campaign on any other set; the analysis takes latency from items
 * whose first failed check is the expected one). HC1 and HC7 fail in transport as "malformed"
 * after the session lookup, so sessionKnown passes and transcriptDecrypts fails.
 */
export const HOSTILE_EXPECTED_CHECKS: Readonly<Record<Exclude<HostileClass, "HC0">, readonly string[]>> = Object.freeze({
  HC1: ["transcriptDecrypts"],
  HC2: ["sessionKnown"],
  HC3: ["transcriptDecrypts"],
  HC4: ["nonceBinding"],
  HC5: ["groth16"],
  HC6: ["shape"],
  HC7: ["transcriptDecrypts"],
});

/** Expected failedChecks of the correctness items sealed into honest target sessions. */
export const CORRECTNESS_EXPECTED_CHECKS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  "HC3-on-session": ["transcriptDecrypts"],
  "HC4-on-session": ["nonceBinding"],
  "HC5-on-session": ["groth16"],
  "noncanonical-on-session": ["transcriptDecrypts"],
});

/** The outcome label the worker records for the expected result ("accepted" or "rejected:<first failed check>"). */
export function expectedOutcome(cls: HostileClass): string {
  return cls === "HC0" ? "accepted" : `rejected:${HOSTILE_EXPECTED_CHECKS[cls][0] as string}`;
}

/** True when two check lists hold exactly the same names, each once (order ignored). */
export function sameCheckSet(a: readonly string[], b: readonly string[]): boolean {
  const x = [...a].sort();
  const y = [...b].sort();
  return new Set(x).size === x.length && x.length === y.length && x.every((v, i) => v === y[i]);
}

export interface LoadLevels {
  /** Honest replies in the pool. */
  P: number;
  /** Holders that prove the pool (round robin). */
  H: number;
  /** Replies per active worker per throughput pass. */
  R: number;
  workers: number[];
  conc: number[];
  variants: Variant[];
  /** Hostile items per class per variant per block. */
  hostileN: number;
  /** Distinct replies built for the near-1 MiB classes HC6 and HC7 (cycled up to hostileN). */
  hostileLargeDistinct: number;
  /** Correctness batch per worker: honest items, duplicate groups, hostile-on-honest-session targets. */
  corrHonest: number;
  corrDupGroups: number;
  corrTargets: number;
  corrConc: number;
  warmupBlocks: number;
  measuredBlocks: number;
  settleSec: number;
  timeoutMs: number;
  /** Session cap of the saturation run (the package default is 100,000). */
  saturationCap: number;
}

/** Pre-registered levels (docs/v4/ROBUSTNESS.md section 3.4). Changing them changes the normative text. */
export const FULL_LEVELS: Readonly<LoadLevels> = Object.freeze({
  P: 400,
  H: 4,
  R: 160,
  workers: [1, 2, 4, 6],
  conc: [1, 4, 16],
  variants: ["asShipped", "cachedReads"],
  hostileN: 40,
  hostileLargeDistinct: 8,
  corrHonest: 8,
  corrDupGroups: 2,
  corrTargets: 2,
  corrConc: 16,
  warmupBlocks: 1,
  measuredBlocks: 8,
  settleSec: 600,
  timeoutMs: 30_000,
  saturationCap: 100_000,
} satisfies LoadLevels);

/** Smoke levels (checks the runner; never quoted). */
export const SMOKE_LEVELS: Readonly<LoadLevels> = Object.freeze({
  P: 12,
  H: 2,
  R: 8,
  workers: [1, 2],
  conc: [1, 4],
  variants: ["asShipped", "cachedReads"],
  hostileN: 3,
  hostileLargeDistinct: 2,
  corrHonest: 2,
  corrDupGroups: 2,
  corrTargets: 1,
  corrConc: 16,
  warmupBlocks: 1,
  measuredBlocks: 1,
  settleSec: 5,
  timeoutMs: 30_000,
  saturationCap: 2_000,
} satisfies LoadLevels);

/** Pool indices the correctness batch of worker w uses (fixed per worker; disjoint inside a worker). */
export function correctnessIndices(levels: LoadLevels, w: number): { honest: number[]; dupGroups: number[]; targets: number[] } {
  const need = levels.corrHonest + levels.corrDupGroups + levels.corrTargets;
  if (need > levels.P) throw new Error(`correctness batch needs ${need} distinct pool replies per worker, pool has ${levels.P}`);
  const base = (w * need) % levels.P;
  const idx = Array.from({ length: need }, (_, i) => (base + i) % levels.P);
  return {
    honest: idx.slice(0, levels.corrHonest),
    dupGroups: idx.slice(levels.corrHonest, levels.corrHonest + levels.corrDupGroups),
    targets: idx.slice(levels.corrHonest + levels.corrDupGroups),
  };
}

/**
 * Pool indices used by no worker's correctness batch, highest first. HC5 replies (sealed into
 * honest sessions) and each worker's first verification use these, so they never share a session
 * with a correctness item.
 */
export function freeIndices(levels: LoadLevels): number[] {
  const Wmax = Math.max(...levels.workers);
  const used = new Set<number>();
  for (let w = 0; w < Wmax; w++) {
    const ix = correctnessIndices(levels, w);
    for (const i of [...ix.honest, ...ix.dupGroups, ...ix.targets]) used.add(i);
  }
  const out: number[] = [];
  for (let i = levels.P - 1; i >= 0; i--) if (!used.has(i)) out.push(i);
  return out;
}

export type Cell =
  | { kind: "throughput"; id: string; variant: Variant; W: number; c: number }
  | { kind: "hostile"; id: string; variant: Variant; cls: HostileClass; W: 1; c: 1 }
  | { kind: "correctness"; id: string; variant: "asShipped"; W: number; c: number };

export function cellsOf(levels: LoadLevels): Cell[] {
  const out: Cell[] = [];
  for (const variant of levels.variants) {
    for (const W of levels.workers) for (const c of levels.conc) out.push({ kind: "throughput", id: `tp:${variant}:W${W}:c${c}`, variant, W, c });
    for (const cls of HOSTILE_CLASSES) out.push({ kind: "hostile", id: `hc:${variant}:${cls}`, variant, cls, W: 1, c: 1 });
  }
  const Wmax = Math.max(...levels.workers);
  out.push({ kind: "correctness", id: `corr:asShipped:W${Wmax}:c${levels.corrConc}`, variant: "asShipped", W: Wmax, c: levels.corrConc });
  return out;
}

export interface ScheduledBlock {
  block: number;
  measured: boolean;
  /** Cell ids in run order. */
  order: string[];
  /** Pool rotation offset of each worker (index into the pool). */
  offsets: number[];
}

/**
 * Blocked schedule: every block holds every cell once; order within a block by a Fisher-Yates
 * shuffle driven by one mulberry32 stream (seed robustness.load), block after block; the same
 * stream then draws each worker's pool rotation offset for that block.
 */
export function buildLoadSchedule(levels: LoadLevels, seed: number): ScheduledBlock[] {
  const rng = mulberry32(seed);
  const ids = cellsOf(levels).map((c) => c.id);
  const Wmax = Math.max(...levels.workers);
  const blocks: ScheduledBlock[] = [];
  const n = levels.warmupBlocks + levels.measuredBlocks;
  for (let b = 0; b < n; b++) {
    const order = shuffle(ids.slice(), rng);
    const offsets = Array.from({ length: Wmax }, () => Math.floor(rng() * levels.P));
    blocks.push({ block: b, measured: b >= levels.warmupBlocks, order, offsets });
  }
  return blocks;
}

/** The R pool indices worker w verifies in a pass: a rotation starting at its block offset (each reply at most once per worker store). */
export function rotation(P: number, R: number, offset: number): number[] {
  if (R > P) throw new Error(`R (${R}) exceeds the pool (${P}): a reply can be verified once per store per pass`);
  return Array.from({ length: R }, (_, i) => (offset + i) % P);
}

/** Type-7 quantile (numpy method="linear") of a numeric array; null when empty. */
export function quantile7(xs: readonly number[], q: number): number | null {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const pos = (s.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return (s[lo] as number) + ((s[hi] as number) - (s[lo] as number)) * (pos - lo);
}

/**
 * Throughput of one pass from completion times (ms, one clock for all workers):
 * - steady: the K completions with time in [t10, t90] (type-7 quantiles of the merged completion
 *   times) span K - 1 inter-completion intervals, so the rate is (K - 1) / (t90 - t10);
 * - whole: all completions divided by (last completion - barrier release).
 * Per second; null when the span is zero or fewer than 2 completions fall in the window.
 */
export function passRates(endMs: readonly number[], releaseMs: number): { steadyPerSec: number | null; wholePerSec: number | null; t10Ms: number | null; t90Ms: number | null; lastEndMs: number | null } {
  if (endMs.length === 0) return { steadyPerSec: null, wholePerSec: null, t10Ms: null, t90Ms: null, lastEndMs: null };
  const t10 = quantile7(endMs, 0.1) as number;
  const t90 = quantile7(endMs, 0.9) as number;
  const last = Math.max(...endMs);
  const inWin = endMs.filter((t) => t >= t10 && t <= t90).length;
  const steady = inWin >= 2 && t90 > t10 ? ((inWin - 1) / (t90 - t10)) * 1000 : null;
  const whole = last > releaseMs ? (endMs.length / (last - releaseMs)) * 1000 : null;
  return { steadyPerSec: steady, wholePerSec: whole, t10Ms: t10, t90Ms: t90, lastEndMs: last };
}

export interface LoopRecord<T> {
  index: number;
  lane: number;
  startNs: bigint;
  endNs: bigint;
  value?: T;
  error?: string;
  timedOut?: boolean;
}

/**
 * Closed loop: `lanes` concurrent lanes take the next item from a shared queue as soon as their
 * previous one resolves. Each call is timed from just before fn(item) to its resolution with
 * process.hrtime.bigint(). A call that does not resolve within timeoutMs is recorded as timed
 * out; its promise keeps running, and when `late` is given a promise that settles with it is
 * pushed there, so the caller can wait for it before restoring state (load_worker.ts).
 */
export async function closedLoop<I, T>(items: readonly I[], lanes: number, fn: (item: I, index: number) => Promise<T>, timeoutMs: number, late?: Array<Promise<unknown>>): Promise<Array<LoopRecord<T>>> {
  if (!(lanes >= 1)) throw new Error("lanes must be >= 1");
  const out: Array<LoopRecord<T>> = new Array<LoopRecord<T>>(items.length);
  let next = 0;
  const lane = async (id: number): Promise<void> => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      const item = items[i] as I;
      let timer: NodeJS.Timeout | undefined;
      const startNs = process.hrtime.bigint();
      let call: Promise<T> | null = null;
      try {
        call = fn(item, i);
        const value = await Promise.race([
          call,
          new Promise<never>((_, rej) => {
            timer = setTimeout(() => rej(new LoopTimeout()), timeoutMs);
          }),
        ]);
        out[i] = { index: i, lane: id, startNs, endNs: process.hrtime.bigint(), value };
      } catch (e) {
        const endNs = process.hrtime.bigint();
        if (e instanceof LoopTimeout) {
          out[i] = { index: i, lane: id, startNs, endNs, error: `timeout after ${timeoutMs} ms`, timedOut: true };
          if (late && call) late.push(call.then(() => undefined, () => undefined));
        } else out[i] = { index: i, lane: id, startNs, endNs, error: e instanceof Error ? `${e.name}: ${e.message}` : String(e) };
      } finally {
        if (timer) clearTimeout(timer);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(lanes, Math.max(1, items.length)) }, (_, k) => lane(k)));
  return out;
}

class LoopTimeout extends Error {
  constructor() {
    super("timeout");
    this.name = "LoopTimeout";
  }
}

/**
 * Wait at most boundMs for calls that outlived their timeout. Returns how many there were and
 * how many settled in time (the rest still run).
 */
export async function settleLate(late: ReadonlyArray<Promise<unknown>>, boundMs: number): Promise<{ timedOut: number; settled: number; unsettled: number }> {
  if (late.length === 0) return { timedOut: 0, settled: 0, unsettled: 0 };
  let settled = 0;
  const all = late.map((p) => p.then(() => void settled++));
  let timer: NodeJS.Timeout | undefined;
  await Promise.race([Promise.all(all), new Promise<void>((r) => (timer = setTimeout(r, boundMs)))]);
  if (timer) clearTimeout(timer);
  return { timedOut: late.length, settled, unsettled: late.length - settled };
}

/** A wider gap (ms) between the wall-clock and the monotonic elapsed time flags a block (docs/v4/ROBUSTNESS.md 3.9). */
export const CLOCK_GAP_LIMIT_MS = 1000;
/** A longer gap (ms) between two 100 ms ticks of the parent's event loop flags a block (a stall). */
export const TICK_GAP_LIMIT_MS = 5000;

export interface ClockRecord {
  /** Monotonic clock (process.hrtime.bigint, ms since the run's epoch) at start and end. */
  monoMs: [number, number];
  /** Wall clock (Date.now, ms) at start and end. */
  wallMs: [number, number];
  /** |wall elapsed - monotonic elapsed|, ms. */
  clockGapMs: number;
  /** Longest gap between two 100 ms ticks of this thread's event loop while the watch ran, ms. */
  maxTickGapMs: number;
  /** clockGapMs above CLOCK_GAP_LIMIT_MS or maxTickGapMs above TICK_GAP_LIMIT_MS. */
  clockGap: boolean;
}

/** The clock-gap verdict from two readings of each clock and the longest tick gap (pure; unit-tested). */
export function clockVerdict(mono: [number, number], wall: [number, number], maxTickGapMs: number): ClockRecord {
  const gap = Math.abs(wall[1] - wall[0] - (mono[1] - mono[0]));
  return { monoMs: [r3(mono[0]), r3(mono[1])], wallMs: [wall[0], wall[1]], clockGapMs: r3(gap), maxTickGapMs: r3(maxTickGapMs), clockGap: gap > CLOCK_GAP_LIMIT_MS || maxTickGapMs > TICK_GAP_LIMIT_MS };
}

/**
 * Watches one stretch of the run (a block, a pass, the saturation fill): the monotonic and wall
 * clocks at start and stop, and the longest event-loop tick gap in between. A host suspend shows
 * as a wall/monotonic gap where the monotonic clock excludes suspend (Linux CLOCK_MONOTONIC); a
 * long stall of the process shows as a tick gap.
 */
export class ClockWatch {
  private readonly mono0 = process.hrtime.bigint();
  private readonly wall0 = Date.now();
  private last = this.mono0;
  private maxGapNs = 0n;
  private readonly timer: NodeJS.Timeout;
  constructor(private readonly epochNs: bigint = 0n) {
    this.timer = setInterval(() => {
      const t = process.hrtime.bigint();
      if (t - this.last > this.maxGapNs) this.maxGapNs = t - this.last;
      this.last = t;
    }, 100);
    this.timer.unref();
  }
  stop(): ClockRecord {
    clearInterval(this.timer);
    const mono1 = process.hrtime.bigint();
    const wall1 = Date.now();
    const tail = mono1 - this.last;
    const maxGap = tail > this.maxGapNs ? tail : this.maxGapNs;
    return clockVerdict([nsToMs(this.mono0 - this.epochNs), nsToMs(mono1 - this.epochNs)], [this.wall0, wall1], nsToMs(maxGap));
  }
}

/** ms (float) between two hrtime values. */
export function nsToMs(ns: bigint): number {
  return Number(ns) / 1e6;
}

/** Round to 1 microsecond for records. */
export function r3(x: number): number {
  return Math.round(x * 1000) / 1000;
}

// ------------------------------------------------------------------ Linux /proc readers (Windows: null, host rule D-021)

/** Threads of a process (Linux /proc/<pid>/status), else null. */
export function linuxThreads(pid: number): number | null {
  if (process.platform !== "linux") return null;
  try {
    const m = /^Threads:\s+(\d+)/m.exec(fs.readFileSync(`/proc/${pid}/status`, "utf8"));
    return m ? Number(m[1]) : null;
  } catch {
    return null;
  }
}

/** utime + stime of a process in clock ticks (Linux /proc/<pid>/stat), else null. */
export function linuxCpuTicks(pid: number): number | null {
  if (process.platform !== "linux") return null;
  try {
    const t = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const rest = t.slice(t.lastIndexOf(")") + 2).split(" ");
    return Number(rest[11]) + Number(rest[12]);
  } catch {
    return null;
  }
}
