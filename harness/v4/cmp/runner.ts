import fs from "node:fs";
import path from "node:path";
import { opt, rel, utcNow } from "../bench/lib.ts";
import { acquireMarker, assertMarkersFree, markerRoots, windowsRepoFromArgs, MARKER_REL, type MarkerKind, type MarkerRoot } from "../lib/markers.ts";
import type { QuiesceRecord } from "../lib/quiesce.ts";

/**
 * Shared pieces of the cmp runners (cold.ts, warm.ts, inputs.ts): work markers, the smoke
 * lock, the quiet-machine view and the idle clock. Node built-ins and repository modules only.
 */

// ------------------------------------------------------------------ markers

export interface WorkHold {
  release: () => void;
  /** What was held, for env.json (repo-relative paths only). */
  record: {
    kind: MarkerKind | "smoke-lock";
    paths: string[];
    rule: string;
    borrowed?: boolean;
    /** Smoke runs only: the marker mode and the lock inside _smoke/. */
    smoke?: { markerMode: "BUSY" | "none (--smoke-no-marker)"; lock: string };
  };
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Lock file inside the _smoke/ root, held by every smoke run (with or without results/v4/BUSY),
 * so two smoke runs, or a smoke run and the smoke reset, do not overlap. Smoke runs never write
 * results/v4/bench/RUNNING.
 */
export function holdSmokeLock(smokeRoot: string, campaign: string): () => void {
  fs.mkdirSync(smokeRoot, { recursive: true });
  const lock = path.join(smokeRoot, "SMOKE_LOCK");
  try {
    fs.writeFileSync(lock, JSON.stringify({ campaign, pid: process.pid, startedUtc: utcNow() }) + "\n", { flag: "wx" });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    let other: { pid?: number; campaign?: string } = {};
    try {
      other = JSON.parse(fs.readFileSync(lock, "utf8")) as typeof other;
    } catch {
      /* unreadable: treat as stale */
    }
    if (typeof other.pid === "number" && pidAlive(other.pid)) throw new Error(`${rel(lock)} held by a live smoke run (${other.campaign ?? "?"})`);
    fs.writeFileSync(lock, JSON.stringify({ campaign, pid: process.pid, startedUtc: utcNow() }) + "\n");
  }
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    try {
      const cur = JSON.parse(fs.readFileSync(lock, "utf8")) as { pid?: number };
      if (cur.pid === process.pid) fs.rmSync(lock, { force: true });
    } catch {
      /* gone */
    }
  };
  process.on("exit", release);
  return release;
}

/**
 * Real runs hold the D-034 marker of their kind (RUNNING for timed series, BUSY for untimed
 * CPU-heavy work) through harness/v4/lib/markers.ts, which refuses while either exists and lets a
 * runner borrow the hold of a wrapping `markers.ts run` (PQID_MARKER_TOKEN).
 *
 * Smoke runs are untimed CPU-heavy work: by default they hold results/v4/BUSY (own or borrowed)
 * and the smoke lock. With `smokeNoMarker` (--smoke-no-marker, for agent tasks that may not write
 * markers) they only check that no marker exists and hold the smoke lock.
 */
export function holdWork(opts: {
  kind: MarkerKind;
  smoke: boolean;
  smokeNoMarker?: boolean;
  smokeRoot: string;
  campaign: string;
  runner: string;
  argv: readonly string[];
  note?: string;
  /** Repositories to check and write (default: this checkout, plus --windows-repo); tests pass a temporary one. */
  roots?: readonly MarkerRoot[];
}): WorkHold {
  const windowsRepo = windowsRepoFromArgs(opts.argv);
  const roots = opts.roots ?? markerRoots(windowsRepo !== undefined ? { windowsRepo } : {});
  const owner = opt(opts.argv, "owner");
  const lockRel = rel(path.join(opts.smokeRoot, "SMOKE_LOCK"));
  if (opts.smoke && opts.smokeNoMarker) {
    assertMarkersFree(roots, "BUSY");
    const release = holdSmokeLock(opts.smokeRoot, opts.campaign);
    return {
      release,
      record: {
        kind: "smoke-lock",
        paths: [lockRel],
        rule: "smoke with --smoke-no-marker: refused while results/v4/bench/RUNNING or results/v4/BUSY existed; held only a lock inside _smoke/",
        smoke: { markerMode: "none (--smoke-no-marker)", lock: lockRel },
      },
    };
  }
  const kind: MarkerKind = opts.smoke ? "BUSY" : opts.kind;
  const h = acquireMarker({
    kind,
    campaign: opts.smoke ? `${opts.campaign} (smoke)` : opts.campaign,
    runner: opts.runner,
    roots,
    ...(owner ? { owner } : {}),
    ...(opts.note ? { note: opts.smoke ? `smoke test: ${opts.note}` : opts.note } : {}),
  });
  if (!opts.smoke) {
    return { release: () => h.release(), record: { kind, paths: h.copies.map((c) => `${c.via}:${c.rel}`), rule: h.record.rule, borrowed: h.borrowed } };
  }
  let releaseLock: () => void;
  try {
    releaseLock = holdSmokeLock(opts.smokeRoot, opts.campaign);
  } catch (e) {
    h.release();
    throw e;
  }
  return {
    release: () => {
      releaseLock();
      h.release();
    },
    record: {
      kind,
      paths: [...h.copies.map((c) => `${c.via}:${c.rel}`), lockRel],
      rule: `smoke test (untimed CPU-heavy work, D-034): ${h.record.rule}`,
      borrowed: h.borrowed,
      smoke: { markerMode: "BUSY", lock: lockRel },
    },
  };
}

export { MARKER_REL };

// ------------------------------------------------------------------ quiet machine

/**
 * The quiet-machine fields of a cmp run, in the shape of a Phase D record
 * (harness/v4/bench/guard.ts QuiesceReport), taken from one harness/v4/lib/quiesce.ts reading.
 *
 * `quiesced` here is the guard.ts readQuiesce rule replayed on the same window (`guardTs`), not
 * the stricter D-034 rule of quiesce.ts (`quiesced` of the full record, which also counts a
 * foreign listener on a chain port and a clock gap inside the window). The lib asks a series
 * that reports quiet flags next to Phase D's to use guard.ts or `guardTs`, never `quiesced`.
 * So the postpone rule and the `quiesce.quiesced` flag that scripts/bench/analyze.py and
 * scripts/cmp/analyze_cmp.py count mean what they meant in Phase D. The full reading is kept
 * next to it as `quiesceDetail`.
 */
export interface PhaseDQuiesce {
  utc: string;
  cpuBusyPercent: number | null;
  cpuBasis: string;
  processListBasis: string;
  /** guard.ts counts node processes on Linux; quiesce.ts does not, so always null here. */
  nodeProcesses: null;
  offending: string[];
  quiesced: boolean;
  thresholdPercent: number;
  rule: string;
}

export const PHASE_D_QUIET_RULE =
  "guard.ts readQuiesce rule (Phase D: machine-wide CPU busy <= threshold, and on Linux no process named on the guard.ts list), replayed by harness/v4/lib/quiesce.ts on the same window (guardTs); the full reading is quiesceDetail";

export function phaseDQuiesce(q: QuiesceRecord): PhaseDQuiesce {
  return {
    utc: q.utc,
    cpuBusyPercent: q.cpuBusyPercent,
    cpuBasis: q.cpuBasis,
    processListBasis: q.processListBasis,
    nodeProcesses: null,
    offending: [...q.guardTs.offending],
    quiesced: q.guardTs.quiesced,
    thresholdPercent: q.thresholdPercent,
    rule: PHASE_D_QUIET_RULE,
  };
}

// ------------------------------------------------------------------ idle clock and host-pause watchdog

/** A gap above this (seconds) between the clocks over one idle, or between two watchdog wake-ups, flags a host pause. */
export const HOST_PAUSE_GAP_SEC = 5;
/** Longest single sleep of a watched idle (ms): the watchdog wakes at least this often. */
export const WATCH_TICK_MS = 1000;

export interface IdleReading {
  /** Monotonic idle (performance.now), seconds, 0.1 s resolution (as Phase D idleSec). */
  idleSec: number;
  /** Wall-clock idle (Date.now), seconds. */
  idleWallSec: number;
  /** idleWallSec - idleSec: time one clock saw and the other did not (host standby or a VM pause), seconds. */
  clockGapSec: number;
  /**
   * Largest gap between two consecutive watchdog wake-ups during the watched sleeps of the idle,
   * the larger of the monotonic and the wall-clock gap, seconds (expected about 1). A frozen
   * process wakes late by the length of the pause, whichever clock counts it.
   */
  idleMaxTickGapSec: number;
  /** The two clocks' largest wake-up gaps and the number of wake-ups. */
  idleTickGap: { monoSec: number; wallSec: number; wakeups: number };
  /** |clockGapSec| > 5 s or idleMaxTickGapSec > 5 s. */
  hostPauseSuspected: boolean;
}

const r1 = (sec: number) => Math.round(sec * 10) / 10;

/**
 * Idle reading from the start and end of both clocks plus the watchdog's largest wake-up gaps
 * (milliseconds). Pure.
 */
export function idleReading(
  monoStartMs: number,
  wallStartMs: number,
  monoNowMs: number,
  wallNowMs: number,
  tick: { monoMs: number; wallMs: number; wakeups: number } = { monoMs: 0, wallMs: 0, wakeups: 0 },
  thresholdSec = HOST_PAUSE_GAP_SEC
): IdleReading {
  const idleSec = Math.round((monoNowMs - monoStartMs) / 100) / 10;
  const idleWallSec = Math.round((wallNowMs - wallStartMs) / 100) / 10;
  const clockGapSec = r1(idleWallSec - idleSec);
  const monoSec = r1(tick.monoMs / 1000);
  const wallSec = r1(tick.wallMs / 1000);
  const idleMaxTickGapSec = Math.max(monoSec, wallSec);
  return {
    idleSec,
    idleWallSec,
    clockGapSec,
    idleMaxTickGapSec,
    idleTickGap: { monoSec, wallSec, wakeups: tick.wakeups },
    hostPauseSuspected: Math.abs(clockGapSec) > thresholdSec || idleMaxTickGapSec > thresholdSec,
  };
}

export interface Clock {
  mono(): number;
  wall(): number;
}
export const SYSTEM_CLOCK: Clock = { mono: () => performance.now(), wall: () => Date.now() };

/** Both clocks at one instant. */
export function clocks(clock: Clock = SYSTEM_CLOCK): { mono: number; wall: number } {
  return { mono: clock.mono(), wall: clock.wall() };
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, Math.max(0, ms)));
}

/**
 * The idle between two cold runs, with a host-pause watchdog. On Windows performance.now() is
 * QueryPerformanceCounter, which may keep counting through standby, so the gap between the clocks
 * alone may not show a standby; the watchdog sleeps in steps of at most 1 s and records the largest
 * gap between consecutive wake-ups on both clocks. Only the watched sleeps are measured: the time
 * spent in power and quiet-machine readings between them is not counted as a gap.
 */
export class IdleWatch {
  private start = { mono: 0, wall: 0 };
  private last = { mono: 0, wall: 0 };
  private maxMonoMs = 0;
  private maxWallMs = 0;
  private wakeups = 0;

  constructor(
    private readonly clock: Clock = SYSTEM_CLOCK,
    private readonly sleepFn: (ms: number) => Promise<void> = sleep,
    private readonly tickMs: number = WATCH_TICK_MS
  ) {
    this.restart();
  }

  /** Start a new idle now (after a run ended, or at the campaign start). */
  restart(): void {
    this.start = clocks(this.clock);
    this.last = { ...this.start };
    this.maxMonoMs = 0;
    this.maxWallMs = 0;
    this.wakeups = 0;
  }

  get startMono(): number {
    return this.start.mono;
  }

  /** Sleep `ms` (monotonic) in steps of at most tickMs, recording the wake-up gaps. */
  async sleep(ms: number): Promise<void> {
    const end = this.clock.mono() + Math.max(0, ms);
    this.last = clocks(this.clock); // a new watched segment: time outside watched sleeps is not a gap
    for (;;) {
      const left = end - this.clock.mono();
      if (left <= 0) return;
      await this.sleepFn(Math.min(this.tickMs, left));
      const now = clocks(this.clock);
      this.maxMonoMs = Math.max(this.maxMonoMs, now.mono - this.last.mono);
      this.maxWallMs = Math.max(this.maxWallMs, now.wall - this.last.wall);
      this.wakeups++;
      this.last = now;
    }
  }

  /** Sleep until the monotonic clock reaches `startMono + offsetMs`. */
  sleepUntilOffset(offsetMs: number): Promise<void> {
    return this.sleep(this.start.mono + offsetMs - this.clock.mono());
  }

  /** The idle so far. */
  reading(thresholdSec = HOST_PAUSE_GAP_SEC): IdleReading {
    const now = clocks(this.clock);
    return idleReading(this.start.mono, this.start.wall, now.mono, now.wall, { monoMs: this.maxMonoMs, wallMs: this.maxWallMs, wakeups: this.wakeups }, thresholdSec);
  }
}

// ------------------------------------------------------------------ misc

export function assertCampaignName(c: string | undefined): string {
  if (!c || !/^[a-z0-9_]+$/.test(c)) throw new Error("--campaign must match [a-z0-9_]");
  return c;
}

/** JSON equality with stable key order at the top level of each object (enough for config records). */
export function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}
