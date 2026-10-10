import fs from "node:fs";
import { execFileSync } from "node:child_process";

/**
 * Host facts for the chain-read series: environment, CPU pinning (Linux and WSL2 only) and the
 * host-pause / clock-gap record (docs/v4/CHAINREAD.md).
 *
 * Pinning: `taskset -a -cp <cpus> <pid>` sets the mask of EVERY existing thread of a process;
 * threads created later inherit the mask of the thread that creates them. The read-back reads
 * /proc/<pid>/task/<tid>/status (Cpus_allowed_list) of every thread, so a thread that escaped
 * is found. On the Windows host nothing is pinned or read (DECISIONS D-021; docs/BENCHMARK_POLICY.md allows only
 * the power query as a Windows-specific call).
 */

export function isWsl(): boolean {
  if (process.platform !== "linux") return false;
  if (process.env["WSL_DISTRO_NAME"]) return true;
  try {
    return /microsoft/i.test(fs.readFileSync("/proc/version", "utf8"));
  } catch {
    return false;
  }
}

export type EnvName = "windows" | "wsl2" | "linux";

export function environmentName(): EnvName {
  if (process.platform === "win32") return "windows";
  if (process.platform === "linux") return isWsl() ? "wsl2" : "linux";
  throw new Error(`unsupported platform ${process.platform}`);
}

/** "0", "1", "4-7", "0,2-3" -> sorted CPU numbers. */
export function cpuList(spec: string): number[] {
  const out = new Set<number>();
  for (const part of spec.split(",")) {
    const t = part.trim();
    if (t === "") continue;
    const m = /^(\d+)(?:-(\d+))?$/.exec(t);
    if (!m) throw new Error(`bad CPU list ${JSON.stringify(spec)}`);
    const lo = Number(m[1]);
    const hi = m[2] === undefined ? lo : Number(m[2]);
    if (hi < lo) throw new Error(`bad CPU range ${t}`);
    for (let i = lo; i <= hi; i++) out.add(i);
  }
  return [...out].sort((a, b) => a - b);
}

export interface ThreadAffinity {
  tid: number;
  cpus: string;
}

export interface AffinityCheck {
  pid: number;
  role: string;
  expected: string;
  threads: number;
  /** Threads whose mask is not the expected CPU set. */
  mismatches: ThreadAffinity[];
  ok: boolean;
  error: string | null;
}

/** Cpus_allowed_list of every thread of `pid` (Linux). */
export function readThreadAffinity(pid: number): ThreadAffinity[] {
  const out: ThreadAffinity[] = [];
  for (const t of fs.readdirSync(`/proc/${pid}/task`)) {
    if (!/^\d+$/.test(t)) continue;
    try {
      const st = fs.readFileSync(`/proc/${pid}/task/${t}/status`, "utf8");
      const m = /^Cpus_allowed_list:\s*(.+)$/m.exec(st);
      if (m?.[1]) out.push({ tid: Number(t), cpus: m[1].trim() });
    } catch {
      /* thread ended */
    }
  }
  return out.sort((a, b) => a.tid - b.tid);
}

/** Compare every thread's mask with the expected CPU list. Never throws. */
export function checkAffinity(pid: number, role: string, expected: string): AffinityCheck {
  try {
    const want = cpuList(expected).join(",");
    const threads = readThreadAffinity(pid);
    const mismatches = threads.filter((t) => cpuList(t.cpus).join(",") !== want);
    return { pid, role, expected, threads: threads.length, mismatches, ok: threads.length > 0 && mismatches.length === 0, error: threads.length === 0 ? "no threads read" : null };
  } catch (e) {
    return { pid, role, expected, threads: 0, mismatches: [], ok: false, error: (e as Error).message };
  }
}

/** taskset -a -cp <cpus> <pid> (Linux only). */
export function pinAllThreads(pid: number, cpus: string): void {
  if (process.platform !== "linux") throw new Error("pinning is used on Linux and WSL2 only (D-021: none on the Windows host)");
  cpuList(cpus);
  execFileSync("taskset", ["-a", "-cp", cpus, String(pid)], { stdio: ["ignore", "ignore", "pipe"] });
}

export interface PinTopology {
  harness: string;
  anvil: string;
  besu: string;
}

export const DEFAULT_TOPOLOGY: PinTopology = Object.freeze({ harness: "0", anvil: "1", besu: "4-7" });

export function parseTopology(spec: string | undefined): PinTopology {
  if (!spec) return { ...DEFAULT_TOPOLOGY };
  const out: PinTopology = { ...DEFAULT_TOPOLOGY };
  for (const part of spec.split(/[;\s]+/).filter(Boolean)) {
    const [k, v] = part.split("=");
    if (!v || (k !== "harness" && k !== "anvil" && k !== "besu")) throw new Error(`--cpus expects harness=..;anvil=..;besu=.. (got ${part})`);
    cpuList(v);
    out[k] = v;
  }
  return out;
}

// ---------------------------------------------------------------------------------------
// host pause and clock gaps
// ---------------------------------------------------------------------------------------

export interface ClockRecord {
  monoStartMs: number;
  monoEndMs: number;
  wallStartUtc: string;
  wallEndUtc: string;
  monoSpanMs: number;
  wallSpanMs: number;
  /** wallSpan - monoSpan: a host pause in which the monotonic clock stopped shows here. */
  driftMs: number;
  samples: number;
  /** Longest single sample, ms (a pause in which the monotonic clock ran shows here). */
  maxSampleMs: number;
  /** Longest time between the end of one sample and the start of the next, minus the planned spacing, ms. */
  maxGapExcessMs: number;
  thresholds: { driftMs: number; gapExcessMs: number; sampleMs: number };
  hostPauseSuspected: boolean;
  reasons: string[];
}

const HR0 = process.hrtime.bigint();
export const monoMs = (t: bigint = process.hrtime.bigint()) => Number(t - HR0) / 1e6;

/**
 * Per-pass clock watch, passive (no timer of its own): the series report each sample's start and
 * end; at the end of the pass the record compares wall-clock and monotonic spans and flags long
 * gaps and samples. Thresholds are fixed in docs/v4/CHAINREAD.md.
 */
export class PassClock {
  private readonly mono0 = process.hrtime.bigint();
  private readonly wall0: number;
  private n = 0;
  private maxSample = 0;
  private maxGap = 0;
  private lastEnd: bigint | null = null;

  /** `wallNow` is Date.now unless a test injects a clock. */
  constructor(
    private readonly plannedGapMs = 0,
    private readonly thresholds = { driftMs: 1000, gapExcessMs: 2000, sampleMs: 10_000 },
    private readonly wallNow: () => number = Date.now
  ) {
    this.wall0 = this.wallNow();
  }

  sample(t0: bigint, t1: bigint): void {
    this.n++;
    this.maxSample = Math.max(this.maxSample, Number(t1 - t0) / 1e6);
    if (this.lastEnd !== null) this.maxGap = Math.max(this.maxGap, Number(t0 - this.lastEnd) / 1e6 - this.plannedGapMs);
    this.lastEnd = t1;
  }

  finish(): ClockRecord {
    const mono1 = process.hrtime.bigint();
    const wall1 = this.wallNow();
    const monoSpanMs = Number(mono1 - this.mono0) / 1e6;
    const wallSpanMs = wall1 - this.wall0;
    const driftMs = wallSpanMs - monoSpanMs;
    const reasons: string[] = [];
    if (Math.abs(driftMs) > this.thresholds.driftMs) reasons.push(`wall-clock and monotonic spans differ by ${driftMs.toFixed(0)} ms`);
    if (this.maxGap > this.thresholds.gapExcessMs) reasons.push(`gap of ${this.maxGap.toFixed(0)} ms beyond the planned spacing between two samples`);
    if (this.maxSample > this.thresholds.sampleMs) reasons.push(`one sample took ${this.maxSample.toFixed(0)} ms`);
    return {
      monoStartMs: monoMs(this.mono0),
      monoEndMs: monoMs(mono1),
      wallStartUtc: new Date(this.wall0).toISOString(),
      wallEndUtc: new Date(wall1).toISOString(),
      monoSpanMs,
      wallSpanMs,
      driftMs,
      samples: this.n,
      maxSampleMs: this.maxSample,
      maxGapExcessMs: Math.max(0, this.maxGap),
      thresholds: { ...this.thresholds },
      hostPauseSuspected: reasons.length > 0,
      reasons,
    };
  }
}
