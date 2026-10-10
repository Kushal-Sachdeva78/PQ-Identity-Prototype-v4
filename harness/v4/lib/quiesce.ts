import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { FORBIDDEN, CPU_THRESHOLD_PERCENT } from "../bench/guard.ts";
import { sanitize } from "../bench/lib.ts";
import { CHAIN_PROBE_PORTS } from "./ports.ts";

/**
 * Quiet-machine check for the D-034 series, excluding the runner's own processes by pid.
 *
 * harness/v4/bench/guard.ts (frozen, used by Phase D) flags any process named anvil, besu or
 * java, so a series that starts its own chain node would always read as busy, and excluding
 * those names would let a foreign node through. This check instead excludes exactly the
 * runner's own processes: process.pid, the pids the caller passes (for example the Besu JVMs
 * from setup_qbft.sh pid files, which are not children of the runner) and, on Linux, every
 * descendant of those (by the ppid tree in /proc). It never excludes by name.
 *
 * What it reads, per platform:
 * - Linux and WSL2: /proc/<pid>/stat for every process at the start and end of the window
 *   (name, ppid, CPU ticks) and /proc/stat; foreign processes are classified as chain nodes,
 *   listed tools (guard.ts FORBIDDEN) or heavy (CPU share of one core over the window).
 * - Windows: no process list (docs/BENCHMARK_POLICY.md: the power query is the only Windows-specific call);
 *   foreign chain nodes are found only by the loopback port probe, and load only as the
 *   machine-wide CPU busy figure.
 * - Both: machine-wide CPU busy percent with the guard.ts formula (os.cpus() tick counters),
 *   and a TCP connect to 127.0.0.1 on the known chain ports, minus the runner's own ports.
 * A WSL2 reading covers the Linux VM only: it cannot see Windows processes or Windows load
 * (D-034: nothing else runs on Windows during a WSL window). The record says so; on Linux it
 * also records the steal share of /proc/stat, the only in-guest sign of host contention.
 *
 * Three verdicts, all from the same window:
 * - quiesced: this module's rule (own processes excluded by pid; on Linux the 35 % threshold
 *   applies to machine busy minus the runner's own processes). For the chain-read,
 *   robustness and end-to-end series.
 * - machineWideQuiesced: cpuBusyPercent <= threshold with the guard.ts formula, on every
 *   platform: the like-for-like CPU flag across Windows and WSL readings.
 * - guardTs: the guard.ts readQuiesce rule replayed on this window (machine-wide CPU, and on
 *   Linux any process, own or not, whose name is on the guard.ts list). A Phase D repeat or a
 *   comparable-benchmark series that reports quiet flags next to Phase D's uses guard.ts
 *   itself or this field, never `quiesced`.
 * The reading also records wall-clock and monotonic time over the window: a host suspend or a
 * VM pause shows as a gap between them (more than 1 s makes the reading busy).
 *
 * Never throws: failures are written into the record. Process names are passed through the
 * bench sanitizer; no command lines, paths, user names or host names are read or written.
 *
 * Names are informative only. Under Node 24 on Linux a node process shows as "MainThread" in
 * /proc (its main thread's name), and JavaScript tools (tsc, eslint, vitest) run as node, so
 * the name list cannot see them; the heavy rule (CPU share of one core) does.
 */

export const QUIESCE_SCHEMA = "pqid/v4-quiesce/v1";

/** Process names of chain nodes (Besu runs as java). */
export const CHAIN_PROCESS_NAMES: readonly string[] = Object.freeze(["anvil", "besu", "java", "geth", "reth", "erigon", "nethermind"]);

/** A foreign process using more than this share of one core over the window is heavy. */
export const HEAVY_CORE_PERCENT = 50;

/** A wall-clock minus monotonic gap above this over the window makes the reading busy (suspend, VM pause or clock step). */
export const CLOCK_GAP_LIMIT_MS = 1000;

export interface QuiesceOptions {
  /** Pids of the runner's own processes (chain nodes, provers). process.pid is always own. */
  ownPids?: readonly number[];
  /** Linux: also treat descendants of process.pid and ownPids as own (default true). */
  includeDescendants?: boolean;
  /** Loopback ports the runner's own nodes listen on (excluded from the probe). */
  ownPorts?: readonly number[];
  /** Ports to probe (default CHAIN_PROBE_PORTS: D-034 ports plus fixed ports of committed code). */
  chainPorts?: readonly number[];
  /** Per-port connect timeout; no answer within it counts as closed (default 400 ms). */
  probeTimeoutMs?: number;
  /** CPU sample window (default 3000 ms, as guard.ts). */
  windowMs?: number;
  /** Busy threshold in percent (default guard.ts CPU_THRESHOLD_PERCENT, 35). */
  thresholdPercent?: number;
  /** Share of one core above which a foreign process is heavy (default 50). */
  heavyCorePercent?: number;
}

export interface ProcEntry {
  pid: number;
  ppid: number;
  name: string;
  /** utime + stime, clock ticks. */
  ticks: number;
}

export interface ProcUse {
  pid: number;
  name: string;
  /** CPU over the window, percent of one core. null when the process ended during the window. */
  cpuPercentOfCore: number | null;
}

export interface QuiesceRecord {
  schema: typeof QUIESCE_SCHEMA;
  utc: string;
  environment: "windows" | "wsl2" | "linux" | string;
  windowMs: number;
  /** Machine-wide busy percent over the window, guard.ts formula (os.cpus() ticks, all logical cores). */
  cpuBusyPercent: number | null;
  cpuBasis: string;
  /** Linux: machine busy from /proc/stat minus the runner's own processes. null on Windows. */
  foreignCpuBusyPercent: number | null;
  /** Linux: the runner's own processes' share of the machine, percent. null on Windows. */
  ownCpuPercent: number | null;
  /**
   * Linux: machine busy from /proc/stat over the window (idle and iowait count as idle; steal,
   * irq and softirq as busy). foreignCpuBusyPercent + ownCpuPercent equals it unless the
   * difference was clamped at 0. null on Windows.
   */
  procStatBusyPercent: number | null;
  /** Linux: raw /proc/stat jiffies over the window (all CPUs). null on Windows. */
  procStatJiffies: { total: number; idle: number; iowait: number; steal: number } | null;
  /** Linux: steal share of the window, percent (in WSL2 or a VM: time the host did not run this guest). null on Windows. */
  stealPercent: number | null;
  thresholdPercent: number;
  /** Which figure was compared with the threshold for `quiesced`. */
  thresholdBasis: string;
  /** cpuBusyPercent (guard.ts formula) <= thresholdPercent, or no figure; every platform. */
  machineWideQuiesced: boolean;
  /** The guard.ts readQuiesce rule replayed on this window (for comparisons with Phase D). */
  guardTs: {
    quiesced: boolean;
    /** Listed names seen (own processes included, as guard.ts does), "namexN" when several. */
    offending: string[];
    basis: string;
  };
  /** Wall-clock and monotonic time over the CPU window, ms; gapMs = wallMs - monotonicMs. */
  clock: { monotonicMs: number; wallMs: number; gapMs: number; limitMs: number };
  processListBasis: string;
  ownPidsGiven: number[];
  /** Linux: own processes found (given pids, process.pid and descendants). */
  own: ProcUse[];
  foreignChain: ProcUse[];
  foreignTools: ProcUse[];
  foreignHeavy: ProcUse[];
  heavyCorePercent: number;
  portProbe: {
    basis: string;
    probed: number[];
    ownExcluded: number[];
    open: number[];
    foreignOpen: number[];
  };
  /** What this reading cannot see. */
  visibility: string;
  errors: string[];
  quiesced: boolean;
  /** Why not quiesced (empty when quiesced). */
  reasons: string[];
}

// ------------------------------------------------------------------ pure helpers (unit-tested)

/** Parse /proc/<pid>/stat. The name is between the first "(" and the last ")" (it may contain both). */
export function parseProcStat(text: string): ProcEntry | null {
  const open = text.indexOf("(");
  const close = text.lastIndexOf(")");
  if (open < 0 || close < open) return null;
  const pid = Number(text.slice(0, open).trim());
  const name = text.slice(open + 1, close);
  const rest = text.slice(close + 1).trim().split(/\s+/);
  // rest[0] state, rest[1] ppid, ..., rest[11] utime, rest[12] stime (fields 3, 4, 14, 15)
  const ppid = Number(rest[1]);
  const utime = Number(rest[11]);
  const stime = Number(rest[12]);
  if (!Number.isInteger(pid) || !Number.isInteger(ppid) || !Number.isFinite(utime) || !Number.isFinite(stime)) return null;
  return { pid, ppid, name, ticks: utime + stime };
}

/** /proc/stat aggregate "cpu" line: total and idle (idle + iowait) jiffies. guest time is inside user already. */
export function parseCpuLine(statText: string): { total: number; idle: number } | null {
  const j = parseCpuJiffies(statText);
  return j ? { total: j.total, idle: j.idle } : null;
}

/** The same line with its parts: idle = idle + iowait (as parseCpuLine), plus iowait and steal alone. */
export function parseCpuJiffies(statText: string): { total: number; idle: number; iowait: number; steal: number } | null {
  const line = statText.split("\n").find((l) => /^cpu\s/.test(l));
  if (!line) return null;
  const v = line.trim().split(/\s+/).slice(1).map(Number);
  const [user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0, steal = 0] = v;
  return { total: user + nice + system + idle + iowait + irq + softirq + steal, idle: idle + iowait, iowait, steal };
}

/** The clock part of a reading: the gap between wall-clock and monotonic time over the window, and its verdict. */
export function clockCheck(monotonicMs: number, wallMs: number, limitMs = CLOCK_GAP_LIMIT_MS): { monotonicMs: number; wallMs: number; gapMs: number; limitMs: number; reason: string | null } {
  const gapMs = Math.round((wallMs - monotonicMs) * 10) / 10;
  const reason =
    Math.abs(gapMs) > limitMs
      ? `wall clock and monotonic clock differ by ${gapMs} ms over the ${Math.round(monotonicMs)} ms window (host suspend, VM pause or clock step)`
      : null;
  return { monotonicMs: Math.round(monotonicMs * 10) / 10, wallMs, gapMs, limitMs, reason };
}

/** guard.ts readQuiesce's name rule on a process table: listed names, own processes included, "namexN" when several. */
export function guardOffending(names: Iterable<string>): string[] {
  const counts = new Map<string, number>();
  for (const raw of names) {
    const n = raw.toLowerCase();
    if (FORBIDDEN.includes(n)) counts.set(n, (counts.get(n) ?? 0) + 1);
  }
  return [...counts.entries()].map(([n, c]) => (c > 1 ? `${n}x${c}` : n));
}

/** `roots` plus every process whose ppid chain reaches one of them. */
export function withDescendants(roots: Iterable<number>, table: Iterable<Pick<ProcEntry, "pid" | "ppid">>): Set<number> {
  const children = new Map<number, number[]>();
  for (const p of table) {
    const xs = children.get(p.ppid) ?? [];
    xs.push(p.pid);
    children.set(p.ppid, xs);
  }
  const out = new Set<number>(roots);
  const stack = [...out];
  while (stack.length > 0) {
    const cur = stack.pop() as number;
    for (const c of children.get(cur) ?? []) {
      if (!out.has(c)) {
        out.add(c);
        stack.push(c);
      }
    }
  }
  return out;
}

export interface ClassifyInput {
  before: ReadonlyMap<number, ProcEntry>;
  after: ReadonlyMap<number, ProcEntry>;
  /** Total jiffies of all CPUs over the window (/proc/stat delta). */
  totalJiffies: number;
  /** Idle jiffies over the window. */
  idleJiffies: number;
  logicalCores: number;
  ownRoots: readonly number[];
  includeDescendants: boolean;
  heavyCorePercent: number;
}

export interface Classified {
  own: ProcUse[];
  foreignChain: ProcUse[];
  foreignTools: ProcUse[];
  foreignHeavy: ProcUse[];
  ownCpuPercent: number;
  machineBusyPercent: number;
  foreignCpuBusyPercent: number;
}

const r1 = (x: number) => Math.round(x * 10) / 10;

/** Split the process table into own and foreign processes (by pid) and classify the foreign ones. */
export function classifyProcesses(inp: ClassifyInput): Classified {
  const table = [...inp.after.values()];
  for (const p of inp.before.values()) if (!inp.after.has(p.pid)) table.push(p);
  const own = inp.includeDescendants ? withDescendants(inp.ownRoots, table) : new Set(inp.ownRoots);
  const tot = inp.totalJiffies > 0 ? inp.totalJiffies : 0;
  const useOf = (p: ProcEntry): ProcUse => {
    const a = inp.after.get(p.pid);
    const b = inp.before.get(p.pid);
    let pct: number | null = null;
    if (a && tot > 0) {
      const d = a.ticks - (b ? b.ticks : 0);
      pct = r1((Math.max(0, d) / tot) * inp.logicalCores * 100);
    }
    return { pid: p.pid, name: sanitize(p.name), cpuPercentOfCore: pct };
  };
  const out: Classified = { own: [], foreignChain: [], foreignTools: [], foreignHeavy: [], ownCpuPercent: 0, machineBusyPercent: 0, foreignCpuBusyPercent: 0 };
  let ownCoreSum = 0;
  for (const p of table) {
    const u = useOf(p);
    if (own.has(p.pid)) {
      out.own.push(u);
      ownCoreSum += u.cpuPercentOfCore ?? 0;
      continue;
    }
    const n = p.name.toLowerCase();
    if (CHAIN_PROCESS_NAMES.includes(n)) out.foreignChain.push(u);
    else if (FORBIDDEN.includes(n)) out.foreignTools.push(u);
    if ((u.cpuPercentOfCore ?? 0) > inp.heavyCorePercent) out.foreignHeavy.push(u);
  }
  const byPid = (a: ProcUse, b: ProcUse) => a.pid - b.pid;
  out.own.sort(byPid);
  out.foreignChain.sort(byPid);
  out.foreignTools.sort(byPid);
  out.foreignHeavy.sort((a, b) => (b.cpuPercentOfCore ?? 0) - (a.cpuPercentOfCore ?? 0));
  out.ownCpuPercent = r1(ownCoreSum / Math.max(1, inp.logicalCores));
  out.machineBusyPercent = tot > 0 ? r1((1 - inp.idleJiffies / tot) * 100) : 0;
  out.foreignCpuBusyPercent = r1(Math.max(0, out.machineBusyPercent - out.ownCpuPercent));
  return out;
}

// ------------------------------------------------------------------ probes

function isWsl(): boolean {
  if (process.platform !== "linux") return false;
  if (process.env["WSL_DISTRO_NAME"]) return true;
  try {
    return /microsoft/i.test(fs.readFileSync("/proc/version", "utf8"));
  } catch {
    return false;
  }
}

function environmentName(): string {
  if (process.platform === "win32") return "windows";
  if (process.platform === "linux") return isWsl() ? "wsl2" : "linux";
  return process.platform;
}

/** true when something accepts a TCP connection on 127.0.0.1:port within timeoutMs. */
export function probePort(port: number, timeoutMs = 400): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = net.connect({ host: "127.0.0.1", port });
    let done = false;
    const finish = (open: boolean) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      resolve(open);
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    sock.once("connect", () => finish(true));
    sock.once("error", () => finish(false));
  });
}

/** Probe every port in parallel; returns the open ones, ascending. */
export async function openPorts(ports: readonly number[], timeoutMs = 400): Promise<number[]> {
  const res = await Promise.all(ports.map(async (p) => ((await probePort(p, timeoutMs)) ? p : null)));
  return res.filter((p): p is number => p !== null).sort((a, b) => a - b);
}

function cpuTicks(): { idle: number; total: number } {
  // same formula as harness/v4/bench/guard.ts cpuBusyPercent (os.cpus() tick counters)
  let idle = 0;
  let total = 0;
  for (const c of os.cpus()) {
    const t = c.times;
    idle += t.idle;
    total += t.user + t.nice + t.sys + t.idle + t.irq;
  }
  return { idle, total };
}

function readProcTable(): Map<number, ProcEntry> {
  const out = new Map<number, ProcEntry>();
  for (const e of fs.readdirSync("/proc")) {
    if (!/^\d+$/.test(e)) continue;
    try {
      const p = parseProcStat(fs.readFileSync(`/proc/${e}/stat`, "utf8"));
      if (p) out.set(p.pid, p);
    } catch {
      /* process ended */
    }
  }
  return out;
}

/** Pids from pid files (for example the Besu JVMs of scripts/besu/setup_qbft.sh); missing or bad files are skipped. */
export function readPidFiles(files: readonly string[]): number[] {
  const out: number[] = [];
  for (const f of files) {
    try {
      const n = Number(fs.readFileSync(f, "utf8").trim());
      if (Number.isInteger(n) && n > 0) out.push(n);
    } catch {
      /* missing */
    }
  }
  return out;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, Math.max(0, ms)));

// ------------------------------------------------------------------ the reading

/** One quiet-machine reading that excludes the runner's own processes by pid. Never throws. */
export async function readQuiesceExcluding(opts: QuiesceOptions = {}): Promise<QuiesceRecord> {
  const utc = new Date().toISOString();
  const windowMs = opts.windowMs ?? 3000;
  const threshold = opts.thresholdPercent ?? CPU_THRESHOLD_PERCENT;
  const heavy = opts.heavyCorePercent ?? HEAVY_CORE_PERCENT;
  const ownPidsGiven = [...new Set((opts.ownPids ?? []).filter((p) => Number.isInteger(p) && p > 0))].sort((a, b) => a - b);
  const ownPorts = [...new Set(opts.ownPorts ?? [])].sort((a, b) => a - b);
  const probed = [...new Set(opts.chainPorts ?? CHAIN_PROBE_PORTS)].filter((p) => !ownPorts.includes(p)).sort((a, b) => a - b);
  const env = environmentName();
  const linux = process.platform === "linux";
  const errors: string[] = [];

  // Port probe first, outside the CPU window.
  let open: number[] = [];
  try {
    open = await openPorts(probed, opts.probeTimeoutMs ?? 400);
  } catch (e) {
    errors.push(sanitize(`port probe failed: ${(e as Error).message}`));
  }

  let before: Map<number, ProcEntry> | null = null;
  let after: Map<number, ProcEntry> | null = null;
  let statA: ReturnType<typeof parseCpuJiffies> = null;
  let statB: ReturnType<typeof parseCpuJiffies> = null;
  if (linux) {
    try {
      before = readProcTable();
      statA = parseCpuJiffies(fs.readFileSync("/proc/stat", "utf8"));
    } catch (e) {
      errors.push(sanitize(`/proc read failed: ${(e as Error).message}`));
    }
  }
  const ticksA = cpuTicks();
  const mono0 = process.hrtime.bigint();
  const wall0 = Date.now();
  await sleep(windowMs);
  const mono1 = process.hrtime.bigint();
  const wall1 = Date.now();
  const ticksB = cpuTicks();
  if (linux && before) {
    try {
      after = readProcTable();
      statB = parseCpuJiffies(fs.readFileSync("/proc/stat", "utf8"));
    } catch (e) {
      errors.push(sanitize(`/proc read failed: ${(e as Error).message}`));
    }
  }
  const dt = ticksB.total - ticksA.total;
  const cpuBusyPercent = dt > 0 ? r1((1 - (ticksB.idle - ticksA.idle) / dt) * 100) : null;
  const clock = clockCheck(Number(mono1 - mono0) / 1e6, wall1 - wall0);
  const jiffies =
    statA && statB
      ? { total: statB.total - statA.total, idle: statB.idle - statA.idle, iowait: statB.iowait - statA.iowait, steal: statB.steal - statA.steal }
      : null;
  const stealPercent = jiffies && jiffies.total > 0 ? r1((jiffies.steal / jiffies.total) * 100) : null;

  let cls: Classified | null = null;
  if (linux && before && after && jiffies) {
    cls = classifyProcesses({
      before,
      after,
      totalJiffies: jiffies.total,
      idleJiffies: jiffies.idle,
      logicalCores: os.cpus().length,
      ownRoots: [process.pid, ...ownPidsGiven],
      includeDescendants: opts.includeDescendants !== false,
      heavyCorePercent: heavy,
    });
  }

  const foreignOpen = open.filter((p) => !ownPorts.includes(p));
  const reasons: string[] = [];
  let thresholdBasis: string;
  if (cls) {
    thresholdBasis = "foreignCpuBusyPercent (/proc/stat machine busy minus the runner's own processes)";
    if (cls.foreignCpuBusyPercent > threshold) reasons.push(`foreign CPU busy ${cls.foreignCpuBusyPercent} % > ${threshold} %`);
    if (cls.foreignChain.length > 0) reasons.push(`foreign chain process: ${cls.foreignChain.map((p) => `${p.name}[${p.pid}]`).join(", ")}`);
    if (cls.foreignTools.length > 0) reasons.push(`listed tool running: ${cls.foreignTools.map((p) => `${p.name}[${p.pid}]`).join(", ")}`);
    if (cls.foreignHeavy.length > 0) reasons.push(`heavy foreign process: ${cls.foreignHeavy.map((p) => `${p.name}[${p.pid}] ${p.cpuPercentOfCore} %`).join(", ")}`);
  } else {
    thresholdBasis = "cpuBusyPercent (machine-wide; own processes cannot be separated here)";
    if (cpuBusyPercent !== null && cpuBusyPercent > threshold) reasons.push(`CPU busy ${cpuBusyPercent} % > ${threshold} %`);
    if (linux) reasons.push("process table not read: own and foreign processes not checked");
  }
  if (foreignOpen.length > 0) reasons.push(`foreign listener on chain port(s) ${foreignOpen.join(", ")}`);
  if (clock.reason) reasons.push(clock.reason);

  // guard.ts readQuiesce rule on the same window (machine-wide CPU; Linux: listed names, own included)
  const machineWideQuiesced = cpuBusyPercent === null || cpuBusyPercent <= threshold;
  const guardNames = linux ? [...(after ?? before ?? new Map<number, ProcEntry>()).values()].map((p) => p.name) : [];
  const guardTs = {
    quiesced: machineWideQuiesced && guardOffending(guardNames).length === 0,
    offending: guardOffending(guardNames).map((n) => sanitize(n)),
    basis: linux
      ? before
        ? "guard.ts readQuiesce rule: cpuBusyPercent <= threshold and no process (own or foreign) named on the guard.ts list (/proc names at the end of the window)"
        : "guard.ts readQuiesce rule: /proc read failed, so only cpuBusyPercent <= threshold was checked (as guard.ts does)"
      : "guard.ts readQuiesce rule: cpuBusyPercent <= threshold (no process list on this platform, as guard.ts)",
  };

  const processListBasis = linux
    ? cls
      ? "Linux /proc/<pid>/stat (name, ppid, CPU ticks) at both ends of the window; own = process.pid, given pids" + (opts.includeDescendants !== false ? " and their descendants" : "") + "; exclusion by pid, never by name"
      : "Linux /proc read failed"
    : process.platform === "win32"
      ? "not read on Windows (docs/BENCHMARK_POLICY.md host rule: the power query is the only Windows-specific call); foreign chain nodes only by the port probe"
      : `not read on ${process.platform}`;

  const visibility =
    env === "wsl2"
      ? "WSL2 guest: the process list, CPU figures and port probe cover the Linux VM only; Windows processes and Windows load are not visible (D-034: nothing else runs on Windows during a WSL window). In NAT mode the probe does not reach Windows listeners."
      : env === "windows"
        ? "Windows host: no process list; CPU busy is machine-wide (includes the WSL2 VM and any other load); WSL2 listeners on 127.0.0.1 are seen through localhost forwarding when it is on."
        : "Linux host: the process list and CPU figures cover this OS.";

  return {
    schema: QUIESCE_SCHEMA,
    utc,
    environment: env,
    windowMs,
    cpuBusyPercent,
    cpuBasis: `os.cpus() tick counters, ${windowMs / 1000} s window, all logical cores (guard.ts formula)`,
    foreignCpuBusyPercent: cls ? cls.foreignCpuBusyPercent : null,
    ownCpuPercent: cls ? cls.ownCpuPercent : null,
    procStatBusyPercent: cls ? cls.machineBusyPercent : null,
    procStatJiffies: jiffies,
    stealPercent,
    thresholdPercent: threshold,
    thresholdBasis,
    machineWideQuiesced,
    guardTs,
    clock: { monotonicMs: clock.monotonicMs, wallMs: clock.wallMs, gapMs: clock.gapMs, limitMs: clock.limitMs },
    processListBasis,
    ownPidsGiven,
    own: cls ? cls.own : [],
    foreignChain: cls ? cls.foreignChain : [],
    foreignTools: cls ? cls.foreignTools : [],
    foreignHeavy: cls ? cls.foreignHeavy : [],
    heavyCorePercent: heavy,
    portProbe: {
      basis: `TCP connect to 127.0.0.1, ${opts.probeTimeoutMs ?? 400} ms timeout (refused or no answer = closed); the runner's own ports excluded`,
      probed,
      ownExcluded: ownPorts,
      open,
      foreignOpen,
    },
    visibility,
    errors,
    quiesced: reasons.length === 0,
    reasons,
  };
}

// CLI: `node --import tsx harness/v4/lib/quiesce.ts [--own-pid N ...] [--own-port P ...]` prints one reading.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const nums = (name: string) => argv.flatMap((a, i) => (a === `--${name}` && argv[i + 1] !== undefined ? [Number(argv[i + 1])] : []));
  void readQuiesceExcluding({ ownPids: nums("own-pid"), ownPorts: nums("own-port") }).then((r) => console.log(JSON.stringify(r, null, 2)));
}
