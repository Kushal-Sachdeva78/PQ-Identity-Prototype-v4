import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

/**
 * v4 benchmark guard (docs/v4/BENCH_PROTOCOL.md, "Power" and "Quiet machine").
 * Modelled on harness/bench_env.ts, which stays unchanged. Differences: it never calls
 * wsl.exe, it never refuses to run (it reports; the campaign postpones or discards by
 * rule), and it records nothing that identifies the user or the host.
 *
 * Windows-specific calls: exactly one, the read-only power query (Win32_Battery through
 * powershell.exe). docs/BENCHMARK_POLICY.md allows no other, so on Windows the quiet-machine reading uses
 * only portable Node APIs (CPU load from os.cpus() tick counters) and reads no process list.
 * On Linux the process names come from /proc and power from /sys; inside WSL the power
 * query (and only it) goes through powershell.exe.
 */

export interface PowerReading {
  /** true only when the rule below says mains power. */
  ac: boolean;
  /** Raw status: Win32_Battery.BatteryStatus codes joined by ",", "no-battery", sysfs summary or "query-failed". */
  code: string;
  source: "win32-battery" | "wsl-powershell" | "linux-sysfs" | "none";
  utc: string;
}

/**
 * Windows rule (brief): AC iff every Win32_Battery.BatteryStatus == 2. No battery object
 * (desktop) counts as AC with code "no-battery". Any other code, or a failed query, is
 * NOT AC (the run is discarded and repeated).
 */
const PS_POWER =
  "$b = @(Get-CimInstance Win32_Battery -ErrorAction Stop | ForEach-Object { [int]$_.BatteryStatus }); " +
  "ConvertTo-Json -Compress -InputObject $b";

function isWsl(): boolean {
  if (process.platform !== "linux") return false;
  if (process.env["WSL_DISTRO_NAME"]) return true;
  try {
    return /microsoft/i.test(fs.readFileSync("/proc/version", "utf8"));
  } catch {
    return false;
  }
}

function powershellPowerQuery(): unknown {
  const out = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", PS_POWER], {
    encoding: "utf8",
    timeout: 60_000,
    windowsHide: true,
    stdio: ["ignore", "pipe", "ignore"],
  });
  const clean = out.split(String.fromCharCode(0)).join("").trim();
  return clean === "" ? null : (JSON.parse(clean) as unknown);
}

function fromBatteryCodes(raw: unknown, source: PowerReading["source"]): PowerReading {
  const utc = new Date().toISOString();
  const codes = raw === null ? [] : (Array.isArray(raw) ? raw : [raw]).map((x) => Number(x));
  if (codes.length === 0) return { ac: true, code: "no-battery", source, utc };
  return { ac: codes.every((c) => c === 2), code: codes.join(","), source, utc };
}

function linuxSysfsPower(): PowerReading {
  const utc = new Date().toISOString();
  const base = "/sys/class/power_supply";
  let entries: string[] = [];
  try {
    entries = fs.readdirSync(base);
  } catch {
    return { ac: true, code: "no-power-supply-info", source: "none", utc };
  }
  const mains: Array<{ type: string; online: string }> = [];
  for (const e of entries) {
    try {
      const type = fs.readFileSync(path.join(base, e, "type"), "utf8").trim();
      if (type === "Mains" || type.startsWith("USB")) {
        mains.push({ type, online: fs.readFileSync(path.join(base, e, "online"), "utf8").trim() });
      }
    } catch {
      /* entry without type/online */
    }
  }
  if (mains.length === 0) return { ac: true, code: "no-mains-supply", source: "linux-sysfs", utc };
  return { ac: mains.some((m) => m.online === "1"), code: mains.map((m) => `${m.type}:${m.online}`).join(","), source: "linux-sysfs", utc };
}

/** Read the power state once. Never throws: a failed query is reported as not AC. */
export function readPower(): PowerReading {
  const source: PowerReading["source"] = process.platform === "win32" ? "win32-battery" : isWsl() ? "wsl-powershell" : "linux-sysfs";
  try {
    if (source === "win32-battery" || source === "wsl-powershell") return fromBatteryCodes(powershellPowerQuery(), source);
    if (process.platform === "linux") return linuxSysfsPower();
    return { ac: false, code: `unsupported-platform:${process.platform}`, source: "none", utc: new Date().toISOString() };
  } catch {
    return { ac: false, code: "query-failed", source, utc: new Date().toISOString() };
  }
}

// ------------------------------------------------------------------ quiet machine

/**
 * Process names that must not run during a timed run (builds, tests, compilers, LaTeX,
 * analyses, provers, chains). Checked on Linux only (/proc); on Windows no process list
 * is read (see header). Compared case-insensitively.
 */
export const FORBIDDEN = [
  "tsc", "eslint", "vitest", "circom", "circomspect", "cargo", "rustc", "anvil", "besu",
  "java", "dotnet", "tectonic", "xelatex", "pdflatex", "lualatex", "latexmk",
  "python", "python3", "racket", "z3", "cvc5", "gcc", "cc1", "cc1plus", "clang",
  "make", "ninja", "cmake", "ffmpeg", "prover",
];

/** Machine-wide CPU busy threshold, percent (same value as harness/bench_env.ts). */
export const CPU_THRESHOLD_PERCENT = 35;

export interface QuiesceReport {
  utc: string;
  /** Machine-wide CPU busy percent over the sample window (all logical cores). */
  cpuBusyPercent: number | null;
  cpuBasis: string;
  processListBasis: string;
  nodeProcesses: number | null;
  offending: string[];
  quiesced: boolean;
  thresholdPercent: number;
}

function cpuTicks(): { idle: number; total: number } {
  let idle = 0;
  let total = 0;
  for (const c of os.cpus()) {
    const t = c.times;
    idle += t.idle;
    total += t.user + t.nice + t.sys + t.idle + t.irq;
  }
  return { idle, total };
}

/** CPU busy percent from os.cpus() tick counters over `windowMs` (portable; the sleep uses no CPU). */
export async function cpuBusyPercent(windowMs = 3000): Promise<number | null> {
  const a = cpuTicks();
  await new Promise((r) => setTimeout(r, windowMs));
  const b = cpuTicks();
  const dt = b.total - a.total;
  if (dt <= 0) return null;
  return Math.round((1 - (b.idle - a.idle) / dt) * 1000) / 10;
}

function linuxProcessNames(): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync("/proc")) {
    if (!/^\d+$/.test(e)) continue;
    try {
      out.push(fs.readFileSync(`/proc/${e}/comm`, "utf8").trim());
    } catch {
      /* process ended */
    }
  }
  return out;
}

/**
 * One quiet-machine reading (never throws). Includes a 3 s CPU sample taken while this
 * process sleeps, so it reflects everything else running on the machine.
 */
export async function readQuiesce(windowMs = 3000): Promise<QuiesceReport> {
  const utc = new Date().toISOString();
  const cpu = await cpuBusyPercent(windowMs).catch(() => null);
  let offending: string[] = [];
  let nodeProcesses: number | null = null;
  let processListBasis = "not read on Windows (docs/BENCHMARK_POLICY.md: the power query is the only Windows-specific call)";
  if (process.platform === "linux") {
    try {
      const counts = new Map<string, number>();
      nodeProcesses = 0;
      for (const raw of linuxProcessNames()) {
        const n = raw.toLowerCase();
        if (n === "node") nodeProcesses++;
        if (FORBIDDEN.includes(n)) counts.set(n, (counts.get(n) ?? 0) + 1);
      }
      offending = [...counts.entries()].map(([n, c]) => (c > 1 ? `${n}x${c}` : n));
      processListBasis = "Linux /proc/<pid>/comm";
    } catch {
      processListBasis = "Linux /proc read failed";
    }
  }
  const quiesced = offending.length === 0 && (cpu === null || cpu <= CPU_THRESHOLD_PERCENT);
  return {
    utc,
    cpuBusyPercent: cpu,
    cpuBasis: `os.cpus() tick counters, ${windowMs / 1000} s window, all logical cores`,
    processListBasis,
    nodeProcesses,
    offending,
    quiesced,
    thresholdPercent: CPU_THRESHOLD_PERCENT,
  };
}

// CLI: `node --import tsx harness/v4/bench/guard.ts` prints one power + quiesce reading.
const self = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (self.endsWith(path.join("harness", "v4", "bench", "guard.ts"))) {
  const power = readPower();
  readQuiesce().then((quiesce) => console.log(JSON.stringify({ power, quiesce }, null, 2)));
}
