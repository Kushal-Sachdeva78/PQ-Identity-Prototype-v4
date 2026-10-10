import { execFileSync } from "node:child_process";
import { hostMeta, wslMeta, type HostMeta, type WslMeta } from "@pqid/common/meta";

/**
 * V6 §B — benchmark discipline. Every timing benchmark must:
 *   (1) run on a quiesced machine (this module's guard REFUSES to start when
 *       build tooling or another prover/bench is running);
 *   (2) record its controls (affinity policy + live probe, governor, power
 *       source, fs basis, quiesce report) into the results JSON;
 *   (3) run ≥3 independent invocations and report inter-run stats.
 *
 * Affinity policy (documented deviation from §B2's literal wording):
 * rapidsnark v0.0.8 is MULTI-threaded (pthread pool, nproc threads — verified
 * via nm: 0 OpenMP / 7 pthread symbols). A live probe (recorded below) shows
 * single-vCPU pinning makes it ~2.7× slower (≈677 ms vs ≈250 ms free), so a
 * "pin to one P-core" control would not reproduce the paper's method. Inside
 * the WSL2 VM, vCPU→P/E placement is decided by the Windows hypervisor and is
 * not controllable; the effective controls are therefore: quiesced machine +
 * native ext4 inputs + warm cache + inter-run stability. The probe results
 * are embedded in every zk results file as evidence.
 */
export interface QuiesceReport {
  quiesced: boolean;
  forced: boolean;
  windows: { offendingProcesses: string[]; nodeCount: number; cpuLoadPercent: number };
  wsl: { offendingProcesses: string[]; loadavg1m: number };
}

export interface BenchControls {
  quiesce: QuiesceReport;
  affinity: {
    policy: string;
    rationale: string;
    probe?: { freeMs: number[]; oneVcpuMs: number[]; fourVcpuMs: number[] };
  };
  cpuGovernor: string;
  powerSource: string;
  fsBasis: string;
  invocations: number;
  ambientLoadNote: string;
  host: HostMeta;
  wsl: WslMeta;
}

const WIN_FORBIDDEN = ["tsc", "eslint", "vitest", "circom", "cargo", "anvil", "prover", "dotnet", "msbuild", "java"];
// exact process-name matching (pgrep -x) — immune to the guard's own
// command line containing these words
const WSL_FORBIDDEN_NAMES = [
  "prover",
  "amortized_prover",
  "cargo",
  "cc1",
  "cc1plus",
  "make",
  "ninja",
  "node",
  "vitest",
];

function winProcesses(): Array<{ name: string; pid: number }> {
  const out = execFileSync(
    "powershell",
    ["-NoProfile", "-Command", "Get-Process | Select-Object -Property ProcessName,Id | ConvertTo-Json -Compress"],
    { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 }
  );
  const list = JSON.parse(out) as Array<{ ProcessName: string; Id: number }>;
  return list.map((p) => ({ name: p.ProcessName.toLowerCase(), pid: p.Id }));
}

function winCpuLoad(): number {
  // 5-second averaged % Processor Time — the instantaneous WMI LoadPercentage
  // flaps on ambient desktop activity (UI apps, vendor services) and gives
  // false refusals. Sustained build/prover contention still trips this.
  try {
    const out = execFileSync(
      "powershell",
      [
        "-NoProfile",
        "-Command",
        "[math]::Round(((Get-Counter '\\Processor(_Total)\\% Processor Time' -SampleInterval 1 -MaxSamples 5).CounterSamples.CookedValue | Measure-Object -Average).Average)",
      ],
      { encoding: "utf8" }
    ).trim();
    return Number(out) || 0;
  } catch {
    return -1;
  }
}

function wslCheck(): { offending: string[]; loadavg: number } {
  try {
    // /proc comm names are truncated to 15 chars; match accordingly
    const probe = WSL_FORBIDDEN_NAMES.map((n) => {
      const comm = n.slice(0, 15);
      return `pgrep -x '${comm}' > /dev/null 2>&1 && echo ${n}`;
    }).join("; ");
    const out = execFileSync(
      "wsl",
      ["-u", "root", "-e", "bash", "-c", `${probe}; echo ---LOAD---; cat /proc/loadavg`],
      { encoding: "utf8" }
    );
    const clean = out.split(String.fromCharCode(0)).join("");
    const [procs, load] = clean.split("---LOAD---") as [string, string];
    const offending = procs
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    const loadavg = Number(load.trim().split(/\s+/)[0] ?? "0");
    return { offending, loadavg };
  } catch {
    return { offending: [], loadavg: -1 };
  }
}

function powerSource(): string {
  try {
    const out = execFileSync(
      "powershell",
      ["-NoProfile", "-Command", "(Get-CimInstance Win32_Battery).BatteryStatus"],
      { encoding: "utf8" }
    ).trim();
    if (out === "") return "no battery (desktop)";
    return out === "2" ? `AC (BatteryStatus=${out})` : `battery (BatteryStatus=${out}) — WARNING: may throttle`;
  } catch {
    return "unknown";
  }
}

function wslGovernor(): string {
  try {
    const out = execFileSync(
      "wsl",
      ["-u", "root", "-e", "bash", "-c", "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unavailable"],
      { encoding: "utf8" }
    );
    const v = out.split(String.fromCharCode(0)).join("").trim();
    return v === "unavailable" || v === ""
      ? "unavailable (WSL2 Hyper-V VM — frequency is host-managed; recorded per §B4)"
      : v;
  } catch {
    return "unknown";
  }
}

/**
 * Refuses to proceed when the machine is not quiesced (§B1). The bench
 * process itself (plus its tsx/esbuild service children and the spawned
 * worker budget) is excluded. Override with PQID_BENCH_FORCE=1 (recorded).
 */
export function assertQuiesced(opts: { allowedNodeCount?: number } = {}): QuiesceReport {
  // Each `npx tsx` invocation is a 2-process node chain; the campaign nests
  // campaign -> bench -> worker (≈6). The campaign exports the budget so the
  // inner guards account for their own legitimate ancestry.
  const envAllowance = process.env["PQID_ALLOWED_NODE"];
  const allowedNode = envAllowance
    ? Number(envAllowance)
    : (opts.allowedNodeCount ?? 2);
  const forced = process.env["PQID_BENCH_FORCE"] === "1";

  // Transient spikes (process startup, prior task teardown) settle within
  // seconds, but WSL's 1-minute loadavg needs ~2 minutes to decay after a
  // preceding bench phase — retry generously, fail only on persistent
  // contention.
  const ATTEMPTS = 12;
  let report: QuiesceReport | null = null;
  for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
    const procs = winProcesses();
    const nodeCount = procs.filter((p) => p.name === "node").length;
    const offendingWin = procs
      .filter((p) => WIN_FORBIDDEN.includes(p.name))
      .map((p) => `${p.name}(${p.pid})`);
    if (nodeCount > allowedNode) offendingWin.push(`node×${nodeCount} (allowed ${allowedNode})`);
    const load = winCpuLoad();
    if (load > 35) offendingWin.push(`cpuLoad ${load}% 5s-avg (>35%)`);

    const wsl = wslCheck();
    if (wsl.loadavg > 1.0) wsl.offending.push(`loadavg ${wsl.loadavg} (>1.0)`);

    const quiesced = offendingWin.length === 0 && wsl.offending.length === 0;
    report = {
      quiesced,
      forced,
      windows: { offendingProcesses: offendingWin, nodeCount, cpuLoadPercent: load },
      wsl: { offendingProcesses: wsl.offending, loadavg1m: wsl.loadavg },
    };
    if (quiesced || forced) return report;
    if (attempt < ATTEMPTS) {
      console.log(
        `[bench-guard] not quiesced (attempt ${attempt}/${ATTEMPTS}): ` +
          `${[...offendingWin, ...wsl.offending].join(", ")} — settling 15 s…`
      );
      execFileSync("powershell", ["-NoProfile", "-Command", "Start-Sleep -Seconds 15"]);
    }
  }
  throw new Error(
    `BENCH REFUSED — machine is not quiesced (§B1) after ${ATTEMPTS} attempts.\n` +
      JSON.stringify(report, null, 2) +
      `\nStop the offending processes (or set PQID_BENCH_FORCE=1 to override — recorded in results).`
  );
}

export function collectControls(args: {
  quiesce: QuiesceReport;
  fsBasis: string;
  invocations: number;
  affinityProbe?: { freeMs: number[]; oneVcpuMs: number[]; fourVcpuMs: number[] };
}): BenchControls {
  return {
    quiesce: args.quiesce,
    affinity: {
      policy: "free scheduling across 12 vCPUs/logical CPUs (quiesced machine)",
      rationale:
        "rapidsnark v0.0.8 is pthread-pool multithreaded (0 OpenMP / 7 pthread symbols); the live " +
        "probe shows 1-vCPU pinning ≈2.7× slower than free — pinning would not reproduce the paper's " +
        "method. WSL2 vCPU→P/E-core placement is hypervisor-controlled and not configurable from the " +
        "guest; quiescing + inter-run stability are the effective §B controls (probe embedded as evidence).",
      ...(args.affinityProbe ? { probe: args.affinityProbe } : {}),
    },
    cpuGovernor: wslGovernor(),
    powerSource: powerSource(),
    fsBasis: args.fsBasis,
    invocations: args.invocations,
    ambientLoadNote:
      "host is an interactive laptop: desktop apps (desktop UI, browser, vendor services) " +
      "contribute a fluctuating ~10-20% ambient load that cannot be fully quiesced; build/prover " +
      "tooling is process-checked to zero, and inter-run CV is the stability arbiter (§B5)",
    host: hostMeta(),
    wsl: wslMeta(),
  };
}

/** Inter-run aggregation across ≥3 independent invocations (§B5). */
export interface InterRunStats {
  runs: number;
  meansMs: number[];
  mediansMs: number[];
  medianOfMeansMs: number;
  medianOfMediansMs: number;
  /** (max-min)/median of the per-run medians, % */
  spreadPct: number;
  /** coefficient of variation of the per-run means, % */
  cvPct: number;
  stable: boolean; // cvPct <= 10 (§B5)
}

export function interRun(perRun: Array<{ meanMs: number; medianMs: number }>): InterRunStats {
  const means = perRun.map((r) => r.meanMs);
  const medians = perRun.map((r) => r.medianMs);
  const med = (xs: number[]): number => {
    const s = [...xs].sort((a, b) => a - b);
    const n = s.length;
    return n % 2 ? (s[(n - 1) / 2] as number) : ((s[n / 2 - 1] as number) + (s[n / 2] as number)) / 2;
  };
  const meanOfMeans = means.reduce((a, b) => a + b, 0) / means.length;
  const sd =
    means.length > 1
      ? Math.sqrt(means.reduce((acc, x) => acc + (x - meanOfMeans) ** 2, 0) / (means.length - 1))
      : 0;
  const cvPct = meanOfMeans > 0 ? (sd / meanOfMeans) * 100 : 0;
  const mm = med(medians);
  const spreadPct = mm > 0 ? ((Math.max(...medians) - Math.min(...medians)) / mm) * 100 : 0;
  const round = (x: number): number => Math.round(x * 100) / 100;
  return {
    runs: perRun.length,
    meansMs: means.map(round),
    mediansMs: medians.map(round),
    medianOfMeansMs: round(med(means)),
    medianOfMediansMs: round(mm),
    spreadPct: round(spreadPct),
    cvPct: round(cvPct),
    stable: cvPct <= 10,
  };
}

/** §B6: median is the headline when within-run variance is high. */
export function headline(stats: { meanMs: number; medianMs: number; stddevMs: number }): {
  valueMs: number;
  basis: "mean" | "median";
  rule: string;
} {
  const high = stats.meanMs > 0 && stats.stddevMs / stats.meanMs > 0.2;
  return {
    valueMs: high ? stats.medianMs : stats.meanMs,
    basis: high ? "median" : "mean",
    rule: "σ/mean > 0.2 → median headline (§B6)",
  };
}
