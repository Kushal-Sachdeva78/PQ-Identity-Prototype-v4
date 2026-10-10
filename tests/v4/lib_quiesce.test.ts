import { describe, it, expect } from "vitest";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import {
  CLOCK_GAP_LIMIT_MS,
  QUIESCE_SCHEMA,
  classifyProcesses,
  clockCheck,
  guardOffending,
  openPorts,
  parseCpuJiffies,
  parseCpuLine,
  parseProcStat,
  readQuiesceExcluding,
  withDescendants,
  type ProcEntry,
} from "../../harness/v4/lib/quiesce.ts";
import {
  FROZEN_RUNNER_FALLBACK_SEEDS,
  SEEDS,
  SEED_BOOTSTRAP,
  SEED_REGISTRY,
  USED_SEEDS,
  assertScheduleSeed,
  assertUnusedSeed,
  checkSeedRegistry,
  seedArgs,
  seedFor,
} from "../../harness/v4/lib/seeds.ts";
import { CHAIN_PROBE_PORTS, LEGACY_CHAIN_PORTS, PORTS, d034Ports } from "../../harness/v4/lib/ports.ts";
import { closedPort } from "./helpers/mock_jsonrpc.ts";

// harness/v4/lib/quiesce.ts (pure parts on synthetic /proc data, so they run on any host),
// plus the D-034 seed and port registries.

const stat = (pid: number, name: string, ppid: number, utime: number, stime: number) =>
  `${pid} (${name}) S ${ppid} ${pid} ${pid} 0 -1 4194560 100 0 0 0 ${utime} ${stime} 0 0 20 0 1 0 100 1000 100`;

describe("quiesce: /proc parsing", () => {
  it("parses /proc/<pid>/stat, including names with spaces and parentheses", () => {
    expect(parseProcStat(stat(42, "anvil", 7, 120, 30))).toEqual({ pid: 42, ppid: 7, name: "anvil", ticks: 150 });
    expect(parseProcStat(stat(43, "my (odd) proc", 1, 5, 5))).toEqual({ pid: 43, ppid: 1, name: "my (odd) proc", ticks: 10 });
    expect(parseProcStat("garbage")).toBeNull();
  });
  it("parses the aggregate cpu line of /proc/stat (idle includes iowait)", () => {
    expect(parseCpuLine("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n")).toEqual({ total: 1000, idle: 850 });
    expect(parseCpuLine("intr 1 2 3\n")).toBeNull();
    // user nice system idle iowait irq softirq steal: steal counts as busy and is reported alone
    expect(parseCpuJiffies("cpu  100 0 50 700 50 10 10 80 0 0\n")).toEqual({ total: 1000, idle: 750, iowait: 50, steal: 80 });
  });
});

describe("quiesce: clock gap and the guard.ts rule", () => {
  it("a wall-clock jump against the monotonic clock over the window is a reason (suspend, VM pause)", () => {
    expect(CLOCK_GAP_LIMIT_MS).toBe(1000);
    expect(clockCheck(3000, 3001)).toMatchObject({ gapMs: 1, reason: null });
    const sus = clockCheck(3000, 40_000);
    expect(sus.gapMs).toBe(37_000);
    expect(sus.reason).toMatch(/host suspend, VM pause or clock step/);
    expect(clockCheck(3000, 1500).reason).not.toBeNull();
  });
  it("replays guard.ts's name rule: listed names, own processes included, counted", () => {
    expect(guardOffending(["anvil", "MainThread", "node", "ANVIL", "tsc", "bash"])).toEqual(["anvilx2", "tsc"]);
    expect(guardOffending([])).toEqual([]);
  });
});

describe("quiesce: own processes by pid, never by name", () => {
  const table = (xs: ProcEntry[]) => new Map(xs.map((p) => [p.pid, p] as const));
  // runner 100 -> own anvil 101 -> its child 102; Besu JVM 200 (reparented to init, passed by pid file);
  // foreign anvil 300, foreign tsc 301, foreign busy node 302, kernel thread 2
  const before = table([
    { pid: 1, ppid: 0, name: "init", ticks: 0 },
    { pid: 2, ppid: 0, name: "kthreadd", ticks: 0 },
    { pid: 100, ppid: 1, name: "node", ticks: 1000 },
    { pid: 101, ppid: 100, name: "anvil", ticks: 500 },
    { pid: 102, ppid: 101, name: "anvil", ticks: 10 },
    { pid: 200, ppid: 1, name: "java", ticks: 3000 },
    { pid: 300, ppid: 1, name: "anvil", ticks: 50 },
    { pid: 301, ppid: 1, name: "tsc", ticks: 0 },
    { pid: 302, ppid: 1, name: "node", ticks: 0 },
  ]);
  // 8 cores, window of 800 jiffies in total (100 per core): 100 jiffies = one core fully busy
  const after = table([
    { pid: 1, ppid: 0, name: "init", ticks: 0 },
    { pid: 2, ppid: 0, name: "kthreadd", ticks: 1 },
    { pid: 100, ppid: 1, name: "node", ticks: 1010 },
    { pid: 101, ppid: 100, name: "anvil", ticks: 540 },
    { pid: 102, ppid: 101, name: "anvil", ticks: 10 },
    { pid: 200, ppid: 1, name: "java", ticks: 3080 },
    { pid: 300, ppid: 1, name: "anvil", ticks: 52 },
    { pid: 301, ppid: 1, name: "tsc", ticks: 20 },
    { pid: 302, ppid: 1, name: "node", ticks: 90 },
    { pid: 303, ppid: 100, name: "prover", ticks: 30 }, // own child started during the window
  ]);

  it("descendants follow the ppid tree", () => {
    expect([...withDescendants([100], after.values())].sort((a, b) => a - b)).toEqual([100, 101, 102, 303]);
    expect([...withDescendants([200], after.values())]).toEqual([200]);
  });

  it("excludes the runner, its descendants and given pids; flags foreign chain nodes, listed tools and heavy processes", () => {
    const c = classifyProcesses({ before, after, totalJiffies: 800, idleJiffies: 520, logicalCores: 8, ownRoots: [100, 200], includeDescendants: true, heavyCorePercent: 50 });
    expect(c.own.map((p) => p.pid)).toEqual([100, 101, 102, 200, 303]);
    // a foreign anvil is flagged although its name equals the runner's own anvil
    expect(c.foreignChain.map((p) => `${p.name}:${p.pid}`)).toEqual(["anvil:300"]);
    expect(c.foreignTools.map((p) => p.name)).toEqual(["tsc"]);
    expect(c.foreignHeavy.map((p) => `${p.name}:${p.cpuPercentOfCore}`)).toEqual(["node:90"]);
    // own: 10 + 40 + 0 + 80 + 30 = 160 jiffies of 800 = 20 % of the machine; machine busy 35 %
    expect(c.ownCpuPercent).toBe(20);
    expect(c.machineBusyPercent).toBe(35);
    expect(c.foreignCpuBusyPercent).toBe(15);
    // foreign + own reconciles with the /proc/stat machine figure (recorded as procStatBusyPercent)
    expect(Math.abs(c.foreignCpuBusyPercent + c.ownCpuPercent - c.machineBusyPercent)).toBeLessThanOrEqual(0.1);
    const anvil101 = c.own.find((p) => p.pid === 101);
    expect(anvil101?.cpuPercentOfCore).toBe(40);
  });

  it("without the given pid, the runner's Besu JVM counts as a foreign chain node", () => {
    const c = classifyProcesses({ before, after, totalJiffies: 800, idleJiffies: 520, logicalCores: 8, ownRoots: [100], includeDescendants: true, heavyCorePercent: 50 });
    expect(c.foreignChain.map((p) => p.pid)).toEqual([200, 300]);
    expect(c.foreignHeavy.map((p) => p.pid)).toEqual([302, 200]);
  });

  it("without descendants, the runner's own anvil child is foreign", () => {
    const c = classifyProcesses({ before, after, totalJiffies: 800, idleJiffies: 520, logicalCores: 8, ownRoots: [100, 200], includeDescendants: false, heavyCorePercent: 50 });
    expect(c.foreignChain.map((p) => p.pid)).toEqual([101, 102, 300]);
  });
});

describe("quiesce: loopback port probe and the live reading", () => {
  it("finds a listener and excludes the runner's own port", async () => {
    const srv = http.createServer((_q, s) => s.end());
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
    const port = (srv.address() as AddressInfo).port;
    const shut = await closedPort();
    try {
      expect(await openPorts([port, shut], 1500)).toEqual([port]);
      const foreign = await readQuiesceExcluding({ chainPorts: [port, shut], windowMs: 200, probeTimeoutMs: 1500 });
      expect(foreign.portProbe.open).toEqual([port]);
      expect(foreign.portProbe.foreignOpen).toEqual([port]);
      expect(foreign.quiesced).toBe(false);
      expect(foreign.reasons.join(" ")).toMatch(new RegExp(`chain port\\(s\\) ${port}`));
      const own = await readQuiesceExcluding({ chainPorts: [port, shut], ownPorts: [port], windowMs: 200, probeTimeoutMs: 1500 });
      expect(own.portProbe.probed).toEqual([shut]);
      expect(own.portProbe.ownExcluded).toEqual([port]);
      expect(own.portProbe.foreignOpen).toEqual([]);
    } finally {
      await new Promise<void>((r) => srv.close(() => r()));
    }
  }, 30_000);

  it("records CPU busy and states what the reading cannot see on this platform", async () => {
    const r = await readQuiesceExcluding({ chainPorts: [], windowMs: 300 });
    expect(r.schema).toBe(QUIESCE_SCHEMA);
    expect(r.windowMs).toBe(300);
    expect(r.cpuBusyPercent === null || (r.cpuBusyPercent >= 0 && r.cpuBusyPercent <= 100)).toBe(true);
    expect(r.thresholdPercent).toBe(35);
    expect(r.errors).toEqual([]);
    // like-for-like flags on every platform
    expect(r.machineWideQuiesced).toBe(r.cpuBusyPercent === null || r.cpuBusyPercent <= 35);
    expect(r.guardTs.quiesced).toBe(r.machineWideQuiesced && r.guardTs.offending.length === 0);
    // the clock over the window
    expect(r.clock.monotonicMs).toBeGreaterThanOrEqual(290);
    expect(Math.abs(r.clock.gapMs)).toBeLessThan(r.clock.limitMs);
    if (process.platform === "win32") {
      expect(r.environment).toBe("windows");
      expect(r.processListBasis).toMatch(/not read on Windows/);
      expect(r.foreignCpuBusyPercent).toBeNull();
      expect(r.procStatBusyPercent).toBeNull();
      expect(r.stealPercent).toBeNull();
      expect(r.guardTs.offending).toEqual([]);
      expect(r.thresholdBasis).toMatch(/machine-wide/);
    } else if (process.platform === "linux") {
      expect(r.own.some((p) => p.pid === process.pid)).toBe(true);
      expect(r.foreignCpuBusyPercent).not.toBeNull();
      expect(r.procStatJiffies?.total).toBeGreaterThan(0);
      expect(r.stealPercent).not.toBeNull();
      const machine = r.procStatBusyPercent as number;
      const sum = (r.foreignCpuBusyPercent as number) + (r.ownCpuPercent as number);
      if ((r.foreignCpuBusyPercent as number) > 0) expect(Math.abs(sum - machine)).toBeLessThanOrEqual(0.1);
      else expect(r.ownCpuPercent as number).toBeGreaterThanOrEqual(machine - 0.1);
      if (r.environment === "wsl2") expect(r.visibility).toMatch(/Windows processes and Windows load are not visible/);
    }
  }, 30_000);
});

describe("seeds and ports registries (D-034)", () => {
  it("holds the D-034 seeds, distinct, none reused from earlier series", () => {
    expect(() => checkSeedRegistry()).not.toThrow();
    expect(SEEDS.chainRead).toEqual({ conditionOrder: 20261011, readOrder: 20261012, verifierPool: 20261013, walletReads: 20261014 });
    expect(SEEDS.robustness).toEqual({ load: 20261021, fuzz: 20261022, circuitFuzz: 20261023, forgeFuzz: 20261024 });
    expect(SEEDS.endToEnd.order).toBe(20261031);
    expect(SEEDS.comparable).toEqual({ coldOrder: 20261041, walletRebuilds: 20261042, warm: 20261043 });
    expect(SEED_BOOTSTRAP).toBe(20260927);
    expect(new Set(SEED_REGISTRY.map((e) => e.seed)).size).toBe(SEED_REGISTRY.length);
    for (const e of SEED_REGISTRY) expect(Object.values(USED_SEEDS)).not.toContain(e.seed);
    expect(seedFor("robustness.fuzz")).toBe(20261022);
    expect(() => seedFor("robustness.newThing")).toThrow(/no seed registered/);
  });
  it("refuses the frozen runners' fallback seeds and every other used, unregistered or bootstrap seed", () => {
    expect(() => assertUnusedSeed(20261002)).toThrow(/phaseD\.cold_rs_wsl/);
    expect(() => assertUnusedSeed(20261003)).toThrow(/phaseD\.warm_wsl/);
    for (const used of Object.values(USED_SEEDS)) expect(() => assertUnusedSeed(used)).toThrow(/already used/);
    expect(() => assertUnusedSeed(12345)).toThrow(/not registered/);
    expect(() => assertUnusedSeed(SEED_BOOTSTRAP)).toThrow(/bootstrap/);
    expect(assertUnusedSeed(20261041).id).toBe("comparable.coldOrder");
    expect(seedArgs("comparable.coldOrder")).toEqual(["--seed", "20261041"]);
    expect(seedArgs("comparable.warm")).toEqual(["--seed", "20261043"]);
    expect(() => seedArgs("analysis.bootstrap")).toThrow(/bootstrap/);
    expect(assertScheduleSeed({ config: { seed: 20261041 } }, "comparable.coldOrder")).toBe(20261041);
    expect(() => assertScheduleSeed({ config: { seed: 20261002 } }, "comparable.coldOrder")).toThrow(/expected 20261041/);
    expect(() => assertScheduleSeed({}, "comparable.warm")).toThrow(/undefined/);
  });
  it("FROZEN_RUNNER_FALLBACK_SEEDS matches the frozen runners' source", () => {
    for (const [rel, seed] of Object.entries(FROZEN_RUNNER_FALLBACK_SEEDS)) {
      const src = fs.readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)), "utf8");
      expect(src).toContain(`DEFAULT_SEEDS[campaign] ?? ${seed}`);
      expect(Object.values(USED_SEEDS)).toContain(seed);
    }
  });
  it("holds the D-034 ports and probes them by default", () => {
    expect(PORTS.chainReadAnvilWsl).toBe(8770);
    expect(PORTS.chainReadAnvilWindows).toBe(8771);
    expect(PORTS.loadTest).toBe(8780);
    expect(PORTS.fuzzing).toBe(8781);
    expect(PORTS.endToEnd).toBe(8790);
    expect([...PORTS.besuQbft]).toEqual([18545, 18546, 18547, 18548]);
    for (const p of [...d034Ports(), ...LEGACY_CHAIN_PORTS]) expect(CHAIN_PROBE_PORTS).toContain(p);
  });
});
