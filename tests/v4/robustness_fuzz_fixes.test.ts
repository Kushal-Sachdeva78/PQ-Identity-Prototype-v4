import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PURE_TARGETS } from "../../harness/v4/robustness/fuzz_targets.ts";
import { caseRng, Rng } from "../../harness/v4/robustness/rng.ts";
import { cloneJson, confusionValues, copyBytes } from "../../harness/v4/robustness/mutators.ts";
import { childGroups, maxOf, runTargets, targetsInOrder, targetStatus, writeSummary, writeTargetResult, type ChildRun, type TargetResult } from "../../harness/v4/robustness/fuzz.ts";
import type { FuzzCase, FuzzTarget } from "../../harness/v4/robustness/fuzz_types.ts";
import { SEEDS } from "../../harness/v4/lib/seeds.ts";

/**
 * Regression fixtures for the harness defects found in the fz1 fuzz campaign (triaged
 * 2026-10-03; docs/v4/ROBUSTNESS.md, Deviations, 2026-10-03). Each case comes from the
 * campaign's own seeds (robustness.fuzz 20261022), so case i here is fz1's case i.
 *   - T-witness case 8265: the reference read credId through Buffer.from(object), which calls an
 *     own valueOf; a non-callable own valueOf made the reference refuse (false positive).
 *   - T-open, the ten raw-plaintext cases with a 1e400 literal: the reference threw on the
 *     non-finite number instead of deciding "malformed", so the package was never called.
 *   - The result write of a 200,000-case target: Math.max(...times) overflowed the stack, so
 *     three targets lost their results, and the parent still exited 0.
 *   - The row labels of a failed chain child: its ids are passed in the order the child runs them
 *     (review of the corrections, 2026-10-03).
 * The summarize.py side of the labels is tested in scripts/robustness/test_summarize.py.
 */

const MASTER = SEEDS.robustness.fuzz;
const target = (id: string): FuzzTarget => {
  const t = PURE_TARGETS.find((x) => x.id === id);
  if (!t) throw new Error(`no target ${id}`);
  return t;
};

describe("fz1 T-witness false positive (reference read credId through Buffer.from)", () => {
  it("case 8265 (own valueOf on credId) is assembled with no violation", async () => {
    const t = target("T-witness");
    if (t.setup) await t.setup({ smoke: true, log: () => undefined });
    try {
      const c = await t.gen(caseRng(MASTER, t.id, 8265), 8265);
      const id = (c.input as { priv: Record<string, unknown> }).priv["credId"] as Uint8Array;
      // the case still carries the mutation the old reference tripped on
      expect(Object.prototype.hasOwnProperty.call(id, "valueOf")).toBe(true);
      expect(() => Buffer.from(id)).toThrow(TypeError);
      const out = await t.run(c);
      expect(out.violations).toEqual([]);
      expect(out.outcome).toBe("assembled");
    } finally {
      if (t.teardown) await t.teardown();
    }
  });

  it("an own valueOf of any confusion value, or a callable one, on a valid credId changes nothing", async () => {
    const t = target("T-witness");
    if (t.setup) await t.setup({ smoke: true, log: () => undefined });
    try {
      let base: FuzzCase | null = null;
      for (let i = 0; i < 200 && !base; i++) {
        const c = await t.gen(caseRng(MASTER, t.id, i), i);
        if (c.family === "valid") base = c;
      }
      expect(base).not.toBeNull();
      const b = base as FuzzCase;
      const priv = (b.input as { priv: Record<string, unknown> }).priv;
      const clean = Buffer.from(priv["credId"] as Uint8Array);
      const values = [...confusionValues(new Rng(1)), () => "zz", () => Buffer.alloc(32, 7)];
      for (const val of values) {
        const id = Buffer.from(clean);
        Object.defineProperty(id, "valueOf", { value: val, enumerable: true, writable: true, configurable: true });
        priv["credId"] = id;
        const out = await t.run(b);
        expect({ valueOf: typeof val === "function" ? "function" : String(val).slice(0, 20), violations: out.violations }).toEqual({ valueOf: typeof val === "function" ? "function" : String(val).slice(0, 20), violations: [] });
        expect(out.outcome).toBe("assembled");
      }
    } finally {
      if (t.teardown) await t.teardown();
    }
  });

  it("copyBytes and cloneJson read a byte array's bytes and ignore its own keys", () => {
    const src = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
    for (const [k, v] of [
      ["valueOf", "x".repeat(26)],
      ["valueOf", ""],
      ["valueOf", true],
      ["length", 5],
      ["buffer", new ArrayBuffer(4)],
      ["byteOffset", 3],
    ] as Array<[string, unknown]>) {
      const id = Buffer.from(src);
      Object.defineProperty(id, k, { value: v, enumerable: true, writable: true, configurable: true });
      const a = copyBytes(id);
      expect(a.equals(src)).toBe(true);
      expect(Object.prototype.hasOwnProperty.call(a, k)).toBe(false);
      const b = cloneJson({ priv: { credId: id } }).priv.credId as unknown as Buffer;
      expect(Buffer.isBuffer(b) && b.equals(src)).toBe(true);
      expect(Object.prototype.hasOwnProperty.call(b, k)).toBe(false);
    }
    // a pooled Buffer (non-zero byteOffset) is copied by its own bytes only
    const pooled = Buffer.from("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "hex");
    expect(copyBytes(pooled).toString("hex")).toBe(pooled.toString("hex"));
  });
});

describe("fz1 T-open oracle defect (reference threw on a non-finite number)", () => {
  /** The ten fz1 cases recorded as raw-plaintext/harness:run-error (failure file 00a08412a548). */
  const FZ1_RUN_ERROR_CASES = [2205, 5266, 23402, 25139, 26667, 27224, 41058, 43322, 43361, 45790];

  it("each 1e400 raw-plaintext case reaches verifierOpenReply and is malformed for both", async () => {
    const t = target("T-open");
    if (t.setup) await t.setup({ smoke: true, log: () => undefined });
    try {
      for (const i of FZ1_RUN_ERROR_CASES) {
        const c = await t.gen(caseRng(MASTER, t.id, i), i);
        expect(c.family).toBe("raw-plaintext");
        const out = await t.run(c);
        expect({ i, outcome: out.outcome, violations: out.violations }).toEqual({ i, outcome: "malformed", violations: [] });
        expect(c.recipe.join("; ")).toMatch(/1e400/i);
        expect(out.callMs).toBeGreaterThan(0);
      }
    } finally {
      if (t.teardown) await t.teardown();
    }
  });
});

describe("fz1 lost results (result write of a 200,000-case target)", () => {
  it("maxOf equals Math.max on small arrays, NaN and -0 included", () => {
    for (const xs of [[], [3, 1, 2], [NaN, 1], [1, NaN], [-0], [-0, 0], [0, -0], [-Infinity], [5]]) {
      expect(Object.is(maxOf(xs), Math.max(...xs))).toBe(true);
    }
  });

  it("writeTargetResult writes the call-time summary of 200,000 times", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-fuzz-write-test-"));
    try {
      const n = 200_000;
      const times = Array.from({ length: n }, (_, i) => (i * 7919) % 1000 / 10);
      times[123_457] = 4321.5;
      const res: TargetResult = {
        schema: "pqid/v4-fuzz-target/v2",
        target: "T-big",
        title: "t",
        entryPoints: [],
        property: "p",
        documentedErrors: [],
        masterSeed: MASTER,
        targetSeed: 1,
        budget: n,
        casesRun: n,
        complete: true,
        stoppedBy: null,
        crash: null,
        outcomes: { "f/ok": n },
        casesWithViolations: 0,
        harnessErrors: 0,
        signatures: [],
        observations: [],
        slow: { thresholdMs: 1000, basis: "b", cases: [] },
        callTimeMs: { note: "n", median: null, p99: null, max: null },
        startedUtc: "",
        finishedUtc: "",
      };
      writeTargetResult(dir, res, [], [], times);
      const j = JSON.parse(fs.readFileSync(path.join(dir, "targets", "T-big.json"), "utf8")) as TargetResult;
      const sorted = [...times].sort((a, b) => a - b);
      expect(j.callTimeMs.max).toBe(4321.5);
      expect(j.callTimeMs.median).toBeCloseTo(((sorted[n / 2 - 1] as number) + (sorted[n / 2] as number)) / 2, 9);
      expect(j.casesRun).toBe(n);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  const fake = (id: string, crashAt: number | null, setupThrows = false): FuzzTarget => ({
    id,
    title: id,
    entryPoints: [],
    kind: "pure",
    budget: 10,
    smokeBudget: 10,
    property: "p",
    documentedErrors: [],
    ...(setupThrows
      ? {
          async setup() {
            throw new Error("setup failed");
          },
        }
      : {}),
    gen: (_rng, i) => ({ family: "f", input: i, recipe: [] }),
    // a malformed outcome (observations not iterable) makes the runner's own bookkeeping throw
    run: (c) => (c.input === crashAt ? ({ outcome: "ok", violations: [], observations: null, callMs: 0.1 } as unknown as ReturnType<FuzzTarget["run"]>) : { outcome: "ok", violations: [], observations: [], callMs: 0.1 }),
  });

  it("a crash in the child keeps a record with the true casesRun and reports it to the parent", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-fuzz-crash-test-"));
    try {
      const lines: Array<Record<string, unknown>> = [];
      await expect(runTargets([fake("T-ok", null), fake("T-crash", 6), fake("T-after", null)], dir, { "T-ok": 10, "T-crash": 10, "T-after": 10 }, true, (o) => lines.push(o as Record<string, unknown>))).rejects.toThrow(TypeError);
      const ok = JSON.parse(fs.readFileSync(path.join(dir, "targets", "T-ok.json"), "utf8")) as TargetResult;
      expect(ok.complete).toBe(true);
      expect(ok.crash).toBeNull();
      const cr = JSON.parse(fs.readFileSync(path.join(dir, "targets", "T-crash.json"), "utf8")) as TargetResult;
      expect(cr.schema).toBe("pqid/v4-fuzz-target/v2");
      expect(cr.complete).toBe(false);
      expect(cr.casesRun).toBe(7);
      expect(cr.crash?.atCase).toBe(6);
      expect(cr.crash?.errorClass).toBe("TypeError");
      expect(cr.stoppedBy).toBe("crashed at case 6 (TypeError)");
      expect(fs.existsSync(path.join(dir, "targets", "T-after.json"))).toBe(false);
      expect(lines.filter((l) => l["done"]).map((l) => l["done"])).toEqual(["T-ok"]);
      expect(lines.find((l) => l["crashed"])).toMatchObject({ crashed: "T-crash", cases: 7, atCase: 6 });
      // a setup failure: crash outside the case loop, 0 cases
      await expect(runTargets([fake("T-setup", null, true)], dir, { "T-setup": 10 }, true, () => undefined)).rejects.toThrow("setup failed");
      const su = JSON.parse(fs.readFileSync(path.join(dir, "targets", "T-setup.json"), "utf8")) as TargetResult;
      expect(su.casesRun).toBe(0);
      expect(su.crash?.atCase).toBeNull();
      expect(su.stoppedBy).toBe("crashed outside the case loop (Error)");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the summary labels lost results and the step fails when a child failed", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-fuzz-summary-test-"));
    try {
      await runTargets([fake("T-ok", null)], dir, { "T-ok": 10 }, true, () => undefined);
      await runTargets([fake("T-crash", 6), fake("T-after", null)], dir, { "T-crash": 10, "T-after": 10 }, true, () => undefined).catch(() => undefined);
      // T-lost: a child that died without any record (as T-dates in fz1); T-stale: one that left only a checkpoint (as T-reply-shape)
      const stale = JSON.parse(fs.readFileSync(path.join(dir, "targets", "T-ok.json"), "utf8")) as TargetResult;
      fs.writeFileSync(path.join(dir, "targets", "T-stale.json"), JSON.stringify({ ...stale, target: "T-stale", casesRun: 4, complete: false, budget: 10 }));
      fs.mkdirSync(path.join(dir, "observations", "T-lost"), { recursive: true });
      fs.writeFileSync(path.join(dir, "observations", "T-lost", "x.json"), "{}");
      const run = (ids: string[], code: number | null, extra: Partial<ChildRun> = {}): ChildRun => ({ ids, code, stoppedBy: null, lastHeartbeat: null, wallSec: 1, hang: null, anvil: null, hangFile: null, doneTargets: [], crash: null, ...extra });
      const runs = [run(["T-ok"], 0, { doneTargets: ["T-ok"] }), run(["T-crash", "T-after"], 1, { crash: { target: "T-crash", cases: 7, atCase: 6, error: "TypeError" } }), run(["T-lost"], 1), run(["T-stale"], 1)];
      const chosen = ["T-ok", "T-crash", "T-after", "T-lost", "T-stale"].map((id) => ({ id, kind: "pure" as const }));
      const step = writeSummary(dir, "unit", true, chosen, runs, null, { "T-ok": 10, "T-crash": 10, "T-after": 10, "T-lost": 10, "T-stale": 10 });
      expect(step.exitCode).toBe(1);
      expect(step.failed).toBe(true);
      const s = JSON.parse(fs.readFileSync(path.join(dir, "summary.json"), "utf8")) as { schema: string; step: { exitCode: number }; totals: Record<string, unknown>; targets: Array<Record<string, unknown>> };
      expect(s.schema).toBe("pqid/v4-fuzz-summary/v2");
      expect(s.step.exitCode).toBe(1);
      const by = Object.fromEntries(s.targets.map((r) => [r["target"], r]));
      expect(by["T-ok"]).toMatchObject({ status: "complete", casesRun: 10, complete: true, resultLost: false });
      expect(by["T-crash"]).toMatchObject({ status: "crashed at case 6 (TypeError), record kept", casesRun: 7, resultLost: false, casesWithViolations: 0 });
      expect(by["T-after"]).toMatchObject({ status: "not run (the child stopped during T-crash)", casesRun: 0 });
      expect(by["T-lost"]).toMatchObject({ status: "result lost (child crashed)", casesRun: null, resultLost: true, casesWithViolations: null, budget: 10 });
      expect((by["T-lost"] as { filesOnDisk: { observations: string[] } }).filesOnDisk.observations).toHaveLength(1);
      expect(by["T-stale"]).toMatchObject({ status: "result lost (child crashed), last checkpoint at 4 cases", casesRun: null, checkpointCasesRun: 4, resultLost: true });
      expect(s.totals).toMatchObject({ casesRun: 10 + 7 + 0 + 0 + 4, casesRunIsLowerBound: true, resultLostTargets: ["T-lost", "T-stale"] });
      const md = fs.readFileSync(path.join(dir, "summary.md"), "utf8");
      expect(md).toContain("| T-lost | result lost (child crashed) | not known / 10 | lost | lost |");
      expect(md).toContain("at least 4 / 10");
      expect(md).toContain("Step result: failed (runner exit 1)");
      expect(md).not.toMatch(/\| 0 \/ \?|\/ \? \|/);
      // a clean campaign passes
      const okStep = writeSummary(dir, "unit-ok", true, [{ id: "T-ok", kind: "pure" }], [runs[0] as ChildRun], null, { "T-ok": 10 });
      expect(okStep).toEqual({ exitCode: 0, failed: false, reasons: [] });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("targetStatus: a watchdog stop is a lost result, not a crash", () => {
    const st = targetStatus("T-x", null, { ids: ["T-x"], code: null, stoppedBy: "no progress for 120 s (hang candidate)", doneTargets: [], crash: null });
    expect(st).toMatchObject({ status: "result lost (child stopped by the watchdog)", resultLost: true, casesRun: null });
  });

  it("a reordered chain subset: the child's ids are in run order, so the labels name the target that was running", () => {
    const all = [
      { id: "T-a", kind: "pure" as const },
      { id: "T-verify", kind: "chain" as const },
      { id: "T-wallet-req", kind: "chain" as const },
      { id: "T-wallet-iss", kind: "chain" as const },
    ];
    const by = (id: string) => all.find((t) => t.id === id) as (typeof all)[number];
    // --targets T-wallet-iss,T-a,T-verify
    const groups = childGroups(all, [by("T-wallet-iss"), by("T-a"), by("T-verify")]);
    expect(groups).toEqual([["T-a"], ["T-verify", "T-wallet-iss"]]);
    const chainIds = groups[1] as string[];
    // the child runs its ids in the order given
    expect(targetsInOrder(all, chainIds).map((t) => t.id)).toEqual(chainIds);
    expect(targetsInOrder(all, ["T-wallet-iss", "T-verify"]).map((t) => t.id)).toEqual(["T-wallet-iss", "T-verify"]);
    expect(() => targetsInOrder(all, ["T-nope"])).toThrow("unknown target T-nope");
    // the watchdog stops the chain child during T-verify, before any record
    const run = { ids: chainIds, code: null, stoppedBy: "no progress for 120 s (hang candidate)", doneTargets: [], crash: null };
    expect(targetStatus("T-verify", null, run).status).toBe("result lost (child stopped by the watchdog)");
    expect(targetStatus("T-wallet-iss", null, run)).toMatchObject({ status: "not run (the child stopped during T-verify)", resultLost: false, casesRun: 0 });
    // the same after T-verify reported done: T-wallet-iss was running
    const run2 = { ...run, doneTargets: ["T-verify"] };
    expect(targetStatus("T-wallet-iss", null, run2).status).toBe("result lost (child stopped by the watchdog)");
  });

  it("childGroups keeps the chain targets in CHAIN_TARGETS order (the order fz1's chain child ran them)", async () => {
    const { CHAIN_TARGETS } = await import("../../harness/v4/robustness/fuzz_chain.ts");
    const all = [...PURE_TARGETS, ...CHAIN_TARGETS];
    const chainOrder = CHAIN_TARGETS.map((t) => t.id);
    expect(childGroups(all, all)).toEqual([...PURE_TARGETS.map((t) => [t.id]), chainOrder]);
    expect(childGroups(all, [...CHAIN_TARGETS].reverse())).toEqual([chainOrder]);
  });
});
