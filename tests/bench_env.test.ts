import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { RESULTS_DIR } from "@pqid/common/paths";
import { interRun, headline } from "../harness/bench_env.ts";

/**
 * V6 §K — benchmark-environment self-checks:
 *  - the §B guard refuses under contention (this very test process IS the
 *    contention: vitest + node workers are running, so assertQuiesced must
 *    throw unless forced);
 *  - controls (affinity policy + rationale, governor, power, fs basis,
 *    invocations) are recorded in the published results;
 *  - inter-run aggregation and the §B6 median-headline rule behave correctly.
 */
describe("§B guard", () => {
  it("refuses to run while test tooling is alive (unless forced)", async () => {
    const { assertQuiesced } = await import("../harness/bench_env.ts");
    delete process.env["PQID_BENCH_FORCE"];
    // vitest + its node workers exceed the allowed-node budget and/or load
    expect(() => assertQuiesced({ allowedNodeCount: 0 })).toThrow(/BENCH REFUSED/);
  });

  it("records the forced flag when overridden", async () => {
    const { assertQuiesced } = await import("../harness/bench_env.ts");
    process.env["PQID_BENCH_FORCE"] = "1";
    const report = assertQuiesced({ allowedNodeCount: 0 });
    delete process.env["PQID_BENCH_FORCE"];
    expect(report.forced).toBe(true);
    expect(report.quiesced).toBe(false);
  });
});

describe("§B5 inter-run stats", () => {
  it("computes medians, spread, CV, and the stability flag", () => {
    const ir = interRun([
      { meanMs: 100, medianMs: 99 },
      { meanMs: 102, medianMs: 101 },
      { meanMs: 98, medianMs: 97 },
    ]);
    expect(ir.runs).toBe(3);
    expect(ir.medianOfMediansMs).toBe(99);
    expect(ir.stable).toBe(true);

    const noisy = interRun([
      { meanMs: 100, medianMs: 99 },
      { meanMs: 180, medianMs: 175 },
      { meanMs: 95, medianMs: 94 },
    ]);
    expect(noisy.stable).toBe(false); // CV > 10% must be flagged (§B5)
  });
});

describe("§B6 headline rule", () => {
  it("uses the median when σ/mean > 0.2 and the mean otherwise", () => {
    expect(headline({ meanMs: 1250, medianMs: 936, stddevMs: 530 }).basis).toBe("median");
    expect(headline({ meanMs: 156, medianMs: 154, stddevMs: 7.6 }).basis).toBe("mean");
  });
});

describe("published results carry §B controls", () => {
  const zkPath = path.join(RESULTS_DIR, "zk.json");
  it.skipIf(!fs.existsSync(zkPath))("zk.json records controls + affinity probe", () => {
    const zk = JSON.parse(fs.readFileSync(zkPath, "utf8")) as {
      schema: string;
      controls?: {
        quiesce: { quiesced: boolean };
        affinity: { policy: string; rationale: string; probe?: unknown };
        cpuGovernor: string;
        powerSource: string;
        fsBasis: string;
        invocations: number;
      };
    };
    if (zk.schema !== "pqid/zk-bench/v2") return; // pre-V6 sample
    expect(zk.controls).toBeDefined();
    expect(zk.controls?.quiesce.quiesced).toBe(true);
    expect(zk.controls?.affinity.rationale).toMatch(/pthread|multithreaded/);
    expect(zk.controls?.affinity.probe).toBeDefined();
    expect(zk.controls?.cpuGovernor.length).toBeGreaterThan(0);
    expect(zk.controls?.invocations).toBeGreaterThanOrEqual(3);
  });
});

describe("§F circomspect gate artifact", () => {
  const auditPath = path.join(RESULTS_DIR, "circomspect.json");
  it.skipIf(!fs.existsSync(auditPath))("audit passed with zero blocking findings", () => {
    const audit = JSON.parse(fs.readFileSync(auditPath, "utf8")) as {
      pass: boolean;
      blockingFindings: number;
      publicSignalConstraintCoverage: Record<string, string>;
    };
    expect(audit.pass).toBe(true);
    expect(audit.blockingFindings).toBe(0);
    // every public signal accounted for
    for (const sig of ["issuerKeyHash", "revRoot", "policyHash", "nonce", "stmtCode"]) {
      expect(audit.publicSignalConstraintCoverage[sig]).toBeDefined();
    }
  });
});
