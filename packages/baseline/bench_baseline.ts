import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { REPO_ROOT, RESULTS_DIR } from "@pqid/common/paths";
import type { SampleSummary } from "@pqid/common/stats";
import {
  assertQuiesced,
  collectControls,
  interRun,
  headline,
  type InterRunStats,
} from "../../harness/bench_env.ts";

/**
 * Table VI baseline coordinator, V6 revision: ≥3 independent worker
 * invocations (separate Node processes, §B5), aggregated per metric.
 * The measurement itself lives in baseline_worker.ts.
 */
const RUNS = Number(process.env["PQID_BASELINE_RUNS"] ?? 3);

interface AggOp {
  headline: { valueMs: number; basis: "mean" | "median"; rule: string };
  repr: SampleSummary;
  perRun: SampleSummary[];
  interRun: InterRunStats;
}

interface WorkerRun {
  config: Record<string, unknown>;
  ecdsaP256: Record<string, SampleSummary | Record<string, number>>;
  oauth2Tokens: Record<string, SampleSummary | number>;
  postgres: Record<string, SampleSummary | unknown>;
}

const METRICS: Array<[keyof WorkerRun, string]> = [
  ["ecdsaP256", "keygen"],
  ["ecdsaP256", "sign"],
  ["ecdsaP256", "verify"],
  ["oauth2Tokens", "jwtIssue"],
  ["oauth2Tokens", "jwtVerify"],
  ["postgres", "insert"],
  ["postgres", "tokenAuthSelect"],
];

function agg(perRun: SampleSummary[]): AggOp {
  const repr = [...perRun].sort((a, b) => a.medianMs - b.medianMs)[
    Math.floor(perRun.length / 2)
  ] as SampleSummary;
  return { headline: headline(repr), repr, perRun, interRun: interRun(perRun) };
}

function main(): void {
  const quiesce = assertQuiesced({ allowedNodeCount: 3 });
  const runs: WorkerRun[] = [];
  for (let i = 1; i <= RUNS; i++) {
    console.log(`[baseline] worker run ${i}/${RUNS}…`);
    const outFile = path.join(os.tmpdir(), `pqid-baseline-${randomBytes(3).toString("hex")}.json`);
    const res = spawnSync(
      process.platform === "win32" ? "npx.cmd" : "npx",
      ["tsx", "packages/baseline/baseline_worker.ts"],
      {
        cwd: REPO_ROOT,
        encoding: "utf8",
        shell: process.platform === "win32",
        env: { ...process.env, PQID_RUN_OUT: outFile },
        maxBuffer: 64 * 1024 * 1024,
      }
    );
    if (res.status !== 0) throw new Error(`baseline worker #${i} failed: ${res.stderr}`);
    runs.push(JSON.parse(fs.readFileSync(outFile, "utf8")) as WorkerRun);
    fs.rmSync(outFile, { force: true });
  }

  const aggregated: Record<string, Record<string, AggOp>> = {};
  for (const [section, metric] of METRICS) {
    const sec = (aggregated[section as string] ??= {});
    sec[metric] = agg(runs.map((r) => (r[section] as Record<string, SampleSummary>)[metric] as SampleSummary));
  }

  const first = runs[0] as WorkerRun;
  const result = {
    schema: "pqid/baseline/v2",
    label: "[M] measured under §B controls (upgrades the paper's [A] baseline column)",
    controls: collectControls({
      quiesce,
      fsBasis: "Node host process; PostgreSQL over localhost TCP into WSL2",
      invocations: RUNS,
    }),
    config: { ...first.config, runs: RUNS },
    ecdsaP256: { ...aggregated["ecdsaP256"], sizes: first.ecdsaP256["sizes"] },
    oauth2Tokens: {
      ...aggregated["oauth2Tokens"],
      opaqueTokenBytes: first.oauth2Tokens["opaqueTokenBytes"],
      jwtEs256Bytes: first.oauth2Tokens["jwtEs256Bytes"],
    },
    postgres: {
      ...aggregated["postgres"],
      serverVersion: first.postgres["serverVersion"],
      storage: first.postgres["storage"],
      note: first.postgres["note"],
    },
  };
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  const outFile = path.join(RESULTS_DIR, "baseline.json");
  fs.writeFileSync(outFile, JSON.stringify(result, null, 2));

  const e = aggregated["ecdsaP256"] as Record<string, AggOp>;
  const p = aggregated["postgres"] as Record<string, AggOp>;
  console.log(
    `[baseline] ECDSA sign ${e["sign"]?.headline.valueMs} / verify ${e["verify"]?.headline.valueMs} ms ` +
      `(paper ref 0.2/0.3); PG insert ${p["insert"]?.headline.valueMs} / auth-select ${p["tokenAuthSelect"]?.headline.valueMs} ms -> ${outFile}`
  );
}

main();
