import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { REPO_ROOT, RESULTS_DIR, PQID_NATIVE_WSL, toWslPath } from "@pqid/common/paths";
import type { SampleSummary } from "@pqid/common/stats";
import { assertQuiesced, collectControls, interRun, headline, type InterRunStats } from "./bench_env.ts";

/**
 * Table IV benchmark driver, V6 revision: per liboqs build, ≥3 independent
 * python invocations (separate processes, §B5), aggregated per operation.
 *   - generic  : reference optimized-C, AVX2 OFF — the paper's configuration
 *   - avx2     : dist build, runtime AVX2 dispatch — the paper's [A] upgraded
 */
const RUNS = Number(process.env["PQID_PQC_RUNS"] ?? 3);
const N = Number(process.env["PQID_PQC_N"] ?? 1000);
const WARMUP = Number(process.env["PQID_PQC_WARMUP"] ?? 5);

type OpStats = SampleSummary;
interface PyRun {
  config: Record<string, unknown>;
  algorithms: Record<string, Record<string, OpStats | Record<string, number>>>;
}

interface AggOp {
  headline: { valueMs: number; basis: "mean" | "median"; rule: string };
  repr: OpStats;
  perRun: OpStats[];
  interRun: InterRunStats;
}

function runPython(build: "generic" | "avx2"): PyRun {
  const script = toWslPath(path.join(REPO_ROOT, "packages", "pqc", "bench_pqc.py"));
  const label = build === "generic" ? "reference-optimized-C-noAVX2" : "dist-AVX2";
  const cmd =
    `OQS_INSTALL_PATH=${PQID_NATIVE_WSL}/liboqs-${build} PQID_LIBOQS_BUILD=${label} ` +
    `${PQID_NATIVE_WSL}/venv/bin/python ${script} --n ${N} --warmup ${WARMUP}`;
  const res = spawnSync("wsl", ["-u", "root", "-e", "bash", "-c", cmd], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (res.status !== 0) throw new Error(`bench_pqc.py (${build}) failed: ${res.stderr}`);
  const payload = res.stdout.split("===PQID_JSON===")[1];
  if (!payload) throw new Error("no JSON payload");
  return JSON.parse(payload) as PyRun;
}

const OPS: Record<string, string[]> = {
  "ML-DSA-44": ["keygen", "sign", "verify"],
  "ML-KEM-512": ["keygen", "encap", "decap"],
};

function aggregateBuild(runs: PyRun[]): Record<string, Record<string, AggOp | unknown>> {
  const out: Record<string, Record<string, AggOp | unknown>> = {};
  for (const [alg, ops] of Object.entries(OPS)) {
    out[alg] = {};
    for (const op of ops) {
      const perRun = runs.map((r) => r.algorithms[alg]?.[op] as OpStats);
      const ir = interRun(perRun);
      const repr = [...perRun].sort((a, b) => a.medianMs - b.medianMs)[
        Math.floor(perRun.length / 2)
      ] as OpStats;
      (out[alg] as Record<string, AggOp>)[op] = { headline: headline(repr), repr, perRun, interRun: ir };
    }
    (out[alg] as Record<string, unknown>)["sizes"] = runs[0]?.algorithms[alg]?.["sizes"];
  }
  return out;
}

function main(): void {
  const quiesce = assertQuiesced({ allowedNodeCount: 2 });
  fs.mkdirSync(RESULTS_DIR, { recursive: true });

  for (const build of ["generic", "avx2"] as const) {
    console.log(`[bench:pqc] ${build}: ${RUNS} independent invocations, N=${N}, warmup=${WARMUP}…`);
    const runs: PyRun[] = [];
    for (let i = 1; i <= RUNS; i++) {
      console.log(`[bench:pqc]   run ${i}/${RUNS}`);
      runs.push(runPython(build));
    }
    const result = {
      schema: "pqid/pqc-bench/v2",
      label: "[M] measured under §B controls",
      controls: collectControls({
        quiesce,
        fsBasis: "in-process loops inside WSL python (no per-op I/O)",
        invocations: RUNS,
      }),
      config: { ...runs[0]?.config, runs: RUNS },
      algorithms: aggregateBuild(runs),
    };
    const file = build === "generic" ? "pqc.json" : "pqc_avx2.json";
    fs.writeFileSync(path.join(RESULTS_DIR, file), JSON.stringify(result, null, 2));
    const d = result.algorithms["ML-DSA-44"] as Record<string, AggOp>;
    const k = result.algorithms["ML-KEM-512"] as Record<string, AggOp>;
    console.log(
      `[bench:pqc] ${build}: ML-DSA-44 kg/s/v ${d["keygen"]?.headline.valueMs}/${d["sign"]?.headline.valueMs}/${d["verify"]?.headline.valueMs} ms | ` +
        `ML-KEM-512 kg/e/d ${k["keygen"]?.headline.valueMs}/${k["encap"]?.headline.valueMs}/${k["decap"]?.headline.valueMs} ms -> results/${file}`
    );
  }
  console.log("[bench:pqc] paper Table IV: ML-DSA-44 0.124/0.287/0.060; ML-KEM-512 0.091/0.094/0.024");
}

main();
