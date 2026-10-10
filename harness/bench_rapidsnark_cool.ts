import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { RESULTS_DIR, ZKEY_FILE, VKEY_FILE, REPO_ROOT, toWslPath } from "@pqid/common/paths";
import { sha256File } from "@pqid/common/hash";
import { summarize, type SampleSummary } from "@pqid/common/stats";
import { assertQuiesced, collectControls, interRun, headline } from "./bench_env.ts";

/**
 * §C1 — rapidsnark re-measured on a COOL machine. The full campaign measures
 * rapidsnark LAST, after ~50 minutes of sustained snarkJS proving, i.e. at
 * maximum heat soak on this 15 W ULV part (the campaign's snarkJS inter-run
 * bimodality — run 1 ≈ 981 ms vs runs 2–3 ≈ 2.1 s — exposed thermal state as
 * the dominant confound). This bench isolates that confound: run it after a
 * ≥10-minute idle cool-down; it reuses the SAME staged, SHA-256-verified
 * zkey + witness on WSL-native ext4 and writes a separate results file with
 * a thermal-state annotation. This is a controlled experiment on a recorded
 * confound — not tuning.
 */
const RUNS = Number(process.env["PQID_ZK_RUNS"] ?? 3);
const N = Number(process.env["PQID_ZK_RAPIDSNARK_N"] ?? 100);
const WARMUP = Number(process.env["PQID_ZK_WARMUP"] ?? 5);
const BENCH_WSL = "/root/pqid-native/bench";
const PROVER_WSL = "/root/pqid-native/rapidsnark/bin/prover";

function wsl(cmd: string): string {
  return execFileSync("wsl", ["-u", "root", "-e", "bash", "-c", cmd], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  })
    .split(String.fromCharCode(0))
    .join("");
}

async function main(): Promise<void> {
  const quiesce = assertQuiesced({ allowedNodeCount: 3 });

  // staged inputs must still match the pinned zkey (byte-identical discipline)
  const zkeySha = sha256File(ZKEY_FILE);
  const stagedSha = wsl(`sha256sum ${BENCH_WSL}/bench.zkey | cut -d' ' -f1`).trim();
  if (stagedSha !== zkeySha) {
    throw new Error(`staged zkey (${stagedSha.slice(0, 12)}…) != pinned (${zkeySha.slice(0, 12)}…) — re-run bench:zk staging`);
  }

  const benchScript = path.join(REPO_ROOT, "harness", "rapidsnark_bench.sh");
  wsl(`tr -d '\\r' < ${toWslPath(benchScript)} > /tmp/pqid_rs_bench.sh`);

  const coldRuns: SampleSummary[] = [];
  const amortRuns: SampleSummary[] = [];
  for (let i = 1; i <= RUNS; i++) {
    console.log(`[rapidsnark-cool] cold run ${i}/${RUNS} (N=${N})…`);
    wsl(
      `bash /tmp/pqid_rs_bench.sh ${PROVER_WSL} ${BENCH_WSL}/bench.zkey ${BENCH_WSL}/bench.wtns ` +
        `${BENCH_WSL}/proof.json ${BENCH_WSL}/public.json ${N} ${WARMUP} ${BENCH_WSL}/samples.txt`
    );
    coldRuns.push(
      summarize(wsl(`cat ${BENCH_WSL}/samples.txt`).trim().split(/\r?\n/).map((l) => Number(l) / 1000))
    );
    console.log(`[rapidsnark-cool] amortized run ${i}/${RUNS} (N=${N})…`);
    wsl(
      `cd ${BENCH_WSL} && ./amortized_prover bench.zkey bench.wtns ${N} ${WARMUP} ` +
        `samples_amort.txt proof_amort.json public_amort.json 2>/dev/null`
    );
    amortRuns.push(
      summarize(wsl(`cat ${BENCH_WSL}/samples_amort.txt`).trim().split(/\r?\n/).map((l) => Number(l) / 1000))
    );
  }

  // the cool-state proof must still verify
  const snarkjs = await import("snarkjs");
  const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, "utf8")) as unknown;
  const proof = JSON.parse(wsl(`cat ${BENCH_WSL}/proof.json`)) as never;
  const signals = JSON.parse(wsl(`cat ${BENCH_WSL}/public.json`)) as string[];
  const verifies = await snarkjs.groth16.verify(vkey, signals, proof);
  if (!verifies) throw new Error("cool-state proof did not verify");

  const rep = (runs: SampleSummary[]): SampleSummary =>
    [...runs].sort((a, b) => a.medianMs - b.medianMs)[Math.floor(runs.length / 2)] as SampleSummary;
  const result = {
    schema: "pqid/zk-rapidsnark-cool/v1",
    label: "[M] §C1 cool-state re-measurement (thermal-confound isolation)",
    thermalState:
      "run after a >=10-minute idle cool-down on the quiesced machine — versus the campaign's " +
      "zk.json where rapidsnark executed LAST, heat-soaked after ~50 min of sustained snarkJS " +
      "proving. Identical staged zkey+witness (SHA-256-verified), identical N/warmup/method.",
    controls: collectControls({
      quiesce,
      fsBasis: "WSL-native ext4 staged inputs (same files as zk.json)",
      invocations: RUNS,
    }),
    config: { n: N, warmup: WARMUP, runs: RUNS, zkeySha256: zkeySha },
    cold: { perRun: coldRuns, interRun: interRun(coldRuns), headline: headline(rep(coldRuns)) },
    amortized: { perRun: amortRuns, interRun: interRun(amortRuns), headline: headline(rep(amortRuns)) },
    proofVerifies: verifies,
    campaignComparison: {
      note: "compare against results/zk.json rapidsnarkProveCold/Amortized (heat-soaked ordering)",
    },
    paperClaim: { manuscriptVersion: "V6.6", coolMs: 177 },
  };
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  const outFile = path.join(RESULTS_DIR, "zk_rapidsnark_cool.json");
  fs.writeFileSync(outFile, JSON.stringify(result, null, 2));
  console.log(
    `[rapidsnark-cool] cold ${result.cold.headline.valueMs} ms (runs ${result.cold.interRun.mediansMs.join("/")}, CV ${result.cold.interRun.cvPct}%); ` +
      `amortized ${result.amortized.headline.valueMs} ms (CV ${result.amortized.interRun.cvPct}%) (V6.6 cool 177) -> ${outFile}`
  );
  process.exit(0);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
