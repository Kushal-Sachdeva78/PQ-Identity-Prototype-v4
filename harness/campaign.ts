import { spawnSync } from "node:child_process";
import { REPO_ROOT } from "@pqid/common/paths";
import { assertQuiesced } from "./bench_env.ts";

/**
 * V6 §B — the controlled measurement campaign. Runs every measured artifact
 * STRICTLY SERIALLY on a quiesced machine (the guard refuses otherwise; each
 * bench re-checks on its own). Never run builds, tests, lint, or doc
 * generation concurrently with this.
 *
 *   1. circomspect gate (static, not timing-sensitive)
 *   2. bench:pqc      (Table IV, 3×2 python invocations)
 *   3. bench:zk       (Table V, 3 invocations × {witness, snarkjs cold/amort,
 *                      verify, rapidsnark cold/amort})
 *   4. bench:baseline (Table VI, 3 worker invocations)
 *   5. gas            (deterministic units; quiesced anyway)
 *   6. negative test, malicious-wallet probe, e2e
 *   7. e2e latency budget (§E), RESULTS.md + reconciliation regeneration
 */
const STEPS: Array<[string, string[]]> = [
  ["circomspect gate", ["tsx", "harness/circomspect_audit.ts"]],
  ["bench:pqc", ["tsx", "harness/bench_pqc.ts"]],
  ["bench:zk", ["tsx", "harness/bench_zk.ts"]],
  ["bench:baseline", ["tsx", "packages/baseline/bench_baseline.ts"]],
  ["gas", ["tsx", "onchain/measure_gas.ts"]],
  ["negative test", ["tsx", "harness/negative_test.ts"]],
  ["malicious-wallet probe", ["tsx", "harness/malicious_wallet_probe.ts"]],
  ["e2e", ["tsx", "harness/e2e.ts"]],
  ["e2e latency budget", ["tsx", "harness/e2e_latency.ts"]],
  ["tables (RESULTS.md + reconciliation)", ["tsx", "harness/generate_results.ts"]],
];

function main(): void {
  console.log("[campaign] §B guard…");
  // The campaign's own launch chain (npx -> npm-exec node -> tsx node) is up
  // to 3 node processes; +1 slack. Foreign build tooling is still forbidden
  // by name, and CPU-load/WSL-load thresholds apply regardless.
  assertQuiesced({ allowedNodeCount: 4 });
  // Inner benches inherit a node-process budget covering the legitimate
  // campaign->bench->worker npx/tsx chains (≈6; one spare for transient npm).
  process.env["PQID_ALLOWED_NODE"] = "8";
  const t0 = Date.now();
  for (const [name, args] of STEPS) {
    console.log(`\n[campaign] ===== ${name} =====`);
    const res = spawnSync(process.platform === "win32" ? "npx.cmd" : "npx", args, {
      cwd: REPO_ROOT,
      stdio: "inherit",
      shell: process.platform === "win32",
      env: process.env,
    });
    if (res.status !== 0) {
      console.error(`[campaign] step "${name}" FAILED (exit ${res.status}) — aborting`);
      process.exit(1);
    }
  }
  console.log(`\n[campaign] COMPLETE in ${((Date.now() - t0) / 60000).toFixed(1)} min`);
}

main();
