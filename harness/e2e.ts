import fs from "node:fs";
import path from "node:path";
import { RESULTS_DIR } from "@pqid/common/paths";
import { hostMeta, wslMeta } from "@pqid/common/meta";
import { runLifecycle } from "./e2e_core.ts";

/** Headless E2E (positive path) — writes results/e2e.json. */
async function main(): Promise<void> {
  const result = await runLifecycle((s) => {
    console.log(`${s.ok ? "✓" : "✗"} [${s.wallMs.toFixed(0).padStart(6)} ms] ${s.step}`);
  });
  const out = {
    schema: "pqid/e2e/v1",
    label:
      "[M] end-to-end pipeline execution; wall times include WSL-bridge and EVM overhead and are NOT the Table IV/V numbers (see pqc.json / zk.json)",
    ok: result.ok,
    issuanceImpl: result.issuanceImpl,
    issuanceNote:
      "issuance signs with dilithium-py 1.4.0 (paper A.5); the wallet verifies that signature with liboqs 0.15.0 — a live cross-implementation check, excluded from timing tables",
    vcBytes: result.vcBytes,
    proofBytes: result.proofBytes,
    steps: result.steps,
    host: hostMeta(),
    wsl: wslMeta(),
  };
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  const outFile = path.join(RESULTS_DIR, "e2e.json");
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
  console.log(`\n[e2e] ${result.ok ? "ALL STEPS PASSED" : "FAILED"} -> ${outFile}`);
  process.exit(result.ok ? 0 : 1);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
