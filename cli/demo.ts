import fs from "node:fs";
import path from "node:path";
import { RESULTS_DIR } from "@pqid/common/paths";
import { runLifecycle, type E2EStep } from "@pqid/harness/e2e-core";

/**
 * `make demo` — the full credential lifecycle with human-readable output:
 *   register → issue → prove (snarkJS + rapidsnark) → verify → revoke →
 *   re-verify (REJECTED). A transcript is written to
 *   results/demo_transcript.txt for the supplementary materials.
 */
const lines: string[] = [];
function say(line = ""): void {
  console.log(line);
  lines.push(line);
}

const PHASES: Array<[RegExp, string]> = [
  [/^ledger: start/, "\n━━ Phase 0 · Local ledger (single-node EVM; multi-node BFT is [F]) ━━"],
  [/^issuer: ML-DSA-44 keygen/, "\n━━ Phase 1 · DID registration (Algorithm 1) ━━"],
  [/^revocation: build/, "\n━━ Phase 2 · Revocation accumulator (depth-32 Poseidon SMT) ━━"],
  [/^issuer: issue VC/, "\n━━ Phase 3 · Credential issuance (Algorithm 2) ━━"],
  [/^wallet: OFF-CIRCUIT/, "\n━━ Phase 4 · Two-phase authentication (Algorithm 3) ━━"],
  [/^issuer: REVOKE/, "\n━━ Phase 5 · Revocation (Algorithm 4) + post-revocation rejection ━━"],
];

async function main(): Promise<void> {
  say("PQ-ID prototype demo — IEEE Access-2026-15409 reference implementation");
  say(`started ${new Date().toISOString()}`);

  const result = await runLifecycle((s: E2EStep) => {
    for (const [re, banner] of PHASES) {
      if (re.test(s.step)) say(banner);
    }
    const mark = s.ok ? "✓" : "✗";
    say(`  ${mark} ${s.step}  (${s.wallMs.toFixed(0)} ms)`);
    if (s.detail && !s.ok) say(`      ${JSON.stringify(s.detail)}`);
  });

  say("");
  say("━━ Summary ━━");
  say(`  steps: ${result.steps.length}, all passed: ${result.ok}`);
  say(`  VC size (canonical JSON incl. Dilithium signature): ${result.vcBytes} B`);
  say(`  proof size: ${result.proofBytes.snarkjs} B (snarkJS) / ${result.proofBytes.rapidsnark} B (rapidsnark)`);
  say(`  issuance signer: ${result.issuanceImpl} (verified by liboqs in the wallet — live interop)`);
  say("");
  say(result.ok
    ? "LIFECYCLE COMPLETE — including the required post-revocation rejection."
    : "LIFECYCLE FAILED — see steps above.");

  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  const transcript = path.join(RESULTS_DIR, "demo_transcript.txt");
  fs.writeFileSync(transcript, lines.join("\n") + "\n");
  console.log(`\ntranscript -> ${transcript}`);
  process.exit(result.ok ? 0 : 1);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
