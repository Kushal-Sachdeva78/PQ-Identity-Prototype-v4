import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { REPO_ROOT, RESULTS_DIR, toWslPath } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";

/**
 * V6 §F — circuit soundness audit gate. Runs circomspect (trailofbits) over
 * the production circuit, parses the SARIF, applies the documented triage,
 * and FAILS (exit 1) on any non-triaged finding in our templates.
 *
 * Triage policy:
 *  - Findings in circomlib's own templates are upstream-library findings; the
 *    pinned circomlib 2.0.5 gadgets (Poseidon, SMTVerifier, comparators) are
 *    widely audited; anything appearing there is reported but non-blocking.
 *  - Findings in CredentialAuth are blocking unless explicitly triaged below
 *    with a justification.
 */
interface Triage {
  signal: string;
  rule: string;
  justification: string;
}

const TRIAGED_ACCEPTED: Triage[] = [
  {
    signal: "nonceSq",
    rule: "under-constrained-signal (single-constraint intermediate)",
    justification:
      "Intentional statement-binding square: anchors the verifier-chosen public nonce into the " +
      "constraint system so it cannot be dangling. The square itself carries no semantic value; " +
      "the canonical anchoring pattern (cf. tornado-core recipientSquare).",
  },
  {
    signal: "issuerKeyHashSq",
    rule: "under-constrained-signal (single-constraint intermediate)",
    justification:
      "Intentional statement-binding square for the public issuerKeyHash (its semantic check — " +
      "equality with Poseidon(pk_issuer resolved on-chain) — is the verifier's off-circuit duty " +
      "per the two-phase design).",
  },
];

interface SarifResult {
  ruleId?: string;
  level?: string;
  message?: { text?: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: { startLine?: number };
    };
  }>;
}

function main(): void {
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  const sarifPath = path.join(RESULTS_DIR, "circomspect.sarif");
  const cmd =
    `cd ${toWslPath(REPO_ROOT)} && /root/.cargo/bin/circomspect ` +
    `circuits/credential_auth.circom -L node_modules/circomlib/circuits ` +
    `--level WARNING --sarif-file results/circomspect.sarif`;
  const res = spawnSync("wsl", ["-u", "root", "-e", "bash", "-c", cmd], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  // circomspect exits non-zero when issues are found; the gate below decides.
  if (!fs.existsSync(sarifPath)) {
    throw new Error(`circomspect produced no SARIF output: ${res.stderr} ${res.stdout}`);
  }

  const sarif = JSON.parse(fs.readFileSync(sarifPath, "utf8")) as {
    runs?: Array<{ results?: SarifResult[] }>;
  };
  const circuitSource = fs
    .readFileSync(path.join(REPO_ROOT, "circuits", "credential_auth.circom"), "utf8")
    .split(/\r?\n/);
  const findings = (sarif.runs ?? []).flatMap((r) => r.results ?? []).map((f) => {
    const uri = f.locations?.[0]?.physicalLocation?.artifactLocation?.uri ?? "";
    const line = f.locations?.[0]?.physicalLocation?.region?.startLine ?? 0;
    const text = f.message?.text ?? "";
    const inOurCircuit = uri.includes("credential_auth.circom");
    // The SARIF message is generic; the affected signal is identified by the
    // flagged source line. Triage matches on the declaration line content.
    const flaggedLine = inOurCircuit ? (circuitSource[line - 1] ?? "") : "";
    const triage = TRIAGED_ACCEPTED.find(
      (t) => text.includes(`\`${t.signal}\``) || flaggedLine.includes(t.signal)
    );
    return {
      ruleId: f.ruleId ?? "unknown",
      level: f.level ?? "warning",
      message: text,
      file: uri.split("/").slice(-1)[0],
      line,
      inOurCircuit,
      status: !inOurCircuit
        ? "library (non-blocking, reported)"
        : triage
          ? "triaged-accepted"
          : "BLOCKING",
      justification: triage?.justification,
    };
  });

  const blocking = findings.filter((f) => f.status === "BLOCKING");
  const summary = {
    schema: "pqid/circomspect/v1",
    label:
      "[M] static soundness audit (circomspect; a third-party cryptographic audit remains [F])",
    tool: "circomspect (trailofbits), level WARNING, curve BN254",
    circuit: "circuits/credential_auth.circom (CredentialAuth(32) v2)",
    totalFindings: findings.length,
    blockingFindings: blocking.length,
    pass: blocking.length === 0,
    publicSignalConstraintCoverage: {
      issuerKeyHash: "binding square (triaged) + verifier on-chain equality off-circuit",
      revRoot: "SMTVerifier(32) root input — real constraint",
      policyHash: "Poseidon(predicateCode, threshold) equality — real constraint",
      nonce: "binding square (triaged) + verifier freshness check off-circuit",
      stmtCode: "Poseidon(STMT_V1, domainTag) equality — real constraint (V6 §F3)",
    },
    findings,
    host: hostMeta(),
  };
  const outPath = path.join(RESULTS_DIR, "circomspect.json");
  fs.writeFileSync(outPath, JSON.stringify(summary, null, 2));
  console.log(
    `[circomspect] ${findings.length} finding(s), ${blocking.length} blocking -> ${outPath}`
  );
  for (const f of findings) {
    console.log(`  [${f.status}] ${f.file}:${f.line} ${f.ruleId}`);
  }
  if (blocking.length > 0) {
    console.error("[circomspect] GATE FAILED — unresolved findings in CredentialAuth");
    process.exit(1);
  }
  console.log("[circomspect] gate PASSED");
}

main();
