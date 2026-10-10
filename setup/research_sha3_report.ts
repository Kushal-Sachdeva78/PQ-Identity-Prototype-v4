import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { REPO_ROOT, CIRCUIT_BUILD_DIR } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";

/**
 * Compiles the [F]-labeled research circuit (SHA-3/Keccak in-circuit) and
 * records its constraint count — evidence for the Gap-1 decision that SHA-3
 * cannot live inside the ~21k-constraint production circuit.
 */
function circomBinary(): string {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  if (process.platform === "win32" && fs.existsSync(win)) return win;
  return "circom";
}

async function main(): Promise<void> {
  const outDir = path.join(CIRCUIT_BUILD_DIR, "research");
  fs.mkdirSync(outDir, { recursive: true });
  const circuit = path.join(REPO_ROOT, "circuits", "research", "sha3_incircuit.circom");
  console.log("[research] compiling Keccak(1088,256) — r1cs only…");
  // -l node_modules lets keccak256-circom's "../node_modules/circomlib/…"
  // includes resolve against the hoisted root node_modules.
  const out = execFileSync(circomBinary(), [circuit, "--r1cs", "-o", outDir, "-l", "node_modules"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  console.log(out);

  const snarkjs = await import("snarkjs");
  const info = await snarkjs.r1cs.info(path.join(outDir, "sha3_incircuit.r1cs"));

  const perBlock = info.nConstraints;
  const report = {
    label: "[F] future work — constraint-count report only (never benchmarked)",
    circuit: "circuits/research/sha3_incircuit.circom (Keccak(1088,256), 1 sponge block)",
    proxyNote:
      "Keccak-256 as constraint-count proxy for SHA3-256 (identical permutation/rate; only padding constants differ)",
    constraintsPerBlock: perBlock,
    wires: info.nVars,
    estimates: {
      productionPoseidonCircuitConstraints: 21159,
      sha3CredIdBindingMinBlocks: 11,
      sha3CredIdBindingMinConstraints: perBlock * 11,
      sha3Depth32MerkleBlocks: 32,
      sha3Depth32MerkleConstraints: perBlock * 32,
      sha3FullRelationConstraints: perBlock * (11 + 32),
      note:
        "cred ‖ pk_issuer is ≥ 1,408 bytes → ≥ 11 rate blocks; a depth-32 SHA-3 " +
        "Merkle path adds 32 permutations. In-circuit Dilithium verification (also [F]) " +
        "is estimated at millions of constraints in the manuscript.",
    },
    host: hostMeta(),
  };
  const outFile = path.join(outDir, "sha3_research_info.json");
  fs.writeFileSync(outFile, JSON.stringify(report, null, 2));
  console.log(
    `[research] Keccak block = ${perBlock} constraints; full SHA-3 relation ≈ ` +
      `${report.estimates.sha3FullRelationConstraints} (vs production ${report.estimates.productionPoseidonCircuitConstraints}) -> ${outFile}`
  );
  process.exit(0);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
