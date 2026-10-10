import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { REPO_ROOT, CIRCUIT_BUILD_DIR, R1CS_FILE } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";

/**
 * Compile circuits/credential_auth.circom with the pinned circom 2.2.3 binary
 * and record the REAL constraint/wire/input counts (no targets, no tuning).
 * The paper claims 21,434 constraints / 21,472 wires / 5 public / 41 private;
 * divergences are recorded in RESULTS.md, not papered over.
 */
function circomBinary(): string {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  if (process.platform === "win32" && fs.existsSync(win)) return win;
  return "circom"; // PATH fallback (Linux/CI)
}

async function main(): Promise<void> {
  fs.mkdirSync(CIRCUIT_BUILD_DIR, { recursive: true });
  const circuit = path.join(REPO_ROOT, "circuits", "credential_auth.circom");

  const args = [
    circuit,
    "--r1cs",
    "--wasm",
    "--sym",
    "--inspect",
    "-o",
    CIRCUIT_BUILD_DIR,
  ];
  console.log(`[circom] ${circomBinary()} ${args.join(" ")}`);
  const compileOut = execFileSync(circomBinary(), args, {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  console.log(compileOut);

  const snarkjs = await import("snarkjs");
  const info = await snarkjs.r1cs.info(R1CS_FILE);
  const circuitInfo = {
    source: "circuits/credential_auth.circom",
    compiler: "circom 2.2.3",
    curve: "BN254",
    nConstraints: info.nConstraints,
    nWires: info.nVars,
    nPubInputs: info.nPubInputs,
    nPrvInputs: info.nPrvInputs,
    nOutputs: info.nOutputs,
    nLabels: Number(info.nLabels),
    paperClaim: {
      manuscriptVersion: "V6.6",
      nConstraints: 21715,
      nWires: 21745,
      nPubInputs: 5,
      nPrvInputs: 43,
    },
    circomStdout: compileOut,
    host: hostMeta(),
  };
  const outFile = path.join(CIRCUIT_BUILD_DIR, "circuit_info.json");
  fs.writeFileSync(outFile, JSON.stringify(circuitInfo, null, 2));
  console.log(
    `[circom] constraints=${info.nConstraints} wires=${info.nVars} ` +
      `public=${info.nPubInputs} private=${info.nPrvInputs} -> ${outFile}`
  );
  process.exit(0); // snarkjs keeps worker threads alive
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
