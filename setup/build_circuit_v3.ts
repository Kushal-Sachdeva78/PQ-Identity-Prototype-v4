import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { REPO_ROOT, CIRCUIT_BUILD_DIR_V3, R1CS_FILE_V3 } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";

/**
 * Compile circuits/credential_auth_v3.circom with the pinned circom 2.2.3
 * binary and record the real constraint/wire/input counts.
 *
 * v3 is compiled with --O2 (full linear simplification). At circom's default
 * --O1 the v3 system has 39,354 constraints, which exceeds the 2^15 capacity
 * of the committed powers-of-tau; --O2 removes the linear constraints by
 * substitution. For a like-for-like cost comparison, harness/v3/compare_v2_v3.ts
 * also compiles v2 at --O2 (10,588 constraints).
 */
function circomBinary(): string {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  if (process.platform === "win32" && fs.existsSync(win)) return win;
  return "circom"; // PATH fallback (Linux/CI)
}

async function main(): Promise<void> {
  fs.mkdirSync(CIRCUIT_BUILD_DIR_V3, { recursive: true });
  const circuit = path.join(REPO_ROOT, "circuits", "credential_auth_v3.circom");

  const args = [
    circuit,
    "--O2",
    "--r1cs",
    "--wasm",
    "--sym",
    "--inspect",
    "-o",
    CIRCUIT_BUILD_DIR_V3,
  ];
  console.log(`[circom] ${circomBinary()} ${args.join(" ")}`);
  const compileOut = execFileSync(circomBinary(), args, {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  console.log(compileOut);
  // Keep the committed record free of ANSI colour codes and of this machine's
  // absolute paths (review 9.13: v2's circuit_info.json leaks a local path).
  const esc = String.fromCharCode(27);
  const cleanStdout = compileOut
    .split(esc)
    .map((part, i) => (i === 0 ? part : part.replace(/^\[[0-9;]*m/, "")))
    .join("")
    .split(REPO_ROOT)
    .join("<repo>")
    .split(REPO_ROOT.replace(/\\/g, "/"))
    .join("<repo>");

  const snarkjs = await import("snarkjs");
  const info = await snarkjs.r1cs.info(R1CS_FILE_V3);
  const circuitInfo = {
    source: "circuits/credential_auth_v3.circom",
    compiler: "circom 2.2.3",
    optimization: "--O2",
    curve: "BN254",
    nConstraints: info.nConstraints,
    nWires: info.nVars,
    nPubInputs: info.nPubInputs,
    nPrvInputs: info.nPrvInputs,
    nOutputs: info.nOutputs,
    nLabels: Number(info.nLabels),
    circomStdout: cleanStdout,
    host: hostMeta(),
  };
  const outFile = path.join(CIRCUIT_BUILD_DIR_V3, "circuit_info.json");
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
