import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { REPO_ROOT, CIRCUIT_BUILD_DIR_V3 } from "@pqid/common/paths";

/**
 * The attacker's own witness generator: circuits/credential_auth_v3.circom
 * compiled with one defence line deleted. Removing an `===` between existing
 * signals leaves the wire layout unchanged (checked by comparing the .sym
 * with the committed one), so the witness it produces can be fed to the REAL
 * v3 proving key. That is exactly what a malicious prover can do, so a route
 * built this way tests the R1CS and the proof system, not the reference wasm's
 * assertions.
 */
export interface AttackerCircuit {
  dir: string;
  wasm: string;
  /** True iff the attacker build's wire layout equals the committed v3 build. */
  sameWireLayout: boolean;
  cleanup(): void;
}

function circomBinary(): string {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  return process.platform === "win32" && fs.existsSync(win) ? win : "circom";
}

export function compileV3Without(defenceLine: string): AttackerCircuit {
  const srcFile = path.join(REPO_ROOT, "circuits", "credential_auth_v3.circom");
  const src = fs.readFileSync(srcFile, "utf8");
  if (!src.includes(defenceLine)) throw new Error(`defence line not found in the v3 circuit: ${defenceLine}`);
  const nodeModules = path.join(REPO_ROOT, "node_modules").split(path.sep).join("/");
  const attackerSrc = src
    .replace(defenceLine, "// (removed by the attacker)")
    .split('"../node_modules/')
    .join(`"${nodeModules}/`);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-attacker-"));
  const file = path.join(dir, "credential_auth_v3.circom");
  fs.writeFileSync(file, attackerSrc);
  execFileSync(circomBinary(), [file, "--O2", "--wasm", "--sym", "-o", dir], { encoding: "utf8" });
  const sym = fs.readFileSync(path.join(dir, "credential_auth_v3.sym"));
  const committed = fs.readFileSync(path.join(CIRCUIT_BUILD_DIR_V3, "credential_auth_v3.sym"));
  return {
    dir,
    wasm: path.join(dir, "credential_auth_v3_js", "credential_auth_v3.wasm"),
    sameWireLayout: sym.equals(committed),
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}
