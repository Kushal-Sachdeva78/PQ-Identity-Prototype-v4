import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT, PTAU_FILE } from "@pqid/common/paths";

/**
 * v4 artifact paths (docs/v4/V4_DESIGN.md sections 2 and 7). All paths are absolute and
 * derived from REPO_ROOT, so scripts and tests work from any working directory.
 *
 * Every Groth16 artifact made before the ceremony is a dev artifact: the file names carry
 * the label "dev" (docs/BENCHMARK_POLICY.md, evidence rules).
 */
export { REPO_ROOT };

/** Label of the current v4 proving/verification key (replaced by the ceremony key later). */
export const KEY_LABEL_V4 = "dev";

// ---- circuit sources ----
export const CIRCUIT_V4_SRC = path.join(REPO_ROOT, "circuits", "credential_auth_v4.circom");
export const CIRCUIT_V4_LIB = path.join(REPO_ROOT, "circuits", "v4", "lib_v4.circom");

// ---- compiled circuit (setup/build_circuit_v4.ts) ----
export const BUILD_DIR_V4 = path.join(REPO_ROOT, "circuits", "build", "v4");
export const R1CS_V4 = path.join(BUILD_DIR_V4, "credential_auth_v4.r1cs");
export const WASM_V4 = path.join(BUILD_DIR_V4, "credential_auth_v4_js", "credential_auth_v4.wasm");
export const SYM_V4 = path.join(BUILD_DIR_V4, "credential_auth_v4.sym");
export const CIRCUIT_INFO_V4 = path.join(BUILD_DIR_V4, "circuit_info.json");

// ---- dev Groth16 key (setup/groth16_setup_v4.ts) ----
export const SETUP_OUT_DIR_V4 = path.join(REPO_ROOT, "setup", "out", "v4");
export const ZKEY_V4 = path.join(SETUP_OUT_DIR_V4, "credential_auth_v4_dev.zkey");
export const VKEY_V4 = path.join(SETUP_OUT_DIR_V4, "verification_key_dev.json");
export const SOL_V4 = path.join(SETUP_OUT_DIR_V4, "Groth16VerifierV4_dev.sol");
export const TRANSCRIPT_V4 = path.join(SETUP_OUT_DIR_V4, "setup_transcript_dev.json");
/** v4 pins (DECISIONS D-006); setup/pins.json (v2/v3) is read-only for v4. */
export const PINS_V4 = path.join(REPO_ROOT, "setup", "pins_v4.json");

// ---- powers of tau ----
/** Committed Hermez 2^15 file, pinned in setup/pins.json (read-only for v4). */
export const PTAU = PTAU_FILE;
/**
 * Hermez 2^16 file, for when the circuit outgrows 2^15 (TASKS S23). Not committed and
 * never downloaded by a script: the operator fetches it and checks its published hash.
 */
export const PTAU_16 = path.join(REPO_ROOT, "setup", "ptau", "powersOfTau28_hez_final_16.ptau");

// ---- results ----
export const RESULTS_V4 = path.join(REPO_ROOT, "results", "v4");

/** circom 2.2.3: the pinned Windows binary when present, else `circom` on PATH. */
export function circomBinary(): string {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  if (process.platform === "win32" && fs.existsSync(win)) return win;
  return "circom";
}

/**
 * Native rapidsnark prover binary from PQID_RAPIDSNARK, or null when unset. v4 never
 * reaches a prover through wsl.exe (DECISIONS D-001, D-002); on this Windows host the
 * variable is unset and the rapidsnark series are blocked until a Linux build exists.
 */
export function rapidsnarkBinary(): string | null {
  const v = process.env["PQID_RAPIDSNARK"]?.trim();
  return v ? v : null;
}
