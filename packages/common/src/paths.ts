import path from "node:path";
import { fileURLToPath } from "node:url";

/** Absolute path of the repository root (this file lives at packages/common/src/). */
export const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  ".."
);

export const CIRCUITS_DIR = path.join(REPO_ROOT, "circuits");
export const CIRCUIT_BUILD_DIR = path.join(REPO_ROOT, "circuits", "build");
export const SETUP_DIR = path.join(REPO_ROOT, "setup");
export const SETUP_OUT_DIR = path.join(REPO_ROOT, "setup", "out");
export const PTAU_DIR = path.join(REPO_ROOT, "setup", "ptau");
export const PINS_FILE = path.join(REPO_ROOT, "setup", "pins.json");
export const FIXTURES_DIR = path.join(REPO_ROOT, "fixtures");
export const KEYS_DIR = path.join(REPO_ROOT, "fixtures", "keys");
export const RESULTS_DIR = path.join(REPO_ROOT, "results");

export const PTAU_FILE = path.join(PTAU_DIR, "powersOfTau28_hez_final_15.ptau");
export const R1CS_FILE = path.join(CIRCUIT_BUILD_DIR, "credential_auth.r1cs");
export const WASM_FILE = path.join(
  CIRCUIT_BUILD_DIR,
  "credential_auth_js",
  "credential_auth.wasm"
);
export const ZKEY_FILE = path.join(SETUP_OUT_DIR, "credential_auth_final.zkey");
export const VKEY_FILE = path.join(SETUP_OUT_DIR, "verification_key.json");
export const SOLIDITY_VERIFIER_FILE = path.join(SETUP_OUT_DIR, "Groth16Verifier.sol");

/**
 * Circuit v3 (issuance-bound credential, circuits/credential_auth_v3.circom).
 * Built and set up side by side with v2 so the published v2 artifacts and
 * their pins stay byte-identical.
 */
export const CIRCUIT_BUILD_DIR_V3 = path.join(REPO_ROOT, "circuits", "build", "v3");
export const SETUP_OUT_DIR_V3 = path.join(REPO_ROOT, "setup", "out", "v3");
export const R1CS_FILE_V3 = path.join(CIRCUIT_BUILD_DIR_V3, "credential_auth_v3.r1cs");
export const WASM_FILE_V3 = path.join(
  CIRCUIT_BUILD_DIR_V3,
  "credential_auth_v3_js",
  "credential_auth_v3.wasm"
);
export const ZKEY_FILE_V3 = path.join(SETUP_OUT_DIR_V3, "credential_auth_v3_final.zkey");
export const VKEY_FILE_V3 = path.join(SETUP_OUT_DIR_V3, "verification_key.json");
export const SOLIDITY_VERIFIER_FILE_V3 = path.join(SETUP_OUT_DIR_V3, "Groth16Verifier.sol");
export const RESULTS_DIR_V3 = path.join(REPO_ROOT, "results", "v3");

/** Path of the rapidsnark prover binary inside WSL (Linux path). */
export const RAPIDSNARK_PROVER_WSL = "/root/pqid-native/rapidsnark/bin/prover";
/** Root of the WSL-side native artifacts (Linux path). */
export const PQID_NATIVE_WSL = "/root/pqid-native";

/** Convert a Windows absolute path to its WSL /mnt/<drive>/ form. */
export function toWslPath(winPath: string): string {
  const abs = path.resolve(winPath);
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(abs);
  if (!m) throw new Error(`cannot convert path to WSL form: ${winPath}`);
  const drive = (m[1] as string).toLowerCase();
  const rest = (m[2] as string).replace(/\\/g, "/");
  return `/mnt/${drive}/${rest}`;
}
