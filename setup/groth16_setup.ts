import fs from "node:fs";
import path from "node:path";
import {
  R1CS_FILE,
  PTAU_FILE,
  SETUP_OUT_DIR,
  ZKEY_FILE,
  VKEY_FILE,
  SOLIDITY_VERIFIER_FILE,
  REPO_ROOT,
} from "@pqid/common/paths";
import { sha256File } from "@pqid/common/hash";
import { verifyOrPin, readPins } from "./pins.ts";

/**
 * Groth16 phase-2 setup, deterministic by construction so the zkey SHA-256 is
 * byte-stable across rebuilds (determinism test requirement):
 *   r1cs + ptau --newZKey--> 0000.zkey --beacon(fixed hash)--> final.zkey
 * A real deployment must replace this with a multi-party ceremony; that is the
 * paper's [A] assumption (Appendix A.1) and is documented in REPRODUCE.md.
 */
const BEACON_HASH =
  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const BEACON_ITER_EXP = 10;

async function main(): Promise<void> {
  fs.mkdirSync(SETUP_OUT_DIR, { recursive: true });
  if (!fs.existsSync(R1CS_FILE)) throw new Error("r1cs missing — run build_circuit first");
  if (!fs.existsSync(PTAU_FILE)) throw new Error("ptau missing — run download_ptau first");

  // Verify the ptau pin on every run (abort-on-drift requirement).
  const pins = readPins();
  const ptauPin = pins["powersOfTau28_hez_final_15.ptau"];
  if (!ptauPin) throw new Error("ptau pin missing — run download_ptau first");
  const ptauNow = sha256File(PTAU_FILE);
  if (ptauNow !== ptauPin.sha256) {
    throw new Error(`ptau SHA-256 drift: pinned ${ptauPin.sha256}, actual ${ptauNow}`);
  }

  const snarkjs = await import("snarkjs");
  const zkey0 = path.join(SETUP_OUT_DIR, "credential_auth_0000.zkey");

  console.log("[setup] groth16 newZKey (phase 2 init)…");
  await snarkjs.zKey.newZKey(R1CS_FILE, PTAU_FILE, zkey0);

  console.log("[setup] beacon finalization (deterministic dev SRS; production = MPC [A])…");
  const zKeyAny = snarkjs.zKey as unknown as {
    beacon(
      oldZkey: string,
      newZkey: string,
      name: string,
      beaconHash: string,
      numIterExp: number
    ): Promise<unknown>;
  };
  await zKeyAny.beacon(zkey0, ZKEY_FILE, "pqid dev beacon", BEACON_HASH, BEACON_ITER_EXP);
  fs.rmSync(zkey0);

  console.log("[setup] exporting verification key…");
  const vkey = await snarkjs.zKey.exportVerificationKey(ZKEY_FILE);
  fs.writeFileSync(VKEY_FILE, JSON.stringify(vkey, null, 2));

  console.log("[setup] exporting Solidity verifier…");
  const templatePath = path.join(
    REPO_ROOT,
    "node_modules",
    "snarkjs",
    "templates",
    "verifier_groth16.sol.ejs"
  );
  const templates = { groth16: fs.readFileSync(templatePath, "utf8") };
  const solidity = await snarkjs.zKey.exportSolidityVerifier(ZKEY_FILE, templates);
  fs.writeFileSync(SOLIDITY_VERIFIER_FILE, solidity);

  const zkeyHash = sha256File(ZKEY_FILE);
  verifyOrPin("credential_auth_final.zkey", zkeyHash, {
    note: "Deterministic beacon-finalized dev zkey; paper's zkey was 22e69c5b… (different circuit build, see RESULTS.md divergences)",
  });
  const vkeyHash = sha256File(VKEY_FILE);
  verifyOrPin("verification_key.json", vkeyHash);

  console.log(`[setup] zkey  ${ZKEY_FILE}\n[setup] sha256 ${zkeyHash}`);
  console.log(`[setup] vkey  ${VKEY_FILE}\n[setup] sha256 ${vkeyHash}`);
  process.exit(0);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
