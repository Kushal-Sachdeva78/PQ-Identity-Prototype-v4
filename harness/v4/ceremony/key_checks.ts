import fs from "node:fs";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { fileURLToPath } from "node:url";
import { deriveBeaconTrapdoor, forgeProof } from "../../v3/trapdoor.ts";
import { compareVkeys, type VkeyLike } from "./followup_lib.ts";

/**
 * Key checks of the ceremony follow-up, in a child process (snarkjs keeps worker threads):
 *
 *   node --import tsx harness/v4/ceremony/key_checks.ts --config <json>
 *
 * Config: { zkey, vkey, wasm, input (object), expectPublic (string[] | null),
 *           beacon: { value, iterExp },
 *           otherVkey?: file (a key of the same circuit and phase 1, e.g. the v4 dev key),
 *           control?: { vkey, beacon, iterExp } (a beacon-only key: positive control) }
 *
 * 1. The verification key file equals the one exported from the zkey.
 * 2. Proof round trip: witness and Groth16 proof with the new zkey, verified with the new vkey;
 *    public signals equal the pinned ones (when given); the same proof is rejected by the
 *    other key.
 * 3. Same circuit and phase 1 as the other key: alpha, beta, gamma and IC equal, delta differs.
 * 4. Public-beacon trapdoor (review finding 9.3, harness/v3/trapdoor.ts): delta derived from the
 *    announced beacon alone must NOT equal the key's delta (secret contributions precede the
 *    beacon), and a proof forged from it must not verify. Control: the same derivation on the
 *    committed beacon-only v2 key matches its delta, and the forged proof verifies there, so the
 *    check can see a public trapdoor when there is one. This rules out only a beacon-only key;
 *    the 1-of-N soundness argument rests on the contributors, not on this check.
 * Prints one JSON line. Paths are repo-relative to the working directory (the repo root).
 */

interface Config {
  zkey: string;
  vkey: string;
  wasm: string;
  input: Record<string, unknown>;
  expectPublic: string[] | null;
  beacon: { value: string; iterExp: number };
  otherVkey?: string | null;
  control?: { vkey: string; beacon: string; iterExp: number } | null;
}

export interface KeyChecksResult {
  schema: "pqid/v4-ceremony-key-checks/v1";
  vkeyMatchesZkeyExport: boolean;
  proof: { verifies: boolean; publicSignalsMatch: boolean | null; publicSignals: string[]; rejectedByOtherKey: boolean | null; tamperedSignalRejected: boolean };
  sameCircuitAsOther: { sameAlphaBetaGamma: boolean; sameIC: boolean; deltaDiffers: boolean } | null;
  trapdoor: {
    beaconDerivedDeltaMatchesKey: boolean;
    gammaIsGenerator: boolean;
    forgedProofVerifies: boolean;
    control: { key: string; beaconDerivedDeltaMatchesKey: boolean; forgedProofVerifies: boolean } | null;
  };
  pass: boolean;
}

function readJson<T>(f: string): T {
  return JSON.parse(fs.readFileSync(f, "utf8")) as T;
}

/** The pass rule (exported for the tests). */
export function keyChecksPass(r: Omit<KeyChecksResult, "pass" | "schema">): boolean {
  const o = r.sameCircuitAsOther;
  const c = r.trapdoor.control;
  return (
    r.vkeyMatchesZkeyExport &&
    r.proof.verifies &&
    r.proof.publicSignalsMatch !== false &&
    r.proof.rejectedByOtherKey !== false &&
    r.proof.tamperedSignalRejected &&
    (o === null || (o.sameAlphaBetaGamma && o.sameIC && o.deltaDiffers)) &&
    r.trapdoor.gammaIsGenerator &&
    !r.trapdoor.beaconDerivedDeltaMatchesKey &&
    !r.trapdoor.forgedProofVerifies &&
    (c === null || (c.beaconDerivedDeltaMatchesKey && c.forgedProofVerifies))
  );
}

export async function runKeyChecks(c: Config): Promise<KeyChecksResult> {
  const snarkjs = await import("snarkjs");
  const vkey = readJson<VkeyLike & Parameters<typeof deriveBeaconTrapdoor>[0]>(c.vkey);
  const exported = JSON.parse(JSON.stringify(await snarkjs.zKey.exportVerificationKey(c.zkey))) as unknown;
  const vkeyMatchesZkeyExport = isDeepStrictEqual(exported, vkey);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(c.input as never, c.wasm, c.zkey);
  const pubs = (publicSignals as unknown[]).map(String);
  const verifies = (await snarkjs.groth16.verify(vkey as never, publicSignals, proof)) === true;
  const publicSignalsMatch = c.expectPublic === null ? null : pubs.length === c.expectPublic.length && pubs.every((x, i) => x === c.expectPublic?.[i]);
  const bad = [...pubs];
  bad[0] = (BigInt(bad[0] as string) + 1n).toString();
  const tamperedSignalRejected = (await snarkjs.groth16.verify(vkey as never, bad, proof)) !== true;
  let rejectedByOtherKey: boolean | null = null;
  let sameCircuitAsOther: KeyChecksResult["sameCircuitAsOther"] = null;
  if (c.otherVkey) {
    const other = readJson<VkeyLike>(c.otherVkey);
    rejectedByOtherKey = (await snarkjs.groth16.verify(other as never, publicSignals, proof)) !== true;
    sameCircuitAsOther = compareVkeys(vkey, other);
  }
  const td = await deriveBeaconTrapdoor(vkey, c.beacon.value, c.beacon.iterExp);
  const forged = await forgeProof(vkey, td.d, publicSignals);
  const forgedProofVerifies = (await snarkjs.groth16.verify(vkey as never, publicSignals, forged)) === true;
  let control: KeyChecksResult["trapdoor"]["control"] = null;
  if (c.control) {
    const cv = readJson<Parameters<typeof deriveBeaconTrapdoor>[0]>(c.control.vkey);
    const ctd = await deriveBeaconTrapdoor(cv, c.control.beacon, c.control.iterExp);
    const n = cv.IC.length - 1;
    const sig = Array.from({ length: n }, (_, i) => String(i + 1));
    const cf = await forgeProof(cv, ctd.d, sig);
    control = { key: c.control.vkey.split(path.sep).join("/"), beaconDerivedDeltaMatchesKey: ctd.matchesDelta, forgedProofVerifies: (await snarkjs.groth16.verify(cv as never, sig, cf)) === true };
  }
  const body = {
    vkeyMatchesZkeyExport,
    proof: { verifies, publicSignalsMatch, publicSignals: pubs, rejectedByOtherKey, tamperedSignalRejected },
    sameCircuitAsOther,
    trapdoor: { beaconDerivedDeltaMatchesKey: td.matchesDelta, gammaIsGenerator: td.gammaIsGenerator, forgedProofVerifies, control },
  };
  return { schema: "pqid/v4-ceremony-key-checks/v1", ...body, pass: keyChecksPass(body) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const i = process.argv.indexOf("--config");
  if (i < 0 || !process.argv[i + 1]) {
    console.error("usage: node --import tsx harness/v4/ceremony/key_checks.ts --config <json>");
    process.exit(2);
  }
  // Exit explicitly: snarkjs keeps worker threads alive after the last proof.
  runKeyChecks(readJson<Config>(process.argv[i + 1] as string)).then(
    (r) => {
      console.log(JSON.stringify(r));
      process.exit(r.pass ? 0 : 1);
    },
    (e: unknown) => {
      console.error(e instanceof Error ? e.message : String(e));
      process.exit(1);
    }
  );
}
