import { getPoseidon, poseidonBig } from "@pqid/common/encoding";
import { IssuanceTree } from "@pqid/issuer";
import { revKeyFromCredId } from "@pqid/v4/encoding";
import type { HeldData } from "./suite_lib.ts";

/**
 * Mutation runs only. A replacement mutant (G02, G03, G05) turns a computed value into a
 * free private input. These fillers give it a value: the honest wallet supplies what the
 * removed computation would have produced; the attacker supplies the value that best
 * serves the attack (the genuine leaf at the path position, the credential's holder
 * commitment, a key that the offered low leaf brackets).
 */
export type Filler = (input: Record<string, string | string[]>, held: HeldData) => void;
export type HonestFiller = (input: Record<string, string | string[]>, info: { credId: Buffer; holderCommit: string }) => void;

export async function makeFillers(group: string | undefined): Promise<{ attacker: Filler | null; honest: HonestFiller | undefined }> {
  const p = await getPoseidon();
  const leafOf = (i: Record<string, string | string[]>, holderCommit: string) =>
    poseidonBig(p, [
      1004n,
      BigInt(i["issuerKeyHash"] as string),
      BigInt(i["credIDHi"] as string),
      BigInt(i["credIDLo"] as string),
      BigInt(holderCommit),
      BigInt(i["birthDate"] as string),
      BigInt(i["expiryDate"] as string),
      BigInt(i["credType"] as string),
    ]).toString();
  switch (group) {
    case "G02_holder_commit":
      return {
        attacker: (i, h) => void (i["mutHolderCommit"] = h.vc.credential.holderCommit),
        honest: (i, info) => void (i["mutHolderCommit"] = info.holderCommit),
      };
    case "G03_leaf":
      return {
        attacker: (i, h) => {
          // Any value the attacker can name that opens the offered path to the public issRoot:
          // the genuine leaf at that index of the issuer's tree, or its own tree's leaf.
          const idx = Number(i["issLeafIndex"]);
          const path = { leafIndex: String(i["issLeafIndex"]), pathElements: i["issPathElements"] as string[], root: String(i["issRoot"]) };
          const opens = (leaf: bigint) => IssuanceTree.rootFromPath(p, leaf, path, path.pathElements.length).toString() === String(i["issRoot"]);
          const candidates: bigint[] = [];
          if (idx < h.issuer.tree.size) candidates.push(h.issuer.tree.leaf(idx));
          candidates.push(BigInt(leafOf(i, h.vc.credential.holderCommit)));
          const hit = candidates.find(opens);
          i["mutLeaf"] = (hit ?? candidates[0]!).toString();
        },
        honest: (i, info) => void (i["mutLeaf"] = leafOf(i, info.holderCommit)),
      };
    case "G05_revkey":
      return {
        attacker: (i) => {
          const lo = BigInt(i["revLowValue"] as string);
          const hi = BigInt(i["revLowNext"] as string);
          i["mutRevKey"] = (hi - lo > 1n ? lo + 1n : lo).toString();
        },
        honest: (i, info) => void (i["mutRevKey"] = revKeyFromCredId(info.credId).toString()),
      };
    default:
      return { attacker: null, honest: undefined };
  }
}
