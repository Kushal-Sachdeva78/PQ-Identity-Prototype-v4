import { newMemEmptyTrie, type SMT } from "circomlibjs";
import { getPoseidon, smtKeyFromCredId } from "@pqid/common/encoding";

/**
 * Revoked-set accumulator: a sparse Merkle tree over Poseidon, depth-32 as
 * verified in-circuit by circomlib's SMTVerifier(32). The JS tree
 * (circomlibjs) and the circuit gadget (circomlib) are the canonical matched
 * pair — same hash (Poseidon), same arity (binary), same leaf encoding
 * (Hash1 = Poseidon(key, value, 1), Hash2 = Poseidon(L, R), empty root = 0).
 *
 * Keys:   smtKey = Poseidon(credIDHi, credIDLo)   (credID field packing, Gap 11)
 * Values: 1 (presence marker for a revoked credID)
 */
export const SMT_DEPTH = 32;
export const REVOKED_LEAF_VALUE = 1n;

export interface NonMembershipProof {
  /** Sibling path, padded with zeros to SMT_DEPTH entries (decimal strings). */
  siblings: string[];
  /** Key of the conflicting leaf along the path (0 when the slot is empty). */
  oldKey: string;
  /** Value of the conflicting leaf (0 when the slot is empty). */
  oldValue: string;
  /** 1 iff the addressed slot is empty (no conflicting leaf). */
  isOld0: "0" | "1";
  /** The SMT key the proof speaks about (= Poseidon(credIDHi, credIDLo)). */
  key: string;
  /** Tree root this opening verifies against. */
  root: string;
}

export class RevocationTree {
  /** credIDs inserted so far, in order (lets an issuer snapshot the published state). */
  private readonly revokedIds: Buffer[] = [];

  private constructor(
    private readonly tree: SMT,
    private readonly poseidon: Awaited<ReturnType<typeof getPoseidon>>
  ) {}

  static async create(): Promise<RevocationTree> {
    const poseidon = await getPoseidon();
    const tree = await newMemEmptyTrie();
    return new RevocationTree(tree, poseidon);
  }

  /** Current root as a field element (0 for the empty tree). */
  root(): bigint {
    return this.tree.F.toObject(this.tree.root);
  }

  smtKey(credId: Uint8Array): bigint {
    return smtKeyFromCredId(this.poseidon, credId);
  }

  /** Revoke a credential: insert its SMT key. Returns the new root. */
  async insert(credId: Uint8Array): Promise<bigint> {
    const key = this.smtKey(credId);
    const found = await this.tree.find(key);
    if (found.found) throw new Error("credID already revoked");
    await this.tree.insert(key, REVOKED_LEAF_VALUE);
    this.revokedIds.push(Buffer.from(credId));
    return this.root();
  }

  /**
   * An independent copy of the current revoked set. A v3 issuer serves
   * non-membership openings from the snapshot whose root is anchored on chain
   * while newer revocations wait for the next epoch.
   */
  async snapshot(): Promise<RevocationTree> {
    const copy = await RevocationTree.create();
    for (const id of this.revokedIds) await copy.insert(id);
    return copy;
  }

  /** True iff credId is currently in the revoked set. */
  async isRevoked(credId: Uint8Array): Promise<boolean> {
    const res = await this.tree.find(this.smtKey(credId));
    return res.found;
  }

  /**
   * Non-membership opening for a (non-revoked) credID, in the exact shape the
   * circuit's SMTVerifier(32) consumes. Throws if the credID is revoked —
   * this is the precise mechanism behind the negative test: once revoked, no
   * valid opening against the current root exists.
   */
  async getNonMembershipProof(credId: Uint8Array): Promise<NonMembershipProof> {
    const key = this.smtKey(credId);
    const res = await this.tree.find(key);
    if (res.found) {
      throw new Error(
        "credID is in the revoked set — no non-membership proof exists"
      );
    }
    if (res.siblings.length > SMT_DEPTH) {
      throw new Error(`SMT path exceeds depth ${SMT_DEPTH}`);
    }
    const F = this.tree.F;
    const siblings: string[] = res.siblings.map((s) => F.toObject(s).toString());
    while (siblings.length < SMT_DEPTH) siblings.push("0");
    return {
      siblings,
      oldKey: res.isOld0 ? "0" : F.toObject(res.notFoundKey as Uint8Array).toString(),
      oldValue: res.isOld0 ? "0" : F.toObject(res.notFoundValue as Uint8Array).toString(),
      isOld0: res.isOld0 ? "1" : "0",
      key: key.toString(),
      root: this.root().toString(),
    };
  }
}
