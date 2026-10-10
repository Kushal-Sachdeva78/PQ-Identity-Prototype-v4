import type { Poseidon } from "circomlibjs";
import { getPoseidon, poseidonBig, ISSUANCE_TREE_DEPTH } from "@pqid/common/encoding";

/**
 * Circuit v3 issuance tree: an append-only binary Poseidon Merkle tree of
 * issued-credential leaves (see credentialLeaf in @pqid/common/encoding).
 *
 *   node(level+1, i) = Poseidon(node(level, 2i), node(level, 2i+1))
 *   empty leaf       = 0;  empty subtree at level l = zeros[l]
 *
 * This is the JS twin of the MerkleRoot template in
 * circuits/credential_auth_v3.circom: bit l of the leaf index says whether the
 * running hash is the right (1) or left (0) child at level l. The issuer signs
 * each root it publishes (ML-DSA-44); the circuit proves that the prover's
 * credential leaf is under such a root. Only non-empty nodes are stored.
 */
export interface IssuancePath {
  /** Position of the leaf (decimal string; the circuit range-checks < 2^depth). */
  leafIndex: string;
  /** Sibling hashes from the leaf level upwards (decimal strings), `depth` entries. */
  pathElements: string[];
  /** The root this path opens to. */
  root: string;
}

export class IssuanceTree {
  private readonly layers: Array<Map<number, bigint>>;
  private nextIndex = 0;

  private constructor(
    readonly depth: number,
    private readonly poseidon: Poseidon,
    private readonly zeros: bigint[]
  ) {
    this.layers = Array.from({ length: depth + 1 }, () => new Map<number, bigint>());
  }

  static async create(depth: number = ISSUANCE_TREE_DEPTH): Promise<IssuanceTree> {
    if (!Number.isInteger(depth) || depth < 1 || depth > 32) {
      throw new Error("issuance tree depth must be an integer in [1, 32]");
    }
    const poseidon = await getPoseidon();
    const zeros: bigint[] = [0n];
    for (let l = 0; l < depth; l++) {
      const z = zeros[l] as bigint;
      zeros.push(poseidonBig(poseidon, [z, z]));
    }
    return new IssuanceTree(depth, poseidon, zeros);
  }

  get size(): number {
    return this.nextIndex;
  }

  private node(level: number, index: number): bigint {
    return (this.layers[level] as Map<number, bigint>).get(index) ?? (this.zeros[level] as bigint);
  }

  root(): bigint {
    return this.node(this.depth, 0);
  }

  leaf(index: number): bigint {
    if (!Number.isInteger(index) || index < 0 || index >= this.nextIndex) {
      throw new Error(`no leaf at index ${index}`);
    }
    return this.node(0, index);
  }

  /** Append a leaf; returns its index. */
  insert(leaf: bigint): number {
    if (leaf === 0n) throw new Error("the zero leaf is reserved for empty slots");
    const capacity = 2 ** this.depth;
    if (this.nextIndex >= capacity) throw new Error("issuance tree is full");
    const index = this.nextIndex++;
    (this.layers[0] as Map<number, bigint>).set(index, leaf);
    let i = index;
    for (let l = 0; l < this.depth; l++) {
      // arithmetic, not bitwise: JS bit operators truncate to int32 (> 2^31 leaves)
      const leftIndex = i - (i % 2);
      const left = this.node(l, leftIndex);
      const right = this.node(l, leftIndex + 1);
      i = Math.floor(i / 2);
      (this.layers[l + 1] as Map<number, bigint>).set(i, poseidonBig(this.poseidon, [left, right]));
    }
    return index;
  }

  /**
   * Node (level, index) of the tree as it was when it held only its first
   * `size` leaves. The tree is append-only, so a subtree lying wholly below
   * `size` is unchanged since then and one lying wholly at or above it was
   * empty; only the one subtree per level straddling `size` is recomputed.
   */
  private nodeAt(level: number, index: number, size: number): bigint {
    const width = 2 ** level;
    const first = index * width;
    if (first + width <= size) return this.node(level, index);
    if (first >= size) return this.zeros[level] as bigint;
    return poseidonBig(this.poseidon, [
      this.nodeAt(level - 1, 2 * index, size),
      this.nodeAt(level - 1, 2 * index + 1, size),
    ]);
  }

  /** Root of the tree when it held its first `size` leaves. */
  rootAt(size: number): bigint {
    if (!Number.isInteger(size) || size < 0 || size > this.nextIndex) {
      throw new Error(`size ${size} out of range [0, ${this.nextIndex}]`);
    }
    return this.nodeAt(this.depth, 0, size);
  }

  /** Authentication path of leaf `index` in the tree of its first `size` leaves. */
  pathAt(index: number, size: number): IssuancePath {
    this.leaf(index); // bounds check
    if (!Number.isInteger(size) || size <= index || size > this.nextIndex) {
      throw new Error(`leaf ${index} is not among the first ${size} leaves`);
    }
    const pathElements: string[] = [];
    let i = index;
    for (let l = 0; l < this.depth; l++) {
      pathElements.push(this.nodeAt(l, i % 2 === 0 ? i + 1 : i - 1, size).toString());
      i = Math.floor(i / 2);
    }
    return { leafIndex: index.toString(), pathElements, root: this.rootAt(size).toString() };
  }

  /** Authentication path of an existing leaf against the current root. */
  path(index: number): IssuancePath {
    return this.pathAt(index, this.nextIndex);
  }

  /**
   * Recompute a root from a leaf and a path (the circuit's MerkleRoot, in JS).
   * Rejects what the circuit rejects: a path of the wrong length or an index
   * outside [0, 2^depth).
   */
  static rootFromPath(poseidon: Poseidon, leaf: bigint, path: IssuancePath, depth: number): bigint {
    if (path.pathElements.length !== depth) {
      throw new Error(`path has ${path.pathElements.length} siblings, expected ${depth}`);
    }
    if (!/^(0|[1-9][0-9]*)$/.test(path.leafIndex)) throw new Error("leafIndex must be a canonical decimal");
    let i = BigInt(path.leafIndex);
    if (i >= 2n ** BigInt(depth)) throw new Error(`leafIndex out of range for depth ${depth}`);
    let cur = leaf;
    for (const sib of path.pathElements) {
      const s = BigInt(sib);
      cur = (i & 1n) === 0n ? poseidonBig(poseidon, [cur, s]) : poseidonBig(poseidon, [s, cur]);
      i >>= 1n;
    }
    return cur;
  }
}
