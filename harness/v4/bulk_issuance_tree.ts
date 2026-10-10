import type { Poseidon } from "circomlibjs";
import { poseidonBig } from "@pqid/common/encoding";
import { IssuanceTree } from "@pqid/issuer";

/**
 * E4 (docs/v4/E4_SCALE.md): bulk loader for the issuance tree of packages/issuer (reused
 * read-only, as v3 and v4 use it). Building a depth-32 tree of 10^6 leaves by
 * IssuanceTree.insert costs 32 Poseidon hashes per leaf (3.2 * 10^7 in all); hashing level
 * by level costs about one hash per node that holds data (about 2 * 10^6).
 *
 * The result is an ordinary IssuanceTree whose internal state is exactly the state that
 * inserting `leaves` one by one produces:
 *   - layers[0] maps i -> leaves[i] for i < n;
 *   - layers[l+1] maps j -> Poseidon(node(l, 2j), node(l, 2j+1)) for every j < ceil(size_l / 2),
 *     where a missing right child is zeros[l] (the insert path sets exactly these ancestors);
 *   - nextIndex = n.
 * Later inserts, rootAt, pathAt and leaf therefore run the package's own code on it.
 * tests/v4/scale_bulk_tree.test.ts checks roots, every layer, paths and later inserts
 * against incremental insertion for small n.
 *
 * The package keeps these fields TypeScript-private (not #private); the loader writes them
 * at run time and checks their shape first, so a change to IssuanceTree fails loudly.
 */

interface IssuanceTreeInternals {
  layers: Array<Map<number, bigint>>;
  nextIndex: number;
  zeros: bigint[];
  poseidon: Poseidon;
  depth: number;
}

function internalsOf(tree: IssuanceTree): IssuanceTreeInternals {
  const t = tree as unknown as IssuanceTreeInternals;
  const ok =
    Array.isArray(t.layers) &&
    t.layers.length === t.depth + 1 &&
    t.layers.every((m) => m instanceof Map && m.size === 0) &&
    t.nextIndex === 0 &&
    Array.isArray(t.zeros) &&
    t.zeros.length === t.depth + 1 &&
    typeof t.poseidon === "function";
  if (!ok) throw new Error("IssuanceTree internals are not the expected shape: update harness/v4/bulk_issuance_tree.ts");
  return t;
}

/** An IssuanceTree holding `leaves` at indices 0..n-1, equal to n incremental inserts. */
export async function bulkIssuanceTree(leaves: readonly bigint[], depth = 32): Promise<IssuanceTree> {
  const tree = await IssuanceTree.create(depth);
  const t = internalsOf(tree);
  if (leaves.length > 2 ** depth) throw new Error("issuance tree is full");
  for (const leaf of leaves) {
    if (typeof leaf !== "bigint") throw new Error("leaves must be bigints");
    if (leaf === 0n) throw new Error("the zero leaf is reserved for empty slots");
  }
  let below: bigint[] = leaves.slice();
  const layer0 = t.layers[0] as Map<number, bigint>;
  for (let i = 0; i < below.length; i++) layer0.set(i, below[i] as bigint);
  for (let l = 0; l < depth; l++) {
    const zl = t.zeros[l] as bigint;
    const width = Math.ceil(below.length / 2);
    const up: bigint[] = new Array<bigint>(width);
    const map = t.layers[l + 1] as Map<number, bigint>;
    for (let j = 0; j < width; j++) {
      const left = below[2 * j] as bigint;
      const right = 2 * j + 1 < below.length ? (below[2 * j + 1] as bigint) : zl;
      const h = poseidonBig(t.poseidon, [left, right]);
      up[j] = h;
      map.set(j, h);
    }
    below = up;
  }
  t.nextIndex = leaves.length;
  return tree;
}

/** Test helper: the tree's layer maps (read-only view of the private state). */
export function issuanceTreeLayers(tree: IssuanceTree): ReadonlyArray<ReadonlyMap<number, bigint>> {
  return (tree as unknown as IssuanceTreeInternals).layers;
}
