import type { Poseidon } from "circomlibjs";
import { BN254_P, IMT_MAX, REV_DEPTH, REV_KEY_BITS } from "./constants.ts";
import { getPoseidon, poseidonBig, imtLeafHash } from "./encoding.ts";

/**
 * v4 revocation tree: an indexed Merkle tree (IMT) over Poseidon
 * (docs/v4/V4_DESIGN.md section 1.4). JS twin of ImtNonMembership in
 * circuits/v4/lib_v4.circom.
 *
 *   occupied leaf i : Poseidon(IMT_LEAF_V4, value_i, nextValue_i)   (imtLeafHash)
 *   empty slot      : 0;  empty subtree at level l = zeros[l], zeros[l+1] = Poseidon(zeros[l], zeros[l])
 *   node(l+1, j)    = Poseidon(node(l, 2j), node(l, 2j+1))
 *
 * Index 0 holds the sentinel (0, IMT_MAX). The occupied leaves form a sorted linked
 * list 0 -> k1 -> k2 -> ... -> IMT_MAX by nextValue. Insert k: the low leaf L with
 * L.value < k < L.nextValue gets nextValue := k and (k, oldNext) is appended at the
 * next free index, so a depth-d tree holds 2^d - 1 keys with no insertion failure.
 * Non-membership of k: open the low leaf that strictly brackets k.
 *
 * Storage: leaves are appended contiguously from index 0, so the non-empty nodes of
 * every level are exactly a prefix of that level. Each level is stored as an array
 * of that prefix (only non-empty nodes are stored; everything past the prefix is the
 * zero subtree of that level).
 */

export interface ImtLeaf {
  value: bigint;
  nextValue: bigint;
}

export interface ImtInsertResult {
  /** Index of the low leaf whose nextValue changed. */
  lowIndex: number;
  /** Index where (key, oldNext) was appended. */
  newIndex: number;
  /** Root after the insertion. */
  root: bigint;
}

/**
 * Non-membership witness in the shape the circuit consumes (decimal strings).
 * lowPath: `depth` sibling hashes, leaf level first. Bit i of lowIndex selects the
 * order at level i exactly as MerkleRootV4: 0 -> (cur, sibling), 1 -> (sibling, cur).
 */
export interface ImtNonMembershipWitness {
  lowIndex: string;
  lowValue: string;
  lowNext: string;
  lowPath: string[];
  root: string;
}

export const IMT_MIN_DEPTH = 1;
export const IMT_MAX_DEPTH = 48;

/** Serialization magic (8 ASCII bytes) of the published-tree format. */
export const IMT_SERIAL_MAGIC = "PQIDIMT1";
const HEADER_BYTES = 48;
const KEY_BYTES = 32;

/** LessThan(252) in ImtBracket equals integer comparison only for inputs < 2^252. */
const LESS_THAN_BOUND = 1n << 252n;

const BUCKET_BITS = 16;
const BUCKET_COUNT = 1 << BUCKET_BITS; // 65,536
const BUCKET_SHIFT = BigInt(REV_KEY_BITS - BUCKET_BITS); // top 16 of 251 bits
const GROUP_BITS = 8;
const GROUP_COUNT = BUCKET_COUNT >> GROUP_BITS; // 256 groups of 256 buckets

function assertDepth(depth: number): void {
  if (!Number.isInteger(depth) || depth < IMT_MIN_DEPTH || depth > IMT_MAX_DEPTH) {
    throw new Error(`IMT depth must be an integer in [${IMT_MIN_DEPTH}, ${IMT_MAX_DEPTH}], got ${String(depth)}`);
  }
}

/** Keys (revKeys) must satisfy 0 < key < IMT_MAX = 2^251. */
function assertKey(key: unknown): asserts key is bigint {
  if (typeof key !== "bigint") throw new Error("IMT key must be a bigint");
  if (key <= 0n || key >= IMT_MAX) throw new Error("IMT key out of range: need 0 < key < 2^251");
}

function cmpBig(a: bigint, b: bigint): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** First position in sorted `arr` whose element is >= x. */
function lowerBound(arr: readonly bigint[], x: bigint): number {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if ((arr[mid] as bigint) < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** Canonical decimal string -> field element, or null. */
function parseField(s: unknown): bigint | null {
  if (typeof s !== "string" || !/^(0|[1-9][0-9]*)$/.test(s)) return null;
  const v = BigInt(s);
  return v < BN254_P ? v : null;
}

/**
 * Predecessor index over the stored values (sentinel 0 included): 65,536 buckets keyed
 * by the top 16 bits of the 251-bit key, each a small sorted array, plus a count of
 * non-empty buckets per group of 256 so the walk back to the previous non-empty
 * bucket skips empty groups.
 */
class SortedValues {
  private constructor(
    private readonly buckets: Array<bigint[] | undefined>,
    private readonly groupNonEmpty: Uint16Array
  ) {}

  static empty(): SortedValues {
    return new SortedValues(new Array<bigint[] | undefined>(BUCKET_COUNT).fill(undefined), new Uint16Array(GROUP_COUNT));
  }

  /** Build from values already sorted ascending. */
  static fromSorted(sorted: readonly bigint[]): SortedValues {
    const s = SortedValues.empty();
    for (const v of sorted) {
      const b = Number(v >> BUCKET_SHIFT);
      let arr = s.buckets[b];
      if (!arr) {
        arr = [];
        s.buckets[b] = arr;
        const g = b >> GROUP_BITS;
        s.groupNonEmpty[g] = (s.groupNonEmpty[g] as number) + 1;
      }
      arr.push(v);
    }
    return s;
  }

  clone(): SortedValues {
    return new SortedValues(
      this.buckets.map((a) => (a ? a.slice() : undefined)),
      this.groupNonEmpty.slice()
    );
  }

  add(v: bigint): void {
    const b = Number(v >> BUCKET_SHIFT);
    let arr = this.buckets[b];
    if (!arr) {
      arr = [];
      this.buckets[b] = arr;
      const g = b >> GROUP_BITS;
      this.groupNonEmpty[g] = (this.groupNonEmpty[g] as number) + 1;
    }
    arr.splice(lowerBound(arr, v), 0, v);
  }

  /** Largest stored value < k (exists for every k > 0 because 0 is stored). */
  predecessor(k: bigint): bigint {
    let b = Number(k >> BUCKET_SHIFT);
    const own = this.buckets[b];
    if (own) {
      const pos = lowerBound(own, k);
      if (pos > 0) return own[pos - 1] as bigint;
    }
    b -= 1;
    while (b >= 0) {
      const g = b >> GROUP_BITS;
      if (this.groupNonEmpty[g] === 0) {
        b = (g << GROUP_BITS) - 1; // skip the whole empty group
        continue;
      }
      const arr = this.buckets[b];
      if (arr && arr.length > 0) return arr[arr.length - 1] as bigint;
      b -= 1;
    }
    throw new Error("internal: no predecessor (sentinel missing)");
  }
}

export class IndexedMerkleTree {
  private constructor(
    readonly depth: number,
    private readonly poseidon: Poseidon,
    private readonly zeros: readonly bigint[],
    private readonly values: bigint[],
    private readonly nexts: bigint[],
    private readonly indexOf: Map<bigint, number>,
    private readonly sorted: SortedValues,
    /** layers[l] = the non-empty prefix of level l (level 0 = leaf hashes). */
    private readonly layers: bigint[][]
  ) {}

  private static async base(depth: number): Promise<{ poseidon: Poseidon; zeros: bigint[] }> {
    assertDepth(depth);
    const poseidon = await getPoseidon();
    const zeros: bigint[] = [0n];
    for (let l = 0; l < depth; l++) {
      const z = zeros[l] as bigint;
      zeros.push(poseidonBig(poseidon, [z, z]));
    }
    return { poseidon, zeros };
  }

  /** Empty tree: only the sentinel (0, IMT_MAX) at index 0. */
  static async create(depth: number = REV_DEPTH): Promise<IndexedMerkleTree> {
    return IndexedMerkleTree.bulkBuild([], depth);
  }

  /**
   * Build the tree that inserting `keys` one by one, in the given order, produces:
   * leaf i+1 holds keys[i], and every nextValue is that key's successor in the final
   * sorted set (IMT_MAX for the largest). Pass sorted keys for a sorted leaf layout.
   * Hashes level by level (about 2 Poseidon calls per key), so it suits 10^6 keys.
   */
  static async bulkBuild(keys: readonly bigint[], depth: number = REV_DEPTH): Promise<IndexedMerkleTree> {
    const { poseidon, zeros } = await IndexedMerkleTree.base(depth);
    const capacity = 2 ** depth - 1;
    if (keys.length > capacity) {
      throw new Error(`${keys.length} keys exceed the capacity 2^${depth} - 1 = ${capacity}`);
    }
    for (const k of keys) assertKey(k);
    const sortedKeys = keys.slice().sort(cmpBig);
    for (let i = 1; i < sortedKeys.length; i++) {
      if (sortedKeys[i] === sortedKeys[i - 1]) throw new Error(`duplicate key ${String(sortedKeys[i])}`);
    }
    const successor = new Map<bigint, bigint>();
    for (let i = 0; i < sortedKeys.length; i++) {
      successor.set(sortedKeys[i] as bigint, sortedKeys[i + 1] ?? IMT_MAX);
    }
    const values: bigint[] = [0n, ...keys];
    const nexts: bigint[] = [sortedKeys[0] ?? IMT_MAX];
    for (const k of keys) nexts.push(successor.get(k) as bigint);
    const indexOf = new Map<bigint, number>();
    for (let i = 0; i < values.length; i++) indexOf.set(values[i] as bigint, i);
    const sorted = SortedValues.fromSorted([0n, ...sortedKeys]);

    const layers: bigint[][] = [];
    const leafLayer: bigint[] = new Array<bigint>(values.length);
    for (let i = 0; i < values.length; i++) {
      leafLayer[i] = imtLeafHash(poseidon, values[i] as bigint, nexts[i] as bigint);
    }
    layers.push(leafLayer);
    for (let l = 0; l < depth; l++) {
      const below = layers[l] as bigint[];
      const zl = zeros[l] as bigint;
      const width = Math.ceil(below.length / 2);
      const up: bigint[] = new Array<bigint>(width);
      for (let j = 0; j < width; j++) {
        const left = below[2 * j] as bigint;
        const right = 2 * j + 1 < below.length ? (below[2 * j + 1] as bigint) : zl;
        up[j] = poseidonBig(poseidon, [left, right]);
      }
      layers.push(up);
    }
    return new IndexedMerkleTree(depth, poseidon, zeros, values, nexts, indexOf, sorted, layers);
  }

  /** Occupied leaves, including the sentinel at index 0. */
  get size(): number {
    return this.values.length;
  }

  /** Number of keys (revocations) held: size - 1. */
  get keyCount(): number {
    return this.values.length - 1;
  }

  /** Maximum number of keys: 2^depth - 1. */
  get capacity(): number {
    return 2 ** this.depth - 1;
  }

  private node(level: number, index: number): bigint {
    const layer = this.layers[level] as bigint[];
    return index < layer.length ? (layer[index] as bigint) : (this.zeros[level] as bigint);
  }

  root(): bigint {
    return this.node(this.depth, 0);
  }

  /** True iff `key` is a valid revKey held by the tree (the sentinel 0 is not a key). */
  has(key: bigint): boolean {
    return typeof key === "bigint" && key > 0n && key < IMT_MAX && this.indexOf.has(key);
  }

  leafAt(index: number): ImtLeaf {
    if (!Number.isInteger(index) || index < 0 || index >= this.values.length) {
      throw new Error(`no occupied leaf at index ${String(index)}`);
    }
    return { value: this.values[index] as bigint, nextValue: this.nexts[index] as bigint };
  }

  /** Keys in leaf order (leaf 1 upwards; the sentinel is not included). */
  keysInLeafOrder(): bigint[] {
    return this.values.slice(1);
  }

  /** Recompute the ancestors of the given leaf indices, sharing common ancestors. */
  private rehash(leafIndices: number[]): void {
    let cur = Array.from(new Set(leafIndices)).sort((a, b) => a - b);
    for (let l = 0; l < this.depth; l++) {
      const parents: number[] = [];
      for (const i of cur) {
        const p = Math.floor(i / 2);
        if (parents[parents.length - 1] !== p) parents.push(p);
      }
      const up = this.layers[l + 1] as bigint[];
      for (const p of parents) {
        if (p > up.length) throw new Error("internal: non-contiguous IMT level");
        up[p] = poseidonBig(this.poseidon, [this.node(l, 2 * p), this.node(l, 2 * p + 1)]);
      }
      cur = parents;
    }
  }

  /**
   * Insert (revoke) `key`. Throws on a duplicate, on a key outside 0 < key < 2^251,
   * or when the tree already holds 2^depth - 1 keys.
   */
  insert(key: bigint): ImtInsertResult {
    assertKey(key);
    if (this.indexOf.has(key)) throw new Error(`duplicate key ${key.toString()}: already in the tree`);
    if (this.values.length >= 2 ** this.depth) {
      throw new Error(`revocation tree is full (capacity 2^${this.depth} - 1 keys)`);
    }
    const low = this.sorted.predecessor(key);
    const lowIndex = this.indexOf.get(low);
    if (lowIndex === undefined) throw new Error("internal: predecessor not indexed");
    const oldNext = this.nexts[lowIndex] as bigint;
    if (!(low < key && key < oldNext)) throw new Error("internal: low leaf does not bracket the key");

    this.nexts[lowIndex] = key;
    const newIndex = this.values.length;
    this.values.push(key);
    this.nexts.push(oldNext);
    this.indexOf.set(key, newIndex);
    this.sorted.add(key);

    const leaves = this.layers[0] as bigint[];
    leaves[lowIndex] = imtLeafHash(this.poseidon, low, key);
    leaves[newIndex] = imtLeafHash(this.poseidon, key, oldNext);
    this.rehash([lowIndex, newIndex]);
    return { lowIndex, newIndex, root: this.root() };
  }

  /** Index of the occupied leaf that strictly brackets a non-member key. */
  lowLeafIndex(key: bigint): number {
    assertKey(key);
    if (this.indexOf.has(key)) throw new Error("key is in the tree: no low leaf brackets it");
    const idx = this.indexOf.get(this.sorted.predecessor(key));
    if (idx === undefined) throw new Error("internal: predecessor not indexed");
    return idx;
  }

  private pathOf(index: number): string[] {
    const out: string[] = [];
    let i = index;
    for (let l = 0; l < this.depth; l++) {
      out.push(this.node(l, i % 2 === 0 ? i + 1 : i - 1).toString());
      i = Math.floor(i / 2);
    }
    return out;
  }

  /**
   * Opening of any occupied leaf in witness shape, whatever key it is used for. The
   * honest wallet uses nonMembershipWitness; tests and attack routes use this to open
   * leaves that do not bracket a key.
   */
  openLeaf(index: number): ImtNonMembershipWitness {
    const leaf = this.leafAt(index);
    return {
      lowIndex: index.toString(),
      lowValue: leaf.value.toString(),
      lowNext: leaf.nextValue.toString(),
      lowPath: this.pathOf(index),
      root: this.root().toString(),
    };
  }

  /** Non-membership witness for `key`; throws if the key is present (revoked) or out of range. */
  nonMembershipWitness(key: bigint): ImtNonMembershipWitness {
    return this.openLeaf(this.lowLeafIndex(key));
  }

  /** Independent copy: later inserts into either tree do not affect the other. */
  snapshot(): IndexedMerkleTree {
    return new IndexedMerkleTree(
      this.depth,
      this.poseidon,
      this.zeros,
      this.values.slice(),
      this.nexts.slice(),
      new Map(this.indexOf),
      this.sorted.clone(),
      this.layers.map((layer) => layer.slice())
    );
  }

  /**
   * Published-tree format (all integers big-endian):
   *   bytes 0..7   "PQIDIMT1"
   *   byte  8      depth
   *   bytes 9..11  zero
   *   bytes 12..15 n = number of keys (u32)
   *   bytes 16..47 root (32 bytes)
   *   then n keys of 32 bytes each, in leaf order (leaf 1 .. leaf n).
   * nextValues are not stored: they follow from the key set. Size = 48 + 32 n bytes.
   */
  serialize(): Uint8Array {
    const n = this.values.length - 1;
    const out = new Uint8Array(HEADER_BYTES + KEY_BYTES * n);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < IMT_SERIAL_MAGIC.length; i++) out[i] = IMT_SERIAL_MAGIC.charCodeAt(i);
    out[8] = this.depth;
    dv.setUint32(12, n, false);
    writeBig32(out, 16, this.root());
    for (let i = 1; i <= n; i++) writeBig32(out, HEADER_BYTES + KEY_BYTES * (i - 1), this.values[i] as bigint);
    return out;
  }

  /** Inverse of serialize(): rebuilds every hash and throws unless the root matches. */
  static async deserialize(bytes: Uint8Array): Promise<IndexedMerkleTree> {
    if (!(bytes instanceof Uint8Array) || bytes.length < HEADER_BYTES) throw new Error("IMT bytes too short");
    for (let i = 0; i < IMT_SERIAL_MAGIC.length; i++) {
      if (bytes[i] !== IMT_SERIAL_MAGIC.charCodeAt(i)) throw new Error("not a serialized IMT (bad magic)");
    }
    if (bytes[9] !== 0 || bytes[10] !== 0 || bytes[11] !== 0) throw new Error("IMT header reserved bytes must be zero");
    const depth = bytes[8] as number;
    assertDepth(depth);
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const n = dv.getUint32(12, false);
    if (bytes.length !== HEADER_BYTES + KEY_BYTES * n) throw new Error("IMT byte length does not match its key count");
    const root = readBig32(bytes, 16);
    const keys: bigint[] = new Array<bigint>(n);
    for (let i = 0; i < n; i++) keys[i] = readBig32(bytes, HEADER_BYTES + KEY_BYTES * i);
    const tree = await IndexedMerkleTree.bulkBuild(keys, depth);
    if (tree.root() !== root) throw new Error("IMT root mismatch: keys do not rebuild the stated root");
    return tree;
  }

  /**
   * JS twin of ImtNonMembership(depth) (circuits/v4/lib_v4.circom): rebuilds the root
   * from Poseidon(IMT_LEAF_V4, lowValue, lowNext) along lowPath (bit i of lowIndex
   * selects the order at level i, lowIndex < 2^depth) and requires it to equal
   * witness.root, and requires lowValue < key < lowNext strictly. The key must be a
   * revKey (0 < key < 2^251); lowValue and lowNext must be < 2^252, the range where
   * the circuit's LessThan(252) is integer comparison. Returns false, never throws.
   * The caller still compares witness.root with the anchored revRoot.
   */
  static verifyNonMembership(
    poseidon: Poseidon,
    key: bigint,
    witness: ImtNonMembershipWitness,
    depth: number
  ): boolean {
    try {
      if (!Number.isInteger(depth) || depth < IMT_MIN_DEPTH || depth > IMT_MAX_DEPTH) return false;
      if (typeof key !== "bigint" || key <= 0n || key >= IMT_MAX) return false;
      if (typeof witness !== "object" || witness === null) return false;
      if (!Array.isArray(witness.lowPath) || witness.lowPath.length !== depth) return false;
      const lowIndex = parseField(witness.lowIndex);
      const lowValue = parseField(witness.lowValue);
      const lowNext = parseField(witness.lowNext);
      const root = parseField(witness.root);
      if (lowIndex === null || lowValue === null || lowNext === null || root === null) return false;
      if (lowIndex >= 1n << BigInt(depth)) return false;
      if (lowValue >= LESS_THAN_BOUND || lowNext >= LESS_THAN_BOUND) return false;
      if (!(lowValue < key && key < lowNext)) return false;
      let cur = imtLeafHash(poseidon, lowValue, lowNext);
      let bits = lowIndex;
      for (const s of witness.lowPath) {
        const sib = parseField(s);
        if (sib === null) return false;
        cur = (bits & 1n) === 0n ? poseidonBig(poseidon, [cur, sib]) : poseidonBig(poseidon, [sib, cur]);
        bits >>= 1n;
      }
      return cur === root;
    } catch {
      return false;
    }
  }
}

function writeBig32(out: Uint8Array, offset: number, v: bigint): void {
  if (v < 0n || v >= 1n << 256n) throw new Error("value does not fit in 32 bytes");
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[offset + i] = Number(x & 0xffn);
    x >>= 8n;
  }
}

function readBig32(bytes: Uint8Array, offset: number): bigint {
  let v = 0n;
  for (let i = 0; i < 32; i++) v = (v << 8n) | BigInt(bytes[offset + i] as number);
  return v;
}
