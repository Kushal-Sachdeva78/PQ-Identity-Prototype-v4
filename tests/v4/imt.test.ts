import { describe, it, expect, beforeAll } from "vitest";
import { randomBytes } from "node:crypto";
import type { Poseidon } from "circomlibjs";
import { IndexedMerkleTree, type ImtNonMembershipWitness } from "@pqid/v4/imt";
import { IMT_MAX, REV_DEPTH } from "@pqid/v4/constants";
import { getPoseidon, poseidonBig, imtLeafHash, revKeyFromCredId } from "@pqid/v4/encoding";

/**
 * v4 revocation IMT (packages/v4/src/imt.ts): the JS tree, at small depths and at REV_DEPTH,
 * with an exhaustive check at depth 3. The circuit twin and the B2 check of circomlib's SMT
 * depth limit are in imt_circuit_twin.test.ts. Keys are generated in memory; nothing secret
 * is written.
 */

let poseidon: Poseidon;
beforeAll(async () => {
  poseidon = await getPoseidon();
});

// ------------------------------------------------------------ independent references

/** Dense reference root: hash all 2^depth slots (small depths only). */
function denseRoot(p: Poseidon, leaves: Array<[bigint, bigint]>, depth: number): bigint {
  let level: bigint[] = [];
  for (let i = 0; i < 2 ** depth; i++) {
    const leaf = leaves[i];
    level.push(leaf ? imtLeafHash(p, leaf[0], leaf[1]) : 0n);
  }
  for (let l = 0; l < depth; l++) {
    const up: bigint[] = [];
    for (let j = 0; j < level.length; j += 2) up.push(poseidonBig(p, [level[j] as bigint, level[j + 1] as bigint]));
    level = up;
  }
  return level[0] as bigint;
}

/** Root rebuilt from a leaf opening, ignoring any bracketing (Merkle part only). */
function openingRoot(p: Poseidon, w: ImtNonMembershipWitness): bigint {
  let cur = imtLeafHash(p, BigInt(w.lowValue), BigInt(w.lowNext));
  let i = BigInt(w.lowIndex);
  for (const s of w.lowPath) {
    cur = (i & 1n) === 0n ? poseidonBig(p, [cur, BigInt(s)]) : poseidonBig(p, [BigInt(s), cur]);
    i >>= 1n;
  }
  return cur;
}

function leavesOf(t: IndexedMerkleTree): Array<[bigint, bigint]> {
  const out: Array<[bigint, bigint]> = [];
  for (let i = 0; i < t.size; i++) {
    const l = t.leafAt(i);
    out.push([l.value, l.nextValue]);
  }
  return out;
}

/** Walk the linked list from the sentinel: must visit every key in increasing order. */
function assertLinkedList(t: IndexedMerkleTree): void {
  const byValue = new Map<bigint, bigint>();
  for (const [v, n] of leavesOf(t)) byValue.set(v, n);
  const visited: bigint[] = [];
  let cur = 0n;
  for (;;) {
    const next = byValue.get(cur);
    expect(next).toBeDefined();
    expect((next as bigint) > cur).toBe(true);
    if (next === IMT_MAX) break;
    visited.push(next as bigint);
    cur = next as bigint;
  }
  expect(visited.length).toBe(t.keyCount);
  expect(visited).toEqual(t.keysInLeafOrder().slice().sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));
}

function randomKey(): bigint {
  return revKeyFromCredId(randomBytes(32));
}

function randomKeys(n: number): bigint[] {
  const s = new Set<bigint>();
  while (s.size < n) s.add(randomKey());
  return [...s];
}

// ------------------------------------------------------------------------- JS tree

describe("v4 IMT: basic behaviour", () => {
  it("empty tree holds only the sentinel (0, IMT_MAX)", async () => {
    const t = await IndexedMerkleTree.create(4);
    expect(t.size).toBe(1);
    expect(t.keyCount).toBe(0);
    expect(t.capacity).toBe(15);
    expect(t.leafAt(0)).toEqual({ value: 0n, nextValue: IMT_MAX });
    expect(t.root()).toBe(denseRoot(poseidon, [[0n, IMT_MAX]], 4));
    expect(() => t.leafAt(1)).toThrow(/no occupied leaf/);
    const d = await IndexedMerkleTree.create();
    expect(d.depth).toBe(REV_DEPTH);
  });

  it("depth 4: insert keeps the sorted linked list and matches a dense reference root", async () => {
    const t = await IndexedMerkleTree.create(4);
    const r1 = t.insert(50n);
    expect(r1).toEqual({ lowIndex: 0, newIndex: 1, root: t.root() });
    const r2 = t.insert(10n);
    expect(r2.lowIndex).toBe(0);
    expect(r2.newIndex).toBe(2);
    const r3 = t.insert(30n); // between 10 and 50: low leaf is 10 at index 2
    expect(r3.lowIndex).toBe(2);
    const r4 = t.insert(70n); // above 50: low leaf is 50 at index 1
    expect(r4.lowIndex).toBe(1);
    expect(leavesOf(t)).toEqual([
      [0n, 10n],
      [50n, 70n],
      [10n, 30n],
      [30n, 50n],
      [70n, IMT_MAX],
    ]);
    expect(t.root()).toBe(denseRoot(poseidon, leavesOf(t), 4));
    assertLinkedList(t);
    for (const k of [10n, 30n, 50n, 70n]) expect(t.has(k)).toBe(true);
    for (const k of [0n, 1n, 11n, 71n, IMT_MAX]) expect(t.has(k)).toBe(false);
  });

  it("depth 4: non-membership witnesses verify; revoked keys have no witness", async () => {
    const t = await IndexedMerkleTree.create(4);
    for (const k of [50n, 10n, 30n, 70n]) t.insert(k);
    for (const [k, lowValue] of [
      [1n, 0n],
      [9n, 0n],
      [11n, 10n],
      [49n, 30n],
      [51n, 50n],
      [IMT_MAX - 1n, 70n],
    ] as const) {
      const w = t.nonMembershipWitness(k);
      expect(w.lowValue).toBe(lowValue.toString());
      expect(w.lowPath).toHaveLength(4);
      expect(w.root).toBe(t.root().toString());
      expect(IndexedMerkleTree.verifyNonMembership(poseidon, k, w, 4)).toBe(true);
      expect(IndexedMerkleTree.verifyNonMembership(poseidon, k, w, 5)).toBe(false);
    }
    for (const k of [10n, 30n, 50n, 70n]) {
      expect(() => t.nonMembershipWitness(k)).toThrow(/in the tree/);
    }
    for (const k of [0n, IMT_MAX, IMT_MAX + 1n, -1n]) {
      expect(() => t.nonMembershipWitness(k)).toThrow(/out of range/);
    }
  });

  it("rejects duplicates, out-of-range keys and inserts past capacity 2^d - 1", async () => {
    const t = await IndexedMerkleTree.create(2);
    t.insert(5n);
    expect(() => t.insert(5n)).toThrow(/duplicate/);
    expect(() => t.insert(0n)).toThrow(/out of range/);
    expect(() => t.insert(IMT_MAX)).toThrow(/out of range/);
    expect(() => t.insert(-3n)).toThrow(/out of range/);
    expect(() => t.insert(5 as unknown as bigint)).toThrow(/bigint/);
    t.insert(6n);
    t.insert(1n);
    expect(t.size).toBe(4);
    expect(() => t.insert(7n)).toThrow(/full/);
    const root = t.root();
    expect(t.size).toBe(4); // failed inserts change nothing
    expect(t.root()).toBe(root);
    await expect(IndexedMerkleTree.create(0)).rejects.toThrow(/depth/);
    await expect(IndexedMerkleTree.create(49)).rejects.toThrow(/depth/);
  });

  it("predecessor search across the 65,536 buckets agrees with a linear scan", async () => {
    // Keys clustered in a few buckets and spread over others, so the search walks back
    // across empty buckets and whole empty groups.
    const keys = new Set<bigint>();
    const top = (b: number): bigint => BigInt(b) << 235n;
    for (const b of [0, 1, 255, 256, 257, 4000, 65535]) {
      for (let j = 0; j < 5; j++) keys.add(top(b) + BigInt(1 + Math.floor(Math.random() * 1e9)));
    }
    for (let j = 0; j < 300; j++) keys.add(randomKey());
    const t = await IndexedMerkleTree.bulkBuild([...keys], 12);
    const vals = [0n, ...keys];
    const probes: bigint[] = [];
    for (const b of [0, 1, 2, 254, 255, 256, 258, 3999, 4000, 4001, 30000, 65534, 65535]) {
      probes.push(top(b) + 1n, top(b) + 7n + BigInt(Math.floor(Math.random() * 1e12)));
      if (b > 0) probes.push(top(b) - 1n);
    }
    for (let j = 0; j < 500; j++) probes.push(randomKey());
    for (const k of probes) {
      if (keys.has(k) || k <= 0n || k >= IMT_MAX) continue;
      let best = 0n;
      for (const v of vals) if (v < k && v > best) best = v;
      expect(t.leafAt(t.lowLeafIndex(k)).value).toBe(best);
    }
  });
});

describe("v4 IMT at REV_DEPTH", () => {
  it("random revKeys: insert, non-membership, verification and tampering", async () => {
    const t = await IndexedMerkleTree.create(REV_DEPTH);
    const revoked = randomKeys(40);
    for (const k of revoked) {
      const before = t.size;
      const r = t.insert(k);
      expect(r.newIndex).toBe(before);
      expect(t.leafAt(r.lowIndex).nextValue).toBe(k);
      expect(r.root).toBe(t.root());
    }
    assertLinkedList(t);
    for (const k of revoked) {
      expect(t.has(k)).toBe(true);
      expect(() => t.nonMembershipWitness(k)).toThrow(/in the tree/);
    }
    for (let i = 0; i < 20; i++) {
      const k = randomKey();
      const w = t.nonMembershipWitness(k);
      expect(w.lowPath).toHaveLength(REV_DEPTH);
      expect(IndexedMerkleTree.verifyNonMembership(poseidon, k, w, REV_DEPTH)).toBe(true);
      expect(openingRoot(poseidon, w)).toBe(t.root());
    }
    // tampering: every field
    const k = randomKey();
    const w = t.nonMembershipWitness(k);
    const bad = (m: Partial<ImtNonMembershipWitness>): boolean =>
      IndexedMerkleTree.verifyNonMembership(poseidon, k, { ...w, ...m }, REV_DEPTH);
    const idx = Number(w.lowIndex);
    expect(bad({ lowIndex: String(idx === 0 ? 1 : idx - 1) })).toBe(false);
    expect(bad({ lowIndex: (2n ** BigInt(REV_DEPTH) + BigInt(idx)).toString() })).toBe(false);
    expect(bad({ lowIndex: "0" + w.lowIndex })).toBe(false);
    expect(bad({ lowValue: k.toString() })).toBe(false);
    expect(bad({ lowNext: k.toString() })).toBe(false);
    expect(bad({ lowNext: (BigInt(w.lowNext) + 1n).toString() })).toBe(false); // still brackets, hash differs
    expect(bad({ lowValue: (BigInt(w.lowValue) + 1n).toString() })).toBe(false);
    expect(bad({ root: (BigInt(w.root) + 1n).toString() })).toBe(false);
    expect(bad({ lowPath: w.lowPath.slice(1) })).toBe(false);
    expect(bad({ lowPath: [...w.lowPath.slice(0, 5), "1", ...w.lowPath.slice(6)] })).toBe(false);
    expect(IndexedMerkleTree.verifyNonMembership(poseidon, k, w, REV_DEPTH)).toBe(true);
    expect(IndexedMerkleTree.verifyNonMembership(poseidon, 0n, w, REV_DEPTH)).toBe(false);
    expect(IndexedMerkleTree.verifyNonMembership(poseidon, IMT_MAX, w, REV_DEPTH)).toBe(false);
  });

  it("bulkBuild equals incremental insertion in the same order (and stays equal on later inserts)", async () => {
    for (const [depth, n] of [
      [REV_DEPTH, 120],
      [10, 700],
    ] as const) {
      const keys = randomKeys(n);
      const inc = await IndexedMerkleTree.create(depth);
      for (const k of keys) inc.insert(k);
      const bulk = await IndexedMerkleTree.bulkBuild(keys, depth);
      expect(bulk.root()).toBe(inc.root());
      expect(bulk.size).toBe(inc.size);
      expect(leavesOf(bulk)).toEqual(leavesOf(inc));
      const sortedKeys = keys.slice().sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      const incSorted = await IndexedMerkleTree.create(depth);
      for (const k of sortedKeys) incSorted.insert(k);
      expect((await IndexedMerkleTree.bulkBuild(sortedKeys, depth)).root()).toBe(incSorted.root());
      for (const k of randomKeys(10)) {
        expect(bulk.insert(k)).toEqual(inc.insert(k));
      }
      const probe = randomKey();
      expect(bulk.nonMembershipWitness(probe)).toEqual(inc.nonMembershipWitness(probe));
    }
  });

  it("bulkBuild rejects duplicates, out-of-range keys and too many keys", async () => {
    await expect(IndexedMerkleTree.bulkBuild([5n, 7n, 5n], 4)).rejects.toThrow(/duplicate/);
    await expect(IndexedMerkleTree.bulkBuild([5n, 0n], 4)).rejects.toThrow(/out of range/);
    await expect(IndexedMerkleTree.bulkBuild([IMT_MAX], 4)).rejects.toThrow(/out of range/);
    await expect(IndexedMerkleTree.bulkBuild([1n, 2n, 3n, 4n], 2)).rejects.toThrow(/capacity/);
    expect((await IndexedMerkleTree.bulkBuild([1n, 2n, 3n], 2)).size).toBe(4);
  });

  it("snapshot is independent of later inserts", async () => {
    const t = await IndexedMerkleTree.create(REV_DEPTH);
    for (const k of randomKeys(15)) t.insert(k);
    const snap = t.snapshot();
    const oldRoot = t.root();
    const probe = randomKey();
    const wOld = snap.nonMembershipWitness(probe);
    t.insert(probe);
    for (const k of randomKeys(5)) t.insert(k);
    expect(snap.root()).toBe(oldRoot);
    expect(snap.has(probe)).toBe(false);
    expect(t.has(probe)).toBe(true);
    expect(snap.nonMembershipWitness(probe)).toEqual(wOld);
    expect(IndexedMerkleTree.verifyNonMembership(poseidon, probe, wOld, REV_DEPTH)).toBe(true);
    snap.insert(randomKey());
    expect(t.size).toBe(1 + 15 + 6);
    expect(snap.size).toBe(1 + 15 + 1);
  });

  it("serialize/deserialize round-trips and rejects tampered bytes", async () => {
    const t = await IndexedMerkleTree.create(REV_DEPTH);
    for (const k of randomKeys(25)) t.insert(k);
    const bytes = t.serialize();
    expect(bytes.length).toBe(48 + 32 * 25);
    const back = await IndexedMerkleTree.deserialize(bytes);
    expect(back.root()).toBe(t.root());
    expect(back.depth).toBe(REV_DEPTH);
    expect(leavesOf(back)).toEqual(leavesOf(t));
    const empty = await IndexedMerkleTree.deserialize((await IndexedMerkleTree.create(7)).serialize());
    expect(empty.size).toBe(1);

    const flipKey = bytes.slice();
    flipKey[48 + 32 * 3 + 31] = (flipKey[48 + 32 * 3 + 31] as number) ^ 1;
    await expect(IndexedMerkleTree.deserialize(flipKey)).rejects.toThrow(/root mismatch|duplicate/);
    const flipRoot = bytes.slice();
    flipRoot[20] = (flipRoot[20] as number) ^ 0x80;
    await expect(IndexedMerkleTree.deserialize(flipRoot)).rejects.toThrow(/root mismatch/);
    const badMagic = bytes.slice();
    badMagic[0] = 0;
    await expect(IndexedMerkleTree.deserialize(badMagic)).rejects.toThrow(/magic/);
    await expect(IndexedMerkleTree.deserialize(bytes.slice(0, bytes.length - 1))).rejects.toThrow(/length/);
    const badDepth = bytes.slice();
    badDepth[8] = 0;
    await expect(IndexedMerkleTree.deserialize(badDepth)).rejects.toThrow(/depth/);
  });
});

describe("v4 IMT: exhaustive check at depth 3", () => {
  it("for every key set up to capacity and every key, a witness exists iff the key is absent, and only the bracketing low leaf verifies", async () => {
    const DEPTH = 3;
    const universe = [3n, 5n, 8n, 11n, 12n, 20n, 21n, 30n];
    const probes: bigint[] = [0n, IMT_MAX, IMT_MAX - 1n];
    for (let k = 1n; k <= 32n; k++) probes.push(k);
    let sets = 0;
    let accepted = 0;
    let rejected = 0;
    for (let mask = 0; mask < 2 ** universe.length; mask++) {
      const set = universe.filter((_, i) => (mask >> i) & 1);
      if (set.length > 2 ** DEPTH - 1) continue; // above capacity: checked below
      sets++;
      // deterministic insertion order that varies with the set
      const order = set.slice();
      const rot = mask % Math.max(1, order.length);
      order.push(...order.splice(0, rot));
      if (mask % 2 === 1) order.reverse();
      const t = await IndexedMerkleTree.create(DEPTH);
      for (const k of order) t.insert(k);
      if (set.length === 2 ** DEPTH - 1) {
        const missing = universe.find((k) => !set.includes(k)) as bigint;
        expect(() => t.insert(missing)).toThrow(/full/);
      }
      expect(t.root()).toBe(denseRoot(poseidon, leavesOf(t), DEPTH));
      assertLinkedList(t);
      const openings = Array.from({ length: t.size }, (_, i) => t.openLeaf(i));
      for (const o of openings) expect(openingRoot(poseidon, o)).toBe(t.root()); // every opening is a valid Merkle path
      for (const k of probes) {
        const inRange = k > 0n && k < IMT_MAX;
        const shouldExist = inRange && !set.includes(k);
        if (shouldExist) {
          const w = t.nonMembershipWitness(k);
          expect(IndexedMerkleTree.verifyNonMembership(poseidon, k, w, DEPTH)).toBe(true);
        } else {
          expect(() => t.nonMembershipWitness(k)).toThrow();
        }
        let bracketing = 0;
        for (let i = 0; i < openings.length; i++) {
          const leaf = t.leafAt(i);
          const brackets = inRange && leaf.value < k && k < leaf.nextValue;
          const ok = IndexedMerkleTree.verifyNonMembership(poseidon, k, openings[i] as ImtNonMembershipWitness, DEPTH);
          expect(ok).toBe(brackets);
          if (ok) {
            bracketing++;
            accepted++;
            expect(String(i)).toBe(t.nonMembershipWitness(k).lowIndex);
          } else {
            rejected++;
          }
        }
        expect(bracketing).toBe(shouldExist ? 1 : 0);
      }
    }
    expect(sets).toBe(255); // all subsets of 8 keys except the full set (capacity 7)
    expect(accepted).toBeGreaterThan(0);
    expect(rejected).toBeGreaterThan(accepted);
  });
});
