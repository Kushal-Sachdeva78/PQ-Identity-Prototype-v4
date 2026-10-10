import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { IssuanceTree } from "@pqid/issuer";
import { bulkIssuanceTree, issuanceTreeLayers } from "../../harness/v4/bulk_issuance_tree.ts";
import { distribution } from "../../harness/v4/scale_lib.ts";

// E4 (docs/v4/E4_SCALE.md): the bulk loader used for the 10^6-leaf issuance tree must give
// the same tree state as inserting the leaves one by one with IssuanceTree.insert.

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function leaves(n: number, tag: string): bigint[] {
  const out: bigint[] = [];
  for (let i = 0; i < n; i++) {
    const v = BigInt("0x" + createHash("sha256").update(`${tag}:${i}`).digest("hex")) % P;
    out.push(v === 0n ? 1n : v);
  }
  return out;
}

async function incremental(ls: bigint[], depth: number): Promise<IssuanceTree> {
  const t = await IssuanceTree.create(depth);
  for (const l of ls) t.insert(l);
  return t;
}

function sameLayers(a: IssuanceTree, b: IssuanceTree): void {
  const la = issuanceTreeLayers(a);
  const lb = issuanceTreeLayers(b);
  expect(la.length).toBe(lb.length);
  for (let l = 0; l < la.length; l++) {
    const ma = la[l] as ReadonlyMap<number, bigint>;
    const mb = lb[l] as ReadonlyMap<number, bigint>;
    expect(mb.size).toBe(ma.size);
    for (const [k, v] of ma) expect(mb.get(k)).toBe(v);
  }
}

describe("E4 bulk issuance tree loader", () => {
  for (const n of [0, 1, 2, 3, 4, 5, 7, 8, 9, 31, 33, 100, 257]) {
    it(`depth 32, n = ${n}: same root, layers, paths and later inserts as incremental insertion`, async () => {
      const ls = leaves(n + 6, `n${n}`);
      const base = ls.slice(0, n);
      const inc = await incremental(base, 32);
      const bulk = await bulkIssuanceTree(base, 32);
      expect(bulk.size).toBe(n);
      expect(bulk.root()).toBe(inc.root());
      sameLayers(inc, bulk);
      for (const i of [0, Math.floor(n / 2), n - 1]) {
        if (i < 0 || i >= n) continue;
        expect(bulk.pathAt(i, n)).toEqual(inc.pathAt(i, n));
        expect(bulk.leaf(i)).toBe(inc.leaf(i));
      }
      if (n > 1) expect(bulk.rootAt(n - 1)).toBe(inc.rootAt(n - 1));
      for (const extra of ls.slice(n)) {
        expect(bulk.insert(extra)).toBe(inc.insert(extra));
        expect(bulk.root()).toBe(inc.root());
      }
      sameLayers(inc, bulk);
    });
  }

  it("small depth: a full tree matches and the next insert is refused by both", async () => {
    const ls = leaves(16, "full");
    const inc = await incremental(ls, 4);
    const bulk = await bulkIssuanceTree(ls, 4);
    expect(bulk.root()).toBe(inc.root());
    sameLayers(inc, bulk);
    expect(() => inc.insert(5n)).toThrow(/full/);
    expect(() => bulk.insert(5n)).toThrow(/full/);
    await expect(bulkIssuanceTree(leaves(17, "over"), 4)).rejects.toThrow(/full/);
  });

  it("refuses the zero leaf like IssuanceTree.insert", async () => {
    await expect(bulkIssuanceTree([1n, 0n], 8)).rejects.toThrow(/zero leaf/);
  });
});

describe("E4 distribution statistics", () => {
  it("median, quartiles (linear interpolation) and IQR", () => {
    const d = distribution([4, 1, 3, 2, 5]);
    expect(d.n).toBe(5);
    expect(d.median).toBe(3);
    expect(d.q1).toBe(2);
    expect(d.q3).toBe(4);
    expect(d.iqr).toBe(2);
    const e = distribution([1, 2, 3, 4]);
    expect(e.median).toBe(2.5);
    expect(e.q1).toBe(1.75);
    expect(e.q3).toBe(3.25);
  });
});
