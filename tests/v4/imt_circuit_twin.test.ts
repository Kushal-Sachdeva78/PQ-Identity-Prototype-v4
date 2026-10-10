import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { newMemEmptyTrie, type Poseidon } from "circomlibjs";
import { IndexedMerkleTree, type ImtNonMembershipWitness } from "@pqid/v4/imt";
import { getPoseidon, revKeyFromCredId, credIdLimbs } from "@pqid/v4/encoding";
import { REPO_ROOT } from "@pqid/common/paths";
import { patchWitnessWire, r1csSatisfied } from "../../harness/v3/wtns_tamper.ts";

/**
 * Circuit twin of the v4 revocation IMT (circuits/v4/research/imt_nonmembership_d4.circom,
 * the same ImtNonMembership template as circuits/v4/lib_v4.circom) and the B2 check of
 * circomlib SMTVerifier's depth limit. Split from imt.test.ts so the JS tree tests carry no
 * reference to the v3 tamper helpers (public export, DECISIONS D-030).
 */

let poseidon: Poseidon;
beforeAll(async () => {
  poseidon = await getPoseidon();
});

function randomKey(): bigint {
  return revKeyFromCredId(randomBytes(32));
}

function randomKeys(n: number): bigint[] {
  const s = new Set<bigint>();
  while (s.size < n) s.add(randomKey());
  return [...s];
}

// ------------------------------------------------------------------ circuit twins

function circomBinary(): string {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  if (process.platform === "win32" && fs.existsSync(win)) return win;
  return "circom";
}

interface Compiled {
  dir: string;
  r1cs: string;
  wasm: string;
  sym: string;
}

function compileResearch(name: string, outRoot: string): Compiled {
  const dir = path.join(outRoot, name);
  fs.mkdirSync(dir, { recursive: true });
  const src = path.join(REPO_ROOT, "circuits", "v4", "research", `${name}.circom`);
  execFileSync(circomBinary(), [src, "--O2", "--r1cs", "--wasm", "--sym", "-o", dir], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  return {
    dir,
    r1cs: path.join(dir, `${name}.r1cs`),
    wasm: path.join(dir, `${name}_js`, `${name}.wasm`),
    sym: path.join(dir, `${name}.sym`),
  };
}

/** Witness index of a signal from a .sym file (labelIdx,varIdx,componentIdx,name). */
function wireOf(symFile: string, name: string): number {
  for (const line of fs.readFileSync(symFile, "utf8").split("\n")) {
    const parts = line.trim().split(",");
    if (parts[3] === name) {
      const idx = Number(parts[1]);
      if (idx < 0) throw new Error(`${name} was optimised away`);
      return idx;
    }
  }
  throw new Error(`signal ${name} not found in ${symFile}`);
}

type Snarkjs = typeof import("snarkjs");

describe("v4 IMT circuit twin (circuits/v4/research/imt_nonmembership_d4.circom) and SMTVerifier depth limit", () => {
  let tmp: string;
  let imt: Compiled;
  let smt: Compiled;
  let snarkjs: Snarkjs;
  let n = 0;

  beforeAll(async () => {
    snarkjs = await import("snarkjs");
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-v4-imt-"));
    imt = compileResearch("imt_nonmembership_d4", tmp);
    smt = compileResearch("smt_nonmembership_bare_d4", tmp);
  });
  afterAll(() => {
    if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
  });

  /** Returns the .wtns path if the witness generator accepts, or null if it rejects. */
  async function witness(c: Compiled, input: Record<string, unknown>): Promise<string | null> {
    const out = path.join(tmp, `w${n++}.wtns`);
    try {
      await snarkjs.wtns.calculate(input, c.wasm, out);
      return out;
    } catch (e) {
      expect(String(e)).toMatch(/Assert Failed/);
      return null;
    }
  }

  /** Limbs whose revKey is `key`: hi = key >> 123, lo = (key mod 2^123) << 5 | junk (junk ignored). */
  function limbsFor(key: bigint, junk = 0n): { credIDHi: string; credIDLo: string } {
    return {
      credIDHi: (key >> 123n).toString(),
      credIDLo: (((key & ((1n << 123n) - 1n)) << 5n) | junk).toString(),
    };
  }

  function imtInput(key: bigint, w: ImtNonMembershipWitness, junk = 0n): Record<string, unknown> {
    return {
      ...limbsFor(key, junk),
      root: w.root,
      lowIndex: w.lowIndex,
      lowValue: w.lowValue,
      lowNext: w.lowNext,
      lowPath: w.lowPath,
    };
  }

  it("honest witnesses satisfy the R1CS (revKey from real credID limbs, and at the last slot of a full tree)", async () => {
    const t = await IndexedMerkleTree.create(4);
    for (const k of randomKeys(9)) t.insert(k);
    for (let i = 0; i < 4; i++) {
      const credId = randomBytes(32);
      const { hi, lo } = credIdLimbs(credId);
      const key = revKeyFromCredId(credId);
      const w = t.nonMembershipWitness(key);
      const input = { credIDHi: hi.toString(), credIDLo: lo.toString(), root: w.root, lowIndex: w.lowIndex, lowValue: w.lowValue, lowNext: w.lowNext, lowPath: w.lowPath };
      const f = await witness(imt, input);
      expect(f).not.toBeNull();
      expect(await r1csSatisfied(imt.r1cs, f as string)).toBe(true);
    }
    // fill to capacity (15 keys) and use the leaf at index 15 as the low leaf
    for (const k of randomKeys(6)) t.insert(k);
    expect(t.size).toBe(16);
    expect(() => t.insert(randomKey())).toThrow(/full/);
    const last = t.leafAt(15);
    const key = last.value + 1n;
    const w = t.nonMembershipWitness(key);
    expect(w.lowIndex).toBe("15");
    const f = await witness(imt, imtInput(key, w, 31n));
    expect(f).not.toBeNull();
    expect(await r1csSatisfied(imt.r1cs, f as string)).toBe(true);
  });

  it("the witness generator accepts exactly the bracketing low leaf, and matches the JS twin", async () => {
    const t = await IndexedMerkleTree.create(4);
    const revoked = randomKeys(7);
    for (const k of revoked) t.insert(k);
    const openings = Array.from({ length: t.size }, (_, i) => t.openLeaf(i));
    const nonMembers = randomKeys(3);
    let accepted = 0;
    let rejected = 0;
    for (const key of [...nonMembers, ...revoked.slice(0, 3)]) {
      for (let i = 0; i < openings.length; i++) {
        const o = openings[i] as ImtNonMembershipWitness;
        const js = IndexedMerkleTree.verifyNonMembership(poseidon, key, o, 4);
        const f = await witness(imt, imtInput(key, o));
        expect(f !== null).toBe(js);
        if (f) {
          accepted++;
          expect(revoked.includes(key)).toBe(false);
          expect(await r1csSatisfied(imt.r1cs, f)).toBe(true);
        } else {
          rejected++;
        }
      }
    }
    expect(accepted).toBe(nonMembers.length); // one bracketing leaf per non-member, none for revoked keys
    expect(rejected).toBe(6 * openings.length - nonMembers.length);
  });

  it("limbs outside 128 bits are rejected", async () => {
    const t = await IndexedMerkleTree.create(4);
    const key = randomKey();
    const w = t.nonMembershipWitness(key);
    const input = imtInput(key, w);
    expect(await witness(imt, { ...input, credIDLo: (1n << 128n).toString() })).toBeNull();
    expect(await witness(imt, { ...input, credIDHi: (1n << 128n).toString() })).toBeNull();
  });

  it("R1CS rejects a tampered honest witness (lowNext set to the key, or a different root)", async () => {
    const t = await IndexedMerkleTree.create(4);
    for (const k of randomKeys(5)) t.insert(k);
    const key = randomKey();
    const w = t.nonMembershipWitness(key);
    const f = await witness(imt, imtInput(key, w));
    expect(f).not.toBeNull();
    expect(await r1csSatisfied(imt.r1cs, f as string)).toBe(true);
    const lowNextWire = wireOf(imt.sym, "main.lowNext");
    const rootWire = wireOf(imt.sym, "main.root");
    expect(rootWire).toBe(1); // the only public signal
    const g = path.join(tmp, `tamper${n++}.wtns`);
    fs.copyFileSync(f as string, g);
    patchWitnessWire(g, lowNextWire, key);
    expect(await r1csSatisfied(imt.r1cs, g)).toBe(false);
    const h = path.join(tmp, `tamper${n++}.wtns`);
    fs.copyFileSync(f as string, h);
    patchWitnessWire(h, rootWire, BigInt(w.root) + 1n);
    expect(await r1csSatisfied(imt.r1cs, h)).toBe(false);
  });

  it("B2: circomlib SMTVerifier(4) proves non-membership only on paths of at most 3 levels (effective path bits = nLevels - 1)", async () => {
    // circomlibjs SMT: key bit i (least significant first) picks the branch at level i;
    // two keys sharing their low j bits sit at depth j + 1.
    const smtInput = async (keys: bigint[], probe: bigint): Promise<{ input: Record<string, unknown>; pathLen: number }> => {
      const tree = await newMemEmptyTrie();
      for (const k of keys) await tree.insert(k, 1n);
      const res = await tree.find(probe);
      expect(res.found).toBe(false);
      const F = tree.F;
      const siblings = res.siblings.map((s) => F.toObject(s).toString());
      const pathLen = siblings.length;
      while (siblings.length < 4) siblings.push("0");
      return {
        pathLen,
        input: {
          key: probe.toString(),
          root: F.toObject(tree.root).toString(),
          siblings,
          oldKey: res.isOld0 ? "0" : F.toObject(res.notFoundKey as Uint8Array).toString(),
          oldValue: res.isOld0 ? "0" : F.toObject(res.notFoundValue as Uint8Array).toString(),
          isOld0: res.isOld0 ? "1" : "0",
        },
      };
    };
    // keys 1 (..0001) and 5 (..0101) share 2 low bits: leaves at depth 3; probe 17 (..10001) lands on key 1
    const ok = await smtInput([1n, 5n], 17n);
    expect(ok.pathLen).toBe(3);
    const f = await witness(smt, ok.input);
    expect(f).not.toBeNull();
    expect(await r1csSatisfied(smt.r1cs, f as string)).toBe(true);
    // an empty slot (isOld0 = 1) also works
    const empty = await smtInput([1n, 5n], 2n);
    expect(await witness(smt, empty.input)).not.toBeNull();
    // keys 1 (..0001) and 9 (..1001) share 3 low bits: leaves at depth 4, the last sibling is non-zero
    const bad = await smtInput([1n, 9n], 17n);
    expect(bad.pathLen).toBe(4);
    expect(await witness(smt, bad.input)).toBeNull();
    const bad2 = await smtInput([1n, 9n], 25n); // lands on key 9 at depth 4
    expect(bad2.pathLen).toBe(4);
    expect(await witness(smt, bad2.input)).toBeNull();
  });
});
