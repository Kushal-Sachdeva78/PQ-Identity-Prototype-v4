import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Rng, crc32, mix32, targetSeed, caseSeed, caseRng } from "../../harness/v4/robustness/rng.ts";
import { encodeTyped, decodeTyped, typedJsonCapped } from "../../harness/v4/robustness/typed_json.ts";
import {
  daysFromCivil,
  civilFromDays,
  refIsValidYmd,
  refAge,
  refReached,
  refAddDays,
  refUtcDateOf,
  refCanonical,
  refStrictUtf8,
  refIsCanonicalDecBelow,
  refIsFieldDec,
  refDepth,
  refRequestValid,
  refReplyValid,
  refParseStatement,
  P_DEC,
} from "../../harness/v4/robustness/oracles.ts";
import { mutateBytes, mutateJsonText, mutateValue } from "../../harness/v4/robustness/mutators.ts";
import * as G from "../../harness/v4/robustness/valid_gen.ts";
import { decodeMappings, summariseCoverage } from "../../harness/v4/robustness/coverage.ts";
import { flattenForgeJson } from "../../harness/v4/robustness/forge_fuzz.ts";
import { assertCommitted, budgetDeviation, checkCommitted, COMMITTED_PATHS } from "../../harness/v4/robustness/common.ts";
import { SEEDS } from "../../harness/v4/lib/seeds.ts";

/**
 * Unit tests of the robustness row's in-repo seeded generator and its references
 * (DECISIONS D-034; docs/v4/ROBUSTNESS.md). The references are checked against independent
 * facts (known CRC values, Date.UTC, hand-made cases), not against the package code they judge.
 */

describe("rng: seeded generator", () => {
  it("crc32 matches the IEEE check value and Python's zlib.crc32", () => {
    expect(crc32("123456789")).toBe(0xcbf43926);
    expect(crc32("")).toBe(0);
    expect(crc32("T-dates")).toBe(crc32(new TextEncoder().encode("T-dates")));
  });

  it("is deterministic per (master, target, case) and independent of earlier cases", () => {
    const a = caseRng(SEEDS.robustness.fuzz, "T-x", 41);
    const b = caseRng(SEEDS.robustness.fuzz, "T-x", 41);
    const xs = Array.from({ length: 20 }, () => a.u32());
    expect(Array.from({ length: 20 }, () => b.u32())).toEqual(xs);
    expect(caseRng(SEEDS.robustness.fuzz, "T-x", 42).u32()).not.toBe(xs[0]);
    expect(caseRng(SEEDS.robustness.fuzz, "T-y", 41).u32()).not.toBe(xs[0]);
    expect(targetSeed(SEEDS.robustness.fuzz, "T-x")).toBe((SEEDS.robustness.fuzz ^ crc32("T-x")) >>> 0);
    expect(caseSeed(targetSeed(7, "a"), 3)).toBe(caseSeed(targetSeed(7, "a"), 3));
    expect(() => caseSeed(1, -1)).toThrow();
    expect(mix32(1, 2)).not.toBe(mix32(2, 1));
  });

  it("int, bigBelow and pick stay in range; shuffle is a permutation; fork does not advance the stream", () => {
    const r = new Rng(20261022);
    const counts = new Array(6).fill(0) as number[];
    for (let i = 0; i < 6000; i++) {
      const x = r.int(0, 5);
      expect(x).toBeGreaterThanOrEqual(0);
      expect(x).toBeLessThanOrEqual(5);
      counts[x] = (counts[x] as number) + 1;
    }
    for (const c of counts) expect(c).toBeGreaterThan(800); // about 1000 each
    const n = 2n ** 254n + 12345n;
    for (let i = 0; i < 200; i++) {
      const v = r.bigBelow(n);
      expect(v >= 0n && v < n).toBe(true);
    }
    expect(r.int(-3, -3)).toBe(-3);
    expect(() => r.int(2, 1)).toThrow();
    const arr = Array.from({ length: 50 }, (_, i) => i);
    expect([...r.shuffle(arr.slice())].sort((a, b) => a - b)).toEqual(arr);
    const s1 = new Rng(5);
    const s2 = new Rng(5);
    s1.fork("x").u32();
    expect(s1.u32()).toBe(s2.u32());
    expect(new Rng(5).fork("x").u32()).toBe(new Rng(5).fork("x").u32());
    expect(new Rng(5).bytes(13).length).toBe(13);
  });
});

describe("typed JSON: failure inputs decode to the tested value", () => {
  it("round-trips bigint, bytes, -0, NaN, Infinity, undefined, holes, __proto__ and null-prototype objects", () => {
    const np = Object.create(null) as Record<string, unknown>;
    np["a"] = 1n;
    const tricky: Record<string, unknown> = {};
    Object.defineProperty(tricky, "__proto__", { value: { polluted: true }, enumerable: true, writable: true, configurable: true });
    // eslint-disable-next-line no-sparse-arrays
    const holey = [1, , 3];
    const v = { b: 10n ** 80n, bytes: Buffer.from([0, 255, 7]), z: -0, n: NaN, inf: -Infinity, u: undefined, holey, np, tricky };
    const back = decodeTyped(JSON.parse(JSON.stringify(encodeTyped(v)))) as typeof v;
    expect(back.b).toBe(10n ** 80n);
    expect(Buffer.isBuffer(back.bytes) && back.bytes.equals(Buffer.from([0, 255, 7]))).toBe(true);
    expect(Object.is(back.z, -0)).toBe(true);
    expect(Number.isNaN(back.n)).toBe(true);
    expect(back.inf).toBe(-Infinity);
    expect("u" in back && back.u === undefined).toBe(true);
    expect(back.holey.length).toBe(3);
    expect(1 in back.holey).toBe(false);
    expect(Object.getPrototypeOf(back.np)).toBe(null);
    expect(Object.prototype.hasOwnProperty.call(back.tricky, "__proto__")).toBe(true);
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });

  it("marks exotic objects instead of throwing, and caps large inputs by hash", () => {
    const getter = {};
    Object.defineProperty(getter, "x", { get: () => 1, enumerable: true });
    const enc = encodeTyped({ m: new Map(), g: getter, p: new Proxy({}, {}), f: () => 1, c: new (class K {})(), t: new Uint16Array(2) }) as unknown as { entries: Array<[string, { $t: string; kind?: string }]> };
    const kinds = Object.fromEntries(enc.entries.map(([k, v]) => [k, v.kind ?? v.$t]));
    expect(kinds).toMatchObject({ m: "map", f: "function", c: "class-instance", t: "typed-array" });
    const capped = typedJsonCapped("x".repeat(5000), 100, () => "h");
    expect(capped.truncated).toBe(true);
    expect(capped.typed).toBeNull();
    expect(capped.sha256).toBe("h");
  });
});

describe("references (oracles.ts) against independent facts", () => {
  it("calendar: days-from-civil equals Date.UTC, and validity follows the calendar", () => {
    const r = new Rng(1);
    for (let i = 0; i < 2000; i++) {
      const y = r.int(1900, 9999);
      const m = r.int(1, 12);
      const d = r.int(1, 28);
      expect(daysFromCivil(y, m, d)).toBe(Math.round(Date.UTC(y, m - 1, d) / 86400000));
      expect(civilFromDays(daysFromCivil(y, m, d))).toEqual({ y, m, d });
    }
    expect(refIsValidYmd(20240229)).toBe(true);
    expect(refIsValidYmd(20230229)).toBe(false);
    expect(refIsValidYmd(19000229)).toBe(false);
    expect(refIsValidYmd(20000229)).toBe(true);
    expect(refIsValidYmd(18991231)).toBe(false);
    expect(refIsValidYmd(99991231)).toBe(true);
    expect(refIsValidYmd(20240431)).toBe(false);
    expect(refIsValidYmd("20240101")).toBe(false);
    expect(refIsValidYmd(20240101.5)).toBe(false);
    expect(refAddDays(20240228, 1)).toBe(20240229);
    expect(refAddDays(20231231, 1)).toBe(20240101);
    expect(refUtcDateOf(0)).toBe(19700101);
    expect(refUtcDateOf(-1)).toBe(19691231);
  });

  it("age: the D-010 29 February rule (anniversary on 1 March in common years)", () => {
    expect(refAge(20000229, 20180228)).toBe(17);
    expect(refAge(20000229, 20180301)).toBe(18);
    expect(refAge(20000229, 20200229)).toBe(20);
    expect(refAge(19840315, 20020314)).toBe(17);
    expect(refAge(19840315, 20020315)).toBe(18);
    expect(refReached(19840315, 18, 20020315)).toBe(true);
    expect(refReached(20260101, 0, 20251231)).toBe(false);
  });

  it("canonical JSON, strict UTF-8 and canonical decimals", () => {
    expect(refCanonical({ b: 1, a: [true, null, "x"], "é": -0 })).toBe('{"a":[true,null,"x"],"b":1,"é":0}');
    expect(() => refCanonical({ x: NaN })).toThrow();
    expect(refStrictUtf8(Buffer.from("héllo €", "utf8"))).toBe("héllo €");
    expect(refStrictUtf8(Buffer.from([0xc0, 0xaf]))).toBeNull(); // overlong
    expect(refStrictUtf8(Buffer.from([0xed, 0xa0, 0x80]))).toBeNull(); // surrogate
    expect(refStrictUtf8(Buffer.from([0xe2, 0x82]))).toBeNull(); // truncated
    expect(refStrictUtf8(Buffer.from([0xf4, 0x90, 0x80, 0x80]))).toBeNull(); // above U+10FFFF
    expect(refIsCanonicalDecBelow("0", "10")).toBe(true);
    expect(refIsCanonicalDecBelow("01", "10")).toBe(false);
    expect(refIsCanonicalDecBelow("10", "10")).toBe(false);
    expect(refIsCanonicalDecBelow("9", "10")).toBe(true);
    expect(refIsFieldDec((BigInt(P_DEC) - 1n).toString())).toBe(true);
    expect(refIsFieldDec(P_DEC)).toBe(false);
    expect(refIsFieldDec("-1")).toBe(false);
    expect(refIsFieldDec("1".repeat(100_000))).toBe(false);
    expect(refDepth({ a: [[1]] })).toBe(3);
    expect(refDepth(5)).toBe(0);
    expect(refDepth([])).toBe(1);
    expect(refDepth({ a: {}, b: [1, [2]] })).toBe(3);
    expect(refDepth(G.deepChain(200_000, "object"))).toBe(200_000);
  });

  it("generators produce values the references accept, and mutators report what they did", () => {
    const r = new Rng(77);
    for (let i = 0; i < 300; i++) {
      expect(refRequestValid(G.request(r))).toBe(true);
      expect(refReplyValid(G.reply(r))).toBe(true);
      const s = G.statement(r);
      expect(refParseStatement(Buffer.from(refCanonical(s), "utf8"))).toBe(true);
    }
    const b = mutateBytes(r, Buffer.from("abcdef"), [], 2);
    expect(b.ops.length).toBeGreaterThan(0);
    const t = mutateJsonText(r, '{"a":1}');
    expect(typeof t.value).toBe("string");
    const v = mutateValue(r, { a: 1, b: [2] }, 1);
    expect(v.ops.length).toBeGreaterThan(0);
  });
});

describe("coverage from NODE_V8_COVERAGE (coverage.ts)", () => {
  it("decodes source-map mappings (VLQ)", () => {
    // "AAAA" = [0,0,0,0]; "CAAC" adds [1,0,0,1]; next line "AACA" adds [0,0,1,0]: the generated
    // column restarts per line, the source fields carry over (source-map v3)
    expect(decodeMappings("AAAA,CAAC;AACA")).toEqual([
      [
        [0, 0, 0, 0],
        [1, 0, 0, 1],
      ],
      [[0, 0, 1, 1]],
    ]);
  });

  it("maps V8 block counts to source lines through the source-map cache", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-cov-test-"));
    try {
      const scope = path.join(dir, "src");
      fs.mkdirSync(scope);
      const file = path.join(scope, "m.ts");
      fs.writeFileSync(file, "line1\nline2\n");
      const url = pathToFileURL(file).href;
      // generated code: 2 lines of 10 characters; line 1 maps to source line 1, line 2 to source line 2
      const cov = {
        result: [
          {
            url,
            functions: [
              { functionName: "", isBlockCoverage: true, ranges: [{ startOffset: 0, endOffset: 22, count: 1 }] },
              { functionName: "f", isBlockCoverage: true, ranges: [{ startOffset: 11, endOffset: 21, count: 0 }] },
            ],
          },
        ],
        "source-map-cache": { [url]: { lineLengths: [10, 10], data: { mappings: "AAAA;AACA", sources: ["m.ts"] } } },
      };
      const covDir = path.join(dir, "cov");
      fs.mkdirSync(covDir);
      fs.writeFileSync(path.join(covDir, "coverage-1-1-0.json"), JSON.stringify(cov));
      const s = summariseCoverage([covDir], scope);
      const f = s.files.find((x) => x.file.endsWith("m.ts"));
      expect(f?.linesExecutable).toBe(2);
      expect(f?.linesCovered).toBe(1);
      expect(f?.uncoveredLines).toEqual([2]);
      expect(f?.functions).toBe(1);
      expect(f?.functionsCovered).toBe(0);
      expect(s.processes).toBe(1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("forge results (forge_fuzz.ts)", () => {
  it("flattens forge --json output and keeps counterexamples", () => {
    const j = {
      "test/v4/X.t.sol:XTest": {
        duration: "1ms",
        test_results: {
          "testFuzz_a(uint256)": { status: "Success", reason: null, counterexample: null, kind: { Fuzz: { runs: 64, mean_gas: 1, median_gas: 1 } }, traces: [] },
          "invariant_b()": { status: "Failure", reason: "bad", counterexample: { Sequence: [{ calldata: "0x00" }] }, kind: { Invariant: { runs: 8, calls: 200, reverts: 0 } } },
        },
      },
    };
    const out = flattenForgeJson(j);
    expect(out).toHaveLength(2);
    const inv = out.find((t) => t.test === "invariant_b()");
    expect(inv).toMatchObject({ suite: "test/v4/X.t.sol:XTest", status: "Failure", kind: "Invariant", runs: 8, calls: 200, reason: "bad" });
    expect(inv?.counterexample).toEqual({ Sequence: [{ calldata: "0x00" }] });
    expect(out.find((t) => t.kind === "Fuzz")?.runs).toBe(64);
    expect(flattenForgeJson(null)).toEqual([]);
  });
});

describe("full-run guards (common.ts)", () => {
  const settings = [
    { flag: "cases", value: 300, registered: 300 },
    { flag: "mutations", value: 5000, registered: 5000 },
  ];
  it("a full run keeps the pre-registered budgets unless a deviation is given", () => {
    expect(budgetDeviation([], false, settings)).toBeNull();
    expect(budgetDeviation([], true, [{ flag: "cases", value: 8, registered: 300 }])).toBeNull();
    expect(() => budgetDeviation(["--cases", "10"], false, [{ flag: "cases", value: 10, registered: 300 }])).toThrow(/pre-registered/);
    expect(() => budgetDeviation(["--deviation", "  "], false, [{ flag: "cases", value: 10, registered: 300 }])).toThrow(/--deviation/);
    const d = budgetDeviation(["--cases", "10", "--deviation", "short run after a crash"], false, [{ flag: "cases", value: 10, registered: 300 }]);
    expect(d?.text).toBe("short run after a crash");
    expect(d?.changed.map((x) => x.flag)).toEqual(["cases"]);
  });

  it("the commit check rejects an untracked path or unavailable repository and covers the code under test", () => {
    const paths = ["no/such/path/robustness-check-xyz"];
    const c = checkCommitted(paths);
    expect(c.gitClean).toBe(false);
    if (c.gitHead === null) {
      expect(c.problems).toEqual(["not a git checkout (git rev-parse HEAD failed)"]);
      expect(() => assertCommitted(false, paths)).toThrow(/not a git checkout/);
      expect(assertCommitted(true, paths)).toEqual(c);
    } else {
      expect(c.gitHead).toMatch(/^[0-9a-f]{40,64}$/);
      expect(c.problems).toContain("not tracked: no/such/path/robustness-check-xyz");
      expect(() => assertCommitted(false, paths)).toThrow(/not tracked: no\/such\/path\/robustness-check-xyz/);
    }
    for (const p of ["docs/v4/ROBUSTNESS.md", "harness/v4/robustness", "packages/v4/src", "onchain/test/v4", "scripts/robustness"]) expect(COMMITTED_PATHS).toContain(p);
  });
});

describe("hang records (fuzz.ts writeHang)", () => {
  it("regenerates the hung case from (seed, target, index) into a hang file, or names the last completed case", async () => {
    const { writeHang } = await import("../../harness/v4/robustness/fuzz.ts");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-hang-test-"));
    try {
      const f = await writeHang(dir, { hang: { target: "T-dates", caseIndex: 7, afterCase: null }, stoppedBy: "no progress for 120 s" }, true);
      expect(f).not.toBeNull();
      const j = JSON.parse(fs.readFileSync(path.join(dir, "failures", "T-dates", "hang_7.json"), "utf8")) as Record<string, unknown>;
      expect(j["caseIndex"]).toBe(7);
      expect(j["target"]).toBe("T-dates");
      expect(j["masterSeed"]).toBe(SEEDS.robustness.fuzz);
      expect(j["input"]).not.toBeUndefined();
      expect(String(j["replay"])).toContain("--replay");
      await writeHang(dir, { hang: { target: "T-dates", caseIndex: null, afterCase: 4123 }, stoppedBy: "x" }, true);
      const k = JSON.parse(fs.readFileSync(path.join(dir, "failures", "T-dates", "hang_after_4123.json"), "utf8")) as Record<string, unknown>;
      expect(k["lastCompletedCase"]).toBe(4123);
      expect(await writeHang(dir, { hang: null, stoppedBy: null }, true)).toBeNull();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
