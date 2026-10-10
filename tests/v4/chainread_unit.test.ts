import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { Interface, JsonRpcProvider, Network } from "ethers";
import type { LedgerV4 } from "@pqid/v4/ledger";
import { SEEDS } from "../../harness/v4/lib/seeds.ts";
import { CLIENT_VARIANTS } from "../../harness/v4/lib/rpc_trace.ts";
import type { PowerReading } from "../../harness/v4/bench/guard.ts";
import type { QuiesceRecord } from "../../harness/v4/lib/quiesce.ts";
import {
  FULL_GUARD,
  FULL_SIZES,
  SMOKE_GUARD,
  SMOKE_SIZES,
  S2_CELLS,
  SeriesStop,
  buildSchedule,
  flushCurrentPass,
  freshConnectionProblems,
  newCounts,
  roundSeries,
  runPass,
  s1CellIds,
  s3CellIds,
  type GuardIo,
  type GuardOptions,
  type PassContext,
} from "../../harness/v4/chainread/series.ts";
import { protocolDepartures } from "../../harness/v4/chainread/run.ts";
import { agentLikeGlobal, agentRecord, globalAgentOptions } from "../../harness/v4/chainread/target.ts";
import { CLIENTS, PRESENTATION_VARIANTS, READSET_VARIANTS, READ_CLIENTS, presentationVariant } from "../../harness/v4/chainread/variants.ts";
import { compareMultisets, multiset, readKeys, requestKey, stableJson } from "../../harness/v4/chainread/wire.ts";
import { ReadPlan, SIX_READS, unionMs, verifierTable, walletTable } from "../../harness/v4/chainread/plans.ts";
import { RawClient, parseHttpResponse, rpcPayload } from "../../harness/v4/chainread/raw.ts";
import { PassClock, cpuList, parseTopology, DEFAULT_TOPOLOGY } from "../../harness/v4/chainread/host.ts";
import { appendJsonlGz, jsonLine, readJsonlGz, targetDir, CHAINREAD_SMOKE_ROOT, CHAINREAD_ROOT } from "../../harness/v4/chainread/io.ts";
import { chainreadProtocolSha, harnessFiles, sourceFiles } from "../../harness/v4/chainread/env.ts";
import { compileReadBatch, decodeAggregate, encodeAggregate, installMulticall } from "../../harness/v4/chainread/contract.ts";
import { startMockRpc, type MockRpc } from "./helpers/mock_jsonrpc.ts";

// harness/v4/chainread (docs/v4/CHAINREAD.md): the parts that need no chain. Network tests use
// the shared mock JSON-RPC server on an OS-assigned port (never a D-034 or other fixed port).

describe("chainread: schedule (D-034 seeds, blocked orders)", () => {
  it("is deterministic and uses the registered seeds and the unchanged bootstrap seed", () => {
    const a = buildSchedule(FULL_SIZES);
    const b = buildSchedule(FULL_SIZES);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(a.seeds).toEqual({ conditionOrder: 20261011, readOrder: 20261012, verifierPool: 20261013, walletReads: 20261014, bootstrap: 20260927 });
    expect(a.seeds.conditionOrder).toBe(SEEDS.chainRead.conditionOrder);
  });

  it("every round and block holds every cell or variant exactly once", () => {
    const sch = buildSchedule(FULL_SIZES);
    const sorted = (xs: readonly string[]) => [...xs].sort().join("|");
    expect(sch.s1.rounds).toHaveLength(FULL_SIZES.r1);
    for (const r of sch.s1.rounds) expect(sorted(r)).toBe(sorted(s1CellIds()));
    expect(s1CellIds()).toHaveLength(17);
    expect(sch.s2.rounds).toHaveLength(FULL_SIZES.n2);
    for (const r of sch.s2.rounds) expect(sorted(r)).toBe(sorted(S2_CELLS));
    expect(sch.s3.rounds).toHaveLength(FULL_SIZES.r3);
    expect(s3CellIds()).toHaveLength(READ_CLIENTS.length * SIX_READS.length + READSET_VARIANTS.length);
    for (const r of sch.s3.rounds) expect(sorted(r)).toBe(sorted(s3CellIds()));
    for (const series of [sch.s4, sch.s5]) {
      expect(series.passes).toHaveLength(FULL_SIZES.passes);
      for (const ps of series.passes) {
        expect([...ps.order].sort((x, y) => x - y)).toEqual(Array.from({ length: FULL_SIZES.p }, (_, i) => i));
        expect(ps.blocks).toHaveLength(FULL_SIZES.p);
        for (const blk of ps.blocks) expect(sorted(blk)).toBe("A|B|C|D|E|F|G|H|I");
      }
    }
    // separate streams: the verifier and wallet orders differ
    expect(JSON.stringify(sch.s4.passes[0]?.order)).not.toBe(JSON.stringify(sch.s5.passes[0]?.order));
  });

  it("the timed schedule does not depend on the warm-up size", () => {
    const a = buildSchedule({ ...SMOKE_SIZES, warmupRounds: 1, warmupPresentations: 1 });
    const b = buildSchedule({ ...SMOKE_SIZES, warmupRounds: 5, warmupPresentations: 5 });
    expect(JSON.stringify({ ...a, warmup: "" })).toBe(JSON.stringify({ ...b, warmup: "" }));
  });
});

describe("chainread: variants (D-034 labels)", () => {
  it("only the shipped client and plan carry the label 'as shipped'", () => {
    expect(PRESENTATION_VARIANTS.map((v) => v.id).join("")).toBe("ABCDEFGHI");
    for (const v of PRESENTATION_VARIANTS) {
      const shipped = v.client === "asShipped" && v.plan === "sequential" && !v.multicall && !v.cached;
      expect(v.label).toBe(shipped ? "as shipped" : "variant, not shipped");
    }
    expect(PRESENTATION_VARIANTS.filter((v) => v.label === "as shipped").map((v) => v.id)).toEqual(["A"]);
    for (const rs of READSET_VARIANTS) expect(rs.label).toBe(rs.client === "asShipped" && !rs.concurrent ? "as shipped" : "variant, not shipped");
    expect(presentationVariant("H").multicall).toBe(true);
    expect(presentationVariant("cachedReads").id).toBe("I");
    expect(() => presentationVariant("Z")).toThrow(/unknown variant/);
  });

  it("client settings are the documented ethers options on top of the shipped client", () => {
    expect(CLIENTS.asShipped).toBe(CLIENT_VARIANTS.asShipped);
    expect(CLIENTS.asShipped.label).toBe("as shipped");
    for (const [k, c] of Object.entries(CLIENTS)) if (k !== "asShipped") expect(c.label).toBe("variant, not shipped");
    expect(CLIENTS.staticNetwork.options).toEqual({ staticNetwork: true });
    expect(CLIENTS.noBatchStall.options).toEqual({ batchStallTime: 0 });
    expect(CLIENTS.staticNoStall.options).toEqual({ staticNetwork: true, batchStallTime: 0 });
    expect(CLIENTS.unbatched.options).toEqual({ batchMaxCount: 1 });
    expect(CLIENTS.unbatchedStatic.options).toEqual({ staticNetwork: true, batchMaxCount: 1 });
  });
});

describe("chainread: logical requests (equivalence rule)", () => {
  it("canonical JSON ignores key order; eth_chainId is dropped; multisets count repeats", () => {
    expect(stableJson({ b: 1, a: { d: 2, c: 3 } })).toBe(stableJson({ a: { c: 3, d: 2 }, b: 1 }));
    expect(requestKey({ method: "eth_call", params: [{ to: "0xab", data: "0x01" }, "latest"] })).toBe(requestKey({ method: "eth_call", params: [{ data: "0x01", to: "0xab" }, "latest"] }));
    const reqs = [
      { method: "eth_chainId", params: [] },
      { method: "eth_call", params: [{ to: "0x1", data: "0x" }, "latest"] },
      { method: "eth_call", params: [{ to: "0x1", data: "0x" }, "latest"] },
      { method: "eth_getLogs", params: [{ address: "0x1" }] },
    ];
    const keys = readKeys(reqs);
    expect(keys).toHaveLength(3);
    const ref = multiset(keys);
    expect(compareMultisets(ref, multiset(keys)).equal).toBe(true);
    const fewer = compareMultisets(ref, multiset(keys.slice(1)));
    expect(fewer).toMatchObject({ equal: false, extra: [] });
    expect(fewer.missing).toHaveLength(1);
    const more = compareMultisets(ref, multiset([...keys, keys[0] as string]));
    expect(more.extra).toHaveLength(1);
    expect(more.missing).toHaveLength(0);
  });
});

/** A fake ledger: each read resolves after `ms` with its own name and arguments. */
function fakeLedger(ms = 5) {
  const calls: string[] = [];
  const read =
    (m: string) =>
    (...args: unknown[]) => {
      calls.push(`${m}:${JSON.stringify(args)}`);
      return new Promise((r) => setTimeout(() => r(`${m}(${args.join(",")})`), ms));
    };
  const L = {
    resolveDidRecord: read("resolveDidRecord"),
    getPopSignature: read("getPopSignature"),
    latestAccreditation: read("latestAccreditation"),
    currentEpoch: read("currentEpoch"),
    latestKemKey: read("latestKemKey"),
    getMinAnchorInterval: read("getMinAnchorInterval"),
    chainId: () => Promise.resolve(31337),
    other: 42,
  };
  return { ledger: L as unknown as LedgerV4, calls };
}

describe("chainread: read plans", () => {
  it("unionMs merges overlapping intervals", () => {
    expect(unionMs([])).toBe(0);
    expect(unionMs([{ t0Ms: 0, t1Ms: 10 }])).toBe(10);
    expect(unionMs([{ t0Ms: 0, t1Ms: 10 }, { t0Ms: 5, t1Ms: 12 }, { t0Ms: 20, t1Ms: 25 }])).toBe(17);
    expect(unionMs([{ t0Ms: 20, t1Ms: 25 }, { t0Ms: 0, t1Ms: 30 }])).toBe(30);
  });

  it("sequential: pass-through, outer reads timed, other properties untouched", async () => {
    const f = fakeLedger(2);
    const plan = new ReadPlan(f.ledger, "sequential");
    plan.begin();
    expect((plan.proxy as unknown as { other: number }).other).toBe(42);
    await plan.proxy.resolveDidRecord("did:a", "0xc");
    await plan.proxy.currentEpoch("did:a", "0xc");
    const rep = await plan.end();
    expect(rep.mode).toBe("sequential");
    expect(rep.outerCalls.map((c) => c.method)).toEqual(["resolveDidRecord", "currentEpoch"]);
    expect(rep.prefetchStarted).toBe(0);
    expect(rep.chainUnionMs).toBeCloseTo(rep.chainSumMs, 6);
    expect(f.calls).toHaveLength(2);
  });

  it("concurrent (verifier table): the first read starts the whole group; calls are served FIFO", async () => {
    const f = fakeLedger(20);
    const plan = new ReadPlan(f.ledger, "concurrent");
    plan.begin(verifierTable());
    const P = plan.proxy;
    const v1 = await P.resolveDidRecord("did:i", "0xc");
    // all five reads of the group were started by the first call
    expect(f.calls).toHaveLength(5);
    expect(v1).toBe("resolveDidRecord(did:i,0xc)");
    await Promise.all([P.resolveDidRecord("did:i", "0xc"), P.getPopSignature("did:i", "0xc"), P.latestAccreditation("did:i"), P.currentEpoch("did:i", "0xc")]);
    await P.chainId(); // never planned, never counted as unplanned
    const rep = await plan.end();
    expect(rep.groupsFired).toEqual(["verifier: issuer pair"]);
    expect(rep.prefetchStarted).toBe(5);
    expect(rep.prefetchConsumed).toBe(5);
    expect(rep.leftOver).toEqual([]);
    expect(rep.unplanned).toEqual([]);
    expect(f.calls).toHaveLength(5);
    // the group's reads overlapped, so the union is far below the sum
    expect(rep.chainUnionMs).toBeLessThan(rep.chainSumMs);
  });

  it("concurrent: unused prefetched reads are left over; a read without a rule is unplanned", async () => {
    const f = fakeLedger(1);
    const plan = new ReadPlan(f.ledger, "concurrent");
    plan.begin(verifierTable());
    await plan.proxy.resolveDidRecord("did:i", "0xc");
    await plan.proxy.latestKemKey("did:v", "0xv");
    const rep = await plan.end();
    expect(rep.leftOver.length).toBe(4);
    expect(rep.unplanned).toEqual([`latestKemKey:${JSON.stringify(["did:v", "0xv"])}`]);
    expect(() => new ReadPlan(f.ledger, "concurrent").begin(null)).toThrow(/prefetch table/);
  });

  it("wallet table: the verifier pair and the issuer pair get different groups", async () => {
    const f = fakeLedger(1);
    const plan = new ReadPlan(f.ledger, "concurrent");
    plan.begin(walletTable("did:v"));
    const P = plan.proxy;
    await Promise.all([P.resolveDidRecord("did:v", "0xv"), P.latestAccreditation("did:i")]);
    await Promise.all([P.resolveDidRecord("did:v", "0xv"), P.getPopSignature("did:v", "0xv"), P.latestKemKey("did:v", "0xv")]);
    await Promise.all([P.latestAccreditation("did:i"), P.getMinAnchorInterval()]);
    await Promise.all([P.resolveDidRecord("did:i", "0xc"), P.resolveDidRecord("did:i", "0xc"), P.getPopSignature("did:i", "0xc"), P.currentEpoch("did:i", "0xc")]);
    const rep = await plan.end();
    expect(rep.groupsFired).toEqual(["wallet: verifier pair", "wallet: issuer DID", "wallet: issuer pair"]);
    expect(rep.prefetchStarted).toBe(11);
    expect(rep.prefetchConsumed).toBe(11);
    expect(rep.leftOver).toEqual([]);
    expect(rep.unplanned).toEqual([]);
  });
});

describe("chainread: raw transports", () => {
  it("rpcPayload: one object for a request, an array for a batch", () => {
    expect(JSON.parse(rpcPayload({ method: "eth_chainId", params: [] }))).toEqual({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] });
    const arr = JSON.parse(rpcPayload([{ method: "a", params: [] }, { method: "b", params: [1] }], 7)) as Array<{ id: number }>;
    expect(arr.map((x) => x.id)).toEqual([7, 8]);
  });

  it("parseHttpResponse: Content-Length, chunked with trailers, incomplete and close-delimited bodies", () => {
    const cl = Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhelloEXTRA');
    const r = parseHttpResponse(cl);
    expect(r?.status).toBe(200);
    expect(r?.body.toString()).toBe("hello");
    expect(r?.consumed).toBe(cl.length - 5);
    expect(r?.close).toBe(false);
    expect(parseHttpResponse(Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel"))).toBeNull();
    expect(parseHttpResponse(Buffer.from("HTTP/1.1 200 OK\r\nContent-Le"))).toBeNull();
    const ch = Buffer.from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\nX-T: 1\r\n\r\n");
    const c = parseHttpResponse(ch);
    expect(c?.body.toString()).toBe("abcde");
    expect(c?.consumed).toBe(ch.length);
    expect(parseHttpResponse(Buffer.from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab"))).toBeNull();
    const closeDelim = Buffer.from("HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nbody");
    expect(parseHttpResponse(closeDelim, false)).toBeNull();
    expect(parseHttpResponse(closeDelim, true)?.body.toString()).toBe("body");
    expect(() => parseHttpResponse(Buffer.from("SSH-2.0 x\r\n\r\n"))).toThrow(/not an HTTP/);
  });

  describe("RawClient against the mock JSON-RPC server", () => {
    let mock: MockRpc;
    let raw: RawClient;
    beforeAll(async () => {
      mock = await startMockRpc();
      raw = new RawClient(mock.url);
    });
    afterAll(async () => {
      raw.close();
      await mock.close();
    });

    it("counts new TCP connections per call for every transport (equal to the server's accepted connections)", async () => {
      const body = rpcPayload({ method: "eth_blockNumber", params: [] });
      const seen: Array<[string, number | null]> = [];
      for (const t of ["fetch", "httpKeepAlive", "tcpRawNoDelay", "httpFresh"] as const) {
        for (let i = 0; i < 2; i++) {
          const o = await raw.single(t, body, 1);
          expect(o.ok, `${t} ${o.error ?? ""}`).toBe(true);
          expect(o.responses).toBe(1);
          expect(o.bytesOut).toBe(Buffer.byteLength(body));
          expect(o.bytesIn).toBeGreaterThan(10);
          seen.push([t, o.newConnections]);
        }
      }
      // fetch (undici) may open a second connection when the next request starts before the first
      // socket is back in its pool; the count is recorded either way and must match the server
      expect(seen[0]).toEqual(["fetch", 1]);
      expect(seen.slice(2)).toEqual([
        ["httpKeepAlive", 1],
        ["httpKeepAlive", 0],
        ["tcpRawNoDelay", 1],
        ["tcpRawNoDelay", 0],
        ["httpFresh", 1],
        ["httpFresh", 1],
      ]);
      expect(seen.reduce((a, [, n]) => a + (n ?? 0), 0)).toBe(mock.connections());
      expect(mock.okPosts()).toHaveLength(8);
    });

    it("a JSON-RPC array is one POST with one response per element; k concurrent POSTs are k POSTs", async () => {
      mock.reset();
      const arr = await raw.single("httpKeepAlive", rpcPayload([{ method: "eth_chainId", params: [] }, { method: "eth_blockNumber", params: [] }, { method: "eth_call", params: [{ to: "0x" + "11".repeat(20), data: "0x" }, "latest"] }]), 3);
      expect(arr.ok).toBe(true);
      expect(arr.responses).toBe(3);
      expect(mock.okPosts()).toHaveLength(1);
      expect(mock.okPosts()[0]?.batch).toBe(true);
      mock.reset();
      const k = await raw.concurrent([0, 1, 2].map((i) => rpcPayload({ method: "eth_blockNumber", params: [] }, i + 1)));
      expect(k.ok).toBe(true);
      expect(k.each).toHaveLength(3);
      expect(mock.okPosts()).toHaveLength(3);
      expect(k.newConnections).toBe(mock.connections());
    });

    it("a JSON-RPC error or a wrong element count is not ok", async () => {
      const bad = await raw.single("httpKeepAlive", rpcPayload({ method: "no_such_method", params: [] }), 1);
      expect(bad.ok).toBe(false);
      expect(bad.rpcErrors).toBe(1);
      const short = await raw.single("tcpRawNoDelay", rpcPayload({ method: "eth_chainId", params: [] }), 2);
      expect(short.ok).toBe(false);
      expect(short.error).toMatch(/responses 1\/2/);
    });
  });
});

describe("chainread: multicall helper and transport", () => {
  const helper = "0x" + "aa".repeat(20);
  const registry = "0x" + "bb".repeat(20);
  const other = "0x" + "cc".repeat(20);

  it("compiles ChainReadBatch with the repository's solc and round-trips aggregate data", () => {
    const c = compileReadBatch();
    expect(c.bytecode.length).toBeGreaterThan(100);
    expect(c.sourceSha256).toMatch(/^[0-9a-f]{64}$/);
    const data = encodeAggregate([{ to: registry, data: "0x1234" }]);
    const iface = new Interface(c.abi);
    const decodedCall = iface.decodeFunctionData("aggregate", data);
    expect(String((decodedCall[0] as unknown as Array<[string, string]>)[0]?.[1])).toBe("0x1234");
    const ret = iface.encodeFunctionResult("aggregate", [7n, [[true, "0xdead"], [false, "0x08c379a0"]]]);
    expect(decodeAggregate(ret)).toEqual({ blockNumber: 7n, results: [{ ok: true, data: "0xdead" }, { ok: false, data: "0x08c379a0" }] });
  });

  it("aggregates the registry eth_calls of one turn into one eth_call; a failed sub-call is re-sent alone", async () => {
    const mock = await startMockRpc();
    const provider = new JsonRpcProvider(mock.url, Network.from(31337n), { staticNetwork: true, batchStallTime: 0, cacheTimeout: -1 });
    try {
      const iface = new Interface(compileReadBatch().abi);
      mock.setCallResult(iface.encodeFunctionResult("aggregate", [1n, [[true, "0x01"], [false, "0x"]]]));
      const mc = installMulticall(provider, helper, [registry]);
      const send = (to: string, data: string) => provider.send("eth_call", [{ to, data }, "latest"]) as Promise<string>;
      const [a, b, c] = await Promise.all([send(registry, "0x11"), send(registry.toUpperCase().replace("0X", "0x"), "0x22"), send(other, "0x33")]);
      expect(a).toBe("0x01");
      // b failed inside the aggregate and was re-sent alone (the mock answers every eth_call the same way)
      expect(typeof b).toBe("string");
      expect(typeof c).toBe("string");
      const st = mc.stats();
      expect(st).toMatchObject({ aggregates: 1, subCalls: 2, fallbacks: 1, passedThrough: 1, sizes: [2] });
      const targets = mock.okPosts().flatMap((r) => r.callTargets);
      expect(targets.filter((t) => t === helper)).toHaveLength(1);
      expect(targets.filter((t) => t === registry)).toHaveLength(1); // the fallback
      expect(targets.filter((t) => t === other)).toHaveLength(1); // not an allowed target: unchanged
      mc.detach();
    } finally {
      provider.destroy();
      await mock.close();
    }
  });
});

describe("chainread: host, output and environment helpers", () => {
  it("CPU lists and the pinned topology", () => {
    expect(cpuList("0")).toEqual([0]);
    expect(cpuList("4-7")).toEqual([4, 5, 6, 7]);
    expect(cpuList("0,2-3,2")).toEqual([0, 2, 3]);
    expect(() => cpuList("3-1")).toThrow();
    expect(() => cpuList("a")).toThrow();
    expect(parseTopology(undefined)).toEqual(DEFAULT_TOPOLOGY);
    expect(DEFAULT_TOPOLOGY).toEqual({ harness: "0", anvil: "1", besu: "4-7" });
    expect(parseTopology("harness=2;besu=5-6")).toEqual({ harness: "2", anvil: "1", besu: "5-6" });
    expect(() => parseTopology("foo=1")).toThrow();
  });

  it("PassClock flags a long gap between samples and a long sample, not the planned spacing", () => {
    const ms = (x: number) => BigInt(Math.round(x * 1e6));
    const c = new PassClock(2000);
    c.sample(ms(0), ms(5));
    c.sample(ms(2005), ms(2010)); // the planned 2 s spacing
    expect(c.finish().hostPauseSuspected).toBe(false);
    const d = new PassClock(0);
    d.sample(ms(0), ms(5));
    d.sample(ms(3005), ms(3010)); // 3 s gap
    d.sample(ms(3010), ms(14010)); // 11 s sample
    const rec = d.finish();
    expect(rec.hostPauseSuspected).toBe(true);
    expect(rec.reasons.join(" ")).toMatch(/gap of 3000 ms/);
    expect(rec.reasons.join(" ")).toMatch(/one sample took 11000 ms/);
    expect(rec.samples).toBe(3);
  });

  it("gzip members append and read back as one stream; numbers are rounded to 1 ns", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-cr-"));
    try {
      const f = path.join(dir, "x.jsonl.gz");
      appendJsonlGz(f, [{ a: 1 }, { a: 2.1234567891 }]);
      appendJsonlGz(f, []);
      appendJsonlGz(f, [{ a: 3n }]);
      expect(readJsonlGz<{ a: unknown }>(f)).toEqual([{ a: 1 }, { a: 2.123457 }, { a: "3" }]);
      expect(jsonLine({ x: 0.1 + 0.2 })).toBe('{"x":0.3}');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("results paths: campaigns under results/v4/chainread, smoke under its _smoke folder", () => {
    expect(targetDir("cr_wsl", "anvil", false)).toBe(path.join(CHAINREAD_ROOT, "cr_wsl", "anvil"));
    expect(targetDir("smoke_win", "besu", true)).toBe(path.join(CHAINREAD_SMOKE_ROOT, "smoke_win", "besu"));
    expect(() => targetDir("../x", "anvil", false)).toThrow();
    expect(() => targetDir("cr", "geth", false)).toThrow();
  });

  it("the environment record hashes the protocol, the harness and the E4 code-under-test list", () => {
    const sha = chainreadProtocolSha();
    expect(sha.normative).toMatch(/^[0-9a-f]{64}$/);
    expect(sha.file).toMatch(/^[0-9a-f]{64}$/);
    const h = harnessFiles();
    expect(h).toContain("harness/v4/chainread/ReadBatch.sol");
    expect(h).toContain("harness/v4/lib/rpc_trace.ts");
    expect(h).toContain("scripts/chainread/run_wsl.sh");
    for (const f of h) expect(fs.existsSync(path.join(process.cwd(), f)), f).toBe(true);
    const s = sourceFiles();
    expect(s[0]).toBe("onchain/contracts/v4/RegistriesV4.sol");
    expect(s).toContain("packages/v4/src/ledger.ts");
    expect(s).toContain("setup/out/v4/verification_key_dev.json");
  });
});

// ---------------------------------------------------------------------------------------
// guard logic of the timed run (stubbed power, quiet and affinity readers; temp output folder)
// ---------------------------------------------------------------------------------------

function stubIo(powerSeq: boolean[], wall?: () => number): GuardIo & { powerReads: () => number; slept: number[] } {
  let i = 0;
  const slept: number[] = [];
  return {
    readPower: () => {
      const ac = powerSeq[Math.min(i, powerSeq.length - 1)] ?? true;
      i++;
      return { ac, code: ac ? "2" : "1", source: "none", utc: new Date().toISOString() } as PowerReading;
    },
    readQuiesce: async () => ({ quiesced: true, reasons: [] }) as unknown as QuiesceRecord,
    readAffinity: (pid, role, cpus) => ({ pid, role, expected: cpus, threads: 1, mismatches: [], ok: true, error: null }),
    sleep: async (ms) => {
      slept.push(ms);
    },
    wallNow: wall ?? (() => Date.now()),
    powerReads: () => i,
    slept,
  };
}

function passCtx(dir: string, io: GuardIo, guard: Partial<GuardOptions> = {}): PassContext {
  return { dir, targetNode: { name: "anvil", ownPids: [], ownPorts: [] }, guard: { ...FULL_GUARD, ...guard }, pins: null, log: () => undefined, io };
}

const readLines = (f: string) => (fs.existsSync(f) ? fs.readFileSync(f, "utf8").split("\n").filter((l) => l.trim()) : []).map((l) => JSON.parse(l) as Record<string, unknown>);

describe("chainread: pass guard (power, errors, stop)", () => {
  let dir: string;
  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-cr-guard-"));
  });
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));
  const sub = (name: string) => {
    const d = path.join(dir, name);
    fs.mkdirSync(d, { recursive: true });
    return d;
  };

  it("a pass that ends off AC is written as discarded-battery and repeated; its samples never count as used", async () => {
    const d = sub("discard");
    const io = stubIo([true, false, true, true]);
    const counts = newCounts();
    let bodies = 0;
    await runPass(passCtx(d, io), "s4", "s4.jsonl.gz", 1, 0, counts, async (sink) => {
      bodies++;
      sink.samples.push({ status: "ok", x: bodies });
      sink.posts.push({ v: "A" });
    });
    expect(bodies).toBe(2);
    const passes = readLines(path.join(d, "passes.jsonl"));
    expect(passes.map((p) => p["status"])).toEqual(["discarded-battery", "ok"]);
    const samples = readJsonlGz<Record<string, unknown>>(path.join(d, "s4.jsonl.gz"));
    expect(samples).toEqual([
      { status: "discarded-battery", x: 1, sampleStatus: "ok" },
      { status: "ok", x: 2 },
    ]);
    expect(readJsonlGz<Record<string, unknown>>(path.join(d, "posts.jsonl.gz"))).toEqual([{ v: "A", discarded: true }, { v: "A" }]);
    expect(counts).toEqual({ samples: 1, errors: 0, discardedSamples: 1, discardedErrors: 0, stoppedSamples: 0 });
  });

  it("a pass is repeated at most 3 times off AC, then the series stops", async () => {
    const d = sub("repeats");
    const io = stubIo([true, false, true, false, true, false, true, false, true, false]);
    const counts = newCounts();
    await expect(runPass(passCtx(d, io), "s5", "s5.jsonl.gz", 1, 0, counts, async (sink) => void sink.samples.push({ status: "ok" }))).rejects.toThrow(SeriesStop);
    const passes = readLines(path.join(d, "passes.jsonl"));
    expect(passes).toHaveLength(4);
    expect(passes.every((p) => p["status"] === "discarded-battery")).toBe(true);
    expect(counts.discardedSamples).toBe(4);
    expect(counts.samples).toBe(0);
  });

  it("before a pass: not on AC waits (recorded) and reads again; the smoke guard never discards", async () => {
    const d = sub("wait");
    const io = stubIo([false, false, true, true]);
    await runPass(passCtx(d, io), "s1", "s1.jsonl.gz", 1, 0, newCounts(), async (sink) => void sink.samples.push({ status: "ok" }));
    const [p] = readLines(path.join(d, "passes.jsonl"));
    expect(p?.["powerWaits"]).toBe(2);
    expect(io.slept).toEqual([FULL_GUARD.powerWaitMs, FULL_GUARD.powerWaitMs]);
    const d2 = sub("smoke");
    const io2 = stubIo([false]);
    await runPass(passCtx(d2, io2, SMOKE_GUARD), "s1", "s1.jsonl.gz", 1, 0, newCounts(), async (sink) => void sink.samples.push({ status: "ok" }));
    expect(readLines(path.join(d2, "passes.jsonl")).map((x) => x["status"])).toEqual(["ok"]);
  });

  it("a cell is retried once; the third error record of a series stops it and the pass is written as stopped", async () => {
    const d = sub("errors");
    const io = stubIo([true]);
    let calls = 0;
    const cellFn = async () => {
      calls++;
      const t = process.hrtime.bigint();
      return { t0: t, t1: t, posts: [], t0TraceMs: 0, ok: false, problems: [`boom ${calls}`], record: { ms: 1 } };
    };
    await expect(roundSeries(passCtx(d, io), "s3", "s3.jsonl.gz", [["c1", "c2", "c3"]], 1, 0, cellFn)).rejects.toThrow(/3 errors/);
    expect(calls).toBe(3); // c1 twice (retry), then c2 once
    expect(readLines(path.join(d, "errors.jsonl")).map((e) => [e["cell"], e["try"]])).toEqual([
      ["c1", 1],
      ["c1", 2],
      ["c2", 1],
    ]);
    const [p] = readLines(path.join(d, "passes.jsonl"));
    expect(p?.["status"]).toBe("stopped");
    expect(String(p?.["stopReason"])).toMatch(/3 errors/);
    const samples = readJsonlGz<Record<string, unknown>>(path.join(d, "s3.jsonl.gz"));
    expect(samples).toHaveLength(3);
    expect(samples.every((s) => s["status"] === "stopped" && s["sampleStatus"] === "error")).toBe(true);
  });

  it("an error then a good retry gives one error record and the series goes on", async () => {
    const d = sub("retry");
    let calls = 0;
    const cellFn = async () => {
      calls++;
      const t = process.hrtime.bigint();
      return { t0: t, t1: t, posts: [], t0TraceMs: 0, ok: calls !== 1, problems: calls === 1 ? ["once"] : [], record: { ms: 1 } };
    };
    const counts = await roundSeries(passCtx(d, stubIo([true])), "s1", "s1.jsonl.gz", [["a", "b"]], 1, 0, cellFn);
    expect(counts).toMatchObject({ samples: 3, errors: 1 });
    expect(readJsonlGz<Record<string, unknown>>(path.join(d, "s1.jsonl.gz")).map((s) => s["status"])).toEqual(["error", "ok", "ok"]);
  });

  it("errors of a discarded pass are counted apart and do not reach the 3-error stop", async () => {
    const d = sub("discarded-errors");
    const io = stubIo([true, false, true, true]);
    const counts = newCounts();
    await runPass(passCtx(d, io), "s4", "s4.jsonl.gz", 1, 0, counts, async (sink) => {
      sink.recordError({ cell: "x" }, ["e1"]);
      sink.recordError({ cell: "y" }, ["e2"]);
    });
    expect(counts).toMatchObject({ errors: 2, discardedErrors: 2 });
    expect(readLines(path.join(d, "errors.jsonl"))).toHaveLength(4);
  });

  it("flushCurrentPass writes the pass in progress as stopped (signal path)", async () => {
    const d = sub("flush");
    const io = stubIo([true]);
    const counts = newCounts();
    let release: () => void = () => undefined;
    const running = runPass(passCtx(d, io), "s2", "s2.jsonl.gz", 1, 0, counts, async (sink) => {
      sink.samples.push({ status: "ok" });
      await new Promise<void>((r) => (release = r));
    });
    await new Promise((r) => setTimeout(r, 20));
    flushCurrentPass("signal SIGINT");
    release();
    await running;
    const passes = readLines(path.join(d, "passes.jsonl"));
    expect(passes).toHaveLength(1); // written once, as stopped
    expect(passes[0]).toMatchObject({ status: "stopped", stopReason: "signal SIGINT", powerPost: null });
    expect(counts.stoppedSamples).toBe(1);
  });

  it("an affinity change during a pinned pass flags the pass after it, kept and counted", async () => {
    const d = sub("affinity");
    let n = 0;
    const io: GuardIo = {
      ...stubIo([true]),
      readAffinity: (pid, role, cpus) => {
        n++;
        const ok = n === 1; // fine before the pass, changed after it
        return { pid, role, expected: cpus, threads: 2, mismatches: ok ? [] : [{ tid: 7, cpus: "0-7" }], ok, error: null };
      },
    };
    const ctx = { ...passCtx(d, io), pins: [{ pid: 1, role: "anvil", cpus: "1" }] };
    await runPass(ctx, "s4", "s4.jsonl.gz", 1, 0, newCounts(), async (sink) => void sink.samples.push({ status: "ok" }));
    const [p] = readLines(path.join(d, "passes.jsonl"));
    expect(p).toMatchObject({ status: "ok", affinityMismatchPost: true });
  });
});

describe("chainread: fresh-connection guard, clock drift, protocol departures, agents, seed streams", () => {
  it("an S2 sample must open a new TCP connection and classify every attempt", () => {
    expect(freshConnectionProblems({ tcpConnects: 1, tcpConnectsUnknown: 0 })).toEqual([]);
    expect(freshConnectionProblems({ tcpConnects: 0, tcpConnectsUnknown: 0 })[0]).toMatch(/not a fresh connection/);
    expect(freshConnectionProblems({ tcpConnects: 2, tcpConnectsUnknown: 1 })[0]).toMatch(/could not be classified/);
  });

  it("PassClock flags a wall-clock jump against the monotonic clock (host pause)", () => {
    let wall = 1_000_000;
    const c = new PassClock(0, undefined, () => wall);
    wall += 5000; // the wall clock moved 5 s while the monotonic clock barely moved
    const rec = c.finish();
    expect(rec.driftMs).toBeGreaterThan(4900);
    expect(rec.hostPauseSuspected).toBe(true);
    expect(rec.reasons.join(" ")).toMatch(/wall-clock and monotonic spans differ/);
  });

  it("a timed run that departs from the protocol is listed (it then needs --deviation)", () => {
    const base = { smoke: false, pin: true, env: "wsl2", series: ["s1", "s2", "s3", "s4", "s5"], sizes: FULL_SIZES, holders: 4, settleSec: 600, cpus: undefined, allowSourceDrift: false };
    expect(protocolDepartures(base)).toEqual([]);
    expect(protocolDepartures({ ...base, env: "windows", pin: false })).toEqual([]);
    expect(protocolDepartures({ ...base, pin: false })).toEqual(["not pinned (--no-pin)"]);
    expect(protocolDepartures({ ...base, series: ["s4"], settleSec: 60 })).toHaveLength(2);
    expect(protocolDepartures({ ...base, sizes: { ...FULL_SIZES, p: 50 }, allowSourceDrift: true })).toHaveLength(2);
    expect(protocolDepartures({ ...base, cpus: "harness=0;anvil=1;besu=4-7" })).toEqual([]);
    expect(protocolDepartures({ ...base, cpus: "anvil=2" })).toHaveLength(1);
    expect(protocolDepartures({ ...base, smoke: true, pin: false, settleSec: 2, sizes: SMOKE_SIZES })).toEqual([]);
  });

  it("variant clients get an agent with the options of Node's global agent (idle timeout included)", () => {
    const { agent, record } = agentLikeGlobal();
    try {
      const g = globalAgentOptions();
      expect(record).toMatchObject({ kind: "own http.Agent with the global agent's options", keepAlive: g.keepAlive, scheduling: g.scheduling ?? null, timeoutMs: g.timeout ?? null });
      expect(record.timeoutMs).toBe((http.globalAgent as unknown as { options: { timeout?: number } }).options.timeout ?? null);
      expect((agent as unknown as { options: { timeout?: number; keepAlive?: boolean } }).options).toMatchObject({ keepAlive: true, timeout: g.timeout });
      expect(agentRecord("Node's global HTTP agent (as LedgerV4)").timeoutMs).toBe(record.timeoutMs);
    } finally {
      agent.destroy();
    }
  });

  it("conditionOrder orders the variants within every S4 and S5 block; the pool seeds order the presentations only", () => {
    const a = buildSchedule(SMOKE_SIZES);
    expect(Object.keys(a.streamUse).sort()).toEqual(["conditionOrder", "readOrder", "verifierPool", "walletReads"]);
    expect(a.streamUse["conditionOrder"]).toMatchObject({ seed: 20261011, registryUse: "order of conditions (client variants) within blocks" });
    expect(a.streamUse["conditionOrder"]?.usedFor).toMatch(/S4 variant order of every block/);
    // more S1 rounds draw more from conditionOrder: the S4 blocks move, the S4 presentation order does not
    const b = buildSchedule({ ...SMOKE_SIZES, r1: SMOKE_SIZES.r1 + 1 });
    expect(b.s4.passes[0]?.order).toEqual(a.s4.passes[0]?.order);
    expect(b.s5.passes[0]?.order).toEqual(a.s5.passes[0]?.order);
    expect(JSON.stringify(b.s4.passes.map((p) => p.blocks))).not.toBe(JSON.stringify(a.s4.passes.map((p) => p.blocks)));
    // more S3 rounds (readOrder) leave S4 and S5 unchanged
    const c = buildSchedule({ ...SMOKE_SIZES, r3: SMOKE_SIZES.r3 + 3 });
    expect(JSON.stringify([c.s4, c.s5])).toBe(JSON.stringify([a.s4, a.s5]));
  });
});
