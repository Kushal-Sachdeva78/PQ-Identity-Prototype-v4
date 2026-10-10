import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "node:http";
import { JsonRpcProvider, Network } from "ethers";
import { buildWorld, defaultAnvilPort, pregenerate, startTarget, type Pregenerated, type TargetNode, type TargetWorld } from "../../harness/v4/chainread/target.ts";
import { buildRoles, equivalenceCheck, runVerifierOnce, runWalletOnce, type EquivalenceRow, type References, type Roles } from "../../harness/v4/chainread/series.ts";
import { decodeAggregate, encodeAggregate, installMulticall } from "../../harness/v4/chainread/contract.ts";
import { PORTS } from "../../harness/v4/lib/ports.ts";

// harness/v4/chainread on a real Anvil (docs/v4/CHAINREAD.md section 6): one v4 world, every S4
// and S5 variant once through the equivalence pre-check, the per-POST connection record, and the
// ChainReadBatch helper. Anvil binds the chain-read D-034 port of this OS (8771 on Windows, 8770
// in WSL); the test refuses to start when that port is busy (for example during a campaign).

let tn: TargetNode;
let tw: TargetWorld;
let pre: Pregenerated;
let roles: Roles;
let rows: EquivalenceRow[];
let refs: References;

beforeAll(async () => {
  expect([PORTS.chainReadAnvilWindows, PORTS.chainReadAnvilWsl]).toContain(defaultAnvilPort());
  tn = await startTarget("anvil", { port: defaultAnvilPort(), besuRpc: "http://127.0.0.1:18545", expectAnvil: null });
  tw = await buildWorld(tn.url, 2, () => undefined);
  pre = await pregenerate(tw, 2, () => undefined);
  roles = await buildRoles(tn, tw);
  const eq = await equivalenceCheck(tn, tw, pre, roles, () => undefined);
  rows = eq.rows;
  refs = eq.refs;
});

afterAll(() => {
  roles?.close();
  tw?.world.stop();
  tn?.anvil?.stop();
});

const row = (role: "verifier" | "wallet", v: string) => rows.find((r) => r.role === role && r.variant === v) as EquivalenceRow;

describe("chainread on Anvil: equivalence pre-check", () => {
  it("every variant gives the shipped decision or wallet output with the same JSON-RPC multiset", () => {
    expect(tn.endpoint).toBe("loopback, same host");
    expect(rows).toHaveLength(18);
    for (const r of rows) expect(r.ok, `${r.role} ${r.variant}: ${r.problems.join("; ")}`).toBe(true);
  });

  it("as shipped: the verifier makes 7 sequential POSTs with 14 requests (eth_chainId rides along), the wallet 16 with 32", () => {
    expect(row("verifier", "A")).toMatchObject({ posts: 7, requests: 14, depth: 7 });
    expect(row("wallet", "A")).toMatchObject({ posts: 16, requests: 32, depth: 16 });
    expect(refs.verifierRequests).toHaveLength(7);
    // variant B (the ethers option of E4's noBatchStall, on a new provider) changes timing only
    expect(row("verifier", "B")).toMatchObject({ posts: 7, requests: 14, depth: 7 });
  });

  it("staticNetwork halves the requests but not the POSTs (prediction H2, as a count)", () => {
    expect(row("verifier", "C")).toMatchObject({ posts: 7, requests: 7 });
    expect(row("wallet", "C")).toMatchObject({ posts: 16, requests: 16 });
  });

  it("concurrent plans need fewer sequential round trips; multicall aggregates the eth_calls", () => {
    for (const v of ["E", "F", "G", "H"]) {
      expect(row("verifier", v).depth).toBeLessThan(7);
      expect(row("wallet", v).depth).toBeLessThan(16);
    }
    expect(row("verifier", "G").requests).toBe(7);
    const h = row("verifier", "H");
    expect(h.multicall?.aggregates).toBe(1);
    expect(h.multicall?.subCalls).toBe(5);
    expect(h.multicall?.fallbacks).toBe(0);
    expect(h.requests).toBe(3); // one aggregate eth_call and the two eth_getLogs
    expect(row("wallet", "H").multicall?.subCalls).toBe(11);
  });
});

describe("chainread on Anvil: per-sample records", () => {
  it("TCP connections come from the trace: the shipped client reconnects after the global agent's sockets are closed", async () => {
    const A = roles.verifier.find((rv) => rv.v.id === "A");
    if (!A) throw new Error("no variant A");
    const warm = await runVerifierOnce({ tw, pre }, roles, A, 1, refs);
    expect(warm.ok, warm.problems.join("; ")).toBe(true);
    expect(warm.record["tcpConnectsUnknown"]).toBe(0);
    http.globalAgent.destroy();
    const fresh = await runVerifierOnce({ tw, pre }, roles, A, 1, refs);
    expect(fresh.ok, fresh.problems.join("; ")).toBe(true);
    expect(Number(fresh.record["tcpConnects"])).toBeGreaterThanOrEqual(1);
    expect(fresh.posts.some((p) => (p.http?.connects ?? 0) > 0)).toBe(true);
    expect(fresh.record).toMatchObject({ posts: 7, requests: 14, depth: 7, accepted: true });
  });

  it("the wallet read phase of a variant matches the reference for each holder", async () => {
    for (const id of ["A", "D", "G"]) {
      const rv = roles.wallet.find((x) => x.v.id === id);
      if (!rv) throw new Error(`no wallet variant ${id}`);
      for (const i of [0, 1]) {
        const o = await runWalletOnce({ tw, pre }, roles, rv, i, refs);
        expect(o.ok, `${id}/${i}: ${o.problems.join("; ")}`).toBe(true);
        expect(o.record["holder"]).toBe(i % tw.holders.length);
      }
    }
  });
});

describe("chainread on Anvil: ChainReadBatch", () => {
  it("returns each staticcall's result in order and reports a reverting call without stopping the others", async () => {
    const provider = new JsonRpcProvider(tn.url, Network.from(BigInt(tw.chainId)), { staticNetwork: true, cacheTimeout: -1 });
    try {
      const call = refs.verifierRequests.find((r) => r.method === "eth_call");
      const p0 = (call?.params as Array<{ to: string; data: string }>)[0];
      if (!p0) throw new Error("no eth_call among the verifier's requests");
      const direct = await provider.call({ to: p0.to, data: p0.data });
      const out = await provider.call({ to: tw.helper.address, data: encodeAggregate([{ to: p0.to, data: p0.data }, { to: p0.to, data: "0xdeadbeef" }, { to: p0.to, data: p0.data }]) });
      const dec = decodeAggregate(out);
      expect(dec.results.map((r) => r.ok)).toEqual([true, false, true]);
      expect(dec.results[0]?.data).toBe(direct);
      expect(dec.results[2]?.data).toBe(direct);
      expect(dec.blockNumber).toBeGreaterThan(0n);
    } finally {
      provider.destroy();
    }
  });

  it("the multicall transport re-sends a failed sub-call alone, so the caller sees ethers' usual error", async () => {
    const provider = new JsonRpcProvider(tn.url, Network.from(BigInt(tw.chainId)), { staticNetwork: true, batchStallTime: 0, cacheTimeout: -1 });
    const mc = installMulticall(provider, tw.helper.address, tw.registries);
    try {
      const call = refs.verifierRequests.find((r) => r.method === "eth_call");
      const p0 = (call?.params as Array<{ to: string; data: string }>)[0];
      if (!p0) throw new Error("no eth_call among the verifier's requests");
      const [good, bad] = await Promise.allSettled([provider.call({ to: p0.to, data: p0.data }), provider.call({ to: p0.to, data: "0xdeadbeef" })]);
      expect(good.status).toBe("fulfilled");
      expect(bad.status).toBe("rejected");
      expect(mc.stats()).toMatchObject({ aggregates: 1, subCalls: 2, fallbacks: 1 });
    } finally {
      mc.detach();
      provider.destroy();
    }
  });
});
