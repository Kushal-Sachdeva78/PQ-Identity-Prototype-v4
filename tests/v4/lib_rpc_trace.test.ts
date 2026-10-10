import { describe, it, expect, beforeEach, afterEach } from "vitest";
import http from "node:http";
import { Contract, FetchRequest, Interface, JsonRpcProvider, Network } from "ethers";
import {
  AS_SHIPPED_OPTIONS,
  ROUND_TRIP_DEFINITION,
  TRACE_EPOCH_NS,
  TRACE_EPOCH_UTC,
  assertAsShipped,
  assertEthers,
  attachContracts,
  connectClientLedger,
  createClientProvider,
  defineClientVariant,
  describeProvider,
  endpointLabel,
  ledgerProvider,
  maxInFlight,
  rawChainId,
  rebindLedger,
  sequentialDepth,
  summarize,
  traceConnections,
  traceOf,
  traceProvider,
  type RpcTrace,
} from "../../harness/v4/lib/rpc_trace.ts";
import { startMockRpc, closedPort, type MockRpc } from "./helpers/mock_jsonrpc.ts";

// Unit tests of the shared round-trip trace (harness/v4/lib/rpc_trace.ts) against a local mock
// JSON-RPC server (no chain): the server's own record of HTTP requests is the ground truth.

const ADDR = "0x" + "33".repeat(20);
const CALL = { to: ADDR, data: new Interface(["function minAnchorInterval() view returns (uint64)"]).encodeFunctionData("minAnchorInterval", []) };
const ADDRESSES = {
  didRegistry: "0x" + "11".repeat(20),
  accreditationRegistry: "0x" + "22".repeat(20),
  issuanceRootRegistry: ADDR,
  verifierKemRegistry: "0x" + "44".repeat(20),
};

const unbatchedStatic = defineClientVariant("unbatchedStatic", { staticNetwork: true, batchMaxCount: 1 }, "test: one POST per request");

let mock: MockRpc;
const providers: JsonRpcProvider[] = [];
const agents: http.Agent[] = [];
const keep = <T extends JsonRpcProvider>(p: T): T => {
  providers.push(p);
  return p;
};
const agent = (o: http.AgentOptions = {}): http.Agent => {
  const a = new http.Agent({ keepAlive: true, ...o });
  agents.push(a);
  return a;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

beforeEach(async () => {
  mock = await startMockRpc();
});
afterEach(async () => {
  for (const p of providers.splice(0)) p.destroy();
  for (const a of agents.splice(0)) a.destroy();
  await mock.close();
});

async function settle(...traces: RpcTrace[]): Promise<void> {
  for (let i = 0; i < 200 && traces.some((t) => t.inFlight() > 0); i++) await new Promise((r) => setTimeout(r, 5));
  // let ethers resolve the callers of the last batch
  await new Promise((r) => setTimeout(r, 20));
}

/** The trace agrees with what the server received, POST by POST. */
function expectMatchesServer(t: RpcTrace, m: MockRpc): void {
  const recs = t.records();
  const c = t.counts();
  expect(t.inFlight()).toBe(0);
  expect(recs.length).toBe(c.posts);
  // round trips: every _send call is one client POST; the server saw each one (plus any retried attempts)
  expect(c.httpAttempts).toBe(m.requests.length);
  expect(recs.filter((r) => r.ok).length).toBe(m.okPosts().length);
  const sig = (methods: string[], batch: boolean) => (batch ? "[" : "") + methods.join(",");
  expect(recs.filter((r) => r.ok).map((r) => sig(r.methods, r.batch)).sort()).toEqual(m.okPosts().map((r) => sig(r.methods, r.batch)).sort());
  // requests: payload elements, by method
  expect(c.byMethod).toEqual(m.byMethod());
  expect(c.requests).toBe(m.okPosts().reduce((s, r) => s + r.methods.length, 0));
  // bytes: request bodies as sent, response bodies after decoding
  expect(recs.reduce((s, r) => s + (r.http?.bytesOut ?? 0), 0)).toBe(m.requests.reduce((s, r) => s + r.bytesIn, 0));
  expect(recs.reduce((s, r) => s + (r.http?.bytesIn ?? 0), 0)).toBe(m.requests.reduce((s, r) => s + r.bodyBytes, 0));
  // TCP connections: every one the server accepted was attributed to exactly one attempt
  expect(c.connects).toBe(m.connections());
  expect(c.connectsUnknown).toBe(0);
  for (const r of recs) expect(r.http?.newConnection?.length).toBe(r.http?.attempts);
  expect(t.connectEvents().length).toBe(c.connects);
  // summarize() of the records gives the same counts
  const sum = summarize(recs);
  expect({ ...sum, postMs: 0, spanMs: 0, sequentialDepth: 0, maxInFlight: 0 }).toEqual({ ...c, postMs: 0, spanMs: 0, sequentialDepth: 0, maxInFlight: 0 });
}

describe("rpc_trace: definition and environment", () => {
  it("wraps ethers 6.13.4 and states one definition of a round trip", () => {
    expect(() => assertEthers()).not.toThrow();
    expect(ROUND_TRIP_DEFINITION).toMatch(/one HTTP POST = one call of the provider's _send/);
    expect(ROUND_TRIP_DEFINITION).toMatch(/network-detection eth_chainId/);
  });
});

describe("rpc_trace: POST counting against the server", () => {
  it("counts ethers' direct network detection (eth_chainId before the provider started) as one POST", async () => {
    const p = keep(createClientProvider("asShipped", mock.url));
    const t = traceProvider(p);
    const net = await p.getNetwork();
    expect(net.chainId).toBe(31337n);
    await settle(t);
    expect(mock.requests.length).toBe(1);
    expect(mock.requests[0]).toMatchObject({ batch: false, methods: ["eth_chainId"] });
    const [r] = t.records();
    expect(r).toMatchObject({ seq: 0, size: 1, batch: false, methods: ["eth_chainId"], direct: true, ok: true, rpcErrors: 0 });
    expect(r?.queueMs).toEqual([null]);
    expect(t.counts()).toMatchObject({ posts: 1, requests: 1, directPosts: 1, byMethod: { eth_chainId: 1 } });
    expectMatchesServer(t, mock);
  });

  it("as shipped: eth_chainId rides in the same batched POST as the call it checks (requests > POSTs)", async () => {
    const p = keep(createClientProvider("asShipped", mock.url));
    const t = traceProvider(p);
    await p.call(CALL);
    await p.call(CALL);
    await settle(t);
    const c = t.counts();
    expect(c.byMethod["eth_call"]).toBe(2);
    expect(c.byMethod["eth_chainId"]).toBeGreaterThanOrEqual(2);
    expect(c.requests).toBeGreaterThan(c.posts);
    const mixed = t.records().filter((r) => r.batch && r.methods.includes("eth_call") && r.methods.includes("eth_chainId"));
    expect(mixed.length).toBeGreaterThanOrEqual(1);
    expect(mock.requests.some((r) => r.batch && r.methods.includes("eth_call") && r.methods.includes("eth_chainId"))).toBe(true);
    expectMatchesServer(t, mock);
  });

  it("as shipped, concurrent calls: one JSON-RPC batch counts as one POST with several requests", async () => {
    const p = keep(createClientProvider("asShipped", mock.url));
    const t = traceProvider(p);
    await p.getBlockNumber(); // start the provider
    await settle(t);
    const m = t.mark();
    await Promise.all([p.call(CALL), p.call(CALL), p.call(CALL), p.call(CALL), p.call(CALL)]);
    await settle(t);
    const after = t.since(m);
    expect(after.reduce((s, r) => s + r.methods.filter((x) => x === "eth_call").length, 0)).toBe(5);
    expect(after.length).toBeLessThan(5);
    expect(after.some((r) => r.batch && r.size >= 5)).toBe(true);
    expectMatchesServer(t, mock);
  });

  it("staticNetwork: no eth_chainId at all, one POST per sequential call", async () => {
    const chainId = await rawChainId(mock.url);
    expect(chainId).toBe(31337);
    mock.reset();
    const p = keep(createClientProvider("staticNetwork", mock.url, { chainId }));
    const t = traceProvider(p);
    await p.call(CALL);
    await p.call(CALL);
    expect((await p.getNetwork()).chainId).toBe(31337n);
    await settle(t);
    expect(t.counts()).toMatchObject({ posts: 2, requests: 2, byMethod: { eth_call: 2 }, directPosts: 0 });
    expect(mock.byMethod()["eth_chainId"]).toBeUndefined();
    expect(t.records().every((r) => !r.batch && r.size === 1)).toBe(true);
    expectMatchesServer(t, mock);
  });

  it("noBatchStall: the trace still equals the server, whatever batching the event loop produced", async () => {
    const p = keep(createClientProvider("noBatchStall", mock.url));
    const t = traceProvider(p);
    await p.call(CALL);
    await Promise.all([p.call(CALL), p.call(CALL), p.getBlockNumber()]);
    await settle(t);
    expect(describeProvider(p).batchStallTime).toBe(0);
    expectMatchesServer(t, mock);
  });

  it("batchMaxCount 1: concurrent requests become concurrent single POSTs (depth 1); awaited ones are sequential", async () => {
    const slow = await startMockRpc({ delayMs: 40 });
    try {
      const p = keep(createClientProvider(unbatchedStatic, slow.url, { chainId: 31337 }));
      const t = traceProvider(p);
      await Promise.all([p.call(CALL), p.call(CALL), p.call(CALL), p.call(CALL)]);
      await settle(t);
      const conc = t.drain();
      expect(conc.length).toBe(4);
      expect(conc.every((r) => r.size === 1 && !r.batch)).toBe(true);
      expect(maxInFlight(conc)).toBeGreaterThanOrEqual(2);
      expect(sequentialDepth(conc)).toBeLessThan(4);
      for (let i = 0; i < 3; i++) await p.call(CALL);
      await settle(t);
      const seq = t.drain();
      expect(seq.length).toBe(3);
      expect(sequentialDepth(seq)).toBe(3);
      expect(maxInFlight(seq)).toBe(1);
      expect(t.counts().posts).toBe(7);
      expect(t.counts().httpAttempts).toBe(slow.requests.length);
    } finally {
      await slow.close();
    }
  });

  it("an HTTP 429 retried inside one _send is one round trip with two HTTP attempts", async () => {
    const p = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337 }));
    const t = traceProvider(p);
    mock.failNext(429);
    expect(await p.send("eth_blockNumber", [])).toBe("0x2a");
    await settle(t);
    expect(mock.requests.map((r) => r.status)).toEqual([429, 200]);
    const [r] = t.records();
    expect(t.records().length).toBe(1);
    expect(r).toMatchObject({ ok: true, size: 1, methods: ["eth_blockNumber"] });
    expect(r?.http).toMatchObject({ attempts: 2, statuses: [429, 200] });
    expect(t.counts()).toMatchObject({ posts: 1, httpAttempts: 2 });
    expectMatchesServer(t, mock);
  });

  it("a JSON-RPC error inside a successful POST is counted as an rpc error, not a failed POST", async () => {
    const p = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337 }));
    const t = traceProvider(p);
    await expect(p.send("pqid_noSuchMethod", [])).rejects.toThrow();
    await settle(t);
    expect(t.records()[0]).toMatchObject({ ok: true, rpcErrors: 1, error: null });
    expect(t.counts()).toMatchObject({ posts: 1, failedPosts: 0, rpcErrors: 1 });
    expectMatchesServer(t, mock);
  });

  it("a POST that fails in transport is recorded as failed, with the endpoint redacted", async () => {
    const port = await closedPort();
    const url = `http://127.0.0.1:${port}`;
    const raw = (p: JsonRpcProvider) => (p as unknown as { _send: (x: unknown) => Promise<unknown> })._send.bind(p);
    const payload = { jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] };

    // ECONNREFUSED names "127.0.0.1:<port>" (not the URL): the provider's host:port is redacted by default
    const p = keep(createClientProvider("staticNetwork", url, { chainId: 31337 }));
    const t = traceProvider(p);
    await expect(raw(p)(payload)).rejects.toBeTruthy();
    const [r] = t.records();
    expect(r).toMatchObject({ ok: false, direct: true, size: 1 });
    expect(r?.http?.attempts).toBe(1);
    expect(r?.http?.statuses).toEqual([]);
    expect(r?.http?.newConnection).toEqual([true]);
    expect(t.connectEvents()[0]).toMatchObject({ postSeq: 0, attempt: 0, ok: false, tConnectedMs: null });
    expect(r?.error).toMatch(/ECONNREFUSED/);
    expect(r?.error).not.toContain(`127.0.0.1:${port}`);
    expect(r?.error).toContain("<rpc-url>");
    expect(t.counts()).toMatchObject({ posts: 1, failedPosts: 1, connects: 1 });

    // an extra string given by the caller is redacted too
    const p2 = keep(createClientProvider("staticNetwork", url, { chainId: 31337 }));
    const t2 = traceProvider(p2, { redact: ["ECONNREFUSED"] });
    await expect(raw(p2)(payload)).rejects.toBeTruthy();
    expect(t2.records()[0]?.error).not.toMatch(/ECONNREFUSED/);

    // an error text that carries the full provider URL
    const req = new FetchRequest(mock.url + "/rpc-secret-path");
    req.getUrlFunc = async (r2: FetchRequest) => {
      throw new Error(`cannot reach ${r2.url}`);
    };
    const p3 = keep(new JsonRpcProvider(req, Network.from(31337n), { staticNetwork: true }));
    const t3 = traceProvider(p3);
    await expect(raw(p3)(payload)).rejects.toBeTruthy();
    const e3 = t3.records()[0]?.error ?? "";
    expect(e3).toContain("cannot reach <rpc-url>");
    expect(e3).not.toContain("rpc-secret-path");
    expect(e3).not.toContain(String(mock.port));
  }, 30_000);

  it("a 301/302 answer to a POST is not followed: one attempt, failed POST", async () => {
    const p = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337 }));
    const t = traceProvider(p);
    mock.failNext(302);
    await expect(p.send("eth_blockNumber", [])).rejects.toBeTruthy();
    await settle(t);
    expect(mock.requests.map((r) => r.status)).toEqual([302]);
    expect(t.records()[0]).toMatchObject({ ok: false, size: 1 });
    expect(t.records()[0]?.http).toMatchObject({ attempts: 1, statuses: [302] });
    expect(t.counts()).toMatchObject({ posts: 1, failedPosts: 1, httpAttempts: 1 });
    expect(ROUND_TRIP_DEFINITION).toMatch(/301\/302 is not followed for a POST/);
  });

  it("bytesIn is the response body after content decoding; the Content-Encoding is recorded", async () => {
    const gz = await startMockRpc({ gzip: true });
    try {
      const p = keep(createClientProvider("staticNetwork", gz.url, { chainId: 31337 }));
      const t = traceProvider(p);
      expect(await p.call(CALL)).toMatch(/^0x0+e10$/);
      await settle(t);
      const r = t.records()[0];
      expect(r?.http?.contentEncoding).toEqual(["gzip"]);
      expect(r?.http?.bytesIn).toBe(gz.requests[0]?.bodyBytes);
      expect(r?.http?.bytesIn).not.toBe(gz.requests[0]?.bytesOut);
      expectMatchesServer(t, gz);
    } finally {
      await gz.close();
    }
  });

  it("stamps queue delay: requests wait for the 10 ms batching stall; direct detection has none", async () => {
    const p = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337 }));
    const t = traceProvider(p);
    await p.call(CALL);
    await settle(t);
    const q = t.records()[0]?.queueMs[0];
    expect(q).not.toBeNull();
    expect(q as number).toBeGreaterThanOrEqual(5);
    const r = t.records()[0];
    expect(r?.tEndMs).toBeGreaterThanOrEqual(r?.tStartMs as number);
    expect(r?.ms).toBeCloseTo((r?.tEndMs as number) - (r?.tStartMs as number), 6);
    expect(r?.http?.contentEncoding).toEqual([null]);
  });
});

describe("rpc_trace: TCP connections per POST", () => {
  it("the first POST opens a connection, kept-alive POSTs reuse it (dedicated agent)", async () => {
    const p = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337, agent: agent() }));
    const t = traceProvider(p);
    for (let i = 0; i < 3; i++) await p.call(CALL);
    await settle(t);
    const recs = [...t.records()].sort((a, b) => a.seq - b.seq);
    expect(recs.map((r) => r.http?.connects)).toEqual([1, 0, 0]);
    expect(recs.map((r) => r.http?.newConnection)).toEqual([[true], [false], [false]]);
    const [ev] = t.connectEvents();
    expect(ev).toMatchObject({ postSeq: 0, attempt: 0, ok: true });
    expect(ev?.tConnectedMs as number).toBeGreaterThanOrEqual(ev?.tStartMs as number);
    expect(ev?.tStartMs as number).toBeGreaterThanOrEqual(recs[0]?.tStartMs as number);
    expect(mock.connections()).toBe(1);
    expect(summarize(recs).connects).toBe(1);
    expectMatchesServer(t, mock);
  });

  it("an idle gap longer than the agent's keep-alive timeout reconnects: the POST after the gap shows 1", async () => {
    const p = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337, agent: agent({ timeout: 200 }) }));
    const t = traceProvider(p);
    await p.call(CALL);
    await p.call(CALL);
    await sleep(400);
    const m = t.mark();
    await p.call(CALL);
    await settle(t);
    expect([...t.records()].sort((a, b) => a.seq - b.seq).map((r) => r.http?.connects)).toEqual([1, 0, 1]);
    expect(t.connectEvents(m).map((e) => e.postSeq)).toEqual([2]);
    expect(mock.connections()).toBe(2);
    expectMatchesServer(t, mock);
  });

  it("as shipped (Node's global agent) and with an agent swapped in as http.globalAgent, as the end-to-end runs do", async () => {
    const p = keep(createClientProvider("asShipped", mock.url));
    const t = traceProvider(p);
    await p.call(CALL);
    await p.call(CALL);
    await settle(t);
    expect(t.counts().connects).toBe(1);
    const original = http.globalAgent;
    const swapped = agent();
    try {
      (http as unknown as { globalAgent: http.Agent }).globalAgent = swapped;
      const m = t.mark();
      await p.call(CALL);
      await settle(t);
      expect(summarize(t.since(m)).connects).toBe(1);
    } finally {
      (http as unknown as { globalAgent: http.Agent }).globalAgent = original;
    }
    expect(t.counts().connects).toBe(2);
    expectMatchesServer(t, mock);
  });

  it("traceConnections records every new client socket of the process (any agent), with port and loopback", async () => {
    const rec = traceConnections();
    try {
      const p = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337, agent: agent() }));
      await p.call(CALL);
      await p.call(CALL);
      await sleep(20);
      expect(rec.count(mock.port)).toBe(1);
      const ev = rec.events().find((e) => e.port === mock.port);
      expect(ev).toMatchObject({ ok: true, loopback: true });
      expect(ev?.tConnectedMs as number).toBeGreaterThanOrEqual(ev?.tMs as number);
      // a refused connection: port from the connection attempt, ok false once the socket closed
      const shut = await closedPort();
      const pf = keep(createClientProvider("staticNetwork", `http://127.0.0.1:${shut}`, { chainId: 31337, agent: agent() }));
      const rawSend = (pf as unknown as { _send: (x: unknown) => Promise<unknown> })._send.bind(pf);
      await expect(rawSend({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] })).rejects.toBeTruthy();
      await sleep(50);
      expect(rec.events().find((e) => e.port === shut)).toMatchObject({ ok: false, loopback: true, tConnectedMs: null });
    } finally {
      rec.stop();
    }
    const p2 = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337, agent: agent() }));
    await p2.call(CALL);
    await sleep(20);
    expect(rec.count(mock.port)).toBe(1);
    expect(mock.connections()).toBe(2);
  });
});

describe("rpc_trace: trace life cycle", () => {
  it("labels, marks, drain and reset; the epoch has a UTC anchor", async () => {
    const p = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337 }));
    const t = traceProvider(p, { label: "a" });
    expect(t.epochNs).toBe(TRACE_EPOCH_NS);
    expect(t.epochUtc).toBe(TRACE_EPOCH_UTC);
    expect(Date.parse(t.epochUtc)).toBeLessThanOrEqual(Date.now());
    await p.call(CALL);
    t.setLabel("b");
    const m = t.mark();
    await p.call(CALL);
    await settle(t);
    expect(t.records().map((r) => r.label)).toEqual(["a", "b"]);
    expect(t.since(m).map((r) => r.label)).toEqual(["b"]);
    expect(t.drain().length).toBe(2);
    expect(t.records().length).toBe(0);
    expect(t.counts().posts).toBe(2);
    t.reset();
    expect(t.counts().posts).toBe(0);
  });

  it("refuses to trace a provider twice; detach restores the provider's own methods", async () => {
    const p = keep(createClientProvider("asShipped", mock.url));
    const t = traceProvider(p);
    expect(traceOf(p)).toBe(t);
    expect(() => traceProvider(p)).toThrow(/already traced/);
    expect(Object.prototype.hasOwnProperty.call(p, "_send")).toBe(true);
    t.detach();
    expect(traceOf(p)).toBeNull();
    for (const k of ["send", "_send", "_getConnection"]) expect(Object.prototype.hasOwnProperty.call(p, k)).toBe(false);
    await p.getBlockNumber();
    await new Promise((r) => setTimeout(r, 30));
    expect(mock.requests.length).toBeGreaterThanOrEqual(1);
    expect(t.counts().posts).toBe(0);
    mock.reset();
    const t2 = traceProvider(p);
    await p.getBlockNumber();
    await settle(t2);
    expect(t2.counts().posts).toBeGreaterThanOrEqual(1);
    expectMatchesServer(t2, mock);
  });

  it("keepRecords false keeps counts only", async () => {
    const p = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337 }));
    const t = traceProvider(p, { keepRecords: false });
    await p.call(CALL);
    await settle(t);
    expect(t.records().length).toBe(0);
    expect(t.counts()).toMatchObject({ posts: 1, requests: 1 });
  });
});

describe("rpc_trace: client factories", () => {
  it("asShipped has exactly the options of ledger.ts makeProvider; variants do not", () => {
    const shipped = keep(createClientProvider("asShipped", mock.url));
    expect(describeProvider(shipped)).toEqual(AS_SHIPPED_OPTIONS);
    expect(() => assertAsShipped(shipped)).not.toThrow();
    const st = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337 }));
    expect(describeProvider(st)).toEqual({ ...AS_SHIPPED_OPTIONS, staticNetwork: true });
    expect(() => assertAsShipped(st)).toThrow(/staticNetwork/);
    const ns = keep(createClientProvider("noBatchStall", mock.url));
    expect(describeProvider(ns)).toEqual({ ...AS_SHIPPED_OPTIONS, batchStallTime: 0 });
    expect(() => createClientProvider("staticNetwork", mock.url)).toThrow(/chain id/);
    expect(() => defineClientVariant("asShipped", {}, "x")).toThrow();
  });

  it("labels endpoints as D-034 asks (loopback, same host)", () => {
    for (const u of ["http://127.0.0.1:8770", "http://localhost:8790", "http://[::1]:8545", "http://127.1.2.3/"]) expect(endpointLabel(u)).toBe("loopback, same host");
    for (const u of ["https://rpc.example.org/v1/key", "http://10.0.0.5:8545", "not a url"]) expect(endpointLabel(u)).toBe("remote");
  });
});

describe("rpc_trace: attaching to LedgerV4 and contract sets (packages unchanged)", () => {
  it("LedgerV4.connect builds the shipped client; rebindLedger routes every read through another provider; restore puts it back", async () => {
    const { LedgerV4 } = await import("@pqid/v4/ledger");
    const ledger = await LedgerV4.connect(mock.url, ADDRESSES);
    try {
      const shipped = ledgerProvider(ledger);
      assertAsShipped(shipped);
      const t0 = traceProvider(shipped);
      const vp = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337 }));
      const tv = traceProvider(vp);
      const h = rebindLedger(ledger, vp);
      expect(h.previous).toBe(shipped);
      expect(ledgerProvider(ledger)).toBe(vp);
      expect(ledger.devDeployerSigner().provider).toBe(vp);
      expect(await ledger.getMinAnchorInterval()).toBe(3600);
      expect(await ledger.chainId()).toBe(31337);
      await settle(t0, tv);
      expect(t0.counts().posts).toBe(0);
      expect(tv.counts().byMethod).toEqual({ eth_call: 1 });
      expect(mock.requests.flatMap((r) => r.callTargets).filter((x) => x !== null)).toEqual([ADDR]);
      expectMatchesServer(tv, mock);

      h.restore();
      expect(ledgerProvider(ledger)).toBe(shipped);
      expect(await ledger.getMaxWindow()).toBe(3600);
      await settle(t0, tv);
      expect(t0.counts().byMethod["eth_call"]).toBe(1);
      expect(t0.counts().byMethod["eth_chainId"]).toBeGreaterThanOrEqual(1);
      expect(tv.counts().byMethod).toEqual({ eth_call: 1 });
      expect(() => rebindLedger(ledger, keep(createClientProvider("noBatchStall", "http://127.0.0.1:1")))).toThrow(/another URL/);
    } finally {
      ledger.destroy();
    }
  });

  it("connectClientLedger gives a traced ledger per variant", async () => {
    const a = await connectClientLedger(mock.url, ADDRESSES, 0, "asShipped", { trace: true });
    const b = await connectClientLedger(mock.url, ADDRESSES, 0, "noBatchStall", { trace: { label: "nb" } });
    try {
      expect(a.options).toEqual(AS_SHIPPED_OPTIONS);
      expect(a.spec.label).toBe("as shipped");
      expect(a.endpoint).toBe("loopback, same host");
      expect(a.traced).toBe(true);
      expect(a.chainIdCheckedAgainstNode).toBeNull();
      expect(b.options.batchStallTime).toBe(0);
      expect(b.spec.label).toBe("variant, not shipped");
      expect(await a.ledger.getMinAnchorInterval()).toBe(3600);
      expect(await b.ledger.getMinAnchorInterval()).toBe(3600);
      await settle(a.trace as RpcTrace, b.trace as RpcTrace);
      expect(a.trace?.counts().byMethod["eth_call"]).toBe(1);
      expect(b.trace?.counts().byMethod["eth_call"]).toBe(1);
      expect(b.trace?.records().every((r) => r.label === "nb")).toBe(true);
      const both = (a.trace?.counts().httpAttempts ?? 0) + (b.trace?.counts().httpAttempts ?? 0);
      expect(both).toBe(mock.requests.length);
      expect((a.trace?.counts().connects ?? 0) + (b.trace?.counts().connects ?? 0)).toBe(mock.connections());
      a.trace?.detach();
      expect(a.traced).toBe(false);
    } finally {
      a.ledger.destroy();
      b.ledger.destroy();
    }
  });

  it("staticNetwork: the given chain id is checked against the node before connecting", async () => {
    await expect(connectClientLedger(mock.url, ADDRESSES, 0, "staticNetwork", { chainId: 1 })).rejects.toThrow(/differs from the node's eth_chainId 31337/);
    const ok = await connectClientLedger(mock.url, ADDRESSES, 0, "staticNetwork", { chainId: 31337, trace: true });
    const unchecked = await connectClientLedger(mock.url, ADDRESSES, 0, "staticNetwork", { chainId: 31337, checkChainId: false });
    try {
      expect(ok.chainIdCheckedAgainstNode).toBe(true);
      expect(unchecked.chainIdCheckedAgainstNode).toBe(false);
      expect(unchecked.traced).toBe(false);
      expect(await ok.ledger.chainId()).toBe(31337);
      await settle(ok.trace as RpcTrace);
      // the check is a raw request outside the trace
      expect(ok.trace?.counts().posts).toBe(0);
    } finally {
      ok.ledger.destroy();
      unchecked.ledger.destroy();
    }
  });

  it("attachContracts moves a contract set onto a traced provider", async () => {
    const plain = keep(createClientProvider("asShipped", mock.url));
    const set = { irr: new Contract(ADDR, ["function minAnchorInterval() view returns (uint64)"], plain) };
    const vp = keep(createClientProvider("staticNetwork", mock.url, { chainId: 31337 }));
    const t = traceProvider(vp);
    const moved = attachContracts(set, vp);
    expect(await moved.irr.getFunction("minAnchorInterval")()).toBe(3600n);
    await settle(t);
    expect(t.counts().byMethod).toEqual({ eth_call: 1 });
    expectMatchesServer(t, mock);
  });
});

describe("rpc_trace: interval helpers", () => {
  const iv = (a: number, b: number) => ({ tStartMs: a, tEndMs: b });
  it("sequentialDepth is the longest chain of non-overlapping POSTs (an upper bound on dependent round trips)", () => {
    expect(sequentialDepth([])).toBe(0);
    expect(sequentialDepth([iv(0, 1), iv(1, 2), iv(2, 3)])).toBe(3);
    expect(sequentialDepth([iv(0, 5), iv(1, 5), iv(2, 5)])).toBe(1);
    expect(sequentialDepth([iv(0, 1), iv(1.5, 2), iv(0.5, 3)])).toBe(2);
    expect(sequentialDepth([iv(0, 10), iv(0, 1), iv(2, 3), iv(4, 5)])).toBe(3);
  });
  it("maxInFlight counts overlap; touching intervals do not overlap", () => {
    expect(maxInFlight([iv(0, 1), iv(1, 2)])).toBe(1);
    expect(maxInFlight([iv(0, 3), iv(1, 2), iv(1.5, 4)])).toBe(3);
  });
});
