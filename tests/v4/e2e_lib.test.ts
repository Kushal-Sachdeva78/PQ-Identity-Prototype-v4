import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect } from "vitest";
import { buildSchedule } from "../../harness/v4/bench/lib.ts";
import { SEEDS, USED_SEEDS } from "../../harness/v4/lib/seeds.ts";
import { PORTS } from "../../harness/v4/lib/ports.ts";
import { endpointLabel } from "../../harness/v4/lib/rpc_trace.ts";
import {
  E2E_ANVIL_PORT,
  E2E_RESULTS_REL,
  E2E_SEED,
  REPO_ROOT,
  STAGE_IDS,
  applyColdDefinition,
  campaignConditions,
  checkKeySpec,
  checkMarks,
  classifyUrl,
  clockGap,
  compactGc,
  compactPost,
  computeReport,
  crossesBlackout,
  cpuFamilyOf,
  e2eSchedule,
  emulationSuspected,
  endToEndOf,
  estimateSetupCost,
  findSecrets,
  gcKindName,
  idleFields,
  keySpecFromJson,
  loadKeySpec,
  midnightBlackout,
  parseCondition,
  parseMsgLines,
  rawWriteGasLimit,
  reachLabel,
  recordOuterCalls,
  redactSecrets,
  resolveRoot,
  resolveRpcArg,
  resultsRootRefusal,
  roleGasBudgets,
  runLabels,
  secretNeedles,
  stageAt,
  stageWindows,
  stateDocErrors,
  stateDocNeedles,
  urlCarriesNoSecret,
  urlNeedles,
  SETUP_GAS,
  MSG_PREFIX,
  type E2eStateDoc,
  type GcEvent,
  type HookEvent,
  type LedgerCall,
  type Marks,
  type PartyPost,
} from "../../harness/v4/e2e/lib.ts";

// A synthetic presentation timeline (ms): every stage has a known length.
const MARKS: Marks = {
  s1Start: 100,
  s1End: 110, // S1 10
  s2Start: 111, // agent switch 1
  s2End: 112, // S2 1
  checkRequestEnd: 162, // S3 50
  issuerStart: 164, // S4 2
  issuerEnd: 244, // S5 80
  inputMark: 254, // S7 window 10 (S6 inside)
  sealMark: 1254, // S8 1000
  presentEnd: 1255, // S9 1
  s10Start: 1257, // agent switch 2
  s10End: 1258, // S10 1
  s11End: 1358, // S11 100
};

function post(party: "verifier" | "wallet", t: number, ms: number, methods: string[], extra: Partial<PartyPost> = {}): PartyPost {
  return {
    party,
    seq: 0,
    label: party,
    tStartMs: t,
    tEndMs: t + ms,
    ms,
    size: methods.length,
    batch: methods.length > 1,
    methods,
    queueMs: methods.map(() => 1),
    direct: false,
    ok: true,
    rpcErrors: 0,
    error: null,
    http: { attempts: 1, statuses: [200], ms: ms - 0.5, bytesOut: 100, bytesIn: 200 },
    ...extra,
  };
}

describe("e2e stage accounting", () => {
  it("windows are contiguous inside the wallet and the stages add up to endToEnd", () => {
    const w = stageWindows(MARKS);
    expect(w.map((x) => x.id)).toEqual(["S1", "S2", "S3", "S4", "S5", "S7", "S8", "S9", "S10", "S11"]);
    for (let i = 2; i < 8; i++) expect(w[i]!.start).toBe(w[i - 1]!.end);
    const { endToEndMs, agentSwitchMs } = endToEndOf(MARKS);
    expect(agentSwitchMs).toBe(3);
    expect(endToEndMs).toBe(1258 - 3);
    const sum = w.reduce((a, x) => a + (x.end - x.start), 0);
    expect(sum).toBe(endToEndMs);
    expect(stageAt(w, 110.5)).toBeNull(); // inside the first agent switch
    expect(stageAt(w, 1254)).toBe("S9"); // the seal starts exactly at the S9 start
    expect(stageAt(w, 1358)).toBeNull(); // end of S11 is exclusive
  });

  it("checkMarks refuses missing or out-of-order marks", () => {
    const { inputMark: _x, ...missing } = MARKS;
    expect(() => checkMarks(missing)).toThrow(/inputMark missing/);
    expect(() => checkMarks({ ...MARKS, sealMark: 200 })).toThrow(/before the previous mark/);
    expect(() => checkMarks(MARKS)).not.toThrow();
  });

  it("attributes POSTs, ledger calls and crypto events to stages; S6 is carved out of the S7 window", () => {
    const posts: PartyPost[] = [
      post("verifier", 101, 5, ["eth_chainId"], { direct: true, batch: false, http: { attempts: 1, statuses: [200], ms: 4, bytesOut: 50, bytesIn: 60, connects: 1, newConnection: [true] } }),
      post("wallet", 120, 3, ["eth_chainId", "eth_call"], { http: { attempts: 1, statuses: [200], ms: 2, bytesOut: 50, bytesIn: 60, connects: 1, newConnection: [true] } }),
      post("wallet", 130, 4, ["eth_call"]),
      post("wallet", 170, 6, ["eth_call", "eth_chainId"], { http: { attempts: 2, statuses: [429, 200], ms: 5, bytesOut: 10, bytesIn: 20, connects: 0, newConnection: [false, null] } }),
      post("verifier", 1270, 8, ["eth_getLogs"], { ok: false, rpcErrors: 1 }),
      post("verifier", 1400, 2, ["eth_blockNumber"]), // after S11: outside
    ];
    const calls: LedgerCall[] = [
      { party: "verifier", method: "chainId", start: 101, end: 106, ok: true },
      { party: "wallet", method: "resolveDidRecord", start: 119, end: 140, ok: true },
      { party: "wallet", method: "latestAccreditation", start: 169, end: 180, ok: true },
      { party: "verifier", method: "resolveDidRecord", start: 1265, end: 1290, ok: true },
    ];
    const events: HookEvent[] = [
      { kind: "mlDsaVerify", start: 150, end: 151 },
      { kind: "mlDsaImport", start: 149, end: 149.5 },
      { kind: "mlDsaVerify", start: 163, end: 163.5 }, // S4: credential signature
      { kind: "mlKemEncaps", start: 246, end: 246.25 },
      { kind: "aesGcmCipher", start: 1254, end: 1254.1 },
      { kind: "mlKemDecaps", start: 1259, end: 1259.5 },
      { kind: "mlDsaVerify", start: 1300, end: 1302 },
    ];
    const r = computeReport(MARKS, events, calls, posts);
    expect(r.stages.S1.posts).toBe(1);
    expect(r.stages.S1.postsByParty.verifier).toBe(1);
    expect(r.stages.S3.posts).toBe(2);
    expect(r.stages.S3.requests).toBe(3);
    expect(r.stages.S3.byMethod).toEqual({ eth_chainId: 1, eth_call: 2 });
    expect(r.stages.S3.batchPosts).toBe(1);
    expect(r.stages.S5.http429).toBe(1);
    expect(r.stages.S5.httpAttempts).toBe(2);
    expect(r.stages.S11.failedPosts).toBe(1);
    expect(r.stages.S11.rpcErrors).toBe(1);
    expect(r.outside.posts).toBe(1);
    expect(r.totals.posts).toBe(6);
    expect(r.totals.postsByParty).toEqual({ verifier: 3, wallet: 3 });
    expect(r.totals.http429).toBe(1);
    expect(r.stages.S3.ledgerCalls).toEqual({ resolveDidRecord: 1 });
    expect(r.stages.S3.ledgerMs).toBe(21);
    expect(r.stages.S3.mlDsaVerify).toBe(1);
    expect(r.stages.S3.mlDsaImport).toBe(1);
    expect(r.stages.S4.mlDsaVerify).toBe(1);
    // S6 = encapsulate time; S7 = window minus S6
    expect(r.stages.S6.ms).toBe(0.25);
    expect(r.stages.S7.ms).toBe(9.75);
    expect(r.stages.S8.ms).toBe(1000);
    expect(r.s7s8Ms).toBe(1009.75); // the coarse split that does not depend on the input mark
    // S11 split: chain 25, ML-DSA 2, decaps 0.5, other by subtraction
    expect(r.verifySplit).toEqual({ chainMs: 25, mlDsaMs: 2, mlKemDecapsMs: 0.5, otherMs: 72.5 });
    expect(r.walletChecksSplit.chainMs).toBe(21 + 11);
    const stageSum = STAGE_IDS.reduce((a, id) => a + r.stages[id].ms, 0);
    expect(Math.abs(stageSum - r.endToEndMs)).toBeLessThan(1e-9);
    // new TCP connections per stage and party (rpc_trace per-attempt attribution)
    expect(r.stages.S1.connects).toBe(1);
    expect(r.stages.S3.connects).toBe(1);
    expect(r.stages.S5.connects).toBe(0);
    expect(r.stages.S5.connectsUnknown).toBe(1);
    expect(r.totals.connectsByParty).toEqual({ verifier: 1, wallet: 1 });
    expect(r.totals.connectsUnknown).toBe(1);
    // the compact record keeps the attribution, not the payload
    const c = compactPost(posts[3] as PartyPost, stageWindows(MARKS));
    expect(c["stage"]).toBe("S5");
    expect((c["http"] as Record<string, unknown>)["newConnection"]).toEqual([false, null]);
    expect(JSON.stringify(c)).not.toContain("params");
  });

  it("recordOuterCalls counts an inner read once, in the outer call, and records failures", async () => {
    let t = 0;
    const now = () => ++t;
    const target = {
      async resolveDidRecord() {
        return 1;
      },
      async getPopSignature(this: { resolveDidRecord(): Promise<number> }) {
        return (await this.resolveDidRecord()) + 1;
      },
      async latestKemKey() {
        throw new Error("boom");
      },
      notARead: 5,
    };
    const sink: LedgerCall[] = [];
    const p = recordOuterCalls(target, "wallet", ["resolveDidRecord", "getPopSignature", "latestKemKey"], sink, now);
    expect(await p.getPopSignature()).toBe(2);
    await expect(p.latestKemKey()).rejects.toThrow("boom");
    expect(p.notARead).toBe(5);
    expect(sink.map((c) => [c.method, c.ok])).toEqual([
      ["getPopSignature", true],
      ["latestKemKey", false],
    ]);
  });
});

describe("e2e garbage collection bookkeeping", () => {
  it("attributes collections to the stage they start in; ignores those outside S1 start to S11 end", () => {
    const gc: GcEvent[] = [
      { start: 90, ms: 3, kind: "minor" }, // before S1: ignored
      { start: 105, ms: 1, kind: "minor" }, // S1
      { start: 110.5, ms: 0.25, kind: "minor" }, // agent switch: counted, outside every window
      { start: 600, ms: 12, kind: "major" }, // S8
      { start: 700, ms: 2, kind: "minor" }, // S8
      { start: 1300, ms: 4, kind: "incremental" }, // S11
      { start: 1358, ms: 9, kind: "major" }, // at the S11 end: ignored
    ];
    const r = computeReport(MARKS, [], [], [], gc);
    expect(r.stages.S1.gcCount).toBe(1);
    expect(r.stages.S8.gcCount).toBe(2);
    expect(r.stages.S8.gcMs).toBe(14);
    expect(r.stages.S11.gcMs).toBe(4);
    expect(r.stages.S3.gcCount).toBe(0);
    expect(r.gcTotals).toEqual({ count: 5, ms: 19.25, majorCount: 1, majorMs: 12, outsideWindows: 1 });
    // the stage accounting itself is unchanged by collections
    expect(computeReport(MARKS, [], [], []).stages.S8.ms).toBe(r.stages.S8.ms);
    expect(compactGc(gc, MARKS).map((x) => x.stage)).toEqual(["S1", null, "S8", "S8", "S11"]);
    expect([gcKindName(1), gcKindName(4), gcKindName(8), gcKindName(16), gcKindName(99)]).toEqual(["minor", "major", "incremental", "weakcb", "99"]);
  });
});

describe("e2e schedule, seeds and ports", () => {
  it("uses the registered D-034 seed itself (no derived or ad-hoc seed) and the D-034 port", () => {
    expect(E2E_SEED).toBe(20261031);
    expect(E2E_SEED).toBe(SEEDS.endToEnd.order);
    expect(Object.values(USED_SEEDS)).not.toContain(E2E_SEED);
    expect(E2E_ANVIL_PORT).toBe(8790);
    expect(E2E_ANVIL_PORT).toBe(PORTS.endToEnd);
  });

  it("cold: every block holds every endpoint once; warm: controls included and warm-up blocks negative", () => {
    const cold = e2eSchedule("cold", ["anvil", "besu"], 30, 0);
    expect(cold.seed).toBe(20261031);
    expect(cold.slots.length).toBe(60);
    for (let b = 0; b < 30; b++) expect(cold.slots.filter((s) => s.block === b).map((s) => s.condition).sort()).toEqual(["anvil", "besu"]);
    expect(e2eSchedule("cold", ["anvil", "besu"], 30, 0).slots).toEqual(cold.slots);
    // exactly the bench lib schedule with the registered seed (reproducible from schedule.json)
    expect(cold.slots).toEqual(buildSchedule(["anvil", "besu"], 30, 20261031));
    const warm = e2eSchedule("warm", ["anvil", "besu"], 30, 5);
    expect(warm.slots).toEqual(buildSchedule(["anvil", "besu", "anvil:control", "besu:control"], 35, 20261031, -5));
    expect(warm.slots.length).toBe(35 * 4);
    expect(Math.min(...warm.slots.map((s) => s.block))).toBe(-5);
    expect(campaignConditions("warm", ["anvil"])).toEqual(["anvil", "anvil:control"]);
    expect(parseCondition("besu:control")).toEqual({ endpoint: "besu", control: true });
    expect(parseCondition("custom")).toEqual({ endpoint: "custom", control: false });
  });
});

describe("e2e clocks", () => {
  it("flags a host pause when the wall clock runs ahead of the monotonic clock", () => {
    const a = { mono: 1000, wall: 1_700_000_000_000, uptime: null };
    expect(clockGap(a, { mono: 601_000, wall: 1_700_000_600_400, uptime: null }, 5).hostPauseSuspected).toBe(false);
    const g = clockGap(a, { mono: 601_000, wall: 1_700_000_636_600, uptime: null }, 5);
    expect(g.clockGapSec).toBeCloseTo(36.6, 6);
    expect(g.hostPauseSuspected).toBe(true);
    // the flat fields named as in the comparable-benchmark series (docs/v4/CMP.md)
    expect(idleFields(g)).toEqual({ idleSec: 600, idleWallSec: 636.6, clockGapSec: 36.6, hostPauseSuspected: true });
  });

  it("UTC midnight black-out from 23:50 to 00:10", () => {
    const day = Date.UTC(2026, 9, 1);
    const at = (h: number, m: number) => day + (h * 60 + m) * 60_000;
    expect(midnightBlackout(at(23, 49)).inside).toBe(false);
    expect(midnightBlackout(at(23, 55))).toEqual({ inside: true, endsAtMs: day + 86_400_000 + 600_000 });
    expect(midnightBlackout(at(0, 5))).toEqual({ inside: true, endsAtMs: day + 600_000 });
    expect(midnightBlackout(at(0, 11)).inside).toBe(false);
    expect(crossesBlackout(at(23, 40), 5 * 60_000)).toBe(false);
    expect(crossesBlackout(at(23, 40), 11 * 60_000)).toBe(true);
  });
});

describe("e2e secrets and endpoints", () => {
  const url = "https://eth-sepolia.example-provider.io/v2/AbCdEf0123456789XYZ?apikey=QwErTy987654321&x=1";

  it("finds the URL, its API-key path segment and query value; redacts them", () => {
    const n = urlNeedles(url);
    const vals = n.map((x) => x.value);
    expect(vals).toContain(url);
    expect(vals).toContain("AbCdEf0123456789XYZ");
    expect(vals).toContain("QwErTy987654321");
    expect(vals).not.toContain("1");
    expect(findSecrets(`{"error":"failed at https://x/v2/AbCdEf0123456789XYZ"}`, n)).toEqual(["rpcUrl:path"]);
    expect(findSecrets(`{"ok":true}`, n)).toEqual([]);
    expect(redactSecrets(`bad response from ${url}`, n)).not.toContain("AbCdEf0123456789XYZ");
    const long = "ab".repeat(100);
    expect(secretNeedles("k", long).map((x) => x.name)).toEqual(["k", "k:tail"]);
    expect(findSecrets(`...${long.slice(-40)}`, secretNeedles("k", long))).toEqual(["k:tail"]);
  });

  it("an API key in the host name is a needle; loopback, LAN and IP hosts are not", () => {
    const keyed = "https://k3y0123456789abcdef.provider.example";
    const n = urlNeedles(keyed);
    expect(n.map((x) => x.name)).toEqual(expect.arrayContaining(["rpcUrl:host", "rpcUrl:hostLabel"]));
    const err = "getaddrinfo ENOTFOUND k3y0123456789abcdef.provider.example";
    expect(findSecrets(err, n)).toEqual(expect.arrayContaining(["rpcUrl:host", "rpcUrl:hostLabel"]));
    expect(redactSecrets(err, n)).not.toContain("k3y0123456789abcdef");
    expect(findSecrets("label sepolia-a", n)).toEqual([]);
    for (const u of ["http://127.0.0.1:8790", "http://192.168.1.20:8790", "http://laptop.local:8790", "http://[::1]:8545", "http://localhost:8545"]) {
      expect(urlNeedles(u).some((x) => x.name.startsWith("rpcUrl:host")), u).toBe(false);
    }
  });

  it("classifies transports and labels runs (D-034)", () => {
    expect(classifyUrl("http://127.0.0.1:8790").transport).toBe("http-loopback");
    expect(classifyUrl("https://rpc.example.org/key").transport).toBe("https-internet");
    expect(classifyUrl("http://192.168.1.20:8790").transport).toBe("http-lan");
    expect(classifyUrl("http://10.0.0.5:8545").reach).toBe("lan");
    expect(classifyUrl("http://172.20.1.1:8545").reach).toBe("lan");
    expect(classifyUrl("http://172.32.1.1:8545").reach).toBe("internet");
    expect(classifyUrl("http://laptop.local:8790").reach).toBe("lan");
    expect(classifyUrl("http://[fd00::1]:8545").reach).toBe("lan");
    expect(() => classifyUrl("ws://127.0.0.1:1")).toThrow();
    expect(runLabels("http-loopback", "cold", "dev")).toEqual(expect.arrayContaining(["loopback, same host", "one-process cold", "dev key"]));
    expect(runLabels("https-internet", "warm", "dev")).toEqual(expect.arrayContaining(["public RPC endpoint over the internet", "one-process warm"]));
    expect(runLabels("http-lan", "cold", "ceremony")).toEqual(expect.arrayContaining(["local network, another host", "key: ceremony"]));
    expect(runLabels("http-loopback", "cold", "ceremony")).not.toContain("dev key");
    // the prover is named when it is not snarkJS
    expect(runLabels("http-loopback", "warm", "dev", "rapidsnark")).toContain("prover: rapidsnark");
    expect(runLabels("http-loopback", "warm", "dev").some((l) => l.startsWith("prover"))).toBe(false);
  });

  it("one environment per results root: results/v4/e2e/ takes WSL2 runs only, named or by default", () => {
    const wslRoot = path.join(REPO_ROOT, ...E2E_RESULTS_REL.split("/"));
    expect(resultsRootRefusal(undefined, false, "wsl2")).toBeNull();
    expect(resultsRootRefusal(wslRoot, false, "wsl2")).toBeNull();
    expect(resultsRootRefusal(undefined, false, "linux")).toMatch(/WSL2 series only/);
    expect(resultsRootRefusal(wslRoot, false, "linux")).toMatch(/WSL2 series only/);
    expect(resultsRootRefusal(wslRoot + path.sep, false, "darwin")).toMatch(/WSL2 series only/);
    expect(resultsRootRefusal(path.join(REPO_ROOT, "results", "v4", "e2e_device_rpi5"), false, "linux")).toBeNull();
    expect(resultsRootRefusal(undefined, false, "windows")).toMatch(/smoke runs only/);
    expect(resultsRootRefusal(undefined, true, "windows")).toBeNull();
  });

  it("the cold definition: a cold result whose bn128 curve was built before S1 becomes an error", () => {
    const ok = { ok: true, error: null, errorKind: null, endToEndMs: 10 };
    expect(applyColdDefinition(ok, false)).toBe(ok);
    const broken = applyColdDefinition(ok, true);
    expect(broken.ok).toBe(false);
    expect(broken.errorKind).toBe("cold-definition");
    expect(broken.endToEndMs).toBe(10);
    const failed = { ok: false, error: "wallet: x", errorKind: "wallet", endToEndMs: NaN };
    expect(applyColdDefinition(failed, true)).toBe(failed);
  });

  it("loopback detection agrees with rpc_trace endpointLabel (one D-034 label rule)", () => {
    for (const u of ["http://127.0.0.1:8790", "http://127.5.6.7:1", "http://localhost:8545", "http://a.localhost:1", "http://[::1]:8545", "http://192.168.1.2:8545", "https://rpc.example.org/v2/x", "http://10.1.2.3:1"]) {
      const mine = classifyUrl(u).loopback ? "loopback, same host" : "remote";
      expect(mine, u).toBe(endpointLabel(u));
      expect(reachLabel(classifyUrl(u).transport) === "loopback, same host", u).toBe(endpointLabel(u) === "loopback, same host");
    }
  });

  it("--rpc hook: env:NAME, a URL that cannot carry a key, or --rpc-env; a URL with a path or query is refused", () => {
    const env = { PQID_E2E_RPC_URL: " https://eth-sepolia.example-provider.io/v2/AbCdEf0123456789XYZ ", MY_RPC: "https://a.example/k/123456789" };
    expect(resolveRpcArg(undefined, "PQID_E2E_RPC_URL", env)).toEqual({ url: "https://eth-sepolia.example-provider.io/v2/AbCdEf0123456789XYZ", source: "environment variable PQID_E2E_RPC_URL", envName: "PQID_E2E_RPC_URL" });
    expect(resolveRpcArg("env:MY_RPC", "PQID_E2E_RPC_URL", env).url).toBe("https://a.example/k/123456789");
    expect(resolveRpcArg("env:MISSING", "PQID_E2E_RPC_URL", env).url).toBeNull();
    // an internet URL never goes on the command line (the key may sit in the host name)
    expect(() => resolveRpcArg("https://rpc.sepolia.example", "X", {})).toThrow(/loopback or local-network/);
    expect(() => resolveRpcArg("https://k3y0123456789abcdef.provider.example/", "X", {})).toThrow(/loopback or local-network/);
    expect(resolveRpcArg("http://192.168.1.20:8790", "X", {}).url).toBe("http://192.168.1.20:8790");
    expect(resolveRpcArg("http://127.0.0.1:8790/", "X", {}).envName).toBeNull();
    expect(() => resolveRpcArg("https://eth-sepolia.example-provider.io/v2/AbCdEf0123456789XYZ", "X", {})).toThrow(/environment variable/);
    expect(() => resolveRpcArg("https://rpc.example?apikey=1", "X", {})).toThrow(/environment variable/);
    expect(() => resolveRpcArg("https://user:pw@rpc.example", "X", {})).toThrow(/environment variable/);
    expect(() => resolveRpcArg("rpc.example", "X", {})).toThrow(/env:NAME/);
    expect(() => resolveRpcArg("env:1BAD", "X", {})).toThrow();
    expect(urlCarriesNoSecret("http://127.0.0.1:8790")).toBe(true);
    expect(urlCarriesNoSecret("https://x.example/#k")).toBe(false);
  });

  it("emulation heuristic", () => {
    expect(cpuFamilyOf("Intel(R) Core(TM) Ultra 7 355")).toBe("x86");
    expect(cpuFamilyOf("Apple M2")).toBe("arm");
    expect(emulationSuspected("arm64", "Intel(R) Core(TM) Ultra 7 355")).toBe(true);
    expect(emulationSuspected("arm64", "Apple M2")).toBe(false);
    expect(emulationSuspected("x64", "AMD Ryzen 7")).toBe(false);
  });

  it("state document shape and its secret needles", () => {
    const doc: E2eStateDoc = {
      schema: "pqid/v4-e2e-state/v1",
      key: { label: "dev", wasm: "w", zkey: "z", vkey: "v" },
      endpoint: { id: "custom", kind: "custom", rpcUrl: url, chainId: 11155111, transport: "https-internet" },
      setupId: "0123456789abcdef01234567",
      registry: { addresses: { didRegistry: "0x" + "1".repeat(40), accreditationRegistry: "0x" + "2".repeat(40), issuanceRootRegistry: "0x" + "3".repeat(40), verifierKemRegistry: "0x" + "4".repeat(40) }, fromBlock: 5 },
      governancePkHex: "a".repeat(2624),
      wallet: { holderSecret: "123456789012345678901234567890", vc: { credential: { holderCommit: "1", typeId: "t" }, credID: "c", signature: "s", leafIndex: 0 }, issuerPkHex: "b".repeat(2624), leafIndex: 0, blobB64: "UFFJRFBVQjEAAAAA" },
      verifier: { did: "did:pq:x", controller: "0x" + "5".repeat(40), origin: "https://e2e.verifier.example", pkHex: "c".repeat(2624), kemPublicKeyHex: "d".repeat(2368), kemPrivatePkcs8B64: Buffer.from("k".repeat(2498)).toString("base64") },
      policy: { predicate: "age_gte", threshold: 18, typeId: "pqid:type:age-credential:v1" },
    };
    expect(stateDocErrors(doc)).toEqual([]);
    expect(stateDocErrors({ ...doc, setupId: "x" })).toEqual(["setupId"]);
    expect(stateDocErrors({ ...doc, wallet: { ...doc.wallet, holderSecret: "0x12" } })).toContain("wallet.holderSecret");
    const names = stateDocNeedles(doc).map((x) => x.name);
    expect(names).toEqual(expect.arrayContaining(["holderSecret", "kemPrivateKey", "rpcUrl", "rpcUrl:path"]));
    const local = { ...doc, endpoint: { ...doc.endpoint, kind: "anvil" as const, rpcUrl: "http://127.0.0.1:8790" } };
    expect(stateDocNeedles(local).some((x) => x.name.startsWith("rpcUrl"))).toBe(false);
  });

  it("testnet cost estimate is the stated arithmetic", () => {
    expect(rawWriteGasLimit(100_000)).toBe(125_000);
    const roles = roleGasBudgets();
    const gas = SETUP_GAS.deploy + 3 * SETUP_GAS.transfer + roles.governance + roles.issuer + roles.verifier;
    const est = estimateSetupCost(10n ** 9n);
    // at 1 gwei every component is an exact integer: total = gas x 1.3 gwei
    expect(BigInt(est.totalWei)).toBe(BigInt(gas) * 1_300_000_000n);
    expect(Math.abs(est.totalEth - (gas * 1.3) / 1e9)).toBeLessThan(1e-9);
    expect(est.totalEth).toBeGreaterThan(0.005);
    expect(est.totalEth).toBeLessThan(0.02);
  });
});

describe("e2e key spec (D-034: ceremony key, dev key labelled)", () => {
  const pin = (key: string) => ({ file: "setup/pins_v4.json", key });
  const devDoc = {
    wasm: { rel: "circuits/build/v4/credential_auth_v4_js/credential_auth_v4.wasm", pin: pin("v4/credential_auth_v4.wasm") },
    zkey: { rel: "setup/out/v4/credential_auth_v4_dev.zkey", pin: pin("v4/credential_auth_v4_dev.zkey") },
    vkey: { rel: "setup/out/v4/verification_key_dev.json", pin: pin("v4/verification_key_dev.json") },
  };

  it("the default is the pinned dev key", () => {
    const k = loadKeySpec(undefined);
    expect(k.spec.label).toBe("dev");
    expect(Object.values(k.artifacts).every((a) => a.pinned && a.pinMatch === true)).toBe(true);
  });

  it("a key spec must pin every artifact against an existing pin, with repo-relative paths", () => {
    expect(checkKeySpec(keySpecFromJson({ label: "ceremony-test", ...devDoc }), "test").artifacts.zkey.pinned).toBe(true);
    // a pin key that the pin file does not hold is refused (bench lib alone would call it unpinned)
    expect(() => checkKeySpec(keySpecFromJson({ label: "ceremony-test", ...devDoc, zkey: { ...devDoc.zkey, pin: pin("v4/no-such-key") } }), "test")).toThrow(/no pin found for zkey/);
    expect(() => keySpecFromJson({ label: "ceremony-test", ...devDoc, vkey: { rel: devDoc.vkey.rel } })).toThrow(/must pin every artifact/);
    expect(() => keySpecFromJson({ label: "x", ...devDoc, wasm: { rel: "../outside.wasm" } })).toThrow(/repo-relative/);
    expect(() => keySpecFromJson({ label: "x", ...devDoc, wasm: { rel: "C:/abs.wasm" } })).toThrow(/repo-relative/);
    expect(() => keySpecFromJson({ label: "", ...devDoc })).toThrow(/label/);
  });
});

describe("e2e plumbing", () => {
  it("child messages: only prefixed JSON lines are read", () => {
    const text = `noise\n${MSG_PREFIX}{"type":"result","ok":true}\n${MSG_PREFIX}not json\n{"type":"plain"}\n`;
    expect(parseMsgLines(text)).toEqual([{ type: "result", ok: true }]);
  });

  it("the smoke root ignores itself", () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-e2e-root-"));
    try {
      const r = resolveRoot(tmp, true);
      expect(r).toBe(path.join(tmp, "_smoke"));
      expect(fs.readFileSync(path.join(r, ".gitignore"), "utf8")).toMatch(/^\*$/m);
      expect(resolveRoot(tmp, false)).toBe(path.resolve(tmp));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});
