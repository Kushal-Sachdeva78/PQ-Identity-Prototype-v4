import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { REPO_ROOT, VERSIONS, checkArtifact, envInfo, sanitize, sha256FileHex, sha256Hex, buildSchedule, protocolSha, type ArtifactRecord, type ArtifactSpec, type Slot } from "../bench/lib.ts";
import { execFileSync } from "node:child_process";
import { readPower, type PowerReading } from "../bench/guard.ts";
import { SEEDS, SEED_BOOTSTRAP, assertUnusedSeed } from "../lib/seeds.ts";
import { PORTS } from "../lib/ports.ts";
import type { PostRecord } from "../lib/rpc_trace.ts";

/**
 * Shared definitions and pure helpers of the end-to-end presentation series
 * (docs/v4/E2E.md; DECISIONS D-034 conventions). Imported by the orchestrator
 * (campaign.ts), the child (child_present.ts), the read-only testnet check and the tests.
 * Importing this module loads no ethers, solc or snarkJS code.
 */

export { REPO_ROOT };

// ---------------------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------------------

export const E2E_PROTOCOL_DOC = "docs/v4/E2E.md";
export const E2E_RESULTS_REL = "results/v4/e2e";
export const SMOKE_DIR = "_smoke";

export const SCHEMA = Object.freeze({
  state: "pqid/v4-e2e-state/v1",
  run: "pqid/v4-e2e-run/v1",
  child: "pqid/v4-e2e-child/v1",
  env: "pqid/v4-e2e-env/v1",
  schedule: "pqid/v4-e2e-schedule/v1",
  deployment: "pqid/v4-e2e-deployment/v1",
});

/** D-034 port of this series (the orchestrator's own Anvil). */
export const E2E_ANVIL_PORT = PORTS.endToEnd;
/** Besu QBFT network of scripts/besu/setup_qbft.sh (node 1 RPC). */
export const BESU_RPC_PORTS: readonly number[] = PORTS.besuQbft;

/** Registered seed (D-034) and the bootstrap seed (BENCH_PROTOCOL.md). */
export const E2E_SEED_ID = "endToEnd.order";
export const E2E_SEED = SEEDS.endToEnd.order;
export const E2E_BOOTSTRAP_SEED = SEED_BOOTSTRAP;
// refuses at load when the registry no longer holds this seed or an earlier series used it
assertUnusedSeed(E2E_SEED);

/** The protocol's request policy (age_gte 18, default credential type). */
export const E2E_POLICY = Object.freeze({ predicate: "age_gte" as const, threshold: 18 });
/** Birth date of the presenting holder (the Phase D fixture date). */
export const PRESENTING_BIRTH_DATE = 19840315;
/** Number of holders issued per setup (the presenting one included). */
export const HOLDERS_PER_SETUP = 8;

export type EndpointKind = "anvil" | "besu" | "custom";
export const ENDPOINT_KINDS: readonly EndpointKind[] = ["anvil", "besu", "custom"];

export type Mode = "cold" | "warm";

/** Outermost LedgerV4 reads recorded per party (same list as harness/v4/scale_lib.ts LEDGER_READS). */
export const LEDGER_READS: readonly string[] = Object.freeze([
  "resolveDidRecord",
  "getPopSignature",
  "latestAccreditation",
  "currentEpoch",
  "latestKemKey",
  "getMinAnchorInterval",
  "getMaxWindow",
  "chainId",
  "blockTimestamp",
  "blockNumber",
]);

// ---------------------------------------------------------------------------------------
// stages
// ---------------------------------------------------------------------------------------

export type StageId = "S1" | "S2" | "S3" | "S4" | "S5" | "S6" | "S7" | "S8" | "S9" | "S10" | "S11";

export interface StageSpec {
  id: StageId;
  key: string;
  party: "verifier" | "wallet" | "transport";
  what: string;
}

export const STAGES: readonly StageSpec[] = Object.freeze([
  { id: "S1", key: "verifierRequest", party: "verifier", what: "VerifierV4.newRequest (the verifier ledger's chainId; in a cold run this includes ethers' network detection)" },
  { id: "S2", key: "requestTransport", party: "transport", what: "JSON.stringify and JSON.parse of the request in the process (bytes recorded; no network between the parties)" },
  { id: "S3", key: "walletRequestChecks", party: "wallet", what: "HolderWalletV4.present() call to the end of its checkRequest (request copy, verifier DID record, PoP record and DIDRegisteredV4 log, KEM key and KemKeyPublishedV4 log, ML-DSA verifies of the PoP and the KEM statement, date and policy checks)" },
  { id: "S4", key: "walletCredential", party: "wallet", what: "end of checkRequest to the start of checkIssuerData (credential selection, ML-DSA credential signature)" },
  { id: "S5", key: "walletIssuerChecks", party: "wallet", what: "checkIssuerData (latestAccreditation twice, issuer record, PoP, accreditation, currentEpoch, minAnchorInterval; path and IMT witness from the stored blob; no issuer contact)" },
  { id: "S6", key: "walletKem", party: "wallet", what: "ML-KEM-768 encapsulation (the node:crypto encapsulate call); inside the S7 window" },
  { id: "S7", key: "walletSessionAndInput", party: "wallet", what: "end of checkIssuerData to the input mark, minus S6 (date and predicate checks, transcript SHA3, HKDF, Poseidon circuit input)" },
  { id: "S8", key: "walletWitnessProve", party: "wallet", what: "input mark to the first aes-256-gcm createCipheriv after it (snarkJS witness and Groth16 proof as shipped proveV4: in a cold process also the first dynamic import of snarkJS, then a SHA-256 of the zkey file and of the in-memory witness, and the wallet's own shape check; not the same work as Phase D wp)" },
  { id: "S9", key: "walletSeal", party: "wallet", what: "createCipheriv mark to the return of present() (AES-256-GCM seal, reply object)" },
  { id: "S10", key: "replyTransport", party: "transport", what: "JSON.stringify of the reply (bytes recorded); verifyReply receives the JSON string" },
  { id: "S11", key: "verifierVerify", party: "verifier", what: "VerifierV4.verifyReply (decapsulation, HKDF, AES-GCM open, issuer record, PoP, accreditation, chainId, currentEpoch, Poseidon checks, Groth16 verify, ML-DSA epoch signature)" },
]);

export const STAGE_IDS: readonly StageId[] = STAGES.map((s) => s.id);

/** Time marks of one instrumented presentation, in ms on one monotonic base. */
export interface Marks {
  s1Start: number;
  s1End: number;
  s2Start: number;
  /** present() call (S2 end, S3 start). */
  s2End: number;
  /** end of checkRequest (S3 end, S4 start). */
  checkRequestEnd: number;
  /** checkIssuerData start and end (S5). */
  issuerStart: number;
  issuerEnd: number;
  /** wallet cfg.inputHook call (S7 end, S8 start). */
  inputMark: number;
  /** first aes-256-gcm createCipheriv at or after inputMark (S8 end, S9 start). */
  sealMark: number;
  /** present() return (S9 end). */
  presentEnd: number;
  s10Start: number;
  /** S10 end, S11 start (verifyReply call). */
  s10End: number;
  /** verifyReply return. */
  s11End: number;
}

export interface StageWindow {
  id: StageId;
  start: number;
  end: number;
}

const MARK_ORDER: Array<keyof Marks> = [
  "s1Start",
  "s1End",
  "s2Start",
  "s2End",
  "checkRequestEnd",
  "issuerStart",
  "issuerEnd",
  "inputMark",
  "sealMark",
  "presentEnd",
  "s10Start",
  "s10End",
  "s11End",
];

/** Throws unless every mark is a finite number and the marks are in protocol order. */
export function checkMarks(m: Partial<Marks>): asserts m is Marks {
  let prev = -Infinity;
  for (const k of MARK_ORDER) {
    const v = m[k];
    if (typeof v !== "number" || !Number.isFinite(v)) throw new Error(`stage mark ${k} missing`);
    if (v < prev) throw new Error(`stage mark ${k} (${v}) is before the previous mark (${prev})`);
    prev = v;
  }
}

/**
 * Contiguous stage windows. S6 has no window of its own: it is the encapsulate time inside
 * the S7 window, which is reported as the window minus S6. The two agent switches (S1 end to
 * S2 start, S9 end to S10 start) lie between windows and are not part of any stage.
 */
export function stageWindows(m: Marks): StageWindow[] {
  return [
    { id: "S1", start: m.s1Start, end: m.s1End },
    { id: "S2", start: m.s2Start, end: m.s2End },
    { id: "S3", start: m.s2End, end: m.checkRequestEnd },
    { id: "S4", start: m.checkRequestEnd, end: m.issuerStart },
    { id: "S5", start: m.issuerStart, end: m.issuerEnd },
    { id: "S7", start: m.issuerEnd, end: m.inputMark },
    { id: "S8", start: m.inputMark, end: m.sealMark },
    { id: "S9", start: m.sealMark, end: m.presentEnd },
    { id: "S10", start: m.s10Start, end: m.s10End },
    { id: "S11", start: m.s10End, end: m.s11End },
  ];
}

/** endToEndMs: S1 start to S11 end minus the two agent switches. */
export function endToEndOf(m: Pick<Marks, "s1Start" | "s1End" | "s2Start" | "presentEnd" | "s10Start" | "s11End">): { endToEndMs: number; agentSwitchMs: number } {
  const agentSwitchMs = m.s2Start - m.s1End + (m.s10Start - m.presentEnd);
  return { endToEndMs: m.s11End - m.s1Start - agentSwitchMs, agentSwitchMs };
}

/** The window (stage id) that contains time t, start inclusive and end exclusive; null outside every window. */
export function stageAt(windows: readonly StageWindow[], t: number): StageId | null {
  for (const w of windows) if (t >= w.start && t < w.end) return w.id;
  // a zero-length last window cannot contain anything; an event exactly at the S11 end is outside
  return null;
}

export type HookKind = "mlDsaVerify" | "mlDsaImport" | "mlKemEncaps" | "mlKemDecaps" | "aesGcmCipher";

export interface HookEvent {
  kind: HookKind;
  start: number;
  end: number;
}

/** One V8 garbage collection (perf_hooks entry type "gc"), start on the marks' time base, in ms. */
export interface GcEvent {
  start: number;
  ms: number;
  /** minor, major, incremental, weakcb, or the numeric kind. */
  kind: string;
}

/** perf_hooks NODE_PERFORMANCE_GC_* kind numbers to names. */
export function gcKindName(kind: unknown): string {
  switch (kind) {
    case 1:
      return "minor";
    case 4:
      return "major";
    case 8:
      return "incremental";
    case 16:
      return "weakcb";
    default:
      return String(kind ?? "unknown");
  }
}

export type Party = "verifier" | "wallet";

export interface LedgerCall {
  party: Party;
  method: string;
  start: number;
  end: number;
  ok: boolean;
}

export interface PartyPost extends PostRecord {
  party: Party;
}

export interface StageReport {
  id: StageId;
  ms: number;
  posts: number;
  requests: number;
  postsByParty: Record<Party, number>;
  byMethod: Record<string, number>;
  /** Sum of POST durations that started in the stage. */
  postMs: number;
  /** POSTs that carried a JSON array (a JSON-RPC batch). */
  batchPosts: number;
  failedPosts: number;
  rpcErrors: number;
  httpAttempts: number;
  /** HTTP status 429 seen in the stage's POSTs (FetchRequest retries them inside one POST). */
  http429: number;
  /** New TCP (or TLS) connections opened by the stage's POSTs (rpc_trace per-attempt attribution). */
  connects: number;
  /** HTTP attempts whose connection could not be classified (expected 0). */
  connectsUnknown: number;
  bytesOut: number;
  bytesIn: number;
  /** Outermost LedgerV4 calls that started in the stage, by method. */
  ledgerCalls: Record<string, number>;
  ledgerMs: number;
  mlDsaVerify: number;
  mlDsaVerifyMs: number;
  mlDsaImport: number;
  mlDsaImportMs: number;
  mlKemEncapsMs: number;
  mlKemDecapsMs: number;
  /** V8 garbage collections that started in the stage (perf_hooks "gc" entries), count and summed duration. */
  gcCount: number;
  gcMs: number;
}

export interface PresentationReport {
  endToEndMs: number;
  agentSwitchMs: number;
  stages: Record<StageId, StageReport>;
  /** S11 split as E4: chain (outermost verifier reads), ML-DSA (verify and key import), ML-KEM decapsulation, other [S] by subtraction. */
  verifySplit: { chainMs: number; mlDsaMs: number; mlKemDecapsMs: number; otherMs: number };
  /** S3 + S5 split for the wallet's registry checks. */
  walletChecksSplit: { chainMs: number; mlDsaMs: number; otherMs: number };
  /** S7 + S8 (session and circuit input plus witness and proof), the coarser split that does not depend on the input mark. */
  s7s8Ms: number;
  totals: {
    posts: number;
    requests: number;
    postsByParty: Record<Party, number>;
    requestsByParty: Record<Party, number>;
    byMethod: Record<string, number>;
    ledgerCallsByParty: Record<Party, number>;
    chainMsByParty: Record<Party, number>;
    rpcErrors: number;
    failedPosts: number;
    http429: number;
    httpAttempts: number;
    connectsByParty: Record<Party, number>;
    connectsUnknown: number;
  };
  /** POSTs, hook events and ledger calls outside every stage window (expected 0). */
  outside: { posts: number; events: number; ledgerCalls: number };
  /** Garbage collections that started between S1 start and S11 end: count, summed ms, major count, and those in no stage window (the agent switches). */
  gcTotals: { count: number; ms: number; majorCount: number; majorMs: number; outsideWindows: number };
}

function emptyStage(id: StageId): StageReport {
  return {
    id,
    ms: 0,
    posts: 0,
    requests: 0,
    postsByParty: { verifier: 0, wallet: 0 },
    byMethod: {},
    postMs: 0,
    batchPosts: 0,
    failedPosts: 0,
    rpcErrors: 0,
    httpAttempts: 0,
    http429: 0,
    connects: 0,
    connectsUnknown: 0,
    bytesOut: 0,
    bytesIn: 0,
    ledgerCalls: {},
    ledgerMs: 0,
    mlDsaVerify: 0,
    mlDsaVerifyMs: 0,
    mlDsaImport: 0,
    mlDsaImportMs: 0,
    mlKemEncapsMs: 0,
    mlKemDecapsMs: 0,
    gcCount: 0,
    gcMs: 0,
  };
}

const r3 = (x: number) => Math.round(x * 1000) / 1000;

/**
 * Per-stage accounting of one presentation from its marks, hook events, outermost ledger calls,
 * POST records and garbage collections (all on one time base). Pure; unit-tested. A collection
 * is attributed to the stage in which it started; collections that started before S1 or at or
 * after the S11 end are ignored.
 */
export function computeReport(m: Marks, events: readonly HookEvent[], calls: readonly LedgerCall[], posts: readonly PartyPost[], gc: readonly GcEvent[] = []): PresentationReport {
  checkMarks(m);
  const windows = stageWindows(m);
  const stages = Object.fromEntries(STAGE_IDS.map((id) => [id, emptyStage(id)])) as Record<StageId, StageReport>;
  for (const w of windows) stages[w.id].ms = w.end - w.start;
  const outside = { posts: 0, events: 0, ledgerCalls: 0 };
  const totals: PresentationReport["totals"] = {
    posts: 0,
    requests: 0,
    postsByParty: { verifier: 0, wallet: 0 },
    requestsByParty: { verifier: 0, wallet: 0 },
    byMethod: {},
    ledgerCallsByParty: { verifier: 0, wallet: 0 },
    chainMsByParty: { verifier: 0, wallet: 0 },
    rpcErrors: 0,
    failedPosts: 0,
    http429: 0,
    httpAttempts: 0,
    connectsByParty: { verifier: 0, wallet: 0 },
    connectsUnknown: 0,
  };

  for (const p of posts) {
    const st = stageAt(windows, p.tStartMs);
    const n429 = (p.http?.statuses ?? []).filter((s) => s === 429).length;
    const conn = p.http?.connects ?? 0;
    const connUnknown = (p.http?.newConnection ?? []).filter((x) => x === null).length;
    totals.posts++;
    totals.requests += p.size;
    totals.postsByParty[p.party]++;
    totals.requestsByParty[p.party] += p.size;
    for (const meth of p.methods) totals.byMethod[meth] = (totals.byMethod[meth] ?? 0) + 1;
    totals.rpcErrors += p.rpcErrors;
    if (!p.ok) totals.failedPosts++;
    totals.http429 += n429;
    totals.httpAttempts += p.http?.attempts ?? 0;
    totals.connectsByParty[p.party] += conn;
    totals.connectsUnknown += connUnknown;
    if (!st) {
      outside.posts++;
      continue;
    }
    const s = stages[st];
    s.posts++;
    s.requests += p.size;
    s.postsByParty[p.party]++;
    for (const meth of p.methods) s.byMethod[meth] = (s.byMethod[meth] ?? 0) + 1;
    s.postMs += p.ms;
    if (p.batch) s.batchPosts++;
    if (!p.ok) s.failedPosts++;
    s.rpcErrors += p.rpcErrors;
    s.httpAttempts += p.http?.attempts ?? 0;
    s.http429 += n429;
    s.connects += conn;
    s.connectsUnknown += connUnknown;
    s.bytesOut += p.http?.bytesOut ?? 0;
    s.bytesIn += p.http?.bytesIn ?? 0;
  }

  for (const c of calls) {
    const st = stageAt(windows, c.start);
    totals.ledgerCallsByParty[c.party]++;
    totals.chainMsByParty[c.party] += c.end - c.start;
    if (!st) {
      outside.ledgerCalls++;
      continue;
    }
    const s = stages[st];
    s.ledgerCalls[c.method] = (s.ledgerCalls[c.method] ?? 0) + 1;
    s.ledgerMs += c.end - c.start;
  }

  for (const e of events) {
    const st = stageAt(windows, e.start);
    if (!st) {
      // the seal's createCipheriv starts exactly at sealMark, which is the S9 start: inside.
      outside.events++;
      continue;
    }
    const s = stages[st];
    const d = e.end - e.start;
    if (e.kind === "mlDsaVerify") {
      s.mlDsaVerify++;
      s.mlDsaVerifyMs += d;
    } else if (e.kind === "mlDsaImport") {
      s.mlDsaImport++;
      s.mlDsaImportMs += d;
    } else if (e.kind === "mlKemEncaps") {
      s.mlKemEncapsMs += d;
    } else if (e.kind === "mlKemDecaps") {
      s.mlKemDecapsMs += d;
    }
  }

  const gcTotals = { count: 0, ms: 0, majorCount: 0, majorMs: 0, outsideWindows: 0 };
  for (const g of gc) {
    if (g.start < m.s1Start || g.start >= m.s11End) continue;
    gcTotals.count++;
    gcTotals.ms += g.ms;
    if (g.kind === "major") {
      gcTotals.majorCount++;
      gcTotals.majorMs += g.ms;
    }
    const st = stageAt(windows, g.start);
    if (!st) {
      gcTotals.outsideWindows++;
      continue;
    }
    stages[st].gcCount++;
    stages[st].gcMs += g.ms;
  }
  gcTotals.ms = r3(gcTotals.ms);
  gcTotals.majorMs = r3(gcTotals.majorMs);

  // S6 is the encapsulate time inside the S7 window; S7 is the window minus S6.
  const s6 = stages.S7.mlKemEncapsMs;
  stages.S6.ms = s6;
  stages.S6.mlKemEncapsMs = s6;
  stages.S7.ms = stages.S7.ms - s6;
  stages.S7.mlKemEncapsMs = 0;

  for (const id of STAGE_IDS) {
    const s = stages[id];
    s.ms = r3(s.ms);
    s.postMs = r3(s.postMs);
    s.ledgerMs = r3(s.ledgerMs);
    s.mlDsaVerifyMs = r3(s.mlDsaVerifyMs);
    s.mlDsaImportMs = r3(s.mlDsaImportMs);
    s.mlKemEncapsMs = r3(s.mlKemEncapsMs);
    s.mlKemDecapsMs = r3(s.mlKemDecapsMs);
    s.gcMs = r3(s.gcMs);
  }
  totals.chainMsByParty.verifier = r3(totals.chainMsByParty.verifier);
  totals.chainMsByParty.wallet = r3(totals.chainMsByParty.wallet);

  const { endToEndMs, agentSwitchMs } = endToEndOf(m);
  const s11 = stages.S11;
  const vMlDsa = s11.mlDsaVerifyMs + s11.mlDsaImportMs;
  const wChain = stages.S3.ledgerMs + stages.S5.ledgerMs;
  const wMlDsa = stages.S3.mlDsaVerifyMs + stages.S3.mlDsaImportMs + stages.S5.mlDsaVerifyMs + stages.S5.mlDsaImportMs;
  return {
    endToEndMs: r3(endToEndMs),
    agentSwitchMs: r3(agentSwitchMs),
    stages,
    verifySplit: {
      chainMs: s11.ledgerMs,
      mlDsaMs: r3(vMlDsa),
      mlKemDecapsMs: s11.mlKemDecapsMs,
      otherMs: r3(s11.ms - s11.ledgerMs - vMlDsa - s11.mlKemDecapsMs),
    },
    walletChecksSplit: {
      chainMs: r3(wChain),
      mlDsaMs: r3(wMlDsa),
      otherMs: r3(stages.S3.ms + stages.S5.ms - wChain - wMlDsa),
    },
    s7s8Ms: r3(stages.S7.ms + stages.S8.ms),
    totals,
    outside,
    gcTotals,
  };
}

/** Raw garbage-collection list of a result line: the stage each one started in, start and duration in ms. */
export function compactGc(gc: readonly GcEvent[], m: Marks): Array<{ stage: StageId | null; tStartMs: number; ms: number; kind: string }> {
  const windows = stageWindows(m);
  return gc.filter((g) => g.start >= m.s1Start && g.start < m.s11End).map((g) => ({ stage: stageAt(windows, g.start), tStartMs: r3(g.start), ms: r3(g.ms), kind: g.kind }));
}

/** Compact per-POST record for a result line (no URL, no payload). */
export function compactPost(p: PartyPost, windows: readonly StageWindow[] | null): Record<string, unknown> {
  return {
    party: p.party,
    stage: windows ? stageAt(windows, p.tStartMs) : null,
    seq: p.seq,
    tStartMs: r3(p.tStartMs),
    ms: r3(p.ms),
    size: p.size,
    batch: p.batch,
    methods: p.methods,
    direct: p.direct,
    queueMsMax: p.queueMs.reduce<number | null>((a, q) => (q === null ? a : a === null ? q : Math.max(a, q)), null),
    ok: p.ok,
    rpcErrors: p.rpcErrors,
    error: p.error,
    http: p.http
      ? {
          attempts: p.http.attempts,
          statuses: p.http.statuses,
          ms: r3(p.http.ms),
          bytesOut: p.http.bytesOut,
          bytesIn: p.http.bytesIn,
          connects: p.http.connects ?? null,
          newConnection: p.http.newConnection ?? null,
          contentEncoding: p.http.contentEncoding ?? null,
        }
      : null,
  };
}

// ---------------------------------------------------------------------------------------
// outermost ledger calls (Proxy on one party's LedgerV4)
// ---------------------------------------------------------------------------------------

/**
 * A Proxy that records every outermost call of the listed methods (a read that another read
 * makes internally, such as resolveDidRecord inside getPopSignature, counts once, in the
 * outer call). The parties await their reads one at a time; concurrent outer calls would be
 * merged into the first (the depth counter is per proxy).
 */
export function recordOuterCalls<T extends object>(target: T, party: Party, methods: readonly string[], sink: LedgerCall[], now: () => number): T {
  const set = new Set(methods);
  let depth = 0;
  return new Proxy(target, {
    get(t, prop, receiver) {
      const v = Reflect.get(t, prop, receiver) as unknown;
      if (typeof prop !== "string" || typeof v !== "function" || !set.has(prop)) return v;
      const fn = v as (...a: unknown[]) => unknown;
      return async function (this: unknown, ...args: unknown[]) {
        const outer = depth === 0;
        depth++;
        const start = now();
        let ok = false;
        try {
          const r = await fn.apply(this, args);
          ok = true;
          return r;
        } finally {
          depth--;
          if (outer) sink.push({ party, method: prop, start, end: now(), ok });
        }
      };
    },
  });
}

// ---------------------------------------------------------------------------------------
// schedule and seeds
// ---------------------------------------------------------------------------------------

/**
 * Every e2e campaign seeds its order with the registered seed itself (D-034 endToEnd.order =
 * 20261031): no derived or ad-hoc seed. Campaigns differ in their conditions, so one seed is
 * enough; schedule.json records it as config.seed (the harness/v4/lib/seeds.ts convention).
 */
export const STREAM_SEED_RULE =
  "mulberry32 seeded with the registered seed endToEnd.order = 20261031 (DECISIONS D-034) for every e2e campaign; bench lib buildSchedule (Fisher-Yates from the end, one stream for all blocks of the campaign, warm-up blocks first)";

export const CONTROL_SUFFIX = ":control";

/** Conditions of a campaign: cold, one per endpoint; warm, each endpoint instrumented plus its uninstrumented control. */
export function campaignConditions(mode: Mode, endpoints: readonly string[]): string[] {
  if (mode === "cold") return [...endpoints];
  return [...endpoints, ...endpoints.map((e) => e + CONTROL_SUFFIX)];
}

export function parseCondition(c: string): { endpoint: string; control: boolean } {
  return c.endsWith(CONTROL_SUFFIX) ? { endpoint: c.slice(0, -CONTROL_SUFFIX.length), control: true } : { endpoint: c, control: false };
}

/** Blocked randomised schedule (bench lib buildSchedule with the registered seed). */
export function e2eSchedule(mode: Mode, endpoints: readonly string[], blocks: number, warmup: number): { seed: number; slots: Slot[] } {
  const seed = assertUnusedSeed(E2E_SEED).seed;
  const conditions = campaignConditions(mode, endpoints);
  const slots = mode === "cold" ? buildSchedule(conditions, blocks, seed) : buildSchedule(conditions, warmup + blocks, seed, -warmup);
  return { seed, slots };
}

// ---------------------------------------------------------------------------------------
// clocks: host pause and UTC midnight
// ---------------------------------------------------------------------------------------

export interface ClockReading {
  /** performance.now(), ms (monotonic; stops while a WSL2 VM is paused). */
  mono: number;
  /** Date.now(), ms (wall clock; resynced after a pause). */
  wall: number;
  /** /proc/uptime in ms on Linux (CLOCK_BOOTTIME), else null. */
  uptime: number | null;
}

export function readClocks(): ClockReading {
  let uptime: number | null = null;
  if (process.platform === "linux") {
    try {
      uptime = Number(fs.readFileSync("/proc/uptime", "utf8").split(/\s+/)[0]) * 1000;
      if (!Number.isFinite(uptime)) uptime = null;
    } catch {
      uptime = null;
    }
  }
  return { mono: performance.now(), wall: Date.now(), uptime };
}

export interface ClockGap {
  monoSec: number;
  wallSec: number;
  uptimeSec: number | null;
  /** wallSec - monoSec. */
  clockGapSec: number;
  thresholdSec: number;
  hostPauseSuspected: boolean;
}

/**
 * Wall time minus monotonic time over a window. In WSL2 the monotonic clock stops while the VM
 * is paused (host sleep, standby) and the wall clock is resynced afterwards, so a gap well above
 * zero means the host paused during the window (cold_rs_wsl showed gaps up to 672 s).
 */
export function clockGap(a: ClockReading, b: ClockReading, thresholdSec: number): ClockGap {
  const monoSec = (b.mono - a.mono) / 1000;
  const wallSec = (b.wall - a.wall) / 1000;
  const uptimeSec = a.uptime !== null && b.uptime !== null ? (b.uptime - a.uptime) / 1000 : null;
  const gap = wallSec - monoSec;
  const r = (x: number) => Math.round(x * 1000) / 1000;
  return {
    monoSec: r(monoSec),
    wallSec: r(wallSec),
    uptimeSec: uptimeSec === null ? null : r(uptimeSec),
    clockGapSec: r(gap),
    thresholdSec,
    hostPauseSuspected: Math.abs(gap) > thresholdSec,
  };
}

/**
 * The flat per-run idle fields of the comparable-benchmark series (docs/v4/CMP.md), so every
 * D-034 cold series names them the same way: idleSec (monotonic), idleWallSec, clockGapSec =
 * idleWallSec - idleSec, hostPauseSuspected = |clockGapSec| > threshold.
 */
export function idleFields(g: ClockGap): { idleSec: number; idleWallSec: number; clockGapSec: number; hostPauseSuspected: boolean } {
  return { idleSec: g.monoSec, idleWallSec: g.wallSec, clockGapSec: g.clockGapSec, hostPauseSuspected: g.hostPauseSuspected };
}

/** Idle gap above this is flagged (the run is kept, flagged and counted). */
export const IDLE_PAUSE_THRESHOLD_SEC = 5;
/** A gap above this inside a run or a warm block discards it (repeated). */
export const RUN_PAUSE_THRESHOLD_SEC = 2;

/**
 * UTC midnight black-out (E2E.md rule 10): no warm block between 23:50 and 00:10 UTC (the
 * wallet date log and the verifier session TTL change at midnight).
 */
export function midnightBlackout(nowMs: number, marginMin = 10): { inside: boolean; endsAtMs: number | null } {
  const day = 86_400_000;
  const into = ((nowMs % day) + day) % day;
  const margin = marginMin * 60_000;
  if (into < margin) return { inside: true, endsAtMs: nowMs - into + margin };
  if (into >= day - margin) return { inside: true, endsAtMs: nowMs - into + day + margin };
  return { inside: false, endsAtMs: null };
}

/** true when [nowMs, nowMs + durationMs] touches the black-out window. */
export function crossesBlackout(nowMs: number, durationMs: number, marginMin = 10): boolean {
  if (midnightBlackout(nowMs, marginMin).inside) return true;
  const day = 86_400_000;
  const into = ((nowMs % day) + day) % day;
  const nextStart = nowMs - into + day - marginMin * 60_000;
  return nowMs + durationMs >= nextStart;
}

// ---------------------------------------------------------------------------------------
// endpoints and secrets
// ---------------------------------------------------------------------------------------

export type Transport = "http-loopback" | "https-loopback" | "http-lan" | "https-lan" | "https-internet" | "http-internet";

export type Reach = "loopback" | "lan" | "internet";

export interface UrlClass {
  scheme: "http" | "https";
  loopback: boolean;
  /** loopback (this host), lan (a private address or a .local name: another host on the local network) or internet. */
  reach: Reach;
  transport: Transport;
}

/** Same rule as harness/v4/lib/rpc_trace.ts endpointLabel (checked by a unit test): localhost, *.localhost, ::1, 127.0.0.0/8. */
export function isLoopbackHostname(hostname: string): boolean {
  let h = hostname.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  return h === "localhost" || h.endsWith(".localhost") || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h) || /^::ffff:127\.\d+\.\d+\.\d+$/.test(h);
}

/** RFC 1918 and link-local IPv4, IPv6 unique-local and link-local, and mDNS .local names. */
export function isLanHostname(hostname: string): boolean {
  let h = hostname.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.endsWith(".local")) return true;
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(h);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  return /^f[cd][0-9a-f]{2}:/.test(h) || /^fe[89ab][0-9a-f]:/.test(h);
}

export function classifyUrl(url: string): UrlClass {
  const u = new URL(url);
  const scheme = u.protocol === "https:" ? "https" : u.protocol === "http:" ? "http" : null;
  if (!scheme) throw new Error(`unsupported RPC URL scheme ${u.protocol} (http or https only)`);
  const reach: Reach = isLoopbackHostname(u.hostname) ? "loopback" : isLanHostname(u.hostname) ? "lan" : "internet";
  return { scheme, loopback: reach === "loopback", reach, transport: `${scheme}-${reach}` as Transport };
}

/** SHA-256 of the URL text (the only trace of a custom URL in any result). */
export function urlSha256(url: string): string {
  return sha256Hex(url);
}

/**
 * true when a URL cannot carry an API key or a credential: no user info, no query, no fragment,
 * and an empty path (or "/"). Only such a URL may be given on the command line (`--rpc <url>`);
 * any other goes through an environment variable (`--rpc env:NAME` or `--rpc-env NAME`).
 */
export function urlCarriesNoSecret(url: string): boolean {
  try {
    const u = new URL(url);
    return u.username === "" && u.password === "" && u.search === "" && u.hash === "" && (u.pathname === "" || u.pathname === "/");
  } catch {
    return false;
  }
}

/**
 * The custom endpoint's URL from `--rpc <value>` or `--rpc-env <NAME>` (the hook for a public
 * testnet run that Kushal starts). `--rpc env:NAME` reads the variable NAME; `--rpc <url>` is
 * accepted only for a loopback or local-network URL that cannot carry a secret
 * (urlCarriesNoSecret): an internet URL always comes from the environment, because some
 * providers put the API key in the host name and argv lands in shell history. `--rpc-env NAME`
 * (default PQID_E2E_RPC_URL) reads NAME. Returns the URL and where it came from (never the URL
 * itself in `source`). Pure: `env` is passed in.
 */
export function resolveRpcArg(rpcArg: string | undefined, rpcEnv: string, env: Readonly<Record<string, string | undefined>>): { url: string | null; source: string; envName: string | null } {
  if (rpcArg !== undefined) {
    const v = rpcArg.trim();
    if (v.startsWith("env:")) {
      const name = v.slice(4);
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error("--rpc env:NAME needs a valid environment variable name");
      return { url: env[name]?.trim() || null, source: `environment variable ${name}`, envName: name };
    }
    if (!/^https?:\/\//i.test(v)) throw new Error("--rpc takes env:NAME or an http(s) URL");
    if (!urlCarriesNoSecret(v)) {
      throw new Error("--rpc <url>: this URL has a path, query or user info, which may carry an API key; put it in an environment variable and pass --rpc env:NAME (or --rpc-env NAME)");
    }
    if (classifyUrl(v).reach === "internet") {
      throw new Error("--rpc <url> takes only a loopback or local-network URL; an internet URL (its host name may carry an API key) goes through an environment variable: --rpc env:NAME (or --rpc-env NAME)");
    }
    return { url: v, source: "command line (a loopback or local-network URL without path, query or user info)", envName: null };
  }
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(rpcEnv)) throw new Error("--rpc-env needs a valid environment variable name");
  return { url: env[rpcEnv]?.trim() || null, source: `environment variable ${rpcEnv}`, envName: rpcEnv };
}

export interface SecretNeedle {
  name: string;
  value: string;
}

/** Shortest needle that is scanned (shorter strings would match ordinary text). */
export const MIN_NEEDLE = 8;

/**
 * Strings that must never appear in a result: the URL itself, the URL without its scheme, the
 * host name and every host label, and every path segment, query value and user-info part of at
 * least MIN_NEEDLE characters (an API key usually sits in the path or query, with some
 * providers in the host name, as in <key>.provider.example).
 */
export function urlNeedles(url: string, name = "rpcUrl"): SecretNeedle[] {
  const out: SecretNeedle[] = [{ name, value: url }];
  try {
    const u = new URL(url);
    out.push({ name: `${name}:noScheme`, value: url.replace(/^[a-z]+:\/\//i, "") });
    // host name needles for internet DNS names only (an IP literal or a loopback or
    // local-network name carries no provider key, and appears in ordinary diagnostics)
    const host = u.hostname.replace(/^\[|\]$/g, "");
    if (!/^[0-9.]+$/.test(host) && !host.includes(":") && !isLoopbackHostname(host) && !isLanHostname(host)) {
      out.push({ name: `${name}:host`, value: host });
      for (const label of host.split(".")) if (label.length >= MIN_NEEDLE) out.push({ name: `${name}:hostLabel`, value: label });
    }
    if (u.username) out.push({ name: `${name}:user`, value: decodeURIComponent(u.username) });
    if (u.password) out.push({ name: `${name}:password`, value: decodeURIComponent(u.password) });
    for (const seg of u.pathname.split("/")) if (seg.length >= MIN_NEEDLE) out.push({ name: `${name}:path`, value: decodeURIComponent(seg) });
    for (const [, v] of u.searchParams) if (v.length >= MIN_NEEDLE) out.push({ name: `${name}:query`, value: v });
  } catch {
    /* not a URL: the whole string is the needle */
  }
  return out.filter((n) => n.value.length >= MIN_NEEDLE);
}

/** Needles for a long secret: the full text and its last 32 characters (key material, not a constant header). */
export function secretNeedles(name: string, value: string): SecretNeedle[] {
  const out: SecretNeedle[] = [];
  if (value.length >= MIN_NEEDLE) out.push({ name, value });
  if (value.length >= 64) out.push({ name: `${name}:tail`, value: value.slice(-32) });
  return out;
}

/** Names of the needles found in the text (empty when clean). */
export function findSecrets(text: string, needles: readonly SecretNeedle[]): string[] {
  const hits = new Set<string>();
  for (const n of needles) if (n.value.length >= MIN_NEEDLE && text.includes(n.value)) hits.add(n.name);
  return [...hits].sort();
}

/** Redact every needle in free text (errors, stderr tails), then the bench sanitizer. */
export function redactSecrets(text: string, needles: readonly SecretNeedle[]): string {
  let out = text;
  const sorted = [...needles].sort((a, b) => b.value.length - a.value.length);
  for (const n of sorted) if (n.value.length >= MIN_NEEDLE) out = out.split(n.value).join(`<${n.name.split(":")[0]}>`);
  return sanitize(out);
}

// ---------------------------------------------------------------------------------------
// state document (orchestrator -> child, stdin only)
// ---------------------------------------------------------------------------------------

export interface RegistryAddresses {
  didRegistry: string;
  accreditationRegistry: string;
  issuanceRootRegistry: string;
  verifierKemRegistry: string;
}

/** Circuit key of a run: label ("dev" until the ceremony) and absolute artifact paths on the runner (never written to results). */
export interface RunKey {
  label: string;
  wasm: string;
  zkey: string;
  vkey: string;
}

/** What a wallet and a verifier hold for one endpoint. Secret fields: wallet.holderSecret, verifier.kemPrivatePkcs8B64, endpoint.rpcUrl of a custom endpoint. */
export interface E2eStateDoc {
  schema: typeof SCHEMA.state;
  key: RunKey;
  endpoint: { id: string; kind: EndpointKind; rpcUrl: string; chainId: number; transport: Transport };
  setupId: string;
  registry: { addresses: RegistryAddresses; fromBlock: number };
  governancePkHex: string;
  wallet: {
    holderSecret: string;
    vc: { credential: Record<string, unknown> & { holderCommit: string; typeId: string }; credID: string; signature: string; leafIndex: number };
    issuerPkHex: string;
    leafIndex: number;
    blobB64: string;
  };
  verifier: { did: string; controller: string; origin: string; pkHex: string; kemPublicKeyHex: string; kemPrivatePkcs8B64: string };
  policy: { predicate: "age_gte"; threshold: number; typeId: string };
}

const HEX = /^[0-9a-f]+$/;
const ADDR = /^0x[0-9a-f]{40}$/;

/** Shape errors of a state document (empty when well formed). */
export function stateDocErrors(d: unknown): string[] {
  const e: string[] = [];
  const x = d as Partial<E2eStateDoc> | null;
  if (!x || typeof x !== "object") return ["state document is not an object"];
  if (x.schema !== SCHEMA.state) e.push("schema");
  const k = x.key;
  if (!k || typeof k.label !== "string" || !/^[A-Za-z0-9._ -]{1,40}$/.test(k.label) || typeof k.wasm !== "string" || typeof k.zkey !== "string" || typeof k.vkey !== "string") e.push("key");
  const ep = x.endpoint;
  if (!ep || typeof ep.id !== "string" || !ENDPOINT_KINDS.includes(ep.kind as EndpointKind) || typeof ep.rpcUrl !== "string" || !Number.isSafeInteger(ep.chainId)) e.push("endpoint");
  if (typeof x.setupId !== "string" || !/^[0-9a-f]{16,64}$/.test(x.setupId)) e.push("setupId");
  const reg = x.registry;
  if (!reg || !Number.isSafeInteger(reg.fromBlock) || !reg.addresses || !Object.values(reg.addresses).every((a) => typeof a === "string" && ADDR.test(a)) || Object.keys(reg.addresses).length !== 4) e.push("registry");
  if (typeof x.governancePkHex !== "string" || x.governancePkHex.length !== 2624 || !HEX.test(x.governancePkHex)) e.push("governancePkHex");
  const w = x.wallet;
  if (!w || typeof w.holderSecret !== "string" || !/^[0-9]+$/.test(w.holderSecret)) e.push("wallet.holderSecret");
  if (!w || !w.vc || typeof w.vc.credID !== "string" || typeof w.vc.credential?.holderCommit !== "string") e.push("wallet.vc");
  if (!w || typeof w.issuerPkHex !== "string" || w.issuerPkHex.length !== 2624) e.push("wallet.issuerPkHex");
  if (!w || !Number.isSafeInteger(w.leafIndex) || w.leafIndex < 0) e.push("wallet.leafIndex");
  if (!w || typeof w.blobB64 !== "string" || w.blobB64.length < 16) e.push("wallet.blobB64");
  const v = x.verifier;
  if (!v || typeof v.did !== "string" || !v.did.startsWith("did:pq:") || typeof v.controller !== "string" || !ADDR.test(v.controller) || typeof v.origin !== "string") e.push("verifier.identity");
  if (!v || typeof v.kemPublicKeyHex !== "string" || v.kemPublicKeyHex.length !== 2368 || typeof v.kemPrivatePkcs8B64 !== "string") e.push("verifier.kem");
  const p = x.policy;
  if (!p || p.predicate !== "age_gte" || !Number.isSafeInteger(p.threshold) || typeof p.typeId !== "string") e.push("policy");
  return e;
}

/** The secret needles of a state document. */
export function stateDocNeedles(d: E2eStateDoc): SecretNeedle[] {
  const out: SecretNeedle[] = [];
  out.push(...secretNeedles("holderSecret", d.wallet.holderSecret));
  out.push(...secretNeedles("holderSecretHex", BigInt(d.wallet.holderSecret).toString(16)));
  out.push(...secretNeedles("kemPrivateKey", d.verifier.kemPrivatePkcs8B64));
  out.push(...secretNeedles("kemPrivateKeyHex", Buffer.from(d.verifier.kemPrivatePkcs8B64, "base64").toString("hex")));
  if (d.endpoint.kind === "custom") out.push(...urlNeedles(d.endpoint.rpcUrl));
  return out;
}

// ---------------------------------------------------------------------------------------
// labels and device
// ---------------------------------------------------------------------------------------

/** The endpoint label of a transport (D-034: "loopback, same host" for a node on this machine's loopback). */
export function reachLabel(transport: Transport): string {
  if (transport.endsWith("-loopback")) return "loopback, same host";
  if (transport.endsWith("-lan")) return "local network, another host";
  return "public RPC endpoint over the internet";
}

/** D-034 labels carried by every record of a condition (the prover is named when it is not snarkJS, the wallet default). */
export function runLabels(transport: Transport, mode: Mode, keyLabel: string, prover: string = "snarkjs"): string[] {
  const out: string[] = [];
  out.push(reachLabel(transport));
  out.push(mode === "cold" ? "one-process cold" : "one-process warm");
  out.push("both parties in one process (transport bytes only, no wallet-verifier network)");
  if (keyLabel === "dev") out.push("dev key");
  else out.push(`key: ${keyLabel}`);
  if (prover !== "snarkjs") out.push(`prover: ${prover}`);
  return out;
}

/**
 * One environment per results root (E2E.md section 2): results/v4/e2e/ takes WSL2 runs only,
 * whether it is named by default or with --results-root; Windows runs are smoke runs only.
 * Returns the refusal text, or null when the run may write there.
 */
export function resultsRootRefusal(resultsRoot: string | undefined, smoke: boolean, envName: string): string | null {
  if (smoke) return null;
  if (envName === "windows") return "Windows runs of this series are smoke runs only (E2E.md section 2); use --smoke";
  const target = resultsRoot === undefined ? abs(E2E_RESULTS_REL) : path.resolve(resultsRoot);
  const wslRoot = abs(E2E_RESULTS_REL);
  const same = process.platform === "win32" ? target.toLowerCase() === wslRoot.toLowerCase() : target === wslRoot;
  if (same && envName !== "wsl2") {
    return `results/v4/e2e/ holds the WSL2 series only; a ${envName} run needs its own --results-root (devices: results/v4/e2e_device_<label>, via scripts/e2e/device_run.sh)`;
  }
  return null;
}

/**
 * The cold definition (E2E.md section 5): snarkJS's bn128 curve is not built before S1 in a
 * cold child. A cold result whose curve was already built is not a cold run: it becomes an error
 * record (errorKind "cold-definition"), so the slot is repeated.
 */
export function applyColdDefinition<T extends { ok: boolean; error: string | null; errorKind: string | null }>(res: T, curveBuiltBeforeS1: boolean): T {
  if (!curveBuiltBeforeS1 || !res.ok) return res;
  return { ...res, ok: false, errorKind: "cold-definition", error: "cold definition broken: the bn128 curve was already built before S1 (something built it during set-up)" };
}

export type CpuFamily = "x86" | "arm" | "unknown";

export function cpuFamilyOf(model: string): CpuFamily {
  if (/intel|amd|xeon|ryzen|epyc|pentium|celeron|core\(tm\)/i.test(model)) return "x86";
  if (/apple|arm|cortex|neoverse|snapdragon|qualcomm|kryo|ampere|graviton|mediatek|exynos|tensor/i.test(model)) return "arm";
  return "unknown";
}

/**
 * Heuristic emulation check: the process architecture disagrees with the CPU the OS reports
 * (for example an arm64 Node under QEMU user mode on an x86 laptop). A heuristic only, so a
 * non-x64 run also needs --device-label.
 */
export function emulationSuspected(arch: string, cpuModel: string): boolean {
  const fam = cpuFamilyOf(cpuModel);
  if (arch === "arm64" || arch === "arm") return fam === "x86";
  if (arch === "x64" || arch === "ia32") return fam === "arm";
  return false;
}

function linuxOsName(): string | null {
  try {
    const t = fs.readFileSync("/etc/os-release", "utf8");
    const m = /^PRETTY_NAME="?([^"\n]*)"?/m.exec(t);
    return m?.[1] ?? null;
  } catch {
    return null;
  }
}

export interface DeviceRecord {
  cpuModel: string;
  cpuFamily: CpuFamily;
  logicalCores: number;
  ramGiB: number;
  platform: string;
  arch: string;
  osName: string;
  kernel: string;
  wsl: boolean;
  node: string;
  openssl: string;
  v8: string;
  emulationSuspected: boolean;
  deviceLabel: string | null;
}

/** Device record with no usernames, hostnames or home paths (bench lib envInfo plus kernel, WSL and emulation facts). */
export function deviceRecord(deviceLabel?: string | null): DeviceRecord {
  const e = envInfo();
  const kernel = os.release();
  const wsl = process.platform === "linux" && (/microsoft/i.test(kernel) || !!process.env["WSL_DISTRO_NAME"]);
  return {
    cpuModel: e.cpuModel,
    cpuFamily: cpuFamilyOf(e.cpuModel),
    logicalCores: e.logicalCores,
    ramGiB: e.ramGiB,
    platform: e.platform,
    arch: e.arch,
    osName: process.platform === "linux" ? (linuxOsName() ?? e.osName) : e.osName,
    kernel,
    wsl,
    node: e.node,
    openssl: e.openssl,
    v8: e.v8,
    emulationSuspected: emulationSuspected(e.arch, e.cpuModel),
    deviceLabel: deviceLabel ? sanitize(deviceLabel).slice(0, 120) : null,
  };
}

export function environmentName(d: Pick<DeviceRecord, "platform" | "wsl">): string {
  return d.platform === "win32" ? "windows" : d.wsl ? "wsl2" : d.platform;
}

// ---------------------------------------------------------------------------------------
// power (devices)
// ---------------------------------------------------------------------------------------

export type PowerRule = "ac" | "record-only";

/** macOS: `pmset -g batt` (read-only); AC iff it reports "AC Power". */
export function parsePmset(text: string): { ac: boolean; code: string } {
  const src = /drawing from '([^']+)'/i.exec(text)?.[1] ?? "unknown";
  return { ac: /ac power/i.test(src), code: `pmset:${src}` };
}

/**
 * Android (Termux): the guard.ts Linux rule on /sys/class/power_supply (AC iff a Mains or USB
 * supply reports online = 1), when the files are readable; "unreadable" otherwise.
 */
function androidSysfsPower(utc: string): PowerReading {
  const base = "/sys/class/power_supply";
  try {
    const mains: string[] = [];
    let online = false;
    for (const e of fs.readdirSync(base)) {
      try {
        const type = fs.readFileSync(path.join(base, e, "type"), "utf8").trim();
        if (type === "Mains" || type.startsWith("USB")) {
          const on = fs.readFileSync(path.join(base, e, "online"), "utf8").trim();
          mains.push(`${type}:${on}`);
          if (on === "1") online = true;
        }
      } catch {
        /* entry without type/online */
      }
    }
    if (mains.length === 0) return { ac: false, code: "android:no-readable-mains-supply", source: "none", utc };
    return { ac: online, code: `android:${mains.join(",")}`, source: "none", utc };
  } catch {
    return { ac: false, code: "android:power-supply-unreadable", source: "none", utc };
  }
}

/**
 * Power reading for this series: guard.ts readPower() on Windows, WSL and Linux (unchanged
 * BENCH_PROTOCOL rule); on macOS the read-only `pmset -g batt`; on Android (Termux) the same
 * sysfs rule when readable; elsewhere no reading ("unsupported", not AC). With the rule
 * "record-only" (devices, E2E.md section 15) a reading never discards a run; it is recorded only.
 */
/** `ac` is the verdict the series uses; `acReading` is what the reading itself said. */
export function readPowerE2e(rule: PowerRule): PowerReading & { rule: PowerRule; counts: boolean; acReading: boolean } {
  let r: PowerReading;
  if (process.platform === "android") {
    r = androidSysfsPower(new Date().toISOString());
  } else if (process.platform === "darwin") {
    const utc = new Date().toISOString();
    try {
      const out = execFileSync("pmset", ["-g", "batt"], { encoding: "utf8", timeout: 30_000, stdio: ["ignore", "pipe", "ignore"] });
      const p = parsePmset(out);
      r = { ac: p.ac, code: p.code, source: "none", utc };
    } catch {
      r = { ac: false, code: "query-failed", source: "none", utc };
    }
  } else {
    r = readPower();
  }
  return { ...r, ac: rule === "record-only" ? true : r.ac, acReading: r.ac, rule, counts: rule === "ac" };
}

// ---------------------------------------------------------------------------------------
// testnet cost (estimates [S] from results/v4/scale/anchor.json)
// ---------------------------------------------------------------------------------------

/** Gas of the setup writes [M] on Anvil (Prague), results/v4/scale/anchor.json (E4); used here as estimates [S]. */
export const SETUP_GAS = Object.freeze({
  source: "results/v4/scale/anchor.json oneOffGas and publishEpoch.first (Anvil, Prague) [M], used as estimates [S]",
  deploy: 730693 + 509831 + 545846 + 518452,
  registerDidIssuer: 1110102,
  registerDidVerifier: 1175158,
  accreditation: 164406,
  kemKey: 220925,
  epoch: 145231,
  transfer: 21000,
});

/** LedgerV4.rawWrite's gas limit for an estimate (est + est/5 + 5000). */
export function rawWriteGasLimit(est: number): number {
  return est + Math.floor(est / 5) + 5000;
}

/** Gas limits a role account must be able to pay (each write's limit, plus one sweep transfer). */
export function roleGasBudgets(epochs = 2): Record<"governance" | "issuer" | "verifier", number> {
  return {
    governance: rawWriteGasLimit(SETUP_GAS.accreditation) + SETUP_GAS.transfer,
    issuer: rawWriteGasLimit(SETUP_GAS.registerDidIssuer) + epochs * rawWriteGasLimit(SETUP_GAS.epoch) + SETUP_GAS.transfer,
    verifier: rawWriteGasLimit(SETUP_GAS.registerDidVerifier) + rawWriteGasLimit(SETUP_GAS.kemKey) + SETUP_GAS.transfer,
  };
}

export interface CostEstimate {
  maxFeePerGasWei: string;
  margin: number;
  deployWei: string;
  fundingTransfersWei: string;
  roleFundingWei: Record<"governance" | "issuer" | "verifier", string>;
  totalWei: string;
  totalEth: number;
  basis: string;
}

/**
 * Upper-bound cost of one setup at a given maxFeePerGas: deployment (funder), three funding
 * transfers (funder) and the role balances the funder sends (each role must hold gas limit x
 * maxFeePerGas to send, times the margin). The role balances are mostly swept back at the end.
 */
export function estimateSetupCost(maxFeePerGasWei: bigint, margin = 1.3, epochs = 2): CostEstimate {
  const m = BigInt(Math.round(margin * 1000));
  const scale = (g: number) => (BigInt(g) * maxFeePerGasWei * m) / 1000n;
  const roles = roleGasBudgets(epochs);
  const deployWei = scale(SETUP_GAS.deploy);
  const fundingTransfersWei = scale(3 * SETUP_GAS.transfer);
  const roleWei = { governance: scale(roles.governance), issuer: scale(roles.issuer), verifier: scale(roles.verifier) };
  const total = deployWei + fundingTransfersWei + roleWei.governance + roleWei.issuer + roleWei.verifier;
  return {
    maxFeePerGasWei: maxFeePerGasWei.toString(),
    margin,
    deployWei: deployWei.toString(),
    fundingTransfersWei: fundingTransfersWei.toString(),
    roleFundingWei: { governance: roleWei.governance.toString(), issuer: roleWei.issuer.toString(), verifier: roleWei.verifier.toString() },
    totalWei: total.toString(),
    totalEth: Number(total) / 1e18,
    basis: `${SETUP_GAS.source}; gas limit = est + est/5 + 5000 per write (LedgerV4.rawWrite); ${epochs} epoch anchors budgeted for the issuer; x${margin} margin; role balances are swept back at the end`,
  };
}

// ---------------------------------------------------------------------------------------
// files, hashes, roots
// ---------------------------------------------------------------------------------------

export function abs(rel: string): string {
  return path.join(REPO_ROOT, ...rel.split("/"));
}

export function relOf(file: string): string {
  return path.relative(REPO_ROOT, file).split(path.sep).join("/");
}

/** <resultsRoot> (default results/v4/e2e); smoke output goes to <resultsRoot>/_smoke, which ignores itself. */
export function resolveRoot(resultsRoot: string | undefined, smoke: boolean): string {
  const base = resultsRoot ? path.resolve(resultsRoot) : abs(E2E_RESULTS_REL);
  if (!smoke) return base;
  const dir = path.join(base, SMOKE_DIR);
  fs.mkdirSync(dir, { recursive: true });
  // The smoke folder is never committed: it carries its own ignore file (the root
  // .gitignore entry is added separately).
  const gi = path.join(dir, ".gitignore");
  if (!fs.existsSync(gi)) fs.writeFileSync(gi, "# smoke output of harness/v4/e2e: never committed, never quoted\n*\n");
  return dir;
}

/** SHA-256 of a protocol document above its "## Deviations" heading (LF line ends), and of the whole file. */
export function docSha(rel: string): { normative: string; file: string } {
  const f = abs(rel);
  if (!fs.existsSync(f)) throw new Error(`${rel} missing: the protocol must exist before any run`);
  const text = fs.readFileSync(f, "utf8").replace(/\r\n/g, "\n");
  const cut = text.indexOf("\n## Deviations");
  if (cut < 0) throw new Error(`${rel} has no '## Deviations' section`);
  return { normative: sha256Hex(text.slice(0, cut)), file: sha256FileHex(f) };
}

export function protocolRecord(): Record<string, unknown> {
  const e2e = docSha(E2E_PROTOCOL_DOC);
  const bench = protocolSha();
  return {
    e2e: { doc: E2E_PROTOCOL_DOC, normativeSha256: e2e.normative, fileSha256: e2e.file },
    bench: { doc: "docs/v4/BENCH_PROTOCOL.md", normativeSha256: bench.normative, fileSha256: bench.file },
    basis: "normative = SHA-256 of the text above '## Deviations' with LF line ends; file = SHA-256 of the whole file",
  };
}

/** SHA-256 per file (repo-relative, forward slashes); missing files are recorded as null. */
export function hashFiles(rels: readonly string[]): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const r of rels) {
    const f = abs(r);
    out[r] = fs.existsSync(f) ? sha256FileHex(f) : null;
  }
  return out;
}

function listTs(dirRel: string): string[] {
  const d = abs(dirRel);
  if (!fs.existsSync(d)) return [];
  return fs
    .readdirSync(d)
    .filter((f) => f.endsWith(".ts"))
    .sort()
    .map((f) => `${dirRel}/${f}`);
}

/** Package sources and the registry contract (as the E4 header), plus the harness files of this series. */
export function codeHashes(): { sourceSha256: Record<string, string | null>; harnessSha256: Record<string, string | null> } {
  return {
    sourceSha256: hashFiles(["onchain/contracts/v4/RegistriesV4.sol", ...listTs("packages/v4/src")]),
    harnessSha256: hashFiles([
      ...listTs("harness/v4/e2e"),
      ...listTs("harness/v4/lib"),
      "harness/v4/bench/lib.ts",
      "harness/v4/bench/guard.ts",
      "scripts/e2e/analyze_e2e.py",
      "scripts/e2e/quiet_window_e2e_wsl.sh",
      "scripts/e2e/testnet_window.sh",
      "scripts/e2e/device_run.sh",
      "scripts/e2e/smoke_windows.sh",
      "scripts/besu/setup_qbft.sh",
      "scripts/wsl/besu_wsl_setup.sh",
    ]),
  };
}

export function packageVersion(name: string): string | null {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "node_modules", ...name.split("/"), "package.json"), "utf8")) as { version?: string };
    return pkg.version ?? null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------------------
// circuit key of a run
// ---------------------------------------------------------------------------------------

export interface KeySpec {
  /** "dev" for the dev key; the ceremony key's label after the ceremony (D-034). */
  label: string;
  wasm: ArtifactSpec;
  zkey: ArtifactSpec;
  vkey: ArtifactSpec;
}

/** The dev key of BENCH_PROTOCOL.md (setup/pins_v4.json), label "dev". */
export const DEV_KEY_SPEC: KeySpec = Object.freeze({ label: "dev", wasm: VERSIONS.v4.wasm, zkey: VERSIONS.v4.zkey, vkey: VERSIONS.v4.vkey });

function relSafe(r: unknown, what: string): string {
  if (typeof r !== "string" || r.length === 0 || path.isAbsolute(r) || /^[A-Za-z]:/.test(r) || r.split(/[\\/]/).includes("..")) throw new Error(`key spec: ${what} must be a repo-relative path`);
  return r.split("\\").join("/");
}

/**
 * The run's key: the dev key by default, or a key-spec JSON file (repo-relative) of the form
 * {"label": "...", "wasm": {"rel": "...", "pin": {"file": "...", "key": "..."}}, "zkey": {...}, "vkey": {...}}.
 * A key other than "dev" must have every artifact pinned. Each artifact is hashed and checked
 * against its pin (bench lib checkArtifact; a mismatch throws).
 */
export function loadKeySpec(specRel: string | undefined): { spec: KeySpec; source: string; artifacts: Record<"wasm" | "zkey" | "vkey", ArtifactRecord> } {
  if (!specRel) return checkKeySpec(DEV_KEY_SPEC, "default: dev key (harness/v4/bench/lib.ts VERSIONS.v4, setup/pins_v4.json)");
  const j = JSON.parse(fs.readFileSync(abs(relSafe(specRel, "--key-spec")), "utf8")) as unknown;
  return checkKeySpec(keySpecFromJson(j), specRel);
}

/** Parse a key-spec document (format in loadKeySpec's comment); paths must be repo-relative. */
export function keySpecFromJson(doc: unknown): KeySpec {
  const j = (doc ?? {}) as Record<string, unknown>;
  const art = (k: "wasm" | "zkey" | "vkey"): ArtifactSpec => {
    const a = j[k] as { rel?: unknown; pin?: { file?: unknown; key?: unknown } } | undefined;
    if (!a) throw new Error(`key spec: ${k} missing`);
    const out: ArtifactSpec = { rel: relSafe(a.rel, `${k}.rel`) };
    if (a.pin) {
      if (typeof a.pin.key !== "string") throw new Error(`key spec: ${k}.pin.key must be a string`);
      out.pin = { file: relSafe(a.pin.file, `${k}.pin.file`), key: a.pin.key };
    }
    return out;
  };
  const label = String(j["label"] ?? "");
  if (!/^[A-Za-z0-9._ -]{1,40}$/.test(label)) throw new Error("key spec: label must be 1 to 40 plain characters");
  const spec: KeySpec = { label, wasm: art("wasm"), zkey: art("zkey"), vkey: art("vkey") };
  if (label !== "dev" && ![spec.wasm, spec.zkey, spec.vkey].every((a) => a.pin)) throw new Error("key spec: a key other than dev must pin every artifact");
  return spec;
}

/**
 * Hash every artifact of a key and compare it with its pin (bench lib checkArtifact throws on a
 * mismatch). checkArtifact treats a pin key that is absent from its pin file as "not pinned"
 * without an error; this series requires every artifact to match an existing pin.
 */
export function checkKeySpec(spec: KeySpec, source: string): { spec: KeySpec; source: string; artifacts: Record<"wasm" | "zkey" | "vkey", ArtifactRecord> } {
  const artifacts = { wasm: checkArtifact(spec.wasm), zkey: checkArtifact(spec.zkey), vkey: checkArtifact(spec.vkey) };
  const unpinned = (Object.keys(artifacts) as Array<keyof typeof artifacts>).filter((k) => !artifacts[k].pinned);
  if (unpinned.length > 0) throw new Error(`key spec ${source}: no pin found for ${unpinned.join(", ")} (every artifact must match a committed pin)`);
  return { spec, source, artifacts };
}

export function runKeyOf(spec: KeySpec): RunKey {
  return { label: spec.label, wasm: abs(spec.wasm.rel), zkey: abs(spec.zkey.rel), vkey: abs(spec.vkey.rel) };
}

// ---------------------------------------------------------------------------------------
// child line protocol
// ---------------------------------------------------------------------------------------

/** Every line the child writes for the orchestrator starts with this prefix (other output is ignored). */
export const MSG_PREFIX = "E2E-MSG ";

export function parseMsgLines(text: string): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.startsWith(MSG_PREFIX)) continue;
    try {
      const j = JSON.parse(line.slice(MSG_PREFIX.length)) as unknown;
      if (j && typeof j === "object" && !Array.isArray(j)) out.push(j as Record<string, unknown>);
    } catch {
      /* not a message */
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------
// small numeric helpers
// ---------------------------------------------------------------------------------------

export function median(xs: readonly number[]): number | null {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const h = (s.length - 1) / 2;
  const lo = s[Math.floor(h)] as number;
  const hi = s[Math.ceil(h)] as number;
  return (lo + hi) / 2;
}

export function round3(x: number): number {
  return r3(x);
}
