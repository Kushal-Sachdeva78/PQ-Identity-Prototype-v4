import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import type { Socket } from "node:net";
import { PerformanceObserver } from "node:perf_hooks";
import nodeCrypto, { createPrivateKey, createHash, type KeyObject } from "node:crypto";
import { getPoseidon, holderCommit as computeHolderCommit } from "@pqid/common/encoding";
import { sha256File } from "@pqid/common/hash";
import { HolderWalletV4, type HeldCredentialV4 } from "@pqid/v4/wallet";
import { VerifierV4, type VerifierIdentity, type VerifyDecisionV4 } from "@pqid/v4/verifier";
import { parsePublication, publishedSource } from "@pqid/v4/published";
import { SystemClock } from "@pqid/v4/clock";
import { ML_DSA_44_SPKI_PREFIX, mlKemPublicKeyRawOf } from "@pqid/v4/pqc";
import type { LedgerV4 } from "@pqid/v4/ledger";
import type { ProofRequestV4, SessionReplyV4 } from "@pqid/v4/session";
import type { VerifiableCredentialV4 } from "@pqid/v4/issuer";
import type { ProverBackendV4 } from "@pqid/v4/prove";
import { connectClientLedger, traceProvider, TRACE_EPOCH_NS, type ClientLedger, type RpcTrace } from "../lib/rpc_trace.ts";
import {
  LEDGER_READS,
  computeReport,
  compactGc,
  compactPost,
  checkMarks,
  gcKindName,
  stageWindows,
  recordOuterCalls,
  round3,
  type E2eStateDoc,
  type GcEvent,
  type HookEvent,
  type HookKind,
  type LedgerCall,
  type Marks,
  type Party,
  type PartyPost,
  type PresentationReport,
} from "./lib.ts";

/**
 * One presentation of the shipped v4 code, end to end, with run-time instrumentation only
 * (docs/v4/E2E.md). Nothing in packages/ changes: the harness wraps instance methods of one
 * wallet, puts a Proxy in front of each party's LedgerV4, wraps node:crypto functions that
 * packages/v4/src/pqc.ts reads at call time, and traces each party's ethers provider with
 * harness/v4/lib/rpc_trace.ts (one HTTP POST = one _send call).
 *
 * Parties: one verifier and one wallet per endpoint, each with its own LedgerV4.connect (its
 * own as-shipped JsonRpcProvider) and its own HTTP agent pair. Both live in one process; the
 * process-wide http(s).globalAgent is switched to the party's agent at the party boundaries,
 * so each party keeps its own connection pool, as two processes would. The party agents copy
 * Node's global agent options (Node 24: keep-alive, a 5 s socket timeout). Before every warm
 * iteration the warm child replaces both parties' agents (resetAgents, untimed), so every warm
 * iteration opens its own connections as a cold run does and its connection state does not
 * depend on its place in the schedule (E2E.md section 5). New connections are recorded per POST
 * by the trace and per party by the agents.
 */

export const nowMs = (): number => Number(process.hrtime.bigint() - TRACE_EPOCH_NS) / 1e6;

// ---------------------------------------------------------------------------------------
// node:crypto hooks
// ---------------------------------------------------------------------------------------

type Fn = (...a: unknown[]) => unknown;

/** PerformanceObserver.takeRecords (Node 16+; missing from the repository's @types/node 22.10). */
function takeRecords(o: PerformanceObserver): PerformanceEntry[] {
  return (o as unknown as { takeRecords?: () => PerformanceEntry[] }).takeRecords?.() ?? [];
}

/**
 * Records ML-DSA verify and key import, ML-KEM encapsulate and decapsulate, and aes-256-gcm
 * createCipheriv calls, and V8 garbage collections (a perf_hooks observer on entry type "gc";
 * its entries arrive after the collection, so flushGc() waits two event-loop turns, untimed).
 */
export class CryptoHooks {
  events: HookEvent[] = [];
  gc: GcEvent[] = [];
  private orig: Record<string, Fn> | null = null;
  private gcObserver: PerformanceObserver | null = null;

  get installed(): boolean {
    return this.orig !== null;
  }

  private gcOffsetMs = 0;

  private takeGc(entries: readonly PerformanceEntry[]): void {
    for (const e of entries) {
      const detail = (e as PerformanceEntry & { detail?: { kind?: unknown } }).detail;
      this.gc.push({ start: e.startTime + this.gcOffsetMs, ms: e.duration, kind: gcKindName(detail?.kind) });
    }
  }

  install(): void {
    if (this.orig) return;
    const c = nodeCrypto as unknown as Record<string, Fn>;
    for (const k of ["verify", "createPublicKey", "encapsulate", "decapsulate", "createCipheriv"]) {
      if (typeof c[k] !== "function") throw new Error(`node:crypto.${k} is missing (needs Node 24.7+ with OpenSSL 3.5)`);
    }
    const orig = { verify: c["verify"] as Fn, createPublicKey: c["createPublicKey"] as Fn, encapsulate: c["encapsulate"] as Fn, decapsulate: c["decapsulate"] as Fn, createCipheriv: c["createCipheriv"] as Fn };
    this.orig = orig;
    // performance.now() (the gc entries' base) and the marks' clock (process.hrtime) are the
    // same monotonic clock: one offset converts between them
    this.gcOffsetMs = nowMs() - performance.now();
    this.gcObserver = new PerformanceObserver((list) => this.takeGc(list.getEntries()));
    this.gcObserver.observe({ entryTypes: ["gc"] });
    const ev = (kind: HookKind, f: Fn, self: unknown, a: unknown[]) => {
      const start = nowMs();
      try {
        return f.apply(self, a);
      } finally {
        this.events.push({ kind, start, end: nowMs() });
      }
    };
    const isMlDsaKey = (k: unknown) => k instanceof nodeCrypto.KeyObject && (k as KeyObject).asymmetricKeyType === ("ml-dsa-44" as never);
    const isMlDsaDer = (a: unknown) => {
      const key = (a as { key?: unknown } | null)?.key;
      return Buffer.isBuffer(key) && key.length > ML_DSA_44_SPKI_PREFIX.length && key.subarray(0, ML_DSA_44_SPKI_PREFIX.length).equals(ML_DSA_44_SPKI_PREFIX);
    };
    c["verify"] = function (this: unknown, ...a: unknown[]) {
      return isMlDsaKey(a[2]) ? ev("mlDsaVerify", orig.verify, this, a) : orig.verify.apply(this, a);
    };
    c["createPublicKey"] = function (this: unknown, ...a: unknown[]) {
      return isMlDsaDer(a[0]) ? ev("mlDsaImport", orig.createPublicKey, this, a) : orig.createPublicKey.apply(this, a);
    };
    c["encapsulate"] = function (this: unknown, ...a: unknown[]) {
      return ev("mlKemEncaps", orig.encapsulate, this, a);
    };
    c["decapsulate"] = function (this: unknown, ...a: unknown[]) {
      return ev("mlKemDecaps", orig.decapsulate, this, a);
    };
    c["createCipheriv"] = function (this: unknown, ...a: unknown[]) {
      return String(a[0]).toLowerCase() === "aes-256-gcm" ? ev("aesGcmCipher", orig.createCipheriv, this, a) : orig.createCipheriv.apply(this, a);
    };
  }

  uninstall(): void {
    if (!this.orig) return;
    const c = nodeCrypto as unknown as Record<string, Fn>;
    for (const [k, f] of Object.entries(this.orig)) c[k] = f;
    this.orig = null;
    if (this.gcObserver) {
      this.takeGc(takeRecords(this.gcObserver));
      this.gcObserver.disconnect();
      this.gcObserver = null;
    }
  }

  drain(): HookEvent[] {
    const out = this.events;
    this.events = [];
    return out;
  }

  /** Wait two event-loop turns (Node creates a gc entry in an immediate after the collection), then return and clear the collections seen. */
  async flushGc(): Promise<GcEvent[]> {
    await new Promise<void>((r) => setImmediate(r));
    await new Promise<void>((r) => setImmediate(r));
    if (this.gcObserver) this.takeGc(takeRecords(this.gcObserver));
    const out = this.gc;
    this.gc = [];
    return out;
  }

  /** Clear the collections seen so far (before a timed window). */
  dropGc(): void {
    if (this.gcObserver) takeRecords(this.gcObserver);
    this.gc = [];
  }
}

// ---------------------------------------------------------------------------------------
// HTTP agents per party
// ---------------------------------------------------------------------------------------

export interface PartyAgents {
  http: http.Agent;
  https: https.Agent;
  /** Connections this party's agents opened (time on the trace base). */
  connections: number[];
}

function agentOptions(a: http.Agent): http.AgentOptions {
  const o = (a as unknown as { options?: Record<string, unknown> }).options ?? {};
  const pick: http.AgentOptions = {};
  if (typeof o["keepAlive"] === "boolean") pick.keepAlive = o["keepAlive"];
  if (typeof o["keepAliveMsecs"] === "number") pick.keepAliveMsecs = o["keepAliveMsecs"];
  if (typeof o["timeout"] === "number") pick.timeout = o["timeout"];
  if (o["scheduling"] === "lifo" || o["scheduling"] === "fifo") pick.scheduling = o["scheduling"];
  if (typeof o["maxSockets"] === "number") pick.maxSockets = o["maxSockets"];
  if (typeof o["maxFreeSockets"] === "number") pick.maxFreeSockets = o["maxFreeSockets"];
  return pick;
}

/** Node's own global agents at module load (the party agents copy their options, never the swapped ones). */
const NODE_HTTP_AGENT = http.globalAgent;
const NODE_HTTPS_AGENT = https.globalAgent as unknown as http.Agent;

/**
 * A party's agents, configured as Node's own global agents (keep-alive on Node 24), counting new
 * connections. `onFree` is called when one of their sockets goes back to the pool (a POST ended).
 */
export function newPartyAgents(onFree?: () => void): PartyAgents {
  const connections: number[] = [];
  const h = new http.Agent(agentOptions(NODE_HTTP_AGENT));
  const s = new https.Agent(agentOptions(NODE_HTTPS_AGENT));
  for (const ag of [h, s] as http.Agent[]) {
    const orig = (ag as unknown as { createConnection: Fn }).createConnection;
    (ag as unknown as { createConnection: Fn }).createConnection = function (this: unknown, ...a: unknown[]) {
      connections.push(nowMs());
      return orig.apply(this, a) as Socket;
    };
    if (onFree) ag.on("free", () => onFree());
  }
  return { http: h, https: s, connections };
}

/** Make the party's agents the process-wide defaults (ethers' FetchRequest uses Node's global agents). */
export function useAgents(a: PartyAgents): void {
  (http as unknown as { globalAgent: http.Agent }).globalAgent = a.http;
  (https as unknown as { globalAgent: https.Agent }).globalAgent = a.https;
}

// ---------------------------------------------------------------------------------------
// parties
// ---------------------------------------------------------------------------------------

export interface PartySet {
  endpointId: string;
  kind: E2eStateDoc["endpoint"]["kind"];
  chainId: number;
  setupId: string;
  rpcUrl: string;
  keyLabel: string;
  policy: E2eStateDoc["policy"];
  wallet: HolderWalletV4;
  verifier: VerifierV4;
  walletClient: ClientLedger;
  verifierClient: ClientLedger;
  walletTrace: RpcTrace | null;
  verifierTrace: RpcTrace | null;
  walletProxy: LedgerV4;
  verifierProxy: LedgerV4;
  calls: LedgerCall[];
  agents: Record<Party, PartyAgents>;
  /** When each party's last POST ended (a socket went back to its pool), on the marks' time base; null before the first. */
  lastFreeMs: Record<Party, number | null>;
  /** Marks of the presentation in progress. */
  cur: Partial<Marks>;
  instrumented: boolean;
  build: { stateLoadMs: number; attachMs: number; verifierCtorMs: number; walletMs: number; blobBytes: number };
}

export class HolderCommitMismatch extends Error {
  constructor() {
    super("holderCommit mismatch: the holder secret does not open the credential's holderCommit");
    this.name = "HolderCommitMismatch";
  }
}

/**
 * Build one endpoint's verifier and wallet from a state document (untimed set-up). The wallet
 * is the shipped HolderWalletV4 with the holder's secret set at run time; the verifier identity
 * carries no ML-DSA signing key and no EVM account (verifyReply and newRequest use neither).
 */
export async function buildParties(doc: E2eStateDoc, opts: { prover?: ProverBackendV4; instrument?: boolean } = {}): Promise<PartySet> {
  const t0 = nowMs();
  const blob = Buffer.from(doc.wallet.blobB64, "base64");
  const pub = await parsePublication(new Uint8Array(blob.buffer, blob.byteOffset, blob.byteLength));
  const stateLoadMs = nowMs() - t0;

  const t1 = nowMs();
  const url = doc.endpoint.rpcUrl;
  const redact = [url];
  const verifierClient = await connectClientLedger(url, doc.registry.addresses, doc.registry.fromBlock, "asShipped", { trace: { label: "verifier", redact } });
  let walletClient: ClientLedger;
  try {
    walletClient = await connectClientLedger(url, doc.registry.addresses, doc.registry.fromBlock, "asShipped", { trace: { label: "wallet", redact } });
  } catch (e) {
    verifierClient.ledger.destroy();
    throw e;
  }
  const attachMs = nowMs() - t1;
  try {
    return await buildPartiesOn(doc, opts, { verifierClient, walletClient, pub, blobBytes: blob.length, stateLoadMs, attachMs });
  } catch (e) {
    verifierClient.ledger.destroy();
    walletClient.ledger.destroy();
    throw e;
  }
}

async function buildPartiesOn(
  doc: E2eStateDoc,
  opts: { prover?: ProverBackendV4; instrument?: boolean },
  c: { verifierClient: ClientLedger; walletClient: ClientLedger; pub: Awaited<ReturnType<typeof parsePublication>>; blobBytes: number; stateLoadMs: number; attachMs: number }
): Promise<PartySet> {
  const { verifierClient, walletClient, pub, stateLoadMs, attachMs } = c;
  const url = doc.endpoint.rpcUrl;

  const calls: LedgerCall[] = [];
  const verifierProxy = recordOuterCalls(verifierClient.ledger, "verifier", LEDGER_READS, calls, nowMs);
  const walletProxy = recordOuterCalls(walletClient.ledger, "wallet", LEDGER_READS, calls, nowMs);

  const governancePk = Buffer.from(doc.governancePkHex, "hex");
  const kemPublicKey = Buffer.from(doc.verifier.kemPublicKeyHex, "hex");
  const kemPrivate = createPrivateKey({ key: Buffer.from(doc.verifier.kemPrivatePkcs8B64, "base64"), format: "der", type: "pkcs8" });
  if (!mlKemPublicKeyRawOf(kemPrivate).equals(kemPublicKey)) throw new Error("state document: the verifier's ML-KEM private key does not match its public key");

  const t2 = nowMs();
  const identity: VerifierIdentity = {
    label: "e2e-verifier",
    did: doc.verifier.did,
    pk: Buffer.from(doc.verifier.pkHex, "hex"),
    sk: null as unknown as KeyObject,
    kem: { publicKey: kemPublicKey, privateKey: kemPrivate },
    account: null as unknown as VerifierIdentity["account"],
    controller: doc.verifier.controller,
    origin: doc.verifier.origin,
  };
  const vkey = JSON.parse(fs.readFileSync(doc.key.vkey, "utf8")) as unknown;
  const verifier = new VerifierV4({ ledger: verifierProxy, identity, pinnedGovernancePk: governancePk, clock: SystemClock, vkey });
  const verifierCtorMs = nowMs() - t2;

  const t3 = nowMs();
  const ps = {} as PartySet;
  const wallet = await HolderWalletV4.create({
    ledger: walletProxy,
    clock: SystemClock,
    pinnedGovernancePk: governancePk,
    prover: opts.prover ?? "snarkjs",
    artifacts: { wasm: doc.key.wasm, zkey: doc.key.zkey, keyLabel: doc.key.label },
  });
  const secret = BigInt(doc.wallet.holderSecret);
  (wallet as unknown as { holderSecret: bigint }).holderSecret = secret;
  wallet.holderCommit = computeHolderCommit(await getPoseidon(), secret);
  if (wallet.holderCommit.toString() !== doc.wallet.vc.credential.holderCommit) throw new HolderCommitMismatch();
  const held: HeldCredentialV4 = {
    vc: doc.wallet.vc as unknown as VerifiableCredentialV4,
    issuerPk: Buffer.from(doc.wallet.issuerPkHex, "hex"),
    source: publishedSource(pub, new Map([[doc.wallet.vc.credID, doc.wallet.leafIndex]])),
  };
  wallet.add(held);
  const walletMs = nowMs() - t3;

  Object.assign(ps, {
    endpointId: doc.endpoint.id,
    kind: doc.endpoint.kind,
    chainId: doc.endpoint.chainId,
    setupId: doc.setupId,
    rpcUrl: url,
    keyLabel: doc.key.label,
    policy: doc.policy,
    wallet,
    verifier,
    walletClient,
    verifierClient,
    walletTrace: walletClient.trace,
    verifierTrace: verifierClient.trace,
    walletProxy,
    verifierProxy,
    calls,
    agents: { verifier: newPartyAgents(() => (ps.lastFreeMs.verifier = nowMs())), wallet: newPartyAgents(() => (ps.lastFreeMs.wallet = nowMs())) },
    lastFreeMs: { verifier: null, wallet: null },
    cur: {},
    instrumented: true,
    build: { stateLoadMs: round3(stateLoadMs), attachMs: round3(attachMs), verifierCtorMs: round3(verifierCtorMs), walletMs: round3(walletMs), blobBytes: c.blobBytes },
  } satisfies PartySet);
  installWalletMarks(ps);
  if (opts.instrument === false) setInstrumented(ps, false);
  return ps;
}

/** Instance wrappers on the wallet (checkRequest end, checkIssuerData start and end) and the input mark. */
function installWalletMarks(ps: PartySet): void {
  const proto = HolderWalletV4.prototype;
  const w = ps.wallet as unknown as Record<string, unknown>;
  w["checkRequest"] = async function (this: HolderWalletV4, ...a: Parameters<HolderWalletV4["checkRequest"]>) {
    try {
      return await proto.checkRequest.apply(this, a);
    } finally {
      ps.cur.checkRequestEnd = nowMs();
    }
  };
  w["checkIssuerData"] = async function (this: HolderWalletV4, ...a: Parameters<HolderWalletV4["checkIssuerData"]>) {
    ps.cur.issuerStart = nowMs();
    try {
      return await proto.checkIssuerData.apply(this, a);
    } finally {
      ps.cur.issuerEnd = nowMs();
    }
  };
  // The input mark: records the time only; it never reads or changes the circuit input.
  ps.wallet.cfg.inputHook = () => {
    ps.cur.inputMark = nowMs();
  };
}

function removeWalletMarks(ps: PartySet): void {
  const w = ps.wallet as unknown as Record<string, unknown>;
  delete w["checkRequest"];
  delete w["checkIssuerData"];
  ps.wallet.cfg.inputHook = undefined;
}

/**
 * Switch a party set between the instrumented configuration and the uninstrumented control
 * (plain ledgers, no traces, no wrappers; the caller uninstalls the crypto hooks).
 */
export function setInstrumented(ps: PartySet, on: boolean): void {
  if (ps.instrumented === on) return;
  if (on) {
    ps.wallet.cfg.ledger = ps.walletProxy;
    ps.verifier.opts.ledger = ps.verifierProxy;
    ps.walletTrace = traceProvider(ps.walletClient.provider, { label: "wallet", redact: [ps.rpcUrl] });
    ps.verifierTrace = traceProvider(ps.verifierClient.provider, { label: "verifier", redact: [ps.rpcUrl] });
    installWalletMarks(ps);
  } else {
    ps.wallet.cfg.ledger = ps.walletClient.ledger;
    ps.verifier.opts.ledger = ps.verifierClient.ledger;
    ps.walletTrace?.detach();
    ps.verifierTrace?.detach();
    ps.walletTrace = null;
    ps.verifierTrace = null;
    removeWalletMarks(ps);
  }
  ps.instrumented = on;
}

/**
 * Warm connection state (E2E.md section 5): replace both parties' agents with new ones (their old
 * sockets are destroyed), so the next presentation opens its own connections whatever its place
 * in the schedule. Untimed; called by the warm child before every iteration, instrumented and
 * control alike. Returns, per party, the ms since its last POST ended (null before the first).
 */
export function resetAgents(ps: PartySet): Record<Party, number | null> {
  const t = nowMs();
  const idle = {
    verifier: ps.lastFreeMs.verifier === null ? null : round3(t - ps.lastFreeMs.verifier),
    wallet: ps.lastFreeMs.wallet === null ? null : round3(t - ps.lastFreeMs.wallet),
  };
  for (const party of ["verifier", "wallet"] as const) {
    const old = ps.agents[party];
    old.http.destroy();
    old.https.destroy();
    ps.agents[party] = newPartyAgents(() => (ps.lastFreeMs[party] = nowMs()));
  }
  // Node's own agents stay the process default between presentations
  (http as unknown as { globalAgent: http.Agent }).globalAgent = NODE_HTTP_AGENT;
  (https as unknown as { globalAgent: https.Agent }).globalAgent = NODE_HTTPS_AGENT as unknown as https.Agent;
  return idle;
}

/** true once snarkJS (ffjavascript) has built its bn128 curve in this process (globalThis.curve_bn128 is set then). */
export function curveBuilt(): boolean {
  return Boolean((globalThis as { curve_bn128?: unknown }).curve_bn128);
}

export function destroyParties(ps: PartySet): void {
  try {
    ps.walletClient.ledger.destroy();
  } catch {
    /* already destroyed */
  }
  try {
    ps.verifierClient.ledger.destroy();
  } catch {
    /* already destroyed */
  }
  for (const a of Object.values(ps.agents)) {
    a.http.destroy();
    a.https.destroy();
  }
}

// ---------------------------------------------------------------------------------------
// one presentation
// ---------------------------------------------------------------------------------------

export interface IterationResult {
  ok: boolean;
  instrumented: boolean;
  error: string | null;
  /** Where it failed: "wallet" (refusal or proof failure), "verifier" (decision not accepted), "rpc" (failed POST, JSON-RPC error or HTTP 429), "marks". */
  errorKind: string | null;
  decision: { accepted: boolean; failedChecks: string[]; notEvaluated: string[]; reasons: string[] } | null;
  endToEndMs: number;
  agentSwitchMs: number;
  report: PresentationReport | null;
  posts: Array<Record<string, unknown>> | null;
  connections: Record<Party, number>;
  /** Garbage collections that started inside the timed window (instrumented iterations; null for a control). */
  gc: Array<{ stage: string | null; tStartMs: number; ms: number; kind: string }> | null;
  bytes: { request: number; reply: number; proof: number | null };
  publicSignalsSha256: string | null;
  /** Kept in memory for the untimed isolated verify; never written. */
  proofForIsolatedVerify?: { proof: unknown; publicSignals: string[] };
}

function errText(e: unknown): string {
  const x = e as { name?: string; message?: string } | null;
  return `${x?.name ?? "Error"}: ${String(x?.message ?? e)}`.split("\n")[0]!.slice(0, 400);
}

/**
 * Run one presentation: S1 verifier request, S2 request transport, S3 to S9 inside the
 * wallet's present(), S10 reply transport, S11 verifyReply. Instrumented iterations compute the
 * per-stage report; a control iteration (setInstrumented(ps, false) and hooks uninstalled)
 * yields endToEndMs only.
 */
export async function runPresentation(ps: PartySet, hooks: CryptoHooks): Promise<IterationResult> {
  const inst = ps.instrumented;
  if (inst !== hooks.installed) throw new Error("crypto hooks must be installed exactly for instrumented iterations");
  ps.cur = {};
  hooks.drain();
  if (inst) hooks.dropGc();
  ps.calls.length = 0;
  ps.walletTrace?.drain();
  ps.verifierTrace?.drain();
  const connBefore = { verifier: ps.agents.verifier.connections.length, wallet: ps.agents.wallet.connections.length };
  const m = ps.cur;
  const policy = { predicate: ps.policy.predicate, threshold: ps.policy.threshold, typeId: ps.policy.typeId };

  let request: ProofRequestV4 | null = null;
  let reply: SessionReplyV4 | null = null;
  let presentation: { proof: unknown; publicSignals: string[] } | null = null;
  let decision: VerifyDecisionV4 | null = null;
  let error: string | null = null;
  let errorKind: string | null = null;
  let reqBytes = 0;
  let replyBytes = 0;

  // ---- timed window (S1 to S11) ----
  useAgents(ps.agents.verifier);
  m.s1Start = nowMs();
  try {
    request = await ps.verifier.newRequest(policy);
  } catch (e) {
    error = errText(e);
    errorKind = "verifier";
  }
  m.s1End = nowMs();
  if (request) {
    useAgents(ps.agents.wallet);
    m.s2Start = nowMs();
    const reqJson = JSON.stringify(request);
    const parsed = JSON.parse(reqJson) as ProofRequestV4;
    reqBytes = Buffer.byteLength(reqJson, "utf8");
    m.s2End = nowMs();
    try {
      const r = await ps.wallet.present(parsed);
      reply = r.reply;
      presentation = { proof: r.presentation.proof, publicSignals: r.presentation.publicSignals };
    } catch (e) {
      error = errText(e);
      errorKind = "wallet";
    }
    m.presentEnd = nowMs();
    useAgents(ps.agents.verifier);
    if (reply) {
      m.s10Start = nowMs();
      const replyJson = JSON.stringify(reply);
      replyBytes = Buffer.byteLength(replyJson, "utf8");
      m.s10End = nowMs();
      try {
        // verifierOpenReply accepts the reply as a JSON string (what a transport delivers)
        decision = await ps.verifier.verifyReply(replyJson as unknown as SessionReplyV4);
      } catch (e) {
        error = errText(e);
        errorKind = "verifier";
      }
      m.s11End = nowMs();
    }
  }
  // ---- end of the timed window ----

  const connections = { verifier: ps.agents.verifier.connections.length - connBefore.verifier, wallet: ps.agents.wallet.connections.length - connBefore.wallet };
  const events = hooks.drain();
  const gcEvents = inst ? await hooks.flushGc() : [];
  const vPosts = ps.verifierTrace?.drain() ?? [];
  const wPosts = ps.walletTrace?.drain() ?? [];
  const posts: PartyPost[] = [...vPosts.map((p) => ({ ...p, party: "verifier" as const })), ...wPosts.map((p) => ({ ...p, party: "wallet" as const }))].sort((a, b) => a.tStartMs - b.tStartMs);

  if (decision && !error) {
    const allTrue = decision.accepted && decision.failedChecks.length === 0 && decision.notEvaluated.length === 0;
    if (!allTrue) {
      error = `decision not accepted: failed ${decision.failedChecks.join(",") || "-"}; not evaluated ${decision.notEvaluated.join(",") || "-"}; ${decision.reasons.join("; ").slice(0, 300)}`;
      errorKind = "verifier";
    }
  }

  let report: PresentationReport | null = null;
  let endToEndMs = NaN;
  let agentSwitchMs = 0;
  if (inst && !error) {
    // the seal mark: the first aes-256-gcm createCipheriv at or after the input mark
    const inputMark = m.inputMark;
    const seal = inputMark === undefined ? undefined : events.find((e) => e.kind === "aesGcmCipher" && e.start >= inputMark);
    if (seal) m.sealMark = seal.start;
    try {
      checkMarks(m);
      report = computeReport(m, events, ps.calls, posts, gcEvents);
      endToEndMs = report.endToEndMs;
      agentSwitchMs = report.agentSwitchMs;
      if (report.totals.failedPosts > 0 || report.totals.rpcErrors > 0 || report.totals.http429 > 0) {
        error = `RPC trouble: ${report.totals.failedPosts} failed POSTs, ${report.totals.rpcErrors} JSON-RPC errors, ${report.totals.http429} HTTP 429`;
        errorKind = "rpc";
      }
    } catch (e) {
      error = errText(e);
      errorKind = "marks";
    }
  } else if (!error && m.s11End !== undefined && m.s1Start !== undefined && m.s1End !== undefined && m.s2Start !== undefined && m.presentEnd !== undefined && m.s10Start !== undefined) {
    agentSwitchMs = m.s2Start - m.s1End + (m.s10Start - m.presentEnd);
    endToEndMs = m.s11End - m.s1Start - agentSwitchMs;
  }

  const windows = report && m.sealMark !== undefined ? stageWindows(m as Marks) : null;
  const proofJson = presentation ? JSON.stringify(presentation.proof) : null;
  const res: IterationResult = {
    ok: error === null,
    instrumented: inst,
    error,
    errorKind,
    decision: decision ? { accepted: decision.accepted, failedChecks: [...decision.failedChecks], notEvaluated: [...decision.notEvaluated], reasons: decision.reasons.map((r) => r.slice(0, 200)) } : null,
    endToEndMs: Number.isFinite(endToEndMs) ? round3(endToEndMs) : NaN,
    agentSwitchMs: round3(agentSwitchMs),
    report,
    posts: inst ? posts.map((p) => compactPost(p, windows)) : null,
    connections,
    gc: report ? compactGc(gcEvents, m as Marks) : null,
    bytes: { request: reqBytes, reply: replyBytes, proof: proofJson ? Buffer.byteLength(proofJson, "utf8") : null },
    publicSignalsSha256: presentation ? createHash("sha256").update(JSON.stringify(presentation.publicSignals)).digest("hex") : null,
  };
  if (presentation) Object.defineProperty(res, "proofForIsolatedVerify", { value: presentation, enumerable: false });
  return res;
}

// ---------------------------------------------------------------------------------------
// untimed probes after a cold run
// ---------------------------------------------------------------------------------------

async function rawCall(url: string, method: string, params: unknown[]): Promise<{ ms: number; result: unknown; ok: boolean; status: number }> {
  const t = nowMs();
  try {
    const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    const j = (await res.json()) as { result?: unknown; error?: unknown };
    return { ms: round3(nowMs() - t), result: j.result ?? null, ok: res.ok && j.error === undefined, status: res.status };
  } catch {
    return { ms: round3(nowMs() - t), result: null, ok: false, status: 0 };
  }
}

/**
 * Raw round trips through fetch (its own undici pool, not the parties' agents): 5 x
 * eth_blockNumber, then eth_getBlockByNumber("latest"). latestBlockAgeSec = local wall clock
 * minus the latest block's timestamp; for an endpoint with regular blocks it bounds the clock
 * offset to the chain (Anvil mines only on transactions, so there it is the time since the last
 * transaction).
 */
export async function rttProbe(url: string): Promise<{ blockNumberMs: number[]; getBlockMs: number | null; latestBlockAgeSec: number | null; errors: number }> {
  const blockNumberMs: number[] = [];
  let errors = 0;
  for (let i = 0; i < 5; i++) {
    const r = await rawCall(url, "eth_blockNumber", []);
    blockNumberMs.push(r.ms);
    if (!r.ok) errors++;
  }
  const b = await rawCall(url, "eth_getBlockByNumber", ["latest", false]);
  let latestBlockAgeSec: number | null = null;
  if (b.ok && b.result && typeof (b.result as { timestamp?: unknown }).timestamp === "string") {
    latestBlockAgeSec = round3(Date.now() / 1000 - Number(BigInt((b.result as { timestamp: string }).timestamp)));
  } else errors++;
  return { blockNumberMs, getBlockMs: b.ms, latestBlockAgeSec, errors };
}

/**
 * Time one SHA-256 of the zkey file with the shipped helper (packages/common sha256File, which
 * proveV4's snarkJS path calls on every proof inside S8), untimed relative to the presentation:
 * the share of S8 that is the zkey hash [S] (the OS file cache is warm, as it is inside S8).
 */
export function timeZkeySha256(zkeyFile: string): { ms: number; bytes: number } {
  const t = nowMs();
  sha256File(zkeyFile);
  return { ms: round3(nowMs() - t), bytes: fs.statSync(zkeyFile).size };
}

/** snarkjs.groth16.verify of the same proof, timed (the curve is already built in this process). */
export async function isolatedVerify(proof: unknown, publicSignals: string[], vkeyFile: string): Promise<{ ms: number; verified: boolean }> {
  const vkey = JSON.parse(fs.readFileSync(vkeyFile, "utf8")) as unknown;
  const snarkjs = await import("snarkjs");
  const t = nowMs();
  const verified = await snarkjs.groth16.verify(vkey as never, publicSignals as never, proof as never);
  return { ms: round3(nowMs() - t), verified };
}
