import type http from "node:http";
import type net from "node:net";
import dc from "node:diagnostics_channel";
import {
  JsonRpcProvider,
  Network,
  FetchRequest,
  version as ETHERS_VERSION,
  type BaseContract,
  type FetchGetUrlFunc,
  type GetUrlResponse,
  type JsonRpcApiProviderOptions,
  type JsonRpcError,
  type JsonRpcPayload,
  type JsonRpcResult,
} from "ethers";
import type { LedgerV4, RegistryAddressesV4 } from "@pqid/v4/ledger";
import { sanitize } from "../bench/lib.ts";

/**
 * One definition of a JSON-RPC round trip for the chain-read, robustness and end-to-end
 * harnesses (DECISIONS D-034), and the client variants they measure.
 *
 * ROUND TRIP: one HTTP POST, which is one call of the provider's `_send` (ethers 6.13.4
 * JsonRpcApiProvider). This includes ethers' own network-detection requests: the eth_chainId
 * that rides in the request queue with other requests, and the eth_chainId that ethers sends
 * directly through `_send` when getNetwork() runs before the provider has started. A REQUEST is
 * one JSON-RPC payload element; a POST carries one (a single object) or several (a JSON array).
 *
 * How it works, at run time and per instance (no package change): the tracer replaces three
 * methods on one JsonRpcProvider object and puts them back on detach().
 *  - send(method, params): stamps the time each request enters ethers' queue.
 *  - _send(payload): one record per call: start and end time, payload size, methods, queue
 *    delay per element, outcome, JSON-RPC errors in the response.
 *  - _getConnection(): wraps the FetchRequest's getUrl function of that one POST, so the
 *    record also has the transport attempts (FetchRequest retries a throttled request, HTTP
 *    429, inside one `_send`; a 301 or 302 answer to a POST is not followed and makes the POST
 *    fail), status codes, bytes sent, response body bytes after content decoding (ethers
 *    gunzips a gzip body, so this is not the byte count on the wire), the response
 *    Content-Encoding, the HTTP time, and per attempt whether it opened a new TCP connection.
 * New TCP connections are seen through Node's diagnostics channels (no Node module is
 * patched): "net.client.socket" stamps every client socket when net.connect creates it, and
 * "http.client.request.created" hands over the ClientRequest that ethers' getUrl creates
 * synchronously inside the attempt. An attempt opened a new connection when the socket it got
 * was created during that attempt (fallback: Node's request.reusedSocket). This covers Node's
 * global agent, an agent swapped in as http.globalAgent and the dedicated agents of variants,
 * whatever wrappers sit on their createConnection.
 * The clock is process.hrtime.bigint(); times are ms since the trace epoch (shared by every
 * trace in the process unless one is given). TRACE_EPOCH_UTC is the wall-clock time of that
 * epoch, to line traces up with host events (wall and monotonic clocks drift apart when the
 * host sleeps).
 *
 * Importing this module loads ethers only (no solc, no snarkJS), so an end-to-end cold run
 * can import it before its proving stage.
 */

export const EXPECTED_ETHERS_VERSION = "6.13.4";

export const ROUND_TRIP_DEFINITION =
  "round trip = one HTTP POST = one call of the provider's _send (ethers 6.13.4), including ethers' network-detection eth_chainId (queued or sent directly before the provider has started); request = one JSON-RPC payload element; transport retries inside one _send (HTTP 429 throttling) are recorded as http.attempts, not as extra round trips; a 301/302 is not followed for a POST and makes the POST fail";

/** Process-wide default epoch of trace times. */
export const TRACE_EPOCH_NS: bigint = process.hrtime.bigint();
/** Wall-clock (UTC) time of TRACE_EPOCH_NS, read in the same instant. */
export const TRACE_EPOCH_UTC: string = new Date().toISOString();

const nsToMs = (ns: bigint) => Number(ns) / 1e6;

const TRACED = Symbol.for("pqid.v4.rpcTrace");

type Params = unknown[] | Record<string, unknown>;
interface ProviderInternals {
  send: (method: string, params: Params) => Promise<unknown>;
  _send: (payload: JsonRpcPayload | JsonRpcPayload[]) => Promise<Array<JsonRpcResult | JsonRpcError>>;
  _getConnection?: () => FetchRequest;
  _getOption: (key: string) => unknown;
  [TRACED]?: RpcTrace;
}

/** Throws unless ethers is the version whose internals this module wraps. */
export function assertEthers(): void {
  if (ETHERS_VERSION !== EXPECTED_ETHERS_VERSION) {
    throw new Error(`ethers ${ETHERS_VERSION} found; harness/v4/lib/rpc_trace.ts wraps the internals of ${EXPECTED_ETHERS_VERSION}: re-check _send, send and _getConnection before use`);
  }
  const proto = JsonRpcProvider.prototype as unknown as Partial<ProviderInternals>;
  for (const k of ["send", "_send", "_getConnection", "_getOption"] as const) {
    if (typeof proto[k] !== "function") throw new Error(`ethers JsonRpcProvider.prototype.${k} is missing: update harness/v4/lib/rpc_trace.ts`);
  }
}

// ---------------------------------------------------------------------------------------
// client variants
// ---------------------------------------------------------------------------------------

export interface ClientVariantSpec {
  name: string;
  shipped: boolean;
  /** D-034: every non-shipped client is reported as "variant, not shipped". */
  label: "as shipped" | "variant, not shipped";
  /** ethers options set on top of the shipped ones (cacheTimeout -1, pollingInterval 100). */
  options: { staticNetwork?: true; batchStallTime?: number; batchMaxCount?: number };
  description: string;
}

/** Exactly what packages/v4/src/ledger.ts makeProvider builds. */
export const AS_SHIPPED: ClientVariantSpec = Object.freeze({
  name: "asShipped",
  shipped: true,
  label: "as shipped",
  options: Object.freeze({}),
  description:
    "packages/v4/src/ledger.ts makeProvider: new JsonRpcProvider(url, undefined, { cacheTimeout: -1 }) and pollingInterval 100; ethers defaults otherwise (no staticNetwork, so an eth_chainId with every call; batchStallTime 10 ms; batchMaxCount 100); Node's global HTTP agent",
}) as ClientVariantSpec;

/** A measured client variant that the shipped code does not use. */
export function defineClientVariant(name: string, options: ClientVariantSpec["options"], description: string): ClientVariantSpec {
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,40}$/.test(name)) throw new Error(`bad variant name ${name}`);
  if (name === AS_SHIPPED.name) throw new Error("asShipped is the shipped client; a variant needs another name");
  if (options.batchStallTime !== undefined && !(Number.isInteger(options.batchStallTime) && options.batchStallTime >= 0)) throw new Error("batchStallTime must be an integer >= 0");
  if (options.batchMaxCount !== undefined && !(Number.isInteger(options.batchMaxCount) && options.batchMaxCount >= 1)) throw new Error("batchMaxCount must be an integer >= 1");
  return Object.freeze({ name, shipped: false, label: "variant, not shipped", options: Object.freeze({ ...options }), description }) as ClientVariantSpec;
}

export const CLIENT_VARIANTS = Object.freeze({
  asShipped: AS_SHIPPED,
  staticNetwork: defineClientVariant(
    "staticNetwork",
    { staticNetwork: true },
    "as shipped plus the ethers v6 option staticNetwork with the network given (chain id read once, untimed): no eth_chainId before each call (D-034 reading of 'static network')"
  ),
  noBatchStall: defineClientVariant("noBatchStall", { batchStallTime: 0 }, "as shipped with batchStallTime 0 (requests leave on the next timer turn instead of after the 10 ms batching stall)"),
});
export type ClientVariantName = keyof typeof CLIENT_VARIANTS;

export interface ClientOptions {
  /**
   * Chain id for staticNetwork variants (required there, ignored otherwise). createClientProvider
   * takes it as given; connectClientLedger checks it against the node's eth_chainId first.
   */
  chainId?: number | bigint;
  /** Dedicated HTTP agent (variants only; the shipped client uses Node's global agent). */
  agent?: http.Agent;
}

function specOf(variant: ClientVariantName | ClientVariantSpec): ClientVariantSpec {
  const spec = typeof variant === "string" ? (CLIENT_VARIANTS as Record<string, ClientVariantSpec>)[variant] : variant;
  if (!spec) throw new Error(`unknown client variant ${String(variant)}; known: ${Object.keys(CLIENT_VARIANTS).join(", ")}`);
  return spec;
}

/** A JsonRpcProvider for one client variant. */
export function createClientProvider(variant: ClientVariantName | ClientVariantSpec, url: string, opts: ClientOptions = {}): JsonRpcProvider {
  assertEthers();
  const spec = specOf(variant);
  if (spec.shipped) {
    if (opts.agent) throw new Error("asShipped uses Node's global HTTP agent, as LedgerV4 does; pass no agent");
    // packages/v4/src/ledger.ts makeProvider, verbatim
    const provider = new JsonRpcProvider(url, undefined, { cacheTimeout: -1 });
    provider.pollingInterval = 100;
    return provider;
  }
  const o: JsonRpcApiProviderOptions = { cacheTimeout: -1 };
  if (spec.options.batchStallTime !== undefined) o.batchStallTime = spec.options.batchStallTime;
  if (spec.options.batchMaxCount !== undefined) o.batchMaxCount = spec.options.batchMaxCount;
  let network: Network | undefined;
  if (spec.options.staticNetwork) {
    if (opts.chainId === undefined) throw new Error(`${spec.name}: staticNetwork needs the chain id (read it once, untimed, with rawChainId(url))`);
    network = Network.from(BigInt(opts.chainId));
    o.staticNetwork = true;
  }
  let conn: string | FetchRequest = url;
  if (opts.agent) {
    const req = new FetchRequest(url);
    req.getUrlFunc = FetchRequest.createGetUrlFunc({ agent: opts.agent });
    conn = req;
  }
  const provider = new JsonRpcProvider(conn, network, o);
  provider.pollingInterval = 100;
  return provider;
}

export interface ProviderOptionsRecord {
  staticNetwork: true | string | null;
  batchStallTime: number;
  batchMaxCount: number;
  batchMaxSize: number;
  cacheTimeout: number;
  polling: boolean;
  pollingInterval: number | null;
}

/** The effective ethers options of a provider (for env.json and the as-shipped check). */
export function describeProvider(provider: JsonRpcProvider): ProviderOptionsRecord {
  const p = provider as unknown as ProviderInternals & { pollingInterval?: number };
  const sn = p._getOption("staticNetwork");
  return {
    staticNetwork: sn === true ? true : sn instanceof Network ? `Network(chainId ${sn.chainId})` : null,
    batchStallTime: Number(p._getOption("batchStallTime")),
    batchMaxCount: Number(p._getOption("batchMaxCount")),
    batchMaxSize: Number(p._getOption("batchMaxSize")),
    cacheTimeout: Number(p._getOption("cacheTimeout")),
    polling: Boolean(p._getOption("polling")),
    pollingInterval: typeof p.pollingInterval === "number" ? p.pollingInterval : null,
  };
}

/** describeProvider() of the shipped client (ledger.ts makeProvider on ethers 6.13.4). */
export const AS_SHIPPED_OPTIONS: Readonly<ProviderOptionsRecord> = Object.freeze({
  staticNetwork: null,
  batchStallTime: 10,
  batchMaxCount: 100,
  batchMaxSize: 1 << 20,
  cacheTimeout: -1,
  polling: false,
  pollingInterval: 100,
});

/** Throws unless the provider has exactly the shipped options (guards against drift of ledger.ts). */
export function assertAsShipped(provider: JsonRpcProvider): void {
  const got = describeProvider(provider);
  const diff = (Object.keys(AS_SHIPPED_OPTIONS) as Array<keyof ProviderOptionsRecord>).filter((k) => got[k] !== AS_SHIPPED_OPTIONS[k]);
  if (diff.length > 0) {
    throw new Error(`provider is not the shipped client: ${diff.map((k) => `${k}=${String(got[k])} (shipped ${String(AS_SHIPPED_OPTIONS[k])})`).join(", ")}`);
  }
}

/** The URL a JsonRpcProvider posts to. */
export function providerUrl(provider: JsonRpcProvider): string {
  const p = provider as unknown as ProviderInternals;
  if (typeof p._getConnection !== "function") throw new Error("provider has no _getConnection (not an HTTP JsonRpcProvider)");
  return p._getConnection().url;
}

/** eth_chainId over a plain fetch (untimed set-up; not through ethers, not traced). */
export async function rawChainId(url: string): Promise<number> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }),
  });
  const j = (await res.json()) as { result?: string; error?: { message?: string } };
  if (typeof j.result !== "string") throw new Error(`eth_chainId failed: ${j.error?.message ?? `HTTP ${res.status}`}`);
  return Number(BigInt(j.result));
}

/** D-034 label of a measured endpoint (a node on this laptop's loopback, or anything else). */
export type EndpointLabel = "loopback, same host" | "remote";

/**
 * "loopback, same host" for 127.0.0.0/8, ::1 and localhost, else "remote" (D-034). The URL
 * itself is never stored by this module's records.
 */
export function endpointLabel(url: string): EndpointLabel {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return "remote";
  }
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  return isLoopbackHost(host) ? "loopback, same host" : "remote";
}

function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase();
  return h === "localhost" || h.endsWith(".localhost") || h === "::1" || /^127\.\d+\.\d+\.\d+$/.test(h) || /^::ffff:127\.\d+\.\d+\.\d+$/.test(h);
}

// ---------------------------------------------------------------------------------------
// TCP connections (Node diagnostics channels; nothing is patched)
// ---------------------------------------------------------------------------------------

/** Monotonic creation time of every client socket that net.connect made since the hooks were installed. */
const socketBornNs = new WeakMap<object, bigint>();

/** One HTTP attempt of a traced POST, as seen from Node's http layer. */
interface AttemptProbe {
  t0: bigint;
  req: http.ClientRequest | null;
  /** true: the attempt's socket was created during the attempt; false: reused; null: unknown. */
  newConnection: boolean | null;
  bornNs: bigint | null;
  connectedNs: bigint | null;
  connectOk: boolean | null;
  contentEncoding: string | null;
}

let captureSlot: AttemptProbe | null = null;
let netHooksInstalled = false;
const connectionRecorders = new Set<(socket: net.Socket, bornNs: bigint) => void>();

function onNetClientSocket(msg: unknown): void {
  const socket = (msg as { socket?: net.Socket } | null)?.socket;
  if (!socket) return;
  const t = process.hrtime.bigint();
  socketBornNs.set(socket, t);
  for (const r of connectionRecorders) r(socket, t);
}

function onHttpRequestCreated(msg: unknown): void {
  const slot = captureSlot;
  if (!slot || slot.req) return;
  const req = (msg as { request?: http.ClientRequest } | null)?.request;
  if (!req) return;
  slot.req = req;
  req.once("socket", (s: net.Socket) => classifyAttemptSocket(slot, req, s));
}

function classifyAttemptSocket(slot: AttemptProbe, req: http.ClientRequest, s: net.Socket): void {
  const born = socketBornNs.get(s);
  const isNew = born !== undefined ? born >= slot.t0 : !req.reusedSocket;
  slot.newConnection = isNew;
  if (!isNew) return;
  slot.bornNs = born ?? process.hrtime.bigint();
  if (s.connecting) {
    // Node's http client has its own 'error' listener on the socket by now, so one more does not
    // change how an error is handled; without one, wait for 'close' instead (it comes later).
    const failEvent = s.listenerCount("error") > 0 ? "error" : "close";
    const onConnect = () => {
      s.off(failEvent, onFail);
      slot.connectedNs = process.hrtime.bigint();
      slot.connectOk = true;
    };
    const onFail = () => {
      s.off("connect", onConnect);
      if (slot.connectOk === null) slot.connectOk = false;
    };
    s.once("connect", onConnect);
    s.once(failEvent, onFail);
  } else if (!s.destroyed) {
    slot.connectedNs = process.hrtime.bigint();
    slot.connectOk = true;
  } else {
    slot.connectOk = false;
  }
}

/**
 * Subscribe (once per process) to the diagnostics channels "net.client.socket" and
 * "http.client.request.created". Called by traceProvider and traceConnections; sockets
 * created before the first call are classified by request.reusedSocket only.
 */
export function installNetHooks(): void {
  if (netHooksInstalled) return;
  netHooksInstalled = true;
  dc.subscribe("net.client.socket", onNetClientSocket);
  dc.subscribe("http.client.request.created", onHttpRequestCreated);
}

/** One client TCP socket of the process (any agent, any code), for traceConnections. */
export interface ConnectionEvent {
  /** 0-based index within the recorder. */
  seq: number;
  /** Socket creation (net.connect), ms on the recorder's epoch. */
  tMs: number;
  /** TCP connect completed, ms on the epoch; null when it failed or has not happened yet. */
  tConnectedMs: number | null;
  /** Remote port, once known (from the connection attempt or the connect). The address itself is not stored. */
  port: number | null;
  /** The remote address was a loopback address, once known. */
  loopback: boolean | null;
  /** true connected; false closed before connecting (set when the socket closes); null pending. */
  ok: boolean | null;
}

export interface ConnectionRecorder {
  readonly epochNs: bigint;
  /** Every client socket since the recorder started (a live list; it fills in as sockets connect). */
  events(): readonly ConnectionEvent[];
  /** Events whose remote port is known and equal to `port` (all events without it). */
  count(port?: number): number;
  stop(): void;
}

/**
 * Process-wide recorder of new client TCP connections (every agent and every caller, including
 * untraced code and the quiet check's port probe; filter by port). Complements the per-POST
 * attribution of traceProvider, which needs no recorder.
 */
export function traceConnections(opts: { epochNs?: bigint } = {}): ConnectionRecorder {
  installNetHooks();
  const epochNs = opts.epochNs ?? TRACE_EPOCH_NS;
  const list: ConnectionEvent[] = [];
  const onSocket = (s: net.Socket, bornNs: bigint) => {
    const ev: ConnectionEvent = { seq: list.length, tMs: nsToMs(bornNs - epochNs), tConnectedMs: null, port: null, loopback: null, ok: null };
    list.push(ev);
    // listeners on 'connectionAttempt', 'connect' and 'close' only: an added 'error' listener
    // would change how an unhandled socket error behaves in the measured code
    const onAttempt = (address: unknown, port: unknown) => {
      if (typeof port === "number") ev.port = port;
      if (typeof address === "string") ev.loopback = isLoopbackHost(address);
    };
    const onConnect = () => {
      s.off("close", onClose);
      s.off("connectionAttempt", onAttempt);
      ev.tConnectedMs = nsToMs(process.hrtime.bigint() - epochNs);
      ev.ok = true;
      if (typeof s.remotePort === "number") ev.port = s.remotePort;
      if (typeof s.remoteAddress === "string") ev.loopback = isLoopbackHost(s.remoteAddress);
    };
    const onClose = () => {
      s.off("connect", onConnect);
      s.off("connectionAttempt", onAttempt);
      if (ev.ok === null) ev.ok = false;
    };
    s.on("connectionAttempt", onAttempt);
    s.once("connect", onConnect);
    s.once("close", onClose);
  };
  connectionRecorders.add(onSocket);
  return {
    epochNs,
    events: () => list,
    count: (port) => (port === undefined ? list.length : list.filter((e) => e.port === port).length),
    stop: () => {
      connectionRecorders.delete(onSocket);
    },
  };
}

// ---------------------------------------------------------------------------------------
// the trace
// ---------------------------------------------------------------------------------------

export interface PostRecord {
  /** 0-based POST index within the trace (in start order). */
  seq: number;
  /** Caller label current when the POST started (setLabel). */
  label: string | null;
  tStartMs: number;
  tEndMs: number;
  /** _send duration: the round trip as defined. */
  ms: number;
  /** Payload elements (JSON-RPC requests) in this POST. */
  size: number;
  /** true when the payload was a JSON array (a JSON-RPC batch), even of one element. */
  batch: boolean;
  methods: string[];
  /** Per element: from send() to the start of this POST, ms; null when it did not come through send(). */
  queueMs: Array<number | null>;
  /** No element came through send(): ethers' direct network detection before the provider started. */
  direct: boolean;
  /** _send resolved (HTTP 2xx and a JSON body). */
  ok: boolean;
  /** Response elements that carry a JSON-RPC error. */
  rpcErrors: number;
  /** _send rejection, sanitized (code and short message), else null. */
  error: string | null;
  /** Transport details of this POST; null for a provider without _getConnection. */
  http: PostHttp | null;
}

export interface PostHttp {
  /** HTTP requests made inside this _send (more than 1 only when FetchRequest retried an HTTP 429). */
  attempts: number;
  statuses: number[];
  /** Time inside the getUrl function, summed over attempts, ms. */
  ms: number;
  /** Request body bytes sent, summed over attempts. */
  bytesOut: number;
  /** Response body bytes after content decoding (ethers gunzips a gzip body), summed over attempts; not bytes on the wire. */
  bytesIn: number;
  /** Attempts that opened a new TCP connection (always set by the tracer; optional for records built elsewhere). */
  connects?: number;
  /** Per attempt: true opened a new TCP connection, false used a kept-alive socket, null unknown. */
  newConnection?: Array<boolean | null>;
  /** Per attempt: the response Content-Encoding (lower case), null when none or no response. */
  contentEncoding?: Array<string | null>;
}

/** A new TCP connection opened by one attempt of a traced POST. */
export interface TraceConnectEvent {
  postSeq: number;
  /** 0-based attempt within the POST. */
  attempt: number;
  label: string | null;
  /** Socket creation (net.connect), ms on the trace epoch. */
  tStartMs: number;
  /** TCP connect completed, ms on the trace epoch; null when it failed or was not seen. */
  tConnectedMs: number | null;
  /** tConnectedMs - tStartMs, or null. */
  connectMs: number | null;
  /** true connected; false failed before connecting; null not seen. */
  ok: boolean | null;
}

export interface TraceCounts {
  posts: number;
  requests: number;
  byMethod: Record<string, number>;
  /** POSTs by payload size ("1", "2", ...). */
  postsBySize: Record<string, number>;
  /** POSTs whose payload was a JSON array. */
  batchPosts: number;
  directPosts: number;
  failedPosts: number;
  rpcErrors: number;
  /** HTTP requests made inside the POSTs (equals posts unless FetchRequest retried). */
  httpAttempts: number;
  /** HTTP attempts that opened a new TCP connection. */
  connects: number;
  /** HTTP attempts whose connection could not be classified (no ClientRequest seen). */
  connectsUnknown: number;
}

export interface TraceMark {
  seq: number;
  tMs: number;
}

export interface RpcTrace {
  readonly provider: JsonRpcProvider;
  readonly epochNs: bigint;
  /** Wall-clock (UTC) time of epochNs (TRACE_EPOCH_UTC for the default epoch). */
  readonly epochUtc: string;
  readonly definition: string;
  setLabel(label: string | null): void;
  /** Retained records (all finished POSTs since creation, the last drain or reset), in finish order; sort by seq for start order. */
  records(): readonly PostRecord[];
  /** Return the retained records and forget them (counts are kept). */
  drain(): PostRecord[];
  /** Cumulative counts since creation or reset (a POST counts when it starts; its attempts and connects when it ends). */
  counts(): TraceCounts;
  mark(): TraceMark;
  /** Retained records of POSTs that started at or after the mark. */
  since(m: TraceMark): PostRecord[];
  /**
   * New TCP connections of finished POSTs since creation or reset (not cleared by drain), in
   * finish order; with a mark, only those of POSTs that started at or after it. The raw list
   * for assigning connects to concurrent POSTs.
   */
  connectEvents(m?: TraceMark): TraceConnectEvent[];
  /** POSTs started and not yet finished. */
  inFlight(): number;
  reset(): void;
  /** Put the provider's own methods back. */
  detach(): void;
}

export interface TraceOptions {
  label?: string | null;
  /** Time base (default TRACE_EPOCH_NS, shared by every trace in the process). */
  epochNs?: bigint;
  /** Keep a record per POST (default true); false keeps counts only. */
  keepRecords?: boolean;
  /** Extra strings to redact from error text (the provider's URL and its host:port are always redacted). */
  redact?: readonly string[];
}

function emptyCounts(): TraceCounts {
  return { posts: 0, requests: 0, byMethod: {}, postsBySize: {}, batchPosts: 0, directPosts: 0, failedPosts: 0, rpcErrors: 0, httpAttempts: 0, connects: 0, connectsUnknown: 0 };
}

interface Draft {
  seq: number;
  label: string | null;
  t0: bigint;
  size: number;
  batch: boolean;
  methods: string[];
  queueMs: Array<number | null>;
  http: { attempts: number; statuses: number[]; ns: bigint; bytesOut: number; bytesIn: number; probes: AttemptProbe[] } | null;
}

/** Trace every POST of one provider (see the module header for the definition). */
export function traceProvider(provider: JsonRpcProvider, opts: TraceOptions = {}): RpcTrace {
  assertEthers();
  const p = provider as unknown as ProviderInternals;
  if (typeof p._send !== "function" || typeof p.send !== "function") throw new Error("not an ethers JsonRpcApiProvider (no send/_send)");
  if (p[TRACED]) throw new Error("provider is already traced; detach the first trace before tracing it again");
  installNetHooks();

  const epochNs = opts.epochNs ?? TRACE_EPOCH_NS;
  const epochUtc = epochNs === TRACE_EPOCH_NS ? TRACE_EPOCH_UTC : new Date(Date.now() - nsToMs(process.hrtime.bigint() - epochNs)).toISOString();
  const keep = opts.keepRecords !== false;
  const hasConn = typeof p._getConnection === "function";
  const redactions = [...(opts.redact ?? [])];
  if (hasConn) {
    try {
      const u = providerUrl(provider);
      redactions.push(u);
      const host = new URL(u).host;
      if (host) redactions.push(host);
    } catch {
      /* no URL */
    }
  }
  // longest first, so the full URL is replaced before its host:port
  redactions.sort((a, b) => b.length - a.length);
  const redact = (s: string) => {
    let out = s;
    for (const r of redactions) if (r.length >= 4) out = out.split(r).join("<rpc-url>");
    return sanitize(out).slice(0, 300);
  };

  // own properties before wrapping (normally none: the methods live on the prototype)
  const ownBefore = {
    send: Object.getOwnPropertyDescriptor(p, "send"),
    _send: Object.getOwnPropertyDescriptor(p, "_send"),
    _getConnection: Object.getOwnPropertyDescriptor(p, "_getConnection"),
  };
  const origSend = p.send;
  const origRawSend = p._send;
  const origGetConnection = p._getConnection;

  const enqueued = new WeakMap<object, bigint[]>();
  let label: string | null = opts.label ?? null;
  let seq = 0;
  let inFlight = 0;
  let current: Draft | null = null;
  let counts = emptyCounts();
  let records: PostRecord[] = [];
  let connectEvents: TraceConnectEvent[] = [];
  let generation = 0;

  const wrappedSend = function (this: unknown, method: string, params: Params): Promise<unknown> {
    if (params !== null && typeof params === "object") {
      const xs = enqueued.get(params);
      if (xs) xs.push(process.hrtime.bigint());
      else enqueued.set(params, [process.hrtime.bigint()]);
    }
    return origSend.call(this, method, params);
  };

  const wrappedRawSend = function (this: unknown, payload: JsonRpcPayload | JsonRpcPayload[]): Promise<Array<JsonRpcResult | JsonRpcError>> {
    const t0 = process.hrtime.bigint();
    const items = Array.isArray(payload) ? payload : [payload];
    const draft: Draft = {
      seq: seq++,
      label,
      t0,
      size: items.length,
      batch: Array.isArray(payload),
      methods: items.map((it) => String((it as { method?: unknown })?.method ?? "?")),
      queueMs: items.map((it) => {
        const prm = (it as { params?: unknown })?.params;
        const q = prm !== null && typeof prm === "object" ? enqueued.get(prm)?.shift() : undefined;
        return q === undefined ? null : nsToMs(t0 - q);
      }),
      http: hasConn ? { attempts: 0, statuses: [], ns: 0n, bytesOut: 0, bytesIn: 0, probes: [] } : null,
    };
    const gen = generation;
    counts.posts++;
    counts.requests += draft.size;
    for (const m of draft.methods) counts.byMethod[m] = (counts.byMethod[m] ?? 0) + 1;
    counts.postsBySize[String(draft.size)] = (counts.postsBySize[String(draft.size)] ?? 0) + 1;
    if (draft.batch) counts.batchPosts++;
    const direct = draft.queueMs.every((q) => q === null);
    if (direct) counts.directPosts++;
    inFlight++;

    const finish = (ok: boolean, result: Array<JsonRpcResult | JsonRpcError> | null, err: unknown) => {
      const t1 = process.hrtime.bigint();
      inFlight--;
      const rpcErrors = result ? result.filter((r) => r && typeof r === "object" && "error" in r).length : 0;
      const probes = draft.http?.probes ?? [];
      const newConnection = probes.map((pr) => pr.newConnection);
      const connects = newConnection.filter((x) => x === true).length;
      if (gen === generation) {
        if (!ok) counts.failedPosts++;
        counts.rpcErrors += rpcErrors;
        counts.httpAttempts += draft.http?.attempts ?? 0;
        counts.connects += connects;
        counts.connectsUnknown += newConnection.filter((x) => x === null).length;
      }
      if (!keep || gen !== generation) return;
      probes.forEach((pr, attempt) => {
        if (pr.newConnection !== true || pr.bornNs === null) return;
        const tStartMs = nsToMs(pr.bornNs - epochNs);
        const tConnectedMs = pr.connectedNs === null ? null : nsToMs(pr.connectedNs - epochNs);
        connectEvents.push({ postSeq: draft.seq, attempt, label: draft.label, tStartMs, tConnectedMs, connectMs: tConnectedMs === null ? null : tConnectedMs - tStartMs, ok: pr.connectOk });
      });
      let error: string | null = null;
      if (!ok) {
        const e = err as { code?: unknown; shortMessage?: unknown; message?: unknown } | null;
        error = redact(`${typeof e?.code === "string" ? e.code + ": " : ""}${String(e?.shortMessage ?? e?.message ?? err)}`);
      }
      records.push({
        seq: draft.seq,
        label: draft.label,
        tStartMs: nsToMs(draft.t0 - epochNs),
        tEndMs: nsToMs(t1 - epochNs),
        ms: nsToMs(t1 - draft.t0),
        size: draft.size,
        batch: draft.batch,
        methods: draft.methods,
        queueMs: draft.queueMs,
        direct,
        ok,
        rpcErrors,
        error,
        http: draft.http
          ? {
              attempts: draft.http.attempts,
              statuses: draft.http.statuses,
              ms: nsToMs(draft.http.ns),
              bytesOut: draft.http.bytesOut,
              bytesIn: draft.http.bytesIn,
              connects,
              newConnection,
              contentEncoding: probes.map((pr) => pr.contentEncoding),
            }
          : null,
      });
    };

    const prev = current;
    current = draft;
    let promise: Promise<Array<JsonRpcResult | JsonRpcError>>;
    try {
      promise = origRawSend.call(this, payload);
    } catch (e) {
      promise = Promise.reject(e);
    } finally {
      current = prev;
    }
    return promise.then(
      (res) => {
        finish(true, res, null);
        return res;
      },
      (e: unknown) => {
        finish(false, null, e);
        throw e;
      }
    );
  };

  const wrappedGetConnection = function (this: unknown): FetchRequest {
    const req = (origGetConnection as () => FetchRequest).call(this);
    const draft = current;
    if (draft?.http) {
      const h = draft.http;
      const inner: FetchGetUrlFunc = req.getUrlFunc;
      req.getUrlFunc = async (r: FetchRequest, signal?: Parameters<FetchGetUrlFunc>[1]): Promise<GetUrlResponse> => {
        h.attempts++;
        h.bytesOut += r.body ? r.body.length : 0;
        const probe: AttemptProbe = { t0: process.hrtime.bigint(), req: null, newConnection: null, bornNs: null, connectedNs: null, connectOk: null, contentEncoding: null };
        h.probes.push(probe);
        // ethers' Node getUrl creates its ClientRequest synchronously; the diagnostics channel
        // hands it to this attempt while captureSlot points here.
        const prevSlot = captureSlot;
        captureSlot = probe;
        let pending: Promise<GetUrlResponse>;
        try {
          pending = inner(r, signal);
        } catch (e) {
          pending = Promise.reject(e);
        } finally {
          captureSlot = prevSlot;
        }
        try {
          const resp = await pending;
          h.statuses.push(resp.statusCode);
          h.bytesIn += resp.body ? resp.body.length : 0;
          const ce = resp.headers?.["content-encoding"];
          probe.contentEncoding = typeof ce === "string" && ce.length > 0 ? ce.toLowerCase() : null;
          return resp;
        } finally {
          h.ns += process.hrtime.bigint() - probe.t0;
        }
      };
    }
    return req;
  };

  p.send = wrappedSend;
  p._send = wrappedRawSend;
  if (hasConn) p._getConnection = wrappedGetConnection;

  const trace: RpcTrace = {
    provider,
    epochNs,
    epochUtc,
    definition: ROUND_TRIP_DEFINITION,
    setLabel: (l) => {
      label = l;
    },
    records: () => records,
    drain: () => {
      const out = records;
      records = [];
      return out;
    },
    counts: () => JSON.parse(JSON.stringify(counts)) as TraceCounts,
    mark: () => ({ seq, tMs: nsToMs(process.hrtime.bigint() - epochNs) }),
    since: (m) => records.filter((r) => r.seq >= m.seq),
    connectEvents: (m) => (m ? connectEvents.filter((e) => e.postSeq >= m.seq) : [...connectEvents]),
    inFlight: () => inFlight,
    reset: () => {
      generation++;
      counts = emptyCounts();
      records = [];
      connectEvents = [];
    },
    detach: () => {
      if (p.send !== wrappedSend || p._send !== wrappedRawSend || (hasConn && p._getConnection !== wrappedGetConnection)) {
        throw new Error("another wrapper was installed on top of this trace; detach in reverse order");
      }
      const restore = (k: "send" | "_send" | "_getConnection") => {
        const d = ownBefore[k];
        if (d) Object.defineProperty(p, k, d);
        else delete (p as unknown as Record<string, unknown>)[k];
      };
      restore("send");
      restore("_send");
      if (hasConn) restore("_getConnection");
      delete p[TRACED];
    },
  };
  p[TRACED] = trace;
  return trace;
}

/** The trace attached to a provider, if any. */
export function traceOf(provider: JsonRpcProvider): RpcTrace | null {
  return (provider as unknown as ProviderInternals)[TRACED] ?? null;
}

// ---------------------------------------------------------------------------------------
// analysis helpers (pure)
// ---------------------------------------------------------------------------------------

type Interval = Pick<PostRecord, "tStartMs" | "tEndMs">;

/**
 * Sequential depth: the largest number of POSTs that ran one after another without
 * overlapping (greedy by end time, which is optimal). It is an UPPER BOUND on the number of
 * dependent round trips, not that number itself: independent POSTs that happen not to overlap
 * (for example unbatched concurrent POSTs that the event loop serialises on a fast loopback)
 * count too. For strictly sequential code it is the POST count; for reads that all overlap it
 * is 1. Report it next to maxInFlight and the queue delays (PostRecord.queueMs).
 */
export function sequentialDepth(posts: readonly Interval[]): number {
  const xs = [...posts].sort((a, b) => a.tEndMs - b.tEndMs);
  let n = 0;
  let lastEnd = -Infinity;
  for (const x of xs) {
    if (x.tStartMs >= lastEnd) {
      n++;
      lastEnd = x.tEndMs;
    }
  }
  return n;
}

/** Largest number of POSTs in flight at the same time. */
export function maxInFlight(posts: readonly Interval[]): number {
  const ev: Array<[number, number]> = [];
  for (const x of posts) {
    ev.push([x.tStartMs, 1]);
    ev.push([x.tEndMs, -1]);
  }
  ev.sort((a, b) => a[0] - b[0] || a[1] - b[1]); // an end before a start at the same instant
  let cur = 0;
  let best = 0;
  for (const [, d] of ev) {
    cur += d;
    best = Math.max(best, cur);
  }
  return best;
}

export interface TraceSummary extends TraceCounts {
  /** Sum of POST durations, ms. */
  postMs: number;
  /** First POST start to last POST end, ms (0 without POSTs). */
  spanMs: number;
  /** Upper bound on dependent round trips (see sequentialDepth). */
  sequentialDepth: number;
  maxInFlight: number;
}

/** Counts and timing facts of a set of POST records (for example one presentation). */
export function summarize(posts: readonly PostRecord[]): TraceSummary {
  const c = emptyCounts();
  let postMs = 0;
  for (const r of posts) {
    c.posts++;
    c.requests += r.size;
    for (const m of r.methods) c.byMethod[m] = (c.byMethod[m] ?? 0) + 1;
    c.postsBySize[String(r.size)] = (c.postsBySize[String(r.size)] ?? 0) + 1;
    if (r.batch) c.batchPosts++;
    if (r.direct) c.directPosts++;
    if (!r.ok) c.failedPosts++;
    c.rpcErrors += r.rpcErrors;
    c.httpAttempts += r.http?.attempts ?? 0;
    c.connects += r.http?.connects ?? 0;
    c.connectsUnknown += (r.http?.newConnection ?? []).filter((x) => x === null).length;
    postMs += r.ms;
  }
  // loops, not Math.max(...xs) / Math.min(...xs): the same values (NaN and -0 included) without
  // passing every element as a call argument (a spread throws past about 125,000; fz1 triage)
  let lastEnd = -Infinity;
  let firstStart = Infinity;
  for (const r of posts) {
    lastEnd = Math.max(lastEnd, r.tEndMs);
    firstStart = Math.min(firstStart, r.tStartMs);
  }
  const spanMs = posts.length === 0 ? 0 : lastEnd - firstStart;
  return { ...c, postMs, spanMs, sequentialDepth: sequentialDepth(posts), maxInFlight: maxInFlight(posts) };
}

// ---------------------------------------------------------------------------------------
// LedgerV4 and contract sets (run-time access; packages/ unchanged)
// ---------------------------------------------------------------------------------------

interface LedgerInternals {
  rpcUrl: string;
  addresses: RegistryAddressesV4;
  provider: JsonRpcProvider;
  contracts: Record<string, BaseContract>;
  deployer: { signer?: { connect?: (p: JsonRpcProvider) => unknown }; constructor: unknown };
  signers: Map<string, unknown>;
}

function internalsOf(ledger: LedgerV4): LedgerInternals {
  const L = ledger as unknown as Partial<LedgerInternals>;
  if (!L.provider || typeof (L.provider as unknown as Partial<ProviderInternals>)._send !== "function") {
    throw new Error("LedgerV4 has no provider field: update harness/v4/lib/rpc_trace.ts");
  }
  if (!L.contracts || typeof L.contracts !== "object") throw new Error("LedgerV4 has no contracts field: update harness/v4/lib/rpc_trace.ts");
  if (!L.deployer || typeof L.deployer.signer?.connect !== "function") throw new Error("LedgerV4 deployer is not a NonceManager over a Wallet: update harness/v4/lib/rpc_trace.ts");
  if (!(L.signers instanceof Map)) throw new Error("LedgerV4 has no signers map: update harness/v4/lib/rpc_trace.ts");
  if (typeof L.rpcUrl !== "string" || !L.addresses) throw new Error("LedgerV4 has no rpcUrl/addresses: update harness/v4/lib/rpc_trace.ts");
  return L as LedgerInternals;
}

/** The provider inside a LedgerV4 (TypeScript-private field; same access as scale_lib.providerOf). */
export function ledgerProvider(ledger: LedgerV4): JsonRpcProvider {
  return internalsOf(ledger).provider;
}

/**
 * Trace a LedgerV4's own provider in place (the as-shipped client of that ledger). Every
 * holder of this instance is traced together (in a World: all parties on world.ledger).
 */
export function traceLedger(ledger: LedgerV4, opts: TraceOptions = {}): RpcTrace {
  return traceProvider(ledgerProvider(ledger), opts);
}

export interface RebindHandle {
  /** The provider the ledger had before (not destroyed: the caller decides). */
  previous: JsonRpcProvider;
  /** Put the previous provider, contracts, deployer and signers back. */
  restore(): void;
}

/**
 * Make an existing LedgerV4 use another provider (for example a client variant, traced or
 * not), as LedgerV4.connect would have built it: contracts re-attached with the package's own
 * LedgerV4.attachContracts, the deployer signer re-connected, role signers rebuilt on demand
 * (their nonces are re-read from the chain). Run-time only; packages/ is unchanged.
 * It changes the LedgerV4 instance itself, so it affects every object that holds it: in a
 * World the issuers, wallets and verifiers share world.ledger. For per-party clients or
 * traces, connect one ledger per party (connectClientLedger) and give it to that party.
 */
export function rebindLedger(ledger: LedgerV4, provider: JsonRpcProvider, opts: { allowOtherUrl?: boolean } = {}): RebindHandle {
  assertEthers();
  const L = internalsOf(ledger);
  const Ctor = (ledger as unknown as { constructor: { attachContracts?: (a: RegistryAddressesV4, p: JsonRpcProvider) => Record<string, BaseContract> } }).constructor;
  if (typeof Ctor.attachContracts !== "function") throw new Error("LedgerV4.attachContracts is missing: update harness/v4/lib/rpc_trace.ts");
  if (!opts.allowOtherUrl && providerUrl(provider) !== L.rpcUrl) throw new Error("rebindLedger: the new provider posts to another URL than the ledger's rpcUrl");
  const prev = { provider: L.provider, contracts: L.contracts, deployer: L.deployer, signers: L.signers };
  const DeployerCtor = prev.deployer.constructor as new (signer: unknown) => LedgerInternals["deployer"];
  const contracts = Ctor.attachContracts.call(Ctor, L.addresses, provider);
  const deployer = new DeployerCtor((prev.deployer.signer as { connect: (p: JsonRpcProvider) => unknown }).connect(provider));
  L.provider = provider;
  L.contracts = contracts;
  L.deployer = deployer;
  L.signers = new Map();
  let restored = false;
  return {
    previous: prev.provider,
    restore: () => {
      if (restored) return;
      restored = true;
      L.provider = prev.provider;
      L.contracts = prev.contracts;
      L.deployer = prev.deployer;
      L.signers = prev.signers;
    },
  };
}

/** A contract set re-attached to another provider (Contract.connect per entry). */
export function attachContracts<T extends Record<string, BaseContract>>(contracts: T, provider: JsonRpcProvider): { [K in keyof T]: BaseContract } {
  const out = {} as { [K in keyof T]: BaseContract };
  for (const k of Object.keys(contracts) as Array<keyof T>) out[k] = (contracts[k] as BaseContract).connect(provider);
  return out;
}

export interface ClientLedger {
  ledger: LedgerV4;
  spec: ClientVariantSpec;
  provider: JsonRpcProvider;
  options: ProviderOptionsRecord;
  trace: RpcTrace | null;
  /** D-034 endpoint label of the URL (the URL itself is not kept here). */
  endpoint: EndpointLabel;
  /**
   * The provider is traced right now (live: a later traceProvider or detach changes it). A
   * traced client runs wrapper code per request, so traced and untraced figures (for example
   * E4's) are reported separately.
   */
  readonly traced: boolean;
  /** staticNetwork: the given chain id was checked against the node's eth_chainId (untimed). null for other variants. */
  chainIdCheckedAgainstNode: boolean | null;
}

export interface ConnectClientOptions extends ClientOptions {
  trace?: boolean | TraceOptions;
  /** staticNetwork: compare opts.chainId with a raw eth_chainId before connecting (default true). */
  checkChainId?: boolean;
}

/**
 * LedgerV4.connect for one client variant, optionally traced. asShipped keeps the provider
 * LedgerV4.connect built (checked against AS_SHIPPED_OPTIONS); a variant replaces it through
 * rebindLedger and the unused shipped provider is destroyed. For a staticNetwork variant the
 * given chain id is first checked against the node (one raw eth_chainId through fetch, untimed,
 * outside the trace and outside Node's http agents): ethers never checks a static network, so
 * a wrong id would go unnoticed and LedgerV4.chainId() would report it.
 */
export async function connectClientLedger(
  url: string,
  addresses: RegistryAddressesV4,
  fromBlock: number,
  variant: ClientVariantName | ClientVariantSpec,
  opts: ConnectClientOptions = {}
): Promise<ClientLedger> {
  const spec = specOf(variant);
  if (spec.shipped && opts.agent) throw new Error("asShipped uses Node's global HTTP agent, as LedgerV4 does; pass no agent");
  let chainIdCheckedAgainstNode: boolean | null = null;
  if (spec.options.staticNetwork) {
    if (opts.chainId === undefined) throw new Error(`${spec.name}: staticNetwork needs the chain id (read it once, untimed, with rawChainId(url))`);
    if (opts.checkChainId === false) {
      chainIdCheckedAgainstNode = false;
    } else {
      const live = await rawChainId(url);
      if (BigInt(live) !== BigInt(opts.chainId)) {
        throw new Error(`${spec.name}: the given chain id ${String(opts.chainId)} differs from the node's eth_chainId ${live}`);
      }
      chainIdCheckedAgainstNode = true;
    }
  }
  const { LedgerV4: Ledger } = await import("@pqid/v4/ledger");
  const ledger = await Ledger.connect(url, addresses, fromBlock);
  let provider = ledgerProvider(ledger);
  if (spec.shipped) {
    assertAsShipped(provider);
  } else {
    const next = createClientProvider(spec, url, opts);
    const h = rebindLedger(ledger, next);
    h.previous.destroy();
    provider = next;
  }
  const trace = opts.trace ? traceProvider(provider, opts.trace === true ? {} : opts.trace) : null;
  const finalProvider = provider;
  return {
    ledger,
    spec,
    provider,
    options: describeProvider(provider),
    trace,
    endpoint: endpointLabel(url),
    get traced() {
      return traceOf(finalProvider) !== null;
    },
    chainIdCheckedAgainstNode,
  };
}
