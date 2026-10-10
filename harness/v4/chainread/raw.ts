import http from "node:http";
import net from "node:net";
import { traceConnections, type ConnectionRecorder } from "../lib/rpc_trace.ts";

/**
 * Raw JSON-RPC transports for series S1 and S2 (docs/v4/CHAINREAD.md), no ethers:
 *  - fetch:          Node's global fetch (undici, its own keep-alive pool)
 *  - httpKeepAlive:  node:http with a dedicated keep-alive Agent (maxSockets 1 for single
 *                    requests, so every request reuses one warm socket)
 *  - httpPool:       node:http keep-alive Agent without a socket limit (k concurrent POSTs)
 *  - httpFresh:      node:http with a new non-keep-alive Agent per request (TCP connect
 *                    included: the fresh-connection cell)
 *  - tcpRawNoDelay:  one persistent net.Socket with setNoDelay(true); one write per HTTP/1.1
 *                    POST, the response parsed here (Content-Length or chunked); the connect is
 *                    made before the timed write and is not part of the time
 * Times are process.hrtime.bigint() from the call to the parsed response, in ms.
 * New TCP connections are counted with the shared library's process-wide recorder
 * (harness/v4/lib/rpc_trace.ts traceConnections: Node's "net.client.socket" diagnostics channel,
 * nothing patched), filtered by the target's port, so every transport, fetch (undici) included,
 * reports them. The raw series run one request set at a time, so nothing else of the process
 * connects to that port meanwhile.
 */

export type RawTransport = "fetch" | "httpKeepAlive" | "httpFresh" | "tcpRawNoDelay";

export interface RpcRequest {
  method: string;
  params: unknown;
}

/** JSON-RPC body: one object for a single request, an array for a batch (even of one). */
export function rpcPayload(reqs: RpcRequest | readonly RpcRequest[], firstId = 1): string {
  if (!Array.isArray(reqs)) {
    const r = reqs as RpcRequest;
    return JSON.stringify({ jsonrpc: "2.0", id: firstId, method: r.method, params: r.params ?? [] });
  }
  return JSON.stringify((reqs as readonly RpcRequest[]).map((r, i) => ({ jsonrpc: "2.0", id: firstId + i, method: r.method, params: r.params ?? [] })));
}

export interface RawOutcome {
  ms: number;
  status: number | null;
  /** Request body bytes (JSON-RPC payload; HTTP headers not counted, for every transport). */
  bytesOut: number;
  /** Response body bytes (HTTP headers not counted). */
  bytesIn: number;
  /** JSON-RPC elements in the response. */
  responses: number;
  rpcErrors: number;
  ok: boolean;
  /** New TCP connections to the target during this call (RawClient); null from httpPost and fetchPost used alone. */
  newConnections: number | null;
  error: string | null;
}

const nsMs = (a: bigint, b: bigint) => Number(b - a) / 1e6;

function inspectBody(text: string, expected: number): { responses: number; rpcErrors: number; ok: boolean; error: string | null } {
  try {
    const j = JSON.parse(text) as unknown;
    const arr = Array.isArray(j) ? j : [j];
    const rpcErrors = arr.filter((x) => x && typeof x === "object" && "error" in (x as object)).length;
    const ok = arr.length === expected && rpcErrors === 0;
    return { responses: arr.length, rpcErrors, ok, error: ok ? null : `responses ${arr.length}/${expected}, rpc errors ${rpcErrors}` };
  } catch {
    return { responses: 0, rpcErrors: 0, ok: false, error: "response is not JSON" };
  }
}

/** One POST over node:http with the given agent. */
export function httpPost(url: string, body: string, agent: http.Agent, expected: number): Promise<RawOutcome> {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const bytesOut = Buffer.byteLength(body);
    const req = http.request(url, { method: "POST", agent, headers: { "content-type": "application/json", "content-length": bytesOut } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        const buf = Buffer.concat(chunks);
        const insp = inspectBody(buf.toString("utf8"), expected);
        const t1 = process.hrtime.bigint();
        resolve({ ms: nsMs(t0, t1), status: res.statusCode ?? null, bytesOut, bytesIn: buf.length, ...insp, ok: insp.ok && res.statusCode === 200, newConnections: null });
      });
      res.on("error", (e) => resolve({ ms: nsMs(t0, process.hrtime.bigint()), status: res.statusCode ?? null, bytesOut, bytesIn: 0, responses: 0, rpcErrors: 0, ok: false, newConnections: null, error: `response error: ${e.message}` }));
    });
    req.on("error", (e) => resolve({ ms: nsMs(t0, process.hrtime.bigint()), status: null, bytesOut, bytesIn: 0, responses: 0, rpcErrors: 0, ok: false, newConnections: null, error: `request error: ${(e as NodeJS.ErrnoException).code ?? e.message}` }));
    req.end(body);
  });
}

/** One POST over the global fetch (undici). */
export async function fetchPost(url: string, body: string, expected: number): Promise<RawOutcome> {
  const t0 = process.hrtime.bigint();
  const bytesOut = Buffer.byteLength(body);
  try {
    const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body });
    const text = await res.text();
    const insp = inspectBody(text, expected);
    return { ms: nsMs(t0, process.hrtime.bigint()), status: res.status, bytesOut, bytesIn: Buffer.byteLength(text), ...insp, ok: insp.ok && res.status === 200, newConnections: null };
  } catch (e) {
    return { ms: nsMs(t0, process.hrtime.bigint()), status: null, bytesOut, bytesIn: 0, responses: 0, rpcErrors: 0, ok: false, newConnections: null, error: `fetch error: ${(e as Error).message}` };
  }
}

// ---------------------------------------------------------------------------------------
// raw TCP
// ---------------------------------------------------------------------------------------

export interface ParsedResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
  /** Bytes of the input this response used (headers and body). */
  consumed: number;
  /** The server asked to close the connection. */
  close: boolean;
}

/**
 * Parse one HTTP/1.1 response from the start of `buf`. Returns null while incomplete. Bodies
 * with Content-Length or chunked transfer coding; a body delimited by connection close is
 * complete only when `ended` is true.
 */
export function parseHttpResponse(buf: Buffer, ended = false): ParsedResponse | null {
  const headEnd = buf.indexOf("\r\n\r\n");
  if (headEnd < 0) return null;
  const head = buf.subarray(0, headEnd).toString("latin1").split("\r\n");
  const m = /^HTTP\/1\.[01] (\d{3})/.exec(head[0] ?? "");
  if (!m) throw new Error(`not an HTTP/1.x response: ${JSON.stringify((head[0] ?? "").slice(0, 40))}`);
  const headers: Record<string, string> = {};
  for (const line of head.slice(1)) {
    const i = line.indexOf(":");
    if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  const status = Number(m[1]);
  const close = /\bclose\b/i.test(headers["connection"] ?? "");
  let pos = headEnd + 4;
  const te = (headers["transfer-encoding"] ?? "").toLowerCase();
  if (te.includes("chunked")) {
    const parts: Buffer[] = [];
    for (;;) {
      const lineEnd = buf.indexOf("\r\n", pos);
      if (lineEnd < 0) return null;
      const size = parseInt(buf.subarray(pos, lineEnd).toString("latin1").split(";")[0] ?? "", 16);
      if (!Number.isFinite(size)) throw new Error("bad chunk size");
      pos = lineEnd + 2;
      if (size === 0) {
        // optional trailers, then an empty line
        const end = buf.indexOf("\r\n", pos);
        if (end < 0) return null;
        if (end === pos) return { status, headers, body: Buffer.concat(parts), consumed: pos + 2, close };
        const trailersEnd = buf.indexOf("\r\n\r\n", pos);
        if (trailersEnd < 0) return null;
        return { status, headers, body: Buffer.concat(parts), consumed: trailersEnd + 4, close };
      }
      if (buf.length < pos + size + 2) return null;
      parts.push(buf.subarray(pos, pos + size));
      pos += size + 2;
    }
  }
  const cl = headers["content-length"];
  if (cl !== undefined) {
    const n = Number(cl);
    if (!Number.isSafeInteger(n) || n < 0) throw new Error("bad content-length");
    if (buf.length < pos + n) return null;
    return { status, headers, body: buf.subarray(pos, pos + n), consumed: pos + n, close };
  }
  if (!ended) return null;
  return { status, headers, body: buf.subarray(pos), consumed: buf.length, close: true };
}

/** Persistent raw TCP connection that sends one HTTP/1.1 POST at a time. */
export class RawTcpClient {
  private sock: net.Socket | null = null;
  private buf: Buffer = Buffer.alloc(0);
  private ended = false;
  private waiter: (() => void) | null = null;
  connects = 0;
  readonly host: string;
  readonly port: number;
  readonly path: string;

  constructor(url: string) {
    const u = new URL(url);
    this.host = u.hostname;
    this.port = Number(u.port || 80);
    this.path = u.pathname || "/";
  }

  /** Open the connection if needed (untimed by callers). Returns true when a new one was opened. */
  async ensure(): Promise<boolean> {
    if (this.sock && !this.sock.destroyed && !this.ended) return false;
    this.sock?.destroy();
    this.buf = Buffer.alloc(0);
    this.ended = false;
    const sock = net.connect({ host: this.host, port: this.port, noDelay: true });
    sock.setNoDelay(true);
    await new Promise<void>((resolve, reject) => {
      sock.once("connect", () => resolve());
      sock.once("error", reject);
    });
    sock.on("data", (d: Buffer) => {
      this.buf = this.buf.length === 0 ? d : Buffer.concat([this.buf, d]);
      this.waiter?.();
    });
    sock.on("end", () => {
      this.ended = true;
      this.waiter?.();
    });
    sock.on("close", () => {
      this.ended = true;
      this.waiter?.();
    });
    sock.on("error", () => {
      this.ended = true;
      this.waiter?.();
    });
    this.sock = sock;
    this.connects++;
    return true;
  }

  /** One POST on the open connection (call ensure() first). */
  async post(body: string, expected: number): Promise<RawOutcome> {
    const sock = this.sock;
    if (!sock || sock.destroyed || this.ended) throw new Error("RawTcpClient: not connected (call ensure first)");
    const bodyBuf = Buffer.from(body, "utf8");
    const head = `POST ${this.path} HTTP/1.1\r\nHost: ${this.host}:${this.port}\r\nContent-Type: application/json\r\nContent-Length: ${bodyBuf.length}\r\nConnection: keep-alive\r\n\r\n`;
    const out = Buffer.concat([Buffer.from(head, "latin1"), bodyBuf]);
    const t0 = process.hrtime.bigint();
    sock.write(out);
    let parsed: ParsedResponse | null = null;
    try {
      for (;;) {
        parsed = parseHttpResponse(this.buf, this.ended);
        if (parsed) break;
        if (this.ended) throw new Error("connection closed before a complete response");
        await new Promise<void>((r) => (this.waiter = r));
        this.waiter = null;
      }
    } catch (e) {
      this.ended = true;
      return { ms: nsMs(t0, process.hrtime.bigint()), status: null, bytesOut: bodyBuf.length, bytesIn: 0, responses: 0, rpcErrors: 0, ok: false, newConnections: null, error: `tcp error: ${(e as Error).message}` };
    }
    const insp = inspectBody(parsed.body.toString("utf8"), expected);
    const t1 = process.hrtime.bigint();
    this.buf = this.buf.subarray(parsed.consumed);
    if (parsed.close) this.ended = true;
    return { ms: nsMs(t0, t1), status: parsed.status, bytesOut: bodyBuf.length, bytesIn: parsed.body.length, ...insp, ok: insp.ok && parsed.status === 200, newConnections: null };
  }

  close(): void {
    this.sock?.destroy();
    this.sock = null;
  }
}

// ---------------------------------------------------------------------------------------
// the raw client of one target
// ---------------------------------------------------------------------------------------

export interface ConcurrentOutcome {
  /** First send to last parsed response, ms. */
  spanMs: number;
  each: RawOutcome[];
  ok: boolean;
  newConnections: number;
}

/** All raw transports of one URL, with new TCP connections counted per call. */
export class RawClient {
  readonly keepAlive: http.Agent;
  readonly pool: http.Agent;
  readonly tcp: RawTcpClient;
  readonly port: number;
  private readonly conns: ConnectionRecorder;

  constructor(readonly url: string) {
    this.keepAlive = new http.Agent({ keepAlive: true, maxSockets: 1 });
    this.pool = new http.Agent({ keepAlive: true });
    this.tcp = new RawTcpClient(url);
    this.port = this.tcp.port;
    this.conns = traceConnections();
  }

  /** New TCP connections to the target's port since the recorder started. */
  connections(): number {
    return this.conns.count(this.port);
  }

  async single(transport: RawTransport, body: string, expected: number): Promise<RawOutcome> {
    const before = this.connections();
    let r: RawOutcome;
    switch (transport) {
      case "fetch":
        r = await fetchPost(this.url, body, expected);
        break;
      case "httpKeepAlive":
        r = await httpPost(this.url, body, this.keepAlive, expected);
        break;
      case "httpFresh": {
        const agent = new http.Agent({ keepAlive: false });
        try {
          r = await httpPost(this.url, body, agent, expected);
        } finally {
          agent.destroy();
        }
        break;
      }
      case "tcpRawNoDelay":
        await this.tcp.ensure();
        r = await this.tcp.post(body, expected);
        break;
    }
    return { ...r, newConnections: this.connections() - before };
  }

  /** k single POSTs started together on the keep-alive pool. */
  async concurrent(bodies: readonly string[]): Promise<ConcurrentOutcome> {
    const before = this.connections();
    const t0 = process.hrtime.bigint();
    const each = await Promise.all(bodies.map((b) => httpPost(this.url, b, this.pool, 1)));
    const spanMs = nsMs(t0, process.hrtime.bigint());
    return { spanMs, each, ok: each.every((e) => e.ok), newConnections: this.connections() - before };
  }

  close(): void {
    this.conns.stop();
    this.keepAlive.destroy();
    this.pool.destroy();
    this.tcp.close();
  }
}
