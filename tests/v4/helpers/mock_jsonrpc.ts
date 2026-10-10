import http from "node:http";
import { gzipSync } from "node:zlib";
import type { AddressInfo } from "node:net";

/**
 * Minimal JSON-RPC 2.0 server over HTTP for unit tests (no chain). It binds 127.0.0.1 on an
 * ephemeral port chosen by the OS (port 0), so it never takes a D-034 or other fixed port.
 * It records every HTTP request it receives and every TCP connection it accepts, which are the
 * ground truth the tests compare the round-trip trace with.
 */

export interface MockHttpRequest {
  /** 0-based arrival index. */
  index: number;
  status: number;
  /** Request body bytes received. */
  bytesIn: number;
  /** Response body bytes sent (on the wire: compressed when the mock gzips). */
  bytesOut: number;
  /** Response body bytes before compression (equals bytesOut without gzip). */
  bodyBytes: number;
  /** The body was a JSON array (a JSON-RPC batch). */
  batch: boolean;
  methods: string[];
  /** Calldata `to` of each eth_call element (lower case), else null. */
  callTargets: Array<string | null>;
}

export interface MockRpc {
  url: string;
  port: number;
  chainId: number;
  /** Every HTTP request, in arrival order (including failed ones). */
  requests: MockHttpRequest[];
  /** Requests answered with HTTP 200 (the POSTs a client saw succeed). */
  okPosts(): MockHttpRequest[];
  byMethod(): Record<string, number>;
  /** TCP connections accepted since start or reset. */
  connections(): number;
  /** Answer the next `times` requests with this HTTP status and an empty JSON object. */
  failNext(status: number, times?: number): void;
  /** Result of every eth_call (hex). Default: uint256 3600. */
  setCallResult(hex: string): void;
  reset(): void;
  close(): Promise<void>;
}

const UINT_3600 = "0x" + (3600).toString(16).padStart(64, "0");

export async function startMockRpc(opts: { chainId?: number; delayMs?: number; gzip?: boolean } = {}): Promise<MockRpc> {
  const chainId = opts.chainId ?? 31337;
  const requests: MockHttpRequest[] = [];
  let connections = 0;
  let failQueue: number[] = [];
  let callResult = UINT_3600;

  const answer = (req: { id?: unknown; method?: unknown; params?: unknown }): Record<string, unknown> => {
    const base = { jsonrpc: "2.0", id: req.id ?? null };
    switch (req.method) {
      case "eth_chainId":
        return { ...base, result: "0x" + chainId.toString(16) };
      case "net_version":
        return { ...base, result: String(chainId) };
      case "eth_blockNumber":
        return { ...base, result: "0x2a" };
      case "eth_call":
        return { ...base, result: callResult };
      case "eth_getLogs":
        return { ...base, result: [] };
      case "eth_gasPrice":
      case "eth_maxPriorityFeePerGas":
        return { ...base, result: "0x1" };
      default:
        return { ...base, error: { code: -32601, message: `the method ${String(req.method)} does not exist/is not available` } };
    }
  };

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const rec: MockHttpRequest = { index: requests.length, status: 200, bytesIn: body.length, bytesOut: 0, bodyBytes: 0, batch: false, methods: [], callTargets: [] };
      requests.push(rec);
      let parsed: unknown = null;
      try {
        parsed = JSON.parse(body.toString("utf8"));
      } catch {
        parsed = null;
      }
      const items = Array.isArray(parsed) ? parsed : parsed === null ? [] : [parsed];
      rec.batch = Array.isArray(parsed);
      for (const it of items as Array<{ method?: unknown; params?: unknown }>) {
        rec.methods.push(String(it?.method ?? "?"));
        const p0 = Array.isArray(it?.params) ? (it.params[0] as { to?: unknown } | undefined) : undefined;
        rec.callTargets.push(it?.method === "eth_call" && typeof p0?.to === "string" ? p0.to.toLowerCase() : null);
      }
      const forced = failQueue.shift();
      let status = 200;
      let out: string;
      if (forced !== undefined) {
        status = forced;
        out = "{}";
      } else if (parsed === null) {
        status = 400;
        out = JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
      } else {
        const answers = (items as Array<{ id?: unknown; method?: unknown; params?: unknown }>).map(answer);
        out = JSON.stringify(Array.isArray(parsed) ? answers : answers[0]);
      }
      const plain = Buffer.from(out, "utf8");
      const bytes = opts.gzip ? gzipSync(plain) : plain;
      rec.status = status;
      rec.bytesOut = bytes.length;
      rec.bodyBytes = plain.length;
      const send = () => {
        res.writeHead(status, { "content-type": "application/json", "content-length": String(bytes.length), ...(opts.gzip ? { "content-encoding": "gzip" } : {}) });
        res.end(bytes);
      };
      if (opts.delayMs && opts.delayMs > 0) setTimeout(send, opts.delayMs);
      else send();
    });
  });
  server.on("connection", () => {
    connections++;
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    port,
    chainId,
    requests,
    okPosts: () => requests.filter((r) => r.status === 200),
    byMethod: () => {
      const out: Record<string, number> = {};
      for (const r of requests) if (r.status === 200) for (const m of r.methods) out[m] = (out[m] ?? 0) + 1;
      return out;
    },
    connections: () => connections,
    failNext: (status, times = 1) => {
      for (let i = 0; i < times; i++) failQueue.push(status);
    },
    setCallResult: (hex) => {
      callResult = hex;
    },
    reset: () => {
      requests.length = 0;
      failQueue = [];
      connections = 0;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** A loopback port that nothing listens on (bound once by the OS, then released). */
export async function closedPort(): Promise<number> {
  const srv = http.createServer();
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
  const port = (srv.address() as AddressInfo).port;
  await new Promise<void>((r) => srv.close(() => r()));
  return port;
}
