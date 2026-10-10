import type { JsonRpcProvider } from "ethers";

/**
 * Logical JSON-RPC requests of one provider, for the equivalence rule of docs/v4/CHAINREAD.md:
 * a client variant must make the same reads as the shipped sequential plan. The capture wraps
 * the provider's send() (instance property, run time only) and records (method, params) of
 * every request that enters ethers' queue through it. Install it LAST (outermost), after the
 * round-trip trace and the multicall transport, so it sees the individual registry eth_calls a
 * multicall later aggregates ("multicall sub-calls expanded") and not the aggregate itself.
 * ethers' direct network detection (eth_chainId before the provider has started) does not pass
 * through send(); every comparison drops eth_chainId anyway.
 */

export interface WireRequest {
  method: string;
  params: unknown;
}

type SendFn = (method: string, params: unknown[] | Record<string, unknown>) => Promise<unknown>;
interface SendHolder {
  send: SendFn;
}

const CAPTURED = Symbol.for("pqid.v4.chainread.capture");

/** JSON with object keys sorted (stable across insertion order). */
export function stableJson(x: unknown): string {
  return JSON.stringify(x, (_k, v: unknown) => {
    if (typeof v === "bigint") return `${v.toString()}n`;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const o = v as Record<string, unknown>;
      return Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]]));
    }
    return v;
  });
}

/** One string per request: method and canonical params (hex lower-cased by ethers already). */
export function requestKey(r: WireRequest): string {
  return `${r.method} ${stableJson(r.params ?? [])}`;
}

export interface Capture {
  /** Requests since the last take/reset, in send order. */
  take(): WireRequest[];
  reset(): void;
  detach(): void;
}

/** Record every request that passes through provider.send (see the module header). */
export function captureRequests(provider: JsonRpcProvider): Capture {
  const p = provider as unknown as SendHolder & { [CAPTURED]?: true };
  if (p[CAPTURED]) throw new Error("provider already has a request capture");
  const own = Object.getOwnPropertyDescriptor(p, "send");
  const inner = p.send;
  let buf: WireRequest[] = [];
  const wrapped: SendFn = function (this: unknown, method, params) {
    // params are copied as JSON now: ethers does not change them later, but the copy is cheap
    buf.push({ method, params: JSON.parse(JSON.stringify(params ?? [])) as unknown });
    return inner.call(this, method, params);
  };
  p.send = wrapped;
  p[CAPTURED] = true;
  return {
    take: () => {
      const out = buf;
      buf = [];
      return out;
    },
    reset: () => {
      buf = [];
    },
    detach: () => {
      if (p.send !== wrapped) throw new Error("another wrapper was installed on top of the capture; detach in reverse order");
      if (own) Object.defineProperty(p, "send", own);
      else delete (p as unknown as Record<string, unknown>)["send"];
      delete p[CAPTURED];
    },
  };
}

/** Requests without ethers' network checks (eth_chainId), as keys. */
export function readKeys(reqs: readonly WireRequest[]): string[] {
  return reqs.filter((r) => r.method !== "eth_chainId").map(requestKey);
}

export type Multiset = Map<string, number>;

export function multiset(keys: Iterable<string>): Multiset {
  const m: Multiset = new Map();
  for (const k of keys) m.set(k, (m.get(k) ?? 0) + 1);
  return m;
}

export interface MultisetDiff {
  equal: boolean;
  /** In the reference but not (often enough) in the run. */
  missing: string[];
  /** In the run but not (as often) in the reference. */
  extra: string[];
}

export function compareMultisets(reference: Multiset, run: Multiset): MultisetDiff {
  const missing: string[] = [];
  const extra: string[] = [];
  for (const [k, n] of reference) {
    const m = run.get(k) ?? 0;
    for (let i = m; i < n; i++) missing.push(k);
  }
  for (const [k, n] of run) {
    const m = reference.get(k) ?? 0;
    for (let i = m; i < n; i++) extra.push(k);
  }
  return { equal: missing.length === 0 && extra.length === 0, missing, extra };
}

/** Counts by method (eth_chainId included), for records. */
export function methodCounts(reqs: readonly WireRequest[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const r of reqs) out[r.method] = (out[r.method] ?? 0) + 1;
  return out;
}
