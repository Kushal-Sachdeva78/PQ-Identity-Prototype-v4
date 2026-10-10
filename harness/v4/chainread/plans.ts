import type { LedgerV4 } from "@pqid/v4/ledger";

/**
 * Read plans for the chain-read series (docs/v4/CHAINREAD.md). A ReadPlan is a Proxy on one
 * client LedgerV4 that the verifier or wallet uses instead of the ledger itself. It times every
 * OUTERMOST read the role makes (a read that another read makes internally, such as
 * resolveDidRecord inside getPopSignature, runs on the ledger itself and is not seen) and, in
 * the concurrent plan, starts reads early.
 *
 * - sequential: pass-through; the role's own (shipped) order and awaits.
 * - concurrent ("variant, not shipped"): emulates a code change that issues independent reads
 *   together. On the first read of a key group (rules below, derived from the shipped
 *   verifier.ts, governance.ts and wallet.ts), every read the shipped code makes for that group
 *   is started at once on the ledger; the role's own calls are then served from per-(method,
 *   args) FIFO queues. The JSON-RPC requests are therefore the same multiset as the sequential
 *   plan's (the series check this per presentation); only their timing differs.
 *   A call with no queued result and no rule goes to the ledger directly and is reported as
 *   unplanned; a queued result nobody used is reported as left over. The series treat either as
 *   an equivalence error, never as a timing.
 *
 * Prefetch tables (one group per key, fired once per presentation):
 *   verifier, issuer pair (did, controller), on resolveDidRecord(did, controller):
 *     resolveDidRecord x2, getPopSignature, latestAccreditation(did), currentEpoch
 *   wallet, verifier pair (the request's verifier), on resolveDidRecord(verifierDid, controller):
 *     resolveDidRecord x2, getPopSignature, latestKemKey
 *   wallet, issuer DID, on latestAccreditation(issuerDid):
 *     latestAccreditation x2, getMinAnchorInterval()
 *   wallet, issuer pair, on resolveDidRecord(issuerDid, controller):
 *     resolveDidRecord x2, getPopSignature, currentEpoch
 */

export const PLAN_READS = [
  "resolveDidRecord",
  "getPopSignature",
  "latestAccreditation",
  "currentEpoch",
  "latestKemKey",
  "getMinAnchorInterval",
  "getMaxWindow",
  "chainId",
] as const;
export type ReadMethod = (typeof PLAN_READS)[number];
const READ_SET = new Set<string>(PLAN_READS);

export type PlannedRead = readonly [ReadMethod, readonly unknown[]];

export interface PrefetchRule {
  name: string;
  on: ReadMethod;
  when?: (args: readonly unknown[]) => boolean;
  group: (args: readonly unknown[]) => PlannedRead[];
}

export interface PrefetchTable {
  role: "verifier" | "wallet" | "readSet";
  rules: readonly PrefetchRule[];
}

const s = (x: unknown) => String(x);

/** The verifier's reads per presentation (verifier.ts checkPresentation, governance.ts). */
export function verifierTable(): PrefetchTable {
  return {
    role: "verifier",
    rules: [
      {
        name: "verifier: issuer pair",
        on: "resolveDidRecord",
        group: ([did, ctrl]) => [
          ["resolveDidRecord", [s(did), s(ctrl)]],
          ["resolveDidRecord", [s(did), s(ctrl)]],
          ["getPopSignature", [s(did), s(ctrl)]],
          ["latestAccreditation", [s(did)]],
          ["currentEpoch", [s(did), s(ctrl)]],
        ],
      },
    ],
  };
}

/** The wallet's reads per presentation (wallet.ts checkRequest and checkIssuerData). */
export function walletTable(verifierDid: string): PrefetchTable {
  return {
    role: "wallet",
    rules: [
      {
        name: "wallet: verifier pair",
        on: "resolveDidRecord",
        when: ([did]) => did === verifierDid,
        group: ([did, ctrl]) => [
          ["resolveDidRecord", [s(did), s(ctrl)]],
          ["resolveDidRecord", [s(did), s(ctrl)]],
          ["getPopSignature", [s(did), s(ctrl)]],
          ["latestKemKey", [s(did), s(ctrl)]],
        ],
      },
      {
        name: "wallet: issuer DID",
        on: "latestAccreditation",
        group: ([did]) => [
          ["latestAccreditation", [s(did)]],
          ["latestAccreditation", [s(did)]],
          ["getMinAnchorInterval", []],
        ],
      },
      {
        name: "wallet: issuer pair",
        on: "resolveDidRecord",
        when: ([did]) => did !== verifierDid,
        group: ([did, ctrl]) => [
          ["resolveDidRecord", [s(did), s(ctrl)]],
          ["resolveDidRecord", [s(did), s(ctrl)]],
          ["getPopSignature", [s(did), s(ctrl)]],
          ["currentEpoch", [s(did), s(ctrl)]],
        ],
      },
    ],
  };
}

export interface OuterCall {
  method: string;
  /** ms since the plan's begin(). */
  t0Ms: number;
  t1Ms: number;
  /** Served from a prefetch queue (concurrent plan). */
  prefetched: boolean;
  ok: boolean;
}

export interface PlanReport {
  mode: "sequential" | "concurrent";
  role: string | null;
  outerCalls: OuterCall[];
  /** Sum of outer-call durations, ms (equals chainUnionMs when calls never overlap). */
  chainSumMs: number;
  /** Time during which at least one outer call was pending, ms. */
  chainUnionMs: number;
  groupsFired: string[];
  prefetchStarted: number;
  prefetchConsumed: number;
  /** Prefetched results nobody asked for (must be 0). */
  leftOver: string[];
  /** Calls with neither a queued result nor a rule (must be empty in the concurrent plan). */
  unplanned: string[];
}

const keyOf = (m: string, args: readonly unknown[]) => `${m}:${JSON.stringify(args)}`;

/** Union length of [t0, t1] intervals. */
export function unionMs(xs: ReadonlyArray<{ t0Ms: number; t1Ms: number }>): number {
  const iv = [...xs].sort((a, b) => a.t0Ms - b.t0Ms);
  let total = 0;
  let curA = -Infinity;
  let curB = -Infinity;
  for (const x of iv) {
    if (x.t0Ms > curB) {
      if (curB > curA) total += curB - curA;
      curA = x.t0Ms;
      curB = x.t1Ms;
    } else if (x.t1Ms > curB) {
      curB = x.t1Ms;
    }
  }
  if (curB > curA) total += curB - curA;
  return total;
}

export class ReadPlan {
  readonly proxy: LedgerV4;
  private t0 = process.hrtime.bigint();
  private calls: OuterCall[] = [];
  private table: PrefetchTable | null = null;
  private fifo = new Map<string, Array<Promise<unknown>>>();
  private fired = new Set<string>();
  private groupsFired: string[] = [];
  private started = 0;
  private consumed = 0;
  private unplanned: string[] = [];
  private pending = new Set<Promise<unknown>>();

  constructor(
    readonly target: LedgerV4,
    readonly mode: "sequential" | "concurrent"
  ) {
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const plan = this;
    this.proxy = new Proxy(target, {
      get(t, prop, receiver) {
        const v = Reflect.get(t, prop, receiver) as unknown;
        if (typeof prop !== "string" || typeof v !== "function" || !READ_SET.has(prop)) return v;
        const fn = v as (...a: unknown[]) => Promise<unknown>;
        return function (...args: unknown[]) {
          return plan.outer(prop as ReadMethod, fn, args);
        };
      },
    });
  }

  private ms(): number {
    return Number(process.hrtime.bigint() - this.t0) / 1e6;
  }

  /** Start a presentation: clear the record and set the prefetch table (concurrent plan). */
  begin(table: PrefetchTable | null = null): void {
    if (this.mode === "concurrent" && !table) throw new Error("the concurrent plan needs a prefetch table");
    this.t0 = process.hrtime.bigint();
    this.calls = [];
    this.table = this.mode === "concurrent" ? table : null;
    this.fifo.clear();
    this.fired.clear();
    this.groupsFired = [];
    this.started = 0;
    this.consumed = 0;
    this.unplanned = [];
    this.pending.clear();
  }

  private startRead(m: ReadMethod, args: readonly unknown[]): Promise<unknown> {
    const fn = (this.target as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>)[m];
    if (typeof fn !== "function") throw new Error(`LedgerV4.${m} is missing`);
    const p = Promise.resolve().then(() => fn.apply(this.target, [...args]));
    // a prefetched read that fails before anyone awaits it must not become an unhandled rejection
    p.catch(() => undefined);
    this.pending.add(p);
    void p.finally(() => this.pending.delete(p)).catch(() => undefined);
    return p;
  }

  private fire(m: ReadMethod, args: readonly unknown[]): void {
    if (!this.table) return;
    for (const rule of this.table.rules) {
      if (rule.on !== m || (rule.when && !rule.when(args))) continue;
      const gk = `${rule.name}|${JSON.stringify(args)}`;
      if (this.fired.has(gk)) continue;
      this.fired.add(gk);
      this.groupsFired.push(rule.name);
      for (const [gm, ga] of rule.group(args)) {
        const k = keyOf(gm, ga);
        const q = this.fifo.get(k) ?? [];
        q.push(this.startRead(gm, ga));
        this.fifo.set(k, q);
        this.started++;
      }
      return;
    }
  }

  private async outer(m: ReadMethod, fn: (...a: unknown[]) => Promise<unknown>, args: unknown[]): Promise<unknown> {
    const t0Ms = this.ms();
    let prefetched = false;
    let p: Promise<unknown>;
    if (this.mode === "concurrent" && m !== "chainId") {
      const k = keyOf(m, args);
      if (!(this.fifo.get(k)?.length ?? 0)) this.fire(m, args);
      const q = this.fifo.get(k);
      if (q && q.length > 0) {
        p = q.shift() as Promise<unknown>;
        this.consumed++;
        prefetched = true;
      } else {
        this.unplanned.push(k);
        p = fn.apply(this.target, args);
      }
    } else {
      p = fn.apply(this.target, args);
    }
    let ok = false;
    try {
      const v = await p;
      ok = true;
      return v;
    } finally {
      this.calls.push({ method: m, t0Ms, t1Ms: this.ms(), prefetched, ok });
    }
  }

  /** End the presentation: wait for stray prefetched reads and report. */
  async end(): Promise<PlanReport> {
    const leftOver: string[] = [];
    for (const [k, q] of this.fifo) for (let i = 0; i < q.length; i++) leftOver.push(k);
    await Promise.allSettled([...this.pending]);
    const calls = this.calls;
    return {
      mode: this.mode,
      role: this.table?.role ?? null,
      outerCalls: calls,
      chainSumMs: calls.reduce((a, c) => a + (c.t1Ms - c.t0Ms), 0),
      chainUnionMs: unionMs(calls),
      groupsFired: [...this.groupsFired],
      prefetchStarted: this.started,
      prefetchConsumed: this.consumed,
      leftOver,
      unplanned: [...this.unplanned],
    };
  }
}

/** The six reads of E4's besu subcommand (scale.ts READ_CALLS), for the per-read series. */
export const SIX_READS = ["resolveDidRecord", "getPopSignature", "latestAccreditation", "currentEpoch", "latestKemKey", "getMinAnchorInterval"] as const;
export type SixRead = (typeof SIX_READS)[number];

export interface SixReadIds {
  issuerDid: string;
  issuerController: string;
  verifierDid: string;
  verifierController: string;
}

/** One of the six reads on a ledger (the arguments E4 used). */
export function sixRead(L: LedgerV4, r: SixRead, ids: SixReadIds): Promise<unknown> {
  switch (r) {
    case "resolveDidRecord":
      return L.resolveDidRecord(ids.issuerDid, ids.issuerController);
    case "getPopSignature":
      return L.getPopSignature(ids.issuerDid, ids.issuerController);
    case "latestAccreditation":
      return L.latestAccreditation(ids.issuerDid);
    case "currentEpoch":
      return L.currentEpoch(ids.issuerDid, ids.issuerController);
    case "latestKemKey":
      return L.latestKemKey(ids.verifierDid, ids.verifierController);
    case "getMinAnchorInterval":
      return L.getMinAnchorInterval();
  }
}
