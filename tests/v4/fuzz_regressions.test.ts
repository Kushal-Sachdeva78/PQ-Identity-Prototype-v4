import http from "node:http";
import type { AddressInfo } from "node:net";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { HolderWalletV4, WalletRefusal, type WalletV4Config } from "@pqid/v4/wallet";
import { isProofRequestV4, newRequest, requestShapeErrors, type ProofRequestV4 } from "@pqid/v4/session";
import { World } from "@pqid/v4/world";
import type { VerifierV4 } from "@pqid/v4/verifier";
import { DEFAULT_TYPE_ID } from "@pqid/v4/constants";

/**
 * Regression fixtures for the two packages/v4 defects found by the fz1 fuzz campaign and its
 * triage (ROBUSTNESS.md section 7: a confirmed and fixed failure becomes a regression fixture).
 *
 * 1. fz1 T-wallet-req (failure d684e06eec1c, 13 cases: 5 undefined roots, 8 null roots):
 *    HolderWalletV4.checkRequest, and present() through it, threw a TypeError on a null or
 *    undefined request instead of WalletRefusal("requestShape").
 * 2. Triage second opinion on the fz1 "incomplete" finding: requestShapeErrors spread the
 *    policy's error list into push(), so a JSON request whose policy had about 125,000 or more
 *    extra keys threw RangeError (call stack) in requestShapeErrors, checkRequest and present.
 *
 * Both failed closed. The refusals must come before any ledger or clock access, so the wallet
 * here gets a ledger and a clock that throw on any access (as the triage probe did).
 */

/** A stand-in that records and throws on any access (get, has, set, keys, descriptors, prototype). */
function tripwire(name: string, touched: string[]): object {
  const fail = (what: string): never => {
    touched.push(`${name}: ${what}`);
    throw new Error(`${name} touched (${what})`);
  };
  return new Proxy(
    {},
    {
      get: (_t, k) => fail(`get ${String(k)}`),
      has: (_t, k) => fail(`has ${String(k)}`),
      set: (_t, k) => fail(`set ${String(k)}`),
      ownKeys: () => fail("ownKeys"),
      getOwnPropertyDescriptor: (_t, k) => fail(`getOwnPropertyDescriptor ${String(k)}`),
      getPrototypeOf: () => fail("getPrototypeOf"),
    }
  );
}

async function isolatedWallet(): Promise<{ wallet: HolderWalletV4; touched: string[] }> {
  const touched: string[] = [];
  const cfg = {
    ledger: tripwire("ledger", touched),
    clock: tripwire("clock", touched),
    pinnedGovernancePk: Buffer.alloc(0),
  } as unknown as WalletV4Config;
  return { wallet: await HolderWalletV4.create(cfg), touched };
}

/** The wallet's private state that a request may change (date reservation, KEM rollback guard). */
function walletState(w: HolderWalletV4): { dateLog: number; kemNotBefore: number } {
  const s = w as unknown as { dateLog: unknown[]; kemNotBefore: Map<string, number> };
  return { dateLog: s.dateLog.length, kemNotBefore: s.kemNotBefore.size };
}

async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (e) {
    return e;
  }
  throw new Error("expected a rejection; the call resolved");
}

function describeError(e: unknown): string {
  return e instanceof WalletRefusal ? `WalletRefusal(${e.check})` : `${(e as Error)?.constructor?.name}: ${(e as Error)?.message}`;
}

const NULLISH: Array<[string, () => unknown]> = [
  ["null", () => null],
  ["undefined", () => undefined],
  ['JSON.parse("null")', () => JSON.parse("null") as unknown],
];

describe("fz1 T-wallet-req: a null or undefined request is refused as requestShape", () => {
  it.each(NULLISH)("checkRequest(%s) rejects with WalletRefusal requestShape before any ledger or clock access", async (_name, make) => {
    const { wallet, touched } = await isolatedWallet();
    const e = await rejection(wallet.checkRequest(make() as ProofRequestV4));
    expect(describeError(e)).toBe("WalletRefusal(requestShape)");
    expect(e).toBeInstanceOf(WalletRefusal);
    expect(touched).toEqual([]);
    expect(walletState(wallet)).toEqual({ dateLog: 0, kemNotBefore: 0 });
  });

  it.each(NULLISH)("present(%s) rejects with WalletRefusal requestShape before any ledger or clock access", async (_name, make) => {
    const { wallet, touched } = await isolatedWallet();
    const e = await rejection(wallet.present(make() as ProofRequestV4));
    expect(describeError(e)).toBe("WalletRefusal(requestShape)");
    expect(e).toBeInstanceOf(WalletRefusal);
    expect(touched).toEqual([]);
    expect(walletState(wallet)).toEqual({ dateLog: 0, kemNotBefore: 0 });
  });

  it("the other non-object roots the campaign tried stay refused as requestShape", async () => {
    const { wallet, touched } = await isolatedWallet();
    for (const v of ["str", "", 0, Number.NaN, Number.POSITIVE_INFINITY, true, false, 10n, [], {}]) {
      for (const call of [() => wallet.checkRequest(v as never), () => wallet.present(v as never)]) {
        const e = await rejection(call());
        expect(describeError(e), `root ${String(v)}`).toBe("WalletRefusal(requestShape)");
      }
    }
    expect(touched).toEqual([]);
    expect(walletState(wallet)).toEqual({ dateLog: 0, kemNotBefore: 0 });
  });
});

/** A well-formed request with fixed fields (no chain needed for shape checks). */
function fixedRequest(): ProofRequestV4 {
  return newRequest({
    verifierDid: "did:pq:" + "a".repeat(44),
    verifierController: "0x" + "1".repeat(40),
    chainId: 31337,
    policy: { predicate: "age_gte", threshold: 18, typeId: DEFAULT_TYPE_ID, today: 20261003 },
    issuedAt: 1_790_000_000,
  });
}

/** The size of the fz1 triage probe (about 1.45 MB of JSON); the fixture never goes below it. */
const TRIAGE_POLICY_KEYS = 130_000;
/** Largest argument count the probe below tries before it concludes that a spread does not overflow. */
const SPREAD_PROBE_CAP = 4_000_000;

/** Whether push(...list) with n elements (a packed array, as schemaErrors builds) overflows the call stack. */
function spreadOverflows(n: number): boolean {
  const list: string[] = [];
  for (let i = 0; i < n; i++) list.push("x");
  try {
    ([] as string[]).push(...list);
    return false;
  } catch (e) {
    if (e instanceof RangeError) return true;
    throw e;
  }
}

/**
 * The smallest argument count whose spread into push() overflows on this runtime (doubling, then
 * bisection), or null when none up to SPREAD_PROBE_CAP does. It depends on the stack size and the
 * V8 version (Node 24.18, V8 13.6, default stack: about 125,000).
 */
function smallestOverflowingSpread(): number | null {
  let ok = 0;
  let n = 1024;
  while (!spreadOverflows(n)) {
    ok = n;
    if (n >= SPREAD_PROBE_CAP) return null;
    n = Math.min(n * 2, SPREAD_PROBE_CAP);
  }
  let bad = n;
  while (bad - ok > 1) {
    const mid = Math.floor((ok + bad) / 2);
    if (spreadOverflows(mid)) bad = mid;
    else ok = mid;
  }
  return bad;
}

// Sized at run time, so the fixture stays meaningful on a runtime with a larger stack: at least
// the triage size and at least twice the smallest overflowing spread found here.
const SPREAD_OVERFLOW_AT = smallestOverflowingSpread();
const EXTRA_POLICY_KEYS = Math.max(TRIAGE_POLICY_KEYS, 2 * (SPREAD_OVERFLOW_AT ?? 0));

describe(`fz1 triage: requestShapeErrors on a JSON request whose policy has ${EXTRA_POLICY_KEYS} extra keys (spread overflow here from ${SPREAD_OVERFLOW_AT ?? "none"} arguments)`, () => {
  let wide: unknown;
  let wireBytes = 0;
  beforeAll(() => {
    console.log(
      `[fuzz_regressions] spread into push() overflows from ${SPREAD_OVERFLOW_AT ?? `no count up to ${SPREAD_PROBE_CAP}`} arguments on Node ${process.versions.node} (V8 ${process.versions.v8}); extra policy keys N = ${EXTRA_POLICY_KEYS}`
    );
    const base = fixedRequest();
    const policy: Record<string, unknown> = { ...base.policy };
    for (let i = 0; i < EXTRA_POLICY_KEYS; i++) policy["x" + i] = 0;
    // Parsed from JSON text, exactly as a wallet receives a request from a verifier.
    const text = JSON.stringify({ ...base, policy });
    wireBytes = text.length;
    wide = JSON.parse(text) as unknown;
  });

  it("returns one error per extra key, in key order, without throwing", () => {
    expect(wireBytes).toBeGreaterThan(1_000_000);
    let errors: string[] = [];
    expect(() => {
      errors = requestShapeErrors(wide);
    }).not.toThrow();
    expect(errors.length).toBe(EXTRA_POLICY_KEYS);
    expect(errors[0]).toBe("request.policy.x0 is not an allowed field");
    expect(errors[EXTRA_POLICY_KEYS - 1]).toBe(`request.policy.x${EXTRA_POLICY_KEYS - 1} is not an allowed field`);
    expect(isProofRequestV4(wide)).toBe(false);
    // The fixture is meaningful on this runtime: the replaced form, push(...list), overflows the
    // call stack with this many errors. When no spread up to the probe cap overflows here, the old
    // defect cannot occur on this runtime; the line above still checks the fixed code at N.
    if (SPREAD_OVERFLOW_AT === null) {
      console.warn(`[fuzz_regressions] no spread overflow up to ${SPREAD_PROBE_CAP} arguments on this runtime; the old failure is not reproducible here`);
    } else {
      expect(() => ([] as string[]).push(...errors)).toThrow(RangeError);
    }
  });

  it("keeps the error list unchanged otherwise: top-level errors first, then policy errors in key order", () => {
    const base = fixedRequest() as unknown as Record<string, unknown>;
    const { issuedAt: _dropped, ...rest } = base;
    const bad = { ...rest, policy: { ...(base["policy"] as Record<string, unknown>), threshold: 300, extra: 1 } };
    expect(requestShapeErrors(bad)).toEqual([
      "request.issuedAt is missing",
      "request.policy.threshold must be an integer in [0, 255]",
      "request.policy.extra is not an allowed field",
    ]);
    expect(requestShapeErrors(fixedRequest())).toEqual([]);
  });

  it("checkRequest and present refuse it as requestShape before any ledger or clock access", async () => {
    const { wallet, touched } = await isolatedWallet();
    for (const call of [() => wallet.checkRequest(wide as ProofRequestV4), () => wallet.present(wide as ProofRequestV4)]) {
      const e = await rejection(call());
      expect(describeError(e)).toBe("WalletRefusal(requestShape)");
    }
    expect(touched).toEqual([]);
    expect(walletState(wallet)).toEqual({ dateLog: 0, kemNotBefore: 0 });
  });
});

// The honest path on a live chain: Anvil on an OS-assigned port, never a D-034 port.
async function freePort(): Promise<number> {
  const s = http.createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
  const p = (s.address() as AddressInfo).port;
  await new Promise<void>((r) => s.close(() => r()));
  return p;
}

describe("fz1 regressions: the honest path is unchanged (Anvil)", () => {
  let world: World;
  let V: VerifierV4;
  let holder: HolderWalletV4;
  beforeAll(async () => {
    world = await World.create({ port: await freePort() });
    const A = await world.addIssuer("A");
    holder = await world.addHolder();
    await world.issue(A, holder, { birthDate: 19800101 });
    await world.publishEpoch(A);
    V = await world.addVerifier("V");
  }, 300_000);
  afterAll(() => world?.stop());

  it("an honest request passes checkRequest with the verifier's registered KEM key, also as a JSON wire copy", async () => {
    const req = await V.newRequest({ predicate: "age_gte", threshold: 18, typeId: DEFAULT_TYPE_ID });
    expect(requestShapeErrors(req)).toEqual([]);
    const registered = Buffer.from(V.opts.identity.kem.publicKey);
    const a = await world.addHolder();
    const { kemPk } = await a.checkRequest(req);
    expect(kemPk.equals(registered)).toBe(true);
    expect(walletState(a)).toEqual({ dateLog: 1, kemNotBefore: 1 });
    const b = await world.addHolder();
    const { kemPk: wireKemPk } = await b.checkRequest(JSON.parse(JSON.stringify(req)) as ProofRequestV4);
    expect(wireKemPk.equals(registered)).toBe(true);
  });

  it("an honest presentation is still accepted, and the same wallet then refuses null and undefined as requestShape", async () => {
    const req = await V.newRequest({ predicate: "age_gte", threshold: 18, typeId: DEFAULT_TYPE_ID });
    const { reply } = await holder.present(req, { callerOrigin: V.opts.identity.origin });
    const d = await V.verifyReply(reply);
    expect(d.failedChecks).toEqual([]);
    expect(d.accepted).toBe(true);
    const before = walletState(holder);
    for (const [, make] of NULLISH) {
      expect(describeError(await rejection(holder.checkRequest(make() as ProofRequestV4)))).toBe("WalletRefusal(requestShape)");
      expect(describeError(await rejection(holder.present(make() as ProofRequestV4)))).toBe("WalletRefusal(requestShape)");
    }
    expect(walletState(holder)).toEqual(before);
  }, 600_000);
});
