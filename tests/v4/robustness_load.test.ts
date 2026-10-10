import { describe, it, expect } from "vitest";
import { mlKemKeygen } from "@pqid/v4/pqc";
import { VerifierSessionStore, verifierOpenReply, walletOpenSession, MAX_PRESENTATION_BYTES } from "@pqid/v4/session";
import { presentationShapeError, type PresentationV4 } from "@pqid/v4/verifier";
import {
  FULL_LEVELS,
  SMOKE_LEVELS,
  HOSTILE_CLASSES,
  HOSTILE_EXPECTED_CHECKS,
  buildLoadSchedule,
  cellsOf,
  closedLoop,
  clockVerdict,
  correctnessIndices,
  expectedOutcome,
  freeIndices,
  passRates,
  quantile7,
  rotation,
  sameCheckSet,
  settleLate,
  CLOCK_GAP_LIMIT_MS,
  TICK_GAP_LIMIT_MS,
} from "../../harness/v4/robustness/load_lib.ts";
import { buildHostile, notJson, unknownSession, tamperedBox, wideNonCanonical, longDecimalSignal, prettyPrinted, sealCanonical, wire, type SessionKeys } from "../../harness/v4/robustness/hostile.ts";
import { Rng } from "../../harness/v4/robustness/rng.ts";
import * as G from "../../harness/v4/robustness/valid_gen.ts";
import { SEEDS } from "../../harness/v4/lib/seeds.ts";

/**
 * Unit tests of the load test's pure parts (harness/v4/robustness/load_lib.ts) and of the
 * hostile-reply constructions (hostile.ts) against the package's own transport step
 * (verifierOpenReply) with an in-memory ML-KEM key. No chain, no timing.
 */

describe("load_lib: schedule, rotation, rates", () => {
  it("type-7 quantiles equal numpy's linear method", () => {
    expect(quantile7([1, 2, 3, 4], 0.5)).toBe(2.5);
    expect(quantile7([1, 2, 3, 4], 0.1)).toBeCloseTo(1.3, 12);
    expect(quantile7([10], 0.99)).toBe(10);
    expect(quantile7([], 0.5)).toBeNull();
  });

  it("every block holds every cell once; the schedule is reproducible from the seed", () => {
    const s1 = buildLoadSchedule(FULL_LEVELS, SEEDS.robustness.load);
    const s2 = buildLoadSchedule(FULL_LEVELS, SEEDS.robustness.load);
    expect(s1).toEqual(s2);
    const ids = cellsOf(FULL_LEVELS).map((c) => c.id).sort();
    // 24 throughput cells + 16 hostile-cost cells + 1 correctness batch
    expect(ids).toHaveLength(2 * 4 * 3 + 2 * 8 + 1);
    expect(s1).toHaveLength(FULL_LEVELS.warmupBlocks + FULL_LEVELS.measuredBlocks);
    for (const b of s1) {
      expect([...b.order].sort()).toEqual(ids);
      expect(b.offsets).toHaveLength(6);
      for (const o of b.offsets) expect(o >= 0 && o < FULL_LEVELS.P).toBe(true);
    }
    expect(s1[0]?.measured).toBe(false);
    expect(s1.filter((b) => b.measured)).toHaveLength(8);
    expect(s1[1]?.order).not.toEqual(s1[2]?.order);
    expect(buildLoadSchedule(FULL_LEVELS, 1)[1]?.order).not.toEqual(s1[1]?.order);
  });

  it("rotation verifies each pool reply at most once per worker store; correctness indices are disjoint", () => {
    const r = rotation(12, 8, 10);
    expect(r).toEqual([10, 11, 0, 1, 2, 3, 4, 5]);
    expect(new Set(r).size).toBe(8);
    expect(() => rotation(4, 5, 0)).toThrow();
    for (const L of [FULL_LEVELS, SMOKE_LEVELS]) {
      for (let w = 0; w < Math.max(...L.workers); w++) {
        const ix = correctnessIndices(L, w);
        const all = [...ix.honest, ...ix.dupGroups, ...ix.targets];
        expect(new Set(all).size).toBe(all.length);
        expect(all.every((i) => i >= 0 && i < L.P)).toBe(true);
      }
    }
  });

  it("steady-state and whole-pass rates", () => {
    const ends = Array.from({ length: 101 }, (_, i) => 1000 + i * 10); // one completion every 10 ms
    const r = passRates(ends, 1000);
    // 81 completions in [t10, t90] = 800 ms are 80 intervals of 10 ms: exactly 100 per second
    expect(r.steadyPerSec).toBeCloseTo(100, 9);
    expect(r.wholePerSec).toBeCloseTo(101 / 1, 6);
    expect(passRates([], 0).steadyPerSec).toBeNull();
    expect(passRates([5], 0).steadyPerSec).toBeNull();
  });

  it("free pool indices lie outside every worker's correctness batch", () => {
    for (const L of [FULL_LEVELS, SMOKE_LEVELS]) {
      const used = new Set<number>();
      for (let w = 0; w < Math.max(...L.workers); w++) {
        const ix = correctnessIndices(L, w);
        for (const i of [...ix.honest, ...ix.dupGroups, ...ix.targets]) used.add(i);
      }
      const free = freeIndices(L);
      expect(free.length).toBeGreaterThan(0);
      expect(free.every((i) => !used.has(i) && i >= 0 && i < L.P)).toBe(true);
      expect(free.length + used.size).toBe(L.P);
      expect(free[0]).toBe(L.P - 1);
    }
    expect(freeIndices(FULL_LEVELS)).toHaveLength(400 - 6 * 12);
  });

  it("expected hostile outcomes and exact check sets", () => {
    expect(expectedOutcome("HC0")).toBe("accepted");
    expect(expectedOutcome("HC5")).toBe("rejected:groth16");
    expect(expectedOutcome("HC1")).toBe("rejected:transcriptDecrypts");
    expect(Object.keys(HOSTILE_EXPECTED_CHECKS).sort()).toEqual(["HC1", "HC2", "HC3", "HC4", "HC5", "HC6", "HC7"]);
    expect(sameCheckSet(["groth16"], ["groth16"])).toBe(true);
    expect(sameCheckSet(["nonceBinding", "groth16"], ["groth16"])).toBe(false);
    expect(sameCheckSet(["groth16", "groth16"], ["groth16", "groth16"])).toBe(false);
    expect(sameCheckSet([], [])).toBe(true);
  });

  it("clock-gap verdict: wall against monotonic elapsed time, and the longest tick gap", () => {
    const ok = clockVerdict([0, 60_000], [1_000_000, 1_060_400], 250);
    expect(ok.clockGapMs).toBe(400);
    expect(ok.clockGap).toBe(false);
    // a 30 s suspend the monotonic clock did not count
    expect(clockVerdict([0, 60_000], [1_000_000, 1_090_000], 120).clockGap).toBe(true);
    // a wall clock stepped back by more than the limit
    expect(clockVerdict([0, 60_000], [1_000_000, 1_060_000 - CLOCK_GAP_LIMIT_MS - 1], 100).clockGap).toBe(true);
    // a stall of the event loop longer than the tick limit
    expect(clockVerdict([0, 60_000], [0, 60_000], TICK_GAP_LIMIT_MS + 1).clockGap).toBe(true);
    expect(clockVerdict([0, 60_000], [0, 60_000], TICK_GAP_LIMIT_MS).clockGap).toBe(false);
  });

  it("calls that outlive their timeout are handed back and can be waited for", async () => {
    const late: Array<Promise<unknown>> = [];
    let finished = 0;
    const recs = await closedLoop(
      [0, 1, 2],
      3,
      async (x) => {
        await new Promise((r) => setTimeout(r, x === 1 ? 150 : 5));
        finished++;
        return x;
      },
      50,
      late
    );
    expect(recs[1]?.timedOut).toBe(true);
    expect(late).toHaveLength(1);
    expect(finished).toBe(2);
    const s = await settleLate(late, 2000);
    expect(s).toEqual({ timedOut: 1, settled: 1, unsettled: 0 });
    expect(finished).toBe(3);
    const never = new Promise<void>(() => undefined);
    expect(await settleLate([never], 20)).toEqual({ timedOut: 1, settled: 0, unsettled: 1 });
    expect(await settleLate([], 20)).toEqual({ timedOut: 0, settled: 0, unsettled: 0 });
  });

  it("closed loop keeps at most `lanes` calls in flight, times each one and records timeouts", async () => {
    let inFlight = 0;
    let peak = 0;
    const recs = await closedLoop(
      Array.from({ length: 12 }, (_, i) => i),
      3,
      async (x) => {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, x === 5 ? 200 : 5));
        inFlight--;
        if (x === 7) throw new Error("boom");
        return x * 2;
      },
      100
    );
    expect(peak).toBe(3);
    expect(recs.map((r) => r.index)).toEqual(Array.from({ length: 12 }, (_, i) => i));
    expect(recs[5]?.timedOut).toBe(true);
    expect(recs[7]?.error).toContain("boom");
    expect(recs[2]?.value).toBe(4);
    for (const r of recs) expect(r.endNs >= r.startNs).toBe(true);
  });
});

describe("hostile replies against the package transport (verifierOpenReply)", () => {
  const kem = mlKemKeygen();
  const store = new VerifierSessionStore({ nowMs: () => 1_790_000_000_000 });
  const open = (): SessionKeys => {
    const req = store.open({ verifierDid: "did:pq:4Cq1", verifierController: "0x" + "1".repeat(40), chainId: 31337, policy: { predicate: "age_gte", threshold: 18, typeId: "pqid:type:age-credential:v1", today: 20260927 } });
    const ws = walletOpenSession(req, kem.publicKey);
    return { sessionId: req.sessionId, ct: ws.ciphertext, key: ws.key, iv: ws.iv, transcript: ws.transcript };
  };
  const rng = new Rng(SEEDS.robustness.load).fork("test");
  const pres = G.presentation(rng) as unknown as PresentationV4;
  const openReply = (w: Buffer) => verifierOpenReply(store, kem.privateKey, kem.publicKey, w);

  it("a canonical seal opens, and every hostile class fails where it should", () => {
    const s = open();
    const ok = openReply(wire(sealCanonical(s, pres)));
    expect(ok.ok).toBe(true);
    expect(presentationShapeError(ok.presentation)).toBeNull();
    expect(openReply(notJson(rng, wire(sealCanonical(s, pres)))).error).toBe("malformed");
    expect(openReply(unknownSession(rng, 64)).error).toBe("unknownSession");
    expect(openReply(tamperedBox(open(), pres, rng)).error).toBe("decryptFailed");
    expect(openReply(prettyPrinted(open(), pres)).error).toBe("malformed");
    const wide = wideNonCanonical(open(), rng);
    expect(wide.plaintextBytes).toBeLessThanOrEqual(MAX_PRESENTATION_BYTES);
    expect(wide.plaintextBytes).toBeGreaterThan(MAX_PRESENTATION_BYTES - 200);
    const w = openReply(wide.wire);
    expect(w.error).toBe("malformed");
    expect(w.detail).toContain("canonical");
    const long = longDecimalSignal(open(), pres, rng);
    expect(long.plaintextBytes).toBeLessThanOrEqual(MAX_PRESENTATION_BYTES);
    expect(long.plaintextBytes).toBeGreaterThan(MAX_PRESENTATION_BYTES - 200);
    const l = openReply(long.wire);
    expect(l.ok).toBe(true);
    expect(presentationShapeError(l.presentation)).toBe("public signals must be canonical decimals below p");
    // none of these consumed a session (verifierOpenReply never consumes)
    expect(store.status(s.sessionId)).toBe("open");
  });

  it("buildHostile cycles the large classes and gives every other item its own session", () => {
    const sessions: SessionKeys[] = [];
    const honest = open();
    const inp = { rng, newSession: () => { const s = open(); sessions.push(s); return s; }, presentations: [pres], honestWires: [wire(sealCanonical(honest, pres))], honestKeys: [honest], hc5Indices: [0] };
    const hc6 = buildHostile("HC6", 5, 2, inp);
    expect(hc6).toHaveLength(5);
    expect(new Set(hc6.map((x) => x.wire)).size).toBe(2);
    const before = sessions.length;
    const hc4 = buildHostile("HC4", 3, 2, inp);
    expect(new Set(hc4.map((x) => x.wire)).size).toBe(3);
    expect(sessions.length - before).toBe(3);
    expect(hc4.map((x) => x.sessionId)).toEqual(sessions.slice(before).map((s) => s.sessionId));
    // HC5 uses the honest sessions it is given, never a harness session
    const hc5 = buildHostile("HC5", 2, 2, inp);
    expect(sessions.length - before).toBe(3);
    expect(hc5.every((x) => x.sessionId === honest.sessionId)).toBe(true);
    expect(HOSTILE_CLASSES).toHaveLength(8);
  });

  it("HC5 is sealed into the presentation's own honest session: the nonce signal is right and only the proof differs", () => {
    // two honest sessions, each with a presentation whose nonce signal is that session's nonce
    const mk = () => {
      const req = store.open({ verifierDid: "did:pq:4Cq1", verifierController: "0x" + "1".repeat(40), chainId: 31337, policy: { predicate: "age_gte", threshold: 18, typeId: "pqid:type:age-credential:v1", today: 20260927 } });
      const ws = walletOpenSession(req, kem.publicKey);
      const p = G.presentation(rng) as unknown as PresentationV4;
      p.publicSignals[3] = ws.nonce.toString();
      return { keys: { sessionId: req.sessionId, ct: ws.ciphertext, key: ws.key, iv: ws.iv, transcript: ws.transcript } as SessionKeys, p };
    };
    const a = mk();
    const b = mk();
    const inp = { rng, newSession: () => { throw new Error("HC5 must not open harness sessions"); }, presentations: [a.p, b.p], honestWires: [], honestKeys: [a.keys, b.keys], hc5Indices: [1, 0] };
    const items = buildHostile("HC5", 3, 2, inp);
    expect(items.map((x) => x.sessionId)).toEqual([b.keys.sessionId, a.keys.sessionId, b.keys.sessionId]);
    for (const [k, it] of items.entries()) {
      const own = k % 2 === 0 ? b : a;
      const o = openReply(it.wire);
      expect(o.ok).toBe(true);
      expect(o.sessionId).toBe(own.keys.sessionId);
      const got = o.presentation as unknown as PresentationV4;
      // the nonce signal is the session's derived nonce: verifyReply's nonceBinding passes
      expect(got.publicSignals[3]).toBe((o.nonce as bigint).toString());
      expect(got.publicSignals).toEqual(own.p.publicSignals);
      expect(got.issuerDid).toBe(own.p.issuerDid);
      expect(got.epochStatement).toEqual(own.p.epochStatement);
      expect(got.proof).not.toEqual(own.p.proof);
      expect(presentationShapeError(got)).toBeNull();
    }
    // opening consumed nothing
    expect(store.status(a.keys.sessionId)).toBe("open");
    expect(store.status(b.keys.sessionId)).toBe("open");
  });
});
