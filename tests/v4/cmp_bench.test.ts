import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { abs, buildSchedule, sha256FileHex, sha256Hex, VERSIONS } from "../../harness/v4/bench/lib.ts";
import { SEEDS, assertUnusedSeed, seedFor } from "../../harness/v4/lib/seeds.ts";
import { guardOffending, readQuiesceExcluding, type QuiesceRecord } from "../../harness/v4/lib/quiesce.ts";
import { CPU_THRESHOLD_PERCENT } from "../../harness/v4/bench/guard.ts";
import {
  BENCH_PROTOCOL_NORMATIVE_SHA256,
  CIRCUITS,
  CMP_SEEDS,
  EDDSA_FILES,
  PINS_CMP_REL,
  PIN_KEYS,
  PROVE_CONDITIONS,
  REAL_MODE,
  RUNNER_CODE,
  TIMED_CODE,
  V2O2_EXPECTED,
  V2O2_FILES,
  V2_BEACON,
  WALLET_CONDITIONS,
  WALLET_SIZES,
  canonicalOrder,
  circuitSpecs,
  committedExtras,
  conditionIdOf,
  conditionNotes,
  gitClean,
  normativeSha,
  parseList,
  pinKeyForPath,
  protocolRecord,
  realModeProblems,
  resolveV4Key,
  walletSize,
  type RealModeParams,
} from "../../harness/v4/cmp/spec.ts";
import { WALLET_IMT_MAX, hash31, walletLeaves, walletRevKeys } from "../../harness/v4/cmp/wallet_data.ts";
import { buildEddsaFixture, EDDSA_FIXTURE } from "../../harness/v4/cmp/eddsa_fixture.ts";
import { HOST_PAUSE_GAP_SEC, IdleWatch, PHASE_D_QUIET_RULE, holdSmokeLock, holdWork, idleReading, phaseDQuiesce, type Clock } from "../../harness/v4/cmp/runner.ts";
import { MARKER_TOKEN_ENV, acquireMarker, type MarkerRoot } from "../../harness/v4/lib/markers.ts";
import { findPrivate, needles, privateKinds, scrubText } from "../../harness/v4/cmp/log_scrub.ts";
import { SMOKE_OUTPUT, moveSmokeOutput, stampOf } from "../../harness/v4/cmp/smoke_reset.ts";
import { buildWalletEntry } from "../../harness/v4/cmp/inputs.ts";
import { verifySignature } from "../../baselines/eddsa/lib.ts";
import { IMT_MAX } from "@pqid/v4/constants";

// harness/v4/cmp (comparable benchmark series, docs/v4/CMP.md): seeds, schedules, specs and pins,
// the EdDSA fixture, the wallet data generator, the idle clock and the smoke lock.

const COLD = CIRCUITS.map((c) => conditionIdOf(c));
/** First block of the cold schedule with the optional curve condition (seed 20261041, canonical order). */
const PINNED_CURVE_BLOCK0 = ["v4/snarkjs", "v2/snarkjs", "eddsa/snarkjs", "v3/snarkjs", "curve/snarkjs", "v2o2/snarkjs"];

describe("cmp: seeds and schedules (D-034)", () => {
  it("uses the three pre-registered comparable seeds from the registry", () => {
    expect(CMP_SEEDS).toEqual({ cold: 20261041, wallet: 20261042, warm: 20261043 });
    expect(CMP_SEEDS.cold).toBe(seedFor("comparable.coldOrder"));
    expect(CMP_SEEDS.wallet).toBe(seedFor("comparable.walletRebuilds"));
    expect(CMP_SEEDS.warm).toBe(SEEDS.comparable.warm);
    for (const s of Object.values(CMP_SEEDS)) expect(assertUnusedSeed(s).row).toBe("comparable");
  });

  it("builds the cold schedule deterministically, every block holding each circuit once", () => {
    const a = buildSchedule(COLD, 30, CMP_SEEDS.cold);
    const b = buildSchedule(COLD, 30, CMP_SEEDS.cold);
    expect(a).toEqual(b);
    expect(a).toHaveLength(150);
    for (let blk = 0; blk < 30; blk++) {
      const conds = a.filter((s) => s.block === blk).map((s) => s.condition).sort();
      expect(conds).toEqual([...COLD].sort());
    }
    // pinned first block: a change of the PRNG, the shuffle or the condition order shows here
    expect(a.slice(0, 5).map((s) => s.condition)).toEqual(["v3/snarkjs", "v2/snarkjs", "v4/snarkjs", "eddsa/snarkjs", "v2o2/snarkjs"]);
    expect(buildSchedule(COLD, 30, CMP_SEEDS.cold + 1)).not.toEqual(a);
  });

  it("builds the wallet and warm schedules from their own seeds", () => {
    const w = buildSchedule(["wallet1e5/node", "wallet1e6/node"], 10, CMP_SEEDS.wallet);
    expect(w).toHaveLength(20);
    expect(w.slice(0, 4).map((s) => s.condition)).toEqual(["wallet1e5/node", "wallet1e6/node", "wallet1e5/node", "wallet1e6/node"]);
    const k = buildSchedule(COLD, 35, CMP_SEEDS.warm, -5);
    expect(k[0]?.block).toBe(-5);
    expect(k.filter((s) => s.block < 0)).toHaveLength(25);
    expect(k.slice(0, 5).map((s) => s.condition)).toEqual(["v2o2/snarkjs", "v3/snarkjs", "v2/snarkjs", "v4/snarkjs", "eddsa/snarkjs"]);
  });

  it("puts --conditions into canonical order, so the typed order never changes a schedule", () => {
    const typed = parseList("v4,v2,curve,v3,v2o2,eddsa", PROVE_CONDITIONS, "--conditions") ?? [];
    const canon = canonicalOrder(typed, PROVE_CONDITIONS);
    expect(canon).toEqual(["v2", "v2o2", "v3", "v4", "eddsa", "curve"]);
    expect(canonicalOrder(["wallet1e6", "wallet1e5"], WALLET_CONDITIONS)).toEqual(["wallet1e5", "wallet1e6"]);
    expect(canonicalOrder(["eddsa", "v2"], CIRCUITS)).toEqual(["v2", "eddsa"]);
    expect(() => canonicalOrder(["v9" as never], CIRCUITS)).toThrow(/unknown/);
    // the cold schedule with the optional curve condition, pinned (first block)
    const withCurve = buildSchedule(canon.map((c) => conditionIdOf(c)), 30, CMP_SEEDS.cold);
    expect(withCurve).toHaveLength(180);
    expect(withCurve.slice(0, 6).map((s) => s.condition)).toEqual(PINNED_CURVE_BLOCK0);
    expect(buildSchedule(typed.map((c) => conditionIdOf(c)), 30, CMP_SEEDS.cold)).not.toEqual(withCurve); // why canonical order matters
  });
});

describe("cmp: specs, protocol and pins", () => {
  it("keeps every new artifact under results/v4/cmp/ and the frozen ones where Phase D has them", () => {
    for (const p of Object.values(V2O2_FILES)) expect(p.startsWith("results/v4/cmp/artifacts/v2_O2/")).toBe(true);
    const s = circuitSpecs();
    expect(s.v2.zkey).toEqual(VERSIONS.v2.zkey);
    expect(s.v3.wasm).toEqual(VERSIONS.v3.wasm);
    expect(s.v4.zkey).toEqual(VERSIONS.v4.zkey);
    expect(s.v4.keyLabel).toBe("dev key");
    expect(s.v2o2.input).toEqual({ kind: "bench-lock", version: "v2" });
    expect(s.eddsa.zkey.rel).toBe(EDDSA_FILES.zkey);
    expect(s.v2o2.keyLabel).toMatch(/\bdev\b/);
    expect(conditionIdOf("wallet1e6")).toBe("wallet1e6/node");
    expect(conditionIdOf("curve")).toBe("curve/snarkjs");
    expect(WALLET_SIZES.wallet1e6).toEqual({ credentials: 1_000_000, revocations: 10_000 });
    expect(walletSize("wallet1e5", true).credentials).toBeLessThan(10_000);
  });

  it("states the v2 beacon recipe of setup/groth16_setup.ts and the --O2 stop rule of results/v3", () => {
    const src = fs.readFileSync(abs("setup/groth16_setup.ts"), "utf8");
    expect(src).toContain(`"${V2_BEACON.hash}"`);
    expect(src).toContain(`BEACON_ITER_EXP = ${V2_BEACON.iterExp}`);
    expect(src).toContain(`"${V2_BEACON.name}"`);
    const o2 = JSON.parse(fs.readFileSync(abs("results/v3/compare_v2_v3.json"), "utf8")) as { constraints: { v2_O2: { nConstraints: number; nWires: number } } };
    expect(o2.constraints.v2_O2.nConstraints).toBe(V2O2_EXPECTED.nConstraints);
    expect(o2.constraints.v2_O2.nWires).toBe(V2O2_EXPECTED.nWires);
  });

  it("extends the Phase D protocol text it names and hashes docs/v4/CMP.md above Deviations", () => {
    const r = protocolRecord();
    expect(r.benchProtocolSha256).toBe(BENCH_PROTOCOL_NORMATIVE_SHA256);
    expect(r.cmpProtocolSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(normativeSha("docs/v4/CMP.md").normative).toBe(r.cmpProtocolSha256);
    expect(fs.readFileSync(abs("docs/v4/CMP.md"), "utf8")).toContain(BENCH_PROTOCOL_NORMATIVE_SHA256);
  });

  it("takes the v4 key as an input and refuses unsafe forms", () => {
    expect(resolveV4Key().isDevKey).toBe(true);
    expect(() => resolveV4Key({ zkey: "setup/out/v4/x.zkey" })).toThrow(/go together/);
    expect(() => resolveV4Key({ zkey: "setup/out/v4/x.zkey", vkey: "setup/out/v4/x.json" })).toThrow(/--v4-key-label/);
    expect(() => resolveV4Key({ zkey: "setup/out/v4/x.zkey", vkey: "setup/out/v4/x.json", label: "dev key 2" })).toThrow(/dev label/);
    expect(() => resolveV4Key({ zkey: "C:/x.zkey", vkey: "setup/out/v4/x.json", label: "ceremony key" })).toThrow(/repository-relative/);
    expect(() => resolveV4Key({ zkey: "../x.zkey", vkey: "setup/out/v4/x.json", label: "ceremony key" })).toThrow(/repository-relative/);
    expect(() => resolveV4Key({ zkey: "setup/out/v4/x.zkey", vkey: "setup/out/v4/x.json", label: "ceremony key" })).toThrow(/no pin entry/);
    expect(pinKeyForPath("setup/pins_v4.json", "setup/out/v4/credential_auth_v4_dev.zkey")).toBe("v4/credential_auth_v4_dev.zkey");
    const viaPins = resolveV4Key({ zkey: "setup/out/v4/credential_auth_v4_dev.zkey", vkey: "setup/out/v4/verification_key_dev.json", pins: "setup/pins_v4.json" });
    expect(viaPins.isDevKey).toBe(true);
  });

  it("parses condition lists strictly", () => {
    expect(parseList("v2,v4", CIRCUITS, "--conditions")).toEqual(["v2", "v4"]);
    expect(parseList(undefined, CIRCUITS, "--conditions")).toBeUndefined();
    expect(() => parseList("v2,v9", CIRCUITS, "--conditions")).toThrow(/unknown/);
    expect(() => parseList("v2,v2", CIRCUITS, "--conditions")).toThrow(/duplicate/);
  });

  it.skipIf(!fs.existsSync(abs(PINS_CMP_REL)))("pins the built v2o2 artifacts and the EdDSA artifacts (skipped when the build has not run)", () => {
    const pins = JSON.parse(fs.readFileSync(abs(PINS_CMP_REL), "utf8")) as Record<string, { sha256: string; path: string; bytes: number }>;
    const keys = [...Object.values(PIN_KEYS.v2o2), ...Object.values(PIN_KEYS.eddsa)];
    expect(Object.keys(pins).sort()).toEqual([...keys].sort());
    for (const k of keys) {
      const e = pins[k] as { sha256: string; path: string; bytes: number };
      expect(sha256FileHex(abs(e.path))).toBe(e.sha256);
      expect(fs.statSync(abs(e.path)).size).toBe(e.bytes);
    }
    const info = JSON.parse(fs.readFileSync(abs(EDDSA_FILES.info), "utf8")) as { wasmSha256: string };
    const setup = JSON.parse(fs.readFileSync(abs(EDDSA_FILES.setup), "utf8")) as { zkeySha256: string; vkeySha256: string };
    expect(pins[PIN_KEYS.eddsa.wasm]?.sha256).toBe(info.wasmSha256);
    expect(pins[PIN_KEYS.eddsa.zkey]?.sha256).toBe(setup.zkeySha256);
    expect(pins[PIN_KEYS.eddsa.vkey]?.sha256).toBe(setup.vkeySha256);
    const rec = JSON.parse(fs.readFileSync(abs(V2O2_FILES.setup), "utf8")) as { verifyFromR1cs: boolean; deterministic: { equal: boolean }; recipeCheck: { reproducesPinnedV2Key: boolean } };
    expect(rec.verifyFromR1cs).toBe(true);
    expect(rec.deterministic.equal).toBe(true);
    expect(rec.recipeCheck.reproducesPinnedV2Key).toBe(true);
  });
});

describe("cmp: condition notes and real-mode rules", () => {
  it("records what each condition is, its optimisation level and its constraint count", () => {
    const notes = conditionNotes(["v2", "v2o2", "v3", "v4", "eddsa", "curve", "wallet1e5"], circuitSpecs(), false);
    expect(notes["v2"]?.optimization).toMatch(/^--O1/);
    expect(notes["v2"]?.nConstraints).toBe(21715);
    expect(notes["v2o2"]?.optimization).toBe("--O2");
    expect(notes["v3"]?.nConstraints).toBe(18683);
    expect(notes["v4"]?.nConstraints).toBe(17450);
    expect(notes["v4"]?.keyLabel).toBe("dev key");
    expect(notes["eddsa"]?.note).toMatch(/not PQ, not v4/);
    expect(notes["curve"]?.nConstraints).toBeNull();
    expect(notes["wallet1e5"]?.note).toMatch(/100000 credentials, 1000 revocation keys/);
    expect(notes["wallet1e5"]?.note).toMatch(/single-thread/);
    if (fs.existsSync(abs(V2O2_FILES.info))) expect(notes["v2o2"]?.nConstraints).toBe(V2O2_EXPECTED.nConstraints);
  });

  const ok: RealModeParams = {
    series: "prove",
    platform: "win32",
    params: { ...REAL_MODE.prove },
    v4Included: true,
    isDevKey: false,
    allowDevKey: false,
    committedAtHead: true,
    allowUncommitted: false,
  };

  it("accepts exactly the fixed real-mode parameters on Windows with a committed tree", () => {
    expect(realModeProblems(ok)).toEqual([]);
    expect(realModeProblems({ ...ok, series: "wallet", params: { ...REAL_MODE.wallet }, v4Included: false })).toEqual([]);
    expect(realModeProblems({ ...ok, series: "warm", params: { ...REAL_MODE.warm } })).toEqual([]);
    expect(REAL_MODE.prove.n).toBe(30);
    expect(REAL_MODE.wallet.n).toBe(10);
  });

  it("refuses every other value, the dev key, another OS and an uncommitted tree", () => {
    expect(realModeProblems({ ...ok, series: "wallet", params: { ...REAL_MODE.wallet, n: 5 }, v4Included: false })).toEqual(["n must be 10 in a real wallet series (got 5)"]);
    expect(realModeProblems({ ...ok, params: { ...REAL_MODE.prove, n: 31 } })[0]).toMatch(/n must be 30/);
    for (const [k, v] of [["idleSec", 300], ["leadSec", 10], ["maxPostpone", 3], ["postponeStepSec", 30], ["childTimeoutSec", 1800]] as const) {
      expect(realModeProblems({ ...ok, params: { ...REAL_MODE.prove, [k]: v } })).toEqual([`${k} must be ${REAL_MODE.prove[k]} in a real prove series (got ${v})`]);
    }
    expect(realModeProblems({ ...ok, series: "warm", params: { ...REAL_MODE.warm, blockGapSec: 5 } })[0]).toMatch(/blockGapSec must be 2/);
    expect(realModeProblems({ ...ok, series: "warm", params: { ...REAL_MODE.warm, warmup: 6 } })[0]).toMatch(/warmup must be 5/);
    expect(realModeProblems({ ...ok, platform: "linux" })[0]).toMatch(/native Windows only/);
    expect(realModeProblems({ ...ok, isDevKey: true })[0]).toMatch(/dev key/);
    expect(realModeProblems({ ...ok, isDevKey: true, allowDevKey: true })).toEqual([]);
    expect(realModeProblems({ ...ok, isDevKey: true, v4Included: false })).toEqual([]);
    expect(realModeProblems({ ...ok, committedAtHead: false })[0]).toMatch(/--allow-uncommitted/);
    expect(realModeProblems({ ...ok, committedAtHead: null })[0]).toMatch(/committedAtHead null/);
    expect(realModeProblems({ ...ok, committedAtHead: false, allowUncommitted: true })).toEqual([]);
    expect(realModeProblems({ ...ok, platform: "linux", isDevKey: true, committedAtHead: false, params: {} }).length).toBe(9);
  });

  it("covers the protocol addendum, pins, input lock and analysis in the committed check", () => {
    expect(committedExtras(false)).toEqual(["docs/v4/CMP.md", "results/v4/cmp/artifacts/pins_cmp.json", "results/v4/cmp/inputs", "scripts/cmp/analyze_cmp.py", "scripts/cmp/quiet_window_cmp.sh"]);
    expect(committedExtras(true)).toContain("results/v4/cmp/_smoke/inputs");
    const tracked = gitClean(["setup/pins.json"]); // frozen v2/v3 pin file: tracked and unchanged
    if (tracked !== null) {
      expect(tracked).toBe(true);
      expect(gitClean(["setup/pins.json", "results/v4/cmp/no_such_file.json"])).toBe(false); // not tracked
    }
  });
});

describe("cmp: EdDSA fixture input", () => {
  it("is byte-reproducible, signs with the public fixture key and pins the expected signals", async () => {
    const a = await buildEddsaFixture();
    const b = await buildEddsaFixture();
    expect(a).toEqual(b);
    expect(a.signatureVerifies).toBe(true);
    expect(sha256Hex(JSON.stringify(a.input))).toBe("68a55d53385b2e682af327b8f0a7d319270af0b77a7dedc620c9e57375ffc394");
    expect(sha256Hex(JSON.stringify(a.publicSignals))).toBe("01b2eb38368309c9a775301618c0e0b1091d3d94b4c4e2cc355d71cd4a87fdea");
    expect(a.publicSignals).toHaveLength(4);
    expect(a.publicSignals[3]).toBe(EDDSA_FIXTURE.nonce.toString());
    expect(a.input["today"]).toBe("20260927");
    expect(a.input["holderSecret"]).toBe("123456789");
    // the off-circuit check is real: the input's signature verifies on the credential hash, a changed S does not
    const sig = { R8x: BigInt(a.input["sigR8x"] as string), R8y: BigInt(a.input["sigR8y"] as string), S: BigInt(a.input["sigS"] as string) };
    const [Ax, Ay, h] = [BigInt(a.issuerPublic.Ax), BigInt(a.issuerPublic.Ay), BigInt(a.credHash)];
    expect(await verifySignature(Ax, Ay, h, sig)).toBe(true);
    expect(await verifySignature(Ax, Ay, h, { ...sig, S: sig.S + 1n })).toBe(false);
    expect(await verifySignature(Ax, Ay, h + 1n, sig)).toBe(false);
  }, 60_000);
});

describe("cmp: wallet data", () => {
  it("derives leaves and keys from SHA-256 of a counter, in range, distinct and deterministic", () => {
    const ref = (s: string) => BigInt("0x" + createHash("sha256").update(s, "utf8").digest().subarray(0, 31).toString("hex"));
    expect(hash31("pqid-bench-wallet-leaf/0")).toBe(ref("pqid-bench-wallet-leaf/0"));
    const leaves = walletLeaves(2000);
    expect(leaves[0]?.toString(16)).toBe("b2ee7efa17407785fe01b884eddf47eeba8a121efab5596357999d2ee70f6b");
    expect(leaves[1]).toBe(ref("pqid-bench-wallet-leaf/1"));
    expect(new Set(leaves).size).toBe(leaves.length);
    for (const l of leaves) expect(l < 1n << 248n).toBe(true);
    const keys = walletRevKeys(10_000);
    expect(keys[0]?.toString(16)).toBe("5eb52a9354ec18c93c0a2f2d4703fa375d0af3524d313b1791f170b7599ceb");
    expect(new Set(keys).size).toBe(10_000);
    for (const k of keys) expect(k > 0n && k < WALLET_IMT_MAX).toBe(true);
    expect(WALLET_IMT_MAX).toBe(IMT_MAX);
    expect(walletLeaves(5)).toEqual(walletLeaves(5));
    expect(() => walletLeaves(-1)).toThrow();
  });

  it("rebuilds the same pinned roots twice (smoke size)", async () => {
    const a = await buildWalletEntry("wallet1e5", true);
    const b = await buildWalletEntry("wallet1e5", true);
    expect(a.issuanceRoot).toBe(b.issuanceRoot);
    expect(a.revocationRoot).toBe(b.revocationRoot);
    expect(a.issuanceRoot).toBe("5596811772265031351347570378322900830432020191493649745768111465329187335282");
    expect(a.revocationRoot).toBe("3224265465416783870803838695512622433795797519406120300453279813676356253736");
  }, 60_000);
});

describe("cmp: quiet-machine view (Phase D rule)", () => {
  const reading = (strict: boolean, guard: boolean): QuiesceRecord =>
    ({
      schema: "pqid/v4-quiesce/v1",
      utc: "2026-10-01T00:00:00.000Z",
      environment: "windows",
      windowMs: 3000,
      cpuBusyPercent: guard ? 4.2 : 61.5,
      cpuBasis: "os.cpus() tick counters",
      thresholdPercent: 35,
      machineWideQuiesced: guard,
      guardTs: { quiesced: guard, offending: [], basis: "guard.ts rule" },
      processListBasis: "not read on Windows",
      quiesced: strict,
      reasons: strict ? [] : ["foreign listener on chain port(s) 8545"],
    }) as unknown as QuiesceRecord;

  it("takes quiesced from the guard.ts rule (guardTs), never from the stricter D-034 verdict", () => {
    const a = phaseDQuiesce(reading(false, true)); // a foreign chain-port listener alone: quiet under Phase D's rule
    expect(a.quiesced).toBe(true);
    expect(a.cpuBusyPercent).toBe(4.2);
    expect(a.rule).toBe(PHASE_D_QUIET_RULE);
    expect(a.nodeProcesses).toBeNull();
    const b = phaseDQuiesce(reading(true, false)); // CPU over 35 %: busy under both
    expect(b.quiesced).toBe(false);
    expect(Object.keys(a).sort()).toEqual(["cpuBasis", "cpuBusyPercent", "nodeProcesses", "offending", "processListBasis", "quiesced", "rule", "thresholdPercent", "utc"]);
  });

  it("gives a live reading the guard.ts readQuiesce verdict", async () => {
    const q = await readQuiesceExcluding({ windowMs: 200, chainPorts: [] });
    const v = phaseDQuiesce(q);
    expect(v.thresholdPercent).toBe(CPU_THRESHOLD_PERCENT);
    const cpuQuiet = q.cpuBusyPercent === null || q.cpuBusyPercent <= CPU_THRESHOLD_PERCENT;
    if (process.platform === "win32") {
      // guard.ts on Windows: machine-wide CPU busy only (no process list)
      expect(v.quiesced).toBe(cpuQuiet);
      expect(v.offending).toEqual([]);
    } else {
      // guard.ts on Linux: CPU, and no process named on its list
      expect(guardOffending(v.offending)).toEqual(v.offending);
      expect(v.quiesced).toBe(cpuQuiet && v.offending.length === 0);
    }
  });

  it("names timed and runner code that exists", () => {
    for (const f of [...Object.values(TIMED_CODE).flat(), ...RUNNER_CODE]) expect(fs.existsSync(abs(f)), f).toBe(true);
    expect(TIMED_CODE.prove).toEqual(["harness/v4/bench/child_prove.ts"]);
    expect(TIMED_CODE.warm).toEqual(["harness/v4/cmp/warm.ts"]);
  });
});

/** A fake clock: sleeping advances both clocks by the slept time, plus any pause injected at that wake-up. */
function fakeClock(pauses: Array<{ atWakeup: number; monoMs: number; wallMs: number }>) {
  let mono = 1_000;
  let wall = 1_700_000_000_000;
  let wakeups = 0;
  const clock: Clock = { mono: () => mono, wall: () => wall };
  const sleepFn = (ms: number): Promise<void> => {
    mono += ms;
    wall += ms;
    wakeups++;
    for (const p of pauses) {
      if (p.atWakeup === wakeups) {
        mono += p.monoMs;
        wall += p.wallMs;
      }
    }
    return Promise.resolve();
  };
  const advance = (ms: number): void => {
    mono += ms;
    wall += ms;
  };
  return { clock, sleepFn, advance };
}

describe("cmp: idle clock, host-pause watchdog and smoke lock", () => {
  it("flags a host pause when the wall clock runs ahead of the monotonic clock by more than 5 s", () => {
    expect(idleReading(0, 1_000_000, 600_000, 1_600_000)).toEqual({
      idleSec: 600,
      idleWallSec: 600,
      clockGapSec: 0,
      idleMaxTickGapSec: 0,
      idleTickGap: { monoSec: 0, wallSec: 0, wakeups: 0 },
      hostPauseSuspected: false,
    });
    expect(idleReading(0, 0, 600_000, 637_000).hostPauseSuspected).toBe(true);
    expect(idleReading(0, 0, 600_000, 637_000).clockGapSec).toBe(37);
    expect(idleReading(0, 0, 600_000, 605_000).hostPauseSuspected).toBe(false);
    expect(idleReading(0, 0, 600_000, 594_000).hostPauseSuspected).toBe(true);
    // both clocks counted the pause (QueryPerformanceCounter through standby): only the wake-up gap shows it
    expect(idleReading(0, 0, 637_000, 637_000, { monoMs: 38_000, wallMs: 38_000, wakeups: 600 })).toMatchObject({ clockGapSec: 0, idleMaxTickGapSec: 38, hostPauseSuspected: true });
    expect(idleReading(0, 0, 600_000, 600_000, { monoMs: 5_000, wallMs: 1_016, wakeups: 600 }).hostPauseSuspected).toBe(false);
    expect(HOST_PAUSE_GAP_SEC).toBe(5);
  });

  it("watchdog: wakes at least every second and records a pause on either clock", async () => {
    // no pause: 600 s idle in 1 s steps, the largest gap is one step
    const a = fakeClock([]);
    const w = new IdleWatch(a.clock, a.sleepFn, 1000);
    await w.sleepUntilOffset(580_000);
    a.advance(4_000); // power and quiet readings (not watched)
    await w.sleepUntilOffset(600_000);
    const r = w.reading();
    expect(r.idleSec).toBe(600);
    expect(r.idleMaxTickGapSec).toBe(1);
    expect(r.idleTickGap.wakeups).toBe(596);
    expect(r.hostPauseSuspected).toBe(false);

    // standby counted by both clocks (Windows QPC): clockGapSec stays 0, the wake-up gap is 38 s
    const b = fakeClock([{ atWakeup: 100, monoMs: 37_000, wallMs: 37_000 }]);
    const wb = new IdleWatch(b.clock, b.sleepFn, 1000);
    await wb.sleepUntilOffset(600_000);
    const rb = wb.reading();
    expect(rb.clockGapSec).toBe(0);
    expect(rb.idleMaxTickGapSec).toBe(38);
    expect(rb.idleSec).toBe(600); // the remaining steps shrink: the idle ends at the monotonic target
    expect(rb.hostPauseSuspected).toBe(true);

    // a pause the monotonic clock did not count (Linux CLOCK_MONOTONIC, a paused VM): both signals fire
    const c = fakeClock([{ atWakeup: 10, monoMs: 0, wallMs: 37_000 }]);
    const wc = new IdleWatch(c.clock, c.sleepFn, 1000);
    await wc.sleepUntilOffset(600_000);
    const rc = wc.reading();
    expect(rc.clockGapSec).toBe(37);
    expect(rc.idleTickGap).toEqual({ monoSec: 1, wallSec: 38, wakeups: 600 });
    expect(rc.hostPauseSuspected).toBe(true);

    // restart clears the watchdog for the next idle
    wc.restart();
    await wc.sleep(3_000);
    expect(wc.reading()).toMatchObject({ idleSec: 3, idleMaxTickGapSec: 1, hostPauseSuspected: false });
  });

  it("holds one smoke lock at a time inside the smoke root and releases it", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-cmp-lock-"));
    try {
      const release = holdSmokeLock(dir, "t1");
      expect(fs.existsSync(path.join(dir, "SMOKE_LOCK"))).toBe(true);
      expect(() => holdSmokeLock(dir, "t2")).toThrow(/live smoke run/);
      release();
      expect(fs.existsSync(path.join(dir, "SMOKE_LOCK"))).toBe(false);
      fs.writeFileSync(path.join(dir, "SMOKE_LOCK"), JSON.stringify({ campaign: "old", pid: 2 ** 22 + 12345 }));
      const r2 = holdSmokeLock(dir, "t3"); // stale (dead pid) lock is replaced
      r2();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("smoke runs hold BUSY and the smoke lock by default, only the lock with --smoke-no-marker, and borrow a wrapper's hold", () => {
    // a temporary repository: nothing is written to this checkout's markers
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-cmp-hold-"));
    const roots: MarkerRoot[] = [{ repo, via: "local" }];
    const smokeRoot = path.join(repo, "results", "v4", "cmp", "_smoke");
    const busy = path.join(repo, "results", "v4", "BUSY");
    const running = path.join(repo, "results", "v4", "bench", "RUNNING");
    const lock = path.join(smokeRoot, "SMOKE_LOCK");
    const saved = process.env[MARKER_TOKEN_ENV];
    delete process.env[MARKER_TOKEN_ENV];
    try {
      const h = holdWork({ kind: "RUNNING", smoke: true, smokeRoot, campaign: "t1", runner: "test", argv: [], roots });
      expect([fs.existsSync(busy), fs.existsSync(running), fs.existsSync(lock)]).toEqual([true, false, true]);
      expect(h.record.kind).toBe("BUSY");
      expect(h.record.smoke?.markerMode).toBe("BUSY");
      expect(() => holdWork({ kind: "BUSY", smoke: true, smokeNoMarker: true, smokeRoot, campaign: "t2", runner: "test", argv: [], roots })).toThrow(/refusing to start/);
      h.release();
      expect([fs.existsSync(busy), fs.existsSync(lock)]).toEqual([false, false]);

      const n = holdWork({ kind: "BUSY", smoke: true, smokeNoMarker: true, smokeRoot, campaign: "t3", runner: "test", argv: [], roots });
      expect(n.record.kind).toBe("smoke-lock");
      expect(n.record.smoke?.markerMode).toBe("none (--smoke-no-marker)");
      expect([fs.existsSync(busy), fs.existsSync(lock)]).toEqual([false, true]);
      n.release();

      // a wrapping `markers.ts run --kind BUSY` holds the marker; the smoke runner borrows it
      const wrapper = acquireMarker({ kind: "BUSY", campaign: "w", runner: "wrapper", roots, inheritedToken: "", releaseOnExit: false, exitOnSignal: false });
      process.env[MARKER_TOKEN_ENV] = wrapper.record.token;
      const b = holdWork({ kind: "BUSY", smoke: true, smokeRoot, campaign: "t4", runner: "test", argv: [], roots });
      expect(b.record.borrowed).toBe(true);
      b.release();
      expect(fs.existsSync(busy)).toBe(true); // still the wrapper's
      wrapper.release();
      expect(fs.existsSync(busy)).toBe(false);
    } finally {
      if (saved === undefined) delete process.env[MARKER_TOKEN_ENV];
      else process.env[MARKER_TOKEN_ENV] = saved;
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });

  it("smoke reset moves earlier smoke output aside and deletes nothing", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-cmp-reset-"));
    try {
      expect(moveSmokeOutput(dir)).toEqual({ moved: [], to: null });
      fs.mkdirSync(path.join(dir, "prove", "cold_cmp"), { recursive: true });
      fs.writeFileSync(path.join(dir, "prove", "cold_cmp", "runs.jsonl"), "x\n");
      fs.writeFileSync(path.join(dir, "summary_cmp.json"), "{}\n");
      fs.writeFileSync(path.join(dir, "SMOKE_LOCK"), "{}\n");
      const now = new Date("2026-10-03T12:34:56.789Z");
      expect(stampOf(now)).toBe("20261003T123456Z");
      const r = moveSmokeOutput(dir, now);
      expect(r.moved).toEqual(["prove", "summary_cmp.json"]);
      expect(path.basename(r.to ?? "")).toBe("old_20261003T123456Z");
      expect(fs.readFileSync(path.join(dir, "old_20261003T123456Z", "prove", "cold_cmp", "runs.jsonl"), "utf8")).toBe("x\n");
      expect(fs.existsSync(path.join(dir, "prove"))).toBe(false);
      expect(fs.existsSync(path.join(dir, "SMOKE_LOCK"))).toBe(true); // not smoke output
      fs.mkdirSync(path.join(dir, "wallet"));
      expect(path.basename(moveSmokeOutput(dir, now).to ?? "")).toBe("old_20261003T123456Z_2");
      expect(SMOKE_OUTPUT).toContain("logs");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("cmp: log hygiene", () => {
  it("scrubs the repository path, home path, user and host names in either case", () => {
    const ns = needles();
    const home = os.homedir();
    const text = `at file:///${home.replace(/\\/g, "/")}/x.ts and ${home.toUpperCase()}\\y and ${os.hostname()} ${os.userInfo().username}`;
    const out = scrubText(text, ns);
    expect(privateKinds(out, ns)).toEqual([]);
    expect(privateKinds(text, ns).length).toBeGreaterThan(0);
    expect(scrubText("results/v4/cmp/prove/cold_cmp ok 1234 ms", ns)).toBe("results/v4/cmp/prove/cold_cmp ok 1234 ms");
  });

  it("finds private strings in text files, skips binary artifacts and skipped folders", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-cmp-scrub-"));
    try {
      const fake = [{ text: "SecretHostXyz", kind: "host name" as const, tag: "<host>" }];
      fs.writeFileSync(path.join(dir, "a.log"), "clean\n");
      fs.writeFileSync(path.join(dir, "b.json"), '{"h":"secrethostxyz"}\n');
      fs.writeFileSync(path.join(dir, "c.zkey"), "SecretHostXyz");
      fs.mkdirSync(path.join(dir, "old_1"));
      fs.writeFileSync(path.join(dir, "old_1", "d.log"), "SecretHostXyz");
      const hits = findPrivate(dir, ["old_*"], fake);
      expect(hits.map((h) => path.basename(h.file))).toEqual(["b.json"]);
      expect(hits[0]?.kinds).toEqual(["host name"]);
      expect(findPrivate(dir, [], fake)).toHaveLength(2);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
