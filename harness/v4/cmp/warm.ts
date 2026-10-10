import fs from "node:fs";
import path from "node:path";
import { readPower, type PowerReading } from "../bench/guard.ts";
import { readQuiesceExcluding, type QuiesceRecord } from "../lib/quiesce.ts";
import {
  abs,
  appendJsonl,
  buildSchedule,
  envInfo,
  flag,
  gitHead,
  inputFileSha,
  opt,
  optNum,
  rel,
  sanitize,
  sha256Hex,
  snarkjsVersion,
  utcNow,
  writeJson,
  type Slot,
} from "../bench/lib.ts";
import { readCmpLock } from "./inputs.ts";
import { assertCampaignName, holdWork, phaseDQuiesce, sameJson, sleep, PHASE_D_QUIET_RULE } from "./runner.ts";
import {
  CIRCUITS,
  CMP_SEEDS,
  TIMED_CODE,
  canonicalOrder,
  checkCircuitArtifacts,
  circuitSpecs,
  cmpRoot,
  codeRecord,
  conditionIdOf,
  conditionNotes,
  parseList,
  protocolRecord,
  proveRoot,
  realModeProblems,
  resolveV4Key,
  v4KeyFromArgs,
  type Circuit,
  type CircuitArtifacts,
} from "./spec.ts";

/**
 * Warm series of the cmp conditions (docs/v4/CMP.md, "Warm series"), the rules of
 * harness/v4/bench/warm.ts for snarkJS: ONE process holds every circuit; after 5 warm-up blocks
 * it runs n = 30 measured blocks, each block every circuit once in the recorded shuffled order
 * (mulberry32, seed 20261043, D-034). One iteration makes exactly the calls of
 * harness/v4/bench/child_prove.ts (witness from the wasm path into memory, groth16.prove from
 * the zkey path, groth16.verify), so warm and cold differ only in process state.
 *
 *   node --import tsx harness/v4/cmp/warm.ts [--conditions v2,v2o2,v3,v4,eddsa] [v4 key flags] [--campaign NAME]
 *   add --smoke: n=1, warm-up 1, settle 5 s, output under results/v4/cmp/_smoke/, holds
 *   results/v4/BUSY (--smoke-no-marker: only the smoke lock); a smoke campaign always starts fresh
 *
 * Real runs: native Windows only, n = 30, warm-up 5, settle 600 s, block gap 2 s (spec.ts
 * REAL_MODE), the ceremony key (the dev key only with --allow-dev-key), and the code,
 * docs/v4/CMP.md, pins, input lock and analysis committed at HEAD (--allow-uncommitted overrides,
 * recorded).
 *
 * Settle 600 s on AC first; power before and after every block (a block with a non-AC reading
 * is recorded as discarded-battery and repeated); a quiet-machine reading before every block
 * (recorded, never postponing, as Phase D warm; `quiesce.quiesced` is the guard.ts rule,
 * runner.ts phaseDQuiesce, and `quiesceDetail` the full reading).
 * Not resumable: a restart is a new session in the same runs.jsonl; the analysis uses the latest
 * complete session. Real runs hold results/v4/bench/RUNNING (D-034).
 */

interface Loaded {
  circuit: Circuit;
  keyLabel: string;
  input: Record<string, unknown>;
  vkey: unknown;
  wasm: string;
  zkey: string;
  publicSha: string;
}

type Snarkjs = typeof import("snarkjs");

function msSince(t0: bigint): number {
  return Math.round((Number(process.hrtime.bigint() - t0) / 1e6) * 1000) / 1000;
}

/** The snarkJS path of harness/v4/bench/warm.ts iterate() (same calls, same order). */
async function iterate(snarkjs: Snarkjs, L: Loaded) {
  const wtns: { type: "mem"; data?: Uint8Array } = { type: "mem" };
  const tW = process.hrtime.bigint();
  await snarkjs.wtns.calculate(L.input, L.wasm, wtns);
  const witnessMs = msSince(tW);
  if (!wtns.data) throw new Error("snarkjs produced no in-memory witness");
  const witnessSha256 = sha256Hex(wtns.data);
  const tP = process.hrtime.bigint();
  const r = await snarkjs.groth16.prove(L.zkey, wtns);
  const proveMs = msSince(tP);
  const tV = process.hrtime.bigint();
  const verified = await snarkjs.groth16.verify(L.vkey, r.publicSignals, r.proof);
  const verifyMs = msSince(tV);
  const publicSignalsSha256 = sha256Hex(JSON.stringify(r.publicSignals));
  return {
    timings: { witnessMs, proveMs, verifyMs, wpMs: Math.round((witnessMs + proveMs) * 1000) / 1000 },
    checks: { verified, publicSignalsMatch: publicSignalsSha256 === L.publicSha },
    hashes: { witnessSha256, publicSignalsSha256 },
  };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const smoke = flag(argv, "smoke");
  const smokeNoMarker = flag(argv, "smoke-no-marker");
  if (smokeNoMarker && !smoke) throw new Error("--smoke-no-marker goes with --smoke");
  const campaign = assertCampaignName(opt(argv, "campaign") ?? "warm_cmp");
  // canonical order: the typed order of --conditions never changes the schedule of the seed
  const circuits = canonicalOrder(parseList(opt(argv, "conditions"), CIRCUITS, "--conditions") ?? [...CIRCUITS], CIRCUITS);
  const n = optNum(argv, "n", smoke ? 1 : 30);
  const warmup = optNum(argv, "warmup", smoke ? 1 : 5);
  const settleSec = optNum(argv, "settle", smoke ? 5 : 600);
  const blockGapSec = optNum(argv, "block-gap", 2);
  const seed = CMP_SEEDS.warm;
  const v4 = resolveV4Key(v4KeyFromArgs(argv));
  const allowDevKey = flag(argv, "allow-dev-key");
  const allowUncommitted = flag(argv, "allow-uncommitted");
  const code = codeRecord(TIMED_CODE.warm, smoke);
  if (!smoke) {
    const problems = realModeProblems({
      series: "warm",
      platform: process.platform,
      params: { n, warmup, settleSec, blockGapSec },
      v4Included: circuits.includes("v4"),
      isDevKey: v4.isDevKey,
      allowDevKey,
      committedAtHead: code.committedAtHead,
      allowUncommitted,
    });
    if (problems.length > 0) throw new Error(`refusing a real warm series (docs/v4/CMP.md): ${problems.join("; ")} (use --smoke to test the runner)`);
  }

  const root = proveRoot(smoke);
  const dir = path.join(root, campaign);
  const scheduleFile = path.join(dir, "schedule.json");
  const envFile = path.join(dir, "env.json");
  const runsFile = path.join(dir, "runs.jsonl");
  if (smoke && fs.existsSync(dir)) {
    throw new Error(`${rel(dir)} exists: a smoke always starts fresh (scripts/cmp/quiet_window_cmp.sh with PQID_CMP_SMOKE=1 moves old smoke output aside first, or run harness/v4/cmp/smoke_reset.ts)`);
  }

  const protocol = protocolRecord();
  const lock = readCmpLock(smoke);
  const specs = circuitSpecs(v4KeyFromArgs(argv));
  const artifacts: Partial<Record<Circuit, CircuitArtifacts>> = {};
  const inputs: Record<string, unknown> = {};
  for (const c of circuits) {
    const e = lock.circuits[c];
    if (!e) throw new Error(`no pinned input for ${c} in the cmp lock (run harness/v4/cmp/inputs.ts${smoke ? " --smoke" : ""})`);
    const a = checkCircuitArtifacts(specs[c]);
    for (const k of ["wasm", "zkey", "vkey"] as const) if (a[k].sha256 !== e.artifacts[k].sha256) throw new Error(`${c} ${k} changed since its input was pinned; re-run inputs.ts`);
    if (e.keyLabel !== specs[c].keyLabel) throw new Error(`${c}: key label differs from the pinned one`);
    if (inputFileSha(abs(e.file)) !== e.inputSha256) throw new Error(`${c}: input file differs from its pin`);
    artifacts[c] = a;
    inputs[c] = { file: e.file, inputSha256: e.inputSha256, publicSignalsSha256: e.publicSignalsSha256, source: e.source };
  }

  const hold = holdWork({ kind: "RUNNING", smoke, smokeNoMarker, smokeRoot: cmpRoot(true), campaign, runner: "harness/v4/cmp/warm.ts", argv, note: "cmp warm series" });
  fs.mkdirSync(dir, { recursive: true });

  const conditions = circuits.map((c) => conditionIdOf(c));
  const config = { campaign, mode: "warm", smoke, conditions, n, warmup, settleSec, blockGapSec, seed, seedSource: "DECISIONS D-034 (harness/v4/lib/seeds.ts)" };
  let schedule: Slot[];
  if (fs.existsSync(scheduleFile)) {
    const s = JSON.parse(fs.readFileSync(scheduleFile, "utf8")) as { config: typeof config; slots: Slot[] };
    if (!sameJson(s.config, config)) throw new Error(`${rel(scheduleFile)} exists with a different configuration; use a new --campaign`);
    schedule = s.slots;
  } else {
    schedule = buildSchedule(conditions, warmup + n, seed, -warmup);
    writeJson(scheduleFile, {
      schema: "pqid/v4-cmp-schedule/v1",
      createdUtc: utcNow(),
      config,
      prng: "mulberry32, Fisher-Yates from the end; one stream for all blocks (harness/v4/bench/lib.ts buildSchedule)",
      rule: "blocks < 0 are warm-up (not analysed); each block holds every condition once, in shuffled order; conditions in canonical order before shuffling",
      slots: schedule,
    });
  }

  const keyLabels = Object.fromEntries(circuits.map((c) => [c, specs[c].keyLabel]));
  const session = utcNow();
  const sessionEntry = { session, env: envInfo(), gitHead: gitHead(), codeCommittedAtHead: code.committedAtHead, allowUncommitted: !smoke && allowUncommitted, protocolSha256: protocol.benchProtocolSha256, protocolFileSha256: protocol.benchProtocolFileSha256, cmpProtocolFileSha256: protocol.cmpProtocolFileSha256, snarkjs: snarkjsVersion(), marker: hold.record };
  if (fs.existsSync(envFile)) {
    const e = JSON.parse(fs.readFileSync(envFile, "utf8")) as Record<string, unknown> & { sessions: unknown[] };
    for (const [what, a, b] of [
      ["artifacts", e["artifacts"], artifacts],
      ["inputs", e["inputs"], inputs],
      ["docs/v4/BENCH_PROTOCOL.md (above Deviations)", e["protocolSha256"], protocol.benchProtocolSha256],
      ["docs/v4/CMP.md (above Deviations)", e["cmpProtocolSha256"], protocol.cmpProtocolSha256],
      ["key labels", e["keyLabels"], keyLabels],
      ["timed code", (e["code"] as { timed?: unknown } | undefined)?.timed, code.timed],
    ] as Array<[string, unknown, unknown]>) {
      if (!sameJson(a, b)) throw new Error(`${what} changed since this campaign started; use a new --campaign`);
    }
    e.sessions.push(sessionEntry);
    writeJson(envFile, e);
  } else {
    writeJson(envFile, {
      schema: "pqid/v4-cmp-env/v1",
      campaign,
      mode: "warm",
      kind: "prove",
      smoke,
      label: smoke ? "SMOKE TEST: not a result" : "[M] cmp warm series (snarkJS)",
      protocol: protocol.benchProtocol,
      protocolSha256: protocol.benchProtocolSha256,
      protocolShaBasis: protocol.shaBasis,
      cmpProtocol: protocol.cmpProtocol,
      cmpProtocolSha256: protocol.cmpProtocolSha256,
      keyLabels,
      v4Key: circuits.includes("v4") ? { label: v4.keyLabel, isDevKey: v4.isDevKey, allowDevKeyFlag: allowDevKey } : null,
      conditionNotes: conditionNotes(circuits, specs, smoke),
      artifacts,
      inputs,
      code,
      allowUncommitted: !smoke && allowUncommitted,
      rapidsnark: { available: false, status: "not used: the cmp series is snarkJS on Windows (D-034 skips the WSL cmp campaign)" },
      blocked: [],
      quietRule: { postpone: "none (warm blocks are never postponed, as Phase D)", recorded: `quiesce = Phase D view: ${PHASE_D_QUIET_RULE}` },
      sessions: [sessionEntry],
    });
  }

  console.log(`[cmp-warm] ${campaign}: ${conditions.join(", ")}; warm-up ${warmup} + ${n} blocks; settle ${settleSec} s -> ${rel(dir)}`);
  for (;;) {
    await sleep(Math.max(0, settleSec - 5) * 1000);
    const p = readPower();
    await sleep(Math.min(5, settleSec) * 1000);
    if (p.ac) break;
    console.log(`[cmp-warm] not on AC at the start (code ${p.code}); settling again`);
  }

  const snarkjs = await import("snarkjs");
  const loaded = Object.fromEntries(
    circuits.map((c) => {
      const e = lock.circuits[c] as NonNullable<(typeof lock.circuits)[Circuit]>;
      const s = specs[c];
      const L: Loaded = {
        circuit: c,
        keyLabel: s.keyLabel,
        input: JSON.parse(fs.readFileSync(abs(e.file), "utf8")) as Record<string, unknown>,
        vkey: JSON.parse(fs.readFileSync(abs(s.vkey.rel), "utf8")) as unknown,
        wasm: abs(s.wasm.rel),
        zkey: abs(s.zkey.rel),
        publicSha: e.publicSignalsSha256,
      };
      return [conditionIdOf(c), L];
    })
  ) as Record<string, Loaded>;

  const blocks = [...new Set(schedule.map((s) => s.block))].sort((a, b) => a - b);
  let discardedBlocks = 0;
  let consecutiveNonAc = 0;
  for (const b of blocks) {
    const slots = schedule.filter((s) => s.block === b).sort((x, y) => x.pos - y.pos);
    for (;;) {
      const pre: PowerReading = readPower();
      const q: QuiesceRecord = await readQuiesceExcluding({ windowMs: Math.max(1, blockGapSec) * 1000 });
      if (!pre.ac) {
        consecutiveNonAc++;
        if (consecutiveNonAc >= 360) throw new Error("no mains power for 6 h; stopping");
        console.log(`[cmp-warm] block ${b}: not on AC (code ${pre.code}); waiting 60 s`);
        await sleep(60_000);
        continue;
      }
      consecutiveNonAc = 0;
      const recs: Array<Record<string, unknown>> = [];
      for (const s of slots) {
        const L = loaded[s.condition];
        if (!L) throw new Error(`no loaded condition ${s.condition}`);
        const utcStart = utcNow();
        let res: Awaited<ReturnType<typeof iterate>> | null = null;
        let error: string | undefined;
        try {
          res = await iterate(snarkjs, L);
          if (!res.checks.verified || !res.checks.publicSignalsMatch) error = "proof did not verify or public signals differ";
        } catch (e) {
          error = sanitize(e instanceof Error ? e.message : String(e));
        }
        recs.push({
          type: "run",
          schema: "pqid/v4-cmp-run/v1",
          campaign,
          mode: "warm",
          kind: "prove",
          session,
          slot: s.slot,
          block: s.block,
          pos: s.pos,
          warmup: s.block < 0,
          condition: s.condition,
          version: L.circuit,
          prover: "snarkjs",
          keyLabel: L.keyLabel,
          status: error ? "error" : "ok",
          utcStart,
          utcEnd: utcNow(),
          timings: res?.timings ?? null,
          aux: null,
          checks: res?.checks ?? null,
          hashes: res?.hashes ?? null,
          env: { ...envInfo(), powerCode: pre.code, utc: utcStart },
          ...(error ? { error } : {}),
        });
        if (error) {
          for (const r of recs) appendJsonl(runsFile, { ...r, power: { pre, post: null }, quiesce: phaseDQuiesce(q), quiesceDetail: q });
          throw new Error(`block ${b} ${s.condition}: ${error}`);
        }
      }
      const post = readPower();
      const ok = post.ac;
      for (const r of recs) appendJsonl(runsFile, { ...r, status: ok ? r["status"] : "discarded-battery", ...(ok ? {} : { stage: "post" }), power: { pre, post }, quiesce: phaseDQuiesce(q), quiesceDetail: q });
      const summary = recs.map((r) => `${String(r["version"])} ${(r["timings"] as { proveMs: number }).proveMs.toFixed(0)}`).join(", ");
      console.log(`[cmp-warm] block ${b}${b < 0 ? " (warm-up)" : ""}: ${ok ? "ok" : "DISCARDED (power)"}; prove ms: ${summary}`);
      if (ok) break;
      discardedBlocks++;
    }
  }
  appendJsonl(runsFile, { type: "session-end", campaign, session, utc: utcNow(), complete: true, measuredBlocks: n, warmupBlocks: warmup, discardedBlocks });
  hold.release();
  console.log(`[cmp-warm] ${campaign} complete -> ${rel(runsFile)}`);
  process.exit(0);
}

const self = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (self.endsWith(path.join("harness", "v4", "cmp", "warm.ts"))) {
  main().catch((e: unknown) => {
    console.error(`[cmp-warm] ${sanitize(e instanceof Error ? e.message : String(e))}`);
    process.exit(1);
  });
}
