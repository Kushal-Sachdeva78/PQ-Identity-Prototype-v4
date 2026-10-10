import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readPower, readQuiesce, type PowerReading, type QuiesceReport } from "./guard.ts";
import {
  ALL_PROVERS,
  ALL_VERSIONS,
  DEFAULT_SEEDS,
  RAPIDSNARK_BLOCKED,
  VERSIONS,
  abs,
  acquireRunning,
  appendJsonl,
  benchRoot,
  buildSchedule,
  conditionId,
  envInfo,
  flag,
  gitHead,
  opt,
  optList,
  optNum,
  parseCondition,
  protocolSha,
  rapidsnarkState,
  rel,
  resolveVersion,
  sanitize,
  sha256Hex,
  sleep,
  snarkjsVersion,
  utcNow,
  writeJson,
  type Slot,
  type Version,
} from "./lib.ts";

/**
 * Warm series (docs/v4/BENCH_PROTOCOL.md, "Warm series"). ONE process holds every
 * condition; after `warmup` blocks it runs `n` measured blocks, each block every condition
 * once in a recorded shuffled order (seeded).
 *
 *   node --import tsx harness/v4/bench/warm.ts --campaign warm --versions v2,v3,v4 --provers snarkjs,rapidsnark
 *   add --smoke for the smoke test (n=3, warm-up 1, settle 5 s, output under results/v4/bench/_tmp/)
 *
 * One iteration makes exactly the calls of child_prove.ts (witness from the wasm path into
 * memory; prove from the zkey path; verify), so warm and cold differ only in process state:
 *   snarkjs    : in-process repeats; wasm, zkey and curve code are warm (JIT, page cache,
 *                bn128 curve and worker threads built once).
 *   rapidsnark : the prover binary loads the zkey in every process, so "warm" means
 *                repeated prover invocations with the zkey on a warm OS page cache and a
 *                warm Node process for witness and verify.
 * Power is read before and after every block; a block with a non-AC reading is recorded as
 * "discarded-battery" and repeated. Not resumable: a restart starts a new session; the
 * analysis uses the latest complete session.
 */

interface Loaded {
  version: Version;
  keyLabel: string;
  input: Record<string, unknown>;
  vkey: unknown;
  wasm: string;
  zkey: string;
  publicSha: string;
}

interface IterationResult {
  timings: { witnessMs: number; proveMs: number; verifyMs: number; wpMs: number };
  aux: Record<string, number | null>;
  checks: { verified: boolean; publicSignalsMatch: boolean };
  hashes: { witnessSha256: string; publicSignalsSha256: string };
}

function hr(): bigint {
  return process.hrtime.bigint();
}
function msSince(t0: bigint): number {
  return Math.round((Number(process.hrtime.bigint() - t0) / 1e6) * 1000) / 1000;
}

type Snarkjs = typeof import("snarkjs");

async function iterate(snarkjs: Snarkjs, L: Loaded, prover: "snarkjs" | "rapidsnark", rapidsnarkBin: string | undefined): Promise<IterationResult> {
  const wtns: { type: "mem"; data?: Uint8Array } = { type: "mem" };
  const tW = hr();
  await snarkjs.wtns.calculate(L.input as never, L.wasm, wtns);
  const witnessMs = msSince(tW);
  if (!wtns.data) throw new Error("snarkjs produced no in-memory witness");
  const witnessSha256 = sha256Hex(wtns.data);
  let proveMs: number;
  let proof: unknown;
  let publicSignals: string[];
  const aux: Record<string, number | null> = {};
  if (prover === "snarkjs") {
    const tP = hr();
    const r = await snarkjs.groth16.prove(L.zkey, wtns as never);
    proveMs = msSince(tP);
    proof = r.proof;
    publicSignals = r.publicSignals as string[];
  } else {
    if (!rapidsnarkBin) throw new Error("rapidsnark unavailable");
    const tag = `pqid-bench-${process.pid}-${randomBytes(4).toString("hex")}`;
    const wtnsFile = path.join(os.tmpdir(), `${tag}.wtns`);
    const proofFile = path.join(os.tmpdir(), `${tag}.proof.json`);
    const publicFile = path.join(os.tmpdir(), `${tag}.public.json`);
    try {
      const tWr = hr();
      fs.writeFileSync(wtnsFile, wtns.data);
      aux["wtnsWriteMs"] = msSince(tWr);
      const tP = hr();
      const res = spawnSync(rapidsnarkBin, [L.zkey, wtnsFile, proofFile, publicFile], { shell: false, windowsHide: true, encoding: "utf8" });
      proveMs = msSince(tP);
      if (res.error) throw res.error;
      if (res.status !== 0) throw new Error(`rapidsnark exited ${res.status}`);
      proof = JSON.parse(fs.readFileSync(proofFile, "utf8")) as unknown;
      publicSignals = JSON.parse(fs.readFileSync(publicFile, "utf8")) as string[];
    } finally {
      for (const f of [wtnsFile, proofFile, publicFile]) fs.rmSync(f, { force: true });
    }
  }
  const tV = hr();
  const verified = await snarkjs.groth16.verify(L.vkey as never, publicSignals as never, proof as never);
  const verifyMs = msSince(tV);
  const publicSignalsSha256 = sha256Hex(JSON.stringify(publicSignals));
  return {
    timings: { witnessMs, proveMs, verifyMs, wpMs: Math.round((witnessMs + proveMs) * 1000) / 1000 },
    aux,
    checks: { verified, publicSignalsMatch: publicSignalsSha256 === L.publicSha },
    hashes: { witnessSha256, publicSignalsSha256 },
  };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const smoke = flag(argv, "smoke");
  const campaign = opt(argv, "campaign") ?? "warm";
  if (!/^[a-z0-9_]+$/.test(campaign)) throw new Error("--campaign must match [a-z0-9_]");
  const versions = optList(argv, "versions", ALL_VERSIONS, ALL_VERSIONS);
  const provers = optList(argv, "provers", ALL_PROVERS, ALL_PROVERS);
  const n = optNum(argv, "n", smoke ? 3 : 30);
  const warmup = optNum(argv, "warmup", smoke ? 1 : 5);
  const settleSec = optNum(argv, "settle", smoke ? 5 : 600);
  const blockGapSec = optNum(argv, "block-gap", 2);
  const seed = optNum(argv, "seed", DEFAULT_SEEDS[campaign] ?? 20261003);
  if (!smoke && n < 30) console.log(`[warm] WARNING: n=${n} < 30`);

  const root = benchRoot(smoke);
  const dir = path.join(root, campaign);
  fs.mkdirSync(dir, { recursive: true });
  const scheduleFile = path.join(dir, "schedule.json");
  const envFile = path.join(dir, "env.json");
  const runsFile = path.join(dir, "runs.jsonl");

  const protoSha = protocolSha();
  const rs = rapidsnarkState();
  const blocked: Array<{ condition: string; reason: string }> = [];
  const conditions: string[] = [];
  for (const v of versions) {
    for (const p of provers) {
      if (p === "rapidsnark" && !rs.available) blocked.push({ condition: conditionId(v, p), reason: rs.reason ?? RAPIDSNARK_BLOCKED });
      else conditions.push(conditionId(v, p));
    }
  }
  if (conditions.length === 0) throw new Error("no runnable condition");
  const resolved = Object.fromEntries(versions.map((v) => [v, resolveVersion(v, smoke)])) as Record<Version, ReturnType<typeof resolveVersion>>;

  // RUNNING first: nothing below (schedule, env.json, runs) is written while another runner is live
  const release = acquireRunning(root, campaign);

  const config = { campaign, mode: "warm", smoke, versions, provers, conditions, blocked, n, warmup, settleSec, blockGapSec, seed };
  let schedule: Slot[];
  if (fs.existsSync(scheduleFile)) {
    const s = JSON.parse(fs.readFileSync(scheduleFile, "utf8")) as { config: typeof config; slots: Slot[] };
    if (JSON.stringify(s.config) !== JSON.stringify(config)) throw new Error(`${rel(scheduleFile)} exists with a different configuration; use a new --campaign`);
    schedule = s.slots;
  } else {
    schedule = buildSchedule(conditions, warmup + n, seed, -warmup);
    writeJson(scheduleFile, {
      schema: "pqid/v4-bench-schedule/v1",
      createdUtc: utcNow(),
      config,
      prng: "mulberry32, Fisher-Yates from the end; one stream for all blocks",
      rule: "blocks < 0 are warm-up (not analysed); each block holds every runnable condition once, in shuffled order",
      slots: schedule,
    });
  }

  const artifacts = Object.fromEntries(versions.map((v) => [v, resolved[v].artifacts]));
  const inputs = Object.fromEntries(
    versions.map((v) => [v, { file: resolved[v].lock.file, inputSha256: resolved[v].lock.inputSha256, publicSignalsSha256: resolved[v].lock.publicSignalsSha256, source: resolved[v].lock.source }])
  );
  const session = utcNow();
  const sessionEntry = { session, env: envInfo(), gitHead: gitHead(), protocolSha256: protoSha.normative, protocolFileSha256: protoSha.file, snarkjs: snarkjsVersion() };
  const rapidsnark = rs.available ? { available: true, sha256: rs.sha256, basename: rs.basename } : { available: false, status: RAPIDSNARK_BLOCKED };
  if (fs.existsSync(envFile)) {
    const e = JSON.parse(fs.readFileSync(envFile, "utf8")) as { artifacts: unknown; inputs: unknown; protocolSha256: string; rapidsnark: unknown; sessions: unknown[] };
    if (JSON.stringify(e.artifacts) !== JSON.stringify(artifacts)) throw new Error("artifacts changed since this campaign started; use a new --campaign");
    if (JSON.stringify(e.inputs) !== JSON.stringify(inputs)) throw new Error("pinned inputs changed since this campaign started; use a new --campaign");
    if (e.protocolSha256 !== protoSha.normative) throw new Error("docs/v4/BENCH_PROTOCOL.md (above Deviations) changed since this campaign started; use a new --campaign");
    if (JSON.stringify(e.rapidsnark) !== JSON.stringify(rapidsnark)) throw new Error("rapidsnark state changed since this campaign started; use a new --campaign");
    e.sessions.push(sessionEntry);
    writeJson(envFile, e);
  } else {
    writeJson(envFile, {
      schema: "pqid/v4-bench-env/v1",
      campaign,
      mode: "warm",
      smoke,
      label: smoke ? "SMOKE TEST: not a result" : "[M] warm series",
      protocol: "docs/v4/BENCH_PROTOCOL.md",
      protocolSha256: protoSha.normative,
      protocolShaBasis: "SHA-256 of docs/v4/BENCH_PROTOCOL.md above '## Deviations', LF line ends",
      keyLabels: Object.fromEntries(versions.map((v) => [v, VERSIONS[v].keyLabel])),
      artifacts,
      inputs,
      rapidsnark,
      blocked,
      sessions: [sessionEntry],
    });
  }

  console.log(
    `[warm] ${campaign}: ${conditions.join(", ")}; warm-up ${warmup} + ${n} blocks; settle ${settleSec} s; ` +
      `blocked: ${blocked.map((b) => b.condition).join(", ") || "none"} -> ${rel(dir)}`
  );
  // ---- settle (idle) until on AC
  for (;;) {
    await sleep(Math.max(0, settleSec - 5) * 1000);
    const p = readPower();
    await sleep(Math.min(5, settleSec) * 1000);
    if (p.ac) break;
    console.log(`[warm] not on AC at the start (code ${p.code}); settling again`);
  }

  // ---- load once (untimed)
  const snarkjs = await import("snarkjs");
  const loaded = Object.fromEntries(
    versions.map((v) => {
      const r = resolved[v];
      const L: Loaded = {
        version: v,
        keyLabel: r.spec.keyLabel,
        input: JSON.parse(fs.readFileSync(abs(r.lock.file), "utf8")) as Record<string, unknown>,
        vkey: JSON.parse(fs.readFileSync(abs(r.spec.vkey.rel), "utf8")) as unknown,
        wasm: abs(r.spec.wasm.rel),
        zkey: abs(r.spec.zkey.rel),
        publicSha: r.lock.publicSignalsSha256,
      };
      return [v, L];
    })
  ) as Record<Version, Loaded>;

  const blocks = [...new Set(schedule.map((s) => s.block))].sort((a, b) => a - b);
  let discardedBlocks = 0;
  let consecutiveNonAc = 0;
  for (const b of blocks) {
    const slots = schedule.filter((s) => s.block === b).sort((x, y) => x.pos - y.pos);
    for (;;) {
      const pre: PowerReading = readPower();
      const q: QuiesceReport = await readQuiesce(Math.max(1, blockGapSec) * 1000); // doubles as the gap after the query
      if (!pre.ac) {
        consecutiveNonAc++;
        if (consecutiveNonAc >= 360) throw new Error("no mains power for 6 h; stopping");
        console.log(`[warm] block ${b}: not on AC (code ${pre.code}); waiting 60 s`);
        await sleep(60_000);
        continue;
      }
      consecutiveNonAc = 0;
      const recs: Array<Record<string, unknown>> = [];
      for (const s of slots) {
        const { version, prover } = parseCondition(s.condition);
        const L = loaded[version];
        const utcStart = utcNow();
        let res: IterationResult | null = null;
        let error: string | undefined;
        try {
          res = await iterate(snarkjs, L, prover, rs.bin);
          if (!res.checks.verified || !res.checks.publicSignalsMatch) error = "proof did not verify or public signals differ";
        } catch (e) {
          error = sanitize(e instanceof Error ? e.message : String(e));
        }
        recs.push({
          type: "run",
          schema: "pqid/v4-bench-run/v1",
          campaign,
          mode: "warm",
          session,
          slot: s.slot,
          block: s.block,
          pos: s.pos,
          warmup: s.block < 0,
          condition: s.condition,
          version,
          prover,
          keyLabel: L.keyLabel,
          status: error ? "error" : "ok",
          utcStart,
          utcEnd: utcNow(),
          timings: res?.timings ?? null,
          aux: res?.aux ?? null,
          checks: res?.checks ?? null,
          hashes: res?.hashes ?? null,
          env: { ...envInfo(), powerCode: pre.code, utc: utcStart },
          ...(error ? { error } : {}),
        });
        if (error) {
          for (const r of recs) appendJsonl(runsFile, { ...r, power: { pre, post: null }, quiesce: q });
          throw new Error(`block ${b} ${s.condition}: ${error}`);
        }
      }
      const post = readPower();
      const ok = post.ac;
      for (const r of recs) appendJsonl(runsFile, { ...r, status: ok ? r["status"] : "discarded-battery", ...(ok ? {} : { stage: "post" }), power: { pre, post }, quiesce: q });
      const summary = recs.map((r) => `${r["condition"]} ${((r["timings"] as IterationResult["timings"]).proveMs).toFixed(0)}`).join(", ");
      console.log(`[warm] block ${b}${b < 0 ? " (warm-up)" : ""}: ${ok ? "ok" : "DISCARDED (power)"}; prove ms: ${summary}`);
      if (ok) break;
      discardedBlocks++;
    }
  }
  appendJsonl(runsFile, { type: "session-end", campaign, session, utc: utcNow(), complete: true, measuredBlocks: n, warmupBlocks: warmup, discardedBlocks });
  release();
  console.log(`[warm] ${campaign} complete -> ${rel(runsFile)}`);
  process.exit(0);
}

main().catch((e: unknown) => {
  console.error(`[warm] ${sanitize(e instanceof Error ? e.message : String(e))}`);
  process.exit(1);
});
