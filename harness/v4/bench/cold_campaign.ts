import fs from "node:fs";
import path from "node:path";
import { readPower, readQuiesce, type PowerReading, type QuiesceReport } from "./guard.ts";
import {
  ALL_PROVERS,
  ALL_VERSIONS,
  CHILD_SCRIPT,
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
  lastJsonLine,
  opt,
  optList,
  optNum,
  parseCondition,
  protocolSha,
  rapidsnarkState,
  readJsonl,
  rel,
  resolveVersion,
  runNodeChild,
  sanitize,
  sleep,
  snarkjsVersion,
  utcNow,
  writeJson,
  type Prover,
  type Slot,
  type Version,
} from "./lib.ts";

/**
 * Cold series runner (docs/v4/BENCH_PROTOCOL.md, "Cold series").
 *
 *   node --import tsx harness/v4/bench/cold_campaign.ts --campaign cold_v4 --versions v4 --provers snarkjs,rapidsnark
 *   node --import tsx harness/v4/bench/cold_campaign.ts --campaign cold_v2v3 --versions v2,v3 --provers snarkjs,rapidsnark
 *   add --smoke for the smoke test (n=2, idle 5 s, output under results/v4/bench/_tmp/)
 *
 * Per slot of the recorded randomised schedule: wait the fixed idle since the previous run
 * ended, read power + quiet-machine state `lead` seconds before the start, spawn ONE fresh
 * child process (child_prove.ts), read power again when it exits, append one JSON line to
 * <root>/<campaign>/runs.jsonl. A run with a non-AC reading before or after is recorded as
 * "discarded-battery" and the slot is repeated after a full idle. Resumable: completed slots
 * (status "ok") are skipped on restart; schedule.json and env.json must still match.
 */

interface RunRecord {
  type: "run";
  schema: "pqid/v4-bench-run/v1";
  campaign: string;
  mode: "cold";
  session: string;
  slot: number;
  block: number;
  pos: number;
  condition: string;
  version: Version;
  prover: Prover;
  keyLabel: string;
  attempt: number;
  status: "ok" | "discarded-battery" | "error";
  stage?: "pre" | "post";
  utcStart: string | null;
  utcEnd: string | null;
  idleSec: number;
  postponements: number;
  power: { pre: PowerReading; post: PowerReading | null };
  quiesce: QuiesceReport;
  timings: { witnessMs: number; proveMs: number; verifyMs: number; wpMs: number } | null;
  aux: Record<string, unknown> | null;
  checks: { verified: boolean; publicSignalsMatch: boolean } | null;
  hashes: Record<string, string> | null;
  env: ReturnType<typeof envInfo> & { powerCode: string; utc: string };
  error?: string;
}

interface ChildLine {
  ok: boolean;
  verified?: boolean;
  publicSignalsMatch?: boolean;
  timings?: { witnessMs: number; proveMs: number; verifyMs: number; wpMs: number };
  aux?: Record<string, unknown>;
  hashes?: Record<string, string>;
  error?: string;
}

const MAX_ERRORS_PER_SLOT = 3;
const MAX_CONSECUTIVE_NON_AC = 36; // 36 idles (6 h at 600 s) without mains power: stop

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const smoke = flag(argv, "smoke");
  const campaign = opt(argv, "campaign");
  if (!campaign || !/^[a-z0-9_]+$/.test(campaign)) throw new Error("--campaign <name> required ([a-z0-9_])");
  const versions = optList(argv, "versions", ALL_VERSIONS, []);
  if (versions.length === 0) throw new Error("--versions required (e.g. v4 or v2,v3)");
  const provers = optList(argv, "provers", ALL_PROVERS, ALL_PROVERS);
  const n = optNum(argv, "n", smoke ? 2 : 30);
  const idleSec = optNum(argv, "idle", smoke ? 5 : 600);
  const leadSec = Math.min(optNum(argv, "lead", 20), idleSec);
  const maxPostpone = optNum(argv, "max-postpone", smoke ? 0 : 10);
  const postponeStepSec = optNum(argv, "postpone-step", 60);
  const seed = optNum(argv, "seed", DEFAULT_SEEDS[campaign] ?? 20261002);
  const childTimeoutMs = optNum(argv, "child-timeout", 900) * 1000;
  if (!smoke && n < 30) console.log(`[cold] WARNING: n=${n} < 30 (the protocol requires >= 30 for a real series)`);

  const root = benchRoot(smoke);
  const dir = path.join(root, campaign);
  fs.mkdirSync(dir, { recursive: true });
  const scheduleFile = path.join(dir, "schedule.json");
  const envFile = path.join(dir, "env.json");
  const runsFile = path.join(dir, "runs.jsonl");

  // ---- preconditions: protocol, rapidsnark, artifacts + pinned inputs
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

  // ---- schedule (created once; must match on resume)
  const config = { campaign, mode: "cold", smoke, versions, provers, conditions, blocked, n, idleSec, leadSec, seed, maxPostpone, postponeStepSec };
  let schedule: Slot[];
  if (fs.existsSync(scheduleFile)) {
    const s = JSON.parse(fs.readFileSync(scheduleFile, "utf8")) as { config: typeof config; slots: Slot[] };
    if (JSON.stringify(s.config) !== JSON.stringify(config)) {
      throw new Error(`${rel(scheduleFile)} exists with a different configuration; resume with the same flags or use a new --campaign`);
    }
    schedule = s.slots;
  } else {
    schedule = buildSchedule(conditions, n, seed);
    writeJson(scheduleFile, {
      schema: "pqid/v4-bench-schedule/v1",
      createdUtc: utcNow(),
      config,
      prng: "mulberry32, Fisher-Yates from the end; one stream for all blocks",
      rule: "each block holds every runnable condition once, in shuffled order",
      slots: schedule,
    });
  }

  // ---- env.json (campaign level; sessions appended on resume)
  const artifacts = Object.fromEntries(versions.map((v) => [v, resolved[v].artifacts]));
  const inputs = Object.fromEntries(
    versions.map((v) => [v, { file: resolved[v].lock.file, inputSha256: resolved[v].lock.inputSha256, publicSignalsSha256: resolved[v].lock.publicSignalsSha256, source: resolved[v].lock.source }])
  );
  const session = utcNow();
  // Protocol order: warm series first. Not enforced; recorded and warned.
  const warmSeriesComplete = readJsonl<{ type?: string; complete?: boolean }>(path.join(root, "warm", "runs.jsonl")).some(
    (r) => r.type === "session-end" && r.complete === true
  );
  if (!warmSeriesComplete) console.log("[cold] WARNING: no complete warm series in this results root (protocol order: warm series first)");
  const sessionEntry = { session, env: envInfo(), gitHead: gitHead(), protocolSha256: protoSha.normative, protocolFileSha256: protoSha.file, snarkjs: snarkjsVersion(), warmSeriesComplete };
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
      mode: "cold",
      smoke,
      label: smoke ? "SMOKE TEST: not a result" : "[M] cold series",
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

  // ---- progress so far
  const prior = readJsonl<RunRecord>(runsFile).filter((r) => r.type === "run");
  const done = new Set(prior.filter((r) => r.status === "ok").map((r) => r.slot));
  const attempts = new Map<number, number>();
  for (const r of prior) attempts.set(r.slot, (attempts.get(r.slot) ?? 0) + 1);
  const todo = schedule.filter((s) => !done.has(s.slot));
  console.log(
    `[cold] ${campaign}: ${schedule.length} slots (${conditions.join(", ")}), ${done.size} done, ${todo.length} to run; ` +
      `idle ${idleSec} s; blocked: ${blocked.map((b) => b.condition).join(", ") || "none"} -> ${rel(dir)}`
  );

  const now = () => performance.now();
  let idleStart = now();
  let consecutiveNonAc = 0;

  for (const slot of todo) {
    const { version, prover } = parseCondition(slot.condition);
    const r = resolved[version];
    let errors = prior.filter((x) => x.slot === slot.slot && x.status === "error").length;
    for (;;) {
      // ---- fixed idle; power + quiet-machine reading `lead` seconds before the start
      await sleep(idleStart + (idleSec - leadSec) * 1000 - now());
      let pre = readPower();
      let q = await readQuiesce();
      let postponements = 0;
      while (!q.quiesced && postponements < maxPostpone) {
        console.log(`[cold] slot ${slot.slot}: machine busy (cpu ${q.cpuBusyPercent}%, ${q.offending.join(" ") || "-"}); postponing ${postponeStepSec} s`);
        await sleep(postponeStepSec * 1000);
        postponements++;
        q = await readQuiesce();
        pre = readPower();
      }
      await sleep(idleStart + idleSec * 1000 - now());
      const idleSecActual = Math.round((now() - idleStart) / 100) / 10;
      const attempt = (attempts.get(slot.slot) ?? 0) + 1;
      attempts.set(slot.slot, attempt);
      const base = {
        type: "run" as const,
        schema: "pqid/v4-bench-run/v1" as const,
        campaign,
        mode: "cold" as const,
        session,
        slot: slot.slot,
        block: slot.block,
        pos: slot.pos,
        condition: slot.condition,
        version,
        prover,
        keyLabel: r.spec.keyLabel,
        attempt,
        idleSec: idleSecActual,
        postponements,
        quiesce: q,
      };

      if (!pre.ac) {
        consecutiveNonAc++;
        appendJsonl(runsFile, {
          ...base, status: "discarded-battery", stage: "pre", utcStart: null, utcEnd: null,
          power: { pre, post: null }, timings: null, aux: null, checks: null, hashes: null,
          env: { ...envInfo(), powerCode: pre.code, utc: utcNow() },
        } satisfies RunRecord);
        console.log(`[cold] slot ${slot.slot} ${slot.condition}: not on AC before the run (code ${pre.code}); discarded, full idle again`);
        if (consecutiveNonAc >= MAX_CONSECUTIVE_NON_AC) throw new Error(`no mains power for ${consecutiveNonAc} consecutive checks; stopping (resume later)`);
        idleStart = now();
        continue;
      }
      consecutiveNonAc = 0;

      // ---- one cold run in a fresh process
      const utcStart = utcNow();
      const child = await runNodeChild(
        CHILD_SCRIPT,
        [
          "--version", version,
          "--prover", prover,
          "--input", abs(r.lock.file),
          "--input-sha", r.lock.inputSha256,
          "--public-sha", r.lock.publicSignalsSha256,
          "--wasm", abs(r.spec.wasm.rel),
          "--zkey", abs(r.spec.zkey.rel),
          "--vkey", abs(r.spec.vkey.rel),
        ],
        childTimeoutMs
      );
      idleStart = now();
      const utcEnd = utcNow();
      const post = readPower();
      const line = lastJsonLine<ChildLine>(child.stdout);
      const env = { ...envInfo(), powerCode: pre.code, utc: utcStart };

      if (child.code !== 0 || !line || !line.ok || !line.timings) {
        errors++;
        const why = child.timedOut ? "child timed out" : line?.error ?? (line && !line.ok ? "proof did not verify or public signals differ" : `exit ${child.code}`);
        appendJsonl(runsFile, {
          ...base, status: "error", utcStart, utcEnd, power: { pre, post },
          timings: line?.timings ?? null, aux: { ...(line?.aux ?? {}), childWallMs: Math.round(child.wallMs * 1000) / 1000 },
          checks: line ? { verified: line.verified ?? false, publicSignalsMatch: line.publicSignalsMatch ?? false } : null,
          hashes: line?.hashes ?? null, env,
          error: sanitize(`${why}; stderr tail: ${child.stderr.slice(-800)}`),
        } satisfies RunRecord);
        console.log(`[cold] slot ${slot.slot} ${slot.condition}: ERROR (${sanitize(why)}) [${errors}/${MAX_ERRORS_PER_SLOT}]`);
        if (errors >= MAX_ERRORS_PER_SLOT) throw new Error(`slot ${slot.slot} failed ${errors} times; stopping (fix, then resume)`);
        continue;
      }

      const rec: RunRecord = {
        ...base,
        status: post.ac ? "ok" : "discarded-battery",
        ...(post.ac ? {} : { stage: "post" as const }),
        utcStart,
        utcEnd,
        power: { pre, post },
        timings: line.timings,
        aux: { ...(line.aux ?? {}), childWallMs: Math.round(child.wallMs * 1000) / 1000 },
        checks: { verified: line.verified ?? false, publicSignalsMatch: line.publicSignalsMatch ?? false },
        hashes: line.hashes ?? null,
        env,
      };
      appendJsonl(runsFile, rec);
      const t = line.timings;
      console.log(
        `[cold] slot ${slot.slot + 1}/${schedule.length} ${slot.condition}: ${rec.status} ` +
          `witness ${t.witnessMs.toFixed(1)} prove ${t.proveMs.toFixed(1)} verify ${t.verifyMs.toFixed(1)} ms (idle ${idleSecActual} s)`
      );
      if (post.ac) break;
      console.log(`[cold] slot ${slot.slot}: power left AC during the run (code ${post.code}); discarded, repeating after a full idle`);
    }
  }

  appendJsonl(runsFile, { type: "campaign-end", campaign, session, utc: utcNow(), complete: true });
  release();
  console.log(`[cold] ${campaign} complete -> ${rel(runsFile)}`);
  process.exit(0);
}

main().catch((e: unknown) => {
  console.error(`[cold] ${sanitize(e instanceof Error ? e.message : String(e))}`);
  process.exit(1);
});
