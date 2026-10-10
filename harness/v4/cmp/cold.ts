import fs from "node:fs";
import path from "node:path";
import { readPower, type PowerReading } from "../bench/guard.ts";
import { readQuiesceExcluding, type QuiesceRecord } from "../lib/quiesce.ts";
import {
  CHILD_SCRIPT,
  abs,
  appendJsonl,
  buildSchedule,
  envInfo,
  flag,
  gitHead,
  inputFileSha,
  lastJsonLine,
  opt,
  optNum,
  readJsonl,
  rel,
  runNodeChild,
  sanitize,
  snarkjsVersion,
  utcNow,
  writeJson,
  type Slot,
} from "../bench/lib.ts";
import { readCmpLock, type CmpLock } from "./inputs.ts";
import { assertCampaignName, holdWork, phaseDQuiesce, sameJson, IdleWatch, HOST_PAUSE_GAP_SEC, PHASE_D_QUIET_RULE, WATCH_TICK_MS, type IdleReading, type PhaseDQuiesce } from "./runner.ts";
import {
  CMP_SEEDS,
  CURVE_CONDITION,
  DEFAULT_COLD_CONDITIONS,
  PROVE_CONDITIONS,
  TIMED_CODE,
  WALLET_CONDITIONS,
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
  walletRoot,
  walletSize,
  type Circuit,
  type CircuitArtifacts,
  type ProveCondition,
  type WalletCondition,
} from "./spec.ts";

/**
 * Cold campaigns of the cmp series (docs/v4/CMP.md, "Cold series" and "Wallet rebuild").
 *
 *   node --import tsx harness/v4/cmp/cold.ts --kind prove  [--conditions v2,v2o2,v3,v4,eddsa[,curve]] [v4 key flags] [--campaign NAME]
 *   node --import tsx harness/v4/cmp/cold.ts --kind wallet [--conditions wallet1e5,wallet1e6] [--campaign NAME]
 *   add --smoke for the smoke test (n=1, idle 5 s, no postponing, tiny wallet sizes, output under
 *   results/v4/cmp/_smoke/, holds results/v4/BUSY; --smoke-no-marker holds only the smoke lock;
 *   a smoke campaign always starts fresh)
 *
 * Real runs: native Windows only, the fixed parameters of spec.ts REAL_MODE, the ceremony key
 * (the dev key only with --allow-dev-key), and the code, docs/v4/CMP.md, pins, input lock and
 * analysis committed and unchanged at HEAD (--allow-uncommitted overrides, recorded).
 *
 * Per slot of the recorded randomised schedule (blocked, mulberry32, seed of D-034: 20261041 for
 * prove, 20261042 for wallet; conditions in canonical order whatever order --conditions gives):
 * fixed idle since the previous run ended (600 s, monotonic clock, slept in steps of at most 1 s
 * by a host-pause watchdog, runner.ts IdleWatch), power and quiet-machine readings 20 s before
 * the start (postpone 60 s steps, at most 10, while the Phase D guard rule says busy; runner.ts
 * phaseDQuiesce), ONE fresh child process, power again after it exits, one JSON line in
 * runs.jsonl. Discard, error, timeout and resume rules are those of
 * harness/v4/bench/cold_campaign.ts.
 *
 * Children: circuits run harness/v4/bench/child_prove.ts UNCHANGED (the protocol's prove
 * definition, snarkJS); `curve` runs child_curve.ts; wallet sizes run child_wallet.ts.
 * Real runs hold results/v4/bench/RUNNING (D-034; borrowed from a wrapping `markers.ts run`) and
 * refuse while it or results/v4/BUSY exists.
 */

type Kind = "prove" | "wallet";

interface Plan {
  name: ProveCondition | WalletCondition;
  condition: string;
  version: string;
  prover: string;
  keyLabel: string;
  script: string;
  args: string[];
}

interface ChildLine {
  ok: boolean;
  verified?: boolean;
  publicSignalsMatch?: boolean;
  timings?: Record<string, number>;
  aux?: Record<string, unknown>;
  hashes?: Record<string, string>;
  checks?: Record<string, boolean>;
  roots?: Record<string, string>;
  size?: Record<string, number>;
  error?: string;
}

export interface CmpRunRecord extends IdleReading {
  type: "run";
  schema: "pqid/v4-cmp-run/v1";
  campaign: string;
  mode: "cold";
  kind: Kind;
  session: string;
  slot: number;
  block: number;
  pos: number;
  condition: string;
  version: string;
  prover: string;
  keyLabel: string;
  attempt: number;
  status: "ok" | "discarded-battery" | "error";
  stage?: "pre" | "post";
  utcStart: string | null;
  utcEnd: string | null;
  postponements: number;
  power: { pre: PowerReading; post: PowerReading | null };
  /** Phase D view of the reading: `quiesced` is the guard.ts rule (runner.ts phaseDQuiesce). */
  quiesce: PhaseDQuiesce;
  /** The full harness/v4/lib/quiesce.ts reading (its own `quiesced` is the stricter D-034 rule). */
  quiesceDetail: QuiesceRecord;
  timings: Record<string, number> | null;
  aux: Record<string, unknown> | null;
  checks: Record<string, boolean> | null;
  hashes: Record<string, string> | null;
  results?: Record<string, unknown>;
  env: ReturnType<typeof envInfo> & { powerCode: string; utc: string };
  error?: string;
}

const MAX_ERRORS_PER_SLOT = 3;
const MAX_CONSECUTIVE_NON_AC = 36;
const CURVE_SCRIPT = abs("harness/v4/cmp/child_curve.ts");
const WALLET_SCRIPT = abs("harness/v4/cmp/child_wallet.ts");

function plansFor(kind: Kind, names: readonly string[], lock: CmpLock, smoke: boolean, argv: readonly string[]) {
  const specs = circuitSpecs(v4KeyFromArgs(argv));
  const plans: Plan[] = [];
  const artifacts: Partial<Record<Circuit, CircuitArtifacts>> = {};
  const inputs: Record<string, unknown> = {};
  for (const n of names) {
    if (kind === "wallet") {
      const c = n as WalletCondition;
      const e = lock.wallet[c];
      if (!e) throw new Error(`no pinned wallet roots for ${c} in the cmp lock (run harness/v4/cmp/inputs.ts${smoke ? " --smoke" : ""})`);
      const size = walletSize(c, smoke);
      if (e.credentials !== size.credentials || e.revocations !== size.revocations) throw new Error(`${c}: lock sizes ${e.credentials}/${e.revocations} differ from the series sizes ${size.credentials}/${size.revocations}`);
      inputs[c] = { credentials: e.credentials, revocations: e.revocations, issuanceRoot: e.issuanceRoot, revocationRoot: e.revocationRoot, generator: e.generator };
      plans.push({
        name: c,
        condition: conditionIdOf(c),
        version: c,
        prover: "node",
        keyLabel: "none (no key)",
        script: WALLET_SCRIPT,
        args: ["--condition", c, "--credentials", String(e.credentials), "--revocations", String(e.revocations), "--iss-root", e.issuanceRoot, "--rev-root", e.revocationRoot],
      });
      continue;
    }
    if (n === CURVE_CONDITION) {
      plans.push({ name: "curve", condition: conditionIdOf("curve"), version: "curve", prover: "snarkjs", keyLabel: "none (no key)", script: CURVE_SCRIPT, args: [] });
      continue;
    }
    const c = n as Circuit;
    const s = specs[c];
    const e = lock.circuits[c];
    if (!e) throw new Error(`no pinned input for ${c} in the cmp lock (run harness/v4/cmp/inputs.ts${smoke ? " --smoke" : ""} with the same v4 key flags)`);
    const a = checkCircuitArtifacts(s);
    for (const k of ["wasm", "zkey", "vkey"] as const) {
      if (a[k].sha256 !== e.artifacts[k].sha256) throw new Error(`${c} ${k} changed since its input was pinned (${e.artifacts[k].sha256} -> ${a[k].sha256}); re-run inputs.ts`);
    }
    if (e.keyLabel !== s.keyLabel) throw new Error(`${c}: key label '${s.keyLabel}' differs from the pinned '${e.keyLabel}'`);
    const sha = inputFileSha(abs(e.file));
    if (sha !== e.inputSha256) throw new Error(`${c} input file hash ${sha} != pinned ${e.inputSha256}`);
    artifacts[c] = a;
    inputs[c] = { file: e.file, inputSha256: e.inputSha256, publicSignalsSha256: e.publicSignalsSha256, source: e.source };
    plans.push({
      name: c,
      condition: conditionIdOf(c),
      version: c,
      prover: "snarkjs",
      keyLabel: s.keyLabel,
      script: CHILD_SCRIPT,
      args: [
        "--version", c,
        "--prover", "snarkjs",
        "--input", abs(e.file),
        "--input-sha", e.inputSha256,
        "--public-sha", e.publicSignalsSha256,
        "--wasm", abs(s.wasm.rel),
        "--zkey", abs(s.zkey.rel),
        "--vkey", abs(s.vkey.rel),
      ],
    });
  }
  return { plans, artifacts, inputs, specs };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const smoke = flag(argv, "smoke");
  const smokeNoMarker = flag(argv, "smoke-no-marker");
  if (smokeNoMarker && !smoke) throw new Error("--smoke-no-marker goes with --smoke");
  const kind = (opt(argv, "kind") ?? "prove") as Kind;
  if (kind !== "prove" && kind !== "wallet") throw new Error("--kind prove|wallet");
  const campaign = assertCampaignName(opt(argv, "campaign") ?? (kind === "prove" ? "cold_cmp" : "wallet_cmp"));
  // canonical order: the typed order of --conditions never changes the schedule of a seed
  const names: string[] =
    kind === "prove"
      ? canonicalOrder(parseList(opt(argv, "conditions"), PROVE_CONDITIONS, "--conditions") ?? [...DEFAULT_COLD_CONDITIONS], PROVE_CONDITIONS)
      : canonicalOrder(parseList(opt(argv, "conditions"), WALLET_CONDITIONS, "--conditions") ?? [...WALLET_CONDITIONS], WALLET_CONDITIONS);
  const n = optNum(argv, "n", smoke ? 1 : kind === "prove" ? 30 : 10);
  const idleSec = optNum(argv, "idle", smoke ? 5 : 600);
  const leadSec = Math.min(optNum(argv, "lead", smoke ? 4 : 20), idleSec);
  const maxPostpone = optNum(argv, "max-postpone", smoke ? 0 : 10);
  const postponeStepSec = optNum(argv, "postpone-step", 60);
  const childTimeoutSec = optNum(argv, "child-timeout", 900);
  const childTimeoutMs = childTimeoutSec * 1000;
  const seed = kind === "prove" ? CMP_SEEDS.cold : CMP_SEEDS.wallet;
  const allowDevKey = flag(argv, "allow-dev-key");
  const allowUncommitted = flag(argv, "allow-uncommitted");

  // v4 key: real campaigns run after the ceremony (D-034); the dev key needs an explicit override.
  const v4 = resolveV4Key(v4KeyFromArgs(argv));
  const timedFiles = kind === "wallet" ? TIMED_CODE.wallet : [...TIMED_CODE.prove, ...(names.includes(CURVE_CONDITION) ? TIMED_CODE.curve : [])];
  const code = codeRecord(timedFiles, smoke);
  if (!smoke) {
    const problems = realModeProblems({
      series: kind,
      platform: process.platform,
      params: { n, idleSec, leadSec, maxPostpone, postponeStepSec, childTimeoutSec },
      v4Included: kind === "prove" && names.includes("v4"),
      isDevKey: v4.isDevKey,
      allowDevKey,
      committedAtHead: code.committedAtHead,
      allowUncommitted,
    });
    if (problems.length > 0) throw new Error(`refusing a real ${kind} series (docs/v4/CMP.md): ${problems.join("; ")} (use --smoke to test the runner)`);
  }

  const root = kind === "prove" ? proveRoot(smoke) : walletRoot(smoke);
  const dir = path.join(root, campaign);
  const scheduleFile = path.join(dir, "schedule.json");
  const envFile = path.join(dir, "env.json");
  const runsFile = path.join(dir, "runs.jsonl");
  if (smoke && fs.existsSync(dir)) {
    throw new Error(`${rel(dir)} exists: a smoke always starts fresh (scripts/cmp/quiet_window_cmp.sh with PQID_CMP_SMOKE=1 moves old smoke output aside first, or run harness/v4/cmp/smoke_reset.ts)`);
  }

  const protocol = protocolRecord();
  const lock = readCmpLock(smoke);
  const { plans, artifacts, inputs, specs } = plansFor(kind, names, lock, smoke, argv);

  // Marker first: nothing below is written while another runner holds RUNNING or BUSY.
  const hold = holdWork({ kind: "RUNNING", smoke, smokeNoMarker, smokeRoot: cmpRoot(true), campaign, runner: "harness/v4/cmp/cold.ts", argv, note: `cmp ${kind} cold series` });
  fs.mkdirSync(dir, { recursive: true });

  const conditions = plans.map((p) => p.condition);
  const config = { campaign, mode: "cold", kind, smoke, conditions, n, idleSec, leadSec, seed, seedSource: "DECISIONS D-034 (harness/v4/lib/seeds.ts)", maxPostpone, postponeStepSec, childTimeoutSec };
  let schedule: Slot[];
  if (fs.existsSync(scheduleFile)) {
    const s = JSON.parse(fs.readFileSync(scheduleFile, "utf8")) as { config: typeof config; slots: Slot[] };
    if (!sameJson(s.config, config)) throw new Error(`${rel(scheduleFile)} exists with a different configuration; resume with the same flags or use a new --campaign`);
    schedule = s.slots;
  } else {
    schedule = buildSchedule(conditions, n, seed);
    writeJson(scheduleFile, {
      schema: "pqid/v4-cmp-schedule/v1",
      createdUtc: utcNow(),
      config,
      prng: "mulberry32, Fisher-Yates from the end; one stream for all blocks (harness/v4/bench/lib.ts buildSchedule)",
      rule: "each block holds every condition once, in shuffled order; conditions in canonical order before shuffling",
      slots: schedule,
    });
  }

  const keyLabels = Object.fromEntries(plans.map((p) => [p.version, p.keyLabel]));
  const notes = conditionNotes(names, specs, smoke);
  const session = utcNow();
  const warmComplete =
    kind === "prove" &&
    readJsonl<{ type?: string; complete?: boolean }>(path.join(proveRoot(smoke), "warm_cmp", "runs.jsonl")).some((r) => r.type === "session-end" && r.complete === true);
  const sessionEntry = {
    session,
    env: envInfo(),
    gitHead: gitHead(),
    codeCommittedAtHead: code.committedAtHead,
    allowUncommitted: !smoke && allowUncommitted,
    protocolSha256: protocol.benchProtocolSha256,
    protocolFileSha256: protocol.benchProtocolFileSha256,
    cmpProtocolFileSha256: protocol.cmpProtocolFileSha256,
    snarkjs: snarkjsVersion(),
    warmSeriesComplete: warmComplete,
    marker: hold.record,
  };
  const label = smoke ? "SMOKE TEST: not a result" : kind === "prove" ? "[M] cmp cold series (snarkJS)" : "[M] cmp wallet rebuild series";
  if (fs.existsSync(envFile)) {
    const e = JSON.parse(fs.readFileSync(envFile, "utf8")) as Record<string, unknown> & { sessions: unknown[]; code: { timed: unknown } };
    const checks: Array<[string, unknown, unknown]> = [
      ["artifacts", e["artifacts"], artifacts],
      ["inputs", e["inputs"], inputs],
      ["docs/v4/BENCH_PROTOCOL.md (above Deviations)", e["protocolSha256"], protocol.benchProtocolSha256],
      ["docs/v4/CMP.md (above Deviations)", e["cmpProtocolSha256"], protocol.cmpProtocolSha256],
      ["timed code", e.code.timed, code.timed],
      ["key labels", e["keyLabels"], keyLabels],
    ];
    for (const [what, a, b] of checks) if (!sameJson(a, b)) throw new Error(`${what} changed since this campaign started; use a new --campaign`);
    e.sessions.push(sessionEntry);
    writeJson(envFile, e);
  } else {
    writeJson(envFile, {
      schema: "pqid/v4-cmp-env/v1",
      campaign,
      mode: "cold",
      kind,
      smoke,
      label,
      protocol: protocol.benchProtocol,
      protocolSha256: protocol.benchProtocolSha256,
      protocolShaBasis: protocol.shaBasis,
      cmpProtocol: protocol.cmpProtocol,
      cmpProtocolSha256: protocol.cmpProtocolSha256,
      keyLabels,
      v4Key: kind === "prove" && names.includes("v4") ? { label: v4.keyLabel, isDevKey: v4.isDevKey, allowDevKeyFlag: allowDevKey } : null,
      conditionNotes: notes,
      artifacts,
      inputs,
      inputsLock: { path: rel(path.join(cmpRoot(smoke), "inputs", "inputs_cmp.lock.json")), createdUtc: lock.createdUtc },
      code,
      allowUncommitted: !smoke && allowUncommitted,
      rapidsnark: { available: false, status: "not used: the cmp series is snarkJS on Windows (D-034 skips the WSL cmp campaign)" },
      blocked: [],
      quietRule: { postpone: PHASE_D_QUIET_RULE, recorded: "quiesce = Phase D view (quiesced = guard.ts rule); quiesceDetail = full harness/v4/lib/quiesce.ts reading" },
      hostPause: {
        rule: `hostPauseSuspected = |clockGapSec| > ${HOST_PAUSE_GAP_SEC} s or idleMaxTickGapSec > ${HOST_PAUSE_GAP_SEC} s`,
        watchdog: `the idle is slept in steps of at most ${WATCH_TICK_MS} ms; idleMaxTickGapSec is the largest gap between consecutive wake-ups on performance.now() or Date.now() (power and quiet readings between watched sleeps are not counted)`,
        windowsNote: "performance.now() is QueryPerformanceCounter on Windows and may count through standby, so clockGapSec alone may not show a standby; the watchdog gap does. Not verified with a standby test on this laptop [A].",
      },
      sessions: [sessionEntry],
    });
  }

  const prior = readJsonl<CmpRunRecord>(runsFile).filter((r) => r.type === "run");
  const done = new Set(prior.filter((r) => r.status === "ok").map((r) => r.slot));
  const attempts = new Map<number, number>();
  for (const r of prior) attempts.set(r.slot, (attempts.get(r.slot) ?? 0) + 1);
  const todo = schedule.filter((s) => !done.has(s.slot));
  const byCondition = new Map(plans.map((p) => [p.condition, p] as const));
  console.log(`[cmp-cold] ${campaign} (${kind}): ${schedule.length} slots (${conditions.join(", ")}), ${done.size} done, ${todo.length} to run; idle ${idleSec} s -> ${rel(dir)}`);

  const idle = new IdleWatch();
  let consecutiveNonAc = 0;
  for (const slot of todo) {
    const plan = byCondition.get(slot.condition);
    if (!plan) throw new Error(`schedule condition ${slot.condition} has no plan`);
    let errors = prior.filter((x) => x.slot === slot.slot && x.status === "error").length;
    for (;;) {
      await idle.sleepUntilOffset((idleSec - leadSec) * 1000);
      let pre = readPower();
      let q = await readQuiesceExcluding({});
      let postponements = 0;
      while (!q.guardTs.quiesced && postponements < maxPostpone) {
        console.log(`[cmp-cold] slot ${slot.slot}: machine busy (cpu ${q.cpuBusyPercent} %${q.guardTs.offending.length ? `, ${q.guardTs.offending.join(" ")}` : ""}); postponing ${postponeStepSec} s`);
        await idle.sleep(postponeStepSec * 1000);
        postponements++;
        q = await readQuiesceExcluding({});
        pre = readPower();
      }
      await idle.sleepUntilOffset(idleSec * 1000);
      const idleRec = idle.reading();
      const attempt = (attempts.get(slot.slot) ?? 0) + 1;
      attempts.set(slot.slot, attempt);
      const base = {
        type: "run" as const,
        schema: "pqid/v4-cmp-run/v1" as const,
        campaign,
        mode: "cold" as const,
        kind,
        session,
        slot: slot.slot,
        block: slot.block,
        pos: slot.pos,
        condition: slot.condition,
        version: plan.version,
        prover: plan.prover,
        keyLabel: plan.keyLabel,
        attempt,
        ...idleRec,
        postponements,
        quiesce: phaseDQuiesce(q),
        quiesceDetail: q,
      };
      if (!pre.ac) {
        consecutiveNonAc++;
        appendJsonl(runsFile, {
          ...base, status: "discarded-battery", stage: "pre", utcStart: null, utcEnd: null,
          power: { pre, post: null }, timings: null, aux: null, checks: null, hashes: null,
          env: { ...envInfo(), powerCode: pre.code, utc: utcNow() },
        } satisfies CmpRunRecord);
        console.log(`[cmp-cold] slot ${slot.slot} ${slot.condition}: not on AC before the run (code ${pre.code}); discarded, full idle again`);
        if (consecutiveNonAc >= MAX_CONSECUTIVE_NON_AC) throw new Error(`no mains power for ${consecutiveNonAc} consecutive checks; stopping (resume later)`);
        idle.restart();
        continue;
      }
      consecutiveNonAc = 0;

      const utcStart = utcNow();
      const child = await runNodeChild(plan.script, plan.args, childTimeoutMs);
      idle.restart();
      const utcEnd = utcNow();
      const post = readPower();
      const line = lastJsonLine<ChildLine>(child.stdout);
      const env = { ...envInfo(), powerCode: pre.code, utc: utcStart };
      const aux = { ...(line?.aux ?? {}), childWallMs: Math.round(child.wallMs * 1000) / 1000 };
      const checks = line ? (line.checks ?? { verified: line.verified ?? false, publicSignalsMatch: line.publicSignalsMatch ?? false }) : null;
      const results = line?.roots || line?.size ? { ...(line.size ? { size: line.size } : {}), ...(line.roots ? { roots: line.roots } : {}) } : undefined;

      if (child.code !== 0 || !line || !line.ok || !line.timings) {
        errors++;
        const why = child.timedOut ? "child timed out" : (line?.error ?? (line && !line.ok ? "check failed (proof did not verify, other public signals or other roots)" : `exit ${child.code}`));
        appendJsonl(runsFile, {
          ...base, status: "error", utcStart, utcEnd, power: { pre, post },
          timings: line?.timings ?? null, aux, checks, hashes: line?.hashes ?? null,
          ...(results ? { results } : {}), env,
          error: sanitize(`${why}; stderr tail: ${child.stderr.slice(-800)}`),
        } satisfies CmpRunRecord);
        console.log(`[cmp-cold] slot ${slot.slot} ${slot.condition}: ERROR (${sanitize(why)}) [${errors}/${MAX_ERRORS_PER_SLOT}]`);
        if (errors >= MAX_ERRORS_PER_SLOT) throw new Error(`slot ${slot.slot} failed ${errors} times; stopping (fix, then resume)`);
        continue;
      }
      const rec: CmpRunRecord = {
        ...base,
        status: post.ac ? "ok" : "discarded-battery",
        ...(post.ac ? {} : { stage: "post" as const }),
        utcStart,
        utcEnd,
        power: { pre, post },
        timings: line.timings,
        aux,
        checks,
        hashes: line.hashes ?? null,
        ...(results ? { results } : {}),
        env,
      };
      appendJsonl(runsFile, rec);
      const t = Object.entries(line.timings).map(([k, v]) => `${k.replace(/Ms$/, "")} ${v.toFixed(1)}`).join(" ");
      console.log(
        `[cmp-cold] slot ${slot.slot + 1}/${schedule.length} ${slot.condition}: ${rec.status} ${t} ms (idle ${idleRec.idleSec} s, wall ${idleRec.idleWallSec} s, max wake-up gap ${idleRec.idleMaxTickGapSec} s${idleRec.hostPauseSuspected ? ", HOST PAUSE SUSPECTED" : ""})`
      );
      if (post.ac) break;
      console.log(`[cmp-cold] slot ${slot.slot}: power left AC during the run (code ${post.code}); discarded, repeating after a full idle`);
    }
  }
  appendJsonl(runsFile, { type: "campaign-end", campaign, session, utc: utcNow(), complete: true });
  hold.release();
  console.log(`[cmp-cold] ${campaign} complete -> ${rel(runsFile)}`);
  process.exit(0);
}

const self = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (self.endsWith(path.join("harness", "v4", "cmp", "cold.ts"))) {
  main().catch((e: unknown) => {
    console.error(`[cmp-cold] ${sanitize(e instanceof Error ? e.message : String(e))}`);
    process.exit(1);
  });
}
