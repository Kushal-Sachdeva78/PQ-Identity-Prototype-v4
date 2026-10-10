import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { flag, opt, sanitize, sleep } from "../bench/lib.ts";
import { readPower } from "../bench/guard.ts";
import { acquireMarker, markerRoots, windowsRepoFromArgs, MarkerHeldError, type MarkerHandle, type MarkerKind, type MarkerRoot } from "../lib/markers.ts";
import { assertEthers, TRACE_EPOCH_UTC } from "../lib/rpc_trace.ts";
import { SEEDS } from "../lib/seeds.ts";
import { appendJsonl, errText, relRepo, targetDir, writeJsonFile } from "./io.ts";
import { baseEnvironment, compareSourcesWithE4 } from "./env.ts";
import { checkAffinity, DEFAULT_TOPOLOGY, environmentName, parseTopology, pinAllThreads, type AffinityCheck } from "./host.ts";
import { buildWorld, defaultAnvilPort, pregenerate, startTarget, type TargetName, type TargetNode, type TargetWorld } from "./target.ts";
import {
  FULL_GUARD,
  FULL_SIZES,
  SMOKE_GUARD,
  SMOKE_SIZES,
  SeriesStop,
  buildRoles,
  buildSchedule,
  equivalenceCheck,
  flushCurrentPass,
  runS1,
  runS2,
  runS3,
  runS4,
  runS5,
  type PinExpectation,
  type Roles,
  type RunSizes,
  type SeriesContext,
  type SeriesCounts,
} from "./series.ts";
import { PRESENTATION_VARIANTS, READSET_VARIANTS, READ_CLIENTS, CLIENTS } from "./variants.ts";

/**
 * Chain-read campaign runner, one target per process (docs/v4/CHAINREAD.md).
 *
 *   node --import tsx harness/v4/chainread/run.ts --target anvil|besu --campaign <name> [options]
 *
 * Timed run (writes results/v4/chainread/<campaign>/<target>/): needs --confirm-quiet (the
 * operator states: AC power, other applications closed, no other agent jobs; in WSL also the
 * Windows side idle), holds results/v4/bench/RUNNING through harness/v4/lib/markers.ts (D-034),
 * refuses while RUNNING or BUSY exists in any repository it checks, refuses when the code under
 * test differs from E4's recorded hashes, pins in WSL/Linux (harness CPU 0, Anvil CPU 1, Besu
 * JVMs 4-7) and settles 600 s before the first series. Any option that departs from
 * docs/v4/CHAINREAD.md (--no-pin, --allow-source-drift, a subset of --series, other sizes,
 * holders, settle or CPUs) needs --deviation "<text>", which env.json records; a dated entry in
 * the CHAINREAD.md Deviations list is written before such a run.
 * Markers: on the Windows host the repository's own results/v4/bench/RUNNING. In WSL the Windows
 * repository (--windows-repo <its /mnt/c path>, or PQID_WINDOWS_REPO) holds it and the clone is
 * checked but gets no copy (write mode explicit-only), because R0 runs the unchanged scale.ts in
 * the clone inside the same window and scale.ts refuses while the clone's own RUNNING exists.
 * Under a driver that holds the marker with `markers.ts run`, the runner uses that hold.
 * --smoke: tiny sizes, holds results/v4/BUSY (untimed CPU-heavy work, D-034; under a driver that
 * holds BUSY with `markers.ts run --kind BUSY` the runner uses that hold), output under
 * results/v4/chainread/_smoke/ (gitignored; never cited); pins only with --pin.
 *
 * Options: --series s1,s2,s3,s4,s5  --port <anvil port; D-034: 8770 WSL, 8771 Windows>
 *   --besu-rpc <url> (http://127.0.0.1:18545)  --windows-repo <path>  --pin | --no-pin
 *   --cpus "harness=0;anvil=1;besu=4-7"  --settle-sec <s>  --expect-anvil <x.y.z>
 *   --expect-node <x.y.z>  --holders <H> (4)  --p --passes --r1 --r3 --n2 (sizes)
 *   --deviation "<text>"  --allow-source-drift
 */

type SeriesName = "s1" | "s2" | "s3" | "s4" | "s5";
const ALL_SERIES: readonly SeriesName[] = ["s1", "s2", "s3", "s4", "s5"];
const RUNNER = "harness/v4/chainread/run.ts";

const log = (s: string) => console.log(sanitize(`[cr ${new Date().toISOString().slice(11, 19)}] ${s}`));

function intOpt(argv: string[], name: string, dflt: number): number {
  const v = opt(argv, name);
  if (v === undefined) return dflt;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`--${name} needs a non-negative integer`);
  return n;
}

async function main(argv: string[]): Promise<number> {
  assertEthers();
  const target = opt(argv, "target") as TargetName | undefined;
  const campaign = opt(argv, "campaign");
  if ((target !== "anvil" && target !== "besu") || !campaign) {
    console.error("usage: run.ts --target anvil|besu --campaign <name> [--smoke] [--confirm-quiet] [options]; see the file header");
    return 2;
  }
  const smoke = flag(argv, "smoke");
  const env = environmentName();
  const series = (opt(argv, "series") ?? ALL_SERIES.join(",")).split(",").map((s) => s.trim()) as SeriesName[];
  for (const s of series) if (!ALL_SERIES.includes(s)) throw new Error(`--series: unknown ${s}`);
  const base = smoke ? SMOKE_SIZES : FULL_SIZES;
  const sizes: RunSizes = {
    ...base,
    r1: intOpt(argv, "r1", base.r1),
    n2: intOpt(argv, "n2", base.n2),
    r3: intOpt(argv, "r3", base.r3),
    p: intOpt(argv, "p", base.p),
    passes: intOpt(argv, "passes", base.passes),
  };
  if (sizes.p < 1) throw new Error("--p must be at least 1");
  const guard = smoke ? SMOKE_GUARD : FULL_GUARD;
  const holders = intOpt(argv, "holders", 4);
  const settleSec = intOpt(argv, "settle-sec", smoke ? 2 : 600);
  const port = intOpt(argv, "port", defaultAnvilPort());
  const besuRpc = opt(argv, "besu-rpc") ?? "http://127.0.0.1:18545";
  const expectAnvil = opt(argv, "expect-anvil") ?? null;
  const expectNode = opt(argv, "expect-node") ?? null;
  const windowsRepo = windowsRepoFromArgs(argv);
  const topology = parseTopology(opt(argv, "cpus"));
  if (flag(argv, "pin") && flag(argv, "no-pin")) throw new Error("--pin and --no-pin together");
  const pin = env !== "windows" && (smoke ? flag(argv, "pin") : !flag(argv, "no-pin"));
  if (env === "windows" && flag(argv, "pin")) throw new Error("no pinning on the Windows host (DECISIONS D-021)");
  const confirmQuiet = flag(argv, "confirm-quiet");
  if (!smoke && !confirmQuiet) {
    throw new Error(
      "a timed run needs --confirm-quiet: the operator states that the laptop is on AC power, other applications are closed (Windows timer resolution can be raised by other programs), no other agent jobs or chain nodes run, and in WSL that the Windows side is idle (D-034)"
    );
  }
  if (expectNode && process.version !== `v${expectNode}`) throw new Error(`Node ${process.version} is not the expected v${expectNode} (D-034 toolchain)`);
  const allowSourceDrift = flag(argv, "allow-source-drift");
  const departures = protocolDepartures({ smoke, pin, env, series, sizes, holders, settleSec, cpus: opt(argv, "cpus"), allowSourceDrift });
  const deviationText = opt(argv, "deviation")?.trim() || null;
  if (!smoke && departures.length > 0 && !deviationText) {
    throw new Error(
      `a timed run departs from docs/v4/CHAINREAD.md (${departures.join("; ")}): pass --deviation "<text>" (recorded in env.json) after adding a dated entry to the CHAINREAD.md Deviations list`
    );
  }

  // markers (D-034): a timed run holds RUNNING, a smoke run (untimed, CPU-heavy) holds BUSY
  const roots: MarkerRoot[] = markerRoots({ ...(windowsRepo !== undefined ? { windowsRepo } : {}), ...(smoke ? { allowLocalOnlyInWsl: true } : {}) });
  const explicit = roots.some((r) => r.via === "explicit");
  const markerKind: MarkerKind = smoke ? "BUSY" : "RUNNING";
  const markerRel = smoke ? "results/v4/BUSY" : "results/v4/bench/RUNNING";
  const markerBasis = explicit
    ? `${markerRel} written in the Windows repository through its explicit path; the local clone is checked and gets no copy (R0's unchanged scale.ts refuses while the clone's own results/v4/bench/RUNNING exists)`
    : `${markerRel} of this repository`;
  const marker: MarkerHandle = acquireMarker({
    kind: markerKind,
    campaign,
    runner: RUNNER,
    owner: "operator",
    note: `chain-read ${target}${smoke ? " smoke" : ""}`,
    roots,
    write: explicit ? "explicit-only" : "all",
  });

  const dir = targetDir(campaign, target, smoke);
  if (!smoke && fs.existsSync(path.join(dir, "env.json"))) throw new Error(`${relRepo(dir)}/env.json exists: a timed run never overwrites; use a new campaign name`);
  if (smoke) fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });

  const src = compareSourcesWithE4();
  if (!smoke && !src.vsE4.equal && !allowSourceDrift) {
    marker.release();
    throw new Error(`the code under test differs from E4's recorded hashes (${[...src.vsE4.differing, ...src.vsE4.missingInE4].join(", ")}); pass --allow-source-drift with --deviation to run anyway (recorded)`);
  }

  const envRec: Record<string, unknown> = {
    schema: "pqid/v4-chainread-env/v1",
    campaign,
    target,
    smoke,
    label: smoke ? "SMOKE: script check with tiny sizes on a busy machine. Not a result; never cited." : "[M] measured unless a field says [S] or [A]",
    startedUtc: new Date().toISOString(),
    status: "running",
    ...baseEnvironment(),
    sourceSha256: src.sourceSha256,
    sourceVsE4: src.vsE4,
    allowSourceDrift,
    deviation: { text: deviationText, departures, rule: "a timed run that departs from docs/v4/CHAINREAD.md needs --deviation and a dated entry in its Deviations list" },
    options: { series, sizes, guard, holders, settleSec, port, besuRpc, expectAnvil, expectNode, pin, topology: pin ? topology : null, windowsRepoGiven: windowsRepo !== undefined },
    conditions: {
      operatorConfirmedQuiet: confirmQuiet,
      statement: "--confirm-quiet: AC power, other applications closed, no other agent jobs or chain nodes, Windows side idle during a WSL window (operator statement; Windows processes are not read, docs/BENCHMARK_POLICY.md)",
      powerAtStart: readPower(),
    },
    marker: {
      held: true,
      kind: marker.kind,
      borrowed: marker.borrowed,
      holder: { campaign: marker.record.campaign, runner: marker.record.runner, pidNamespace: marker.record.pidNamespace },
      borrowedBy: marker.borrowedBy ?? null,
      copies: marker.copies,
      checked: roots.map((r) => r.via),
      basis: markerBasis,
      startedUtc: marker.record.startedUtc,
    },
    traceEpochUtc: TRACE_EPOCH_UTC,
    variants: {
      clients: Object.fromEntries(Object.entries(CLIENTS).map(([k, v]) => [k, { label: v.label, options: v.options, description: v.description }])),
      presentation: PRESENTATION_VARIANTS,
      readClients: READ_CLIENTS,
      readSets: READSET_VARIANTS,
    },
  };
  const envFile = path.join(dir, "env.json");
  writeJsonFile(envFile, envRec);

  let tn: TargetNode | null = null;
  let tw: TargetWorld | null = null;
  let roles: Roles | null = null;
  const counts: Record<string, SeriesCounts> = {};
  let status = "completed";
  let stopReason: string | null = null;
  // Stop our own Anvil on exit or on a signal. Registered after acquireMarker, so on a signal the
  // marker is released first and this still runs before the exit (harness/v4/lib/markers.ts).
  const stopNode = () => tn?.anvil?.stop();
  process.on("exit", stopNode);
  const signals = ["SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"] as const;
  const onSignal = (sig: string) => {
    // keep what the pass in progress measured (status "stopped") and say why the run ended
    try {
      flushCurrentPass(`signal ${sig}`);
      envRec["status"] = "interrupted";
      envRec["stopReason"] = `signal ${sig}`;
      envRec["finishedUtc"] = new Date().toISOString();
      envRec["counts"] = counts;
      writeJsonFile(envFile, envRec);
    } catch {
      /* best effort on the way out */
    }
    stopNode();
    setImmediate(() => process.exit(130));
  };
  for (const sig of signals) process.on(sig, onSignal);
  try {
    log(`target ${target}: ${target === "anvil" ? `starting Anvil on 127.0.0.1:${port}` : "attaching to Besu QBFT"}`);
    tn = await startTarget(target, { port, besuRpc, expectAnvil });
    log(`node ${tn.clientVersion} (${tn.endpoint})`);
    tw = await buildWorld(tn.url, holders, log);
    log(`world ready in ${tw.setupMs} ms (chain id ${tw.chainId}); pre-generating ${sizes.p} presentations (proving untimed, unpinned)`);
    const pre = await pregenerate(tw, sizes.p, log);
    roles = await buildRoles(tn, tw);
    const eq = await equivalenceCheck(tn, tw, pre, roles, log);
    writeJsonFile(path.join(dir, "equivalence.json"), {
      schema: "pqid/v4-chainread-equivalence/v1",
      rule: "as-shipped variant A gives the references (decision and check vector; wallet outputs per holder; JSON-RPC multiset without eth_chainId); every other variant must match them with drained prefetch queues and no unplanned read; multicall must aggregate",
      rows: eq.rows,
      references: {
        verifierRequests: eq.refs.verifierRequests.length,
        verifierReadKeys: [...eq.refs.verifierReads.entries()].map(([k, n]) => ({ n, method: k.split(" ")[0] })),
        walletReadKeys: [...eq.refs.walletReads.entries()].map(([k, n]) => ({ n, method: k.split(" ")[0] })),
      },
    });
    if (eq.rows.some((r) => !r.ok)) throw new SeriesStop("equivalence pre-check failed (equivalence.json); no timing was taken");

    // pinning (after the unpinned pre-generation; E4's pin-at-launch is replicated by R0)
    let pins: PinExpectation[] | null = null;
    let readBack: AffinityCheck[] | null = null;
    if (pin) {
      pins = [{ pid: process.pid, role: "harness", cpus: topology.harness }];
      if (tn.anvil?.proc.pid) pins.push({ pid: tn.anvil.proc.pid, role: "anvil", cpus: topology.anvil });
      if (target === "besu") {
        if (tn.ownPids.length !== 4) throw new SeriesStop(`expected 4 Besu pids from the setup_qbft.sh pid files, found ${tn.ownPids.length}`);
        tn.ownPids.forEach((p, i) => pins?.push({ pid: p, role: `besu-node-${i + 1}`, cpus: topology.besu }));
      }
      for (const p of pins) pinAllThreads(p.pid, p.cpus);
      readBack = pins.map((p) => checkAffinity(p.pid, p.role, p.cpus));
      const bad = readBack.filter((r) => !r.ok);
      if (bad.length > 0) throw new SeriesStop(`pinning read-back mismatch: ${JSON.stringify(bad).slice(0, 500)}`);
      log(`pinned: ${pins.map((p) => `${p.role} -> CPU ${p.cpus}`).join(", ")}; every thread read back`);
    }

    const schedule = buildSchedule(sizes);
    writeJsonFile(path.join(dir, "schedule.json"), schedule);
    Object.assign(envRec, {
      target: { name: tn.name, url: tn.url, endpoint: tn.endpoint, clientVersion: tn.clientVersion, chainId: tw.chainId, evm: tn.evm, besuPidFiles: tn.besuPidFiles, ownPorts: tn.ownPorts },
      clients: roles.describe(),
      workload: {
        holders,
        presentations: sizes.p,
        policy: "age_gte 18, default credential type",
        helper: tw.helper,
        registries: tw.registries,
        fromBlock: tw.fromBlock,
        setupMs: tw.setupMs,
        pregenerationMs: pre.pregenMs,
        pregeneration: "unpinned, all cores, untimed (snarkjs Groth16 with the v4 dev key)",
      },
      pinning: pin
        ? { pinned: true, method: "taskset -a -cp <cpus> <pid> after the unpinned pre-generation; /proc/<pid>/task/*/status read back for every thread, before every pass", topology, readBack, note: "[A] WSL2 vCPUs are not fixed physical cores: Hyper-V places them on P or E cores" }
        : { pinned: false, method: env === "windows" ? "none: Windows host, unpinned (D-021)" : "none (--no-pin or smoke)" },
      seedsUsed: { ...SEEDS.chainRead, bootstrap: SEEDS.analysis.bootstrap },
    });
    writeJsonFile(envFile, envRec);

    const settle = { requestedSec: settleSec, startedUtc: new Date().toISOString(), finishedUtc: "", actualSec: 0, powerAfter: null as unknown };
    log(`settle ${settleSec} s (nothing runs)`);
    const s0 = Date.now();
    await sleep(settleSec * 1000);
    settle.finishedUtc = new Date().toISOString();
    settle.actualSec = (Date.now() - s0) / 1000;
    settle.powerAfter = readPower();
    envRec["settle"] = settle;
    writeJsonFile(envFile, envRec);

    const ctx: SeriesContext = { dir, targetNode: tn, tw, pre, sizes, guard, schedule, refs: eq.refs, pins, log };
    for (const s of series) {
      log(`${s}: start`);
      const t0 = Date.now();
      switch (s) {
        case "s1":
          counts[s] = await runS1(ctx);
          break;
        case "s2":
          counts[s] = await runS2(ctx);
          break;
        case "s3":
          counts[s] = await runS3(ctx);
          break;
        case "s4":
          counts[s] = await runS4(ctx, roles);
          break;
        case "s5":
          counts[s] = await runS5(ctx, roles);
          break;
      }
      const c = counts[s];
      log(`${s}: done in ${((Date.now() - t0) / 1000).toFixed(0)} s (${c?.samples ?? 0} samples, ${c?.errors ?? 0} errors; discarded ${c?.discardedSamples ?? 0} samples, ${c?.discardedErrors ?? 0} errors)`);
    }
  } catch (e) {
    status = e instanceof SeriesStop ? "stopped" : "failed";
    stopReason = errText(e);
    log(`${status}: ${stopReason}`);
    appendJsonl(path.join(dir, "errors.jsonl"), { fatal: true, status, reason: stopReason, utc: new Date().toISOString() });
  } finally {
    roles?.close();
    tw?.world.stop();
    stopNode();
    for (const sig of signals) process.off(sig, onSignal);
    process.off("exit", stopNode);
    envRec["status"] = status;
    envRec["stopReason"] = stopReason;
    envRec["finishedUtc"] = new Date().toISOString();
    envRec["counts"] = counts;
    envRec["powerAtEnd"] = readPower();
    writeJsonFile(envFile, envRec);
    marker.release();
  }
  log(`${status}: ${relRepo(dir)}`);
  return status === "completed" ? 0 : 1;
}

/**
 * The options of this run that depart from docs/v4/CHAINREAD.md (empty for a protocol run).
 * A timed run with any of them needs --deviation.
 */
export function protocolDepartures(o: {
  smoke: boolean;
  pin: boolean;
  env: string;
  series: readonly string[];
  sizes: RunSizes;
  holders: number;
  settleSec: number;
  cpus: string | undefined;
  allowSourceDrift: boolean;
}): string[] {
  if (o.smoke) return [];
  const out: string[] = [];
  if (o.env !== "windows" && !o.pin) out.push("not pinned (--no-pin)");
  if (o.allowSourceDrift) out.push("code under test differs from E4 (--allow-source-drift)");
  if (o.series.join(",") !== ALL_SERIES.join(",")) out.push(`series ${o.series.join(",")} instead of ${ALL_SERIES.join(",")}`);
  for (const k of Object.keys(FULL_SIZES) as Array<keyof RunSizes>) if (o.sizes[k] !== FULL_SIZES[k]) out.push(`size ${k} ${o.sizes[k]} instead of ${FULL_SIZES[k]}`);
  if (o.holders !== 4) out.push(`holders ${o.holders} instead of 4`);
  if (o.settleSec !== 600) out.push(`settle ${o.settleSec} s instead of 600 s`);
  if (o.cpus !== undefined && JSON.stringify(parseTopology(o.cpus)) !== JSON.stringify(DEFAULT_TOPOLOGY)) out.push(`CPU topology ${o.cpus}`);
  return out;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e: unknown) => {
      console.error(sanitize(`[cr] FAILED: ${e instanceof Error ? e.message : String(e)}`));
      process.exit(e instanceof MarkerHeldError ? 3 : 1);
    }
  );
}
