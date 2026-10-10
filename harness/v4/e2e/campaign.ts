import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import type { PowerReading } from "../bench/guard.ts";
import {
  REPO_ROOT,
  appendJsonl,
  envInfo,
  flag,
  gitHead,
  opt,
  optNum,
  rapidsnarkState,
  readJsonl,
  sha256FileHex,
  snarkjsVersion,
  tsxImportUrl,
  utcNow,
  writeJson,
  type Slot,
} from "../bench/lib.ts";
import { acquireMarker, assertMarkersFree, markerRoots, type MarkerHandle } from "../lib/markers.ts";
import { readQuiesceExcluding, readPidFiles, type QuiesceRecord } from "../lib/quiesce.ts";
import { AS_SHIPPED_OPTIONS, ROUND_TRIP_DEFINITION } from "../lib/rpc_trace.ts";
import {
  BESU_RPC_PORTS,
  E2E_ANVIL_PORT,
  E2E_BOOTSTRAP_SEED,
  E2E_SEED,
  E2E_SEED_ID,
  IDLE_PAUSE_THRESHOLD_SEC,
  RUN_PAUSE_THRESHOLD_SEC,
  SCHEMA,
  STAGES,
  STREAM_SEED_RULE,
  campaignConditions,
  classifyUrl,
  clockGap,
  codeHashes,
  crossesBlackout,
  deviceRecord,
  loadKeySpec,
  runKeyOf,
  e2eSchedule,
  environmentName,
  findSecrets,
  idleFields,
  median,
  midnightBlackout,
  packageVersion,
  parseCondition,
  parseMsgLines,
  readPowerE2e,
  protocolRecord,
  readClocks,
  redactSecrets,
  relOf,
  resolveRoot,
  resolveRpcArg,
  resultsRootRefusal,
  runLabels,
  secretNeedles,
  urlNeedles,
  type ClockReading,
  type EndpointKind,
  type Mode,
  type PowerRule,
  type SecretNeedle,
} from "./lib.ts";
import { SetupFailed, endpointRecord, rpc, setupCustom, setupLocal, type E2eSetup, type EndpointRecord, type SweepTransfer } from "./setup.ts";

/**
 * End-to-end presentation series, orchestrator (docs/v4/E2E.md).
 *
 *   node --import tsx harness/v4/e2e/campaign.ts --mode cold --campaign e2e_cold_wsl --endpoints anvil,besu \
 *        [--windows-repo /mnt/c/.../PQ-Identity-v4] [--anvil-bin PATH] [--key-spec FILE | --allow-dev-key]
 *        [--device-label TEXT] [--results-root DIR] [--smoke]
 *   node --import tsx harness/v4/e2e/campaign.ts --mode warm --campaign e2e_warm_wsl --endpoints anvil,besu ...
 *   custom endpoint (public testnet; Kushal only, interactive terminal): --endpoints custom --endpoint-label L
 *        --expect-chain-id N --max-fee-gwei X --max-total-eth Y --confirm-public-testnet
 *        [--rpc env:NAME | --rpc <url without path or query> | --rpc-env PQID_E2E_RPC_URL] [--funder-env PQID_E2E_FUNDER_KEY]
 *
 * Holds results/v4/bench/RUNNING (D-034; a WSL runner also in the Windows repository through
 * --windows-repo) for a real series, or uses the marker a wrapping `markers.ts run` holds; a
 * smoke run holds no marker but refuses while one exists, and writes only under
 * <results root>/_smoke/.
 */

const CHILD_SCRIPT = path.join(REPO_ROOT, "harness", "v4", "e2e", "child_present.ts");
const MAX_ERRORS_PER_SLOT = 3;
const MAX_CONSECUTIVE_NON_AC = 36;
const REANCHOR_MARGIN_SEC = 2 * 3600;
const RUNNER = "harness/v4/e2e/campaign.ts";

// ---------------------------------------------------------------------------------------
// interruptible sleep and signals
// ---------------------------------------------------------------------------------------

const stop = { requested: false, signal: "" as string, wakers: new Set<() => void>() };

function sleep(ms: number): Promise<void> {
  if (stop.requested || ms <= 0) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(t);
      stop.wakers.delete(done);
      resolve();
    };
    const t = setTimeout(done, ms);
    stop.wakers.add(done);
  });
}

function installSignals(log: (s: string) => void): void {
  for (const sig of ["SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"] as const) {
    process.on(sig, () => {
      if (stop.requested) {
        log(`[e2e] second ${sig}: exiting now`);
        process.exit(130);
      }
      stop.requested = true;
      stop.signal = sig;
      log(`[e2e] ${sig}: stopping after the current step (cleanup, sweep, marker release); send again to exit at once`);
      for (const w of [...stop.wakers]) w();
    });
  }
}

class Interrupted extends Error {
  constructor() {
    super(`interrupted by ${stop.signal}`);
  }
}

function checkStop(): void {
  if (stop.requested) throw new Interrupted();
}

// ---------------------------------------------------------------------------------------
// options
// ---------------------------------------------------------------------------------------

interface Options {
  mode: Mode;
  campaign: string;
  endpoints: EndpointKind[];
  smoke: boolean;
  n: number;
  warmup: number;
  idleSec: number;
  leadSec: number;
  settleSec: number;
  blockGapSec: number;
  maxPostpone: number;
  postponeStepSec: number;
  childTimeoutSec: number;
  resultsRoot: string | undefined;
  windowsRepo: string | undefined;
  deviceLabel: string | null;
  prover: "snarkjs" | "rapidsnark";
  anvilBin: string | undefined;
  expectAnvil: string;
  expectNode: string;
  besuPort: number;
  powerRule: PowerRule;
  allowDevKey: boolean;
  custom: {
    rpcArg: string | undefined;
    rpcEnv: string;
    funderEnv: string;
    label: string | undefined;
    expectChainId: number | undefined;
    maxFeeGwei: number | undefined;
    maxTotalEth: number | undefined;
    finality: "finalized" | "latest";
    finalityTimeoutSec: number;
    txTimeoutSec: number;
    writesTimeoutSec: number;
    sweep: boolean;
    allowHttp: boolean;
    confirmPublic: boolean;
  };
}

function parseOptions(argv: string[]): Options {
  const smoke = flag(argv, "smoke");
  const mode = opt(argv, "mode") as Mode | undefined;
  if (mode !== "cold" && mode !== "warm") throw new Error("--mode cold|warm required");
  const campaign = opt(argv, "campaign");
  if (!campaign || !/^[a-z0-9_]+$/.test(campaign)) throw new Error("--campaign <name> required ([a-z0-9_])");
  const eps = (opt(argv, "endpoints") ?? "").split(",").map((s) => s.trim()).filter(Boolean) as EndpointKind[];
  if (eps.length === 0) throw new Error("--endpoints anvil,besu[,custom] required");
  for (const e of eps) if (!["anvil", "besu", "custom"].includes(e)) throw new Error(`unknown endpoint ${e}`);
  if (new Set(eps).size !== eps.length) throw new Error("--endpoints lists an endpoint twice");
  const prover = (opt(argv, "prover") ?? "snarkjs") as Options["prover"];
  if (prover !== "snarkjs" && prover !== "rapidsnark") throw new Error("--prover snarkjs|rapidsnark");
  if (opt(argv, "rpc-url") !== undefined) throw new Error("use --rpc env:NAME (or --rpc-env NAME); see docs/v4/A4_TESTNET.md");
  const rpcArg = opt(argv, "rpc");
  if (rpcArg !== undefined && !eps.includes("custom")) throw new Error("--rpc is the custom endpoint's URL: use it with --endpoints custom");
  if (opt(argv, "client") !== undefined || flag(argv, "client")) throw new Error("this series measures only the shipped client (LedgerV4 as shipped, D-034); there is no --client option");
  const num = (name: string): number | undefined => {
    const v = opt(argv, name);
    if (v === undefined) return undefined;
    const x = Number(v);
    if (!Number.isFinite(x)) throw new Error(`--${name} must be a number`);
    return x;
  };
  const finality = (opt(argv, "custom-finality") ?? "finalized") as "finalized" | "latest";
  if (finality !== "finalized" && finality !== "latest") throw new Error("--custom-finality finalized|latest");
  const o: Options = {
    mode,
    campaign,
    endpoints: eps,
    smoke,
    n: optNum(argv, "n", smoke ? (mode === "cold" ? 2 : 3) : 30),
    warmup: optNum(argv, "warmup", smoke ? 1 : 5),
    idleSec: optNum(argv, "idle", smoke ? 5 : 600),
    leadSec: optNum(argv, "lead", smoke ? 2 : 20),
    settleSec: optNum(argv, "settle", smoke ? 5 : 600),
    blockGapSec: optNum(argv, "block-gap", 2),
    maxPostpone: optNum(argv, "max-postpone", smoke ? 0 : 10),
    postponeStepSec: optNum(argv, "postpone-step", 60),
    childTimeoutSec: optNum(argv, "child-timeout", 300),
    resultsRoot: opt(argv, "results-root"),
    windowsRepo: opt(argv, "windows-repo"),
    deviceLabel: opt(argv, "device-label") ?? null,
    prover,
    anvilBin: opt(argv, "anvil-bin"),
    expectAnvil: opt(argv, "expect-anvil") ?? (smoke ? "any" : "1.5.1"),
    expectNode: opt(argv, "expect-node") ?? "auto",
    besuPort: optNum(argv, "besu-port", BESU_RPC_PORTS[0] as number),
    powerRule: (opt(argv, "power-rule") ?? "ac") as PowerRule,
    allowDevKey: flag(argv, "allow-dev-key"),
    custom: {
      rpcArg,
      rpcEnv: opt(argv, "rpc-env") ?? "PQID_E2E_RPC_URL",
      funderEnv: opt(argv, "funder-env") ?? "PQID_E2E_FUNDER_KEY",
      label: opt(argv, "endpoint-label"),
      expectChainId: num("expect-chain-id"),
      maxFeeGwei: num("max-fee-gwei"),
      maxTotalEth: num("max-total-eth"),
      finality,
      finalityTimeoutSec: optNum(argv, "finality-timeout", 1800),
      txTimeoutSec: optNum(argv, "tx-timeout", 600),
      writesTimeoutSec: optNum(argv, "writes-timeout", 1800),
      sweep: !flag(argv, "no-sweep"),
      allowHttp: flag(argv, "allow-http-custom"),
      confirmPublic: flag(argv, "confirm-public-testnet"),
    },
  };
  o.leadSec = Math.min(o.leadSec, o.idleSec);
  if (o.powerRule !== "ac" && o.powerRule !== "record-only") throw new Error("--power-rule ac|record-only");
  if (!Number.isInteger(o.n) || o.n < 1) throw new Error("--n must be a positive integer");
  if (!smoke && o.n < 30) console.log(`[e2e] WARNING: n=${o.n} < 30 (the protocol requires 30)`);
  return o;
}

// ---------------------------------------------------------------------------------------
// processes
// ---------------------------------------------------------------------------------------

function whichOnPath(name: string): string | null {
  const exts = process.platform === "win32" ? [".exe", ".cmd", ""] : [""];
  for (const dir of (process.env["PATH"] ?? "").split(path.delimiter)) {
    for (const ext of exts) {
      const f = path.join(dir, name + ext);
      try {
        if (fs.statSync(f).isFile()) return f;
      } catch {
        /* next */
      }
    }
  }
  return null;
}

async function assertPortFree(port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", (e: NodeJS.ErrnoException) => reject(new Error(`127.0.0.1:${port} is in use (${e.code ?? e.message}); this series binds only its own D-034 port ${E2E_ANVIL_PORT}`)));
    srv.listen(port, "127.0.0.1", () => srv.close(() => resolve()));
  });
}

interface AnvilProc {
  proc: ChildProcess;
  url: string;
  tool: Record<string, unknown>;
}

async function startAnvil(o: Options, log: (s: string) => void): Promise<AnvilProc> {
  const bin = o.anvilBin ? path.resolve(o.anvilBin) : process.platform === "win32" ? path.join(REPO_ROOT, "tools", "foundry", "anvil.exe") : whichOnPath("anvil");
  if (!bin || !fs.existsSync(bin)) throw new Error("anvil binary not found (pass --anvil-bin; D-034: Anvil 1.5.1 from the pqid-v4 Docker image in WSL)");
  const v = spawnSync(bin, ["--version"], { encoding: "utf8", windowsHide: true, shell: false });
  const versionLine = (v.stdout ?? "").split(/\r?\n/)[0]?.trim() ?? "";
  if (o.expectAnvil !== "any" && !versionLine.includes(o.expectAnvil)) throw new Error(`anvil reports '${versionLine}', expected ${o.expectAnvil} (D-034 toolchain; --expect-anvil any only for smoke runs)`);
  await assertPortFree(E2E_ANVIL_PORT);
  const proc = spawn(bin, ["--host", "127.0.0.1", "--port", String(E2E_ANVIL_PORT), "--silent"], { stdio: ["ignore", "ignore", "pipe"], windowsHide: true, shell: false });
  proc.stderr?.resume();
  const url = `http://127.0.0.1:${E2E_ANVIL_PORT}`;
  const deadline = Date.now() + 30_000;
  for (;;) {
    try {
      const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }) });
      if (res.ok) break;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline || proc.exitCode !== null) {
      proc.kill();
      throw new Error("anvil did not answer within 30 s");
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  log(`[e2e] anvil up on 127.0.0.1:${E2E_ANVIL_PORT} (${versionLine}, pid ${proc.pid})`);
  return { proc, url, tool: { name: "anvil", versionLine, binarySha256: sha256FileHex(bin), binaryName: path.basename(bin), pid: proc.pid ?? null, host: "127.0.0.1", port: E2E_ANVIL_PORT, mining: "automine" } };
}

interface ChildOutcome {
  code: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  wallMs: number;
  timedOut: boolean;
}

function childEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  return env;
}

/** One cold child: init message on stdin (the state document), one result line out. */
function runColdChild(init: unknown, timeoutMs: number): Promise<ChildOutcome> {
  return new Promise((resolve, reject) => {
    const t0 = performance.now();
    const child = spawn(process.execPath, ["--import", tsxImportUrl(), CHILD_SCRIPT], { cwd: REPO_ROOT, env: childEnv(), stdio: ["pipe", "pipe", "pipe"], windowsHide: true, shell: false });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    child.stdout.setEncoding("utf8").on("data", (d: string) => (stdout += d));
    child.stderr.setEncoding("utf8").on("data", (d: string) => (stderr = (stderr + d).slice(-20_000)));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr, wallMs: performance.now() - t0, timedOut });
    });
    child.stdin.on("error", () => undefined);
    child.stdin.end(JSON.stringify(init) + "\n");
  });
}

/** The warm child: one long-lived process, commands on stdin, messages on stdout. */
class WarmChild {
  readonly proc: ChildProcess;
  private buf = "";
  private queue: Array<Record<string, unknown>> = [];
  private waiters: Array<(m: Record<string, unknown> | null) => void> = [];
  stderr = "";
  exited = false;

  constructor(init: unknown) {
    this.proc = spawn(process.execPath, ["--import", tsxImportUrl(), CHILD_SCRIPT], { cwd: REPO_ROOT, env: childEnv(), stdio: ["pipe", "pipe", "pipe"], windowsHide: true, shell: false });
    this.proc.stdout?.setEncoding("utf8").on("data", (d: string) => {
      this.buf += d;
      let i: number;
      while ((i = this.buf.indexOf("\n")) >= 0) {
        const line = this.buf.slice(0, i);
        this.buf = this.buf.slice(i + 1);
        for (const m of parseMsgLines(line)) this.push(m);
      }
    });
    this.proc.stderr?.setEncoding("utf8").on("data", (d: string) => (this.stderr = (this.stderr + d).slice(-20_000)));
    this.proc.on("close", () => {
      this.exited = true;
      for (const w of this.waiters.splice(0)) w(null);
    });
    this.proc.stdin?.on("error", () => undefined);
    this.proc.stdin?.write(JSON.stringify(init) + "\n");
  }

  private push(m: Record<string, unknown>): void {
    const w = this.waiters.shift();
    if (w) w(m);
    else this.queue.push(m);
  }

  next(timeoutMs: number): Promise<Record<string, unknown> | null> {
    const m = this.queue.shift();
    if (m) return Promise.resolve(m);
    if (this.exited) return Promise.resolve(null);
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        const i = this.waiters.indexOf(done);
        if (i >= 0) this.waiters.splice(i, 1);
        resolve(null);
      }, timeoutMs);
      const done = (x: Record<string, unknown> | null) => {
        clearTimeout(timer);
        resolve(x);
      };
      this.waiters.push(done);
    });
  }

  send(cmd: unknown): void {
    this.proc.stdin?.write(JSON.stringify(cmd) + "\n");
  }

  async close(): Promise<void> {
    if (this.exited) return;
    this.send({ type: "exit" });
    await this.next(30_000);
    if (!this.exited) this.proc.kill();
  }
}

// ---------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------

interface Endpoint {
  kind: EndpointKind;
  url: string;
  record: EndpointRecord;
  ownPids: number[];
  ownPorts: number[];
  setup: E2eSetup | null;
}

function nodeExpectation(o: Options, env: string): string {
  if (o.expectNode !== "auto") return o.expectNode;
  return env === "wsl2" && !o.smoke ? "24.21.0" : "any";
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const o = parseOptions(argv);
  const log = (s: string) => console.log(s);
  installSignals(log);

  // ---- device and toolchain guards
  const device = deviceRecord(o.deviceLabel);
  const envName = environmentName(device);
  if (device.emulationSuspected && !o.smoke) throw new Error(`emulation suspected (process arch ${device.arch}, CPU '${device.cpuModel}'): emulated runs are never device measurements (E2E.md rule 11); only --smoke is allowed`);
  if (device.arch !== "x64" && !o.deviceLabel && !o.smoke) throw new Error(`a ${device.arch} run needs --device-label (the emulation check is a heuristic)`);
  if (o.powerRule === "record-only" && !o.deviceLabel && !o.smoke) throw new Error("--power-rule record-only is for device campaigns (with --device-label); the laptop series uses the AC rule");
  // One environment per results root (E2E.md section 2): results/v4/e2e/ is the WSL2 root, by
  // default or named with --results-root; any other environment (a device, a Linux host) names
  // its own root. Windows runs are smoke runs.
  const rootRefusal = resultsRootRefusal(o.resultsRoot, o.smoke, envName);
  if (rootRefusal) throw new Error(rootRefusal);
  const wantNode = nodeExpectation(o, envName);
  if (wantNode !== "any" && process.version !== `v${wantNode}`) throw new Error(`Node ${process.version} is not the pinned ${wantNode} (D-034: one WSL toolchain, Node 24.21.0 by its absolute nvm path)`);

  // ---- protocol and artifacts (refuses when the protocol document is missing)
  const protocol = protocolRecord();
  const key = loadKeySpec(opt(argv, "key-spec"));
  const artifacts = key.artifacts;
  const runKey = runKeyOf(key.spec);
  // D-034: the end-to-end campaigns run after the key ceremony, with the ceremony key. A real
  // run with the dev key is allowed only on request, and every record then says "dev key".
  if (key.spec.label === "dev" && !o.smoke && !o.allowDevKey) {
    throw new Error("the dev key is the default, but D-034 runs this series with the ceremony key: pass --key-spec <repo-relative key spec> (or --allow-dev-key for a run labelled 'dev key' that is repeated after the ceremony)");
  }
  const rs = o.prover === "rapidsnark" ? rapidsnarkState() : null;
  if (o.prover === "rapidsnark" && !rs?.available) throw new Error("--prover rapidsnark needs PQID_RAPIDSNARK (WSL only)");

  // ---- markers (D-034): a real series holds RUNNING (or uses the hold of a wrapping
  // `markers.ts run`); a smoke run holds none and refuses while one exists
  const roots = markerRoots({ ...(o.windowsRepo ? { windowsRepo: o.windowsRepo } : {}), ...(o.smoke ? { allowLocalOnlyInWsl: true } : {}) });
  let marker: MarkerHandle | null = null;
  if (o.smoke) assertMarkersFree(roots, "RUNNING");
  else marker = acquireMarker({ kind: "RUNNING", campaign: o.campaign, runner: RUNNER, owner: o.endpoints.includes("custom") ? "Kushal" : "operator", roots, exitOnSignal: false });
  const markerRecord = marker
    ? {
        kind: marker.kind,
        copies: marker.copies,
        borrowed: marker.borrowed,
        heldBy: { campaign: marker.record.campaign, runner: marker.record.runner, startedUtc: marker.record.startedUtc, pidNamespace: marker.record.pidNamespace },
        borrowedBy: marker.borrowedBy ?? null,
      }
    : { kind: null, note: "smoke run: no marker held (refused while one existed)" };

  // ---- custom endpoint secrets: read once from the environment, removed from it at once
  let customUrl: string | null = null;
  let customUrlSource: string | null = null;
  let funderKey: string | null = null;
  const globalNeedles: SecretNeedle[] = [];
  if (o.endpoints.includes("custom")) {
    const r = resolveRpcArg(o.custom.rpcArg, o.custom.rpcEnv, process.env);
    customUrl = r.url;
    customUrlSource = r.source;
    funderKey = process.env[o.custom.funderEnv]?.trim() || null;
    if (r.envName) delete process.env[r.envName];
    delete process.env[o.custom.funderEnv];
    if (!customUrl) throw new Error(`custom endpoint: no URL (${r.source} is empty)`);
    if (!funderKey || !/^(0x)?[0-9a-fA-F]{64}$/.test(funderKey)) throw new Error(`custom endpoint: environment variable ${o.custom.funderEnv} must hold a 32-byte hex key (a fresh test-only key)`);
    globalNeedles.push(...urlNeedles(customUrl), ...secretNeedles("funderKey", funderKey), ...secretNeedles("funderKeyNo0x", funderKey.replace(/^0x/, "")));
    if (!o.custom.label || !/^[A-Za-z0-9._-]{1,60}$/.test(o.custom.label)) throw new Error("custom endpoint: --endpoint-label <label> required ([A-Za-z0-9._-], no URL)");
    // every record carries these strings: they must not contain any part of the URL (host labels
    // included), or the secret scan would stop the campaign at its first record
    for (const [what, text] of [["--endpoint-label", o.custom.label], ["--campaign", o.campaign], ["--device-label", o.deviceLabel ?? ""]] as const) {
      const hits = findSecrets(text, globalNeedles);
      if (hits.length > 0) throw new Error(`${what} contains a part of the RPC URL (${hits.join(", ")}); choose a name without it`);
    }
    if (o.custom.expectChainId === undefined) throw new Error("custom endpoint: --expect-chain-id required");
    if (o.custom.maxFeeGwei === undefined || o.custom.maxTotalEth === undefined) throw new Error("custom endpoint: --max-fee-gwei and --max-total-eth required");
    const cls = classifyUrl(customUrl);
    if (cls.reach === "internet") {
      // operator never transacts on a public network (docs/BENCHMARK_POLICY.md): a public endpoint needs
      // https, an interactive terminal and an explicit confirmation flag (approval A4).
      if (cls.scheme !== "https") throw new Error("a custom endpoint on the internet must use https");
      if (!o.custom.confirmPublic || !process.stdin.isTTY) throw new Error("a public custom endpoint needs --confirm-public-testnet and an interactive terminal (approval A4: Kushal starts this run himself)");
      if (o.custom.finality !== "finalized") throw new Error("a public custom endpoint always waits for the 'finalized' block");
    } else if (cls.scheme !== "https" && !o.custom.allowHttp) {
      throw new Error(`custom endpoint on ${cls.reach === "lan" ? "the local network" : "loopback"} over http: pass --allow-http-custom`);
    }
  }

  const root = resolveRoot(o.resultsRoot, o.smoke);
  const dir = path.join(root, o.campaign);
  fs.mkdirSync(dir, { recursive: true });
  const files = { schedule: path.join(dir, "schedule.json"), env: path.join(dir, "env.json"), runs: path.join(dir, "runs.jsonl"), deployments: path.join(dir, "deployments.jsonl") };
  const session = utcNow();
  const endpoints: Endpoint[] = [];
  let anvil: AnvilProc | null = null;
  let warm: WarmChild | null = null;
  const killAnvil = () => anvil?.proc.kill();
  process.on("exit", killAnvil);

  const needles = (): SecretNeedle[] => [...globalNeedles, ...endpoints.flatMap((e) => (e.setup ? e.setup.needles() : []))];
  /** Append a record after the secret scan; a hit stops the campaign (the line is not written). */
  const writeRecord = (file: string, rec: Record<string, unknown>) => {
    const text = JSON.stringify(rec);
    const hits = findSecrets(text, needles());
    if (hits.length > 0) {
      appendJsonl(file, { type: "withheld", campaign: o.campaign, session, utc: utcNow(), slot: rec["slot"] ?? null, reason: `secret scan hit (${hits.join(", ")}): the line was not written` });
      throw new Error(`secret scan hit in a result line (${hits.join(", ")}); stopping`);
    }
    fs.appendFileSync(file, text + "\n");
  };
  /** As writeRecord, but a secret-scan hit writes only a "withheld" line and never throws (failure and clean-up paths). */
  const writeQuiet = (file: string, rec: Record<string, unknown>): boolean => {
    const text = JSON.stringify(rec);
    const hits = findSecrets(text, needles());
    if (hits.length > 0) {
      appendJsonl(file, { type: "withheld", campaign: o.campaign, session, utc: utcNow(), reason: `secret scan hit (${hits.join(", ")}): the ${String(rec["type"])} line was not written` });
      return false;
    }
    fs.appendFileSync(file, text + "\n");
    return true;
  };
  const redactTransfers = (sw: SweepTransfer[]): SweepTransfer[] => sw.map((s) => (s.note ? { ...s, note: redactSecrets(s.note, needles()) } : s));
  const sweepSummary = (sw: SweepTransfer[]): string => sw.map((s) => `${s.role} ${s.txHash ? "sent" : redactSecrets(s.note ?? "skipped", needles())}`).join(", ");

  let exitCode = 0;
  try {
    // ---- resume checks before any set-up (a set-up on a public testnet costs gas)
    const conditions = campaignConditions(o.mode, o.endpoints);
    const config = {
      campaign: o.campaign,
      mode: o.mode,
      smoke: o.smoke,
      endpoints: o.endpoints,
      customLabel: o.endpoints.includes("custom") ? o.custom.label : null,
      conditions,
      n: o.n,
      warmup: o.mode === "warm" ? o.warmup : 0,
      idleSec: o.idleSec,
      leadSec: o.leadSec,
      settleSec: o.mode === "warm" ? o.settleSec : null,
      blockGapSec: o.blockGapSec,
      maxPostpone: o.maxPostpone,
      postponeStepSec: o.postponeStepSec,
      prover: o.prover,
      childTimeoutSec: o.childTimeoutSec,
      powerRule: o.powerRule,
      keyLabel: key.spec.label,
      seedId: E2E_SEED_ID,
      seed: E2E_SEED,
    };
    const code = codeHashes();
    const keyLabel = key.spec.label;
    const stable = {
      protocolE2e: (protocol["e2e"] as { normativeSha256: string }).normativeSha256,
      protocolBench: (protocol["bench"] as { normativeSha256: string }).normativeSha256,
      key: { label: key.spec.label, source: key.source, wasm: key.spec.wasm, zkey: key.spec.zkey, vkey: key.spec.vkey },
      artifacts,
      sourceSha256: code.sourceSha256,
      prover: o.prover === "rapidsnark" ? { name: "rapidsnark", sha256: rs?.sha256 ?? null, basename: rs?.basename ?? null } : { name: "snarkjs", version: snarkjsVersion() },
    };
    if (fs.existsSync(files.schedule)) {
      const s = JSON.parse(fs.readFileSync(files.schedule, "utf8")) as { config: typeof config };
      if (JSON.stringify(s.config) !== JSON.stringify(config)) throw new Error(`${relOf(files.schedule)} exists with a different configuration; resume with the same flags or use a new --campaign`);
    }
    if (fs.existsSync(files.env)) {
      const e = JSON.parse(fs.readFileSync(files.env, "utf8")) as { stable: typeof stable };
      if (JSON.stringify(e.stable) !== JSON.stringify(stable)) throw new Error("protocol, artifacts, package sources or prover changed since this campaign started; use a new --campaign");
    }

    // ---- endpoints
    for (const kind of o.endpoints) {
      checkStop();
      if (kind === "anvil") {
        anvil = await startAnvil(o, log);
        const record = await endpointRecord("anvil", anvil.url, { tool: anvil.tool });
        endpoints.push({ kind, url: anvil.url, record, ownPids: anvil.proc.pid ? [anvil.proc.pid] : [], ownPorts: [E2E_ANVIL_PORT], setup: null });
      } else if (kind === "besu") {
        const url = `http://127.0.0.1:${o.besuPort}`;
        const client = String(await rpc(url, "web3_clientVersion").catch(() => ""));
        if (!client.toLowerCase().startsWith("besu/")) throw new Error(`no Besu node answers on ${url} (web3_clientVersion '${client}'); start it with scripts/besu/setup_qbft.sh up`);
        const pidFiles = [1, 2, 3, 4].map((i) => path.join(REPO_ROOT, ".scratch-v4", "besu", `node-${i}.pid`));
        const pids = readPidFiles(pidFiles).filter((p) => {
          try {
            process.kill(p, 0);
            return true;
          } catch {
            return false;
          }
        });
        if (pids.length !== 4 && !o.smoke) throw new Error(`Besu: ${pids.length} of 4 node pids alive from .scratch-v4/besu/node-*.pid; the series uses only a network started by scripts/besu/setup_qbft.sh in this checkout`);
        const record = await endpointRecord("besu", url, { tool: { name: "besu", client, nodesAlive: pids.length, setupScript: "scripts/besu/setup_qbft.sh" } });
        endpoints.push({ kind, url, record, ownPids: pids, ownPorts: [...BESU_RPC_PORTS], setup: null });
      } else {
        const url = customUrl as string;
        const record = await endpointRecord("custom", url, { label: o.custom.label as string, tool: null });
        if (record.chainId !== o.custom.expectChainId) throw new Error(`custom endpoint chain id ${record.chainId} is not --expect-chain-id ${o.custom.expectChainId}`);
        endpoints.push({ kind, url, record, ownPids: [], ownPorts: [], setup: null });
      }
    }

    // ---- set-up per endpoint (untimed)
    for (const ep of endpoints) {
      checkStop();
      const t = performance.now();
      log(`[e2e] set-up on ${ep.record.label} ...`);
      try {
        ep.setup =
          ep.kind === "custom"
            ? await setupCustom(ep.url, ep.record, {
                funderKey: funderKey as string,
                expectChainId: o.custom.expectChainId as number,
                maxFeeGwei: o.custom.maxFeeGwei as number,
                maxTotalEth: o.custom.maxTotalEth as number,
                finality: o.custom.finality,
                finalityTimeoutSec: o.custom.finalityTimeoutSec,
                txTimeoutSec: o.custom.txTimeoutSec,
                writesTimeoutSec: o.custom.writesTimeoutSec,
                campaign: o.campaign,
                session,
                log,
              })
            : await setupLocal(ep.url, ep.record, { campaign: o.campaign, session });
      } catch (e) {
        if (e instanceof SetupFailed) {
          // public facts of a failed custom set-up: what was sent, and the sweep of every funded role
          writeQuiet(files.deployments, { type: "setup-failed", schema: SCHEMA.deployment, setupId: e.setupId, campaign: o.campaign, session, utc: utcNow(), endpoint: ep.record, transactions: e.transactions, reason: redactSecrets(e.message, needles()) });
          if (e.partialSweep) {
            writeQuiet(files.deployments, { type: "sweep", partial: true, setupId: e.setupId, campaign: o.campaign, session, utc: utcNow(), transfers: redactTransfers(e.partialSweep) });
            log(`[e2e] partial sweep after the failed set-up: ${sweepSummary(e.partialSweep)}`);
          }
        }
        throw e;
      }
      writeRecord(files.deployments, ep.setup.deployment as unknown as Record<string, unknown>);
      log(`[e2e] set-up ${ep.record.label} done in ${((performance.now() - t) / 1000).toFixed(1)} s (setupId ${ep.setup.setupId})`);
    }
    funderKey = null;

    // ---- schedule (created once; an existing one was checked against the configuration above)
    let slots: Slot[];
    if (fs.existsSync(files.schedule)) {
      slots = (JSON.parse(fs.readFileSync(files.schedule, "utf8")) as { slots: Slot[] }).slots;
    } else {
      const sch = e2eSchedule(o.mode, o.endpoints, o.n, o.mode === "warm" ? o.warmup : 0);
      slots = sch.slots;
      writeJson(files.schedule, {
        schema: SCHEMA.schedule,
        createdUtc: utcNow(),
        config,
        prng: STREAM_SEED_RULE,
        rule: o.mode === "cold" ? "each block holds every endpoint once, in shuffled order; one cold run per slot" : "blocks < 0 are warm-up (not analysed); each block holds every endpoint instrumented and its uninstrumented control once, in shuffled order",
        slots,
      });
    }

    // ---- env.json (campaign level; one session entry per start)
    const sessionEntry = {
      session,
      device,
      environment: envName,
      gitHead: gitHead(),
      endpoints: endpoints.map((e) => e.record),
      customUrlSource,
      setupIds: Object.fromEntries(endpoints.map((e) => [e.kind, e.setup?.setupId ?? null])),
      labels: Object.fromEntries(endpoints.map((e) => [e.kind, runLabels(e.record.transport, o.mode, keyLabel, o.prover)])),
      nodeExpectation: wantNode,
      anvilExpectation: o.endpoints.includes("anvil") ? o.expectAnvil : null,
      marker: markerRecord,
      harnessSha256: code.harnessSha256,
    };
    if (fs.existsSync(files.env)) {
      const e = JSON.parse(fs.readFileSync(files.env, "utf8")) as { stable: typeof stable; sessions: unknown[] };
      if (JSON.stringify(e.stable) !== JSON.stringify(stable)) throw new Error("protocol, artifacts, package sources or prover changed since this campaign started; use a new --campaign");
      e.sessions.push(sessionEntry);
      writeJson(files.env, e);
    } else {
      writeJson(files.env, {
        schema: SCHEMA.env,
        campaign: o.campaign,
        mode: o.mode,
        smoke: o.smoke,
        label: o.smoke ? "SMOKE TEST: not a result, never quoted" : `[M] end-to-end ${o.mode} series`,
        keyLabel,
        stable,
        protocol,
        seeds: { id: E2E_SEED_ID, seed: E2E_SEED, rule: STREAM_SEED_RULE, bootstrap: E2E_BOOTSTRAP_SEED },
        stages: STAGES,
        client: { variant: "asShipped", options: AS_SHIPPED_OPTIONS, roundTrip: ROUND_TRIP_DEFINITION, note: "the shipped LedgerV4 client only; no client variant is part of this series" },
        harnessSha256: code.harnessSha256,
        versions: { snarkjs: snarkjsVersion(), ethers: packageVersion("ethers"), solc: packageVersion("solc"), circomlibjs: packageVersion("circomlibjs") },
        sessions: [sessionEntry],
      });
    }

    const ownPids = () => [...endpoints.flatMap((e) => e.ownPids), ...(warm?.proc.pid ? [warm.proc.pid] : [])];
    const ownPorts = endpoints.flatMap((e) => e.ownPorts);
    const quiesce = (windowMs = 3000): Promise<QuiesceRecord> => readQuiesceExcluding({ ownPids: ownPids(), ownPorts, windowMs });
    const byKind = new Map(endpoints.map((e) => [e.kind as string, e]));
    const labelsOf = (kind: string) => runLabels((byKind.get(kind) as Endpoint).record.transport, o.mode, keyLabel, o.prover);
    const runEnv = (power: PowerReading, utc: string) => ({ ...envInfo(), powerCode: power.code, utc });

    log(`[e2e] ${o.campaign} (${o.mode}${o.smoke ? ", SMOKE" : ""}): ${slots.length} slots over ${conditions.join(", ")} -> ${relOf(dir)}`);

    if (o.mode === "cold") {
      // ================================================================= cold series
      const prior = readJsonl<{ type?: string; slot?: number; status?: string }>(files.runs).filter((r) => r.type === "run");
      const done = new Set(prior.filter((r) => r.status === "ok").map((r) => r.slot));
      const attempts = new Map<number, number>();
      for (const r of prior) if (typeof r.slot === "number") attempts.set(r.slot, (attempts.get(r.slot) ?? 0) + 1);
      const todo = slots.filter((s) => !done.has(s.slot));
      log(`[e2e] ${done.size} slots done, ${todo.length} to run; idle ${o.idleSec} s`);
      let idleFrom: ClockReading = readClocks();
      let consecutiveNonAc = 0;
      for (const slot of todo) {
        const ep = byKind.get(slot.condition) as Endpoint;
        let errors = prior.filter((x) => x.slot === slot.slot && x.status === "error").length;
        for (;;) {
          checkStop();
          // re-anchor (untimed, inside the idle) when under 2 h of the epoch window remain
          const re = await (ep.setup as E2eSetup).reanchorIfNeeded(REANCHOR_MARGIN_SEC);
          if (re) writeRecord(files.deployments, { type: "reanchor", setupId: ep.setup?.setupId, campaign: o.campaign, session, utc: utcNow(), ...re });
          await sleep(idleFrom.mono + (o.idleSec - o.leadSec) * 1000 - performance.now());
          checkStop();
          let pre = readPowerE2e(o.powerRule);
          let q = await quiesce();
          let postponements = 0;
          while (!q.quiesced && postponements < o.maxPostpone) {
            log(`[e2e] slot ${slot.slot}: machine busy (${q.reasons.join("; ")}); postponing ${o.postponeStepSec} s`);
            await sleep(o.postponeStepSec * 1000);
            checkStop();
            postponements++;
            q = await quiesce();
            pre = readPowerE2e(o.powerRule);
          }
          await sleep(idleFrom.mono + o.idleSec * 1000 - performance.now());
          checkStop();
          const spawnAt = readClocks();
          const idle = clockGap(idleFrom, spawnAt, IDLE_PAUSE_THRESHOLD_SEC);
          const attempt = (attempts.get(slot.slot) ?? 0) + 1;
          attempts.set(slot.slot, attempt);
          const base = {
            type: "run" as const,
            schema: SCHEMA.run,
            campaign: o.campaign,
            mode: "cold" as const,
            smoke: o.smoke,
            session,
            setupId: ep.setup?.setupId ?? null,
            slot: slot.slot,
            block: slot.block,
            pos: slot.pos,
            condition: slot.condition,
            endpoint: slot.condition,
            control: false,
            attempt,
            labels: labelsOf(slot.condition),
            ...idleFields(idle),
            idle,
            postponements,
            quiesce: q,
          };
          if (!pre.ac) {
            consecutiveNonAc++;
            writeRecord(files.runs, { ...base, status: "discarded-battery", stage: "pre", utcStart: null, utcEnd: null, power: { pre, post: null }, runClock: null, childWallMs: null, result: null, env: runEnv(pre, utcNow()) });
            log(`[e2e] slot ${slot.slot} ${slot.condition}: not on AC before the run (code ${pre.code}); discarded, full idle again`);
            if (consecutiveNonAc >= MAX_CONSECUTIVE_NON_AC) throw new Error(`no mains power for ${consecutiveNonAc} consecutive checks; stopping (resume later)`);
            idleFrom = readClocks();
            continue;
          }
          consecutiveNonAc = 0;

          // ---- one cold run in a fresh process
          const utcStart = utcNow();
          const child = await runColdChild({ type: "init", mode: "cold", docs: [(ep.setup as E2eSetup).stateDoc(runKey)], prover: o.prover }, o.childTimeoutSec * 1000);
          const endAt = readClocks();
          idleFrom = endAt;
          const utcEnd = utcNow();
          const runClock = clockGap(spawnAt, endAt, RUN_PAUSE_THRESHOLD_SEC);
          const post = readPowerE2e(o.powerRule);
          const msgs = parseMsgLines(child.stdout);
          const result = msgs.find((m) => m["type"] === "result") ?? null;
          const fatal = msgs.find((m) => m["type"] === "fatal") ?? null;
          const env = runEnv(pre, utcStart);
          let status: string;
          let error: string | undefined;
          let stage: string | undefined;
          if (child.timedOut || child.code !== 0 || !result || result["ok"] !== true) {
            status = "error";
            const why = child.timedOut
              ? `child timed out after ${o.childTimeoutSec} s`
              : result
                ? `${String(result["errorKind"] ?? "error")}: ${String(result["error"] ?? "not ok")}`
                : fatal
                  ? `child failed: ${String(fatal["error"])}`
                  : `child exit ${child.code}${child.signal ? ` (${child.signal})` : ""}`;
            error = redactSecrets(`${why}; stderr tail: ${child.stderr.slice(-600)}`, needles());
          } else if (runClock.hostPauseSuspected) {
            status = "discarded-pause";
          } else if (!post.ac) {
            status = "discarded-battery";
            stage = "post";
          } else status = "ok";
          writeRecord(files.runs, {
            ...base,
            status,
            ...(stage ? { stage } : {}),
            utcStart,
            utcEnd,
            power: { pre, post },
            runClock,
            childWallMs: Math.round(child.wallMs * 1000) / 1000,
            result,
            env,
            ...(error ? { error } : {}),
          });
          const e2e = result && typeof result["endToEndMs"] === "number" ? (result["endToEndMs"] as number).toFixed(1) : "-";
          log(`[e2e] slot ${slot.slot + 1}/${slots.length} ${slot.condition}: ${status} endToEnd ${e2e} ms (idle ${idle.monoSec} s mono, gap ${idle.clockGapSec} s)${error ? ` ${error.slice(0, 200)}` : ""}`);
          if (status === "ok") break;
          if (status === "error") {
            errors++;
            if (errors >= MAX_ERRORS_PER_SLOT) throw new Error(`slot ${slot.slot} failed ${errors} times; stopping (fix, then resume)`);
          }
          // discarded or error: the slot is repeated after a full idle
        }
      }
      fs.appendFileSync(files.runs, JSON.stringify({ type: "campaign-end", campaign: o.campaign, session, utc: utcNow(), complete: true }) + "\n");
    } else {
      // ================================================================= warm series
      const docs = endpoints.map((e) => (e.setup as E2eSetup).stateDoc(runKey));
      warm = new WarmChild({ type: "init", mode: "warm", docs, prover: o.prover });
      const ready = await warm.next(600_000);
      if (!ready || ready["type"] !== "ready") throw new Error(`warm child did not start: ${ready ? String(ready["error"]) : redactSecrets(warm.stderr.slice(-600), needles())}`);
      writeRecord(files.runs, { type: "session-start", campaign: o.campaign, session, utc: utcNow(), smoke: o.smoke, child: ready });
      log(`[e2e] warm child ready; settling ${o.settleSec} s`);
      for (;;) {
        const settleFrom = readClocks();
        await sleep(Math.max(0, o.settleSec - 5) * 1000);
        checkStop();
        const p = readPowerE2e(o.powerRule);
        await sleep(Math.min(5, o.settleSec) * 1000);
        checkStop();
        const settle = clockGap(settleFrom, readClocks(), IDLE_PAUSE_THRESHOLD_SEC);
        writeRecord(files.runs, { type: "settle", campaign: o.campaign, session, utc: utcNow(), power: p, ...idleFields(settle), settle });
        if (p.ac) break;
        log(`[e2e] not on AC after the settle (code ${p.code}); settling again`);
      }
      const blocks = [...new Set(slots.map((s) => s.block))].sort((a, b) => a - b);
      const blockMs: number[] = [];
      let discardedBlocks = 0;
      let seq = 0;
      for (const b of blocks) {
        const re: Array<Record<string, unknown>> = [];
        for (const ep of endpoints) {
          // untimed re-anchor between blocks (never needed under about 22 h)
          const r = await (ep.setup as E2eSetup).reanchorIfNeeded(REANCHOR_MARGIN_SEC);
          if (r) re.push({ endpoint: ep.kind, ...r });
        }
        if (re.length > 0) {
          for (const r of re) writeRecord(files.deployments, { type: "reanchor", campaign: o.campaign, session, utc: utcNow(), ...r });
          throw new Error("an epoch was re-anchored during the warm session: the warm child holds the old blob; restart the session (a new session in the same runs.jsonl)");
        }
        const inBlock = slots.filter((s) => s.block === b).sort((x, y) => x.pos - y.pos);
        let blockErrors = 0;
        let consecutiveNonAcW = 0;
        for (;;) {
          checkStop();
          // UTC midnight black-out (rule 10)
          const est = (median(blockMs) ?? 60_000) * 1.5 + o.blockGapSec * 1000 + 10_000;
          if (crossesBlackout(Date.now(), est)) {
            const bo = midnightBlackout(Date.now());
            const until = bo.inside && bo.endsAtMs ? bo.endsAtMs : midnightBlackout(Date.now() + est).endsAtMs ?? Date.now() + 20 * 60_000;
            log(`[e2e] block ${b}: UTC midnight black-out; waiting until ${new Date(until + 5000).toISOString()}`);
            await sleep(until + 5000 - Date.now());
            continue;
          }
          const pre = readPowerE2e(o.powerRule);
          const q = await quiesce(Math.max(1, o.blockGapSec) * 1000);
          if (!pre.ac) {
            consecutiveNonAcW++;
            if (consecutiveNonAcW >= 360) throw new Error("no mains power for 6 h; stopping");
            log(`[e2e] block ${b}: not on AC (code ${pre.code}); waiting 60 s`);
            await sleep(60_000);
            continue;
          }
          consecutiveNonAcW = 0;
          const b0 = readClocks();
          const recs: Array<Record<string, unknown>> = [];
          let anyError = false;
          for (const s of inBlock) {
            checkStop();
            const { endpoint, control } = parseCondition(s.condition);
            const mySeq = ++seq;
            const utcStart = utcNow();
            warm.send({ type: "iterate", endpoint, control, seq: mySeq });
            let msg = await warm.next(o.childTimeoutSec * 1000);
            while (msg && msg["type"] === "result" && msg["seq"] !== mySeq && msg["seq"] !== null) msg = await warm.next(o.childTimeoutSec * 1000);
            const ok = !!msg && msg["type"] === "result" && msg["ok"] === true;
            if (!ok) anyError = true;
            const error = ok ? undefined : redactSecrets(msg ? `${String(msg["errorKind"] ?? msg["type"])}: ${String(msg["error"] ?? "not ok")}` : `no answer within ${o.childTimeoutSec} s; stderr tail: ${warm.stderr.slice(-600)}`, needles());
            recs.push({
              type: "run",
              schema: SCHEMA.run,
              campaign: o.campaign,
              mode: "warm",
              smoke: o.smoke,
              session,
              setupId: byKind.get(endpoint)?.setup?.setupId ?? null,
              slot: s.slot,
              block: s.block,
              pos: s.pos,
              warmup: s.block < 0,
              condition: s.condition,
              endpoint,
              control,
              labels: [...labelsOf(endpoint), ...(control ? ["uninstrumented control"] : [])],
              status: ok ? "ok" : "error",
              utcStart,
              utcEnd: utcNow(),
              result: msg,
              ...(error ? { error } : {}),
            });
            if (!ok) break;
            if (!warm || warm.exited) break;
          }
          const b1 = readClocks();
          const blockClock = clockGap(b0, b1, RUN_PAUSE_THRESHOLD_SEC);
          blockMs.push(b1.mono - b0.mono);
          const post = readPowerE2e(o.powerRule);
          const pause = blockClock.hostPauseSuspected;
          for (const r of recs) {
            // a block with an error is repeated whole: its other iterations are kept but not analysed
            const status = r["status"] === "error" ? "error" : anyError ? "discarded-block-error" : pause ? "discarded-pause" : post.ac ? "ok" : "discarded-battery";
            writeRecord(files.runs, { ...r, status, ...(status === "discarded-battery" ? { stage: "post" } : {}), power: { pre, post }, quiesce: q, blockClock, env: runEnv(pre, String(r["utcStart"])) });
          }
          const sum = recs.map((r) => `${String(r["condition"])} ${typeof (r["result"] as Record<string, unknown> | null)?.["endToEndMs"] === "number" ? ((r["result"] as Record<string, number>)["endToEndMs"] as number).toFixed(0) : "-"}`).join(", ");
          log(`[e2e] block ${b}${b < 0 ? " (warm-up)" : ""}: ${anyError ? "ERROR" : pause ? "DISCARDED (host pause)" : post.ac ? "ok" : "DISCARDED (power)"}; endToEnd ms: ${sum}`);
          if (!anyError && !pause && post.ac) break;
          if (anyError) {
            blockErrors++;
            if (warm.exited) throw new Error(`warm child exited: ${redactSecrets(warm.stderr.slice(-600), needles())}`);
            if (blockErrors >= MAX_ERRORS_PER_SLOT) throw new Error(`block ${b} failed ${blockErrors} times; stopping (a restart is a new session)`);
          } else discardedBlocks++;
        }
      }
      await warm.close();
      fs.appendFileSync(files.runs, JSON.stringify({ type: "session-end", campaign: o.campaign, session, utc: utcNow(), complete: true, measuredBlocks: o.n, warmupBlocks: o.warmup, discardedBlocks }) + "\n");
    }
    log(`[e2e] ${o.campaign} complete -> ${relOf(files.runs)}`);
  } catch (e) {
    exitCode = e instanceof Interrupted ? 130 : 1;
    const msg = redactSecrets(e instanceof Error ? e.message : String(e), needles());
    console.error(`[e2e] ${msg}`);
    try {
      fs.appendFileSync(files.runs, JSON.stringify({ type: "session-stop", campaign: o.campaign, session, utc: utcNow(), reason: msg.slice(0, 500) }) + "\n");
    } catch {
      /* the folder may not exist yet */
    }
  } finally {
    try {
      await warm?.close();
    } catch {
      /* already gone */
    }
    for (const ep of endpoints) {
      if (ep.setup && ep.kind === "custom" && o.custom.sweep) {
        try {
          const sw = await ep.setup.sweep();
          writeQuiet(files.deployments, { type: "sweep", partial: false, setupId: ep.setup.setupId, campaign: o.campaign, session, utc: utcNow(), transfers: redactTransfers(sw) });
          log(`[e2e] sweep: ${sweepSummary(sw)}`);
        } catch (e) {
          console.error(`[e2e] sweep failed: ${redactSecrets((e as Error).message, needles())}`);
        }
      }
      ep.setup?.destroy();
    }
    killAnvil();
    marker?.release();
  }
  return exitCode;
}

main().then(
  (code) => process.exit(code),
  (e: unknown) => {
    console.error(`[e2e] ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
);

