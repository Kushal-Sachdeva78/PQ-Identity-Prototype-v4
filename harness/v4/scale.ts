import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import v8 from "node:v8";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { REPO_ROOT } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";
import { sha3_256 } from "@pqid/common/hash";
import { IssuanceTree } from "@pqid/issuer";
import { startAnvil, type AnvilHandle } from "@pqid/ledger";
import { World } from "@pqid/v4/world";
import { LedgerV4 } from "@pqid/v4/ledger";
import { IndexedMerkleTree } from "@pqid/v4/imt";
import {
  REV_DEPTH,
  ISSUANCE_DEPTH,
  MIN_ANCHOR_INTERVAL_SEC,
  EPOCH_WINDOW_SEC,
  MAX_ACCREDITATION_SEC,
  DEFAULT_TYPE_ID,
  KEM_ALG,
} from "@pqid/v4/constants";
import { signEpochV4, anchorEpochV4, issueCredentialV4, revokeCredentialV4, type VerifiableCredentialV4 } from "@pqid/v4/issuer";
import { accreditIssuer } from "@pqid/v4/governance";
import { mlDsaSign, mlDsaVerify, implementationLabel } from "@pqid/v4/pqc";
import { epochMessage, verifierKemMessage } from "@pqid/v4/statements";
import { VerifierV4, type VerifierIdentity, type PresentationV4 } from "@pqid/v4/verifier";
import type { VerifierSessionStore, SessionReplyV4 } from "@pqid/v4/session";
import { VKEY_V4, KEY_LABEL_V4 } from "@pqid/v4/paths";
import type { HolderWalletV4 } from "@pqid/v4/wallet";
import { bulkIssuanceTree } from "./bulk_issuance_tree.ts";
import {
  distribution,
  nowNs,
  msSince,
  timeMs,
  fieldElements,
  revocationKeys,
  memory,
  assertPortFree,
  rawRpc,
  readAffinity,
  relaunchPinned,
  worldOnRpc,
  swapWorldLedger,
  providerOf,
  disableBatchStall,
  countRpc,
  timedLedger,
  cachedLedger,
  recordingLedger,
  hookPqcCrypto,
  evmInfo,
  calldataInfo,
  snapshotSessions,
  restoreSessions,
  replaceSessionStore,
  sha256OfFile,
  writeJson,
  osInfo,
  type AffinityReadBack,
  type RecordedWrite,
} from "./scale_lib.ts";

/**
 * Experiment E4: scale and ledger (TASKS S53-S57; docs/v4/E4_SCALE.md).
 *
 *   node --import tsx harness/v4/scale.ts <trees|anchor|verifier|besu> [--n N[,N...]] [--dry] [options]
 *
 *   trees     issuance-tree and revocation-IMT inserts when the trees already hold n entries;
 *             sign+anchor time of an epoch at that size; memory             [M]
 *   anchor    gas of every registry write on Anvil; anchor gas per day for
 *             1 h and 24 h cadences                                        [M] gas, [S] per day
 *   verifier  VerifierV4.verifyReply throughput on ONE core (the measuring process is
 *             re-launched pinned to CPU 0) with the chain-read / ML-DSA / ML-KEM / Groth16 split
 *   besu      registry reads and write latency: 4-validator Besu QBFT network vs one Anvil node
 *             (start the network first: scripts/besu/setup_qbft.sh up)
 *
 * --dry writes to results/v4/scale/_dry/ and labels the file as a script check, not a result.
 * Refuses to run while results/v4/bench/RUNNING exists (docs/BENCHMARK_POLICY.md benchmark rule).
 */

const HERE = fileURLToPath(import.meta.url);
const RESULTS_DIR = path.join(REPO_ROOT, "results", "v4", "scale");
const DRY_DIR = path.join(RESULTS_DIR, "_dry");
const BENCH_RUNNING = path.join(REPO_ROOT, "results", "v4", "bench", "RUNNING");
const CHILD_ENV = "PQID_E4_CHILD";

// ---------------------------------------------------------------------------------------
// arguments
// ---------------------------------------------------------------------------------------

type Sub = "trees" | "anchor" | "verifier" | "besu" | "trees-worker";

interface Args {
  sub: Sub;
  dry: boolean;
  /** trees: tree sizes; anchor: epochs; verifier: presentations P; besu: rounds R. */
  n: number[] | null;
  k: number;
  epochs: number | null;
  issueK: number | null;
  build: "auto" | "incremental" | "bulk";
  heapMiB: number;
  p: number | null;
  passes: number | null;
  warmup: number | null;
  holders: number | null;
  r: number | null;
  w: number | null;
  port: number | null;
  besuRpc: string;
  out: string | null;
  part: string | null;
  noPin: boolean;
  gwei: number[];
  seed: string;
}

const USAGE = `usage: node --import tsx harness/v4/scale.ts <trees|anchor|verifier|besu> [options]
  --dry                  small sizes; output to results/v4/scale/_dry/ (script check, not results)
  --n <list>             trees: sizes (default 100000,1000000; dry 1000)
                         anchor: epochs (default 10; dry 3)
                         verifier: presentations P (default 200; dry 5)
                         besu: read rounds R (default 200; dry 5)
  trees:    --k <K> (1000) --epochs <E> (5; dry 2) --issue-k <n> (200; dry 20)
            --build auto|incremental|bulk (auto: incremental up to 100000, else bulk)
            --heap-mib <MiB> (8192, heap limit of each per-size worker process)
  anchor:   --epochs <E> --gwei <list> (optional gas prices in gwei for an [A] ETH/day column)
  verifier: --p <P> --passes <n> (3; dry 1) --warmup <n> (5; dry 2) --holders <n> (4; dry 2)
            --no-pin (measure in this process without CPU pinning; debugging only)
  besu:     --r <R> --w <W> (writes per target: 20; dry 3) --besu-rpc <url> (http://127.0.0.1:18545)
  common:   --port <p> (Anvil port; trees 8750, anchor 8751, verifier 8752, besu 8753)
            --out <file> --seed <s>`;

function parseArgs(argv: string[]): Args {
  const sub = argv[0] as Sub | undefined;
  if (!sub || !["trees", "anchor", "verifier", "besu", "trees-worker"].includes(sub)) {
    console.error(USAGE);
    process.exit(2);
  }
  const a: Args = {
    sub,
    dry: false,
    n: null,
    k: 1000,
    epochs: null,
    issueK: null,
    build: "auto",
    heapMiB: 8192,
    p: null,
    passes: null,
    warmup: null,
    holders: null,
    r: null,
    w: null,
    port: null,
    besuRpc: "http://127.0.0.1:18545",
    out: null,
    part: null,
    noPin: false,
    gwei: [],
    seed: "pqid-e4-v1",
  };
  const rest = argv.slice(1);
  for (let i = 0; i < rest.length; i++) {
    let key = rest[i] as string;
    let val: string | undefined;
    const eq = key.indexOf("=");
    if (key.startsWith("--") && eq > 0) {
      val = key.slice(eq + 1);
      key = key.slice(0, eq);
    }
    const next = (): string => {
      if (val !== undefined) return val;
      const v = rest[++i];
      if (v === undefined) throw new Error(`${key} needs a value`);
      return v;
    };
    const int = (): number => {
      const v = Number(next());
      if (!Number.isSafeInteger(v) || v < 0) throw new Error(`${key} needs a non-negative integer`);
      return v;
    };
    const ints = (): number[] =>
      next()
        .split(",")
        .map((s) => {
          const v = Number(s.trim());
          if (!Number.isSafeInteger(v) || v < 0) throw new Error(`${key} needs non-negative integers`);
          return v;
        });
    switch (key) {
      case "--dry": a.dry = true; break;
      case "--n": a.n = ints(); break;
      case "--k": a.k = int(); break;
      case "--epochs": a.epochs = int(); break;
      case "--issue-k": a.issueK = int(); break;
      case "--build": {
        const b = next();
        if (b !== "auto" && b !== "incremental" && b !== "bulk") throw new Error("--build auto|incremental|bulk");
        a.build = b;
        break;
      }
      case "--heap-mib": a.heapMiB = int(); break;
      case "--p": a.p = int(); break;
      case "--passes": a.passes = int(); break;
      case "--warmup": a.warmup = int(); break;
      case "--holders": a.holders = int(); break;
      case "--r": a.r = int(); break;
      case "--w": a.w = int(); break;
      case "--port": a.port = int(); break;
      case "--besu-rpc": a.besuRpc = next(); break;
      case "--out": a.out = path.resolve(next()); break;
      case "--part": a.part = path.resolve(next()); break;
      case "--no-pin": a.noPin = true; break;
      case "--gwei": a.gwei = next().split(",").map((s) => Number(s)); break;
      case "--seed": a.seed = next(); break;
      case "--help": console.log(USAGE); process.exit(0); break;
      default: throw new Error(`unknown option ${key}\n${USAGE}`);
    }
  }
  return a;
}

/** Options as recorded in results (no paths). */
function recordedOptions(a: Args): Record<string, unknown> {
  return Object.fromEntries(Object.entries(a).filter(([k]) => k !== "out" && k !== "part"));
}

function outFile(a: Args, sub: string): string {
  return a.out ?? path.join(a.dry ? DRY_DIR : RESULTS_DIR, `${sub}.json`);
}

function relRepo(p: string): string {
  return path.relative(REPO_ROOT, p).split(path.sep).join("/");
}

/** execArgv with anything that names a local path removed (results carry no user paths). */
function safeExecArgv(): string[] {
  const home = os.homedir().toLowerCase();
  const user = os.userInfo().username.toLowerCase();
  return process.execArgv.map((s) => {
    const l = decodeURIComponent(s).toLowerCase().replace(/\\/g, "/");
    return l.includes(home.replace(/\\/g, "/")) || (user.length > 2 && l.includes(user)) ? "<path omitted>" : s;
  });
}

function header(a: Args, sub: string): Record<string, unknown> {
  return {
    schema: `pqid/v4-e4-${sub}/v1`,
    experiment: "E4",
    subcommand: sub,
    dry: a.dry,
    label: a.dry
      ? "DRY RUN: small-size script check on a busy machine. Not a result; do not cite."
      : "[M] measured unless a field says [S] or [A]",
    options: recordedOptions(a),
    startedUtc: new Date().toISOString(),
    host: hostMeta(),
    hostState: osInfo(),
    runtime: {
      node: process.version,
      openssl: process.versions.openssl,
      v8: process.versions.v8,
      pqc: implementationLabel(),
      execArgv: safeExecArgv(),
      gcExposed: typeof (globalThis as { gc?: unknown }).gc === "function",
      heapSizeLimitMiB: Math.round(v8.getHeapStatistics().heap_size_limit / 2 ** 20),
    },
    timer: "process.hrtime.bigint() (monotonic, ns), reported in ms",
    harnessSha256: Object.fromEntries(
      ["harness/v4/scale.ts", "harness/v4/scale_lib.ts", "harness/v4/bulk_issuance_tree.ts", "scripts/besu/setup_qbft.sh"].map((f) => [
        f,
        sha256OfFile(path.join(REPO_ROOT, f)),
      ])
    ),
    // the code under test (v4 sources change during the run; results are tied to these hashes)
    sourceSha256: Object.fromEntries(
      [
        "onchain/contracts/v4/RegistriesV4.sol",
        ...fs
          .readdirSync(path.join(REPO_ROOT, "packages", "v4", "src"))
          .filter((f) => f.endsWith(".ts"))
          .sort()
          .map((f) => `packages/v4/src/${f}`),
        "packages/issuer/src/issuance.ts",
        relRepo(VKEY_V4),
      ].map((f) => [f, sha256OfFile(path.join(REPO_ROOT, f))])
    ),
    keyLabel: KEY_LABEL_V4,
  };
}

function log(msg: string): void {
  console.log(`[e4] ${msg}`);
}

// ---------------------------------------------------------------------------------------
// trees
// ---------------------------------------------------------------------------------------

async function treesParent(a: Args): Promise<void> {
  const sizes = a.n ?? (a.dry ? [1000] : [100_000, 1_000_000]);
  const partDir = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-e4-trees-"));
  const runs: unknown[] = [];
  const started = header(a, "trees");
  try {
    for (const n of sizes) {
      const part = path.join(partDir, `n${n}.json`);
      // forward the options except --n, --out and --part (the worker gets one size and a part file)
      const fwd: string[] = [];
      const src = process.argv.slice(3);
      for (let i = 0; i < src.length; i++) {
        const s = src[i] as string;
        if (s === "--n" || s === "--out" || s === "--part") {
          i++;
          continue;
        }
        if (s.startsWith("--n=") || s.startsWith("--out=") || s.startsWith("--part=")) continue;
        fwd.push(s);
      }
      const args = [
        "--expose-gc",
        `--max-old-space-size=${a.heapMiB}`,
        ...process.execArgv,
        HERE,
        "trees-worker",
        "--n",
        String(n),
        "--part",
        part,
        ...fwd,
      ];
      log(`trees: n = ${n} in a fresh worker process`);
      const r = spawnSync(process.execPath, args, { stdio: "inherit", env: process.env });
      if (r.status !== 0 || !fs.existsSync(part)) throw new Error(`trees worker for n = ${n} failed (exit ${r.status})`);
      runs.push(JSON.parse(fs.readFileSync(part, "utf8")));
    }
  } finally {
    fs.rmSync(partDir, { recursive: true, force: true });
  }
  const result = {
    ...started,
    finishedUtc: new Date().toISOString(),
    method: {
      leaves: "[A] issuance leaves are pseudo-random field elements in [1, p) from SHA-256(seed:i); tree cost does not depend on what a leaf commits to",
      revocationKeys: "[A] revocation keys are the top 251 bits of SHA-256(seed:i), the distribution of real revKeys (251 bits of a SHA3-256 credID)",
      issuanceBuild:
        "incremental = IssuanceTree.insert per leaf (packages/issuer); bulk = harness/v4/bulk_issuance_tree.ts, same internal state (tests/v4/scale_bulk_tree.test.ts)",
      revocationBuild: "IndexedMerkleTree.bulkBuild (packages/v4/src/imt.ts)",
      inserts: "K single inserts timed one by one after the tree holds n entries (IssuanceTree.insert; IndexedMerkleTree.insert)",
      epoch:
        "signEpochV4 (roots, IMT snapshot for serving witnesses, ML-DSA-44 sign) and anchorEpochV4 (gas estimate, submit, receipt, anchor re-read) on a local Anvil, minAnchorInterval advanced between epochs (untimed)",
      memory: "process.memoryUsage() after global.gc() in a fresh worker process per n (node --expose-gc)",
    },
    runs,
  };
  const file = outFile(a, "trees");
  writeJson(file, result);
  log(`wrote ${relRepo(file)}`);
}

async function treesWorker(a: Args): Promise<void> {
  const n = (a.n ?? [])[0];
  if (n === undefined || !a.part) throw new Error("trees-worker needs --n and --part");
  const K = a.k;
  const E = a.epochs ?? (a.dry ? 2 : 5);
  const issueK = a.issueK ?? (a.dry ? 20 : 200);
  const port = a.port ?? 8750;
  const method = a.build === "auto" ? (n <= 100_000 ? "incremental" : "bulk") : a.build;
  const seed = `${a.seed}:trees:n${n}`;
  const mem: Record<string, unknown> = { start: memory() };

  log(`n=${n}: generating ${n + K} leaves and ${n + K} revocation keys`);
  const leaves = fieldElements(`${seed}:leaf`, n + K);
  const keys = revocationKeys(`${seed}:rev`, n + K);
  mem["inputsGenerated"] = memory();

  log(`n=${n}: building issuance tree (${method})`);
  const tb = nowNs();
  let tree: IssuanceTree;
  if (method === "incremental") {
    tree = await IssuanceTree.create(ISSUANCE_DEPTH);
    for (let i = 0; i < n; i++) tree.insert(leaves[i] as bigint);
  } else {
    tree = await bulkIssuanceTree(leaves.slice(0, n), ISSUANCE_DEPTH);
  }
  const issuanceBuildMs = msSince(tb);
  mem["afterIssuanceBuild"] = memory();

  log(`n=${n}: building revocation IMT (bulkBuild, depth ${REV_DEPTH})`);
  const tr = nowNs();
  const imt = await IndexedMerkleTree.bulkBuild(keys.slice(0, n), REV_DEPTH);
  const imtBuildMs = msSince(tr);
  mem["afterImtBuild"] = memory();

  log(`n=${n}: timing ${K} issuance inserts and ${K} revocation inserts`);
  const issSamples: number[] = [];
  for (let i = n; i < n + K; i++) {
    const t0 = nowNs();
    tree.insert(leaves[i] as bigint);
    issSamples.push(msSince(t0));
  }
  const revSamples: number[] = [];
  for (let i = n; i < n + K; i++) {
    const t0 = nowNs();
    imt.insert(keys[i] as bigint);
    revSamples.push(msSince(t0));
  }
  mem["afterInserts"] = memory();

  // Epoch sign + anchor with the big trees, on a local Anvil.
  await assertPortFree(port);
  const world = await World.create({ port });
  const epochs: Array<Record<string, unknown>> = [];
  const components: Record<string, unknown> = {};
  const issueSamples: number[] = [];
  const revokeSamples: number[] = [];
  try {
    const issuer = await world.addIssuer(`e4-trees-${n}`);
    issuer.tree = tree;
    issuer.rev = imt;
    // Components, isolated (not part of the flow): roots, IMT snapshot, ML-DSA-44 sign.
    const rootSamples: number[] = [];
    for (let i = 0; i < 20; i++) {
      const t0 = nowNs();
      tree.root();
      imt.root();
      rootSamples.push(msSince(t0));
    }
    const snapSamples: number[] = [];
    for (let i = 0; i < 3; i++) {
      const t0 = nowNs();
      imt.snapshot();
      snapSamples.push(msSince(t0));
    }
    const probe = {
      issuer: issuer.did,
      controller: issuer.controller,
      chainId: await world.ledger.chainId(),
      registry: world.ledger.addresses.issuanceRootRegistry.toLowerCase(),
      epoch: 1,
      root: tree.root().toString(),
      revRoot: imt.root().toString(),
      notBefore: world.clock.nowSec(),
      notAfter: world.clock.nowSec() + EPOCH_WINDOW_SEC,
    };
    const signSamples: number[] = [];
    for (let i = 0; i < 20; i++) {
      const t0 = nowNs();
      mlDsaSign(issuer.sk, epochMessage(probe));
      signSamples.push(msSince(t0));
    }
    components["rootsReadMs"] = distribution(rootSamples);
    components["imtSnapshotMs"] = distribution(snapSamples);
    components["mlDsa44SignEpochMs"] = distribution(signSamples);

    for (let e = 1; e <= E; e++) {
      if (e > 1) await world.advance(MIN_ANCHOR_INTERVAL_SEC);
      await world.syncChainTime();
      const s = await timeMs(() => signEpochV4(issuer, world.ledger, world.clock));
      const an = await timeMs(() => anchorEpochV4(issuer, world.ledger, s.value));
      epochs.push({ epoch: e, signMs: s.ms, anchorMs: an.ms, signPlusAnchorMs: s.ms + an.ms, gasUsed: Number(an.value.gasUsed) });
    }
    mem["afterEpochs"] = memory();

    // End-to-end issuer routines at this size (tree insert + leaf hash + ML-DSA sign; IMT insert).
    const holderCommit = 123456789n;
    const vcs: VerifiableCredentialV4[] = [];
    for (let i = 0; i < issueK; i++) {
      const t0 = nowNs();
      const vc = await issueCredentialV4(issuer, {
        subject: `did:pq:e4-subject-${i}`,
        holderCommit,
        birthDate: 19900101,
        typeId: DEFAULT_TYPE_ID,
        issuedDate: world.today,
      });
      issueSamples.push(msSince(t0));
      vcs.push(vc);
    }
    for (const vc of vcs) {
      const t0 = nowNs();
      revokeCredentialV4(issuer, vc.credID);
      revokeSamples.push(msSince(t0));
    }
  } finally {
    world.stop();
  }
  mem["end"] = memory();

  const signMs = epochs.map((x) => x["signMs"] as number);
  const anchorMs = epochs.map((x) => x["anchorMs"] as number);
  const both = epochs.map((x) => x["signPlusAnchorMs"] as number);
  const run = {
    n,
    k: K,
    worker: {
      execArgv: safeExecArgv(),
      gcExposed: typeof (globalThis as { gc?: unknown }).gc === "function",
      heapSizeLimitMiB: Math.round(v8.getHeapStatistics().heap_size_limit / 2 ** 20),
      anvilPort: port,
    },
    issuance: {
      depth: ISSUANCE_DEPTH,
      buildMethod: method,
      buildMs: issuanceBuildMs,
      sizeAfterInserts: tree.size,
      insertMs: distribution(issSamples),
      insertsPerSec: Math.round(1000 / distribution(issSamples).median),
    },
    revocation: {
      depth: REV_DEPTH,
      buildMethod: "IndexedMerkleTree.bulkBuild",
      buildMs: imtBuildMs,
      keysAfterInserts: imt.keyCount,
      insertMs: distribution(revSamples),
      insertsPerSec: Math.round(1000 / distribution(revSamples).median),
    },
    epoch: {
      epochs: E,
      signMs: distribution(signMs),
      anchorMs: distribution(anchorMs),
      signPlusAnchorMs: distribution(both),
      perEpoch: epochs,
      components,
      note:
        "signMs = signEpochV4 (roots, IMT snapshot kept to serve witnesses, ML-DSA-44 sign). anchorMs = anchorEpochV4 as shipped: eth_estimateGas, submit, receipt (ethers polls every 100 ms, ledger.ts makeProvider; Anvil mines at once) and the anchor re-read. The first epoch's anchor writes empty storage slots (higher gas); later epochs overwrite them.",
    },
    issuerRoutines: {
      issueCredentialV4Ms: distribution(issueSamples),
      revokeCredentialV4Ms: distribution(revokeSamples),
      samples: issueK,
    },
    memory: mem,
  };
  writeJson(a.part, run);
}

// ---------------------------------------------------------------------------------------
// anchor
// ---------------------------------------------------------------------------------------

function pickWrites(ws: RecordedWrite[], method: string): RecordedWrite[] {
  return ws.filter((w) => w.method === method);
}

function laterSplit(ep: RecordedWrite[], changed: boolean[], want: boolean): unknown {
  const g = ep.slice(1).filter((_, i) => changed[i + 1] === want).map((w) => w.gasUsed);
  return g.length > 0 ? distribution(g) : null;
}

/** Calldata facts per transaction hash (filled by anchorCmd after the writes). */
const calldataByTx = new Map<string, Record<string, unknown>>();

function gasRow(w: RecordedWrite | undefined): Record<string, unknown> | null {
  return w ? { gasUsed: w.gasUsed, blockNumber: w.blockNumber, ...(calldataByTx.get(w.txHash) ?? { calldataBytes: w.calldataBytes }) } : null;
}

async function anchorCmd(a: Args): Promise<void> {
  const E = (a.n ?? [])[0] ?? a.epochs ?? (a.dry ? 3 : 10);
  if (E < 2) throw new Error("anchor needs at least 2 epochs (first and later)");
  const port = a.port ?? 8751;
  const head = header(a, "anchor");
  await assertPortFree(port);
  const world = await World.create({ port });
  const rec = recordingLedger(world.ledger);
  swapWorldLedger(world, rec.proxy);
  let blockGasLimit: number | null = null;
  try {
    const deployGas = world.ledger.deployment.deployGas;
    log("anchor: issuer registration and accreditation");
    const issuer = await world.addIssuer("e4-anchor");
    await accreditIssuer(world.governance, world.ledger, world.clock, { did: issuer.did, controller: issuer.controller });
    log("anchor: verifier registration, KEM key and a KEM key rotation");
    const verifier = await world.addVerifier("e4-anchor-verifier");
    await world.advance(60); // kemMonotonic: a rotated KEM statement needs a later notBefore
    await world.publishKemKey(verifier.opts.identity);
    const holder = await world.addHolder();
    const vcs: VerifiableCredentialV4[] = [];
    const revRootChanged: boolean[] = [];
    for (let e = 1; e <= E; e++) {
      if (e > 1) await world.advance(MIN_ANCHOR_INTERVAL_SEC);
      // every epoch issues one credential (new issuance root); every second epoch also revokes one (new revRoot)
      vcs.push(await world.issue(issuer, holder, { birthDate: 19900101 }));
      if (e % 2 === 0) revokeCredentialV4(issuer, (vcs[e - 2] as VerifiableCredentialV4).credID);
      revRootChanged.push(issuer.anchored === null || issuer.rev.root().toString() !== issuer.anchored.statement.revRoot);
      await world.publishEpoch(issuer);
      log(`anchor: epoch ${e} anchored`);
    }
    const blk = (await rawRpc(world.anvil.rpcUrl, "eth_getBlockByNumber", ["latest", false])) as { gasLimit?: string };
    blockGasLimit = blk.gasLimit ? Number(BigInt(blk.gasLimit)) : null;
    const evm = await evmInfo(world.anvil.rpcUrl);

    const ws = rec.writes;
    for (const w of ws) calldataByTx.set(w.txHash, await calldataInfo(world.anvil.rpcUrl, w.txHash, w.gasUsed));
    const reg = pickWrites(ws, "registerDID");
    const acc = pickWrites(ws, "publish");
    const kem = pickWrites(ws, "publishKemKey");
    const ep = pickWrites(ws, "publishEpoch");
    const later = ep.slice(1).map((w) => w.gasUsed);
    const laterMedian = distribution(later).median;
    const first = (ep[0] as RecordedWrite).gasUsed;
    const accLater = acc[1]?.gasUsed ?? null;
    const newRev = laterSplit(ep, revRootChanged, true) as { median: number } | null;
    const cadences = [
      { name: "1h (minAnchorInterval, D-012)", intervalSec: MIN_ANCHOR_INTERVAL_SEC },
      { name: "24h (epoch window, D-012)", intervalSec: EPOCH_WINDOW_SEC },
    ].map((c) => {
      const perDay = 86400 / c.intervalSec;
      const steady = perDay * laterMedian;
      const row: Record<string, unknown> = {
        cadence: c.name,
        anchorsPerDay: perDay,
        gasPerDaySteadyState: steady,
        gasFirstDay: first + (perDay - 1) * laterMedian,
        gasPerYearSteadyState: steady * 365,
        gasPerDayIfEveryEpochHasNewRevRoot: newRev ? perDay * newRev.median : null,
        label: "[S] anchorsPerDay x median gas of later publishEpoch [M] (mix: half the later epochs carry a new revRoot)",
      };
      if (a.gwei.length > 0) {
        row["ethPerDayAtGasPrice"] = Object.fromEntries(a.gwei.map((g) => [`${g} gwei [A]`, (steady * g) / 1e9]));
      }
      return row;
    });
    const result = {
      ...head,
      finishedUtc: new Date().toISOString(),
      chain: {
        node: "Anvil (tools/foundry/anvil.exe), automine, default hardfork",
        client: String(await rawRpc(world.anvil.rpcUrl, "web3_clientVersion")),
        chainId: await world.ledger.chainId(),
        blockGasLimit,
        evm,
        note: "Prague applies the EIP-7623 calldata floor (21000 + 10 per calldata token); rows with floorBinds = true cost the floor, not their execution gas, and would cost less on a Cancun chain (see besu.json)",
      },
      contracts: "onchain/contracts/v4/RegistriesV4.sol (solc-js 0.8.28, optimizer 200 runs, default EVM version)",
      oneOffGas: {
        deploy: deployGas,
        registerDID_issuer: gasRow(reg[0]),
        registerDID_verifierWithOrigin: gasRow(reg[1]),
        publishAccreditation_first: gasRow(acc[0]),
        publishAccreditation_renewal: gasRow(acc[1]),
        publishKemKey_first: gasRow(kem[0]),
        publishKemKey_rotation: gasRow(kem[1]),
        label: "[M] gasUsed from receipts; calldata facts and the EIP-7623 floor [S] from the transaction input",
      },
      publishEpoch: {
        first: gasRow(ep[0]),
        later: distribution(later),
        laterWithNewRevRoot: laterSplit(ep, revRootChanged, true),
        laterWithSameRevRoot: laterSplit(ep, revRootChanged, false),
        perEpoch: ep.map((w, i) => ({ epoch: i + 1, revRootChanged: revRootChanged[i] ?? null, ...gasRow(w) })),
        note: "gas does not depend on tree size: the registry stores two 32-byte roots, a 32-byte signature hash and a window. Every epoch has a new issuance root; every second epoch also has a new revRoot (writing an unchanged slot costs less).",
        label: "[M]",
      },
      perDay: cadences,
      accreditationRenewal: {
        maxValiditySec: MAX_ACCREDITATION_SEC,
        gasPerRenewal: accLater,
        gasPerDayAmortized: accLater === null ? null : accLater / (MAX_ACCREDITATION_SEC / 86400),
        label: "[S] one renewal per 30-day accreditation window (D-014), per issuer",
      },
      writes: ws.map((w) => ({ contract: w.contract, method: w.method, ...gasRow(w) })),
    };
    const file = outFile(a, "anchor");
    writeJson(file, result);
    log(`wrote ${relRepo(file)}: first publishEpoch ${first} gas, later median ${laterMedian} gas`);
  } finally {
    world.stop();
  }
}

// ---------------------------------------------------------------------------------------
// verifier
// ---------------------------------------------------------------------------------------

interface PassSample {
  variant: string;
  pass: number;
  index: number;
  totalMs: number;
  chainMs: number;
  chainCalls: number;
  rpcRequests: number;
  mlDsaMs: number;
  mlDsaVerifyCalls: number;
  mlKemMs: number;
  otherMs: number;
  byMethod: Record<string, { calls: number; ms: number }>;
  rpcByMethod: Record<string, number>;
}

async function verifierParent(a: Args): Promise<void> {
  const port = a.port ?? 8752;
  await assertPortFree(port);
  log(`verifier: starting Anvil on 127.0.0.1:${port} in the parent process (not pinned)`);
  const anvil = await startAnvil(port);
  const t0 = Date.now();
  const file = outFile(a, "verifier");
  try {
    const env = {
      ...process.env,
      [CHILD_ENV]: "verifier",
      PQID_E4_RPC: anvil.rpcUrl,
      PQID_E4_ANVIL_PID: String(anvil.proc.pid ?? ""),
    };
    if (a.noPin) {
      await verifierMeasure(a, anvil.rpcUrl, { method: "none (--no-pin)", pinned: false }, anvil.proc.pid ?? null);
      return;
    }
    log("verifier: re-launching the measurement pinned to CPU 0");
    const launch = await relaunchPinned(HERE, process.argv.slice(2), env);
    const ok = fs.existsSync(file) && fs.statSync(file).mtimeMs >= t0;
    if (launch.exitCode !== 0 || !ok) {
      throw new Error(`pinned verifier run failed (exit ${String(launch.exitCode)}, output ${ok ? "written" : "missing"})`);
    }
  } finally {
    anvil.stop();
  }
}

async function verifierChild(a: Args): Promise<void> {
  const rpc = process.env["PQID_E4_RPC"];
  if (!rpc) throw new Error("verifier child needs PQID_E4_RPC");
  const anvilPid = Number(process.env["PQID_E4_ANVIL_PID"] ?? "");
  const method =
    process.platform === "win32" ? 'cmd.exe /d /s /c "start "" /b /wait /affinity 1 node ..."' : "taskset -c 0 node ...";
  await verifierMeasure(a, rpc, { method, pinned: true }, Number.isSafeInteger(anvilPid) && anvilPid > 0 ? anvilPid : null);
}

async function verifierMeasure(
  a: Args,
  rpcUrl: string,
  pin: { method: string; pinned: boolean },
  anvilPid: number | null
): Promise<void> {
  const head = header(a, "verifier");
  const self = readAffinity(process.pid);
  const anvilAff: AffinityReadBack | null = anvilPid ? readAffinity(anvilPid) : null;
  log(`verifier: affinity read-back ${self.value ?? self.error} (cpus ${JSON.stringify(self.cpus)})`);
  if (pin.pinned && !(self.cpus && self.cpus.length === 1 && self.cpus[0] === 0)) {
    throw new Error(`pinning failed: read-back ${JSON.stringify(self)}`);
  }
  const P = (a.n ?? [])[0] ?? a.p ?? (a.dry ? 5 : 200);
  const passes = a.passes ?? (a.dry ? 1 : 3);
  const warmup = Math.min(P, a.warmup ?? (a.dry ? 2 : 5));
  const H = Math.max(1, Math.min(a.holders ?? (a.dry ? 2 : 4), P, 28));

  const world = await worldOnRpc(rpcUrl);
  try {
    log(`verifier: issuer, ${H} holders, epoch, verifier`);
    const issuer = await world.addIssuer("e4-issuer");
    const holders: HolderWalletV4[] = [];
    for (let h = 0; h < H; h++) {
      const w = await world.addHolder();
      await world.issue(issuer, w, { birthDate: 19900101 + h });
      holders.push(w);
    }
    await world.publishEpoch(issuer);
    const base = await world.addVerifier("e4-verifier");
    const timed = timedLedger(world.ledger);
    const verifier = new VerifierV4({ ...base.opts, ledger: timed.proxy });
    // Sessions run on the verifier's clock (world's ManualClock, not moved during the run), so
    // untimed pre-generation cannot expire them. The cached-reads verifier shares this store.
    const store: VerifierSessionStore = verifier.sessions;
    const cached = cachedLedger(timed.proxy);
    const verifierCached = new VerifierV4({ ...base.opts, ledger: cached.proxy });
    replaceSessionStore(verifierCached, store);

    log(`verifier: pre-generating ${P} presentations (proving is not timed)`);
    const replies: SessionReplyV4[] = [];
    const pres: PresentationV4[] = [];
    const tGen = nowNs();
    for (let i = 0; i < P; i++) {
      const req = await verifier.newRequest({ predicate: "age_gte", threshold: 18, typeId: DEFAULT_TYPE_ID });
      const { reply, presentation } = await (holders[i % H] as HolderWalletV4).present(req);
      replies.push(reply);
      pres.push(presentation);
      if ((i + 1) % 10 === 0 || i + 1 === P) log(`verifier: ${i + 1}/${P} presentations`);
    }
    const pregenMs = msSince(tGen);
    const snap = snapshotSessions(store);

    const provider = providerOf(world.ledger);
    const rpcCount = countRpc(provider);
    const hooks = hookPqcCrypto();
    const origGetOption = provider._getOption;

    const runPass = async (variant: string, pass: number, count: number, record: boolean): Promise<PassSample[]> => {
      const v = variant === "cachedReads" ? verifierCached : verifier;
      if (variant === "noBatchStall") disableBatchStall(provider);
      const out: PassSample[] = [];
      try {
        for (let i = 0; i < count; i++) {
          timed.reset();
          hooks.reset();
          rpcCount.reset();
          const t0 = nowNs();
          const d = await v.verifyReply(replies[i] as SessionReplyV4);
          const total = msSince(t0);
          if (!d.accepted) throw new Error(`presentation ${i} rejected (${variant}): ${d.reasons.join("; ")}`);
          if (!record) continue;
          const mlDsaMs = hooks.stats.mlDsaVerifyMs + hooks.stats.mlDsaImportMs;
          out.push({
            variant,
            pass,
            index: i,
            totalMs: total,
            chainMs: timed.stats.ms,
            chainCalls: timed.stats.calls,
            rpcRequests: rpcCount.get(),
            mlDsaMs,
            mlDsaVerifyCalls: hooks.stats.mlDsaVerifyCalls,
            mlKemMs: hooks.stats.mlKemDecapsMs,
            otherMs: total - timed.stats.ms - mlDsaMs - hooks.stats.mlKemDecapsMs,
            byMethod: structuredClone(timed.stats.byMethod),
            rpcByMethod: rpcCount.byMethod(),
          });
        }
      } finally {
        provider._getOption = origGetOption;
        restoreSessions(store, snap);
      }
      return out;
    };

    const variants = ["asShipped", "noBatchStall", "cachedReads"] as const;
    log(`verifier: warm-up (${warmup} presentations per variant, not recorded)`);
    for (const v of variants) await runPass(v, 0, warmup, false);
    const samples: PassSample[] = [];
    for (let pass = 1; pass <= passes; pass++) {
      for (const v of variants) {
        log(`verifier: pass ${pass}/${passes}, ${v}`);
        samples.push(...(await runPass(v, pass, P, true)));
      }
    }
    hooks.uninstall();
    rpcCount.stop();

    log("verifier: isolated components (Groth16 verify, ML-DSA-44 verify of the epoch statement)");
    const snarkjs = await import("snarkjs");
    const vkey = JSON.parse(fs.readFileSync(VKEY_V4, "utf8")) as unknown;
    const g16: number[] = [];
    const mldsa: number[] = [];
    for (let pass = 1; pass <= passes; pass++) {
      for (const p of pres) {
        const t0 = nowNs();
        const ok = await snarkjs.groth16.verify(vkey as never, p.publicSignals, p.proof);
        g16.push(msSince(t0));
        if (!ok) throw new Error("Groth16 component check failed");
        const { signature, ...fields } = p.epochStatement;
        const msg = epochMessage(fields);
        const sig = Buffer.from(signature, "hex");
        const t1 = nowNs();
        const ok2 = mlDsaVerify(issuer.pk, msg, sig);
        mldsa.push(msSince(t1));
        if (!ok2) throw new Error("ML-DSA component check failed");
      }
    }

    const summarize = (variant: string) => {
      const s = samples.filter((x) => x.variant === variant);
      const total = s.map((x) => x.totalMs);
      const sumMs = total.reduce((x, y) => x + y, 0);
      const byMethod: Record<string, { calls: number; ms: number }> = {};
      const rpcByMethod: Record<string, number> = {};
      for (const x of s) {
        for (const [m, b] of Object.entries(x.byMethod)) {
          const t = (byMethod[m] ??= { calls: 0, ms: 0 });
          t.calls += b.calls;
          t.ms += b.ms;
        }
        for (const [m, c] of Object.entries(x.rpcByMethod)) rpcByMethod[m] = (rpcByMethod[m] ?? 0) + c;
      }
      return {
        samples: s.length,
        totalMs: distribution(total),
        presentationsPerSecFromMedian: Math.round((1000 / distribution(total).median) * 100) / 100,
        presentationsPerSecAggregate: Math.round((s.length / (sumMs / 1000)) * 100) / 100,
        chainMs: distribution(s.map((x) => x.chainMs)),
        mlDsaMs: distribution(s.map((x) => x.mlDsaMs)),
        mlKemDecapsMs: distribution(s.map((x) => x.mlKemMs)),
        otherMs: distribution(s.map((x) => x.otherMs)),
        chainCallsPerPresentation: distribution(s.map((x) => x.chainCalls)),
        rpcRequestsPerPresentation: distribution(s.map((x) => x.rpcRequests)),
        rpcMethodsMeanPerPresentation: Object.fromEntries(Object.entries(rpcByMethod).map(([m, c]) => [m, c / s.length])),
        mlDsaVerifyCallsPerPresentation: distribution(s.map((x) => x.mlDsaVerifyCalls)),
        chainMsByMethodMeanPerPresentation: Object.fromEntries(
          Object.entries(byMethod).map(([m, b]) => [m, { callsPerPresentation: b.calls / s.length, msPerPresentation: b.ms / s.length }])
        ),
      };
    };

    const result = {
      ...head,
      finishedUtc: new Date().toISOString(),
      pinning: {
        requested: "one core: CPU 0 (affinity mask 0x1)",
        method: pin.method,
        pinned: pin.pinned,
        readBack: self,
        anvilNode: {
          note: "Anvil was started by the unpinned parent process, so the ledger node is not confined to the verifier's core",
          readBack: anvilAff,
        },
        deviation:
          process.platform === "win32"
            ? "native Windows host (DECISIONS D-001): not pinned (docs/BENCHMARK_POLICY.md allows only the power-state query as a Windows call); the pinned series runs on Linux with taskset -c 0 and /proc/<pid>/status"
            : "Linux: taskset -c 0, read back from /proc/<pid>/status",
      },
      setup: {
        chain: "Anvil, automine, started by the parent process",
        presentations: P,
        holders: H,
        passes,
        warmupPerVariant: warmup,
        policy: { predicate: "age_gte", threshold: 18, typeId: DEFAULT_TYPE_ID },
        keyLabel: KEY_LABEL_V4,
        pregenerationMs: pregenMs,
        sessionStore: "the verifier's own VerifierSessionStore (TTL on the verifier's clock, which does not move during the run); the cached-reads verifier shares it",
        sessionReuse:
          "the open-session map is copied before the first pass and put back after each pass, so every variant verifies the same P replies as fresh sessions",
      },
      variants: {
        asShipped: "LedgerV4 as shipped: ethers JsonRpcProvider with its default batchStallTime (10 ms per request batch)",
        noBatchStall: "same verifier; the harness sets the provider's batchStallTime to 0 for this pass (client setting, not package code)",
        cachedReads: "every LedgerV4 read served from an in-memory cache after its first call (isolates the non-chain cost)",
      },
      split: {
        chainMs: "outermost LedgerV4 reads (timed by a Proxy on the instance)",
        mlDsaMs: "node:crypto verify with an ML-DSA-44 key plus the ML-DSA public-key import (pqc.ts mlDsaVerify), hooked on the node:crypto module object",
        mlKemDecapsMs: "node:crypto decapsulate (ML-KEM-768)",
        otherMs: "the rest: Groth16 verify, Poseidon hashing (issuerKeyHash, policyHash, stmtCode), AES-GCM, JSON and checks [S] by subtraction",
      },
      results: Object.fromEntries(variants.map((v) => [v, summarize(v)])),
      isolatedComponents: {
        groth16VerifyMs: distribution(g16),
        mlDsa44VerifyEpochStatementMs: distribution(mldsa),
        note: "run after the passes on the same P presentations, same process and pinning; snarkjs.groth16.verify is the call the verifier makes",
      },
      samples: samples.map((s) => ({
        variant: s.variant,
        pass: s.pass,
        index: s.index,
        totalMs: s.totalMs,
        chainMs: s.chainMs,
        mlDsaMs: s.mlDsaMs,
        mlKemMs: s.mlKemMs,
        otherMs: s.otherMs,
        rpcRequests: s.rpcRequests,
      })),
    };
    const file = outFile(a, "verifier");
    writeJson(file, result);
    const r = summarize("asShipped");
    log(`wrote ${relRepo(file)}: asShipped median ${r.totalMs.median} ms/presentation, ${r.presentationsPerSecFromMedian}/s`);
  } finally {
    world.stop();
  }
}

// ---------------------------------------------------------------------------------------
// besu
// ---------------------------------------------------------------------------------------

interface Target {
  name: string;
  url: string;
  world: World;
  writes: RecordedWrite[];
  issuerDid: string;
  issuerController: string;
  verifier: VerifierIdentity;
  noStall: LedgerV4;
  /** Last KEM statement notBefore posted for the verifier (kemMonotonic needs it to increase). */
  lastKemNotBefore: number;
}

async function setClockToChain(world: World): Promise<void> {
  const t = await world.ledger.blockTimestamp();
  if (t > world.clock.nowSec()) world.clock.set(t);
}

async function setupTarget(name: string, url: string): Promise<Target> {
  log(`besu: deploying the v4 registries on ${name}`);
  const world = await worldOnRpc(url);
  const rec = recordingLedger(world.ledger);
  swapWorldLedger(world, rec.proxy);
  await setClockToChain(world);
  const issuer = await world.addIssuer(`e4-${name}-issuer`);
  await setClockToChain(world);
  await world.publishEpoch(issuer);
  await setClockToChain(world);
  const v = await world.addVerifier(`e4-${name}-verifier`);
  const lastKemNotBefore = world.clock.nowSec();
  const noStall = await LedgerV4.connect(url, world.ledger.addresses, world.ledger.deployment.fromBlock);
  disableBatchStall(providerOf(noStall));
  return {
    name,
    url,
    world,
    writes: rec.writes,
    issuerDid: issuer.did,
    issuerController: issuer.controller,
    verifier: v.opts.identity,
    noStall,
    lastKemNotBefore,
  };
}

/** Fork milestones of the local QBFT genesis written by scripts/besu/setup_qbft.sh (public config only). */
function besuGenesisConfig(): Record<string, unknown> | null {
  const f = path.join(REPO_ROOT, ".scratch-v4", "besu", "networkFiles", "genesis.json");
  if (!fs.existsSync(f)) return null;
  const cfg = (JSON.parse(fs.readFileSync(f, "utf8")) as { config?: Record<string, unknown> }).config ?? {};
  return Object.fromEntries(Object.entries(cfg).filter(([k]) => /Block$|Time$|^chainId$|^zeroBaseFee$|^qbft$/.test(k)));
}

const READ_CALLS = ["resolveDidRecord", "getPopSignature", "latestAccreditation", "currentEpoch", "latestKemKey", "getMinAnchorInterval"] as const;
type ReadCall = (typeof READ_CALLS)[number];

function readCall(t: Target, L: LedgerV4, c: ReadCall): Promise<unknown> {
  switch (c) {
    case "resolveDidRecord":
      return L.resolveDidRecord(t.issuerDid, t.issuerController);
    case "getPopSignature":
      return L.getPopSignature(t.issuerDid, t.issuerController);
    case "latestAccreditation":
      return L.latestAccreditation(t.issuerDid);
    case "currentEpoch":
      return L.currentEpoch(t.issuerDid, t.issuerController);
    case "latestKemKey":
      return L.latestKemKey(t.verifier.did, t.verifier.controller);
    case "getMinAnchorInterval":
      return L.getMinAnchorInterval();
  }
}

async function publishKemFixedGas(t: Target): Promise<{ ms: number; gasUsed: number; blockNumber: number; txHash: string }> {
  const id = t.verifier;
  await setClockToChain(t.world);
  const now = Math.max(t.world.clock.nowSec(), t.lastKemNotBefore + 1);
  t.lastKemNotBefore = now;
  const statement = verifierKemMessage({
    verifier: id.did,
    controller: id.controller,
    chainId: await t.world.ledger.chainId(),
    registry: t.world.ledger.addresses.verifierKemRegistry.toLowerCase(),
    kemAlg: KEM_ALG,
    kemPkSha3: sha3_256(id.kem.publicKey).toString("hex"),
    notBefore: now,
    notAfter: now + 365 * 24 * 3600,
  });
  const signature = mlDsaSign(id.sk, statement);
  const t0 = nowNs();
  const r = await t.world.ledger.publishKemKey(
    id.account,
    { did: id.did, kemPk: id.kem.publicKey, statement, signature },
    { gasLimit: 1_000_000 }
  );
  return { ms: msSince(t0), gasUsed: r.gasUsed, blockNumber: r.blockNumber, txHash: r.txHash };
}

async function besuCmd(a: Args): Promise<void> {
  const R = (a.n ?? [])[0] ?? a.r ?? (a.dry ? 5 : 200);
  const W = a.w ?? (a.dry ? 3 : 20);
  const port = a.port ?? 8753;
  const head = header(a, "besu");
  let besuClient: string;
  try {
    besuClient = String(await rawRpc(a.besuRpc, "web3_clientVersion"));
  } catch (e) {
    throw new Error(`Besu JSON-RPC not reachable at ${a.besuRpc} (${(e as Error).message}); run scripts/besu/setup_qbft.sh up first`);
  }
  if (!/^besu\//i.test(besuClient)) throw new Error(`${a.besuRpc} is not a Besu node (${besuClient})`);
  await assertPortFree(port);
  const anvil: AnvilHandle = await startAnvil(port);
  const targets: Target[] = [];
  try {
    targets.push(await setupTarget("anvil", anvil.rpcUrl));
    targets.push(await setupTarget("besu-qbft-4", a.besuRpc));

    // RPC requests per call (as shipped), counted once per target.
    const rpcPerCall: Record<string, Record<string, { requests: number; byMethod: Record<string, number> }>> = {};
    for (const t of targets) {
      const c = countRpc(providerOf(t.world.ledger));
      const row: Record<string, { requests: number; byMethod: Record<string, number> }> = {};
      for (const call of READ_CALLS) {
        c.reset();
        await readCall(t, t.world.ledger, call);
        row[call] = { requests: c.get(), byMethod: c.byMethod() };
      }
      c.stop();
      rpcPerCall[t.name] = row;
    }

    // Reads: R rounds, targets and client variants interleaved within each round; 2 warm-up rounds.
    // samples["<target>|<series>"] = ms per call
    const samples = new Map<string, number[]>();
    const push = (key: string, ms: number) => {
      const s = samples.get(key);
      if (s) s.push(ms);
      else samples.set(key, [ms]);
    };
    const series = (key: string): number[] => samples.get(key) ?? [];
    log(`besu: ${R} read rounds x ${READ_CALLS.length} calls x ${targets.length} targets x 2 client variants`);
    for (let r = -2; r < R; r++) {
      for (const t of targets) {
        for (const variant of ["asShipped", "noBatchStall"] as const) {
          const L = variant === "asShipped" ? t.world.ledger : t.noStall;
          for (const call of READ_CALLS) {
            const t0 = nowNs();
            await readCall(t, L, call);
            const ms = msSince(t0);
            if (r >= 0) push(`${t.name}|${variant}|${call}`, ms);
          }
        }
        const data = t.world.ledger.rawContract("DIDRegistryV4").interface.encodeFunctionData("resolve", [t.issuerDid, t.issuerController]);
        const to = t.world.ledger.addresses.didRegistry;
        const t1 = nowNs();
        await rawRpc(t.url, "eth_blockNumber");
        const m1 = msSince(t1);
        const t2 = nowNs();
        await rawRpc(t.url, "eth_call", [{ to, data }, "latest"]);
        const m2 = msSince(t2);
        if (r >= 0) {
          push(`${t.name}|raw|eth_blockNumber`, m1);
          push(`${t.name}|raw|eth_call_resolve`, m2);
        }
      }
      if (r >= 0 && ((r + 1) % 50 === 0 || r + 1 === R)) log(`besu: read round ${r + 1}/${R}`);
    }

    // Writes: submit to receipt with a fixed gas limit (no estimation), W per target, alternating.
    log(`besu: ${W} KEM-key writes and ${W} value transfers per target`);
    type WriteLog = { kemPublishMs: number[]; transferMs: number[]; gas: number[]; blocks: number[]; calldata: Record<string, unknown> | null };
    const writes: Record<string, WriteLog> = {};
    for (const t of targets) writes[t.name] = { kemPublishMs: [], transferMs: [], gas: [], blocks: [], calldata: null };
    for (let i = 0; i < W; i++) {
      for (const t of targets) {
        const w = writes[t.name] as WriteLog;
        const k = await publishKemFixedGas(t);
        w.kemPublishMs.push(k.ms);
        w.gas.push(k.gasUsed);
        w.blocks.push(k.blockNumber);
        if (i === 0) w.calldata = await calldataInfo(t.url, k.txHash, k.gasUsed);
        // an ordinary (non-precompile) address with no code
        const to = "0x" + createHash("sha256").update(`pqid-e4-transfer:${t.name}:${i}`).digest("hex").slice(0, 40);
        const t0 = nowNs();
        await t.world.ledger.fund(to, "0.001");
        w.transferMs.push(msSince(t0));
      }
    }

    // Block time and finality (Besu): block intervals and hash stability of the write blocks.
    const besuT = targets[1] as Target;
    const latest = Number(BigInt(String(await rawRpc(besuT.url, "eth_blockNumber"))));
    const tsOf = async (url: string, b: number) =>
      (await rawRpc(url, "eth_getBlockByNumber", ["0x" + b.toString(16), false])) as { timestamp: string; hash: string };
    const from = Math.max(1, latest - 60);
    const stamps: number[] = [];
    for (let b = from; b <= latest; b++) stamps.push(Number(BigInt((await tsOf(besuT.url, b)).timestamp)));
    const intervals = stamps.slice(1).map((s, i) => s - (stamps[i] as number));
    const besuWriteBlocks = (writes[besuT.name] as { blocks: number[] }).blocks;
    const hashesAtWrite: Array<{ block: number; hash: string }> = [];
    for (const b of besuWriteBlocks) hashesAtWrite.push({ block: b, hash: (await tsOf(besuT.url, b)).hash });
    let validators: unknown = null;
    try {
      validators = await rawRpc(besuT.url, "qbft_getValidatorsByBlockNumber", ["latest"]);
    } catch (e) {
      validators = `unavailable: ${(e as Error).message}`;
    }
    const peers = Number(BigInt(String(await rawRpc(besuT.url, "net_peerCount"))));
    // re-read the write blocks after later blocks exist: a QBFT block never changes once committed
    const reread = [];
    for (const h of hashesAtWrite) reread.push({ ...h, hashLater: (await tsOf(besuT.url, h.block)).hash });
    const latestAfter = Number(BigInt(String(await rawRpc(besuT.url, "eth_blockNumber"))));

    const summarizeReads = (name: string) =>
      Object.fromEntries(
        (["asShipped", "noBatchStall"] as const).map((variant) => [
          variant,
          Object.fromEntries(READ_CALLS.map((c) => [c, distribution(series(`${name}|${variant}|${c}`))])),
        ])
      );

    const result = {
      ...head,
      finishedUtc: new Date().toISOString(),
      networks: {
        anvil: {
          client: String(await rawRpc(anvil.rpcUrl, "web3_clientVersion")),
          chainId: await (targets[0] as Target).world.ledger.chainId(),
          consensus: "none (single dev node, automine: one block per transaction)",
          finality: "[A] immediate by construction (single node, no forks)",
          evm: await evmInfo(anvil.rpcUrl),
        },
        besu: {
          client: besuClient,
          chainId: await besuT.world.ledger.chainId(),
          consensus: "QBFT, 4 validators, blockperiodseconds 2, all on 127.0.0.1 (scripts/besu/setup_qbft.sh)",
          evm: { ...(await evmInfo(besuT.url)), genesisConfig: besuGenesisConfig() },
          validators,
          node1PeerCount: peers,
          blockIntervalSec: intervals.length > 0 ? distribution(intervals) : null,
          blockIntervalWindow: { fromBlock: from, toBlock: latest },
          finality:
            "[A] QBFT gives immediate finality: a committed block is final and is never reorganised (Besu QBFT docs); [M] check below: the block hash of every write block re-read later",
          finalityCheck: {
            writeBlocks: reread.length,
            unchangedHashes: reread.filter((x) => x.hash === x.hashLater).length,
            latestBlockAtReread: latestAfter,
          },
        },
      },
      method: {
        reads:
          "R rounds; in each round, for each target and client variant, the six LedgerV4 reads a verifier or wallet makes, timed one by one (2 unrecorded warm-up rounds)",
        clientVariants: {
          asShipped: "LedgerV4 from worldOnRpc (ethers JsonRpcProvider, default batchStallTime 10 ms)",
          noBatchStall: "LedgerV4.connect to the same registries with the provider's batchStallTime set to 0 by the harness",
        },
        raw: "direct JSON-RPC over fetch (no ethers): eth_blockNumber and eth_call of DIDRegistryV4.resolve",
        writes:
          "submit to receipt: LedgerV4.publishKemKey with a fixed gas limit (no estimation) and LedgerV4.fund (a value transfer); ethers polls receipts every 100 ms (ledger.ts makeProvider)",
      },
      rpcRequestsPerCall: rpcPerCall,
      reads: Object.fromEntries(targets.map((t) => [t.name, summarizeReads(t.name)])),
      rawRpc: Object.fromEntries(
        targets.map((t) => [
          t.name,
          {
            eth_blockNumber: distribution(series(`${t.name}|raw|eth_blockNumber`)),
            eth_call_resolve: distribution(series(`${t.name}|raw|eth_call_resolve`)),
          },
        ])
      ),
      writeLatency: Object.fromEntries(
        targets.map((t) => {
          const w = writes[t.name] as WriteLog;
          return [
            t.name,
            {
              publishKemKeySubmitToReceiptMs: W > 0 ? distribution(w.kemPublishMs) : null,
              valueTransferSubmitToReceiptMs: W > 0 ? distribution(w.transferMs) : null,
              publishKemKeyGas: W > 0 ? distribution(w.gas) : null,
              publishKemKeyCalldata: w.calldata,
            },
          ];
        })
      ),
      setupWriteGas: Object.fromEntries(
        targets.map((t) => [
          t.name,
          {
            deploy: t.world.ledger.deployment.deployGas,
            writes: t.writes.map((w) => ({ method: `${w.contract}.${w.method}`, gasUsed: w.gasUsed, msIncludingEstimate: w.ms })),
          },
        ])
      ),
    };
    const file = outFile(a, "besu");
    writeJson(file, result);
    log(`wrote ${relRepo(file)}`);
  } finally {
    for (const t of targets) {
      t.noStall.destroy();
      t.world.stop();
    }
    anvil.stop();
  }
}

// ---------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------

async function main(): Promise<void> {
  if (fs.existsSync(BENCH_RUNNING)) {
    throw new Error("results/v4/bench/RUNNING exists: a timed benchmark is active; E4 must not run now");
  }
  const a = parseArgs(process.argv.slice(2));
  switch (a.sub) {
    case "trees":
      return treesParent(a);
    case "trees-worker":
      return treesWorker(a);
    case "anchor":
      return anchorCmd(a);
    case "verifier":
      return process.env[CHILD_ENV] === "verifier" ? verifierChild(a) : verifierParent(a);
    case "besu":
      return besuCmd(a);
  }
}

main().then(
  () => process.exit(0),
  (e: unknown) => {
    console.error(`[e4] FAILED: ${e instanceof Error ? (e.stack ?? e.message) : String(e)}`);
    process.exit(1);
  }
);
