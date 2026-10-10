import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import type { JsonRpcProvider } from "ethers";
import { startAnvil, type AnvilHandle } from "@pqid/ledger";
import type { World } from "@pqid/v4/world";
import type { LedgerV4 } from "@pqid/v4/ledger";
import type { IssuerV4 } from "@pqid/v4/issuer";
import type { HolderWalletV4 } from "@pqid/v4/wallet";
import type { VerifierV4 } from "@pqid/v4/verifier";
import type { ProofRequestV4, SessionReplyV4 } from "@pqid/v4/session";
import { DEFAULT_TYPE_ID } from "@pqid/v4/constants";
import { REPO_ROOT } from "../bench/lib.ts";
import { assertPortFree, rawRpc, worldOnRpc, evmInfo } from "../scale_lib.ts";
import { connectClientLedger, endpointLabel, type EndpointLabel, type ProviderOptionsRecord, type RpcTrace } from "../lib/rpc_trace.ts";
import { PORTS } from "../lib/ports.ts";
import { readPidFiles } from "../lib/quiesce.ts";
import { deployReadBatch, installMulticall, type MulticallHandle, type ReadBatchDeployment } from "./contract.ts";
import { captureRequests, type Capture } from "./wire.ts";
import { clientSpec, type ClientName } from "./variants.ts";
import type { SixReadIds } from "./plans.ts";

/**
 * Chain targets and the v4 world of the chain-read series (docs/v4/CHAINREAD.md):
 * - anvil: a fresh Anvil started here on the D-034 port (8770 in WSL, 8771 on Windows), with the
 *   version checked against --expect-anvil;
 * - besu: the 4-validator QBFT network of scripts/besu/setup_qbft.sh, already up (RPC 18545).
 * World: worldOnRpc (exactly World.create's steps on an external node), 1 issuer, H holders
 * (default 4, birth dates as E4), one epoch, one verifier with an ML-KEM key, then ChainReadBatch.
 * The ManualClock is set to the chain's time before each write (Besu produces blocks on its own
 * clock) and never moves during the series, so sessions and validity windows cannot expire.
 */

export type TargetName = "anvil" | "besu";

export interface TargetNode {
  name: TargetName;
  url: string;
  /** D-034 endpoint label (rpc_trace endpointLabel): "loopback, same host" for 127.0.0.1. */
  endpoint: EndpointLabel;
  anvil: AnvilHandle | null;
  clientVersion: string;
  /** Pids of this run's own chain processes (Anvil child; Besu JVMs from the pid files). */
  ownPids: number[];
  ownPorts: number[];
  besuPidFiles: string[];
  evm: Record<string, unknown>;
}

export const BESU_DIR = path.join(REPO_ROOT, ".scratch-v4", "besu");

export function defaultAnvilPort(): number {
  return process.platform === "win32" ? PORTS.chainReadAnvilWindows : PORTS.chainReadAnvilWsl;
}

/** Start or attach to the target node. */
export async function startTarget(target: TargetName, opts: { port: number; besuRpc: string; expectAnvil: string | null }): Promise<TargetNode> {
  if (target === "anvil") {
    await assertPortFree(opts.port);
    const anvil = await startAnvil(opts.port);
    try {
      const clientVersion = String(await rawRpc(anvil.rpcUrl, "web3_clientVersion"));
      if (opts.expectAnvil && !clientVersion.includes(`/v${opts.expectAnvil}`)) {
        throw new Error(`Anvil ${clientVersion} is not the expected ${opts.expectAnvil} (D-034 toolchain; put the pinned anvil first on PATH)`);
      }
      return {
        name: "anvil",
        url: anvil.rpcUrl,
        endpoint: endpointLabel(anvil.rpcUrl),
        anvil,
        clientVersion,
        ownPids: anvil.proc.pid ? [anvil.proc.pid] : [],
        ownPorts: [opts.port],
        besuPidFiles: [],
        evm: await evmInfo(anvil.rpcUrl),
      };
    } catch (e) {
      anvil.stop();
      throw e;
    }
  }
  let clientVersion: string;
  try {
    clientVersion = String(await rawRpc(opts.besuRpc, "web3_clientVersion"));
  } catch (e) {
    throw new Error(`Besu JSON-RPC not reachable (${(e as Error).message}); run scripts/besu/setup_qbft.sh up first`);
  }
  if (!/^besu\//i.test(clientVersion)) throw new Error(`the --besu-rpc node is not Besu (${clientVersion})`);
  const pidFiles = [1, 2, 3, 4].map((i) => path.join(BESU_DIR, `node-${i}.pid`));
  const endpoint = endpointLabel(opts.besuRpc);
  if (endpoint !== "loopback, same host") throw new Error("the Besu target must be the local QBFT network on 127.0.0.1 (D-034: a public endpoint is used only by Kushal)");
  return {
    name: "besu",
    url: opts.besuRpc,
    endpoint,
    anvil: null,
    clientVersion,
    ownPids: readPidFiles(pidFiles),
    ownPorts: [...PORTS.besuQbft],
    besuPidFiles: pidFiles.map((f) => path.relative(REPO_ROOT, f).split(path.sep).join("/")),
    evm: { ...(await evmInfo(opts.besuRpc)), genesisConfig: besuGenesisConfig() },
  };
}

/** Fork milestones of the local QBFT genesis written by setup_qbft.sh (public config only; as scale.ts). */
export function besuGenesisConfig(): Record<string, unknown> | null {
  const f = path.join(BESU_DIR, "networkFiles", "genesis.json");
  if (!fs.existsSync(f)) return null;
  const cfg = (JSON.parse(fs.readFileSync(f, "utf8")) as { config?: Record<string, unknown> }).config ?? {};
  return Object.fromEntries(Object.entries(cfg).filter(([k]) => /Block$|Time$|^chainId$|^zeroBaseFee$|^qbft$/.test(k)));
}

export interface TargetWorld {
  world: World;
  issuer: IssuerV4;
  holders: HolderWalletV4[];
  verifier: VerifierV4;
  helper: ReadBatchDeployment;
  ids: SixReadIds;
  chainId: number;
  registries: string[];
  fromBlock: number;
  setupMs: number;
}

async function setClockToChain(world: World): Promise<void> {
  const t = await world.ledger.blockTimestamp();
  if (t > world.clock.nowSec()) world.clock.set(t);
}

/** Registries, roles and the helper on the target (untimed set-up). */
export async function buildWorld(url: string, holdersN: number, log: (s: string) => void): Promise<TargetWorld> {
  const t0 = Date.now();
  const world = await worldOnRpc(url);
  try {
    await setClockToChain(world);
    const issuer = await world.addIssuer("cr-issuer");
    const holders: HolderWalletV4[] = [];
    for (let h = 0; h < holdersN; h++) {
      const w = await world.addHolder();
      await world.issue(issuer, w, { birthDate: 19900101 + h });
      holders.push(w);
    }
    await setClockToChain(world);
    await world.publishEpoch(issuer);
    await setClockToChain(world);
    const verifier = await world.addVerifier("cr-verifier");
    log("world: issuer, holders, epoch and verifier on chain; deploying ChainReadBatch");
    const helper = await deployReadBatch(world.ledger);
    const a = world.ledger.addresses;
    return {
      world,
      issuer,
      holders,
      verifier,
      helper,
      ids: {
        issuerDid: issuer.did,
        issuerController: issuer.controller,
        verifierDid: verifier.opts.identity.did,
        verifierController: verifier.opts.identity.controller,
      },
      chainId: await world.ledger.chainId(),
      registries: [a.didRegistry, a.accreditationRegistry, a.issuanceRootRegistry, a.verifierKemRegistry].map((x) => x.toLowerCase()),
      fromBlock: world.ledger.deployment.fromBlock,
      setupMs: Date.now() - t0,
    };
  } catch (e) {
    world.stop();
    throw e;
  }
}

export interface Pregenerated {
  replies: SessionReplyV4[];
  walletRequests: ProofRequestV4[];
  pregenMs: number;
}

export const POLICY = Object.freeze({ predicate: "age_gte" as const, threshold: 18, typeId: DEFAULT_TYPE_ID });

/** P verifier replies (proving untimed, unpinned) and P wallet requests (never answered). */
export async function pregenerate(tw: TargetWorld, P: number, log: (s: string) => void): Promise<Pregenerated> {
  const t0 = Date.now();
  const replies: SessionReplyV4[] = [];
  const walletRequests: ProofRequestV4[] = [];
  const H = tw.holders.length;
  for (let i = 0; i < P; i++) {
    const req = await tw.verifier.newRequest(POLICY);
    const { reply } = await (tw.holders[i % H] as HolderWalletV4).present(req);
    replies.push(reply);
    walletRequests.push(await tw.verifier.newRequest(POLICY));
    if ((i + 1) % 20 === 0 || i + 1 === P) log(`pre-generation: ${i + 1}/${P} presentations`);
  }
  return { replies, walletRequests, pregenMs: Date.now() - t0 };
}

// ---------------------------------------------------------------------------------------
// client ledgers
// ---------------------------------------------------------------------------------------

/** The HTTP agent a client's POSTs travel on (env.json records it per client). */
export interface AgentRecord {
  kind: "Node's global HTTP agent (as LedgerV4)" | "own http.Agent with the global agent's options";
  keepAlive: boolean;
  scheduling: string | null;
  /** Idle-socket timeout, ms (Node 24's global agent: 5000; a pooled socket idle longer is closed). */
  timeoutMs: number | null;
  noDelay: boolean | null;
}

type AgentOpts = { keepAlive?: boolean; scheduling?: "fifo" | "lifo"; timeout?: number; noDelay?: boolean };

/** The options of Node's global HTTP agent in this process (Node 24: keepAlive, lifo, timeout 5000 ms). */
export function globalAgentOptions(): AgentOpts {
  const g = http.globalAgent as unknown as { options?: AgentOpts; keepAlive?: boolean; scheduling?: "fifo" | "lifo" };
  const o = g.options ?? {};
  const scheduling = o.scheduling ?? g.scheduling;
  return {
    keepAlive: o.keepAlive ?? g.keepAlive ?? false,
    ...(scheduling !== undefined ? { scheduling } : {}),
    ...(typeof o.timeout === "number" ? { timeout: o.timeout } : {}),
    ...(typeof o.noDelay === "boolean" ? { noDelay: o.noDelay } : {}),
  };
}

/**
 * A dedicated agent with the options of Node's global agent, so a variant differs from the
 * shipped client in its ethers options only, not in its connection handling (idle timeout,
 * scheduling). Each variant keeps its own socket pool.
 */
export function agentLikeGlobal(): { agent: http.Agent; record: AgentRecord } {
  const o = globalAgentOptions();
  const agent = new http.Agent({ ...o, keepAlive: o.keepAlive ?? true });
  return { agent, record: agentRecord("own http.Agent with the global agent's options", o) };
}

export function agentRecord(kind: AgentRecord["kind"], o: AgentOpts = globalAgentOptions()): AgentRecord {
  return { kind, keepAlive: o.keepAlive ?? false, scheduling: o.scheduling ?? null, timeoutMs: o.timeout ?? null, noDelay: o.noDelay ?? null };
}

export interface Client {
  name: ClientName;
  label: "as shipped" | "variant, not shipped";
  ledger: LedgerV4;
  provider: JsonRpcProvider;
  /** Effective ethers options (rpc_trace describeProvider). */
  options: ProviderOptionsRecord;
  /** staticNetwork clients: the chain id was checked against the node's eth_chainId (untimed). */
  chainIdCheckedAgainstNode: boolean | null;
  /** HTTP agent of the client's POSTs. */
  agent: AgentRecord;
  trace: RpcTrace;
  capture: Capture;
  multicall: MulticallHandle | null;
  close: () => void;
}

/**
 * One traced client ledger (harness/v4/lib/rpc_trace.ts connectClientLedger: LedgerV4.connect,
 * then the variant's provider). Wrapper order on the provider, innermost first: round-trip trace,
 * multicall (H only), request capture. The shipped client keeps Node's global agent, as LedgerV4
 * does; every other client gets its own agent with the global agent's options (agentLikeGlobal:
 * keep-alive, lifo, the 5 s idle timeout of Node 24), so the agent behaves the same and only the
 * ethers options differ. New TCP connections are taken from the trace (per POST, http.connects),
 * so no agent is wrapped.
 */
export async function makeClient(url: string, tw: TargetWorld, name: ClientName, opts: { multicall: boolean }): Promise<Client> {
  const spec = clientSpec(name);
  const own = spec.shipped ? null : agentLikeGlobal();
  const agent = own?.agent ?? null;
  // staticNetwork: the world's chain id, checked by connectClientLedger against the node (untimed)
  const cl = await connectClientLedger(url, tw.world.ledger.addresses, tw.fromBlock, spec, {
    ...(spec.options.staticNetwork ? { chainId: tw.chainId } : {}),
    ...(agent ? { agent } : {}),
    trace: { keepRecords: true },
  });
  const trace = cl.trace as RpcTrace;
  const multicall = opts.multicall ? installMulticall(cl.provider, tw.helper.address, tw.registries) : null;
  const capture = captureRequests(cl.provider);
  // chainId() is cached per LedgerV4 instance (ledger.ts); read it once, untimed
  const cid = await cl.ledger.chainId();
  if (cid !== tw.chainId) throw new Error(`client ${name}: chain id ${cid} differs from the world's ${tw.chainId}`);
  trace.drain();
  capture.reset();
  return {
    name,
    label: spec.label,
    ledger: cl.ledger,
    provider: cl.provider,
    options: cl.options,
    chainIdCheckedAgainstNode: cl.chainIdCheckedAgainstNode,
    agent: own?.record ?? agentRecord("Node's global HTTP agent (as LedgerV4)"),
    trace,
    capture,
    multicall,
    close: () => {
      capture.detach();
      multicall?.detach();
      trace.detach();
      cl.ledger.destroy();
      agent?.destroy();
    },
  };
}
