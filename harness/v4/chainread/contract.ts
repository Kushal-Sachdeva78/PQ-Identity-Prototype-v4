import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { ContractFactory, Interface, JsonRpcProvider, getBytes, hexlify, type InterfaceAbi } from "ethers";
import { compileSolidityV4, type LedgerV4 } from "@pqid/v4/ledger";
import { REPO_ROOT } from "../bench/lib.ts";

/**
 * The multicall client variant ("variant, not shipped", docs/v4/CHAINREAD.md):
 * - ChainReadBatch (harness/v4/chainread/ReadBatch.sol), compiled with the repository's pinned
 *   solc-js 0.8.28 through compileSolidityV4 (the v4 registries' compiler settings) and deployed
 *   by the harness only, from a fresh role account the v4 ledger funds (so the deployer's nonce
 *   tracker inside LedgerV4 is never bypassed);
 * - installMulticall(provider): a run-time override of one provider's send() that queues the
 *   registry eth_calls issued in the same event-loop turn and sends them as ONE eth_call of
 *   ChainReadBatch.aggregate; each caller gets its own return data. A failed sub-call is re-sent
 *   alone (ethers then raises its usual error); this never happens on honest paths and is
 *   counted. eth_getLogs and everything else pass through unchanged.
 */

export const READ_BATCH_SOURCE = path.join(REPO_ROOT, "harness", "v4", "chainread", "ReadBatch.sol");
export const READ_BATCH_CONTRACT = "ChainReadBatch";

export interface CompiledReadBatch {
  abi: InterfaceAbi;
  bytecode: string;
  sourceSha256: string;
  bytecodeSha256: string;
  compiler: string;
}

let compiled: CompiledReadBatch | null = null;

/** Compile ReadBatch.sol (cached per process). */
export function compileReadBatch(): CompiledReadBatch {
  if (compiled) return compiled;
  const src = fs.readFileSync(READ_BATCH_SOURCE, "utf8");
  const out = compileSolidityV4({ "ReadBatch.sol": src });
  const c = out[READ_BATCH_CONTRACT];
  if (!c) throw new Error(`${READ_BATCH_CONTRACT} missing from solc output`);
  compiled = {
    abi: c.abi as InterfaceAbi,
    bytecode: c.bytecode,
    sourceSha256: createHash("sha256").update(fs.readFileSync(READ_BATCH_SOURCE)).digest("hex"),
    bytecodeSha256: createHash("sha256").update(getBytes(c.bytecode)).digest("hex"),
    compiler: "solc-js 0.8.28 via compileSolidityV4 (optimizer on, 200 runs; the v4 registries' settings)",
  };
  return compiled;
}

let iface: Interface | null = null;
function readBatchInterface(): Interface {
  iface ??= new Interface(compileReadBatch().abi);
  return iface;
}

export interface SubCall {
  to: string;
  data: string;
}

export interface SubResult {
  ok: boolean;
  data: string;
}

export function encodeAggregate(calls: readonly SubCall[]): string {
  return readBatchInterface().encodeFunctionData("aggregate", [calls.map((c) => [c.to, c.data])]);
}

export function decodeAggregate(hex: string): { blockNumber: bigint; results: SubResult[] } {
  const r = readBatchInterface().decodeFunctionResult("aggregate", hex);
  const blockNumber = BigInt(r[0] as bigint);
  const results = (r[1] as unknown as Array<[boolean, string]>).map((x) => ({ ok: Boolean(x[0]), data: hexlify(x[1]) }));
  return { blockNumber, results };
}

export interface ReadBatchDeployment {
  address: string;
  txHash: string;
  blockNumber: number;
  gasUsed: number;
  deployedBy: "fresh role account funded by LedgerV4.newRoleAccount";
  sourceSha256: string;
  bytecodeSha256: string;
  compiler: string;
}

/** Deploy ChainReadBatch on the ledger's chain from a fresh funded role account. */
export async function deployReadBatch(ledger: LedgerV4): Promise<ReadBatchDeployment> {
  const c = compileReadBatch();
  const account = await ledger.newRoleAccount("chainread-helper", "1");
  const provider = new JsonRpcProvider(ledger.rpcUrl, undefined, { cacheTimeout: -1 });
  provider.pollingInterval = 100;
  try {
    const wallet = account.connectTo(provider);
    const factory = new ContractFactory(c.abi, c.bytecode, wallet);
    const contract = await factory.deploy();
    const receipt = await contract.deploymentTransaction()?.wait();
    if (!receipt) throw new Error("ChainReadBatch deployment: no receipt");
    return {
      address: (await contract.getAddress()).toLowerCase(),
      txHash: receipt.hash,
      blockNumber: receipt.blockNumber,
      gasUsed: Number(receipt.gasUsed),
      deployedBy: "fresh role account funded by LedgerV4.newRoleAccount",
      sourceSha256: c.sourceSha256,
      bytecodeSha256: c.bytecodeSha256,
      compiler: c.compiler,
    };
  } finally {
    provider.destroy();
  }
}

// ---------------------------------------------------------------------------------------
// the multicall transport
// ---------------------------------------------------------------------------------------

type SendFn = (method: string, params: unknown[] | Record<string, unknown>) => Promise<unknown>;
interface SendHolder {
  send: SendFn;
}

export interface MulticallStats {
  /** Aggregate eth_calls sent. */
  aggregates: number;
  /** Registry eth_calls carried inside them. */
  subCalls: number;
  /** Sub-calls re-sent alone after a failed sub-call or a failed aggregate. */
  fallbacks: number;
  /** eth_calls that did not qualify (other target, block tag or fields) and went out unchanged. */
  passedThrough: number;
  /** Sub-calls per aggregate, in send order. */
  sizes: number[];
}

export interface MulticallHandle {
  readonly helper: string;
  stats(): MulticallStats;
  reset(): void;
  detach(): void;
}

const MULTICALL = Symbol.for("pqid.v4.chainread.multicall");

function plainCall(x: unknown): SubCall | null {
  if (!x || typeof x !== "object" || Array.isArray(x)) return null;
  const o = x as Record<string, unknown>;
  const keys = Object.keys(o).sort().join(",");
  if (keys !== "data,to") return null;
  if (typeof o["to"] !== "string" || typeof o["data"] !== "string") return null;
  return { to: o["to"].toLowerCase(), data: o["data"] };
}

/**
 * Aggregate a provider's registry eth_calls (see the module header). `targets` are the
 * contract addresses whose calls may be aggregated (the v4 registries). Install it after the
 * round-trip trace (so the aggregate is traced as one request) and before the request capture.
 */
export function installMulticall(provider: JsonRpcProvider, helper: string, targets: readonly string[]): MulticallHandle {
  const p = provider as unknown as SendHolder & { [MULTICALL]?: true };
  if (p[MULTICALL]) throw new Error("provider already has a multicall transport");
  const own = Object.getOwnPropertyDescriptor(p, "send");
  const inner = p.send;
  const allowed = new Set(targets.map((t) => t.toLowerCase()));
  const helperAddr = helper.toLowerCase();
  let stats: MulticallStats = { aggregates: 0, subCalls: 0, fallbacks: 0, passedThrough: 0, sizes: [] };
  let queue: Array<{ call: SubCall; resolve: (v: unknown) => void; reject: (e: unknown) => void }> = [];
  let timer: NodeJS.Timeout | null = null;

  const alone = (q: (typeof queue)[number]) => {
    stats.fallbacks++;
    inner.call(p, "eth_call", [{ to: q.call.to, data: q.call.data }, "latest"]).then(q.resolve, q.reject);
  };

  const flush = () => {
    timer = null;
    const batch = queue;
    queue = [];
    if (batch.length === 0) return;
    stats.aggregates++;
    stats.subCalls += batch.length;
    stats.sizes.push(batch.length);
    const data = encodeAggregate(batch.map((b) => b.call));
    inner.call(p, "eth_call", [{ to: helperAddr, data }, "latest"]).then(
      (hex) => {
        let dec: ReturnType<typeof decodeAggregate>;
        try {
          dec = decodeAggregate(String(hex));
        } catch {
          for (const q of batch) alone(q);
          return;
        }
        if (dec.results.length !== batch.length) {
          for (const q of batch) alone(q);
          return;
        }
        batch.forEach((q, i) => {
          const r = dec.results[i] as SubResult;
          if (r.ok) q.resolve(r.data);
          else alone(q);
        });
      },
      () => {
        for (const q of batch) alone(q);
      }
    );
  };

  const wrapped: SendFn = function (this: unknown, method, params) {
    if (method === "eth_call" && Array.isArray(params) && params.length === 2 && params[1] === "latest") {
      const call = plainCall(params[0]);
      if (call && allowed.has(call.to)) {
        return new Promise((resolve, reject) => {
          queue.push({ call, resolve, reject });
          timer ??= setTimeout(flush, 0);
        });
      }
      stats.passedThrough++;
    }
    return inner.call(this, method, params);
  };
  p.send = wrapped;
  p[MULTICALL] = true;
  return {
    helper: helperAddr,
    stats: () => ({ ...stats, sizes: [...stats.sizes] }),
    reset: () => {
      stats = { aggregates: 0, subCalls: 0, fallbacks: 0, passedThrough: 0, sizes: [] };
    },
    detach: () => {
      if (p.send !== wrapped) throw new Error("another wrapper was installed on top of the multicall transport; detach in reverse order");
      if (timer) clearTimeout(timer);
      if (own) Object.defineProperty(p, "send", own);
      else delete (p as unknown as Record<string, unknown>)["send"];
      delete p[MULTICALL];
    },
  };
}
