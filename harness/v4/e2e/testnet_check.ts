import { Wallet as EthWallet } from "ethers";
import { opt } from "../bench/lib.ts";
import { classifyUrl, estimateSetupCost, findSecrets, redactSecrets, resolveRpcArg, secretNeedles, urlNeedles, urlSha256, SETUP_GAS, type SecretNeedle } from "./lib.ts";

/**
 * Read-only check of a public testnet endpoint before Kushal's run (docs/v4/A4_TESTNET.md).
 * It SENDS NOTHING: no transaction, no signature. The funder key is read from the environment
 * only to derive its public address; the URL only to call read methods. Neither is printed.
 *
 *   node --import tsx harness/v4/e2e/testnet_check.ts --expect-chain-id 11155111 [--max-fee-gwei 30] [--max-total-eth 0.2]
 *        [--rpc env:NAME | --rpc <loopback or LAN url without path or query> | --rpc-env PQID_E2E_RPC_URL]
 *        [--funder-env PQID_E2E_FUNDER_KEY] [--allow-local]
 *
 * --allow-local (scripts/e2e/device_run.sh): a loopback or local-network endpoint is not a
 * problem (a phone reading a laptop's node); an internet endpoint still needs https.
 *
 * Prints one JSON report: chain id, client, latest and finalized block, block period, fee data,
 * funder balance, set-up cost estimate (one campaign = one set-up), JSON-RPC batch support,
 * single-block eth_getLogs support, five raw round trips, and whether the run may start
 * (exit 0 ready, 4 not ready, 1 failure).
 */

interface RpcOut {
  ok: boolean;
  ms: number;
  status: number;
  result: unknown;
  error: string | null;
  isArray: boolean;
}

async function post(url: string, body: unknown, needles: SecretNeedle[]): Promise<RpcOut> {
  const t = performance.now();
  try {
    const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(20_000) });
    const text = await res.text();
    let j: unknown = null;
    try {
      j = JSON.parse(text);
    } catch {
      j = null;
    }
    const one = (Array.isArray(j) ? j[0] : j) as { result?: unknown; error?: { message?: string } } | null;
    return {
      ok: res.ok && !!one && one.error === undefined,
      ms: Math.round((performance.now() - t) * 100) / 100,
      status: res.status,
      result: Array.isArray(j) ? j : (one?.result ?? null),
      error: one?.error ? redactSecrets(String(one.error.message ?? "JSON-RPC error"), needles).slice(0, 200) : res.ok ? null : `HTTP ${res.status}`,
      isArray: Array.isArray(j),
    };
  } catch (e) {
    return { ok: false, ms: Math.round((performance.now() - t) * 100) / 100, status: 0, result: null, error: redactSecrets(String((e as Error).message), needles).slice(0, 200), isArray: false };
  }
}

const call = (url: string, method: string, params: unknown[], needles: SecretNeedle[]) => post(url, { jsonrpc: "2.0", id: 1, method, params }, needles);
const hexNum = (x: unknown): number | null => (typeof x === "string" && /^0x[0-9a-f]+$/i.test(x) ? Number(BigInt(x)) : null);

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const rpcEnv = opt(argv, "rpc-env") ?? "PQID_E2E_RPC_URL";
  const funderEnv = opt(argv, "funder-env") ?? "PQID_E2E_FUNDER_KEY";
  const expectChainId = Number(opt(argv, "expect-chain-id"));
  if (!Number.isSafeInteger(expectChainId) || expectChainId <= 0) throw new Error("--expect-chain-id N required (Sepolia: 11155111)");
  const maxFeeGwei = Number(opt(argv, "max-fee-gwei") ?? "30");
  const maxTotalEth = Number(opt(argv, "max-total-eth") ?? "0.2");
  const allowLocal = argv.includes("--allow-local");
  const r = resolveRpcArg(opt(argv, "rpc"), rpcEnv, process.env);
  const url = r.url;
  const key = process.env[funderEnv]?.trim();
  if (r.envName) delete process.env[r.envName];
  delete process.env[funderEnv];
  if (!url) throw new Error(`no RPC URL: ${r.source} is empty (read -rs ${r.envName ?? rpcEnv}; export ${r.envName ?? rpcEnv})`);
  const needles: SecretNeedle[] = [...urlNeedles(url)];
  let funder: string | null = null;
  if (key) {
    if (!/^(0x)?[0-9a-fA-F]{64}$/.test(key)) throw new Error(`${funderEnv} must hold a 32-byte hex key`);
    needles.push(...secretNeedles("funderKey", key), ...secretNeedles("funderKeyNo0x", key.replace(/^0x/, "")));
    funder = new EthWallet(key).address;
  }
  const cls = classifyUrl(url);

  const chain = await call(url, "eth_chainId", [], needles);
  const client = await call(url, "web3_clientVersion", [], needles);
  const latest = await call(url, "eth_getBlockByNumber", ["latest", false], needles);
  const finalized = await call(url, "eth_getBlockByNumber", ["finalized", false], needles);
  const gasPrice = await call(url, "eth_gasPrice", [], needles);
  const prio = await call(url, "eth_maxPriorityFeePerGas", [], needles);
  const balance = funder ? await call(url, "eth_getBalance", [funder, "latest"], needles) : null;
  const latestNum = hexNum((latest.result as { number?: string } | null)?.number);
  const latestTs = hexNum((latest.result as { timestamp?: string } | null)?.timestamp);
  const baseFee = hexNum((latest.result as { baseFeePerGas?: string } | null)?.baseFeePerGas);
  let blockPeriodSec: number | null = null;
  if (latestNum !== null && latestNum > 10 && latestTs !== null) {
    const old = await call(url, "eth_getBlockByNumber", ["0x" + (latestNum - 10).toString(16), false], needles);
    const oldTs = hexNum((old.result as { timestamp?: string } | null)?.timestamp);
    if (oldTs !== null) blockPeriodSec = (latestTs - oldTs) / 10;
  }
  const batch = await post(url, [{ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }, { jsonrpc: "2.0", id: 2, method: "eth_blockNumber", params: [] }], needles);
  const logs = latestNum !== null ? await call(url, "eth_getLogs", [{ fromBlock: "0x" + latestNum.toString(16), toBlock: "0x" + latestNum.toString(16) }], needles) : null;
  const rtt: number[] = [];
  let rttErrors = 0;
  for (let i = 0; i < 5; i++) {
    const r = await call(url, "eth_blockNumber", [], needles);
    rtt.push(r.ms);
    if (!r.ok) rttErrors++;
  }

  // ethers' getFeeData: maxFeePerGas = 2 x baseFee + maxPriorityFeePerGas (what the set-up will pay at most)
  const prioWei = hexNum(prio.result) ?? 1e9;
  const maxFeeWei = baseFee !== null ? BigInt(baseFee) * 2n + BigInt(prioWei) : BigInt(hexNum(gasPrice.result) ?? 0);
  const est = estimateSetupCost(maxFeeWei);
  const estAtCap = estimateSetupCost(BigInt(Math.round(maxFeeGwei * 1e9)));
  const balWei = balance && typeof balance.result === "string" ? BigInt(balance.result) : null;
  const chainId = hexNum(chain.result);
  const problems: string[] = [];
  if (chainId !== expectChainId) problems.push(`chain id ${chainId} is not the expected ${expectChainId}`);
  if (cls.reach === "internet" || !allowLocal) {
    if (cls.scheme !== "https") problems.push("the URL is not https");
    if (cls.reach !== "internet") problems.push(`the URL is a ${cls.reach} address, not a public endpoint`);
  }
  if (!funder) problems.push(`${funderEnv} is not set (the funder address cannot be checked)`);
  if (Number(maxFeeWei) / 1e9 > maxFeeGwei) problems.push(`current maxFeePerGas ${(Number(maxFeeWei) / 1e9).toFixed(3)} gwei is above --max-fee-gwei ${maxFeeGwei}: the set-up would refuse now`);
  if (est.totalEth > maxTotalEth) problems.push(`estimate ${est.totalEth.toFixed(5)} ETH per set-up is above --max-total-eth ${maxTotalEth}`);
  if (balWei !== null && balWei < 2n * BigInt(est.totalWei)) problems.push(`funder balance ${(Number(balWei) / 1e18).toFixed(5)} ETH is below two set-ups at the current fee (${((2 * Number(est.totalWei)) / 1e18).toFixed(5)} ETH; cold and warm campaigns each make one)`);
  if (!batch.isArray) problems.push("the endpoint does not answer a JSON-RPC batch with an array (ethers batches requests; expect errors)");
  if (logs && !logs.ok) problems.push(`single-block eth_getLogs failed (${logs.error}); the wallet's and verifier's log reads need it`);
  if (!finalized.ok) problems.push("the 'finalized' block tag is not served; the set-up waits for it");

  const report = {
    schema: "pqid/v4-e2e-testnet-check/v1",
    note: "read-only: nothing was sent or signed; the URL and the key are not printed",
    utc: new Date().toISOString(),
    endpoint: { scheme: cls.scheme, reach: cls.reach, transport: cls.transport, urlSource: r.source, urlSha256: urlSha256(url), chainId, client: client.ok ? client.result : null },
    blocks: { latest: latestNum, finalized: hexNum((finalized.result as { number?: string } | null)?.number), blockPeriodSecLast10: blockPeriodSec, latestBlockAgeSec: latestTs !== null ? Math.round(Date.now() / 1000 - latestTs) : null },
    fees: { baseFeeGwei: baseFee !== null ? baseFee / 1e9 : null, maxPriorityFeeGwei: prioWei / 1e9, maxFeePerGasGwei: Number(maxFeeWei) / 1e9, gasPriceGwei: (hexNum(gasPrice.result) ?? 0) / 1e9, capGwei: maxFeeGwei, rule: "ethers getFeeData: maxFeePerGas = 2 x baseFee + maxPriorityFeePerGas" },
    funder: funder ? { address: funder, balanceEth: balWei !== null ? Number(balWei) / 1e18 : null } : null,
    costPerSetup: { atCurrentFee: est, atFeeCap: estAtCap, gasTable: SETUP_GAS },
    capabilities: { jsonRpcBatch: batch.isArray, singleBlockGetLogs: logs ? logs.ok : null, finalizedTag: finalized.ok },
    rawRoundTripsMs: { eth_blockNumber: rtt, errors: rttErrors },
    readyToRun: problems.length === 0,
    problems,
  };
  const text = JSON.stringify(report, null, 2);
  const hits = findSecrets(text, needles);
  if (hits.length > 0) throw new Error(`report withheld: secret scan hit (${hits.join(", ")})`);
  console.log(text);
  return problems.length === 0 ? 0 : 4;
}

main().then(
  (c) => process.exit(c),
  (e: unknown) => {
    console.error(`[testnet_check] ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
);
