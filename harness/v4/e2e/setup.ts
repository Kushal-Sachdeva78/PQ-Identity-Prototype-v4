import { randomBytes, type KeyObject } from "node:crypto";
import { ContractFactory, JsonRpcProvider, Wallet as EthWallet, formatEther, type TransactionReceipt } from "ethers";
import { didFromPublicKey } from "@pqid/common/did";
import { sha3_256 } from "@pqid/common/hash";
import { LedgerV4, RoleAccount, compileRegistriesV4, type RegistryAddressesV4 } from "@pqid/v4/ledger";
import { SystemClock } from "@pqid/v4/clock";
import { createGovernance, accreditIssuer, type Governance } from "@pqid/v4/governance";
import { registerWithPop, issueCredentialV4, publishEpochV4, type IssuerV4 } from "@pqid/v4/issuer";
import { IssuanceTree } from "@pqid/issuer";
import { IndexedMerkleTree } from "@pqid/v4/imt";
import { HolderWalletV4 } from "@pqid/v4/wallet";
import { publishedEpochBlob } from "@pqid/v4/published";
import { mlDsaKeygen, mlDsaSign, mlKemKeygen, type MlKemKeyPair } from "@pqid/v4/pqc";
import { verifierKemMessage } from "@pqid/v4/statements";
import { ledgerProvider } from "../lib/rpc_trace.ts";
import { utcDateOf } from "@pqid/v4/dates";
import { DEFAULT_TYPE_ID, ISSUANCE_DEPTH, KEM_ALG, MAX_EPOCH_WINDOW_SEC, MIN_ANCHOR_INTERVAL_SEC, REV_DEPTH } from "@pqid/v4/constants";
import {
  E2E_POLICY,
  HOLDERS_PER_SETUP,
  PRESENTING_BIRTH_DATE,
  SCHEMA,
  SETUP_GAS,
  classifyUrl,
  estimateSetupCost,
  rawWriteGasLimit,
  roleGasBudgets,
  secretNeedles,
  urlNeedles,
  urlSha256,
  type E2eStateDoc,
  type EndpointKind,
  type RunKey,
  type SecretNeedle,
  type Transport,
} from "./lib.ts";

/**
 * Per-endpoint set-up of the end-to-end series (docs/v4/E2E.md, rule 3), untimed. Every party
 * uses SystemClock and no dev RPC is called, so the same code runs on Anvil, Besu and a public
 * testnet. Secrets (governance, issuer and verifier ML-DSA keys, the verifier's ML-KEM key,
 * role EVM keys, holder secrets) stay in this process's memory; the child receives only what a
 * wallet and a verifier hold, on its stdin (stateDoc()).
 *
 * Local endpoints (anvil, besu): LedgerV4.deploy with a fresh governance account; role
 * accounts are funded by the dev deployer (worldOnRpc's steps with SystemClock instead of
 * ManualClock). Custom endpoint: the registries are deployed by a funder key read from the
 * environment, role accounts are funded from it within fee caps, the orchestrator waits for
 * finality after the last write and sweeps the role balances back at the end.
 */

export interface EndpointRecord {
  id: string;
  kind: EndpointKind;
  /** Label: anvil, besu, or the custom --endpoint-label. */
  label: string;
  transport: Transport;
  scheme: "http" | "https";
  /** Loopback endpoints: the port; never a custom URL (custom: urlSha256 only). */
  port: number | null;
  urlSha256: string | null;
  chainId: number;
  client: string | null;
  blockPeriod: string;
  validators: number | null;
  tool: Record<string, unknown> | null;
}

export interface Deployment {
  schema: typeof SCHEMA.deployment;
  setupId: string;
  campaign: string;
  session: string;
  endpoint: EndpointRecord;
  chainId: number;
  addresses: RegistryAddressesV4;
  fromBlock: number;
  deployer: { kind: "anvil-dev-key-0" | "funder"; address: string };
  roles: { governance: string; issuerController: string; verifierController: string };
  transactions: Array<{ what: string; txHash: string; blockNumber: number; gasUsed: number; effectiveGasPriceWei: string | null }>;
  durations: Record<string, number>;
  epoch: { epoch: number; notBefore: number; notAfter: number; fromDate: number; toDate: number };
  holders: number;
  presentingBirthDate: number;
  fees: Record<string, unknown> | null;
  finality: Record<string, unknown> | null;
  utc: string;
}

export interface E2eSetup {
  setupId: string;
  endpoint: EndpointRecord;
  rpcUrl: string;
  ledger: LedgerV4;
  deployment: Deployment;
  stateDoc(key: RunKey): E2eStateDoc;
  /** Needles of every secret this set-up holds (for the result scan). */
  needles(): SecretNeedle[];
  /** Re-anchor when less than `marginSec` of the epoch window remains (untimed; call during an idle). */
  reanchorIfNeeded(marginSec: number): Promise<null | { epoch: number; notAfter: number; gasUsed: number; ms: number }>;
  /** Custom endpoints: send leftover role balances back to the funder. */
  sweep(): Promise<Array<{ role: string; txHash: string | null; valueWei: string; note?: string }>>;
  destroy(): void;
}

interface Parties {
  governance: Governance;
  issuer: IssuerV4;
  holders: HolderWalletV4[];
  presenting: { holder: HolderWalletV4; vc: Awaited<ReturnType<typeof issueCredentialV4>> };
  verifier: { did: string; pk: Buffer; sk: KeyObject; kem: MlKemKeyPair; account: RoleAccount; controller: string; origin: string };
  blob: Uint8Array;
  /** The set-up ledger behind a write recorder (re-anchors go through it). */
  writer: LedgerV4;
}

const sinceMs = (t: number) => Math.round((performance.now() - t) * 10) / 10;

function birthDates(): number[] {
  // the presenting holder first (Phase D fixture date); the others distinct, all adults
  return [PRESENTING_BIRTH_DATE, 19700101, 19751111, 19800229, 19881203, 19920707, 19950505, 20000101].slice(0, HOLDERS_PER_SETUP);
}

const ORIGIN = "https://e2e.verifier.example";

/** A Proxy that records every registry write (LedgerV4.rawWrite) made through it. */
function recordWrites(ledger: LedgerV4, txs: Deployment["transactions"]): LedgerV4 {
  return new Proxy(ledger, {
    get(target, prop, receiver) {
      const v = Reflect.get(target, prop, receiver) as unknown;
      if (prop !== "rawWrite" || typeof v !== "function") return v;
      const fn = v as (...a: unknown[]) => Promise<{ txHash: string; blockNumber: number; gasUsed: number }>;
      return async function (this: unknown, ...args: unknown[]) {
        const r = await fn.apply(this, args);
        txs.push({ what: `${String(args[1])}.${String(args[2])}`, txHash: r.txHash, blockNumber: r.blockNumber, gasUsed: r.gasUsed, effectiveGasPriceWei: null });
        return r;
      };
    },
  });
}

/** The shared steps after the registries exist and the role accounts are funded. */
async function buildParties(rawLedger: LedgerV4, accounts: { governance: RoleAccount; issuer: RoleAccount; verifier: RoleAccount }, txs: Deployment["transactions"], durations: Record<string, number>): Promise<Parties> {
  const ledger = recordWrites(rawLedger, txs);
  let t = performance.now();
  const governance = await createGovernance(ledger, accounts.governance);
  // the issuer of createIssuerV4, with a role account funded by the caller
  const ik = mlDsaKeygen();
  const issuer: IssuerV4 = {
    label: "e2e-issuer",
    did: didFromPublicKey(ik.publicKey),
    pk: ik.publicKey,
    sk: ik.privateKey,
    account: accounts.issuer,
    controller: accounts.issuer.address.toLowerCase(),
    tree: await IssuanceTree.create(ISSUANCE_DEPTH),
    rev: await IndexedMerkleTree.create(REV_DEPTH),
    leafIndexByCredId: new Map(),
    credIdByLeaf: new Map(),
    signed: [],
    anchored: null,
  };
  await registerWithPop(ledger, issuer);
  durations["issuerRegisterMs"] = sinceMs(t);
  t = performance.now();
  await accreditIssuer(governance, ledger, SystemClock, { did: issuer.did, controller: issuer.controller });
  durations["accreditMs"] = sinceMs(t);

  t = performance.now();
  const holders: HolderWalletV4[] = [];
  let presenting: Parties["presenting"] | null = null;
  const today = utcDateOf(SystemClock.nowSec());
  for (const bd of birthDates()) {
    const h = await HolderWalletV4.create({ ledger, clock: SystemClock, pinnedGovernancePk: governance.pk });
    const vc = await issueCredentialV4(issuer, { subject: h.subject, holderCommit: h.holderCommit, birthDate: bd, typeId: DEFAULT_TYPE_ID, issuedDate: today });
    holders.push(h);
    if (bd === PRESENTING_BIRTH_DATE && !presenting) presenting = { holder: h, vc };
  }
  if (!presenting) throw new Error("internal: no presenting holder");
  durations["issueMs"] = sinceMs(t);

  t = performance.now();
  await publishEpochV4(issuer, ledger, SystemClock);
  const blob = publishedEpochBlob(issuer);
  durations["epochMs"] = sinceMs(t);

  // verifier: World.newVerifierIdentity + World.publishKemKey steps, SystemClock
  t = performance.now();
  const vk = mlDsaKeygen();
  const kem = mlKemKeygen();
  const verifier = { did: didFromPublicKey(vk.publicKey), pk: vk.publicKey, sk: vk.privateKey, kem, account: accounts.verifier, controller: accounts.verifier.address.toLowerCase(), origin: ORIGIN };
  await registerWithPop(ledger, verifier, ORIGIN);
  const now = SystemClock.nowSec();
  const statement = verifierKemMessage({
    verifier: verifier.did,
    controller: verifier.controller,
    chainId: await ledger.chainId(),
    registry: ledger.addresses.verifierKemRegistry.toLowerCase(),
    kemAlg: KEM_ALG,
    kemPkSha3: sha3_256(kem.publicKey).toString("hex"),
    notBefore: now,
    notAfter: now + 365 * 24 * 3600,
  });
  await ledger.publishKemKey(verifier.account, { did: verifier.did, kemPk: kem.publicKey, statement, signature: mlDsaSign(verifier.sk, statement) });
  durations["verifierMs"] = sinceMs(t);
  return { governance, issuer, holders, presenting, verifier, blob, writer: ledger };
}

function receiptRec(what: string, r: TransactionReceipt | null): Deployment["transactions"][number] {
  if (!r) throw new Error(`${what}: no receipt`);
  return { what, txHash: r.hash, blockNumber: r.blockNumber, gasUsed: Number(r.gasUsed), effectiveGasPriceWei: r.gasPrice !== undefined && r.gasPrice !== null ? r.gasPrice.toString() : null };
}

function makeSetup(args: {
  setupId: string;
  endpoint: EndpointRecord;
  rpcUrl: string;
  ledger: LedgerV4;
  deployment: Deployment;
  parties: Parties;
  extraNeedles: SecretNeedle[];
  sweep: E2eSetup["sweep"];
  destroyExtra?: () => void;
}): E2eSetup {
  const { parties: P, ledger } = args;
  let blob = P.blob;
  return {
    setupId: args.setupId,
    endpoint: args.endpoint,
    rpcUrl: args.rpcUrl,
    ledger,
    deployment: args.deployment,
    stateDoc(key: RunKey): E2eStateDoc {
      const kemDer = P.verifier.kem.privateKey.export({ format: "der", type: "pkcs8" });
      return {
        schema: SCHEMA.state,
        key,
        endpoint: { id: args.endpoint.id, kind: args.endpoint.kind, rpcUrl: args.rpcUrl, chainId: args.endpoint.chainId, transport: args.endpoint.transport },
        setupId: args.setupId,
        registry: { addresses: ledger.addresses, fromBlock: ledger.deployment.fromBlock },
        governancePkHex: P.governance.pk.toString("hex"),
        wallet: {
          holderSecret: P.presenting.holder.holderSecret.toString(),
          vc: P.presenting.vc as unknown as E2eStateDoc["wallet"]["vc"],
          issuerPkHex: P.issuer.pk.toString("hex"),
          leafIndex: P.presenting.vc.leafIndex,
          blobB64: Buffer.from(blob).toString("base64"),
        },
        verifier: {
          did: P.verifier.did,
          controller: P.verifier.controller,
          origin: P.verifier.origin,
          pkHex: P.verifier.pk.toString("hex"),
          kemPublicKeyHex: P.verifier.kem.publicKey.toString("hex"),
          kemPrivatePkcs8B64: Buffer.from(kemDer).toString("base64"),
        },
        policy: { predicate: E2E_POLICY.predicate, threshold: E2E_POLICY.threshold, typeId: DEFAULT_TYPE_ID },
      };
    },
    needles(): SecretNeedle[] {
      const der = (k: KeyObject) => Buffer.from(k.export({ format: "der", type: "pkcs8" }));
      const out: SecretNeedle[] = [...args.extraNeedles];
      for (const h of P.holders) {
        out.push(...secretNeedles("holderSecret", h.holderSecret.toString()));
        out.push(...secretNeedles("holderSecretHex", h.holderSecret.toString(16)));
      }
      for (const [name, k] of [
        ["governanceSk", P.governance.sk],
        ["issuerSk", P.issuer.sk],
        ["verifierSk", P.verifier.sk],
        ["verifierKemSk", P.verifier.kem.privateKey],
      ] as const) {
        const d = der(k);
        out.push(...secretNeedles(name, d.toString("base64")));
        out.push(...secretNeedles(`${name}Hex`, d.toString("hex")));
      }
      return out;
    },
    async reanchorIfNeeded(marginSec: number) {
      const a = P.issuer.anchored;
      if (!a) throw new Error("internal: issuer has no anchored epoch");
      if (a.statement.notAfter - SystemClock.nowSec() >= marginSec) return null;
      const t = performance.now();
      const r = await publishEpochV4(P.issuer, P.writer, SystemClock);
      blob = publishedEpochBlob(P.issuer);
      return { epoch: r.statement.epoch, notAfter: r.statement.notAfter, gasUsed: Number(r.gasUsed), ms: sinceMs(t) };
    },
    sweep: args.sweep,
    destroy(): void {
      ledger.destroy();
      args.destroyExtra?.();
    },
  };
}

function newSetupId(): string {
  return randomBytes(12).toString("hex");
}

function epochRecord(P: Parties): Deployment["epoch"] {
  const s = P.issuer.anchored?.statement;
  if (!s) throw new Error("internal: no anchored statement");
  return { epoch: s.epoch, notBefore: s.notBefore, notAfter: s.notAfter, fromDate: s.fromDate, toDate: s.toDate };
}

// ---------------------------------------------------------------------------------------
// local endpoints (Anvil, Besu QBFT)
// ---------------------------------------------------------------------------------------

export async function setupLocal(rpcUrl: string, endpoint: EndpointRecord, meta: { campaign: string; session: string }): Promise<E2eSetup> {
  const setupId = newSetupId();
  const durations: Record<string, number> = {};
  const txs: Deployment["transactions"] = [];
  let t = performance.now();
  const governanceAccount = RoleAccount.random("governance");
  const ledger = await LedgerV4.deploy(rpcUrl, { governanceAddress: governanceAccount.address, minAnchorIntervalSec: MIN_ANCHOR_INTERVAL_SEC, maxWindowSec: MAX_EPOCH_WINDOW_SEC });
  durations["deployMs"] = sinceMs(t);
  try {
    t = performance.now();
    await ledger.fund(governanceAccount);
    const issuerAccount = await ledger.newRoleAccount("issuer:e2e");
    const verifierAccount = await ledger.newRoleAccount("verifier:e2e");
    durations["fundMs"] = sinceMs(t);
    const P = await buildParties(ledger, { governance: governanceAccount, issuer: issuerAccount, verifier: verifierAccount }, txs, durations);
    const deployment: Deployment = {
      schema: SCHEMA.deployment,
      setupId,
      campaign: meta.campaign,
      session: meta.session,
      endpoint,
      chainId: await ledger.chainId(),
      addresses: ledger.addresses,
      fromBlock: ledger.deployment.fromBlock,
      deployer: { kind: "anvil-dev-key-0", address: ledger.deployment.deployer },
      roles: { governance: governanceAccount.address, issuerController: issuerAccount.address, verifierController: verifierAccount.address },
      transactions: [
        ...Object.entries(ledger.deployment.deployGas).map(([what, gasUsed]) => ({ what: `deploy ${what}`, txHash: "", blockNumber: -1, gasUsed, effectiveGasPriceWei: null })),
        ...txs,
      ],
      durations,
      epoch: epochRecord(P),
      holders: P.holders.length,
      presentingBirthDate: PRESENTING_BIRTH_DATE,
      fees: null,
      finality: { rule: endpoint.kind === "besu" ? "QBFT: final when mined" : "Anvil single node: final when mined" },
      utc: new Date().toISOString(),
    };
    return makeSetup({ setupId, endpoint, rpcUrl, ledger, deployment, parties: P, extraNeedles: [], sweep: async () => [] });
  } catch (e) {
    ledger.destroy();
    throw e;
  }
}

// ---------------------------------------------------------------------------------------
// custom endpoint (public testnet; started by Kushal only)
// ---------------------------------------------------------------------------------------

export interface CustomOptions {
  funderKey: string;
  expectChainId: number;
  maxFeeGwei: number;
  maxTotalEth: number;
  finality: "finalized" | "latest";
  finalityTimeoutSec: number;
  /** Longest wait for one funder transaction (deploy, funding) or one sweep transfer to be mined. */
  txTimeoutSec: number;
  /** Longest wait for the governance, issuer and verifier writes together (they run inside the shipped LedgerV4.rawWrite, which has no timeout of its own). */
  writesTimeoutSec: number;
  campaign: string;
  session: string;
  log: (s: string) => void;
  /** Tests only: called after the role accounts are funded (a throw here exercises the failure sweep). */
  testHooks?: { afterFunding?: () => void | Promise<void> };
}

/** One sweep transfer back to the funder (public facts only). */
export interface SweepTransfer {
  role: string;
  txHash: string | null;
  valueWei: string;
  note?: string;
}

/**
 * A custom set-up that failed. Carries the public facts of what was already sent (transactions)
 * and the result of the sweep of every role account funded before the failure, so the
 * orchestrator records both in deployments.jsonl (the role keys exist only in memory).
 */
export class SetupFailed extends Error {
  readonly setupId: string;
  readonly transactions: Deployment["transactions"];
  readonly partialSweep: SweepTransfer[] | null;
  constructor(cause: unknown, setupId: string, transactions: Deployment["transactions"], partialSweep: SweepTransfer[] | null) {
    super((`custom set-up failed: ${cause instanceof Error ? cause.message : String(cause)}`.split("\n")[0] ?? "custom set-up failed").slice(0, 600), { cause });
    this.name = "SetupFailed";
    this.setupId = setupId;
    this.transactions = transactions;
    this.partialSweep = partialSweep;
  }
}

async function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const t = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} did not finish within ${Math.round(ms / 1000)} s`)), ms);
  });
  try {
    return await Promise.race([p, t]);
  } finally {
    clearTimeout(timer);
  }
}

async function waitFinalized(provider: JsonRpcProvider, block: number, mode: CustomOptions["finality"], timeoutSec: number): Promise<Record<string, unknown>> {
  const t0 = performance.now();
  if (mode === "latest") return { rule: "latest (no finality wait; allowed only for a loopback or local-network node, never an internet endpoint)", waitedSec: 0 };
  for (;;) {
    let fin: number | null = null;
    try {
      const b = (await provider.send("eth_getBlockByNumber", ["finalized", false])) as { number?: string } | null;
      fin = b?.number ? Number(BigInt(b.number)) : null;
    } catch {
      fin = null;
    }
    if (fin !== null && fin >= block) return { rule: "waited until the 'finalized' block reached the last set-up write", lastWriteBlock: block, finalizedBlock: fin, waitedSec: Math.round((performance.now() - t0) / 100) / 10 };
    if ((performance.now() - t0) / 1000 > timeoutSec) throw new Error(`the 'finalized' block did not reach block ${block} within ${timeoutSec} s`);
    await new Promise((r) => setTimeout(r, 12_000));
  }
}

type FeeOpts = { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } | { gasPrice: bigint };

/**
 * Send every listed role account's balance back to the funder. A role whose transaction count
 * shows a pending transaction (a write stuck under a fee spike) is swept with that pending nonce
 * and a doubled fee, which replaces the stuck transaction. One retry per role.
 */
export async function sweepRoles(provider: JsonRpcProvider, funderAddr: string, roles: ReadonlyArray<readonly [string, RoleAccount]>, fallbackMaxFee: bigint, txTimeoutMs: number): Promise<SweepTransfer[]> {
  const out: SweepTransfer[] = [];
  for (const [role, acct] of roles) {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const f = await provider.getFeeData();
        const latest = await provider.getTransactionCount(acct.address, "latest");
        const pending = await provider.getTransactionCount(acct.address, "pending");
        const stuck = pending > latest;
        const k = stuck ? 2n : 1n;
        const mf = (f.maxFeePerGas ?? f.gasPrice ?? fallbackMaxFee) * k;
        const opts: FeeOpts = f.maxFeePerGas !== null && f.maxPriorityFeePerGas !== null ? { maxFeePerGas: mf, maxPriorityFeePerGas: f.maxPriorityFeePerGas * k } : { gasPrice: mf };
        const bal = await provider.getBalance(acct.address, "latest");
        const cost = 21000n * mf;
        if (bal <= cost) {
          out.push({ role, txHash: null, valueWei: "0", note: "balance below the transfer fee" });
          break;
        }
        const w = acct.connectTo(provider);
        const tx = await w.sendTransaction({ to: funderAddr, value: bal - cost, gasLimit: 21000n, nonce: latest, ...opts });
        const r = await tx.wait(1, txTimeoutMs);
        out.push({ role, txHash: r?.hash ?? tx.hash, valueWei: (bal - cost).toString(), ...(stuck ? { note: "replaced a pending role transaction (same nonce, doubled fee)" } : {}) });
        break;
      } catch (e) {
        if (attempt === 1) out.push({ role, txHash: null, valueWei: "0", note: `sweep failed: ${String((e as Error).message).split("\n")[0]?.slice(0, 160)}` });
      }
    }
  }
  return out;
}

export async function setupCustom(rpcUrl: string, endpoint: EndpointRecord, o: CustomOptions): Promise<E2eSetup> {
  const setupId = newSetupId();
  const durations: Record<string, number> = {};
  const txs: Deployment["transactions"] = [];
  const provider = new JsonRpcProvider(rpcUrl, undefined, { cacheTimeout: -1 });
  provider.pollingInterval = 4000;
  const funder = new EthWallet(o.funderKey, provider);
  const funderAddr = funder.address.toLowerCase();
  const needles: SecretNeedle[] = [...urlNeedles(rpcUrl), ...secretNeedles("funderKey", o.funderKey), ...secretNeedles("funderKeyNo0x", o.funderKey.replace(/^0x/, ""))];
  const txTimeoutMs = o.txTimeoutSec * 1000;
  const capWei = BigInt(Math.round(o.maxFeeGwei * 1e9));
  // role accounts that were sent funds (swept back if the set-up fails after that)
  const funded: Array<readonly [string, RoleAccount]> = [];
  let maxFee = 0n;
  let ledger: LedgerV4 | null = null;
  /** Fresh fee data for each funder transaction, refused above the cap (no fixed fee snapshot). */
  const freshFees = async (): Promise<FeeOpts> => {
    const f = await provider.getFeeData();
    const mf = f.maxFeePerGas ?? f.gasPrice;
    if (mf === null) throw new Error("the endpoint reports no fee data");
    if (mf > capWei) throw new Error(`maxFeePerGas ${Number(mf) / 1e9} gwei is now above --max-fee-gwei ${o.maxFeeGwei}; set-up stopped`);
    return f.maxFeePerGas !== null && f.maxPriorityFeePerGas !== null ? { maxFeePerGas: f.maxFeePerGas, maxPriorityFeePerGas: f.maxPriorityFeePerGas } : { gasPrice: mf };
  };
  try {
    const chainId = Number((await provider.getNetwork()).chainId);
    if (chainId !== o.expectChainId) throw new Error(`chain id ${chainId} is not the expected ${o.expectChainId}`);
    const fee = await provider.getFeeData();
    const snapshot = fee.maxFeePerGas ?? fee.gasPrice;
    if (snapshot === null) throw new Error("the endpoint reports no fee data");
    maxFee = snapshot;
    if (maxFee > capWei) throw new Error(`maxFeePerGas ${Number(maxFee) / 1e9} gwei is above --max-fee-gwei ${o.maxFeeGwei}`);
    const est = estimateSetupCost(maxFee);
    const balance = await provider.getBalance(funderAddr);
    o.log(`[setup custom] chain ${chainId}; maxFeePerGas ${Number(maxFee) / 1e9} gwei; estimate ${est.totalEth.toFixed(6)} ETH (cap ${o.maxTotalEth}); funder balance ${formatEther(balance)} ETH`);
    if (est.totalEth > o.maxTotalEth) throw new Error(`estimated set-up cost ${est.totalEth.toFixed(6)} ETH is above --max-total-eth ${o.maxTotalEth}`);
    if (balance < BigInt(est.totalWei)) throw new Error(`funder balance ${formatEther(balance)} ETH is below the estimate ${est.totalEth.toFixed(6)} ETH`);

    // ---- deploy the four registries (compileRegistriesV4, ContractFactory signed by the funder)
    let t = performance.now();
    const governanceAccount = RoleAccount.random("governance");
    const issuerAccount = RoleAccount.random("issuer:e2e");
    const verifierAccount = RoleAccount.random("verifier:e2e");
    const roles = [
      ["governance", governanceAccount],
      ["issuer", issuerAccount],
      ["verifier", verifierAccount],
    ] as const;
    const compiled = compileRegistriesV4();
    const fromBlock = (await provider.getBlockNumber()) + 1;
    const dep = async (name: keyof typeof compiled, ctorArgs: unknown[]): Promise<string> => {
      const c = compiled[name];
      const f = new ContractFactory(c.abi as never, c.bytecode, funder);
      const contract = await f.deploy(...ctorArgs, await freshFees());
      const r = await contract.deploymentTransaction()?.wait(1, txTimeoutMs);
      txs.push(receiptRec(`deploy ${name}`, r ?? null));
      return (await contract.getAddress()).toLowerCase();
    };
    const didRegistry = await dep("DIDRegistryV4", []);
    const accreditationRegistry = await dep("AccreditationRegistryV4", [governanceAccount.address]);
    const issuanceRootRegistry = await dep("IssuanceRootRegistryV4", [didRegistry, MIN_ANCHOR_INTERVAL_SEC, MAX_EPOCH_WINDOW_SEC]);
    const verifierKemRegistry = await dep("VerifierKemRegistryV4", [didRegistry]);
    durations["deployMs"] = sinceMs(t);
    const addresses = { didRegistry, accreditationRegistry, issuanceRootRegistry, verifierKemRegistry };

    // ---- fund the role accounts (gas limits x the first maxFeePerGas x 1.3)
    t = performance.now();
    const budgets = roleGasBudgets();
    for (const [role, acct] of roles) {
      const value = (BigInt(budgets[role]) * maxFee * 13n) / 10n;
      const tx = await funder.sendTransaction({ to: acct.address, value, ...(await freshFees()) });
      funded.push([role, acct]);
      txs.push(receiptRec(`fund ${role}`, await tx.wait(1, txTimeoutMs)));
    }
    durations["fundMs"] = sinceMs(t);
    await o.testHooks?.afterFunding?.();

    ledger = await LedgerV4.connect(rpcUrl, addresses, fromBlock);
    // The orchestrator's set-up ledger only (never a measured client): poll for receipts every
    // 4 s instead of the shipped 100 ms, to stay inside public RPC rate limits.
    ledgerProvider(ledger).pollingInterval = 4000;
    const bp = buildParties(ledger, { governance: governanceAccount, issuer: issuerAccount, verifier: verifierAccount }, txs, durations);
    bp.catch(() => undefined); // after a timeout the writes may still settle or fail in the background
    const P = await withTimeout(bp, o.writesTimeoutSec * 1000, "the governance, issuer and verifier writes");
    for (const x of txs) {
      if (x.effectiveGasPriceWei !== null || !x.txHash) continue;
      const r = await provider.getTransactionReceipt(x.txHash);
      x.effectiveGasPriceWei = r?.gasPrice !== undefined && r?.gasPrice !== null ? r.gasPrice.toString() : null;
    }
    const lastBlock = Math.max(...txs.map((x) => x.blockNumber), await provider.getBlockNumber());
    t = performance.now();
    const finality = await waitFinalized(provider, lastBlock, o.finality, o.finalityTimeoutSec);
    durations["finalityWaitMs"] = sinceMs(t);
    const deployment: Deployment = {
      schema: SCHEMA.deployment,
      setupId,
      campaign: o.campaign,
      session: o.session,
      endpoint,
      chainId,
      addresses,
      fromBlock,
      deployer: { kind: "funder", address: funderAddr },
      roles: { governance: governanceAccount.address, issuerController: issuerAccount.address, verifierController: verifierAccount.address },
      transactions: txs,
      durations,
      epoch: epochRecord(P),
      holders: P.holders.length,
      presentingBirthDate: PRESENTING_BIRTH_DATE,
      fees: {
        maxFeePerGasWei: maxFee.toString(),
        maxPriorityFeePerGasWei: fee.maxPriorityFeePerGas?.toString() ?? null,
        capGwei: o.maxFeeGwei,
        estimate: est,
        capTotalEth: o.maxTotalEth,
        gasTable: SETUP_GAS,
        rawWriteGasLimit: "est + est/5 + 5000",
        firstEpochGasLimit: rawWriteGasLimit(SETUP_GAS.epoch),
        funderFeeRule: "fresh fee data for each funder transaction, refused above the cap; the role writes use the shipped client's fee data",
        timeouts: { txSec: o.txTimeoutSec, writesSec: o.writesTimeoutSec, finalitySec: o.finalityTimeoutSec },
      },
      finality,
      utc: new Date().toISOString(),
    };
    const setupLedger = ledger;
    return makeSetup({ setupId, endpoint, rpcUrl, ledger: setupLedger, deployment, parties: P, extraNeedles: needles, sweep: () => sweepRoles(provider, funderAddr, roles, maxFee, txTimeoutMs), destroyExtra: () => provider.destroy() });
  } catch (e) {
    let partial: SweepTransfer[] | null = null;
    if (funded.length > 0) {
      o.log(`[setup custom] set-up failed after funding ${funded.map((r) => r[0]).join(", ")}; sweeping their balances back to the funder`);
      partial = await sweepRoles(provider, funderAddr, funded, maxFee, txTimeoutMs).catch((se: unknown) => [{ role: "all", txHash: null, valueWei: "0", note: `sweep failed: ${String((se as Error).message).split("\n")[0]?.slice(0, 160)}` }]);
    }
    ledger?.destroy();
    provider.destroy();
    throw new SetupFailed(e, setupId, txs, partial);
  }
}

// ---------------------------------------------------------------------------------------
// endpoint records
// ---------------------------------------------------------------------------------------

export async function rpc(url: string, method: string, params: unknown[] = [], timeoutMs = 10_000): Promise<unknown> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: ac.signal });
    const j = (await res.json()) as { result?: unknown; error?: { message?: string } };
    if (j.error) throw new Error(`${method}: ${j.error.message ?? "JSON-RPC error"}`);
    return j.result;
  } finally {
    clearTimeout(timer);
  }
}

/** Block period from the last few block timestamps (seconds), or null with fewer than 3 blocks. */
export async function measuredBlockPeriod(url: string): Promise<number | null> {
  const latest = Number(BigInt((await rpc(url, "eth_blockNumber")) as string));
  if (latest < 3) return null;
  const n = Math.min(10, latest);
  const ts = async (b: number) => Number(BigInt(((await rpc(url, "eth_getBlockByNumber", ["0x" + b.toString(16), false])) as { timestamp: string }).timestamp));
  const a = await ts(latest - n);
  const b = await ts(latest);
  return Math.round(((b - a) / n) * 100) / 100;
}

export async function endpointRecord(kind: EndpointKind, url: string, extra: { label?: string; tool?: Record<string, unknown> | null } = {}): Promise<EndpointRecord> {
  const cls = classifyUrl(url);
  const chainId = Number(BigInt((await rpc(url, "eth_chainId")) as string));
  let client: string | null = null;
  try {
    client = String(await rpc(url, "web3_clientVersion"));
  } catch {
    client = null;
  }
  let validators: number | null = null;
  let blockPeriod = "unknown";
  if (kind === "anvil") blockPeriod = "automine (a block per transaction)";
  if (kind === "besu") {
    try {
      validators = ((await rpc(url, "qbft_getValidatorsByBlockNumber", ["latest"])) as unknown[]).length;
    } catch {
      validators = null;
    }
    const p = await measuredBlockPeriod(url);
    blockPeriod = p === null ? "unknown" : `${p} s measured (QBFT, configured 2 s)`;
  }
  if (kind === "custom") {
    try {
      const p = await measuredBlockPeriod(url);
      blockPeriod = p === null ? "unknown" : `${p} s measured over the last 10 blocks`;
    } catch {
      blockPeriod = "unknown";
    }
  }
  const port = cls.loopback ? Number(new URL(url).port || (cls.scheme === "https" ? 443 : 80)) : null;
  return {
    id: kind,
    kind,
    label: extra.label ?? kind,
    transport: cls.transport,
    scheme: cls.scheme,
    port: kind === "custom" ? null : port,
    urlSha256: kind === "custom" ? urlSha256(url) : null,
    chainId,
    client,
    blockPeriod,
    validators,
    tool: extra.tool ?? null,
  };
}
