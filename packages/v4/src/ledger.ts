import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { inspect } from "node:util";
import {
  JsonRpcProvider,
  Wallet as EthWallet,
  NonceManager,
  ContractFactory,
  Contract,
  EventLog,
  getBytes,
  hexlify,
  keccak256,
  solidityPackedKeccak256,
  parseEther,
  type Signer,
  type Result,
  type TransactionReceipt,
  type ContractTransactionResponse,
} from "ethers";
import solc from "solc";
import { REPO_ROOT } from "@pqid/common/paths";
import { startAnvil, type AnvilHandle } from "@pqid/ledger";
import { MIN_ANCHOR_INTERVAL_SEC, MAX_EPOCH_WINDOW_SEC } from "./constants.ts";

/**
 * v4 ledger client (docs/v4/V4_DESIGN.md sections 4 and 7) for
 * onchain/contracts/v4/RegistriesV4.sol on a local EVM (Anvil).
 *
 * - The deployer (Anvil dev account #0, a publicly known test key) deploys the contracts
 *   and funds role accounts. It never writes registry data.
 * - Every role (governance, each issuer controller, each verifier controller, attackers)
 *   has its own fresh random EVM key, made in memory by RoleAccount.random or
 *   LedgerV4.newRoleAccount. Keys are never written to disk or logged.
 * - EVM authorization is liveness only. Trust decisions rest on the ML-DSA-44 statements
 *   that wallets and verifiers check off chain. This client only moves bytes and checks
 *   that bytes read from event logs match the hashes stored on chain.
 * - Every write returns WriteResult (gasUsed etc.) so experiment E4 can measure costs.
 */

// ---------------------------------------------------------------------------------------
// constants and small helpers
// ---------------------------------------------------------------------------------------

/** Anvil's deterministic dev account #0 (publicly known test key; deployer and faucet only). */
const ANVIL_DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/** Default funding for a new role account (dev chain ETH). */
export const DEFAULT_ROLE_FUNDING_ETH = "100";

export const CONTRACTS_V4_FILE = path.join(REPO_ROOT, "onchain", "contracts", "v4", "RegistriesV4.sol");

/** Registry check names (V4_DESIGN 6.3). Revert reasons start with one of them. */
export const REGISTRY_CHECKS = [
  "recordUnique",
  "controllerOnly",
  "epochIncrement",
  "anchorCadence",
  "windowBounds",
  "governanceWriter",
  "accreditationSerial",
  "kemMonotonic",
] as const;
export type RegistryCheck = (typeof REGISTRY_CHECKS)[number];

export type ContractNameV4 =
  | "DIDRegistryV4"
  | "AccreditationRegistryV4"
  | "IssuanceRootRegistryV4"
  | "VerifierKemRegistryV4";

function strip0x(h: string): string {
  return h.replace(/^0x/i, "").toLowerCase();
}

function hex32(x: string, what: string): string {
  const h = x.replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(h)) throw new Error(`${what} must be 32 bytes of hex`);
  return "0x" + h.toLowerCase();
}

function toBuf(hex: string): Buffer {
  return Buffer.from(getBytes(hex));
}

function keccakHex(b: Uint8Array): string {
  return strip0x(keccak256(b));
}

function num(x: unknown): number {
  const n = Number(x as bigint);
  if (!Number.isSafeInteger(n)) throw new Error("internal: value is not a safe integer");
  return n;
}

/** A stored uint as a number, or null when it is above Number.MAX_SAFE_INTEGER. */
function safeOrNull(x: unknown): number | null {
  const b = BigInt(x as bigint);
  return b >= 0n && b <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(b) : null;
}

// ---------------------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------------------

/** A registry call reverted. `check` is the V4_DESIGN 6.3 check name when known. */
export class RegistryRevertError extends Error {
  constructor(
    readonly method: string,
    readonly check: RegistryCheck | null,
    readonly reason: string | null,
    /** true if the transaction was mined and reverted; false if gas estimation reverted. */
    readonly mined: boolean,
    options?: { cause?: unknown }
  ) {
    super(
      `${method} reverted${mined ? " on chain" : ""}: ${reason ?? "no reason string"}${check ? ` [${check}]` : ""}`,
      options
    );
    this.name = "RegistryRevertError";
  }
}

/** Bytes read from an event log do not match the hash stored on chain (or are missing). */
export class LedgerIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LedgerIntegrityError";
  }
}

/** The V4_DESIGN 6.3 check named by a revert, or null. */
export function registryCheckOf(e: unknown): RegistryCheck | null {
  if (e instanceof RegistryRevertError) return e.check;
  const reason = revertReasonOf(e);
  return reason ? checkFromReason(reason) : null;
}

function checkFromReason(reason: string): RegistryCheck | null {
  for (const c of REGISTRY_CHECKS) if (reason.startsWith(`${c}:`) || reason === c) return c;
  return null;
}

function revertReasonOf(e: unknown): string | null {
  if (typeof e !== "object" || e === null) return null;
  const r = (e as { reason?: unknown }).reason;
  if (typeof r === "string" && r.length > 0) return r;
  const revert = (e as { revert?: { args?: unknown[] } }).revert;
  const a0 = revert?.args?.[0];
  if (typeof a0 === "string") return a0;
  const msg = (e as { message?: unknown }).message;
  if (typeof msg === "string") {
    const m = /reverted with reason string '([^']*)'/.exec(msg) ?? /execution reverted: "?([^"\n]*)"?/.exec(msg);
    if (m?.[1]) return m[1];
  }
  return null;
}

function isCallException(e: unknown): boolean {
  return typeof e === "object" && e !== null && (e as { code?: unknown }).code === "CALL_EXCEPTION";
}

function isNonceError(e: unknown): boolean {
  if (typeof e !== "object" || e === null) return false;
  if ((e as { code?: unknown }).code === "NONCE_EXPIRED") return true;
  const msg = String((e as { message?: unknown }).message ?? "");
  return /nonce too low|nonce has already been used|already known/i.test(msg);
}

// ---------------------------------------------------------------------------------------
// accounts and signers
// ---------------------------------------------------------------------------------------

/**
 * NonceManager that serializes sends and re-reads the account nonce after a failed send
 * (the v3 ResettingNonceManager pattern, packages/ledger/src/evm.ts). ethers' NonceManager
 * increments its local nonce before gas estimation, so one failed send would otherwise
 * leave a nonce gap and every later transaction of that account would be queued forever.
 */
export class SerialNonceSigner extends NonceManager {
  private tail: Promise<unknown> = Promise.resolve();

  override sendTransaction(
    tx: Parameters<NonceManager["sendTransaction"]>[0]
  ): ReturnType<NonceManager["sendTransaction"]> {
    const run = this.tail.then(async () => {
      try {
        return await super.sendTransaction(tx);
      } catch (e) {
        this.reset();
        throw e;
      }
    });
    this.tail = run.catch(() => undefined);
    return run;
  }
}

/**
 * One protocol role's EVM account: a fresh random secp256k1 key held only in memory (a
 * private class field), never serialized, logged or written. `address` is lower-case 0x hex
 * (the form the signed statements use for `controller`).
 */
export class RoleAccount {
  readonly #wallet: EthWallet;
  readonly address: string;

  private constructor(
    readonly label: string,
    wallet: EthWallet
  ) {
    this.#wallet = wallet;
    this.address = wallet.address.toLowerCase();
  }

  /** New random account (unfunded). Fund it with LedgerV4.fund before it writes. */
  static random(label: string): RoleAccount {
    for (;;) {
      try {
        return new RoleAccount(label, new EthWallet(hexlify(randomBytes(32))));
      } catch {
        // key out of range (probability ~2^-128): draw again
      }
    }
  }

  /** @internal An ethers signer for this account on `provider`. */
  connectTo(provider: JsonRpcProvider): EthWallet {
    return this.#wallet.connect(provider);
  }

  toJSON(): { label: string; address: string } {
    return { label: this.label, address: this.address };
  }

  toString(): string {
    return `RoleAccount(${this.label}, ${this.address})`;
  }

  [inspect.custom](): string {
    return this.toString();
  }
}

/** A role account, or any ethers Signer (e.g. for negative tests). */
export type SignerLike = RoleAccount | Signer;

// ---------------------------------------------------------------------------------------
// compilation
// ---------------------------------------------------------------------------------------

export interface CompiledContractV4 {
  abi: unknown[];
  bytecode: string;
}

/** Compile .sol sources with the pinned solc-js 0.8.28 (optimizer 200), as v3 does. */
export function compileSolidityV4(sources: Record<string, string>): Record<string, CompiledContractV4> {
  const input = {
    language: "Solidity",
    sources: Object.fromEntries(Object.entries(sources).map(([name, content]) => [name, { content }])),
    settings: {
      optimizer: { enabled: true, runs: 200 },
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input))) as {
    errors?: Array<{ severity: string; formattedMessage: string }>;
    contracts?: Record<string, Record<string, { abi: unknown[]; evm: { bytecode: { object: string } } }>>;
  };
  const fatal = (output.errors ?? []).filter((e) => e.severity === "error");
  if (fatal.length > 0) throw new Error("solc errors:\n" + fatal.map((e) => e.formattedMessage).join("\n"));
  const result: Record<string, CompiledContractV4> = {};
  for (const file of Object.values(output.contracts ?? {})) {
    for (const [name, c] of Object.entries(file)) {
      result[name] = { abi: c.abi, bytecode: "0x" + c.evm.bytecode.object };
    }
  }
  return result;
}

let compiledCache: Record<string, CompiledContractV4> | null = null;

/** Compile onchain/contracts/v4/RegistriesV4.sol (cached per process). */
export function compileRegistriesV4(): Record<ContractNameV4, CompiledContractV4> {
  // PQID_V4_CONTRACTS: mutation runs only (harness/v4/mutation.ts) point this at a copy
  // of the contracts with one require removed. Never set in normal use.
  const file = process.env["PQID_V4_CONTRACTS"] ?? CONTRACTS_V4_FILE;
  compiledCache ??= compileSolidityV4({ "RegistriesV4.sol": fs.readFileSync(file, "utf8") });
  const out = {} as Record<ContractNameV4, CompiledContractV4>;
  for (const n of [
    "DIDRegistryV4",
    "AccreditationRegistryV4",
    "IssuanceRootRegistryV4",
    "VerifierKemRegistryV4",
  ] as const) {
    const c = compiledCache[n];
    if (!c) throw new Error(`contract ${n} missing from solc output`);
    out[n] = c;
  }
  return out;
}

// ---------------------------------------------------------------------------------------
// public types
// ---------------------------------------------------------------------------------------

export interface RegistryAddressesV4 {
  didRegistry: string;
  accreditationRegistry: string;
  issuanceRootRegistry: string;
  verifierKemRegistry: string;
}

export interface DeployOptionsV4 {
  /** Governance EVM account (constructor argument of AccreditationRegistryV4). */
  governanceAddress: string;
  /** Minimum seconds between two epochs of one record (default MIN_ANCHOR_INTERVAL_SEC). */
  minAnchorIntervalSec?: number;
  /** Maximum epoch window notAfter - notBefore in seconds (default MAX_EPOCH_WINDOW_SEC). */
  maxWindowSec?: number;
}

export interface DeploymentInfoV4 {
  deployer: string;
  /** Block of the first deployment transaction (lower bound for log scans). */
  fromBlock: number;
  /** Deployment gas per contract (0 when attached with connect). */
  deployGas: Record<ContractNameV4, number>;
}

/** Result of every registry write. */
export interface WriteResult {
  gasUsed: number;
  txHash: string;
  blockNumber: number;
  /** Transaction calldata size in bytes. */
  calldataBytes: number;
}

export interface WriteOptions {
  /** Skip gas estimation and send with this limit (a reverting call is then mined). */
  gasLimit?: number | bigint;
}

export interface DidRecordV4 {
  did: string;
  controller: string;
  recordKey: string;
  pk: Buffer;
  /** 64 lower-case hex chars, no 0x. */
  popNonce: string;
  /** keccak256 of the PoP signature, 64 lower-case hex chars, no 0x. */
  popSigHash: string;
  origin: string;
  active: boolean;
  registeredAt: number;
  registeredBlock: number;
}

export interface AccreditationPublicationV4 {
  issuerDid: string;
  statement: Buffer;
  signature: Buffer;
  /** On-chain publication counter for this issuer DID (1, 2, ...). Not the signed serial. */
  serial: number;
  /**
   * Signed serial the registry recorded (strictly increasing; must equal the statement's
   * serial). null when the stored value is above Number.MAX_SAFE_INTEGER: no valid statement
   * can carry such a serial (statements.ts requires a safe integer), so readers must refuse.
   * The current contract caps it at 2^53 - 1; an older or mutated registry may not.
   */
  signedSerial: number | null;
  /** The stored signed serial, exact. */
  signedSerialRaw: bigint;
  publishedAt: number;
  publishedBlock: number;
}

export interface EpochAnchorV4 {
  /** 0 when no epoch was published for the record. */
  epoch: number;
  root: bigint;
  revRoot: bigint;
  notBefore: number;
  notAfter: number;
  /** 64 lower-case hex chars, no 0x (as passed to publishEpoch). */
  sigHash: string;
  publishedAt: number;
  publishedBlock: number;
}

export interface KemKeyPublicationV4 {
  did: string;
  controller: string;
  kemPk: Buffer;
  statement: Buffer;
  signature: Buffer;
  /** 1, 2, ... per record. */
  version: number;
  /**
   * notBefore the registry recorded for this publication (check kemMonotonic: strictly
   * increasing per record). Readers must require it to equal the signed statement's notBefore.
   * null when the stored value is above Number.MAX_SAFE_INTEGER (no valid statement can carry
   * it; the current contract caps it, an older or mutated registry may not).
   */
  notBefore: number | null;
  publishedAt: number;
  publishedBlock: number;
}

function makeProvider(rpcUrl: string): JsonRpcProvider {
  // cacheTimeout -1: a nonce re-read after a reset must reach the node, not a 250 ms cache
  const provider = new JsonRpcProvider(rpcUrl, undefined, { cacheTimeout: -1 });
  provider.pollingInterval = 100; // Anvil insta-mines; default 4 s polling only adds latency
  return provider;
}

// ---------------------------------------------------------------------------------------
// the client
// ---------------------------------------------------------------------------------------

export class LedgerV4 {
  private readonly signers = new Map<string, SerialNonceSigner>();
  private chainIdCache: number | null = null;

  private constructor(
    readonly rpcUrl: string,
    readonly addresses: RegistryAddressesV4,
    readonly deployment: DeploymentInfoV4,
    private readonly provider: JsonRpcProvider,
    private readonly deployer: SerialNonceSigner,
    private readonly contracts: Record<ContractNameV4, Contract>
  ) {}

  // ---- construction ----

  /**
   * Deploy the four v4 registries. The deployer (Anvil dev key #0) deploys and funds only;
   * the governance EVM account is `opts.governanceAddress`, never the deployer by default.
   */
  static async deploy(rpcUrl: string, opts: DeployOptionsV4): Promise<LedgerV4> {
    if (typeof opts.governanceAddress !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(opts.governanceAddress)) {
      throw new Error("deploy: governanceAddress must be a 0x EVM address");
    }
    const minAnchor = opts.minAnchorIntervalSec ?? MIN_ANCHOR_INTERVAL_SEC;
    const maxWindow = opts.maxWindowSec ?? MAX_EPOCH_WINDOW_SEC;
    if (!Number.isSafeInteger(minAnchor) || minAnchor < 0) throw new Error("deploy: bad minAnchorIntervalSec");
    if (!Number.isSafeInteger(maxWindow) || maxWindow <= 0) throw new Error("deploy: bad maxWindowSec");

    const provider = makeProvider(rpcUrl);
    const deployer = new SerialNonceSigner(new EthWallet(ANVIL_DEPLOYER_KEY, provider));
    try {
      const compiled = compileRegistriesV4();
      const fromBlock = (await provider.getBlockNumber()) + 1;
      const deployGas = {} as Record<ContractNameV4, number>;
      const dep = async (name: ContractNameV4, args: unknown[]): Promise<string> => {
        const c = compiled[name];
        const factory = new ContractFactory(c.abi as never, c.bytecode, deployer);
        const contract = await factory.deploy(...args);
        const receipt = await contract.deploymentTransaction()?.wait();
        if (!receipt) throw new Error(`deploy ${name}: no receipt`);
        deployGas[name] = num(receipt.gasUsed);
        return (await contract.getAddress()).toLowerCase();
      };
      const didRegistry = await dep("DIDRegistryV4", []);
      const accreditationRegistry = await dep("AccreditationRegistryV4", [opts.governanceAddress]);
      const issuanceRootRegistry = await dep("IssuanceRootRegistryV4", [didRegistry, minAnchor, maxWindow]);
      const verifierKemRegistry = await dep("VerifierKemRegistryV4", [didRegistry]);
      const addresses = { didRegistry, accreditationRegistry, issuanceRootRegistry, verifierKemRegistry };
      return new LedgerV4(
        rpcUrl,
        addresses,
        { deployer: (await deployer.getAddress()).toLowerCase(), fromBlock, deployGas },
        provider,
        deployer,
        LedgerV4.attachContracts(addresses, provider)
      );
    } catch (e) {
      provider.destroy();
      throw e;
    }
  }

  /**
   * Make a fresh governance role account, deploy with it as the governance EVM account,
   * then fund it. Convenience for worlds and tests.
   */
  static async deployGovernanceFirst(
    rpcUrl: string,
    opts: Omit<DeployOptionsV4, "governanceAddress"> = {}
  ): Promise<{ ledger: LedgerV4; governanceAccount: RoleAccount }> {
    const governanceAccount = RoleAccount.random("governance");
    const ledger = await LedgerV4.deploy(rpcUrl, { ...opts, governanceAddress: governanceAccount.address });
    try {
      await ledger.fund(governanceAccount);
    } catch (e) {
      ledger.destroy();
      throw e;
    }
    return { ledger, governanceAccount };
  }

  /**
   * Attach to already-deployed registries (e.g. a second reader). Role accounts used through
   * two LedgerV4 instances at once get two nonce trackers; writes retry once on a nonce
   * error, but keep each writing account on one instance.
   */
  static async connect(rpcUrl: string, addresses: RegistryAddressesV4, fromBlock = 0): Promise<LedgerV4> {
    const provider = makeProvider(rpcUrl);
    const deployer = new SerialNonceSigner(new EthWallet(ANVIL_DEPLOYER_KEY, provider));
    const lower = {
      didRegistry: addresses.didRegistry.toLowerCase(),
      accreditationRegistry: addresses.accreditationRegistry.toLowerCase(),
      issuanceRootRegistry: addresses.issuanceRootRegistry.toLowerCase(),
      verifierKemRegistry: addresses.verifierKemRegistry.toLowerCase(),
    };
    const zero = { DIDRegistryV4: 0, AccreditationRegistryV4: 0, IssuanceRootRegistryV4: 0, VerifierKemRegistryV4: 0 };
    return new LedgerV4(
      rpcUrl,
      lower,
      { deployer: (await deployer.getAddress()).toLowerCase(), fromBlock, deployGas: zero },
      provider,
      deployer,
      LedgerV4.attachContracts(lower, provider)
    );
  }

  private static attachContracts(a: RegistryAddressesV4, provider: JsonRpcProvider): Record<ContractNameV4, Contract> {
    const c = compileRegistriesV4();
    return {
      DIDRegistryV4: new Contract(a.didRegistry, c.DIDRegistryV4.abi as never, provider),
      AccreditationRegistryV4: new Contract(a.accreditationRegistry, c.AccreditationRegistryV4.abi as never, provider),
      IssuanceRootRegistryV4: new Contract(a.issuanceRootRegistry, c.IssuanceRootRegistryV4.abi as never, provider),
      VerifierKemRegistryV4: new Contract(a.verifierKemRegistry, c.VerifierKemRegistryV4.abi as never, provider),
    };
  }

  destroy(): void {
    this.provider.destroy();
  }

  // ---- accounts ----

  /** Fresh random role account, funded from the deployer (default 100 ETH). */
  async newRoleAccount(label: string, fundEth: string = DEFAULT_ROLE_FUNDING_ETH): Promise<RoleAccount> {
    const acct = RoleAccount.random(label);
    await this.fund(acct, fundEth);
    return acct;
  }

  /** Send dev ETH from the deployer (the deployer's only job besides deploying). */
  async fund(to: RoleAccount | string, eth: string = DEFAULT_ROLE_FUNDING_ETH): Promise<void> {
    const address = typeof to === "string" ? to : to.address;
    for (let attempt = 0; ; attempt++) {
      try {
        const tx = await this.deployer.sendTransaction({ to: address, value: parseEther(eth) });
        const r = await tx.wait();
        if (!r || r.status !== 1) throw new Error("funding transaction failed");
        return;
      } catch (e) {
        if (attempt < 2 && isNonceError(e)) continue;
        throw e;
      }
    }
  }

  /** For negative tests only: the deployer as a signer (it must not be able to write registry data). */
  devDeployerSigner(): Signer {
    return this.deployer;
  }

  private signerOf(who: SignerLike): Signer {
    if (!(who instanceof RoleAccount)) return who;
    let s = this.signers.get(who.address);
    if (!s) {
      s = new SerialNonceSigner(who.connectTo(this.provider));
      this.signers.set(who.address, s);
    }
    return s;
  }

  private async addressOf(who: SignerLike): Promise<string> {
    return who instanceof RoleAccount ? who.address : (await who.getAddress()).toLowerCase();
  }

  // ---- generic write ----

  /**
   * Send a registry transaction from `who`. Gas is estimated (+20% + 5000 margin: the
   * estimate can depend on the block the call lands in) unless opts.gasLimit is given.
   * Reverts become RegistryRevertError with the V4_DESIGN 6.3 check name.
   */
  async rawWrite(
    who: SignerLike,
    contract: ContractNameV4,
    method: string,
    args: unknown[],
    opts: WriteOptions = {}
  ): Promise<WriteResult> {
    const signer = this.signerOf(who);
    const fn = (this.contracts[contract].connect(signer) as Contract).getFunction(method);
    for (let attempt = 0; ; attempt++) {
      let tx: ContractTransactionResponse;
      try {
        let gasLimit: bigint;
        if (opts.gasLimit !== undefined) {
          gasLimit = BigInt(opts.gasLimit);
        } else {
          const est = await fn.estimateGas(...args);
          gasLimit = est + est / 5n + 5_000n;
        }
        tx = (await fn(...args, { gasLimit })) as ContractTransactionResponse;
      } catch (e) {
        if (attempt < 2 && isNonceError(e)) continue;
        if (isCallException(e)) {
          const reason = revertReasonOf(e);
          throw new RegistryRevertError(`${contract}.${method}`, reason ? checkFromReason(reason) : null, reason, false, {
            cause: e,
          });
        }
        throw e;
      }
      let receipt: TransactionReceipt | null;
      try {
        receipt = await tx.wait();
      } catch (e) {
        if (!isCallException(e)) throw e;
        const reason = await this.replayReason(tx, await this.addressOf(who));
        throw new RegistryRevertError(`${contract}.${method}`, reason ? checkFromReason(reason) : null, reason, true, {
          cause: e,
        });
      }
      if (!receipt) throw new Error(`${contract}.${method}: no receipt`);
      return {
        gasUsed: num(receipt.gasUsed),
        txHash: receipt.hash,
        blockNumber: receipt.blockNumber,
        calldataBytes: (tx.data.length - 2) / 2,
      };
    }
  }

  /** Best-effort revert reason of a mined, reverted transaction (re-run on the parent block). */
  private async replayReason(tx: ContractTransactionResponse, from: string): Promise<string | null> {
    const blockNumber = tx.blockNumber ?? (await this.provider.getTransactionReceipt(tx.hash))?.blockNumber;
    if (blockNumber === undefined || blockNumber === null) return null;
    try {
      await this.provider.call({ from, to: tx.to, data: tx.data, blockTag: blockNumber - 1 });
      return null;
    } catch (e) {
      return revertReasonOf(e);
    }
  }

  /** Read-only contract handle (for tools that need a raw view call). */
  rawContract(name: ContractNameV4): Contract {
    return this.contracts[name];
  }

  // ---- keys ----

  /** recordKey = keccak256(abi.encodePacked(did, controller)), 0x hex. */
  static recordKey(did: string, controller: string): string {
    return solidityPackedKeccak256(["string", "address"], [did, controller]).toLowerCase();
  }

  /** keccak256(bytes(issuerDid)), the AccreditationRegistryV4 key, 0x hex. */
  static issuerKey(issuerDid: string): string {
    return keccak256(Buffer.from(issuerDid, "utf8")).toLowerCase();
  }

  // ---- DIDRegistryV4 ----

  /**
   * Register (did, signer's address) with its ML-DSA proof of possession. `pk` is the raw
   * ML-DSA-44 public key (1312 bytes for honest callers); neither this client nor the contract
   * checks its length or the PoP: wallets and verifiers do (did:pq binding, issuerPop).
   * `popNonce`: 32 bytes of hex, with or without 0x.
   */
  async registerDid(
    who: SignerLike,
    a: { did: string; pk: Uint8Array; popNonce: string; popSig: Uint8Array; origin?: string },
    opts: WriteOptions = {}
  ): Promise<WriteResult> {
    return this.rawWrite(
      who,
      "DIDRegistryV4",
      "registerDID",
      [a.did, a.pk, hex32(a.popNonce, "popNonce"), a.popSig, a.origin ?? ""],
      opts
    );
  }

  /** The record (did, controller), or null if there is none. */
  async resolveDidRecord(did: string, controller: string): Promise<DidRecordV4 | null> {
    const r = (await this.contracts.DIDRegistryV4.getFunction("resolve")(did, controller)) as Result;
    if (!(r.getValue("exists") as boolean)) return null;
    return {
      did,
      controller: controller.toLowerCase(),
      recordKey: LedgerV4.recordKey(did, controller),
      pk: toBuf(r.getValue("pk") as string),
      popNonce: strip0x(r.getValue("popNonce") as string),
      popSigHash: strip0x(r.getValue("popSigHash") as string),
      origin: r.getValue("origin") as string,
      active: r.getValue("active") as boolean,
      registeredAt: num(r.getValue("registeredAt")),
      registeredBlock: num(r.getValue("registeredBlock")),
    };
  }

  /**
   * The PoP signature of (did, controller), read from its DIDRegisteredV4 log and checked
   * against the stored keccak256 hash. Throws if there is no record or no matching log.
   */
  async getPopSignature(did: string, controller: string): Promise<Buffer> {
    const rec = await this.resolveDidRecord(did, controller);
    if (!rec) throw new Error("no DID record for (did, controller)");
    const logs = await this.eventsAt("DIDRegistryV4", "DIDRegisteredV4", rec.recordKey, rec.registeredBlock);
    for (const log of logs) {
      const sig = toBuf(log.args.getValue("popSig") as string);
      if (
        keccakHex(sig) === rec.popSigHash &&
        (log.args.getValue("did") as string) === did &&
        (log.args.getValue("controller") as string).toLowerCase() === rec.controller
      ) {
        return sig;
      }
    }
    throw new LedgerIntegrityError("no DIDRegisteredV4 log matches the stored PoP signature hash");
  }

  /** Deactivate (did, signer's address). */
  async deactivateDid(who: SignerLike, did: string, opts: WriteOptions = {}): Promise<WriteResult> {
    return this.rawWrite(who, "DIDRegistryV4", "deactivate", [did], opts);
  }

  /** Every controller that registered `did` (from logs, in registration order). */
  async listDidControllers(did: string): Promise<string[]> {
    const c = this.contracts.DIDRegistryV4;
    const logs = await c.queryFilter(c.getEvent("DIDRegisteredV4")(), this.deployment.fromBlock, "latest");
    const out: string[] = [];
    for (const l of logs) {
      if (l instanceof EventLog && (l.args.getValue("did") as string) === did) {
        out.push((l.args.getValue("controller") as string).toLowerCase());
      }
    }
    return out;
  }

  // ---- AccreditationRegistryV4 ----

  /** Post a governance-signed accreditation statement (governance EVM account only). */
  async publishAccreditation(
    governance: SignerLike,
    issuerDid: string,
    statement: Uint8Array,
    signature: Uint8Array,
    opts: WriteOptions & { signedSerial?: number | bigint } = {}
  ): Promise<WriteResult> {
    // The registry requires the signed serial to increase, by at most 2^20, up to 2^53 - 1
    // (check accreditationSerial). The caller may pass it; otherwise it is read from the
    // statement's JSON "serial" field, and for non-JSON test payloads it defaults to the next
    // value after the current one.
    let signedSerial: number | bigint | undefined = opts.signedSerial;
    if (signedSerial === undefined) {
      try {
        const v = (JSON.parse(Buffer.from(statement).toString("utf8")) as { serial?: unknown }).serial;
        if (typeof v === "number" && Number.isSafeInteger(v) && v > 0) signedSerial = v;
      } catch {
        /* not JSON */
      }
    }
    signedSerial ??= (await this.accreditationSignedSerial(issuerDid)) + 1n;
    const { signedSerial: _drop, ...w } = opts;
    return this.rawWrite(governance, "AccreditationRegistryV4", "publish", [issuerDid, signedSerial, statement, signature], w);
  }

  /**
   * The signed serial AccreditationRegistryV4 stores for issuerDid (0n if nothing was
   * published). Governance derives its next serial from it (stored + 1).
   */
  async accreditationSignedSerial(issuerDid: string): Promise<bigint> {
    const l = (await this.contracts.AccreditationRegistryV4.getFunction("latest")(issuerDid)) as Result;
    return BigInt(l.getValue("signedSerial") as bigint);
  }

  /**
   * Latest posted accreditation for issuerDid (bytes from logs, checked against stored hashes),
   * or null. Never throws on a stored signed serial above Number.MAX_SAFE_INTEGER: it then
   * returns signedSerial null (see AccreditationPublicationV4), which checkAccreditation
   * turns into a named refusal.
   */
  async latestAccreditation(issuerDid: string): Promise<AccreditationPublicationV4 | null> {
    const l = (await this.contracts.AccreditationRegistryV4.getFunction("latest")(issuerDid)) as Result;
    const serial = num(l.getValue("serial"));
    if (serial === 0) return null;
    const signedSerialRaw = BigInt(l.getValue("signedSerial") as bigint);
    const signedSerial = safeOrNull(signedSerialRaw);
    const statementHash = strip0x(l.getValue("statementHash") as string);
    const signatureHash = strip0x(l.getValue("signatureHash") as string);
    const publishedBlock = num(l.getValue("publishedBlock"));
    const logs = await this.eventsAt(
      "AccreditationRegistryV4",
      "AccreditationPublishedV4",
      LedgerV4.issuerKey(issuerDid),
      publishedBlock
    );
    for (const log of logs) {
      if (num(log.args.getValue("serial")) !== serial) continue;
      const statement = toBuf(log.args.getValue("statement") as string);
      const signature = toBuf(log.args.getValue("signature") as string);
      if (keccakHex(statement) === statementHash && keccakHex(signature) === signatureHash) {
        return { issuerDid, statement, signature, serial, signedSerial, signedSerialRaw, publishedAt: num(l.getValue("publishedAt")), publishedBlock };
      }
    }
    throw new LedgerIntegrityError("no AccreditationPublishedV4 log matches the stored hashes");
  }

  /** Every accreditation posted for issuerDid, oldest first (from logs; only the latest is hash-anchored). */
  async accreditationHistory(issuerDid: string): Promise<Array<{ serial: number; statement: Buffer; signature: Buffer; blockNumber: number }>> {
    const c = this.contracts.AccreditationRegistryV4;
    const logs = await c.queryFilter(
      c.getEvent("AccreditationPublishedV4")(LedgerV4.issuerKey(issuerDid)),
      this.deployment.fromBlock,
      "latest"
    );
    return logs
      .filter((l): l is EventLog => l instanceof EventLog)
      .map((l) => ({
        serial: num(l.args.getValue("serial")),
        statement: toBuf(l.args.getValue("statement") as string),
        signature: toBuf(l.args.getValue("signature") as string),
        blockNumber: l.blockNumber,
      }));
  }

  /** The governance EVM account set at deployment (lower-case). */
  async governanceAddress(): Promise<string> {
    return ((await this.contracts.AccreditationRegistryV4.getFunction("governance")()) as string).toLowerCase();
  }

  // ---- IssuanceRootRegistryV4 ----

  /** Anchor epoch `epoch` of (did, signer's address). `sigHash`: 32-byte hex of the epoch signature hash. */
  async publishEpoch(
    controller: SignerLike,
    a: {
      did: string;
      epoch: number;
      root: bigint | string;
      revRoot: bigint | string;
      notBefore: number;
      notAfter: number;
      sigHash: string;
    },
    opts: WriteOptions = {}
  ): Promise<WriteResult> {
    return this.rawWrite(
      controller,
      "IssuanceRootRegistryV4",
      "publishEpoch",
      [a.did, a.epoch, BigInt(a.root), BigInt(a.revRoot), a.notBefore, a.notAfter, hex32(a.sigHash, "sigHash")],
      opts
    );
  }

  /** Current anchor of (did, controller); epoch 0 means none was published. */
  async currentEpoch(did: string, controller: string): Promise<EpochAnchorV4> {
    const a = (await this.contracts.IssuanceRootRegistryV4.getFunction("current")(did, controller)) as Result;
    return {
      epoch: num(a.getValue("epoch")),
      root: a.getValue("root") as bigint,
      revRoot: a.getValue("revRoot") as bigint,
      notBefore: num(a.getValue("notBefore")),
      notAfter: num(a.getValue("notAfter")),
      sigHash: strip0x(a.getValue("sigHash") as string),
      publishedAt: num(a.getValue("publishedAt")),
      publishedBlock: num(a.getValue("publishedBlock")),
    };
  }

  async getMinAnchorInterval(): Promise<number> {
    return num(await this.contracts.IssuanceRootRegistryV4.getFunction("minAnchorInterval")());
  }

  async getMaxWindow(): Promise<number> {
    return num(await this.contracts.IssuanceRootRegistryV4.getFunction("maxWindow")());
  }

  // ---- VerifierKemRegistryV4 ----

  /**
   * Publish the ML-KEM-768 key of (did, signer's address) with its ML-DSA-signed statement.
   * The registry requires the declared notBefore to exceed the record's previous one (check
   * kemMonotonic). The caller may pass it; otherwise it is read from the statement's JSON
   * "notBefore" field, and for non-JSON test payloads it defaults to the stored value + 1.
   */
  async publishKemKey(
    verifier: SignerLike,
    a: { did: string; kemPk: Uint8Array; statement: Uint8Array; signature: Uint8Array },
    opts: WriteOptions & { notBefore?: number | bigint } = {}
  ): Promise<WriteResult> {
    let notBefore: number | bigint | undefined = opts.notBefore;
    if (notBefore === undefined) {
      try {
        const v = (JSON.parse(Buffer.from(a.statement).toString("utf8")) as { notBefore?: unknown }).notBefore;
        if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) notBefore = v;
      } catch {
        /* not JSON */
      }
    }
    if (notBefore === undefined) {
      const k = (await this.contracts.VerifierKemRegistryV4.getFunction("latest")(a.did, await this.addressOf(verifier))) as Result;
      notBefore = BigInt(k.getValue("notBefore") as bigint) + 1n;
    }
    const { notBefore: _drop, ...w } = opts;
    return this.rawWrite(verifier, "VerifierKemRegistryV4", "publishKemKey", [a.did, notBefore, a.kemPk, a.statement, a.signature], w);
  }

  /** Current KEM key of (did, controller) (bytes from logs, checked against stored hashes), or null. */
  async latestKemKey(did: string, controller: string): Promise<KemKeyPublicationV4 | null> {
    const k = (await this.contracts.VerifierKemRegistryV4.getFunction("latest")(did, controller)) as Result;
    const version = num(k.getValue("version"));
    if (version === 0) return null;
    const publishedBlock = num(k.getValue("publishedBlock"));
    const want = {
      kemPk: strip0x(k.getValue("kemPkHash") as string),
      statement: strip0x(k.getValue("statementHash") as string),
      signature: strip0x(k.getValue("signatureHash") as string),
    };
    const logs = await this.eventsAt(
      "VerifierKemRegistryV4",
      "KemKeyPublishedV4",
      LedgerV4.recordKey(did, controller),
      publishedBlock
    );
    for (const log of logs) {
      if (num(log.args.getValue("version")) !== version) continue;
      const kemPk = toBuf(log.args.getValue("kemPk") as string);
      const statement = toBuf(log.args.getValue("statement") as string);
      const signature = toBuf(log.args.getValue("signature") as string);
      if (keccakHex(kemPk) === want.kemPk && keccakHex(statement) === want.statement && keccakHex(signature) === want.signature) {
        return {
          did,
          controller: controller.toLowerCase(),
          kemPk,
          statement,
          signature,
          version,
          notBefore: safeOrNull(k.getValue("notBefore")),
          publishedAt: num(k.getValue("publishedAt")),
          publishedBlock,
        };
      }
    }
    throw new LedgerIntegrityError("no KemKeyPublishedV4 log matches the stored hashes");
  }

  // ---- chain ----

  async chainId(): Promise<number> {
    this.chainIdCache ??= num((await this.provider.getNetwork()).chainId);
    return this.chainIdCache;
  }

  /** Timestamp (s) of the latest block. */
  async blockTimestamp(): Promise<number> {
    const b = await this.provider.getBlock("latest");
    if (!b) throw new Error("no latest block");
    return b.timestamp;
  }

  async blockNumber(): Promise<number> {
    return this.provider.getBlockNumber();
  }

  /** Dev chains only (Anvil): move block time forward and mine one block. */
  async devAdvanceTime(seconds: number): Promise<void> {
    await this.provider.send("evm_increaseTime", [seconds]);
    await this.provider.send("evm_mine", []);
  }

  /** Dev chains only (Anvil): the next mined block gets timestamp `ts` (s). Mines nothing. */
  async devSetNextTimestamp(ts: number): Promise<void> {
    await this.provider.send("evm_setNextBlockTimestamp", [ts]);
  }

  /** Dev chains only (Anvil): mine one empty block. */
  async devMine(): Promise<void> {
    await this.provider.send("evm_mine", []);
  }

  // ---- internals ----

  private async eventsAt(contract: ContractNameV4, event: string, key: string, block: number): Promise<EventLog[]> {
    const c = this.contracts[contract];
    const logs = await c.queryFilter(c.getEvent(event)(key), block, block);
    return logs.filter((l): l is EventLog => l instanceof EventLog);
  }
}

export { startAnvil, type AnvilHandle };
