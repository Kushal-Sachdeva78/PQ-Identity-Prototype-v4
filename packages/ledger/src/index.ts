import type { Contract, JsonRpcProvider } from "ethers";
import { didRegistryKey, type DidDocument } from "@pqid/common/did";
import { sha3_256, canonicalJsonBytes } from "@pqid/common/hash";
import {
  compileRegistries,
  compileIssuanceRootRegistry,
  deployContract,
  devSigner,
  startAnvil,
  type AnvilHandle,
} from "./evm.ts";

/**
 * Ledger / registry layer (paper §III-C) on a single-node EVM. The four
 * registries are real Solidity contracts; multi-node BFT is out of scope [F].
 */
export interface RegistryAddresses {
  didRegistry: string;
  issuerRegistry: string;
  revocationRegistry: string;
  schemaRegistry: string;
  /** Circuit v3: current ML-DSA-signed issuance-tree root per issuer. */
  issuanceRootRegistry: string;
}

/** An issuer's current anchored issuance root (epoch 0 = never published). */
export interface IssuanceRootAnchor {
  root: bigint;
  /** Revocation root the issuer signed and anchored for this epoch (circuit v3's revRoot). */
  revRoot: bigint;
  epoch: number;
  /** SHA3-256 of the attestation's ML-DSA-44 signature, hex. */
  sigHash: string;
  /** Block timestamp (s) of the anchor. */
  publishedAt: number;
}

export const DEFAULT_MIN_ANCHOR_INTERVAL_SEC = 3600;

export class Ledger {
  private constructor(
    readonly rpcUrl: string,
    readonly addresses: RegistryAddresses,
    private readonly didRegistry: Contract,
    private readonly issuerRegistry: Contract,
    private readonly revocationRegistry: Contract,
    private readonly schemaRegistry: Contract,
    private readonly issuanceRootRegistry: Contract,
    private readonly provider: JsonRpcProvider
  ) {}

  /**
   * Deploy the registries to the EVM at rpcUrl. `minAnchorIntervalSec` is the
   * issuance-root registry's minimum time between two epoch anchors of one
   * issuer (default one hour; honest v3 wallets refuse registries below their
   * floor, so an issuer cannot hand out per-holder epochs). Tests advance
   * Anvil's clock with devAdvanceTime.
   */
  static async deploy(rpcUrl: string, opts: { minAnchorIntervalSec?: number } = {}): Promise<Ledger> {
    const { signer, provider } = devSigner(rpcUrl);
    const compiled = compileRegistries();
    const get = (n: string) => {
      const c = compiled[n];
      if (!c) throw new Error(`contract ${n} missing from compilation`);
      return c;
    };
    const didRegistry = await deployContract(get("DIDRegistry"), signer);
    const issuerRegistry = await deployContract(get("IssuerRegistry"), signer);
    const revocationRegistry = await deployContract(get("RevocationRegistry"), signer, [
      await didRegistry.getAddress(),
    ]);
    const schemaRegistry = await deployContract(get("SchemaRegistry"), signer);
    const issuanceRootRegistry = await deployContract(compileIssuanceRootRegistry(), signer, [
      await didRegistry.getAddress(),
      opts.minAnchorIntervalSec ?? DEFAULT_MIN_ANCHOR_INTERVAL_SEC,
    ]);
    return new Ledger(
      rpcUrl,
      {
        didRegistry: await didRegistry.getAddress(),
        issuerRegistry: await issuerRegistry.getAddress(),
        revocationRegistry: await revocationRegistry.getAddress(),
        schemaRegistry: await schemaRegistry.getAddress(),
        issuanceRootRegistry: await issuanceRootRegistry.getAddress(),
      },
      didRegistry,
      issuerRegistry,
      revocationRegistry,
      schemaRegistry,
      issuanceRootRegistry,
      provider
    );
  }

  /** Algorithm 1 (on-chain half): register a DID Document. */
  async registerDid(did: string, publicKeyDilithium: Uint8Array, endpoints: string[] = []): Promise<void> {
    const key = didRegistryKey(did);
    const tx = await this.didRegistry["registerDID"]?.(
      key,
      did,
      publicKeyDilithium,
      JSON.stringify(endpoints)
    );
    await tx.wait();
  }

  /** did:pq resolver: DID Document from the DID Registry. */
  async resolveDid(did: string): Promise<DidDocument & { active: boolean }> {
    const key = didRegistryKey(did);
    const fn = this.didRegistry["resolveDID"];
    if (!fn) throw new Error("resolveDID missing on contract");
    const [didStr, pk, endpoints, active] = (await fn(key)) as [string, string, string, boolean];
    return {
      id: didStr,
      publicKeyDilithium: pk.replace(/^0x/, ""),
      endpoints: JSON.parse(endpoints) as string[],
      active,
    };
  }

  async accreditIssuer(did: string): Promise<void> {
    const tx = await this.issuerRegistry["accredit"]?.(didRegistryKey(did));
    await tx.wait();
  }

  async isAccredited(did: string): Promise<boolean> {
    const fn = this.issuerRegistry["accredited"];
    if (!fn) throw new Error("accredited missing on contract");
    return (await fn(didRegistryKey(did))) as boolean;
  }

  /** Algorithm 4 (on-chain half): publish a new revocation root. */
  async publishRevRoot(issuerDid: string, root: bigint): Promise<void> {
    const tx = await this.revocationRegistry["publishRevRoot"]?.(
      didRegistryKey(issuerDid),
      root
    );
    await tx.wait();
  }

  async getRevRoot(issuerDid: string): Promise<bigint> {
    const fn = this.revocationRegistry["revRoot"];
    if (!fn) throw new Error("revRoot missing on contract");
    return (await fn(didRegistryKey(issuerDid))) as bigint;
  }

  /**
   * Circuit v3: anchor a signed issuance root. `signature` is the hex ML-DSA-44
   * signature from the issuer's attestation; only its SHA3-256 goes on chain.
   */
  async publishIssuanceRoot(
    issuerDid: string,
    att: { epoch: number; root: string; revRoot: string; signature: string }
  ): Promise<void> {
    const sigHash = sha3_256(Buffer.from(att.signature, "hex"));
    const cur = await this.getIssuanceRoot(issuerDid);
    if (
      cur.epoch === att.epoch &&
      cur.root.toString() === att.root &&
      cur.revRoot.toString() === att.revRoot &&
      cur.sigHash === sigHash.toString("hex")
    ) {
      return; // already anchored (idempotent retry)
    }
    const fn = this.issuanceRootRegistry.getFunction("publishIssuanceRoot");
    const args = [didRegistryKey(issuerDid), att.epoch, BigInt(att.root), BigInt(att.revRoot), sigHash] as const;
    // margin: the estimate depends on whether publishedAt changes in the mined block
    const estimate = await fn.estimateGas(...args);
    const tx = await fn(...args, { gasLimit: estimate + estimate / 5n + 5_000n });
    await tx.wait();
  }

  /** The anchor registry's minimum interval between epochs (s); wallets check it. */
  async getMinAnchorInterval(): Promise<number> {
    const fn = this.issuanceRootRegistry["minAnchorInterval"];
    if (!fn) throw new Error("minAnchorInterval missing on contract");
    return Number((await fn()) as bigint);
  }

  async getIssuanceRoot(issuerDid: string): Promise<IssuanceRootAnchor> {
    const fn = this.issuanceRootRegistry["issuanceRoot"];
    if (!fn) throw new Error("issuanceRoot missing on contract");
    const [root, revRoot, epoch, sigHash, publishedAt] = (await fn(didRegistryKey(issuerDid))) as [
      bigint,
      bigint,
      bigint,
      string,
      bigint,
    ];
    return {
      root,
      revRoot,
      epoch: Number(epoch),
      sigHash: sigHash.replace(/^0x/, "").toLowerCase(),
      publishedAt: Number(publishedAt),
    };
  }

  /** Dev chains only (Anvil): move block time forward, e.g. to test anchor cadence. */
  async devAdvanceTime(seconds: number): Promise<void> {
    await this.provider.send("evm_increaseTime", [seconds]);
    await this.provider.send("evm_mine", []);
  }

  async registerSchema(schemaId: string, schemaJson: unknown, uri: string): Promise<void> {
    const idKey = sha3_256(Buffer.from(schemaId, "utf8"));
    const schemaHash = sha3_256(canonicalJsonBytes(schemaJson));
    const tx = await this.schemaRegistry["registerSchema"]?.(idKey, schemaHash, uri);
    await tx.wait();
  }

  destroy(): void {
    this.provider.destroy();
  }
}

export { startAnvil, type AnvilHandle };
