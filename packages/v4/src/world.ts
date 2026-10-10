import { sha3_256 } from "@pqid/common/hash";
import { didFromPublicKey } from "@pqid/common/did";
import { startAnvil, type AnvilHandle } from "@pqid/ledger";
import { LedgerV4, RoleAccount } from "./ledger.ts";
import { ManualClock } from "./clock.ts";
import { mlDsaKeygen, mlDsaSign, mlKemKeygen } from "./pqc.ts";
import { verifierKemMessage } from "./statements.ts";
import { KEM_ALG, MAX_EPOCH_WINDOW_SEC, MIN_ANCHOR_INTERVAL_SEC, DEFAULT_TYPE_ID } from "./constants.ts";
import { utcDateOf } from "./dates.ts";
import { createGovernance, accreditIssuer, type Governance } from "./governance.ts";
import {
  createIssuerV4,
  registerWithPop,
  issueCredentialV4,
  publishEpochV4,
  issuanceWitnessV4,
  revocationWitnessV4,
  type IssuerV4,
  type VerifiableCredentialV4,
} from "./issuer.ts";
import { VerifierV4, type VerifierIdentity, type VerifierCheck } from "./verifier.ts";
import { HolderWalletV4, type IssuerDataSource, type WalletCheck, type WalletV4Config } from "./wallet.ts";
import type { CircuitArtifactsV4 } from "./prove.ts";
import { publishedEpochBlob, parsePublication, type ParsedPublication } from "./published.ts";
import { revKeyFromCredId } from "./encoding.ts";

function union<T>(a?: ReadonlySet<T>, b?: ReadonlySet<T>): ReadonlySet<T> | undefined {
  if (!a && !b) return undefined;
  return new Set<T>([...(a ?? []), ...(b ?? [])]);
}

/**
 * A complete local v4 deployment for tests, the security suite, benchmarks of the
 * protocol layer and the demo: one Anvil node, the v4 registries, a governance key,
 * issuers, verifiers and holders, and one clock that moves together with Anvil's
 * block time.
 */
export interface WorldOptions {
  port?: number;
  minAnchorIntervalSec?: number;
  maxWindowSec?: number;
  /** Defaults for every verifier / holder created (mutation runs; normal use leaves them unset). */
  vkey?: unknown;
  artifacts?: CircuitArtifactsV4;
  verifierDisabled?: ReadonlySet<VerifierCheck>;
  walletDisabled?: ReadonlySet<WalletCheck>;
  inputHook?: WalletV4Config["inputHook"];
  governanceSkipPop?: boolean;
}

export class World {
  opts: WorldOptions = {};

  private constructor(
    readonly anvil: AnvilHandle,
    readonly ledger: LedgerV4,
    readonly clock: ManualClock,
    readonly governance: Governance
  ) {}

  static async create(opts: WorldOptions = {}): Promise<World> {
    const anvil = await startAnvil(opts.port ?? 8570);
    try {
      // Governance EVM account first (the accreditation registry takes it as a constructor
      // argument); it is a fresh random key, not Anvil's dev key #0 (which only deploys and funds).
      const governanceAccount = RoleAccount.random("governance");
      const ledger = await LedgerV4.deploy(anvil.rpcUrl, {
        governanceAddress: governanceAccount.address,
        minAnchorIntervalSec: opts.minAnchorIntervalSec ?? MIN_ANCHOR_INTERVAL_SEC,
        maxWindowSec: opts.maxWindowSec ?? MAX_EPOCH_WINDOW_SEC,
      });
      await ledger.fund(governanceAccount);
      const clock = new ManualClock(await ledger.blockTimestamp());
      const governance = await createGovernance(ledger, governanceAccount);
      const w = new World(anvil, ledger, clock, governance);
      w.opts = opts;
      return w;
    } catch (e) {
      anvil.stop();
      throw e;
    }
  }

  /** Move the shared clock and Anvil's block time forward together. */
  async advance(seconds: number): Promise<void> {
    // Anvil stamps blocks with wall-clock time, so the chain can run ahead of the manual
    // clock during setup; move forward from whichever is later.
    const chainNow = await this.ledger.blockTimestamp();
    this.clock.set(Math.max(this.clock.nowSec(), chainNow) + seconds);
    await this.syncChainTime();
  }

  get today(): number {
    return utcDateOf(this.clock.nowSec());
  }

  /** Issuer with keys, a PoP-registered DID record and a governance accreditation. */
  async addIssuer(label: string, opts: { accredit?: boolean } = {}): Promise<IssuerV4> {
    const issuer = await createIssuerV4(this.ledger, label);
    await registerWithPop(this.ledger, issuer);
    if (opts.accredit !== false) {
      await accreditIssuer(this.governance, this.ledger, this.clock, { did: issuer.did, controller: issuer.controller }, { skipPopCheck: this.opts.governanceSkipPop });
    }
    return issuer;
  }

  /**
   * Anchor the issuer's next epoch and publish its blob (published-tree mode). Every
   * wallet downloads the same blob at publication time, independent of any presentation.
   */
  async publishEpoch(issuer: IssuerV4) {
    await this.syncChainTime();
    const r = await publishEpochV4(issuer, this.ledger, this.clock);
    await this.refreshPublication(issuer);
    return r;
  }

  /**
   * Wallets download the blob of the issuer's current anchor (call after anchoring by any
   * path other than publishEpoch). Stands for the per-epoch download a wallet makes when a
   * new anchor appears on chain, independent of any presentation.
   */
  async refreshPublication(issuer: IssuerV4): Promise<void> {
    if (issuer.anchored) this.publications.set(issuer, await parsePublication(publishedEpochBlob(issuer)));
  }

  /** The last blob each issuer published (what wallets have downloaded). */
  readonly publications = new Map<IssuerV4, ParsedPublication>();

  /**
   * Wallet data source backed by the issuer's latest published blob. The wallet knows its
   * leaf index from issuance; nothing is requested from the issuer when it presents
   * (B5 PRIV-3: the online services saw the credID at every presentation).
   */
  publishedSource(issuer: IssuerV4, leafIndex: number): IssuerDataSource {
    const latest = (): ParsedPublication => {
      const pub = this.publications.get(issuer);
      if (!pub) throw new Error("the issuer has not published an epoch yet");
      return pub;
    };
    return {
      issuance: () => ({ path: latest().issuance.path(leafIndex), statement: latest().statement }),
      revocation: (credIdHex: string) => latest().rev.nonMembershipWitness(revKeyFromCredId(Buffer.from(credIdHex, "hex"))),
    };
  }

  /** Verifier with ML-DSA identity, PoP-registered DID record, origin and an ML-KEM key statement. */
  async addVerifier(label: string, opts: { origin?: string; disabledChecks?: ReadonlySet<VerifierCheck> } = {}): Promise<VerifierV4> {
    const id = await this.newVerifierIdentity(label, opts.origin ?? `https://${label}.verifier.example`);
    return new VerifierV4({
      ledger: this.ledger,
      identity: id,
      pinnedGovernancePk: this.governance.pk,
      clock: this.clock,
      vkey: this.opts.vkey,
      disabledChecks: union(this.opts.verifierDisabled, opts.disabledChecks),
    });
  }

  async newVerifierIdentity(label: string, origin: string): Promise<VerifierIdentity> {
    const { publicKey, privateKey } = mlDsaKeygen();
    const kem = mlKemKeygen();
    const account = await this.ledger.newRoleAccount(`verifier:${label}`);
    const identity: VerifierIdentity = {
      label,
      did: didFromPublicKey(publicKey),
      pk: publicKey,
      sk: privateKey,
      kem,
      account,
      controller: account.address.toLowerCase(),
      origin,
    };
    await registerWithPop(this.ledger, identity, origin);
    await this.publishKemKey(identity);
    return identity;
  }

  /**
   * Sign and publish the verifier's current ML-KEM key (statement window [now, now +
   * validitySec], default 365 days, at most MAX_VERIFIER_KEM_SEC). The registry requires the
   * signed notBefore to exceed the record's previous one (check kemMonotonic), so when the
   * shared clock has not moved past the previous notBefore (a rotation within the same
   * second), the clock is first set to one second after it.
   */
  async publishKemKey(identity: VerifierIdentity, opts: { validitySec?: number } = {}): Promise<void> {
    const prev = await this.ledger.latestKemKey(identity.did, identity.controller);
    if (prev && prev.notBefore !== null && this.clock.nowSec() <= prev.notBefore) this.clock.set(prev.notBefore + 1);
    const now = this.clock.nowSec();
    const statement = verifierKemMessage({
      verifier: identity.did,
      controller: identity.controller,
      chainId: await this.ledger.chainId(),
      registry: this.ledger.addresses.verifierKemRegistry.toLowerCase(),
      kemAlg: KEM_ALG,
      kemPkSha3: sha3_256(identity.kem.publicKey).toString("hex"),
      notBefore: now,
      notAfter: now + (opts.validitySec ?? 365 * 24 * 3600),
    });
    const signature = mlDsaSign(identity.sk, statement);
    await this.ledger.publishKemKey(identity.account, { did: identity.did, kemPk: identity.kem.publicKey, statement, signature });
  }

  async addHolder(opts: { originBinding?: boolean; disabledChecks?: ReadonlySet<WalletCheck>; allowedTypes?: readonly string[] } = {}): Promise<HolderWalletV4> {
    return HolderWalletV4.create({
      ledger: this.ledger,
      clock: this.clock,
      pinnedGovernancePk: this.governance.pk,
      originBinding: opts.originBinding,
      allowedTypes: opts.allowedTypes,
      artifacts: this.opts.artifacts,
      inputHook: this.opts.inputHook,
      disabledChecks: union(this.opts.walletDisabled, opts.disabledChecks),
    });
  }

  /** The issuer's online path and revocation services, as a wallet data source. */
  onlineSource(issuer: IssuerV4): IssuerDataSource {
    return {
      issuance: (credIdHex: string) => issuanceWitnessV4(issuer, credIdHex),
      revocation: (credIdHex: string) => revocationWitnessV4(issuer, credIdHex),
    };
  }

  /**
   * Issue a credential to a holder and put it in the holder's wallet. The wallet reads the
   * issuer's published blobs by default; `source: "online"` models the issuer's online path
   * and revocation services (which see the credID and the time of every presentation).
   */
  async issue(
    issuer: IssuerV4,
    holder: HolderWalletV4,
    a: { birthDate: number; typeId?: string; expiryDate?: number; issuedDate?: number; source?: "published" | "online" }
  ): Promise<VerifiableCredentialV4> {
    const vc = await issueCredentialV4(issuer, {
      subject: holder.subject,
      holderCommit: holder.holderCommit,
      birthDate: a.birthDate,
      typeId: a.typeId ?? DEFAULT_TYPE_ID,
      issuedDate: a.issuedDate ?? this.today,
      expiryDate: a.expiryDate,
    });
    const leafIndex = issuer.leafIndexByCredId.get(vc.credID);
    if (leafIndex === undefined) throw new Error("issuer did not record the leaf index");
    const source = a.source === "online" ? this.onlineSource(issuer) : this.publishedSource(issuer, leafIndex);
    holder.add({ vc, issuerPk: issuer.pk, source });
    return vc;
  }

  /** Make the next block's timestamp the shared clock's time (keeps registry cadence in step). */
  async syncChainTime(): Promise<void> {
    // Mine a block at the clock's time: gas estimation runs against the latest block, so
    // only setting the NEXT block's timestamp is not enough for time-dependent checks.
    const chainNow = await this.ledger.blockTimestamp();
    if (this.clock.nowSec() > chainNow) {
      await this.ledger.devSetNextTimestamp(this.clock.nowSec());
      await this.ledger.devMine();
    }
  }

  stop(): void {
    this.ledger.destroy?.();
    this.anvil.stop();
  }
}
