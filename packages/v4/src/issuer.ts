import { randomBytes, type KeyObject } from "node:crypto";
import { canonicalJsonBytes, sha3_256 } from "@pqid/common/hash";
import { didFromPublicKey } from "@pqid/common/did";
import { IssuanceTree, type IssuancePath } from "@pqid/issuer";
import { getPoseidon, issuerKeyHash, credIdLimbs } from "@pqid/common/encoding";
import { credentialLeafV4, credTypeField, revKeyFromCredId } from "./encoding.ts";
import { assertValidYmd, addDays, utcDateOf } from "./dates.ts";
import { DEFAULT_CREDENTIAL_DAYS, DEFAULT_TYPE_ID, EPOCH_WINDOW_SEC, EPOCH_BACKDATE_SEC, REV_DEPTH, ISSUANCE_DEPTH } from "./constants.ts";
import { mlDsaKeygen, mlDsaSign } from "./pqc.ts";
import { didPopMessage, epochMessage } from "./statements.ts";
import { IndexedMerkleTree } from "./imt.ts";
import type { LedgerV4 } from "./ledger.ts";
import type { Clock } from "./clock.ts";

/**
 * v4 issuer (V4_DESIGN sections 1, 3, 4). Differences from v3's issuer:
 *  - the credential commits birthDate, expiryDate and a credential type (not an age);
 *  - revocation is an indexed Merkle tree keyed by the 251-bit revKey;
 *  - each epoch statement carries a signed validity window and names the
 *    controller, chain and registry it is anchored in;
 *  - the issuer's DID record carries an ML-DSA proof of possession that binds its
 *    controller account, chain and registry.
 */

export type RoleAccount = Awaited<ReturnType<LedgerV4["newRoleAccount"]>>;

export interface CredentialV4 {
  v: 4;
  subject: string;
  issuer: string;
  issuerController: string;
  typeId: string;
  birthDate: number;
  expiryDate: number;
  issuedDate: number;
  holderCommit: string;
  salt: string;
}

export interface VerifiableCredentialV4 {
  credential: CredentialV4;
  credID: string; // hex, 32 bytes = SHA3-256(canonicalJson(credential) || pk_issuer)
  signature: string; // hex, ML-DSA-44 over credID
  leafIndex: number;
}

export interface EpochStatementFields {
  issuer: string;
  controller: string;
  chainId: number;
  registry: string;
  epoch: number;
  root: string;
  revRoot: string;
  notBefore: number;
  notAfter: number;
  fromDate: number;
  toDate: number;
}

export interface EpochStatementV4 extends EpochStatementFields {
  signature: string; // hex ML-DSA-44 over epochMessage(fields)
}

interface EpochState {
  statement: EpochStatementV4;
  size: number;
  rev: IndexedMerkleTree;
}

export interface IssuerV4 {
  label: string;
  did: string;
  pk: Buffer;
  /** ML-DSA-44 private key; stays in memory (never serialized). */
  sk: KeyObject;
  account: RoleAccount;
  controller: string;
  tree: IssuanceTree;
  rev: IndexedMerkleTree;
  leafIndexByCredId: Map<string, number>;
  credIdByLeaf: Map<number, string>;
  signed: EpochState[];
  anchored: EpochState | null;
}

export function computeCredIdV4(cred: CredentialV4, pkIssuer: Uint8Array): Buffer {
  return sha3_256(canonicalJsonBytes(cred), pkIssuer);
}

export function sigHashOf(signatureHex: string): string {
  return sha3_256(Buffer.from(signatureHex, "hex")).toString("hex");
}

/** Create the issuer's keys and an EVM controller account (not yet registered). */
export async function createIssuerV4(ledger: LedgerV4, label: string): Promise<IssuerV4> {
  const { publicKey, privateKey } = mlDsaKeygen();
  const account = await ledger.newRoleAccount(`issuer:${label}`);
  return {
    label,
    did: didFromPublicKey(publicKey),
    pk: publicKey,
    sk: privateKey,
    account,
    controller: account.address.toLowerCase(),
    tree: await IssuanceTree.create(ISSUANCE_DEPTH),
    rev: await IndexedMerkleTree.create(REV_DEPTH),
    leafIndexByCredId: new Map(),
    credIdByLeaf: new Map(),
    signed: [],
    anchored: null,
  };
}

/**
 * Register a DID record (did, controller) with an ML-DSA proof of possession. The PoP
 * signs the origin registered with the record (issuers pass "", verifiers their web
 * origin), so the EVM account that submits the registration cannot choose another one.
 */
export async function registerWithPop(
  ledger: LedgerV4,
  who: { did: string; pk: Buffer; sk: KeyObject; account: RoleAccount },
  origin = ""
): Promise<{ popNonce: string; gasUsed: bigint | number }> {
  const popNonce = randomBytes(32).toString("hex");
  const msg = didPopMessage({
    did: who.did,
    controller: who.account.address.toLowerCase(),
    chainId: await ledger.chainId(),
    registry: ledger.addresses.didRegistry.toLowerCase(),
    nonce: popNonce,
    origin,
  });
  const popSig = mlDsaSign(who.sk, msg);
  const r = await ledger.registerDid(who.account, { did: who.did, pk: who.pk, popNonce, popSig, origin });
  return { popNonce, gasUsed: r.gasUsed };
}

/** Issue a v4 credential and append its leaf (the new root is signed at the next epoch). */
export async function issueCredentialV4(
  issuer: IssuerV4,
  args: {
    subject: string;
    holderCommit: bigint;
    birthDate: number;
    typeId?: string;
    issuedDate: number;
    expiryDate?: number;
  }
): Promise<VerifiableCredentialV4> {
  const credential: CredentialV4 = {
    v: 4,
    subject: args.subject,
    issuer: issuer.did,
    issuerController: issuer.controller,
    typeId: args.typeId ?? DEFAULT_TYPE_ID,
    birthDate: assertValidYmd(args.birthDate, "birthDate"),
    expiryDate: assertValidYmd(args.expiryDate ?? addDays(args.issuedDate, DEFAULT_CREDENTIAL_DAYS), "expiryDate"),
    issuedDate: assertValidYmd(args.issuedDate, "issuedDate"),
    holderCommit: args.holderCommit.toString(),
    salt: randomBytes(32).toString("hex"),
  };
  const credId = computeCredIdV4(credential, issuer.pk);
  const signature = mlDsaSign(issuer.sk, credId);
  const poseidon = await getPoseidon();
  const leaf = credentialLeafV4(poseidon, {
    issuerKeyHash: issuerKeyHash(poseidon, issuer.pk),
    credId,
    holderCommit: args.holderCommit,
    birthDate: credential.birthDate,
    expiryDate: credential.expiryDate,
    credType: credTypeField(poseidon, credential.typeId),
  });
  const leafIndex = issuer.tree.insert(leaf);
  const hex = credId.toString("hex");
  issuer.leafIndexByCredId.set(hex, leafIndex);
  issuer.credIdByLeaf.set(leafIndex, hex);
  return { credential, credID: hex, signature: signature.toString("hex"), leafIndex };
}

/** Revoke: insert the credential's revKey into the IMT. Takes effect at the next epoch. */
export function revokeCredentialV4(issuer: IssuerV4, credIdHex: string): void {
  if (!issuer.leafIndexByCredId.has(credIdHex)) throw new Error("credential was not issued by this issuer");
  const key = revKeyFromCredId(Buffer.from(credIdHex, "hex"));
  if (issuer.rev.has(key)) throw new Error("credential already revoked");
  issuer.rev.insert(key);
}

/**
 * Sign the next epoch statement over the current trees with a validity window
 * [now, now + EPOCH_WINDOW_SEC]. Epochs number anchored statements (previous + 1),
 * so an unanchored statement is superseded, not skipped.
 */
export async function signEpochV4(
  issuer: IssuerV4,
  ledger: LedgerV4,
  clock: Clock,
  opts: { windowSec?: number; notBefore?: number } = {}
): Promise<EpochStatementV4> {
  const notBefore = opts.notBefore ?? clock.nowSec() - EPOCH_BACKDATE_SEC;
  const notAfter = notBefore + (opts.windowSec ?? EPOCH_WINDOW_SEC);
  const fields: EpochStatementFields = {
    issuer: issuer.did,
    controller: issuer.controller,
    chainId: await ledger.chainId(),
    registry: ledger.addresses.issuanceRootRegistry.toLowerCase(),
    epoch: (issuer.anchored?.statement.epoch ?? 0) + 1,
    root: issuer.tree.root().toString(),
    revRoot: issuer.rev.root().toString(),
    notBefore,
    notAfter,
    fromDate: utcDateOf(notBefore),
    toDate: utcDateOf(notAfter),
  };
  const signature = mlDsaSign(issuer.sk, epochMessage(fields)).toString("hex");
  const statement: EpochStatementV4 = { ...fields, signature };
  issuer.signed.push({ statement, size: issuer.tree.size, rev: issuer.rev.snapshot() });
  return statement;
}

/** Anchor a signed statement on chain, then make it the served one. */
export async function anchorEpochV4(
  issuer: IssuerV4,
  ledger: LedgerV4,
  statement: EpochStatementV4
): Promise<{ gasUsed: bigint | number }> {
  const r = await ledger.publishEpoch(issuer.account, {
    did: issuer.did,
    epoch: statement.epoch,
    root: BigInt(statement.root),
    revRoot: BigInt(statement.revRoot),
    notBefore: statement.notBefore,
    notAfter: statement.notAfter,
    sigHash: sigHashOf(statement.signature),
  });
  await syncAnchorV4(issuer, ledger);
  return { gasUsed: r.gasUsed };
}

/** Reconcile the served state with the chain (the source of truth). */
export async function syncAnchorV4(issuer: IssuerV4, ledger: LedgerV4): Promise<void> {
  const cur = await ledger.currentEpoch(issuer.did, issuer.controller);
  if (!cur || Number(cur.epoch) === 0) return;
  const match = (s: EpochStatementV4) =>
    s.epoch === Number(cur.epoch) &&
    s.root === BigInt(cur.root).toString() &&
    s.revRoot === BigInt(cur.revRoot).toString() &&
    s.notBefore === Number(cur.notBefore) &&
    s.notAfter === Number(cur.notAfter) &&
    sigHashOf(s.signature) === String(cur.sigHash).replace(/^0x/, "").toLowerCase();
  if (issuer.anchored && match(issuer.anchored.statement)) return;
  const entry = issuer.signed.find((e) => match(e.statement));
  if (!entry) throw new Error(`chain anchor (epoch ${cur.epoch}) is not a statement this issuer signed: state diverged`);
  issuer.anchored = entry;
  issuer.signed = issuer.signed.filter((e) => e.statement.epoch > entry.statement.epoch);
}

/** Sign and anchor in one step (the honest issuer's routine). */
export async function publishEpochV4(issuer: IssuerV4, ledger: LedgerV4, clock: Clock, opts: { windowSec?: number } = {}) {
  const st = await signEpochV4(issuer, ledger, clock, opts);
  const { gasUsed } = await anchorEpochV4(issuer, ledger, st);
  return { statement: st, gasUsed };
}

export interface IssuanceServiceReply {
  path: IssuancePath;
  statement: EpochStatementV4;
}

/** Holder-facing: path of the credential against the ANCHORED statement. */
export function issuanceWitnessV4(issuer: IssuerV4, credIdHex: string): IssuanceServiceReply {
  const leafIndex = issuer.leafIndexByCredId.get(credIdHex);
  if (leafIndex === undefined) throw new Error("credential was not issued by this issuer");
  const a = issuer.anchored;
  if (!a || leafIndex >= a.size) throw new Error("credential is not yet covered by an anchored epoch statement");
  const path = issuer.tree.pathAt(leafIndex, a.size);
  if (path.root !== a.statement.root) throw new Error("internal: anchored root does not match the tree snapshot");
  return { path, statement: a.statement };
}

/** Holder-facing: revocation non-membership witness against the ANCHORED revRoot. */
export function revocationWitnessV4(issuer: IssuerV4, credIdHex: string) {
  const a = issuer.anchored;
  if (!a) throw new Error("no anchored epoch statement");
  const key = revKeyFromCredId(Buffer.from(credIdHex, "hex"));
  const w = a.rev.nonMembershipWitness(key); // throws if revoked in the anchored snapshot
  if (w.root !== a.statement.revRoot) throw new Error("internal: anchored revRoot does not match the snapshot");
  return w;
}

/** Limb helper re-exported for harnesses. */
export { credIdLimbs };
