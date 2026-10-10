import type { KeyObject } from "node:crypto";
import { sha3_256 } from "@pqid/common/hash";
import { didFromPublicKey } from "@pqid/common/did";
import { mlDsaKeygen, mlDsaSign, mlDsaVerify } from "./pqc.ts";
import { accreditationMessage, didPopMessage, tryParseStatement, type AccreditationStatement } from "./statements.ts";
import { MAX_ACCREDITATION_SEC, TYPE_ACCREDITATION } from "./constants.ts";
import type { LedgerV4 } from "./ledger.ts";
import type { Clock } from "./clock.ts";
import type { RoleAccount } from "./issuer.ts";

/**
 * Governance (V4_DESIGN sections 3, 7). Accreditation statements are signed with the
 * governance ML-DSA-44 key, whose public key verifiers and wallets pin in their
 * configuration. The governance EVM account only posts the bytes (liveness): nothing is
 * trusted because of which account posted it.
 *
 * Governance keeps no serial counter: the next serial for an issuer DID is derived from
 * the registry (stored signed serial + 1), so a restarted governance process continues
 * where the chain is.
 */
export interface Governance {
  pk: Buffer;
  sk: KeyObject;
  account: RoleAccount;
}

/** The signed accreditation fields (the statement without `type`). */
export type AccreditationFields = Omit<AccreditationStatement, "type">;

export async function createGovernance(ledger: LedgerV4, account?: RoleAccount): Promise<Governance> {
  const { publicKey, privateKey } = mlDsaKeygen();
  return {
    pk: publicKey,
    sk: privateKey,
    account: account ?? (await ledger.newRoleAccount("governance")),
  };
}

/**
 * The serial governance signs next for issuerDid: the registry's stored signed serial + 1
 * (1 when nothing was published). Throws when the stored value leaves no valid serial
 * (above 2^53 - 2, which the current registry's accreditationSerial caps prevent).
 */
export async function nextAccreditationSerial(ledger: LedgerV4, issuerDid: string): Promise<number> {
  const next = (await ledger.accreditationSignedSerial(issuerDid)) + 1n;
  if (next > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("governance refuses accreditation: the registry's signed serial for this DID leaves no valid serial");
  }
  return Number(next);
}

export interface PopCheck {
  ok: boolean;
  reason?: string;
  pk?: Buffer;
  /** The record's origin; covered by the PoP signature when ok. */
  origin?: string;
}

/**
 * Resolve the DID record (did, controller) and check its ML-DSA proof of possession
 * binds this DID, this controller, this chain, this registry and the record's registered
 * origin. The PoP message is rebuilt with the on-chain origin, so a record whose origin
 * was chosen by the submitting EVM account (and not signed by the DID key) fails here.
 * Used by governance before accreditation, and by verifiers and wallets on resolution.
 */
export async function checkRecordAndPop(ledger: LedgerV4, did: string, controller: string): Promise<PopCheck> {
  const rec = await ledger.resolveDidRecord(did, controller);
  if (!rec) return { ok: false, reason: "no DID record for (did, controller)" };
  if (!rec.active) return { ok: false, reason: "DID record is deactivated" };
  const pk = Buffer.from(rec.pk);
  if (didFromPublicKey(pk) !== did) return { ok: false, reason: "registered key does not match the did:pq identifier" };
  let popSig: Buffer;
  try {
    popSig = await ledger.getPopSignature(did, controller);
  } catch (e) {
    return { ok: false, reason: `proof of possession unavailable: ${(e as Error).message}` };
  }
  let msg: Buffer;
  try {
    msg = didPopMessage({
      did,
      controller: controller.toLowerCase(),
      chainId: await ledger.chainId(),
      registry: ledger.addresses.didRegistry.toLowerCase(),
      nonce: String(rec.popNonce).replace(/^0x/, "").toLowerCase(),
      origin: rec.origin,
    });
  } catch {
    return { ok: false, reason: "registered origin is not a valid proof-of-possession origin" };
  }
  if (!mlDsaVerify(pk, msg, popSig)) {
    return { ok: false, reason: "proof of possession does not verify under the registered key (for this controller, chain, registry and origin)" };
  }
  return { ok: true, pk, origin: rec.origin };
}

/**
 * Governance accreditation: refuses unless the record's proof of possession verifies
 * (this is what stops the real-key squatter), then signs and posts the statement. The
 * statement names this chain and this AccreditationRegistryV4, and its serial is the
 * registry's stored signed serial + 1.
 */
export async function accreditIssuer(
  gov: Governance,
  ledger: LedgerV4,
  clock: Clock,
  who: { did: string; controller: string },
  opts: { validitySec?: number; status?: "accredited" | "revoked"; skipPopCheck?: boolean } = {}
): Promise<{ fields: AccreditationFields; statement: Buffer; signature: Buffer }> {
  const pop = await checkRecordAndPop(ledger, who.did, who.controller);
  if (!opts.skipPopCheck && !pop.ok) {
    throw new Error(`governance refuses accreditation: ${pop.reason}`);
  }
  const rec = await ledger.resolveDidRecord(who.did, who.controller);
  if (!rec) throw new Error("governance refuses accreditation: no DID record");
  const now = clock.nowSec();
  const validity = Math.min(opts.validitySec ?? MAX_ACCREDITATION_SEC, MAX_ACCREDITATION_SEC);
  const fields: AccreditationFields = {
    issuerDid: who.did,
    controller: who.controller.toLowerCase(),
    pkSha3: sha3_256(Buffer.from(rec.pk)).toString("hex"),
    chainId: await ledger.chainId(),
    registry: ledger.addresses.accreditationRegistry.toLowerCase(),
    serial: await nextAccreditationSerial(ledger, who.did),
    status: opts.status ?? "accredited",
    notBefore: now,
    notAfter: now + validity,
  };
  const statement = accreditationMessage(fields);
  const signature = mlDsaSign(gov.sk, statement);
  await ledger.publishAccreditation(gov.account, who.did, statement, signature, { signedSerial: fields.serial });
  return { fields, statement, signature };
}

export interface AccreditationCheck {
  ok: boolean;
  reason?: string;
  fields?: AccreditationFields;
}

/**
 * The accreditation check verifiers and wallets run: the latest posted statement for
 * the DID verifies under the PINNED governance key, is a valid canonical accreditation
 * statement, names this chain and this AccreditationRegistryV4, names this DID,
 * controller and key, carries the serial the registry recorded, says "accredited", is in
 * its validity window, and does not roll back the serial.
 */
export async function checkAccreditation(
  ledger: LedgerV4,
  pinnedGovernancePk: Buffer,
  did: string,
  controller: string,
  pk: Buffer,
  nowSec: number,
  highestSerialSeen?: Map<string, number>
): Promise<AccreditationCheck> {
  const latest = await ledger.latestAccreditation(did);
  if (!latest) return { ok: false, reason: "no accreditation statement for this DID" };
  if (latest.signedSerial === null) {
    return { ok: false, reason: "registry signed serial is above 2^53 - 1, which no valid statement can carry" };
  }
  if (!mlDsaVerify(pinnedGovernancePk, Buffer.from(latest.statement), Buffer.from(latest.signature))) {
    return { ok: false, reason: "accreditation statement is not signed by the pinned governance key" };
  }
  const parsed = tryParseStatement(Buffer.from(latest.statement));
  if (!parsed.ok) return { ok: false, reason: `accreditation statement is malformed: ${parsed.errors.join("; ")}` };
  if (parsed.value.type !== TYPE_ACCREDITATION) return { ok: false, reason: "wrong statement type" };
  const { type: _type, ...f } = parsed.value;
  if (f.chainId !== (await ledger.chainId())) return { ok: false, reason: "accreditation names a different chain" };
  if (f.registry !== ledger.addresses.accreditationRegistry.toLowerCase()) {
    return { ok: false, reason: "accreditation names a different accreditation registry" };
  }
  if (f.issuerDid !== did) return { ok: false, reason: "accreditation names a different DID" };
  if (f.controller !== controller.toLowerCase()) return { ok: false, reason: "accreditation names a different controller" };
  if (f.pkSha3 !== sha3_256(pk).toString("hex")) return { ok: false, reason: "accreditation names a different key" };
  if (f.serial !== latest.signedSerial) return { ok: false, reason: "statement serial differs from the registry's monotonic signed serial" };
  if (f.status !== "accredited") return { ok: false, reason: `accreditation status is ${f.status}` };
  if (nowSec < f.notBefore || nowSec > f.notAfter) return { ok: false, reason: "accreditation is outside its validity window" };
  if (highestSerialSeen) {
    const hi = highestSerialSeen.get(did) ?? 0;
    if (f.serial < hi) return { ok: false, reason: `accreditation serial ${f.serial} rolls back ${hi}` };
    highestSerialSeen.set(did, f.serial);
  }
  return { ok: true, fields: f };
}
