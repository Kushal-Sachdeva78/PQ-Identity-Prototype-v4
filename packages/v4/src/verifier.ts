import fs from "node:fs";
import type { KeyObject } from "node:crypto";
import type { Groth16Proof } from "snarkjs";
import { sha3_256 } from "@pqid/common/hash";
import { didFromPublicKey } from "@pqid/common/did";
import { BN254_P } from "./constants.ts";
import { getPoseidon, issuerKeyHash, verifierDomainTag, credTypeField, policyHashV4, stmtCodeV4 } from "./encoding.ts";
import { isValidYmd, utcDateOf } from "./dates.ts";
import { mlDsaVerify } from "./pqc.ts";
import { epochMessage, isDidPq } from "./statements.ts";
import { checkRecordAndPop, checkAccreditation } from "./governance.ts";
import { VerifierSessionStore, verifierOpenReply, type ProofRequestV4, type SessionReplyV4 } from "./session.ts";
import { VKEY_V4 } from "./paths.ts";
import type { LedgerV4 } from "./ledger.ts";
import type { Clock } from "./clock.ts";
import type { EpochStatementV4, RoleAccount } from "./issuer.ts";

/**
 * v4 verifier (V4_DESIGN section 6.1). Order of checks:
 *   shape, sessionKnown, transcriptDecrypts, issuerRecord, issuerPop, accreditation,
 *   issuerKeyHash, epochAnchorCurrent, epochWindow, revRoot, policyHash, nonceBinding,
 *   stmtCode, groth16, sessionFresh, epochSignature
 * The session is consumed only when every other check passed; the ML-DSA epoch
 * signature runs last and only for that copy.
 *
 * `disabledChecks` exists ONLY for the mutation table (harness/v4): a disabled check
 * is skipped and counted as passed. Production code never sets it.
 */
export const VERIFIER_CHECKS = [
  "shape",
  "sessionKnown",
  "transcriptDecrypts",
  "issuerRecord",
  "issuerPop",
  "accreditation",
  "issuerKeyHash",
  "epochAnchorCurrent",
  "epochWindow",
  "revRoot",
  "policyHash",
  "nonceBinding",
  "stmtCode",
  "groth16",
  "sessionFresh",
  "epochSignature",
] as const;
export type VerifierCheck = (typeof VERIFIER_CHECKS)[number];

export interface PresentationV4 {
  proof: Groth16Proof;
  publicSignals: string[];
  issuerDid: string;
  issuerController: string;
  epochStatement: EpochStatementV4;
}

export interface VerifyDecisionV4 {
  accepted: boolean;
  checks: Partial<Record<VerifierCheck, boolean>>;
  failedChecks: VerifierCheck[];
  notEvaluated: VerifierCheck[];
  reasons: string[];
}

export interface VerifierIdentity {
  label: string;
  did: string;
  pk: Buffer;
  sk: KeyObject;
  kem: { publicKey: Buffer; privateKey: KeyObject };
  account: RoleAccount;
  controller: string;
  origin: string;
}

export interface VerifierV4Options {
  ledger: LedgerV4;
  identity: VerifierIdentity;
  pinnedGovernancePk: Buffer;
  clock: Clock;
  vkey?: unknown;
  disabledChecks?: ReadonlySet<VerifierCheck>;
}

const DEC = /^(0|[1-9][0-9]*)$/;
const ADDR = /^0x[0-9a-f]{40}$/;
/** ML-DSA-44 signature: 2,420 bytes as lower-case hex. */
export const SIG_HEX = /^[0-9a-f]{4840}$/;
/** ML-DSA-44 public key length in bytes (FIPS 204). */
export const ML_DSA_44_PK_BYTES = 1312;
export const EPOCH_KEYS = "chainId,controller,epoch,fromDate,issuer,notAfter,notBefore,registry,revRoot,root,signature,toDate";
const PROOF_KEYS = "curve,pi_a,pi_b,pi_c,protocol";

export class VerifierV4 {
  /** Sessions run on the verifier's clock, so suites exercise the real TTL (B5 VER-4). */
  readonly sessions: VerifierSessionStore;
  private readonly vkey: unknown;
  private readonly highestSerial = new Map<string, number>();
  readonly disabled: ReadonlySet<VerifierCheck>;

  constructor(readonly opts: VerifierV4Options) {
    this.vkey = opts.vkey ?? JSON.parse(fs.readFileSync(VKEY_V4, "utf8"));
    const nPublic = (this.vkey as { nPublic?: number }).nPublic;
    if (nPublic !== 8) throw new Error(`v4 verification key must have nPublic=8, got ${String(nPublic)}`);
    this.disabled = opts.disabledChecks ?? new Set();
    this.sessions = new VerifierSessionStore({ nowMs: () => opts.clock.nowSec() * 1000 });
  }

  get did(): string {
    return this.opts.identity.did;
  }

  /** Open a session: the request carries this verifier's date, policy and identity. */
  async newRequest(policy: { predicate: "age_gte" | "age_lt"; threshold: number; typeId: string; today?: number }): Promise<ProofRequestV4> {
    const now = this.opts.clock.nowSec();
    return this.sessions.open({
      verifierDid: this.opts.identity.did,
      verifierController: this.opts.identity.controller,
      chainId: await this.opts.ledger.chainId(),
      policy: { predicate: policy.predicate, threshold: policy.threshold, typeId: policy.typeId, today: policy.today ?? utcDateOf(now) },
      issuedAt: now,
    });
  }

  /** Never throws on attacker-controlled input: any exception is a failed decision (B5 VER-2). */
  async verifyReply(reply: SessionReplyV4): Promise<VerifyDecisionV4> {
    try {
      return await this.verifyReplyInner(reply);
    } catch (e) {
      // Fail closed. Reported without a check name: this is the exception handler, not the
      // shape check (the mutation table must be able to tell them apart).
      const d: VerifyDecisionV4 = { accepted: false, checks: {}, failedChecks: [], notEvaluated: [...VERIFIER_CHECKS], reasons: [`verifier error on hostile input (rejected): ${(e as Error).message}`] };
      return d;
    }
  }

  private async verifyReplyInner(reply: SessionReplyV4): Promise<VerifyDecisionV4> {
    const d: VerifyDecisionV4 = { accepted: false, checks: {}, failedChecks: [], notEvaluated: [], reasons: [] };
    const on = (c: VerifierCheck) => !this.disabled.has(c);
    const set = (c: VerifierCheck, ok: boolean, reason?: string) => {
      const v = on(c) ? ok : true;
      d.checks[c] = v;
      if (!v) {
        d.failedChecks.push(c);
        if (reason) d.reasons.push(`${c}: ${reason}`);
      }
      return v;
    };
    const finish = () => {
      for (const c of VERIFIER_CHECKS) if (d.checks[c] === undefined) d.notEvaluated.push(c);
      d.accepted = VERIFIER_CHECKS.every((c) => d.checks[c] === true);
      return d;
    };

    // Transport: session lookup and decryption under the ML-KEM-derived key.
    const opened = verifierOpenReply(this.sessions, this.opts.identity.kem.privateKey, this.opts.identity.kem.publicKey, reply);
    const known = opened.ok || (opened.error !== "unknownSession" && opened.error !== "expiredSession");
    if (!set("sessionKnown", known, opened.error)) return finish();
    if (!set("transcriptDecrypts", opened.ok, opened.error)) return finish();
    const request = opened.request as ProofRequestV4;
    const derivedNonce = opened.nonce as bigint;
    return this.checkPresentation(request, derivedNonce, opened.presentation, opened.sessionId as string, d, set, finish);
  }

  /** The presentation checks after transport (shared by verifyReply). */
  private async checkPresentation(
    request: ProofRequestV4,
    derivedNonce: bigint,
    raw: unknown,
    sessionId: string,
    d: VerifyDecisionV4,
    set: (c: VerifierCheck, ok: boolean, reason?: string) => boolean,
    finish: () => VerifyDecisionV4
  ): Promise<VerifyDecisionV4> {
    // One plain-data copy before anything else.
    let p: PresentationV4;
    try {
      p = structuredClone(raw) as PresentationV4;
    } catch {
      set("shape", false, "presentation must be plain data");
      return finish();
    }
    const shapeErr = presentationShapeError(p);
    if (!set("shape", shapeErr === null, shapeErr ?? undefined)) return finish();
    const sig = p.publicSignals;
    const st = p.epochStatement;
    const { ledger, clock, pinnedGovernancePk } = this.opts;
    const now = clock.nowSec();
    const poseidon = await getPoseidon();

    // Issuer: record (did, controller), proof of possession, pinned-governance accreditation.
    const rec = await ledger.resolveDidRecord(p.issuerDid, p.issuerController);
    const recPk = rec ? Buffer.from(rec.pk) : null;
    const recordOk = !!rec && rec.active && !!recPk && recPk.length === ML_DSA_44_PK_BYTES && didFromPublicKey(recPk) === p.issuerDid;
    set("issuerRecord", recordOk, rec ? (rec.active ? "registered key does not match the did:pq identifier" : "DID record deactivated") : "no DID record for (did, controller)");
    const pk: Buffer | null = recordOk || this.disabled.has("issuerRecord") ? recPk : null;
    const pop = await checkRecordAndPop(ledger, p.issuerDid, p.issuerController);
    set("issuerPop", pop.ok, pop.reason);
    if (pk) {
      const acc = await checkAccreditation(ledger, pinnedGovernancePk, p.issuerDid, p.issuerController, pk, now, this.highestSerial);
      set("accreditation", acc.ok, acc.reason);
      set("issuerKeyHash", issuerKeyHash(poseidon, pk).toString() === sig[0], "Poseidon(pk_issuer) does not match public signal 0");
    } else {
      set("accreditation", false, "no issuer key");
      set("issuerKeyHash", false, "no issuer key");
    }

    // Epoch statement: current anchor, validity window, roots.
    const chainId = await ledger.chainId();
    const anchor = await ledger.currentEpoch(p.issuerDid, p.issuerController);
    const anchorOk =
      !!anchor &&
      Number(anchor.epoch) === st.epoch &&
      BigInt(anchor.root).toString() === st.root &&
      BigInt(anchor.revRoot).toString() === st.revRoot &&
      Number(anchor.notBefore) === st.notBefore &&
      Number(anchor.notAfter) === st.notAfter &&
      String(anchor.sigHash).replace(/^0x/, "").toLowerCase() === sha3_256(Buffer.from(st.signature, "hex")).toString("hex") &&
      st.issuer === p.issuerDid &&
      st.controller === p.issuerController &&
      st.chainId === chainId &&
      st.registry === ledger.addresses.issuanceRootRegistry.toLowerCase() &&
      sig[5] === st.root;
    set("epochAnchorCurrent", anchorOk, "the epoch statement is not the issuer's current anchor (or names another chain, registry, controller or root)");
    const windowOk =
      now >= st.notBefore &&
      now <= st.notAfter &&
      st.fromDate === utcDateOf(st.notBefore) &&
      st.toDate === utcDateOf(st.notAfter) &&
      sig[6] === String(st.fromDate) &&
      sig[7] === String(st.toDate);
    set("epochWindow", windowOk, "outside the epoch statement's signed validity window (or window signals differ)");
    set("revRoot", sig[1] === st.revRoot, "revRoot (signal 1) is not the anchored revocation root");

    // Policy, session nonce, verifier domain.
    const pol = request.policy;
    const expectedPolicy = policyHashV4(poseidon, {
      predicate: pol.predicate,
      threshold: pol.threshold,
      today: pol.today,
      requiredType: credTypeField(poseidon, pol.typeId),
    }).toString();
    set("policyHash", sig[2] === expectedPolicy, "policyHash does not bind this session's predicate, threshold, date and type");
    set("nonceBinding", sig[3] === derivedNonce.toString(), "nonce is not the one derived from this session's ML-KEM transcript");
    const expectedStmt = stmtCodeV4(poseidon, verifierDomainTag(poseidon, this.opts.identity.did)).toString();
    set("stmtCode", sig[4] === expectedStmt, "stmtCode does not bind this verifier");

    // Groth16.
    let proofOk = false;
    try {
      const snarkjs = await import("snarkjs");
      proofOk = await snarkjs.groth16.verify(this.vkey, sig, p.proof);
    } catch (e) {
      d.reasons.push(`groth16: malformed proof: ${(e as Error).message}`);
    }
    set("groth16", proofOk, "Groth16 proof does not verify");

    // Consume the session only if everything so far passed (synchronous from here).
    const othersPass = VERIFIER_CHECKS.every((c) => c === "sessionFresh" || c === "epochSignature" || d.checks[c] === true);
    if (othersPass) {
      set("sessionFresh", this.sessions.consume(sessionId) || this.disabled.has("sessionFresh"), "session already used");
    }
    if (othersPass && d.checks.sessionFresh === true && pk) {
      const { signature, ...fields } = st;
      let ok = false;
      try {
        ok = mlDsaVerify(pk, epochMessage(fields), Buffer.from(signature, "hex"));
      } catch {
        ok = false;
      }
      set("epochSignature", ok, "epoch statement ML-DSA-44 signature does not verify under pk_issuer");
    }
    return finish();
  }
}

/** Structural checks: exactly 8 canonical signals, well-formed statement and identifiers. */
/** BN254 base-field modulus (proof coordinates live in F_q, not the scalar field F_p). */
const BN254_P_BASE = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

export function presentationShapeError(p: unknown): string | null {
  const x = p as Partial<PresentationV4> | null;
  if (!x || typeof x !== "object") return "presentation must be an object";
  const keys = Object.keys(x).sort().join(",");
  if (keys !== "epochStatement,issuerController,issuerDid,proof,publicSignals") return `presentation keys must be exactly epochStatement, issuerController, issuerDid, proof, publicSignals (got ${keys})`;
  const s = x.publicSignals as unknown;
  if (!Array.isArray(s) || s.length !== 8) return "expected 8 public signals";
  for (let i = 0; i < 8; i++) {
    const v = s[i];
    if (typeof v !== "string" || !DEC.test(v) || BigInt(v) >= BN254_P) return "public signals must be canonical decimals below p";
  }
  if (!isDidPq(x.issuerDid)) return "issuerDid malformed";
  if (typeof x.issuerController !== "string" || !ADDR.test(x.issuerController)) return "issuerController must be a lower-case 0x address";
  const st = x.epochStatement as unknown as Record<string, unknown> | undefined;
  if (!st || typeof st !== "object") return "epochStatement missing";
  if (Object.keys(st).sort().join(",") !== EPOCH_KEYS) return "epochStatement has the wrong fields";
  for (const k of ["epoch", "chainId", "notBefore", "notAfter", "fromDate", "toDate"]) {
    if (!Number.isSafeInteger(st[k])) return `epochStatement.${k} must be an integer`;
  }
  if (!isValidYmd(st["fromDate"]) || !isValidYmd(st["toDate"])) return "epochStatement dates malformed";
  for (const k of ["root", "revRoot"]) {
    const v = st[k];
    if (typeof v !== "string" || !DEC.test(v) || BigInt(v) >= BN254_P) return `epochStatement.${k} malformed`;
  }
  if (typeof st["signature"] !== "string" || !SIG_HEX.test(st["signature"] as string)) return "epochStatement.signature malformed";
  if (typeof st["registry"] !== "string" || !ADDR.test(st["registry"] as string)) return "epochStatement.registry malformed";
  if (typeof st["controller"] !== "string" || !ADDR.test(st["controller"] as string)) return "epochStatement.controller malformed";
  if (!isDidPq(st["issuer"])) return "epochStatement.issuer malformed";
  const pr = x.proof as unknown as Record<string, unknown> | undefined;
  if (!pr || typeof pr !== "object" || Array.isArray(pr)) return "proof missing";
  if (Object.keys(pr).sort().join(",") !== PROOF_KEYS) return "proof must have exactly pi_a, pi_b, pi_c, protocol, curve";
  if (pr["protocol"] !== "groth16" || pr["curve"] !== "bn128") return "proof must be groth16 on bn128";
  const decs = (a: unknown, n: number) => Array.isArray(a) && a.length === n && a.every((v) => typeof v === "string" && DEC.test(v) && BigInt(v) < BN254_P_BASE);
  if (!decs(pr["pi_a"], 3) || !decs(pr["pi_c"], 3)) return "proof pi_a / pi_c malformed";
  const b = pr["pi_b"];
  if (!Array.isArray(b) || b.length !== 3 || !b.every((row) => decs(row, 2))) return "proof pi_b malformed";
  return null;
}
