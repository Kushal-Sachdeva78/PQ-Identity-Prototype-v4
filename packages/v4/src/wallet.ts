import { randomBytes } from "node:crypto";
import { sha3_256 } from "@pqid/common/hash";
import { didFromPublicKey } from "@pqid/common/did";
import { getPoseidon, holderCommit as computeHolderCommit, BN254_P } from "@pqid/common/encoding";
import {
  issuerKeyHash,
  verifierDomainTag,
  credTypeField,
  policyHashV4,
  stmtCodeV4,
  isStandardThreshold,
  revKeyFromCredId,
} from "./encoding.ts";
import { acceptableTodays, isValidYmd, predicateHolds, utcDateOf } from "./dates.ts";
import { DEFAULT_TYPE_ID, KEM_ALG, MIN_ANCHOR_INTERVAL_SEC, TYPE_ACCREDITATION, TYPE_VERIFIER_KEM, WALLET_CLOCK_SKEW_SEC } from "./constants.ts";
import { mlDsaVerify } from "./pqc.ts";
import { epochMessage, tryParseStatement, type VerifierKemStatement, type AccreditationStatement } from "./statements.ts";
import { checkRecordAndPop, checkAccreditation } from "./governance.ts";
import { walletOpenSession, walletSealReply, requestShapeErrors, type ProofRequestV4, type SessionReplyV4 } from "./session.ts";
import { buildCircuitInputV4 } from "./witness.ts";
import { proveV4, type ProverBackendV4, type CircuitArtifactsV4 } from "./prove.ts";
import { IndexedMerkleTree } from "./imt.ts";
import { computeCredIdV4, type VerifiableCredentialV4, type EpochStatementV4, type IssuanceServiceReply } from "./issuer.ts";
import { presentationShapeError, EPOCH_KEYS, SIG_HEX, type PresentationV4 } from "./verifier.ts";
import type { LedgerV4 } from "./ledger.ts";
import type { Clock } from "./clock.ts";

/**
 * Honest v4 wallet (V4_DESIGN section 6.2). It is the defence for routes where the
 * verifier is the attacker (stale dates, threshold probing, relays with origin binding)
 * and for the holder's own privacy (served data must equal what every holder sees).
 *
 * `disabledChecks` exists ONLY for the mutation table; production code never sets it.
 */
export const WALLET_CHECKS = [
  "requestShape",
  "verifierRecord",
  "verifierPop",
  "verifierKemKey",
  "originBinding",
  "dateCurrent",
  "thresholdStandard",
  "typeAllowed",
  "typeHeld",
  "issuerRecord",
  "issuerPop",
  "accreditation",
  "anchorMatches",
  "epochWindow",
  "dateInWindow",
  "anchorCadence",
  "credentialSignature",
  "predicateHolds",
] as const;
export type WalletCheck = (typeof WALLET_CHECKS)[number];

/** "proofFailed": the wallet's own proof or presentation failed (bug or inconsistent served data). */
export type WalletRefusalReason = WalletCheck | "proofFailed";

export class WalletRefusal extends Error {
  constructor(
    readonly check: WalletRefusalReason,
    reason: string
  ) {
    super(`wallet refuses (${check}): ${reason}`);
  }
}

/** Where the wallet gets its issuance path and revocation opening. */
export interface IssuerDataSource {
  issuance(credIdHex: string): IssuanceServiceReply;
  revocation(credIdHex: string): { lowIndex: string; lowValue: string; lowNext: string; lowPath: string[]; root: string };
}

export interface HeldCredentialV4 {
  vc: VerifiableCredentialV4;
  issuerPk: Buffer;
  source: IssuerDataSource;
}

export interface WalletV4Config {
  ledger: LedgerV4;
  clock: Clock;
  pinnedGovernancePk: Buffer;
  /** Refuse when the registry lets issuers anchor more often than this (s). */
  minAnchorIntervalSec?: number;
  skewSec?: number;
  /** Modelled origin binding: refuse when the caller's origin is not the verifier's registered origin. */
  originBinding?: boolean;
  /**
   * Credential types this wallet will present (and accept at issuance). A request for any
   * other type is refused before the wallet looks at what it holds (B5 CIR-4, PRIV-6,
   * VER-7). Default: the standard age credential only.
   */
  allowedTypes?: readonly string[];
  prover?: ProverBackendV4;
  /** Circuit artifacts (default: the v4 dev key). Mutation runs pass a mutant's. */
  artifacts?: CircuitArtifactsV4;
  /** Mutation runs only: fills the free inputs a replacement mutant adds. */
  inputHook?: (input: Record<string, string | string[]>, info: { credId: Buffer; holderCommit: string; issuerDid: string }) => void;
  disabledChecks?: ReadonlySet<WalletCheck>;
}

export interface PresentContext {
  /** Authenticated origin of the caller (supplied by the platform in a browser). */
  callerOrigin?: string;
}

const ADDR = /^0x[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;

function deepFreezeCopy<T>(x: T): T {
  if (x && typeof x === "object") {
    for (const v of Object.values(x as Record<string, unknown>)) deepFreezeCopy(v);
    Object.freeze(x);
  }
  return x;
}

export class HolderWalletV4 {
  readonly holderSecret: bigint;
  holderCommit = 0n;
  readonly credentials: HeldCredentialV4[] = [];
  private readonly highestSerial = new Map<string, number>();
  /** Dates the wallet has committed to answering (B5 CIR-1): at most one date per 2 x skew window. */
  private readonly dateLog: Array<{ date: number; atSec: number }> = [];
  /** Newest KEM statement notBefore accepted per verifier record (B5 REG-5: no rollback). */
  private readonly kemNotBefore = new Map<string, number>();
  readonly disabled: ReadonlySet<WalletCheck>;
  /** Pseudonymous subject string for issuance (not used by the relation). */
  readonly subject = `did:pq:holder-${randomBytes(8).toString("hex")}`;

  constructor(readonly cfg: WalletV4Config) {
    this.holderSecret = BigInt("0x" + randomBytes(31).toString("hex")) % BN254_P;
    this.disabled = cfg.disabledChecks ?? new Set();
  }

  static async create(cfg: WalletV4Config): Promise<HolderWalletV4> {
    const w = new HolderWalletV4(cfg);
    w.holderCommit = computeHolderCommit(await getPoseidon(), w.holderSecret);
    return w;
  }

  get allowedTypes(): readonly string[] {
    return this.cfg.allowedTypes ?? [DEFAULT_TYPE_ID];
  }

  /** Store an issued credential; types outside the allow-list are refused (a covert type is a tag). */
  add(held: HeldCredentialV4): void {
    this.check("typeAllowed", this.allowedTypes.includes(held.vc.credential.typeId), `credential type ${held.vc.credential.typeId} is not on this wallet's allow-list`);
    this.credentials.push(held);
  }

  private check(c: WalletCheck, ok: boolean, reason: string): void {
    if (!ok && !this.disabled.has(c)) throw new WalletRefusal(c, reason);
  }

  /** Validate a request and resolve the verifier's registered ML-KEM key (never from the request). */
  async checkRequest(request: ProofRequestV4, ctx: PresentContext = {}): Promise<{ kemPk: Buffer }> {
    const { ledger, clock } = this.cfg;
    // A null or undefined request reads as {} here, so the policy read cannot throw; the
    // shape check below still runs on the original value and refuses it as requestShape
    // (fuzz finding fz1 T-wallet-req, d684e06eec1c).
    const r = (request ?? {}) as unknown as Record<string, unknown>;
    const pol = (r["policy"] ?? {}) as Record<string, unknown>;
    const shapeOk =
      requestShapeErrors(request).length === 0 &&
      r["type"] === "pqid:request:v4" &&
      typeof r["sessionId"] === "string" &&
      HEX64.test(r["sessionId"] as string) &&
      typeof r["verifierDid"] === "string" &&
      (r["verifierDid"] as string).startsWith("did:pq:") &&
      typeof r["verifierController"] === "string" &&
      ADDR.test(r["verifierController"] as string) &&
      r["chainId"] === (await ledger.chainId()) &&
      (pol["predicate"] === "age_gte" || pol["predicate"] === "age_lt") &&
      Number.isSafeInteger(pol["threshold"]) &&
      typeof pol["typeId"] === "string" &&
      isValidYmd(pol["today"]);
    this.check("requestShape", shapeOk, "malformed request");

    const vrec = await ledger.resolveDidRecord(request.verifierDid, request.verifierController);
    const vpk = vrec ? Buffer.from(vrec.pk) : null;
    this.check(
      "verifierRecord",
      !!vrec && vrec.active && !!vpk && didFromPublicKey(vpk) === request.verifierDid,
      "verifier DID record missing, inactive or not bound to its key"
    );
    const vpop = await checkRecordAndPop(ledger, request.verifierDid, request.verifierController);
    this.check("verifierPop", vpop.ok, vpop.reason ?? "verifier proof of possession invalid");

    const now = clock.nowSec();
    const kem = await ledger.latestKemKey(request.verifierDid, request.verifierController);
    let kemOk = false;
    const kemKey = `${request.verifierDid}|${request.verifierController}`;
    if (kem && vpk) {
      try {
        // Typed parse (canonical bytes, exact fields, capped window), then bind the statement
        // to this chain and registry and to the registry's stored notBefore, and never accept
        // an older statement than one already seen for this record (B5 REG-5, PRIV-8).
        const parsed = tryParseStatement(Buffer.from(kem.statement), TYPE_VERIFIER_KEM);
        const st = parsed.ok ? (parsed.value as VerifierKemStatement) : null;
        kemOk =
          !!st &&
          mlDsaVerify(vpk, Buffer.from(kem.statement), Buffer.from(kem.signature)) &&
          st.verifier === request.verifierDid &&
          st.controller === request.verifierController &&
          st.chainId === (await ledger.chainId()) &&
          st.registry === ledger.addresses.verifierKemRegistry.toLowerCase() &&
          kem.notBefore !== null &&
          st.notBefore === kem.notBefore &&
          st.notBefore >= (this.kemNotBefore.get(kemKey) ?? 0) &&
          st.kemAlg === KEM_ALG &&
          st.kemPkSha3 === sha3_256(Buffer.from(kem.kemPk)).toString("hex") &&
          now >= st.notBefore &&
          now <= st.notAfter;
        if (kemOk && st) this.kemNotBefore.set(kemKey, st.notBefore);
      } catch {
        kemOk = false;
      }
    }
    this.check("verifierKemKey", kemOk, "verifier ML-KEM key statement missing, unsigned, expired or for another verifier");

    if (this.cfg.originBinding) {
      this.check(
        "originBinding",
        typeof ctx.callerOrigin === "string" && !!vrec && ctx.callerOrigin === vrec.origin,
        `caller origin ${String(ctx.callerOrigin)} is not the verifier's registered origin`
      );
    }
    const skew = this.cfg.skewSec ?? WALLET_CLOCK_SKEW_SEC;
    const otherDateRecently = this.dateLog.some((e) => now - e.atSec <= 2 * skew && e.date !== request.policy.today);
    this.check(
      "dateCurrent",
      acceptableTodays(now, skew).includes(request.policy.today) && !otherDateRecently,
      otherDateRecently
        ? `the wallet answered another date within the last ${2 * skew} s`
        : `verifier date ${request.policy.today} is not the wallet's current UTC date ${utcDateOf(now)}`
    );
    // Reserve the date in the same synchronous step as the check (no await in between), so two
    // concurrent requests with different dates cannot both pass before either is recorded (C3
    // classification review: a race in the D-017 fix). An answer and a refusal are both
    // observable, so any request that passes the date check commits the wallet to that date.
    this.dateLog.push({ date: request.policy.today, atSec: now });
    while (this.dateLog.length > 64) this.dateLog.shift();
    this.check("thresholdStandard", isStandardThreshold(request.policy.threshold), `threshold ${request.policy.threshold} is not a standard threshold`);
    this.check("typeAllowed", this.allowedTypes.includes(request.policy.typeId), "credential type not available");
    if (!kem) throw new WalletRefusal("verifierKemKey", "no verifier KEM key");
    return { kemPk: Buffer.from(kem.kemPk) };
  }

  /** Check what the issuer's services handed over against the chain; returns the statement. */
  async checkIssuerData(held: HeldCredentialV4): Promise<{ statement: EpochStatementV4; path: IssuanceServiceReply["path"]; rev: ReturnType<IssuerDataSource["revocation"]>; controller: string }> {
    const { ledger, clock, pinnedGovernancePk } = this.cfg;
    const cred = held.vc.credential;
    const did = cred.issuer;
    // The issuer's current controller is the one its latest accreditation names (B5 REG-1:
    // after a controller rotation, credentials naming the old controller keep working).
    // The credential's own controller is only a fallback; every check below still runs
    // against whichever controller is used, so the accreditation must name it exactly.
    const controller = (await this.accreditedController(did)) ?? cred.issuerController;
    const now = clock.nowSec();
    const rec = await ledger.resolveDidRecord(did, controller);
    this.check(
      "issuerRecord",
      !!rec && rec.active && Buffer.from(rec.pk).equals(held.issuerPk) && didFromPublicKey(held.issuerPk) === did,
      "issuer record missing, inactive or holding a different key"
    );
    const pop = await checkRecordAndPop(ledger, did, controller);
    this.check("issuerPop", pop.ok, pop.reason ?? "issuer proof of possession invalid");
    const acc = await checkAccreditation(ledger, pinnedGovernancePk, did, controller, held.issuerPk, now, this.highestSerial);
    this.check("accreditation", acc.ok, acc.reason ?? "issuer not accredited");

    // Data-source failures (leaf not yet in the anchored epoch, credential revoked) become one
    // generic refusal: the source's own error text can name the holder's leaf index (review
    // round 2, P1 / VRA-1).
    const unavailable = () => new WalletRefusal("anchorMatches", "the anchored epoch has no usable data for this credential");
    let served: IssuanceServiceReply;
    try {
      served = held.source.issuance(held.vc.credID);
    } catch {
      throw unavailable();
    }
    const raw = served.statement as unknown as Record<string, unknown>;
    // Strict form before anything is decoded: exact keys, lower-case 4,840-hex signature,
    // dates equal to the window's dates. A lenient decoder would let an issuer plant a
    // per-holder tag that reaches the verifier (B5 PRIV-1, PRIV-2, PRIV-4).
    const strictForm =
      !!raw &&
      typeof raw === "object" &&
      Object.keys(raw).sort().join(",") === EPOCH_KEYS &&
      typeof raw["signature"] === "string" &&
      SIG_HEX.test(raw["signature"]) &&
      Number.isSafeInteger(raw["notBefore"]) &&
      Number.isSafeInteger(raw["notAfter"]) &&
      raw["fromDate"] === utcDateOf(raw["notBefore"] as number) &&
      raw["toDate"] === utcDateOf(raw["notAfter"] as number);
    this.check("anchorMatches", strictForm, "served epoch statement is not in canonical form");
    // Forward only a statement rebuilt from the validated fields, never the served object.
    const st: EpochStatementV4 = {
      issuer: raw["issuer"] as string,
      controller: raw["controller"] as string,
      chainId: raw["chainId"] as number,
      registry: raw["registry"] as string,
      epoch: raw["epoch"] as number,
      root: raw["root"] as string,
      revRoot: raw["revRoot"] as string,
      notBefore: raw["notBefore"] as number,
      notAfter: raw["notAfter"] as number,
      fromDate: raw["fromDate"] as number,
      toDate: raw["toDate"] as number,
      signature: String(raw["signature"]),
    };
    const anchor = await ledger.currentEpoch(did, controller);
    const { signature, ...fields } = st;
    let sigOk = false;
    try {
      sigOk = mlDsaVerify(held.issuerPk, epochMessage(fields), Buffer.from(signature, "hex"));
    } catch {
      sigOk = false;
    }
    const matches =
      !!anchor &&
      sigOk &&
      Number(anchor.epoch) === st.epoch &&
      BigInt(anchor.root).toString() === st.root &&
      BigInt(anchor.revRoot).toString() === st.revRoot &&
      Number(anchor.notBefore) === st.notBefore &&
      Number(anchor.notAfter) === st.notAfter &&
      String(anchor.sigHash).replace(/^0x/, "").toLowerCase() === sha3_256(Buffer.from(signature, "hex")).toString("hex") &&
      st.issuer === did &&
      st.controller === controller &&
      st.chainId === (await ledger.chainId()) &&
      st.registry === ledger.addresses.issuanceRootRegistry.toLowerCase() &&
      served.path.root === st.root;
    this.check("anchorMatches", matches, "issuer served a statement or path that is not its current signed on-chain anchor");
    this.check("epochWindow", now >= st.notBefore && now <= st.notAfter, "the anchored epoch statement is outside its validity window");
    const minInterval = await ledger.getMinAnchorInterval();
    this.check(
      "anchorCadence",
      Number(minInterval) >= (this.cfg.minAnchorIntervalSec ?? MIN_ANCHOR_INTERVAL_SEC),
      `registry allows epochs every ${minInterval} s, below the wallet floor`
    );
    let rev: ReturnType<IssuerDataSource["revocation"]>;
    try {
      rev = held.source.revocation(held.vc.credID);
    } catch {
      throw unavailable();
    }
    this.check("anchorMatches", rev.root === st.revRoot, "revocation opening is not against the anchored revRoot");
    return { statement: st, path: served.path, rev, controller };
  }

  /** Controller named by the issuer DID's latest accreditation statement, if it parses. */
  private async accreditedController(did: string): Promise<string | null> {
    const latest = await this.cfg.ledger.latestAccreditation(did);
    if (!latest) return null;
    const parsed = tryParseStatement(Buffer.from(latest.statement), TYPE_ACCREDITATION);
    return parsed.ok ? (parsed.value as AccreditationStatement).controller : null;
  }

  /** The full presentation: request checks, issuer-data checks, KEM session, proof, sealed reply. */
  async present(callerRequest: ProofRequestV4, ctx: PresentContext = {}): Promise<{ reply: SessionReplyV4; presentation: PresentationV4 }> {
    // One frozen plain-data copy of the caller's request before any check (review round 2,
    // DATE-1): every later step reads this copy, so a getter, a Proxy or a mutation made while
    // the wallet awaits cannot change the date, threshold or policy after it was checked.
    let request: ProofRequestV4;
    try {
      request = deepFreezeCopy(structuredClone(callerRequest));
    } catch {
      throw new WalletRefusal("requestShape", "request must be plain data");
    }
    const { kemPk } = await this.checkRequest(request, ctx);
    const poseidon = await getPoseidon();
    const wantType = credTypeField(poseidon, request.policy.typeId);
    // Of several credentials of the type, use the one that expires last (a renewal), so an
    // expired or superseded first credential does not block a valid one (review round 2, L5).
    const held = this.credentials
      .filter((c) => credTypeField(poseidon, c.vc.credential.typeId) === wantType)
      .sort((a, b) => b.vc.credential.expiryDate - a.vc.credential.expiryDate)[0];
    this.check("typeHeld", !!held, `no credential of type ${request.policy.typeId}`);
    const h = held ?? this.credentials[0];
    if (!h) throw new WalletRefusal("typeHeld", "wallet holds no credential");

    // The credential itself (v3's credential checks; not load-bearing for the verifier).
    const cred = h.vc.credential;
    const credId = computeCredIdV4(cred, h.issuerPk);
    const sigOk =
      credId.toString("hex") === h.vc.credID &&
      mlDsaVerify(h.issuerPk, credId, Buffer.from(h.vc.signature, "hex")) &&
      cred.holderCommit === this.holderCommit.toString();
    this.check("credentialSignature", sigOk, "credential signature or holder binding invalid");

    const { statement, path, rev, controller: issuerController } = await this.checkIssuerData(h);
    this.check(
      "dateInWindow",
      statement.fromDate <= request.policy.today && request.policy.today <= statement.toDate,
      `date ${request.policy.today} is outside the anchored statement's dates ${statement.fromDate}..${statement.toDate}`
    );
    const pred = request.policy.predicate === "age_gte" ? 1 : 2;
    this.check(
      "predicateHolds",
      predicateHolds(pred, cred.birthDate, request.policy.threshold, request.policy.today) && request.policy.today <= cred.expiryDate,
      "the credential does not satisfy the request (the verifier learns this from the refusal)"
    );

    const session = walletOpenSession(request, kemPk);
    const input = await buildPresentationInput({
      request,
      nonce: session.nonce,
      issuerPk: h.issuerPk,
      credId,
      holderSecret: this.holderSecret,
      credential: cred,
      statement,
      path,
      rev,
    });
    this.cfg.inputHook?.(input, { credId, holderCommit: cred.holderCommit, issuerDid: cred.issuer });
    let proved: Awaited<ReturnType<typeof proveV4>>;
    try {
      proved = await proveV4(input, this.cfg.prover ?? "snarkjs", this.cfg.artifacts);
    } catch (e) {
      throw new WalletRefusal("proofFailed", `witness or proof generation failed: ${(e as Error).message.split("\n")[0]}`);
    }
    const presentation: PresentationV4 = {
      proof: proved.proof,
      publicSignals: proved.publicSignals,
      issuerDid: cred.issuer,
      issuerController,
      epochStatement: { ...statement },
    };
    // The verifier's own shape rules, applied before anything leaves the wallet (B5 PRIV-1).
    const shapeErr = presentationShapeError(structuredClone(presentation));
    if (shapeErr) throw new WalletRefusal("proofFailed", `own presentation fails the verifier's shape rules: ${shapeErr}`);
    const reply = walletSealReply(session, presentation);
    return { reply, presentation };
  }
}

/**
 * The circuit input for a presentation (no checks). The honest wallet calls it after
 * its checks; attack harnesses call it directly, as a malicious wallet would.
 */
export async function buildPresentationInput(a: {
  request: ProofRequestV4;
  nonce: bigint;
  issuerPk: Buffer;
  credId: Buffer;
  holderSecret: bigint;
  credential: VerifiableCredentialV4["credential"];
  statement: EpochStatementV4;
  path: IssuanceServiceReply["path"];
  rev: ReturnType<IssuerDataSource["revocation"]>;
  /** Overrides for attack routes (e.g. a different today or requiredType inside the proof). */
  override?: Partial<{ today: number; requiredType: bigint; threshold: number; predicate: "age_gte" | "age_lt"; issuerKeyHash: bigint }>;
}) {
  const poseidon = await getPoseidon();
  const o = a.override ?? {};
  const wantType = o.requiredType ?? credTypeField(poseidon, a.request.policy.typeId);
  const today = o.today ?? a.request.policy.today;
  const threshold = o.threshold ?? a.request.policy.threshold;
  const predicate = o.predicate ?? a.request.policy.predicate;
  const domainTag = verifierDomainTag(poseidon, a.request.verifierDid);
  return buildCircuitInputV4(
    {
      issuerKeyHash: o.issuerKeyHash ?? issuerKeyHash(poseidon, a.issuerPk),
      revRoot: BigInt(a.statement.revRoot),
      policyHash: policyHashV4(poseidon, { predicate, threshold, today, requiredType: wantType }),
      nonce: a.nonce,
      stmtCode: stmtCodeV4(poseidon, domainTag),
      issRoot: BigInt(a.statement.root),
      epochFromDate: a.statement.fromDate,
      epochToDate: a.statement.toDate,
    },
    {
      credId: a.credId,
      holderSecret: a.holderSecret,
      birthDate: a.credential.birthDate,
      expiryDate: a.credential.expiryDate,
      credType: credTypeField(poseidon, a.credential.typeId),
      predicate,
      threshold,
      today,
      requiredType: wantType,
      domainTag,
      issLeafIndex: a.path.leafIndex,
      issPathElements: a.path.pathElements,
      rev: a.rev,
    }
  );
}

/** Issuer data from the issuer's online services (the v3 model: reveals timing to the issuer). */
export function onlineSource(svc: { issuance(credIdHex: string): IssuanceServiceReply; revocation(credIdHex: string): ReturnType<IssuerDataSource["revocation"]> }): IssuerDataSource {
  return svc;
}

/** Revocation key of a credential (for harnesses). */
export function revKeyOf(vc: VerifiableCredentialV4): bigint {
  return revKeyFromCredId(Buffer.from(vc.credID, "hex"));
}

export { IndexedMerkleTree };
