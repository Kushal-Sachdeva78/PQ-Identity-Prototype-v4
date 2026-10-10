import fs from "node:fs";
import { randomBytes } from "node:crypto";
import type { Groth16Proof, PublicSignals } from "snarkjs";
import { VKEY_FILE, VKEY_FILE_V3 } from "@pqid/common/paths";
import { sha3_256 } from "@pqid/common/hash";
import { didFromPublicKey } from "@pqid/common/did";
import {
  getPoseidon,
  issuerKeyHash,
  policyHash as computePolicyHash,
  verifierDomainTag,
  stmtCodeForDomain,
  stmtCodeForDomainV3,
  issuanceRootMessage,
  BN254_P,
  PREDICATE_AGE_GTE,
  PREDICATE_AGE_LT,
} from "@pqid/common/encoding";
import type { Ledger } from "@pqid/ledger";
import type { IssuanceRootAttestation } from "@pqid/issuer";
import { dilithiumVerify, ML_DSA_44_SIZES } from "@pqid/pqc";

/**
 * Verifier service (paper §III-B.4a, "off-circuit checks performed by the
 * verifier"): (i) Groth16.verify against the pinned vkey; (ii) on-chain
 * resolution of pk_issuer with equality against public signal 0;
 * (iii) on-chain resolution of revRoot with equality against signal 1;
 * (iv) session-nonce freshness (single-use, TTL).
 * Plus: policy-hash equality (signal 2) and statement-code check (signal 4).
 *
 * Circuit v3 adds (v), the ISSUANCE ROOT checks:
 *   - issuanceRootCurrent: public signals 5 (issRoot) and 1 (revRoot) are the
 *     issuer's CURRENT epoch statement anchored on chain, and the
 *     presentation's attestation (exactly issuerDid, epoch, root, revRoot,
 *     signature) carries that epoch and exactly the signature bytes whose hash
 *     is anchored. v3 reads revRoot from this anchor, not RevocationRegistry.
 *     Together with the honest wallet's own checks (walletCheckIssuanceV3)
 *     this gives every holder the same view during an epoch;
 *   - issuanceRootSigned: ML-DSA-44.Verify(pk_issuer, issuanceRootMessage(
 *     issuerDid, epoch, issRoot, revRoot), sigma) with pk_issuer from the DID
 *     Registry. This is what ties the proven credential to something the
 *     issuer actually signed; under v2 the only Dilithium check was the
 *     wallet's own (Assumption 5). It runs last, only for the one copy of a
 *     presentation that passed every other check and spent the nonce, on every
 *     such presentation (no cache), so junk or replayed requests cannot
 *     trigger it and its timing reveals nothing about other holders.
 *
 * Hardening from the v3 reviews (applies to both versions): the presentation
 * is copied once as plain data before any check; public signals must be
 * canonical decimal strings below the field modulus (so every check reads the
 * same numbers snarkjs verifies); the registered ML-DSA key must hash to the
 * did:pq identifier (a DID squatted with the squatter's OWN key is useless;
 * squatting with the issuer's genuine key is a registry-layer issue, see
 * docs/CIRCUIT_V3.md); and the session nonce is spent only by an accepted
 * presentation.
 */
export type CircuitVersion = "v2" | "v3";

export interface Presentation {
  proof: Groth16Proof;
  /** v2: [issuerKeyHash, revRoot, policyHash, nonce, stmtCode]; v3 appends issRoot. */
  publicSignals: PublicSignals;
  issuerDid: string; // which issuer the credential claims (public context)
  /** v3 only: the issuer-signed issuance-tree root the proof opens against. */
  issuanceRoot?: IssuanceRootAttestation;
}

export interface VerifyDecision {
  accepted: boolean;
  reasons: string[];
  checks: {
    proofValid: boolean;
    issuerResolvedAndAccredited: boolean;
    issuerKeyHashMatches: boolean;
    revRootMatches: boolean;
    policyHashMatches: boolean;
    nonceFresh: boolean;
    stmtCodeValid: boolean;
    /** v3 only: issRoot, epoch and signature hash equal the issuer's current on-chain anchor. */
    issuanceRootCurrent?: boolean;
    /** v3 only: the ML-DSA-44 signature over the root verifies under pk_issuer. */
    issuanceRootSigned?: boolean;
  };
  /** Checks reported false only because an earlier check made them moot. */
  notEvaluated: string[];
}

export interface VerifierPolicy {
  type: "age_gte" | "age_lt";
  threshold: number;
}

const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;
const SIGNATURE_HEX = new RegExp(`^[0-9a-f]{${ML_DSA_44_SIZES.signature * 2}}$`);

/** Single-use session nonces with a TTL (replay protection). */
export class NonceRegistry {
  private readonly issued = new Map<string, number>(); // nonce -> expiry epoch ms
  constructor(private readonly ttlMs = 5 * 60_000) {}

  issue(): bigint {
    const now = Date.now();
    // Insertion order == expiry order (constant TTL): drop expired ones from the front only.
    for (const [n, expiry] of this.issued) {
      if (expiry >= now) break;
      this.issued.delete(n);
    }
    const nonce = BigInt("0x" + randomBytes(16).toString("hex"));
    this.issued.set(nonce.toString(), now + this.ttlMs);
    return nonce;
  }

  /** True iff the nonce was issued, is unused and has not expired (read-only). */
  peek(nonce: string): boolean {
    const expiry = this.issued.get(nonce);
    return expiry !== undefined && Date.now() <= expiry;
  }

  /** Consume a nonce: valid exactly once, before expiry. */
  consume(nonce: string): boolean {
    const expiry = this.issued.get(nonce);
    if (expiry === undefined) return false;
    this.issued.delete(nonce);
    return Date.now() <= expiry;
  }
}

export class Verifier {
  private readonly nonces: NonceRegistry;
  private readonly vkey: unknown;
  /** This verifier's identifier — folded into stmtCode by honest wallets (V6 §F3). */
  readonly verifierId: string;
  /**
   * Which circuit's proofs this verifier accepts. The default stays v2 so the
   * published results reproduce, but v2 is not sound (review 9.1-9.3: its key
   * has a public trapdoor); use v3 for any real decision.
   */
  readonly circuit: CircuitVersion;

  constructor(
    private readonly ledger: Ledger,
    opts: {
      nonceTtlMs?: number;
      vkeyFile?: string;
      verifierId?: string;
      circuit?: CircuitVersion;
    } = {}
  ) {
    const circuit: unknown = opts.circuit ?? "v2";
    if (circuit !== "v2" && circuit !== "v3") {
      throw new Error(`unknown circuit version: ${String(circuit)} (expected "v2" or "v3")`);
    }
    this.circuit = circuit;
    this.nonces = new NonceRegistry(opts.nonceTtlMs);
    const defaultVkey = this.circuit === "v3" ? VKEY_FILE_V3 : VKEY_FILE;
    this.vkey = JSON.parse(fs.readFileSync(opts.vkeyFile ?? defaultVkey, "utf8"));
    const nPublic = (this.vkey as { nPublic?: number }).nPublic;
    if (nPublic !== (this.circuit === "v3" ? 6 : 5)) {
      throw new Error(`verification key has nPublic=${nPublic}, which does not match circuit ${this.circuit}`);
    }
    this.verifierId = opts.verifierId ?? "pqid:verifier:demo";
  }

  /** Step 1 of a session: the verifier issues a fresh nonce (sent in the request). */
  newSessionNonce(): bigint {
    return this.nonces.issue();
  }

  async verifyPresentation(
    input: Presentation,
    expectedPolicy: VerifierPolicy
  ): Promise<VerifyDecision> {
    const reasons: string[] = [];
    const notEvaluated: string[] = [];
    // One plain-data snapshot before any check or await: every check and
    // snarkjs then read the same values (no getters, proxies or later edits).
    let presentation: Presentation;
    try {
      presentation = structuredClone({
        proof: input?.proof,
        publicSignals: input?.publicSignals,
        issuerDid: input?.issuerDid,
        issuanceRoot: input?.issuanceRoot,
      }) as Presentation;
    } catch {
      return {
        accepted: false,
        reasons: ["presentation must be plain data"],
        checks: {
          proofValid: false,
          issuerResolvedAndAccredited: false,
          issuerKeyHashMatches: false,
          revRootMatches: false,
          policyHashMatches: false,
          nonceFresh: false,
          stmtCodeValid: false,
        },
        notEvaluated: [],
      };
    }
    const signals = presentation.publicSignals as unknown;
    const v3 = this.circuit === "v3";
    const checks: VerifyDecision["checks"] = {
      proofValid: false,
      issuerResolvedAndAccredited: false,
      issuerKeyHashMatches: false,
      revRootMatches: false,
      policyHashMatches: false,
      nonceFresh: false,
      stmtCodeValid: false,
      ...(v3 ? { issuanceRootCurrent: false, issuanceRootSigned: false } : {}),
    };

    // Shape first, before anything is spent: exactly N canonical field elements
    // (an index loop, so a sparse array's holes are caught too) and a known policy.
    const expectedSignals = v3 ? 6 : 5;
    const canonical = (s: unknown) => typeof s === "string" && CANONICAL_DECIMAL.test(s) && BigInt(s) < BN254_P;
    let shapeError: string | null = null;
    if (!Array.isArray(signals) || signals.length !== expectedSignals) {
      shapeError = `expected ${expectedSignals} public signals, got ${Array.isArray(signals) ? signals.length : typeof signals}`;
    } else if (Array.from({ length: expectedSignals }, (_, i) => signals[i]).some((s) => !canonical(s))) {
      shapeError = "public signals must be canonical decimal strings below the BN254 scalar modulus";
    } else if (typeof presentation.issuerDid !== "string") {
      shapeError = "issuerDid must be a string";
    } else if (
      (expectedPolicy?.type !== "age_gte" && expectedPolicy?.type !== "age_lt") ||
      !Number.isSafeInteger(expectedPolicy.threshold) ||
      expectedPolicy.threshold < 0
    ) {
      shapeError = "unknown verifier policy";
    }
    if (shapeError) {
      return { accepted: false, reasons: [shapeError], checks, notEvaluated: Object.keys(checks) };
    }
    const sig = signals as string[];
    const [sigIssuerKeyHash, sigRevRoot, sigPolicyHash, sigNonce, sigStmtCode] =
      sig as [string, string, string, string, string];

    const poseidon = await getPoseidon();
    let pkIssuer: Buffer | null = null;

    // (ii) resolve pk_issuer on-chain; the key must be the one the did:pq
    // identifier commits to; equality against signal 0
    try {
      const doc = await this.ledger.resolveDid(presentation.issuerDid);
      const accredited = await this.ledger.isAccredited(presentation.issuerDid);
      const pk = Buffer.from(doc.publicKeyDilithium, "hex");
      const keyBound = didFromPublicKey(pk) === presentation.issuerDid;
      checks.issuerResolvedAndAccredited = doc.active && accredited && keyBound;
      if (!doc.active) reasons.push("issuer DID is deactivated");
      if (!accredited) reasons.push("issuer is not accredited in the Issuer Registry");
      if (!keyBound) reasons.push("registered key does not match the did:pq identifier");
      if (keyBound) pkIssuer = pk;
      const expectedKeyHash = issuerKeyHash(poseidon, pk).toString();
      checks.issuerKeyHashMatches = keyBound && expectedKeyHash === sigIssuerKeyHash;
      if (expectedKeyHash !== sigIssuerKeyHash) {
        reasons.push("Poseidon(pk_issuer) does not match public signal 0");
      }
    } catch (e) {
      reasons.push(`issuer DID resolution failed: ${(e as Error).message}`);
    }

    // (iii) resolve the current revocation root on-chain; equality against
    // signal 1. v3 takes it from the issuer's anchored, ML-DSA-signed epoch
    // statement (so it follows the epoch cadence and cannot be rolled back);
    // v2 from the RevocationRegistry.
    try {
      const chainRoot = v3
        ? (await this.ledger.getIssuanceRoot(presentation.issuerDid)).revRoot
        : await this.ledger.getRevRoot(presentation.issuerDid);
      checks.revRootMatches = chainRoot.toString() === sigRevRoot;
      if (!checks.revRootMatches) {
        reasons.push(
          `revocation root mismatch: proof used ${sigRevRoot}, chain has ${chainRoot}`
        );
      }
    } catch (e) {
      reasons.push(`revRoot resolution failed: ${(e as Error).message}`);
    }

    // policy commitment equality (signal 2)
    const predicateCode =
      expectedPolicy.type === "age_gte" ? PREDICATE_AGE_GTE : PREDICATE_AGE_LT;
    const expectedPolicyHash = computePolicyHash(
      poseidon,
      predicateCode,
      BigInt(expectedPolicy.threshold)
    ).toString();
    checks.policyHashMatches = expectedPolicyHash === sigPolicyHash;
    if (!checks.policyHashMatches) reasons.push("policy hash does not match the requested policy");

    // (iv) nonce freshness — read-only here; spent below, right before the last check
    checks.nonceFresh = this.nonces.peek(sigNonce);
    if (!checks.nonceFresh) reasons.push("nonce is stale, unknown, or already used");

    // statement code must bind THIS verifier's domain (V6 §F3): a proof made
    // for another verifier carries a different stmtCode and is rejected here.
    const domain = verifierDomainTag(poseidon, this.verifierId);
    const expectedStmtCode = (
      v3 ? stmtCodeForDomainV3(poseidon, domain) : stmtCodeForDomain(poseidon, domain)
    ).toString();
    checks.stmtCodeValid = sigStmtCode === expectedStmtCode;
    if (!checks.stmtCodeValid) {
      reasons.push("stmtCode does not bind this verifier's domain (cross-verifier replay?)");
    }

    // (v-a) v3: the proof's issuance root is the issuer's current anchored root
    if (v3) {
      checks.issuanceRootCurrent = await this.checkIssuanceAnchor(presentation, sig[5] as string, sigRevRoot, reasons);
    }

    // (i) Groth16 proof verification
    try {
      const snarkjs = await import("snarkjs");
      checks.proofValid = await snarkjs.groth16.verify(this.vkey, sig, presentation.proof);
    } catch (e) {
      checks.proofValid = false;
      reasons.push(`malformed proof: ${(e as Error).message}`);
    }
    if (!checks.proofValid) reasons.push("Groth16 proof verification failed");

    // Spend the nonce only if every other check (except v3's ML-DSA) passed.
    // Everything from here to the return is synchronous, so of several racing
    // copies of one presentation exactly one spends the nonce, and only that
    // one reaches ML-DSA. A presentation that then fails ML-DSA has spent its
    // nonce, so it cannot be replayed to make the verifier run ML-DSA again.
    const othersPass = Object.entries(checks).every(
      ([k, v]) => k === "nonceFresh" || k === "issuanceRootSigned" || v === true
    );
    if (othersPass && checks.nonceFresh) {
      checks.nonceFresh = this.nonces.consume(sigNonce);
      if (!checks.nonceFresh) reasons.push("nonce was used concurrently");
    }

    // (v-b) v3: ML-DSA over the epoch statement, only for the copy that spent the nonce
    if (v3) {
      if (othersPass && checks.nonceFresh && pkIssuer) {
        checks.issuanceRootSigned = this.verifyRootSignature(presentation, sig[1] as string, sig[5] as string, pkIssuer, reasons);
      } else {
        notEvaluated.push("issuanceRootSigned");
      }
    }
    const accepted = Object.values(checks).every(Boolean);
    return { accepted, reasons, checks, notEvaluated };
  }

  /**
   * (v-a) The attestation has exactly the five expected fields, and issRoot,
   * revRoot, the epoch and the SHA3-256 of the signature bytes equal the
   * issuer's current on-chain anchor.
   */
  private async checkIssuanceAnchor(
    presentation: Presentation,
    sigIssRoot: string,
    sigRevRoot: string,
    reasons: string[]
  ): Promise<boolean> {
    const att = presentation.issuanceRoot as unknown as Record<string, unknown> | undefined;
    if (!att || typeof att !== "object") {
      reasons.push("v3 presentation carries no issuance-root attestation");
      return false;
    }
    if (Object.keys(att).sort().join(",") !== "epoch,issuerDid,revRoot,root,signature") {
      reasons.push("issuance-root attestation must have exactly issuerDid, epoch, root, revRoot, signature");
      return false;
    }
    if (att["issuerDid"] !== presentation.issuerDid) {
      reasons.push("issuance-root attestation names a different issuer");
      return false;
    }
    if (att["root"] !== sigIssRoot) {
      reasons.push("issRoot (public signal 5) is not the attested issuance root");
      return false;
    }
    if (att["revRoot"] !== sigRevRoot) {
      reasons.push("revRoot (public signal 1) is not the attested revocation root");
      return false;
    }
    const signature = att["signature"];
    const epoch = att["epoch"];
    if (typeof signature !== "string" || !SIGNATURE_HEX.test(signature)) {
      reasons.push("malformed issuance-root signature (expected 2,420 bytes, lower-case hex)");
      return false;
    }
    if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 1) {
      reasons.push("malformed issuance-root epoch");
      return false;
    }
    const sigHash = sha3_256(Buffer.from(signature, "hex")).toString("hex");
    try {
      const anchor = await this.ledger.getIssuanceRoot(presentation.issuerDid);
      if (anchor.epoch === 0) {
        reasons.push("issuer has no issuance root anchored on chain");
        return false;
      }
      if (anchor.root.toString() !== sigIssRoot || anchor.revRoot.toString() !== sigRevRoot || anchor.epoch !== epoch) {
        reasons.push(
          `issRoot is not the issuer's current anchored root (proof: epoch ${epoch}; chain: epoch ${anchor.epoch})`
        );
        return false;
      }
      if (anchor.sigHash !== sigHash) {
        reasons.push("attestation signature bytes differ from the ones anchored on chain");
        return false;
      }
      return true;
    } catch (e) {
      reasons.push(`issuance-root resolution failed: ${(e as Error).message}`);
      return false;
    }
  }

  /** (v-b) ML-DSA-44 over the anchored epoch statement, under the DID-bound issuer key. */
  private verifyRootSignature(
    presentation: Presentation,
    sigRevRoot: string,
    sigIssRoot: string,
    pkIssuer: Buffer,
    reasons: string[]
  ): boolean {
    const att = presentation.issuanceRoot as IssuanceRootAttestation;
    let valid = false;
    try {
      valid = dilithiumVerify(
        pkIssuer,
        issuanceRootMessage(att.issuerDid, att.epoch, BigInt(sigIssRoot), BigInt(sigRevRoot)),
        Buffer.from(att.signature, "hex")
      );
    } catch {
      valid = false; // liboqs rejects malformed encodings by raising
    }
    if (!valid) reasons.push("issuance-root ML-DSA-44 signature does not verify under pk_issuer");
    return valid;
  }
}
