import { randomBytes } from "node:crypto";
import type { VerifiableCredential, IssuanceWitness, IssuanceRootAttestation } from "@pqid/issuer";
import { computeCredId } from "@pqid/issuer";
import { dilithiumKeygen, dilithiumVerify, type SigKeypair } from "@pqid/pqc";
import { didFromPublicKey } from "@pqid/common/did";
import { sha3_256 } from "@pqid/common/hash";
import {
  getPoseidon,
  issuerKeyHash,
  policyHash as computePolicyHash,
  holderCommit as computeHolderCommit,
  verifierDomainTag,
  stmtCodeForDomain,
  stmtCodeForDomainV3,
  PREDICATE_AGE_GTE,
  PREDICATE_AGE_LT,
  BN254_P,
} from "@pqid/common/encoding";
import type { NonMembershipProof } from "@pqid/revocation";
import {
  buildCircuitInput,
  buildCircuitInputV3,
  type CircuitInput,
  type PublicInputs,
  type PublicInputsV3,
} from "./witness.ts";
import {
  prove,
  proveBoth,
  V3_ARTIFACTS,
  type ProverBackend,
  type ProveResult,
} from "./prove.ts";

/**
 * Wallet / Prover (Algorithm 3): performs the OFF-CIRCUIT checks — issuer
 * Dilithium signature, holder binding, policy applicability — then builds the
 * witness (incl. the depth-32 non-membership opening) and runs Groth16.Prove.
 * The off-circuit checks are the load-bearing half of the two-phase
 * verification (Assumption 5); see harness/malicious_wallet_probe.ts for what
 * happens when a wallet skips them.
 */
export interface HolderWallet {
  did: string;
  keys: SigKeypair;
  holderSecret: bigint;
  holderCommit: bigint;
}

/** Supported policy predicates (V6: two working predicate types). */
export interface PolicyV1 {
  type: "age_gte" | "age_lt";
  attribute: "age";
  threshold: number;
}

export function predicateCodeFor(policy: PolicyV1): bigint {
  return policy.type === "age_gte" ? PREDICATE_AGE_GTE : PREDICATE_AGE_LT;
}

export interface ProofRequest {
  policy: PolicyV1;
  /** Verifier-chosen session nonce, sent in the request (freshness). */
  nonce: bigint;
  /** Requesting verifier's identifier — folded into stmtCode (V6 §F3). */
  verifierId: string;
}

export async function createWallet(): Promise<HolderWallet> {
  const poseidon = await getPoseidon();
  const keys = dilithiumKeygen();
  // 248-bit secret < BN254 p
  const holderSecret = BigInt("0x" + randomBytes(31).toString("hex")) % BN254_P;
  return {
    did: didFromPublicKey(keys.publicKey),
    keys,
    holderSecret,
    holderCommit: computeHolderCommit(poseidon, holderSecret),
  };
}

export interface OffCircuitCheckResult {
  credIdConsistent: boolean;
  dilithiumValid: boolean;
  holderBound: boolean;
  policyApplicable: boolean;
  ok: boolean;
}

/** The wallet's off-circuit checks. If any fails, NO proof is generated. */
export function walletCheckCredential(
  wallet: HolderWallet,
  vc: VerifiableCredential,
  pkIssuer: Buffer,
  policy: PolicyV1
): OffCircuitCheckResult {
  const recomputed = computeCredId(vc.credential, pkIssuer).toString("hex");
  const credIdConsistent = recomputed === vc.credID;
  const dilithiumValid =
    credIdConsistent &&
    dilithiumVerify(
      pkIssuer,
      Buffer.from(vc.credID, "hex"),
      Buffer.from(vc.signature, "hex")
    );
  const holderBound =
    vc.credential.holderCommit === wallet.holderCommit.toString() &&
    vc.credential.subject === wallet.did;
  const claimValue = vc.credential.claims[policy.attribute];
  const policyApplicable =
    typeof claimValue === "number" &&
    (policy.type === "age_gte"
      ? claimValue >= policy.threshold
      : claimValue < policy.threshold);
  const ok = credIdConsistent && dilithiumValid && holderBound && policyApplicable;
  return { credIdConsistent, dilithiumValid, holderBound, policyApplicable, ok };
}

export interface GenerateProofArgs {
  wallet: HolderWallet;
  vc: VerifiableCredential;
  request: ProofRequest;
  pkIssuer: Buffer;
  /** Current on-chain revocation root (resolved by the wallet). */
  revRoot: bigint;
  /** Non-membership opening obtained from the issuer's revocation service. */
  nonMembership: NonMembershipProof;
  /** If true, SKIP the off-circuit checks (malicious-wallet probe ONLY). */
  dangerouslySkipOffCircuitChecks?: boolean;
}

export async function buildProofInput(args: GenerateProofArgs): Promise<CircuitInput> {
  const poseidon = await getPoseidon();
  if (!args.dangerouslySkipOffCircuitChecks) {
    const check = walletCheckCredential(
      args.wallet,
      args.vc,
      args.pkIssuer,
      args.request.policy
    );
    if (!check.ok) {
      throw new Error(
        `off-circuit check failed: ${JSON.stringify(check)} — no proof generated`
      );
    }
  }
  const predicateCode = predicateCodeFor(args.request.policy);
  const domainTag = verifierDomainTag(poseidon, args.request.verifierId);
  const pub: PublicInputs = {
    issuerKeyHash: issuerKeyHash(poseidon, args.pkIssuer),
    revRoot: args.revRoot,
    policyHash: computePolicyHash(
      poseidon,
      predicateCode,
      BigInt(args.request.policy.threshold)
    ),
    nonce: args.request.nonce,
    stmtCode: stmtCodeForDomain(poseidon, domainTag),
  };
  return buildCircuitInput(pub, {
    credId: Buffer.from(args.vc.credID, "hex"),
    holderSecret: args.wallet.holderSecret,
    holderCommit: BigInt(args.vc.credential.holderCommit),
    claimAge: BigInt(args.vc.credential.claims["age"] as number),
    threshold: BigInt(args.request.policy.threshold),
    predicateCode,
    domainTag,
    nonMembership: args.nonMembership,
  });
}

/** Algorithm 3 end-to-end: checks → witness → Groth16.Prove. */
export async function generateProof(
  args: GenerateProofArgs,
  backend: ProverBackend = "snarkjs"
): Promise<ProveResult> {
  const input = await buildProofInput(args);
  return prove(input, backend);
}

// ============================================================================
// Circuit v3: prove membership of the credential leaf in the issuer-signed
// issuance tree (circuits/credential_auth_v3.circom)
// ============================================================================

/**
 * On-chain state the wallet reads itself right before presenting (see
 * readChainViewV3). It never takes these from the issuer's service: a value
 * only this holder receives would tag it.
 */
export interface ChainViewV3 {
  /** The issuer's current anchored epoch statement (IssuanceRootRegistry). */
  anchor: { root: bigint; revRoot: bigint; epoch: number; sigHash: string };
  /** The registry's minimum time between two epochs of one issuer (s). */
  minAnchorIntervalSec: number;
  /** The issuer DID's registry state. */
  issuer: { accredited: boolean; active: boolean; publicKeyDilithium: string };
}

/** The ledger calls readChainViewV3 needs (structurally matches @pqid/ledger's Ledger). */
export interface ChainReaderV3 {
  getIssuanceRoot(did: string): Promise<{ root: bigint; revRoot: bigint; epoch: number; sigHash: string }>;
  getMinAnchorInterval(): Promise<number>;
  isAccredited(did: string): Promise<boolean>;
  resolveDid(did: string): Promise<{ publicKeyDilithium: string; active: boolean }>;
}

export async function readChainViewV3(ledger: ChainReaderV3, issuerDid: string): Promise<ChainViewV3> {
  const [anchor, minAnchorIntervalSec, accredited, doc] = await Promise.all([
    ledger.getIssuanceRoot(issuerDid),
    ledger.getMinAnchorInterval(),
    ledger.isAccredited(issuerDid),
    ledger.resolveDid(issuerDid),
  ]);
  return {
    anchor: { root: anchor.root, revRoot: anchor.revRoot, epoch: anchor.epoch, sigHash: anchor.sigHash },
    minAnchorIntervalSec,
    issuer: { accredited, active: doc.active, publicKeyDilithium: doc.publicKeyDilithium },
  };
}

/**
 * The shortest registry interval between epochs an honest wallet accepts.
 * Below it, an issuer could give individual holders their own epoch (and so
 * their own public roots) often enough to tag them.
 */
export const WALLET_MIN_ANCHOR_INTERVAL_SEC = 3600;

export interface GenerateProofV3Args extends GenerateProofArgs {
  /** Leaf path + the issuer's signed epoch statement, from the issuer's services. */
  issuance: IssuanceWitness;
  /** What the chain says; the honest wallet checks the issuer's data against it. */
  chain: ChainViewV3;
  /** Holder policy; defaults to WALLET_MIN_ANCHOR_INTERVAL_SEC. */
  walletPolicy?: { minAnchorIntervalSec?: number };
}

const DECIMAL = /^(0|[1-9][0-9]*)$/;
const SIG_HEX = /^[0-9a-f]{4840}$/;

/**
 * The attestation exactly as every holder must present it: the five fields,
 * canonical encodings, a fresh object in a fixed key order. Throws on any
 * other shape, so an issuer cannot tag one holder through extra fields,
 * key order or alternative encodings.
 */
export function canonicalAttestation(att: unknown): IssuanceRootAttestation {
  const a = att as Record<string, unknown> | null;
  const keys = a && typeof a === "object" ? Object.keys(a).sort().join(",") : "";
  if (keys !== "epoch,issuerDid,revRoot,root,signature") {
    throw new Error("attestation must have exactly issuerDid, epoch, root, revRoot, signature");
  }
  const { issuerDid, epoch, root, revRoot, signature } = a as Record<string, unknown>;
  if (
    typeof issuerDid !== "string" ||
    typeof root !== "string" ||
    !DECIMAL.test(root) ||
    typeof revRoot !== "string" ||
    !DECIMAL.test(revRoot)
  ) {
    throw new Error("attestation issuerDid/root/revRoot malformed");
  }
  if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 1) throw new Error("attestation epoch malformed");
  if (typeof signature !== "string" || !SIG_HEX.test(signature)) throw new Error("attestation signature malformed");
  return { issuerDid, epoch, root, revRoot, signature };
}

/**
 * The honest wallet's privacy checks: the issuer is an accredited, active
 * issuer whose registered key is the credential's; the registry enforces the
 * holder's minimum epoch interval; and everything the issuer's services
 * handed over (attestation, path, revocation opening) is what every other
 * holder sees on chain right now. Otherwise the wallet refuses to present
 * (a colluding verifier would read a tag even if honest verifiers rejected
 * the presentation). Returns the canonical attestation to use.
 */
export function walletCheckIssuanceV3(args: GenerateProofV3Args): IssuanceRootAttestation {
  const att = canonicalAttestation(args.issuance.attestation);
  const { anchor, issuer } = args.chain;
  if (att.issuerDid !== args.vc.credential.issuer || didFromPublicKey(args.pkIssuer) !== att.issuerDid) {
    throw new Error("attestation issuer does not match the credential's issuer key");
  }
  if (!issuer.accredited || !issuer.active || issuer.publicKeyDilithium !== args.pkIssuer.toString("hex")) {
    throw new Error("issuer is not an accredited, active issuer with this key — refusing to present");
  }
  const floor = args.walletPolicy?.minAnchorIntervalSec ?? WALLET_MIN_ANCHOR_INTERVAL_SEC;
  if (args.chain.minAnchorIntervalSec < floor) {
    throw new Error(
      `anchor registry allows epochs every ${args.chain.minAnchorIntervalSec} s (< ${floor} s) — refusing to present`
    );
  }
  if (att.root !== anchor.root.toString() || att.revRoot !== anchor.revRoot.toString() || att.epoch !== anchor.epoch) {
    throw new Error("issuer served a root that is not its current on-chain anchor — refusing to present");
  }
  if (sha3_256(Buffer.from(att.signature, "hex")).toString("hex") !== anchor.sigHash) {
    throw new Error("issuer served signature bytes that differ from the anchored ones — refusing to present");
  }
  if (args.issuance.path.root !== att.root) {
    throw new Error("issuance path does not open to the attested root — no proof generated");
  }
  if (args.revRoot.toString() !== att.revRoot || args.nonMembership.root !== att.revRoot) {
    throw new Error("revocation opening is not against the anchored revRoot — refusing to present");
  }
  return att;
}

/**
 * Algorithm 3 for v3. The credential checks stay (they catch a bad credential
 * before any proving) but are no longer load-bearing for the verifier: a
 * wallet that skips them still has to open an issued leaf. The issuance
 * checks (walletCheckIssuanceV3) protect the holder's own privacy.
 */
export async function buildProofInputV3(args: GenerateProofV3Args): Promise<CircuitInput> {
  const poseidon = await getPoseidon();
  if (!args.dangerouslySkipOffCircuitChecks) {
    const check = walletCheckCredential(
      args.wallet,
      args.vc,
      args.pkIssuer,
      args.request.policy
    );
    if (!check.ok) {
      throw new Error(
        `off-circuit check failed: ${JSON.stringify(check)} — no proof generated`
      );
    }
  }
  // Use the checked, canonical copy from here on (the caller's object may change).
  const issRoot = args.dangerouslySkipOffCircuitChecks
    ? BigInt(args.issuance.attestation.root)
    : BigInt(walletCheckIssuanceV3(args).root);
  const predicateCode = predicateCodeFor(args.request.policy);
  const domainTag = verifierDomainTag(poseidon, args.request.verifierId);
  const pub: PublicInputsV3 = {
    issuerKeyHash: issuerKeyHash(poseidon, args.pkIssuer),
    revRoot: args.revRoot,
    policyHash: computePolicyHash(
      poseidon,
      predicateCode,
      BigInt(args.request.policy.threshold)
    ),
    nonce: args.request.nonce,
    stmtCode: stmtCodeForDomainV3(poseidon, domainTag),
    issRoot,
  };
  return buildCircuitInputV3(pub, {
    credId: Buffer.from(args.vc.credID, "hex"),
    holderSecret: args.wallet.holderSecret,
    claimAge: BigInt(args.vc.credential.claims["age"] as number),
    threshold: BigInt(args.request.policy.threshold),
    predicateCode,
    domainTag,
    issLeafIndex: args.issuance.path.leafIndex,
    issPathElements: args.issuance.path.pathElements,
    nonMembership: args.nonMembership,
  });
}

/** Algorithm 3 (v3) end-to-end: checks → witness → Groth16.Prove with the v3 key. */
export async function generateProofV3(
  args: GenerateProofV3Args,
  backend: ProverBackend = "snarkjs"
): Promise<ProveResult> {
  const input = await buildProofInputV3(args);
  return prove(input, backend, V3_ARTIFACTS);
}

/**
 * The presentation an honest wallet sends: a freshly built object with the
 * canonical attestation, never the object the issuer's service returned.
 */
export function presentationV3(
  result: ProveResult,
  issuerDid: string,
  attestation: IssuanceRootAttestation
): {
  proof: ProveResult["proof"];
  publicSignals: ProveResult["publicSignals"];
  issuerDid: string;
  issuanceRoot: IssuanceRootAttestation;
} {
  return {
    proof: result.proof,
    publicSignals: result.publicSignals,
    issuerDid,
    issuanceRoot: canonicalAttestation(attestation),
  };
}

export { prove, proveBoth, type ProverBackend, type ProveResult };
export { V2_ARTIFACTS, V3_ARTIFACTS, type CircuitArtifacts } from "./prove.ts";
export { buildCircuitInput, buildCircuitInputV3, type CircuitInput } from "./witness.ts";
