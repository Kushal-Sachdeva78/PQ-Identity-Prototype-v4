import { randomBytes } from "node:crypto";
import { canonicalJsonBytes, sha3_256 } from "@pqid/common/hash";
import { didFromPublicKey } from "@pqid/common/did";
import {
  getPoseidon,
  credentialLeaf,
  issuerKeyHash,
  issuanceRootMessage,
} from "@pqid/common/encoding";
import {
  dilithiumKeygen,
  dilithiumSign,
  dilithiumKeygenDpy,
  dilithiumSignDpy,
  type SigKeypair,
} from "@pqid/pqc";
import { IssuanceTree, type IssuancePath } from "./issuance.ts";

export { IssuanceTree, type IssuancePath } from "./issuance.ts";

/**
 * Issuer service (Algorithm 2 of the paper):
 *   cred   = {subject, claims, issuer, issuedAt, holderCommit}
 *   credID = SHA3-256( canonicalJson(cred) ‖ pk_issuer )       (32 bytes)
 *   σ      = Dilithium.Sign(I.sk, credID)                       (ML-DSA-44)
 *   VC     = {credential, credID, signature}
 *
 * holderCommit = Poseidon(holderSecret) is supplied by the holder's wallet at
 * issuance time and carried inside the signed credential (holder binding).
 */
export interface Claims {
  [name: string]: string | number;
}

export interface Credential {
  subject: string; // holder DID
  claims: Claims;
  issuer: string; // issuer DID
  issuedAt: string; // ISO-8601 UTC
  holderCommit: string; // Poseidon(holderSecret), decimal field element
  schema: string; // schema id registered in the Schema Registry
  /** v3: 32 random bytes (hex) so credID, and hence the leaf, is unguessable. */
  salt?: string;
}

export interface VerifiableCredential {
  credential: Credential;
  credID: string; // hex, 32 bytes
  signature: string; // hex, ML-DSA-44 signature over credID
}

/**
 * ML-DSA-44 implementation used for issuance. "liboqs" is the default;
 * "dilithium-py" matches the paper's A.5 harness issuance step (portability)
 * and is byte-compatible with liboqs (enforced by tests/interop). Timing
 * tables never include dilithium-py operations.
 */
export type SigImpl = "liboqs" | "dilithium-py";

export interface Issuer {
  did: string;
  keys: SigKeypair;
  impl: SigImpl;
}

export function createIssuer(impl: SigImpl = "liboqs"): Issuer {
  const keys = impl === "dilithium-py" ? dilithiumKeygenDpy() : dilithiumKeygen();
  return { did: didFromPublicKey(keys.publicKey), keys, impl };
}

export function computeCredId(cred: Credential, pkIssuer: Uint8Array): Buffer {
  return sha3_256(canonicalJsonBytes(cred), pkIssuer);
}

export function issueCredential(args: {
  issuer: Issuer;
  subjectDid: string;
  claims: Claims;
  holderCommit: bigint;
  schema?: string;
  issuedAt?: string;
}): VerifiableCredential {
  const cred: Credential = {
    subject: args.subjectDid,
    claims: args.claims,
    issuer: args.issuer.did,
    issuedAt: args.issuedAt ?? new Date().toISOString(),
    holderCommit: args.holderCommit.toString(),
    schema: args.schema ?? "pqid:schema:identity-v1",
  };
  const credId = computeCredId(cred, args.issuer.keys.publicKey);
  const signature =
    args.issuer.impl === "dilithium-py"
      ? dilithiumSignDpy(args.issuer.keys.secretKey, credId)
      : dilithiumSign(args.issuer.keys.secretKey, credId);
  return {
    credential: cred,
    credID: credId.toString("hex"),
    signature: signature.toString("hex"),
  };
}

// ============================================================================
// Circuit v3: issuance tree + issuer-signed epoch statements
// ============================================================================

/**
 * An issuer's signed statement for one epoch: "root is my issuance-tree root
 * and revRoot my revocation root". The issuer anchors (epoch, root, revRoot,
 * SHA3(signature)) on chain; the verifier accepts only the CURRENT anchor and
 * checks `signature` with pk_issuer resolved on-chain (packages/verifier,
 * circuit "v3"); the circuit proves the credential leaf is under `root` and
 * not revoked under `revRoot`. Revocations take effect at the next epoch.
 */
export interface IssuanceRootAttestation {
  issuerDid: string;
  epoch: number;
  root: string; // decimal field element
  revRoot: string; // decimal field element
  signature: string; // hex, ML-DSA-44 over issuanceRootMessage(issuerDid, epoch, root, revRoot)
}

/** What a holder needs to prove membership: its leaf position + path + signed epoch statement. */
export interface IssuanceWitness {
  path: IssuancePath;
  attestation: IssuanceRootAttestation;
}

export interface IssuerV3 extends Issuer {
  tree: IssuanceTree;
  /** Leaf index of each issued credential, keyed by credID hex. */
  leafIndexByCredId: Map<string, number>;
  /** Signed statements not yet superseded by an anchor, with the tree size each covers. */
  signed: Array<{ attestation: IssuanceRootAttestation; size: number }>;
  /** The most recently signed statement (may not be anchored yet). */
  latest: IssuanceRootAttestation | null;
  /** The statement anchored on chain and the tree size it covers: what holders are served. */
  anchored: { attestation: IssuanceRootAttestation; size: number } | null;
}

export async function createIssuerV3(impl: SigImpl = "liboqs"): Promise<IssuerV3> {
  return {
    ...createIssuer(impl),
    tree: await IssuanceTree.create(),
    leafIndexByCredId: new Map(),
    signed: [],
    latest: null,
    anchored: null,
  };
}

/**
 * Algorithm 2 for v3: issue exactly as v2 (credID, sigma over credID), then
 * append the credential leaf
 *   Poseidon(CRED_LEAF_V1, issuerKeyHash, credIDHi, credIDLo, holderCommit, age)
 * to the issuance tree. The new root is not attested until signIssuanceRoot.
 */
export async function issueCredentialV3(args: {
  issuer: IssuerV3;
  subjectDid: string;
  claims: Claims;
  holderCommit: bigint;
  schema?: string;
  issuedAt?: string;
}): Promise<{ vc: VerifiableCredential; leafIndex: number }> {
  const age = args.claims["age"];
  if (typeof age !== "number" || !Number.isInteger(age) || age < 0 || age >= 2 ** 32) {
    throw new Error("v3 credentials need an integer claims.age in [0, 2^32)");
  }
  const cred: Credential = {
    subject: args.subjectDid,
    claims: args.claims,
    issuer: args.issuer.did,
    issuedAt: args.issuedAt ?? new Date().toISOString(),
    holderCommit: args.holderCommit.toString(),
    schema: args.schema ?? "pqid:schema:identity-v1",
    salt: randomBytes(32).toString("hex"),
  };
  const credId = computeCredId(cred, args.issuer.keys.publicKey);
  const signature =
    args.issuer.impl === "dilithium-py"
      ? dilithiumSignDpy(args.issuer.keys.secretKey, credId)
      : dilithiumSign(args.issuer.keys.secretKey, credId);
  const poseidon = await getPoseidon();
  const leaf = credentialLeaf(poseidon, {
    issuerKeyHash: issuerKeyHash(poseidon, args.issuer.keys.publicKey),
    credId,
    holderCommit: args.holderCommit,
    claimAge: BigInt(age),
  });
  const leafIndex = args.issuer.tree.insert(leaf);
  const credIdHex = credId.toString("hex");
  args.issuer.leafIndexByCredId.set(credIdHex, leafIndex);
  return {
    vc: { credential: cred, credID: credIdHex, signature: signature.toString("hex") },
    leafIndex,
  };
}

/**
 * Sign the next epoch statement: the current issuance-tree root and the given
 * revocation root (the root of the issuer's revoked-set snapshot for that
 * epoch). Epochs number ANCHORED statements (the registry requires previous
 * + 1), so a signed-but-never-anchored statement is superseded, not skipped.
 * An unchanged pair is not re-signed: every holder must see the same bytes.
 * The caller anchors it with Ledger.publishIssuanceRoot and then calls
 * syncIssuanceAnchor with what the chain reports.
 */
export function signIssuanceRoot(issuer: IssuerV3, revRoot: bigint): IssuanceRootAttestation {
  const root = issuer.tree.root();
  const anchoredEpoch = issuer.anchored?.attestation.epoch ?? 0;
  const latest = issuer.latest;
  if (
    latest &&
    latest.root === root.toString() &&
    latest.revRoot === revRoot.toString() &&
    latest.epoch >= anchoredEpoch
  ) {
    return latest;
  }
  const epoch = anchoredEpoch + 1;
  const msg = issuanceRootMessage(issuer.did, epoch, root, revRoot);
  const signature =
    issuer.impl === "dilithium-py"
      ? dilithiumSignDpy(issuer.keys.secretKey, msg)
      : dilithiumSign(issuer.keys.secretKey, msg);
  const att: IssuanceRootAttestation = {
    issuerDid: issuer.did,
    epoch,
    root: root.toString(),
    revRoot: revRoot.toString(),
    signature: signature.toString("hex"),
  };
  issuer.latest = att;
  issuer.signed.push({ attestation: att, size: issuer.tree.size });
  return att;
}

/**
 * Reconcile the issuer's served state with the chain (the source of truth).
 * If the chain holds a newer epoch that this issuer signed, that statement
 * becomes the served one; if the chain holds anything this issuer did not
 * sign, its state has diverged and it must not serve paths.
 */
export function syncIssuanceAnchor(
  issuer: IssuerV3,
  chain: { epoch: number; root: bigint; revRoot: bigint; sigHash: string }
): void {
  if (chain.epoch === 0) return;
  const matches = (a: IssuanceRootAttestation) =>
    a.epoch === chain.epoch &&
    a.root === chain.root.toString() &&
    a.revRoot === chain.revRoot.toString() &&
    sha3_256(Buffer.from(a.signature, "hex")).toString("hex") === chain.sigHash;
  if (issuer.anchored && matches(issuer.anchored.attestation)) return;
  const entry = issuer.signed.find((e) => matches(e.attestation));
  if (!entry) {
    throw new Error(`chain anchor (epoch ${chain.epoch}) is not a statement this issuer signed — state diverged`);
  }
  issuer.anchored = entry;
  issuer.signed = issuer.signed.filter((e) => e.attestation.epoch > chain.epoch);
}

/**
 * Holder-facing issuance service: the path of `credId` against the statement
 * currently ANCHORED on chain, also while newer issuances are unsigned or a
 * newer statement is signed but not yet anchored. A credential issued after
 * that statement is refused until the next anchor. Wallets fetch this right
 * before presenting and check it against the chain (buildProofInputV3).
 */
export function issuanceWitness(issuer: IssuerV3, credIdHex: string): IssuanceWitness {
  const leafIndex = issuer.leafIndexByCredId.get(credIdHex);
  if (leafIndex === undefined) throw new Error("credential was not issued by this issuer");
  const anchored = issuer.anchored;
  if (!anchored || leafIndex >= anchored.size) {
    throw new Error("credential is not yet covered by an anchored issuance root");
  }
  const path = issuer.tree.pathAt(leafIndex, anchored.size);
  if (path.root !== anchored.attestation.root) {
    throw new Error("internal: anchored root does not match the tree snapshot");
  }
  return { path, attestation: anchored.attestation };
}
