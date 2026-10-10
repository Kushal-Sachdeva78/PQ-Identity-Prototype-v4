import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import type { PublicSignals } from "snarkjs";
import { sha256File } from "@pqid/common/hash";
import { didFromPublicKey } from "@pqid/common/did";
import {
  REPO_ROOT,
  RESULTS_DIR_V3,
  R1CS_FILE,
  R1CS_FILE_V3,
  VKEY_FILE,
  VKEY_FILE_V3,
  ZKEY_FILE,
  ZKEY_FILE_V3,
} from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";
import {
  getPoseidon,
  issuerKeyHash,
  policyHash,
  verifierDomainTag,
  stmtCodeForDomain,
  stmtCodeForDomainV3,
  credentialLeaf,
  issuanceRootMessage,
  PREDICATE_AGE_GTE,
} from "@pqid/common/encoding";
import {
  computeCredId,
  createIssuerV3,
  issueCredentialV3,
  issuanceWitness,
  signIssuanceRoot,
  syncIssuanceAnchor,
  IssuanceTree,
  type Credential,
  type IssuanceRootAttestation,
  type IssuanceWitness,
  type IssuerV3,
  type VerifiableCredential,
} from "@pqid/issuer";
import { dilithiumKeygen, dilithiumSign, mlDsaImplementation } from "@pqid/pqc";
import {
  createWallet,
  buildProofInput,
  buildProofInputV3,
  canonicalAttestation,
  readChainViewV3,
  type HolderWallet,
  type PolicyV1,
} from "@pqid/wallet";
import { buildCircuitInput, buildCircuitInputV3, type CircuitInput } from "@pqid/wallet/witness";
import { computeWitness, proveSnarkjsOnWitness, V2_ARTIFACTS, V3_ARTIFACTS } from "@pqid/wallet/prove";
import { RevocationTree, type NonMembershipProof } from "@pqid/revocation";
import { Ledger, startAnvil } from "@pqid/ledger";
import { Verifier, type Presentation, type VerifierPolicy, type VerifyDecision } from "@pqid/verifier";
import { fixtureRevokedCredIds } from "../fixture.ts";
import { deriveBeaconTrapdoor, forgeProof } from "./trapdoor.ts";
import { patchWitnessWire, r1csSatisfied } from "./wtns_tamper.ts";
import {
  revokedInclusion,
  forgedIsOld0Opening,
  sameKeyOpening,
  truncatedEmptyOpening,
} from "./smt_forgery.ts";
import { compileV3Without } from "./attacker_circuit.ts";

/**
 * v2 vs v3 SECURITY SUITE (review findings 9.1-9.3, plus the findings of the
 * adversarial review of v3 itself).
 *
 * Every attack runs against the published v2 circuit AND the v3 circuit on the
 * same host, the same local EVM and the same issuers, through the real Verifier
 * (on-chain DID / accreditation / revRoot / issuance-root resolution, nonce
 * registry, Groth16.verify, and for v3 the ML-DSA-44 issuance-root check).
 *
 * Attacker capabilities: full control of its own wallet and prover (any
 * witness values, hand-edited witness files, its own witness generator built
 * from the circuit minus a defence line, its own Merkle trees, its own ML-DSA
 * key, its own DID); it reads everything public. It cannot sign with an
 * accredited issuer's ML-DSA key. Route A8 additionally lets it write the
 * issuer's on-chain anchor (modelling an ECDSA forger, review 9.4).
 *
 * Record kinds:
 *   control          must be ACCEPTED (honest holders);
 *   attack           v3 must NOT be accepted; v2 results document its gaps;
 *   baseline         an honest library refuses before any proof exists (not
 *                    counted as a defence: the attacker controls that code);
 *   privacy          v3 must reject presentations that would make holders
 *                    linkable, and honest holders' views must be identical;
 *   known-limitation accepted by design today; listed so the attack count is
 *                    not read as covering it.
 * Pass criterion: controls accepted, no v3 attack route accepted, privacy
 * checks hold.
 */
type Circuit = "v2" | "v3";
type Kind = "control" | "attack" | "baseline" | "privacy" | "known-limitation";
type Outcome =
  | "ACCEPTED"
  | "rejected by verifier"
  | "no proof: witness generator refused"
  | "no proof: honest component refused"
  | "proof does not verify (R1CS unsatisfied)"
  | "rejected by the anchor registry"
  | "invalid test";

interface Attempt {
  circuit: Circuit;
  route: string;
  outcome: Outcome;
  accepted: boolean;
  failedChecks?: string[];
  notEvaluated?: string[];
  reasons?: string[];
  r1csSatisfied?: boolean;
  detail?: string;
  /** Privacy records: whether the property held for this attempt. */
  pass?: boolean;
}

interface AttackRecord {
  id: string;
  title: string;
  finding: string;
  kind: Kind;
  attempts: Attempt[];
}

interface Built {
  input: CircuitInput;
  issuerDid: string;
  attestation?: IssuanceRootAttestation;
  /** Overwrite one witness wire after generation (malicious-prover route). */
  tamper?: { wire: number; value: bigint };
  /** Use this witness generator instead of the reference wasm (malicious prover). */
  wasm?: string;
  /** Edit the presentation after proving. */
  mutate?: (p: Presentation) => void;
}

const POLICY_18: VerifierPolicy = { type: "age_gte", threshold: 18 };
/** Minimum seconds between two anchors of one issuer on this suite's chain (time is advanced explicitly). */
const ANCHOR_INTERVAL = 3600;
const WALLET_POLICY_18: PolicyV1 = { type: "age_gte", attribute: "age", threshold: 18 };
const ISS_ROOT_WIRE = 6; // wire 0 = constant 1; wires 1..6 = public signals, issRoot last
const BOOLEANITY_LINE = "smtIsOld0 * (smtIsOld0 - 1) === 0;";

const circuitSources: Record<string, string[]> = {
  CredentialAuth: fs
    .readFileSync(path.join(REPO_ROOT, "circuits", "credential_auth.circom"), "utf8")
    .split(/\r?\n/),
  CredentialAuthV3: fs
    .readFileSync(path.join(REPO_ROOT, "circuits", "credential_auth_v3.circom"), "utf8")
    .split(/\r?\n/),
};

/** "Assert Failed … template CredentialAuthV3_309 line: 118" -> source line text. */
function describeWitnessFailure(e: unknown): string {
  const msg = String((e as Error)?.message ?? e);
  const m = /template (\w+?)_\d+ line: (\d+)/.exec(msg);
  if (!m) return msg.split("\n").slice(0, 2).join(" ").trim();
  const [, template, line] = m as unknown as [string, string, string];
  const src = circuitSources[template];
  const text = src?.[Number(line) - 1]?.trim();
  return `assertion failed in ${template} line ${line}${text ? `: ${text}` : ""}`;
}

function failed(d: VerifyDecision): { failedChecks: string[]; notEvaluated: string[] } {
  const notEvaluated = d.notEvaluated;
  return {
    failedChecks: Object.entries(d.checks)
      .filter(([k, v]) => v === false && !notEvaluated.includes(k))
      .map(([k]) => k),
    notEvaluated,
  };
}

/** What a verifier sees of a presentation, minus the per-session nonce and the (re-randomized) proof. */
function verifierView(p: Presentation): string {
  const s = p.publicSignals;
  return JSON.stringify({
    signals: s.filter((_, i) => i !== 3),
    issuerDid: p.issuerDid,
    attestation: p.issuanceRoot ?? null,
  });
}

async function main(): Promise<void> {
  const poseidon = await getPoseidon();
  const anvil = await startAnvil(18711);
  const attacks: AttackRecord[] = [];
  let trapdoorInfo: Record<Circuit, { matchesDelta: boolean; gammaIsGenerator: boolean }> | null = null;
  let viewCheck: Record<string, unknown> | null = null;
  let attackerBuild: { sameWireLayout: boolean } | null = null;

  try {
    const ledger = await Ledger.deploy(anvil.rpcUrl, { minAnchorIntervalSec: ANCHOR_INTERVAL });
    const v2Verifier = new Verifier(ledger, { circuit: "v2" });
    const v3Verifier = new Verifier(ledger, { circuit: "v3" });
    const verifierFor = (c: Circuit) => (c === "v2" ? v2Verifier : v3Verifier);

    // ------------------------------------------------------------ world setup
    console.log(`[suite] ML-DSA-44 backend: ${mlDsaImplementation()}`);
    const issuerA = await createIssuerV3();
    const issuerB = await createIssuerV3();
    for (const iss of [issuerA, issuerB]) {
      await ledger.registerDid(iss.did, iss.keys.publicKey);
      await ledger.accreditIssuer(iss.did);
    }
    // Each issuer keeps a WORKING revoked set (revocations land here at once)
    // and serves openings from the SNAPSHOT whose root is anchored in the
    // current epoch statement; revocations take effect at the next epoch.
    const revTrees = new Map<string, RevocationTree>();
    const anchoredRev = new Map<string, RevocationTree>();
    const addIssuerRevocation = async (iss: IssuerV3, revoked: Uint8Array[] = fixtureRevokedCredIds()) => {
      const t = await RevocationTree.create();
      for (const id of revoked) await t.insert(id);
      revTrees.set(iss.did, t);
    };
    for (const iss of [issuerA, issuerB]) await addIssuerRevocation(iss);
    const revTree = (iss: IssuerV3) => revTrees.get(iss.did) as RevocationTree;
    const ikh = (iss: IssuerV3) => issuerKeyHash(poseidon, iss.keys.publicKey);
    /**
     * Issuer signs its next epoch statement (issuance root + a snapshot of its
     * revoked set), waits out the anchor interval, anchors it, publishes the
     * same revocation root for v2 verifiers, and syncs its state from the chain.
     */
    const signAndAnchor = async (iss: IssuerV3) => {
      const snapshot = await revTree(iss).snapshot();
      const att = signIssuanceRoot(iss, snapshot.root());
      const cur = await ledger.getIssuanceRoot(iss.did);
      if (cur.epoch !== att.epoch) {
        if (cur.epoch > 0) await ledger.devAdvanceTime(ANCHOR_INTERVAL);
        await ledger.publishIssuanceRoot(iss.did, att);
        await ledger.publishRevRoot(iss.did, snapshot.root());
      }
      syncIssuanceAnchor(iss, await ledger.getIssuanceRoot(iss.did));
      anchoredRev.set(iss.did, snapshot);
      return att;
    };
    /** What an honest wallet reads from the chain itself before presenting. */
    const chainOf = (iss: IssuerV3) => readChainViewV3(ledger, iss.did);

    const holders: Record<string, { wallet: HolderWallet; vc: VerifiableCredential; issuer: IssuerV3 }> = {};
    const issueTo = async (name: string, issuer: IssuerV3, age: number) => {
      const wallet = await createWallet();
      const { vc } = await issueCredentialV3({
        issuer,
        subjectDid: wallet.did,
        claims: { age, name: `holder ${name}` },
        holderCommit: wallet.holderCommit,
      });
      holders[name] = { wallet, vc, issuer };
    };
    await issueTo("adult", issuerA, 42);
    await issueTo("minor", issuerA, 16);
    await issueTo("revokee", issuerA, 30);
    await issueTo("victim", issuerA, 50);
    for (const [i, age] of [19, 25, 33, 61].entries()) await issueTo(`filler${i}`, issuerA, age);
    await issueTo("holderB", issuerB, 35);
    const attA1 = await signAndAnchor(issuerA);
    await signAndAnchor(issuerB);
    const H = (name: string) => holders[name] as { wallet: HolderWallet; vc: VerifiableCredential; issuer: IssuerV3 };
    const witnessOf = (name: string): IssuanceWitness => issuanceWitness(H(name).issuer, H(name).vc.credID);
    const adultAtEpoch1 = witnessOf("adult");
    console.log(
      `[suite] issuer A: ${issuerA.tree.size} credentials, root anchored (epoch ${attA1.epoch}); issuer B: ${issuerB.tree.size}`
    );

    // attacker's own ML-DSA key and (unaccredited) DID
    const attackerKeys = dilithiumKeygen();
    const attackerDid = didFromPublicKey(attackerKeys.publicKey);
    await ledger.registerDid(attackerDid, attackerKeys.publicKey);

    // ---------------------------------------------------------------- helpers
    const published = (iss: IssuerV3) => anchoredRev.get(iss.did) as RevocationTree;
    const nm = async (iss: IssuerV3, credId: Uint8Array): Promise<NonMembershipProof> =>
      published(iss).getNonMembershipProof(credId);
    const currentRevRoot = (iss: IssuerV3) => published(iss).root();

    /** Raw v2 witness input (a malicious wallet can set every private value). */
    const v2Input = (p: {
      nonce: bigint;
      issuer: IssuerV3;
      credId: Uint8Array;
      holderSecret: bigint;
      holderCommit: bigint;
      claimAge: bigint;
      nonMembership: NonMembershipProof;
      revRoot?: bigint;
    }): CircuitInput => {
      const domainTag = verifierDomainTag(poseidon, v2Verifier.verifierId);
      return buildCircuitInput(
        {
          issuerKeyHash: ikh(p.issuer),
          revRoot: p.revRoot ?? BigInt(p.nonMembership.root),
          policyHash: policyHash(poseidon, PREDICATE_AGE_GTE, 18n),
          nonce: p.nonce,
          stmtCode: stmtCodeForDomain(poseidon, domainTag),
        },
        {
          credId: p.credId,
          holderSecret: p.holderSecret,
          holderCommit: p.holderCommit,
          claimAge: p.claimAge,
          threshold: 18n,
          predicateCode: PREDICATE_AGE_GTE,
          domainTag,
          nonMembership: p.nonMembership,
        }
      );
    };

    /** Raw v3 witness input (a malicious wallet can set every private value). */
    const v3Input = (p: {
      nonce: bigint;
      issuerKeyHash: bigint;
      issRoot: bigint;
      credId: Uint8Array;
      holderSecret: bigint;
      claimAge: bigint;
      leafIndex: string;
      pathElements: string[];
      nonMembership: NonMembershipProof;
      revRoot?: bigint;
      verifierId?: string;
    }): CircuitInput => {
      const domainTag = verifierDomainTag(poseidon, p.verifierId ?? v3Verifier.verifierId);
      return buildCircuitInputV3(
        {
          issuerKeyHash: p.issuerKeyHash,
          revRoot: p.revRoot ?? BigInt(p.nonMembership.root),
          policyHash: policyHash(poseidon, PREDICATE_AGE_GTE, 18n),
          nonce: p.nonce,
          stmtCode: stmtCodeForDomainV3(poseidon, domainTag),
          issRoot: p.issRoot,
        },
        {
          credId: p.credId,
          holderSecret: p.holderSecret,
          claimAge: p.claimAge,
          threshold: 18n,
          predicateCode: PREDICATE_AGE_GTE,
          domainTag,
          issLeafIndex: p.leafIndex,
          issPathElements: p.pathElements,
          nonMembership: p.nonMembership,
        }
      );
    };

    /**
     * An honest holder's v3 input: path from the issuer's service (or `witness`,
     * e.g. one a malicious issuer served), checked by the wallet against the
     * chain; the presented attestation is the wallet's canonical rebuild.
     */
    const honestV3 = async (
      name: string,
      nonce: bigint,
      opts: { verifierId?: string; witness?: IssuanceWitness; policy?: PolicyV1; nonMembership?: NonMembershipProof } = {}
    ) => {
      const h = H(name);
      const w = opts.witness ?? witnessOf(name);
      const chain = await chainOf(h.issuer);
      return {
        input: await buildProofInputV3({
          wallet: h.wallet,
          vc: h.vc,
          request: { policy: opts.policy ?? WALLET_POLICY_18, nonce, verifierId: opts.verifierId ?? v3Verifier.verifierId },
          pkIssuer: h.issuer.keys.publicKey,
          revRoot: chain.anchor.revRoot,
          nonMembership: opts.nonMembership ?? (await nm(h.issuer, Buffer.from(h.vc.credID, "hex"))),
          issuance: w,
          chain,
        }),
        issuerDid: h.issuer.did,
        attestation: canonicalAttestation(w.attestation),
      };
    };

    /** An attacker-built issuance tree holding exactly the leaves it chooses. */
    const attackerTree = async (leaves: bigint[]) => {
      const t = await IssuanceTree.create();
      for (const l of leaves) t.insert(l);
      return t;
    };

    const attempt = async (
      circuit: Circuit,
      route: string,
      build: (nonce: bigint) => Promise<Built>,
      opts: {
        policy?: VerifierPolicy;
        verifier?: Verifier;
        capture?: (p: Presentation) => void;
        /** The route EXPECTS an honest component (issuer service or the holder's own wallet) to refuse with this reason. */
        expectRefusal?: RegExp;
      } = {}
    ): Promise<Attempt> => {
      const verifier = opts.verifier ?? verifierFor(circuit);
      const policy = opts.policy ?? POLICY_18;
      const nonce = verifier.newSessionNonce();
      let built: Built;
      try {
        built = await build(nonce);
      } catch (e) {
        // fail closed: an unexpected exception is a broken test, not a defence
        return {
          circuit,
          route,
          outcome: opts.expectRefusal?.test((e as Error).message) ? "no proof: honest component refused" : "invalid test",
          accepted: false,
          detail: (e as Error).message,
        };
      }
      const art = circuit === "v2" ? V2_ARTIFACTS : V3_ARTIFACTS;
      let wtnsFile: string;
      try {
        wtnsFile = (await computeWitness(built.input, built.wasm ?? art.wasm)).wtnsFile;
      } catch (e) {
        const assertion = /Assert Failed/.test(String((e as Error)?.message));
        return {
          circuit,
          route,
          outcome: assertion ? "no proof: witness generator refused" : "invalid test",
          accepted: false,
          detail: describeWitnessFailure(e),
        };
      }
      try {
        let r1csOk: boolean | undefined;
        if (built.tamper) patchWitnessWire(wtnsFile, built.tamper.wire, built.tamper.value);
        if (built.tamper || built.wasm) {
          r1csOk = await r1csSatisfied(circuit === "v2" ? R1CS_FILE : R1CS_FILE_V3, wtnsFile);
        }
        const proved = await proveSnarkjsOnWitness(wtnsFile, art.zkey);
        const presentation: Presentation = {
          proof: proved.proof,
          publicSignals: proved.publicSignals,
          issuerDid: built.issuerDid,
          ...(built.attestation ? { issuanceRoot: built.attestation } : {}),
        };
        built.mutate?.(presentation);
        opts.capture?.(presentation);
        const decision = await verifier.verifyPresentation(presentation, policy);
        const malicious = built.tamper !== undefined || built.wasm !== undefined;
        const outcome: Outcome = decision.accepted
          ? "ACCEPTED"
          : malicious && !decision.checks.proofValid
            ? "proof does not verify (R1CS unsatisfied)"
            : "rejected by verifier";
        return {
          circuit,
          route,
          outcome,
          accepted: decision.accepted,
          ...failed(decision),
          reasons: decision.reasons,
          ...(r1csOk === undefined ? {} : { r1csSatisfied: r1csOk }),
        };
      } finally {
        fs.rmSync(wtnsFile, { force: true });
      }
    };

    const record = (r: AttackRecord) => {
      attacks.push(r);
      for (const a of r.attempts) {
        console.log(
          `[suite] ${r.id} ${a.circuit} ${a.route}\n          -> ${a.outcome}` +
            `${a.failedChecks?.length ? ` [${a.failedChecks.join(", ")}]` : ""}${a.detail ? ` (${a.detail})` : ""}`
        );
      }
    };

    // ------------------------------------------------------ C0 positive controls
    {
      const adult = H("adult");
      record({
        id: "C0",
        title: "Honest holders are accepted",
        finding: "control",
        kind: "control",
        attempts: [
          await attempt("v2", "honest wallet, adult (42), age >= 18", async (nonce) => ({
            input: await buildProofInput({
              wallet: adult.wallet,
              vc: adult.vc,
              request: { policy: WALLET_POLICY_18, nonce, verifierId: v2Verifier.verifierId },
              pkIssuer: issuerA.keys.publicKey,
              revRoot: currentRevRoot(issuerA),
              nonMembership: await nm(issuerA, Buffer.from(adult.vc.credID, "hex")),
            }),
            issuerDid: issuerA.did,
          })),
          await attempt("v3", "honest wallet, adult (42), age >= 18", (nonce) => honestV3("adult", nonce)),
          await attempt(
            "v3",
            "honest wallet, minor (16), age < 18 (second predicate)",
            (nonce) => honestV3("minor", nonce, { policy: { type: "age_lt", attribute: "age", threshold: 18 } }),
            { policy: { type: "age_lt", threshold: 18 } }
          ),
        ],
      });
    }

    // ------------------------------------- A1 forged credential (the 9.1 probe)
    {
      const attacker = await createWallet();
      const forged: Credential = {
        subject: attacker.did,
        claims: { age: 42, name: "Forged Identity" },
        issuer: issuerA.did,
        issuedAt: "2026-09-26T00:00:00.000Z",
        holderCommit: attacker.holderCommit.toString(),
        schema: "pqid:schema:identity-v1",
      };
      const forgedId = computeCredId(forged, issuerA.keys.publicKey);
      const vcForged: VerifiableCredential = {
        credential: forged,
        credID: forgedId.toString("hex"),
        signature: "00".repeat(2420), // no valid issuer signature exists
      };
      const forgedLeafA = credentialLeaf(poseidon, {
        issuerKeyHash: ikh(issuerA),
        credId: forgedId,
        holderCommit: attacker.holderCommit,
        claimAge: 42n,
      });
      const ownTree = await attackerTree([forgedLeafA]);
      const ownPath = ownTree.path(0);
      const adultPath = witnessOf("adult").path;
      const forgedNm = await nm(issuerA, forgedId);
      const forgedV3Input = (nonce: bigint, issRoot: bigint, p: { leafIndex: string; pathElements: string[] }) =>
        v3Input({
          nonce,
          issuerKeyHash: ikh(issuerA),
          issRoot,
          credId: forgedId,
          holderSecret: attacker.holderSecret,
          claimAge: 42n,
          leafIndex: p.leafIndex,
          pathElements: p.pathElements,
          nonMembership: forgedNm,
        });

      // attacker-signed attestation that claims to come from issuer A
      const selfSigned: IssuanceRootAttestation = {
        issuerDid: issuerA.did,
        epoch: attA1.epoch,
        root: ownTree.root().toString(),
        revRoot: attA1.revRoot,
        signature: dilithiumSign(
          attackerKeys.secretKey,
          issuanceRootMessage(issuerA.did, attA1.epoch, ownTree.root(), BigInt(attA1.revRoot))
        ).toString("hex"),
      };
      // a fully self-consistent world under the attacker's OWN (unaccredited) DID
      const ownIkh = issuerKeyHash(poseidon, attackerKeys.publicKey);
      const selfLeaf = credentialLeaf(poseidon, {
        issuerKeyHash: ownIkh,
        credId: forgedId,
        holderCommit: attacker.holderCommit,
        claimAge: 42n,
      });
      const selfTree = await attackerTree([selfLeaf]);
      const selfRev = await RevocationTree.create();
      await ledger.publishRevRoot(attackerDid, selfRev.root());
      const selfAtt: IssuanceRootAttestation = {
        issuerDid: attackerDid,
        epoch: 1,
        root: selfTree.root().toString(),
        revRoot: selfRev.root().toString(),
        signature: dilithiumSign(
          attackerKeys.secretKey,
          issuanceRootMessage(attackerDid, 1, selfTree.root(), selfRev.root())
        ).toString("hex"),
      };
      await ledger.publishIssuanceRoot(attackerDid, selfAtt);
      const selfNm = await selfRev.getNonMembershipProof(forgedId);

      record({
        id: "A1",
        title: "Forged credential the issuer never issued (malicious-wallet probe)",
        finding: "9.1",
        kind: "attack",
        attempts: [
          await attempt("v2", "wallet skips the Dilithium check (harness/malicious_wallet_probe.ts)", async (nonce) => ({
            input: await buildProofInput({
              wallet: attacker,
              vc: vcForged,
              request: { policy: WALLET_POLICY_18, nonce, verifierId: v2Verifier.verifierId },
              pkIssuer: issuerA.keys.publicKey,
              revRoot: currentRevRoot(issuerA),
              nonMembership: forgedNm,
              dangerouslySkipOffCircuitChecks: true,
            }),
            issuerDid: issuerA.did,
          })),
          await attempt("v3", "forged leaf + issuer A's anchored root + a real holder's path", async (nonce) => ({
            input: forgedV3Input(nonce, BigInt(attA1.root), adultPath),
            issuerDid: issuerA.did,
            attestation: attA1,
          })),
          await attempt("v3", "attacker-built tree; presents issuer A's genuine attestation", async (nonce) => ({
            input: forgedV3Input(nonce, ownTree.root(), ownPath),
            issuerDid: issuerA.did,
            attestation: attA1,
          })),
          await attempt("v3", "attacker-built tree; root signed with the attacker's own ML-DSA key", async (nonce) => ({
            input: forgedV3Input(nonce, ownTree.root(), ownPath),
            issuerDid: issuerA.did,
            attestation: selfSigned,
          })),
          await attempt("v3", "attacker-built tree; issRoot wire swapped to A's anchored root in the witness file", async (nonce) => ({
            input: forgedV3Input(nonce, ownTree.root(), ownPath),
            issuerDid: issuerA.did,
            attestation: attA1,
            tamper: { wire: ISS_ROOT_WIRE, value: BigInt(attA1.root) },
          })),
          await attempt("v3", "self-issued under the attacker's own registered but unaccredited DID", async (nonce) => ({
            input: v3Input({
              nonce,
              issuerKeyHash: ownIkh,
              issRoot: selfTree.root(),
              credId: forgedId,
              holderSecret: attacker.holderSecret,
              claimAge: 42n,
              leafIndex: "0",
              pathElements: selfTree.path(0).pathElements,
              nonMembership: selfNm,
            }),
            issuerDid: attackerDid,
            attestation: selfAtt,
          })),
        ],
      });
    }

    // ----------------------------------------------- A2 forged age (16 -> 42)
    {
      const minor = H("minor");
      const minorId = Buffer.from(minor.vc.credID, "hex");
      const minorNm = await nm(issuerA, minorId);
      const minorW = witnessOf("minor");
      const reLeaf = credentialLeaf(poseidon, {
        issuerKeyHash: ikh(issuerA),
        credId: minorId,
        holderCommit: minor.wallet.holderCommit,
        claimAge: 42n,
      });
      const ownTree = await attackerTree([reLeaf]);
      const asAdult = (nonce: bigint, issRoot: bigint, p: { leafIndex: string; pathElements: string[] }) =>
        v3Input({
          nonce,
          issuerKeyHash: ikh(issuerA),
          issRoot,
          credId: minorId,
          holderSecret: minor.wallet.holderSecret,
          claimAge: 42n,
          leafIndex: p.leafIndex,
          pathElements: p.pathElements,
          nonMembership: minorNm,
        });
      record({
        id: "A2",
        title: "Holder of a genuine age-16 credential claims age 42",
        finding: "9.1",
        kind: "attack",
        attempts: [
          await attempt("v2", "malicious wallet sets claimAge = 42 with the minor's real credential", async (nonce) => ({
            input: v2Input({
              nonce,
              issuer: issuerA,
              credId: minorId,
              holderSecret: minor.wallet.holderSecret,
              holderCommit: minor.wallet.holderCommit,
              claimAge: 42n,
              nonMembership: minorNm,
            }),
            issuerDid: issuerA.did,
          })),
          await attempt("v3", "claimAge = 42 with the minor's genuine path and A's anchored root", async (nonce) => ({
            input: asAdult(nonce, BigInt(minorW.attestation.root), minorW.path),
            issuerDid: issuerA.did,
            attestation: minorW.attestation,
          })),
          await attempt("v3", "re-leafed with age 42 in an attacker-built tree; A's genuine attestation", async (nonce) => ({
            input: asAdult(nonce, ownTree.root(), ownTree.path(0)),
            issuerDid: issuerA.did,
            attestation: minorW.attestation,
          })),
          await attempt("v3", "attacker-built tree; issRoot wire swapped to A's anchored root", async (nonce) => ({
            input: asAdult(nonce, ownTree.root(), ownTree.path(0)),
            issuerDid: issuerA.did,
            attestation: minorW.attestation,
            tamper: { wire: ISS_ROOT_WIRE, value: BigInt(minorW.attestation.root) },
          })),
        ],
      });
    }

    // ------------------------------- A4 stolen credential, holder secret unknown
    {
      const victim = H("victim");
      const thief = await createWallet();
      const victimId = Buffer.from(victim.vc.credID, "hex");
      const victimNm = await nm(issuerA, victimId);
      const victimW = witnessOf("victim");
      const thiefLeaf = credentialLeaf(poseidon, {
        issuerKeyHash: ikh(issuerA),
        credId: victimId,
        holderCommit: thief.holderCommit,
        claimAge: 50n,
      });
      const ownTree = await attackerTree([thiefLeaf]);
      const thiefInput = (nonce: bigint, issRoot: bigint, p: { leafIndex: string; pathElements: string[] }) =>
        v3Input({
          nonce,
          issuerKeyHash: ikh(issuerA),
          issRoot,
          credId: victimId,
          holderSecret: thief.holderSecret,
          claimAge: 50n,
          leafIndex: p.leafIndex,
          pathElements: p.pathElements,
          nonMembership: victimNm,
        });
      record({
        id: "A4",
        title: "Thief holds the victim's full credential and path, but not the holder secret",
        finding: "9.1 / 9.7",
        kind: "attack",
        attempts: [
          await attempt("v2", "victim's credential with the thief's own secret and holderCommit", async (nonce) => ({
            input: v2Input({
              nonce,
              issuer: issuerA,
              credId: victimId,
              holderSecret: thief.holderSecret,
              holderCommit: thief.holderCommit,
              claimAge: 50n,
              nonMembership: victimNm,
            }),
            issuerDid: issuerA.did,
          })),
          await attempt("v3", "victim's genuine path, thief's secret", async (nonce) => ({
            input: thiefInput(nonce, BigInt(victimW.attestation.root), victimW.path),
            issuerDid: issuerA.did,
            attestation: victimW.attestation,
          })),
          await attempt("v3", "thief's leaf in an attacker-built tree; issRoot wire swapped", async (nonce) => ({
            input: thiefInput(nonce, ownTree.root(), ownTree.path(0)),
            issuerDid: issuerA.did,
            attestation: victimW.attestation,
            tamper: { wire: ISS_ROOT_WIRE, value: BigInt(victimW.attestation.root) },
          })),
        ],
      });
    }

    // ------------------------------ A5 cross-issuer transplant (B's credential as A's)
    {
      const hb = H("holderB");
      const idB = Buffer.from(hb.vc.credID, "hex");
      const wB = witnessOf("holderB");
      const relabelled: IssuanceRootAttestation = { ...wB.attestation, issuerDid: issuerA.did };
      const asIssuer = (nonce: bigint, key: bigint, nonMembership: NonMembershipProof) =>
        v3Input({
          nonce,
          issuerKeyHash: key,
          issRoot: BigInt(wB.attestation.root),
          credId: idB,
          holderSecret: hb.wallet.holderSecret,
          claimAge: 35n,
          leafIndex: wB.path.leafIndex,
          pathElements: wB.path.pathElements,
          nonMembership,
        });
      record({
        id: "A5",
        title: "Holder of issuer B's credential presents it as issuer A's",
        finding: "9.1",
        kind: "attack",
        attempts: [
          await attempt("v2", "B's holder claims issuerDid A (issuerKeyHash = A's)", async (nonce) => ({
            input: v2Input({
              nonce,
              issuer: issuerA,
              credId: idB,
              holderSecret: hb.wallet.holderSecret,
              holderCommit: hb.wallet.holderCommit,
              claimAge: 35n,
              nonMembership: await nm(issuerA, idB),
            }),
            issuerDid: issuerA.did,
          })),
          await attempt("v3", "valid proof on B's tree, issuerDid A, B's attestation", async (nonce) => ({
            input: asIssuer(nonce, ikh(issuerB), await nm(issuerA, idB)),
            issuerDid: issuerA.did,
            attestation: wB.attestation,
          })),
          await attempt("v3", "valid proof on B's tree, B's attestation relabelled as issuer A", async (nonce) => ({
            input: asIssuer(nonce, ikh(issuerB), await nm(issuerA, idB)),
            issuerDid: issuerA.did,
            attestation: relabelled,
          })),
          await attempt("v3", "witness uses A's issuerKeyHash with B's path", async (nonce) => ({
            input: asIssuer(nonce, ikh(issuerA), await nm(issuerA, idB)),
            issuerDid: issuerA.did,
            attestation: relabelled,
          })),
        ],
      });
    }

    // ----------------------------------------- A6 attestation / encoding tampering
    {
      const w = witnessOf("adult");
      const bSigOnARoot: IssuanceRootAttestation = {
        ...w.attestation,
        signature: dilithiumSign(
          issuerB.keys.secretKey,
          issuanceRootMessage(issuerA.did, w.attestation.epoch, BigInt(w.attestation.root), BigInt(w.attestation.revRoot))
        ).toString("hex"),
      };
      record({
        id: "A6",
        title: "Honest v3 proof with a tampered, foreign, missing or re-encoded root attestation",
        finding: "v3 verifier checks (v); review setup-1 / verifier-3",
        kind: "attack",
        attempts: [
          await attempt("v3", "attestation epoch changed after signing", async (nonce) => ({
            ...(await honestV3("adult", nonce)),
            attestation: { ...w.attestation, epoch: w.attestation.epoch + 1 },
          })),
          await attempt("v3", "attestation omitted", async (nonce) => {
            const b = await honestV3("adult", nonce);
            return { input: b.input, issuerDid: b.issuerDid };
          }),
          await attempt("v3", "A's root signed by issuer B's key", async (nonce) => ({
            ...(await honestV3("adult", nonce)),
            attestation: bSigOnARoot,
          })),
          await attempt("v3", "issRoot re-encoded as hex in signal and attestation (canonical-signal check; the anchor comparison would also reject it)", async (nonce) => ({
            ...(await honestV3("adult", nonce)),
            mutate: (p) => {
              const hex = "0x" + BigInt(w.attestation.root).toString(16);
              p.publicSignals = [...p.publicSignals.slice(0, 5), hex];
              p.issuanceRoot = { ...w.attestation, root: hex };
            },
          })),
        ],
      });
    }

    // ------------------------------------------------ A7 DID squatting (review verifier-1)
    {
      // Issuer C announces its DID; the attacker registers that DID string with
      // ITS OWN key first; governance later accredits the DID string.
      const issuerC = await createIssuerV3();
      await ledger.registerDid(issuerC.did, attackerKeys.publicKey);
      await ledger.accreditIssuer(issuerC.did);
      const squatIkh = issuerKeyHash(poseidon, attackerKeys.publicKey);
      const attacker = await createWallet();
      const forgedId = randomBytes(32);
      const squatTree = await attackerTree([
        credentialLeaf(poseidon, { issuerKeyHash: squatIkh, credId: forgedId, holderCommit: attacker.holderCommit, claimAge: 42n }),
      ]);
      const squatRev = await RevocationTree.create();
      await ledger.publishRevRoot(issuerC.did, squatRev.root());
      const squatAtt: IssuanceRootAttestation = {
        issuerDid: issuerC.did,
        epoch: 1,
        root: squatTree.root().toString(),
        revRoot: squatRev.root().toString(),
        signature: dilithiumSign(attackerKeys.secretKey, issuanceRootMessage(issuerC.did, 1, squatTree.root(), squatRev.root())).toString("hex"),
      };
      await ledger.publishIssuanceRoot(issuerC.did, squatAtt);
      const squatNm = await squatRev.getNonMembershipProof(forgedId);
      record({
        id: "A7",
        title: "Attacker registers an accredited issuer's DID string with its own key first",
        finding: "review verifier-1",
        kind: "attack",
        attempts: [
          await attempt("v3", "self-consistent credential signed by the squatter's key under issuer C's DID", async (nonce) => ({
            input: v3Input({
              nonce,
              issuerKeyHash: squatIkh,
              issRoot: squatTree.root(),
              credId: forgedId,
              holderSecret: attacker.holderSecret,
              claimAge: 42n,
              leafIndex: "0",
              pathElements: squatTree.path(0).pathElements,
              nonMembership: squatNm,
            }),
            issuerDid: issuerC.did,
            attestation: squatAtt,
          })),
        ],
      });
    }

    // ------------------------------------------------ T1 trapdoor forgery (9.3)
    {
      const vk2 = JSON.parse(fs.readFileSync(VKEY_FILE, "utf8"));
      const vk3 = JSON.parse(fs.readFileSync(VKEY_FILE_V3, "utf8"));
      const BEACON = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
      const t2 = await deriveBeaconTrapdoor(vk2, BEACON, 10);
      const t3 = await deriveBeaconTrapdoor(vk3, BEACON, 10);
      trapdoorInfo = {
        v2: { matchesDelta: t2.matchesDelta, gammaIsGenerator: t2.gammaIsGenerator },
        v3: { matchesDelta: t3.matchesDelta, gammaIsGenerator: t3.gammaIsGenerator },
      };
      const forged = async (circuit: Circuit): Promise<Attempt> => {
        const verifier = verifierFor(circuit);
        const nonce = verifier.newSessionNonce();
        const domain = verifierDomainTag(poseidon, verifier.verifierId);
        const signals: PublicSignals = [
          ikh(issuerA).toString(),
          (await ledger.getRevRoot(issuerA.did)).toString(),
          policyHash(poseidon, PREDICATE_AGE_GTE, 18n).toString(),
          nonce.toString(),
          (circuit === "v2"
            ? stmtCodeForDomain(poseidon, domain)
            : stmtCodeForDomainV3(poseidon, domain)
          ).toString(),
          ...(circuit === "v3" ? [attA1.root] : []),
        ];
        const proof = await forgeProof(circuit === "v2" ? vk2 : vk3, circuit === "v2" ? t2.d : t3.d, signals);
        const decision = await verifier.verifyPresentation(
          { proof, publicSignals: signals, issuerDid: issuerA.did, ...(circuit === "v3" ? { issuanceRoot: attA1 } : {}) },
          POLICY_18
        );
        return {
          circuit,
          route: "proof built from the public-beacon trapdoor: no credential, no witness",
          outcome: decision.accepted ? "ACCEPTED" : "rejected by verifier",
          accepted: decision.accepted,
          ...failed(decision),
          reasons: decision.reasons,
          detail: `beacon-derived d matches the key's delta: ${circuit === "v2" ? t2.matchesDelta : t3.matchesDelta}`,
        };
      };
      record({
        id: "T1",
        title: "Groth16 proof forged from the setup trapdoor (no credential at all)",
        finding: "9.3",
        kind: "attack",
        attempts: [await forged("v2"), await forged("v3")],
      });
    }

    // ------------------------------------------- R1 regression on the v3 verifier
    {
      const verifierB = new Verifier(ledger, { circuit: "v3", verifierId: "pqid:verifier:other" });
      const nonce = v3Verifier.newSessionNonce();
      const hb = await honestV3("adult", nonce);
      const wt = await computeWitness(hb.input, V3_ARTIFACTS.wasm);
      const proved = await proveSnarkjsOnWitness(wt.wtnsFile, ZKEY_FILE_V3);
      fs.rmSync(wt.wtnsFile, { force: true });
      const pres: Presentation = {
        proof: proved.proof,
        publicSignals: proved.publicSignals,
        issuerDid: issuerA.did,
        issuanceRoot: hb.attestation,
      };
      const first = await v3Verifier.verifyPresentation(pres, POLICY_18);
      const replay = await v3Verifier.verifyPresentation(pres, POLICY_18);
      record({
        id: "C1",
        title: "First use of the presentation replayed in R1 is accepted",
        finding: "control",
        kind: "control",
        attempts: [
          {
            circuit: "v3",
            route: "honest presentation, first use",
            outcome: first.accepted ? "ACCEPTED" : "rejected by verifier",
            accepted: first.accepted,
            ...failed(first),
            reasons: first.reasons,
          },
        ],
      });
      record({
        id: "R1",
        title: "v3 keeps v2's replay, cross-verifier and policy protections",
        finding: "regression",
        kind: "attack",
        attempts: [
          {
            circuit: "v3",
            route: "replay of the accepted presentation above",
            outcome: replay.accepted ? "ACCEPTED" : "rejected by verifier",
            accepted: replay.accepted,
            ...failed(replay),
            reasons: replay.reasons,
          },
          await attempt(
            "v3",
            "proof bound to verifier A presented to verifier B",
            (n) => honestV3("adult", n),
            { verifier: verifierB }
          ),
          await attempt(
            "v3",
            "age >= 18 proof presented to a verifier requiring age >= 21",
            (n) => honestV3("adult", n),
            { policy: { type: "age_gte", threshold: 21 } }
          ),
        ],
      });
    }

    // ------------------------------------ KL1 relay (review critic-2), known limitation
    {
      // The attacker opens a session at the verifier and forwards the request
      // unchanged to a victim's honest wallet; the returned proof is valid for
      // THIS verifier, so it is accepted. Needs channel binding (e.g. the wallet
      // taking verifierId from the authenticated origin); same in v2.
      const adult = H("adult");
      record({
        id: "KL1",
        title: "Relay: an intermediary forwards a verifier's request to a victim's honest wallet",
        finding: "review critic-2 (same in v2)",
        kind: "known-limitation",
        attempts: [
          await attempt("v2", "victim's honest wallet answers the relayed request", async (nonce) => ({
            input: await buildProofInput({
              wallet: adult.wallet,
              vc: adult.vc,
              request: { policy: WALLET_POLICY_18, nonce, verifierId: v2Verifier.verifierId },
              pkIssuer: issuerA.keys.publicKey,
              revRoot: currentRevRoot(issuerA),
              nonMembership: await nm(issuerA, Buffer.from(adult.vc.credID, "hex")),
            }),
            issuerDid: issuerA.did,
          })),
          await attempt("v3", "victim's honest wallet answers the relayed request", (nonce) => honestV3("adult", nonce)),
        ],
      });
    }

    // -------------------------- PV privacy: identical views, no covert tags (review privacy-*)
    {
      const names = ["adult", "victim", "filler0", "filler1"];
      const views: Record<Circuit, string[]> = { v2: [], v3: [] };
      const accepted: Attempt[] = [];
      for (const name of names) {
        const h = H(name);
        accepted.push(
          await attempt("v2", `${name} presents`, async (nonce) => ({
            input: await buildProofInput({
              wallet: h.wallet,
              vc: h.vc,
              request: { policy: WALLET_POLICY_18, nonce, verifierId: v2Verifier.verifierId },
              pkIssuer: issuerA.keys.publicKey,
              revRoot: currentRevRoot(issuerA),
              nonMembership: await nm(issuerA, Buffer.from(h.vc.credID, "hex")),
            }),
            issuerDid: issuerA.did,
          }), { capture: (p) => views.v2.push(verifierView(p)) })
        );
        accepted.push(
          await attempt("v3", `${name} presents`, (nonce) => honestV3(name, nonce), {
            capture: (p) => views.v3.push(verifierView(p)),
          })
        );
      }
      const distinct = { v2: new Set(views.v2).size, v3: new Set(views.v3).size };
      viewCheck = {
        holders: names.length,
        distinctVerifierViews: distinct,
        allAccepted: accepted.every((a) => a.accepted),
        pass: distinct.v3 === 1 && accepted.every((a) => a.accepted),
        note: "view = public signals except the nonce, plus issuerDid and the attestation; proofs are re-randomized",
      };
      console.log(`[suite] PV1 distinct verifier views across ${names.length} holders: v2=${distinct.v2} v3=${distinct.v3}`);

      // Issuer-side tagging attempts. The defence is the holder's OWN wallet: a
      // colluding verifier would read a tag even if honest verifiers rejected
      // it, so the property is that the honest wallet never emits one.
      const w = witnessOf("adult");
      const resigned = dilithiumSign(
        issuerA.keys.secretKey,
        issuanceRootMessage(issuerA.did, w.attestation.epoch, BigInt(w.attestation.root), BigInt(w.attestation.revRoot))
      ).toString("hex");
      const refused = (a: Attempt): Attempt => ({ ...a, pass: a.outcome === "no proof: honest component refused" });
      record({
        id: "PV2",
        title: "Issuer tags one holder with re-signed signature bytes for the current root",
        finding: "review privacy-3; round-2 circuit2-1",
        kind: "privacy",
        attempts: [
          resigned === w.attestation.signature
            ? { circuit: "v3", route: "re-signed variant", outcome: "invalid test", accepted: false, detail: "ML-DSA signing was deterministic; no variant exists", pass: false }
            : refused(await attempt("v3", "holder's wallet is served a valid but differently-encoded signature of the current root", (nonce) =>
                honestV3("adult", nonce, { witness: { path: w.path, attestation: { ...w.attestation, signature: resigned } } }),
              { expectRefusal: /signature bytes that differ from the anchored/ })),
        ],
      });
      const unanchoredTree = await attackerTree([1n, 2n]);
      record({
        id: "PV4",
        title: "Issuer tags one holder through the attestation object or an unanchored root",
        finding: "round-2 verifier2-2 / privacy2-1 / circuit2-1",
        kind: "privacy",
        attempts: [
          refused(await attempt("v3", "attestation served with an extra per-holder field", (nonce) =>
            honestV3("adult", nonce, { witness: { path: w.path, attestation: { ...w.attestation, tag: "holder-adult" } as unknown as IssuanceRootAttestation } }),
          { expectRefusal: /attestation must have exactly/ })),
          refused(await attempt("v3", "holder served a root that is not the on-chain anchor", (nonce) =>
            honestV3("adult", nonce, {
              witness: {
                path: { ...unanchoredTree.path(0), root: unanchoredTree.root().toString() },
                attestation: { ...w.attestation, root: unanchoredTree.root().toString() },
              },
            }),
          { expectRefusal: /not its current on-chain anchor/ })),
        ],
      });
      // PV5: key order cannot tag either — the wallet presents a fresh canonical object
      const permuted = { signature: w.attestation.signature, revRoot: w.attestation.revRoot, root: w.attestation.root, epoch: w.attestation.epoch, issuerDid: w.attestation.issuerDid };
      let permutedView = "";
      const pv5 = await attempt("v3", "attestation served with permuted key order", (nonce) =>
        honestV3("adult", nonce, { witness: { path: w.path, attestation: permuted as unknown as IssuanceRootAttestation } }),
      { capture: (p) => { permutedView = verifierView(p); } });
      record({
        id: "PV5",
        title: "Key order of the served attestation does not reach the verifier",
        finding: "round-2 verifier2-2",
        kind: "privacy",
        attempts: [{ ...pv5, pass: pv5.accepted && permutedView === views.v3[0], detail: `view identical to other holders': ${permutedView === views.v3[0]}` }],
      });
      // PV6: an issuer that re-anchors right before serving one holder would
      // give that holder its own epoch; the registry refuses a second anchor
      // within the interval.
      issuerA.tree.insert(credentialLeaf(poseidon, { issuerKeyHash: ikh(issuerA), credId: randomBytes(32), holderCommit: 1n, claimAge: 1n }));
      const rushed = signIssuanceRoot(issuerA, currentRevRoot(issuerA));
      let registryRefused = false;
      let refusal = "";
      try {
        await ledger.publishIssuanceRoot(issuerA.did, rushed);
      } catch (e) {
        registryRefused = /too soon/.test((e as Error).message);
        refusal = (e as Error).message.split("\n")[0] ?? "";
      }
      record({
        id: "PV6",
        title: "Issuer re-anchors immediately to give one holder a fresh epoch",
        finding: "round-2 privacy2-3",
        kind: "privacy",
        attempts: [
          {
            circuit: "v3",
            route: `anchor epoch ${rushed.epoch} submitted right after epoch ${rushed.epoch - 1}`,
            outcome: registryRefused ? "rejected by the anchor registry" : "ACCEPTED",
            accepted: !registryRefused,
            detail: refusal.slice(0, 160),
            pass: registryRefused,
          },
        ],
      });

      // PV7: per-holder REVOCATION roots (round 3). The revocation root is part
      // of the anchored epoch statement, so a per-holder revRoot needs a new
      // epoch (refused by the cadence), and an opening against a revRoot that
      // is not anchored is refused by the holder's wallet.
      const perHolderRev = await revTree(issuerA).snapshot();
      await perHolderRev.insert(randomBytes(32)); // a dummy "revocation" only for this holder
      const tagged = signIssuanceRoot(issuerA, perHolderRev.root());
      let revRefused = false;
      try {
        await ledger.publishIssuanceRoot(issuerA.did, tagged);
      } catch (e) {
        revRefused = /too soon/.test((e as Error).message);
      }
      const adultId = Buffer.from(H("adult").vc.credID, "hex");
      const privateOpening = refused(
        await attempt("v3", "holder's wallet is served an opening against a per-holder revRoot that is not anchored", async (nonce) =>
          honestV3("adult", nonce, { nonMembership: await perHolderRev.getNonMembershipProof(adultId) }),
        { expectRefusal: /not against the anchored revRoot/ })
      );
      record({
        id: "PV7",
        title: "Issuer tags one holder with its own revocation root",
        finding: "round-3 walletpriv-1 / evidence3-1",
        kind: "privacy",
        attempts: [
          {
            circuit: "v3",
            route: "anchor a per-holder revRoot as the next epoch right away",
            outcome: revRefused ? "rejected by the anchor registry" : "ACCEPTED",
            accepted: !revRefused,
            pass: revRefused,
          },
          privateOpening,
        ],
      });

      // PV8: an issuer-created, unaccredited DID used for just one holder
      const issuerX = await createIssuerV3();
      await ledger.registerDid(issuerX.did, issuerX.keys.publicKey); // registered, never accredited
      await addIssuerRevocation(issuerX, []);
      const wx = await createWallet();
      const { vc: vcx } = await issueCredentialV3({ issuer: issuerX, subjectDid: wx.did, claims: { age: 42 }, holderCommit: wx.holderCommit });
      holders["taggedByDid"] = { wallet: wx, vc: vcx, issuer: issuerX };
      await signAndAnchor(issuerX);
      record({
        id: "PV8",
        title: "Issuer issues one holder's credential from its own unaccredited per-holder DID",
        finding: "round-3 walletpriv-2",
        kind: "privacy",
        attempts: [
          refused(await attempt("v3", "holder's wallet checks the issuer's accreditation before presenting", (nonce) =>
            honestV3("taggedByDid", nonce),
          { expectRefusal: /not an accredited, active issuer/ })),
        ],
      });
    }

    // ----------------------- A3 revocation bypass (changes A's revRoot; runs late)
    {
      const rv = H("revokee");
      const rvId = Buffer.from(rv.vc.credID, "hex");
      const staleOpening = await nm(issuerA, rvId);
      const staleRoot = currentRevRoot(issuerA);
      await revTree(issuerA).insert(rvId); // Algorithm 4: revoke (working set)
      await signAndAnchor(issuerA); // takes effect with the next epoch statement
      const rvW = witnessOf("revokee"); // the revokee's leaf is still issued; path to the new epoch
      const currentRoot = currentRevRoot(issuerA);
      const staleWithCurrent = { ...staleOpening, root: currentRoot.toString() };

      // hand-built openings for the REVOKED key (the attacker rebuilds the public revoked set)
      const inc = await revokedInclusion([...fixtureRevokedCredIds(), rvId], rvId);
      if (inc.root !== currentRoot) throw new Error("rebuilt revoked set does not match the on-chain root");
      const forgedOld0 = await forgedIsOld0Opening(inc);
      const sameKey = sameKeyOpening(inc);
      const truncated = truncatedEmptyOpening(inc);
      const attackerGen = compileV3Without(BOOLEANITY_LINE);
      attackerBuild = { sameWireLayout: attackerGen.sameWireLayout };

      // 9.2: a fresh credID that is not in the revoked set
      const freshId = randomBytes(32);
      const freshNm = await nm(issuerA, freshId);
      const freshLeaf = credentialLeaf(poseidon, {
        issuerKeyHash: ikh(issuerA),
        credId: freshId,
        holderCommit: rv.wallet.holderCommit,
        claimAge: 30n,
      });
      const ownTree = await attackerTree([freshLeaf]);

      const rvV3 = (nonce: bigint, p: {
        credId: Uint8Array;
        nonMembership: NonMembershipProof;
        revRoot?: bigint;
        issRoot: bigint;
        path: { leafIndex: string; pathElements: string[] };
      }) =>
        v3Input({
          nonce,
          issuerKeyHash: ikh(issuerA),
          issRoot: p.issRoot,
          credId: p.credId,
          holderSecret: rv.wallet.holderSecret,
          claimAge: 30n,
          leafIndex: p.path.leafIndex,
          pathElements: p.path.pathElements,
          nonMembership: p.nonMembership,
          ...(p.revRoot === undefined ? {} : { revRoot: p.revRoot }),
        });
      const rvV2 = (nonce: bigint, credId: Uint8Array, nonMembership: NonMembershipProof, revRoot?: bigint) =>
        v2Input({
          nonce,
          issuer: issuerA,
          credId,
          holderSecret: rv.wallet.holderSecret,
          holderCommit: rv.wallet.holderCommit,
          claimAge: 30n,
          nonMembership,
          ...(revRoot === undefined ? {} : { revRoot }),
        });
      const issRootA = BigInt(rvW.attestation.root);
      const withRv = (nonce: bigint, nonMembership: NonMembershipProof, revRoot?: bigint) => ({
        input: rvV3(nonce, { credId: rvId, nonMembership, issRoot: issRootA, path: rvW.path, ...(revRoot === undefined ? {} : { revRoot }) }),
        issuerDid: issuerA.did,
        attestation: rvW.attestation,
      });

      try {
        record({
          id: "B0",
          title: "Revoked holder's honest wallet asks for a non-membership opening",
          finding: "baseline (attacker-controlled library; not a defence)",
          kind: "baseline",
          attempts: [
            await attempt("v2", "honest revocation service refuses", async (nonce) => ({
              input: rvV2(nonce, rvId, await nm(issuerA, rvId)),
              issuerDid: issuerA.did,
            }), { expectRefusal: /in the revoked set/ }),
            await attempt("v3", "honest revocation service refuses", async (nonce) => withRv(nonce, await nm(issuerA, rvId)), { expectRefusal: /in the revoked set/ }),
          ],
        });
        record({
          id: "A3",
          title: "Revoked holder tries to keep authenticating",
          finding: "9.2 (D) + paper A.5 (B, C) + v3 review circuit-1/2 (E, F, G)",
          kind: "attack",
          attempts: [
            await attempt("v2", "B: stale opening against the current root", async (nonce) => ({
              input: rvV2(nonce, rvId, staleWithCurrent, currentRoot),
              issuerDid: issuerA.did,
            })),
            await attempt("v2", "C: stale opening and stale root", async (nonce) => ({
              input: rvV2(nonce, rvId, staleOpening, staleRoot),
              issuerDid: issuerA.did,
            })),
            await attempt("v2", "D: fresh credID not in the revoked set (9.2)", async (nonce) => ({
              input: rvV2(nonce, freshId, freshNm),
              issuerDid: issuerA.did,
            })),
            await attempt("v2", "E: same revoked credID, non-boolean smtIsOld0 (forged non-membership)", async (nonce) => ({
              input: rvV2(nonce, rvId, forgedOld0, currentRoot),
              issuerDid: issuerA.did,
            })),
            await attempt("v2", "F: isOld0 = 0 with oldKey = the revoked key itself", async (nonce) => ({
              input: rvV2(nonce, rvId, sameKey, currentRoot),
              issuerDid: issuerA.did,
            })),
            await attempt("v2", "G: isOld0 = 1 claiming an empty slot above the revoked leaf", async (nonce) => ({
              input: rvV2(nonce, rvId, truncated, currentRoot),
              issuerDid: issuerA.did,
            })),
            await attempt("v3", "B: stale opening against the current root", async (nonce) => withRv(nonce, staleWithCurrent, currentRoot)),
            await attempt("v3", "C: stale opening and stale root", async (nonce) => withRv(nonce, staleOpening, staleRoot)),
            await attempt("v3", "D1: fresh credID with the revoked credential's genuine path", async (nonce) => ({
              input: rvV3(nonce, { credId: freshId, nonMembership: freshNm, issRoot: issRootA, path: rvW.path }),
              issuerDid: issuerA.did,
              attestation: rvW.attestation,
            })),
            await attempt("v3", "D2: fresh credID in an attacker-built tree; A's genuine attestation", async (nonce) => ({
              input: rvV3(nonce, { credId: freshId, nonMembership: freshNm, issRoot: ownTree.root(), path: ownTree.path(0) }),
              issuerDid: issuerA.did,
              attestation: rvW.attestation,
            })),
            await attempt("v3", "D3: fresh credID in an attacker-built tree; issRoot wire swapped", async (nonce) => ({
              input: rvV3(nonce, { credId: freshId, nonMembership: freshNm, issRoot: ownTree.root(), path: ownTree.path(0) }),
              issuerDid: issuerA.did,
              attestation: rvW.attestation,
              tamper: { wire: ISS_ROOT_WIRE, value: issRootA },
            })),
            await attempt("v3", "E1: non-boolean smtIsOld0 through the reference witness generator", async (nonce) => withRv(nonce, forgedOld0, currentRoot)),
            attackerGen.sameWireLayout
              ? await attempt("v3", "E2: non-boolean smtIsOld0 through the attacker's own witness generator (circuit minus the booleanity line)", async (nonce) => ({
                  ...withRv(nonce, forgedOld0, currentRoot),
                  wasm: attackerGen.wasm,
                }))
              : { circuit: "v3", route: "E2: attacker witness generator", outcome: "invalid test", accepted: false, detail: "attacker build's wire layout differs from the committed v3 build" },
            await attempt("v3", "F: isOld0 = 0 with oldKey = the revoked key itself", async (nonce) => withRv(nonce, sameKey, currentRoot)),
            await attempt("v3", "G: isOld0 = 1 claiming an empty slot above the revoked leaf", async (nonce) => withRv(nonce, truncated, currentRoot)),
          ],
        });
      } finally {
        attackerGen.cleanup();
      }
    }

    // ------------- C2 / B1 / PV3: batching, signing and anchoring windows
    {
      await issueTo("late", issuerA, 27);
      const during = await attempt("v3", "adult presents while a newer leaf is still unsigned", (n) => honestV3("adult", n));
      const lateEarly = await attempt("v3", "late holder asks for a path before its leaf is anchored", (n) => honestV3("late", n), { expectRefusal: /not yet covered by an anchored issuance root/ });
      const pendingRev = await revTree(issuerA).snapshot();
      const pending = signIssuanceRoot(issuerA, pendingRev.root()); // signed, not anchored yet
      const duringSigned = await attempt("v3", `adult presents while epoch ${pending.epoch} is signed but not anchored`, (n) => honestV3("adult", n));
      await ledger.devAdvanceTime(ANCHOR_INTERVAL);
      await ledger.publishIssuanceRoot(issuerA.did, pending);
      await ledger.publishRevRoot(issuerA.did, pendingRev.root());
      syncIssuanceAnchor(issuerA, await ledger.getIssuanceRoot(issuerA.did));
      anchoredRev.set(issuerA.did, pendingRev);
      const attA2 = pending;
      record({
        id: "C2",
        title: "Honest holders keep presenting through open batches and signing windows; refreshed paths work",
        finding: "control (reviews lifecycle-2, lifecycle2-2)",
        kind: "control",
        attempts: [
          during,
          duringSigned,
          await attempt("v3", `adult with a path refreshed to epoch ${attA2.epoch}`, (n) => honestV3("adult", n)),
          await attempt("v3", `late holder with its first path (epoch ${attA2.epoch})`, (n) => honestV3("late", n)),
        ],
      });
      record({
        id: "B1",
        title: "A newly issued holder gets no path until its leaf is under an anchored root",
        finding: "baseline",
        kind: "baseline",
        attempts: [lateEarly],
      });
      const stale = await attempt(
        "v3",
        `adult's wallet is given its epoch-${adultAtEpoch1.attestation.epoch} path after epoch ${attA2.epoch} was anchored`,
        (nonce) => honestV3("adult", nonce, { witness: adultAtEpoch1 }),
        { expectRefusal: /not its current on-chain anchor/ }
      );
      record({
        id: "PV3",
        title: "Holder offered a path to an older root after a newer one is anchored",
        finding: "reviews privacy-1 / lifecycle-1; round-2 privacy2-2",
        kind: "privacy",
        attempts: [{ ...stale, pass: stale.outcome === "no proof: honest component refused" }],
      });

      // A8: an adversary who can write issuer A's on-chain anchor (an ECDSA
      // forger, review 9.4) anchors its own tree and signature. The ML-DSA
      // check is what still stops it. Runs last: it overwrites A's anchor.
      const attacker = await createWallet();
      const forgedId = randomBytes(32);
      const evilTree = await attackerTree([
        credentialLeaf(poseidon, { issuerKeyHash: ikh(issuerA), credId: forgedId, holderCommit: attacker.holderCommit, claimAge: 42n }),
      ]);
      const evilEpoch = (await ledger.getIssuanceRoot(issuerA.did)).epoch + 1;
      const evilAtt: IssuanceRootAttestation = {
        issuerDid: issuerA.did,
        epoch: evilEpoch,
        root: evilTree.root().toString(),
        revRoot: currentRevRoot(issuerA).toString(),
        signature: dilithiumSign(
          attackerKeys.secretKey,
          issuanceRootMessage(issuerA.did, evilEpoch, evilTree.root(), currentRevRoot(issuerA))
        ).toString("hex"),
      };
      await ledger.devAdvanceTime(ANCHOR_INTERVAL);
      await ledger.publishIssuanceRoot(issuerA.did, evilAtt);
      const evilNm = await nm(issuerA, forgedId);
      record({
        id: "A8",
        title: "Adversary that can write issuer A's on-chain anchor publishes its own root and signature",
        finding: "review 9.4 (ECDSA-authorized registry writes)",
        kind: "attack",
        attempts: [
          await attempt("v3", "forged leaf under the adversary-anchored root and adversary signature", async (nonce) => ({
            input: v3Input({
              nonce,
              issuerKeyHash: ikh(issuerA),
              issRoot: evilTree.root(),
              credId: forgedId,
              holderSecret: attacker.holderSecret,
              claimAge: 42n,
              leafIndex: "0",
              pathElements: evilTree.path(0).pathElements,
              nonMembership: evilNm,
            }),
            issuerDid: issuerA.did,
            attestation: evilAtt,
          })),
        ],
      });
    }

    ledger.destroy();
  } finally {
    anvil.stop();
  }

  // ------------------------------------------------------------------ verdict
  const byKind = (k: Kind) => attacks.filter((a) => a.kind === k).flatMap((a) => a.attempts);
  const controls = byKind("control");
  const attackRoutes = byKind("attack");
  const v3AttackRoutes = attackRoutes.filter((a) => a.circuit === "v3");
  const v2AttackRoutes = attackRoutes.filter((a) => a.circuit === "v2");
  const privacyRoutes = byKind("privacy");
  const invalid = attacks.flatMap((a) => a.attempts).filter((a) => a.outcome === "invalid test");
  const controlsPass = controls.every((a) => a.accepted);
  const v3Accepted = v3AttackRoutes.filter((a) => a.accepted);
  const v2Accepted = v2AttackRoutes.filter((a) => a.accepted);
  const privacyPass =
    privacyRoutes.length > 0 &&
    privacyRoutes.every((a) => a.pass === true) &&
    (viewCheck as { pass?: boolean } | null)?.pass === true;
  const onlyProof = (a: Attempt) => a.failedChecks?.length === 1 && a.failedChecks[0] === "proofValid";
  const stoppedBy = (routes: Attempt[]) => ({
    verifierCheck: routes.filter((a) => a.outcome === "rejected by verifier" && !onlyProof(a)).length,
    proofSystem: routes.filter(
      (a) => a.outcome === "proof does not verify (R1CS unsatisfied)" || (a.outcome === "rejected by verifier" && onlyProof(a))
    ).length,
    referenceWitnessGeneratorOnly: routes.filter((a) => a.outcome === "no proof: witness generator refused").length,
  });
  const pass =
    controlsPass && v3Accepted.length === 0 && privacyPass && invalid.length === 0 &&
    attackerBuild?.sameWireLayout === true;

  const out = {
    schema: "pqid/v3-security-suite/v2",
    label: "[M] v2 vs v3 attack suite (same host, same chain, same issuers)",
    pass,
    summary: {
      controlsAccepted: Object.fromEntries(
        (["v2", "v3"] as const).map((c) => {
          const cs = controls.filter((a) => a.circuit === c);
          return [c, `${cs.filter((a) => a.accepted).length}/${cs.length}`];
        })
      ),
      v3AttackRoutes: v3AttackRoutes.length,
      v3AttackRoutesAccepted: v3Accepted.length,
      v3AttackRoutesStoppedBy: stoppedBy(v3AttackRoutes),
      v2AttackRoutes: v2AttackRoutes.length,
      v2AttackRoutesAccepted: v2Accepted.length,
      v2GapsReproduced: [
        ...new Set(
          attacks
            .filter((a) => a.kind === "attack" && a.attempts.some((t) => t.circuit === "v2" && t.accepted))
            .map((a) => a.id)
        ),
      ],
      privacyChecksPass: privacyPass,
      knownLimitationsAccepted: byKind("known-limitation").filter((a) => a.accepted).map((a) => `${a.circuit}: ${a.route}`),
      invalidTests: invalid.length,
    },
    privacy: { verifierViews: viewCheck },
    trapdoor: trapdoorInfo,
    attackerWitnessGenerator: attackerBuild,
    artifacts: {
      v2: { zkeySha256: sha256File(ZKEY_FILE), vkeySha256: sha256File(VKEY_FILE), r1csSha256: sha256File(R1CS_FILE) },
      v3: { zkeySha256: sha256File(ZKEY_FILE_V3), vkeySha256: sha256File(VKEY_FILE_V3), r1csSha256: sha256File(R1CS_FILE_V3) },
    },
    harnessSha256: sha256File(fileURLToPath(import.meta.url)),
    mlDsa: mlDsaImplementation(),
    attacks,
    host: hostMeta(),
  };
  fs.mkdirSync(RESULTS_DIR_V3, { recursive: true });
  const outFile = path.join(RESULTS_DIR_V3, "security_suite.json");
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2));

  console.log("\n[suite] ================================================================");
  console.log(`[suite] controls accepted:         ${JSON.stringify(out.summary.controlsAccepted)}`);
  console.log(`[suite] v2 attack routes accepted: ${v2Accepted.length}/${v2AttackRoutes.length}  (gaps: ${out.summary.v2GapsReproduced.join(", ")})`);
  console.log(`[suite] v3 attack routes accepted: ${v3Accepted.length}/${v3AttackRoutes.length}`);
  console.log(`[suite] privacy checks pass:       ${privacyPass}`);
  console.log(`[suite] known limitations (accepted by design): ${out.summary.knownLimitationsAccepted.length}`);
  console.log(`[suite] ${pass ? "PASS" : "FAIL"} -> ${path.relative(REPO_ROOT, outFile)}`);
  process.exit(pass ? 0 : 1);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
