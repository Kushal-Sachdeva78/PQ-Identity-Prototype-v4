import fs from "node:fs";
import { getPoseidon, issuerKeyHash as ikh } from "@pqid/common/encoding";
import { IssuanceTree } from "@pqid/issuer";
import { World } from "@pqid/v4/world";
import { walletOpenSession, walletSealReply, type ProofRequestV4, type SessionReplyV4 } from "@pqid/v4/session";
import { buildPresentationInput, type HolderWalletV4, WalletRefusal } from "@pqid/v4/wallet";
import { VerifierV4, type PresentationV4, type VerifyDecisionV4 } from "@pqid/v4/verifier";
import { proveV4 } from "@pqid/v4/prove";
import { R1CS_V4, SYM_V4, ZKEY_V4, VKEY_V4, WASM_V4, KEY_LABEL_V4 } from "@pqid/v4/paths";
import {
  computeCredIdV4,
  issuanceWitnessV4,
  revocationWitnessV4,
  type IssuerV4,
  type VerifiableCredentialV4,
  type EpochStatementV4,
} from "@pqid/v4/issuer";
import { credentialLeafV4, credTypeField } from "@pqid/v4/encoding";
import { attackerProve, type R1csReport } from "./r1cs_tools.ts";

/**
 * Shared machinery for the v4 security suite (docs/v4/ROUTES.md). The attacker here is a
 * malicious wallet: it opens the ML-KEM session itself with the verifier's registered key,
 * builds any witness with its own generator, and seals any presentation.
 */

export type Layer = "circuit" | "verifier" | "wallet" | "wallet-enforced" | "registry" | "governance" | "transport" | "accepted";
export type Kind = "control" | "attack" | "privacy" | "baseline" | "known-limitation";

export interface Attempt {
  route: string;
  attacker: string;
  goal: string;
  expect: { layer: Layer; any: string[] };
  accepted: boolean;
  stoppedBy: { layer: Layer; checks: string[] };
  r1cs?: { violated: number; byGroup: Record<string, number> };
  proofVerifies?: boolean;
  /** true iff the route ended where the catalogue says it must (fail closed otherwise). */
  valid: boolean;
  detail?: string;
}

export interface RouteRecord {
  id: string;
  title: string;
  kind: Kind;
  attempts: Attempt[];
}

export class Recorder {
  readonly records: RouteRecord[] = [];
  private cur: RouteRecord | null = null;

  begin(id: string, title: string, kind: Kind): void {
    this.cur = { id, title, kind, attempts: [] };
    this.records.push(this.cur);
    console.log(`[suite] ${id} (${kind}) ${title}`);
  }

  push(a: Attempt): void {
    if (!this.cur) throw new Error("no open record");
    this.cur.attempts.push(a);
    const tag = a.valid ? "ok " : "INVALID";
    console.log(`   ${tag} ${a.route} -> ${a.accepted ? "ACCEPTED" : `stopped: ${a.stoppedBy.layer} [${a.stoppedBy.checks.join(", ")}]`}`);
  }

  /** Run one route; any unexpected exception makes the attempt invalid (fail closed). */
  async route(
    route: string,
    meta: { attacker: string; goal: string; expect: { layer: Layer; any: string[] } },
    fn: () => Promise<{ accepted: boolean; stoppedBy: { layer: Layer; checks: string[] }; r1cs?: R1csReport; proofVerifies?: boolean; detail?: string }>
  ): Promise<void> {
    try {
      const r = await fn();
      const kind = this.cur?.kind;
      let valid: boolean;
      if (kind === "control") {
        valid = r.accepted;
      } else if (kind === "known-limitation") {
        valid = meta.expect.layer === "accepted" ? r.accepted : !r.accepted && r.stoppedBy.layer === meta.expect.layer;
      } else {
        valid =
          !r.accepted &&
          r.stoppedBy.layer === meta.expect.layer &&
          (meta.expect.any.length === 0 || meta.expect.any.some((c) => r.stoppedBy.checks.includes(c)));
        if (meta.expect.layer === "circuit") valid = valid && r.proofVerifies === false;
      }
      this.push({
        route,
        attacker: meta.attacker,
        goal: meta.goal,
        expect: meta.expect,
        accepted: r.accepted,
        stoppedBy: r.stoppedBy,
        ...(r.r1cs ? { r1cs: { violated: r.r1cs.violated, byGroup: r.r1cs.byGroup } } : {}),
        ...(r.proofVerifies !== undefined ? { proofVerifies: r.proofVerifies } : {}),
        valid,
        ...(r.detail ? { detail: r.detail } : {}),
      });
    } catch (e) {
      this.push({
        route,
        attacker: meta.attacker,
        goal: meta.goal,
        expect: meta.expect,
        accepted: false,
        stoppedBy: { layer: "accepted", checks: [] },
        valid: false,
        detail: `unexpected exception: ${(e as Error).message}`.slice(0, 600),
      });
    }
  }
}

/** Outcome of a verifier decision in suite terms. */
export function fromDecision(d: VerifyDecisionV4) {
  return {
    accepted: d.accepted,
    stoppedBy: { layer: (d.accepted ? "accepted" : "verifier") as Layer, checks: d.failedChecks as string[] },
    detail: d.reasons.join("; ").slice(0, 600),
  };
}

/** Outcome of an honest-wallet refusal. */
export function fromRefusal(e: unknown, layer: Layer = "wallet") {
  if (!(e instanceof WalletRefusal)) throw e;
  return { accepted: false, stoppedBy: { layer, checks: [e.check] }, detail: e.message };
}

// ---------------------------------------------------------------- artifacts under test
export interface SuiteArtifacts {
  r1cs: string;
  sym: string;
  zkey: string;
  wasm: string;
  vkey: unknown;
  /** Circuit source the attacker's generator is built from (real or mutant). */
  src?: string;
  attackerDir?: string;
  keyLabel: string;
}

let current: SuiteArtifacts | null = null;
/** Mutation runs only: fills the free inputs a replacement mutant adds. */
let mutantFiller: ((input: Record<string, string | string[]>, held: HeldData) => void) | null = null;

export function setSuiteArtifacts(a: SuiteArtifacts | null, filler: typeof mutantFiller = null): void {
  current = a;
  mutantFiller = filler;
}

export function realArtifacts(): SuiteArtifacts {
  return current ?? { r1cs: R1CS_V4, sym: SYM_V4, zkey: ZKEY_V4, wasm: WASM_V4, vkey: JSON.parse(fs.readFileSync(VKEY_V4, "utf8")) as unknown, keyLabel: KEY_LABEL_V4 };
}

// ---------------------------------------------------------------- malicious wallet
export interface HeldData {
  vc: VerifiableCredentialV4;
  issuer: IssuerV4;
  holderSecret: bigint;
}

export function heldOf(holder: HolderWalletV4, issuer: IssuerV4, vc: VerifiableCredentialV4): HeldData {
  return { vc, issuer, holderSecret: holder.holderSecret };
}

/** A malicious wallet opens the session with the verifier's REGISTERED key (as it must to be read). */
export async function attackerSession(world: World, verifier: VerifierV4, request: ProofRequestV4) {
  const kem = await world.ledger.latestKemKey(verifier.did, verifier.opts.identity.controller);
  if (!kem) throw new Error("verifier has no KEM key");
  return walletOpenSession(request, kem.kemPk);
}

export interface Forge {
  /** Replace what the issuer's services would give (path, statement, revocation witness). */
  path?: { leafIndex: string; pathElements: string[]; root: string };
  statement?: EpochStatementV4;
  rev?: { lowIndex: string; lowValue: string; lowNext: string; lowPath: string[]; root: string };
  credential?: Partial<VerifiableCredentialV4["credential"]>;
  credId?: Buffer;
  holderSecret?: bigint;
  override?: Parameters<typeof buildPresentationInput>[0]["override"];
  /** Edit the circuit input directly (attacker-chosen wire inputs). */
  input?: (input: Record<string, string | string[]>) => void;
  /** Edit the presentation after proving. */
  presentation?: (p: PresentationV4) => void;
  /** Use this session nonce instead of the transcript-derived one. */
  nonce?: bigint;
  issuerDid?: string;
  issuerController?: string;
}

/** Build the malicious wallet's circuit input for a request. */
export async function forgedInput(world: World, request: ProofRequestV4, held: HeldData, nonce: bigint, f: Forge = {}) {
  const cred = { ...held.vc.credential, ...(f.credential ?? {}) };
  const credId = f.credId ?? Buffer.from(held.vc.credID, "hex");
  let path = f.path;
  let statement = f.statement;
  let rev = f.rev;
  if (!path || !statement) {
    try {
      const s = issuanceWitnessV4(held.issuer, held.vc.credID);
      path = path ?? s.path;
      statement = statement ?? s.statement;
    } catch {
      /* forged credential: the caller must supply path and statement */
    }
  }
  if (!rev) {
    try {
      rev = revocationWitnessV4(held.issuer, held.vc.credID);
    } catch {
      /* revoked: caller supplies rev */
    }
  }
  if (!path || !statement || !rev) throw new Error("forge: missing path, statement or revocation witness");
  const input = await buildPresentationInput({
    request,
    nonce,
    issuerPk: held.issuer.pk,
    credId,
    holderSecret: f.holderSecret ?? held.holderSecret,
    credential: cred,
    statement,
    path,
    rev,
    override: f.override,
  });
  f.input?.(input);
  mutantFiller?.(input, { ...held, holderSecret: f.holderSecret ?? held.holderSecret });
  return { input, statement };
}

/**
 * Circuit route: the attacker's own generator produces the witness, the real R1CS is
 * checked, the real proving key proves it, and the presentation goes to the verifier.
 */
export async function circuitRoute(world: World, verifier: VerifierV4, request: ProofRequestV4, held: HeldData, f: Forge = {}) {
  const session = await attackerSession(world, verifier, request);
  const { input, statement } = await forgedInput(world, request, held, f.nonce ?? session.nonce, f);
  const res = await attackerProve(input, realArtifacts());
  const presentation: PresentationV4 = {
    proof: res.proof as PresentationV4["proof"],
    publicSignals: res.publicSignals,
    issuerDid: f.issuerDid ?? held.vc.credential.issuer,
    issuerController: f.issuerController ?? held.vc.credential.issuerController,
    epochStatement: { ...statement },
  };
  f.presentation?.(presentation);
  const decision = await verifier.verifyReply(walletSealReply(session, presentation));
  if (decision.accepted) return { ...fromDecision(decision), r1cs: res.r1cs, proofVerifies: res.proofVerifies };
  const groups = Object.keys(res.r1cs.byGroup);
  return {
    accepted: false,
    stoppedBy: { layer: (res.r1cs.satisfied ? "verifier" : "circuit") as Layer, checks: res.r1cs.satisfied ? decision.failedChecks : groups },
    r1cs: res.r1cs,
    proofVerifies: res.proofVerifies,
    detail: `verifier failedChecks=[${decision.failedChecks.join(",")}]`,
  };
}

/**
 * Verifier route: a VALID proof (R1CS satisfied, reference generator used as a tool) with
 * attacker-chosen public data or presentation edits; the verifier must stop it by a check.
 */
export async function verifierRoute(world: World, verifier: VerifierV4, request: ProofRequestV4, held: HeldData, f: Forge = {}) {
  const session = await attackerSession(world, verifier, request);
  const { input, statement } = await forgedInput(world, request, held, f.nonce ?? session.nonce, f);
  const a = realArtifacts();
  const proved = await proveV4(input, "snarkjs", { wasm: a.wasm, zkey: a.zkey, keyLabel: a.keyLabel });
  const presentation: PresentationV4 = {
    proof: proved.proof,
    publicSignals: proved.publicSignals,
    issuerDid: f.issuerDid ?? held.vc.credential.issuer,
    issuerController: f.issuerController ?? held.vc.credential.issuerController,
    epochStatement: { ...statement },
  };
  f.presentation?.(presentation);
  const reply = walletSealReply(session, presentation);
  return { reply, presentation, decision: await verifier.verifyReply(reply) };
}

/** Honest presentation through the honest wallet. */
export async function honest(holder: HolderWalletV4, verifier: VerifierV4, policy: Parameters<VerifierV4["newRequest"]>[0], ctx: { callerOrigin?: string } = {}) {
  const request = await verifier.newRequest(policy);
  const { reply, presentation } = await holder.present(request, { callerOrigin: ctx.callerOrigin ?? verifier.opts.identity.origin });
  const decision = await verifier.verifyReply(reply);
  return { request, reply, presentation, decision };
}

/** Build an attacker-owned issuance tree holding one leaf; returns its path. */
export async function attackerTree(leaf: bigint) {
  const t = await IssuanceTree.create(32);
  const idx = t.insert(leaf);
  return t.path(idx);
}

export async function leafFor(issuer: IssuerV4, cred: VerifiableCredentialV4["credential"], credId: Buffer, holderCommit: bigint) {
  const p = await getPoseidon();
  return credentialLeafV4(p, {
    issuerKeyHash: ikh(p, issuer.pk),
    credId,
    holderCommit,
    birthDate: cred.birthDate,
    expiryDate: cred.expiryDate,
    credType: credTypeField(p, cred.typeId),
  });
}

export function credIdOf(issuer: IssuerV4, cred: VerifiableCredentialV4["credential"]): Buffer {
  return computeCredIdV4(cred, issuer.pk);
}

export type { SessionReplyV4 };
