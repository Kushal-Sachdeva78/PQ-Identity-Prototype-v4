import fs from "node:fs";
import path from "node:path";
import { randomBytes, createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { sha256File } from "@pqid/common/hash";
import { hostMeta } from "@pqid/common/meta";
import { REPO_ROOT } from "@pqid/common/paths";
import { World } from "@pqid/v4/world";
import { utcDateOf, addDays } from "@pqid/v4/dates";
import { revKeyFromCredId } from "@pqid/v4/encoding";
import { mlDsaKeygen, mlDsaSign, mlKemKeygen, mlKemDecaps, implementationLabel, hkdfSha256Extract, hkdfSha256Expand, aes256gcmOpen } from "@pqid/v4/pqc";
import { sha3_256 } from "@pqid/common/hash";
import { LedgerV4 } from "@pqid/v4/ledger";
import { HolderWalletV4 as HolderWalletV4Class } from "@pqid/v4/wallet";
import { epochMessage, accreditationMessage, didPopMessage, verifierKemMessage } from "@pqid/v4/statements";
import { didFromPublicKey } from "@pqid/common/did";
import { VerifierV4 as VerifierV4Class } from "@pqid/v4/verifier";
import { walletSealReply, verifierOpenReply, transcriptHash, deriveSessionSecrets, type ProofRequestV4 } from "@pqid/v4/session";
import { accreditIssuer, checkRecordAndPop } from "@pqid/v4/governance";
import {
  createIssuerV4,
  registerWithPop,
  issueCredentialV4,
  signEpochV4,
  anchorEpochV4,
  revokeCredentialV4,
  issuanceWitnessV4,
  revocationWitnessV4,
  sigHashOf,
  type IssuerV4,
  type EpochStatementV4,
} from "@pqid/v4/issuer";
import { WalletRefusal, type HolderWalletV4 } from "@pqid/v4/wallet";
import type { VerifierV4, PresentationV4 } from "@pqid/v4/verifier";
import { DEFAULT_TYPE_ID, EPOCH_WINDOW_SEC, MIN_ANCHOR_INTERVAL_SEC, STANDARD_THRESHOLDS, MAX_ACCREDITATION_SEC, MAX_EPOCH_WINDOW_SEC, KEM_ALG, SESSION_TTL_MS } from "@pqid/v4/constants";
import { R1CS_V4, ZKEY_V4, VKEY_V4, WASM_V4, KEY_LABEL_V4 } from "@pqid/v4/paths";
import { makeFillers } from "./mutant_fillers.ts";
import {
  setSuiteArtifacts,
  Recorder,
  fromDecision,
  fromRefusal,
  circuitRoute,
  verifierRoute,
  attackerSession,
  honest,
  heldOf,
  attackerTree,
  leafFor,
  type HeldData,
  type Layer,
} from "./suite_lib.ts";

/**
 * v4 SECURITY SUITE (C1). Route catalogue: docs/v4/ROUTES.md. Output:
 * results/v4/security_suite.json and results/v4/attack_matrix.json (v2, v3, v4).
 *
 * Attacker capabilities: full control of its own wallet and prover (any witness, its
 * own witness generator with every circuit check removed, its own trees, ML-DSA keys,
 * DIDs and EVM accounts). Some routes also give it an issuer's controller EVM key, the
 * governance EVM account, or a position between wallet and verifier (relay). It never
 * holds an accredited issuer's or the governance's ML-DSA private key.
 *
 * Pass criterion (fail closed): every control accepted; every attack and privacy route
 * stopped at the layer the catalogue names (circuit routes: the real R1CS is violated AND
 * the real-key proof fails verification); known limitations behave as documented; no
 * route throws unexpectedly.
 */
const PORT = Number(process.env["PQID_SUITE_PORT"] ?? 8581);
const TYPE2 = "pqid:type:library-card:v1";

function yearsBefore(date: number, years: number): number {
  return date - years * 10000;
}

/** Suite configuration: the real v4 by default; mutation runs pass one defence removed. */
interface SuiteConfig {
  name: string;
  port: number;
  out: string;
  mutantGroup?: string;
  artifacts?: { r1cs: string; sym: string; zkey: string; wasm: string; vkeyFile: string; src: string; attackerDir: string; keyLabel: string };
  verifierDisabled?: string[];
  walletDisabled?: string[];
  governanceSkipPop?: boolean;
}

function loadConfig(): SuiteConfig {
  const i = process.argv.indexOf("--config");
  if (i < 0) return { name: "v4", port: PORT, out: path.join(REPO_ROOT, "results", "v4") };
  return JSON.parse(fs.readFileSync(process.argv[i + 1] as string, "utf8")) as SuiteConfig;
}

async function main(): Promise<void> {
  const cfg = loadConfig();
  const rec = new Recorder();
  const fillers = await makeFillers(cfg.mutantGroup);
  let vkeyOverride: unknown;
  if (cfg.artifacts) {
    vkeyOverride = JSON.parse(fs.readFileSync(cfg.artifacts.vkeyFile, "utf8"));
    setSuiteArtifacts(
      { r1cs: cfg.artifacts.r1cs, sym: cfg.artifacts.sym, zkey: cfg.artifacts.zkey, wasm: cfg.artifacts.wasm, vkey: vkeyOverride, src: cfg.artifacts.src, attackerDir: cfg.artifacts.attackerDir, keyLabel: cfg.artifacts.keyLabel },
      fillers.attacker
    );
  }
  const world = await World.create({
    port: cfg.port,
    vkey: vkeyOverride,
    artifacts: cfg.artifacts ? { wasm: cfg.artifacts.wasm, zkey: cfg.artifacts.zkey, keyLabel: cfg.artifacts.keyLabel } : undefined,
    verifierDisabled: cfg.verifierDisabled ? new Set(cfg.verifierDisabled as never[]) : undefined,
    walletDisabled: cfg.walletDisabled ? new Set(cfg.walletDisabled as never[]) : undefined,
    inputHook: fillers.honest ? (input, info) => fillers.honest!(input, info) : undefined,
    governanceSkipPop: cfg.governanceSkipPop,
  });
  const L = world.ledger;
  // Deterministic time of day (review round 2, GAP-H1): every run starts at 06:00 UTC of the
  // next day, so date-boundary routes do not depend on when the suite is started.
  {
    const base0 = Math.max(world.clock.nowSec(), Number(await L.blockTimestamp()));
    await world.advance((Math.floor(base0 / 86400) + 1) * 86400 + 6 * 3600 - base0);
  }
  const t0 = Date.now();
  try {
    // ------------------------------------------------------------------ setup
    const A = await world.addIssuer("A");
    const B = await world.addIssuer("B");
    const C = await world.addIssuer("C"); // frozen-anchor and anchor-writer routes
    const V = await world.addVerifier("V");
    const V2 = await world.addVerifier("V2");
    const M = await world.addVerifier("relay", { origin: "https://relay.example" });
    const today = world.today;

    const adult = await world.addHolder();
    const minor = await world.addHolder();
    const revoked = await world.addHolder();
    const expired = await world.addHolder();
    const other = await world.addHolder({ allowedTypes: [DEFAULT_TYPE_ID, TYPE2] });
    const holderB = await world.addHolder();
    const holderC = await world.addHolder();
    const bday18 = await world.addHolder();
    const bday18tomorrow = await world.addHolder();
    const originBound = await world.addHolder({ originBinding: true });
    const extra = [await world.addHolder(), await world.addHolder()];

    const vcAdult = await world.issue(A, adult, { birthDate: 19900510 });
    const vcMinor = await world.issue(A, minor, { birthDate: yearsBefore(today, 16) });
    const vcRevoked = await world.issue(A, revoked, { birthDate: 19850101 });
    const vcExpired = await world.issue(A, expired, { birthDate: 19800101, issuedDate: addDays(today, -100), expiryDate: addDays(today, -1) });
    const vcOther = await world.issue(A, other, { birthDate: 19800101, typeId: TYPE2 });
    const vcB = await world.issue(B, holderB, { birthDate: 19750101 });
    const vcC = await world.issue(C, holderC, { birthDate: 19700101 });
    const vcBday = await world.issue(A, bday18, { birthDate: yearsBefore(today, 18) });
    await world.issue(A, bday18tomorrow, { birthDate: yearsBefore(addDays(today, 1), 18) });
    await world.issue(A, originBound, { birthDate: 19950303 });
    for (const h of extra) await world.issue(A, h, { birthDate: 19920202 });

    await world.publishEpoch(A); // epoch 1
    await world.publishEpoch(B);
    await world.publishEpoch(C);
    // Keep the pre-revocation view for stale-opening routes.
    const oldStatementA = issuanceWitnessV4(A, vcRevoked.credID).statement;
    const oldPathRevoked = issuanceWitnessV4(A, vcRevoked.credID).path;
    const oldRevWitness = revocationWitnessV4(A, vcRevoked.credID);
    revokeCredentialV4(A, vcRevoked.credID);
    await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
    await world.publishEpoch(A); // epoch 2: revocation effective
    const policy18: { predicate: "age_gte" | "age_lt"; threshold: number; typeId: string } = { predicate: "age_gte", threshold: 18, typeId: DEFAULT_TYPE_ID };

    // ------------------------------------------------------------------ controls
    rec.begin("C0", "Honest holders are accepted", "control");
    const ctl = (label: string, holder: HolderWalletV4, pol: typeof policy18) =>
      rec.route(label, { attacker: "none", goal: "honest presentation", expect: { layer: "accepted", any: [] } }, async () => fromDecision((await honest(holder, V, pol)).decision));
    await ctl("C0-a adult, age_gte 18", adult, policy18);
    await ctl("C0-b minor, age_lt 18", minor, { ...policy18, predicate: "age_lt" });
    await ctl("C0-c adult, age_gte 21", adult, { ...policy18, threshold: 21 });
    await ctl("C0-d turns 18 today (birthday boundary), age_gte 18", bday18, policy18);
    await ctl("C0-e holder of issuer B, age_gte 21", holderB, { ...policy18, threshold: 21 });

    rec.begin("B2-boundary", "Birthday boundary: turns 18 tomorrow (honest wallet refuses, not an attack)", "baseline");
    await rec.route("honest wallet, age_gte 18 one day before the 18th birthday", { attacker: "none", goal: "boundary", expect: { layer: "wallet", any: ["predicateHolds"] } }, async () => {
      try {
        await honest(bday18tomorrow, V, policy18);
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return fromRefusal(e);
      }
    });

    rec.begin("B3-65", "Adult asks age_gte 65 (honest wallet refuses; not an attack)", "baseline");
    await rec.route("C0-c65 adult (born 1990), age_gte 65", { attacker: "none", goal: "boundary", expect: { layer: "wallet", any: ["predicateHolds"] } }, async () => {
      try {
        await honest(adult, V, { ...policy18, threshold: 65 });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return fromRefusal(e);
      }
    });

    rec.begin("C2", "Honest holders keep presenting through open batches, signed-but-unanchored epochs and refreshes", "control");
    const late = await world.addHolder();
    const vcLate = await world.issue(A, late, { birthDate: 19880808 }); // newer leaf, unsigned
    rec.begin("B1", "Late holder asks the issuer's service for a path before its leaf is anchored", "baseline");
    await rec.route("B1 issuer service refuses an unanchored leaf", { attacker: "none", goal: "", expect: { layer: "wallet", any: ["issuerServiceRefused"] } }, async () => {
      try {
        issuanceWitnessV4(A, vcLate.credID);
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return { accepted: false, stoppedBy: { layer: "wallet" as Layer, checks: ["issuerServiceRefused"] }, detail: (e as Error).message };
      }
    });
    rec.begin("C2", "Honest holders keep presenting through open batches, signed-but-unanchored epochs and refreshes", "control");
    await ctl("C2-a adult while a newer leaf is unsigned", adult, policy18);
    await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
    const signedOnly = await signEpochV4(A, L, world.clock); // epoch 3 signed, not anchored
    await ctl("C2-b adult while epoch 3 is signed but not anchored", adult, policy18);
    await world.syncChainTime();
    await anchorEpochV4(A, L, signedOnly);
    await world.refreshPublication(A); // wallets download the new blob when the anchor appears
    await ctl("C2-c adult after the refresh to epoch 3", adult, policy18);
    await ctl("C2-d late holder with its first path", late, policy18);

    // ------------------------------------------------------------------ helpers bound to this world
    const held = (h: HolderWalletV4, issuer: IssuerV4, vc: typeof vcAdult): HeldData => heldOf(h, issuer, vc);
    const req = (v: VerifierV4, pol: Parameters<VerifierV4["newRequest"]>[0] = policy18) => v.newRequest(pol);
    const revFor = (issuer: IssuerV4, credId: Buffer) => {
      const a = issuer.anchored;
      if (!a) throw new Error("no anchor");
      return a.rev.nonMembershipWitness(revKeyFromCredId(credId));
    };
    const circ = async (holder: HeldData, v: VerifierV4, f: Parameters<typeof circuitRoute>[4], pol = policy18) => circuitRoute(world, v, await req(v, pol), holder, f);
    const ver = async (holder: HeldData, v: VerifierV4, f: Parameters<typeof verifierRoute>[4], pol = policy18) =>
      fromDecision((await verifierRoute(world, v, await req(v, pol), holder, f)).decision);
    const statementA = () => issuanceWitnessV4(A, vcAdult.credID).statement;

    // ------------------------------------------------------------------ A1 forged credential
    rec.begin("A1", "Forged credential the issuer never issued", "attack");
    const forgedId = randomBytes(32);
    const forgedCred = { ...vcAdult.credential, birthDate: 19700101, salt: randomBytes(32).toString("hex") };
    await rec.route("A1-a forged leaf with a real holder's path under A's anchored root", { attacker: "malicious holder", goal: "prove a never-issued credential", expect: { layer: "circuit", any: ["G04_issuance_membership"] } }, () =>
      circ(held(adult, A, vcAdult), V, { credId: forgedId, credential: forgedCred, rev: revFor(A, forgedId) })
    );
    const forgedLeaf = await leafFor(A, forgedCred, forgedId, adult.holderCommit);
    const ownPath = await attackerTree(forgedLeaf);
    await rec.route("A1-b attacker-built tree, valid proof, A's genuine statement", { attacker: "malicious holder", goal: "never-issued credential", expect: { layer: "verifier", any: ["epochAnchorCurrent"] } }, () =>
      ver(held(adult, A, vcAdult), V, { credId: forgedId, credential: forgedCred, path: ownPath, rev: revFor(A, forgedId), input: (i) => void (i["issRoot"] = ownPath.root) })
    );
    await rec.route("A1-c attacker-built tree, statement signed with the attacker's key naming A", { attacker: "malicious holder", goal: "never-issued credential", expect: { layer: "verifier", any: ["epochAnchorCurrent", "epochSignature"] } }, async () => {
      const k = mlDsaKeygen();
      const { signature: _s, ...fields } = statementA();
      const f2 = { ...fields, root: ownPath.root };
      const st: EpochStatementV4 = { ...f2, signature: mlDsaSign(k.privateKey, epochMessage(f2)).toString("hex") };
      return ver(held(adult, A, vcAdult), V, { credId: forgedId, credential: forgedCred, path: ownPath, statement: st, rev: revFor(A, forgedId) });
    });
    await rec.route("A1-d self-issued under the attacker's own PoP-registered, unaccredited DID", { attacker: "malicious holder with own issuer DID", goal: "self-issue", expect: { layer: "verifier", any: ["accreditation"] } }, async () => {
      const X = await world.addIssuer("X", { accredit: false });
      const self = await world.addHolder();
      const vcX = await world.issue(X, self, { birthDate: 19600101 });
      await world.publishEpoch(X);
      return ver(held(self, X, vcX), V, {});
    });

    // ------------------------------------------------------------------ A2 minor claims adult
    rec.begin("A2", "Holder of a genuine minor's credential claims adulthood", "attack");
    await rec.route("A2-a genuine path, earlier birthDate", { attacker: "minor", goal: "age_gte 18", expect: { layer: "circuit", any: ["G04_issuance_membership"] } }, () =>
      circ(held(minor, A, vcMinor), V, { credential: { birthDate: 19900101 } })
    );
    await rec.route("A2-b genuine leaf and birthDate, age_gte 18", { attacker: "minor", goal: "age_gte 18", expect: { layer: "circuit", any: ["G12_age"] } }, () => circ(held(minor, A, vcMinor), V, {}));
    await rec.route("A2-d adult proves age_lt 18 with the attacker's generator", { attacker: "adult", goal: "age_lt 18 (under-age discount or child service)", expect: { layer: "circuit", any: ["G12_age"] } }, () =>
      circ(held(adult, A, vcAdult), V, {}, { ...policy18, predicate: "age_lt" })
    );
    await rec.route("A2-c attacker-built tree with a fake birthDate, A's statement", { attacker: "minor", goal: "age_gte 18", expect: { layer: "verifier", any: ["epochAnchorCurrent"] } }, async () => {
      const cred = { ...vcMinor.credential, birthDate: 19900101 };
      const id = Buffer.from(vcMinor.credID, "hex");
      const p = await attackerTree(await leafFor(A, cred, id, minor.holderCommit));
      return ver(held(minor, A, vcMinor), V, { credential: cred, path: p, input: (i) => void (i["issRoot"] = p.root) });
    });

    // ------------------------------------------------------------------ A4 thief
    rec.begin("A4", "Thief holds the victim's credential and path but not the holder secret", "attack");
    await rec.route("A4-a victim's genuine path, thief's secret", { attacker: "thief", goal: "present the victim's credential", expect: { layer: "circuit", any: ["G04_issuance_membership"] } }, () =>
      circ(held(adult, A, vcAdult), V, { holderSecret: BigInt("0x" + randomBytes(31).toString("hex")) })
    );

    // ------------------------------------------------------------------ A5 issuer swap
    rec.begin("A5", "Holder of issuer B's credential presents it as issuer A's", "attack");
    await rec.route("A5-a proof on B's tree, issuerDid A, B's statement", { attacker: "B's holder", goal: "claim issuer A", expect: { layer: "verifier", any: ["issuerKeyHash", "epochAnchorCurrent"] } }, () =>
      ver(held(holderB, B, vcB), V, { issuerDid: A.did, issuerController: A.controller })
    );
    await rec.route("A5-b A's issuerKeyHash with B's path", { attacker: "B's holder", goal: "claim issuer A", expect: { layer: "circuit", any: ["G04_issuance_membership"] } }, async () => {
      const { getPoseidon, issuerKeyHash } = await import("@pqid/common/encoding");
      return circ(held(holderB, B, vcB), V, { override: { issuerKeyHash: issuerKeyHash(await getPoseidon(), A.pk) }, issuerDid: A.did, issuerController: A.controller });
    });

    // ------------------------------------------------------------------ A6 statements
    rec.begin("A6", "Honest proof with a tampered, missing or foreign epoch statement", "attack");
    const edit = (fn: (p: PresentationV4) => void) => ver(held(adult, A, vcAdult), V, { presentation: fn });
    await rec.route("A6-a epoch changed after signing", { attacker: "malicious holder", goal: "tamper", expect: { layer: "verifier", any: ["epochAnchorCurrent"] } }, () => edit((p) => void (p.epochStatement.epoch += 1)));
    await rec.route("A6-b statement omitted", { attacker: "malicious holder", goal: "tamper", expect: { layer: "verifier", any: ["shape"] } }, () =>
      edit((p) => void delete (p as unknown as Record<string, unknown>)["epochStatement"])
    );
    await rec.route("A6-c A's root signed by B's key", { attacker: "malicious holder", goal: "foreign signature", expect: { layer: "verifier", any: ["epochAnchorCurrent", "epochSignature"] } }, () =>
      edit((p) => {
        const { signature: _s, ...f } = p.epochStatement;
        p.epochStatement.signature = mlDsaSign(B.sk, epochMessage(f)).toString("hex");
      })
    );
    await rec.route("A6-e issuer A's own statement for another chain and registry (same epoch and roots)", { attacker: "malicious holder", goal: "present under a statement from another deployment", expect: { layer: "verifier", any: ["epochAnchorCurrent"] } }, async () => {
      const { signature: _s, ...f } = statementA();
      const f2 = { ...f, chainId: f.chainId + 1, registry: "0x" + "ab".repeat(20) };
      const st: EpochStatementV4 = { ...f2, signature: mlDsaSign(A.sk, epochMessage(f2)).toString("hex") };
      return ver(held(adult, A, vcAdult), V, { statement: st });
    });
    await rec.route("A6-d notAfter extended after signing", { attacker: "malicious holder", goal: "extend validity", expect: { layer: "verifier", any: ["epochAnchorCurrent"] } }, () =>
      edit((p) => void (p.epochStatement.notAfter += 7 * 86400))
    );

    // ------------------------------------------------------------------ A7 squatter with own key
    rec.begin("A7", "Attacker registers issuer A's DID string with its own key", "attack");
    await rec.route("A7-a self-consistent credential under A's DID string, attacker key and controller", { attacker: "squatter (own key)", goal: "impersonate issuer A", expect: { layer: "verifier", any: ["issuerRecord", "accreditation"] } }, async () => {
      const S = await createIssuerV4(L, "squatter-own");
      S.did = A.did; // claims A's DID string with its own key
      await registerWithPop(L, S);
      const sh = await world.addHolder();
      const vcS = await issueCredentialV4(S, { subject: sh.subject, holderCommit: sh.holderCommit, birthDate: 19700101, issuedDate: world.today });
      await world.syncChainTime();
      await anchorEpochV4(S, L, await signEpochV4(S, L, world.clock));
      return ver(held(sh, S, vcS), V, {});
    });

    // ------------------------------------------------------------------ T1 trapdoor
    let beaconMatchesDelta: boolean | null = null;
    rec.begin("T1", "Groth16 proof forged from the public beacon (no credential)", "attack");
    await rec.route("T1-a public-beacon trapdoor applied to the v4 dev key", { attacker: "anyone", goal: "forge without a witness", expect: { layer: "verifier", any: ["groth16"] } }, async () => {
      const { deriveBeaconTrapdoor, forgeProof } = await import("../v3/trapdoor.ts");
      const request = await req(V);
      const session = await attackerSession(world, V, request);
      const good = await verifierRoute(world, V, await req(V), held(adult, A, vcAdult), {});
      const signals = [...good.presentation.publicSignals];
      signals[3] = session.nonce.toString();
      const vkey = JSON.parse(fs.readFileSync(VKEY_V4, "utf8")) as Parameters<typeof deriveBeaconTrapdoor>[0];
      // The v4 dev key uses the same public beacon as v2/v3 (hash 0x0102..1f20, 2^10 iterations).
      const td = await deriveBeaconTrapdoor(vkey, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", 10);
      const proof = await forgeProof(vkey, td.d, signals);
      beaconMatchesDelta = td.matchesDelta;
      const pres = { ...good.presentation, proof: proof as PresentationV4["proof"], publicSignals: signals };
      return fromDecision(await V.verifyReply(walletSealReply(session, pres)));
    });

    // ------------------------------------------------------------------ R1 replay and binding
    rec.begin("R1", "Replay, cross-session, cross-verifier and policy binding", "attack");
    const first = await honest(adult, V, policy18);
    rec.begin("C1", "First use of the presentation replayed below is accepted", "control");
    await rec.route("C1-a honest first use", { attacker: "none", goal: "", expect: { layer: "accepted", any: [] } }, async () => fromDecision(first.decision));
    rec.begin("R1", "Replay, cross-session, cross-verifier and policy binding", "attack");
    await rec.route("R1-a replay of the accepted reply", { attacker: "network adversary", goal: "reuse a presentation", expect: { layer: "verifier", any: ["sessionKnown"] } }, async () => fromDecision(await V.verifyReply(first.reply)));
    await rec.route("R1-b reply moved into a new session", { attacker: "network adversary", goal: "reuse in another session", expect: { layer: "verifier", any: ["transcriptDecrypts"] } }, async () => {
      const r2 = await req(V);
      return fromDecision(await V.verifyReply({ ...first.reply, sessionId: r2.sessionId }));
    });
    await rec.route("R1-c presentation for V re-sealed to V2", { attacker: "malicious holder or verifier V", goal: "cross-verifier reuse", expect: { layer: "verifier", any: ["nonceBinding", "stmtCode"] } }, async () => {
      const s2 = await attackerSession(world, V2, await req(V2));
      return fromDecision(await V2.verifyReply(walletSealReply(s2, first.presentation)));
    });
    await rec.route("R1-e leaked presentation replayed by a third party into a new session at the same verifier", { attacker: "third party holding a leaked presentation (verifier logs)", goal: "authenticate as the holder in a new session", expect: { layer: "verifier", any: ["nonceBinding"] } }, async () => {
      const s2 = await attackerSession(world, V, await req(V));
      return fromDecision(await V.verifyReply(walletSealReply(s2, first.presentation)));
    });
    await rec.route("R1-d age_gte 18 proof where 21 is required", { attacker: "malicious holder", goal: "weaker policy", expect: { layer: "verifier", any: ["policyHash"] } }, () =>
      ver(held(adult, A, vcAdult), V, { override: { threshold: 18 } }, { ...policy18, threshold: 21 })
    );

    await rec.route("R1-f the same reply verified twice at once", { attacker: "network adversary", goal: "two acceptances from one presentation", expect: { layer: "verifier", any: ["sessionFresh"] } }, async () => {
      const r = await req(V);
      const { reply } = await adult.present(r, { callerOrigin: V.opts.identity.origin });
      const [d1, d2] = await Promise.all([V.verifyReply(reply), V.verifyReply(reply)]);
      if (d1.accepted && d2.accepted) return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] }, detail: "both verifications accepted" };
      return fromDecision(d1.accepted ? d2 : d1);
    });

    await rec.route("R1-g reply sent after the session's lifetime", { attacker: "holder or relay", goal: "use an expired session", expect: { layer: "verifier", any: ["sessionKnown"] } }, async () => {
      const r = await req(V);
      const { reply } = await adult.present(r, { callerOrigin: V.opts.identity.origin });
      await world.advance(SESSION_TTL_MS / 1000 + 1);
      return fromDecision(await V.verifyReply(reply));
    });

    // ------------------------------------------------------------------ A3 revoked holder
    rec.begin("A3", "Revoked holder tries to keep authenticating", "attack");
    const hr = held(revoked, A, vcRevoked);
    const revId = Buffer.from(vcRevoked.credID, "hex");
    const revKey = revKeyFromCredId(revId);
    const imt = A.anchored!.rev;
    await rec.route("A3-B stale low leaf against the current root", { attacker: "revoked holder", goal: "keep presenting", expect: { layer: "circuit", any: ["G06_rev_low_membership"] } }, () => circ(hr, V, { rev: oldRevWitness }));
    await rec.route("A3-C stale low leaf, stale revRoot and the old statement", { attacker: "revoked holder", goal: "keep presenting", expect: { layer: "verifier", any: ["epochAnchorCurrent"] } }, () =>
      ver(hr, V, { rev: oldRevWitness, statement: oldStatementA, path: oldPathRevoked })
    );
    const freshId = randomBytes(32);
    await rec.route("A3-D1 fresh credID with the revoked credential's genuine path", { attacker: "revoked holder", goal: "evade revocation", expect: { layer: "circuit", any: ["G04_issuance_membership"] } }, () =>
      circ(hr, V, { credId: freshId, rev: revFor(A, freshId) })
    );
    await rec.route("A3-D2 fresh credID in an attacker-built tree, A's statement", { attacker: "revoked holder", goal: "evade revocation", expect: { layer: "verifier", any: ["epochAnchorCurrent"] } }, async () => {
      const p = await attackerTree(await leafFor(A, vcRevoked.credential, freshId, revoked.holderCommit));
      return ver(hr, V, { credId: freshId, path: p, rev: revFor(A, freshId), input: (i) => void (i["issRoot"] = p.root) });
    });
    const ownIdx = imt.lowLeafIndex(revKey + 1n); // the revoked key's own leaf brackets revKey+1
    await rec.route("A3-F the revoked key's own leaf as low leaf (lowValue = key)", { attacker: "revoked holder", goal: "evade revocation", expect: { layer: "circuit", any: ["G07_rev_bracket"] } }, () =>
      circ(hr, V, { rev: imt.openLeaf(ownIdx) })
    );
    let predIdx = -1; // the predecessor leaf now points to revKey
    for (let i = 0; i < imt.size; i++) if (imt.leafAt(i).nextValue === revKey) predIdx = i;
    if (predIdx < 0) throw new Error("internal: no predecessor of the revoked key");
    await rec.route("A3-G the predecessor leaf, whose next is now the revoked key", { attacker: "revoked holder", goal: "evade revocation", expect: { layer: "circuit", any: ["G07_rev_bracket"] } }, () =>
      circ(hr, V, { rev: imt.openLeaf(predIdx) })
    );

    await rec.route("A3-H current statement, valid proof against the pre-revocation revocation root", { attacker: "revoked holder", goal: "evade revocation", expect: { layer: "verifier", any: ["revRoot"] } }, () =>
      ver(hr, V, { rev: oldRevWitness, input: (i) => void (i["revRoot"] = oldRevWitness.root) })
    );

    // ------------------------------------------------------------------ NL forged neighbour leaves
    rec.begin("NL", "Forged neighbour-leaf (low-leaf) openings in the indexed Merkle tree", "attack");
    const real = imt.openLeaf(predIdx);
    await rec.route("NL-a fabricated bracketing leaf with a real leaf's path", { attacker: "revoked holder", goal: "fake non-membership", expect: { layer: "circuit", any: ["G06_rev_low_membership"] } }, () =>
      circ(hr, V, { rev: { ...real, lowValue: (revKey - 1n).toString(), lowNext: (revKey + 1n).toString() } })
    );
    await rec.route("NL-b fabricated leaf at an empty index", { attacker: "revoked holder", goal: "fake non-membership", expect: { layer: "circuit", any: ["G06_rev_low_membership"] } }, () => {
      const empty = imt.size + 7;
      const w = imt.openLeaf(0);
      return circ(hr, V, { rev: { ...w, lowIndex: String(empty), lowValue: (revKey - 1n).toString(), lowNext: (revKey + 1n).toString() } });
    });
    await rec.route("NL-c real predecessor leaf with lowNext edited to bracket the key", { attacker: "revoked holder", goal: "fake non-membership", expect: { layer: "circuit", any: ["G06_rev_low_membership"] } }, () =>
      circ(hr, V, { rev: { ...real, lowNext: (revKey + 1n).toString() } })
    );
    await rec.route("NL-d stale sentinel (0, 2^251), which brackets every key, with index 0's current path", { attacker: "revoked holder", goal: "fake non-membership", expect: { layer: "circuit", any: ["G06_rev_low_membership"] } }, () =>
      circ(hr, V, { rev: { ...imt.openLeaf(0), lowValue: "0", lowNext: (1n << 251n).toString() } })
    );

    // ------------------------------------------------------------------ EX / TY / SD / TP
    rec.begin("EX", "Expired credential", "attack");
    await rec.route("EX-a verifier's today after expiryDate", { attacker: "holder of an expired credential", goal: "present after expiry", expect: { layer: "circuit", any: ["G13_expiry"] } }, () =>
      circ(held(expired, A, vcExpired), V, {})
    );
    await rec.route("EX-b older date inside the proof (before expiry)", { attacker: "holder of an expired credential", goal: "present after expiry", expect: { layer: "circuit", any: ["G15_epoch_window", "G08_policy_hash"] } }, () =>
      circ(held(expired, A, vcExpired), V, { input: (i) => void (i["today"] = String(addDays(today, -2))) })
    );
    rec.begin("TY", "Wrong credential type", "attack");
    const { getPoseidon } = await import("@pqid/common/encoding");
    const { credTypeField } = await import("@pqid/v4/encoding");
    const ownType = credTypeField(await getPoseidon(), TYPE2);
    await rec.route("TY-a requiredType = verifier's type, credential of another type", { attacker: "holder of another type", goal: "type confusion", expect: { layer: "circuit", any: ["G14_type", "G08_policy_hash"] } }, () =>
      circ(held(other, A, vcOther), V, {})
    );
    await rec.route("TY-b requiredType = own type inside the proof", { attacker: "holder of another type", goal: "type confusion", expect: { layer: "verifier", any: ["policyHash"] } }, () =>
      ver(held(other, A, vcOther), V, { override: { requiredType: ownType } })
    );
    await rec.route("TY-c verifier asks for a credential type outside the wallet's allow-list", { attacker: "verifier", goal: "learn which types (and issuers) the holder has", expect: { layer: "wallet-enforced", any: ["typeAllowed"] } }, async () => {
      try {
        await adult.present(await V.newRequest({ ...policy18, typeId: "pqid:type:status-card:v1" }), { callerOrigin: V.opts.identity.origin });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return fromRefusal(e, "wallet-enforced");
      }
    });
    // Added after the mutation table (C3): removing G08 let no route through, so no route
    // kept the verifier's public policyHash while changing the private policy inputs.
    rec.begin("PH", "Private policy inputs differ from the verifier's public policyHash", "attack");
    await rec.route("PH-a minor flips the private predicate to age_lt under the age_gte 18 policyHash", { attacker: "minor", goal: "age_gte 18", expect: { layer: "circuit", any: ["G08_policy_hash"] } }, () =>
      circ(held(minor, A, vcMinor), V, { input: (i) => void (i["predicateCode"] = "2") })
    );
    await rec.route("PH-b minor lowers the private threshold to 16 under the age_gte 18 policyHash", { attacker: "minor", goal: "age_gte 18", expect: { layer: "circuit", any: ["G08_policy_hash"] } }, () =>
      circ(held(minor, A, vcMinor), V, { input: (i) => void (i["threshold"] = "16") })
    );
    await rec.route("PH-c holder of another type sets the private requiredType to its own type", { attacker: "holder of another type", goal: "type confusion", expect: { layer: "circuit", any: ["G08_policy_hash"] } }, () =>
      circ(held(other, A, vcOther), V, { input: (i) => void (i["requiredType"] = ownType.toString()) })
    );

    rec.begin("SD", "Stale dates", "attack");
    await rec.route("SD-a prover uses yesterday's date to stay under 18 after turning 18", { attacker: "holder who turned 18 today", goal: "age_lt 18 after the birthday", expect: { layer: "circuit", any: ["G15_epoch_window", "G08_policy_hash"] } }, () =>
      circ(held(bday18, A, vcBday), V, { input: (i) => void (i["today"] = String(addDays(today, -1))) }, { ...policy18, predicate: "age_lt" })
    );
    await rec.route("SD-b verifier supplies a stale date (probe / accept expired)", { attacker: "verifier", goal: "learn the birth date or accept expired", expect: { layer: "wallet-enforced", any: ["dateCurrent"] } }, async () => {
      try {
        await adult.present(await V.newRequest({ ...policy18, today: addDays(today, -400) }), { callerOrigin: V.opts.identity.origin });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return fromRefusal(e, "wallet-enforced");
      }
    });
    await rec.route("SD-c buggy wallet (date check off): date outside the signed epoch window", { attacker: "verifier + buggy wallet", goal: "stale-date proof", expect: { layer: "circuit", any: ["G15_epoch_window"] } }, async () =>
      circuitRoute(world, V, await V.newRequest({ ...policy18, today: addDays(today, -400) }), held(adult, A, vcAdult), {})
    );
    rec.begin("TP", "Threshold probing", "attack");
    for (const t of [17, 19, 20]) {
      await rec.route(`TP-a verifier asks threshold ${t}`, { attacker: "verifier", goal: "binary-search the birth date", expect: { layer: "wallet-enforced", any: ["thresholdStandard"] } }, async () => {
        try {
          await adult.present(await V.newRequest({ ...policy18, threshold: t }), { callerOrigin: V.opts.identity.origin });
          return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
        } catch (e) {
          return fromRefusal(e, "wallet-enforced");
        }
      });
    }
    await rec.route("TP-b buggy wallet (threshold check off), threshold 17", { attacker: "verifier + buggy wallet", goal: "non-standard threshold proof", expect: { layer: "circuit", any: ["G10_standard_threshold"] } }, async () =>
      circuitRoute(world, V, await V.newRequest({ ...policy18, threshold: 17 }), held(adult, A, vcAdult), {})
    );
    // Added after the C3 classification review: without thresholdStandard the wallet evaluates
    // the predicate at any threshold, so the kind (and timing) of its refusal depends on the
    // birth date. Observation model (DECISIONS D-026): the caller of present() sees the refusal.
    rec.begin("TP-c", "Non-standard thresholds as a refusal-kind oracle (observation model D-026)", "privacy");
    await rec.route("TP-c refusal kinds at non-standard thresholds around the adult's age and at 17 for the minor", { attacker: "verifier", goal: "learn the exact age beyond the standard brackets", expect: { layer: "wallet-enforced", any: ["thresholdStandard"] } }, async () => {
      const aAge = Math.floor((today - 19900510) / 10000);
      const probes: Array<[HolderWalletV4, number]> = [[minor, 17], [adult, 17], [adult, aAge], [adult, aAge + 1]];
      for (const [, t] of probes) if (STANDARD_THRESHOLDS.includes(t as never) || t < 0 || t > 255) throw new Error(`probe threshold ${t} is standard or out of range`);
      const seen: string[] = [];
      for (const [h, t] of probes) {
        try {
          await h.present(await V.newRequest({ ...policy18, threshold: t }), { callerOrigin: V.opts.identity.origin });
          seen.push("answered");
        } catch (e) {
          seen.push(e instanceof WalletRefusal ? e.check : "error");
        }
      }
      const kinds = [...new Set(seen)];
      return { accepted: kinds.length > 1, stoppedBy: { layer: "wallet-enforced" as Layer, checks: kinds.length > 1 ? [] : kinds }, detail: `observations ${seen.join(", ")}` };
    });

    // Review round 2 (DATE-1): the wallet must check and use one snapshot of the request. The
    // attacker's request reads one value while the wallet checks it and another once the wallet
    // has started reading issuer data (a deterministic flip, not a timing race).
    const flipOnIssuerRead = (h: HolderWalletV4) => {
      const hc = h.credentials[0]!;
      const saved = hc.source;
      const state = { flipped: false, restore: () => void (hc.source = saved) };
      hc.source = { issuance: (id: string) => ((state.flipped = true), saved.issuance(id)), revocation: saved.revocation };
      return state;
    };
    rec.begin("SD-g", "Request whose date changes after the wallet checked it (accessor)", "attack");
    await rec.route("SD-g request date reads today at the check and tomorrow afterwards (holder turns 18 tomorrow)", { attacker: "verifier", goal: "an answer for a future date (exact birth date)", expect: { layer: "wallet-enforced", any: ["requestSnapshot"] } }, async () => {
      const st = flipOnIssuerRead(bday18tomorrow);
      try {
        const base = await V.newRequest(policy18);
        const pol: Record<string, unknown> = { ...base.policy };
        Object.defineProperty(pol, "today", { enumerable: true, configurable: true, get: () => (st.flipped ? addDays(today, 1) : today) });
        const tampered = { ...base, policy: pol } as unknown as ProofRequestV4;
        try {
          await bday18tomorrow.present(tampered, { callerOrigin: V.opts.identity.origin });
          return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] }, detail: "a reply exists, so the wallet proved for tomorrow" };
        } catch (e) {
          if (e instanceof WalletRefusal && e.check === "predicateHolds") return { accepted: false, stoppedBy: { layer: "wallet-enforced" as Layer, checks: ["requestSnapshot"] }, detail: `evaluated at the checked date (issuer data read: ${st.flipped})` };
          return fromRefusal(e, "wallet-enforced");
        }
      } finally {
        st.restore();
      }
    });
    rec.begin("TP-d", "Request whose threshold changes after the wallet checked it (accessor)", "attack");
    await rec.route("TP-d threshold reads 18 at the check and 17 afterwards", { attacker: "verifier", goal: "a predicate at a non-standard threshold (age oracle)", expect: { layer: "wallet-enforced", any: ["requestSnapshot"] } }, async () => {
      const st = flipOnIssuerRead(adult);
      try {
        const base = await V.newRequest(policy18);
        const pol: Record<string, unknown> = { ...base.policy };
        Object.defineProperty(pol, "threshold", { enumerable: true, configurable: true, get: () => (st.flipped ? 17 : 18) });
        const tampered = { ...base, policy: pol } as unknown as ProofRequestV4;
        try {
          const { reply } = await adult.present(tampered, { callerOrigin: V.opts.identity.origin });
          const d = await V.verifyReply(reply);
          return { accepted: false, stoppedBy: { layer: "wallet-enforced" as Layer, checks: ["requestSnapshot"] }, detail: `answered at the checked threshold (verifier accepted: ${d.accepted})` };
        } catch (e) {
          if (e instanceof WalletRefusal && e.check === "proofFailed") return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] }, detail: "the wallet evaluated threshold 17 (proof failed at G10)" };
          return fromRefusal(e, "wallet-enforced");
        }
      } finally {
        st.restore();
      }
    });

    // ------------------------------------------------------------------ SQ real-key squatter
    rec.begin("SQ", "Real-key squatter: registers issuer A's DID with A's genuine public key", "attack");
    const Q = await L.newRoleAccount("squatter");
    const squat = { did: A.did, pk: A.pk, sk: mlDsaKeygen().privateKey, account: Q };
    await registerWithPop(L, squat); // PoP made with a key that is NOT A's: invalid
    await rec.route("SQ-a asks governance to accredit (garbage PoP)", { attacker: "squatter", goal: "get accredited as A", expect: { layer: "governance", any: ["issuerPop"] } }, async () => {
      try {
        await accreditIssuer(world.governance, L, world.clock, { did: A.did, controller: Q.address.toLowerCase() }, { skipPopCheck: cfg.governanceSkipPop });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return { accepted: false, stoppedBy: { layer: "governance" as Layer, checks: ["issuerPop"] }, detail: (e as Error).message };
      }
    });
    await rec.route("SQ-b replays A's genuine PoP signature under its own controller", { attacker: "squatter", goal: "get accredited as A", expect: { layer: "governance", any: ["issuerPop"] } }, async () => {
      const Q2 = await L.newRoleAccount("squatter2");
      const popSig = await L.getPopSignature(A.did, A.controller);
      const recA = await L.resolveDidRecord(A.did, A.controller);
      await L.registerDid(Q2, { did: A.did, pk: A.pk, popNonce: recA!.popNonce, popSig, origin: "" });
      const pop = await checkRecordAndPop(L, A.did, Q2.address.toLowerCase());
      if (pop.ok) return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      if (cfg.governanceSkipPop) {
        await accreditIssuer(world.governance, L, world.clock, { did: A.did, controller: Q2.address.toLowerCase() }, { skipPopCheck: true });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] }, detail: "governance accredited without checking PoP" };
      }
      try {
        await accreditIssuer(world.governance, L, world.clock, { did: A.did, controller: Q2.address.toLowerCase() }, { skipPopCheck: cfg.governanceSkipPop });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return { accepted: false, stoppedBy: { layer: "governance" as Layer, checks: ["issuerPop"] }, detail: `${pop.reason}; ${(e as Error).message}` };
      }
    });
    await rec.route("SQ-c presentation through the squatter's record with its own epoch (old revRoot)", { attacker: "squatter + revoked holder", goal: "keep a revoked credential accepted", expect: { layer: "verifier", any: ["issuerPop", "accreditation"] } }, async () => {
      const sqIssuer = { ...A, account: Q, controller: Q.address.toLowerCase(), sk: squat.sk, anchored: null, signed: [] } as IssuerV4;
      await world.syncChainTime();
      const st = await signEpochV4(sqIssuer, L, world.clock);
      await L.publishEpoch(Q, { did: A.did, epoch: st.epoch, root: BigInt(st.root), revRoot: BigInt(oldStatementA.revRoot), notBefore: st.notBefore, notAfter: st.notAfter, sigHash: sigHashOf(st.signature) });
      return ver(hr, V, { statement: { ...st, revRoot: oldStatementA.revRoot }, issuerController: Q.address.toLowerCase(), rev: oldRevWitness });
    });

    // ------------------------------------------------------------------ RA rogue accreditation
    rec.begin("RA", "Rogue accreditation (attacker holds the governance EVM account)", "attack");
    const Xr = await world.addIssuer("Xrogue", { accredit: false });
    const xh = await world.addHolder();
    const vcXr = await world.issue(Xr, xh, { birthDate: 19600101 });
    await world.publishEpoch(Xr);
    const chainIdL = await L.chainId();
    const accFields = (serial: number) => ({
      issuerDid: Xr.did,
      controller: Xr.controller,
      pkSha3: (await_sha3(Xr.pk)),
      chainId: chainIdL,
      registry: L.addresses.accreditationRegistry.toLowerCase(),
      serial,
      status: "accredited" as const,
      notBefore: world.clock.nowSec() - 10,
      notAfter: world.clock.nowSec() + 86400,
    });
    await rec.route("RA-a accreditation signed with the attacker's ML-DSA key", { attacker: "governance EVM account holder", goal: "accredit its own issuer", expect: { layer: "verifier", any: ["accreditation"] } }, async () => {
      const st = accreditationMessage(accFields(900));
      await L.publishAccreditation(world.governance.account, Xr.did, st, mlDsaSign(mlDsaKeygen().privateKey, st));
      return ver(held(xh, Xr, vcXr), V, {});
    });
    await rec.route("RA-b accreditation with a garbage signature", { attacker: "governance EVM account holder", goal: "accredit its own issuer", expect: { layer: "verifier", any: ["accreditation"] } }, async () => {
      const st = accreditationMessage(accFields(901));
      await L.publishAccreditation(world.governance.account, Xr.did, st, randomBytes(2420));
      return ver(held(xh, Xr, vcXr), V, {});
    });
    await rec.route("RA-c replay of an older genuine accreditation after revocation (serial rollback)", { attacker: "governance EVM account holder", goal: "undo a de-accreditation", expect: { layer: "registry", any: ["accreditationSerial"] } }, async () => {
      const Y = await world.addIssuer("Yrevoked");
      const first = await L.latestAccreditation(Y.did);
      await accreditIssuer(world.governance, L, world.clock, { did: Y.did, controller: Y.controller }, { status: "revoked" });
      try {
        await L.publishAccreditation(world.governance.account, Y.did, first!.statement, first!.signature);
      } catch (e) {
        const { registryCheckOf } = await import("@pqid/v4/ledger");
        return { accepted: false, stoppedBy: { layer: "registry" as Layer, checks: [registryCheckOf(e) ?? "unknown"] }, detail: (e as Error).message.slice(0, 300) };
      }
      const yh = await world.addHolder();
      const vcY = await world.issue(Y, yh, { birthDate: 19600101 });
      await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
      await world.publishEpoch(Y);
      return ver(held(yh, Y, vcY), V, {});
    });

    await rec.route("RA-d replay of an older genuine accreditation with a higher declared serial", { attacker: "governance EVM account holder", goal: "undo a de-accreditation", expect: { layer: "verifier", any: ["accreditation"] } }, async () => {
      const Y2 = await world.addIssuer("Y2revoked");
      const y2h = await world.addHolder();
      const vcY2 = await world.issue(Y2, y2h, { birthDate: 19600101 });
      await world.publishEpoch(Y2);
      const first = await L.latestAccreditation(Y2.did);
      await accreditIssuer(world.governance, L, world.clock, { did: Y2.did, controller: Y2.controller }, { status: "revoked" });
      const cur = await L.latestAccreditation(Y2.did);
      await L.publishAccreditation(world.governance.account, Y2.did, first!.statement, first!.signature, { signedSerial: (cur!.signedSerial ?? 0) + 1 });
      return ver(held(y2h, Y2, vcY2), V, {});
    });
    await rec.route("RA-f holder of an issuer that governance de-accredited", { attacker: "holder", goal: "keep presenting after de-accreditation", expect: { layer: "verifier", any: ["accreditation"] } }, async () => {
      const F2 = await world.addIssuer("F2deaccredited");
      const f2h = await world.addHolder();
      const vcF2 = await world.issue(F2, f2h, { birthDate: 19600101 });
      await world.publishEpoch(F2);
      await accreditIssuer(world.governance, L, world.clock, { did: F2.did, controller: F2.controller }, { status: "revoked" });
      return ver(held(f2h, F2, vcF2), V, {});
    });
    await rec.route("RA-e revoked holder presents through the issuer's retired controller record after a rotation", { attacker: "revoked holder", goal: "evade revocation through the old record's frozen anchor", expect: { layer: "verifier", any: ["accreditation"] } }, async () => {
      const R2 = await world.addIssuer("R2rotating");
      const rv2 = await world.addHolder();
      const vcR2 = await world.issue(R2, rv2, { birthDate: 19700101 });
      await world.publishEpoch(R2);
      const oldController = R2.controller;
      const oldW = issuanceWitnessV4(R2, vcR2.credID);
      const oldRev = revocationWitnessV4(R2, vcR2.credID);
      const acct = await L.newRoleAccount("R2rotating:new-controller");
      Object.assign(R2, { account: acct, controller: acct.address.toLowerCase(), anchored: null, signed: [] });
      await registerWithPop(L, R2);
      await accreditIssuer(world.governance, L, world.clock, { did: R2.did, controller: R2.controller }, { skipPopCheck: cfg.governanceSkipPop });
      revokeCredentialV4(R2, vcR2.credID);
      await world.publishEpoch(R2);
      return ver(held(rv2, R2, vcR2), V, { statement: oldW.statement, path: oldW.path, rev: oldRev, issuerController: oldController });
    });
    rec.begin("DE", "Holder of an issuer whose DID record was deactivated", "attack");
    await rec.route("DE-a issuer deactivates its record; its holder keeps presenting", { attacker: "holder", goal: "present under a deactivated issuer record", expect: { layer: "verifier", any: ["issuerRecord", "issuerPop"] } }, async () => {
      const D2 = await world.addIssuer("D2deactivated");
      const d2h = await world.addHolder();
      const vcD2 = await world.issue(D2, d2h, { birthDate: 19700101 });
      await world.publishEpoch(D2);
      await L.deactivateDid(D2.account, D2.did);
      return ver(held(d2h, D2, vcD2), V, {});
    });

    // ------------------------------------------------------------------ A8 anchor writer
    rec.begin("A8", "Adversary with issuer C's controller EVM key anchors its own root and signature", "attack");
    await rec.route("A8-a forged leaf under the adversary-anchored root", { attacker: "holder of C's controller EVM key", goal: "forged credential", expect: { layer: "verifier", any: ["epochSignature"] } }, async () => {
      const cred = { ...vcC.credential, birthDate: 19500101 };
      const id = randomBytes(32);
      const p = await attackerTree(await leafFor(C, cred, id, holderC.holderCommit));
      const k = mlDsaKeygen();
      await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
      await world.syncChainTime();
      const now = world.clock.nowSec();
      const cur = await L.currentEpoch(C.did, C.controller);
      const fields = {
        issuer: C.did, controller: C.controller, chainId: await L.chainId(), registry: L.addresses.issuanceRootRegistry.toLowerCase(),
        epoch: Number(cur.epoch) + 1, root: p.root, revRoot: C.rev.root().toString(), notBefore: now, notAfter: now + EPOCH_WINDOW_SEC,
        fromDate: utcDateOf(now), toDate: utcDateOf(now + EPOCH_WINDOW_SEC),
      };
      const st: EpochStatementV4 = { ...fields, signature: mlDsaSign(k.privateKey, epochMessage(fields)).toString("hex") };
      await L.publishEpoch(C.account, { did: C.did, epoch: st.epoch, root: BigInt(st.root), revRoot: BigInt(st.revRoot), notBefore: st.notBefore, notAfter: st.notAfter, sigHash: sigHashOf(st.signature) });
      return ver(held(holderC, C, vcC), V, { credId: id, credential: cred, path: p, statement: st, rev: C.rev.nonMembershipWitness(revKeyFromCredId(id)) });
    });

    // ------------------------------------------------------------------ RL relay variants
    rec.begin("RL", "Relay variants (ML-KEM session to the verifier's registered key)", "attack");
    const pRL = { ...policy18, threshold: 21 };
    await rec.route("RL-a passive capture: read the reply without the KEM secret", { attacker: "eavesdropper", goal: "read the presentation", expect: { layer: "transport", any: ["aeadConfidentiality"] } }, async () => {
      const request = await req(V, pRL);
      const { reply } = await adult.present(request, { callerOrigin: V.opts.identity.origin });
      // The eavesdropper sees request, the registered KEM key and the ciphertext, so it can
      // compute the transcript; it lacks only the ML-KEM shared secret.
      const kemPk = (await L.latestKemKey(V.did, V.opts.identity.controller))!.kemPk;
      const T = transcriptHash(request, kemPk, Buffer.from(reply.ct, "hex"));
      const prk = hkdfSha256Extract(T, randomBytes(32));
      const key = hkdfSha256Expand(prk, "pqid:v4:aead-key", 32);
      const iv = hkdfSha256Expand(prk, "pqid:v4:aead-iv", 12);
      const box = Buffer.from(reply.box, "hex");
      const pt = aes256gcmOpen(key, iv, T, box.subarray(0, box.length - 16), box.subarray(box.length - 16));
      return { accepted: pt !== null, stoppedBy: { layer: "transport" as Layer, checks: pt === null ? ["aeadConfidentiality"] : [] } };
    });
    await rec.route("RL-b captured reply replayed later", { attacker: "eavesdropper", goal: "replay", expect: { layer: "verifier", any: ["sessionKnown"] } }, async () => {
      const h = await honest(adult, V, pRL);
      return fromDecision(await V.verifyReply(h.reply));
    });
    await rec.route("RL-c relay presents its own verifier identity to the victim", { attacker: "relay (registered verifier M)", goal: "authenticate as the victim at V", expect: { layer: "verifier", any: ["nonceBinding", "stmtCode"] } }, async () => {
      const rM = await M.newRequest(pRL);
      const toM = await adult.present(rM, { callerOrigin: M.opts.identity.origin }); // victim answers M
      const opened = verifierOpenReply(M.sessions, M.opts.identity.kem.privateKey, M.opts.identity.kem.publicKey, toM.reply);
      if (!opened.ok) throw new Error("relay could not open its own session");
      const sV = await attackerSession(world, V, await req(V, pRL));
      return fromDecision(await V.verifyReply(walletSealReply(sV, opened.presentation)));
    });
    await rec.route("RL-d1 relay adds its own KEM key to the request", { attacker: "relay", goal: "make the wallet encrypt to the relay", expect: { layer: "wallet", any: ["requestShape"] } }, async () => {
      const r = await req(V, pRL);
      const tampered = { ...r, kemPk: mlKemKeygen().publicKey.toString("hex") } as unknown as ProofRequestV4;
      try {
        await adult.present(tampered, { callerOrigin: V.opts.identity.origin });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        // With requestShape removed, the session module's strict request schema still refuses.
        if (!(e instanceof Error) || e.constructor.name === "WalletRefusal") return fromRefusal(e);
        return { accepted: false, stoppedBy: { layer: "wallet" as Layer, checks: ["sessionSchema"] }, detail: e.message.slice(0, 200) };
      }
    });
    await rec.route("RL-d2 relay forwards V's request and tries to read the reply with its own KEM key", { attacker: "relay", goal: "read the victim's reply", expect: { layer: "transport", any: ["kemKeyFromChain"] } }, async () => {
      const r = await req(V, pRL);
      const { reply } = await adult.present(r, { callerOrigin: V.opts.identity.origin });
      const relayKem = mlKemKeygen();
      const relayView = verifierOpenReply(M.sessions, relayKem.privateKey, relayKem.publicKey, reply);
      return { accepted: relayView.ok, stoppedBy: { layer: "transport" as Layer, checks: relayView.ok ? [] : ["kemKeyFromChain"] }, detail: `relay open: ${relayView.ok ? "ok" : relayView.error}` };
    });
    await rec.route("RL-e relay lowers the threshold (21 -> 18) before forwarding", { attacker: "relay", goal: "pass V's stricter policy", expect: { layer: "verifier", any: ["transcriptDecrypts"] } }, async () => {
      const r = await req(V, pRL);
      const altered = { ...r, policy: { ...r.policy, threshold: 18 } };
      const { reply } = await minorOrAdult(adult).present(altered, { callerOrigin: V.opts.identity.origin });
      return fromDecision(await V.verifyReply(reply));
    });
    rec.begin("KL1", "Real-time relay forwarding V's genuine request unchanged and the reply back", "known-limitation");
    await rec.route("RL-f victim's honest wallet answers the relayed request", { attacker: "real-time relay", goal: "authenticate as the victim at V", expect: { layer: "accepted", any: [] } }, async () => {
      const r = await req(V, pRL);
      const { reply } = await adult.present(r, { callerOrigin: M.opts.identity.origin }); // no origin binding
      return fromDecision(await V.verifyReply(reply));
    });
    rec.begin("RL-f+", "Same relay against a wallet with (modelled) origin binding", "attack");
    await rec.route("RL-f with origin binding: caller origin is the relay's", { attacker: "real-time relay", goal: "authenticate as the victim at V", expect: { layer: "wallet", any: ["originBinding"] } }, async () => {
      try {
        const r = await req(V, pRL);
        await originBound.present(r, { callerOrigin: M.opts.identity.origin });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return fromRefusal(e);
      }
    });

    // ------------------------------------------------------------------ KEM rollback, origin, controller rotation (B5 REG-5, REG-6, REG-1)
    rec.begin("RL-g", "Verifier controller EVM account re-posts a retired KEM key statement", "attack");
    await rec.route("RL-g re-post the previous KEM statement after a rotation", { attacker: "holder of the verifier's controller EVM key", goal: "make wallets encrypt to a retired (leaked) KEM key", expect: { layer: "registry", any: ["kemMonotonic"] } }, async () => {
      const VK = await world.addVerifier("VK");
      const id = VK.opts.identity;
      const old = await L.latestKemKey(id.did, id.controller);
      if (!old) throw new Error("internal: no KEM key");
      id.kem = mlKemKeygen();
      await world.advance(60);
      await world.publishKemKey(id); // rotation
      try {
        await L.publishKemKey(id.account, { did: id.did, kemPk: old.kemPk, statement: old.statement, signature: old.signature });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        const { registryCheckOf } = await import("@pqid/v4/ledger");
        return { accepted: false, stoppedBy: { layer: "registry" as Layer, checks: [registryCheckOf(e) ?? "unknown"] }, detail: (e as Error).message.slice(0, 200) };
      }
    });
    rec.begin("SQ-d", "Verifier record registered with an origin its proof of possession did not sign", "attack");
    await rec.route("SQ-d controller EVM account registers the verifier DID under a relay origin", { attacker: "holder of a verifier controller EVM key", goal: "pass wallet origin binding from a relay origin", expect: { layer: "wallet", any: ["verifierPop"] } }, async () => {
      const { publicKey, privateKey } = mlDsaKeygen();
      const account = await L.newRoleAccount("verifier:origin-swap");
      const did = didFromPublicKey(publicKey);
      const popNonce = randomBytes(32).toString("hex");
      const signedOrigin = "https://genuine.verifier.example";
      const msg = didPopMessage({ did, controller: account.address.toLowerCase(), chainId: await L.chainId(), registry: L.addresses.didRegistry.toLowerCase(), nonce: popNonce, origin: signedOrigin });
      await L.registerDid(account, { did, pk: publicKey, popNonce, popSig: mlDsaSign(privateKey, msg), origin: M.opts.identity.origin });
      const identity = { label: "origin-swap", did, pk: publicKey, sk: privateKey, kem: mlKemKeygen(), account, controller: account.address.toLowerCase(), origin: M.opts.identity.origin };
      await world.publishKemKey(identity);
      const VO = new VerifierV4Class({ ledger: L, identity, pinnedGovernancePk: world.governance.pk, clock: world.clock });
      try {
        await originBound.present(await VO.newRequest(pRL), { callerOrigin: M.opts.identity.origin });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return fromRefusal(e);
      }
    });
    rec.begin("C4", "Issuer rotates its controller EVM account; credentials naming the old controller keep working (B5 REG-1)", "control");
    await rec.route("C4-a holder presents after the issuer's controller rotation", { attacker: "none", goal: "honest presentation", expect: { layer: "accepted", any: [] } }, async () => {
      const R = await world.addIssuer("Rrotating");
      const rh = await world.addHolder();
      await world.issue(R, rh, { birthDate: 19800101 });
      await world.publishEpoch(R);
      const acct = await L.newRoleAccount("Rrotating:new-controller");
      Object.assign(R, { account: acct, controller: acct.address.toLowerCase(), anchored: null, signed: [] });
      await registerWithPop(L, R);
      await accreditIssuer(world.governance, L, world.clock, { did: R.did, controller: R.controller }, { skipPopCheck: cfg.governanceSkipPop });
      await world.publishEpoch(R); // epoch 1 of the new record, same tree
      return fromDecision((await honest(rh, V, policy18)).decision);
    });

    rec.begin("RL-h", "Verifier controller EVM account posts a KEM key statement the verifier did not sign", "attack");
    await rec.route("RL-h KEM statement for the attacker's KEM key, signed with another ML-DSA key", { attacker: "holder of the verifier's controller EVM key", goal: "make wallets encrypt to a key the attacker holds", expect: { layer: "wallet", any: ["verifierKemKey"] } }, async () => {
      const VH = await world.addVerifier("VH");
      const id = VH.opts.identity;
      const evil = mlKemKeygen();
      await world.advance(2);
      const now = world.clock.nowSec();
      const statement = verifierKemMessage({ verifier: id.did, controller: id.controller, chainId: await L.chainId(), registry: L.addresses.verifierKemRegistry.toLowerCase(), kemAlg: KEM_ALG, kemPkSha3: sha3_256(evil.publicKey).toString("hex"), notBefore: now, notAfter: now + 86400 });
      await L.publishKemKey(id.account, { did: id.did, kemPk: evil.publicKey, statement, signature: mlDsaSign(mlDsaKeygen().privateKey, statement) });
      const request = await VH.newRequest(pRL);
      try {
        const { reply } = await adult.present(request, { callerOrigin: id.origin });
        const ct = Buffer.from(reply.ct, "hex");
        const T = transcriptHash(request, evil.publicKey, ct);
        const sec = deriveSessionSecrets(mlKemDecaps(evil.privateKey, ct), T);
        const box = Buffer.from(reply.box, "hex");
        const pt = aes256gcmOpen(sec.key, sec.iv, T, box.subarray(0, box.length - 16), box.subarray(box.length - 16));
        return { accepted: pt !== null, stoppedBy: { layer: "transport" as Layer, checks: pt === null ? ["aeadConfidentiality"] : [] }, detail: pt ? "the attacker decrypted the reply" : "reply not readable with the attacker's key" };
      } catch (e) {
        return fromRefusal(e);
      }
    });

    rec.begin("RL-i", "Retired KEM statement re-posted with a higher declared notBefore", "attack");
    await rec.route("RL-i re-post the retired KEM statement declaring a notBefore above the stored one", { attacker: "holder of the verifier's controller EVM key", goal: "make wallets encrypt to a retired (leaked) KEM key", expect: { layer: "wallet", any: ["verifierKemKey"] } }, async () => {
      const VK2 = await world.addVerifier("VK2");
      const id = VK2.opts.identity;
      const oldKem = id.kem;
      const old = await L.latestKemKey(id.did, id.controller);
      id.kem = mlKemKeygen();
      await world.advance(60);
      await world.publishKemKey(id); // rotation
      const cur = await L.latestKemKey(id.did, id.controller);
      await L.publishKemKey(id.account, { did: id.did, kemPk: old!.kemPk, statement: old!.statement, signature: old!.signature }, { notBefore: (cur!.notBefore ?? 0) + 1 });
      const request = await VK2.newRequest(pRL);
      try {
        const { reply } = await adult.present(request, { callerOrigin: id.origin });
        const ct = Buffer.from(reply.ct, "hex");
        const T = transcriptHash(request, oldKem.publicKey, ct);
        let pt: Buffer | null = null;
        try {
          const sec = deriveSessionSecrets(mlKemDecaps(oldKem.privateKey, ct), T);
          const box = Buffer.from(reply.box, "hex");
          pt = aes256gcmOpen(sec.key, sec.iv, T, box.subarray(0, box.length - 16), box.subarray(box.length - 16));
        } catch {
          pt = null;
        }
        return { accepted: pt !== null, stoppedBy: { layer: "transport" as Layer, checks: pt === null ? ["aeadConfidentiality"] : [] }, detail: pt ? "the retired key decrypted the reply" : "reply not readable with the retired key" };
      } catch (e) {
        return fromRefusal(e);
      }
    });

    rec.begin("RG", "Registry write rules (writes that would corrupt or roll back a record)", "attack");
    const RGI = await world.addIssuer("RGissuer"); // own issuer: a write accepted in a mutant run cannot disturb other routes
    await world.publishEpoch(RGI);
    const regTry = async (fn: () => Promise<unknown>) => {
      try {
        await fn();
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        const { registryCheckOf } = await import("@pqid/v4/ledger");
        return { accepted: false, stoppedBy: { layer: "registry" as Layer, checks: [registryCheckOf(e) ?? "unknown"] }, detail: (e as Error).message.slice(0, 200) };
      }
    };
    const rgCur = async () => L.currentEpoch(RGI.did, RGI.controller);
    await rec.route("RG-a stranger anchors an epoch for the issuer's DID", { attacker: "any EVM account", goal: "anchor a root for a DID it does not control", expect: { layer: "registry", any: ["controllerOnly"] } }, async () => {
      const stranger = await L.newRoleAccount("rg-stranger");
      await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
      const cur = await rgCur();
      const now = world.clock.nowSec();
      void cur;
      // epoch 1: the first epoch of (did, stranger), so only controllerOnly can refuse it
      return regTry(() => L.publishEpoch(stranger, { did: RGI.did, epoch: 1, root: 1n, revRoot: 1n, notBefore: now, notAfter: now + 3600, sigHash: sigHashOf("00".repeat(2420)) }));
    });
    await rec.route("RG-b the controller re-anchors the current epoch number (rollback)", { attacker: "holder of the issuer's controller EVM key", goal: "replace or roll back an anchored epoch", expect: { layer: "registry", any: ["epochIncrement"] } }, async () => {
      await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
      const cur = await rgCur();
      const now = world.clock.nowSec();
      return regTry(() => L.publishEpoch(RGI.account, { did: RGI.did, epoch: Number(cur.epoch), root: 1n, revRoot: 1n, notBefore: now, notAfter: now + 3600, sigHash: sigHashOf("00".repeat(2420)) }));
    });
    await rec.route("RG-c the controller anchors a window longer than the registry maximum", { attacker: "holder of the issuer's controller EVM key", goal: "a statement that stays valid for days", expect: { layer: "registry", any: ["windowBounds"] } }, async () => {
      await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
      const cur = await rgCur();
      const now = world.clock.nowSec();
      return regTry(() => L.publishEpoch(RGI.account, { did: RGI.did, epoch: Number(cur.epoch) + 1, root: 1n, revRoot: 1n, notBefore: now, notAfter: now + 7 * 86400, sigHash: sigHashOf("00".repeat(2420)) }));
    });
    await rec.route("RG-d a second registration of the same (did, controller) record", { attacker: "holder of the issuer's controller EVM key", goal: "replace the record's key", expect: { layer: "registry", any: ["recordUnique"] } }, async () => {
      const recRG = await L.resolveDidRecord(RGI.did, RGI.controller);
      const popSig = await L.getPopSignature(RGI.did, RGI.controller);
      return regTry(() => L.registerDid(RGI.account, { did: RGI.did, pk: mlDsaKeygen().publicKey, popNonce: recRG!.popNonce, popSig, origin: "" }));
    });
    await rec.route("RG-e an issuer account posts its own accreditation statement", { attacker: "issuer's controller EVM account", goal: "self-accreditation on chain", expect: { layer: "registry", any: ["governanceWriter"] } }, async () => {
      const latest = await L.latestAccreditation(RGI.did);
      // a fresh statement with the next serial, so only governanceWriter can refuse it
      const { type: _t, ...fields } = JSON.parse(Buffer.from(latest!.statement).toString("utf8")) as Record<string, unknown>;
      const st = accreditationMessage({ ...(fields as Parameters<typeof accreditationMessage>[0]), serial: Number(fields["serial"]) + 1 });
      return regTry(() => L.publishAccreditation(RGI.account, RGI.did, st, mlDsaSign(mlDsaKeygen().privateKey, st)));
    });

    // ------------------------------------------------------------------ review round 2 records
    const R5 = await world.addIssuer("R5renewals");
    const ren = await world.addHolder();
    await world.issue(R5, ren, { birthDate: 19850101, issuedDate: addDays(today, -100), expiryDate: addDays(today, -1) });
    await world.issue(R5, ren, { birthDate: 19850101 });
    await world.publishEpoch(R5);
    rec.begin("C5", "Holder with an expired credential and its renewal of the same type (review round 2, L5)", "control");
    await rec.route("C5-a renewal presented although the first held credential expired", { attacker: "none", goal: "honest presentation", expect: { layer: "accepted", any: [] } }, async () =>
      fromDecision((await honest(ren, V, policy18)).decision)
    );
    rec.begin("PV15", "Holder whose leaf is newer than the published blob (review round 2, P1)", "privacy");
    await rec.route("PV15 the wallet's refusal carries no leaf index", { attacker: "verifier", goal: "learn the holder's position in the issuance tree", expect: { layer: "wallet", any: ["anchorMatches"] } }, async () => {
      const np = await world.addHolder();
      const vcNp = await world.issue(R5, np, { birthDate: 19850101 }); // after R5's last anchor
      const idx = R5.leafIndexByCredId.get(vcNp.credID);
      try {
        await np.present(await req(V), { callerOrigin: V.opts.identity.origin });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] }, detail: "unexpected reply" };
      } catch (e) {
        const msg = (e as Error).message;
        const leaks = !(e instanceof WalletRefusal) || /\d/.test(msg);
        return leaks ? { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] }, detail: `refusal text carries data (leaf ${idx}): ${msg.slice(0, 120)}` } : fromRefusal(e);
      }
    });
    rec.begin("KL5", "Credential lending: the holder gives another person its holder secret and credential", "known-limitation");
    await rec.route("KL5 lent credential presented by another person", { attacker: "holder and borrower together", goal: "let someone else pass as the holder", expect: { layer: "accepted", any: [] } }, async () =>
      fromDecision((await verifierRoute(world, V, await req(V), held(adult, A, vcAdult), {})).decision)
    );
    rec.begin("KL6", "Issuer splits its holders across several accredited DIDs", "known-limitation");
    await rec.route("KL6 holder of a small, separately accredited DID of one issuer", { attacker: "issuer", goal: "smaller anonymity sets", expect: { layer: "accepted", any: [] } }, async () => {
      const K6 = await world.addIssuer("K6split");
      const k6h = await world.addHolder();
      await world.issue(K6, k6h, { birthDate: 19800101 });
      await world.publishEpoch(K6);
      return fromDecision((await honest(k6h, V, policy18)).decision);
    });

    // ------------------------------------------------------------------ privacy
    rec.begin("PV1", "Four holders present to one verifier on one day: identical verifier views", "privacy");
    await rec.route("PV1 views equal except the session nonce", { attacker: "colluding verifier", goal: "link holders", expect: { layer: "wallet", any: ["identicalViews"] } }, async () => {
      const views: string[] = [];
      for (const h of [adult, extra[0]!, extra[1]!, late]) {
        const x = await honest(h, V, policy18);
        const s = [...x.presentation.publicSignals];
        s[3] = "nonce";
        views.push(JSON.stringify({ s, st: x.presentation.epochStatement, d: x.presentation.issuerDid, c: x.presentation.issuerController }));
      }
      const same = views.every((v) => v === views[0]);
      return { accepted: !same, stoppedBy: { layer: "wallet" as Layer, checks: same ? ["identicalViews"] : [] } };
    });
    const privacyRefusal = async (label: string, holder: HolderWalletV4, source: HolderWalletV4["credentials"][number]["source"], expect: string[]) =>
      rec.route(label, { attacker: "issuer tagging one holder", goal: "link the holder", expect: { layer: "wallet", any: expect } }, async () => {
        const hc = holder.credentials[0]!;
        const saved = hc.source;
        hc.source = source;
        try {
          await holder.present(await req(V), { callerOrigin: V.opts.identity.origin });
          return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
        } catch (e) {
          return fromRefusal(e);
        } finally {
          hc.source = saved;
        }
      });
    const base = world.onlineSource(A);
    rec.begin("PV2", "Issuer serves one holder re-signed statement bytes", "privacy");
    await privacyRefusal("PV2 re-signed statement (different ML-DSA bytes)", extra[0]!, {
      ...base,
      issuance: (id) => {
        const s = base.issuance(id);
        const { signature: _x, ...f } = s.statement;
        return { ...s, statement: { ...f, signature: mlDsaSign(A.sk, epochMessage(f)).toString("hex") } };
      },
    }, ["anchorMatches"]);
    rec.begin("PV3", "Holder offered a path to an older statement after a newer anchor", "privacy");
    await privacyRefusal("PV3 older statement and path", extra[0]!, { ...base, issuance: () => ({ path: oldPathRevoked, statement: oldStatementA }) }, ["anchorMatches"]);
    rec.begin("PV4", "Statement with an extra per-holder field", "privacy");
    await privacyRefusal("PV4 extra field", extra[0]!, { ...base, issuance: (id) => { const s = base.issuance(id); return { ...s, statement: { ...s.statement, tag: "holder-17" } as unknown as EpochStatementV4 }; } }, ["anchorMatches"]);
    rec.begin("PV6", "Issuer re-anchors immediately to give one holder its own epoch", "privacy");
    await rec.route("PV6 immediate re-anchor", { attacker: "issuer", goal: "per-holder epoch", expect: { layer: "registry", any: ["anchorCadence"] } }, async () => {
      await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
      await world.publishEpoch(A); // a fresh epoch now
      await world.advance(5); // ... and five seconds later, another for one holder
      const st = await signEpochV4(A, L, world.clock);
      try {
        await anchorEpochV4(A, L, st);
        await world.refreshPublication(A); // keep later routes consistent in a mutant run
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        const { registryCheckOf } = await import("@pqid/v4/ledger");
        return { accepted: false, stoppedBy: { layer: "registry" as Layer, checks: [registryCheckOf(e) ?? "unknown"] }, detail: (e as Error).message.slice(0, 200) };
      }
    });
    rec.begin("PV8", "Credential from an unaccredited per-holder issuer DID", "privacy");
    await rec.route("PV8 honest wallet checks accreditation", { attacker: "issuer", goal: "per-holder DID", expect: { layer: "wallet", any: ["accreditation", "issuerPop"] } }, async () => {
      const Z = await world.addIssuer("Zper", { accredit: false });
      const zh = await world.addHolder();
      await world.issue(Z, zh, { birthDate: 19700101 });
      await world.publishEpoch(Z);
      try {
        await zh.present(await req(V), { callerOrigin: V.opts.identity.origin });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return fromRefusal(e);
      }
    });

    rec.begin("PV5", "Served statement with permuted key order", "privacy");
    await rec.route("PV5 permuted key order: verifier view identical to the canonical one", { attacker: "issuer tagging one holder", goal: "link the holder", expect: { layer: "wallet", any: ["identicalViews"] } }, async () => {
      const h = extra[1]!;
      const hc = h.credentials[0]!;
      const saved = hc.source;
      const normal = (await honest(h, V, policy18)).presentation.epochStatement;
      hc.source = {
        ...saved,
        issuance: (id) => {
          const x = saved.issuance(id);
          const rev = Object.fromEntries(Object.entries(x.statement).reverse()) as unknown as EpochStatementV4;
          return { ...x, statement: rev };
        },
      };
      try {
        const tagged = (await honest(h, V, policy18)).presentation.epochStatement;
        const same = JSON.stringify(tagged) === JSON.stringify(normal);
        return { accepted: !same, stoppedBy: { layer: "wallet" as Layer, checks: same ? ["identicalViews"] : [] } };
      } catch (e) {
        return fromRefusal(e);
      } finally {
        hc.source = saved;
      }
    });
    rec.begin("PV7", "Per-holder revocation root anchored right away", "privacy");
    await rec.route("PV7 second revocation root five seconds after an anchor", { attacker: "issuer", goal: "per-holder revocation root", expect: { layer: "registry", any: ["anchorCadence"] } }, async () => {
      const P7 = await world.addIssuer("P7"); // own issuer: an accepted mutant anchor cannot disturb later routes
      await world.publishEpoch(P7);
      await world.advance(5);
      const cur = await L.currentEpoch(P7.did, P7.controller);
      const now = world.clock.nowSec();
      try {
        await L.publishEpoch(P7.account, { did: P7.did, epoch: Number(cur.epoch) + 1, root: BigInt(cur.root), revRoot: BigInt(cur.revRoot) + 1n, notBefore: now, notAfter: now + 3600, sigHash: sigHashOf("00".repeat(2420)) });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        const { registryCheckOf } = await import("@pqid/v4/ledger");
        return { accepted: false, stoppedBy: { layer: "registry" as Layer, checks: [registryCheckOf(e) ?? "unknown"] }, detail: (e as Error).message.slice(0, 200) };
      }
    });
    rec.begin("PV9", "Second controller record for the same DID (per-holder record)", "privacy");
    await rec.route("PV9 credential naming a second, PoP-valid controller of issuer A", { attacker: "issuer", goal: "per-holder controller record", expect: { layer: "wallet", any: ["accreditation", "anchorMatches"] } }, async () => {
      const Q3 = await L.newRoleAccount("second-controller");
      const AQ = await createIssuerV4(L, "A-second-controller");
      Object.assign(AQ, { did: A.did, pk: A.pk, sk: A.sk, account: Q3, controller: Q3.address.toLowerCase() });
      await registerWithPop(L, AQ); // valid PoP: A's own key signs for the second controller
      const ph = await world.addHolder();
      await world.issue(AQ, ph, { birthDate: 19700101 });
      await world.publishEpoch(AQ);
      try {
        await ph.present(await req(V), { callerOrigin: V.opts.identity.origin });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return fromRefusal(e);
      }
    });
    rec.begin("PV10", "Epoch signature re-encoded as a per-holder tag (upper case, trailing data)", "privacy");
    await privacyRefusal("PV10 upper-case signature with a trailing tag", extra[0]!, {
      ...base,
      issuance: (id) => {
        const x = base.issuance(id);
        return { ...x, statement: { ...x.statement, signature: x.statement.signature.toUpperCase() + "7a" } };
      },
    }, ["anchorMatches"]);
    rec.begin("PV11", "Extra `type` key in the served statement", "privacy");
    await privacyRefusal("PV11 statement with type = the epoch statement type", extra[0]!, {
      ...base,
      issuance: (id) => {
        const x = base.issuance(id);
        return { ...x, statement: { ...x.statement, type: "pqid:epoch:v4" } as unknown as EpochStatementV4 };
      },
    }, ["anchorMatches"]);
    rec.begin("PV12", "Published-tree wallet: does the issuer see a request when the holder presents?", "privacy");
    await rec.route("PV12 issuer contacts during a presentation (published-tree default)", { attacker: "issuer colluding with the verifier", goal: "link a presentation to a credential", expect: { layer: "wallet", any: ["publishedTree"] } }, async () => {
      // Count every read of issuer A's service state (the index map and the anchored
      // snapshot that its online path and revocation services use) during one presentation.
      let touches = 0;
      const origMap = A.leafIndexByCredId;
      const counting = new Map(origMap);
      const get = counting.get.bind(counting);
      counting.get = (k: string) => (touches++, get(k));
      A.leafIndexByCredId = counting;
      const desc = Object.getOwnPropertyDescriptor(A, "anchored")!;
      let anchoredVal = A.anchored;
      Object.defineProperty(A, "anchored", { configurable: true, enumerable: true, get: () => (touches++, anchoredVal), set: (v) => void (anchoredVal = v) });
      try {
        await honest(adult, V, policy18);
      } finally {
        A.leafIndexByCredId = origMap;
        Object.defineProperty(A, "anchored", { ...desc, value: anchoredVal });
      }
      return { accepted: touches > 0, stoppedBy: { layer: "wallet" as Layer, checks: touches > 0 ? [] : ["publishedTree"] }, detail: `reads of the issuer's service state during the presentation: ${touches}` };
    });
    rec.begin("KL4", "Online mode: the issuer's services see the credID at presentation time", "known-limitation");
    await rec.route("KL4 online-mode wallet contacts the issuer while presenting", { attacker: "issuer colluding with the verifier", goal: "link a presentation to a credential", expect: { layer: "accepted", any: [] } }, async () => {
      const seen: string[] = [];
      const online = world.onlineSource(A);
      const hc = extra[0]!.credentials[0]!;
      const saved = hc.source;
      hc.source = { issuance: (id) => (seen.push(id), online.issuance(id)), revocation: (id) => (seen.push(id), online.revocation(id)) };
      try {
        await honest(extra[0]!, V, policy18);
      } finally {
        hc.source = saved;
      }
      return { accepted: seen.length > 0, stoppedBy: { layer: "accepted" as Layer, checks: [] }, detail: `issuer service calls naming the credID during the presentation: ${seen.length}` };
    });
    rec.begin("PV13", "Issuer plants a covert-type credential in one wallet as a tag", "privacy");
    await rec.route("PV13 wallet refuses a credential type outside its allow-list at issuance", { attacker: "issuer", goal: "tag one holder with a covert type", expect: { layer: "wallet", any: ["typeAllowed"] } }, async () => {
      try {
        await world.issue(A, extra[1]!, { birthDate: 19920202, typeId: "pqid:type:covert-tag:v1" });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return fromRefusal(e);
      }
    });

    rec.begin("PV14", "Deployment whose registry allows an anchor every second (per-holder epochs)", "privacy");
    await rec.route("PV14 honest wallet refuses a registry with a 1 s minimum anchor interval", { attacker: "deployer", goal: "per-holder epochs", expect: { layer: "wallet", any: ["anchorCadence"] } }, async () => {
      const L2 = await LedgerV4.deploy(world.anvil.rpcUrl, { governanceAddress: world.governance.account.address, minAnchorIntervalSec: 1, maxWindowSec: MAX_EPOCH_WINDOW_SEC });
      await world.syncChainTime();
      const I2 = await createIssuerV4(L2, "I2-short-cadence");
      await registerWithPop(L2, I2);
      await accreditIssuer(world.governance, L2, world.clock, { did: I2.did, controller: I2.controller }, { skipPopCheck: cfg.governanceSkipPop });
      const vk = mlDsaKeygen();
      const vkem = mlKemKeygen();
      const vacct = await L2.newRoleAccount("verifier:short-cadence");
      const vid = { label: "V-short", did: didFromPublicKey(vk.publicKey), pk: vk.publicKey, sk: vk.privateKey, kem: vkem, account: vacct, controller: vacct.address.toLowerCase(), origin: "https://short.verifier.example" };
      await registerWithPop(L2, vid, vid.origin);
      const now = world.clock.nowSec();
      const kst = verifierKemMessage({ verifier: vid.did, controller: vid.controller, chainId: await L2.chainId(), registry: L2.addresses.verifierKemRegistry.toLowerCase(), kemAlg: KEM_ALG, kemPkSha3: sha3_256(vkem.publicKey).toString("hex"), notBefore: now, notAfter: now + 86400 });
      await L2.publishKemKey(vacct, { did: vid.did, kemPk: vkem.publicKey, statement: kst, signature: mlDsaSign(vk.privateKey, kst) });
      const V2L = new VerifierV4Class({ ledger: L2, identity: vid, pinnedGovernancePk: world.governance.pk, clock: world.clock });
      const w2 = await HolderWalletV4Class.create({ ledger: L2, clock: world.clock, pinnedGovernancePk: world.governance.pk, disabledChecks: cfg.walletDisabled ? new Set(cfg.walletDisabled as never[]) : undefined });
      const vc2 = await issueCredentialV4(I2, { subject: w2.subject, holderCommit: w2.holderCommit, birthDate: 19800101, issuedDate: world.today });
      w2.add({ vc: vc2, issuerPk: I2.pk, source: { issuance: (x: string) => issuanceWitnessV4(I2, x), revocation: (x: string) => revocationWitnessV4(I2, x) } });
      await world.syncChainTime();
      await anchorEpochV4(I2, L2, await signEpochV4(I2, L2, world.clock));
      try {
        const { reply } = await w2.present(await V2L.newRequest(policy18), { callerOrigin: vid.origin });
        return fromDecision(await V2L.verifyReply(reply));
      } catch (e) {
        return fromRefusal(e);
      } finally {
        L2.destroy?.();
      }
    });

    // ------------------------------------------------------------------ baselines
    rec.begin("B0", "Revoked holder's honest wallet asks for a non-membership witness", "baseline");
    await rec.route("B0 issuer service refuses", { attacker: "none", goal: "", expect: { layer: "wallet", any: ["issuerServiceRefused"] } }, async () => {
      try {
        revocationWitnessV4(A, vcRevoked.credID);
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return { accepted: false, stoppedBy: { layer: "wallet" as Layer, checks: ["issuerServiceRefused"] }, detail: (e as Error).message };
      }
    });

    // ------------------------------------------------------------------ FA frozen anchor (moves time past every window)
    // Issuer F anchors, then revokes a holder but never anchors again (controller seized or
    // issuer offline): the revoked holder is the one who keeps presenting (B5 REG-9).
    const F = await world.addIssuer("Ffrozen");
    const fh = await world.addHolder();
    const vcF = await world.issue(F, fh, { birthDate: 19700101 });
    await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
    await world.publishEpoch(F);
    const fId = Buffer.from(vcF.credID, "hex");
    const fRev = F.anchored!.rev.nonMembershipWitness(revKeyFromCredId(fId)); // anchored (pre-revocation) opening
    revokeCredentialV4(F, vcF.credID); // revoked locally; no new epoch is anchored
    rec.begin("KL2", "Frozen anchor: revoked holder inside the last statement's window (bounded latency)", "known-limitation");
    await rec.route("FA-a before notAfter: revoked holder presents under the frozen anchor", { attacker: "revoked holder + frozen anchor", goal: "keep presenting", expect: { layer: "accepted", any: [] } }, async () =>
      fromDecision((await honest(fh, V, policy18)).decision)
    );
    rec.begin("FA", "Frozen anchor expires", "attack");
    {
      // One second past notAfter: the date stays the statement's toDate, so only the window fails.
      const base = Math.max(world.clock.nowSec(), Number(await L.blockTimestamp()));
      await world.advance(F.anchored!.statement.notAfter + 1 - base);
    }
    await rec.route("FA-b after notAfter: verifier rejects the frozen statement", { attacker: "revoked holder + frozen anchor", goal: "keep presenting", expect: { layer: "verifier", any: ["epochWindow"] } }, () =>
      ver(held(fh, F, vcF), V, { rev: fRev, statement: F.anchored!.statement, path: issuanceWitnessV4(F, vcF.credID).path })
    );
    await rec.route("FA-c after notAfter: honest wallet refuses", { attacker: "revoked holder + frozen anchor", goal: "keep presenting", expect: { layer: "wallet", any: ["epochWindow"] } }, async () => {
      try {
        await fh.present(await req(V), { callerOrigin: V.opts.identity.origin });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return fromRefusal(e);
      }
    });

    // ------------------------------------------------------------------ KL3 withheld de-accreditation (moves time 30 days)
    const G = await world.addIssuer("Gwithheld");
    const gh = await world.addHolder();
    const vcG = await world.issue(G, gh, { birthDate: 19700101 });
    await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
    await world.publishEpoch(G);
    rec.begin("KL3", "Governance's de-accreditation of G is withheld: G stays accepted inside its accreditation window", "known-limitation");
    await rec.route("KL3-a withheld de-accreditation, inside the accreditation window", { attacker: "governance EVM account holder withholding a statement", goal: "keep a de-accredited issuer accepted", expect: { layer: "accepted", any: [] } }, async () =>
      fromDecision((await honest(gh, V, policy18)).decision)
    );
    rec.begin("KL3-b", "Withheld de-accreditation: bounded by the accreditation window", "attack");
    await world.advance(MAX_ACCREDITATION_SEC + 60);
    await world.publishEpoch(G);
    await rec.route("KL3-b after the accreditation window: verifier rejects", { attacker: "governance EVM account holder withholding a statement", goal: "keep a de-accredited issuer accepted", expect: { layer: "verifier", any: ["accreditation"] } }, () => ver(held(gh, G, vcG), V, {}));

    // ------------------------------------------------------------------ LD leap day, midnight (last: jumps to 2027-02-28)
    // Fresh issuer and verifier after the jump (earlier accreditations have expired).
    const jumpTo = async (isoUtc: string) => {
      const target = Math.floor(Date.parse(isoUtc) / 1000);
      const base = Math.max(world.clock.nowSec(), Number(await L.blockTimestamp()));
      if (target <= base) throw new Error(`clock already past ${isoUtc}`);
      await world.advance(target - base);
    };
    // Next common year T with a standard threshold t such that T - t is a leap year.
    const isLeap = (y: number) => (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
    const nowYear = Math.floor(utcDateOf(world.clock.nowSec()) / 10000);
    let T = 0;
    let tLD = 0;
    for (let y = nowYear + 1; y < nowYear + 12 && !T; y++) {
      if (isLeap(y)) continue;
      const t = STANDARD_THRESHOLDS.find((x) => isLeap(y - x));
      if (t !== undefined) [T, tLD] = [y, t];
    }
    if (!T) throw new Error("no leap-day test year found");
    await jumpTo(`${T}-02-28T12:00:00Z`);
    const LI = await world.addIssuer("LD");
    const VL = await world.addVerifier("VL");
    const leap = await world.addHolder();
    const mid = await world.addHolder();
    const mid2 = await world.addHolder();
    const vcLeap = await world.issue(LI, leap, { birthDate: (T - tLD) * 10000 + 229 });
    await world.issue(LI, mid, { birthDate: 19900101 });
    await world.issue(LI, mid2, { birthDate: 19900101 });
    await world.publishEpoch(LI);
    const p15 = { ...policy18, threshold: tLD };
    const refusalOf = async (h: HolderWalletV4, v: VerifierV4, pol: typeof policy18) => {
      try {
        return fromDecision((await honest(h, v, pol)).decision);
      } catch (e) {
        return fromRefusal(e);
      }
    };
    rec.begin("LD", "29 February birth on 28 Feb and 1 Mar of a common year (D-010)", "control");
    await rec.route("LD-c age_lt t on 28 Feb (not yet t: accepted; permissive AGE_LT reading, D-010)", { attacker: "none", goal: "honest presentation", expect: { layer: "accepted", any: [] } }, () => refusalOf(leap, VL, { ...p15, predicate: "age_lt" }));
    rec.begin("LD-refuse", "Leap-day birth: honest wallet refuses age_gte t on 28 Feb (not an attack)", "baseline");
    await rec.route("LD-a age_gte t on 28 Feb: honest wallet refuses", { attacker: "none", goal: "boundary", expect: { layer: "wallet", any: ["predicateHolds"] } }, () => refusalOf(leap, VL, p15));
    rec.begin("LD-forge", "Leap-day birth: malicious wallet proves age_gte t on 28 Feb", "attack");
    await rec.route("LD-b age_gte t on 28 Feb with the attacker's generator", { attacker: "holder born 29 Feb", goal: "age_gte t one day early", expect: { layer: "circuit", any: ["G12_age"] } }, () => circ(held(leap, LI, vcLeap), VL, {}, p15));
    // Midnight: a session opened at 23:58 on the 28th is answered after a 00:01 re-anchor.
    await jumpTo(`${T}-02-28T23:58:00Z`);
    const openBefore = await VL.newRequest(policy18);
    await jumpTo(`${T}-03-01T00:01:00Z`);
    await world.publishEpoch(LI); // backdated notBefore keeps 2027-02-28 inside the new window
    rec.begin("C3", "Session opened before midnight, answered after a post-midnight re-anchor (B5 CIR-2)", "control");
    await rec.route("C3-a session across midnight and a re-anchor", { attacker: "none", goal: "honest presentation", expect: { layer: "accepted", any: [] } }, async () => {
      const { reply } = await mid.present(openBefore, { callerOrigin: VL.opts.identity.origin });
      return fromDecision(await VL.verifyReply(reply));
    });
    rec.begin("SD-d", "Verifier asks for the other acceptable date minutes after midnight (two-date probe)", "attack");
    await rec.route("SD-d second request for 1 Mar right after answering 28 Feb", { attacker: "verifier", goal: "answers for two dates: exact birth or expiry date", expect: { layer: "wallet-enforced", any: ["dateCurrent"] } }, async () => {
      try {
        await mid.present(await VL.newRequest(policy18), { callerOrigin: VL.opts.identity.origin });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return fromRefusal(e, "wallet-enforced");
      }
    });
    rec.begin("B4", "Honest verifier asks the other date minutes after midnight (D-017 cost; not a defence)", "baseline");
    await rec.route("B4 honest request for 1 Mar after the wallet answered 28 Feb at 00:01", { attacker: "none", goal: "honest presentation", expect: { layer: "wallet", any: ["dateCurrent"] } }, async () => {
      try {
        await mid.present(await VL.newRequest(policy18), { callerOrigin: VL.opts.identity.origin });
        return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] } };
      } catch (e) {
        return fromRefusal(e);
      }
    });
    rec.begin("SD-f", "Two requests with the two acceptable dates at the same moment (race)", "attack");
    await rec.route("SD-f concurrent requests for 28 Feb and 1 Mar right after midnight", { attacker: "verifier", goal: "answers for two dates: exact birth or expiry date", expect: { layer: "wallet-enforced", any: ["dateCurrent"] } }, async () => {
      const r1 = await VL.newRequest({ ...policy18, today: T * 10000 + 228 });
      const r2 = await VL.newRequest(policy18);
      const out = await Promise.allSettled([mid2.present(r1, { callerOrigin: VL.opts.identity.origin }), mid2.present(r2, { callerOrigin: VL.opts.identity.origin })]);
      const kinds = out.map((o) => (o.status === "fulfilled" ? "answered" : o.reason instanceof WalletRefusal ? o.reason.check : `error: ${String((o.reason as Error)?.message).slice(0, 80)}`));
      const dateRefused = kinds.filter((k) => k === "dateCurrent").length;
      if (dateRefused === 0) return { accepted: true, stoppedBy: { layer: "accepted" as Layer, checks: [] }, detail: `both dates reached the predicate: ${kinds.join(" | ")}` };
      return { accepted: false, stoppedBy: { layer: "wallet-enforced" as Layer, checks: ["dateCurrent"] }, detail: kinds.join(" | ") };
    });

    await jumpTo(`${T}-03-01T12:00:00Z`);
    rec.begin("LD", "29 February birth on 28 Feb and 1 Mar of a common year (D-010)", "control");
    await rec.route("LD-d age_gte t on 1 Mar: accepted", { attacker: "none", goal: "honest presentation", expect: { layer: "accepted", any: [] } }, () => refusalOf(leap, VL, p15));
    rec.begin("LD-refuse", "Leap-day birth: honest wallet refuses age_lt t on 1 Mar (not an attack)", "baseline");
    await rec.route("LD-e age_lt t on 1 Mar: honest wallet refuses", { attacker: "none", goal: "boundary", expect: { layer: "wallet", any: ["predicateHolds"] } }, () => refusalOf(leap, VL, { ...p15, predicate: "age_lt" }));

    // ------------------------------------------------------------------ output
    const out = summarize(rec, {
      durationSec: Math.round((Date.now() - t0) / 1000),
      artifacts: cfg.artifacts
        ? { mutant: true, r1cs: rel(cfg.artifacts.r1cs), keyLabel: cfg.artifacts.keyLabel }
        : {
            r1cs: { file: rel(R1CS_V4), sha256: sha256File(R1CS_V4) },
            wasm: { file: rel(WASM_V4), sha256: sha256File(WASM_V4) },
            zkey: { file: rel(ZKEY_V4), sha256: sha256File(ZKEY_V4), keyLabel: KEY_LABEL_V4 },
            vkey: { file: rel(VKEY_V4), sha256: sha256File(VKEY_V4) },
          },
      pqc: implementationLabel(),
      trapdoor: { beaconDerivedDeltaMatchesKey: beaconMatchesDelta, note: "false means a secret contribution precedes the beacon, so delta is not public" },
      standardThresholds: STANDARD_THRESHOLDS,
    });
    const dir = cfg.out;
    fs.mkdirSync(dir, { recursive: true });
    const isReal = !cfg.mutantGroup && !cfg.artifacts && !(cfg.verifierDisabled ?? []).length && !(cfg.walletDisabled ?? []).length && !cfg.governanceSkipPop && !process.env["PQID_V4_CONTRACTS"];
    const meta = { config: cfg.name, mutantGroup: cfg.mutantGroup ?? null, verifierDisabled: cfg.verifierDisabled ?? [], walletDisabled: cfg.walletDisabled ?? [], governanceSkipPop: !!cfg.governanceSkipPop, contracts: process.env["PQID_V4_CONTRACTS"] ? "mutant" : "onchain/contracts/v4/RegistriesV4.sol" };
    fs.writeFileSync(path.join(dir, "security_suite.json"), JSON.stringify({ ...meta, ...out }, null, 2));
    if (isReal) fs.writeFileSync(path.join(dir, "attack_matrix.json"), JSON.stringify(attackMatrix(out), null, 2));
    console.log(`[suite] ${out.pass ? "PASS" : "FAIL"} v4 attack routes accepted: ${out.summary.v4AttackRoutesAccepted}/${out.summary.v4AttackRoutes}; invalid: ${out.summary.invalid}`);
    if (!out.pass) process.exitCode = 1;
  } finally {
    world.stop();
  }
}

function minorOrAdult(h: HolderWalletV4): HolderWalletV4 {
  return h;
}

function await_sha3(b: Buffer): string {
  return createHash("sha3-256").update(b).digest("hex");
}

function rel(p: string): string {
  return path.relative(REPO_ROOT, p).split(path.sep).join("/");
}

function summarize(rec: Recorder, extra: Record<string, unknown>) {
  const all = rec.records.flatMap((r) => r.attempts.map((a) => ({ r, a })));
  const attacks = all.filter(({ r }) => r.kind === "attack");
  const byLayer: Record<string, number> = {};
  for (const { a } of attacks) if (!a.accepted) byLayer[a.stoppedBy.layer] = (byLayer[a.stoppedBy.layer] ?? 0) + 1;
  const invalid = all.filter(({ a }) => !a.valid);
  // Every catalogued route must have an attempt (B5 PRIV-7): ids from docs/v4/ROUTES.md
  // tables, except rows whose expected column is n/a (v2/v3-only routes).
  const catalogued: string[] = [];
  for (const line of fs.readFileSync(path.join(REPO_ROOT, "docs", "v4", "ROUTES.md"), "utf8").split(/\r?\n/)) {
    const m = /^\| ([A-Z][A-Za-z0-9+-]*) \|/.exec(line);
    if (!m || m[1] === "ID") continue;
    if (/\| n\/a \|\s*$/.test(line)) continue;
    catalogued.push(m[1]!);
  }
  const attempted = new Set(all.map(({ a }) => a.route.split(" ")[0]!));
  const notRun = catalogued.filter((id) => !attempted.has(id) && ![...attempted].some((x) => x.startsWith(id + "#")));
  const summary = {
    controlsAccepted: `${all.filter(({ r, a }) => r.kind === "control" && a.accepted).length}/${all.filter(({ r }) => r.kind === "control").length}`,
    v4AttackRoutes: attacks.length,
    v4AttackRoutesAccepted: attacks.filter(({ a }) => a.accepted).length,
    v4AttackRoutesStoppedBy: byLayer,
    privacyRecords: all.filter(({ r }) => r.kind === "privacy").length,
    knownLimitations: all.filter(({ r }) => r.kind === "known-limitation").map(({ a }) => `${a.route}: ${a.accepted ? "accepted" : "stopped"}`),
    invalid: invalid.length,
    invalidRoutes: invalid.map(({ a }) => `${a.route}: ${a.detail ?? JSON.stringify(a.stoppedBy)}`),
    cataloguedRoutesNotRun: notRun,
  };
  return {
    schema: "pqid/v4-security-suite/v1",
    label: "[M] v4 security suite (dev key; routes per docs/v4/ROUTES.md)",
    keyLabel: KEY_LABEL_V4,
    pass: invalid.length === 0 && summary.v4AttackRoutesAccepted === 0 && notRun.length === 0,
    summary,
    records: rec.records,
    ...extra,
    harnessSha256: sha256File(fileURLToPath(import.meta.url)),
    host: hostMeta(),
  };
}

/** v2, v3 (committed results/v3/security_suite.json) and v4 side by side, per attack family. */
function attackMatrix(v4: ReturnType<typeof summarize>) {
  const v3file = path.join(REPO_ROOT, "results", "v3", "security_suite.json");
  const v3 = JSON.parse(fs.readFileSync(v3file, "utf8")) as { attacks: Array<{ id: string; title: string; kind: string; attempts: Array<{ circuit: string; route: string; accepted: boolean; outcome: string }> }> };
  const fam = new Map<string, { title: string; v2: string; v3: string; v4: string }>();
  const cell = (xs: Array<{ accepted: boolean }>) => (xs.length === 0 ? "n/a" : `${xs.filter((x) => x.accepted).length}/${xs.length} accepted`);
  for (const r of v3.attacks) {
    if (r.kind !== "attack" && r.kind !== "known-limitation") continue;
    fam.set(r.id, { title: r.title, v2: cell(r.attempts.filter((a) => a.circuit === "v2")), v3: cell(r.attempts.filter((a) => a.circuit === "v3")), v4: "n/a" });
  }
  for (const r of v4.records) {
    if (r.kind !== "attack" && r.kind !== "known-limitation") continue;
    const e = fam.get(r.id) ?? { title: r.title, v2: "not run", v3: "not run", v4: "n/a" };
    e.v4 = cell(r.attempts);
    fam.set(r.id, e);
  }
  return {
    schema: "pqid/attack-matrix/v1",
    sources: { v2v3: "results/v3/security_suite.json (committed, dev keys of their versions)", v4: "results/v4/security_suite.json" },
    note: "Cells count accepted routes per family. v2/v3 cells come from the committed v3 suite; 'not run' = the family did not exist for that version.",
    rows: [...fam.entries()].map(([id, e]) => ({ id, ...e })),
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // Exit explicitly: snarkjs keeps worker threads alive after the last proof.
  main().then(
    () => process.exit(process.exitCode ?? 0),
    (e: unknown) => {
      console.error(e);
      process.exit(1);
    }
  );
}
