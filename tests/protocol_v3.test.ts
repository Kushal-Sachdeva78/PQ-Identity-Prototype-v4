import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomBytes } from "node:crypto";
import { getPoseidon, issuerKeyHash, credentialLeaf, issuanceRootMessage } from "@pqid/common/encoding";
import {
  createIssuerV3,
  issueCredentialV3,
  signIssuanceRoot,
  syncIssuanceAnchor,
  issuanceWitness,
  computeCredId,
  IssuanceTree,
  type IssuerV3,
  type VerifiableCredential,
  type IssuanceWitness,
  type IssuanceRootAttestation,
} from "@pqid/issuer";
import { dilithiumSign, dilithiumVerify } from "@pqid/pqc";
import {
  createWallet,
  buildProofInputV3,
  generateProofV3,
  presentationV3,
  readChainViewV3,
  prove,
  V3_ARTIFACTS,
  type ChainViewV3,
  type HolderWallet,
  type PolicyV1,
} from "@pqid/wallet";
import { RevocationTree } from "@pqid/revocation";
import { Ledger, startAnvil, DEFAULT_MIN_ANCHOR_INTERVAL_SEC, type AnvilHandle } from "@pqid/ledger";
import { Verifier, type Presentation } from "@pqid/verifier";
import { fixtureRevokedCredIds } from "../harness/fixture.ts";

/**
 * Circuit v3 end to end: issuer-signed epoch statements (issuance root +
 * revocation root) anchored on chain, the wallet's privacy checks, the
 * verifier's checks, and the attacks v3 was built to stop (the full
 * v2-vs-v3 matrix, with more routes, is harness/v3/security_suite.ts).
 * Needs Anvil and an ML-DSA-44 backend (liboqs in WSL, or the local
 * dilithium-py venv — see packages/pqc).
 */
let anvil: AnvilHandle;
let ledger: Ledger;
let verifier: Verifier;
let issuer: IssuerV3;
let wallet: HolderWallet;
let vc: VerifiableCredential;
/** Working revoked set (revocations land here) and the snapshot anchored in the current epoch. */
let tree: RevocationTree;
let served: RevocationTree;
const policy: PolicyV1 = { type: "age_gte", attribute: "age", threshold: 18 };
const POLICY_18 = { type: "age_gte", threshold: 18 } as const;

/** Sign the next epoch (issuance root + revocation snapshot), wait out the interval, anchor, sync. */
async function signAndAnchor(
  iss: IssuerV3 = issuer,
  l: Ledger = ledger,
  revTree: RevocationTree = tree
): Promise<{ att: IssuanceRootAttestation; snapshot: RevocationTree }> {
  const snapshot = await revTree.snapshot();
  const att = signIssuanceRoot(iss, snapshot.root());
  const cur = await l.getIssuanceRoot(iss.did);
  if (cur.epoch !== att.epoch) {
    if (cur.epoch > 0) await l.devAdvanceTime(DEFAULT_MIN_ANCHOR_INTERVAL_SEC);
    await l.publishIssuanceRoot(iss.did, att);
  }
  syncIssuanceAnchor(iss, await l.getIssuanceRoot(iss.did));
  if (iss === issuer && l === ledger) served = snapshot;
  return { att, snapshot };
}

const chainView = (): Promise<ChainViewV3> => readChainViewV3(ledger, issuer.did);

async function present(
  args: { vc?: VerifiableCredential; wallet?: HolderWallet; issuance?: IssuanceWitness } = {}
): Promise<Presentation> {
  const theVc = args.vc ?? vc;
  const issuance = args.issuance ?? issuanceWitness(issuer, theVc.credID);
  const chain = await chainView();
  const result = await generateProofV3({
    wallet: args.wallet ?? wallet,
    vc: theVc,
    request: { policy, nonce: verifier.newSessionNonce(), verifierId: verifier.verifierId },
    pkIssuer: issuer.keys.publicKey,
    revRoot: chain.anchor.revRoot,
    nonMembership: await served.getNonMembershipProof(Buffer.from(theVc.credID, "hex")),
    issuance,
    chain,
  });
  return presentationV3(result, issuer.did, issuance.attestation);
}

/** A FIPS-204-invalid re-encoding of a valid ML-DSA-44 signature: one hint index repeated (null if 80 hints). */
function repeatHintIndex(sigHex: string): string | null {
  const sig = Buffer.from(sigHex, "hex");
  const y = sig.length - 84; // hint section: 80 index bytes + 4 cumulative counts
  const ends = [0, 1, 2, 3].map((i) => sig[y + 80 + i] as number);
  const total = ends[3] as number;
  const poly = ends.findIndex((e, i) => e > (i === 0 ? 0 : (ends[i - 1] as number)));
  if (poly < 0 || total >= 80) return null;
  const at = ends[poly] as number; // insert a copy of this poly's last index here
  for (let j = total; j > at; j--) sig[y + j] = sig[y + j - 1] as number;
  sig[y + at] = sig[y + at - 1] as number;
  for (let i = poly; i < 4; i++) sig[y + 80 + i] = (ends[i] as number) + 1;
  return sig.toString("hex");
}

beforeAll(async () => {
  anvil = await startAnvil(18645);
  ledger = await Ledger.deploy(anvil.rpcUrl); // default anchor interval (1 h); tests advance the clock
  verifier = new Verifier(ledger, { circuit: "v3" });
  issuer = await createIssuerV3();
  wallet = await createWallet();
  await ledger.registerDid(issuer.did, issuer.keys.publicKey);
  await ledger.accreditIssuer(issuer.did);
  tree = await RevocationTree.create();
  for (const id of fixtureRevokedCredIds()) await tree.insert(id);
  ({ vc } = await issueCredentialV3({
    issuer,
    subjectDid: wallet.did,
    claims: { age: 42 },
    holderCommit: wallet.holderCommit,
  }));
  await signAndAnchor();
}, 300_000);

afterAll(() => {
  ledger?.destroy();
  anvil?.stop();
});

describe("v3 issuer", () => {
  it("signs epoch statements (issuance root + revocation root) with ML-DSA-44", async () => {
    const att = issuer.anchored!.attestation;
    expect(att.root).toBe(issuer.tree.root().toString());
    expect(att.revRoot).toBe(served.root().toString());
    expect(
      dilithiumVerify(
        issuer.keys.publicKey,
        issuanceRootMessage(att.issuerDid, att.epoch, BigInt(att.root), BigInt(att.revRoot)),
        Buffer.from(att.signature, "hex")
      )
    ).toBe(true);
    const anchor = await ledger.getIssuanceRoot(issuer.did);
    expect(anchor.revRoot).toBe(served.root());
  });

  it("puts a salt in every v3 credential and keeps credID = SHA3-256(cred ‖ pk)", () => {
    expect(vc.credential.salt).toMatch(/^[0-9a-f]{64}$/);
    expect(computeCredId(vc.credential, issuer.keys.publicKey).toString("hex")).toBe(vc.credID);
  });

  it("does not re-sign an unchanged statement, and re-anchoring it is an idempotent no-op", async () => {
    const before = issuer.latest!;
    expect(signIssuanceRoot(issuer, served.root())).toBe(before);
    await ledger.publishIssuanceRoot(issuer.did, before); // must not revert
    expect((await ledger.getIssuanceRoot(issuer.did)).epoch).toBe(before.epoch);
  });

  it("serves the ANCHORED statement through an open batch and a signed-but-unanchored window", async () => {
    const epoch = issuer.anchored!.attestation.epoch;
    const other = await createWallet();
    const { vc: otherVc } = await issueCredentialV3({
      issuer,
      subjectDid: other.did,
      claims: { age: 30 },
      holderCommit: other.holderCommit,
    });
    expect(issuanceWitness(issuer, vc.credID).attestation.epoch).toBe(epoch);
    expect(() => issuanceWitness(issuer, otherVc.credID)).toThrow(/not yet covered/);
    const snap = await tree.snapshot();
    const att = signIssuanceRoot(issuer, snap.root()); // signed, not anchored yet
    expect(att.epoch).toBe(epoch + 1);
    expect(issuanceWitness(issuer, vc.credID).attestation.epoch).toBe(epoch);
    expect(() => issuanceWitness(issuer, otherVc.credID)).toThrow(/not yet covered/);
    expect((await verifier.verifyPresentation(await present(), POLICY_18)).accepted).toBe(true);
    await ledger.devAdvanceTime(DEFAULT_MIN_ANCHOR_INTERVAL_SEC);
    await ledger.publishIssuanceRoot(issuer.did, att);
    syncIssuanceAnchor(issuer, await ledger.getIssuanceRoot(issuer.did));
    served = snap;
    expect(issuanceWitness(issuer, otherVc.credID).attestation.epoch).toBe(epoch + 1);
  }, 120_000);

  it("refuses to serve when the chain holds a statement it did not sign", async () => {
    const lone = await createIssuerV3();
    expect(() =>
      syncIssuanceAnchor(lone, { epoch: 1, root: 1n, revRoot: 0n, sigHash: "00".repeat(32) })
    ).toThrow(/diverged/);
  });
});

describe("anchor registry and ledger", () => {
  it("enforces epoch = previous + 1 and the interval; a reverted anchor does not stall or reorder later writes", async () => {
    const node = await startAnvil(18655); // its own node: two nonce managers on one dev account would race
    const strict = await Ledger.deploy(node.rpcUrl);
    expect(await strict.getMinAnchorInterval()).toBe(DEFAULT_MIN_ANCHOR_INTERVAL_SEC);
    const iss = await createIssuerV3();
    const rev = await RevocationTree.create();
    await strict.registerDid(iss.did, iss.keys.publicKey);
    const w = await createWallet();
    await issueCredentialV3({ issuer: iss, subjectDid: w.did, claims: { age: 20 }, holderCommit: w.holderCommit });
    await signAndAnchor(iss, strict, rev);
    await issueCredentialV3({ issuer: iss, subjectDid: w.did, claims: { age: 21 }, holderCommit: w.holderCommit });
    const e2 = signIssuanceRoot(iss, rev.root());
    // two writes in flight: the anchor reverts, the revocation root must still land, in order
    const [anchorResult] = await Promise.allSettled([
      strict.publishIssuanceRoot(iss.did, e2),
      strict.publishRevRoot(iss.did, 12345n),
    ]);
    expect(anchorResult.status).toBe("rejected");
    expect(String((anchorResult as PromiseRejectedResult).reason)).toMatch(/too soon/);
    expect(await strict.getRevRoot(iss.did)).toBe(12345n);
    await strict.publishRevRoot(iss.did, 777n);
    expect(await strict.getRevRoot(iss.did)).toBe(777n);
    await expect(strict.publishIssuanceRoot(iss.did, { ...e2, epoch: e2.epoch + 1 })).rejects.toThrow(/previous \+ 1/);
    await strict.devAdvanceTime(DEFAULT_MIN_ANCHOR_INTERVAL_SEC);
    await strict.publishIssuanceRoot(iss.did, e2);
    expect((await strict.getIssuanceRoot(iss.did)).epoch).toBe(2);
    strict.destroy();
    node.stop();
  }, 180_000);
});

describe("v3 wallet privacy checks (the holder never presents an issuer-chosen tag)", () => {
  const buildWith = async (
    issuance: IssuanceWitness,
    over: { chain?: Partial<ChainViewV3>; nonMembership?: Awaited<ReturnType<RevocationTree["getNonMembershipProof"]>> } = {}
  ) => {
    const chain = { ...(await chainView()), ...over.chain };
    return buildProofInputV3({
      wallet,
      vc,
      request: { policy, nonce: verifier.newSessionNonce(), verifierId: verifier.verifierId },
      pkIssuer: issuer.keys.publicKey,
      revRoot: chain.anchor.revRoot,
      nonMembership: over.nonMembership ?? (await served.getNonMembershipProof(Buffer.from(vc.credID, "hex"))),
      issuance,
      chain,
    });
  };

  it("refuses re-signed bytes, an extra field, an unanchored root, a per-holder revRoot, an unaccredited issuer and a fast registry", async () => {
    const w = issuanceWitness(issuer, vc.credID);
    const att = w.attestation;
    const resigned = dilithiumSign(
      issuer.keys.secretKey,
      issuanceRootMessage(att.issuerDid, att.epoch, BigInt(att.root), BigInt(att.revRoot))
    ).toString("hex");
    if (resigned !== att.signature) {
      await expect(buildWith({ ...w, attestation: { ...att, signature: resigned } })).rejects.toThrow(/differ from the anchored/);
    }
    await expect(
      buildWith({ ...w, attestation: { ...att, tag: "holder-42" } as unknown as IssuanceRootAttestation })
    ).rejects.toThrow(/attestation must have exactly/);
    const own = await IssuanceTree.create();
    own.insert(1n);
    await expect(
      buildWith({ path: { ...w.path, root: own.root().toString() }, attestation: { ...att, root: own.root().toString() } })
    ).rejects.toThrow(/not its current on-chain anchor/);
    const perHolder = await served.snapshot();
    await perHolder.insert(randomBytes(32));
    await expect(
      buildWith(w, { nonMembership: await perHolder.getNonMembershipProof(Buffer.from(vc.credID, "hex")) })
    ).rejects.toThrow(/not against the anchored revRoot/);
    const base = await chainView();
    await expect(buildWith(w, { chain: { issuer: { ...base.issuer, accredited: false } } })).rejects.toThrow(/accredited/);
    await expect(buildWith(w, { chain: { minAnchorIntervalSec: 60 } })).rejects.toThrow(/refusing to present/);
  }, 120_000);

  it("presents a freshly built attestation in a fixed key order, whatever order the issuer used", async () => {
    const w = issuanceWitness(issuer, vc.credID);
    const a = w.attestation;
    const permuted = { signature: a.signature, revRoot: a.revRoot, root: a.root, epoch: a.epoch, issuerDid: a.issuerDid };
    const p = await present({ issuance: { path: w.path, attestation: permuted } });
    expect(JSON.stringify(p.issuanceRoot)).toBe(
      JSON.stringify({ issuerDid: a.issuerDid, epoch: a.epoch, root: a.root, revRoot: a.revRoot, signature: a.signature })
    );
    expect((await verifier.verifyPresentation(p, POLICY_18)).accepted).toBe(true);
  }, 120_000);
});

describe("v3 verifier", () => {
  it("accepts an honest presentation (all 9 checks, incl. the anchored and signed epoch statement)", async () => {
    const decision = await verifier.verifyPresentation(await present(), POLICY_18);
    expect(decision.reasons).toEqual([]);
    expect(decision.checks.issuanceRootCurrent).toBe(true);
    expect(decision.checks.issuanceRootSigned).toBe(true);
    expect(decision.accepted).toBe(true);
  }, 120_000);

  it("reads revRoot from the anchored statement: rolling back RevocationRegistry changes nothing", async () => {
    const p = await present();
    await ledger.publishRevRoot(issuer.did, 424242n); // stale / rolled-back v2-style write
    expect((await verifier.verifyPresentation(p, POLICY_18)).accepted).toBe(true);
  }, 120_000);

  it("rejects a missing attestation and one with an extra field (a malicious wallet forwarding a tag)", async () => {
    const p = await present();
    const tagged: Presentation = { ...p, issuanceRoot: { ...p.issuanceRoot!, tag: 7 } as unknown as IssuanceRootAttestation };
    const d1 = await verifier.verifyPresentation(tagged, POLICY_18);
    expect(d1.accepted).toBe(false);
    expect(d1.reasons.join(" ")).toMatch(/must have exactly/);
    delete p.issuanceRoot;
    const d2 = await verifier.verifyPresentation(p, POLICY_18);
    expect(d2.accepted).toBe(false);
    expect(d2.checks.issuanceRootCurrent).toBe(false);
  }, 120_000);

  it("rejects an attestation whose epoch was altered", async () => {
    const p = await present();
    p.issuanceRoot = { ...p.issuanceRoot!, epoch: p.issuanceRoot!.epoch + 7 };
    const d = await verifier.verifyPresentation(p, POLICY_18);
    expect(d.accepted).toBe(false);
    expect(d.checks.issuanceRootCurrent).toBe(false);
  }, 120_000);

  it("rejects a path to an older statement once a newer one is anchored", async () => {
    const old = issuanceWitness(issuer, vc.credID);
    const w = await createWallet();
    await issueCredentialV3({ issuer, subjectDid: w.did, claims: { age: 50 }, holderCommit: w.holderCommit });
    await signAndAnchor();
    await expect(present({ issuance: old })).rejects.toThrow(/not its current on-chain anchor/);
    const chain = await chainView();
    const input = await buildProofInputV3({
      wallet,
      vc,
      request: { policy, nonce: verifier.newSessionNonce(), verifierId: verifier.verifierId },
      pkIssuer: issuer.keys.publicKey,
      revRoot: chain.anchor.revRoot,
      nonMembership: await served.getNonMembershipProof(Buffer.from(vc.credID, "hex")),
      issuance: old,
      chain,
      dangerouslySkipOffCircuitChecks: true,
    });
    const d = await verifier.verifyPresentation(
      presentationV3(await prove(input, "snarkjs", V3_ARTIFACTS), issuer.did, old.attestation),
      POLICY_18
    );
    expect(d.accepted).toBe(false);
    expect(d.checks.issuanceRootCurrent).toBe(false);
    expect(d.checks.proofValid).toBe(true);
    expect((await verifier.verifyPresentation(await present(), POLICY_18)).accepted).toBe(true);
  }, 180_000);

  it("rejects non-canonical public signals without spending the session nonce", async () => {
    const p = await present();
    const junk: Presentation = {
      ...p,
      publicSignals: [...p.publicSignals.slice(0, 5), "0" + (p.publicSignals[5] as string)],
    };
    const d = await verifier.verifyPresentation(junk, POLICY_18);
    expect(d.accepted).toBe(false);
    expect(d.reasons.join(" ")).toMatch(/canonical/);
    expect((await verifier.verifyPresentation(p, POLICY_18)).accepted).toBe(true);
  }, 120_000);

  it("a rejected presentation does not burn the nonce or run ML-DSA; an accepted one burns the nonce", async () => {
    const p = await present();
    const wrongPolicy = await verifier.verifyPresentation(p, { type: "age_gte", threshold: 21 });
    expect(wrongPolicy.accepted).toBe(false);
    expect(wrongPolicy.notEvaluated).toContain("issuanceRootSigned");
    expect((await verifier.verifyPresentation(p, POLICY_18)).accepted).toBe(true);
    const replay = await verifier.verifyPresentation(p, POLICY_18);
    expect(replay.accepted).toBe(false);
    expect(replay.checks.nonceFresh).toBe(false);
  }, 120_000);

  it("of several concurrent copies of one presentation exactly one is accepted and only it runs ML-DSA", async () => {
    const p = await present();
    const ds = await Promise.all([0, 1, 2].map(() => verifier.verifyPresentation(structuredClone(p), POLICY_18)));
    expect(ds.filter((d) => d.accepted)).toHaveLength(1);
    for (const d of ds.filter((x) => !x.accepted)) {
      expect(d.notEvaluated).toContain("issuanceRootSigned");
    }
  }, 120_000);

  it("rejects a 5-signal presentation, non-plain-data input, sparse signals, an unknown policy and unknown circuit options", async () => {
    const p = await present();
    expect((await verifier.verifyPresentation({ ...p, publicSignals: p.publicSignals.slice(0, 5) }, POLICY_18)).accepted).toBe(false);
    const proxied = { ...p, publicSignals: new Proxy(p.publicSignals, {}) };
    expect((await verifier.verifyPresentation(proxied, POLICY_18)).reasons).toEqual(["presentation must be plain data"]);
    const sparse = [...p.publicSignals];
    delete sparse[2];
    expect((await verifier.verifyPresentation({ ...p, publicSignals: sparse }, POLICY_18)).reasons.join(" ")).toMatch(/canonical/);
    const bad = await verifier.verifyPresentation(p, { type: "AGE_GTE" as never, threshold: 18 });
    expect(bad.reasons).toEqual(["unknown verifier policy"]);
    expect(() => new Verifier(ledger, { circuit: "V3" as never })).toThrow(/unknown circuit/);
  }, 120_000);

  it("the ML-DSA backend rejects a signature with a repeated hint index (FIPS 204 strict decoding)", () => {
    const msg = Buffer.from("pqid:hint-test");
    let sig: Buffer | null = null;
    let mauled: string | null = null;
    for (let i = 0; i < 20 && !mauled; i++) {
      sig = dilithiumSign(issuer.keys.secretKey, msg); // hedged: a fresh signature each time
      mauled = repeatHintIndex(sig.toString("hex")); // null only when all 80 hint slots are used
    }
    expect(mauled).not.toBeNull();
    expect(dilithiumVerify(issuer.keys.publicKey, msg, sig!)).toBe(true);
    expect(dilithiumVerify(issuer.keys.publicKey, msg, Buffer.from(mauled!, "hex"))).toBe(false);
  });
});

describe("attacks v3 closes (review 9.1, 9.2; v3 review verifier-1)", () => {
  it("malicious-wallet probe: a never-issued credential yields no proof against the signed root", async () => {
    const attacker = await createWallet();
    const forged = {
      ...vc.credential,
      subject: attacker.did,
      holderCommit: attacker.holderCommit.toString(),
      salt: randomBytes(32).toString("hex"),
    };
    const forgedId = computeCredId(forged, issuer.keys.publicKey);
    const chain = await chainView();
    const input = await buildProofInputV3({
      wallet: attacker,
      vc: { credential: forged, credID: forgedId.toString("hex"), signature: "00".repeat(2420) },
      request: { policy, nonce: verifier.newSessionNonce(), verifierId: verifier.verifierId },
      pkIssuer: issuer.keys.publicKey,
      revRoot: chain.anchor.revRoot,
      nonMembership: await served.getNonMembershipProof(forgedId),
      issuance: issuanceWitness(issuer, vc.credID), // someone else's genuine path
      chain,
      dangerouslySkipOffCircuitChecks: true,
    });
    await expect(prove(input, "snarkjs", V3_ARTIFACTS)).rejects.toThrow(/Assert Failed/);
  }, 120_000);

  it("a proof on an attacker-built tree is rejected by the issuance-root check", async () => {
    const poseidon = await getPoseidon();
    const own = await IssuanceTree.create();
    own.insert(
      credentialLeaf(poseidon, {
        issuerKeyHash: issuerKeyHash(poseidon, issuer.keys.publicKey),
        credId: Buffer.from(vc.credID, "hex"),
        holderCommit: wallet.holderCommit,
        claimAge: 99n,
      })
    );
    const genuine = issuanceWitness(issuer, vc.credID);
    const edited = { ...vc, credential: { ...vc.credential, claims: { age: 99 } } };
    const forgedAtt = { ...genuine.attestation, root: own.root().toString() };
    const chain = await chainView();
    const input = await buildProofInputV3({
      wallet,
      vc: edited,
      request: { policy, nonce: verifier.newSessionNonce(), verifierId: verifier.verifierId },
      pkIssuer: issuer.keys.publicKey,
      revRoot: chain.anchor.revRoot,
      nonMembership: await served.getNonMembershipProof(Buffer.from(vc.credID, "hex")),
      issuance: { path: own.path(0), attestation: forgedAtt },
      chain,
      dangerouslySkipOffCircuitChecks: true,
    });
    const proved = await prove(input, "snarkjs", V3_ARTIFACTS);
    const d = await verifier.verifyPresentation(presentationV3(proved, issuer.did, forgedAtt), POLICY_18);
    expect(d.checks.proofValid).toBe(true);
    expect(d.checks.issuanceRootCurrent).toBe(false);
    expect(d.accepted).toBe(false);
  }, 180_000);

  it("a revoked holder cannot switch to a fresh credID", async () => {
    const revokee = await createWallet();
    const { vc: rvc } = await issueCredentialV3({
      issuer,
      subjectDid: revokee.did,
      claims: { age: 30 },
      holderCommit: revokee.holderCommit,
    });
    await signAndAnchor();
    await tree.insert(Buffer.from(rvc.credID, "hex")); // revoke; effective with the next epoch
    await signAndAnchor();
    await expect(served.getNonMembershipProof(Buffer.from(rvc.credID, "hex"))).rejects.toThrow(/revoked/);
    const iw = issuanceWitness(issuer, rvc.credID);

    const fresh = randomBytes(32);
    const chain = await chainView();
    const input = await buildProofInputV3({
      wallet: revokee,
      vc: { ...rvc, credID: fresh.toString("hex") },
      request: { policy, nonce: verifier.newSessionNonce(), verifierId: verifier.verifierId },
      pkIssuer: issuer.keys.publicKey,
      revRoot: chain.anchor.revRoot,
      nonMembership: await served.getNonMembershipProof(fresh),
      issuance: iw,
      chain,
      dangerouslySkipOffCircuitChecks: true,
    });
    await expect(prove(input, "snarkjs", V3_ARTIFACTS)).rejects.toThrow(/Assert Failed/);
  }, 240_000);

  it("a DID squatted with the squatter's own key is not accepted even if accredited", async () => {
    const victimIssuer = await createIssuerV3(); // announces its DID, has not registered yet
    const squatter = await createIssuerV3();
    await ledger.registerDid(victimIssuer.did, squatter.keys.publicKey);
    await ledger.accreditIssuer(victimIssuer.did);
    const w = await createWallet();
    const { vc: svc } = await issueCredentialV3({
      issuer: squatter,
      subjectDid: w.did,
      claims: { age: 42 },
      holderCommit: w.holderCommit,
    });
    const rev = await RevocationTree.create();
    const root = squatter.tree.root();
    const msgAtt: IssuanceRootAttestation = {
      issuerDid: victimIssuer.did,
      epoch: 1,
      root: root.toString(),
      revRoot: rev.root().toString(),
      signature: dilithiumSign(
        squatter.keys.secretKey,
        issuanceRootMessage(victimIssuer.did, 1, root, rev.root())
      ).toString("hex"),
    };
    await ledger.publishIssuanceRoot(victimIssuer.did, msgAtt);
    const input = await buildProofInputV3({
      wallet: w,
      vc: svc,
      request: { policy, nonce: verifier.newSessionNonce(), verifierId: verifier.verifierId },
      pkIssuer: squatter.keys.publicKey,
      revRoot: rev.root(),
      nonMembership: await rev.getNonMembershipProof(Buffer.from(svc.credID, "hex")),
      issuance: { path: squatter.tree.path(0), attestation: msgAtt },
      chain: await readChainViewV3(ledger, victimIssuer.did),
      dangerouslySkipOffCircuitChecks: true,
    });
    const result = await prove(input, "snarkjs", V3_ARTIFACTS);
    const d = await verifier.verifyPresentation(presentationV3(result, victimIssuer.did, msgAtt), POLICY_18);
    expect(d.accepted).toBe(false);
    expect(d.reasons.join(" ")).toMatch(/does not match the did:pq identifier/);
  }, 180_000);
});
