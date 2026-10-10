import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import { sha3_256 } from "@pqid/common/hash";
import { createIssuer, issueCredential, type Issuer, type VerifiableCredential } from "@pqid/issuer";
import { createWallet, generateProof, type HolderWallet, type PolicyV1 } from "@pqid/wallet";
import { RevocationTree } from "@pqid/revocation";
import { Ledger, startAnvil, type AnvilHandle } from "@pqid/ledger";
import { Verifier, type Presentation } from "@pqid/verifier";

/**
 * M6 + M7 acceptance: registries on a local EVM, did:pq resolution, and the
 * verifier's resolve + equality + Groth16.verify + nonce pipeline, including
 * the reject paths (stale nonce, wrong revocation root).
 */
let anvil: AnvilHandle;
let ledger: Ledger;
let verifier: Verifier;
let issuer: Issuer;
let wallet: HolderWallet;
let vc: VerifiableCredential;
let tree: RevocationTree;
const policy: PolicyV1 = { type: "age_gte", attribute: "age", threshold: 18 };

async function makePresentation(nonce: bigint, verifierId?: string): Promise<Presentation> {
  const credIdBytes = Buffer.from(vc.credID, "hex");
  const nonMembership = await tree.getNonMembershipProof(credIdBytes);
  const result = await generateProof(
    {
      wallet,
      vc,
      request: { policy, nonce, verifierId: verifierId ?? verifier.verifierId },
      pkIssuer: issuer.keys.publicKey,
      revRoot: await ledger.getRevRoot(issuer.did),
      nonMembership,
    },
    "snarkjs"
  );
  return { proof: result.proof, publicSignals: result.publicSignals, issuerDid: issuer.did };
}

beforeAll(async () => {
  anvil = await startAnvil(18545);
  ledger = await Ledger.deploy(anvil.rpcUrl);
  verifier = new Verifier(ledger);

  issuer = createIssuer();
  wallet = await createWallet();

  await ledger.registerDid(issuer.did, issuer.keys.publicKey, ["https://issuer.example/api"]);
  await ledger.registerDid(wallet.did, wallet.keys.publicKey);
  await ledger.accreditIssuer(issuer.did);

  const schema = JSON.parse(
    fs.readFileSync(new URL("../fixtures/vc-schema.json", import.meta.url), "utf8")
  ) as unknown;
  await ledger.registerSchema("pqid:schema:identity-v1", schema, "fixtures/vc-schema.json");

  tree = await RevocationTree.create();
  const revoked = JSON.parse(
    fs.readFileSync(new URL("../fixtures/revoked-set.json", import.meta.url), "utf8")
  ) as { labels: string[] };
  for (const label of revoked.labels) await tree.insert(sha3_256(Buffer.from(label, "utf8")));
  await ledger.publishRevRoot(issuer.did, tree.root());

  vc = issueCredential({
    issuer,
    subjectDid: wallet.did,
    claims: { age: 42 },
    holderCommit: wallet.holderCommit,
    issuedAt: "2026-01-01T00:00:00.000Z",
  });
}, 300_000);

afterAll(() => {
  ledger?.destroy();
  anvil?.stop();
});

describe("ledger + did:pq resolver (M7)", () => {
  it("resolves a registered DID Document end-to-end from the EVM", async () => {
    const doc = await ledger.resolveDid(issuer.did);
    expect(doc.id).toBe(issuer.did);
    expect(doc.publicKeyDilithium).toBe(issuer.keys.publicKey.toString("hex"));
    expect(doc.endpoints).toEqual(["https://issuer.example/api"]);
    expect(doc.active).toBe(true);
  });

  it("reports issuer accreditation and revocation root", async () => {
    expect(await ledger.isAccredited(issuer.did)).toBe(true);
    expect(await ledger.isAccredited(wallet.did)).toBe(false);
    expect(await ledger.getRevRoot(issuer.did)).toBe(tree.root());
  });
});

describe("verifier (M6)", () => {
  it("accepts a valid presentation (all 7 checks pass)", async () => {
    const nonce = verifier.newSessionNonce();
    const presentation = await makePresentation(nonce);
    const decision = await verifier.verifyPresentation(presentation, {
      type: "age_gte",
      threshold: 18,
    });
    expect(decision.reasons).toEqual([]);
    expect(decision.accepted).toBe(true);
  }, 120_000);

  it("rejects a replayed presentation (stale nonce)", async () => {
    const nonce = verifier.newSessionNonce();
    const presentation = await makePresentation(nonce);
    const first = await verifier.verifyPresentation(presentation, { type: "age_gte", threshold: 18 });
    expect(first.accepted).toBe(true);
    const replay = await verifier.verifyPresentation(presentation, { type: "age_gte", threshold: 18 });
    expect(replay.accepted).toBe(false);
    expect(replay.checks.nonceFresh).toBe(false);
    expect(replay.reasons.join(" ")).toMatch(/nonce/);
  }, 120_000);

  it("rejects a proof built against an outdated revocation root", async () => {
    const nonce = verifier.newSessionNonce();
    const presentation = await makePresentation(nonce); // proof against current root
    // Issuer revokes some other credential -> publishes a NEW root on-chain.
    await tree.insert(sha3_256(Buffer.from("some-other-credential", "utf8")));
    await ledger.publishRevRoot(issuer.did, tree.root());

    const decision = await verifier.verifyPresentation(presentation, { type: "age_gte", threshold: 18 });
    expect(decision.accepted).toBe(false);
    expect(decision.checks.revRootMatches).toBe(false);
    expect(decision.checks.proofValid).toBe(true); // the proof itself is sound — the statement is outdated
  }, 120_000);

  it("rejects a policy mismatch (verifier wanted 21+)", async () => {
    const nonce = verifier.newSessionNonce();
    const presentation = await makePresentation(nonce); // proves age >= 18
    const decision = await verifier.verifyPresentation(presentation, { type: "age_gte", threshold: 21 });
    expect(decision.accepted).toBe(false);
    expect(decision.checks.policyHashMatches).toBe(false);
  }, 120_000);

  it("rejects a cross-verifier replay (proof bound to verifier A presented to verifier B)", async () => {
    // Verifier B with its own identity and nonce registry.
    const verifierB = new Verifier(ledger, { verifierId: "pqid:verifier:other" });
    const nonceB = verifierB.newSessionNonce();
    // Wallet (honestly or maliciously) builds the proof bound to verifier A's
    // domain, but uses B's nonce and presents to B.
    const presentation = await makePresentation(nonceB, verifier.verifierId);
    const decision = await verifierB.verifyPresentation(presentation, {
      type: "age_gte",
      threshold: 18,
    });
    expect(decision.accepted).toBe(false);
    expect(decision.checks.stmtCodeValid).toBe(false);
    expect(decision.reasons.join(" ")).toMatch(/domain/);
  }, 120_000);
});
