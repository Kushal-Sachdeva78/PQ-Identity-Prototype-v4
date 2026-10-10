import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { World } from "@pqid/v4/world";
import { publishedEpochBlob, parsePublication, publishedSource, publishedBytes } from "@pqid/v4/published";
import { issuanceWitnessV4, revocationWitnessV4, revokeCredentialV4, type IssuerV4 } from "@pqid/v4/issuer";
import { DEFAULT_TYPE_ID, MIN_ANCHOR_INTERVAL_SEC } from "@pqid/v4/constants";

// E3 published-tree mode: wallets rebuild their own paths from one published blob.
describe("published-tree mode", () => {
  let world: World;
  let A: IssuerV4;
  beforeAll(async () => {
    world = await World.create({ port: 8591 });
    A = await world.addIssuer("A");
  }, 300_000);
  afterAll(() => world?.stop());

  it("rebuilds the anchored roots, gives the same witnesses as the online services, and the verifier accepts", async () => {
    const holders: Array<{ h: Awaited<ReturnType<World["addHolder"]>>; vc: Awaited<ReturnType<World["issue"]>> }> = [];
    for (let i = 0; i < 6; i++) {
      const h = await world.addHolder();
      const vc = await world.issue(A, h, { birthDate: 19800101 + i });
      holders.push({ h, vc });
    }
    await world.publishEpoch(A);
    revokeCredentialV4(A, holders[5]!.vc.credID);
    await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
    await world.publishEpoch(A);
    const blob = publishedEpochBlob(A);
    const pub = await parsePublication(blob);
    expect(pub.statement.epoch).toBe(A.anchored!.statement.epoch);
    const stLen = new TextEncoder().encode(JSON.stringify(pub.statement)).length;
    expect(blob.length).toBe(publishedBytes(6, 1, stLen));
    const idx = new Map(holders.map(({ vc }) => [vc.credID, vc.leafIndex] as const));
    const src = publishedSource(pub, idx);
    for (const { vc } of holders.slice(0, 5)) {
      expect(src.issuance(vc.credID).path).toEqual(issuanceWitnessV4(A, vc.credID).path);
      expect(src.revocation(vc.credID)).toEqual(revocationWitnessV4(A, vc.credID));
    }
    expect(() => src.revocation(holders[5]!.vc.credID)).toThrow();
    // present with the published source instead of the issuer's services
    const { h, vc } = holders[0]!;
    h.credentials[0]!.source = src;
    const V = await world.addVerifier("V");
    const req = await V.newRequest({ predicate: "age_gte", threshold: 18, typeId: DEFAULT_TYPE_ID });
    const { reply } = await h.present(req, { callerOrigin: V.opts.identity.origin });
    const d = await V.verifyReply(reply);
    expect(d.failedChecks).toEqual([]);
    expect(d.accepted).toBe(true);
    void vc;
  }, 600_000);
});
