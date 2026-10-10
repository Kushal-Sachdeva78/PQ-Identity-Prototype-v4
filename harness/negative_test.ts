import fs from "node:fs";
import path from "node:path";
import { sha3_256 } from "@pqid/common/hash";
import { RESULTS_DIR, VKEY_FILE } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";
import {
  getPoseidon,
  issuerKeyHash,
  policyHash,
  holderCommit,
  verifierDomainTag,
  stmtCodeForDomain,
  PREDICATE_AGE_GTE,
} from "@pqid/common/encoding";
import { RevocationTree } from "@pqid/revocation";
import { buildCircuitInput } from "@pqid/wallet/witness";
import { computeWitness, proveSnarkjsOnWitness } from "@pqid/wallet/prove";
import { fixtureRevokedCredIds, FIXTURE_PK_ISSUER, FIXTURE_HOLDER_SECRET } from "./fixture.ts";

/**
 * REQUIRED NEGATIVE TEST (paper A.5): a credential whose credID is in the
 * revoked set must not produce an accepted proof. All three adversarial
 * strategies are exercised:
 *   A. honest wallet: the revocation service refuses a non-membership opening;
 *   B. stale opening + CURRENT root: the witness violates the SMTVerifier
 *      constraints — no proof can even be generated;
 *   C. stale opening + STALE root: a proof IS generated and is cryptographically
 *      valid, but the verifier's on-chain revRoot equality check rejects it.
 * Outcome required: no path yields an ACCEPTED proof.
 */
async function main(): Promise<void> {
  const poseidon = await getPoseidon();
  const tree = await RevocationTree.create();
  for (const credId of fixtureRevokedCredIds()) await tree.insert(credId);

  // The credential under test — and a pre-revocation snapshot of its opening.
  const credId = sha3_256(Buffer.from("pqid-negative-subject", "utf8"));
  const staleOpening = await tree.getNonMembershipProof(credId);
  const staleRoot = tree.root();

  // REVOKE it (Algorithm 4): insert into the SMT; new root is now canonical.
  await tree.insert(credId);
  const currentRoot = tree.root();
  console.log(`[negative] credential revoked; root ${staleRoot} -> ${currentRoot}`);

  const domainTag = verifierDomainTag(poseidon, "pqid:verifier:demo");
  const mkInput = (opening: typeof staleOpening, root: bigint) =>
    buildCircuitInput(
      {
        issuerKeyHash: issuerKeyHash(poseidon, FIXTURE_PK_ISSUER),
        revRoot: root,
        policyHash: policyHash(poseidon, PREDICATE_AGE_GTE, 18n),
        nonce: 7777n,
        stmtCode: stmtCodeForDomain(poseidon, domainTag),
      },
      {
        credId,
        holderSecret: FIXTURE_HOLDER_SECRET,
        holderCommit: holderCommit(poseidon, FIXTURE_HOLDER_SECRET),
        claimAge: 42n,
        threshold: 18n,
        predicateCode: PREDICATE_AGE_GTE,
        domainTag,
        nonMembership: opening,
      }
    );

  // Path A — honest wallet
  let pathA = false;
  try {
    await tree.getNonMembershipProof(credId);
  } catch (e) {
    pathA = (e as Error).message.includes("revoked");
    console.log(`[negative] A: honest wallet refused: "${(e as Error).message}"`);
  }

  // Path B — stale opening against the current root: witness must fail
  let pathB = false;
  try {
    const wtns = await computeWitness(mkInput({ ...staleOpening, root: currentRoot.toString() }, currentRoot));
    fs.rmSync(wtns.wtnsFile, { force: true });
    console.log("[negative] B: WITNESS UNEXPECTEDLY SUCCEEDED — soundness violation");
  } catch {
    pathB = true;
    console.log("[negative] B: stale opening + current root -> constraint violation (no proof)");
  }

  // Path C — stale opening + stale root: proof exists but verifier rejects
  let pathC = false;
  const { wtnsFile } = await computeWitness(mkInput(staleOpening, staleRoot));
  const proved = await proveSnarkjsOnWitness(wtnsFile);
  fs.rmSync(wtnsFile, { force: true });
  const snarkjs = await import("snarkjs");
  const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, "utf8")) as unknown;
  const cryptographicallyValid = await snarkjs.groth16.verify(
    vkey,
    proved.publicSignals,
    proved.proof
  );
  // The verifier's mandatory equality check against the CURRENT on-chain root:
  const proofRoot = proved.publicSignals[1];
  const rootEqualityPasses = proofRoot === currentRoot.toString();
  pathC = cryptographicallyValid && !rootEqualityPasses;
  console.log(
    `[negative] C: stale-root proof valid=${cryptographicallyValid}, ` +
      `revRoot equality vs chain=${rootEqualityPasses} -> verifier rejects`
  );

  const pass = pathA && pathB && pathC;
  const out = {
    schema: "pqid/negative-test/v1",
    label: "[M] revoked credential ⇒ no accepted proof",
    pass,
    paths: {
      honestWalletRefuses: pathA,
      staleOpeningCurrentRootWitnessFails: pathB,
      staleRootProofRejectedByRootEquality: pathC,
    },
    detail: {
      staleRoot: staleRoot.toString(),
      currentRoot: currentRoot.toString(),
      pathCProofCryptographicallyValid: cryptographicallyValid,
      note:
        "Path C shows why the verifier's on-chain revRoot equality check is mandatory: " +
        "Groth16 validity alone does not imply freshness of the revocation statement.",
    },
    host: hostMeta(),
  };
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  const outFile = path.join(RESULTS_DIR, "negative.json");
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
  console.log(`\n[negative] ${pass ? "PASS" : "FAIL"} -> ${outFile}`);
  process.exit(pass ? 0 : 1);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
