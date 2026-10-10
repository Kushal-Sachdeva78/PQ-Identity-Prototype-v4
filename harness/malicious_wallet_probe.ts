import fs from "node:fs";
import path from "node:path";
import { RESULTS_DIR } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";
import { createIssuer } from "@pqid/issuer";
import { computeCredId, type Credential } from "@pqid/issuer";
import { createWallet, buildProofInput, prove } from "@pqid/wallet";
import { Ledger, startAnvil } from "@pqid/ledger";
import { Verifier } from "@pqid/verifier";
import { buildFixtureTree } from "./fixture.ts";

/**
 * MALICIOUS-WALLET PROBE (Assumption 5 / paper §III-B.4a, documented limit).
 *
 * A modified wallet SKIPS the off-circuit Dilithium check and presents a
 * FORGED credential: cred* was never signed by the issuer, but
 * credID* = SHA3-256(cred* ‖ pk_issuer) is internally consistent and not in
 * the revoked set. Relation R does not constrain the issuer signature, so the
 * Groth16 proof verifies AND the verifier accepts — both verifier-side checks
 * (on-chain pk_issuer resolution + Groth16.verify) pass by construction.
 *
 * This probe EXISTS TO DOCUMENT the gap honestly (it is the paper's stated
 * wallet-honesty assumption, with in-circuit Dilithium verification or TEE
 * attestation as the [F] mitigations). A PASS here means the gap reproduces
 * exactly as the paper describes.
 */
async function main(): Promise<void> {
  const anvil = await startAnvil(18549);
  let accepted = false;
  let reasons: string[] = [];
  try {
    const ledger = await Ledger.deploy(anvil.rpcUrl);
    // A real, accredited issuer with an on-chain DID Document…
    const issuer = createIssuer("liboqs");
    await ledger.registerDid(issuer.did, issuer.keys.publicKey);
    await ledger.accreditIssuer(issuer.did);

    const tree = await buildFixtureTree();
    await ledger.publishRevRoot(issuer.did, tree.root());

    // …and a malicious wallet forging a credential that issuer NEVER signed.
    const wallet = await createWallet();
    const forged: Credential = {
      subject: wallet.did,
      claims: { age: 42, name: "Forged Identity" },
      issuer: issuer.did,
      issuedAt: "2026-06-11T00:00:00.000Z",
      holderCommit: wallet.holderCommit.toString(),
      schema: "pqid:schema:identity-v1",
    };
    const forgedCredId = computeCredId(forged, issuer.keys.publicKey);
    const vcForged = {
      credential: forged,
      credID: forgedCredId.toString("hex"),
      signature: "00".repeat(2420), // garbage — no valid Dilithium signature exists
    };

    const verifier = new Verifier(ledger);
    const nonce = verifier.newSessionNonce();
    const input = await buildProofInput({
      wallet,
      vc: vcForged,
      request: {
        policy: { type: "age_gte", attribute: "age", threshold: 18 },
        nonce,
        verifierId: verifier.verifierId, // malicious wallet still targets THIS verifier
      },
      pkIssuer: issuer.keys.publicKey,
      revRoot: tree.root(),
      nonMembership: await tree.getNonMembershipProof(forgedCredId),
      dangerouslySkipOffCircuitChecks: true, // ← the malicious wallet
    });
    const proved = await prove(input, "snarkjs");

    const decision = await verifier.verifyPresentation(
      { proof: proved.proof, publicSignals: proved.publicSignals, issuerDid: issuer.did },
      { type: "age_gte", threshold: 18 }
    );
    accepted = decision.accepted;
    reasons = decision.reasons;
    ledger.destroy();
  } finally {
    anvil.stop();
  }

  // The probe PASSES when the forged proof IS accepted — that is the
  // documented Assumption-5 gap reproducing as specified.
  const gapReproduced = accepted;
  const out = {
    schema: "pqid/malicious-wallet-probe/v1",
    label: "[M] Assumption-5 demonstration (wallet honesty is load-bearing)",
    forgedProofAccepted: accepted,
    verifierReasons: reasons,
    gapReproducedAsDocumented: gapReproduced,
    interpretation:
      "Relation R does not verify the issuer's Dilithium signature in-circuit (by design — " +
      "millions of constraints). A wallet that skips the off-circuit check can prove possession " +
      "of a forged credential. End-to-end unforgeability therefore rests on Assumption 5 " +
      "(honest-but-protected wallet). Mitigations are [F]: in-circuit ML-DSA verification or " +
      "TEE/remote-attestation-bound wallets (paper §VII).",
    host: hostMeta(),
  };
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  const outFile = path.join(RESULTS_DIR, "malicious_probe.json");
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
  console.log(
    `[probe] forged-credential proof accepted = ${accepted} ` +
      `(expected true — this is the documented Assumption-5 gap) -> ${outFile}`
  );
  process.exit(gapReproduced ? 0 : 1);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
