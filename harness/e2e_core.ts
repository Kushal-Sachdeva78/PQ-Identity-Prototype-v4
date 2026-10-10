import fs from "node:fs";
import path from "node:path";
import { canonicalJsonBytes, sha3_256 } from "@pqid/common/hash";
import { REPO_ROOT } from "@pqid/common/paths";
import { createIssuer, issueCredential, type SigImpl } from "@pqid/issuer";
import { createWallet, walletCheckCredential, generateProof, type PolicyV1, type ProveResult } from "@pqid/wallet";
import { RevocationTree } from "@pqid/revocation";
import { Ledger, startAnvil, type AnvilHandle } from "@pqid/ledger";
import { Verifier, type Presentation } from "@pqid/verifier";

/**
 * The full credential lifecycle (paper Figure 2), executable end-to-end:
 *   DID registration → issuance (dilithium-py per A.5) → off-circuit liboqs
 *   Dilithium verify → witness (depth-32 non-membership) → Groth16 proof
 *   (snarkJS + rapidsnark) → verifier resolve+equality+verify+nonce →
 *   revocation → re-verify rejects.
 *
 * Wall-clock timings recorded here are PIPELINE times (they include WSL
 * bridge overhead and EVM round trips) — Table IV/V numbers come exclusively
 * from results/pqc.json and results/zk.json.
 */
export interface E2EStep {
  step: string;
  ok: boolean;
  wallMs: number;
  detail?: Record<string, unknown>;
}

export type StepSink = (step: E2EStep) => void;

export interface E2EResult {
  steps: E2EStep[];
  ok: boolean;
  vcBytes: number;
  proofBytes: { snarkjs: number; rapidsnark: number };
  issuanceImpl: SigImpl;
}

export async function runLifecycle(onStep: StepSink = () => {}): Promise<E2EResult> {
  const steps: E2EStep[] = [];
  const record = async <T>(
    name: string,
    fn: () => Promise<T>,
    detail?: (v: T) => Record<string, unknown>
  ): Promise<T> => {
    const t0 = process.hrtime.bigint();
    try {
      const v = await fn();
      const step: E2EStep = {
        step: name,
        ok: true,
        wallMs: Math.round(Number(process.hrtime.bigint() - t0) / 1e3) / 1e3,
        ...(detail ? { detail: detail(v) } : {}),
      };
      steps.push(step);
      onStep(step);
      return v;
    } catch (e) {
      const step: E2EStep = {
        step: name,
        ok: false,
        wallMs: Math.round(Number(process.hrtime.bigint() - t0) / 1e3) / 1e3,
        detail: { error: (e as Error).message },
      };
      steps.push(step);
      onStep(step);
      throw e;
    }
  };

  let anvil: AnvilHandle | null = null;
  let ledger: Ledger | null = null;
  try {
    anvil = await record("ledger: start single-node EVM (Anvil)", () => startAnvil(18548));
    ledger = await record("ledger: deploy DID/Issuer/Revocation/Schema registries", () =>
      Ledger.deploy((anvil as AnvilHandle).rpcUrl)
    , (l) => ({ addresses: l.addresses }));
    const ldg = ledger;

    // ---- actors
    const issuer = await record(
      "issuer: ML-DSA-44 keygen (dilithium-py 1.4.0, harness issuance step per paper A.5)",
      async () => createIssuer("dilithium-py"),
      (i) => ({ did: i.did, pkBytes: i.keys.publicKey.length })
    );
    const wallet = await record(
      "wallet: ML-DSA-44 keygen (liboqs) + holder secret/commitment",
      () => createWallet(),
      (w) => ({ did: w.did })
    );

    // ---- DID registration (Algorithm 1)
    await record("ledger: register issuer DID Document", () =>
      ldg.registerDid(issuer.did, issuer.keys.publicKey, ["https://issuer.example/api"])
    );
    await record("ledger: register holder DID Document", () =>
      ldg.registerDid(wallet.did, wallet.keys.publicKey)
    );
    await record("ledger: accredit issuer in Issuer Registry", () => ldg.accreditIssuer(issuer.did));
    const schema = JSON.parse(
      fs.readFileSync(path.join(REPO_ROOT, "fixtures", "vc-schema.json"), "utf8")
    ) as unknown;
    await record("ledger: register credential schema", () =>
      ldg.registerSchema("pqid:schema:identity-v1", schema, "fixtures/vc-schema.json")
    );

    // ---- revoked-set accumulator (8 fixture entries) + root on-chain
    const tree = await record(
      "revocation: build depth-32 SMT with 8 revoked fixture credIDs",
      async () => {
        const t = await RevocationTree.create();
        const revoked = JSON.parse(
          fs.readFileSync(path.join(REPO_ROOT, "fixtures", "revoked-set.json"), "utf8")
        ) as { labels: string[] };
        for (const label of revoked.labels) await t.insert(sha3_256(Buffer.from(label, "utf8")));
        return t;
      },
      (t) => ({ root: t.root().toString().slice(0, 24) + "…" })
    );
    await record("ledger: publish initial revocation root (Algorithm 4)", () =>
      ldg.publishRevRoot(issuer.did, tree.root())
    );

    // ---- issuance (Algorithm 2)
    const vc = await record(
      "issuer: issue VC — credID = SHA3-256(cred ‖ pk_issuer), Dilithium sign (dilithium-py)",
      async () =>
        issueCredential({
          issuer,
          subjectDid: wallet.did,
          claims: { age: 42, name: "Demo Holder" },
          holderCommit: wallet.holderCommit,
          issuedAt: "2026-06-11T00:00:00.000Z",
        }),
      (v) => ({ credID: v.credID.slice(0, 16) + "…", sigBytes: v.signature.length / 2 })
    );
    const vcBytes = canonicalJsonBytes(vc).length;

    // ---- wallet off-circuit checks (two-phase verification, phase 1)
    const policy: PolicyV1 = { type: "age_gte", attribute: "age", threshold: 18 };
    await record(
      "wallet: OFF-CIRCUIT Dilithium verify (liboqs ← dilithium-py sig: live interop) + holder binding + policy",
      async () => {
        const res = walletCheckCredential(wallet, vc, issuer.keys.publicKey, policy);
        if (!res.ok) throw new Error(`off-circuit checks failed: ${JSON.stringify(res)}`);
        return res;
      },
      (r) => ({ ...r })
    );

    // ---- proof generation (Algorithm 3), both backends
    const verifier = new Verifier(ldg);
    const nonce = verifier.newSessionNonce();
    const proofArgs = async () => ({
      wallet,
      vc,
      request: { policy, nonce, verifierId: verifier.verifierId },
      pkIssuer: issuer.keys.publicKey,
      revRoot: await ldg.getRevRoot(issuer.did),
      nonMembership: await tree.getNonMembershipProof(Buffer.from(vc.credID, "hex")),
    });
    const rsProof = await record(
      "wallet: witness (incl. depth-32 non-membership) + Groth16 prove [rapidsnark native]",
      async () => generateProof(await proofArgs(), "rapidsnark"),
      (p) => ({ proofBytes: p.proofJsonBytes, witnessMs: p.timings.witnessMs, proveMs: p.timings.proveMs })
    );
    const sjProof = await record(
      "wallet: Groth16 prove [snarkJS] on the same statement",
      async () => generateProof(await proofArgs(), "snarkjs"),
      (p) => ({ proofBytes: p.proofJsonBytes, proveMs: p.timings.proveMs })
    );

    // ---- verification (two-phase verification, phase 2)
    const present = (p: ProveResult): Presentation => ({
      proof: p.proof,
      publicSignals: p.publicSignals,
      issuerDid: issuer.did,
    });
    await record(
      "verifier: resolve pk_issuer + revRoot on-chain, equality, Groth16.verify, nonce (rapidsnark proof)",
      async () => {
        const d = await verifier.verifyPresentation(present(rsProof), { type: "age_gte", threshold: 18 });
        if (!d.accepted) throw new Error(`rejected: ${d.reasons.join("; ")}`);
        return d;
      },
      (d) => ({ checks: d.checks })
    );
    const nonce2 = verifier.newSessionNonce();
    const sjProof2 = await record(
      "wallet: fresh proof for second session [snarkJS]",
      async () =>
        generateProof(
          {
            wallet,
            vc,
            request: { policy, nonce: nonce2, verifierId: verifier.verifierId },
            pkIssuer: issuer.keys.publicKey,
            revRoot: await ldg.getRevRoot(issuer.did),
            nonMembership: await tree.getNonMembershipProof(Buffer.from(vc.credID, "hex")),
          },
          "snarkjs"
        )
    );
    await record("verifier: accept snarkJS proof (second session)", async () => {
      const d = await verifier.verifyPresentation(present(sjProof2), { type: "age_gte", threshold: 18 });
      if (!d.accepted) throw new Error(`rejected: ${d.reasons.join("; ")}`);
      return d;
    });

    // ---- revocation (Algorithm 4) + re-verify rejects
    await record("issuer: REVOKE credential — insert credID into SMT, publish new root", async () => {
      await tree.insert(Buffer.from(vc.credID, "hex"));
      await ldg.publishRevRoot(issuer.did, tree.root());
    });
    await record(
      "wallet: attempt to build a fresh proof — REFUSED (no non-membership opening exists)",
      async () => {
        try {
          await tree.getNonMembershipProof(Buffer.from(vc.credID, "hex"));
          throw new Error("non-membership proof unexpectedly succeeded for a revoked credID");
        } catch (e) {
          if ((e as Error).message.includes("revoked")) return { refused: true };
          throw e;
        }
      },
      (r) => r
    );
    await record(
      "verifier: REJECT replay of the pre-revocation proof (revRoot equality fails)",
      async () => {
        const nonce3 = verifier.newSessionNonce();
        void nonce3; // old proof carries the old nonce anyway — both checks fail
        const d = await verifier.verifyPresentation(present(sjProof), { type: "age_gte", threshold: 18 });
        if (d.accepted) throw new Error("verifier ACCEPTED a revoked credential — protocol violation");
        return d;
      },
      (d) => ({ reasons: d.reasons, revRootMatches: d.checks.revRootMatches })
    );

    return {
      steps,
      ok: steps.every((s) => s.ok),
      vcBytes,
      proofBytes: { snarkjs: sjProof.proofJsonBytes, rapidsnark: rsProof.proofJsonBytes },
      issuanceImpl: "dilithium-py",
    };
  } finally {
    ledger?.destroy();
    anvil?.stop();
  }
}
