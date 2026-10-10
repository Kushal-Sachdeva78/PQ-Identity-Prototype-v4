import fs from "node:fs";
import path from "node:path";
import { RESULTS_DIR } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";

/**
 * V6 §E — end-to-end authentication latency budget (paper §VI-C), recomputed
 * from the MEASURED components in results/zk.json and results/pqc.json, plus
 * the paper's [S] network estimates (unchanged, clearly labeled).
 */
interface Phase {
  headline: { valueMs: number; basis: string };
}
interface ZkJson {
  witnessGeneration: Phase;
  snarkjsProveCold: Phase;
  rapidsnarkProveCold: Phase;
  rapidsnarkProveAmortized: Phase;
  snarkjsVerify: Phase;
}
interface PqcJson {
  algorithms: Record<string, Record<string, { headline?: { valueMs: number } }>>;
}

function main(): void {
  const zk = JSON.parse(fs.readFileSync(path.join(RESULTS_DIR, "zk.json"), "utf8")) as ZkJson;
  const pqc = JSON.parse(fs.readFileSync(path.join(RESULTS_DIR, "pqc.json"), "utf8")) as PqcJson;
  const coolPath = path.join(RESULTS_DIR, "zk_rapidsnark_cool.json");
  const cool = fs.existsSync(coolPath)
    ? (JSON.parse(fs.readFileSync(coolPath, "utf8")) as {
        cold: { headline: { valueMs: number }; perRun: Array<{ medianMs: number }> };
      })
    : null;

  const witness = zk.witnessGeneration.headline.valueMs;
  const proveRs = zk.rapidsnarkProveCold.headline.valueMs;
  const proveRsAmort = zk.rapidsnarkProveAmortized.headline.valueMs;
  const proveRsCool = cool?.cold.perRun[0]?.medianMs; // truly-cool first run
  const proveSjs = zk.snarkjsProveCold.headline.valueMs;
  const verify = zk.snarkjsVerify.headline.valueMs;
  const dilithiumVerify =
    pqc.algorithms["ML-DSA-44"]?.["verify"]?.headline?.valueMs ?? 0.06;

  // Paper §VI-C network-dependent estimates — [S], reused unchanged.
  const net = {
    didLookupMs: { min: 20, max: 50, label: "[S]", source: "paper §VI-C (stitched estimate)" },
    revRootRetrievalMs: { min: 5, max: 15, label: "[S]", source: "paper §VI-C" },
    proofTransmissionMs: { min: 10, max: 50, label: "[S]", source: "paper §VI-C" },
  };
  const netMin = net.didLookupMs.min + net.revRootRetrievalMs.min + net.proofTransmissionMs.min;
  const netMax = net.didLookupMs.max + net.revRootRetrievalMs.max + net.proofTransmissionMs.max;

  const r1 = (x: number): number => Math.round(x * 10) / 10;
  const coreRapidsnark = r1(witness + proveRs + verify);
  const coreRapidsnarkCool = proveRsCool !== undefined ? r1(witness + proveRsCool + verify) : null;
  const coreSnarkjs = r1(witness + proveSjs + verify);

  const result = {
    schema: "pqid/e2e-latency/v1",
    label: "core components [M] (from zk.json/pqc.json headline values); network components [S] (paper estimates)",
    components: {
      witnessGenerationMs: { value: witness, label: "[M]", source: "results/zk.json witnessGeneration", basis: zk.witnessGeneration.headline.basis },
      proveRapidsnarkColdMs: { value: proveRs, label: "[M]", source: "results/zk.json rapidsnarkProveCold (paper-comparable basis)" },
      proveRapidsnarkAmortizedMs: { value: proveRsAmort, label: "[M]", source: "results/zk.json rapidsnarkProveAmortized (pure proving)" },
      proveSnarkjsMs: { value: proveSjs, label: "[M]", source: "results/zk.json snarkjsProveCold", basis: zk.snarkjsProveCold.headline.basis },
      verifyMs: { value: verify, label: "[M]", source: "results/zk.json snarkjsVerify" },
      walletDilithiumVerifyMs: { value: dilithiumVerify, label: "[M]", source: "results/pqc.json ML-DSA-44 verify" },
      ...net,
    },
    totals: {
      coreRapidsnarkMs: coreRapidsnark,
      coreRapidsnarkCoolMs: coreRapidsnarkCool,
      thermalNote:
        "coreRapidsnarkMs uses the campaign headline (sustained/heat-soaked state); " +
        "coreRapidsnarkCoolMs uses the truly-cool first run from zk_rapidsnark_cool.json — " +
        "the realistic single-authentication case (a wallet proves once, not 100× back-to-back)",
      coreSnarkjsMs: coreSnarkjs,
      e2eRapidsnarkMs: { min: r1(coreRapidsnark + dilithiumVerify + netMin), max: r1(coreRapidsnark + dilithiumVerify + netMax) },
      e2eSnarkjsMs: { min: r1(coreSnarkjs + dilithiumVerify + netMin), max: r1(coreSnarkjs + dilithiumVerify + netMax) },
      subSecondCoreRapidsnark: coreRapidsnark < 1000,
      subSecondCoreSnarkjs: coreSnarkjs < 1000,
      qualifier:
        "the sub-second claim holds ONLY for the native (rapidsnark) prover path; the snarkJS-path total must always carry that qualifier",
    },
    paperClaim: {
      manuscriptVersion: "V6.6",
      coreCoolMs: 309,
      coreSustainedMs: 390,
      coreBreakdown: "92 witness + 177 (cool) / 258.6 (sustained) rapidsnark + 40 verify (V6.6 §VI-C)",
      e2eRangeMs: "340–510 [S]",
    },
    host: hostMeta(),
  };
  const outFile = path.join(RESULTS_DIR, "e2e_latency.json");
  fs.writeFileSync(outFile, JSON.stringify(result, null, 2));
  console.log(
    `[latency] core: rapidsnark ${coreRapidsnark} ms (V6.6 390 sustained / 309 cool), snarkJS ${coreSnarkjs} ms; ` +
      `e2e rapidsnark ${result.totals.e2eRapidsnarkMs.min}-${result.totals.e2eRapidsnarkMs.max} ms -> ${outFile}`
  );
}

main();
