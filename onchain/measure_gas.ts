import fs from "node:fs";
import path from "node:path";
import { Interface } from "ethers";
import solc from "solc";
import { RESULTS_DIR, SOLIDITY_VERIFIER_FILE } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";
import { startAnvil } from "@pqid/ledger";
import { compileSolidity, deployContract, devSigner } from "@pqid/ledger/evm";
import { buildFixtureProofInput } from "../harness/fixture.ts";
import { assertQuiesced, collectControls } from "../harness/bench_env.ts";
import { prove } from "@pqid/wallet/prove";

/**
 * M8: upgrade the paper's on-chain gas figure from [A] (~2–3×10⁵, analytical)
 * to [M]. Deploys the snarkJS-exported Groth16Verifier to a local Anvil node,
 * calls verifyProof with a REAL proof, and records:
 *   - staticCall result (must be true)
 *   - eth_estimateGas of a direct verifyProof transaction (incl. 21k intrinsic)
 *   - receipt.gasUsed of a probe transaction that calls the verifier and
 *     writes the result to storage (upper bound incl. one SSTORE)
 */
const PROBE_SOURCE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
interface IGroth16Verifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[5] calldata pubSignals) external view returns (bool);
}
contract VerifierGasProbe {
    IGroth16Verifier public immutable verifier;
    bool public lastResult;
    constructor(address v) { verifier = IGroth16Verifier(v); }
    function probe(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[5] calldata pubSignals) external returns (bool ok) {
        ok = verifier.verifyProof(a, b, c, pubSignals);
        lastResult = ok;
    }
}
`;

async function main(): Promise<void> {
  if (!fs.existsSync(SOLIDITY_VERIFIER_FILE)) {
    throw new Error("Groth16Verifier.sol missing — run setup first");
  }
  // Gas units are execution-deterministic, but §B lists this as a measured
  // artifact — guard + record controls anyway (anvil is spawned by this run).
  const quiesce = assertQuiesced({ allowedNodeCount: 4 }); // own npx->npm->tsx chain = 3
  console.log("[gas] generating a real proof from the fixture pipeline…");
  const input = await buildFixtureProofInput();
  const proved = await prove(input, "snarkjs");

  const snarkjs = await import("snarkjs");
  const calldataStr = await snarkjs.groth16.exportSolidityCallData(
    proved.proof,
    proved.publicSignals
  );
  const [pA, pB, pC, pubSignals] = JSON.parse(`[${calldataStr}]`) as [
    [string, string],
    [[string, string], [string, string]],
    [string, string],
    string[]
  ];

  console.log("[gas] starting Anvil and deploying verifier + probe…");
  const anvil = await startAnvil(18546);
  try {
    const { signer, provider } = devSigner(anvil.rpcUrl);
    const verifierCompiled = compileSolidity({
      "Groth16Verifier.sol": fs.readFileSync(SOLIDITY_VERIFIER_FILE, "utf8"),
    });
    const verifierContract = verifierCompiled["Groth16Verifier"];
    if (!verifierContract) throw new Error("Groth16Verifier not found in solc output");
    const verifier = await deployContract(verifierContract, signer);
    const verifierAddr = await verifier.getAddress();

    const probeCompiled = compileSolidity({ "VerifierGasProbe.sol": PROBE_SOURCE });
    const probeContract = probeCompiled["VerifierGasProbe"];
    if (!probeContract) throw new Error("VerifierGasProbe not found in solc output");
    const probe = await deployContract(probeContract, signer, [verifierAddr]);

    // 1) correctness: staticCall must return true
    const staticResult = (await verifier["verifyProof"]?.staticCall(
      pA,
      pB,
      pC,
      pubSignals
    )) as boolean;
    if (!staticResult) throw new Error("on-chain verifyProof returned false for a valid proof");

    // negative control: corrupt one public signal -> must return false
    const badSignals = [...pubSignals];
    badSignals[3] = "0x" + (BigInt(badSignals[3] as string) + 1n).toString(16);
    const staticBad = (await verifier["verifyProof"]?.staticCall(
      pA,
      pB,
      pC,
      badSignals
    )) as boolean;
    if (staticBad) throw new Error("verifier accepted a corrupted public signal");

    // NOTE: eth_estimateGas is unusable here — the snarkjs verifier returns
    // false instead of reverting, so the estimator converges on a gas limit
    // that completes the tx while starving the bn254 pairing precompile
    // (verification silently fails). We therefore send REAL transactions with
    // a generous explicit gas limit and read receipt.gasUsed from runs whose
    // verification result is confirmed true.
    const GAS_LIMIT = 1_000_000n;

    // 2) bare verification transaction sent directly to the verifier
    const iface = new Interface(verifierContract.abi as never);
    const data = iface.encodeFunctionData("verifyProof", [pA, pB, pC, pubSignals]);
    const directTx = await signer.sendTransaction({
      to: verifierAddr,
      data,
      gasLimit: GAS_LIMIT,
    });
    const directReceipt = await directTx.wait();
    if (!directReceipt || directReceipt.status !== 1) {
      throw new Error("direct verifyProof transaction failed");
    }
    const directGas = directReceipt.gasUsed;

    // 3) probe transaction (verify + 1 SSTORE) whose result is checkable
    const probeTx = await probe["probe"]?.(pA, pB, pC, pubSignals, {
      gasLimit: GAS_LIMIT,
    });
    const receipt = await probeTx.wait();
    const probeGas = receipt.gasUsed as bigint;
    const lastResult = (await probe["lastResult"]?.()) as boolean;
    if (!lastResult) throw new Error("probe recorded a failed verification");

    const result = {
      schema: "pqid/gas/v2",
      label: "[M] measured (local Anvil single-node EVM; public testnet remains [F])",
      controls: collectControls({
        quiesce,
        fsBasis: "local Anvil EVM (gas units are execution-deterministic)",
        invocations: 1,
      }),
      paperClaim: { manuscriptVersion: "V6.6", gas: 242931, label: "[M] measured (local single-node EVM; public testnet remains [F])" },
      verifyProofDirectTxGasUsed: Number(directGas),
      probeTxGasUsed: Number(probeGas),
      probeNote:
        "direct = bare verifyProof tx (21k intrinsic + calldata + execution); probe = verifyProof " +
        "via CALL + result SSTORE. Real receipts with explicit 1M gas limit — eth_estimateGas is " +
        "unsound for this verifier because it returns false (not revert) under gas starvation.",
      calldataBytes: (data.length - 2) / 2,
      staticCallValid: staticResult,
      corruptedSignalRejected: !staticBad,
      publicSignals: proved.publicSignals,
      toolchain: {
        solc: solc.version(),
        anvil: "foundry stable (tools/foundry/anvil.exe)",
        snarkjsVerifierTemplate: "snarkjs 0.7.4 verifier_groth16.sol.ejs",
        optimizer: { enabled: true, runs: 200 },
      },
      host: hostMeta(),
    };
    fs.mkdirSync(RESULTS_DIR, { recursive: true });
    const outFile = path.join(RESULTS_DIR, "gas.json");
    fs.writeFileSync(outFile, JSON.stringify(result, null, 2));
    console.log(
      `[gas] verifyProof direct estimate: ${directGas} gas; probe tx: ${probeGas} gas ` +
        `(V6.6 [M]: 242931 bare / 268893 via contract) -> ${outFile}`
    );
    provider.destroy();
  } finally {
    anvil.stop();
  }
  process.exit(0);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
