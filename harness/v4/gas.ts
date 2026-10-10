import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Interface } from "ethers";
import { REPO_ROOT } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";
import { sha256File } from "@pqid/common/hash";
import { compileSolidity, deployContract, devSigner } from "@pqid/ledger/evm";
import { World } from "@pqid/v4/world";
import { SOL_V4, KEY_LABEL_V4 } from "@pqid/v4/paths";
import { DEFAULT_TYPE_ID, MIN_ANCHOR_INTERVAL_SEC } from "@pqid/v4/constants";

/**
 * v4 gas on a local Anvil chain (TASKS Part 3: "v4 Solidity verifier gas measured").
 *   - verifyProof: the v4 Groth16 Solidity verifier (setup/out/v4/Groth16VerifierV4_dev.sol,
 *     8 public signals) called with a REAL presentation from an honest wallet; staticCall must
 *     return true; the gas of a direct transaction (receipt.gasUsed, includes 21,000 intrinsic).
 *   - the issuer's epoch anchor, first and later (the other v4 registry writes, with
 *     calldata and the EVM version, are measured by harness/v4/scale.ts, E4).
 * Gas is deterministic for fixed calldata; no timing, so no quiet machine is needed. Key: dev.
 * Output: results/v4/gas.json
 */
const OUT = path.join(REPO_ROOT, "results", "v4", "gas.json");

async function main(): Promise<void> {
  const world = await World.create({ port: 8597 });
  try {
    const L = world.ledger;
    const gas: Record<string, number> = {};
    const track = <T extends { gasUsed?: bigint | number }>(name: string, r: T) => {
      if (r && r.gasUsed !== undefined) gas[name] = Number(r.gasUsed);
      return r;
    };
    // Registry writes, measured through the ledger wrappers on fresh records.
    const issuer = await world.addIssuer("gas-issuer");
    const V = await world.addVerifier("gas-verifier");
    const h = await world.addHolder();
    await world.issue(issuer, h, { birthDate: 19900510 });
    const first = await world.publishEpoch(issuer);
    track("publishEpoch_first", first as never);
    await world.issue(issuer, await world.addHolder(), { birthDate: 19800101 });
    await world.advance(MIN_ANCHOR_INTERVAL_SEC + 1);
    const later = await world.publishEpoch(issuer);
    track("publishEpoch_later", later as never);

    // A real presentation (honest wallet) and the verifier's own decision.
    const req = await V.newRequest({ predicate: "age_gte", threshold: 18, typeId: DEFAULT_TYPE_ID });
    const { reply, presentation } = await h.present(req, { callerOrigin: V.opts.identity.origin });
    const decision = await V.verifyReply(reply);
    if (!decision.accepted) throw new Error(`honest presentation not accepted: ${decision.failedChecks.join(",")}`);

    // Deploy the v4 Solidity verifier and call it with that proof.
    const { signer } = devSigner(world.anvil.rpcUrl);
    const compiled = compileSolidity({ "Groth16VerifierV4_dev.sol": fs.readFileSync(SOL_V4, "utf8") });
    const contract = compiled["Groth16Verifier"];
    if (!contract) throw new Error("Groth16Verifier missing from solc output");
    const verifier = await deployContract(contract, signer);
    const snarkjs = await import("snarkjs");
    const calldata = await snarkjs.groth16.exportSolidityCallData(presentation.proof, presentation.publicSignals);
    const [pA, pB, pC, pub] = JSON.parse(`[${calldata}]`) as [unknown, unknown, unknown, string[]];
    if (pub.length !== 8) throw new Error(`expected 8 public signals, got ${pub.length}`);
    const ok = (await verifier["verifyProof"]?.staticCall(pA, pB, pC, pub)) as boolean;
    if (!ok) throw new Error("on-chain verifyProof returned false for a valid v4 proof");
    const bad = [...pub];
    bad[3] = (BigInt(bad[3] as string) + 1n).toString();
    const okBad = (await verifier["verifyProof"]?.staticCall(pA, pB, pC, bad)) as boolean;
    const data = new Interface(contract.abi as never).encodeFunctionData("verifyProof", [pA, pB, pC, pub]);
    const tx = await signer.sendTransaction({ to: await verifier.getAddress(), data, gasLimit: 1_000_000n });
    const receipt = await tx.wait();
    if (!receipt || receipt.status !== 1) throw new Error("verifyProof transaction failed");
    // Gas depends on the proof bytes (zero calldata bytes cost 4, others 16), so measure
    // several fresh presentations and report the spread.
    const N = 10;
    const perProof: number[] = [Number(receipt.gasUsed)];
    for (let i = 1; i < N; i++) {
      const r2 = await V.newRequest({ predicate: "age_gte", threshold: 18, typeId: DEFAULT_TYPE_ID });
      await world.advance(1);
      const p2 = (await h.present(r2, { callerOrigin: V.opts.identity.origin })).presentation;
      const cd2 = await snarkjs.groth16.exportSolidityCallData(p2.proof, p2.publicSignals);
      const [a2, b2, c2, s2] = JSON.parse(`[${cd2}]`) as [unknown, unknown, unknown, string[]];
      const d2 = new Interface(contract.abi as never).encodeFunctionData("verifyProof", [a2, b2, c2, s2]);
      const t2 = await signer.sendTransaction({ to: await verifier.getAddress(), data: d2, gasLimit: 1_000_000n });
      const rc2 = await t2.wait();
      if (!rc2 || rc2.status !== 1) throw new Error("verifyProof transaction failed");
      perProof.push(Number(rc2.gasUsed));
    }
    const sorted = [...perProof].sort((x, y) => x - y);
    const median = sorted.length % 2 ? sorted[(sorted.length - 1) / 2]! : (sorted[sorted.length / 2 - 1]! + sorted[sorted.length / 2]!) / 2;

    const out = {
      schema: "pqid/v4-gas/v1",
      label: "[M] local Anvil, one transaction each; gas is deterministic for fixed calldata",
      keyLabel: KEY_LABEL_V4,
      verifier: { file: "setup/out/v4/Groth16VerifierV4_dev.sol", sha256: sha256File(SOL_V4) },
      verifyProofDirectTxGasUsed: median,
      verifyProofGasPerProof: { n: perProof.length, median, min: sorted[0], max: sorted[sorted.length - 1], values: perProof, note: "one fresh presentation per transaction; the spread comes from zero bytes in the proof calldata" },
      verifyProofCalldataBytes: (data.length - 2) / 2,
      calldata: (() => {
        const bytes = Buffer.from(data.slice(2), "hex");
        const zero = bytes.filter((x) => x === 0).length;
        const tokens = zero + 4 * (bytes.length - zero);
        const floor = 21000 + 10 * tokens;
        return { zeroBytes: zero, nonZeroBytes: bytes.length - zero, eip7623FloorGas: floor, floorBinds: Number(receipt.gasUsed) === floor, ofFirstProof: true, note: "[S] EIP-7623 floor = 21000 + 10 x (zero bytes + 4 x non-zero bytes)" };
      })(),
      staticCallValidProof: ok,
      staticCallTamperedNonceRejected: okBad === false,
      registryWrites: gas,
      evm: "Anvil default hardfork (see tools/foundry version in host meta)",
      host: hostMeta(),
    };
    fs.mkdirSync(path.dirname(OUT), { recursive: true });
    fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + "\n");
    console.log(`[gas] verifyProof median ${out.verifyProofDirectTxGasUsed} gas (min ${sorted[0]}, max ${sorted[sorted.length - 1]}, n ${perProof.length}) (calldata ${out.verifyProofCalldataBytes} B); registry writes ${JSON.stringify(gas)} -> results/v4/gas.json`);
    void L;
  } finally {
    world.stop();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(
    () => process.exit(0),
    (e: unknown) => {
      console.error(e);
      process.exit(1);
    }
  );
}
