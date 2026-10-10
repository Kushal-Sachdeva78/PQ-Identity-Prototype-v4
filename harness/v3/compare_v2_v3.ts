import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { Interface } from "ethers";
import {
  REPO_ROOT,
  RESULTS_DIR_V3,
  CIRCUIT_BUILD_DIR,
  CIRCUIT_BUILD_DIR_V3,
  PTAU_FILE,
  ZKEY_FILE,
  ZKEY_FILE_V3,
  WASM_FILE,
  WASM_FILE_V3,
  SOLIDITY_VERIFIER_FILE,
  SOLIDITY_VERIFIER_FILE_V3,
} from "@pqid/common/paths";
import { summarize } from "@pqid/common/stats";
import { computeWitness, proveSnarkjsOnWitness } from "@pqid/wallet/prove";
import {
  compileSolidity,
  compileRegistries,
  compileIssuanceRootRegistry,
  deployContract,
  devSigner,
  startAnvil,
} from "@pqid/ledger/evm";
import { sha3_256 } from "@pqid/common/hash";
import { BN254_P } from "@pqid/common/encoding";
import { didRegistryKey } from "@pqid/common/did";
import { assertQuiesced, collectControls } from "../bench_env.ts";
import { buildFixtureProofInput, buildFixtureProofInputV3 } from "../fixture.ts";

/**
 * Cost of the v3 fix, measured side by side on one host in one session:
 *   - R1CS constraints: v2 as published (--O1), v2 at --O2, v3 (--O2);
 *   - snarkJS witness + Groth16 prove time, interleaved rounds so thermal
 *     drift hits all three configurations alike (median and IQR reported);
 *   - on-chain verifyProof gas (real Anvil receipts, as onchain/measure_gas.ts);
 *   - gas of anchoring one signed issuance root (paid by the issuer once per
 *     epoch, not per presentation).
 * v2-at-O2 isolates what v3 adds from the optimisation-level change: its key
 * is a throwaway phase-2 init used ONLY for timing (never for verification).
 * rapidsnark is not included (needs the WSL native build).
 */
const ROUNDS = Number(process.env["PQID_COMPARE_ROUNDS"] ?? 15);
const WARMUP = 2;

function circomBinary(): string {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  return process.platform === "win32" && fs.existsSync(win) ? win : "circom";
}

function quartiles(xs: number[]): { q1: number; q3: number; iqr: number } {
  const s = [...xs].sort((a, b) => a - b);
  const at = (p: number) => {
    const i = (s.length - 1) * p;
    const lo = Math.floor(i);
    const hi = Math.ceil(i);
    return (s[lo] as number) + ((s[hi] as number) - (s[lo] as number)) * (i - lo);
  };
  const r = (x: number) => Math.round(x * 10) / 10;
  return { q1: r(at(0.25)), q3: r(at(0.75)), iqr: r(at(0.75) - at(0.25)) };
}

interface Config {
  name: string;
  wasm: string;
  zkey: string;
  input: Record<string, string | string[]>;
  solidity?: string;
  nPublic: number;
}

async function main(): Promise<void> {
  const quiesce = assertQuiesced({ allowedNodeCount: 4 });
  const snarkjs = await import("snarkjs");

  // --- v2 at --O2 (constraints + a timing-only key)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-v2-o2-"));
  execFileSync(
    circomBinary(),
    [path.join(REPO_ROOT, "circuits", "credential_auth.circom"), "--O2", "--r1cs", "--wasm", "-o", tmp],
    { cwd: REPO_ROOT, encoding: "utf8" }
  );
  const v2o2R1cs = path.join(tmp, "credential_auth.r1cs");
  const v2o2Wasm = path.join(tmp, "credential_auth_js", "credential_auth.wasm");
  const v2o2Zkey = path.join(tmp, "credential_auth_o2_timing.zkey");
  await snarkjs.zKey.newZKey(v2o2R1cs, PTAU_FILE, v2o2Zkey);

  const info = async (r1cs: string) => {
    const i = await snarkjs.r1cs.info(r1cs);
    return { nConstraints: i.nConstraints, nWires: i.nVars, nPublic: i.nPubInputs, nPrivate: i.nPrvInputs };
  };
  const constraints = {
    v2_published_O1: await info(path.join(CIRCUIT_BUILD_DIR, "credential_auth.r1cs")),
    v2_O2: await info(v2o2R1cs),
    v3_O2: await info(path.join(CIRCUIT_BUILD_DIR_V3, "credential_auth_v3.r1cs")),
  };

  const v2Input = await buildFixtureProofInput();
  const v3Input = await buildFixtureProofInputV3();
  const configs: Config[] = [
    { name: "v2_published_O1", wasm: WASM_FILE, zkey: ZKEY_FILE, input: v2Input, solidity: SOLIDITY_VERIFIER_FILE, nPublic: 5 },
    { name: "v2_O2", wasm: v2o2Wasm, zkey: v2o2Zkey, input: v2Input, nPublic: 5 },
    { name: "v3_O2", wasm: WASM_FILE_V3, zkey: ZKEY_FILE_V3, input: v3Input, solidity: SOLIDITY_VERIFIER_FILE_V3, nPublic: 6 },
  ];

  // --- interleaved timing rounds
  const samples: Record<string, { witnessMs: number[]; proveMs: number[] }> = {};
  for (const c of configs) samples[c.name] = { witnessMs: [], proveMs: [] };
  const proofs: Record<string, { proof: unknown; publicSignals: string[] }> = {};
  for (let round = -WARMUP; round < ROUNDS; round++) {
    for (const c of configs) {
      const w = await computeWitness(c.input, c.wasm);
      const p = await proveSnarkjsOnWitness(w.wtnsFile, c.zkey);
      fs.rmSync(w.wtnsFile, { force: true });
      proofs[c.name] = { proof: p.proof, publicSignals: p.publicSignals };
      if (round >= 0) {
        samples[c.name]?.witnessMs.push(w.witnessMs);
        samples[c.name]?.proveMs.push(p.timings.proveMs);
      }
    }
    if (round >= 0) console.log(`[compare] round ${round + 1}/${ROUNDS}`);
  }
  const timing = Object.fromEntries(
    configs.map((c) => {
      const s = samples[c.name] as { witnessMs: number[]; proveMs: number[] };
      return [
        c.name,
        {
          witness: { ...summarize(s.witnessMs), ...quartiles(s.witnessMs) },
          prove: { ...summarize(s.proveMs), ...quartiles(s.proveMs) },
        },
      ];
    })
  );

  // --- on-chain verifyProof gas for the two real verifiers
  const gas: Record<string, Record<string, number | boolean>> = {};
  const anvil = await startAnvil(18731);
  try {
    const { signer, provider } = devSigner(anvil.rpcUrl);
    for (const c of configs.filter((x) => x.solidity)) {
      const compiled = compileSolidity({ "Groth16Verifier.sol": fs.readFileSync(c.solidity as string, "utf8") });
      const contract = compiled["Groth16Verifier"];
      if (!contract) throw new Error("Groth16Verifier missing from solc output");
      const verifier = await deployContract(contract, signer);
      const pr = proofs[c.name] as { proof: never; publicSignals: string[] };
      const calldata = await snarkjs.groth16.exportSolidityCallData(pr.proof, pr.publicSignals);
      const [pA, pB, pC, pub] = JSON.parse(`[${calldata}]`) as [unknown, unknown, unknown, string[]];
      const ok = (await verifier["verifyProof"]?.staticCall(pA, pB, pC, pub)) as boolean;
      if (!ok) throw new Error(`${c.name}: on-chain verifyProof returned false for a valid proof`);
      const data = new Interface(contract.abi as never).encodeFunctionData("verifyProof", [pA, pB, pC, pub]);
      const tx = await signer.sendTransaction({ to: await verifier.getAddress(), data, gasLimit: 1_000_000n });
      const receipt = await tx.wait();
      if (!receipt || receipt.status !== 1) throw new Error(`${c.name}: verifyProof tx failed`);
      gas[c.name] = {
        verifyProofDirectTxGasUsed: Number(receipt.gasUsed),
        calldataBytes: (data.length - 2) / 2,
        staticCallValid: ok,
      };
    }

    // one issuance-root anchor (first write for an issuer, then a later epoch)
    const didContract = compileRegistries()["DIDRegistry"];
    if (!didContract) throw new Error("DIDRegistry missing from solc output");
    const didRegistry = await deployContract(didContract, signer);
    const anchorRegistry = await deployContract(compileIssuanceRootRegistry(), signer, [
      await didRegistry.getAddress(),
      0,
    ]);
    const didKey = didRegistryKey("did:pq:compare-issuer");
    const register = didRegistry["registerDID"];
    if (!register) throw new Error("registerDID missing on contract");
    await (await register(didKey, "did:pq:compare-issuer", "0x" + "11".repeat(1312), "[]")).wait();
    const anchorGas: number[] = [];
    const publish = anchorRegistry.getFunction("publishIssuanceRoot");
    for (const epoch of [1, 2]) {
      const field = (tag: string) => BigInt("0x" + sha3_256(Buffer.from(`${tag}-${epoch}`)).toString("hex")) % BN254_P;
      const args = [didKey, epoch, field("root"), field("revroot"), sha3_256(Buffer.from(`sig-${epoch}`))] as const;
      const estimate = await publish.estimateGas(...args);
      const tx = await publish(...args, { gasLimit: estimate + estimate / 5n + 5_000n });
      anchorGas.push(Number((await tx.wait()).gasUsed));
      await provider.send("evm_increaseTime", [1]); // the next anchor lands in a later block second
      await provider.send("evm_mine", []);
    }
    gas["issuanceRootAnchor"] = {
      firstEpochTxGasUsed: anchorGas[0] as number,
      laterEpochTxGasUsed: anchorGas[1] as number,
    };
    provider.destroy();
  } finally {
    anvil.stop();
  }
  fs.rmSync(tmp, { recursive: true, force: true });

  const med = (n: string) => (timing[n] as { prove: { medianMs: number } }).prove.medianMs;
  const out = {
    schema: "pqid/v3-compare/v1",
    label: "[M] v2 vs v3 cost, same host, same session, interleaved rounds (snarkJS only)",
    rounds: ROUNDS,
    warmupRoundsDiscarded: WARMUP,
    constraints,
    addedByV3: {
      constraintsVsV2SameOpt: constraints.v3_O2.nConstraints - constraints.v2_O2.nConstraints,
      publicSignals: constraints.v3_O2.nPublic - constraints.v2_O2.nPublic,
    },
    timing,
    proveMedianRatio: {
      v3_over_v2_O2: Math.round((med("v3_O2") / med("v2_O2")) * 100) / 100,
      v3_over_v2_published: Math.round((med("v3_O2") / med("v2_published_O1")) * 100) / 100,
    },
    gas,
    proofJsonBytes: Buffer.byteLength(JSON.stringify(proofs["v3_O2"]?.proof), "utf8"),
    notes: [
      "v2_O2 uses a throwaway, un-contributed phase-2 key: timing only, never used to verify anything.",
      "Groth16 proof size is constant (3 group elements) for both versions; v3 adds one public signal (issRoot).",
      "Timing is indicative: snarkJS in Node on one laptop; see controls.powerSource and controls.quiesce.",
    ],
    controls: collectControls({
      quiesce,
      fsBasis: "Windows NTFS (repo checkout), Node snarkJS",
      invocations: 1,
    }),
  };
  fs.mkdirSync(RESULTS_DIR_V3, { recursive: true });
  const outFile = path.join(RESULTS_DIR_V3, "compare_v2_v3.json");
  fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
  console.log(
    `[compare] constraints v2(O1)=${constraints.v2_published_O1.nConstraints} v2(O2)=${constraints.v2_O2.nConstraints} ` +
      `v3(O2)=${constraints.v3_O2.nConstraints}\n[compare] prove median ms: ` +
      configs.map((c) => `${c.name}=${med(c.name)}`).join(" ") +
      `\n[compare] gas: ` +
      Object.entries(gas).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(" ") +
      `\n[compare] -> ${path.relative(REPO_ROOT, outFile)}`
  );
  process.exit(0);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
