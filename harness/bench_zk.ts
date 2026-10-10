import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync, execFileSync } from "node:child_process";
import {
  REPO_ROOT,
  RESULTS_DIR,
  ZKEY_FILE,
  VKEY_FILE,
  CIRCUIT_BUILD_DIR,
  toWslPath,
} from "@pqid/common/paths";
import { sha256File } from "@pqid/common/hash";
import { summarize, type SampleSummary } from "@pqid/common/stats";
import { readPins } from "../setup/pins.ts";
import { buildFixtureProofInput } from "./fixture.ts";
import { assertQuiesced, collectControls, interRun, headline, type InterRunStats } from "./bench_env.ts";

/**
 * Table V benchmark, V6 revision (§B discipline + §C cold/amortized split).
 *
 * All numbers measured at runtime; nothing tuned. Per metric:
 *   - ≥3 independent invocations (separate worker processes / WSL loops)
 *   - within-run stats + inter-run stats (median spread, CV; flag > 10%)
 *   - §B6 median headline when σ/mean > 0.2
 *
 * rapidsnark bases (byte-identical zkey + witness, SHA-256-verified, staged
 * on WSL-native ext4 — never /mnt/c):
 *   cold      — per-proof subprocess wall (process start + zkey/wtns I/O):
 *               the paper's A.2 method
 *   amortized — zkey loaded+parsed once (groth16_prover_create), prove-only
 *               per call (harness/native/amortized_prover.c)
 * snarkJS bases: cold = file-based prove per call (paper basis);
 * amortized = in-memory buffers (no preparsed-zkey API in snarkJS 0.7.4).
 */
const RUNS = Number(process.env["PQID_ZK_RUNS"] ?? 3);
const N_WITNESS = Number(process.env["PQID_ZK_WITNESS_N"] ?? 1000);
const N_PROVE_SJS = Number(process.env["PQID_ZK_SNARKJS_N"] ?? 1000);
const N_SJS_AMORT = Number(process.env["PQID_ZK_SNARKJS_AMORT_N"] ?? 100);
const N_VERIFY = Number(process.env["PQID_ZK_VERIFY_N"] ?? 1000);
const N_RAPIDSNARK = Number(process.env["PQID_ZK_RAPIDSNARK_N"] ?? 100);
const WARMUP = Number(process.env["PQID_ZK_WARMUP"] ?? 5);

const BENCH_WSL = "/root/pqid-native/bench";
const PROVER_WSL = "/root/pqid-native/rapidsnark/bin/prover";

interface PhaseResult {
  perRun: SampleSummary[];
  interRun: InterRunStats;
  headline: { valueMs: number; basis: "mean" | "median"; rule: string };
}

function wsl(cmd: string): string {
  const out = execFileSync("wsl", ["-u", "root", "-e", "bash", "-c", cmd], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return out.split(String.fromCharCode(0)).join("");
}

function aggregate(perRun: SampleSummary[]): PhaseResult {
  const ir = interRun(perRun);
  // headline from the pooled view: use the median run (by median) as representative
  const rep = [...perRun].sort((a, b) => a.medianMs - b.medianMs)[Math.floor(perRun.length / 2)] as SampleSummary;
  return { perRun, interRun: ir, headline: headline(rep) };
}

function runWorker(phase: string, n: number, wtnsFile: string, run: number): SampleSummary {
  const outFile = path.join(os.tmpdir(), `pqid-zkrun-${phase}-${run}-${randomBytes(3).toString("hex")}.json`);
  console.log(`[bench:zk] ${phase} run ${run}/${RUNS} (N=${n})…`);
  const res = spawnSync(
    process.platform === "win32" ? "npx.cmd" : "npx",
    ["tsx", "harness/bench_zk_worker.ts"],
    {
      cwd: REPO_ROOT,
      encoding: "utf8",
      shell: process.platform === "win32",
      env: {
        ...process.env,
        PQID_PHASE: phase,
        PQID_N: String(n),
        PQID_WARMUP: String(WARMUP),
        PQID_WTNS: wtnsFile,
        PQID_RUN_OUT: outFile,
      },
      maxBuffer: 64 * 1024 * 1024,
    }
  );
  if (res.status !== 0) throw new Error(`worker ${phase}#${run} failed: ${res.stderr}`);
  const data = JSON.parse(fs.readFileSync(outFile, "utf8")) as { stats: SampleSummary };
  fs.rmSync(outFile, { force: true });
  return data.stats;
}

function runRapidsnarkCold(run: number): SampleSummary {
  console.log(`[bench:zk] rapidsnark-cold run ${run}/${RUNS} (N=${N_RAPIDSNARK}, native ext4)…`);
  const benchScript = path.join(REPO_ROOT, "harness", "rapidsnark_bench.sh");
  wsl(
    `tr -d '\\r' < ${toWslPath(benchScript)} > /tmp/pqid_rs_bench.sh && ` +
      `bash /tmp/pqid_rs_bench.sh ${PROVER_WSL} ${BENCH_WSL}/bench.zkey ${BENCH_WSL}/bench.wtns ` +
      `${BENCH_WSL}/proof.json ${BENCH_WSL}/public.json ${N_RAPIDSNARK} ${WARMUP} ${BENCH_WSL}/samples.txt`
  );
  const samples = wsl(`cat ${BENCH_WSL}/samples.txt`)
    .trim()
    .split(/\r?\n/)
    .map((l) => Number(l) / 1000);
  if (samples.length !== N_RAPIDSNARK) throw new Error(`expected ${N_RAPIDSNARK} samples`);
  return summarize(samples);
}

function runRapidsnarkAmortized(run: number): SampleSummary {
  console.log(`[bench:zk] rapidsnark-amortized run ${run}/${RUNS} (N=${N_RAPIDSNARK}, zkey loaded once)…`);
  wsl(
    `cd ${BENCH_WSL} && ./amortized_prover bench.zkey bench.wtns ${N_RAPIDSNARK} ${WARMUP} ` +
      `samples_amort.txt proof_amort.json public_amort.json 2>/dev/null`
  );
  const samples = wsl(`cat ${BENCH_WSL}/samples_amort.txt`)
    .trim()
    .split(/\r?\n/)
    .map((l) => Number(l) / 1000);
  if (samples.length !== N_RAPIDSNARK) throw new Error(`expected ${N_RAPIDSNARK} samples`);
  return summarize(samples);
}

/** Live affinity probe — evidence for the documented §B2 policy deviation. */
function affinityProbe(): { freeMs: number[]; oneVcpuMs: number[]; fourVcpuMs: number[] } {
  console.log("[bench:zk] affinity probe (free vs 1 vCPU vs 4 vCPUs, N=3 each)…");
  const probe = (prefix: string, out: string): number[] => {
    wsl(
      `cd ${BENCH_WSL} && ${prefix} ./amortized_prover bench.zkey bench.wtns 3 1 ${out} /tmp/p.json /tmp/pub.json 2>/dev/null`
    );
    return wsl(`cat ${BENCH_WSL}/${out}`)
      .trim()
      .split(/\r?\n/)
      .map((l) => Math.round(Number(l) / 100) / 10);
  };
  return {
    freeMs: probe("", "probe_free.txt"),
    oneVcpuMs: probe("taskset -c 0", "probe_c0.txt"),
    fourVcpuMs: probe("taskset -c 0-3", "probe_c03.txt"),
  };
}

async function main(): Promise<void> {
  const quiesce = assertQuiesced({ allowedNodeCount: 3 }); // coordinator + worker + npx shim
  const snarkjs = await import("snarkjs");

  // pins verified on every run
  const pins = readPins();
  const zkeySha = sha256File(ZKEY_FILE);
  const pin = pins["credential_auth_final.zkey"];
  if (pin && pin.sha256 !== zkeySha) {
    throw new Error(`zkey drift: pinned ${pin.sha256}, actual ${zkeySha}`);
  }

  // ---- stage byte-identical inputs on WSL-native ext4 (§B3)
  console.log("[bench:zk] staging zkey + witness on WSL-native ext4…");
  const input = await buildFixtureProofInput();
  const wtnsFile = path.join(os.tmpdir(), `pqid-bench-${randomBytes(4).toString("hex")}.wtns`);
  await snarkjs.wtns.calculate(input, path.join(CIRCUIT_BUILD_DIR, "credential_auth_js", "credential_auth.wasm"), wtnsFile);
  const witnessSha = sha256File(wtnsFile);
  wsl(
    `mkdir -p ${BENCH_WSL} && cp ${toWslPath(ZKEY_FILE)} ${BENCH_WSL}/bench.zkey && ` +
      `cp ${toWslPath(wtnsFile)} ${BENCH_WSL}/bench.wtns && ` +
      `Z=$(sha256sum ${BENCH_WSL}/bench.zkey | cut -d' ' -f1) && ` +
      `W=$(sha256sum ${BENCH_WSL}/bench.wtns | cut -d' ' -f1) && ` +
      `[ "$Z" = "${zkeySha}" ] && [ "$W" = "${witnessSha}" ] && echo STAGED-VERIFIED`
  );

  const probe = affinityProbe();
  console.log(
    `[bench:zk] probe: free ${probe.freeMs} | 1 vCPU ${probe.oneVcpuMs} | 4 vCPU ${probe.fourVcpuMs} (ms)`
  );

  // ---- phases, each ≥RUNS independent invocations, strictly serial
  const witness = aggregate(
    Array.from({ length: RUNS }, (_, i) => runWorker("witness", N_WITNESS, "", i + 1))
  );
  const sjsCold = aggregate(
    Array.from({ length: RUNS }, (_, i) => runWorker("snarkjs-cold", N_PROVE_SJS, wtnsFile, i + 1))
  );
  const sjsAmort = aggregate(
    Array.from({ length: RUNS }, (_, i) => runWorker("snarkjs-amortized", N_SJS_AMORT, wtnsFile, i + 1))
  );
  const verify = aggregate(
    Array.from({ length: RUNS }, (_, i) => runWorker("verify", N_VERIFY, wtnsFile, i + 1))
  );
  const rsCold = aggregate(Array.from({ length: RUNS }, (_, i) => runRapidsnarkCold(i + 1)));
  const rsAmort = aggregate(Array.from({ length: RUNS }, (_, i) => runRapidsnarkAmortized(i + 1)));

  // ---- correctness + proof sizes from final artifacts
  const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, "utf8")) as unknown;
  const rsProof = JSON.parse(wsl(`cat ${BENCH_WSL}/proof.json`)) as never;
  const rsSignals = JSON.parse(wsl(`cat ${BENCH_WSL}/public.json`)) as string[];
  const rsVerifies = await snarkjs.groth16.verify(vkey, rsSignals, rsProof);
  if (!rsVerifies) throw new Error("rapidsnark cold proof did not verify under snarkJS");
  const rsAmortProof = JSON.parse(wsl(`cat ${BENCH_WSL}/proof_amort.json`)) as never;
  const rsAmortSignals = JSON.parse(wsl(`cat ${BENCH_WSL}/public_amort.json`)) as string[];
  const rsAmortVerifies = await snarkjs.groth16.verify(vkey, rsAmortSignals, rsAmortProof);
  if (!rsAmortVerifies) throw new Error("rapidsnark amortized proof did not verify under snarkJS");
  const { proof: sjProof, publicSignals: sjSignals } = await snarkjs.groth16.prove(ZKEY_FILE, wtnsFile);
  const sjVerifies = await snarkjs.groth16.verify(vkey, sjSignals, sjProof);
  const sjProofBytes = Buffer.byteLength(JSON.stringify(sjProof), "utf8");
  const rsProofBytes = Number(wsl(`stat -c %s ${BENCH_WSL}/proof.json`).trim());
  fs.rmSync(wtnsFile, { force: true });

  const circuitInfo = JSON.parse(
    fs.readFileSync(path.join(CIRCUIT_BUILD_DIR, "circuit_info.json"), "utf8")
  ) as Record<string, unknown>;

  const ratio = (a: number, b: number): number => Math.round((a / b) * 100) / 100;
  const result = {
    schema: "pqid/zk-bench/v2",
    label: "[M] measured under §B controls",
    controls: collectControls({
      quiesce,
      fsBasis:
        "rapidsnark inputs on WSL-native ext4 (~/pqid-native/bench), SHA-256-verified after copy; " +
        "snarkJS on the Windows host (paper basis)",
      invocations: RUNS,
      affinityProbe: probe,
    }),
    config: {
      circuit: {
        nConstraints: circuitInfo["nConstraints"],
        nWires: circuitInfo["nWires"],
        nPubInputs: circuitInfo["nPubInputs"],
        nPrvInputs: circuitInfo["nPrvInputs"],
        version: "v2 (V6: domain-separated stmtCode + 2 predicates)",
        paperClaim: { manuscriptVersion: "V6.6", nConstraints: 21715, nWires: 21745, nPubInputs: 5, nPrvInputs: 43 },
      },
      zkeySha256: zkeySha,
      witnessSha256: witnessSha,
      bytesIdenticalAcrossProvers: true,
      snarkjsVersion: "0.7.4",
      rapidsnark: "v0.0.8 (81eddf1), static GMP 6.3.0, GCC 15.2.0, WSL2 Ubuntu 26.04",
      bases: {
        rapidsnarkCold: "per-proof subprocess wall: process start + zkey/wtns load from ext4 (paper A.2 method)",
        rapidsnarkAmortized: "groth16_prover_create once; groth16_prover_prove per call (in-memory witness)",
        snarkjsCold: "groth16.prove(zkeyFile, wtnsFile) per call in a resident Node process (paper basis)",
        snarkjsAmortized: "groth16.prove(zkeyBuffer, wtnsBuffer) per call — in-memory, parsed per call (no preparsed-zkey API)",
      },
      n: {
        witness: N_WITNESS,
        snarkjsCold: N_PROVE_SJS,
        snarkjsAmortized: N_SJS_AMORT,
        verify: N_VERIFY,
        rapidsnark: N_RAPIDSNARK,
        warmup: WARMUP,
        runs: RUNS,
      },
    },
    witnessGeneration: witness,
    snarkjsProveCold: sjsCold,
    snarkjsProveAmortized: sjsAmort,
    snarkjsVerify: verify,
    rapidsnarkProveCold: rsCold,
    rapidsnarkProveAmortized: rsAmort,
    speedups: {
      coldCold: ratio(sjsCold.headline.valueMs, rsCold.headline.valueMs),
      amortizedAmortized: ratio(sjsAmort.headline.valueMs, rsAmort.headline.valueMs),
      note: "each ratio compares identical bases (§C3); headline-basis values used",
    },
    correctness: {
      rapidsnarkColdVerifies: rsVerifies,
      rapidsnarkAmortizedVerifies: rsAmortVerifies,
      snarkjsVerifies: sjVerifies,
    },
    proofSize: {
      snarkjsJsonBytes: sjProofBytes,
      rapidsnarkJsonBytes: rsProofBytes,
      compressedGroupElementsBytes: 128,
      publicSignals: sjSignals.length,
    },
    paperClaims: {
      manuscriptVersion: "V6.6",
      note: "V6.6 adopted the prototype's controlled measurements; mirrors the measured headline fields above. Proving reported per thermal state (cool single-authentication vs sustained back-to-back).",
      snarkjsProveMs: { coolMs: 981, sustainedMeanMs: 2095, n: 1000 },
      rapidsnarkProveMs: { coolMs: 177, sustainedMeanMs: 258.6, n: 100 },
      witnessMs: 92,
      verifyMs: 40,
      speedup: { coolCoolX: 5.5, thermalRangeX: "5.5-8" },
      proofBytes: 723,
      publicSignals: 5,
    },
  };

  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  const outFile = path.join(RESULTS_DIR, "zk.json");
  fs.writeFileSync(outFile, JSON.stringify(result, null, 2));

  const fmt = (p: PhaseResult): string =>
    `${p.headline.valueMs} ms [${p.headline.basis}] (runs: ${p.interRun.mediansMs.join("/")}, CV ${p.interRun.cvPct}%${p.interRun.stable ? "" : " ⚠UNSTABLE"})`;
  console.log(`\n[bench:zk] witness            ${fmt(witness)} (V6.6 92)`);
  console.log(`[bench:zk] snarkjs cold        ${fmt(sjsCold)} (V6.6 981 cool / 2095 sustained)`);
  console.log(`[bench:zk] snarkjs amortized   ${fmt(sjsAmort)}`);
  console.log(`[bench:zk] rapidsnark cold     ${fmt(rsCold)} (V6.6 177 cool / 258.6 sustained)`);
  console.log(`[bench:zk] rapidsnark amortized ${fmt(rsAmort)}`);
  console.log(`[bench:zk] verify              ${fmt(verify)} (V6.6 40)`);
  console.log(`[bench:zk] speedup cold/cold   ${result.speedups.coldCold}x (V6.6 5.5x cool/cool, range 5.5-8x); amort/amort ${result.speedups.amortizedAmortized}x`);
  console.log(`[bench:zk] proof ${sjProofBytes} B snarkjs / ${rsProofBytes} B rapidsnark; -> ${outFile}`);
  process.exit(0);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
