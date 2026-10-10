import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { ZKEY_FILE, VKEY_FILE, WASM_FILE } from "@pqid/common/paths";
import { summarize } from "@pqid/common/stats";
import { buildFixtureProofInput } from "./fixture.ts";

/**
 * One independent benchmark invocation (§B5: separate process per run).
 * Phases:
 *   witness           — N× snarkJS WASM witness calculation (file output)
 *   snarkjs-cold      — N× groth16.prove(zkeyFile, wtnsFile)   [paper basis]
 *   snarkjs-amortized — N× groth16.prove(zkeyBuf, wtnsBuf) — in-memory buffers
 *                       (snarkJS 0.7.4 has no preparsed-zkey API; this basis
 *                       removes per-call file I/O, §C2)
 *   verify            — N× groth16.verify on one proof
 * env: PQID_PHASE, PQID_N, PQID_WARMUP, PQID_WTNS, PQID_RUN_OUT
 */
async function main(): Promise<void> {
  const phase = process.env["PQID_PHASE"] ?? "witness";
  const n = Number(process.env["PQID_N"] ?? 100);
  const warmup = Number(process.env["PQID_WARMUP"] ?? 5);
  const wtnsFile = process.env["PQID_WTNS"] ?? "";
  const outFile = process.env["PQID_RUN_OUT"] ?? "";
  if (!outFile) throw new Error("PQID_RUN_OUT required");

  const snarkjs = await import("snarkjs");
  const samples: number[] = [];

  if (phase === "witness") {
    const input = await buildFixtureProofInput();
    const tmp = path.join(os.tmpdir(), `pqid-w-${randomBytes(4).toString("hex")}.wtns`);
    for (let i = 0; i < n + warmup; i++) {
      const t0 = process.hrtime.bigint();
      await snarkjs.wtns.calculate(input, WASM_FILE, tmp);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      if (i >= warmup) samples.push(ms);
    }
    fs.rmSync(tmp, { force: true });
  } else if (phase === "snarkjs-cold") {
    if (!wtnsFile) throw new Error("PQID_WTNS required");
    for (let i = 0; i < n + warmup; i++) {
      const t0 = process.hrtime.bigint();
      await snarkjs.groth16.prove(ZKEY_FILE, wtnsFile);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      if (i >= warmup) samples.push(ms);
    }
  } else if (phase === "snarkjs-amortized") {
    if (!wtnsFile) throw new Error("PQID_WTNS required");
    const zkeyBuf = new Uint8Array(fs.readFileSync(ZKEY_FILE));
    const wtnsBuf = new Uint8Array(fs.readFileSync(wtnsFile));
    for (let i = 0; i < n + warmup; i++) {
      const t0 = process.hrtime.bigint();
      await snarkjs.groth16.prove(zkeyBuf, wtnsBuf);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      if (i >= warmup) samples.push(ms);
    }
  } else if (phase === "verify") {
    if (!wtnsFile) throw new Error("PQID_WTNS required");
    const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY_FILE, wtnsFile);
    const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, "utf8")) as unknown;
    for (let i = 0; i < n + warmup; i++) {
      const t0 = process.hrtime.bigint();
      const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      if (!ok) throw new Error("verification failed in benchmark");
      if (i >= warmup) samples.push(ms);
    }
  } else {
    throw new Error(`unknown phase ${phase}`);
  }

  fs.writeFileSync(
    outFile,
    JSON.stringify({ phase, n, warmup, stats: summarize(samples), samples })
  );
  process.exit(0);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
