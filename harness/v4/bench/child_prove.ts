import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

/**
 * ONE cold run in a fresh process (docs/v4/BENCH_PROTOCOL.md, "What is timed").
 * Spawned by cold_campaign.ts as `node --import <tsx> child_prove.ts --version ... `;
 * prints exactly one JSON line on stdout and exits.
 *
 * Timed phases (process.hrtime.bigint, milliseconds):
 *   witness : snarkjs.wtns.calculate(input, <wasm path>, in-memory wtns); includes reading
 *             and compiling the circuit wasm in this fresh process.
 *   prove   : snarkjs  -> groth16.prove(<zkey path>, in-memory wtns); includes reading and
 *                         parsing the zkey and building the bn128 curve (wasm + worker threads).
 *             rapidsnark -> spawnSync(<prover>, [zkey, wtns, proof.json, public.json]) wall
 *                         time: prover process start, zkey load, proving, proof file write.
 *   verify  : snarkjs groth16.verify with the bn128 curve already built in this process
 *             (by prove for snarkjs; by an untimed buildBn128() for rapidsnark), so both
 *             provers' verify timings measure the same work.
 * Recorded but not timed as a phase: snarkjs import, input read/hash, the rapidsnark
 * witness-file write and curve build, and process start to main().
 *
 * This file imports only Node built-ins and snarkjs (no workspace code), so every version
 * and prover starts the same small process. It prints no paths.
 */

interface Args {
  version: string;
  prover: "snarkjs" | "rapidsnark";
  input: string;
  inputSha: string;
  publicSha: string;
  wasm: string;
  zkey: string;
  vkey: string;
}

function arg(name: string): string {
  const i = process.argv.indexOf(`--${name}`);
  const v = i >= 0 ? process.argv[i + 1] : undefined;
  if (!v) throw new Error(`missing --${name}`);
  return v;
}

function hr(): bigint {
  return process.hrtime.bigint();
}

function msSince(t0: bigint): number {
  return Math.round((Number(process.hrtime.bigint() - t0) / 1e6) * 1000) / 1000;
}

function sha256(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function out(line: unknown, code: number): void {
  process.stdout.write(JSON.stringify(line) + "\n", () => process.exit(code));
}

/** The ffjavascript build snarkjs itself imports (nested copy when present). */
async function snarkjsFfjavascript(): Promise<{ buildBn128: () => Promise<unknown> }> {
  // Found by path, not by require.resolve("ffjavascript/package.json"): ffjavascript's
  // "exports" does not list ./package.json, which Node enforces (seen on the Linux install).
  const candidates = [
    path.join(process.cwd(), "node_modules", "snarkjs", "node_modules", "ffjavascript", "package.json"),
    path.join(process.cwd(), "node_modules", "ffjavascript", "package.json"),
  ];
  const pkgFile = candidates.find((f) => fs.existsSync(f));
  if (!pkgFile) throw new Error("ffjavascript not found next to snarkjs");
  const pkg = JSON.parse(fs.readFileSync(pkgFile, "utf8")) as { exports?: { ".": { node?: { import?: string } } }; module?: string };
  const entry = pkg.exports?.["."]?.node?.import ?? pkg.module ?? "./main.js";
  return (await import(pathToFileURL(path.join(path.dirname(pkgFile), entry)).href)) as { buildBn128: () => Promise<unknown> };
}

async function main(): Promise<void> {
  const mainAtMs = Math.round(performance.now() * 1000) / 1000; // since process time origin
  const a: Args = {
    version: arg("version"),
    prover: arg("prover") as Args["prover"],
    input: arg("input"),
    inputSha: arg("input-sha"),
    publicSha: arg("public-sha"),
    wasm: arg("wasm"),
    zkey: arg("zkey"),
    vkey: arg("vkey"),
  };
  if (a.prover !== "snarkjs" && a.prover !== "rapidsnark") throw new Error(`unknown prover ${a.prover}`);

  const tImport = hr();
  const snarkjs = await import("snarkjs");
  const importMs = msSince(tImport);

  const tIn = hr();
  const input = JSON.parse(fs.readFileSync(a.input, "utf8")) as Record<string, unknown>;
  const inputSha = sha256(JSON.stringify(input));
  const vkey = JSON.parse(fs.readFileSync(a.vkey, "utf8")) as unknown;
  const inputReadMs = msSince(tIn);
  if (inputSha !== a.inputSha) throw new Error(`input sha256 ${inputSha} != pinned ${a.inputSha}`);

  // ---- witness (timed)
  const wtns: { type: "mem"; data?: Uint8Array } = { type: "mem" };
  const tW = hr();
  await snarkjs.wtns.calculate(input as never, a.wasm, wtns);
  const witnessMs = msSince(tW);
  if (!wtns.data) throw new Error("snarkjs produced no in-memory witness");
  const witnessSha256 = sha256(wtns.data);

  // ---- prove (timed)
  let proveMs: number;
  let proof: unknown;
  let publicSignals: string[];
  const aux: Record<string, number | string | boolean | null> = {};
  if (a.prover === "snarkjs") {
    const tP = hr();
    const r = await snarkjs.groth16.prove(a.zkey, wtns as never);
    proveMs = msSince(tP);
    proof = r.proof;
    publicSignals = r.publicSignals as string[];
    aux["curveInitMs"] = null; // inside prove
  } else {
    const bin = process.env["PQID_RAPIDSNARK"]?.trim();
    if (!bin) throw new Error("PQID_RAPIDSNARK unset");
    const tag = `pqid-bench-${process.pid}-${randomBytes(4).toString("hex")}`;
    const wtnsFile = path.join(os.tmpdir(), `${tag}.wtns`);
    const proofFile = path.join(os.tmpdir(), `${tag}.proof.json`);
    const publicFile = path.join(os.tmpdir(), `${tag}.public.json`);
    try {
      const tWr = hr();
      fs.writeFileSync(wtnsFile, wtns.data);
      aux["wtnsWriteMs"] = msSince(tWr);
      const tP = hr();
      const res = spawnSync(bin, [a.zkey, wtnsFile, proofFile, publicFile], { shell: false, windowsHide: true, encoding: "utf8" });
      proveMs = msSince(tP);
      if (res.error) throw res.error;
      if (res.status !== 0) throw new Error(`rapidsnark exited ${res.status}`);
      proof = JSON.parse(fs.readFileSync(proofFile, "utf8")) as unknown;
      publicSignals = JSON.parse(fs.readFileSync(publicFile, "utf8")) as string[];
      aux["proofFileBytes"] = fs.statSync(proofFile).size;
    } finally {
      for (const f of [wtnsFile, proofFile, publicFile]) fs.rmSync(f, { force: true });
    }
    const tC = hr();
    await (await snarkjsFfjavascript()).buildBn128();
    aux["curveInitMs"] = msSince(tC);
  }

  // ---- verify (timed)
  const tV = hr();
  const verified = await snarkjs.groth16.verify(vkey as never, publicSignals as never, proof as never);
  const verifyMs = msSince(tV);

  const publicSignalsSha256 = sha256(JSON.stringify(publicSignals));
  out(
    {
      schema: "pqid/v4-bench-child/v1",
      version: a.version,
      prover: a.prover,
      ok: verified && publicSignalsSha256 === a.publicSha,
      verified,
      publicSignalsMatch: publicSignalsSha256 === a.publicSha,
      timings: { witnessMs, proveMs, verifyMs, wpMs: Math.round((witnessMs + proveMs) * 1000) / 1000 },
      aux: { mainAtMs, importMs, inputReadMs, ...aux, proofJsonBytes: Buffer.byteLength(JSON.stringify(proof), "utf8") },
      hashes: { inputSha256: inputSha, witnessSha256, publicSignalsSha256 },
      runtime: { node: process.version, openssl: process.versions.openssl ?? "unknown" },
    },
    0
  );
}

main().catch((e: unknown) => {
  const msg = e instanceof Error ? e.message : String(e);
  out({ schema: "pqid/v4-bench-child/v1", ok: false, error: msg.slice(0, 2000) }, 1);
});
