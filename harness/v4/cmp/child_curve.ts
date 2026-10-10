import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

/**
 * Optional `curve` condition of the cmp cold series (docs/v4/CMP.md): ONE fresh process that
 * only builds the bn128 curve the way snarkJS does at the start of groth16.prove in a fresh
 * process (ffjavascript 0.3.0, the copy nested under snarkjs, buildBn128(): wasm plus one worker
 * thread per logical core). Prints exactly one JSON line on stdout and exits.
 *
 * It does not split the prove phase: the five circuit conditions keep child_prove.ts unchanged
 * (the protocol's prove definition, curve build inside prove). Interleaved with them, this
 * condition gives the curve build's cold cost in the same campaign, so it can be read next to
 * the prove medians (descriptive, never subtracted run by run).
 *
 * Timed: curveMs = buildBn128(). Aux: snarkjs import (to load the same module graph as
 * child_prove.ts), worker count, process start to main(). Checks: the curve was registered as
 * the one snarkjs reuses, and worker threads were started (no proof is made, so the record has
 * no verified or publicSignalsMatch). Imports only Node built-ins and snarkjs's own
 * ffjavascript. Prints no paths.
 */

function msSince(t0: bigint): number {
  return Math.round((Number(process.hrtime.bigint() - t0) / 1e6) * 1000) / 1000;
}

function out(line: unknown, code: number): void {
  process.stdout.write(JSON.stringify(line) + "\n", () => process.exit(code));
}

interface Bn128 {
  terminate(): Promise<void>;
  tm?: { concurrency?: number };
}

/** The ffjavascript build snarkjs itself imports (same lookup as harness/v4/bench/child_prove.ts). */
async function snarkjsFfjavascript(): Promise<{ buildBn128: () => Promise<Bn128>; version: string }> {
  const candidates = [
    path.join(process.cwd(), "node_modules", "snarkjs", "node_modules", "ffjavascript", "package.json"),
    path.join(process.cwd(), "node_modules", "ffjavascript", "package.json"),
  ];
  const pkgFile = candidates.find((f) => fs.existsSync(f));
  if (!pkgFile) throw new Error("ffjavascript not found next to snarkjs");
  const pkg = JSON.parse(fs.readFileSync(pkgFile, "utf8")) as { version: string; exports?: { ".": { node?: { import?: string } } }; module?: string };
  const entry = pkg.exports?.["."]?.node?.import ?? pkg.module ?? "./main.js";
  const mod = (await import(pathToFileURL(path.join(path.dirname(pkgFile), entry)).href)) as { buildBn128: () => Promise<Bn128> };
  return { buildBn128: mod.buildBn128, version: pkg.version };
}

async function main(): Promise<void> {
  const mainAtMs = Math.round(performance.now() * 1000) / 1000;
  const tImport = process.hrtime.bigint();
  await import("snarkjs");
  const ff = await snarkjsFfjavascript();
  const importMs = msSince(tImport);
  const g = globalThis as { curve_bn128?: unknown };
  if (g.curve_bn128) throw new Error("bn128 curve already built before the curve phase");

  const tC = process.hrtime.bigint();
  const curve = await ff.buildBn128();
  const curveMs = msSince(tC);
  if (g.curve_bn128 !== curve) throw new Error("buildBn128() did not register the curve snarkjs would reuse");
  const workerCount = curve.tm?.concurrency ?? null;
  await curve.terminate();
  out(
    {
      schema: "pqid/v4-cmp-curve-child/v1",
      condition: "curve",
      ok: true,
      // no proof is made here, so no verified/publicSignalsMatch: only what this child checks
      checks: { curveRegistered: true, workerThreads: (workerCount ?? 0) > 0 },
      timings: { curveMs },
      aux: { mainAtMs, importMs, workerCount, ffjavascript: ff.version },
      runtime: { node: process.version, openssl: process.versions.openssl ?? "unknown" },
    },
    0
  );
}

main().catch((e: unknown) => {
  const msg = e instanceof Error ? e.message : String(e);
  out({ schema: "pqid/v4-cmp-curve-child/v1", ok: false, error: msg.slice(0, 2000) }, 1);
});
