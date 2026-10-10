import fs from "node:fs";
import path from "node:path";
import { flag, rel, sanitize } from "../bench/lib.ts";
import { holdWork } from "./runner.ts";
import { cmpRoot } from "./spec.ts";

/**
 * A smoke test always starts fresh (docs/v4/CMP.md, "Smoke test"): this moves the previous smoke
 * output aside, from results/v4/cmp/_smoke/{prove,wallet,inputs,logs,summary_cmp.json,
 * summary_cmp.md} to results/v4/cmp/_smoke/old_<UTC stamp>/. Smoke output only (gitignored, never
 * a result); nothing outside _smoke/ is touched and nothing is deleted.
 *
 *   node --import tsx harness/v4/cmp/smoke_reset.ts [--smoke-no-marker]
 *
 * Refuses while results/v4/bench/RUNNING or results/v4/BUSY exists (a borrowed BUSY hold of a
 * smoke window is accepted) or while another smoke run holds the smoke lock; holds results/v4/BUSY
 * (or with --smoke-no-marker only the smoke lock) while moving.
 */

export const SMOKE_OUTPUT: readonly string[] = ["prove", "wallet", "inputs", "logs", "summary_cmp.json", "summary_cmp.md"];

export function stampOf(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

/** Move the existing smoke output under smokeRoot into smokeRoot/old_<stamp>/; returns what moved (names) and where. */
export function moveSmokeOutput(smokeRoot: string, now: Date = new Date()): { moved: string[]; to: string | null } {
  const present = SMOKE_OUTPUT.filter((n) => fs.existsSync(path.join(smokeRoot, n)));
  if (present.length === 0) return { moved: [], to: null };
  let to = path.join(smokeRoot, `old_${stampOf(now)}`);
  for (let i = 2; fs.existsSync(to); i++) to = path.join(smokeRoot, `old_${stampOf(now)}_${i}`);
  fs.mkdirSync(to, { recursive: true });
  for (const n of present) fs.renameSync(path.join(smokeRoot, n), path.join(to, n));
  return { moved: present, to };
}

function main(): void {
  const argv = process.argv.slice(2);
  const smokeRoot = cmpRoot(true);
  const hold = holdWork({ kind: "BUSY", smoke: true, smokeNoMarker: flag(argv, "smoke-no-marker"), smokeRoot, campaign: "cmp_smoke_reset", runner: "harness/v4/cmp/smoke_reset.ts", argv, note: "moves old smoke output aside" });
  try {
    const r = moveSmokeOutput(smokeRoot);
    console.log(r.to ? `[cmp-smoke-reset] moved ${r.moved.join(", ")} -> ${rel(r.to)}` : `[cmp-smoke-reset] no earlier smoke output under ${rel(smokeRoot)}`);
  } finally {
    hold.release();
  }
}

const self = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (self.endsWith(path.join("harness", "v4", "cmp", "smoke_reset.ts"))) {
  try {
    main();
    process.exit(0);
  } catch (e) {
    console.error(`[cmp-smoke-reset] ${sanitize(e instanceof Error ? e.message : String(e))}`);
    process.exit(1);
  }
}
