import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { REPO_ROOT, sanitize } from "../bench/lib.ts";

/**
 * Output helpers of the chain-read series (docs/v4/CHAINREAD.md). Markers (D-034) come from
 * harness/v4/lib/markers.ts.
 *
 * Results root: results/v4/chainread/ (DECISIONS D-034). A timed run writes
 * results/v4/chainread/<campaign>/<target>/ and never overwrites an existing env.json; a smoke
 * run writes results/v4/chainread/_smoke/<campaign>/<target>/ (gitignored, never cited) and
 * replaces its own earlier smoke output.
 *
 * Large series files are JSON Lines compressed with gzip, written as one gzip member per pass
 * (a file of members reads as one stream with zcat, Python's gzip module or Node's zlib), so a
 * stopped run keeps every finished pass.
 */

export const CHAINREAD_ROOT = path.join(REPO_ROOT, "results", "v4", "chainread");
export const CHAINREAD_SMOKE_ROOT = path.join(CHAINREAD_ROOT, "_smoke");
export const CAMPAIGN_RE = /^[a-z][a-z0-9_]{0,39}$/;

export function targetDir(campaign: string, target: string, smoke: boolean): string {
  if (!CAMPAIGN_RE.test(campaign)) throw new Error(`campaign name must match ${CAMPAIGN_RE} (got ${campaign})`);
  if (target !== "anvil" && target !== "besu") throw new Error(`target must be anvil or besu (got ${target})`);
  return path.join(smoke ? CHAINREAD_SMOKE_ROOT : CHAINREAD_ROOT, campaign, target);
}

export function relRepo(p: string): string {
  return path.relative(REPO_ROOT, p).split(path.sep).join("/");
}

/** JSON with bigint as decimal strings and numbers rounded to 1 ns (ms with 6 decimals). */
export function jsonLine(x: unknown): string {
  return JSON.stringify(x, (_k, v: unknown) => {
    if (typeof v === "bigint") return v.toString();
    if (typeof v === "number" && !Number.isInteger(v) && Number.isFinite(v)) return Math.round(v * 1e6) / 1e6;
    return v;
  });
}

export function writeJsonFile(file: string, x: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const text = JSON.stringify(
    x,
    (_k, v: unknown) => (typeof v === "bigint" ? v.toString() : typeof v === "number" && !Number.isInteger(v) && Number.isFinite(v) ? Math.round(v * 1e6) / 1e6 : v),
    2
  );
  fs.writeFileSync(file, text + "\n");
}

/** Append records as one gzip member. */
export function appendJsonlGz(file: string, recs: readonly unknown[]): void {
  if (recs.length === 0) return;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, zlib.gzipSync(recs.map(jsonLine).join("\n") + "\n", { level: 9 }));
}

export function readJsonlGz<T>(file: string): T[] {
  if (!fs.existsSync(file)) return [];
  return zlib
    .gunzipSync(fs.readFileSync(file))
    .toString("utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as T);
}

export function appendJsonl(file: string, rec: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, jsonLine(rec) + "\n");
}

/** Short, sanitized error text for records (no repo path, home, temp, user or host). */
export function errText(e: unknown): string {
  const x = e as { code?: unknown; shortMessage?: unknown; message?: unknown } | null;
  const code = typeof x?.code === "string" ? `${x.code}: ` : "";
  return sanitize(`${code}${String(x?.shortMessage ?? x?.message ?? e)}`).slice(0, 400);
}
