import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { REPO_ROOT, rel, sanitize } from "../bench/lib.ts";

/**
 * Log hygiene of the cmp window (docs/v4/CMP.md, "Order of work and commands"). The runners
 * sanitize their own messages, but a Node crash, an unhandled rejection or a runtime warning
 * prints stack traces with absolute paths that bypass that. So:
 *
 *   node --import tsx harness/v4/cmp/log_scrub.ts scrub <file>...
 *       rewrite each file with the repository path, home path, temp path, user name and host name
 *       replaced by <repo>, <home>, <tmp>, <user>, <host> (harness/v4/bench/lib.ts sanitize, then
 *       the same needles case-insensitively); the window runs it on each step log after the step
 *       exits (no extra process runs next to a timed run)
 *   node --import tsx harness/v4/cmp/log_scrub.ts check <dir> [--skip NAME]...
 *       exit 1 when a text file under <dir> contains the user name, the host name or the home
 *       path (case-insensitive); prints which kind and which file, never the value. --skip leaves
 *       out folders with that name (a trailing * matches a prefix). Binary artifacts (.zkey,
 *       .wasm, .r1cs, .ptau, .sym, .wtns, .bin) are not read.
 */

export type NeedleKind = "repository path" | "home path" | "temp path" | "user name" | "host name";

export interface Needle {
  text: string;
  kind: NeedleKind;
  tag: string;
}

/** The private strings of this machine (at least 3 characters each), longest first. */
export function needles(): Needle[] {
  const out: Needle[] = [];
  const add = (s: string | undefined, kind: NeedleKind, tag: string) => {
    if (s && s.length >= 3 && !out.some((n) => n.text.toLowerCase() === s.toLowerCase())) out.push({ text: s, kind, tag });
  };
  for (const p of [REPO_ROOT, REPO_ROOT.replace(/\\/g, "/")]) add(p, "repository path", "<repo>");
  for (const p of [os.homedir(), os.homedir().replace(/\\/g, "/")]) add(p, "home path", "<home>");
  for (const p of [os.tmpdir(), os.tmpdir().replace(/\\/g, "/")]) add(p, "temp path", "<tmp>");
  try {
    add(os.userInfo().username, "user name", "<user>");
  } catch {
    /* no user info */
  }
  add(os.hostname(), "host name", "<host>");
  return out.sort((a, b) => b.text.length - a.text.length);
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** sanitize(), then every needle again case-insensitively (Windows paths come in either case). */
export function scrubText(text: string, ns: readonly Needle[] = needles()): string {
  let out = sanitize(text);
  for (const n of ns) out = out.replace(new RegExp(escapeRe(n.text), "gi"), n.tag);
  return out;
}

/** The kinds of private strings found in `text` (case-insensitive). Only user, host and home are checked. */
export function privateKinds(text: string, ns: readonly Needle[] = needles()): NeedleKind[] {
  const low = text.toLowerCase();
  const kinds = new Set<NeedleKind>();
  for (const n of ns) {
    if (n.kind !== "user name" && n.kind !== "host name" && n.kind !== "home path") continue;
    if (low.includes(n.text.toLowerCase())) kinds.add(n.kind);
  }
  return [...kinds].sort();
}

const BINARY = new Set([".zkey", ".wasm", ".r1cs", ".ptau", ".sym", ".wtns", ".bin"]);

function skipped(name: string, skip: readonly string[]): boolean {
  return skip.some((s) => (s.endsWith("*") ? name.startsWith(s.slice(0, -1)) : name === s));
}

/** Every text file under dir with the private kinds it holds. */
export function findPrivate(dir: string, skip: readonly string[] = [], ns: readonly Needle[] = needles()): Array<{ file: string; kinds: NeedleKind[] }> {
  const hits: Array<{ file: string; kinds: NeedleKind[] }> = [];
  const walk = (d: string) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!skipped(e.name, skip)) walk(p);
        continue;
      }
      if (!e.isFile() || BINARY.has(path.extname(e.name).toLowerCase())) continue;
      const kinds = privateKinds(fs.readFileSync(p, "latin1"), ns);
      if (kinds.length > 0) hits.push({ file: rel(p), kinds });
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  return hits;
}

function cli(argv: string[]): number {
  const [sub, ...rest] = argv;
  if (sub === "scrub") {
    let changed = 0;
    for (const f of rest) {
      if (!fs.existsSync(f)) continue;
      const text = fs.readFileSync(f, "utf8");
      const out = scrubText(text);
      if (out !== text) {
        fs.writeFileSync(f, out);
        changed++;
      }
    }
    console.log(`[log-scrub] ${rest.length} file(s) checked, ${changed} rewritten`);
    return 0;
  }
  if (sub === "check") {
    const dir = rest[0];
    if (!dir) {
      console.error("usage: log_scrub.ts check <dir> [--skip NAME]...");
      return 2;
    }
    const skip: string[] = [];
    for (let i = 1; i < rest.length; i++) if (rest[i] === "--skip" && rest[i + 1]) skip.push(rest[++i] as string);
    const hits = findPrivate(path.resolve(dir), skip);
    for (const h of hits) console.log(`[log-scrub] ${h.file}: ${h.kinds.join(", ")}`);
    console.log(`[log-scrub] check ${rel(path.resolve(dir))}${skip.length ? ` (skipping ${skip.join(", ")})` : ""}: ${hits.length === 0 ? "no user name, host name or home path found" : `${hits.length} file(s) with private strings`}`);
    return hits.length === 0 ? 0 : 1;
  }
  console.error("usage: log_scrub.ts scrub <file>... | check <dir> [--skip NAME]...");
  return 2;
}

const self = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (self.endsWith(path.join("harness", "v4", "cmp", "log_scrub.ts"))) {
  try {
    process.exit(cli(process.argv.slice(2)));
  } catch (e) {
    console.error(`[log-scrub] ${sanitize(e instanceof Error ? e.message : String(e))}`);
    process.exit(1);
  }
}
