import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { REPO_ROOT } from "@pqid/common/paths";

/**
 * Circuit mutants for the mutation table (C3). One mutant per constraint group of
 * circuits/credential_auth_v4.circom, built from the source markers:
 *   - group has a `// @@mutant` section: use its (uncommented) replacement lines;
 *   - else, group has `// @check` lines: drop only those lines (the defence's checks);
 *   - else: drop the whole group (G11 ranges, G17 nonce).
 * Each mutant is compiled at --O2 into circuits/build/v4/mutants/<group>/ (gitignored)
 * and gets a THROWAWAY key (never pinned, never used outside the mutation run).
 */
export const V4_SRC = path.join(REPO_ROOT, "circuits", "credential_auth_v4.circom");
export const MUTANTS_DIR = path.join(REPO_ROOT, "circuits", "build", "v4", "mutants");

export interface GroupBlock {
  name: string;
  start: number; // line index of "// @@<name>"
  end: number; // line index of "// @@end"
  mutantAt: number | null; // line index of "// @@mutant" or null
}

export function listGroups(src: string): GroupBlock[] {
  const lines = src.split(/\r?\n/);
  const out: GroupBlock[] = [];
  let cur: GroupBlock | null = null;
  lines.forEach((l, i) => {
    const t = l.trim();
    const open = /^\/\/ @@(G\d\d_[a-z_]+)\s*$/.exec(t);
    if (open) {
      if (cur) throw new Error(`nested group at line ${i + 1}`);
      cur = { name: open[1] as string, start: i, end: -1, mutantAt: null };
    } else if (t === "// @@mutant" && cur) {
      (cur as GroupBlock).mutantAt = i;
    } else if (t === "// @@end" && cur) {
      (cur as GroupBlock).end = i;
      out.push(cur);
      cur = null;
    }
  });
  if (cur) throw new Error("unterminated group");
  return out;
}

export type MutationKind = "replacement" | "checks-removed" | "group-removed";

export function mutantSource(src: string, group: string): { source: string; kind: MutationKind; removed: string[] } {
  const lines = src.split(/\r?\n/);
  const g = listGroups(src).find((x) => x.name === group);
  if (!g) throw new Error(`unknown group ${group}`);
  const body = lines.slice(g.start + 1, g.mutantAt ?? g.end);
  const removed: string[] = [];
  let replacement: string[] = [];
  let kind: MutationKind;
  if (g.mutantAt !== null) {
    kind = "replacement";
    replacement = lines.slice(g.mutantAt + 1, g.end).map((l) => l.replace(/^(\s*)\/\/ ?/, "$1"));
    removed.push(...body.filter((l) => l.trim() && !l.trim().startsWith("//")).map((l) => l.trim()));
  } else if (body.some((l) => /\/\/ @check\s*$/.test(l))) {
    kind = "checks-removed";
    replacement = body.map((l) => {
      if (/\/\/ @check\s*$/.test(l)) {
        removed.push(l.trim());
        return `    // [mutant ${group}] removed: ${l.trim()}`;
      }
      return l;
    });
  } else {
    kind = "group-removed";
    removed.push(...body.filter((l) => l.trim() && !l.trim().startsWith("//")).map((l) => l.trim()));
    replacement = [`    // [mutant ${group}] group removed`];
  }
  const out = [...lines.slice(0, g.start), `    // @@${group} (MUTANT: ${kind})`, ...replacement, ...lines.slice(g.end + 1)];
  return { source: out.join("\n"), kind, removed };
}

function circomBin(): string {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  return process.platform === "win32" && fs.existsSync(win) ? win : "circom";
}

export interface BuiltMutant {
  group: string;
  kind: MutationKind;
  removed: string[];
  dir: string;
  r1cs: string;
  wasm: string;
  sym: string;
  nConstraints?: number;
}

/** Write and compile one mutant (idempotent). */
export function buildMutant(group: string): BuiltMutant {
  const src = fs.readFileSync(V4_SRC, "utf8");
  const m = mutantSource(src, group);
  const dir = path.join(MUTANTS_DIR, group);
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, "credential_auth_v4.circom");
  // Relative include; circuits/ is on the library path of the compile below (no absolute path
  // in the written source).
  const text = m.source;
  const r1cs = path.join(dir, "credential_auth_v4.r1cs");
  const wasm = path.join(dir, "credential_auth_v4_js", "credential_auth_v4.wasm");
  const sym = path.join(dir, "credential_auth_v4.sym");
  const stale = !fs.existsSync(file) || fs.readFileSync(file, "utf8") !== text || !fs.existsSync(wasm);
  if (stale) {
    fs.writeFileSync(file, text);
    execFileSync(circomBin(), [file, "--O2", "--r1cs", "--wasm", "--sym", "-l", path.join(REPO_ROOT, "node_modules"), "-l", path.join(REPO_ROOT, "circuits"), "-o", dir], {
      cwd: REPO_ROOT,
      stdio: "pipe",
    });
  }
  return { group, kind: m.kind, removed: m.removed, dir, r1cs, wasm, sym };
}

export function allGroups(): string[] {
  return listGroups(fs.readFileSync(V4_SRC, "utf8")).map((g) => g.name);
}
