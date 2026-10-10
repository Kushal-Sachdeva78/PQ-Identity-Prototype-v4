import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { REPO_ROOT, rel, sanitize } from "../bench/lib.ts";

/**
 * Line and function coverage of packages/v4/src from Node's built-in coverage output
 * (NODE_V8_COVERAGE; DECISIONS D-034: no coverage package). Each process writes
 * coverage-<pid>-*.json with V8 block coverage of the code tsx produced and, because tsx
 * enables source maps, a "source-map-cache" entry per module (line lengths and the source map).
 *
 * Method:
 *  - effective count at a generated position = count of the innermost V8 range containing it;
 *  - each source-map segment maps a generated position to an original TypeScript line; a line
 *    with at least one segment is executable, and covered when any of its segments has a count
 *    above 0 in any process (union over all coverage files);
 *  - a function is covered when its range's call count is above 0 in any process (module
 *    top-level functions are not counted).
 * Lines are those esbuild (through tsx) maps; type-only lines have no segment and are not
 * counted. Numbers from this method are comparable with each other, not with other tools.
 * Totals cover the modules the fuzz processes loaded: a package file no process loaded has no
 * source map here, so its executable lines are unknown; it is listed under unloadedFiles and is
 * not in the denominator (the total is "of modules loaded", not of packages/v4/src).
 */

export interface FileCoverage {
  file: string;
  /** False for a package file no fuzz process loaded (no line counts; not in the totals). */
  loaded: boolean;
  linesExecutable: number;
  linesCovered: number;
  functions: number;
  functionsCovered: number;
  uncoveredLines: number[];
}

export interface CoverageSummary {
  schema: "pqid/v4-coverage/v1";
  method: string;
  scope: string;
  processes: number;
  filesWithoutSourceMap: string[];
  /** Package files no fuzz process loaded: not in the totals. */
  unloadedFiles: string[];
  /** What the totals are a share of. */
  totalsScope: string;
  totals: { linesExecutable: number; linesCovered: number; linePercent: number; functions: number; functionsCovered: number; functionPercent: number };
  files: FileCoverage[];
}

interface Range {
  startOffset: number;
  endOffset: number;
  count: number;
}
interface FnCov {
  functionName: string;
  ranges: Range[];
  isBlockCoverage: boolean;
}
interface ScriptCov {
  url: string;
  functions: FnCov[];
}
interface SourceMapEntry {
  lineLengths: number[];
  data: { mappings: string; sources: string[] };
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_INDEX = new Map([...B64].map((c, i) => [c, i]));

/** Decode a source-map "mappings" string into per-line segments [genCol, srcIdx, srcLine, srcCol]. */
export function decodeMappings(mappings: string): Array<Array<[number, number, number, number]>> {
  const lines: Array<Array<[number, number, number, number]>> = [];
  let srcIdx = 0;
  let srcLine = 0;
  let srcCol = 0;
  for (const lineText of mappings.split(";")) {
    const segs: Array<[number, number, number, number]> = [];
    let genCol = 0;
    if (lineText.length > 0) {
      for (const segText of lineText.split(",")) {
        if (segText.length === 0) continue;
        const vals: number[] = [];
        let shift = 0;
        let value = 0;
        for (const ch of segText) {
          const d = B64_INDEX.get(ch);
          if (d === undefined) throw new Error(`bad base64 character in mappings: ${ch}`);
          value += (d & 31) << shift;
          if (d & 32) shift += 5;
          else {
            vals.push(value & 1 ? -(value >>> 1) : value >>> 1);
            value = 0;
            shift = 0;
          }
        }
        genCol += vals[0] ?? 0;
        if (vals.length >= 4) {
          srcIdx += vals[1] as number;
          srcLine += vals[2] as number;
          srcCol += vals[3] as number;
          segs.push([genCol, srcIdx, srcLine, srcCol]);
        }
      }
    }
    lines.push(segs);
  }
  return lines;
}

/** Innermost-range count at each requested offset (ranges of one script, all functions). */
function countsAt(ranges: Range[], offsets: number[]): number[] {
  return offsets.map((o) => {
    let best: Range | null = null;
    for (const r of ranges) {
      if (r.startOffset <= o && o < r.endOffset && (!best || r.endOffset - r.startOffset < best.endOffset - best.startOffset)) best = r;
    }
    return best ? best.count : 0;
  });
}

function srcFileOfUrl(url: string): string | null {
  if (!url.startsWith("file://")) return null;
  try {
    return path.resolve(fileURLToPath(url));
  } catch {
    return null;
  }
}

/** Summarise every coverage-*.json under `dirs` for the source files under `scopeDir` (default packages/v4/src). */
export function summariseCoverage(dirs: readonly string[], scopeDir = path.join(REPO_ROOT, "packages", "v4", "src")): CoverageSummary {
  const scope = path.resolve(scopeDir).toLowerCase();
  const exec = new Map<string, Set<number>>();
  const covered = new Map<string, Set<number>>();
  const fns = new Map<string, Map<string, boolean>>();
  const noMap = new Set<string>();
  let processes = 0;
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir)) {
      if (!/^coverage-.*\.json$/.test(f)) continue;
      let j: { result?: ScriptCov[]; "source-map-cache"?: Record<string, SourceMapEntry> };
      try {
        j = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8")) as typeof j;
      } catch {
        continue;
      }
      processes++;
      const smc = j["source-map-cache"] ?? {};
      for (const sc of j.result ?? []) {
        const file = srcFileOfUrl(sc.url);
        if (!file || !file.toLowerCase().startsWith(scope + path.sep) || !file.endsWith(".ts")) continue;
        const key = rel(file);
        const ranges = sc.functions.flatMap((fn) => fn.ranges);
        const fnMap = fns.get(key) ?? new Map<string, boolean>();
        fns.set(key, fnMap);
        for (const fn of sc.functions) {
          const r0 = fn.ranges[0];
          if (!r0 || r0.startOffset === 0) continue; // module top level
          const id = `${fn.functionName}@${r0.startOffset}`;
          fnMap.set(id, (fnMap.get(id) ?? false) || r0.count > 0);
        }
        const sm = smc[sc.url];
        if (!sm) {
          noMap.add(key);
          continue;
        }
        const lineStart: number[] = [];
        let acc = 0;
        for (const len of sm.lineLengths) {
          lineStart.push(acc);
          acc += len + 1;
        }
        const segs = decodeMappings(sm.data.mappings);
        const offsets: number[] = [];
        const origLines: number[] = [];
        segs.forEach((line, gl) => {
          for (const [gc, , sl] of line) {
            offsets.push((lineStart[gl] ?? 0) + gc);
            origLines.push(sl + 1);
          }
        });
        const counts = countsAt(ranges, offsets);
        const e = exec.get(key) ?? new Set<number>();
        const c = covered.get(key) ?? new Set<number>();
        exec.set(key, e);
        covered.set(key, c);
        origLines.forEach((ln, i) => {
          e.add(ln);
          if ((counts[i] as number) > 0) c.add(ln);
        });
      }
    }
  }
  const files: FileCoverage[] = [];
  const all = new Set<string>([...exec.keys(), ...fns.keys()]);
  // include package files that no process loaded (0 % covered)
  if (fs.existsSync(scopeDir)) {
    for (const f of fs.readdirSync(scopeDir)) if (f.endsWith(".ts")) all.add(rel(path.join(scopeDir, f)));
  }
  for (const key of [...all].sort()) {
    const e = exec.get(key) ?? new Set<number>();
    const c = covered.get(key) ?? new Set<number>();
    const fm = fns.get(key) ?? new Map<string, boolean>();
    files.push({
      file: key,
      loaded: exec.has(key) || fns.has(key),
      linesExecutable: e.size,
      linesCovered: c.size,
      functions: fm.size,
      functionsCovered: [...fm.values()].filter(Boolean).length,
      uncoveredLines: [...e].filter((l) => !c.has(l)).sort((a, b) => a - b),
    });
  }
  const t = files.reduce(
    (s, f) => ({ le: s.le + f.linesExecutable, lc: s.lc + f.linesCovered, fn: s.fn + f.functions, fc: s.fc + f.functionsCovered }),
    { le: 0, lc: 0, fn: 0, fc: 0 }
  );
  const pct = (a: number, b: number) => (b === 0 ? 0 : Math.round((1000 * a) / b) / 10);
  return {
    schema: "pqid/v4-coverage/v1",
    method:
      "NODE_V8_COVERAGE block coverage of the tsx-transformed modules, mapped to TypeScript lines through the source maps tsx registers (source-map-cache); line covered = any mapped segment with innermost-range count > 0 in any process; functions by call count; union over processes",
    scope: rel(scopeDir),
    processes,
    filesWithoutSourceMap: [...noMap].sort(),
    unloadedFiles: files.filter((f) => !f.loaded).map((f) => f.file),
    totalsScope: "modules of the scope loaded by at least one fuzz process (unloaded files are listed, not counted)",
    totals: { linesExecutable: t.le, linesCovered: t.lc, linePercent: pct(t.lc, t.le), functions: t.fn, functionsCovered: t.fc, functionPercent: pct(t.fc, t.fn) },
    files,
  };
}

export function coverageMarkdown(s: CoverageSummary, title: string): string {
  const lines = [
    `# ${title}`,
    "",
    `Scope: \`${s.scope}\`. Processes: ${s.processes}. Method: ${s.method}.`,
    "",
    `Total over the modules the fuzz processes loaded (${s.files.length - s.unloadedFiles.length} of ${s.files.length} files): lines ${s.totals.linesCovered}/${s.totals.linesExecutable} (${s.totals.linePercent} %), functions ${s.totals.functionsCovered}/${s.totals.functions} (${s.totals.functionPercent} %). This is not the coverage of the whole scope.`,
    "",
    "| File | Lines covered | Functions covered |",
    "|---|---|---|",
    ...s.files.filter((f) => f.loaded).map((f) => `| ${f.file} | ${f.linesCovered}/${f.linesExecutable} | ${f.functionsCovered}/${f.functions} |`),
    "",
  ];
  if (s.unloadedFiles.length) lines.push(`Not loaded by any fuzz process (not in the totals): ${s.unloadedFiles.join(", ")}.`, "");
  if (s.filesWithoutSourceMap.length) lines.push(`Files loaded without a source map (lines not counted): ${s.filesWithoutSourceMap.join(", ")}.`, "");
  return lines.join("\n");
}

// CLI: node --import tsx harness/v4/robustness/coverage.ts <coverage dir> [<dir> ...] [--out <file.json>]
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  const args = process.argv.slice(2);
  const oi = args.indexOf("--out");
  const out = oi >= 0 ? args[oi + 1] : undefined;
  const dirs = args.filter((a, i) => a !== "--out" && (oi < 0 || i !== oi + 1));
  if (dirs.length === 0) {
    console.error("usage: coverage.ts <NODE_V8_COVERAGE dir> [...] [--out file.json]");
    process.exit(2);
  }
  const s = summariseCoverage(dirs.map((d) => path.resolve(d)));
  const text = JSON.stringify(s, null, 2) + "\n";
  if (out) fs.writeFileSync(out, text);
  else console.log(sanitize(text));
}
