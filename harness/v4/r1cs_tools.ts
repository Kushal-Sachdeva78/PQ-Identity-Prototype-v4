import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { REPO_ROOT } from "@pqid/common/paths";

/**
 * R1CS-level tooling for the v4 security suite (prompt section 5, "fail at R1CS level").
 *
 * The attacker does not use the reference witness generator. It builds its witness with
 * its OWN generator: the v4 circuit with every `// @check` line removed, compiled at
 * --O0 (so every signal is a wire). That witness is mapped into the REAL circuit's --O2
 * wire layout by signal name (.sym files), checked against the REAL R1CS here (every
 * violated constraint is listed and attributed to a named constraint group), and then
 * proved with the REAL proving key; the proof is expected to fail Groth16 verification.
 */

const require = createRequire(import.meta.url);

export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ------------------------------------------------------------------ binfile I/O
interface Section {
  type: number;
  start: number;
  size: number;
}
function sections(buf: Buffer, magic: string): Section[] {
  if (buf.toString("ascii", 0, 4) !== magic) throw new Error(`not a .${magic} file`);
  const n = buf.readUInt32LE(8);
  const out: Section[] = [];
  let pos = 12;
  for (let i = 0; i < n; i++) {
    const type = buf.readUInt32LE(pos);
    const size = Number(buf.readBigUInt64LE(pos + 4));
    out.push({ type, start: pos + 12, size });
    pos += 12 + size;
  }
  return out;
}
function readLE(buf: Buffer, off: number, n8: number): bigint {
  let v = 0n;
  for (let i = n8 - 1; i >= 0; i--) v = (v << 8n) | BigInt(buf[off + i] as number);
  return v;
}

export interface R1cs {
  n8: number;
  nWires: number;
  nPubIn: number;
  nPubOut: number;
  constraints: Array<[Map<number, bigint>, Map<number, bigint>, Map<number, bigint>]>;
}

const r1csCache = new Map<string, R1cs>();
export function readR1cs(file: string): R1cs {
  const hit = r1csCache.get(file);
  if (hit) return hit;
  const buf = fs.readFileSync(file);
  const secs = sections(buf, "r1cs");
  const h = secs.find((s) => s.type === 1);
  const c = secs.find((s) => s.type === 2);
  if (!h || !c) throw new Error("r1cs sections missing");
  const n8 = buf.readUInt32LE(h.start);
  let p = h.start + 4 + n8;
  const nWires = buf.readUInt32LE(p);
  const nPubOut = buf.readUInt32LE(p + 4);
  const nPubIn = buf.readUInt32LE(p + 8);
  p += 12 + 4 + 8; // nPrvIn, nLabels
  const m = buf.readUInt32LE(p);
  const constraints: R1cs["constraints"] = [];
  let q = c.start;
  const lc = () => {
    const n = buf.readUInt32LE(q);
    q += 4;
    const map = new Map<number, bigint>();
    for (let i = 0; i < n; i++) {
      const w = buf.readUInt32LE(q);
      map.set(w, readLE(buf, q + 4, n8));
      q += 4 + n8;
    }
    return map;
  };
  for (let i = 0; i < m; i++) constraints.push([lc(), lc(), lc()]);
  const r = { n8, nWires, nPubIn, nPubOut, constraints };
  r1csCache.set(file, r);
  return r;
}

export function readWtns(file: string): bigint[] {
  const buf = fs.readFileSync(file);
  const secs = sections(buf, "wtns");
  const h = secs.find((s) => s.type === 1);
  const d = secs.find((s) => s.type === 2);
  if (!h || !d) throw new Error("wtns sections missing");
  const n8 = buf.readUInt32LE(h.start);
  const n = buf.readUInt32LE(h.start + 4 + n8);
  const out: bigint[] = [];
  for (let i = 0; i < n; i++) out.push(readLE(buf, d.start + i * n8, n8));
  return out;
}

export function writeWtns(file: string, w: bigint[]): void {
  const n8 = 32;
  const header = Buffer.alloc(4 + n8 + 4);
  header.writeUInt32LE(n8, 0);
  let pv = P;
  for (let i = 0; i < n8; i++) {
    header[4 + i] = Number(pv & 0xffn);
    pv >>= 8n;
  }
  header.writeUInt32LE(w.length, 4 + n8);
  const data = Buffer.alloc(w.length * n8);
  w.forEach((v, idx) => {
    let x = ((v % P) + P) % P;
    for (let i = 0; i < n8; i++) {
      data[idx * n8 + i] = Number(x & 0xffn);
      x >>= 8n;
    }
  });
  const sec = (type: number, body: Buffer) => {
    const hdr = Buffer.alloc(12);
    hdr.writeUInt32LE(type, 0);
    hdr.writeBigUInt64LE(BigInt(body.length), 4);
    return Buffer.concat([hdr, body]);
  };
  const top = Buffer.alloc(12);
  top.write("wtns", 0, "ascii");
  top.writeUInt32LE(2, 4);
  top.writeUInt32LE(2, 8);
  fs.writeFileSync(file, Buffer.concat([top, sec(1, header), sec(2, data)]));
}

// ------------------------------------------------------------------ sym files
export interface Sym {
  /** wire -> signal names */
  names: Map<number, string[]>;
  /** signal name -> wire (-1 when eliminated by simplification) */
  wireOf: Map<string, number>;
}
const symCache = new Map<string, Sym>();
export function readSym(file: string): Sym {
  const hit = symCache.get(file);
  if (hit) return hit;
  const names = new Map<number, string[]>();
  const wireOf = new Map<string, number>();
  for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    if (!line) continue;
    const parts = line.split(",");
    const wire = Number(parts[1]);
    const name = parts.slice(3).join(",");
    wireOf.set(name, wire);
    if (wire >= 0) {
      const arr = names.get(wire) ?? [];
      arr.push(name);
      names.set(wire, arr);
    }
  }
  const s = { names, wireOf };
  symCache.set(file, s);
  return s;
}

// ------------------------------------------------------------------ constraint groups
const GROUP_PREFIXES: Array<[RegExp, string]> = [
  [/^main\.holder\./, "G02_holder_commit"],
  [/^main\.leaf\./, "G03_leaf"],
  [/^main\.iss\./, "G04_issuance_membership"],
  [/^main\.(hiBits|loBits)\./, "G05_revkey"],
  [/^main\.revMember\./, "G06_rev_low_membership"],
  [/^main\.revBracket\./, "G07_rev_bracket"],
  [/^main\.pol\./, "G08_policy_hash"],
  [/^main\.thrAcc/, "G10_standard_threshold"],
  [/^main\.r(Birth|Expiry|Today|From|To|Thr)\./, "G11_ranges"],
  [/^main\.reached\./, "G12_age"],
  [/^main\.notExpired\./, "G13_expiry"],
  [/^main\.(afterFrom|beforeTo)\./, "G15_epoch_window"],
  [/^main\.stmt\./, "G16_stmt"],
  [/^main\.nonceSq/, "G17_nonce"],
];

/** Attribute one constraint of the real R1CS to a constraint group via signal names. */
export function constraintGroup(sym: Sym, c: R1cs["constraints"][number]): string {
  const votes = new Map<string, number>();
  const topLevel: string[] = [];
  for (const lcmap of c) {
    for (const w of lcmap.keys()) {
      if (w === 0) continue;
      for (const n of sym.names.get(w) ?? []) {
        const g = GROUP_PREFIXES.find(([re]) => re.test(n))?.[1];
        if (g) votes.set(g, (votes.get(g) ?? 0) + 1);
        else topLevel.push(n);
      }
    }
  }
  if (votes.size > 0) return [...votes.entries()].sort((a, b) => b[1] - a[1])[0]![0];
  if (topLevel.length > 0 && topLevel.every((n) => n === "main.predicateCode")) return "G09_predicate_code";
  return `unattributed(${[...new Set(topLevel)].slice(0, 3).join("|")})`;
}

export interface R1csReport {
  satisfied: boolean;
  violated: number;
  byGroup: Record<string, number>;
  firstViolated: Array<{ index: number; group: string }>;
}

/** Evaluate every constraint A*B = C of `r1csFile` on witness `w`. */
export function checkR1cs(r1csFile: string, symFile: string, w: bigint[]): R1csReport {
  const r = readR1cs(r1csFile);
  const sym = readSym(symFile);
  if (w.length !== r.nWires) throw new Error(`witness has ${w.length} wires, r1cs has ${r.nWires}`);
  if (w[0] !== 1n) throw new Error("wire 0 must be the constant 1");
  const ev = (m: Map<number, bigint>) => {
    let s = 0n;
    for (const [k, v] of m) s += v * (w[k] as bigint);
    return s % P;
  };
  const byGroup: Record<string, number> = {};
  const firstViolated: R1csReport["firstViolated"] = [];
  let violated = 0;
  r.constraints.forEach((c, i) => {
    const lhs = (ev(c[0]) * ev(c[1])) % P;
    const rhs = ev(c[2]);
    if (lhs !== rhs) {
      violated++;
      const g = constraintGroup(sym, c);
      byGroup[g] = (byGroup[g] ?? 0) + 1;
      if (firstViolated.length < 10) firstViolated.push({ index: i, group: g });
    }
  });
  return { satisfied: violated === 0, violated, byGroup, firstViolated };
}

// ------------------------------------------------------------------ attacker generator
export const V4_SRC = path.join(REPO_ROOT, "circuits", "credential_auth_v4.circom");
export const V4_BUILD = path.join(REPO_ROOT, "circuits", "build", "v4");
export const ATTACKER_DIR = path.join(V4_BUILD, "attacker");

function circomBin(): string {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  return process.platform === "win32" && fs.existsSync(win) ? win : "circom";
}

/** Source of the attacker's generator: the v4 circuit with every `// @check` line removed. */
export function attackerSource(src: string): string {
  const out = src
    .split(/\r?\n/)
    .map((l) => (/\/\/ @check\s*$/.test(l) ? `    // [attacker generator] removed: ${l.trim()}` : l))
    .join("\n");
  // The include stays relative ("v4/lib_v4.circom"); the compile adds circuits/ to the library
  // path, so the generated source names no absolute (home) path.
  return out;
}

/**
 * Build (once) the attacker's --O0 witness generator from `srcFile` (default: the real v4
 * circuit; mutation runs pass a mutant's source) into `outDir`.
 */
export function buildAttackerGenerator(srcFile: string = V4_SRC, outDir: string = ATTACKER_DIR): { wasm: string; sym: string; witnessCalculator: string } {
  fs.mkdirSync(outDir, { recursive: true });
  const src = attackerSource(fs.readFileSync(srcFile, "utf8"));
  const file = path.join(outDir, "credential_auth_v4_attacker.circom");
  const wasm = path.join(outDir, "credential_auth_v4_attacker_js", "credential_auth_v4_attacker.wasm");
  const sym = path.join(outDir, "credential_auth_v4_attacker.sym");
  const stale = !fs.existsSync(wasm) || !fs.existsSync(file) || fs.readFileSync(file, "utf8") !== src;
  if (stale) {
    fs.writeFileSync(file, src);
    execFileSync(circomBin(), [file, "--O0", "--wasm", "--sym", "-l", path.join(REPO_ROOT, "node_modules"), "-l", path.join(REPO_ROOT, "circuits"), "-o", outDir], {
      cwd: REPO_ROOT,
      stdio: "pipe",
    });
  }
  return { wasm, sym, witnessCalculator: path.join(outDir, "credential_auth_v4_attacker_js", "witness_calculator.js") };
}

/** Run the attacker's generator on arbitrary inputs; returns its (O0-layout) witness. */
export async function attackerWitnessO0(input: Record<string, unknown>, g = buildAttackerGenerator()): Promise<bigint[]> {
  const snarkjs = await import("snarkjs");
  const tmp = path.join(os.tmpdir(), `pqid-v4-att-o0-${randomBytes(4).toString("hex")}.wtns`);
  try {
    await (snarkjs.wtns as unknown as { calculate(i: unknown, wasm: string, out: string): Promise<void> }).calculate(input, g.wasm, tmp);
    return readWtns(tmp);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

/** Kept for tooling that wants the circom-generated calculator directly (CommonJS). */
export function loadGeneratedCalculator(file: string): unknown {
  return require(file);
}

/** Map an O0 witness of the attacker generator into the real circuit's wire layout by name. */
export function mapToReal(attW: bigint[], attSymFile: string, realSymFile: string, realR1csFile: string): bigint[] {
  const att = readSym(attSymFile);
  const real = readSym(realSymFile);
  const r = readR1cs(realR1csFile);
  const out: bigint[] = new Array(r.nWires).fill(0n);
  out[0] = 1n;
  for (let w = 1; w < r.nWires; w++) {
    const names = real.names.get(w) ?? [];
    const src = names.map((n) => att.wireOf.get(n)).find((x) => x !== undefined && x >= 0);
    if (src === undefined) throw new Error(`real wire ${w} (${names.join("|")}) has no counterpart in the attacker witness`);
    out[w] = attW[src] as bigint;
  }
  return out;
}

export interface AttackerProofResult {
  r1cs: R1csReport;
  proofVerifies: boolean;
  proof: unknown;
  publicSignals: string[];
}

/**
 * Full R1CS-level route: attacker inputs -> attacker generator -> real layout ->
 * real R1CS check -> Groth16 proof under the real proving key -> verification.
 */
export async function attackerProve(
  input: Record<string, unknown>,
  real: { r1cs: string; sym: string; zkey: string; vkey: unknown; src?: string; attackerDir?: string }
): Promise<AttackerProofResult> {
  const g = buildAttackerGenerator(real.src ?? V4_SRC, real.attackerDir ?? ATTACKER_DIR);
  const attW = await attackerWitnessO0(input, g);
  const w = mapToReal(attW, g.sym, real.sym, real.r1cs);
  const report = checkR1cs(real.r1cs, real.sym, w);
  const tmp = path.join(os.tmpdir(), `pqid-v4-attacker-${randomBytes(4).toString("hex")}.wtns`);
  writeWtns(tmp, w);
  try {
    const snarkjs = await import("snarkjs");
    const { proof, publicSignals } = await snarkjs.groth16.prove(real.zkey, tmp);
    const proofVerifies = await snarkjs.groth16.verify(real.vkey, publicSignals, proof);
    return { r1cs: report, proofVerifies, proof, publicSignals };
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}
