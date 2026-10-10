import type { Rng } from "./rng.ts";

/**
 * Mutation operators of the in-repo fuzz generator (D-034). Every operator takes an Rng and
 * returns a new value (inputs are never changed in place) plus a short description of what
 * it did; the descriptions go into failure files as the mutation recipe.
 *
 * Families:
 *  - bytes: bit flip, byte set, insert, delete, duplicate, truncate, splice from another
 *    input, 32-bit big-endian length-field edits, junk appended;
 *  - strings: character edits with hostile code points (NUL, BOM, lone surrogates, quotes,
 *    backslash, non-ASCII), case changes, truncation, repetition;
 *  - JSON text: whitespace, duplicate keys, key reordering, BOM, number spellings (-0, 1e0,
 *    leading zeros, 1.0), \\u escapes, trailing commas, deep nesting, huge digit strings,
 *    overlong and invalid UTF-8 at the byte level;
 *  - value trees: type confusion, key deletion and insertion ("__proto__", "constructor",
 *    "toString"), swaps, numeric edits, array edits, wrapping, and exotic objects (getters,
 *    Proxy, class instances, typed arrays, null-prototype objects).
 */

export interface Mutated<T> {
  value: T;
  ops: string[];
}

// ------------------------------------------------------------------ interesting values

export const INTERESTING_U32 = [0, 1, 2, 7, 8, 16, 31, 32, 33, 48, 64, 127, 128, 255, 256, 1024, 65535, 65536, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff];

/** Code points that break naive string handling. */
export const HOSTILE_CHARS = ["\u0000", "\u0001", "\u001f", " ", '"', "\\", "/", "\u007f", "\u0080", "\u00e9", "\u2028", "\u2029", "\ufeff", "\ufffd", "\ud800", "\udfff", "\ud83d\ude00", "\u{10ffff}", "A", "0", "9", "f", "F", "x", ":", "-", "+", "."];

/** Values of other JSON and non-JSON types for type confusion. */
export function confusionValues(rng: Rng): unknown[] {
  return [
    null,
    true,
    false,
    0,
    -0,
    1,
    -1,
    1.5,
    2 ** 53,
    2 ** 53 - 1,
    -(2 ** 53),
    1e308,
    NaN,
    Infinity,
    "",
    "0",
    "-0",
    "1e3",
    " 1",
    "x".repeat(rng.int(1, 300)),
    [],
    [0],
    {},
    { a: 1 },
    undefined,
    10n,
  ];
}

// ------------------------------------------------------------------ bytes

export function mutateBytes(rng: Rng, input: Uint8Array, corpus: readonly Uint8Array[] = [], rounds = 1): Mutated<Buffer> {
  let b: Buffer = Buffer.from(input);
  const ops: string[] = [];
  for (let r = 0; r < rounds; r++) {
    const op = rng.weighted<string>([
      [4, "flip"],
      [3, "set"],
      [2, "insert"],
      [2, "delete"],
      [1, "duplicate"],
      [2, "truncate"],
      [1, "splice"],
      [2, "u32"],
      [1, "append"],
    ]);
    const pos = b.length === 0 ? 0 : rng.int(0, b.length - 1);
    switch (op) {
      case "flip": {
        if (b.length === 0) break;
        const bit = rng.int(0, 7);
        b = Buffer.from(b);
        b[pos] = (b[pos] as number) ^ (1 << bit);
        ops.push(`flip byte ${pos} bit ${bit}`);
        break;
      }
      case "set": {
        if (b.length === 0) break;
        const v = rng.pick([0x00, 0xff, 0x7f, 0x80, 0x22, 0x5c, 0x30, 0x39, 0x7b, 0x7d, 0x5b, 0x5d, 0x2c, 0x3a, rng.int(0, 255)]);
        b = Buffer.from(b);
        b[pos] = v;
        ops.push(`set byte ${pos} = 0x${v.toString(16)}`);
        break;
      }
      case "insert": {
        const n = rng.pick([1, 1, 2, 4, 8, 32, rng.int(1, 64)]);
        const ins = rng.bytes(n);
        b = Buffer.concat([b.subarray(0, pos), ins, b.subarray(pos)]);
        ops.push(`insert ${n} bytes at ${pos}`);
        break;
      }
      case "delete": {
        if (b.length === 0) break;
        const n = Math.min(b.length - pos, rng.pick([1, 1, 2, 4, 32, rng.int(1, 64)]));
        b = Buffer.concat([b.subarray(0, pos), b.subarray(pos + n)]);
        ops.push(`delete ${n} bytes at ${pos}`);
        break;
      }
      case "duplicate": {
        if (b.length === 0) break;
        const n = Math.min(b.length - pos, rng.int(1, 64));
        b = Buffer.concat([b.subarray(0, pos + n), b.subarray(pos, pos + n), b.subarray(pos + n)]);
        ops.push(`duplicate ${n} bytes at ${pos}`);
        break;
      }
      case "truncate": {
        const keep = rng.int(0, b.length);
        b = Buffer.from(b.subarray(0, keep));
        ops.push(`truncate to ${keep}`);
        break;
      }
      case "splice": {
        if (corpus.length === 0) break;
        const other = rng.pick(corpus);
        if (other.length === 0) break;
        const from = rng.int(0, other.length - 1);
        const n = Math.min(other.length - from, rng.int(1, 128));
        b = Buffer.concat([b.subarray(0, pos), Buffer.from(other.subarray(from, from + n)), b.subarray(pos)]);
        ops.push(`splice ${n} bytes from corpus at ${pos}`);
        break;
      }
      case "u32": {
        if (b.length < 4) break;
        const at = rng.int(0, b.length - 4);
        const v = rng.pick(INTERESTING_U32);
        b = Buffer.from(b);
        b.writeUInt32BE(v >>> 0, at);
        ops.push(`u32be at ${at} = ${v}`);
        break;
      }
      case "append": {
        const n = rng.int(1, 64);
        b = Buffer.concat([b, rng.bytes(n)]);
        ops.push(`append ${n} bytes`);
        break;
      }
    }
  }
  return { value: b, ops };
}

/** Overwrite a 32-bit big-endian field at `offset` (length and count fields of binary formats). */
export function setU32be(input: Uint8Array, offset: number, v: number): Buffer {
  const b = Buffer.from(input);
  if (offset + 4 <= b.length) b.writeUInt32BE(v >>> 0, offset);
  return b;
}

// ------------------------------------------------------------------ strings

export function mutateString(rng: Rng, s: string): Mutated<string> {
  const op = rng.weighted<string>([
    [3, "replace"],
    [2, "insert"],
    [2, "delete"],
    [1, "case"],
    [1, "truncate"],
    [1, "repeat"],
    [1, "prefix"],
    [1, "empty"],
  ]);
  const pos = s.length === 0 ? 0 : rng.int(0, s.length - 1);
  const ch = rng.pick(HOSTILE_CHARS);
  switch (op) {
    case "replace":
      return { value: s.slice(0, pos) + ch + s.slice(pos + 1), ops: [`replace char ${pos} with U+${ch.codePointAt(0)?.toString(16)}`] };
    case "insert":
      return { value: s.slice(0, pos) + ch + s.slice(pos), ops: [`insert U+${ch.codePointAt(0)?.toString(16)} at ${pos}`] };
    case "delete":
      return { value: s.slice(0, pos) + s.slice(pos + 1), ops: [`delete char ${pos}`] };
    case "case": {
      const up = s.toUpperCase();
      return { value: up !== s ? up : s.toLowerCase(), ops: ["change case"] };
    }
    case "truncate": {
      const n = rng.int(0, s.length);
      return { value: s.slice(0, n), ops: [`truncate to ${n}`] };
    }
    case "repeat": {
      const k = rng.pick([2, 3, 10, 100]);
      return { value: s.repeat(k).slice(0, 100_000), ops: [`repeat x${k}`] };
    }
    case "prefix":
      return { value: ch + s, ops: [`prefix U+${ch.codePointAt(0)?.toString(16)}`] };
    default:
      return { value: "", ops: ["empty string"] };
  }
}

/** Hex-string edits: case change, odd length, non-hex digit, length change. */
export function mutateHex(rng: Rng, hex: string): Mutated<string> {
  const op = rng.pick(["upper", "odd", "nonhex", "shorter", "longer", "prefix0x", "space"]);
  const pos = hex.length === 0 ? 0 : rng.int(0, hex.length - 1);
  switch (op) {
    case "upper":
      return { value: hex.slice(0, pos) + hex.slice(pos).toUpperCase(), ops: [`upper-case from ${pos}`] };
    case "odd":
      return { value: hex + "0", ops: ["odd length"] };
    case "nonhex":
      return { value: hex.slice(0, pos) + rng.pick(["g", "G", "z", " ", "-", "\u0000"]) + hex.slice(pos + 1), ops: [`non-hex at ${pos}`] };
    case "shorter":
      return { value: hex.slice(0, Math.max(0, hex.length - rng.pick([1, 2, 64]))), ops: ["shorter"] };
    case "longer":
      return { value: hex + rng.pick(["00", "ff", "0".repeat(64)]), ops: ["longer"] };
    case "prefix0x":
      return { value: "0x" + hex, ops: ["0x prefix"] };
    default:
      return { value: hex.slice(0, pos) + " " + hex.slice(pos), ops: [`space at ${pos}`] };
  }
}

// ------------------------------------------------------------------ JSON text

/** Deep nesting of arrays or objects (iteratively built text). */
export function deepJson(depth: number, kind: "array" | "object" | "mixed", leaf = "0"): string {
  if (kind === "array") return "[".repeat(depth) + leaf + "]".repeat(depth);
  if (kind === "object") return '{"a":'.repeat(depth) + leaf + "}".repeat(depth);
  let open = "";
  let close = "";
  for (let i = 0; i < depth; i++) {
    if (i % 2 === 0) {
      open += "[";
      close = "]" + close;
    } else {
      open += '{"k":';
      close = "}" + close;
    }
  }
  return open + leaf + close;
}

/** A canonical decimal digit string of `n` digits (no leading zero). */
export function hugeDigits(rng: Rng, n: number): string {
  const head = String(rng.int(1, 9));
  if (n <= 1) return head;
  // repeat a random block to keep generation fast
  let block = "";
  for (let i = 0; i < 64; i++) block += String(rng.int(0, 9));
  return (head + block.repeat(Math.ceil(n / 64))).slice(0, n);
}

/** Mutations on JSON text (the result may or may not parse). */
export function mutateJsonText(rng: Rng, text: string): Mutated<string> {
  const op = rng.weighted<string>([
    [2, "whitespace"],
    [2, "dupkey"],
    [1, "bom"],
    [2, "number"],
    [2, "escape"],
    [1, "trailing-comma"],
    [1, "wrap-array"],
    [2, "char"],
    [1, "deep"],
    [1, "reorder"],
    [1, "huge-number"],
  ]);
  switch (op) {
    case "whitespace": {
      const positions = [...text.matchAll(/[,:{}[\]]/g)].map((m) => m.index ?? 0);
      if (positions.length === 0) return { value: " " + text, ops: ["leading space"] };
      const at = rng.pick(positions) + 1;
      const ws = rng.pick([" ", "\n", "\t", "\r\n", "  "]);
      return { value: text.slice(0, at) + ws + text.slice(at), ops: [`whitespace at ${at}`] };
    }
    case "dupkey": {
      const m = [...text.matchAll(/"([^"\\]{1,40})":("(?:[^"\\]|\\.){0,200}"|-?\d[\d.eE+-]{0,80}|true|false|null)/g)];
      if (m.length === 0) return { value: text, ops: ["dupkey: no simple member"] };
      const hit = rng.pick(m);
      const at = (hit.index ?? 0) + hit[0].length;
      const val = rng.bool() ? hit[2] : JSON.stringify(rng.pick(["x", 0, null, true]));
      return { value: text.slice(0, at) + `,"${hit[1]}":${val}` + text.slice(at), ops: [`duplicate key ${hit[1]}`] };
    }
    case "bom":
      return { value: "\ufeff" + text, ops: ["BOM prefix"] };
    case "number": {
      const m = [...text.matchAll(/(?<=[:[,])(-?\d+)(?=[,}\]])/g)];
      if (m.length === 0) return { value: text, ops: ["number: none"] };
      const hit = rng.pick(m);
      const at = hit.index ?? 0;
      const n = hit[1] as string;
      const spelling = rng.pick([n === "0" ? "-0" : "-" + n, n + ".0", n + "e0", "0" + n, n.length > 1 ? n[0] + "e" + (n.length - 1) : n + ".00", "1e400", "-1"]);
      return { value: text.slice(0, at) + spelling + text.slice(at + n.length), ops: [`number ${n} -> ${spelling}`] };
    }
    case "escape": {
      const m = [...text.matchAll(/"((?:[^"\\]){1,200})"/g)];
      if (m.length === 0) return { value: text, ops: ["escape: none"] };
      const hit = rng.pick(m);
      const inner = hit[1] as string;
      const k = rng.int(0, inner.length - 1);
      const c = inner.charCodeAt(k);
      const esc = "\\u" + c.toString(16).padStart(4, "0");
      const start = (hit.index ?? 0) + 1 + k;
      return { value: text.slice(0, start) + esc + text.slice(start + 1), ops: [`\\u-escape char ${k} of a string`] };
    }
    case "trailing-comma": {
      const at = text.lastIndexOf("}");
      if (at <= 0) return { value: text + ",", ops: ["trailing comma"] };
      return { value: text.slice(0, at) + "," + text.slice(at), ops: ["trailing comma before }"] };
    }
    case "wrap-array":
      return { value: "[" + text + "]", ops: ["wrap in array"] };
    case "char": {
      const pos = text.length === 0 ? 0 : rng.int(0, text.length - 1);
      const ch = rng.pick(HOSTILE_CHARS);
      return { value: text.slice(0, pos) + ch + text.slice(pos + 1), ops: [`char ${pos} -> U+${ch.codePointAt(0)?.toString(16)}`] };
    }
    case "deep": {
      const depth = rng.pick([9, 10, 64, 1000, 10_000]);
      const at = text.indexOf(":");
      const end = at < 0 ? -1 : text.indexOf(",", at);
      if (at < 0 || end < 0) return { value: deepJson(depth, "array"), ops: [`replace by depth-${depth} array`] };
      return { value: text.slice(0, at + 1) + deepJson(depth, rng.pick(["array", "object", "mixed"] as const)) + text.slice(end), ops: [`nest depth ${depth} into first member`] };
    }
    case "reorder": {
      try {
        const v = JSON.parse(text) as unknown;
        if (v && typeof v === "object" && !Array.isArray(v)) {
          const keys = rng.shuffle(Object.keys(v as object));
          const o: Record<string, unknown> = {};
          for (const k of keys) Object.defineProperty(o, k, { value: (v as Record<string, unknown>)[k], enumerable: true, writable: true, configurable: true });
          return { value: JSON.stringify(o), ops: ["reorder top-level keys"] };
        }
      } catch {
        /* fall through */
      }
      return { value: text, ops: ["reorder: not an object"] };
    }
    default: {
      const digits = rng.pick([100, 1000, 100_000, 400_000]);
      const m = [...text.matchAll(/"(0|[1-9][0-9]*)"/g)];
      const huge = hugeDigits(rng, digits);
      if (m.length === 0) return { value: text, ops: ["huge-number: no decimal string"] };
      const hit = rng.pick(m);
      const at = hit.index ?? 0;
      return { value: text.slice(0, at) + `"${huge}"` + text.slice(at + hit[0].length), ops: [`decimal string -> ${digits} digits`] };
    }
  }
}

/** Byte-level encoding hazards on UTF-8 text: overlong encodings, lone surrogates (CESU), invalid bytes. */
export function utf8Hazard(rng: Rng, text: string): Mutated<Buffer> {
  const bytes = Buffer.from(text, "utf8");
  const op = rng.pick(["overlong-slash", "overlong-quote", "cesu-surrogate", "invalid-ff", "truncated-seq", "bom-bytes", "nul"]);
  const pos = bytes.length === 0 ? 0 : rng.int(0, bytes.length);
  const ins: Record<string, number[]> = {
    "overlong-slash": [0xc0, 0xaf],
    "overlong-quote": [0xc0, 0xa2],
    "cesu-surrogate": [0xed, 0xa0, 0x80],
    "invalid-ff": [0xff],
    "truncated-seq": [0xe2, 0x82],
    "bom-bytes": [0xef, 0xbb, 0xbf],
    nul: [0x00],
  };
  return { value: Buffer.concat([bytes.subarray(0, pos), Buffer.from(ins[op] as number[]), bytes.subarray(pos)]), ops: [`${op} at byte ${pos}`] };
}

// ------------------------------------------------------------------ value trees

type Path = Array<string | number>;

/** Every path to a node of a JSON-like value (root included), breadth limited. */
export function paths(v: unknown, max = 400): Path[] {
  const out: Path[] = [[]];
  const queue: Array<[unknown, Path]> = [[v, []]];
  while (queue.length && out.length < max) {
    const [x, p] = queue.shift() as [unknown, Path];
    if (x === null || typeof x !== "object" || ArrayBuffer.isView(x)) continue; // byte arrays are leaves
    if (Array.isArray(x)) {
      x.forEach((y, i) => {
        out.push([...p, i]);
        queue.push([y, [...p, i]]);
      });
    } else {
      for (const k of Object.keys(x)) {
        out.push([...p, k]);
        queue.push([(x as Record<string, unknown>)[k], [...p, k]]);
      }
    }
  }
  return out;
}

/**
 * A copy of the bytes of a byte array, read through its internal slots only: own properties a
 * mutation added to the array (an own valueOf, length or buffer key) are ignored. The TypedArray
 * constructor reads a typed-array argument's buffer, offset and length from internal slots, not
 * from properties. Buffer.from(view) is not used: for an object it first calls value.valueOf(),
 * so an own non-callable valueOf throws a TypeError and an own valueOf of "" gives an empty
 * buffer (the fz1 T-witness false positive; docs/v4/ROBUSTNESS.md, Deviations, 2026-10-03).
 */
export function copyBytes(v: Uint8Array): Buffer {
  const u = new Uint8Array(v);
  return Buffer.from(u.buffer, u.byteOffset, u.byteLength);
}

/** Plain-data deep copy that keeps "__proto__" keys as own properties (a byte array is copied by its bytes; own keys on it are dropped). */
export function cloneJson<T>(v: T): T {
  if (v === null || typeof v !== "object") return v;
  if (v instanceof Uint8Array) return copyBytes(v) as unknown as T;
  if (Array.isArray(v)) return v.map((x) => cloneJson(x)) as unknown as T;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(v as object)) {
    Object.defineProperty(out, k, { value: cloneJson((v as Record<string, unknown>)[k]), enumerable: true, writable: true, configurable: true });
  }
  return out as T;
}

function getAt(root: unknown, p: Path): unknown {
  let x = root;
  for (const k of p) x = (x as Record<string | number, unknown>)[k];
  return x;
}

function setAt(root: unknown, p: Path, val: unknown): unknown {
  if (p.length === 0) return val;
  const parent = getAt(root, p.slice(0, -1)) as Record<string | number, unknown>;
  const k = p[p.length - 1] as string | number;
  Object.defineProperty(parent, k, { value: val, enumerable: true, writable: true, configurable: true });
  return root;
}

function deleteAt(root: unknown, p: Path): unknown {
  if (p.length === 0) return root;
  const parent = getAt(root, p.slice(0, -1)) as Record<string | number, unknown> | unknown[];
  const k = p[p.length - 1] as string | number;
  if (Array.isArray(parent) && typeof k === "number") parent.splice(k, 1);
  else delete (parent as Record<string | number, unknown>)[k];
  return root;
}

const EXTRA_KEYS = ["__proto__", "constructor", "toString", "valueOf", "hasOwnProperty", "x", "", "signature", "type", "a".repeat(300)];

/** One or more value-level mutations of a JSON-like tree (the input is copied first). */
export function mutateValue(rng: Rng, input: unknown, rounds = 1): Mutated<unknown> {
  let root = cloneJson(input);
  const ops: string[] = [];
  for (let r = 0; r < rounds; r++) {
    const ps = paths(root);
    const p = rng.pick(ps);
    const cur = getAt(root, p);
    const where = p.length === 0 ? "root" : p.join(".");
    const op = rng.weighted<string>([
      [4, "confuse"],
      [2, "delete"],
      [2, "addkey"],
      [3, "string"],
      [3, "number"],
      [1, "array"],
      [1, "wrap"],
      [1, "swap"],
    ]);
    switch (op) {
      case "confuse": {
        const v = rng.pick(confusionValues(rng));
        root = setAt(root, p, v);
        ops.push(`${where}: replace by ${typeof v === "bigint" ? "bigint" : JSON.stringify(v) ?? String(v)}`.slice(0, 160));
        break;
      }
      case "delete":
        if (p.length > 0) {
          root = deleteAt(root, p);
          ops.push(`${where}: delete`);
        }
        break;
      case "addkey": {
        if (cur && typeof cur === "object" && !Array.isArray(cur)) {
          const k = rng.pick(EXTRA_KEYS);
          Object.defineProperty(cur, k, { value: rng.pick(confusionValues(rng)), enumerable: true, writable: true, configurable: true });
          ops.push(`${where}: add key ${JSON.stringify(k.slice(0, 20))}`);
        }
        break;
      }
      case "string":
        if (typeof cur === "string") {
          const m = /^[0-9a-f]+$/.test(cur) && cur.length >= 8 ? mutateHex(rng, cur) : mutateString(rng, cur);
          root = setAt(root, p, m.value);
          ops.push(`${where}: ${m.ops.join(", ")}`);
        }
        break;
      case "number":
        if (typeof cur === "number") {
          const v = rng.pick([cur + 1, cur - 1, -cur, cur * 10, cur + 0.5, 0, -0, cur + 86400, cur - 86400, cur + 1e4, 2 ** 53, Math.floor(cur / 100)]);
          root = setAt(root, p, v);
          ops.push(`${where}: ${cur} -> ${Object.is(v, -0) ? "-0" : v}`);
        } else if (typeof cur === "string" && /^(0|[1-9][0-9]*)$/.test(cur)) {
          const n = BigInt(cur);
          const v = rng.pick([n + 1n, n === 0n ? 1n : n - 1n, n * 2n, n + 21888242871839275222246405745257275088548364400416034343698204186575808495617n, 0n]);
          const s = rng.bool(0.15) ? "0" + v.toString() : v.toString();
          root = setAt(root, p, s);
          ops.push(`${where}: decimal edit`);
        }
        break;
      case "array":
        if (Array.isArray(cur)) {
          const a = cur.slice();
          const k = rng.pick(["dup", "drop", "empty", "reverse"]);
          if (k === "dup" && a.length) a.push(cloneJson(a[rng.int(0, a.length - 1)]));
          else if (k === "drop" && a.length) a.splice(rng.int(0, a.length - 1), 1);
          else if (k === "empty") a.length = 0;
          else a.reverse();
          root = setAt(root, p, a);
          ops.push(`${where}: array ${k}`);
        }
        break;
      case "wrap":
        root = setAt(root, p, rng.bool() ? [cur] : { v: cur });
        ops.push(`${where}: wrap`);
        break;
      case "swap": {
        const q = rng.pick(ps);
        if (q.length === 0 || p.length === 0 || q.join(".").startsWith(p.join(".")) || p.join(".").startsWith(q.join("."))) break;
        const a = cloneJson(getAt(root, p));
        const b = cloneJson(getAt(root, q));
        root = setAt(root, p, b);
        root = setAt(root, q, a);
        ops.push(`swap ${where} <-> ${q.join(".")}`);
        break;
      }
    }
  }
  return { value: root, ops };
}

// ------------------------------------------------------------------ exotic objects

export type ExoticKind = "getter" | "throwing-getter" | "proxy" | "throwing-proxy" | "class-instance" | "null-proto" | "typed-array" | "map" | "frozen";

class Shape {
  constructor(src: Record<string, unknown>) {
    Object.assign(this, src);
  }
}

/**
 * An exotic stand-in for a plain object (wire inputs never contain these; in-process callers
 * can pass them). Getters and Proxy objects here return the same values as `src` unless they
 * are the throwing kinds.
 */
export function exotic(rng: Rng, src: Record<string, unknown>, kind?: ExoticKind): Mutated<unknown> {
  const k: ExoticKind = kind ?? rng.pick(["getter", "throwing-getter", "proxy", "throwing-proxy", "class-instance", "null-proto", "typed-array", "map", "frozen"] as const);
  switch (k) {
    case "getter": {
      const o: Record<string, unknown> = {};
      for (const key of Object.keys(src)) Object.defineProperty(o, key, { get: () => src[key], enumerable: true, configurable: true });
      return { value: o, ops: ["every field behind a getter"] };
    }
    case "throwing-getter": {
      const o = { ...src };
      const keys = Object.keys(src);
      const key = keys.length ? rng.pick(keys) : "x";
      Object.defineProperty(o, key, {
        get: () => {
          throw new Error("getter throws");
        },
        enumerable: true,
        configurable: true,
      });
      return { value: o, ops: [`field ${key} behind a throwing getter`] };
    }
    case "proxy":
      return { value: new Proxy({ ...src }, {}), ops: ["transparent Proxy"] };
    case "throwing-proxy":
      return {
        value: new Proxy(
          { ...src },
          {
            ownKeys() {
              throw new Error("ownKeys trap throws");
            },
          }
        ),
        ops: ["Proxy whose ownKeys trap throws"],
      };
    case "class-instance":
      return { value: new Shape({ ...src }), ops: ["class instance with the same own fields"] };
    case "null-proto": {
      const o = Object.create(null) as Record<string, unknown>;
      Object.assign(o, src);
      return { value: o, ops: ["null-prototype object"] };
    }
    case "typed-array":
      return { value: new Uint8Array([1, 2, 3]), ops: ["typed array instead of object"] };
    case "map":
      return { value: new Map(Object.entries(src)), ops: ["Map instead of object"] };
    default:
      return { value: Object.freeze({ ...src }), ops: ["frozen copy"] };
  }
}
