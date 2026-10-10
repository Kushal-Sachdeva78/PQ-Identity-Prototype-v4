/**
 * Typed JSON for fuzz inputs and failure files: values that plain JSON cannot hold (bigint,
 * bytes, undefined, -0, NaN, +-Infinity, objects with keys such as "__proto__") are written as
 * tagged objects, so a saved failure input decodes back to exactly the value that was tested.
 *
 *   bigint     {"$t":"bigint","v":"123"}
 *   bytes      {"$t":"bytes","hex":"00ff"}          (Uint8Array and Buffer; decoded as Buffer)
 *   undefined  {"$t":"undefined"}
 *   number     {"$t":"number","v":"-0"|"NaN"|"Infinity"|"-Infinity"}
 *   object     {"$t":"object","entries":[[key, value], ...]}   (own enumerable keys, in order)
 *   nullproto  {"$t":"nullproto","entries":[...]}               (Object.create(null))
 *   array      [ ... ]  (holes are written as {"$t":"hole"})
 *   exotic     {"$t":"exotic","kind":"...","note":"..."}         (getters, Proxy, class instances,
 *              typed arrays other than bytes, Map, Set, symbols, functions: not reconstructable;
 *              the case is replayed by regenerating it from its seed and index)
 * Strings, booleans, null and other finite numbers are written as themselves.
 */

export type Typed = null | boolean | number | string | Typed[] | { $t: string; [k: string]: unknown };

const TAG = "$t";

function isPlainProto(v: object): boolean {
  const p = Object.getPrototypeOf(v) as unknown;
  return p === Object.prototype;
}

/** Encode a value for a failure file. Never throws (exotic parts become {"$t":"exotic"}). */
export function encodeTyped(v: unknown, depth = 0): Typed {
  if (depth > 2000) return { $t: "exotic", kind: "too-deep", note: "nesting beyond 2000 levels is not written (regenerate from seed)" };
  try {
    if (v === null) return null;
    switch (typeof v) {
      case "boolean":
      case "string":
        return v;
      case "number":
        if (Object.is(v, -0)) return { $t: "number", v: "-0" };
        if (Number.isNaN(v)) return { $t: "number", v: "NaN" };
        if (v === Infinity) return { $t: "number", v: "Infinity" };
        if (v === -Infinity) return { $t: "number", v: "-Infinity" };
        return v;
      case "bigint":
        return { $t: "bigint", v: v.toString() };
      case "undefined":
        return { $t: "undefined" };
      case "symbol":
        return { $t: "exotic", kind: "symbol", note: String(v.description ?? "") };
      case "function":
        return { $t: "exotic", kind: "function", note: "" };
      default:
        break;
    }
    if (v instanceof Uint8Array) return { $t: "bytes", hex: Buffer.from(v.buffer, v.byteOffset, v.byteLength).toString("hex") };
    if (ArrayBuffer.isView(v)) return { $t: "exotic", kind: "typed-array", note: Object.prototype.toString.call(v) };
    if (Array.isArray(v)) {
      if (Object.getPrototypeOf(v) !== Array.prototype) return { $t: "exotic", kind: "array-subclass", note: "" };
      const out: Typed[] = [];
      for (let i = 0; i < v.length; i++) out.push(i in v ? encodeTyped(v[i], depth + 1) : { $t: "hole" });
      return out;
    }
    const o = v as object;
    if (o instanceof Map || o instanceof Set) return { $t: "exotic", kind: o instanceof Map ? "map" : "set", note: "" };
    const proto = Object.getPrototypeOf(o) as unknown;
    if (proto !== null && !isPlainProto(o)) return { $t: "exotic", kind: "class-instance", note: String((proto as { constructor?: { name?: string } }).constructor?.name ?? "") };
    const entries: Array<[string, Typed]> = [];
    for (const k of Object.keys(o)) {
      const d = Object.getOwnPropertyDescriptor(o, k);
      if (d && (d.get || d.set)) entries.push([k, { $t: "exotic", kind: "accessor", note: "" }]);
      else entries.push([k, encodeTyped((o as Record<string, unknown>)[k], depth + 1)]);
    }
    return { $t: proto === null ? "nullproto" : "object", entries };
  } catch (e) {
    return { $t: "exotic", kind: "unreadable", note: (e as Error)?.name ?? "error" };
  }
}

/** Decode a typed value; exotic parts decode to a marker object { __exotic: kind }. */
export function decodeTyped(t: unknown): unknown {
  if (t === null || typeof t !== "object") return t;
  if (Array.isArray(t)) {
    const out: unknown[] = [];
    t.forEach((x, i) => {
      if (x && typeof x === "object" && !Array.isArray(x) && (x as Record<string, unknown>)[TAG] === "hole") {
        out.length = i + 1;
        return;
      }
      out[i] = decodeTyped(x);
    });
    return out;
  }
  const o = t as Record<string, unknown>;
  switch (o[TAG]) {
    case "bigint":
      return BigInt(String(o["v"]));
    case "bytes":
      return Buffer.from(String(o["hex"]), "hex");
    case "undefined":
      return undefined;
    case "number": {
      const v = String(o["v"]);
      return v === "-0" ? -0 : v === "NaN" ? NaN : v === "Infinity" ? Infinity : -Infinity;
    }
    case "object":
    case "nullproto": {
      const out: Record<string, unknown> = o[TAG] === "nullproto" ? (Object.create(null) as Record<string, unknown>) : {};
      for (const [k, v] of o["entries"] as Array<[string, unknown]>) {
        Object.defineProperty(out, k, { value: decodeTyped(v), enumerable: true, writable: true, configurable: true });
      }
      return out;
    }
    case "exotic":
      return { __exotic: o["kind"] };
    default:
      throw new Error(`unknown typed-JSON tag ${String(o[TAG])}`);
  }
}

/** JSON text of a typed encoding, with a size cap: above it, only the SHA-256 of the full text is kept. */
export function typedJsonCapped(v: unknown, capBytes: number, sha256: (s: string) => string): { typed: Typed | null; bytes: number; sha256: string; truncated: boolean } {
  const typed = encodeTyped(v);
  const text = JSON.stringify(typed);
  const bytes = Buffer.byteLength(text, "utf8");
  return { typed: bytes <= capBytes ? typed : null, bytes, sha256: sha256(text), truncated: bytes > capBytes };
}
