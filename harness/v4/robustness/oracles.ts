/**
 * Independent reference predicates for the fuzz targets (harness/v4/robustness/fuzz_targets.ts).
 *
 * Written from the specification text (docs/v4/V4_DESIGN.md sections 1, 3, 5 and 6.1, the
 * contract comments of packages/v4/src, DECISIONS D-010) and NOT by calling the package
 * function under test: dates use integer civil-calendar arithmetic (Howard Hinnant's
 * days-from-civil algorithm) instead of the JS Date object; decimal field checks compare digit
 * strings instead of calling BigInt on unbounded input; shapes are checked field by field with
 * explicit character classes. Where the package documents a choice the design text leaves
 * open (for example, shorter epoch windows are well formed; null-prototype objects count as
 * plain), the reference follows the package's documented choice and says so.
 *
 * A disagreement between a target and its reference is a failure of the property; triage
 * decides whether the package or the reference is wrong (docs/v4/ROBUSTNESS.md).
 */

export const P_DEC = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
export const Q_DEC = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
export const P_BIG = BigInt(P_DEC);
export const Q_BIG = BigInt(Q_DEC);

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const LOWER_HEX = "0123456789abcdef";
const DIGITS = "0123456789";

// ------------------------------------------------------------------ calendar (integer arithmetic)

/** Days since 1970-01-01 of a proleptic Gregorian date (Hinnant, days_from_civil). */
export function daysFromCivil(y: number, m: number, d: number): number {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const mp = (m + 9) % 12;
  const doy = Math.floor((153 * mp + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

/** Proleptic Gregorian date of a day count since 1970-01-01 (Hinnant, civil_from_days). */
export function civilFromDays(z0: number): { y: number; m: number; d: number } {
  const z = z0 + 719468;
  const era = Math.floor(z / 146097);
  const doe = z - era * 146097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
  const y = yoe + era * 400;
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const m = mp < 10 ? mp + 3 : mp - 9;
  return { y: m <= 2 ? y + 1 : y, m, d };
}

export function refIsLeap(y: number): boolean {
  return daysFromCivil(y, 3, 1) - daysFromCivil(y, 2, 1) === 29;
}

/** D-010: an integer YYYYMMDD naming a real calendar day in [19000101, 99991231]. */
export function refIsValidYmd(x: unknown): boolean {
  if (typeof x !== "number" || !Number.isInteger(x) || x < 19000101 || x > 99991231) return false;
  const y = Math.floor(x / 10000);
  const m = Math.floor((x % 10000) / 100);
  const d = x % 100;
  if (m < 1 || m > 12 || d < 1) return false;
  const back = civilFromDays(daysFromCivil(y, m, d));
  return back.y === y && back.m === m && back.d === d;
}

/** UTC date (YYYYMMDD) of unix seconds; any finite seconds value (floored to the day). */
export function refUtcDateOf(sec: number): number {
  const { y, m, d } = civilFromDays(Math.floor(sec / 86400));
  return y * 10000 + m * 100 + d;
}

export function refUnixOfUtcDate(date: number): number {
  return daysFromCivil(Math.floor(date / 10000), Math.floor((date % 10000) / 100), date % 100) * 86400;
}

export function refAddDays(date: number, days: number): number {
  const z = daysFromCivil(Math.floor(date / 10000), Math.floor((date % 10000) / 100), date % 100) + days;
  const c = civilFromDays(z);
  return c.y * 10000 + c.m * 100 + c.d;
}

/**
 * Completed years on `today` for a birth on `birth` (both valid YYYYMMDD, today >= birth),
 * with the D-010 rule: a 29 February birth has its anniversary on 1 March in common years.
 */
export function refAge(birth: number, today: number): number {
  const by = Math.floor(birth / 10000);
  const bm = Math.floor((birth % 10000) / 100);
  const bd = birth % 100;
  const ty = Math.floor(today / 10000);
  const anniversaryThisYear = bm === 2 && bd === 29 && !refIsLeap(ty) ? daysFromCivil(ty, 3, 1) : daysFromCivil(ty, bm, bd);
  const t = daysFromCivil(ty, Math.floor((today % 10000) / 100), today % 100);
  return ty - by - (t < anniversaryThisYear ? 1 : 0);
}

/** "age >= threshold on today" for valid dates (false when today is before birth). */
export function refReached(birth: number, threshold: number, today: number): boolean {
  if (today < birth) return false;
  return refAge(birth, today) >= threshold;
}

// ------------------------------------------------------------------ primitives of the statement formats

export function refIsDidPq(v: unknown): boolean {
  if (typeof v !== "string" || !v.startsWith("did:pq:")) return false;
  const s = v.slice(7);
  if (s.length < 1 || s.length > 64) return false;
  for (const c of s) if (!BASE58.includes(c)) return false;
  return true;
}

export function refIsLowerAddress(v: unknown): boolean {
  if (typeof v !== "string" || v.length !== 42 || v[0] !== "0" || v[1] !== "x") return false;
  for (let i = 2; i < 42; i++) if (!LOWER_HEX.includes(v[i] as string)) return false;
  return true;
}

export function refIsLowerHex(v: unknown, len: number): boolean {
  if (typeof v !== "string" || v.length !== len) return false;
  for (let i = 0; i < v.length; i++) if (!LOWER_HEX.includes(v[i] as string)) return false;
  return true;
}

/** Lower-case hex of whole bytes, length within [minChars, maxChars]. */
export function refIsByteHex(v: unknown, minChars: number, maxChars: number): boolean {
  if (typeof v !== "string" || v.length % 2 !== 0 || v.length < minChars || v.length > maxChars) return false;
  for (let i = 0; i < v.length; i++) if (!LOWER_HEX.includes(v[i] as string)) return false;
  return true;
}

export function refIsUint(v: unknown): boolean {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= 9007199254740991;
}

export function refIsSafeInt(v: unknown): boolean {
  return typeof v === "number" && Number.isInteger(v) && Math.abs(v) <= 9007199254740991;
}

/** Canonical decimal (no sign, no leading zero) strictly below the modulus given as a decimal string. */
export function refIsCanonicalDecBelow(v: unknown, modDec: string): boolean {
  if (typeof v !== "string" || v.length === 0) return false;
  for (let i = 0; i < v.length; i++) if (!DIGITS.includes(v[i] as string)) return false;
  if (v.length > 1 && v[0] === "0") return false;
  if (v.length < modDec.length) return true;
  if (v.length > modDec.length) return false;
  return v < modDec; // same length, digit strings compare like numbers
}

export const refIsFieldDec = (v: unknown) => refIsCanonicalDecBelow(v, P_DEC);

export function refIsPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v) as unknown;
  return proto === Object.prototype || proto === null; // the package's documented choice
}

function exactKeys(v: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(v);
  if (own.length !== keys.length) return false;
  for (const k of keys) if (!Object.prototype.hasOwnProperty.call(v, k)) return false;
  return true;
}

// ------------------------------------------------------------------ statements (V4_DESIGN section 3)

export const REF_TYPES = {
  pop: "pqid:did-pop:v2",
  acc: "pqid:accreditation:v2",
  epoch: "pqid:issuer-epoch:v4",
  kem: "pqid:verifier-kem:v1",
} as const;

const DAY = 86400;
const WINDOW_CAP: Record<string, number> = { [REF_TYPES.acc]: 30 * DAY, [REF_TYPES.epoch]: DAY, [REF_TYPES.kem]: 400 * DAY };

/**
 * Reference validity of a statement value. Window rules: notBefore < notAfter and length at
 * most the cap (accreditation 30 days D-014, epoch 24 h = the registry's maxWindow, KEM key 400
 * days). The design text fixes honest epoch windows at exactly 24 h; the package documents that
 * shorter windows are well formed, and the reference follows the package there.
 */
export function refStatementValid(v: unknown, expectedType?: string): boolean {
  if (!refIsPlainObject(v)) return false;
  const t = v["type"];
  if (expectedType !== undefined && t !== expectedType) return false;
  const pos = (x: unknown) => refIsUint(x) && (x as number) > 0;
  const hex64 = (x: unknown) => refIsLowerHex(x, 64);
  switch (t) {
    case REF_TYPES.pop:
      return (
        exactKeys(v, ["type", "did", "controller", "chainId", "registry", "nonce", "origin"]) &&
        refIsDidPq(v["did"]) &&
        refIsLowerAddress(v["controller"]) &&
        pos(v["chainId"]) &&
        refIsLowerAddress(v["registry"]) &&
        hex64(v["nonce"]) &&
        typeof v["origin"] === "string" &&
        v["origin"].length <= 256 &&
        [...v["origin"]].every((c) => c.charCodeAt(0) >= 0x21 && c.charCodeAt(0) <= 0x7e && c.length === 1)
      );
    case REF_TYPES.acc:
      return (
        exactKeys(v, ["type", "issuerDid", "controller", "pkSha3", "chainId", "registry", "serial", "status", "notBefore", "notAfter"]) &&
        refIsDidPq(v["issuerDid"]) &&
        refIsLowerAddress(v["controller"]) &&
        hex64(v["pkSha3"]) &&
        pos(v["chainId"]) &&
        refIsLowerAddress(v["registry"]) &&
        refIsUint(v["serial"]) &&
        (v["status"] === "accredited" || v["status"] === "revoked") &&
        refIsUint(v["notBefore"]) &&
        refIsUint(v["notAfter"]) &&
        refWindowOk(v["notBefore"] as number, v["notAfter"] as number, WINDOW_CAP[t] as number)
      );
    case REF_TYPES.epoch:
      return (
        exactKeys(v, ["type", "issuer", "controller", "chainId", "registry", "epoch", "root", "revRoot", "notBefore", "notAfter", "fromDate", "toDate"]) &&
        refIsDidPq(v["issuer"]) &&
        refIsLowerAddress(v["controller"]) &&
        pos(v["chainId"]) &&
        refIsLowerAddress(v["registry"]) &&
        refIsUint(v["epoch"]) &&
        refIsFieldDec(v["root"]) &&
        refIsFieldDec(v["revRoot"]) &&
        refIsUint(v["notBefore"]) &&
        refIsUint(v["notAfter"]) &&
        refIsValidYmd(v["fromDate"]) &&
        refIsValidYmd(v["toDate"]) &&
        refWindowOk(v["notBefore"] as number, v["notAfter"] as number, WINDOW_CAP[t] as number) &&
        v["fromDate"] === refUtcDateOf(v["notBefore"] as number) &&
        v["toDate"] === refUtcDateOf(v["notAfter"] as number)
      );
    case REF_TYPES.kem:
      return (
        exactKeys(v, ["type", "verifier", "controller", "chainId", "registry", "kemAlg", "kemPkSha3", "notBefore", "notAfter"]) &&
        refIsDidPq(v["verifier"]) &&
        refIsLowerAddress(v["controller"]) &&
        pos(v["chainId"]) &&
        refIsLowerAddress(v["registry"]) &&
        v["kemAlg"] === "ML-KEM-768" &&
        hex64(v["kemPkSha3"]) &&
        refIsUint(v["notBefore"]) &&
        refIsUint(v["notAfter"]) &&
        refWindowOk(v["notBefore"] as number, v["notAfter"] as number, WINDOW_CAP[t] as number)
      );
    default:
      return false;
  }
}

function refWindowOk(nb: number, na: number, cap: number): boolean {
  return nb < na && na - nb <= cap;
}

/** Reference canonical JSON (sorted keys by UTF-16 code units, no whitespace, JSON.stringify scalars). */
export function refCanonical(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite number");
    return Object.is(v, -0) ? "0" : JSON.stringify(v);
  }
  if (typeof v === "boolean") return v ? "true" : "false";
  if (Array.isArray(v)) return "[" + v.map(refCanonical).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v as object).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + refCanonical((v as Record<string, unknown>)[k])).join(",") + "}";
  }
  throw new Error(`not JSON data: ${typeof v}`);
}

/** Strict UTF-8 decoding: null on any invalid sequence (overlong, surrogate code points, truncation). */
export function refStrictUtf8(bytes: Uint8Array): string | null {
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i] as number;
    let cp: number;
    let n: number;
    if (b0 < 0x80) {
      cp = b0;
      n = 1;
    } else if (b0 >= 0xc2 && b0 <= 0xdf) {
      cp = b0 & 0x1f;
      n = 2;
    } else if (b0 >= 0xe0 && b0 <= 0xef) {
      cp = b0 & 0x0f;
      n = 3;
    } else if (b0 >= 0xf0 && b0 <= 0xf4) {
      cp = b0 & 0x07;
      n = 4;
    } else return null;
    if (i + n > bytes.length) return null;
    for (let k = 1; k < n; k++) {
      const b = bytes[i + k] as number;
      if ((b & 0xc0) !== 0x80) return null;
      cp = (cp << 6) | (b & 0x3f);
    }
    if ((n === 3 && cp < 0x800) || (n === 4 && (cp < 0x10000 || cp > 0x10ffff)) || (cp >= 0xd800 && cp <= 0xdfff)) return null;
    out += String.fromCodePoint(cp);
    i += n;
  }
  return out;
}

/** Reference of tryParseStatement: strict UTF-8, JSON, valid, and bytes equal to the canonical form. */
export function refParseStatement(bytes: Uint8Array, expectedType?: string): boolean {
  const text = refStrictUtf8(bytes);
  if (text === null) return false;
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return false;
  }
  if (!refStatementValid(v, expectedType)) return false;
  return Buffer.from(refCanonical(v), "utf8").equals(Buffer.from(bytes));
}

// ------------------------------------------------------------------ session messages (V4_DESIGN section 5)

export const REF_MAX_PRESENTATION_BYTES = 1 << 20;

export function refRequestValid(v: unknown, typeIdMax = 256): boolean {
  if (!refIsPlainObject(v)) return false;
  if (!exactKeys(v, ["type", "sessionId", "verifierDid", "verifierController", "chainId", "policy", "issuedAt"])) return false;
  const p = v["policy"];
  if (!refIsPlainObject(p) || !exactKeys(p, ["predicate", "threshold", "typeId", "today"])) return false;
  return (
    v["type"] === "pqid:request:v4" &&
    refIsLowerHex(v["sessionId"], 64) &&
    refIsDidPq(v["verifierDid"]) &&
    refIsLowerAddress(v["verifierController"]) &&
    refIsUint(v["chainId"]) &&
    (v["chainId"] as number) > 0 &&
    refIsUint(v["issuedAt"]) &&
    (p["predicate"] === "age_gte" || p["predicate"] === "age_lt") &&
    refIsUint(p["threshold"]) &&
    (p["threshold"] as number) <= 255 &&
    typeof p["typeId"] === "string" &&
    p["typeId"].length >= 1 &&
    p["typeId"].length <= typeIdMax &&
    refIsValidYmd(p["today"])
  );
}

export function refReplyValid(v: unknown): boolean {
  if (!refIsPlainObject(v) || !exactKeys(v, ["type", "sessionId", "ct", "box"])) return false;
  return (
    v["type"] === "pqid:reply:v4" &&
    refIsLowerHex(v["sessionId"], 64) &&
    refIsLowerHex(v["ct"], 2 * 1088) &&
    refIsByteHex(v["box"], 2 * 16, 2 * (REF_MAX_PRESENTATION_BYTES + 16))
  );
}

/**
 * Nesting depth of JSON data: a primitive is 0, an object or array is 1 + its deepest child
 * (an empty one is 1). Computes the full depth with an explicit stack (no recursion, so a
 * hostile depth cannot overflow the harness's own stack); the package instead stops at a
 * threshold (session.ts jsonDepthExceeds).
 */
export function refDepth(v: unknown): number {
  let best = 0;
  const stack: Array<[unknown, number]> = [[v, 0]];
  while (stack.length > 0) {
    const [x, d] = stack.pop() as [unknown, number];
    if (x === null || typeof x !== "object") {
      if (d > best) best = d;
      continue;
    }
    const kids = Array.isArray(x) ? x : Object.values(x as object);
    if (kids.length === 0 && d + 1 > best) best = d + 1;
    for (const c of kids) stack.push([c, d + 1]);
  }
  return best;
}

// ------------------------------------------------------------------ presentation shape (V4_DESIGN 5 and 6.1)

const EPOCH_FIELDS = ["chainId", "controller", "epoch", "fromDate", "issuer", "notAfter", "notBefore", "registry", "revRoot", "root", "signature", "toDate"];

/**
 * Reference of the verifier's `shape` check for JSON data: exactly the five presentation
 * fields; 8 canonical decimal public signals below p; issuerDid did:pq; issuerController a
 * lower-case address; epochStatement with exactly the epoch fields plus signature, integer
 * numbers (sign not checked by shape), valid dates, canonical field decimals, a 4,840-hex
 * signature, lower-case addresses and a did:pq issuer; proof with exactly pi_a, pi_b, pi_c,
 * protocol "groth16", curve "bn128", coordinates canonical decimals below the base-field
 * modulus q (pi_a and pi_c of 3, pi_b of 3 x 2).
 */
export function refPresentationShapeOk(x: unknown): boolean {
  if (!refIsPlainObject(x) || !exactKeys(x, ["epochStatement", "issuerController", "issuerDid", "proof", "publicSignals"])) return false;
  const s = x["publicSignals"];
  if (!Array.isArray(s) || s.length !== 8 || !s.every(refIsFieldDec)) return false;
  if (!refIsDidPq(x["issuerDid"]) || !refIsLowerAddress(x["issuerController"])) return false;
  const st = x["epochStatement"];
  if (!refIsPlainObject(st) || !exactKeys(st, EPOCH_FIELDS)) return false;
  for (const k of ["epoch", "chainId", "notBefore", "notAfter", "fromDate", "toDate"]) if (!refIsSafeInt(st[k])) return false;
  if (!refIsValidYmd(st["fromDate"]) || !refIsValidYmd(st["toDate"])) return false;
  if (!refIsFieldDec(st["root"]) || !refIsFieldDec(st["revRoot"])) return false;
  if (!refIsLowerHex(st["signature"], 4840)) return false;
  if (!refIsLowerAddress(st["registry"]) || !refIsLowerAddress(st["controller"]) || !refIsDidPq(st["issuer"])) return false;
  const pr = x["proof"];
  if (!refIsPlainObject(pr) || !exactKeys(pr, ["curve", "pi_a", "pi_b", "pi_c", "protocol"])) return false;
  if (pr["protocol"] !== "groth16" || pr["curve"] !== "bn128") return false;
  const coords = (a: unknown, n: number) => Array.isArray(a) && a.length === n && a.every((c) => refIsCanonicalDecBelow(c, Q_DEC));
  if (!coords(pr["pi_a"], 3) || !coords(pr["pi_c"], 3)) return false;
  const b = pr["pi_b"];
  return Array.isArray(b) && b.length === 3 && b.every((row) => coords(row, 2));
}

// ------------------------------------------------------------------ circuit input (V4_DESIGN section 2)

export const REF_PUBLIC_ORDER = ["issuerKeyHash", "revRoot", "policyHash", "nonce", "stmtCode", "issRoot", "epochFromDate", "epochToDate"] as const;

/** A field element given as bigint or safe integer, as its canonical decimal; null when not one. */
export function refFieldLike(x: unknown): string | null {
  let v: bigint;
  if (typeof x === "bigint") v = x;
  else if (typeof x === "number" && Number.isInteger(x) && Math.abs(x) <= 9007199254740991) v = BigInt(x);
  else return null;
  return v >= 0n && v < P_BIG ? v.toString() : null;
}

// ------------------------------------------------------------------ circuit relation model (R4)

export interface RelationModelInput {
  /** Every circuit input as a bigint (decimal strings already parsed); values may be any integer >= 0. */
  [signal: string]: bigint | bigint[];
}

export interface RelationVerdict {
  /** The R1CS of R4 is satisfiable with these inputs (every check holds). */
  satisfiable: boolean;
  /** Constraint groups whose check fails (G-names of the circuit). */
  failing: string[];
}

/**
 * The relation R4 of circuits/credential_auth_v4.circom as integer arithmetic over F_p, from the
 * design text and the circuit's group comments: Num2Bits(n) needs x < 2^n; LessThan(n) is
 * evaluated as the circuit does it (bit n of x + 2^n - y mod p, with Num2Bits(n+1) failing
 * when that value is >= 2^(n+1)). Hash functions are passed in (Poseidon of circomlibjs).
 */
export function relationR4(inp: RelationModelInput, h: (xs: bigint[]) => bigint): RelationVerdict {
  const g = (k: string) => {
    const v = inp[k];
    if (typeof v !== "bigint") throw new Error(`model input ${k} missing`);
    return ((v % P_BIG) + P_BIG) % P_BIG;
  };
  const arr = (k: string) => {
    const v = inp[k];
    if (!Array.isArray(v)) throw new Error(`model input ${k} missing`);
    return v.map((x) => ((x % P_BIG) + P_BIG) % P_BIG);
  };
  const failing: string[] = [];
  const fits = (x: bigint, n: number) => x < 1n << BigInt(n);
  const lessThan = (a: bigint, b: bigint, n: number): bigint | null => {
    const x = (((a + (1n << BigInt(n)) - b) % P_BIG) + P_BIG) % P_BIG;
    if (!fits(x, n + 1)) return null; // Num2Bits(n+1) has no solution
    return 1n - ((x >> BigInt(n)) & 1n);
  };
  const merkle = (leaf: bigint, index: bigint, path: bigint[]): bigint | null => {
    if (!fits(index, path.length)) return null;
    let cur = leaf;
    for (let i = 0; i < path.length; i++) {
      const bit = (index >> BigInt(i)) & 1n;
      cur = bit === 0n ? h([cur, path[i] as bigint]) : h([path[i] as bigint, cur]);
    }
    return cur;
  };

  const holderCommit = h([g("holderSecret")]);
  const leaf = h([1004n, g("issuerKeyHash"), g("credIDHi"), g("credIDLo"), holderCommit, g("birthDate"), g("expiryDate"), g("credType")]);
  const issRoot = merkle(leaf, g("issLeafIndex"), arr("issPathElements"));
  if (issRoot === null) failing.push("G04_issuance_membership(index range)");
  else if (issRoot !== g("issRoot")) failing.push("G04_issuance_membership");
  if (!fits(g("credIDHi"), 128) || !fits(g("credIDLo"), 128)) failing.push("G05_revkey(limb range)");
  const revKey = (g("credIDHi") << 123n) + (g("credIDLo") >> 5n);
  const revLeaf = h([1007n, g("revLowValue"), g("revLowNext")]);
  const revRoot = merkle(revLeaf, g("revLowIndex"), arr("revLowPath"));
  if (revRoot === null) failing.push("G06_rev_low_membership(index range)");
  else if (revRoot !== g("revRoot")) failing.push("G06_rev_low_membership");
  const below = lessThan(g("revLowValue"), revKey % P_BIG, 252);
  const above = lessThan(revKey % P_BIG, g("revLowNext"), 252);
  if (below !== 1n || above !== 1n) failing.push("G07_rev_bracket");
  if (h([1006n, g("predicateCode"), g("threshold"), g("today"), g("requiredType")]) !== g("policyHash")) failing.push("G08_policy_hash");
  const pc = g("predicateCode");
  if (pc !== 1n && pc !== 2n) failing.push("G09_predicate_code");
  const thr = g("threshold");
  if (![13n, 14n, 15n, 16n, 18n, 21n, 65n].includes(thr)) failing.push("G10_standard_threshold");
  const ranges = [fits(g("birthDate"), 27), fits(g("expiryDate"), 27), fits(g("today"), 27), fits(g("epochFromDate"), 27), fits(g("epochToDate"), 27), fits(thr, 8)];
  const rangesOk = ranges.every(Boolean);
  if (!rangesOk) failing.push("G11_ranges");
  // LessEqThan(n)(a, b) = LessThan(n)(a, b + 1)
  const reached = lessThan((g("birthDate") + 10000n * thr) % P_BIG, (g("today") + 1n) % P_BIG, 28);
  if (reached === null || reached !== (((2n - pc) % P_BIG) + P_BIG) % P_BIG) failing.push("G12_age");
  const notExpired = lessThan(g("today"), (g("expiryDate") + 1n) % P_BIG, 27);
  if (notExpired !== 1n) failing.push("G13_expiry");
  if (g("credType") !== g("requiredType")) failing.push("G14_type");
  const afterFrom = lessThan(g("epochFromDate"), (g("today") + 1n) % P_BIG, 27);
  const beforeTo = lessThan(g("today"), (g("epochToDate") + 1n) % P_BIG, 27);
  if (afterFrom !== 1n || beforeTo !== 1n) failing.push("G15_epoch_window");
  if (h([4n, g("domainTag")]) !== g("stmtCode")) failing.push("G16_stmt");
  return { satisfiable: failing.length === 0, failing };
}
