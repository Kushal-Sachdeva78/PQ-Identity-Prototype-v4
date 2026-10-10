import nodeCrypto from "node:crypto";
import type { Poseidon } from "circomlibjs";
import { canonicalJsonBytes } from "@pqid/common/hash";
import { poseidonBig } from "@pqid/common/encoding";
import { isValidYmd, utcDateOf, unixOfUtcDate, addDays, acceptableTodays, predicateHolds, ageOn } from "@pqid/v4/dates";
import { getPoseidon, credTypeField, fieldFrom31Bytes, policyHashV4, revKeyFromCredId, fieldDec, type PredicateName } from "@pqid/v4/encoding";
import {
  validateStatement,
  tryParseStatement,
  parseStatement,
  statementBytes,
  detachSignature,
  verifyStatement,
  signStatement,
  STATEMENT_TYPES,
  type StatementType,
} from "@pqid/v4/statements";
import {
  requestShapeErrors,
  isProofRequestV4,
  replyShapeErrors,
  isSessionReplyV4,
  newRequest,
  jsonDepthExceeds,
  verifierOpenReply,
  VerifierSessionStore,
  walletOpenSession,
  walletSealReply,
  MAX_PRESENTATION_DEPTH,
  type NewRequestParams,
} from "@pqid/v4/session";
import { presentationShapeError } from "@pqid/v4/verifier";
import { buildCircuitInputV4, type PublicInputsV4, type PrivateInputsV4 } from "@pqid/v4/witness";
import {
  mlDsaKeygen,
  mlDsaSign,
  mlDsaVerify,
  mlDsaVerifyKey,
  mlDsaImportPublicKey,
  mlKemKeygen,
  mlKemEncaps,
  mlKemDecaps,
  aes256gcmSeal,
  aes256gcmOpen,
  hkdfSha256Extract,
  hkdfSha256Expand,
  type MlDsaKeyPair,
  type MlKemKeyPair,
} from "@pqid/v4/pqc";
import { IndexedMerkleTree } from "@pqid/v4/imt";
import { parsePublication } from "@pqid/v4/published";
import { Rng } from "./rng.ts";
import { mutateBytes, mutateJsonText, mutateValue, utf8Hazard, exotic, hugeDigits, setU32be, cloneJson, copyBytes, type Mutated } from "./mutators.ts";
import * as G from "./valid_gen.ts";
import {
  P_BIG,
  refIsValidYmd,
  refUtcDateOf,
  refUnixOfUtcDate,
  refAddDays,
  refAge,
  refReached,
  refStatementValid,
  refParseStatement,
  refCanonical,
  refStrictUtf8,
  refRequestValid,
  refReplyValid,
  refDepth,
  refPresentationShapeOk,
  refIsFieldDec,
  refFieldLike,
  daysFromCivil,
  REF_PUBLIC_ORDER,
} from "./oracles.ts";
import { Verdict, errClass, errMsg, timedCall, timedCallAsync, type FuzzCase, type FuzzTarget, type CaseOutcome } from "./fuzz_types.ts";

/**
 * Pure fuzz targets: every untrusted-input entry point of packages/v4 that runs without a chain
 * (DECISIONS D-034, docs/v4/ROBUSTNESS.md). Chain-backed targets are in fuzz_chain.ts.
 *
 * Each target generates a case from its own seeded stream (rng.ts), calls the entry points and
 * checks the property against the references in oracles.ts. A disagreement is a violation; an
 * observation is a fact worth reporting that is not a property failure (for example, a
 * non-canonical encoding that the code accepts by design or without a stated rule).
 */

let poseidonP: Poseidon | null = null;
async function pos(): Promise<Poseidon> {
  poseidonP ??= await getPoseidon();
  return poseidonP;
}
function P(): Poseidon {
  if (!poseidonP) throw new Error("poseidon not initialised (target setup)");
  return poseidonP;
}

const sameJson = (a: unknown, b: unknown): boolean => {
  try {
    return refCanonical(a) === refCanonical(b);
  } catch {
    return false;
  }
};

/**
 * The reference canonical text of a parsed value, or null when it has none (a non-finite number:
 * an overflowing literal such as 1e400 parses to Infinity). A value with no canonical text is not
 * canonical, so a caller comparing it with a plaintext decides "malformed" (fz1 T-open oracle
 * defect; docs/v4/ROBUSTNESS.md, Deviations, 2026-10-03). refCanonical itself keeps its throw.
 */
const refCanonicalOrNull = (v: unknown): string | null => {
  try {
    return refCanonical(v);
  } catch {
    return null;
  }
};

const EXOTIC_FAMILY = "exotic";

/** Plan-based targets keep a sub-seed: run() redraws the same mutations from it. */
function plan(rng: Rng, family: string, input: unknown = null): FuzzCase {
  return { family, input, recipe: [], meta: { subSeed: rng.u32() } };
}
function subRng(c: FuzzCase): Rng {
  return new Rng(Number(c.meta?.["subSeed"] ?? 0));
}

// =====================================================================================
// T-dates
// =====================================================================================

const tDates: FuzzTarget = {
  id: "T-dates",
  title: "date encoding and age arithmetic",
  entryPoints: ["isValidYmd", "utcDateOf", "unixOfUtcDate", "addDays", "acceptableTodays", "predicateHolds", "ageOn"],
  kind: "pure",
  budget: 200_000,
  smokeBudget: 2_000,
  property:
    "isValidYmd equals an integer civil-calendar reference (D-010 range); utcDateOf, unixOfUtcDate and addDays equal the reference; unixOfUtcDate and addDays throw Error exactly on invalid dates; acceptableTodays holds exactly the UTC dates of now and now - skew, sorted, never a date after today; predicateHolds equals calendar age with the 29 February rule (anniversary on 1 March in common years), ageOn equals completed years",
  documentedErrors: ["Error"],
  gen(rng) {
    const fam = rng.weighted<string>([
      [3, "isValidYmd"],
      [2, "utcDateOf"],
      [2, "addDays"],
      [1, "unixOfUtcDate"],
      [2, "acceptableTodays"],
      [4, "predicate"],
    ]);
    switch (fam) {
      case "isValidYmd": {
        const base = G.ymd(rng);
        const x = rng.weighted<unknown>([
          [3, base],
          [2, base + rng.pick([1, -1, 30, -30, 100, -100, 70, 9000])],
          [1, Math.floor(base / 100) * 100 + rng.pick([0, 29, 30, 31, 32, 99])],
          [1, Math.floor(base / 10000) * 10000 + rng.pick([0, 1300, 229, 230, 431, 631, 931, 1131])],
          [1, rng.pick([19000100, 18991231, 100000101, 0, -20240101, 2.5e7 + 0.5, NaN, Infinity, 2 ** 53, "20240101", null, 20240101n])],
        ]);
        return { family: fam, input: { x }, recipe: [] };
      }
      case "utcDateOf":
        return { family: fam, input: { sec: rng.weighted<number>([
          [4, G.unixTime(rng)],
          [1, daysFromCivil(1900, 1, 1) * 86400 + rng.int(-86400, 86400)],
          [1, daysFromCivil(9999, 12, 31) * 86400 + rng.int(0, 86399)],
          [1, rng.int(-2e9, 0)],
        ]) }, recipe: [] };
      case "addDays":
        return { family: fam, input: { date: rng.bool(0.9) ? G.ymd(rng) : rng.pick([20230229, 20241301, 0, 19000100]), days: rng.weighted<number>([
          [3, rng.int(-400, 400)],
          [1, rng.int(-1_000_000, 1_000_000)],
          [1, rng.pick([0, 1, -1, 365, 366, -365, 146097])],
        ]) }, recipe: [] };
      case "unixOfUtcDate":
        return { family: fam, input: { date: rng.bool(0.8) ? G.ymd(rng) : rng.pick([20230229, 20240431, 99991232, 18991231, 1.5, "20240101"]) }, recipe: [] };
      case "acceptableTodays": {
        const now = rng.weighted<number>([
          [3, G.unixTime(rng)],
          [2, daysFromCivil(rng.int(1971, 2099), rng.int(1, 12), 1) * 86400 + rng.int(0, 900)],
        ]);
        return { family: fam, input: { now, skew: rng.pick([0, 1, 299, 300, 301, 3600, rng.int(0, 86399)]) }, recipe: [] };
      }
      default: {
        let birth = G.ymd(rng);
        if (birth > 99000101) birth = 19840315;
        const thr = rng.weighted<number>([
          [4, rng.pick([13, 14, 15, 16, 18, 21, 65])],
          [2, rng.int(0, 120)],
          [1, rng.int(0, 255)],
        ]);
        const anniv = birth + 10000 * thr;
        // the anniversary itself, or 28 February when it is 29 February of a common year
        const around = anniv <= 99991231 && refIsValidYmd(anniv) ? anniv : anniv <= 99991231 && anniv % 10000 === 229 ? anniv - 1 : G.ymd(rng);
        let today = rng.weighted<number>([
          [3, refAddDays(around, rng.pick([-1, 0, 1, 2]))],
          [1, refAddDays(around, rng.int(-400, 400))],
          [1, G.ymd(rng)],
        ]);
        if (!refIsValidYmd(today)) today = 20260927;
        return { family: fam, input: { birth, threshold: thr, today, code: rng.pick([1, 2] as const) }, recipe: [] };
      }
    }
  },
  run(c) {
    const v = new Verdict();
    const i = c.input as Record<string, unknown>;
    switch (c.family) {
      case "isValidYmd": {
        const r = timedCall(() => isValidYmd(i["x"]));
        v.callMs = r.ms;
        if (r.error) v.thrown(r.error, [], "isValidYmd");
        else v.check(r.value === refIsValidYmd(i["x"]), "isValidYmd=ref", `isValidYmd(${String(i["x"])}) = ${String(r.value)}`);
        v.outcome = r.value ? "valid" : "invalid";
        break;
      }
      case "utcDateOf": {
        const sec = i["sec"] as number;
        const r = timedCall(() => utcDateOf(sec));
        v.callMs = r.ms;
        if (r.error) v.thrown(r.error, [], "utcDateOf");
        else v.check(r.value === refUtcDateOf(sec), "utcDateOf=ref", `utcDateOf(${sec}) = ${String(r.value)}, reference ${refUtcDateOf(sec)}`);
        break;
      }
      case "addDays": {
        const date = i["date"] as number;
        const days = i["days"] as number;
        const r = timedCall(() => addDays(date, days));
        v.callMs = r.ms;
        if (!refIsValidYmd(date)) {
          v.check(r.error !== undefined, "addDays:throwsOnInvalid", `addDays(${date}) returned ${String(r.value)}`);
          if (r.error) v.thrown(r.error, tDates.documentedErrors, "addDays");
          v.outcome = "invalid-date";
        } else if (r.error) v.thrown(r.error, [], "addDays");
        else v.check(r.value === refAddDays(date, days), "addDays=ref", `addDays(${date}, ${days}) = ${String(r.value)}, reference ${refAddDays(date, days)}`);
        break;
      }
      case "unixOfUtcDate": {
        const date = i["date"] as number;
        const r = timedCall(() => unixOfUtcDate(date));
        v.callMs = r.ms;
        if (!refIsValidYmd(date)) {
          v.check(r.error !== undefined, "unixOfUtcDate:throwsOnInvalid", `unixOfUtcDate(${String(date)}) returned ${String(r.value)}`);
          if (r.error) v.thrown(r.error, tDates.documentedErrors, "unixOfUtcDate");
          v.outcome = "invalid-date";
        } else if (r.error) v.thrown(r.error, [], "unixOfUtcDate");
        else v.check(r.value === refUnixOfUtcDate(date), "unixOfUtcDate=ref", `unixOfUtcDate(${date}) = ${String(r.value)}`);
        break;
      }
      case "acceptableTodays": {
        const now = i["now"] as number;
        const skew = i["skew"] as number;
        const r = timedCall(() => acceptableTodays(now, skew));
        v.callMs = r.ms;
        if (r.error) {
          v.thrown(r.error, [], "acceptableTodays");
          break;
        }
        const got = r.value as number[];
        const today = refUtcDateOf(now);
        const want = [...new Set([refUtcDateOf(now - skew), today])].sort((a, b) => a - b);
        v.check(JSON.stringify(got) === JSON.stringify(want), "acceptableTodays=ref", `acceptableTodays(${now}, ${skew}) = ${JSON.stringify(got)}, reference ${JSON.stringify(want)}`);
        v.check(got.every((d) => d <= today), "acceptableTodays:noFutureDate", `contains a date after ${today}: ${JSON.stringify(got)}`);
        v.outcome = got.length === 2 ? "two-dates" : "one-date";
        break;
      }
      default: {
        const birth = i["birth"] as number;
        const thr = i["threshold"] as number;
        const today = i["today"] as number;
        const code = i["code"] as 1 | 2;
        const r = timedCall(() => predicateHolds(code, birth, thr, today));
        v.callMs = r.ms;
        if (r.error) {
          v.thrown(r.error, [], "predicateHolds");
          break;
        }
        const reached = refReached(birth, thr, today);
        v.check(r.value === (code === 1 ? reached : !reached), "predicateHolds=calendarAge", `predicateHolds(${code}, ${birth}, ${thr}, ${today}) = ${String(r.value)}, calendar age ${today >= birth ? refAge(birth, today) : "negative"}`);
        if (today >= birth) {
          const a = ageOn(birth, today);
          v.check(a === refAge(birth, today), "ageOn=calendarAge", `ageOn(${birth}, ${today}) = ${a}, reference ${refAge(birth, today)}`);
        }
        v.outcome = r.value ? "holds" : "fails";
        if (birth % 10000 === 229) v.outcome += "-feb29";
      }
    }
    return v.done();
  },
};

// =====================================================================================
// T-encoding
// =====================================================================================

const tEncoding: FuzzTarget = {
  id: "T-encoding",
  title: "field encodings",
  entryPoints: ["credTypeField", "fieldFrom31Bytes", "policyHashV4", "revKeyFromCredId", "fieldDec"],
  kind: "pure",
  budget: 100_000,
  smokeBudget: 1_000,
  property:
    "outputs are field elements (< p); revKey < 2^251 and equals hi * 2^123 + floor(lo / 32) of the credID limbs; fieldFrom31Bytes equals the big-endian integer of exactly 31 bytes; each throws Error exactly on its documented bad input (empty or non-string typeId, length other than 31 or 32, threshold outside [0, 255], invalid date, unknown predicate, value outside [0, p)); typeIds that differ only in lone surrogates are recorded as an observation when they collide",
  documentedErrors: ["Error"],
  async setup() {
    await pos();
  },
  gen(rng) {
    const fam = rng.weighted<string>([
      [3, "credType"],
      [2, "from31"],
      [3, "policy"],
      [2, "revKey"],
      [1, "fieldDec"],
    ]);
    switch (fam) {
      case "credType": {
        const base = rng.pick(["pqid:type:age-credential:v1", "t", "x".repeat(rng.int(1, 300)), "é漢😀", ""]);
        const m = rng.bool(0.6) ? mutateStringSafe(rng, base) : { value: base, ops: [] as string[] };
        const typeId = rng.bool(0.05) ? rng.pick<unknown>([null, 5, ["a"], undefined]) : m.value;
        return { family: fam, input: { typeId }, recipe: m.ops };
      }
      case "from31":
        return { family: fam, input: { b: rng.bytes(rng.weighted<number>([
          [6, 31],
          [1, 30],
          [1, 32],
          [1, 0],
          [1, rng.int(0, 64)],
        ])) }, recipe: [] };
      case "policy": {
        const predicate = rng.weighted<unknown>([
          [8, rng.pick(["age_gte", "age_lt"])],
          [1, rng.pick(["AGE_GTE", "age_gt", "", 1, null])],
        ]);
        const threshold = rng.weighted<unknown>([
          [6, rng.pick([13, 14, 15, 16, 18, 21, 65])],
          [2, rng.int(0, 255)],
          [1, rng.pick([-1, 256, 1.5, NaN, 2 ** 53, "18", 18n])],
        ]);
        const today = rng.weighted<unknown>([
          [8, G.ymd(rng)],
          [1, rng.pick([20230229, 20241301, 0, "20240101"])],
        ]);
        const requiredType = rng.weighted<bigint>([
          [8, G.fieldElement(rng)],
          [1, P_BIG + G.fieldElement(rng)],
        ]);
        return { family: fam, input: { predicate, threshold, today, requiredType }, recipe: [] };
      }
      case "revKey":
        return { family: fam, input: { credId: rng.bool(0.9) ? rng.bytes(32) : rng.bytes(rng.pick([0, 31, 33, 64])) }, recipe: [] };
      default:
        return { family: fam, input: { x: rng.weighted<bigint>([
          [3, G.fieldElement(rng)],
          [1, P_BIG + BigInt(rng.int(0, 5))],
          [1, -BigInt(rng.int(1, 5))],
          [1, P_BIG - 1n],
        ]) }, recipe: [] };
    }
  },
  run(c) {
    const v = new Verdict();
    const i = c.input as Record<string, unknown>;
    const p = P();
    switch (c.family) {
      case "credType": {
        const t = i["typeId"];
        const r = timedCall(() => credTypeField(p, t as string));
        v.callMs = r.ms;
        const shouldThrow = typeof t !== "string" || t.length === 0;
        if (shouldThrow) {
          v.check(r.error !== undefined, "credTypeField:throwsOnBadTypeId", `credTypeField(${JSON.stringify(t)}) returned`);
          if (r.error) v.thrown(r.error, tEncoding.documentedErrors, "credTypeField");
          v.outcome = "refused";
          break;
        }
        if (r.error) {
          v.thrown(r.error, [], "credTypeField");
          break;
        }
        v.check(typeof r.value === "bigint" && r.value >= 0n && r.value < P_BIG, "credTypeField:inField", `credTypeField = ${String(r.value)}`);
        const s = t as string;
        const wf = (s as unknown as { toWellFormed(): string }).toWellFormed();
        if (wf !== s) {
          const other = credTypeField(p, wf);
          if (other === r.value) v.observe("credType:loneSurrogateCollision", `typeIds ${JSON.stringify(s.slice(0, 40))} and its well-formed form map to the same credType field`);
        }
        v.outcome = "ok";
        break;
      }
      case "from31": {
        const b = i["b"] as Buffer;
        const r = timedCall(() => fieldFrom31Bytes(b));
        v.callMs = r.ms;
        if (b.length !== 31) {
          v.check(r.error !== undefined, "fieldFrom31Bytes:throwsOnLength", `length ${b.length} returned`);
          if (r.error) v.thrown(r.error, tEncoding.documentedErrors, "fieldFrom31Bytes");
          v.outcome = "refused";
        } else if (r.error) v.thrown(r.error, [], "fieldFrom31Bytes");
        else {
          const want = BigInt("0x" + b.toString("hex"));
          v.check(r.value === want && want < 1n << 248n, "fieldFrom31Bytes=bigEndian", `got ${String(r.value)}`);
        }
        break;
      }
      case "policy": {
        const { predicate, threshold, today, requiredType } = i as { predicate: unknown; threshold: unknown; today: unknown; requiredType: bigint };
        const r = timedCall(() => policyHashV4(p, { predicate: predicate as PredicateName, threshold: threshold as number, today: today as number, requiredType }));
        v.callMs = r.ms;
        const ok =
          (predicate === "age_gte" || predicate === "age_lt") &&
          typeof threshold === "number" &&
          Number.isInteger(threshold) &&
          threshold >= 0 &&
          threshold <= 255 &&
          refIsValidYmd(today);
        if (!ok) {
          v.check(r.error !== undefined, "policyHashV4:throwsOnBadInput", `returned for ${JSON.stringify({ predicate, threshold: String(threshold), today: String(today) })}`);
          if (r.error) v.thrown(r.error, tEncoding.documentedErrors, "policyHashV4");
          v.outcome = "refused";
          break;
        }
        if (r.error) {
          v.thrown(r.error, [], "policyHashV4");
          break;
        }
        v.check(typeof r.value === "bigint" && r.value < P_BIG, "policyHashV4:inField", String(r.value));
        if (requiredType >= P_BIG) {
          const alias = policyHashV4(p, { predicate: predicate as PredicateName, threshold: threshold as number, today: today as number, requiredType: requiredType - P_BIG });
          if (alias === r.value) v.observe("policyHash:requiredTypeAliasModP", "requiredType and requiredType - p give the same policyHash (Poseidon reduces mod p; requiredType always comes from credTypeField, so not reachable from a request)");
        }
        v.outcome = "ok";
        break;
      }
      case "revKey": {
        const id = i["credId"] as Buffer;
        const r = timedCall(() => revKeyFromCredId(id));
        v.callMs = r.ms;
        if (id.length !== 32) {
          v.check(r.error !== undefined, "revKeyFromCredId:throwsOnLength", `length ${id.length} returned`);
          if (r.error) v.thrown(r.error, tEncoding.documentedErrors, "revKeyFromCredId");
          v.outcome = "refused";
          break;
        }
        if (r.error) {
          v.thrown(r.error, [], "revKeyFromCredId");
          break;
        }
        const hi = BigInt("0x" + id.subarray(0, 16).toString("hex"));
        const lo = BigInt("0x" + id.subarray(16).toString("hex"));
        const want = hi * 2n ** 123n + lo / 32n;
        v.check(r.value === want && want < 2n ** 251n, "revKey=limbFormula", `got ${String(r.value)}`);
        break;
      }
      default: {
        const x = i["x"] as bigint;
        const r = timedCall(() => fieldDec(x));
        v.callMs = r.ms;
        if (x < 0n || x >= P_BIG) {
          v.check(r.error !== undefined, "fieldDec:throwsOutOfRange", `fieldDec(${x}) returned`);
          if (r.error) v.thrown(r.error, tEncoding.documentedErrors, "fieldDec");
        } else if (r.error) v.thrown(r.error, [], "fieldDec");
        else v.check(r.value === x.toString(), "fieldDec=decimal", String(r.value));
      }
    }
    return v.done();
  },
};

function mutateStringSafe(rng: Rng, s: string): Mutated<string> {
  const loneSurrogate = rng.bool(0.3);
  if (loneSurrogate) {
    const pos = s.length === 0 ? 0 : rng.int(0, s.length);
    const ch = rng.pick(["\ud800", "\udbff", "\udc00", "\udfff"]);
    return { value: s.slice(0, pos) + ch + s.slice(pos), ops: [`insert lone surrogate U+${ch.charCodeAt(0).toString(16)} at ${pos}`] };
  }
  let v = s;
  const ops: string[] = [];
  const n = rng.int(1, 3);
  for (let k = 0; k < n; k++) {
    const pos = v.length === 0 ? 0 : rng.int(0, v.length);
    const ch = rng.pick(["\u0000", "�", "﻿", "é", "\u{1f600}", "A", ":"]);
    v = v.slice(0, pos) + ch + v.slice(pos);
    ops.push(`insert U+${ch.codePointAt(0)?.toString(16)} at ${pos}`);
  }
  return { value: v, ops };
}

// =====================================================================================
// T-stmt-json and T-stmt-bytes
// =====================================================================================

const TYPE_LIST = STATEMENT_TYPES as readonly string[];

function genStatementValue(rng: Rng): FuzzCase {
  const fam = rng.weighted<string>([
    [3, "valid"],
    [6, "mutated"],
    [1, "tree"],
    [1, EXOTIC_FAMILY],
  ]);
  const s = G.statement(rng);
  const expected = rng.weighted<string | undefined>([
    [3, undefined],
    [2, s["type"] as string],
    [1, rng.pick(TYPE_LIST)],
  ]);
  if (fam === "valid") return { family: fam, input: s, recipe: [], meta: { expected } };
  if (fam === "tree") return { family: fam, input: G.jsonTree(rng, 4), recipe: [], meta: { expected } };
  if (fam === EXOTIC_FAMILY) {
    const e = exotic(rng, s);
    return { family: fam, input: e.value, recipe: e.ops, meta: { expected } };
  }
  const m = mutateValue(rng, s, rng.int(1, 3));
  return { family: fam, input: m.value, recipe: m.ops, meta: { expected } };
}

const tStmtJson: FuzzTarget = {
  id: "T-stmt-json",
  title: "statement validation (values)",
  entryPoints: ["validateStatement", "statementBytes", "tryParseStatement", "parseStatement", "detachSignature"],
  kind: "pure",
  budget: 100_000,
  smokeBudget: 1_000,
  property:
    "validateStatement never throws on JSON data and accepts exactly the values the reference accepts (all 4 types, with and without an expected type); for an accepted value, statementBytes gives the reference canonical bytes, parsing them returns an equal value, and they parse as no other type; detachSignature accepts {statement, signature} exactly when the statement is valid and the signature is 4,840 lower-case hex characters. Exotic in-process objects (getters, Proxy, class instances) may throw; that is recorded as an observation",
  documentedErrors: ["StatementError"],
  gen: genStatementValue,
  run(c) {
    const v = new Verdict();
    const exp = c.meta?.["expected"] as StatementType | undefined;
    const r = timedCall(() => validateStatement(c.input, exp));
    v.callMs = r.ms;
    if (r.error) {
      if (c.family === EXOTIC_FAMILY) v.observe("exoticObjectThrows", `validateStatement threw ${errClass(r.error)} on ${c.recipe.join(", ")}`);
      else v.thrown(r.error, [], "validateStatement");
      v.outcome = "threw";
      return v.done();
    }
    let ref: boolean;
    try {
      ref = refStatementValid(c.input, exp);
    } catch {
      v.outcome = "reference-threw";
      return v.done();
    }
    const ok = r.value?.ok === true;
    v.check(ok === ref, "validateStatement=ref", `validateStatement ok=${ok}, reference ${ref} (${c.recipe.join("; ")})${ok ? "" : ": " + (r.value as { errors?: string[] }).errors?.join("; ")}`);
    v.outcome = ok ? "accepted" : "rejected";
    if (ok && ref) {
      try {
        const bytes = statementBytes(c.input, exp);
        v.check(bytes.toString("utf8") === refCanonical(c.input), "statementBytes=refCanonical", "canonical bytes differ from the reference");
        const back = parseStatement(bytes);
        v.check(sameJson(back, c.input), "roundTrip", "parseStatement(statementBytes(s)) differs from s");
        for (const t of TYPE_LIST) {
          if (t === (c.input as Record<string, unknown>)["type"]) continue;
          v.check(!tryParseStatement(bytes, t as StatementType).ok, "noCrossTypeAcceptance", `bytes of ${String((c.input as Record<string, unknown>)["type"])} parse as ${t}`);
        }
      } catch (e) {
        v.fail("acceptedButNotSerialisable", `${errClass(e)}: ${errMsg(e)}`, errClass(e));
      }
    }
    if (c.family !== EXOTIC_FAMILY && c.input && typeof c.input === "object" && !Array.isArray(c.input)) {
      const sig = Buffer.alloc(2420, 0xab).toString("hex");
      const withSig = { ...(c.input as Record<string, unknown>), signature: sig };
      const d = detachSignature(withSig, exp);
      const { signature: _s, ...rest } = withSig;
      v.check(d.ok === refStatementValid(rest, exp), "detachSignature=ref", `detachSignature ok=${d.ok}`);
      const bad = detachSignature({ ...(c.input as Record<string, unknown>), signature: sig.toUpperCase() }, exp);
      v.check(!bad.ok, "detachSignature:rejectsUpperHex", "accepted an upper-case signature");
    }
    return v.done();
  },
};

function genStatementBytes(rng: Rng): FuzzCase {
  const s = G.statement(rng);
  const canon = Buffer.from(refCanonical(s), "utf8");
  const expected = rng.weighted<string | undefined>([
    [3, undefined],
    [2, s["type"] as string],
    [1, rng.pick(TYPE_LIST)],
  ]);
  const fam = rng.weighted<string>([
    [1, "canonical"],
    [4, "bytes"],
    [4, "json-text"],
    [2, "utf8"],
    [1, "pretty"],
  ]);
  let m: Mutated<Buffer>;
  switch (fam) {
    case "canonical":
      m = { value: canon, ops: [] };
      break;
    case "bytes":
      m = mutateBytes(rng, canon, [], rng.int(1, 3));
      break;
    case "json-text": {
      const t = mutateJsonText(rng, canon.toString("utf8"));
      m = { value: Buffer.from(t.value, "utf8"), ops: t.ops };
      break;
    }
    case "utf8":
      m = utf8Hazard(rng, canon.toString("utf8"));
      break;
    default:
      m = { value: Buffer.from(JSON.stringify(s, null, rng.pick([1, 2, "\t"])), "utf8"), ops: ["pretty-printed"] };
  }
  return { family: fam, input: m.value, recipe: m.ops, meta: { expected } };
}

const tStmtBytes: FuzzTarget = {
  id: "T-stmt-bytes",
  title: "statement parsing (bytes)",
  entryPoints: ["tryParseStatement", "parseStatement"],
  kind: "pure",
  budget: 100_000,
  smokeBudget: 1_000,
  property:
    "tryParseStatement never throws and accepts exactly the byte strings that are strict UTF-8, valid JSON, a valid statement (of the expected type, if given) and byte-identical to the canonical encoding (so duplicate keys, whitespace, -0, other number spellings, \\u escapes, BOM and invalid UTF-8 are rejected); parseStatement throws StatementError exactly when tryParseStatement rejects",
  documentedErrors: ["StatementError"],
  gen: genStatementBytes,
  run(c) {
    const v = new Verdict();
    const bytes = c.input as Buffer;
    const exp = c.meta?.["expected"] as StatementType | undefined;
    const r = timedCall(() => tryParseStatement(bytes, exp));
    v.callMs = r.ms;
    if (r.error) {
      v.thrown(r.error, [], "tryParseStatement");
      return v.done();
    }
    const ref = refParseStatement(bytes, exp);
    const ok = r.value?.ok === true;
    v.check(ok === ref, "tryParseStatement=ref", `ok=${ok}, reference ${ref} (${c.recipe.join("; ")})`);
    const p = timedCall(() => parseStatement(bytes, exp));
    if (ok) v.check(p.error === undefined, "parseStatement:agrees", `parseStatement threw ${errClass(p.error)}`);
    else {
      v.check(p.error !== undefined, "parseStatement:agrees", "parseStatement returned for rejected bytes");
      if (p.error) v.thrown(p.error, tStmtBytes.documentedErrors, "parseStatement");
    }
    v.outcome = ok ? "accepted" : "rejected";
    return v.done();
  },
};

// =====================================================================================
// T-stmt-sig
// =====================================================================================

let sigKeys: MlDsaKeyPair | null = null;
let sigOther: MlDsaKeyPair | null = null;
let signedSet: Array<{ bytes: Buffer; sig: Buffer; type: string }> = [];

const tStmtSig: FuzzTarget = {
  id: "T-stmt-sig",
  title: "statement signatures",
  entryPoints: ["verifyStatement", "signStatement"],
  kind: "pure",
  budget: 10_000,
  smokeBudget: 200,
  property:
    "verifyStatement never throws and returns true exactly for an original (public key, canonical statement bytes, signature) triple signed in this run (ML-DSA-44 keys generated in memory, never written): any change to the key, the bytes or the signature, a wrong expected type or a non-byte argument gives false; signStatement refuses (StatementError) exactly the bytes that are not a valid canonical statement, and what it signs verifies",
  documentedErrors: ["StatementError"],
  async setup() {
    sigKeys = mlDsaKeygen();
    sigOther = mlDsaKeygen();
    const rng = new Rng(0x5157);
    signedSet = [];
    for (let k = 0; k < 8; k++) {
      const s = G.statement(rng, G.STATEMENT_KINDS[k % 4]);
      const bytes = canonicalJsonBytes(s);
      signedSet.push({ bytes, sig: signStatement(sigKeys.privateKey, bytes), type: s["type"] as string });
    }
  },
  gen(rng) {
    return plan(rng, rng.weighted<string>([
      [1, "original"],
      [3, "bytes"],
      [2, "sig"],
      [1, "pk"],
      [1, "type"],
      [1, "types"],
      [2, "sign"],
    ]));
  },
  run(c) {
    const v = new Verdict();
    const rng = subRng(c);
    const keys = sigKeys as MlDsaKeyPair;
    const item = rng.pick(signedSet);
    let pk: unknown = keys.publicKey;
    let bytes: unknown = item.bytes;
    let sig: unknown = item.sig;
    let exp: string | undefined = rng.bool(0.5) ? item.type : undefined;
    switch (c.family) {
      case "bytes": {
        const m = rng.bool(0.5) ? mutateBytes(rng, item.bytes, [], rng.int(1, 2)) : (() => {
          const t = mutateJsonText(rng, item.bytes.toString("utf8"));
          return { value: Buffer.from(t.value, "utf8"), ops: t.ops };
        })();
        bytes = m.value;
        c.recipe.push(...m.ops);
        break;
      }
      case "sig": {
        const m = mutateBytes(rng, item.sig, [], 1);
        sig = m.value;
        c.recipe.push(...m.ops);
        break;
      }
      case "pk": {
        const choice = rng.pick(["mutate", "other", "short"]);
        pk = choice === "mutate" ? mutateBytes(rng, keys.publicKey, [], 1).value : choice === "other" ? (sigOther as MlDsaKeyPair).publicKey : keys.publicKey.subarray(0, 1311);
        c.recipe.push(`pk ${choice}`);
        break;
      }
      case "type":
        exp = rng.pick(TYPE_LIST.filter((t) => t !== item.type));
        c.recipe.push(`expected type ${exp}`);
        break;
      case "types": {
        const which = rng.int(0, 2);
        const junk = rng.pick<unknown>([item.bytes.toString("hex"), Array.from(item.bytes.subarray(0, 8)), null, undefined, 42]);
        if (which === 0) pk = junk;
        else if (which === 1) bytes = junk;
        else sig = junk;
        c.recipe.push(`argument ${which} of wrong type`);
        break;
      }
      case "sign": {
        const m = mutateBytes(rng, item.bytes, [], rng.int(0, 2));
        const s = timedCall(() => signStatement(keys.privateKey, m.value));
        v.callMs = s.ms;
        c.recipe.push(...m.ops);
        const valid = refParseStatement(m.value);
        if (!valid) {
          v.check(s.error !== undefined, "signStatement:refusesNonStatement", "signed bytes that are not a valid canonical statement");
          if (s.error) v.thrown(s.error, tStmtSig.documentedErrors, "signStatement");
          v.outcome = "refused";
        } else if (s.error) v.thrown(s.error, [], "signStatement");
        else {
          v.check(verifyStatement(keys.publicKey, m.value, s.value as Buffer), "signStatement:verifies", "own signature does not verify");
          v.outcome = "signed";
        }
        return v.done();
      }
    }
    const r = timedCall(() => verifyStatement(pk as Uint8Array, bytes as Uint8Array, sig as Uint8Array, exp as StatementType | undefined));
    v.callMs = r.ms;
    if (r.error) {
      v.fail("verifyStatement:throws", `${errClass(r.error)}: ${errMsg(r.error)}`, errClass(r.error));
      return v.done();
    }
    const intact =
      Buffer.isBuffer(pk) && pk.equals(keys.publicKey) && Buffer.isBuffer(bytes) && bytes.equals(item.bytes) && Buffer.isBuffer(sig) && sig.equals(item.sig) && (exp === undefined || exp === item.type);
    v.check(r.value === intact, "verifyStatement=intactTriple", `verifyStatement=${String(r.value)}, intact=${intact} (${c.family}: ${c.recipe.join("; ")})`);
    v.outcome = r.value ? "verified" : "rejected";
    return v.done();
  },
};

// =====================================================================================
// T-req-shape and T-reply-shape
// =====================================================================================

function genShapeValue(rng: Rng, valid: () => Record<string, unknown>): FuzzCase {
  const fam = rng.weighted<string>([
    [2, "valid"],
    [7, "mutated"],
    [2, "text"],
    [1, "tree"],
    [1, EXOTIC_FAMILY],
  ]);
  const base = valid();
  if (fam === "valid") return { family: fam, input: base, recipe: [] };
  if (fam === "tree") return { family: fam, input: G.jsonTree(rng, 4), recipe: [] };
  if (fam === EXOTIC_FAMILY) {
    const e = exotic(rng, base);
    return { family: fam, input: e.value, recipe: e.ops };
  }
  if (fam === "text") {
    const t = mutateJsonText(rng, JSON.stringify(base));
    try {
      return { family: fam, input: JSON.parse(t.value) as unknown, recipe: t.ops };
    } catch {
      return { family: "text-unparsable", input: t.value, recipe: t.ops };
    }
  }
  const m = mutateValue(rng, base, rng.int(1, 3));
  return { family: fam, input: m.value, recipe: m.ops };
}

const tReqShape: FuzzTarget = {
  id: "T-req-shape",
  title: "proof request shape",
  entryPoints: ["requestShapeErrors", "isProofRequestV4", "newRequest"],
  kind: "pure",
  budget: 200_000,
  smokeBudget: 2_000,
  property:
    "requestShapeErrors never throws on JSON data and returns no error exactly for the requests the V4_DESIGN section 5 reference accepts (exact keys at both levels, did:pq, lower-case address, positive chainId, threshold 0..255, typeId of 1..256 characters, valid date, non-negative issuedAt); isProofRequestV4 agrees; newRequest returns a reference-valid request carrying the given fields, or throws, exactly as the reference decides for those fields",
  documentedErrors: ["Error", "TypeError"],
  gen: (rng) => genShapeValue(rng, () => G.request(rng)),
  run(c) {
    const v = new Verdict();
    const r = timedCall(() => requestShapeErrors(c.input));
    v.callMs = r.ms;
    if (r.error) {
      if (c.family === EXOTIC_FAMILY) v.observe("exoticObjectThrows", `requestShapeErrors threw ${errClass(r.error)} on ${c.recipe.join(", ")}`);
      else v.thrown(r.error, [], "requestShapeErrors");
      v.outcome = "threw";
      return v.done();
    }
    const ok = (r.value as string[]).length === 0;
    v.check(ok === refRequestValid(c.input), "requestShapeErrors=ref", `ok=${ok} (${c.recipe.join("; ")}): ${(r.value as string[]).join("; ").slice(0, 300)}`);
    v.check(isProofRequestV4(c.input) === ok, "isProofRequestV4=agrees", "isProofRequestV4 disagrees with requestShapeErrors");
    v.outcome = ok ? "accepted" : "rejected";
    if (c.family !== EXOTIC_FAMILY && c.input && typeof c.input === "object" && !Array.isArray(c.input)) {
      const x = c.input as Record<string, unknown>;
      const params = { verifierDid: x["verifierDid"], verifierController: x["verifierController"], chainId: x["chainId"], policy: x["policy"], issuedAt: x["issuedAt"] } as unknown as NewRequestParams;
      const n = timedCall(() => newRequest(params));
      const pol = x["policy"];
      let refOk = false;
      if (pol !== null && pol !== undefined) {
        const pp = pol as Record<string, unknown>;
        const cand = {
          type: "pqid:request:v4",
          sessionId: "0".repeat(64),
          verifierDid: x["verifierDid"],
          verifierController: x["verifierController"],
          chainId: x["chainId"],
          policy: { predicate: pp["predicate"], threshold: pp["threshold"], typeId: pp["typeId"], today: pp["today"] },
          issuedAt: x["issuedAt"] ?? Math.floor(Date.now() / 1000),
        };
        refOk = refRequestValid(cand);
      }
      if (refOk) {
        if (n.error) v.fail("newRequest:refusedValidParams", `${errClass(n.error)}: ${errMsg(n.error)}`, errClass(n.error));
        else {
          const out = n.value as unknown as Record<string, unknown>;
          v.check(refRequestValid(out) && out["verifierDid"] === x["verifierDid"] && out["chainId"] === x["chainId"], "newRequest:validAndFaithful", "newRequest output is not a valid request with the given fields");
        }
      } else {
        v.check(n.error !== undefined, "newRequest:refusesInvalidParams", `newRequest accepted invalid parameters (${c.recipe.join("; ")})`);
        if (n.error) v.thrown(n.error, tReqShape.documentedErrors, "newRequest");
      }
    }
    return v.done();
  },
};

const tReplyShape: FuzzTarget = {
  id: "T-reply-shape",
  title: "session reply shape",
  entryPoints: ["replyShapeErrors", "isSessionReplyV4"],
  kind: "pure",
  budget: 200_000,
  smokeBudget: 2_000,
  property:
    "replyShapeErrors never throws on JSON data and returns no error exactly for replies the reference accepts (exact keys, type, 64-hex sessionId, ct of 2,176 lower-case hex characters, box of lower-case hex of whole bytes between 32 characters and 2 x (1 MiB + 16)); isSessionReplyV4 agrees",
  documentedErrors: [],
  gen: (rng) => genShapeValue(rng, () => G.reply(rng)),
  run(c) {
    const v = new Verdict();
    const r = timedCall(() => replyShapeErrors(c.input));
    v.callMs = r.ms;
    if (r.error) {
      if (c.family === EXOTIC_FAMILY) v.observe("exoticObjectThrows", `replyShapeErrors threw ${errClass(r.error)} on ${c.recipe.join(", ")}`);
      else v.thrown(r.error, [], "replyShapeErrors");
      v.outcome = "threw";
      return v.done();
    }
    const ok = (r.value as string[]).length === 0;
    v.check(ok === refReplyValid(c.input), "replyShapeErrors=ref", `ok=${ok} (${c.recipe.join("; ")})`);
    v.check(isSessionReplyV4(c.input) === ok, "isSessionReplyV4=agrees", "disagrees");
    v.outcome = ok ? "accepted" : "rejected";
    return v.done();
  },
};

// =====================================================================================
// T-open
// =====================================================================================

let openKem: MlKemKeyPair | null = null;

function rawPlaintext(rng: Rng): { bytes: Buffer; ops: string[] } {
  const k = rng.weighted<string>([
    [3, "canonical"],
    [2, "noncanonical"],
    [1, "array"],
    [1, "scalar"],
    [2, "deep"],
    [1, "badutf8"],
    [1, "proto"],
    [1, "huge"],
    [1, "empty"],
  ]);
  const obj = G.jsonTree(rng, 5) as unknown;
  const o = obj && typeof obj === "object" && !Array.isArray(obj) ? obj : { a: obj };
  switch (k) {
    case "canonical":
      return { bytes: Buffer.from(refCanonical(o)), ops: ["canonical object"] };
    case "noncanonical": {
      const t = mutateJsonText(rng, refCanonical(o));
      return { bytes: Buffer.from(t.value), ops: t.ops };
    }
    case "array":
      return { bytes: Buffer.from(refCanonical([o])), ops: ["array"] };
    case "scalar":
      return { bytes: Buffer.from(rng.pick(["1", '"x"', "null", "true", "-0"])), ops: ["scalar"] };
    case "deep": {
      const d = rng.pick([7, 8, 9, 10, 64, 5000]);
      return { bytes: Buffer.from('{"a":' + "[".repeat(d - 1) + "0" + "]".repeat(d - 1) + "}"), ops: [`object of depth ${d}`] };
    }
    case "badutf8":
      return { bytes: utf8Hazard(rng, refCanonical(o)).value, ops: ["invalid UTF-8"] };
    case "proto":
      return { bytes: Buffer.from('{"__proto__":{"x":1},"a":1}'), ops: ['"__proto__" key'] };
    case "huge":
      return { bytes: Buffer.from(`{"s":"${hugeDigits(rng, rng.pick([10_000, 500_000]))}"}`), ops: ["long string member"] };
    default:
      return { bytes: Buffer.alloc(0), ops: ["empty plaintext"] };
  }
}

const tOpen: FuzzTarget = {
  id: "T-open",
  title: "verifier transport (open reply)",
  entryPoints: ["verifierOpenReply"],
  kind: "pure",
  budget: 50_000,
  smokeBudget: 500,
  property:
    "verifierOpenReply (in-memory session store, ML-KEM-768 pair generated in memory) never throws on a reply given as an object, a JSON string or UTF-8 bytes; its result is the one the reference decides: malformed for a reply that is not JSON or not of the reply shape, unknownSession or expiredSession for the session state, decryptFailed whenever ct or box differ from what the wallet sealed, malformed for a plaintext that is not strict UTF-8 canonical JSON of an object nesting at most 8 levels, else ok with a presentation equal to the sealed one; ok never consumes the session",
  documentedErrors: [],
  async setup() {
    openKem = mlKemKeygen();
  },
  gen(rng) {
    return plan(rng, rng.weighted<string>([
      [2, "honest"],
      [3, "reply-object"],
      [2, "reply-string"],
      [2, "reply-bytes"],
      [3, "raw-plaintext"],
      [1, "expired"],
      [1, "unknown-session"],
    ]));
  },
  run(c) {
    const v = new Verdict();
    const rng = subRng(c);
    const kem = openKem as MlKemKeyPair;
    let clockMs = 1_790_000_000_000;
    const store = new VerifierSessionStore({ nowMs: () => clockMs });
    const req = store.open({ verifierDid: G.didPq(rng), verifierController: G.address(rng), chainId: 31337, policy: { predicate: "age_gte", threshold: 18, typeId: "pqid:type:age-credential:v1", today: 20260927 } });
    const sess = walletOpenSession(req, kem.publicKey);
    let plaintext: Buffer;
    let honest: Record<string, unknown>;
    if (c.family === "raw-plaintext") {
      const pt = rawPlaintext(rng);
      plaintext = pt.bytes;
      c.recipe.push(...pt.ops);
      const box = aes256gcmSeal(sess.key, sess.iv, sess.transcript, plaintext);
      honest = { type: "pqid:reply:v4", sessionId: req.sessionId, ct: sess.ciphertext.toString("hex"), box: Buffer.concat([box.ciphertext, box.tag]).toString("hex") };
    } else {
      const pres = rng.bool(0.5) ? G.presentation(rng) : ((): Record<string, unknown> => {
        const t = G.jsonTree(rng, 4);
        return t && typeof t === "object" && !Array.isArray(t) ? (t as Record<string, unknown>) : { v: t };
      })();
      plaintext = canonicalJsonBytes(pres);
      honest = walletSealReply(sess, pres) as unknown as Record<string, unknown>;
    }
    // the wire form and its mutation
    let form: unknown = honest;
    let parsed: unknown = honest;
    let parseOk = true;
    switch (c.family) {
      case "reply-object": {
        const m = mutateValue(rng, honest, rng.int(1, 2));
        form = m.value;
        parsed = m.value;
        c.recipe.push(...m.ops);
        break;
      }
      case "reply-string": {
        const t = mutateJsonText(rng, JSON.stringify(honest));
        form = t.value;
        c.recipe.push(...t.ops);
        try {
          parsed = JSON.parse(t.value) as unknown;
        } catch {
          parseOk = false;
        }
        break;
      }
      case "reply-bytes": {
        const text = JSON.stringify(honest);
        const m = rng.bool(0.5) ? utf8Hazard(rng, text) : mutateBytes(rng, Buffer.from(text), [], 1);
        form = m.value;
        c.recipe.push(...m.ops);
        const s = refStrictUtf8(m.value);
        if (s === null) parseOk = false;
        else {
          try {
            parsed = JSON.parse(s) as unknown;
          } catch {
            parseOk = false;
          }
        }
        break;
      }
      case "expired":
        clockMs += 5 * 60_000 + rng.int(0, 60_000);
        c.recipe.push("clock past the session TTL");
        form = rng.bool() ? JSON.stringify(honest) : honest;
        break;
      case "unknown-session":
        form = { ...honest, sessionId: G.lowerHex(rng, 64) };
        parsed = form;
        c.recipe.push("random sessionId");
        break;
      default:
        form = rng.pick([honest, JSON.stringify(honest), Buffer.from(JSON.stringify(honest))]);
    }
    // the reference decision
    let want: string;
    let wantPresentation: unknown = undefined;
    if (!parseOk || !refReplyValid(parsed)) want = "malformed";
    else {
      const pr = parsed as Record<string, unknown>;
      if (pr["sessionId"] !== req.sessionId) want = "unknownSession";
      else if (c.family === "expired") want = "expiredSession";
      else if (pr["ct"] !== honest["ct"] || pr["box"] !== honest["box"]) want = "decryptFailed";
      else {
        const text = refStrictUtf8(plaintext);
        let obj: unknown;
        let jsonOk = text !== null;
        if (jsonOk) {
          try {
            obj = JSON.parse(text as string) as unknown;
          } catch {
            jsonOk = false;
          }
        }
        if (!jsonOk || obj === null || typeof obj !== "object" || Array.isArray(obj)) want = "malformed";
        else if (refDepth(obj) > MAX_PRESENTATION_DEPTH) want = "malformed";
        else if (refCanonicalOrNull(obj) !== text) want = "malformed";
        else {
          want = "ok";
          wantPresentation = obj;
        }
      }
    }
    const r = timedCall(() => verifierOpenReply(store, kem.privateKey, kem.publicKey, form));
    v.callMs = r.ms;
    if (r.error) {
      v.fail("verifierOpenReply:throws", `${errClass(r.error)}: ${errMsg(r.error)} (${c.family}: ${c.recipe.join("; ")})`, errClass(r.error));
      return v.done();
    }
    const got = r.value?.ok ? "ok" : (r.value?.error ?? "?");
    v.outcome = got;
    v.check(got === want, "verifierOpenReply=ref", `result ${got}, reference ${want} (${c.family}: ${c.recipe.join("; ")})`);
    if (got === "ok") {
      v.check(sameJson(r.value?.presentation, wantPresentation), "ok:presentationEqualsSealed", "decrypted presentation differs from the sealed one");
      v.check(store.status(req.sessionId) === "open", "ok:sessionStillOpen", `session status ${store.status(req.sessionId)} after open`);
      v.check(r.value?.nonce === sess.nonce, "ok:nonceEqualsWallet", "verifier-derived nonce differs from the wallet's");
    }
    return v.done();
  },
};

// =====================================================================================
// T-depth
// =====================================================================================

const tDepth: FuzzTarget = {
  id: "T-depth",
  title: "JSON nesting bound",
  entryPoints: ["jsonDepthExceeds"],
  kind: "pure",
  budget: 20_000,
  smokeBudget: 300,
  property:
    "jsonDepthExceeds(v, max) equals (reference depth of v, computed in full with an explicit stack) > max for random trees and chains up to depth 1,000, and never throws on chains of depth 10^5 and 10^6 (iterative implementation)",
  documentedErrors: [],
  gen(rng) {
    const fam = rng.weighted<string>([
      [4, "tree"],
      [3, "chain"],
      [1, "huge-chain"],
    ]);
    let depth = 0;
    let value: unknown;
    if (fam === "tree") {
      value = G.jsonTree(rng, rng.int(0, 14), 300);
      depth = refDepth(value);
    } else if (fam === "chain") {
      depth = rng.int(0, 1000);
      value = G.deepChain(depth, rng.pick(["array", "object"] as const));
    } else {
      depth = rng.pick([100_000, 1_000_000]);
      value = G.deepChain(depth, rng.pick(["array", "object"] as const));
    }
    const max = rng.pick([0, 1, 2, 8, rng.int(0, 20), Math.max(0, depth - 1), depth, depth + 1]);
    return { family: fam, input: value, recipe: [`depth ${depth}`, `max ${max}`], meta: { depth, max } };
  },
  run(c) {
    const v = new Verdict();
    const depth = c.meta?.["depth"] as number;
    const max = c.meta?.["max"] as number;
    const r = timedCall(() => jsonDepthExceeds(c.input, max));
    v.callMs = r.ms;
    if (r.error) {
      v.fail("jsonDepthExceeds:throws", `${errClass(r.error)} at depth ${depth}`, errClass(r.error));
      return v.done();
    }
    v.check(r.value === depth > max, "jsonDepthExceeds=refDepth", `jsonDepthExceeds(depth ${depth}, max ${max}) = ${String(r.value)}`);
    v.outcome = r.value ? "exceeds" : "within";
    return v.done();
  },
};

// =====================================================================================
// T-pres-shape
// =====================================================================================

const tPresShape: FuzzTarget = {
  id: "T-pres-shape",
  title: "presentation shape",
  entryPoints: ["presentationShapeError"],
  kind: "pure",
  budget: 100_000,
  smokeBudget: 1_000,
  property:
    "presentationShapeError never throws on JSON data and returns null exactly when the reference shape predicate holds (oracles.ts refPresentationShapeOk); inputs with decimal strings of 10^5 or more digits are timed by the slow-input detector (hypothesis: the BigInt parse has no length cap)",
  documentedErrors: [],
  gen(rng) {
    const fam = rng.weighted<string>([
      [2, "valid"],
      [7, "mutated"],
      [2, "text"],
      [1, "huge-digits"],
      [1, "tree"],
    ]);
    const base = G.presentation(rng);
    if (fam === "valid") return { family: fam, input: base, recipe: [] };
    if (fam === "tree") return { family: fam, input: G.jsonTree(rng, 5), recipe: [] };
    if (fam === "huge-digits") {
      const n = rng.pick([77, 78, 80, 1000, 100_000, 400_000]);
      const digits = hugeDigits(rng, n);
      const where = rng.pick(["signal", "root", "pi_a"]);
      const x = cloneJson(base) as Record<string, Record<string, unknown> & unknown[]>;
      if (where === "signal") (x["publicSignals"] as unknown as string[])[rng.int(0, 7)] = digits;
      else if (where === "root") (x["epochStatement"] as Record<string, unknown>)["root"] = digits;
      else ((x["proof"] as Record<string, unknown>)["pi_a"] as string[])[0] = digits;
      return { family: fam, input: x, recipe: [`${where}: ${n}-digit decimal`], meta: { digits: n } };
    }
    if (fam === "text") {
      const t = mutateJsonText(rng, JSON.stringify(base));
      try {
        return { family: fam, input: JSON.parse(t.value) as unknown, recipe: t.ops };
      } catch {
        return { family: "valid", input: base, recipe: ["text mutation did not parse; valid input used"] };
      }
    }
    const m = mutateValue(rng, base, rng.int(1, 3));
    return { family: fam, input: m.value, recipe: m.ops };
  },
  run(c) {
    const v = new Verdict();
    const r = timedCall(() => presentationShapeError(c.input));
    v.callMs = r.ms;
    if (r.error) {
      v.fail("presentationShapeError:throws", `${errClass(r.error)}: ${errMsg(r.error)} (${c.recipe.join("; ")})`, errClass(r.error));
      return v.done();
    }
    const ok = r.value === null;
    v.check(ok === refPresentationShapeOk(c.input), "presentationShapeError=ref", `null=${ok}, reference ${!ok} (${c.recipe.join("; ")}): ${String(r.value)}`);
    const digits = c.meta?.["digits"] as number | undefined;
    if (digits !== undefined && digits >= 100_000) v.observe("longDecimalParse", `${digits}-digit decimal: presentationShapeError took ${r.ms.toFixed(1)} ms (not a timing result)`);
    v.outcome = ok ? "shape-ok" : "shape-rejected";
    return v.done();
  },
};

// =====================================================================================
// T-witness
// =====================================================================================

function genWitnessInputs(rng: Rng): { pub: Record<string, unknown>; priv: Record<string, unknown> } {
  const dateNum = () => G.ymd(rng);
  const pub: Record<string, unknown> = {
    issuerKeyHash: G.fieldElement(rng),
    revRoot: G.fieldElement(rng),
    policyHash: G.fieldElement(rng),
    nonce: rng.bigBits(248),
    stmtCode: G.fieldElement(rng),
    issRoot: G.fieldElement(rng),
    epochFromDate: dateNum(),
    epochToDate: dateNum(),
  };
  const priv: Record<string, unknown> = {
    credId: rng.bytes(32),
    holderSecret: G.fieldElement(rng),
    birthDate: dateNum(),
    expiryDate: dateNum(),
    credType: G.fieldElement(rng),
    predicate: rng.pick(["age_gte", "age_lt"]),
    threshold: rng.pick([13, 14, 15, 16, 18, 21, 65, rng.int(0, 255)]),
    today: dateNum(),
    requiredType: G.fieldElement(rng),
    domainTag: G.fieldElement(rng),
    issLeafIndex: String(rng.int(0, 2 ** 32 - 1)),
    issPathElements: Array.from({ length: 32 }, () => G.fieldDec(rng)),
    rev: { lowIndex: String(rng.int(0, 2 ** 30 - 1)), lowValue: G.fieldDec(rng), lowNext: G.fieldDec(rng), lowPath: Array.from({ length: 30 }, () => G.fieldDec(rng)), root: G.fieldDec(rng) },
  };
  return { pub, priv };
}

/** Reference assembly of the circuit input (V4_DESIGN section 2 signal names); null when the inputs are not well formed. */
function refAssemble(pub: Record<string, unknown>, priv: Record<string, unknown>): Record<string, string | string[]> | null {
  const out: Record<string, string | string[]> = {};
  if (!pub || typeof pub !== "object" || !priv || typeof priv !== "object") return null;
  for (const n of REF_PUBLIC_ORDER) {
    const d = refFieldLike(pub[n]);
    if (d === null) return null;
    out[n] = d;
  }
  const id = priv["credId"];
  if (!(id instanceof Uint8Array)) return null;
  // only the bytes enter the circuit: read them through the array's internal slots, so an own
  // key a mutation added (for example valueOf) has no effect (Buffer.from(id) calls an own valueOf)
  const bytes = copyBytes(id);
  if (bytes.length !== 32) return null;
  const hex = bytes.toString("hex");
  out["credIDHi"] = BigInt("0x" + hex.slice(0, 32)).toString();
  out["credIDLo"] = BigInt("0x" + hex.slice(32)).toString();
  for (const n of ["holderSecret", "birthDate", "expiryDate", "credType"]) {
    const d = refFieldLike(priv[n]);
    if (d === null) return null;
    out[n] = d;
  }
  const pc = priv["predicate"] === "age_gte" ? "1" : priv["predicate"] === "age_lt" ? "2" : null;
  if (pc === null) return null;
  out["predicateCode"] = pc;
  for (const n of ["threshold", "today", "requiredType", "domainTag"]) {
    const d = refFieldLike(priv[n]);
    if (d === null) return null;
    out[n] = d;
  }
  if (!refIsFieldDec(priv["issLeafIndex"])) return null;
  out["issLeafIndex"] = priv["issLeafIndex"] as string;
  const ip = priv["issPathElements"];
  if (!Array.isArray(ip) || ip.length !== 32 || !ip.every(refIsFieldDec)) return null;
  out["issPathElements"] = ip as string[];
  const rev = priv["rev"] as Record<string, unknown> | null | undefined;
  if (!rev || typeof rev !== "object") return null;
  for (const [src, dst] of [
    ["lowIndex", "revLowIndex"],
    ["lowValue", "revLowValue"],
    ["lowNext", "revLowNext"],
  ] as const) {
    if (!refIsFieldDec(rev[src])) return null;
    out[dst] = rev[src] as string;
  }
  const lp = rev["lowPath"];
  if (!Array.isArray(lp) || lp.length !== 30 || !lp.every(refIsFieldDec)) return null;
  out["revLowPath"] = lp as string[];
  return out;
}

const tWitness: FuzzTarget = {
  id: "T-witness",
  title: "circuit input assembly",
  entryPoints: ["buildCircuitInputV4"],
  kind: "pure",
  budget: 50_000,
  smokeBudget: 500,
  property:
    "buildCircuitInputV4 either throws an Error (any subclass) or returns exactly the reference assembly: the 25 circuit inputs, every value a canonical decimal below p, issPathElements of 32 and revLowPath of 30 elements; it returns exactly when the reference says the inputs are well formed",
  documentedErrors: ["Error", "TypeError", "RangeError", "SyntaxError"],
  gen(rng) {
    const base = genWitnessInputs(rng);
    const fam = rng.weighted<string>([
      [2, "valid"],
      [7, "mutated"],
      [1, "huge-digits"],
    ]);
    if (fam === "valid") return { family: fam, input: base, recipe: [] };
    if (fam === "huge-digits") {
      const x = cloneJson(base);
      const n = rng.pick([78, 1000, 100_000, 400_000]);
      (x.priv["issPathElements"] as string[])[rng.int(0, 31)] = hugeDigits(rng, n);
      return { family: fam, input: x, recipe: [`issPathElements: ${n}-digit decimal`], meta: { digits: n } };
    }
    const m = mutateValue(rng, base, rng.int(1, 3));
    return { family: fam, input: m.value, recipe: m.ops };
  },
  run(c) {
    const v = new Verdict();
    const x = (c.input ?? {}) as { pub: Record<string, unknown>; priv: Record<string, unknown> };
    const r = timedCall(() => buildCircuitInputV4(x.pub as unknown as PublicInputsV4, x.priv as unknown as PrivateInputsV4));
    v.callMs = r.ms;
    let ref: ReturnType<typeof refAssemble> = null;
    try {
      ref = refAssemble(x.pub, x.priv);
    } catch {
      ref = null;
    }
    if (r.error) {
      v.thrown(r.error, tWitness.documentedErrors, "buildCircuitInputV4");
      v.check(ref === null, "buildCircuitInputV4:refusedWellFormed", `threw ${errClass(r.error)} on inputs the reference accepts: ${errMsg(r.error)}`);
      v.outcome = "refused";
    } else {
      v.check(ref !== null, "buildCircuitInputV4:acceptedMalformed", `returned for inputs the reference refuses (${c.recipe.join("; ")})`);
      const out = r.value as Record<string, unknown>;
      const allCanonical = Object.values(out).every((val) => (Array.isArray(val) ? val.every(refIsFieldDec) : refIsFieldDec(val)));
      v.check(allCanonical, "buildCircuitInputV4:canonicalOutput", "an output value is not a canonical decimal below p");
      if (ref) v.check(sameJson(out, ref), "buildCircuitInputV4=refAssembly", "output differs from the reference assembly");
      v.outcome = "assembled";
    }
    const digits = c.meta?.["digits"] as number | undefined;
    if (digits !== undefined && digits >= 100_000) v.observe("longDecimalParse", `${digits}-digit decimal: buildCircuitInputV4 took ${r.ms.toFixed(1)} ms (not a timing result)`);
    return v.done();
  },
};

// =====================================================================================
// T-pqc
// =====================================================================================

let pqcDsa: MlDsaKeyPair | null = null;
let pqcKem: MlKemKeyPair | null = null;

const tPqc: FuzzTarget = {
  id: "T-pqc",
  title: "PQC and AEAD wrappers",
  entryPoints: ["mlDsaVerify", "mlDsaVerifyKey", "mlKemDecaps", "aes256gcmOpen", "hkdfSha256Expand"],
  kind: "pure",
  budget: 20_000,
  smokeBudget: 300,
  property:
    "mlDsaVerify and mlDsaVerifyKey never throw and accept only the exact (key, message, signature) signed in this run; aes256gcmOpen never throws and returns the plaintext only for the exact sealed (key, iv, aad, ciphertext, tag), null otherwise; mlKemDecaps throws Error only on a ciphertext that is not 1,088 bytes and returns the encapsulated secret exactly for the untouched ciphertext (implicit rejection otherwise); hkdfSha256Expand throws Error exactly for an output length outside [1, 8160] or a PRK under 32 bytes and otherwise equals Node's HKDF",
  documentedErrors: ["Error"],
  async setup() {
    pqcDsa = mlDsaKeygen();
    pqcKem = mlKemKeygen();
  },
  gen(rng) {
    return plan(rng, rng.weighted<string>([
      [3, "dsa"],
      [2, "dsa-key"],
      [2, "kem"],
      [3, "aead"],
      [1, "hkdf"],
    ]));
  },
  run(c) {
    const v = new Verdict();
    const rng = subRng(c);
    const dsa = pqcDsa as MlDsaKeyPair;
    const kem = pqcKem as MlKemKeyPair;
    const maybeMutate = (b: Buffer, label: string): { value: Buffer | unknown; changed: boolean } => {
      if (!rng.bool(0.4)) return { value: b, changed: false };
      if (rng.bool(0.15)) {
        c.recipe.push(`${label}: wrong type`);
        return { value: rng.pick<unknown>([b.toString("hex"), Array.from(b.subarray(0, 4)), null, 7]), changed: true };
      }
      const m = mutateBytes(rng, b, [], 1);
      c.recipe.push(...m.ops.map((o) => `${label}: ${o}`));
      return { value: m.value, changed: !m.value.equals(b) };
    };
    switch (c.family) {
      case "dsa":
      case "dsa-key": {
        const msg = rng.bytes(rng.int(0, 300));
        const sig = mlDsaSign(dsa.privateKey, msg);
        const pk = c.family === "dsa" ? maybeMutate(dsa.publicKey, "pk") : { value: dsa.publicKey, changed: false };
        const m = maybeMutate(msg, "msg");
        const s = maybeMutate(sig, "sig");
        const intact = !pk.changed && !m.changed && !s.changed;
        let keyArg: unknown = null;
        if (c.family === "dsa-key") {
          keyArg = rng.bool(0.85) ? mlDsaImportPublicKey(dsa.publicKey) : rng.pick<unknown>([kem.privateKey, dsa.privateKey, null]);
        }
        const r = timedCall(() => (c.family === "dsa" ? mlDsaVerify(pk.value as Uint8Array, m.value as Uint8Array, s.value as Uint8Array) : mlDsaVerifyKey(keyArg as never, m.value as Uint8Array, s.value as Uint8Array)));
        v.callMs = r.ms;
        if (r.error) {
          v.fail(`${c.family}:throws`, `${errClass(r.error)}: ${errMsg(r.error)}`, errClass(r.error));
          break;
        }
        const keyOk = c.family === "dsa" || (keyArg !== null && (keyArg as { type?: string }).type === "public");
        v.check(r.value === (intact && keyOk), `${c.family}:acceptsOnlyIntact`, `verify=${String(r.value)} intact=${intact} (${c.recipe.join("; ")})`);
        v.outcome = r.value ? "verified" : "rejected";
        break;
      }
      case "kem": {
        const enc = mlKemEncaps(kem.publicKey);
        const lenChange = rng.bool(0.1);
        const ct = lenChange ? enc.ciphertext.subarray(0, rng.pick([0, 1087, 1000])) : maybeMutate(enc.ciphertext, "ct").value;
        if (lenChange) c.recipe.push("ct: wrong length");
        const r = timedCall(() => mlKemDecaps(kem.privateKey, ct as Uint8Array));
        v.callMs = r.ms;
        const wellFormed = ct instanceof Uint8Array && ct.length === 1088;
        if (!wellFormed) {
          v.check(r.error !== undefined, "mlKemDecaps:throwsOnLength", "returned for a malformed ciphertext");
          if (r.error) v.thrown(r.error, tPqc.documentedErrors, "mlKemDecaps");
          v.outcome = "refused";
        } else if (r.error) v.fail("mlKemDecaps:throwsOnWellFormed", `${errClass(r.error)}: ${errMsg(r.error)}`, errClass(r.error));
        else {
          const same = Buffer.from(ct).equals(enc.ciphertext);
          v.check((r.value as Buffer).length === 32, "mlKemDecaps:32bytes", "shared secret length");
          v.check((r.value as Buffer).equals(enc.sharedSecret) === same, "mlKemDecaps:implicitRejection", `secret equal=${!same} for ciphertext changed=${!same}`);
          v.outcome = same ? "decapsulated" : "implicit-rejection";
        }
        break;
      }
      case "aead": {
        const key = rng.bytes(32);
        const iv = rng.bytes(12);
        const aad = rng.bytes(rng.int(0, 64));
        const pt = rng.bytes(rng.int(0, 512));
        const box = aes256gcmSeal(key, iv, aad, pt);
        const parts = [maybeMutate(key, "key"), maybeMutate(iv, "iv"), maybeMutate(aad, "aad"), maybeMutate(box.ciphertext, "ct"), maybeMutate(box.tag, "tag")];
        const intact = parts.every((x) => !x.changed);
        const r = timedCall(() => aes256gcmOpen(parts[0]!.value as Uint8Array, parts[1]!.value as Uint8Array, parts[2]!.value as Uint8Array, parts[3]!.value as Uint8Array, parts[4]!.value as Uint8Array));
        v.callMs = r.ms;
        if (r.error) {
          v.fail("aes256gcmOpen:throws", `${errClass(r.error)}: ${errMsg(r.error)}`, errClass(r.error));
          break;
        }
        if (intact) v.check(r.value !== null && (r.value as Buffer).equals(pt), "aes256gcmOpen:opensIntact", "intact box did not open");
        else v.check(r.value === null, "aes256gcmOpen:rejectsTamper", `tampered box opened (${c.recipe.join("; ")})`);
        v.outcome = r.value ? "opened" : "rejected";
        break;
      }
      default: {
        const ikm = rng.bytes(32);
        const salt = rng.bytes(rng.pick([0, 32, 64]));
        const prk = rng.bool(0.9) ? hkdfSha256Extract(salt, ikm) : rng.bytes(rng.pick([0, 16, 31]));
        const len = rng.weighted<number>([
          [6, rng.int(1, 100)],
          [1, rng.pick([0, -1, 8160, 8161, 1.5, NaN, 255 * 32])],
        ]);
        const info = rng.bytes(rng.int(0, 40));
        const r = timedCall(() => hkdfSha256Expand(prk, info, len));
        v.callMs = r.ms;
        const ok = Number.isInteger(len) && len >= 1 && len <= 8160 && prk.length >= 32;
        if (!ok) {
          v.check(r.error !== undefined, "hkdf:throwsOnBadLength", `returned for len ${len}, prk ${prk.length} bytes`);
          if (r.error) v.thrown(r.error, tPqc.documentedErrors, "hkdfSha256Expand");
          v.outcome = "refused";
        } else if (r.error) v.fail("hkdf:throwsOnGoodInput", `${errClass(r.error)}`, errClass(r.error));
        else {
          if (prk.length === 32 && salt.length > 0) {
            const want = Buffer.from(nodeCrypto.hkdfSync("sha256", ikm, salt, info, len));
            v.check((r.value as Buffer).equals(want), "hkdf=nodeHkdf", "differs from crypto.hkdfSync");
          }
          v.check((r.value as Buffer).length === len, "hkdf:length", "output length");
          v.outcome = "derived";
        }
      }
    }
    return v.done();
  },
};

// =====================================================================================
// T-imt
// =====================================================================================

const tImt: FuzzTarget = {
  id: "T-imt",
  title: "revocation tree (IMT) bytes and witnesses",
  entryPoints: ["IndexedMerkleTree.deserialize", "IndexedMerkleTree.verifyNonMembership"],
  kind: "pure",
  budget: 20_000,
  smokeBudget: 100,
  property:
    "deserialize(serialize(t)) equals t (depth, keys in leaf order, root) for random trees of depth 1 to 12 (and 1 % at depth 30); any byte string deserialize accepts serialises back to exactly the same bytes (only canonical encodings are accepted), and everything else throws Error; verifyNonMembership never throws, accepts the honest witness of every non-member key, and when it accepts a witness whose root is the tree's root, the opened leaf is the tree's leaf at lowIndex and strictly brackets a key that is not in the tree",
  documentedErrors: ["Error"],
  async setup() {
    await pos();
  },
  gen(rng) {
    const depth = rng.bool(0.01) ? 30 : rng.int(1, 12);
    const cap = Math.min(2 ** depth - 1, 40);
    const n = rng.int(0, cap);
    const keys = new Set<bigint>();
    while (keys.size < n) {
      keys.add(rng.weighted<bigint>([
        [8, 1n + rng.bigBelow((1n << 251n) - 1n)],
        [1, 1n],
        [1, (1n << 251n) - 1n],
      ]));
    }
    return { family: rng.pick(["roundtrip", "bytes", "count", "nonmember", "witness-mutated"]), input: { depth, keys: [...keys] }, recipe: [], meta: { subSeed: rng.u32() } };
  },
  async run(c) {
    const v = new Verdict();
    const rng = subRng(c);
    const { depth, keys } = c.input as { depth: number; keys: bigint[] };
    const tree = await IndexedMerkleTree.bulkBuild(keys, depth);
    const bytes = tree.serialize();
    if (c.family === "roundtrip" || c.family === "bytes" || c.family === "count") {
      let mb: Buffer = Buffer.from(bytes);
      if (c.family === "bytes") {
        const m = mutateBytes(rng, bytes, [], rng.int(1, 2));
        mb = m.value;
        c.recipe.push(...m.ops);
      } else if (c.family === "count") {
        const field = rng.pick([8, 9, 12]);
        mb = field === 12 ? setU32be(bytes, 12, rng.pick([0, keys.length + 1, Math.max(0, keys.length - 1), 0xffffffff])) : Buffer.from(bytes);
        if (field !== 12) mb[field] = rng.pick([0, 49, 255, depth + 1, (mb[field] as number) ^ 1]);
        c.recipe.push(`header field ${field} edited`);
      }
      const r = await timedCallAsync(() => IndexedMerkleTree.deserialize(mb));
      v.callMs = r.ms;
      const same = mb.equals(Buffer.from(bytes));
      if (r.error) {
        v.thrown(r.error, tImt.documentedErrors, "deserialize");
        v.check(!same, "deserialize:acceptsOwnEncoding", `refused the honest encoding: ${errMsg(r.error)}`);
        v.outcome = "refused";
      } else {
        const t2 = r.value as IndexedMerkleTree;
        v.check(Buffer.from(t2.serialize()).equals(mb), "deserialize:onlyCanonical", `accepted bytes that do not re-serialise identically (${c.recipe.join("; ")})`);
        if (same) {
          v.check(t2.root() === tree.root() && t2.depth === depth && JSON.stringify(t2.keysInLeafOrder().map(String)) === JSON.stringify(tree.keysInLeafOrder().map(String)), "roundTrip", "round trip changed the tree");
        } else v.observe("mutatedBytesAccepted", `mutation produced another valid encoding (${c.recipe.join("; ")})`);
        v.outcome = same ? "roundtrip" : "accepted-other";
      }
      return v.done();
    }
    // non-membership
    const member = keys.length > 0 && rng.bool(0.3);
    const key = member ? rng.pick(keys) : rng.weighted<bigint>([
      [8, 1n + rng.bigBelow((1n << 251n) - 1n)],
      [1, rng.pick([0n, 1n << 251n, -1n, (1n << 251n) - 1n])],
    ]);
    let w: Record<string, unknown>;
    if (tree.has(key) || key <= 0n || key >= 1n << 251n) w = tree.openLeaf(rng.int(0, tree.size - 1)) as unknown as Record<string, unknown>;
    else w = tree.nonMembershipWitness(key) as unknown as Record<string, unknown>;
    const honest = !tree.has(key) && key > 0n && key < 1n << 251n;
    if (c.family === "witness-mutated") {
      const m = mutateValue(rng, w, 1);
      w = m.value as Record<string, unknown>;
      c.recipe.push(...m.ops);
    }
    const p = P();
    const depthArg = rng.bool(0.95) ? depth : rng.pick([0, depth + 1, 49]);
    if (depthArg !== depth) c.recipe.push(`depth argument ${depthArg}`);
    const r = timedCall(() => IndexedMerkleTree.verifyNonMembership(p, key, w as never, depthArg));
    v.callMs = r.ms;
    if (r.error) {
      v.fail("verifyNonMembership:throws", `${errClass(r.error)}: ${errMsg(r.error)}`, errClass(r.error));
      return v.done();
    }
    if (c.family === "nonmember" && honest && depthArg === depth) {
      v.check(r.value === true, "verifyNonMembership:completeness", "the honest witness of a non-member key was rejected");
    }
    if (r.value === true && w["root"] === tree.root().toString()) {
      const idx = Number(w["lowIndex"]);
      let leafOk = false;
      try {
        const leaf = tree.leafAt(idx);
        leafOk = leaf.value.toString() === w["lowValue"] && leaf.nextValue.toString() === w["lowNext"];
      } catch {
        leafOk = false;
      }
      v.check(leafOk, "verifyNonMembership:opensRealLeaf", `accepted an opening that is not the tree's leaf ${String(w["lowIndex"])}`);
      v.check(!tree.has(key), "verifyNonMembership:keyNotMember", "accepted non-membership of a member key");
    }
    v.outcome = r.value ? "accepted" : "rejected";
    return v.done();
  },
};

// =====================================================================================
// T-pub
// =====================================================================================

function writeBlob(depth: number, n: number, statement: Buffer, leaves: bigint[], imt: Uint8Array, trailing: Buffer = Buffer.alloc(0)): Buffer {
  const head = Buffer.alloc(20);
  head.write("PQIDPUB1", 0, "ascii");
  head[8] = depth & 0xff;
  head.writeUInt32BE(n >>> 0, 12);
  head.writeUInt32BE(statement.length, 16);
  const ls = Buffer.alloc(32 * leaves.length);
  leaves.forEach((x, i) => {
    let y = x;
    for (let k = 31; k >= 0; k--) {
      ls[i * 32 + k] = Number(y & 0xffn);
      y >>= 8n;
    }
  });
  const m = Buffer.alloc(4);
  m.writeUInt32BE(imt.length, 0);
  return Buffer.concat([head, statement, ls, m, Buffer.from(imt), trailing]);
}

/** Independent issuance-tree root (zero subtrees for missing nodes). */
function refIssuanceRoot(leaves: bigint[], depth: number, p: Poseidon): bigint {
  const h = (a: bigint, b: bigint) => poseidonBig(p, [a, b]);
  let zero = 0n;
  let level = leaves.map((x) => ((x % P_BIG) + P_BIG) % P_BIG);
  for (let l = 0; l < depth; l++) {
    const next: bigint[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(h(level[i] as bigint, i + 1 < level.length ? (level[i + 1] as bigint) : zero));
    zero = h(zero, zero);
    level = next;
  }
  return level[0] ?? zero;
}

const tPub: FuzzTarget = {
  id: "T-pub",
  title: "published-tree blob",
  entryPoints: ["parsePublication"],
  kind: "pure",
  budget: 20_000,
  smokeBudget: 100,
  property:
    "parsePublication never hangs (per-case time recorded, watchdog in the runner), accepts every honest blob of the documented layout (n <= 64 leaves, depth 32, r <= 16 revocations), and when it returns, the statement's root equals an independent Merkle rebuild of the returned leaves at the blob's depth and revRoot equals the returned revocation tree's root. Throwing on a malformed blob is allowed (any error class is recorded). Blobs that differ from the canonical encoding of what they parse to (trailing bytes, a depth other than 32, a leaf >= p, another statement spelling) are recorded as observations",
  documentedErrors: ["Error", "TypeError", "RangeError", "SyntaxError"],
  async setup() {
    await pos();
  },
  gen(rng) {
    const n = rng.weighted<number>([
      [3, rng.int(1, 16)],
      [1, 0],
      [1, rng.int(17, 64)],
    ]);
    const r = rng.int(0, 16);
    const fam = rng.weighted<string>([
      [2, "honest"],
      [4, "bytes"],
      [2, "length-field"],
      [1, "trailing"],
      [1, "depth-consistent"],
      [1, "depth-byte"],
      [1, "leaf-alias"],
      [1, "statement-spelling"],
      [1, "truncate"],
    ]);
    return { family: fam, input: { n, r }, recipe: [], meta: { subSeed: rng.u32() } };
  },
  async run(c) {
    const v = new Verdict();
    const rng = subRng(c);
    const p = P();
    const { n, r } = c.input as { n: number; r: number };
    const leaves = Array.from({ length: n }, () => G.fieldElement(rng));
    const keys = new Set<bigint>();
    while (keys.size < r) keys.add(1n + rng.bigBelow((1n << 251n) - 1n));
    const rev = await IndexedMerkleTree.bulkBuild([...keys], 30);
    let depth = 32;
    if (c.family === "depth-consistent") {
      depth = rng.pick([0, 1, 7, 31, 33, 64, 255]);
      c.recipe.push(`depth ${depth} with a matching root`);
    }
    const root = refIssuanceRoot(leaves, depth, p);
    const st = { ...G.statement(rng, "epoch"), root: root.toString(), revRoot: rev.root().toString(), signature: G.lowerHex(rng, 4840) };
    delete (st as Record<string, unknown>)["type"];
    let stBytes = Buffer.from(JSON.stringify(st));
    if (c.family === "statement-spelling") {
      stBytes = Buffer.from(JSON.stringify(st, null, 1));
      c.recipe.push("statement pretty-printed");
    }
    let blobLeaves = leaves;
    if (c.family === "leaf-alias" && n > 0) {
      const k = rng.int(0, n - 1);
      blobLeaves = leaves.slice();
      if ((leaves[k] as bigint) + P_BIG < 1n << 256n) blobLeaves[k] = (leaves[k] as bigint) + P_BIG;
      c.recipe.push(`leaf ${k} written as leaf + p`);
    }
    let blob = writeBlob(depth, n, stBytes, blobLeaves, rev.serialize(), c.family === "trailing" ? rng.bytes(rng.int(1, 64)) : Buffer.alloc(0));
    if (c.family === "trailing") c.recipe.push("trailing bytes");
    const canonical = writeBlob(32, n, Buffer.from(JSON.stringify(st)), leaves, rev.serialize());
    switch (c.family) {
      case "bytes": {
        const m = mutateBytes(rng, blob, [], rng.int(1, 2));
        blob = m.value;
        c.recipe.push(...m.ops);
        break;
      }
      case "length-field": {
        const at = rng.pick([12, 16, 20 + stBytes.length + 32 * n]);
        blob = setU32be(blob, at, rng.pick([0, 1, n + 1, 0x7fffffff, 0xffffffff, stBytes.length + 1]));
        c.recipe.push(`u32 field at ${at} edited`);
        break;
      }
      case "depth-byte":
        blob = Buffer.from(blob);
        blob[8] = rng.pick([0, 31, 33, 255]);
        c.recipe.push(`depth byte ${blob[8]} without a matching root`);
        break;
      case "truncate":
        blob = blob.subarray(0, rng.int(0, blob.length - 1));
        c.recipe.push(`truncated to ${blob.length}`);
        break;
    }
    const res = await timedCallAsync(() => parsePublication(blob));
    v.callMs = res.ms;
    if (res.error) {
      const cls = errClass(res.error);
      v.outcome = `threw:${cls}`;
      if (cls !== "Error") v.observe(`throws:${cls}`, `${cls}: ${errMsg(res.error).slice(0, 120)} (${c.family})`);
      v.thrown(res.error, tPub.documentedErrors, "parsePublication");
      v.check(c.family !== "honest", "parsePublication:acceptsHonest", `refused an honest blob: ${errMsg(res.error)}`);
      return v.done();
    }
    const out = res.value as Awaited<ReturnType<typeof parsePublication>>;
    const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
    const parsedN = dv.getUint32(12, false);
    const L = dv.getUint32(16, false);
    const parsedLeaves: bigint[] = [];
    for (let i = 0; i < parsedN; i++) parsedLeaves.push(BigInt("0x" + blob.subarray(20 + L + 32 * i, 20 + L + 32 * i + 32).toString("hex")));
    const want = refIssuanceRoot(parsedLeaves, blob[8] as number, p);
    v.check(String((out.statement as unknown as Record<string, unknown>)["root"]) === want.toString(), "parsePublication:rootMatchesLeaves", "returned statement root is not the rebuilt root of the blob's leaves");
    v.check(out.rev.root().toString() === String((out.statement as unknown as Record<string, unknown>)["revRoot"]), "parsePublication:revRootMatches", "revocation tree root differs from the statement's revRoot");
    // classify against the canonical encoding of what was parsed (not against the original blob)
    const imtOff = 20 + L + 32 * parsedN;
    const M = dv.getUint32(imtOff, false);
    const kinds: string[] = [];
    if (blob[8] !== 32) kinds.push("depthNotChecked");
    if (parsedLeaves.some((x) => x >= P_BIG)) kinds.push("leafAboveP");
    if (!blob.subarray(20, 20 + L).equals(Buffer.from(JSON.stringify(out.statement)))) kinds.push("statementSpelling");
    if (M > blob.length - imtOff - 4) kinds.push("imtLengthOverstated");
    else if (blob.length > imtOff + 4 + M) kinds.push("trailingBytesIgnored");
    if (blob[9] !== 0 || blob[10] !== 0 || blob[11] !== 0) kinds.push("reservedBytesNotZero");
    for (const kind of kinds) v.observe(`nonCanonicalAccepted:${kind}`, `accepted a blob that is not the canonical encoding of its content (${kind}; ${c.recipe.join("; ")})`);
    v.outcome = kinds.length ? `accepted-noncanonical:${kinds.join("+")}` : blob.equals(canonical) ? "accepted" : "accepted-other-content";
    return v.done();
  },
};

/** Every pure target, in run order. */
export const PURE_TARGETS: readonly FuzzTarget[] = [tDates, tEncoding, tStmtJson, tStmtBytes, tStmtSig, tReqShape, tReplyShape, tOpen, tDepth, tPresShape, tWitness, tPqc, tImt, tPub];

export type { FuzzTarget, FuzzCase, CaseOutcome };
