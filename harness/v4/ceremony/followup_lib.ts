import { isDeepStrictEqual } from "node:util";
import { createHash } from "node:crypto";
import { rekeyedNames, checkLabel } from "./rekey_rewrite.mjs";

/**
 * Pure helpers of the ceremony follow-up (docs/v4/CEREMONY_FOLLOWUP.md, TASKS I): transcript
 * checks, the snarkjs `zkey verify` log parser, pin-file text that never rewrites an existing
 * entry, install targets, dated output names, the verdict comparisons against the dev-key
 * suite (run 10) and mutation campaign (campaign 5), and the list of series that use the key.
 * No file system access here (followup.ts does the I/O), so every rule is unit-tested
 * (tests/v4/ceremony_followup.test.ts).
 */

// ------------------------------------------------------------------ fixed paths and rules

export const CEREMONY_RESULTS_REL = "results/v4/ceremony";
export const CEREMONY_SMOKE_REL = "results/v4/ceremony/_smoke";
export const LOG_DIR_REL = "verification/v4";
export const DEFAULT_FINAL_DIR_REL = "ceremony/v4/final";
/** Output of `node ceremony/rehearse.mjs` (gitignored); the dry run reads it. */
export const REHEARSAL_FINAL_DIR_REL = "ceremony/rehearsal/_out/ceremony/final";
/** A second rehearsal key of the same tiny circuit and ptau (drand code path): the "other key" of the dry run. */
export const REHEARSAL_OTHER_FINAL_DIR_REL = "ceremony/rehearsal/_out/beacon_drand/final";
export const REHEARSAL_WASM_REL = "ceremony/rehearsal/_out/build/tiny_js/tiny.wasm";
/** The input of rehearse.mjs step 7 (tiny circuit). */
export const REHEARSAL_INPUT = Object.freeze({ x: 3, salt: 11, y: 35, tag: 40 });
export const FREEZE_REL = "docs/v4/FREEZE.md";
/** v4 dev pins: read only. tests/v4/circuit_v4.test.ts requires exactly its six dev entries. */
export const DEV_PINS_REL = "setup/pins_v4.json";
export const PINS_REL = "setup/pins.json";
export const PTAU_PIN_NAME = "powersOfTau28_hez_final_15.ptau";
export const PTAU_REL = "setup/ptau/powersOfTau28_hez_final_15.ptau";
export const FROZEN_R1CS_REL = "circuits/build/v4/credential_auth_v4.r1cs";
export const FROZEN_WASM_REL = "circuits/build/v4/credential_auth_v4_js/credential_auth_v4.wasm";
export const KEY_DIR_REL = "setup/out/v4";
export const DEV_VKEY_REL = "setup/out/v4/verification_key_dev.json";
/** The v2 committed key: beacon only (review finding 9.3), the positive control of the trapdoor check. */
export const CONTROL_V2_VKEY_REL = "setup/out/verification_key.json";
export const CONTROL_V2_BEACON = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
export const CONTROL_V2_ITER_EXP = 10;
/** Dev-key results the ledger cites (read only; never rewritten). */
export const DEV_SUITE_REL = "results/v4/security_suite.json";
export const DEV_MUTATION_REL = "results/v4/mutation.json";
export const BENCH_LOCK_REL = "results/v4/bench/inputs/inputs.lock.json";
export const EXPECTED_SNARKJS = "0.7.4";
export const MIN_CONTRIBUTIONS = 3;
export const MIN_EXTERNAL = 1;
export const MIN_ITER_EXP = 10;
/** drand League of Entropy mainnet, default network (ceremony/lib.mjs DRAND_DEFAULT.chainHash). */
export const DRAND_DEFAULT_CHAIN_HASH = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce";
/** Genesis time (Unix seconds) and round period of that network (ceremony/lib.mjs DRAND_DEFAULT). */
export const DRAND_DEFAULT_GENESIS_TIME = 1595431050;
export const DRAND_DEFAULT_PERIOD_SEC = 30;
/** Files whose SHA-256 the kit writes into the transcript (ceremony/coordinator.mjs KIT_FILES). */
export const KIT_FILES: readonly string[] = Object.freeze(["contribute.ps1", "contribute.sh", "contribute_core.mjs", "lib.mjs", "coordinator.mjs", "package.json", "CONTRIBUTE.md"]);
export const DEV_ZKEY_REL = "setup/out/v4/credential_auth_v4_dev.zkey";
/** Throwaway mutant circuits and keys of the mutation campaign (gitignored; shared with campaign 5). */
export const MUTANTS_DIR_REL = "circuits/build/v4/mutants";
/** Port of the first defence in campaign 5 (harness/v4/mutation.ts counts up from it in defence order). */
export const CAMPAIGN5_BASE_PORT = 8600;
export const DEV_PIN_KEYS: readonly string[] = Object.freeze([
  "v4/credential_auth_v4.r1cs",
  "v4/credential_auth_v4.wasm",
  "v4/credential_auth_v4_dev.zkey",
  "v4/verification_key_dev.json",
  "v4/Groth16VerifierV4_dev.sol",
  "v4/setup_transcript_dev.json",
]);

/**
 * Loopback ports of the follow-up and of the post-fix rerun with the dev key (DECISIONS D-041;
 * harness/v4/lib/ports.ts CEREMONY_FOLLOWUP_PORTS): the suite on 8800, the mutation campaign one
 * port per defence from 8801 (59 defences: 8801 to 8859).
 */
export const CEREMONY_PORTS = Object.freeze({ suite: 8800, mutationBase: 8801, mutationLast: 8899 });

/** Ports the selected steps bind (probed before the run starts and after each suite child exits). */
export function portsForSteps(steps: readonly string[], defenceIndexes: readonly number[]): number[] {
  const out: number[] = [];
  if (steps.includes("suite")) out.push(CEREMONY_PORTS.suite);
  if (steps.includes("mutation")) out.push(...defenceIndexes.map((i) => defencePort(i)));
  return [...new Set(out)].sort((a, b) => a - b);
}

/** Port of the defence at `index` in the full defence list (stable, so a partial rerun reuses it). */
export function defencePort(index: number): number {
  if (!Number.isInteger(index) || index < 0) throw new Error(`defence index ${index} is not a non-negative integer`);
  const p = CEREMONY_PORTS.mutationBase + index;
  if (p > CEREMONY_PORTS.mutationLast) throw new Error(`defence index ${index} needs port ${p}, past the follow-up range ${CEREMONY_PORTS.mutationBase}-${CEREMONY_PORTS.mutationLast}`);
  return p;
}

/**
 * Code the post-ceremony suite and mutation campaign run. The real follow-up refuses to start
 * while any of these has an uncommitted change (the provenance audit found suite rows run on a
 * harness version no commit holds), and records the SHA-256 of the files in CODE_FILES.
 */
export const CODE_PATHS: readonly string[] = Object.freeze([
  "harness/v4/security_suite.ts",
  "harness/v4/suite_lib.ts",
  "harness/v4/mutant_fillers.ts",
  "harness/v4/mutate.ts",
  "harness/v4/mutation.ts",
  "harness/v4/r1cs_tools.ts",
  "harness/v3/trapdoor.ts",
  "harness/v4/bench/lib.ts",
  "harness/v4/bench/guard.ts",
  "harness/v4/lib",
  "harness/v4/cmp/spec.ts",
  "harness/v4/e2e/lib.ts",
  "harness/v4/ceremony",
  "scripts/ceremony",
  "packages",
  "onchain/contracts/v4",
  "docs/v4/ROUTES.md",
  "circuits/credential_auth_v4.circom",
  "circuits/v4/lib_v4.circom",
  "ceremony/coordinator.mjs",
  "ceremony/lib.mjs",
]);

/** Files whose SHA-256 goes into the follow-up record (the suite records its own harnessSha256). */
export const CODE_FILES: readonly string[] = Object.freeze([
  "harness/v4/security_suite.ts",
  "harness/v4/suite_lib.ts",
  "harness/v4/mutant_fillers.ts",
  "harness/v4/mutate.ts",
  "harness/v4/mutation.ts",
  "harness/v4/r1cs_tools.ts",
  "harness/v3/trapdoor.ts",
  "harness/v4/ceremony/followup.ts",
  "harness/v4/ceremony/followup_lib.ts",
  "harness/v4/ceremony/key_checks.ts",
  "harness/v4/ceremony/rekey.mjs",
  "harness/v4/ceremony/rekey_hooks.mjs",
  "harness/v4/ceremony/rekey_rewrite.mjs",
  "harness/v4/ceremony/rekey_probe.ts",
  "harness/v4/cmp/spec.ts",
  "harness/v4/e2e/lib.ts",
  "packages/v4/src/paths.ts",
  "ceremony/coordinator.mjs",
  "ceremony/lib.mjs",
  "artifact/compare_suite.py",
]);

// ------------------------------------------------------------------ small helpers

export function sha256Text(s: string | Uint8Array): string {
  return createHash("sha256").update(s).digest("hex");
}

export function utcDate(d: Date = new Date()): string {
  return d.toISOString().slice(0, 10);
}

/** Compact UTC stamp for smoke folders: 20261001T101530Z. */
export function utcStamp(d: Date = new Date()): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}

export function isHex(s: unknown, bytes?: number): s is string {
  if (typeof s !== "string" || !/^[0-9a-f]+$/.test(s) || s.length % 2 !== 0) return false;
  return bytes === undefined ? true : s.length === bytes * 2;
}

/** Repo-relative path check (forward slashes, no '..', not absolute). */
export function cleanRel(p: string, what: string): string {
  const r = p.replace(/\\/g, "/").replace(/^\.\//, "").replace(/\/+$/, "");
  if (r === "" || r.startsWith("/") || /^[A-Za-z]:/.test(r) || r.split("/").includes("..")) {
    throw new Error(`${what} must be a repository-relative path without '..' (got ${JSON.stringify(p)})`);
  }
  return r;
}

/**
 * First free dated name: `<base>_<date>`, then `<base>_<date>_r2`, `_r3`, ... Output folders and
 * logs are never overwritten; a second run on the same day gets the next suffix.
 */
export function pickDatedName(base: string, date: string, ext: string, exists: (name: string) => boolean): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error(`date must be YYYY-MM-DD (got ${date})`);
  for (let n = 1; n < 1000; n++) {
    const name = `${base}_${date}${n === 1 ? "" : `_r${n}`}${ext}`;
    if (!exists(name)) return name;
  }
  throw new Error(`no free name for ${base}_${date}`);
}

/** Parse a comma list of 1-based contribution indexes ("2" or "2,3"). */
export function parseIndexList(s: string | undefined): number[] {
  if (s === undefined || s.trim() === "") return [];
  const out = s.split(",").map((x) => x.trim());
  const nums = out.map((x) => {
    if (!/^[1-9]\d*$/.test(x)) throw new Error(`--external: ${JSON.stringify(x)} is not a contribution index (1, 2, ...)`);
    return Number(x);
  });
  return [...new Set(nums)].sort((a, b) => a - b);
}

// ------------------------------------------------------------------ FREEZE.md

/** File -> SHA-256 from the table of docs/v4/FREEZE.md (rows "| `path` ... | sha256 |"). */
export function parseFreezeTable(md: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of md.split(/\r?\n/)) {
    const m = /^\|\s*`([^`]+)`[^|]*\|\s*([0-9a-f]{64})\s*\|\s*$/.exec(line);
    if (m) out.set(m[1] as string, m[2] as string);
  }
  return out;
}

// ------------------------------------------------------------------ transcript

export interface TranscriptContribution {
  index: number;
  name: string;
  contributionHash: string;
  zkey?: { file: string; sha256: string };
  acceptedAtUtc?: string;
  reportedHashMatched?: boolean | null;
  receiptMatched?: boolean | null;
  verifiedByContributor?: boolean | null;
}

export interface TranscriptBeaconSource {
  kind: string;
  round?: number;
  height?: number;
  expectedTimeUtc?: string;
  plannedAtUtc?: string;
  announced?: string | null;
  chainHash?: string;
  blockHash?: string;
  iterExp?: number;
  response?: { round: number; randomness: string; signature: string; previous_signature?: string | null };
  [k: string]: unknown;
}

export interface CeremonyTranscript {
  schema: string;
  label: string;
  title?: string;
  circuit: {
    name: string;
    r1cs: { file: string; sha256: string; nConstraints?: number; compiler?: string | null; freeze?: { match?: boolean; source?: string | null } | null };
    circuitHash: string;
  };
  ptau: { file: string; sha256: string; pin?: { checked?: boolean; pinFile?: string; pinName?: string } | null };
  initialZkey?: { file: string; sha256: string };
  contributions: TranscriptContribution[];
  beacon: {
    index: number;
    name: string;
    value: string;
    numIterationsExp: number;
    source: TranscriptBeaconSource;
    contributionHash: string;
    appliedAtUtc?: string;
  };
  final: {
    zkey: { file: string; sha256: string };
    verificationKey: { file: string; sha256: string };
    solidityVerifier: { file: string; sha256: string };
    verifiedFromR1cs?: boolean;
  };
  tools?: { snarkjs?: string; node?: string; compiler?: string | null; kitFilesSha256?: Record<string, string> };
  dates?: Record<string, string | null>;
}

export type CheckStatus = "pass" | "fail" | "warn" | "skipped";

export interface Check {
  id: string;
  status: CheckStatus;
  detail: string;
}

export type Mode = "ceremony" | "rehearsal";

export interface TranscriptContext {
  mode: Mode;
  /** SHA-256 of the frozen r1cs (FREEZE.md, pins_v4.json and the file agree); null in rehearsal mode. */
  frozenR1csSha: string | null;
  /** SHA-256 of the pinned Hermez ptau (setup/pins.json); null in rehearsal mode. */
  pinnedPtauSha: string | null;
  /** Contribution indexes the coordinator declares were made by people outside the project on their own computers. */
  external: readonly number[];
  /** SHA-256 of the files on disk (null when the file is missing). */
  files: { zkeySha: string | null; vkeySha: string | null; solSha: string | null };
  /**
   * Accepted SHA-256 per kit file (KIT_FILES): the working-tree file and the committed blob.
   * Undefined or null: the kit-file rule is skipped.
   */
  kitFiles?: Readonly<Record<string, readonly string[]>> | null;
  minContributions?: number;
}

const REHEARSAL_PREFIX = "REHEARSAL ONLY";

/** Contributor name as compared by the distinct-contributor rule: NFKC, trimmed, inner spaces collapsed, lower case. */
export function normalizeName(s: unknown): string {
  return typeof s === "string" ? s.normalize("NFKC").trim().replace(/\s+/g, " ").toLowerCase() : "";
}

/** Counts for records (names are compared, never recorded). */
export function contributorCounts(t: CeremonyTranscript, external: readonly number[]) {
  const cs = Array.isArray(t.contributions) ? t.contributions : [];
  const names = cs.map((c) => normalizeName(c.name));
  return {
    contributions: cs.length,
    distinctNames: new Set(names.filter((x) => x.length > 0)).size,
    externalSharingAName: external.filter((i) => {
      const nm = names[i - 1];
      return nm !== undefined && nm.length > 0 && names.some((o, j) => j !== i - 1 && o === nm);
    }),
  };
}

/** Expected time of a drand round on the default network (genesis + (round - 1) * 30 s), or null for a bad round. */
export function drandRoundTimeUtc(round: unknown): string | null {
  if (typeof round !== "number" || !Number.isInteger(round) || round < 1) return null;
  return new Date((DRAND_DEFAULT_GENESIS_TIME + (round - 1) * DRAND_DEFAULT_PERIOD_SEC) * 1000).toISOString();
}

/**
 * The kit-file hashes in the transcript against the committed kit: every recorded file must be a
 * kit file with an accepted hash, and every kit file must be recorded. A difference is a warning
 * (the kit that ran is not the committed one; compare by hand).
 */
export function kitFilesCheck(recorded: Readonly<Record<string, string>> | undefined, accepted: Readonly<Record<string, readonly string[]>>): Check {
  if (!recorded || typeof recorded !== "object") return { id: "tools.kitFiles", status: "warn", detail: "the transcript records no kit-file hashes" };
  const bad: string[] = [];
  for (const [f, h] of Object.entries(recorded)) {
    const ok = accepted[f];
    if (!ok) bad.push(`${f}: not a committed kit file`);
    else if (!ok.includes(String(h).toLowerCase())) bad.push(`${f}: ${String(h).slice(0, 16)}... is not the committed file`);
  }
  for (const f of Object.keys(accepted)) if (!(f in recorded)) bad.push(`${f}: not recorded`);
  return bad.length
    ? { id: "tools.kitFiles", status: "warn", detail: `kit files differ from the committed kit: ${bad.join("; ")}` }
    : { id: "tools.kitFiles", status: "pass", detail: `${Object.keys(recorded).length} kit files equal the committed kit (working tree or HEAD blob)` };
}

function chk(id: string, ok: boolean, detail: string, softFail: CheckStatus = "fail"): Check {
  return { id, status: ok ? "pass" : softFail, detail };
}

function timeOf(s: unknown): number | null {
  if (typeof s !== "string") return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

/**
 * Every transcript rule of the follow-up. Ceremony mode needs: label "ceremony", the frozen
 * r1cs and the pinned ptau, at least 3 non-beacon contributions under at least 3 distinct
 * names with at least one declared external, a drand (default network) or Bitcoin beacon
 * planned before the last contribution was accepted (drand: the round time, recomputed from
 * the round number, after it), 2^10 or more iterations, snarkjs 0.7.4, and file hashes equal
 * to the transcript. Rehearsal mode (dry run) skips the freeze, pin and distinct-name rules and
 * allows the dummy beacon.
 */
export function checkTranscript(t: CeremonyTranscript, ctx: TranscriptContext): Check[] {
  const out: Check[] = [];
  const cer = ctx.mode === "ceremony";
  const min = ctx.minContributions ?? MIN_CONTRIBUTIONS;
  out.push(chk("schema", t.schema === "pqid/ceremony-transcript/v1", `schema ${JSON.stringify(t.schema)}`));
  out.push(chk("label", t.label === ctx.mode, `transcript label ${JSON.stringify(t.label)}, expected ${JSON.stringify(ctx.mode)}`));

  // circuit and phase 1
  if (cer) {
    out.push(chk("r1cs.frozen", ctx.frozenR1csSha !== null && t.circuit?.r1cs?.sha256 === ctx.frozenR1csSha, `transcript r1cs ${t.circuit?.r1cs?.sha256 ?? "?"}; frozen ${ctx.frozenR1csSha ?? "?"}`));
    out.push(chk("r1cs.freezeRecorded", t.circuit?.r1cs?.freeze?.match === true, `transcript freeze record: ${JSON.stringify(t.circuit?.r1cs?.freeze ?? null)}`));
    out.push(chk("ptau.pinned", ctx.pinnedPtauSha !== null && t.ptau?.sha256 === ctx.pinnedPtauSha, `transcript ptau ${t.ptau?.sha256 ?? "?"}; pinned ${ctx.pinnedPtauSha ?? "?"}`));
    out.push(chk("ptau.pinChecked", t.ptau?.pin?.checked === true, `transcript pin record: ${JSON.stringify(t.ptau?.pin ?? null)}`));
  } else {
    for (const id of ["r1cs.frozen", "r1cs.freezeRecorded", "ptau.pinned", "ptau.pinChecked"]) out.push({ id, status: "skipped", detail: "rehearsal: throwaway circuit and ptau, not frozen or pinned" });
  }

  // contributions
  const cs = Array.isArray(t.contributions) ? t.contributions : [];
  const n = cs.length;
  out.push(chk("contributions.count", n >= min, `${n} non-beacon contribution(s); at least ${min} required`));
  const counts = contributorCounts(t, ctx.external);
  const unnamed = cs.filter((c) => normalizeName(c.name).length === 0).map((c) => c.index);
  if (cer) {
    out.push(
      chk(
        "contributions.distinctContributors",
        counts.distinctNames >= min && unnamed.length === 0,
        `${counts.distinctNames} distinct contributor name(s) in ${n} contribution(s); at least ${min} required (names compared trimmed and case-folded; only the count is recorded)${unnamed.length ? `; no name on #${unnamed.join(", #")}` : ""}`
      )
    );
  } else {
    out.push({ id: "contributions.distinctContributors", status: "skipped", detail: "rehearsal: one operator plays every contributor" });
  }
  out.push(
    chk(
      "contributions.externalNameUnique",
      counts.externalSharingAName.length === 0,
      counts.externalSharingAName.length ? `declared external #${counts.externalSharingAName.join(", #")} shares its name with another contribution` : "no declared external contribution shares its name with another contribution",
      "warn"
    )
  );
  out.push(chk("contributions.indexes", cs.every((c, i) => c.index === i + 1), `indexes ${cs.map((c) => c.index).join(",")}`));
  out.push(chk("contributions.hashes", cs.every((c) => isHex(c.contributionHash, 64)), "every contribution hash is 64 bytes hex"));
  out.push(chk("contributions.distinctHashes", new Set(cs.map((c) => c.contributionHash)).size === n, "no contribution hash appears twice"));
  if (cer) {
    out.push(chk("contributions.notRehearsal", cs.every((c) => typeof c.name === "string" && !c.name.startsWith(REHEARSAL_PREFIX)), "no contribution carries the rehearsal prefix"));
  } else {
    out.push({ id: "contributions.notRehearsal", status: "skipped", detail: "rehearsal" });
  }
  const badExt = ctx.external.filter((i) => i < 1 || i > n);
  out.push(
    chk(
      "contributions.externalDeclared",
      ctx.external.length >= MIN_EXTERNAL && badExt.length === 0,
      ctx.external.length === 0
        ? "no external contribution declared (--external <index>)"
        : badExt.length
          ? `declared index(es) ${badExt.join(",")} not in 1..${n}`
          : `declared external: #${ctx.external.join(", #")} (coordinator's declaration [A]; the transcript cannot show it)`
    )
  );
  const repFalse = cs.filter((c) => c.reportedHashMatched === false).map((c) => c.index);
  const repNull = cs.filter((c) => c.reportedHashMatched === null || c.reportedHashMatched === undefined).map((c) => c.index);
  out.push(
    repFalse.length
      ? chk("contributions.secondRouteHash", false, `reported hash did not match for #${repFalse.join(", #")}`)
      : chk("contributions.secondRouteHash", repNull.length === 0, repNull.length ? `no hash by a second route recorded for #${repNull.join(", #")}` : "every contribution hash was confirmed by a second route", "warn")
  );
  const extNoRoute = ctx.external.filter((i) => repNull.includes(i));
  if (cer) out.push(chk("contributions.externalSecondRoute", extNoRoute.length === 0, extNoRoute.length ? `declared external #${extNoRoute.join(", #")} has no hash by a second route` : "every declared external contribution has its hash by a second route", "warn"));
  const recFalse = cs.filter((c) => c.receiptMatched === false).map((c) => c.index);
  const recNull = cs.filter((c) => c.receiptMatched === null || c.receiptMatched === undefined).map((c) => c.index);
  out.push(recFalse.length ? chk("contributions.receipts", false, `receipt did not match for #${recFalse.join(", #")}`) : chk("contributions.receipts", recNull.length === 0, recNull.length ? `no receipt for #${recNull.join(", #")}` : "every receipt matched", "warn"));

  // beacon
  const b = t.beacon;
  const src = b?.source ?? ({ kind: "missing" } as TranscriptBeaconSource);
  out.push(chk("beacon.index", b?.index === n + 1, `beacon index ${b?.index}, expected ${n + 1}`));
  out.push(chk("beacon.value", isHex(b?.value) && (b?.value?.length ?? 0) >= 2, "beacon value is hex"));
  out.push(chk("beacon.iterations", Number.isInteger(b?.numIterationsExp) && b.numIterationsExp >= MIN_ITER_EXP, `2^${b?.numIterationsExp} iterations (minimum 2^${MIN_ITER_EXP})`));
  out.push(chk("beacon.contributionHash", isHex(b?.contributionHash, 64), "beacon contribution hash is 64 bytes hex"));
  const kindOk = cer ? src.kind === "drand" || src.kind === "bitcoin" : ["drand", "bitcoin", "dummy"].includes(src.kind);
  out.push(chk("beacon.kind", kindOk, `beacon source ${JSON.stringify(src.kind)}${cer ? " (ceremony: drand or bitcoin)" : ""}`));
  if (src.kind === "drand") {
    const r = src.response;
    out.push(chk("beacon.drandChain", src.chainHash === DRAND_DEFAULT_CHAIN_HASH, `chain hash ${src.chainHash ?? "?"} (default network ${DRAND_DEFAULT_CHAIN_HASH.slice(0, 16)}...)`));
    out.push(chk("beacon.drandRound", !!r && Number(r.round) === src.round, `response round ${r?.round}, planned round ${src.round}`));
    out.push(chk("beacon.drandValue", !!r && String(r.randomness).toLowerCase() === b.value, "beacon value equals the drand randomness field"));
    out.push(chk("beacon.drandSha", !!r && isHex(String(r.signature).toLowerCase()) && sha256Text(Buffer.from(String(r.signature), "hex")) === String(r.randomness).toLowerCase(), "randomness = sha256(signature) (the BLS signature itself is not checked offline)"));
  } else if (src.kind === "bitcoin") {
    out.push(chk("beacon.bitcoinHash", isHex(b.value, 32) && src.blockHash === b.value, "block hash is 32 bytes hex and equals the recorded block hash (two explorers are compared by hand)"));
  }
  const accepted = cs.map((c) => timeOf(c.acceptedAtUtc)).filter((x): x is number => x !== null);
  // Loops, not a spread into Math.max or Math.min: a spread passes every element as a call
  // argument and throws a RangeError past about 125,000 elements (the fuzz writer failed that
  // way, fz1 triage).
  let lastT: number | null = null;
  let firstT: number | null = null;
  for (const x of accepted) {
    if (lastT === null || x > lastT) lastT = x;
    if (firstT === null || x < firstT) firstT = x;
  }
  const plannedT = timeOf(src.plannedAtUtc);
  out.push(chk("contributions.acceptedTimes", accepted.length === n && n > 0, `${accepted.length} of ${n} contributions have an acceptance time`));
  if (src.kind === "dummy") {
    out.push({ id: "beacon.plannedBeforeLastContribution", status: "skipped", detail: "rehearsal dummy beacon has no plan" });
  } else {
    out.push(chk("beacon.plannedBeforeLastContribution", plannedT !== null && lastT !== null && plannedT < lastT, `plan recorded ${src.plannedAtUtc ?? "?"}; last contribution accepted ${lastT === null ? "?" : new Date(lastT).toISOString()}`));
    out.push(chk("beacon.plannedBeforeFirstContribution", plannedT !== null && firstT !== null && plannedT < firstT, `plan recorded ${src.plannedAtUtc ?? "?"}; first contribution accepted ${firstT === null ? "?" : new Date(firstT).toISOString()} (HANDOFF_STEPS step 2 fixes it before anyone contributes)`, "warn"));
  }
  if (src.kind === "drand") {
    // The round time comes from the pinned default network, not from the transcript's own field.
    const computed = drandRoundTimeUtc(src.round);
    const roundT = computed === null ? null : Date.parse(computed);
    out.push(chk("beacon.drandRoundTime", roundT !== null && timeOf(src.expectedTimeUtc) === roundT, `round ${src.round ?? "?"} is due at ${computed ?? "?"} on the default network (genesis ${DRAND_DEFAULT_GENESIS_TIME}, ${DRAND_DEFAULT_PERIOD_SEC} s); transcript says ${src.expectedTimeUtc ?? "?"}`));
    const ok = roundT !== null && lastT !== null && roundT > lastT;
    out.push(
      cer || !src["rehearsalPastRound"]
        ? chk("beacon.unknownAtLastContribution", ok, `drand round time ${computed ?? "?"} (recomputed) after the last accepted contribution ${lastT === null ? "?" : new Date(lastT).toISOString()}`)
        : { id: "beacon.unknownAtLastContribution", status: "skipped", detail: "rehearsal: past drand round on purpose (code-path check)" }
    );
  } else if (src.kind === "bitcoin") {
    out.push({ id: "beacon.unknownAtLastContribution", status: "warn", detail: "Bitcoin: the block time at the planned height is not in the transcript; compare it with the last acceptance time by hand" });
  }

  // final files and tools
  out.push(chk("final.zkeySha", ctx.files.zkeySha !== null && ctx.files.zkeySha === t.final?.zkey?.sha256, `final zkey on disk ${ctx.files.zkeySha ?? "missing"}; transcript ${t.final?.zkey?.sha256 ?? "?"}`));
  out.push(chk("final.vkeySha", ctx.files.vkeySha !== null && ctx.files.vkeySha === t.final?.verificationKey?.sha256, `verification key on disk ${ctx.files.vkeySha ?? "missing"}; transcript ${t.final?.verificationKey?.sha256 ?? "?"}`));
  out.push(chk("final.solSha", ctx.files.solSha !== null && ctx.files.solSha === t.final?.solidityVerifier?.sha256, `Solidity verifier on disk ${ctx.files.solSha ?? "missing"}; transcript ${t.final?.solidityVerifier?.sha256 ?? "?"}`));
  out.push(chk("final.verifiedFromR1cs", t.final?.verifiedFromR1cs === true, "coordinator verified the final zkey from r1cs + ptau at finalize"));
  out.push(chk("tools.snarkjs", t.tools?.snarkjs === EXPECTED_SNARKJS, `snarkjs ${t.tools?.snarkjs ?? "?"} (pinned ${EXPECTED_SNARKJS})`));
  out.push(ctx.kitFiles ? kitFilesCheck(t.tools?.kitFilesSha256, ctx.kitFiles) : { id: "tools.kitFiles", status: "skipped", detail: "committed kit hashes not given" });
  return out;
}

export function failed(checks: readonly Check[]): Check[] {
  return checks.filter((c) => c.status === "fail");
}

/**
 * The contribution list for records: index, hash, declared role and the coordinator's checks.
 * Names are left out (they are in the transcript and inside the zkey; whether to publish them is
 * the author's decision, and anonymised builds must not carry them).
 */
export function contributionsForRecord(t: CeremonyTranscript, external: readonly number[]) {
  return (t.contributions ?? []).map((c) => ({
    index: c.index,
    contributionHash: c.contributionHash,
    declaredExternal: external.includes(c.index),
    reportedHashMatched: c.reportedHashMatched ?? null,
    receiptMatched: c.receiptMatched ?? null,
    verifiedByContributor: c.verifiedByContributor ?? null,
    acceptedAtUtc: c.acceptedAtUtc ?? null,
  }));
}

/** Beacon facts for records (no names). */
export function beaconForRecord(t: CeremonyTranscript) {
  const s = t.beacon?.source ?? ({ kind: "missing" } as TranscriptBeaconSource);
  return {
    index: t.beacon?.index ?? null,
    kind: s.kind,
    round: s.round ?? null,
    height: s.height ?? null,
    chainHash: s.chainHash ?? null,
    expectedTimeUtc: s.expectedTimeUtc ?? null,
    plannedAtUtc: s.plannedAtUtc ?? null,
    announced: s.announced ?? null,
    value: t.beacon?.value ?? null,
    numIterationsExp: t.beacon?.numIterationsExp ?? null,
    contributionHash: t.beacon?.contributionHash ?? null,
    appliedAtUtc: t.beacon?.appliedAtUtc ?? null,
  };
}

// ------------------------------------------------------------------ snarkjs CLI `zkey verify` log

export interface VerifyEntry {
  index: number;
  name: string;
  contributionHash: string;
  type: "contribution" | "beacon";
  beaconHash?: string;
  numIterationsExp?: number;
}

export interface ParsedCliVerify {
  ok: boolean;
  circuitHash: string | null;
  contributions: VerifyEntry[];
}

// eslint-disable-next-line no-control-regex
const ANSI_RE = /\u001b\[[0-9;]*m/g;

export function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, "");
}

/**
 * Parse the console output of `snarkjs zkey verify <r1cs> <ptau> <zkey>` (snarkjs 0.7.4 CLI):
 * "[INFO]  snarkJS: contribution #N <name>:" followed by four lines of hex, "Beacon generator:",
 * "Beacon iterations Exp:", "Circuit Hash:" and "ZKey Ok!".
 */
export function parseCliVerify(text: string): ParsedCliVerify {
  const lines = stripAnsi(text).split(/\r?\n/);
  const body = (l: string) => l.replace(/^\s*\[(?:INFO|WARN|ERROR|DEBUG)\]\s+snarkJS:\s?/, "");
  let circuitHash: string | null = null;
  let ok = false;
  const contributions: VerifyEntry[] = [];
  let hexTarget: { set: (h: string) => void; acc: string; left: number } | null = null;
  for (const raw of lines) {
    const isLogLine = /^\s*\[(?:INFO|WARN|ERROR|DEBUG)\]/.test(raw);
    if (hexTarget && !isLogLine) {
      const hx = raw.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
      if (hx.length > 0) {
        hexTarget.acc += hx;
        hexTarget.left--;
        if (hexTarget.left === 0) {
          hexTarget.set(hexTarget.acc);
          hexTarget = null;
        }
        continue;
      }
    }
    if (hexTarget) {
      hexTarget.set(hexTarget.acc);
      hexTarget = null;
    }
    const l = body(raw).trimEnd();
    let m = /^Circuit Hash:\s*$/.exec(l);
    if (m) {
      hexTarget = { set: (h) => (circuitHash = h), acc: "", left: 4 };
      continue;
    }
    m = /^contribution #(\d+) ?(.*):$/.exec(l);
    if (m) {
      const e: VerifyEntry = { index: Number(m[1]), name: (m[2] ?? "").trim(), contributionHash: "", type: "contribution" };
      contributions.push(e);
      hexTarget = { set: (h) => (e.contributionHash = h), acc: "", left: 4 };
      continue;
    }
    const last = contributions[contributions.length - 1];
    m = /^Beacon generator: ([0-9a-fA-F]+)$/.exec(l);
    if (m && last) {
      last.type = "beacon";
      last.beaconHash = (m[1] as string).toLowerCase();
      continue;
    }
    m = /^Beacon iterations Exp: (\d+)$/.exec(l);
    if (m && last) {
      last.numIterationsExp = Number(m[1]);
      continue;
    }
    if (/^ZKey Ok!$/.test(l)) ok = true;
  }
  if (hexTarget) hexTarget.set(hexTarget.acc);
  contributions.sort((a, b) => a.index - b.index);
  return { ok, circuitHash, contributions };
}

/** The zkey's contribution list (from `zkey verify`) must equal the transcript: names, hashes, order, beacon. */
export function compareVerifyWithTranscript(t: CeremonyTranscript, v: ParsedCliVerify): Check[] {
  const out: Check[] = [];
  out.push(chk("zkeyVerify.ok", v.ok, v.ok ? "snarkjs printed 'ZKey Ok!'" : "snarkjs did not print 'ZKey Ok!'"));
  out.push(chk("zkeyVerify.circuitHash", v.circuitHash !== null && v.circuitHash === t.circuit?.circuitHash, `circuit hash ${v.circuitHash?.slice(0, 16) ?? "?"}... vs transcript ${t.circuit?.circuitHash?.slice(0, 16) ?? "?"}...`));
  const expected: VerifyEntry[] = [
    ...(t.contributions ?? []).map((c) => ({ index: c.index, name: c.name, contributionHash: c.contributionHash, type: "contribution" as const })),
    { index: t.beacon?.index, name: t.beacon?.name, contributionHash: t.beacon?.contributionHash, type: "beacon" as const, beaconHash: t.beacon?.value, numIterationsExp: t.beacon?.numIterationsExp },
  ];
  const sameList =
    v.contributions.length === expected.length &&
    expected.every((e, i) => {
      const g = v.contributions[i];
      if (!g || g.index !== e.index || g.name !== e.name || g.contributionHash !== e.contributionHash || g.type !== e.type) return false;
      return e.type !== "beacon" || (g.beaconHash === e.beaconHash && g.numIterationsExp === e.numIterationsExp);
    });
  out.push(chk("zkeyVerify.contributionList", sameList, `${v.contributions.length} entries in the zkey, ${expected.length} in the transcript (names, hashes, order, beacon value and iterations)`));
  const beacons = v.contributions.filter((c) => c.type === "beacon");
  out.push(chk("zkeyVerify.beaconLast", beacons.length === 1 && v.contributions[v.contributions.length - 1]?.type === "beacon", `${beacons.length} beacon entr${beacons.length === 1 ? "y" : "ies"}; the beacon must be the last entry`));
  return out;
}

/** Last line of `coordinator.mjs audit`: "[audit] ALL CHECKS PASSED" or "[audit] N CHECK(S) FAILED". */
export function parseAuditLog(text: string): { passed: boolean; failedChecks: string[]; passedChecks: number } {
  const lines = stripAnsi(text).split(/\r?\n/);
  const failedChecks = lines.filter((l) => l.startsWith("[audit] FAIL ")).map((l) => l.slice("[audit] FAIL ".length));
  const passedChecks = lines.filter((l) => l.startsWith("[audit] PASS ")).length;
  const passed = lines.some((l) => l.trim() === "[audit] ALL CHECKS PASSED") && failedChecks.length === 0 && passedChecks > 0;
  return { passed, failedChecks, passedChecks };
}

// ------------------------------------------------------------------ install targets and pins

export interface InstallTarget {
  role: "zkey" | "vkey" | "sol" | "transcript";
  /** Repo-relative target path. */
  rel: string;
  /** Pin entry name in setup/pins_v4.json style ("v4/<file name>"). */
  pinKey: string;
}

/** The new key files: <keyDir>/credential_auth_v4_<label>.zkey and friends (the rekey loader's names). */
export function installTargets(label: string, keyDirRel: string = KEY_DIR_REL): InstallTarget[] {
  checkLabel(label);
  const dir = cleanRel(keyDirRel, "key folder");
  const names = rekeyedNames(label);
  return (["zkey", "vkey", "sol", "transcript"] as const).map((role) => ({ role, rel: `${dir}/${names[role]}`, pinKey: `v4/${names[role]}` }));
}

/** Pins of a non-dev key live in their own file (setup/pins_v4.json keeps exactly the dev entries). */
export function pinsFileRel(label: string, dirRel = "setup"): string {
  checkLabel(label);
  return `${cleanRel(dirRel, "pins folder")}/pins_v4_${label}.json`;
}

/** Key spec of the end-to-end series (harness/v4/e2e/lib.ts loadKeySpec --key-spec). */
export function keySpecRel(label: string, dirRel = "setup"): string {
  checkLabel(label);
  return `${cleanRel(dirRel, "key spec folder")}/key_spec_v4_${label}.json`;
}

export interface PinEntry {
  sha256: string;
  label: string;
  path: string;
  note?: string;
}

/** Canonical pins text (setup/pins_v4.json format): JSON.stringify(_, null, 2) plus a newline. */
export const EMPTY_PINS_TEXT = "{}\n";

/**
 * Add pin entries to the text of a pins file (setup/pins_v4.json format). Existing entries are
 * never changed: a name that exists for the same file (sha256, label and path equal) is left as
 * it is, with its own note (a re-run has another run id in the note); any other difference
 * throws. Refuses a file that is not in that canonical format (it would be re-formatted). For a
 * new file pass EMPTY_PINS_TEXT.
 */
export function addPinEntries(text: string, entries: Record<string, PinEntry>): { text: string; added: string[]; unchanged: string[] } {
  const parsed = JSON.parse(text) as Record<string, unknown>;
  if (JSON.stringify(parsed, null, 2) + "\n" !== text) throw new Error("pins file is not in canonical JSON.stringify(_, null, 2) form; add the entries by hand");
  const added: string[] = [];
  const unchanged: string[] = [];
  const next: Record<string, unknown> = { ...parsed };
  for (const [k, e] of Object.entries(entries)) {
    if (!/^v4\/[A-Za-z0-9_.-]+$/.test(k)) throw new Error(`pin name ${k} must look like v4/<file name>`);
    if (!isHex(e.sha256, 32)) throw new Error(`pin ${k}: sha256 must be 32 bytes hex`);
    if (e.label === "dev") throw new Error(`pin ${k}: the dev label is reserved for the dev key`);
    if (k in parsed) {
      const have = parsed[k] as Partial<PinEntry> | null;
      if (have && have.sha256 === e.sha256 && have.label === e.label && have.path === e.path) unchanged.push(k);
      else throw new Error(`pin ${k} already exists with other content; existing pins are never rewritten`);
      continue;
    }
    if (Object.values(parsed).some((v) => (v as { path?: string })?.path === e.path)) throw new Error(`a pin entry for ${e.path} already exists under another name`);
    next[k] = e;
    added.push(k);
  }
  const out = JSON.stringify(next, null, 2) + "\n";
  const back = JSON.parse(out) as Record<string, unknown>;
  for (const [k, v] of Object.entries(parsed)) if (!isDeepStrictEqual(back[k], v)) throw new Error(`internal: existing pin ${k} changed`);
  return { text: out, added, unchanged };
}

/**
 * Text files that get pinned (verification key, Solidity verifier, transcript) must hold no CR
 * byte: with `* text=auto eol=lf` (.gitattributes) git would commit other bytes than the pinned
 * ones, and the pin would then fail in a fresh clone and in the WSL clone. Binary files (the
 * zkey, marked binary) are not checked.
 */
export function crProblems(files: ReadonlyArray<{ rel: string; bytes: Uint8Array }>): string[] {
  return files.filter((f) => /\.(json|sol)$/i.test(f.rel) && f.bytes.includes(13)).map((f) => `${f.rel} contains CR bytes (CRLF line ends); normalize it to LF in the ceremony folder, then re-run the kit audit (HANDOFF_STEPS step 5) and the follow-up`);
}

/**
 * The install must not touch the dev key: no target path or pin name may be one of the dev
 * pins (setup/pins_v4.json), and the new pins file must not be the dev pins file.
 */
export function assertNoDevOverlap(targets: readonly InstallTarget[], devPins: Record<string, { path?: string }>, pinsRel: string): void {
  if (cleanRel(pinsRel, "pins file") === DEV_PINS_REL) throw new Error(`${DEV_PINS_REL} holds the dev pins only; a ceremony key gets its own pins file`);
  const devPaths = new Set(Object.values(devPins).map((e) => e.path));
  for (const t of targets) {
    if (devPaths.has(t.rel)) throw new Error(`${t.rel} is a dev-key file; the ceremony key is never written over it`);
    if (t.pinKey in devPins) throw new Error(`pin name ${t.pinKey} is a dev pin`);
    if (/_dev\./.test(t.rel)) throw new Error(`${t.rel} carries the dev label`);
  }
}

/**
 * Key spec for the end-to-end series (harness/v4/e2e/lib.ts loadKeySpec): label plus wasm, zkey
 * and vkey, each pinned (the wasm in setup/pins_v4.json, the key in its own pins file).
 */
export function e2eKeySpec(label: string, keyDirRel: string = KEY_DIR_REL, pinsRel: string = pinsFileRel(label)) {
  const t = installTargets(label, keyDirRel);
  const by = (r: InstallTarget["role"]) => t.find((x) => x.role === r) as InstallTarget;
  return {
    label,
    wasm: { rel: FROZEN_WASM_REL, pin: { file: DEV_PINS_REL, key: "v4/credential_auth_v4.wasm" } },
    zkey: { rel: by("zkey").rel, pin: { file: pinsRel, key: by("zkey").pinKey } },
    vkey: { rel: by("vkey").rel, pin: { file: pinsRel, key: by("vkey").pinKey } },
  };
}

/** Key label text of the comparable-benchmark rows ("<label> key", as Phase D's "dev key"). */
export function cmpKeyLabel(label: string): string {
  checkLabel(label);
  return `${label} key`;
}

/** Flags of the comparable-benchmark runners (harness/v4/cmp/spec.ts v4KeyFromArgs). */
export function cmpKeyFlags(label: string, keyDirRel: string = KEY_DIR_REL, pinsRel: string = pinsFileRel(label)): string[] {
  const t = installTargets(label, keyDirRel);
  const by = (r: InstallTarget["role"]) => t.find((x) => x.role === r) as InstallTarget;
  return ["--v4-zkey", by("zkey").rel, "--v4-vkey", by("vkey").rel, "--v4-key-label", cmpKeyLabel(label), "--v4-pins", pinsRel];
}

/** Environment of scripts/cmp/quiet_window_cmp.sh for the same key. */
export function cmpKeyEnv(label: string, keyDirRel: string = KEY_DIR_REL, pinsRel: string = pinsFileRel(label)): Record<string, string> {
  const t = installTargets(label, keyDirRel);
  const by = (r: InstallTarget["role"]) => t.find((x) => x.role === r) as InstallTarget;
  return { PQID_CMP_V4_ZKEY: by("zkey").rel, PQID_CMP_V4_VKEY: by("vkey").rel, PQID_CMP_V4_LABEL: cmpKeyLabel(label), PQID_CMP_V4_PINS: pinsRel };
}

// ------------------------------------------------------------------ which series use the key

export interface KeyUse {
  series: string;
  where: string;
  keyBefore: string;
  afterCeremony: string;
  how: string;
}

/** One word for a POSIX shell (Git Bash): single-quoted unless it is only [A-Za-z0-9_./:=,-]. */
export function shellQuote(a: string): string {
  return /^[A-Za-z0-9_./:=,-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`;
}

export function shellJoin(args: readonly string[]): string {
  return args.map(shellQuote).join(" ");
}

/** Environment assignments for a command prefix: NAME=value with only the value quoted. */
export function shellEnv(env: Readonly<Record<string, string>>): string {
  return Object.entries(env)
    .map(([k, v]) => {
      if (!/^[A-Z_][A-Z0-9_]*$/.test(k)) throw new Error(`not an environment name: ${k}`);
      return `${k}=${shellQuote(v)}`;
    })
    .join(" ");
}

/**
 * Every series that proves or verifies with a v4 key, and what the ceremony changes (D-034).
 * The record of the follow-up carries this list; docs/v4/CEREMONY_FOLLOWUP.md prints it.
 */
export function keyUsers(label: string): KeyUse[] {
  const envText = shellEnv(cmpKeyEnv(label));
  return [
    { series: "C1 security suite", where: "Windows", keyBefore: "dev (results/v4/security_suite.json, run 10)", afterCeremony: `re-run by this follow-up with the ${label} key`, how: "harness/v4/ceremony/followup.ts suite step (new dated folder under results/v4/ceremony/)" },
    { series: "C3 mutation campaign", where: "Windows", keyBefore: "dev (results/v4/mutation.json, campaign 5)", afterCeremony: `re-run by this follow-up; verifier, wallet, registry and governance mutants use the ${label} key, circuit mutants keep their throwaway keys`, how: "harness/v4/ceremony/followup.ts mutation step" },
    { series: "Phase D warm, cold_v4 (results/v4/bench/)", where: "Windows snarkJS", keyBefore: "dev key", afterCeremony: "stay as they are (ledger-cited, labelled dev key); the v4 rows of cold_cmp and warm_cmp are the post-ceremony repeat (D-034)", how: "no rerun of the frozen runners (harness/v4/bench/lib.ts names the dev key)" },
    { series: "Phase D cold_v2v3", where: "Windows snarkJS", keyBefore: "no v4 key", afterCeremony: "not affected", how: "-" },
    { series: "Phase D warm_wsl, cold_rs_wsl (results/v4/bench_wsl/)", where: "WSL snarkJS and rapidsnark", keyBefore: "dev key", afterCeremony: `stay as they are; the WSL v4 Phase D repeat (D-034) uses the ${label} key`, how: "needs a runner that takes a non-dev key and rapidsnark in WSL (open: the frozen runners name the dev key; the cmp runners are snarkJS on Windows only)" },
    { series: "cmp cold_cmp, warm_cmp (results/v4/cmp/prove/)", where: "Windows snarkJS", keyBefore: "not run yet", afterCeremony: `v4 condition uses the ${label} key`, how: `node --import tsx harness/v4/cmp/inputs.ts ${shellJoin(cmpKeyFlags(label))} (then the same with --check); ${envText} bash scripts/cmp/quiet_window_cmp.sh` },
    { series: "cmp wallet_cmp", where: "Windows", keyBefore: "no key", afterCeremony: "not affected", how: "-" },
    { series: "e2e e2e_cold_wsl, e2e_warm_wsl (results/v4/e2e/)", where: "WSL, loopback Anvil and Besu", keyBefore: "not run yet (D-034: after the ceremony)", afterCeremony: `uses the ${label} key`, how: `scripts/e2e/quiet_window_e2e_wsl.sh --confirm-quiet --key-spec ${keySpecRel(label)} (started from Windows as docs/v4/E2E.md says; the WSL clone needs the key files, the pins file and the key spec at the same commit)` },
    { series: "e2e testnet and device campaigns", where: "the author (approval A4) / devices", keyBefore: "not run yet", afterCeremony: `use the ${label} key`, how: `--key-spec ${keySpecRel(label)}` },
    { series: "chain-read campaign (S4 verifier reads)", where: "WSL and Windows", keyBefore: "dev key (D-034: before the ceremony)", afterCeremony: "stays dev, labelled dev; not repeated", how: "-" },
    { series: "robustness load test and fuzzing", where: "Windows", keyBefore: "dev key (D-034: before the ceremony)", afterCeremony: "stays dev, labelled dev; not repeated", how: "-" },
    { series: "E4 verifier throughput (results/v4/scale/)", where: "Windows", keyBefore: "dev key", afterCeremony: "stays dev; not repeated", how: "-" },
    { series: "gas (results/v4/gas.json)", where: "Windows", keyBefore: "dev verifier contract", afterCeremony: "stays dev; not repeated by this follow-up", how: "-" },
    { series: "C2 analyzers", where: "-", keyBefore: "no key (circuit only)", afterCeremony: "not affected", how: "-" },
  ];
}

// ------------------------------------------------------------------ suite verdicts

/**
 * harness/v4/security_suite.ts is frozen (ledger-cited) and writes a fixed label text that says
 * "dev key", and its route T1 derives a trapdoor from the dev key's beacon (0102...1f20). Under
 * the rekey loader the authoritative fields are keyLabel and artifacts.zkey; the public-beacon
 * check for the new key's own beacon is the follow-up's keys step.
 */
export function suiteLabelNote(labelText: string, keyLabel: string): string {
  return `the label text ${JSON.stringify(labelText)} is fixed in the frozen harness/v4/security_suite.ts; this run used the ${keyLabel} key (fields keyLabel and artifacts.zkey). Route T1 there applies the dev key's public beacon (0102...1f20, 2^10) to this key; the check with this key's own beacon is in keys/key_checks.json (trapdoor)`;
}

export interface SuiteAttempt {
  route: string;
  accepted: boolean;
  valid: boolean;
  stoppedBy: { layer: string; checks: string[] };
  detail?: string;
}
export interface SuiteRecord {
  id: string;
  kind: string;
  attempts: SuiteAttempt[];
}
export interface SuiteFile {
  pass?: boolean;
  keyLabel?: string;
  summary?: Record<string, unknown>;
  records: SuiteRecord[];
  trapdoor?: unknown;
  standardThresholds?: unknown;
  pqc?: unknown;
}

/** Verdict per (record id, route), numbered on repeats (as artifact/compare_suite.py). */
export function suiteVerdicts(f: SuiteFile): Map<string, { accepted: boolean; valid: boolean; layer: string; checks: string }> {
  const out = new Map<string, { accepted: boolean; valid: boolean; layer: string; checks: string }>();
  for (const r of f.records) {
    for (const a of r.attempts) {
      let key = `${r.id}|${a.route}`;
      for (let n = 2; out.has(key); n++) key = `${r.id}|${a.route}#${n}`;
      out.set(key, { accepted: !!a.accepted, valid: !!a.valid, layer: String(a.stoppedBy?.layer), checks: [...(a.stoppedBy?.checks ?? [])].sort().join("+") });
    }
  }
  return out;
}

export interface SuiteComparison {
  verdictsBase: number;
  verdictsNew: number;
  /** accepted, valid or stopping layer differ (the rule of artifact/compare_suite.py). */
  verdictDiffs: string[];
  /** same verdict, different list of failed checks (reported, not a verdict difference). */
  checkDiffs: string[];
  summaryDiffs: string[];
  identical: boolean;
}

/** Summary fields compared by default (the ceremony follow-up). */
export const SUITE_SUMMARY_KEYS: readonly string[] = Object.freeze(["controlsAccepted", "v4AttackRoutes", "v4AttackRoutesAccepted", "v4AttackRoutesStoppedBy", "privacyRecords", "knownLimitations", "invalid", "cataloguedRoutesNotRun"]);

/**
 * Top-level outputs of the suite that must be identical when the key is the same (the post-fix
 * rerun): the public-beacon trapdoor check, the standard age thresholds and the PQC
 * implementation label (OpenSSL and Node versions).
 */
export const SUITE_STRICT_FIELDS: readonly ("trapdoor" | "standardThresholds" | "pqc")[] = Object.freeze(["trapdoor", "standardThresholds", "pqc"] as const);

/** The record list of a suite output: "<id>|<kind>|<number of attempts>" in order (ids repeat; records with no attempts count too). */
export function suiteRecordList(f: SuiteFile): string[] {
  return f.records.map((r) => `${r.id}|${r.kind}|${r.attempts.length}`);
}

/** Entries of `xs` not matched in `ys`, counting repeats (multiset difference). */
function multisetMinus(xs: readonly string[], ys: readonly string[]): string[] {
  const left = new Map<string, number>();
  for (const y of ys) left.set(y, (left.get(y) ?? 0) + 1);
  const out: string[] = [];
  for (const x of xs) {
    const n = left.get(x) ?? 0;
    if (n > 0) left.set(x, n - 1);
    else out.push(x);
  }
  return out;
}

/**
 * Compare two suite outputs. `allSummaryKeys` compares every summary field of either file, not
 * only SUITE_SUMMARY_KEYS. `strict` (the post-fix rerun with the dev key) implies it and also
 * compares SUITE_STRICT_FIELDS and the record list (id, kind, number of attempts, in order); each
 * difference goes into summaryDiffs.
 */
export function compareSuites(base: SuiteFile, next: SuiteFile, opts: { allSummaryKeys?: boolean; strict?: boolean } = {}): SuiteComparison {
  const a = suiteVerdicts(base);
  const b = suiteVerdicts(next);
  const verdictDiffs: string[] = [];
  const checkDiffs: string[] = [];
  for (const k of [...new Set([...a.keys(), ...b.keys()])].sort()) {
    const x = a.get(k);
    const y = b.get(k);
    if (!x || !y || x.accepted !== y.accepted || x.valid !== y.valid || x.layer !== y.layer) {
      verdictDiffs.push(`${k}: base ${x ? `${x.accepted}/${x.valid}/${x.layer}` : "missing"}, new ${y ? `${y.accepted}/${y.valid}/${y.layer}` : "missing"}`);
    } else if (x.checks !== y.checks) checkDiffs.push(`${k}: base [${x.checks}], new [${y.checks}]`);
  }
  const summaryDiffs: string[] = [];
  const sa = base.summary ?? {};
  const sb = next.summary ?? {};
  const keys = opts.allSummaryKeys || opts.strict ? [...new Set([...SUITE_SUMMARY_KEYS, ...Object.keys(sa), ...Object.keys(sb)])] : [...SUITE_SUMMARY_KEYS];
  for (const k of keys) {
    if (!isDeepStrictEqual(sa[k], sb[k])) summaryDiffs.push(`${k}: base ${JSON.stringify(sa[k])}, new ${JSON.stringify(sb[k])}`);
  }
  if (base.pass !== next.pass) summaryDiffs.push(`pass: base ${base.pass}, new ${next.pass}`);
  if (opts.strict) {
    for (const k of SUITE_STRICT_FIELDS) {
      if (!isDeepStrictEqual(base[k], next[k])) summaryDiffs.push(`${k} (top level): base ${JSON.stringify(base[k])}, new ${JSON.stringify(next[k])}`);
    }
    const la = suiteRecordList(base);
    const lb = suiteRecordList(next);
    if (!isDeepStrictEqual(la, lb)) {
      const onlyBase = multisetMinus(la, lb);
      const onlyNew = multisetMinus(lb, la);
      summaryDiffs.push(`records (id|kind|attempts): ${onlyBase.length === 0 && onlyNew.length === 0 ? "the same records in another order" : `only in base ${JSON.stringify(onlyBase)}, only in new ${JSON.stringify(onlyNew)}`}`);
    }
  }
  return { verdictsBase: a.size, verdictsNew: b.size, verdictDiffs, checkDiffs, summaryDiffs, identical: verdictDiffs.length === 0 && summaryDiffs.length === 0 };
}

export interface SuiteStepFacts {
  exit: number | null;
  pass: boolean | undefined;
  /** The output names the key of this run (label, files and SHA-256). */
  keyMatches: boolean;
  portClosed: boolean;
  vsDev: SuiteComparison;
  /** artifact/compare_suite.py: its exit (null when it timed out), or null when it could not start. */
  compareSuitePy: { exit: number | null } | null;
  /**
   * The post-fix rerun with the dev key: a different failed-check list or a different attack
   * matrix is a difference too (review). The ceremony follow-up reports them only.
   */
  strict: boolean;
  /** Strict mode: the run's attack_matrix.json deep-equals results/v4/attack_matrix.json (null: not compared). */
  attackMatrixEqual?: boolean | null;
}

/**
 * Status of the suite step: fail when the child failed, the suite did not pass, the output
 * names another key or the port stayed open; review on any difference from dev run 10; pass
 * otherwise. A difference is never dropped: it sets review.
 */
export function suiteStepStatus(f: SuiteStepFacts): StepStatus {
  if (f.exit !== 0 || f.pass !== true || !f.keyMatches || !f.portClosed) return "fail";
  if (!f.vsDev.identical || (f.compareSuitePy !== null && f.compareSuitePy.exit !== 0)) return "review";
  if (f.strict && (f.vsDev.checkDiffs.length > 0 || f.attackMatrixEqual !== true)) return "review";
  return "pass";
}

// ------------------------------------------------------------------ mutation rows (harness/v4/mutation.ts rules)

export interface MutationVerdict {
  kind: string;
  accepted: boolean;
  valid: boolean;
  stoppedBy: string;
  detail?: string;
}

/** harness/v4/mutation.ts verdicts(): keyed by "<record id>|<route>", later attempts overwrite earlier ones. */
export function mutationVerdicts(f: SuiteFile): Map<string, MutationVerdict> {
  const m = new Map<string, MutationVerdict>();
  for (const r of f.records) for (const a of r.attempts) m.set(`${r.id}|${a.route}`, { kind: r.kind, accepted: a.accepted, valid: a.valid, stoppedBy: `${a.stoppedBy.layer}:${a.stoppedBy.checks.join("+")}`, detail: a.detail });
  return m;
}

/** One row of the mutation table from the baseline and the mutant run (the loop body of harness/v4/mutation.ts). */
export function mutationRow(base: Map<string, MutationVerdict>, v: Map<string, MutationVerdict>) {
  const routesNowAccepted: string[] = [];
  const controlsBroken: string[] = [];
  const harnessErrors: string[] = [];
  const stoppedElsewhere: string[] = [];
  for (const [k, b] of base) {
    const x = v.get(k);
    if (!x) {
      harnessErrors.push(`${k}: missing`);
      continue;
    }
    if ((b.kind === "attack" || b.kind === "privacy") && !b.accepted && x.accepted) routesNowAccepted.push(k);
    else if (b.kind === "control" && b.accepted && !x.accepted) controlsBroken.push(`${k}: ${x.stoppedBy}`);
    else if (!x.accepted && b.stoppedBy !== x.stoppedBy) stoppedElsewhere.push(`${k}: ${b.stoppedBy} -> ${x.stoppedBy}`);
    if (b.valid && !x.valid && !x.accepted && x.detail?.startsWith("unexpected exception")) harnessErrors.push(`${k}: ${x.detail.slice(0, 200)}`);
  }
  return { routesNowAccepted, controlsBroken, stoppedElsewhere, harnessErrors };
}

export type DefenceKind = "circuit" | "verifier" | "wallet" | "registry" | "governance";

/** Repo-relative files of a mutant circuit and its throwaway key (harness/v4/mutate.ts buildMutant, harness/v4/mutation.ts mutantKey). */
export function mutantPaths(group: string) {
  if (!/^G\d\d_[a-z_]+$/.test(group)) throw new Error(`not a constraint group name: ${group}`);
  const dir = `${MUTANTS_DIR_REL}/${group}`;
  return {
    dir,
    r1cs: `${dir}/credential_auth_v4.r1cs`,
    sym: `${dir}/credential_auth_v4.sym`,
    wasm: `${dir}/credential_auth_v4_js/credential_auth_v4.wasm`,
    src: `${dir}/credential_auth_v4.circom`,
    attackerDir: `${dir}/attacker`,
    zkey: `${dir}/mutant_throwaway.zkey`,
    vkeyFile: `${dir}/mutant_throwaway_vkey.json`,
    stamp: `${dir}/mutant_throwaway.r1cs.sha256`,
  };
}

/** Repo-relative file of the registry contracts with one check removed (harness/v4/mutation.ts mutantContracts). */
export function mutantContractsRel(check: string): string {
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(check)) throw new Error(`not a registry check name: ${check}`);
  return `${MUTANTS_DIR_REL}/contracts/RegistriesV4__no_${check}.sol`;
}

/** harness/v4/mutation.ts mutantContracts() text rule: every `require(..., "<check>:...")` replaced by a comment. */
export function mutantContractsSource(src: string, check: string): { text: string; removed: number } {
  const re = new RegExp(`require\\((?:[^;]|\\n)*?"${check}:[^"]*"\\s*\\);`, "g");
  const removed = (src.match(re) ?? []).length;
  if (removed === 0) throw new Error(`no require for registry check ${check}`);
  return { text: src.replace(re, `/* [mutant] removed registry check ${check} */`), removed };
}

/** What the mutation I/O made for one defence: the mutant circuit files, or the mutant contracts file. */
export interface MutantBuilt {
  circuit?: Omit<ReturnType<typeof mutantPaths>, "dir" | "stamp">;
  contractsFile?: string;
}

/**
 * Suite config and extra environment of one mutant (harness/v4/mutation.ts prepare(), with
 * repo-relative paths). `built` carries what the I/O made: the mutant circuit files (circuit
 * defences) or the mutant contracts file (registry defences).
 */
export function mutantConfig(x: { kind: DefenceKind; name: string }, port: number, out: string, built: MutantBuilt = {}): { cfg: Record<string, unknown>; env: Record<string, string> } {
  const cfg: Record<string, unknown> = { name: `${x.kind}:${x.name}`, port, out };
  const env: Record<string, string> = {};
  if (x.kind === "circuit") {
    const c = built.circuit;
    if (!c) throw new Error(`circuit defence ${x.name}: mutant files missing`);
    cfg["mutantGroup"] = x.name;
    cfg["artifacts"] = { r1cs: c.r1cs, sym: c.sym, zkey: c.zkey, wasm: c.wasm, vkeyFile: c.vkeyFile, src: c.src, attackerDir: c.attackerDir, keyLabel: "mutant-throwaway" };
  } else if (x.kind === "verifier") cfg["verifierDisabled"] = [x.name];
  else if (x.kind === "wallet") cfg["walletDisabled"] = [x.name];
  else if (x.kind === "governance") cfg["governanceSkipPop"] = true;
  else if (x.kind === "registry") {
    if (!built.contractsFile) throw new Error(`registry defence ${x.name}: mutant contracts missing`);
    env["PQID_V4_CONTRACTS"] = built.contractsFile;
  }
  return { cfg, env };
}

/**
 * Status of the mutation step: fail on a run error, review when any row differs from campaign 5
 * (compareMutationTables also compares the harness-error lists, so a harness error that campaign
 * 5 had too, as in governance:issuerPopBeforeAccreditation, is not a difference), pass otherwise.
 */
export function mutationStatus(errors: readonly string[], vsDev: Pick<MutationComparison, "identical">): StepStatus {
  return errors.length > 0 ? "fail" : !vsDev.identical ? "review" : "pass";
}

/** Defences whose row lists harness errors (information; the comparison with campaign 5 decides the status). */
export function harnessErrorRows(rows: readonly MutationTableRow[]): string[] {
  return rows.filter((r) => Array.isArray(r.harnessErrors) && r.harnessErrors.length > 0).map((r) => `${r.kind}:${r.name}`);
}

export interface MutationTableRow {
  kind: string;
  name: string;
  error?: string;
  routesNowAccepted?: string[];
  controlsBroken?: string[];
  stoppedElsewhere?: string[];
  harnessErrors?: string[];
  [k: string]: unknown;
}
export interface MutationTable {
  rows: MutationTableRow[];
  noEffect?: string[];
}

export interface MutationComparison {
  defencesBase: number;
  defencesNew: number;
  missing: string[];
  extra: string[];
  differing: Array<{ defence: string; field: string; base: unknown; new: unknown }>;
  noEffectBase: string[];
  noEffectNew: string[];
  identical: boolean;
}

const sortStrings = (xs: unknown): string[] => (Array.isArray(xs) ? [...xs].map(String).sort() : []);

/**
 * Compare two mutation tables per defence: routes let through, honest controls broken, routes
 * stopped elsewhere, harness errors and run errors. With `only`, rows outside that set are not
 * expected in `next` (a partial run). With `exit` (the post-fix rerun with the dev key) the exit
 * code of each mutant suite run is compared too.
 */
export function compareMutationTables(base: MutationTable, next: MutationTable, only?: ReadonlySet<string>, opts: { exit?: boolean } = {}): MutationComparison {
  const key = (r: MutationTableRow) => `${r.kind}:${r.name}`;
  const inScope = (k: string) => !only || only.has(k) || only.has(k.split(":")[0] as string);
  const a = new Map(base.rows.filter((r) => inScope(key(r))).map((r) => [key(r), r]));
  const b = new Map(next.rows.map((r) => [key(r), r]));
  const differing: MutationComparison["differing"] = [];
  for (const [k, x] of a) {
    const y = b.get(k);
    if (!y) continue;
    for (const f of ["routesNowAccepted", "controlsBroken", "stoppedElsewhere", "harnessErrors"] as const) {
      if (!isDeepStrictEqual(sortStrings(x[f]), sortStrings(y[f]))) differing.push({ defence: k, field: f, base: sortStrings(x[f]), new: sortStrings(y[f]) });
    }
    if ("error" in x !== "error" in y) differing.push({ defence: k, field: "error", base: x.error ?? null, new: y.error ?? null });
    if (opts.exit && (x["exit"] ?? null) !== (y["exit"] ?? null)) differing.push({ defence: k, field: "exit", base: x["exit"] ?? null, new: y["exit"] ?? null });
  }
  const missing = [...a.keys()].filter((k) => !b.has(k)).sort();
  const extra = [...b.keys()].filter((k) => !a.has(k)).sort();
  const noEff = (t: MutationTable, scope: (k: string) => boolean) => sortStrings((t.noEffect ?? []).filter((k) => scope(k)));
  const noEffectBase = noEff(base, inScope);
  const noEffectNew = noEff(next, () => true);
  return {
    defencesBase: a.size,
    defencesNew: b.size,
    missing,
    extra,
    differing,
    noEffectBase,
    noEffectNew,
    identical: missing.length === 0 && extra.length === 0 && differing.length === 0 && isDeepStrictEqual(noEffectBase, noEffectNew),
  };
}

// ------------------------------------------------------------------ verification keys

export interface VkeyLike {
  vk_alpha_1: unknown;
  vk_beta_2: unknown;
  vk_gamma_2: unknown;
  vk_delta_2: unknown;
  IC: unknown;
  nPublic?: number;
}

/**
 * Two keys of the same r1cs and phase 1 share alpha, beta, gamma and IC (gamma is the generator
 * in snarkjs, so IC does not depend on phase 2); a different phase 2 shows only in delta.
 */
export function compareVkeys(a: VkeyLike, b: VkeyLike) {
  return {
    sameAlphaBetaGamma: isDeepStrictEqual(a.vk_alpha_1, b.vk_alpha_1) && isDeepStrictEqual(a.vk_beta_2, b.vk_beta_2) && isDeepStrictEqual(a.vk_gamma_2, b.vk_gamma_2),
    sameIC: isDeepStrictEqual(a.IC, b.IC),
    deltaDiffers: !isDeepStrictEqual(a.vk_delta_2, b.vk_delta_2),
  };
}

// ------------------------------------------------------------------ overall status

export type StepStatus = "pass" | "review" | "fail" | "skipped";

/**
 * Overall status: fail when any step failed; review when every step passed or was skipped but
 * at least one needs a person to look (for example a verdict that differs from the dev-key run);
 * pass otherwise. A run with every step skipped is "skipped".
 */
export function overallStatus(steps: Readonly<Record<string, StepStatus>>): StepStatus {
  const v = Object.values(steps);
  if (v.includes("fail")) return "fail";
  if (v.length === 0 || v.every((s) => s === "skipped")) return "skipped";
  if (v.includes("review")) return "review";
  return "pass";
}

/** Exit codes of followup.ts and scripts/ceremony/followup.sh. */
export const EXIT = Object.freeze({ pass: 0, fail: 1, usage: 2, refused: 3, stopped: 4, review: 5 });

/**
 * Exit code of a run that started (the preflight passed). A refusal after the start (a port that
 * became busy, an install target that appeared, the installed key changing) is "stopped" (4):
 * the run folder, logs and possibly installed files exist. A run where nothing ran is a failure.
 */
export function exitCode(status: StepStatus, refusedAfterStart: boolean): number {
  if (refusedAfterStart) return EXIT.stopped;
  return status === "pass" ? EXIT.pass : status === "review" ? EXIT.review : EXIT.fail;
}

/** "devrerun": the post-fix rerun with the pinned dev key (D-034 exception), see the end of this file. */
export type RunKind = "real" | "dry" | "check" | "devrerun";

export interface KeySwitch {
  readonly method: string;
  readonly packageDefaultKey: string;
}

/** How the ceremony-key suite and mutation runs reach the key (packages/v4 stays frozen and keeps the dev key as default). */
export const KEY_SWITCH: KeySwitch = Object.freeze({
  method: "harness/v4/ceremony/rekey.mjs (in-memory rewrite of packages/v4/src/paths.ts in the child process; no repository file changes)",
  packageDefaultKey: "dev",
});

/** The post-fix rerun needs no switch: the pinned dev key is the package default. */
export const DEV_KEY_SWITCH: KeySwitch = Object.freeze({
  method: "none: the pinned dev key is the default of packages/v4/src/paths.ts, so the children run without the rekey loader (rekey_probe.ts without the loader checks that they resolve the pinned dev files)",
  packageDefaultKey: "dev",
});

/** The key switch of a run: none for the dev key (the rekey loader refuses the dev label), the loader otherwise. */
export function keySwitchFor(label: string): KeySwitch {
  return label === DEV_LABEL ? DEV_KEY_SWITCH : KEY_SWITCH;
}

const STEP_TEXT: Readonly<Record<string, string>> = Object.freeze({
  verify: "verified (transcript rules, kit audit, snarkjs zkey verify)",
  keys: "key checks (proof round trip, same circuit and phase 1 as the dev key, no public-beacon trapdoor)",
  install: "installed on new paths and pinned in its own pins file",
  suite: "C1 security suite re-run with it under the rekey loader",
  mutation: "C3 mutation campaign re-run with it under the rekey loader",
});

const DEV_STEP_TEXT: Readonly<Record<string, string>> = Object.freeze({
  suite: "C1 security suite re-run with the pinned dev key, compared with dev run 10",
  mutation: "C3 mutation campaign re-run with the pinned dev key, compared with campaign 5",
});

/**
 * Record label built from the steps that completed (pass or review); a failed or skipped step is
 * not named. `scope` (the post-fix rerun): the steps and defences the run was asked for; a run
 * that leaves out a step or defences says PARTIAL and what it left out.
 */
export function recordLabel(kind: RunKind, label: string, ran: readonly string[], scope?: FixcheckScope): string {
  if (kind === "dry") return "DRY RUN on the rehearsal outputs (REHEARSAL ONLY); checks the follow-up itself; not a result, never quoted";
  if (kind === "check") return `CHECK ONLY: verify and key checks of the ${label} key before the real follow-up; not a result, never quoted`;
  if (kind === "devrerun") {
    const parts = ran.map((s) => DEV_STEP_TEXT[s]).filter((x): x is string => typeof x === "string");
    const partial = scope ? fixcheckPartial(scope) : null;
    return `[M] ${FIXCHECK_RUN_LABEL}, ${DEV_KEY_TEXT}${partial ? `, PARTIAL (${partial})` : ""}: ${parts.length ? parts.join("; ") : "no step completed"}`;
  }
  const parts = ran.map((s) => STEP_TEXT[s]).filter((x): x is string => typeof x === "string");
  return `[M] ceremony follow-up (TASKS I): ${label} key${parts.length ? `: ${parts.join("; ")}` : ": no step completed"}`;
}

/** Label of the mutation table of a run; a post-fix rerun with --only says PARTIAL and names the defences. */
export function mutationTableLabel(kind: RunKind, label: string, only?: ReadonlySet<string> | null): string {
  if (kind === "devrerun") {
    const partial = only && only.size > 0 ? `, PARTIAL (defences ${[...only].sort().join(", ")} only)` : "";
    return `[M] ${FIXCHECK_RUN_LABEL}, ${DEV_KEY_TEXT}${partial}: one defence removed at a time; whole v4 suite re-run per mutant with the pinned dev key (circuit mutants use throwaway keys)`;
  }
  return `[M] one defence removed at a time; whole v4 suite re-run per mutant with the ${label} key (circuit mutants use throwaway keys)`;
}

// ------------------------------------------------------------------ post-fix rerun with the dev key (D-034 exception)

/**
 * D-034: packages/v4 is frozen for the measurement period except for a fix of a defect found by
 * fuzzing; such a fix gets tests, the security suite and the mutation campaign again before any
 * timed series. `followup.ts --dev-rerun` runs the suite and mutation steps of the follow-up
 * with the pinned dev key (no rekey loader) into new paths and compares them with dev run 10 and
 * campaign 5. Verify, keys and install do not run: the dev key is unchanged and pinned.
 */
export const FIXCHECK_RESULTS_REL = "results/v4/fixcheck";
/** Log folders: verification/v4/fixcheck_<date>[_rN]/. */
export const FIXCHECK_LOG_PREFIX = `${LOG_DIR_REL}/fixcheck_`;
export const DEV_LABEL = "dev";
/** Every record of the post-fix rerun carries both texts. */
export const FIXCHECK_RUN_LABEL = "post-fix rerun (D-034)";
export const DEV_KEY_TEXT = "dev key";
export const DEV_ATTACK_MATRIX_REL = "results/v4/attack_matrix.json";
export const FIXCHECK_PURPOSE =
  "D-034: a packages/v4 fix of a defect found by fuzzing gets tests, the security suite and the mutation campaign again before any timed series; this run re-runs C1 and C3 with the unchanged, pinned dev key and compares them with dev run 10 and campaign 5";
export const FIXCHECK_EXPECTED =
  "a fix that touches only refusal paths outside the suite's routes leaves every verdict, summary field, failed-check list and attack-matrix cell equal to dev run 10 and every mutation row (with its exit code) equal to campaign 5; any difference is review and is listed, never dropped";

/** What a post-fix rerun was asked to run: its steps, its --only set and, without the suite step, its --baseline. */
export interface FixcheckScope {
  steps: readonly string[];
  only: ReadonlySet<string> | null;
  baselineRel?: string | null;
}

/**
 * What a post-fix rerun leaves out of D-034 (the suite step and the full mutation campaign, every
 * defence), as text; null when the run covers both.
 */
export function fixcheckPartial(scope: FixcheckScope): string | null {
  const parts: string[] = [];
  const suite = scope.steps.includes("suite");
  const mutation = scope.steps.includes("mutation");
  if (!suite) parts.push(`no suite step: mutation on ${scope.baselineRel ?? "the suite output of an earlier post-fix rerun"}`);
  if (!mutation) parts.push("no mutation step");
  if (mutation && scope.only && scope.only.size > 0) parts.push(`defences ${[...scope.only].sort().join(", ")} only`);
  return parts.length > 0 ? parts.join("; ") : null;
}

/**
 * The `next` list of a post-fix rerun record. Only a run with both steps and every defence (or a
 * full mutation-only run on the suite output of a post-fix rerun that passed on the same code,
 * checked before the start) can complete D-034; a partial pass says what is still missing.
 */
export function fixcheckNext(out: string, logs: string, status: string, scope: FixcheckScope): string[] {
  const common = [`commit ${out}/ and ${logs}/ (whatever the status: the record of the D-034 rerun is kept)`];
  const partial = fixcheckPartial(scope);
  const tail = "in DECISIONS with the fix, then the fuzz confirmation run (results/v4/BUSY) before any timed series";
  if (status === "pass") {
    if (partial === null) return [...common, `every verdict and every mutation row equals the dev runs: record it ${tail}`];
    if (!scope.steps.includes("mutation")) {
      return [...common, `PARTIAL post-fix rerun (${partial}): D-034 is not met yet; run the full mutation step on this suite output next: bash scripts/ceremony/followup.sh --dev-rerun --steps mutation --baseline ${out}/suite/security_suite.json`];
    }
    if (!scope.steps.includes("suite") && !(scope.only && scope.only.size > 0)) {
      return [...common, `every mutation row equals campaign 5, on ${scope.baselineRel ?? "the baseline"} (the suite output of a post-fix rerun whose suite step passed on the same code, checked before the start): the two runs together cover D-034; record both ${tail}`];
    }
    return [...common, `PARTIAL post-fix rerun (${partial}): D-034 is not met until the suite step and the full mutation step (every defence, no --only) have passed on the same committed code; a partial pass is not the D-034 rerun`];
  }
  const p = partial ? ` (partial: ${partial})` : "";
  if (status === "review") return [...common, `REVIEW${p}: read suite/vs_dev.json and mutation/vs_dev.json (each difference is listed); a person decides before any timed series; nothing here is hidden or re-run to make it go away`];
  return [...common, `FAIL${p}: read the log folder; no timed series until a rerun passes or the failure is explained in DECISIONS`];
}

/** Every record of the post-fix rerun names both texts; so do the suite and mutant config names (the frozen suite copies the name into its output's `config` field). */
export function fixcheckConfigName(name: string): string {
  return `${name}, ${DEV_KEY_TEXT}, ${FIXCHECK_RUN_LABEL}`;
}

/** Why the post-fix rerun refuses on the code state (it runs only committed code; there is no override). */
export function devRerunCodeProblems(dirty: readonly string[] | null): string[] {
  if (dirty === null) return ["git status could not be read, so the code state is unknown; the post-fix rerun runs only committed code"];
  if (dirty.length > 0) return [`the code the suite and mutation campaign run has uncommitted changes (${dirty.join(", ")}); commit the fix and the harness first (the post-fix rerun has no --allow-uncommitted)`];
  return [];
}

/**
 * Strict command line (the post-fix rerun): only the named options, each at most once. A boolean
 * takes no value (`--dry-run=yes` is refused), a value option needs a non-empty value (`--steps ""`,
 * `--steps=` and a trailing `--steps` are refused), and every other word is refused (`--dryrun`).
 */
export function parseStrictArgs(argv: readonly string[], booleans: readonly string[], values: readonly string[]): { flags: Set<string>; values: Map<string, string> } {
  const flags = new Set<string>();
  const vals = new Map<string, string>();
  const seen = new Set<string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    const m = /^--([A-Za-z][A-Za-z0-9-]*)(?:=([\s\S]*))?$/.exec(a);
    if (!m) throw new Error(`unexpected argument ${JSON.stringify(a)}`);
    const name = m[1] as string;
    const inline = m[2];
    if (seen.has(name)) throw new Error(`--${name} is given twice`);
    seen.add(name);
    if (booleans.includes(name)) {
      if (inline !== undefined) throw new Error(`--${name} takes no value (got ${JSON.stringify(a)})`);
      flags.add(name);
    } else if (values.includes(name)) {
      let v = inline;
      if (v === undefined) {
        const nextArg = argv[i + 1];
        if (nextArg === undefined || nextArg.startsWith("--")) throw new Error(`--${name} needs a value`);
        v = nextArg;
        i++;
      }
      if (v.trim().length === 0) throw new Error(`--${name} needs a non-empty value`);
      vals.set(name, v);
    } else {
      throw new Error(`unknown option --${name} (allowed: ${[...booleans, ...values].map((x) => `--${x}`).join(", ")})`);
    }
  }
  return { flags, values: vals };
}

/**
 * --date of a post-fix rerun: a real YYYY-MM-DD date within one day of the current UTC date (the
 * folder names the day of the run; one day either way fits any time zone). startedUtc still
 * records the real start time.
 */
export function checkRunDate(date: string, now: Date = new Date()): string {
  const t = /^\d{4}-\d{2}-\d{2}$/.test(date) ? Date.parse(`${date}T00:00:00Z`) : NaN;
  if (Number.isNaN(t) || utcDate(new Date(t)) !== date) throw new Error(`--date must be a date YYYY-MM-DD (got ${date})`);
  const today = utcDate(now);
  const days = Math.round((t - Date.parse(`${today}T00:00:00Z`)) / 86_400_000);
  if (Math.abs(days) > 1) throw new Error(`--date ${date} is not within one day of today's UTC date ${today}: the folder names the day of the run`);
  return date;
}

/** The six files of the pinned dev key, in setup/pins_v4.json order (r1cs and wasm are the frozen circuit). */
export const DEV_KEY_FILES: ReadonlyArray<{ role: "r1cs" | "wasm" | "zkey" | "vkey" | "sol" | "transcript"; pinKey: string; rel: string }> = Object.freeze([
  { role: "r1cs", pinKey: "v4/credential_auth_v4.r1cs", rel: FROZEN_R1CS_REL },
  { role: "wasm", pinKey: "v4/credential_auth_v4.wasm", rel: FROZEN_WASM_REL },
  { role: "zkey", pinKey: "v4/credential_auth_v4_dev.zkey", rel: DEV_ZKEY_REL },
  { role: "vkey", pinKey: "v4/verification_key_dev.json", rel: DEV_VKEY_REL },
  { role: "sol", pinKey: "v4/Groth16VerifierV4_dev.sol", rel: "setup/out/v4/Groth16VerifierV4_dev.sol" },
  { role: "transcript", pinKey: "v4/setup_transcript_dev.json", rel: "setup/out/v4/setup_transcript_dev.json" },
]);

export interface PinnedFile {
  role: string;
  file: string;
  sha256: string;
  pin: string;
}

/**
 * The pinned dev key: every file of DEV_KEY_FILES must have its setup/pins_v4.json entry with
 * label "dev" and the same path, and its bytes on disk must have the pinned SHA-256.
 * `shaOf(rel)` returns the SHA-256 of a repo-relative file, or null when it is missing.
 */
export function checkDevKeyPins(pins: Readonly<Record<string, { sha256?: string; label?: string; path?: string } | undefined>>, shaOf: (rel: string) => string | null): { files: PinnedFile[]; problems: string[] } {
  const files: PinnedFile[] = [];
  const problems: string[] = [];
  for (const f of DEV_KEY_FILES) {
    const pin = pins[f.pinKey];
    if (!pin) {
      problems.push(`${f.pinKey}: no entry in ${DEV_PINS_REL}`);
      continue;
    }
    if (pin.label !== DEV_LABEL) problems.push(`${f.pinKey}: label ${JSON.stringify(pin.label)}, expected "dev"`);
    if (pin.path !== f.rel) problems.push(`${f.pinKey}: path ${JSON.stringify(pin.path)}, expected ${f.rel}`);
    if (!isHex(pin.sha256, 32)) {
      problems.push(`${f.pinKey}: the pin holds no SHA-256`);
      continue;
    }
    const sha = shaOf(f.rel);
    if (sha === null) problems.push(`${f.rel}: missing`);
    else if (sha !== pin.sha256) problems.push(`${f.rel}: SHA-256 ${sha} differs from its pin ${pin.sha256}`);
    else files.push({ role: f.role, file: f.rel, sha256: sha, pin: `${DEV_PINS_REL}#${f.pinKey}` });
  }
  return { files, problems };
}

/**
 * The comparison basis of the post-fix rerun: dev run 10 must have been made with the pinned
 * dev key (keyLabel, r1cs, wasm, zkey, vkey), and campaign 5 must name run 10 as its baseline
 * (file and SHA-256). Otherwise the comparison would not be like for like.
 */
export function comparisonBasisProblems(
  run10: { keyLabel?: string; artifacts?: Record<string, { file?: string; sha256?: string } | undefined> } | null,
  run10Sha: string | null,
  campaign5: { baseline?: { file?: string; sha256?: string }; rows?: unknown[] } | null,
  pinned: readonly PinnedFile[]
): string[] {
  const out: string[] = [];
  if (!run10 || run10Sha === null) return [`${DEV_SUITE_REL} (dev run 10) missing`];
  if (run10.keyLabel !== DEV_LABEL) out.push(`${DEV_SUITE_REL}: keyLabel ${JSON.stringify(run10.keyLabel)}, expected "dev"`);
  for (const role of ["r1cs", "wasm", "zkey", "vkey"] as const) {
    const p = pinned.find((x) => x.role === role);
    const a = run10.artifacts?.[role];
    if (!p) out.push(`the pinned dev ${role} is not known`);
    else if (a?.file !== p.file || a?.sha256 !== p.sha256) out.push(`${DEV_SUITE_REL} was made with another ${role} (${a?.file ?? "?"} ${a?.sha256 ?? "?"}; pinned ${p.file} ${p.sha256})`);
  }
  if (!campaign5) return [...out, `${DEV_MUTATION_REL} (campaign 5) missing`];
  if (campaign5.baseline?.file !== DEV_SUITE_REL || campaign5.baseline?.sha256 !== run10Sha) out.push(`${DEV_MUTATION_REL}: baseline ${JSON.stringify(campaign5.baseline ?? null)} is not ${DEV_SUITE_REL} with SHA-256 ${run10Sha}`);
  if (!Array.isArray(campaign5.rows) || campaign5.rows.length === 0) out.push(`${DEV_MUTATION_REL}: no rows`);
  return out;
}

/**
 * Output and log folders of a post-fix rerun: results/v4/fixcheck/<date>[_rN]/ and
 * verification/v4/fixcheck_<date>[_rN]/, the first name free in both (never reused).
 */
export function fixcheckDirs(date: string, exists: (rel: string) => boolean): { name: string; out: string; logs: string } {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error(`date must be YYYY-MM-DD (got ${date})`);
  for (let n = 1; n < 1000; n++) {
    const name = n === 1 ? date : `${date}_r${n}`;
    const out = `${FIXCHECK_RESULTS_REL}/${name}`;
    const logs = `${FIXCHECK_LOG_PREFIX}${name}`;
    if (!exists(out) && !exists(logs)) return { name, out, logs };
  }
  throw new Error(`no free post-fix rerun folder for ${date}`);
}

/**
 * Ledger-cited dev-key results and frozen-runner outputs. A post-fix rerun never writes there:
 * results/v4/security_suite.json, attack_matrix.json, everything named results/v4/mutation*
 * (mutation.json, mutation_progress.json, mutation/, the run folders), results/v4/scale/,
 * results/v4/bench*, and the pins and key files under setup/.
 */
export function isProtectedResult(rel: string): boolean {
  const r = rel.replace(/\\/g, "/").replace(/^\.\//, "");
  return (
    r === DEV_SUITE_REL ||
    r === DEV_ATTACK_MATRIX_REL ||
    /^results\/v4\/mutation/.test(r) ||
    /^results\/v4\/(?:scale|bench[^/]*)(?:\/|$)/.test(r) ||
    /^setup(?:\/|$)/.test(r)
  );
}

/** A path the post-fix rerun may write: under results/v4/fixcheck/<run>/ or verification/v4/fixcheck_<run>/, and not protected. */
export function assertFixcheckOutput(rel: string): string {
  const r = cleanRel(rel, "post-fix rerun output");
  const runRe = /^\d{4}-\d{2}-\d{2}(?:_r\d+)?(?:\/|$)/;
  const underResults = r.startsWith(`${FIXCHECK_RESULTS_REL}/`) && runRe.test(r.slice(FIXCHECK_RESULTS_REL.length + 1));
  const underLogs = r.startsWith(FIXCHECK_LOG_PREFIX) && runRe.test(r.slice(FIXCHECK_LOG_PREFIX.length));
  if (!(underResults || underLogs) || isProtectedResult(r)) throw new Error(`${r}: a post-fix rerun writes only under ${FIXCHECK_RESULTS_REL}/<date>[_rN]/ and ${FIXCHECK_LOG_PREFIX}<date>[_rN]/`);
  return r;
}

/**
 * --baseline of a mutation-only post-fix rerun: the suite output of an earlier post-fix rerun
 * (results/v4/fixcheck/<date>[_rN]/suite/security_suite.json). Never dev run 10, which ran the
 * code before the fix.
 */
export function checkFixcheckBaseline(rel: string): string {
  const r = cleanRel(rel, "--baseline");
  if (!/^results\/v4\/fixcheck\/\d{4}-\d{2}-\d{2}(?:_r\d+)?\/suite\/security_suite\.json$/.test(r)) {
    throw new Error(`--baseline of a post-fix rerun must be the suite output of a post-fix rerun (${FIXCHECK_RESULTS_REL}/<date>[_rN]/suite/security_suite.json), not ${r}`);
  }
  return r;
}

/** The record (fixcheck.json) and the suite comparison (suite/vs_dev.json) of the post-fix rerun that wrote a --baseline. */
export function fixcheckBaselineFiles(baselineRel: string): { record: string; vsDev: string } {
  const run = checkFixcheckBaseline(baselineRel).slice(0, -"/suite/security_suite.json".length);
  return { record: `${run}/fixcheck.json`, vsDev: `${run}/suite/vs_dev.json` };
}

/** The fields of an earlier post-fix rerun record that a mutation-only rerun checks. */
export interface FixcheckRecordLike {
  schema?: string;
  steps?: Record<string, string | undefined>;
  suite?: { status?: string; file?: string | null };
  code?: { gitHead?: string | null; uncommitted?: unknown };
}

/**
 * --baseline of a mutation-only post-fix rerun, beyond its name and key: the earlier run's record
 * must show a suite step that passed (equal to dev run 10 under the strict rules) and wrote this
 * file, on committed code; the file must still have the SHA-256 its suite comparison recorded; and
 * no file under CODE_PATHS may have changed between that run's commit and HEAD (`changedSince`:
 * the changed files, null when git could not tell). Result commits in between are fine.
 */
export function fixcheckBaselineProblems(
  baselineRel: string,
  rec: FixcheckRecordLike | null,
  recordedSha: string | null,
  fileSha: string | null,
  changedSince: readonly string[] | null
): string[] {
  const f = fixcheckBaselineFiles(baselineRel);
  if (!rec) return [`${f.record} missing or unreadable: the baseline's post-fix rerun left no record`];
  const out: string[] = [];
  if (rec.schema !== "pqid/v4-fixcheck/v1") out.push(`${f.record}: schema ${JSON.stringify(rec.schema)}, not a post-fix rerun record`);
  if (rec.steps?.["suite"] !== "pass" || rec.suite?.status !== "pass") out.push(`${f.record}: its suite step is ${JSON.stringify(rec.steps?.["suite"] ?? rec.suite?.status ?? null)}, not pass (a mutation baseline must be a suite run equal to dev run 10)`);
  if (rec.suite?.file !== baselineRel) out.push(`${f.record}: its suite output is ${JSON.stringify(rec.suite?.file ?? null)}, not ${baselineRel}`);
  if (fileSha === null) out.push(`${baselineRel} missing`);
  else if (recordedSha === null) out.push(`${f.vsDev} names no SHA-256 for ${baselineRel}`);
  else if (recordedSha !== fileSha) out.push(`${baselineRel} changed after its run (SHA-256 ${fileSha}, recorded ${recordedSha})`);
  if (!Array.isArray(rec.code?.uncommitted) || rec.code.uncommitted.length > 0) out.push(`${f.record}: the run's code state was uncommitted or unknown`);
  const head = rec.code?.gitHead ?? null;
  if (!head) out.push(`${f.record}: names no commit`);
  else if (changedSince === null) out.push(`git could not compare the code at ${head} with HEAD`);
  else if (changedSince.length > 0) out.push(`the code changed since the baseline's run at ${head} (${changedSince.join(", ")}); run the suite step again`);
  return out;
}

/** What rekey_probe.ts prints (structural copy, so this file stays free of package imports). */
export interface ProbeLike {
  rekeyLabel: string | null;
  keyLabel: string;
  zkey: string;
  vkey: string;
  proveDefault: { zkey: string; keyLabel: string };
  vkeyParses: boolean;
}

/**
 * The probe child resolves the key of the run: with the rekey loader the rewritten label and
 * files; without it (the dev key) no rewrite at all and the dev files.
 */
export function probeResolvesKey(p: ProbeLike, k: { label: string; zkey: { file: string }; vkey: { file: string } }, viaLoader: boolean): boolean {
  const rewrite = viaLoader ? p.rekeyLabel === k.label && k.label !== DEV_LABEL : p.rekeyLabel === null && k.label === DEV_LABEL;
  return rewrite && p.keyLabel === k.label && p.zkey === k.zkey.file && p.vkey === k.vkey.file && p.proveDefault.zkey === k.zkey.file && p.proveDefault.keyLabel === k.label && p.vkeyParses === true;
}
