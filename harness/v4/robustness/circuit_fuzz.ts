import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import type { Poseidon } from "circomlibjs";
import { poseidonBig } from "@pqid/common/encoding";
import { getPoseidon, revKeyFromCredId, credTypeField } from "@pqid/v4/encoding";
import { IndexedMerkleTree } from "@pqid/v4/imt";
import { DEFAULT_TYPE_ID, IMT_MAX } from "@pqid/v4/constants";
import { R1CS_V4, WASM_V4, SYM_V4, ZKEY_V4, VKEY_V4, PINS_V4, CIRCUIT_INFO_V4 } from "@pqid/v4/paths";
import { envInfo, gitHead, sanitize, rel, utcNow, writeJson, flag, opt, optNum, sha256FileHex, appendJsonl } from "../bench/lib.ts";
import { acquireMarker, assertMarkersFree, markerRoots, windowsRepoFromArgs } from "../lib/markers.ts";
import { SEEDS } from "../lib/seeds.ts";
import { readR1cs, readSym, readWtns, writeWtns, checkR1cs, attackerSource, buildAttackerGenerator, attackerWitnessO0, mapToReal, constraintGroup, V4_SRC, ATTACKER_DIR, P as FIELD_P } from "../r1cs_tools.ts";
import { caseRng, type Rng } from "./rng.ts";
import { relationR4, refAddDays, refIsValidYmd, daysFromCivil, civilFromDays } from "./oracles.ts";
import { robustnessRoot, protocolRecord, assertCommitted, budgetDeviation } from "./common.ts";

/**
 * Bounded circuit and witness fuzz of relation R4 (circuits/credential_auth_v4.circom, frozen at
 * B7; dev key). Untimed; a full campaign holds results/v4/BUSY (D-034). Seed: robustness.circuitFuzz
 * 20261023 (harness/v4/lib/seeds.ts).
 *
 *   node --import tsx harness/v4/robustness/circuit_fuzz.ts --campaign <name> [--deviation "<text>" --cases N --mutations N --prove N]
 *   node --import tsx harness/v4/robustness/circuit_fuzz.ts --smoke [--cases N --mutations N --prove N]
 *   node --import tsx harness/v4/robustness/circuit_fuzz.ts --replay <failures/....json>
 * A full run uses the pre-registered budgets (300 cases, 5,000 mutations, 15 + 15 proofs); another
 * budget needs --deviation (recorded in plan.json and appended to the protocol's Deviations).
 *
 * Read-only guard: the R1CS, wasm, zkey and vkey are hashed against setup/pins_v4.json and the
 * sym file against circuits/build/v4/circuit_info.json before anything runs; nothing under
 * circuits/ is written. The tracked attacker generator (circuits/build/v4/attacker) is used only
 * when its source equals attackerSource(the frozen circuit) and its wasm exists; otherwise a fresh
 * one is compiled into the OS temp directory.
 *
 * Per case (about half aimed at true statements; values at every constraint-group boundary):
 *  (a) the reference wasm witness exists exactly when the JS relation model (oracles.ts relationR4)
 *      says the statement is true; then the real R1CS is satisfied and the 8 public wires equal
 *      the inputs;
 *  (b) the attacker generator's witness (every @check removed, --O0), mapped to the real layout,
 *      satisfies the real R1CS exactly when the model says true ("generator refused", for example
 *      a Num2Bits range, is allowed for false statements only);
 *  (c) a few true and false cases are proved with the dev zkey: each verifies exactly when true.
 * Witness mutation: random edits of 1 to 3 wires of honest witnesses (reference witnesses that
 * satisfy the real R1CS with the right public wires); the real R1CS must reject the edit unless it
 * leaves every input wire (public and private) unchanged, in which case the edited wires are free
 * hint wires and are recorded by name. A satisfied edit that changes a public wire is a critical
 * failure; one that changes only private inputs is a failure of its own class. Each failure file
 * holds the base case's circuit input and every edit (wire, name, kind, old and new value), so
 * --replay rebuilds the base witness, applies the edits and re-checks the real R1CS.
 */
const REGISTERED = Object.freeze({ cases: 300, mutations: 5000, prove: 15 });

const SELF = fileURLToPath(import.meta.url);
const MASTER = SEEDS.robustness.circuitFuzz;
const N_PUBLIC = 8;
const N_INPUT_WIRES = 85; // wires 1..85: 8 public + 77 private inputs (circuit_info.json)
const STD = [13, 14, 15, 16, 18, 21, 65];

type Input = Record<string, string | string[]>;

interface CaseSpec {
  index: number;
  aims: string[];
  input: Input;
  model: { satisfiable: boolean; failing: string[] };
}

// ------------------------------------------------------------------ guard

function checkArtifacts(): Record<string, { sha256: string; pinned: string; ok: boolean }> {
  const pins = JSON.parse(fs.readFileSync(PINS_V4, "utf8")) as Record<string, { sha256: string }>;
  const info = JSON.parse(fs.readFileSync(CIRCUIT_INFO_V4, "utf8")) as { symSha256: string };
  const items: Array<[string, string, string]> = [
    ["r1cs", R1CS_V4, pins["v4/credential_auth_v4.r1cs"]?.sha256 ?? ""],
    ["wasm", WASM_V4, pins["v4/credential_auth_v4.wasm"]?.sha256 ?? ""],
    ["zkey", ZKEY_V4, pins["v4/credential_auth_v4_dev.zkey"]?.sha256 ?? ""],
    ["vkey", VKEY_V4, pins["v4/verification_key_dev.json"]?.sha256 ?? ""],
    ["sym", SYM_V4, info.symSha256],
  ];
  const out: Record<string, { sha256: string; pinned: string; ok: boolean }> = {};
  for (const [k, f, pin] of items) {
    const sha = sha256FileHex(f);
    out[k] = { sha256: sha, pinned: pin, ok: sha === pin };
    if (sha !== pin) throw new Error(`${rel(f)} sha256 ${sha} differs from its pin ${pin}: the frozen circuit or dev key changed`);
  }
  return out;
}

/** The attacker generator: the tracked copy when it is current, else a fresh build in the OS temp dir. */
function attackerGenerator(log: (s: string) => void): { g: ReturnType<typeof buildAttackerGenerator>; source: string } {
  const want = attackerSource(fs.readFileSync(V4_SRC, "utf8")).replace(/\r\n/g, "\n");
  const trackedSrc = path.join(ATTACKER_DIR, "credential_auth_v4_attacker.circom");
  const trackedWasm = path.join(ATTACKER_DIR, "credential_auth_v4_attacker_js", "credential_auth_v4_attacker.wasm");
  if (fs.existsSync(trackedSrc) && fs.existsSync(trackedWasm) && fs.readFileSync(trackedSrc, "utf8").replace(/\r\n/g, "\n") === want) {
    // current: buildAttackerGenerator would not rebuild; compare exactly as it does before calling it
    if (fs.readFileSync(trackedSrc, "utf8") === attackerSource(fs.readFileSync(V4_SRC, "utf8"))) {
      return { g: buildAttackerGenerator(), source: "tracked circuits/build/v4/attacker (current; not rebuilt)" };
    }
  }
  const dir = path.join(os.tmpdir(), `pqid-v4-attacker-${randomBytes(4).toString("hex")}`);
  log("attacker generator: tracked copy is not current; compiling a fresh one into the OS temp directory");
  return { g: buildAttackerGenerator(V4_SRC, dir), source: "fresh build in the OS temp directory (tracked copy not current)" };
}

// ------------------------------------------------------------------ case generation

function ymdOf(z: number): number {
  const c = civilFromDays(z);
  return c.y * 10000 + c.m * 100 + c.d;
}

function dayOf(d: number): number {
  return daysFromCivil(Math.floor(d / 10000), Math.floor((d % 10000) / 100), d % 100);
}

/** One generated case (exported for replay tooling and checks; the runner draws case i from caseRng(MASTER, "circuit-case", i)). */
export async function genCase(rng: Rng, index: number, p: Poseidon, defaultType: bigint): Promise<CaseSpec> {
  const h = (xs: bigint[]) => poseidonBig(p, xs);
  const aims: string[] = [];
  const wantTrue = rng.bool(0.5);
  // ---- an honest statement
  const today = ymdOf(rng.int(dayOf(20000101), dayOf(20991231)));
  const from = refAddDays(today, -rng.int(0, 1));
  const to = refAddDays(from, 1);
  const predicate = rng.pick([1, 2]);
  const threshold = rng.pick(STD);
  // a birth date that satisfies the predicate (age_gte: old enough; age_lt: too young)
  let birth = predicate === 1 ? refAddDays(today - 10000 * threshold, -rng.int(0, 20000)) : refAddDays(today - 10000 * threshold, rng.int(1, 3000));
  if (!refIsValidYmd(birth)) birth = predicate === 1 ? 19000301 : refAddDays(today, -1);
  let expiry = refAddDays(today, rng.int(0, 3000));
  const credType = defaultType;
  let requiredType = defaultType;
  let pc = BigInt(predicate);
  let thr = BigInt(threshold);
  let todayB = BigInt(today);
  let fromB = BigInt(from);
  let toB = BigInt(to);
  const credId = rng.bytes(32);
  const hi = BigInt("0x" + credId.subarray(0, 16).toString("hex"));
  const lo = BigInt("0x" + credId.subarray(16).toString("hex"));
  let holderSecret = rng.bigBelow(FIELD_P);
  const leafSecret = holderSecret;
  const issuerKeyHash = rng.bigBelow(FIELD_P);
  const domainTag = rng.bigBelow(FIELD_P);
  const nonce = rng.bigBits(248);
  // ---- boundary perturbations (the true half keeps them on the true side)
  const which = rng.weighted<string>([
    [3, "age"],
    [2, "expiry"],
    [2, "window"],
    [2, "threshold"],
    [1, "predicateCode"],
    [1, "type"],
    [2, "revocation"],
    [1, "issRoot"],
    [1, "holder"],
    [1, "policy"],
    [1, "stmt"],
    [1, "ranges"],
  ]);
  aims.push(which);
  let revMode: "correct" | "nonBracketing" | "stale" | "forged" = "correct";
  let foreignIssRoot = false;
  let badPolicy = false;
  let badStmt = false;
  switch (which) {
    case "age": {
      const leap = rng.bool(0.25);
      const delta = rng.pick([0, 1, 2]) * (rng.bool() ? 1 : -1);
      const anniv = today - 10000 * threshold;
      let b = leap ? Math.floor(anniv / 10000) * 10000 + 229 : anniv;
      if (!refIsValidYmd(b)) b = Math.floor(anniv / 10000) * 10000 + 228;
      if (refIsValidYmd(b)) birth = refAddDays(b, delta);
      aims.push(`birth at today - 10000t ${delta >= 0 ? "+" : ""}${delta} day${leap ? " (29 Feb)" : ""}`);
      break;
    }
    case "expiry":
      expiry = refAddDays(today, rng.pick([0, 1, -1]));
      aims.push(`expiry ${expiry - today >= 0 ? "on/after" : "before"} today`);
      break;
    case "window": {
      const at = rng.pick(["from-1", "from", "to", "to+1"]);
      if (at === "from-1") fromB = BigInt(refAddDays(today, 1));
      else if (at === "from") fromB = BigInt(today);
      else if (at === "to") toB = BigInt(today);
      else toB = BigInt(refAddDays(today, -1));
      if (at === "from-1") toB = BigInt(refAddDays(Number(fromB), 1));
      if (at === "to+1") fromB = BigInt(refAddDays(Number(toB), -1));
      aims.push(`today at ${at}`);
      break;
    }
    case "threshold":
      thr = BigInt(wantTrue ? rng.pick(STD) : rng.pick([0, 12, 17, 19, 20, 22, 64, 66, 255, 256, 1000]));
      aims.push(`threshold ${thr}`);
      break;
    case "predicateCode":
      pc = wantTrue ? pc : rng.pick([0n, 3n, rng.bigBelow(FIELD_P)]);
      aims.push(`predicateCode ${pc.toString().slice(0, 12)}`);
      break;
    case "type":
      if (!wantTrue) requiredType = rng.bigBelow(FIELD_P);
      aims.push(wantTrue ? "credType = requiredType" : "credType != requiredType");
      break;
    case "revocation":
      revMode = wantTrue ? "correct" : rng.pick(["nonBracketing", "stale", "forged"] as const);
      aims.push(`IMT opening ${revMode}`);
      break;
    case "issRoot":
      foreignIssRoot = !wantTrue;
      aims.push(foreignIssRoot ? "foreign issRoot" : "own issRoot");
      break;
    case "holder":
      if (!wantTrue) holderSecret = rng.bigBelow(FIELD_P);
      aims.push(wantTrue ? "holder secret matches" : "holder secret mismatch");
      break;
    case "policy":
      badPolicy = !wantTrue;
      aims.push(badPolicy ? "policyHash inconsistent" : "policyHash consistent");
      break;
    case "stmt":
      badStmt = !wantTrue;
      aims.push(badStmt ? "stmtCode inconsistent" : "stmtCode consistent");
      break;
    case "ranges": {
      if (!wantTrue) {
        const f = rng.pick(["birth", "expiry", "today"]);
        const big = BigInt(1 << 27) + BigInt(rng.int(0, 5));
        if (f === "birth") birth = Number(big);
        else if (f === "expiry") expiry = Number(big);
        else todayB = big;
        aims.push(`${f} >= 2^27`);
      } else aims.push("ranges respected");
      break;
    }
  }
  // ---- issuance tree opening (sparse path: random or zero siblings)
  const leaf = h([1004n, issuerKeyHash, hi, lo, h([leafSecret]), BigInt(birth), BigInt(expiry), credType]);
  const issIndex = BigInt(rng.int(0, 2 ** 32 - 1));
  const issPath: bigint[] = [];
  let z = 0n;
  let cur = leaf;
  for (let l = 0; l < 32; l++) {
    const sib = rng.bool(0.15) ? rng.bigBelow(FIELD_P) : z;
    issPath.push(sib);
    cur = ((issIndex >> BigInt(l)) & 1n) === 0n ? h([cur, sib]) : h([sib, cur]);
    z = h([z, z]);
  }
  const issRoot = foreignIssRoot ? rng.bigBelow(FIELD_P) : cur;
  const b = { issIndex, issPath, issRoot, birth, expiry, credType, requiredType, pc, thr, todayB, fromB, toB, hi, lo, holderSecret, issuerKeyHash, domainTag, nonce, revMode, badPolicy, badStmt, credId };
  // ---- revocation IMT with 1..20 random keys (the credential's revKey not among them)
  const revKey = revKeyFromCredId(b.credId);
  const keys = new Set<bigint>();
  const nk = rng.int(1, 20);
  while (keys.size < nk) {
    const k = 1n + rng.bigBelow(IMT_MAX - 1n);
    if (k !== revKey) keys.add(k);
  }
  const tree = await IndexedMerkleTree.bulkBuild([...keys], 30);
  let w = tree.nonMembershipWitness(revKey);
  let revRoot = BigInt(w.root);
  if (b.revMode === "nonBracketing") {
    const lowIdx = Number(w.lowIndex);
    const others = Array.from({ length: tree.size }, (_, i) => i).filter((i) => i !== lowIdx);
    w = tree.openLeaf(rng.pick(others));
  } else if (b.revMode === "stale") {
    revRoot = BigInt((await IndexedMerkleTree.bulkBuild([...keys].slice(1), 30)).root());
  } else if (b.revMode === "forged") {
    const lv = BigInt(w.lowValue);
    // a forged low leaf that brackets the key, under the real path: its hash is not in the tree
    w = { ...w, lowNext: (revKey + 1n).toString(), lowValue: (lv < revKey ? lv : 0n).toString() };
  }
  const policyHash = b.badPolicy ? rng.bigBelow(FIELD_P) : h([1006n, b.pc, b.thr, b.todayB, b.requiredType]);
  const stmtCode = b.badStmt ? h([5n, b.domainTag]) : h([4n, b.domainTag]);
  const input: Input = {
    issuerKeyHash: b.issuerKeyHash.toString(),
    revRoot: revRoot.toString(),
    policyHash: policyHash.toString(),
    nonce: b.nonce.toString(),
    stmtCode: stmtCode.toString(),
    issRoot: b.issRoot.toString(),
    epochFromDate: b.fromB.toString(),
    epochToDate: b.toB.toString(),
    credIDHi: b.hi.toString(),
    credIDLo: b.lo.toString(),
    holderSecret: b.holderSecret.toString(),
    birthDate: String(b.birth),
    expiryDate: String(b.expiry),
    credType: b.credType.toString(),
    predicateCode: b.pc.toString(),
    threshold: b.thr.toString(),
    today: b.todayB.toString(),
    requiredType: b.requiredType.toString(),
    domainTag: b.domainTag.toString(),
    issLeafIndex: b.issIndex.toString(),
    issPathElements: b.issPath.map(String),
    revLowIndex: w.lowIndex,
    revLowValue: w.lowValue,
    revLowNext: w.lowNext,
    revLowPath: w.lowPath,
  };
  const model = relationR4(modelInputs(input), (xs) => h(xs));
  return { index, aims, input, model };
}

function modelInputs(input: Input): Record<string, bigint | bigint[]> {
  const m: Record<string, bigint | bigint[]> = {};
  for (const [k, v] of Object.entries(input)) m[k] = Array.isArray(v) ? v.map((x) => BigInt(x)) : BigInt(v);
  return m;
}

// ------------------------------------------------------------------ witness helpers

async function referenceWitness(input: Input): Promise<{ ok: true; w: bigint[] } | { ok: false; error: string }> {
  const snarkjs = await import("snarkjs");
  const tmp = path.join(os.tmpdir(), `pqid-v4-cfz-${randomBytes(6).toString("hex")}.wtns`);
  try {
    await (snarkjs.wtns as unknown as { calculate(i: unknown, wasm: string, out: string): Promise<void> }).calculate(input, WASM_V4, tmp);
    return { ok: true, w: readWtns(tmp) };
  } catch (e) {
    return { ok: false, error: assertLine((e as Error).message) };
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

function assertLine(msg: string): string {
  const m = /Error in template (\w+)_\d+ line: (\d+)/.exec(msg);
  return m ? `${m[1]} line ${m[2]}` : sanitize(msg.split("\n")[0] ?? "").slice(0, 160);
}

/** Constraint indices touching each wire (for incremental re-checks of mutated witnesses). */
function constraintIndex(r: ReturnType<typeof readR1cs>): Map<number, number[]> {
  const idx = new Map<number, number[]>();
  r.constraints.forEach((c, i) => {
    const seen = new Set<number>();
    for (const lc of c) for (const w of lc.keys()) seen.add(w);
    for (const w of seen) {
      const a = idx.get(w);
      if (a) a.push(i);
      else idx.set(w, [i]);
    }
  });
  return idx;
}

function constraintHolds(c: ReturnType<typeof readR1cs>["constraints"][number], w: bigint[]): boolean {
  const ev = (m: Map<number, bigint>) => {
    let s = 0n;
    for (const [k, v] of m) s += v * (w[k] as bigint);
    return s % FIELD_P;
  };
  return (ev(c[0]) * ev(c[1])) % FIELD_P === ev(c[2]);
}

// ------------------------------------------------------------------ main

interface Totals {
  cases: number;
  modelTrue: number;
  modelFalse: number;
  referenceAgrees: number;
  referenceDisagrees: number;
  attackerAgrees: number;
  attackerRefusedFalse: number;
  attackerDisagrees: number;
  publicWiresMatch: number;
  proved: number;
  proofAgrees: number;
  proofDisagrees: number;
  rejectedByGroup: Record<string, number>;
  mutations: number;
  mutationsRejected: number;
  mutationsFreeWires: number;
  /** Satisfied edits that changed a public wire (critical). */
  mutationsPublicChangedSatisfied: number;
  /** Satisfied edits that changed private input wires only. */
  mutationsPrivateInputChangedSatisfied: number;
  freeWires: Record<string, number>;
}

interface HonestWitness {
  caseIndex: number;
  input: Input;
  w: bigint[];
}

interface WireEdit {
  index: number;
  name: string;
  kind: string;
  old: string;
  new: string;
}

async function run(argv: string[]): Promise<void> {
  const smoke = flag(argv, "smoke");
  const campaign = opt(argv, "campaign") ?? (smoke ? "smoke" : undefined);
  if (!campaign || !/^[A-Za-z0-9_.-]{1,64}$/.test(campaign)) throw new Error("--campaign <name> is required");
  const nCases = optNum(argv, "cases", smoke ? 8 : REGISTERED.cases);
  const nMut = optNum(argv, "mutations", smoke ? 60 : REGISTERED.mutations);
  const nProve = optNum(argv, "prove", smoke ? 1 : REGISTERED.prove);
  const deviation = budgetDeviation(argv, smoke, [
    { flag: "cases", value: nCases, registered: REGISTERED.cases },
    { flag: "mutations", value: nMut, registered: REGISTERED.mutations },
    { flag: "prove", value: nProve, registered: REGISTERED.prove },
  ]);
  const root = path.join(robustnessRoot(smoke), "circuit_fuzz", campaign);
  if (fs.existsSync(path.join(root, "plan.json"))) throw new Error(`${rel(root)} already holds a campaign; choose a new --campaign name`);
  const commit = assertCommitted(smoke);
  const roots = markerRoots({ ...(windowsRepoFromArgs(argv) ? { windowsRepo: windowsRepoFromArgs(argv) as string } : {}), allowLocalOnlyInWsl: smoke });
  let release: () => void = () => undefined;
  if (smoke) assertMarkersFree(roots, "BUSY");
  else {
    const hnd = acquireMarker({ kind: "BUSY", campaign: `robustness/circuit_fuzz/${campaign}`, runner: "harness/v4/robustness/circuit_fuzz.ts", owner: "operator", roots });
    release = () => hnd.release();
  }
  const log = (s: string) => console.log(`[circuit-fuzz] ${sanitize(s)}`);
  try {
    fs.mkdirSync(path.join(root, "failures"), { recursive: true });
    const artifacts = checkArtifacts();
    const { g, source } = attackerGenerator(log);
    const p = await getPoseidon();
    const defaultType = credTypeField(p, DEFAULT_TYPE_ID);
    writeJson(path.join(root, "plan.json"), {
      schema: "pqid/v4-circuit-fuzz-plan/v1",
      campaign,
      smoke,
      preRegistration: "docs/v4/ROBUSTNESS.md section 5",
      protocol: protocolRecord(smoke),
      masterSeed: MASTER,
      cases: nCases,
      mutations: nMut,
      proved: { true: nProve, false: nProve },
      registeredBudgets: REGISTERED,
      deviation,
      gitClean: commit.gitClean,
      commitChecked: commit.paths,
      oracle: "harness/v4/robustness/oracles.ts relationR4 (integer model of R4 over F_p, from the circuit's group comments)",
      keyLabel: "dev",
      createdUtc: utcNow(),
    });
    writeJson(path.join(root, "env.json"), { schema: "pqid/v4-circuit-fuzz-env/v2", env: envInfo(), gitHead: gitHead(), commit, artifacts, attackerGenerator: source });
    const r1cs = readR1cs(R1CS_V4);
    const sym = readSym(SYM_V4);
    const t: Totals = {
      cases: 0,
      modelTrue: 0,
      modelFalse: 0,
      referenceAgrees: 0,
      referenceDisagrees: 0,
      attackerAgrees: 0,
      attackerRefusedFalse: 0,
      attackerDisagrees: 0,
      publicWiresMatch: 0,
      proved: 0,
      proofAgrees: 0,
      proofDisagrees: 0,
      rejectedByGroup: {},
      mutations: 0,
      mutationsRejected: 0,
      mutationsFreeWires: 0,
      mutationsPublicChangedSatisfied: 0,
      mutationsPrivateInputChangedSatisfied: 0,
      freeWires: {},
    };
    const failures: string[] = [];
    const honestWitnesses: HonestWitness[] = [];
    let provedTrue = 0;
    let provedFalse = 0;
    const snarkjs = await import("snarkjs");
    const vkey = JSON.parse(fs.readFileSync(VKEY_V4, "utf8")) as unknown;
    for (let i = 0; i < nCases; i++) {
      const rng = caseRng(MASTER, "circuit-case", i);
      const spec = await genCase(rng, i, p, defaultType);
      t.cases++;
      if (spec.model.satisfiable) t.modelTrue++;
      else t.modelFalse++;
      const rec: Record<string, unknown> = { index: i, aims: spec.aims, model: spec.model };
      const fail = (what: string, detail: string) => {
        const file = path.join(root, "failures", `case${i}_${what}.json`);
        writeJson(file, { schema: "pqid/v4-circuit-fuzz-failure/v1", what, detail: sanitize(detail), index: i, masterSeed: MASTER, aims: spec.aims, model: spec.model, input: spec.input, replay: `node --import tsx harness/v4/robustness/circuit_fuzz.ts --replay ${rel(file)}`, note: "synthetic circuit input (random fixture values; no real holder secret)" });
        failures.push(rel(file));
      };
      // (a) reference witness
      const ref = await referenceWitness(spec.input);
      rec["reference"] = ref.ok ? "witness" : `refused (${ref.error})`;
      if (ref.ok !== spec.model.satisfiable) {
        t.referenceDisagrees++;
        fail("reference", `reference generator ${ref.ok ? "produced a witness" : "refused"}, model says ${spec.model.satisfiable ? "true" : `false (${spec.model.failing.join(", ")})`}`);
      } else t.referenceAgrees++;
      if (ref.ok) {
        const rep = checkR1cs(R1CS_V4, SYM_V4, ref.w);
        const pubOk = Array.from({ length: N_PUBLIC }, (_, k) => (ref.w[k + 1] as bigint).toString() === String(spec.input[["issuerKeyHash", "revRoot", "policyHash", "nonce", "stmtCode", "issRoot", "epochFromDate", "epochToDate"][k] as string]));
        if (pubOk.every(Boolean)) t.publicWiresMatch++;
        else fail("publicWires", "reference witness public wires differ from the inputs");
        if (!rep.satisfied) fail("referenceR1cs", `reference witness violates ${rep.violated} constraints`);
        // only a witness that satisfies the real R1CS with the right public wires is a mutation base
        if (honestWitnesses.length < 10 && rep.satisfied && pubOk.every(Boolean)) honestWitnesses.push({ caseIndex: i, input: spec.input, w: ref.w });
      }
      // (b) attacker generator witness on the real R1CS
      let attW: bigint[] | null = null;
      try {
        attW = mapToReal(await attackerWitnessO0(spec.input, g), g.sym, SYM_V4, R1CS_V4);
      } catch (e) {
        rec["attacker"] = `refused (${assertLine((e as Error).message)})`;
      }
      if (attW) {
        const rep = checkR1cs(R1CS_V4, SYM_V4, attW);
        rec["attacker"] = rep.satisfied ? "satisfies real R1CS" : { violated: rep.violated, byGroup: rep.byGroup };
        for (const [grp, n] of Object.entries(rep.byGroup)) t.rejectedByGroup[grp] = (t.rejectedByGroup[grp] ?? 0) + (n > 0 ? 1 : 0);
        if (rep.satisfied === spec.model.satisfiable) t.attackerAgrees++;
        else {
          t.attackerDisagrees++;
          fail("attacker", `attacker witness ${rep.satisfied ? "satisfies" : "violates"} the real R1CS, model says ${spec.model.satisfiable}`);
        }
      } else if (!spec.model.satisfiable) t.attackerRefusedFalse++;
      else {
        t.attackerDisagrees++;
        fail("attacker", "attacker generator refused a true statement");
      }
      // (c) Groth16 on a few cases
      const proveThis = (spec.model.satisfiable && provedTrue < nProve && ref.ok) || (!spec.model.satisfiable && provedFalse < nProve && attW !== null);
      if (proveThis) {
        const tmp = path.join(os.tmpdir(), `pqid-v4-cfz-p-${randomBytes(6).toString("hex")}.wtns`);
        try {
          writeWtns(tmp, spec.model.satisfiable && ref.ok ? ref.w : (attW as bigint[]));
          const { proof, publicSignals } = await snarkjs.groth16.prove(ZKEY_V4, tmp);
          const ok = await snarkjs.groth16.verify(vkey as never, publicSignals, proof);
          t.proved++;
          if (spec.model.satisfiable) provedTrue++;
          else provedFalse++;
          rec["groth16"] = ok ? "verifies" : "does not verify";
          if (ok === spec.model.satisfiable) t.proofAgrees++;
          else {
            t.proofDisagrees++;
            fail("groth16", `proof ${ok ? "verifies" : "fails"} for a ${spec.model.satisfiable ? "true" : "false"} statement`);
          }
        } finally {
          fs.rmSync(tmp, { force: true });
        }
      }
      appendJsonl(path.join(root, "cases.jsonl"), rec);
      if ((i + 1) % 10 === 0 || i + 1 === nCases) log(`${i + 1}/${nCases} cases (${t.referenceDisagrees + t.attackerDisagrees + t.proofDisagrees} disagreements)`);
    }
    // ---- witness mutation
    const index = constraintIndex(r1cs);
    const mrng = caseRng(MASTER, "circuit-mutation", 0);
    for (let m = 0; m < nMut && honestWitnesses.length > 0; m++) {
      const baseW = mrng.pick(honestWitnesses);
      const base = baseW.w;
      const w = base.slice();
      const nw = mrng.int(1, 3);
      const wires = new Set<number>();
      while (wires.size < nw) wires.add(mrng.int(1, r1cs.nWires - 1));
      const kinds = new Map<number, string>();
      for (const wi of wires) {
        const old = w[wi] as bigint;
        const kind = mrng.pick(["random", "+1", "-1", "swap01"]);
        kinds.set(wi, kind);
        w[wi] = kind === "random" ? mrng.bigBelow(FIELD_P) : kind === "+1" ? (old + 1n) % FIELD_P : kind === "-1" ? (old - 1n + FIELD_P) % FIELD_P : old === 0n ? 1n : old === 1n ? 0n : (old + 1n) % FIELD_P;
      }
      const changed = [...wires].filter((wi) => w[wi] !== base[wi]);
      if (changed.length === 0) continue;
      t.mutations++;
      const touched = new Set<number>();
      for (const wi of changed) for (const ci of index.get(wi) ?? []) touched.add(ci);
      const violated = [...touched].filter((ci) => !constraintHolds(r1cs.constraints[ci] as never, w));
      const inputChanged = changed.some((wi) => wi <= N_INPUT_WIRES);
      const publicChanged = changed.some((wi) => wi <= N_PUBLIC);
      const names = changed.map((wi) => (sym.names.get(wi) ?? [`wire${wi}`])[0] as string);
      let verdict: string;
      if (violated.length > 0) {
        t.mutationsRejected++;
        const groups = [...new Set(violated.map((ci) => constraintGroup(sym, r1cs.constraints[ci] as never)))];
        verdict = `rejected (${groups.join(", ")})`;
      } else if (!inputChanged) {
        t.mutationsFreeWires++;
        for (const n of names) t.freeWires[n] = (t.freeWires[n] ?? 0) + 1;
        verdict = "satisfied: free hint wire(s)";
      } else {
        if (publicChanged) t.mutationsPublicChangedSatisfied++;
        else t.mutationsPrivateInputChangedSatisfied++;
        verdict = publicChanged ? "CRITICAL: satisfied with a changed public wire" : "satisfied with a changed private input";
        const edits: WireEdit[] = changed.map((wi) => ({ index: wi, name: (sym.names.get(wi) ?? [`wire${wi}`])[0] as string, kind: kinds.get(wi) ?? "?", old: (base[wi] as bigint).toString(), new: (w[wi] as bigint).toString() }));
        const file = path.join(root, "failures", `mutation${m}.json`);
        writeJson(file, {
          schema: "pqid/v4-circuit-fuzz-mutation-failure/v2",
          what: "mutation",
          detail: verdict,
          critical: publicChanged,
          masterSeed: MASTER,
          mutationIndex: m,
          baseCaseIndex: baseW.caseIndex,
          baseInput: baseW.input,
          edits,
          touchedConstraints: touched.size,
          replay: `node --import tsx harness/v4/robustness/circuit_fuzz.ts --replay ${rel(file)}`,
          note: "synthetic circuit input (random fixture values; no real holder secret); replay rebuilds the base witness from baseInput with the reference wasm, applies the edits and checks the real R1CS",
        });
        failures.push(rel(file));
      }
      appendJsonl(path.join(root, "mutations.jsonl"), { m, baseCaseIndex: baseW.caseIndex, wires: changed, names, kinds: changed.map((wi) => kinds.get(wi)), verdict });
    }
    log(`mutations: ${t.mutations} (${t.mutationsRejected} rejected, ${t.mutationsFreeWires} free hint wires, ${t.mutationsPublicChangedSatisfied} satisfied with a changed public wire, ${t.mutationsPrivateInputChangedSatisfied} satisfied with a changed private input)`);
    const summary = {
      schema: "pqid/v4-circuit-fuzz-summary/v1",
      campaign,
      smoke,
      note: smoke ? "smoke run: checks the runner only; never quoted" : "untimed; counts only; dev key",
      totals: t,
      failures,
      finishedUtc: utcNow(),
    };
    writeJson(path.join(root, "summary.json"), summary);
    log(`summary: ${rel(path.join(root, "summary.json"))}; failures ${failures.length}`);
  } finally {
    release();
  }
}

/**
 * Replay a failure file. A case failure: model and reference generator on the stored input. A
 * mutation failure: the base witness rebuilt from baseInput with the reference wasm, the edits
 * applied (each edit's old value checked first) and the real R1CS checked in full. Exit 1 when the
 * failure reproduces, 0 when it does not. Refuses while RUNNING or BUSY exists (D-034).
 */
async function replay(file: string, argv: readonly string[]): Promise<number> {
  assertMarkersFree(markerRoots({ ...(windowsRepoFromArgs(argv) ? { windowsRepo: windowsRepoFromArgs(argv) as string } : {}), allowLocalOnlyInWsl: true }), "BUSY");
  const j = JSON.parse(fs.readFileSync(path.resolve(file), "utf8")) as { input?: Input; model?: unknown; what?: string; baseInput?: Input; edits?: WireEdit[] };
  if (j.what === "mutation") {
    if (!j.baseInput || !Array.isArray(j.edits)) throw new Error("this mutation failure file predates replayable mutation records (no baseInput or edits): rerun the campaign seed");
    const ref = await referenceWitness(j.baseInput);
    if (!ref.ok) throw new Error(`the reference wasm refused the base input (${ref.error}): the circuit or the input changed`);
    const w = ref.w.slice();
    const stale: string[] = [];
    for (const e of j.edits) {
      if ((w[e.index] as bigint).toString() !== e.old) stale.push(`wire ${e.index} (${e.name}) is ${String(w[e.index])}, the record says ${e.old}`);
      w[e.index] = BigInt(e.new);
    }
    const base = checkR1cs(R1CS_V4, SYM_V4, ref.w);
    const rep = checkR1cs(R1CS_V4, SYM_V4, w);
    const inputChanged = j.edits.some((e) => e.index <= N_INPUT_WIRES);
    const publicChanged = j.edits.some((e) => e.index <= N_PUBLIC);
    console.log(JSON.stringify({ kind: "mutation", baseWitnessSatisfied: base.satisfied, editsApplied: j.edits.length, staleEdits: stale, mutatedSatisfied: rep.satisfied, violated: rep.violated, byGroup: rep.byGroup, inputChanged, publicChanged }, null, 2));
    return rep.satisfied && inputChanged ? 1 : 0;
  }
  if (!j.input) throw new Error("this failure file holds no circuit input");
  const p = await getPoseidon();
  const model = relationR4(modelInputs(j.input), (xs) => poseidonBig(p, xs));
  const ref = await referenceWitness(j.input);
  console.log(JSON.stringify({ kind: "case", model, reference: ref.ok ? "witness" : ref.error }, null, 2));
  return ref.ok === model.satisfiable ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === SELF) {
  const argv = process.argv.slice(2);
  const rf = opt(argv, "replay");
  (rf ? replay(rf, argv) : run(argv).then(() => 0)).then(
    (code) => process.exit(code),
    (e: unknown) => {
      console.error(sanitize(e instanceof Error ? (e.stack ?? e.message) : String(e)));
      process.exit(1);
    }
  );
}

