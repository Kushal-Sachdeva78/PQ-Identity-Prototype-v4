#!/usr/bin/env node
// Coordinator for the PQ-Identity Groth16 phase-2 ceremony (snarkjs 0.7.4 from node_modules).
// Operator guide: ceremony/README.md. Exact steps for the real v4 ceremony: ceremony/HANDOFF_STEPS.md.
//
// Commands (all take --dir <ceremony folder>, default ceremony/v4):
//   init         r1cs + ptau -> <circuit>_0000.zkey; records r1cs/ptau sha256, checks the ptau pin
//                (setup/pins.json, then setup/pins_v4.json, both read-only) and the circuit freeze
//   verify <z>   snarkjs zKey.verifyFromR1cs; prints circuit hash and every contribution
//   accept <z>   verify + chain check (extends the current head by exactly one contribution)
//                + optional reported-hash/receipt check; stores it as the next <circuit>_NNNN.zkey
//   kit          folder to hand to the next contributor (scripts + current zkey + SHA256SUMS)
//   beacon-plan  fix the beacon in advance (drand round or Bitcoin block height, 2^iterExp)
//   beacon <z> <beaconHex> <iterExp>   apply the announced public beacon to the head
//   finalize     verify, export vkey + Solidity verifier, write the ceremony transcript
//   audit        independent check of published outputs against a transcript (anyone can run)
//   status       show the ceremony state
//
// The coordinator never handles contributor entropy. It writes only inside --dir.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import {
  checkNodeVersion,
  loadSnarkjs,
  solidityTemplates,
  sha256File,
  sha256Hex,
  isHex,
  formatHashHex,
  captureLogger,
  verifyZkey,
  envMeta,
  nowUtc,
  recPath,
  parseArgs,
  writeJsonAtomic,
  DRAND_DEFAULT,
  EXPECTED_SNARKJS,
} from "./lib.mjs";

const CEREMONY_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(CEREMONY_DIR, "..");
const DEFAULTS = {
  r1cs: path.join(REPO_ROOT, "circuits", "build", "v4", "credential_auth_v4.r1cs"),
  ptau: path.join(REPO_ROOT, "setup", "ptau", "powersOfTau28_hez_final_15.ptau"),
  dir: path.join(CEREMONY_DIR, "v4"),
};
const PIN_FILES = [path.join(REPO_ROOT, "setup", "pins.json"), path.join(REPO_ROOT, "setup", "pins_v4.json")];
const FREEZE_FILE = path.join(REPO_ROOT, "docs", "v4", "FREEZE.md");
const STATE_NAME = "ceremony_state.json";
const KIT_FILES = ["contribute.ps1", "contribute.sh", "contribute_core.mjs", "lib.mjs", "coordinator.mjs", "package.json", "CONTRIBUTE.md"];
const MIN_ITER_EXP = 10;
const REHEARSAL_PREFIX = "REHEARSAL ONLY";

const FLAGS = ["no-pin", "allow-unfrozen", "allow-past", "with-verify-files", "json", "any-snarkjs", "help"];
const OPTIONS = [
  "dir", "r1cs", "ptau", "label", "ptau-pin", "frozen-sha256", "min-contributions", "title", "compiler",
  "hash", "receipt", "contributor", "out", "kind", "round", "at", "height", "iter-exp", "announced",
  "drand-json", "source", "transcript", "zkey", "vkey", "sol", "my-hash",
];

const USAGE = `node ceremony/coordinator.mjs <command> [options]
  init        [--r1cs f] [--ptau f] [--dir d] [--label ceremony|rehearsal] [--title t]
              [--ptau-pin <name in setup/pins*.json>] [--frozen-sha256 <r1cs sha256>]
              [--min-contributions 3] [--compiler "<circom version>"]
              rehearsal only: [--no-pin] [--allow-unfrozen]
  verify      <zkey> [--dir d] [--r1cs f --ptau f]
  accept      <zkey> [--dir d] [--hash <contribution hash>] [--receipt <file>] [--contributor <name>]
  kit         --out <new folder> [--dir d] [--with-verify-files]
  beacon-plan --kind drand (--round N | --at <ISO time>) | --kind bitcoin --height H
              [--iter-exp 10] [--announced "<where and when it was announced>"] [--dir d]
              rehearsal only: [--allow-past] (code-path checks with an already public round)
  beacon      <head zkey> <beaconHex> <iterExp> [--dir d]
              drand plan: --drand-json <saved API response>; bitcoin plan: --height H
              rehearsal: --source "REHEARSAL ONLY ..."
  finalize    [--dir d]
  audit       --transcript f --zkey f --r1cs f --ptau f [--vkey f] [--sol f] [--my-hash <hex>]
  status      [--dir d] [--json]`;

// ---------------------------------------------------------------- helpers

function statePath(dir) {
  return path.join(dir, STATE_NAME);
}

function loadState(dir) {
  const f = statePath(dir);
  if (!fs.existsSync(f)) throw new Error(`no ceremony in ${dir} (run init first)`);
  return JSON.parse(fs.readFileSync(f, "utf8"));
}

function saveState(dir, state, event, detail) {
  state.log.push({ atUtc: nowUtc(), event, ...(detail ? { detail } : {}) });
  writeJsonAtomic(statePath(dir), state);
}

/** Absolute path of a file recorded relative to the repo root. */
function abs(rec) {
  return path.isAbsolute(rec) ? rec : path.join(REPO_ROOT, rec);
}

const rec = (f) => recPath(f, REPO_ROOT);
const pad4 = (n) => String(n).padStart(4, "0");

function headEntry(state) {
  return state.chain[state.chain.length - 1];
}

/** r1cs and ptau must still be the files recorded at init. */
function checkInputsUnchanged(state) {
  for (const k of ["r1cs", "ptau"]) {
    const f = abs(state[k].file);
    if (!fs.existsSync(f)) throw new Error(`${k} file missing: ${state[k].file}`);
    const sha = sha256File(f);
    if (sha !== state[k].sha256) throw new Error(`${k} changed since init (${sha} != ${state[k].sha256})`);
  }
}

function findPin(name) {
  for (const f of PIN_FILES) {
    if (!fs.existsSync(f)) continue;
    const pins = JSON.parse(fs.readFileSync(f, "utf8"));
    if (pins[name]) return { file: rec(f), name, sha256: pins[name].sha256 };
  }
  return null;
}

function contributionView(c) {
  const v = { index: c.index, name: c.name, contributionHash: c.contributionHash, type: c.type };
  if (c.type === "beacon") {
    v.beaconHash = c.beaconHash;
    v.numIterationsExp = c.numIterationsExp;
  }
  return v;
}

function printContributions(list) {
  if (list.length === 0) console.log("  (no contributions yet)");
  for (const c of list) {
    console.log(`  #${c.index} ${c.type === "beacon" ? "[beacon] " : ""}${c.name}`);
    console.log(formatHashHex(c.contributionHash, "      "));
    if (c.type === "beacon") console.log(`      beacon value ${c.beaconHash}, 2^${c.numIterationsExp} iterations`);
  }
}

function sameEntry(a, b) {
  return a.name === b.name && a.contributionHash === b.contributionHash && a.type === b.type;
}

function kitFileHashes() {
  const out = {};
  for (const f of KIT_FILES) {
    const p = path.join(CEREMONY_DIR, f);
    if (fs.existsSync(p)) out[f] = sha256File(p);
  }
  return out;
}

function drandRoundTime(round) {
  return new Date((DRAND_DEFAULT.genesisTime + (round - 1) * DRAND_DEFAULT.periodSec) * 1000).toISOString();
}

// ---------------------------------------------------------------- commands

async function cmdInit(a) {
  const label = a.label ?? "ceremony";
  if (label !== "ceremony" && label !== "rehearsal") throw new Error("--label must be ceremony or rehearsal");
  if (label === "ceremony" && (a["no-pin"] || a["allow-unfrozen"])) {
    throw new Error("--no-pin and --allow-unfrozen are for rehearsals only");
  }
  const dir = path.resolve(a.dir ?? DEFAULTS.dir);
  const r1cs = path.resolve(a.r1cs ?? DEFAULTS.r1cs);
  const ptau = path.resolve(a.ptau ?? DEFAULTS.ptau);
  if (fs.existsSync(statePath(dir))) throw new Error(`${dir} already holds a ceremony; use a new --dir`);
  for (const f of [r1cs, ptau]) if (!fs.existsSync(f)) throw new Error(`not found: ${f}`);
  const minContributions = Number(a["min-contributions"] ?? 3);
  if (!Number.isInteger(minContributions) || minContributions < 1) throw new Error("--min-contributions must be >= 1");

  const { snarkjs, version } = await loadSnarkjs({ allowOther: Boolean(a["any-snarkjs"]) });
  console.log(`[init] hashing r1cs and ptau...`);
  const r1csSha = sha256File(r1cs);
  const ptauSha = sha256File(ptau);

  // ptau pin (setup/pins.json and setup/pins_v4.json are read, never written)
  let pin = null;
  if (a["no-pin"]) {
    pin = { checked: false, reason: "rehearsal: locally generated throwaway ptau, not pinned" };
  } else {
    const name = a["ptau-pin"] ?? path.basename(ptau);
    const found = findPin(name);
    if (!found) throw new Error(`ptau pin "${name}" not found in setup/pins.json or setup/pins_v4.json`);
    if (found.sha256 !== ptauSha) throw new Error(`ptau sha256 ${ptauSha} differs from pin ${found.name} (${found.sha256})`);
    pin = { checked: true, pinFile: found.file, pinName: found.name, match: true };
    console.log(`[init] ptau matches pin ${found.file}:${found.name}`);
  }

  // circuit freeze: the r1cs sha256 must be the frozen one
  let freeze = null;
  const want = a["frozen-sha256"]?.toLowerCase();
  if (want) {
    if (want !== r1csSha) throw new Error(`r1cs sha256 ${r1csSha} is not the frozen ${want}`);
    freeze = { source: "--frozen-sha256", r1csSha256: want, match: true };
  } else if (fs.existsSync(FREEZE_FILE)) {
    const text = fs.readFileSync(FREEZE_FILE, "utf8").toLowerCase();
    if (!text.includes(r1csSha)) {
      if (!a["allow-unfrozen"]) throw new Error(`r1cs sha256 ${r1csSha} does not appear in ${rec(FREEZE_FILE)}: not the frozen circuit`);
      freeze = { source: rec(FREEZE_FILE), match: false, note: "rehearsal on an unfrozen build" };
    } else {
      freeze = { source: rec(FREEZE_FILE), r1csSha256: r1csSha, match: true };
    }
  } else if (a["allow-unfrozen"]) {
    freeze = { source: null, match: false, note: "rehearsal: no freeze applies" };
  } else {
    throw new Error(`${rec(FREEZE_FILE)} does not exist: the circuit is not frozen (TASKS B7). Freeze first.`);
  }

  const { logger } = captureLogger(false);
  const info = await snarkjs.r1cs.info(r1cs, logger);
  const needed = info.nConstraints + info.nPubInputs + info.nOutputs + 1;

  // compiler facts from a circuit_info.json next to the r1cs, when it describes this exact r1cs
  let compiler = a.compiler ?? null;
  const infoFile = path.join(path.dirname(r1cs), "circuit_info.json");
  if (!compiler && fs.existsSync(infoFile)) {
    try {
      const ci = JSON.parse(fs.readFileSync(infoFile, "utf8"));
      if (ci.r1csSha256 === r1csSha) compiler = [ci.compiler, ci.optimization].filter(Boolean).join(" ");
    } catch {
      /* not a circuit_info file */
    }
  }

  fs.mkdirSync(dir, { recursive: true });
  const circuitName = path.basename(r1cs, ".r1cs");
  const zkey0 = path.join(dir, `${circuitName}_0000.zkey`);
  if (fs.existsSync(zkey0)) throw new Error(`${zkey0} already exists`);
  console.log(`[init] snarkjs zkey new (phase-2 start; deterministic from r1cs + ptau)...`);
  const nz = captureLogger(false);
  const csHash = await snarkjs.zKey.newZKey(r1cs, ptau, zkey0, nz.logger);
  if (!csHash || csHash === -1) {
    fs.rmSync(zkey0, { force: true });
    throw new Error("snarkjs zkey new failed:\n" + nz.lines.join("\n"));
  }
  const circuitHash = Buffer.from(csHash).toString("hex");
  const zkey0Sha = sha256File(zkey0);

  const state = {
    schema: "pqid/ceremony-state/v1",
    label,
    title: a.title ?? (label === "rehearsal" ? `${REHEARSAL_PREFIX}: ceremony rehearsal` : `PQ-Identity ${circuitName} phase-2 ceremony`),
    circuitName,
    minContributions,
    createdAtUtc: nowUtc(),
    r1cs: {
      file: rec(r1cs),
      sha256: r1csSha,
      nConstraints: info.nConstraints,
      nPubInputs: info.nPubInputs,
      nPrvInputs: info.nPrvInputs,
      nOutputs: info.nOutputs,
      compiler,
      freeze,
    },
    ptau: { file: rec(ptau), sha256: ptauSha, pin, needed },
    circuitHash,
    chain: [
      {
        step: 0,
        file: rec(zkey0),
        sha256: zkey0Sha,
        contributions: [],
        acceptedAtUtc: nowUtc(),
        note: "initial zkey, no contributions; anyone can recompute it from r1cs + ptau",
      },
    ],
    beaconPlan: null,
    beacon: null,
    final: null,
    tools: { snarkjs: version, node: process.version },
    log: [],
  };
  saveState(dir, state, "init", { r1cs: rec(r1cs), ptau: rec(ptau) });
  console.log(`[init] circuit ${circuitName}: ${info.nConstraints} constraints, ${info.nPubInputs} public inputs`);
  console.log(`[init] r1cs sha256 ${r1csSha}`);
  console.log(`[init] ptau sha256 ${ptauSha}`);
  console.log(`[init] circuit hash (snarkjs):\n${formatHashHex(circuitHash)}`);
  console.log(`[init] ${rec(zkey0)} sha256 ${zkey0Sha}`);
  console.log(`[init] next: make a kit for contributor 1:  node ceremony/coordinator.mjs kit --dir "${dir}" --out <folder>`);
  return 0;
}

async function cmdVerify(a) {
  const zkey = a._[1];
  if (!zkey || !fs.existsSync(zkey)) throw new Error("usage: verify <zkey> [--dir d] [--r1cs f --ptau f]");
  let r1cs = a.r1cs;
  let ptau = a.ptau;
  let state = null;
  if (!r1cs || !ptau) {
    state = loadState(path.resolve(a.dir ?? DEFAULTS.dir));
    checkInputsUnchanged(state);
    r1cs = abs(state.r1cs.file);
    ptau = abs(state.ptau.file);
  }
  const { snarkjs } = await loadSnarkjs({ allowOther: Boolean(a["any-snarkjs"]) });
  console.log(`[verify] snarkjs zkey verify ${path.basename(zkey)} against ${path.basename(r1cs)} + ${path.basename(ptau)}...`);
  const v = await verifyZkey(snarkjs, r1cs, ptau, zkey);
  if (!v.ok) {
    console.error(v.lines.join("\n"));
    throw new Error(`zkey does NOT verify${v.error ? ": " + v.error : ""}`);
  }
  const sha = sha256File(zkey);
  console.log(`[verify] OK. zkey sha256 ${sha}`);
  console.log(`[verify] circuit hash:\n${formatHashHex(v.circuitHash)}`);
  printContributions(v.contributions);
  if (state) {
    if (v.circuitHash !== state.circuitHash) console.log("[verify] WARNING: circuit hash differs from this ceremony's");
    const inChain = state.chain.findIndex((e) => e.sha256 === sha);
    if (inChain >= 0) console.log(`[verify] this is step ${inChain} of the accepted chain${inChain === state.chain.length - 1 ? " (head)" : ""}`);
    else if (state.beacon && state.beacon.sha256 === sha) console.log("[verify] this is the beacon-finalized zkey");
    else console.log("[verify] not (yet) part of the accepted chain");
  }
  return 0;
}

async function cmdAccept(a) {
  const zkey = a._[1];
  if (!zkey || !fs.existsSync(zkey)) throw new Error("usage: accept <zkey> [--hash h] [--receipt f] [--contributor name]");
  const dir = path.resolve(a.dir ?? DEFAULTS.dir);
  const state = loadState(dir);
  if (state.beacon) throw new Error("the beacon is already applied; no more contributions");
  checkInputsUnchanged(state);
  // Contributions close before the announced beacon becomes public.
  const plan = state.beaconPlan;
  if (plan?.kind === "drand" && !plan.rehearsalPastRound && Date.now() >= Date.parse(plan.expectedTimeUtc)) {
    throw new Error(`REJECTED: the announced drand round ${plan.round} was due at ${plan.expectedTimeUtc}; contributions are closed. Apply the beacon.`);
  }
  if (plan?.kind === "bitcoin") console.log(`[accept] check that the Bitcoin tip is still below the announced height ${plan.height}`);
  const head = headEntry(state);
  const { snarkjs } = await loadSnarkjs({ allowOther: Boolean(a["any-snarkjs"]) });
  const sha = sha256File(zkey);
  if (state.chain.some((e) => e.sha256 === sha)) throw new Error("this exact zkey is already in the chain");

  console.log(`[accept] snarkjs zkey verify ${path.basename(zkey)} (full chain from r1cs + ptau)...`);
  const v = await verifyZkey(snarkjs, abs(state.r1cs.file), abs(state.ptau.file), zkey);
  if (!v.ok) {
    console.error(v.lines.join("\n"));
    throw new Error(`REJECTED: zkey does not verify${v.error ? ": " + v.error : ""}`);
  }
  if (v.circuitHash !== state.circuitHash) throw new Error("REJECTED: circuit hash differs from this ceremony's");
  const prev = head.contributions;
  if (v.contributions.length !== prev.length + 1) {
    throw new Error(
      `REJECTED: expected exactly one new contribution on top of the head (step ${head.step}, ${prev.length} contributions); ` +
        `file has ${v.contributions.length}. It was probably built on an older zkey.`
    );
  }
  for (let i = 0; i < prev.length; i++) {
    if (!sameEntry(prev[i], v.contributions[i])) {
      throw new Error(`REJECTED: contribution #${i + 1} differs from the accepted chain: the file does not extend the current head`);
    }
  }
  const added = v.contributions[v.contributions.length - 1];
  if (added.type !== "contribution") throw new Error("REJECTED: the new entry is a beacon, not a contribution");

  let reported = null;
  if (a.hash) {
    const h = a.hash.toLowerCase().replace(/[^0-9a-f]/g, "");
    if (h !== added.contributionHash) throw new Error(`REJECTED: contributor-reported hash ${h.slice(0, 16)}... differs from the file's ${added.contributionHash.slice(0, 16)}...`);
    reported = { given: true, matched: true };
  }
  let receipt = null;
  if (a.receipt) {
    const r = JSON.parse(fs.readFileSync(a.receipt, "utf8"));
    const problems = [];
    if (r.contributionHash !== added.contributionHash) problems.push("contribution hash");
    if (r.output?.sha256 !== sha) problems.push("output sha256");
    if (r.input?.sha256 !== head.sha256) problems.push("input sha256 (contributor did not start from the current head)");
    if (r.contributor !== added.name) problems.push("contributor name");
    if (problems.length) throw new Error(`REJECTED: receipt does not match the file: ${problems.join(", ")}`);
    receipt = { given: true, matched: true, verifiedLocally: r.verifiedLocally === true, snarkjs: r.snarkjs, platform: r.environment?.platform ?? null };
  }
  if (a.contributor && a.contributor !== added.name) {
    throw new Error(`REJECTED: contribution is named "${added.name}", expected "${a.contributor}"`);
  }
  if (prev.some((c) => c.name === added.name)) console.log(`[accept] WARNING: name "${added.name}" already appears in the chain`);

  const step = state.chain.length;
  const dest = path.join(dir, `${state.circuitName}_${pad4(step)}.zkey`);
  if (fs.existsSync(dest) && path.resolve(zkey) !== dest) throw new Error(`${dest} already exists`);
  if (path.resolve(zkey) !== dest) fs.copyFileSync(zkey, dest);
  state.chain.push({
    step,
    file: rec(dest),
    sha256: sha,
    contribution: contributionView(added),
    contributions: v.contributions.map(contributionView),
    reportedHash: reported ?? { given: false },
    receipt: receipt ?? { given: false },
    acceptedAtUtc: nowUtc(),
  });
  saveState(dir, state, "accept", { step, name: added.name });
  console.log(`[accept] ACCEPTED contribution #${added.index} "${added.name}" as step ${step}`);
  console.log(formatHashHex(added.contributionHash));
  console.log(`[accept] new head ${rec(dest)} sha256 ${sha}`);
  const n = step;
  console.log(`[accept] ${n} contribution(s) so far; minimum before the beacon: ${state.minContributions}`);
  return 0;
}

async function cmdKit(a) {
  const dir = path.resolve(a.dir ?? DEFAULTS.dir);
  const state = loadState(dir);
  if (state.beacon) throw new Error("the beacon is already applied; the ceremony takes no more contributions");
  if (!a.out) throw new Error("kit needs --out <new folder>");
  const out = path.resolve(a.out);
  if (fs.existsSync(out) && fs.readdirSync(out).length > 0) throw new Error(`${out} exists and is not empty`);
  fs.mkdirSync(out, { recursive: true });
  const head = headEntry(state);
  const files = [];
  for (const f of KIT_FILES) {
    const src = path.join(CEREMONY_DIR, f);
    if (!fs.existsSync(src)) throw new Error(`kit file missing: ${f}`);
    fs.copyFileSync(src, path.join(out, f));
    files.push(f);
  }
  const headName = path.basename(abs(head.file));
  fs.copyFileSync(abs(head.file), path.join(out, headName));
  files.push(headName);
  if (a["with-verify-files"]) {
    for (const k of ["r1cs", "ptau"]) {
      const n = path.basename(abs(state[k].file));
      fs.copyFileSync(abs(state[k].file), path.join(out, n));
      files.push(n);
    }
  }
  const sums = files.map((f) => `${sha256File(path.join(out, f))}  ${f}`).join("\n") + "\n";
  fs.writeFileSync(path.join(out, "SHA256SUMS.txt"), sums);
  const next = pad4(state.chain.length);
  console.log(`[kit] ${out}`);
  for (const f of files) console.log(`  ${f}`);
  console.log("  SHA256SUMS.txt");
  console.log(`[kit] input zkey for the next contributor: ${headName}`);
  console.log(`[kit] publish or send separately (second channel): sha256 ${head.sha256}`);
  console.log(`[kit] the contributor names the output ${state.circuitName}_${next}.zkey`);
  return 0;
}

async function cmdBeaconPlan(a) {
  const dir = path.resolve(a.dir ?? DEFAULTS.dir);
  const state = loadState(dir);
  if (state.beaconPlan) throw new Error("a beacon plan is already recorded; it is fixed once announced");
  if (state.beacon) throw new Error("the beacon is already applied");
  const iterExp = Number(a["iter-exp"] ?? MIN_ITER_EXP);
  if (!Number.isInteger(iterExp) || iterExp < MIN_ITER_EXP || iterExp > 63) throw new Error("--iter-exp must be an integer 10..63");
  let plan;
  if (a["allow-past"] && state.label !== "rehearsal") throw new Error("--allow-past is for rehearsals only");
  if (a.kind === "drand") {
    let round;
    if (a.round) round = Number(a.round);
    else if (a.at) {
      const t = Date.parse(a.at) / 1000;
      if (!Number.isFinite(t)) throw new Error("--at must be an ISO date-time, e.g. 2026-10-20T12:00:00Z");
      round = Math.ceil((t - DRAND_DEFAULT.genesisTime) / DRAND_DEFAULT.periodSec) + 1;
    } else throw new Error("drand plan needs --round N or --at <ISO time>");
    if (!Number.isInteger(round) || round < 1) throw new Error("bad drand round");
    const expected = drandRoundTime(round);
    const past = Date.parse(expected) <= Date.now();
    if (past && !(a["allow-past"] && state.label === "rehearsal")) {
      throw new Error(`drand round ${round} (${expected}) is already public; pick a future round`);
    }
    plan = {
      kind: "drand",
      network: DRAND_DEFAULT.network,
      chainHash: DRAND_DEFAULT.chainHash,
      round,
      expectedTimeUtc: expected,
      url: `${DRAND_DEFAULT.api}${round}`,
      valueRule: "beacon value = the round's 'randomness' field (32 bytes hex) = sha256(signature)",
      ...(past ? { rehearsalPastRound: "REHEARSAL ONLY: round was already public when planned (code-path check)" } : {}),
    };
  } else if (a.kind === "bitcoin") {
    const height = Number(a.height);
    if (!Number.isInteger(height) || height < 1) throw new Error("bitcoin plan needs --height H (a future block height)");
    plan = {
      kind: "bitcoin",
      height,
      valueRule: "beacon value = the block hash at this height as block explorers show it (64 hex, lowercase, no 0x)",
      note: "operator checks the current tip is well below this height when announcing",
    };
  } else {
    throw new Error("--kind must be drand or bitcoin");
  }
  plan.iterExp = iterExp;
  plan.iterations = 2 ** iterExp;
  plan.plannedAtUtc = nowUtc();
  plan.announced = a.announced ?? null;
  state.beaconPlan = plan;
  saveState(dir, state, "beacon-plan", { kind: plan.kind, round: plan.round, height: plan.height });
  console.log("[beacon-plan] recorded (announce exactly this, before the last contribution arrives):");
  console.log(JSON.stringify(plan, null, 2));
  return 0;
}

async function cmdBeacon(a) {
  const [, zkey, hexArg, iterArg] = a._;
  if (!zkey || !hexArg || !iterArg) throw new Error("usage: beacon <head zkey> <beaconHex> <iterExp> [--dir d] ...");
  const dir = path.resolve(a.dir ?? DEFAULTS.dir);
  const state = loadState(dir);
  if (state.beacon) throw new Error("the beacon is already applied");
  checkInputsUnchanged(state);
  const head = headEntry(state);
  if (!fs.existsSync(zkey) || sha256File(zkey) !== head.sha256) throw new Error(`the beacon applies to the head only (${head.file})`);
  const value = hexArg.toLowerCase().replace(/^0x/, "");
  if (!isHex(value) || value.length < 2 || value.length > 510) throw new Error("beacon value must be hex (1..255 bytes)");
  const iterExp = Number(iterArg);
  if (!Number.isInteger(iterExp) || iterExp < MIN_ITER_EXP || iterExp > 63) throw new Error("iterExp must be an integer 10..63");
  const nContrib = state.chain.length - 1;
  if (nContrib < state.minContributions) {
    throw new Error(`only ${nContrib} contribution(s); this ceremony needs at least ${state.minContributions} before the beacon`);
  }

  const plan = state.beaconPlan;
  let source;
  let check;
  let beaconName;
  if (state.label === "ceremony" && !plan) throw new Error("no beacon plan recorded: run beacon-plan and announce it first");
  if (plan) {
    if (iterExp !== plan.iterExp) throw new Error(`iterExp ${iterExp} differs from the announced ${plan.iterExp}`);
    if (plan.kind === "drand") {
      if (!a["drand-json"]) throw new Error("save the API response of the planned round and pass it with --drand-json");
      const d = JSON.parse(fs.readFileSync(a["drand-json"], "utf8"));
      if (Number(d.round) !== plan.round) throw new Error(`drand JSON is round ${d.round}, the plan says ${plan.round}`);
      const randomness = String(d.randomness).toLowerCase();
      if (randomness !== value) throw new Error("beacon value differs from the drand randomness field");
      if (!isHex(String(d.signature).toLowerCase())) throw new Error("drand JSON has no hex signature");
      if (sha256Hex(Buffer.from(String(d.signature), "hex")) !== randomness) throw new Error("drand randomness != sha256(signature)");
      source = { ...plan, response: { round: d.round, randomness, signature: String(d.signature).toLowerCase(), previous_signature: d.previous_signature ?? null } };
      check = "round equals the plan; randomness equals sha256(signature). The BLS signature itself is checked by anyone with the drand client or a second relay.";
      beaconName = `beacon: drand default round ${plan.round}`;
    } else {
      if (value.length !== 64) throw new Error("a Bitcoin block hash is 32 bytes (64 hex)");
      if (Number(a.height) !== plan.height) throw new Error(`--height ${a.height} differs from the announced ${plan.height}`);
      source = { ...plan, blockHash: value };
      check = "operator copied the block hash at the announced height; anyone re-checks it on two block explorers";
      beaconName = `beacon: bitcoin block ${plan.height}`;
    }
    if (a.source) source.operatorNote = a.source;
    if (state.label === "rehearsal") beaconName = `${REHEARSAL_PREFIX} ${beaconName}`;
  } else {
    // rehearsal without a plan: dummy beacon, explicitly labelled
    if (!a.source || !a.source.startsWith(REHEARSAL_PREFIX)) throw new Error(`rehearsal beacon needs --source "${REHEARSAL_PREFIX}: ..."`);
    source = { kind: "dummy", description: a.source };
    check = "none (dummy value, rehearsal only)";
    beaconName = `${REHEARSAL_PREFIX} dummy beacon`;
  }

  const { snarkjs } = await loadSnarkjs({ allowOther: Boolean(a["any-snarkjs"]) });
  const finalDir = path.join(dir, "final");
  fs.mkdirSync(finalDir, { recursive: true });
  const out = path.join(finalDir, `${state.circuitName}_final.zkey`);
  if (fs.existsSync(out)) throw new Error(`${out} already exists`);
  console.log(`[beacon] snarkjs zkey beacon (2^${iterExp} iterations) on ${head.file}...`);
  const { lines, logger } = captureLogger(false);
  const h = await snarkjs.zKey.beacon(abs(head.file), out, beaconName, value, iterExp, logger);
  if (!h) {
    fs.rmSync(out, { force: true });
    throw new Error("snarkjs zkey beacon failed:\n" + lines.join("\n"));
  }
  const contributionHash = Buffer.from(h).toString("hex");
  state.beacon = {
    name: beaconName,
    value,
    numIterationsExp: iterExp,
    iterations: 2 ** iterExp,
    source,
    check,
    contributionHash,
    file: rec(out),
    sha256: sha256File(out),
    appliedAtUtc: nowUtc(),
  };
  saveState(dir, state, "beacon", { name: beaconName });
  console.log(`[beacon] applied "${beaconName}", beacon contribution hash:`);
  console.log(formatHashHex(contributionHash));
  console.log(`[beacon] ${rec(out)} sha256 ${state.beacon.sha256}`);
  console.log(`[beacon] next: node ceremony/coordinator.mjs finalize --dir "${dir}"`);
  return 0;
}

async function cmdFinalize(a) {
  const dir = path.resolve(a.dir ?? DEFAULTS.dir);
  const state = loadState(dir);
  if (!state.beacon) throw new Error("no beacon applied yet: finalize runs after the beacon");
  if (state.final) throw new Error("already finalized");
  checkInputsUnchanged(state);
  const zkey = abs(state.beacon.file);
  if (sha256File(zkey) !== state.beacon.sha256) throw new Error("final zkey changed since the beacon");
  const { snarkjs, version } = await loadSnarkjs({ allowOther: Boolean(a["any-snarkjs"]) });

  console.log("[finalize] snarkjs zkey verify of the final zkey (full chain from r1cs + ptau)...");
  const v = await verifyZkey(snarkjs, abs(state.r1cs.file), abs(state.ptau.file), zkey);
  if (!v.ok) {
    console.error(v.lines.join("\n"));
    throw new Error(`final zkey does NOT verify${v.error ? ": " + v.error : ""}`);
  }
  if (v.circuitHash !== state.circuitHash) throw new Error("circuit hash differs");
  const accepted = headEntry(state).contributions;
  if (v.contributions.length !== accepted.length + 1) throw new Error("final zkey does not have exactly the accepted contributions + beacon");
  accepted.forEach((c, i) => {
    if (!sameEntry(c, v.contributions[i])) throw new Error(`contribution #${i + 1} differs from the accepted chain`);
  });
  const b = v.contributions[v.contributions.length - 1];
  if (b.type !== "beacon" || b.beaconHash !== state.beacon.value || b.numIterationsExp !== state.beacon.numIterationsExp) {
    throw new Error("last entry is not the recorded beacon");
  }
  if (b.contributionHash !== state.beacon.contributionHash) throw new Error("beacon contribution hash differs from the recorded one");
  const secret = v.contributions.filter((c) => c.type === "contribution");
  if (secret.length < Math.max(1, state.minContributions)) throw new Error(`only ${secret.length} non-beacon contributions`);

  const finalDir = path.dirname(zkey);
  const vkeyFile = path.join(finalDir, "verification_key.json");
  const solFile = path.join(finalDir, "Groth16Verifier.sol");
  const transcriptFile = path.join(finalDir, "ceremony_transcript.json");
  console.log("[finalize] exporting verification key and Solidity verifier...");
  const vkey = await snarkjs.zKey.exportVerificationKey(zkey);
  fs.writeFileSync(vkeyFile, JSON.stringify(vkey, null, 2) + "\n");
  fs.writeFileSync(solFile, await snarkjs.zKey.exportSolidityVerifier(zkey, solidityTemplates()));

  const rehearsal = state.label === "rehearsal";
  const transcript = {
    schema: "pqid/ceremony-transcript/v1",
    label: state.label,
    ...(rehearsal ? { warning: `${REHEARSAL_PREFIX}: throwaway circuit and key; says nothing about any PQ-Identity key` } : {}),
    title: state.title,
    circuit: {
      name: state.circuitName,
      r1cs: state.r1cs,
      circuitHash: state.circuitHash,
      circuitHashNote: "snarkjs csHash (BLAKE2b-512 over the circuit's phase-2 constraint data), printed by snarkjs zkey verify",
    },
    ptau: state.ptau,
    initialZkey: { file: state.chain[0].file, sha256: state.chain[0].sha256 },
    contributions: state.chain.slice(1).map((e) => ({
      index: e.contribution.index,
      name: e.contribution.name,
      contributionHash: e.contribution.contributionHash,
      zkey: { file: e.file, sha256: e.sha256 },
      acceptedAtUtc: e.acceptedAtUtc,
      reportedHashMatched: e.reportedHash.given ? e.reportedHash.matched : null,
      receiptMatched: e.receipt.given ? e.receipt.matched : null,
      verifiedByContributor: e.receipt.given ? e.receipt.verifiedLocally : null,
    })),
    beacon: {
      index: b.index,
      name: state.beacon.name,
      value: state.beacon.value,
      numIterationsExp: state.beacon.numIterationsExp,
      iterations: state.beacon.iterations,
      source: state.beacon.source,
      check: state.beacon.check,
      contributionHash: state.beacon.contributionHash,
      appliedAtUtc: state.beacon.appliedAtUtc,
    },
    final: {
      zkey: { file: rec(zkey), sha256: sha256File(zkey) },
      verificationKey: { file: rec(vkeyFile), sha256: sha256File(vkeyFile) },
      solidityVerifier: { file: rec(solFile), sha256: sha256File(solFile), contract: "Groth16Verifier (snarkjs template)" },
      verifiedFromR1cs: true,
      verifiedAtUtc: nowUtc(),
    },
    honesty:
      "The key is sound if at least one listed non-beacon contribution kept its randomness secret (1-of-N), " +
      "on top of the phase-1 powers of tau. See ceremony/README.md.",
    tools: {
      snarkjs: version,
      snarkjsExpected: EXPECTED_SNARKJS,
      node: process.version,
      compiler: state.r1cs.compiler,
      kitFilesSha256: kitFileHashes(),
    },
    environment: envMeta(),
    dates: {
      initUtc: state.createdAtUtc,
      beaconPlannedUtc: state.beaconPlan?.plannedAtUtc ?? null,
      beaconAppliedUtc: state.beacon.appliedAtUtc,
      finalizedUtc: nowUtc(),
    },
  };
  fs.writeFileSync(transcriptFile, JSON.stringify(transcript, null, 2) + "\n");
  const sums = [zkey, vkeyFile, solFile, transcriptFile].map((f) => `${sha256File(f)}  ${path.basename(f)}`).join("\n") + "\n";
  fs.writeFileSync(path.join(finalDir, "SHA256SUMS.txt"), sums);
  state.final = {
    transcript: rec(transcriptFile),
    transcriptSha256: sha256File(transcriptFile),
    vkey: transcript.final.verificationKey,
    sol: transcript.final.solidityVerifier,
    finalizedAtUtc: transcript.dates.finalizedUtc,
  };
  saveState(dir, state, "finalize");
  console.log(`[finalize] ${secret.length} contribution(s) + beacon verified`);
  console.log(`[finalize] ${rec(transcriptFile)}`);
  console.log(`[finalize] ${rec(vkeyFile)} sha256 ${transcript.final.verificationKey.sha256}`);
  console.log(`[finalize] ${rec(solFile)} sha256 ${transcript.final.solidityVerifier.sha256}`);
  return 0;
}

async function cmdAudit(a) {
  for (const k of ["transcript", "zkey", "r1cs", "ptau"]) if (!a[k]) throw new Error(`audit needs --${k}`);
  const t = JSON.parse(fs.readFileSync(a.transcript, "utf8"));
  const results = [];
  const check = (name, ok, detail) => {
    results.push({ name, ok });
    console.log(`[audit] ${ok ? "PASS" : "FAIL"} ${name}${detail ? " (" + detail + ")" : ""}`);
  };
  check("r1cs sha256 equals transcript", sha256File(a.r1cs) === t.circuit.r1cs.sha256);
  check("ptau sha256 equals transcript", sha256File(a.ptau) === t.ptau.sha256);
  check("final zkey sha256 equals transcript", sha256File(a.zkey) === t.final.zkey.sha256);
  const { snarkjs } = await loadSnarkjs({ allowOther: Boolean(a["any-snarkjs"]) });
  console.log("[audit] snarkjs zkey verify (from r1cs + ptau)...");
  const v = await verifyZkey(snarkjs, a.r1cs, a.ptau, a.zkey);
  check("snarkjs zkey verify", v.ok, v.error ?? undefined);
  check("circuit hash equals transcript", v.circuitHash === t.circuit.circuitHash);
  const expected = [
    ...t.contributions.map((c) => ({ name: c.name, contributionHash: c.contributionHash, type: "contribution" })),
    { name: t.beacon.name, contributionHash: t.beacon.contributionHash, type: "beacon" },
  ];
  const listOk = v.contributions.length === expected.length && expected.every((e, i) => sameEntry(e, v.contributions[i]));
  check("contribution list (names, hashes, order) equals transcript", listOk, `${v.contributions.length} entries in zkey`);
  const last = v.contributions[v.contributions.length - 1];
  check(
    "beacon value and iterations equal transcript",
    Boolean(last) && last.type === "beacon" && last.beaconHash === t.beacon.value && last.numIterationsExp === t.beacon.numIterationsExp
  );
  if (t.beacon.source?.kind === "drand" && t.beacon.source.response) {
    const r = t.beacon.source.response;
    check("drand randomness = sha256(signature)", sha256Hex(Buffer.from(r.signature, "hex")) === r.randomness);
    console.log(`[audit] compare with ${DRAND_DEFAULT.api}${r.round} and a second relay, e.g. ${DRAND_DEFAULT.relays[3]}/public/${r.round}`);
  }
  if (a.vkey) {
    const exported = JSON.parse(JSON.stringify(await snarkjs.zKey.exportVerificationKey(a.zkey)));
    check("verification key equals the one exported from the zkey", isDeepStrictEqual(exported, JSON.parse(fs.readFileSync(a.vkey, "utf8"))));
    check("verification key sha256 equals transcript", sha256File(a.vkey) === t.final.verificationKey.sha256);
  }
  if (a.sol) {
    const sol = await snarkjs.zKey.exportSolidityVerifier(a.zkey, solidityTemplates());
    check("Solidity verifier equals the one exported from the zkey", sol === fs.readFileSync(a.sol, "utf8"));
  }
  if (a["my-hash"]) {
    const h = a["my-hash"].toLowerCase().replace(/[^0-9a-f]/g, "");
    const hit = v.contributions.find((c) => c.contributionHash === h);
    check("my contribution hash is in the final zkey", Boolean(hit), hit ? `#${hit.index} "${hit.name}"` : "not found");
  }
  const secret = v.contributions.filter((c) => c.type === "contribution").length;
  console.log(`[audit] non-beacon contributions in the zkey: ${secret}`);
  const failed = results.filter((r) => !r.ok).length;
  console.log(failed === 0 ? "[audit] ALL CHECKS PASSED" : `[audit] ${failed} CHECK(S) FAILED`);
  return failed === 0 ? 0 : 1;
}

async function cmdStatus(a) {
  const dir = path.resolve(a.dir ?? DEFAULTS.dir);
  const state = loadState(dir);
  if (a.json) {
    console.log(JSON.stringify(state, null, 2));
    return 0;
  }
  console.log(`${state.title} [${state.label}]`);
  console.log(`  circuit ${state.circuitName}: ${state.r1cs.nConstraints} constraints; r1cs ${state.r1cs.sha256}`);
  console.log(`  ptau ${state.ptau.file} ${state.ptau.sha256} pin ${state.ptau.pin?.checked ? "checked" : "not checked"}`);
  console.log(`  freeze: ${state.r1cs.freeze?.match ? "r1cs matches " + state.r1cs.freeze.source : "none (" + (state.r1cs.freeze?.note ?? "") + ")"}`);
  for (const e of state.chain) {
    const who = e.contribution ? `#${e.contribution.index} "${e.contribution.name}" ${e.contribution.contributionHash.slice(0, 16)}...` : "(initial)";
    console.log(`  step ${e.step}: ${e.file} ${who}`);
  }
  console.log(`  contributions: ${state.chain.length - 1} (minimum ${state.minContributions})`);
  console.log(`  beacon plan: ${state.beaconPlan ? JSON.stringify({ kind: state.beaconPlan.kind, round: state.beaconPlan.round, height: state.beaconPlan.height, iterExp: state.beaconPlan.iterExp }) : "none"}`);
  console.log(`  beacon: ${state.beacon ? state.beacon.name : "not applied"}`);
  console.log(`  finalized: ${state.final ? state.final.transcript : "no"}`);
  return 0;
}

async function main() {
  checkNodeVersion();
  const a = parseArgs(process.argv.slice(2), { flags: FLAGS, options: OPTIONS });
  const cmd = a._[0];
  if (!cmd || a.help) {
    console.log(USAGE);
    return cmd ? 0 : 2;
  }
  switch (cmd) {
    case "init":
      return cmdInit(a);
    case "verify":
      return cmdVerify(a);
    case "accept":
      return cmdAccept(a);
    case "kit":
      return cmdKit(a);
    case "beacon-plan":
      return cmdBeaconPlan(a);
    case "beacon":
      return cmdBeacon(a);
    case "finalize":
      return cmdFinalize(a);
    case "audit":
      return cmdAudit(a);
    case "status":
      return cmdStatus(a);
    default:
      console.error(USAGE);
      return 2;
  }
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(`ERROR: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
);
