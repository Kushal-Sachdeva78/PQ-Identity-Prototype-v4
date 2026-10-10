#!/usr/bin/env node
// End-to-end ceremony rehearsal on a tiny throwaway circuit. REHEARSAL ONLY.
//
//   node ceremony/rehearse.mjs
//
// Steps (all output under ceremony/rehearsal/_out/, which is gitignored and wiped first):
//   1. compile ceremony/rehearsal/tiny.circom with circom (--O2)
//   2. tiny local powers of tau: snarkjs powersoftau new bn128 2^8, one throwaway contribution,
//      prepare phase2, verify
//   3. coordinator init (label rehearsal)
//   4. three simulated contributors, each with a fresh OS-random contribution, through the same
//      path real contributors use: coordinator kit -> contribute.ps1 / contribute.sh in the kit
//      folder -> coordinator accept (reported hash + receipt checked)
//   5. negative checks that must be rejected (stale base, wrong reported hash, tampered file,
//      beacon on a non-head file, finalize before the beacon, audit of a hash that is not in the key)
//   6. dummy beacon marked REHEARSAL ONLY, finalize, third-party audit
//   7. prove and verify with the rehearsal key (and two negative verifications)
// The only committed output is ceremony/rehearsal/REHEARSAL_TRANSCRIPT.json.
// No timings are recorded (this is not a benchmark).

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loadSnarkjs, loadCurves, sha256File, sha256Hex, captureLogger, envMeta, nowUtc, recPath, writeJsonAtomic } from "./lib.mjs";

const CEREMONY_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(CEREMONY_DIR, "..");
const REH_DIR = path.join(CEREMONY_DIR, "rehearsal");
const OUT = path.join(REH_DIR, "_out");
const TRANSCRIPT_OUT = path.join(REH_DIR, "REHEARSAL_TRANSCRIPT.json");
const COORD = path.join(CEREMONY_DIR, "coordinator.mjs");
const CIRCUIT_SRC = path.join(REH_DIR, "tiny.circom");
const RUNNING_FLAG = path.join(REPO_ROOT, "results", "v4", "bench", "RUNNING");
const PTAU_POWER = 8;
const LABEL = "REHEARSAL ONLY";

const rec = (f) => recPath(f, REPO_ROOT);
const failures = [];

function step(msg) {
  console.log(`\n=== ${msg}`);
}

function run(cmd, args, { cwd = REPO_ROOT, quiet = false } = {}) {
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, windowsHide: true });
  if (r.error) throw r.error;
  const out = (r.stdout ?? "") + (r.stderr ? "\n" + r.stderr : "");
  if (!quiet) {
    for (const line of out.split(/\r?\n/)) if (line.trim()) console.log(`    | ${line}`);
  }
  return { code: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "", out };
}

function coord(args, opts) {
  return run(process.execPath, [COORD, ...args], opts);
}

function mustPass(label, r) {
  if (r.code !== 0) {
    failures.push(`${label}: exit ${r.code}`);
    throw new Error(`${label} failed (exit ${r.code})`);
  }
  return r;
}

/** A step that must be refused: nonzero exit. Returns a record for the transcript. */
function mustReject(name, expectation, r) {
  const ok = r.code !== 0;
  const reasonLine = r.out.split(/\r?\n/).find((l) => /ERROR|REJECTED|FAIL/.test(l)) ?? "";
  console.log(`    -> ${ok ? "rejected as expected" : "NOT REJECTED (bad)"}`);
  if (!ok) failures.push(`negative check "${name}" was not rejected`);
  return { name, expectation, result: ok ? "rejected" : "ACCEPTED (failure)", exitCode: r.code, reason: reasonLine.replace(/\s+/g, " ").trim().slice(0, 300) };
}

function circomBinary() {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  if (process.platform === "win32" && fs.existsSync(win)) return win;
  return "circom";
}

/** Which wrapper each simulated contributor uses, and how to launch it. */
function wrappers() {
  if (process.platform === "win32") {
    const candidates = [process.env.PQID_BASH, "C:\\Program Files\\Git\\bin\\bash.exe", "C:\\Program Files (x86)\\Git\\bin\\bash.exe"].filter(Boolean);
    const bash = candidates.find((c) => fs.existsSync(c));
    const ps1 = { kind: "contribute.ps1", launcher: "powershell.exe" };
    const sh = bash ? { kind: "contribute.sh", launcher: bash, launcherNote: "Git Bash" } : null;
    return [ps1, sh ?? ps1, ps1];
  }
  const sh = { kind: "contribute.sh", launcher: "bash" };
  const pwsh = spawnSync("pwsh", ["-v"], { encoding: "utf8" });
  const ps1 = pwsh.status === 0 ? { kind: "contribute.ps1", launcher: "pwsh" } : sh;
  return [sh, ps1, sh];
}

function runWrapper(w, kitDir, { input, name, output, r1cs, ptau, expectSha }) {
  if (w.kind === "contribute.ps1") {
    const args = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path.join(kitDir, "contribute.ps1"),
      "-InputZkey", input, "-Name", name, "-OutputZkey", output, "-ExpectInputSha256", expectSha];
    if (r1cs) args.push("-R1cs", r1cs, "-Ptau", ptau);
    return run(w.launcher, args, { cwd: kitDir });
  }
  const args = [path.join(kitDir, "contribute.sh"), input, name, output, "--expect-sha256", expectSha];
  if (r1cs) args.push("--r1cs", r1cs, "--ptau", ptau);
  return run(w.launcher, args, { cwd: kitDir });
}

/**
 * drand default-network round 1000000, fetched 2026-09-27 from https://api.drand.sh/public/1000000
 * (randomness also matched https://drand.cloudflare.com/public/1000000). Already public, so it is
 * used only to exercise the drand checks of coordinator beacon; a real ceremony plans a future round.
 */
const DRAND_ROUND_1000000 = {
  round: 1000000,
  randomness: "a26ba4d229c666f52a06f1a9be1278dcc7a80dbc1dd2004a1ae7b63cb79fd37e",
  signature:
    "87e355169c4410a8ad6d3e7f5094b2122932c1062f603e6628aba2e4cb54f46c3bf1083c3537cd3b99e8296784f46fb40e090961cf9634f02c7dc2a96b69fc3c03735bc419962780a71245b72f81882cf6bb9c961bcf32da5624993bb747c9e5",
  previous_signature:
    "86bbc40c9d9347568967add4ddf6e351aff604352a7e1eec9b20dea4ca531ed6c7d38de9956ffc3bb5a7fabe28b3a36b069c8113bd9824135c3bff9b03359476f6b03beec179d4aeff456f4d34bbf702b9af78c3bb44e1892ace8e581bf4afa9",
};

/** Throwaway ceremony with one accepted contribution; returns its dir and head file. */
function miniCeremony(tag, { r1cs, ptau, core }) {
  const d = path.join(OUT, `beacon_${tag}`);
  mustPass(`init ${tag}`, coord(["init", "--label", "rehearsal", "--title", `${LABEL}: ${tag} beacon code path`, "--r1cs", r1cs, "--ptau", ptau,
    "--dir", d, "--no-pin", "--allow-unfrozen", "--min-contributions", "1"], { quiet: true }));
  const s = readState(d);
  const c1 = path.join(d, "incoming.zkey");
  mustPass(`contribution ${tag}`, run(process.execPath, [core, "--in", path.join(REPO_ROOT, s.chain[0].file), "--name", `${LABEL} ${tag} contributor`,
    "--out", c1, "--no-receipt"], { quiet: true }));
  mustPass(`accept ${tag}`, coord(["accept", c1, "--dir", d], { quiet: true }));
  const s2 = readState(d);
  return { dir: d, head: path.join(REPO_ROOT, s2.chain[s2.chain.length - 1].file) };
}

function positive(name, r, list) {
  const ok = r.code === 0;
  console.log(`    ${ok ? "ok" : "FAILED"}: ${name}`);
  if (!ok) {
    failures.push(`beacon path: ${name}`);
    for (const line of r.out.split(/\r?\n/)) if (line.trim()) console.log(`    | ${line}`);
  }
  list.push({ name, expectation: "succeeds", result: ok ? "succeeded" : "FAILED", exitCode: r.code });
}

async function beaconPaths(ctx) {
  const checks = [];
  const q = { quiet: true };

  console.log("  8a. drand plan (round 1000000, already public: REHEARSAL ONLY --allow-past)");
  const dr = miniCeremony("drand", ctx);
  positive("beacon-plan --kind drand --round 1000000 --allow-past", coord(["beacon-plan", "--dir", dr.dir, "--kind", "drand", "--round", "1000000", "--allow-past",
    "--announced", `${LABEL}: not announced anywhere`], q), checks);
  checks.push(mustReject("second beacon-plan", "a plan is fixed once recorded", coord(["beacon-plan", "--dir", dr.dir, "--kind", "drand", "--round", "1000001", "--allow-past"], q)));
  const good = path.join(dr.dir, "drand_1000000.json");
  fs.writeFileSync(good, JSON.stringify(DRAND_ROUND_1000000, null, 2) + "\n");
  const badSig = path.join(dr.dir, "drand_1000000_badsig.json");
  const sig = DRAND_ROUND_1000000.signature;
  fs.writeFileSync(badSig, JSON.stringify({ ...DRAND_ROUND_1000000, signature: (sig[0] === "8" ? "9" : "8") + sig.slice(1) }, null, 2) + "\n");
  const R = DRAND_ROUND_1000000.randomness;
  checks.push(mustReject("drand: no API response given", "beacon needs --drand-json for a drand plan", coord(["beacon", dr.head, R, "10", "--dir", dr.dir], q)));
  checks.push(mustReject("drand: iterations differ from plan", "iterExp must equal the announced value", coord(["beacon", dr.head, R, "11", "--dir", dr.dir, "--drand-json", good], q)));
  checks.push(mustReject("drand: value is not the round's randomness", "value must equal the randomness field",
    coord(["beacon", dr.head, "00".repeat(32), "10", "--dir", dr.dir, "--drand-json", good], q)));
  checks.push(mustReject("drand: signature altered", "randomness must equal sha256(signature)", coord(["beacon", dr.head, R, "10", "--dir", dr.dir, "--drand-json", badSig], q)));
  positive("drand beacon with the saved round-1000000 response", coord(["beacon", dr.head, R, "10", "--dir", dr.dir, "--drand-json", good], q), checks);
  positive("finalize (drand)", coord(["finalize", "--dir", dr.dir], q), checks);
  const drFinal = path.join(dr.dir, "final");
  const drAudit = coord(["audit", "--transcript", path.join(drFinal, "ceremony_transcript.json"), "--zkey", path.join(drFinal, "tiny_final.zkey"),
    "--r1cs", ctx.r1cs, "--ptau", ctx.ptau, "--vkey", path.join(drFinal, "verification_key.json")], q);
  positive("audit (drand), includes randomness = sha256(signature)", drAudit, checks);
  if (!/PASS drand randomness = sha256\(signature\)/.test(drAudit.stdout)) failures.push("audit did not run the drand check");

  console.log("  8b. bitcoin plan (height 900000; the block hash used is a made-up test value, not a real block)");
  const bt = miniCeremony("bitcoin", ctx);
  const fakeHash = sha256Hex(Buffer.from("REHEARSAL ONLY: made-up value standing in for a Bitcoin block hash"));
  positive("beacon-plan --kind bitcoin --height 900000", coord(["beacon-plan", "--dir", bt.dir, "--kind", "bitcoin", "--height", "900000"], q), checks);
  checks.push(mustReject("bitcoin: height differs from plan", "--height must equal the announced height",
    coord(["beacon", bt.head, fakeHash, "10", "--dir", bt.dir, "--height", "900001"], q)));
  checks.push(mustReject("bitcoin: value is not 32 bytes", "a block hash is 64 hex", coord(["beacon", bt.head, "abcd", "10", "--dir", bt.dir, "--height", "900000"], q)));
  positive("bitcoin beacon (made-up test value)", coord(["beacon", bt.head, fakeHash, "10", "--dir", bt.dir, "--height", "900000"], q), checks);
  positive("finalize (bitcoin)", coord(["finalize", "--dir", bt.dir], q), checks);

  console.log("  8c. label ceremony refuses rehearsal shortcuts");
  checks.push(mustReject("ceremony label with --no-pin", "pins are mandatory for a real ceremony",
    coord(["init", "--label", "ceremony", "--r1cs", ctx.r1cs, "--ptau", ctx.ptau, "--dir", path.join(OUT, "ceremony_label_a"), "--no-pin"], q)));
  checks.push(mustReject("ceremony label with an unpinned ptau", "ptau must match setup/pins.json or setup/pins_v4.json",
    coord(["init", "--label", "ceremony", "--r1cs", ctx.r1cs, "--ptau", ctx.ptau, "--dir", path.join(OUT, "ceremony_label_b")], q)));
  // a throwaway rehearsal state relabelled as ceremony, to reach the plan check of beacon
  const m = miniCeremony("noplan", ctx);
  const sf = path.join(m.dir, "ceremony_state.json");
  const relabelled = JSON.parse(fs.readFileSync(sf, "utf8"));
  relabelled.label = "ceremony";
  fs.writeFileSync(sf, JSON.stringify(relabelled, null, 2) + "\n");
  checks.push(mustReject("ceremony label: beacon without an announced plan", "a real ceremony needs beacon-plan first",
    coord(["beacon", m.head, "ab".repeat(32), "10", "--dir", m.dir], q)));
  checks.push(mustReject("ceremony label: beacon-plan --allow-past", "past rounds are for rehearsals only",
    coord(["beacon-plan", "--dir", m.dir, "--kind", "drand", "--round", "1000000", "--allow-past"], q)));
  checks.push(mustReject("ceremony label: drand round already public", "a real plan must name a future round",
    coord(["beacon-plan", "--dir", m.dir, "--kind", "drand", "--round", "1000000"], q)));
  // a plan whose round time has passed (written into the throwaway state) closes contributions
  const closed = JSON.parse(fs.readFileSync(sf, "utf8"));
  closed.beaconPlan = { kind: "drand", round: 1000000, expectedTimeUtc: "2021-07-04T20:37:00.000Z", iterExp: 10, iterations: 1024 };
  fs.writeFileSync(sf, JSON.stringify(closed, null, 2) + "\n");
  const late = path.join(m.dir, "late.zkey");
  mustPass("late contribution", run(process.execPath, [ctx.core, "--in", m.head, "--name", `${LABEL} late contributor`, "--out", late, "--no-receipt"], q));
  checks.push(mustReject("contribution after the announced drand round time", "accept closes when the beacon round is due",
    coord(["accept", late, "--dir", m.dir], q)));
  return checks;
}

function readState(dir) {
  return JSON.parse(fs.readFileSync(path.join(dir, "ceremony_state.json"), "utf8"));
}

async function main() {
  if (fs.existsSync(RUNNING_FLAG)) {
    console.error("A timed benchmark is running (results/v4/bench/RUNNING exists). No rehearsal now (docs/BENCHMARK_POLICY.md).");
    return 3;
  }
  const startedUtc = nowUtc();
  const { snarkjs, version: snarkjsVersion } = await loadSnarkjs();
  fs.rmSync(OUT, { recursive: true, force: true });
  fs.mkdirSync(OUT, { recursive: true });

  // 1. compile the throwaway circuit
  step("1. compile tiny.circom (REHEARSAL ONLY circuit)");
  const circom = circomBinary();
  const circomVersion = run(circom, ["--version"], { quiet: true }).stdout.trim();
  console.log(`    ${circomVersion}`);
  const buildDir = path.join(OUT, "build");
  fs.mkdirSync(buildDir, { recursive: true });
  mustPass("circom compile", run(circom, [CIRCUIT_SRC, "--r1cs", "--wasm", "--O2", "-o", buildDir]));
  const r1cs = path.join(buildDir, "tiny.r1cs");
  const wasm = path.join(buildDir, "tiny_js", "tiny.wasm");
  const r1csInfo = await snarkjs.r1cs.info(r1cs, captureLogger(false).logger);

  // 2. tiny local powers of tau
  step(`2. local powers of tau 2^${PTAU_POWER} (throwaway: one contribution, prepare phase2)`);
  const curves = await loadCurves();
  const curve = await curves.getCurveFromName("bn128");
  const ptauDir = path.join(OUT, "ptau");
  fs.mkdirSync(ptauDir, { recursive: true });
  const pot0 = path.join(ptauDir, "pot8_0000.ptau");
  const pot1 = path.join(ptauDir, "pot8_0001.ptau");
  const ptau = path.join(ptauDir, "pot8_final.ptau");
  const pl = captureLogger(false);
  await snarkjs.powersOfTau.newAccumulator(curve, PTAU_POWER, pot0, pl.logger);
  const ptauContribution = await snarkjs.powersOfTau.contribute(pot0, pot1, `${LABEL} ptau contribution`, crypto.randomBytes(64).toString("hex"), pl.logger);
  await snarkjs.powersOfTau.preparePhase2(pot1, ptau, pl.logger);
  const ptauOk = (await snarkjs.powersOfTau.verify(ptau, pl.logger)) === true;
  await curve.terminate();
  if (!ptauOk) failures.push("rehearsal ptau does not verify");
  console.log(`    ptau verify: ${ptauOk ? "OK" : "FAILED"}; sha256 ${sha256File(ptau)}`);

  // 3. coordinator init
  step("3. coordinator init (label rehearsal)");
  const cdir = path.join(OUT, "ceremony");
  mustPass("coordinator init", coord(["init", "--label", "rehearsal", "--title", `${LABEL}: PQ-Identity ceremony rehearsal on a tiny circuit`,
    "--r1cs", r1cs, "--ptau", ptau, "--dir", cdir, "--no-pin", "--allow-unfrozen", "--min-contributions", "3", "--compiler", `${circomVersion} --O2`]));

  // 4. three contributors through the kit and the wrapper scripts
  const plan = wrappers();
  const contributors = [];
  for (let i = 1; i <= 3; i++) {
    const w = plan[i - 1];
    const withVerify = i !== 2; // contributor 2 has no r1cs/ptau: exercises the "coordinator verifies" path
    const name = `${LABEL} contributor ${i} (${w.kind})`;
    step(`4.${i} contributor ${i}: ${w.kind}${withVerify ? " with local verification" : " without local verification"}`);
    const kitDir = path.join(OUT, `contributor_${i}`);
    mustPass(`kit ${i}`, coord(["kit", "--dir", cdir, "--out", kitDir, ...(withVerify ? ["--with-verify-files"] : [])]));
    const st = readState(cdir);
    const head = st.chain[st.chain.length - 1];
    const input = path.join(kitDir, path.basename(head.file));
    const output = path.join(kitDir, `tiny_${String(i).padStart(4, "0")}.zkey`);
    const r = mustPass(`contributor ${i}`, runWrapper(w, kitDir, {
      input, name, output, expectSha: head.sha256,
      r1cs: withVerify ? path.join(kitDir, "tiny.r1cs") : null,
      ptau: withVerify ? path.join(kitDir, "pot8_final.ptau") : null,
    }));
    const m = /CONTRIBUTION_HASH ([0-9a-f]{128})/.exec(r.stdout);
    if (!m) throw new Error(`contributor ${i}: no CONTRIBUTION_HASH printed`);
    const printed = m[1];
    step(`4.${i} coordinator accept (reported hash + receipt)`);
    mustPass(`accept ${i}`, coord(["accept", output, "--dir", cdir, "--hash", printed, "--receipt", `${output}.receipt.json`, "--contributor", name]));
    const st2 = readState(cdir);
    const accepted = st2.chain[st2.chain.length - 1].contribution;
    const receipt = JSON.parse(fs.readFileSync(`${output}.receipt.json`, "utf8"));
    contributors.push({
      step: i,
      name,
      wrapper: w.kind,
      launcher: w.launcherNote ?? path.basename(w.launcher),
      verifiedLocally: receipt.verifiedLocally,
      inputSha256: receipt.input.sha256,
      printedHash: printed,
      acceptedHash: accepted.contributionHash,
      printedEqualsAccepted: printed === accepted.contributionHash,
      entropy: receipt.entropy,
    });
    if (printed !== accepted.contributionHash) failures.push(`contributor ${i}: printed hash differs from accepted`);
  }

  // 5. negative checks
  step("5. negative checks (each must be rejected)");
  const negDir = path.join(OUT, "negative");
  fs.mkdirSync(negDir, { recursive: true });
  const core = path.join(CEREMONY_DIR, "contribute_core.mjs");
  const st = readState(cdir);
  const step1 = path.join(REPO_ROOT, st.chain[1].file);
  const headFile = path.join(REPO_ROOT, st.chain[st.chain.length - 1].file);
  const negatives = [];

  console.log("  5a. late contributor builds on step 1 instead of the head");
  const fork = path.join(negDir, "fork.zkey");
  mustPass("fork contribution", run(process.execPath, [core, "--in", step1, "--name", `${LABEL} stale-base contributor`, "--out", fork, "--no-receipt"], { quiet: true }));
  negatives.push(mustReject("stale base (fork of step 1)", "accept refuses a file that does not extend the current head", coord(["accept", fork, "--dir", cdir])));

  console.log("  5b. valid next contribution, but the reported hash is someone else's");
  const extra = path.join(negDir, "extra.zkey");
  mustPass("extra contribution", run(process.execPath, [core, "--in", headFile, "--name", `${LABEL} extra contributor`, "--out", extra, "--no-receipt"], { quiet: true }));
  negatives.push(mustReject("wrong reported hash", "accept refuses when the hash sent over the second channel differs",
    coord(["accept", extra, "--dir", cdir, "--hash", contributors[0].printedHash])));

  console.log("  5c. tampered file (bytes flipped in the middle of a valid next contribution)");
  const tampered = path.join(negDir, "tampered.zkey");
  const buf = fs.readFileSync(extra);
  const mid = Math.floor(buf.length / 2);
  for (let k = 0; k < 4; k++) buf[mid + k] ^= 0xff;
  fs.writeFileSync(tampered, buf);
  negatives.push(mustReject("tampered zkey", "snarkjs zkey verify fails", coord(["accept", tampered, "--dir", cdir])));

  console.log("  5d. beacon applied to a file that is not the head");
  negatives.push(mustReject("beacon on non-head", "beacon applies to the head only",
    coord(["beacon", step1, "ab".repeat(32), "10", "--dir", cdir, "--source", `${LABEL}: negative check`])));

  console.log("  5e. finalize before the beacon");
  negatives.push(mustReject("finalize before beacon", "finalize needs the beacon", coord(["finalize", "--dir", cdir])));

  // 6. beacon, finalize, audit
  step("6. dummy beacon (REHEARSAL ONLY), finalize, audit");
  const dummy = sha256Hex(Buffer.from("PQ-Identity ceremony rehearsal: REHEARSAL ONLY dummy beacon, not a public randomness source"));
  mustPass("beacon", coord(["beacon", headFile, dummy, "10", "--dir", cdir,
    "--source", `${LABEL}: dummy beacon = sha256 of a fixed string, not a public randomness source`]));
  mustPass("finalize", coord(["finalize", "--dir", cdir]));
  const finalDir = path.join(cdir, "final");
  const transcriptFile = path.join(finalDir, "ceremony_transcript.json");
  const finalZkey = path.join(finalDir, "tiny_final.zkey");
  const vkeyFile = path.join(finalDir, "verification_key.json");
  const solFile = path.join(finalDir, "Groth16Verifier.sol");
  const audit = coord(["audit", "--transcript", transcriptFile, "--zkey", finalZkey, "--r1cs", r1cs, "--ptau", ptau,
    "--vkey", vkeyFile, "--sol", solFile, "--my-hash", contributors[1].printedHash]);
  const auditPassed = audit.code === 0 && /ALL CHECKS PASSED/.test(audit.stdout);
  if (!auditPassed) failures.push("audit of the finalized rehearsal key failed");

  console.log("  6b. audit with a contribution hash that is not in the key (the stale-base one)");
  const forkReceiptHash = /CONTRIBUTION_HASH ([0-9a-f]{128})/.exec(
    run(process.execPath, [core, "--in", step1, "--name", `${LABEL} never-accepted contributor`, "--out", path.join(negDir, "fork2.zkey"), "--no-receipt"], { quiet: true }).stdout
  )?.[1];
  negatives.push(mustReject("audit: hash not in the final key", "audit fails when a contributor's hash is missing",
    coord(["audit", "--transcript", transcriptFile, "--zkey", finalZkey, "--r1cs", r1cs, "--ptau", ptau, "--my-hash", forkReceiptHash ?? "00"])));

  // 7. prove and verify with the rehearsal key
  step("7. prove and verify with the rehearsal key");
  const input = { x: 3, salt: 11, y: 35, tag: 40 };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, finalZkey);
  const vkey = JSON.parse(fs.readFileSync(vkeyFile, "utf8"));
  const silent = captureLogger(false).logger;
  const proofOk = (await snarkjs.groth16.verify(vkey, publicSignals, proof, silent)) === true;
  const badSignals = [...publicSignals];
  badSignals[0] = String(BigInt(badSignals[0]) + 1n);
  const tamperedRejected = (await snarkjs.groth16.verify(vkey, badSignals, proof, silent)) !== true;
  const vkey0 = await snarkjs.zKey.exportVerificationKey(path.join(REPO_ROOT, st.chain[0].file));
  const initKeyRejects = (await snarkjs.groth16.verify(vkey0, publicSignals, proof, silent)) !== true;
  console.log(`    proof verifies with the final rehearsal vkey: ${proofOk}`);
  console.log(`    tampered public signal rejected: ${tamperedRejected}`);
  console.log(`    proof rejected by the pre-contribution (0000) vkey: ${initKeyRejects}`);
  if (!proofOk) failures.push("proof did not verify with the rehearsal key");
  if (!tamperedRejected) failures.push("tampered public signal was accepted");
  if (!initKeyRejects) failures.push("proof verified under the 0000 key (delta unchanged?)");

  // 8. planned-beacon code paths on more throwaway ceremonies (tiny circuit, 1 contribution each)
  step("8. planned-beacon code paths (drand, bitcoin) on throwaway ceremonies");
  const beaconPathChecks = await beaconPaths({ r1cs, ptau, core });

  // transcript
  const ceremonyTranscript = JSON.parse(fs.readFileSync(transcriptFile, "utf8"));
  const result = failures.length === 0 ? "PASS" : "FAIL";
  const out = {
    schema: "pqid/ceremony-rehearsal/v1",
    label: LABEL,
    warning: `${LABEL}. Throwaway circuit, throwaway local powers of tau, dummy beacon. Nothing here is a PQ-Identity key or ceremony evidence for one.`,
    result,
    failures,
    startedUtc,
    finishedUtc: nowUtc(),
    script: { file: rec(fileURLToPath(import.meta.url)), sha256: sha256File(fileURLToPath(import.meta.url)) },
    circuit: {
      source: rec(CIRCUIT_SRC),
      sourceSha256: sha256File(CIRCUIT_SRC),
      compiler: `${circomVersion} --O2`,
      nConstraints: r1csInfo.nConstraints,
      nPubInputs: r1csInfo.nPubInputs,
      nPrvInputs: r1csInfo.nPrvInputs,
      r1csSha256: sha256File(r1cs),
    },
    ptau: {
      power: PTAU_POWER,
      how: "snarkjs powersOfTau.newAccumulator bn128 2^8, one contribution with OS randomness (in memory only), preparePhase2",
      contributionHash: Buffer.from(ptauContribution).toString("hex"),
      verified: ptauOk,
      sha256: sha256File(ptau),
    },
    contributors,
    negativeChecks: negatives,
    beaconPathChecks,
    beacon: { value: dummy, derivation: "sha256 of a fixed ASCII string (see ceremony/rehearse.mjs)", numIterationsExp: 10, label: `${LABEL} dummy` },
    audit: { command: "coordinator.mjs audit --transcript --zkey --r1cs --ptau --vkey --sol --my-hash <contributor 2>", passed: auditPassed },
    proof: {
      statement: "x^3 + x + 5 = y and x * salt + 7 = tag with x < 2^32 (x = 3, salt = 11 private)",
      publicSignals,
      verifiesWithFinalKey: proofOk,
      tamperedPublicSignalRejected: tamperedRejected,
      rejectedByInitialKey: initKeyRejects,
    },
    ceremonyTranscript,
    tools: { snarkjs: snarkjsVersion, node: process.version, circom: circomVersion },
    environment: envMeta(),
    note: "Intermediate files are in ceremony/rehearsal/_out/ (gitignored, deleted on the next run). No durations are recorded.",
  };
  writeJsonAtomic(TRANSCRIPT_OUT, out);
  step(`REHEARSAL ${result}: ${rec(TRANSCRIPT_OUT)}`);
  for (const f of failures) console.log(`  FAILURE: ${f}`);
  return failures.length === 0 ? 0 : 1;
}

/**
 * circom writes generate_witness.js and witness_calculator.js next to the wasm. They are not
 * needed after proving, and the repo's `eslint .` would lint them, so they are removed on exit
 * (the wasm stays in _out for inspection).
 */
function removeGeneratedJs() {
  const jsDir = path.join(OUT, "build", "tiny_js");
  if (!fs.existsSync(jsDir)) return;
  for (const f of fs.readdirSync(jsDir)) if (/\.(c|m)?js$/.test(f)) fs.rmSync(path.join(jsDir, f), { force: true });
}

main().then(
  (code) => {
    removeGeneratedJs();
    process.exit(code);
  },
  (e) => {
    removeGeneratedJs();
    console.error(`REHEARSAL ERROR: ${e instanceof Error ? e.stack : String(e)}`);
    for (const f of failures) console.error(`  FAILURE: ${f}`);
    process.exit(1);
  }
);
