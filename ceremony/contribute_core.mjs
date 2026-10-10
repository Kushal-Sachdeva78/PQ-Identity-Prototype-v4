#!/usr/bin/env node
// One phase-2 contribution to the PQ-Identity Groth16 ceremony.
//
// Called by contribute.ps1 (Windows) and contribute.sh (macOS/Linux); the rehearsal uses
// the same wrappers. It runs snarkjs zkey contribute through the snarkjs library, so the
// entropy never appears on a command line, in a file or in a log:
//   - 64 bytes from the OS random generator (crypto.randomBytes), passed in memory;
//   - snarkjs itself mixes in another 64 OS random bytes (misc.getRandomRng);
//   - optional extra text typed by the contributor (hidden, kept in memory only).
// When the process exits the secret is gone; nothing secret is ever written to disk.
//
// Usage:
//   node contribute_core.mjs --in <input.zkey> --name "<name>" --out <output.zkey>
//        [--r1cs <circuit.r1cs> --ptau <file.ptau>]   verify the output afterwards
//        [--expect-in-sha256 <hex>]                     check the input file first
//        [--extra-entropy]                              also ask for typed random text
//        [--no-receipt] [--any-snarkjs]

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import {
  checkNodeVersion,
  loadSnarkjs,
  sha256File,
  formatHashHex,
  captureLogger,
  verifyZkey,
  checkContributorName,
  envMeta,
  nowUtc,
  parseArgs,
  isHex,
} from "./lib.mjs";

const USAGE = `Usage:
  node contribute_core.mjs --in <input.zkey> --name "<your name>" --out <output.zkey>
       [--r1cs <circuit.r1cs> --ptau <file.ptau>] [--expect-in-sha256 <hex>]
       [--extra-entropy] [--no-receipt] [--any-snarkjs]`;

/** Read one line without echoing it (TTY), or one line from piped stdin. */
function readHidden(prompt) {
  process.stdout.write(prompt);
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    return new Promise((resolve) => {
      let data = "";
      stdin.setEncoding("utf8");
      const onData = (d) => {
        data += d;
        const i = data.indexOf("\n");
        if (i >= 0) {
          stdin.off("data", onData);
          stdin.pause();
          resolve(data.slice(0, i).replace(/\r$/, ""));
        }
      };
      stdin.on("data", onData);
      stdin.on("end", () => resolve(data));
      stdin.resume();
    });
  }
  return new Promise((resolve, reject) => {
    let s = "";
    const cleanup = () => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
      process.stdout.write("\n");
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          cleanup();
          resolve(s);
          return;
        }
        if (ch === "\u0003") {
          cleanup();
          reject(new Error("cancelled"));
          return;
        }
        if (ch === "\u007f" || ch === "\b") {
          s = s.slice(0, -1);
          continue;
        }
        s += ch;
      }
    };
    stdin.setRawMode(true);
    stdin.setEncoding("utf8");
    stdin.on("data", onData);
    stdin.resume();
  });
}

async function main() {
  checkNodeVersion();
  const args = parseArgs(process.argv.slice(2), {
    flags: ["extra-entropy", "no-receipt", "any-snarkjs", "help"],
    options: ["in", "name", "out", "r1cs", "ptau", "expect-in-sha256"],
  });
  if (args.help) {
    console.log(USAGE);
    return 0;
  }
  if (!args.in || !args.name || !args.out) {
    console.error(USAGE);
    return 2;
  }
  const name = checkContributorName(args.name);
  const inFile = path.resolve(args.in);
  const outFile = path.resolve(args.out);
  const receiptFile = `${outFile}.receipt.json`;
  if (!fs.existsSync(inFile)) throw new Error(`input zkey not found: ${args.in}`);
  if (inFile === outFile) throw new Error("output must be a new file, not the input");
  if (fs.existsSync(outFile)) throw new Error(`output already exists (not overwritten): ${args.out}`);
  if (!args["no-receipt"] && fs.existsSync(receiptFile)) throw new Error(`receipt already exists: ${receiptFile}`);
  if (!fs.existsSync(path.dirname(outFile))) throw new Error(`output folder does not exist: ${path.dirname(outFile)}`);
  if (Boolean(args.r1cs) !== Boolean(args.ptau)) throw new Error("give both --r1cs and --ptau, or neither");
  for (const f of [args.r1cs, args.ptau]) if (f && !fs.existsSync(f)) throw new Error(`not found: ${f}`);

  const { snarkjs, version } = await loadSnarkjs({ allowOther: Boolean(args["any-snarkjs"]) });

  console.log("PQ-Identity Groth16 phase-2 ceremony: one contribution");
  console.log(`  contributor name : ${name}`);
  console.log(`  input zkey       : ${path.basename(inFile)}`);
  const inSha = sha256File(inFile);
  console.log(`  input sha256     : ${inSha}`);
  if (args["expect-in-sha256"]) {
    const want = String(args["expect-in-sha256"]).toLowerCase();
    if (!isHex(want, 32)) throw new Error("--expect-in-sha256 must be 64 hex characters");
    if (want !== inSha) {
      throw new Error(`input sha256 does not match the value the coordinator published (${want}). Do not contribute; ask the coordinator.`);
    }
    console.log("  input sha256 matches the published value");
  }
  console.log(`  snarkjs          : ${version}`);

  let extra = "";
  if (args["extra-entropy"]) {
    extra = await readHidden("Type some random text (not shown, never saved), then press Enter: ");
  }

  console.log("Contributing. Randomness comes from the OS generator and stays in memory only...");
  const { lines, logger } = captureLogger(false);
  let entropy = crypto.randomBytes(64).toString("hex") + (extra ? "\n" + extra : "");
  const usedExtra = extra.length > 0;
  extra = "";
  let hashBytes;
  try {
    hashBytes = await snarkjs.zKey.contribute(inFile, outFile, name, entropy, logger);
  } catch (e) {
    fs.rmSync(outFile, { force: true });
    throw e;
  } finally {
    entropy = "";
  }
  if (!hashBytes) {
    fs.rmSync(outFile, { force: true });
    throw new Error("snarkjs zkey contribute failed:\n" + lines.join("\n"));
  }
  const contributionHash = Buffer.from(hashBytes).toString("hex");
  const outSha = sha256File(outFile);

  console.log("");
  console.log("Your contribution hash (write it down or copy it; publish or send it separately):");
  console.log(formatHashHex(contributionHash));
  console.log(`CONTRIBUTION_HASH ${contributionHash}`);
  console.log(`OUTPUT_SHA256 ${outSha}`);
  console.log(`output zkey: ${path.basename(outFile)}`);

  let verified = null;
  let circuitHash = null;
  let chain = null;
  if (args.r1cs && args.ptau) {
    console.log("");
    console.log("Verifying the output against the circuit and the powers of tau (snarkjs zkey verify)...");
    const v = await verifyZkey(snarkjs, args.r1cs, args.ptau, outFile);
    const last = v.contributions[v.contributions.length - 1];
    const problems = [];
    if (!v.ok) problems.push(`snarkjs zkey verify failed${v.error ? ": " + v.error : ""}`);
    if (!last) problems.push("no contribution found in the output");
    else {
      if (last.contributionHash !== contributionHash) problems.push("last contribution hash differs from the one just made");
      if (last.name !== name) problems.push(`last contribution name is "${last.name}", expected "${name}"`);
      if (last.type !== "contribution") problems.push("last entry is a beacon, not a contribution");
    }
    if (problems.length) {
      console.error(v.lines.join("\n"));
      throw new Error("VERIFICATION FAILED, do not send this file: " + problems.join("; "));
    }
    verified = true;
    circuitHash = v.circuitHash;
    chain = v.contributions.map((c) => ({ index: c.index, name: c.name, contributionHash: c.contributionHash, type: c.type }));
    console.log("Verified. Contributions in this file:");
    for (const c of chain) console.log(`  #${c.index} ${c.type === "beacon" ? "[beacon] " : ""}${c.name}  ${c.contributionHash.slice(0, 16)}...`);
  } else {
    console.log("(no --r1cs/--ptau given: output not verified here; the coordinator verifies it)");
  }

  if (!args["no-receipt"]) {
    const receipt = {
      schema: "pqid/ceremony-contribution-receipt/v1",
      contributor: name,
      input: { file: path.basename(inFile), sha256: inSha },
      output: { file: path.basename(outFile), sha256: outSha },
      contributionHash,
      verifiedLocally: verified === true,
      circuitHash,
      chain,
      entropy: usedExtra
        ? "OS randomness (64 B here + 64 B inside snarkjs) plus typed text; none of it was written anywhere"
        : "OS randomness (64 B here + 64 B inside snarkjs); none of it was written anywhere",
      snarkjs: version,
      environment: envMeta(),
      dateUtc: nowUtc(),
    };
    fs.writeFileSync(receiptFile, JSON.stringify(receipt, null, 2) + "\n");
    console.log(`receipt (no secrets): ${path.basename(receiptFile)}`);
  }

  console.log("");
  console.log("Next: send the output zkey (and the receipt) back to the coordinator.");
  console.log("Also send or post your CONTRIBUTION_HASH through a second channel, so you can");
  console.log("later check that the published transcript lists exactly that hash under your name.");
  console.log("Nothing secret was saved. You can close this window.");
  return 0;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(`ERROR: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
);
