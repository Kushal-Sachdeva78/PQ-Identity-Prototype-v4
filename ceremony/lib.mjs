// Shared helpers for the PQ-Identity phase-2 ceremony kit (coordinator, contributors,
// rehearsal). Node ESM, no dependencies beyond snarkjs. This file is handed to outside
// contributors together with contribute_core.mjs, so it must not import repo code.
//
// Nothing here writes entropy or secret values anywhere.

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

/** snarkjs version every step of the ceremony is pinned to (repo package.json). */
export const EXPECTED_SNARKJS = "0.7.4";

/** Minimum Node.js major version for the kit. */
export const MIN_NODE_MAJOR = 20;

/**
 * drand League of Entropy mainnet, "default" network (chained, 30 s rounds).
 * Values read from https://api.drand.sh/info on 2026-09-27; randomness = sha256(signature)
 * per https://docs.drand.love/docs/specification/ ("rand := sha256.Sum256(signature)"),
 * checked on round 1000000 the same day.
 */
export const DRAND_DEFAULT = Object.freeze({
  network: "drand League of Entropy mainnet, default network (pedersen-bls-chained)",
  chainHash: "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce",
  genesisTime: 1595431050,
  periodSec: 30,
  api: "https://api.drand.sh/public/",
  relays: ["https://api.drand.sh", "https://api2.drand.sh", "https://api3.drand.sh", "https://drand.cloudflare.com"],
});

export function checkNodeVersion() {
  const major = Number(process.versions.node.split(".")[0]);
  if (!(major >= MIN_NODE_MAJOR)) {
    throw new Error(`Node.js ${MIN_NODE_MAJOR} or newer is needed (this is ${process.version}). Get it from https://nodejs.org`);
  }
}

/** Where snarkjs resolves from (the kit's own node_modules, else the repo's). */
export function snarkjsLocation() {
  const req = createRequire(import.meta.url);
  let cjs;
  try {
    cjs = req.resolve("snarkjs");
  } catch {
    return null;
  }
  const dir = path.resolve(path.dirname(cjs), "..");
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  return { dir, version: String(pkg.version) };
}

/** Load snarkjs and check it is the pinned version (unless allowOther). */
export async function loadSnarkjs({ allowOther = false } = {}) {
  const loc = snarkjsLocation();
  if (!loc) {
    throw new Error(
      "snarkjs is not installed next to this kit. In the kit folder run:  npm install\n" +
        `(the kit's package.json pins snarkjs ${EXPECTED_SNARKJS})`
    );
  }
  if (loc.version !== EXPECTED_SNARKJS && !allowOther) {
    throw new Error(`snarkjs ${loc.version} found, the ceremony is pinned to ${EXPECTED_SNARKJS}. Run npm install in the kit folder.`);
  }
  const snarkjs = await import("snarkjs");
  return { snarkjs, version: loc.version, dir: loc.dir };
}

/** snarkjs curves module (not in the package's exports map; loaded by file URL). */
export async function loadCurves() {
  const loc = snarkjsLocation();
  if (!loc) throw new Error("snarkjs not found");
  return import(pathToFileURL(path.join(loc.dir, "src", "curves.js")).href);
}

/** The Groth16 Solidity verifier template shipped with snarkjs. */
export function solidityTemplates() {
  const loc = snarkjsLocation();
  if (!loc) throw new Error("snarkjs not found");
  return { groth16: fs.readFileSync(path.join(loc.dir, "templates", "verifier_groth16.sol.ejs"), "utf8") };
}

export function sha256File(file) {
  const h = crypto.createHash("sha256");
  const fd = fs.openSync(file, "r");
  try {
    const buf = Buffer.allocUnsafe(1 << 20);
    let n;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n));
  } finally {
    fs.closeSync(fd);
  }
  return h.digest("hex");
}

export function sha256Hex(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

export function isHex(s, bytes) {
  if (typeof s !== "string" || !/^[0-9a-f]+$/.test(s) || s.length % 2 !== 0) return false;
  return bytes === undefined ? true : s.length === bytes * 2;
}

/** Print a 64-byte hash the way snarkjs does (4 lines of 4 words). */
export function formatHashHex(hex, indent = "    ") {
  const lines = [];
  for (let i = 0; i < 4; i++) {
    const words = [];
    for (let j = 0; j < 4; j++) words.push(hex.slice(i * 32 + j * 8, i * 32 + j * 8 + 8));
    lines.push(indent + words.join(" "));
  }
  return lines.join("\n");
}

/** Logger for snarkjs that records every message and optionally echoes it. */
export function captureLogger(echo = false) {
  const lines = [];
  const push = (m) => {
    const s = String(m);
    lines.push(s);
    if (echo) console.log(s);
  };
  return { lines, logger: { info: push, warn: push, error: push, log: push, debug: () => undefined } };
}

function hexOnly(s) {
  return s.replace(/[^0-9a-f]/gi, "").toLowerCase();
}

/**
 * Parse the messages snarkjs zkey verify logs (zkey_verify_frominit.js) into
 * { circuitHash, contributions: [{index, name, contributionHash, type, beaconHash?, numIterationsExp?}] }.
 */
export function parseVerifyLog(lines) {
  let circuitHash = null;
  const contributions = [];
  for (const m of lines) {
    let r = /^Circuit Hash: *\n([\s\S]*)$/.exec(m);
    if (r) {
      circuitHash = hexOnly(r[1]);
      continue;
    }
    r = /^contribution #(\d+) ?(.*):\n([\s\S]*)$/.exec(m);
    if (r) {
      contributions.push({ index: Number(r[1]), name: r[2].trim(), contributionHash: hexOnly(r[3]), type: "contribution" });
      continue;
    }
    const last = contributions[contributions.length - 1];
    r = /^Beacon generator: ([0-9a-fA-F]+)$/.exec(m);
    if (r && last) {
      last.type = "beacon";
      last.beaconHash = r[1].toLowerCase();
      continue;
    }
    r = /^Beacon iterations Exp: (\d+)$/.exec(m);
    if (r && last) last.numIterationsExp = Number(r[1]);
  }
  contributions.sort((a, b) => a.index - b.index);
  return { circuitHash, contributions };
}

/** snarkjs zkey verify (from r1cs + ptau) with the contribution list parsed out. */
export async function verifyZkey(snarkjs, r1csFile, ptauFile, zkeyFile, { echo = false } = {}) {
  const { lines, logger } = captureLogger(echo);
  let ok = false;
  let error = null;
  try {
    ok = (await snarkjs.zKey.verifyFromR1cs(r1csFile, ptauFile, zkeyFile, logger)) === true;
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }
  const parsed = parseVerifyLog(lines);
  return { ok, error, ...parsed, lines };
}

/** A contributor name is shown in the zkey and the transcript: keep it short and plain. */
export function checkContributorName(name) {
  if (typeof name !== "string" || name.trim().length === 0) throw new Error("contributor name is empty");
  if (name.length > 64) throw new Error("contributor name is longer than 64 characters");
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f"`$\\]/.test(name)) {
    throw new Error('contributor name may not contain control characters, quotes, backticks, "$" or "\\"');
  }
  return name.trim();
}

/** Platform facts for transcripts: no hostname, username or home path. */
export function envMeta() {
  return {
    platform: `${process.platform} ${os.arch()}`,
    osRelease: os.release(),
    node: process.version,
  };
}

export function nowUtc() {
  return new Date().toISOString();
}

/**
 * Path for records: relative to `root` (forward slashes) when inside it, else the base
 * name only, so no home path or username ends up in a transcript.
 */
export function recPath(file, root) {
  const abs = path.resolve(file);
  if (root) {
    const rel = path.relative(path.resolve(root), abs);
    if (rel && !rel.startsWith("..") && !path.isAbsolute(rel)) return rel.split(path.sep).join("/");
  }
  return path.basename(abs);
}

/** Minimal argument parser: positionals plus --flag and --key value. */
export function parseArgs(argv, { flags = [], options = [] } = {}) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      if (flags.includes(key)) {
        out[key] = true;
      } else if (options.includes(key)) {
        const v = argv[i + 1];
        if (v === undefined) throw new Error(`--${key} needs a value`);
        out[key] = v;
        i++;
      } else {
        throw new Error(`unknown option --${key}`);
      }
    } else {
      out._.push(a);
    }
  }
  return out;
}

/** Write JSON atomically (temp file + rename). */
export function writeJsonAtomic(file, obj) {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + "\n");
  fs.renameSync(tmp, file);
}
