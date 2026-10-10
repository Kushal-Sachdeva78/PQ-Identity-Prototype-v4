// Key and download sizes for the phone kit (docs/v4/PHONE_PROTOCOL.md, "Key download size").
//
// Reads each artifact once, hashes it and gzips it IN MEMORY (node:zlib, levels 6 and 9).
// Writes nothing except the JSON result. No timing, no network.
//
// Usage (repo root):  node mobile/scripts/key_size.mjs [--out <path>]
// Default output:     mobile/results/key_size.json
//
// Native path (Mopro): the app bundle carries the zkey; the wasm is transpiled into the
// app binary by rust-witness, so the wasm size is not a native download (the binary size
// is measured on the Mac/CI build, not here).
// Safari path: the page downloads the zkey, the wasm, the vkey, the input files and
// snarkjs.min.js on every cold page load (serve.ts sends Cache-Control: no-store).

import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const rel = (p) => path.relative(REPO_ROOT, p).split(path.sep).join("/");

const ARTIFACTS = [
  { id: "zkey", file: "setup/out/v4/credential_auth_v4_dev.zkey", native: true, safari: true },
  { id: "wasm", file: "circuits/build/v4/credential_auth_v4_js/credential_auth_v4.wasm", native: false, safari: true },
  { id: "vkey", file: "setup/out/v4/verification_key_dev.json", native: false, safari: true },
  { id: "snarkjs", file: "node_modules/snarkjs/build/snarkjs.min.js", native: false, safari: true },
  { id: "input", file: "mobile/inputs/v4_input.json", native: false, safari: true },
  { id: "inputMopro", file: "mobile/inputs/v4_input.mopro.json", native: true, safari: false },
  { id: "inputMeta", file: "mobile/inputs/v4_input.meta.json", native: true, safari: true },
];

function argValue(name) {
  const i = process.argv.indexOf(`--${name}`);
  if (i < 0) return undefined;
  const v = process.argv[i + 1];
  if (!v || v.startsWith("--")) throw new Error(`--${name} needs a value`);
  return v;
}

function readPins() {
  const f = path.join(REPO_ROOT, "setup", "pins_v4.json");
  if (!fs.existsSync(f)) return {};
  const pins = JSON.parse(fs.readFileSync(f, "utf8"));
  const byPath = {};
  for (const v of Object.values(pins)) byPath[v.path] = v.sha256;
  return byPath;
}

function snarkjsVersion() {
  try {
    return JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "node_modules", "snarkjs", "package.json"), "utf8")).version;
  } catch {
    return null;
  }
}

function main() {
  const out = path.resolve(REPO_ROOT, argValue("out") ?? path.join("mobile", "results", "key_size.json"));
  const pins = readPins();
  const rows = [];
  for (const a of ARTIFACTS) {
    const abs = path.join(REPO_ROOT, a.file);
    if (!fs.existsSync(abs)) throw new Error(`${a.file} missing`);
    const data = fs.readFileSync(abs);
    const sha256 = createHash("sha256").update(data).digest("hex");
    const gz6 = zlib.gzipSync(data, { level: 6 }).length;
    const gz9 = zlib.gzipSync(data, { level: 9 }).length;
    rows.push({
      id: a.id,
      path: a.file,
      bytes: data.length,
      sha256,
      pinnedSha256Match: a.file in pins ? pins[a.file] === sha256 : null,
      gzipLevel6Bytes: gz6,
      gzipLevel9Bytes: gz9,
      gzipLevel9Ratio: Number((gz9 / data.length).toFixed(4)),
      countsFor: { native: a.native, safari: a.safari },
    });
  }
  const sum = (pred, key) => rows.filter(pred).reduce((s, r) => s + r[key], 0);
  const result = {
    schema: "pqid/v4-phone-key-size/v1",
    label: "[M] file sizes and in-memory gzip sizes (node:zlib); dev key",
    generator: "mobile/scripts/key_size.mjs",
    keyLabel: "dev",
    artifacts: rows,
    totals: {
      nativeBundledBytes: sum((r) => r.countsFor.native, "bytes"),
      nativeBundledNote: "zkey + input + input meta files only; the app binary (with the transpiled witness generator) is not included",
      safariPerColdLoadBytes: sum((r) => r.countsFor.safari, "bytes"),
      safariPerColdLoadGzip9Bytes: sum((r) => r.countsFor.safari, "gzipLevel9Bytes"),
      safariNote: "serve.ts sends files uncompressed with Cache-Control: no-store; the gzip column is what a gzip-serving host would send",
    },
    env: {
      node: process.versions.node,
      zlib: process.versions.zlib,
      snarkjs: snarkjsVersion(),
      platform: process.platform,
      timestampUtc: new Date().toISOString(),
    },
  };
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(result, null, 2) + "\n");
  for (const r of rows) {
    console.log(`[key_size] ${r.id.padEnd(8)} ${String(r.bytes).padStart(10)} B  gzip-9 ${String(r.gzipLevel9Bytes).padStart(10)} B  pin ${r.pinnedSha256Match}`);
  }
  console.log(`[key_size] wrote ${rel(out)}`);
}

main();
