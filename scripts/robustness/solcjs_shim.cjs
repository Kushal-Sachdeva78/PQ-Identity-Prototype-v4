#!/usr/bin/env node
// solc command-line shim over the repository's pinned solc-js 0.8.28 (node_modules/solc), so
// forge can compile the RegistriesV4 fuzz and invariant tests without downloading a native solc
// (DECISIONS D-034: no downloads for the robustness row). It is the compiler the v4 ledger uses
// (packages/v4/src/ledger.ts compileSolidityV4: solc-js 0.8.28, optimizer 200).
//
// Supported subset of the solc CLI, which is what forge calls:
//   solc --version
//   solc --standard-json [--base-path <dir>] [--include-path <dir>]... [--allow-paths <list>] [other flags ignored]
//     reads the Standard JSON input on stdin and writes the Standard JSON output on stdout.
// Imports that forge did not inline are read from the base path and include paths, and only
// from inside them (no network, no other file access).
//
// Launchers: scripts/robustness/solc_shim.cmd (Windows, passed to forge with --use) and
// scripts/robustness/solc_shim.sh (Linux and WSL).
"use strict";
/* global require, __dirname */
/* eslint-disable @typescript-eslint/no-require-imports */

const fs = require("node:fs");
const path = require("node:path");

function repoRoot() {
  return path.resolve(__dirname, "..", "..");
}

function loadSolc() {
  return require(path.join(repoRoot(), "node_modules", "solc"));
}

function main(argv) {
  if (argv.includes("--version") || argv.includes("-v")) {
    const solc = loadSolc();
    // forge parses the last non-empty line, after "Version: "
    process.stdout.write("solc, the solidity compiler commandline interface (solc-js shim)\n");
    process.stdout.write(`Version: ${solc.version()}\n`);
    return 0;
  }
  if (!argv.includes("--standard-json")) {
    process.stderr.write("solcjs_shim: only --version and --standard-json are supported\n");
    return 2;
  }
  const roots = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if ((a === "--base-path" || a === "--include-path") && i + 1 < argv.length) roots.push(path.resolve(argv[++i]));
    else if (a.startsWith("--base-path=") || a.startsWith("--include-path=")) roots.push(path.resolve(a.slice(a.indexOf("=") + 1)));
  }
  if (roots.length === 0) roots.push(process.cwd());
  const input = fs.readFileSync(0, "utf8");
  const solc = loadSolc();
  const findImports = (p) => {
    for (const r of roots) {
      const f = path.resolve(r, p);
      const inside = f === r || f.startsWith(r + path.sep);
      if (inside && fs.existsSync(f) && fs.statSync(f).isFile()) return { contents: fs.readFileSync(f, "utf8") };
    }
    return { error: `File not found inside the base or include paths: ${p}` };
  };
  const out = solc.compile(input, { import: findImports });
  process.stdout.write(out);
  return 0;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (e) {
  process.stderr.write(`solcjs_shim: ${e && e.message ? e.message : String(e)}\n`);
  process.exitCode = 1;
}
