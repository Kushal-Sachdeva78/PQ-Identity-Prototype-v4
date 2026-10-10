import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { REPO_ROOT, envInfo, gitHead, sanitize, rel, utcNow, writeJson, flag, opt, optNum, sha256FileHex } from "../bench/lib.ts";
import { acquireMarker, assertMarkersFree, markerRoots, windowsRepoFromArgs } from "../lib/markers.ts";
import { SEEDS } from "../lib/seeds.ts";
import { robustnessRoot, protocolRecord, assertCommitted, budgetDeviation } from "./common.ts";

/**
 * Forge fuzz and invariant tests of onchain/contracts/v4/RegistriesV4.sol (robustness row,
 * DECISIONS D-034; docs/v4/ROBUSTNESS.md section 6). Untimed; a full campaign holds
 * results/v4/BUSY. Seed robustness.forgeFuzz 20261024.
 *
 *   node --import tsx harness/v4/robustness/forge_fuzz.ts --campaign <name> [--windows-repo <dir>] [--forge <path>]
 *        [--deviation "<text>" --fuzz-runs N --invariant-runs N --invariant-depth N]
 *   node --import tsx harness/v4/robustness/forge_fuzz.ts --smoke [--campaign <name>]
 *
 * A full run uses the pre-registered budgets (10,000 fuzz runs; invariant 256 x 100) and refuses
 * to start unless the tests, the configuration, the shim and the contracts are committed; another
 * budget needs --deviation (recorded in plan.json and appended to the protocol's Deviations).
 * The effective compiler settings (forge config: evm_version, optimizer, optimizer_runs) are
 * recorded in env.json.
 *
 * Tests: onchain/test/v4/RegistriesV4.fuzz.t.sol (config onchain/foundry.toml). The compiler is
 * the repository's solc-js 0.8.28 through scripts/robustness/solc_shim.(cmd|sh) (no download;
 * forge runs with --offline). Build output, caches and forge's own failure-persistence files go
 * to a fresh directory in the OS temp directory per run, so a campaign never replays an earlier
 * campaign's failures; the persisted failure files are copied into the results.
 * Results: results/v4/robustness/forge/<campaign>/ plan.json, env.json, results.json (forge's
 * JSON without traces), failures/<contract>.<test>.json (counterexample calldata and arguments,
 * replay command), persisted/ (forge's failure files), summary.json, summary.md.
 */

const SELF = fileURLToPath(import.meta.url);
const SEED = SEEDS.robustness.forgeFuzz;
const TEST_FILE = path.join(REPO_ROOT, "onchain", "test", "v4", "RegistriesV4.fuzz.t.sol");
const CONTRACT_FILE = path.join(REPO_ROOT, "onchain", "contracts", "v4", "RegistriesV4.sol");
const CONFIG_FILE = path.join(REPO_ROOT, "onchain", "foundry.toml");
const SHIM_FILES = ["scripts/robustness/solcjs_shim.cjs", "scripts/robustness/solc_shim.cmd", "scripts/robustness/solc_shim.sh"];

export const FORGE_BUDGETS = Object.freeze({
  full: Object.freeze({ fuzzRuns: 10_000, invariantRuns: 256, invariantDepth: 100 }),
  smoke: Object.freeze({ fuzzRuns: 64, invariantRuns: 8, invariantDepth: 25 }),
});

function forgeBinary(argv: readonly string[]): string {
  const given = opt(argv, "forge") ?? process.env["PQID_FORGE"];
  if (given) return path.resolve(given);
  if (process.platform === "win32") return path.join(REPO_ROOT, "tools", "foundry", "forge.exe");
  // the D-034 WSL toolchain directory (run_robustness.sh PQID_ANVIL_DIR), when it also holds forge
  const toolDir = process.env["PQID_ANVIL_DIR"];
  if (toolDir && fs.existsSync(path.join(toolDir, "forge"))) return path.join(toolDir, "forge");
  const home = os.homedir();
  const user = path.join(home, ".foundry", "bin", "forge");
  return fs.existsSync(user) ? user : "forge";
}

function shimFile(): string {
  const shim = path.join(REPO_ROOT, "scripts", "robustness", process.platform === "win32" ? "solc_shim.cmd" : "solc_shim.sh");
  if (process.platform !== "win32") {
    try {
      fs.accessSync(shim, fs.constants.X_OK);
    } catch {
      throw new Error(`${rel(shim)} is not executable, and forge runs the --use path directly: chmod +x it (git stores it with mode 100755 only when staged with git add --chmod=+x)`);
    }
  }
  return shim;
}

/** The replay command of this OS (forge.exe and the .cmd launcher on Windows, forge and the .sh launcher elsewhere). */
function replayCommand(test: string): string {
  const forge = process.platform === "win32" ? "tools/foundry/forge.exe" : "forge";
  const shim = process.platform === "win32" ? "scripts/robustness/solc_shim.cmd" : "scripts/robustness/solc_shim.sh";
  return `${forge} test --root onchain --use ${shim} --offline --fuzz-seed ${SEED} --match-test "${test}" -vvv (forge first replays the persisted failure copied under persisted/ when it is placed in the persist directory)`;
}

/** The compiler and EVM settings forge will use (forge config --json), selected keys only (no paths). */
function effectiveSettings(forge: string, shim: string, env: NodeJS.ProcessEnv): Record<string, unknown> | { error: string } {
  const r = spawnSync(forge, ["config", "--root", path.join(REPO_ROOT, "onchain"), "--use", shim, "--offline", "--json"], { encoding: "utf8", windowsHide: true, env, shell: false });
  if (r.status !== 0) return { error: sanitize(String(r.stderr)).slice(0, 300) };
  try {
    const j = JSON.parse(String(r.stdout)) as Record<string, unknown>;
    const keys = ["evm_version", "optimizer", "optimizer_runs", "via_ir", "offline", "auto_detect_solc", "src", "test", "bytecode_hash", "cbor_metadata"];
    return { ...Object.fromEntries(keys.map((k) => [k, j[k] ?? null])), solc: rel(shim) };
  } catch (e) {
    return { error: sanitize((e as Error).message) };
  }
}

function versionLine(cmd: string, args: string[], env?: NodeJS.ProcessEnv): string | null {
  const r = spawnSync(cmd, args, { encoding: "utf8", windowsHide: true, env: env ?? process.env, shell: false });
  if (r.status !== 0) return null;
  const lines = String(r.stdout).split(/\r?\n/).filter((l) => l.trim().length > 0);
  return lines.length ? sanitize(lines.slice(0, 2).join(" | ")) : null;
}

/** Forge's JSON result per test, without traces and other bulky fields. */
export interface ForgeTestResult {
  suite: string;
  test: string;
  status: string;
  reason: string | null;
  kind: string;
  runs: number | null;
  calls: number | null;
  reverts: number | null;
  counterexample: unknown;
}

/** Flatten forge's `--json` output ({ "<file>:<Contract>": { test_results: { sig: {...} } } }). */
export function flattenForgeJson(j: unknown): ForgeTestResult[] {
  const out: ForgeTestResult[] = [];
  if (!j || typeof j !== "object") return out;
  for (const [suite, v] of Object.entries(j as Record<string, unknown>)) {
    const tr = (v as { test_results?: Record<string, Record<string, unknown>> } | null)?.test_results ?? {};
    for (const [test, r] of Object.entries(tr)) {
      const kindObj = (r["kind"] ?? {}) as Record<string, Record<string, unknown>>;
      const kind = Object.keys(kindObj)[0] ?? "Unknown";
      const k = kindObj[kind] ?? {};
      out.push({
        suite,
        test,
        status: String(r["status"] ?? "?"),
        reason: r["reason"] === null || r["reason"] === undefined ? null : sanitize(String(r["reason"])),
        kind,
        runs: typeof k["runs"] === "number" ? (k["runs"] as number) : null,
        calls: typeof k["calls"] === "number" ? (k["calls"] as number) : null,
        reverts: typeof k["reverts"] === "number" ? (k["reverts"] as number) : null,
        counterexample: r["counterexample"] ?? null,
      });
    }
  }
  return out.sort((a, b) => (a.suite + a.test < b.suite + b.test ? -1 : 1));
}

function copyTree(src: string, dst: string): string[] {
  const copied: string[] = [];
  if (!fs.existsSync(src)) return copied;
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, e.name);
    const d = path.join(dst, e.name);
    if (e.isDirectory()) copied.push(...copyTree(s, d));
    else {
      fs.mkdirSync(path.dirname(d), { recursive: true });
      fs.copyFileSync(s, d);
      copied.push(d);
    }
  }
  return copied;
}

async function main(argv: string[]): Promise<number> {
  const smoke = flag(argv, "smoke");
  const campaign = opt(argv, "campaign") ?? (smoke ? "smoke" : undefined);
  if (!campaign || !/^[A-Za-z0-9_.-]{1,64}$/.test(campaign)) throw new Error("--campaign <name> is required (letters, digits, _ . -)");
  const base = smoke ? FORGE_BUDGETS.smoke : FORGE_BUDGETS.full;
  const budgets = {
    fuzzRuns: optNum(argv, "fuzz-runs", base.fuzzRuns),
    invariantRuns: optNum(argv, "invariant-runs", base.invariantRuns),
    invariantDepth: optNum(argv, "invariant-depth", base.invariantDepth),
  };
  const deviation = budgetDeviation(argv, smoke, [
    { flag: "fuzz-runs", value: budgets.fuzzRuns, registered: FORGE_BUDGETS.full.fuzzRuns },
    { flag: "invariant-runs", value: budgets.invariantRuns, registered: FORGE_BUDGETS.full.invariantRuns },
    { flag: "invariant-depth", value: budgets.invariantDepth, registered: FORGE_BUDGETS.full.invariantDepth },
  ]);
  const root = path.join(robustnessRoot(smoke), "forge", campaign);
  if (fs.existsSync(path.join(root, "plan.json"))) throw new Error(`${rel(root)} already holds a campaign; choose a new --campaign name`);
  const commit = assertCommitted(smoke);
  const forge = forgeBinary(argv);
  const shim = shimFile();
  const roots = markerRoots({ ...(windowsRepoFromArgs(argv) ? { windowsRepo: windowsRepoFromArgs(argv) as string } : {}), allowLocalOnlyInWsl: smoke });
  let release: () => void = () => undefined;
  if (smoke) assertMarkersFree(roots, "BUSY");
  else {
    const h = acquireMarker({ kind: "BUSY", campaign: `robustness/forge/${campaign}`, runner: "harness/v4/robustness/forge_fuzz.ts", owner: "operator", roots });
    release = () => h.release();
  }
  const build = path.join(os.tmpdir(), `pqid-v4-forge-${randomBytes(4).toString("hex")}`);
  try {
    fs.mkdirSync(root, { recursive: true });
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      PQID_NODE: process.execPath,
      FOUNDRY_OUT: path.join(build, "out"),
      FOUNDRY_CACHE_PATH: path.join(build, "cache"),
      FOUNDRY_FUZZ_FAILURE_PERSIST_DIR: path.join(build, "fuzz-failures"),
      FOUNDRY_INVARIANT_FAILURE_PERSIST_DIR: path.join(build, "invariant-failures"),
      FOUNDRY_FUZZ_RUNS: String(budgets.fuzzRuns),
      FOUNDRY_INVARIANT_RUNS: String(budgets.invariantRuns),
      FOUNDRY_INVARIANT_DEPTH: String(budgets.invariantDepth),
      FOUNDRY_OFFLINE: "true",
    };
    const args = ["test", "--root", path.join(REPO_ROOT, "onchain"), "--use", shim, "--offline", "--fuzz-seed", String(SEED), "--json"];
    writeJson(path.join(root, "plan.json"), {
      schema: "pqid/v4-forge-fuzz-plan/v1",
      campaign,
      smoke,
      preRegistration: "docs/v4/ROBUSTNESS.md section 6",
      protocol: protocolRecord(smoke),
      seed: SEED,
      seedId: "robustness.forgeFuzz (DECISIONS D-034)",
      budgets,
      registeredBudgets: FORGE_BUDGETS.full,
      deviation,
      gitClean: commit.gitClean,
      commitChecked: commit.paths,
      command: `forge test --root onchain --use ${rel(shim)} --offline --fuzz-seed ${SEED} --json (FOUNDRY_FUZZ_RUNS=${budgets.fuzzRuns}, FOUNDRY_INVARIANT_RUNS=${budgets.invariantRuns}, FOUNDRY_INVARIANT_DEPTH=${budgets.invariantDepth})`,
      tests: rel(TEST_FILE),
      contracts: rel(CONTRACT_FILE),
      createdUtc: utcNow(),
    });
    writeJson(path.join(root, "env.json"), {
      schema: "pqid/v4-forge-fuzz-env/v2",
      env: envInfo(),
      gitHead: gitHead(),
      commit,
      compilerSettings: effectiveSettings(forge, shim, env),
      forge: versionLine(forge, ["--version"]),
      forgeBinary: process.platform === "win32" ? "tools/foundry/forge.exe (or --forge)" : path.basename(forge),
      solc: versionLine(process.execPath, [path.join(REPO_ROOT, "scripts", "robustness", "solcjs_shim.cjs"), "--version"]),
      sha256: Object.fromEntries([rel(CONTRACT_FILE), rel(TEST_FILE), rel(CONFIG_FILE), ...SHIM_FILES].map((f) => [f, sha256FileHex(path.join(REPO_ROOT, ...f.split("/")))])),
      marker: smoke ? "none (smoke run; markers checked free)" : "results/v4/BUSY held for the whole campaign (D-034)",
    });
    console.log(`[forge] fuzz runs ${budgets.fuzzRuns}, invariant runs ${budgets.invariantRuns} x depth ${budgets.invariantDepth}, seed ${SEED}`);
    const t0 = Date.now();
    const res = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
      const child = spawn(forge, args, { cwd: REPO_ROOT, env, windowsHide: true, shell: false, stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      child.stdout.setEncoding("utf8").on("data", (d: string) => (stdout += d));
      child.stderr.setEncoding("utf8").on("data", (d: string) => (stderr += d));
      child.on("error", (e) => resolve({ code: 127, stdout, stderr: stderr + String(e) }));
      child.on("close", (code) => resolve({ code, stdout, stderr }));
    });
    const wallSec = Math.round((Date.now() - t0) / 100) / 10;
    let parsed: unknown = null;
    try {
      const start = res.stdout.indexOf("{");
      parsed = start >= 0 ? (JSON.parse(res.stdout.slice(start)) as unknown) : null;
    } catch {
      parsed = null;
    }
    if (parsed === null) {
      fs.writeFileSync(path.join(root, "forge_stderr.txt"), sanitize(res.stderr).slice(-20000));
      throw new Error(`forge produced no JSON result (exit ${String(res.code)}); stderr tail in ${rel(path.join(root, "forge_stderr.txt"))}`);
    }
    const tests = flattenForgeJson(parsed);
    writeJson(path.join(root, "results.json"), { schema: "pqid/v4-forge-fuzz-results/v1", forgeExitCode: res.code, wallSec, note: "forge --json output without traces; untimed (wallSec is the run's wall time, not a result)", tests });
    const failures: string[] = [];
    for (const t of tests.filter((x) => x.status !== "Success")) {
      const name = `${t.suite.split(":").pop() ?? "suite"}.${t.test.replace(/\(.*$/, "")}`;
      const file = path.join(root, "failures", `${name}.json`);
      writeJson(file, {
        schema: "pqid/v4-forge-fuzz-failure/v1",
        ...t,
        seed: SEED,
        budgets,
        replay: replayCommand(t.test.replace(/\(.*$/, "")),
        note: "the counterexample holds the failing calldata and decoded arguments (fuzz) or the call sequence (invariant)",
        writtenUtc: utcNow(),
      });
      failures.push(rel(file));
    }
    const persisted = [...copyTree(path.join(build, "fuzz-failures"), path.join(root, "persisted", "fuzz")), ...copyTree(path.join(build, "invariant-failures"), path.join(root, "persisted", "invariant"))].map(rel);
    const summary = {
      schema: "pqid/v4-forge-fuzz-summary/v1",
      campaign,
      smoke,
      note: smoke ? "smoke run: checks the runner only; never quoted" : "untimed; counts only",
      seed: SEED,
      budgets,
      totals: {
        tests: tests.length,
        passed: tests.filter((t) => t.status === "Success").length,
        failed: tests.filter((t) => t.status !== "Success").length,
        fuzzRuns: tests.reduce((s, t) => s + (t.kind === "Fuzz" ? (t.runs ?? 0) : 0), 0),
        invariantCalls: tests.reduce((s, t) => s + (t.kind === "Invariant" ? (t.calls ?? 0) : 0), 0),
      },
      tests: tests.map((t) => ({ suite: t.suite, test: t.test, kind: t.kind, status: t.status, runs: t.runs, calls: t.calls, reverts: t.reverts, reason: t.reason })),
      failures,
      persisted,
      finishedUtc: utcNow(),
    };
    writeJson(path.join(root, "summary.json"), summary);
    const md = [
      `# Forge fuzz and invariant campaign ${campaign}${smoke ? " (smoke: never quoted)" : ""}`,
      "",
      `Generated by harness/v4/robustness/forge_fuzz.ts. Pre-registration: docs/v4/ROBUSTNESS.md section 6. Seed ${SEED}; fuzz runs ${budgets.fuzzRuns}; invariant runs ${budgets.invariantRuns} x depth ${budgets.invariantDepth}. Counts only.`,
      "",
      "| Test | Kind | Status | Runs | Calls | Reason |",
      "|---|---|---|---|---|---|",
      ...tests.map((t) => `| ${t.suite.split(":").pop()}.${t.test.replace(/\(.*$/, "")} | ${t.kind} | ${t.status} | ${t.runs ?? ""} | ${t.calls ?? ""} | ${(t.reason ?? "").slice(0, 120).replace(/\|/g, "/")} |`),
      "",
      failures.length ? `Failures: ${failures.map((f) => `\`${f}\``).join(", ")}.` : "No failures.",
      "",
    ].join("\n");
    fs.writeFileSync(path.join(root, "summary.md"), md);
    console.log(`[forge] ${summary.totals.passed}/${summary.totals.tests} passed, ${summary.totals.failed} failed (${wallSec} s); summary ${rel(path.join(root, "summary.md"))}`);
    return 0;
  } finally {
    fs.rmSync(build, { recursive: true, force: true });
    release();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === SELF) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e: unknown) => {
      console.error(sanitize(e instanceof Error ? (e.stack ?? e.message) : String(e)));
      process.exit(1);
    }
  );
}
