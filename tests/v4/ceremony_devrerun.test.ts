import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { REPO_ROOT } from "@pqid/common/paths";
import * as L from "../../harness/v4/ceremony/followup_lib.ts";

/**
 * Post-fix rerun with the dev key (`followup.ts --dev-rerun`, D-034 exception for a packages/v4
 * fix of a fuzz-found defect; docs/v4/CEREMONY_FOLLOWUP.md). Option parsing, output paths, the
 * check of the pinned dev key, the labels and the strict comparison with dev run 10 and campaign 5.
 * Read-only on the repository: no suite or mutation run, nothing written.
 */

const repo = (r: string) => path.join(REPO_ROOT, ...r.split("/"));
const readJson = <T>(r: string): T => JSON.parse(fs.readFileSync(repo(r), "utf8")) as T;
const F = () => import("../../harness/v4/ceremony/followup.ts");

type Pins = Record<string, { sha256?: string; label?: string; path?: string }>;

// ------------------------------------------------------------------ options

describe("--dev-rerun options", () => {
  const day = new Date("2026-10-04T12:00:00Z");

  it("defaults: suite and mutation with the dev key, nothing of the ceremony", async () => {
    const { parseOptions } = await F();
    const o = parseOptions(["--dev-rerun", "--date", "2026-10-04"], day);
    expect(o).toMatchObject({ kind: "devrerun", preview: false, dry: false, checkOnly: false, label: "dev", external: [], steps: ["suite", "mutation"], only: null, jobs: 2, date: "2026-10-04", allowUncommitted: false, baselineRel: null });
    expect(parseOptions(["--dev-rerun", "--dry-run"])).toMatchObject({ kind: "devrerun", preview: true, dry: false, steps: ["suite", "mutation"] });
    expect(parseOptions(["--dev-rerun", "--steps", "suite"]).steps).toEqual(["suite"]);
    expect(parseOptions(["--dev-rerun", "--steps", "mutation,suite"]).steps).toEqual(["suite", "mutation"]);
    expect(parseOptions(["--dev-rerun", "--only", "governance,wallet:requestShape", "--jobs", "3"])).toMatchObject({ only: new Set(["governance", "wallet:requestShape"]), jobs: 3 });
    expect(parseOptions(["--dev-rerun", "--steps", "mutation", "--baseline", "results/v4/fixcheck/2026-10-04/suite/security_suite.json"])).toMatchObject({ steps: ["mutation"], baselineRel: "results/v4/fixcheck/2026-10-04/suite/security_suite.json" });
    // the ceremony modes are unchanged and are never a dev rerun
    expect(parseOptions(["--external", "2"])).toMatchObject({ kind: "real", preview: false, label: "ceremony" });
    expect(parseOptions(["--dry-run"])).toMatchObject({ kind: "dry", preview: false });
  });

  it("refuses verify, keys and install, every ceremony option and --allow-uncommitted", async () => {
    const { parseOptions } = await F();
    for (const s of ["verify", "keys", "install", "suite,keys", "nope"]) expect(() => parseOptions(["--dev-rerun", "--steps", s]), s).toThrow(/only the suite and mutation/);
    expect(() => parseOptions(["--dev-rerun", "--allow-uncommitted"])).toThrow(/always refuses uncommitted code/);
    for (const f of [["--check-only"], ["--external", "2"], ["--external=2"], ["--label", "dev"], ["--label", "ceremony"], ["--final-dir", "ceremony/v4/final"]]) {
      expect(() => parseOptions(["--dev-rerun", ...f]), f.join(" ")).toThrow(/does not apply to --dev-rerun/);
    }
    expect(() => parseOptions(["--dev-rerun", "--jobs", "9"])).toThrow(/--jobs/);
    expect(() => parseOptions(["--dev-rerun", "--date", "20261004"])).toThrow(/--date/);
  });

  it("only its own options, each once and well formed: a misspelt dry run never becomes the real rerun", async () => {
    const { parseOptions, DEV_RERUN_FLAGS, DEV_RERUN_VALUES } = await F();
    expect([...DEV_RERUN_FLAGS, ...DEV_RERUN_VALUES]).toEqual(["dev-rerun", "dry-run", "steps", "only", "jobs", "date", "baseline", "owner"]);
    const bad: Array<[string[], RegExp]> = [
      [["--dryrun"], /unknown option --dryrun/],
      [["--dry-run=yes"], /--dry-run takes no value/],
      [["--dry-run="], /--dry-run takes no value/],
      [["--dry-run", "--dry-run"], /given twice/],
      [["--steps", "suite", "--steps", "mutation"], /given twice/],
      [["--steps", ""], /--steps needs a non-empty value/],
      [["--steps="], /--steps needs a non-empty value/],
      [["--steps", " , "], /--steps: no step named/],
      [["--steps"], /--steps needs a value/],
      [["--steps", "--dry-run"], /--steps needs a value/],
      [["--jobs=0"], /--jobs/],
      [["--owner", ""], /--owner needs a non-empty value/],
      [["dry-run"], /unexpected argument/],
      [["-n"], /unexpected argument/],
      [["--verbose"], /unknown option --verbose/],
      [["--only", "governance", "--steps", "suite"], /--only .*needs the mutation step/],
      [["--only", ","], /--only: no defence named/],
      [["--only", "wallet:noSuchCheck"], /--only: wallet:noSuchCheck is no defence/],
      [["--only", "governance,nonsense"], /--only: nonsense is no defence/],
    ];
    for (const [args, re] of bad) expect(() => parseOptions(["--dev-rerun", ...args], day), args.join(" ")).toThrow(re);
    // the switch itself takes no value either (it never falls back to a ceremony run)
    expect(() => parseOptions(["--dev-rerun=yes"], day)).toThrow(/--dev-rerun takes no value/);
    expect(() => parseOptions(["--dry-run", "--dev-rerun=1"], day)).toThrow(/takes no value/);
    // the = form of a value option and the option order are fine
    expect(parseOptions(["--jobs=3", "--dev-rerun", "--steps=suite", "--owner=kushal", "--dry-run"], day)).toMatchObject({ kind: "devrerun", preview: true, steps: ["suite"], jobs: 3, owner: "kushal" });
    expect(parseOptions(["--dev-rerun", "--only=registry", "--jobs", "1"], day)).toMatchObject({ only: new Set(["registry"]), jobs: 1 });
  });

  it("--date names the day of the run: a real date within one day of today (UTC)", async () => {
    const { parseOptions } = await F();
    for (const d of ["2026-10-03", "2026-10-04", "2026-10-05"]) expect(parseOptions(["--dev-rerun", "--date", d], day).date, d).toBe(d);
    for (const d of ["2026-10-02", "2026-10-06", "2025-10-04", "2026-09-01"]) expect(() => parseOptions(["--dev-rerun", "--date", d], day), d).toThrow(/not within one day of today's UTC date 2026-10-04/);
    for (const d of ["2026-02-30", "2026-13-01", "2026-10-4"]) expect(() => parseOptions(["--dev-rerun", "--date", d], day), d).toThrow(/--date must be a date/);
    expect(parseOptions(["--dev-rerun"], day).date).toBe("2026-10-04");
    expect(L.checkRunDate("2026-10-03", new Date("2026-10-03T23:59:59Z"))).toBe("2026-10-03");
    // the ceremony modes keep their own --date rule
    expect(parseOptions(["--external", "2", "--date", "2020-01-01"]).date).toBe("2020-01-01");
  });

  it("a mutation-only rerun needs the suite output of a post-fix rerun as its baseline, never dev run 10", async () => {
    const { parseOptions } = await F();
    expect(() => parseOptions(["--dev-rerun", "--steps", "mutation"])).toThrow(/needs --baseline/);
    for (const bad of [L.DEV_SUITE_REL, "results/v4/mutation/wallet__requestShape/security_suite.json", "results/v4/ceremony/followup_2026-10-20/suite/security_suite.json", "results/v4/fixcheck/2026-10-04/mutation/mutation.json", "results/v4/fixcheck/latest/suite/security_suite.json", "../results/v4/fixcheck/2026-10-04/suite/security_suite.json"]) {
      expect(() => parseOptions(["--dev-rerun", "--steps", "mutation", "--baseline", bad]), bad).toThrow();
    }
    // with the suite step the baseline is this run's own suite output
    expect(() => parseOptions(["--dev-rerun", "--baseline", "results/v4/fixcheck/2026-10-04/suite/security_suite.json"])).toThrow(/only for --dev-rerun --steps mutation/);
    expect(L.checkFixcheckBaseline("results\\v4\\fixcheck\\2026-10-04_r2\\suite\\security_suite.json")).toBe("results/v4/fixcheck/2026-10-04_r2/suite/security_suite.json");
  });
});

// ------------------------------------------------------------------ output paths

describe("--dev-rerun output paths", () => {
  it("results/v4/fixcheck/<date>[_rN]/ and verification/v4/fixcheck_<date>[_rN]/, never reused", () => {
    expect(L.fixcheckDirs("2026-10-04", () => false)).toEqual({ name: "2026-10-04", out: "results/v4/fixcheck/2026-10-04", logs: "verification/v4/fixcheck_2026-10-04" });
    const have = new Set(["results/v4/fixcheck/2026-10-04", "verification/v4/fixcheck_2026-10-04_r2"]);
    // r2 is taken by its log folder alone, so the next free name is r3
    expect(L.fixcheckDirs("2026-10-04", (r) => have.has(r)).name).toBe("2026-10-04_r3");
    expect(() => L.fixcheckDirs("2026-10", () => false)).toThrow(/YYYY-MM-DD/);
  });

  it("never the ledger-cited dev results, the mutation folders, the frozen series or setup/", () => {
    for (const p of [
      L.DEV_SUITE_REL,
      L.DEV_ATTACK_MATRIX_REL,
      L.DEV_MUTATION_REL,
      "results/v4/mutation_progress.json",
      "results/v4/mutation",
      "results/v4/mutation/wallet__requestShape/security_suite.json",
      "results/v4/mutation_run1_preB5/x.json",
      "results/v4/scale/x.json",
      "results/v4/bench/RUNNING",
      "results/v4/bench_wsl/summary.json",
      L.DEV_PINS_REL,
      "setup/out/v4/credential_auth_v4_dev.zkey",
    ]) {
      expect(L.isProtectedResult(p), p).toBe(true);
      expect(() => L.assertFixcheckOutput(p), p).toThrow();
    }
    for (const p of ["results/v4/ceremony/followup_2026-10-04", "results/v4/fixcheck", "results/v4/fixcheck/x", "results/v4/fixcheck/../mutation", "verification/v4/ceremony_followup_2026-10-04", "verification/v4/fixcheck_", "/abs/results/v4/fixcheck/2026-10-04"]) {
      expect(() => L.assertFixcheckOutput(p), p).toThrow();
    }
    for (const p of ["results/v4/fixcheck/2026-10-04", "results/v4/fixcheck/2026-10-04_r2/suite/security_suite.json", "results/v4/fixcheck/2026-10-04/mutation/mutation.json", "results/v4/fixcheck/2026-10-04/mutation/wallet__requestShape/config.json", "verification/v4/fixcheck_2026-10-04/mutation/wallet__requestShape.log"]) {
      expect(L.assertFixcheckOutput(p), p).toBe(p);
      expect(L.isProtectedResult(p), p).toBe(false);
    }
  });

  it("the run folders of the driver, and the path rule applied to the names the steps use (a fixed list; the guard below enforces it at run time)", async () => {
    const { runDirs, allDefences } = await F();
    const d = runDirs({ kind: "devrerun", label: "dev", date: "2026-10-04" });
    expect(d.out).toMatch(/^results\/v4\/fixcheck\/2026-10-04(?:_r\d+)?$/);
    expect(d.logs).toBe(`verification/v4/fixcheck_${d.out.slice("results/v4/fixcheck/".length)}`);
    expect(d.runId).toBe(`fixcheck_${d.out.slice("results/v4/fixcheck/".length)}`);
    expect(d.specRel).toBeNull();
    expect(d.pinsRel).toBe(L.DEV_PINS_REL);
    const written = [
      `${d.out}/fixcheck.json`,
      `${d.out}/suite/config.json`,
      `${d.out}/suite/security_suite.json`,
      `${d.out}/suite/attack_matrix.json`,
      `${d.out}/suite/key_probe.json`,
      `${d.out}/suite/vs_dev.json`,
      `${d.out}/mutation/mutation.json`,
      `${d.out}/mutation/mutation_partial.json`,
      `${d.out}/mutation/progress.json`,
      `${d.out}/mutation/key_probe.json`,
      `${d.out}/mutation/vs_dev.json`,
      ...allDefences().flatMap((x) => [`${d.out}/mutation/${x.kind}__${x.name}/config.json`, `${d.out}/mutation/${x.kind}__${x.name}/security_suite.json`, `${d.logs}/mutation/${x.kind}__${x.name}.log`]),
      `${d.logs}/fixcheck.log`,
      `${d.logs}/suite.log`,
      `${d.logs}/compare_suite.log`,
    ];
    for (const f of written) {
      expect(L.assertFixcheckOutput(f), f).toBe(f);
      expect(f.startsWith("results/v4/mutation") || f === L.DEV_SUITE_REL, f).toBe(false);
    }
    // the ceremony runs keep their own folders
    expect(runDirs({ kind: "real", label: "ceremony", date: "2026-10-20" }).out).toMatch(/^results\/v4\/ceremony\/followup_2026-10-20/);
  });

  it("the output guard of the dev rerun refuses every path outside its two folders; the ceremony modes have none", async () => {
    const { outputGuardFor } = await F();
    const g = outputGuardFor("devrerun");
    expect(g).toBe(L.assertFixcheckOutput);
    for (const k of ["real", "dry", "check"] as const) expect(outputGuardFor(k), k).toBeNull();
    const guard = g as (r: string) => string;
    for (const p of [L.DEV_SUITE_REL, L.DEV_ATTACK_MATRIX_REL, L.DEV_MUTATION_REL, "results/v4/mutation_progress.json", "results/v4/mutation/wallet__requestShape/security_suite.json", "results/v4/mutation/wallet__requestShape", "results/v4/scale/x.json", "results/v4/bench/RUNNING", "results/v4/BUSY", L.DEV_PINS_REL, "setup/out/v4/credential_auth_v4_dev.zkey", "results/v4/ceremony/followup_2026-10-04/followup.json", "verification/v4/followup.log"]) {
      expect(() => guard(p), p).toThrow(/a post-fix rerun writes only under/);
    }
    for (const p of ["results/v4/fixcheck/2026-10-04/fixcheck.json", "results/v4/fixcheck/2026-10-04/mutation/wallet__requestShape", "verification/v4/fixcheck_2026-10-04/fixcheck.log"]) expect(guard(p)).toBe(p);
  });

  it("every direct file write of the driver is in a guarded helper, the mutant scratch folder or a ceremony-only step", () => {
    const lines = fs.readFileSync(repo("harness/v4/ceremony/followup.ts"), "utf8").split("\n");
    const byFunction = new Map<string, number>();
    let fn = "(top level)";
    for (const line of lines) {
      const m = /^(?:export )?(?:async )?function (\w+)/.exec(line);
      if (m) fn = m[1] as string;
      const n = (line.match(/\bfs\.(?:writeFileSync|appendFileSync|copyFileSync|mkdirSync|rmSync|renameSync|unlinkSync|cpSync|writeSync|createWriteStream)\(|zKey\.(?:newZKey|contribute)\(/g) ?? []).length;
      if (n > 0) byFunction.set(fn, (byFunction.get(fn) ?? 0) + n);
    }
    // guarded helpers (every run output), the gitignored mutants (shared with campaign 5), and two
    // steps that never run in a dev rerun (install: --steps refuses it; dryrunKey: ceremony dry run only)
    expect([...byFunction.keys()].sort()).toEqual(["dryrunKey", "log", "mkdirRel", "mutantContracts", "mutantKey", "stepInstall", "writeJsonRel", "writeTextNew"]);
    const text = lines.join("\n");
    for (const h of ["mkdirRel", "writeJsonRel", "writeTextNew"]) expect(text, h).toMatch(new RegExp(`function ${h}\\([^)]*\\): void \\{\\n  guardOut\\(r\\);`));
    // the main log is checked before it is set; the guard is set before the first write
    expect(text).toContain("guardOut(mainLog);\n    MAIN_LOG = mainLog;");
    const setAt = text.indexOf("OUTPUT_GUARD = outputGuardFor(o.kind);");
    expect(setAt).toBeGreaterThan(0);
    expect(setAt).toBeLessThan(text.indexOf("mkdirRel(d.out);"));
    expect(text).toContain("const k = dev ? devPinnedKey() :");
    expect(text).toContain("mutant contracts are written only under ${L.MUTANTS_DIR_REL}/");
  });

  it("the suite and mutant configs of a dev rerun name only the run folder and the follow-up ports", async () => {
    const { allDefences } = await F();
    const out = "results/v4/fixcheck/2026-10-04";
    for (const x of allDefences()) {
      const built: L.MutantBuilt = x.kind === "circuit" ? { circuit: L.mutantPaths(x.name) } : x.kind === "registry" ? { contractsFile: L.mutantContractsRel(x.name) } : {};
      const { cfg } = L.mutantConfig(x, L.defencePort(x.index), `${out}/mutation/${x.kind}__${x.name}`, built);
      expect(L.assertFixcheckOutput(cfg["out"] as string)).toBe(cfg["out"]);
      expect(cfg["port"]).toBe(8801 + x.index);
    }
    expect(L.portsForSteps(["suite", "mutation"], allDefences().map((x) => x.index))).toEqual(Array.from({ length: 60 }, (_, i) => 8800 + i));
  });
});

// ------------------------------------------------------------------ the pinned dev key

describe("--dev-rerun key check", () => {
  const pins = readJson<Pins>(L.DEV_PINS_REL);
  const sha = (map: Record<string, string>) => (rel: string) => map[rel] ?? null;
  const pinnedShas = Object.fromEntries(L.DEV_KEY_FILES.map((f) => [f.rel, pins[f.pinKey]?.sha256 as string]));

  it("the six dev files are setup/pins_v4.json's six entries, in order, with their paths", () => {
    expect(L.DEV_KEY_FILES.map((f) => f.pinKey)).toEqual([...L.DEV_PIN_KEYS]);
    expect(Object.keys(pins)).toEqual([...L.DEV_PIN_KEYS]);
    for (const f of L.DEV_KEY_FILES) expect(pins[f.pinKey]?.path, f.pinKey).toBe(f.rel);
  });

  it("passes when every file has its pinned SHA-256, label dev and path", () => {
    const r = L.checkDevKeyPins(pins, sha(pinnedShas));
    expect(r.problems).toEqual([]);
    expect(r.files.map((f) => f.role)).toEqual(["r1cs", "wasm", "zkey", "vkey", "sol", "transcript"]);
    expect(r.files.find((f) => f.role === "zkey")).toEqual({ role: "zkey", file: "setup/out/v4/credential_auth_v4_dev.zkey", sha256: pins["v4/credential_auth_v4_dev.zkey"]?.sha256, pin: "setup/pins_v4.json#v4/credential_auth_v4_dev.zkey" });
  });

  it("names each problem: other bytes, a missing file, a missing pin, another label or path", () => {
    const zk = "setup/out/v4/credential_auth_v4_dev.zkey";
    expect(L.checkDevKeyPins(pins, sha({ ...pinnedShas, [zk]: "0".repeat(64) })).problems.join(" ")).toMatch(/credential_auth_v4_dev\.zkey: SHA-256 0{64} differs from its pin/);
    expect(L.checkDevKeyPins(pins, (r) => (r === zk ? null : (pinnedShas[r] ?? null))).problems).toEqual([`${zk}: missing`]);
    const noPin = { ...pins };
    delete noPin["v4/verification_key_dev.json"];
    expect(L.checkDevKeyPins(noPin, sha(pinnedShas)).problems).toEqual(["v4/verification_key_dev.json: no entry in setup/pins_v4.json"]);
    const relabel = structuredClone(pins);
    (relabel["v4/credential_auth_v4_dev.zkey"] as { label: string }).label = "ceremony";
    expect(L.checkDevKeyPins(relabel, sha(pinnedShas)).problems.join(" ")).toMatch(/label "ceremony", expected "dev"/);
    const moved = structuredClone(pins);
    (moved["v4/credential_auth_v4.wasm"] as { path: string }).path = "elsewhere.wasm";
    expect(L.checkDevKeyPins(moved, sha(pinnedShas)).problems.join(" ")).toMatch(/path "elsewhere\.wasm"/);
    const noSha = structuredClone(pins);
    delete (noSha["v4/Groth16VerifierV4_dev.sol"] as { sha256?: string }).sha256;
    expect(L.checkDevKeyPins(noSha, sha(pinnedShas)).problems).toEqual(["v4/Groth16VerifierV4_dev.sol: the pin holds no SHA-256"]);
  });

  it("the dev key in this repository matches its pins (files on disk, read only)", async () => {
    const { devPinnedKey } = await F();
    const k = devPinnedKey();
    expect(k).toMatchObject({ label: "dev", keyDir: "setup/out/v4", zkey: { file: "setup/out/v4/credential_auth_v4_dev.zkey", sha256: pins["v4/credential_auth_v4_dev.zkey"]?.sha256 }, vkey: { file: "setup/out/v4/verification_key_dev.json", sha256: pins["v4/verification_key_dev.json"]?.sha256 } });
    expect(k.pinned).toHaveLength(6);
    expect(k.note).toContain("post-fix rerun (D-034)");
  });

  it("the comparison basis: dev run 10 was made with the pinned key and campaign 5 used run 10", async () => {
    const { devPinnedKey } = await F();
    const k = devPinnedKey();
    const run10 = readJson<{ keyLabel?: string; artifacts?: Record<string, { file?: string; sha256?: string }> }>(L.DEV_SUITE_REL);
    const c5 = readJson<{ baseline?: { file?: string; sha256?: string }; rows?: unknown[] }>(L.DEV_MUTATION_REL);
    const run10Sha = createHash("sha256").update(fs.readFileSync(repo(L.DEV_SUITE_REL))).digest("hex");
    expect(L.comparisonBasisProblems(run10, run10Sha, c5, k.pinned)).toEqual([]);
    const other = structuredClone(run10);
    (other.artifacts?.["zkey"] as { sha256: string }).sha256 = "1".repeat(64);
    expect(L.comparisonBasisProblems(other, run10Sha, c5, k.pinned).join(" ")).toMatch(/was made with another zkey/);
    expect(L.comparisonBasisProblems(run10, "2".repeat(64), c5, k.pinned).join(" ")).toMatch(/baseline .* is not results\/v4\/security_suite\.json/);
    expect(L.comparisonBasisProblems({ ...run10, keyLabel: "ceremony" }, run10Sha, c5, k.pinned).join(" ")).toMatch(/keyLabel "ceremony"/);
    expect(L.comparisonBasisProblems(null, null, c5, k.pinned)).toEqual([`${L.DEV_SUITE_REL} (dev run 10) missing`]);
    expect(L.comparisonBasisProblems(run10, run10Sha, null, k.pinned).join(" ")).toMatch(/campaign 5\) missing/);
  });

  it("the probe rule: the dev key resolves only without the loader, a rekeyed key only with it", () => {
    const devProbe: L.ProbeLike = { rekeyLabel: null, keyLabel: "dev", zkey: "setup/out/v4/credential_auth_v4_dev.zkey", vkey: "setup/out/v4/verification_key_dev.json", proveDefault: { zkey: "setup/out/v4/credential_auth_v4_dev.zkey", keyLabel: "dev" }, vkeyParses: true };
    const dev = { label: "dev", zkey: { file: devProbe.zkey }, vkey: { file: devProbe.vkey } };
    expect(L.probeResolvesKey(devProbe, dev, false)).toBe(true);
    expect(L.probeResolvesKey(devProbe, dev, true)).toBe(false);
    expect(L.probeResolvesKey({ ...devProbe, rekeyLabel: "dev" }, dev, false)).toBe(false);
    expect(L.probeResolvesKey({ ...devProbe, vkeyParses: false }, dev, false)).toBe(false);
    expect(L.probeResolvesKey({ ...devProbe, proveDefault: { zkey: "setup/out/v4/credential_auth_v4_ceremony.zkey", keyLabel: "dev" } }, dev, false)).toBe(false);
    const cer = { label: "ceremony", zkey: { file: "setup/out/v4/credential_auth_v4_ceremony.zkey" }, vkey: { file: "setup/out/v4/verification_key_ceremony.json" } };
    const cerProbe: L.ProbeLike = { rekeyLabel: "ceremony", keyLabel: "ceremony", zkey: cer.zkey.file, vkey: cer.vkey.file, proveDefault: { zkey: cer.zkey.file, keyLabel: "ceremony" }, vkeyParses: true };
    expect(L.probeResolvesKey(cerProbe, cer, true)).toBe(true);
    expect(L.probeResolvesKey(cerProbe, cer, false)).toBe(false);
    expect(L.probeResolvesKey(devProbe, cer, true)).toBe(false);
  });

  it("the probe file is key_probe.json for the dev key (no rekey happens) and rekey_probe.json under the loader", async () => {
    const { probeFileName } = await F();
    expect(probeFileName({ label: "dev" })).toBe("key_probe.json");
    expect(probeFileName({ label: "ceremony" })).toBe("rekey_probe.json");
    expect(probeFileName({ label: "dryrun" })).toBe("rekey_probe.json");
  });

  it("a probe child without the loader resolves the pinned dev key (the check before the suite and mutation steps)", async () => {
    const { devPinnedKey, probeKey } = await F();
    const k = devPinnedKey();
    const saved = { label: process.env["PQID_V4_REKEY_LABEL"], dir: process.env["PQID_V4_REKEY_DIR"] };
    // even with a rekey label in the parent's environment, the dev child runs without it
    process.env["PQID_V4_REKEY_LABEL"] = "probe";
    try {
      const p = await probeKey(k, null);
      expect(p).toMatchObject({ rekeyLabel: null, keyLabel: "dev", zkey: k.zkey.file, vkey: k.vkey.file, vkeyParses: true });
    } finally {
      if (saved.label === undefined) delete process.env["PQID_V4_REKEY_LABEL"];
      else process.env["PQID_V4_REKEY_LABEL"] = saved.label;
    }
  });
});

// ------------------------------------------------------------------ labels

describe("--dev-rerun labels", () => {
  it("every record says dev key and post-fix rerun (D-034), and never the rekey loader or the ceremony", () => {
    const full = L.recordLabel("devrerun", "dev", ["suite", "mutation"]);
    expect(full).toBe("[M] post-fix rerun (D-034), dev key: C1 security suite re-run with the pinned dev key, compared with dev run 10; C3 mutation campaign re-run with the pinned dev key, compared with campaign 5");
    expect(L.recordLabel("devrerun", "dev", [])).toBe("[M] post-fix rerun (D-034), dev key: no step completed");
    expect(L.recordLabel("devrerun", "dev", ["suite"])).not.toMatch(/mutation/);
    const table = L.mutationTableLabel("devrerun", "dev");
    for (const t of [full, table]) {
      expect(t).toContain(L.FIXCHECK_RUN_LABEL);
      expect(t).toContain(L.DEV_KEY_TEXT);
      expect(t).not.toMatch(/rekey|ceremony/);
    }
    expect(L.FIXCHECK_RUN_LABEL).toBe("post-fix rerun (D-034)");
    expect(L.DEV_KEY_TEXT).toBe("dev key");
    // the ceremony labels are unchanged
    expect(L.mutationTableLabel("real", "ceremony")).toBe("[M] one defence removed at a time; whole v4 suite re-run per mutant with the ceremony key (circuit mutants use throwaway keys)");
    expect(L.recordLabel("real", "ceremony", ["suite"])).toMatch(/under the rekey loader/);
  });

  it("the key switch: none for the dev key, the loader for any other key", () => {
    expect(L.keySwitchFor("dev")).toBe(L.DEV_KEY_SWITCH);
    expect(L.DEV_KEY_SWITCH.method).toMatch(/^none: .*without the rekey loader/);
    expect(L.DEV_KEY_SWITCH.packageDefaultKey).toBe("dev");
    expect(L.keySwitchFor("ceremony")).toBe(L.KEY_SWITCH);
    expect(L.keySwitchFor("dryrun")).toBe(L.KEY_SWITCH);
  });

  const full: L.FixcheckScope = { steps: ["suite", "mutation"], only: null };
  const suiteOnly: L.FixcheckScope = { steps: ["suite"], only: null };
  const base = "results/v4/fixcheck/2026-10-04/suite/security_suite.json";
  const mutationOnly: L.FixcheckScope = { steps: ["mutation"], only: null, baselineRel: base };
  const some: L.FixcheckScope = { steps: ["suite", "mutation"], only: new Set(["wallet:requestShape", "governance"]) };

  it("purpose, expected outcome and next steps: a difference is review and is never dropped", () => {
    expect(L.FIXCHECK_PURPOSE).toMatch(/^D-034: .*dev run 10 and campaign 5$/);
    expect(L.FIXCHECK_EXPECTED).toMatch(/any difference is review/);
    expect(L.fixcheckNext("results/v4/fixcheck/2026-10-04", "verification/v4/fixcheck_2026-10-04", "review", full).join(" ")).toMatch(/REVIEW: .*nothing here is hidden/);
    expect(L.fixcheckNext("o", "l", "pass", full)[0]).toBe("commit o/ and l/ (whatever the status: the record of the D-034 rerun is kept)");
    expect(L.fixcheckNext("o", "l", "pass", full)[1]).toMatch(/^every verdict and every mutation row equals the dev runs: record it in DECISIONS/);
    expect(L.fixcheckNext("o", "l", "fail", full).join(" ")).toMatch(/^commit .*FAIL: /);
  });

  it("a partial run never says D-034 is met: suite only, --only, or a mutation-only run says what is missing", () => {
    expect(L.fixcheckPartial(full)).toBeNull();
    expect(L.fixcheckPartial(suiteOnly)).toBe("no mutation step");
    expect(L.fixcheckPartial(mutationOnly)).toBe(`no suite step: mutation on ${base}`);
    expect(L.fixcheckPartial(some)).toBe("defences governance, wallet:requestShape only");
    expect(L.fixcheckPartial({ steps: ["suite"], only: new Set(["governance"]) })).toBe("no mutation step");
    const pass = (sc: L.FixcheckScope) => L.fixcheckNext("results/v4/fixcheck/2026-10-04", "verification/v4/fixcheck_2026-10-04", "pass", sc).join(" ");
    // suite only: the next command is the full mutation step on this suite output
    expect(pass(suiteOnly)).toMatch(/PARTIAL post-fix rerun \(no mutation step\): D-034 is not met yet; .*--dev-rerun --steps mutation --baseline results\/v4\/fixcheck\/2026-10-04\/suite\/security_suite\.json$/);
    // --only: never the record-it text
    expect(pass(some)).toMatch(/PARTIAL post-fix rerun \(defences governance, wallet:requestShape only\): D-034 is not met until/);
    expect(pass({ ...mutationOnly, only: new Set(["governance"]) })).toMatch(/D-034 is not met until/);
    // a full mutation-only run on a checked baseline completes D-034 together with that run
    expect(pass(mutationOnly)).toMatch(/the two runs together cover D-034; record both in DECISIONS/);
    for (const sc of [suiteOnly, some]) expect(pass(sc), JSON.stringify(sc.steps)).not.toMatch(/record (it|both) in DECISIONS/);
    expect(L.fixcheckNext("o", "l", "review", some).join(" ")).toMatch(/REVIEW \(partial: defences governance, wallet:requestShape only\)/);
    expect(L.fixcheckNext("o", "l", "fail", suiteOnly).join(" ")).toMatch(/FAIL \(partial: no mutation step\)/);
  });

  it("the record and mutation table labels say PARTIAL when a step or defences are left out", () => {
    expect(L.recordLabel("devrerun", "dev", ["suite", "mutation"], full)).toBe(L.recordLabel("devrerun", "dev", ["suite", "mutation"]));
    expect(L.recordLabel("devrerun", "dev", ["suite"], suiteOnly)).toBe("[M] post-fix rerun (D-034), dev key, PARTIAL (no mutation step): C1 security suite re-run with the pinned dev key, compared with dev run 10");
    expect(L.recordLabel("devrerun", "dev", ["suite", "mutation"], some)).toMatch(/^\[M\] post-fix rerun \(D-034\), dev key, PARTIAL \(defences governance, wallet:requestShape only\): /);
    expect(L.recordLabel("devrerun", "dev", ["mutation"], mutationOnly)).toMatch(/PARTIAL \(no suite step: mutation on results\/v4\/fixcheck\/2026-10-04\/suite\/security_suite\.json\)/);
    expect(L.mutationTableLabel("devrerun", "dev", new Set(["wallet:requestShape", "governance"]))).toMatch(/^\[M\] post-fix rerun \(D-034\), dev key, PARTIAL \(defences governance, wallet:requestShape only\): one defence removed/);
    expect(L.mutationTableLabel("devrerun", "dev", null)).toBe(L.mutationTableLabel("devrerun", "dev"));
    expect(L.mutationTableLabel("devrerun", "dev")).not.toMatch(/PARTIAL/);
    // the ceremony labels do not change with the new arguments
    expect(L.mutationTableLabel("real", "ceremony", new Set(["governance"]))).toBe(L.mutationTableLabel("real", "ceremony"));
    expect(L.recordLabel("real", "ceremony", ["suite"], suiteOnly)).toBe(L.recordLabel("real", "ceremony", ["suite"]));
  });

  it("the suite and mutant config names carry both labels (the frozen suite copies the name into its output's config field)", () => {
    expect(L.fixcheckConfigName("v4")).toBe("v4, dev key, post-fix rerun (D-034)");
    expect(L.fixcheckConfigName("wallet:requestShape")).toBe("wallet:requestShape, dev key, post-fix rerun (D-034)");
    const suite = fs.readFileSync(repo("harness/v4/security_suite.ts"), "utf8");
    // the name only reaches the output's `config` field (nothing in the suite or the verdict rules reads it otherwise)
    expect(suite.match(/cfg\.name/g)).toEqual(["cfg.name"]);
    expect(suite).toContain("const meta = { config: cfg.name,");
    const drv = fs.readFileSync(repo("harness/v4/ceremony/followup.ts"), "utf8");
    expect(drv).toContain('name: strict ? L.fixcheckConfigName("v4") : `v4:${k.label}-key`');
    expect(drv).toContain('if (strict) cfg["name"] = L.fixcheckConfigName(String(cfg["name"]));');
  });

  it("the real rerun holds results/v4/BUSY for its whole run, labelled; the preview holds no marker", async () => {
    const { markerSpec } = await F();
    for (const steps of [["suite", "mutation"], ["suite"], ["mutation"]] as Array<Array<"suite" | "mutation">>) {
      const m = markerSpec({ kind: "devrerun", steps }, { runId: "fixcheck_2026-10-04" });
      expect(m, steps.join(",")).toMatchObject({ kind: "BUSY", campaign: "fixcheck_2026-10-04" });
      expect(m?.note).toMatch(/^post-fix rerun \(D-034\), dev key: /);
    }
    expect(markerSpec({ kind: "devrerun", steps: ["suite", "mutation"] }, { runId: "fixcheck_2026-10-04" })?.note).toContain("security suite and mutation campaign");
    // the ceremony modes are unchanged
    expect(markerSpec({ kind: "real", steps: ["verify"] }, { runId: "followup_2026-10-20" })).toMatchObject({ kind: "BUSY", campaign: "ceremony_followup_2026-10-20" });
    expect(markerSpec({ kind: "check", steps: ["verify", "keys"] }, { runId: "x" })?.kind).toBe("BUSY");
    expect(markerSpec({ kind: "dry", steps: ["verify", "keys", "install"] }, { runId: "x" })).toBeNull();
    expect(markerSpec({ kind: "dry", steps: ["suite"] }, { runId: "x" })?.kind).toBe("BUSY");
    const drv = fs.readFileSync(repo("harness/v4/ceremony/followup.ts"), "utf8");
    expect(drv.match(/acquireMarker\(/g)).toHaveLength(1);
    expect(drv).toContain("const ms = markerSpec(o, d);\n    if (ms) marker = acquireMarker({ ...ms,");
    // the preview returns before the marker is taken
    expect(drv.indexOf('if (o.kind === "devrerun" && o.preview) return devRerunPreview(o, dirty);')).toBeLessThan(drv.indexOf("const ms = markerSpec(o, d);"));
  });

  it("the driver, the script and the document name the mode and its labels", () => {
    const sh = fs.readFileSync(repo("scripts/ceremony/followup.sh"), "utf8");
    expect(sh).toContain("bash scripts/ceremony/followup.sh --dev-rerun --dry-run");
    expect(sh).toContain("results/v4/fixcheck/<date>[_rN]/");
    // the help text covers every comment line of the header and stops before the code
    const lines = sh.split("\n");
    const helpEnd = Number(/sed -n '2,(\d+)p'/.exec(sh)?.[1]);
    expect(lines[helpEnd - 1]?.startsWith("#")).toBe(true);
    expect(lines[helpEnd]?.startsWith("#")).toBe(false);
    const doc = fs.readFileSync(repo("docs/v4/CEREMONY_FOLLOWUP.md"), "utf8");
    for (const s of ["--dev-rerun", "post-fix rerun (D-034)", "dev key", "results/v4/fixcheck/", "verification/v4/fixcheck_"]) expect(doc, s).toContain(s);
    expect(doc).not.toContain("\u2014");
    expect(doc).not.toContain("\u2013");
  });
});

// ------------------------------------------------------------------ code state and the mutation-only baseline

describe("--dev-rerun code state", () => {
  it("refuses uncommitted code and an unknown code state, with no override", () => {
    expect(L.devRerunCodeProblems([])).toEqual([]);
    const p = L.devRerunCodeProblems(["packages/v4/src/wallet.ts", "harness/v4/ceremony/followup.ts"]);
    expect(p).toHaveLength(1);
    expect(p[0]).toMatch(/^the code the suite and mutation campaign run has uncommitted changes \(packages\/v4\/src\/wallet\.ts, harness\/v4\/ceremony\/followup\.ts\); .*no --allow-uncommitted/);
    expect(L.devRerunCodeProblems(null)).toEqual(["git status could not be read, so the code state is unknown; the post-fix rerun runs only committed code"]);
    expect(L.CODE_PATHS).toContain("packages");
    const drv = fs.readFileSync(repo("harness/v4/ceremony/followup.ts"), "utf8");
    expect(drv).toContain("problems.push(...L.devRerunCodeProblems(dirty));");
    // the real rerun refuses on any problem of the plan (the same list the dry run prints)
    expect(drv).toContain("if (p.problems.length > 0) throw new Refused(p.problems.join(\"; \"));");
  });

  it("the record names every package source file (all packages, not only v4 and common)", async () => {
    const { packageSourceFiles } = await F();
    const files = packageSourceFiles();
    expect(files).toEqual([...files].sort());
    for (const f of ["packages/v4/src/wallet.ts", "packages/v4/src/session.ts", "packages/v4/package.json", "packages/common/package.json"]) expect(files, f).toContain(f);
    for (const pkg of ["common", "issuer", "ledger", "pqc", "v4"]) expect(files.some((f) => f.startsWith(`packages/${pkg}/src/`)), pkg).toBe(true);
    for (const f of files) {
      expect(f, f).toMatch(/^packages\/[^/]+\/(?:src\/.+|package\.json)$/);
      expect(f.split("/").some((x) => x === "__pycache__" || x === "node_modules" || x.startsWith(".")), f).toBe(false);
      expect(fs.existsSync(repo(f)), f).toBe(true);
    }
  });

  it("codeChangedSince: compares HEAD with itself, or reports unavailable history; malformed commits return null", async () => {
    const { codeChangedSince, uncommittedCode } = await F();
    const result = spawnSync("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT, encoding: "utf8", env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" }, windowsHide: true });
    if (result.status === 0) {
      const head = result.stdout.trim();
      expect(head).toMatch(/^[0-9a-f]{40,64}$/);
      expect(codeChangedSince(head)).toEqual([]);
    } else {
      expect(codeChangedSince("a".repeat(40))).toBeNull();
      expect(uncommittedCode()).toBeNull();
    }
    expect(codeChangedSince("HEAD~1; echo")).toBeNull();
    expect(codeChangedSince("")).toBeNull();
  });
});

describe("--dev-rerun mutation-only baseline", () => {
  const base = "results/v4/fixcheck/2026-10-04/suite/security_suite.json";
  const good: L.FixcheckRecordLike = { schema: "pqid/v4-fixcheck/v1", steps: { suite: "pass" }, suite: { status: "pass", file: base }, code: { gitHead: "a".repeat(40), uncommitted: [] } };
  const sha = "b".repeat(64);

  it("the record and comparison next to the baseline", () => {
    expect(L.fixcheckBaselineFiles(base)).toEqual({ record: "results/v4/fixcheck/2026-10-04/fixcheck.json", vsDev: "results/v4/fixcheck/2026-10-04/suite/vs_dev.json" });
    expect(() => L.fixcheckBaselineFiles(L.DEV_SUITE_REL)).toThrow();
  });

  it("accepts only a suite step that passed on committed code, unchanged since, with no code change up to HEAD", () => {
    expect(L.fixcheckBaselineProblems(base, good, sha, sha, [])).toEqual([]);
    const one = (rec: L.FixcheckRecordLike | null, recorded: string | null = sha, file: string | null = sha, changed: string[] | null = []) => L.fixcheckBaselineProblems(base, rec, recorded, file, changed).join(" | ");
    expect(one(null)).toMatch(/fixcheck\.json missing or unreadable/);
    expect(one({ ...good, schema: "pqid/v4-ceremony-followup/v1" })).toMatch(/not a post-fix rerun record/);
    expect(one({ ...good, steps: { suite: "review" }, suite: { status: "review", file: base } })).toMatch(/its suite step is "review", not pass/);
    expect(one({ ...good, steps: { suite: "fail" } })).toMatch(/not pass/);
    expect(one({ ...good, suite: { status: "pass", file: "results/v4/fixcheck/2026-10-03/suite/security_suite.json" } })).toMatch(/its suite output is .*2026-10-03.*, not/);
    expect(one(good, sha, "c".repeat(64))).toMatch(/changed after its run/);
    expect(one(good, null)).toMatch(/names no SHA-256/);
    expect(one(good, sha, null)).toMatch(/security_suite\.json missing/);
    expect(one({ ...good, code: { gitHead: "a".repeat(40), uncommitted: ["packages/v4/src/wallet.ts"] } })).toMatch(/uncommitted or unknown/);
    expect(one({ ...good, code: { gitHead: "a".repeat(40), uncommitted: null } })).toMatch(/uncommitted or unknown/);
    expect(one({ ...good, code: { gitHead: null, uncommitted: [] } })).toMatch(/names no commit/);
    expect(one(good, sha, sha, null)).toMatch(/git could not compare/);
    expect(one(good, sha, sha, ["packages/v4/src/session.ts"])).toMatch(/the code changed since the baseline's run at a{40} \(packages\/v4\/src\/session\.ts\); run the suite step again/);
  });
});

// ------------------------------------------------------------------ strict comparison (committed dev-key runs, read only)

describe("--dev-rerun comparison: any difference is review", () => {
  const devSuite = readJson<L.SuiteFile>(L.DEV_SUITE_REL);
  const devTable = readJson<L.MutationTable>(L.DEV_MUTATION_REL);
  const facts = (over: Partial<L.SuiteStepFacts> = {}): L.SuiteStepFacts => ({ exit: 0, pass: true, keyMatches: true, portClosed: true, vsDev: L.compareSuites(devSuite, devSuite, { strict: true }), compareSuitePy: { exit: 0 }, strict: true, attackMatrixEqual: true, ...over });

  it("dev run 10 and campaign 5 compared with themselves pass the strict rules", () => {
    const s = L.compareSuites(devSuite, devSuite, { strict: true });
    expect(s).toMatchObject({ identical: true, verdictDiffs: [], summaryDiffs: [], checkDiffs: [], verdictsBase: 130 });
    expect(L.suiteStepStatus(facts())).toBe("pass");
    const m = L.compareMutationTables(devTable, devTable, undefined, { exit: true });
    expect(m.identical).toBe(true);
    expect(L.mutationStatus([], m)).toBe("pass");
  });

  it("a changed failed-check list is review in the dev rerun (the ceremony follow-up reports it only)", () => {
    const s = structuredClone(devSuite);
    const a = s.records.flatMap((r) => r.attempts).find((x) => !x.accepted && x.stoppedBy.checks.length > 0) as L.SuiteAttempt;
    a.stoppedBy = { ...a.stoppedBy, checks: [...a.stoppedBy.checks, "anotherCheck"] };
    const c = L.compareSuites(devSuite, s, { strict: true });
    expect(c.identical).toBe(true);
    expect(c.checkDiffs).toHaveLength(1);
    expect(L.suiteStepStatus(facts({ vsDev: c }))).toBe("review");
    expect(L.suiteStepStatus(facts({ vsDev: c, strict: false }))).toBe("pass");
  });

  it("a summary field outside the default list (invalidRoutes) is compared in the dev rerun", () => {
    const s = structuredClone(devSuite);
    (s.summary as Record<string, unknown>)["invalidRoutes"] = ["X: something"];
    expect(L.compareSuites(devSuite, s).identical).toBe(true);
    const strict = L.compareSuites(devSuite, s, { strict: true });
    expect(strict.identical).toBe(false);
    expect(strict.summaryDiffs[0]).toMatch(/^invalidRoutes:/);
    expect(L.suiteStepStatus(facts({ vsDev: strict }))).toBe("review");
  });

  it("the top-level trapdoor, thresholds and PQC label, and the record list, are compared in the dev rerun", () => {
    expect(L.SUITE_STRICT_FIELDS).toEqual(["trapdoor", "standardThresholds", "pqc"]);
    for (const k of L.SUITE_STRICT_FIELDS) expect(devSuite[k], k).toBeDefined();
    const changes: Array<[string, (s: L.SuiteFile) => void, RegExp]> = [
      ["trapdoor", (s) => (s.trapdoor = { beaconDerivedDeltaMatchesKey: true, note: "x" }), /^trapdoor \(top level\): /],
      ["standardThresholds", (s) => (s.standardThresholds = [13, 14]), /^standardThresholds \(top level\): /],
      ["pqc", (s) => (s.pqc = "OpenSSL 3.6.0 via Node 26.0.0"), /^pqc \(top level\): /],
      ["a record with no attempts", (s) => s.records.push({ id: "ZZ", kind: "baseline", attempts: [] }), /^records \(id\|kind\|attempts\): only in base \[\], only in new \["ZZ\|baseline\|0"\]$/],
      ["the kind of a record with no attempts", (s) => ((s.records.find((r) => r.attempts.length === 0) as L.SuiteRecord).kind = "attack"), /^records \(id\|kind\|attempts\): only in base \["[^"]+\|[a-z-]+\|0"\], only in new \["[^"]+\|attack\|0"\]$/],
      ["the record order", (s) => s.records.reverse(), /^records \(id\|kind\|attempts\): the same records in another order$/],
    ];
    for (const [what, change, re] of changes) {
      const s = structuredClone(devSuite);
      change(s);
      const strict = L.compareSuites(devSuite, s, { strict: true });
      expect(strict.identical, what).toBe(false);
      expect(strict.summaryDiffs, what).toHaveLength(1);
      expect(strict.summaryDiffs[0], what).toMatch(re);
      expect(L.suiteStepStatus(facts({ vsDev: strict })), what).toBe("review");
      // the ceremony comparison (another key) does not compare these
      expect(L.compareSuites(devSuite, s).summaryDiffs, what).toEqual([]);
      expect(L.compareSuites(devSuite, s, { allSummaryKeys: true }).summaryDiffs, what).toEqual([]);
    }
    // the record list the strict rule compares: 72 records, ids repeat, two records have no attempts
    expect(L.suiteRecordList(devSuite)).toHaveLength(72);
    expect(L.suiteRecordList(devSuite).filter((x) => x.endsWith("|0"))).toHaveLength(2);
  });

  it("an attack matrix that differs, or was not compared, is review in the dev rerun", () => {
    expect(L.suiteStepStatus(facts({ attackMatrixEqual: false }))).toBe("review");
    expect(L.suiteStepStatus(facts({ attackMatrixEqual: null }))).toBe("review");
    expect(L.suiteStepStatus(facts({ attackMatrixEqual: null, strict: false }))).toBe("pass");
  });

  it("one changed verdict is review; a failed suite, another key or an open port fails", () => {
    const s = structuredClone(devSuite);
    const a = s.records.find((r) => r.kind === "attack")?.attempts[0] as L.SuiteAttempt;
    a.accepted = true;
    a.stoppedBy = { layer: "accepted", checks: [] };
    expect(L.suiteStepStatus(facts({ vsDev: L.compareSuites(devSuite, s, { strict: true }) }))).toBe("review");
    expect(L.suiteStepStatus(facts({ compareSuitePy: { exit: 1 } }))).toBe("review");
    expect(L.suiteStepStatus(facts({ compareSuitePy: { exit: null } }))).toBe("review");
    expect(L.suiteStepStatus(facts({ compareSuitePy: null }))).toBe("pass");
    for (const over of [{ exit: 1 }, { exit: null }, { pass: false }, { pass: undefined }, { keyMatches: false }, { portClosed: false }] as Array<Partial<L.SuiteStepFacts>>) {
      expect(L.suiteStepStatus(facts(over)), JSON.stringify(over)).toBe("fail");
    }
  });

  it("every mutation row is compared, with its exit code in the dev rerun", () => {
    const changed = structuredClone(devTable);
    const row = changed.rows.find((r) => r["exit"] === 1) as L.MutationTableRow;
    row["exit"] = 0;
    expect(L.compareMutationTables(devTable, changed).identical).toBe(true);
    const c = L.compareMutationTables(devTable, changed, undefined, { exit: true });
    expect(c.identical).toBe(false);
    expect(c.differing).toEqual([{ defence: `${row.kind}:${row.name}`, field: "exit", base: 1, new: 0 }]);
    expect(L.mutationStatus([], c)).toBe("review");
    // a route let through, a missing row and a run error are differences too
    const routes = structuredClone(devTable);
    (routes.rows.find((r) => r.kind === "wallet" && r.name === "requestShape") as L.MutationTableRow).routesNowAccepted = ["X|new route"];
    expect(L.mutationStatus([], L.compareMutationTables(devTable, routes, undefined, { exit: true }))).toBe("review");
    const missing = { rows: devTable.rows.slice(1), noEffect: devTable.noEffect };
    expect(L.compareMutationTables(devTable, missing, undefined, { exit: true }).missing).toHaveLength(1);
    expect(L.mutationStatus(["wallet:requestShape: suite produced no output"], L.compareMutationTables(devTable, devTable, undefined, { exit: true }))).toBe("fail");
  });
});

// ------------------------------------------------------------------ transcript rule on a long list (no spread)

describe("transcript times without a spread", () => {
  it("first and last acceptance times are found by a loop (200,000 contributions do not overflow the call stack)", () => {
    const n = 200_000;
    const base = Date.parse("2026-10-11T00:00:00Z");
    const contributions: L.TranscriptContribution[] = Array.from({ length: n }, (_, i) => ({ index: i + 1, name: `c${i}`, contributionHash: "ab".repeat(32), acceptedAtUtc: new Date(base + i * 1000).toISOString() }));
    const t = {
      schema: "pqid/ceremony-transcript/v1",
      label: "rehearsal",
      circuit: { name: "x", r1cs: { file: "x", sha256: "0".repeat(64) }, circuitHash: "0".repeat(128) },
      ptau: { file: "x", sha256: "0".repeat(64) },
      contributions,
      beacon: { index: n + 1, name: "b", value: "00", numIterationsExp: 10, contributionHash: "cd".repeat(32), source: { kind: "bitcoin", plannedAtUtc: new Date(base + 500 * 1000).toISOString() } },
      final: { zkey: { file: "z", sha256: "0".repeat(64) }, verificationKey: { file: "v", sha256: "0".repeat(64) }, solidityVerifier: { file: "s", sha256: "0".repeat(64) } },
    } as L.CeremonyTranscript;
    const cs = L.checkTranscript(t, { mode: "rehearsal", frozenR1csSha: null, pinnedPtauSha: null, external: [1], files: { zkeySha: null, vkeySha: null, solSha: null } });
    const by = (id: string) => cs.find((c) => c.id === id);
    expect(by("contributions.acceptedTimes")?.status).toBe("pass");
    // planned after the first acceptance (warning) and before the last one (pass)
    expect(by("beacon.plannedBeforeLastContribution")?.status).toBe("pass");
    expect(by("beacon.plannedBeforeLastContribution")?.detail).toContain(new Date(base + (n - 1) * 1000).toISOString());
    expect(by("beacon.plannedBeforeFirstContribution")?.status).toBe("warn");
    expect(by("beacon.plannedBeforeFirstContribution")?.detail).toContain(new Date(base).toISOString());
  });

  it("followup_lib.ts spreads no list into Math.max or Math.min", () => {
    const src = fs.readFileSync(repo("harness/v4/ceremony/followup_lib.ts"), "utf8");
    expect(src).not.toMatch(/Math\.(?:max|min)\(\s*\.\.\./);
  });
});

// ------------------------------------------------------------------ the dry run of the mode (preflight and key probe; nothing written)

describe("--dev-rerun --dry-run", () => {
  it("stops before the suite, writes nothing, holds no marker and prints the labelled plan (exit 0 ready, 3 would refuse)", async () => {
    const list = (r: string) => (fs.existsSync(repo(r)) ? fs.readdirSync(repo(r)).sort() : []);
    const before = { fixcheck: list(L.FIXCHECK_RESULTS_REL), logs: list("verification/v4").filter((x) => x.startsWith("fixcheck_")), busy: fs.existsSync(repo("results/v4/BUSY")) };
    const { uncommittedCode } = await F();
    const dirty = uncommittedCode();
    const tsx = pathToFileURL(path.join(REPO_ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;
    const r = spawnSync(process.execPath, ["--import", tsx, path.join(REPO_ROOT, "harness", "v4", "ceremony", "followup.ts"), "--dev-rerun", "--dry-run", "--steps", "suite"], { cwd: REPO_ROOT, encoding: "utf8", windowsHide: true, timeout: 120_000 });
    expect([0, 3], r.stderr).toContain(r.status);
    expect(list(L.FIXCHECK_RESULTS_REL)).toEqual(before.fixcheck);
    expect(list("verification/v4").filter((x) => x.startsWith("fixcheck_"))).toEqual(before.logs);
    expect(fs.existsSync(repo("results/v4/BUSY"))).toBe(before.busy);
    const line = r.stdout.split(/\r?\n/).filter((l) => l.startsWith("{")).pop();
    if (r.status === 3 && !line) {
      // refused at once: a marker exists (D-034), so nothing ran
      expect(r.stderr).toMatch(/REFUSED/);
      return;
    }
    const p = JSON.parse(line as string) as Record<string, unknown>;
    expect(p).toMatchObject({ schema: "pqid/v4-fixcheck-preview/v1", run: "post-fix rerun (D-034)", key: "dev key", keyLabel: "dev", steps: ["suite"], ports: [8800], realRunWouldStart: r.status === 0 });
    expect(p["label"]).toMatch(/^DRY RUN of the post-fix rerun \(D-034\), dev key: .*nothing written; not a result$/);
    expect(p["probe"]).toMatchObject({ rekeyLabel: null, keyLabel: "dev", zkey: "setup/out/v4/credential_auth_v4_dev.zkey" });
    expect((p["outputs"] as { results: string }).results).toMatch(/^results\/v4\/fixcheck\/\d{4}-\d{2}-\d{2}(?:_r\d+)?$/);
    expect(p["command"]).toBe("bash scripts/ceremony/followup.sh --dev-rerun --steps suite");
    expect(p["partial"]).toBe("no mutation step");
    // exit 3 always comes with its reasons, each printed on its own line
    const problems = p["problems"] as string[];
    const printed = r.stdout.split(/\r?\n/).filter((l) => l.startsWith("[fixcheck] the real rerun would refuse: "));
    expect(printed).toHaveLength(problems.length);
    expect(problems.length > 0).toBe(r.status === 3);
    // uncommitted code under CODE_PATHS is one of them exactly when git status shows it
    const codeProblem = problems.filter((x) => /uncommitted changes|code state is unknown/.test(x));
    expect(codeProblem).toEqual(L.devRerunCodeProblems(dirty));
    if (dirty === null || dirty.length > 0) expect(r.status).toBe(3);
  });
});
