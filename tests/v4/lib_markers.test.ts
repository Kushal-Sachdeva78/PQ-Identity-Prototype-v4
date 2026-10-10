import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { REPO_ROOT, tsxImportUrl } from "../../harness/v4/bench/lib.ts";
import {
  MARKER_REL,
  MARKER_SCHEMA,
  MARKER_TOKEN_ENV,
  MarkerHeldError,
  WINDOWS_REPO_ENV,
  acquireMarker,
  assertMarkersFree,
  assertRepoRoot,
  currentPidNamespace,
  markerRoots,
  readMarkers,
  resolveWindowsCommand,
  wslLauncherReason,
  type MarkerRoot,
} from "../../harness/v4/lib/markers.ts";

// D-034 markers (harness/v4/lib/markers.ts). Every test works in throwaway repositories under
// the OS temp directory; the real results/v4/bench/RUNNING and results/v4/BUSY are never
// touched (docs/BENCHMARK_POLICY.md: no RUNNING marker outside a timed series).

const MARKERS_TS = fileURLToPath(new URL("../../harness/v4/lib/markers.ts", import.meta.url));
const BENCH_LIB_TS = fileURLToPath(new URL("../../harness/v4/bench/lib.ts", import.meta.url));

/** Environment for CLI children without inherited marker variables. */
function cleanEnv(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  delete env[MARKER_TOKEN_ENV];
  delete env[WINDOWS_REPO_ENV];
  return env;
}

/** A Node script (run under tsx) written into a throwaway directory. */
function script(dir: string, name: string, body: string): string {
  const f = path.join(dir, name);
  fs.writeFileSync(f, body);
  return f;
}

function runNode(args: string[], env: NodeJS.ProcessEnv = cleanEnv()): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, { cwd: REPO_ROOT, env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let out = "";
    let err = "";
    child.stdout.setEncoding("utf8").on("data", (d: string) => (out += d));
    child.stderr.setEncoding("utf8").on("data", (d: string) => (err += d));
    child.once("error", reject);
    child.once("close", (code) => resolve({ code, out, err }));
  });
}

const runCli = (args: string[], env: NodeJS.ProcessEnv = cleanEnv()) => runNode(["--import", tsxImportUrl(), MARKERS_TS, ...args], env);

function fakeRepo(tag: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `pqid-markers-${tag}-`));
  fs.mkdirSync(path.join(dir, "docs", "v4"), { recursive: true });
  fs.writeFileSync(path.join(dir, "docs", "v4", "BENCH_PROTOCOL.md"), "# test\n\n## Deviations\n");
  fs.mkdirSync(path.join(dir, "results", "v4", "bench"), { recursive: true });
  return dir;
}

const QUIET = { releaseOnExit: false, exitOnSignal: false, inheritedToken: "" } as const;

let local: string;
let win: string;
let roots: MarkerRoot[];
const made: string[] = [];

beforeEach(() => {
  local = fakeRepo("local");
  win = fakeRepo("win");
  made.push(local, win);
  roots = markerRoots({ repo: local, allowLocalOnlyInWsl: true });
});
afterEach(() => {
  for (const d of made.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

const file = (repo: string, kind: "RUNNING" | "BUSY") => path.join(repo, ...MARKER_REL[kind].split("/"));

describe("markers: D-034 paths and record", () => {
  it("uses results/v4/bench/RUNNING for timed series and results/v4/BUSY for heavy untimed work", () => {
    expect(MARKER_REL).toEqual({ RUNNING: "results/v4/bench/RUNNING", BUSY: "results/v4/BUSY" });
  });

  it("writes who and when, with no user name, host name or path", () => {
    const h = acquireMarker({ kind: "RUNNING", campaign: "cr_test", runner: "harness/v4/chainread.ts", owner: "operator", roots, ...QUIET });
    try {
      const text = fs.readFileSync(file(local, "RUNNING"), "utf8");
      const rec = JSON.parse(text) as Record<string, unknown>;
      expect(rec).toMatchObject({
        schema: MARKER_SCHEMA,
        kind: "RUNNING",
        campaign: "cr_test",
        runner: "harness/v4/chainread.ts",
        owner: "operator",
        pid: process.pid,
        pidNamespace: currentPidNamespace(),
        writtenVia: "local repository",
      });
      expect(typeof rec["token"]).toBe("string");
      expect(Date.parse(String(rec["startedUtc"]))).not.toBeNaN();
      expect(h.borrowed).toBe(false);
      expect(h.copies).toEqual([{ rel: "results/v4/bench/RUNNING", via: "local" }]);
      const banned = [os.hostname(), os.homedir(), os.homedir().replace(/\\/g, "/"), local, local.replace(/\\/g, "/"), REPO_ROOT, REPO_ROOT.replace(/\\/g, "/")];
      let user = "";
      try {
        user = os.userInfo().username;
      } catch {
        /* none */
      }
      if (user.length >= 3) banned.push(user);
      for (const b of banned) if (b.length >= 3) expect(text.includes(b)).toBe(false);
    } finally {
      h.release();
    }
    expect(fs.existsSync(file(local, "RUNNING"))).toBe(false);
  });

  it("refuses absolute paths as labels", () => {
    expect(() => acquireMarker({ kind: "BUSY", campaign: "x", runner: "C:\\tools\\run.ts", roots, ...QUIET })).toThrow(/absolute/);
    expect(() => acquireMarker({ kind: "BUSY", campaign: "x", runner: "/home/someone/run.ts", roots, ...QUIET })).toThrow(/absolute/);
  });
});

describe("markers: refusal (D-034: every runner refuses while either marker exists)", () => {
  it("RUNNING blocks RUNNING and BUSY; BUSY blocks RUNNING and BUSY; release frees", () => {
    const a = acquireMarker({ kind: "RUNNING", campaign: "a", runner: "t", roots, ...QUIET });
    expect(() => acquireMarker({ kind: "RUNNING", campaign: "b", runner: "t", roots, ...QUIET })).toThrow(MarkerHeldError);
    expect(() => acquireMarker({ kind: "BUSY", campaign: "b", runner: "t", roots, ...QUIET })).toThrow(MarkerHeldError);
    expect(() => assertMarkersFree(roots)).toThrow(MarkerHeldError);
    a.release();
    expect(a.released()).toBe(true);
    expect(() => assertMarkersFree(roots)).not.toThrow();
    const b = acquireMarker({ kind: "BUSY", campaign: "fuzz", runner: "t", roots, ...QUIET });
    expect(fs.existsSync(file(local, "BUSY"))).toBe(true);
    try {
      acquireMarker({ kind: "RUNNING", campaign: "c", runner: "t", roots, ...QUIET });
      expect.unreachable("RUNNING must be refused while BUSY exists");
    } catch (e) {
      expect(e).toBeInstanceOf(MarkerHeldError);
      const err = e as MarkerHeldError;
      expect(err.wanted).toBe("RUNNING");
      expect(err.held.map((h) => h.rel)).toEqual(["results/v4/BUSY"]);
      expect(err.message).toMatch(/campaign fuzz/);
    }
    b.release();
    expect(readMarkers(roots)).toEqual([]);
  });

  it("never replaces a stale marker (dead pid) by itself, and says it looks stale", () => {
    const dead = 2 ** 22 + 12345; // above any default pid limit
    fs.writeFileSync(
      file(local, "RUNNING"),
      JSON.stringify({ schema: MARKER_SCHEMA, kind: "RUNNING", campaign: "old", runner: "t", owner: null, note: null, startedUtc: "2026-10-01T00:00:00.000Z", pid: dead, pidNamespace: currentPidNamespace(), token: "x", rule: "r", writtenVia: "local repository" })
    );
    expect(() => acquireMarker({ kind: "RUNNING", campaign: "new", runner: "t", roots, ...QUIET })).toThrow(/probably stale/);
    expect(JSON.parse(fs.readFileSync(file(local, "RUNNING"), "utf8")).campaign).toBe("old");
  });

  it("refuses on a legacy Phase D marker and on an unreadable marker", () => {
    fs.writeFileSync(file(local, "RUNNING"), JSON.stringify({ campaign: "cold_v4", pid: 1, startedUtc: "2026-09-28T00:00:00Z", rule: "x" }));
    const held = readMarkers(roots);
    expect(held[0]?.legacy?.campaign).toBe("cold_v4");
    expect(() => acquireMarker({ kind: "BUSY", campaign: "n", runner: "t", roots, ...QUIET })).toThrow(/legacy marker/);
    fs.rmSync(file(local, "RUNNING"));
    fs.writeFileSync(file(local, "BUSY"), "not json");
    expect(() => acquireMarker({ kind: "RUNNING", campaign: "n", runner: "t", roots, ...QUIET })).toThrow(/unreadable marker/);
  });

  it("release removes only its own marker (a marker another runner wrote stays)", () => {
    const h = acquireMarker({ kind: "BUSY", campaign: "a", runner: "t", roots, ...QUIET });
    const other = { ...h.record, token: "someone-else", campaign: "other" };
    fs.writeFileSync(file(local, "BUSY"), JSON.stringify(other));
    h.release();
    expect(fs.existsSync(file(local, "BUSY"))).toBe(true);
  });
});

describe("markers: explicit repository path (WSL runner writing the Windows marker through /mnt/c)", () => {
  it("checks and writes both repositories; a marker in either one blocks", () => {
    const both = markerRoots({ repo: local, windowsRepo: win });
    expect(both.map((r) => r.via)).toEqual(["local", "explicit"]);
    const h = acquireMarker({ kind: "RUNNING", campaign: "cr_wsl", runner: "harness/v4/chainread.ts", roots: both, ...QUIET });
    expect(JSON.parse(fs.readFileSync(file(local, "RUNNING"), "utf8")).writtenVia).toBe("local repository");
    const winRec = JSON.parse(fs.readFileSync(file(win, "RUNNING"), "utf8")) as Record<string, unknown>;
    expect(winRec["writtenVia"]).toBe("explicit repository path");
    expect(JSON.stringify(winRec).includes(win)).toBe(false);
    expect(JSON.stringify(winRec).includes(win.replace(/\\/g, "/"))).toBe(false);
    // a runner on the Windows side (its local repository is `win`) refuses
    const winSide = markerRoots({ repo: win, allowLocalOnlyInWsl: true });
    expect(() => acquireMarker({ kind: "BUSY", campaign: "fuzz", runner: "t", roots: winSide, ...QUIET })).toThrow(MarkerHeldError);
    h.release();
    expect(fs.existsSync(file(local, "RUNNING"))).toBe(false);
    expect(fs.existsSync(file(win, "RUNNING"))).toBe(false);
  });

  it("a marker held only in the Windows repository blocks a runner that passes the explicit path, not one that forgets it", () => {
    const winHolder = acquireMarker({ kind: "BUSY", campaign: "fuzz_win", runner: "t", roots: markerRoots({ repo: win, allowLocalOnlyInWsl: true }), ...QUIET });
    try {
      expect(() => acquireMarker({ kind: "RUNNING", campaign: "cr_wsl", runner: "t", roots: markerRoots({ repo: local, windowsRepo: win }), ...QUIET })).toThrow(/explicit repository/);
      // this is why WSL runners must pass the Windows path (markerRoots refuses without it inside WSL)
      const localOnly = acquireMarker({ kind: "RUNNING", campaign: "cr_wsl", runner: "t", roots, ...QUIET });
      localOnly.release();
    } finally {
      winHolder.release();
    }
  });

  it("validates repository paths and de-duplicates the same repository", () => {
    expect(() => assertRepoRoot(path.join(local, "nope"), "explicit repository")).toThrow(/not a PQ-Identity-v4 repository/);
    expect(() => markerRoots({ repo: local, windowsRepo: os.tmpdir() })).toThrow(/not a PQ-Identity-v4 repository/);
    expect(() => markerRoots({ repo: local, windowsRepo: "relative/path" })).toThrow(/absolute/);
    expect(markerRoots({ repo: local, windowsRepo: local }).length).toBe(1);
    expect(markerRoots({ repo: local, windowsRepo: win, includeLocal: false }).map((r) => r.via)).toEqual(["explicit"]);
  });

  it("inside WSL, refuses to build roots without the Windows repository", () => {
    const wsl = process.platform === "linux" && (Boolean(process.env["WSL_DISTRO_NAME"]) || /microsoft/i.test(fs.existsSync("/proc/version") ? fs.readFileSync("/proc/version", "utf8") : ""));
    if (wsl) expect(() => markerRoots({ repo: local })).toThrow(/--windows-repo/);
    else expect(markerRoots({ repo: local }).length).toBe(1);
  });
});

describe("markers: a wrapping holder (markers.ts run) and the runner it starts", () => {
  it("a runner started under the wrapper's token uses the held marker; other kinds are refused", () => {
    const outer = acquireMarker({ kind: "RUNNING", campaign: "window", runner: "scripts/x.sh", roots, ...QUIET });
    try {
      const inner = acquireMarker({ kind: "RUNNING", campaign: "series", runner: "t", roots, releaseOnExit: false, exitOnSignal: false, inheritedToken: outer.record.token });
      expect(inner.borrowed).toBe(true);
      // the record is the wrapper's hold; borrowedBy names the runner that uses it
      expect(inner.record.campaign).toBe("window");
      expect(inner.borrowedBy).toEqual({ campaign: "series", runner: "t" });
      expect(outer.borrowedBy).toBeNull();
      inner.release();
      expect(fs.existsSync(file(local, "RUNNING"))).toBe(true);
      expect(() => acquireMarker({ kind: "BUSY", campaign: "b", runner: "t", roots, releaseOnExit: false, exitOnSignal: false, inheritedToken: outer.record.token })).toThrow(MarkerHeldError);
      expect(() => acquireMarker({ kind: "RUNNING", campaign: "c", runner: "t", roots, releaseOnExit: false, exitOnSignal: false, inheritedToken: "wrong" })).toThrow(MarkerHeldError);
    } finally {
      outer.release();
    }
  });

  it("CLI: status exit codes, and run holds the marker exactly while the command runs", async () => {
    const env = cleanEnv();
    const free = await runCli(["status", "--repo", local, "--allow-local-only"], env);
    expect(free.code).toBe(0);
    expect(JSON.parse(free.out).free).toBe(true);

    // the wrapped command checks that the marker exists and carries the token it was given
    const check = [
      "const fs=require('fs');",
      `const f=${JSON.stringify(file(local, "BUSY"))};`,
      `const t=process.env[${JSON.stringify(MARKER_TOKEN_ENV)}];`,
      "const r=JSON.parse(fs.readFileSync(f,'utf8'));",
      "process.exit(r.token===t && r.kind==='BUSY' && r.campaign==='cli_test' ? 7 : 1);",
    ].join("");
    const run = await runCli(["run", "--repo", local, "--allow-local-only", "--kind", "BUSY", "--campaign", "cli_test", "--runner", "tests/v4/lib_markers.test.ts", "--", process.execPath, "-e", check], env);
    expect(run.code).toBe(7);
    expect(fs.existsSync(file(local, "BUSY"))).toBe(false);

    const holder = acquireMarker({ kind: "RUNNING", campaign: "held", runner: "t", roots, ...QUIET });
    try {
      const held = await runCli(["status", "--repo", local, "--allow-local-only"], env);
      expect(held.code).toBe(3);
      expect(JSON.parse(held.out).held[0].record.campaign).toBe("held");
      const refused = await runCli(["run", "--repo", local, "--allow-local-only", "--kind", "BUSY", "--campaign", "x", "--runner", "t", "--", process.execPath, "-e", "process.exit(0)"], env);
      expect(refused.code).toBe(3);
      expect(refused.err).toMatch(/refusing to start/);
    } finally {
      holder.release();
    }
  }, 120_000);
});

describe("markers: frozen Phase D runners in WSL (write explicit-only) and exec-if-free", () => {
  it("explicit-only checks every repository but writes only the Windows copy; a markers.ts runner under it borrows", () => {
    const both = markerRoots({ repo: local, windowsRepo: win });
    expect(() => acquireMarker({ kind: "RUNNING", campaign: "x", runner: "t", roots, write: "explicit-only", ...QUIET })).toThrow(/explicit repository/);
    const h = acquireMarker({ kind: "RUNNING", campaign: "window", runner: "harness/v4/bench/cold_campaign.ts", roots: both, write: "explicit-only", ...QUIET });
    try {
      expect(h.copies).toEqual([{ rel: "results/v4/bench/RUNNING", via: "explicit" }]);
      expect(fs.existsSync(file(local, "RUNNING"))).toBe(false);
      expect(fs.existsSync(file(win, "RUNNING"))).toBe(true);
      const inner = acquireMarker({ kind: "RUNNING", campaign: "series", runner: "harness/v4/x.ts", roots: both, releaseOnExit: false, exitOnSignal: false, inheritedToken: h.record.token });
      expect(inner.borrowed).toBe(true);
      expect(inner.borrowedBy).toEqual({ campaign: "series", runner: "harness/v4/x.ts" });
    } finally {
      h.release();
    }
    expect(fs.existsSync(file(win, "RUNNING"))).toBe(false);
    // a marker in the clone still blocks, although explicit-only does not write there
    fs.writeFileSync(file(local, "RUNNING"), JSON.stringify({ campaign: "cold_rs_wsl", pid: 1, startedUtc: "2026-09-28T00:00:00Z" }));
    expect(() => acquireMarker({ kind: "RUNNING", campaign: "y", runner: "t", roots: both, write: "explicit-only", ...QUIET })).toThrow(/legacy marker/);
  });

  it("CLI run --write explicit-only: the frozen bench/lib.ts acquireRunning holds the clone's RUNNING while the wrapper holds the Windows copy", async () => {
    const child = script(
      local,
      "frozen_runner.mts",
      [
        'import fs from "node:fs";',
        'import path from "node:path";',
        `const { acquireRunning } = await import(${JSON.stringify(pathToFileURL(BENCH_LIB_TS).href)});`,
        "const [cloneBench, winFile, winRepo] = process.argv.slice(2);",
        "let release;",
        "try {",
        '  release = acquireRunning(cloneBench, "phase_d_repeat");',
        "} catch (e) {",
        "  process.exit(/held by a live runner/.test(String(e)) ? 9 : 1);",
        "}",
        'const legacy = JSON.parse(fs.readFileSync(path.join(cloneBench, "RUNNING"), "utf8"));',
        'const w = JSON.parse(fs.readFileSync(winFile, "utf8"));',
        `const ok = legacy.pid === process.pid && legacy.campaign === "phase_d_repeat" && w.token === process.env[${JSON.stringify(MARKER_TOKEN_ENV)}] && w.writtenVia === "explicit repository path" && process.env[${JSON.stringify(WINDOWS_REPO_ENV)}] === winRepo;`,
        "release();",
        "process.exit(ok ? 7 : 1);",
      ].join("\n")
    );
    const cloneBench = path.join(local, "results", "v4", "bench");
    const args = (write: string[]) => [
      "run",
      "--repo",
      local,
      "--windows-repo",
      win,
      ...write,
      "--kind",
      "RUNNING",
      "--campaign",
      "phase_d_repeat",
      "--runner",
      "harness/v4/bench/cold_campaign.ts",
      "--",
      process.execPath,
      "--import",
      tsxImportUrl(),
      child,
      cloneBench,
      file(win, "RUNNING"),
      win,
    ];
    const ok = await runCli(args(["--write", "explicit-only"]));
    expect(ok.err).toBe("");
    expect(ok.code).toBe(7);
    expect(readMarkers(markerRoots({ repo: local, windowsRepo: win }))).toEqual([]);
    // default write mode: the wrapper's live pid in the clone's RUNNING makes the frozen runner refuse
    const clash = await runCli(args([]));
    expect(clash.code).toBe(9);
    expect(readMarkers(markerRoots({ repo: local, windowsRepo: win }))).toEqual([]);
  }, 120_000);

  it("CLI exec-if-free starts the command only when no marker of either kind exists, and holds none", async () => {
    const flagFile = path.join(local, "ran.txt");
    const cmd = ["--", process.execPath, "-e", `require("fs").writeFileSync(${JSON.stringify(flagFile)}, String(process.env[${JSON.stringify(MARKER_TOKEN_ENV)}] === undefined && process.env[${JSON.stringify(WINDOWS_REPO_ENV)}] === ${JSON.stringify(win)})); process.exit(6)`];
    const free = await runCli(["exec-if-free", "--repo", local, "--windows-repo", win, ...cmd]);
    expect(free.code).toBe(6);
    expect(fs.readFileSync(flagFile, "utf8")).toBe("true");
    fs.rmSync(flagFile);
    const busy = acquireMarker({ kind: "BUSY", campaign: "fuzz", runner: "t", roots: markerRoots({ repo: win, allowLocalOnlyInWsl: true }), ...QUIET });
    try {
      const refused = await runCli(["exec-if-free", "--repo", local, "--windows-repo", win, ...cmd]);
      expect(refused.code).toBe(3);
      expect(refused.err).toMatch(/results\/v4\/BUSY/);
      expect(fs.existsSync(flagFile)).toBe(false);
    } finally {
      busy.release();
    }
  }, 120_000);
});

describe("markers: signals and Windows command resolution", () => {
  it("on a signal the marker is released and later listeners of the same signal still run before the exit", async () => {
    const flagFile = path.join(local, "cleanup.txt");
    const child = script(
      local,
      "signal_runner.mts",
      [
        'import fs from "node:fs";',
        `const { acquireMarker, markerRoots } = await import(${JSON.stringify(pathToFileURL(MARKERS_TS).href)});`,
        "const [repo, flagFile, markerPath] = process.argv.slice(2);",
        'acquireMarker({ kind: "BUSY", campaign: "sig", runner: "t", roots: markerRoots({ repo, allowLocalOnlyInWsl: true }), inheritedToken: "" });',
        'process.on("SIGTERM", () => fs.writeFileSync(flagFile, "cleanup ran; marker present " + fs.existsSync(markerPath)));',
        "setTimeout(() => process.exit(5), 10000);",
        'process.emit("SIGTERM", "SIGTERM");',
      ].join("\n")
    );
    const r = await runNode(["--import", tsxImportUrl(), child, local, flagFile, file(local, "BUSY")]);
    expect(r.err).toBe("");
    expect(r.code).toBe(130);
    expect(fs.readFileSync(flagFile, "utf8")).toBe("cleanup ran; marker present false");
    expect(fs.existsSync(file(local, "BUSY"))).toBe(false);
  }, 60_000);

  const W = {
    SystemRoot: "C:\\Windows",
    LOCALAPPDATA: "C:\\Users\\u\\AppData\\Local",
    PATHEXT: ".COM;.EXE;.BAT;.CMD",
    cwd: "C:\\work",
  };
  const APPS = "C:\\Users\\u\\AppData\\Local\\Microsoft\\WindowsApps";
  const GIT = "C:\\Program Files\\Git\\usr\\bin";
  const SYS = "C:\\Windows\\System32";
  const files = new Set(
    [`${SYS}\\bash.exe`, `${SYS}\\wsl.exe`, `${APPS}\\bash.exe`, `${APPS}\\ubuntu2404.exe`, `${GIT}\\bash.exe`, "C:\\Program Files\\nodejs\\node.exe", "C:\\work\\scripts\\driver.cmd"].map((f) => f.toLowerCase())
  );
  const isFile = (f: string) => files.has(f.toLowerCase());

  it("resolves through PATH and PATHEXT and refuses commands that start WSL (pure, any host)", () => {
    // PowerShell: the WindowsApps alias or System32 comes before Git
    expect(resolveWindowsCommand("bash", { ...W, PATH: `${APPS};${GIT}` }, isFile)).toMatchObject({ kind: "refused", reason: /WSL launcher/ });
    expect(resolveWindowsCommand("bash", { ...W, PATH: `${SYS};${GIT}` }, isFile)).toMatchObject({ kind: "refused" });
    // Git Bash puts its own bin first
    const git = resolveWindowsCommand("bash", { ...W, PATH: `${GIT};${APPS};${SYS}` }, isFile);
    expect(git.kind).toBe("ok");
    expect(git.kind === "ok" && git.file.toLowerCase()).toBe(`${GIT}\\bash.exe`.toLowerCase());
    expect(resolveWindowsCommand(`${GIT}\\bash.exe`, { ...W, PATH: APPS }, isFile).kind).toBe("ok");
    expect(resolveWindowsCommand("wsl", { ...W, PATH: SYS }, isFile)).toMatchObject({ kind: "refused", reason: /starts WSL/ });
    expect(resolveWindowsCommand("ubuntu2404", { ...W, PATH: APPS }, isFile)).toMatchObject({ kind: "refused" });
    expect(resolveWindowsCommand("node", { ...W, PATH: `"C:\\Program Files\\nodejs";${SYS}` }, isFile).kind).toBe("ok");
    expect(resolveWindowsCommand("scripts\\driver.cmd", { ...W, PATH: "" }, isFile)).toMatchObject({ kind: "ok", file: "C:\\work\\scripts\\driver.cmd" });
    expect(resolveWindowsCommand("nope", { ...W, PATH: `${SYS};${GIT}` }, isFile).kind).toBe("not-found");
    expect(wslLauncherReason(`${GIT}\\bash.exe`, W)).toBeNull();
    expect(wslLauncherReason("D:\\tools\\wsl.exe", W)).toMatch(/starts WSL/);
  });

  it.runIf(process.platform === "win32")("CLI on Windows: a plain bash that resolves to the WSL launcher is refused before any marker is taken", async () => {
    const appData = fs.mkdtempSync(path.join(os.tmpdir(), "pqid-markers-appdata-"));
    made.push(appData);
    const apps = path.join(appData, "Microsoft", "WindowsApps");
    fs.mkdirSync(apps, { recursive: true });
    fs.writeFileSync(path.join(apps, "bash.exe"), "");
    const env = cleanEnv();
    for (const k of Object.keys(env)) if (/^(path|localappdata)$/i.test(k)) delete env[k];
    env["PATH"] = apps;
    env["LOCALAPPDATA"] = appData;
    const base = ["--repo", local, "--allow-local-only"];
    const run = await runCli(["run", ...base, "--kind", "BUSY", "--campaign", "x", "--runner", "t", "--", "bash", "-c", "exit 0"], env);
    expect(run.code).toBe(2);
    expect(run.err).toMatch(/WSL launcher/);
    expect(fs.existsSync(file(local, "BUSY"))).toBe(false);
    const exec = await runCli(["exec-if-free", ...base, "--", "bash", "-c", "exit 0"], env);
    expect(exec.code).toBe(2);
    const missing = await runCli(["exec-if-free", ...base, "--", "pqid-no-such-command"], env);
    expect(missing.code).toBe(127);
  }, 120_000);
});
