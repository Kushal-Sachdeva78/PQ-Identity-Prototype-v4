import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { REPO_ROOT, sanitize, utcNow, opt, flag } from "../bench/lib.ts";

/**
 * Work markers of DECISIONS D-034.
 *
 * - results/v4/bench/RUNNING: held by every timed series. WSL runners write it in the Windows
 *   repository through its /mnt/c path (pass that path explicitly).
 * - results/v4/BUSY: held by untimed but CPU-heavy work (fuzzing, builds).
 * - Every runner refuses to start while either marker exists, in any repository it checks.
 *   A marker is never replaced automatically, even when it looks stale: a person removes a
 *   stale marker after checking that nothing runs (the pid inside a marker written from WSL
 *   cannot be checked from Windows, or the other way round).
 *
 * The marker records who and when without usernames, hostnames or paths: campaign, runner
 * (repo-relative script or a short label), optional owner label, pid with its namespace,
 * start time (UTC) and a random token. Creation is exclusive (open with O_EXCL), so two
 * runners cannot both create the same marker; after creating its own marker a runner checks
 * the other kind again and backs off if one appeared (both may back off, neither runs).
 *
 * Frozen tools (compatibility): the Phase D runners (harness/v4/bench/lib.ts acquireRunning:
 * cold_campaign.ts, warm.ts) replace a RUNNING marker whose pid is not alive in their own OS,
 * and refuse one whose pid is alive (so they cannot run under a `run` wrapper that holds the
 * same file). scale.ts, baselines_measure.ts, revocation_capacity.ts and analyze.py refuse any
 * results/v4/bench/RUNNING, whatever its owner. None of them reads results/v4/BUSY. So:
 * - before starting a frozen tool, a driver checks both kinds in every repository
 *   (`status`, exit 0 required) or starts it through `exec-if-free`;
 * - a WSL Phase D repeat holds the Windows marker with `run --write explicit-only`, which
 *   checks the clone and the Windows repository but writes only the Windows copy, while the
 *   frozen runner holds the clone's own RUNNING;
 * - an E4 replication with scale.ts cannot run inside any RUNNING window.
 *
 * Windows command resolution (`run`, `exec-if-free`): the command is resolved through PATH and
 * PATHEXT before the marker is taken and spawned by its absolute path. A command that starts
 * WSL (wsl.exe, or the bash.exe launcher in System32 or WindowsApps, which a plain `bash`
 * finds first from PowerShell) is refused: v4 code never calls wsl.exe (docs/BENCHMARK_POLICY.md). Run the
 * driver from Git Bash or pass the absolute path of Git's bash.exe.
 */

export type MarkerKind = "RUNNING" | "BUSY";
export const MARKER_KINDS: readonly MarkerKind[] = ["RUNNING", "BUSY"];

/** Repo-relative marker paths (D-034). */
export const MARKER_REL: Readonly<Record<MarkerKind, string>> = Object.freeze({
  RUNNING: "results/v4/bench/RUNNING",
  BUSY: "results/v4/BUSY",
});

export const MARKER_RULE: Readonly<Record<MarkerKind, string>> = Object.freeze({
  RUNNING: "timed series active (D-034): only file editing and web research (docs/BENCHMARK_POLICY.md); every runner refuses to start",
  BUSY: "untimed CPU-heavy work active (D-034): no timed series and no other heavy work may start; every runner refuses to start",
});

export const MARKER_SCHEMA = "pqid/v4-marker/v1";
/** Set by `markers.ts run` for the command it wraps, so that command can use the marker it holds. */
export const MARKER_TOKEN_ENV = "PQID_MARKER_TOKEN";
/** Optional fallback for --windows-repo (a WSL runner's path to the Windows repository). */
export const WINDOWS_REPO_ENV = "PQID_WINDOWS_REPO";

export type PidNamespace = "win32" | "wsl2" | "linux" | string;

export interface MarkerRecord {
  schema: typeof MARKER_SCHEMA;
  kind: MarkerKind;
  campaign: string;
  /** Repo-relative script path or a short label of the runner. */
  runner: string;
  /** Optional label of who started it (for example "operator" or "Kushal"); never a user name read from the OS. */
  owner: string | null;
  note: string | null;
  startedUtc: string;
  pid: number;
  /** Where `pid` lives: a pid is only meaningful in its own namespace. */
  pidNamespace: PidNamespace;
  /** Random id of this hold; release removes a marker only when the token matches. */
  token: string;
  rule: string;
  /** How this copy was written (never the path itself). */
  writtenVia: "local repository" | "explicit repository path";
}

export interface MarkerRoot {
  /** Absolute repository root (used to build paths; never written into a marker or result). */
  repo: string;
  via: "local" | "explicit";
}

export interface HeldMarker {
  kind: MarkerKind;
  via: MarkerRoot["via"];
  /** Repo-relative path (MARKER_REL). */
  rel: string;
  /** Absolute path (for removal by the holder; not for results). */
  file: string;
  /** Parsed record, or null when the file is not a readable marker record. */
  record: MarkerRecord | null;
  /** Legacy Phase D marker fields, when the file is one ({campaign, pid, startedUtc}). */
  legacy: { campaign?: string; pid?: number; startedUtc?: string } | null;
  staleHint: string;
}

export class MarkerHeldError extends Error {
  constructor(
    readonly held: HeldMarker[],
    readonly wanted: MarkerKind
  ) {
    super(
      sanitize(
        `refusing to start (${wanted}): ` +
          held
            .map((h) => {
              const who = h.record ? `campaign ${h.record.campaign}, runner ${h.record.runner}, since ${h.record.startedUtc}` : h.legacy ? `legacy marker, campaign ${h.legacy.campaign ?? "?"}` : "unreadable marker";
              return `${h.rel} exists in the ${h.via} repository (${who}; ${h.staleHint})`;
            })
            .join("; ") +
          ". D-034: every runner refuses while results/v4/bench/RUNNING or results/v4/BUSY exists; a stale marker is removed by hand after checking that nothing runs."
      )
    );
    this.name = "MarkerHeldError";
  }
}

// ------------------------------------------------------------------ environment

function isWsl(): boolean {
  if (process.platform !== "linux") return false;
  if (process.env["WSL_DISTRO_NAME"]) return true;
  try {
    return /microsoft/i.test(fs.readFileSync("/proc/version", "utf8"));
  } catch {
    return false;
  }
}

export function currentPidNamespace(): PidNamespace {
  if (process.platform === "win32") return "win32";
  if (process.platform === "linux") return isWsl() ? "wsl2" : "linux";
  return process.platform;
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

function staleHintOf(rec: { pid?: number; pidNamespace?: string } | null, legacy: boolean): string {
  if (!rec || typeof rec.pid !== "number") return "no pid recorded";
  const ns = rec.pidNamespace ?? (legacy ? "unknown (legacy marker)" : "unknown");
  if (ns !== currentPidNamespace()) return `pid ${rec.pid} in namespace ${ns}: liveness cannot be checked from here`;
  return pidAlive(rec.pid) ? `pid ${rec.pid} is alive` : `pid ${rec.pid} is not alive here: probably stale`;
}

// ------------------------------------------------------------------ roots

function sameDir(a: string, b: string): boolean {
  const norm = (p: string) => {
    let r = path.resolve(p);
    try {
      r = fs.realpathSync.native(r);
    } catch {
      /* keep the resolved path */
    }
    return process.platform === "win32" ? r.toLowerCase() : r;
  };
  return norm(a) === norm(b);
}

/** Throws unless `dir` looks like a PQ-Identity-v4 repository (docs/v4/BENCH_PROTOCOL.md and results/v4/). */
export function assertRepoRoot(dir: string, what: string): void {
  if (!path.isAbsolute(dir)) throw new Error(`${what}: repository path must be absolute`);
  const proto = path.join(dir, "docs", "v4", "BENCH_PROTOCOL.md");
  const results = path.join(dir, "results", "v4");
  if (!fs.existsSync(proto) || !fs.existsSync(results) || !fs.statSync(results).isDirectory()) {
    throw new Error(sanitize(`${what}: ${dir} is not a PQ-Identity-v4 repository (needs docs/v4/BENCH_PROTOCOL.md and results/v4/)`));
  }
}

export interface MarkerRootOptions {
  /** Local repository (default: this checkout, REPO_ROOT). */
  repo?: string;
  /** The Windows repository as seen from WSL (for example /mnt/c/.../PQ-Identity-v4). */
  windowsRepo?: string;
  /** Also check and write the local repository when windowsRepo is given (default true). */
  includeLocal?: boolean;
  /**
   * Allow a WSL runner to use only the local (clone) repository. D-034 requires WSL runners to
   * hold the Windows marker, so this is for tests and smoke runs only (default false).
   */
  allowLocalOnlyInWsl?: boolean;
}

/** The repositories whose markers a runner checks and writes. */
export function markerRoots(opts: MarkerRootOptions = {}): MarkerRoot[] {
  const local = opts.repo ?? REPO_ROOT;
  const roots: MarkerRoot[] = [];
  const windowsRepo = opts.windowsRepo ?? (process.env[WINDOWS_REPO_ENV]?.trim() || undefined);
  if (windowsRepo === undefined && isWsl() && !opts.allowLocalOnlyInWsl) {
    throw new Error(
      `WSL runner without --windows-repo (or ${WINDOWS_REPO_ENV}): D-034 requires timed WSL series to hold results/v4/bench/RUNNING in the Windows repository through its /mnt/c path`
    );
  }
  if (windowsRepo === undefined || opts.includeLocal !== false) {
    assertRepoRoot(local, "local repository");
    roots.push({ repo: path.resolve(local), via: "local" });
  }
  if (windowsRepo !== undefined) {
    assertRepoRoot(windowsRepo, "explicit repository");
    if (!roots.some((r) => sameDir(r.repo, windowsRepo))) roots.push({ repo: path.resolve(windowsRepo), via: "explicit" });
  }
  return roots;
}

/** Explicit Windows repository from --windows-repo <path> (or the environment fallback). */
export function windowsRepoFromArgs(argv: readonly string[]): string | undefined {
  return opt(argv, "windows-repo") ?? (process.env[WINDOWS_REPO_ENV]?.trim() || undefined);
}

export function markerFile(root: MarkerRoot, kind: MarkerKind): string {
  return path.join(root.repo, ...MARKER_REL[kind].split("/"));
}

// ------------------------------------------------------------------ inspection

function parseMarker(text: string): { record: MarkerRecord | null; legacy: HeldMarker["legacy"] } {
  try {
    const j = JSON.parse(text) as Partial<MarkerRecord> & { campaign?: unknown; pid?: unknown; startedUtc?: unknown };
    if (j && j.schema === MARKER_SCHEMA && typeof j.token === "string" && (j.kind === "RUNNING" || j.kind === "BUSY")) {
      return { record: j as MarkerRecord, legacy: null };
    }
    if (j && typeof j === "object") {
      return {
        record: null,
        legacy: {
          ...(typeof j.campaign === "string" ? { campaign: j.campaign } : {}),
          ...(typeof j.pid === "number" ? { pid: j.pid } : {}),
          ...(typeof j.startedUtc === "string" ? { startedUtc: j.startedUtc } : {}),
        },
      };
    }
  } catch {
    /* not JSON */
  }
  return { record: null, legacy: null };
}

/** Every marker (either kind) present in the given repositories. */
export function readMarkers(roots: readonly MarkerRoot[] = markerRoots()): HeldMarker[] {
  const out: HeldMarker[] = [];
  for (const root of roots) {
    for (const kind of MARKER_KINDS) {
      const file = markerFile(root, kind);
      if (!fs.existsSync(file)) continue;
      let text = "";
      try {
        text = fs.readFileSync(file, "utf8");
      } catch {
        /* vanished or unreadable: still counts as held */
      }
      const { record, legacy } = parseMarker(text);
      out.push({ kind, via: root.via, rel: MARKER_REL[kind], file, record, legacy, staleHint: staleHintOf(record ?? legacy, record === null) });
    }
  }
  return out;
}

/** Throws MarkerHeldError when any marker exists (for smoke runs and analyses that hold none). */
export function assertMarkersFree(roots: readonly MarkerRoot[] = markerRoots(), wanted: MarkerKind = "RUNNING"): void {
  const held = readMarkers(roots);
  if (held.length > 0) throw new MarkerHeldError(held, wanted);
}

// ------------------------------------------------------------------ acquire / release

export interface AcquireOptions extends MarkerRootOptions {
  kind: MarkerKind;
  campaign: string;
  /** Repo-relative script path or short label (no absolute paths). */
  runner: string;
  owner?: string;
  note?: string;
  /** Repositories to use; default markerRoots(options). */
  roots?: readonly MarkerRoot[];
  /** Release on process exit (default true). */
  releaseOnExit?: boolean;
  /**
   * On SIGINT/SIGTERM/SIGBREAK/SIGHUP: release, then exit with code 130 on the next turn of the
   * event loop (setImmediate), so listeners registered after this one for the same signal
   * (for example the runner stopping its own Anvil) still run first (default true).
   */
  exitOnSignal?: boolean;
  /** Token inherited from a wrapping `markers.ts run` (default: process.env[MARKER_TOKEN_ENV]). */
  inheritedToken?: string;
  /**
   * "all" (default): write the marker in every repository checked. "explicit-only": check every
   * repository but write only the explicit (Windows) copy; for a WSL wrapper around a frozen
   * Phase D runner, which holds the clone's own RUNNING itself.
   */
  write?: MarkerWriteMode;
}

export type MarkerWriteMode = "all" | "explicit-only";

export interface MarkerHandle {
  kind: MarkerKind;
  /**
   * The record of the hold. For a borrowed handle this is the WRAPPER's record (its campaign
   * and runner); results then record `record` as the hold and `borrowedBy` as the runner.
   */
  record: MarkerRecord;
  /** Repo-relative marker path and the repository it lives in, per copy. */
  copies: Array<{ rel: string; via: MarkerRoot["via"] }>;
  /** true when the marker is held by a wrapping process (`markers.ts run`) and this handle only uses it. */
  borrowed: boolean;
  /** Borrowed handles: the campaign and runner labels of the runner that borrowed the hold; null otherwise. */
  borrowedBy?: { campaign: string; runner: string } | null;
  released(): boolean;
  /** Remove every copy this handle wrote, if it still carries this handle's token. Idempotent. */
  release(): void;
}

function cleanLabel(s: string, what: string): string {
  const t = sanitize(String(s)).trim();
  if (t.length === 0) throw new Error(`${what} must be a non-empty label`);
  if (t.length > 200) throw new Error(`${what} is longer than 200 characters`);
  if (path.isAbsolute(t) || /^[A-Za-z]:[\\/]/.test(t)) throw new Error(`${what} must not be an absolute path`);
  return t;
}

function removeIfOurs(file: string, token: string): void {
  try {
    const cur = JSON.parse(fs.readFileSync(file, "utf8")) as { token?: string };
    if (cur.token === token) fs.rmSync(file, { force: true });
  } catch {
    /* already gone or not ours */
  }
}

/**
 * Create the marker of `kind` in every repository (D-034), refusing when any RUNNING or BUSY
 * marker exists in any of them. Returns a handle whose release() removes what it wrote.
 */
export function acquireMarker(opts: AcquireOptions): MarkerHandle {
  const kind = opts.kind;
  if (kind !== "RUNNING" && kind !== "BUSY") throw new Error(`unknown marker kind ${String(kind)}`);
  const roots = opts.roots ?? markerRoots(opts);
  if (roots.length === 0) throw new Error("no repository to hold the marker in");
  const campaign = cleanLabel(opts.campaign, "campaign");
  const runner = cleanLabel(opts.runner, "runner");
  const owner = opts.owner === undefined ? null : cleanLabel(opts.owner, "owner");
  const note = opts.note === undefined ? null : sanitize(opts.note).slice(0, 500);

  const write: MarkerWriteMode = opts.write ?? "all";
  if (write !== "all" && write !== "explicit-only") throw new Error(`unknown write mode ${String(write)}`);
  const writeRoots = write === "all" ? roots : roots.filter((r) => r.via === "explicit");
  if (writeRoots.length === 0) throw new Error("write mode explicit-only needs an explicit repository (--windows-repo)");

  const held = readMarkers(roots);

  // A wrapping `markers.ts run` holds this kind with our inherited token: use it, write nothing.
  // It wrote every copy, or (write explicit-only) only the explicit one; either way the explicit
  // copy, when there is an explicit repository, must be among the held ones.
  const inherited = opts.inheritedToken ?? process.env[MARKER_TOKEN_ENV];
  if (inherited && held.length > 0) {
    const allOurs = held.every((h) => h.kind === kind && h.record?.token === inherited);
    const explicitRoot = roots.find((r) => r.via === "explicit");
    const covers = explicitRoot
      ? held.some((h) => h.via === "explicit" && h.file === markerFile(explicitRoot, kind))
      : roots.every((r) => held.some((h) => h.via === r.via && h.file === markerFile(r, kind)));
    if (allOurs && covers) {
      const rec = held[0]?.record as MarkerRecord;
      return {
        kind,
        record: rec,
        copies: held.map((h) => ({ rel: h.rel, via: h.via })),
        borrowed: true,
        borrowedBy: { campaign, runner },
        released: () => false,
        release: () => undefined,
      };
    }
  }
  if (held.length > 0) throw new MarkerHeldError(held, kind);

  const token = randomUUID();
  const base = {
    schema: MARKER_SCHEMA,
    kind,
    campaign,
    runner,
    owner,
    note,
    startedUtc: utcNow(),
    pid: process.pid,
    pidNamespace: currentPidNamespace(),
    token,
    rule: MARKER_RULE[kind],
  } as const;

  const written: Array<{ file: string; root: MarkerRoot }> = [];
  const undo = () => {
    for (const w of written) removeIfOurs(w.file, token);
  };
  let record: MarkerRecord | null = null;
  try {
    for (const root of writeRoots) {
      const file = markerFile(root, kind);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      const rec: MarkerRecord = { ...base, writtenVia: root.via === "local" ? "local repository" : "explicit repository path" };
      record ??= rec;
      fs.writeFileSync(file, JSON.stringify(rec, null, 2) + "\n", { flag: "wx" });
      written.push({ file, root });
    }
  } catch (e) {
    undo();
    if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new MarkerHeldError(readMarkers(roots), kind);
    throw e;
  }
  // Race check: another runner may have created the other kind between our check and our write.
  const after = readMarkers(roots).filter((h) => h.record?.token !== token);
  if (after.length > 0) {
    undo();
    throw new MarkerHeldError(after, kind);
  }

  let released = false;
  const handlers: Array<[string, (...a: unknown[]) => void]> = [];
  const release = () => {
    if (released) return;
    released = true;
    undo();
    for (const [ev, fn] of handlers) process.off(ev, fn);
  };
  if (opts.releaseOnExit !== false) {
    const onExit = () => release();
    process.on("exit", onExit);
    handlers.push(["exit", onExit]);
  }
  if (opts.exitOnSignal !== false) {
    for (const sig of ["SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"] as const) {
      const fn = () => {
        release();
        // exit on the next turn, so later listeners of this signal (the runner's own cleanup) run first
        setImmediate(() => process.exit(130));
      };
      process.on(sig, fn);
      handlers.push([sig, fn]);
    }
  }
  return {
    kind,
    record: record as MarkerRecord,
    copies: written.map((w) => ({ rel: MARKER_REL[kind], via: w.root.via })),
    borrowed: false,
    borrowedBy: null,
    released: () => released,
    release,
  };
}

// ------------------------------------------------------------------ command resolution (Windows)

export type CommandResolution =
  | { kind: "ok"; file: string }
  | { kind: "refused"; file: string; reason: string }
  | { kind: "not-found"; reason: string };

export interface WindowsCommandEnv {
  PATH?: string;
  PATHEXT?: string;
  /** %SystemRoot% (default C:\Windows). */
  SystemRoot?: string;
  /** %LOCALAPPDATA% (its Microsoft\WindowsApps holds the app execution aliases). */
  LOCALAPPDATA?: string;
  /** Base of a relative command path. */
  cwd: string;
}

const WSL_EXECUTABLES: readonly string[] = ["wsl.exe", "wslg.exe", "wslhost.exe"];

/** Why a resolved Windows executable would start WSL, or null. */
export function wslLauncherReason(file: string, env: Pick<WindowsCommandEnv, "SystemRoot" | "LOCALAPPDATA">): string | null {
  const w = path.win32;
  const base = w.basename(file).toLowerCase();
  const dir = w.dirname(w.resolve(file)).toLowerCase();
  const under = (root: string | undefined, ...sub: string[]): boolean => {
    if (!root) return false;
    const r = w.join(root, ...sub).toLowerCase().replace(/\\+$/, "");
    return dir === r || dir.startsWith(r + "\\");
  };
  if (WSL_EXECUTABLES.includes(base)) return `${base} starts WSL`;
  const sysRoot = env.SystemRoot ?? "C:\\Windows";
  const inSystem = under(sysRoot, "System32") || under(sysRoot, "SysWOW64") || under(sysRoot, "Sysnative");
  const inWindowsApps = under(env.LOCALAPPDATA, "Microsoft", "WindowsApps");
  if (base === "bash.exe" && (inSystem || inWindowsApps)) return `bash.exe in ${inSystem ? "the Windows system folder" : "WindowsApps"} is the WSL launcher`;
  if (inWindowsApps && /^ubuntu.*\.exe$/.test(base)) return `${base} in WindowsApps launches a WSL distribution`;
  return null;
}

/**
 * Resolve a command the way it will be spawned on Windows (PATH and PATHEXT; a command with a
 * path is taken relative to cwd; the current directory is not searched), and refuse one that
 * would start WSL. Pure: `isFile` answers whether a candidate exists.
 */
export function resolveWindowsCommand(cmd: string, env: WindowsCommandEnv, isFile: (p: string) => boolean): CommandResolution {
  const w = path.win32;
  const exts = (env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD")
    .split(";")
    .map((e) => e.trim())
    .filter((e) => e.startsWith("."));
  const candidates = (base: string): string[] => (w.extname(base) ? [base, ...exts.map((e) => base + e)] : exts.map((e) => base + e));
  let found: string | null = null;
  if (/[\\/]/.test(cmd) || /^[A-Za-z]:/.test(cmd)) {
    found = candidates(w.resolve(env.cwd, cmd)).find((c) => isFile(c)) ?? null;
  } else {
    const dirs = (env.PATH ?? "")
      .split(";")
      .map((d) => d.trim().replace(/^"(.*)"$/, "$1"))
      .filter((d) => d.length > 0);
    for (const d of dirs) {
      found = candidates(w.join(d, cmd)).find((c) => isFile(c)) ?? null;
      if (found) break;
    }
  }
  if (!found) return { kind: "not-found", reason: `${cmd} was not found on PATH (PATHEXT ${exts.join(";")})` };
  const why = wslLauncherReason(found, env);
  return why ? { kind: "refused", file: found, reason: why } : { kind: "ok", file: found };
}

function isFile(p: string): boolean {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

/** On Windows: resolveWindowsCommand with this process's environment. Elsewhere: the command unchanged (execvp searches PATH). */
export function resolveSpawnCommand(cmd: string): CommandResolution {
  if (process.platform !== "win32") return { kind: "ok", file: cmd };
  const sysRoot = process.env["SystemRoot"] ?? process.env["windir"];
  const localAppData = process.env["LOCALAPPDATA"];
  return resolveWindowsCommand(
    cmd,
    {
      cwd: process.cwd(),
      ...(process.env["PATH"] !== undefined ? { PATH: process.env["PATH"] } : {}),
      ...(process.env["PATHEXT"] !== undefined ? { PATHEXT: process.env["PATHEXT"] } : {}),
      ...(sysRoot !== undefined ? { SystemRoot: sysRoot } : {}),
      ...(localAppData !== undefined ? { LOCALAPPDATA: localAppData } : {}),
    },
    isFile
  );
}

// ------------------------------------------------------------------ CLI

const USAGE = `markers.ts (DECISIONS D-034 work markers)
  status [--repo <dir>] [--windows-repo <dir>]
      Print the markers present (JSON). Exit 0 when free, 3 when any marker exists.
  run --kind RUNNING|BUSY --campaign <name> --runner <label> [--owner <label>] [--note <text>]
      [--repo <dir>] [--windows-repo <dir>] [--write all|explicit-only] -- <command> [args...]
      Hold the marker while <command> runs (argv, no shell). The command gets ${MARKER_TOKEN_ENV}
      (so a runner built on markers.ts uses the held marker) and, with --windows-repo,
      ${WINDOWS_REPO_ENV}. --write explicit-only checks every repository but writes only the
      Windows copy: for a frozen Phase D runner in WSL, which writes the clone's RUNNING itself.
      Exit code = the command's.
  exec-if-free [--repo <dir>] [--windows-repo <dir>] -- <command> [args...]
      Start <command> only when no RUNNING or BUSY marker exists in any repository; hold
      nothing (for frozen tools that write their own legacy marker or none; they never read
      BUSY). Exit 3 when a marker exists, else the command's exit code.
  WSL runners must pass --windows-repo /mnt/c/.../PQ-Identity-v4 (or set ${WINDOWS_REPO_ENV}).
  On Windows the command is resolved through PATH and PATHEXT and refused (exit 2) when it would
  start WSL (wsl.exe, or the bash.exe launcher that a plain "bash" finds from PowerShell): run
  from Git Bash or pass the absolute path of Git's bash.exe. Not found: exit 127.`;

async function runChild(file: string, args: readonly string[], env: NodeJS.ProcessEnv): Promise<number> {
  const child = spawn(file, [...args], { stdio: "inherit", shell: false, windowsHide: true, env });
  const forward = (sig: NodeJS.Signals) => () => {
    if (child.exitCode === null) child.kill(sig);
  };
  const sigs = ["SIGINT", "SIGTERM", "SIGBREAK", "SIGHUP"] as const;
  const fns = sigs.map((s) => [s, forward(s)] as const);
  for (const [s, fn] of fns) process.on(s, fn);
  const code = await new Promise<number>((resolve) => {
    child.once("error", (e) => {
      console.error(sanitize(`markers.ts: could not start the command: ${e.message}`));
      resolve(127);
    });
    child.once("exit", (c, sig) => resolve(c ?? (sig ? 128 : 1)));
  });
  for (const [s, fn] of fns) process.off(s, fn);
  return code;
}

/** The command's file, or an exit code after printing why it is not started. */
function commandOrExit(cmd: readonly string[]): string | number {
  const res = resolveSpawnCommand(cmd[0] as string);
  if (res.kind === "refused") {
    console.error(sanitize(`markers.ts: refusing to start ${res.file}: ${res.reason}. v4 code never calls wsl.exe (docs/BENCHMARK_POLICY.md); run from Git Bash or pass the absolute path of Git's bash.exe.`));
    return 2;
  }
  if (res.kind === "not-found") {
    console.error(sanitize(`markers.ts: ${res.reason}`));
    return 127;
  }
  return res.file;
}

async function cli(argv: string[]): Promise<number> {
  const sep = argv.indexOf("--");
  const own = sep >= 0 ? argv.slice(0, sep) : argv;
  const cmd = sep >= 0 ? argv.slice(sep + 1) : [];
  const sub = own[0];
  const rootOpts: MarkerRootOptions = {
    ...(opt(own, "repo") !== undefined ? { repo: path.resolve(opt(own, "repo") as string) } : {}),
    ...(windowsRepoFromArgs(own) !== undefined ? { windowsRepo: windowsRepoFromArgs(own) as string } : {}),
    ...(flag(own, "allow-local-only") ? { allowLocalOnlyInWsl: true } : {}),
  };
  const childEnv = (token: string | null): NodeJS.ProcessEnv => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env[MARKER_TOKEN_ENV];
    if (token !== null) env[MARKER_TOKEN_ENV] = token;
    if (rootOpts.windowsRepo !== undefined) env[WINDOWS_REPO_ENV] = rootOpts.windowsRepo;
    return env;
  };
  if (sub === "status") {
    const held = readMarkers(markerRoots(rootOpts));
    console.log(
      JSON.stringify(
        { free: held.length === 0, held: held.map((h) => ({ kind: h.kind, rel: h.rel, repository: h.via, record: h.record, legacy: h.legacy, staleHint: h.staleHint })) },
        null,
        2
      )
    );
    return held.length === 0 ? 0 : 3;
  }
  if (sub === "run") {
    const kind = opt(own, "kind") as MarkerKind | undefined;
    const campaign = opt(own, "campaign");
    const runner = opt(own, "runner");
    const write = (opt(own, "write") ?? "all") as MarkerWriteMode;
    if (!kind || !campaign || !runner || cmd.length === 0 || (write !== "all" && write !== "explicit-only")) {
      console.error(USAGE);
      return 2;
    }
    const file = commandOrExit(cmd);
    if (typeof file === "number") return file;
    const owner = opt(own, "owner");
    const note = opt(own, "note");
    const handle = acquireMarker({
      kind,
      campaign,
      runner,
      ...(owner !== undefined ? { owner } : {}),
      ...(note !== undefined ? { note } : {}),
      ...rootOpts,
      write,
      inheritedToken: "",
      exitOnSignal: false,
    });
    try {
      return await runChild(file, cmd.slice(1), childEnv(handle.record.token));
    } finally {
      handle.release();
    }
  }
  if (sub === "exec-if-free") {
    if (cmd.length === 0) {
      console.error(USAGE);
      return 2;
    }
    const file = commandOrExit(cmd);
    if (typeof file === "number") return file;
    assertMarkersFree(markerRoots(rootOpts), "RUNNING");
    return runChild(file, cmd.slice(1), childEnv(null));
  }
  console.error(USAGE);
  return 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  cli(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e: unknown) => {
      console.error(sanitize(e instanceof Error ? e.message : String(e)));
      process.exit(e instanceof MarkerHeldError ? 3 : 1);
    }
  );
}
