import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { REPO_ROOT, sha256FileHex, sanitize, opt } from "../bench/lib.ts";

/**
 * Results root of the robustness row (DECISIONS D-034): results/v4/robustness/.
 * Smoke runs write only under results/v4/robustness/_smoke/, which is ignored by git twice: by
 * the line `results/v4/robustness/_smoke/` in the repository .gitignore and by a one-line
 * `.gitignore` ("*") that the runners place inside _smoke/ itself, so smoke output can never be
 * committed even from a checkout whose root .gitignore lacks the line.
 */
export const ROBUSTNESS_ROOT = path.join(REPO_ROOT, "results", "v4", "robustness");
export const SMOKE_ROOT = path.join(ROBUSTNESS_ROOT, "_smoke");

export function robustnessRoot(smoke: boolean): string {
  if (smoke) {
    fs.mkdirSync(SMOKE_ROOT, { recursive: true });
    const gi = path.join(SMOKE_ROOT, ".gitignore");
    if (!fs.existsSync(gi)) fs.writeFileSync(gi, "*\n");
    return SMOKE_ROOT;
  }
  return ROBUSTNESS_ROOT;
}

export const ROBUSTNESS_DOC = path.join(REPO_ROOT, "docs", "v4", "ROBUSTNESS.md");

/**
 * SHA-256 of docs/v4/ROBUSTNESS.md (the row's protocol and pre-registration) above
 * "## Deviations" with LF line ends (`normative`), and of the whole file (`file`).
 */
export function robustnessProtocolSha(): { normative: string; file: string } {
  if (!fs.existsSync(ROBUSTNESS_DOC)) throw new Error("docs/v4/ROBUSTNESS.md missing: the protocol must exist before any run");
  const text = fs.readFileSync(ROBUSTNESS_DOC, "utf8").replace(/\r\n/g, "\n");
  const cut = text.indexOf("\n## Deviations");
  if (cut < 0) throw new Error("docs/v4/ROBUSTNESS.md has no '## Deviations' section");
  return { normative: createHash("sha256").update(text.slice(0, cut)).digest("hex"), file: sha256FileHex(ROBUSTNESS_DOC) };
}

/** robustnessProtocolSha(), or the reason it is unavailable (smoke runs only; full runs require it). */
export function protocolRecord(smoke: boolean): { normative: string; file: string } | { error: string } {
  try {
    return robustnessProtocolSha();
  } catch (e) {
    if (!smoke) throw e;
    return { error: (e as Error).message };
  }
}

/**
 * What a full (non-smoke) run of this row requires to be committed and unchanged against HEAD:
 * the protocol, the harness and its helpers, the drivers, the forge tests and configuration, and
 * the code under test. A pre-registered hash only means something when git recorded the text.
 */
export const COMMITTED_PATHS: readonly string[] = Object.freeze([
  "docs/v4/ROBUSTNESS.md",
  "docs/v4/BENCH_PROTOCOL.md",
  "harness/v4/robustness",
  "harness/v4/lib",
  "harness/v4/bench/lib.ts",
  "harness/v4/bench/guard.ts",
  "harness/v4/scale_lib.ts",
  "harness/v4/r1cs_tools.ts",
  "scripts/robustness",
  "onchain/test/v4",
  "onchain/foundry.toml",
  "onchain/contracts/v4",
  "packages/v4/src",
]);

export interface CommitCheck {
  /** Every path is tracked, and nothing under them is untracked, staged or modified against HEAD. */
  gitClean: boolean;
  gitHead: string | null;
  paths: string[];
  /** Why not clean (repo-relative paths with git's porcelain status codes; at most 50 lines). */
  problems: string[];
}

function gitRead(args: string[]): { ok: boolean; out: string } {
  try {
    const out = execFileSync("git", args, {
      cwd: REPO_ROOT,
      encoding: "utf8",
      // read-only: no optional index refresh, no lazy fetch
      env: { ...process.env, GIT_OPTIONAL_LOCKS: "0", GIT_NO_LAZY_FETCH: "1" },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      maxBuffer: 64 * 1024 * 1024,
    });
    return { ok: true, out };
  } catch (e) {
    return { ok: false, out: String((e as { stderr?: unknown }).stderr ?? (e as Error).message) };
  }
}

/** Read-only git checks: ls-files --error-unmatch per path, status (untracked included), diff against HEAD. */
export function checkCommitted(paths: readonly string[] = COMMITTED_PATHS): CommitCheck {
  const problems: string[] = [];
  const head = gitRead(["rev-parse", "HEAD"]);
  if (!head.ok) return { gitClean: false, gitHead: null, paths: [...paths], problems: ["not a git checkout (git rev-parse HEAD failed)"] };
  for (const p of paths) if (!gitRead(["ls-files", "--error-unmatch", "--", p]).ok) problems.push(`not tracked: ${p}`);
  const st = gitRead(["status", "--porcelain=v1", "--untracked-files=all", "--", ...paths]);
  if (!st.ok) problems.push("git status failed");
  else for (const line of st.out.split(/\r?\n/)) if (line.trim()) problems.push(`${line.slice(0, 2).trim()}: ${line.slice(3)}`);
  if (!gitRead(["diff", "--quiet", "HEAD", "--", ...paths]).ok) problems.push("working tree differs from HEAD (git diff HEAD)");
  return { gitClean: problems.length === 0, gitHead: head.out.trim(), paths: [...paths], problems: problems.slice(0, 50).map((x) => sanitize(x)) };
}

/**
 * checkCommitted(); a full run refuses to start unless it is clean, a smoke run only records it.
 * Run this before taking a marker or writing results.
 */
export function assertCommitted(smoke: boolean, paths: readonly string[] = COMMITTED_PATHS): CommitCheck {
  const c = checkCommitted(paths);
  if (!smoke && !c.gitClean) {
    throw new Error(
      `a full run needs the protocol, the harness and the code under test committed and unchanged against HEAD (docs/v4/ROBUSTNESS.md 3.2): ${c.problems.slice(0, 8).join("; ")}${c.problems.length > 8 ? `; ... (${c.problems.length} problems)` : ""}`
    );
  }
  return c;
}

export interface BudgetSetting {
  /** Command-line option, without the leading dashes. */
  flag: string;
  /** Value in effect for this run. */
  value: number;
  /** Pre-registered value of a full run (docs/v4/ROBUSTNESS.md). */
  registered: number;
}

/**
 * Full runs use the pre-registered budgets. A full run whose budget differs from them refuses
 * to start unless --deviation "<text>" is given; the text is returned (for plan.json) and must
 * also be appended, dated, to the Deviations section of docs/v4/ROBUSTNESS.md before the run.
 * Smoke runs may change any budget and return null.
 */
export function budgetDeviation(argv: readonly string[], smoke: boolean, settings: readonly BudgetSetting[]): { text: string; changed: BudgetSetting[] } | null {
  if (smoke) return null;
  const changed = settings.filter((s) => s.value !== s.registered);
  if (changed.length === 0) return null;
  const text = opt(argv, "deviation");
  if (!text || text.trim().length === 0) {
    throw new Error(`budgets are pre-registered (docs/v4/ROBUSTNESS.md): ${changed.map((s) => `--${s.flag} ${s.value} (registered ${s.registered})`).join(", ")} needs --deviation "<text>", recorded in plan.json and appended, dated, to the protocol's Deviations`);
  }
  return { text: sanitize(text.trim()).slice(0, 2000), changed };
}
