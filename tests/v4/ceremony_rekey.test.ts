import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { REPO_ROOT } from "@pqid/common/paths";
import { rewritePathsSource, rekeyedNames, checkLabel, isPathsModule, DEV_FILES, REKEY_EXPORT } from "../../harness/v4/ceremony/rekey_rewrite.mjs";

/**
 * The rekey loader (harness/v4/ceremony/rekey.mjs): a process started with it sees
 * packages/v4/src/paths.ts with the key label and the four key file names replaced, so the
 * unchanged security suite runs with the ceremony key. packages/v4 itself is never edited.
 */

const PATHS_TS = path.join(REPO_ROOT, "packages", "v4", "src", "paths.ts");
const pathsSource = () => fs.readFileSync(PATHS_TS, "utf8");
const TSX = pathToFileURL(path.join(REPO_ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;
const REKEY = pathToFileURL(path.join(REPO_ROOT, "harness", "v4", "ceremony", "rekey.mjs")).href;
const PROBE = path.join(REPO_ROOT, "harness", "v4", "ceremony", "rekey_probe.ts");

function probe(env: Record<string, string | undefined>, withLoader: boolean) {
  const e: NodeJS.ProcessEnv = { ...process.env };
  delete e["PQID_V4_REKEY_LABEL"];
  delete e["PQID_V4_REKEY_DIR"];
  for (const [k, v] of Object.entries(env)) if (v !== undefined) e[k] = v;
  const args = ["--import", TSX, ...(withLoader ? ["--import", REKEY] : []), PROBE];
  const r = spawnSync(process.execPath, args, { cwd: REPO_ROOT, env: e, encoding: "utf8", windowsHide: true, timeout: 120_000 });
  const line = r.stdout.split(/\r?\n/).filter((l) => l.startsWith("{")).pop();
  return { status: r.status, stderr: r.stderr, out: line ? (JSON.parse(line) as Record<string, unknown>) : null };
}

describe("rewrite of packages/v4/src/paths.ts (text only)", () => {
  it("replaces the label and the four dev file names, exactly once each, and marks the module", () => {
    const src = pathsSource();
    const out = rewritePathsSource(src, { label: "ceremony" });
    const names = rekeyedNames("ceremony");
    for (const k of ["zkey", "vkey", "sol", "transcript"] as const) {
      expect(out).toContain(`SETUP_OUT_DIR_V4, "${names[k]}"`);
      expect(out).not.toContain(`"${DEV_FILES[k]}"`);
    }
    expect(out).toContain('KEY_LABEL_V4 = "ceremony"');
    expect(out).not.toMatch(/KEY_LABEL_V4\s*=\s*"dev"/);
    expect(out).toContain(`export const ${REKEY_EXPORT} = "ceremony";`);
    // every other line of the module is unchanged
    const before = new Set(src.split(/\r?\n/));
    const changed = out.split(/\r?\n/).filter((l) => !before.has(l));
    expect(changed.length).toBeLessThanOrEqual(8);
  });

  it("with a key folder, names the folder instead of setup/out/v4", () => {
    const dir = path.join(REPO_ROOT, "results", "v4", "ceremony", "_smoke", "x");
    const out = rewritePathsSource(pathsSource(), { label: "dryrun", dirAbs: dir });
    expect(out).toContain(`${JSON.stringify(dir)}, "credential_auth_v4_dryrun.zkey"`);
    expect(out).toContain("export const SETUP_OUT_DIR_V4 = path.join(REPO_ROOT, \"setup\", \"out\", \"v4\");");
  });

  it("fails closed when paths.ts changed (a name missing or doubled)", () => {
    const src = pathsSource();
    expect(() => rewritePathsSource(src.replace("credential_auth_v4_dev.zkey", "credential_auth_v4_x.zkey"), { label: "ceremony" })).toThrow(/expected exactly one/);
    const zkeyLine = src.split(/\r?\n/).find((l) => l.includes("credential_auth_v4_dev.zkey")) as string;
    expect(() => rewritePathsSource(`${src}\n${zkeyLine.replace("ZKEY_V4", "ZKEY_V4_COPY")}\n`, { label: "ceremony" })).toThrow(/found 2/);
    expect(() => rewritePathsSource(src.replace('KEY_LABEL_V4 = "dev"', 'KEY_LABEL_V4 = "other"'), { label: "ceremony" })).toThrow(/KEY_LABEL_V4/);
  });

  it("refuses the dev label and malformed labels", () => {
    for (const bad of ["dev", "", "Ceremony", "a b", "a/b", "1abc", "x".repeat(32)]) expect(() => checkLabel(bad)).toThrow();
    for (const ok of ["ceremony", "ceremony2", "dryrun", "rehearsal", "ceremony-b"]) expect(() => checkLabel(ok)).not.toThrow();
  });

  it("matches only this repository's paths.ts", () => {
    const url = pathToFileURL(PATHS_TS).href;
    expect(isPathsModule(url, REPO_ROOT)).toBe(true);
    expect(isPathsModule(`${url}?t=1`, REPO_ROOT)).toBe(true);
    expect(isPathsModule(pathToFileURL(path.join(REPO_ROOT, "packages", "v4", "src", "prove.ts")).href, REPO_ROOT)).toBe(false);
    expect(isPathsModule(pathToFileURL(path.join(REPO_ROOT, "artifact", "out", "x", "packages", "v4", "src", "paths.ts")).href, REPO_ROOT)).toBe(false);
    expect(isPathsModule("node:path", REPO_ROOT)).toBe(false);
    if (process.platform === "win32") expect(isPathsModule(url.toUpperCase().replace("FILE:", "file:"), REPO_ROOT)).toBe(true);
  });
});

describe("rekey loader in a child process", () => {
  it("without the loader the process resolves the dev key", () => {
    const r = probe({}, false);
    expect(r.status).toBe(0);
    expect(r.out).toMatchObject({ rekeyLabel: null, keyLabel: "dev", zkey: "setup/out/v4/credential_auth_v4_dev.zkey", vkey: "setup/out/v4/verification_key_dev.json", proveDefault: { zkey: "setup/out/v4/credential_auth_v4_dev.zkey", keyLabel: "dev" }, vkeyParses: true });
  });

  it("with the loader every consumer (bare and relative imports) resolves the rekeyed files", () => {
    const r = probe({ PQID_V4_REKEY_LABEL: "probe" }, true);
    expect(r.status).toBe(0);
    expect(r.out).toMatchObject({
      rekeyLabel: "probe",
      keyLabel: "probe",
      zkey: "setup/out/v4/credential_auth_v4_probe.zkey",
      vkey: "setup/out/v4/verification_key_probe.json",
      sol: "setup/out/v4/Groth16VerifierV4_probe.sol",
      transcript: "setup/out/v4/setup_transcript_probe.json",
      proveDefault: { zkey: "setup/out/v4/credential_auth_v4_probe.zkey", keyLabel: "probe" },
      vkeyParses: false,
    });
  });

  it("with a key folder the files are taken from it", () => {
    const r = probe({ PQID_V4_REKEY_LABEL: "probe", PQID_V4_REKEY_DIR: "results/v4/ceremony/_smoke/probe_key" }, true);
    expect(r.status).toBe(0);
    expect(r.out?.["zkey"]).toBe("results/v4/ceremony/_smoke/probe_key/credential_auth_v4_probe.zkey");
  });

  it("refuses a missing label, the dev label and a folder outside the repository", () => {
    for (const env of [{}, { PQID_V4_REKEY_LABEL: "dev" }, { PQID_V4_REKEY_LABEL: "probe", PQID_V4_REKEY_DIR: "../outside" }]) {
      const r = probe(env, true);
      expect(r.status, JSON.stringify(env)).not.toBe(0);
      expect(r.out).toBeNull();
      expect(r.stderr).toMatch(/rekey:/);
    }
  });
});
