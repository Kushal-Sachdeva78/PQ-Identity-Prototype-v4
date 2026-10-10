// Pure text rewrite used by the rekey loader (harness/v4/ceremony/rekey.mjs).
//
// packages/v4/src/paths.ts names the dev key (KEY_LABEL_V4 = "dev", *_dev.* files under
// setup/out/v4). packages/v4 is frozen for the measurement period (DECISIONS D-034), so the
// ceremony follow-up does not edit it. Instead, a process started with the rekey loader sees
// a copy of paths.ts whose four key file names and key label are replaced. Every other export
// is the original code. Each replacement must hit exactly once, otherwise the loader throws
// (fail closed: a changed paths.ts stops the run instead of silently keeping the dev key).
//
// Plain JavaScript on purpose: the loader hooks run before tsx can compile TypeScript.

/** Suffix of the module this rewrite applies to (forward slashes). */
export const PATHS_SUFFIX = "/packages/v4/src/paths.ts";

/** Labels the rewrite accepts: lower case, digits and dashes; never "dev". */
export const LABEL_RE = /^[a-z][a-z0-9-]{0,30}$/;

/** The dev file names in paths.ts. */
export const DEV_FILES = Object.freeze({
  zkey: "credential_auth_v4_dev.zkey",
  vkey: "verification_key_dev.json",
  sol: "Groth16VerifierV4_dev.sol",
  transcript: "setup_transcript_dev.json",
});

/** Export added to the rewritten module, so a probe can tell that the loader was active. */
export const REKEY_EXPORT = "PQID_V4_REKEY_LABEL";

/** File names of a key with this label (the dev names with `_dev` replaced). */
export function rekeyedNames(label) {
  checkLabel(label);
  return {
    zkey: `credential_auth_v4_${label}.zkey`,
    vkey: `verification_key_${label}.json`,
    sol: `Groth16VerifierV4_${label}.sol`,
    transcript: `setup_transcript_${label}.json`,
  };
}

export function checkLabel(label) {
  if (typeof label !== "string" || !LABEL_RE.test(label)) {
    throw new Error(`rekey: label must match ${LABEL_RE} (got ${JSON.stringify(label)})`);
  }
  if (label === "dev") throw new Error('rekey: label "dev" is the default key; run without the rekey loader instead');
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function replaceOnce(source, re, replacement, what) {
  const hits = source.match(re);
  const n = hits ? hits.length : 0;
  if (n !== 1) throw new Error(`rekey: expected exactly one ${what} in packages/v4/src/paths.ts, found ${n}; the file changed, update harness/v4/ceremony/rekey_rewrite.mjs`);
  return source.replace(re, replacement);
}

/**
 * Rewrite the source text of packages/v4/src/paths.ts (TypeScript, or the JavaScript tsx
 * made of it) for a key with `label` in `dirAbs` (absolute directory, or null for the
 * default setup/out/v4 directory, SETUP_OUT_DIR_V4).
 * @param {string} source
 * @param {{ label: string, dirAbs?: string | null }} opts
 * @returns {string}
 */
export function rewritePathsSource(source, { label, dirAbs = null }) {
  checkLabel(label);
  if (typeof source !== "string") throw new Error("rekey: paths.ts source is not text");
  if (dirAbs !== null && (typeof dirAbs !== "string" || dirAbs.length === 0)) throw new Error("rekey: dirAbs must be an absolute path or null");
  const names = rekeyedNames(label);
  const dirExpr = dirAbs === null ? "SETUP_OUT_DIR_V4" : JSON.stringify(dirAbs);
  let out = source;
  for (const k of ["zkey", "vkey", "sol", "transcript"]) {
    const re = new RegExp(`SETUP_OUT_DIR_V4\\s*,\\s*(["'])${escapeRe(DEV_FILES[k])}\\1`, "g");
    out = replaceOnce(out, re, `${dirExpr}, ${JSON.stringify(names[k])}`, `${DEV_FILES[k]} path`);
  }
  out = replaceOnce(out, /\bKEY_LABEL_V4\s*=\s*(["'])dev\1/g, `KEY_LABEL_V4 = ${JSON.stringify(label)}`, "KEY_LABEL_V4 = \"dev\"");
  out += `\n// [rekey] rewritten by harness/v4/ceremony/rekey.mjs: key label ${JSON.stringify(label)}\nexport const ${REKEY_EXPORT} = ${JSON.stringify(label)};\n`;
  return out;
}

/** True when `fileUrl` is the paths.ts of the repository at `repoRoot` (absolute path). */
export function isPathsModule(fileUrl, repoRoot) {
  if (typeof fileUrl !== "string" || !fileUrl.startsWith("file:")) return false;
  let p;
  try {
    p = decodeURIComponent(new URL(fileUrl).pathname);
  } catch {
    return false;
  }
  const fold = process.platform === "win32" ? (s) => s.toLowerCase() : (s) => s;
  const norm = (s) => fold(s.replace(/\\/g, "/").replace(/^\/([A-Za-z]:)/, "$1"));
  return norm(p) === norm(`${repoRoot.replace(/[\\/]+$/, "")}${PATHS_SUFFIX}`);
}
