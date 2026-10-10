// Rekey loader: run an unchanged v4 harness with a key other than the dev key.
//
//   PQID_V4_REKEY_LABEL=ceremony node --import tsx --import ./harness/v4/ceremony/rekey.mjs <script.ts> ...
//
// Environment:
//   PQID_V4_REKEY_LABEL  required; the key label (lower case, digits, dashes; not "dev")
//   PQID_V4_REKEY_DIR    optional; repo-relative folder of the key files (default setup/out/v4)
//
// In that process packages/v4/src/paths.ts exports KEY_LABEL_V4 = <label> and the paths
// <dir>/credential_auth_v4_<label>.zkey, verification_key_<label>.json,
// Groth16VerifierV4_<label>.sol and setup_transcript_<label>.json instead of the *_dev.* files.
// Every consumer of those constants (prover defaults, VerifierV4 default vkey, World, the
// security suite's artifact record) then uses that key. No repository file is changed.
// Load it after tsx. Docs: docs/v4/CEREMONY_FOLLOWUP.md.

import { register } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkLabel } from "./rekey_rewrite.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");

const label = process.env.PQID_V4_REKEY_LABEL;
if (label === undefined || label === "") {
  throw new Error("rekey: PQID_V4_REKEY_LABEL is not set (the loader was imported on purpose, so a missing label is an error)");
}
checkLabel(label);

const dirRel = (process.env.PQID_V4_REKEY_DIR ?? "setup/out/v4").replace(/\\/g, "/").replace(/\/+$/, "");
if (dirRel === "" || path.isAbsolute(dirRel) || /^[A-Za-z]:/.test(dirRel) || dirRel.split("/").includes("..")) {
  throw new Error(`rekey: PQID_V4_REKEY_DIR must be a repo-relative folder without '..' (got ${JSON.stringify(dirRel)})`);
}
const dirAbs = dirRel === "setup/out/v4" ? null : path.join(repoRoot, ...dirRel.split("/"));

register("./rekey_hooks.mjs", import.meta.url, { data: { label, dirAbs, repoRoot } });
