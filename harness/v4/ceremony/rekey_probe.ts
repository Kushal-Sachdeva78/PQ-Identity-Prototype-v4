import path from "node:path";
import { fileURLToPath } from "node:url";
import { REPO_ROOT } from "@pqid/common/paths";
import * as paths from "@pqid/v4/paths";
import { V4_DEV_ARTIFACTS, loadVkeyV4 } from "@pqid/v4/prove";

/**
 * Prints, as one JSON line, the key that packages/v4 resolves in this process: the constants
 * of @pqid/v4/paths (bare specifier) and the prover defaults of @pqid/v4/prove, which imports
 * "./paths.ts" relatively. Run under the rekey loader, every field must name the rekeyed files;
 * without it, the dev files. Used by followup.ts before each suite or mutation run and by the
 * tests. Reads no key file except the verification key (to check it parses).
 */
export interface RekeyProbe {
  rekeyLabel: string | null;
  keyLabel: string;
  zkey: string;
  vkey: string;
  sol: string;
  transcript: string;
  proveDefault: { zkey: string; keyLabel: string };
  vkeyParses: boolean;
}

function rel(p: string): string {
  return path.relative(REPO_ROOT, p).split(path.sep).join("/");
}

export function probe(): RekeyProbe {
  let vkeyParses = false;
  try {
    vkeyParses = typeof loadVkeyV4(paths.VKEY_V4) === "object";
  } catch {
    vkeyParses = false;
  }
  const rk = (paths as Record<string, unknown>)["PQID_V4_REKEY_LABEL"];
  return {
    rekeyLabel: typeof rk === "string" ? rk : null,
    keyLabel: paths.KEY_LABEL_V4,
    zkey: rel(paths.ZKEY_V4),
    vkey: rel(paths.VKEY_V4),
    sol: rel(paths.SOL_V4),
    transcript: rel(paths.TRANSCRIPT_V4),
    proveDefault: { zkey: rel(V4_DEV_ARTIFACTS.zkey), keyLabel: V4_DEV_ARTIFACTS.keyLabel },
    vkeyParses,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(probe()));
}
