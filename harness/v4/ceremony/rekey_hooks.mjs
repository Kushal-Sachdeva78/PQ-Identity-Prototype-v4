// Module customization hooks of the rekey loader (registered by harness/v4/ceremony/rekey.mjs).
// Only packages/v4/src/paths.ts of this repository is changed, and only in memory; see
// rekey_rewrite.mjs for what is replaced. Every other module loads unchanged.

import { rewritePathsSource, isPathsModule } from "./rekey_rewrite.mjs";

let cfg = null;

export async function initialize(data) {
  cfg = data;
}

export async function load(url, context, nextLoad) {
  const r = await nextLoad(url, context);
  if (!cfg || !isPathsModule(url, cfg.repoRoot)) return r;
  if (r.source === undefined || r.source === null) {
    throw new Error("rekey: packages/v4/src/paths.ts came back without source text; load the rekey loader after tsx (node --import tsx --import <rekey.mjs>)");
  }
  const text = typeof r.source === "string" ? r.source : Buffer.from(r.source).toString("utf8");
  return { ...r, source: rewritePathsSource(text, { label: cfg.label, dirAbs: cfg.dirAbs }) };
}
