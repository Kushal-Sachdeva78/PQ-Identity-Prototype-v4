/**
 * ONE cold wallet rebuild in a fresh process (docs/v4/CMP.md, "Wallet rebuild"). Spawned by
 * harness/v4/cmp/cold.ts as
 *   node --import <tsx> child_wallet.ts --condition wallet1e5 --credentials N --revocations R --iss-root X --rev-root Y
 * prints exactly one JSON line on stdout and exits.
 *
 * What a wallet does after downloading a published blob (packages/v4/src/published.ts
 * parsePublication), without the blob parsing, in four timed phases (process.hrtime.bigint):
 *   poseidonInit : the first getPoseidon() of the process (circomlibjs buildPoseidon on its own
 *                  ffjavascript: a single-thread bn128 build plus the Poseidon constants), the
 *                  cost every fresh wallet process pays once; an error when it takes under 1 ms
 *                  (already built). This is the wallet library's curve build, not the
 *                  multi-threaded prover curve build of the cmp `curve` condition.
 *   issuance     : IssuanceSnapshot.build(leaves, ISSUANCE_DEPTH, poseidon)
 *   revocation   : IndexedMerkleTree.bulkBuild(keys, REV_DEPTH)
 *   derived      : rebuild = issuance + revocation; total = poseidonInit + rebuild
 * Not timed (aux): module import, leaf and key generation (harness/v4/cmp/wallet_data.ts), the
 * circomlibjs and ffjavascript versions (read after the timed phases).
 * Both rebuilt roots must equal the pinned roots (results/v4/cmp/inputs/inputs_cmp.lock.json).
 *
 * In results/v4/privacy.json the first Poseidon build sat inside the timed 10^5 issuance rebuild
 * and not inside the 10^6 one (same process, cached); here it is a phase of its own in every run.
 * Prints no paths.
 */

import fs from "node:fs";
import path from "node:path";

function arg(name: string): string {
  const i = process.argv.indexOf(`--${name}`);
  const v = i >= 0 ? process.argv[i + 1] : undefined;
  if (!v) throw new Error(`missing --${name}`);
  return v;
}

function msSince(t0: bigint): number {
  return Math.round((Number(process.hrtime.bigint() - t0) / 1e6) * 1000) / 1000;
}

function out(line: unknown, code: number): void {
  process.stdout.write(JSON.stringify(line) + "\n", () => process.exit(code));
}

/** Below this the first getPoseidon() cannot have built anything (a cached singleton returns in microseconds). */
const POSEIDON_INIT_MIN_MS = 1;

/** Version of a package under node_modules (the copy nested under `parent` first); null when not found. */
function pkgVersion(name: string, parent?: string): string | null {
  const nm = path.join(process.cwd(), "node_modules");
  const candidates = [...(parent ? [path.join(nm, parent, "node_modules", name, "package.json")] : []), path.join(nm, name, "package.json")];
  for (const f of candidates) {
    try {
      return (JSON.parse(fs.readFileSync(f, "utf8")) as { version?: string }).version ?? null;
    } catch {
      /* next candidate */
    }
  }
  return null;
}

async function main(): Promise<void> {
  const mainAtMs = Math.round(performance.now() * 1000) / 1000;
  const condition = arg("condition");
  const credentials = Number(arg("credentials"));
  const revocations = Number(arg("revocations"));
  const issRootPin = arg("iss-root");
  const revRootPin = arg("rev-root");
  if (!Number.isInteger(credentials) || credentials < 1 || !Number.isInteger(revocations) || revocations < 0) throw new Error("bad sizes");

  // ---- imports (aux)
  const tI = process.hrtime.bigint();
  const enc = await import("@pqid/common/encoding");
  const pub = await import("@pqid/v4/published");
  const imt = await import("@pqid/v4/imt");
  const c = await import("@pqid/v4/constants");
  const wd = await import("./wallet_data.ts");
  const importMs = msSince(tI);
  if (wd.WALLET_IMT_MAX !== c.IMT_MAX) throw new Error("wallet_data.ts WALLET_IMT_MAX differs from @pqid/v4/constants IMT_MAX");

  // ---- data (aux)
  const tG = process.hrtime.bigint();
  const leaves = wd.walletLeaves(credentials);
  const keys = wd.walletRevKeys(revocations, c.IMT_MAX);
  const genMs = msSince(tG);

  // ---- poseidonInit (timed): first getPoseidon() of this process
  const tC = process.hrtime.bigint();
  const poseidon = await enc.getPoseidon();
  const poseidonInitMs = msSince(tC);
  if (poseidonInitMs < POSEIDON_INIT_MIN_MS) throw new Error(`first getPoseidon() took ${poseidonInitMs} ms: already built before the poseidonInit phase`);
  const tC2 = process.hrtime.bigint();
  const again = await enc.getPoseidon();
  const poseidonCachedMs = msSince(tC2);
  if (again !== poseidon) throw new Error("getPoseidon() returned a different instance the second time");

  // ---- issuance (timed)
  const tIs = process.hrtime.bigint();
  const snap = await pub.IssuanceSnapshot.build(leaves, c.ISSUANCE_DEPTH, poseidon);
  const issuanceMs = msSince(tIs);

  // ---- revocation (timed)
  const tR = process.hrtime.bigint();
  const rev = await imt.IndexedMerkleTree.bulkBuild(keys, c.REV_DEPTH);
  const revocationMs = msSince(tR);

  const issuanceRoot = snap.root().toString();
  const revocationRoot = rev.root().toString();
  const issuanceRootMatch = issuanceRoot === issRootPin;
  const revocationRootMatch = revocationRoot === revRootPin;
  const r3 = (x: number) => Math.round(x * 1000) / 1000;
  const mem = process.memoryUsage();
  out(
    {
      schema: "pqid/v4-cmp-wallet-child/v1",
      condition,
      ok: issuanceRootMatch && revocationRootMatch,
      checks: { issuanceRootMatch, revocationRootMatch },
      size: { credentials, revocations, issuanceDepth: c.ISSUANCE_DEPTH, revocationDepth: c.REV_DEPTH },
      timings: { poseidonInitMs, issuanceMs, revocationMs, rebuildMs: r3(issuanceMs + revocationMs), totalMs: r3(poseidonInitMs + issuanceMs + revocationMs) },
      aux: {
        mainAtMs,
        importMs,
        genMs,
        poseidonCachedMs,
        poseidonLib: { circomlibjs: pkgVersion("circomlibjs"), ffjavascript: pkgVersion("ffjavascript", "circomlibjs"), threads: "single (circomlibjs buildPoseidon)" },
        maxRssMiB: Math.round((process.resourceUsage().maxRSS / 1024) * 10) / 10,
        heapUsedMiB: Math.round((mem.heapUsed / 2 ** 20) * 10) / 10,
      },
      roots: { issuanceRoot, revocationRoot },
      runtime: { node: process.version, openssl: process.versions.openssl ?? "unknown" },
    },
    0
  );
}

main().catch((e: unknown) => {
  const msg = e instanceof Error ? e.message : String(e);
  out({ schema: "pqid/v4-cmp-wallet-child/v1", ok: false, error: msg.slice(0, 2000) }, 1);
});
