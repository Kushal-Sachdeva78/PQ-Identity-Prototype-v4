import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { REPO_ROOT } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";
import { STANDARD_THRESHOLDS, MIN_ANCHOR_INTERVAL_SEC, EPOCH_WINDOW_SEC, WALLET_CLOCK_SKEW_SEC, REV_DEPTH, ISSUANCE_DEPTH, IMT_MAX } from "@pqid/v4/constants";
import { publishedBytes, IssuanceSnapshot } from "@pqid/v4/published";
import { IndexedMerkleTree } from "@pqid/v4/imt";

/**
 * E3: privacy measured instead of asserted.
 *
 * Anonymity set (prompt definition): the credentials in the current epoch that satisfy the
 * verifier's policy. Every other number here is a leak in bits, computed from the stated
 * model; labels: [M] measured by this script (sizes of real serialized blobs, rebuild times),
 * [S] computed from a stated population or behaviour model.
 *
 * Usage: tsx harness/v4/privacy.ts [--timing]   (--timing measures wallet rebuild time at
 * 10^5 and 10^6 credentials; run it only on a quiet machine, docs/v4/BENCH_PROTOCOL.md rules)
 */
const OUT = path.join(REPO_ROOT, "results", "v4", "privacy.json");
const YEAR_DAYS = 365.2425;
const log2 = (x: number) => Math.log(x) / Math.log(2);

/** Population model: ages uniform on [lo, hi) years. */
function bracketProbs(lo: number, hi: number, thresholds: readonly number[]) {
  const cuts = [lo, ...thresholds.filter((t) => t > lo && t < hi), hi];
  const out: Array<{ from: number; to: number; p: number }> = [];
  for (let i = 0; i + 1 < cuts.length; i++) out.push({ from: cuts[i]!, to: cuts[i + 1]!, p: (cuts[i + 1]! - cuts[i]!) / (hi - lo) });
  return out;
}
const entropy = (ps: number[]) => -ps.filter((p) => p > 0).reduce((s, p) => s + p * log2(p), 0);

async function sizes(statementBytes: number) {
  const rows = [];
  for (const n of [100_000, 1_000_000]) {
    for (const rf of [0.001, 0.01, 0.05]) {
      const r = Math.round(n * rf);
      rows.push({ credentials: n, revocationFraction: rf, revocations: r, bytes: publishedBytes(n, r, statementBytes), MiB: +(publishedBytes(n, r, statementBytes) / 2 ** 20).toFixed(2), label: "[S] exact from the blob format (packages/v4/src/published.ts), validated against a real blob by tests/v4/published.test.ts" });
    }
  }
  return rows;
}

async function timing() {
  const rows = [];
  for (const n of [100_000, 1_000_000]) {
    const leaves = Array.from({ length: n }, () => BigInt("0x" + randomBytes(31).toString("hex")));
    const t0 = process.hrtime.bigint();
    await IssuanceSnapshot.build(leaves, ISSUANCE_DEPTH);
    const issMs = Number(process.hrtime.bigint() - t0) / 1e6;
    const r = Math.round(n * 0.01);
    const keys = Array.from({ length: r }, () => BigInt("0x" + randomBytes(31).toString("hex")) % IMT_MAX);
    const t1 = process.hrtime.bigint();
    await IndexedMerkleTree.bulkBuild(keys, REV_DEPTH);
    const revMs = Number(process.hrtime.bigint() - t1) / 1e6;
    rows.push({ credentials: n, revocations: r, issuanceRebuildMs: Math.round(issMs), revocationRebuildMs: Math.round(revMs), label: "[M] single run, in-process, wallet-side rebuild from a downloaded blob" });
    console.log(`[privacy] rebuild n=${n}: issuance ${Math.round(issMs)} ms, revocation (r=${r}) ${Math.round(revMs)} ms`);
  }
  return rows;
}

async function main(): Promise<void> {
  const thresholds = STANDARD_THRESHOLDS;
  const models = [
    { name: "ages uniform 0-90 years", lo: 0, hi: 90 },
    { name: "adults uniform 18-90 years", lo: 18, hi: 90 },
  ];
  const anonymity = [];
  for (const m of models) {
    for (const n of [100_000, 1_000_000]) {
      for (const t of thresholds) {
        const pGte = Math.max(0, Math.min(1, (m.hi - Math.max(t, m.lo)) / (m.hi - m.lo)));
        anonymity.push({ model: m.name, credentialsInEpoch: n, threshold: t, ageGteSet: Math.round(n * pGte), ageLtSet: Math.round(n * (1 - pGte)), label: "[S] no revocations, none expired, one type" });
      }
    }
  }
  const brackets = models.map((m) => {
    const b = bracketProbs(m.lo, m.hi, thresholds);
    return { model: m.name, brackets: b.length, maxBits: +log2(b.length).toFixed(3), expectedBits: +entropy(b.map((x) => x.p)).toFixed(3), label: "[S] verifier asks every standard threshold and links the answers" };
  });
  const binarySearchBits = models.map((m) => ({ model: m.name, bits: +log2((m.hi - m.lo) * YEAR_DAYS).toFixed(2), label: "[S] unrestricted thresholds at day resolution (the v3 leak)" }));
  const crossings = [30, 90, 365].map((w) => ({ windowDays: w, pCrossingUniform090: +Math.min(1, (thresholds.length * w) / (90 * YEAR_DAYS)).toFixed(4), bitsIfCrossed: +log2(YEAR_DAYS).toFixed(2), label: "[S] daily queries by a verifier that can link the holder across days (e.g. an account); answer flips on the birthday" }));
  const leaks = {
    issuerVisibility: { issuersEqualSize: [2, 10, 100].map((k) => ({ issuers: k, bits: +log2(k).toFixed(2) })), note: "[S] the verifier learns which issuer; bits = log2(number of equally sized issuers)" },
    epochVisibility: { maxEpochsPerDay: Math.floor(86400 / MIN_ANCHOR_INTERVAL_SEC), windowSec: EPOCH_WINDOW_SEC, note: "[S] the epoch is shared by every holder of the issuer; it reveals at most which anchor interval the presentation fell in, which the verifier already knows from time" },
    pathFetchOnline: [100_000, 1_000_000].map((n) => ({ credentials: n, bitsToIssuer: +log2(n).toFixed(2), note: "[S] online mode: the issuer sees which leaf (so which holder) fetches a path, and when" })),
    pathFetchPublished: { bitsToIssuer: 0, note: "[S] published-tree mode: every wallet downloads the same blob" },
    perHolderEpochTargeting: { maxDistinctEpochsPerDay: Math.floor(86400 / MIN_ANCHOR_INTERVAL_SEC), bitsPerDayUpperBound: +log2(Math.floor(86400 / MIN_ANCHOR_INTERVAL_SEC)).toFixed(2), note: "[S] registry cadence caps epochs at one per interval; with published trees the issuer cannot tell who presents in an epoch, so this only partitions presentations by hour" },
    thresholdAnswers: brackets,
    unrestrictedBinarySearch: binarySearchBits,
    repeatedQueriesAroundBirthday: crossings,
    refusalKinds: {
      bitsUpperBound: 1,
      note: "[S] observation model DECISIONS D-026 (the caller of the wallet sees the refusal reason and timing): for a request that passes the request-level checks, a revoked credential or one not yet in the anchored epoch is refused with one generic anchorMatches refusal, differently from one that does not satisfy the predicate or has expired (predicateHolds); only holders who cannot present are affected. Requests with a non-standard threshold, a non-current date or a type outside the allow-list are refused before any credential-dependent work (routes TP-a, TP-c, TP-d, SD-b, SD-d, SD-f, SD-g, TY-c).",
    },
    dateLogAcrossVerifiers: {
      bitsUpperBound: 1,
      windowSec: 2 * WALLET_CLOCK_SKEW_SEC,
      note: "[S] review round 2 VRA-2: the wallet answers one date per window across all verifiers, so a verifier asking the other date within the window after midnight learns that the holder answered some verifier for the first date (DECISIONS D-027)",
    },
    allowListMembership: {
      note: "[S] review round 2 VRA-6: typeAllowed and typeHeld refuse differently, so a verifier can learn whether a type is on the wallet's allow-list (the list itself, not the credentials held beyond the D-018 bound)",
    },
    midnightTolerance: {
      fractionOfDay: +(WALLET_CLOCK_SKEW_SEC / 86400).toFixed(4),
      note: "[S] share of the day in which the wallet accepts two dates (the previous date only in the first WALLET_CLOCK_SKEW_SEC after UTC midnight, never a future date; DECISIONS D-017); within any 2 x WALLET_CLOCK_SKEW_SEC window the wallet answers one date only, so a verifier gets at most one of the two answers per visit",
    },
  };
  const statementBytesTypical = 720; // placeholder until measured below
  let stBytes = statementBytesTypical;
  const suite = path.join(REPO_ROOT, "results", "v4", "security_suite.json");
  void suite;
  // measure a real statement's JSON length from a synthetic but well-formed statement
  const st = { issuer: "did:pq:" + "x".repeat(28), controller: "0x" + "a".repeat(40), chainId: 31337, registry: "0x" + "b".repeat(40), epoch: 12345, root: (2n ** 253n).toString(), revRoot: (2n ** 253n).toString(), notBefore: 1790000000, notAfter: 1790086400, fromDate: 20260927, toDate: 20260928, signature: "c".repeat(4840) };
  stBytes = new TextEncoder().encode(JSON.stringify(st)).length;
  const out = {
    schema: "pqid/v4-privacy/v1",
    anonymitySetDefinition: "credentials in the current anchored epoch of the presentation's issuer that satisfy the verifier's policy (predicate, threshold, date, type), unexpired and not revoked",
    anonymity,
    leaks,
    publishedTree: { statementBytes: stBytes, sizes: await sizes(stBytes), timing: process.argv.includes("--timing") ? await timing() : "not run (needs a quiet machine: --timing)" },
    host: hostMeta(),
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(out, null, 2));
  console.log(`[privacy] -> ${path.relative(REPO_ROOT, OUT)}`);
  process.exit(0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e: unknown) => {
    console.error(e);
    process.exit(1);
  });
}
