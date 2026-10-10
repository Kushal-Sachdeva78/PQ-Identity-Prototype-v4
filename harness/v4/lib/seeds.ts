/**
 * Pre-registered PRNG seeds of the series run under DECISIONS D-034 (2026-10-01), as constants.
 *
 * Source of truth: DECISIONS.md D-034, "Pre-registered seeds (new series only)". A harness takes
 * its seed from here by id and records the value in its schedule; it never picks a seed at run
 * time. The bootstrap seed of every analysis stays 20260927 (BENCH_PROTOCOL.md).
 *
 * Seeds already used by earlier series are listed in USED_SEEDS so that no new series reuses
 * one by mistake (the module checks this when it loads).
 */

export interface SeedEntry {
  /** Stable id, `<row>.<use>`. */
  id: string;
  seed: number;
  /** Work-table row of D-034. */
  row: "chainRead" | "robustness" | "endToEnd" | "comparable" | "analysis";
  /** What the seed drives. */
  use: string;
}

/** The D-034 registry, in the order of the decision text. */
export const SEED_REGISTRY: readonly SeedEntry[] = Object.freeze([
  { id: "chainRead.conditionOrder", seed: 20261011, row: "chainRead", use: "order of conditions (client variants) within blocks" },
  { id: "chainRead.readOrder", seed: 20261012, row: "chainRead", use: "order of the registry reads within rounds" },
  { id: "chainRead.verifierPool", seed: 20261013, row: "chainRead", use: "verifier presentation pool and its order" },
  { id: "chainRead.walletReads", seed: 20261014, row: "chainRead", use: "wallet registry-read series" },
  { id: "robustness.load", seed: 20261021, row: "robustness", use: "verifier load test (cell order, pool rotation)" },
  { id: "robustness.fuzz", seed: 20261022, row: "robustness", use: "in-repo seeded fuzz generator (package entry points)" },
  { id: "robustness.circuitFuzz", seed: 20261023, row: "robustness", use: "bounded circuit and witness fuzz" },
  { id: "robustness.forgeFuzz", seed: 20261024, row: "robustness", use: "forge fuzz and invariant tests of the registries" },
  { id: "endToEnd.order", seed: 20261031, row: "endToEnd", use: "end-to-end presentation series (condition order)" },
  { id: "comparable.coldOrder", seed: 20261041, row: "comparable", use: "comparable benchmarks, cold run order" },
  { id: "comparable.walletRebuilds", seed: 20261042, row: "comparable", use: "comparable benchmarks, wallet rebuild series" },
  { id: "comparable.warm", seed: 20261043, row: "comparable", use: "comparable benchmarks, warm block order" },
  { id: "analysis.bootstrap", seed: 20260927, row: "analysis", use: "percentile bootstrap of every analysis (unchanged, BENCH_PROTOCOL.md)" },
] satisfies SeedEntry[]);

/** The same values by row, for direct use in harness code. */
export const SEEDS = Object.freeze({
  chainRead: Object.freeze({ conditionOrder: 20261011, readOrder: 20261012, verifierPool: 20261013, walletReads: 20261014 }),
  robustness: Object.freeze({ load: 20261021, fuzz: 20261022, circuitFuzz: 20261023, forgeFuzz: 20261024 }),
  endToEnd: Object.freeze({ order: 20261031 }),
  comparable: Object.freeze({ coldOrder: 20261041, walletRebuilds: 20261042, warm: 20261043 }),
  analysis: Object.freeze({ bootstrap: 20260927 }),
} as const);

/** Bootstrap seed of every analysis (BENCH_PROTOCOL.md, "Randomisation"; D-034 keeps it). */
export const SEED_BOOTSTRAP = SEEDS.analysis.bootstrap;

/**
 * Seeds earlier series already used. A new series must not reuse any of them.
 * - Phase D, pre-registered in BENCH_PROTOCOL.md: warm, cold_v4, cold_v2v3.
 * - WSL Phase D campaigns (results/v4/bench_wsl/<campaign>/schedule.json): cold_rs_wsl and
 *   warm_wsl ran with these seeds although no protocol text registered them.
 */
export const USED_SEEDS: Readonly<Record<string, number>> = Object.freeze({
  "phaseD.warm": 20260929,
  "phaseD.cold_v4": 20260930,
  "phaseD.cold_v2v3": 20261001,
  "phaseD.cold_rs_wsl": 20261002,
  "phaseD.warm_wsl": 20261003,
});

/**
 * Fallback seeds of the frozen Phase D runners: harness/v4/bench/cold_campaign.ts and warm.ts
 * use DEFAULT_SEEDS[campaign] and, for any other campaign name, these values, which are
 * USED_SEEDS phaseD.cold_rs_wsl and phaseD.warm_wsl. A D-034 run of either runner therefore
 * always passes --seed (seedArgs) and checks schedule.json (assertScheduleSeed).
 */
export const FROZEN_RUNNER_FALLBACK_SEEDS: Readonly<Record<string, number>> = Object.freeze({
  "harness/v4/bench/cold_campaign.ts": 20261002,
  "harness/v4/bench/warm.ts": 20261003,
});

/** The registered seed with this id; throws on an unknown id (no ad-hoc seeds). */
export function seedFor(id: string): number {
  const hit = SEED_REGISTRY.find((e) => e.id === id);
  if (!hit) throw new Error(`no seed registered under '${id}' (DECISIONS D-034); known ids: ${SEED_REGISTRY.map((e) => e.id).join(", ")}`);
  return hit.seed;
}

/**
 * Throws unless `seed` is a D-034 series seed: registered, not used by an earlier series
 * (USED_SEEDS, including the frozen runners' fallbacks) and not the analysis bootstrap seed.
 * Returns its registry entry.
 */
export function assertUnusedSeed(seed: number): SeedEntry {
  for (const [usedId, used] of Object.entries(USED_SEEDS)) {
    if (used === seed) throw new Error(`seed ${seed} was already used by ${usedId}; a D-034 series takes its seed from harness/v4/lib/seeds.ts (pass --seed to frozen runners)`);
  }
  const hit = SEED_REGISTRY.find((e) => e.seed === seed);
  if (!hit) throw new Error(`seed ${seed} is not registered in DECISIONS D-034 (harness/v4/lib/seeds.ts); no ad-hoc seeds`);
  if (hit.row === "analysis") throw new Error(`seed ${seed} is the analysis bootstrap seed (${hit.id}), not a series seed`);
  return hit;
}

/** ["--seed", "<seed>"] for a frozen runner (cold_campaign.ts, warm.ts), checked with assertUnusedSeed. */
export function seedArgs(id: string): string[] {
  const seed = seedFor(id);
  assertUnusedSeed(seed);
  return ["--seed", String(seed)];
}

/**
 * Throws unless a frozen runner's schedule.json (parsed) carries the D-034 seed `id`
 * (config.seed). A driver checks this after the runner wrote its schedule and before the
 * first timed slot (a cold slot starts only after its idle).
 */
export function assertScheduleSeed(schedule: unknown, id: string): number {
  const want = seedFor(id);
  assertUnusedSeed(want);
  const got = (schedule as { config?: { seed?: unknown } } | null)?.config?.seed;
  if (got !== want) throw new Error(`schedule.json has seed ${String(got)}, expected ${want} (${id}, DECISIONS D-034)`);
  return want;
}

/**
 * Registry self-check: every D-034 seed is distinct, matches SEEDS, and is not a seed of an
 * earlier series. Runs when the module loads; exported for the unit test.
 */
export function checkSeedRegistry(): void {
  const seen = new Map<number, string>();
  for (const e of SEED_REGISTRY) {
    const prev = seen.get(e.seed);
    if (prev !== undefined) throw new Error(`seed ${e.seed} registered twice (${prev}, ${e.id})`);
    seen.set(e.seed, e.id);
    const [row, use] = e.id.split(".") as [string, string];
    const byRow = (SEEDS as unknown as Record<string, Record<string, number>>)[row];
    if (!byRow || byRow[use] !== e.seed) throw new Error(`SEEDS.${e.id} does not match the registry entry ${e.seed}`);
    for (const [usedId, used] of Object.entries(USED_SEEDS)) {
      if (used === e.seed) throw new Error(`seed ${e.seed} (${e.id}) was already used by ${usedId}`);
    }
  }
  let n = 0;
  for (const row of Object.values(SEEDS)) n += Object.keys(row).length;
  if (n !== SEED_REGISTRY.length) throw new Error("SEEDS and SEED_REGISTRY list different entries");
  const used = new Set(Object.values(USED_SEEDS));
  for (const [runner, seed] of Object.entries(FROZEN_RUNNER_FALLBACK_SEEDS)) {
    if (!used.has(seed)) throw new Error(`fallback seed ${seed} of ${runner} is missing from USED_SEEDS`);
  }
}

checkSeedRegistry();
