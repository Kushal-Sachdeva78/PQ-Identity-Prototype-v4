import { describe, it, expect } from "vitest";
import { PURE_TARGETS } from "../../harness/v4/robustness/fuzz_targets.ts";
import { caseRng } from "../../harness/v4/robustness/rng.ts";
import { SEEDS } from "../../harness/v4/lib/seeds.ts";
import type { Violation } from "../../harness/v4/robustness/fuzz_types.ts";

/**
 * Every pure fuzz target of harness/v4/robustness/fuzz_targets.ts at a small fixed budget, from
 * the campaign's own seeds (robustness.fuzz 20261022; case i of a target is the campaign's case
 * i), on every test run. A property violation fails this test; the full budgets run in the fuzz
 * campaign (docs/v4/ROBUSTNESS.md section 4). Untimed.
 */

const MASTER = SEEDS.robustness.fuzz;
/** Cases per target here (the slowest targets get fewer). */
const BUDGET: Record<string, number> = { "T-pub": 60, "T-imt": 120, "T-open": 200 };
const DEFAULT_BUDGET = 300;

describe("pure fuzz targets at a small fixed budget (same seeds as the campaign)", () => {
  for (const t of PURE_TARGETS) {
    it(`${t.id}: ${t.title}`, async () => {
      if (t.setup) await t.setup({ smoke: true, log: () => undefined });
      const n = BUDGET[t.id] ?? DEFAULT_BUDGET;
      const violations: Array<{ index: number; v: Violation }> = [];
      try {
        for (let i = 0; i < n; i++) {
          const c = await t.gen(caseRng(MASTER, t.id, i), i);
          const out = await t.run(c);
          for (const v of out.violations) violations.push({ index: i, v });
        }
      } finally {
        if (t.teardown) await t.teardown();
      }
      expect(violations.slice(0, 5)).toEqual([]);
    });
  }
});
