import type { Rng } from "./rng.ts";

/** Shared types of the fuzz runner (fuzz.ts) and its targets (fuzz_targets.ts, fuzz_chain.ts). */

export interface FuzzCase {
  /** Generator family (for the outcome histogram). */
  family: string;
  /** The value handed to the entry point(s); exotic objects cannot be written exactly. */
  input: unknown;
  /** Mutation recipe (what the generator did to a valid input). */
  recipe: string[];
  /** Extra facts the property needs (expected values, indices); written with failures. */
  meta?: Record<string, unknown>;
}

export interface Violation {
  /** Short id of the failed predicate (part of the failure signature). */
  predicate: string;
  detail: string;
  /** Class of an unexpected exception, when the violation is one. */
  errorClass?: string;
}

export interface Observation {
  /** Stable id (counted per target). */
  id: string;
  detail: string;
}

export interface CaseOutcome {
  /** Outcome label for the histogram ("accepted", "rejected", "threw:Error", ...). */
  outcome: string;
  violations: Violation[];
  observations: Observation[];
  /** Wall time of the call(s) under test only, ms (slow-input detector; not a timing result). */
  callMs: number;
}

export interface TargetContext {
  smoke: boolean;
  log: (s: string) => void;
  /** Send a record to the parent runner (one JSON line on stdout), for example {anvilPid}. */
  emit?: (o: Record<string, unknown>) => void;
}

export interface FuzzTarget {
  id: string;
  title: string;
  entryPoints: string[];
  kind: "pure" | "chain";
  /** Full-campaign number of cases (pre-registered in docs/v4/ROBUSTNESS.md). */
  budget: number;
  /** Smoke-run number of cases. */
  smokeBudget: number;
  /** The property, in words (copied into the results). */
  property: string;
  /** Exception classes the entry points may throw by contract (anything else is a violation). */
  documentedErrors: string[];
  setup?(ctx: TargetContext): Promise<void>;
  teardown?(): Promise<void>;
  gen(rng: Rng, index: number): FuzzCase | Promise<FuzzCase>;
  run(c: FuzzCase): CaseOutcome | Promise<CaseOutcome>;
}

export function errClass(e: unknown): string {
  if (e instanceof Error) return e.name || e.constructor?.name || "Error";
  return `non-Error:${typeof e}`;
}

export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Run fn, return [value | undefined, error | undefined, ms]. */
export function timedCall<T>(fn: () => T): { value?: T; error?: unknown; ms: number } {
  const t0 = process.hrtime.bigint();
  try {
    const value = fn();
    return { value, ms: Number(process.hrtime.bigint() - t0) / 1e6 };
  } catch (error) {
    return { error, ms: Number(process.hrtime.bigint() - t0) / 1e6 };
  }
}

export async function timedCallAsync<T>(fn: () => Promise<T>): Promise<{ value?: T; error?: unknown; ms: number }> {
  const t0 = process.hrtime.bigint();
  try {
    const value = await fn();
    return { value, ms: Number(process.hrtime.bigint() - t0) / 1e6 };
  } catch (error) {
    return { error, ms: Number(process.hrtime.bigint() - t0) / 1e6 };
  }
}

/** Collects violations and observations of one case. */
export class Verdict {
  readonly violations: Violation[] = [];
  readonly observations: Observation[] = [];
  outcome = "ok";
  callMs = 0;

  fail(predicate: string, detail: string, errorClass?: string): void {
    this.violations.push({ predicate, detail: detail.slice(0, 600), ...(errorClass ? { errorClass } : {}) });
  }

  check(cond: boolean, predicate: string, detail: string): void {
    if (!cond) this.fail(predicate, detail);
  }

  observe(id: string, detail: string): void {
    this.observations.push({ id, detail: detail.slice(0, 400) });
  }

  /** An exception from an entry point: allowed when its class is documented, else a violation. */
  thrown(e: unknown, documented: readonly string[], where: string): void {
    const cls = errClass(e);
    if (!documented.includes(cls)) this.fail(`${where}:undocumentedThrow`, `${where} threw ${cls}: ${errMsg(e)}`, cls);
  }

  done(): CaseOutcome {
    return { outcome: this.outcome, violations: this.violations, observations: this.observations, callMs: this.callMs };
  }
}
