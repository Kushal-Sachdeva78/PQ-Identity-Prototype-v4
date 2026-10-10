export interface SampleSummary {
  n: number;
  meanMs: number;
  medianMs: number;
  stddevMs: number;
  minMs: number;
  maxMs: number;
  p95Ms: number;
}

/**
 * Summary statistics matching the paper's methodology: mean, median,
 * sample standard deviation (n-1 denominator), min, max, p95.
 */
export function summarize(samplesMs: readonly number[]): SampleSummary {
  if (samplesMs.length === 0) throw new Error("no samples");
  const n = samplesMs.length;
  const sorted = [...samplesMs].sort((a, b) => a - b);
  const mean = samplesMs.reduce((a, b) => a + b, 0) / n;
  const median =
    n % 2 === 1
      ? (sorted[(n - 1) / 2] as number)
      : (((sorted[n / 2 - 1] as number) + (sorted[n / 2] as number)) / 2);
  const variance =
    n > 1
      ? samplesMs.reduce((acc, x) => acc + (x - mean) ** 2, 0) / (n - 1)
      : 0;
  const p95Idx = Math.min(n - 1, Math.ceil(0.95 * n) - 1);
  const round = (x: number): number => Math.round(x * 10000) / 10000;
  return {
    n,
    meanMs: round(mean),
    medianMs: round(median),
    stddevMs: round(Math.sqrt(variance)),
    minMs: round(sorted[0] as number),
    maxMs: round(sorted[n - 1] as number),
    p95Ms: round(sorted[p95Idx] as number),
  };
}

/** Time a synchronous function, returning elapsed milliseconds. */
export function timeSyncMs(fn: () => void): number {
  const t0 = process.hrtime.bigint();
  fn();
  const t1 = process.hrtime.bigint();
  return Number(t1 - t0) / 1e6;
}

/** Time an async function, returning elapsed milliseconds. */
export async function timeAsyncMs(fn: () => Promise<unknown>): Promise<number> {
  const t0 = process.hrtime.bigint();
  await fn();
  const t1 = process.hrtime.bigint();
  return Number(t1 - t0) / 1e6;
}
