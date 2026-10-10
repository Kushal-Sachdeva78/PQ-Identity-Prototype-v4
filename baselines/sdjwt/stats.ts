/**
 * Order statistics for the smoke measurement: median, quartiles (linear interpolation
 * between closest ranks, the "type 7" definition used by R and numpy's default), IQR.
 */
export interface Summary {
  n: number;
  median: number;
  q1: number;
  q3: number;
  iqr: number;
  min: number;
  max: number;
  mean: number;
}

export function quantile(sorted: readonly number[], q: number): number {
  if (sorted.length === 0) throw new Error("no samples");
  const pos = (sorted.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  const a = sorted[lo] as number;
  const b = sorted[hi] as number;
  return a + (b - a) * (pos - lo);
}

export function summarize(samples: readonly number[], digits = 4): Summary {
  const s = [...samples].sort((a, b) => a - b);
  const r = (x: number): number => Math.round(x * 10 ** digits) / 10 ** digits;
  const q1 = quantile(s, 0.25);
  const q3 = quantile(s, 0.75);
  return {
    n: s.length,
    median: r(quantile(s, 0.5)),
    q1: r(q1),
    q3: r(q3),
    iqr: r(q3 - q1),
    min: r(s[0] as number),
    max: r(s[s.length - 1] as number),
    mean: r(s.reduce((a, b) => a + b, 0) / s.length),
  };
}

/** Elapsed milliseconds of a synchronous call. */
export function timeMs(fn: () => void): number {
  const t0 = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - t0) / 1e6;
}
