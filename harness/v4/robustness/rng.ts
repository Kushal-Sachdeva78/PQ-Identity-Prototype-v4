/**
 * Seeded generator for the robustness row (DECISIONS D-034: an in-repo seeded generator, no
 * property-testing package). Deterministic on every platform: 32-bit integer arithmetic only
 * (Math.imul, >>> 0), no Math.random, no time, no crypto randomness.
 *
 * Seeds:
 *  - master seeds come from harness/v4/lib/seeds.ts (robustness.fuzz 20261022, robustness.load
 *    20261021, robustness.circuitFuzz 20261023, robustness.forgeFuzz 20261024);
 *  - a target's seed is (master XOR crc32(targetId)) >>> 0;
 *  - case i of a target draws from its own stream, seeded by caseSeed(targetSeed, i), so any
 *    single case can be regenerated from (target, seed, i) without replaying the earlier ones.
 *
 * PRNG: sfc32 (Chris Doty-Humphrey's small fast chaotic generator, 128-bit state), its state
 * filled by splitmix32 from the 32-bit seed. Not cryptographic; enough for test inputs.
 */

/** CRC-32 (IEEE 802.3, reflected 0xEDB88320) of the UTF-8 bytes of `s`; same value as Python's zlib.crc32. */
export function crc32(s: string | Uint8Array): number {
  const bytes = typeof s === "string" ? new TextEncoder().encode(s) : s;
  let c = 0xffffffff;
  for (const b of bytes) {
    c ^= b;
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
  }
  return (c ^ 0xffffffff) >>> 0;
}

/** splitmix32 step: returns [next state, output]. */
function splitmix32(state: number): [number, number] {
  const s = (state + 0x9e3779b9) >>> 0;
  let z = s;
  z = Math.imul(z ^ (z >>> 16), 0x85ebca6b) >>> 0;
  z = Math.imul(z ^ (z >>> 13), 0xc2b2ae35) >>> 0;
  z = (z ^ (z >>> 16)) >>> 0;
  return [s, z];
}

/** Mix two 32-bit values into one seed (order matters). */
export function mix32(a: number, b: number): number {
  let [s, x] = splitmix32((a >>> 0) ^ Math.imul(b >>> 0, 0x9e3779b1));
  [s, x] = splitmix32(s ^ x);
  return (x ^ (b >>> 0)) >>> 0;
}

/** Seed of one target: (master XOR crc32(targetId)) >>> 0. */
export function targetSeed(master: number, targetId: string): number {
  return ((master >>> 0) ^ crc32(targetId)) >>> 0;
}

/** Seed of case `index` of a target (independent stream per case). */
export function caseSeed(tSeed: number, index: number): number {
  if (!Number.isSafeInteger(index) || index < 0) throw new Error("case index must be a non-negative integer");
  return mix32(mix32(tSeed, index >>> 0), Math.floor(index / 2 ** 32));
}

export class Rng {
  private a: number;
  private b: number;
  private c: number;
  private d: number;
  /** Number of 32-bit outputs drawn so far (for diagnostics). */
  draws = 0;

  constructor(readonly seed: number) {
    let s = seed >>> 0;
    const out: number[] = [];
    for (let i = 0; i < 4; i++) {
      const [ns, z] = splitmix32(s);
      s = ns;
      out.push(z);
    }
    [this.a, this.b, this.c, this.d] = out as [number, number, number, number];
    for (let i = 0; i < 12; i++) this.u32(); // warm the state
    this.draws = 0;
  }

  /** Uniform 32-bit unsigned integer. */
  u32(): number {
    this.draws++;
    this.a >>>= 0;
    this.b >>>= 0;
    this.c >>>= 0;
    this.d >>>= 0;
    const t = (((this.a + this.b) >>> 0) + this.d) >>> 0;
    this.d = (this.d + 1) >>> 0;
    this.a = this.b ^ (this.b >>> 9);
    this.b = (this.c + (this.c << 3)) >>> 0;
    this.c = ((this.c << 21) | (this.c >>> 11)) >>> 0;
    this.c = (this.c + t) >>> 0;
    return t >>> 0;
  }

  /** Uniform float in [0, 1) with 32 bits of resolution. */
  float(): number {
    return this.u32() / 4294967296;
  }

  /** Uniform integer in [lo, hi] (inclusive); exact for spans up to 2^32 (rejection sampling). */
  int(lo: number, hi: number): number {
    if (!Number.isSafeInteger(lo) || !Number.isSafeInteger(hi) || hi < lo) throw new Error(`bad range [${lo}, ${hi}]`);
    const span = hi - lo + 1;
    if (span <= 4294967296) {
      if (span === 4294967296) return lo + this.u32();
      const lim = 4294967296 - (4294967296 % span);
      for (;;) {
        const x = this.u32();
        if (x < lim) return lo + (x % span);
      }
    }
    // wider spans: combine two draws (53 bits), then rejection on the bigint path
    return lo + Number(this.bigBelow(BigInt(span)));
  }

  bool(p = 0.5): boolean {
    return this.float() < p;
  }

  pick<T>(xs: readonly T[]): T {
    if (xs.length === 0) throw new Error("pick from an empty list");
    return xs[this.int(0, xs.length - 1)] as T;
  }

  /** Weighted choice: entries [weight, value]; weights are non-negative numbers. */
  weighted<T>(entries: ReadonlyArray<readonly [number, T]>): T {
    const total = entries.reduce((s, [w]) => s + w, 0);
    if (!(total > 0)) throw new Error("weights sum to zero");
    let x = this.float() * total;
    for (const [w, v] of entries) {
      if (x < w) return v;
      x -= w;
    }
    return entries[entries.length - 1]![1];
  }

  bytes(n: number): Buffer {
    const out = Buffer.alloc(n);
    for (let i = 0; i < n; i += 4) {
      const x = this.u32();
      for (let k = 0; k < 4 && i + k < n; k++) out[i + k] = (x >>> (8 * k)) & 0xff;
    }
    return out;
  }

  /** Uniform bigint in [0, 2^bits). */
  bigBits(bits: number): bigint {
    if (!Number.isInteger(bits) || bits < 0) throw new Error("bits must be a non-negative integer");
    let v = 0n;
    let got = 0;
    while (got < bits) {
      v = (v << 32n) | BigInt(this.u32());
      got += 32;
    }
    return v >> BigInt(got - bits);
  }

  /** Uniform bigint in [0, n) (rejection sampling). */
  bigBelow(n: bigint): bigint {
    if (n <= 0n) throw new Error("bigBelow needs n > 0");
    const bits = n.toString(2).length;
    for (;;) {
      const x = this.bigBits(bits);
      if (x < n) return x;
    }
  }

  /** Fisher-Yates in place (from the end). */
  shuffle<T>(xs: T[]): T[] {
    for (let i = xs.length - 1; i > 0; i--) {
      const j = this.int(0, i);
      const t = xs[i] as T;
      xs[i] = xs[j] as T;
      xs[j] = t;
    }
    return xs;
  }

  /** Independent child stream (does not advance this stream). */
  fork(label: string | number): Rng {
    const l = typeof label === "number" ? label >>> 0 : crc32(label);
    return new Rng(mix32(this.seed ^ 0x5bd1e995, l));
  }

  /** A small integer biased towards 0 (geometric-like), capped at `max`. */
  small(max: number, p = 0.5): number {
    let n = 0;
    while (n < max && this.bool(p)) n++;
    return n;
  }
}

/** Rng for case `index` of target `targetId` under `master`. */
export function caseRng(master: number, targetId: string, index: number): Rng {
  return new Rng(caseSeed(targetSeed(master, targetId), index));
}
