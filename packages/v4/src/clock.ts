/**
 * Injectable clock (unix seconds). Every v4 party reads time through a Clock so the
 * suites can move time forward (frozen-anchor route, stale dates) together with Anvil's
 * block time. Real deployments use SystemClock.
 */
export interface Clock {
  nowSec(): number;
}

export const SystemClock: Clock = { nowSec: () => Math.floor(Date.now() / 1000) };

/** A clock that starts at a fixed time and only moves when told to. */
export class ManualClock implements Clock {
  constructor(private t: number) {}
  nowSec(): number {
    return this.t;
  }
  set(t: number): void {
    this.t = t;
  }
  advance(seconds: number): void {
    this.t += seconds;
  }
}

/** A clock that is some seconds ahead of (or behind) another clock. */
export class OffsetClock implements Clock {
  constructor(
    private readonly base: Clock,
    private readonly offsetSec: number
  ) {}
  nowSec(): number {
    return this.base.nowSec() + this.offsetSec;
  }
}
