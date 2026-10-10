import { MIN_DATE, MAX_DATE } from "./constants.ts";

/**
 * v4 date encoding (DECISIONS D-010): a UTC calendar date as the integer YYYYMMDD,
 * proleptic Gregorian. Every valid date is < 2^27.
 *
 * Age arithmetic is integer arithmetic on this encoding:
 *   "at least t years old on day D"  iff  birth + 10000 * t <= D
 * because adding 10000*t moves the year by t and keeps MMDD, and YYYYMMDD integers
 * order exactly like dates. A 29 February birth has no anniversary in a common year;
 * (Y+t)0229 lies between (Y+t)0228 and (Y+t)0301, so the person reaches age t on
 * 1 March in common years.
 */

export function isLeapYear(y: number): boolean {
  return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
}

export function daysInMonth(y: number, m: number): number {
  if (m === 2) return isLeapYear(y) ? 29 : 28;
  return [4, 6, 9, 11].includes(m) ? 30 : 31;
}

export interface Ymd {
  y: number;
  m: number;
  d: number;
}

export function splitYmd(date: number): Ymd {
  return { y: Math.floor(date / 10000), m: Math.floor(date / 100) % 100, d: date % 100 };
}

/** True iff `date` is an integer YYYYMMDD naming a real calendar day in range. */
export function isValidYmd(date: unknown): date is number {
  if (typeof date !== "number" || !Number.isSafeInteger(date)) return false;
  if (date < MIN_DATE || date > MAX_DATE) return false;
  const { y, m, d } = splitYmd(date);
  return m >= 1 && m <= 12 && d >= 1 && d <= daysInMonth(y, m);
}

export function assertValidYmd(date: unknown, what = "date"): number {
  if (!isValidYmd(date)) throw new Error(`${what} must be a valid YYYYMMDD date in [${MIN_DATE}, ${MAX_DATE}], got ${String(date)}`);
  return date;
}

/** The UTC calendar date of a unix time (seconds) as YYYYMMDD. */
export function utcDateOf(unixSec: number): number {
  const t = new Date(unixSec * 1000);
  return t.getUTCFullYear() * 10000 + (t.getUTCMonth() + 1) * 100 + t.getUTCDate();
}

/** Unix time (s) of 00:00:00 UTC on `date`. */
export function unixOfUtcDate(date: number): number {
  const { y, m, d } = splitYmd(assertValidYmd(date));
  return Date.UTC(y, m - 1, d) / 1000;
}

/** `date` plus `days` calendar days (may be negative). */
export function addDays(date: number, days: number): number {
  return utcDateOf(unixOfUtcDate(date) + days * 86400);
}

/** Completed years of age on `today` for someone born on `birth` (both YYYYMMDD). */
export function ageOn(birth: number, today: number): number {
  return Math.floor((today - birth) / 10000);
}

/** The circuit's predicate, in JS: 1 = AGE_GTE (age >= t), 2 = AGE_LT (age < t). */
export function predicateHolds(predicateCode: 1 | 2, birth: number, threshold: number, today: number): boolean {
  const reached = birth + 10000 * threshold <= today;
  return predicateCode === 1 ? reached : !reached;
}

/**
 * Dates an honest wallet accepts as "today" at wallet time `nowSec`: the UTC date of now,
 * plus the previous date during the first `skewSec` seconds after a UTC midnight (a
 * verifier whose clock is slightly behind). Never a future date: a verifier that could
 * ask for D and D+1 at the same moment would learn exact birth and expiry dates on
 * boundary days (B5 CIR-1, PRIV-5).
 */
export function acceptableTodays(nowSec: number, skewSec: number): number[] {
  const out = new Set<number>([utcDateOf(nowSec), utcDateOf(nowSec - skewSec)]);
  return [...out].sort((a, b) => a - b);
}
