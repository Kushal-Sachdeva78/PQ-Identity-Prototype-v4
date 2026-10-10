/**
 * Age claims for the SD-JWT baseline: one boolean `age_over_NN` per standard threshold
 * (STANDARD_THRESHOLDS, DECISIONS D-011, read from @pqid/v4/constants), fixed at issuance,
 * plus an optional `birthdate` claim ("YYYY-MM-DD").
 *
 * Age rule is the v4 one (docs/v4/V4_DESIGN.md section 1): with dates as YYYYMMDD integers,
 * "at least t years old on day D" iff birth + 10000*t <= D. A 29 February birth reaches
 * age t on 1 March in common years.
 *
 * Unlike the v4 circuit (which checks age against the verifier's date at presentation
 * time), these booleans are computed on the issuance date and do not change until the
 * credential is re-issued.
 */
import { STANDARD_THRESHOLDS } from "@pqid/v4/constants";

export const AGE_THRESHOLDS: readonly number[] = STANDARD_THRESHOLDS;

function daysInMonth(y: number, m: number): number {
  if (m === 2) return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28;
  return [4, 6, 9, 11].includes(m) ? 30 : 31;
}

export function isValidYmd(date: number): boolean {
  if (!Number.isSafeInteger(date) || date < 19000101 || date > 99991231) return false;
  const y = Math.floor(date / 10000);
  const m = Math.floor(date / 100) % 100;
  const d = date % 100;
  return m >= 1 && m <= 12 && d >= 1 && d <= daysInMonth(y, m);
}

/** UTC calendar date of a unix time (seconds) as YYYYMMDD. */
export function utcYmd(unixSec: number): number {
  const t = new Date(unixSec * 1000);
  return t.getUTCFullYear() * 10000 + (t.getUTCMonth() + 1) * 100 + t.getUTCDate();
}

/** "YYYY-MM-DD" for a YYYYMMDD integer. */
export function isoDate(date: number): string {
  const s = String(date);
  return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}`;
}

export function ageOver(birth: number, threshold: number, onDate: number): boolean {
  return birth + 10000 * threshold <= onDate;
}

/**
 * Claims an issuer would sign: `age_over_NN` for every standard threshold, evaluated on
 * `issuanceDate`, and (unless `includeBirthdate` is false) `birthdate`.
 */
export function ageClaims(birth: number, issuanceDate: number, includeBirthdate = true): Record<string, boolean | string> {
  if (!isValidYmd(birth)) throw new Error(`invalid birth date ${birth}`);
  if (!isValidYmd(issuanceDate)) throw new Error(`invalid issuance date ${issuanceDate}`);
  if (birth > issuanceDate) throw new Error("birth date after issuance date");
  const out: Record<string, boolean | string> = {};
  for (const t of AGE_THRESHOLDS) out[`age_over_${t}`] = ageOver(birth, t, issuanceDate);
  if (includeBirthdate) out.birthdate = isoDate(birth);
  return out;
}
