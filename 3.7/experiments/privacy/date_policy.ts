/** Experimental policy only; not installed in the shipped wallet. */
export const MIDNIGHT_BLACKOUT_SEC = 300;
export function statelessDateAllowed(nowSec: number, requestedDate: number): boolean {
  const t = new Date(nowSec * 1000);
  const today = t.getUTCFullYear() * 10000 + (t.getUTCMonth() + 1) * 100 + t.getUTCDate();
  const second = ((nowSec % 86400) + 86400) % 86400;
  return requestedDate === today && second >= MIDNIGHT_BLACKOUT_SEC && second < 86400 - MIDNIGHT_BLACKOUT_SEC;
}
