import fs from "node:fs";
import { PINS_FILE } from "@pqid/common/paths";

export interface PinEntry {
  sha256: string;
  source?: string;
  note?: string;
}
export type Pins = Record<string, PinEntry>;

export function readPins(): Pins {
  if (!fs.existsSync(PINS_FILE)) return {};
  return JSON.parse(fs.readFileSync(PINS_FILE, "utf8")) as Pins;
}

export function writePins(pins: Pins): void {
  fs.writeFileSync(PINS_FILE, JSON.stringify(pins, null, 2) + "\n");
}

/**
 * Verify `actualSha256` against the pin for `name`. If no pin exists yet the
 * hash is recorded (trust-on-first-use; pins.json is committed so any later
 * drift aborts the run, per the security requirements).
 */
export function verifyOrPin(name: string, actualSha256: string, extra?: Omit<PinEntry, "sha256">): void {
  const pins = readPins();
  const existing = pins[name];
  if (existing) {
    if (existing.sha256 !== actualSha256) {
      throw new Error(
        `PIN MISMATCH for ${name}:\n  pinned ${existing.sha256}\n  actual ${actualSha256}\n` +
          `Aborting. If this change is intentional, delete the entry from setup/pins.json and re-run.`
      );
    }
    console.log(`[pins] ${name} OK (${actualSha256.slice(0, 16)}…)`);
  } else {
    pins[name] = { sha256: actualSha256, ...extra };
    writePins(pins);
    console.log(`[pins] ${name} PINNED (${actualSha256.slice(0, 16)}…)`);
  }
}
