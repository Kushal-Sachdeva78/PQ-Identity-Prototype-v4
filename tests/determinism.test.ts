import { describe, it, expect } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { R1CS_FILE, PTAU_FILE, ZKEY_FILE, VKEY_FILE } from "@pqid/common/paths";
import { sha256File } from "@pqid/common/hash";
import { readPins } from "../setup/pins.ts";
import { buildFixtureProofInput } from "../harness/fixture.ts";
import { computeWitness, proveSnarkjsOnWitness } from "@pqid/wallet/prove";

/**
 * Determinism requirements:
 *  - pinned artifacts have not drifted (abort-on-drift discipline);
 *  - identical inputs reproduce identical witnesses and verifying proofs;
 *  - the zkey is byte-stable across rebuilds (deterministic beacon setup).
 */
describe("pins", () => {
  it("ptau, zkey, and vkey match their pinned SHA-256", () => {
    const pins = readPins();
    expect(sha256File(PTAU_FILE)).toBe(pins["powersOfTau28_hez_final_15.ptau"]?.sha256);
    expect(sha256File(ZKEY_FILE)).toBe(pins["credential_auth_final.zkey"]?.sha256);
    expect(sha256File(VKEY_FILE)).toBe(pins["verification_key.json"]?.sha256);
  });
});

describe("witness/proof determinism", () => {
  it("identical inputs produce byte-identical witnesses and verifying proofs", async () => {
    const input = await buildFixtureProofInput();
    const w1 = await computeWitness(input);
    const w2 = await computeWitness(input);
    const h1 = sha256File(w1.wtnsFile);
    const h2 = sha256File(w2.wtnsFile);
    expect(h1).toBe(h2);

    const p1 = await proveSnarkjsOnWitness(w1.wtnsFile);
    const p2 = await proveSnarkjsOnWitness(w2.wtnsFile);
    fs.rmSync(w1.wtnsFile, { force: true });
    fs.rmSync(w2.wtnsFile, { force: true });

    // Groth16 proofs are randomized — bytes differ, but both must verify and
    // carry the same statement.
    expect(p1.publicSignals).toEqual(p2.publicSignals);
    const snarkjs = await import("snarkjs");
    const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, "utf8")) as unknown;
    expect(await snarkjs.groth16.verify(vkey, p1.publicSignals, p1.proof)).toBe(true);
    expect(await snarkjs.groth16.verify(vkey, p2.publicSignals, p2.proof)).toBe(true);
  });
});

describe("zkey rebuild stability (slow)", () => {
  it("re-running the beacon setup reproduces the pinned zkey byte-for-byte", async () => {
    const snarkjs = await import("snarkjs");
    const tmp0 = path.join(os.tmpdir(), `pqid-det-0000-${Date.now()}.zkey`);
    const tmpF = path.join(os.tmpdir(), `pqid-det-final-${Date.now()}.zkey`);
    await snarkjs.zKey.newZKey(R1CS_FILE, PTAU_FILE, tmp0);
    const zKeyAny = snarkjs.zKey as unknown as {
      beacon(o: string, n: string, name: string, hash: string, iter: number): Promise<unknown>;
    };
    await zKeyAny.beacon(
      tmp0,
      tmpF,
      "pqid dev beacon",
      "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
      10
    );
    const rebuilt = sha256File(tmpF);
    fs.rmSync(tmp0, { force: true });
    fs.rmSync(tmpF, { force: true });
    expect(rebuilt).toBe(readPins()["credential_auth_final.zkey"]?.sha256);
  }, 600_000);
});
