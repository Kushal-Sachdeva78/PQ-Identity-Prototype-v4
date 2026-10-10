import fs from "node:fs";

/**
 * Witness-file surgery for the "malicious prover" attack routes.
 *
 * The reference witness generator (the circuit's .wasm) refuses to emit a
 * witness that violates an `===` assertion, but an attacker is not bound to
 * use it: whatever witness they feed the Groth16 prover, the proof only
 * verifies if the witness satisfies the R1CS. These helpers take a witness
 * that is internally consistent for a statement the attacker CAN satisfy
 * (e.g. its own issuance root), swap one public wire for the value the
 * verifier will demand (the issuer's signed root), and let the suite check
 * that the R1CS then rejects it and the resulting proof does not verify.
 *
 * .wtns layout (iden3 binfile v2): "wtns" | u32 version | u32 nSections |
 * sections { u32 type | u64 size | data }; section 1 = { u32 n8 | prime |
 * u32 nWitness }, section 2 = nWitness little-endian n8-byte field elements.
 * Wire 0 is the constant 1; wires 1..nPublic are the public signals in order.
 */
export function patchWitnessWire(wtnsFile: string, index: number, value: bigint): void {
  const buf = fs.readFileSync(wtnsFile);
  if (buf.toString("ascii", 0, 4) !== "wtns") throw new Error("not a .wtns file");
  const nSections = buf.readUInt32LE(8);
  let pos = 12;
  let n8 = 0;
  let nWitness = 0;
  let dataStart = -1;
  for (let s = 0; s < nSections; s++) {
    const type = buf.readUInt32LE(pos);
    const size = Number(buf.readBigUInt64LE(pos + 4));
    const start = pos + 12;
    if (type === 1) {
      n8 = buf.readUInt32LE(start);
      nWitness = buf.readUInt32LE(start + 4 + n8);
    } else if (type === 2) {
      dataStart = start;
    }
    pos = start + size;
  }
  if (dataStart < 0 || n8 === 0) throw new Error("malformed .wtns (sections 1/2 missing)");
  if (index < 0 || index >= nWitness) throw new Error(`wire ${index} out of range (${nWitness})`);
  let v = value;
  const off = dataStart + index * n8;
  for (let i = 0; i < n8; i++) {
    buf[off + i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error("value does not fit in n8 bytes");
  fs.writeFileSync(wtnsFile, buf);
}

const quietLogger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  debug: () => undefined,
};

/** True iff the witness satisfies every R1CS constraint (snarkjs wtns check). */
export async function r1csSatisfied(r1csFile: string, wtnsFile: string): Promise<boolean> {
  const snarkjs = await import("snarkjs");
  return snarkjs.wtns.check(r1csFile, wtnsFile, quietLogger);
}
