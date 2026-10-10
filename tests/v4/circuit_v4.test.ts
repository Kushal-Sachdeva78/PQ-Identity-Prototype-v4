import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { sha3_256, sha256File } from "@pqid/common/hash";
import {
  getPoseidon,
  poseidonBig,
  issuerKeyHash,
  verifierDomainTag,
  credTypeField,
  credentialLeafV4,
  policyHashV4,
  stmtCodeV4,
  revKeyFromCredId,
  imtLeafHash,
  fieldFrom31Bytes,
  type PredicateName,
} from "@pqid/v4/encoding";
import { DEFAULT_TYPE_ID, IMT_MAX, ISSUANCE_DEPTH, REV_DEPTH } from "@pqid/v4/constants";
import {
  CIRCUIT_V4_SRC,
  CIRCUIT_V4_LIB,
  CIRCUIT_INFO_V4,
  R1CS_V4,
  WASM_V4,
  SYM_V4,
  ZKEY_V4,
  VKEY_V4,
  SOL_V4,
  TRANSCRIPT_V4,
  PINS_V4,
  KEY_LABEL_V4,
  circomBinary,
  rapidsnarkBinary,
} from "@pqid/v4/paths";
import {
  buildCircuitInputV4,
  publicSignalsFromInputsV4,
  publicSignalsOfInputV4,
  PUBLIC_SIGNAL_ORDER_V4,
  type CircuitInputV4,
  type PublicInputsV4,
  type PrivateInputsV4,
  type RevLowLeafWitnessV4,
} from "@pqid/v4/witness";
import { proveV4, verifyV4, loadVkeyV4, computeWitnessV4, RAPIDSNARK_UNAVAILABLE } from "@pqid/v4/prove";

/**
 * Circuit v4 (circuits/credential_auth_v4.circom) with the v4 DEV key.
 *
 * The honest witness is built by hand (no issuer/imt packages): the credential leaf sits
 * at index 0 of the depth-32 issuance tree with zero-subtree siblings, and the revocation
 * IMT holds only the sentinel (0, 2^251) at index 0, which brackets every revKey.
 *
 * One Groth16 prove; everything else is witness level. Each false statement is rejected
 * twice: (a) the reference witness generator (the circuit's wasm) refuses it, and (b) an
 * attacker witness that satisfies every other relation fails the REAL R1CS (snarkjs wtns
 * check). The attacker witness comes from a twin of the circuit with every `// @check`
 * line removed, compiled at --O0 into a temp dir; its values are mapped into the real
 * --O2 wire layout by signal name (.sym files). The mapping is validated first: for true
 * statements it reproduces the reference witness exactly and passes the R1CS check.
 */

const PK_ISSUER = Buffer.alloc(1312, 0xa7); // stand-in bytes for an ML-DSA-44 public key
const HOLDER_SECRET = 0x1d2c3b4a5968778695a4b3c2d1e0f0e1d2c3b4a5968778695a4b3c2d1e0f0en;
const VERIFIER_ID = "pqid:verifier:test-v4";
const TODAY = 20260927;
const FROM = 20260927;
const TO = 20260928;
const ADULT_BIRTH = 20000315;
const EXPIRY = 20261226;

type Poseidon = Awaited<ReturnType<typeof getPoseidon>>;
let poseidon: Poseidon;
let zeros: bigint[];
let credId: Buffer;
let ikh: bigint;
let defaultType: bigint;
let domainTag: bigint;
let nonce: bigint;

/** Root of a binary Poseidon Merkle path (JS twin of MerkleRootV4). */
function rootFromPath(leaf: bigint, index: bigint, pathElements: readonly string[]): bigint {
  let cur = leaf;
  let i = index;
  for (const s of pathElements) {
    const sib = BigInt(s);
    cur = (i & 1n) === 0n ? poseidonBig(poseidon, [cur, sib]) : poseidonBig(poseidon, [sib, cur]);
    i >>= 1n;
  }
  return cur;
}

function zeroPath(depth: number): string[] {
  return zeros.slice(0, depth).map((z) => z.toString());
}

/** IMT holding only the sentinel (0, IMT_MAX) at index 0. */
function sentinelRev(): RevLowLeafWitnessV4 & { root: string } {
  const lowPath = zeroPath(REV_DEPTH);
  const root = rootFromPath(imtLeafHash(poseidon, 0n, IMT_MAX), 0n, lowPath);
  return { lowIndex: "0", lowValue: "0", lowNext: IMT_MAX.toString(), lowPath, root: root.toString() };
}

/**
 * IMT after revoking `key`: index 0 = (0, key), index 1 = (key, IMT_MAX). Returns the
 * opening of either leaf; neither brackets `key` strictly.
 */
function revokedRev(key: bigint, which: 0 | 1): RevLowLeafWitnessV4 & { root: string } {
  const l0 = imtLeafHash(poseidon, 0n, key);
  const l1 = imtLeafHash(poseidon, key, IMT_MAX);
  const upper = zeroPath(REV_DEPTH).slice(1);
  const lowPath = [(which === 0 ? l1 : l0).toString(), ...upper];
  const root = rootFromPath(which === 0 ? l0 : l1, BigInt(which), lowPath);
  return which === 0
    ? { lowIndex: "0", lowValue: "0", lowNext: key.toString(), lowPath, root: root.toString() }
    : { lowIndex: "1", lowValue: key.toString(), lowNext: IMT_MAX.toString(), lowPath, root: root.toString() };
}

interface Opts {
  birthDate: number;
  expiryDate: number;
  credType: bigint;
  requiredType: bigint;
  predicate: PredicateName;
  threshold: number;
  today: number;
  from: number;
  to: number;
  rev: RevLowLeafWitnessV4 & { root: string };
  /** Replace the issuance root the leaf opens to (a false public issRoot). */
  issRoot: bigint;
}

interface Fixture {
  pub: PublicInputsV4;
  priv: PrivateInputsV4;
  input: CircuitInputV4;
}

/**
 * A witness that is consistent everywhere (leaf, issuance root, IMT root, policyHash,
 * stmtCode) for the given parameters, whether or not the statement is true.
 */
function fixture(o: Partial<Opts> = {}): Fixture {
  const birthDate = o.birthDate ?? ADULT_BIRTH;
  const expiryDate = o.expiryDate ?? EXPIRY;
  const credType = o.credType ?? defaultType;
  const requiredType = o.requiredType ?? defaultType;
  const predicate = o.predicate ?? "age_gte";
  const threshold = o.threshold ?? 18;
  const today = o.today ?? TODAY;
  const rev = o.rev ?? sentinelRev();
  const leaf = credentialLeafV4(poseidon, {
    issuerKeyHash: ikh,
    credId,
    holderCommit: poseidonBig(poseidon, [HOLDER_SECRET]),
    birthDate,
    expiryDate,
    credType,
  });
  const issPathElements = zeroPath(ISSUANCE_DEPTH);
  const issRoot = rootFromPath(leaf, 0n, issPathElements);
  const pub: PublicInputsV4 = {
    issuerKeyHash: ikh,
    revRoot: BigInt(rev.root),
    policyHash: policyHashV4(poseidon, { predicate, threshold, today, requiredType }),
    nonce,
    stmtCode: stmtCodeV4(poseidon, domainTag),
    issRoot: o.issRoot ?? issRoot,
    epochFromDate: o.from ?? FROM,
    epochToDate: o.to ?? TO,
  };
  const priv: PrivateInputsV4 = {
    credId,
    holderSecret: HOLDER_SECRET,
    birthDate,
    expiryDate,
    credType,
    predicate,
    threshold,
    today,
    requiredType,
    domainTag,
    issLeafIndex: "0",
    issPathElements,
    rev,
  };
  return { pub, priv, input: buildCircuitInputV4(pub, priv) };
}

// ------------------------------------------------------------------ witness I/O
const quietLogger = { info: () => undefined, warn: () => undefined, error: () => undefined, debug: () => undefined };

interface WtnsLayout {
  n8: number;
  nWitness: number;
  dataStart: number;
}

function wtnsLayout(buf: Uint8Array): WtnsLayout {
  const b = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength);
  if (b.toString("ascii", 0, 4) !== "wtns") throw new Error("not a .wtns file");
  const nSections = b.readUInt32LE(8);
  let pos = 12;
  let n8 = 0;
  let nWitness = 0;
  let dataStart = -1;
  for (let s = 0; s < nSections; s++) {
    const type = b.readUInt32LE(pos);
    const size = Number(b.readBigUInt64LE(pos + 4));
    const start = pos + 12;
    if (type === 1) {
      n8 = b.readUInt32LE(start);
      nWitness = b.readUInt32LE(start + 4 + n8);
    } else if (type === 2) {
      dataStart = start;
    }
    pos = start + size;
  }
  if (dataStart < 0 || n8 === 0) throw new Error("malformed .wtns");
  return { n8, nWitness, dataStart };
}

function wtnsValues(buf: Uint8Array): bigint[] {
  const { n8, nWitness, dataStart } = wtnsLayout(buf);
  const out: bigint[] = new Array<bigint>(nWitness);
  for (let w = 0; w < nWitness; w++) {
    let v = 0n;
    const off = dataStart + w * n8;
    for (let i = n8 - 1; i >= 0; i--) v = (v << 8n) | BigInt(buf[off + i] as number);
    out[w] = v;
  }
  return out;
}

/** name -> witness index for every signal that is a wire (.sym: label,wire,component,name). */
function readSym(file: string): Map<string, number> {
  const out = new Map<string, number>();
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (!line) continue;
    const a = line.indexOf(",");
    const b = line.indexOf(",", a + 1);
    const c = line.indexOf(",", b + 1);
    const wire = Number(line.slice(a + 1, b));
    if (wire >= 0) out.set(line.slice(c + 1).trim(), wire);
  }
  return out;
}

function tmpFile(ext: string): string {
  return path.join(os.tmpdir(), `pqid-v4-test-${Date.now()}-${randomBytes(4).toString("hex")}${ext}`);
}

/** Reference witness (the circuit's own wasm) into a temp file. Caller deletes it. */
async function referenceWitness(input: CircuitInputV4): Promise<string> {
  const { wtnsFile } = await computeWitnessV4(input);
  return wtnsFile;
}

async function r1csSatisfied(wtnsFile: string): Promise<boolean> {
  const snarkjs = await import("snarkjs");
  return snarkjs.wtns.check(R1CS_V4, wtnsFile, quietLogger);
}

// ------------------------------------------------------------------ attacker generator
let twinDir = "";
let twinWasm = "";
let twinSym = new Map<string, number>();
let realSym = new Map<string, number>();
let removedChecks = 0;
let template: Uint8Array = new Uint8Array();

/** The circuit with every `// @check` line dropped and includes made absolute. */
function twinSource(): { src: string; removed: number } {
  const src = fs.readFileSync(CIRCUIT_V4_SRC, "utf8");
  const dir = path.dirname(CIRCUIT_V4_SRC);
  let removed = 0;
  const lines = src.split(/\r?\n/).map((line) => {
    if (/\/\/\s*@check\s*$/.test(line)) {
      removed++;
      return "// [twin] check removed";
    }
    const inc = /^(\s*include\s+")([^"]+)(";.*)$/.exec(line);
    if (inc) {
      const abs = path.resolve(dir, inc[2] as string).split(path.sep).join("/");
      return `${inc[1]}${abs}${inc[3]}`;
    }
    return line;
  });
  return { src: lines.join("\n"), removed };
}

/**
 * Attacker witness for `input` in the REAL circuit's wire layout: every wire holds the
 * value the honest computation gives it, but no check was enforced while computing.
 */
async function attackerWitness(input: CircuitInputV4): Promise<string> {
  const snarkjs = await import("snarkjs");
  const mem: { type: "mem"; data?: Uint8Array } = { type: "mem" };
  await snarkjs.wtns.calculate(input, twinWasm, mem);
  if (!mem.data) throw new Error("twin produced no witness");
  const twinVals = wtnsValues(mem.data);
  const { n8, nWitness, dataStart } = wtnsLayout(template);
  const vals: Array<bigint | undefined> = new Array<bigint | undefined>(nWitness);
  vals[0] = 1n;
  for (const [name, w] of realSym) {
    const tw = twinSym.get(name);
    if (tw === undefined) throw new Error(`twin has no signal ${name}`);
    vals[w] = twinVals[tw];
  }
  const out = Buffer.from(template);
  for (let w = 0; w < nWitness; w++) {
    let v = vals[w];
    if (v === undefined) throw new Error(`wire ${w} unmapped`);
    const off = dataStart + w * n8;
    for (let i = 0; i < n8; i++) {
      out[off + i] = Number(v & 0xffn);
      v >>= 8n;
    }
  }
  const file = tmpFile(".wtns");
  fs.writeFileSync(file, out);
  return file;
}

async function withFile<T>(file: string, f: (file: string) => Promise<T>): Promise<T> {
  try {
    return await f(file);
  } finally {
    fs.rmSync(file, { force: true });
  }
}

/** 1-based line of the unique `// @check` line of the circuit that contains `snippet`. */
function checkLine(snippet: string): number {
  const lines = fs.readFileSync(CIRCUIT_V4_SRC, "utf8").split(/\r?\n/);
  const hits = lines.flatMap((l, i) => (l.includes(snippet) && /\/\/\s*@check\s*$/.test(l) ? [i + 1] : []));
  if (hits.length !== 1) throw new Error(`expected one @check line containing "${snippet}", found ${hits.length}`);
  return hits[0] as number;
}

/**
 * (a) the reference generator refuses, at exactly the named check; (b) the attacker
 * witness claims the verifier's public statement and fails the real R1CS.
 */
async function expectRejectedTwice(fx: Fixture, failingCheck: string): Promise<void> {
  const line = checkLine(failingCheck);
  await expect(referenceWitness(fx.input)).rejects.toThrow(
    new RegExp(String.raw`Assert Failed[\s\S]*CredentialAuthV4\w* line: ${line}\b`)
  );
  const file = await attackerWitness(fx.input);
  await withFile(file, async (f) => {
    const vals = wtnsValues(fs.readFileSync(f));
    // the attacker witness really claims the verifier's public statement...
    expect(vals.slice(1, 1 + PUBLIC_SIGNAL_ORDER_V4.length).map(String)).toEqual(publicSignalsFromInputsV4(fx.pub));
    // ...and the real R1CS rejects it
    expect(await r1csSatisfied(f)).toBe(false);
  });
}

/** True statement: reference witness passes the R1CS and the attacker mapping reproduces it. */
async function expectAcceptedBoth(fx: Fixture): Promise<void> {
  const ref = await referenceWitness(fx.input);
  await withFile(ref, async (r) => {
    expect(await r1csSatisfied(r)).toBe(true);
    const att = await attackerWitness(fx.input);
    await withFile(att, async (a) => {
      expect(fs.readFileSync(a).equals(fs.readFileSync(r))).toBe(true);
    });
  });
}

beforeAll(async () => {
  for (const f of [R1CS_V4, WASM_V4, SYM_V4, ZKEY_V4, VKEY_V4]) {
    if (!fs.existsSync(f)) throw new Error(`${f} missing: run setup/build_circuit_v4.ts and setup/groth16_setup_v4.ts --rekey`);
  }
  poseidon = await getPoseidon();
  zeros = [0n];
  for (let l = 0; l < ISSUANCE_DEPTH; l++) {
    const z = zeros[l] as bigint;
    zeros.push(poseidonBig(poseidon, [z, z]));
  }
  credId = sha3_256(Buffer.from("pqid-v4-fixture-subject", "utf8"));
  ikh = issuerKeyHash(poseidon, PK_ISSUER);
  defaultType = credTypeField(poseidon, DEFAULT_TYPE_ID);
  domainTag = verifierDomainTag(poseidon, VERIFIER_ID);
  nonce = fieldFrom31Bytes(sha3_256(Buffer.from("pqid-v4-fixture-nonce", "utf8")).subarray(0, 31));

  // attacker generator: compile the check-free twin at --O0 (temp dir)
  twinDir = path.join(os.tmpdir(), `pqid-v4-twin-${randomBytes(4).toString("hex")}`);
  fs.mkdirSync(twinDir, { recursive: true });
  const twin = twinSource();
  removedChecks = twin.removed;
  const twinMain = path.join(twinDir, "credential_auth_v4.circom");
  fs.writeFileSync(twinMain, twin.src);
  const res = spawnSync(circomBinary(), [twinMain, "--O0", "--wasm", "--sym", "-o", twinDir], { encoding: "utf8" });
  if (res.status !== 0) throw new Error(`twin compile failed: ${res.stdout} ${res.stderr}`);
  twinWasm = path.join(twinDir, "credential_auth_v4_js", "credential_auth_v4.wasm");
  twinSym = readSym(path.join(twinDir, "credential_auth_v4.sym"));
  realSym = readSym(SYM_V4);

  // template .wtns (header of the real circuit) from the honest reference witness
  const honest = await referenceWitness(fixture().input);
  template = new Uint8Array(fs.readFileSync(honest));
  fs.rmSync(honest, { force: true });
});

afterAll(() => {
  if (twinDir) fs.rmSync(twinDir, { recursive: true, force: true });
});

describe("v4 artifacts (dev key)", () => {
  it("pins_v4.json matches every artifact and labels each one dev", () => {
    const pins = JSON.parse(fs.readFileSync(PINS_V4, "utf8")) as Record<string, { sha256: string; label: string; path: string }>;
    const files = [R1CS_V4, WASM_V4, ZKEY_V4, VKEY_V4, SOL_V4, TRANSCRIPT_V4];
    expect(Object.keys(pins)).toHaveLength(files.length);
    for (const f of files) {
      const entry = Object.values(pins).find((p) => path.resolve(path.dirname(PINS_V4), "..", p.path) === path.resolve(f));
      expect(entry, `pin for ${f}`).toBeDefined();
      expect(entry?.sha256).toBe(sha256File(f));
      expect(entry?.label).toBe(KEY_LABEL_V4);
    }
    expect(KEY_LABEL_V4).toBe("dev");
    for (const f of [ZKEY_V4, VKEY_V4, SOL_V4, TRANSCRIPT_V4]) expect(path.basename(f)).toMatch(/_dev\./);
    const t = JSON.parse(fs.readFileSync(TRANSCRIPT_V4, "utf8")) as { schema: string; key_label: string; phase2: Array<{ step: string }> };
    expect(t.schema).toBe("pqid/v4-dev-setup-transcript/v1");
    expect(t.key_label).toBe("dev");
    expect(t.phase2.map((p) => p.step)).toEqual(["contribution", "beacon"]);
  });

  it("the build (and so the dev key) comes from the current circuit sources", () => {
    const info = JSON.parse(fs.readFileSync(CIRCUIT_INFO_V4, "utf8")) as {
      r1csSha256: string;
      nPubInputs: number;
      sourceSha256: Record<string, string>;
    };
    expect(info.r1csSha256).toBe(sha256File(R1CS_V4));
    expect(info.nPubInputs).toBe(8);
    expect(info.sourceSha256["circuits/credential_auth_v4.circom"]).toBe(sha256File(CIRCUIT_V4_SRC));
    expect(info.sourceSha256["circuits/v4/lib_v4.circom"]).toBe(sha256File(CIRCUIT_V4_LIB));
  });
});

describe("witness assembly", () => {
  it("public signal order has the eight V4_DESIGN names", () => {
    expect([...PUBLIC_SIGNAL_ORDER_V4]).toEqual([
      "issuerKeyHash",
      "revRoot",
      "policyHash",
      "nonce",
      "stmtCode",
      "issRoot",
      "epochFromDate",
      "epochToDate",
    ]);
    const fx = fixture();
    expect(publicSignalsOfInputV4(fx.input)).toEqual(publicSignalsFromInputsV4(fx.pub));
  });

  it("rejects malformed shapes (path lengths, non-canonical decimals, non-field values)", () => {
    const fx = fixture();
    expect(() => buildCircuitInputV4(fx.pub, { ...fx.priv, issPathElements: fx.priv.issPathElements.slice(1) })).toThrow(/32 elements/);
    expect(() => buildCircuitInputV4(fx.pub, { ...fx.priv, rev: { ...fx.priv.rev, lowPath: [] } })).toThrow(/30 elements/);
    expect(() => buildCircuitInputV4(fx.pub, { ...fx.priv, issLeafIndex: "007" })).toThrow(/canonical/);
    expect(() => buildCircuitInputV4({ ...fx.pub, nonce: -1n }, fx.priv)).toThrow(/field element/);
    expect(() => buildCircuitInputV4(fx.pub, { ...fx.priv, credId: new Uint8Array(31) })).toThrow(/32 bytes/);
  });

  it("the fixture revKey is inside (0, 2^251), so the sentinel brackets it", () => {
    const k = revKeyFromCredId(credId);
    expect(k > 0n && k < IMT_MAX).toBe(true);
  });
});

describe("credential_auth_v4 with the dev key", () => {
  it("honest witness proves and verifies; eight public signals in order", async () => {
    const fx = fixture();
    const vkey = loadVkeyV4();
    const r = await proveV4(fx.input, "snarkjs");
    expect(r.keyLabel).toBe("dev");
    expect(r.zkeySha256).toBe(sha256File(ZKEY_V4));
    expect(r.publicSignals).toHaveLength(8);
    expect(r.publicSignals).toEqual(publicSignalsFromInputsV4(fx.pub));
    expect(r.timings.witnessMs).toBeGreaterThan(0);
    expect(r.timings.proveMs).toBeGreaterThan(0);
    expect(await verifyV4(vkey, r.publicSignals, r.proof)).toBe(true);
    // the same proof does not verify for another nonce, another date window, or a short list
    const wrongNonce = [...r.publicSignals];
    wrongNonce[3] = (nonce + 1n).toString();
    expect(await verifyV4(vkey, wrongNonce, r.proof)).toBe(false);
    const wrongTo = [...r.publicSignals];
    wrongTo[7] = "20261231";
    expect(await verifyV4(vkey, wrongTo, r.proof)).toBe(false);
    expect(await verifyV4(vkey, r.publicSignals.slice(0, 7), r.proof)).toBe(false);
  });

  it.skipIf(rapidsnarkBinary() !== null)("rapidsnark backend reports unavailable on this host (no wsl.exe fallback)", async () => {
    await expect(proveV4(fixture().input, "rapidsnark")).rejects.toThrow(RAPIDSNARK_UNAVAILABLE);
  });
});

describe("attacker generator (check-free twin mapped by signal name)", () => {
  it("removed every @check line of the circuit", () => {
    const src = fs.readFileSync(CIRCUIT_V4_SRC, "utf8");
    const codeAsserts = src.split(/\r?\n/).filter((l) => (l.split("//")[0] ?? "").includes("===")).length;
    expect(removedChecks).toBeGreaterThan(0);
    expect(removedChecks).toBe(codeAsserts);
  });

  it("reproduces the reference witness byte for byte on true statements, which pass the R1CS", async () => {
    await expectAcceptedBoth(fixture()); // adult, age >= 18
    await expectAcceptedBoth(fixture({ birthDate: 20080927 })); // 18th birthday is today
    await expectAcceptedBoth(fixture({ birthDate: 20080928, predicate: "age_lt" })); // one day short of 18
    await expectAcceptedBoth(fixture({ expiryDate: TODAY })); // last valid day
    await expectAcceptedBoth(fixture({ today: TO })); // last day of the window
  });
});

describe("R1CS-level rejections (reference generator AND real R1CS)", () => {
  const AGE_CHECK = "reached.out === 2 - predicateCode";

  it("under-age GTE claim (one day before the 18th birthday)", async () => {
    await expectRejectedTwice(fixture({ birthDate: 20080928, predicate: "age_gte", threshold: 18 }), AGE_CHECK);
  });

  it("over-age LT claim (adult claiming age < 18)", async () => {
    await expectRejectedTwice(fixture({ birthDate: ADULT_BIRTH, predicate: "age_lt", threshold: 18 }), AGE_CHECK);
  });

  it("expired credential (expiry the day before today)", async () => {
    await expectRejectedTwice(fixture({ expiryDate: 20260926 }), "notExpired.out === 1");
  });

  it("wrong credential type", async () => {
    await expectRejectedTwice(
      fixture({ credType: credTypeField(poseidon, "pqid:type:other-credential:v1") }),
      "credType === requiredType"
    );
  });

  it("non-standard threshold 17", async () => {
    await expectRejectedTwice(fixture({ threshold: 17 }), "thrAcc[6] === 0");
  });

  it("today outside the epoch window (after the end and before the start)", async () => {
    await expectRejectedTwice(fixture({ today: 20260929 }), "beforeTo.out === 1");
    await expectRejectedTwice(fixture({ today: 20260926 }), "afterFrom.out === 1");
  });

  it("low leaf not bracketing the key (revoked credential, both neighbours)", async () => {
    const key = revKeyFromCredId(credId);
    await expectRejectedTwice(fixture({ rev: revokedRev(key, 0) }), "revBracket.aboveOk === 1");
    await expectRejectedTwice(fixture({ rev: revokedRev(key, 1) }), "revBracket.belowOk === 1");
  });

  it("wrong issuance root (a real root that does not hold this leaf)", async () => {
    const other = credentialLeafV4(poseidon, {
      issuerKeyHash: ikh,
      credId,
      holderCommit: poseidonBig(poseidon, [HOLDER_SECRET]),
      birthDate: 19500101,
      expiryDate: EXPIRY,
      credType: defaultType,
    });
    const otherRoot = rootFromPath(other, 0n, zeroPath(ISSUANCE_DEPTH));
    await expectRejectedTwice(fixture({ issRoot: otherRoot }), "iss.root === issRoot");
  });
});

// ------------------------------------------------------------------ hint wires (B5 CIR-6)
// The attacker generator recomputes every hint (bit decompositions, comparator bits) with
// circom's own code, so circuit routes cannot express a witness that keeps the honest
// inputs but changes one hint. These tests edit hint wires of an honest witness directly
// and evaluate the real --O2 R1CS: every single-bit edit must violate a constraint of the
// gadget that owns the wire.
describe("hint wires: direct single-wire edits of an honest witness (real R1CS)", () => {
  const GADGETS: Array<{ prefix: string; group: string }> = [
    { prefix: "main.iss.idxBits", group: "G04_issuance_membership" },
    { prefix: "main.revMember.mr.idxBits", group: "G06_rev_low_membership" },
    { prefix: "main.revBracket.below.n2b", group: "G07_rev_bracket" },
    { prefix: "main.revBracket.above.n2b", group: "G07_rev_bracket" },
    { prefix: "main.hiBits", group: "G05_revkey" },
    { prefix: "main.loBits", group: "G05_revkey" },
    { prefix: "main.reached.lt.n2b", group: "G12_age" },
    { prefix: "main.notExpired.lt.n2b", group: "G13_expiry" },
    { prefix: "main.afterFrom.lt.n2b", group: "G15_epoch_window" },
    { prefix: "main.beforeTo.lt.n2b", group: "G15_epoch_window" },
  ];

  it("every sampled bit flip in every gadget's hint wires is rejected, attributed to that gadget's group", async () => {
    const { readWtns, checkR1cs } = await import("../../harness/v4/r1cs_tools.ts");
    const sym = readSym(SYM_V4);
    const file = await referenceWitness(fixture().input);
    const honestW = await withFile(file, async (f) => readWtns(f));
    expect(checkR1cs(R1CS_V4, SYM_V4, honestW).satisfied).toBe(true);
    let edits = 0;
    for (const g of GADGETS) {
      const wires = [...sym.entries()].filter(([n]) => n.startsWith(`${g.prefix}.out[`)).map(([, w]) => w);
      expect(wires.length, `${g.prefix}: bit wires present at --O2`).toBeGreaterThan(0);
      const step = Math.max(1, Math.floor(wires.length / 8));
      for (let i = 0; i < wires.length; i += step) {
        const w = [...honestW];
        const idx = wires[i] as number;
        w[idx] = w[idx] === 0n ? 1n : 0n;
        const rep = checkR1cs(R1CS_V4, SYM_V4, w);
        expect(rep.satisfied, `${g.prefix} wire ${idx}`).toBe(false);
        expect(Object.keys(rep.byGroup), `${g.prefix} wire ${idx}`).toContain(g.group);
        edits++;
      }
    }
    expect(edits).toBeGreaterThan(40);
  }, 600_000);
});
