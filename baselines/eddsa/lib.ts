/**
 * Baseline E2b: classical ZK credential with the issuer's EdDSA-Poseidon (BabyJubJub)
 * signature verified inside the Groth16 circuit (circuits/baselines/eddsa_credential.circom).
 *
 * Comparison baseline only. Not part of PQ-Identity v4 and not post-quantum.
 * Issuer private keys live only inside the closure returned by createIssuer() and are
 * never written, logged or returned.
 */
import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import {
  getPoseidon,
  poseidonBig,
  poseidonFoldBytes,
  BN254_P,
} from "@pqid/common/encoding";

// ------------------------------------------------------------------ paths
export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
export const CIRCUIT_NAME = "eddsa_credential";
export const CIRCUIT_SRC = path.join(REPO_ROOT, "circuits", "baselines", `${CIRCUIT_NAME}.circom`);
export const BUILD_DIR = path.join(REPO_ROOT, "circuits", "build", "baselines");
export const R1CS_FILE = path.join(BUILD_DIR, `${CIRCUIT_NAME}.r1cs`);
export const SYM_FILE = path.join(BUILD_DIR, `${CIRCUIT_NAME}.sym`);
export const WASM_FILE = path.join(BUILD_DIR, `${CIRCUIT_NAME}_js`, `${CIRCUIT_NAME}.wasm`);
export const CIRCUIT_INFO_FILE = path.join(BUILD_DIR, `${CIRCUIT_NAME}_info.json`);
export const SETUP_DIR = path.join(REPO_ROOT, "setup", "out", "baselines");
export const ZKEY_FILE = path.join(SETUP_DIR, `${CIRCUIT_NAME}_throwaway.zkey`);
export const VKEY_FILE = path.join(SETUP_DIR, `${CIRCUIT_NAME}_throwaway_vkey.json`);
export const SETUP_RECORD_FILE = path.join(SETUP_DIR, `${CIRCUIT_NAME}_throwaway_setup.json`);
export const PTAU_FILE = path.join(REPO_ROOT, "setup", "ptau", "powersOfTau28_hez_final_15.ptau");
export const PINS_FILE = path.join(REPO_ROOT, "setup", "pins.json");
export const RESULTS_FILE = path.join(REPO_ROOT, "results", "v4", "baselines", "eddsa_smoke.json");

export const KEY_LABEL = "throwaway baseline key";

/** Repo-relative path with forward slashes (no home paths in records). */
export function rel(p: string): string {
  return path.relative(REPO_ROOT, p).split(path.sep).join("/");
}

export function circomBinary(): string {
  const win = path.join(REPO_ROOT, "tools", "circom.exe");
  return process.platform === "win32" && fs.existsSync(win) ? win : "circom";
}

// ------------------------------------------------------------ constants
/** Same policy tag as POLICY_V4 (docs/v4/V4_DESIGN.md 1.2). */
export const POLICY_TAG = 1006n;
/** Same credential-type fold tag as v4 DOMAIN_CRED_TYPE. */
export const DOMAIN_CRED_TYPE = 1005n;
export const DEFAULT_TYPE_ID = "pqid:type:age-credential:v1";
export const PREDICATE_AGE_GTE = 1n;
export const PREDICATE_AGE_LT = 2n;
/** Public signal order of the baseline circuit. */
export const PUBLIC_SIGNAL_ORDER = ["Ax", "Ay", "policyHash", "nonce"] as const;

// ------------------------------------------------------------ crypto setup
interface BabyJubPoint {
  0: Uint8Array;
  1: Uint8Array;
}
interface EddsaSig {
  R8: BabyJubPoint;
  S: bigint;
}
interface Eddsa {
  F: { e(v: bigint): Uint8Array; toObject(e: Uint8Array): bigint };
  prv2pub(prv: Uint8Array): BabyJubPoint;
  signPoseidon(prv: Uint8Array, msg: Uint8Array): EddsaSig;
  verifyPoseidon(msg: Uint8Array, sig: EddsaSig, A: BabyJubPoint): boolean;
}

let eddsaSingleton: Eddsa | null = null;
export async function getEddsa(): Promise<Eddsa> {
  if (!eddsaSingleton) {
    const lib = (await import("circomlibjs")) as unknown as { buildEddsa: () => Promise<Eddsa> };
    eddsaSingleton = await lib.buildEddsa();
  }
  return eddsaSingleton;
}

export interface Signature {
  R8x: bigint;
  R8y: bigint;
  S: bigint;
}

export interface BaselineIssuer {
  /** Issuer BabyJubJub public key (affine, field elements). */
  readonly Ax: bigint;
  readonly Ay: bigint;
  /** EdDSA-Poseidon signature on one field element. The private key stays in this closure. */
  sign(msg: bigint): Signature;
}

/** Fresh issuer key from 32 bytes of OS randomness, held in memory only. */
export async function createIssuer(): Promise<BaselineIssuer> {
  const eddsa = await getEddsa();
  const F = eddsa.F;
  const prv = randomBytes(32);
  const A = eddsa.prv2pub(prv);
  const Ax = F.toObject(A[0]);
  const Ay = F.toObject(A[1]);
  return Object.freeze({
    Ax,
    Ay,
    sign(msg: bigint): Signature {
      const sig = eddsa.signPoseidon(prv, F.e(msg));
      return { R8x: F.toObject(sig.R8[0]), R8y: F.toObject(sig.R8[1]), S: sig.S };
    },
  });
}

/** Off-circuit EdDSA-Poseidon verification (the check the circuit repeats). */
export async function verifySignature(Ax: bigint, Ay: bigint, msg: bigint, sig: Signature): Promise<boolean> {
  const eddsa = await getEddsa();
  const F = eddsa.F;
  return eddsa.verifyPoseidon(
    F.e(msg),
    { R8: [F.e(sig.R8x), F.e(sig.R8y)] as unknown as BabyJubPoint, S: sig.S },
    [F.e(Ax), F.e(Ay)] as unknown as BabyJubPoint
  );
}

// ------------------------------------------------------------ encodings
export async function holderCommitOf(holderSecret: bigint): Promise<bigint> {
  return poseidonBig(await getPoseidon(), [holderSecret]);
}

export async function credTypeField(typeId: string): Promise<bigint> {
  return poseidonFoldBytes(await getPoseidon(), new TextEncoder().encode(typeId), DOMAIN_CRED_TYPE);
}

export interface CredentialAttrs {
  holderCommit: bigint;
  birthDate: number; // YYYYMMDD
  expiryDate: number; // YYYYMMDD
  credType: bigint;
}

/** credHash = Poseidon4(holderCommit, birthDate, expiryDate, credType). */
export async function credHashOf(c: CredentialAttrs): Promise<bigint> {
  return poseidonBig(await getPoseidon(), [c.holderCommit, BigInt(c.birthDate), BigInt(c.expiryDate), c.credType]);
}

export interface Policy {
  predicateCode: bigint; // 1 = AGE_GTE, 2 = AGE_LT
  threshold: number; // years
  today: number; // YYYYMMDD
  requiredType: bigint;
}

/** policyHash = Poseidon5(1006, predicateCode, threshold, today, requiredType). */
export async function policyHashOf(p: Policy): Promise<bigint> {
  return poseidonBig(await getPoseidon(), [POLICY_TAG, p.predicateCode, BigInt(p.threshold), BigInt(p.today), p.requiredType]);
}

export interface SignedCredential extends CredentialAttrs {
  credHash: bigint;
  sig: Signature;
}

/** Issuer side: hash the attributes and sign the hash. */
export async function issueCredential(issuer: BaselineIssuer, attrs: CredentialAttrs): Promise<SignedCredential> {
  const credHash = await credHashOf(attrs);
  return { ...attrs, credHash, sig: issuer.sign(credHash) };
}

/** Random field element below p (for holder secrets and nonces). */
export function randomField(): bigint {
  return BigInt("0x" + randomBytes(31).toString("hex")) % BN254_P;
}

export type CircuitInput = Record<string, string>;

/** Circuit input for a presentation of `cred` under issuer key (Ax, Ay). */
export async function buildInput(args: {
  Ax: bigint;
  Ay: bigint;
  cred: SignedCredential;
  holderSecret: bigint;
  policy: Policy;
  nonce: bigint;
  /** Override the policyHash the verifier expects (negative tests only). */
  policyHashOverride?: bigint;
}): Promise<CircuitInput> {
  const { Ax, Ay, cred, holderSecret, policy, nonce } = args;
  const ph = args.policyHashOverride ?? (await policyHashOf(policy));
  return {
    Ax: Ax.toString(),
    Ay: Ay.toString(),
    policyHash: ph.toString(),
    nonce: nonce.toString(),
    holderSecret: holderSecret.toString(),
    birthDate: String(cred.birthDate),
    expiryDate: String(cred.expiryDate),
    credType: cred.credType.toString(),
    sigR8x: cred.sig.R8x.toString(),
    sigR8y: cred.sig.R8y.toString(),
    sigS: cred.sig.S.toString(),
    predicateCode: policy.predicateCode.toString(),
    threshold: String(policy.threshold),
    today: String(policy.today),
    requiredType: policy.requiredType.toString(),
  };
}

/** Public signals a verifier expects, in circuit order. */
export async function expectedPublicSignals(Ax: bigint, Ay: bigint, policy: Policy, nonce: bigint): Promise<string[]> {
  return [Ax, Ay, await policyHashOf(policy), nonce].map((x) => x.toString());
}

// ------------------------------------------------------------ snarkjs helpers
export interface MemFile {
  type: "mem";
  data?: Uint8Array;
}

export async function snarkjsLib(): Promise<typeof import("snarkjs")> {
  return import("snarkjs");
}

/** Witness in memory (throws "Assert Failed" when a circuit constraint check fails). */
export async function computeWitness(input: CircuitInput): Promise<MemFile> {
  const snarkjs = await snarkjsLib();
  const w: MemFile = { type: "mem" };
  await snarkjs.wtns.calculate(input, WASM_FILE, w);
  return w;
}

/** Witness vector (wire values) of an in-memory witness. */
export async function witnessValues(w: MemFile): Promise<bigint[]> {
  const snarkjs = await snarkjsLib();
  const exp = snarkjs.wtns.exportJson as unknown as (f: MemFile) => Promise<bigint[]>;
  return (await exp(w)).map((x) => BigInt(x));
}

/** Encode a witness vector as an in-memory .wtns (format version 2, BN254). */
export function encodeWitness(values: readonly bigint[]): MemFile {
  const n8 = 32;
  const header = 4 + 4 + 4;
  const sec1 = 4 + 8 + (4 + n8 + 4);
  const sec2 = 4 + 8 + n8 * values.length;
  const buf = Buffer.alloc(header + sec1 + sec2);
  let o = 0;
  buf.write("wtns", o, "ascii");
  o += 4;
  buf.writeUInt32LE(2, o);
  o += 4;
  buf.writeUInt32LE(2, o);
  o += 4;
  const writeBig = (v: bigint) => {
    let x = ((v % BN254_P) + BN254_P) % BN254_P;
    for (let i = 0; i < n8; i++) {
      buf[o + i] = Number(x & 0xffn);
      x >>= 8n;
    }
    o += n8;
  };
  buf.writeUInt32LE(1, o);
  o += 4;
  buf.writeBigUInt64LE(BigInt(4 + n8 + 4), o);
  o += 8;
  buf.writeUInt32LE(n8, o);
  o += 4;
  // the field prime itself (writeBig would reduce it mod p to 0)
  {
    let x = BN254_P;
    for (let i = 0; i < n8; i++) {
      buf[o + i] = Number(x & 0xffn);
      x >>= 8n;
    }
    o += n8;
  }
  buf.writeUInt32LE(values.length, o);
  o += 4;
  buf.writeUInt32LE(2, o);
  o += 4;
  buf.writeBigUInt64LE(BigInt(n8 * values.length), o);
  o += 8;
  for (const v of values) writeBig(v);
  return { type: "mem", data: new Uint8Array(buf) };
}

/** R1CS satisfiability of a witness against the compiled baseline R1CS. */
export async function r1csSatisfied(w: MemFile): Promise<boolean> {
  const snarkjs = await snarkjsLib();
  const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined, debug: () => undefined };
  const check = snarkjs.wtns.check as unknown as (r: string, f: MemFile, l: unknown) => Promise<boolean>;
  return check(R1CS_FILE, w, quiet);
}

export async function loadVkey(): Promise<unknown> {
  return JSON.parse(fs.readFileSync(VKEY_FILE, "utf8"));
}
