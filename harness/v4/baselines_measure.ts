import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { REPO_ROOT } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";
import { mlDsaKeygen, mlDsaSign, mlDsaVerify, mlKemKeygen, mlKemEncaps, mlKemDecaps, implementationLabel } from "@pqid/v4/pqc";
import { newIssuerKey, issue, present, verify, sizesOf, sharedHandles } from "../../baselines/sdjwt/sdjwt.ts";
import { issueBatch, batchSizes } from "../../baselines/sdjwt/batch.ts";
import { keygen } from "../../baselines/sdjwt/jose.ts";
import { ageClaims } from "../../baselines/sdjwt/age.ts";
import * as ed from "../../baselines/eddsa/lib.ts";

/**
 * E2 measurements on THIS host (quiet machine required: docs/v4/BENCH_PROTOCOL.md rules; the
 * script refuses while results/v4/bench/RUNNING exists and records the AC state).
 *   pqc      OpenSSL ML-DSA-44, ML-KEM-768 and ES256 primitives (criterion 1 on this host)
 *   sdjwt    ML-DSA-44 SD-JWT (and ES256 for contrast): issue, present, verify, sizes, batch cost
 *   eddsa    classical ZK credential (EdDSA verified in-circuit): witness, prove, verify, sizes
 * Output: results/v4/baselines/measure.json. --smoke runs tiny n into results/v4/baselines/_smoke.json.
 */
const SMOKE = process.argv.includes("--smoke");
const OUT = path.join(REPO_ROOT, "results", "v4", "baselines", SMOKE ? "_smoke.json" : "measure.json");

function stats(xs: number[]) {
  const s = [...xs].sort((a, b) => a - b);
  const q = (p: number) => {
    const h = (s.length - 1) * p;
    const lo = Math.floor(h);
    return s[lo]! + (h - lo) * ((s[Math.min(lo + 1, s.length - 1)] ?? s[lo]!) - s[lo]!);
  };
  const r = (x: number) => Math.round(x * 10000) / 10000;
  return { n: s.length, medianMs: r(q(0.5)), q1Ms: r(q(0.25)), q3Ms: r(q(0.75)), iqrMs: r(q(0.75) - q(0.25)), minMs: r(s[0]!), maxMs: r(s[s.length - 1]!) };
}
function timeIt(n: number, warm: number, fn: () => void) {
  for (let i = 0; i < warm; i++) fn();
  const xs: number[] = [];
  for (let i = 0; i < n; i++) {
    const t0 = process.hrtime.bigint();
    fn();
    xs.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  return stats(xs);
}
async function timeItAsync(n: number, warm: number, fn: () => Promise<unknown>) {
  for (let i = 0; i < warm; i++) await fn();
  const xs: number[] = [];
  for (let i = 0; i < n; i++) {
    const t0 = process.hrtime.bigint();
    await fn();
    xs.push(Number(process.hrtime.bigint() - t0) / 1e6);
  }
  return stats(xs);
}
function powerStatus(): string {
  try {
    if (process.platform === "win32") {
      const out = require_("node:child_process").execFileSync("powershell", ["-NoProfile", "-Command", "(Get-CimInstance Win32_Battery).BatteryStatus"], { encoding: "utf8" }).trim();
      return out === "2" ? "AC" : `battery status ${out}`;
    }
  } catch {
    /* unknown */
  }
  return "unknown";
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const require_ = (m: string): any => (globalThis as any).process.getBuiltinModule(m);

function pqc() {
  const N = SMOKE ? 20 : 1000;
  const W = SMOKE ? 2 : 50;
  const msg = crypto.randomBytes(32);
  const d = mlDsaKeygen();
  const sig = mlDsaSign(d.privateKey, msg);
  const k = mlKemKeygen();
  const enc = mlKemEncaps(k.publicKey);
  const es = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const esSig = crypto.sign("sha256", msg, es.privateKey);
  return {
    implementation: implementationLabel(),
    mlDsa44: { keygen: timeIt(N, W, () => void mlDsaKeygen()), sign: timeIt(N, W, () => void mlDsaSign(d.privateKey, msg)), verify: timeIt(N, W, () => void mlDsaVerify(d.publicKey, msg, sig)) },
    mlKem768: { keygen: timeIt(N, W, () => void mlKemKeygen()), encaps: timeIt(N, W, () => void mlKemEncaps(k.publicKey)), decaps: timeIt(N, W, () => void mlKemDecaps(k.privateKey, enc.ciphertext)) },
    es256: { sign: timeIt(N, W, () => void crypto.sign("sha256", msg, es.privateKey)), verify: timeIt(N, W, () => void crypto.verify("sha256", msg, es.publicKey, esSig)) },
    label: "[M] in-process, warm, OpenSSL via Node",
  };
}

function sdjwt(alg: "ML-DSA-44" | "ES256") {
  const N = SMOKE ? 10 : 200;
  const W = SMOKE ? 2 : 20;
  const issuer = newIssuerKey(alg);
  const holder = keygen(alg);
  const now = Math.floor(Date.now() / 1000);
  const today = Number(new Date(now * 1000).toISOString().slice(0, 10).replace(/-/g, ""));
  const claims = ageClaims(19900510, today, false);
  const cred = issue(issuer, claims, holder.publicKey, { now });
  const pres = present(cred, ["age_over_18"], { nonce: "n1", aud: "https://verifier.example", holderKey: holder.privateKey, iat: now });
  const pres2 = present(cred, ["age_over_18"], { nonce: "n2", aud: "https://verifier2.example", holderKey: holder.privateKey, iat: now });
  const vopts = { nonce: "n1", aud: "https://verifier.example", now, allowedAlgs: [alg] as const };
  const ok = verify(pres, issuer.publicKey, vopts);
  if (!ok.ok) throw new Error(`baseline presentation does not verify: ${ok.error}`);
  const batches = [];
  for (const n of SMOKE ? [1, 10] : [1, 10, 30, 100]) {
    let batch: ReturnType<typeof issueBatch> = [];
    const t0 = process.hrtime.bigint();
    batch = issueBatch(issuer, claims, n, { now, holderAlg: alg });
    const issueMs = Number(process.hrtime.bigint() - t0) / 1e6;
    const sizes = batchSizes(batch);
    const a = present(batch[0]!.sdjwt, ["age_over_18"], { nonce: "x", aud: "a", holderKey: batch[0]!.holder.privateKey, iat: now });
    const b = n > 1 ? present(batch[1]!.sdjwt, ["age_over_18"], { nonce: "y", aud: "b", holderKey: batch[1]!.holder.privateKey, iat: now }) : null;
    batches.push({ ...sizes, issueBatchMs: Math.round(issueMs * 100) / 100, holderKeygenIncluded: true, sharedHandlesBetweenTwoBatchPresentations: b ? sharedHandles(a, b).length : null });
  }
  return {
    alg,
    issue: timeIt(N, W, () => void issue(issuer, claims, holder.publicKey, { now })),
    present: timeIt(N, W, () => void present(cred, ["age_over_18"], { nonce: "n", aud: "https://verifier.example", holderKey: holder.privateKey, iat: now })),
    verify: timeIt(N, W, () => void verify(pres, issuer.publicKey, vopts)),
    sizes: { credential: sizesOf(cred), presentation: sizesOf(pres) },
    linkability: { sharedHandlesBetweenTwoPresentationsOfOneCredential: sharedHandles(pres, pres2), note: "values a colluding pair of verifiers can match; empty means unlinkable at the credential layer" },
    batches,
    label: "[M] in-process, warm",
  };
}

async function eddsa() {
  const N = SMOKE ? 2 : 10;
  const W = SMOKE ? 1 : 2;
  const snarkjs = await ed.snarkjsLib();
  const issuer = await ed.createIssuer();
  const holderSecret = ed.randomField();
  const credType = await ed.credTypeField(ed.DEFAULT_TYPE_ID);
  const today = Number(new Date().toISOString().slice(0, 10).replace(/-/g, ""));
  const cred = await ed.issueCredential(issuer, { holderCommit: await ed.holderCommitOf(holderSecret), birthDate: 19900510, expiryDate: 99991231, credType });
  const policy = { predicateCode: 1n, threshold: 18, today, requiredType: credType };
  const input = await ed.buildInput({ Ax: issuer.Ax, Ay: issuer.Ay, cred, holderSecret, policy, nonce: ed.randomField() });
  const vkey = await ed.loadVkey();
  const info = JSON.parse(fs.readFileSync(ed.CIRCUIT_INFO_FILE, "utf8")) as Record<string, unknown>;
  let w = await ed.computeWitness(input);
  const witness = await timeItAsync(N, W, async () => void (w = await ed.computeWitness(input)));
  let proved = await snarkjs.groth16.prove(ed.ZKEY_FILE, w as never);
  const prove = await timeItAsync(N, W, async () => void (proved = await snarkjs.groth16.prove(ed.ZKEY_FILE, w as never)));
  const verifyT = await timeItAsync(N, W, async () => void (await snarkjs.groth16.verify(vkey, proved.publicSignals, proved.proof)));
  return {
    constraints: info["nConstraints"] ?? info,
    witness,
    prove,
    verify: verifyT,
    proofJsonBytes: Buffer.byteLength(JSON.stringify(proved.proof)),
    keyLabel: ed.KEY_LABEL,
    label: "[M] in-process, warm, snarkJS 0.7.4",
  };
}

async function main(): Promise<void> {
  if (fs.existsSync(path.join(REPO_ROOT, "results", "v4", "bench", "RUNNING"))) throw new Error("a timed benchmark is running (results/v4/bench/RUNNING)");
  const power = powerStatus();
  if (!SMOKE && power !== "AC") throw new Error(`not on AC power (${power}); protocol requires AC`);
  const out = {
    schema: "pqid/v4-baselines-measure/v1",
    smoke: SMOKE,
    power,
    pqc: pqc(),
    sdjwtMlDsa: sdjwt("ML-DSA-44"),
    sdjwtEs256: sdjwt("ES256"),
    eddsaZk: await eddsa(),
    host: hostMeta(),
  };
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(out, null, 2));
  console.log(`[baselines] -> ${path.relative(REPO_ROOT, OUT)}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(
    () => process.exit(0),
    (e: unknown) => {
      console.error(e);
      process.exit(1);
    }
  );
}
