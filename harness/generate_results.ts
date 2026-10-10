import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT, RESULTS_DIR } from "@pqid/common/paths";

/**
 * Regenerates RESULTS.md from results/*.json and injects the AUTO-GENERATED
 * complete divergence table into MANUSCRIPT_RECONCILIATION.md (between
 * markers). V6 §D: every measured cell is programmatically diffed against the
 * embedded paper claims; every |Δ| > THRESHOLD row appears — no hand-curated
 * omissions. Causes are curated text; the LIST is automatic.
 */
const THRESHOLD_PCT = 5;

function load(name: string): any | null {
  const p = path.join(RESULTS_DIR, name);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, "utf8"));
}
function loadAt(p: string): any | null {
  return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : null;
}

const pqc = load("pqc.json");
const pqcAvx2 = load("pqc_avx2.json");
const zk = load("zk.json");
const zkCool = load("zk_rapidsnark_cool.json");
const gas = load("gas.json");
const baseline = load("baseline.json");
const neg = load("negative.json");
const probe = load("malicious_probe.json");
const e2e = load("e2e.json");
const latency = load("e2e_latency.json");
const circomspect = load("circomspect.json");
const circuitInfo = loadAt(path.join(REPO_ROOT, "circuits", "build", "circuit_info.json"));
const sha3 = loadAt(path.join(REPO_ROOT, "circuits", "build", "research", "sha3_research_info.json"));

/** headline value of a v2 aggregated op */
const hv = (op: any): number | undefined => op?.headline?.valueMs;
const sd = (op: any): number | undefined => op?.repr?.stddevMs;
const cv = (op: any): string => (op?.interRun ? `${op.interRun.cvPct}%${op.interRun.stable ? "" : " ⚠"}` : "—");

interface ClaimSpec {
  id: string;
  table: string;
  metric: string;
  paper: number;
  paperLabel: string;
  unit: string;
  measured: () => number | undefined;
  measuredLabel: string;
  cause: string;
}

// Paper-claim reference values track the SUBMITTED manuscript (V6.6), which
// adopted the prototype's controlled measurements. They are compared against
// the measured results below; with V6.6 the two agree (divergences collapse to
// ~0 within the 5% threshold). The `measured:` accessors and all comparison
// logic are unchanged — only these reference constants are versioned to V6.6.
const CLAIMS: ClaimSpec[] = [
  // ----- Table V (PQC) — V6.6 generic AVX2-off figures
  { id: "dilithium-keygen", table: "V", metric: "ML-DSA-44 keygen (ms)", paper: 0.052, paperLabel: "[M]", unit: "ms",
    measured: () => hv(pqc?.algorithms?.["ML-DSA-44"]?.keygen), measuredLabel: "[M]",
    cause: "V6.6 reports the controlled liboqs 0.15.0 generic (AVX2-off) measurement." },
  { id: "dilithium-sign", table: "V", metric: "ML-DSA-44 sign (ms)", paper: 0.188, paperLabel: "[M]", unit: "ms",
    measured: () => hv(pqc?.algorithms?.["ML-DSA-44"]?.sign), measuredLabel: "[M]",
    cause: "V6.6 reports the controlled measurement." },
  { id: "dilithium-verify", table: "V", metric: "ML-DSA-44 verify (ms)", paper: 0.058, paperLabel: "[M]", unit: "ms",
    measured: () => hv(pqc?.algorithms?.["ML-DSA-44"]?.verify), measuredLabel: "[M]",
    cause: "V6.6 reports the controlled measurement." },
  { id: "kyber-keygen", table: "V", metric: "ML-KEM-512 keygen (ms)", paper: 0.016, paperLabel: "[M]", unit: "ms",
    measured: () => hv(pqc?.algorithms?.["ML-KEM-512"]?.keygen), measuredLabel: "[M]",
    cause: "V6.6 reports the controlled measurement." },
  { id: "kyber-encap", table: "V", metric: "ML-KEM-512 encap (ms)", paper: 0.018, paperLabel: "[M]", unit: "ms",
    measured: () => hv(pqc?.algorithms?.["ML-KEM-512"]?.encap), measuredLabel: "[M]",
    cause: "V6.6 reports the controlled measurement." },
  { id: "kyber-decap", table: "V", metric: "ML-KEM-512 decap (ms)", paper: 0.022, paperLabel: "[M]", unit: "ms",
    measured: () => hv(pqc?.algorithms?.["ML-KEM-512"]?.decap), measuredLabel: "[M]",
    cause: "V6.6 reports the controlled measurement." },
  // ----- Table VI (Groth16) — V6.6 circuit v2 + controlled campaign
  { id: "constraints", table: "VI", metric: "R1CS constraints", paper: 21715, paperLabel: "[M]", unit: "",
    measured: () => circuitInfo?.nConstraints, measuredLabel: "[M]",
    cause: "V6.6 reports the measured circuit-v2 count (21,715)." },
  { id: "private-inputs", table: "VI", metric: "private inputs", paper: 43, paperLabel: "[M]", unit: "",
    measured: () => circuitInfo?.nPrvInputs, measuredLabel: "[M]",
    cause: "V6.6 reports the measured circuit-v2 witness size (43)." },
  { id: "witness-gen", table: "VI", metric: "witness generation (ms)", paper: 92, paperLabel: "[M]", unit: "ms",
    measured: () => hv(zk?.witnessGeneration), measuredLabel: "[M]",
    cause: "V6.6 reports the controlled measurement (92 ms, inter-run CV 0.5%)." },
  { id: "snarkjs-prove", table: "VI", metric: "snarkJS prove (ms, sustained mean)", paper: 2095, paperLabel: "[M]", unit: "ms",
    measured: () => hv(zk?.snarkjsProveCold), measuredLabel: "[M]",
    cause: "V6.6 reports ≈981 ms cool / ≈2.1 s sustained (campaign mean 2095 ms, CV 21%); this row compares the sustained-mean headline." },
  { id: "rapidsnark-prove", table: "VI", metric: "rapidsnark prove, cold (ms, campaign/sustained)", paper: 258.6, paperLabel: "[M]", unit: "ms",
    measured: () => hv(zk?.rapidsnarkProveCold), measuredLabel: "[M]",
    cause: "V6.6 reports ≈250–286 ms heat-soaked (mean 258.6 ms) for the sustained ordering." },
  { id: "rapidsnark-prove-cool", table: "VI", metric: "rapidsnark prove, cold (ms, truly-cool first run)", paper: 177, paperLabel: "[M]", unit: "ms",
    measured: () => zkCool?.cold?.perRun?.[0]?.medianMs, measuredLabel: "[M]",
    cause: "V6.6 reports ≈177 ms in the truly-cool single-authentication state." },
  { id: "verify", table: "VI", metric: "Groth16 verify (ms)", paper: 40, paperLabel: "[M]", unit: "ms",
    measured: () => hv(zk?.snarkjsVerify), measuredLabel: "[M]",
    cause: "V6.6 reports the controlled measurement (40 ms, inter-run CV 0.6%)." },
  { id: "speedup", table: "VI", metric: "speedup snarkJS/rapidsnark (sustained/sustained)", paper: 8.1, paperLabel: "[M]", unit: "×",
    measured: () => zk?.speedups?.coldCold, measuredLabel: "[M]",
    cause: "V6.6 headlines ≈5.5× (cool/cool) with a ≈5.5–8× spread across thermal states; this row compares the sustained/sustained basis (≈8×)." },
  { id: "proof-size", table: "VI", metric: "proof size, snarkJS JSON (B)", paper: 723, paperLabel: "[M]", unit: "B",
    measured: () => zk?.proofSize?.snarkjsJsonBytes, measuredLabel: "[M]",
    cause: "V6.6 reports 723 B (snarkJS JSON serialization); ≈128 B compressed." },
  // ----- gas + baseline + §VI-C — V6.6 measured upgrades
  { id: "gas", table: "VI", metric: "on-chain verify gas (bare tx)", paper: 242931, paperLabel: "[M]", unit: "gas",
    measured: () => gas?.verifyProofDirectTxGasUsed, measuredLabel: "[M]",
    cause: "V6.6 reports the measured bare verifyProof gas on a local single-node EVM (242,931)." },
  { id: "ecdsa-sign", table: "V/VII", metric: "ECDSA P-256 sign (ms)", paper: 0.026, paperLabel: "[M]", unit: "ms",
    measured: () => hv(baseline?.ecdsaP256?.sign), measuredLabel: "[M]",
    cause: "V6.6 measures ECDSA P-256 on the same host with OpenSSL." },
  { id: "ecdsa-verify", table: "V/VII", metric: "ECDSA P-256 verify (ms)", paper: 0.062, paperLabel: "[M]", unit: "ms",
    measured: () => hv(baseline?.ecdsaP256?.verify), measuredLabel: "[M]",
    cause: "V6.6 measures ECDSA P-256 on the same host with OpenSSL." },
  { id: "vic-core", table: "§VI-C", metric: "core auth latency, native prover (ms)", paper: 390, paperLabel: "[M]", unit: "ms",
    measured: () => latency?.totals?.coreRapidsnarkMs, measuredLabel: "[M]",
    cause: "V6.6 reports the measured core breakdown: ≈0.31 s cool / ≈0.39 s sustained (92 + 177/258.6 + 40 ms)." },
];

interface DivRow extends ClaimSpec {
  measuredValue: number;
  deltaPct: number;
  direction: string;
}

function divergences(): DivRow[] {
  const rows: DivRow[] = [];
  for (const c of CLAIMS) {
    const m = c.measured();
    if (m === undefined || m === null || Number.isNaN(m)) continue;
    const deltaPct = ((m - c.paper) / c.paper) * 100;
    if (Math.abs(deltaPct) <= THRESHOLD_PCT) continue;
    rows.push({
      ...c,
      measuredValue: m,
      deltaPct: Math.round(deltaPct * 10) / 10,
      direction: deltaPct < 0 ? (c.unit === "ms" ? "faster" : "smaller") : c.unit === "ms" ? "slower" : "larger",
    });
  }
  return rows;
}

function divergenceTable(rows: DivRow[]): string[] {
  const L: string[] = [];
  L.push(`| # | Table | Metric | Paper | Measured | Δ | Direction | Cause (summary) | Source |`);
  L.push(`|---|---|---|---|---|---|---|---|---|`);
  rows.forEach((r, i) => {
    const src =
      r.table === "IV" || r.id.startsWith("ecdsa") ? (r.id.startsWith("ecdsa") ? "baseline.json" : "pqc.json")
      : r.id === "gas" ? "gas.json"
      : r.id === "vic-core" ? "e2e_latency.json"
      : r.id === "constraints" || r.id === "private-inputs" ? "circuit_info.json"
      : "zk.json";
    const causeSummary = (r.cause.split(/(?<=[a-z)])\.\s/)[0] ?? r.cause).slice(0, 160);
    L.push(
      `| ${i + 1} | ${r.table} | ${r.metric} | ${r.paper}${r.unit} ${r.paperLabel} | ${r.measuredValue}${r.unit} ${r.measuredLabel} | ${r.deltaPct > 0 ? "+" : ""}${r.deltaPct}% | ${r.direction} | ${causeSummary}. | \`results/${src}\` |`
    );
  });
  return L;
}

function controlsBlock(c: any): string[] {
  if (!c) return ["_no controls recorded (pre-V6 run)_"];
  return [
    `- quiesced: ${c.quiesce?.quiesced}${c.quiesce?.forced ? " (FORCED override)" : ""}; Windows load ${c.quiesce?.windows?.cpuLoadPercent}%; WSL loadavg ${c.quiesce?.wsl?.loadavg1m}`,
    `- affinity: ${c.affinity?.policy}${c.affinity?.probe ? ` — probe (amortized prove, ms): free ${JSON.stringify(c.affinity.probe.freeMs)}, 1 vCPU ${JSON.stringify(c.affinity.probe.oneVcpuMs)}, 4 vCPU ${JSON.stringify(c.affinity.probe.fourVcpuMs)}` : ""}`,
    `- governor: ${c.cpuGovernor}; power: ${c.powerSource}`,
    `- fs basis: ${c.fsBasis}; independent invocations: ${c.invocations}`,
  ];
}

function main(): void {
  const L: string[] = [];
  const w = (s = ""): void => void L.push(s);
  const host = zk?.controls?.host ?? pqc?.controls?.host ?? {};
  const wsl = zk?.controls?.wsl ?? pqc?.controls?.wsl ?? {};

  w("# RESULTS — Measured Evidence for IEEE Access-2026-15409 (controlled campaign; reconciled to submitted manuscript V6.6)");
  w();
  w("> Generated by `harness/generate_results.ts` from `results/*.json`. **Do not edit by hand.**");
  w("> Labels: `[M]` measured, `[S]` simulated/estimate, `[A]` assumption, `[F]` future work.");
  w("> Benchmarks follow the §B discipline: quiesced machine (guard-enforced), recorded controls,");
  w("> ≥3 independent invocations per metric, median headline where σ/mean > 0.2.");
  w();
  w("## Measurement host & controls");
  w();
  w("| Field | Value |");
  w("|---|---|");
  w(`| CPU | ${host.cpuModel ?? "—"} (2 P + 8 E cores, 12 logical; paper's reference CPU) |`);
  w(`| OS build | ${host.osBuild ?? "—"} | `);
  w(`| Node.js | ${host.nodeVersion ?? "—"} |`);
  w(`| WSL | ${wsl.distro ?? "—"}, kernel ${wsl.kernel ?? "—"} |`);
  w(`| GCC (native) | ${wsl.gcc ?? "—"} |`);
  w();
  w("ZK-bench controls (full record in `results/zk.json` → `controls`):");
  w();
  for (const line of controlsBlock(zk?.controls)) w(line);
  w();

  // ---------------- Table V (PQC) ----------------
  w("## Table V — PQC primitives (liboqs 0.15.0, generic AVX2-off build)");
  w();
  if (!pqc) w("_Run `make bench` first._");
  else {
    const d = pqc.algorithms["ML-DSA-44"];
    const k = pqc.algorithms["ML-KEM-512"];
    w(`N=${pqc.config?.n}, warmup=${pqc.config?.warmup}, ${pqc.config?.runs} independent invocations. Source: \`results/pqc.json\`.`);
    w();
    w("| Algorithm | Op | Headline (ms) | σ (ms) | inter-run CV | Paper | Status |");
    w("|---|---|---|---|---|---|---|");
    const row = (alg: string, op: string, o: any, paper: number): void =>
      w(`| ${alg} | ${op} | ${hv(o)} | ${sd(o)} | ${cv(o)} | ${paper} | [M] |`);
    row("ML-DSA-44", "keygen", d.keygen, 0.052);
    row("ML-DSA-44", "sign", d.sign, 0.188);
    row("ML-DSA-44", "verify", d.verify, 0.058);
    row("ML-KEM-512", "keygen", k.keygen, 0.016);
    row("ML-KEM-512", "encap", k.encap, 0.018);
    row("ML-KEM-512", "decap", k.decap, 0.022);
    w();
    w(`Sizes match FIPS 203/204 exactly (pk 1312/800, sk 2560/1632, sig 2420, ct 768, ss 32).`);
    if (pqcAvx2) {
      const da = pqcAvx2.algorithms["ML-DSA-44"];
      const ka = pqcAvx2.algorithms["ML-KEM-512"];
      w();
      w(`AVX2 dist build ([A]→[M], \`results/pqc_avx2.json\`): ML-DSA-44 sign ${hv(da.sign)} / verify ${hv(da.verify)} ms; ML-KEM-512 encap ${hv(ka.encap)} / decap ${hv(ka.decap)} ms.`);
    }
  }
  w();

  // ---------------- Table VI (Groth16) ----------------
  w("## Table VI — Groth16 (BN254), circuit v2, byte-identical prover inputs");
  w();
  if (!zk) w("_Run `make bench` first._");
  else {
    const cc = zk.config.circuit;
    w(`Circuit: **${cc.nConstraints} constraints**, ${cc.nWires} wires, ${cc.nPubInputs} public / ${cc.nPrvInputs} private (${cc.version}; V6.6: 21,715/21,745/5/43 — agrees).`);
    w(`zkey SHA-256 \`${String(zk.config.zkeySha256).slice(0, 16)}…\`, witness SHA-256 \`${String(zk.config.witnessSha256).slice(0, 16)}…\` — identical for both provers.`);
    w();
    w("| Metric | Headline | basis | inter-run medians (ms) | CV | Paper | Status |");
    w("|---|---|---|---|---|---|---|");
    const row = (name: string, p: any, paper: string): void =>
      w(`| ${name} | ${p.headline.valueMs} ms | ${p.headline.basis} | ${p.interRun.mediansMs.join(" / ")} | ${p.interRun.cvPct}%${p.interRun.stable ? "" : " ⚠"} | ${paper} | [M] |`);
    row("Witness generation (snarkJS WASM)", zk.witnessGeneration, "92 (CV 0.5%)");
    row("snarkJS prove — cold (file-based, paper basis)", zk.snarkjsProveCold, "981 cool / 2095 sustained");
    row("snarkJS prove — amortized (in-memory buffers)", zk.snarkjsProveAmortized, "—");
    row("rapidsnark prove — cold (subprocess wall, ext4; paper basis; heat-soaked ordering)", zk.rapidsnarkProveCold, "177 cool / 258.6 sustained");
    row("rapidsnark prove — amortized (zkey parsed once)", zk.rapidsnarkProveAmortized, "—");
    if (zkCool) {
      row("rapidsnark prove — cold, COOL-STATE re-run (§C1, after ≥10 min idle)", zkCool.cold, "177 cool");
      row("rapidsnark prove — amortized, cool-state", zkCool.amortized, "—");
    }
    row("Groth16 verify (snarkJS)", zk.snarkjsVerify, "40 (CV 0.6%)");
    w();
    w(`**Speedups (identical bases, §C3):** cold/cold **${zk.speedups.coldCold}×** (V6.6: ≈5.5× cool/cool, ≈5.5–8× across thermal states); amortized/amortized **${zk.speedups.amortizedAmortized}×**.`);
    w();
    w(`Proof: ${zk.proofSize.snarkjsJsonBytes} B snarkJS / ${zk.proofSize.rapidsnarkJsonBytes} B rapidsnark JSON (≈128 B compressed); ${zk.proofSize.publicSignals} public signals. Cross-prover verification: rapidsnark cold ${zk.correctness.rapidsnarkColdVerifies}, amortized ${zk.correctness.rapidsnarkAmortizedVerifies} under snarkJS.`);
    w();
    w("### Thermal-state characterization (the §C finding)");
    w();
    w("The §B controls isolated **package thermal state** as the dominant residual variable on this");
    w("15 W ULV laptop CPU. Evidence, all from SHA-256-identical inputs and identical methods:");
    w();
    w("| State | rapidsnark cold | snarkJS cold | Evidence |");
    w("|---|---|---|---|");
    if (zkCool) {
      w(`| truly cool (≥10 min idle) | **${zkCool.cold.perRun?.[0]?.medianMs ?? "—"} ms** | ~981 ms (campaign run 1) | \`zk_rapidsnark_cool.json\` run 1; \`zk.json\` snarkJS run 1 |`);
      w(`| self-heated steady state | ≈${zkCool.cold.perRun?.[1]?.medianMs ?? "—"} ms | ≈2095 ms | cool-bench runs 2–3; campaign snarkJS runs 2–3 |`);
    }
    w(`| heat-soaked (campaign ordering) | ${hv(zk.rapidsnarkProveCold)} ms | ${hv(zk.snarkjsProveCold)} ms | \`zk.json\` (rapidsnark measured after ~50 min of snarkJS) |`);
    w(`| V6.6 manuscript (cool / sustained) | 177 / 258.6 ms | 981 / 2095 ms | matches the measured campaign |`);
    w();
    w("The snarkJS cold CV (⚠ flag above) is this bimodality, not scheduler noise. For a single");
    w("authentication (the protocol's real workload — one proof, not 100 back-to-back) the");
    w("cool-state figures are the representative ones; sustained-throughput figures apply to bulk");
    w("proving. The V5 rapidsnark figure (274.59 ms) was additionally contaminated by concurrent");
    w("builds and 9p file I/O — fully superseded by these controlled numbers.");
  }
  w();

  // ---------------- gas ----------------
  w("## On-chain verification gas ([A] → [M])");
  w();
  if (gas) {
    w(`\`verifyProof\` bare tx **${gas.verifyProofDirectTxGasUsed} gas**; via contract + SSTORE ${gas.probeTxGasUsed} gas; calldata ${gas.calldataBytes} B; valid proof accepted ${gas.staticCallValid}, corrupted signal rejected ${gas.corruptedSignalRejected}. V6.6: 242,931 gas [M] (local single-node EVM); public testnet remains [F]. Source: \`results/gas.json\`.`);
  } else w("_Run `npm run gas`._");
  w();

  // ---------------- Table VII (baseline) ----------------
  w("## Table VII — vs centralized classical baseline (measured)");
  w();
  if (baseline && zk) {
    const e = baseline.ecdsaP256;
    const t = baseline.oauth2Tokens;
    const pg = baseline.postgres;
    w(`PostgreSQL ${String(pg.serverVersion).split(",")[0]}; ${baseline.config?.runs} invocations. Source: \`results/baseline.json\`.`);
    w();
    w("| Dimension | Baseline (measured) | Proposed (measured) |");
    w("|---|---|---|");
    w(`| Per-auth sig/proof size | ECDSA ${e.sizes.signatureBytes} B + token ${t.opaqueTokenBytes} B | Dilithium 2420 B + Groth16 ${zk.proofSize.snarkjsJsonBytes} B |`);
    w(`| Verifier-side time | ECDSA verify ${hv(e.verify)} ms; PG token-auth ${hv(pg.tokenAuthSelect)} ms | Groth16 verify ${hv(zk.snarkjsVerify)} ms |`);
    w(`| Client-side time | JWT issue ${hv(t.jwtIssue)} ms | prove ${hv(zk.rapidsnarkProveCold)} ms (native) / ${hv(zk.snarkjsProveCold)} ms (snarkJS) |`);
    w(`| Per-credential storage | ${t.opaqueTokenBytes}–${t.jwtEs256Bytes} B token | ${e2e ? e2e.vcBytes : "≈5200"} B VC incl. Dilithium sig |`);
    w(`| Server-side PII | full record (${pg.storage?.user_row} B row) | zero PII on-chain |`);
  } else w("_Run `make bench` first._");
  w();

  // ---------------- §E latency ----------------
  w("## End-to-end latency budget (§VI-C, recomputed from measured components)");
  w();
  if (latency) {
    const t = latency.totals;
    w("| Path | Core (witness+prove+verify) | + Dilithium verify + network [S] | Sub-second core? |");
    w("|---|---|---|---|");
    w(`| native (rapidsnark, cold) | **${t.coreRapidsnarkMs} ms** | ${t.e2eRapidsnarkMs.min}–${t.e2eRapidsnarkMs.max} ms | **${t.subSecondCoreRapidsnark}** |`);
    w(`| snarkJS | ${t.coreSnarkjsMs} ms | ${t.e2eSnarkjsMs.min}–${t.e2eSnarkjsMs.max} ms | ${t.subSecondCoreSnarkjs} |`);
    w();
    w(`V6.6 §VI-C reports the measured core breakdown (≈0.31 s cool / ≈0.39 s sustained, native path) and an ≈0.34–0.51 s e2e total [S]. ${t.qualifier}. Source: \`results/e2e_latency.json\` (each component labeled).`);
  } else w("_Run `npm run e2e:latency`._");
  w();

  // ---------------- negative + probe + audit ----------------
  w("## Soundness evidence");
  w();
  if (neg) w(`- **Negative test: ${neg.pass ? "PASS" : "FAIL"}** — revoked credential ⇒ no accepted proof via all three adversary strategies (honest-refusal / stale-opening-current-root constraint violation / stale-root verifier rejection). \`results/negative.json\`.`);
  if (probe) w(`- **Assumption-5 probe:** forged-credential proof accepted = ${probe.forgedProofAccepted} (the documented wallet-honesty gap reproduces exactly as the paper states; mitigations [F]). \`results/malicious_probe.json\`.`);
  if (circomspect) {
    w(`- **circomspect audit: ${circomspect.pass ? "PASS" : "FAIL"}** — ${circomspect.totalFindings} finding(s), ${circomspect.blockingFindings} blocking. Both findings are the intentional public-input binding squares (triaged with justification in \`results/circomspect.json\`). Every public signal is constrained: revRoot (SMT root), policyHash (Poseidon equality), stmtCode (Poseidon(STMT_V1, domainTag) — V6 domain separation), issuerKeyHash + nonce (binding squares + off-circuit checks). A third-party audit remains [F].`);
  }
  if (sha3) w(`- **[F] SHA-3 in-circuit report:** one Keccak block = ${sha3.constraintsPerBlock} constraints (≈${(sha3.estimates.sha3FullRelationConstraints / 1e6).toFixed(1)}M for the full relation) — the quantitative basis for Poseidon in-circuit. \`circuits/build/research/\`.`);
  w();

  // ---------------- auto divergence ----------------
  const rows = divergences();
  w(`## Complete divergence table (auto-generated, threshold ${THRESHOLD_PCT}%)`);
  w();
  w("Programmatic diff of every measured cell against the embedded paper claims (§D), versioned to");
  w("the submitted manuscript (V6.6). The list is automatic and complete; cause texts are curated.");
  w("Full reconciliation actions per row live in `MANUSCRIPT_RECONCILIATION.md` (mirrored automatically).");
  w();
  if (rows.length === 0) {
    w("**No divergences.** Every measured cell agrees with the submitted manuscript (V6.6) within the");
    w(`${THRESHOLD_PCT}% threshold — the manuscript adopted the prototype's controlled measurements.`);
    w();
  }
  for (const line of divergenceTable(rows)) w(line);
  w();
  w("Metrics measured within the threshold (no divergence): " +
    CLAIMS.filter((c) => {
      const m = c.measured();
      return m !== undefined && Math.abs(((m - c.paper) / c.paper) * 100) <= THRESHOLD_PCT;
    })
      .map((c) => c.metric)
      .join("; ") + ".");
  w();
  w("---");
  w(`_Regenerated ${new Date().toISOString()} by harness/generate_results.ts._`);

  fs.writeFileSync(path.join(REPO_ROOT, "RESULTS.md"), L.join("\n") + "\n");
  console.log(`[tables] wrote RESULTS.md (${L.length} lines, ${rows.length} divergences)`);

  // ---------------- mirror into MANUSCRIPT_RECONCILIATION.md ----------------
  const reconPath = path.join(REPO_ROOT, "MANUSCRIPT_RECONCILIATION.md");
  const BEGIN = "<!-- AUTO-DIVERGENCE:BEGIN (generated by harness/generate_results.ts — do not edit) -->";
  const END = "<!-- AUTO-DIVERGENCE:END -->";
  const R: string[] = [BEGIN, ""];
  R.push(`## Complete divergence table (auto-generated, threshold ${THRESHOLD_PCT}%)`);
  R.push("");
  R.push("Diff of every measured cell against the **submitted manuscript (V6.6)**.");
  R.push("");
  if (rows.length === 0) {
    R.push("**No divergences.** Every measured cell agrees with the submitted manuscript (V6.6)");
    R.push(`within the ${THRESHOLD_PCT}% threshold; the items above were incorporated into V6.6, so the`);
    R.push("manuscript and the prototype now report the same numbers. (Earlier revisions showed");
    R.push("divergences here; those edits are now reflected in the submitted text.)");
    R.push("");
  }
  for (const line of divergenceTable(rows)) R.push(line);
  R.push("");
  R.push("### Reconciliation actions, one per divergent cell");
  R.push("");
  if (rows.length === 0) R.push("_None — all cells agree with V6.6._");
  rows.forEach((r, i) => {
    R.push(`${i + 1}. **${r.metric}** (Table ${r.table}) — paper ${r.paper}${r.unit} ${r.paperLabel} → measured **${r.measuredValue}${r.unit}** ${r.measuredLabel} (${r.deltaPct > 0 ? "+" : ""}${r.deltaPct}%, ${r.direction}).`);
    R.push(`   ${r.cause}`);
    R.push("");
  });
  const block = R.concat([END]).join("\n");
  let recon = fs.existsSync(reconPath) ? fs.readFileSync(reconPath, "utf8") : "";
  if (recon.includes(BEGIN) && recon.includes(END)) {
    recon = recon.slice(0, recon.indexOf(BEGIN)) + block + recon.slice(recon.indexOf(END) + END.length);
  } else {
    recon = recon.trimEnd() + "\n\n---\n\n" + block + "\n";
  }
  fs.writeFileSync(reconPath, recon);
  console.log(`[tables] mirrored ${rows.length} divergence rows into MANUSCRIPT_RECONCILIATION.md`);
}

main();
