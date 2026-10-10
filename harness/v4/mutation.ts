import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { REPO_ROOT, PTAU_FILE } from "@pqid/common/paths";
import { hostMeta } from "@pqid/common/meta";
import { sha256File } from "@pqid/common/hash";
import { VERIFIER_CHECKS } from "@pqid/v4/verifier";
import { WALLET_CHECKS } from "@pqid/v4/wallet";
import { REGISTRY_CHECKS, CONTRACTS_V4_FILE } from "@pqid/v4/ledger";
import { allGroups, buildMutant, MUTANTS_DIR } from "./mutate.ts";

/**
 * Mutation table (C3). Remove each defence one at a time, rebuild what it lives in, run the
 * WHOLE security suite (harness/v4/security_suite.ts) against the weakened system, and record
 * which routes then succeed. Defences:
 *   - circuit: each constraint group of circuits/credential_auth_v4.circom (mutant circuit,
 *     throwaway Groth16 key: newZKey + one random contribution, never pinned);
 *   - verifier: each named check of packages/v4/src/verifier.ts;
 *   - wallet: each named check of packages/v4/src/wallet.ts;
 *   - registry: each named `require` of onchain/contracts/v4/RegistriesV4.sol;
 *   - governance: the proof-of-possession check before accreditation.
 * A defence whose removal lets no route through is a finding: redundant or untested.
 *
 * Usage: tsx harness/v4/mutation.ts [--only <kind>:<name>,...] [--jobs 2]
 * Output: results/v4/mutation/<kind>__<name>/security_suite.json, results/v4/mutation.json
 */

interface Defence {
  kind: "circuit" | "verifier" | "wallet" | "registry" | "governance";
  name: string;
}

const OUT = path.join(REPO_ROOT, "results", "v4", "mutation");
const BASELINE = path.join(REPO_ROOT, "results", "v4", "security_suite.json");

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

async function mutantKey(dir: string, r1cs: string): Promise<{ zkey: string; vkeyFile: string }> {
  const zkey = path.join(dir, "mutant_throwaway.zkey");
  const vkeyFile = path.join(dir, "mutant_throwaway_vkey.json");
  const stamp = path.join(dir, "mutant_throwaway.r1cs.sha256");
  const sha = sha256File(r1cs);
  if (fs.existsSync(zkey) && fs.existsSync(vkeyFile) && fs.existsSync(stamp) && fs.readFileSync(stamp, "utf8") === sha) return { zkey, vkeyFile };
  const snarkjs = await import("snarkjs");
  const z0 = path.join(dir, "m0.zkey");
  const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined, debug: () => undefined };
  await snarkjs.zKey.newZKey(r1cs, PTAU_FILE, z0, quiet);
  await (snarkjs.zKey as unknown as { contribute(a: string, b: string, n: string, e: string, l?: unknown): Promise<unknown> }).contribute(z0, zkey, "mutant throwaway", randomBytes(32).toString("hex"), quiet);
  fs.rmSync(z0, { force: true });
  fs.writeFileSync(vkeyFile, JSON.stringify(await snarkjs.zKey.exportVerificationKey(zkey), null, 1));
  fs.writeFileSync(stamp, sha);
  return { zkey, vkeyFile };
}

/** Contracts with the `require` of one registry check removed. */
function mutantContracts(check: string): string {
  const src = fs.readFileSync(CONTRACTS_V4_FILE, "utf8");
  const re = new RegExp(`require\\((?:[^;]|\\n)*?"${check}:[^"]*"\\s*\\);`, "g");
  const n = (src.match(re) ?? []).length;
  if (n === 0) throw new Error(`no require for registry check ${check}`);
  const out = src.replace(re, `/* [mutant] removed registry check ${check} */`);
  const dir = path.join(MUTANTS_DIR, "contracts");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `RegistriesV4__no_${check}.sol`);
  fs.writeFileSync(file, out);
  return file;
}

async function prepare(d: Defence, port: number): Promise<{ cfgFile: string; env: NodeJS.ProcessEnv; out: string }> {
  const out = path.join(OUT, `${d.kind}__${d.name}`);
  fs.mkdirSync(out, { recursive: true });
  const cfg: Record<string, unknown> = { name: `${d.kind}:${d.name}`, port, out };
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env["PQID_V4_CONTRACTS"];
  if (d.kind === "circuit") {
    const m = buildMutant(d.name);
    const k = await mutantKey(m.dir, m.r1cs);
    cfg["mutantGroup"] = d.name;
    cfg["artifacts"] = {
      r1cs: m.r1cs,
      sym: m.sym,
      zkey: k.zkey,
      wasm: m.wasm,
      vkeyFile: k.vkeyFile,
      src: path.join(m.dir, "credential_auth_v4.circom"),
      attackerDir: path.join(m.dir, "attacker"),
      keyLabel: "mutant-throwaway",
    };
  } else if (d.kind === "verifier") cfg["verifierDisabled"] = [d.name];
  else if (d.kind === "wallet") cfg["walletDisabled"] = [d.name];
  else if (d.kind === "governance") cfg["governanceSkipPop"] = true;
  else if (d.kind === "registry") env["PQID_V4_CONTRACTS"] = mutantContracts(d.name);
  const cfgFile = path.join(out, "config.json");
  fs.writeFileSync(cfgFile, JSON.stringify(cfg, null, 2));
  return { cfgFile, env, out };
}

function runSuite(cfgFile: string, env: NodeJS.ProcessEnv, logFile: string): Promise<number> {
  return new Promise((resolve) => {
    const tsx = path.join(REPO_ROOT, "node_modules", "tsx", "dist", "cli.mjs");
    const child = spawn(process.execPath, [tsx, path.join(REPO_ROOT, "harness", "v4", "security_suite.ts"), "--config", cfgFile], { env, cwd: REPO_ROOT });
    const log = fs.createWriteStream(logFile);
    child.stdout.pipe(log);
    child.stderr.pipe(log);
    const timer = setTimeout(() => child.kill(), 40 * 60_000);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve(code ?? -1);
    });
  });
}

interface SuiteFile {
  records: Array<{ id: string; kind: string; attempts: Array<{ route: string; accepted: boolean; valid: boolean; stoppedBy: { layer: string; checks: string[] }; detail?: string }> }>;
}

function verdicts(f: SuiteFile) {
  const m = new Map<string, { kind: string; accepted: boolean; valid: boolean; stoppedBy: string; detail?: string }>();
  for (const r of f.records) for (const a of r.attempts) m.set(`${r.id}|${a.route}`, { kind: r.kind, accepted: a.accepted, valid: a.valid, stoppedBy: `${a.stoppedBy.layer}:${a.stoppedBy.checks.join("+")}`, detail: a.detail });
  return m;
}

async function main(): Promise<void> {
  if (!fs.existsSync(BASELINE)) throw new Error("run harness/v4/security_suite.ts first (baseline)");
  const base = verdicts(JSON.parse(fs.readFileSync(BASELINE, "utf8")) as SuiteFile);
  let defences: Defence[] = [
    ...allGroups().map((name) => ({ kind: "circuit" as const, name })),
    ...VERIFIER_CHECKS.map((name) => ({ kind: "verifier" as const, name })),
    ...WALLET_CHECKS.map((name) => ({ kind: "wallet" as const, name })),
    ...REGISTRY_CHECKS.map((name) => ({ kind: "registry" as const, name })),
    { kind: "governance", name: "issuerPopBeforeAccreditation" },
  ];
  const only = arg("--only");
  if (only) {
    const want = new Set(only.split(","));
    defences = defences.filter((d) => want.has(`${d.kind}:${d.name}`) || want.has(d.kind));
  }
  const jobs = Number(arg("--jobs") ?? 2);
  fs.mkdirSync(OUT, { recursive: true });
  const queue = [...defences];
  const rows: Array<Record<string, unknown>> = [];
  let port = 8600;
  const worker = async () => {
    for (;;) {
      const d = queue.shift();
      if (!d) return;
      const myPort = port++;
      const t0 = Date.now();
      let row: Record<string, unknown>;
      try {
        const { cfgFile, env, out } = await prepare(d, myPort);
        const code = await runSuite(cfgFile, env, path.join(out, "run.log"));
        const file = path.join(out, "security_suite.json");
        if (!fs.existsSync(file)) throw new Error(`suite produced no output (exit ${code})`);
        const v = verdicts(JSON.parse(fs.readFileSync(file, "utf8")) as SuiteFile);
        const nowAccepted: string[] = [];
        const controlsBroken: string[] = [];
        const invalid: string[] = [];
        const layerShift: string[] = [];
        for (const [k, b] of base) {
          const x = v.get(k);
          if (!x) {
            invalid.push(`${k}: missing`);
            continue;
          }
          if ((b.kind === "attack" || b.kind === "privacy") && !b.accepted && x.accepted) nowAccepted.push(k);
          else if (b.kind === "control" && b.accepted && !x.accepted) controlsBroken.push(`${k}: ${x.stoppedBy}`);
          else if (!x.accepted && b.stoppedBy !== x.stoppedBy) layerShift.push(`${k}: ${b.stoppedBy} -> ${x.stoppedBy}`);
          if (b.valid && !x.valid && !x.accepted && x.detail?.startsWith("unexpected exception")) invalid.push(`${k}: ${x.detail.slice(0, 200)}`);
        }
        row = { ...d, exit: code, seconds: Math.round((Date.now() - t0) / 1000), routesNowAccepted: nowAccepted, controlsBroken, stoppedElsewhere: layerShift, harnessErrors: invalid };
      } catch (e) {
        row = { ...d, error: (e as Error).message.slice(0, 500), seconds: Math.round((Date.now() - t0) / 1000) };
      }
      rows.push(row);
      console.log(`[mutation] ${d.kind}:${d.name} -> ${JSON.stringify({ accepted: (row["routesNowAccepted"] as string[] | undefined)?.length ?? "ERR", controlsBroken: (row["controlsBroken"] as string[] | undefined)?.length ?? "-", s: row["seconds"] })}`);
      fs.writeFileSync(path.join(REPO_ROOT, "results", "v4", "mutation_progress.json"), JSON.stringify(rows, null, 2));
    }
  };
  await Promise.all(Array.from({ length: jobs }, () => worker()));
  const out = {
    schema: "pqid/v4-mutation-table/v1",
    label: "[M] one defence removed at a time; whole v4 suite re-run per mutant (circuit mutants use throwaway keys)",
    baseline: { file: "results/v4/security_suite.json", sha256: sha256File(BASELINE) },
    rows: rows.sort((a, b) => `${a["kind"]}:${a["name"]}`.localeCompare(`${b["kind"]}:${b["name"]}`)),
    noEffect: rows.filter((r) => Array.isArray(r["routesNowAccepted"]) && (r["routesNowAccepted"] as string[]).length === 0).map((r) => `${r["kind"]}:${r["name"]}`),
    host: hostMeta(),
  };
  const file = only ? path.join(REPO_ROOT, "results", "v4", `mutation_partial_${Date.now()}.json`) : path.join(REPO_ROOT, "results", "v4", "mutation.json");
  fs.writeFileSync(file, JSON.stringify(out, null, 2));
  console.log(`[mutation] done -> ${path.relative(REPO_ROOT, file)}; no-effect defences: ${out.noEffect.length}`);
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
