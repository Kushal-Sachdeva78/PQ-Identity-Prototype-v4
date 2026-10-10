import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { version as ETHERS_VERSION } from "ethers";
import { REPO_ROOT, envInfo, gitHead, protocolSha, sanitize, snarkjsVersion } from "../bench/lib.ts";
import { SEED_REGISTRY } from "../lib/seeds.ts";
import { PORTS } from "../lib/ports.ts";
import { ROUND_TRIP_DEFINITION } from "../lib/rpc_trace.ts";
import { environmentName, isWsl } from "./host.ts";

/**
 * Environment record of a chain-read run (env.json): no usernames, hostnames or home paths.
 * Host facts come from harness/v4/bench/lib.ts envInfo (portable Node APIs; no Windows call
 * besides the guard's power query), paths are repo-relative, free text is sanitized.
 */

export const CHAINREAD_DOC = path.join(REPO_ROOT, "docs", "v4", "CHAINREAD.md");

function sha256File(rel: string): string | null {
  const f = path.join(REPO_ROOT, ...rel.split("/"));
  try {
    return createHash("sha256").update(fs.readFileSync(f)).digest("hex");
  } catch {
    return null;
  }
}

/** sha256 of docs/v4/CHAINREAD.md above "## Deviations" (LF line ends) and of the whole file. */
export function chainreadProtocolSha(): { normative: string; file: string } {
  if (!fs.existsSync(CHAINREAD_DOC)) throw new Error("docs/v4/CHAINREAD.md missing: the chain-read protocol must exist before any run");
  const text = fs.readFileSync(CHAINREAD_DOC, "utf8").replace(/\r\n/g, "\n");
  const cut = text.indexOf("\n## Deviations");
  if (cut < 0) throw new Error("docs/v4/CHAINREAD.md has no '## Deviations' section");
  return { normative: createHash("sha256").update(text.slice(0, cut)).digest("hex"), file: sha256File("docs/v4/CHAINREAD.md") as string };
}

/** The chain-read code and the shared code it runs (hashes tie results to the code). */
export function harnessFiles(): string[] {
  const list = (dir: string, re: RegExp) =>
    fs
      .readdirSync(path.join(REPO_ROOT, ...dir.split("/")))
      .filter((f) => re.test(f))
      .sort()
      .map((f) => `${dir}/${f}`);
  const scripts = fs.existsSync(path.join(REPO_ROOT, "scripts", "chainread")) ? list("scripts/chainread", /\.(sh|py)$/) : [];
  return [
    ...list("harness/v4/chainread", /\.(ts|sol)$/),
    ...list("harness/v4/lib", /\.ts$/),
    "harness/v4/scale_lib.ts",
    "harness/v4/bench/guard.ts",
    "harness/v4/bench/lib.ts",
    "scripts/besu/setup_qbft.sh",
    "scripts/wsl/besu_wsl_setup.sh",
    ...scripts,
  ];
}

/** The E4 code-under-test list (scale.ts header): contract, packages/v4/src, issuance, dev vkey. */
export function sourceFiles(): string[] {
  return [
    "onchain/contracts/v4/RegistriesV4.sol",
    ...fs
      .readdirSync(path.join(REPO_ROOT, "packages", "v4", "src"))
      .filter((f) => f.endsWith(".ts"))
      .sort()
      .map((f) => `packages/v4/src/${f}`),
    "packages/issuer/src/issuance.ts",
    "setup/out/v4/verification_key_dev.json",
  ];
}

export interface SourceComparison {
  e4File: string;
  equal: boolean;
  differing: string[];
  missingInE4: string[];
  note: string;
}

/** Compare the code under test with the hashes E4 recorded in results/v4/scale/verifier.json. */
export function compareSourcesWithE4(): { sourceSha256: Record<string, string | null>; vsE4: SourceComparison } {
  const sourceSha256 = Object.fromEntries(sourceFiles().map((f) => [f, sha256File(f)]));
  const e4File = "results/v4/scale/verifier.json";
  let e4: Record<string, string> = {};
  try {
    e4 = (JSON.parse(fs.readFileSync(path.join(REPO_ROOT, ...e4File.split("/")), "utf8")) as { sourceSha256?: Record<string, string> }).sourceSha256 ?? {};
  } catch {
    /* no E4 file in this checkout */
  }
  const differing = Object.keys(sourceSha256).filter((f) => f in e4 && e4[f] !== sourceSha256[f]);
  const missingInE4 = Object.keys(sourceSha256).filter((f) => !(f in e4));
  const extraInE4 = Object.keys(e4).filter((f) => !(f in sourceSha256));
  return {
    sourceSha256,
    vsE4: {
      e4File,
      equal: differing.length === 0 && missingInE4.length === 0 && extraInE4.length === 0 && Object.keys(e4).length > 0,
      differing,
      missingInE4: [...missingInE4, ...extraInE4.map((f) => `${f} (only in E4)`)],
      note: "the as-shipped variant is comparable with E4 only when the code under test is byte-identical (D-034 freezes packages/v4 for the measurement period)",
    },
  };
}

function pkgVersion(name: string): string | null {
  try {
    return (JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "node_modules", ...name.split("/"), "package.json"), "utf8")) as { version?: string }).version ?? null;
  } catch {
    return null;
  }
}

/** execArgv with anything that names a local path removed. */
function safeExecArgv(): string[] {
  return process.execArgv.map((s) => {
    const t = sanitize(s);
    return /<repo>|<home>|<tmp>|<user>|[A-Za-z]:[\\/]|^\//.test(t) || t.includes("/") ? "<path omitted>" : t;
  });
}

export function baseEnvironment(): Record<string, unknown> {
  return {
    environment: environmentName(),
    isWsl: isWsl(),
    host: envInfo(),
    osRelease: os.release(),
    uptimeSec: Math.round(os.uptime()),
    freeMemGiB: Math.round((os.freemem() / 2 ** 30) * 10) / 10,
    runtime: {
      node: process.version,
      openssl: process.versions.openssl ?? null,
      v8: process.versions.v8 ?? null,
      uv: process.versions.uv ?? null,
      execArgv: safeExecArgv(),
      ethers: ETHERS_VERSION,
      snarkjs: snarkjsVersion(),
      solc: pkgVersion("solc"),
      tsx: pkgVersion("tsx"),
    },
    gitHead: gitHead(),
    protocol: { benchProtocol: protocolSha(), chainread: chainreadProtocolSha() },
    harnessSha256: Object.fromEntries(harnessFiles().map((f) => [f, sha256File(f)])),
    seeds: SEED_REGISTRY.filter((e) => e.row === "chainRead" || e.row === "analysis"),
    ports: { anvilWsl: PORTS.chainReadAnvilWsl, anvilWindows: PORTS.chainReadAnvilWindows, besuQbft: PORTS.besuQbft },
    timer: "process.hrtime.bigint() (monotonic, ns), reported in ms",
    roundTripDefinition: ROUND_TRIP_DEFINITION,
    networkLabel: "loopback, same host (D-034): the node listens on 127.0.0.1 of the same laptop (per target: target.endpoint)",
    keyLabel: "dev (v4 Groth16 dev key; proving untimed)",
  };
}
