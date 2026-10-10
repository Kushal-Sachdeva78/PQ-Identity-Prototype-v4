import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import net from "node:net";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { World } from "@pqid/v4/world";
import { anvilBinary } from "@pqid/ledger/evm";
import { LedgerV4, RegistryRevertError } from "@pqid/v4/ledger";
import { VerifierV4, type PresentationV4, type VerifyDecisionV4 } from "@pqid/v4/verifier";
import { issuanceWitnessV4, revocationWitnessV4, revokeCredentialV4, sigHashOf, type EpochStatementV4 } from "@pqid/v4/issuer";
import { epochMessage } from "@pqid/v4/statements";
import { mlDsaVerify } from "@pqid/v4/pqc";
import { proveV4, verifyV4, loadVkeyV4 } from "@pqid/v4/prove";
import { DEFAULT_TYPE_ID } from "@pqid/v4/constants";
import { R1CS_V4, WASM_V4, ZKEY_V4, VKEY_V4, REPO_ROOT } from "@pqid/v4/paths";
import { attackerSession, forgedInput, heldOf, honest, type HeldData, type Forge } from "../../../harness/v4/suite_lib.ts";
import { walletSealReply } from "@pqid/v4/session";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const runName = process.argv[2];
if (!runName || !/^attempt_[0-9]{3}$/.test(runName)) throw new Error("Usage: run.ts attempt_NNN");
const OUT = path.join(HERE, runName);
const sha = (x: Buffer | string) => createHash("sha256").update(x).digest("hex");
const hashFile = (p: string) => sha(fs.readFileSync(p));
function resolvedAnvilBinary(): string {
  const configured = anvilBinary();
  if (path.isAbsolute(configured) || configured.includes('/') || configured.includes('\\')) return path.resolve(configured);
  const suffixes = process.platform === 'win32' && !path.extname(configured)
    ? ['', ...(process.env.PATHEXT ?? '.EXE;.COM').split(';')]
    : [''];
  for (const directory of [process.cwd(), ...(process.env.PATH ?? '').split(path.delimiter)]) {
    for (const suffix of suffixes) {
      const candidate = path.join(directory, configured + suffix);
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
    }
  }
  throw new Error('Cannot resolve selected Anvil binary for its provenance hash');
}
const rel = (p: string) => path.relative(REPO_ROOT, p).replaceAll("\\", "/");
const scrub = (s: string) => s.replaceAll(REPO_ROOT, "<repo>").replaceAll(REPO_ROOT.replaceAll("\\", "/"), "<repo>").replace(/C:\\Users\\[^\\\s]+/gi, "<home>");
const write = (name: string, data: unknown) => fs.writeFileSync(path.join(OUT, name), JSON.stringify(data, (_k, v: unknown) => typeof v === "bigint" ? v.toString() : v, 2) + "\n");
function insist(ok: unknown, text: string): asserts ok { if (!ok) throw new Error(text); }
function walk(p: string): string[] { return fs.readdirSync(p, { withFileTypes: true }).flatMap(x => x.isDirectory() ? walk(path.join(p, x.name)) : [path.join(p, x.name)]); }
const files = [...walk(path.join(REPO_ROOT, "packages")).filter(p => /\.(ts|json)$/.test(p)), path.join(REPO_ROOT, "onchain/contracts/v4/RegistriesV4.sol"), path.join(REPO_ROOT, "harness/v4/suite_lib.ts"), path.join(REPO_ROOT, "harness/v4/r1cs_tools.ts"), path.join(REPO_ROOT, "circuits/credential_auth_v4.circom"), path.join(REPO_ROOT, "circuits/v4/lib_v4.circom"), path.join(REPO_ROOT, "setup/pins_v4.json"), R1CS_V4, WASM_V4, ZKEY_V4, VKEY_V4];
const sourceHashes = () => Object.fromEntries(files.map(p => [rel(p), hashFile(p)]));

type Rpc = { id: number | string; jsonrpc: string; method: string; params?: any[] };
type ProxyTrace = { mode: string; method: string; originalTag?: unknown; forwardedTag?: unknown; responseSha256?: string; error?: string };
async function readProxy(upstream: string, trace: ProxyTrace[]) {
  let staleBlock: number | null = null;
  const server = http.createServer(async (req, res) => {
    try {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(Buffer.from(c));
      const input: Rpc | Rpc[] = JSON.parse(Buffer.concat(chunks).toString());
      const processRpc = async (q: Rpc) => {
        const copy = structuredClone(q);
        const t: ProxyTrace = { mode: staleBlock === null ? "live" : `stale-block-${staleBlock}`, method: q.method };
        trace.push(t);
        const allowed = new Set(["eth_chainId", "net_version", "eth_call", "eth_getLogs", "eth_blockNumber", "eth_getBlockByNumber", "eth_getCode"]);
        if (!allowed.has(q.method)) throw new Error(`read-only proxy rejected method ${q.method}`);
        if (staleBlock !== null) {
          const blockHex = `0x${staleBlock.toString(16)}`;
          if (q.method === "eth_blockNumber") return { jsonrpc: "2.0", id: q.id, result: blockHex };
          if (q.method === "eth_call" || q.method === "eth_getCode") {
            copy.params ??= [];
            t.originalTag = copy.params[1];
            if (!copy.params[1] || ["latest", "pending", "safe", "finalized"].includes(copy.params[1]) || Number(copy.params[1]) > staleBlock) copy.params[1] = blockHex;
            t.forwardedTag = copy.params[1];
          }
          if (q.method === "eth_getBlockByNumber") {
            copy.params ??= [];
            t.originalTag = copy.params[0];
            if (["latest", "pending", "safe", "finalized"].includes(copy.params[0]) || Number(copy.params[0]) > staleBlock) copy.params[0] = blockHex;
            t.forwardedTag = copy.params[0];
          }
          if (q.method === "eth_getLogs") {
            const filter = copy.params?.[0];
            if (filter) {
              if (Number(filter.fromBlock) > staleBlock) return { jsonrpc: "2.0", id: q.id, result: [] };
              if (!filter.toBlock || ["latest", "pending", "safe", "finalized"].includes(filter.toBlock) || Number(filter.toBlock) > staleBlock) filter.toBlock = blockHex;
              t.forwardedTag = filter.toBlock;
            }
          }
        }
        const answer = await fetch(upstream, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(copy) });
        if (!answer.ok) throw new Error(`upstream HTTP ${answer.status}`);
        const body = await answer.json();
        t.responseSha256 = sha(JSON.stringify(body));
        return body;
      };
      const output = Array.isArray(input) ? await Promise.all(input.map(processRpc)) : await processRpc(input);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(output));
    } catch (e) {
      const msg = scrub(String((e as Error).message));
      trace.push({ mode: "error", method: "unknown", error: msg });
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: msg }));
    }
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address() as net.AddressInfo;
  return { url: `http://127.0.0.1:${address.port}`, setStale: (n: number | null) => { staleBlock = n; }, close: async () => { server.closeAllConnections(); await new Promise<void>(r => server.close(() => r())); } };
}
async function unusedPort(): Promise<number> {
  const s = net.createServer();
  await new Promise<void>((resolve, reject) => { s.once("error", reject); s.listen(0, "127.0.0.1", resolve); });
  const port = (s.address() as net.AddressInfo).port;
  await new Promise<void>(r => s.close(() => r()));
  return port;
}

const startedUtc = new Date().toISOString();
const expected: Record<string, { accepted: boolean; failedChecks: string[]; kind: string }> = {
  H1: { accepted: true, failedChecks: [], kind: "honest-control" },
  H2: { accepted: true, failedChecks: [], kind: "honest-control" },
  R1: { accepted: false, failedChecks: ["epochAnchorCurrent"], kind: "canonical-view-attack" },
  R2: { accepted: false, failedChecks: ["epochAnchorCurrent"], kind: "canonical-view-attack" },
  S1: { accepted: true, failedChecks: [], kind: "stale-rpc-known-limitation" },
  S2: { accepted: true, failedChecks: [], kind: "stale-rpc-known-limitation" },
  N1: { accepted: false, failedChecks: ["epochWindow"], kind: "expired-control" },
  R3: { accepted: false, failedChecks: ["epochIncrement"], kind: "registry-rollback" },
  R4: { accepted: false, failedChecks: ["epochAnchorCurrent"], kind: "counter-relabel-attack" },
  N2: { accepted: false, failedChecks: ["epochSignature"], kind: "signature-control" },
  N3: { accepted: false, failedChecks: ["epochSignature"], kind: "unsigned-control" },
};
const cases: any[] = [];
const proxyTrace: ProxyTrace[] = [];
let world: World | undefined;
let proxy: Awaited<ReturnType<typeof readProxy>> | undefined;
let proxyLedger: LedgerV4 | undefined;
let before: Record<string, string> = {};
let markerHeld = false;
let failed = false;
const marker = path.join(HERE, "BUSY");
const context: Record<string, unknown> = { startedUtc, caseDesignDate: "2026-10-06", executionDateUtc: startedUtc.slice(0, 10), keyLabel: "dev", timedBenchmark: false, independentHoldout: false, source: "new internally authored supplementary cases", frozenCataloguesChanged: false, proxyScope: "local historic-block RPC fixture, same-host loopback; no consensus fork or authenticated light client" };
function save() { write("results.json", { ...context, cases, expected }); }
async function record(id: string, action: () => Promise<Record<string, any>>) {
  console.log(`START ${id}`);
  const start = new Date().toISOString();
  try {
    const out = await action();
    const wanted = expected[id]!;
    const actual = out.decision as VerifyDecisionV4 | undefined;
    const accepted = actual ? actual.accepted : out.accepted;
    const failedChecks = actual ? actual.failedChecks : out.failedChecks;
    const pass = accepted === wanted.accepted && JSON.stringify([...failedChecks].sort()) === JSON.stringify([...wanted.failedChecks].sort()) && !out.error;
    cases.push({ id, startedUtc: start, finishedUtc: new Date().toISOString(), expected: wanted, expectedOutcomeMet: pass, ...out });
    if (!pass) failed = true;
    save();
    console.log(`END ${id} expectedOutcomeMet=${pass} accepted=${accepted} failedChecks=${failedChecks.join(",")}`);
  } catch (e) {
    failed = true;
    cases.push({ id, startedUtc: start, finishedUtc: new Date().toISOString(), expected: expected[id], expectedOutcomeMet: false, error: scrub((e as Error).stack ?? String(e)) });
    save();
    console.log(`ERROR ${id}: ${scrub((e as Error).message)}`);
  }
}

async function main() {
  insist(!fs.existsSync(OUT), "Run directory already exists; choose another attempt name.");
  fs.mkdirSync(OUT);
  insist(!fs.existsSync(path.join(REPO_ROOT, "results/v4/BUSY")) && !fs.existsSync(path.join(REPO_ROOT, "results/v4/bench/RUNNING")), "Original results BUSY/RUNNING marker exists.");
  fs.writeFileSync(marker, JSON.stringify({ pid: process.pid, startedUtc, purpose: "untimed supplementary rollback" }) + "\n", { flag: "wx" });
  markerHeld = true;
  before = sourceHashes();
  context.protocolSha256 = hashFile(path.join(HERE, "PROTOCOL.md"));
  context.runnerSha256 = hashFile(fileURLToPath(import.meta.url));
  context.tsconfigSha256 = hashFile(path.join(HERE, "tsconfig.json"));
  context.environment = { node: process.version, openssl: process.versions.openssl, platform: process.platform, arch: process.arch, solc: JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "node_modules/solc/package.json"), "utf8")).version, snarkjs: JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "node_modules/snarkjs/package.json"), "utf8")).version };
  write("source_hashes_before.json", before);
  save();
  const port = await unusedPort();
  world = await World.create({ port });
  insist(world.anvil.proc.exitCode === null, "Own Anvil process exited; refuse existing endpoint.");
  context.anvil = { port, versionBinarySha256: hashFile(resolvedAnvilBinary()), freshLocalDeployment: true };
  world.clock.set(Date.UTC(2030, 0, 1, 6, 0, 0) / 1000);
  await world.syncChainTime();
  context.clockFixture = { initialUtc: "2030-01-01T06:00:00Z", purpose: "functional clock, no timing inference" };
  const issuer = await world.addIssuer("rollback-fixture");
  const holderA = await world.addHolder();
  const holderB = await world.addHolder();
  const vcA = await world.issue(issuer, holderA, { birthDate: 19840315, expiryDate: 20310101 });
  await world.issue(issuer, holderB, { birthDate: 19840315, expiryDate: 20310101 });
  const identity = await world.newVerifierIdentity("rollback-fixture", "https://rollback-fixture.verifier.example");
  const makeVerifier = (ledger: LedgerV4) => new VerifierV4({ ledger, identity, pinnedGovernancePk: world!.governance.pk, clock: world!.clock });
  const firstVerifier = makeVerifier(world.ledger);
  await world.publishEpoch(issuer);
  const oldIssuance = issuanceWitnessV4(issuer, vcA.credID);
  const oldRev = revocationWitnessV4(issuer, vcA.credID);
  const oldStatement = structuredClone(oldIssuance.statement);
  const oldAnchor = await world.ledger.currentEpoch(issuer.did, issuer.controller);
  const oldBlock = oldAnchor.publishedBlock;
  const { signature, ...signedFields } = oldStatement;
  insist(mlDsaVerify(issuer.pk, epochMessage(signedFields), Buffer.from(signature, "hex")), "Old statement signature did not verify.");
  const held: HeldData = heldOf(holderA, issuer, vcA);
  const oldForge: Forge = { path: oldIssuance.path, statement: oldStatement, rev: oldRev };
  const policy = { predicate: "age_gte" as const, threshold: 18, typeId: DEFAULT_TYPE_ID };
  context.publicFixture = { issuerPkHex: issuer.pk.toString("hex"), oldStatement, oldAnchor, registryAddresses: world.ledger.addresses, oldEpochSignatureValid: true };
  const present = async (verifier: VerifierV4, forge: Forge, proofName: string) => {
    const request = await verifier.newRequest(policy);
    const session = await attackerSession(world!, verifier, request);
    const { input, statement } = await forgedInput(world!, request, held, session.nonce, forge);
    const proved = await proveV4(input);
    const presentation: PresentationV4 = { proof: proved.proof, publicSignals: proved.publicSignals, issuerDid: issuer.did, issuerController: issuer.controller, epochStatement: structuredClone(statement) };
    forge.presentation?.(presentation);
    const proofVerifies = await verifyV4(loadVkeyV4(), presentation.publicSignals, presentation.proof);
    insist(proofVerifies, `Unexpected invalid Groth16 proof in ${proofName}`);
    const anchorSeen = await verifier.opts.ledger.currentEpoch(issuer.did, issuer.controller);
    const decision = await verifier.verifyReply(walletSealReply(session, presentation));
    write(`${proofName}_presentation.json`, presentation);
    const { signature: ps, ...pf } = presentation.epochStatement;
    return { decision, proofVerifies, epochSignatureValidIndependentCheck: mlDsaVerify(issuer.pk, epochMessage(pf), Buffer.from(ps, "hex")), verifierClockSec: world!.clock.nowSec(), oldEpochStillWithinWindow: world!.clock.nowSec() >= oldStatement.notBefore && world!.clock.nowSec() <= oldStatement.notAfter, anchorSeen, presentedEpoch: presentation.epochStatement.epoch, allVerifierChecksEnabled: verifier.disabled.size === 0 };
  };
  await record("H1", async () => { const h = await honest(holderA, firstVerifier, policy); write("H1_presentation.json", h.presentation); return { decision: h.decision, anchoredEpoch: 1, holderRevoked: false }; });
  await world.advance(3601);
  revokeCredentialV4(issuer, vcA.credID);
  await world.publishEpoch(issuer);
  const latestStatement = structuredClone(issuer.anchored!.statement);
  insist(latestStatement.epoch === 2 && latestStatement.root === oldStatement.root && latestStatement.revRoot !== oldStatement.revRoot, "Epoch fixture failed to keep issuance root and change revocation root.");
  insist(world.clock.nowSec() <= oldStatement.notAfter, "Old epoch unexpectedly expired.");
  let targetRevoked = false;
  try { revocationWitnessV4(issuer, vcA.credID); } catch { targetRevoked = true; }
  insist(targetRevoked, "A still has a non-membership witness in epoch 2.");
  context.latestEpoch = { statement: latestStatement, targetRevoked, latestAnchor: await world.ledger.currentEpoch(issuer.did, issuer.controller) };
  proxy = await readProxy(world.anvil.rpcUrl, proxyTrace);
  proxyLedger = await LedgerV4.connect(proxy.url, world.ledger.addresses);
  const remembered = makeVerifier(proxyLedger);
  await record("H2", async () => { const h = await honest(holderB, remembered, policy); write("H2_presentation.json", h.presentation); insist(h.decision.accepted, "Remembered verifier did not first accept epoch 2."); return { decision: h.decision, anchoredEpoch: 2, holderBRevoked: false, rememberedInstanceLaterUsedIn: ["R2", "S2"] }; });
  const h2 = cases.find(c => c.id === "H2");
  insist(h2?.decision?.accepted, "Cannot claim remembered condition without H2 acceptance.");
  await record("R1", () => present(makeVerifier(world!.ledger), oldForge, "R1"));
  await record("R2", () => present(remembered, oldForge, "R2"));
  proxy.setStale(oldBlock);
  const staleFresh = makeVerifier(proxyLedger);
  await record("S1", async () => ({ ...(await present(staleFresh, oldForge, "S1")), verifierHistory: "fresh", staleBlock: oldBlock }));
  await record("S2", async () => ({ ...(await present(remembered, oldForge, "S2")), verifierHistory: "accepted epoch 2 at H2; same verifier instance", staleBlock: oldBlock }));
  const beforeExpiryClock = world.clock.nowSec();
  world.clock.set(oldStatement.notAfter + 1);
  await record("N1", () => present(makeVerifier(proxyLedger!), oldForge, "N1"));
  world.clock.set(beforeExpiryClock);
  proxy.setStale(null);
  await world.advance(3601);
  const anchorArgs = (st: EpochStatementV4) => ({ did: issuer.did, epoch: st.epoch, root: st.root, revRoot: st.revRoot, notBefore: st.notBefore, notAfter: st.notAfter, sigHash: sigHashOf(st.signature) });
  await record("R3", async () => {
    try { const receipt = await world!.ledger.publishEpoch(issuer.account, anchorArgs(oldStatement)); return { accepted: true, failedChecks: [], receipt }; }
    catch (e) { if (!(e instanceof RegistryRevertError)) throw e; return { accepted: false, failedChecks: e.check ? [e.check] : [], registryRevert: { method: e.method, reason: e.reason, check: e.check, mined: e.mined }, anchorAfter: await world!.ledger.currentEpoch(issuer.did, issuer.controller) }; }
  });
  const relabelled = { ...oldStatement, epoch: 3 };
  await record("R4", async () => {
    const receipt = await world!.ledger.publishEpoch(issuer.account, anchorArgs(relabelled));
    return { registryWriteAccepted: true, receipt, ...(await present(makeVerifier(world!.ledger), oldForge, "R4")) };
  });
  await record("N2", () => present(makeVerifier(world!.ledger), { ...oldForge, statement: relabelled }, "N2"));
  await world.advance(3601);
  const unsigned = { ...oldStatement, epoch: 4, signature: "00".repeat(2420) };
  await record("N3", async () => {
    const receipt = await world!.ledger.publishEpoch(issuer.account, anchorArgs(unsigned));
    return { registryWriteAccepted: true, receipt, ...(await present(makeVerifier(world!.ledger), { ...oldForge, statement: unsigned }, "N3")) };
  });
  insist(cases.length === Object.keys(expected).length, "Case count differs from predeclared set.");
  insist(proxyTrace.some(t => t.mode.startsWith("stale") && t.method === "eth_call" && t.forwardedTag === `0x${oldBlock.toString(16)}`), "No historic RPC eth_call observed.");
}

try { await main(); }
catch (e) { failed = true; context.fatal = scrub((e as Error).stack ?? String(e)); console.log(`FATAL ${scrub((e as Error).message)}`); }
finally {
  proxyLedger?.destroy();
  if (proxy) await proxy.close();
  world?.stop();
  if (Object.keys(before).length) {
    const after = sourceHashes();
    write("source_hashes_after.json", after);
    context.sourceAndArtifactHashesUnchanged = JSON.stringify(before) === JSON.stringify(after);
    if (!context.sourceAndArtifactHashesUnchanged) failed = true;
  }
  if (fs.existsSync(OUT)) {
    write("proxy_trace.json", proxyTrace);
    context.finishedUtc = new Date().toISOString();
    context.status = failed ? "FAILED" : "COMPLETE";
    context.summary = { casesExecuted: cases.length, expectedOutcomesMet: cases.filter(c => c.expectedOutcomeMet).length, unexpectedErrors: cases.filter(c => c.error).length, honestControlsAccepted: cases.filter(c => c.expected?.kind === "honest-control" && c.decision?.accepted).length, staleRpcAcceptances: cases.filter(c => c.expected?.kind === "stale-rpc-known-limitation" && c.decision?.accepted).length, proxyReadCount: proxyTrace.length };
    save();
  }
  if (markerHeld) fs.unlinkSync(marker);
}
console.log(JSON.stringify({ status: context.status, summary: context.summary }));
process.exit(failed ? 1 : 0);
