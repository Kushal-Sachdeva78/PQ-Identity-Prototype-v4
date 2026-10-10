import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import type { AddressInfo } from 'node:net';
import { startAnvil, type AnvilHandle } from '@pqid/v4/ledger';
import { setupLocal, endpointRecord, type E2eSetup } from '../../../harness/v4/e2e/setup.ts';
import { buildParties, runPresentation, resetAgents, setInstrumented, destroyParties, CryptoHooks, type PartySet } from '../../../harness/v4/e2e/presentation.ts';
import { DEV_KEY_SPEC, checkKeySpec, runKeyOf, findSecrets, stateDocNeedles, type SecretNeedle } from '../../../harness/v4/e2e/lib.ts';
import { readPower } from '../../../harness/v4/bench/guard.ts';
import { readQuiesceExcluding } from '../../../harness/v4/lib/quiesce.ts';

const mode = process.argv[2];
if (!['preflight', 'smoke', 'run'].includes(mode ?? '')) throw new Error('mode required');
const smoke = mode === 'smoke';
const win = process.env.PQID_WINDOWS_REPO!;
const source = process.env.PQID_SOURCE_ROOT!;
const nativeSource = process.env.PQID_NATIVE_SOURCE!;
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const out = path.join(nativeSource, 'runs', `${stamp}-${mode}`);
const marker = path.join(nativeSource, 'RUNNING');
const sha = (f: string) => createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const round = (x: number) => Math.round(x * 1000) / 1000;
const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));
let needles: SecretNeedle[] = [];
function safeText(value: unknown): string {
  const s = JSON.stringify(value);
  if (findSecrets(s, needles).length) throw new Error('result secret scan refused output');
  if (s.includes(os.homedir()) || s.includes(win) || s.includes(source)) throw new Error('result contains private path');
  return s;
}
function write(name: string, value: unknown): void { fs.writeFileSync(path.join(out, name), safeText(value) + '\n'); }
function append(name: string, value: unknown): void { fs.appendFileSync(path.join(out, name), safeText(value) + '\n'); }
function cleanError(e: unknown): string {
  let s = String((e as Error)?.message ?? e).split('\n')[0]!.slice(0, 500);
  for (const p of [win, source, os.homedir(), process.env.PQID_STAGE_ROOT!]) if (p) s = s.split(p).join('[local path]');
  if (findSecrets(s, needles).length) return 'error text withheld by secret scan';
  return s;
}
function files(root: string, rel: string): string[] {
  const p = path.join(root, rel);
  if (!fs.existsSync(p)) throw new Error(`missing source path: ${rel}`);
  if (fs.statSync(p).isFile()) return [rel];
  return fs.readdirSync(p).sort().flatMap(n => {
    if (['node_modules', 'dist', 'build'].includes(n)) return [];
    const r = `${rel}/${n}`;
    if (fs.statSync(path.join(root, r)).isDirectory()) return files(root, r);
    return /\.(ts|mjs|cjs|sol|json)$/.test(n) ? [r] : [];
  });
}
function sourcesEqual(): Record<string, {windowsSha256: string; wslSha256: string; equality: string}> {
  const rels = ['packages', 'harness/v4/e2e', 'harness/v4/lib', 'harness/v4/bench', 'onchain/contracts/v4', 'package.json', 'package-lock.json', 'setup/pins_v4.json'].flatMap(p => files(win, p));
  const hashes: Record<string, {windowsSha256: string; wslSha256: string; equality: string}> = {};
  for (const rel of rels) {
    const a = sha(path.join(win, rel));
    if (!fs.existsSync(path.join(source, rel))) throw new Error(`WSL source absent: ${rel}`);
    const b = sha(path.join(source, rel));
    const normalize = (root: string) => fs.readFileSync(path.join(root, rel), 'utf8').replace(/\r\n/g, '\n');
    if (a !== b && normalize(win) !== normalize(source)) throw new Error(`WSL source mismatch beyond line endings: ${rel}`);
    hashes[rel] = { windowsSha256: a, wslSha256: b, equality: a === b ? 'byte-identical' : 'identical after CRLF-to-LF normalization only' };
  }
  const pins = JSON.parse(fs.readFileSync(path.join(win, 'setup/pins_v4.json'), 'utf8'));
  for (const entry of Object.values(pins) as Array<{path: string; sha256: string}>) {
    for (const root of [win, source]) if (sha(path.join(root, entry.path)) !== entry.sha256) throw new Error(`pin mismatch: ${entry.path}`);
    hashes[entry.path] = { windowsSha256: entry.sha256, wslSha256: entry.sha256, equality: 'byte-identical, pinned' };
  }
  return hashes;
}
function checkMarkers(): void {
  for (const root of [win, source]) {
    if (fs.existsSync(path.join(root, 'results/v4/BUSY'))) throw new Error('another CPU-heavy job holds BUSY');
    const p = path.join(root, 'results/v4/bench/RUNNING');
    if (fs.existsSync(p) && !fs.readFileSync(p, 'utf8').includes('3.7-native')) throw new Error('another benchmark holds RUNNING');
  }
}
function rng(seed: number): () => number {
  return () => { let t = seed += 0x6D2B79F5; t = Math.imul(t ^ t >>> 15, t | 1); t ^= t + Math.imul(t ^ t >>> 7, t | 61); return ((t ^ t >>> 14) >>> 0) / 4294967296; };
}
type Prover = 'snarkjs' | 'rapidsnark';
type Condition = { id: string; prover: Prover; delayMs: number; instrumented: boolean };
const conditions: Condition[] = [];
for (const prover of ['snarkjs', 'rapidsnark'] as Prover[]) {
  for (const delayMs of [0, 20, 50]) conditions.push({ id: `${prover}-${delayMs}ms`, prover, delayMs, instrumented: true });
  conditions.push({ id: `${prover}-0ms-control`, prover, delayMs: 0, instrumented: false });
}
const random = rng(20261031);
const warmups = smoke ? 0 : 5;
const n = smoke ? 1 : 30;
const schedule = Array.from({ length: warmups + n }, (_, i) => {
  const order = [...conditions];
  for (let j = order.length - 1; j > 0; j--) { const k = Math.floor(random() * (j + 1)); [order[j], order[k]] = [order[k]!, order[j]!]; }
  return { block: i - warmups, warmup: i < warmups, order: order.map(c => c.id) };
});

type ProxyRec = { requestedDelayMs: number; timerWaitMs: number; upstreamMs: number; status: number; bytesIn: number; bytesOut: number };
async function makeProxy(target: string) {
  let delayMs = 0;
  let records: ProxyRec[] = [];
  let active = 0;
  const upstreamAgent = new http.Agent({ keepAlive: true });
  const server = http.createServer((req, res) => {
    active++;
    const chunks: Buffer[] = [];
    req.on('data', b => chunks.push(Buffer.from(b)));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const desired = delayMs;
      const t = performance.now();
      const upstream = http.request(target, { method: 'POST', agent: upstreamAgent, headers: { 'content-type': 'application/json', 'content-length': body.length } }, answer => {
        const bs: Buffer[] = [];
        answer.on('data', b => bs.push(Buffer.from(b)));
        answer.on('end', async () => {
          const response = Buffer.concat(bs);
          const upstreamMs = performance.now() - t;
          const start = performance.now();
          if (desired > 0) await sleep(desired);
          records.push({ requestedDelayMs: desired, timerWaitMs: round(performance.now() - start), upstreamMs: round(upstreamMs), status: answer.statusCode ?? 0, bytesIn: body.length, bytesOut: response.length });
          res.writeHead(answer.statusCode ?? 502, { 'content-type': 'application/json', 'content-length': response.length });
          res.end(response); active--;
        });
      });
      upstream.on('error', () => { records.push({ requestedDelayMs: desired, timerWaitMs: 0, upstreamMs: round(performance.now() - t), status: 502, bytesIn: body.length, bytesOut: 0 }); res.writeHead(502); res.end(); active--; });
      upstream.end(body);
    });
  });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`, port,
    begin(delay: number) { if (active) throw new Error('proxy not drained before iteration'); records = []; delayMs = delay; },
    end() { if (active) throw new Error('proxy not drained after iteration'); const r = records; records = []; return r; },
    close() { upstreamAgent.destroy(); server.closeAllConnections(); server.close(); }
  };
}
async function freePort(): Promise<number> {
  const s = http.createServer(); await new Promise<void>(r => s.listen(0, '127.0.0.1', r));
  const port = (s.address() as AddressInfo).port; await new Promise<void>(r => s.close(() => r())); return port;
}

let anvil: AnvilHandle | undefined;
let setup: E2eSetup | undefined;
let proxy: Awaited<ReturnType<typeof makeProxy>> | undefined;
const parties = new Map<Prover, PartySet>();
const hooks = new CryptoHooks();
let ownsMarker = false;
async function main() {
  checkMarkers();
  const before = sourcesEqual();
  if (process.version !== 'v24.21.0' || process.platform !== 'linux' || !/microsoft/i.test(os.release())) throw new Error('expected Node 24.21.0 on WSL');
  const rapid = process.env.PQID_NATIVE_RAW!;
  const anvilBin = process.env.PQID_ANVIL_BIN!;
  const anvilVersion = execFileSync(anvilBin, ['--version'], { encoding: 'utf8' }).trim();
  if (!anvilVersion.includes('1.5.1')) throw new Error('expected Anvil 1.5.1');
  const protocolSha = sha(path.join(nativeSource, 'PROTOCOL.md'));
  fs.mkdirSync(out, { recursive: true });
  const env = {
    schema: 'pqid-3.7-native/v1', mode, startedUtc: new Date().toISOString(), labels: ['exploratory', 'dev key', 'loopback, same host', 'both parties in one process', 'warm process, fresh party HTTP agents', 'simulated per-POST response delay', 'rapidsnark: experimental proof metadata adapter, not shipped'],
    node: process.version, openssl: process.versions.openssl, v8: process.versions.v8, platform: process.platform, architecture: process.arch, kernel: os.release(), cpu: os.cpus()[0]?.model, cores: os.cpus().length, memoryBytes: os.totalmem(),
    anvilVersion, anvilSha256: sha(anvilBin), rapidsnarkSha256: sha(rapid), nativeAdapterSha256: sha(process.env.PQID_RAPIDSNARK!), protocolSha256: protocolSha,
    harnessSha256: Object.fromEntries(['runner.ts', 'run_wsl.sh', 'analyze.py', 'native_adapter.py'].filter(f => fs.existsSync(path.join(nativeSource, f))).map(f => [f, sha(path.join(nativeSource, f))])),
    sourceHashes: before, keyLabel: 'dev', seed: 20261031, bootstrapSeed: 20260927, warmups, measuredBlocks: n,
    originalC5Unchanged: true, remoteEndpoint: false, secondDevice: false, cpuPinned: false, windowsLoadObservable: false,
  };
  write('environment.json', env);
  write('schedule.json', { seed: 20261031, conditions, blocks: schedule });
  if (mode === 'preflight') { write('completion.json', { status: 'preflight-pass', sourceFilesMatched: Object.keys(before).length }); console.log(`preflight-pass: ${Object.keys(before).length} source/artifact hashes matched`); return; }
  const check = checkKeySpec(DEV_KEY_SPEC, 'pinned existing dev key');
  if (!check) throw new Error('key check failed');
  fs.writeFileSync(marker, JSON.stringify({ holder: '3.7-native', pid: process.pid, mode, startedUtc: env.startedUtc }) + '\n', { flag: 'wx' }); ownsMarker = true;
  const beforePower = readPower();
  if (!smoke && !beforePower.ac) throw new Error('AC power required before setup');
  const setupStart = performance.now();
  anvil = await startAnvil(await freePort());
  const rec = await endpointRecord('anvil', anvil.rpcUrl);
  setup = await setupLocal(anvil.rpcUrl, rec, { campaign: '3.7-native-exploratory', session: stamp });
  proxy = await makeProxy(anvil.rpcUrl);
  const doc = setup.stateDoc(runKeyOf(DEV_KEY_SPEC));
  needles = [...setup.needles(), ...stateDocNeedles(doc)];
  doc.endpoint.rpcUrl = proxy.url;
  for (const prover of ['snarkjs', 'rapidsnark'] as Prover[]) parties.set(prover, await buildParties(doc, { prover }));
  write('setup.json', { deployment: setup.deployment, totalSetupMs: round(performance.now() - setupStart), partyBuilds: Object.fromEntries([...parties].map(([p, s]) => [p, s.build])), beforePower });
  const settleStart = performance.now(); const settleWall = Date.now();
  const settleMs = smoke ? 0 : 600_000;
  console.log(`setup complete; ${smoke ? 'smoke validation' : '600 s settle, then 5 warmup + 30 measured blocks'}`);
  for (let remaining = settleMs; remaining > 0; remaining -= Math.min(remaining, 30_000)) {
    await sleep(Math.min(remaining, 30_000)); console.log(`settle remaining ${Math.max(0, remaining - 30_000) / 1000} s`);
  }
  write('settle.json', { requestedMs: settleMs, monotonicMs: round(performance.now() - settleStart), wallMs: Date.now() - settleWall });
  let reference: string[] | undefined;
  let completeBlocks = 0;
  for (const block of schedule) {
    let success = false;
    for (let attempt = 0; attempt < 2; attempt++) {
      const powerBefore = readPower();
      const quiesce = await readQuiesceExcluding({ windowMs: smoke ? 200 : 2000, ownPids: [process.pid], ownPorts: [Number(new URL(anvil.rpcUrl).port), proxy.port] });
      const t = performance.now(); const wall = Date.now();
      const iterations: Record<string, unknown>[] = [];
      let failure: string | null = !smoke && !powerBefore.ac ? 'power-before' : null;
      for (const id of block.order) {
        if (failure) break;
        const c = conditions.find(x => x.id === id)!;
        const ps = parties.get(c.prover)!;
        setInstrumented(ps, c.instrumented);
        if (c.instrumented) hooks.install(); else hooks.uninstall();
        const partyIdleMsAtStart = resetAgents(ps);
        proxy.begin(c.delayMs);
        const r = await runPresentation(ps, hooks);
        hooks.uninstall();
        const proxyRecords = proxy.end();
        const signals = r.proofForIsolatedVerify?.publicSignals.filter((_, i) => i !== 3);
        if (r.ok && signals && !reference) reference = signals;
        const signalsEqual = signals !== undefined && JSON.stringify(signals) === JSON.stringify(reference);
        const postsEqual = !c.instrumented || r.report?.totals.posts === proxyRecords.length;
        const stagesSum = r.report ? Object.values(r.report.stages).reduce((a, s) => a + s.ms, 0) : null;
        const sumOk = stagesSum === null || Math.abs(stagesSum - r.endToEndMs) < 0.05;
        const correct = r.ok && signalsEqual && postsEqual && sumOk && proxyRecords.every(x => x.status === 200 && x.requestedDelayMs === c.delayMs);
        if (r.error) r.error = cleanError(r.error);
        const nativeAdapter = c.prover === 'rapidsnark' && fs.existsSync(process.env.PQID_NATIVE_ADAPTER_META!) ? JSON.parse(fs.readFileSync(process.env.PQID_NATIVE_ADAPTER_META!, 'utf8')) : null;
        iterations.push({ condition: c, result: r, proxyRecords, partyIdleMsAtStart, nativeAdapter, checks: { correct, signalsEqualExceptNonce: signalsEqual, postsEqual, stageSumEqualsTotal: sumOk } });
        if (!correct) failure = r.error ?? 'invariant-check';
      }
      const elapsed = performance.now() - t;
      const clockGapMs = Date.now() - wall - elapsed;
      const powerAfter = readPower();
      if (!smoke && !powerAfter.ac) failure = 'power-after';
      if (Math.abs(clockGapMs) > 2000) failure = 'clock-gap';
      const status = failure ? 'excluded-block' : 'ok';
      append('blocks.jsonl', { block: block.block, warmup: block.warmup, attempt, status, failure, powerBefore, powerAfter, quiesce, blockMs: round(elapsed), clockGapMs: round(clockGapMs), iterations, finishedUtc: new Date().toISOString() });
      console.log(`${smoke ? 'smoke' : block.warmup ? 'warmup' : 'measured'} block ${block.block} attempt ${attempt}: ${status}${failure ? ` (${failure})` : ''}`);
      if (!failure) { success = true; break; }
    }
    if (!success) throw new Error('block failed twice; campaign stopped with all attempts retained');
    if (!block.warmup) completeBlocks++;
  }
  const after = sourcesEqual();
  if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error('source/pin changed during run');
  if (sha(path.join(nativeSource, 'PROTOCOL.md')) !== protocolSha) throw new Error('protocol changed during run');
  write('completion.json', { status: smoke ? 'smoke-pass' : 'complete', completeBlocks, conditions: conditions.length, sourceAndPinHashesUnchanged: true, finishedUtc: new Date().toISOString(), temporaryWitnessFilesRemaining: fs.readdirSync(os.tmpdir()).filter(n => n.startsWith('pqid-v4')).length });
  console.log(`${smoke ? 'smoke-pass' : 'complete'}: ${completeBlocks} blocks x ${conditions.length} conditions`);
}
main().then(() => finish(0)).catch(e => {
  const message = cleanError(e); console.error(message);
  if (fs.existsSync(out)) write('failure.json', { status: 'failed', message, utc: new Date().toISOString() });
  finish(1);
});
function finish(code: number) {
  hooks.uninstall();
  for (const ps of parties.values()) destroyParties(ps);
  proxy?.close(); setup?.destroy(); anvil?.stop();
  if (ownsMarker) fs.unlinkSync(marker);
  process.exitCode = code;
  setTimeout(() => process.exit(code), 250);
}
