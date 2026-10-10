import readline from "node:readline";
import { MSG_PREFIX, SCHEMA, applyColdDefinition, findSecrets, redactSecrets, stateDocErrors, stateDocNeedles, round3, type E2eStateDoc, type SecretNeedle } from "./lib.ts";

/**
 * The end-to-end child process (docs/v4/E2E.md). Spawned by campaign.ts with
 * `node --import <tsx> harness/v4/e2e/child_present.ts`; it takes no secret on argv or in its
 * environment. The first stdin line is the init message with the state documents (holder
 * secret, verifier ML-KEM key, RPC URL); nothing it receives is written anywhere.
 *
 *   cold: build one endpoint's verifier and wallet (untimed), run ONE instrumented
 *         presentation, then the untimed tail (raw RTT probe, isolated Groth16 verify, one timed
 *         SHA-256 of the zkey, maxRSS), print one result line, exit. A run whose bn128 curve was
 *         built before S1 is not cold: it is reported as an error (errorKind "cold-definition").
 *   warm: build every endpoint's parties once, time one SHA-256 of the zkey, print "ready", then
 *         answer {"type":"iterate","endpoint":...,"control":bool} lines until {"type":"exit"}.
 *         Before every iteration both parties' HTTP agents are replaced (untimed), so each warm
 *         iteration opens its own connections (E2E.md section 5).
 *
 * Output: only lines starting with "E2E-MSG " are read by the orchestrator. Every line is
 * scanned for the secrets it was given before it is written.
 */

const mainAtMs = performance.now();

interface InitMsg {
  type: "init";
  mode: "cold" | "warm";
  docs: E2eStateDoc[];
  prover?: "snarkjs" | "rapidsnark";
}

let needles: SecretNeedle[] = [];

function emit(obj: Record<string, unknown>): Promise<void> {
  let text = JSON.stringify(obj);
  const hits = findSecrets(text, needles);
  if (hits.length > 0) text = JSON.stringify({ type: obj["type"] ?? "error", ok: false, error: `child output withheld: secret scan hit (${hits.join(", ")})`, schema: SCHEMA.child });
  return new Promise((resolve) => process.stdout.write(MSG_PREFIX + text + "\n", () => resolve()));
}

function fail(e: unknown): Promise<void> {
  const msg = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
  return emit({ type: "fatal", schema: SCHEMA.child, ok: false, error: redactSecrets(msg.split("\n").slice(0, 3).join(" "), needles).slice(0, 600) });
}

async function readInit(rl: readline.Interface): Promise<{ init: InitMsg; stdinMs: number }> {
  const t = performance.now();
  const it = rl[Symbol.asyncIterator]();
  const first = await it.next();
  if (first.done) throw new Error("no init message on stdin");
  const init = JSON.parse(first.value) as InitMsg;
  if (init.type !== "init" || (init.mode !== "cold" && init.mode !== "warm") || !Array.isArray(init.docs) || init.docs.length === 0) throw new Error("bad init message");
  for (const d of init.docs) {
    const errs = stateDocErrors(d);
    if (errs.length > 0) throw new Error(`state document invalid: ${errs.join(", ")}`);
  }
  if (init.mode === "cold" && init.docs.length !== 1) throw new Error("a cold child takes exactly one state document");
  return { init, stdinMs: performance.now() - t };
}

async function main(): Promise<void> {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  const { init, stdinMs } = await readInit(rl);
  needles = init.docs.flatMap(stateDocNeedles);

  // ffjavascript sets globalThis.curve_bn128 = null when it loads and to the curve once a
  // multi-thread bn128 curve is built (snarkJS prove builds one): test for a built curve.
  const curveBuilt = () => Boolean((globalThis as { curve_bn128?: unknown }).curve_bn128);
  const bn128Before = curveBuilt();
  const tImport = performance.now();
  const P = await import("./presentation.ts");
  const importMs = performance.now() - tImport;
  const hooks = new P.CryptoHooks();
  const prover = init.prover ?? "snarkjs";
  const runtime = { node: process.version, openssl: process.versions.openssl ?? "unknown", platform: process.platform, arch: process.arch };

  if (init.mode === "cold") {
    const doc = init.docs[0] as E2eStateDoc;
    const ps = await P.buildParties(doc, { prover });
    hooks.install();
    const bn128BeforeS1 = curveBuilt();
    const raw = await P.runPresentation(ps, hooks);
    hooks.uninstall();
    const res = applyColdDefinition(raw, bn128BeforeS1);
    // ---- untimed tail ----
    const rtt = await P.rttProbe(doc.endpoint.rpcUrl);
    let iso: { ms: number; verified: boolean } | null = null;
    if (raw.proofForIsolatedVerify) iso = await P.isolatedVerify(raw.proofForIsolatedVerify.proof, raw.proofForIsolatedVerify.publicSignals, doc.key.vkey);
    const zkeySha256 = P.timeZkeySha256(doc.key.zkey);
    const ru = process.resourceUsage();
    P.destroyParties(ps);
    await emit({
      type: "result",
      schema: SCHEMA.child,
      mode: "cold",
      endpoint: doc.endpoint.id,
      kind: doc.endpoint.kind,
      setupId: doc.setupId,
      prover,
      keyLabel: doc.key.label,
      ...res,
      error: res.error ? redactSecrets(res.error, needles) : null,
      aux: {
        mainAtMs: round3(mainAtMs),
        stdinMs: round3(stdinMs),
        importMs: round3(importMs),
        build: ps.build,
        bn128CurveCachedBeforeImport: bn128Before,
        bn128CurveCachedBeforeS1: bn128BeforeS1,
        bn128CurveBuiltAfterS11: curveBuilt(),
        rttProbe: rtt,
        isolatedGroth16Verify: iso,
        zkeySha256Ms: zkeySha256.ms,
        zkeyBytes: zkeySha256.bytes,
        maxRssKiB: ru.maxRSS,
      },
      runtime,
    });
    process.exit(0);
  }

  // ---- warm ----
  const sets = new Map<string, Awaited<ReturnType<typeof P.buildParties>>>();
  for (const doc of init.docs) {
    if (sets.has(doc.endpoint.id)) throw new Error(`duplicate endpoint ${doc.endpoint.id}`);
    sets.set(doc.endpoint.id, await P.buildParties(doc, { prover }));
  }
  const zkeySha256 = P.timeZkeySha256((init.docs[0] as E2eStateDoc).key.zkey);
  await emit({
    type: "ready",
    schema: SCHEMA.child,
    endpoints: [...sets.keys()],
    aux: { mainAtMs: round3(mainAtMs), stdinMs: round3(stdinMs), importMs: round3(importMs), build: Object.fromEntries([...sets].map(([k, v]) => [k, v.build])), zkeySha256Ms: zkeySha256.ms, zkeyBytes: zkeySha256.bytes },
    runtime,
  });
  for await (const line of rl) {
    if (line.trim() === "") continue;
    let cmd: { type?: string; endpoint?: string; control?: boolean; seq?: number };
    try {
      cmd = JSON.parse(line) as typeof cmd;
    } catch {
      await emit({ type: "error", ok: false, error: "unparsable command" });
      continue;
    }
    if (cmd.type === "exit") break;
    if (cmd.type !== "iterate" || typeof cmd.endpoint !== "string") {
      await emit({ type: "error", ok: false, error: "unknown command" });
      continue;
    }
    const ps = sets.get(cmd.endpoint);
    if (!ps) {
      await emit({ type: "result", ok: false, seq: cmd.seq ?? null, error: `unknown endpoint ${cmd.endpoint}` });
      continue;
    }
    const control = cmd.control === true;
    // untimed: fresh agents for both parties (every warm iteration opens its own connections)
    const partyIdleMsAtStart = P.resetAgents(ps);
    P.setInstrumented(ps, !control);
    if (control) hooks.uninstall();
    else hooks.install();
    const t = performance.now();
    const res = await P.runPresentation(ps, hooks);
    const iterationWallMs = performance.now() - t;
    await emit({
      type: "result",
      schema: SCHEMA.child,
      mode: "warm",
      seq: cmd.seq ?? null,
      endpoint: ps.endpointId,
      kind: ps.kind,
      setupId: ps.setupId,
      control,
      prover,
      keyLabel: ps.keyLabel,
      ...res,
      error: res.error ? redactSecrets(res.error, needles) : null,
      aux: { iterationWallMs: round3(iterationWallMs), agentsReset: true, partyIdleMsAtStart, maxRssKiB: process.resourceUsage().maxRSS },
    });
  }
  hooks.uninstall();
  for (const ps of sets.values()) P.destroyParties(ps);
  await emit({ type: "bye", schema: SCHEMA.child });
  process.exit(0);
}

main().catch(async (e: unknown) => {
  await fail(e);
  process.exit(1);
});
