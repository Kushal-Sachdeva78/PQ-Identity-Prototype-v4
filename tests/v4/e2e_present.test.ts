import http from "node:http";
import type { AddressInfo } from "node:net";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { JsonRpcProvider, Wallet as EthWallet } from "ethers";
import { startAnvil, type AnvilHandle } from "@pqid/v4/ledger";
import { SetupFailed, endpointRecord, setupCustom, setupLocal, type E2eSetup } from "../../harness/v4/e2e/setup.ts";
import { buildParties, curveBuilt, runPresentation, resetAgents, setInstrumented, destroyParties, CryptoHooks, HolderCommitMismatch, type PartySet } from "../../harness/v4/e2e/presentation.ts";
import { DEV_KEY_SPEC, STAGE_IDS, applyColdDefinition, findSecrets, runKeyOf, stateDocNeedles } from "../../harness/v4/e2e/lib.ts";

// End-to-end engine on a real Anvil (an OS-assigned port, never a D-034 port). Shipped
// packages/v4 code; the harness instruments at run time only.

async function freePort(): Promise<number> {
  const s = http.createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", () => r()));
  const p = (s.address() as AddressInfo).port;
  await new Promise<void>((r) => s.close(() => r()));
  return p;
}

describe("e2e presentation engine (Anvil)", () => {
  let anvil: AnvilHandle;
  let setup: E2eSetup;
  const sets: PartySet[] = [];
  const hooks = new CryptoHooks();

  beforeAll(async () => {
    anvil = await startAnvil(await freePort());
    const rec = await endpointRecord("anvil", anvil.rpcUrl, {});
    setup = await setupLocal(anvil.rpcUrl, rec, { campaign: "test", session: "test" });
  }, 300_000);

  afterAll(() => {
    hooks.uninstall();
    for (const ps of sets) destroyParties(ps);
    setup?.destroy();
    anvil?.stop();
  });

  it("the input mark only records time: same decision and the same public signals except the session nonce", async () => {
    const doc = setup.stateDoc(runKeyOf(DEV_KEY_SPEC));
    const marked = await buildParties(doc);
    const plain = await buildParties(doc, { instrument: false });
    sets.push(marked, plain);
    expect(typeof marked.wallet.cfg.inputHook).toBe("function");
    expect(plain.wallet.cfg.inputHook).toBeUndefined();

    // the hook reads nothing from its arguments and changes nothing
    let reads = 0;
    const spy = new Proxy({ a: "1", b: ["2"] }, { get: (t, k, r) => (reads++, Reflect.get(t, k, r)) });
    marked.wallet.cfg.inputHook?.(spy as never, { credId: Buffer.alloc(32), holderCommit: "1", issuerDid: "did:pq:x" });
    expect(reads).toBe(0);
    expect(typeof marked.cur.inputMark).toBe("number");

    // the cold definition holds for the harness's own set-up path: the set-up and two party
    // builds in this process have not built snarkJS's bn128 curve (the first proof does)
    expect(curveBuilt()).toBe(false);
    hooks.install();
    const a = await runPresentation(marked, hooks);
    hooks.uninstall();
    // a cold-style run in a process whose curve is already built is not cold: an error record
    expect(curveBuilt()).toBe(true);
    const notCold = applyColdDefinition(a, curveBuilt());
    expect(notCold.ok).toBe(false);
    expect(notCold.errorKind).toBe("cold-definition");
    const b = await runPresentation(plain, hooks);
    expect(a.ok, a.error ?? "").toBe(true);
    expect(b.ok, b.error ?? "").toBe(true);
    expect(a.decision?.accepted).toBe(true);
    expect(b.decision?.accepted).toBe(true);
    expect(a.decision?.failedChecks).toEqual([]);
    expect(b.decision?.failedChecks).toEqual([]);
    const sa = a.proofForIsolatedVerify?.publicSignals as string[];
    const sb = b.proofForIsolatedVerify?.publicSignals as string[];
    expect(sa).toHaveLength(8);
    expect(sa.filter((_, i) => i !== 3)).toEqual(sb.filter((_, i) => i !== 3)); // signal 3 is the per-session nonce
    expect(sa[3]).not.toEqual(sb[3]);

    // the instrumented report accounts for the whole presentation
    const r = a.report;
    expect(r).not.toBeNull();
    if (!r) return;
    const sum = STAGE_IDS.reduce((x, id) => x + r.stages[id].ms, 0);
    expect(Math.abs(sum - r.endToEndMs)).toBeLessThan(0.01);
    expect(r.outside).toEqual({ posts: 0, events: 0, ledgerCalls: 0 });
    expect(r.totals.postsByParty.wallet).toBeGreaterThan(0);
    expect(r.totals.postsByParty.verifier).toBeGreaterThan(0);
    // the first presentation of fresh providers: one network-detection POST in S1
    expect(r.stages.S1.posts).toBe(1);
    expect(r.stages.S1.byMethod).toEqual({ eth_chainId: 1 });
    // no chain traffic outside the wallet's checks and the verifier's two stages
    for (const id of ["S2", "S4", "S6", "S7", "S8", "S9", "S10"] as const) expect(r.stages[id].posts).toBe(0);
    expect(r.stages.S6.ms).toBeGreaterThan(0);
    expect(r.stages.S8.ms).toBeGreaterThan(r.stages.S3.ms);
    // each party opened its own connection, and the trace's per-POST attribution agrees with the agents
    expect(a.connections).toEqual({ verifier: 1, wallet: 1 });
    expect(r.totals.connectsByParty).toEqual(a.connections);
    expect(r.totals.connectsUnknown).toBe(0);
    expect(r.stages.S1.connects).toBe(1);
    expect(r.stages.S3.connects).toBe(1);
    // garbage collections inside the window are attributed to stages (the first proof collects)
    expect(Array.isArray(a.gc)).toBe(true);
    const gcInStages = STAGE_IDS.reduce((x, id) => x + r.stages[id].gcCount, 0);
    expect(gcInStages + r.gcTotals.outsideWindows).toBe(r.gcTotals.count);
    expect(a.gc?.length).toBe(r.gcTotals.count);
    expect(b.gc).toBeNull();
    // no secret in what a result line would carry
    const line = JSON.stringify(a);
    expect(findSecrets(line, [...setup.needles(), ...stateDocNeedles(doc)])).toEqual([]);
  }, 300_000);

  it("warm: after the agent reset every iteration opens one connection per party, whatever came before; a control gives endToEnd only", async () => {
    const ps = sets[0] as PartySet;
    setInstrumented(ps, true);
    hooks.install();
    // the reset reports how long ago each party's last POST ended (the first test ran presentations)
    const idle = resetAgents(ps);
    expect(idle.wallet).not.toBeNull();
    expect(idle.verifier).not.toBeNull();
    const w1 = await runPresentation(ps, hooks);
    expect(w1.ok, w1.error ?? "").toBe(true);
    expect(w1.report?.stages.S1.posts).toBe(0); // chain id cached by LedgerV4
    expect(w1.connections).toEqual({ verifier: 1, wallet: 1 });
    expect(w1.report?.totals.connectsByParty).toEqual({ verifier: 1, wallet: 1 });
    expect(w1.report?.stages.S3.connects).toBe(1); // the wallet's first read
    expect(w1.report?.stages.S11.connects).toBe(1); // the verifier's first read
    // without the reset an immediate repeat reuses both sockets: the schedule-position effect the reset removes
    const w2 = await runPresentation(ps, hooks);
    expect(w2.ok, w2.error ?? "").toBe(true);
    expect(w2.connections).toEqual({ verifier: 0, wallet: 0 });
    // a control iteration after a reset opens the same connections as an instrumented one
    setInstrumented(ps, false);
    hooks.uninstall();
    resetAgents(ps);
    const c = await runPresentation(ps, hooks);
    expect(c.ok, c.error ?? "").toBe(true);
    expect(c.report).toBeNull();
    expect(c.posts).toBeNull();
    expect(c.gc).toBeNull();
    expect(c.connections).toEqual({ verifier: 1, wallet: 1 });
    expect(c.endToEndMs).toBeGreaterThan(0);
    setInstrumented(ps, true);
    hooks.install();
    resetAgents(ps);
    const again = await runPresentation(ps, hooks);
    hooks.uninstall();
    expect(again.ok, again.error ?? "").toBe(true);
    expect(again.report).not.toBeNull();
    expect(again.connections).toEqual({ verifier: 1, wallet: 1 });
  }, 300_000);

  it("a custom set-up that fails after funding sweeps the funded role balances back to the funder", async () => {
    // a fresh funder (never a fixed key), funded by the local dev deployer
    const funder = EthWallet.createRandom();
    await setup.ledger.fund(funder.address, "5");
    const provider = new JsonRpcProvider(anvil.rpcUrl, undefined, { staticNetwork: true });
    try {
      const rec = await endpointRecord("custom", anvil.rpcUrl, { label: "test-custom" });
      const logs: string[] = [];
      const err = await setupCustom(anvil.rpcUrl, rec, {
        funderKey: funder.privateKey,
        expectChainId: 31337,
        maxFeeGwei: 100,
        maxTotalEth: 2,
        finality: "latest",
        finalityTimeoutSec: 60,
        txTimeoutSec: 60,
        writesTimeoutSec: 120,
        campaign: "test",
        session: "test",
        log: (s) => logs.push(s),
        testHooks: {
          afterFunding: () => {
            throw new Error("injected failure after funding");
          },
        },
      }).then(
        () => null,
        (e: unknown) => e
      );
      expect(err).toBeInstanceOf(SetupFailed);
      const f = err as SetupFailed;
      expect(f.message).toMatch(/injected failure after funding/);
      expect(f.transactions.filter((x) => x.what.startsWith("deploy ")).length).toBe(4);
      const funding = f.transactions.filter((x) => x.what.startsWith("fund "));
      expect(funding.map((x) => x.what)).toEqual(["fund governance", "fund issuer", "fund verifier"]);
      expect(f.partialSweep?.map((s) => s.role)).toEqual(["governance", "issuer", "verifier"]);
      for (const s of f.partialSweep ?? []) expect(s.txHash, s.note ?? "").toMatch(/^0x[0-9a-f]{64}$/);
      for (const x of funding) {
        const tx = await provider.getTransaction(x.txHash);
        expect(tx?.to).toBeTruthy();
        const left = await provider.getBalance(tx?.to as string);
        // what is left is the fee ceiling's unused part, far below what the role was sent
        expect(left < (tx?.value ?? 0n) / 4n, `${x.what}: ${left} left of ${tx?.value}`).toBe(true);
        const swept = BigInt(f.partialSweep?.find((s) => `fund ${s.role}` === x.what)?.valueWei ?? "0");
        expect(swept > ((tx?.value ?? 0n) * 3n) / 4n).toBe(true);
      }
      expect(logs.some((l) => l.includes("sweeping their balances back"))).toBe(true);
      expect(JSON.stringify({ message: f.message, tx: f.transactions, sweep: f.partialSweep, logs })).not.toContain(funder.privateKey.slice(2));
    } finally {
      provider.destroy();
    }
  }, 300_000);

  it("refuses a holder secret that does not open the credential's commitment", async () => {
    const doc = setup.stateDoc(runKeyOf(DEV_KEY_SPEC));
    doc.wallet.holderSecret = (BigInt(doc.wallet.holderSecret) + 1n).toString();
    await expect(buildParties(doc)).rejects.toBeInstanceOf(HolderCommitMismatch);
  }, 120_000);
});
