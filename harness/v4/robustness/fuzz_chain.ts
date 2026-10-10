import fs from "node:fs";
import nodeCrypto from "node:crypto";
import { canonicalJsonBytes } from "@pqid/common/hash";
import { startAnvil, type AnvilHandle } from "@pqid/ledger";
import type { World } from "@pqid/v4/world";
import { VerifierV4, type PresentationV4 } from "@pqid/v4/verifier";
import { HolderWalletV4, WalletRefusal, WALLET_CHECKS, type HeldCredentialV4, type IssuerDataSource } from "@pqid/v4/wallet";
import { transcriptHash, deriveSessionSecrets, type ProofRequestV4, type SessionReplyV4 } from "@pqid/v4/session";
import { aes256gcmSeal } from "@pqid/v4/pqc";
import { DEFAULT_TYPE_ID, WALLET_CLOCK_SKEW_SEC, STANDARD_THRESHOLDS } from "@pqid/v4/constants";
import { acceptableTodays } from "@pqid/v4/dates";
import { VKEY_V4 } from "@pqid/v4/paths";
import type { IssuerV4 } from "@pqid/v4/issuer";
import type { LedgerV4 } from "@pqid/v4/ledger";
import { worldOnRpc, cachedLedger, snapshotSessions, restoreSessions, replaceSessionStore, assertPortFree } from "../scale_lib.ts";
import { PORTS } from "../lib/ports.ts";
import { Rng } from "./rng.ts";
import { mutateValue, mutateBytes, mutateJsonText, exotic, cloneJson } from "./mutators.ts";
import { refCanonical, refRequestValid, refPresentationShapeOk, refStrictUtf8, Q_BIG } from "./oracles.ts";
import { Verdict, errClass, errMsg, timedCallAsync, type FuzzTarget, type FuzzCase } from "./fuzz_types.ts";

/**
 * Chain-backed fuzz targets (D-034 port 8781): the verifier's full decision, the honest wallet's
 * request checks and its checks of the issuer's served data, against a fresh local Anvil
 * deployment ("loopback, same host"), the v4 DEV key (label dev).
 *
 * Setup (untimed, once per child process): Anvil on 127.0.0.1:<PQID_FUZZ_PORT>, one accredited
 * issuer with an anchored epoch, H holders, one verifier V on the world's ManualClock (never
 * advanced, so no session expires). K honest presentations are made by the holders' own
 * wallets; the harness records each session's ML-KEM shared secret by wrapping
 * node:crypto.encapsulate during that step only (run time, packages/ unchanged), derives the
 * session key and IV the same way the wallet does, and keeps them in memory (never written).
 * That lets a case re-seal a mutated presentation into the same session, so the transcript
 * nonce still matches and every later check is exercised (harness only; AES-GCM nonce reuse is
 * acceptable in a test).
 *
 * The verifier reads the chain through an in-memory read cache (harness/v4/scale_lib.ts
 * cachedLedger) after a warm-up; 1 case in 20 uses the as-shipped client instead.
 */

const K_HONEST = 8;
const H_HOLDERS = 2;

interface HonestItem {
  request: ProofRequestV4;
  reply: SessionReplyV4;
  presentation: PresentationV4;
  key: Buffer;
  iv: Buffer;
  transcript: Buffer;
  nonce: bigint;
}

interface ChainWorld {
  anvil: AnvilHandle;
  world: World;
  issuer: IssuerV4;
  holders: HolderWalletV4[];
  verifier: VerifierV4;
  verifierShipped: VerifierV4;
  honest: HonestItem[];
  snap: Map<string, unknown>;
  vkey: unknown;
  chainId: number;
  /** World ledger behind the in-memory read cache (wallet targets use it too). */
  cachedLedger: LedgerV4;
}

let CW: ChainWorld | null = null;
let setupPromise: Promise<ChainWorld> | null = null;

async function ensureWorld(log: (s: string) => void, k = K_HONEST, emit?: (o: Record<string, unknown>) => void): Promise<ChainWorld> {
  if (CW) return CW;
  setupPromise ??= (async () => {
    const port = Number(process.env["PQID_FUZZ_PORT"] ?? PORTS.fuzzing);
    await assertPortFree(port);
    log(`chain targets: Anvil on 127.0.0.1:${port}`);
    const anvil = await startAnvil(port);
    // the parent runner stops this Anvil itself if its watchdog has to kill this process
    if (anvil.proc.pid !== undefined) emit?.({ anvilPid: anvil.proc.pid, anvilPort: port });
    try {
      const world = await worldOnRpc(anvil.rpcUrl);
      const issuer = await world.addIssuer("fuzz-issuer");
      const holders: HolderWalletV4[] = [];
      for (let h = 0; h < H_HOLDERS; h++) {
        const w = await world.addHolder();
        await world.issue(issuer, w, { birthDate: 19900101 + h });
        holders.push(w);
      }
      await world.publishEpoch(issuer);
      const base = await world.addVerifier("fuzz-verifier");
      const cached = cachedLedger(world.ledger);
      const verifier = new VerifierV4({ ...base.opts, ledger: cached.proxy });
      const verifierShipped = new VerifierV4({ ...base.opts });
      replaceSessionStore(verifierShipped, verifier.sessions);
      const kemPk = base.opts.identity.kem.publicKey;

      log(`chain targets: ${k} honest presentations (proving, untimed)`);
      const c = nodeCrypto as unknown as Record<string, unknown>;
      const orig = c["encapsulate"] as (key: unknown) => { sharedKey: Buffer; ciphertext: Buffer };
      let captured: { ss: Buffer; ct: Buffer } | null = null;
      c["encapsulate"] = (key: unknown) => {
        const r = orig(key);
        captured = { ss: Buffer.from(r.sharedKey), ct: Buffer.from(r.ciphertext) };
        return r;
      };
      const honest: HonestItem[] = [];
      try {
        for (let i = 0; i < k; i++) {
          captured = null;
          const request = await verifier.newRequest({ predicate: "age_gte", threshold: 18, typeId: DEFAULT_TYPE_ID });
          const { reply, presentation } = await (holders[i % H_HOLDERS] as HolderWalletV4).present(request);
          const cap = captured as { ss: Buffer; ct: Buffer } | null;
          if (!cap || !cap.ct.equals(Buffer.from(reply.ct, "hex"))) throw new Error("could not capture the session secret of a presentation");
          const transcript = transcriptHash(request, kemPk, cap.ct);
          const s = deriveSessionSecrets(cap.ss, transcript);
          cap.ss.fill(0);
          honest.push({ request, reply, presentation, key: s.key, iv: s.iv, transcript, nonce: s.nonce });
        }
      } finally {
        c["encapsulate"] = orig;
      }
      const snap = snapshotSessions(verifier.sessions);
      // warm the read cache and check every honest reply verifies (as shipped too)
      for (const h of honest) {
        const d = await verifier.verifyReply(h.reply);
        if (!d.accepted) throw new Error(`honest presentation rejected in setup: ${d.reasons.join("; ")}`);
        restoreSessions(verifier.sessions, snap);
      }
      const d0 = await verifierShipped.verifyReply((honest[0] as HonestItem).reply);
      if (!d0.accepted) throw new Error(`honest presentation rejected by the as-shipped verifier: ${d0.reasons.join("; ")}`);
      restoreSessions(verifier.sessions, snap);
      CW = { anvil, world, issuer, holders, verifier, verifierShipped, honest, snap, vkey: JSON.parse(fs.readFileSync(VKEY_V4, "utf8")) as unknown, chainId: await world.ledger.chainId(), cachedLedger: cached.proxy };
      return CW;
    } catch (e) {
      anvil.stop();
      throw e;
    }
  })();
  return setupPromise;
}

async function stopWorld(): Promise<void> {
  if (!CW) return;
  try {
    CW.world.ledger.destroy();
  } catch {
    /* already closed */
  }
  CW.anvil.stop();
  CW = null;
  setupPromise = null;
}

/** A fresh honest wallet reading the chain through the read cache (empty date log, no credentials). */
function walletOnCache(W: ChainWorld): Promise<HolderWalletV4> {
  return HolderWalletV4.create({ ledger: W.cachedLedger, clock: W.world.clock, pinnedGovernancePk: W.world.governance.pk });
}

function plan(rng: Rng, family: string): FuzzCase {
  return { family, input: null, recipe: [], meta: { subSeed: rng.u32() } };
}

const PRES_FIELDS = ["publicSignals", "issuerDid", "issuerController", "epochStatement"] as const;

function sameJson(a: unknown, b: unknown): boolean {
  try {
    return refCanonical(a) === refCanonical(b);
  } catch {
    return false;
  }
}

function safeJsonBytes(v: unknown): Buffer {
  try {
    return canonicalJsonBytes(v);
  } catch {
    return Buffer.from(JSON.stringify(v, (_k, x: unknown) => (typeof x === "bigint" ? x.toString() : x)) ?? "null");
  }
}

// =====================================================================================
// T-verify
// =====================================================================================

const tVerify: FuzzTarget = {
  id: "T-verify",
  title: "verifier decision (full)",
  entryPoints: ["VerifierV4.verifyReply"],
  kind: "chain",
  budget: 20_000,
  smokeBudget: 40,
  property:
    "verifyReply never throws, and accepts exactly when the transport is intact (same sessionId and ct, box = the session's seal of strict canonical JSON), the presentation's publicSignals, issuerDid, issuerController and epochStatement equal the honest values, the proof passes the shape rules and Groth16 verification (so a re-randomised proof is a legitimate acceptance) and the session is open; a rejected reply that failed any of the first 14 checks leaves the session open, and the honest reply of that session is still accepted afterwards. 1 case in 20 uses the as-shipped chain client, the rest the read cache",
  documentedErrors: [],
  async setup(ctx) {
    await ensureWorld(ctx.log, ctx.smoke ? 4 : K_HONEST, ctx.emit);
  },
  async teardown() {
    await stopWorld();
  },
  gen(rng) {
    return plan(rng, rng.weighted<string>([
      [1, "honest"],
      [4, "presentation"],
      [3, "signals"],
      [3, "proof"],
      [2, "epoch"],
      [1, "cross"],
      [2, "transport"],
      [1, "noncanonical"],
    ]));
  },
  async run(c) {
    const v = new Verdict();
    const W = CW as ChainWorld;
    const rng = new Rng(Number(c.meta?.["subSeed"] ?? 0));
    const k = rng.int(0, W.honest.length - 1);
    const h = W.honest[k] as HonestItem;
    const shipped = rng.int(0, 19) === 0;
    const verifier = shipped ? W.verifierShipped : W.verifier;
    restoreSessions(W.verifier.sessions, W.snap);
    let pres: unknown = cloneJson(h.presentation);
    let plaintext: Buffer | null = null;
    switch (c.family) {
      case "presentation": {
        const m = mutateValue(rng, pres, rng.int(1, 2));
        pres = m.value;
        c.recipe.push(...m.ops);
        break;
      }
      case "signals": {
        const p = pres as Record<string, string[]>;
        const s = (p["publicSignals"] as string[]).slice();
        const i = rng.int(0, 7);
        const other = (W.honest[(k + 1) % W.honest.length] as HonestItem).presentation.publicSignals;
        s[i] = rng.pick([other[i] as string, (BigInt(s[i] as string) + 1n).toString(), "0", (21888242871839275222246405745257275088548364400416034343698204186575808495617n - 1n).toString()]);
        p["publicSignals"] = s;
        c.recipe.push(`public signal ${i} replaced`);
        break;
      }
      case "proof": {
        const p = pres as { proof: Record<string, unknown> };
        const kind = rng.pick(["coord+1", "out-of-range", "identity", "other-proof", "swap-ac", "random-in-range", "pi_b-row"]);
        const pr = p.proof as { pi_a: string[]; pi_b: string[][]; pi_c: string[] };
        if (kind === "coord+1") pr.pi_a[rng.int(0, 1)] = (BigInt(pr.pi_a[0] as string) + 1n).toString();
        else if (kind === "out-of-range") pr.pi_c[0] = (Q_BIG + BigInt(rng.int(0, 3))).toString();
        else if (kind === "identity") p.proof["pi_a"] = ["0", "1", "0"];
        else if (kind === "other-proof") p.proof = cloneJson((W.honest[(k + 1) % W.honest.length] as HonestItem).presentation.proof) as unknown as Record<string, unknown>;
        else if (kind === "swap-ac") {
          const a = pr.pi_a;
          pr.pi_a = pr.pi_c;
          pr.pi_c = a;
        } else if (kind === "random-in-range") pr.pi_a = [rng.bigBelow(Q_BIG).toString(), rng.bigBelow(Q_BIG).toString(), "1"];
        else pr.pi_b = [pr.pi_b[1] as string[], pr.pi_b[0] as string[], pr.pi_b[2] as string[]];
        c.recipe.push(`proof: ${kind}`);
        break;
      }
      case "epoch": {
        const p = pres as { epochStatement: Record<string, unknown> };
        const m = mutateValue(rng, p.epochStatement, 1);
        p.epochStatement = m.value as Record<string, unknown>;
        c.recipe.push(...m.ops.map((o) => `epochStatement: ${o}`));
        break;
      }
      case "cross":
        pres = cloneJson((W.honest[(k + 1) % W.honest.length] as HonestItem).presentation);
        c.recipe.push("another session's presentation sealed into this session");
        break;
      case "noncanonical": {
        const t = mutateJsonText(rng, refCanonical(pres));
        plaintext = Buffer.from(t.value, "utf8");
        c.recipe.push(...t.ops);
        break;
      }
    }
    plaintext ??= safeJsonBytes(pres);
    const box = aes256gcmSeal(h.key, h.iv, h.transcript, plaintext);
    let reply: Record<string, unknown> = { type: "pqid:reply:v4", sessionId: h.request.sessionId, ct: h.reply.ct, box: Buffer.concat([box.ciphertext, box.tag]).toString("hex") };
    let transportIntact = true;
    if (c.family === "transport") {
      const kind = rng.pick(["ct", "box", "session", "type", "bytes"]);
      transportIntact = false;
      if (kind === "ct") reply["ct"] = mutateHexByte(rng, reply["ct"] as string);
      else if (kind === "box") reply["box"] = mutateHexByte(rng, reply["box"] as string);
      else if (kind === "session") reply["sessionId"] = (W.honest[(k + 1) % W.honest.length] as HonestItem).request.sessionId;
      else if (kind === "type") reply["type"] = "pqid:reply:v3";
      else {
        const m = mutateBytes(rng, Buffer.from(JSON.stringify(reply)), [], 1);
        reply = { __bytes: m.value } as Record<string, unknown>;
        c.recipe.push(...m.ops);
      }
      c.recipe.push(`transport: ${kind}`);
    }
    const wire: unknown = reply["__bytes"] ? reply["__bytes"] : rng.bool(0.5) ? Buffer.from(JSON.stringify(reply)) : reply;
    if (reply["__bytes"]) {
      // a byte-level edit may leave the JSON (and so the reply) unchanged in meaning
      try {
        const back = JSON.parse((reply["__bytes"] as Buffer).toString("utf8")) as Record<string, unknown>;
        transportIntact =
          refStrictUtf8(reply["__bytes"] as Buffer) !== null &&
          back["type"] === "pqid:reply:v4" &&
          back["sessionId"] === h.request.sessionId &&
          back["ct"] === h.reply.ct &&
          back["box"] === Buffer.concat([box.ciphertext, box.tag]).toString("hex") &&
          Object.keys(back).length === 4;
      } catch {
        transportIntact = false;
      }
    }
    // oracle
    let canonicalOk = false;
    let parsed: unknown = undefined;
    try {
      parsed = JSON.parse(plaintext.toString("utf8"));
      canonicalOk = Buffer.from(refCanonical(parsed), "utf8").equals(plaintext) && parsed !== null && typeof parsed === "object" && !Array.isArray(parsed);
    } catch {
      canonicalOk = false;
    }
    let expectAccept = false;
    if (transportIntact && canonicalOk && refPresentationShapeOk(parsed)) {
      const pp = parsed as Record<string, unknown>;
      const fieldsHonest = PRES_FIELDS.every((f) => sameJson(pp[f], (h.presentation as unknown as Record<string, unknown>)[f]));
      if (fieldsHonest) {
        const snarkjs = await import("snarkjs");
        try {
          expectAccept = await snarkjs.groth16.verify(W.vkey as never, h.presentation.publicSignals, pp["proof"] as never);
        } catch {
          expectAccept = false;
        }
      }
    }
    const r = await timedCallAsync(() => verifier.verifyReply(wire as SessionReplyV4));
    v.callMs = r.ms;
    if (r.error) {
      v.fail("verifyReply:throws", `${errClass(r.error)}: ${errMsg(r.error)}`, errClass(r.error));
      return v.done();
    }
    const d = r.value as Awaited<ReturnType<VerifierV4["verifyReply"]>>;
    v.outcome = d.accepted ? "accepted" : `rejected:${d.failedChecks[0] ?? (d.reasons[0]?.startsWith("verifier error") ? "exception" : "?")}`;
    if (shipped) v.outcome += ":asShipped";
    v.check(d.accepted === expectAccept, "verifyReply=oracle", `accepted=${d.accepted}, oracle ${expectAccept} (${c.family}: ${c.recipe.join("; ")}); failed ${d.failedChecks.join(",")}; ${d.reasons.join("; ").slice(0, 200)}`);
    if (d.reasons.some((x) => x.startsWith("verifier error on hostile input"))) v.observe("exceptionPath", `an exception inside verifyReply was turned into a rejection: ${d.reasons[0]?.slice(0, 200)}`);
    if (!d.accepted) {
      const first14 = ["shape", "sessionKnown", "transcriptDecrypts", "issuerRecord", "issuerPop", "accreditation", "issuerKeyHash", "epochAnchorCurrent", "epochWindow", "revRoot", "policyHash", "nonceBinding", "stmtCode", "groth16"];
      const failedEarly = d.failedChecks.some((x) => first14.includes(x)) || d.notEvaluated.length === 16;
      if (failedEarly) {
        v.check(W.verifier.sessions.status(h.request.sessionId) === "open", "rejectedReplyDoesNotConsume", `session ${k} no longer open after a rejected reply`);
        const again = await W.verifier.verifyReply(h.reply);
        v.check(again.accepted, "honestStillAcceptedAfterHostile", `honest reply of session ${k} rejected after a hostile reply: ${again.reasons.join("; ").slice(0, 200)}`);
      }
    }
    return v.done();
  },
};

function mutateHexByte(rng: Rng, hex: string): string {
  const i = rng.int(0, hex.length / 2 - 1);
  const b = (parseInt(hex.slice(2 * i, 2 * i + 2), 16) ^ (1 << rng.int(0, 7))).toString(16).padStart(2, "0");
  return hex.slice(0, 2 * i) + b + hex.slice(2 * i + 2);
}

// =====================================================================================
// T-wallet-req
// =====================================================================================

const tWalletReq: FuzzTarget = {
  id: "T-wallet-req",
  title: "wallet request checks",
  entryPoints: ["HolderWalletV4.checkRequest", "HolderWalletV4.present (exotic requests only)"],
  kind: "chain",
  budget: 5_000,
  smokeBudget: 30,
  property:
    "checkRequest (a fresh wallet per case, so the date log is empty) either returns the verifier's registered KEM key or throws WalletRefusal naming a WALLET_CHECKS check; it returns only for a request that the reference accepts and that names this chain, the registered verifier, a standard threshold, an allowed type and an acceptable date; present() on a Proxy or a throwing getter refuses with requestShape before any other check",
  documentedErrors: ["WalletRefusal"],
  async setup(ctx) {
    await ensureWorld(ctx.log, ctx.smoke ? 4 : K_HONEST, ctx.emit);
  },
  async teardown() {
    await stopWorld();
  },
  gen(rng) {
    return plan(rng, rng.weighted<string>([
      [1, "honest"],
      [6, "mutated"],
      [1, "exotic"],
    ]));
  },
  async run(c) {
    const v = new Verdict();
    const W = CW as ChainWorld;
    const rng = new Rng(Number(c.meta?.["subSeed"] ?? 0));
    const wallet = await walletOnCache(W);
    const base = await W.verifier.newRequest({ predicate: rng.pick(["age_gte", "age_lt"] as const), threshold: rng.pick([...STANDARD_THRESHOLDS]), typeId: DEFAULT_TYPE_ID });
    let req: unknown = cloneJson(base);
    if (c.family === "mutated") {
      const m = mutateValue(rng, req, rng.int(1, 2));
      req = m.value;
      c.recipe.push(...m.ops);
    }
    if (c.family === "exotic") {
      const kind = rng.pick(["proxy", "throwing-proxy", "throwing-getter"] as const);
      const e = exotic(rng, req as Record<string, unknown>, kind);
      c.recipe.push(...e.ops);
      const r = await timedCallAsync(() => wallet.present(e.value as ProofRequestV4));
      v.callMs = r.ms;
      const ok = r.error instanceof WalletRefusal && r.error.check === "requestShape";
      v.check(ok, "present:exoticRefusedAsRequestShape", r.error ? `${errClass(r.error)}: ${errMsg(r.error)}` : "present() answered an exotic request");
      v.outcome = ok ? "refused:requestShape" : "other";
      return v.done();
    }
    const r = await timedCallAsync(() => wallet.checkRequest(req as ProofRequestV4));
    v.callMs = r.ms;
    const x = req as Record<string, unknown>;
    const pol = (x && typeof x === "object" ? x["policy"] : null) as Record<string, unknown> | null;
    const now = W.world.clock.nowSec();
    const shouldPass =
      refRequestValid(req) &&
      x["chainId"] === W.chainId &&
      x["verifierDid"] === base.verifierDid &&
      x["verifierController"] === base.verifierController &&
      !!pol &&
      STANDARD_THRESHOLDS.includes(pol["threshold"] as number) &&
      pol["typeId"] === DEFAULT_TYPE_ID &&
      acceptableTodays(now, WALLET_CLOCK_SKEW_SEC).includes(pol["today"] as number);
    if (r.error) {
      const named = r.error instanceof WalletRefusal && (WALLET_CHECKS as readonly string[]).includes(r.error.check);
      v.check(named, "checkRequest:onlyNamedRefusals", `threw ${errClass(r.error)}: ${errMsg(r.error)}`);
      v.check(!shouldPass, "checkRequest:refusedGoodRequest", `refused a request the reference accepts: ${errMsg(r.error)}`);
      v.outcome = `refused:${r.error instanceof WalletRefusal ? r.error.check : errClass(r.error)}`;
    } else {
      v.check(shouldPass, "checkRequest:acceptedBadRequest", `accepted (${c.recipe.join("; ")})`);
      v.outcome = "accepted";
    }
    return v.done();
  },
};

// =====================================================================================
// T-wallet-iss
// =====================================================================================

const SECRET_MARK = "SECRET-SOURCE-TEXT";

const tWalletIss: FuzzTarget = {
  id: "T-wallet-iss",
  title: "wallet checks of served issuer data",
  entryPoints: ["HolderWalletV4.checkIssuerData"],
  kind: "chain",
  budget: 5_000,
  smokeBudget: 30,
  property:
    "checkIssuerData through a mutating IssuerDataSource returns only for the exact anchored canonical epoch statement with a path whose root is the anchored root and a revocation opening against the anchored revRoot; otherwise it throws WalletRefusal naming a WALLET_CHECKS check, and the refusal text never contains the credID, the leaf index or the data source's own error text (review round 2, VRA-1)",
  documentedErrors: ["WalletRefusal"],
  async setup(ctx) {
    await ensureWorld(ctx.log, ctx.smoke ? 4 : K_HONEST, ctx.emit);
  },
  async teardown() {
    await stopWorld();
  },
  gen(rng) {
    return plan(rng, rng.weighted<string>([
      [1, "honest"],
      [4, "statement"],
      [1, "path-root"],
      [1, "rev-root"],
      [1, "issuance-throws"],
      [1, "revocation-throws"],
      [1, "statement-type"],
    ]));
  },
  async run(c) {
    const v = new Verdict();
    const W = CW as ChainWorld;
    const rng = new Rng(Number(c.meta?.["subSeed"] ?? 0));
    const held = (W.holders[0] as HolderWalletV4).credentials[0] as HeldCredentialV4;
    const wallet = await walletOnCache(W);
    const leafIndex = W.issuer.leafIndexByCredId.get(held.vc.credID) ?? -1;
    const honestServed = held.source.issuance(held.vc.credID);
    const honestRev = held.source.revocation(held.vc.credID);
    let changedStatement = false;
    let changedRoot = false;
    let changedRev = false;
    const source: IssuerDataSource = {
      issuance: (id) => {
        const s = held.source.issuance(id);
        if (c.family === "issuance-throws") throw new Error(`${SECRET_MARK} no leaf ${leafIndex} for ${id}`);
        let statement: unknown = cloneJson(s.statement);
        if (c.family === "statement") {
          const m = mutateValue(rng, statement, 1);
          statement = m.value;
          changedStatement = !sameJson(statement, s.statement);
          c.recipe.push(...m.ops);
        }
        if (c.family === "statement-type") {
          const e = exotic(rng, statement as Record<string, unknown>, rng.pick(["getter", "class-instance", "null-proto"] as const));
          statement = e.value;
          c.recipe.push(...e.ops);
        }
        const path = { ...s.path };
        if (c.family === "path-root") {
          path.root = (BigInt(s.path.root) + 1n).toString();
          changedRoot = true;
        }
        return { path, statement: statement as typeof s.statement };
      },
      revocation: (id) => {
        const r = held.source.revocation(id);
        if (c.family === "revocation-throws") throw new Error(`${SECRET_MARK} credential ${id} at leaf ${leafIndex} is revoked`);
        if (c.family === "rev-root") {
          changedRev = true;
          return { ...r, root: (BigInt(r.root) + 1n).toString() };
        }
        return r;
      },
    };
    const r = await timedCallAsync(() => wallet.checkIssuerData({ ...held, source }));
    v.callMs = r.ms;
    if (r.error) {
      const named = r.error instanceof WalletRefusal && (WALLET_CHECKS as readonly string[]).includes(r.error.check);
      v.check(named, "checkIssuerData:onlyNamedRefusals", `threw ${errClass(r.error)}: ${errMsg(r.error)}`);
      const msg = errMsg(r.error);
      v.check(!msg.includes(SECRET_MARK) && !msg.includes(held.vc.credID), "refusalLeaksNothing", `refusal text: ${msg.slice(0, 200)}`);
      if (/\bleaf\b/i.test(msg) && msg.includes(String(leafIndex))) v.fail("refusalLeaksLeafIndex", `refusal text names the leaf index: ${msg.slice(0, 200)}`);
      const exoticOk = c.family === "statement-type"; // a class instance or getter statement may be read like data
      v.check(changedStatement || changedRoot || changedRev || c.family.endsWith("throws") || exoticOk, "checkIssuerData:refusedHonestData", `refused honest data: ${msg}`);
      v.outcome = `refused:${r.error instanceof WalletRefusal ? r.error.check : errClass(r.error)}`;
    } else {
      const out = r.value as Awaited<ReturnType<HolderWalletV4["checkIssuerData"]>>;
      const exact = sameJson(out.statement, honestServed.statement) && out.path.root === honestServed.path.root && out.rev.root === honestRev.root;
      v.check(exact && !changedRoot && !changedRev, "checkIssuerData:acceptedOnlyAnchored", `returned for changed data (${c.family}: ${c.recipe.join("; ")})`);
      if (changedStatement) v.fail("checkIssuerData:acceptedChangedStatement", `accepted a changed statement (${c.recipe.join("; ")})`);
      v.outcome = "accepted";
    }
    return v.done();
  },
};

export const CHAIN_TARGETS: readonly FuzzTarget[] = [tVerify, tWalletReq, tWalletIss];
