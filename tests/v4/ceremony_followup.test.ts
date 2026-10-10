import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { spawnSync } from "node:child_process";
import { REPO_ROOT } from "@pqid/common/paths";
import * as L from "../../harness/v4/ceremony/followup_lib.ts";
import { keyChecksPass, type KeyChecksResult } from "../../harness/v4/ceremony/key_checks.ts";
import { d034Ports, LEGACY_CHAIN_PORTS } from "../../harness/v4/lib/ports.ts";

/**
 * Ceremony follow-up rules (harness/v4/ceremony/followup_lib.ts, docs/v4/CEREMONY_FOLLOWUP.md).
 * Read-only on the repository: the committed dev-key suite and mutation campaign are inputs of
 * the regression tests, nothing is written.
 */

const repo = (r: string) => path.join(REPO_ROOT, ...r.split("/"));
const readJson = <T>(r: string): T => JSON.parse(fs.readFileSync(repo(r), "utf8")) as T;
const sha = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");
const hex = (n: number) => randomBytes(n).toString("hex");

/** The first drand round (default network) due at or after `iso`. */
const roundAt = (iso: string) => Math.ceil((Date.parse(iso) / 1000 - L.DRAND_DEFAULT_GENESIS_TIME) / L.DRAND_DEFAULT_PERIOD_SEC) + 1;

/** Point the transcript's drand plan and response at the round due at `iso` (consistently). */
function setDrandRound(t: L.CeremonyTranscript, iso: string): void {
  const round = roundAt(iso);
  t.beacon.source.round = round;
  t.beacon.source.expectedTimeUtc = L.drandRoundTimeUtc(round) as string;
  (t.beacon.source.response as { round: number }).round = round;
}

// ------------------------------------------------------------------ a ceremony transcript that passes

function goodTranscript(): { t: L.CeremonyTranscript; ctx: L.TranscriptContext } {
  const sig = randomBytes(96);
  const randomness = sha(sig);
  const r1csSha = hex(32);
  const ptauSha = hex(32);
  const files = { zkeySha: hex(32), vkeySha: hex(32), solSha: hex(32) };
  const round = roundAt("2026-10-20T12:00:00Z");
  const t: L.CeremonyTranscript = {
    schema: "pqid/ceremony-transcript/v1",
    label: "ceremony",
    circuit: { name: "credential_auth_v4", r1cs: { file: L.FROZEN_R1CS_REL, sha256: r1csSha, freeze: { match: true, source: L.FREEZE_REL } }, circuitHash: hex(64) },
    ptau: { file: L.PTAU_REL, sha256: ptauSha, pin: { checked: true, pinFile: "setup/pins.json", pinName: L.PTAU_PIN_NAME } },
    contributions: [1, 2, 3].map((i) => ({ index: i, name: `contributor ${i}`, contributionHash: hex(64), acceptedAtUtc: `2026-10-1${i}T10:00:00.000Z`, reportedHashMatched: true, receiptMatched: true, verifiedByContributor: true })),
    beacon: {
      index: 4,
      name: "beacon: drand default round 1",
      value: randomness,
      numIterationsExp: 10,
      contributionHash: hex(64),
      source: { kind: "drand", chainHash: L.DRAND_DEFAULT_CHAIN_HASH, round, expectedTimeUtc: L.drandRoundTimeUtc(round) as string, plannedAtUtc: "2026-10-10T09:00:00.000Z", announced: "announced", response: { round, randomness, signature: sig.toString("hex") } },
    },
    final: { zkey: { file: "ceremony/v4/final/credential_auth_v4_final.zkey", sha256: files.zkeySha }, verificationKey: { file: "ceremony/v4/final/verification_key.json", sha256: files.vkeySha }, solidityVerifier: { file: "ceremony/v4/final/Groth16Verifier.sol", sha256: files.solSha }, verifiedFromR1cs: true },
    tools: { snarkjs: "0.7.4" },
  };
  return { t, ctx: { mode: "ceremony", frozenR1csSha: r1csSha, pinnedPtauSha: ptauSha, external: [2], files } };
}

const statusOf = (cs: L.Check[], id: string) => cs.find((c) => c.id === id)?.status;
const failedIds = (cs: L.Check[]) => L.failed(cs).map((c) => c.id);

describe("transcript rules (ceremony mode)", () => {
  it("a complete ceremony transcript passes every rule, with no warning", () => {
    const { t, ctx } = goodTranscript();
    const cs = L.checkTranscript(t, ctx);
    expect(failedIds(cs)).toEqual([]);
    expect(cs.filter((c) => c.status === "warn")).toEqual([]);
    expect(cs.length).toBeGreaterThan(25);
  });

  const cases: Array<[string, (t: L.CeremonyTranscript, ctx: L.TranscriptContext) => void, string]> = [
    ["rehearsal label", (t) => (t.label = "rehearsal"), "label"],
    ["only two contributions", (t) => {
      t.contributions.pop();
      t.beacon.index = 3;
    }, "contributions.count"],
    ["no external contribution declared", (_t, c) => (c.external = []), "contributions.externalDeclared"],
    ["declared external index out of range", (_t, c) => (c.external = [4]), "contributions.externalDeclared"],
    ["r1cs is not the frozen one", (t) => (t.circuit.r1cs.sha256 = hex(32)), "r1cs.frozen"],
    ["frozen r1cs unknown", (_t, c) => (c.frozenR1csSha = null), "r1cs.frozen"],
    ["ptau not the pinned one", (t) => (t.ptau.sha256 = hex(32)), "ptau.pinned"],
    ["dummy beacon", (t) => (t.beacon.source = { kind: "dummy" }), "beacon.kind"],
    ["drand round due before the last contribution", (t) => setDrandRound(t, "2026-10-12T00:00:00Z"), "beacon.unknownAtLastContribution"],
    ["recorded round time is not the round's time on the default network", (t) => (t.beacon.source.expectedTimeUtc = "2026-10-25T00:00:00.000Z"), "beacon.drandRoundTime"],
    ["three contributions under one name", (t) => t.contributions.forEach((c) => (c.name = "Same Person")), "contributions.distinctContributors"],
    ["names that differ only in case and spaces", (t) => t.contributions.forEach((c, i) => (c.name = ["Ana  Lee", " ana lee", "ANA LEE "][i] as string)), "contributions.distinctContributors"],
    ["a contribution without a name", (t) => ((t.contributions[2] as L.TranscriptContribution).name = "  "), "contributions.distinctContributors"],
    ["beacon planned after the last contribution", (t) => (t.beacon.source.plannedAtUtc = "2026-10-14T00:00:00.000Z"), "beacon.plannedBeforeLastContribution"],
    ["another drand network", (t) => (t.beacon.source.chainHash = hex(32)), "beacon.drandChain"],
    ["randomness is not sha256(signature)", (t) => {
      const r = t.beacon.source.response as NonNullable<L.TranscriptBeaconSource["response"]>;
      r.signature = hex(96);
    }, "beacon.drandSha"],
    ["beacon value differs from the round", (t) => (t.beacon.value = hex(32)), "beacon.drandValue"],
    ["response for another round", (t) => ((t.beacon.source.response as { round: number }).round = 1), "beacon.drandRound"],
    ["fewer than 2^10 iterations", (t) => (t.beacon.numIterationsExp = 9), "beacon.iterations"],
    ["beacon not right after the contributions", (t) => (t.beacon.index = 5), "beacon.index"],
    ["a rehearsal contribution", (t) => ((t.contributions[0] as L.TranscriptContribution).name = "REHEARSAL ONLY contributor 1"), "contributions.notRehearsal"],
    ["the same contribution twice", (t) => ((t.contributions[1] as L.TranscriptContribution).contributionHash = (t.contributions[0] as L.TranscriptContribution).contributionHash), "contributions.distinctHashes"],
    ["a reported hash that did not match", (t) => ((t.contributions[1] as L.TranscriptContribution).reportedHashMatched = false), "contributions.secondRouteHash"],
    ["final zkey on disk differs", (_t, c) => (c.files.zkeySha = hex(32)), "final.zkeySha"],
    ["final zkey missing", (_t, c) => (c.files.zkeySha = null), "final.zkeySha"],
    ["verification key differs", (_t, c) => (c.files.vkeySha = hex(32)), "final.vkeySha"],
    ["Solidity verifier differs", (_t, c) => (c.files.solSha = hex(32)), "final.solSha"],
    ["coordinator did not verify at finalize", (t) => (t.final.verifiedFromR1cs = false), "final.verifiedFromR1cs"],
    ["another snarkjs", (t) => (t.tools = { snarkjs: "0.7.5" }), "tools.snarkjs"],
    ["wrong schema", (t) => (t.schema = "other"), "schema"],
  ];
  for (const [name, mutate, id] of cases) {
    it(`fails: ${name}`, () => {
      const { t, ctx } = goodTranscript();
      mutate(t, ctx);
      const cs = L.checkTranscript(t, ctx);
      expect(statusOf(cs, id)).toBe("fail");
    });
  }

  it("warns (not fails) when a hash came by no second route, or the plan came after the first contribution", () => {
    const { t, ctx } = goodTranscript();
    (t.contributions[1] as L.TranscriptContribution).reportedHashMatched = null;
    t.beacon.source.plannedAtUtc = "2026-10-11T12:00:00.000Z";
    const cs = L.checkTranscript(t, ctx);
    expect(failedIds(cs)).toEqual([]);
    expect(statusOf(cs, "contributions.secondRouteHash")).toBe("warn");
    expect(statusOf(cs, "contributions.externalSecondRoute")).toBe("warn");
    expect(statusOf(cs, "beacon.plannedBeforeFirstContribution")).toBe("warn");
  });

  it("a Bitcoin beacon passes, with a warning that the block time is checked by hand", () => {
    const { t, ctx } = goodTranscript();
    const h = hex(32);
    t.beacon.value = h;
    t.beacon.source = { kind: "bitcoin", height: 990_000, blockHash: h, plannedAtUtc: "2026-10-10T09:00:00.000Z" };
    const cs = L.checkTranscript(t, ctx);
    expect(failedIds(cs)).toEqual([]);
    expect(statusOf(cs, "beacon.unknownAtLastContribution")).toBe("warn");
  });

  it("rehearsal mode skips the freeze and pin rules and allows the dummy beacon, but still needs 3 contributions", () => {
    const { t, ctx } = goodTranscript();
    t.label = "rehearsal";
    t.beacon.source = { kind: "dummy" };
    const cs = L.checkTranscript(t, { ...ctx, mode: "rehearsal", frozenR1csSha: null, pinnedPtauSha: null });
    expect(failedIds(cs)).toEqual([]);
    expect(statusOf(cs, "r1cs.frozen")).toBe("skipped");
    t.contributions.pop();
    t.beacon.index = 3;
    expect(failedIds(L.checkTranscript(t, { ...ctx, mode: "rehearsal", frozenR1csSha: null, pinnedPtauSha: null }))).toContain("contributions.count");
  });

  it("records carry hashes and declared roles, never contributor names", () => {
    const { t } = goodTranscript();
    const rec = JSON.stringify({ c: L.contributionsForRecord(t, [2]), b: L.beaconForRecord(t), n: L.contributorCounts(t, [2]) });
    expect(rec).not.toContain("contributor ");
    expect(L.contributionsForRecord(t, [2]).map((c) => c.declaredExternal)).toEqual([false, true, false]);
    expect(L.contributorCounts(t, [2])).toEqual({ contributions: 3, distinctNames: 3, externalSharingAName: [] });
  });

  it("warns (not fails) when a declared external contribution shares its name with another one", () => {
    const { t, ctx } = goodTranscript();
    // four contributions, three distinct people; the declared external #4 has the name of #1
    t.contributions.push({ ...(t.contributions[0] as L.TranscriptContribution), index: 4, contributionHash: hex(64), acceptedAtUtc: "2026-10-14T10:00:00.000Z" });
    t.beacon.index = 5;
    ctx.external = [4];
    const cs = L.checkTranscript(t, ctx);
    expect(failedIds(cs)).toEqual([]);
    expect(statusOf(cs, "contributions.distinctContributors")).toBe("pass");
    expect(statusOf(cs, "contributions.externalNameUnique")).toBe("warn");
    expect(L.contributorCounts(t, [4])).toEqual({ contributions: 4, distinctNames: 3, externalSharingAName: [4] });
  });

  it("the drand round time is recomputed from the default network, as the kit does", () => {
    expect(L.drandRoundTimeUtc(1)).toBe(new Date(L.DRAND_DEFAULT_GENESIS_TIME * 1000).toISOString());
    expect(L.drandRoundTimeUtc(roundAt("2026-10-20T12:00:00Z"))).toBe("2026-10-20T12:00:00.000Z");
    for (const bad of [0, -1, 1.5, "7", null]) expect(L.drandRoundTimeUtc(bad)).toBeNull();
    const lib = fs.readFileSync(repo("ceremony/lib.mjs"), "utf8");
    expect(lib).toContain(`genesisTime: ${L.DRAND_DEFAULT_GENESIS_TIME},`);
    expect(lib).toContain(`periodSec: ${L.DRAND_DEFAULT_PERIOD_SEC},`);
  });

  it("kit-file hashes: equal to the committed kit passes, any other hash or file warns, no list warns", () => {
    const accepted = { "lib.mjs": ["a".repeat(64), "b".repeat(64)], "coordinator.mjs": ["c".repeat(64)] };
    expect(L.kitFilesCheck({ "lib.mjs": "b".repeat(64), "coordinator.mjs": "c".repeat(64) }, accepted).status).toBe("pass");
    expect(L.kitFilesCheck({ "lib.mjs": "d".repeat(64), "coordinator.mjs": "c".repeat(64) }, accepted).status).toBe("warn");
    expect(L.kitFilesCheck({ "lib.mjs": "a".repeat(64) }, accepted).status).toBe("warn");
    expect(L.kitFilesCheck({ "lib.mjs": "a".repeat(64), "coordinator.mjs": "c".repeat(64), "extra.mjs": "e".repeat(64) }, accepted).status).toBe("warn");
    expect(L.kitFilesCheck(undefined, accepted).status).toBe("warn");
    const { t, ctx } = goodTranscript();
    t.tools = { snarkjs: "0.7.4", kitFilesSha256: { "lib.mjs": "d".repeat(64), "coordinator.mjs": "c".repeat(64) } };
    const cs = L.checkTranscript(t, { ...ctx, kitFiles: accepted });
    expect(failedIds(cs)).toEqual([]);
    expect(statusOf(cs, "tools.kitFiles")).toBe("warn");
    expect(statusOf(L.checkTranscript(t, ctx), "tools.kitFiles")).toBe("skipped");
  });

  it("the kit-file list is the kit's own list (coordinator.mjs KIT_FILES)", () => {
    expect(fs.readFileSync(repo("ceremony/coordinator.mjs"), "utf8")).toContain(`const KIT_FILES = ${JSON.stringify(L.KIT_FILES).replace(/,/g, ", ")};`);
  });
});

// ------------------------------------------------------------------ the rehearsal transcript and its real snarkjs log (fixtures)

describe("rehearsal fixtures (real kit transcript and real snarkjs 0.7.4 `zkey verify` output)", () => {
  // tests/v4/fixtures: copies of ceremony/rehearsal/_out/ceremony/final/ceremony_transcript.json and of
  // `node node_modules/snarkjs/build/cli.cjs zkey verify <tiny.r1cs> <pot8_final.ptau> <tiny_final.zkey>`
  // (stdout and stderr, ANSI colours kept), made on 2026-10-03. REHEARSAL ONLY names, tiny circuit.
  const t = readJson<L.CeremonyTranscript>("tests/v4/fixtures/ceremony_rehearsal_transcript.json");
  const log = fs.readFileSync(repo("tests/v4/fixtures/ceremony_rehearsal_zkey_verify.log"), "utf8");

  it("the parser reads the real CLI output: ZKey Ok, circuit hash, 3 contributions and the beacon", () => {
    expect(log).toContain("\u001b[");
    const p = L.parseCliVerify(log);
    expect(p.ok).toBe(true);
    expect(p.circuitHash).toBe(t.circuit.circuitHash);
    expect(p.contributions.map((c) => [c.index, c.type, c.name])).toEqual([
      [1, "contribution", "REHEARSAL ONLY contributor 1 (contribute.ps1)"],
      [2, "contribution", "REHEARSAL ONLY contributor 2 (contribute.sh)"],
      [3, "contribution", "REHEARSAL ONLY contributor 3 (contribute.ps1)"],
      [4, "beacon", "REHEARSAL ONLY dummy beacon"],
    ]);
    expect(p.contributions.map((c) => c.contributionHash)).toEqual([...t.contributions.map((c) => c.contributionHash), t.beacon.contributionHash]);
    expect(p.contributions[3]).toMatchObject({ beaconHash: "5123ef05b95eb9e8b63b54dde02dd7158bd1dea923f9ce28727cdc6451575fc1", numIterationsExp: 10 });
    expect(L.failed(L.compareVerifyWithTranscript(t, p))).toEqual([]);
  });

  it("the real transcript passes the rehearsal-mode rules (files, kit hashes and the external name aside)", () => {
    const cs = L.checkTranscript(t, { mode: "rehearsal", frozenR1csSha: null, pinnedPtauSha: null, external: [1], files: { zkeySha: t.final.zkey.sha256, vkeySha: t.final.verificationKey.sha256, solSha: t.final.solidityVerifier.sha256 } });
    expect(failedIds(cs)).toEqual([]);
    expect(cs.filter((c) => c.status === "warn")).toEqual([]);
    expect(statusOf(cs, "contributions.distinctContributors")).toBe("skipped");
    // in ceremony mode the same transcript fails the rules a real ceremony must meet
    const cer = failedIds(L.checkTranscript(t, { mode: "ceremony", frozenR1csSha: null, pinnedPtauSha: null, external: [1], files: { zkeySha: null, vkeySha: null, solSha: null } }));
    for (const id of ["label", "r1cs.frozen", "ptau.pinned", "contributions.notRehearsal", "beacon.kind"]) expect(cer).toContain(id);
  });

  it("the fixtures carry no path outside the repository, user name or host name", () => {
    for (const text of [log, JSON.stringify(t)]) {
      expect(text).not.toMatch(/(?:^|[^A-Za-z])[A-Za-z]:[\\/]|\/home\/|\/Users\/|\\\\Users\\\\/);
    }
  });
});

// ------------------------------------------------------------------ snarkjs zkey verify output

const E = "\u001b";
const info = (s: string) => `${E}[32;22m[INFO]  ${E}[39;1msnarkJS${E}[0m: ${s}`;
function hexBlock(h: string): string {
  const groups = h.match(/.{8}/g) as string[];
  return [0, 4, 8, 12].map((i) => `\t\t${groups.slice(i, i + 4).join(" ")}`).join("\n");
}

function cliOutput(t: L.CeremonyTranscript, ok = true): string {
  const lines = [info("Reading r1cs"), info("Circuit hash: "), hexBlock(t.circuit.circuitHash), info("Circuit Hash: "), hexBlock(t.circuit.circuitHash), info("-------------------------")];
  lines.push(info(`contribution #${t.beacon.index} ${t.beacon.name}:`), hexBlock(t.beacon.contributionHash), info(`Beacon generator: ${t.beacon.value}`), info(`Beacon iterations Exp: ${t.beacon.numIterationsExp}`), info("-------------------------"));
  for (const c of [...t.contributions].reverse()) lines.push(info(`contribution #${c.index} ${c.name}:`), hexBlock(c.contributionHash), info("-------------------------"));
  if (ok) lines.push(info("ZKey Ok!"));
  return lines.join("\n") + "\n";
}

describe("snarkjs zkey verify log", () => {
  it("parses the CLI output (ANSI colours, hex blocks, beacon lines) into the contribution list", () => {
    const { t } = goodTranscript();
    const p = L.parseCliVerify(cliOutput(t));
    expect(p.ok).toBe(true);
    expect(p.circuitHash).toBe(t.circuit.circuitHash);
    expect(p.contributions.map((c) => [c.index, c.type])).toEqual([[1, "contribution"], [2, "contribution"], [3, "contribution"], [4, "beacon"]]);
    expect(p.contributions[3]?.beaconHash).toBe(t.beacon.value);
    expect(p.contributions[3]?.numIterationsExp).toBe(10);
    expect(L.failed(L.compareVerifyWithTranscript(t, p))).toEqual([]);
  });

  it("a name, hash or order that differs from the transcript fails", () => {
    const { t } = goodTranscript();
    const p = L.parseCliVerify(cliOutput(t));
    const t2 = structuredClone(t);
    (t2.contributions[0] as L.TranscriptContribution).name = "someone else";
    expect(failedIds(L.compareVerifyWithTranscript(t2, p))).toContain("zkeyVerify.contributionList");
    const t3 = structuredClone(t);
    t3.beacon.numIterationsExp = 11;
    expect(failedIds(L.compareVerifyWithTranscript(t3, p))).toContain("zkeyVerify.contributionList");
  });

  it("no 'ZKey Ok!' or another circuit hash fails", () => {
    const { t } = goodTranscript();
    expect(failedIds(L.compareVerifyWithTranscript(t, L.parseCliVerify(cliOutput(t, false))))).toContain("zkeyVerify.ok");
    const t2 = structuredClone(t);
    t2.circuit.circuitHash = hex(64);
    expect(failedIds(L.compareVerifyWithTranscript(t2, L.parseCliVerify(cliOutput(t))))).toContain("zkeyVerify.circuitHash");
  });

  it("parses the kit's audit summary", () => {
    expect(L.parseAuditLog("[audit] PASS a\n[audit] PASS b\n[audit] ALL CHECKS PASSED\n")).toEqual({ passed: true, failedChecks: [], passedChecks: 2 });
    const bad = L.parseAuditLog("[audit] PASS a\n[audit] FAIL contribution list\n[audit] 1 CHECK(S) FAILED\n");
    expect(bad.passed).toBe(false);
    expect(bad.failedChecks).toEqual(["contribution list"]);
    expect(L.parseAuditLog("").passed).toBe(false);
  });
});

// ------------------------------------------------------------------ install targets and pins

describe("install targets and pins", () => {
  it("the ceremony key gets new paths next to the dev key, never the dev names", () => {
    const t = L.installTargets("ceremony");
    expect(t.map((x) => x.rel)).toEqual([
      "setup/out/v4/credential_auth_v4_ceremony.zkey",
      "setup/out/v4/verification_key_ceremony.json",
      "setup/out/v4/Groth16VerifierV4_ceremony.sol",
      "setup/out/v4/setup_transcript_ceremony.json",
    ]);
    expect(t.map((x) => x.pinKey)).toEqual(t.map((x) => `v4/${path.basename(x.rel)}`));
    expect(L.pinsFileRel("ceremony")).toBe("setup/pins_v4_ceremony.json");
    expect(L.keySpecRel("ceremony")).toBe("setup/key_spec_v4_ceremony.json");
    for (const bad of ["dev", "Ceremony", "", "a/b", "x".repeat(40)]) expect(() => L.installTargets(bad)).toThrow();
    expect(() => L.installTargets("ceremony", "../elsewhere")).toThrow();
  });

  it("the dev pins are untouched: a new pins file, no dev path, no dev pin name", () => {
    const devPins = readJson<Record<string, { path?: string }>>(L.DEV_PINS_REL);
    expect(Object.keys(devPins)).toEqual([...L.DEV_PIN_KEYS]);
    expect(() => L.assertNoDevOverlap(L.installTargets("ceremony"), devPins, L.pinsFileRel("ceremony"))).not.toThrow();
    expect(() => L.assertNoDevOverlap(L.installTargets("ceremony"), devPins, L.DEV_PINS_REL)).toThrow(/dev pins only/);
    const evil: L.InstallTarget[] = [{ role: "zkey", rel: "setup/out/v4/credential_auth_v4_dev.zkey", pinKey: "v4/x.zkey" }];
    expect(() => L.assertNoDevOverlap(evil, devPins, L.pinsFileRel("ceremony"))).toThrow(/dev-key file/);
  });

  it("pin entries are added to a new canonical file, are idempotent and never rewritten", () => {
    const e = (s: string): L.PinEntry => ({ sha256: s, label: "ceremony", path: "setup/out/v4/credential_auth_v4_ceremony.zkey" });
    const a = hex(32);
    const first = L.addPinEntries(L.EMPTY_PINS_TEXT, { "v4/credential_auth_v4_ceremony.zkey": e(a) });
    expect(first.added).toEqual(["v4/credential_auth_v4_ceremony.zkey"]);
    expect(first.text).toBe(JSON.stringify({ "v4/credential_auth_v4_ceremony.zkey": e(a) }, null, 2) + "\n");
    const again = L.addPinEntries(first.text, { "v4/credential_auth_v4_ceremony.zkey": e(a) });
    expect(again).toEqual({ text: first.text, added: [], unchanged: ["v4/credential_auth_v4_ceremony.zkey"] });
    // a re-run names another run id in the note: the same file stays pinned as it was
    const rerun = L.addPinEntries(first.text, { "v4/credential_auth_v4_ceremony.zkey": { ...e(a), note: "checked by run followup_2026-10-21_r2" } });
    expect(rerun).toEqual({ text: first.text, added: [], unchanged: ["v4/credential_auth_v4_ceremony.zkey"] });
    expect(() => L.addPinEntries(first.text, { "v4/credential_auth_v4_ceremony.zkey": { ...e(a), label: "ceremony2" } })).toThrow(/never rewritten/);
    expect(() => L.addPinEntries(first.text, { "v4/credential_auth_v4_ceremony.zkey": { ...e(a), path: "setup/out/v4/other.zkey" } })).toThrow(/never rewritten/);
    expect(() => L.addPinEntries(first.text, { "v4/credential_auth_v4_ceremony.zkey": e(hex(32)) })).toThrow(/never rewritten/);
    expect(() => L.addPinEntries(first.text, { "v4/other.zkey": e(hex(32)) })).toThrow(/already exists under another name/);
    expect(() => L.addPinEntries(JSON.stringify({}), { "v4/a.zkey": e(a) })).toThrow(/canonical/);
    expect(() => L.addPinEntries(L.EMPTY_PINS_TEXT, { "v4/a.zkey": { ...e(a), label: "dev" } })).toThrow(/reserved/);
    expect(() => L.addPinEntries(L.EMPTY_PINS_TEXT, { "a.zkey": e(a) })).toThrow(/v4\//);
    // the committed dev pins file is canonical, so the same function would refuse to change an entry in it
    const devText = fs.readFileSync(repo(L.DEV_PINS_REL), "utf8").replace(/\r\n/g, "\n");
    expect(() => L.addPinEntries(devText, { "v4/credential_auth_v4_dev.zkey": { sha256: hex(32), label: "ceremony", path: "x" } })).toThrow();
  });

  it("text files with CR bytes are not installed (they would be committed with other bytes than their pins)", () => {
    const lf = Buffer.from('{\n  "a": 1\n}\n');
    const crlf = Buffer.from('{\r\n  "a": 1\r\n}\r\n');
    expect(L.crProblems([{ rel: "ceremony/v4/final/verification_key.json", bytes: lf }])).toEqual([]);
    const p = L.crProblems([
      { rel: "ceremony/v4/final/verification_key.json", bytes: crlf },
      { rel: "ceremony/v4/final/Groth16Verifier.sol", bytes: Buffer.from("pragma\r\n") },
      { rel: "ceremony/v4/final/ceremony_transcript.json", bytes: lf },
      { rel: "ceremony/v4/final/credential_auth_v4_final.zkey", bytes: Buffer.from([1, 13, 10, 2]) },
    ]);
    expect(p).toHaveLength(2);
    expect(p[0]).toMatch(/verification_key\.json contains CR bytes.*re-run the kit audit/);
    expect(p[1]).toMatch(/Groth16Verifier\.sol/);
    // Publication checkout preserves exact bytes; the key preflight still rejects CR bytes.
    const attrs = fs.readFileSync(repo(".gitattributes"), "utf8");
    expect(attrs).toMatch(/^\* -text\r?$/m);
    expect(attrs).toMatch(/^\*\.zkey binary\r?$/m);
  });

  it("the campaign flags and key spec name the ceremony key, its pins file and no dev label", () => {
    expect(L.cmpKeyFlags("ceremony")).toEqual(["--v4-zkey", "setup/out/v4/credential_auth_v4_ceremony.zkey", "--v4-vkey", "setup/out/v4/verification_key_ceremony.json", "--v4-key-label", "ceremony key", "--v4-pins", "setup/pins_v4_ceremony.json"]);
    expect(L.cmpKeyEnv("ceremony")).toEqual({ PQID_CMP_V4_ZKEY: "setup/out/v4/credential_auth_v4_ceremony.zkey", PQID_CMP_V4_VKEY: "setup/out/v4/verification_key_ceremony.json", PQID_CMP_V4_LABEL: "ceremony key", PQID_CMP_V4_PINS: "setup/pins_v4_ceremony.json" });
    const spec = L.e2eKeySpec("ceremony");
    expect(spec.label).toBe("ceremony");
    expect(spec.wasm).toEqual({ rel: L.FROZEN_WASM_REL, pin: { file: "setup/pins_v4.json", key: "v4/credential_auth_v4.wasm" } });
    expect(spec.zkey.pin).toEqual({ file: "setup/pins_v4_ceremony.json", key: "v4/credential_auth_v4_ceremony.zkey" });
    expect(/\bdev\b/i.test(L.cmpKeyLabel("ceremony"))).toBe(false);
    // the wasm pin the key spec points at exists in the dev pins file with the frozen wasm's path
    expect(readJson<Record<string, { path: string }>>(L.DEV_PINS_REL)["v4/credential_auth_v4.wasm"]?.path).toBe(L.FROZEN_WASM_REL);
  });

  it("lists every series that uses a v4 key, with the post-ceremony commands", () => {
    const u = L.keyUsers("ceremony");
    expect(new Set(u.map((x) => x.series)).size).toBe(u.length);
    const text = u.map((x) => x.how).join("\n");
    expect(text).toContain("--key-spec setup/key_spec_v4_ceremony.json");
    expect(text).toContain("--v4-key-label 'ceremony key' --v4-pins setup/pins_v4_ceremony.json");
    expect(text).toContain("PQID_CMP_V4_LABEL='ceremony key' PQID_CMP_V4_PINS=setup/pins_v4_ceremony.json bash scripts/cmp/quiet_window_cmp.sh");
    expect(L.shellJoin(["a b", "it's", "x=y"])).toBe("'a b' 'it'\\''s' x=y");
    expect(L.shellEnv({ A: "x y", B: "z" })).toBe("A='x y' B=z");
    expect(() => L.shellEnv({ "A B": "x" })).toThrow();
    for (const s of ["C1 security suite", "C3 mutation campaign", "Phase D warm_wsl, cold_rs_wsl (results/v4/bench_wsl/)", "cmp cold_cmp, warm_cmp (results/v4/cmp/prove/)", "e2e e2e_cold_wsl, e2e_warm_wsl (results/v4/e2e/)"]) expect(u.some((x) => x.series === s)).toBe(true);
  });
});

// ------------------------------------------------------------------ small helpers

describe("names, dates, ports and code paths", () => {
  it("dated names never reuse an existing one", () => {
    const have = new Set(["followup_2026-10-20", "followup_2026-10-20_r2"]);
    expect(L.pickDatedName("followup", "2026-10-21", "", (n) => have.has(n))).toBe("followup_2026-10-21");
    expect(L.pickDatedName("followup", "2026-10-20", "", (n) => have.has(n))).toBe("followup_2026-10-20_r3");
    expect(() => L.pickDatedName("followup", "20261020", "", () => false)).toThrow();
  });

  it("parses --external and repository-relative paths", () => {
    expect(L.parseIndexList("3, 2,3")).toEqual([2, 3]);
    expect(L.parseIndexList(undefined)).toEqual([]);
    expect(() => L.parseIndexList("0")).toThrow();
    expect(() => L.parseIndexList("two")).toThrow();
    expect(L.cleanRel(".\\ceremony\\v4\\final\\", "x")).toBe("ceremony/v4/final");
    for (const bad of ["/etc", "C:/x", "a/../b", ""]) expect(() => L.cleanRel(bad, "x")).toThrow();
  });

  it("FREEZE.md, the dev pins and the file agree on the frozen r1cs; the ptau pin is the committed Hermez file", () => {
    const freeze = L.parseFreezeTable(fs.readFileSync(repo(L.FREEZE_REL), "utf8"));
    const r1cs = freeze.get(L.FROZEN_R1CS_REL);
    expect(r1cs).toMatch(/^[0-9a-f]{64}$/);
    expect(readJson<Record<string, { sha256: string }>>(L.DEV_PINS_REL)["v4/credential_auth_v4.r1cs"]?.sha256).toBe(r1cs);
    expect(freeze.get(L.PTAU_REL)).toBe(readJson<Record<string, { sha256: string }>>(L.PINS_REL)[L.PTAU_PIN_NAME]?.sha256);
  });

  it("the drand chain hash is the kit's default network", () => {
    expect(fs.readFileSync(repo("ceremony/lib.mjs"), "utf8")).toContain(`chainHash: "${L.DRAND_DEFAULT_CHAIN_HASH}"`);
  });

  it("follow-up ports stay clear of D-034, the committed chain ports, the suite default and the dev mutation range", () => {
    expect(L.defencePort(0)).toBe(8801);
    expect(L.defencePort(58)).toBe(8859);
    expect(L.defencePort(98)).toBe(8899);
    expect(() => L.defencePort(99)).toThrow();
    const ours = [L.CEREMONY_PORTS.suite, ...Array.from({ length: 99 }, (_, i) => L.defencePort(i))];
    const taken = new Set<number>([...d034Ports(), ...LEGACY_CHAIN_PORTS, 8581, ...Array.from({ length: 100 }, (_, i) => 8600 + i)]);
    expect(ours.filter((p) => taken.has(p))).toEqual([]);
    // the ports the preflight probes for the selected steps
    expect(L.portsForSteps(["verify", "keys", "install"], [])).toEqual([]);
    expect(L.portsForSteps(["suite"], [])).toEqual([8800]);
    expect(L.portsForSteps(["suite", "mutation"], [58, 0, 15])).toEqual([8800, 8801, 8816, 8859]);
    expect(L.portsForSteps(["mutation"], [57])).toEqual([8858]);
  });

  it("exit codes: refused before the start 3, stopped after the start 4, review 5, nothing ran 1", () => {
    expect(L.EXIT).toEqual({ pass: 0, fail: 1, usage: 2, refused: 3, stopped: 4, review: 5 });
    expect(L.exitCode("pass", false)).toBe(0);
    expect(L.exitCode("review", false)).toBe(5);
    expect(L.exitCode("fail", false)).toBe(1);
    expect(L.exitCode("skipped", false)).toBe(1);
    expect(L.exitCode("pass", true)).toBe(4);
    const sh = fs.readFileSync(repo("scripts/ceremony/followup.sh"), "utf8");
    for (const [code, word] of [[0, "PASS"], [3, "REFUSED"], [4, "STOPPED"], [5, "REVIEW"], [2, "USAGE"]] as const) expect(sh).toMatch(new RegExp(`\\n\\s*${code}\\) echo "followup\\.sh: ${word}`));
  });

  it("the record label names only the steps that completed, and says when a run is not a result", () => {
    expect(L.recordLabel("real", "ceremony", ["verify", "keys", "install"])).toBe(
      "[M] ceremony follow-up (TASKS I): ceremony key: verified (transcript rules, kit audit, snarkjs zkey verify); key checks (proof round trip, same circuit and phase 1 as the dev key, no public-beacon trapdoor); installed on new paths and pinned in its own pins file"
    );
    expect(L.recordLabel("real", "ceremony", [])).toMatch(/no step completed/);
    expect(L.recordLabel("real", "ceremony", ["suite", "mutation"])).toMatch(/C1 security suite re-run with it under the rekey loader; C3 mutation campaign/);
    expect(L.recordLabel("dry", "rehearsal", ["verify"])).toMatch(/^DRY RUN.*not a result/);
    expect(L.recordLabel("check", "ceremony", ["verify", "keys"])).toMatch(/^CHECK ONLY.*not a result/);
    expect(L.KEY_SWITCH).toEqual({ method: expect.stringContaining("harness/v4/ceremony/rekey.mjs") as unknown as string, packageDefaultKey: "dev" });
  });

  it("every recorded code file exists", () => {
    for (const f of L.CODE_FILES) expect(fs.existsSync(repo(f)), f).toBe(true);
    for (const f of ["harness/v4/cmp/spec.ts", "harness/v4/e2e/lib.ts"]) {
      expect(L.CODE_FILES).toContain(f);
      expect(L.CODE_PATHS).toContain(f);
    }
  });

  it("the follow-up's own files are LF in the working tree (the record hashes working-tree bytes)", () => {
    const own = [...fs.readdirSync(repo("harness/v4/ceremony")).map((f) => `harness/v4/ceremony/${f}`), "scripts/ceremony/followup.sh", "docs/v4/CEREMONY_FOLLOWUP.md", "tests/v4/ceremony_followup.test.ts", "tests/v4/ceremony_rekey.test.ts", "tests/v4/ceremony_devrerun.test.ts"];
    for (const f of own) expect(fs.readFileSync(repo(f)).includes(13), f).toBe(false);
  });

  it("overall status", () => {
    expect(L.overallStatus({ a: "pass", b: "pass" })).toBe("pass");
    expect(L.overallStatus({ a: "pass", b: "review" })).toBe("review");
    expect(L.overallStatus({ a: "review", b: "fail" })).toBe("fail");
    expect(L.overallStatus({ a: "skipped" })).toBe("skipped");
    expect(L.overallStatus({})).toBe("skipped");
  });
});

// ------------------------------------------------------------------ verdict comparisons (committed dev-key runs, read only)

describe("comparisons against the dev-key suite and mutation campaign", () => {
  const devSuite = readJson<L.SuiteFile>(L.DEV_SUITE_REL);
  const devTable = readJson<L.MutationTable>(L.DEV_MUTATION_REL);

  it("the dev suite equals itself (130 verdicts, the count of the rebuild check)", () => {
    const c = L.compareSuites(devSuite, devSuite);
    expect(c.identical).toBe(true);
    expect(c.verdictsBase).toBe(130);
  });

  it("the frozen suite's fixed label text and its T1 beacon are the ones the follow-up's note explains", () => {
    const label = (devSuite as { label?: string }).label as string;
    expect(label).toContain("dev key");
    const src = fs.readFileSync(repo("harness/v4/security_suite.ts"), "utf8");
    expect(src).toContain(JSON.stringify(label));
    expect(src).toContain(`"${L.CONTROL_V2_BEACON}", 10`);
    const note = L.suiteLabelNote(label, "ceremony");
    expect(note).toContain("ceremony key");
    expect(note).toContain("keys/key_checks.json");
  });

  it("one changed verdict or one missing route is a difference", () => {
    const s = structuredClone(devSuite);
    const a = s.records.find((r) => r.kind === "attack")?.attempts[0] as L.SuiteAttempt;
    a.accepted = true;
    a.stoppedBy = { layer: "accepted", checks: [] };
    const c = L.compareSuites(devSuite, s);
    expect(c.identical).toBe(false);
    expect(c.verdictDiffs).toHaveLength(1);
    const s2 = structuredClone(devSuite);
    s2.records[0]?.attempts.pop();
    expect(L.compareSuites(devSuite, s2).verdictDiffs.length).toBeGreaterThan(0);
  });

  it("the follow-up's mutation rule reproduces all 59 rows of campaign 5 from its committed suite outputs", () => {
    const base = L.mutationVerdicts(devSuite);
    expect(devTable.rows).toHaveLength(59);
    for (const r of devTable.rows) {
      const f = `results/v4/mutation/${r.kind}__${r.name}/security_suite.json`;
      const m = L.mutationRow(base, L.mutationVerdicts(readJson<L.SuiteFile>(f)));
      for (const k of ["routesNowAccepted", "controlsBroken", "stoppedElsewhere", "harnessErrors"] as const) expect(isDeepStrictEqual(m[k], r[k]), `${r.kind}:${r.name} ${k}`).toBe(true);
    }
  });

  it("table comparison: identical, partial (--only), and a changed row", () => {
    expect(L.compareMutationTables(devTable, devTable).identical).toBe(true);
    const only = new Set(["governance"]);
    const part = { rows: devTable.rows.filter((r) => r.kind === "governance"), noEffect: (devTable.noEffect ?? []).filter((k) => k.startsWith("governance:")) };
    expect(L.compareMutationTables(devTable, part, only).identical).toBe(true);
    expect(L.compareMutationTables(devTable, part).missing.length).toBe(58);
    const changed = structuredClone(devTable);
    (changed.rows[0] as L.MutationTableRow).routesNowAccepted = [];
    const c = L.compareMutationTables(devTable, changed);
    expect(c.identical).toBe(false);
    expect(c.differing[0]?.field).toBe("routesNowAccepted");
    const errored = structuredClone(devTable);
    (errored.rows[1] as L.MutationTableRow).error = "suite produced no output";
    expect(L.compareMutationTables(devTable, errored).differing.some((d) => d.field === "error")).toBe(true);
  });

  it("mutation status: campaign 5 compared with itself passes although one of its rows has harness errors", () => {
    const withErrors = L.harnessErrorRows(devTable.rows);
    expect(withErrors).toEqual(["governance:issuerPopBeforeAccreditation"]);
    expect(L.mutationStatus([], L.compareMutationTables(devTable, devTable))).toBe("pass");
    // the documented smoke --only governance: the partial table equal to campaign 5's row passes too
    const only = new Set(["governance"]);
    const part = { rows: devTable.rows.filter((r) => r.kind === "governance"), noEffect: (devTable.noEffect ?? []).filter((k) => k.startsWith("governance:")) };
    expect(L.mutationStatus([], L.compareMutationTables(devTable, part, only))).toBe("pass");
    // a changed harness-error list is a difference (review); a run error fails
    const changed = structuredClone(devTable);
    const g = changed.rows.find((r) => r.kind === "governance") as L.MutationTableRow;
    g.harnessErrors = [...(g.harnessErrors ?? []), "X|new route: unexpected exception: something else"];
    expect(L.mutationStatus([], L.compareMutationTables(devTable, changed))).toBe("review");
    const cleared = structuredClone(devTable);
    (cleared.rows.find((r) => r.kind === "governance") as L.MutationTableRow).harnessErrors = [];
    expect(L.mutationStatus([], L.compareMutationTables(devTable, cleared))).toBe("review");
    expect(L.mutationStatus(["circuit:G02_holder_commit: suite produced no output"], L.compareMutationTables(devTable, devTable))).toBe("fail");
  });

  it("the defence list and its order are campaign 5's (the order fixes the ports: 8600 + index there, 8801 + index here)", async () => {
    const F = await import("../../harness/v4/ceremony/followup.ts");
    const all = F.allDefences();
    expect(all).toHaveLength(59);
    expect(all.map((x) => `${x.kind}:${x.name}`).sort()).toEqual(devTable.rows.map((r) => `${r.kind}:${r.name}`).sort());
    for (const x of all) {
      const cfg = readJson<{ port: number }>(`results/v4/mutation/${x.kind}__${x.name}/config.json`);
      expect(cfg.port - L.CAMPAIGN5_BASE_PORT, `${x.kind}:${x.name}`).toBe(x.index);
    }
    expect(F.selectDefences(new Set(["governance"])).map((x) => x.index)).toEqual([58]);
    expect(F.selectDefences(new Set(["circuit:G02_holder_commit", "wallet"])).length).toBe(1 + all.filter((x) => x.kind === "wallet").length);
    expect(() => F.selectDefences(new Set(["nothing"]))).toThrow(/matches no defence/);
  });

  it("the mutant configs equal campaign 5's config.json for all 59 defences (paths repo-relative; port and out aside)", async () => {
    const F = await import("../../harness/v4/ceremony/followup.ts");
    const { MUTANTS_DIR } = await import("../../harness/v4/mutate.ts");
    expect(path.relative(REPO_ROOT, MUTANTS_DIR).split(path.sep).join("/")).toBe(L.MUTANTS_DIR_REL);
    const norm = (v: unknown): unknown => (typeof v === "string" ? v.replace(/^<repo>[\\/]/, "").replace(/\\/g, "/") : Array.isArray(v) ? v.map(norm) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, norm(x)])) : v);
    for (const x of F.allDefences()) {
      const committed = norm(readJson<Record<string, unknown>>(`results/v4/mutation/${x.kind}__${x.name}/config.json`)) as Record<string, unknown>;
      const built: L.MutantBuilt = x.kind === "circuit" ? { circuit: L.mutantPaths(x.name) } : x.kind === "registry" ? { contractsFile: L.mutantContractsRel(x.name) } : {};
      const { cfg, env } = L.mutantConfig(x, 1, "out", built);
      const strip = (c: Record<string, unknown>) => Object.fromEntries(Object.entries(c).filter(([k]) => k !== "port" && k !== "out"));
      expect(strip(cfg), `${x.kind}:${x.name}`).toEqual(strip(committed));
      expect(env).toEqual(x.kind === "registry" ? { PQID_V4_CONTRACTS: L.mutantContractsRel(x.name) } : {});
    }
  });

  it("the registry mutant removes every require of its check and nothing else", () => {
    const src = fs.readFileSync(repo("onchain/contracts/v4/RegistriesV4.sol"), "utf8");
    const checks = devTable.rows.filter((r) => r.kind === "registry").map((r) => r.name);
    expect(checks.length).toBe(8);
    for (const c of checks) {
      const m = L.mutantContractsSource(src, c);
      expect(m.removed, c).toBeGreaterThan(0);
      expect(m.text).not.toContain(`"${c}:`);
      for (const other of checks.filter((o) => o !== c)) expect(m.text.split(`"${other}:`).length, `${c} keeps ${other}`).toBe(src.split(`"${other}:`).length);
      expect(L.mutantContractsRel(c)).toBe(`circuits/build/v4/mutants/contracts/RegistriesV4__no_${c}.sol`);
    }
    expect(() => L.mutantContractsSource(src, "noSuchCheck")).toThrow(/no require/);
  });

  it("two keys of one circuit differ only in delta", () => {
    const dev = readJson<L.VkeyLike>(L.DEV_VKEY_REL);
    expect(L.compareVkeys(dev, dev)).toEqual({ sameAlphaBetaGamma: true, sameIC: true, deltaDiffers: false });
    const other = structuredClone(dev);
    other.vk_delta_2 = [["1", "2"], ["3", "4"], ["1", "0"]];
    expect(L.compareVkeys(dev, other)).toEqual({ sameAlphaBetaGamma: true, sameIC: true, deltaDiffers: true });
  });
});

// ------------------------------------------------------------------ driver options and inputs (no run, nothing written)

describe("follow-up driver: options and inputs", () => {
  it("parses a real run and a dry run, and refuses unsafe combinations", async () => {
    const F = await import("../../harness/v4/ceremony/followup.ts");
    const real = F.parseOptions(["--external", "3,2"]);
    expect(real).toMatchObject({ mode: "ceremony", dry: false, label: "ceremony", finalDirRel: "ceremony/v4/final", external: [2, 3], steps: ["verify", "keys", "install", "suite", "mutation"], jobs: 2, allowUncommitted: false });
    const dry = F.parseOptions(["--dry-run"]);
    expect(dry).toMatchObject({ mode: "rehearsal", dry: true, label: "rehearsal", finalDirRel: L.REHEARSAL_FINAL_DIR_REL, external: [1], steps: ["verify", "keys", "install"] });
    expect(() => F.parseOptions([])).toThrow(/--external/);
    expect(() => F.parseOptions(["--external", "2", "--label", "dev"])).toThrow(/dev/);
    expect(() => F.parseOptions(["--external", "2", "--label", "other"])).toThrow(/ceremony/);
    expect(() => F.parseOptions(["--dry-run", "--label", "ceremony"])).toThrow(/dry run/);
    expect(() => F.parseOptions(["--external", "2", "--steps", "install"])).toThrow(/verify and keys/);
    expect(() => F.parseOptions(["--steps", "mutation"])).toThrow(/--baseline/);
    expect(() => F.parseOptions(["--external", "2", "--steps", "nope"])).toThrow(/unknown step/);
    expect(() => F.parseOptions(["--external", "2", "--jobs", "9"])).toThrow(/--jobs/);
    expect(() => F.parseOptions(["--external", "2", "--final-dir", "../elsewhere"])).toThrow();
    expect(F.parseOptions(["--steps", "suite"]).steps).toEqual(["suite"]);
  });

  it("--check-only: verify and keys on the ceremony outputs, ceremony rules, external indexes required", async () => {
    const F = await import("../../harness/v4/ceremony/followup.ts");
    expect(F.parseOptions(["--check-only", "--external", "2"])).toMatchObject({ kind: "check", mode: "ceremony", dry: false, checkOnly: true, label: "ceremony", finalDirRel: "ceremony/v4/final", external: [2], steps: ["verify", "keys"] });
    expect(F.parseOptions(["--check-only", "--external", "2", "--steps", "verify"]).steps).toEqual(["verify"]);
    expect(() => F.parseOptions(["--check-only"])).toThrow(/--external/);
    expect(() => F.parseOptions(["--check-only", "--external", "2", "--steps", "verify,keys,install"])).toThrow(/only the verify and keys/);
    expect(() => F.parseOptions(["--check-only", "--dry-run"])).toThrow(/exclude each other/);
    expect(F.parseOptions(["--external", "2"]).kind).toBe("real");
    expect(F.parseOptions(["--dry-run"]).kind).toBe("dry");
  });

  it("the frozen r1cs, the frozen wasm and the pinned ptau agree in this repository", async () => {
    const F = await import("../../harness/v4/ceremony/followup.ts");
    const f = F.frozenInputs();
    expect(f.notes).toEqual([]);
    const devPins = readJson<Record<string, { sha256: string; path: string }>>(L.DEV_PINS_REL);
    expect(f.frozenR1csSha).toBe(devPins["v4/credential_auth_v4.r1cs"]?.sha256);
    expect(f.frozenWasmSha).toBe(devPins["v4/credential_auth_v4.wasm"]?.sha256);
    expect(devPins["v4/credential_auth_v4.wasm"]?.path).toBe(L.FROZEN_WASM_REL);
    expect(f.pinnedPtauSha).toBe(readJson<Record<string, { sha256: string }>>(L.PINS_REL)[L.PTAU_PIN_NAME]?.sha256);
  });

  it("the code record names git blobs and preserves unavailable HEAD metadata; every kit file has an accepted hash", async () => {
    const F = await import("../../harness/v4/ceremony/followup.ts");
    const rec = F.codeRecord();
    const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT, encoding: "utf8", env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" }, windowsHide: true });
    expect(Object.keys(rec)).toEqual([...L.CODE_FILES]);
    for (const f of L.CODE_FILES) {
      expect(rec[f]?.sha256, f).toMatch(/^[0-9a-f]{64}$/);
      expect(rec[f]?.sha256, f).toBe(sha(fs.readFileSync(repo(f))));
      expect(rec[f]?.gitBlob, f).toMatch(/^[0-9a-f]{40,64}$/);
      if (head.status !== 0) expect(rec[f], f).toMatchObject({ headBlob: null, matchesHead: null });
    }
    if (head.status === 0) {
      expect(head.stdout.trim()).toMatch(/^[0-9a-f]{40,64}$/);
      expect(rec["harness/v4/security_suite.ts"]).toMatchObject({ matchesHead: true });
    }
    const kit = F.kitAccepted();
    expect(Object.keys(kit).sort()).toEqual([...L.KIT_FILES].sort());
    for (const f of L.KIT_FILES) {
      const workingSha = sha(fs.readFileSync(repo(`ceremony/${f}`)));
      expect(kit[f]?.length, f).toBeGreaterThan(0);
      expect(kit[f], f).toContain(workingSha);
      for (const acceptedSha of kit[f] ?? []) expect(acceptedSha, f).toMatch(/^[0-9a-f]{64}$/);
      if (head.status !== 0) expect(kit[f], f).toEqual([workingSha]);
    }
  });

  it.skipIf(!fs.existsSync(repo(`${L.REHEARSAL_FINAL_DIR_REL}/ceremony_transcript.json`)))("the install preflight finds no conflict for a new key folder (rehearsal outputs, read only)", async () => {
    const F = await import("../../harness/v4/ceremony/followup.ts");
    const inp = F.loadInputs({ mode: "rehearsal", dry: true, finalDirRel: L.REHEARSAL_FINAL_DIR_REL });
    const keyDir = `${L.CEREMONY_SMOKE_REL}/not_there_${hex(4)}/key`;
    expect(F.installConflicts({ label: "rehearsal" }, inp, { keyDir, pinsRel: L.pinsFileRel("rehearsal", keyDir), specRel: L.keySpecRel("rehearsal", keyDir) })).toEqual([]);
    // the dev pins file is never a target pins file
    expect(F.installConflicts({ label: "rehearsal" }, inp, { keyDir, pinsRel: L.DEV_PINS_REL, specRel: L.keySpecRel("rehearsal", keyDir) }).join(" ")).toMatch(/dev pins only/);
    expect(fs.existsSync(repo(keyDir))).toBe(false);
  });

  it("refuses a real run before the ceremony has finished, and a suite run before the key is installed", async () => {
    const F = await import("../../harness/v4/ceremony/followup.ts");
    const o = F.parseOptions(["--external", "2", "--final-dir", "ceremony/v4_not_there/final"]);
    expect(() => F.loadInputs(o)).toThrow(/finalize/);
    expect(() => F.installedKey({ label: "ceremony" }, { keyDir: "setup/out/v4", pinsRel: "setup/pins_v4_not_there.json" })).toThrow(/no 'ceremony' pin/);
  });
});

// ------------------------------------------------------------------ key checks on the v4 circuit

describe("key checks on the v4 circuit (the dev key as a stand-in for a new key)", () => {
  const lock = readJson<{ versions: Record<string, { file: string; publicSignals: string[] }> }>(L.BENCH_LOCK_REL).versions["v4"] as { file: string; publicSignals: string[] };
  const config = (otherVkey: string | null) => ({
    zkey: repo("setup/out/v4/credential_auth_v4_dev.zkey"),
    vkey: repo(L.DEV_VKEY_REL),
    wasm: repo(L.FROZEN_WASM_REL),
    input: readJson<Record<string, unknown>>(lock.file),
    expectPublic: lock.publicSignals,
    // the dev key's own public beacon (a secret contribution precedes it)
    beacon: { value: L.CONTROL_V2_BEACON, iterExp: 10 },
    otherVkey,
    control: { vkey: repo(L.CONTROL_V2_VKEY_REL), beacon: L.CONTROL_V2_BEACON, iterExp: L.CONTROL_V2_ITER_EXP },
  });

  it("proves the pinned Phase D input, sees no beacon-only trapdoor, and the v2 control sees one", async () => {
    const { runKeyChecks } = await import("../../harness/v4/ceremony/key_checks.ts");
    const r = await runKeyChecks(config(null));
    expect(r.vkeyMatchesZkeyExport).toBe(true);
    expect(r.proof).toMatchObject({ verifies: true, publicSignalsMatch: true, tamperedSignalRejected: true, rejectedByOtherKey: null });
    expect(r.proof.publicSignals).toEqual(lock.publicSignals);
    expect(r.trapdoor).toMatchObject({ beaconDerivedDeltaMatchesKey: false, gammaIsGenerator: true, forgedProofVerifies: false });
    expect(r.trapdoor.control).toMatchObject({ beaconDerivedDeltaMatchesKey: true, forgedProofVerifies: true });
    expect(r.pass).toBe(true);
  });

  it("the same key as its own 'other key' fails (delta equal, proof accepted by it)", async () => {
    const { runKeyChecks } = await import("../../harness/v4/ceremony/key_checks.ts");
    const r = await runKeyChecks(config(repo(L.DEV_VKEY_REL)));
    expect(r.proof.rejectedByOtherKey).toBe(false);
    expect(r.sameCircuitAsOther).toEqual({ sameAlphaBetaGamma: true, sameIC: true, deltaDiffers: false });
    expect(r.pass).toBe(false);
  });
});

// ------------------------------------------------------------------ key checks pass rule

describe("key checks pass rule", () => {
  const good: Omit<KeyChecksResult, "pass" | "schema"> = {
    vkeyMatchesZkeyExport: true,
    proof: { verifies: true, publicSignalsMatch: true, publicSignals: ["1"], rejectedByOtherKey: true, tamperedSignalRejected: true },
    sameCircuitAsOther: { sameAlphaBetaGamma: true, sameIC: true, deltaDiffers: true },
    trapdoor: { beaconDerivedDeltaMatchesKey: false, gammaIsGenerator: true, forgedProofVerifies: false, control: { key: "setup/out/verification_key.json", beaconDerivedDeltaMatchesKey: true, forgedProofVerifies: true } },
  };
  it("passes only when every check holds and the control sees the v2 trapdoor", () => {
    expect(keyChecksPass(good)).toBe(true);
    const flips: Array<(x: typeof good) => void> = [
      (x) => (x.vkeyMatchesZkeyExport = false),
      (x) => (x.proof.verifies = false),
      (x) => (x.proof.publicSignalsMatch = false),
      (x) => (x.proof.rejectedByOtherKey = false),
      (x) => (x.proof.tamperedSignalRejected = false),
      (x) => ((x.sameCircuitAsOther as { sameIC: boolean }).sameIC = false),
      (x) => ((x.sameCircuitAsOther as { deltaDiffers: boolean }).deltaDiffers = false),
      (x) => (x.trapdoor.beaconDerivedDeltaMatchesKey = true),
      (x) => (x.trapdoor.forgedProofVerifies = true),
      (x) => (x.trapdoor.gammaIsGenerator = false),
      (x) => ((x.trapdoor.control as { beaconDerivedDeltaMatchesKey: boolean }).beaconDerivedDeltaMatchesKey = false),
      (x) => ((x.trapdoor.control as { forgedProofVerifies: boolean }).forgedProofVerifies = false),
    ];
    for (const f of flips) {
      const x = structuredClone(good);
      f(x);
      expect(keyChecksPass(x)).toBe(false);
    }
    expect(keyChecksPass({ ...structuredClone(good), proof: { ...good.proof, publicSignalsMatch: null } })).toBe(true);
  });
});
