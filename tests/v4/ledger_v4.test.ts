import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import { randomBytes } from "node:crypto";
import { inspect } from "node:util";
import { ContractFactory, keccak256, Log, type JsonRpcProvider } from "ethers";
import { sha3_256 } from "@pqid/common/hash";
import { didFromPublicKey } from "@pqid/common/did";
import {
  LedgerV4,
  RoleAccount,
  RegistryRevertError,
  LedgerIntegrityError,
  registryCheckOf,
  startAnvil,
  compileSolidityV4,
  CONTRACTS_V4_FILE,
  REGISTRY_CHECKS,
  type AnvilHandle,
  type RegistryCheck,
  type WriteResult,
} from "@pqid/v4/ledger";
import { MIN_ANCHOR_INTERVAL_SEC, MAX_EPOCH_WINDOW_SEC, KEM_ALG } from "@pqid/v4/constants";
import { ManualClock } from "@pqid/v4/clock";
import { mlDsaKeygen, mlDsaSign, mlKemKeygen } from "@pqid/v4/pqc";
import {
  didPopMessage,
  verifierKemMessage,
  parseStatement,
  StatementError,
  MAX_VERIFIER_KEM_SEC,
  type AccreditationStatement,
  type VerifierKemStatement,
} from "@pqid/v4/statements";
import {
  accreditIssuer,
  checkAccreditation,
  checkRecordAndPop,
  createGovernance,
  nextAccreditationSerial,
  type Governance,
} from "@pqid/v4/governance";
import { registerWithPop } from "@pqid/v4/issuer";

/**
 * v4 registries and ledger client (V4_DESIGN sections 4, 6.3, 7) on a local Anvil node.
 * The contracts never verify ML-DSA, so signatures here are random buffers of the real
 * ML-DSA-44 size (2420 bytes); public keys are 1312 bytes, ML-KEM-768 keys 1184 bytes.
 * Every EVM key is a fresh in-memory role account.
 */

const PORT = 8561;
const MIN = MIN_ANCHOR_INTERVAL_SEC;
const MAX_WINDOW = MAX_EPOCH_WINDOW_SEC;
const ML_DSA_44_PK = 1312;
const ML_DSA_44_SIG = 2420;
const ML_KEM_768_PK = 1184;

let anvil: AnvilHandle;
let ledger: LedgerV4;
let gov: RoleAccount;
let issuerA: RoleAccount;
let issuerB: RoleAccount;
let issuerC: RoleAccount;
let verifier: RoleAccount;
let stranger: RoleAccount;

const DID = "did:pq:" + randomBytes(32).toString("hex");
const VERIFIER_DID = "did:pq:" + randomBytes(32).toString("hex");
const pkA = randomBytes(ML_DSA_44_PK);
const pkB = randomBytes(ML_DSA_44_PK);
const sigA = randomBytes(ML_DSA_44_SIG);
const sigB = randomBytes(ML_DSA_44_SIG);
const nonceA = randomBytes(32).toString("hex");
const nonceB = randomBytes(32).toString("hex");

const gas: Record<string, WriteResult> = {};

/** A canonical-JSON-sized statement (the contracts store only its hash). */
function statementBytes(fields: Record<string, unknown>): Buffer {
  return Buffer.from(JSON.stringify(fields), "utf8");
}

async function expectCheck(p: Promise<unknown>, check: RegistryCheck): Promise<RegistryRevertError> {
  let err: unknown = null;
  try {
    await p;
  } catch (e) {
    err = e;
  }
  expect(err, `expected a ${check} revert`).toBeInstanceOf(RegistryRevertError);
  const e = err as RegistryRevertError;
  expect(e.check).toBe(check);
  expect(registryCheckOf(e)).toBe(check);
  expect(e.message).toContain(check);
  return e;
}

/** Run fn while the ledger's provider returns logs with one byte flipped where `needle` occurs. */
async function withTamperedLogs<T>(needle: Buffer, fn: () => Promise<T>): Promise<T> {
  const provider = (ledger as unknown as { provider: JsonRpcProvider }).provider;
  const orig = provider.getLogs.bind(provider);
  const needleHex = needle.subarray(0, 32).toString("hex");
  provider.getLogs = async (filter) => {
    const logs = await orig(filter);
    return logs.map((l) => {
      const at = l.data.indexOf(needleHex);
      if (at < 0) return l;
      const c = l.data[at] === "0" ? "1" : "0";
      const data = l.data.slice(0, at) + c + l.data.slice(at + 1);
      return new Log(
        {
          transactionHash: l.transactionHash,
          blockHash: l.blockHash,
          blockNumber: l.blockNumber,
          removed: l.removed,
          address: l.address,
          data,
          topics: l.topics,
          index: l.index,
          transactionIndex: l.transactionIndex,
        } as Log,
        provider
      );
    });
  };
  try {
    return await fn();
  } finally {
    provider.getLogs = orig;
  }
}

beforeAll(async () => {
  anvil = await startAnvil(PORT);
  gov = RoleAccount.random("governance");
  ledger = await LedgerV4.deploy(anvil.rpcUrl, {
    minAnchorIntervalSec: MIN,
    maxWindowSec: MAX_WINDOW,
    governanceAddress: gov.address,
  });
  await ledger.fund(gov);
  issuerA = await ledger.newRoleAccount("issuer-a");
  issuerB = await ledger.newRoleAccount("issuer-b");
  issuerC = await ledger.newRoleAccount("issuer-c");
  verifier = await ledger.newRoleAccount("verifier");
  stranger = await ledger.newRoleAccount("stranger");
}, 120_000);

afterAll(() => {
  ledger?.destroy();
  anvil?.stop();
});

describe("v4 registries: deployment and accounts", () => {
  it("deploys four registries with the configured policy and a separate governance account", async () => {
    const a = ledger.addresses;
    const all = [a.didRegistry, a.accreditationRegistry, a.issuanceRootRegistry, a.verifierKemRegistry];
    expect(new Set(all).size).toBe(4);
    for (const x of all) expect(x).toMatch(/^0x[0-9a-f]{40}$/);
    expect(await ledger.chainId()).toBe(31337);
    expect(await ledger.getMinAnchorInterval()).toBe(MIN);
    expect(await ledger.getMaxWindow()).toBe(MAX_WINDOW);
    expect(await ledger.governanceAddress()).toBe(gov.address);
    expect(gov.address).not.toBe(ledger.deployment.deployer);
    for (const g of Object.values(ledger.deployment.deployGas)) expect(g).toBeGreaterThan(100_000);
  });

  it("role accounts are fresh, distinct, funded and never expose their key", async () => {
    const addrs = [gov, issuerA, issuerB, issuerC, verifier, stranger].map((r) => r.address);
    expect(new Set(addrs).size).toBe(addrs.length);
    for (const x of addrs) expect(x).toMatch(/^0x[0-9a-f]{40}$/);
    expect(addrs).not.toContain(ledger.deployment.deployer);
    const json = JSON.stringify(issuerA);
    expect(JSON.parse(json)).toEqual({ label: "issuer-a", address: issuerA.address });
    const shown = inspect(issuerA, { depth: 10, showHidden: true }) + String(issuerA) + json;
    expect(shown.replace(issuerA.address.slice(2), "")).not.toMatch(/[0-9a-fA-F]{64}/);
  });

  it("recordKey is keccak256(abi.encodePacked(did, controller)) on chain and off chain", async () => {
    const onChain = (await ledger.rawContract("DIDRegistryV4").getFunction("recordKeyOf")(DID, issuerA.address)) as string;
    expect(onChain.toLowerCase()).toBe(LedgerV4.recordKey(DID, issuerA.address));
    const packed = Buffer.concat([Buffer.from(DID, "utf8"), Buffer.from(issuerA.address.slice(2), "hex")]);
    expect(LedgerV4.recordKey(DID, issuerA.address)).toBe(keccak256(packed));
    expect(LedgerV4.recordKey(DID, issuerA.address)).not.toBe(LedgerV4.recordKey(DID, issuerB.address));
  });
});

describe("DIDRegistryV4", () => {
  it("two controllers register records for the same DID string; both exist under distinct record keys", async () => {
    gas["registerDid"] = await ledger.registerDid(issuerA, {
      did: DID,
      pk: pkA,
      popNonce: nonceA,
      popSig: sigA,
      origin: "https://issuer-a.example",
    });
    await ledger.registerDid(issuerB, { did: DID, pk: pkB, popNonce: "0x" + nonceB, popSig: sigB, origin: "" });

    const ra = await ledger.resolveDidRecord(DID, issuerA.address);
    const rb = await ledger.resolveDidRecord(DID, issuerB.address);
    expect(ra).not.toBeNull();
    expect(rb).not.toBeNull();
    if (!ra || !rb) return;
    expect(ra.recordKey).not.toBe(rb.recordKey);
    expect(ra.recordKey).toBe(LedgerV4.recordKey(DID, issuerA.address));
    expect(ra.controller).toBe(issuerA.address);
    expect(ra.pk.equals(pkA)).toBe(true);
    expect(rb.pk.equals(pkB)).toBe(true);
    expect(ra.popNonce).toBe(nonceA);
    expect(rb.popNonce).toBe(nonceB);
    expect(ra.popSigHash).toBe(keccak256(sigA).slice(2));
    expect(rb.popSigHash).toBe(keccak256(sigB).slice(2));
    expect(ra.origin).toBe("https://issuer-a.example");
    expect(ra.active && rb.active).toBe(true);
    expect(ra.registeredAt).toBeGreaterThan(0);
    expect(ra.registeredBlock).toBeLessThan(rb.registeredBlock);

    expect(await ledger.resolveDidRecord(DID, stranger.address)).toBeNull();
    expect(await ledger.listDidControllers(DID)).toEqual([issuerA.address, issuerB.address]);
  });

  it("recordUnique: the same (did, controller) cannot register twice", async () => {
    await expectCheck(
      ledger.registerDid(issuerA, { did: DID, pk: pkB, popNonce: nonceB, popSig: sigB, origin: "https://evil.example" }),
      "recordUnique"
    );
    const ra = await ledger.resolveDidRecord(DID, issuerA.address);
    expect(ra?.pk.equals(pkA)).toBe(true);
    expect(ra?.origin).toBe("https://issuer-a.example");
  });

  it("rejects a malformed PoP nonce before sending", async () => {
    await expect(
      ledger.registerDid(stranger, { did: DID, pk: pkA, popNonce: "abcd", popSig: sigA })
    ).rejects.toThrow(/popNonce/);
  });

  it("serves each record's PoP signature from its event log, checked against the stored hash", async () => {
    expect((await ledger.getPopSignature(DID, issuerA.address)).equals(sigA)).toBe(true);
    expect((await ledger.getPopSignature(DID, issuerB.address)).equals(sigB)).toBe(true);
    await expect(ledger.getPopSignature(DID, stranger.address)).rejects.toThrow(/no DID record/);
    // a node that serves altered log bytes is caught by the hash check
    await expect(withTamperedLogs(sigA, () => ledger.getPopSignature(DID, issuerA.address))).rejects.toBeInstanceOf(
      LedgerIntegrityError
    );
    expect((await ledger.getPopSignature(DID, issuerA.address)).equals(sigA)).toBe(true);
  });
});

describe("AccreditationRegistryV4", () => {
  const st1 = statementBytes({
    controller: "0x" + "11".repeat(20),
    issuerDid: DID,
    notAfter: 1_800_000_000 + 30 * 86400,
    notBefore: 1_800_000_000,
    pkSha3: "ab".repeat(32),
    serial: 1,
    status: "accredited",
    type: "pqid:accreditation:v2",
  });
  const sg1 = randomBytes(ML_DSA_44_SIG);
  const st2 = statementBytes({ type: "pqid:accreditation:v2", serial: 2, issuerDid: DID, status: "revoked" });
  const sg2 = randomBytes(ML_DSA_44_SIG);

  it("governanceWriter: only the governance EVM account can publish (not issuers, strangers or the deployer)", async () => {
    expect(await ledger.latestAccreditation(DID)).toBeNull();
    await expectCheck(ledger.publishAccreditation(issuerA, DID, st1, sg1), "governanceWriter");
    await expectCheck(ledger.publishAccreditation(stranger, DID, st1, sg1), "governanceWriter");
    await expectCheck(ledger.publishAccreditation(ledger.devDeployerSigner(), DID, st1, sg1), "governanceWriter");
    expect(await ledger.latestAccreditation(DID)).toBeNull();
  });

  it("publishes statements with full bytes in the log; latest is hash-checked and replaces the previous one", async () => {
    gas["publishAccreditation"] = await ledger.publishAccreditation(gov, DID, st1, sg1);
    const l1 = await ledger.latestAccreditation(DID);
    expect(l1?.statement.equals(st1)).toBe(true);
    expect(l1?.signature.equals(sg1)).toBe(true);
    expect(l1?.serial).toBe(1);
    expect(l1?.publishedAt).toBeGreaterThan(0);

    await ledger.publishAccreditation(gov, DID, st2, sg2);
    const l2 = await ledger.latestAccreditation(DID);
    expect(l2?.statement.equals(st2)).toBe(true);
    expect(l2?.signature.equals(sg2)).toBe(true);
    expect(l2?.serial).toBe(2);

    const hist = await ledger.accreditationHistory(DID);
    expect(hist.map((h) => h.serial)).toEqual([1, 2]);
    expect(hist[0]?.statement.equals(st1)).toBe(true);

    // keyed by keccak256(issuerDid): another DID has nothing
    expect(await ledger.latestAccreditation(VERIFIER_DID)).toBeNull();
    await expect(withTamperedLogs(sg2, () => ledger.latestAccreditation(DID))).rejects.toBeInstanceOf(LedgerIntegrityError);
  });
});

describe("IssuanceRootRegistryV4", () => {
  const sigHash = (): string => randomBytes(32).toString("hex");
  const root1 = 123456789n;
  const rev1 = 987654321n;

  it("controllerOnly, epochIncrement and windowBounds are enforced before the first anchor", async () => {
    const cur0 = await ledger.currentEpoch(DID, issuerA.address);
    expect(cur0.epoch).toBe(0);
    const now = await ledger.blockTimestamp();
    const ok = { did: DID, root: root1, revRoot: rev1, notBefore: now, notAfter: now + MAX_WINDOW, sigHash: sigHash() };

    // a controller without a record for this DID string (another controller's record does not help)
    await expectCheck(ledger.publishEpoch(stranger, { ...ok, epoch: 1 }), "controllerOnly");
    // epochs start at 1 and advance by exactly one
    await expectCheck(ledger.publishEpoch(issuerA, { ...ok, epoch: 0 }), "epochIncrement");
    await expectCheck(ledger.publishEpoch(issuerA, { ...ok, epoch: 2 }), "epochIncrement");
    // notBefore < notAfter <= notBefore + maxWindow
    await expectCheck(ledger.publishEpoch(issuerA, { ...ok, epoch: 1, notAfter: now }), "windowBounds");
    await expectCheck(ledger.publishEpoch(issuerA, { ...ok, epoch: 1, notAfter: now - 1 }), "windowBounds");
    await expectCheck(ledger.publishEpoch(issuerA, { ...ok, epoch: 1, notAfter: now + MAX_WINDOW + 1 }), "windowBounds");
    expect((await ledger.currentEpoch(DID, issuerA.address)).epoch).toBe(0);
  });

  it("anchors epoch 1 at the maximum window and returns every field", async () => {
    const now = await ledger.blockTimestamp();
    const h = sigHash();
    gas["publishEpoch_first"] = await ledger.publishEpoch(issuerA, {
      did: DID,
      epoch: 1,
      root: root1,
      revRoot: rev1.toString(),
      notBefore: now,
      notAfter: now + MAX_WINDOW,
      sigHash: "0x" + h,
    });
    const cur = await ledger.currentEpoch(DID, issuerA.address);
    expect(cur.epoch).toBe(1);
    expect(cur.root).toBe(root1);
    expect(cur.revRoot).toBe(rev1);
    expect(cur.notBefore).toBe(now);
    expect(cur.notAfter).toBe(now + MAX_WINDOW);
    expect(cur.sigHash).toBe(h);
    expect(cur.publishedAt).toBeGreaterThanOrEqual(now);
    expect(cur.publishedBlock).toBe(gas["publishEpoch_first"].blockNumber);
  });

  it("anchorCadence: the next epoch needs minAnchorInterval seconds (exact boundary)", async () => {
    const cur = await ledger.currentEpoch(DID, issuerA.address);
    const next = (notBefore: number) => ({
      did: DID,
      epoch: 2,
      root: root1 + 1n,
      revRoot: rev1 + 1n,
      notBefore,
      notAfter: notBefore + 3600,
      sigHash: sigHash(),
    });
    await expectCheck(ledger.publishEpoch(issuerA, next(cur.publishedAt)), "anchorCadence");
    // a repeated epoch number fails epochIncrement first
    await expectCheck(ledger.publishEpoch(issuerA, { ...next(cur.publishedAt), epoch: 1 }), "epochIncrement");

    await ledger.devSetNextTimestamp(cur.publishedAt + MIN - 1);
    await expectCheck(ledger.publishEpoch(issuerA, next(cur.publishedAt + MIN - 1)), "anchorCadence");

    await ledger.devSetNextTimestamp(cur.publishedAt + MIN);
    gas["publishEpoch_next"] = await ledger.publishEpoch(issuerA, next(cur.publishedAt + MIN));
    const cur2 = await ledger.currentEpoch(DID, issuerA.address);
    expect(cur2.epoch).toBe(2);
    expect(cur2.publishedAt).toBe(cur.publishedAt + MIN);
    expect(cur2.root).toBe(root1 + 1n);
  });

  it("records of the same DID string under different controllers have separate anchors", async () => {
    await ledger.registerDid(issuerC, {
      did: DID,
      pk: randomBytes(ML_DSA_44_PK),
      popNonce: randomBytes(32).toString("hex"),
      popSig: randomBytes(ML_DSA_44_SIG),
    });
    const now = await ledger.blockTimestamp();
    // issuerC starts at epoch 1 although issuerA's record is at epoch 2
    await expectCheck(
      ledger.publishEpoch(issuerC, { did: DID, epoch: 3, root: 5n, revRoot: 6n, notBefore: now, notAfter: now + 60, sigHash: sigHash() }),
      "epochIncrement"
    );
    await ledger.publishEpoch(issuerC, { did: DID, epoch: 1, root: 5n, revRoot: 6n, notBefore: now, notAfter: now + 60, sigHash: sigHash() });
    expect((await ledger.currentEpoch(DID, issuerC.address)).epoch).toBe(1);
    expect((await ledger.currentEpoch(DID, issuerC.address)).root).toBe(5n);
    expect((await ledger.currentEpoch(DID, issuerA.address)).epoch).toBe(2);
    expect((await ledger.currentEpoch(DID, issuerB.address)).epoch).toBe(0);
  });

  it("a reverted transaction mined on chain changes nothing and the signer's next nonce still works", async () => {
    const before = await ledger.currentEpoch(DID, issuerA.address);
    const now = await ledger.blockTimestamp();
    const bad = { did: DID, epoch: 7, root: 1n, revRoot: 1n, notBefore: now, notAfter: now + 60, sigHash: sigHash() };
    const e = await expectCheck(ledger.publishEpoch(issuerA, bad, { gasLimit: 500_000 }), "epochIncrement");
    expect(e.mined).toBe(true);
    expect(await ledger.currentEpoch(DID, issuerA.address)).toEqual(before);

    await ledger.devAdvanceTime(MIN);
    const t = await ledger.blockTimestamp();
    await ledger.publishEpoch(issuerA, { ...bad, epoch: 3, notBefore: t, notAfter: t + 60 });
    expect((await ledger.currentEpoch(DID, issuerA.address)).epoch).toBe(3);
  });
});

describe("VerifierKemRegistryV4", () => {
  const kem1 = randomBytes(ML_KEM_768_PK);
  const kem2 = randomBytes(ML_KEM_768_PK);
  // notBefore strictly increases per record (check kemMonotonic), so a rotation carries a later one
  const kst = (kemPkSha3: string, notBefore = 1_800_000_000) =>
    statementBytes({
      chainId: 31337,
      controller: "0x" + "22".repeat(20),
      kemAlg: "ML-KEM-768",
      kemPkSha3,
      notAfter: notBefore + 86_400,
      notBefore,
      registry: "0x" + "33".repeat(20),
      type: "pqid:verifier-kem:v1",
      verifier: VERIFIER_DID,
    });
  const ksig1 = randomBytes(ML_DSA_44_SIG);
  const ksig2 = randomBytes(ML_DSA_44_SIG);

  it("controllerOnly: only an active record's controller can publish its KEM key", async () => {
    expect(await ledger.latestKemKey(VERIFIER_DID, verifier.address)).toBeNull();
    // not registered yet
    await expectCheck(
      ledger.publishKemKey(verifier, { did: VERIFIER_DID, kemPk: kem1, statement: kst("aa".repeat(32)), signature: ksig1 }),
      "controllerOnly"
    );
    await ledger.registerDid(verifier, {
      did: VERIFIER_DID,
      pk: randomBytes(ML_DSA_44_PK),
      popNonce: randomBytes(32).toString("hex"),
      popSig: randomBytes(ML_DSA_44_SIG),
      origin: "https://verifier.example",
    });
    await expectCheck(
      ledger.publishKemKey(stranger, { did: VERIFIER_DID, kemPk: kem1, statement: kst("aa".repeat(32)), signature: ksig1 }),
      "controllerOnly"
    );
  });

  it("publishes, reads back (hash-checked) and rotates the KEM key", async () => {
    const s1 = kst("aa".repeat(32));
    gas["publishKemKey"] = await ledger.publishKemKey(verifier, { did: VERIFIER_DID, kemPk: kem1, statement: s1, signature: ksig1 });
    const k1 = await ledger.latestKemKey(VERIFIER_DID, verifier.address);
    expect(k1?.kemPk.equals(kem1)).toBe(true);
    expect(k1?.statement.equals(s1)).toBe(true);
    expect(k1?.signature.equals(ksig1)).toBe(true);
    expect(k1?.version).toBe(1);
    expect(k1?.notBefore).toBe(1_800_000_000);

    const s2 = kst("bb".repeat(32), 1_800_000_060);
    await ledger.publishKemKey(verifier, { did: VERIFIER_DID, kemPk: kem2, statement: s2, signature: ksig2 });
    const k2 = await ledger.latestKemKey(VERIFIER_DID, verifier.address);
    expect(k2?.kemPk.equals(kem2)).toBe(true);
    expect(k2?.statement.equals(s2)).toBe(true);
    expect(k2?.version).toBe(2);
    expect(k2?.notBefore).toBe(1_800_000_060);
    expect(await ledger.latestKemKey(VERIFIER_DID, stranger.address)).toBeNull();
    await expect(withTamperedLogs(kem2, () => ledger.latestKemKey(VERIFIER_DID, verifier.address))).rejects.toBeInstanceOf(
      LedgerIntegrityError
    );
  });
});

describe("deactivation", () => {
  it("only the controller deactivates its record; a deactivated record cannot anchor or publish a KEM key", async () => {
    // the stranger has no record for DID, so it cannot touch issuerB's
    await expectCheck(ledger.deactivateDid(stranger, DID), "controllerOnly");
    gas["deactivateDid"] = await ledger.deactivateDid(issuerB, DID);
    expect((await ledger.resolveDidRecord(DID, issuerB.address))?.active).toBe(false);
    expect((await ledger.resolveDidRecord(DID, issuerA.address))?.active).toBe(true);
    await expectCheck(ledger.deactivateDid(issuerB, DID), "controllerOnly");
    const now = await ledger.blockTimestamp();
    await expectCheck(
      ledger.publishEpoch(issuerB, { did: DID, epoch: 1, root: 1n, revRoot: 1n, notBefore: now, notAfter: now + 60, sigHash: "cd".repeat(32) }),
      "controllerOnly"
    );
    await expectCheck(
      ledger.publishKemKey(issuerB, { did: DID, kemPk: randomBytes(ML_KEM_768_PK), statement: Buffer.from("{}"), signature: sigB }),
      "controllerOnly"
    );
    // a deactivated record cannot be re-registered by the same controller either
    await expectCheck(ledger.registerDid(issuerB, { did: DID, pk: pkB, popNonce: nonceB, popSig: sigB }), "recordUnique");
    // its PoP signature stays readable (history), and the record says inactive
    expect((await ledger.getPopSignature(DID, issuerB.address)).equals(sigB)).toBe(true);
  });
});

describe("chain helpers", () => {
  it("dev clock: advance time and set the next block timestamp", async () => {
    const t0 = await ledger.blockTimestamp();
    await ledger.devAdvanceTime(1000);
    const t1 = await ledger.blockTimestamp();
    expect(t1).toBeGreaterThanOrEqual(t0 + 1000);
    await ledger.devSetNextTimestamp(t1 + 5000);
    await ledger.devMine();
    expect(await ledger.blockTimestamp()).toBe(t1 + 5000);
  });

  it("a second client attached with connect() reads the same state", async () => {
    const other = await LedgerV4.connect(anvil.rpcUrl, ledger.addresses, ledger.deployment.fromBlock);
    try {
      expect(await other.currentEpoch(DID, issuerA.address)).toEqual(await ledger.currentEpoch(DID, issuerA.address));
      expect((await other.getPopSignature(DID, issuerA.address)).equals(sigA)).toBe(true);
      expect((await other.latestKemKey(VERIFIER_DID, verifier.address))?.version).toBe(2);
      expect(await other.governanceAddress()).toBe(gov.address);
    } finally {
      other.destroy();
    }
  });

  it("deployGovernanceFirst makes a funded governance account that is not the deployer", async () => {
    const { ledger: l2, governanceAccount } = await LedgerV4.deployGovernanceFirst(anvil.rpcUrl, {
      minAnchorIntervalSec: 60,
      maxWindowSec: 600,
    });
    try {
      expect(await l2.governanceAddress()).toBe(governanceAccount.address);
      expect(governanceAccount.address).not.toBe(l2.deployment.deployer);
      expect(await l2.getMinAnchorInterval()).toBe(60);
      expect(await l2.getMaxWindow()).toBe(600);
      await l2.publishAccreditation(governanceAccount, DID, Buffer.from("{}"), randomBytes(ML_DSA_44_SIG));
      expect((await l2.latestAccreditation(DID))?.serial).toBe(1);
    } finally {
      l2.destroy();
    }
  });
});

/**
 * Review round 1 (B5), registry findings REG-2 to REG-6: real ML-DSA-44 keys and signed
 * statements on the same Anvil node. A second deployment (REG-2) and an uncapped registry
 * variant (REG-3) are deployed on that node as well.
 */
describe("registry review fixes (REG-2 to REG-6)", () => {
  let clock: ManualClock;
  let governance: Governance;

  interface Identity {
    did: string;
    pk: Buffer;
    sk: ReturnType<typeof mlDsaKeygen>["privateKey"];
    account: RoleAccount;
    controller: string;
  }
  const newIdentity = async (label: string): Promise<Identity> => {
    const k = mlDsaKeygen();
    const account = await ledger.newRoleAccount(label);
    return { did: didFromPublicKey(k.publicKey), pk: k.publicKey, sk: k.privateKey, account, controller: account.address };
  };

  beforeAll(async () => {
    clock = new ManualClock(await ledger.blockTimestamp());
    governance = await createGovernance(ledger, gov); // gov is this deployment's governance EVM account
  });

  it("REG-2: a revoked issuer's old accreditation moved to another deployment is refused (chainId and registry are signed)", async () => {
    const I = await newIdentity("reg2-issuer");
    await registerWithPop(ledger, I);
    const acc1 = await accreditIssuer(governance, ledger, clock, { did: I.did, controller: I.controller });
    expect(acc1.fields.chainId).toBe(await ledger.chainId());
    expect(acc1.fields.registry).toBe(ledger.addresses.accreditationRegistry);
    expect((parseStatement(acc1.statement) as AccreditationStatement).registry).toBe(ledger.addresses.accreditationRegistry);
    expect((await checkAccreditation(ledger, governance.pk, I.did, I.controller, I.pk, clock.nowSec())).ok).toBe(true);

    // de-accredited on D1
    await accreditIssuer(governance, ledger, clock, { did: I.did, controller: I.controller }, { status: "revoked" });
    const d1 = await checkAccreditation(ledger, governance.pk, I.did, I.controller, I.pk, clock.nowSec());
    expect(d1).toEqual({ ok: false, reason: "accreditation status is revoked" });

    // D2: same Anvil (same chainId), fresh registries, governance EVM account held by the attacker,
    // same pinned governance ML-DSA key. I registers there itself (its PoP binds D2's DID registry).
    const evilGov = RoleAccount.random("reg2-d2-governance-evm");
    const L2 = await LedgerV4.deploy(anvil.rpcUrl, { governanceAddress: evilGov.address, minAnchorIntervalSec: MIN, maxWindowSec: MAX_WINDOW });
    try {
      await L2.fund(evilGov);
      await registerWithPop(L2, I);
      expect((await checkRecordAndPop(L2, I.did, I.controller)).ok).toBe(true);
      // the attacker transplants I's old D1 "accredited" statement (serial 1 is above D2's 0)
      await L2.publishAccreditation(evilGov, I.did, acc1.statement, acc1.signature);
      expect((await L2.latestAccreditation(I.did))?.statement.equals(acc1.statement)).toBe(true);
      const d2 = await checkAccreditation(L2, governance.pk, I.did, I.controller, I.pk, clock.nowSec(), new Map());
      expect(d2).toEqual({ ok: false, reason: "accreditation names a different accreditation registry" });

      // control: a statement governance signs for D2 itself is accepted there
      const govD2: Governance = { pk: governance.pk, sk: governance.sk, account: evilGov };
      const accD2 = await accreditIssuer(govD2, L2, clock, { did: I.did, controller: I.controller });
      expect(accD2.fields.registry).toBe(L2.addresses.accreditationRegistry);
      expect(accD2.fields.serial).toBe(2);
      expect((await checkAccreditation(L2, governance.pk, I.did, I.controller, I.pk, clock.nowSec(), new Map())).ok).toBe(true);

      // the typed parser: a governance-signed but non-canonical statement is refused by name
      const loose = Buffer.from(JSON.stringify({ ...accD2.fields, serial: 3, type: "pqid:accreditation:v2" }, null, 1));
      await L2.publishAccreditation(evilGov, I.did, loose, mlDsaSign(governance.sk, loose));
      const d2loose = await checkAccreditation(L2, governance.pk, I.did, I.controller, I.pk, clock.nowSec(), new Map());
      expect(d2loose.ok).toBe(false);
      expect(d2loose.reason).toMatch(/^accreditation statement is malformed: .*canonical/);
    } finally {
      L2.destroy();
    }
  });

  it("REG-3: accreditationSerial reverts a signed serial above 2^53 - 1 or a step above 2^20; one bad publication no longer blocks the DID", async () => {
    const junk = Buffer.from("{}");
    const sig = randomBytes(ML_DSA_44_SIG);
    const did3 = "did:pq:" + randomBytes(32).toString("hex");
    const above = await expectCheck(ledger.publishAccreditation(gov, did3, junk, sig, { signedSerial: 2n ** 64n - 1n }), "accreditationSerial");
    expect(above.reason).toContain("above 2^53 - 1");
    expect((await expectCheck(ledger.publishAccreditation(gov, did3, junk, sig, { signedSerial: 2n ** 53n }), "accreditationSerial")).reason).toContain(
      "above 2^53 - 1"
    );
    // 2^53 - 1 is a valid serial, but from 0 it is a step above 2^20
    const step = await expectCheck(ledger.publishAccreditation(gov, did3, junk, sig, { signedSerial: Number.MAX_SAFE_INTEGER }), "accreditationSerial");
    expect(step.reason).toContain("step above 2^20");
    await expectCheck(ledger.publishAccreditation(gov, did3, junk, sig, { signedSerial: 2 ** 20 + 1 }), "accreditationSerial");
    // exact boundaries are accepted: 0 + 2^20, then 2^20 + 2^20
    await ledger.publishAccreditation(gov, did3, junk, sig, { signedSerial: 2 ** 20 });
    await expectCheck(ledger.publishAccreditation(gov, did3, junk, sig, { signedSerial: 2 ** 21 + 1 }), "accreditationSerial");
    await ledger.publishAccreditation(gov, did3, junk, sig, { signedSerial: 2 ** 21 });
    expect((await ledger.latestAccreditation(did3))?.signedSerial).toBe(2 ** 21);
    expect(await ledger.accreditationSignedSerial(did3)).toBe(2n ** 21n);

    // a garbage publication at the largest step, then honest governance still accredits
    const B = await newIdentity("reg3-issuer");
    await registerWithPop(ledger, B);
    await ledger.publishAccreditation(gov, B.did, Buffer.from("x"), Buffer.from("y"), { signedSerial: 2 ** 20 });
    expect((await checkAccreditation(ledger, governance.pk, B.did, B.controller, B.pk, clock.nowSec())).reason).toBe(
      "accreditation statement is not signed by the pinned governance key"
    );
    const accB = await accreditIssuer(governance, ledger, clock, { did: B.did, controller: B.controller });
    expect(accB.fields.serial).toBe(2 ** 20 + 1);
    expect((await checkAccreditation(ledger, governance.pk, B.did, B.controller, B.pk, clock.nowSec())).ok).toBe(true);
  });

  it("REG-3: a stored signed serial above 2^53 - 1 (registry without the caps) gives a named refusal, not an exception", async () => {
    const src = fs.readFileSync(CONTRACTS_V4_FILE, "utf8");
    const uncapped = src
      .replace(/require\(signedSerial <= MAX_SIGNED_SERIAL,[^;]*;/, "")
      .replace(/require\(\s*uint256\(signedSerial\) <= uint256\(l\.signedSerial\) \+ MAX_SERIAL_STEP,[^;]*;/, "");
    expect(src.length - uncapped.length).toBeGreaterThan(100); // both caps removed
    const c = compileSolidityV4({ "RegistriesV4.sol": uncapped })["AccreditationRegistryV4"];
    if (!c) throw new Error("AccreditationRegistryV4 missing from solc output");
    const mgov = await ledger.newRoleAccount("uncapped-governance");
    const deployed = await new ContractFactory(c.abi as never, c.bytecode, ledger.devDeployerSigner()).deploy(mgov.address);
    await deployed.waitForDeployment();
    const L3 = await LedgerV4.connect(
      anvil.rpcUrl,
      { ...ledger.addresses, accreditationRegistry: (await deployed.getAddress()).toLowerCase() },
      ledger.deployment.fromBlock
    );
    try {
      const B = await newIdentity("reg3-uncapped");
      await L3.publishAccreditation(mgov, B.did, Buffer.from("x"), Buffer.from("y"), { signedSerial: 2n ** 64n - 1n });
      const l = await L3.latestAccreditation(B.did);
      expect(l?.signedSerial).toBeNull();
      expect(l?.signedSerialRaw).toBe(2n ** 64n - 1n);
      expect(await checkAccreditation(L3, governance.pk, B.did, B.controller, B.pk, clock.nowSec())).toEqual({
        ok: false,
        reason: "registry signed serial is above 2^53 - 1, which no valid statement can carry",
      });
      await expect(nextAccreditationSerial(L3, B.did)).rejects.toThrow(/leaves no valid serial/);
    } finally {
      L3.destroy();
    }
  });

  it("REG-4: governance derives the next serial from the chain, so de-accreditation works after a restart", async () => {
    const I = await newIdentity("reg4-issuer");
    await registerWithPop(ledger, I);
    expect(await nextAccreditationSerial(ledger, I.did)).toBe(1);
    const a1 = await accreditIssuer(governance, ledger, clock, { did: I.did, controller: I.controller });
    expect(a1.fields.serial).toBe(1);
    const a2 = await accreditIssuer(governance, ledger, clock, { did: I.did, controller: I.controller });
    expect(a2.fields.serial).toBe(2);
    const seen = new Map<string, number>();
    expect((await checkAccreditation(ledger, governance.pk, I.did, I.controller, I.pk, clock.nowSec(), seen)).ok).toBe(true);

    // restart: a new process holds the same governance keys and no in-memory state
    const restarted: Governance = { pk: governance.pk, sk: governance.sk, account: gov };
    expect(await nextAccreditationSerial(ledger, I.did)).toBe(3);
    const revoked = await accreditIssuer(restarted, ledger, clock, { did: I.did, controller: I.controller }, { status: "revoked" });
    expect(revoked.fields.serial).toBe(3);
    expect(await checkAccreditation(ledger, governance.pk, I.did, I.controller, I.pk, clock.nowSec(), seen)).toEqual({
      ok: false,
      reason: "accreditation status is revoked",
    });
  });

  it("REG-5: kemMonotonic stops re-posting an older KEM statement; the stored notBefore is exposed; KEM windows are capped", async () => {
    const V = await newIdentity("reg5-verifier");
    await registerWithPop(ledger, V, "https://reg5.verifier.example");
    const t0 = clock.nowSec();
    const kemStatement = (kemPk: Buffer, notBefore: number) => {
      const statement = verifierKemMessage({
        verifier: V.did,
        controller: V.controller,
        chainId: 31337,
        registry: ledger.addresses.verifierKemRegistry,
        kemAlg: KEM_ALG,
        kemPkSha3: sha3_256(kemPk).toString("hex"),
        notBefore,
        notAfter: notBefore + 365 * 86400,
      });
      return { did: V.did, kemPk, statement, signature: mlDsaSign(V.sk, statement) };
    };
    const K1 = kemStatement(mlKemKeygen().publicKey, t0);
    const K2 = kemStatement(mlKemKeygen().publicKey, t0 + 60);
    await ledger.publishKemKey(V.account, K1);
    expect((await ledger.latestKemKey(V.did, V.controller))?.notBefore).toBe(t0);
    await ledger.publishKemKey(V.account, K2); // rotation
    const rotated = await ledger.latestKemKey(V.did, V.controller);
    expect(rotated?.kemPk.equals(K2.kemPk)).toBe(true);
    expect(rotated?.notBefore).toBe(t0 + 60);

    // rollback by the controller EVM account: re-posting the older genuine K1 statement
    await expectCheck(ledger.publishKemKey(V.account, K1), "kemMonotonic");
    // an equal notBefore is not enough either (strictly increasing)
    await expectCheck(ledger.publishKemKey(V.account, kemStatement(mlKemKeygen().publicKey, t0 + 60)), "kemMonotonic");
    // a declared notBefore above 2^53 - 1 is refused
    await expectCheck(ledger.publishKemKey(V.account, K1, { notBefore: 2n ** 53n }), "kemMonotonic");
    const still = await ledger.latestKemKey(V.did, V.controller);
    expect(still?.kemPk.equals(K2.kemPk)).toBe(true);
    expect(still?.version).toBe(2);

    // The contract never parses the statement: a controller can declare a larger notBefore than
    // the one K1 signs. Readers must compare the stored notBefore with the signed one.
    await ledger.publishKemKey(V.account, K1, { notBefore: t0 + 120 });
    const lied = await ledger.latestKemKey(V.did, V.controller);
    expect(lied?.notBefore).toBe(t0 + 120);
    expect((parseStatement(lied!.statement) as VerifierKemStatement).notBefore).toBe(t0);

    // KEM statement windows are capped at MAX_VERIFIER_KEM_SEC (400 days)
    expect(MAX_VERIFIER_KEM_SEC).toBe(400 * 86400);
    const base = parseStatement(K2.statement) as VerifierKemStatement;
    const { type: _t, ...fields } = base;
    expect(verifierKemMessage({ ...fields, notAfter: fields.notBefore + MAX_VERIFIER_KEM_SEC }).length).toBeGreaterThan(0);
    expect(() => verifierKemMessage({ ...fields, notAfter: fields.notBefore + MAX_VERIFIER_KEM_SEC + 1 })).toThrow(StatementError);

    // kemMonotonic is a named registry check (mutation table and revert mapping)
    expect(REGISTRY_CHECKS).toContain("kemMonotonic");
  });

  it("REG-6: the PoP signs the registered origin; a registration under another origin fails the PoP check", async () => {
    // W's DID key signs a PoP for its real origin; the holder of W's controller EVM key
    // front-runs W's registration with the same PoP and a relay origin
    const W = await newIdentity("reg6-verifier");
    const popNonce = randomBytes(32).toString("hex");
    const popSig = mlDsaSign(
      W.sk,
      didPopMessage({
        did: W.did,
        controller: W.controller,
        chainId: await ledger.chainId(),
        registry: ledger.addresses.didRegistry,
        nonce: popNonce,
        origin: "https://w.verifier.example",
      })
    );
    await ledger.registerDid(W.account, { did: W.did, pk: W.pk, popNonce, popSig, origin: "https://relay.attacker.example" });
    const frontRun = await checkRecordAndPop(ledger, W.did, W.controller);
    expect(frontRun.ok).toBe(false);
    expect(frontRun.reason).toMatch(/^proof of possession does not verify/);
    // governance also refuses to accredit that record
    await expect(accreditIssuer(governance, ledger, clock, { did: W.did, controller: W.controller })).rejects.toThrow(/proof of possession does not verify/);

    // control: the same flow with the signed origin registered verifies and returns that origin
    const X = await newIdentity("reg6-control");
    await registerWithPop(ledger, X, "https://x.verifier.example");
    expect(await checkRecordAndPop(ledger, X.did, X.controller)).toMatchObject({ ok: true, origin: "https://x.verifier.example" });
    // issuers register with the empty origin
    const I = await newIdentity("reg6-issuer");
    await registerWithPop(ledger, I);
    expect(await checkRecordAndPop(ledger, I.did, I.controller)).toMatchObject({ ok: true, origin: "" });

    // an origin the PoP schema cannot carry is refused by name
    const Y = await newIdentity("reg6-bad-origin");
    await ledger.registerDid(Y.account, { did: Y.did, pk: Y.pk, popNonce, popSig: randomBytes(ML_DSA_44_SIG), origin: "https://bad origin.example" });
    expect(await checkRecordAndPop(ledger, Y.did, Y.controller)).toEqual({ ok: false, reason: "registered origin is not a valid proof-of-possession origin" });
    expect(() =>
      didPopMessage({ did: Y.did, controller: Y.controller, chainId: 31337, registry: ledger.addresses.didRegistry, nonce: popNonce, origin: "x".repeat(257) })
    ).toThrow(StatementError);
  });
});

describe("gas (dev chain, informational)", () => {
  it("prints gas per write and deployment", () => {
    const rows: Array<[string, number, number]> = Object.entries(gas).map(([k, r]) => [k, r.gasUsed, r.calldataBytes]);
    for (const [name, g] of Object.entries(ledger.deployment.deployGas)) rows.push([`deploy ${name}`, g, 0]);
    console.log(
      "v4 registry gas (Anvil, solc 0.8.28 optimizer 200; 1312-byte pk, 2420-byte signatures, 1184-byte KEM key):\n" +
        rows.map(([k, g, c]) => `  ${k.padEnd(34)} ${String(g).padStart(9)} gas   calldata ${c} B`).join("\n")
    );
    for (const k of ["registerDid", "publishAccreditation", "publishEpoch_first", "publishEpoch_next", "publishKemKey", "deactivateDid"]) {
      const r = gas[k];
      expect(r, k).toBeDefined();
      expect(r?.gasUsed ?? 0).toBeGreaterThan(21_000);
      expect(r?.gasUsed ?? Infinity).toBeLessThan(30_000_000);
    }
    // an epoch anchor stores hashes only, so it costs far less than registering a 1312-byte key
    expect(gas["publishEpoch_next"]?.gasUsed ?? Infinity).toBeLessThan(gas["registerDid"]?.gasUsed ?? 0);
  });
});
