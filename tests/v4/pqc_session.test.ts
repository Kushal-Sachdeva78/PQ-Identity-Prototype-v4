import { describe, it, expect, beforeAll } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import nodeCrypto, { randomBytes } from "node:crypto";
import { REPO_ROOT } from "@pqid/common/paths";
import { canonicalJsonBytes } from "@pqid/common/hash";
import { didFromPublicKey } from "@pqid/common/did";
import {
  BN254_P,
  EPOCH_WINDOW_SEC,
  MAX_ACCREDITATION_SEC,
  MAX_EPOCH_WINDOW_SEC,
  SESSION_TTL_MS,
  TYPE_ACCREDITATION,
  TYPE_EPOCH,
  TYPE_VERIFIER_KEM,
} from "@pqid/v4/constants";
import { utcDateOf, unixOfUtcDate } from "@pqid/v4/dates";
import {
  ML_DSA_44_SIZES,
  ML_KEM_768_SIZES,
  ML_DSA_44_SPKI_PREFIX,
  ML_KEM_768_SPKI_PREFIX,
  mlDsaKeygen,
  mlDsaSign,
  mlDsaVerify,
  mlDsaVerifyKey,
  mlDsaImportPublicKey,
  mlDsaPublicKeyRawOf,
  mlKemKeygen,
  mlKemEncaps,
  mlKemDecaps,
  mlKemPublicKeyRawOf,
  sha3_256,
  hkdfSha256Extract,
  hkdfSha256Expand,
  aes256gcmSeal,
  aes256gcmOpen,
  implementationLabel,
} from "@pqid/v4/pqc";
import {
  didPopMessage,
  accreditationMessage,
  epochMessage,
  verifierKemMessage,
  validateStatement,
  validateEpoch,
  tryParseStatement,
  parseStatement,
  signStatement,
  verifyStatement,
  attachSignature,
  detachSignature,
  StatementError,
  type EpochStatement,
} from "@pqid/v4/statements";
import {
  newRequest,
  transcriptHash,
  deriveSessionSecrets,
  walletOpenSession,
  walletSealReply,
  walletSeal,
  verifierOpenReply,
  VerifierSessionStore,
  requestShapeErrors,
  type ProofRequestV4,
  type NewRequestParams,
  type SessionReplyV4,
} from "@pqid/v4/session";

// Keys in this file are made in memory for the test run only (dev, never written).

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const flip = (b: Uint8Array, i: number, mask = 0x01): Buffer => {
  const c = Buffer.from(b);
  c[i] = (c[i] ?? 0) ^ mask;
  return c;
};
const randAddr = () => "0x" + randomBytes(20).toString("hex");

// ============================================================================
// Primitives
// ============================================================================

describe("v4 pqc: sizes, encodings, provenance", () => {
  it("ML-DSA-44: 1,312-byte public key, 2,420-byte signature, SPKI header matches OpenSSL", () => {
    const { publicKey, privateKey } = mlDsaKeygen();
    expect(publicKey.length).toBe(ML_DSA_44_SIZES.publicKey);
    expect(publicKey.length).toBe(1312);
    const sig = mlDsaSign(privateKey, Buffer.from("size check"));
    expect(sig.length).toBe(2420);
    const spki = nodeCrypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
    expect(spki.subarray(0, ML_DSA_44_SPKI_PREFIX.length).equals(ML_DSA_44_SPKI_PREFIX)).toBe(true);
    expect(spki.subarray(ML_DSA_44_SPKI_PREFIX.length).equals(publicKey)).toBe(true);
    expect(mlDsaPublicKeyRawOf(privateKey).equals(publicKey)).toBe(true);
    // Node 24's own raw export agrees (untyped in @types/node 22).
    const exportRaw = (k: nodeCrypto.KeyObject) => (k as unknown as { export(o: { format: string }): Buffer }).export({ format: "raw-public" });
    expect(Buffer.from(exportRaw(nodeCrypto.createPublicKey(privateKey))).equals(publicKey)).toBe(true);
  });

  it("ML-DSA-44 raw import via SPKI prefix and via JWK {kty:AKP} give the same key", () => {
    const { publicKey } = mlDsaKeygen();
    const a = mlDsaImportPublicKey(publicKey, "spki").export({ format: "der", type: "spki" });
    const b = mlDsaImportPublicKey(publicKey, "jwk").export({ format: "der", type: "spki" });
    expect(a.equals(b)).toBe(true);
    expect(() => mlDsaImportPublicKey(publicKey.subarray(1))).toThrow();
  });

  it("ML-KEM-768: 1,184-byte public key, 1,088-byte ciphertext, 32-byte shared secret", () => {
    const { publicKey, privateKey } = mlKemKeygen();
    expect(publicKey.length).toBe(ML_KEM_768_SIZES.publicKey);
    expect(publicKey.length).toBe(1184);
    const { ciphertext, sharedSecret } = mlKemEncaps(publicKey);
    expect(ciphertext.length).toBe(1088);
    expect(sharedSecret.length).toBe(32);
    expect(mlKemDecaps(privateKey, ciphertext).equals(sharedSecret)).toBe(true);
    const spki = nodeCrypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
    expect(spki.subarray(0, ML_KEM_768_SPKI_PREFIX.length).equals(ML_KEM_768_SPKI_PREFIX)).toBe(true);
    expect(mlKemPublicKeyRawOf(privateKey).equals(publicKey)).toBe(true);
  });

  it("implementation label names OpenSSL and Node versions", () => {
    expect(implementationLabel()).toBe(`OpenSSL ${process.versions.openssl} via Node ${process.versions.node}`);
    expect(implementationLabel()).toMatch(/^OpenSSL \d+\.\d+\.\d+ via Node \d+\.\d+\.\d+$/);
  });
});

describe("v4 pqc: ML-DSA-44 sign/verify", () => {
  const kp = mlDsaKeygen();
  const other = mlDsaKeygen();
  const msg = Buffer.from("pqid v4 statement bytes");
  const sig = mlDsaSign(kp.privateKey, msg);

  it("verifies a valid signature; signing is hedged (two signatures differ, both verify)", () => {
    expect(mlDsaVerify(kp.publicKey, msg, sig)).toBe(true);
    const sig2 = mlDsaSign(kp.privateKey, msg);
    expect(sig2.equals(sig)).toBe(false);
    expect(mlDsaVerify(kp.publicKey, msg, sig2)).toBe(true);
    expect(mlDsaVerify(kp.publicKey, new Uint8Array(0), mlDsaSign(kp.privateKey, new Uint8Array(0)))).toBe(true);
  });

  it("rejects tampered signatures, messages and wrong keys", () => {
    for (const i of [0, 31, 32, 1000, 2335, 2336, 2419]) expect(mlDsaVerify(kp.publicKey, msg, flip(sig, i))).toBe(false);
    expect(mlDsaVerify(kp.publicKey, flip(msg, 0), sig)).toBe(false);
    expect(mlDsaVerify(kp.publicKey, Buffer.concat([msg, Buffer.of(0)]), sig)).toBe(false);
    expect(mlDsaVerify(other.publicKey, msg, sig)).toBe(false);
    expect(mlDsaVerify(flip(kp.publicKey, 100), msg, sig)).toBe(false);
  });

  it("never throws on malformed input; wrong lengths return false", () => {
    const bad = (x: unknown) => x as Uint8Array;
    expect(mlDsaVerify(kp.publicKey.subarray(1), msg, sig)).toBe(false);
    expect(mlDsaVerify(Buffer.concat([kp.publicKey, Buffer.of(0)]), msg, sig)).toBe(false);
    expect(mlDsaVerify(kp.publicKey, msg, sig.subarray(1))).toBe(false);
    expect(mlDsaVerify(kp.publicKey, msg, Buffer.concat([sig, Buffer.of(0)]))).toBe(false);
    expect(mlDsaVerify(Buffer.alloc(0), msg, sig)).toBe(false);
    expect(mlDsaVerify(Buffer.alloc(1312), msg, sig)).toBe(false);
    expect(mlDsaVerify(Buffer.alloc(1312, 0xff), msg, Buffer.alloc(2420, 0xff))).toBe(false);
    expect(mlDsaVerify(bad(null), msg, sig)).toBe(false);
    expect(mlDsaVerify(bad("00".repeat(1312)), msg, sig)).toBe(false);
    expect(mlDsaVerify(kp.publicKey, bad(undefined), sig)).toBe(false);
    expect(mlDsaVerify(kp.publicKey, msg, bad(hex(sig)))).toBe(false);
  });

  it("mlDsaVerifyKey (pre-imported key) agrees with mlDsaVerify and never throws", () => {
    const key = mlDsaImportPublicKey(kp.publicKey);
    expect(mlDsaVerifyKey(key, msg, sig)).toBe(true);
    expect(mlDsaVerifyKey(key, msg, flip(sig, 9))).toBe(false);
    expect(mlDsaVerifyKey(key, flip(msg, 2), sig)).toBe(false);
    expect(mlDsaVerifyKey(mlDsaImportPublicKey(other.publicKey), msg, sig)).toBe(false);
    expect(mlDsaVerifyKey(key, msg, sig.subarray(1))).toBe(false);
    expect(mlDsaVerifyKey(kp.privateKey, msg, sig)).toBe(false);
    expect(mlDsaVerifyKey(null as unknown as nodeCrypto.KeyObject, msg, sig)).toBe(false);
  });

  it("derived raw public keys are returned as copies", () => {
    const a = mlDsaPublicKeyRawOf(kp.privateKey);
    a.fill(0);
    expect(mlDsaPublicKeyRawOf(kp.privateKey).equals(kp.publicKey)).toBe(true);
    const kem = mlKemKeygen();
    const b = mlKemPublicKeyRawOf(kem.privateKey);
    b.fill(0);
    expect(mlKemPublicKeyRawOf(kem.privateKey).equals(kem.publicKey)).toBe(true);
  });

  it("sign refuses a key of the wrong algorithm", () => {
    expect(() => mlDsaSign(mlKemKeygen().privateKey, msg)).toThrow();
    expect(() => mlDsaSign(nodeCrypto.createPublicKey(kp.privateKey), msg)).toThrow();
  });
});

describe("v4 pqc: ML-KEM-768", () => {
  const kp = mlKemKeygen();

  it("tampered ciphertext decapsulates to an unrelated secret (implicit rejection, no throw)", () => {
    const { ciphertext, sharedSecret } = mlKemEncaps(kp.publicKey);
    const ss2 = mlKemDecaps(kp.privateKey, flip(ciphertext, 500));
    expect(ss2.length).toBe(32);
    expect(ss2.equals(sharedSecret)).toBe(false);
    const other = mlKemKeygen();
    expect(mlKemDecaps(other.privateKey, ciphertext).equals(sharedSecret)).toBe(false);
  });

  it("two encapsulations to one key give different ciphertexts and secrets", () => {
    const a = mlKemEncaps(kp.publicKey);
    const b = mlKemEncaps(kp.publicKey);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
    expect(a.sharedSecret.equals(b.sharedSecret)).toBe(false);
  });

  it("rejects wrong lengths and a public key with a coefficient >= q (FIPS 203 input check)", () => {
    expect(() => mlKemEncaps(kp.publicKey.subarray(1))).toThrow();
    expect(() => mlKemDecaps(kp.privateKey, Buffer.alloc(1087))).toThrow();
    const bad = Buffer.from(kp.publicKey);
    bad[0] = 0xff;
    bad[1] = 0xff; // first 12-bit coefficient = 0xFFF = 4095 >= q = 3329
    expect(() => mlKemEncaps(bad)).toThrow();
    expect(() => mlKemDecaps(mlDsaKeygen().privateKey, Buffer.alloc(1088))).toThrow();
  });
});

describe("v4 pqc: SHA3-256, HKDF-SHA-256, AES-256-GCM", () => {
  it("SHA3-256 known answers (FIPS 202)", () => {
    expect(hex(sha3_256())).toBe("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    expect(hex(sha3_256(Buffer.from("abc")))).toBe("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    expect(sha3_256(Buffer.from("a"), Buffer.from("bc")).equals(sha3_256(Buffer.from("abc")))).toBe(true);
  });

  it("HKDF matches RFC 5869 test case 1", () => {
    const ikm = Buffer.alloc(22, 0x0b);
    const salt = Buffer.from("000102030405060708090a0b0c", "hex");
    const info = Buffer.from("f0f1f2f3f4f5f6f7f8f9", "hex");
    const prk = hkdfSha256Extract(salt, ikm);
    expect(hex(prk)).toBe("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    const okm = hkdfSha256Expand(prk, info, 42);
    expect(hex(okm)).toBe("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    expect(Buffer.from(nodeCrypto.hkdfSync("sha256", ikm, salt, info, 42)).equals(okm)).toBe(true);
  });

  it("HKDF matches RFC 5869 test case 3 (empty salt and info) and Node's hkdfSync at many lengths", () => {
    const ikm = Buffer.alloc(22, 0x0b);
    const prk = hkdfSha256Extract(Buffer.alloc(0), ikm);
    expect(hex(prk)).toBe("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
    expect(hex(hkdfSha256Expand(prk, Buffer.alloc(0), 42))).toBe(
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
    const salt = randomBytes(32);
    const ikm2 = randomBytes(32);
    const prk2 = hkdfSha256Extract(salt, ikm2);
    for (const len of [1, 12, 31, 32, 33, 64, 65, 255 * 32]) {
      const ours = hkdfSha256Expand(prk2, "pqid:v4:test", len);
      const node = Buffer.from(nodeCrypto.hkdfSync("sha256", ikm2, salt, Buffer.from("pqid:v4:test"), len));
      expect(ours.equals(node)).toBe(true);
    }
    expect(() => hkdfSha256Expand(prk2, "x", 0)).toThrow();
    expect(() => hkdfSha256Expand(prk2, "x", 255 * 32 + 1)).toThrow();
    expect(() => hkdfSha256Expand(prk2.subarray(1), "x", 32)).toThrow();
  });

  it("AES-256-GCM known answers (GCM spec test cases 13 and 14)", () => {
    const k = Buffer.alloc(32);
    const iv = Buffer.alloc(12);
    const t13 = aes256gcmSeal(k, iv, Buffer.alloc(0), Buffer.alloc(0));
    expect(t13.ciphertext.length).toBe(0);
    expect(hex(t13.tag)).toBe("530f8afbc74536b9a963b4f1c4cb738b");
    const t14 = aes256gcmSeal(k, iv, Buffer.alloc(0), Buffer.alloc(16));
    expect(hex(t14.ciphertext)).toBe("cea7403d4d606b6e074ec5d3baf39d18");
    expect(hex(t14.tag)).toBe("d0d1c8a799996bf0265b98b5d48ab919");
  });

  it("AES-256-GCM round trip; any change to key, IV, AAD, ciphertext or tag fails; short tags fail", () => {
    const key = randomBytes(32);
    const iv = randomBytes(12);
    const aad = randomBytes(32);
    const pt = Buffer.from('{"hello":"world"}');
    const { ciphertext, tag } = aes256gcmSeal(key, iv, aad, pt);
    expect(tag.length).toBe(16);
    expect(aes256gcmOpen(key, iv, aad, ciphertext, tag)?.equals(pt)).toBe(true);
    expect(aes256gcmOpen(flip(key, 0), iv, aad, ciphertext, tag)).toBeNull();
    expect(aes256gcmOpen(key, flip(iv, 11), aad, ciphertext, tag)).toBeNull();
    expect(aes256gcmOpen(key, iv, flip(aad, 5), ciphertext, tag)).toBeNull();
    expect(aes256gcmOpen(key, iv, Buffer.alloc(0), ciphertext, tag)).toBeNull();
    expect(aes256gcmOpen(key, iv, aad, flip(ciphertext, 3), tag)).toBeNull();
    expect(aes256gcmOpen(key, iv, aad, ciphertext, flip(tag, 15))).toBeNull();
    expect(aes256gcmOpen(key, iv, aad, ciphertext, tag.subarray(0, 12))).toBeNull();
    expect(aes256gcmOpen(key, iv, aad, ciphertext.subarray(1), tag)).toBeNull();
    expect(aes256gcmOpen(key.subarray(1), iv, aad, ciphertext, tag)).toBeNull();
    expect(() => aes256gcmSeal(key, randomBytes(16), aad, pt)).toThrow();
  });
});

// ============================================================================
// Statements
// ============================================================================

describe("v4 statements (V4_DESIGN section 3)", () => {
  const issuer = mlDsaKeygen();
  const gov = mlDsaKeygen();
  const issuerDid = didFromPublicKey(issuer.publicKey);
  const controller = randAddr();
  const registry = randAddr();
  const notBefore = 1_790_000_000;
  const popFields = { did: issuerDid, controller, chainId: 31337, registry, nonce: randomBytes(32).toString("hex"), origin: "https://v.example" };
  const accFields = {
    issuerDid,
    controller,
    pkSha3: sha3_256(issuer.publicKey).toString("hex"),
    chainId: 31337,
    registry,
    serial: 1,
    status: "accredited" as const,
    notBefore,
    notAfter: notBefore + MAX_ACCREDITATION_SEC,
  };
  const epochFields = {
    issuer: issuerDid,
    controller,
    chainId: 31337,
    registry,
    epoch: 1,
    root: (BN254_P - 1n).toString(),
    revRoot: "0",
    notBefore,
    notAfter: notBefore + EPOCH_WINDOW_SEC,
  };
  const kemFields = {
    verifier: issuerDid,
    controller,
    chainId: 31337,
    registry,
    kemAlg: "ML-KEM-768" as const,
    kemPkSha3: sha3_256(mlKemKeygen().publicKey).toString("hex"),
    notBefore,
    notAfter: notBefore + 30 * 86400,
  };
  const epochFull = (): Record<string, unknown> => ({
    type: TYPE_EPOCH,
    ...epochFields,
    fromDate: utcDateOf(epochFields.notBefore),
    toDate: utcDateOf(epochFields.notAfter),
  });

  it("builders emit canonical JSON with the fixed type strings; bytes parse back", () => {
    const all = [didPopMessage(popFields), accreditationMessage(accFields), epochMessage(epochFields), verifierKemMessage(kemFields)];
    const types = all.map((b) => parseStatement(b).type);
    expect(types).toEqual(["pqid:did-pop:v2", "pqid:accreditation:v2", "pqid:issuer-epoch:v4", "pqid:verifier-kem:v1"]);
    expect(new Set(types).size).toBe(4);
    for (const b of all) expect(canonicalJsonBytes(JSON.parse(b.toString("utf8"))).equals(b)).toBe(true);
    // keys sorted, no whitespace
    expect(didPopMessage(popFields).toString("utf8")).toBe(
      `{"chainId":31337,"controller":"${controller}","did":"${issuerDid}","nonce":"${popFields.nonce}","origin":"https://v.example","registry":"${registry}","type":"pqid:did-pop:v2"}`
    );
  });

  it("epochMessage fills fromDate/toDate from the UTC dates of the window (midnight edge)", () => {
    const d = 20270315;
    const nb = unixOfUtcDate(d) + 86400 - 1; // 23:59:59 UTC
    const st = parseStatement(epochMessage({ ...epochFields, notBefore: nb, notAfter: nb + EPOCH_WINDOW_SEC })) as EpochStatement;
    expect(st.fromDate).toBe(20270315);
    expect(st.toDate).toBe(20270316);
    // explicit, matching dates are accepted and give the same bytes
    expect(epochMessage({ ...epochFields, notBefore: nb, notAfter: nb + EPOCH_WINDOW_SEC, fromDate: 20270315, toDate: 20270316 }).equals(
      epochMessage({ ...epochFields, notBefore: nb, notAfter: nb + EPOCH_WINDOW_SEC })
    )).toBe(true);
    // mismatching dates are rejected
    expect(() => epochMessage({ ...epochFields, notBefore: nb, notAfter: nb + EPOCH_WINDOW_SEC, fromDate: 20270316, toDate: 20270316 })).toThrow(StatementError);
    expect(() => epochMessage({ ...epochFields, notBefore: nb, notAfter: nb + EPOCH_WINDOW_SEC, fromDate: 20270315, toDate: 20270317 })).toThrow(StatementError);
  });

  it("rejects extra and missing fields", () => {
    expect(validateEpoch(epochFull()).ok).toBe(true);
    expect(validateEpoch({ ...epochFull(), extra: 1 }).ok).toBe(false);
    for (const k of Object.keys(epochFull())) {
      const v = epochFull();
      delete v[k];
      expect(validateStatement(v).ok, `missing ${k}`).toBe(false);
    }
    expect(() => didPopMessage({ ...popFields, extra: "x" } as typeof popFields)).toThrow(StatementError);
    const noNonce: Record<string, unknown> = { ...popFields };
    delete noNonce["nonce"];
    expect(() => didPopMessage(noNonce as unknown as typeof popFields)).toThrow(StatementError);
    expect(() => didPopMessage({ ...popFields, type: "pqid:accreditation:v2" } as unknown as typeof popFields)).toThrow(StatementError);
  });

  it("rejects wrong types and wrong encodings", () => {
    const bad: Array<[string, unknown]> = [
      ["chainId", "31337"],
      ["chainId", 0],
      ["chainId", 1.5],
      ["epoch", "1"],
      ["epoch", -1],
      ["epoch", 2 ** 53],
      ["notBefore", null],
      ["controller", controller.toUpperCase().replace("0X", "0x")],
      ["controller", controller.slice(2)],
      ["controller", controller + "00"],
      ["registry", 12345],
      ["issuer", "did:web:example.com"],
      ["issuer", "did:pq:0OIl"],
      ["root", "01"],
      ["root", "+1"],
      ["root", "-1"],
      ["root", "1.0"],
      ["root", " 1"],
      ["root", "1e3"],
      ["root", BN254_P.toString()],
      ["root", 5],
      ["revRoot", ""],
      ["fromDate", "20270315"],
      ["type", "pqid:issuer-epoch:v3"],
    ];
    for (const [k, v] of bad) {
      expect(validateStatement({ ...epochFull(), [k]: v }).ok, `${k}=${JSON.stringify(v)}`).toBe(false);
    }
    expect(() => didPopMessage({ ...popFields, nonce: popFields.nonce.toUpperCase() })).toThrow(StatementError);
    expect(() => didPopMessage({ ...popFields, nonce: popFields.nonce.slice(2) })).toThrow(StatementError);
    expect(() => accreditationMessage({ ...accFields, status: "suspended" as "revoked" })).toThrow(StatementError);
    expect(() => accreditationMessage({ ...accFields, pkSha3: "0x" + accFields.pkSha3.slice(2) })).toThrow(StatementError);
    expect(() => verifierKemMessage({ ...kemFields, kemAlg: "ML-KEM-512" as "ML-KEM-768" })).toThrow(StatementError);
    expect(accreditationMessage({ ...accFields, status: "revoked" }).length).toBeGreaterThan(0);
  });

  it("enforces window order and length bounds", () => {
    expect(() => epochMessage({ ...epochFields, notAfter: epochFields.notBefore })).toThrow(StatementError);
    expect(() => epochMessage({ ...epochFields, notAfter: epochFields.notBefore + MAX_EPOCH_WINDOW_SEC + 1 })).toThrow(StatementError);
    expect(epochMessage({ ...epochFields, notAfter: epochFields.notBefore + 60 }).length).toBeGreaterThan(0);
    expect(() => accreditationMessage({ ...accFields, notAfter: notBefore + MAX_ACCREDITATION_SEC + 1 })).toThrow(StatementError);
    expect(() => accreditationMessage({ ...accFields, notAfter: notBefore - 1 })).toThrow(StatementError);
    expect(() => verifierKemMessage({ ...kemFields, notAfter: notBefore })).toThrow(StatementError);
  });

  it("parsing rejects non-canonical bytes (whitespace, key order, duplicate keys, -0, bad UTF-8)", () => {
    const good = epochMessage(epochFields);
    expect(tryParseStatement(good).ok).toBe(true);
    const obj = JSON.parse(good.toString("utf8")) as Record<string, unknown>;
    expect(tryParseStatement(Buffer.from(JSON.stringify(obj, null, 1))).ok).toBe(false);
    const reversed = Object.fromEntries(Object.entries(obj).reverse());
    expect(tryParseStatement(Buffer.from(JSON.stringify(reversed))).ok).toBe(false);
    const dup = good.toString("utf8").replace('"chainId":31337', '"chainId":1,"chainId":31337');
    expect(tryParseStatement(Buffer.from(dup)).ok).toBe(false);
    const negZero = good.toString("utf8").replace('"epoch":1', '"epoch":-0');
    expect(tryParseStatement(Buffer.from(negZero)).ok).toBe(false);
    expect(tryParseStatement(Buffer.concat([good.subarray(0, 10), Buffer.of(0xff), good.subarray(11)])).ok).toBe(false);
    expect(tryParseStatement(good, TYPE_ACCREDITATION).ok).toBe(false);
  });

  it("signStatement / verifyStatement: valid, tampered, wrong key, cross-type", () => {
    const msg = epochMessage(epochFields);
    const sig = signStatement(issuer.privateKey, msg);
    expect(verifyStatement(issuer.publicKey, msg, sig)).toBe(true);
    expect(verifyStatement(issuer.publicKey, msg, sig, TYPE_EPOCH)).toBe(true);
    expect(verifyStatement(issuer.publicKey, msg, sig, TYPE_ACCREDITATION)).toBe(false);
    expect(verifyStatement(gov.publicKey, msg, sig)).toBe(false);
    expect(verifyStatement(issuer.publicKey, flip(msg, 40), sig)).toBe(false);
    expect(verifyStatement(issuer.publicKey, msg, flip(sig, 7))).toBe(false);
    const other = epochMessage({ ...epochFields, epoch: 2 });
    expect(verifyStatement(issuer.publicKey, other, sig)).toBe(false);
    // the signing helper refuses bytes that are not a valid canonical statement
    expect(() => signStatement(issuer.privateKey, Buffer.from("not a statement"))).toThrow(StatementError);
    expect(() => signStatement(issuer.privateKey, Buffer.from(JSON.stringify(JSON.parse(msg.toString()), null, 2)))).toThrow(StatementError);
    const acc = accreditationMessage(accFields);
    const accSig = signStatement(gov.privateKey, acc);
    expect(verifyStatement(gov.publicKey, acc, accSig, TYPE_ACCREDITATION)).toBe(true);
    expect(verifyStatement(gov.publicKey, acc, accSig, TYPE_VERIFIER_KEM)).toBe(false);
  });

  it("attachSignature / detachSignature round trip (the presentation's epochStatement form)", () => {
    const st = parseStatement(epochMessage(epochFields)) as EpochStatement;
    const sig = signStatement(issuer.privateKey, epochMessage(epochFields));
    const signed = attachSignature(st, sig);
    expect(signed.signature).toBe(hex(sig));
    const d = detachSignature(JSON.parse(JSON.stringify(signed)), TYPE_EPOCH);
    expect(d.ok).toBe(true);
    if (d.ok) {
      expect(d.value.bytes.equals(epochMessage(epochFields))).toBe(true);
      expect(d.value.signature.equals(sig)).toBe(true);
      expect(verifyStatement(issuer.publicKey, d.value.bytes, d.value.signature, TYPE_EPOCH)).toBe(true);
    }
    expect(detachSignature({ ...signed, signature: signed.signature.toUpperCase() }).ok).toBe(false);
    expect(detachSignature({ ...signed, signature: signed.signature.slice(2) }).ok).toBe(false);
    expect(detachSignature({ ...signed, extra: true }).ok).toBe(false);
    expect(detachSignature(signed, TYPE_ACCREDITATION).ok).toBe(false);
  });
});

// ============================================================================
// Session
// ============================================================================

describe("v4 session (V4_DESIGN section 5)", () => {
  const verifierId = mlDsaKeygen();
  const kem = mlKemKeygen();
  const params: NewRequestParams = {
    verifierDid: didFromPublicKey(verifierId.publicKey),
    verifierController: randAddr(),
    chainId: 31337,
    policy: { predicate: "age_gte", threshold: 18, typeId: "pqid:type:age-credential:v1", today: 20270315 },
  };
  const presentationFor = (nonce: bigint) => ({
    proof: { pi_a: ["1", "2", "1"], protocol: "groth16", curve: "bn128" },
    publicSignals: ["1", "2", "3", nonce.toString(), "5", "6", "20270315", "20270316"],
    issuerDid: "did:pq:abc",
    issuerController: randAddr(),
    epochStatement: { epoch: 1, signature: "00" },
  });

  let store: VerifierSessionStore;
  beforeAll(() => {
    store = new VerifierSessionStore();
  });

  it("newRequest: well-formed, random 32-byte sessionId, rejects bad parameters", () => {
    const a = newRequest(params);
    const b = newRequest(params);
    expect(a.type).toBe("pqid:request:v4");
    expect(a.sessionId).toMatch(/^[0-9a-f]{64}$/);
    expect(a.sessionId).not.toBe(b.sessionId);
    expect(requestShapeErrors(a)).toEqual([]);
    expect(() => newRequest({ ...params, verifierController: params.verifierController.toUpperCase() })).toThrow();
    expect(() => newRequest({ ...params, chainId: 0 })).toThrow();
    expect(() => newRequest({ ...params, policy: { ...params.policy, today: 20270230 } })).toThrow();
    expect(() => newRequest({ ...params, policy: { ...params.policy, predicate: "age_eq" as "age_gte" } })).toThrow();
    expect(() => newRequest({ ...params, policy: { ...params.policy, threshold: 256 } })).toThrow();
    expect(requestShapeErrors({ ...a, extra: 1 }).length).toBeGreaterThan(0);
    expect(requestShapeErrors({ ...a, policy: { ...a.policy, extra: 1 } }).length).toBeGreaterThan(0);
  });

  it("round trip: wallet and verifier derive the same 248-bit nonce; presentation parses to plain data", () => {
    const request = store.open(params);
    const session = walletOpenSession(request, kem.publicKey);
    expect(session.ciphertext.length).toBe(1088);
    expect(session.transcript.length).toBe(32);
    expect(session.key.length).toBe(32);
    expect(session.iv.length).toBe(12);
    expect(session.nonce < 1n << 248n).toBe(true);
    expect(session.nonce < BN254_P).toBe(true);
    const pres = presentationFor(session.nonce);
    const reply = walletSealReply(session, pres);
    expect(reply.type).toBe("pqid:reply:v4");
    expect(reply.sessionId).toBe(request.sessionId);
    expect(reply.ct).toBe(hex(session.ciphertext));

    const opened = verifierOpenReply(store, kem.privateKey, kem.publicKey, JSON.parse(JSON.stringify(reply)));
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    expect(opened.nonce).toBe(session.nonce);
    expect(opened.transcript.equals(session.transcript)).toBe(true);
    expect(opened.request).toEqual(request);
    expect(opened.presentation).toEqual(pres);
    expect(Object.getPrototypeOf(opened.presentation)).toBe(Object.prototype);
    // consumed once only; afterwards the session is unknown
    expect(store.consume(request.sessionId)).toBe(true);
    expect(store.consume(request.sessionId)).toBe(false);
    const again = verifierOpenReply(store, kem.privateKey, kem.publicKey, reply);
    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.error).toBe("unknownSession");
  });

  it("walletSeal runs open, build(nonce), seal; a session seals only once", async () => {
    const request = store.open(params);
    const { reply, nonce } = await walletSeal(request, kem.publicKey, async (n) => presentationFor(n));
    const opened = verifierOpenReply(store, kem.privateKey, kem.publicKey, JSON.stringify(reply));
    expect(opened.ok).toBe(true);
    if (opened.ok) {
      expect(opened.nonce).toBe(nonce);
      expect((opened.presentation["publicSignals"] as string[])[3]).toBe(nonce.toString());
    }
    const s = walletOpenSession(store.open(params), kem.publicKey);
    walletSealReply(s, presentationFor(s.nonce));
    expect(() => walletSealReply(s, presentationFor(s.nonce))).toThrow(/already sealed/);
  });

  it("transcript binding: changing any request field, the KEM key or the ciphertext changes nonce, key and iv", () => {
    const request = newRequest({ ...params, issuedAt: 1_790_000_000 });
    const { ciphertext } = mlKemEncaps(kem.publicKey);
    const ss = randomBytes(32);
    const base = deriveSessionSecrets(ss, transcriptHash(request, kem.publicKey, ciphertext));
    const variants: Array<[string, ProofRequestV4]> = [
      ["sessionId", { ...request, sessionId: randomBytes(32).toString("hex") }],
      ["verifierDid", { ...request, verifierDid: didFromPublicKey(mlDsaKeygen().publicKey) }],
      ["verifierController", { ...request, verifierController: randAddr() }],
      ["chainId", { ...request, chainId: 1 }],
      ["policy.predicate", { ...request, policy: { ...request.policy, predicate: "age_lt" } }],
      ["policy.threshold", { ...request, policy: { ...request.policy, threshold: 21 } }],
      ["policy.typeId", { ...request, policy: { ...request.policy, typeId: "pqid:type:other:v1" } }],
      ["policy.today", { ...request, policy: { ...request.policy, today: 20270316 } }],
      ["issuedAt", { ...request, issuedAt: request.issuedAt + 1 }],
    ];
    const seenNonces = new Set<bigint>([base.nonce]);
    for (const [what, r] of variants) {
      const s = deriveSessionSecrets(ss, transcriptHash(r, kem.publicKey, ciphertext));
      expect(s.nonce, what).not.toBe(base.nonce);
      expect(s.key.equals(base.key), what).toBe(false);
      expect(s.iv.equals(base.iv), what).toBe(false);
      seenNonces.add(s.nonce);
    }
    const otherKem = deriveSessionSecrets(ss, transcriptHash(request, mlKemKeygen().publicKey, ciphertext));
    expect(otherKem.nonce).not.toBe(base.nonce);
    expect(otherKem.key.equals(base.key)).toBe(false);
    const otherCt = deriveSessionSecrets(ss, transcriptHash(request, kem.publicKey, flip(ciphertext, 0)));
    expect(otherCt.nonce).not.toBe(base.nonce);
    expect(otherCt.key.equals(base.key)).toBe(false);
    const otherSs = deriveSessionSecrets(flip(ss, 0), transcriptHash(request, kem.publicKey, ciphertext));
    expect(otherSs.nonce).not.toBe(base.nonce);
    expect(otherSs.key.equals(base.key)).toBe(false);
    expect(seenNonces.size).toBe(variants.length + 1);
    // deterministic given the same inputs
    const again = deriveSessionSecrets(ss, transcriptHash(structuredClone(request), kem.publicKey, ciphertext));
    expect(again.nonce).toBe(base.nonce);
    expect(again.key.equals(base.key)).toBe(true);
  });

  it("a reply replayed into another open session of the same verifier fails to decrypt", () => {
    const a = store.open(params);
    const b = store.open(params);
    const s = walletOpenSession(a, kem.publicKey);
    const reply = walletSealReply(s, presentationFor(s.nonce));
    const replayed: SessionReplyV4 = { ...reply, sessionId: b.sessionId };
    const r = verifierOpenReply(store, kem.privateKey, kem.publicKey, replayed);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("decryptFailed");
    // the original still opens (and neither session was consumed by the failure)
    expect(verifierOpenReply(store, kem.privateKey, kem.publicKey, reply).ok).toBe(true);
    expect(store.status(b.sessionId)).toBe("open");
  });

  it("a reply encapsulated to a key other than the verifier's registered one fails to decrypt", () => {
    const request = store.open(params);
    const attackerKem = mlKemKeygen();
    const s = walletOpenSession(request, attackerKem.publicKey);
    const reply = walletSealReply(s, presentationFor(s.nonce));
    const r = verifierOpenReply(store, kem.privateKey, kem.publicKey, reply);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("decryptFailed");
  });

  it("tampered ct or box fails to decrypt; bad shapes are malformed", () => {
    const request = store.open(params);
    const s = walletOpenSession(request, kem.publicKey);
    const reply = walletSealReply(s, presentationFor(s.nonce));
    const flipHex = (h: string, i: number) => h.slice(0, i) + (h[i] === "0" ? "1" : "0") + h.slice(i + 1);
    const cases: Array<[string, unknown, string]> = [
      ["box byte", { ...reply, box: flipHex(reply.box, 10) }, "decryptFailed"],
      ["box tag", { ...reply, box: flipHex(reply.box, reply.box.length - 1) }, "decryptFailed"],
      ["ct byte", { ...reply, ct: flipHex(reply.ct, 100) }, "decryptFailed"],
      ["short box", { ...reply, box: "00".repeat(10) }, "malformed"],
      ["odd hex", { ...reply, box: reply.box + "0" }, "malformed"],
      ["upper hex", { ...reply, box: reply.box.toUpperCase() }, "malformed"],
      ["short ct", { ...reply, ct: reply.ct.slice(2) }, "malformed"],
      ["wrong type", { ...reply, type: "pqid:reply:v3" }, "malformed"],
      ["extra field", { ...reply, nonce: "1" }, "malformed"],
      ["missing box", { type: reply.type, sessionId: reply.sessionId, ct: reply.ct }, "malformed"],
      ["not json", "{not json", "malformed"],
      ["array", [reply], "malformed"],
      ["unknown session", { ...reply, sessionId: randomBytes(32).toString("hex") }, "unknownSession"],
    ];
    for (const [what, rep, err] of cases) {
      const r = verifierOpenReply(store, kem.privateKey, kem.publicKey, rep);
      expect(r.ok, what).toBe(false);
      if (!r.ok) expect(r.error, what).toBe(err);
    }
    expect(verifierOpenReply(store, kem.privateKey, kem.publicKey, reply).ok).toBe(true);
  });

  it("decrypted plaintext that is not a canonical JSON object is malformed", () => {
    for (const pt of ['{"b":1,"a":2}', "[1,2]", "not json", '{"a":1} ']) {
      const request = store.open(params);
      const s = walletOpenSession(request, kem.publicKey);
      const { ciphertext, tag } = aes256gcmSeal(s.key, s.iv, s.transcript, Buffer.from(pt));
      const reply: SessionReplyV4 = { type: "pqid:reply:v4", sessionId: request.sessionId, ct: hex(s.ciphertext), box: hex(Buffer.concat([ciphertext, tag])) };
      const r = verifierOpenReply(store, kem.privateKey, kem.publicKey, reply);
      expect(r.ok, pt).toBe(false);
      if (!r.ok) expect(r.error, pt).toBe("malformed");
    }
  });

  it("the wallet refuses to seal non-JSON data", () => {
    const mk = () => walletOpenSession(store.open(params), kem.publicKey);
    expect(() => walletSealReply(mk(), { n: 1n })).toThrow();
    expect(() => walletSealReply(mk(), { n: undefined })).toThrow();
    expect(() => walletSealReply(mk(), { n: Number.NaN })).toThrow();
    expect(() => walletSealReply(mk(), [1, 2])).toThrow();
    expect(() => walletSealReply(mk(), { d: new Date() })).toThrow();
  });

  it("expiry: TTL applies to open, get and consume; expired sessions report expiredSession, then are pruned", () => {
    let now = 1_000_000;
    const clockStore = new VerifierSessionStore({ nowMs: () => now });
    expect(clockStore.ttlMs).toBe(SESSION_TTL_MS);
    const request = clockStore.open(params);
    expect(request.issuedAt).toBe(Math.floor(now / 1000));
    const s = walletOpenSession(request, kem.publicKey);
    const reply = walletSealReply(s, presentationFor(s.nonce));
    now += SESSION_TTL_MS - 1;
    expect(clockStore.status(request.sessionId)).toBe("open");
    now += 1;
    expect(clockStore.status(request.sessionId)).toBe("expired");
    expect(clockStore.get(request.sessionId)).toBeUndefined();
    const r = verifierOpenReply(clockStore, kem.privateKey, kem.publicKey, reply);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("expiredSession");
    expect(clockStore.consume(request.sessionId)).toBe(false);
    now += SESSION_TTL_MS;
    clockStore.open(params); // prunes
    expect(clockStore.status(request.sessionId)).toBe("unknown");
    const small = new VerifierSessionStore({ maxSessions: 2 });
    small.open(params);
    small.open(params);
    expect(() => small.open(params)).toThrow(/too many/);
  });

  it("day-end cap (review round 2, GAP-V1): a session ends at the end of its issue day plus the wallet skew when the TTL is longer; with the default TTL the TTL is the tighter bound", () => {
    const skewMs = 300_000; // WALLET_CLOCK_SKEW_SEC
    const dayStartMs = 20_000 * 86_400_000;
    let now = dayStartMs + 86_400_000 - 60_000; // 23:59:00 UTC
    const longStore = new VerifierSessionStore({ nowMs: () => now, ttlMs: 3_600_000 });
    const r = longStore.open(params);
    now = dayStartMs + 86_400_000 + skewMs - 1;
    expect(longStore.status(r.sessionId)).toBe("open");
    now += 1;
    expect(longStore.status(r.sessionId)).toBe("expired");
    now = dayStartMs + 86_400_000 - 60_000;
    const defStore = new VerifierSessionStore({ nowMs: () => now });
    const r2 = defStore.open(params);
    now += SESSION_TTL_MS - 1;
    expect(defStore.status(r2.sessionId)).toBe("open");
    now += 1;
    expect(defStore.status(r2.sessionId)).toBe("expired");
  });

  it("stored requests are immutable; verifier refuses a mismatched KEM key pair", () => {
    const request = store.open(params);
    expect(() => {
      (request.policy as { threshold: number }).threshold = 13;
    }).toThrow();
    expect(store.get(request.sessionId)?.policy.threshold).toBe(18);
    const s = walletOpenSession(request, kem.publicKey);
    const reply = walletSealReply(s, presentationFor(s.nonce));
    expect(() => verifierOpenReply(store, kem.privateKey, mlKemKeygen().publicKey, reply)).toThrow(/not the public key/);
  });
});

// ============================================================================
// Interop with dilithium-py 1.4.0 (the v3 local backend)
// ============================================================================

const VENV_PY = path.join(REPO_ROOT, ".venv", process.platform === "win32" ? "Scripts/python.exe" : "bin/python");
const HAVE_VENV = fs.existsSync(VENV_PY);
if (!HAVE_VENV) {
  console.warn(`[pqc_session.test] SKIP interop: ${VENV_PY} not found (create the venv with dilithium-py 1.4.0 to run it)`);
}

interface PyOut {
  impl: string;
  results: Array<{ valid?: boolean; error?: string | null; pk?: string; sigs?: string[] }>;
}

function runPy(ops: unknown[]): PyOut {
  const res = spawnSync(VENV_PY, [path.join(REPO_ROOT, "tests", "v4", "interop_mldsa.py")], {
    input: JSON.stringify({ ops }),
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (res.status !== 0) throw new Error(`interop_mldsa.py failed (${res.status}): ${res.stderr}`);
  return JSON.parse(res.stdout) as PyOut;
}

/**
 * A non-canonical ML-DSA-44 signature: the hint encoding (last omega + k = 84 bytes)
 * repeats one index. FIPS 204 Alg. 21 requires strictly increasing indices, so it is
 * invalid; the decoded hint vector is unchanged. Returns null if the signature has no hint.
 */
function duplicateHintIndex(sig: Buffer): Buffer | null {
  const OMEGA = 80;
  const K = 4;
  const y = sig.subarray(sig.length - (OMEGA + K));
  const ends = [...y.subarray(OMEGA, OMEGA + K)];
  const total = ends[K - 1] ?? 0;
  if (total === 0 || total >= OMEGA) return null;
  const i = ends.findIndex((e, j) => e - (j === 0 ? 0 : (ends[j - 1] ?? 0)) >= 1);
  const endI = ends[i] ?? 0;
  const idx = [...y.subarray(0, total)];
  const dupIdx = [...idx.slice(0, endI), idx[endI - 1] ?? 0, ...idx.slice(endI)];
  const h = Buffer.alloc(OMEGA + K);
  Buffer.from(dupIdx).copy(h, 0);
  for (let j = 0; j < K; j++) h[OMEGA + j] = (ends[j] ?? 0) + (j >= i ? 1 : 0);
  return Buffer.concat([sig.subarray(0, sig.length - (OMEGA + K)), h]);
}

describe.skipIf(!HAVE_VENV)("v4 pqc: ML-DSA-44 interop, OpenSSL (Node) vs dilithium-py 1.4.0", () => {
  const node = mlDsaKeygen();
  const msgs = [
    Buffer.alloc(0),
    randomBytes(32),
    randomBytes(1000),
    didPopMessage({
      did: didFromPublicKey(node.publicKey),
      controller: randAddr(),
      chainId: 31337,
      registry: randAddr(),
      nonce: randomBytes(32).toString("hex"),
      origin: "",
    }),
  ];
  const nodeSigs = msgs.map((m) => mlDsaSign(node.privateKey, m));
  let malleable: Buffer | null = null;
  for (let t = 0; t < 20 && !malleable; t++) malleable = duplicateHintIndex(mlDsaSign(node.privateKey, msgs[1] as Buffer));

  let out: PyOut;
  const summary: Record<string, string> = {};
  beforeAll(() => {
    const ops: unknown[] = [
      ...msgs.map((m, i) => ({ op: "verify", pk: hex(node.publicKey), msg: hex(m), sig: hex(nodeSigs[i] as Buffer) })),
      { op: "verify", pk: hex(node.publicKey), msg: hex(msgs[1] as Buffer), sig: hex(flip(nodeSigs[1] as Buffer, 50)) },
      { op: "verify", pk: hex(node.publicKey), msg: hex(flip(msgs[1] as Buffer, 0)), sig: hex(nodeSigs[1] as Buffer) },
      { op: "verify", pk: hex(node.publicKey), msg: hex(msgs[1] as Buffer), sig: hex(malleable ?? Buffer.alloc(0)) },
      { op: "sign", msgs: msgs.map(hex) },
    ];
    out = runPy(ops);
  });

  it("runs dilithium-py 1.4.0", () => {
    expect(out.impl).toBe("dilithium-py 1.4.0");
  });

  it("Node (OpenSSL) signatures verify under dilithium-py; tampering is rejected", () => {
    const r = out.results;
    for (let i = 0; i < msgs.length; i++) expect(r[i]?.valid, `message ${i}`).toBe(true);
    expect(r[msgs.length]?.valid).toBe(false);
    expect(r[msgs.length + 1]?.valid).toBe(false);
    summary["nodeToDpy"] = `${msgs.length}/${msgs.length} valid, tampered sig and message rejected`;
  });

  it("dilithium-py signatures verify under Node (OpenSSL); tampering is rejected", () => {
    const signed = out.results[msgs.length + 3];
    expect(signed?.pk).toBeDefined();
    const pk = Buffer.from(signed?.pk ?? "", "hex");
    const sigs = (signed?.sigs ?? []).map((s) => Buffer.from(s, "hex"));
    expect(pk.length).toBe(1312);
    expect(sigs.length).toBe(msgs.length);
    sigs.forEach((s, i) => {
      expect(s.length).toBe(2420);
      expect(mlDsaVerify(pk, msgs[i] as Buffer, s), `message ${i}`).toBe(true);
      expect(mlDsaVerify(pk, msgs[i] as Buffer, flip(s, 100))).toBe(false);
    });
    expect(verifyStatement(pk, msgs[3] as Buffer, sigs[3] as Buffer)).toBe(true);
    summary["dpyToNode"] = `${sigs.length}/${sigs.length} valid, tampered sigs rejected`;
  });

  it("non-canonical hint encoding (repeated index): OpenSSL rejects; dilithium-py 1.4.0 accepts (known v3 finding)", () => {
    expect(malleable).not.toBeNull();
    expect(mlDsaVerify(node.publicKey, msgs[1] as Buffer, malleable as Buffer)).toBe(false);
    // Measured behaviour of the pinned dilithium-py 1.4.0 (see packages/pqc/pqc_cli.py
    // _hints_canonical). v4 never verifies with dilithium-py.
    expect(out.results[msgs.length + 2]?.valid).toBe(true);
    summary["nonCanonicalHint"] = "OpenSSL rejects, dilithium-py 1.4.0 accepts";
    console.log(`[interop] ${implementationLabel()} vs ${out.impl}: ${JSON.stringify(summary)}`);
  });
});
