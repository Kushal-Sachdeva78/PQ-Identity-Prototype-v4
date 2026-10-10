// H1 fixture (TASKS H1): an ML-DSA-44 signature, made by Node's OpenSSL exactly as the v4
// issuer signs (packages/v4/src/pqc.ts: pure ML-DSA-44, empty context), over the credential
// message the zkVM guest rebuilds. The issuer key is a throwaway made here and discarded: the
// fixture holds only the public key and the signature. The holder secret is a random throwaway.
//
// Usage: node stretch/h1/make_fixture.mjs <out.json>
import { generateKeyPairSync, sign, verify, randomBytes, createHash } from "node:crypto";
import { writeFileSync } from "node:fs";

const out = process.argv[2];
if (!out) throw new Error("usage: node stretch/h1/make_fixture.mjs <out.json>");

// Same layout as credential_message() in the guest: domain, holder commitment, birth date,
// expiry date and credential type, dates as u32 yyyymmdd, all big-endian.
const DOMAIN = Buffer.from("pqid-h1-credential-v1", "utf8");
function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
}
const holderSecret = randomBytes(32);
const holderCommit = createHash("sha256").update(holderSecret).digest();
const cred = { birth: 20080215, expiry: 20301231, typeId: 1 };
const msg = Buffer.concat([DOMAIN, holderCommit, u32(cred.birth), u32(cred.expiry), u32(cred.typeId)]);

const { publicKey, privateKey } = generateKeyPairSync("ml-dsa-44");
const sig = sign(null, msg, privateKey);
if (!verify(null, msg, publicKey, sig)) throw new Error("OpenSSL self-check failed");
// Raw FIPS 204 public key: the last 1312 bytes of the SPKI DER encoding.
const spki = publicKey.export({ format: "der", type: "spki" });
const pk = spki.subarray(spki.length - 1312);

const fixture = {
  schema: "pqid/v4-h1-fixture/v1",
  note: "throwaway issuer key (secret discarded) and throwaway holder secret; test data only",
  signer: `Node ${process.version}, OpenSSL ${process.versions.openssl}, ML-DSA-44, empty context`,
  issuerPk: Buffer.from(pk).toString("hex"),
  signature: Buffer.from(sig).toString("hex"),
  holderSecret: holderSecret.toString("hex"),
  birth: cred.birth,
  expiry: cred.expiry,
  typeId: cred.typeId,
  today: 20260929,
  threshold: 18,
  nonce: randomBytes(32).toString("hex"),
  messageSha256: createHash("sha256").update(msg).digest("hex"),
};
writeFileSync(out, JSON.stringify(fixture, null, 2) + "\n");
console.log(`[h1] fixture -> ${out} (pk ${pk.length} B, sig ${sig.length} B)`);
