/**
 * Tests for baseline E2a (baselines/sdjwt): ML-DSA-44 SD-JWT with key binding.
 * Covers issue/present/verify, tampering, key binding (nonce, aud, iat, key),
 * linkability of one SD-JWT across presentations, and unlinkability of a batch.
 */
import { describe, it, expect, beforeAll } from "vitest";
import crypto from "node:crypto";
import { STANDARD_THRESHOLDS } from "@pqid/v4/constants";
import { ageClaims, ageOver } from "../../baselines/sdjwt/age.ts";
import {
  ML_DSA_44_PUBLIC_KEY_BYTES,
  ML_DSA_44_SIGNATURE_BYTES,
  b64u,
  b64uDecode,
  keygen,
  parseJws,
  signJws,
} from "../../baselines/sdjwt/jose.ts";
import {
  DAY_SEC,
  SdJwtHolder,
  SdJwtIssuer,
  decodeDisclosure,
  issue,
  linkHandles,
  makeDisclosure,
  present,
  sdHashOf,
  sharedHandles,
  sizesOf,
  splitSdJwt,
  verify,
  type IssuerKey,
} from "../../baselines/sdjwt/sdjwt.ts";
import { batchSizes, checkKeyProof, issueBatch, makeKeyProof } from "../../baselines/sdjwt/batch.ts";

const NOW = 1_790_000_000; // fixed test clock (2026-09-21 UTC); every time below derives from it
const BIRTH = 20070115; // synthetic holder: 19 years old on the issuance date
const ISSUANCE_DATE = 20260921;
const AUD = "https://verifier-a.baseline.invalid";
const AUD_B = "https://verifier-b.baseline.invalid";

let issuer: SdJwtIssuer;
let holder: SdJwtHolder;
let sdjwt: string;
const claims = ageClaims(BIRTH, ISSUANCE_DATE);
const nonce = (): string => b64u(crypto.randomBytes(16));

beforeAll(() => {
  issuer = new SdJwtIssuer("ML-DSA-44");
  holder = new SdJwtHolder("ML-DSA-44");
  sdjwt = issuer.issue(claims, holder.publicKey, { now: NOW });
});

describe("age claims", () => {
  it("one age_over_NN per standard threshold, plus birthdate", () => {
    expect(Object.keys(claims).sort()).toEqual([...STANDARD_THRESHOLDS.map((t) => `age_over_${t}`), "birthdate"].sort());
    expect(claims.age_over_18).toBe(true);
    expect(claims.age_over_21).toBe(false);
    expect(claims.birthdate).toBe("2007-01-15");
  });
  it("birthday boundary and 29 February follow the v4 rule", () => {
    expect(ageOver(20080101, 18, 20260101)).toBe(true);
    expect(ageOver(20080102, 18, 20260101)).toBe(false);
    expect(ageOver(20080229, 18, 20260228)).toBe(false);
    expect(ageOver(20080229, 18, 20260301)).toBe(true);
  });
});

describe("issue / present / verify (ML-DSA-44)", () => {
  it("issued form has the RFC 9901 shape and ML-DSA-44 sizes", () => {
    const parts = splitSdJwt(sdjwt);
    expect(parts.kbJwt).toBeNull();
    expect(parts.disclosures.length).toBe(Object.keys(claims).length);
    const jws = parseJws(parts.issuerJwt);
    expect(jws.header).toEqual({ typ: "dc+sd-jwt", alg: "ML-DSA-44" });
    expect(jws.signature.length).toBe(ML_DSA_44_SIGNATURE_BYTES);
    expect(jws.payload._sd_alg).toBe("sha-256");
    const jwk = (jws.payload.cnf as { jwk: Record<string, string> }).jwk;
    expect(jwk.kty).toBe("AKP");
    expect(jwk.alg).toBe("ML-DSA-44");
    expect(b64uDecode(jwk.pub as string).length).toBe(ML_DSA_44_PUBLIC_KEY_BYTES);
    // no claim value appears in clear in the signed payload
    expect(JSON.stringify(jws.payload)).not.toContain("age_over");
    expect(JSON.stringify(jws.payload)).not.toContain("birthdate");
    // _sd is sorted and each digest is the SHA-256 of one disclosure
    const sd = jws.payload._sd as string[];
    expect([...sd].sort()).toEqual(sd);
    for (const d of parts.disclosures) expect(sd).toContain(decodeDisclosure(d).digest);
    // iat rounded to the UTC day, exp = iat + 90 days
    expect(jws.payload.iat).toBe(NOW - (NOW % DAY_SEC));
    expect(jws.payload.exp).toBe((jws.payload.iat as number) + 90 * DAY_SEC);
  });

  it("verifier learns only age_over_18 (plus the always-visible iss, vct, iat, exp, cnf)", () => {
    const n = nonce();
    const pres = holder.present(sdjwt, ["age_over_18"], { nonce: n, aud: AUD, iat: NOW });
    const r = verify(pres, issuer.publicKey, { nonce: n, aud: AUD, now: NOW, required: ["age_over_18"] });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.disclosed).toEqual({ age_over_18: true });
    expect(r.issuer).toBe(issuer.iss);
    expect(Object.keys(r.claims).sort()).toEqual(["age_over_18", "cnf", "exp", "iat", "iss", "vct"]);
    expect(splitSdJwt(pres).disclosures.length).toBe(1);
  });

  it("presentation with no disclosures still verifies (key binding only)", () => {
    const n = nonce();
    const pres = holder.present(sdjwt, [], { nonce: n, aud: AUD, iat: NOW });
    const r = verify(pres, issuer.publicKey, { nonce: n, aud: AUD, now: NOW });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.disclosed).toEqual({});
    expect(verify(pres, issuer.publicKey, { nonce: n, aud: AUD, now: NOW, required: ["age_over_18"] })).toMatchObject({
      ok: false,
      error: "required_claim_missing",
    });
  });

  it("a false claim is revealed as false, not hidden", () => {
    const n = nonce();
    const pres = holder.present(sdjwt, ["age_over_21"], { nonce: n, aud: AUD, iat: NOW });
    const r = verify(pres, issuer.publicKey, { nonce: n, aud: AUD, now: NOW });
    expect(r.ok && r.disclosed).toEqual({ age_over_21: false });
  });

  it("holder cannot present a claim that was not issued", () => {
    expect(() => holder.present(sdjwt, ["age_over_25"], { nonce: nonce(), aud: AUD, iat: NOW })).toThrow(/no disclosure/);
  });
});

describe("tampering is rejected", () => {
  function reKb(issuerJwt: string, disclosures: string[], n: string, aud = AUD, iat = NOW): string {
    // A dishonest holder rebuilds a valid KB-JWT with its own (correct) key over the tampered set.
    const kb = signJws("ML-DSA-44", holder.privateKeyForTests, { typ: "kb+jwt" }, { iat, aud, nonce: n, sd_hash: sdHashOf(issuerJwt, disclosures) });
    return `${issuerJwt}~${disclosures.map((d) => `${d}~`).join("")}${kb}`;
  }

  it("changed disclosure value (age_over_21 false -> true) with a fresh valid KB-JWT", () => {
    const parts = splitSdJwt(sdjwt);
    const orig = parts.disclosures.map(decodeDisclosure).find((d) => d.name === "age_over_21");
    expect(orig?.value).toBe(false);
    const forged = b64u(JSON.stringify([orig?.salt, "age_over_21", true]));
    const n = nonce();
    const r = verify(reKb(parts.issuerJwt, [forged], n), issuer.publicKey, { nonce: n, aud: AUD, now: NOW });
    expect(r).toMatchObject({ ok: false, error: "disclosure_unreferenced" });
  });

  it("invented disclosure (age_over_25) with a fresh valid KB-JWT", () => {
    const parts = splitSdJwt(sdjwt);
    const n = nonce();
    const r = verify(reKb(parts.issuerJwt, [makeDisclosure("age_over_25", true).encoded], n), issuer.publicKey, { nonce: n, aud: AUD, now: NOW });
    expect(r).toMatchObject({ ok: false, error: "disclosure_unreferenced" });
  });

  it("disclosure swapped in from another holder's credential", () => {
    const other = new SdJwtHolder("ML-DSA-44");
    const otherCred = issuer.issue(ageClaims(19800101, ISSUANCE_DATE), other.publicKey, { now: NOW });
    const d21 = splitSdJwt(otherCred).disclosures.find((d) => decodeDisclosure(d).name === "age_over_21") as string;
    expect(decodeDisclosure(d21).value).toBe(true);
    const n = nonce();
    const r = verify(reKb(splitSdJwt(sdjwt).issuerJwt, [d21], n), issuer.publicKey, { nonce: n, aud: AUD, now: NOW });
    expect(r).toMatchObject({ ok: false, error: "disclosure_unreferenced" });
  });

  it("disclosure edited after the KB-JWT was made", () => {
    const n = nonce();
    const pres = holder.present(sdjwt, ["age_over_18", "age_over_21"], { nonce: n, aud: AUD, iat: NOW });
    const parts = splitSdJwt(pres);
    // drop one disclosure without re-signing: sd_hash no longer matches
    const cut = `${parts.issuerJwt}~${parts.disclosures[0]}~${parts.kbJwt}`;
    expect(verify(cut, issuer.publicKey, { nonce: n, aud: AUD, now: NOW })).toMatchObject({ ok: false, error: "kb_sd_hash" });
  });

  it("duplicate disclosure", () => {
    const parts = splitSdJwt(sdjwt);
    const d = parts.disclosures[0] as string;
    const n = nonce();
    expect(verify(reKb(parts.issuerJwt, [d, d], n), issuer.publicKey, { nonce: n, aud: AUD, now: NOW })).toMatchObject({
      ok: false,
      error: "disclosure_duplicate",
    });
  });

  it("issuer payload edited (signature breaks)", () => {
    const parts = splitSdJwt(sdjwt);
    const jws = parseJws(parts.issuerJwt);
    const payload = { ...jws.payload, exp: (jws.payload.exp as number) + 365 * DAY_SEC };
    const edited = `${jws.segments[0]}.${b64u(JSON.stringify(payload))}.${jws.segments[2]}`;
    const n = nonce();
    const d18 = parts.disclosures.find((x) => decodeDisclosure(x).name === "age_over_18") as string;
    expect(verify(reKb(edited, [d18], n), issuer.publicKey, { nonce: n, aud: AUD, now: NOW })).toMatchObject({
      ok: false,
      error: "issuer_signature",
    });
  });

  it("wrong issuer key, alg none, alg outside the allow list, wrong typ", () => {
    const n = nonce();
    const pres = holder.present(sdjwt, ["age_over_18"], { nonce: n, aud: AUD, iat: NOW });
    const other = new SdJwtIssuer("ML-DSA-44");
    expect(verify(pres, other.publicKey, { nonce: n, aud: AUD, now: NOW })).toMatchObject({ ok: false, error: "issuer_signature" });

    const parts = splitSdJwt(pres);
    const jws = parseJws(parts.issuerJwt);
    const noneHeader = b64u(JSON.stringify({ typ: "dc+sd-jwt", alg: "none" }));
    const noneJwt = `${noneHeader}.${jws.segments[1]}.`;
    expect(verify(`${noneJwt}~${parts.disclosures[0]}~${parts.kbJwt}`, issuer.publicKey, { nonce: n, aud: AUD, now: NOW })).toMatchObject({
      ok: false,
      error: "issuer_alg",
    });
    expect(verify(pres, issuer.publicKey, { nonce: n, aud: AUD, now: NOW, allowedAlgs: ["ES256"] })).toMatchObject({ ok: false, error: "issuer_alg" });

    const k = issuer.keyForTests;
    const wrongTyp = signJws("ML-DSA-44", k.privateKey, { typ: "JWT" }, jws.payload);
    expect(verify(`${wrongTyp}~${parts.disclosures[0]}~${parts.kbJwt}`, issuer.publicKey, { nonce: n, aud: AUD, now: NOW })).toMatchObject({
      ok: false,
      error: "issuer_typ",
    });
  });

  it("expired credential", () => {
    const n = nonce();
    const later = NOW + 91 * DAY_SEC;
    const pres = holder.present(sdjwt, ["age_over_18"], { nonce: n, aud: AUD, iat: later });
    expect(verify(pres, issuer.publicKey, { nonce: n, aud: AUD, now: later })).toMatchObject({ ok: false, error: "expired" });
  });

  it("malicious issuer: a disclosure may not set a reserved claim or collide with a visible one", () => {
    const k: IssuerKey = issuer.keyForTests;
    const bad = makeDisclosure("iss", "https://evil.invalid");
    const jwt = signJws("ML-DSA-44", k.privateKey, { typ: "dc+sd-jwt" }, {
      iss: k.iss,
      iat: NOW,
      exp: NOW + DAY_SEC,
      vct: "x",
      cnf: { jwk: (parseJws(splitSdJwt(sdjwt).issuerJwt).payload.cnf as { jwk: unknown }).jwk },
      _sd_alg: "sha-256",
      _sd: [bad.digest],
    });
    const n = nonce();
    const pres = present(`${jwt}~${bad.encoded}~`, ["iss"], { nonce: n, aud: AUD, holderKey: holder.privateKeyForTests, iat: NOW });
    expect(verify(pres, issuer.publicKey, { nonce: n, aud: AUD, now: NOW })).toMatchObject({ ok: false, error: "claim_name" });
  });
});

describe("key binding", () => {
  it("wrong nonce rejected", () => {
    const pres = holder.present(sdjwt, ["age_over_18"], { nonce: nonce(), aud: AUD, iat: NOW });
    expect(verify(pres, issuer.publicKey, { nonce: nonce(), aud: AUD, now: NOW })).toMatchObject({ ok: false, error: "kb_nonce" });
  });

  it("wrong audience rejected (presentation replayed to another verifier)", () => {
    const n = nonce();
    const pres = holder.present(sdjwt, ["age_over_18"], { nonce: n, aud: AUD, iat: NOW });
    expect(verify(pres, issuer.publicKey, { nonce: n, aud: AUD_B, now: NOW })).toMatchObject({ ok: false, error: "kb_aud" });
  });

  it("stale or future KB-JWT iat rejected", () => {
    const n = nonce();
    const old = holder.present(sdjwt, ["age_over_18"], { nonce: n, aud: AUD, iat: NOW - 3600 });
    expect(verify(old, issuer.publicKey, { nonce: n, aud: AUD, now: NOW })).toMatchObject({ ok: false, error: "kb_iat" });
    const fut = holder.present(sdjwt, ["age_over_18"], { nonce: n, aud: AUD, iat: NOW + 3600 });
    expect(verify(fut, issuer.publicKey, { nonce: n, aud: AUD, now: NOW })).toMatchObject({ ok: false, error: "kb_iat" });
  });

  it("missing KB-JWT rejected", () => {
    const parts = splitSdJwt(sdjwt);
    const noKb = `${parts.issuerJwt}~${parts.disclosures[0]}~`;
    expect(verify(noKb, issuer.publicKey, { nonce: nonce(), aud: AUD, now: NOW })).toMatchObject({ ok: false, error: "kb_missing" });
  });

  it("stolen credential used with the thief's key rejected", () => {
    const thief = keygen("ML-DSA-44");
    const n = nonce();
    const parts = splitSdJwt(sdjwt);
    const d18 = parts.disclosures.find((x) => decodeDisclosure(x).name === "age_over_18") as string;
    const kb = signJws("ML-DSA-44", thief.privateKey, { typ: "kb+jwt" }, { iat: NOW, aud: AUD, nonce: n, sd_hash: sdHashOf(parts.issuerJwt, [d18]) });
    expect(verify(`${parts.issuerJwt}~${d18}~${kb}`, issuer.publicKey, { nonce: n, aud: AUD, now: NOW })).toMatchObject({
      ok: false,
      error: "kb_signature",
    });
    // and the honest present() refuses a key that does not match cnf
    expect(() => present(sdjwt, ["age_over_18"], { nonce: n, aud: AUD, holderKey: thief.privateKey })).toThrow(/cnf/);
  });
});

describe("linkability", () => {
  it("two presentations of the same SD-JWT share the issuer-signed JWT bytes (linkable)", () => {
    const p1 = holder.present(sdjwt, ["age_over_18"], { nonce: nonce(), aud: AUD, iat: NOW });
    const p2 = holder.present(sdjwt, ["age_over_18"], { nonce: nonce(), aud: AUD_B, iat: NOW + 5 });
    const a = splitSdJwt(p1);
    const b = splitSdJwt(p2);
    expect(a.issuerJwt).toBe(b.issuerJwt); // byte-identical, includes signature, all digests, cnf key
    expect(a.disclosures).toEqual(b.disclosures); // same salt too
    expect(a.kbJwt).not.toBe(b.kbJwt);
    const shared = sharedHandles(p1, p2);
    expect(shared.some((h) => h.startsWith("sig:"))).toBe(true);
    expect(shared.some((h) => h.startsWith("cnf:"))).toBe(true);
    expect(shared.filter((h) => h.startsWith("digest:")).length).toBe(Object.keys(claims).length);
    // even with zero disclosed claims the two presentations are linkable
    const z1 = holder.present(sdjwt, [], { nonce: nonce(), aud: AUD, iat: NOW });
    const z2 = holder.present(sdjwt, [], { nonce: nonce(), aud: AUD_B, iat: NOW });
    expect(sharedHandles(z1, z2).length).toBeGreaterThan(0);
  });

  it("batch credentials are unlinkable: no shared signature, digest, salt or cnf key", () => {
    const n = 30;
    const batch = issueBatch(issuer.keyForTests, claims, n, { now: NOW });
    expect(batch.length).toBe(n);
    const pres = batch.map((c, i) =>
      present(c.sdjwt, ["age_over_18"], { nonce: nonce(), aud: i % 2 ? AUD : AUD_B, holderKey: c.holder.privateKey, iat: NOW + i })
    );
    for (const p of pres) {
      const n0 = parseJws(splitSdJwt(p).kbJwt as string).payload.nonce as string;
      const aud = parseJws(splitSdJwt(p).kbJwt as string).payload.aud as string;
      expect(verify(p, issuer.publicKey, { nonce: n0, aud, now: NOW + 60 }).ok).toBe(true);
    }
    const sigs = new Set(pres.map((p) => parseJws(splitSdJwt(p).issuerJwt).signature.toString("base64")));
    expect(sigs.size).toBe(n);
    const allHandles = pres.flatMap((p) => linkHandles(p).perCredential);
    expect(new Set(allHandles).size).toBe(allHandles.length); // every per-credential handle is unique
    for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) expect(sharedHandles(pres[i] as string, pres[j] as string)).toEqual([]);
    // what remains in common is population-level: identical for a different holder issued the same day
    const stranger = new SdJwtHolder("ML-DSA-44");
    const strangerPres = stranger.present(issuer.issue(ageClaims(19900505, ISSUANCE_DATE), stranger.publicKey, { now: NOW + 3000 }), ["age_over_18"], {
      nonce: nonce(),
      aud: AUD,
      iat: NOW,
    });
    for (const p of pres) expect(linkHandles(p).population).toEqual(linkHandles(strangerPres).population);
    // no signature byte string is shared between batch members
    const sizes = batchSizes(batch);
    expect(sizes.n).toBe(n);
    expect(sizes.issuerToHolderBytes).toBe(batch.reduce((a, c) => a + c.sdjwt.length, 0));
  });

  it("key proofs verify and bind the holder key [A: modelled step]", () => {
    const k = keygen("ML-DSA-44");
    const proof = makeKeyProof(k, "iss", "n1", NOW);
    expect(checkKeyProof(proof, "iss", "n1").equals(k.publicKey)).toBe(true);
    expect(() => checkKeyProof(proof, "iss", "n2")).toThrow();
  });
});

describe("classical reference (ES256) and sizes", () => {
  it("ES256 SD-JWT works on the same code path; algorithms are not interchangeable", () => {
    const iss2 = new SdJwtIssuer("ES256");
    const h2 = new SdJwtHolder("ES256");
    const cred = iss2.issue(claims, h2.publicKey, { now: NOW });
    const n = nonce();
    const pres = h2.present(cred, ["age_over_18"], { nonce: n, aud: AUD, iat: NOW });
    expect(verify(pres, iss2.publicKey, { nonce: n, aud: AUD, now: NOW, allowedAlgs: ["ES256"] }).ok).toBe(true);
    // default verifier accepts ML-DSA-44 only
    expect(verify(pres, iss2.publicKey, { nonce: n, aud: AUD, now: NOW })).toMatchObject({ ok: false, error: "issuer_alg" });
    // an ML-DSA key offered for an ES256 header is refused
    expect(verify(pres, issuer.publicKey, { nonce: n, aud: AUD, now: NOW, allowedAlgs: ["ES256", "ML-DSA-44"] })).toMatchObject({
      ok: false,
      error: "issuer_key",
    });
    expect(parseJws(splitSdJwt(pres).issuerJwt).signature.length).toBe(64);
  });

  it("sizesOf adds up to the serialized length", () => {
    const n = nonce();
    const pres = holder.present(sdjwt, ["age_over_18"], { nonce: n, aud: AUD, iat: NOW });
    for (const s of [sdjwt, pres]) {
      const z = sizesOf(s);
      expect(z.issuerJwt.totalBytes + z.disclosures.bytes + z.separatorBytes + (z.kbJwt?.totalBytes ?? 0)).toBe(z.totalBytes);
      expect(z.issuerJwt.headerB64Bytes + z.issuerJwt.payloadB64Bytes + z.issuerJwt.signatureB64Bytes + 2).toBe(z.issuerJwt.totalBytes);
      expect(z.issuerJwt.signatureRawBytes).toBe(ML_DSA_44_SIGNATURE_BYTES);
    }
    expect(sizesOf(pres).kbJwt?.signatureRawBytes).toBe(ML_DSA_44_SIGNATURE_BYTES);
    expect(sizesOf(sdjwt).kbJwt).toBeNull();
  });

  it("issue() refuses to make reserved claims disclosable", () => {
    expect(() => issue(issuer.keyForTests, { exp: 1 }, holder.publicKey, { now: NOW })).toThrow(/must not/);
  });
});
