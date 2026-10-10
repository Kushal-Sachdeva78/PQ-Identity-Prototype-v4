// H1 guest (TASKS H1): inside the RISC Zero zkVM, check an issuer's ML-DSA-44 signature over a
// credential, the holder's knowledge of the secret behind the credential's holder commitment,
// expiry and an age-at-least predicate. The journal (public output) holds only the SHA-256 of
// the issuer public key, the date, the threshold, the credential type and the verifier's
// nonce; the signature, the birth date and the holder secret stay private.
// Copied into methods/guest/src/main.rs by run_h1.sh.
#![no_main]

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Verifier};
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};
use serde::{Deserialize, Serialize};

risc0_zkvm::guest::entry!(main);

#[derive(Deserialize)]
struct Input {
    issuer_pk: Vec<u8>,
    signature: Vec<u8>,
    holder_secret: [u8; 32],
    birth: u32,
    expiry: u32,
    type_id: u32,
    today: u32,
    threshold: u32,
    nonce: [u8; 32],
}

#[derive(Serialize)]
struct Journal {
    issuer_pk_sha256: [u8; 32],
    today: u32,
    threshold: u32,
    type_id: u32,
    nonce: [u8; 32],
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let d = Impl::hash_bytes(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_bytes());
    out
}

/// Same layout as stretch/h1/make_fixture.mjs.
fn credential_message(holder_commit: &[u8; 32], birth: u32, expiry: u32, type_id: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(21 + 32 + 12);
    m.extend_from_slice(b"pqid-h1-credential-v1");
    m.extend_from_slice(holder_commit);
    m.extend_from_slice(&birth.to_be_bytes());
    m.extend_from_slice(&expiry.to_be_bytes());
    m.extend_from_slice(&type_id.to_be_bytes());
    m
}

/// yyyymmdd -> (year, month, day)
fn ymd(d: u32) -> (u32, u32, u32) {
    (d / 10000, (d / 100) % 100, d % 100)
}

fn main() {
    let i: Input = env::read();
    let holder_commit = sha256(&i.holder_secret);
    let msg = credential_message(&holder_commit, i.birth, i.expiry, i.type_id);

    let pk_bytes: [u8; ml_dsa_44::PK_LEN] = i.issuer_pk.as_slice().try_into().expect("public key length");
    let sig: [u8; ml_dsa_44::SIG_LEN] = i.signature.as_slice().try_into().expect("signature length");
    let pk = ml_dsa_44::PublicKey::try_from_bytes(pk_bytes).expect("public key encoding");
    assert!(pk.verify(&msg, &sig, &[]), "issuer signature does not verify");

    assert!(i.expiry >= i.today, "credential expired");
    // Age at least `threshold` on `today`: (birth year + threshold, month, day) <= today, as a
    // tuple, so a 29 February birthday counts from 1 March in a common year (DECISIONS D-010).
    let (by, bm, bd) = ymd(i.birth);
    assert!((by + i.threshold, bm, bd) <= ymd(i.today), "age predicate does not hold");

    env::commit(&Journal {
        issuer_pk_sha256: sha256(&i.issuer_pk),
        today: i.today,
        threshold: i.threshold,
        type_id: i.type_id,
        nonce: i.nonce,
    });
}
