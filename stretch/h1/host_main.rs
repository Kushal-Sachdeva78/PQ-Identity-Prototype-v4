// H1 host (TASKS H1): runs the guest of guest_main.rs in the RISC Zero zkVM on the CPU and
// records cycles, proving time, receipt size and verification time as [M] measurements, plus
// negative controls (a tampered signature, an under-age holder, a wrong holder secret) that the
// guest must refuse. Copied into host/src/main.rs by run_h1.sh.
//
// Usage: cargo run --release -- <fixture.json> <out.json> <runs>
use methods::{H1_GUEST_ELF, H1_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Deserialize)]
struct Fixture {
    #[serde(rename = "issuerPk")]
    issuer_pk: String,
    signature: String,
    #[serde(rename = "holderSecret")]
    holder_secret: String,
    birth: u32,
    expiry: u32,
    #[serde(rename = "typeId")]
    type_id: u32,
    today: u32,
    threshold: u32,
    nonce: String,
}

// Field order must match the guest's Input (the zkVM serde is positional).
#[derive(Serialize, Clone)]
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

fn arr32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str).expect("hex").try_into().expect("32 bytes")
}

fn prove(input: &Input, opts: &ProverOpts) -> anyhow::Result<(risc0_zkvm::ProveInfo, f64)> {
    let env = ExecutorEnv::builder().write(input)?.build()?;
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env, H1_GUEST_ELF, opts)?;
    Ok((info, t.elapsed().as_secs_f64() * 1000.0))
}

fn refused(input: &Input) -> bool {
    // Execution alone decides a refusal: the guest panics before committing a journal.
    let env = ExecutorEnv::builder().write(input).unwrap().build().unwrap();
    risc0_zkvm::default_executor().execute(env, H1_GUEST_ELF).is_err()
}

fn median(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let fixture_path = args.get(1).expect("fixture.json");
    let out_path = args.get(2).expect("out.json");
    let runs: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(3);
    let f: Fixture = serde_json::from_str(&std::fs::read_to_string(fixture_path)?)?;
    let input = Input {
        issuer_pk: hex::decode(&f.issuer_pk)?,
        signature: hex::decode(&f.signature)?,
        holder_secret: arr32(&f.holder_secret),
        birth: f.birth,
        expiry: f.expiry,
        type_id: f.type_id,
        today: f.today,
        threshold: f.threshold,
        nonce: arr32(&f.nonce),
    };

    // Negative controls (execution only).
    let mut bad_sig = input.clone();
    bad_sig.signature[100] ^= 1;
    let mut too_young = input.clone();
    too_young.threshold = 21;
    let mut wrong_secret = input.clone();
    wrong_secret.holder_secret[0] ^= 1;
    let controls = serde_json::json!({
        "tamperedSignatureRefused": refused(&bad_sig),
        "underAgeRefused": refused(&too_young),
        "wrongHolderSecretRefused": refused(&wrong_secret),
        "honestInputRefused": refused(&input),
    });

    let mut prove_ms = Vec::new();
    let mut verify_ms = Vec::new();
    let mut sizes = Vec::new();
    let mut stats = serde_json::Value::Null;
    let mut journal_len = 0usize;
    for _ in 0..runs {
        let (info, ms) = prove(&input, &ProverOpts::succinct())?;
        let receipt: Receipt = info.receipt;
        let t = Instant::now();
        receipt.verify(H1_GUEST_ID)?;
        verify_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        prove_ms.push(ms);
        sizes.push(bincode::serialize(&receipt)?.len());
        journal_len = receipt.journal.bytes.len();
        stats = serde_json::json!({
            "segments": info.stats.segments,
            "totalCycles": info.stats.total_cycles,
            "userCycles": info.stats.user_cycles,
            "pagingCycles": info.stats.paging_cycles,
            "reservedCycles": info.stats.reserved_cycles,
        });
    }
    let out = serde_json::json!({
        "schema": "pqid/v4-h1-zkvm/v1",
        "label": "[M] measured on this laptop (WSL2 Ubuntu 24.04), CPU prover, succinct receipts",
        "statement": "ML-DSA-44 issuer signature over a credential, holder-secret commitment, expiry and age-at-least, proved inside the RISC Zero zkVM; journal = issuer key hash, date, threshold, type, nonce",
        "runs": runs,
        "stats": stats,
        "proveMs": {"median": median(&mut prove_ms.clone()), "all": prove_ms},
        "verifyMs": {"median": median(&mut verify_ms.clone()), "all": verify_ms},
        "receiptBytes": sizes,
        "journalBytes": journal_len,
        "controls": controls,
    });
    std::fs::write(out_path, serde_json::to_string_pretty(&out)? + "\n")?;
    println!("[h1] -> {out_path}");
    Ok(())
}
