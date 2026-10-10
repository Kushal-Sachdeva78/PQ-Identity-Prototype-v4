// PQID_V4_GLUE_BEGIN
// PQ-Identity v4 circuit registration for the Mopro circom adapter.
// Inserted by mobile/mopro/scripts/patch_template.py in place of the template's multiplier2
// block in src/lib.rs (the `#[macro_use] mod circom;` line and the re-exports above it stay
// as `mopro init` wrote them).
//
// - Witness generator: rust-witness. build.rs transpiles the v4 circuit wasm read in place
//   from <repo>/circuits/build/v4/credential_auth_v4_js/ (PQID_V4_WASM_DIR); nothing is copied.
//   rust-witness names the circuit after the wasm file, lower case, special characters
//   removed: credential_auth_v4.wasm -> credentialauthv4, function credentialauthv4_witness
//   (https://raw.githubusercontent.com/chancehudson/rust-witness/main/README.md).
// - The adapter picks the witness function by the zkey FILE NAME passed at run time
//   (https://zkmopro.org/docs/adapters/circom), so the app must pass a path whose file name is
//   exactly credential_auth_v4_dev.zkey (the dev key, setup/out/v4/).

mod witness {
    rust_witness::witness!(credentialauthv4);
}

crate::set_circom_circuits! {
    ("credential_auth_v4_dev.zkey", circom_prover::witness::WitnessFn::RustWitness(witness::credentialauthv4_witness)),
}

/// Identification string the app writes into every log (not a measurement).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn pqid_v4_glue_info() -> String {
    format!(
        "pqid-v4-mopro-glue/1; circuit=credential_auth_v4; zkey=credential_auth_v4_dev.zkey; witness=rust-witness; proofLib=arkworks; crate={} {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    )
}
// PQID_V4_GLUE_END
