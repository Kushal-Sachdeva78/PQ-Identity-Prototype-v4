// build.rs for the PQ-Identity v4 Mopro crate (replaces the one `mopro init` writes).
// Copied into the scaffolded project by mobile/mopro/scripts/patch_template.py.
//
// rust-witness transpiles every .wasm file under the given directory (recursive search) to C
// and links it (https://raw.githubusercontent.com/chancehudson/rust-witness/main/README.md).
// The directory is the repo's compiled v4 circuit, read in place: nothing is copied, so the
// app always proves with the pinned wasm (sha256 in setup/pins_v4.json; checked by
// scripts/check_pins.py before every build).

fn main() {
    println!("cargo:rerun-if-env-changed=PQID_V4_WASM_DIR");
    let dir = std::env::var("PQID_V4_WASM_DIR").expect(
        "PQID_V4_WASM_DIR must name <repo>/circuits/build/v4/credential_auth_v4_js \
         (mobile/mopro/scripts/build_bindings.sh sets it)",
    );
    println!("cargo:rerun-if-changed={}", dir);
    rust_witness::transpile::transpile_wasm(dir);
}
