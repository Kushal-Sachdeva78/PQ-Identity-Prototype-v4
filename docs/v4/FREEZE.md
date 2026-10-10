# B7: freeze of relation R4 (v4 circuit)

Frozen on 2026-09-27 (IST), after mutation campaign 5 and suite run 10.

## What is frozen

| File | SHA-256 |
|---|---|
| `circuits/credential_auth_v4.circom` | c3a5f68d045620e58199d98ff8e06f251fb6dc527b85bc5579c3067753ce5c91 |
| `circuits/v4/lib_v4.circom` | 0637b51c756514ed39d9ccb34177426a55bf2551fc8b90461716eadfbc20ec5e |
| `circuits/build/v4/credential_auth_v4.r1cs` | c593e9f29094c44efa2b0bf1805715b96e5b3a6815b39c761cdb25c18c9e87b5 |
| `circuits/build/v4/credential_auth_v4_js/credential_auth_v4.wasm` | 678720322fc69048b40aa375ee7c9cc2eab5d0ce58f116d54ac1bab6957bd8ae |
| `circuits/build/v4/credential_auth_v4.sym` | 4b56008b59fa0db0b24db9e6ae2ccd0b91ad4fb246d207068f397a5509d30645 |
| `setup/out/v4/credential_auth_v4_dev.zkey` (dev key) | b6f1675c3b8996f5165d54912bc9e7f592cd9ff3286c1a236ad375ea635635d4 |
| `setup/out/v4/verification_key_dev.json` | 87a45ca3ab4616debd4ec1d9351327a13ad5f416793ac08f7b901e45056eff42 |
| `setup/out/v4/Groth16VerifierV4_dev.sol` | bf2a0918213eac2a40b0fa85b4ee167a2b207aa62ee8105dc16724ac1b9d33a7 |
| `setup/ptau/powersOfTau28_hez_final_15.ptau` | 3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f |

- Compiler: circom 2.2.3, `--O2`. The r1cs and wasm hashes equal `setup/pins_v4.json`, and a
  fresh compile reproduces both (`artifact/check_circuit_v4.sh`, `verification/v4/rebuild_quick_1.log`).
- The circuit sources have not changed since commit 60bfc96 (the dev key's commit): `git diff
  60bfc96 HEAD` on both source files and `setup/pins_v4.json` is empty. The only later files
  under `circuits/` are research harnesses in `circuits/v4/research/`, which are not part of R4.
- Key: dev (one secret contribution, entropy discarded, then the public beacon). The ceremony
  key replaces it later (TASKS B8 kit, I); the ceremony runs on exactly the r1cs above.

## Evidence that Phase C passed on this circuit

- C1: security suite run 10 (`verification/v4/suite_run10.log`), `results/v4/security_suite.json`:
  pass, 0 of 86 attack routes accepted, 0 invalid, honest controls 15 of 15 accepted, every
  catalogued route run (`docs/v4/ROUTES.md`); v4 unit tests 164 of 164 (`verification/v4/vitest_v4_5.log`).
- C2: `docs/v4/C2_ANALYZERS.md`.
- C3: campaign 5 against suite run 10 (`verification/v4/mutation_run5.log`), `results/v4/mutation.json`,
  `results/v4/c3_summary.json`, `docs/v4/C3_MUTATION.md`: 59 defences, 40 tested, 19 no-effect and
  all 19 classified (15 redundant, 4 robustness, `docs/v4/C3_CLASSIFICATION.json`), 0 errors, 0
  honest controls broken. Every circuit group whose removal lets a route through is tested; G09,
  G11, G16 and G17 are redundant with the reasons in the classification file.

## Rule after the freeze

- Any change to a file in the table ends the freeze: record it in DECISIONS, make a new dev key
  (or ceremony key), re-run C1 and the circuit rows of C3, and discard Phase D results measured
  on the old artifacts (the bench runner refuses changed artifact hashes).
- Wallet, verifier, registry and harness code may still change; each change re-runs C1 (and the
  affected C3 rows) but does not touch the frozen relation or the benchmarks of proving and
  verification.
