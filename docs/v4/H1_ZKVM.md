# H1: STARK zkVM prototype with ML-DSA-44 inside the proof (facts and pointers)

- What it proves (guest `stretch/h1/guest_main.rs`, run inside the RISC Zero zkVM): an ML-DSA-44
  signature by an issuer key over a credential message, the holder's knowledge of the secret
  behind the credential's holder commitment (SHA-256), expiry not before the date, and age at
  least the threshold on that date. Public output (journal): SHA-256 of the issuer public key,
  date, threshold, credential type, verifier nonce. Private: signature, birth date, holder
  secret, expiry.
- Why (review findings T3, T12): v4 checks the issuer's ML-DSA-44 signatures outside the proof
  (epoch statements) and binds credentials through a Poseidon issuance tree inside a Groth16
  proof. H1 measures what it costs to verify the ML-DSA-44 signature itself inside a proof whose
  soundness does not rest on pairings.
- Signature interoperability: the fixture is signed by Node's OpenSSL exactly as the v4 issuer
  signs (pure ML-DSA-44, empty context; `stretch/h1/make_fixture.mjs`); the guest verifies it with
  the `fips204` crate (0.4.6, no_std). Throwaway issuer key (secret discarded) and holder secret.
- Run: `bash stretch/h1/run_h1.sh [runs]` inside WSL2 Ubuntu (user-space rustup and rzup; the
  official `cargo risczero new` template with our guest and host). Results:
  `results/v4/h1/zkvm_mldsa.json` (cycles, CPU proving time, succinct receipt size, verify time,
  negative controls). Not a Phase D series: few runs, the machine not quiet-checked; label [M]
  with that caveat.

## Results (2026-09-29, `results/v4/h1/zkvm_mldsa.json`, environment `results/v4/h1/env.json`)

- Controls: the honest input is accepted; a tampered signature, an under-age holder (threshold
  21) and a wrong holder secret are refused (`$.controls`).
- Cost [M] (3 runs, CPU prover, succinct receipts; not a Phase D series): user cycles
  <!--ledger:vFourZkvmUserCycles-->3,874,248 (total <!--ledger:vFourZkvmTotalCycles-->4,325,376, <!--ledger:vFourZkvmSegments-->5 segments);
  proving median <!--ledger:vFourZkvmProveMedianS-->909 s; receipt <!--ledger:vFourZkvmReceiptBytes-->223,762 B;
  verification median <!--ledger:vFourZkvmVerifyMedianMs-->11.6 ms.
- For comparison on the same laptop: v4 Groth16 cold proving median <!--ledger:vFourBenchColdProveMedianMs-->1090 ms (snarkJS,
  Windows) and <!--ledger:vFourBenchWslColdRsProveMedianMs-->159 ms (rapidsnark, WSL2); the two statements differ (v4 also
  proves issuance-tree membership and non-revocation; H1 verifies the ML-DSA signature itself).

## Assumptions compared (facts with sources; the comparison text is the author's)

| Item | v4 (relation R4, Groth16 on BN254) | H1 (RISC Zero zkVM, succinct STARK receipt) |
|---|---|---|
| Soundness rests on | pairing-based knowledge soundness (Groth16; AGM attribution in packs/F6_reference_audit.md) [A] | STARK/FRI soundness; RISC Zero states 96 bits (RISC-V prover) and 99 bits (recursion) conjectured, under its "toy problem conjecture" (source 1) [A] |
| Quantum | discrete log in BN254 falls to Shor, so soundness does not hold against a quantum prover [A] | STARK provers "not known to be vulnerable" to quantum attacks (source 1) [A]; the optional STARK-to-SNARK wrap (Groth16 over BN254) is not quantum-safe (source 1) and is not used here |
| Setup | circuit-specific trusted setup (dev key now; ceremony later, TASKS I) | none for STARK receipts; the Groth16 wrap would need RISC Zero's ceremony (source 1) |
| Zero knowledge | perfect ZK (Groth16) [A] | "targets perfect zero-knowledge", no written proof (source 1) [A] |
| Issuer signature | ML-DSA-44 over epoch statements, checked outside the proof; leaves bound by a Poseidon tree inside the proof | ML-DSA-44 over the credential, checked inside the proof |
| Hashes inside the proof | Poseidon (collision resistance) | SHA-256 (holder commitment, issuer key hash) and the zkVM's own hashes |
| Proof size, prove time | `results/v4/bench/summary.json`, `results/v4/bench_wsl/summary.json` | `results/v4/h1/zkvm_mldsa.json` |

Sources (accessed 2026-09-29): (1) RISC Zero, Security Model, https://dev.risczero.com/api/security-model;
(2) fips204 crate 0.4.6, https://docs.rs/fips204/latest/fips204/; (3) RISC Zero install,
https://dev.risczero.com/api/zkvm/install.

## Not covered

- No revocation, issuance tree or ML-KEM session inside the zkVM; H1 is the signature-in-proof
  cost and the assumption change, not a replacement of v4.
- No GPU proving; no phone.

## Provenance note (2026-10-01)

- `results/v4/h1/zkvm_mldsa.json` (the six vFourZkvm* ledger keys) records neither the time of
  the measurement nor the code version: it has no timestamp and no sha256 of the guest, host or
  fixture code. `results/v4/h1/env.json` says "3 proving runs on 2026-09-29", a date without a
  time or zone.
- The only dating: commit 073ce8a (2026-09-29 19:09 IST, 13:39Z), which added the result, and the
  file mtime when audited (2026-09-29T13:37:54Z, 19:07 IST), an upper bound for the end of the
  runs. [S] The three proving times in the file sum to about 2,651 s, so the proving began no
  later than about 12:53Z (18:23 IST). Which guest, host and fixture code ran rests on commit
  073ce8a alone.
- For any future run, `stretch/h1/run_h1.sh` adds `startedUtc`, `finishedUtc` and a `provenance`
  block to `zkvm_mldsa.json`: the tool versions (rustc, cargo, cargo-risczero, r0vm, node) and the
  sha256 of `stretch/h1/run_h1.sh`, `stretch/h1/guest_main.rs`, `stretch/h1/host_main.rs`,
  `stretch/h1/make_fixture.mjs`, the host and guest `Cargo.toml` (cargo add rewrites them on every
  run), `results/v4/h1/fixture.json` and copies of the two Cargo.lock files. The lock files are
  gitignored in `stretch/h1/project`, so the script copies them to
  `results/v4/h1/project.Cargo.lock` (workspace: host and methods) and
  `results/v4/h1/guest.Cargo.lock` (the guest, which fixes the fips204 and risc0 versions), to be
  committed with the result. The committed result is unchanged. Source: the provenance audit
  (`results/v4/provenance/AUDIT.md`).
- Before the next timed H1 run, `run_h1.sh` still has to refuse while the D-034 markers exist
  (`results/v4/bench/RUNNING`, `results/v4/BUSY` in the Windows repository), hold RUNNING during
  the measurement and call Node 24.21.0 by its absolute nvm path (it uses `nvm use 24` now; Node
  only makes the fixture and writes the provenance block, so the timings do not depend on it).
