# harness

Headless runners and the report generator. Every output is measured at runtime
and written to `results/*.json`; `generate_results.ts` maps each value to its
paper-table cell in `RESULTS.md`.

| Script | Output | Purpose |
|---|---|---|
| `bench_pqc.ts` | `results/pqc.json`, `pqc_avx2.json` | Table IV (liboqs ML-DSA-44 + ML-KEM-512, N=1000) |
| `bench_zk.ts` | `results/zk.json` | Table V (Groth16 dual prover on byte-identical zkey+witness) |
| `e2e.ts` | `results/e2e.json` | full positive lifecycle |
| `negative_test.ts` | `results/negative.json` | **required** negative test (revoked ⇒ no accepted proof) |
| `malicious_wallet_probe.ts` | `results/malicious_probe.json` | Assumption-5 demonstration |
| `generate_results.ts` | `RESULTS.md` | regenerate the mapped tables + Divergences |
| `e2e_core.ts`, `fixture.ts` | — | shared lifecycle + deterministic fixtures |
| `rapidsnark_bench.sh` | — | WSL-internal rapidsnark timing loop (subprocess wall time) |

`bench_zk.ts` reports rapidsnark two ways: the primary like-for-like pipeline (`/mnt/c` files)
and a WSL-native-fs variant that bounds the 9p file-I/O share — both on the same SHA-256-verified
inputs. Lower N for smoke runs via `PQID_ZK_SNARKJS_N`, `PQID_ZK_RAPIDSNARK_N`, `PQID_ZK_WARMUP`.
