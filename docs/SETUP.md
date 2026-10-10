# Setup Guide

This guide gets the prototype from a fresh clone to a state where the tests,
benchmarks, and demo can run. For the exact commands that regenerate every
number in the paper, see [`../REPRODUCE.md`](../REPRODUCE.md); for a higher-level
map of what is reproducible, see [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md).

> **TL;DR (any OS, JS-only path):** `npm ci` then
> `npx vitest run tests/circuit.test.ts tests/determinism.test.ts tests/bench_env.test.ts`
> — these suites run against the **committed, SHA-256-pinned** circuit build,
> proving key, and powers-of-tau with no native toolchain. The remaining suites
> (`protocol`, `kyber` → liboqs bridge; `ledger_verifier` → Anvil) and the
> PQC/ZK timing tables need the native pieces (liboqs, rapidsnark, Anvil,
> PostgreSQL); see [`TESTING.md`](TESTING.md) for the per-suite prerequisites.

## 1. Pinned toolchain

| Component | Version |
|---|---|
| Node.js | 22.16.0 (see `.nvmrc`, `.tool-versions`) |
| Python | 3.11+ |
| Circom | 2.2.3 |
| snarkJS | 0.7.4 |
| circomlib / circomlibjs | 2.0.5 / 0.1.7 |
| rapidsnark | v0.0.8 (commit `81eddf1`) |
| GMP (static) | 6.3.0 |
| liboqs / liboqs-python | 0.15.0 |
| dilithium-py | 1.4.0 (E2E issuance only; excluded from timing tables) |
| Solidity / solc-js | 0.8.28 |
| Foundry (Anvil) | stable |
| PostgreSQL | 14+ (baseline measured on 18.4) |

The full pinned list, including the powers-of-tau and zkey SHA-256 pins, is in
[`../REPRODUCE.md`](../REPRODUCE.md).

## 2. Install JavaScript/TypeScript dependencies

```bash
npm ci      # exact, lockfile-pinned install (preferred for reproducibility)
# or: npm install
```

This installs the workspace packages (`@pqid/*`), snarkJS, circomlib(js),
ethers, solc-js, and `pg`. No build step is required — the project runs `.ts`
directly via `tsx`.

## 3. What ships pre-built (no native toolchain needed)

To let reviewers verify on any platform, this release **commits** the pinned,
reproducible artifacts:

- `circuits/build/credential_auth.r1cs`, `.sym`, and the WASM witness calculator
  (`circuits/build/credential_auth_js/`) + `circuits/build/circuit_info.json`
  (the measured 21,715-constraint count);
- `setup/out/credential_auth_final.zkey`, `verification_key.json`, and the
  exported `Groth16Verifier.sol`;
- `setup/pins.json` with the SHA-256 of the ptau, zkey, and vkey;
- the measured `results/*.json` and a committed `results/sample/` snapshot.

Their hashes are verified by `tests/determinism.test.ts`. The pinned
powers-of-tau (`setup/ptau/powersOfTau28_hez_final_15.ptau`, ~38 MB) is **also
committed** here for archival robustness, so the determinism pin-check runs
without a network fetch. Not committed: the platform-specific tool binaries
(see `tools/README.md`) and the 38 MB research SHA-3 r1cs (regenerated on
demand; its tiny JSON summary is committed).

## 4. Native toolchain (only for PQC + ZK timing tables and interop)

The PQC benchmarks (Table IV/V), the rapidsnark prover, the cross-implementation
interop test, and the PostgreSQL baseline (Table VI) require a native Linux
toolchain. Two supported paths:

### Path A — Windows 11 + WSL2 (the committed-results configuration)

```powershell
# build liboqs (generic + AVX2), static GMP 6.3.0, rapidsnark v0.0.8, python venv:
wsl -u root -e bash -c "tr -d '\r' < docker/provision-wsl.sh > /root/provision-wsl.sh && bash /root/provision-wsl.sh"
```

Artifacts land under `~/pqid-native` (`/root/pqid-native`). See
[`../REPRODUCE.md`](../REPRODUCE.md) §A for details.

### Path B — clean Linux host via Docker

```bash
docker build -f docker/Dockerfile.liboqs -t pqid/liboqs .
docker build -f docker/Dockerfile.native -t pqid/rapidsnark .
docker compose -f docker/docker-compose.yml up --build   # + Anvil + PostgreSQL
```

### CI reference

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) provisions the native
toolchain on a clean `ubuntu-24.04` runner (installs circom 2.2.3, builds
liboqs/GMP/rapidsnark via `docker/provision-wsl.sh`, then runs the full test
suite + interop + negative test). It is the canonical clean-host recipe.

## 5. Regenerate the trusted setup (optional)

```bash
npm run setup   # download_ptau -> build_circuit -> groth16_setup
# (Makefile `setup` target additionally runs research_sha3_report.ts)
```

`setup/download_ptau.ts` fetches and SHA-256-pins the powers-of-tau;
`setup/build_circuit.ts` compiles the circuit and records the real constraint
counts; `setup/groth16_setup.ts` runs a deterministic beacon phase-2 setup whose
zkey is byte-stable across rebuilds and re-pins the hash. A mismatch against
`setup/pins.json` aborts the run.

## 6. Sanity check

```bash
npm run build   # typecheck (tsc --noEmit)
npm run lint    # eslint
# JS-only suites (no native toolchain needed):
npx vitest run tests/circuit.test.ts tests/determinism.test.ts tests/bench_env.test.ts
# full suite (needs the liboqs bridge + Anvil — see TESTING.md):
npm test
npm run demo    # full lifecycle: register -> issue -> prove -> verify -> revoke -> reject
```

If the JS-only suites pass against the committed artifacts, your TypeScript/snarkJS
environment is correct. For the native-dependent suites and the timing tables,
continue with [`BENCHMARKS.md`](BENCHMARKS.md) and [`TESTING.md`](TESTING.md).
