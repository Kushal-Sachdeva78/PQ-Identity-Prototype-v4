# Reproducing the code and experiments

Run commands from the repository root. Validation checks the committed implementation and artifacts; measurement campaigns create new evidence and are not part of the default rebuild.

## Environment

The primary v4 validation environment is pinned in `artifact/toolchain.env`: Node 24.18.0, Circom 2.2.3, and Anvil 1.5.1. Node must expose ML-DSA-44 and ML-KEM-768 through OpenSSL 3.5. Python 3.11+ and Bash are needed for the rebuild scripts. The Python packages in `artifact/requirements.txt` support analysis and ML-DSA interoperability tests.

```bash
docker build -f artifact/Dockerfile -t pqid-publication .
docker run --rm pqid-publication bash artifact/rebuild.sh --full --no-install
```

The container installs the pinned dependencies and performs validation. It needs network access to build. It does not run timed campaigns, phone builds, or the supplementary WSL experiment. To retain its scratch reports on a POSIX host:

```bash
mkdir -p artifact/out
docker run --rm -v "$PWD/artifact/out:/work/artifact/out" \
  pqid-publication bash artifact/rebuild.sh --full --no-install
```

For a local installation, put `circom` and `anvil` on `PATH`; the source also recognizes the documented Windows binary locations. Create `.venv` and install `artifact/requirements.txt`. On Linux use `.venv/bin/python`; on Windows use `.venv/Scripts/python.exe`. The ML-DSA interoperability test skips when that repository-local environment is absent. Set `PQID_PYTHON` to the selected interpreter for the shell scripts. Git Bash can run the shell commands on Windows.

## Validation commands

```bash
bash artifact/rebuild.sh                  # install, integrity, typecheck, selected tests
bash artifact/rebuild.sh --no-install     # use existing node_modules
bash artifact/rebuild.sh --full           # also recompile, audit key, rerun security suite
python scripts/verify_artifacts.py        # setup/pins.json and setup/pins_v4.json
python scripts/verify_artifacts.py --manifest
npm run build
npx vitest run tests/v4
npx vitest run tests/circuit.test.ts tests/determinism.test.ts tests/circuit_v3.test.ts
```

`--quick` selects the default validation mode; `--ci` selects full validation. The full rebuild writes its new security-suite output under `artifact/out/suite/` and compares decisions by case and route with `results/v4/security_suite.json`. Timing and host metadata are excluded from that verdict comparison. The selected earlier suites avoid the inherited liboqs/PostgreSQL/WSL integration dependencies; `npm test` discovers additional inherited tests that may require them.

The committed ptau, compiled circuits, finalized proving keys, verification keys, and Solidity verifiers permit validation without first repeating setup. Default verification reads them and fails on pin differences. `setup/groth16_setup_v4.ts` audits the existing development key; its `--rekey` option creates a different key and is outside ordinary reproduction. Randomized Groth16 proof bytes need not match; their public signals and verification results must.

## New measurements and analysis

Read the relevant procedure before starting a campaign. Use a new campaign name, the stated environment, a quiet machine on AC power, and the procedure's fixed inputs and sample counts. Full campaign runners may require a clean committed Git checkout. Do not overlap campaigns or validation with a timed run.

| Experiment | Procedure | Entry points |
| --- | --- | --- |
| Circuit proving/verification | `docs/v4/BENCH_PROTOCOL.md` | `harness/v4/bench/`; `scripts/bench/analyze.py` |
| Comparable circuits and wallet rebuilds | `docs/v4/CMP.md` | `harness/v4/cmp/`; `scripts/cmp/analyze_cmp.py` |
| Registry reads | `docs/v4/CHAINREAD.md` | `scripts/chainread/`; `scripts/chainread/analyze.py` |
| Full presentation | `docs/v4/E2E.md` | `harness/v4/e2e/`; `scripts/e2e/analyze_e2e.py` |
| Load and fuzzing | `docs/v4/ROBUSTNESS.md` | `scripts/robustness/run_robustness.sh` |
| Phone integration | `docs/v4/PHONE_PROTOCOL.md` | `mobile/scripts/`, `mobile/mopro/`, `mobile/safari-fallback/` |

Native proving additionally requires a Linux rapidsnark executable selected by `PQID_RAPIDSNARK`. Besu experiments need their own configured node; phone native builds need macOS/Xcode; zkVM builds need the Rust/RISC Zero environment described under `stretch/`. Historical Windows and WSL series use different Node versions and CPU policies. The default container does not recreate every recorded host or the timing conditions of October 4–8 campaigns.

## Supplementary revision 3.7 experiments

Keep `3.7/experiments/` at its supplied relative location. Its runners resolve the repository by walking three parent directories.

The paired-history privacy experiment compares the shipped wallet with an isolated stateless variant. The rollback experiment tests authentic old epoch statements against current and deliberately stale local RPC views. They are diagnostic case series, separate from the frozen attack catalogue; neither is an independent holdout or a deployment benchmark.

```bash
# A fresh privacy registration must match the current protocol and isolated variant.
node 3.7/experiments/privacy/prepare_publication.mjs
node node_modules/tsx/dist/cli.mjs --tsconfig 3.7/experiments/privacy/tsconfig.json \
  3.7/experiments/privacy/run.ts

# Choose an unused attempt_NNN directory name.
node node_modules/tsx/dist/cli.mjs --tsconfig 3.7/experiments/rollback/tsconfig.json \
  3.7/experiments/rollback/run.ts attempt_002

python -m unittest discover -s 3.7/experiments/native -p test_adapter.py
bash 3.7/experiments/native/run_wsl.sh preflight
bash 3.7/experiments/native/run_wsl.sh smoke
# Only after successful preflight/smoke and the prescribed quiet window:
bash 3.7/experiments/native/run_wsl.sh run
```

The privacy runner enforces its registration hashes; an original pre-execution registration must not be represented as a registration for edited source. Consult `privacy/PROTOCOL.md` and its publication verification notes before preparing a fresh run. The saved-evidence validator checks original hashes through the explicit publication mapping and writes a new audit under artifact/out/. See [the supplementary guide](3.7/experiments/REPRODUCE.md).

The native wrapper describes the original WSL setup: Node 24.21.0, Anvil 1.5.1, matched Windows/WSL source copies, and a native rapidsnark installation. Configure its path variables for the local installation. Its runner deliberately enforces WSL and that Node version. The measured native path uses an experimental metadata adapter that adds the required `curve=bn128` label; adapter process and file costs are included. Earlier unadapted integration failures remain part of the evidence.

For statistical reanalysis, copy a completed native campaign into a scratch directory before running the analyzer, because it writes new summary files:

```bash
cp -R 3.7/experiments/native/runs/<completed-run> artifact/out/native-reanalysis
python 3.7/experiments/native/analyze.py artifact/out/native-reanalysis
python 3.7/experiments/native/audit.py artifact/out/native-reanalysis
```

Historical hashes describe the original experiment snapshot. Publication comment and metadata normalization may differ, while measurements remain unchanged. Setup pins identify the unchanged cryptographic artifacts; `MANIFEST.sha256.tsv` pins the publication files. A new timing run produces new host-dependent results and is not expected to reproduce every historical decimal exactly.
