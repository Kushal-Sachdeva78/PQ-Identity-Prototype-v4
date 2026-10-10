# Supplementary experiments

Run commands from the repository root after installing the root lockfile with
`npm ci`. The three directories retain the October 2026 observations, including
failed attempts. Fresh runs create new directories. They use the committed
development proof key and local Anvil registries.

## Privacy histories

Audit the preserved 78 calls without rerunning proofs:

```text
python 3.7/experiments/privacy/validate.py
```

The audit checks original digests against unchanged files or the explicit mappings
in `PUBLICATION_PROVENANCE.json`. Its new report is
`artifact/out/privacy_validation.json`; the historical `validation.json`, dates
and preregistration remain unchanged. A mapping passes only when both its original
digest and the actual current publication digest match.

Prepare current protocol and runner hashes, then run a new local series:

```text
node 3.7/experiments/privacy/prepare_publication.mjs
node node_modules/tsx/dist/cli.mjs --tsconfig 3.7/experiments/privacy/tsconfig.json 3.7/experiments/privacy/run.ts
```

Preparation writes `preregistration-publication.json` with its current timestamp.
The runner verifies that registration and writes the next unused `run-NN`
directory. The original registration describes the historical experiment. This
supplementary variant changes the date policy in an isolated wallet copy; it is
not an installed fix or independent testing.

## Rollback and stale registry views

Choose an unused attempt name; `attempt_001` contains the historical 11 cases:

```text
node node_modules/tsx/dist/cli.mjs --tsconfig 3.7/experiments/rollback/tsconfig.json 3.7/experiments/rollback/run.ts attempt_002
```

Anvil is selected by `PQID_ANVIL_BIN`, then `ANVIL_BIN`, then the platform default.
The runner hashes that selected executable. Authentic historic registry views are
expected to allow two stale-view presentations; those acceptances are recorded
limitations, not security successes.

## Native presentation timing

Use WSL2 with the experiment's Node 24.21.0 and Anvil 1.5.1 requirements and a
rapidsnark prover binary. Python 3 is needed by the metadata adapter. The launcher
uses the current repository and Node from `PATH`; set overrides for other paths:

```bash
export PQID_NATIVE_RAW=/absolute/path/to/rapidsnark/bin/prover
export PQID_ANVIL_BIN=/absolute/path/to/anvil
export PQID_NODE_BIN=/absolute/path/to/node
bash 3.7/experiments/native/run_wsl.sh typecheck
bash 3.7/experiments/native/run_wsl.sh preflight
bash 3.7/experiments/native/run_wsl.sh smoke
```

`PQID_WINDOWS_REPO` and `PQID_SOURCE_ROOT` optionally choose two checkouts. Their
source equality guard still checks byte equality or newline-only differences and
unchanged key pins. The `run` mode performs the prescribed settle, warmups and
30 measured blocks and requires AC power; avoid competing jobs. A fresh run
records its actual environment and current hashes separately from the retained
campaign. Timing is exploratory monotonic execution time with documented clock
discrepancies, local parties and simulated RPC delay.

The adapter's standard-library tests can run separately:

```text
python 3.7/experiments/native/test_adapter.py
```

`analysis_prespecified.py`, `analyze.py` and `audit.py` take a run directory and
write analysis files there. Use them on a copy when checking retained data so
historical summaries remain intact.
