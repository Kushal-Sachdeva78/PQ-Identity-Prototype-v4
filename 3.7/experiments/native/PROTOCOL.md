# Version 3.7 exploratory native presentation and RPC-delay experiment

Prespecified 2026-10-06; implementation revised 2026-10-08 IST, before any measured iteration. This is a new Tier 2
follow-up, not a replacement for the original C5 criterion or the frozen Phase D
campaigns. All proofs use the existing pinned **development key**. No ceremony
claim is made.

## Question and scope

Measure a complete accepted presentation using rapidsnark with the isolated
experimental metadata adapter described below, and compare it with shipped
snarkJS on the same WSL installation. Measure
sensitivity to deterministic artificial RPC delay. Both parties and Anvil run on
one laptop; parties share one Node process. This is **loopback, same host, simulated
network delay**, not a remote-endpoint or second-device experiment.

The unchanged `harness/v4/e2e/presentation.ts` engine times verifier request through
wallet checks, ML-KEM, witness and proof, sealing, transport serialization, registry
reads, and the final verifier decision (S1-S11). Setup, issuance, epoch publication,
blob load/tree reconstruction and party construction are untimed and recorded
separately. Wallet-verifier network transport is not simulated.

## Conditions and schedule

- WSL2 Ubuntu on the existing laptop; Node 24.21.0; Anvil 1.5.1; existing native
  rapidsnark binary; snarkJS 0.7.4. Binary and source SHA-256 values are recorded.
- One loopback Anvil, freshly deployed registries, one issuer, eight credentials,
  one published epoch, one registered verifier, `age_gte 18`, as in the existing
  e2e setup. The selected holder and credential are identical in every condition.
- Six instrumented conditions: prover {snarkJS, rapidsnark} crossed with {0, 20, 50}
  ms added per HTTP POST. Two additional uninstrumented controls: each prover at
  0 ms. Each block contains all eight conditions once.
- Five complete warm-up blocks, followed by 30 measured blocks. The fixed n is a
  bounded exploratory repeatability series; it does not estimate across-device or
  across-day variation. No cold/first-use claim is made.
- Fisher-Yates order from mulberry32 seed 20261031, with canonical condition order
  fixed in code; the complete schedule is saved before setup and before timing.
- A 600 s settle after setup and before warmups. No app builds/tests/analyses or
  competing agent jobs during the settle and series. Power readings before and
  after every block must report AC. The WSL quiet check is recorded for every
  block; it cannot observe Windows load. This limitation remains explicit.
- Each prover has its own long-lived wallet/verifier instances, with chain IDs
  and process state warmed. Before each iteration both party HTTP agents are
  replaced, as in the existing e2e protocol. No client batch/cache option changes.

## Delay intervention and checks

An experimental loopback HTTP proxy forwards every JSON-RPC body byte-for-byte
to Anvil with a dedicated keep-alive upstream agent. After receiving the complete
upstream response, it waits the selected delay once before releasing that
response. A JSON-RPC batch is one POST and receives one delay. The proxy does not
inspect or modify the RPC operation or result. This models added response latency,
not a WAN: no jitter, bandwidth constraint, loss, TLS, provider cache, distributed
consensus or remote load is introduced. The 0 ms condition uses the same proxy.

Every iteration saves the proxy POST count, requested delay and actual timer wait
durations. Instrumented iterations must match proxy and tracer POST counts. All
conditions must give acceptance with no failed or unevaluated checks. Public
signals other than the per-session nonce must equal the first honest presentation.
The stage sum must equal total time to within 0.05 ms. Public-signal values, proofs,
credentials, role secrets and witnesses are not written to results.

rapidsnark is invoked by the unchanged `proveV4` native backend through the isolated
experimental `native_adapter.py` executable. This adapter runs the real native
binary, requires exactly its expected proof keys and `protocol=groth16`, and adds
`curve=bn128` only when absent. A conflicting curve or any other unexpected key
causes failure. Coordinates and the public-signals file are unchanged; the normal
wallet shape check and full verifier still run. Interpreter startup and the
adapter's extra subprocess/file work are included. Native rows are explicitly
**experimental adapter, not shipped**. Witness calculation,
temporary witness/proof file I/O, subprocess startup/proving, key/witness hashes
and wallet shape checks are included in S8. Temporary files live in this run's
isolated Linux temporary directory and are deleted by the shipped prover. No
sum of separately measured medians is presented as a full trace.

## Error and reporting rules

- Keep every attempted block. On an iteration failure, non-AC reading, or a wall
  versus monotonic block clock gap over 2 s, retain the attempted block as excluded
  and repeat the entire block once. A second failure stops the campaign; no
  incomplete series is represented as n=30. Never drop a slow valid measurement.
- A quiet-check failure is retained and flagged, with a sensitivity analysis
  excluding flagged blocks. Do not silently repeat a block merely because slow.
- Smoke validation (one block, zero settle, no headline timing) has separate output
  and is never pooled with measured results.
- Report n, median, Q1, Q3, IQR, p95, range and percentile bootstrap 95% interval for
  total presentation and each stage (type-7 quantiles; B=10,000; seed 20260927).
- Comparisons resample whole paired blocks: snarkJS/native ratio of medians at
  each delay; delay minus 0 ms median difference for each prover; instrumentation
  ratio at 0 ms. Report the simulation intervention separately from measured
  elapsed time. Report measured counts and errors explicitly.
- Original C5 still reports its original cold snarkJS failure. These are warm,
  development-key, instrumented exploratory results, under different conditions.
- No writes to frozen results, packages, setup keys or earlier document versions. Windows/WSL source equality is checked before running, sources
  and pins are hashed again after running. No git commits or external transactions.

## Run records

`run_wsl.sh smoke` validates the implementation; `run_wsl.sh run` requires the
coordinating agent's exclusive quiet interval. Outputs are appended only into a
new `3.7/experiments/native/runs/<UTC>-<mode>/` folder. `analyze.py` is run only after
the series and timing marker are released. A local `RUNNING` marker coordinates
this follow-up; the parent also enforces repository-wide benchmark exclusivity.

## Deviations

Before smoke validation on 2026-10-07 IST, preflight found CRLF/LF differences in
Windows versus WSL text files. Source equality requires identical content after
CRLF-to-LF conversion only; both raw hashes and every newline-only difference are
recorded. Circuit/key artifacts must remain byte-identical to their frozen pins.
No source or existing clone file is rewritten. Future changes must be written here
before the affected run.

Smoke validation started 2026-10-07 IST and retained at
`runs/2026-10-06T22-30-02-836Z-smoke/` found the unchanged native integration failed
the wallet's strict proof schema twice. On 2026-10-08 IST the experimental metadata
adapter was added before any measured run. The failure is itself an integration
result and remains reportable; the later variant must not be called a passed
shipped-native path. The adapter records only its input/output key names and action,
never witness material or proof coordinates.
