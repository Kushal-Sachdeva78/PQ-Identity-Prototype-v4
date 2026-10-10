# Native experiment validation

Prepared 2026-10-06 to 2026-10-08 IST, before the measured campaign.

- Source preflight passed: 73 source/artifact records match Windows and WSL
  byte-for-byte or solely after recorded CRLF-to-LF normalization. All six frozen
  v4 artifact pins match exactly.
- WSL TypeScript `--noEmit` check passed for the runner and imported modules.
  The initial Windows typecheck could not resolve this copy's existing workspace
  junctions; no Windows package or `node_modules` file was repaired or changed.
- Unadapted native integration smoke failed twice at the wallet's strict proof
  schema. The failures are retained in
  `runs/2026-10-06T22-30-02-836Z-smoke/blocks.jsonl`. rapidsnark emits
  `pi_a`, `pi_b`, `pi_c`, `protocol`, but the verifier requires `curve` as well.
- The experimental adapter adds only `curve=bn128` for the pinned BN254 circuit.
  Six tests pass: coordinate/public-file preservation; already-correct metadata;
  rejection of wrong curve, wrong protocol, unexpected keys, and native failure.
- Adapted smoke passed all eight conditions at
  `runs/2026-10-07T21-50-29-454Z-smoke/`. Every verifier accepted, all non-nonce
  public signals matched, each trace/proxy POST count matched, and stage totals
  matched presentation time. Source/pin hashes were unchanged afterward; zero
  temporary witness files remained. Both power readings reported AC.
- Smoke observations are implementation checks only and are excluded from all
  latency tables. No measured campaign was started during this validation.

The measured native path must be labelled **experimental metadata adapter, not
shipped**. Its time includes Python interpreter startup and the adapter's native
subprocess and file work. The integration failure must remain visible alongside
the later variant's performance.
