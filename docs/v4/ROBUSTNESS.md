# Robustness: load test and fuzzing (protocol and pre-registration)

Protocol for the work-table row "Check robustness" (DECISIONS D-034). It covers the timed load
test "verifier library under concurrent load" and the untimed fuzzing of every untrusted-input
entry point of `packages/v4`, of the frozen v4 circuit and of the v4 registries. It extends
`docs/v4/BENCH_PROTOCOL.md` (a dated pointer is appended under its Deviations) and reuses its
rules where this file says so. Written 2026-10-03, before any non-smoke run. Facts, rules and
commands only. Labels: [M] measured, [S] estimate from the stated arithmetic, [A] assumption.

- Every runner records the SHA-256 of this file above the "## Deviations" heading (LF line
  ends; `protocol.robustness.normative` in `env.json` or `plan.json`) and of the whole file; the
  load runner also records the BENCH_PROTOCOL hashes. Deviations are appended to the last
  section, dated, before the affected run. Changing a level in this file changes the normative
  hash and needs a new campaign.
- A full (non-smoke) run of any runner refuses to start unless this file, the harness, its
  helpers, the drivers, the forge tests and configuration and the code under test are committed
  and unchanged against HEAD (`common.ts` `assertCommitted`: read-only `git ls-files
  --error-unmatch`, `git status --porcelain --untracked-files=all` and `git diff --quiet HEAD`
  over `COMMITTED_PATHS`, with GIT_OPTIONAL_LOCKS=0). The result (`gitClean`, the checked paths,
  any problems) is recorded in `env.json` and `plan.json`. Smoke runs record it and do not refuse.
- Full runs use the budgets and levels of this file. A full fuzz, circuit or forge run with
  another budget refuses to start unless `--deviation "<text>"` is given; the text goes into
  `plan.json` and must be appended, dated, under Deviations before the run. The load test accepts
  no level override outside smoke runs.
- Nothing in `packages/`, `circuits/`, `setup/`, `onchain/contracts/`, the frozen harnesses
  (`harness/v4/scale.ts`, `harness/v4/bench/`, `harness/v4/security_suite.ts`, ...) or any v2/v3
  file changes. Existing helpers are imported read-only (`harness/v4/scale_lib.ts`,
  `harness/v4/bench/lib.ts`, `guard.ts`, `harness/v4/r1cs_tools.ts`, `harness/v4/lib/`).
- Load-test and fuzz results never enter the attack-matrix counts.
- Smoke output (`results/v4/robustness/_smoke/`) is never quoted and never enters the ledger.

## 1. Purpose

E4 measured the verifier one presentation at a time in one process (`results/v4/scale/verifier.json`).
Concurrency, latency percentiles under load, error rate under load, the cost of hostile replies,
the session-store limit and exactly-once under load were not measured. Hostile input was tested
by example only (security suite, `tests/v4/*`); nothing generated inputs, and the randomised IMT
tests are unseeded. This row adds both.

Code-reading hypotheses, stated before the data and reported whatever the runs show (they are
hypotheses, not findings, until a full campaign records them):

- HP1: `presentationShapeError` (verifier.ts), `parseField` (imt.ts) and `decStr` (witness.ts) call
  `BigInt` on decimal strings of unbounded length; a sealed 1 MiB presentation can carry about a
  million digits (load class HC6; fuzz targets T-pres-shape and T-witness).
- HP2: `parsePublication` does not require the blob to be fully consumed, does not check the depth
  byte against ISSUANCE_DEPTH, accepts leaves >= p and can surface out-of-bounds reads as
  TypeError or RangeError (fuzz target T-pub).
- HP3: `credTypeField` encodes typeIds with TextEncoder, so typeIds that differ only in lone
  surrogates map to the same field element (fuzz target T-encoding).

## 2. Files

| File | Role |
|---|---|
| `harness/v4/robustness/load.ts` | load runner (parent): chain, pool, hostile replies, schedule, blocks, saturation |
| `harness/v4/robustness/load_worker.ts`, `load_worker_boot.mjs` | one verifier replica per worker thread; the bootstrap registers tsx and loads web-worker in its main-thread form (section 3.5) |
| `harness/v4/robustness/load_lib.ts` | levels, cells, schedule, rotation, closed loop, pass rates, expected hostile checks, clock watch |
| `harness/v4/robustness/hostile.ts` | hostile replies HC1 to HC7 |
| `harness/v4/robustness/fuzz.ts` | fuzz runner (one child process per target, watchdog, records, replay) |
| `harness/v4/robustness/fuzz_targets.ts`, `fuzz_chain.ts` | pure and chain-backed targets |
| `harness/v4/robustness/rng.ts`, `mutators.ts`, `valid_gen.ts`, `typed_json.ts`, `fuzz_types.ts` | in-repo seeded generator, mutation operators, valid-object generators, failure encoding |
| `harness/v4/robustness/common.ts` | results roots, protocol hash, commit check, budget deviations |
| `harness/v4/robustness/oracles.ts` | independent references and the JS model of relation R4 |
| `harness/v4/robustness/coverage.ts` | line and function coverage from NODE_V8_COVERAGE |
| `harness/v4/robustness/circuit_fuzz.ts` | bounded circuit and witness fuzz |
| `harness/v4/robustness/forge_fuzz.ts` | driver of the forge fuzz and invariant tests |
| `onchain/test/v4/RegistriesV4.fuzz.t.sol`, `onchain/foundry.toml` | forge tests of `onchain/contracts/v4/RegistriesV4.sol` (contracts unchanged) |
| `scripts/robustness/solcjs_shim.cjs`, `solc_shim.cmd`, `solc_shim.sh` | solc command-line shim over the repository's solc-js 0.8.28 for forge |
| `scripts/robustness/run_robustness.sh`, `scrub_log.py` | drivers: `fuzz`, `load`, `smoke`; log scrubbing (fails closed) |
| `scripts/robustness/analyze_load.py`, `summarize.py` | load statistics (numpy) and the results index |
| `tests/v4/robustness_*.test.ts`, `scripts/robustness/test_analyze_load.py`, `test_scrub_log.py` | unit tests; `robustness_properties.test.ts` runs every pure target at a small fixed budget on every test run |
| `results/v4/robustness/` | results root (D-034); `_smoke/` is gitignored |

## 3. Load test: verifier library under concurrent load

### 3.1 What it measures

`VerifierV4.verifyReply` called on reply wire bytes (UTF-8 JSON, so parsing is included) by
several verifier replicas in worker threads of one process, against one local Anvil. It is a
library-level, closed-loop test: no HTTP front end, no network beyond loopback, one node with
automine. Each worker is an independent replica with its own session store (sticky load
balancing); exactly-once across replicas is not modelled (a horizontally scaled verifier would
need a shared atomic consume).

### 3.2 Environment

- One OS per results root. Primary: the native Windows 11 host, unpinned (D-021) and labelled
  unpinned, Node 24.18.0, `tools/foundry/anvil.exe` 1.5.1 (the E4 toolchain).
- Optional WSL2 replicate in its own campaign, with the D-034 WSL toolchain (Node 24.21.0 by its
  absolute nvm path, Anvil 1.5.1 from the pqid-v4 Docker image), analysed on its own; any
  comparison across the two is labelled cross-environment (D-032). On Linux the driver requires
  `PQID_NODE` (the Node binary) and `PQID_ANVIL_DIR` (the directory of that Anvil, put first on
  PATH, so `packages/ledger` startAnvil finds it; packages unchanged) and `PQID_WINDOWS_REPO`
  for the marker. The clone must first be brought to the committed state of this row.
- Toolchain checks: the driver checks Node and Anvil of its OS before a full fuzz or load step,
  and `load.ts` refuses a full run itself unless `process.version` and `anvil --version` (the
  binary startAnvil uses) match the toolchain of its OS (win32: v24.18.0 and 1.5.1; linux:
  v24.21.0 and 1.5.1). Both versions are recorded in `env.json` (`toolchain`).
- The analyses need python3 with numpy (`PQID_PYTHON` may name the interpreter). Ubuntu 24.04 in
  WSL has no system numpy, so a WSL campaign is analysed on the Windows host or in a user-space
  environment that has numpy.
- Recorded in `env.json`: host facts from `envInfo` (no user, host or home path), Node, OpenSSL,
  V8, ethers, snarkjs and Anvil versions, git HEAD and the commit check, SHA-256 of the harness
  and of the code under test (`packages/v4/src`, `RegistriesV4.sol`, the dev vkey), the vkey
  checked against `setup/pins_v4.json` (key label dev), both protocol hashes, the clock-gap
  rule, the marker record.

### 3.3 Chain and clients

- The runner starts its own Anvil on 127.0.0.1:8780 (D-034), automine, fresh deployment through
  `worldOnRpc`: 1 issuer, H holders (birth dates 19900101 + h), one anchored epoch, one verifier V.
  Network label: "loopback, same host" (D-034).
- asShipped: `LedgerV4.connect` as committed (ethers 6.13.4 default batching, no staticNetwork),
  traced for counts with `harness/v4/lib/rpc_trace.ts` (one POST = one `_send`).
- cachedReads: `harness/v4/scale_lib.ts` cachedLedger over a second traced `LedgerV4.connect`. It
  is a harness read cache, "variant, not shipped"; its numbers are never reported as verifier
  capacity. No other client variant.
- If the chain-read row later changes the shipped client, the asShipped cells need a new campaign.

### 3.4 Levels (pre-registered)

| Item | Level |
|---|---|
| Pool | P = 400 honest replies from H = 4 holders; policy age_gte 18, default credential type |
| Throughput cells | variant {asShipped, cachedReads} x active workers W {1, 2, 4, 6} x in-flight per worker c {1, 4, 16} (24 cells); R = 160 replies per active worker per pass |
| Hostile-cost cells | classes HC0 to HC7 x variant, W = 1, c = 1, 40 items per class per block (16 cells); HC6 and HC7 use 8 distinct replies, cycled |
| Correctness batch | once per block, asShipped, W = 6, c = 16; per worker: 8 honest replies, 2 duplicate groups of 2 to 4 copies, one reply of each class HC1 to HC7, 2 target sessions each with 4 hostile replies sealed into that session (tampered box, another session's presentation, garbage proof, non-canonical plaintext); then the targets' honest replies |
| Blocks | 600 s settle, 1 warm-up block (not analysed), 8 measured blocks; every block runs all 41 cells once; at most 5 attempts per block |
| Saturation | once, after the blocks and after the workers are stopped: `newRequest` until the package default cap of 100,000 sessions |
| Per-request timeout | 30 s; a call that times out may run 120 s longer before its worker is replaced |

### 3.5 Workers

- A persistent pool of 6 worker threads, started untimed before the settle. Each receives the
  pool's wire bytes, the hostile replies, the session snapshot and V's public identity and ML-KEM
  key pair in memory (the private key as a cloned KeyObject); nothing secret is written or logged.
- Each worker builds the asShipped and cachedReads verifiers on a ManualClock fixed at the
  parent's clock (no session expires) and one session store loaded with the snapshot. After every
  pass it restores the snapshot (untimed), so every pass verifies fresh sessions. Before the
  restore it waits up to 120 s for calls that outlived their 30 s timeout (they keep running in
  the background and could otherwise consume a session of the next pass) and records how many
  settled (`lateSettled`); a call still running after that makes the worker report a fatal error,
  and the parent replaces it (section 3.9).
- Run-time fixes, packages and node_modules unchanged (`load_worker_boot.mjs`): Node does not apply
  the parent's tsx loader to worker threads, so the bootstrap registers tsx; and the web-worker
  package that ffjavascript (snarkjs) uses for its bn128 thread pool takes its pool-thread branch
  in any worker thread, which made every Groth16 verification throw in the first smoke run. The
  bootstrap loads web-worker once while `isMainThread` reads true. So each worker builds its own
  bn128 thread pool, as a separate verifier process would; threads are oversubscribed at W > 1.
- First verification: after the workers report ready and before the settle, each worker in turn
  verifies one honest reply outside every correctness batch (asShipped, c = 1) and restores its
  sessions; the time is stored once in `aux.json` as `firstVerificationInWorker` (ms, variant,
  outcome). It is not analysed as a series and never compared with Phase D cold. A replacement
  worker (section 3.9) records its own under `replacements`.
- On Linux the runner records the process thread count and Anvil CPU ticks per pass; on Windows
  neither (host rule D-021).

### 3.6 Hostile classes

The harness acts as a wallet: it opens its own sessions (`walletOpenSession` against V's
registered KEM key) or uses an honest session's secrets captured in memory while the holder's
wallet presented (a wrapper around `node:crypto.encapsulate` during pool generation only).
Re-sealing under an honest session reuses an AES-GCM key and IV: acceptable in a test harness only.

| Class | Reply | Expected failedChecks (exact set) |
|---|---|---|
| HC0 | honest reply (reference) | none (accepted) |
| HC1 | bytes that are not JSON | transcriptDecrypts (malformed, after the session lookup) |
| HC2 | well-formed reply for an unknown session | sessionKnown |
| HC3 | harness session, one bit of the box flipped (AES-GCM fails after ML-KEM decapsulation) | transcriptDecrypts |
| HC4 | harness session, valid seal, an honest presentation of another session (wrong nonce signal): every check runs, with chain reads and Groth16 (D-022) | nonceBinding |
| HC5 | valid seal in the honest session the presentation was proved for (a pool reply outside every correctness batch), that presentation with in-range random proof coordinates: only Groth16 fails | groth16 |
| HC6 | harness session, valid seal, public signal 0 replaced by a decimal string sized so the plaintext is just under 1 MiB (HP1) | shape |
| HC7 | harness session, valid seal, a wide JSON object just under 1 MiB with keys out of canonical order | transcriptDecrypts (malformed) |

An untimed pre-pass checks that V accepts all P honest replies, that every distinct hostile reply
and every correctness item is rejected with exactly its registered failedChecks set (correctness
items: tampered box and non-canonical plaintext transcriptDecrypts, another session's presentation
nonceBinding, garbage proof groth16), and that all P honest replies are still accepted afterwards
(rejected replies consume nothing). Any other result stops the campaign before the first block;
the observed sets are written to `inputs/hostile.json`. The sessions are then restored.

### 3.7 What is timed

- Per request: from just before `verifyReply(bytes)` to its resolution (`process.hrtime.bigint()`,
  one monotonic clock for all threads), ms.
- Per pass: barrier release (a SharedArrayBuffer and Atomics release all active workers
  together) to the last completion; steady-state rate over the window between the 10th and 90th
  percentile completion times t10 and t90 of all workers merged: the K completions in the window
  span K - 1 intervals, so the rate is (K - 1) / (t90 - t10).
- Saturation: the fill from the first `newRequest` to the refused one (n = 1).
- Clock record: every block, every pass and the saturation fill record the monotonic and wall
  clocks at start and end, their gap and the longest gap between two 100 ms ticks of the
  parent's event loop (`clock`).
- Not timed: pool generation, pre-pass, worker start, first verification (recorded once, section
  3.5), session restore, drain and replacement warm-up, power and quiet readings, analysis.

### 3.8 Randomisation

Seed robustness.load 20261021 (D-034). Blocked design: every block holds every cell once; the
order within a block is a Fisher-Yates shuffle driven by one mulberry32 stream
(`harness/v4/bench/lib.ts`), block after block; the same stream then draws each worker's pool
rotation offset for the block. `schedule.json` is written before the first block. The
correctness batch order comes from the in-repo generator seeded from the same seed.

### 3.9 Power, quiet machine, markers, errors

- A full campaign holds `results/v4/bench/RUNNING` for its whole length (`markers.ts run --kind
  RUNNING` in the driver; the runner refuses while RUNNING or BUSY exists). The docs/BENCHMARK_POLICY.md quiet
  rule applies.
- Before each block: power (`guard.ts` readPower) and a 3 s quiet reading
  (`harness/v4/lib/quiesce.ts`, own Anvil excluded). Busy: postpone in 60 s steps up to 10 times,
  then run and flag the block. Non-AC before a block: wait 60 s; 36 consecutive non-AC readings
  stop the campaign. Non-AC after a block: its records are kept with status `discarded-battery`
  and the block is repeated after 60 s.
- Clock gap: a block whose wall-clock and monotonic elapsed times differ by more than 1,000 ms
  (a host suspend or a clock step), or during which the parent's event loop missed its 100 ms
  tick for more than 5,000 ms (a stall), is kept with status `discarded-clock-gap` and repeated
  after 60 s, like a battery discard. A block not completed in 5 attempts stops the campaign.
- Per-request errors: an honest reply not accepted (a rejection, an exception, a timeout) or a
  hostile reply without its registered rejection is an error item. Error items are counted in the
  error rates and listed (outcome and time) in the summary, are never latency samples, and leave
  the block status `ok`.
- Error blocks: a pass-level failure (a worker that exits or reports an error, does not report
  ready for the barrier within 120 s, or does not return its pass result within the pass's time
  bound) makes the block an error block: its records are kept with status `error`. Before
  anything else runs, the parent drains the workers: each live worker must answer a ping queued
  behind its current work within 120 s; a worker that is dead or does not answer is terminated
  and replaced. A replacement worker makes
  its first verification (section 3.5) and one pass of R replies at c = 1 per variant
  (`blocks.jsonl` records `replacementWarmup`, never analysed); the repeated block's record lists
  `replacedWorkers`. The block is then repeated once; 3 error blocks stop the campaign.
- No resume: a stopped campaign is rerun under a new name.
- Saturation: the workers are stopped first (`workersStoppedBefore`); power and a quiet reading
  are taken as before a block (postponed when busy, flagged when still busy); on non-AC power the
  fill is not timed (status `discarded-battery`); the fill is watched for a clock gap (status
  `discarded-clock-gap` when one occurs). `saturation.json` holds the power, quiet and clock
  records with the result (n = 1).

### 3.10 Statistics (`scripts/robustness/analyze_load.py`, numpy only)

- Rows used: measured blocks with status ok. Discarded (`discarded-battery`,
  `discarded-clock-gap`) and error blocks and replacement warm-up passes are counted, never
  analysed.
- Latency statistics use only items with the expected outcome: `accepted` for throughput cells
  and HC0; the registered rejection (`rejected:<first failed check>`, section 3.6) for each
  hostile class. Other items are error items (section 3.9), reported as `errorItems` (count,
  outcomes, times), never in a quantile.
- Latency per cell: n, median, Q1, Q3, p95, p99 (type-7), min, max; cluster-bootstrap 95% CIs over
  blocks for the median, p95 and p99.
- Throughput: median over blocks of the steady-state rate, bootstrap CI over blocks.
- Scaling: speedup(W) = median rate(W) / median rate(1) per (variant, c), paired block bootstrap;
  efficiency = speedup / W. Labelled: per-worker bn128 thread pools on unpinned hybrid cores, not
  clean multi-core scaling.
- POSTs and requests per verification (counts); at c > 1 they include ethers JSON-RPC batching
  across concurrent verifications in one worker (labelled). Error rates with an exact
  Clopper-Pearson 95% interval (an upper bound when there are no errors): per cell, over the
  throughput cells (`errorsThroughputCells`) and over every honest reply sent (`errorsAllHonest`:
  throughput cells, HC0 and the honest items of the correctness batch; duplicate copies excluded).
- Hostile cost per class and variant: latency, POSTs and requests per item, unexpected outcomes,
  amplification = the median over blocks of the class's per-block median latency divided by the
  same for HC0, with a paired block bootstrap CI; ratios are printed to 3 significant figures.
- Correctness: required values, every block: exactly 1 accepted copy per duplicate group (a copy
  that is not accepted must be rejected as a used session, sessionFresh or sessionKnown); 0
  misclassified items (an honest reply not accepted, a hostile reply accepted or ending in an
  exception or timeout); 0 consumed sessions among those that phase A's rejected replies name (the
  target sessions and the sessions of the batch's HC3 to HC7 replies); every honest reply sent
  after hostile replies on its session accepted.
- Bootstrap: B = 10,000, seed 20260927, one stream per statistic (`default_rng([seed, crc32(id)])`).
- The analysis refuses to run while `results/v4/bench/RUNNING` or `results/v4/BUSY` exists.

### 3.11 Outputs

`results/v4/robustness/load/<campaign>/`: `schedule.json`, `env.json`, `inputs/pool.json` (hashes
and public signals of every reply), `inputs/presentations.jsonl` (decrypted presentations: public
data), `inputs/hostile.json` (sizes, hashes, expected and observed failedChecks), `aux.json`
(first verification per worker), `runs.jsonl` (per block, cell and worker: latency, start and end
arrays, outcomes, counts, event-loop figures, late settlements; one pass line per cell with its
clock record), `hostile.jsonl`, `correctness.jsonl`, `blocks.jsonl` (block records and
replacement warm-ups), `saturation.json`; written by the analysis: `summary.json`, `summary.md`.
The reply bytes cannot be replayed after the run (the keys lived in memory only);
reproducibility comes from the script, the seed and the hashes.

### 3.12 Smoke

`load.ts --smoke`: P = 12, H = 2, R = 8, W {1, 2}, c {1, 4}, 3 items per hostile class, 1 + 1
blocks, 5 s settle, saturation cap 2,000 (not the package default), no marker (refuses while one
exists), output under `results/v4/robustness/_smoke/load/`. Never quoted. Two smoke-only checks
exist and are recorded in `env.json`: `--inject-fault worker-exit` makes the last worker exit at
the start of block 1 (error block, drain, replacement, warm-up, repeat) and `--timeout-ms <ms>`
shortens the per-request timeout (timeouts, late settlement, error items).

### 3.13 Duration [S]

About 60 to 90 min: settle 10 min; pool generation about 12 min (400 proofs at about 1.75 s, the
smoke run's per-proof time on this host, which is not a result); pre-pass about 2 min (800 honest
and about 200 hostile verifications); first verifications about 1 min; 9 blocks of about 4 to 7
min (24 throughput cells, mostly R x E4's 125 ms at c = 1, shorter at c > 1; 16 hostile cells of
40 items; the correctness batch); saturation about 1 min. Stop rule: if the warm-up block takes
more than 15 min, stop and record a deviation before rerunning.

### 3.14 Known limits [A]

Closed loop; library-level calls with no HTTP front end; one local Anvil with automine; per-worker
session stores (no exactly-once across replicas); cache staleness not modelled; hybrid cores and
no pinning on Windows; one bn128 thread pool per worker thread; the asShipped client is traced
(a wrapper per request); dev key.

## 4. Fuzzing of the package entry points (untimed)

### 4.1 Generator and seeds

- In-repo seeded generator (D-034: no property-testing package): sfc32 seeded by splitmix32
  (`rng.ts`), mutation operators at byte, string, JSON-text and value level (`mutators.ts`),
  generators of valid protocol objects (`valid_gen.ts`). No shrinking.
- Master seed robustness.fuzz 20261022. Target seed = (master XOR crc32(target id)) >>> 0; case i
  draws from its own stream `caseSeed(targetSeed, i)`, so any case regenerates from (seed,
  target, index) alone. Budgets are case counts.
- Each target runs in its own child process (the chain targets together). A watchdog records a
  hang when no progress line arrives for 120 s and stops a target at 90 min ("interrupted at N").
  The child announces each case before running it for every chain-target case, the first 200
  cases of a pure target and every case of a pure target whose median call time exceeds 100 ms;
  a hang is then saved as `failures/<target>/hang_<index>.json` with the case regenerated in the
  parent from (seed, target, index) (for a fast pure target past case 200: `hang_after_<n>.json`
  naming the last completed case). When the watchdog stops the chain child, or the child exits
  with an error, the parent also stops the child's Anvil (the child reports its process id) and
  checks that port 8781 is free; if it is not, the campaign stops.
- Budgets and watchdog settings (scale 1, 120 s, 90 min) are pre-registered; another value in a
  full run needs `--deviation` (header of this file).

### 4.2 Targets and budgets

| Target | Entry points | Property (full text in the target and in `plan.json`) | Budget |
|---|---|---|---|
| T-dates | isValidYmd, utcDateOf, unixOfUtcDate, addDays, acceptableTodays, predicateHolds, ageOn | equal to an integer civil-calendar reference with the D-010 29 February rule; acceptableTodays never holds a future date | 200,000 |
| T-encoding | credTypeField, fieldFrom31Bytes, policyHashV4, revKeyFromCredId, fieldDec | outputs below p, revKey below 2^251 by the limb formula, documented Error exactly on bad input; lone-surrogate collisions recorded (HP3) | 100,000 |
| T-stmt-json | validateStatement, statementBytes, tryParseStatement, parseStatement, detachSignature | accepts exactly what the reference accepts (4 types); canonical round trip; no cross-type acceptance | 100,000 |
| T-stmt-bytes | tryParseStatement, parseStatement | accepts exactly strict UTF-8, valid, canonical bytes; parseStatement agrees | 100,000 |
| T-stmt-sig | verifyStatement, signStatement | verifies exactly the original triples signed in the run (keys in memory); signStatement refuses non-statements | 10,000 |
| T-req-shape | requestShapeErrors, isProofRequestV4, newRequest | never throws on JSON data; equal to the V4_DESIGN section 5 reference | 200,000 |
| T-reply-shape | replyShapeErrors, isSessionReplyV4 | never throws on JSON data; equal to the reference | 200,000 |
| T-open | verifierOpenReply (object, string or bytes) | never throws; result equal to the reference decision; ok never consumes the session | 50,000 |
| T-depth | jsonDepthExceeds | equal to the reference depth up to 1,000; no throw at depth 10^5 and 10^6 | 20,000 |
| T-pres-shape | presentationShapeError | never throws; null exactly when the reference shape holds; long decimals recorded (HP1) | 100,000 |
| T-witness | buildCircuitInputV4 | throws an Error or returns exactly the reference assembly of canonical decimals below p | 50,000 |
| T-pqc | mlDsaVerify, mlDsaVerifyKey, mlKemDecaps, aes256gcmOpen, hkdfSha256Expand | only documented errors; any tamper gives false, null or implicit rejection | 20,000 |
| T-imt | IndexedMerkleTree.deserialize, verifyNonMembership | round trip; only canonical encodings accepted; verifyNonMembership complete and sound against the tree | 20,000 |
| T-pub | parsePublication | never hangs; accepts every honest blob; on return both roots match a rebuild; non-canonical acceptances recorded (HP2) | 20,000 |
| T-verify | VerifierV4.verifyReply (Anvil 8781) | never throws; accepts exactly when the transport is intact, the four presentation fields are the honest ones and Groth16 accepts the proof; a reply failing any of the first 14 checks consumes nothing and the honest reply is accepted afterwards | 20,000 (1 in 20 as shipped, the rest on the read cache) |
| T-wallet-req | HolderWalletV4.checkRequest; present() on exotic requests | only WalletRefusal with a WALLET_CHECKS name; passes only requests the reference accepts for this chain and verifier | 5,000 |
| T-wallet-iss | HolderWalletV4.checkIssuerData through a mutating data source | returns only for the exact anchored data; refusal text never holds the credID, the leaf index or the source's own error text | 5,000 |

### 4.3 References, failures, observations

- References (`oracles.ts`) are written from the design text and the package's contract comments,
  not by calling the function under test (integer calendar arithmetic, digit-string comparison,
  explicit character classes). Where the package documents a choice the design leaves open, the
  reference follows it and says so.
- A disagreement is a property violation. Violations are grouped by signature (target, predicate,
  error class); the first input of each signature (at most 20 per target) is saved as
  `failures/<target>/<sha12>.json` with seed, case index, mutation recipe, the input in typed JSON
  (bytes as hex, bigints as strings; inputs above 4 MiB by hash), the sanitized violation, source
  hashes, git HEAD and the replay command (`fuzz.ts --replay <file>`). Targets that generate keys in
  memory (T-stmt-sig, T-open, T-pqc, the chain targets) regenerate the case with fresh keys:
  mutation positions and choices are identical, key-dependent bytes differ.
- Observations are facts that are not property failures (for example a non-canonical encoding a
  parser accepts); each id is counted and its first input saved under `observations/`.
- Slow inputs: a call slower than max(1 s, 100 x the median of the first 200 cases) is saved under
  `slow/` as an availability candidate. It is not a timing result; it is timed only by adding a
  load class under section 3.
- Chain targets: a fresh Anvil on 127.0.0.1:8781 (D-034), 1 issuer, 2 holders, an anchored epoch,
  one verifier; 8 honest presentations proved with the dev key, their session secrets captured
  in memory (as in section 3.6) so mutated presentations can be re-sealed into the same session.

### 4.4 Coverage

`fuzz.ts --coverage` runs the children with NODE_V8_COVERAGE (D-034: no coverage package) and
`coverage.ts` maps V8 block counts to TypeScript lines of `packages/v4/src` through the source maps
tsx registers: a line is covered when any of its mapped positions has a count above 0 in any
process; functions by call count. Only `coverage/summary.json` and `summary.md` are kept (the raw
files go to the OS temp directory). The totals are a share of the modules the fuzz processes
loaded: a `packages/v4/src` file that no fuzz process loaded has no source map, so its lines are
not counted; it is listed under `unloadedFiles` and the total is labelled "of the loaded
modules", not the coverage of `packages/v4/src`. This is the coverage of the fuzz processes
alone; coverage of the existing test suite is not measured, so no "coverage added by fuzzing"
figure is reported.

## 5. Circuit and witness fuzz (untimed)

- Seed robustness.circuitFuzz 20261023. Read-only guard first: R1CS, wasm, zkey and vkey hashed
  against `setup/pins_v4.json`, the sym file against `circuit_info.json`. The tracked attacker
  generator (`circuits/build/v4/attacker`) is used only when its source equals the generator of the
  frozen circuit and its wasm exists; otherwise a fresh one is compiled into the OS temp directory.
  Nothing under `circuits/` is written.
- 300 cases, about half aimed at true statements, with values at every constraint-group boundary
  (birth date at today - 10000 x threshold +/- 0 to 2 days, including 29 February; expiry at
  today +/- 1; today at the epoch window edges; standard and non-standard thresholds; predicate
  codes 0 to 3 and random; type equal or not; IMT openings correct, non-bracketing, stale or forged;
  foreign issuance root; holder-secret mismatch; inconsistent policy hash or statement code; values
  of 2^27 and above).
- Oracle: `oracles.ts` relationR4, an integer model of R4 over F_p (Poseidon from circomlibjs).
  Per case: the reference witness exists exactly when the model says true, and then satisfies the
  real R1CS with the 8 public wires equal to the inputs; the attacker generator's witness mapped to
  the real layout satisfies the real R1CS exactly when true (a generator refusal is allowed for
  false statements only); 15 true and 15 false cases are proved with the dev zkey and verify
  exactly when true.
- Witness mutation: 5,000 edits of 1 to 3 random wires of up to 10 honest witnesses (reference
  witnesses that satisfy the real R1CS with the 8 public wires equal to the inputs); the real R1CS
  must reject the edit unless no input wire changed (then the edited wires are free hint wires,
  recorded by name). A satisfied edit that changes a public wire is a critical failure
  (`mutationsPublicChangedSatisfied`); one that changes private input wires only is a failure of
  its own class (`mutationsPrivateInputChangedSatisfied`). Each failure file holds the base case
  index and circuit input and every edit (wire, name, kind, old and new value as decimals);
  `--replay` rebuilds the base witness with the reference wasm, checks each edit's old value,
  applies the edits and checks the real R1CS in full.
- Limit [A]: the model is built from the same package encodings as the circuit inputs; a bug shared
  by both would go unnoticed. The hand-written cases of `tests/v4/circuit_v4.test.ts` partly cover
  that.
- Outputs: `results/v4/robustness/circuit_fuzz/<campaign>/` `plan.json`, `env.json`, `cases.jsonl`,
  `mutations.jsonl`, `failures/` (synthetic circuit inputs and mutation records, all replayable
  with `--replay`), `summary.json`.

## 6. Registry fuzz and invariant tests (forge, untimed)

- `onchain/test/v4/RegistriesV4.fuzz.t.sol` against the unchanged `RegistriesV4.sol`. Every call is
  checked against an independent model written from the contract NatSpec and V4_DESIGN 6.3: the
  model predicts acceptance or the exact revert reason of the first failing check
  (recordUnique, controllerOnly, governanceWriter, accreditationSerial, epochIncrement,
  anchorCadence, windowBounds, kemMonotonic), and the stored state must equal the model's.
- Stateless fuzz tests: record key = keccak256(abi.encodePacked(did, controller)) and injective;
  registration stores what was sent, cannot repeat, cannot block another controller;
  deactivation by the owner only, once, never undone; accreditation serial rules over three
  calls; epoch rules over three calls with time steps; anchors only under the sender's own active
  record; KEM key rules over three calls; constructor guards. Values are drawn at the rule edges
  (serial step 2^20, 2^53 - 1, window = maxWindow and maxWindow + 1, uint64 limits) and raw.
- Invariant test: forge drives random sequences through a handler (3 controllers, 3 DID strings
  including the empty one and two that differ by a suffix, the governance account, time steps);
  invariants: every call matched the model; stored DID, accreditation, anchor and KEM state equal
  the model's ghost state; no anchor or KEM key without a DID record; stored windows obey
  windowBounds.
- Vacuity guards: the handler counts the calls each registry accepted, per method.
  `test_handlerReachesEveryAcceptance` drives the handler's own pickers and model to one accepted
  call of every method (register, KEM key, epoch anchor, accreditation, deactivate), so a handler
  or picker bug that makes a method reject the same way in the model and the contract fails
  deterministically. `afterInvariant()` (called by forge after every invariant run) requires, in
  a run of at least 50 model-checked calls, an accepted registration and at least one other
  accepted call. A per-method requirement in every run is not used: with about 17 calls per
  method in a 100-call run and about 22 % of accreditation calls acceptable, a run with no
  accepted accreditation has a probability of about 1 % [S], so 256 runs would fail by chance.
- Seed robustness.forgeFuzz 20261024 (`--fuzz-seed`). Budgets: 10,000 runs per fuzz test; invariant
  256 runs x depth 100. Compiler: the repository's solc-js 0.8.28 with the ledger's settings
  (optimizer 200; EVM version cancun, solc 0.8.28's default, which `compileSolidityV4` leaves in
  place; `onchain/foundry.toml` sets it because forge's own default is prague) through
  `scripts/robustness/solc_shim.cmd` (Windows) or `solc_shim.sh` (which must be executable: the
  runner checks it); forge runs `--offline`, so nothing is downloaded. The effective settings
  (`forge config --json`: evm_version, optimizer, optimizer_runs, via_ir) are recorded in
  `env.json`. forge-std is not vendored; the test declares the cheatcodes it uses.
- `solc_shim.cmd` is a Windows-specific launcher (forge runs the `--use` path directly and cannot
  pass arguments to a compiler); it only runs node on `solcjs_shim.cjs`. It is an exception to the
  docs/BENCHMARK_POLICY.md host rule recorded in DECISIONS.
- Outputs: `results/v4/robustness/forge/<campaign>/` `plan.json`, `env.json`, `results.json` (forge's
  JSON without traces), `failures/<contract>.<test>.json` (counterexample calldata and arguments, or
  the call sequence, and the replay command), `persisted/` (forge's failure files), `summary.json`,
  `summary.md`.

## 7. Markers, order and triage

- Fuzzing, the circuit fuzz and the forge tests are untimed but CPU-heavy: a full campaign holds
  `results/v4/BUSY` (D-034); every runner, and every `--replay`, refuses to start while RUNNING or
  BUSY exists. The load test holds `results/v4/bench/RUNNING`.
- Order (D-034): fuzzing first, before any timed series, so a defect is found before timings are
  taken; the load test after the chain-read results are reviewed (it depends on the shipped
  client's per-POST cost on Windows).
- `packages/v4` stays frozen for the measurement period except for a fix of a defect found by
  fuzzing; such a fix gets tests, the security suite and the mutation campaign again before any
  timed series, and a DECISIONS entry (D-034). A circuit finding falls under the B7 freeze and the
  re-key rule and is Kushal's decision.
- Tests are never weakened. A failure that has no fix stays in `results/` and TASKS; it is never
  added as a skipped or expected-fail test. Confirmed and fixed failures become regression
  fixtures under `tests/v4/`.
- Every free-text field goes through `sanitize` (no repo path, home, temp, user or host name).

## 8. Results layout and index

```
results/v4/robustness/
  fuzz/<campaign>/          plan.json env.json targets/ failures/ (incl. hang_*.json) observations/ slow/ coverage/ summary.(json|md)
  circuit_fuzz/<campaign>/  plan.json env.json cases.jsonl mutations.jsonl failures/ summary.json
  forge/<campaign>/         plan.json env.json results.json failures/ persisted/ summary.(json|md)
  load/<campaign>/          schedule.json env.json inputs/ aux.json runs.jsonl hostile.jsonl correctness.jsonl blocks.jsonl saturation.json summary.(json|md)
  logs/<mode>_<campaign>/   driver logs (scrubbed)
  summary.json, summary.md  index (scripts/robustness/summarize.py)
  _smoke/                   smoke output (gitignored, never quoted)
```

## 9. Commands

Run from the repository root in Git Bash on the Windows host. Full runs need this row committed
first (header of this file).

1. Smoke of every runner (a few minutes; no marker; refuses while one exists):
   `bash scripts/robustness/run_robustness.sh smoke`
2. Fuzzing, circuit fuzz and forge tests under BUSY (about 60 to 75 min [S], from the smoke runs'
   per-case times and the budgets above):
   `bash scripts/robustness/run_robustness.sh fuzz --campaign fz1`
3. Load test in a quiet window on AC power (about 60 to 90 min [S], section 3.13):
   `bash scripts/robustness/run_robustness.sh load --campaign ld1 --confirm-quiet`
4. Single steps: `node --import tsx harness/v4/robustness/fuzz.ts --campaign <name> [--targets T-a,T-b]
   [--coverage]`, `circuit_fuzz.ts --campaign <name>`, `forge_fuzz.ts --campaign <name>`,
   `load.ts --campaign <name>`; replay: `fuzz.ts --replay <failure.json>`,
   `circuit_fuzz.ts --replay <failure.json>`; analysis: `python3 scripts/robustness/analyze_load.py
   --campaign <name>`, `python3 scripts/robustness/summarize.py` (on Windows the interpreter is
   `python`).
5. Unit tests: `npx vitest run tests/v4/robustness_lib.test.ts tests/v4/robustness_load.test.ts
   tests/v4/robustness_properties.test.ts` and `python -m unittest discover -s scripts/robustness -p
   "test_*.py"`.

## Deviations

### 2026-10-03: harness corrections after the fz1 triage (before fz2)

The fz1 triage (TASKS; DECISIONS entry of 2026-10-03) found four defects in the fuzz harness, not
in `packages/v4`. They are corrected in `harness/v4/robustness/` and `scripts/robustness/`. No rule
above this heading changes: targets, properties, references (except as below), budgets, seeds and
watchdog settings are as pre-registered, so the normative hash is unchanged. fz1's files stay as
they are, as the record of the findings. After these corrections and the two package fixes (the
D-034 exception for fuzz-found defects) are committed, the whole fuzz mode of
`run_robustness.sh` (17 targets, circuit fuzz, forge) runs again as a new campaign, fz2 (no
resume: fuzz.ts refuses a campaign directory that already holds plan.json, as section 3.9 states
for the load test). The driver is unchanged: its step already records the runner's exit code.

1. T-witness reference (false positive; fz1 signature 60768ea948f7, case 8265). `refAssemble` read
   credId with `Buffer.from(id)`. For an object, Buffer.from first calls `value.valueOf()`, so an
   own non-callable valueOf added by the addkey mutation made the reference throw, and `run()`
   counted that as "the reference refuses". The package ignores own keys and returned the honest
   assembly. The reference now reads the bytes through the array's internal slots
   (`mutators.ts` `copyBytes`: `new Uint8Array(id)`, then the copy's buffer), so own keys have no
   effect, and the 32-byte check uses the copy's length. `cloneJson` had the same hazard (latent,
   no occurrence in fz1) and now uses `copyBytes` too. Case generation is unchanged: all 50,000
   T-witness cases generate as before (fingerprint of family, recipe, typed input and own keys),
   case 8265 included. Replay of the fz1 failure file: assembled, no violation.
2. T-open reference (oracle defect; signature 00a08412a548, 10 cases recorded as
   `harness:runError`). For a plaintext with an overflowing literal such as 1e400, JSON.parse gives
   Infinity and `refCanonical` throws, so these cases stopped before `verifierOpenReply` was
   called: fz1 holds no observation of the package on them. A parsed value with no canonical text
   is now not canonical, which the T-open property already calls malformed. `refCanonical` keeps
   its throw (other callers rely on it). Replay of the fz1 failure file: malformed, no violation.
3. Lost results (T-dates, T-req-shape, T-reply-shape). The result write took `Math.max(...times)`.
   With more than about 125,000 call times the spread overflows V8's stack, so the three
   200,000-case targets crashed in the write: T-dates and T-req-shape after all their cases,
   T-reply-shape at a periodic save after its 88,736-case checkpoint. fz1 has no quotable result
   for these three targets, and its case total of 708,736 is a lower bound. The maximum is now
   taken by a loop. The same spread in `harness/v4/chainread/series.ts` (queueMsMax) and
   `harness/v4/lib/rpc_trace.ts` (spanMs) is replaced by loops with the same results.
4. Failure reporting. fz1's parent returned 0 whatever its children did, so the driver logged
   "end fuzz exit 0" and "failed=0". Now:
   - a target whose child code throws (setup, bookkeeping, a result write) still gets
     `targets/<id>.json` with its true casesRun and a `crash` field (schema
     pqid/v4-fuzz-target/v2), and the child reports the count to the parent before it exits 1;
   - the parent exits 1 when a child exits non-zero, when the watchdog stops a child, or when a
     target is not complete, and records the reasons under `step` in `summary.json` (schema
     pqid/v4-fuzz-summary/v2). Property violations alone do not change the exit code;
   - a target with no final record is labelled "result lost (child crashed)" (or "child stopped
     by the watchdog") with any count that is known, never "0" or "?"; a target of the same child
     that never started is "not run"; the failure, observation and slow files a lost target left
     are listed. `summarize.py` labels such rows the same way, also in the v1 summary of fz1, and
     lists each failure file once;
   - the parent passes the chain child its targets in the order the child runs them (T-verify,
     T-wallet-req, T-wallet-iss, as in fz1, whatever the order of `--targets`), and the child runs
     them in the order given, so the label of a failed chain child names the target that was
     running; a target named twice in `--targets` is refused;
   - a generator error now counts its case as run (fz1 left it out, so one on the last index would
     have made a full target incomplete; it did not occur in fz1).
5. Replay: a throw inside `run()` is reported as a `harness:runError` verdict instead of a stack
   trace, and a stored input of null (T-open and the chain targets build their input inside
   `run()`) is no longer reported as "above the size cap".

Known limit, not changed: typed JSON (`typed_json.ts`) writes a byte array as its bytes and drops
own keys on it, so a failure file does not show a key that a mutation added to a byte array. Such
a case still replays from (seed, target, index), but the replay's input comparison cannot see the
key.

Regression fixtures: `tests/v4/robustness_fuzz_fixes.test.ts` (case 8265 and an own valueOf of every
confusion value; the ten fz1 1e400 cases of T-open; a result write with 200,000 call times; a
crash record with the true casesRun; the summary labels and the exit code; the labels of a
reordered chain subset) and `scripts/robustness/test_summarize.py` (the index labels of a v1
summary shaped like fz1 and of v2 summaries, the lower-bound total, the runner exit column, each
failure file once). Section 9, item 5 names the three older TypeScript test files; from this
date it includes the new one too, and `npx vitest run tests/v4/robustness_*.test.ts` runs all
four. Its Python command (`python -m unittest discover -s scripts/robustness -p "test_*.py"`)
already picks up `test_summarize.py`.

### 2026-10-03: two packages/v4 fixes after the fz1 triage (DECISIONS D-042)

`packages/v4/src/wallet.ts` and `packages/v4/src/session.ts` were changed under the D-034 exception for a defect found by fuzzing (Kushal's decision of 2026-10-03). No rule above the Deviations heading changes, so the normative hash is unchanged.

1. T-wallet-req (fz1 signature d684e06eec1c; 13 cases: 5 undefined roots, 8 null roots).
   - `checkRequest` read `request["policy"]` before its shape check. A null or undefined request
     therefore threw a TypeError instead of `WalletRefusal("requestShape")`, and `present()` did the
     same.
   - Fix: `request ?? {}` makes that read safe. The shape check still runs on the original value and
     refuses the request as requestShape before any ledger or clock read.
2. requestShapeErrors.
   - It spread the policy's error list into `push()`, so about 125,000 or more extra policy keys
     threw RangeError. 130,000 keys is about 1.45 MB of JSON.
   - This was found in the triage, by analogy with the result-writer spread (item 3 of the entry
     above), not by a generated case.
   - Fix: one push per error. The list is unchanged for every input that did not throw.

- Both defects failed closed. Nothing was read or changed before the throw: no ledger, clock, date
  reservation, KEM guard or credential.
- fz1's files stay as they are and name the old hashes:
  - wallet.ts e5aa0cffb60dc5b3ba2465f8ab7d100ebbe9810e2f1c9bfeb44c229ded8a725d;
  - session.ts d772cc59a9161636e0d05faabd8ae34487911147ae462d24a7c37955d7c5fc80.
  The new hashes are 8f4a0a40... (wallet.ts) and 773b012b... (session.ts).
- Regression fixtures: `tests/v4/fuzz_regressions.test.ts`.
- fz2 can confirm item 1: T-wallet-req should show 0 violations. It cannot confirm item 2, because
  addkey adds 1 to 3 keys per case. Item 2 rests on the fixture.
- After the commit and before any timed series, these run again: the tests, the C1 suite and the C3
  mutation campaign (`bash scripts/ceremony/followup.sh --dev-rerun`, output under
  results/v4/fixcheck/), and fz2.

### 2026-10-03: the auxiliary record is auxiliary.json (after ld1)

- `load.ts` wrote the auxiliary record as `aux.json` (sections 3 and 8 name it so). AUX is a reserved
  device name on Windows, and Git for Windows cannot add a file named `aux.*`. From this date the
  record is `auxiliary.json`; `analyze_load.py` reads `auxiliary.json` and falls back to `aux.json`.
  The text above keeps the old name, so the normative hash is unchanged.
- ld1's record was renamed after the run with its content unchanged (1,557 bytes, sha256
  f20d10b887c318dad8edecbc4fdc173611b6aee4556a30767c23a474707bff90), then the analysis was rerun.

