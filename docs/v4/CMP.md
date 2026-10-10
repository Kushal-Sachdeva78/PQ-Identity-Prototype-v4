# Comparable benchmark series (cmp): addendum to the Phase D protocol

Protocol for the row "Make benchmarks comparable" of DECISIONS D-034. Written 2026-10-01, revised
2026-10-03, before any timed cmp run. Facts, rules and commands only.

- This file extends the publication copy of `docs/v4/BENCH_PROTOCOL.md`, whose text above
  "## Deviations" has SHA-256
  `fe4f88284db9c858b30939b994394194d1f9de930fb229587789842b98ad51f8`. Its rules apply unless this
  file says otherwise. Every cmp runner checks that hash when it starts and refuses if it changed.
  The original experiment snapshot used normative hash
  `d3883a2146e5b0f028f9668376367e7ff7d2406f7096dd87bfddb0aff67fa45f`; that historical hash remains
  in the recorded results. Publication text normalization changes the protocol bytes, so fresh
  campaigns use the publication hash and must not resume an original campaign under edited text.
- Every cmp campaign records the SHA-256 of this file above "## Deviations" (`env.json`,
  `cmpProtocolSha256`, LF line ends) and refuses to resume if it changed. Deviations are appended
  to the last section, dated, before the affected run.
- Existing campaigns, summaries, ledger keys and claims are not changed or replaced. Results of
  this series get new ledger keys.
- Code: `harness/v4/cmp/` (`spec.ts`, `build_v2_o2.ts`, `inputs.ts`, `eddsa_fixture.ts`,
  `wallet_data.ts`, `child_wallet.ts`, `child_curve.ts`, `cold.ts`, `warm.ts`, `runner.ts`,
  `log_scrub.ts`, `smoke_reset.ts`). Analysis: `scripts/cmp/analyze_cmp.py`. Window script:
  `scripts/cmp/quiet_window_cmp.sh`.
- Labels: [M] measured, [S] estimate from the stated arithmetic, [A] assumption.

## What the series adds

- One interleaved cold campaign of v2 (as published), v2 at --O2, v3, v4 and the EdDSA baseline.
  In Phase D, cold v4 and cold v2/v3 were separate campaigns (`sameCampaign = false`).
- v2 at --O2 measured cold, with kept and pinned artifacts and the protocol's phases. The earlier
  figure (`results/v3/compare_v2_v3.json`) was 15 warm in-process rounds with a deleted key.
- The EdDSA baseline with 30 cold runs on a fixed input. The earlier figure
  (`results/v4/baselines/measure.json`) was 10 warm runs on a random input.
- The wallet rebuild repeated (10 cold runs per size) with the wallet's first Poseidon build
  timed as its own phase. The earlier figure (`results/v4/privacy.json`) was one run per size.
- A warm series of the same five circuits.

## Conditions

| Id | Circuit wasm | Proving key | Verification key | Key label | Fixed input |
|---|---|---|---|---|---|
| v2 | `circuits/build/credential_auth_js/credential_auth.wasm` | `setup/out/credential_auth_final.zkey` | `setup/out/verification_key.json` | committed v2 key | `results/v4/bench/inputs/v2_input.json` |
| v2o2 | `results/v4/cmp/artifacts/v2_O2/credential_auth_js/credential_auth.wasm` | `results/v4/cmp/artifacts/v2_O2/credential_auth_v2_O2_timing.zkey` | `results/v4/cmp/artifacts/v2_O2/verification_key_v2_O2_timing.json` | v2 --O2 dev timing key (v2 beacon recipe) | `results/v4/bench/inputs/v2_input.json` |
| v3 | `circuits/build/v3/credential_auth_v3_js/credential_auth_v3.wasm` | `setup/out/v3/credential_auth_v3_final.zkey` | `setup/out/v3/verification_key.json` | committed v3 key | `results/v4/bench/inputs/v3_input.json` |
| v4 | `circuits/build/v4/credential_auth_v4_js/credential_auth_v4.wasm` | given to the runners | given to the runners | ceremony key (dev key only with an override) | `results/v4/bench/inputs/v4_input.json` |
| eddsa | `circuits/build/baselines/eddsa_credential_js/eddsa_credential.wasm` | `setup/out/baselines/eddsa_credential_throwaway.zkey` | `setup/out/baselines/eddsa_credential_throwaway_vkey.json` | throwaway baseline key | `results/v4/cmp/inputs/eddsa_input.json` |

- Optimisation levels: v2 is the published build at circom's default `--O1` (21,715
  constraints); v2o2, v3, v4 and eddsa are `--O2` builds. This is why v4/v2 and v4/v2o2 differ.
  Every campaign's `env.json` records `conditionNotes` per condition (what it is, optimisation
  level, constraints and wires from its circuit info file, key label); the summary copies them.
- v2o2 build (`harness/v4/cmp/build_v2_o2.ts`, untimed, holds `results/v4/BUSY`): circom 2.2.3
  `--O2 --r1cs --wasm` of the frozen `circuits/credential_auth.circom` (read only) into
  `results/v4/cmp/artifacts/v2_O2/`. Stop rule: 10,588 constraints and 10,620 wires
  (`results/v3/compare_v2_v3.json` `$.constraints.v2_O2`), otherwise no key is made. It is a build
  variant that was never shipped.
- v2o2 key: the committed v2 recipe of `setup/groth16_setup.ts`: `newZKey` from the pinned 2^15
  ptau, then `beacon("pqid dev beacon", 0102...1f20, iterExp 10)`. It is deterministic (the build
  makes it twice and compares) and has no secret contribution, so it gives no soundness and is a
  timing key only. The same recipe run on the committed v2 r1cs reproduces the pinned v2 key.
- Pins: `results/v4/cmp/artifacts/pins_cmp.json` holds the v2o2 r1cs, wasm, zkey and vkey hashes
  and the EdDSA wasm, zkey and vkey hashes (cross-checked with
  `circuits/build/baselines/eddsa_credential_info.json` and
  `setup/out/baselines/eddsa_credential_throwaway_setup.json`). v2, v3 and v4 keep their pins in
  `setup/pins.json` and `setup/pins_v4.json`; the v2 wasm has no pin and is hashed only. The v2o2
  r1cs is committed with the other cmp artifacts (as the v2, v3, v4 and EdDSA r1cs files are), so
  the key can be re-checked with `verifyFromR1cs`.
- v4 key: an input of `inputs.ts`, `cold.ts` and `warm.ts` (`--v4-zkey`, `--v4-vkey`,
  `--v4-key-label`, `--v4-pins`; the pin file must hold an entry whose `path` is the given file).
  D-034: the real campaigns run after the key ceremony and use the ceremony key. With the dev key a
  real campaign refuses unless `--allow-dev-key`, and its rows carry the label "dev key". A key
  change after a campaign started makes it refuse to resume (new campaign name).
- `curve` (optional, off by default): a fresh process that builds the bn128 curve as snarkJS does
  first in a fresh prove (ffjavascript 0.3.0 `buildBn128()`, the copy nested under snarkjs; wasm
  plus one worker thread per logical core). Included with `--conditions v2,v2o2,v3,v4,eddsa,curve`;
  it adds 30 cold runs (about 5 h [S]). Its record has the checks `curveRegistered` and
  `workerThreads` (no proof is made, so no `verified`).
- Wallet conditions: `wallet1e5` (100,000 credentials, 1,000 revocation keys) and `wallet1e6`
  (1,000,000 and 10,000), the sizes of `results/v4/privacy.json` `$.publishedTree.timing`.

## Environment and roots

- One OS: native Windows 11, snarkJS 0.7.4 in Node 24.18. rapidsnark is not used. The WSL cmp
  campaign is skipped (D-034: a v4 Phase D repeat in WSL replaces it after the ceremony). The
  runners refuse a real run on any other platform.
- Roots: `results/v4/cmp/prove/` (`cold_cmp`, `warm_cmp`), `results/v4/cmp/wallet/`
  (`wallet_cmp`), `results/v4/cmp/inputs/`, `results/v4/cmp/artifacts/`, logs in
  `results/v4/cmp/logs/`, summary `results/v4/cmp/summary_cmp.json` and `.md`.
- Each campaign folder holds `schedule.json`, `env.json` and `runs.jsonl` as in Phase D. `env.json`
  also records both protocol hashes, the input lock, the v4 key label, the condition notes, the
  quiet rule, the host-pause rule, the marker held, the SHA-256 of the timed code (`code.timed`:
  `child_prove.ts` for cold circuits, `child_curve.ts`, the wallet child and the package files it
  times, `warm.ts` for the warm series) and of the runner code, the committed check (below) and
  whether `--allow-uncommitted` was given. A campaign refuses to resume (and a warm campaign to add
  a session) if the timed code changed.
- Ratios against the Phase D campaigns (`results/v4/bench/`) are cross-campaign consistency
  checks only, never results.

## Real-mode rules

- A real (not smoke) run refuses unless every rule holds (`harness/v4/cmp/spec.ts`
  `realModeProblems`, unit-tested):
  - native Windows (`process.platform` win32);
  - the fixed parameters: cold prove n = 30, wallet n = 10, idle 600 s, lead 20 s, at most 10
    postponements of 60 s, child timeout 900 s; warm n = 30, 5 warm-up blocks, settle 600 s,
    block gap 2 s;
  - the ceremony key for v4 (the dev key only with `--allow-dev-key`);
  - committed check: every runner and timed code file, this file,
    `results/v4/cmp/artifacts/pins_cmp.json`, `results/v4/cmp/inputs/`,
    `scripts/cmp/analyze_cmp.py` and `scripts/cmp/quiet_window_cmp.sh` tracked and unchanged at
    HEAD (read-only `git status --porcelain` and `git ls-files`). `--allow-uncommitted` overrides
    this one rule and is recorded in `env.json`; the window script never passes it.

## Inputs

- v2 and v2o2 use the Phase D v2 input, v3 and v4 their Phase D inputs (`results/v4/bench/inputs/`,
  re-verified against `inputs.lock.json`). The v4 input does not depend on the key.
- eddsa: `harness/v4/cmp/eddsa_fixture.ts` with the unchanged functions of
  `baselines/eddsa/lib.ts` and published constants only: issuer key = SHA-256 of the UTF-8 string
  `pqid-bench-eddsa-fixture-issuer` (a fixture key anyone can derive, never written, valid only for
  the throwaway baseline circuit), holder secret 123456789, birth date 19840315, expiry 20261226,
  credential type `pqid:type:age-credential:v1`, predicate age_gte 18, today 20260927, nonce 424242.
  EdDSA-Poseidon signing is deterministic, so the input is byte-reproducible.
- Wallet data (`harness/v4/cmp/wallet_data.ts`): leaf i = the first 31 bytes of
  SHA-256("pqid-bench-wallet-leaf/" + i), revocation key j = the first 31 bytes of
  SHA-256("pqid-bench-wallet-rev/" + j) mod 2^251, big-endian. Same distribution as the random
  data of `privacy.json`, but reproducible.
- Lock: `results/v4/cmp/inputs/inputs_cmp.lock.json`, made by `harness/v4/cmp/inputs.ts`
  (untimed, holds `results/v4/BUSY`): per circuit the input file and SHA-256, the artifact hashes,
  the expected public signals and one untimed reference proof that must verify and give them
  (the Phase D pins for v2, v2o2, v3 and v4; the fixture's for eddsa); per wallet size the rebuilt
  issuance and revocation roots. A different existing entry is replaced only with `--force` and a
  recorded reason. `--check` rebuilds everything in memory and compares.
- Each session start hashes every artifact and compares it with its pin and with the input lock
  (a mismatch stops the runner); every cold run re-checks the input hash (`child_prove.ts`).
  Every child compares its public signals (or roots) with the pins; a mismatch is an error record.

## What is timed

- Circuits: `harness/v4/bench/child_prove.ts`, unchanged, so witness, prove, verify and wp have
  exactly the Phase D meaning. snarkJS prove includes reading the zkey and building the bn128 curve;
  the curve build is not split out of prove.
- `curve`: `curveMs` = `buildBn128()` in a fresh process (`harness/v4/cmp/child_curve.ts`). It is
  read next to the prove medians (descriptive); it is never subtracted run by run.
- Wallet (`harness/v4/cmp/child_wallet.ts`, one fresh process per run):

| Phase | Call |
|---|---|
| poseidonInit | the first `getPoseidon()` of the process: circomlibjs 0.1.7 `buildPoseidon` on its own ffjavascript 0.2.63, a single-thread bn128 build plus the Poseidon constants; an error if under 1 ms |
| issuance | `IssuanceSnapshot.build(leaves, ISSUANCE_DEPTH, poseidon)` |
| revocation | `IndexedMerkleTree.bulkBuild(keys, REV_DEPTH)` |
| rebuild | issuance + revocation of the same run |
| total | poseidonInit + rebuild of the same run |

- poseidonInit is the wallet library's curve build. It is not the same quantity as the prover's
  multi-threaded `curve` condition (ffjavascript 0.3.0) and is never compared with it.
- Wallet aux (not timed): module import, data generation, a second cached `getPoseidon()`, the
  circomlibjs and ffjavascript versions, peak RSS. Both rebuilt roots must equal the pinned roots.
- In `privacy.json` the first Poseidon build sat inside the timed 10^5 issuance rebuild and not
  inside the 10^6 one (same process, cached). Here it is its own phase in every run.
- Not timed: input generation, artifact hashing, power and quiet-machine readings, idle.

## Cold series (cold_cmp) and wallet series (wallet_cmp)

- Runner: `harness/v4/cmp/cold.ts --kind prove` and `--kind wallet`.
- n = 30 valid runs per circuit (150 runs, 180 with `curve`); n = 10 per wallet size (20 runs).
  A real run refuses any other n.
- One run = one fresh Node process. Fixed idle of 600 s on the monotonic clock from the end of the
  previous run (or the campaign start) to the spawn. Power and quiet-machine reading 20 s before the
  spawn; busy under the Phase D rule (next section): postpone in 60 s steps, at most 10, then run
  flagged. Power again after exit.
- The idle is slept in steps of at most 1 s by a watchdog (`harness/v4/cmp/runner.ts`
  `IdleWatch`, unit-tested with a fake clock). New per-run fields:
  - `idleWallSec`: the same idle on the wall clock; `clockGapSec` = idleWallSec - idleSec.
  - `idleMaxTickGapSec`: the largest gap between two consecutive watchdog wake-ups, the larger of
    the monotonic and the wall-clock gap (expected about 1 s); `idleTickGap` holds both clocks'
    gaps and the number of wake-ups. A frozen process wakes late by the length of the pause,
    whichever clock counts it. The time spent in the power and quiet readings between watched
    sleeps is not counted.
  - `hostPauseSuspected` = |clockGapSec| > 5 s or idleMaxTickGapSec > 5 s.
- On Windows `performance.now()` is QueryPerformanceCounter, which may keep counting through
  standby; then clockGapSec stays near 0 after a standby and only idleMaxTickGapSec shows it. That
  the flag fires on a real standby of this laptop is not verified (no standby test was run) [A].
  Flagged runs are kept and counted, and the sensitivity analysis leaves them out.
- Discard, error, timeout (15 min) and resume rules: those of the Phase D cold series.

## Warm series (warm_cmp)

- Runner: `harness/v4/cmp/warm.ts`. One process holds the five circuits; settle 600 s on AC; 5
  warm-up blocks, then 30 measured blocks, each block every circuit once. One iteration makes the
  calls of `child_prove.ts` (snarkJS path of `harness/v4/bench/warm.ts`). Power before and after
  every block, a quiet-machine reading before every block, the Phase D warm rules otherwise.

## Randomisation

- Blocked order (each block holds every condition once), Fisher-Yates driven by one mulberry32
  stream per campaign (`harness/v4/bench/lib.ts` `buildSchedule`). The conditions are put into
  their canonical order (v2, v2o2, v3, v4, eddsa, curve; wallet1e5, wallet1e6) before the shuffle,
  so the order typed in `--conditions` never changes the schedule of a seed. The first block of
  each schedule is pinned in `tests/v4/cmp_bench.test.ts`.
- Pre-registered seeds (D-034): `cold_cmp` 20261041, `wallet_cmp` 20261042, `warm_cmp` 20261043.
  The runners take them from `harness/v4/lib/seeds.ts`; there is no seed flag. `schedule.json` is
  written before the first run.
- Bootstrap seed: 20260927.

## Power, quiet machine and markers

- Power: `harness/v4/bench/guard.ts` `readPower()` (unchanged rule: AC iff every battery reports 2).
- Quiet reading: one `harness/v4/lib/quiesce.ts` `readQuiesceExcluding()` reading per run (cold,
  3 s window) or per block (warm, 2 s window): the guard.ts CPU formula (all logical cores, 35 %
  threshold), a TCP connect to the known chain ports on 127.0.0.1, and the wall-clock and monotonic
  time over the window. No process list on Windows.
- Busy means the Phase D rule of `harness/v4/bench/guard.ts` `readQuiesce`, which quiesce.ts replays
  on the same window (`guardTs`): on Windows, machine-wide CPU busy above 35 %. The cold runner
  postpones on it; warm blocks are never postponed (as Phase D). Each record keeps it as
  `quiesce` in the Phase D shape (`quiesce.quiesced` = that rule, so `scripts/bench/analyze.py` and
  `scripts/cmp/analyze_cmp.py` count the same flag as for Phase D) and the full reading as
  `quiesceDetail`. Its own `quiesced` (the stricter quiesce.ts rule: also a foreign listener on a
  chain port, or a clock gap over 1 s inside the window) is counted in the summary, never used to
  postpone or to exclude runs.
- Markers (D-034, `harness/v4/lib/markers.ts`): timed campaigns hold `results/v4/bench/RUNNING`;
  the build, `inputs.ts` and smoke runs hold `results/v4/BUSY`; every runner refuses while either
  exists. The window script holds ONE `results/v4/bench/RUNNING` around warm_cmp, wallet_cmp and
  cold_cmp (`markers.ts run`; the runners borrow it through `PQID_MARKER_TOKEN`), so no other work
  can start between them. While RUNNING exists: only file editing and web research (docs/BENCHMARK_POLICY.md).
- Before the window, set by hand (no v4 code changes system settings): sleep and standby "Never"
  on AC, lid close "Do nothing", Windows Update paused, nothing else running (no agents, tests,
  builds or WSL work).

## Statistics

- Campaign selection: `scripts/cmp/analyze_cmp.py --cold NAME --warm NAME --wallet NAME`
  (default `cold_cmp`, `warm_cmp`, `wallet_cmp`; the window script passes the names it ran). The
  summary lists every campaign folder under `prove/` and `wallet/`; the analysis refuses when the
  root holds a campaign of the same kind that was not selected, unless `--ignore NAME` leaves it
  out on purpose (recorded).
- Completeness rule: a campaign counts as complete when it ended with a complete campaign-end
  (warm: session-end) and every configured condition has n >= 30 (cold circuits, warm blocks) or
  n >= 10 (wallet sizes); smoke roots need n >= 1. A primary ratio (and its block and sensitivity
  rerun) gets a number only when the cold campaign is complete; otherwise its status is
  "incomplete". When any of the three campaigns is missing or incomplete, the summary label starts
  with "PARTIAL".
- Per condition and phase: n, median, Q1, Q3, IQR (type 7, numpy `method="linear"`), min, max,
  and a percentile bootstrap 95% CI of the median (B = 10,000, seed 20260927, one stream per id:
  `default_rng([seed, crc32(id)])`), with the condition notes.
- Primary ratios, pre-registered (cold, snarkJS, ratio of medians, each condition resampled
  independently at its own n, as Phase D): v4/v2, v4/v3, v3/v2o2, v2/v2o2, v4/v2o2 and v4/eddsa, on
  prove and wp.
- Secondary: the primary ratios with a block bootstrap (whole blocks resampled, so the pairing
  inside a block is kept), and a sensitivity rerun without runs flagged `hostPauseSuspected` or
  `quiesce.quiesced = false` (the Phase D rule).
- Descriptive only: the other circuit pairs and phases, warm ratios, cold over warm per circuit,
  the curve share (curve median over each circuit's prove median), the wallet phases, the wallet
  poseidonInit share and the 10^6 over 10^5 scaling.
- Consistency (cross-campaign, never a result): cmp over Phase D medians for v2, v3 and v4 (cold and
  warm, with the key labels of both), and the earlier single values of v2 --O2, EdDSA and the
  wallet rebuild next to the new medians. If `scripts/bench/analyze.py` refuses the Phase D root,
  that section says "not computed" and the rest of the analysis still runs.
- Ids: every published ratio id starts with `cmp/` (for example
  `cmp/version/cold/snarkjs/v4_over_v2/prove`), so no id equals one of
  `results/v4/bench/summary.json`. Each entry records `bootstrapStreamId`, the stream passed to
  `boot_ratio`; for v4/v2, v4/v3 and cold/warm it is the `scripts/bench/analyze.py` id, so those
  CIs equal what analyze.py gives on the same rows (unit test `scripts/cmp/test_analyze_cmp.py`).
- Every ratio entry carries `numeratorKey` and `denominatorKey`, and every Markdown ratio table a
  keys column.
- `scripts/cmp/analyze_cmp.py` uses `describe` and `boot_ratio` of `scripts/bench/analyze.py`
  (unchanged). analyze.py also reads `results/v4/cmp/prove` unchanged when `curve` is not included
  (checked on smoke data), but its summary text says that v4 uses the dev key, so the window script
  does not run it.
- No analysis while `results/v4/bench/RUNNING` exists.

## Reporting

- New ledger keys only (a "Cmp" infix); the existing keys stay as they are.
- Which series a table, figure, pack or criterion cites (D-029, D-032) changes only by a DECISIONS
  entry written before the cmp analysis is read.
- v4 rows carry their key label; rows made with the dev key say "dev". The summary label names the
  v4 key (for example "[M] comparable benchmark series (cmp), v4: ceremony key").

## Order of work and commands

Run from the repository root in Git Bash, on AC power, with other work stopped.

1. Build (untimed, done once): `node --import tsx harness/v4/cmp/build_v2_o2.ts`. Run again, it
   rebuilds in an OS temp dir and compares with the pins (nothing is written).
2. After the ceremony key is pinned, inputs (untimed):
   `node --import tsx harness/v4/cmp/inputs.ts <v4 key flags>`, then the same with `--check`.
3. Commit the cmp code, this file, the pins, the artifacts and the input lock (the runners refuse
   a real run otherwise).
4. Smoke test (below), with the same `PQID_CMP_V4_*` environment as the window.
5. The window: `bash scripts/cmp/quiet_window_cmp.sh` with the v4 key in `PQID_CMP_V4_ZKEY`,
   `PQID_CMP_V4_VKEY`, `PQID_CMP_V4_LABEL` and `PQID_CMP_V4_PINS` (the ceremony helper
   `harness/v4/ceremony/followup_lib.ts` `cmpKeyFlags()` gives the same values as flags). Steps:
   marker check (`harness/v4/lib/markers.ts status`; a marker stops the window), inputs check
   (holds BUSY; a failure stops the window), then warm_cmp, wallet_cmp and cold_cmp inside one
   RUNNING hold, then the analysis of the campaigns it ran and a check that no file under
   `results/v4/cmp` (without `_smoke/`) holds the user name, host name or home path. Each step's
   log is scrubbed of paths, user and host names after the step exits
   (`harness/v4/cmp/log_scrub.ts`). `PQID_CMP_WITH_CURVE=1` adds the curve condition. After an
   interruption: `bash scripts/cmp/quiet_window_cmp.sh --from cold_cmp` with the same
   environment (the cold and wallet campaigns resume; warm starts a new session).
6. Analysis only, after every runner has exited: `python scripts/cmp/analyze_cmp.py`.

- Duration [S] (600 s idle per cold run plus the run itself): cold_cmp 150 x about 603 s = about
  25.1 h (Phase D cold_v4 took about 602 s per run; 180 runs with curve, about 30.2 h); wallet_cmp
  10 x about 610 s + 10 x about 665 s = about 3.5 h (rebuild times of `results/v4/privacy.json`:
  about 6.2 s at 10^5 and 60.8 s at 10^6, plus a few seconds of process start, import, data
  generation and the Poseidon build); warm_cmp 600 s settle plus 35 blocks of about 7 s = about
  15 min; inputs check about 2 min. Total about 29 h (about 34 h with curve).

## Smoke test (checks the runners; not a result)

- `--smoke` on every runner: n = 1 per condition, idle 5 s, lead 4 s, no postponing; warm n = 1
  with 1 warm-up block and 5 s settle; wallet sizes 1,000/10 and 4,000/40; output under
  `results/v4/cmp/_smoke/` (gitignored). A smoke run is untimed CPU-heavy work: it holds
  `results/v4/BUSY` (or borrows the window's hold) and the lock `_smoke/SMOKE_LOCK`.
  `--smoke-no-marker` (for agent tasks that may not write markers) holds only the smoke lock and
  still refuses while a marker exists; `env.json` records which was used. A smoke campaign always
  starts fresh: `cold.ts` and `warm.ts` refuse with `--smoke` when the campaign folder exists.
  `python scripts/cmp/analyze_cmp.py --smoke`.
- The window script itself: `PQID_CMP_SMOKE=1 bash scripts/cmp/quiet_window_cmp.sh` with the same
  `PQID_CMP_V4_*` environment as the window (before the ceremony: the dev key, by default or with
  its paths). It moves the earlier smoke output to `_smoke/old_<UTC stamp>/`
  (`harness/v4/cmp/smoke_reset.ts`; nothing is deleted), then runs `inputs.ts --smoke` with that
  key, the inputs check, warm_cmp, wallet_cmp and cold_cmp with `--smoke` inside one hold of
  `results/v4/BUSY`, then the analysis and the private-string check of `_smoke/`; logs in
  `results/v4/cmp/_smoke/logs/`. `PQID_CMP_WITH_CURVE=1` includes the curve condition;
  `PQID_CMP_SMOKE_NO_MARKER=1` passes `--smoke-no-marker`.
- Smoke numbers are never quoted, never enter the claims ledger, and may be deleted.

## Known limits [A]

- The OS file cache is not flushed between cold runs (as Phase D).
- Windows: no process list is read; the guard sees CPU load and chain ports only.
- snarkJS worker placement across performance and efficiency cores is not controlled.
- The v2o2 and eddsa keys are timing keys without soundness; their proving cost equals that of any
  key for the same circuit, but they are not deployment keys.
- The curve condition measures the curve build in its own fresh process; inside a prove the same
  build may overlap differently with the zkey read.
- The host-pause watchdog covers the slept part of the idle, not the few seconds of power and
  quiet readings, and it is not verified with a real standby on this laptop.
- Wallet CIs at n = 10 are coarse.
- No rapidsnark numbers in this series (the WSL campaign is skipped, D-034).

## Deviations

- None yet.
