# Phase D benchmark protocol (v2, v3, v4 proving and verification)

Protocol for TASKS item D and review finding T6. Written 2026-09-27, before any timed run.
Facts, rules and commands only.

- Runner: `harness/v4/bench/` (`inputs.ts`, `child_prove.ts`, `warm.ts`, `cold_campaign.ts`,
  `guard.ts`, `lib.ts`). Analysis: `scripts/bench/analyze.py` (numpy only).
- Results: `results/v4/bench/<campaign>/` (`schedule.json`, `env.json`, `runs.jsonl`), inputs in
  `results/v4/bench/inputs/`, summary in `results/v4/bench/summary.json` and `summary.md`.
- Every campaign records the SHA-256 of this file above the "Deviations" heading (`env.json`,
  `protocolSha256`, LF line ends) and of the whole file per session (`protocolFileSha256`). A
  campaign refuses to resume if the part above "Deviations" changed after it started; a changed
  protocol needs a new campaign.
- Deviations: appended to the last section of this file, dated, before the affected run
  (appending does not change `protocolSha256`).
- Labels: [M] measured, [S] estimate from the stated arithmetic, [A] assumption.

## Conditions

| Version | Circuit wasm | Proving key | Verification key | Key label | Fixed input |
|---|---|---|---|---|---|
| v2 | `circuits/build/credential_auth_js/credential_auth.wasm` | `setup/out/credential_auth_final.zkey` | `setup/out/verification_key.json` | committed v2 key | `harness/fixture.ts` `buildFixtureProofInput()` |
| v3 | `circuits/build/v3/credential_auth_v3_js/credential_auth_v3.wasm` | `setup/out/v3/credential_auth_v3_final.zkey` | `setup/out/v3/verification_key.json` | committed v3 key | `harness/fixture.ts` `buildFixtureProofInputV3()` |
| v4 | `circuits/build/v4/credential_auth_v4_js/credential_auth_v4.wasm` | `setup/out/v4/credential_auth_v4_dev.zkey` | `setup/out/v4/verification_key_dev.json` | dev key | `harness/v4/bench/inputs.ts` `buildFixtureProofInputV4()` |

- Provers: snarkJS 0.7.4 (in Node) and rapidsnark (native binary from `PQID_RAPIDSNARK`).
- Conditions: mode (cold, warm) x version (v2, v3, v4) x prover (snarkjs, rapidsnark) = 12.
- rapidsnark on this host: unavailable (DECISIONS D-001, D-002). With `PQID_RAPIDSNARK` unset,
  every rapidsnark condition is recorded as `blocked: rapidsnark unavailable (D-002)` in
  `schedule.json` and `env.json`, gets no slots, and its ratios are listed as blocked.
- `PQID_RAPIDSNARK` must name the Linux prover binary itself. It is spawned directly with an
  argv array (`prover <zkey> <wtns> <proof.json> <public.json>`), no shell, never `wsl.exe`.
- Artifacts are the committed files. Before a campaign starts, each artifact is hashed and
  compared with its pin (`setup/pins.json` for v2/v3, `setup/pins_v4.json` for v4; the v2 wasm
  has no pin and is hashed only). Any mismatch stops the campaign. All hashes go to `env.json`.
- v4 results carry the label `dev key` until the ceremony key replaces it (Phase I). A re-key
  or circuit change after B7 means new pinned inputs and new v4 campaigns.

## One OS

- All conditions of one results root run on one OS. Today that is native Windows 11 (D-001).
- If rapidsnark becomes available only inside WSL2 or Linux, both provers run there in a new
  results root, with the unchanged runner; ratios never mix OSes (`analyze.py` reads one root).

## Inputs

- One fixed honest input per version, made once by `node --import tsx harness/v4/bench/inputs.ts`.
- v2 and v3: the fixture functions of `harness/fixture.ts`, imported read-only (the inputs of
  `harness/bench_zk.ts` and `harness/v3/compare_v2_v3.ts`).
- v4: the same subject credID, holder secret (123456789), revoked set (`fixtures/revoked-set.json`,
  8 labels), verifier id, nonce (424242) and threshold (18, age_gte) as v2/v3; an 8-leaf issuance tree
  of depth 32 with the subject at index 5 (as v3); the 8 revoked keys in the depth-30 revocation
  IMT; today 20260927, epoch window 20260927 to 20260928, birth date 19840315, expiry 20261226.
- All values are published fixture constants: no key generation, no randomness, no real holder
  secret. Re-running `inputs.ts` gives byte-identical inputs (`--check` verifies this).
- Pin file: `results/v4/bench/inputs/inputs.lock.json`, per version: input file, SHA-256 of the
  compact JSON text, the artifact hashes it was validated against, the expected public signals
  and their SHA-256. `inputs.ts` makes one untimed reference proof per version and refuses to pin
  an input whose proof does not verify. An existing different pin is never replaced without
  `--force`.
- Every run re-checks the input hash and compares its public signals with the pinned ones; a
  mismatch or a failed verification is an error record, never a timing.

## What is timed

Clock: `process.hrtime.bigint()` (monotonic, ns), reported in ms.

| Phase | snarkjs | rapidsnark |
|---|---|---|
| witness | `snarkjs.wtns.calculate(input, <wasm path>, in-memory wtns)` | same call (identical code for both provers) |
| prove | `snarkjs.groth16.prove(<zkey path>, in-memory wtns)` | wall time of `spawnSync(prover, [zkey, wtns, proof.json, public.json])` |
| verify | `snarkjs.groth16.verify(vkey, publicSignals, proof)` | same call |
| wp | witness + prove of the same run | witness + prove of the same run |

- Cold witness includes reading and compiling the circuit wasm in the fresh process.
- Cold snarkjs prove includes reading and parsing the zkey and building the bn128 curve
  (wasm and one worker thread per logical core).
- rapidsnark prove includes the prover's process start, zkey load, proving and proof write.
- verify always runs with the bn128 curve already built in the process: by prove for snarkjs;
  by an untimed `buildBn128()` for rapidsnark (recorded as `aux.curveInitMs`). Both provers'
  verify timings therefore measure the same work.
- Recorded, not timed as a phase (`aux`): time from process start to `main()`, snarkjs import,
  input read and hash, the rapidsnark witness-file write, curve build for rapidsnark, and the
  parent's spawn-to-exit wall time (`childWallMs`).
- Not timed: input generation, artifact hashing, power and quiet-machine readings, idle.

## Cold series

- n = 30 valid runs per runnable condition.
- One run = one fresh Node process (`child_prove.ts`): load, witness, prove, verify, one JSON
  line on stdout, exit. Nothing is shared with any earlier run except the OS file cache.
- Fixed idle: 600 s from the end of the previous run (or from the campaign start) to the spawn.
- 20 s before the spawn: power reading and quiet-machine reading. If the machine is busy, the
  run is postponed in 60 s steps, at most 10 times; after that it runs and stays flagged
  (`quiesce.quiesced = false`). The recorded `idleSec` is the actual idle.
- Power is read again as soon as the child exits.
- Discard rule: a run with a non-AC reading before or after is written with status
  `discarded-battery` (stage `pre` or `post`) and the slot is repeated after a full 600 s idle.
  Discarded runs are kept in `runs.jsonl` and never analysed. 36 non-AC pre-checks in a row
  stop the campaign (resume later).
- Error rule: a child that fails, times out (15 min), does not verify or gives other public
  signals is written with status `error`; the slot is repeated; 3 errors on one slot stop the
  campaign.
- Resumable: rerun the same command; slots with an `ok` record are skipped. `schedule.json`,
  the artifact hashes, the input pins, the rapidsnark state and this file's hash must be
  unchanged, otherwise the runner refuses and a new campaign name is needed.

## Warm series

- One process holds every condition. Warm-up: 5 blocks (not analysed). Then n = 30 blocks.
  Each block runs every runnable condition once, in the recorded shuffled order.
- One iteration makes exactly the calls of a cold run (same table above), so cold and warm
  differ only in process state.
- snarkjs warm: in-process repeats; JIT, wasm and zkey reads (OS page cache) and the bn128
  curve with its worker threads are warm.
- rapidsnark warm: the prover binary loads the zkey in every process, so warm means repeated
  prover invocations with the zkey on a warm OS page cache, driven by a warm Node process for
  witness and verify. The rapidsnark cold/warm ratio for prove therefore measures only the
  page cache and the parent process state.
- Settle before the first block: 600 s idle, then a power reading (must be AC).
- Before each block: power reading, then a 2 s quiet-machine reading (the process sleeps; this
  is also the gap after the power query). Not AC before a block: nothing runs; wait 60 s and
  read again. After each block: power reading; not AC after a block: the block's records are
  written as `discarded-battery` and the block is repeated.
- Not resumable: a restart is a new session in the same `runs.jsonl`; the analysis uses the
  latest complete session (`session-end` record).

## Randomisation

- Blocked order: each block contains every runnable condition exactly once.
- Order within blocks: Fisher-Yates shuffle driven by one mulberry32 PRNG stream per campaign,
  block after block. The full order (slot, block, position, condition) is written to
  `schedule.json` before the first run.
- Pre-registered seeds: `warm` 20260929, `cold_v4` 20260930, `cold_v2v3` 20261001.
- Bootstrap seed: 20260927.

## Power

- Checked before and after every cold run and every warm block (rules above).
- Windows: `(Get-CimInstance Win32_Battery).BatteryStatus` through `powershell.exe`. AC iff
  every battery reports 2. No battery object counts as AC (`no-battery`). Any other code, or a
  failed query, counts as not AC.
- Linux: `/sys/class/power_supply/*/type` and `online`; AC iff a Mains or USB supply reports
  `online = 1`; no mains entry counts as AC (desktop or VM).
- WSL: the same PowerShell query through `powershell.exe`, and only that query.
- The raw code is stored with every run (`power.pre.code`, `power.post.code`, `env.powerCode`).

## Quiet machine

- While a timed series runs, `results/v4/bench/RUNNING` exists (created at the start, removed at
  the end or on interrupt). Rule (docs/BENCHMARK_POLICY.md): only file editing and web research; no builds,
  tests, compiles, LaTeX runs or analyses. A runner refuses to start while a live runner holds
  the marker; a stale marker (dead pid) is replaced.
- Guard reading (`guard.ts`): machine-wide CPU busy percent from `os.cpus()` tick counters over
  3 s while the runner sleeps; threshold 35 % (the value of `harness/bench_env.ts`).
- Windows: no process list is read (docs/BENCHMARK_POLICY.md allows only the power query as a
  Windows-specific call). Linux: process names from `/proc` against a list of build, test,
  compiler, LaTeX, analysis, chain and prover tools.
- Busy means over the threshold or a listed process running. Postpone rule in the cold section.
  The summary counts analysed runs that were flagged busy.

## Order of work and commands

Run from the repo root in a normal terminal, on AC power, with other work stopped.

1. Inputs (once, untimed, after the B7 freeze of the v4 circuit):
   `node --import tsx harness/v4/bench/inputs.ts` then
   `node --import tsx harness/v4/bench/inputs.ts --check`.
2. Warm series, v2, v3, v4 (both provers when available):
   `node --import tsx harness/v4/bench/warm.ts --campaign warm --versions v2,v3,v4 --provers snarkjs,rapidsnark`
3. v4 cold series, both provers:
   `node --import tsx harness/v4/bench/cold_campaign.ts --campaign cold_v4 --versions v4 --provers snarkjs,rapidsnark`
4. v2 and v3 cold series, both provers:
   `node --import tsx harness/v4/bench/cold_campaign.ts --campaign cold_v2v3 --versions v2,v3 --provers snarkjs,rapidsnark`
5. Analysis, after the last runner has exited: `python scripts/bench/analyze.py`

- Set `PQID_RAPIDSNARK=/path/to/prover` before steps 2 to 4 only on a host that has it.
- `cold_campaign.ts` warns, and records `warmSeriesComplete` in `env.json`, when the results
  root holds no complete warm series (the order above is not otherwise enforced).
- Duration [S], from the idle alone (600 s per cold run plus a few seconds of run time):
  step 3 about 5 h with snarkJS only (30 runs), about 10 h with both provers (60 runs);
  step 4 about 10 h with snarkJS only (60 runs), about 20 h with both provers (120 runs).
  Step 2 is the 600 s settle plus 35 blocks of a few seconds per condition.

## Environment record (no usernames, hostnames or home paths)

- Per run (`env` in each `runs.jsonl` line): CPU model, logical cores, RAM GiB, OS name and
  build, Node version, OpenSSL version, V8 version, power status code, UTC timestamp.
- Per campaign (`env.json`): the same per session, snarkjs version, git HEAD (read-only),
  this file's SHA-256, repo-relative artifact paths with SHA-256 and size, input pins, the
  rapidsnark binary's SHA-256 and file name (never its path), blocked conditions.
- Free text (errors, stderr tails) is passed through a filter that replaces the repo path,
  home directory, temp directory, user name and host name.

## Statistics

- Per condition and phase (witness, prove, verify, wp): n, median, Q1, Q3, IQR with type-7
  quantiles (numpy `method="linear"`), min, max.
- Every ratio is a ratio of medians with a percentile bootstrap 95% CI: B = 10,000, fixed seed,
  each condition resampled independently with replacement at its own n; CI = 2.5th and 97.5th
  percentiles of the B ratios; one PRNG stream per ratio (`default_rng([seed, crc32(ratio id)])`).
- Ratios computed (each with CI and both n):

| Ratio | Numerator / denominator | Per | Phases |
|---|---|---|---|
| prover speedup | snarkjs / rapidsnark | mode, version | prove, wp |
| version | v4 / v2 and v4 / v3 | mode, prover | witness, prove, verify, wp |
| cold vs warm | cold / warm | version, prover | witness, prove, verify, wp |

- A ratio with a blocked or empty condition is listed with that status and no number.
- Used rows: cold, every `ok` record; warm, `ok` records of measured blocks of the latest
  complete session. Discarded and error records are counted in the summary, never analysed.
- `analyze.py` refuses to run while `RUNNING` exists in the results root.

## Smoke test (checks the runner; not a result)

- `--smoke` on every script: n = 2 cold runs per condition, idle 5 s, warm n = 3 with 1 warm-up
  block and 5 s settle, no postponing, all output under `results/v4/bench/_tmp/` (gitignored,
  including its own `inputs/`, `RUNNING` and `summary.*`).
- Commands: `inputs.ts --smoke`; `warm.ts --smoke --campaign warm --versions v2,v3,v4 --provers snarkjs`;
  `cold_campaign.ts --smoke --campaign cold_v4 --versions v4`;
  `cold_campaign.ts --smoke --campaign cold_v2v3 --versions v2,v3 --provers snarkjs`;
  `python scripts/bench/analyze.py --smoke`.
- Smoke numbers are never quoted, never enter the claims ledger, and may be deleted.

## Known limits [A]

- The OS file cache is not flushed between cold runs (that needs admin rights). Cold means a
  fresh process after 600 s idle; the zkey and wasm are probably served from the OS cache.
- Warm iterations share one process and are not independent; the bootstrap treats them as
  independent, so warm-based CIs are conditional on that process.
- Cold v4 and cold v2/v3 are separate campaigns on different dates (order fixed by the IRIS
  cutoff, PLAN.md), so cold v4/v2 and v4/v3 ratios compare non-interleaved campaigns
  (`sameCampaign = false` in the summary). The warm series interleaves all three versions in
  one session.
- The host is an interactive laptop with ambient background load; the guard reads CPU load but
  on Windows cannot see which processes run.
- snarkjs uses one worker thread per logical core; timings depend on the scheduler's placement
  across performance and efficiency cores, which is not controlled.
- v4 timings use the dev key; a ceremony key has the same circuit and size, so timings should
  carry over, but that is not measured until Phase I.

## Deviations

- 2026-09-27: the series run earlier than PLAN.md's schedule (the freeze came earlier); the order
  is unchanged: inputs, warm (v2, v3, v4), cold v4, then the E2, E3 and E4 quiet-window
  measurements, then cold v2/v3, then analysis, all from `scripts/bench/quiet_window.sh`.
- rapidsnark is unavailable on this host (DECISIONS D-002): its conditions are recorded as
  blocked by the runners, not measured; every analysed number is snarkJS.
- The inputs' fixture calendar is fixed (`V4_FIXTURE.today` 2026-09-27), so the v4 input is a
  true statement on that date whatever day the series runs; proving time does not depend on it.
- 2026-09-29: rapidsnark became available in WSL2 Ubuntu 24.04 on the same laptop (HANDOFF K1,
  DECISIONS D-031; rapidsnark v0.0.8 commit 81eddf1 built by docker/provision-wsl.sh). Two
  further campaigns run there under this protocol: `warm_wsl` (v2, v3, v4 x snarkJS and
  rapidsnark, interleaved blocks) and `cold_rs_wsl` (v2, v3, v4 x rapidsnark, 30 cold runs each).
  They are analysed on their own (`results/v4/bench_wsl/`), so every ratio inside that summary
  compares runs in one environment; the Windows snarkJS conditions stay in `results/v4/bench/`.
  A ratio across the two environments (for example Windows cold snarkJS over WSL cold
  rapidsnark) is reported only as cross-environment. Power in WSL is read through the same
  PowerShell query (guard.ts).

- 2026-10-03: shared runner library for the D-034 series (chain reads, robustness, end-to-end,
  comparable benchmarks): `harness/v4/lib/` (`rpc_trace.ts`, `markers.ts`, `quiesce.ts`, `seeds.ts`,
  `ports.ts`), tests `tests/v4/lib_*.test.ts`. Campaigns already run are unchanged. For the new
  series:
  - Markers (D-034): a timed series holds `results/v4/bench/RUNNING` in the Windows repository; a
    WSL runner passes `--windows-repo <the /mnt/c path of the Windows repository>`. Untimed
    CPU-heavy work holds `results/v4/BUSY`. A runner built on `markers.ts` refuses to start while
    either marker exists in any repository it checks. Unlike the "Quiet machine" rule above, a stale
    marker is never replaced automatically; a person removes it after checking that nothing runs (a
    pid written from WSL cannot be checked from Windows). Creation is exclusive (O_EXCL, also on
    /mnt/c). `markers.ts run` holds a marker across a multi-step driver; a runner it starts uses
    that marker through `PQID_MARKER_TOKEN` and gets the Windows path in `PQID_WINDOWS_REPO`. A
    marker records campaign, runner label, optional owner label, pid and its namespace, UTC start
    and a random token; no user name, host name or path. A runner that uses a held marker records
    the hold's record plus its own labels (`borrowedBy`).
  - Frozen tools: `cold_campaign.ts`, `warm.ts`, `scale.ts`, `baselines_measure.ts`,
    `revocation_capacity.ts` and `analyze.py` read only `results/v4/bench/RUNNING`, never
    `results/v4/BUSY`. A driver starts any of them only after `markers.ts status` exits 0 for every
    repository, or through `markers.ts exec-if-free`. `cold_campaign.ts` and `warm.ts` (bench/lib.ts
    acquireRunning) refuse a RUNNING marker whose pid is alive and replace one whose pid is dead. A
    WSL Phase D repeat with these runners therefore runs under `markers.ts run --kind RUNNING
    --windows-repo <W> --write explicit-only`, which checks the clone and the Windows repository but
    writes only the Windows copy, while the runner holds the clone's own RUNNING. `scale.ts` refuses
    any RUNNING marker, so an E4 replication cannot run inside a D-034 window: it runs outside one
    with the deviation recorded, or it is dropped.
  - Windows commands: `markers.ts run` and `exec-if-free` resolve the command through PATH and
    PATHEXT before taking a marker and refuse one that would start WSL (wsl.exe, or the bash.exe
    launcher in System32 or WindowsApps that a plain `bash` finds from PowerShell). Drivers are
    started from Git Bash or with the absolute path of Git's bash.exe.
  - Quiet machine: one window gives three verdicts.
    - `quiesced` (`quiesce.ts`) applies to the chain-read, robustness and end-to-end series. It
      excludes the runner's own processes by pid (its own pid, pids it passes, such as the Besu JVMs
      from pid files, and on Linux their descendants), never by name.
      - Linux: a foreign chain process (anvil, besu, java, geth, reth, erigon, nethermind), a
        foreign process on the guard.ts tool list, or a foreign process above 50 % of one core over
        the window makes the reading busy. The 35 % threshold applies to machine busy minus the
        runner's own processes (/proc/stat).
      - Windows: no process list (docs/BENCHMARK_POLICY.md); the 35 % threshold applies to machine-wide busy.
      - Both: a TCP connect to 127.0.0.1 (400 ms timeout) on the D-034 ports and the fixed chain
        ports of committed code (`ports.ts`), minus the runner's own ports; a foreign listener makes
        the reading busy. A gap of more than 1 s between wall-clock and monotonic time over the
        window (host suspend, VM pause or clock step) also makes it busy.
    - The comparable-benchmark row and any Phase D repeat keep the guard.ts rule unchanged: guard.ts
      itself (frozen runners) or the `guardTs` verdict, which replays the guard.ts rule on the same
      window.
    - `machineWideQuiesced` (guard.ts CPU formula, every platform) is recorded as the like-for-like
      flag between Windows and WSL readings.
    - The CPU window stays 3 s. On Linux the record also holds the /proc/stat busy figure, the
      window's jiffies and the steal share. A WSL reading cannot see Windows processes or Windows
      load; the record says so, and nothing else runs on Windows during a WSL window.
  - Round trip: one HTTP POST, which is one call of the ethers provider's `_send`, including ethers'
    network-detection eth_chainId (queued with other requests, or sent directly before the provider
    has started). A request is one JSON-RPC payload element. Transport retries inside one `_send`
    (HTTP 429 throttling) are recorded as `http.attempts`, not as round trips; a 301 or 302 answer
    is not followed for a POST and makes the POST fail.
    - Connections: each attempt records whether it opened a new TCP connection
      (`http.newConnection`, `connects`), seen through Node's diagnostics channels for every agent,
      including an agent swapped in as http.globalAgent. Node 24's global agent closes idle sockets
      after 5 s (keepAlive true, timeout 5000), so a POST after a longer gap reconnects;
      cold-connection and warm figures are separated by this field.
    - Bytes: `http.bytesIn` is the response body after content decoding, with the Content-Encoding
      recorded.
    - Depth: `sequentialDepth` is an upper bound on dependent round trips and is reported next to
      `maxInFlight` and the queue delays.
    - Times: trace times are ms on a monotonic epoch whose UTC time is recorded (`epochUtc`).
    - The E4 counts (`scale_lib.countRpc`) are request counts, not POST counts.
  - Client variants: `asShipped` is exactly `packages/v4/src/ledger.ts` makeProvider and is checked
    against its ethers options before use. `staticNetwork` (ethers option staticNetwork, with the
    chain id given and checked once against a raw eth_chainId, untimed) and `noBatchStall`
    (batchStallTime 0) are labelled "variant, not shipped". Every client record carries the D-034
    endpoint label ("loopback, same host" for 127.0.0.0/8, ::1 and localhost, otherwise "remote";
    the URL is not stored) and whether the client was traced. Traced and untraced figures (for
    example E4's) are reported separately.
  - Seeds: the D-034 registry in `seeds.ts`, looked up by id. The Phase D seeds and 20261002 and
    20261003 (used by cold_rs_wsl and warm_wsl) are never reused. `cold_campaign.ts` and `warm.ts`
    fall back to 20261002 and 20261003 for any campaign name outside their defaults, so every run of
    either runner in a D-034 series passes `--seed` with the value of `seedFor(<id>)`
    (`comparable.coldOrder`, `comparable.warm`; `seedArgs`). The driver checks that schedule.json
    carries that seed (`assertScheduleSeed`) before the first timed slot. Bootstrap seed 20260927.

- 2026-10-03 (provenance audit of 2026-10-01, `results/v4/provenance/AUDIT.md` and `audit.json`;
  recorded after the runs; no result file and no ledger value changes): in `cold_rs_wsl` the UTC gap
  between consecutive runs exceeds the recorded `idleSec` (the runner's monotonic idle) by more than
  5 s in 81 of 89 gaps (median +36.6 s, max +672.1 s, 3,604.5 s in total; each gap in `audit.json`,
  `coldGaps.perGap`); in `cold_v4` and `cold_v2v3` the excess is at most 0.016 s. So for
  `cold_rs_wsl` the Cold series rule "The recorded `idleSec` is the actual idle" does not hold: the
  recorded `idleSec` is a lower bound of the elapsed idle before those runs. Which gap held the
  extra time is not established gap by gap, because a clock step can carry lag from an earlier
  interval. Four `cold_rs_wsl` runs (slots 53, 55, 61, 67) have a UTC span 2.1 to 2.5 s longer than
  the parent's monotonic spawn-to-exit time (`aux.childWallMs`); in the other 86 runs the difference
  is at most 0.9 ms. Two of the four are the fastest wp of their condition (slot 55, v3: 218.5 ms,
  condition median 239.1 ms; slot 61, v2: 175.4 ms, condition median 194.7 ms); if ranks were
  uniform, at least two such minima has a probability of about 0.5 % (computed after seeing the
  data). Without the four runs the cold rapidsnark wp and prove medians move by at most 1.7 ms; the
  wp IQR goes from 19.35 to 15.91 ms for v3 (`vThreeBenchWslColdRsWpIqrMs`), from 19.70 to 17.55 ms
  for v2 and from 16.75 to 17.75 ms for v4 (type-7 quartiles as `scripts/bench/analyze.py`). The
  excess before a run and that run's wp correlate at r = -0.27 (v2, n = 30), -0.19 (v3, n = 29) and
  -0.02 (v4, n = 30), none significant at the 5 % level. The cross-environment cold ratios
  (`vTwoBenchXenvCold*`, `vThreeBenchXenvCold*`, `vFourBenchXenvCold*`) compare Windows runs without
  such gaps against these WSL runs. Cause not established [A]: consistent with the WSL VM's
  monotonic clock not counting time that the wall clock counts (for example host standby). The
  `warm_wsl` settle took 18.3 s longer than 600 s in UTC (Windows `warm`: 1.3 s). The WSL guard
  reads only the VM's own CPU (median 0.0 % in `cold_rs_wsl` and 0.1 % in `warm_wsl`, against 10.7
  to 16.4 % in the three Windows campaigns), so its `quiesced` flags say nothing about Windows-side
  load. Git commits were made on the Windows side during settle periods (e1511cf in the `warm`
  settle; dc30fb6 and 17b5f7a in the `warm_wsl` settle) and during no measured run of the five
  campaigns. The six campaign files in `results/v4/bench_wsl` equal the WSL clone's
  `results/v4/bench/cold_rs_wsl` and `warm_wsl` files byte for byte (sha256). New series follow
  DECISIONS D-034 (one RUNNING marker in the Windows repository; nothing else runs on Windows during
  a WSL window).

- 2026-10-03: chain-read campaign (work-table row "Check the chain-read bottleneck", DECISIONS
  D-034). Protocol addendum: `docs/v4/CHAINREAD.md`. Every env.json records that file's hash above
  its own "Deviations" heading and its whole-file hash, next to this file's hashes. Campaigns:
  - `cr_wsl`: WSL2, pinned, primary (harness CPU 0, Anvil CPU 1, Besu JVMs CPUs 4-7; every thread's
    mask read back before and after every pass).
  - `cr_win`: Windows host, unpinned (D-021).
  - Results go to `results/v4/chainread/<campaign>/<target>/`. Runner: `harness/v4/chainread/`.
    Drivers: `scripts/chainread/run_wsl.sh` and `run_windows.sh`. Analysis:
    `scripts/chainread/analyze.py`.
  - R0 is required in `cr_wsl`: the unchanged `harness/v4/scale.ts verifier` and `scale.ts besu`, E4
    defaults, `--port 8770`, `--out` under `results/v4/chainread/cr_wsl/r0/`. `results/v4/scale/` is
    never written. R0's Anvil runs unpinned and R0 besu meets Besu JVMs still pinned to CPUs 4-7, so
    R0 and the as-shipped S4 series are not like-for-like.
  - D-034 seeds 20261011 to 20261014: conditionOrder orders the conditions within every round or
    block, S4 and S5 blocks included; readOrder orders the S3 cells; verifierPool and walletReads
    order the S4 and S5 presentations. Bootstrap seed 20260927 (this file).
  - Ports: Anvil 8770 in WSL and 8771 on Windows; Besu 18545 to 18548.
  - Markers: a timed campaign holds `results/v4/bench/RUNNING` of the Windows repository for the
    whole campaign through `harness/v4/lib/markers.ts run`. A smoke run (untimed, CPU-heavy) holds
    `results/v4/BUSY`. In WSL either is written only through the /mnt/c path (`--write
    explicit-only`), so the unchanged scale.ts of R0 can run in the clone.
  - Before S1: the 600 s settle and the power rules of this file's warm series. Before every pass:
    the D-034 quiet check, which excludes the run's own chain processes by pid.
  - S2 measures a fresh TCP connection and a fresh provider inside a warm process ("fresh
    connection"); it is not this file's cold series.
  - "Static network" is the ethers v6 option staticNetwork (D-034). Every client or read-plan
    variant other than the as-shipped one is labelled "variant, not shipped"; variant clients use an
    HTTP agent with the options of Node's global agent.
  - A timed run that departs from CHAINREAD.md is refused unless it carries `--deviation "<text>"`
    and a dated CHAINREAD.md Deviations entry exists. Departures are: no pinning, no R0, no Besu
    phase, other sizes, series, settle or CPUs, or source drift.
  - A failed step is resumed in the same campaign with `--from <step>`. Its incomplete output is
    moved aside as `<name>.failed-<UTC>`, kept and never analysed.
  - Existing E4 files, ledger keys and campaigns are unchanged.

- 2026-10-03: robustness row (DECISIONS D-034 and the new D-038 entry). The timed load test
  "verifier library under concurrent load" (`harness/v4/robustness/load.ts`; Anvil on
  127.0.0.1:8780; seed robustness.load 20261021) runs under its own protocol,
  `docs/v4/ROBUSTNESS.md` section 3. Each campaign records that file's normative SHA-256 (text above
  its "## Deviations" heading, LF line ends) next to this file's, and refuses to start unless that
  file, the harness and the code under test are committed and unchanged against HEAD. It holds
  `results/v4/bench/RUNNING` for its whole length and uses this file's power rule, quiet-machine
  reading (through `harness/v4/lib/quiesce.ts`) and bootstrap seed 20260927. It adds a clock-gap
  discard rule (ROBUSTNESS.md 3.9). Per-request errors are counted, never timed, as this file
  requires. Results go to `results/v4/robustness/load/<campaign>/`, analysis is
  `scripts/robustness/analyze_load.py`, and the driver is `scripts/robustness/run_robustness.sh load
  --confirm-quiet`. The package fuzzing (seed 20261022, chain targets on 8781), the circuit and
  witness fuzz (20261023) and the forge fuzz and invariant tests of the v4 registries (20261024) are
  untimed and hold `results/v4/BUSY`. Their per-call times are slow-input flags, not timings. Smoke
  output under `results/v4/robustness/_smoke/` is never quoted.

- 2026-10-03: end-to-end presentation series (DECISIONS D-034 work-table row "Measure the complete
  experience"). Protocol: `docs/v4/E2E.md` (written 2026-10-01, revised 2026-10-03, before any timed
  run of the series; its normative SHA-256 is recorded next to this file's in every e2e env.json).
  Runner `harness/v4/e2e/`, drivers `scripts/e2e/`, analysis `scripts/e2e/analyze_e2e.py`. Results:
  `results/v4/e2e/` (WSL2 with the D-034 toolchain only) and `results/v4/e2e_device_<label>/`
  (devices). Steps for Kushal: `docs/v4/A4_TESTNET.md`. The series inherits this protocol except
  where E2E.md says otherwise:
  - The timed unit is one whole presentation over JSON-RPC (stages S1 to S11, verifier request to
    verifier decision), not proving alone. S8 is the shipped proveV4: in a cold process it includes
    the snarkJS import, and it always includes the zkey and witness hashes and the shape check. It
    is not Phase D wp.
  - Endpoints: Anvil 1.5.1 on 127.0.0.1:8790 and Besu QBFT-4 on 127.0.0.1:18545 to 18548, both
    labelled "loopback, same host". A public testnet is started by Kushal only (approval A4).
  - Cold means a fresh process per presentation that holds both parties, so both parties are cold
    ("one-process cold"). Warm means one long-lived process ("one-process warm") with one
    uninstrumented control iteration per endpoint per block.
  - Before every warm iteration both parties' HTTP agents are replaced (untimed), so every warm
    iteration opens its own connections and cold and warm differ in process state only.
  - A warm block with an iteration error is repeated whole; its other iterations are recorded as
    discarded-block-error and not analysed.
  - The quiet reading is `harness/v4/lib/quiesce.ts` (own processes excluded by pid) instead of
    guard.ts. RUNNING is held in the Windows repository through its /mnt/c path.
  - Seed 20261031 (endToEnd.order) is used as is by every e2e campaign; the bootstrap seed stays
    20260927.
  - Cold idle records also carry idleWallSec, clockGapSec and hostPauseSuspected. The analysis adds
    a sensitivity rerun without runs flagged hostPauseSuspected or quiesce.quiesced = false (the
    docs/v4/CMP.md rule).
  - Groups are never pooled across provers, keys or campaigns. Ratios pair only groups with the same
    prover and key. The instrumentation overhead uses only blocks whose two iterations opened the
    same connections.
  - A non-smoke run needs the ceremony key spec, or --allow-dev-key with every record labelled "dev
    key".

- 2026-10-03: comparable benchmark series (cmp; DECISIONS D-040, D-034 row "Make benchmarks
  comparable"). Addendum `docs/v4/CMP.md`. Its SHA-256 above its own "## Deviations" heading (LF
  line ends) is `b978cea6d3d43a1e21f7e30fd096699672134bd67b880dade08a3df1b1e7b84d` as written. Every
  cmp `env.json` records it as `cmpProtocolSha256`, and the runners refuse to resume if it changes.
  The addendum extends the text above (normative SHA-256
  `d3883a2146e5b0f028f9668376367e7ff7d2406f7096dd87bfddb0aff67fa45f`, which every cmp runner checks
  at start); this text's rules apply unless the addendum says otherwise. Code `harness/v4/cmp/`,
  analysis `scripts/cmp/analyze_cmp.py`, window `scripts/cmp/quiet_window_cmp.sh`, results
  `results/v4/cmp/` (smoke runs under `results/v4/cmp/_smoke/`). Native Windows, snarkJS only:
  - `cold_cmp`: one interleaved cold campaign of v2 (as published, --O1), v2o2, v3, v4 and the EdDSA
    baseline (fixed fixture input), n = 30 each.
  - v2o2: the frozen v2 circuit compiled at --O2 into `results/v4/cmp/artifacts/v2_O2/`, with a
    timing key made by the committed v2 beacon recipe, pinned in
    `results/v4/cmp/artifacts/pins_cmp.json`.
  - v4: the key is given to the runners. That is the ceremony key; the dev key is used only with
    `--allow-dev-key` and is labelled dev.
  - `warm_cmp`: a warm series of the same five circuits (5 warm-up blocks, 30 measured blocks).
  - `wallet_cmp`: a wallet rebuild series, 10 cold runs at 10^5 and 10 at 10^6 credentials. The
    wallet's first Poseidon build (`poseidonInit`: circomlibjs buildPoseidon, single thread) is
    timed as its own phase.
  - Every circuit runs `child_prove.ts` unchanged, so witness, prove, verify and wp keep the meaning
    given above. An optional `curve` condition (off by default) times `buildBn128()` alone in a
    fresh process.
  - Seeds (D-034): cold 20261041, wallet 20261042, warm 20261043; bootstrap 20260927. The conditions
    are put into canonical order before the shuffle.
  - Postponing and the recorded `quiesce.quiesced` follow the guard.ts rule above. The fuller
    `harness/v4/lib/quiesce.ts` reading is recorded as `quiesceDetail`.
  - The cold idle is slept in steps of at most 1 s by a host-pause watchdog. New per-run fields:
    `idleWallSec`, `clockGapSec`, `idleMaxTickGapSec` (the largest gap between two watchdog
    wake-ups) and `hostPauseSuspected` (|clockGapSec| > 5 s or idleMaxTickGapSec > 5 s). On Windows
    performance.now() may count through standby, so clockGapSec alone may not show one. That the
    flag fires on a real standby is not verified [A].
  - A real run refuses: other parameters, another OS, the dev key without `--allow-dev-key`, and
    code, addendum, pins or input lock that are not committed at HEAD (`--allow-uncommitted`
    overrides and is recorded). The window holds one `results/v4/bench/RUNNING` around warm_cmp,
    wallet_cmp and cold_cmp.
  - A primary ratio gets a number only when the cold campaign ended complete with n = 30 per
    circuit. Otherwise its status is "incomplete" and the summary is labelled PARTIAL. Published
    ratio ids start with `cmp/`.
  - Ratios against the campaigns of this file are cross-campaign consistency checks only. The WSL
    cmp campaign is not run (D-034).

- 2026-10-03 (conventions of D-034, 2026-10-01): ceremony key (TASKS I;
  docs/v4/CEREMONY_FOLLOWUP.md). After Kushal's ceremony, `scripts/ceremony/followup.sh`
  (`harness/v4/ceremony/followup.ts`) first runs a check-only pass (verify and key checks, not a
  result). The real run then verifies the key, installs it on new paths
  (`setup/out/v4/*_ceremony.*`), pins it in the new file `setup/pins_v4_ceremony.json` (label
  `ceremony`), and re-runs the C1 security suite and the C3 mutation campaign with it into
  `results/v4/ceremony/`. This work is untimed and holds `results/v4/BUSY`. The dev key files,
  `setup/pins_v4.json`, `results/v4/bench/inputs/inputs.lock.json` and every Phase D campaign stay
  as they are and keep the label `dev key`. The Phase D runners (`harness/v4/bench/`) are not re-run
  with the ceremony key; they name the dev key. The post-ceremony repeat of the v4 conditions is, on
  Windows, the v4 rows of the cmp campaigns `cold_cmp` and `warm_cmp` with the ceremony key
  (`docs/v4/CMP.md`, same prove definition, label `ceremony key`). In WSL it is a v4 repeat with
  snarkJS and rapidsnark; that needs a runner that takes a non-dev key, which does not exist yet. A
  ratio between dev-key and ceremony-key rows compares separate campaigns and is labelled so. The
  Known limits line on the ceremony key ("timings should carry over") stays an assumption until
  those runs exist.

- 2026-10-03: fuzz harness corrections after the fz1 triage (DECISIONS D-043; docs/v4/ROBUSTNESS.md,
  Deviations, 2026-10-03). The fuzzing is untimed, so no rule of this file changes. Two shared
  helpers of the timed series changed, and both give the same results as before:
  - `harness/v4/lib/rpc_trace.ts` `summarize` (spanMs);
  - `harness/v4/chainread/series.ts` (queueMsMax).
  Both now take the largest and smallest values by a loop instead of Math.max(...xs) and
  Math.min(...xs), which throw past about 125,000 elements. No timed campaign has used either file
  yet: results/v4/chainread, e2e and cmp hold smoke output only. Pointer also added under
  docs/v4/CHAINREAD.md, Deviations.

- 2026-10-03 (D-034 exception, DECISIONS D-042): `packages/v4/src/wallet.ts` (checkRequest) and
  `packages/v4/src/session.ts` (requestShapeErrors) were changed. The change fixes two fail-closed
  defects found by the fz1 fuzz campaign and its triage; see docs/v4/ROBUSTNESS.md, Deviations,
  2026-10-03.
  - Old sha256: wallet.ts e5aa0cff..., session.ts d772cc59...
  - New sha256: wallet.ts 8f4a0a40..., session.ts 773b012b...
  - Earlier records (fz1, and E4 under results/v4/scale/) keep the hashes of the code they ran and
    are not rerun. Series run after the commit use the new code.
  - Before any timed series: the tests, the C1 suite and the C3 mutation campaign (post-fix rerun),
    and fz2.
