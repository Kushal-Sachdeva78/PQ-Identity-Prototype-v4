# Chain-read campaign: protocol and how to run

Protocol addendum for the work-table row "Check the chain-read bottleneck" (DECISIONS D-034).
It extends `docs/v4/BENCH_PROTOCOL.md` (a dated pointer is appended under its Deviations) and
reuses its rules where this file says so. Written 2026-10-01, revised 2026-10-03 for the fixed
shared library (`harness/v4/lib/`) and again on 2026-10-03 after the review of the harness, before
any timed run. Facts, rules and commands only. Labels: [M] measured, [S] estimate from the stated
arithmetic, [A] assumption.

- Every results file records the SHA-256 of this file above the "Deviations" heading (LF line
  ends; `env.json` `protocol.chainread.normative`) and of the whole file (`protocol.chainread.file`),
  plus the BENCH_PROTOCOL hashes. Deviations are appended to the last section, dated, before the
  affected run.
- Nothing in `packages/`, `onchain/contracts/v4/`, `harness/v4/scale.ts`, `harness/v4/scale_lib.ts`,
  `harness/v4/bench/` or `results/v4/scale/` changes. Every client variant and read plan is built at
  run time in the harness. The existing E4 results and ledger keys stay as they are.

## 1. Purpose and pre-registered predictions

E4 measured the verifier on the Windows host only, unpinned (`results/v4/scale/verifier.json`:
about 111 ms of a 125 ms verification are chain reads, 14 JSON-RPC requests) and the six registry
reads as distributions only (`besu.json`: about 15 ms per round trip on Anvil and Besu alike).
Round trips (HTTP POSTs), per-request timings, the ethers `staticNetwork` option, batched, parallel
and multicall reads, the wallet's registry reads and any WSL2 run were not measured. This campaign
measures them. Predictions, fixed before the data and reported whatever the results show:

- H1: on the Windows host a round trip costs about one Windows timer quantum (about 15.6 ms)
  whatever the node, while in WSL2 a raw loopback round trip is below 1 ms. The S1 transport cells
  (fetch, node:http keep-alive, raw TCP with noDelay) and the per-POST queue and HTTP times locate
  the cost.
- H2: `staticNetwork` halves the verifier's JSON-RPC requests (14 to 7) but not its POSTs while
  ethers batching is on (the eth_chainId rides in the same POST); with batchMaxCount 1 it halves
  the POSTs too.
- H3: the concurrent read plans cut the sequential depth from 7 to 2 round trips (verifier) and
  from 16 to 4 (wallet read phase).
- H4: in WSL2 the as-shipped verifier spends about 7 x (10 ms batch stall + one round trip) in
  chain reads.

## 2. Files

| File | Role |
|---|---|
| `harness/v4/chainread/run.ts` | runner, one target per process: set-up, equivalence pre-check, pinning, settle, S1 to S5 |
| `harness/v4/chainread/series.ts` | the series, passes, power and quiet rules, records |
| `harness/v4/chainread/target.ts` | Anvil or Besu target, the v4 world, pre-generation, traced client ledgers |
| `harness/v4/chainread/plans.ts` | read plans (sequential, concurrent with prefetch tables), the six reads |
| `harness/v4/chainread/variants.ts` | client settings and the variant tables |
| `harness/v4/chainread/contract.ts`, `ReadBatch.sol` | multicall helper contract ChainReadBatch and the multicall transport |
| `harness/v4/chainread/wire.ts` | logical request capture and multiset comparison |
| `harness/v4/chainread/raw.ts` | raw transports without ethers |
| `harness/v4/chainread/host.ts`, `env.ts`, `io.ts` | pinning and read-back, clock-gap record, environment record, output |
| `harness/v4/lib/` | shared library, used unchanged: round-trip trace and client variants (`rpc_trace.ts`), markers and the `run` wrapper that holds `results/v4/bench/RUNNING` for a driver (`markers.ts`), quiet check (`quiesce.ts`), seeds, ports |
| `scripts/chainread/run_wsl.sh`, `run_windows.sh` | campaign drivers |
| `scripts/chainread/analyze.py`, `test_analyze.py` | statistics (numpy) and its unit test on a synthetic root |
| `scripts/wsl/besu_wsl_setup.sh` | WSL toolchain: Linux JDK 25, Besu 26.9.0, Anvil 1.5.1 (record: `results/v4/chainread/toolchain_wsl.txt`) |
| `tests/v4/chainread_unit.test.ts`, `chainread_anvil.test.ts` | unit tests (no chain; mock JSON-RPC server on an OS-assigned port) and Anvil tests (D-034 port of the OS) |
| `results/v4/chainread/<campaign>/<target>/` | results; `_smoke/` holds smoke output (gitignored, never cited) |

## 3. Environments and toolchain

- E-WSL (primary): WSL2 Ubuntu 24.04 clone `~/pqid-v4`, 8 vCPUs. Toolchain of D-034: Node 24.21.0
  by its absolute nvm path, Anvil 1.5.1 copied from the local `pqid-v4` Docker image
  (`~/pqid-tools/anvil-1.5.1/anvil`), Besu 26.9.0 from the sha256-recorded Windows download, Linux
  Temurin JDK 25.0.4.1+1 (download approved in D-034, sha256 checked), all set up by
  `scripts/wsl/besu_wsl_setup.sh`.
- Pinned topology in E-WSL: after the unpinned pre-generation, every thread of the harness on
  CPU 0, Anvil on CPU 1, the four Besu JVMs on CPUs 4-7, CPUs 2-3 free (`taskset -a -cp`). Every
  thread's mask is read back from `/proc/<pid>/task/*/status` after pinning and before every
  pass; any mismatch stops the run.
- E-WIN (comparison): native Windows, unpinned (D-021), Node 24.18.0, `tools/foundry/anvil.exe`
  1.5.1, Windows Besu 26.9.0 on the Windows JDK 25.0.4.1+1.
- Node differs (24.21.0 in WSL, 24.18.0 on Windows); `env.json` records it and every
  cross-environment ratio names it.
- Traffic is loopback only, labelled "loopback, same host" (D-034).

## 4. Targets and workload

- Targets: a fresh Anvil per Anvil phase (automine, default hardfork; port 8770 in WSL, 8771 on
  Windows, D-034), and the Besu QBFT-4 network of `scripts/besu/setup_qbft.sh` after `clean` and
  `up` (RPC 18545 to 18548, genesis unchanged). The Anvil phase runs with Besu down; the Besu
  phase follows. Target comparisons are between phases.
- Workload: `worldOnRpc` (World.create's steps on the external node), 1 issuer, 4 holders (birth
  dates 19900101 + h, as E4), 1 epoch, 1 verifier with an ML-KEM key, policy age_gte 18 with the
  default credential type; ChainReadBatch deployed last from a fresh role account the ledger funds.
  The ManualClock is set to chain time before each write and then stays fixed.
- Pre-generation, untimed and unpinned: P = 200 verifier replies (holder i mod 4 proves with the
  v4 dev key; label `dev`) and P wallet requests (opened sessions, never answered).

## 5. Client variants and read plans

All variants except the as-shipped ones are client constructions, labelled "variant, not
shipped" wherever their numbers appear (D-034). "Static network" is the ethers v6 option
`staticNetwork` (no eth_chainId before each call; D-034).

Client settings (ethers 6.13.4; all keep cacheTimeout -1 and pollingInterval 100 as shipped;
built with `rpc_trace.ts` `connectClientLedger`, which checks the as-shipped options against
`AS_SHIPPED_OPTIONS` and, for staticNetwork clients, the world's chain id against the node's
eth_chainId once, untimed). HTTP agent: the shipped client uses Node's global agent, as LedgerV4
does; every other client gets its own `http.Agent` with the global agent's options (Node 24:
keep-alive, lifo scheduling, 5 s idle timeout; `target.ts` `agentLikeGlobal`), so a variant
differs from the shipped client in its ethers options only and keeps its own socket pool.
`env.json` records the agent of every client. Variant B (a client variant, not shipped) uses E4's noBatchStall option
(batchStallTime 0), but as a new provider: E4 changed it on the shipped provider through
`_getOption`.

| Client | staticNetwork | batchStallTime | batchMaxCount |
|---|---|---|---|
| asShipped (shipped) | off (eth_chainId per call) | 10 ms | 100 |
| noBatchStall (variant, not shipped) | off | 0 | 100 |
| staticNetwork (variant, not shipped) | on (chain id read once, untimed) | 10 ms | 100 |
| staticNoStall (variant, not shipped) | on | 0 | 100 |
| unbatched (variant, not shipped) | off | (0) | 1 |
| unbatchedStatic (variant, not shipped) | on | (0) | 1 |

Read plans:
- sequential: the role's own shipped order and awaits.
- concurrent: on the first read of a key group, every read the shipped code makes for that group
  starts at once; the role's calls are served from per-(method, arguments) queues. Tables:
  verifier, issuer pair: resolveDidRecord x2, getPopSignature, latestAccreditation, currentEpoch;
  wallet, verifier pair: resolveDidRecord x2, getPopSignature, latestKemKey; wallet, issuer DID:
  latestAccreditation x2, getMinAnchorInterval; wallet, issuer pair: resolveDidRecord x2,
  getPopSignature, currentEpoch. The wallet's checkRequest and checkIssuerData run under
  Promise.all in the concurrent plan (shipped: one after the other).
- multicall: the provider's registry eth_calls issued in one event-loop turn go out as one
  eth_call of ChainReadBatch.aggregate (staticcall per entry); eth_getLogs pass through.

S4 (verifier) and S5 (wallet read phase) variants:

| Id | Name | Client | Plan | Label |
|---|---|---|---|---|
| A | asShipped | asShipped | sequential | as shipped |
| B | noBatchStall | noBatchStall | sequential | variant, not shipped |
| C | staticNetwork | staticNetwork | sequential | variant, not shipped |
| D | staticNoStall | staticNoStall | sequential | variant, not shipped |
| E | concurrentShipped | asShipped | concurrent | variant, not shipped |
| F | parallel | unbatchedStatic | concurrent | variant, not shipped |
| G | batched | staticNoStall | concurrent | variant, not shipped |
| H | multicall | staticNoStall + multicall | concurrent | variant, not shipped |
| I | cachedReads | asShipped + in-memory cache | sequential | variant, not shipped |

S3 cells: each of the six E4 reads (resolveDidRecord, getPopSignature, latestAccreditation,
currentEpoch, latestKemKey, getMinAnchorInterval) alone on each of the six clients (36 cells), and
the read set (all six reads) as sequentialShipped (shipped client, one after another; as shipped),
concurrentShipped, parallel, batched and multicall (5 cells, variant, not shipped).

## 6. Equivalence rules

Before any timing (equivalence pre-check, `equivalence.json`) and for every sample:
- verifier: decision accepted and check vector equal to variant A's;
- wallet: the returned KEM key, statement, path, revocation opening and controller equal to
  variant A's for the same holder;
- the logical JSON-RPC requests (method and parameters, eth_chainId dropped, multicall sub-calls
  expanded) form the same multiset as variant A's (not checked for cachedReads, which reads from
  its cache);
- concurrent plans: every prefetched read was used and no read was unplanned;
- multicall: at least one aggregate carried more than one call, and no sub-call fell back;
- six reads: every result equal (sha256 of the canonical JSON) to the shipped client's.
A violation is an error record, never a timing (section 10).

## 7. Series and sizes

| Series | What | Size | Warm-up | Passes |
|---|---|---|---|---|
| S1 raw JSON-RPC | eth_blockNumber, eth_chainId, eth_call resolve, eth_getLogs DIDRegisteredV4 at registeredBlock, each over fetch, httpKeepAlive and tcpRawNoDelay (12 cells); JSON-RPC arrays of 2, 7 and 14 over httpKeepAlive; 2 and 7 concurrent single POSTs on a keep-alive pool | R = 300 rounds of 17 cells | 2 rounds | 3 of 100 rounds |
| S2 fresh connection | raw httpFresh eth_call; ethers asShipped resolveDidRecord on a new client after the global agent's pooled sockets are closed; ethers staticNetwork resolveDidRecord on a new client with a new agent (the global agent's options); each sample must open at least one new TCP connection and classify every HTTP attempt (else an error record) and records the TCP connect time | n = 30 per cell, 2 s apart | none | 1 |
| S3 reads | 36 per-read cells and 5 read-set cells | R = 200 rounds of 41 cells | 2 rounds | 2 of 100 rounds |
| S4 verifier | VerifierV4.verifyReply, variants A to I | 200 replies x 3 passes = 600 per variant | 5 per variant | 3 |
| S5 wallet read phase | checkRequest + checkIssuerData (no proving), variants A to I | 600 per variant | 5 per variant | 3 |
| R0 E4 replication (WSL) | unchanged `scale.ts verifier` (its measurement child pinned at launch to CPU 0 by scale.ts itself) and `scale.ts besu`, E4 defaults, `--port 8770` and `--out` into `results/v4/chainread/<campaign>/r0/` | E4 | E4 | E4 |

- The 7- and 14-element arrays are the verifier's own requests (with and without eth_chainId):
  a one-POST transport lower bound, not an implementable plan (the getLogs depend on the calls).
- S4: a block runs every variant once on the same reply; the verifier's session map is restored
  before every run, so each run verifies the reply as a fresh session.
- S2 deliberately is not BENCH_PROTOCOL's cold (a fresh process after 600 s idle): it is a fresh
  TCP connection and a fresh ethers provider inside the warm process ("fresh connection").
- R0 is required: it is the pinned Linux verifier series that E4_SCALE.md and D-021 promised.
  Its topology differs from S4: scale.ts starts its Anvil in its unpinned parent, so R0's Anvil
  can run on any vCPU (S4 pins Anvil to CPU 1), and R0 besu runs after the Besu phase against
  Besu JVMs that keep the CPU 4-7 mask the besu step set (`steps.log` records each JVM's mask
  before r0_besu). R0 figures are untraced. R0 and S4 variant A are therefore not like-for-like.
- An emulated fixed-RTT condition is not part of this campaign (D-034 settles the meaning of
  "static network"); the deployment model of section 11 is [S].

## 8. Definitions

- Round trip: one HTTP POST, which is one call of the provider's `_send` (ethers 6.13.4),
  including ethers' own network detection (`harness/v4/lib/rpc_trace.ts`, ROUND_TRIP_DEFINITION).
- Request: one JSON-RPC element.
- Per-POST time (`ms`): `_send` start to its resolution; HTTP time (`h.ms`): the transport call
  inside it; queue delay (`q`): from `send()` to the start of the POST that carries the request.
- New TCP connection: an HTTP attempt whose socket was created during that attempt (Node's
  diagnostics channels "net.client.socket" and "http.client.request.created", no Node module
  patched; `rpc_trace.ts`). Ethers samples take it per POST from the trace (`tcpConnects`, and
  `tcpConnectsUnknown` for attempts that could not be classified); raw transports from the
  library's process-wide connection recorder filtered by the target's port (`newConnections`).
  Every ethers client's agent closes idle sockets after 5 s (Node 24's global agent options, used
  for every client, section 5), so a sample after a pause (for example the first after the pass
  checks) can include a reconnect; it is recorded per POST, not removed.
- Sequential depth: the longest chain of non-overlapping POSTs in one presentation (greedy by end
  time).
- chainSumMs: sum of the role's outermost ledger-read durations; chainUnionMs: time during which
  at least one outermost read was pending (equal for sequential plans). otherMs = totalMs minus
  chainUnionMs, ML-DSA and ML-KEM time [S] (overlap makes it approximate for concurrent plans).
- Warm: a persistent provider and agent with keep-alive sockets, after warm-up.
- Clock: `process.hrtime.bigint()`.

## 9. Order, randomisation, seeds

- Per target: equivalence pre-check, pinning (WSL), settle, S1, S2, S3, S4, S5. Per campaign: the
  Anvil phase, then the Besu phase; in WSL R0 verifier runs after the Anvil phase and R0 besu
  inside the Besu phase. Campaigns: cr_wsl, then cr_win, the same day.
- Every round or block contains every cell or variant exactly once, in a mulberry32 Fisher-Yates
  order (`harness/v4/bench/lib.ts`). Seeds (D-034, `harness/v4/lib/seeds.ts`), one stream per seed,
  drawn in this order:
  - conditionOrder 20261011, the order of the conditions within every round or block: the S1 cell
    order per round, then the S2 cell order per round, then the variant order of every S4 block
    (pass by pass), then the variant order of every S5 block;
  - readOrder 20261012: the S3 cell order per round;
  - verifierPool 20261013: the S4 presentation (reply) order per pass;
  - walletReads 20261014: the S5 presentation (wallet request) order per pass.
  Bootstrap seed 20260927 (unchanged). `schedule.json` records this mapping per seed (`streamUse`)
  next to the registry's wording.
- Warm-up uses the canonical order and draws nothing. `schedule.json` is written before the first
  timed sample.

## 10. Markers, quiet machine, power, settle, host pause, errors

- Markers (D-034): a timed campaign holds `results/v4/bench/RUNNING` of the Windows repository
  for the whole campaign: the driver re-runs itself under `harness/v4/lib/markers.ts run --kind
  RUNNING`, and `run.ts` uses that hold (`PQID_MARKER_TOKEN`); started alone, `run.ts` takes the
  marker itself. In WSL the driver passes `--windows-repo <the Windows repository's /mnt/c path>
  --write explicit-only`: both repositories are checked for RUNNING and BUSY, and only the
  Windows copy is written. The clone gets no copy because the unchanged `scale.ts` (R0) refuses to
  start while the clone's own `results/v4/bench/RUNNING` exists; nothing else runs in the clone
  during the window. Every runner refuses to start while RUNNING or BUSY exists. A smoke run is
  untimed but CPU-heavy, so it holds `results/v4/BUSY` the same way (`markers.ts run --kind BUSY`;
  in WSL also only the Windows copy, so R0's `scale.ts --dry`, which reads only RUNNING, still runs).
- Operator conditions (`--confirm-quiet`, recorded): AC power; other applications closed (on
  Windows other programs can raise the timer resolution, which would move H1); no other agent
  jobs, builds, tests or chain nodes; during the WSL campaign nothing runs on Windows (the WSL
  quiet reading cannot see Windows load).
- Settle: 600 s with nothing running after set-up and pinning, before S1 (BENCH_PROTOCOL warm
  settle), then a power reading.
- Before every pass: power reading (not AC: wait 60 s and read again, at most 36 times); quiet
  reading (`harness/v4/lib/quiesce.ts`, 3 s) that excludes the run's own Anvil and Besu processes
  by pid and their ports; affinity read-back when pinned (a mismatch stops the run). After every
  pass: power reading (not AC: the pass is written as `discarded-battery` and repeated, at most 3
  repeats); affinity read-back again when pinned (`affinityPost`; a mismatch flags the pass
  `affinityMismatchPost`, kept and counted). Busy readings are flagged, kept and counted.
- Host pause and clock gaps, per pass (`clock` in `passes.jsonl`): the wall-clock span minus the
  monotonic span (flag above 1000 ms), the longest gap between two samples beyond the planned
  spacing (flag above 2000 ms) and the longest sample (flag above 10 s). Flagged passes are kept,
  listed and counted in the summary.
- Errors: a JSON-RPC error, a failed POST, a rejected decision, a wallet refusal or an equivalence
  violation is an error record (`errors.jsonl` and the sample with status `error`); the sample is
  retried once; 3 error records in the kept passes of one series stop the run. Error records of a
  discarded-battery pass are counted apart (`discardedErrors`) and do not count toward the stop.
- Stopped pass: when a pass stops (the 3-error rule, a failure, or a signal), its samples and
  POST lines are written with status `stopped` (POST lines `stopped: true`; the sample's own
  status kept as `sampleStatus`) and its pass record has status `stopped` and the reason; on a
  signal `env.json` gets status `interrupted`. Stopped samples are kept and never analysed.
- Protocol departures: a timed run with an option that departs from this file (`--no-pin`,
  `--allow-source-drift`, a subset of `--series`, other sizes, holders, settle or CPU topology;
  in the drivers `--skip-r0` and `--anvil-only`) is refused unless it carries `--deviation
  "<text>"`, which `steps.log` and `env.json` record; a dated entry in the Deviations list below is
  written before such a run.

## 11. Statistics (`scripts/chainread/analyze.py`, numpy)

- Only targets whose `env.json` status is `completed` are analysed; every other target, and every
  `<target>.failed-<UTC>` folder a resume set aside (section 14), is listed under `excluded`.
- Used samples: status `ok`. Error, retried, discarded and stopped samples are counted. Per-POST
  distributions take only the POST lines of used samples.
- Per cell: n, median, Q1, Q3 (type 7, numpy `method="linear"`), IQR, mean, min, max, p95.
- POSTs, requests, requests by method and sequential depth per sample: reported as exact
  distributions (min, median, max), expected to be invariant per variant.
- Ratios of medians variant / asShipped (S4, S5 totalMs and chainUnionMs; S3 per read; S1 per
  transport): percentile bootstrap 95% CI, B = 10,000, seed 20260927,
  `default_rng([seed, crc32(ratio id)])`, each condition resampled at its own n.
- Chain share = chainUnionMs / totalMs (median of the per-sample ratio).
- Per-presentation chain cost = wallet read phase + verifier chain time [S, sum of medians].
- Deployment model [S]: median totalMs on loopback plus median sequential depth x RTT, for RTT
  20, 50 and 100 ms. It keeps the batch stall, the queue delays, the loopback round trips and the
  node's own time that a deployment also pays, so it is an upper bound.
- Labels in every summary: v4 dev key; loopback, same host; traced ethers clients (wrapper code
  runs per request; R0's E4 figures are untraced); "as shipped" or "variant, not shipped" per
  variant; S1 cells "raw transport (no ethers), not the shipped client".
- Ratios between E-WSL and E-WIN are labelled cross-environment (D-032) with both toolchains named.
  In E-WSL the harness is pinned to one CPU, so totalMs and otherMs are not compared across
  environments; chain time, POSTs, requests and depth are. `--cross-target <target>=<a>,<b>`
  takes one target from other campaigns (a target re-run under another name); `cross_env.json`
  records the mapping.

## 12. Outputs

`results/v4/chainread/<campaign>/<target>/` (smoke: `results/v4/chainread/_smoke/...`):
- `env.json`: environment (no usernames, hostnames or home paths), versions, git HEAD, protocol
  hashes, harness and source hashes, E4 source comparison, seeds, ports, target facts, workload,
  pinning read-back, settle, operator conditions, marker, counts, status.
- `schedule.json` (with `streamUse`), `equivalence.json`, `passes.jsonl` (status, stop reason,
  power, quiet reading, affinity before and after, clock per pass), `errors.jsonl`.
- `s1_raw.jsonl.gz`, `s2_fresh.jsonl.gz`, `s3_reads.jsonl.gz`, `s4_verifier.jsonl.gz`,
  `s5_wallet.jsonl.gz`: one line per sample (gzip members, one per pass).
- `posts.jsonl.gz`: one line per POST of every ethers sample: `s` series, `v` variant or `c` cell,
  `p` pass, `a` attempt, `i` reply index or `r` round, `tr` try, `k` POST index, `t0` and `t1`
  (ms from the sample start), `ms`, `n` requests, `b` JSON array, `m` methods, `q` queue delay per
  request, `d` direct network detection, `ok`, `re` JSON-RPC errors, `h` transport (`at` attempts,
  `st` statuses, `ms`, `bo` request body bytes, `bi` response body bytes after decoding, `cn` new
  TCP connections, `nc` per attempt: new, reused or null), `err`.
- Raw samples (S1, S2 raw cell): `bytesOut` and `bytesIn` are body bytes for every transport (HTTP
  headers not counted); `newConnections` is the count of new TCP connections to the target
  during the call.
- `<campaign>/r0/e4_verifier.json`, `e4_besu.json` (WSL, unchanged E4 format);
  `<campaign>/logs/` (`steps.log`, one log per step, `toolchain.<UTC>.txt` per attempt: binary
  paths with `~`, versions, the Anvil sha256, the JDK and Besu versions); WSL:
  `<campaign>/COPY_MANIFEST.<UTC>.sha256` per copy back; `<campaign>/summary.json`, `summary.md`;
  `results/v4/chainread/cross_env.json`, `cross_env.md`. After a resume:
  `<campaign>/<target>.failed-<UTC>/` and `<step>.failed-<UTC>.log` (kept, never analysed).

## 13. Smoke (checks the runner; never a result)

`--smoke`: P = 3, 1 pass, 1 warm-up, S1 and S3 4 rounds, S2 2 per cell, 2 s settle, no power rule,
holds `results/v4/BUSY` (section 10), output under `results/v4/chainread/_smoke/` (gitignored).
Smoke numbers are never quoted and never enter the ledger. The WSL smoke pins (`run.ts --pin`:
the harness, Anvil and the 4 Besu JVMs, every thread read back before and after each pass) and
runs R0 as `scale.ts verifier --dry` and `scale.ts besu --dry` (with `--out` under
`_smoke/<campaign>/r0/`). Before the quiet window both drivers are smoked on both targets, with
the markers free and ports 8770 or 8771 and 18545 to 18548 free, and every `steps.log` line must
show exit 0:

```bash
bash scripts/chainread/run_windows.sh --campaign smoke_win --smoke --with-besu   # Windows, Anvil 8771 and Besu
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash /mnt/c/<repo>/scripts/chainread/run_wsl.sh --campaign smoke_wsl --smoke --with-besu
python scripts/chainread/analyze.py --smoke --campaign smoke_win
python scripts/chainread/analyze.py --smoke --campaign smoke_wsl
```

## 14. Commands

WSL (from the Windows side). The clone's origin is the Windows repository; before the run it is
fast-forwarded to the commit that holds this file (`git -C ~/pqid-v4 pull --ff-only origin v4`,
from a script run inside WSL), and `run_wsl.sh` refuses unless the clone's HEAD equals the Windows
repository's and the chain-read code is byte-identical. The toolchain set-up is idempotent (a tool
already in place is checked and kept); it ran on 2026-10-01 (`results/v4/chainread/toolchain_wsl.txt`).

```bash
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash /mnt/c/<repo>/scripts/wsl/besu_wsl_setup.sh
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash /mnt/c/<repo>/scripts/chainread/run_wsl.sh --campaign cr_wsl --confirm-quiet
```

Windows (Git Bash, repository root):

```bash
bash scripts/chainread/run_windows.sh --campaign cr_win --confirm-quiet
```

Resume after a failed or interrupted step: run the same driver with the same campaign and
`--from <step>` (WSL: anvil, r0_verifier, besu_reset, besu_up, besu, r0_besu; Windows: anvil,
besu_reset, besu_up, besu). The driver refuses an unknown step, a step before `--from` that has
not completed, and a completed target or R0 file at or after `--from` (never redone). Before any
Besu step that runs, the network is made again (besu_reset, besu_up), so a resumed Besu step
always starts on a fresh QBFT network. The output
of a step that runs again and did not complete is moved aside to `<name>.failed-<UTC>` in the
clone and in the Windows copy (kept, never analysed), so the campaign keeps one folder per target
and the analysis and `--cross` commands below work unchanged. The WSL copy back adds missing
files, skips identical ones, lets `logs/steps.log` grow and refuses to overwrite anything else.
A new campaign name is needed only to redo a completed target; `analyze.py --cross-target` then
maps that target to it.

Tests (outside any window; the Anvil test binds the D-034 chain-read port of the OS):

```bash
npx vitest run tests/v4/chainread_unit.test.ts tests/v4/chainread_anvil.test.ts
python -m unittest discover -s scripts/chainread -p "test_analyze.py"
```

Analysis (Windows, after both campaigns; never while a marker exists):

```bash
python scripts/chainread/analyze.py --campaign cr_wsl
python scripts/chainread/analyze.py --campaign cr_win
python scripts/chainread/analyze.py --cross cr_wsl,cr_win
```

Duration [S] from E4's numbers (Windows round trip about 15.6 ms, verifier 125 ms as shipped,
200 proofs in about 250 s unpinned) and the [A] prediction of under 1 ms per WSL round trip plus the
10 ms stall: per target about 8 min set-up and pre-generation, 10 min settle, S1 1 to 2 min, S2
3 min, S3 3 to 5 min, S4 4 to 7 min, S5 7 to 14 min, about 1 min of pass checks. cr_wsl about
1.8 h including R0 (verifier pre-generation of 200 proofs on one vCPU, 17 to 30 min) and Besu
start; cr_win about 1.6 h. Total about 3.5 h.

## 15. Known limits [A]

- The variants are client constructions; the concurrent plans emulate a code change through
  prefetch tables derived from today's verifier and wallet code. Guards: drained queues,
  multiset equality, equal outputs. If that code changes, the tables must be re-derived.
- The wallet's concurrent plan reads the issuer records before the request is validated, which
  changes what an RPC provider observes on refusal paths (D-026). It is measured as a variant only.
- `staticNetwork` removes ethers' per-call check that the node did not switch chains; statement
  binding is unchanged (LedgerV4 caches the chain id per instance).
- Multicall covers eth_call only; ChainReadBatch is new bytecode outside C1 and C3 and is never
  part of the v4 system.
- With stall 0, batching depends on event-loop timing; batch sizes and depth are recorded.
- Pinning after the unpinned pre-generation differs from E4's pin-at-launch (JIT and GC state);
  warm-up mitigates it, and R0 keeps E4's method.
- A WSL2 vCPU is not a fixed physical core; Windows background load reaches the VM.
- conditionOrder is one stream for S1, S2 and the S4 and S5 blocks, so changing the S1 or S2 size
  changes the S4 and S5 variant orders (never their presentation orders); `schedule.json` holds
  the orders used.
- Loopback is not a real network.

## Deviations

- 2026-10-03: series.ts (queueMsMax) and harness/v4/lib/rpc_trace.ts `summarize` (spanMs) now take
  the maximum and minimum by a loop instead of Math.max(...xs) and Math.min(...xs), with the same
  values (fz1 triage; docs/v4/ROBUSTNESS.md, Deviations, 2026-10-03). No option or rule of this file
  changes, and no timed run had used them.
- 2026-10-03 (before cr_wsl and cr_win): the code under test differs from E4's recorded hashes in
  `packages/v4/src/wallet.ts` and `packages/v4/src/session.ts` only (DECISIONS D-042: a null or
  undefined request is refused by name; the policy errors are pushed one by one). Neither change
  is on a read path: the verifier's registry reads, the wallet's read phase and every client
  variant run the same code as E4, and the honest request behaves identically (D-042 regression
  tests; the post-fix suite and mutation rerun gave 130/130 verdicts and 59/59 rows equal, D-044).
  Both campaigns therefore run with `--allow-source-drift` and the deviation text "D-042 package
  fix (wallet.ts, session.ts refusal paths only; no read path changed); CHAINREAD.md Deviations
  2026-10-03". env.json records the differing files (sourceVsE4). R0 and the as-shipped series stay
  comparable with E4 only as stated there (cross-environment, R0 not like-for-like).
- 2026-10-04 (after the campaigns; provenance audit): `summary.json` and `cross_env.json` now record
  `generatedBy`, `generatedUtc`, the sha256 of `scripts/chainread/analyze.py` and each analysed
  target's measured start and end (from its env.json). The analysis was rerun for cr_wsl, cr_win
  and the cross comparison; every earlier field is identical, so the 670 chain-read ledger keys keep
  their values and only their recorded file sha256 and commit changed.

