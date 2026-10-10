# End-to-end presentation series (protocol)

Protocol for the work-table row "Measure the complete experience" (DECISIONS D-034). Written
2026-10-01 and revised 2026-10-03, before any timed run of this series. Facts, rules and commands
only. It inherits every rule of `docs/v4/BENCH_PROTOCOL.md` that is not changed here.

- Runner: `harness/v4/e2e/` (`campaign.ts`, `child_present.ts`, `presentation.ts`, `setup.ts`,
  `lib.ts`, `testnet_check.ts`), shared library `harness/v4/lib/` (round-trip trace, markers,
  quiet check, seeds, ports). Analysis: `scripts/e2e/analyze_e2e.py`. Drivers: `scripts/e2e/`
  (`quiet_window_e2e_wsl.sh`, `testnet_window.sh`, `device_run.sh`, `smoke_windows.sh`).
- Results: `results/v4/e2e/<campaign>/` (`schedule.json`, `env.json`, `deployments.jsonl`,
  `runs.jsonl`), window logs in `results/v4/e2e/logs/<window>/`, summary in
  `results/v4/e2e/summary.json` and `summary.md`.
- Every campaign records the SHA-256 of this file above "## Deviations" (LF line ends) and of the
  whole file, and the same two hashes of `BENCH_PROTOCOL.md`. A campaign refuses to resume when a
  normative part changed; a changed protocol needs a new campaign name.
- Deviations: appended to the last section, dated, before the affected run.
- Labels: [M] measured, [S] estimate from the stated arithmetic, [A] assumption.
- Public testnet steps, costs and privacy notes, and the device steps: `docs/v4/A4_TESTNET.md`.

## 1. Scope

One presentation of the shipped v4 code, timed from the verifier's request to the verifier's
decision. Both parties run in one process; there is no network between them (transport bytes are
recorded). The chain is reached over JSON-RPC.

| Stage | Party | What it covers | Time source |
|---|---|---|---|
| S1 | verifier | `VerifierV4.newRequest` (the verifier ledger's chainId; in a cold run ethers' network detection) | marks around the call |
| S2 | transport | `JSON.stringify` and `JSON.parse` of the request; bytes recorded | marks |
| S3 | wallet | `present()` call to the end of `checkRequest` (request copy, verifier DID record, PoP record and `DIDRegisteredV4` log, KEM key and `KemKeyPublishedV4` log, ML-DSA verifies of the PoP and the KEM statement, date and policy checks) | instance wrapper on `checkRequest` |
| S4 | wallet | end of `checkRequest` to the start of `checkIssuerData` (credential selection, ML-DSA credential signature) | instance wrappers |
| S5 | wallet | `checkIssuerData` (`latestAccreditation` twice, issuer record, PoP, accreditation, `currentEpoch`, `getMinAnchorInterval`; path and IMT witness from the stored blob; no issuer contact) | instance wrapper |
| S6 | wallet | ML-KEM-768 encapsulation (the `node:crypto` `encapsulate` call) | hook |
| S7 | wallet | end of S5 to the input mark, minus S6 (date and predicate checks, transcript SHA3, HKDF, Poseidon circuit input) | input mark |
| S8 | wallet | input mark to the first `aes-256-gcm` `createCipheriv` after it: snarkJS witness and Groth16 proof as the shipped `proveV4` does them, which includes the dynamic import of snarkJS in a cold process, a SHA-256 of the zkey file and of the in-memory witness, and the wallet's own shape check | hook |
| S9 | wallet | that `createCipheriv` to the return of `present()` (AES-256-GCM seal, reply object) | marks |
| S10 | transport | `JSON.stringify` of the reply; bytes recorded; `verifyReply` gets the JSON string | marks |
| S11 | verifier | `VerifierV4.verifyReply` (decapsulation, HKDF, AES-GCM open, issuer record, PoP, accreditation, chainId, `currentEpoch`, Poseidon checks, Groth16 verify, ML-DSA epoch signature) | marks |

- Code: `packages/v4/src` and `onchain/contracts/v4` unchanged. Instrumentation is run-time only:
  instance wrappers on one wallet object, a Proxy in front of each party's `LedgerV4`, wrappers
  on the `node:crypto` functions that `pqc.ts` reads at call time (ML-DSA verify and key import,
  `encapsulate`, `decapsulate`, `createCipheriv`), and the round-trip trace of
  `harness/v4/lib/rpc_trace.ts` on each party's provider.
- The wallet's `cfg.inputHook` is set to a function that records the time and never reads or
  changes the circuit input. `tests/v4/e2e_present.test.ts` shows the decision and every public
  signal except the per-session nonce (signal 3) are the same with and without it. S7 plus S8 is
  reported too, for a reader who prefers the coarser split.
- The decision must be accepted with every check true; anything else is an error record.

## 2. Conditions

| Endpoint | Node | Where | Started by |
|---|---|---|---|
| `anvil` | Anvil 1.5.1 (the pqid-v4 Docker image's binary, D-034), automine, chain id 31337 | 127.0.0.1:8790 (D-034 port) | the orchestrator, stopped at the end |
| `besu` | Besu 26.9.0 QBFT, 4 validators, 2 s blocks, chain id 1337, Linux JDK 25 | 127.0.0.1:18545 to 18548 | `scripts/besu/setup_qbft.sh up` (unchanged), inside the window |
| `custom` | a public testnet over HTTPS; expected chain id fixed on the command line | the internet | Kushal only (approval A4, `docs/v4/A4_TESTNET.md`) |

- Client: `LedgerV4` as shipped (ethers 6.13.4, `cacheTimeout -1`, `batchStallTime` 10 ms, no
  `staticNetwork`, Node's global HTTP agent options). The harness asserts the shipped provider
  options and refuses otherwise. No client variant is part of this series: there is no `--client`
  option (D-034: variants such as no batch stall are "variant, not shipped" and belong to the
  chain-read row).
- Prover: snarkJS (the wallet default) is required. rapidsnark (`--prover rapidsnark`,
  `PQID_RAPIDSNARK`, WSL only) is optional and gets its own campaigns.
- Key: the run's key spec (`--key-spec <repo-relative JSON>`); every artifact is hashed and checked
  against its pin, and a key other than dev must pin all three. D-034: the WSL and testnet campaigns
  run after the key ceremony with the ceremony key. A non-smoke run with the dev key needs
  `--allow-dev-key`; its records carry the label "dev key" and it is repeated after the ceremony.
- Environment: one per results root. `results/v4/e2e/` is WSL2 Ubuntu 24.04 on the laptop of
  D-001 with the D-034 toolchain: Node 24.21.0 called by its absolute nvm path (the orchestrator
  refuses another Node version in WSL), OpenSSL 3.5.8, Anvil 1.5.1, Besu 26.9.0, Linux JDK 25.
  The testnet campaigns run from the same WSL clone into the same root (their endpoint label keeps
  them apart). Device runs use their own roots (`results/v4/e2e_device_<label>/`). The orchestrator
  refuses a non-WSL2 run into `results/v4/e2e/`, whether the root is the default or named with
  `--results-root`. Windows runs are smoke runs only.
- A `custom` endpoint on the local network (a phone reading a laptop's node, section 15) is
  labelled "local network, another host"; over http it needs `--allow-http-custom`.

## 3. Fixed state (one set-up per endpoint per session)

- Made by the orchestrator, untimed, with `SystemClock` for every party and no dev RPC, so the
  same code runs on Anvil, Besu and a testnet.
- Local endpoints: `LedgerV4.deploy` with a fresh governance EVM account; role accounts funded by
  the dev deployer (Anvil key #0; Besu's genesis funds it). Custom endpoint: the four registries
  are deployed with `compileRegistriesV4()` and the funder key (section 11).
- Parties: governance ML-DSA key; one issuer with a PoP-registered DID record and a governance
  accreditation; 8 holders issued (the presenting holder born 19840315, the Phase D fixture date;
  the others 19700101, 19751111, 19800229, 19881203, 19920707, 19950505, 20000101); one anchored
  epoch (24 h window starting 10 min before the set-up time) and its published blob (D-019); one
  verifier with origin `https://e2e.verifier.example`, a PoP record and an ML-KEM-768 statement
  valid 365 days. Policy `age_gte` 18, default credential type. `minAnchorInterval` 1 h.
- Re-anchor: when less than 2 h of the epoch window remain, the orchestrator anchors the next
  epoch untimed during a cold idle (never needed by a campaign shorter than about 22 h). A warm
  session that would need one stops instead (its child holds the old blob); a restart is a new
  session.
- Public facts only go to `deployments.jsonl`: set-up id, endpoint record, chain id, addresses,
  `fromBlock`, transaction hashes, gas used, effective gas price (custom), durations, sweeps.
- Secrets stay in the orchestrator's memory. The child receives only what a wallet and a verifier
  hold (holder secret, credential, issuer public key, blob, governance public key, verifier DID,
  controller, origin, ML-KEM key pair as PKCS8, registry addresses, `fromBlock`, RPC URL, key
  paths) as one JSON line on its stdin; nothing secret goes to argv, the environment, files or
  logs. The child sets the wallet's holder secret at run time and refuses when it does not open
  the credential's `holderCommit`. Every line is scanned for every secret (and for the custom URL,
  its path segments and query values) before it is written; a hit stops the campaign.

## 4. What is timed and counted

- Clock: `process.hrtime.bigint()` (monotonic, ns) on one base per process, reported in ms.
- `endToEndMs` = S1 start to S11 end minus the two agent switches (section 5), which are
  assignments of pre-built agents and are recorded as `agentSwitchMs`. The stages add up to
  `endToEndMs`.
- Per stage and per party: outermost `LedgerV4` calls by method; round trips; JSON-RPC requests by
  method; batch POSTs; HTTP attempts and status codes; bytes sent and received; new TCP or TLS
  connections (`connects`, attributed per POST attempt by the trace) and the per-party agent count
  (`connections`), which must agree; ML-DSA verify and key-import counts and time; ML-KEM
  encapsulation and decapsulation time.
- Round trip (harness/v4/lib/rpc_trace.ts): one HTTP POST = one call of the provider's `_send`,
  including ethers' network detection; request = one JSON-RPC payload element; retries inside one
  POST (HTTP 429) are `http.attempts`, not extra round trips; a 301 or 302 to a POST is not
  followed and fails the POST.
- S11 split as E4: `chainMs` (outermost verifier reads), `mlDsaMs` (verify and key import),
  `mlKemDecapsMs`, `otherMs` [S] by subtraction (AEAD open, Poseidon, Groth16, JSON). The wallet's
  S3 + S5 get the same split without decapsulation.
- Request and reply sizes (JSON bytes), proof size, SHA-256 of the public signals.
- Garbage collection (instrumented iterations): every V8 collection that starts inside the timed
  window (a `perf_hooks` observer on entry type `gc`, untimed bookkeeping), attributed to the stage
  it starts in like the hook events: per stage `gcCount` and `gcMs`, per run `gcTotals` (count, ms,
  major collections) and the raw list (stage, start, duration, kind). The observer is removed for
  control iterations.
- The zkey hash: after S11 (cold) or once at `ready` (warm), untimed, one SHA-256 of the zkey file
  with the shipped helper (`aux.zkeySha256Ms`), the share of S8 that is that hash [S]. The witness
  hash inside S8 (about 0.56 MB for 17,512 wires) is not timed separately.

## 5. Cold and warm

- Parties: one verifier and one wallet per endpoint, each with its own `LedgerV4.connect` (its own
  shipped provider) and its own `http.Agent` and `https.Agent`, configured as Node's global agents.
  `http.globalAgent` and `https.globalAgent` are set to the verifier's agents before S1 and S10 and
  to the wallet's agents before S2, so each party keeps its own connection pool as two processes
  would.
- Keep-alive: Node 24's global agent options (copied) keep a socket for reuse but close it after
  5 s without traffic (shipped behaviour). In a cold run the verifier connects in S1 (network
  detection) and connects again in S11 when the wallet's stages took more than about 5 s; the
  wallet connects in S3. Recorded per POST and per stage.
- Warm connection state is fixed: before every warm iteration (instrumented and control), untimed,
  the child destroys both parties' agents and makes new ones, so every warm iteration opens its own
  connections (the wallet in S3, the verifier in S11; S1 sends nothing because `LedgerV4` caches the
  chain id) and its connection state does not depend on its place in the schedule. Cold and warm
  then differ in process state only (BENCH_PROTOCOL warm definition). Each warm record carries
  `partyIdleMsAtStart` (ms since each party's last POST ended, read before the reset).
- Cold means both parties cold: the verifier is as fresh as the wallet (network detection in S1,
  cold JIT and session store in S11). A real first presentation usually meets a long-running
  verifier, so the analysis also reports the wallet part (S2 to S10) and the verifier part (S1 +
  S11) per mode.
- Cold run: one fresh child process holding one endpoint's fresh verifier and wallet. snarkJS's
  bn128 curve is not built before S8 (recorded as `bn128CurveCachedBeforeS1`); a cold run whose
  curve was already built before S1 is an error record (`errorKind` "cold-definition") and the slot
  is repeated. The verifier's Groth16 verify in S11 uses the curve the wallet's prove built (as the
  Phase D cold verify).
  Untimed before S1 and recorded as `aux`: process start to main, stdin read, imports, state load
  (blob parse and tree rebuild), `LedgerV4.connect` (solc-js compiles the registry source: a
  harness cost a shipped wallet would not have), verifier construction (vkey read), wallet
  construction. Untimed after S11: raw round trips (5 x `eth_blockNumber` and one
  `eth_getBlockByNumber` through `fetch`, its own connection pool), the latest block's age, an
  isolated Groth16 verify of the same proof, one timed SHA-256 of the zkey, `maxRSS`. Label:
  "one-process cold".
- Warm: one long-lived child holding every endpoint's parties, built once. Each iteration makes the
  cold run's calls with a new verifier session and the same wallet object (its date log, KEM and
  serial memories persist). `LedgerV4` caches the chain id, so a warm S1 sends no request (shipped
  behaviour). Label: "one-process warm".
- Control iteration (warm only): the same presentation with the ledger proxies removed, the traces
  detached, the wallet wrappers and the input mark removed and the crypto hooks and the GC observer
  uninstalled; it gives `endToEndMs` and the per-party new connections only (label
  "uninstrumented control").

## 6. Cold series

- n = 30 valid runs per endpoint. A block holds each endpoint once, in shuffled order;
  `e2e_cold_wsl` = `anvil` and `besu`, 60 runs.
- Fixed idle: 600 s on the monotonic clock from the end of the previous run (or from the end of
  the set-up) to the spawn. A due re-anchor happens inside the idle.
- 20 s before the spawn: power reading and quiet reading. Busy: postpone in 60 s steps, at most
  10 times, then run flagged (`quiesce.quiesced = false`).
- Quiet reading (`harness/v4/lib/quiesce.ts`): machine CPU busy minus the runner's own processes
  at most 35 %; no foreign chain process, listed tool or heavy process (above 50 % of one core);
  no foreign listener on the known chain ports; wall and monotonic clocks within 1 s over the 3 s
  window. Own processes are excluded by pid, never by name: the orchestrator and its descendants
  (the Anvil it started, the warm child), and the four Besu JVMs from the pid files of
  `setup_qbft.sh`. A foreign Anvil or Besu is flagged. The record also carries the guard.ts rule
  replayed on the same window (`guardTs`) and the machine-wide flag.
- Power is read again when the child exits. A non-AC reading before or after: `discarded-battery`,
  slot repeated after a full idle; 36 non-AC pre-checks in a row stop the campaign.
- Host pause: each record carries `idleSec` (monotonic), `idleWallSec`, `clockGapSec` =
  idleWallSec - idleSec and `hostPauseSuspected` = |clockGapSec| > 5 s (the names of
  `docs/v4/CMP.md`), the same in `idle` with the Linux uptime clock, and `runClock` for the spawn to
  exit. A flagged idle keeps the run (flagged and counted). A gap above 2 s inside the run makes it
  `discarded-pause`; the slot is repeated.
- Error rule: child failure, timeout (300 s), wallet refusal, decision not accepted, RPC trouble
  (a failed POST, a JSON-RPC error or an HTTP 429), holder-commit mismatch, a broken cold
  definition: status `error` with its `errorKind`, slot repeated after a full idle; 3 errors on one
  slot stop the campaign.
- Resumable: run the same command; slots with an `ok` record are skipped. The schedule's
  configuration, the normative protocol hashes, the artifact hashes, the package and contract
  sources and the prover must be unchanged. A resumed session makes a new set-up; every record
  carries its `setupId`.

## 7. Warm series

- Settle: 600 s idle, then a power reading (must be AC); a `settle` record carries the same clock
  fields as a cold idle.
- Blocks: 5 warm-up blocks (not analysed), then 30. Each block holds every endpoint instrumented
  once and its uninstrumented control once, in shuffled order.
- Before each block: power reading, then a 2 s quiet reading. Not AC: wait 60 s. After each block:
  power reading; not AC: the block is `discarded-battery` and repeated. A block clock gap above
  2 s: `discarded-pause`, repeated. An iteration error: the block stops, the failing iteration is
  written as `error` and the iterations of that block that ran before it as
  `discarded-block-error` (kept, never analysed), and the whole block is repeated; 3 errors on one
  block stop the session.
- Not resumable: a restart is a new session in the same `runs.jsonl`; the analysis uses the latest
  complete session (`session-end` record).

## 8. Randomisation and seeds

- Registered seed (D-034): `endToEnd.order` = 20261031, used as it is by every e2e campaign
  (`schedule.json` `config.seed`): mulberry32 and the bench lib schedule (Fisher-Yates from the end,
  one stream for all blocks of a campaign, warm-up blocks first). No derived or ad-hoc seed. The
  full order is written to `schedule.json` before the first run.
- Campaign names: `e2e_cold_wsl`, `e2e_warm_wsl` (required); `e2e_cold_testnet`,
  `e2e_warm_testnet` (Kushal); `e2e_cold_wsl_rs`, `e2e_warm_wsl_rs` (optional rapidsnark); devices
  `e2e_cold_<label>`, `e2e_warm_<label>`.
- Bootstrap seed: 20260927.

## 9. Markers and the quiet window

- A real series holds `results/v4/bench/RUNNING` (D-034). A WSL runner holds it in the Windows
  repository through its /mnt/c path (`--windows-repo`) and in the clone. Every runner refuses
  while `RUNNING` or `results/v4/BUSY` exists in any repository it checks.
- The WSL driver (`scripts/e2e/quiet_window_e2e_wsl.sh`) holds `RUNNING` for the whole window
  (Besu start, both campaigns, Besu stop) through `harness/v4/lib/markers.ts run`; the campaigns
  use the hold it passes down. `env.json` records the hold (copies, holder, borrowed).
- The testnet driver holds it the same way with owner "Kushal"; a device holds it in its own
  checkout.
- Nothing else runs on Windows during a WSL window: the WSL quiet check cannot see Windows load.
- A smoke run holds no marker and refuses while one exists.

## 10. UTC midnight

- No warm block runs between 23:50 and 00:10 UTC (05:20 to 05:40 IST); the orchestrator waits (the
  wallet date log and the verifier session TTL change at midnight). A cold run refused for a date
  reason is an error record and is repeated.

## 11. Public testnet (custom endpoint)

- Kushal starts the run (approval A4); operator never transacts on a public network. The
  orchestrator refuses an internet custom endpoint without https, an interactive terminal and
  `--confirm-public-testnet`.
- URL hook: `--rpc env:NAME` reads the URL from the variable NAME; `--rpc <url>` is accepted only
  for a loopback or local-network URL with no path, query, fragment or user info. An internet URL
  always comes from the environment (`--rpc env:NAME`, or `--rpc-env NAME`, default
  `PQID_E2E_RPC_URL`), since some providers put the API key in the host name and argv lands in
  shell history. The funder key comes only from the environment (`--funder-env`, default
  `PQID_E2E_FUNDER_KEY`). Both are read once and deleted from the process environment. The funder
  is a fresh test-only key. The secret scan covers the URL, its host name and host labels, path
  segments and query values; the orchestrator refuses an `--endpoint-label`, campaign name or
  device label that contains any of them.
- Caps: refuse when `maxFeePerGas` exceeds `--max-fee-gwei` or the set-up estimate exceeds
  `--max-total-eth` (estimate [S]: the gas of `results/v4/scale/anchor.json`, each write's gas
  limit est + est/5 + 5000, x 1.3). One campaign makes one set-up; a resumed session makes another.
- Every funder transaction (deploy, funding) uses fresh fee data, is refused above the fee cap
  and is waited for at most `--tx-timeout` (600 s). The governance, issuer and verifier writes run
  inside the shipped `LedgerV4.rawWrite`, which has no timeout of its own; together they are
  given at most `--writes-timeout` (1,800 s).
- After the last set-up write the orchestrator waits until the `finalized` block reaches it
  (`--finality-timeout`, 1,800 s). No writes happen during timed runs. Leftover role balances are
  swept back to the funder at the end. When the set-up fails after a role account was funded (a
  write, a timeout, an RPC error, the finality wait), the funded roles are swept at once (a role
  with a pending stuck transaction is swept with that nonce and a doubled fee, which replaces it),
  and `deployments.jsonl` gets a `setup-failed` record (transactions sent) and a `sweep` record
  with `partial` true.
- The URL is recorded only as its SHA-256 with the `--endpoint-label` and where it came from;
  addresses and transaction hashes are recorded (they are public; see A4_TESTNET.md for the
  anonymity question).
- Rate limits and RPC errors are errors (section 6), never silently retried by the harness.
  ethers' `FetchRequest` retries an HTTP 429 inside one POST; that shows as `http.attempts` and
  status 429 and makes the run an error.

## 12. Environment record and labels

- `env.json`: protocol hashes, key and artifact hashes, package and contract source hashes,
  harness file hashes, snarkJS, ethers, solc and circomlibjs versions, the shipped client options
  and the round-trip definition, and per session the device record (CPU model, logical cores, RAM,
  platform, architecture, OS name, kernel, WSL flag, Node, OpenSSL, V8, optional
  `--device-label`, emulation flag), the endpoint records (client version, chain id, block period,
  Besu validator count, transport, the Anvil binary's version and SHA-256), the set-up ids, the
  marker hold and the Node and Anvil expectations. No usernames, hostnames or home paths.
- Labels on every record: "loopback, same host" (anvil, besu), "public RPC endpoint over the
  internet" (testnet) or "local network, another host"; "one-process cold" or "one-process warm";
  "both parties in one process"; "dev key" until the ceremony key; "prover: rapidsnark" on
  rapidsnark campaigns; "uninstrumented control" on control iterations.
- Emulation: the orchestrator refuses non-smoke runs when the process architecture disagrees with
  the CPU the OS reports; a non-x64 run also needs `--device-label`. Emulated timings are never
  results.

## 13. Statistics (`scripts/e2e/analyze_e2e.py`)

- Rows: cold, `ok` records (one per slot: the last `ok` record if a slot has more); warm, `ok`
  records of measured blocks of the latest complete session, one per session and slot,
  instrumented and control separately. Error and discarded records (battery, pause, block error)
  are counted per campaign and per endpoint, with the error kinds (wallet, verifier, rpc, marks,
  cold-definition, child, timeout) and the HTTP 429 count, never analysed. Flagged runs (not
  quiesced, host pause in the idle) are analysed and counted.
- Groups: endpoint label x mode x instrumented or control x prover x key label. The same group in
  two campaigns (for example a dev-key campaign and its rerun under a new name) is never pooled:
  it is kept apart under each campaign name and listed in `notPooled`. Sessions of one resumed
  campaign stay pooled.
- Per group and metric (S1 to S11, `endToEndMs`, the S11 split, S7 + S8, the wallet part S2 to
  S10, the verifier part S1 + S11, chain share, raw round trips, GC ms per run): n, median, Q1, Q3,
  IQR (type 7), min, max, p95, and a percentile bootstrap 95 % CI of the median.
- Sensitivity per group: `endToEndMs` again without the runs flagged `hostPauseSuspected` or
  `quiesce.quiesced = false` (the rule of `docs/v4/CMP.md`).
- New connections: `endToEndMs` by the run's new connections (both parties), and S3, S5 and S11 by
  the stage's own, each split 0 versus 1 or more, with n.
- Ratios of medians with percentile bootstrap 95 % CIs (B = 10,000, seed 20260927, one stream per
  ratio, as BENCH_PROTOCOL.md), only between groups with the same prover and key label: cold /
  warm per endpoint (`endToEndMs` and each stage; separate campaigns, `sameCampaign` false); besu /
  anvil per mode (same campaign, interleaved, `sameCampaign` true); custom / besu per mode
  (different campaigns, not interleaved; public RPC endpoint over the internet versus loopback,
  same host; `sameCampaign` false); instrumentation overhead = warm instrumented / warm control
  `endToEndMs` per endpoint, over the blocks whose two iterations opened the same connections
  (paired and unmatched block counts reported).
- Chain share per run = (wallet + verifier outermost chain ms) / `endToEndMs`, summarised as above.
- Round trips, requests and new connections per stage and party: the modal value per endpoint and
  mode, every run that differs listed.
- Output: `summary.json` and `summary.md` in the results root. The analysis refuses while `RUNNING`
  or `BUSY` exists. Ledger keys only after Kushal sees the numbers.

## 14. Smoke test (checks the runner; not a result)

- `--smoke`: cold n = 2 per endpoint by default (`--n 1` allowed), idle 5 s, lead 2 s; warm 1
  warm-up + 3 blocks by default, settle 5 s; no postponing; Node and Anvil versions not enforced;
  any key; output under `<results root>/_smoke/` (the folder carries its own ignore file); no marker
  held.
- Smoke numbers are never quoted and never enter the claims ledger.

## 15. Devices

- An ARM64 Linux board or an Apple Silicon Mac runs `scripts/e2e/device_run.sh` (the same
  campaigns with `--device-label`, `--results-root results/v4/e2e_device_<label>` and a
  device-local Anvil, or the testnet). An Android phone only under Termux with a Node that links
  OpenSSL 3.5 or later; its endpoint is the testnet or a laptop node on the local network; phones
  use `--power-rule record-only` and the controls of `docs/v4/PHONE_PROTOCOL.md` section 3 that
  apply. With `--endpoint custom`, `device_run.sh` first runs the read-only
  `harness/v4/e2e/testnet_check.ts` with the same endpoint, chain id and caps, and for an internet
  endpoint asks for a typed YES before anything is sent. It scrubs user name, host name and home
  paths from the logs before it packs them. An iPhone cannot run the full presentation with the
  current code (no Node runtime). Steps: `docs/v4/A4_TESTNET.md`. Device results stay out of IRIS
  submission material until Kushal decides (D-031 K3).

## 16. Known limits [A]

- Both parties in one process and on one host: no wallet-verifier network; transport bytes only.
  Agent switching gives each party its own connection pool but not its own event loop or CPU.
- The verifier's Groth16 verify reuses the bn128 curve the wallet's prove built.
- Loopback endpoints have near-zero network delay ("loopback, same host"); the Besu JVMs share the
  cores with the measured process.
- Public RPC endpoints add provider-side caching, load balancing (a lagging node can fail a
  single-block `eth_getLogs`), rate limits and time-of-day variation.
- The OS file cache is not flushed between cold runs; solc-js compiles the registry source in each
  cold child before S1 (untimed, but it can perturb garbage collection and raises `maxRSS`; the
  collections inside the window are recorded per stage).
- Cold `endToEndMs` has both parties cold; it is not "a user's first presentation to a running
  verifier". The wallet part (S2 to S10) is the cold-wallet reading.
- Warm iterations open new connections by design (agents replaced before each); a long-lived
  wallet that reuses a socket within 5 s would be faster in S3 by one connect [A].
- WSL2 virtualisation; the WSL quiet check cannot see Windows load.
- Instrumentation (Proxy, hooks, trace wrappers) adds time to the stages; the warm control
  estimates it, cold runs have no control.
- ethers private internals are wrapped at run time; the harness asserts ethers 6.13.4 and refuses
  another version.
- The cold snarkJS proving stage in WSL has no same-environment Phase D cold counterpart (Phase D
  cold snarkJS ran on Windows): any comparison is cross-environment.
- S8 is not Phase D `wp`: it adds the snarkJS import (cold), the zkey and witness hashes and the
  shape check of the shipped `proveV4`; any comparison with Phase D is labelled cross-environment
  and different work. `aux.zkeySha256Ms` estimates the zkey-hash share [S].
- The chain-read row also measures wallet registry reads on WSL loopback with the same toolchain;
  which one is cited is decided with Kushal.
- Dev key until the ceremony key replaces it.

## Commands

WSL window (operator, after the commit with this harness is in the WSL clone and the toolchain
is in place with `bash scripts/wsl/besu_wsl_setup.sh` inside WSL; from Git Bash on Windows, with
the laptop on AC, sleep and Windows Update off, every Windows application closed):

```
MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -- bash "/mnt/c/<Windows repository>/scripts/e2e/quiet_window_e2e_wsl.sh" \
  --confirm-quiet --key-spec <repo-relative ceremony key spec>
```

It holds `RUNNING` (Windows repository and clone), checks the toolchain and that the clone runs the
Windows repository's code, starts Besu, runs `e2e_cold_wsl` then `e2e_warm_wsl` (both with
`--endpoints anvil,besu`), stops Besu and copies the two campaign folders and the logs to the same
paths in the Windows repository with a SHA-256 manifest (never over an existing folder).
`--from warm` repeats only the warm campaign (Besu is reset and started again; the cold folder is
not copied again). A folder that already exists in the Windows repository is skipped when it is
identical; a resumed cold campaign differs, and `--replace-copy` updates it after a check that the
clone's copy only appends to it. `--copy-only --window-stamp <stamp> [--replace-copy]` repeats only
the copy (no marker; refused while `RUNNING` or `BUSY` exists). `--smoke` (optionally
`--with-besu`) runs the same steps as a smoke test.

Single campaigns (inside the clone, Node by its absolute path):

```
NODE=$HOME/.nvm/versions/node/v24.21.0/bin/node
$NODE --import tsx harness/v4/e2e/campaign.ts --mode cold --campaign e2e_cold_wsl --endpoints anvil,besu \
  --windows-repo "/mnt/c/<Windows repository>" --anvil-bin "$HOME/pqid-tools/anvil-1.5.1/anvil" --key-spec <spec>
```

Public testnet: `docs/v4/A4_TESTNET.md` (Kushal). Devices: the same document. Analysis (Windows
repository, after the copy): `python scripts/e2e/analyze_e2e.py`.

Smoke on Windows (Anvil only, dev key): `bash scripts/e2e/smoke_windows.sh` (cold n 1, warm 1 + 2
blocks, then `analyze_e2e.py --smoke`).

Duration [S]: cold 60 runs x (600 s idle + about 30 s pre-check and child) = about 10.5 h; warm
600 s settle + 35 blocks x 4 iterations x 1.5 to 3 s plus about 5 s of readings per block = about
15 to 20 min; Besu start and stop and two set-ups per campaign about 5 min. About 11 h in total,
avoiding 05:20 to 05:40 IST for the warm series.

## Deviations

- None yet.
