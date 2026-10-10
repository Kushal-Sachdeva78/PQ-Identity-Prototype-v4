# E4: scale and ledger (how to run, what is measured)

Engineering notes for TASKS S53 to S58 (experiment E4). Facts, commands and file pointers only.
Labels: [M] measured, [S] estimate from stated arithmetic, [A] assumption, [F] future work.

## Files

| File | Role |
|---|---|
| `harness/v4/scale.ts` | the E4 harness: subcommands `trees`, `anchor`, `verifier`, `besu` |
| `harness/v4/scale_lib.ts` | statistics, deterministic inputs, CPU pinning and read-back, run-time wrappers (Proxy on a LedgerV4 instance, node:crypto hooks), World on an external node |
| `harness/v4/bulk_issuance_tree.ts` | bulk loader for the 10^6-leaf issuance tree (same internal state as incremental inserts) |
| `tests/v4/scale_bulk_tree.test.ts` | checks the bulk loader against `IssuanceTree.insert` (roots, every layer, paths, later inserts) and the quartile function |
| `scripts/besu/setup_qbft.sh` | 4-validator Besu QBFT network on 127.0.0.1: `up`, `status`, `down`, `clean` |
| `results/v4/scale/<subcommand>.json` | full-size results (written in the quiet window) |
| `results/v4/scale/_dry/` | dry runs (small sizes, busy machine): script checks only, never cited |
| `packs/E4_ledger_vs_log.md` | evidence bullets: ledger rather than a transparency log |

No package code changed: `packages/v4/src/*`, `packages/issuer`, `packages/ledger` and the contracts are
used as they are. Instrumentation wraps objects at run time only.

## Common behaviour

- Run with `node --import tsx harness/v4/scale.ts <subcommand> [options]` from the repo root.
- Refuses to start while `results/v4/bench/RUNNING` exists (docs/BENCHMARK_POLICY.md benchmark rule).
- `--dry`: small default sizes, output to `results/v4/scale/_dry/`, and the file's `label` says
  "DRY RUN ... Not a result; do not cite".
- `--n` sets the size of each subcommand: `trees` tree sizes (list), `anchor` epochs, `verifier`
  presentations P, `besu` read rounds R.
- Every output carries `host` (`hostMeta()` from `@pqid/common/meta`: CPU model, cores, RAM, OS
  build, Node), `hostState` (free RAM, uptime), `runtime` (Node, OpenSSL, V8, heap limit, execArgv
  with any local path replaced by `<path omitted>`), `harnessSha256` (the E4 files), `sourceSha256`
  (the contract, every `packages/v4/src/*.ts`, `packages/issuer/src/issuance.ts`, the v4 dev
  verification key) and `keyLabel` ("dev"). No usernames, hostnames or home paths.
- Statistics: median, quartiles by linear interpolation (Hyndman-Fan type 7), IQR, mean, min,
  max, p95, per sample. Timer: `process.hrtime.bigint()`.
- Anvil ports: trees 8750, anchor 8751, verifier 8752, besu 8753 (`--port`). The harness refuses a
  port that is already bound (it never attaches to another run's node, for example the mutation
  campaign's Anvils on 8600+).

## trees (S54)

What it does, per size n (each n in a fresh worker process started with `--expose-gc` and
`--max-old-space-size=<--heap-mib, default 8192>`):

1. Inputs [A]: n + K issuance leaves = pseudo-random field elements from SHA-256(seed:i);
   n + K revocation keys = top 251 bits of SHA-256(seed:i) (the distribution of real revKeys).
   Tree cost does not depend on what a leaf commits to.
2. Issuance tree (depth 32, `IssuanceTree` from `packages/issuer`): `--build auto` inserts one by
   one up to n = 100,000 and uses the bulk loader above that (`--build incremental|bulk` forces
   one). Build wall time is recorded but is set-up, not a benchmark.
3. Revocation IMT (depth 30): `IndexedMerkleTree.bulkBuild` with the first n keys.
4. [M] K = 1000 further single inserts into each tree, each timed (`insertMs`, `insertsPerSec`).
5. [M] Epoch at that size, on a local Anvil (World): the issuer's trees are replaced by the big
   ones, then E epochs (default 5) of `signEpochV4` (roots, IMT snapshot kept to serve witnesses,
   ML-DSA-44 sign) and `anchorEpochV4` (gas estimate, submit, receipt, anchor re-read), with
   minAnchorInterval advanced between epochs (untimed). Isolated components: roots read, IMT
   snapshot, ML-DSA-44 sign of the epoch message.
6. [M] End-to-end issuer routines at that size: `issueCredentialV4` and `revokeCredentialV4`
   (`--issue-k`, default 200).
7. [M] Memory: `process.memoryUsage()` after `global.gc()` at each stage (heapUsed, rss, ...).

Notes:
- `anchorMs` includes ethers' receipt polling (100 ms interval, `ledger.ts` makeProvider) even
  though Anvil mines at once; it is the as-shipped client latency, not chain latency.
- The bulk loader writes `IssuanceTree`'s TypeScript-private fields at run time after checking
  their shape; `tests/v4/scale_bulk_tree.test.ts` proves equality with incremental insertion.

## anchor (S55)

- [M] Gas from receipts on Anvil (World.create, default hardfork) of: the four deployments,
  `registerDID` (issuer; verifier with an origin string), `publishAccreditation` (first and a
  renewal), `publishKemKey` (first and a rotation), `publishEpoch` (first and E - 1 later epochs;
  every epoch issues one credential, every second epoch also revokes one, recorded as
  `revRootChanged`).
- [S] Per day and per year: anchorsPerDay x median later-epoch gas for the 1 h cadence (24 per
  day, the registry's minAnchorInterval, D-012) and the 24 h cadence (1 per day, the epoch
  window); first-day figure includes the first anchor; accreditation renewal amortised over the
  30-day accreditation window (D-014). `--gwei 1,10` adds an ETH/day column at assumed gas prices [A].
- Per write, from the transaction input: calldata bytes, zero and non-zero bytes, pre-Prague
  calldata gas and the EIP-7623 floor 21000 + 10 x (zero + 4 x non-zero); `floorBinds` is true when
  gasUsed equals the floor.
- Fork dependence (observed in the dry runs): Anvil 1.5.1 runs Prague (`anvil_nodeInfo`
  hardFork), where the EIP-7623 calldata floor sets the gas of calldata-heavy writes with little
  storage work (accreditation renewal, KEM key rotation). The Besu network below runs Cancun
  (genesis), where the same KEM rotation costs less. `besu.json` records both.
- Gas does not depend on tree size (the registry stores two 32-byte roots, a signature hash and a
  window).

## verifier (S56)

- Parent (not pinned) starts Anvil on 127.0.0.1, then re-launches the script pinned to CPU 0 and
  waits. The pinned child builds a World on that Anvil (`worldOnRpc`: exactly World.create's steps
  on an external node), one issuer, H honest holders (default 4), one epoch and one verifier, then
  pre-generates P presentations with the honest wallets (distinct sessions; proving not timed).
- Timed: `VerifierV4.verifyReply` for all P replies, in `--passes` passes (default 3), three
  variants per pass, in the fixed order A, B, C in every pass (not randomised):
  - A `asShipped`: LedgerV4 as shipped (ethers JsonRpcProvider, default batchStallTime 10 ms);
  - B `noBatchStall`: same, with the provider's batchStallTime set to 0 for that pass. Label
    wherever its numbers appear: client variant, not shipped: the harness sets ethers
    batchStallTime to 0 for this pass; Windows host, unpinned (D-021); cause of any difference
    not established; loopback, same host (Anvil on this laptop). Fixed order: measured right
    after the as-shipped pass in every pass, not randomised. In the run of 2026-09-27 22:06 to
    22:13 UTC, 17 of the 600 no-stall samples are below 90 ms (minimum 44.9 ms); the as-shipped
    minimum is 117.4 ms (`samples[].totalMs`; counted by `scripts/provenance/audit.py`,
    `noStall.verifierLowTail` in `results/v4/provenance/audit.json`; the 90 ms threshold was set
    after looking at the data);
  - C `cachedReads`: every LedgerV4 read served from an in-memory cache (isolates non-chain cost).
  Warm-up: `--warmup` presentations per variant (default 5), not recorded. The verifier's
  session map is copied before the first pass and put back after each pass, so every variant
  verifies the same replies as fresh sessions. Every decision must be `accepted`, else the run fails.
- Split per presentation: `chainMs` (outermost LedgerV4 reads via a Proxy on the instance),
  `mlDsaMs` (node:crypto verify with an ML-DSA-44 key plus the key import), `mlKemDecapsMs`
  (node:crypto decapsulate), `otherMs` = total minus those [S] (Groth16 verify, Poseidon hashing,
  AES-GCM, JSON, checks). Also `rpcRequestsPerPresentation` and JSON-RPC methods per presentation.
- Isolated components after the passes (same process and pinning, same P presentations):
  `snarkjs.groth16.verify` (the verifier's call) and ML-DSA-44 verify of the epoch statement.
- Throughput: presentations per second from the median, and aggregate (samples / summed time).
  One presentation at a time on one core; no concurrency.
- Observed in the dry runs (client behaviour, not numbers to cite): each LedgerV4 read sends an
  extra `eth_chainId` (ethers network check, no `staticNetwork` in `ledger.ts` makeProvider), so
  half of the verifier's JSON-RPC requests are `eth_chainId`; a verification makes 7 outermost
  ledger reads and 14 JSON-RPC requests; 3 ML-DSA-44 verifications (PoP, accreditation, epoch).

### Pinning (DECISIONS D-021)

- Linux: the child is started with `taskset -c 0 node ...` and reads its affinity back from
  `/proc/<pid>/status` `Cpus_allowed_list`; it refuses to measure unless it is exactly CPU 0.
  Anvil is started by the unpinned parent, so the ledger node is not confined to the verifier's
  core (its mask is recorded too).
- Windows host: no pinning. docs/BENCHMARK_POLICY.md allows v4 tooling one Windows-specific call (the power-state
  query), so `harness/v4/scale_lib.ts` refuses to pin there. Run the verifier series with
  `--no-pin`; the result records `pinned: false` and the series is labelled unpinned. The pinned
  series runs on Linux after HANDOFF K1.
- Launch with `node --import tsx` (a clean execArgv), not `npx tsx`.

## besu (S57)

### Network (scripts/besu/setup_qbft.sh)

- Tools: Besu 26.9.0 (`~/pqid-tools/besu/besu-26.9.0/bin/besu`, POSIX launcher; works under Git
  Bash) on Temurin JDK 25 (`~/pqid-tools/jdk25/jdk-*`); override with `PQID_BESU_HOME`, `JAVA_HOME`.
- `up`: writes `.scratch-v4/besu/qbftConfigFile.json`, runs
  `besu operator generate-blockchain-config --config-file=qbftConfigFile.json --to=networkFiles --private-key-file-name=key`
  (as the Besu QBFT tutorial), copies each validator key into `Node-<i>/data/`, writes
  `static-nodes.json` per node, starts 4 nodes and waits until node 1 reports block >= 3 and 3
  peers (timeout 420 s, `PQID_BESU_WAIT_SEC`). About 47 s on this host from a clean state.
- Genesis: chainId 1337, berlin/london blocks 0, shanghaiTime 0, cancunTime 0 (the contracts are
  compiled for the solc 0.8.28 default EVM, cancun), `zeroBaseFee: true`, gasLimit 30,000,000,
  QBFT blockperiodseconds 2, epochlength 30000, requesttimeoutseconds 4. The only funded account
  is Anvil's public dev account #0 (`0xf39f...2266`): `LedgerV4.deploy` hard-codes it as deployer
  and faucet, so no new EVM key is made or stored.
- Node flags: `--p2p-host=127.0.0.1 --p2p-interface=127.0.0.1 --nat-method=NONE
  --discovery-enabled=false --static-nodes-file=data/static-nodes.json --rpc-http-enabled
  --rpc-http-host=127.0.0.1 --rpc-http-api=ETH,NET,WEB3,QBFT,TXPOOL
  --host-allowlist=localhost,127.0.0.1 --profile=enterprise --min-gas-price=0`. Ports: RPC
  18545-18548, P2P 30313-30316 (`PQID_BESU_RPC_BASE`, `PQID_BESU_P2P_BASE`).
- Deviation from the tutorial: on Windows, Besu 26.9 refuses `--bootnodes=enode://...` with
  "Illegal char <:> at index 5" (it parses the value as a file path). The script wires peers with
  `static-nodes.json` and disables discovery instead (also: no UDP socket).
- Observed on this host: each java.exe listens only on 127.0.0.1 (one RPC and one P2P TCP port),
  no UDP sockets, about 440 MB working set per node, 2 s block interval, 3 peers per node.
- Firewall: all sockets are loopback-only, so no inbound rule should be needed. Whether Windows
  showed a firewall dialog on the desktop cannot be observed from an agent session; check once
  when running `up` in the quiet window and answer "Cancel" / do not allow public networks if asked.
- `down` stops the nodes (MSYS `kill`, then `taskkill /F /T` on the Windows pid if needed) and
  warns if an RPC port still answers. `clean` = `down` + delete `.scratch-v4/besu/`.
- SECURITY: `generate-blockchain-config` writes the 4 validator node PRIVATE keys to
  `.scratch-v4/besu/networkFiles/keys/*/key` and `.scratch-v4/besu/Node-*/data/key`. They are dev
  keys for a throwaway local network. `.scratch-v4/` is gitignored; never commit, copy, attach or
  publish anything under it. Run `clean` after the measurement to delete them.

### Measurement (harness)

- Deploys the v4 registries through `LedgerV4.deploy` on Besu (via `worldOnRpc`) and on a fresh
  Anvil, then on each: issuer registration with PoP, accreditation, one epoch anchor, one verifier
  with a KEM key (gas and write time recorded, `setupWriteGas`).
- [M] Reads: R rounds (default 200, 2 warm-up rounds); in each round, for each target and client
  variant (`asShipped`, `noBatchStall`), the six reads a verifier or wallet makes, timed one by
  one: `resolveDidRecord`, `getPopSignature`, `latestAccreditation`, `currentEpoch`,
  `latestKemKey`, `getMinAnchorInterval`. JSON-RPC requests per call, by method, are recorded.
  `noBatchStall` label: client variant, not shipped: the harness sets ethers batchStallTime to 0
  for this pass; Windows host, unpinned (D-021); cause of any difference not established;
  loopback, same host (every node on this laptop). Fixed order: in every round the no-stall reads
  of a target run right after its as-shipped reads, not randomised.
- [M] Raw JSON-RPC round trips over fetch (no ethers): `eth_blockNumber`, `eth_call` of
  `DIDRegistryV4.resolve`.
- [M] Writes, submit to receipt: W (default 20) `publishKemKey` with a fixed gas limit (no
  estimation) and W value transfers per target, alternating targets; gas and calldata facts.
- [M] Besu block interval (last 60 blocks), validators (`qbft_getValidatorsByBlockNumber`), peer
  count, and a finality check: the hash of every write block re-read after later blocks.
  [A] QBFT finality is immediate (a committed block is never reorganised; Besu QBFT docs).
- EVM facts per target: Anvil `anvil_nodeInfo` hardFork, `eth_config` (EIP-7910) fork id and blob
  schedule, and the Besu genesis milestones.

## Exact commands for the quiet window (full sizes)

Preconditions: no `results/v4/bench/RUNNING`; the mutation campaign and other agents' jobs have
finished (`tasklist | grep -i "node\|anvil\|java"` shows nothing else); AC power; no other
applications. Run the Besu network only for the `besu` step (4 JVMs produce a block every 2 s and
would disturb the other steps).

```bash
cd "<repo root>"
npx vitest run tests/v4/scale_bulk_tree.test.ts
node --import tsx harness/v4/scale.ts trees      # n = 100000 (incremental) and 1000000 (bulk), K = 1000, 5 epochs
node --import tsx harness/v4/scale.ts anchor     # 10 epochs
node --import tsx harness/v4/scale.ts verifier --no-pin   # P = 200, 3 passes, 4 holders; Windows host unpinned (D-021), on Linux drop --no-pin
bash scripts/besu/setup_qbft.sh clean            # start from fresh keys
bash scripts/besu/setup_qbft.sh up
node --import tsx harness/v4/scale.ts besu       # R = 200 read rounds, W = 20 writes per target
bash scripts/besu/setup_qbft.sh clean            # stop the nodes and delete the dev node keys
```

Optional: `node --import tsx harness/v4/scale.ts anchor --gwei 1,10` for an [A] ETH/day column;
`node --import tsx harness/v4/scale.ts trees --n 1000000 --build incremental --out results/v4/scale/trees_1e6_incremental.json`
(incremental build of 10^6 leaves: 3.2 x 10^7 Poseidon hashes) to cross-check the bulk root at full size.

Expected durations [S] (from the dry runs on a busy machine, scaled linearly; quiet-window times
should be shorter): trees 10^5 about 5 to 8 min, 10^6 about 10 to 20 min (bulk build about 2 x 10^6
and IMT about 3 x 10^6 Poseidon hashes at 70 to 110 microseconds each in the dry runs); anchor under
1 min; verifier 20 to 40 min (pre-generation on one core took 5 to 9 s per proof in the dry runs,
so 200 proofs take 17 to 30 min); besu about 5 min plus about 1 min for `up`.

## Dry runs done (script checks, not results)

Files in `results/v4/scale/_dry/` (`trees.json` n = 1000 incremental, `trees_bulk.json` n = 1000
bulk with K = 200, `anchor.json`, `verifier.json` P = 5, `besu.json` R = 5, W = 3). They ran while
a mutation campaign and other agents used the CPU, and while v4 sources were being edited; the
`sourceSha256` field says which code each file ran against. Never cite them.

## Open items

- Anvil runs Prague and the Besu genesis runs Cancun, so gas of calldata-heavy writes differs
  between the two (EIP-7623 floor). Setting Besu to Prague needs the Prague system contracts in
  the genesis [F]; running Anvil with `--hardfork cancun` needs a `startAnvil` option (package change) [F].
- `ledger.ts` makeProvider leaves ethers' network check on (`eth_chainId` per read) and the 10 ms
  batch stall; E4 measures both as shipped; the chainId checks are not removed by any variant.
  The no-stall variant is reported only with its label (client variant, not shipped: the harness
  sets ethers batchStallTime to 0 for this pass; Windows host, unpinned (D-021); cause of any
  difference not established; loopback, same host), in the ledger keys `vFourScaleVerifierNoStall*`
  (`verifier.json`; `vFourScaleVerifierNoStallMinMs` next to the as-shipped
  `vFourScaleVerifierMinMs`) and `vFourScaleAnvilNoStall*Ms`, `vFourScaleBesuNoStall*Ms`
  (`besu.json`, the six reads; their as-shipped counterparts are `vFourScaleAnvil*Ms`,
  `vFourScaleBesu*Ms`), printed in `packs/E4_ledger_vs_log.md` section 4 (provenance audit,
  2026-10-01; DECISIONS D-034). The no-stall measurements always follow the as-shipped ones in a
  fixed order (not randomised). The RPC request counts are JSON-RPC payload elements (a batch
  counts each element); HTTP round trips are not recorded.
- No transparency log was run; the ledger-versus-log comparison in `packs/E4_ledger_vs_log.md`
  is qualitative for the log side [F].
