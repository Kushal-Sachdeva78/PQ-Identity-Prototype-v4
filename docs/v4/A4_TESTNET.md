# Approval A4: the end-to-end series on a public testnet, and on a device

Steps for Kushal. operator never transacts on a public network (docs/BENCHMARK_POLICY.md), so Kushal starts
both runs described here himself. Protocol: `docs/v4/E2E.md` (sections 11 and 15). Labels: [M]
measured, [S] estimate from the stated arithmetic, [A] assumption, [VERIFY] check before relying
on it.

## 1. What the testnet run measures

The same presentation as the WSL series (verifier request, the wallet's registry reads, witness
and proof, ML-KEM session, the verifier's reads and checks), but every registry read goes over
HTTPS to a public RPC endpoint on the internet instead of a node on the laptop's loopback. Two
campaigns, in this order:

| Campaign | Runs | Set-up |
|---|---|---|
| `e2e_cold_testnet` | 30 cold runs (fresh process, 600 s idle before each) | one (about 5.2 M gas) |
| `e2e_warm_testnet` | 600 s settle, 5 warm-up + 30 blocks, each block one instrumented and one uninstrumented presentation | one more (about 5.2 M gas) |

Each record carries the label "public RPC endpoint over the internet". The loopback WSL runs stay
the lower bound labelled "loopback, same host".

## 2. What you need (once)

1. A testnet. Sepolia (chain id 11155111) is assumed below [A]; any EVM testnet with the Cancun
   opcodes, the `finalized` block tag and single-block `eth_getLogs` works.
2. A fresh EVM account used only for this run (for example made with `cast wallet new`, or any
   wallet app). Never a key that holds real funds or that you use elsewhere.
3. Test ETH for that account from a faucet of your choice: 0.2 test ETH covers both campaigns at a
   fee of up to about 10 gwei (section 3). Faucet terms change [VERIFY]: some ask for a sign-in or
   a small mainnet balance; read section 5 before you choose one.
4. An HTTPS RPC URL for the testnet (a provider's free tier; the account and its API key are
   yours). Check the free tier's request and `eth_getLogs` limits against section 3 [VERIFY].
   Pick an `--endpoint-label` that contains no part of the URL's host name (for example
   `sepolia-a` rather than the provider's name when the host is `<name>.example.com`): every
   record carries the label and the secret scan would stop the run.
5. On the laptop: the WSL clone `~/pqid-v4` at the commit that contains this harness (operator
   fast-forwards it), and the key spec of the ceremony key (D-034; or use `--allow-dev-key`, which
   labels every record "dev key").

## 3. Costs [S]

Set-up gas per campaign [S], from `results/v4/scale/anchor.json` (Anvil, Prague) [M] used as an
estimate: deploy of the four registries 2,304,822; issuer DID record 1,110,102; verifier DID
record 1,175,158; first accreditation 164,406; first KEM key 220,925; first epoch 145,231; three
funding transfers 63,000. Total about 5.18 M gas per set-up, plus 63,000 for the sweep at the end
(about 60,000 more per re-anchor, which a campaign shorter than about 22 h never needs).

| Fee (maxFeePerGas) [A] | Spent per set-up [S] | Spent, both campaigns [S] | Funder balance a set-up needs up front [S] |
|---|---|---|---|
| 1 gwei | about 0.0052 ETH | about 0.010 ETH | about 0.008 ETH |
| 10 gwei | about 0.052 ETH | about 0.104 ETH | about 0.078 ETH |
| 30 gwei | about 0.156 ETH | about 0.311 ETH | about 0.235 ETH |

- "Up front" is what the orchestrator checks before it starts (`estimateSetupCost` in
  `harness/v4/e2e/lib.ts`): the deployment, the three transfers and the role balances (each role's
  write gas limits x maxFeePerGas x 1.3); the role balances not used are swept back at the end.
- Suggested caps: `--max-fee-gwei 10 --max-total-eth 0.1`. The set-up refuses when the current
  maxFeePerGas or the estimate is above them, and nothing is sent.
- Test ETH has no market value, so the money cost is zero when the faucet and the RPC free tier
  cost nothing.
- RPC load [S] (code reading, not measured): about 25 HTTP POSTs carrying about 50 JSON-RPC
  requests per presentation (wallet about 17 round trips, verifier about 8); 30 cold + 70 warm
  presentations make about 5,000 requests, plus about 180 probe requests, set-up reads and receipt
  polling (every 4 s during set-up): about 5,500 to 6,500 requests over about 6 h, about 500 of
  them single-block `eth_getLogs`.

## 4. Steps (in a WSL terminal on the laptop)

Before: laptop on AC, sleep and Windows Update off, every Windows application closed (the run
shares the CPU with Windows), nothing else running. Avoid 05:20 to 05:40 IST for the warm part (the
script waits through it if needed).

```
cd ~/pqid-v4
read -rs PQID_E2E_RPC_URL; export PQID_E2E_RPC_URL            # paste the HTTPS URL, Enter (not echoed)
read -rs PQID_E2E_FUNDER_KEY; export PQID_E2E_FUNDER_KEY      # paste the test-only private key (hex), Enter
NODE=$HOME/.nvm/versions/node/v24.21.0/bin/node
$NODE --import tsx harness/v4/e2e/testnet_check.ts --expect-chain-id 11155111 --max-fee-gwei 10 --max-total-eth 0.1
bash scripts/e2e/testnet_window.sh --endpoint-label sepolia-<provider> --expect-chain-id 11155111 \
  --max-fee-gwei 10 --max-total-eth 0.1 --key-spec <repo-relative ceremony key spec> \
  --windows-repo "/mnt/c/<Windows repository>"
unset PQID_E2E_RPC_URL PQID_E2E_FUNDER_KEY
```

- `testnet_check.ts` is read-only: it sends and signs nothing. It prints the chain id, client,
  fees, the funder's balance, the cost estimate, whether the endpoint answers a JSON-RPC batch and
  a single-block `eth_getLogs`, five raw round trips, and `readyToRun`. The window script runs it
  again first and stops on any problem.
- The window script then asks you to type YES. From there it holds `results/v4/bench/RUNNING`
  (in the clone and, through `--windows-repo`, in the Windows repository), runs the cold campaign,
  then the warm campaign, sweeps leftover role balances back to the funder after each, and copies
  both campaign folders and the logs into the Windows repository with a SHA-256 manifest.
- Duration [S]: cold 30 x (600 s idle + about 30 s) = about 5.3 h; two set-ups with a wait for the
  `finalized` block (Sepolia about 13 to 20 min each [A]); warm about 25 min. About 6 to 6.5 h.
- An internet RPC URL always goes through the environment (`--rpc env:NAME` or the default
  variable), even without a path or query: some providers put the key in the host name.
  `--rpc <url>` takes only a loopback or local-network URL (section 6b).
- If it stops: the cold campaign is resumable (run the same command; it makes a new set-up, about
  5.2 M gas more); the warm campaign restarts as a new session. Ctrl-C once stops after the current
  step and still sweeps; twice exits at once (role balances are then left on the role accounts).
- If a set-up fails after the role accounts were funded (a fee spike above the cap, a write or
  receipt wait over its time limit, an RPC error, the finality wait), the funded role balances are
  swept back at once and `deployments.jsonl` records the failed set-up and the sweep. Time limits:
  600 s per funder transaction (`--tx-timeout`), 1,800 s for the governance, issuer and verifier
  writes together (`--writes-timeout`), 1,800 s for the finality wait (`--finality-timeout`). A
  funding transfer that is still pending when the sweep runs is not swept (its value arrives on a
  role account whose key is gone); the funder's own pending deploy or funding transaction only
  costs its gas when it is mined later.
- Afterwards, tell operator that it finished. Nothing else to send: the results are in
  `results/v4/e2e/e2e_cold_testnet/` and `e2e_warm_testnet/` in the Windows repository.

## 5. Privacy notes

- The RPC URL usually contains an API key. It is read only from the environment (`read -rs` keeps
  it off the screen and out of shell history), deleted from each runner's environment after
  reading, never written to any file or log, and recorded only as its SHA-256 next to your
  `--endpoint-label`. Every result line is scanned for the URL, its host name and host labels, its
  path segments and query values before it is written; a hit stops the campaign.
- The funder key is read the same way and never written. Use a fresh key: whoever has it controls
  the test funds. The shell and the marker wrapper keep both variables in their environment until
  the window ends (readable only by your own user); `unset` them afterwards.
- Public and permanent on the testnet: the funder address, the three role addresses, the four
  contract addresses, every transaction hash and the issuer and verifier records (DID documents,
  public keys, epoch roots, the verifier's ML-KEM public key). `deployments.jsonl` records the
  addresses and transaction hashes. No holder data goes on chain: the credential is a synthetic
  fixture (birth date 19840315), the holder secret never leaves the process, and no presentation
  is posted.
- A faucet that needs a sign-in or a mainnet balance can link the funder address, and through it
  these transactions, to you. Decide one of: keep the testnet campaign folders out of the
  anonymised IRIS export (recommended), or use a faucet without sign-in.
- The RPC provider sees your IP address and every request (which registry is read, when).

## 6. Devices (D-031 K3)

Emulation is never a device measurement: the orchestrator refuses a non-smoke run when the process
architecture disagrees with the CPU the OS reports, and a non-x64 run needs `--device-label`. A
GitHub-hosted arm64 runner (after approval A2) is a virtual machine; its runs would be labelled
"CI VM, not a phone". Device results stay out of IRIS submission material until you decide.

### 6a. Apple Silicon Mac or ARM64 Linux board (the full series)

Install:
1. Node 24 for arm64 (the official nodejs.org build, or `nvm install 24`). Check:
   `node -p "process.arch + ' ' + process.versions.node + ' ' + process.versions.openssl"` shows
   `arm64 24.x 3.5.x` or later (ML-KEM and ML-DSA need OpenSSL 3.5).
2. git, and Python 3 (`device_run.sh` scrubs user name, host name and home paths from the logs
   with it before it packs them, and refuses to start without it).
3. Foundry's anvil 1.5.1 for the device (the darwin_arm64 or linux_arm64 asset of the v1.5.1
   release; check the asset's published sha256 [VERIFY the asset name]). Note its path.
4. A clone of the private repository at the e2e commit (`git clone`, `git checkout <commit>`), then
   `npm ci` in it.

Run (repository root on the device; first a short smoke check, then the series):

```
bash scripts/e2e/device_run.sh --label <id> --device-label "<model, RAM>" --anvil-bin <path to anvil> \
  --key-spec <repo-relative ceremony key spec> --smoke
bash scripts/e2e/device_run.sh --label <id> --device-label "<model, RAM>" --anvil-bin <path to anvil> \
  --key-spec <repo-relative ceremony key spec>
```

- `<id>` is a short name (`m2_air`, `rpi5_8gb`); the device label names the model and RAM only (no
  serial numbers, no names).
- On a Mac, prefix the second command with `caffeinate -i` so the Mac does not sleep; keep it on
  the charger (the AC rule reads `pmset -g batt`). A board on mains counts as AC.
- Duration [S]: 30 cold runs x about 10.5 min = about 5.3 h, plus about 25 min warm.
- Send back the two files it prints: `e2e_device_<id>.tar.gz` and `e2e_device_<id>.tar.gz.sha256`
  (results only: schedule, runs, the local chain's dev addresses, logs, and an environment record
  with CPU model, cores, RAM, OS, kernel, Node and OpenSSL versions; no keys). Add a short note:
  power state, room temperature, anything unusual. operator checks the SHA-256 and the emulation
  flag and runs `python scripts/e2e/analyze_e2e.py --root results/v4/e2e_device_<id>`.

### 6b. Android phone (Termux)

- Only if Termux's Node is 24 with OpenSSL 3.5 or later [VERIFY on the phone]; `device_run.sh`
  checks that ML-KEM-768 and ML-DSA-44 keys can be made and refuses otherwise (then the phone is
  blocked for this series). Install from F-Droid's Termux: `pkg install nodejs git python`, clone,
  `npm ci` [VERIFY that every dependency installs].
- There is no Anvil for Android, so the endpoint is either the public testnet or the laptop's node
  over the local network. With `--endpoint custom`, `device_run.sh` first runs the read-only
  `testnet_check.ts` with the same endpoint, chain id and caps (it sends and signs nothing) and
  stops on any problem; for an internet endpoint it then asks you to type YES before anything is
  sent from the funder account.
- Public testnet from the phone (sections 2 to 5 apply: a fresh test-only funder, two set-ups, one
  per campaign; records labelled "public RPC endpoint over the internet"), in Termux from the
  repository root:

```
read -rs PQID_E2E_RPC_URL; export PQID_E2E_RPC_URL            # paste the HTTPS URL, Enter (not echoed)
read -rs PQID_E2E_FUNDER_KEY; export PQID_E2E_FUNDER_KEY      # paste the test-only private key (hex), Enter
bash scripts/e2e/device_run.sh --label <id> --device-label "<model, RAM>" --key-spec <repo-relative ceremony key spec> \
  --power-rule record-only --endpoint custom -- --endpoint-label sepolia-a --expect-chain-id 11155111 \
  --max-fee-gwei 10 --max-total-eth 0.1 --confirm-public-testnet
unset PQID_E2E_RPC_URL PQID_E2E_FUNDER_KEY
```

- The laptop's node over the local network: start Anvil on the laptop bound to its LAN address on
  port 8790 (this needs a firewall rule and your approval; the runs are labelled "local network,
  another host"), then on the phone, with `PQID_E2E_FUNDER_KEY` set to Anvil's public dev key #0:

```
bash scripts/e2e/device_run.sh --label <id> --device-label "<model, RAM>" --allow-dev-key --power-rule record-only \
  --endpoint custom -- --rpc http://<laptop LAN address>:8790 --allow-http-custom --endpoint-label lan-laptop \
  --expect-chain-id 31337 --max-fee-gwei 10 --max-total-eth 1 --custom-finality latest
```

  (replace `--allow-dev-key` by `--key-spec <spec>` after the ceremony). Add `--smoke` before
  `--endpoint` for a short check first.
- Phone controls (`docs/v4/PHONE_PROTOCOL.md` section 3, as far as they apply): battery 50 to
  100 % at the start, battery saver off, out of its case on a table, other apps closed, Do Not
  Disturb on, screen on with a fixed brightness, Wi-Fi on (the presentation reads the chain);
  `termux-wake-lock` while it runs [VERIFY]. Record the battery level and room temperature in the
  note you send back.

### 6c. iPhone

The full presentation cannot run on an iPhone with the current code (no Node runtime; ML-KEM,
ML-DSA and the JSON-RPC wallet would need a port, which would be a different implementation). The
phone kit stays proving-only (`docs/v4/PHONE_PROTOCOL.md`); a combination of iPhone proving with
laptop chain stages would be an estimate [S], not a measurement.
