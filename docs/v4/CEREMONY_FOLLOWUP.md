# Ceremony follow-up: replacing the development key (TASKS I)

What operator runs after Kushal's multi-party ceremony (`ceremony/HANDOFF_STEPS.md`). Written
2026-10-01 to 2026-10-03, before the ceremony. Facts, rules and commands only.

- Kit and the ceremony itself: `ceremony/README.md`, `ceremony/HANDOFF_STEPS.md` (Kushal runs them;
  operator contacts no one and publishes nothing).
- Entry: `scripts/ceremony/followup.sh` (Git Bash, Windows host). Driver:
  `harness/v4/ceremony/followup.ts`. Pure rules: `harness/v4/ceremony/followup_lib.ts`. Key checks in
  a child process: `harness/v4/ceremony/key_checks.ts`. Rekey loader: `harness/v4/ceremony/rekey.mjs`
  with `rekey_hooks.mjs`, `rekey_rewrite.mjs` and `rekey_probe.ts`.
- Tests: `tests/v4/ceremony_followup.test.ts`, `tests/v4/ceremony_rekey.test.ts`,
  `tests/v4/ceremony_devrerun.test.ts` (the post-fix rerun with the dev key); fixtures
  `tests/v4/fixtures/ceremony_rehearsal_transcript.json` and `ceremony_rehearsal_zkey_verify.log`
  (a real kit transcript and a real snarkjs 0.7.4 `zkey verify` output of the rehearsal).
- Labels: [M] measured, [S] estimate from the stated arithmetic, [A] assumption.

## Preconditions

| Check | How | Expected |
|---|---|---|
| Ceremony finished | `ceremony/v4/final/` | `ceremony_transcript.json`, `credential_auth_v4_final.zkey`, `verification_key.json`, `Groth16Verifier.sol` (HANDOFF_STEPS step 4) |
| At least three contributors, including one external | transcript, plus Kushal's answer | 3 or more non-beacon contributions under 3 or more distinct names; Kushal names the index of each contribution made by a person outside the project on their own computer (`--external 2` or `--external 2,3`) |
| Kit audit passed | HANDOFF_STEPS step 5 | `[audit] ALL CHECKS PASSED` |
| Check-only run passed | `followup.sh --check-only --external <i>` | `followup.sh: PASS` (or REVIEW with only warnings a person has looked at) |
| Follow-up code committed | the driver checks `git status` (read only) | nothing uncommitted under `followup_lib.ts` `CODE_PATHS`; otherwise the real run refuses |
| Ports recorded | DECISIONS D-041 | 8800 (suite) and 8801 to 8899 (mutation, one per defence; 8801 to 8859 for the 59 defences) |
| No other work | `results/v4/bench/RUNNING`, `results/v4/BUSY` | neither exists; nothing else CPU-heavy runs (the follow-up holds `results/v4/BUSY`) |
| Ports free | 127.0.0.1 | 8800 and the defence ports of the selected steps; the preflight probes them and refuses before writing anything |
| Dry run passed on the same commit | see "Dry run" | `followup.sh: PASS` |

- The transcript cannot show who is outside the project. The external count rests on Kushal's
  declaration [A]; the record says so (`options.externalSource`).
- Distinct names are a floor, not proof of distinct people: names are compared trimmed,
  whitespace-collapsed and case-folded, and only the count is recorded.

## Steps

All steps run by default, in this order. A failed step stops the steps that depend on it: an
unverified key is never installed, and the suite and mutation steps never run after a failure.

### 1. verify

- Transcript rules (`followup_lib.ts` `checkTranscript`, ceremony mode):

| Rule | Fails when |
|---|---|
| `schema`, `label` | not `pqid/ceremony-transcript/v1`, or the label is not `ceremony` |
| `r1cs.frozen`, `r1cs.freezeRecorded` | the transcript's r1cs SHA-256 is not the one that `docs/v4/FREEZE.md`, `setup/pins_v4.json` and the file on disk all agree on, or the kit did not record the freeze match |
| `ptau.pinned`, `ptau.pinChecked` | the ptau SHA-256 is not the `setup/pins.json` pin of `powersOfTau28_hez_final_15.ptau` (equal to the file), or the kit did not record the pin check |
| `contributions.count` | fewer than 3 non-beacon contributions |
| `contributions.distinctContributors` | fewer than 3 distinct contributor names (trimmed, case-folded), or a contribution without a name |
| `contributions.indexes`, `.hashes`, `.distinctHashes`, `.acceptedTimes` | indexes not 1..n, a hash that is not 64 bytes hex, a repeated hash, a missing acceptance time |
| `contributions.notRehearsal` | a contribution name starts with `REHEARSAL ONLY` |
| `contributions.externalDeclared` | no `--external` index, or one outside 1..n |
| `contributions.secondRouteHash`, `.receipts` | a reported hash or a receipt that did not match (missing ones are warnings) |
| `beacon.index`, `.value`, `.iterations`, `.contributionHash` | the beacon is not entry n+1, its value is not hex, fewer than 2^10 iterations |
| `beacon.kind` | not drand or Bitcoin |
| `beacon.drandChain`, `.drandRound`, `.drandValue`, `.drandSha` | another drand network, a response for another round, a value that is not the round's `randomness`, or `randomness` that is not SHA-256 of the signature |
| `beacon.drandRoundTime` | the transcript's round time is not genesis 1595431050 + (round - 1) x 30 s (the default network, as in `ceremony/lib.mjs`) |
| `beacon.bitcoinHash` | the block hash is not 32 bytes hex or differs from the recorded one |
| `beacon.plannedBeforeLastContribution` | the plan was recorded after the last contribution was accepted (planned after the first one: warning) |
| `beacon.unknownAtLastContribution` | drand: the recomputed round time is not after the last acceptance (Bitcoin: warning, the block time is compared by hand) |
| `final.zkeySha`, `.vkeySha`, `.solSha`, `.verifiedFromR1cs` | a final file differs from the transcript, or the kit did not verify the final zkey from r1cs and ptau at finalize |
| `tools.snarkjs` | not snarkjs 0.7.4 |

- Warnings (status review, not fail): `contributions.externalNameUnique` (a declared external
  contribution has the name of another contribution); `tools.kitFiles` (the kit-file hashes in the
  transcript are not those of the committed `ceremony/` files, working tree or HEAD blob; the list
  is `coordinator.mjs` `KIT_FILES`); the missing second-route hashes and receipts above.
- The kit's own check: `node ceremony/coordinator.mjs audit` with the transcript, final zkey,
  frozen r1cs, pinned ptau, vkey and Solidity verifier (log `audit.log`).
- Plain snarkjs: `node node_modules/snarkjs/build/cli.cjs zkey verify <frozen r1cs> <pinned ptau>
  <final zkey>` (log `zkey_verify.log`). Its contribution list (names, hashes, order, beacon value and
  iterations) and circuit hash must equal the transcript, and it must print `ZKey Ok!`.

### 2. keys

`key_checks.ts` in a child process:

- the verification key equals the one exported from the final zkey;
- one Groth16 proof of the pinned Phase D v4 input (`results/v4/bench/inputs/v4_input.json`, checked
  against `inputs.lock.json`) with the frozen wasm and the new zkey verifies with the new vkey and
  gives the pinned public signals; a changed public signal is rejected; the dev key rejects it. The
  wasm must agree with `docs/v4/FREEZE.md` and its pin in `setup/pins_v4.json`, otherwise the step
  fails without proving;
- same circuit and phase 1 as the dev key: alpha, beta, gamma and IC equal, delta differs;
- public-beacon trapdoor (review finding 9.3, `harness/v3/trapdoor.ts`): delta derived from the
  ceremony's own beacon value and iterations must not equal the key's delta, and a proof forged
  from it must not verify. Positive control: the same derivation on the committed beacon-only v2
  key (`setup/out/verification_key.json`) matches its delta and its forged proof verifies.

### 3. install

- Copies the four final files to NEW paths, never over an existing different file and never over
  a dev file:

| Final file | Installed as |
|---|---|
| `credential_auth_v4_final.zkey` | `setup/out/v4/credential_auth_v4_ceremony.zkey` |
| `verification_key.json` | `setup/out/v4/verification_key_ceremony.json` |
| `Groth16Verifier.sol` | `setup/out/v4/Groth16VerifierV4_ceremony.sol` |
| `ceremony_transcript.json` | `setup/out/v4/setup_transcript_ceremony.json` |

- Text files with CR bytes are not installed: `.gitattributes` (`* text=auto eol=lf`) would
  commit other bytes than the pinned ones, and the pins would fail in a fresh clone and in the WSL
  clone. The fix is to normalize the file to LF in `ceremony/v4/final/`, re-run the kit audit and
  the follow-up. The zkey is binary and not checked.
- Pins: a NEW file `setup/pins_v4_ceremony.json` with one entry per installed file, each labelled
  `ceremony` (the zkey entry notes the contribution count, the declared external indexes, the
  beacon and the run id). `setup/pins_v4.json` is not touched: it holds exactly the six dev
  entries, and `tests/v4/circuit_v4.test.ts` checks that it has exactly six. An existing ceremony
  pin is never rewritten: a re-run with the same file (SHA-256, label and path equal) leaves the
  entry and its note as they are; anything else stops the run.
- Key spec for the end-to-end series: `setup/key_spec_v4_ceremony.json` (wasm pinned in
  `setup/pins_v4.json`, zkey and vkey in `setup/pins_v4_ceremony.json`).
- The installed key is then loaded through the loaders of the campaigns that will use it:
  `harness/v4/cmp/spec.ts` `resolveV4Key` (label `ceremony key`) and `harness/v4/e2e/lib.ts`
  `loadKeySpec` (label `ceremony`). A loader error is flagged for review.
- Every install conflict (a target or pin with other content, a key spec with other content, CR
  bytes, a dev overlap) is also checked in the preflight, so the run refuses before it writes
  anything.

### 4. suite

- `harness/v4/security_suite.ts`, unchanged, with `--config` naming the output folder of this run
  and port 8800. Without a config it would write `results/v4/security_suite.json`, which the ledger
  cites, so it is never started without one.
- Key: `packages/v4/src/paths.ts` names the dev key, and `packages/v4` is frozen (D-034). The child
  is started as `node --import tsx --import harness/v4/ceremony/rekey.mjs ...` with
  `PQID_V4_REKEY_LABEL=ceremony`. The loader changes, in memory only, the four key file names and
  `KEY_LABEL_V4` of `paths.ts`; every other module loads unchanged. Each replacement must hit
  exactly once, otherwise the child stops (a changed `paths.ts` cannot silently keep the dev
  key). Before the suite step and before the mutation step the driver runs `rekey_probe.ts` under
  the same loader and environment, and refuses unless the probe resolves the installed files and
  label. The records state the switch (`keySwitch`: the loader, and that the package default stays
  the dev key).
- The output must name the installed key (`keyLabel`, `artifacts.zkey` and `artifacts.vkey` with
  their SHA-256). The suite must pass. Its verdicts are compared with the dev-key run 10
  (`results/v4/security_suite.json`, read only): per record and route, accepted, valid and stopping
  layer (the rule of `artifact/compare_suite.py`, which also runs and is logged). A difference sets
  the status to review.
- After the child exits, port 8800 is probed again (5 probes, 1 s apart). A port that still answers
  means a chain node was left running (on Windows, a timeout ends the node child but not its
  Anvil); the step fails and the log says so.
- The suite's `label` text is fixed in the frozen harness and says "dev key"; route T1 applies the
  dev key's public beacon (0102...1f20, 2^10). The record states this (`labelTextNote`); the check
  with the ceremony's own beacon is step 2.

### 5. mutation

- The defences, configs and verdict rules of `harness/v4/mutation.ts` (campaign 5: 59 defences).
  `mutation.ts` itself writes fixed paths (`results/v4/mutation/`, `results/v4/mutation.json`), so
  the loop is re-implemented in the driver with new output paths, ports 8801 + defence index, and
  the rekey loader. The tests tie the copy to campaign 5: the defence list and order (the ports of
  campaign 5's configs), the config of every defence (`followup_lib.ts` `mutantConfig` equals each
  committed `config.json`, port and output folder aside), the registry contract rewrite, and all 59
  rows recomputed from the committed outputs with the driver's verdict rule.
- Verifier, wallet, registry and governance mutants run with the ceremony key. Circuit mutants
  keep their throwaway keys (`circuits/build/v4/mutants/`, reused when the r1cs stamp matches), so
  their rows test the circuit, not the key. Each circuit row records the SHA-256 of its mutant
  r1cs, throwaway zkey and vkey; each registry row records the mutant contracts file and its
  SHA-256 (`circuits/build/v4/mutants/contracts/`).
- The step writes, besides its run folder, the gitignored mutant circuits, throwaway keys and
  mutant contracts under `circuits/build/v4/mutants/` (shared with campaign 5; rebuilt in place
  when the source or the stamp differs).
- Baseline: the suite output of step 4 (it must be made with the same zkey). Rows are compared
  with campaign 5 (`results/v4/mutation.json`, read only), field by field, including the
  harness-error lists. Status: fail on a run error (including a port left open after a mutant
  run), review when any row differs from campaign 5, pass otherwise. Campaign 5 has harness errors
  in one row (`governance:issuerPopBeforeAccreditation`, a deterministic wallet refusal); the same
  errors again are not a difference. The table lists such rows in `harnessErrorRows`.

### Status and exit codes

- `pass` (exit 0): every step passed and every verdict equals the dev-key run. `review` (exit 5):
  finished, but a warning or a difference needs a person to look. `fail` (exit 1): a check failed,
  or no step completed.
- `refused` (exit 3): the preflight stopped the run before it wrote anything (a marker, uncommitted
  code, a busy port, an install conflict, missing ceremony outputs).
- `stopped` (exit 4): a refusal after the start (for example a port that became busy, or a
  target that appeared during the run). The run folder and logs exist, and verify, keys and
  install may have run; `followup.json` `error.afterStart` says so.
- The driver hashes the dev-key results (`results/v4/security_suite.json`, `attack_matrix.json`,
  `mutation.json`, `mutation_progress.json`, every `results/v4/mutation/*/security_suite.json`),
  the dev key files and both pin files before and after; any change fails the run.

### Markers

- The real run and the check-only run hold `results/v4/BUSY` for the whole run (D-034: untimed,
  CPU-heavy). The dry run holds it while it runs a suite or mutation step; a dry run of verify,
  keys and install only (the tiny rehearsal circuit, seconds) holds none. Every run refuses to
  start while either marker exists.

## Outputs

| Path | Content |
|---|---|
| `results/v4/ceremony/followup_<date>/followup.json` | record: inputs with SHA-256 (the wasm with its pin state), contribution hashes and declared roles, contributor counts (no names), beacon, code state (git HEAD; per code file the SHA-256, the git blob id and whether it equals HEAD), environment (no user, host or home path), step results, `keySwitch`, the series that use the key |
| `.../verify/verify.json` | transcript rules, audit result, parsed `zkey verify` |
| `.../keys/key_checks.json`, `key_checks_config.json` | step 2 |
| `.../install.json` | installed files, pins, key spec, loader checks |
| `.../suite/security_suite.json`, `attack_matrix.json`, `config.json`, `rekey_probe.json`, `vs_dev.json` | step 4 |
| `.../mutation/<kind>__<name>/`, `mutation.json`, `progress.json`, `vs_dev.json` | step 5 (`mutation_partial.json` with `--only`) |
| `verification/v4/ceremony_followup_<date>/` | `followup.log` (every step, including one line per mutation defence), `audit.log`, `zkey_verify.log`, `key_checks.log`, `suite.log`, `compare_suite.log`, `mutation/<kind>__<name>.log` |
| `setup/out/v4/*_ceremony.*`, `setup/pins_v4_ceremony.json`, `setup/key_spec_v4_ceremony.json` | step 3 |
| `circuits/build/v4/mutants/` (gitignored) | step 5: mutant circuits, throwaway keys, mutant contracts |

- A second run on the same day gets `_r2`, `_r3` (results and log folders are never reused).
- Logs pass through the free-text filter of `harness/v4/bench/lib.ts` (`sanitize`).
- Contributor names are in the transcript, inside the zkey and in `audit.log` and `zkey_verify.log`
  (snarkjs prints them). They are public by the contributors' consent (HANDOFF_STEPS step 0) and
  stay out of anonymised builds (open point 3).

## Which series use the ceremony key

| Series | Where | v4 key now | After the ceremony |
|---|---|---|---|
| C1 security suite | Windows | dev (run 10, `results/v4/security_suite.json`) | re-run by this follow-up into its dated folder |
| C3 mutation campaign | Windows | dev (campaign 5, `results/v4/mutation.json`) | re-run by this follow-up (circuit mutants keep throwaway keys) |
| Phase D `warm`, `cold_v4` (`results/v4/bench/`) | Windows snarkJS | dev key | stay as they are (ledger-cited, labelled dev key); the v4 rows of `cold_cmp` and `warm_cmp` are the post-ceremony repeat (D-034) |
| Phase D `cold_v2v3` | Windows snarkJS | no v4 key | not affected |
| Phase D `warm_wsl`, `cold_rs_wsl` (`results/v4/bench_wsl/`) | WSL snarkJS and rapidsnark | dev key | stay as they are; the WSL v4 Phase D repeat (D-034) uses the ceremony key, but no runner takes a non-dev key with rapidsnark in WSL yet (open point 5) |
| cmp `cold_cmp`, `warm_cmp` | Windows snarkJS | not run yet | v4 condition with the ceremony key |
| cmp `wallet_cmp` | Windows | no key | not affected |
| e2e `e2e_cold_wsl`, `e2e_warm_wsl` | WSL, loopback Anvil and Besu | not run yet (D-034: after the ceremony) | ceremony key |
| e2e testnet and device campaigns | approval A4, devices | not run yet | ceremony key |
| chain-read campaign (S4 verifier reads) | WSL and Windows | dev key (D-034: before the ceremony) | stays dev, labelled dev; not repeated |
| robustness load test and fuzzing | Windows | dev key (D-034: before the ceremony) | stays dev, labelled dev; not repeated |
| E4 verifier throughput (`results/v4/scale/`) | Windows | dev key | stays dev; not repeated |
| gas (`results/v4/gas.json`) | Windows | dev verifier contract | stays dev; not repeated by this follow-up |
| C2 analyzers | - | no key (circuit only) | not affected |

- Reporting: ceremony-key rows carry their label (`ceremony key` in cmp, `key: ceremony` in e2e);
  dev-key rows keep `dev key`. A table that holds both has a key column. The BENCH_PROTOCOL
  "Known limits" line (ceremony-key timings should carry over) stays an assumption until the cmp and
  WSL repeats have run.
- Ledger: new keys for the ceremony-key suite and mutation rows; the dev-key keys stay as they are.
- The shipped default of `packages/v4` stays the dev key after the follow-up; only the processes
  started under the rekey loader use the ceremony key, and the cmp and e2e campaigns take it through
  their own key flags and key spec.

## Commands

From the repository root in Git Bash on the Windows host.

### Dry run

On the rehearsal outputs; results only under `results/v4/ceremony/_smoke/` (gitignored). Run
`node ceremony/rehearse.mjs` first if `ceremony/rehearsal/_out/` is missing, or again if the kit
files changed since (the kit-file rule then warns):

```
bash scripts/ceremony/followup.sh --dry-run
bash scripts/ceremony/followup.sh --dry-run --steps suite
bash scripts/ceremony/followup.sh --dry-run --steps mutation --only governance --baseline <smoke folder>/suite/security_suite.json
```

- The first runs verify, keys and install on the rehearsal key (tiny circuit, local ptau, dummy
  beacon; the freeze, pin and distinct-name rules are skipped, `--external` defaults to 1). It
  holds no marker.
- The suite and mutation steps cannot use a key of the tiny circuit. In a dry run they use a
  throwaway key of the v4 circuit, made in the smoke folder: the dev zkey plus one phase-2
  contribution with random entropy (not kept), label `dryrun`, pinned in the smoke folder. It has
  the dev key's alpha, beta, gamma and IC and its own delta (checked), so a prover or verifier that
  still read the dev key would break the suite's honest controls, while the verdicts must equal the
  dev run's. `--steps mutation --baseline <smoke folder>/suite/security_suite.json` reuses the key
  of that smoke folder. These steps hold `results/v4/BUSY`, use ports 8800 and 8801+, and the
  mutation step also writes the gitignored files under `circuits/build/v4/mutants/`.
- Dry-run output is not a result and is never quoted.

### Check only (the first command after the ceremony)

```
bash scripts/ceremony/followup.sh --check-only --external <index[,index]>
```

- Runs verify and keys in ceremony mode on `ceremony/v4/final/` (frozen r1cs, pinned ptau, pinned
  wasm, drand or Bitcoin rules), writes only under `results/v4/ceremony/_smoke/checkonly_*`, holds
  `results/v4/BUSY` (the two zkey recomputations take minutes) and installs nothing. It does not
  need the follow-up code to be committed. Not a result; delete the folder afterwards.

### Real run

After the ceremony, with the follow-up code committed and the check-only run passed:

```
bash scripts/ceremony/followup.sh --external <index[,index]>
```

- Parts of a run: `--steps verify,keys,install` then later `--steps suite,mutation` (the suite step
  then uses the installed key and checks it against `setup/pins_v4_ceremony.json`);
  `--steps mutation --baseline <ceremony suite json>`; `--only <kind[:name],...>` (writes
  `mutation_partial.json`); `--jobs` (1 to 4, default 2).
- Duration [S]: verify recomputes the key from r1cs and ptau twice (kit audit and plain snarkjs),
  a few minutes; keys seconds; suite about 2.5 min (dev run 10: 148 s); mutation about 1.5 h (dev
  campaign 5 with 2 jobs: 14:54:44Z to 16:25:52Z, about 91 min). Total about 1 h 40 min.

### After a real run that passed

1. Commit `setup/out/v4/*_ceremony.*`, `setup/pins_v4_ceremony.json`,
   `setup/key_spec_v4_ceremony.json`, the run folder and the log folder.
2. Bring the WSL clone to that commit (the e2e campaigns and the WSL repeat read the key files,
   pins and key spec there).
3. cmp (Windows): `node --import tsx harness/v4/cmp/inputs.ts --v4-zkey setup/out/v4/credential_auth_v4_ceremony.zkey --v4-vkey setup/out/v4/verification_key_ceremony.json --v4-key-label 'ceremony key' --v4-pins setup/pins_v4_ceremony.json`,
   the same with `--check`, then
   `PQID_CMP_V4_ZKEY=setup/out/v4/credential_auth_v4_ceremony.zkey PQID_CMP_V4_VKEY=setup/out/v4/verification_key_ceremony.json PQID_CMP_V4_LABEL='ceremony key' PQID_CMP_V4_PINS=setup/pins_v4_ceremony.json bash scripts/cmp/quiet_window_cmp.sh`
   (`docs/v4/CMP.md`).
4. e2e (WSL window, `docs/v4/E2E.md`): `scripts/e2e/quiet_window_e2e_wsl.sh --confirm-quiet --key-spec setup/key_spec_v4_ceremony.json`.
5. WSL v4 Phase D repeat: after a runner exists (open point 5).

The record (`followup.json` `keyUsers` and `next`) repeats these commands with the run's paths.

## Post-fix rerun with the dev key (D-034)

D-034 keeps `packages/v4` frozen for the measurement period, except for a fix of a defect found by
fuzzing. Such a fix gets the tests, the security suite and the mutation campaign again before any
timed series, plus a DECISIONS entry. `--dev-rerun` is that rerun for C1 and C3. The key does not
change: it is the pinned dev key.

```
bash scripts/ceremony/followup.sh --dev-rerun --dry-run
bash scripts/ceremony/followup.sh --dev-rerun
```

- What it runs: the suite step and the mutation step of this follow-up, unchanged: the same
  re-implemented mutation loop and configs (campaign 5's rules), port 8800 for the suite and
  8801 + defence index for the mutants, the same port probes after each child, and the same hash
  check of the dev-key results before and after.
- What it skips: verify, keys and install. `--steps` takes only `suite` and `mutation`.
  `--check-only`, `--external`, `--label`, `--final-dir` and `--allow-uncommitted` are refused.
- Options: only `--dry-run`, `--steps`, `--only`, `--jobs`, `--date`, `--baseline` and `--owner`,
  each at most once. Anything else is a usage error (exit 2), so a misspelt `--dryrun` or a
  `--dry-run=yes` never starts the real rerun. A value option needs a non-empty value; `--only`
  needs the mutation step and must name defence kinds or `kind:name` pairs that exist; `--date`
  must be a real date within one day of today's UTC date (the folder names the day of the run).
- Key: the dev files under `setup/out/v4/` plus the frozen r1cs and wasm, each checked against
  its entry in `setup/pins_v4.json` (label `dev`, path, SHA-256). The dev key is the package
  default, so the children run without the rekey loader. Before each step, `rekey_probe.ts` runs
  without the loader and must resolve the pinned dev files with no rewrite. The suite output must
  name the same zkey, vkey, r1cs and wasm with their SHA-256. Records carry `keySwitch` "none".
- Comparison basis (checked before the start): dev run 10 (`results/v4/security_suite.json`) was
  made with the pinned key, and campaign 5 (`results/v4/mutation.json`) names run 10 as its
  baseline with the same SHA-256.
- Comparison, stricter than the ceremony run, because the key is the same:

| Step | Compared with | Fields |
|---|---|---|
| suite | dev run 10 | verdict per record and route (accepted, valid, stopping layer), failed-check lists, every summary field, `pass`, the top-level `trapdoor`, `standardThresholds` and `pqc` (OpenSSL and Node versions), the record list (id, kind, number of attempts, in order, records without attempts too), and `attack_matrix.json` against `results/v4/attack_matrix.json`; `artifact/compare_suite.py` also runs |
| mutation | campaign 5 | every row: routes let through, controls broken, routes stopped elsewhere, harness errors, run errors and the exit code of the mutant suite run; missing or extra rows; the no-effect list |

- Expected outcome for a fix that touches only refusal paths outside the suite's routes: every
  verdict equal and every mutation row identical, so the status is pass. Any difference sets
  review (exit 5); `vs_dev.json` lists it and the log prints one `REVIEW difference` line per item.
  A difference is never dropped, and the rerun is not repeated to make one go away. Fail (exit 1):
  the suite did not pass, its output names another key, a port stayed open, or a mutant run
  errored.
- Code state: refuses while anything under `followup_lib.ts` `CODE_PATHS` (this includes
  `packages/`) is uncommitted, and has no override. The record names every file of
  `CODE_FILES`, every `packages/<name>/src/` file (all packages: the suite also runs issuer,
  ledger, pqc and others through its imports) and every `packages/<name>/package.json` by SHA-256
  and git blob id, with whether it equals HEAD; `gitHead` pins the rest.
- Marker: holds `results/v4/BUSY` for the whole run; refuses while either marker exists.
- Duration [S]: suite about 2.5 min (run 10: 148 s), mutation about 91 min (campaign 5 with 2 jobs).
- Labels: every record says `post-fix rerun (D-034)` and `dev key` (record `label`, `run`, `key`;
  mutation table `label`; both `vs_dev.json`; both `key_probe.json`; the marker note). The suite
  and mutant `config.json` names carry both texts (the suite's is
  `v4, dev key, post-fix rerun (D-034)`), and the frozen suite copies that name into its output's `config` field, so
  `suite/security_suite.json` and every mutant output carry them too. The suite's own `label`
  text is fixed in the frozen suite and says "dev key".
- Partial runs: a run without both steps, or with `--only`, says `PARTIAL (...)` in the record
  label (and the mutation table label with `--only`) and in the record field `partial`. Its
  `next` field says what is still missing: D-034 is met only by the suite step and the full
  mutation step (every defence, no `--only`) passing on the same committed code, either in one
  run or as a suite-only run followed by a full mutation-only run on its suite output.
- Dry run (`--dev-rerun --dry-run`): the preflight and the key probe, then it stops before the
  suite. It writes nothing and holds no marker (seconds); it refuses while a marker exists. It
  prints each reason the real rerun would refuse and one JSON line with the labels, the pinned
  files, the probe, the ports, the planned folders, `partial` and, for a mutation-only rerun,
  `baselineRun`. Exit 0: the real rerun would start now (`followup.sh` prints "DRY RUN OK"); 3:
  it would refuse (for example, uncommitted code).
- A mutation-only rerun (`--steps mutation`) needs `--baseline
  results/v4/fixcheck/<run>/suite/security_suite.json` from an earlier post-fix rerun, never dev
  run 10 (made before the fix). Before the start it also checks that run's `fixcheck.json`: the
  suite step passed and wrote that file, on committed code; the file still has the SHA-256 its
  `suite/vs_dev.json` recorded; and no file under `CODE_PATHS` changed between that run's commit
  and HEAD (commits of results in between are fine). The record keeps these facts as
  `baselineRun`.

| Path | Content |
|---|---|
| `results/v4/fixcheck/<date>[_rN]/fixcheck.json` | record: labels, purpose, expected outcome, `partial`, options, `baselineRun` (mutation-only), code state, key switch, step results, the dev-results hash check, `next` |
| `.../suite/security_suite.json`, `attack_matrix.json`, `config.json`, `key_probe.json`, `vs_dev.json` | suite step |
| `.../mutation/<kind>__<name>/`, `mutation.json`, `key_probe.json`, `progress.json`, `vs_dev.json` | mutation step (`mutation_partial.json` with `--only`) |
| `verification/v4/fixcheck_<date>[_rN]/` | `fixcheck.log`, `suite.log`, `compare_suite.log`, `mutation/<kind>__<name>.log` |
| `circuits/build/v4/mutants/` (gitignored) | mutant circuits, throwaway keys and mutant contracts (shared with campaign 5) |

- It never writes `results/v4/security_suite.json`, `attack_matrix.json`, anything named
  `results/v4/mutation*`, `results/v4/scale/`, `results/v4/bench*/` or `setup/`. The driver
  checks both output folders against that list before it starts, and in this mode every run
  output (record, logs, configs, probes, tables, folders) passes the same rule just before it is
  written (`followup.ts` `outputGuardFor`); a write anywhere else throws. The only other writes
  are the gitignored mutants above.
- Ports: the D-041 ports 8800 to 8859 are shared with the ceremony follow-up. The two never run
  at once: each holds `results/v4/BUSY` and refuses while it exists.

## Known limits [A]

- The external status of a contributor is the coordinator's declaration; the kit does not and
  cannot record it. Distinct names do not prove distinct people.
- drand: the BLS signature is not verified offline (round, round time, randomness and SHA-256 of
  the signature are). Bitcoin: the block hash and the block time are compared by hand.
- The public-beacon check rules out a key whose only randomness is public. It cannot show that a
  contributor destroyed their randomness; the 1-of-N argument rests on the contributors.
- The rekey loader changes a frozen module in memory. It is tested (rewrite and child process) and
  fails closed, but it is a run-time switch, not shipped code; the record names it.
- The mutation loop re-implements the rules of `harness/v4/mutation.ts`; the tests tie its defence
  list, configs and verdict rule to campaign 5's committed files. `mutantKey` and the mutant build
  are the same code, checked at run time against the expected paths.
- `harness/v4/lib/ports.ts` lists 8800 to 8859 (`CEREMONY_FOLLOWUP_PORTS`, D-041) for the shared
  quiet check; the driver also probes its ports before the start and after every suite child.

## Open points

1. `ceremony/README.md` does not say "at least three contributors, including one external" in
   one place: the Roles table says "3 or more people", the outside contributor appears only in the
   timeline and in HANDOFF_STEPS. Wording fix proposed to Kushal.
2. `ceremony/HANDOFF_STEPS.md` step 7 says the key is pinned in `setup/pins_v4.json`; it goes to the
   new `setup/pins_v4_ceremony.json`, and operator needs the external contribution indexes.
3. Anonymised export and snapshot: `artifact/export_public.py` keeps `setup/out/v4/` and the exact
   path `setup/pins_v4.json`; the installed transcript copy and the zkey carry contributor names,
   and `setup/pins_v4_ceremony.json` and `setup/key_spec_v4_ceremony.json` (which pin the key and
   which the cmp and e2e commands need) are not in its allow-list or in the snapshot list of
   `scripts/snapshot/make_snapshot.py`. Decide both together before the next export.
4. The suite's fixed "dev key" label text and the dev beacon of route T1 (frozen harness).
5. No runner for the WSL v4 Phase D repeat with a non-dev key: the Phase D runners name the dev
   key (`harness/v4/bench/lib.ts`, `inputs.lock.json`), and the cmp runners are snarkJS on Windows.
6. Closed (D-041, 2026-10-03): ports 8800 to 8899 are recorded, and `harness/v4/lib/ports.ts` lists
   8800 to 8859 for the quiet check.
