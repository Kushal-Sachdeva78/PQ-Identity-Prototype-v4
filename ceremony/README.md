# Ceremony kit (TASKS B8): operator guide

Multi-party Groth16 phase-2 setup for the frozen v4 circuit, run with snarkjs 0.7.4.
Exact commands for the real run: `ceremony/HANDOFF_STEPS.md`. Contributor sheet: `ceremony/CONTRIBUTE.md`.

## Files

| File | What it is |
|---|---|
| `coordinator.mjs` | Coordinator tool: `init`, `verify`, `accept`, `kit`, `beacon-plan`, `beacon`, `finalize`, `audit`, `status` |
| `contribute.ps1` | Contributor wrapper for Windows PowerShell 5.1 / 7 |
| `contribute.sh` | Contributor wrapper for macOS / Linux (also runs in Git Bash) |
| `contribute_core.mjs` | The contribution itself (both wrappers call it; the rehearsal uses the wrappers) |
| `lib.mjs` | Shared helpers (hashing, snarkjs loading, verify-log parsing, drand constants) |
| `package.json` | Pins snarkjs 0.7.4 for a kit used outside the repo (`npm install` in the kit folder) |
| `CONTRIBUTE.md` | One-page sheet that travels with each contributor kit |
| `rehearse.mjs` | End-to-end rehearsal on a throwaway circuit (REHEARSAL ONLY) |
| `rehearsal/tiny.circom` | The throwaway rehearsal circuit (35 constraints) |
| `rehearsal/REHEARSAL_TRANSCRIPT.json` | Result of the last rehearsal (the only committed rehearsal output) |
| `rehearsal/_out/` | Rehearsal scratch output, gitignored, wiped on every run |
| `v4/` | Created by `init` for the real ceremony (state, accepted zkeys, `final/`) |

## Roles

| Role | Who | Does |
|---|---|---|
| Coordinator | the project author | runs `coordinator.mjs`, hands out kits, accepts files, applies the beacon, finalizes |
| Contributors | at least three, including at least one external (a person outside the project, on their own computer); the coordinator's own contribution counts toward the three but is not external; each contributor uses a name of their own | run `contribute.ps1` or `contribute.sh` once, send back one zkey + receipt |
| Beacon | a public randomness source fixed in advance | drand round or Bitcoin block hash, applied last |
| Auditors | anyone (contributors, guide, judges, readers) | run `coordinator.mjs audit` on the published files |

## Why outside contributors count most

- Groth16 phase 2 is 1-of-N: the final key is sound if at least one contributor destroyed the
  randomness they used. Pointer: Bowe, Gabizon, Miers, IACR ePrint 2017/1050 (the MPC snarkjs
  implements; the snarkjs README links it, `node_modules/snarkjs/README.md` lines 152-156, 608).
- Contributions made by the coordinator, on the coordinator's machine, or by anyone who takes the
  coordinator's files and instructions without their own computer, share one point of failure.
  They add nothing if that point is compromised.
- A person outside the project on their own machine is an independent chance that the 1-of-N
  condition holds. For judges and readers, the number that matters is how many independent
  contributors there are, not the total count.
- The v4 key also rests on phase 1: the Hermez `powersOfTau28_hez_final_15.ptau`, pinned by SHA-256
  in `setup/pins.json`. The snarkjs README describes those files as having 54 contributions and a
  beacon (`node_modules/snarkjs/README.md` line 170) [A: not re-verified here].
- The v4 dev key (`setup/out/v4/*_dev.*`) has one secret contribution by the project itself; it
  stays labelled `dev` and is replaced by the ceremony key in Phase I.

## Timeline (relative to the start day S)

| When | Step |
|---|---|
| before S | circuit frozen (`docs/v4/FREEZE.md` lists the r1cs SHA-256; TASKS B7), IRIS snapshot taken, rehearsal passes |
| before S | contributors recruited: at least three, including at least one external (more is better) |
| S | `init`; `beacon-plan` with a round or block after the last planned contribution; announce the plan |
| S to S+n | one contributor at a time: `kit` -> send -> contributor runs the script -> `accept` |
| before the beacon time | last contribution accepted (`accept` refuses once an announced drand round is due) |
| beacon time | beacon value becomes public; `beacon`; `finalize`; `audit` |
| after | contributors check their hashes; the author decides what to publish; Phase I installs the key |

- Contributions are sequential: each contributor starts from the previous accepted file, so the
  schedule is one slot per contributor. The dev-key contribution on this laptop took 1,960 ms
  (`setup/out/v4/setup_transcript_dev.json`, `timingsMs.contributeMs`, one run [M]); the
  optional local check rebuilds the initial key first (`newZKeyMs` 25,881 in the same file [M]).
- Plan about one day per contributor for the human part (sending, running, sending back) [A].

## What contributors need

- Node.js 20 or newer, `npm install` once in the kit folder (snarkjs 0.7.4 only; `npm.cmd install`
  in Windows PowerShell, where the default execution policy can block `npm.ps1`).
- The kit folder: scripts, `CONTRIBUTE.md`, the current zkey, `SHA256SUMS.txt`; optionally the
  r1cs and ptau so they can verify their own output before sending it.
- The current zkey's SHA-256, sent by a second route (not with the files).
- Sizes for v4: zkey 11,425,800 bytes (`credential_auth_v4_0000.zkey` from the v4 dry run),
  r1cs 8,344,920 bytes, ptau 37,831,832 bytes (file sizes on disk). A kit is about 12 MB, or
  about 58 MB with the verification files.

## How files move

| Direction | What | Channel |
|---|---|---|
| coordinator -> contributor | kit folder as a zip | any file transfer (cloud link, email, USB) |
| coordinator -> contributor | SHA-256 of the input zkey | a second route (message, phone, in person) |
| contributor -> coordinator | output zkey + `.receipt.json` | any file transfer |
| contributor -> coordinator (or public) | `CONTRIBUTION_HASH` | a second route, or posted publicly by the contributor |
| coordinator -> everyone | transcript, final zkey, vkey, verifier, SHA256SUMS | the author's decision (see HANDOFF_STEPS.md) |

- The transfer channel does not need to be trusted for soundness: `accept` re-verifies every file
  from the r1cs and ptau, and refuses files that do not extend the current head by exactly one
  contribution.
- The second route protects against a swapped contribution: the contributor's own hash must
  appear in the final transcript under their name.

## Beacon: fixed and announced in advance

- The beacon is the last contribution; it removes any bias the last contributor could add. Its
  value must be unknown to everyone until after the last contribution is accepted.
- Choose one source and announce it (with `beacon-plan`) before contributions close. It is fixed
  once recorded; `beacon` refuses any other round, height or iteration count.
- Iterations: 2^10 (`--iter-exp 10`, the snarkjs minimum; `numIterationsExp` in the zkey).

| Source | Value | Where to read it | Plan command |
|---|---|---|---|
| drand League of Entropy mainnet, default network (30 s rounds, chained) | the round's `randomness` field (32 bytes hex) | `https://api.drand.sh/public/<round>`; check a second relay, e.g. `https://drand.cloudflare.com/public/<round>` | `beacon-plan --kind drand --at <ISO time>` or `--round N` |
| Bitcoin block hash at a future height | block hash as explorers show it (64 hex, no 0x) | two independent block explorers | `beacon-plan --kind bitcoin --height H` |

- drand facts used by the kit (read from `https://api.drand.sh/info` on 2026-09-27): chain hash
  `8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce`, genesis 1595431050,
  period 30 s, scheme `pedersen-bls-chained`. Round r is published at genesis + (r - 1) x 30 s.
- drand randomness is sha256 of the round's BLS signature (`https://docs.drand.love/docs/specification/`);
  `beacon` checks this and the round number from the saved API response. It does not check the BLS
  signature itself; anyone can re-read the round from a second relay or with a drand client.
- The drand quicknet announcement (2023, `https://docs.drand.love/blog/2023/10/16/quicknet-is-live/`)
  said the default network might be deprecated at some point; it still answered on 2026-09-27. If it is gone when the plan is made, use a Bitcoin block height.
- Bitcoin: `beacon` cannot check the value offline; two explorers are compared by hand, and
  `accept` only prints a reminder to check the tip height.

## Verification steps

- Coordinator, each file: `accept` runs `snarkjs zKey.verifyFromR1cs` (the full chain from r1cs +
  ptau), checks the circuit hash, checks the file extends the head by one contribution, and checks
  the hash the contributor sent and the receipt.
- Coordinator, end: `finalize` re-verifies the final zkey, checks the contribution list equals the
  accepted chain plus the recorded beacon, exports the vkey and Solidity verifier, and writes
  `final/ceremony_transcript.json` and `final/SHA256SUMS.txt`.
- Anyone: `node coordinator.mjs audit --transcript ... --zkey ... --r1cs ... --ptau ... [--vkey ...] [--sol ...] [--my-hash ...]`
  checks file hashes, snarkjs verify, contribution names/hashes/order, beacon value and
  iterations, drand randomness = sha256(signature), vkey and verifier = exports of the zkey.
- Contributors: `audit --my-hash <their hash>` or a look at the transcript.
- Plain snarkjs gives the same contribution list: `npx snarkjs zkey verify <r1cs> <ptau> <final.zkey>`.

## Secrets and records

- Contributor randomness: 64 bytes from `crypto.randomBytes` passed in memory to
  `snarkjs.zKey.contribute`, which mixes in another 64 OS random bytes; optional typed text is read
  hidden. Nothing secret goes to disk, a log, or a command line (the snarkjs CLI would take `-e` on
  the command line, which is why the kit uses the library).
- Receipts, state and transcripts hold names, hashes, versions, OS type and UTC dates. Paths are
  repo-relative or base names only; no usernames, hostnames or home paths.
- `ceremony/v4/ceremony_state.json` is the coordinator's log; every command appends to it.

## Rehearsal

- `node ceremony/rehearse.mjs` (refuses to run while `results/v4/bench/RUNNING` exists).
- Tiny circuit, local 2^8 powers of tau (one throwaway contribution), three contributors through
  `kit` and the wrapper scripts (Windows: `contribute.ps1`, Git Bash `contribute.sh`,
  `contribute.ps1`), each with fresh OS randomness, a dummy beacon marked REHEARSAL ONLY,
  `finalize`, `audit`, then a Groth16 proof with the rehearsal key.
- Negative checks that must be refused: stale base, wrong reported hash, tampered file, beacon on
  a non-head file, finalize before the beacon, audit of a missing hash, drand response mismatches,
  Bitcoin height mismatch, `ceremony` label shortcuts, contribution after the announced round.
- Result: `rehearsal/REHEARSAL_TRANSCRIPT.json` (`result`, `failures`, every check). It records no
  durations.

## Commands

```
node ceremony/coordinator.mjs init [--r1cs f] [--ptau f] [--dir d] [--label ceremony|rehearsal] [--min-contributions 3]
node ceremony/coordinator.mjs kit --out <folder outside the repo> [--with-verify-files]
node ceremony/coordinator.mjs accept <zkey> --hash <hex> --receipt <file> --contributor "<name>"
node ceremony/coordinator.mjs verify <zkey>
node ceremony/coordinator.mjs beacon-plan --kind drand --at <ISO time> --announced "<where>"
node ceremony/coordinator.mjs beacon <head zkey> <randomness> 10 --drand-json <saved response>
node ceremony/coordinator.mjs finalize
node ceremony/coordinator.mjs audit --transcript f --zkey f --r1cs f --ptau f --vkey f --sol f
node ceremony/coordinator.mjs status
```

Defaults: r1cs `circuits/build/v4/credential_auth_v4.r1cs`, ptau
`setup/ptau/powersOfTau28_hez_final_15.ptau` (pin checked in `setup/pins.json`, then
`setup/pins_v4.json`; both read only), dir `ceremony/v4`, label `ceremony`, 3 contributions minimum.
Label `ceremony` refuses `--no-pin`, `--allow-unfrozen` and `--allow-past`, and needs
`docs/v4/FREEZE.md` to list the r1cs SHA-256 (or `--frozen-sha256`).

## Known limits

- The kit enforces the count (`--min-contributions 3`); the follow-up also needs 3 distinct
  names, but only the coordinator can say who is external (`scripts/ceremony/followup.sh --external`).
- No lockfile for a kit used outside the repo: `npm install` resolves snarkjs 0.7.4 exactly, its
  dependencies by range. The scripts refuse any snarkjs other than 0.7.4.
- The drand BLS signature is not verified in-kit (see Beacon).
- `SHA256SUMS.txt` and `kitFilesSha256` hash the files as checked out; `.gitattributes` gives
  `*.ps1` CRLF, so hashes of `contribute.ps1` differ between checkouts with different line endings.
- If the circuit outgrows 2^15 (v4 needs 17,459 of 32,768: `circuits/build/v4/circuit_info.json`),
  the 2^16 Hermez file must be fetched, checked and pinned first (TASKS S23), then passed with `--ptau`.
