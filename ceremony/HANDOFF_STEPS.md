# Real v4 ceremony: Kushal's steps and contributors' steps

For the frozen v4 circuit, after the IRIS snapshot. operator does not run these steps, contact
anyone or publish anything. Background and design: `ceremony/README.md`.
All coordinator commands run in PowerShell from the repo folder (`PQ-Identity-v4`).
Handout and incoming files live in sibling folders outside the repo (`..\ceremony_handouts`,
`..\ceremony_incoming`) so they are never committed.

## 0. Preconditions (check each one)

| Check | Command | Expected |
|---|---|---|
| IRIS snapshot taken | `git tag -l iris-snapshot` | prints `iris-snapshot` |
| Circuit frozen (TASKS B7) | `Get-FileHash circuits\build\v4\credential_auth_v4.r1cs` | the SHA-256 listed in `docs\v4\FREEZE.md` |
| No timed benchmark running | `Test-Path results\v4\bench\RUNNING` | `False` |
| Kit works today | `node ceremony/rehearse.mjs` | last line `REHEARSAL PASS` |
| Contributors lined up | (people) | 3 or more, each on their own computer with Node.js 20+; at least one outside the project, two or more is better |

- Tell each contributor in advance: the name they give is public (it is stored in the key and
  the transcript), and they will send one file back plus a hash by message.

## 1. Start the ceremony (day S)

```
New-Item -ItemType Directory -Force ..\ceremony_handouts, ..\ceremony_incoming
node ceremony/coordinator.mjs init
node ceremony/coordinator.mjs status
```

- `init` uses the defaults: r1cs `circuits/build/v4/credential_auth_v4.r1cs`, ptau
  `setup/ptau/powersOfTau28_hez_final_15.ptau` (checked against `setup/pins.json`), folder
  `ceremony/v4`, label `ceremony`, at least 3 contributions. It refuses if the r1cs SHA-256 is not
  in `docs/v4/FREEZE.md`.
- It writes `ceremony/v4/credential_auth_v4_0000.zkey` (deterministic: anyone can recompute it).

## 2. Fix and announce the beacon (same day, before anyone contributes)

Pick a UTC time after the last planned contribution, with margin (for example S + 7 days, 12:00 UTC).

```
node ceremony/coordinator.mjs beacon-plan --kind drand --at 2026-MM-DDT12:00:00Z --announced "<where and when you announce it>"
```

- It prints the drand round number N, its expected time and `https://api.drand.sh/public/N`.
- Announce exactly: the drand default network (League of Entropy mainnet), round N,
  `https://api.drand.sh/public/N`, expected at <time> UTC, beacon value = the `randomness` field,
  2^10 iterations. Where to announce (guide, contributors, repo, a public post) is your decision.
- Bitcoin instead of drand: `node ceremony/coordinator.mjs beacon-plan --kind bitcoin --height <H> --announced "..."`
  with H well above the current tip (check two block explorers).
- The plan cannot be changed afterwards. `accept` refuses contributions once round N is due.

## 3. One round per contributor (repeat for contributor 1, 2, 3, ...)

### 3a. Coordinator: make and send the kit

```
node ceremony/coordinator.mjs kit --out ..\ceremony_handouts\contributor_1 --with-verify-files
Compress-Archive -Path ..\ceremony_handouts\contributor_1\* -DestinationPath ..\ceremony_handouts\contributor_1.zip
```

- `kit` prints the input zkey name (first round: `credential_auth_v4_0000.zkey`), the output name
  the contributor should use (first round: `credential_auth_v4_0001.zkey`) and the input SHA-256.
- Size: about 58 MB with `--with-verify-files`, about 12 MB without (then the contributor cannot
  check their own output; you still verify it on `accept`).
- Send the zip through any file transfer (cloud link, email if it fits, USB).
- Send the printed input SHA-256 by a second route (message, call, in person).

### 3b. Contributor on Windows (PowerShell)

```
Expand-Archive contributor_1.zip -DestinationPath pqid_ceremony
cd pqid_ceremony
Get-FileHash -Algorithm SHA256 .\*
npm.cmd install
powershell -NoProfile -ExecutionPolicy Bypass -File .\contribute.ps1 -InputZkey .\credential_auth_v4_0000.zkey -Name "Their Name" -OutputZkey .\credential_auth_v4_0001.zkey -ExpectInputSha256 <input sha256> -R1cs .\credential_auth_v4.r1cs -Ptau .\powersOfTau28_hez_final_15.ptau
```

### 3b. Contributor on macOS / Linux

```
unzip contributor_1.zip -d pqid_ceremony && cd pqid_ceremony
shasum -a 256 -c SHA256SUMS.txt          # Linux: sha256sum -c SHA256SUMS.txt
npm install
bash contribute.sh credential_auth_v4_0000.zkey "Their Name" credential_auth_v4_0001.zkey --expect-sha256 <input sha256> --r1cs credential_auth_v4.r1cs --ptau powersOfTau28_hez_final_15.ptau
```

- `npm.cmd` rather than `npm` in PowerShell: the default execution policy can block the `npm.ps1` shim.
- Without the verification files, drop `-R1cs ... -Ptau ...` / `--r1cs ... --ptau ...`.
- Optional extra typed randomness: `-ExtraEntropy` / `--extra-entropy`.
- The contributor sends back `credential_auth_v4_0001.zkey` and `credential_auth_v4_0001.zkey.receipt.json`,
  and sends the printed `CONTRIBUTION_HASH` line by a second route (or posts it publicly).

### 3c. Coordinator: accept

Save the returned files in `..\ceremony_incoming\`, then:

```
node ceremony/coordinator.mjs accept ..\ceremony_incoming\credential_auth_v4_0001.zkey --hash <hash from the second route> --receipt ..\ceremony_incoming\credential_auth_v4_0001.zkey.receipt.json --contributor "Their Name"
node ceremony/coordinator.mjs status
```

- ACCEPTED: the file is copied to `ceremony/v4/credential_auth_v4_0001.zkey` and becomes the head.
  Make the next kit (3a) for the next contributor.
- REJECTED: nothing changes. Ask the same contributor to run again from a fresh kit of the current head.
- Your own contribution is allowed (same steps on your laptop). It counts toward the minimum of 3
  but is not independent; the outside contributors are the ones that matter.

## 4. Apply the beacon (after the announced time)

```
curl.exe -s https://api.drand.sh/public/<N> -o ..\ceremony_incoming\drand_<N>.json
curl.exe -s https://drand.cloudflare.com/public/<N>
node ceremony/coordinator.mjs status
node ceremony/coordinator.mjs beacon ceremony/v4/credential_auth_v4_000K.zkey <randomness from the JSON> 10 --drand-json ..\ceremony_incoming\drand_<N>.json
node ceremony/coordinator.mjs finalize
```

- The two `curl` outputs must show the same `randomness`. `000K` is the head `status` shows.
- Bitcoin plan instead: `node ceremony/coordinator.mjs beacon ceremony/v4/credential_auth_v4_000K.zkey <block hash> 10 --height <H>`
  after comparing the hash at height H on two block explorers.
- `beacon` refuses with fewer than 3 accepted contributions. If the round passed with fewer, start
  again with a new folder and a new announced plan (`init --dir ceremony/v4b`); the old files stay
  as a record.
- `finalize` writes `ceremony/v4/final/`: `credential_auth_v4_final.zkey`, `verification_key.json`,
  `Groth16Verifier.sol`, `ceremony_transcript.json`, `SHA256SUMS.txt`.

## 5. Check the result

```
node ceremony/coordinator.mjs audit --transcript ceremony/v4/final/ceremony_transcript.json --zkey ceremony/v4/final/credential_auth_v4_final.zkey --r1cs circuits/build/v4/credential_auth_v4.r1cs --ptau setup/ptau/powersOfTau28_hez_final_15.ptau --vkey ceremony/v4/final/verification_key.json --sol ceremony/v4/final/Groth16Verifier.sol
```

- Expected last line: `[audit] ALL CHECKS PASSED`.
- Send each contributor the `final/` files (or a link). Each one runs, from their kit folder:
  `node coordinator.mjs audit --transcript ceremony_transcript.json --zkey credential_auth_v4_final.zkey --r1cs credential_auth_v4.r1cs --ptau powersOfTau28_hez_final_15.ptau --my-hash <their hash>`
  or checks that the transcript lists their hash under their name.

## 6. What could be published (your decision; operator publishes nothing)

| File | Size | Contains | Note |
|---|---|---|---|
| `final/ceremony_transcript.json` | small | contribution names and hashes, beacon source and value, file hashes, tool versions, dates | names are public: get each contributor's consent |
| `final/verification_key.json`, `final/Groth16Verifier.sol`, `final/SHA256SUMS.txt` | small | public key material | needed by verifiers |
| `final/credential_auth_v4_final.zkey` | about 11 MB | proving key | needed by provers and auditors |
| `ceremony/v4/credential_auth_v4_000*.zkey` | about 11 MB each | intermediate keys | optional; lets anyone re-verify every step |
| `circuits/build/v4/credential_auth_v4.r1cs` | about 8 MB | the constraint system | auditors need it; check the private-terms rule (DECISIONS D-030) before publishing circuit material |
| Hermez ptau | 38 MB | phase 1 | link the Hermez URL and SHA-256 from `setup/pins.json` instead of re-hosting |
| `*.receipt.json` | small | contributor name, hashes, OS type | only with the contributor's consent |
| `ceremony/v4/ceremony_state.json` | small | the coordinator log | optional; no secrets |

- Order: the private repo first (HANDOFF Approval A1), any public release later.
- Anonymous builds (IRIS): the transcript holds contributor names; keep it out of anonymised material.

## 7. Hand back to operator (Phase I)

- Tell the next session: `Resume v4. Ceremony done: ceremony/v4/final.` Also say which
  contribution numbers came from people outside the project.
- Phase I (operator, `docs/v4/CEREMONY_FOLLOWUP.md`), in this order:
  - `bash scripts/ceremony/followup.sh --check-only --external <indexes>`;
  - then `bash scripts/ceremony/followup.sh --external <indexes>`: audit again, install the key
    under `setup/out/v4/` labelled `ceremony` (the dev files stay), pin it in the new file
    `setup/pins_v4_ceremony.json` (`setup/pins_v4.json` keeps its six dev entries), re-run the C1
    suite and the C3 mutation campaign with it into `results/v4/ceremony/`, add new ledger keys,
    and decide with you which `ceremony/v4/` files to commit.
- Keep the final files with LF line ends; a CRLF copy is not installed.
