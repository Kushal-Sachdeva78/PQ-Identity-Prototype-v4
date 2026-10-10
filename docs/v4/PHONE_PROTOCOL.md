# Phone protocol (TASKS E1): native Mopro path and Safari path

Written 2026-09-27, before any phone run. Steps, definitions and rules only; no results.
Labels: [M] measured, [S] estimate, [A] assumption or protocol choice, [VERIFY] a value only the
student's device, Mac or lab set-up can supply. The kit is untested on macOS and on an iPhone
(section 10 lists what was checked on the Windows host).

## 0. Scope and reporting rules

- Two paths, reported separately in every table, figure and ledger entry. They are never pooled
  into one "phone" number.
  - Native: Mopro (mopro-cli 0.3.7), Rust witness generator (rust-witness, the circuit wasm
    transpiled into the app binary) and the arkworks Groth16 prover. Source: `mobile/mopro/`.
  - Safari: snarkJS 0.7.4 in Safari on the same iPhone, wasm witness generator, served from the
    laptop over the LAN. Source: `mobile/safari-fallback/`.
- CI simulator runs (`.github/workflows/ios-mopro.yml`) only show that the native path builds,
  proves and verifies. They give no phone timing, memory or energy. Their logs carry the label
  `[M-sim] ... NOT a phone measurement` and go to `results/v4/phone/ci/`.
- Key: the v4 dev key (`setup/out/v4/credential_auth_v4_dev.zkey`, pinned in
  `setup/pins_v4.json`). Every result carries `keyLabel: "dev"` until the ceremony key replaces
  it (TASKS I). Runs for the paper happen after the B7 freeze; a re-key or circuit change means
  new inputs (`make_input.ts`), a new key size file and new runs.
- Statement proved: the fixed honest input of the laptop Phase D series
  (`harness/v4/bench/inputs.ts` `buildFixtureProofInputV4()`), so phone and laptop prove the same
  statement with the same witness. `mobile/inputs/v4_input.json` SHA-256
  `726b9010786e510096c1c28b566de40fc40e552044a8bf1d1bb84a559ccb1e92` (compact text, bench-lock
  convention); it equals the v4 input of the Phase D smoke lock (`mobile/inputs/v4_input.meta.json`,
  `smokeBenchLock`). All values are published fixture constants (holder secret 123456789).
- Device values [VERIFY]: iPhone model identifier, iOS version, Safari version, battery health,
  storage free, room temperature. The native log records model identifier, iOS version, core
  count and RAM itself; the Safari result records the user agent.

## 1. Files

| What | Path |
|---|---|
| Input builder (no Anvil) | `mobile/scripts/make_input.ts` -> `mobile/inputs/v4_input.json` (snarkJS form), `v4_input.mopro.json` (Mopro form: every signal an array of decimal strings), `v4_input.meta.json` (hashes, expected public signals) |
| Pin check | `mobile/mopro/scripts/check_pins.py` |
| Key and download sizes | `mobile/scripts/key_size.mjs` -> `mobile/results/key_size.json` |
| Mopro project | `mobile/mopro/Config.toml`, `mobile/mopro/rust/circuit_glue.rs`, `mobile/mopro/rust/build.rs`, `mobile/mopro/scripts/{scaffold.sh, patch_template.py, build_bindings.sh, pick_simulator.py}` |
| iOS app | `mobile/mopro/ios/project.yml` (XcodeGen), `mobile/mopro/ios/PQIDPhone/*.swift`, test `mobile/mopro/ios/PQIDPhoneTests/ProofTests.swift` |
| CI | `.github/workflows/ios-mopro.yml` (manual only; after HANDOFF Approval A1) |
| Safari page and server | `mobile/safari-fallback/{index.html, app.js, serve.ts}` |
| Analysis | `mobile/scripts/phone_summary.py` (timing, memory), `mobile/scripts/energy_analysis.py` (energy) |
| Results | `results/v4/phone/native_<utc>_<session>.json`, `results/v4/phone/safari_<utc>.json`, `results/v4/phone/summary.json`, `results/v4/phone/energy_*.json`, `results/v4/phone/ci/` |

The zkey and wasm are never copied into `mobile/`: the Xcode project references the zkey in
place and Xcode copies it into the app bundle at build time; `build.rs` reads the wasm in place;
`serve.ts` serves both in place.

## 2. Definitions

- Cold, native: the first proof after the app process starts. Relaunch = swipe the app away in
  the App Switcher, then open it from the Home Screen. The app counts proofs per process and
  never records a second cold proof in one process.
- Cold, Safari: the first proof after the page loads (reload or new tab). Safari's web-content
  process and its caches may survive a reload, so this is a page-level cold start and is not
  the same as the native cold start. The result records `env.navigationType`.
- Warm: later proofs in the same process (native) or on the same page (Safari), after 5
  warm-up proofs that are not analysed.
- Timed work, native: `proveMs` = wall time of `generateCircomProof` (witness plus Groth16 proof,
  plus any zkey reading Mopro does inside the call [VERIFY whether Mopro caches the parsed zkey
  between calls]). `verifyMs` = `verifyCircomProof`, run after the proof window.
- Timed work, Safari (the calls of `docs/v4/BENCH_PROTOCOL.md` "What is timed"): `witnessMs`
  (`snarkjs.wtns.calculate`, wasm bytes in memory), `proveMs` (`snarkjs.groth16.prove`, zkey
  bytes in memory), `wpMs` = witness + prove, `verifyMs`. Downloads are timed separately
  (`download.*Ms`) and are not part of any proof time.
- Peak memory, native: `phys_footprint` from `task_info(TASK_VM_INFO)`, sampled every 5 ms during
  the proof (`sampledPeakBytes`, and `sampledPeakAboveBaselineBytes` against the reading just
  before the proof), plus the process-lifetime peak `ledger_phys_footprint_peak` after the proof
  (`lifetimePeakAfterBytes`). Field revisions: xnu `osfmk/mach/task_info.h`. Sampling can miss a
  spike shorter than 5 ms; the lifetime peak cannot, but it covers the whole process.
- Peak memory, Safari: not measured. `performance.memory` is a Chrome-only API and Safari has no
  replacement; the result says so (`memory.performanceMemory: null`). A manual reading from Web
  Inspector (Timelines, Memory) on a Mac is possible [VERIFY]; it would be a separate, labelled
  reading.
- Key download size: bytes and gzip size of each file (`mobile/scripts/key_size.mjs`, zlib levels
  6 and 9, in memory). [M] values in `mobile/results/key_size.json` (dev key, 2026-09-27):
  zkey 11,426,668 B (gzip-9 7,890,118 B); wasm 4,465,314 B (gzip-9 1,078,740 B); snarkjs.min.js
  470,367 B (gzip-9 107,589 B). Totals in the same file: native bundle resources 11,436,162 B
  (zkey + input + meta; the app binary is not included); Safari per cold page load 16,376,324 B
  uncompressed, 9,081,917 B if gzip-9 were used (serve.ts sends files uncompressed, plus a small
  `manifest.json`). The native app binary size (it contains the transpiled witness generator) is
  measured on the Mac: size of the Release `PQIDPhone.app` [VERIFY method: Finder size or
  `du -sk`]. Re-run `key_size.mjs` after any re-key; a ceremony zkey is not assumed to have the
  same byte size.
- Energy per proof: net energy above the idle baseline over [proof_start, proof_end] (section 7).

## 3. Controls (both paths)

Every item is recorded per proof by the native app (`before`/`after` snapshots) where iOS allows
it; the student records the rest in the session notes.

| Control | Rule [A] | Recorded by |
|---|---|---|
| Device | One iPhone for all series of a campaign | native log `device`; Safari `env.userAgent` |
| Charging state and battery path | Timing and memory series on battery, unplugged; battery level 50 % to 100 % at the start; energy series follow section 7 | native `batteryState`, `batteryLevel`; Safari: student notes |
| Low Power Mode | Off | native `lowPowerMode`; Safari: notes |
| Thermal state | Native: each proof starts only at `nominal`; the app waits up to 600 s in 5 s steps, then runs and flags the proof (`thermalNotNominalAtStart`); flagged proofs are excluded and repeated. Safari: no API; keep the same idle times; note any warmth | native `thermalState` before/after |
| Phone placement | Out of its case, on a table, not in the hand; room temperature noted [VERIFY] | notes |
| Background activity | Airplane Mode on, Wi-Fi on only for the Safari path; Bluetooth off; other apps closed; Focus / Do Not Disturb on; no charging, no iCloud or App Store downloads in progress | notes |
| Screen | Auto-Brightness off, True Tone and Night Shift off, brightness fixed [VERIFY level] for all series; screen stays on (native: the app disables the idle timer while running; Safari: Auto-Lock set to Never, because the Wake Lock API needs a secure context and the LAN page is plain http) | native `screenBrightness`; Safari `wakeLock`, notes |
| Tab / app in front | The app or the Safari tab stays in front during a run | Safari `hiddenDuringRun` (excluded if true) |
| Idle | Cold runs: at least 120 s idle between the end of one run and the next launch, then 30 s settle in the app (Safari: 10 s after the downloads) | protocol fields in each log |

## 4. Native path

### 4a. Device runs on a Mac with Xcode (the only source of native phone numbers)

Needs [VERIFY]: a Mac with Xcode and its command-line tools, Homebrew, the iPhone and its cable.

1. Tools (user-space):
   ```
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
   cargo install mopro-cli --version 0.3.7 --locked
   brew install xcodegen cmake
   ```
2. Get the repo on the Mac (after Approval A1: clone the private repo; before it: copy the folder).
   The wasm, the zkey and `mobile/` are tracked files.
3. From the repo root:
   ```
   python3 mobile/mopro/scripts/check_pins.py
   bash mobile/mopro/scripts/scaffold.sh
   bash mobile/mopro/scripts/build_bindings.sh mobile/mopro/_work/pqid_v4_mopro device
   cd mobile/mopro/ios && xcodegen generate && open PQIDPhone.xcodeproj
   ```
   `scaffold.sh` runs `mopro init --adapter circom` and `patch_template.py`, which replaces the
   template's multiplier2 registration with `mobile/mopro/rust/circuit_glue.rs` and stops with an
   error if the Mopro template has changed shape. Record the mopro-cli, Rust and Xcode versions
   (`mobile/mopro/ios/MoproiOSBindings/PQID_BUILD_INFO.txt` holds the first two).
4. Xcode: target PQIDPhone, Signing & Capabilities: pick a Team (a free Apple ID "Personal Team"
   is enough for installing on one's own phone [VERIFY]); change the bundle identifier if Xcode
   says it is taken. On the iPhone: Developer Mode on (Settings, Privacy & Security), then trust
   the developer certificate (Settings, General, VPN & Device Management) [VERIFY menu names for
   the iOS version].
5. The scheme runs the Release configuration (project.yml). Run once from Xcode to install, then
   stop it in Xcode. Every timed run is started from the Home Screen, never under the debugger.
6. Cold series (30 analysed runs): in the app turn on "Run the cold proof automatically on
   launch", settle 30 s, memory sampling on. Then 30 times: swipe the app away, wait 120 s, open
   it from the Home Screen, wait until the status line says "Done: 1 proof(s)". One log file per
   launch. Repeat runs that were flagged or failed until 30 are usable.
7. Warm series: turn the automatic cold proof off, relaunch, tap "Warm series" (settings: 5
   warm-up, 30 warm, gap 10 s). The first proof of that launch is recorded as cold, then 5
   warm-up and 30 warm proofs.
8. After the timed runs: tap "Check zkey SHA-256" (it reads the 11 MB zkey, so never before a
   cold proof).
9. Export: Files app, On My iPhone, PQID v4, `pqid_phone`, or Finder on the Mac (iPhone, Files),
   or the share buttons in the app. Copy the JSON files to `results/v4/phone/` on the laptop.
10. Summary: `python mobile/scripts/phone_summary.py` -> `results/v4/phone/summary.json`.

### 4b. CI simulator (after HANDOFF Approval A1; no phone numbers)

- GitHub, Actions, "ios-mopro (manual)", Run workflow (runner macos-15 by default, mopro-cli
  0.3.7, warm runs 0).
- The job scaffolds and patches the crate, builds the simulator bindings, builds the unsigned
  simulator app (Release), runs `ProofTests.testColdProofVerifiesOnSimulator` (one proof,
  verification, public-signal and zkey-hash checks) and uploads `ci_logs/` (build logs, xcresult,
  `native_ci_simulator_<utc>.json`, the unsigned app zip).
- Put the JSON in `results/v4/phone/ci/`. It is evidence that the native path works, never a
  phone timing, memory or energy value.

## 5. Safari path (over the LAN)

1. Laptop and iPhone on the same private Wi-Fi network (not a public one).
2. On the laptop, from the repo root:
   ```
   python mobile/mopro/scripts/check_pins.py
   node --import tsx mobile/safari-fallback/serve.ts
   ```
   It prints `http://<lan-ip>:8765/`. Windows asks once whether Node may accept connections on
   private networks; allow it for this session. The server refuses to start if the wasm, zkey or
   vkey differ from `setup/pins_v4.json`.
3. iPhone: Settings, Display & Brightness, Auto-Lock: Never (for the session). Safari, normal tab.
4. Cold campaign (30 analysed runs): open
   `http://<lan-ip>:8765/?mode=cold&runs=30&idle=120&settle=10` and leave Safari in front. Each
   page load downloads the files (timed), waits 10 s, proves once, posts
   `results/v4/phone/safari_<utc>.json`, waits 120 s and reloads. All runs share one
   `campaignId`.
5. Warm series: open `http://<lan-ip>:8765/?mode=warm&warmup=5&n=30&gap=10&settle=10`. The first
   proof is recorded as cold, then 5 warm-up and 30 warm proofs; one file is posted at the end
   ("Post results again" if the POST failed).
6. Stop the server with Ctrl+C. Run `python mobile/scripts/phone_summary.py`.

## 6. Repetitions

| Path | Mode | Analysed n | Warm-up | Spacing | Excluded (repeated) |
|---|---|---|---|---|---|
| Native | cold | 30 (30 launches) | none | 120 s idle + 30 s settle | error, not verified, public signals differ, thermal flag |
| Native | warm | 30 (one launch) | 5 | 10 s gap | same |
| Safari | cold | 30 (30 page loads) | none | 120 s idle + 10 s settle | error, not verified, public signals differ, tab hidden |
| Safari | warm | 30 (one page) | 5 | 10 s gap | same |

- Statistics (`phone_summary.py`, as `docs/v4/BENCH_PROTOCOL.md`): n, median, Q1, Q3, IQR (numpy
  "linear"), min, max; percentile bootstrap 95 % CI of each median and of each cold/warm ratio of
  medians, B = 10,000, seed 20260927. Groups: path x device x kind; nothing is pooled across
  paths or devices.
- Order [A]: native cold, native warm, Safari cold, Safari warm, on one day, same room, same
  settings. Cross-path interleaving is not practical (app switching); this is a known limit.

## 7. Energy per proof (the student's lab set-up; instrument values unknown here)

Every instrument-specific value is [VERIFY]; fill each one from the energy paper's set-up before
the first energy run and keep them in the session notes.

| Item | Value |
|---|---|
| Instrument (make, model, what it measures) | [VERIFY] |
| Where it sits in the power path (USB power meter, battery-path shunt, bench supply in place of the battery, other) | [VERIFY] |
| Sampling rate | [VERIFY]; `energy_analysis.py` warns when a proof window or a baseline window holds fewer than 10 samples (`--min-samples`) |
| Units and sign of the exported trace | [VERIFY]; the script takes a power column, or voltage and current columns with units (V/mV, A/mA/uA) and sign options |
| Marker method for proof start and end in the trace | [VERIFY]; the app offers (a) idle windows before and after each proof (settings "Idle before/after proof", logged as `pre_idle_start` and `post_idle_end`), (b) a full-screen white flash of 300 ms before and after each proof (`flash_on`, `flash_off`), for an instrument or photodiode that sees the screen, (c) UTC time stamps of every marker in the log |
| Clock synchronisation between phone log and trace | [VERIFY]; the offset X (trace time = UTC epoch seconds + X) goes to `--clock-offset-s`; the app clock is the iOS system clock |
| Baseline idle subtraction | Mean power in the pre-idle window (from `pre_idle_start` to the first flash or proof start), or explicit baseline columns in the marker file; net = gross - baseline x duration |
| Repetitions | [A] a separate energy series: 30 warm proofs, 5 warm-up, idle 5 s before and after each proof, flash on, memory sampling off (it wakes a thread every 5 ms); cold energy optional |

- Analysis: `python mobile/scripts/energy_analysis.py --markers-from-log <native or safari log>
  --clock-offset-s <X> --out-markers <m.csv>`, then `python mobile/scripts/energy_analysis.py
  --trace <trace.csv> --markers <m.csv> [column options] --out results/v4/phone/energy_<path>_<utc>.json`.
  Output per proof: gross J, baseline W, net J, duration, sample counts; per kind: n, median,
  mean, IQR, bootstrap 95 % CIs (B = 10,000, seed 20260927).
- iPhone confounds to control or record [VERIFY each against the set-up]:
  - Charging state and battery path: on USB power the phone also charges the battery unless it
    is full, and a USB meter then sees charging current; on battery, the instrument must sit in
    the battery path. The app logs `batteryState` (unplugged, charging, full) per proof.
  - Low Power Mode (logged), thermal throttling (logged), background activity (Airplane Mode,
    no downloads, no iCloud sync), radios (Wi-Fi needed only for Safari), notifications (Focus).
  - Screen: the display is a large, near-constant load; brightness fixed, Auto-Brightness off,
    True Tone off; the flash markers change display power, so the baseline window ends before
    the first flash (the marker converter does this).
  - Native and Safari energy are separate series and separate rows.

## 8. Reporting

- One row per path x device x mode. Native rows: prove, verify, peak memory, energy. Safari rows:
  witness, prove, witness+prove, verify, download, energy; memory "not measured (Safari has no
  API)". CI simulator rows only as "builds, proves, verifies" (no numbers).
- The laptop comparison uses the Phase D series on the same input (`results/v4/bench/summary.json`
  after the timed campaigns).
- Numbers reach the paper only through the claims ledger (`ledger/`), from the results files above.

## 9. Known limits [A]

- iOS page cache: the zkey may still be in memory after a relaunch; native cold means a fresh
  process, not a cold file cache (the same limit as the laptop protocol).
- Mopro internals (zkey caching between calls, thread count of the arkworks prover) are not
  controlled [VERIFY from the Mopro source for the version used].
- Native and Safari differ in witness generator (transpiled C vs wasm) and prover (arkworks vs
  snarkJS/ffjavascript), so a native/Safari difference is not a pure platform effect.
- Safari: page-level cold; no memory figure; `performance.now()` may be coarsened outside
  cross-origin isolation (the result records `crossOriginIsolated`, false on plain http).
- The simulator is not a phone.
- The kit is untested on macOS and iOS; the first Mac or CI run may need fixes (every [VERIFY]
  above and in the source files).

## 10. What was checked on the Windows host (2026-09-27)

- `node --import tsx mobile/scripts/make_input.ts --check-witness`: input SHA-256 equals the v4
  input of the Phase D smoke lock; the witness satisfies the R1CS; wasm, zkey, vkey match
  `setup/pins_v4.json`. The Mopro-form input has the same 25 signals and values.
- `node mobile/scripts/key_size.mjs` -> `mobile/results/key_size.json`.
- `python mobile/mopro/scripts/check_pins.py`: all checks ok.
- Safari page and server in the desktop Chromium browser pane against `serve.ts` on 127.0.0.1
  with a scratch output folder: 5 cold proofs (including a 2-run automatic-reload campaign), all
  verified with matching public signals, all posted. A functional check only: Chromium is not
  Safari, the tab was hidden, and no timing from it is a result.
- `patch_template.py` on a synthetic copy of the Mopro template files read from GitHub on
  2026-09-27; `energy_analysis.py` and `phone_summary.py` on synthetic inputs (not measurements).
- ESLint (repo config) on `mobile/`: clean. TypeScript check of `mobile/**/*.ts`: clean.
- Not run anywhere yet: mopro-cli, the Rust build, XcodeGen, the Swift compile, the simulator,
  an iPhone, the GitHub workflow.
