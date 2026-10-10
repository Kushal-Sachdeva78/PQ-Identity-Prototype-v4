# Phone kit (TASKS E1)

Protocol, definitions and every step: `docs/v4/PHONE_PROTOCOL.md`. Longfellow facts:
`packs/E1_longfellow_comparison.md`. Two paths, always reported separately: native (Mopro) and
Safari (snarkJS). Dev key until the ceremony.

| Folder / file | Purpose | Runs on | Tested here (Windows, 2026-09-27) |
|---|---|---|---|
| `scripts/make_input.ts` | honest v4 input = the Phase D laptop input (no Anvil) | Node 24 | yes (`--check-witness`: R1CS satisfied) |
| `scripts/key_size.mjs` | zkey/wasm bytes and gzip sizes -> `results/key_size.json` | Node | yes |
| `scripts/phone_summary.py` | medians, IQR, bootstrap CIs per path x device x mode | Python 3 + numpy | synthetic input only |
| `scripts/energy_analysis.py` | trace CSV + marker CSV -> energy per proof | Python 3 + numpy | synthetic input only |
| `mopro/` | Mopro crate glue, Config.toml, build scripts, SwiftUI app, simulator test | macOS + Xcode | no (no macOS here) |
| `safari-fallback/` | page + dependency-free LAN server | Node (server), Safari (page) | page and server in desktop Chromium on 127.0.0.1 only |
| `inputs/` | generated inputs and their hashes | - | generated |

Quick commands (repo root):

```
node --import tsx mobile/scripts/make_input.ts --check-witness
node mobile/scripts/key_size.mjs
python mobile/mopro/scripts/check_pins.py
node --import tsx mobile/safari-fallback/serve.ts          # Safari path
bash mobile/mopro/scripts/scaffold.sh                        # native path, on a Mac
bash mobile/mopro/scripts/build_bindings.sh mobile/mopro/_work/pqid_v4_mopro device
(cd mobile/mopro/ios && xcodegen generate)
python mobile/scripts/phone_summary.py
```

CI: `.github/workflows/ios-mopro.yml`, manual only, after HANDOFF Approval A1 (simulator; no
phone numbers).
