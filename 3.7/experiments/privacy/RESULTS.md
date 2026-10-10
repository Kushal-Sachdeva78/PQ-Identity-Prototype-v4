# Paired-history privacy experiment

The complete run finished on **7 October 2026 at 04:01 IST** (6 October
22:31 UTC). All 78 prespecified wallet-call outcomes matched their expectations:
33 replies passed the real verifier, including Groth16 verification, and 45 calls
produced the expected refusal. These are diagnostic calls, not additions to the
frozen 86-attack catalogue. Sources and development-key artifacts were unchanged.

| Observation | Shipped wallet | Isolated stateless variant | Evidence class |
|---|---:|---:|---|
| Paired histories with different reply presence | 2 of 6 scenarios | 0 of 6 | [M, dev] |
| Paired histories with different reply/check/message observations | 3 of 6 | 0 of 6 | [M, dev] |
| Last pre-midnight / first post-midnight answer offsets | -301 / +300 s | -301 / +300 s | [M, dev] boundary controls |
| Deliberate daily blackout for current-date requests | No fixed blackout | 600 s (0.694444%) | [S] configured schedule |

For asymmetric previous-day histories, the shipped wallet refused a current-day
challenge to the reserved holder and answered the fresh holder. This also occurred
when the earlier request failed the age predicate: the date had already been
reserved. A future-date probe away from midnight made both holders refuse, but
their exact messages differed according to recent history. No-history and
symmetric-history controls had equal observations.

The isolated variant removed date memory, accepted only the current UTC date, and
used one fixed date-refusal message during its midnight blackout and for non-current
dates. Compared observations were equal in all six scenarios. Honest boundary and
birthday controls confirmed the 601-second gap across dates; malformed-date,
nonstandard-threshold, unknown-type and revoked-holder controls still refused.
The revoked-holder and failed-predicate messages remained different, so the variant
does not remove every refusal channel.

The blackout fraction is arithmetic on 86,400 integer seconds, not measured uptime.
These local tests used synchronized injected clocks, real cryptography and the
existing development key. They were selected internally from reviewer feedback, not by
an independent tester. Timing, browser transport, clock-offset, configuration and
blob-sync channels were not tested. The variant is not installed and does not
change the snapshot's C2 verdict or prove unlinkability.

## Evidence and validation

- `PROTOCOL.md` and `preregistration.json`: written and hashed before measurements.
- `run-02/events.jsonl`: all 78 raw request/outcome records, public proof material,
  exact refusal text and successful verifier check vectors.
- `run-02/results.json`: primary complete-run results; not pooled with attempt 1.
- `run-01/`, `run-attempt-01.ts`, `attempt-01.console.log`: preserved partial attempt
  and the frozen-request mutation harness failure, explained in `DEVIATIONS.md`.
- `wallet_stateless_v1.diff` and `variant_change.json`: exact isolated policy change.
- `validation.json`: 78 events audited, 52 source/artifact hashes unchanged,
  and all four used circuit/key artifacts matched their existing pins.
- TypeScript checking completed successfully before both attempts.

From the repository root, rerun on an idle machine with no benchmark RUNNING marker:

```powershell
$env:TSX_DISABLE_CACHE='1'
$env:TEMP=(Resolve-Path -LiteralPath '3.7/experiments/privacy').Path
$env:TMP=$env:TEMP
node node_modules/tsx/dist/cli.mjs --tsconfig 3.7/experiments/privacy/tsconfig.json 3.7/experiments/privacy/run.ts
```

Each execution creates a fresh numbered run directory. Existing results are not
overwritten. `validate.py` audits the primary `run-02` evidence without rerunning
proofs. The local `tsconfig.json` maps package imports to the shipped source because
this copied workspace's `node_modules/@pqid` directories are empty.
