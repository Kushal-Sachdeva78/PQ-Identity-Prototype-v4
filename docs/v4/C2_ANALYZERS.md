# C2: static analyzers on v2, v3, v4 and the revocation-gadget harnesses

Embargo (DECISIONS D-008): the v3 revocation-gadget soundness issue is named only
neutrally here. The per-tool verdict on that issue, with reasons, is in
`private/C2_tool_verdicts.md` (gitignored).

## Tools and runs

| Tool | Version | Backend / mode | Outputs |
|---|---|---|---|
| circomspect | 0.9.0 (cargo build, user space) | default passes | `results/v4/analyzers/circomspect_{v2,v3,v4,smt_harness_plain,smt_harness_fixed}.{txt,sarif}` (paths scrubbed to `<repo>`) |
| Picus | commit 138b151d, Racket 9.3 | z3 5.1.0 (no cvc5 finite-field build exists for Windows, DECISIONS D-009), `--timeout 5000` ms per query | `results/v4/analyzers/picus_*.{txt,json}` |

Picus runs (wall-clock limit set by `timeout`):

| Run | Input | Mode | Limit | Exit | Result |
|---|---|---|---|---|---|
| picus_smt_harness_plain | SMT exclusion harness, depth 4, as in v2/v3 | default | not recorded | 8 | "properly constrained" |
| picus_smt_harness_fixed | same harness with the booleanity fix | default | not recorded | 8 | "properly constrained" |
| picus_smt_harness_plain_strong | plain harness | `--strong` | 900 s | 124 | timed out, no verdict |
| picus_smt_harness_fixed_strong | fixed harness | `--strong` | 900 s | 124 | timed out, no verdict |
| picus_imt_d4 | v4 IMT non-membership twin, depth 4 | default | 1800 s | 8 | "properly constrained" |
| picus_v2_main, picus_v3_main, picus_v4_main | the three main circuits | default | 3600 s | 8 | "properly constrained" |

## What the results mean

- Picus in default mode checks that every OUTPUT signal is uniquely determined by the
  inputs. None of the analyzed main components declares an output signal (all six take
  public inputs only), so "properly constrained" holds trivially and says nothing about
  soundness. This is a property of how the circuits are written, not a tool failure.
- `--strong` asks for uniqueness of every signal. It is the mode that could say something
  about these circuits; it did not finish within 900 s even on the depth-4 harness (z3
  backend, weak on field arithmetic, as recorded in DECISIONS D-009).
- circomspect reports notes (field arithmetic and comparisons in loop counters) on every
  file and these warnings:
  - v2: 2 "intermediate signal in fewer than two constraints";
  - v3: 1 of those, 1 "Num2Bits aliasing";
  - v4: 1 intermediate-signal warning, on `nonceSq` (the deliberate nonce-binding square,
    route R1-e and mutation row G17);
  - harnesses (plain and fixed): notes only, no warnings.
- Neither tool, as run, flags the revocation-gadget soundness issue (details under
  embargo). The finding came from the R1CS-level attack method (attacker generator plus
  real R1CS, `harness/v4/r1cs_tools.ts`) and route A3-E of the v3 suite.

## Follow-ups

- Linux CI job with cvc5 finite-field Picus once the private repository exists (HANDOFF
  Approvals A1); rerun `--strong` there without the Windows z3 limit.
- A Picus harness that exposes the gadget's decision as an output would turn the default
  check into a meaningful one; not done in this round (tool research, not needed for v4,
  whose IMT gadget replaces the SMT).

## Provenance note (2026-10-01)

- The `timestamp` fields in the Picus logs (`results/v4/analyzers/picus_*.json`, one JSON line
  per event) are Windows local time, IST (UTC+05:30), written without a zone; for example
  `2026-09-27T13:47:46` in `picus_v4_main.json`. Read as IST they fall before commit 0a32c7d
  (2026-09-27 13:50 IST) that added them and before the file mtimes; read as UTC they would fall
  about 5 h after that commit. Any script that compares them with UTC fields must add +05:30
  first. The raw tool output stays unchanged. Found by the provenance audit
  (`results/v4/provenance/AUDIT.md`).
