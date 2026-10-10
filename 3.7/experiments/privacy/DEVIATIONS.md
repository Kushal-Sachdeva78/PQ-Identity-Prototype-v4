# Attempts and harness corrections

## Attempt 1, finished 2026-10-06 22:29 UTC (7 October IST)

`run-01/` preserves all 38 completed calls, before/after source hashes and the fatal
error. All completed calls met their prespecified expected outcomes. The final
malformed-date control was not dispatched: the harness tried to assign to the
frozen policy returned by `VerifierV4.newRequest`, causing a TypeError. This is a
harness failure, not a wallet acceptance/refusal result.

The original runner is saved as `run-attempt-01.ts`, matching the hash recorded in
`run-01/run_start.json`. The correction clones the returned public request before
the control mutates it; every other request has equal public field values. Protocol,
variant, case order and expected outcomes are unchanged. A new complete run uses
fresh wallets, keys and chain state. It is not pooled with attempt 1.

## Complete attempt 2 and later evidence audit

Attempt 2 completed on 6 October 2026 at 22:31 UTC (7 October IST): 78 calls,
78 expected outcomes, 33 verified replies and 45 expected refusals. No experimental
protocol or policy change was needed. `run-02` is the primary complete run.

On 8 October IST, the saved evidence was audited with `validate.py` without rerunning
experiments. The generator `prepare.mjs` was made idempotent by preserving an existing
preregistration timestamp rather than attempting to overwrite it on a second call.
`prepare-original.mjs` retains the initial generator. The variant, protocol,
preregistration, runner and run results were not changed by this maintenance.
