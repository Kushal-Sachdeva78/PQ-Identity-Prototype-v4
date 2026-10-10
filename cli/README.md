# cli

`make demo` (`npx tsx cli/demo.ts`) — the full credential lifecycle with
human-readable, phase-banded output:

```
Phase 0 · Local ledger (single-node EVM)
Phase 1 · DID registration (Algorithm 1)
Phase 2 · Revocation accumulator (depth-32 Poseidon SMT)
Phase 3 · Credential issuance (Algorithm 2)
Phase 4 · Two-phase authentication (Algorithm 3)  — prove (snarkJS + rapidsnark), verify
Phase 5 · Revocation (Algorithm 4) + post-revocation rejection
```

It exercises the same `harness/e2e_core.ts` lifecycle as the headless `e2e` runner, and writes
a transcript to `results/demo_transcript.txt` for the supplementary materials. Exit code is 0
only if every step — including the required post-revocation rejection — passes.
