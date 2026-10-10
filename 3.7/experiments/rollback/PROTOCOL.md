# Supplementary epoch rollback and stale-view experiment

This protocol is authored before execution for manuscript revision 3.7 on 2026-10-06. It is a new, internally selected, supplementary case series, not an independent holdout, an IID sample, a security probability, or an addition to the frozen 0/86 and public 0/84 catalogues. No timed benchmark is performed.

## Implementation and boundaries

Use unmodified packages/v4 code, the existing pinned development Groth16 artifacts, real ML-DSA/ML-KEM, and the actual RegistriesV4 contracts on a fresh loopback Anvil deployment. All generated files stay in this directory. No key or witness secrets are serialized. No existing results, packages, setup artifacts, support records are changed.

Two credentials are present at epoch 1. Revoke credential A at epoch 2 while credential B remains valid. Keep epoch 1's real signed statement and real witnesses. Advance chain/manual time by one hour plus one second between epochs, leaving epoch 1 inside its signed validity window. The remembered verifier accepts B at epoch 2 before testing A at epoch 1. The fresh verifier has no earlier acceptance. All sessions and proofs are fresh per case; no disabled verifier check is used.

A local read-only HTTP JSON-RPC proxy forwards reads to the same Anvil. In stale mode it replaces `latest` tags in eth_call with epoch 1's block and caps block/log reads there. It returns genuine historic contract state and authentic signed objects. In live mode it forwards current state. This is an adversarial-RPC fixture, not a consensus attack, real fork, authenticated light client, remote network, or deployment benchmark. A fixture acceptance demonstrates dependence on the canonical fresh-view assumption, not signature forgery. The remembered verifier retains its ordinary state when its proxy changes from live to stale; no added epoch memory is supplied.

## Frozen cases and expected outcomes

| ID | Case | Expected outcome |
|---|---|---|
| H1 | A before revocation, epoch 1/current chain | Accept; all checks true |
| H2 | B after A revocation, epoch 2/current chain, remembered verifier | Accept; all checks true |
| R1 | A with genuine, still-valid epoch 1/witnesses against current epoch 2, fresh verifier | Reject: epochAnchorCurrent only |
| R2 | Same with verifier that accepted epoch 2 | Reject: epochAnchorCurrent only |
| S1 | A/epoch 1 with stale RPC pinned to epoch 1, fresh verifier | Accept; all checks true (expected limitation) |
| S2 | Same after verifier accepted epoch 2 and its RPC becomes stale | Accept; all checks true (expected limitation; source has no epoch high-watermark) |
| N1 | Genuine epoch 1 and stale RPC after epoch 1 expires, new session | Reject: epochWindow only; date still lies in the signed calendar-day range |
| R3 | Controller re-posts epoch 1 after epoch 2 at allowed cadence | Registry rejects: epochIncrement |
| R4 | Controller posts old roots/window/signature hash under next counter 3, presents original signed epoch 1 | Registry accepts write; verifier rejects: epochAnchorCurrent only |
| N2 | Same counter-3 anchor, old statement edited to epoch 3 without a new signature | Reject: epochSignature only |
| N3 | Controller posts same fields at next counter 4 with all-zero signature's hash; statement matches anchor but has no valid signature | Registry accepts write; verifier rejects: epochSignature only |

Assertions also confirm real signature validity for saved epoch 1, actual revocation in epoch 2, unchanged issuance root and changed revocation root, genuine proof verification, nonempty proxy request observations, both fresh and remembered views returning the intended epochs, and exact check vectors rather than accepting arbitrary rejection.

## Evidence policy

The launcher hashes this protocol and runner before execution and saves that pre-execution record. The runner records the same hashes, source/artifact hashes, runtime, date, deployment metadata, public presentations, registry receipts/reverts, case decisions, and proxy read traces. Each run gets a new directory. Failed attempts remain with their status and logs. Unexpected exceptions are failures, never successful rejections. Source and artifact hashes are checked after execution. Findings are reported regardless of whether they meet the expected outcomes.

The local mock clock uses a future, fixed UTC day to avoid midnight and host-date changes. This is a functional fixture, not a claim about natural elapsed time or the current deployment date. Role keys are randomly generated in memory; case selection and expected outcomes are fixed. Source-file and build-artifact hashes, rather than random key bytes, define the reproducible code under test.

The repository's original BUSY/RUNNING markers are read before starting. Per the current user request to keep all experiment writes inside 3.7, this series records its own local marker and never writes an original-results marker. It reports no timing statistic and must not overlap an existing timed run.
