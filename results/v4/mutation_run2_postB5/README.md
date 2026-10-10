# Mutation run 2 (after the review-round fixes, before the C3 routes)

- 2026-09-27 14:32 to 15:46 IST, `harness/v4/mutation.ts --jobs 2`, against suite run 7 (67 attack
  routes). 59 defences: 30 let at least one route through when removed, 29 did not.
- The 29 were classified (docs/v4/C3_MUTATION.md). Nine were untested (verifier revRoot and
  sessionFresh, wallet verifierKemKey and anchorCadence, five registry write rules), so routes
  A3-H, R1-f, RL-h, PV14 and RG-a..RG-e were added (suite run 8, 75 attack routes), and three
  harness artefacts were fixed (exception handler reported as "shape", PV6 blob refresh, RL-d1
  second validation layer). Run 3 is the table the paper uses; this run is kept as evidence of
  the C3 loop.
