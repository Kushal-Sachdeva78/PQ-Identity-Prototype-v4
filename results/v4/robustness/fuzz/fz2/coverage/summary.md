# Fuzz coverage of packages/v4/src (campaign fz2)

Scope: `packages/v4/src`. Processes: 38. Method: NODE_V8_COVERAGE block coverage of the tsx-transformed modules, mapped to TypeScript lines through the source maps tsx registers (source-map-cache); line covered = any mapped segment with innermost-range count > 0 in any process; functions by call count; union over processes.

Total over the modules the fuzz processes loaded (18 of 18 files): lines 2791/3368 (82.9 %), functions 313/390 (80.3 %). This is not the coverage of the whole scope.

| File | Lines covered | Functions covered |
|---|---|---|
| packages/v4/src/clock.ts | 10/23 | 5/10 |
| packages/v4/src/constants.ts | 37/37 | 0/0 |
| packages/v4/src/dates.ts | 43/43 | 13/13 |
| packages/v4/src/encoding.ts | 88/94 | 11/13 |
| packages/v4/src/governance.ts | 102/119 | 6/6 |
| packages/v4/src/imt.ts | 288/350 | 35/40 |
| packages/v4/src/issuer.ts | 153/173 | 13/16 |
| packages/v4/src/ledger.ts | 447/642 | 50/78 |
| packages/v4/src/paths.ts | 22/29 | 1/3 |
| packages/v4/src/pqc.ts | 166/190 | 24/27 |
| packages/v4/src/prove.ts | 52/163 | 5/13 |
| packages/v4/src/published.ts | 94/107 | 10/12 |
| packages/v4/src/session.ts | 259/283 | 38/41 |
| packages/v4/src/statements.ts | 248/260 | 39/45 |
| packages/v4/src/verifier.ts | 218/231 | 19/20 |
| packages/v4/src/wallet.ts | 357/372 | 19/22 |
| packages/v4/src/witness.ts | 58/66 | 6/8 |
| packages/v4/src/world.ts | 149/186 | 19/23 |
