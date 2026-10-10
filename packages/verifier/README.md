# @pqid/verifier

Verifier service (paper §III-B.4a, verifier-side off-circuit checks). Runs the full
acceptance pipeline against a presentation `(proof, publicSignals, issuerDid)`.

## Checks (all seven must pass)

1. `proofValid` — `Groth16.verify` against the pinned vkey.
2. `issuerResolvedAndAccredited` — issuer DID resolves on-chain and is accredited + active.
3. `issuerKeyHashMatches` — `Poseidon(pk_issuer) == signal[0]`.
4. `revRootMatches` — on-chain `revRoot == signal[1]`.
5. `policyHashMatches` — `Poseidon(1, threshold) == signal[2]` for the requested policy.
6. `nonceFresh` — `signal[3]` is a known, unexpired, single-use session nonce.
7. `stmtCodeValid` — `signal[4] == STMT_V1`.

## API

| Member | Description |
|---|---|
| `new Verifier(ledger, opts?)` | binds to a `@pqid/ledger` instance + pinned vkey |
| `newSessionNonce()` | issue a fresh single-use nonce (TTL) |
| `verifyPresentation(presentation, expectedPolicy)` | `{accepted, reasons, checks}` |

## Example

```ts
const verifier = new Verifier(ledger);
const nonce = verifier.newSessionNonce();            // give to the wallet
// ... wallet proves over this nonce ...
const decision = await verifier.verifyPresentation(presentation, { type: "age_gte", threshold: 18 });
console.log(decision.accepted, decision.reasons);
```

Rejects stale/replayed nonces and proofs built against an outdated revocation root.
