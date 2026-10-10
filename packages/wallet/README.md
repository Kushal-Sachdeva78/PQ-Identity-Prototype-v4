# @pqid/wallet

Wallet / Prover (paper Algorithm 3). Phase 1 runs the off-circuit checks; phase 2
builds the witness and runs Groth16.Prove with either backend on byte-identical inputs.

## API

| Function | Description |
|---|---|
| `createWallet()` | holder wallet: `did:pq`, ML-DSA-44 keypair, `holderSecret`, `holderCommit` |
| `walletCheckCredential(wallet, vc, pkIssuer, policy)` | off-circuit: credID recompute, Dilithium verify, holder binding, policy applicability |
| `buildProofInput(args)` | assemble the circuit input (incl. non-membership opening); enforces the off-circuit checks unless `dangerouslySkipOffCircuitChecks` |
| `generateProof(args, backend)` | Algorithm 3 end-to-end → `ProveResult` |
| `prove(input, backend)` / `proveBoth(input)` (`@pqid/wallet/prove`) | single / dual prover; `proveBoth` asserts SHA-256 equality of zkey + witness |

`backend`: `"snarkjs"` (Node JS) or `"rapidsnark"` (native, via WSL). `ProveResult` carries
`zkeySha256`, `witnessSha256`, timings, and the proof byte size.

## Example

```ts
import { createWallet, generateProof } from "@pqid/wallet";
const wallet = await createWallet();
const result = await generateProof({
  wallet, vc, request: { policy, nonce }, pkIssuer, revRoot, nonMembership,
}, "rapidsnark");
// result.publicSignals = [issuerKeyHash, revRoot, policyHash, nonce, stmtCode]
```

`dangerouslySkipOffCircuitChecks` exists only for `harness/malicious_wallet_probe.ts`
(Assumption-5 demonstration). Do not use it in honest flows.
