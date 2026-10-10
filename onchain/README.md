# onchain

The snarkJS-exported Solidity Groth16 verifier and its **measured** gas
(`results/gas.json`, upgrading the paper's `[A]` ~2–3×10⁵ to `[M]`), plus the
registry contracts (`contracts/Registries.sol`) deployed by `@pqid/ledger`.

## `measure_gas.ts`

1. Generates a real proof from the fixture pipeline (`harness/fixture.ts`).
2. Deploys `setup/out/Groth16Verifier.sol` (exported during `make setup`) to a local Anvil EVM.
3. Confirms correctness: a valid proof returns `true` via `staticCall`; a corrupted public
   signal returns `false` (negative control).
4. Records `gasUsed` from real transactions:
   - a bare `verifyProof` transaction, and
   - a probe contract that calls `verifyProof` and stores the result (verifiable upper bound).

> `eth_estimateGas` is unsound for this verifier because it returns `false` (not `revert`) under
> gas starvation, so real transactions with an explicit gas limit are used instead.

Public-testnet measurement remains `[F]`.

```bash
npx tsx onchain/measure_gas.ts   # -> results/gas.json
```
