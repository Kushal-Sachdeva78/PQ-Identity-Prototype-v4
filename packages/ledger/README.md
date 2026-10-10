# @pqid/ledger

Registry layer (paper §III-C) on a single-node EVM (Anvil): DID, Issuer,
Revocation, and Schema registries as real Solidity contracts (`onchain/contracts/
Registries.sol`), plus the `did:pq` resolver. Multi-node permissioned BFT is `[F]`.

No PII is stored on-chain — only DIDs, ML-DSA-44 public keys, and accumulator roots.

## API

| Member | Description |
|---|---|
| `startAnvil(port?)` | launch a local EVM; resolves when the RPC answers |
| `Ledger.deploy(rpcUrl)` | compile + deploy all four registries; returns a `Ledger` |
| `registerDid(did, pk, endpoints?)` | DID Document (Algorithm 1) |
| `resolveDid(did)` | `{id, publicKeyDilithium, endpoints, active}` |
| `accreditIssuer(did)` / `isAccredited(did)` | Issuer Registry |
| `publishRevRoot(issuerDid, root)` / `getRevRoot(issuerDid)` | Revocation Registry (Algorithm 4) |
| `registerSchema(id, json, uri)` | Schema Registry |

Registry keys are `bytes32 = SHA3-256(didString)` computed off-chain, so the contracts stay
hash-agnostic (no EVM-keccak vs FIPS-SHA3 mismatch).

## Example

```ts
const anvil = await startAnvil(8545);
const ledger = await Ledger.deploy(anvil.rpcUrl);
await ledger.registerDid(issuer.did, issuer.keys.publicKey, ["https://issuer.example"]);
await ledger.accreditIssuer(issuer.did);
const doc = await ledger.resolveDid(issuer.did);
```
