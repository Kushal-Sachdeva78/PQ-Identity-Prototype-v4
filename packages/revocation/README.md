# @pqid/revocation

Revoked-set accumulator: a depth-32 sparse Merkle tree over **Poseidon**, matched
to circomlib's `SMTVerifier(32)` (same hash, arity, and leaf encoding). This is the
JS↔circuit canonical pair — the classic off-circuit/in-circuit hash-mismatch failure
is avoided by construction.

## API

| Method | Description |
|---|---|
| `RevocationTree.create()` | empty tree (root = 0) |
| `insert(credId)` | revoke a credential; returns the new root |
| `isRevoked(credId)` | membership check |
| `getNonMembershipProof(credId)` | opening for a non-revoked credID, in `SMTVerifier(32)` shape; **throws** for a revoked credID (this is the negative-test mechanism) |
| `root()` | current root as a BN254 field element |

Keys: `smtKey = Poseidon(credIDHi, credIDLo)` (credID field packing, Gap 11). Values: `1`.

## Example

```ts
import { RevocationTree } from "@pqid/revocation";
const tree = await RevocationTree.create();
await tree.insert(revokedCredId);
const opening = await tree.getNonMembershipProof(myCredId); // verifies in-circuit
await tree.insert(myCredId);
await tree.getNonMembershipProof(myCredId); // throws: no non-membership proof exists
```
