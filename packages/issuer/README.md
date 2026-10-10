# @pqid/issuer

Issuer service (paper Algorithm 2). Builds a verifiable credential, binds it via
`credID = SHA3-256(canonicalJson(cred) ‖ pk_issuer)`, and signs `credID` with ML-DSA-44.

## API

| Function | Description |
|---|---|
| `createIssuer(impl?)` | new issuer with a `did:pq` and ML-DSA-44 keypair (`impl`: `"liboqs"` default, or `"dilithium-py"` for the A.5 issuance path) |
| `computeCredId(cred, pkIssuer)` | `SHA3-256(canonicalJson(cred) ‖ pk_issuer)` (32 bytes) |
| `issueCredential({issuer, subjectDid, claims, holderCommit, …})` | `VC = {credential, credID, signature}` |

## Example

```ts
import { createIssuer, issueCredential } from "@pqid/issuer";
const issuer = createIssuer();
const vc = issueCredential({
  issuer, subjectDid: holderDid, claims: { age: 42 }, holderCommit, // Poseidon(holderSecret)
});
// vc.credID === SHA3-256(canonicalJson(vc.credential) ‖ issuer.keys.publicKey)
```

`canonicalJson` is recursively key-sorted, whitespace-free UTF-8 — the byte string the
`credID` hash is defined over (`@pqid/common/hash`).
