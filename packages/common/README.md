# @pqid/common

Shared primitives used across packages and the circuit. **These encodings are the
contract between the JS protocol code and `credential_auth.circom`** — change them
in lockstep.

| Export | Contents |
|---|---|
| `@pqid/common/encoding` | BN254 field; Poseidon helpers; `issuerKeyHash` (Poseidon fold of `pk_issuer`); `credIdLimbs` / `smtKeyFromCredId` (256-bit → two 128-bit limbs → Poseidon key); `policyHashV1`; `holderCommit`; domain/statement constants |
| `@pqid/common/hash` | `sha3_256` (FIPS-202); `sha256File`/`sha256Bytes`; `canonicalJson(Bytes)` (key-sorted, whitespace-free — defines the `credID` preimage) |
| `@pqid/common/did` | `did:pq:<base58(SHA3-256(pk)[:20])>`; DID Document type; registry key |
| `@pqid/common/meta` | `hostMeta()` (CPU/OS/Node), `wslMeta()` (kernel/gcc/cmake/python) — embedded in every results file |
| `@pqid/common/stats` | `summarize()` (mean/median/sample-σ/min/max/p95); timing helpers |
| `@pqid/common/paths` | repo-relative paths; `toWslPath()` for Windows→WSL path translation |
