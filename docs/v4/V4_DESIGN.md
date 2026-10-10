# v4 design specification (engineering spec, not paper text)

Status: draft 1, 2026-09-27. This file fixes every encoding, message, contract call and
check name that the v4 circuit, the `@pqid/v4` package, the contracts, the suites and the
benchmarks share. Decisions referenced as D-xxx are in DECISIONS.md.

## 0. Principles
- Additive: v2 and v3 files are not changed. v4 lives in `circuits/credential_auth_v4.circom`,
  `circuits/v4/*.circom`, `packages/v4/`, `onchain/contracts/v4/`, `setup/*v4*`,
  `harness/v4/`, `tests/v4/`, `results/v4/`.
- OS-portable: Node 24+ and POSIX shell. No `wsl.exe`. PQC from Node's OpenSSL 3.5 (D-003).
- Every trust decision rests on ML-DSA-44 signatures checked by verifiers and wallets, or
  on the Groth16 relation. EVM accounts (ECDSA) only post data and pay gas: they affect
  liveness, never acceptance.

## 1. Field constants and encodings (BN254 scalar field p)

| Name | Value | Use |
|---|---|---|
| DOMAIN_ISSUER_KEY | 1001 | PoseidonFold of issuer ML-DSA pk (as v2/v3) |
| DOMAIN_VERIFIER_ID | 1002 | PoseidonFold of verifier DID string (as v2/v3) |
| STMT_V4 | 4 | stmtCode = Poseidon(STMT_V4, domainTag) |
| CRED_LEAF_V4 | 1004 | first input of every v4 credential leaf |
| DOMAIN_CRED_TYPE | 1005 | credType = PoseidonFold(utf8(typeId), DOMAIN_CRED_TYPE) |
| POLICY_V4 | 1006 | first input of policyHash |
| IMT_LEAF_V4 | 1007 | first input of every revocation-tree leaf |

- PoseidonFold, issuerKeyHash, verifierDomainTag: exactly as `@pqid/common/encoding`.
- Dates: `YYYYMMDD` as an unsigned integer, proleptic Gregorian, UTC calendar date
  (D-010). Valid range 19000101..99991231, so every date is < 2^27. Age arithmetic:
  "at least t years old on day D" iff `birthDate + 10000*t <= D`. A 29 February birth
  reaches age t on 1 March in common years.
- credIDHi, credIDLo: 128-bit big-endian limbs of credID = SHA3-256(canonicalJson(cred) ||
  pk_issuer), as v3.
- revKey (revocation key, 251 bits) = credIDHi * 2^123 + floor(credIDLo / 2^5). In the
  circuit it is a linear combination of the Num2Bits(128) outputs already computed.
- typeId default: `pqid:type:age-credential:v1` (D-013).

### 1.1 Credential leaf
`leaf = Poseidon8(CRED_LEAF_V4, issuerKeyHash, credIDHi, credIDLo, holderCommit, birthDate, expiryDate, credType)`
with `holderCommit = Poseidon1(holderSecret)` computed in-circuit.

### 1.2 Policy hash (verifier-chosen, bound into the proof)
`policyHash = Poseidon5(POLICY_V4, predicateCode, threshold, today, requiredType)`
- predicateCode 1 = AGE_GTE (age >= t), 2 = AGE_LT (age < t).
- threshold in the standard set `STANDARD_THRESHOLDS` (D-011).
- today: verifier's current UTC date (YYYYMMDD).
- requiredType: credType the verifier requires.

### 1.3 Issuance tree
Identical to v3: binary Poseidon Merkle tree, depth 32, empty leaf 0, append-only
(`IssuanceTree` from `@pqid/issuer`, reused read-only).

### 1.4 Revocation tree: indexed Merkle tree (IMT), depth REV_DEPTH (B2 decides; 30 planned)
- Leaf at an occupied index: `Poseidon3(IMT_LEAF_V4, value, nextValue)`; empty slot: 0.
- Values are revKeys (< 2^251). `IMT_MAX = 2^251`.
- Initial tree: index 0 holds `(0, IMT_MAX)`; the sorted linked list is 0 -> IMT_MAX.
- Insert k (issuer): find the low leaf L with `L.value < k < L.nextValue`; set L's
  nextValue to k; append `(k, oldNext)` at the next free index. Capacity 2^depth - 1 keys.
- Non-membership of k: open a low leaf L at index i under revRoot with
  `L.value < k < L.nextValue` (strict both sides).
- Alternative measured in B2: a sparse Merkle tree non-membership gadget keyed by
  Poseidon(hi, lo), as in v3, at depths 32, 70, 99, 128 (docs/v4/B2_REVOCATION_CAPACITY.md).

## 2. Relation R4 (`circuits/credential_auth_v4.circom`)

Public signals, in order (8):
`[issuerKeyHash, revRoot, policyHash, nonce, stmtCode, issRoot, epochFromDate, epochToDate]`

Private inputs:
`credIDHi, credIDLo, holderSecret, birthDate, expiryDate, credType, predicateCode, threshold,
today, requiredType, domainTag, issLeafIndex, issPathElements[32], revLowIndex,
revLowValue, revLowNext, revLowPath[REV_DEPTH]`

Constraint groups (names used by the mutation table, C3):

| Group | Constraint |
|---|---|
| G01_credid_range | Num2Bits(128) on credIDHi and credIDLo |
| G02_holder_commit | holderCommit = Poseidon1(holderSecret) |
| G03_leaf | leaf = Poseidon8(...) (1.1) |
| G04_issuance_membership | MerkleRoot(32)(leaf, issLeafIndex, issPathElements) == issRoot; issLeafIndex < 2^32 |
| G05_revkey | revKey from the credID bits (linear) |
| G06_rev_low_membership | MerkleRoot(REV_DEPTH)(Poseidon3(IMT_LEAF_V4, revLowValue, revLowNext), revLowIndex, revLowPath) == revRoot; revLowIndex < 2^REV_DEPTH |
| G07_rev_bracket | revLowValue < revKey and revKey < revLowNext (LessThan(252)) |
| G08_policy_hash | Poseidon5(POLICY_V4, predicateCode, threshold, today, requiredType) == policyHash |
| G09_predicate_code | (predicateCode - 1)(predicateCode - 2) == 0 |
| G10_standard_threshold | prod over s in STANDARD_THRESHOLDS of (threshold - s) == 0 |
| G11_ranges | Num2Bits(27) on birthDate, expiryDate, today, epochFromDate, epochToDate; Num2Bits(8) on threshold |
| G12_age | GTE: birthDate + 10000*threshold <= today; LT: birthDate + 10000*threshold > today; selected by predicateCode |
| G13_expiry | today <= expiryDate |
| G14_type | credType == requiredType |
| G15_epoch_window | epochFromDate <= today <= epochToDate |
| G16_stmt | stmtCode == Poseidon2(STMT_V4, domainTag) |
| G17_nonce | nonceSq <== nonce * nonce (keeps the nonce in the constraint system) |

Compile with circom 2.2.3 `--O2`; record the `--O1` count too (T9).

## 3. Signed statements (ML-DSA-44, pure, empty context; canonical JSON bytes)

All `type` strings are distinct, so no statement verifies as another.

| Statement | Signed by | Fields (canonical JSON) |
|---|---|---|
| DID proof of possession | the DID's own ML-DSA key | `{type:"pqid:did-pop:v2", did, controller, chainId, registry, nonce, origin}` |
| Accreditation | governance ML-DSA key (pinned) | `{type:"pqid:accreditation:v2", issuerDid, controller, pkSha3, chainId, registry, serial, status:"accredited"|"revoked", notBefore, notAfter}` |
| Issuer epoch | issuer ML-DSA key | `{type:"pqid:issuer-epoch:v4", issuer, controller, chainId, registry, epoch, root, revRoot, notBefore, notAfter, fromDate, toDate}` |
| Verifier KEM key | verifier ML-DSA key | `{type:"pqid:verifier-kem:v1", verifier, controller, chainId, registry, kemAlg:"ML-KEM-768", kemPkSha3, notBefore, notAfter}` |

- `controller`, `registry`: lower-case 0x hex EVM addresses. `chainId`: number.
  `nonce`: 64 hex chars. `pkSha3`, `kemPkSha3`: SHA3-256 hex of the raw key bytes.
  `root`, `revRoot`: decimal strings. Times: unix seconds (numbers). `fromDate`/`toDate`:
  YYYYMMDD of notBefore/notAfter in UTC. `origin`: the web origin registered with the
  record, `""` for issuers, otherwise at most 256 printable ASCII characters without spaces.
- Deployment binding: every statement names the chain (`chainId`) and the registry it is
  posted to (`registry`: the DID registry for the PoP, AccreditationRegistryV4 for an
  accreditation, IssuanceRootRegistryV4 for an epoch, VerifierKemRegistryV4 for a KEM key),
  so no statement can be moved to another deployment, even one that pins the same
  governance key (review finding REG-2).
- The PoP signs the registered `origin`, so the EVM account that submits the registration
  cannot choose the origin that origin-binding wallets compare against (REG-6).
- Epoch window length: `notAfter - notBefore = EPOCH_WINDOW_SEC` (D-012).
- Accreditation validity: at most 30 days (D-014); verifiers keep the highest serial seen
  per issuer DID and reject lower serials. Governance keeps no serial counter: it signs
  the registry's stored signed serial + 1 (1 when none), so a restart continues from the
  chain (REG-4). Verifiers parse the statement with the typed, canonical parser.
- Verifier KEM key validity: at most 400 days (`MAX_VERIFIER_KEM_SEC`, REG-5). A rotation
  signs a later `notBefore` than the previous statement (the registry enforces it, see
  section 4).

## 4. Contracts (`onchain/contracts/v4/RegistriesV4.sol`)

Record key: `recordKey = keccak256(abi.encodePacked(did, controller))` computed on chain
(indexing only). Each DID string may have many records (one per controller); which one is
authoritative is decided by the governance-signed accreditation, not by the chain.

- `DIDRegistryV4.registerDID(string did, bytes pk, bytes32 popNonce, bytes popSig, string origin)`:
  stores `{pk, popNonce, popSigHash = keccak256(popSig), origin, active, registeredAt}`
  under `recordKey(did, msg.sender)`; emits `DIDRegisteredV4(recordKey, did, controller, popNonce, popSig)`.
  Reverts if that record exists. `resolve(string did, address controller)` view.
  `deactivate(string did)` by the controller. The contract stores `origin` as given;
  readers rebuild the PoP statement with the stored origin, so an origin the DID key did
  not sign fails the PoP check.
- `AccreditationRegistryV4.publish(string issuerDid, uint64 signedSerial, bytes statement, bytes signature)`:
  only the governance EVM account (liveness only); stores the latest `(statementHash,
  signatureHash, serial, publishedAt, publishedBlock, signedSerial)` per
  `keccak256(issuerDid)`; emits the full bytes. `serial` is the on-chain publication
  counter; `signedSerial` is declared by the caller and readers require it to equal the
  statement's signed `serial`. Check `accreditationSerial`: `signedSerial` strictly
  increases, by at most `2^20` per publication, and is at most `2^53 - 1` (the largest
  serial a statement can carry). The step cap keeps one bad publication from blocking the
  DID for good, since the governance address is immutable (REG-3).
- `IssuanceRootRegistryV4.publishEpoch(string did, uint64 epoch, uint256 root, uint256 revRoot, uint64 notBefore, uint64 notAfter, bytes32 sigHash)`:
  keyed by `recordKey(did, msg.sender)`; requires the record exists and is active;
  `epoch == cur + 1`; `now >= cur.publishedAt + minAnchorInterval` unless first;
  `notBefore < notAfter <= notBefore + maxWindow`.
  `current(string did, address controller)` view.
- `VerifierKemRegistryV4.publishKemKey(string did, uint64 notBefore, bytes kemPk, bytes statement, bytes signature)`:
  keyed by `recordKey(did, msg.sender)`; requires the record exists and is active; stores
  `(kemPkHash, statementHash, signatureHash, version, publishedAt, publishedBlock, notBefore)`
  and emits full bytes. `notBefore` is declared by the caller and readers require it to
  equal the statement's signed `notBefore`. Check `kemMonotonic`: `notBefore` strictly
  increases per record and is at most `2^53 - 1`, so the controller EVM account cannot
  re-post an older genuine statement to undo a key rotation (REG-5). It is not capped
  against the block time: the same account can already deactivate the record.
- Solidity pragma ^0.8.24, compiled with the repo's pinned solc-js 0.8.28 (optimizer 200).

## 5. Session protocol (ML-KEM-768, HKDF-SHA-256, AES-256-GCM; D-015, D-016)

1. Verifier -> wallet: `request = {type:"pqid:request:v4", sessionId (64 hex), verifierDid,
   verifierController, chainId, policy:{predicate:"age_gte"|"age_lt", threshold, typeId, today}, issuedAt}`.
2. Wallet: checks (6.2), resolves the verifier's registered ML-KEM key from chain (never
   from the request), encapsulates: `(ct, ss) = Encaps(kemPk)`.
3. `T = SHA3-256(canonicalJson({type:"pqid:transcript:v4", request, kemPkSha3, ctSha3}))`.
   `prk = HKDF-Extract(SHA-256, salt = T, ikm = ss)`.
   `nonce = int(HKDF-Expand(prk, "pqid:v4:nonce", 31))` (248-bit field element).
   `key = HKDF-Expand(prk, "pqid:v4:aead-key", 32)`; `iv = HKDF-Expand(prk, "pqid:v4:aead-iv", 12)`.
4. Wallet proves with public `nonce`, sends `reply = {type:"pqid:reply:v4", sessionId, ct,
   box: AES-256-GCM(key, iv, aad = T, plaintext = canonicalJson(presentation))}`.
5. Verifier: looks up its stored request by sessionId, decapsulates, recomputes T, prk,
   nonce, key, iv; decrypts; runs the checks (6.1); consumes the session only on success.
- Presentation plaintext: `{proof, publicSignals, issuerDid, issuerController, epochStatement}`
  where `epochStatement = {statement fields..., signature}`.
- Origin binding (modelled, optional wallet mode): the wallet is told the authenticated
  origin of its caller (in a browser, the platform supplies it); it refuses if that origin
  differs from the verifier record's registered `origin`.

## 6. Named checks

### 6.1 Verifier (in order)
`shape`, `sessionKnown`, `transcriptDecrypts`, `issuerRecord` (record exists, active,
did:pq matches pk), `issuerPop` (PoP rebuilt with the record's stored origin), `accreditation`
(pinned governance key; typed canonical parse; binds this chainId and this
AccreditationRegistryV4, did, controller, pk; serial equals the registry's stored signed
serial, which must be a safe integer; in window; serial not rolled back; status
accredited), `issuerKeyHash`,
`epochAnchorCurrent` (anchor equals the statement's epoch, root, revRoot, window, sigHash),
`epochWindow` (now in [notBefore, notAfter]; public signals 6, 7 equal fromDate, toDate),
`revRoot`, `policyHash` (own today, threshold, predicate, requiredType), `nonceBinding`
(public nonce equals the transcript-derived nonce), `stmtCode`, `groth16`, `sessionFresh`
(consumed once), `epochSignature` (ML-DSA, last, only for the copy that consumed the session).

### 6.2 Wallet (honest; order as in `packages/v4/src/wallet.ts` WALLET_CHECKS)
- Before any check the wallet takes one frozen plain-data copy of the request and uses only
  that copy (review round 2, DATE-1).
- Request: `requestShape` (strict schema, this chain), `verifierRecord`, `verifierPop` (PoP
  rebuilt with the record's stored origin), `verifierKemKey` (signature by the verifier's key,
  window at most 400 days, algorithm, chainId and registry equal this ledger's, signed notBefore
  equals the registry's stored notBefore and is not older than the newest the wallet has seen
  for that record), `originBinding` (modelled mode only), `dateCurrent` (the wallet's current
  UTC date, or the previous date only in the first WALLET_CLOCK_SKEW_SEC after midnight, never a
  future date; at most one date within any 2 x WALLET_CLOCK_SKEW_SEC, reserved in the same
  synchronous step as the check; D-017, D-026), `thresholdStandard` (D-011), `typeAllowed`
  (allow-list, D-018).
- Credential and issuer data: `typeHeld` (of several credentials of the type, the one that
  expires last), `credentialSignature` (the wallet's own check of its credential; not load-bearing
  for the verifier), `issuerRecord`, `issuerPop`, `accreditation` (controller taken from the
  issuer DID's latest valid accreditation; the credential's controller is a fallback),
  `anchorMatches` (served statement in canonical form, rebuilt from validated fields, equal to
  the chain's anchor; path and revocation opening against the anchored roots; any data-source
  failure becomes one generic refusal), `epochWindow`, `dateInWindow` (today within the
  statement's fromDate..toDate), `anchorCadence` (registry minAnchorInterval at least the wallet
  floor), `predicateHolds` (predicate at the checked date and threshold, and not expired).
- Proof and reply: proof failures and a presentation that fails the verifier's own shape rules
  are refused (`proofFailed`, not a named check); the reply is sealed to the registered KEM key.
- Data source: the issuer's published blob of the anchored epoch by default (D-019); online mode
  is a known limitation (KL4).
- Observation model for refusals: DECISIONS D-026.

### 6.3 Registry (on chain)
`recordUnique`, `controllerOnly`, `epochIncrement`, `anchorCadence`, `windowBounds`,
`governanceWriter` (liveness only), `accreditationSerial` (declared signed serial strictly
increases per issuer DID, step at most 2^20, value at most 2^53 - 1), `kemMonotonic`
(declared KEM statement notBefore strictly increases per record, value at most 2^53 - 1).
Revert reasons start with `<check>:`; the mutation tool removes every `require` whose
message starts with that prefix.

## 7. Keys per role
- EVM: deployer/faucet (Anvil dev key #0, deploys and funds only), governance EVM account,
  one controller per issuer, one per verifier, attacker accounts: all fresh random keys,
  held in memory, never written or logged.
- ML-DSA-44: governance (verifiers and wallets pin its public key), each issuer, each
  verifier (identity), each holder (unused by the relation). ML-KEM-768: each verifier.
- Dev ceremony: circuit key made the v3 way (one contribution with fresh OS entropy never
  written to disk, then the public beacon), labelled `dev` everywhere (prompt section 5).
