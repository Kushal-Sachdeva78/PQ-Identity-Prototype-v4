# v4 security suite: route catalogue (C1)

Engineering spec for `harness/v4/security_suite.ts`. Each route records attacker, goal,
expected stopping layer, and the named check or constraint group. Layers (prompt
section 5):

- `circuit`: the attacker builds its witness with its own generator (`harness/v4/r1cs_tools.ts`:
  every `// @check` removed, --O0, mapped to the real layout by name); the real R1CS is
  evaluated (violated constraints listed per group) and the proof under the real proving
  key must fail verification.
- `verifier` / `wallet` / `registry` / `governance`: attacker-built messages stop at a named
  check (`packages/v4/src/verifier.ts` VERIFIER_CHECKS, `wallet.ts` WALLET_CHECKS, the
  contract `require`s, governance's PoP check).
- `wallet-enforced`: the verifier is the attacker; the honest wallet is the defence.
  Where a circuit constraint backs it, a second attempt disables the wallet check
  ("buggy wallet") and shows the constraint stops the honest prover.
- Nothing counts as stopped by code the attacker runs.

Record kinds: control (must be accepted), attack (must not be accepted), privacy,
baseline (honest component refuses; not a defence), known-limitation (accepted by design,
listed so the count is not read as covering it).

## Controls
| ID | Route | Expect |
|---|---|---|
| C0-a | honest adult, age_gte 18, today, default type | accepted |
| C0-b | honest minor, age_lt 18 | accepted |
| C0-c | honest adult, age_gte 21 | accepted |
| C0-c65 | honest adult, age_gte 65 (baseline record: the honest wallet refuses on the predicate; not an attack) | wallet predicateHolds |
| C0-d | holder who turns 18 today, age_gte 18 (birthday boundary) | accepted |
| LD-c | 29 February birth, age_lt t on 28 Feb of a common year (t: a standard threshold with T - t a leap year) | accepted (the permissive AGE_LT reading of D-010) |
| LD-a | same holder, age_gte t on 28 Feb (baseline) | wallet predicateHolds |
| LD-d | same holder, age_gte t on 1 Mar | accepted |
| LD-e | same holder, age_lt t on 1 Mar (baseline) | wallet predicateHolds |
| C4-a | issuer rotates its controller EVM account (new PoP record, new accreditation, same tree); holder with a credential naming the old controller (B5 REG-1) | accepted |
| C5-a | holder with an expired credential and its renewal of the same type (review round 2, L5) | accepted |
| C3-a | session opened at 23:58, answered at 00:01 after a re-anchor (epoch notBefore backdated by session TTL + skew; B5 CIR-2) | accepted |
| C2-a | adult presents while a newer leaf is unsigned | accepted |
| C2-b | adult presents while the next epoch is signed but not anchored | accepted |
| C2-c | adult after an epoch refresh (new path) | accepted |
| C2-d | late holder, first path | accepted |

## Adapted v3 routes
| ID | Attacker, goal | Route | Expected layer / check |
|---|---|---|---|
| A1-a | malicious holder: forged, never-issued credential | own leaf opened with a real holder's path under A's anchored root | circuit G04 |
| A1-b | same | attacker-built tree, valid proof, presents A's genuine statement | verifier epochAnchorCurrent |
| A1-c | same | attacker-built tree, statement signed with the attacker's ML-DSA key naming A | verifier epochAnchorCurrent, epochSignature |
| A1-d | same | self-issued under the attacker's own PoP-registered, unaccredited DID | verifier accreditation |
| A2-a | minor claims adult | genuine path, earlier birthDate | circuit G04 |
| A2-b | minor claims adult | genuine leaf and birthDate, age_gte 18 | circuit G12 |
| A2-d | adult (review round 2, GAP-H3) | proves age_lt 18 with the attacker's generator | circuit G12 |
| A2-c | minor claims adult | attacker-built tree with a fake birthDate, A's statement | verifier epochAnchorCurrent |
| A4-a | thief with the victim's credential and path, not the holder secret | thief's secret | circuit G04 |
| A5-a | holder of issuer B's credential claims issuer A | proof on B's tree, issuerDid A, B's statement | verifier issuerKeyHash, epochAnchorCurrent |
| A5-b | same | A's issuerKeyHash with B's path | circuit G04 |
| A6-a | tampered statement | epoch changed after signing | verifier epochAnchorCurrent |
| A6-b | missing statement | presentation without epochStatement | verifier shape |
| A6-c | foreign statement | A's root signed by B's key | verifier epochAnchorCurrent / epochSignature |
| A6-e | malicious holder (review round 2, GAP-H6, GAP-R2) | issuer A's own statement signed for another chain and registry, same epoch and roots | verifier epochAnchorCurrent |
| A6-d | extended window | notAfter moved later after signing | verifier epochAnchorCurrent |
| A7-a | squatter with its own key | A's DID string, own key, own controller | verifier issuerRecord, accreditation |
| A8-a | adversary with A's controller EVM key anchors its own root and signature | forged leaf under that root | verifier epochSignature |
| T1-a | trapdoor forgery | public-beacon trapdoor applied to the v4 dev key | verifier groth16 |
| R1-a | replay | accepted reply resent | verifier sessionKnown |
| R1-b | replay into another session | old reply, sessionId rewritten to a new session | verifier transcriptDecrypts |
| R1-c | cross-verifier | presentation for verifier A re-sealed to verifier B | verifier nonceBinding, stmtCode |
| R1-d | policy mismatch | age_gte 18 proof where 21 is required | verifier policyHash |
| R1-g | holder or relay (review round 2, GAP-H4) | reply sent after the session's lifetime | verifier sessionKnown |
| R1-f | network adversary (added after C3: sessionFresh was untested) | the same reply verified twice concurrently | verifier sessionFresh |
| R1-e | third party with a leaked presentation (e.g. verifier logs) | re-sealed into a new session at the same verifier (added after the mutation smoke run showed nonceBinding untested) | verifier nonceBinding |
| A3-B | revoked holder | stale low leaf (valid before revocation) against the current root | circuit G06 |
| A3-C | revoked holder | stale low leaf and stale revRoot / old statement | verifier epochAnchorCurrent, revRoot |
| A3-D1 | revoked holder | fresh credID with the revoked credential's path | circuit G04 |
| A3-D2 | revoked holder | fresh credID in an attacker-built tree, A's statement | verifier epochAnchorCurrent |
| A3-F | revoked holder | the revoked key's own leaf as low leaf (lowValue = key) | circuit G07 |
| A3-G | revoked holder | a real leaf that does not bracket the key | circuit G07 |
| A3-H | revoked holder (added after C3: verifier revRoot was untested) | current statement, valid proof against the pre-revocation revRoot | verifier revRoot |
| A3-E | (v2/v3 revocation-gadget route, details under embargo) | not applicable to the IMT; v2/v3 results carried into the matrix | n/a |

## New routes (one or more per new defence)
| ID | Attacker, goal | Route | Expected layer / check |
|---|---|---|---|
| NL-a | forged neighbour leaf | fabricated (value < key < next) leaf with another leaf's path | circuit G06 |
| NL-b | forged neighbour leaf | fabricated leaf at an empty index (zero path) | circuit G06 |
| NL-c | forged neighbour leaf | real low leaf with lowNext edited to bracket the revoked key | circuit G06 |
| NL-d | forged neighbour leaf | stale sentinel (0, 2^251), which brackets every key, with index 0's current path | circuit G06 |
| EX-a | holder of an expired credential | verifier's today after expiryDate | circuit G13 |
| EX-b | same | older date inside the proof (outside the epoch window) | circuit G15 (and G08); verifier policyHash backs it |
| TY-a | holder of another credential type | requiredType = verifier's type | circuit (G14 enforced by substitution into G08) |
| TY-b | same | requiredType = own type | verifier policyHash |
| TY-c | verifier probes which credential types the holder has (B5 CIR-4, VER-7) | request for a type outside the wallet's allow-list | wallet-enforced typeAllowed |
| LD-b | holder born 29 February, malicious wallet | age_gte t on 28 Feb with the attacker's generator | circuit G12 |
| PH-a | minor | private predicateCode = age_lt, public policyHash = verifier's age_gte 18 (added after C3: G08 removal changed nothing) | circuit G08 |
| PH-b | minor | private threshold 16, public policyHash for 18 | circuit G08 |
| PH-c | holder of another type | private requiredType = own type, public policyHash = verifier's type | circuit G08 |
| SD-a | prover uses an old date (e.g. under-18 after turning 18) | yesterday inside the proof | circuit G15 (and G08); verifier policyHash backs it |
| SD-g | verifier (review round 2, DATE-1) | request whose date reads today at the check and tomorrow once the wallet reads issuer data | wallet-enforced requestSnapshot (the wallet checks and uses one frozen copy) |
| TP-d | verifier (review round 2, DATE-1) | request whose threshold reads 18 at the check and 17 afterwards | wallet-enforced requestSnapshot |
| SD-f | verifier (added after the C3 classification review: race in the date check) | two requests with the two acceptable dates at the same moment, right after midnight | wallet-enforced dateCurrent |
| SD-d | verifier asks for the other acceptable date minutes after midnight (two-date probe; B5 CIR-1, PRIV-5) | second request with a different date within 2 x skew | wallet-enforced dateCurrent |
| SD-b | verifier supplies a stale date (probe the birth date / accept expired) | request with an old today | wallet-enforced dateCurrent |
| SD-c | same, buggy wallet | wallet dateCurrent disabled, date outside the signed epoch window | circuit G15 (honest prover's generator refuses; also attacker-generator R1CS evidence) |
| TP-a | verifier probes with a non-standard threshold | threshold 17 / 19 / 20 | wallet-enforced thresholdStandard |
| TP-b | same, buggy wallet | wallet check disabled | circuit G10 |
| SQ-a | real-key squatter | registers (A.did, A.pk) under its controller with a garbage PoP; asks governance to accredit | governance PoP check |
| SQ-b | same | replays A's genuine PoP signature (bound to A's controller) | governance PoP check; verifier issuerPop |
| SQ-c | same | presentation naming the squatter's controller record (anchors its own epoch) | verifier issuerPop, accreditation, epochSignature |
| RA-a | rogue accreditation (attacker holds the governance EVM account) | statement for its own issuer signed with the attacker's ML-DSA key | verifier accreditation (pinned key) |
| RA-b | same | garbage signature | verifier accreditation |
| RA-d | governance EVM account holder (review round 2, GAP-R1) | re-posts the older genuine accreditation declaring a higher serial | verifier accreditation (statement serial must equal the stored serial) |
| RA-e | revoked holder (review round 2, GAP-H1) | presents through the issuer's retired controller record after a rotation | verifier accreditation (names the new controller) |
| RA-f | holder (review round 2, GAP-H2) | presents after governance de-accredited the issuer | verifier accreditation |
| DE-a | holder (review round 2, GAP-H7, GAP-R6) | presents after the issuer deactivated its DID record | verifier issuerRecord, issuerPop |
| RA-c | same | replay of an older genuine statement after governance revoked the issuer (serial rollback) | registry monotonic serial; verifier accreditation (serial) |
| FA-a | frozen anchor (controller EVM key seized or issuer offline) | a holder revoked after the last anchor keeps presenting it | before notAfter: accepted (documented latency bound, known-limitation record KL2) |
| FA-b | same | one second after notAfter | verifier epochWindow |
| FA-c | same | one second after notAfter | wallet epochWindow |
| KL3-a | governance's de-accreditation is withheld by the governance EVM account holder (B5 REG-7) | holder of the de-accredited issuer presents inside the accreditation window | accepted (known limitation, bounded by MAX_ACCREDITATION_SEC = 30 days) |
| KL3-b | same | after the accreditation window, with a fresh epoch | verifier accreditation |
| RL-a | relay: passive capture | eavesdropper computes the public transcript and tries to decrypt without the ML-KEM shared secret | transport (aeadConfidentiality) |
| RL-b | relay: replay captured reply later / into another session | replay | verifier sessionKnown / transcriptDecrypts |
| RL-c | relay presents its own verifier identity to the victim | victim's proof bound to the relay, re-sealed to the genuine verifier | verifier nonceBinding, stmtCode |
| RL-d1 | relay adds its own KEM key to the request | strict request shape: any extra field | wallet requestShape |
| RL-d2 | relay forwards V's request and tries to read the reply with its own KEM key | the wallet encrypts to the key registered on chain | transport (kemKeyFromChain) |
| RL-e | relay alters the request (policy, date or verifierId) | forwarded to the victim, reply forwarded back | verifier transcriptDecrypts |
| RL-f | real-time relay forwards the genuine request unchanged and the reply back | victim's honest wallet answers | ACCEPTED (known limitation); with modelled origin binding: wallet originBinding |
| RL-h | holder of a verifier's controller EVM key (added after C3: wallet verifierKemKey was untested) | posts a KEM statement for its own KEM key, signed with another ML-DSA key | wallet verifierKemKey |
| RG-a | any EVM account (added after C3: registry write rules were untested in the suite) | anchors an epoch for a DID it does not control | registry controllerOnly |
| RG-b | holder of the issuer's controller EVM key | re-anchors the current epoch number (rollback) | registry epochIncrement |
| RG-c | same | anchors a window longer than the registry maximum | registry windowBounds |
| RG-d | same | registers the same (did, controller) record again with another key | registry recordUnique |
| RG-e | issuer's controller EVM account | posts its own accreditation statement | registry governanceWriter |
| RL-i | holder of a verifier's controller EVM key (review round 2, GAP-R5) | re-posts the retired KEM statement declaring a notBefore above the stored one | wallet verifierKemKey (signed notBefore must equal the stored one) |
| RL-g | holder of a verifier's controller EVM key (B5 REG-5) | re-posts the previous KEM statement after a rotation | registry kemMonotonic |
| SQ-d | holder of a verifier controller EVM key (B5 REG-6) | registers the verifier DID under a relay origin the PoP did not sign | wallet verifierPop |

## Privacy records
| ID | Route | Expected |
|---|---|---|
| TP-c | verifier asks non-standard thresholds around the adult's age and 17 for the minor; compares the refusal kinds (observation model D-026) | wallet thresholdStandard refuses every probe the same way |
| PV1 | four holders present to one verifier on one day | identical verifier views except the nonce |
| PV2 | issuer serves one holder a re-signed (different bytes) statement | wallet anchorMatches refuses |
| PV3 | path to an older statement after a newer anchor | wallet anchorMatches refuses |
| PV4 | statement with an extra field / root not anchored | wallet anchorMatches refuses; verifier shape |
| PV5 | permuted key order in the served statement | verifier sees canonical form |
| PV6 | immediate re-anchor to give one holder its own epoch | registry anchorCadence refuses |
| PV7 | per-holder revocation root anchored right away | registry anchorCadence refuses |
| PV8 | credential from an unaccredited per-holder DID | wallet accreditation refuses |
| PV9 | second controller record for the same DID (per-holder record) | wallet accreditation refuses (accreditation names one controller) |
| PV10 | epoch signature re-encoded as a tag: upper case plus trailing data (B5 PRIV-1) | wallet anchorMatches refuses (strict form before decoding) |
| PV11 | extra type key in the served statement (B5 PRIV-2) | wallet anchorMatches refuses |
| PV12 | published-tree wallet presents: reads of the issuer's service state during the presentation (B5 PRIV-3) | none |
| PV15 | holder whose leaf is newer than the published blob (review round 2, P1, VRA-1) | wallet refusal (anchorMatches) with no leaf index |
| PV14 | deployment whose registry allows an anchor every second (added after C3: wallet anchorCadence was untested) | wallet anchorCadence refuses |
| PV13 | issuer plants a covert-type credential in one wallet as a tag (B5 PRIV-6) | wallet typeAllowed refuses at issuance |
| KL4 | online-mode wallet (not the default) presents | known limitation: the issuer's services see the credID at presentation time |

## Baselines
| ID | Route | Note |
|---|---|---|
| B0 | revoked holder's honest wallet asks for a non-membership witness | issuer service refuses (not a defence) |
| B1 | late holder asks for a path before its leaf is anchored | issuer service refuses (not a defence) |
| B4 | honest verifier asks the other date minutes after midnight, after the wallet answered the first (D-017 cost) | wallet dateCurrent refuses (not a defence) |

## Known limitations (accepted by design)
| ID | Route | Expected |
|---|---|---|
| KL5 | holder lends its holder secret and credential to another person, who presents | accepted: bearer credential without device binding |
| KL6 | issuer splits its holders across several separately accredited DIDs | accepted: smaller anonymity sets; governance policy, not a protocol check |

The suite fails when a row above (other than n/a rows) has no attempt (B5 PRIV-7).

Registry defences covered by unit tests rather than suite routes (tests/v4/ledger_v4.test.ts):
cross-deployment accreditation transplant (B5 REG-2, refused by the signed chainId and registry),
signed-serial cap and step cap (B5 REG-3, accreditationSerial), next serial after a governance
restart (B5 REG-4).
