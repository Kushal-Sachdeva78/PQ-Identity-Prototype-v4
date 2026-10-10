# Paired wallet history and stateless midnight policy, protocol v1

Prepared 7 October 2026 IST before measurement. This is a new, reviewer-informed,
internally selected local experiment, not independent coverage or a security proof. No prior
result, package, key, circuit or support record is changed. Every write is confined
to this directory. Failed attempts remain in numbered run directories.

## Scope and labels

[M, dev] denotes execution of the shipped wallet or an explicitly isolated variant,
with real local Anvil registries, ML-DSA checks, ML-KEM sessions and snarkJS proofs
using the existing development key. Time is injected as a fixture. No measured
latency, remote-network performance or population-frequency claim is made.
[S] denotes arithmetic on the configured one-day acceptance schedule or an
equal-prior, two-history observation model. A distinguishable test pair is an
observed difference, not measured mutual information in a real population.

## Variant

The design is taken from paper revision 3.6, Discussion privacy limitations and
Appendix B's per-holder-history extension. The cited DATE_POLICY_DESIGN.md is absent.
Generate a separate wallet copy, recording the original/copy hashes and unified
diff. Relocate imports only, remove the date log, and replace only the date policy:
accept the current UTC day if the integer second within that day is in
[300, 86100); otherwise throw one fixed dateCurrent refusal. Other checks, KEM and
accreditation memory, circuits, keys and verifier are unchanged. The variant is not
shipped and does not change the snapshot's C2 verdict.

The blackout is the last 300 and first 300 integer seconds around midnight. Last
answer before midnight is at -301 s, first after is at +300 s: a 601 s gap.

## Fixtures and observations

Use two registered verifiers (reference A and challenge B), one honest issuer, and
fresh paired holders with the same birth date, expiry, type and issuer. Secrets
are distinct, ephemeral and never written. Epoch data is published before tests.
All date scenarios use midnight 2026-10-10 UTC; setup/anchor time is one hour before
it. Each scenario has new holders, so injected clock resets between scenarios do
not rewind a holder's history. Expiry is 2026-12-31; normal birth date is 2000-01-01.

Record each full present() call, its request date, injected clock, response presence,
exact WalletRefusal check/message and UTF-8 message length. For successful calls,
record sealed-reply byte length/hash and actual verifier decision. Do not save
credential secrets, private keys, witness data, host/user names or home paths.
Observation comparisons use reply/refusal/check/message only, excluding randomized
proof/ciphertext bytes and timing. Also compare reply-presence and check-only views.

## Prespecified paired histories (both policies, two holders each)

1. No history; challenge current day at +60. Shipped: two replies. Variant: two
   identical blackout refusals.
2. Both holders answer previous day at -301, then challenge current day at +60.
   Shipped: two reservation refusals. Variant: two identical blackout refusals.
3. Only holder 0 answers previous day at -301; challenge both at +60. Shipped:
   holder 0 reservation refusal, holder 1 reply. Variant: equal blackout refusals.
4. Only holder 0 answers current day at +3600; challenge tomorrow at +3601.
   Shipped: both refuse dateCurrent but exact messages differ (recent reservation
   versus non-current day). Variant: identical fixed date refusals.
5. Both holders answer current day at +3600; challenge tomorrow at +3601.
   Both policies: equal refusals within the policy.
6. Only holder 0 receives age >= 65 for the previous day at -301 (predicate fails,
   but date is reserved), then challenge age >= 18 at +60. Shipped: reservation
   refusal versus reply. Variant: equal blackout refusals.

The key expected contrasts are pairs 3 and 6 at the reply-presence level, and pair
4 at the exact-message level. No/symmetric-history cases are negative controls.

## Prespecified boundary and failure controls (both policies)

Fresh adult, current-day age >= 18 at offsets -301, -300, -1, 0, +299 and +300:
shipped accepts all; variant accepts only -301 and +300. Previous day at +299:
shipped accepts and variant refuses; previous day at +300: both refuse. Future
day at -301: both refuse. Sequential previous-day -301 then current-day +300:
both accept both (601 s). Sequential -301 then +299: shipped reserves the previous
day and refuses the second (600 s inclusive); variant refuses the second blackout.
At +3600, threshold 17 refuses thresholdStandard; age >= 65 refuses predicateHolds;
an unknown type refuses typeAllowed; a revoked credential refuses anchorMatches.
A holder born 2008-10-10 fails age >= 18 at -301 and passes at +300; both policies
must preserve those predicate outcomes. An invalid date 20261301 refuses requestShape.

## Availability calculation and success/failure accounting

Enumerate all 86,400 integer second offsets through the variant's date-policy
function, current date and fresh history. Expected [S]: 85,800 eligible seconds,
600 blocked seconds, 0.694444% date-policy unavailability per day. This is not
end-to-end uptime. Other refusal sources, network transport, clock skew, birth-date
semantics, issuer correctness and blob synchronization remain separate limitations.

Save protocol SHA-256 before running. Every completed call and unexpected error is
append-only in events.jsonl. Save results even on failure; do not adjust outcomes
or delete failed attempts. Report every mismatch against these expected outcomes.
Hash relevant source/key artifacts before and after. Refuse if the benchmark RUNNING
marker exists. Use an OS-selected unused local port, no public network.
