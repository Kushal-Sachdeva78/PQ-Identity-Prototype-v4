"""Audit saved evidence, hashes, controls and paired comparisons without rerunning proofs."""
from pathlib import Path
import hashlib
import json
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
if (ROOT / 'results/v4/bench/RUNNING').exists():
    raise SystemExit('Refusing analysis while benchmark RUNNING marker exists')
load = lambda p: json.loads(p.read_text(encoding='utf-8'))
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
manifest_path = ROOT / 'PUBLICATION_PROVENANCE.json'
manifest_entries = load(manifest_path)['files'] if manifest_path.exists() else []
manifest = {entry['path'].replace('\\', '/'): entry for entry in manifest_entries}
assert len(manifest) == len(manifest_entries), 'duplicate publication manifest paths'
matched_exact = []
matched_publication = []

def match_historical_digest(filename, recorded):
    """Check an original digest against either unchanged bytes or a recorded publication copy."""
    filename = Path(filename)
    relative = filename.relative_to(ROOT).as_posix()
    actual = digest(filename)
    if actual == recorded:
        matched_exact.append(relative)
        return
    entry = manifest.get(relative)
    assert entry is not None, f'missing publication mapping: {relative}'
    assert entry['originalSha256'] == recorded, f'historical digest mismatch: {relative}'
    assert entry['publicationSha256'] == actual, f'publication digest mismatch: {relative}'
    matched_publication.append(relative)

pre = load(HERE / 'preregistration.json')
match_historical_digest(HERE / 'PROTOCOL.md', pre['protocolSha256'])
match_historical_digest(HERE / 'wallet_stateless_v1.ts', pre['variantSha256'])
match_historical_digest(HERE / 'date_policy.ts', pre['policySha256'])
run = HERE / 'run-02'
start, result = load(run / 'run_start.json'), load(run / 'results.json')
assert pre['preparedUtc'] < load(HERE / 'run-01/run_start.json')['startedUtc'] < start['startedUtc'] < result['finishedUtc']
match_historical_digest(HERE / 'run.ts', start['runnerSha256'])
match_historical_digest(HERE / 'run-attempt-01.ts', load(HERE / 'run-01/run_start.json')['runnerSha256'])
events = [json.loads(line) for line in (run / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
assert len(events) == len({e['id'] for e in events}) == result['calls'] == 78
assert all(e['outcome'] == e['expected'] and e['expectationMet'] for e in events)
assert not result['unexpectedOutcomes'] and not result['sourceChanges'] and not result['pairExpectationFailures']
assert result['allPrespecifiedChecksPassed']
accepted = [e for e in events if e['replyEmitted']]
refused = [e for e in events if not e['replyEmitted']]
assert len(accepted) == result['acceptedReplies'] == 33
assert len(refused) == result['refusals'] == 45
for e in accepted:
    assert e['outcome'] == 'accepted' and e['verifierAccepted'] and not e['failedChecks']
    assert e['verifierDecision']['checks']['groth16']
for e in refused:
    assert e['outcome'].startswith('refused:')
    assert e['messageUtf8Bytes'] == len(e['message'].encode('utf-8'))
by_id = {e['id']: e for e in events}
for pair in result['pairs']:
    left, right = [by_id[i] for i in pair['challengeIds']]
    obs = lambda e: (e['replyEmitted'], e['outcome'], e.get('message'))
    assert pair['messageObservationDiffers'] == (obs(left) != obs(right))
    assert pair['replyPresenceDiffers'] == (left['replyEmitted'] != right['replyEmitted'])
    assert pair['checkDiffers'] == (left['outcome'] != right['outcome'])
    assert pair['messageObservationDiffers'] == (pair['policy'] == 'shipped' and pair['scenario'] in [3,4,6])
before, after = load(run / 'sources_before.json'), load(run / 'sources_after.json')
assert before == after
for filename, recorded in before.items():
    match_historical_digest(ROOT / filename, recorded)
pins = load(ROOT / 'setup/pins_v4.json')
checked_pins = []
for pin in pins.values():
    if pin['path'] in before:
        assert before[pin['path']] == pin['sha256']
        checked_pins.append(pin['path'])
assert len(checked_pins) == 4
assert result['availability']['blackoutSeconds'] == 600
assert result['availability']['eligibleSeconds'] == 85800
assert result['availability']['minimumCrossDateGapSec'] == 601
counts = {}
for policy in ['shipped','stateless-v1']:
    es = [e for e in events if e['policy'] == policy]
    ps = [p for p in result['pairs'] if p['policy'] == policy]
    counts[policy] = {'calls':len(es), 'verifiedReplies':sum(e['replyEmitted'] for e in es),
        'refusals':sum(not e['replyEmitted'] for e in es), 'pairedScenarios':len(ps),
        'replyPresenceContrasts':sum(p['replyPresenceDiffers'] for p in ps),
        'messageContrasts':sum(p['messageObservationDiffers'] for p in ps)}
validation = {'schema':'privacy-evidence-validation/v1','validatedUtc':datetime.now(timezone.utc).isoformat(),
    'passed':True,'eventsAudited':len(events),'historicalBeforeAfterDigestsMatched':len(before),
    'unchangedDigestChecks':len(matched_exact),'publicationDigestChecks':len(matched_publication),
    'publicationMappedPaths':sorted(set(matched_publication)),
    'matchedPinnedArtifacts':checked_pins,'counts':counts,
    'failedAttemptPreserved':'run-01; 38 completed calls plus harness error before malformed-date dispatch',
    'limitations':'Audit of preserved observations and declared publication mappings; no experiments or proofs rerun, and no independent reproduction.'}
out = ROOT / 'artifact/out/privacy_validation.json'
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(validation,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(validation,indent=2))
