"""Post-run checks and explicitly post-hoc clock-gap sensitivity; primary data unchanged."""
import argparse
import importlib.util
import json
from pathlib import Path
import random
import statistics

spec = importlib.util.spec_from_file_location('analysis', Path(__file__).with_name('analyze.py'))
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('run', type=Path)
    root = ap.parse_args().run
    blocks = [json.loads(s) for s in (root/'blocks.jsonl').read_text().splitlines()]
    measured = [b for b in blocks if not b['warmup'] and b['status'] == 'ok']
    settle = json.loads((root/'settle.json').read_text())
    env = json.loads((root/'environment.json').read_text())
    iteration_checks = [i['checks'] for b in blocks for i in b['iterations']]
    power_readings = [b[p] for b in blocks for p in ['powerBefore', 'powerAfter']]
    audit = {
        'schema': 'pqid-3.7-native-audit/v1',
        'allAttemptedIterations': len(iteration_checks),
        'allInvariantChecksPassed': all(c['correct'] for c in iteration_checks),
        'measuredPresentationCount': sum(len(b['iterations']) for b in measured),
        'warmupPresentationCount': sum(len(b['iterations']) for b in blocks if b['warmup']),
        'nonAcReadings': sum(not p['ac'] for p in power_readings),
        'excludedBlockAttempts': [b['block'] for b in blocks if b['status'] != 'ok'],
        'measuredQuietFlags': {b['block']: b['quiesce']['reasons'] for b in measured if not b['quiesce']['quiesced']},
        'warmupQuietFlags': {b['block']: b['quiesce']['reasons'] for b in blocks if b['warmup'] and not b['quiesce']['quiesced']},
        'settle': dict(settle, wallMinusMonotonicMs=settle['wallMs']-settle['monotonicMs']),
        'blockClockGapMsRange': [min(b['clockGapMs'] for b in blocks), max(b['clockGapMs'] for b in blocks)],
        'measuredBlockGapsOver1000ms': {b['block']: b['clockGapMs'] for b in measured if abs(b['clockGapMs']) > 1000},
        'measuredBlockGapsOver500ms': {b['block']: b['clockGapMs'] for b in measured if abs(b['clockGapMs']) > 500},
        'prespecifiedBlockExclusionThresholdMs': 2000,
        'perIterationWallTimesRecorded': False,
        'interpretation': 'Clock divergence cause unestablished. Retain primary monotonic timings under the prespecified rule; do not call them validated wall-clock user waits. Cannot attribute block clock gaps to individual conditions.',
        'newlineOnlySourceDifferences': [p for p, h in env['sourceHashes'].items() if h['windowsSha256'] != h['wslSha256']],
    }
    # Declared after viewing observations, so this is a diagnostic, not the primary analysis.
    keep = [b for b in measured if b['quiesce']['quiesced'] and abs(b['clockGapMs']) <= 500]
    rng = random.Random(20260927)
    timings = {}
    for c in json.loads((root/'schedule.json').read_text())['conditions']:
        cid = c['id']
        vals = {b['block']: next(i['result']['endToEndMs'] for i in b['iterations'] if i['condition']['id'] == cid) for b in keep}
        timings[cid] = vals
    audit['postHocClockSensitivity'] = {
        'label': 'POST HOC, after observing clock gaps; diagnostic only',
        'rule': 'exclude a block with failed quiet check OR abs(wall-minus-monotonic block gap)>500ms',
        'retainedBlocks': [b['block'] for b in keep],
        'excludedBlocks': [b['block'] for b in measured if b not in keep],
        'groups': {cid: analysis.stats(list(vals.values()), rng) for cid, vals in timings.items()},
        'snarkjsOverNative0ms': analysis.comparison(timings['snarkjs-0ms'], timings['rapidsnark-0ms'], rng, 'ratio'),
    }
    adapters = [i['nativeAdapter'] for b in blocks for i in b['iterations'] if i['condition']['prover'] == 'rapidsnark']
    audit['adapterAudit'] = {
        'nativePresentations': len(adapters),
        'everyActionAddsOnlyCurveMetadata': all(a['action'] == 'added curve=bn128' and a['coordinatesUnchanged'] and a['publicSignalsFileUntouched'] for a in adapters),
        'inputKeys': sorted(set(tuple(a['inputKeys']) for a in adapters)),
    }
    (root/'audit.json').write_text(json.dumps(audit, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k: audit[k] for k in ['allAttemptedIterations', 'allInvariantChecksPassed', 'nonAcReadings', 'measuredBlockGapsOver1000ms', 'measuredBlockGapsOver500ms', 'settle', 'adapterAudit']}, indent=2))
    print('Post-hoc retained blocks:', len(keep))
    for cid, s in audit['postHocClockSensitivity']['groups'].items():
        print(cid, 'median', round(s['median'], 3), 'CI95', [round(x, 3) for x in s['medianCI95']])


if __name__ == '__main__':
    main()
