"""Analyze a completed new 3.7 exploratory series; never pool smoke data."""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from pathlib import Path
import random
import statistics

B = 10_000
SEED = 20260927


def quantile(xs, p):
    ys = sorted(xs)
    h = (len(ys) - 1) * p
    lo, hi = math.floor(h), math.ceil(h)
    return ys[lo] + (ys[hi] - ys[lo]) * (h - lo)


def stats(xs, rng):
    if not xs:
        return None
    samples = [statistics.median(rng.choices(xs, k=len(xs))) for _ in range(B)]
    q1, q3 = quantile(xs, .25), quantile(xs, .75)
    return dict(n=len(xs), median=statistics.median(xs), q1=q1, q3=q3,
                iqr=q3-q1, p95=quantile(xs, .95), minimum=min(xs), maximum=max(xs),
                medianCI95=[quantile(samples, .025), quantile(samples, .975)])


def comparison(a, b, rng, kind):
    ids = sorted(set(a) & set(b))
    x, y = [a[i] for i in ids], [b[i] for i in ids]
    if not ids:
        return None
    def f(xx, yy):
        ma, mb = statistics.median(xx), statistics.median(yy)
        return ma / mb if kind == 'ratio' else ma - mb
    boot = []
    for _ in range(B):
        ix = rng.choices(range(len(ids)), k=len(ids))
        boot.append(f([x[i] for i in ix], [y[i] for i in ix]))
    return dict(pairedBlocks=len(ids), kind=kind, estimate=f(x, y),
                ci95=[quantile(boot, .025), quantile(boot, .975)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('run', type=Path)
    args = ap.parse_args()
    root = args.run.resolve()
    if (root.parents[1] / 'RUNNING').exists():
        raise SystemExit('analysis refused while native series RUNNING')
    env = json.loads((root / 'environment.json').read_text())
    completion = json.loads((root / 'completion.json').read_text())
    if env['mode'] != 'run' or completion['status'] != 'complete':
        raise SystemExit('only complete measured campaigns may be analyzed')
    blocks = [json.loads(s) for s in (root / 'blocks.jsonl').read_text().splitlines()]
    good = [b for b in blocks if b['status'] == 'ok' and not b['warmup']]
    if len(good) != 30 or len({b['block'] for b in good}) != 30:
        raise SystemExit('expected exactly 30 unique complete measured blocks')
    rng = random.Random(SEED)
    groups = {}
    times = {}
    for condition in json.loads((root / 'schedule.json').read_text())['conditions']:
        cid = condition['id']
        rows = [(b, next(i for i in b['iterations'] if i['condition']['id'] == cid)) for b in good]
        if any(not i['checks']['correct'] for _, i in rows):
            raise SystemExit('accepted block has invalid iteration')
        elapsed = [i['result']['endToEndMs'] for _, i in rows]
        times[cid] = {b['block']: i['result']['endToEndMs'] for b, i in rows}
        g = dict(condition=condition, endToEndMs=stats(elapsed, rng))
        clean = [i['result']['endToEndMs'] for b, i in rows if b['quiesce']['quiesced']]
        g['quietSensitivity'] = stats(clean, rng)
        g['flaggedBlocks'] = [b['block'] for b, _ in rows if not b['quiesce']['quiesced']]
        g['httpPostsPerPresentation'] = sorted(set(len(i['proxyRecords']) for _, i in rows))
        g['timerWaitMsPerPost'] = stats([p['timerWaitMs'] for _, i in rows for p in i['proxyRecords']], rng)
        g['requestedAddedDelayMs'] = condition['delayMs']
        g['proxyDelayWaitSumMs'] = stats([sum(p['timerWaitMs'] for p in i['proxyRecords']) for _, i in rows], rng)
        g['bytes'] = {field: stats([i['result']['bytes'][field] for _, i in rows], rng) for field in ['request', 'reply', 'proof']}
        if condition['instrumented']:
            g['stagesMs'] = {s: stats([i['result']['report']['stages'][s]['ms'] for _, i in rows], rng) for s in [f'S{x}' for x in range(1, 12)]}
            g['stageHttpPosts'] = {s: sorted(set(i['result']['report']['stages'][s]['posts'] for _, i in rows)) for s in [f'S{x}' for x in range(1, 12)]}
            g['chainMs'] = stats([sum(i['result']['report']['totals']['chainMsByParty'].values()) for _, i in rows], rng)
            g['chainShare'] = stats([sum(i['result']['report']['totals']['chainMsByParty'].values()) / i['result']['endToEndMs'] for _, i in rows], rng)
        groups[cid] = g
    comparisons = {}
    for delay in [0, 20, 50]:
        comparisons[f'snarkjs_over_rapidsnark_{delay}ms'] = comparison(times[f'snarkjs-{delay}ms'], times[f'rapidsnark-{delay}ms'], rng, 'ratio')
    for prover in ['snarkjs', 'rapidsnark']:
        for delay in [20, 50]:
            comparisons[f'{prover}_{delay}ms_minus_0ms'] = comparison(times[f'{prover}-{delay}ms'], times[f'{prover}-0ms'], rng, 'difference-ms')
        comparisons[f'{prover}_instrumented_over_control_0ms'] = comparison(times[f'{prover}-0ms'], times[f'{prover}-0ms-control'], rng, 'ratio')
    summary = dict(schema='pqid-3.7-native-summary/v1', labels=env['labels'],
                   startedUtc=env['startedUtc'], finishedUtc=completion['finishedUtc'],
                   bootstrap=dict(B=B, seed=SEED, pairedBlockResampling=True),
                   measuredBlocks=len(good), measuredPresentations=sum(len(b['iterations']) for b in good),
                   excludedBlockAttempts=[dict(block=b['block'], warmup=b['warmup'], attempt=b['attempt'], reason=b['failure']) for b in blocks if b['status'] != 'ok'],
                   allChecksPassed=True, groups=groups, comparisons=comparisons,
                   originalC5Unchanged=True, remoteEndpoint=False, secondDevice=False,
                   sourceAndPinHashesUnchanged=completion['sourceAndPinHashesUnchanged'],
                   provenance={f: hashlib.sha256((root/f).read_bytes()).hexdigest() for f in ['environment.json', 'schedule.json', 'blocks.jsonl', 'completion.json']},
                   analysisSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    lines = ['# Version 3.7 exploratory native presentation experiment', '',
             'Development key; one laptop; WSL2; loopback Anvil through an experimental proxy. Native rows use an experimental metadata adapter, not shipped integration; the unadapted native smoke failed the wallet schema check. Both parties share one process. Warm process state and fresh party HTTP agents. Positive delays are deterministic simulated RPC latency, not remote measurements. Original C5 unchanged.', '',
             '| Prover | Added delay per POST | n | Full presentation median [ms] | IQR [ms] | Median 95% CI [ms] | S8 median [ms] | POSTs |',
             '|---|---:|---:|---:|---:|---|---:|---:|']
    for cid, g in groups.items():
        if not g['condition']['instrumented']:
            continue
        s = g['endToEndMs']; c = g['condition']; ci=s['medianCI95']
        lines.append(f"| {c['prover']} | {c['delayMs']} ms | {s['n']} | {s['median']:.2f} | {s['iqr']:.2f} | {ci[0]:.2f} to {ci[1]:.2f} | {g['stagesMs']['S8']['median']:.2f} | {g['httpPostsPerPresentation']} |")
    lines += ['', f"Accepted measured presentations: {summary['measuredPresentations']}; excluded block attempts: {len(summary['excludedBlockAttempts'])}.", '', '## Paired comparisons', '', '| Comparison | Estimate | 95% CI |', '|---|---:|---|']
    for k, c in comparisons.items():
        lines.append(f"| {k} | {c['estimate']:.3f} | {c['ci95'][0]:.3f} to {c['ci95'][1]:.3f} |")
    flagged = groups['snarkjs-0ms']['flaggedBlocks']
    lines += ['', f'Quiet-check flagged measured blocks: {flagged}. Sensitivity results are retained in summary.json; the guard cannot observe Windows load.', '',
              'Confidence intervals describe within-session variation. Setup/synchronization is outside the timed window and retained in setup.json. This is neither cold/first-use latency nor WAN, second-device, distributed-consensus or ceremony-key evidence.']
    (root / 'summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
