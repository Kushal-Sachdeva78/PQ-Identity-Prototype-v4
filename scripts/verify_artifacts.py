#!/usr/bin/env python3
"""Verify committed circuit/setup pins and, optionally, the publication manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def resolve_pin(name: str, entry: dict) -> str:
    if entry.get('path'):
        return entry['path']
    if name.endswith('.ptau'):
        return 'setup/ptau/' + name
    if name.endswith('.r1cs'):
        return 'circuits/build/' + name
    if name.endswith('.wasm'):
        p = Path(name)
        return 'circuits/build/' + str(p.parent / (p.stem + '_js') / p.name).replace('\\', '/')
    return 'setup/out/' + name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', action='store_true', help='also verify every listed publication file')
    args = parser.parse_args()
    checks: dict[str, str] = {}
    for name in ('setup/pins.json', 'setup/pins_v4.json'):
        for key, entry in json.loads((ROOT / name).read_text(encoding='utf-8')).items():
            checks[resolve_pin(key, entry)] = entry['sha256']
    pinned = len(checks)
    if args.manifest:
        for line in (ROOT / 'MANIFEST.sha256.tsv').read_text(encoding='utf-8').splitlines():
            if not line or line.startswith('#'):
                continue
            expected, rel = line.split('\t', 1)
            if rel in checks and checks[rel] != expected:
                raise ValueError('Manifest disagrees with setup pin: ' + rel)
            checks[rel] = expected
    failures = []
    for rel, expected in checks.items():
        path = (ROOT / rel).resolve()
        if not path.is_relative_to(ROOT.resolve()):
            failures.append(rel + ': path escapes repository')
        elif not path.is_file():
            failures.append(rel + ': missing')
        elif digest(path) != expected:
            failures.append(rel + ': SHA-256 mismatch')
    if failures:
        for message in failures:
            print('FAIL ' + message)
        return 1
    print(f'Verified {pinned} pinned artifacts; {len(checks)} total file hashes.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
