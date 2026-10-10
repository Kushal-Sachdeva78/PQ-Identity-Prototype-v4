#!/usr/bin/env python3
"""Compare the verdicts of two v4 security-suite runs (committed vs rebuilt).

Usage: python artifact/compare_suite.py <committed security_suite.json> <rebuilt security_suite.json>

Per (record id, route): accepted, valid and the stopping layer must match. Timings, host
data and details are ignored. Exit 0 when every verdict matches, 1 otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def verdicts(path: Path) -> dict[str, tuple[bool, bool, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, tuple[bool, bool, str]] = {}
    for r in data["records"]:
        for a in r["attempts"]:
            key = f"{r['id']}|{a['route']}"
            n = 2
            while key in out:
                key = f"{r['id']}|{a['route']}#{n}"
                n += 1
            out[key] = (bool(a["accepted"]), bool(a["valid"]), str(a["stoppedBy"]["layer"]))
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 64
    a, b = verdicts(Path(argv[1])), verdicts(Path(argv[2]))
    diffs = [f"{k}: committed {a.get(k)} rebuilt {b.get(k)}" for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
    for d in diffs:
        print("DIFF", d)
    print(f"{len(a)} committed verdicts, {len(b)} rebuilt, {len(diffs)} differ")
    return 1 if diffs else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
