#!/usr/bin/env python3
"""Print the UDID of an available iPhone simulator on the newest installed iOS runtime.

Usage: python3 mobile/mopro/scripts/pick_simulator.py   (macOS with Xcode; used by CI)
Prints "<udid>\t<name>\t<runtime>" and exits 1 when no iPhone simulator is available.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys


def runtime_version(key: str) -> tuple[int, ...]:
    m = re.search(r"iOS-(\d+(?:-\d+)*)$", key)
    return tuple(int(x) for x in m.group(1).split("-")) if m else ()


def main() -> int:
    out = subprocess.run(["xcrun", "simctl", "list", "devices", "available", "-j"],
                         check=True, capture_output=True, text=True).stdout
    devices = json.loads(out).get("devices", {})
    best = None
    for runtime, devs in devices.items():
        v = runtime_version(runtime)
        if not v:
            continue
        for d in devs:
            if d.get("isAvailable", True) and d.get("name", "").startswith("iPhone"):
                cand = (v, d["name"], d["udid"], runtime)
                if best is None or cand[0] > best[0]:
                    best = cand
    if best is None:
        print("no available iPhone simulator", file=sys.stderr)
        return 1
    print(f"{best[2]}\t{best[1]}\t{best[3]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
