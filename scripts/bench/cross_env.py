#!/usr/bin/env python3
"""Cross-environment prover ratios (docs/v4/BENCH_PROTOCOL.md, Deviations 2026-09-29; D-031).

The Windows campaigns (results/v4/bench/) measured snarkJS; rapidsnark ran only in WSL on the
same laptop (results/v4/bench_wsl/). This script reports, for each version and for proving
and witness+proving, the ratio of medians Windows cold snarkJS / WSL cold rapidsnark with the
same percentile bootstrap as scripts/bench/analyze.py. Every ratio here compares two operating
environments and is labelled so; the same-environment speedups are the warm WSL ratios in
results/v4/bench_wsl/summary.json.

Usage: python scripts/bench/cross_env.py
Writes results/v4/bench_wsl/cross_env.json.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import analyze as A  # noqa: E402

WIN = A.REPO / "results" / "v4" / "bench"
WSL = A.REPO / "results" / "v4" / "bench_wsl"


def main() -> int:
    for root in (WIN, WSL):
        if (root / "RUNNING").exists():
            print(f"[cross_env] {root / 'RUNNING'} exists: a timed run is active; no analyses now", file=sys.stderr)
            return 2
    win, _bw, _ = A.load_campaigns(WIN)
    wsl, _bl, _ = A.load_campaigns(WSL)
    ratios = []
    for v in A.VERSIONS:
        num, den = ("cold", v, "snarkjs"), ("cold", v, "rapidsnark")
        for ph in ("prove", "wp"):
            rid = f"crossenv/cold/{v}/snarkjs_win_over_rapidsnark_wsl/{ph}"
            entry = {"id": rid, "phase": ph, "numerator": f"cold/{v}/snarkjs (Windows)", "denominator": f"cold/{v}/rapidsnark (WSL)"}
            if num not in win or den not in wsl:
                entry["status"] = "no data"
                ratios.append(entry)
                continue
            x, y = win[num][ph], wsl[den][ph]
            lo, hi = A.boot_ratio(x, y, A.B_DEFAULT, A.SEED_DEFAULT, rid)
            entry.update({
                "status": "ok",
                "label": "cross-environment: Windows snarkJS over WSL rapidsnark, same laptop, separate campaigns",
                "osNumerator": win[num]["os"],
                "osDenominator": wsl[den]["os"],
                "ratioOfMedians": float(np.median(x) / np.median(y)),
                "ci95": [lo, hi],
                "nNumerator": int(x.size),
                "nDenominator": int(y.size),
            })
            ratios.append(entry)
    out = {
        "schema": "pqid/v4-bench-crossenv/v1",
        "generatedUtc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "generator": "scripts/bench/cross_env.py",
        "label": "[M] cross-environment ratios (not interleaved; different operating environments)",
        "statistics": {"ci": "percentile bootstrap 95%, as scripts/bench/analyze.py", "B": A.B_DEFAULT, "seed": A.SEED_DEFAULT},
        "ratios": ratios,
    }
    (WSL / "cross_env.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8", newline="\n")
    ok = [r for r in ratios if r["status"] == "ok"]
    print(f"[cross_env] {len(ok)}/{len(ratios)} ratios -> {(WSL / 'cross_env.json').relative_to(A.REPO).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
