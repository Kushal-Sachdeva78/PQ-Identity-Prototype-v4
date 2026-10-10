#!/usr/bin/env python3
"""Summarise phone timing and memory logs (docs/v4/PHONE_PROTOCOL.md, "Analysis").

Reads the native app logs (native_*.json, schema pqid/v4-phone-native/v1) and the Safari
results (safari_*.json, schema pqid/v4-phone-safari/v1) from a directory (default
results/v4/phone). Groups never mix: path (native-mopro, native-mopro-simulator,
safari-snarkjs) x device (native: device.model + OS version; Safari: user agent) x kind.

Used records: no error, verified, public signals match. Excluded and counted: native records
flagged thermalNotNominalAtStart (unless --keep-thermal-flagged), Safari records with the tab
hidden during the run, duplicates (same sessionId and index; the last posted copy is kept).
Statistics as docs/v4/BENCH_PROTOCOL.md: n, median, Q1, Q3, IQR (numpy "linear"), min, max;
percentile bootstrap 95% CI of the median and of the cold/warm ratio of medians
(B = 10,000, seed 20260927, default_rng([seed, crc32(id)])).

Usage: python mobile/scripts/phone_summary.py [--dir results/v4/phone] [--out <dir>/summary.json]
Requires numpy only.
"""

from __future__ import annotations

import argparse
import json
import sys
import zlib
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
SEED = 20260927
B = 10_000

NATIVE_METRICS = {
    "proveMs": lambda r: r.get("proveMs"),
    "verifyMs": lambda r: r.get("verifyMs"),
    "sampledPeakBytes": lambda r: (r.get("footprint") or {}).get("sampledPeakBytes"),
    "sampledPeakAboveBaselineBytes": lambda r: (r.get("footprint") or {}).get("sampledPeakAboveBaselineBytes"),
    "lifetimePeakAfterBytes": lambda r: (r.get("footprint") or {}).get("lifetimePeakAfterBytes"),
}
SAFARI_METRICS = {
    "witnessMs": lambda r: r.get("witnessMs"),
    "proveMs": lambda r: r.get("proveMs"),
    "wpMs": lambda r: r.get("wpMs"),
    "verifyMs": lambda r: r.get("verifyMs"),
}
RATIO_METRIC = {"native-mopro": "proveMs", "native-mopro-simulator": "proveMs", "safari-snarkjs": "wpMs"}


def describe(x: np.ndarray) -> dict:
    q1, med, q3 = np.quantile(x, [0.25, 0.5, 0.75], method="linear")
    return {"n": int(x.size), "median": float(med), "q1": float(q1), "q3": float(q3), "iqr": float(q3 - q1),
            "min": float(np.min(x)), "max": float(np.max(x))}


def rng_for(key: str) -> np.random.Generator:
    return np.random.default_rng([SEED, zlib.crc32(key.encode())])


def median_ci(x: np.ndarray, key: str) -> list[float] | None:
    if x.size < 2:
        return None
    idx = rng_for(key).integers(0, x.size, size=(B, x.size))
    lo, hi = np.percentile(np.median(x[idx], axis=1), [2.5, 97.5])
    return [float(lo), float(hi)]


def ratio_ci(num: np.ndarray, den: np.ndarray, key: str) -> dict | None:
    if num.size < 2 or den.size < 2:
        return None
    g = rng_for(key)
    mn = np.median(num[g.integers(0, num.size, size=(B, num.size))], axis=1)
    md = np.median(den[g.integers(0, den.size, size=(B, den.size))], axis=1)
    lo, hi = np.percentile(mn / md, [2.5, 97.5])
    return {"ratio": float(np.median(num) / np.median(den)), "ci95": [float(lo), float(hi)],
            "nNum": int(num.size), "nDen": int(den.size)}


def load(dir_: Path) -> tuple[list[dict], dict]:
    rows: dict[tuple, dict] = {}
    counts = {"files": 0, "records": 0, "duplicates": 0, "unknownSchema": 0}
    for f in sorted(dir_.glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        schema = d.get("schema")
        if schema == "pqid/v4-phone-native/v1":
            dev = d.get("device", {})
            path = "native-mopro-simulator" if dev.get("isSimulator") else "native-mopro"
            device = f"{dev.get('model')} {dev.get('systemName')} {dev.get('systemVersion')}"
        elif schema == "pqid/v4-phone-safari/v1":
            path = "safari-snarkjs"
            device = d.get("env", {}).get("userAgent", "unknown")
        else:
            counts["unknownSchema"] += 1
            continue
        counts["files"] += 1
        for r in d.get("records", []):
            counts["records"] += 1
            key = (d.get("sessionId"), r.get("index"))
            if key in rows:
                counts["duplicates"] += 1
            rows[key] = {"path": path, "device": device, "file": f.name, "keyLabel": d.get("keyLabel"),
                         "context": d.get("context"), "rec": r}
    return list(rows.values()), counts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", type=Path, default=REPO / "results" / "v4" / "phone")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--keep-thermal-flagged", action="store_true")
    a = ap.parse_args()
    out = a.out or (a.dir / "summary.json")

    rows, counts = load(a.dir)
    excluded = {"errorOrUnverified": 0, "thermalFlagged": 0, "hiddenTab": 0}
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        r = row["rec"]
        if r.get("error") or r.get("verified") is not True or r.get("publicSignalsMatch") is not True:
            excluded["errorOrUnverified"] += 1
            continue
        if row["path"].startswith("native") and r.get("thermalNotNominalAtStart") and not a.keep_thermal_flagged:
            excluded["thermalFlagged"] += 1
            continue
        if row["path"] == "safari-snarkjs" and r.get("hiddenDuringRun"):
            excluded["hiddenTab"] += 1
            continue
        groups.setdefault((row["path"], row["device"], r.get("kind")), []).append(row)

    summary = []
    for (path, device, kind), g in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1], str(kv[0][2]))):
        metrics = SAFARI_METRICS if path == "safari-snarkjs" else NATIVE_METRICS
        entry = {"path": path, "device": device, "kind": kind, "n": len(g),
                 "keyLabels": sorted({str(x["keyLabel"]) for x in g}), "metrics": {}}
        for name, get in metrics.items():
            vals = np.array([v for v in (get(x["rec"]) for x in g) if v is not None], dtype=float)
            if vals.size:
                entry["metrics"][name] = {**describe(vals), "medianCI95": median_ci(vals, f"{path}|{device}|{kind}|{name}")}
        summary.append(entry)

    ratios = []
    for path, metric in RATIO_METRIC.items():
        devices = {d for (p, d, _k) in groups if p == path}
        for device in sorted(devices):
            cold = groups.get((path, device, "cold"), [])
            warm = groups.get((path, device, "warm"), [])
            get = (SAFARI_METRICS if path == "safari-snarkjs" else NATIVE_METRICS)[metric]
            num = np.array([v for v in (get(x["rec"]) for x in cold) if v is not None], dtype=float)
            den = np.array([v for v in (get(x["rec"]) for x in warm) if v is not None], dtype=float)
            ratios.append({"path": path, "device": device, "metric": metric, "ratio": "cold/warm",
                           "result": ratio_ci(num, den, f"{path}|{device}|cold/warm|{metric}")
                           or {"status": f"not computed (cold n={num.size}, warm n={den.size}; need 2 each)"}})

    result = {
        "schema": "pqid/v4-phone-summary/v1",
        "label": "[M] phone runs as logged; native and Safari reported separately; simulator rows are not phone measurements",
        "generator": "mobile/scripts/phone_summary.py",
        "dir": str(a.dir.relative_to(REPO)) if a.dir.is_relative_to(REPO) else a.dir.name,
        "counts": counts,
        "excluded": excluded,
        "groups": summary,
        "ratios": ratios,
        "bootstrap": {"B": B, "seed": SEED, "method": "percentile"},
        "timestampUtc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for e in summary:
        m = e["metrics"].get("proveMs") or {}
        print(f"[phone] {e['path']:<24} {e['kind']:<7} n={e['n']:<3} proveMs median {m.get('median')} {e['device'][:60]}")
    print(f"[phone] excluded {excluded}; wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
