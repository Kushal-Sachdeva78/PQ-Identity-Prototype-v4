#!/usr/bin/env python3
"""Energy per proof from a power trace and proof markers (docs/v4/PHONE_PROTOCOL.md, "Energy").

The instrument, its sampling rate, units and the way proof start/end are placed in the trace
are the student's lab set-up (all [VERIFY] in the protocol). This script only integrates.

Inputs
  --trace TRACE.csv    power trace. A time column plus either a power column, or a voltage
                       and a current column (power = V * I). Column names and units are options.
  --markers MARKERS.csv  one row per proof, in the TRACE time base:
                       proof_id,kind,start_s,end_s[,baseline_start_s,baseline_end_s]
                       kind is free text (cold, warm, ...); rows are summarised per kind.
                       Without baseline columns the baseline window is the idle time before the
                       proof: [start_s - guard - baseline_len, start_s - guard].
Helper (no trace needed)
  --markers-from-log LOG.json [...] --clock-offset-s X --out-markers MARKERS.csv
                       turns the app logs (native_*.json or safari_*.json) into a marker CSV:
                       trace_time = UTC epoch seconds of the app marker + X. X comes from the
                       lab's clock synchronisation [VERIFY]; the script cannot know it.

Per proof
  gross_J   = integral of P(t) over [start_s, end_s] (trapezoid rule on the samples, P linearly
              interpolated at the window edges)
  base_W    = mean (or median) power of the samples in the baseline window
  net_J     = gross_J - base_W * (end_s - start_s)
Summary per kind: n, median, mean, Q1, Q3, IQR (numpy "linear"), min, max of net_J and of the
duration, with percentile bootstrap 95% CIs of the median and the mean (B = 10,000, seed
20260927, as scripts/bench/analyze.py). Checks: samples inside each proof window and each
baseline window (warn below --min-samples), overlapping windows, windows outside the trace.

Usage
  python mobile/scripts/energy_analysis.py --trace t.csv --markers m.csv --out energy.json
  python mobile/scripts/energy_analysis.py --markers-from-log results/v4/phone/native_X.json \
         --clock-offset-s 0.0 --out-markers m.csv
Requires numpy only.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import zlib
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

SEED = 20260927
B = 10_000


# ----------------------------------------------------------------------------- reading
def read_csv(path: Path) -> tuple[list[str], list[list[str]]]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        rows = [r for r in csv.reader(f) if r and not r[0].lstrip().startswith("#")]
    if not rows:
        raise SystemExit(f"{path}: empty")
    header = [h.strip() for h in rows[0]]
    return header, rows[1:]


def column(header: list[str], rows: list[list[str]], name: str, path: Path) -> np.ndarray:
    if name not in header:
        raise SystemExit(f"{path}: no column {name!r} (columns: {header})")
    i = header.index(name)
    return np.array([float(r[i]) for r in rows], dtype=float)


TIME_SCALE = {"s": 1.0, "ms": 1e-3, "us": 1e-6}
CURRENT_SCALE = {"A": 1.0, "mA": 1e-3, "uA": 1e-6}
VOLTAGE_SCALE = {"V": 1.0, "mV": 1e-3}
POWER_SCALE = {"W": 1.0, "mW": 1e-3}


def load_trace(a: argparse.Namespace) -> tuple[np.ndarray, np.ndarray, dict]:
    header, rows = read_csv(a.trace)
    t = column(header, rows, a.time_col, a.trace) * TIME_SCALE[a.time_unit]
    if a.power_col:
        p = column(header, rows, a.power_col, a.trace) * POWER_SCALE[a.power_unit]
        how = f"power column {a.power_col} [{a.power_unit}]"
    else:
        v = column(header, rows, a.voltage_col, a.trace) * VOLTAGE_SCALE[a.voltage_unit]
        i = column(header, rows, a.current_col, a.trace) * CURRENT_SCALE[a.current_unit]
        if a.current_sign == "negative-is-discharge":
            i = -i
        p = v * i
        how = f"{a.voltage_col} [{a.voltage_unit}] x {a.current_col} [{a.current_unit}], sign {a.current_sign}"
    order = np.argsort(t, kind="stable")
    t, p = t[order], p[order]
    if np.any(np.diff(t) <= 0):
        raise SystemExit("trace has repeated time stamps")
    dt = np.diff(t)
    info = {
        "file": str(a.trace),
        "samples": int(t.size),
        "startS": float(t[0]),
        "endS": float(t[-1]),
        "medianSamplingIntervalS": float(np.median(dt)),
        "medianSamplingRateHz": float(1.0 / np.median(dt)),
        "maxGapS": float(dt.max()),
        "power": how,
    }
    return t, p, info


def load_markers(path: Path) -> list[dict]:
    header, rows = read_csv(path)
    need = ["proof_id", "kind", "start_s", "end_s"]
    for n in need:
        if n not in header:
            raise SystemExit(f"{path}: needs columns {need} (+ optional baseline_start_s, baseline_end_s)")
    out = []
    for r in rows:
        d = dict(zip(header, (x.strip() for x in r)))
        m = {"proof_id": d["proof_id"], "kind": d["kind"], "start_s": float(d["start_s"]), "end_s": float(d["end_s"])}
        if d.get("baseline_start_s") and d.get("baseline_end_s"):
            m["baseline_start_s"] = float(d["baseline_start_s"])
            m["baseline_end_s"] = float(d["baseline_end_s"])
        if m["end_s"] <= m["start_s"]:
            raise SystemExit(f"{path}: proof {m['proof_id']} ends before it starts")
        out.append(m)
    return out


# ----------------------------------------------------------------------------- integration
def interp(t: np.ndarray, p: np.ndarray, x: float) -> float:
    return float(np.interp(x, t, p))


def integrate(t: np.ndarray, p: np.ndarray, a: float, b: float) -> tuple[float, int]:
    """Trapezoid integral of P over [a, b] with interpolated edges; also the samples inside."""
    inside = (t > a) & (t < b)
    ts = np.concatenate(([a], t[inside], [b]))
    ps = np.concatenate(([interp(t, p, a)], p[inside], [interp(t, p, b)]))
    return float(np.sum((ps[1:] + ps[:-1]) * np.diff(ts) / 2.0)), int(inside.sum())


def window_stat(t: np.ndarray, p: np.ndarray, a: float, b: float, stat: str) -> tuple[float | None, int]:
    sel = (t >= a) & (t <= b)
    n = int(sel.sum())
    if n == 0:
        return None, 0
    return (float(np.mean(p[sel])) if stat == "mean" else float(np.median(p[sel]))), n


# ----------------------------------------------------------------------------- statistics
def describe(x: np.ndarray) -> dict:
    q1, med, q3 = np.quantile(x, [0.25, 0.5, 0.75], method="linear")
    return {"n": int(x.size), "median": float(med), "mean": float(np.mean(x)), "q1": float(q1), "q3": float(q3),
            "iqr": float(q3 - q1), "min": float(np.min(x)), "max": float(np.max(x))}


def bootstrap_ci(x: np.ndarray, fn, key: str) -> list[float] | None:
    if x.size < 2:
        return None
    rng = np.random.default_rng([SEED, zlib.crc32(key.encode())])
    idx = rng.integers(0, x.size, size=(B, x.size))
    vals = fn(x[idx], axis=1)
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return [float(lo), float(hi)]


# ----------------------------------------------------------------------------- markers from app logs
def utc_to_epoch(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def markers_from_logs(logs: list[Path], offset: float, out: Path) -> None:
    rows = []
    for lp in logs:
        d = json.loads(lp.read_text(encoding="utf-8"))
        sid = str(d.get("sessionId", lp.stem))[:8]
        for r in d.get("records", []):
            ev: dict = {}
            for m in r.get("markers", []):
                ev.setdefault(m["event"], m)  # first occurrence (flash_on appears before and after)
            if "proof_start" not in ev or "proof_end" not in ev:
                continue

            def ts(m: dict) -> float:  # native markers: ISO utc; Safari markers: utcMs
                return utc_to_epoch(m["utc"]) if "utc" in m else m["utcMs"] / 1000.0

            row = {"proof_id": f"{d.get('path', 'app')}:{sid}:{r['index']}", "kind": r["kind"],
                   "start_s": ts(ev["proof_start"]) + offset, "end_s": ts(ev["proof_end"]) + offset,
                   "baseline_start_s": "", "baseline_end_s": ""}
            if "pre_idle_start" in ev:
                row["baseline_start_s"] = ts(ev["pre_idle_start"]) + offset
                first = ev.get("flash_on", ev["proof_start"])  # baseline ends before any flash
                row["baseline_end_s"] = ts(first) + offset
            rows.append(row)
    if not rows:
        raise SystemExit("no records with proof_start/proof_end markers in the given logs")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"[energy] wrote {len(rows)} marker rows to {out} (clock offset {offset} s: [VERIFY] from the lab sync)")


# ----------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trace", type=Path)
    ap.add_argument("--markers", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--time-col", default="time_s")
    ap.add_argument("--time-unit", default="s", choices=list(TIME_SCALE))
    ap.add_argument("--power-col", default=None, help="power column; omit to use voltage x current")
    ap.add_argument("--power-unit", default="W", choices=list(POWER_SCALE))
    ap.add_argument("--voltage-col", default="voltage_v")
    ap.add_argument("--voltage-unit", default="V", choices=list(VOLTAGE_SCALE))
    ap.add_argument("--current-col", default="current_a")
    ap.add_argument("--current-unit", default="A", choices=list(CURRENT_SCALE))
    ap.add_argument("--current-sign", default="positive-is-discharge", choices=["positive-is-discharge", "negative-is-discharge"])
    ap.add_argument("--baseline-len-s", type=float, default=3.0, help="default baseline window length before each proof")
    ap.add_argument("--guard-s", type=float, default=0.5, help="gap between the default baseline window and the proof start")
    ap.add_argument("--baseline-stat", default="mean", choices=["mean", "median"])
    ap.add_argument("--min-samples", type=int, default=10)
    ap.add_argument("--markers-from-log", type=Path, nargs="+")
    ap.add_argument("--clock-offset-s", type=float, default=None)
    ap.add_argument("--out-markers", type=Path)
    a = ap.parse_args()

    if a.markers_from_log:
        if a.clock_offset_s is None or a.out_markers is None:
            ap.error("--markers-from-log needs --clock-offset-s and --out-markers")
        markers_from_logs(a.markers_from_log, a.clock_offset_s, a.out_markers)
        return 0
    if not (a.trace and a.markers):
        ap.error("--trace and --markers are required")

    t, p, trace_info = load_trace(a)
    markers = load_markers(a.markers)
    warnings: list[str] = []
    per_proof = []
    windows = []
    for m in markers:
        s, e = m["start_s"], m["end_s"]
        if "baseline_start_s" in m:
            bs, be, bsrc = m["baseline_start_s"], m["baseline_end_s"], "marker file"
        else:
            bs, be, bsrc = s - a.guard_s - a.baseline_len_s, s - a.guard_s, "default (before the proof)"
        if s < t[0] or e > t[-1] or bs < t[0]:
            warnings.append(f"{m['proof_id']}: window outside the trace; skipped")
            continue
        gross, n_in = integrate(t, p, s, e)
        base, n_base = window_stat(t, p, bs, be, a.baseline_stat)
        if n_in < a.min_samples:
            warnings.append(f"{m['proof_id']}: only {n_in} samples inside the proof window (sampling too slow?)")
        if n_base < a.min_samples:
            warnings.append(f"{m['proof_id']}: only {n_base} samples in the baseline window")
        dur = e - s
        rec = {"proof_id": m["proof_id"], "kind": m["kind"], "start_s": s, "end_s": e, "duration_s": dur,
               "samples_in_window": n_in, "gross_J": gross, "mean_power_W": gross / dur,
               "baseline": {"start_s": bs, "end_s": be, "source": bsrc, "stat": a.baseline_stat,
                            "samples": n_base, "power_W": base},
               "net_J": None if base is None else gross - base * dur}
        if base is None:
            warnings.append(f"{m['proof_id']}: empty baseline window; net energy not computed")
        per_proof.append(rec)
        windows.append((min(bs, s), e, m["proof_id"]))
    windows.sort()
    for (s1, e1, id1), (s2, _e2, id2) in zip(windows, windows[1:]):
        if s2 < e1:
            warnings.append(f"windows of {id1} and {id2} overlap")

    summary = {}
    for kind in sorted({r["kind"] for r in per_proof}):
        rows = [r for r in per_proof if r["kind"] == kind and r["net_J"] is not None]
        if not rows:
            continue
        net = np.array([r["net_J"] for r in rows])
        dur = np.array([r["duration_s"] for r in rows])
        summary[kind] = {
            "net_J": {**describe(net),
                      "medianCI95": bootstrap_ci(net, np.median, f"{kind}:net:median"),
                      "meanCI95": bootstrap_ci(net, np.mean, f"{kind}:net:mean")},
            "duration_s": describe(dur),
            "gross_J": describe(np.array([r["gross_J"] for r in rows])),
        }

    result = {
        "schema": "pqid/v4-phone-energy/v1",
        "label": "[M] energy per proof from the lab trace; instrument and sync values [VERIFY] (docs/v4/PHONE_PROTOCOL.md)",
        "generator": "mobile/scripts/energy_analysis.py",
        "trace": trace_info,
        "markers": str(a.markers),
        "parameters": {"baselineLenS": a.baseline_len_s, "guardS": a.guard_s, "baselineStat": a.baseline_stat,
                       "minSamples": a.min_samples, "bootstrap": {"B": B, "seed": SEED, "method": "percentile"}},
        "summary": summary,
        "perProof": per_proof,
        "warnings": warnings,
        "timestampUtc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    text = json.dumps(result, indent=2)
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(text + "\n", encoding="utf-8")
        print(f"[energy] wrote {a.out}")
    for kind, s in summary.items():
        n = s["net_J"]
        print(f"[energy] {kind}: n={n['n']} median net {n['median']:.4f} J (95% CI {n['medianCI95']}), "
              f"median duration {s['duration_s']['median']:.3f} s")
    for w in warnings:
        print(f"[energy] warning: {w}", file=sys.stderr)
    if not a.out:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
