#!/usr/bin/env python3
"""Statistics of the load test "verifier library under concurrent load" (robustness row,
DECISIONS D-034; protocol docs/v4/ROBUSTNESS.md section 3.9). numpy only.

Reads results/v4/robustness/load/<campaign>/ (runs.jsonl, hostile.jsonl, correctness.jsonl,
blocks.jsonl, schedule.json, env.json, auxiliary.json, saturation.json) and writes summary.json and
summary.md in the same folder.

Rows used: measured blocks (not the warm-up) whose block status is "ok"; discarded (battery,
clock gap) and error blocks are counted, never analysed; replacement warm-up passes are counted,
never analysed. Latency is per verification (ms) and uses only items with the expected outcome
("accepted" for honest replies, the class's registered rejection for hostile replies); the other
items are error items (counted and listed, never in a latency statistic). Statistics:
  - per cell: n, median, Q1, Q3, p95, p99 (type-7 quantiles = numpy "linear"), min, max, with
    cluster-bootstrap 95% CIs over measured blocks for the median, p95 and p99;
  - throughput: steady-state rate per block (the K completions between the 10th and 90th
    percentile completion times span K - 1 intervals: (K - 1) / span), median over blocks with a
    bootstrap CI over blocks;
  - scaling: speedup(W) = median rate(W) / median rate(1) per (variant, c), paired block
    bootstrap CI; parallel efficiency = speedup / W;
  - RPC requests and HTTP POSTs per verification (counts);
  - error rate (honest replies not accepted: rejections, exceptions, timeouts): errors / attempts
    with an exact Clopper-Pearson 95% interval, per cell, over the throughput cells
    (errorsThroughputCells) and over every honest reply (errorsAllHonest: throughput, HC0 and
    the correctness batch's honest items);
  - hostile-input cost per class and variant: latency, RPC per item, amplification = median over
    blocks of the class's per-block median divided by the same for HC0, paired block bootstrap CI;
  - correctness under load: counts against the required values;
  - saturation: copied as a single run (n = 1).
Bootstrap: B = 10,000, seed 20260927, one stream per statistic: default_rng([seed, crc32(id)]).

cachedReads uses a harness read cache (variant, not shipped): its numbers are never verifier
capacity. Smoke output (--smoke) is never quoted.

Usage:
  python scripts/robustness/analyze_load.py --campaign <name>
  python scripts/robustness/analyze_load.py --smoke [--campaign smoke]
Refuses to run while results/v4/bench/RUNNING or results/v4/BUSY exists.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import sys
import zlib
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "results" / "v4" / "robustness"
B_DEFAULT = 10_000
SEED_DEFAULT = 20260927
QM = "linear"  # Hyndman-Fan type 7
MARKERS = [REPO / "results" / "v4" / "bench" / "RUNNING", REPO / "results" / "v4" / "BUSY"]


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def rng_for(seed: int, ident: str) -> np.random.Generator:
    return np.random.default_rng([seed, zlib.crc32(ident.encode("utf-8"))])


def describe(x: np.ndarray) -> dict:
    if x.size == 0:
        return {"n": 0}
    q1, med, q3, p95, p99 = np.percentile(x, [25, 50, 75, 95, 99], method=QM)
    return {"n": int(x.size), "median": float(med), "q1": float(q1), "q3": float(q3), "p95": float(p95), "p99": float(p99), "min": float(x.min()), "max": float(x.max())}


def cluster_ci(groups: list[np.ndarray], q: float, ident: str, B: int, seed: int) -> list[float] | None:
    """Cluster bootstrap over blocks: resample blocks with replacement, pool, take the q-quantile."""
    groups = [g for g in groups if g.size > 0]
    k = len(groups)
    if k < 2:
        return None
    rng = rng_for(seed, ident)
    stats = np.empty(B)
    for b in range(B):
        pick = rng.integers(0, k, size=k)
        stats[b] = np.percentile(np.concatenate([groups[i] for i in pick]), q * 100, method=QM)
    lo, hi = np.percentile(stats, [2.5, 97.5], method=QM)
    return [float(lo), float(hi)]


def median_ci(values: np.ndarray, ident: str, B: int, seed: int) -> list[float] | None:
    if values.size < 2:
        return None
    rng = rng_for(seed, ident)
    idx = rng.integers(0, values.size, size=(B, values.size))
    meds = np.median(values[idx], axis=1)
    lo, hi = np.percentile(meds, [2.5, 97.5], method=QM)
    return [float(lo), float(hi)]


def paired_ratio_ci(num: np.ndarray, den: np.ndarray, ident: str, B: int, seed: int) -> list[float] | None:
    """Paired block bootstrap of median(num) / median(den); num and den are per-block values in the same block order."""
    if num.size < 2 or num.size != den.size:
        return None
    rng = rng_for(seed, ident)
    idx = rng.integers(0, num.size, size=(B, num.size))
    r = np.median(num[idx], axis=1) / np.median(den[idx], axis=1)
    lo, hi = np.percentile(r, [2.5, 97.5], method=QM)
    return [float(lo), float(hi)]


def _binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p), summed in log space."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    ks = np.arange(0, k + 1, dtype=float)
    lg = np.vectorize(math.lgamma)
    logpmf = lg(n + 1.0) - lg(ks + 1.0) - lg(n - ks + 1.0) + ks * math.log(p) + (n - ks) * math.log1p(-p)
    m = logpmf.max()
    return float(min(1.0, math.exp(m) * np.exp(logpmf - m).sum()))


def clopper_pearson(x: int, n: int, alpha: float = 0.05) -> list[float] | None:
    """Exact two-sided Clopper-Pearson interval, by bisection on the binomial CDF."""
    if n == 0:
        return None
    # lower: smallest p with P(X >= x) >= alpha/2 (P(X >= x) grows with p)
    lower = 0.0
    if x > 0:
        lo, hi = 0.0, 1.0
        for _ in range(80):
            mid = (lo + hi) / 2
            if 1.0 - _binom_cdf(x - 1, n, mid) >= alpha / 2:
                hi = mid
            else:
                lo = mid
        lower = hi
    # upper: largest p with P(X <= x) >= alpha/2 (P(X <= x) falls with p)
    upper = 1.0
    if x < n:
        lo, hi = 0.0, 1.0
        for _ in range(80):
            mid = (lo + hi) / 2
            if _binom_cdf(x, n, mid) >= alpha / 2:
                lo = mid
            else:
                hi = mid
        upper = lo
    return [float(lower), float(upper)]


# Expected outcome per hostile class when a record does not carry its own `expected` field
# (harness/v4/robustness/load_lib.ts HOSTILE_EXPECTED_CHECKS: "rejected:<first failed check>").
EXPECTED_DEFAULT = {
    "HC0": "accepted",
    "HC1": "rejected:transcriptDecrypts",
    "HC2": "rejected:sessionKnown",
    "HC3": "rejected:transcriptDecrypts",
    "HC4": "rejected:nonceBinding",
    "HC5": "rejected:groth16",
    "HC6": "rejected:shape",
    "HC7": "rejected:transcriptDecrypts",
}


def split_items(lat: list, outcomes: list, expected: str) -> tuple[list[float], list[tuple[str, float]]]:
    """Latencies of items with the expected outcome, and (outcome, latency) of the other items (error items)."""
    good: list[float] = []
    bad: list[tuple[str, float]] = []
    for x, o in zip(lat, outcomes):
        if o == expected:
            good.append(float(x))
        else:
            bad.append((o, float(x)))
    return good, bad


def error_items(bad: list[tuple[str, float]]) -> dict:
    by: dict[str, int] = {}
    for o, _ in bad:
        by[o] = by.get(o, 0) + 1
    return {"count": len(bad), "byOutcome": by, "latMs": [x for _, x in bad], "note": "items without the expected outcome: counted in the error rate, never in the latency statistics"}


def error_rate(errors: int, attempts: int) -> dict:
    return {"errors": errors, "attempts": attempts, "rate": errors / attempts if attempts else None, "clopperPearson95": clopper_pearson(errors, attempts)}


def analyse(root: Path, B: int, seed: int) -> dict:
    schedule = json.loads((root / "schedule.json").read_text(encoding="utf-8"))
    env = json.loads((root / "env.json").read_text(encoding="utf-8")) if (root / "env.json").exists() else {}
    all_blocks = read_jsonl(root / "blocks.jsonl")
    blocks = [b for b in all_blocks if b.get("record", "block") == "block"]
    warmups = [b for b in all_blocks if b.get("record") == "replacementWarmup"]
    runs = read_jsonl(root / "runs.jsonl")
    hostile = read_jsonl(root / "hostile.jsonl")
    corr = read_jsonl(root / "correctness.jsonl")
    sat = json.loads((root / "saturation.json").read_text(encoding="utf-8")) if (root / "saturation.json").exists() else None
    # auxiliary.json since 2026-10-03; aux.json (a reserved device name on Windows) only in older trees
    aux_path = next((p for p in (root / "auxiliary.json", root / "aux.json") if p.exists()), None)
    aux_file = json.loads(aux_path.read_text(encoding="utf-8")) if aux_path else None

    def used(r: dict) -> bool:
        return r.get("measured") is True and r.get("blockStatus") == "ok"

    block_counts: dict[str, int] = {}
    for b in blocks:
        block_counts[b.get("status", "?")] = block_counts.get(b.get("status", "?"), 0) + 1
    measured_ok = sorted({(b["block"], b["attempt"]) for b in blocks if b.get("status") == "ok" and b.get("measured")})
    flagged = sum(1 for b in blocks if b.get("status") == "ok" and b.get("measured") and b.get("flaggedBusy"))
    block_keys = [f"{b}:{a}" for b, a in measured_ok]

    out: dict = {
        "schema": "pqid/v4-load-summary/v2",
        "name": "verifier library under concurrent load",
        "campaign": schedule.get("campaign"),
        "smoke": schedule.get("smoke"),
        "generatedUtc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "bootstrap": {"B": B, "seed": seed, "streams": "default_rng([seed, crc32(statistic id)])"},
        "levels": schedule.get("levels"),
        "blocks": {
            "byStatus": block_counts,
            "measuredOk": len(measured_ok),
            "measuredOkFlaggedBusy": flagged,
            "discardedClockGap": block_counts.get("discarded-clock-gap", 0),
            "replacementWarmups": len(warmups),
            "replacedWorkers": sorted({w for b in blocks for w in (b.get("replacedWorkers") or [])}),
        },
        "labels": {
            "cachedReads": "harness read cache (variant, not shipped): never verifier capacity",
            "asShipped": "LedgerV4 as committed (ethers default batching, no staticNetwork), traced for counts",
            "postsAtConcurrency": "POSTs per verification at c > 1 include ethers JSON-RPC batching across concurrent verifications in one worker",
            "latency": "latency statistics use only items with the expected outcome (accepted for honest replies, the class's registered rejection for hostile replies); other items are error items",
            "replicas": env.get("replicas"),
            "network": "loopback, same host (D-034); one local Anvil with automine; library-level calls, no HTTP front end",
            "pinning": env.get("pinning"),
            "keyLabel": "dev",
        },
        "cells": [],
        "scaling": [],
        "hostile": [],
    }

    # ---- throughput cells (honest replies: expected outcome "accepted")
    workers = [r for r in runs if r.get("type") == "worker" and used(r)]
    passes = [r for r in runs if r.get("type") == "pass" and used(r)]
    cells = sorted({(r["variant"], r["W"], r["c"]) for r in passes})
    rate_by: dict[tuple, dict[str, float]] = {}
    tp_err = tp_n = 0
    for variant, W, c in cells:
        cid = f"tp:{variant}:W{W}:c{c}"
        wr = [r for r in workers if r["cell"] == cid]
        groups = []
        lat_all: list[float] = []
        bad_all: list[tuple[str, float]] = []
        n = 0
        posts = requests = 0
        for key in block_keys:
            b, a = (int(x) for x in key.split(":"))
            good_b: list[float] = []
            for r in wr:
                if r["block"] == b and r["attempt"] == a:
                    good, bad = split_items(r["latMs"], r["outcomes"], r.get("expected", "accepted"))
                    good_b.extend(good)
                    bad_all.extend(bad)
            groups.append(np.array(good_b, dtype=float))
            lat_all.extend(good_b)
        for r in wr:
            n += len(r["outcomes"])
            posts += r["rpc"]["posts"]
            requests += r["rpc"]["requests"]
        errs = len(bad_all)
        tp_err += errs
        tp_n += n
        rates = {f'{p["block"]}:{p["attempt"]}': p.get("steadyPerSec") for p in passes if p["cell"] == cid}
        rates = {k: v for k, v in rates.items() if v is not None}
        rate_by[(variant, W, c)] = rates
        rv = np.array(list(rates.values()), dtype=float)
        x = np.array(lat_all, dtype=float)
        out["cells"].append(
            {
                "cell": cid,
                "variant": variant,
                "W": W,
                "c": c,
                "inFlightTotal": W * c,
                "latencyMs": describe(x),
                "latencyCi95": {q: cluster_ci(groups, qq, f"{cid}:{q}", B, seed) for q, qq in (("median", 0.5), ("p95", 0.95), ("p99", 0.99))},
                "steadyRatePerSec": {"blocks": int(rv.size), "median": float(np.median(rv)) if rv.size else None, "ci95": median_ci(rv, f"{cid}:rate", B, seed)},
                "rpcPerVerification": {"posts": posts / n if n else None, "requests": requests / n if n else None},
                "errors": error_rate(errs, n),
                "errorItems": error_items(bad_all),
            }
        )
    for variant, W, c in cells:
        if W == 1:
            continue
        base = rate_by.get((variant, 1, c), {})
        cur = rate_by.get((variant, W, c), {})
        keys = [k for k in block_keys if k in base and k in cur]
        num = np.array([cur[k] for k in keys], dtype=float)
        den = np.array([base[k] for k in keys], dtype=float)
        sp = float(np.median(num) / np.median(den)) if keys else None
        out["scaling"].append(
            {
                "variant": variant,
                "c": c,
                "W": W,
                "pairedBlocks": len(keys),
                "speedup": sp,
                "speedupCi95": paired_ratio_ci(num, den, f"scale:{variant}:c{c}:W{W}", B, seed),
                "efficiency": sp / W if sp is not None else None,
                "note": "per-worker bn128 thread pools on unpinned cores: not clean multi-core scaling",
            }
        )
    out["errorsThroughputCells"] = error_rate(tp_err, tp_n)

    # ---- hostile-input cost (latency from items with the class's expected outcome)
    hrows = [r for r in hostile if used(r)]
    hc0_err = hc0_n = 0
    for variant in sorted({r["variant"] for r in hrows}):
        per_block_med: dict[str, dict[str, float]] = {}
        for cls in sorted({r["cls"] for r in hrows if r["variant"] == variant}):
            rs = [r for r in hrows if r["variant"] == variant and r["cls"] == cls]
            expected = next((r["expected"] for r in rs if r.get("expected")), EXPECTED_DEFAULT.get(cls, "?"))
            groups = []
            bad_all: list[tuple[str, float]] = []
            for k in block_keys:
                good_k: list[float] = []
                for r in rs:
                    if f'{r["block"]}:{r["attempt"]}' == k:
                        good, bad = split_items(r["latMs"], r["outcomes"], r.get("expected", expected))
                        good_k.extend(good)
                        bad_all.extend(bad)
                groups.append(np.array(good_k, dtype=float))
            per_block_med[cls] = {k: float(np.median(g)) for k, g in zip(block_keys, groups) if g.size}
            allx = np.concatenate([g for g in groups if g.size]) if any(g.size for g in groups) else np.array([])
            items = sum(len(r["outcomes"]) for r in rs)
            accepted = sum(1 for r in rs for o in r["outcomes"] if o == "accepted")
            outcomes: dict[str, int] = {}
            for r in rs:
                for o in r["outcomes"]:
                    outcomes[o] = outcomes.get(o, 0) + 1
            if cls == "HC0":
                hc0_err += len(bad_all)
                hc0_n += items
            row = {
                "variant": variant,
                "cls": cls,
                "expectedOutcome": expected,
                "latencyMs": describe(allx),
                "medianCi95": cluster_ci(groups, 0.5, f"hc:{variant}:{cls}:median", B, seed),
                "rpcPerItem": {"posts": sum(r["rpc"]["posts"] for r in rs) / items if items else None, "requests": sum(r["rpc"]["requests"] for r in rs) / items if items else None},
                "outcomes": outcomes,
                "unexpectedOutcomes": len(bad_all),
                "errorItems": error_items(bad_all),
                "acceptedHostile": accepted if cls != "HC0" else None,
            }
            out["hostile"].append(row)
        ref = per_block_med.get("HC0", {})
        for row in out["hostile"]:
            if row["variant"] != variant or row["cls"] == "HC0":
                continue
            cur = per_block_med.get(row["cls"], {})
            keys = [k for k in block_keys if k in ref and k in cur]
            num = np.array([cur[k] for k in keys], dtype=float)
            den = np.array([ref[k] for k in keys], dtype=float)
            row["amplificationVsHC0"] = {
                "definition": "median over blocks of the class's per-block median latency, divided by the same for HC0 (paired block bootstrap)",
                "ratioOfMedians": float(np.median(num) / np.median(den)) if keys else None,
                "ci95": paired_ratio_ci(num, den, f"amp:{variant}:{row['cls']}", B, seed),
                "pairedBlocks": len(keys),
            }

    # ---- correctness under load
    crows = [r for r in corr if used(r)]
    groups_total = sum(len(r["metrics"]["acceptedCopiesPerDuplicateGroup"]) for r in crows)
    groups_ok = sum(1 for r in crows for g in r["metrics"]["acceptedCopiesPerDuplicateGroup"] if g == 1)
    out["correctness"] = {
        "batches": len(crows),
        "items": sum(r["items"] for r in crows),
        "duplicateGroups": groups_total,
        "duplicateGroupsWithExactlyOneAccepted": groups_ok,
        "misclassifiedItems": sum(r["metrics"]["misclassifiedItems"] for r in crows),
        "sessionsChecked": sum(r["metrics"].get("sessionsChecked", 0) for r in crows),
        "sessionsConsumedByRejectedReplies": sum(r["metrics"]["sessionsConsumedByRejectedReplies"] for r in crows),
        "honestAfterHostileAccepted": sum(r["metrics"]["honestAfterHostileAccepted"] for r in crows),
        "honestAfterHostileTotal": sum(r["metrics"]["honestAfterHostileTotal"] for r in crows),
    }
    c = out["correctness"]
    c["meetsRequired"] = c["batches"] > 0 and groups_ok == groups_total and c["misclassifiedItems"] == 0 and c["sessionsConsumedByRejectedReplies"] == 0 and c["honestAfterHostileAccepted"] == c["honestAfterHostileTotal"]
    # honest items of the correctness batch (expected "accepted" in phase A, and every phase-B item)
    corr_err = corr_n = 0
    for r in crows:
        for e, o in zip(r.get("expectA", []), r.get("outcomesA", [])):
            if e == "accepted":
                corr_n += 1
                corr_err += o != "accepted"
        corr_n += len(r.get("outcomesB", []))
        corr_err += sum(1 for o in r.get("outcomesB", []) if o != "accepted")
    out["errorsAllHonest"] = {
        **error_rate(tp_err + hc0_err + corr_err, tp_n + hc0_n + corr_n),
        "parts": {"throughputCells": [tp_err, tp_n], "hostileHC0": [hc0_err, hc0_n], "correctnessHonest": [corr_err, corr_n]},
        "note": "honest replies not accepted (rejections, exceptions, timeouts) over every honest reply sent in measured ok blocks; duplicate copies excluded",
    }

    # ---- aux and saturation
    first: dict = {}
    if aux_file:
        first = aux_file.get("firstVerificationInWorker", {})
    else:
        for r in runs:
            if r.get("type") == "worker" and r.get("firstVerificationInWorker"):
                first[str(r["worker"])] = r["firstVerificationInWorker"]
    out["aux"] = {
        "firstVerificationInWorker": first,
        "replacements": (aux_file or {}).get("replacements", []),
        "note": "one value per worker (one honest reply outside the correctness batch, asShipped, c = 1, workers one at a time before the settle); recorded, not analysed as a series, not compared with Phase D cold",
    }
    out["saturation"] = sat
    return out


def fmt(x, nd=1) -> str:
    if x is None:
        return "n/a"
    if isinstance(x, (int,)) and not isinstance(x, bool):
        return str(x)
    return f"{x:.{nd}f}"


def sig3(x) -> str:
    """Three significant figures (ratios far below 1 stay readable)."""
    return "n/a" if x is None else f"{x:.3g}"


def ci(c) -> str:
    return f"[{c[0]:.1f}, {c[1]:.1f}]" if c else "n/a"


def markdown(s: dict) -> str:
    L = [f"# Verifier library under concurrent load: campaign {s['campaign']}" + (" (smoke: never quoted)" if s.get("smoke") else ""), ""]
    L.append("Generated by scripts/robustness/analyze_load.py from results written by harness/v4/robustness/load.ts. Protocol: docs/v4/ROBUSTNESS.md section 3. Labels: [M] measured, dev key, loopback, same host, one local Anvil, library-level calls (no HTTP front end), per-worker session stores.")
    L.append("")
    b = s["blocks"]
    L.append(
        f"Blocks: {json.dumps(b['byStatus'])}; measured blocks analysed: {b['measuredOk']} (flagged busy: {b['measuredOkFlaggedBusy']}); "
        f"discarded for a clock gap: {b.get('discardedClockGap', 0)}; worker replacements: {b.get('replacementWarmups', 0)} warm-up passes (not analysed)."
    )
    L.append("")
    L.append("cachedReads uses a harness read cache (variant, not shipped). Its numbers are never verifier capacity.")
    L.append("")
    L.append("Latency columns use only items with the expected outcome; other items are counted as errors and listed as error items in summary.json. POSTs per verification at c > 1 include ethers JSON-RPC batching across concurrent verifications in one worker.")
    L.append("")
    L.append("| Cell | In flight | n | Median ms [95% CI] | p95 ms | p99 ms | Steady rate /s [95% CI] | POSTs / verif. | Requests / verif. | Errors (CP 95%) |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for c in s["cells"]:
        d = c["latencyMs"]
        e = c["errors"]
        cp = e["clopperPearson95"]
        L.append(
            f"| {c['cell']} | {c['inFlightTotal']} | {d.get('n', 0)} | {fmt(d.get('median'))} {ci(c['latencyCi95']['median'])} | {fmt(d.get('p95'))} | {fmt(d.get('p99'))} | "
            f"{fmt(c['steadyRatePerSec']['median'], 2)} {ci(c['steadyRatePerSec']['ci95'])} | {fmt(c['rpcPerVerification']['posts'], 2)} | {fmt(c['rpcPerVerification']['requests'], 2)} | "
            f"{e['errors']}/{e['attempts']} ({'n/a' if not cp else f'{cp[0]:.4f} to {cp[1]:.4f}'}) |"
        )
    L.append("")
    et = s.get("errorsThroughputCells") or {}
    ea = s.get("errorsAllHonest") or {}
    L.append(f"Errors in the throughput cells: {et.get('errors')}/{et.get('attempts')}; over every honest reply (throughput, HC0, correctness batch): {ea.get('errors')}/{ea.get('attempts')}.")
    L.append("")
    if s["scaling"]:
        L.append("| Scaling | W | Speedup vs W=1 [95% CI] | Efficiency |")
        L.append("|---|---|---|---|")
        for r in s["scaling"]:
            sc = r["speedupCi95"]
            L.append(f"| {r['variant']} c={r['c']} | {r['W']} | {fmt(r['speedup'], 2)} {('[%.2f, %.2f]' % tuple(sc)) if sc else 'n/a'} | {fmt(r['efficiency'], 2)} |")
        L.append("")
        L.append("Speedup mixes per-worker bn128 thread pools on unpinned hybrid cores; it is not clean multi-core scaling.")
        L.append("")
    L.append("| Hostile class | Variant | Expected | n | Median ms [95% CI] | p95 ms | POSTs / item | Amplification vs HC0 [95% CI] | Unexpected outcomes | Hostile accepted |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in s["hostile"]:
        a = r.get("amplificationVsHC0") or {}
        aci = a.get("ci95")
        L.append(
            f"| {r['cls']} | {r['variant']} | {r.get('expectedOutcome', '')} | {r['latencyMs'].get('n', 0)} | {fmt(r['latencyMs'].get('median'), 2)} {ci(r['medianCi95'])} | {fmt(r['latencyMs'].get('p95'), 2)} | {fmt(r['rpcPerItem']['posts'], 2)} | "
            f"{sig3(a.get('ratioOfMedians')) if a else ''} {('[%s, %s]' % (sig3(aci[0]), sig3(aci[1]))) if aci else ''} | {r.get('unexpectedOutcomes', 0)} | {'' if r['acceptedHostile'] is None else r['acceptedHostile']} |"
        )
    L.append("")
    L.append("Amplification is the median over blocks of the class's per-block median latency divided by the same for HC0.")
    L.append("")
    c = s["correctness"]
    L.append(
        f"Correctness under load: {c['batches']} batches, {c['items']} items; duplicate groups with exactly one accepted copy {c['duplicateGroupsWithExactlyOneAccepted']}/{c['duplicateGroups']}; "
        f"misclassified items {c['misclassifiedItems']} (required 0); sessions named by rejected replies that were consumed {c['sessionsConsumedByRejectedReplies']} of {c.get('sessionsChecked', 'n/a')} checked (required 0); "
        f"honest reply accepted after hostile replies on its session {c['honestAfterHostileAccepted']}/{c['honestAfterHostileTotal']}. Meets the required values: {'yes' if c['meetsRequired'] else 'NO'}."
    )
    L.append("")
    sat = s.get("saturation")
    if sat:
        status = sat.get("status", "ok")
        if "opened" not in sat:
            L.append(f"Saturation (n = 1): status {status}; not timed.")
        else:
            L.append(
                f"Saturation (n = 1, single run, status {status}): cap {sat['cap']}{' (package default)' if sat.get('capIsPackageDefault') else ' (smoke cap, not the package default)'}; {sat['opened']} sessions opened in {sat['fillMs']} ms; "
                f"at the cap: '{sat['exceptionAtCap']}'; a session opened before saturation was {'accepted' if sat['sessionOpenedBeforeSaturation']['accepted'] else 'NOT accepted'} while the store was full; "
                f"after the TTL: {sat['openAfterTtl']}. Heap per session about {sat['memory']['heapUsedBytesPerSession']} bytes (approximate)."
            )
        L.append("")
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--campaign")
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--B", type=int, default=B_DEFAULT)
    ap.add_argument("--seed", type=int, default=SEED_DEFAULT)
    a = ap.parse_args()
    held = [m for m in MARKERS if m.exists()]
    if held:
        print(f"refusing: {', '.join(m.relative_to(REPO).as_posix() for m in held)} exists (no analyses while a timed series or heavy work runs)", file=sys.stderr)
        return 3
    campaign = a.campaign or ("smoke" if a.smoke else None)
    if not campaign:
        print("--campaign is required", file=sys.stderr)
        return 2
    root = (ROOT / "_smoke" if a.smoke else ROOT) / "load" / campaign
    if not (root / "schedule.json").exists():
        print(f"no load campaign at {root.relative_to(REPO).as_posix()}", file=sys.stderr)
        return 2
    s = analyse(root, a.B, a.seed)
    (root / "summary.json").write_text(json.dumps(s, indent=2) + "\n", encoding="utf-8", newline="\n")
    (root / "summary.md").write_text(markdown(s), encoding="utf-8", newline="\n")
    print(f"wrote {(root / 'summary.md').relative_to(REPO).as_posix()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
