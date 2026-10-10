#!/usr/bin/env python3
"""Phase D analysis (docs/v4/BENCH_PROTOCOL.md, "Statistics"). numpy only.

Reads every campaign under the bench root (<root>/<campaign>/runs.jsonl, env.json,
schedule.json) and writes <root>/summary.json and <root>/summary.md:

  - per condition (mode x version x prover) and phase (witness, prove, verify, wp =
    witness + prove): n, median, Q1, Q3, IQR (type-7 quantiles = numpy "linear"), min, max;
  - every ratio with a percentile bootstrap 95% CI (B = 10,000, fixed seed, each condition
    resampled independently at its own n, statistic = ratio of medians):
      prover speedup  snarkjs / rapidsnark        per mode, version; phases prove, wp
      version         v4 / v2 and v4 / v3         per mode, prover; every phase
      cold / warm                                 per version, prover; every phase
    A ratio whose condition is blocked (rapidsnark, D-002) or has no data is listed with
    that status and no number.

Rows used: cold campaigns, every record with status "ok"; warm campaigns, status "ok",
not warm-up, from the latest complete session. Discarded (battery) and error records are
counted, never analysed.

Usage:
  python scripts/bench/analyze.py            # results/v4/bench
  python scripts/bench/analyze.py --smoke    # results/v4/bench/_tmp (smoke test only)
Refuses to run while <root>/RUNNING exists (a timed run is active), unless --force.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import zlib
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
BENCH = REPO / "results" / "v4" / "bench"
PHASES = ["witness", "prove", "verify", "wp"]
PHASE_KEY = {"witness": "witnessMs", "prove": "proveMs", "verify": "verifyMs", "wp": "wpMs"}
MODES = ["cold", "warm"]
VERSIONS = ["v2", "v3", "v4"]
PROVERS = ["snarkjs", "rapidsnark"]
B_DEFAULT = 10_000
SEED_DEFAULT = 20260927
QUANTILE_METHOD = "linear"  # Hyndman-Fan type 7


def rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return p.name


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


def describe(x: np.ndarray) -> dict:
    q1, med, q3 = np.percentile(x, [25, 50, 75], method=QUANTILE_METHOD)
    return {
        "n": int(x.size),
        "median": float(med),
        "q1": float(q1),
        "q3": float(q3),
        "iqr": float(q3 - q1),
        "min": float(x.min()),
        "max": float(x.max()),
    }


def boot_ratio(a: np.ndarray, b: np.ndarray, B: int, seed: int, rid: str) -> tuple[float, float]:
    """Percentile bootstrap 95% CI of median(a) / median(b); a and b resampled independently."""
    rng = np.random.default_rng([seed, zlib.crc32(rid.encode("utf-8"))])
    ia = rng.integers(0, a.size, size=(B, a.size))
    ib = rng.integers(0, b.size, size=(B, b.size))
    r = np.median(a[ia], axis=1) / np.median(b[ib], axis=1)
    lo, hi = np.percentile(r, [2.5, 97.5], method=QUANTILE_METHOD)
    return float(lo), float(hi)


def load_campaigns(root: Path) -> tuple[dict, dict, list]:
    """-> data[(mode, version, prover)] = {phase: array, campaign, keyLabel}, blocked, bookkeeping."""
    data: dict = {}
    blocked: dict = {}
    books = []
    for d in sorted(p for p in root.iterdir() if p.is_dir() and (p / "runs.jsonl").exists()):
        env = json.loads((d / "env.json").read_text(encoding="utf-8"))
        mode = env["mode"]
        recs = read_jsonl(d / "runs.jsonl")
        runs = [r for r in recs if r.get("type") == "run"]
        session_note = None
        if mode == "warm":
            complete = [r["session"] for r in recs if r.get("type") == "session-end" and r.get("complete")]
            sessions = sorted({r["session"] for r in runs})
            chosen = complete[-1] if complete else (sessions[-1] if sessions else None)
            session_note = {"used": chosen, "complete": bool(complete), "sessions": len(sessions)}
            used = [r for r in runs if r["session"] == chosen and r["status"] == "ok" and not r.get("warmup")]
        else:
            used = [r for r in runs if r["status"] == "ok"]
        books.append(
            {
                "campaign": d.name,
                "mode": mode,
                "label": env.get("label"),
                "protocolSha256": env.get("protocolSha256"),
                "recordsOk": sum(1 for r in runs if r["status"] == "ok" and not r.get("warmup")),
                "recordsUsed": len(used),
                "discardedBattery": sum(1 for r in runs if r["status"] == "discarded-battery"),
                "errors": sum(1 for r in runs if r["status"] == "error"),
                "usedNotQuiesced": sum(1 for r in used if not (r.get("quiesce") or {}).get("quiesced", True)),
                "complete": any(r.get("type") in ("campaign-end", "session-end") and r.get("complete") for r in recs),
                "warmSession": session_note,
                "env": (env.get("sessions") or [{}])[0].get("env"),
                "artifacts": env.get("artifacts"),
                "inputs": env.get("inputs"),
            }
        )
        for b in env.get("blocked", []):
            v, p = b["condition"].split("/")
            blocked[(mode, v, p)] = b["reason"]
        groups: dict = {}
        for r in used:
            groups.setdefault((mode, r["version"], r["prover"]), []).append(r)
        for key, rows in groups.items():
            if key in data:
                raise SystemExit(f"condition {key} appears in two campaigns ({data[key]['campaign']}, {d.name}); analyse them separately")
            e0 = (env.get("sessions") or [{}])[0].get("env") or {}
            data[key] = {
                "campaign": d.name,
                "os": f"{e0.get('platform')} {e0.get('osBuild')}",
                "keyLabel": rows[0].get("keyLabel"),
                **{ph: np.array([float(r["timings"][PHASE_KEY[ph]]) for r in rows]) for ph in PHASES},
            }
    return data, blocked, books


def ratio_specs() -> list[dict]:
    specs = []
    for mode in MODES:
        for v in VERSIONS:
            for ph in ["prove", "wp"]:
                specs.append({"id": f"speedup/{mode}/{v}/{ph}", "kind": "prover speedup snarkjs/rapidsnark",
                              "num": (mode, v, "snarkjs"), "den": (mode, v, "rapidsnark"), "phase": ph})
    for mode in MODES:
        for p in PROVERS:
            for base in ["v2", "v3"]:
                for ph in PHASES:
                    specs.append({"id": f"version/{mode}/{p}/v4_over_{base}/{ph}", "kind": f"v4/{base}",
                                  "num": (mode, "v4", p), "den": (mode, base, p), "phase": ph})
    for v in VERSIONS:
        for p in PROVERS:
            for ph in PHASES:
                specs.append({"id": f"coldwarm/{v}/{p}/{ph}", "kind": "cold/warm",
                              "num": ("cold", v, p), "den": ("warm", v, p), "phase": ph})
    return specs


def cond_name(k: tuple) -> str:
    return f"{k[0]}/{k[1]}/{k[2]}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--smoke", action="store_true", help="analyse results/v4/bench/_tmp (smoke test)")
    ap.add_argument("--root", type=Path, default=None)
    ap.add_argument("--B", type=int, default=B_DEFAULT)
    ap.add_argument("--seed", type=int, default=SEED_DEFAULT)
    ap.add_argument("--force", action="store_true", help="run even if RUNNING exists")
    a = ap.parse_args()
    root = a.root or (BENCH / "_tmp" if a.smoke else BENCH)
    if not root.exists():
        print(f"[analyze] {rel(root)} does not exist", file=sys.stderr)
        return 1
    if (root / "RUNNING").exists() and not a.force:
        print(f"[analyze] {rel(root / 'RUNNING')} exists: a timed run is active; no analyses now (docs/BENCHMARK_POLICY.md)", file=sys.stderr)
        return 2

    data, blocked, books = load_campaigns(root)

    conditions = []
    for key in sorted(data):
        row = data[key]
        conditions.append({
            "condition": cond_name(key), "mode": key[0], "version": key[1], "prover": key[2],
            "campaign": row["campaign"], "os": row["os"], "keyLabel": row["keyLabel"],
            "phases": {ph: describe(row[ph]) for ph in PHASES},
        })

    ratios = []
    for s in ratio_specs():
        num, den, ph = s["num"], s["den"], s["phase"]
        entry = {"id": s["id"], "kind": s["kind"], "phase": ph, "numerator": cond_name(num), "denominator": cond_name(den)}
        missing = [k for k in (num, den) if k not in data]
        if missing:
            reasons = [blocked[k] for k in missing if k in blocked]
            entry["status"] = reasons[0] if reasons else "no data: " + ", ".join(cond_name(k) for k in missing)
            ratios.append(entry)
            continue
        if data[num]["os"] != data[den]["os"]:
            entry["status"] = f"not comparable: different OS ({data[num]['os']} vs {data[den]['os']})"
            ratios.append(entry)
            continue
        x, y = data[num][ph], data[den][ph]
        lo, hi = boot_ratio(x, y, a.B, a.seed, s["id"])
        entry.update({
            "status": "ok",
            "ratioOfMedians": float(np.median(x) / np.median(y)),
            "ci95": [lo, hi],
            "nNumerator": int(x.size),
            "nDenominator": int(y.size),
            "sameCampaign": data[num]["campaign"] == data[den]["campaign"],
        })
        ratios.append(entry)

    smoke = root.resolve() == (BENCH / "_tmp").resolve()
    out = {
        "schema": "pqid/v4-bench-summary/v1",
        "generatedUtc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "generator": "scripts/bench/analyze.py",
        "root": rel(root),
        "label": "SMOKE TEST: not a result (n tiny, machine not quiet)" if smoke else "[M] Phase D benchmark summary",
        "keyNote": "v4 uses the dev key (label 'dev key'); v2 and v3 use their committed keys",
        "statistics": {
            "quantiles": "type 7 (numpy percentile method='linear')",
            "ci": "percentile bootstrap 95%, statistic = median(numerator) / median(denominator), "
                  "each condition resampled independently with replacement at its own n",
            "B": a.B,
            "seed": a.seed,
            "perRatioStream": "numpy default_rng([seed, crc32(ratio id)])",
            "phases": {"witness": "witness generation", "prove": "proving", "verify": "verification",
                       "wp": "witness + proving, summed per run"},
        },
        "campaigns": books,
        "blocked": [{"condition": cond_name(k), "reason": r} for k, r in sorted(blocked.items())],
        "conditions": conditions,
        "ratios": ratios,
        "numpy": np.__version__,
    }
    (root / "summary.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8", newline="\n")

    # ---- summary.md (plain tables)
    L = [f"# Phase D benchmark summary ({out['label']})", "",
         f"- Generated {out['generatedUtc']} by scripts/bench/analyze.py from {rel(root)}/*/runs.jsonl.",
         f"- Quantiles: type 7. CIs: percentile bootstrap 95%, B = {a.B}, seed {a.seed}, ratio of medians.",
         "- v4 rows use the dev key. Times in ms.", ""]
    L += ["## Campaigns", "", "| campaign | mode | used | discarded (battery) | errors | used, not quiet | complete |", "|---|---|---|---|---|---|---|"]
    for b in books:
        L.append(f"| {b['campaign']} | {b['mode']} | {b['recordsUsed']} | {b['discardedBattery']} | {b['errors']} | {b['usedNotQuiesced']} | {b['complete']} |")
    if out["blocked"]:
        L += ["", "## Blocked conditions", ""]
        L += [f"- {x['condition']}: {x['reason']}" for x in out["blocked"]]
    L += ["", "## Conditions", "", "| condition | key | phase | n | median | Q1 | Q3 | IQR |", "|---|---|---|---|---|---|---|---|"]
    for c in conditions:
        for ph in PHASES:
            s = c["phases"][ph]
            L.append(f"| {c['condition']} | {c['keyLabel']} | {ph} | {s['n']} | {s['median']:.2f} | {s['q1']:.2f} | {s['q3']:.2f} | {s['iqr']:.2f} |")
    L += ["", "## Ratios", "", "| ratio | phase | numerator | denominator | ratio of medians | 95% CI | n (num, den) | same campaign |", "|---|---|---|---|---|---|---|---|"]
    for r in ratios:
        if r["status"] == "ok":
            L.append(f"| {r['kind']} | {r['phase']} | {r['numerator']} | {r['denominator']} | {r['ratioOfMedians']:.3f} | "
                     f"{r['ci95'][0]:.3f} to {r['ci95'][1]:.3f} | {r['nNumerator']}, {r['nDenominator']} | {r['sameCampaign']} |")
        else:
            L.append(f"| {r['kind']} | {r['phase']} | {r['numerator']} | {r['denominator']} | {r['status']} | | | |")
    (root / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8", newline="\n")
    n_ok = sum(1 for r in ratios if r["status"] == "ok")
    print(f"[analyze] {len(conditions)} conditions, {n_ok}/{len(ratios)} ratios with CIs -> {rel(root / 'summary.json')}, {rel(root / 'summary.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
