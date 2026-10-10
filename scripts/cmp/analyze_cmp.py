#!/usr/bin/env python3
"""Analysis of the comparable benchmark series (docs/v4/CMP.md, "Statistics"). numpy only.

Reads the cmp results root (results/v4/cmp, or results/v4/cmp/_smoke with --smoke):
  prove/<cold>     cold runs of v2, v2o2, v3, v4, eddsa (and the optional curve condition)
  prove/<warm>     warm blocks of the same circuits (latest complete session)
  wallet/<wallet>  cold wallet rebuilds at 10^5 and 10^6 credentials
(campaign names --cold, --warm, --wallet; default cold_cmp, warm_cmp, wallet_cmp) and writes
<root>/summary_cmp.json and <root>/summary_cmp.md:

  - every campaign folder under prove/ and wallet/ is listed; the analysis refuses when the root
    holds a campaign of the same kind that was not selected, unless --ignore names it (recorded);
  - per condition and phase: n, median, Q1, Q3, IQR (type 7), min, max, and a percentile
    bootstrap 95% CI of the median (B = 10,000, seed 20260927, one stream per id:
    numpy default_rng([seed, crc32(id)])); the condition notes of env.json (what the condition
    is, optimisation level, constraint count, key label);
  - pre-registered primary ratios (cold, snarkJS): v4/v2, v4/v3, v3/v2o2, v2/v2o2, v4/v2o2 and
    v4/eddsa on prove and wp, ratio of medians with the protocol's independent-resampling
    bootstrap (scripts/bench/analyze.py boot_ratio). A primary ratio gets a number only when the
    cold campaign ended complete and every circuit has n >= 30 (smoke: n >= 1); otherwise its
    status is "incomplete" and the summary label starts with PARTIAL. Published ids carry a
    "cmp/" prefix; bootstrapStreamId is the stream passed to boot_ratio (for v4/v2 and v4/v3 the
    analyze.py id, so those CIs equal what analyze.py gives on the same rows);
  - secondary (same completeness rule): the primary ratios with a block bootstrap (whole blocks
    resampled, keeping the pairing inside a block), and a sensitivity rerun without runs flagged
    hostPauseSuspected or not quiet (quiesce.quiesced, the Phase D guard.ts rule, as
    scripts/bench/analyze.py counts it; the stricter quiesce.ts verdict in quiesceDetail is
    counted, not used to exclude);
  - descriptive: every other circuit pair and phase, warm ratios, cold/warm per circuit, the curve
    share (curve condition median over each circuit's prove median, when the curve condition ran),
    the wallet phases and the wallet poseidonInit share;
  - every ratio entry carries the key labels of its numerator and denominator;
  - consistency (cross-campaign, never a result): new cold and warm medians of v2, v3 and v4 over
    the Phase D campaigns in results/v4/bench, and the earlier single values of v2 --O2, EdDSA and
    the wallet rebuild next to the new medians.

Usage:
  python scripts/cmp/analyze_cmp.py            # results/v4/cmp
  python scripts/cmp/analyze_cmp.py --smoke    # results/v4/cmp/_smoke (smoke test only)
  python scripts/cmp/analyze_cmp.py --cold cold_cmp2 --ignore cold_cmp
Refuses while results/v4/bench/RUNNING exists (a timed run is active, docs/BENCHMARK_POLICY.md), unless --force.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import zlib
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "scripts" / "bench"))
import analyze as A  # noqa: E402  (scripts/bench/analyze.py, unchanged)

CMP = REPO / "results" / "v4" / "cmp"
BENCH = REPO / "results" / "v4" / "bench"
RUNNING = BENCH / "RUNNING"
BUSY = REPO / "results" / "v4" / "BUSY"

CIRCUITS = ["v2", "v2o2", "v3", "v4", "eddsa"]
PROVE_PHASES = ["witness", "prove", "verify", "wp"]
WALLET_PHASES = ["poseidonInit", "issuance", "revocation", "rebuild", "total"]
KEY = {
    "witness": "witnessMs", "prove": "proveMs", "verify": "verifyMs", "wp": "wpMs", "curve": "curveMs",
    "poseidonInit": "poseidonInitMs", "issuance": "issuanceMs", "revocation": "revocationMs", "rebuild": "rebuildMs", "total": "totalMs",
}
PRIMARY_PAIRS = [("v4", "v2"), ("v4", "v3"), ("v3", "v2o2"), ("v2", "v2o2"), ("v4", "v2o2"), ("v4", "eddsa")]
PRIMARY_PHASES = ["prove", "wp"]
# the four circuit pairs not in the primary list (one orientation each); descriptive only
OTHER_PAIRS = [("v3", "v2"), ("v2", "eddsa"), ("v3", "eddsa"), ("v2o2", "eddsa")]
WALLETS = ["wallet1e5", "wallet1e6"]
# completeness rule of a real series (docs/v4/CMP.md): per condition, used runs (cold, wallet) or measured blocks (warm)
NEED_REAL = {"cold": 30, "warm": 30, "wallet": 10}
NEED_SMOKE = {"cold": 1, "warm": 1, "wallet": 1}
NO_KEY = "none (no key)"


def rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return p.name


def rng_for(seed: int, rid: str) -> np.random.Generator:
    return np.random.default_rng([seed, zlib.crc32(rid.encode("utf-8"))])


def median_ci(x: np.ndarray, B: int, seed: int, rid: str) -> list[float]:
    """Percentile bootstrap 95% CI of the median (resample with replacement at n)."""
    rng = rng_for(seed, rid)
    idx = rng.integers(0, x.size, size=(B, x.size))
    lo, hi = np.percentile(np.median(x[idx], axis=1), [2.5, 97.5], method=A.QUANTILE_METHOD)
    return [float(lo), float(hi)]


def block_boot_ratio(pairs: np.ndarray, B: int, seed: int, rid: str) -> list[float]:
    """pairs: shape (blocks, 2) = (numerator, denominator) of the same block; whole blocks resampled."""
    rng = rng_for(seed, rid)
    idx = rng.integers(0, pairs.shape[0], size=(B, pairs.shape[0]))
    r = np.median(pairs[idx, 0], axis=1) / np.median(pairs[idx, 1], axis=1)
    lo, hi = np.percentile(r, [2.5, 97.5], method=A.QUANTILE_METHOD)
    return [float(lo), float(hi)]


def stats(x: np.ndarray, B: int, seed: int, rid: str) -> dict:
    d = A.describe(x)
    d["medianCi95"] = median_ci(x, B, seed, rid)
    return d


# ------------------------------------------------------------------ campaigns

def campaign_kind(sub: str, env: dict | None) -> str:
    if env is None:
        return "unknown"
    if sub == "wallet" or env.get("kind") == "wallet":
        return "wallet"
    return str(env.get("mode") or "unknown")


def discover(root: Path) -> list[dict]:
    """Every campaign folder under prove/ and wallet/ with its kind (cold, warm, wallet, unknown)."""
    out = []
    for sub in ("prove", "wallet"):
        d = root / sub
        if not d.is_dir():
            continue
        for c in sorted(p for p in d.iterdir() if p.is_dir()):
            envf, runsf = c / "env.json", c / "runs.jsonl"
            if not envf.exists() and not runsf.exists():
                out.append({"campaign": c.name, "path": rel(c), "kind": None, "note": "no env.json and no runs.jsonl (not a campaign)"})
                continue
            try:
                env = json.loads(envf.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                env = None
            out.append({"campaign": c.name, "path": rel(c), "folder": sub, "kind": campaign_kind(sub, env)})
    return out


def load(dirpath: Path, need: int) -> dict | None:
    """One campaign: env, the analysed rows and bookkeeping (None when absent)."""
    if not (dirpath / "runs.jsonl").exists():
        return None
    env = json.loads((dirpath / "env.json").read_text(encoding="utf-8"))
    recs = A.read_jsonl(dirpath / "runs.jsonl")
    runs = [r for r in recs if r.get("type") == "run"]
    mode = env["mode"]
    note = None
    if mode == "warm":
        complete = [r["session"] for r in recs if r.get("type") == "session-end" and r.get("complete")]
        sessions = sorted({r["session"] for r in runs})
        chosen = complete[-1] if complete else (sessions[-1] if sessions else None)
        note = {"used": chosen, "complete": bool(complete), "sessions": len(sessions)}
        used = [r for r in runs if r["session"] == chosen and r["status"] == "ok" and not r.get("warmup")]
        ended = bool(complete)
    else:
        used = [r for r in runs if r["status"] == "ok"]
        ended = any(r.get("type") == "campaign-end" and r.get("complete") for r in recs)
    configured = sorted((env.get("keyLabels") or {}).keys())
    per = {v: sum(1 for r in used if r["version"] == v) for v in configured}
    short = {v: k for v, k in per.items() if k < need}
    gaps = [r["clockGapSec"] for r in used if isinstance(r.get("clockGapSec"), (int, float))]
    ticks = [r["idleMaxTickGapSec"] for r in used if isinstance(r.get("idleMaxTickGapSec"), (int, float))]
    book = {
        "campaign": dirpath.name,
        "path": rel(dirpath),
        "mode": mode,
        "kind": env.get("kind"),
        "label": env.get("label"),
        "protocolSha256": env.get("protocolSha256"),
        "cmpProtocolSha256": env.get("cmpProtocolSha256"),
        "keyLabels": env.get("keyLabels"),
        "v4Key": env.get("v4Key"),
        "codeCommittedAtHead": [s.get("codeCommittedAtHead") for s in env.get("sessions", [])],
        "allowUncommitted": env.get("allowUncommitted"),
        "sessions": len(env.get("sessions", [])),
        "recordsUsed": len(used),
        "usedPerCondition": per,
        "discardedBattery": sum(1 for r in runs if r["status"] == "discarded-battery"),
        "errors": sum(1 for r in runs if r["status"] == "error"),
        "usedNotQuiesced": sum(1 for r in used if not (r.get("quiesce") or {}).get("quiesced", True)),
        "usedNotQuiescedStrict": sum(1 for r in used if not (r.get("quiesceDetail") or {}).get("quiesced", True)),
        "usedPostponed": sum(1 for r in used if (r.get("postponements") or 0) > 0),
        "usedHostPauseSuspected": sum(1 for r in used if r.get("hostPauseSuspected")),
        "clockGapSec": {"median": float(np.median(gaps)), "max": float(np.max(gaps))} if gaps else None,
        "idleMaxTickGapSec": {"median": float(np.median(ticks)), "max": float(np.max(ticks))} if ticks else None,
        "complete": ended,
        "required": {"campaignEnd": True, "nPerCondition": need},
        "completeForAnalysis": ended and bool(configured) and not short,
        "incompleteReason": None if (ended and configured and not short) else
            "; ".join(([] if ended else ["no complete campaign-end (or session-end)"]) + ([f"n below {need}: {short}"] if short else []) + ([] if configured else ["no configured conditions in env.json"])),
        "warmSession": note,
        "env": (env.get("sessions") or [{}])[0].get("env"),
    }
    return {"env": env, "used": used, "book": book}


def by_version(rows: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for r in rows:
        out.setdefault(r["version"], []).append(r)
    return out


def arr(rows: list[dict], phase: str) -> np.ndarray:
    return np.array([float(r["timings"][KEY[phase]]) for r in rows])


def clean(rows: list[dict]) -> list[dict]:
    return [r for r in rows if not r.get("hostPauseSuspected") and (r.get("quiesce") or {}).get("quiesced", True)]


def key_of(groups: dict, v: str) -> str | None:
    rows = groups.get(v)
    return rows[0].get("keyLabel") if rows else None


# ------------------------------------------------------------------ ratios

def pair_base(mode: str, num: str, den: str, phase: str) -> str:
    if mode in ("cold", "warm") and num == "v4" and den in ("v2", "v3"):
        return f"version/{mode}/snarkjs/v4_over_{den}/{phase}"  # the analyze.py id
    return f"{mode}/snarkjs/{num}_over_{den}/{phase}"


def pair_ids(mode: str, num: str, den: str, phase: str) -> tuple[str, str]:
    """(published id, bootstrap stream id). Published ids carry the cmp/ prefix so they never
    collide with results/v4/bench/summary.json; the stream of v4/v2 and v4/v3 is analyze.py's id."""
    base = pair_base(mode, num, den, phase)
    pid = f"cmp/{base}"
    return pid, (base if base.startswith("version/") else pid)


def ratio_entry(rid: str, x: np.ndarray, y: np.ndarray, B: int, seed: int, stream: str | None = None, **extra) -> dict:
    sid = stream or rid
    lo, hi = A.boot_ratio(x, y, B, seed, sid)
    return {"id": rid, "bootstrapStreamId": sid, "status": "ok", "ratioOfMedians": float(np.median(x) / np.median(y)), "ci95": [lo, hi],
            "nNumerator": int(x.size), "nDenominator": int(y.size), **extra}


def missing(rid: str, why: str, **extra) -> dict:
    return {"id": rid, "status": why, **extra}


def block_pairs(rows: list[dict], num: str, den: str, phase: str) -> np.ndarray:
    blocks: dict[int, dict[str, float]] = {}
    for r in rows:
        if r["version"] in (num, den):
            blocks.setdefault(int(r["block"]), {})[r["version"]] = float(r["timings"][KEY[phase]])
    pairs = [(b[num], b[den]) for _, b in sorted(blocks.items()) if num in b and den in b]
    return np.array(pairs, dtype=float).reshape(-1, 2)


# ------------------------------------------------------------------ consistency inputs

def jget(path: Path, *keys):
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        for k in keys:
            d = d[k]
        return d
    except (OSError, KeyError, TypeError, IndexError, ValueError):
        return None


def v4_label(cold: dict | None, warm: dict | None) -> str | None:
    labels = {}
    for name, c in (("cold", cold), ("warm", warm)):
        k = ((c or {}).get("env") or {}).get("v4Key") or {}
        if k.get("label"):
            labels[name] = k["label"]
    if not labels:
        return None
    if len(set(labels.values())) == 1:
        return next(iter(labels.values()))
    return ", ".join(f"{m} {lab}" for m, lab in labels.items())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--smoke", action="store_true", help="analyse results/v4/cmp/_smoke (smoke test)")
    ap.add_argument("--root", type=Path, default=None)
    ap.add_argument("--cold", default="cold_cmp", help="cold prove campaign under prove/ (default cold_cmp)")
    ap.add_argument("--warm", default="warm_cmp", help="warm campaign under prove/ (default warm_cmp)")
    ap.add_argument("--wallet", default="wallet_cmp", help="wallet campaign under wallet/ (default wallet_cmp)")
    ap.add_argument("--ignore", action="append", default=[], help="campaign folder(s) to leave out on purpose (comma list; recorded)")
    ap.add_argument("--B", type=int, default=A.B_DEFAULT)
    ap.add_argument("--seed", type=int, default=A.SEED_DEFAULT)
    ap.add_argument("--force", action="store_true", help="run even if results/v4/bench/RUNNING exists")
    a = ap.parse_args()
    root = a.root or (CMP / "_smoke" if a.smoke else CMP)
    smoke = a.smoke or root.resolve() == (CMP / "_smoke").resolve()
    if RUNNING.exists() and not a.force:
        print(f"[analyze_cmp] {rel(RUNNING)} exists: a timed run is active; no analyses now (docs/BENCHMARK_POLICY.md)", file=sys.stderr)
        return 2
    if BUSY.exists():
        print(f"[analyze_cmp] note: {rel(BUSY)} exists (untimed heavy work); the analysis itself is light", file=sys.stderr)
    if not root.exists():
        print(f"[analyze_cmp] {rel(root)} does not exist", file=sys.stderr)
        return 1
    B, seed = a.B, a.seed
    need = NEED_SMOKE if smoke else NEED_REAL
    ignore = sorted({x.strip() for item in a.ignore for x in item.split(",") if x.strip()})

    # ---- campaign selection: every folder listed; an unselected campaign of a selected kind refuses
    selected = {"cold": a.cold, "warm": a.warm, "wallet": a.wallet}
    found = discover(root)
    conflicts = []
    for f in found:
        k = f["kind"]
        if k is None:
            f["use"] = "not a campaign"
        elif k in selected and f["campaign"] == selected[k] and (f["folder"] == "wallet") == (k == "wallet"):
            f["use"] = "selected"
        elif f["campaign"] in ignore:
            f["use"] = "ignored (--ignore)"
        else:
            f["use"] = "not selected"
            conflicts.append(f)
    for k, name in selected.items():
        sub = "wallet" if k == "wallet" else "prove"
        hit = next((f for f in found if f.get("folder") == sub and f["campaign"] == name), None)
        if hit is not None and hit["kind"] != k:
            print(f"[analyze_cmp] --{k} {name}: {hit['path']} is a {hit['kind']} campaign, not {k}", file=sys.stderr)
            return 3
    if conflicts:
        names = ", ".join(f"{c['path']} ({c['kind']})" for c in conflicts)
        print(f"[analyze_cmp] the root holds campaign(s) that were not selected: {names}. Select one with --cold/--warm/--wallet "
              f"or leave it out on purpose with --ignore NAME (recorded); refusing so that no summary mixes up campaigns", file=sys.stderr)
        return 3

    cold = load(root / "prove" / a.cold, need["cold"])
    warm = load(root / "prove" / a.warm, need["warm"])
    wallet = load(root / "wallet" / a.wallet, need["wallet"])
    campaigns = [c["book"] for c in (cold, warm, wallet) if c]
    cold_v = by_version(cold["used"]) if cold else {}
    warm_v = by_version(warm["used"]) if warm else {}
    wal_v = by_version(wallet["used"]) if wallet else {}
    cold_ok = bool(cold and cold["book"]["completeForAnalysis"])
    partial = not all(c is not None and c["book"]["completeForAnalysis"] for c in (cold, warm, wallet))
    missing_campaigns = [f"{k} {selected[k]}" for k, c in (("cold", cold), ("warm", warm), ("wallet", wallet)) if c is None]

    notes: dict = {}
    for c in (cold, warm, wallet):
        if c:
            notes.update(c["env"].get("conditionNotes") or {})

    # ---- conditions
    conditions = []
    for mode, groups in (("cold", cold_v), ("warm", warm_v)):
        for v in CIRCUITS + ["curve"]:
            rows = groups.get(v)
            if not rows:
                continue
            phases = ["curve"] if v == "curve" else PROVE_PHASES
            conditions.append({
                "condition": f"{mode}/{v}/snarkjs", "mode": mode, "version": v, "keyLabel": rows[0].get("keyLabel"), "notes": notes.get(v),
                "phases": {ph: stats(arr(rows, ph), B, seed, f"median/{mode}/{v}/{ph}") for ph in phases},
            })
    for w in WALLETS:
        rows = wal_v.get(w)
        if not rows:
            continue
        size = (rows[0].get("results") or {}).get("size")
        lib = ((rows[0].get("aux") or {}).get("poseidonLib"))
        conditions.append({
            "condition": f"cold/{w}/node", "mode": "cold", "version": w, "keyLabel": None, "size": size, "notes": notes.get(w), "poseidonLib": lib,
            "phases": {ph: stats(arr(rows, ph), B, seed, f"median/cold/{w}/{ph}") for ph in WALLET_PHASES},
        })

    # ---- primary (pre-registered), block bootstrap, sensitivity
    primary, block, sens = [], [], []
    for num, den in PRIMARY_PAIRS:
        for ph in PRIMARY_PHASES:
            rid, stream = pair_ids("cold", num, den, ph)
            meta = {"numerator": f"cold/{num}/snarkjs", "denominator": f"cold/{den}/snarkjs", "numeratorKey": key_of(cold_v, num),
                    "denominatorKey": key_of(cold_v, den), "phase": ph, "preRegistered": True, "sameCampaign": True}
            if num not in cold_v or den not in cold_v:
                primary.append(missing(rid, "no data", bootstrapStreamId=stream, **meta))
                continue
            if not cold_ok:
                why = (cold["book"]["incompleteReason"] if cold else "no cold campaign")
                inc = {**meta, "nNumerator": len(cold_v[num]), "nDenominator": len(cold_v[den]), "reason": why}
                primary.append(missing(rid, "incomplete", bootstrapStreamId=stream, **inc))
                block.append(missing(f"cmp/block/{pair_base('cold', num, den, ph)}", "incomplete", **inc))
                sens.append(missing(f"cmp/sens/{pair_base('cold', num, den, ph)}", "incomplete", **inc))
                continue
            primary.append(ratio_entry(rid, arr(cold_v[num], ph), arr(cold_v[den], ph), B, seed, stream=stream, **meta))
            pairs = block_pairs(cold["used"], num, den, ph)
            bid = f"cmp/block/{pair_base('cold', num, den, ph)}"
            if pairs.shape[0] >= 1:
                block.append({"id": bid, "bootstrapStreamId": bid, "status": "ok", "ratioOfMedians": float(np.median(pairs[:, 0]) / np.median(pairs[:, 1])),
                              "ci95": block_boot_ratio(pairs, B, seed, bid), "blocks": int(pairs.shape[0]), **meta})
            cx, cy = clean(cold_v[num]), clean(cold_v[den])
            sid = f"cmp/sens/{pair_base('cold', num, den, ph)}"
            smeta = {**meta, "excluded": {"numerator": len(cold_v[num]) - len(cx), "denominator": len(cold_v[den]) - len(cy)},
                     "rule": "runs with hostPauseSuspected or quiesce.quiesced = false (Phase D guard.ts rule) left out"}
            if cx and cy:
                sens.append(ratio_entry(sid, arr(cx, ph), arr(cy, ph), B, seed, **smeta))
            else:
                sens.append(missing(sid, "no data after exclusion", **smeta))

    # ---- descriptive ratios: the other circuit pairs (cold), primary pairs on witness/verify (cold), every pair (warm)
    descriptive = []
    for mode, groups, plan in (
        ("cold", cold_v, [(p_, ("witness", "verify")) for p_ in PRIMARY_PAIRS] + [(p_, tuple(PROVE_PHASES)) for p_ in OTHER_PAIRS]),
        ("warm", warm_v, [(p_, tuple(PROVE_PHASES)) for p_ in PRIMARY_PAIRS + OTHER_PAIRS]),
    ):
        for (num, den), phases in plan:
            if num not in groups or den not in groups:
                continue
            for ph in phases:
                rid, stream = pair_ids(mode, num, den, ph)
                descriptive.append(ratio_entry(rid, arr(groups[num], ph), arr(groups[den], ph), B, seed, stream=stream,
                                               numerator=f"{mode}/{num}/snarkjs", denominator=f"{mode}/{den}/snarkjs",
                                               numeratorKey=key_of(groups, num), denominatorKey=key_of(groups, den), phase=ph, preRegistered=False))
    coldwarm = []
    for v in CIRCUITS:
        for ph in PROVE_PHASES:
            if v in cold_v and v in warm_v:
                coldwarm.append(ratio_entry(f"cmp/coldwarm/{v}/snarkjs/{ph}", arr(cold_v[v], ph), arr(warm_v[v], ph), B, seed,
                                            stream=f"coldwarm/{v}/snarkjs/{ph}",  # analyze.py's stream for the same pair
                                            numerator=f"cold/{v}/snarkjs", denominator=f"warm/{v}/snarkjs",
                                            numeratorKey=key_of(cold_v, v), denominatorKey=key_of(warm_v, v), phase=ph))
    curve_share = []
    if "curve" in cold_v:
        cv = arr(cold_v["curve"], "curve")
        for v in CIRCUITS:
            if v in cold_v:
                curve_share.append(ratio_entry(f"cmp/curveshare/cold/{v}", cv, arr(cold_v[v], "prove"), B, seed,
                                               numerator="cold/curve/snarkjs curve", denominator=f"cold/{v}/snarkjs prove",
                                               numeratorKey=NO_KEY, denominatorKey=key_of(cold_v, v),
                                               note="median of the separate curve condition over the circuit's prove median; descriptive, not a split of prove"))

    wallet_ratios = []
    for w in WALLETS:
        if w in wal_v:
            rows = wal_v[w]
            wallet_ratios.append(ratio_entry(f"cmp/wallet/{w}/poseidoninit_over_total", arr(rows, "poseidonInit"), arr(rows, "total"), B, seed,
                                             numerator=f"{w} poseidonInit", denominator=f"{w} total", numeratorKey=NO_KEY, denominatorKey=NO_KEY,
                                             note="share of the first Poseidon build (circomlibjs, single thread) in the cold rebuild (descriptive)"))
    if all(w in wal_v for w in WALLETS):
        for ph in ("issuance", "revocation", "rebuild", "total"):
            wallet_ratios.append(ratio_entry(f"cmp/wallet/1e6_over_1e5/{ph}", arr(wal_v["wallet1e6"], ph), arr(wal_v["wallet1e5"], ph), B, seed,
                                             numerator=f"wallet1e6 {ph}", denominator=f"wallet1e5 {ph}", numeratorKey=NO_KEY, denominatorKey=NO_KEY,
                                             note="scaling, descriptive"))

    # ---- consistency (cross-campaign; never a result)
    consistency: dict = {"label": "cross-campaign consistency check: different campaigns, dates and sessions; never cited as a result", "phaseD": [], "earlierValues": []}
    if BENCH.exists() and not smoke:
        try:
            old, _blocked, _books = A.load_campaigns(BENCH)
        except SystemExit as e:  # for example two Phase D campaigns with the same condition
            old = None
            consistency["phaseD"] = f"not computed: {e}"
        if old is not None:
            for mode, groups in (("cold", cold_v), ("warm", warm_v)):
                for v in ("v2", "v3", "v4"):
                    key = (mode, v, "snarkjs")
                    if v not in groups or key not in old:
                        continue
                    for ph in PROVE_PHASES:
                        consistency["phaseD"].append(ratio_entry(
                            f"cmp/consistency/{mode}/{v}/cmp_over_phaseD/{ph}", arr(groups[v], ph), old[key][ph], B, seed,
                            numerator=f"cmp {mode}/{v}", denominator=f"Phase D {mode}/{v} (campaign {old[key]['campaign']})",
                            numeratorKey=key_of(groups, v), denominatorKey=old[key]["keyLabel"], phase=ph, label="cross-campaign"))
    else:
        consistency["phaseD"] = "not computed (smoke run or no Phase D root)"
    o2 = REPO / "results" / "v3" / "compare_v2_v3.json"
    ez = REPO / "results" / "v4" / "baselines" / "measure.json"
    pv = REPO / "results" / "v4" / "privacy.json"

    def newmed(groups: dict, v: str, ph: str):
        return float(np.median(arr(groups[v], ph))) if v in groups else None

    for ph, k in (("witness", "witness"), ("prove", "prove")):
        consistency["earlierValues"].append({
            "what": f"v2 --O2 {ph} median (ms)", "earlier": jget(o2, "timing", "v2_O2", k, "medianMs"),
            "earlierSource": "results/v3/compare_v2_v3.json $.timing.v2_O2", "earlierMode": "warm, in-process, 15 rounds after 2 warm-up, newZKey key without contribution, 2026-09-26",
            "cmpColdMedian": newmed(cold_v, "v2o2", ph), "cmpWarmMedian": newmed(warm_v, "v2o2", ph)})
    for ph in ("witness", "prove", "verify"):
        consistency["earlierValues"].append({
            "what": f"EdDSA baseline {ph} median (ms)", "earlier": jget(ez, "eddsaZk", ph, "medianMs"),
            "earlierSource": "results/v4/baselines/measure.json $.eddsaZk", "earlierMode": "warm, in-process, n=10 after 2 warm-up, random issuer key and input",
            "cmpColdMedian": newmed(cold_v, "eddsa", ph), "cmpWarmMedian": newmed(warm_v, "eddsa", ph)})
    timing = jget(pv, "publishedTree", "timing") or []
    for w, n in (("wallet1e5", 100000), ("wallet1e6", 1000000)):
        row = next((t for t in timing if isinstance(t, dict) and t.get("credentials") == n), None)
        cmp_size = ((wal_v[w][0].get("results") or {}).get("size") or {}).get("credentials") if w in wal_v else None
        same_size = cmp_size == n
        consistency["earlierValues"].append({
            "what": f"wallet rebuild {n} credentials (ms)",
            "earlier": {"issuanceRebuildMs": row.get("issuanceRebuildMs"), "revocationRebuildMs": row.get("revocationRebuildMs")} if row else None,
            "earlierSource": "results/v4/privacy.json $.publishedTree.timing", "earlierMode": "single run, in-process, random leaves; the 10^5 issuance figure includes the first Poseidon build, the 10^6 figure does not (cached)",
            "cmpCredentials": cmp_size,
            "cmpColdMedian": {ph: newmed(wal_v, w, ph) for ph in WALLET_PHASES} if (w in wal_v and same_size) else None,
            **({} if same_size or cmp_size is None else {"note": f"cmp ran {cmp_size} credentials (smoke size): not shown"})})

    v4l = v4_label(cold, warm)
    base_label = "SMOKE TEST: not a result (n tiny, idle shortened, machine not quiet)" if smoke else "[M] comparable benchmark series (cmp)"
    label = ("PARTIAL " if partial else "") + base_label + (f", v4: {v4l}" if v4l else "")
    out = {
        "schema": "pqid/v4-cmp-summary/v1",
        "generatedUtc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "generator": "scripts/cmp/analyze_cmp.py",
        "root": rel(root),
        "label": label,
        "partial": partial,
        "partialReason": None if not partial else "; ".join(
            [f"missing campaign(s): {', '.join(missing_campaigns)}"] * bool(missing_campaigns)
            + [f"{b['campaign']}: {b['incompleteReason']}" for b in campaigns if not b["completeForAnalysis"]]),
        "completenessRule": {"nPerCondition": need, "campaignEnd": "complete campaign-end (cold, wallet) or session-end (warm)",
                             "primary": "a primary ratio gets a number only when the cold campaign meets the rule"},
        "v4Key": v4l,
        "protocol": "docs/v4/CMP.md (addendum to docs/v4/BENCH_PROTOCOL.md)",
        "selection": {"cold": a.cold, "warm": a.warm, "wallet": a.wallet, "ignored": ignore},
        "campaignFolders": found,
        "statistics": {
            "quantiles": "type 7 (numpy percentile method='linear')",
            "medianCi": "percentile bootstrap 95% of the median, resampled at n; stream median/<mode>/<condition>/<phase>",
            "ratioCi": "percentile bootstrap 95% of median(num)/median(den), each condition resampled independently (scripts/bench/analyze.py boot_ratio, stream bootstrapStreamId)",
            "blockCi": "percentile bootstrap 95%, whole blocks resampled (pairing inside a block kept)",
            "ids": "published ids start with cmp/ (never equal to an id of results/v4/bench/summary.json); bootstrapStreamId of v4/v2, v4/v3 and cold/warm is the analyze.py id",
            "B": B, "seed": seed, "perIdStream": "numpy default_rng([seed, crc32(stream id)])",
            "primary": [f"cold {n_}/{d_} on {', '.join(PRIMARY_PHASES)}" for n_, d_ in PRIMARY_PAIRS],
        },
        "campaigns": campaigns,
        "conditions": conditions,
        "ratios": {"primary": primary, "blockBootstrap": block, "sensitivity": sens, "descriptive": descriptive,
                   "coldOverWarm": coldwarm, "curveShare": curve_share, "wallet": wallet_ratios},
        "consistency": consistency,
        "numpy": np.__version__,
    }
    (root / "summary_cmp.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8", newline="\n")

    # ---- summary_cmp.md
    def f(x) -> str:
        return "-" if x is None else f"{x:.2f}"

    L = [f"# Comparable benchmark series ({out['label']})", "",
         f"- Generated {out['generatedUtc']} by scripts/cmp/analyze_cmp.py from {rel(root)}.",
         f"- Quantiles type 7; CIs percentile bootstrap 95%, B = {B}, seed {seed}. Times in ms.",
         f"- Campaigns: cold {a.cold}, warm {a.warm}, wallet {a.wallet}" + (f"; ignored on purpose: {', '.join(ignore)}" if ignore else "") + ".",
         f"- Completeness rule: complete campaign end and n >= {need['cold']} per circuit (cold, warm), n >= {need['wallet']} per wallet size."]
    if partial:
        L.append(f"- PARTIAL: {out['partialReason']}. Primary ratios without a complete cold campaign have no number.")
    L += ["", "## Campaigns", "",
          "- not quiet: the Phase D guard.ts rule (quiesce.quiesced); strict: the quiesce.ts rule (quiesceDetail.quiesced, also a foreign chain-port listener or a clock gap in the window).", "",
          "| campaign | mode | used | discarded (battery) | errors | not quiet | not quiet (strict) | postponed | host pause suspected | complete | meets the rule |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for b in campaigns:
        L.append(f"| {b['campaign']} | {b['mode']} | {b['recordsUsed']} | {b['discardedBattery']} | {b['errors']} | {b['usedNotQuiesced']} | {b['usedNotQuiescedStrict']} | {b['usedPostponed']} | {b['usedHostPauseSuspected']} | {b['complete']} | {b['completeForAnalysis']} |")
    L += ["", "| campaign folder | kind | use |", "|---|---|---|"]
    for c in found:
        L.append(f"| {c['path']} | {c['kind'] or '-'} | {c['use']} |")
    L += ["", "## Condition notes", "", "| condition | key | optimisation | constraints | note |", "|---|---|---|---|---|"]
    for v, nt in sorted(notes.items()):
        nc = f"{nt.get('nConstraints'):,}" if isinstance(nt.get("nConstraints"), int) else "-"
        L.append(f"| {v} | {nt.get('keyLabel') or '-'} | {nt.get('optimization') or '-'} | {nc} | {nt.get('note')} |")
    L += ["", "## Conditions", "", "| condition | key | phase | n | median | 95% CI of median | Q1 | Q3 | IQR |", "|---|---|---|---|---|---|---|---|---|"]
    for c in conditions:
        for ph, s in c["phases"].items():
            L.append(f"| {c['condition']} | {c['keyLabel'] or '-'} | {ph} | {s['n']} | {s['median']:.2f} | {s['medianCi95'][0]:.2f} to {s['medianCi95'][1]:.2f} | {s['q1']:.2f} | {s['q3']:.2f} | {s['iqr']:.2f} |")

    def rtable(title: str, rows: list[dict]) -> None:
        nonlocal L
        L += ["", f"## {title}", "", "| id | keys (numerator / denominator) | ratio of medians | 95% CI | n |", "|---|---|---|---|---|"]
        for r in rows:
            keys = f"{r.get('numeratorKey') or '-'} / {r.get('denominatorKey') or '-'}"
            if r.get("status") == "ok":
                n_ = f"{r['blocks']} blocks" if "blocks" in r else f"{r['nNumerator']}, {r['nDenominator']}"
                L.append(f"| {r['id']} | {keys} | {r['ratioOfMedians']:.3f} | {r['ci95'][0]:.3f} to {r['ci95'][1]:.3f} | {n_} |")
            else:
                n_ = f"{r['nNumerator']}, {r['nDenominator']}" if "nNumerator" in r else ""
                L.append(f"| {r['id']} | {keys} | {r['status']} | | {n_} |")

    rtable("Primary ratios (pre-registered, cold, snarkJS)", primary)
    rtable("Block bootstrap (secondary)", block)
    rtable("Sensitivity (secondary)", sens)
    rtable("Descriptive ratios", descriptive)
    rtable("Cold over warm (descriptive)", coldwarm)
    if curve_share:
        rtable("Curve share (descriptive)", curve_share)
    rtable("Wallet (descriptive)", wallet_ratios)
    L += ["", "## Consistency (cross-campaign, never a result)", ""]
    if isinstance(consistency["phaseD"], list):
        rtable("cmp over Phase D (cross-campaign)", consistency["phaseD"])
    else:
        L.append(f"- Phase D: {consistency['phaseD']}")
    L += ["", "| earlier value | earlier | source and mode | cmp cold median | cmp warm median |", "|---|---|---|---|---|"]
    for e in consistency["earlierValues"]:
        ev, cc, cw = e.get("earlier"), e.get("cmpColdMedian"), e.get("cmpWarmMedian")
        ev_s = json.dumps(ev) if isinstance(ev, dict) else f(ev)
        cc_s = json.dumps({k: round(v, 1) for k, v in cc.items() if v is not None}) if isinstance(cc, dict) else f(cc)
        L.append(f"| {e['what']} | {ev_s} | {e['earlierSource']}: {e['earlierMode']} | {cc_s} | {f(cw)} |")
    (root / "summary_cmp.md").write_text("\n".join(L) + "\n", encoding="utf-8", newline="\n")
    ok = sum(1 for r in primary if r["status"] == "ok")
    print(f"[analyze_cmp] {len(conditions)} conditions; {ok}/{len(primary)} primary ratios with CIs{' (PARTIAL)' if partial else ''} -> {rel(root / 'summary_cmp.json')}, {rel(root / 'summary_cmp.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
