#!/usr/bin/env python3
"""Analysis of the end-to-end presentation series (docs/v4/E2E.md, section 13).

Reads every campaign folder under the results root (default results/v4/e2e; --smoke reads
results/v4/e2e/_smoke) and writes summary.json and summary.md next to them.

- Rows: cold, "ok" records (one per slot: the last "ok" record of a slot if a slot has more);
  warm, "ok" records of measured blocks of the latest complete session, one per (session, slot).
  Error and discarded records (battery, pause, block error) are counted only, per campaign and
  per endpoint, with the error kinds.
- Groups: endpoint label x mode x instrumented/control x prover x key label. The same group in
  two campaigns is never pooled: it is kept apart under each campaign's name and listed in
  "notPooled". Sessions of one resumed campaign stay pooled.
- Per group and metric (endToEndMs, S1..S11, the S11 split, S7 + S8, the wallet part S2..S10,
  the verifier part S1 + S11, chain share, raw round trips, GC time): n, median, Q1, Q3, IQR
  (type 7), min, max, p95 and a percentile bootstrap 95 % CI of the median.
- Sensitivity per group: endToEndMs again without runs flagged hostPauseSuspected or
  quiesce.quiesced = false (docs/v4/CMP.md rule).
- New connections: endToEndMs, S3, S5 and S11 split by whether the run (or the stage) opened a
  new TCP or TLS connection (0 versus 1 or more), with n.
- Ratios of medians with percentile bootstrap CIs (B = 10,000, seed 20260927, one stream per
  ratio; describe() and boot_ratio() of scripts/bench/analyze.py), only between groups with the
  same prover and key label. The instrumentation overhead uses only warm blocks whose
  instrumented and control iterations opened the same connections.
- Round trips, requests and new connections per stage and party: modal value, every run that
  differs listed.

Refuses while results/v4/bench/RUNNING or results/v4/BUSY exists (a timed run or heavy work is
active), unless --force. Numbers are [M] from the runs files; ratios of separate campaigns carry
sameCampaign false.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import zlib
from collections import Counter
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts" / "bench"))
from analyze import B_DEFAULT, QUANTILE_METHOD, SEED_DEFAULT, boot_ratio, describe  # noqa: E402

STAGES = ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11"]
WALLET_PART = ["S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10"]
VERIFIER_PART = ["S1", "S11"]
SPLIT = ["chainMs", "mlDsaMs", "mlKemDecapsMs", "otherMs"]
CONN_STAGES = ["S3", "S5", "S11"]
STATUSES = ["ok", "error", "discarded-battery", "discarded-pause", "discarded-block-error"]
MARKERS = [REPO / "results" / "v4" / "bench" / "RUNNING", REPO / "results" / "v4" / "BUSY"]


def rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return p.name


def read_jsonl(path: Path) -> list[dict]:
    out = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def median_ci(x: np.ndarray, B: int, seed: int, rid: str) -> tuple[float, float]:
    """Percentile bootstrap 95 % CI of the median (one stream per id, as boot_ratio)."""
    rng = np.random.default_rng([seed, zlib.crc32(rid.encode("utf-8"))])
    idx = rng.integers(0, x.size, size=(B, x.size))
    m = np.median(x[idx], axis=1)
    lo, hi = np.percentile(m, [2.5, 97.5], method=QUANTILE_METHOD)
    return float(lo), float(hi)


def stats(x: np.ndarray, B: int, seed: int, rid: str) -> dict:
    d = describe(x)
    d["p95"] = float(np.percentile(x, 95, method=QUANTILE_METHOD))
    lo, hi = median_ci(x, B, seed, rid) if x.size > 1 else (float("nan"), float("nan"))
    d["medianCi95"] = [lo, hi]
    return d


def error_kind(rec: dict) -> str:
    """Where an error record failed: the child's errorKind (wallet, verifier, rpc, marks, cold-definition), else child, timeout or no-answer."""
    res = rec.get("result") or {}
    k = res.get("errorKind")
    if isinstance(k, str) and k:
        return k
    err = str(rec.get("error") or "")
    if "timed out" in err:
        return "timeout"
    if "no answer" in err:
        return "no-answer"
    return "child"


def run_http429(rec: dict) -> int:
    rep = (rec.get("result") or {}).get("report") or {}
    return int((rep.get("totals") or {}).get("http429") or 0)


def row_of(rec: dict) -> dict | None:
    res = rec.get("result") or {}
    if not isinstance(res.get("endToEndMs"), (int, float)):
        return None
    conns = res.get("connections") or {}
    row = {
        "campaign": rec["campaign"],
        "session": rec.get("session"),
        "slot": rec.get("slot"),
        "block": rec.get("block"),
        "endpoint": rec.get("endpoint"),
        "control": bool(rec.get("control")),
        "setupId": rec.get("setupId"),
        "labels": rec.get("labels", []),
        "endToEndMs": float(res["endToEndMs"]),
        "flagNotQuiesced": not (rec.get("quiesce") or {}).get("quiesced", True),
        "flagIdlePause": bool(rec.get("hostPauseSuspected", (rec.get("idle") or {}).get("hostPauseSuspected", False))),
        "clockGapSec": rec.get("clockGapSec", (rec.get("idle") or {}).get("clockGapSec")),
        "connections": {"verifier": int(conns.get("verifier", 0)), "wallet": int(conns.get("wallet", 0))} if conns else None,
        "partyIdleMsAtStart": (res.get("aux") or {}).get("partyIdleMsAtStart"),
        "stages": {},
        "posts": {},
        "requests": {},
        "connects": {},
        "split": {},
        "chainShare": None,
        "rtt": None,
        "gcMs": None,
        "gcMajor": None,
    }
    rep = res.get("report")
    if rep:
        for s in STAGES:
            st = rep["stages"][s]
            row["stages"][s] = float(st["ms"])
            row["posts"][s] = {"verifier": st["postsByParty"]["verifier"], "wallet": st["postsByParty"]["wallet"]}
            row["requests"][s] = int(st["requests"])
            row["connects"][s] = st.get("connects")
        row["split"] = {k: float(rep["verifySplit"][k]) for k in SPLIT}
        row["s7s8"] = float(rep.get("s7s8Ms", row["stages"]["S7"] + row["stages"]["S8"]))
        row["walletPart"] = float(sum(row["stages"][s] for s in WALLET_PART))
        row["verifierPart"] = float(sum(row["stages"][s] for s in VERIFIER_PART))
        chain = rep["totals"]["chainMsByParty"]["verifier"] + rep["totals"]["chainMsByParty"]["wallet"]
        row["chainShare"] = chain / row["endToEndMs"] if row["endToEndMs"] > 0 else None
        row["postsTotal"] = rep["totals"]["postsByParty"]
        row["requestsTotal"] = rep["totals"]["requestsByParty"]
        row["connectsTotal"] = rep["totals"].get("connectsByParty")
        gct = rep.get("gcTotals")
        if gct:
            row["gcMs"] = float(gct.get("ms", 0.0))
            row["gcMajor"] = int(gct.get("majorCount", 0))
    aux = res.get("aux") or {}
    rtt = (aux.get("rttProbe") or {}).get("blockNumberMs")
    if rtt:
        row["rtt"] = float(np.median(np.array(rtt, dtype=float)))
    return row


def last_per(records: list[dict], key) -> tuple[list[dict], int]:
    """Keep the last record per key (file order); returns the kept records and how many were dropped."""
    kept: dict = {}
    for r in records:
        kept[key(r)] = r
    out = list(kept.values())
    return out, len(records) - len(out)


def endpoint_counts(runs: list[dict]) -> dict:
    out: dict = {}
    for r in runs:
        ep = str(r.get("endpoint"))
        c = out.setdefault(ep, {**{s: 0 for s in STATUSES}, "errorKinds": {}, "http429": 0})
        st = r.get("status")
        if st in c:
            c[st] += 1
        if st == "error":
            k = error_kind(r)
            c["errorKinds"][k] = c["errorKinds"].get(k, 0) + 1
        c["http429"] += run_http429(r)
    for c in out.values():
        c["errorKinds"] = dict(sorted(c["errorKinds"].items()))
    return dict(sorted(out.items()))


def load(root: Path) -> tuple[list[dict], list[dict]]:
    rows: list[dict] = []
    books: list[dict] = []
    for d in sorted(p for p in root.iterdir() if p.is_dir() and (p / "runs.jsonl").exists() and (p / "env.json").exists()):
        env = json.loads((d / "env.json").read_text(encoding="utf-8"))
        mode = env["mode"]
        prover = str((((env.get("stable") or {}).get("prover")) or {}).get("name") or "snarkjs")
        key_label = str(env.get("keyLabel") or "unknown")
        recs = read_jsonl(d / "runs.jsonl")
        runs = [r for r in recs if r.get("type") == "run"]
        note = None
        if mode == "warm":
            complete = [r["session"] for r in recs if r.get("type") == "session-end" and r.get("complete")]
            sessions = sorted({r["session"] for r in runs})
            chosen = complete[-1] if complete else None
            note = {"used": chosen, "complete": bool(complete), "sessions": len(sessions)}
            ok = [r for r in runs if r["session"] == chosen and r["status"] == "ok" and not r.get("warmup")]
            used, dropped = last_per(ok, lambda r: (r["session"], r["slot"]))
        else:
            ok = [r for r in runs if r["status"] == "ok"]
            used, dropped = last_per(ok, lambda r: r["slot"])
        mine = [x for x in (row_of(r) for r in used) if x is not None]
        eps = {e["id"]: e for s in env.get("sessions", []) for e in s.get("endpoints", [])}
        for x in mine:
            e = eps.get(x["endpoint"], {})
            x["mode"] = mode
            x["kind"] = e.get("kind", x["endpoint"])
            x["endpointLabel"] = e.get("label", x["endpoint"])
            x["environment"] = (env.get("sessions") or [{}])[-1].get("environment")
            x["prover"] = prover
            x["keyLabel"] = key_label
        rows.extend(mine)
        books.append(
            {
                "campaign": d.name,
                "mode": mode,
                "label": env.get("label"),
                "keyLabel": key_label,
                "prover": prover,
                "protocolE2eSha256": (env.get("protocol") or {}).get("e2e", {}).get("normativeSha256"),
                "sessions": len(env.get("sessions", [])),
                "warmSession": note,
                "recordsUsed": len(mine),
                "duplicateOkDropped": dropped,
                "ok": sum(1 for r in runs if r["status"] == "ok"),
                "errors": sum(1 for r in runs if r["status"] == "error"),
                "discardedBattery": sum(1 for r in runs if r["status"] == "discarded-battery"),
                "discardedPause": sum(1 for r in runs if r["status"] == "discarded-pause"),
                "discardedBlockError": sum(1 for r in runs if r["status"] == "discarded-block-error"),
                "byEndpoint": endpoint_counts(runs),
                "countsCover": "every run record of every session",
                "withheld": sum(1 for r in recs if r.get("type") == "withheld"),
                "usedNotQuiesced": sum(1 for x in mine if x["flagNotQuiesced"]),
                "usedIdlePause": sum(1 for x in mine if x["flagIdlePause"]),
                "complete": any(r.get("type") in ("campaign-end", "session-end") and r.get("complete") for r in recs),
            }
        )
    return rows, books


def variant(r: dict) -> str:
    return "control" if r["control"] else "instrumented"


def base_key(r: dict) -> str:
    return f"{r['endpointLabel']}|{r['mode']}|{variant(r)}|{r['prover']}|{r['keyLabel']}"


def modal(values: list[tuple[object, object]]) -> dict:
    """values: (run id, value) -> modal value and the runs that differ."""
    if not values:
        return {"mode": None, "n": 0, "deviating": []}
    c = Counter(json.dumps(v, sort_keys=True) for _, v in values)
    top = c.most_common(1)[0][0]
    return {"mode": json.loads(top), "n": len(values), "deviating": [{"run": rid, "value": v} for rid, v in values if json.dumps(v, sort_keys=True) != top]}


def cell(s: object) -> str:
    """A Markdown table cell: group keys and ratio ids use "|" as a separator."""
    return str(s).replace("|", "\\|")


def conn_class(n: object) -> str | None:
    if not isinstance(n, (int, float)):
        return None
    return "0" if n == 0 else "1+"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=str(REPO / "results" / "v4" / "e2e"))
    ap.add_argument("--smoke", action="store_true", help="analyse <root>/_smoke (never quoted)")
    ap.add_argument("--force", action="store_true", help="run even if RUNNING or BUSY exists")
    ap.add_argument("--B", type=int, default=B_DEFAULT)
    ap.add_argument("--seed", type=int, default=SEED_DEFAULT)
    a = ap.parse_args()
    held = [m for m in MARKERS if m.exists()]
    if held and not a.force:
        print(f"[analyze_e2e] {', '.join(rel(m) for m in held)} exists: a timed run or heavy work is active; no analyses now (docs/BENCHMARK_POLICY.md, D-034)", file=sys.stderr)
        return 3
    root = Path(a.root) / ("_smoke" if a.smoke else "")
    if not root.exists():
        print(f"[analyze_e2e] no results root {rel(root)}", file=sys.stderr)
        return 2
    rows, books = load(root)
    if not rows:
        print("[analyze_e2e] no usable records", file=sys.stderr)
        return 2

    # ---- groups: never pool one condition across campaigns
    campaigns_of: dict[str, set] = {}
    for r in rows:
        campaigns_of.setdefault(base_key(r), set()).add(r["campaign"])
    not_pooled = [{"group": k, "campaigns": sorted(v)} for k, v in sorted(campaigns_of.items()) if len(v) > 1]
    for r in rows:
        r["group"] = base_key(r) + (f"|{r['campaign']}" if len(campaigns_of[base_key(r)]) > 1 else "")
    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(r["group"], []).append(r)

    rid = lambda r: f"{r['campaign']}#{r['session']}#{r['slot']}"  # noqa: E731
    out_groups = {}
    for g, rs in sorted(groups.items()):
        e2e = np.array([r["endToEndMs"] for r in rs], dtype=float)
        clean = [r for r in rs if not r["flagNotQuiesced"] and not r["flagIdlePause"]]
        gd = {
            "endpoint": rs[0]["endpointLabel"],
            "kind": rs[0]["kind"],
            "mode": rs[0]["mode"],
            "instrumented": not rs[0]["control"],
            "prover": rs[0]["prover"],
            "keyLabel": rs[0]["keyLabel"],
            "campaigns": sorted({r["campaign"] for r in rs}),
            "environments": sorted({str(r["environment"]) for r in rs}),
            "labels": sorted({lab for r in rs for lab in r["labels"]}),
            "n": len(rs),
            "endToEndMs": stats(e2e, a.B, a.seed, f"{g}|endToEndMs"),
            "sensitivity": {
                "rule": "runs flagged hostPauseSuspected or quiesce.quiesced = false left out (docs/v4/CMP.md)",
                "n": len(clean),
                "excluded": len(rs) - len(clean),
                "endToEndMs": stats(np.array([r["endToEndMs"] for r in clean], dtype=float), a.B, a.seed, f"{g}|sensitivity|endToEndMs") if clean else None,
            },
            "connectionsPerRun": modal([(rid(r), r["connections"]) for r in rs]),
        }
        by_conn: dict = {}
        cls_total = [(conn_class(None if r["connections"] is None else r["connections"]["verifier"] + r["connections"]["wallet"]), r["endToEndMs"]) for r in rs]
        by_conn["endToEndMs"] = {c: stats(np.array([v for cc, v in cls_total if cc == c], dtype=float), a.B, a.seed, f"{g}|conn|endToEndMs|{c}") for c in ("0", "1+") if any(cc == c for cc, _ in cls_total)}
        if not rs[0]["control"]:
            for s in CONN_STAGES:
                pairs = [(conn_class(r["connects"].get(s)), r["stages"][s]) for r in rs]
                by_conn[s] = {c: stats(np.array([v for cc, v in pairs if cc == c], dtype=float), a.B, a.seed, f"{g}|conn|{s}|{c}") for c in ("0", "1+") if any(cc == c for cc, _ in pairs)}
        gd["byNewConnections"] = {"rule": "endToEndMs by the run's new connections (both parties); S3, S5, S11 by the stage's own; 0 versus 1 or more", **by_conn}
        if not rs[0]["control"]:
            gd["stagesMs"] = {s: stats(np.array([r["stages"][s] for r in rs], dtype=float), a.B, a.seed, f"{g}|{s}") for s in STAGES}
            gd["verifySplitMs"] = {k: stats(np.array([r["split"][k] for r in rs], dtype=float), a.B, a.seed, f"{g}|split|{k}") for k in SPLIT}
            gd["s7s8Ms"] = stats(np.array([r["s7s8"] for r in rs], dtype=float), a.B, a.seed, f"{g}|s7s8")
            gd["walletPartMs"] = stats(np.array([r["walletPart"] for r in rs], dtype=float), a.B, a.seed, f"{g}|walletPart")
            gd["verifierPartMs"] = stats(np.array([r["verifierPart"] for r in rs], dtype=float), a.B, a.seed, f"{g}|verifierPart")
            cs = np.array([r["chainShare"] for r in rs if r["chainShare"] is not None], dtype=float)
            if cs.size:
                gd["chainShare"] = stats(cs, a.B, a.seed, f"{g}|chainShare")
            gd["roundTrips"] = {s: modal([(rid(r), r["posts"][s]) for r in rs]) for s in STAGES}
            gd["requests"] = {s: modal([(rid(r), r["requests"][s]) for r in rs]) for s in STAGES}
            gd["roundTripsTotal"] = modal([(rid(r), r.get("postsTotal")) for r in rs])
            gd["requestsTotal"] = modal([(rid(r), r.get("requestsTotal")) for r in rs])
            gd["newConnections"] = {s: modal([(rid(r), r["connects"].get(s)) for r in rs]) for s in STAGES}
            gd["newConnectionsTotal"] = modal([(rid(r), r.get("connectsTotal")) for r in rs])
            gcv = np.array([r["gcMs"] for r in rs if r["gcMs"] is not None], dtype=float)
            if gcv.size:
                gd["gc"] = {"msPerRun": stats(gcv, a.B, a.seed, f"{g}|gcMs"), "runsWithMajorGc": sum(1 for r in rs if (r["gcMajor"] or 0) > 0)}
            rtt = np.array([r["rtt"] for r in rs if r["rtt"] is not None], dtype=float)
            if rtt.size:
                gd["rawEthBlockNumberMsMedianPerRun"] = stats(rtt, a.B, a.seed, f"{g}|rtt")
        idle = [r["partyIdleMsAtStart"] for r in rs if isinstance(r.get("partyIdleMsAtStart"), dict)]
        if idle:
            gd["partyIdleMsAtStart"] = {
                p: {"median": float(np.median(v)), "max": float(np.max(v)), "n": int(v.size)}
                for p in ("verifier", "wallet")
                for v in [np.array([x[p] for x in idle if isinstance(x.get(p), (int, float))], dtype=float)]
                if v.size
            }
        out_groups[g] = gd

    def metric_of(r: dict, metric: str) -> float | None:
        if metric == "endToEndMs":
            return r["endToEndMs"]
        return r["stages"].get(metric)

    def arr(rs: list[dict], metric: str) -> np.ndarray | None:
        vals = [metric_of(r, metric) for r in rs]
        if not vals or any(v is None for v in vals):
            return None
        return np.array(vals, dtype=float)

    ratios: list[dict] = []

    def add_ratio(rid_: str, num: str, den: str, metric: str, what: str, x_rows: list[dict] | None = None, y_rows: list[dict] | None = None, extra: dict | None = None) -> None:
        xr = groups[num] if x_rows is None else x_rows
        yr = groups[den] if y_rows is None else y_rows
        x, y = arr(xr, metric), arr(yr, metric)
        base = {"id": rid_, "numerator": num, "denominator": den, "metric": metric, "what": what, **(extra or {})}
        if x is None or y is None or x.size == 0 or y.size == 0:
            ratios.append({**base, "status": "missing condition"})
            return
        my = float(np.median(y))
        if my == 0:
            ratios.append({**base, "status": "zero denominator median"})
            return
        lo, hi = boot_ratio(x, y, a.B, a.seed, rid_)
        ratios.append(
            {
                **base,
                "value": float(np.median(x)) / my,
                "ci95": [lo, hi],
                "nNumerator": int(x.size),
                "nDenominator": int(y.size),
                "sameCampaign": out_groups[num]["campaigns"] == out_groups[den]["campaigns"] and len(out_groups[num]["campaigns"]) == 1,
            }
        )

    def tag(g: str) -> str:
        parts = g.split("|")
        return f"|{parts[5]}" if len(parts) > 5 else ""

    G = {g: out_groups[g] for g in out_groups}
    instr = [g for g in G if G[g]["instrumented"]]
    for g1 in instr:
        a1 = G[g1]
        if a1["mode"] != "cold":
            continue
        for g2 in instr:
            a2 = G[g2]
            if a2["mode"] == "warm" and a2["endpoint"] == a1["endpoint"] and a2["prover"] == a1["prover"] and a2["keyLabel"] == a1["keyLabel"]:
                for metric in ["endToEndMs", *STAGES]:
                    add_ratio(f"coldWarm|{a1['endpoint']}|{a1['prover']}|{a1['keyLabel']}{tag(g1)}{tag(g2)}|{metric}", g1, g2, metric, "cold / warm (separate campaigns)")
    for g1 in instr:
        a1 = G[g1]
        if a1["mode"] != "warm":
            continue
        for g2, a2 in G.items():
            if a2["instrumented"] or a2["mode"] != "warm" or a2["endpoint"] != a1["endpoint"] or a2["prover"] != a1["prover"] or a2["keyLabel"] != a1["keyLabel"] or a2["campaigns"] != a1["campaigns"]:
                continue
            # matched blocks only: same session and block, and both iterations opened the same connections
            ctl = {(r["session"], r["block"]): r for r in groups[g2]}
            xs, ys, unmatched = [], [], 0
            for r in groups[g1]:
                c = ctl.get((r["session"], r["block"]))
                if c is not None and c["connections"] == r["connections"]:
                    xs.append(r)
                    ys.append(c)
                else:
                    unmatched += 1
            add_ratio(
                f"overhead|{a1['endpoint']}|{a1['prover']}|{a1['keyLabel']}{tag(g1)}",
                g1,
                g2,
                "endToEndMs",
                "instrumentation overhead: warm instrumented / warm control (same session; blocks whose two iterations opened the same connections)",
                xs,
                ys,
                {"pairedBlocks": len(xs), "unmatchedBlocks": unmatched},
            )
    for g1 in instr:
        a1 = G[g1]
        if a1["kind"] != "besu":
            continue
        for g2 in instr:
            a2 = G[g2]
            if a2["kind"] == "anvil" and a2["mode"] == a1["mode"] and a2["prover"] == a1["prover"] and a2["keyLabel"] == a1["keyLabel"] and a2["campaigns"] == a1["campaigns"]:
                for metric in ["endToEndMs", *STAGES]:
                    add_ratio(f"besuAnvil|{a1['mode']}|{a1['prover']}|{a1['keyLabel']}{tag(g1)}|{metric}", g1, g2, metric, "besu / anvil (same campaign, interleaved)")
    for g1 in instr:
        a1 = G[g1]
        if a1["kind"] != "custom":
            continue
        for g2 in instr:
            a2 = G[g2]
            if a2["kind"] == "besu" and a2["mode"] == a1["mode"] and a2["prover"] == a1["prover"] and a2["keyLabel"] == a1["keyLabel"]:
                for metric in ["endToEndMs", "S1", "S3", "S5", "S11"]:
                    add_ratio(
                        f"customBesu|{a1['endpoint']}|{a1['mode']}|{a1['prover']}|{a1['keyLabel']}{tag(g1)}{tag(g2)}|{metric}",
                        g1,
                        g2,
                        metric,
                        "custom / besu (different campaigns, not interleaved; public RPC endpoint over the internet versus loopback, same host)",
                    )

    summary = {
        "schema": "pqid/v4-e2e-summary/v2",
        "generatedUtc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "generator": "scripts/e2e/analyze_e2e.py",
        "root": rel(root),
        "smoke": a.smoke,
        "label": "SMOKE: not a result, never quoted" if a.smoke else "[M] from the runs files; ratios [M] with percentile bootstrap CIs",
        "bootstrap": {"B": a.B, "seed": a.seed, "quantiles": QUANTILE_METHOD, "rule": "one PRNG stream per id: default_rng([seed, crc32(id)])"},
        "groupKey": "endpoint label | mode | instrumented or control | prover | key label [| campaign, when the same condition is in more than one campaign]",
        "notPooled": not_pooled,
        "campaigns": books,
        "groups": out_groups,
        "ratios": ratios,
    }
    (root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    md = [f"# End-to-end presentation summary ({'SMOKE, not a result' if a.smoke else 'measured'})", ""]
    md.append(f"Generated by `scripts/e2e/analyze_e2e.py` from `{rel(root)}`. Protocol: `docs/v4/E2E.md`. Medians in ms with percentile bootstrap 95 % CIs (B = {a.B}, seed {a.seed}). Group: endpoint | mode | instrumented or control | prover | key.")
    md.append("")
    if not_pooled:
        md.append("Not pooled (the same condition in more than one campaign; kept apart by campaign): " + "; ".join(f"{x['group']} ({', '.join(x['campaigns'])})" for x in not_pooled) + ".")
        md.append("")
    md.append("| Campaign | Mode | Prover | Key | Used | ok | errors | discarded (battery, pause, block error) | duplicate ok dropped | flagged (not quiet, idle pause) |")
    md.append("|---|---|---|---|---|---|---|---|---|---|")
    for b in books:
        md.append(f"| {b['campaign']} | {b['mode']} | {b['prover']} | {b['keyLabel']} | {b['recordsUsed']} | {b['ok']} | {b['errors']} | {b['discardedBattery']}, {b['discardedPause']}, {b['discardedBlockError']} | {b['duplicateOkDropped']} | {b['usedNotQuiesced']}, {b['usedIdlePause']} |")
    md.append("")
    md.append("| Campaign | Endpoint | ok | error | discarded (battery, pause, block error) | error kinds | HTTP 429 |")
    md.append("|---|---|---|---|---|---|---|")
    for b in books:
        for ep, c in b["byEndpoint"].items():
            kinds = ", ".join(f"{k} {v}" for k, v in c["errorKinds"].items()) or "-"
            md.append(f"| {b['campaign']} | {ep} | {c['ok']} | {c['error']} | {c['discarded-battery']}, {c['discarded-pause']}, {c['discarded-block-error']} | {kinds} | {c['http429']} |")
    md.append("")
    md.append("| Group | n | endToEnd median [CI] | IQR | p95 | sensitivity n, median [CI] | labels |")
    md.append("|---|---|---|---|---|---|---|")
    for g, gd in out_groups.items():
        e = gd["endToEndMs"]
        se = gd["sensitivity"]
        sens = f"{se['n']}, {se['endToEndMs']['median']:.1f} [{se['endToEndMs']['medianCi95'][0]:.1f}, {se['endToEndMs']['medianCi95'][1]:.1f}]" if se["endToEndMs"] else f"{se['n']}, -"
        md.append(f"| {cell(g)} | {gd['n']} | {e['median']:.1f} [{e['medianCi95'][0]:.1f}, {e['medianCi95'][1]:.1f}] | {e['iqr']:.1f} | {e['p95']:.1f} | {sens} | {'; '.join(gd['labels'])} |")
    md.append("")
    for g, gd in out_groups.items():
        md.append(f"## {g}")
        md.append("")
        bc = gd["byNewConnections"]
        conn_txt = []
        for metric in ["endToEndMs", *CONN_STAGES]:
            if metric in bc and bc[metric]:
                conn_txt.append(f"{metric}: " + ", ".join(f"{c} new: n {v['n']}, median {v['median']:.2f}" for c, v in bc[metric].items()))
        md.append("New connections (0 versus 1 or more): " + ("; ".join(conn_txt) if conn_txt else "-") + f". Connections per run (verifier, wallet), modal: {json.dumps(gd['connectionsPerRun']['mode'])} ({len(gd['connectionsPerRun']['deviating'])} runs differ).")
        if "partyIdleMsAtStart" in gd:
            md.append("Party idle at iteration start (ms since its last POST ended, before the agent reset): " + ", ".join(f"{p} median {v['median']:.0f}, max {v['max']:.0f}" for p, v in gd["partyIdleMsAtStart"].items()) + ".")
        md.append("")
        if "stagesMs" not in gd:
            continue
        md.append("| Stage | median [CI] | IQR | round trips (verifier, wallet) mode | requests mode | runs differing |")
        md.append("|---|---|---|---|---|---|")
        for s in STAGES:
            st = gd["stagesMs"][s]
            rt = gd["roundTrips"][s]
            rq = gd["requests"][s]
            mode_rt = rt["mode"] or {}
            md.append(f"| {s} | {st['median']:.2f} [{st['medianCi95'][0]:.2f}, {st['medianCi95'][1]:.2f}] | {st['iqr']:.2f} | {mode_rt.get('verifier', 0)}, {mode_rt.get('wallet', 0)} | {rq['mode']} | {len(rt['deviating'])} |")
        sp = gd["verifySplitMs"]
        md.append("")
        md.append("S11 split (medians): " + ", ".join(f"{k} {sp[k]['median']:.2f}" for k in SPLIT) + ".")
        md.append(f"S7 + S8 (coarse split, no input mark needed), median: {gd['s7s8Ms']['median']:.2f}. Wallet part (S2 to S10), median: {gd['walletPartMs']['median']:.2f}; verifier part (S1 + S11), median: {gd['verifierPartMs']['median']:.2f}.")
        md.append(f"Round trips per presentation (verifier, wallet), modal: {json.dumps(gd['roundTripsTotal']['mode'])}; new TCP connections, modal: {json.dumps(gd['newConnectionsTotal']['mode'])} ({len(gd['newConnectionsTotal']['deviating'])} runs differ).")
        if "chainShare" in gd:
            md.append(f"Chain share (median per run): {gd['chainShare']['median']:.3f}.")
        if "gc" in gd:
            md.append(f"GC inside the window (median ms per run): {gd['gc']['msPerRun']['median']:.2f}; runs with a major GC: {gd['gc']['runsWithMajorGc']}.")
        md.append("")
    md.append("## Ratios")
    md.append("")
    md.append("| Ratio | Metric | value [CI] | n | same campaign |")
    md.append("|---|---|---|---|---|")
    for r in ratios:
        if "value" in r:
            md.append(f"| {r['id'].split('|')[0]} {cell(r['numerator'])} / {cell(r['denominator'])} | {r['metric']} | {r['value']:.3f} [{r['ci95'][0]:.3f}, {r['ci95'][1]:.3f}] | {r['nNumerator']}, {r['nDenominator']} | {str(r['sameCampaign']).lower()} |")
        else:
            md.append(f"| {cell(r['id'])} | {r['metric']} | {r['status']} | | |")
    (root / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"[analyze_e2e] {len(rows)} records, {len(out_groups)} groups, {sum(1 for r in ratios if 'value' in r)} ratios -> {rel(root / 'summary.json')}, {rel(root / 'summary.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
