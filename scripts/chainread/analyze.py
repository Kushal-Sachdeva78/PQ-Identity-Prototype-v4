#!/usr/bin/env python3
"""Chain-read campaign statistics (docs/v4/CHAINREAD.md section 11). numpy only.

  python scripts/chainread/analyze.py --campaign cr_wsl [--target anvil|besu]
      -> <campaign>/summary.json, summary.md
  python scripts/chainread/analyze.py --cross cr_wsl,cr_win [--cross-target besu=cr_wsl_b,cr_win]
      -> results/v4/chainread/cross_env.json, cross_env.md
  add --smoke to read results/v4/chainread/_smoke/ instead (never cited)

Rules:
- Refuses while results/v4/bench/RUNNING or results/v4/BUSY exists (docs/BENCHMARK_POLICY.md, D-034).
- Only targets whose env.json status is "completed" are analysed; any other target is listed
  under "excluded" with its status, and so is every <target>.failed-<UTC> folder a resumed
  campaign set aside (CHAINREAD.md section 14). --cross-target maps one target to other
  campaigns (a target re-run under another campaign name); the mapping is recorded.
- Used samples: status "ok" (discarded-battery, stopped and error samples are counted, never
  analysed). Per-POST distributions take only the POSTs of used samples.
- Distributions: n, median, Q1, Q3 (type 7, numpy method="linear"), IQR, mean, min, max, p95.
- Counts (POSTs, requests, depth): exact distributions (min, median, max, value counts).
- Ratios of medians with a percentile bootstrap 95% CI: B = 10,000, seed 20260927 (BENCH_PROTOCOL
  bootstrap seed, unchanged by D-034), one stream per ratio default_rng([seed, crc32(ratio id)]),
  numerator resampled first, then the denominator, each at its own n.
- [S] values (chain cost per presentation, deployment model) are labelled. Deployment model:
  median totalMs on loopback plus median sequential depth x RTT (an upper bound: it keeps the
  batch stall, queue delays, loopback round trips and node time a deployment also pays).
- Labels carried into every output: the v4 dev key (D-034: numbers before the ceremony are
  dev), "loopback, same host", traced ethers clients (wrapper code per request; R0's E4 figures
  are untraced), and per variant "as shipped" or "variant, not shipped"; S1 cells are raw
  transports, not the shipped client.
- Windows/WSL ratios are labelled cross-environment (D-032) and name both toolchains.
- R0 (WSL): the unchanged E4 files <campaign>/r0/e4_verifier.json and e4_besu.json are quoted as
  they are (their own distributions), never recomputed. R0's Anvil runs unpinned (scale.ts
  starts it in its unpinned parent) and R0 besu runs against Besu JVMs still pinned to CPUs 4-7.
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
import zlib
from collections import Counter
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "results" / "v4" / "chainread"
SMOKE_ROOT = ROOT / "_smoke"
SEED = 20260927
B = 10_000
RTTS_MS = (20, 50, 100)
TARGETS = ("anvil", "besu")
VARIANTS = ("A", "B", "C", "D", "E", "F", "G", "H", "I")
RAW_LABEL = "raw transport (no ethers), not the shipped client"
TRACED_LABEL = "traced ethers clients (wrapper code runs per request; R0's E4 figures are untraced)"
DEFAULT_KEY_LABEL = "dev (v4 Groth16 dev key; proving untimed)"
DEFAULT_NETWORK_LABEL = "loopback, same host"


def relp(p: Path) -> str:
    """Repo-relative POSIX path (a path outside the repository keeps only its last two parts)."""
    try:
        return p.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return "/".join(p.parts[-2:])


def r4(x: float) -> float:
    return float(round(float(x), 4))


def dist(xs) -> dict | None:
    a = np.asarray([x for x in xs if x is not None], dtype=float)
    if a.size == 0:
        return None
    q1, med, q3, p95 = np.quantile(a, [0.25, 0.5, 0.75, 0.95], method="linear")
    return {"n": int(a.size), "median": r4(med), "q1": r4(q1), "q3": r4(q3), "iqr": r4(q3 - q1), "mean": r4(a.mean()), "min": r4(a.min()), "max": r4(a.max()), "p95": r4(p95)}


def exact(xs) -> dict | None:
    v = [x for x in xs if x is not None]
    if not v:
        return None
    c = Counter(v)
    return {"min": min(v), "median": float(np.median(np.asarray(v, dtype=float))), "max": max(v), "counts": {str(k): c[k] for k in sorted(c)}, "invariant": len(c) == 1}


def boot_ratio(num, den, rid: str) -> dict | None:
    a = np.asarray(num, dtype=float)
    b = np.asarray(den, dtype=float)
    if a.size == 0 or b.size == 0 or np.median(b) == 0:
        return None
    rng = np.random.default_rng([SEED, zlib.crc32(rid.encode())])
    meds_a = np.empty(B)
    meds_b = np.empty(B)
    chunk = 1000
    for i in range(0, B, chunk):
        meds_a[i : i + chunk] = np.median(a[rng.integers(0, a.size, (chunk, a.size))], axis=1)
    for i in range(0, B, chunk):
        meds_b[i : i + chunk] = np.median(b[rng.integers(0, b.size, (chunk, b.size))], axis=1)
    ok = meds_b != 0
    ratios = meds_a[ok] / meds_b[ok]
    lo, hi = np.percentile(ratios, [2.5, 97.5])
    return {"id": rid, "ratio": r4(np.median(a) / np.median(b)), "ci95": [r4(lo), r4(hi)], "nNum": int(a.size), "nDen": int(b.size), "B": B, "seed": SEED}


def read_jsonl_gz(p: Path) -> list[dict]:
    if not p.exists():
        return []
    with gzip.open(p, "rt", encoding="utf8") as f:
        return [json.loads(line) for line in f if line.strip()]


def read_jsonl(p: Path) -> list[dict]:
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf8").splitlines() if line.strip()]


def used(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r.get("status") == "ok"]


def refuse_if_markers() -> None:
    held = [p for p in (REPO / "results/v4/bench/RUNNING", REPO / "results/v4/BUSY") if p.exists()]
    if held:
        sys.exit(f"analyze: refusing while {', '.join(str(p.relative_to(REPO)).replace(chr(92), '/') for p in held)} exists (docs/BENCHMARK_POLICY.md, D-034)")


# --------------------------------------------------------------------------- per target


class NotCompleted(Exception):
    def __init__(self, folder: str, status: str | None):
        super().__init__(f"{folder} status is {status}, not completed")
        self.folder = folder
        self.status = status


def quality(target_dir: Path, rows_by_series: dict[str, list[dict]]) -> dict:
    passes = read_jsonl(target_dir / "passes.jsonl")
    out = {}
    for s in ("s1", "s2", "s3", "s4", "s5"):
        ps = [p for p in passes if p["series"] == s]
        rows = rows_by_series.get(s, [])
        out[s] = {
            "passAttempts": len(ps),
            "passesOk": sum(1 for p in ps if p["status"] == "ok"),
            "passesDiscardedBattery": sum(1 for p in ps if p["status"] == "discarded-battery"),
            "passesStopped": sum(1 for p in ps if p["status"] == "stopped"),
            "passesAffinityMismatchPost": sum(1 for p in ps if p.get("affinityMismatchPost")),
            "passesBusyFlagged": sum(1 for p in ps if not p["quiesce"]["quiesced"]),
            "passesMachineWideBusy": sum(1 for p in ps if p["quiesce"].get("machineWideQuiesced") is False),
            "busyReasons": sorted({r for p in ps for r in p["quiesce"]["reasons"]}),
            "quiesceCpuBusyPercent": dist(p["quiesce"].get("cpuBusyPercent") for p in ps),
            "quiesceStealPercentMax": max((p["quiesce"].get("stealPercent") or 0 for p in ps), default=None),
            "passesHostPauseSuspected": sum(1 for p in ps if (p.get("clock") or {}).get("hostPauseSuspected")),
            "hostPauseReasons": [r for p in ps for r in (p.get("clock") or {}).get("reasons", [])],
            "maxClockDriftMs": max((abs(p["clock"]["driftMs"]) for p in ps if p.get("clock")), default=None),
            "affinityAllOk": all(all(a["ok"] for a in (p.get("affinity") or [])) for p in ps),
            "samples": len(rows),
            "samplesUsed": len(used(rows)),
            "samplesError": sum(1 for r in rows if r.get("status") == "error"),
            "samplesDiscarded": sum(1 for r in rows if r.get("status") == "discarded-battery"),
            "samplesStopped": sum(1 for r in rows if r.get("status") == "stopped"),
        }
    return out


def s1_summary(rows: list[dict]) -> dict:
    u = used(rows)
    cells = sorted({r["cell"] for r in u})
    out = {"label": RAW_LABEL, "cells": {}, "ratios": []}
    for c in cells:
        rs = [r for r in u if r["cell"] == c]
        d = {"label": RAW_LABEL, "ms": dist(r["ms"] for r in rs), "newConnections": sum(int(r.get("newConnections") or 0) for r in rs), "newConnectionsUnknown": sum(1 for r in rs if r.get("newConnections") is None)}
        if rs and rs[0].get("eachMs"):
            d["eachMs"] = dist(x for r in rs for x in r["eachMs"])
        out["cells"][c] = d
    for m in ("eth_blockNumber", "eth_chainId", "eth_call_resolve", "eth_getLogs_registered"):
        base = [r["ms"] for r in u if r["cell"] == f"single:{m}:fetch"]
        for t in ("httpKeepAlive", "tcpRawNoDelay"):
            num = [r["ms"] for r in u if r["cell"] == f"single:{m}:{t}"]
            br = boot_ratio(num, base, f"s1:{m}:{t}/fetch")
            if br:
                out["ratios"].append(br)
    return out


def ethers_counts(rs: list[dict]) -> dict:
    by_method = Counter()
    by_size = Counter()
    for r in rs:
        by_method.update(r.get("byMethod") or {})
        by_size.update({k: v for k, v in (r.get("postsBySize") or {}).items()})
    n = max(1, len(rs))
    return {
        "posts": exact([r.get("posts") for r in rs]),
        "requests": exact([r.get("requests") for r in rs]),
        "depth": exact([r.get("depth") for r in rs]),
        "maxInFlight": exact([r.get("maxInFlight") for r in rs]),
        "requestsByMethodMean": {k: r4(v / n) for k, v in sorted(by_method.items())},
        "postsBySizeTotal": {k: by_size[k] for k in sorted(by_size, key=lambda x: int(x))},
        "tcpConnectsTotal": sum(int(r.get("tcpConnects") or 0) for r in rs),
        "tcpConnectsUnknownTotal": sum(int(r.get("tcpConnectsUnknown") or 0) for r in rs),
        "queueMsMax": dist(r.get("queueMsMax") for r in rs),
    }


def s2_summary(rows: list[dict]) -> dict:
    u = used(rows)
    out = {}
    for c in sorted({r["cell"] for r in u}):
        rs = [r for r in u if r["cell"] == c]
        d = {"label": rs[0].get("label") or (RAW_LABEL if c.startswith("raw:") else None), "ms": dist(r["ms"] for r in rs), "tcpConnects": exact([r.get("tcpConnects", r.get("newConnections")) for r in rs])}
        if rs[0].get("posts") is not None:
            d.update({"posts": exact([r["posts"] for r in rs]), "requests": exact([r["requests"] for r in rs])})
        if rs[0].get("connectMs") is not None:
            d["connectMs"] = dist(x for r in rs for x in (r.get("connectMs") or []))
        out[c] = d
    return out


def s3_summary(rows: list[dict]) -> dict:
    u = used(rows)
    out = {"cells": {}, "ratios": []}
    for c in sorted({r["cell"] for r in u}):
        rs = [r for r in u if r["cell"] == c]
        out["cells"][c] = {"label": rs[0].get("label"), "ms": dist(r["ms"] for r in rs), **ethers_counts(rs)}
    reads = sorted({r["read"] for r in u if r.get("kind") == "read"})
    for rd in reads:
        base = [r["ms"] for r in u if r["cell"] == f"read:asShipped:{rd}"]
        for c in ("noBatchStall", "staticNetwork", "staticNoStall", "unbatched", "unbatchedStatic"):
            br = boot_ratio([r["ms"] for r in u if r["cell"] == f"read:{c}:{rd}"], base, f"s3:{rd}:{c}/asShipped")
            if br:
                out["ratios"].append(br)
    base = [r["ms"] for r in u if r["cell"] == "set:sequentialShipped"]
    for v in ("concurrentShipped", "parallel", "batched", "multicall"):
        br = boot_ratio([r["ms"] for r in u if r["cell"] == f"set:{v}"], base, f"s3:set:{v}/sequentialShipped")
        if br:
            out["ratios"].append(br)
    return out


def sample_key(r: dict) -> tuple:
    return (r.get("variant"), r.get("pass"), r.get("attempt"), r.get("index"), r.get("try"))


def post_key(p: dict) -> tuple:
    return (p.get("v"), p.get("p"), p.get("a"), p.get("i"), p.get("tr"))


def presentation_summary(rows: list[dict], posts: list[dict], series: str) -> dict:
    u = used(rows)
    keys = {sample_key(r) for r in u}
    out = {"variants": {}, "ratios": []}
    for v in VARIANTS:
        rs = [r for r in u if r["variant"] == v]
        if not rs:
            continue
        # only the POSTs of used samples (not those of error tries, discarded or stopped passes)
        ps = [p for p in posts if p.get("s") == series and p.get("v") == v and post_key(p) in keys]
        tot = dist(r["totalMs"] for r in rs)
        d = {
            "name": rs[0]["name"],
            "label": rs[0]["label"],
            "totalMs": tot,
            "presentationsPerSecFromMedian": r4(1000 / tot["median"]) if tot and tot["median"] > 0 else None,
            "chainUnionMs": dist(r["chainUnionMs"] for r in rs),
            "chainSumMs": dist(r["chainSumMs"] for r in rs),
            "mlDsaMs": dist(r["mlDsaMs"] for r in rs),
            "otherMs": dist(r["otherMs"] for r in rs),
            "chainShare": dist(r["chainUnionMs"] / r["totalMs"] for r in rs if r["totalMs"] > 0),
            "outerCalls": exact([r.get("outerCalls") for r in rs]),
            **ethers_counts(rs),
            "perPost": {
                "postMs": dist(p["ms"] for p in ps),
                "httpMs": dist((p.get("h") or {}).get("ms") for p in ps),
                "queueMs": dist(q for p in ps for q in (p.get("q") or []) if q is not None),
            },
        }
        if "mlKemMs" in rs[0]:
            d["mlKemMs"] = dist(r["mlKemMs"] for r in rs)
        mc = [r["multicall"] for r in rs if r.get("multicall")]
        if mc:
            d["multicall"] = {"aggregatesPerPresentation": exact([m["aggregates"] for m in mc]), "subCallsPerAggregate": exact([s for m in mc for s in m["sizes"]]), "fallbacks": sum(m["fallbacks"] for m in mc)}
        out["variants"][v] = d
    base = [r for r in u if r["variant"] == "A"]
    for v in VARIANTS[1:]:
        rs = [r for r in u if r["variant"] == v]
        for metric in ("totalMs", "chainUnionMs"):
            br = boot_ratio([r[metric] for r in rs], [r[metric] for r in base], f"{series}:{v}/A:{metric}")
            if br:
                out["ratios"].append(br)
    return out


def derived(s4: dict, s5: dict) -> dict:
    out = {"label": "[S] from medians; not a measurement", "chainCostPerPresentationMs": {}, "deploymentModel": {}}
    # [S] deployment model: the loopback time (median totalMs, which keeps the batch stall, the
    # queue delays, the loopback round trips and the node's own time) plus the added network time
    # of the median sequential depth at each RTT. An upper bound: the loopback round trip is
    # counted again inside each RTT.
    for v in VARIANTS:
        a = s4["variants"].get(v)
        b = s5["variants"].get(v)
        if a and b:
            out["chainCostPerPresentationMs"][v] = {"walletChainUnion": b["chainUnionMs"]["median"], "verifierChainUnion": a["chainUnionMs"]["median"], "sum": r4(a["chainUnionMs"]["median"] + b["chainUnionMs"]["median"])}
        model = {}
        for role, s in (("verifier", a), ("wallet", b)):
            if not s or not s.get("depth"):
                continue
            loop = s["totalMs"]["median"]
            nonchain = loop - s["chainUnionMs"]["median"]
            model[role] = {f"rtt{t}ms": r4(loop + s["depth"]["median"] * t) for t in RTTS_MS} | {
                "depthMedian": s["depth"]["median"],
                "loopbackTotalMsMedian": r4(loop),
                "nonChainMsMedian": r4(nonchain),
            }
        if model:
            out["deploymentModel"][v] = model
    out["deploymentModelRule"] = "median totalMs on loopback + median sequential depth x RTT, for RTT 20, 50 and 100 ms; an upper bound that keeps the batch stall, queue delays, loopback round trips and node time"
    return out


def r0_summary(cdir: Path) -> dict | None:
    """Quote the unchanged E4 replication files (WSL R0) as they are."""
    out = {}
    v = cdir / "r0" / "e4_verifier.json"
    if v.exists():
        j = json.loads(v.read_text(encoding="utf8"))
        out["verifier"] = {
            "file": relp(v),
            "dry": j.get("dry"),
            "label": j.get("label"),
            "pinning": j.get("pinning"),
            "runtime": j.get("runtime"),
            "results": {k: {m: x.get(m) for m in ("totalMs", "chainMs", "mlDsaMs", "mlKemDecapsMs", "otherMs", "rpcRequestsPerPresentation", "presentationsPerSecFromMedian")} for k, x in (j.get("results") or {}).items()},
        }
    b = cdir / "r0" / "e4_besu.json"
    if b.exists():
        j = json.loads(b.read_text(encoding="utf8"))
        out["besu"] = {"file": relp(b), "dry": j.get("dry"), "label": j.get("label"), "reads": j.get("reads"), "rawRpc": j.get("rawRpc"), "rpcRequestsPerCall": j.get("rpcRequestsPerCall")}
    if not out:
        return None
    out["note"] = "unchanged E4 harness (harness/v4/scale.ts) with --out; E4's own distributions, quoted as written; untraced (no rpc_trace wrapper)"
    out["topology"] = "R0 Anvil unpinned (scale.ts verifier starts it in its unpinned parent; the measurement child is pinned to CPU 0); R0 besu runs after the Besu phase, so the Besu JVMs keep the CPU 4-7 mask the besu step set (steps.log records it); S4 pins Anvil to CPU 1. R0 and S4 A are not like-for-like."
    return out


def target_status(tdir: Path) -> str | None:
    env_p = tdir / "env.json"
    if not env_p.exists():
        return None
    try:
        return json.loads(env_p.read_text(encoding="utf8")).get("status")
    except (OSError, ValueError):
        return "unreadable"


def set_aside(cdir: Path) -> list[dict]:
    """<target>.failed-<UTC> folders of a resumed campaign: kept, never analysed."""
    out = []
    if cdir.exists():
        for d in sorted(cdir.iterdir()):
            if d.is_dir() and any(d.name.startswith(f"{t}.failed-") for t in TARGETS):
                out.append({"folder": relp(d), "status": target_status(d), "reason": "set aside by a resume (CHAINREAD.md section 14); never analysed"})
    return out


def labels_of(env: dict) -> dict:
    return {
        "key": env.get("keyLabel") or DEFAULT_KEY_LABEL,
        "network": env.get("networkLabel") or DEFAULT_NETWORK_LABEL,
        "endpoint": (env.get("target") or {}).get("endpoint"),
        "clients": TRACED_LABEL,
        "variants": "only A asShipped and the read set sequentialShipped are as shipped; every other variant is 'variant, not shipped' (D-034)",
    }


def analyse_target(tdir: Path) -> dict | None:
    """The summary of one completed target; None when there is no env.json. Raises NotCompleted otherwise."""
    env_p = tdir / "env.json"
    if not env_p.exists():
        return None
    env = json.loads(env_p.read_text(encoding="utf8"))
    if env.get("status") != "completed":
        raise NotCompleted(relp(tdir), env.get("status"))
    rows = {
        "s1": read_jsonl_gz(tdir / "s1_raw.jsonl.gz"),
        "s2": read_jsonl_gz(tdir / "s2_fresh.jsonl.gz"),
        "s3": read_jsonl_gz(tdir / "s3_reads.jsonl.gz"),
        "s4": read_jsonl_gz(tdir / "s4_verifier.jsonl.gz"),
        "s5": read_jsonl_gz(tdir / "s5_wallet.jsonl.gz"),
    }
    posts = read_jsonl_gz(tdir / "posts.jsonl.gz")
    s4 = presentation_summary(rows["s4"], posts, "s4")
    s5 = presentation_summary(rows["s5"], posts, "s5")
    return {
        "environment": env.get("environment"),
        "labels": labels_of(env),
        "smoke": env.get("smoke"),
        "toolchain": {"node": env.get("runtime", {}).get("node"), "openssl": env.get("runtime", {}).get("openssl"), "client": env.get("target", {}).get("clientVersion"), "pinned": env.get("pinning", {}).get("pinned")},
        "sourceVsE4Equal": env.get("sourceVsE4", {}).get("equal"),
        "deviation": env.get("deviation"),
        "counts": env.get("counts"),
        "protocol": env.get("protocol"),
        "quality": quality(tdir, rows),
        "s1": s1_summary(rows["s1"]),
        "s2": s2_summary(rows["s2"]),
        "s3": s3_summary(rows["s3"]),
        "s4": s4,
        "s5": s5,
        "derived": derived(s4, s5),
    }


# --------------------------------------------------------------------------- markdown


def fmt(d: dict | None) -> str:
    return "-" if not d else f"{d['median']:.2f} [{d['q1']:.2f}, {d['q3']:.2f}]"


def fmt_ex(d: dict | None) -> str:
    if not d:
        return "-"
    return f"{d['median']:g}" if d["invariant"] else f"{d['median']:g} ({d['min']}-{d['max']})"


def md_campaign(name: str, res: dict) -> str:
    out = [
        f"# Chain-read summary: {name}",
        "",
        "Generated by scripts/chainread/analyze.py. Medians with [Q1, Q3] in ms; counts as median (min-max when not invariant).",
        f"Labels: key {DEFAULT_KEY_LABEL}; loopback, same host; {TRACED_LABEL}. Every variant except A asShipped and the shipped read set is a variant, not shipped (D-034). S1 cells: {RAW_LABEL}.",
        "",
    ]
    for x in res.get("excluded", []):
        out.append(f"Excluded, not analysed: {x['folder']} (status {x['status']}; {x['reason']})")
    if res.get("excluded"):
        out.append("")
    for t, r in res["targets"].items():
        out += [f"## {t} ({r['environment']}, node {r['toolchain']['node']}, {r['toolchain']['client']}, pinned {r['toolchain']['pinned']})", ""]
        lab = r.get("labels") or {}
        out += [f"Key: {lab.get('key')}. Endpoint: {lab.get('endpoint')}. Clients: {lab.get('clients')}.", ""]
        if r.get("deviation") and (r["deviation"].get("text") or r["deviation"].get("departures")):
            out += [f"Deviation: {r['deviation'].get('text')} ({'; '.join(r['deviation'].get('departures') or [])})", ""]
        if r.get("smoke"):
            out += ["SMOKE output: never cited.", ""]
        for s, title in (("s4", "Verifier (S4)"), ("s5", "Wallet read phase (S5)")):
            out += [f"### {title}", "", "| Variant | Label | totalMs | chainUnionMs | POSTs | requests | depth | chain share |", "|---|---|---|---|---|---|---|---|"]
            for v, d in r[s]["variants"].items():
                out.append(f"| {v} {d['name']} | {d['label']} | {fmt(d['totalMs'])} | {fmt(d['chainUnionMs'])} | {fmt_ex(d['posts'])} | {fmt_ex(d['requests'])} | {fmt_ex(d['depth'])} | {d['chainShare']['median'] if d['chainShare'] else '-'} |")
            out += ["", "| Ratio | median ratio | 95% CI |", "|---|---|---|"]
            out += [f"| {x['id']} | {x['ratio']} | {x['ci95'][0]} to {x['ci95'][1]} |" for x in r[s]["ratios"]]
            out.append("")
        out += ["### Raw JSON-RPC (S1)", "", f"Every S1 cell is a {RAW_LABEL}.", "", "| Cell | ms |", "|---|---|"]
        out += [f"| {c} | {fmt(d['ms'])} |" for c, d in r["s1"]["cells"].items()]
        out += ["", "### Fresh connection (S2)", "", "| Cell | ms | TCP connects |", "|---|---|---|"]
        out += [f"| {c} | {fmt(d['ms'])} | {fmt_ex(d['tcpConnects'])} |" for c, d in r["s2"].items()]
        out += ["", "### Reads (S3)", "", "| Cell | label | ms | POSTs | requests | depth |", "|---|---|---|---|---|---|"]
        out += [f"| {c} | {d['label']} | {fmt(d['ms'])} | {fmt_ex(d['posts'])} | {fmt_ex(d['requests'])} | {fmt_ex(d['depth'])} |" for c, d in r["s3"]["cells"].items()]
        q = r["quality"]
        out += ["", "### Run quality", "", "| Series | passes ok | discarded | stopped | busy-flagged | machine-wide busy | host pause suspected | affinity changed | samples used | errors |", "|---|---|---|---|---|---|---|---|---|---|"]
        out += [
            f"| {s} | {x['passesOk']} | {x['passesDiscardedBattery']} | {x['passesStopped']} | {x['passesBusyFlagged']} | {x['passesMachineWideBusy']} | {x['passesHostPauseSuspected']} | {x['passesAffinityMismatchPost']} | {x['samplesUsed']} | {x['samplesError']} |"
            for s, x in q.items()
        ]
        out += [
            "",
            "### [S] Chain cost per presentation and deployment model",
            "",
            f"Deployment model [S]: {r['derived']['deploymentModelRule']}.",
            "",
            "| Variant | wallet + verifier chain ms [S] | verifier at RTT 20/50/100 ms [S] | wallet at RTT 20/50/100 ms [S] |",
            "|---|---|---|---|",
        ]
        dm = r["derived"]
        for v in VARIANTS:
            cc = dm["chainCostPerPresentationMs"].get(v)
            m = dm["deploymentModel"].get(v, {})
            ver = m.get("verifier")
            wal = m.get("wallet")
            f3 = lambda x: "-" if not x else " / ".join(str(x[f"rtt{t}ms"]) for t in RTTS_MS)  # noqa: E731
            out.append(f"| {v} | {cc['sum'] if cc else '-'} | {f3(ver)} | {f3(wal)} |")
        out.append("")
    r0 = res.get("r0")
    if r0 and r0.get("verifier"):
        out += ["## R0: unchanged E4 verifier harness (quoted from its own file)", "", f"File: {r0['verifier']['file']} (dry {r0['verifier']['dry']}). {r0['note']}. {r0['topology']}", "", "| E4 variant | totalMs | chainMs | requests per presentation |", "|---|---|---|---|"]
        for k, x in r0["verifier"]["results"].items():
            out.append(f"| {k} | {fmt(x.get('totalMs'))} | {fmt(x.get('chainMs'))} | {x.get('rpcRequestsPerPresentation')} |")
        out.append("")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- cross environment


CROSS_LABEL = (
    "cross-environment (D-032): ratios between separate campaigns in different environments and toolchains; "
    "the harness is pinned to one CPU in WSL and unpinned on Windows, so only chain time, POSTs, requests and depth are compared. "
    f"v4 dev key; loopback, same host; {TRACED_LABEL}."
)


def cross(a: str, b: str, root: Path, target_sources: dict[str, tuple[str, str]] | None = None) -> dict:
    """Cross-environment ratios a/b per target. target_sources maps a target to other (a, b) campaigns."""
    sources = {t: (target_sources or {}).get(t, (a, b)) for t in TARGETS}
    res = {"label": CROSS_LABEL, "numerator": a, "denominator": b, "targetSources": {t: {"numerator": x, "denominator": y} for t, (x, y) in sources.items()}, "excluded": [], "targets": {}}
    for t in TARGETS:
        ca, cb = sources[t]
        da, db = root / ca / t, root / cb / t
        if not (da / "env.json").exists() or not (db / "env.json").exists():
            continue
        ea = json.loads((da / "env.json").read_text(encoding="utf8"))
        eb = json.loads((db / "env.json").read_text(encoding="utf8"))
        bad = [(e, d) for e, d in ((ea, da), (eb, db)) if e.get("status") != "completed"]
        if bad:
            res["excluded"] += [{"target": t, "folder": relp(d), "status": e.get("status")} for e, d in bad]
            continue
        tc = lambda e: {"environment": e.get("environment"), "node": e.get("runtime", {}).get("node"), "client": e.get("target", {}).get("clientVersion"), "pinned": e.get("pinning", {}).get("pinned")}  # noqa: E731
        entry = {"campaigns": {"numerator": ca, "denominator": cb}, "toolchains": {ca: tc(ea), cb: tc(eb)}, "labels": {ca: labels_of(ea), cb: labels_of(eb)}, "ratios": [], "counts": {}}
        for s, f in (("s4", "s4_verifier.jsonl.gz"), ("s5", "s5_wallet.jsonl.gz")):
            ra, rb = used(read_jsonl_gz(da / f)), used(read_jsonl_gz(db / f))
            for v in VARIANTS:
                xa = [r for r in ra if r["variant"] == v]
                xb = [r for r in rb if r["variant"] == v]
                if not xa or not xb:
                    continue
                br = boot_ratio([r["chainUnionMs"] for r in xa], [r["chainUnionMs"] for r in xb], f"xenv:{t}:{s}:{v}:chainUnionMs:{ca}/{cb}")
                if br:
                    br["label"] = xa[0].get("label")
                    entry["ratios"].append(br)
                entry["counts"][f"{s}:{v}"] = {k: {ca: exact([r[k] for r in xa]), cb: exact([r[k] for r in xb])} for k in ("posts", "requests", "depth")}
        ra, rb = used(read_jsonl_gz(da / "s1_raw.jsonl.gz")), used(read_jsonl_gz(db / "s1_raw.jsonl.gz"))
        for c in sorted({r["cell"] for r in ra} & {r["cell"] for r in rb}):
            br = boot_ratio([r["ms"] for r in ra if r["cell"] == c], [r["ms"] for r in rb if r["cell"] == c], f"xenv:{t}:s1:{c}:{ca}/{cb}")
            if br:
                br["label"] = RAW_LABEL
                entry["ratios"].append(br)
        res["targets"][t] = entry
    return res


def md_cross(res: dict) -> str:
    out = ["# Chain-read cross-environment ratios", "", "Generated by scripts/chainread/analyze.py.", "", f"Label: {res['label']}", ""]
    for t, x in res["targetSources"].items():
        out.append(f"- {t}: {x['numerator']} / {x['denominator']}")
    out.append("")
    for x in res.get("excluded", []):
        out.append(f"Excluded, not analysed: {x['folder']} ({x['target']}, status {x['status']})")
    for t, e in res["targets"].items():
        ca, cb = e["campaigns"]["numerator"], e["campaigns"]["denominator"]
        out += ["", f"## {t}", "", f"Toolchains: {ca} {e['toolchains'][ca]}; {cb} {e['toolchains'][cb]}", "", "| Ratio | label | median ratio | 95% CI |", "|---|---|---|---|"]
        out += [f"| {r['id']} | {r.get('label')} | {r['ratio']} | {r['ci95'][0]} to {r['ci95'][1]} |" for r in e["ratios"]]
    return "\n".join(out) + "\n"


def analyse_campaign(cdir: Path, name: str, smoke: bool, only: str | None = None) -> dict:
    """Summary of a campaign: completed targets analysed, every other target listed under excluded."""
    targets: dict = {}
    excluded: list[dict] = []
    for t in TARGETS:
        if only and t != only:
            continue
        try:
            r = analyse_target(cdir / t)
        except NotCompleted as e:
            excluded.append({"folder": e.folder, "status": e.status, "reason": "env.json status is not completed; never analysed"})
            continue
        if r:
            targets[t] = r
    excluded += set_aside(cdir)
    return {
        "schema": "pqid/v4-chainread-summary/v1",
        "campaign": name,
        "smoke": smoke,
        "rules": (__doc__ or "").split("Rules:")[1].strip(),
        "labels": {"key": DEFAULT_KEY_LABEL, "network": DEFAULT_NETWORK_LABEL, "clients": TRACED_LABEL, "s1": RAW_LABEL},
        "targets": targets,
        "excluded": excluded,
        "r0": r0_summary(cdir),
    }


def parse_cross_targets(items: list[str] | None) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    for it in items or []:
        t, _, pair = it.partition("=")
        xs = [x.strip() for x in pair.split(",")]
        if t not in TARGETS or len(xs) != 2 or not all(xs):
            raise SystemExit(f"analyze: --cross-target expects <anvil|besu>=<numerator campaign>,<denominator campaign> (got {it})")
        out[t] = (xs[0], xs[1])
    return out


def provenance(campaign_dirs: dict[str, Path], targets: list[str]) -> dict[str, object]:
    """Who wrote the summary and when, plus each analysed target's measured start and end (from its
    env.json), so the summary carries its own dating and code hash (provenance audit, 2026-10-04)."""
    import datetime as _dt
    import hashlib as _hl

    measured: dict[str, dict[str, object]] = {}
    for label, cdir in campaign_dirs.items():
        for t in targets:
            env_file = cdir / t / "env.json"
            if env_file.exists():
                env = json.loads(env_file.read_text(encoding="utf-8"))
                measured.setdefault(label, {})[t] = {"startedUtc": env.get("startedUtc"), "finishedUtc": env.get("finishedUtc"),
                                                     "env": relp(env_file)}
    me = Path(__file__).resolve()
    return {
        "generatedBy": "scripts/chainread/analyze.py",
        "generatedUtc": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "sourceSha256": {"scripts/chainread/analyze.py": _hl.sha256(me.read_bytes()).hexdigest()},
        "measured": measured,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--campaign")
    ap.add_argument("--target", choices=TARGETS, help="analyse only this target of --campaign")
    ap.add_argument("--cross", help="<numerator campaign>,<denominator campaign>")
    ap.add_argument("--cross-target", action="append", help="<target>=<numerator>,<denominator>: take this target from other campaigns (repeatable)")
    ap.add_argument("--smoke", action="store_true")
    args = ap.parse_args()
    if not args.campaign and not args.cross:
        ap.error("give --campaign or --cross")
    refuse_if_markers()
    root = SMOKE_ROOT if args.smoke else ROOT
    if args.campaign:
        cdir = root / args.campaign
        res = analyse_campaign(cdir, args.campaign, args.smoke, args.target)
        for x in res["excluded"]:
            print(f"analyze: excluded {x['folder']} (status {x['status']})")
        if not res["targets"]:
            sys.exit(f"analyze: no completed target under {relp(cdir)}")
        suffix = f".{args.target}" if args.target else ""
        res = {"schema": res["schema"], **provenance({args.campaign: cdir}, list(res["targets"])),
               **{k: v for k, v in res.items() if k != "schema"}} if "schema" in res else {**provenance({args.campaign: cdir}, list(res["targets"])), **res}
        (cdir / f"summary{suffix}.json").write_text(json.dumps(res, indent=1) + "\n", encoding="utf8", newline="\n")
        (cdir / f"summary{suffix}.md").write_text(md_campaign(args.campaign, res), encoding="utf8", newline="\n")
        print(f"wrote {relp(cdir / f'summary{suffix}.json')} and summary{suffix}.md ({', '.join(res['targets'])})")
    if args.cross:
        parts = [x.strip() for x in args.cross.split(",")]
        if len(parts) != 2 or not all(parts):
            ap.error("--cross expects <numerator campaign>,<denominator campaign>")
        a, b = parts
        res = {"schema": "pqid/v4-chainread-cross/v1", "smoke": args.smoke, **cross(a, b, root, parse_cross_targets(args.cross_target))}
        for x in res["excluded"]:
            print(f"analyze: excluded {x['folder']} (status {x['status']})")
        if not res["targets"]:
            sys.exit("analyze: no target completed in both campaigns")
        res = {"schema": res["schema"], **provenance({a: root / a, b: root / b}, list(res["targets"])),
               **{k: v for k, v in res.items() if k != "schema"}}
        out = root / "cross_env.json"
        out.write_text(json.dumps(res, indent=1) + "\n", encoding="utf8", newline="\n")
        (root / "cross_env.md").write_text(md_cross(res), encoding="utf8", newline="\n")
        print(f"wrote {relp(out)} and cross_env.md")


if __name__ == "__main__":
    main()
