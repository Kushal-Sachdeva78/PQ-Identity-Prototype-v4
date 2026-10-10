"""Tests for scripts/chainread/analyze.py on a synthetic results root (OS temp dir).

Run: python -m unittest discover -s scripts/chainread -p "test_analyze.py" -v

The synthetic campaign has the chain-read layout (<campaign>/<target>/env.json, passes.jsonl,
s1..s5 *.jsonl.gz, posts.jsonl.gz, <campaign>/r0/e4_verifier.json) with made-up values; nothing
in results/ is read or written.
"""

from __future__ import annotations

import gzip
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import analyze as A  # noqa: E402

VARIANTS = "ABCDEFGHI"
STALL_MS = 10.0  # synthetic per-round-trip batch stall of the variants with ethers' default stall


def write_gz(p: Path, rows: list[dict]) -> None:
    # two gzip members, as the runner writes one member per pass
    half = len(rows) // 2
    with open(p, "wb") as f:
        for part in (rows[:half], rows[half:]):
            f.write(gzip.compress("".join(json.dumps(r) + "\n" for r in part).encode()))


def quiesce(ok: bool = True) -> dict:
    return {"quiesced": ok, "reasons": [] if ok else ["CPU busy 50 % > 35 %"], "machineWideQuiesced": ok, "cpuBusyPercent": 5.0 if ok else 50.0, "stealPercent": None}


def make_target(tdir: Path, chain_scale: float, seed: int, status: str = "completed") -> None:
    rng = np.random.default_rng(seed)
    tdir.mkdir(parents=True)
    env = {
        "status": status,
        "environment": "windows",
        "smoke": False,
        "runtime": {"node": "v24.18.0"},
        "target": {"clientVersion": "anvil/v1.5.1", "endpoint": "loopback, same host"},
        "pinning": {"pinned": False},
        "sourceVsE4": {"equal": True},
        "protocol": {},
        "keyLabel": "dev (v4 Groth16 dev key; proving untimed)",
        "networkLabel": "loopback, same host (D-034)",
    }
    (tdir / "env.json").write_text(json.dumps(env))
    passes = []
    for s in ("s1", "s2", "s3", "s4", "s5"):
        passes.append({"series": s, "status": "ok", "quiesce": quiesce(s != "s4"), "clock": {"hostPauseSuspected": False, "reasons": [], "driftMs": 1.0}, "affinity": None, "affinityMismatchPost": s == "s5"})
    passes.append({"series": "s4", "status": "stopped", "quiesce": quiesce(), "clock": {"hostPauseSuspected": False, "reasons": [], "driftMs": 0.0}, "affinity": None, "affinityMismatchPost": False})
    (tdir / "passes.jsonl").write_text("".join(json.dumps(p) + "\n" for p in passes))
    s1 = []
    for i in range(40):
        for t in ("fetch", "httpKeepAlive", "tcpRawNoDelay"):
            s1.append({"cell": f"single:eth_blockNumber:{t}", "label": A.RAW_LABEL, "ms": float(rng.normal(15 if t == "fetch" else 10, 0.5)), "newConnections": 1 if i == 0 else 0, "status": "ok"})
    write_gz(tdir / "s1_raw.jsonl.gz", s1)
    write_gz(tdir / "s2_fresh.jsonl.gz", [{"cell": "raw:httpFresh:eth_call_resolve", "label": A.RAW_LABEL, "ms": 2.0 + i / 10, "newConnections": 1, "status": "ok"} for i in range(10)])
    write_gz(tdir / "s3_reads.jsonl.gz", [{"cell": "read:asShipped:currentEpoch", "kind": "read", "read": "currentEpoch", "label": "as shipped", "ms": 15.0, "posts": 1, "requests": 2, "depth": 1, "status": "ok"} for _ in range(10)])
    posts_rows: list[dict] = []
    for series, depth_a in (("s4", 7), ("s5", 16)):
        rows = []
        for v in VARIANTS:
            depth = depth_a if v in "ABCDI" else (2 if series == "s4" else 4)
            stall = STALL_MS * depth if v in "ACE" else 0.0
            for i in range(60):
                chain = chain_scale * depth * (1.0 + 0.05 * rng.standard_normal())
                ok = i < 59
                rows.append(
                    {
                        "variant": v,
                        "name": v,
                        "label": "as shipped" if v == "A" else "variant, not shipped",
                        "pass": 1,
                        "attempt": 1,
                        "index": i,
                        "try": 1,
                        "totalMs": chain + stall + 10.0,
                        "chainUnionMs": chain + stall,
                        "chainSumMs": chain + stall,
                        "mlDsaMs": 2.0,
                        "otherMs": 8.0,
                        "outerCalls": 8,
                        "posts": depth,
                        "requests": depth * 2,
                        "depth": depth,
                        "maxInFlight": 1,
                        "tcpConnects": 0,
                        "tcpConnectsUnknown": 0,
                        "status": "ok" if ok else "error",
                    }
                )
                # one POST line per sample; the error try's POST is far slower and must not count
                posts_rows.append({"s": series, "v": v, "p": 1, "a": 1, "i": i, "tr": 1, "ms": (chain / depth) if ok else 999.0, "h": {"ms": 1.0}, "q": [0.5]})
        write_gz(tdir / f"{series}_{'verifier' if series == 's4' else 'wallet'}.jsonl.gz", rows)
    write_gz(tdir / "posts.jsonl.gz", posts_rows)


class AnalyzeChainread(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pqid-cr-analyze-"))
        make_target(self.tmp / "cr_x" / "anvil", 15.0, 1)
        make_target(self.tmp / "cr_y" / "anvil", 11.0, 2)
        r0 = self.tmp / "cr_x" / "r0"
        r0.mkdir()
        d = {"n": 600, "median": 30.0, "q1": 29.0, "q3": 31.0, "iqr": 2.0, "mean": 30.0, "min": 25.0, "max": 40.0, "p95": 35.0}
        (r0 / "e4_verifier.json").write_text(json.dumps({"dry": False, "label": "x", "pinning": {"pinned": True}, "runtime": {}, "results": {"asShipped": {"totalMs": d, "chainMs": d, "rpcRequestsPerPresentation": 14}}}))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_distribution_type7(self) -> None:
        d = A.dist([1, 2, 3, 4, None])
        self.assertEqual(d["n"], 4)
        self.assertEqual(d["median"], 2.5)
        self.assertEqual(d["q1"], 1.75)
        self.assertEqual(d["q3"], 3.25)
        self.assertIsNone(A.dist([]))
        e = A.exact([7, 7, 7])
        self.assertTrue(e["invariant"])
        self.assertFalse(A.exact([7, 8])["invariant"])

    def test_bootstrap_is_seeded_and_brackets_the_ratio(self) -> None:
        rng = np.random.default_rng(0)
        num, den = rng.normal(20, 1, 200), rng.normal(10, 1, 200)
        a = A.boot_ratio(num, den, "t:1")
        b = A.boot_ratio(num, den, "t:1")
        c = A.boot_ratio(num, den, "t:2")
        self.assertEqual(a, b)
        self.assertNotEqual(a["ci95"], c["ci95"])
        self.assertEqual(a["seed"], 20260927)
        self.assertEqual(a["B"], 10_000)
        self.assertLess(a["ci95"][0], a["ratio"])
        self.assertGreater(a["ci95"][1], a["ratio"])
        self.assertIsNone(A.boot_ratio([], den, "t:3"))

    def test_target_summary(self) -> None:
        res = A.analyse_target(self.tmp / "cr_x" / "anvil")
        s4 = res["s4"]["variants"]
        self.assertEqual(set(s4), set(VARIANTS))
        self.assertEqual(s4["A"]["totalMs"]["n"], 59)  # the error sample is counted, never analysed
        self.assertEqual(s4["A"]["depth"]["median"], 7.0)
        self.assertTrue(s4["A"]["depth"]["invariant"])
        self.assertEqual(s4["G"]["depth"]["median"], 2.0)
        ids = {r["id"] for r in res["s4"]["ratios"]}
        self.assertIn("s4:G/A:chainUnionMs", ids)
        g = next(r for r in res["s4"]["ratios"] if r["id"] == "s4:G/A:chainUnionMs")
        self.assertLess(g["ratio"], 0.4)
        q = res["quality"]
        self.assertEqual(q["s4"]["passesBusyFlagged"], 1)
        self.assertEqual(q["s4"]["passesMachineWideBusy"], 1)
        self.assertEqual(q["s4"]["passesStopped"], 1)
        self.assertEqual(q["s4"]["passesDiscardedBattery"], 0)
        self.assertEqual(q["s5"]["passesAffinityMismatchPost"], 1)
        self.assertEqual(q["s4"]["samplesError"], 9)
        s1 = res["s1"]
        self.assertEqual(s1["cells"]["single:eth_blockNumber:fetch"]["newConnections"], 1)
        self.assertEqual(s1["cells"]["single:eth_blockNumber:fetch"]["label"], A.RAW_LABEL)
        self.assertTrue(any(r["id"] == "s1:eth_blockNumber:httpKeepAlive/fetch" for r in s1["ratios"]))
        self.assertTrue(res["labels"]["key"].startswith("dev"))
        self.assertEqual(res["labels"]["endpoint"], "loopback, same host")

    def test_per_post_distributions_use_only_the_posts_of_used_samples(self) -> None:
        res = A.analyse_target(self.tmp / "cr_x" / "anvil")
        pp = res["s4"]["variants"]["A"]["perPost"]["postMs"]
        self.assertEqual(pp["n"], 59)
        self.assertLess(pp["max"], 999.0)

    def test_deployment_model_keeps_the_loopback_time_and_the_stall(self) -> None:
        res = A.analyse_target(self.tmp / "cr_x" / "anvil")
        dm = res["derived"]
        self.assertTrue(dm["label"].startswith("[S]"))
        s4 = res["s4"]["variants"]
        ver = dm["deploymentModel"]["A"]["verifier"]
        self.assertAlmostEqual(ver["rtt20ms"], 7 * 20 + s4["A"]["totalMs"]["median"], places=3)
        self.assertAlmostEqual(ver["loopbackTotalMsMedian"], s4["A"]["totalMs"]["median"], places=3)
        # A (stall on) and B (stall off) have the same depth: the model keeps their loopback gap,
        # which is about 7 x the synthetic 10 ms stall, at every RTT
        b = dm["deploymentModel"]["B"]["verifier"]
        for t in A.RTTS_MS:
            gap = ver[f"rtt{t}ms"] - b[f"rtt{t}ms"]
            self.assertAlmostEqual(gap, s4["A"]["totalMs"]["median"] - s4["B"]["totalMs"]["median"], places=3)
            self.assertGreater(gap, 7 * STALL_MS * 0.8)
        self.assertIn("upper bound", dm["deploymentModelRule"])

    def test_r0_and_cross(self) -> None:
        r0 = A.r0_summary(self.tmp / "cr_x")
        self.assertEqual(r0["verifier"]["results"]["asShipped"]["rpcRequestsPerPresentation"], 14)
        self.assertIn("unpinned", r0["topology"])
        self.assertIsNone(A.r0_summary(self.tmp / "cr_y"))
        x = A.cross("cr_x", "cr_y", self.tmp)
        self.assertTrue(x["label"].startswith("cross-environment"))
        self.assertIn("dev key", x["label"])
        self.assertIn("loopback, same host", x["label"])
        rs = x["targets"]["anvil"]["ratios"]
        a = next(r for r in rs if r["id"] == "xenv:anvil:s4:A:chainUnionMs:cr_x/cr_y")
        # chain time with the synthetic stall: (15 x 7 + 70) / (11 x 7 + 70)
        self.assertAlmostEqual(a["ratio"], (15 * 7 + 70) / (11 * 7 + 70), delta=0.05)
        self.assertEqual(a["label"], "as shipped")
        self.assertIn("# Chain-read cross-environment ratios", A.md_cross(x))

    def test_incomplete_target_is_excluded_and_the_rest_is_analysed(self) -> None:
        make_target(self.tmp / "cr_x" / "besu", 15.0, 3, status="stopped")
        make_target(self.tmp / "cr_x" / "besu.failed-20261004T000000Z", 15.0, 4, status="failed")
        with self.assertRaises(A.NotCompleted):
            A.analyse_target(self.tmp / "cr_x" / "besu")
        res = A.analyse_campaign(self.tmp / "cr_x", "cr_x", False)
        self.assertEqual(list(res["targets"]), ["anvil"])
        st = {x["folder"].split("/")[-1]: x["status"] for x in res["excluded"]}
        self.assertEqual(st, {"besu": "stopped", "besu.failed-20261004T000000Z": "failed"})
        md = A.md_campaign("cr_x", res)
        self.assertIn("Excluded, not analysed", md)
        self.assertIn("dev key", md)
        only = A.analyse_campaign(self.tmp / "cr_x", "cr_x", False, "besu")
        self.assertEqual(only["targets"], {})

    def test_cross_takes_a_target_from_other_campaigns(self) -> None:
        make_target(self.tmp / "cr_x" / "besu", 15.0, 3, status="stopped")
        make_target(self.tmp / "cr_y" / "besu", 11.0, 5)
        make_target(self.tmp / "cr_x_b" / "besu", 15.0, 6)
        x = A.cross("cr_x", "cr_y", self.tmp)
        self.assertNotIn("besu", x["targets"])
        self.assertEqual([e["status"] for e in x["excluded"]], ["stopped"])
        y = A.cross("cr_x", "cr_y", self.tmp, A.parse_cross_targets(["besu=cr_x_b,cr_y"]))
        self.assertEqual(y["targets"]["besu"]["campaigns"], {"numerator": "cr_x_b", "denominator": "cr_y"})
        self.assertEqual(y["targetSources"]["besu"], {"numerator": "cr_x_b", "denominator": "cr_y"})
        self.assertEqual(y["targetSources"]["anvil"], {"numerator": "cr_x", "denominator": "cr_y"})
        self.assertTrue(any(r["id"].endswith(":cr_x_b/cr_y") for r in y["targets"]["besu"]["ratios"]))
        with self.assertRaises(SystemExit):
            A.parse_cross_targets(["geth=a,b"])


if __name__ == "__main__":
    unittest.main()
