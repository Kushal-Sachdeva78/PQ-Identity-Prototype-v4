"""Tests for scripts/e2e/analyze_e2e.py on synthetic results roots (OS temp dirs).

Run: python -m unittest discover -s scripts/e2e -p "test_analyze_e2e.py" -v

The synthetic roots hold made-up timings (anvil and besu); nothing in results/ is read or
written. Skipped while results/v4/bench/RUNNING or results/v4/BUSY exists (no analyses during a
timed run or heavy work, docs/BENCHMARK_POLICY.md and D-034).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SCRIPT = HERE / "analyze_e2e.py"
STAGES = ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11"]
MARKERS = [REPO / "results" / "v4" / "bench" / "RUNNING", REPO / "results" / "v4" / "BUSY"]


def report(e2e: float, posts_wallet: int = 17, connects_wallet: int = 1, http429: int = 0) -> dict:
    """A report whose stages add up to e2e (S8 takes the rest)."""
    fixed = {"S1": 5.0, "S2": 0.05, "S3": 100.0, "S4": 1.0, "S5": 150.0, "S6": 0.2, "S7": 6.0, "S9": 0.3, "S10": 0.02, "S11": 110.0}
    ms = dict(fixed)
    ms["S8"] = e2e - sum(fixed.values())
    posts = {s: {"verifier": 0, "wallet": 0} for s in STAGES}
    posts["S1"]["verifier"] = 1
    posts["S3"]["wallet"] = 7
    posts["S5"]["wallet"] = posts_wallet - 7
    posts["S11"]["verifier"] = 7
    stages = {}
    for s in STAGES:
        p = posts[s]
        stages[s] = {"ms": ms[s], "postsByParty": p, "requests": 2 * (p["verifier"] + p["wallet"]), "connects": (1 if s == "S1" else connects_wallet if s == "S3" else 0)}
    return {
        "stages": stages,
        "verifySplit": {"chainMs": 90.0, "mlDsaMs": 1.0, "mlKemDecapsMs": 0.2, "otherMs": 18.8},
        "totals": {
            "chainMsByParty": {"verifier": 95.0, "wallet": 240.0},
            "postsByParty": {"verifier": 8, "wallet": posts_wallet},
            "requestsByParty": {"verifier": 16, "wallet": 2 * posts_wallet},
            "connectsByParty": {"verifier": 1, "wallet": connects_wallet},
            "http429": http429,
        },
        "gcTotals": {"count": 2, "ms": 1.5, "majorCount": 1 if e2e > 2600 else 0, "majorMs": 1.0, "outsideWindows": 0},
    }


def run_rec(campaign: str, mode: str, slot: int, block: int, endpoint: str, e2e: float, status: str = "ok", control: bool = False, session: str = "s1", warmup: bool = False, conns: dict | None = None, error_kind: str | None = None, http429: int = 0, **extra) -> dict:
    rep = None if control else report(e2e, http429=http429, **extra)
    res = {
        "ok": status == "ok",
        "errorKind": error_kind,
        "endToEndMs": e2e,
        "report": rep,
        "connections": conns or {"verifier": 1, "wallet": 1},
        "aux": {"rttProbe": {"blockNumberMs": [1.0, 2.0, 3.0]}} if mode == "cold" else {"partyIdleMsAtStart": {"verifier": 1500.0, "wallet": 4000.0}},
    }
    return {
        "type": "run", "campaign": campaign, "mode": mode, "session": session, "slot": slot, "block": block, "pos": 0,
        "warmup": warmup, "condition": endpoint + (":control" if control else ""), "endpoint": endpoint, "control": control,
        "setupId": "ab" * 12, "labels": ["loopback, same host", f"one-process {mode}", "dev key"], "status": status,
        "quiesce": {"quiesced": True}, "hostPauseSuspected": slot == 1, "clockGapSec": 0.0, "result": res,
    }


def env(campaign: str, mode: str, prover: str = "snarkjs", endpoints: tuple[str, ...] = ("anvil", "besu")) -> dict:
    eps = [{"id": e, "kind": e, "label": e} for e in endpoints]
    return {
        "campaign": campaign, "mode": mode, "label": "synthetic", "keyLabel": "dev",
        "stable": {"prover": {"name": prover}},
        "protocol": {"e2e": {"normativeSha256": "0" * 64}},
        "sessions": [{"environment": "wsl2", "endpoints": eps}],
    }


def write_campaign(root: Path, name: str, e: dict, recs: list[dict]) -> None:
    d = root / name
    d.mkdir(parents=True)
    (d / "env.json").write_text(json.dumps(e), encoding="utf-8")
    (d / "runs.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")


COLD_ANVIL = [2500.0, 2600.0, 2550.0, 2700.0, 2450.0]
COLD_BESU = [2800.0, 2900.0, 2850.0, 3000.0, 2750.0]
COLD_ANVIL_RS = [900.0, 950.0, 1000.0]
WARM_ANVIL = [1200.0, 1250.0, 1150.0]
WARM_BESU = [1500.0, 1550.0, 1450.0]


def build_root(root: Path) -> None:
    recs = []
    slot = 0
    for i in range(5):
        recs.append(run_rec("e2e_cold_test", "cold", slot, i, "anvil", COLD_ANVIL[i], posts_wallet=(18 if i == 4 else 17)))
        slot += 1
        recs.append(run_rec("e2e_cold_test", "cold", slot, i, "besu", COLD_BESU[i]))
        slot += 1
    recs.append(run_rec("e2e_cold_test", "cold", 0, 0, "anvil", 99999.0, status="error", error_kind="rpc", http429=2))
    recs.append(run_rec("e2e_cold_test", "cold", 1, 0, "besu", 99999.0, status="discarded-battery"))
    recs.append({"type": "campaign-end", "campaign": "e2e_cold_test", "complete": True})
    write_campaign(root, "e2e_cold_test", env("e2e_cold_test", "cold"), recs)

    # the same condition with another prover: its own group, never pooled or paired with snarkJS
    recs = [run_rec("e2e_cold_rs_test", "cold", i, i, "anvil", x) for i, x in enumerate(COLD_ANVIL_RS)]
    recs.append({"type": "campaign-end", "campaign": "e2e_cold_rs_test", "complete": True})
    write_campaign(root, "e2e_cold_rs_test", env("e2e_cold_rs_test", "cold", prover="rapidsnark", endpoints=("anvil",)), recs)

    recs = [{"type": "session-start", "session": "s0"}]
    # an older complete session that must be ignored, and a warm-up block
    recs.append(run_rec("e2e_warm_test", "warm", 0, 0, "anvil", 5000.0, session="s0"))
    recs.append({"type": "session-end", "session": "s0", "complete": True})
    recs.append(run_rec("e2e_warm_test", "warm", 0, -1, "anvil", 7000.0, session="s1", warmup=True))
    # slots of block b: 1 + 4b .. 4 + 4b (anvil, anvil:control, besu, besu:control)
    for b in range(3):
        base = 1 + 4 * b
        if b == 1:
            # first attempt of block 1: anvil ran, its control ran, then besu failed. The fixed runner
            # writes anvil as discarded-block-error; the control is written "ok" as the old runner
            # did (the analysis's safety net keeps only the last ok record per session and slot).
            recs.append(run_rec("e2e_warm_test", "warm", base, b, "anvil", 88888.0, session="s1", status="discarded-block-error", connects_wallet=0))
            recs.append(run_rec("e2e_warm_test", "warm", base + 1, b, "anvil", 77777.0, session="s1", control=True))
            recs.append(run_rec("e2e_warm_test", "warm", base + 2, b, "besu", 99999.0, session="s1", status="error", error_kind="wallet"))
        for k, (ep, xs) in enumerate((("anvil", WARM_ANVIL), ("besu", WARM_BESU))):
            recs.append(run_rec("e2e_warm_test", "warm", base + 2 * k, b, ep, xs[b], session="s1", connects_wallet=0))
            # block 2's anvil control reused a socket: that block is left out of the overhead ratio
            ctl_conns = {"verifier": 0, "wallet": 1} if (b == 2 and ep == "anvil") else None
            recs.append(run_rec("e2e_warm_test", "warm", base + 2 * k + 1, b, ep, xs[b] * 0.98, session="s1", control=True, conns=ctl_conns))
    recs.append({"type": "session-end", "session": "s1", "complete": True})
    write_campaign(root, "e2e_warm_test", env("e2e_warm_test", "warm"), recs)


def run_analysis(root: Path) -> dict:
    p = subprocess.run([sys.executable, str(SCRIPT), "--root", str(root), "--B", "2000"], capture_output=True, text=True)
    if p.returncode != 0:
        raise AssertionError(p.stderr)
    return json.loads((root / "summary.json").read_text(encoding="utf-8"))


SNARK = "snarkjs|dev"


@unittest.skipIf(any(m.exists() for m in MARKERS), "a timed run or heavy work is active (results/v4/bench/RUNNING or results/v4/BUSY)")
class AnalyzeE2eTest(unittest.TestCase):
    tmp: Path
    summary: dict

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="pqid-e2e-analysis-"))
        build_root(cls.tmp)
        cls.summary = run_analysis(cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_writes_both_files(self) -> None:
        self.assertTrue((self.tmp / "summary.md").exists())
        self.assertIn(f"anvil|cold|instrumented|{SNARK}", (self.tmp / "summary.md").read_text(encoding="utf-8"))

    def test_rows_used(self) -> None:
        g = self.summary["groups"]
        self.assertEqual(g[f"anvil|cold|instrumented|{SNARK}"]["n"], 5)  # error and discarded records not analysed
        self.assertEqual(g[f"besu|cold|instrumented|{SNARK}"]["n"], 5)
        self.assertEqual(g[f"anvil|warm|instrumented|{SNARK}"]["n"], 3)  # latest complete session, no warm-up
        self.assertEqual(g[f"anvil|warm|control|{SNARK}"]["n"], 3)
        self.assertAlmostEqual(g[f"anvil|cold|instrumented|{SNARK}"]["endToEndMs"]["median"], float(np.median(COLD_ANVIL)))
        self.assertAlmostEqual(g[f"besu|warm|instrumented|{SNARK}"]["endToEndMs"]["median"], float(np.median(WARM_BESU)))
        self.assertNotIn("stagesMs", g[f"anvil|warm|control|{SNARK}"])  # controls give endToEnd only
        books = {b["campaign"]: b for b in self.summary["campaigns"]}
        self.assertEqual(books["e2e_cold_test"]["errors"], 1)
        self.assertEqual(books["e2e_cold_test"]["discardedBattery"], 1)
        self.assertEqual(books["e2e_cold_test"]["usedIdlePause"], 1)  # slot 1 flagged, kept and counted
        self.assertEqual(books["e2e_warm_test"]["warmSession"]["used"], "s1")

    def test_errored_then_repeated_warm_block(self) -> None:
        g = self.summary["groups"]
        for ep in ("anvil", "besu"):
            for v in ("instrumented", "control"):
                self.assertEqual(g[f"{ep}|warm|{v}|{SNARK}"]["n"], 3, f"{ep} {v}")
        # the stale "ok" control of the failed attempt is dropped (last ok per session and slot)
        self.assertAlmostEqual(g[f"anvil|warm|control|{SNARK}"]["endToEndMs"]["median"], float(np.median([x * 0.98 for x in WARM_ANVIL])))
        self.assertLess(g[f"anvil|warm|instrumented|{SNARK}"]["endToEndMs"]["max"], 2000.0)
        books = {b["campaign"]: b for b in self.summary["campaigns"]}
        self.assertEqual(books["e2e_warm_test"]["discardedBlockError"], 1)
        self.assertEqual(books["e2e_warm_test"]["duplicateOkDropped"], 1)
        self.assertEqual(books["e2e_warm_test"]["byEndpoint"]["besu"]["errorKinds"], {"wallet": 1})

    def test_prover_is_part_of_the_group_and_never_paired_across(self) -> None:
        g = self.summary["groups"]
        rs = g["anvil|cold|instrumented|rapidsnark|dev"]
        self.assertEqual(rs["n"], len(COLD_ANVIL_RS))
        self.assertEqual(rs["campaigns"], ["e2e_cold_rs_test"])
        self.assertAlmostEqual(rs["endToEndMs"]["median"], float(np.median(COLD_ANVIL_RS)))
        self.assertEqual(g[f"anvil|cold|instrumented|{SNARK}"]["campaigns"], ["e2e_cold_test"])
        self.assertEqual(self.summary["notPooled"], [])
        for r in self.summary["ratios"]:
            self.assertEqual(r["numerator"].split("|")[3:5], r["denominator"].split("|")[3:5], r["id"])
        self.assertFalse(any("rapidsnark" in r["id"] for r in self.summary["ratios"]))  # no warm rapidsnark group to pair with

    def test_stages_add_up_and_round_trips_modal(self) -> None:
        g = self.summary["groups"][f"anvil|cold|instrumented|{SNARK}"]
        med = sum(g["stagesMs"][s]["median"] for s in STAGES if s != "S8")
        self.assertGreater(g["stagesMs"]["S8"]["median"], 0)
        self.assertGreater(g["endToEndMs"]["median"], med)
        rt = g["roundTrips"]["S5"]
        self.assertEqual(rt["mode"], {"verifier": 0, "wallet": 10})
        self.assertEqual([d["run"] for d in rt["deviating"]], ["e2e_cold_test#s1#8"])
        self.assertEqual(g["newConnectionsTotal"]["mode"], {"verifier": 1, "wallet": 1})
        self.assertEqual(self.summary["groups"][f"anvil|warm|instrumented|{SNARK}"]["newConnectionsTotal"]["mode"], {"verifier": 1, "wallet": 0})
        self.assertAlmostEqual(g["chainShare"]["median"], float(np.median([335.0 / x for x in COLD_ANVIL])))
        # wallet part S2..S10 = endToEnd - S1 - S11 here
        self.assertAlmostEqual(g["walletPartMs"]["median"], float(np.median(COLD_ANVIL)) - 115.0)
        self.assertAlmostEqual(g["verifierPartMs"]["median"], 115.0)
        self.assertEqual(g["gc"]["runsWithMajorGc"], 1)

    def test_new_connection_split_sensitivity_and_endpoint_books(self) -> None:
        g = self.summary["groups"]
        cold = g[f"anvil|cold|instrumented|{SNARK}"]["byNewConnections"]
        self.assertEqual(list(cold["S3"].keys()), ["1+"])
        self.assertEqual(cold["S3"]["1+"]["n"], 5)
        warm = g[f"anvil|warm|instrumented|{SNARK}"]["byNewConnections"]
        self.assertEqual(warm["S3"]["0"]["n"], 3)
        self.assertEqual(warm["S11"]["0"]["n"], 3)
        ctl = g[f"anvil|warm|control|{SNARK}"]["byNewConnections"]["endToEndMs"]
        self.assertEqual(ctl["1+"]["n"], 3)
        self.assertIn("partyIdleMsAtStart", g[f"anvil|warm|control|{SNARK}"])
        sens = g[f"besu|cold|instrumented|{SNARK}"]["sensitivity"]
        self.assertEqual((sens["n"], sens["excluded"]), (4, 1))  # slot 1 (besu) has hostPauseSuspected
        self.assertAlmostEqual(sens["endToEndMs"]["median"], float(np.median(COLD_BESU[1:])))
        books = {b["campaign"]: b for b in self.summary["campaigns"]}
        anvil = books["e2e_cold_test"]["byEndpoint"]["anvil"]
        self.assertEqual((anvil["ok"], anvil["error"], anvil["errorKinds"], anvil["http429"]), (5, 1, {"rpc": 1}, 2))
        self.assertEqual(books["e2e_cold_test"]["byEndpoint"]["besu"]["discarded-battery"], 1)

    def test_ratios_and_campaign_flags(self) -> None:
        r = {x["id"]: x for x in self.summary["ratios"]}
        ba = r[f"besuAnvil|cold|{SNARK}|endToEndMs"]
        self.assertTrue(ba["sameCampaign"])
        self.assertAlmostEqual(ba["value"], float(np.median(COLD_BESU)) / float(np.median(COLD_ANVIL)))
        self.assertLessEqual(ba["ci95"][0], ba["value"])
        self.assertGreaterEqual(ba["ci95"][1], ba["value"])
        cw = r[f"coldWarm|anvil|{SNARK}|endToEndMs"]
        self.assertFalse(cw["sameCampaign"])
        self.assertAlmostEqual(cw["value"], float(np.median(COLD_ANVIL)) / float(np.median(WARM_ANVIL)))
        ov = r[f"overhead|anvil|{SNARK}"]
        self.assertTrue(ov["sameCampaign"])
        self.assertEqual((ov["pairedBlocks"], ov["unmatchedBlocks"]), (2, 1))  # block 2's connections differ
        self.assertAlmostEqual(ov["value"], 1 / 0.98)
        self.assertEqual(r[f"overhead|besu|{SNARK}"]["pairedBlocks"], 3)

    def test_deterministic_apart_from_the_timestamp(self) -> None:
        again = run_analysis(self.tmp)
        a = dict(self.summary)
        b = dict(again)
        a.pop("generatedUtc")
        b.pop("generatedUtc")
        self.assertEqual(a, b)


@unittest.skipIf(any(m.exists() for m in MARKERS), "a timed run or heavy work is active (results/v4/bench/RUNNING or results/v4/BUSY)")
class NotPooledTest(unittest.TestCase):
    """The same condition (endpoint, mode, prover, key) in two campaigns is kept apart, never pooled."""

    def test_two_campaigns_of_one_condition(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="pqid-e2e-analysis-np-"))
        try:
            for name, xs in (("e2e_cold_a", [1000.0, 1100.0, 1050.0]), ("e2e_cold_b", [2000.0, 2100.0])):
                recs = [run_rec(name, "cold", i, i, "anvil", x) for i, x in enumerate(xs)]
                write_campaign(tmp, name, env(name, "cold", endpoints=("anvil",)), recs)
            s = run_analysis(tmp)
            self.assertEqual(s["notPooled"], [{"group": f"anvil|cold|instrumented|{SNARK}", "campaigns": ["e2e_cold_a", "e2e_cold_b"]}])
            self.assertEqual(s["groups"][f"anvil|cold|instrumented|{SNARK}|e2e_cold_a"]["n"], 3)
            self.assertEqual(s["groups"][f"anvil|cold|instrumented|{SNARK}|e2e_cold_b"]["n"], 2)
            self.assertNotIn(f"anvil|cold|instrumented|{SNARK}", s["groups"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
