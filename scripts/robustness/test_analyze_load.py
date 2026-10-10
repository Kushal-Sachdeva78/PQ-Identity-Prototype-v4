"""Tests for scripts/robustness/analyze_load.py on a synthetic load campaign (OS temp dir).

Run: python -m unittest discover -s scripts/robustness -p "test_analyze_load.py" -v

The synthetic campaign has the load-test layout with made-up numbers; nothing in results/ is
read or written.
"""

from __future__ import annotations

import json
import math
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze_load as A  # noqa: E402


def write_jsonl(p: Path, rows: list[dict]) -> None:
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


class ClopperPearson(unittest.TestCase):
    def test_closed_forms(self) -> None:
        lo, hi = A.clopper_pearson(0, 100)
        self.assertEqual(lo, 0.0)
        self.assertAlmostEqual(hi, 1 - 0.025 ** (1 / 100), places=9)
        lo, hi = A.clopper_pearson(100, 100)
        self.assertAlmostEqual(lo, 0.025 ** (1 / 100), places=9)
        self.assertEqual(hi, 1.0)
        self.assertIsNone(A.clopper_pearson(0, 0))

    def test_symmetry_and_order(self) -> None:
        lo, hi = A.clopper_pearson(5, 100)
        lo2, hi2 = A.clopper_pearson(95, 100)
        self.assertAlmostEqual(lo, 1 - hi2, places=9)
        self.assertAlmostEqual(hi, 1 - lo2, places=9)
        self.assertTrue(0 < lo < 0.05 < hi < 0.2)


class Analyse(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="pqid-load-test-"))
        levels = {"P": 4, "R": 2, "workers": [1, 2], "conc": [1]}
        (self.dir / "schedule.json").write_text(json.dumps({"campaign": "t", "smoke": True, "levels": levels}), encoding="utf-8")
        (self.dir / "env.json").write_text(json.dumps({"replicas": "per-worker stores", "pinning": "unpinned"}), encoding="utf-8")
        blocks = [{"block": 0, "attempt": 0, "measured": False, "status": "ok"}]
        runs: list[dict] = []
        hostile: list[dict] = []
        corr: list[dict] = []
        for b in (1, 2, 3):
            blocks.append({"block": b, "attempt": 0, "measured": True, "status": "ok", "flaggedBusy": b == 3})
            for W, rate in ((1, 10.0 * b), (2, 18.0 * b)):
                cid = f"tp:asShipped:W{W}:c1"
                head = {"block": b, "attempt": 0, "measured": True, "blockStatus": "ok", "cell": cid, "variant": "asShipped", "W": W, "c": 1}
                for w in range(W):
                    outcomes = ["accepted", "accepted"] if not (b == 2 and W == 2 and w == 1) else ["accepted", "rejected:groth16"]
                    runs.append({"type": "worker", **head, "worker": w, "latMs": [100.0 * b, 100.0 * b + 10], "outcomes": outcomes, "rpc": {"posts": 14, "requests": 28}, "firstVerificationInWorker": {"ms": 500.0}})
                runs.append({"type": "pass", **head, "steadyPerSec": rate})
            for cls, lat, exp in (("HC0", 100.0, "accepted"), ("HC4", 110.0, "rejected:nonceBinding"), ("HC1", 1.0, "rejected:transcriptDecrypts")):
                hostile.append({"block": b, "attempt": 0, "measured": True, "blockStatus": "ok", "variant": "asShipped", "cls": cls, "expected": exp, "latMs": [lat * b, lat * b], "outcomes": [exp] * 2, "rpc": {"posts": 14 if cls != "HC1" else 0, "requests": 28 if cls != "HC1" else 0}})
            corr.append({"block": b, "attempt": 0, "measured": True, "blockStatus": "ok", "items": 10, "metrics": {"acceptedCopiesPerDuplicateGroup": [1, 1], "misclassifiedItems": 0, "sessionsConsumedByRejectedReplies": 0, "honestAfterHostileAccepted": 1, "honestAfterHostileTotal": 1}})
        # a discarded block is counted, never analysed
        blocks.append({"block": 4, "attempt": 0, "measured": True, "status": "discarded-battery"})
        runs.append({"type": "worker", "block": 4, "attempt": 0, "measured": True, "blockStatus": "discarded-battery", "cell": "tp:asShipped:W1:c1", "variant": "asShipped", "W": 1, "c": 1, "worker": 0, "latMs": [9999.0], "outcomes": ["error:timeout"], "rpc": {"posts": 0, "requests": 0}})
        write_jsonl(self.dir / "blocks.jsonl", blocks)
        write_jsonl(self.dir / "runs.jsonl", runs)
        write_jsonl(self.dir / "hostile.jsonl", hostile)
        write_jsonl(self.dir / "correctness.jsonl", corr)

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_summary(self) -> None:
        s = A.analyse(self.dir, B=300, seed=20260927)
        self.assertEqual(s["blocks"]["byStatus"], {"ok": 4, "discarded-battery": 1})
        self.assertEqual(s["blocks"]["measuredOk"], 3)
        self.assertEqual(s["blocks"]["measuredOkFlaggedBusy"], 1)
        cells = {c["cell"]: c for c in s["cells"]}
        w1 = cells["tp:asShipped:W1:c1"]
        self.assertEqual(w1["latencyMs"]["n"], 6)  # the discarded block's 9999 ms is not used
        self.assertEqual(w1["latencyMs"]["max"], 310.0)
        self.assertEqual(w1["steadyRatePerSec"]["median"], 20.0)
        self.assertEqual(w1["rpcPerVerification"], {"posts": 7.0, "requests": 14.0})
        w2 = cells["tp:asShipped:W2:c1"]
        self.assertEqual(w2["errors"]["errors"], 1)
        self.assertEqual(w2["errors"]["attempts"], 12)
        # the rejected honest item (210 ms) is an error item, not a latency sample
        self.assertEqual(w2["latencyMs"]["n"], 11)
        self.assertEqual(w2["errorItems"]["count"], 1)
        self.assertEqual(w2["errorItems"]["latMs"], [210.0])
        self.assertEqual(s["errorsThroughputCells"]["errors"], 1)
        # throughput 18 items and HC0 6 items; this fixture's correctness rows carry no item outcomes
        self.assertEqual(s["errorsAllHonest"]["attempts"], 18 + 6 + 0)
        sc = s["scaling"][0]
        self.assertAlmostEqual(sc["speedup"], 36.0 / 20.0)
        self.assertAlmostEqual(sc["efficiency"], 0.9)
        lo, hi = sc["speedupCi95"]
        self.assertTrue(lo <= 1.8 <= hi)  # every block has ratio 1.8
        hc = {r["cls"]: r for r in s["hostile"]}
        self.assertAlmostEqual(hc["HC4"]["amplificationVsHC0"]["ratioOfMedians"], 1.1)
        self.assertEqual(hc["HC1"]["latencyMs"]["n"], 6)
        self.assertEqual(hc["HC1"]["unexpectedOutcomes"], 0)
        self.assertEqual(hc["HC4"]["acceptedHostile"], 0)
        self.assertEqual(hc["HC1"]["rpcPerItem"]["posts"], 0.0)
        self.assertTrue(s["correctness"]["meetsRequired"])
        self.assertEqual(s["correctness"]["duplicateGroups"], 6)
        self.assertEqual(s["aux"]["firstVerificationInWorker"]["0"]["ms"], 500.0)
        md = A.markdown(s)
        self.assertIn("never verifier capacity", md)
        self.assertNotIn(chr(0x2014), md)  # no em dashes in generated text

    def test_amplification_formats_small_ratios(self) -> None:
        s = A.analyse(self.dir, B=300, seed=20260927)
        md = A.markdown(s)
        self.assertIn("| HC1 | asShipped | rejected:transcriptDecrypts |", md)
        self.assertIn(" 0.01 ", md)  # HC1/HC0 = 1/100 with three significant figures, not 0.000
        self.assertIn("ethers JSON-RPC batching", md)

    def test_bootstrap_is_seeded(self) -> None:
        a = A.analyse(self.dir, B=300, seed=1)
        b = A.analyse(self.dir, B=300, seed=1)
        self.assertEqual(a["cells"], b["cells"])
        self.assertTrue(math.isfinite(a["cells"][0]["latencyMs"]["median"]))


class ErrorItemsAndDiscards(unittest.TestCase):
    """Honest items that were rejected or timed out are error items: counted, never latency samples.
    A clock-gap block and a replacement warm-up are counted, never analysed."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="pqid-load-test-"))
        (self.dir / "schedule.json").write_text(json.dumps({"campaign": "e", "smoke": True, "levels": {}}), encoding="utf-8")
        cid = "tp:asShipped:W1:c1"
        blocks = [{"record": "block", "block": 0, "attempt": 0, "measured": False, "status": "ok"}]
        runs: list[dict] = []
        hostile: list[dict] = []
        corr: list[dict] = []
        for b in (1, 2):
            blocks.append({"record": "block", "block": b, "attempt": 0, "measured": True, "status": "ok", "replacedWorkers": [0] if b == 2 else []})
            head = {"block": b, "attempt": 0, "measured": True, "blockStatus": "ok", "cell": cid, "variant": "asShipped", "W": 1, "c": 1}
            lat = [100.0, 101.0, 102.0, 103.0]
            out = ["accepted"] * 4
            if b == 2:
                lat = [100.0, 50.0, 30000.0, 103.0]
                out = ["accepted", "rejected:groth16", "error:timeout", "accepted"]
            runs.append({"type": "worker", **head, "worker": 0, "expected": "accepted", "latMs": lat, "outcomes": out, "rpc": {"posts": 4, "requests": 8}})
            runs.append({"type": "pass", **head, "steadyPerSec": 9.0})
            hostile.append({"block": b, "attempt": 0, "measured": True, "blockStatus": "ok", "variant": "asShipped", "cls": "HC0", "expected": "accepted", "latMs": [100.0, 30000.0 if b == 2 else 100.0], "outcomes": ["accepted", "error:timeout" if b == 2 else "accepted"], "rpc": {"posts": 2, "requests": 4}})
            hostile.append({"block": b, "attempt": 0, "measured": True, "blockStatus": "ok", "variant": "asShipped", "cls": "HC5", "expected": "rejected:groth16", "latMs": [90.0, 5.0], "outcomes": ["rejected:groth16", "rejected:nonceBinding"], "rpc": {"posts": 2, "requests": 4}})
            corr.append({"block": b, "attempt": 0, "measured": True, "blockStatus": "ok", "items": 3, "expectA": ["accepted", "rejected:HC1"], "outcomesA": ["accepted", "rejected:transcriptDecrypts"], "outcomesB": ["accepted"], "metrics": {"acceptedCopiesPerDuplicateGroup": [1], "misclassifiedItems": 0, "sessionsChecked": 3, "sessionsConsumedByRejectedReplies": 0, "honestAfterHostileAccepted": 1, "honestAfterHostileTotal": 1}})
        # a block discarded for a clock gap, and a replacement warm-up pass: counted, never analysed
        blocks.append({"record": "block", "block": 3, "attempt": 0, "measured": True, "status": "discarded-clock-gap"})
        runs.append({"type": "worker", "block": 3, "attempt": 0, "measured": True, "blockStatus": "discarded-clock-gap", "cell": cid, "variant": "asShipped", "W": 1, "c": 1, "worker": 0, "latMs": [99999.0], "outcomes": ["accepted"], "rpc": {"posts": 1, "requests": 2}})
        blocks.append({"record": "replacementWarmup", "worker": 0, "afterBlock": 1, "afterAttempt": 0, "variant": "asShipped", "latMs": [8000.0], "analysed": False})
        write_jsonl(self.dir / "blocks.jsonl", blocks)
        write_jsonl(self.dir / "runs.jsonl", runs)
        write_jsonl(self.dir / "hostile.jsonl", hostile)
        write_jsonl(self.dir / "correctness.jsonl", corr)
        (self.dir / "auxiliary.json").write_text(json.dumps({"firstVerificationInWorker": {"0": {"ms": 7000.0, "accepted": True}}, "replacements": [{"worker": 0}]}), encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_error_items_are_not_latency(self) -> None:
        s = A.analyse(self.dir, B=200, seed=20260927)
        self.assertEqual(s["blocks"]["byStatus"], {"ok": 3, "discarded-clock-gap": 1})
        self.assertEqual(s["blocks"]["measuredOk"], 2)
        self.assertEqual(s["blocks"]["discardedClockGap"], 1)
        self.assertEqual(s["blocks"]["replacementWarmups"], 1)
        self.assertEqual(s["blocks"]["replacedWorkers"], [0])
        cell = s["cells"][0]
        # 4 + 2 accepted items; the rejection, the timeout and the discarded block are not latency samples
        self.assertEqual(cell["latencyMs"]["n"], 6)
        self.assertEqual(cell["latencyMs"]["max"], 103.0)
        self.assertEqual(cell["latencyMs"]["min"], 100.0)
        self.assertEqual(cell["errors"]["errors"], 2)
        self.assertEqual(cell["errors"]["attempts"], 8)
        self.assertEqual(cell["errorItems"]["byOutcome"], {"rejected:groth16": 1, "error:timeout": 1})
        self.assertEqual(sorted(cell["errorItems"]["latMs"]), [50.0, 30000.0])
        hc = {r["cls"]: r for r in s["hostile"]}
        self.assertEqual(hc["HC0"]["latencyMs"]["n"], 3)
        self.assertEqual(hc["HC0"]["latencyMs"]["max"], 100.0)
        self.assertEqual(hc["HC5"]["latencyMs"]["n"], 2)  # only the registered rejection (groth16)
        self.assertEqual(hc["HC5"]["unexpectedOutcomes"], 2)
        # every honest reply: throughput 2/8, HC0 1/4, correctness honest items 0/4
        self.assertEqual(s["errorsAllHonest"]["errors"], 3)
        self.assertEqual(s["errorsAllHonest"]["attempts"], 16)
        self.assertEqual(s["errorsThroughputCells"]["errors"], 2)
        self.assertEqual(s["correctness"]["sessionsChecked"], 6)
        self.assertEqual(s["aux"]["firstVerificationInWorker"]["0"]["ms"], 7000.0)
        self.assertNotIn(chr(0x2014), A.markdown(s))


if __name__ == "__main__":
    unittest.main()
