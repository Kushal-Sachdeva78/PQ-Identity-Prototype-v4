"""Tests for scripts/cmp/analyze_cmp.py on synthetic results roots (OS temp dirs).

Run: python -m unittest discover -s scripts/cmp -p "test_analyze_cmp.py" -v

The synthetic roots have the cmp layout (prove/cold_cmp, prove/warm_cmp, wallet/wallet_cmp) with
made-up timings; nothing in results/ is written. The Phase D root (results/v4/bench) is read only
by the consistency section. Skipped while results/v4/bench/RUNNING exists (no analyses during a
timed run, docs/BENCHMARK_POLICY.md).
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
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
sys.path.insert(0, str(REPO / "scripts" / "bench"))
import analyze as A  # noqa: E402

SCRIPT = HERE / "analyze_cmp.py"
CIRCUITS = ["v2", "v2o2", "v3", "v4", "eddsa"]
BASE = {"v2": 1000.0, "v2o2": 900.0, "v3": 1200.0, "v4": 1150.0, "eddsa": 600.0}
KEYS = {"v2": "committed v2 key", "v2o2": "v2 --O2 dev timing key", "v3": "committed v3 key", "v4": "test v4 key", "eddsa": "throwaway baseline key", "curve": "none (no key)"}
NOTES = {v: {"note": f"note {v}", "optimization": "--O1" if v == "v2" else "--O2", "nConstraints": 1000 + i, "nWires": 1001 + i, "source": f"info/{v}", "keyLabel": KEYS[v]}
         for i, v in enumerate(CIRCUITS)}
N_COLD, N_WARM, N_WALLET = 30, 30, 10


def rec(campaign, mode, version, block, prove, **extra):
    t = {"curveMs": prove} if version == "curve" else {"witnessMs": prove / 10, "proveMs": prove, "verifyMs": 13.0, "wpMs": prove * 1.1}
    r = {"type": "run", "campaign": campaign, "mode": mode, "session": "s1", "slot": 0, "block": block, "pos": 0,
         "version": version, "prover": "snarkjs", "keyLabel": KEYS[version], "status": "ok", "timings": t,
         "quiesce": {"quiesced": True}, "quiesceDetail": {"quiesced": True}, "hostPauseSuspected": False, "clockGapSec": 0.0,
         "idleMaxTickGapSec": 1.0, "postponements": 0}
    r.update(extra)
    return r


def write(dirpath: Path, env: dict, rows: list[dict]) -> None:
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / "env.json").write_text(json.dumps(env), encoding="utf-8")
    (dirpath / "runs.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


def cold_env(name: str = "cold_cmp", curve: bool = True) -> dict:
    vs = CIRCUITS + (["curve"] if curve else [])
    return {"mode": "cold", "kind": "prove", "label": "test", "campaign": name, "keyLabels": {v: KEYS[v] for v in vs},
            "v4Key": {"label": KEYS["v4"], "isDevKey": False}, "conditionNotes": NOTES, "sessions": [{"env": {}}]}


def build_root(root: Path, rng: np.random.Generator, n_cold: int = N_COLD, cold_end: bool = True) -> list[dict]:
    cold = []
    for b in range(n_cold):
        for v in CIRCUITS + ["curve"]:
            base = 300.0 if v == "curve" else BASE[v]
            extra = {"hostPauseSuspected": True, "clockGapSec": 0.0, "idleMaxTickGapSec": 37.0} if (b == 3 and v == "v4") else {}
            if b == 5 and v == "v2":
                extra = {"quiesce": {"quiesced": False}}
            if b == 6 and v == "v3":  # strict rule only (for example a foreign chain-port listener): counted, kept
                extra = {"quiesceDetail": {"quiesced": False}}
            cold.append(rec("cold_cmp", "cold", v, b, base + 20 * rng.standard_normal(), **extra))
    if cold_end:
        cold.append({"type": "campaign-end", "complete": True})
    write(root / "prove" / "cold_cmp", cold_env(), cold)
    warm = [rec("warm_cmp", "warm", v, b, BASE[v] * 0.7 + 5 * rng.standard_normal(), warmup=b < 0) for b in range(-1, N_WARM) for v in CIRCUITS]
    warm.append({"type": "session-end", "session": "s1", "complete": True})
    write(root / "prove" / "warm_cmp", {"mode": "warm", "kind": "prove", "label": "test", "keyLabels": {v: KEYS[v] for v in CIRCUITS},
                                        "v4Key": {"label": KEYS["v4"], "isDevKey": False}, "conditionNotes": NOTES, "sessions": [{"env": {}}]}, warm)
    wal = []
    for b in range(N_WALLET):
        for w, scale in (("wallet1e5", 1.0), ("wallet1e6", 10.0)):
            iss, revo, cur = 6000 * scale + rng.standard_normal(), 140 * scale, 220.0
            wal.append({"type": "run", "mode": "cold", "session": "s1", "block": b, "version": w, "prover": "node", "keyLabel": "none (no key)", "status": "ok",
                        "timings": {"poseidonInitMs": cur, "issuanceMs": iss, "revocationMs": revo, "rebuildMs": iss + revo, "totalMs": cur + iss + revo},
                        "results": {"size": {"credentials": int(100000 * scale), "revocations": int(1000 * scale)}},
                        "aux": {"poseidonLib": {"circomlibjs": "0.1.7", "ffjavascript": "0.2.63"}},
                        "quiesce": {"quiesced": True}, "hostPauseSuspected": False, "clockGapSec": 0.0})
    wal.append({"type": "campaign-end", "complete": True})
    write(root / "wallet" / "wallet_cmp", {"mode": "cold", "kind": "wallet", "label": "test", "keyLabels": {"wallet1e5": "none (no key)", "wallet1e6": "none (no key)"},
                                           "sessions": [{"env": {}}]}, wal)
    return cold


def run(root: Path, *args: str) -> tuple[subprocess.CompletedProcess, dict | None]:
    p = subprocess.run([sys.executable, str(SCRIPT), "--root", str(root), "--B", "800", *args], capture_output=True, text=True)
    s = json.loads((root / "summary_cmp.json").read_text(encoding="utf-8")) if p.returncode == 0 else None
    return p, s


def all_ratio_entries(s: dict) -> list[dict]:
    out = [r for rows in s["ratios"].values() for r in rows]
    if isinstance(s["consistency"]["phaseD"], list):
        out += s["consistency"]["phaseD"]
    return out


@unittest.skipIf((REPO / "results" / "v4" / "bench" / "RUNNING").exists(), "a timed run is active (results/v4/bench/RUNNING)")
class AnalyzeCmpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="pqid-cmp-analyze-"))
        cls.cold = build_root(cls.tmp, np.random.default_rng(1))
        cls.run1, cls.s1 = run(cls.tmp)
        cls.run2, cls.s2 = run(cls.tmp)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def arr(self, v: str, key: str = "proveMs") -> np.ndarray:
        return np.array([r["timings"][key] for r in self.cold if r.get("version") == v])

    def test_runs_and_writes_both_files(self) -> None:
        self.assertEqual(self.run1.returncode, 0, self.run1.stderr)
        self.assertTrue((self.tmp / "summary_cmp.md").exists())
        self.assertFalse(self.s1["partial"])
        self.assertEqual(self.s1["label"], "[M] comparable benchmark series (cmp), v4: test v4 key")

    def test_deterministic_apart_from_the_timestamp(self) -> None:
        a, b = dict(self.s1), dict(self.s2)
        a.pop("generatedUtc")
        b.pop("generatedUtc")
        self.assertEqual(a, b)

    def test_primary_ratios_are_the_protocol_bootstrap_with_cmp_ids(self) -> None:
        prim = {r["id"]: r for r in self.s1["ratios"]["primary"]}
        self.assertEqual(len(prim), 12)
        r = prim["cmp/version/cold/snarkjs/v4_over_v2/prove"]
        self.assertEqual(r["bootstrapStreamId"], "version/cold/snarkjs/v4_over_v2/prove")  # analyze.py's id
        x, y = self.arr("v4"), self.arr("v2")
        self.assertAlmostEqual(r["ratioOfMedians"], float(np.median(x) / np.median(y)), places=12)
        lo, hi = A.boot_ratio(x, y, 800, A.SEED_DEFAULT, "version/cold/snarkjs/v4_over_v2/prove")
        self.assertEqual(r["ci95"], [lo, hi])
        self.assertIn("cmp/cold/snarkjs/v4_over_eddsa/wp", prim)
        self.assertTrue(all(p["preRegistered"] and p["status"] == "ok" for p in prim.values()))
        self.assertEqual((r["numeratorKey"], r["denominatorKey"]), ("test v4 key", "committed v2 key"))

    def test_every_published_id_has_the_cmp_prefix_and_key_labels(self) -> None:
        entries = all_ratio_entries(self.s1)
        self.assertGreater(len(entries), 50)
        for e in entries:
            self.assertTrue(e["id"].startswith("cmp/"), e["id"])
            self.assertIn("numeratorKey", e, e["id"])
            self.assertIn("denominatorKey", e, e["id"])
        cw = {r["id"]: r for r in self.s1["ratios"]["coldOverWarm"]}
        self.assertEqual(cw["cmp/coldwarm/v4/snarkjs/prove"]["bootstrapStreamId"], "coldwarm/v4/snarkjs/prove")
        md = (self.tmp / "summary_cmp.md").read_text(encoding="utf-8")
        self.assertIn("| cmp/version/cold/snarkjs/v4_over_v2/prove | test v4 key / committed v2 key |", md)

    def test_block_bootstrap_and_sensitivity(self) -> None:
        blk = {r["id"]: r for r in self.s1["ratios"]["blockBootstrap"]}
        self.assertEqual(blk["cmp/block/version/cold/snarkjs/v4_over_v2/prove"]["blocks"], N_COLD)
        sens = {r["id"]: r for r in self.s1["ratios"]["sensitivity"]}
        s = sens["cmp/sens/version/cold/snarkjs/v4_over_v2/prove"]
        self.assertEqual(s["excluded"], {"numerator": 1, "denominator": 1})
        self.assertEqual((s["nNumerator"], s["nDenominator"]), (N_COLD - 1, N_COLD - 1))

    def test_conditions_have_median_cis_and_notes(self) -> None:
        conds = {c["condition"]: c for c in self.s1["conditions"]}
        c = conds["cold/v4/snarkjs"]["phases"]["prove"]
        self.assertEqual(c["n"], N_COLD)
        self.assertLessEqual(c["medianCi95"][0], c["median"])
        self.assertGreaterEqual(c["medianCi95"][1], c["median"])
        self.assertIn("cold/curve/snarkjs", conds)
        self.assertIn("cold/wallet1e6/node", conds)
        self.assertIn("poseidonInit", conds["cold/wallet1e6/node"]["phases"])
        self.assertEqual(conds["cold/wallet1e6/node"]["poseidonLib"]["ffjavascript"], "0.2.63")
        self.assertEqual(conds["warm/eddsa/snarkjs"]["phases"]["prove"]["n"], N_WARM)  # warm-up block left out
        self.assertEqual(conds["cold/v2/snarkjs"]["notes"]["optimization"], "--O1")
        self.assertEqual(conds["cold/v2o2/snarkjs"]["notes"]["nConstraints"], 1001)

    def test_descriptive_curve_share_wallet_and_campaigns(self) -> None:
        ids = {r["id"] for r in self.s1["ratios"]["descriptive"]}
        self.assertIn("cmp/cold/snarkjs/v3_over_v2/prove", ids)
        self.assertIn("cmp/warm/snarkjs/v4_over_eddsa/prove", ids)
        self.assertNotIn("cmp/version/cold/snarkjs/v4_over_v2/prove", ids)  # primary, not repeated
        self.assertEqual(len(self.s1["ratios"]["curveShare"]), 5)
        self.assertEqual(len(self.s1["ratios"]["coldOverWarm"]), 20)
        w = {r["id"]: r for r in self.s1["ratios"]["wallet"]}
        self.assertIn("cmp/wallet/1e6_over_1e5/rebuild", w)
        self.assertIn("cmp/wallet/wallet1e5/poseidoninit_over_total", w)
        books = {b["campaign"]: b for b in self.s1["campaigns"]}
        self.assertEqual(books["cold_cmp"]["usedHostPauseSuspected"], 1)
        self.assertEqual(books["cold_cmp"]["usedNotQuiesced"], 1)
        self.assertEqual(books["cold_cmp"]["usedNotQuiescedStrict"], 1)
        self.assertEqual(books["cold_cmp"]["idleMaxTickGapSec"]["max"], 37.0)
        self.assertTrue(all(b["completeForAnalysis"] for b in books.values()))
        sens = {r["id"]: r for r in self.s1["ratios"]["sensitivity"]}
        self.assertEqual(sens["cmp/sens/version/cold/snarkjs/v4_over_v3/prove"]["excluded"], {"numerator": 1, "denominator": 0})
        ev = [e for e in self.s1["consistency"]["earlierValues"] if e["what"].startswith("wallet rebuild 100000")][0]
        self.assertIsNotNone(ev["cmpColdMedian"])
        self.assertEqual([f["use"] for f in self.s1["campaignFolders"]], ["selected"] * 3)


@unittest.skipIf((REPO / "results" / "v4" / "bench" / "RUNNING").exists(), "a timed run is active (results/v4/bench/RUNNING)")
class AnalyzeCmpPartialAndSelectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pqid-cmp-analyze-p-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_partial_cold_campaign_gives_no_primary_number(self) -> None:
        build_root(self.tmp, np.random.default_rng(2), n_cold=N_COLD, cold_end=False)  # no campaign-end
        p, s = run(self.tmp)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(s["partial"])
        self.assertTrue(s["label"].startswith("PARTIAL [M] comparable benchmark series (cmp)"))
        for r in s["ratios"]["primary"] + s["ratios"]["blockBootstrap"] + s["ratios"]["sensitivity"]:
            self.assertEqual(r["status"], "incomplete", r["id"])
            self.assertNotIn("ratioOfMedians", r)
        self.assertIn("PARTIAL", (self.tmp / "summary_cmp.md").read_text(encoding="utf-8"))

    def test_too_few_runs_per_circuit_is_partial(self) -> None:
        build_root(self.tmp, np.random.default_rng(3), n_cold=N_COLD - 1)  # ended, but n = 29
        p, s = run(self.tmp)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(s["partial"])
        self.assertIn("n below 30", s["partialReason"])
        self.assertEqual({r["status"] for r in s["ratios"]["primary"]}, {"incomplete"})

    def test_missing_campaign_is_partial(self) -> None:
        build_root(self.tmp, np.random.default_rng(4))
        shutil.rmtree(self.tmp / "prove" / "warm_cmp")
        p, s = run(self.tmp)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(s["partial"])
        self.assertIn("missing campaign(s): warm warm_cmp", s["partialReason"])
        self.assertEqual({r["status"] for r in s["ratios"]["primary"]}, {"ok"})  # the cold campaign itself is complete

    def test_unselected_campaign_of_the_same_kind_refuses_until_selected_or_ignored(self) -> None:
        build_root(self.tmp, np.random.default_rng(5))
        shutil.copytree(self.tmp / "prove" / "cold_cmp", self.tmp / "prove" / "cold_cmp2")
        env = json.loads((self.tmp / "prove" / "cold_cmp2" / "env.json").read_text(encoding="utf-8"))
        env["campaign"] = "cold_cmp2"
        (self.tmp / "prove" / "cold_cmp2" / "env.json").write_text(json.dumps(env), encoding="utf-8")
        p, _ = run(self.tmp)
        self.assertEqual(p.returncode, 3)
        self.assertIn("cold_cmp2", p.stderr)
        p, _ = run(self.tmp, "--cold", "cold_cmp2")  # cold_cmp is now the unselected one
        self.assertEqual(p.returncode, 3)
        p, s = run(self.tmp, "--cold", "cold_cmp2", "--ignore", "cold_cmp")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(s["selection"], {"cold": "cold_cmp2", "warm": "warm_cmp", "wallet": "wallet_cmp", "ignored": ["cold_cmp"]})
        uses = {f["campaign"]: f["use"] for f in s["campaignFolders"]}
        self.assertEqual(uses["cold_cmp"], "ignored (--ignore)")
        self.assertEqual(uses["cold_cmp2"], "selected")
        self.assertEqual(s["campaigns"][0]["campaign"], "cold_cmp2")
        p, _ = run(self.tmp, "--cold", "warm_cmp", "--ignore", "cold_cmp,cold_cmp2")  # a warm campaign named as cold
        self.assertEqual(p.returncode, 3)

    def test_a_phase_d_root_that_analyze_py_refuses_does_not_abort_the_analysis(self) -> None:
        build_root(self.tmp, np.random.default_rng(6))
        spec = importlib.util.spec_from_file_location("analyze_cmp_under_test", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)

        def refuse(_root):
            raise SystemExit("condition ('cold', 'v4', 'snarkjs') appears in two campaigns")

        mod.A.load_campaigns, saved = refuse, mod.A.load_campaigns
        argv = sys.argv
        try:
            sys.argv = ["analyze_cmp.py", "--root", str(self.tmp), "--B", "200"]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(mod.main(), 0)
        finally:
            sys.argv = argv
            mod.A.load_campaigns = saved
        s = json.loads((self.tmp / "summary_cmp.json").read_text(encoding="utf-8"))
        self.assertTrue(str(s["consistency"]["phaseD"]).startswith("not computed: condition"))
        self.assertEqual({r["status"] for r in s["ratios"]["primary"]}, {"ok"})


if __name__ == "__main__":
    unittest.main()
