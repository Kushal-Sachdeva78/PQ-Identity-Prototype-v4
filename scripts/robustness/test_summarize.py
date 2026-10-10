"""Tests for scripts/robustness/summarize.py on synthetic fuzz summaries (OS temp dir).

Run: python -m unittest discover -s scripts/robustness -p "test_summarize.py" -v

Regression fixtures for the fz1 triage (docs/v4/ROBUSTNESS.md, Deviations, 2026-10-03): a v1
summary shaped like fz1's lost rows (no final record, casesRun 0 or a checkpoint count, stoppedBy
"child exit code 1") and v2 summaries as fuzz.ts now writes them. The synthetic campaigns have
made-up numbers; nothing in results/ is written. One test reads the committed fz1 summary (read
only) when it is present.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import summarize as S  # noqa: E402

LOST = "result lost (child crashed)"


def v1_row(target: str, budget: int | None, cases: int, complete: bool, stopped: str | None = None, violations: int | None = 0, sigs: list | None = None) -> dict:
    """A target row of a v1 fuzz summary (fuzz.ts before 2026-10-03, as in fz1)."""
    return {
        "target": target,
        "kind": "pure",
        "budget": budget,
        "casesRun": cases,
        "complete": complete,
        "stoppedBy": stopped,
        "hangFile": None,
        "anvilCleanup": None,
        "casesWithViolations": violations,
        "distinctSignatures": None if violations is None else len(sigs or []),
        "signatures": sigs or [],
        "observations": [],
        "slowCases": 0,
        "harnessErrors": None if violations is None else 0,
    }


def v1_summary() -> dict:
    """Shaped like fz1: T-dates died with no record, T-reply-shape left a checkpoint of 88736."""
    sig = {"predicate": "noViolation", "errorClass": None, "occurrences": 1, "file": "results/v4/robustness/fuzz/v1camp/failures/T-ok/aaaaaaaaaaaa.json"}
    rows = [
        v1_row("T-dates", None, 0, False, "child exit code 1", violations=None),
        v1_row("T-ok", 100, 100, True, sigs=[sig], violations=1),
        v1_row("T-reply-shape", 200, 88736, False, "child exit code 1"),
    ]
    return {
        "schema": "pqid/v4-fuzz-summary/v1",
        "campaign": "v1camp",
        "smoke": False,
        "totals": {"targets": 3, "casesRun": 88836, "targetsWithViolations": 1, "distinctSignatures": 1, "incompleteTargets": ["T-dates", "T-reply-shape"], "hangs": []},
        "coverage": None,
        "targets": rows,
    }


def v2_summary(camp: str, failed: bool) -> dict:
    """As fuzz.ts writes it since 2026-10-03: a crashed target with its record kept (its failure
    file listed under signatures and under filesOnDisk), a lost one, and a complete one."""
    f = f"results/v4/robustness/fuzz/{camp}/failures/T-crash/bbbbbbbbbbbb.json"
    ok = {"target": "T-ok", "kind": "pure", "budget": 10, "status": "complete", "complete": True, "resultLost": False, "casesRun": 10, "checkpointCasesRun": None, "signatures": [], "observations": [], "filesOnDisk": None}
    if not failed:
        return {"schema": "pqid/v4-fuzz-summary/v2", "campaign": camp, "smoke": False, "step": {"exitCode": 0, "failed": False, "reasons": []}, "totals": {"targets": 1, "casesRun": 10, "casesRunIsLowerBound": False, "targetsWithViolations": 0, "distinctSignatures": 0, "incompleteTargets": []}, "coverage": None, "targets": [ok]}
    crash = {
        "target": "T-crash",
        "kind": "pure",
        "budget": 10,
        "status": "crashed at case 6 (TypeError), record kept",
        "complete": False,
        "resultLost": False,
        "casesRun": 7,
        "checkpointCasesRun": None,
        "stoppedBy": "crashed at case 6 (TypeError)",
        "signatures": [{"predicate": "noViolation", "errorClass": None, "occurrences": 2, "file": f}],
        "observations": [],
        "filesOnDisk": {"failures": [f], "observations": [], "slow": []},
    }
    lost = {"target": "T-lost", "kind": "pure", "budget": 10, "status": LOST, "complete": False, "resultLost": True, "casesRun": None, "checkpointCasesRun": None, "signatures": [], "observations": [], "filesOnDisk": {"failures": [], "observations": [], "slow": []}}
    return {
        "schema": "pqid/v4-fuzz-summary/v2",
        "campaign": camp,
        "smoke": False,
        "step": {"exitCode": 1, "failed": True, "reasons": ["child T-crash: exit code 1", "child T-lost: exit code 1"]},
        "totals": {"targets": 3, "casesRun": 17, "casesRunIsLowerBound": True, "targetsWithViolations": 1, "distinctSignatures": 1, "incompleteTargets": ["T-crash", "T-lost"], "resultLostTargets": ["T-lost"]},
        "coverage": None,
        "targets": [ok, crash, lost],
    }


class FuzzTargetStatus(unittest.TestCase):
    def test_v1_rows_like_fz1(self) -> None:
        s = v1_summary()
        by = {r["target"]: S.fuzz_target_status(r) for r in s["targets"]}
        self.assertEqual(by["T-dates"], LOST)
        self.assertEqual(by["T-reply-shape"], LOST + ", last checkpoint at 88736 cases")
        self.assertEqual(by["T-ok"], "complete")

    def test_v1_other_stops(self) -> None:
        self.assertEqual(S.fuzz_target_status(v1_row("T-x", 10, 3, False, "no progress for 120 s (hang candidate)")), "stopped (no progress for 120 s (hang candidate))")
        self.assertEqual(S.fuzz_target_status(v1_row("T-x", 10, 3, False, None)), "incomplete")

    def test_v2_status_is_taken_as_written(self) -> None:
        for r in v2_summary("c", True)["targets"]:
            self.assertEqual(S.fuzz_target_status(r), r["status"])


class Collect(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pqid-summarize-test-")).resolve()
        self.root = self.tmp / "results" / "v4" / "robustness"
        for camp, doc in (("v1camp", v1_summary()), ("v2fail", v2_summary("v2fail", True)), ("v2ok", v2_summary("v2ok", False))):
            d = self.root / "fuzz" / camp
            d.mkdir(parents=True)
            (d / "summary.json").write_text(json.dumps(doc), encoding="utf-8")
        (self.root / "fuzz" / "v3none").mkdir(parents=True)
        # rel() resolves paths against REPO: point it at the temp tree
        self.patch = mock.patch.object(S, "REPO", self.tmp)
        self.patch.start()
        self.idx = S.collect(self.root)
        self.by = {r["campaign"]: r for r in self.idx["fuzz"]}
        self.md = S.markdown(self.idx, False)

    def tearDown(self) -> None:
        self.patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_v1_lost_targets_and_lower_bound(self) -> None:
        r = self.by["v1camp"]
        self.assertEqual(r["casesRun"], 88836)
        self.assertTrue(r["casesRunIsLowerBound"])
        self.assertEqual(r["resultLostTargets"], ["T-dates", "T-reply-shape"])
        self.assertIsNone(r["runnerExit"])
        self.assertEqual([x["status"] for x in r["targetStatus"]], [LOST, LOST + ", last checkpoint at 88736 cases"])
        row = next(x for x in self.md.splitlines() if x.startswith("| v1camp |"))
        self.assertIn("88836 (a lower bound: the result of 2 target(s) was lost)", row)
        self.assertIn("T-dates: result lost (child crashed); T-reply-shape: result lost (child crashed), last checkpoint at 88736 cases", row)
        self.assertIn("| not recorded (v1 summary) |", row)
        self.assertNotIn("?", row)

    def test_v2_failed_campaign(self) -> None:
        r = self.by["v2fail"]
        self.assertEqual(r["runnerExit"], 1)
        self.assertTrue(r["casesRunIsLowerBound"])
        self.assertEqual(r["resultLostTargets"], ["T-lost"])
        self.assertEqual([x["status"] for x in r["targetStatus"]], ["crashed at case 6 (TypeError), record kept", LOST])
        row = next(x for x in self.md.splitlines() if x.startswith("| v2fail |"))
        self.assertIn("17 (a lower bound: the result of 1 target(s) was lost)", row)
        self.assertIn("| 1 |", row)

    def test_failure_files_listed_once(self) -> None:
        f = "results/v4/robustness/fuzz/v2fail/failures/T-crash/bbbbbbbbbbbb.json"
        self.assertEqual(self.by["v2fail"]["failures"], [f])
        self.assertEqual(self.md.count(f"`{f}`"), 1)
        self.assertEqual(self.md.count("`results/v4/robustness/fuzz/v1camp/failures/T-ok/aaaaaaaaaaaa.json`"), 1)

    def test_v2_clean_campaign(self) -> None:
        r = self.by["v2ok"]
        self.assertEqual(r["runnerExit"], 0)
        self.assertFalse(r["casesRunIsLowerBound"])
        self.assertEqual(r["targetStatus"], [])
        row = next(x for x in self.md.splitlines() if x.startswith("| v2ok |"))
        self.assertTrue(row.startswith("| v2ok | 10 | 0 | 0 | none | 0 |"), row)

    def test_campaign_without_summary(self) -> None:
        self.assertEqual(self.by["v3none"]["status"], "no summary (incomplete or not analysed)")
        self.assertIn("| v3none | no summary (incomplete or not analysed) |", self.md)


FZ1 = S.ROOT / "fuzz" / "fz1" / "summary.json"


@unittest.skipUnless(FZ1.is_file(), "the committed fz1 summary is not present")
class CommittedFz1(unittest.TestCase):
    """Reads results/v4/robustness/fuzz/fz1/summary.json (read only)."""

    def test_fz1_labels(self) -> None:
        s = json.loads(FZ1.read_text(encoding="utf-8"))
        self.assertEqual(s["schema"], "pqid/v4-fuzz-summary/v1")
        status = {r["target"]: S.fuzz_target_status(r) for r in s["targets"] if not r.get("complete")}
        self.assertEqual(status, {"T-dates": LOST, "T-req-shape": LOST, "T-reply-shape": LOST + ", last checkpoint at 88736 cases"})


if __name__ == "__main__":
    unittest.main()
