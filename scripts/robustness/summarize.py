#!/usr/bin/env python3
"""Index of the robustness row's results (DECISIONS D-034; docs/v4/ROBUSTNESS.md section 8).

Reads the per-campaign summaries the runners and analyze_load.py wrote:
  results/v4/robustness/fuzz/<campaign>/summary.json          (harness/v4/robustness/fuzz.ts)
  results/v4/robustness/circuit_fuzz/<campaign>/summary.json  (harness/v4/robustness/circuit_fuzz.ts)
  results/v4/robustness/forge/<campaign>/summary.json         (harness/v4/robustness/forge_fuzz.ts)
  results/v4/robustness/load/<campaign>/summary.json          (scripts/robustness/analyze_load.py)
and writes results/v4/robustness/summary.json and summary.md: one row per campaign with its
headline counts, and every failure file. Counts and pointers only; no new statistics.

Usage: python scripts/robustness/summarize.py [--smoke]   (--smoke reads and writes _smoke/)
Refuses to run while results/v4/bench/RUNNING or results/v4/BUSY exists.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "results" / "v4" / "robustness"
MARKERS = [REPO / "results" / "v4" / "bench" / "RUNNING", REPO / "results" / "v4" / "BUSY"]


def rel(p: Path) -> str:
    return p.resolve().relative_to(REPO).as_posix()


def load(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def fuzz_target_status(r: dict) -> str:
    """How a fuzz target ended. v2 summaries (fuzz.ts from 2026-10-03) carry it as "status". A v1
    summary (fz1) has none: there a target whose child exited non-zero has no final record (the
    child wrote nothing, or only its last 30 s checkpoint), so its result is lost; its casesRun
    of 0, or the checkpoint's count, is not the number of cases that ran."""
    if r.get("status"):
        return str(r["status"])
    if r.get("complete"):
        return "complete"
    stopped = str(r.get("stoppedBy") or "")
    if stopped.startswith("child exit code"):
        cp = r.get("casesRun") or 0
        return "result lost (child crashed)" + (f", last checkpoint at {cp} cases" if cp else "")
    if stopped:
        return f"stopped ({stopped[:80]})"
    return "incomplete"


def collect(root: Path) -> dict:
    out: dict = {"fuzz": [], "circuit_fuzz": [], "forge": [], "load": []}
    for kind in out:
        d = root / kind
        if not d.is_dir():
            continue
        for camp in sorted(p for p in d.iterdir() if p.is_dir()):
            s = load(camp / "summary.json")
            row: dict = {"campaign": camp.name, "path": rel(camp), "summary": (rel(camp / "summary.json") if s else None)}
            if s is None:
                row["status"] = "no summary (incomplete or not analysed)"
            elif kind == "fuzz":
                t = s.get("totals", {})
                rows = s.get("targets", [])
                status = [{"target": r.get("target"), "status": fuzz_target_status(r)} for r in rows if not r.get("complete")]
                lost = [x["target"] for x in status if x["status"].startswith("result lost")]
                row.update(
                    casesRun=t.get("casesRun"),
                    casesRunIsLowerBound=bool(t.get("casesRunIsLowerBound")) or bool(lost),
                    runnerExit=(s.get("step") or {}).get("exitCode"),
                    targetStatus=status,
                    resultLostTargets=lost,
                    targets=t.get("targets"),
                    targetsWithViolations=t.get("targetsWithViolations"),
                    distinctSignatures=t.get("distinctSignatures"),
                    incompleteTargets=t.get("incompleteTargets"),
                    coverage=s.get("coverage"),
                    # a v2 row of a crashed target lists its failure files both under signatures and
                    # under filesOnDisk: each file once, in order
                    failures=list(
                        dict.fromkeys(
                            [sig["file"] for r in rows for sig in r.get("signatures", []) if sig.get("file")]
                            + [f for r in rows for f in ((r.get("filesOnDisk") or {}).get("failures") or [])]
                        )
                    ),
                    observations={r["target"]: r.get("observations") for r in s.get("targets", []) if r.get("observations")},
                )
            elif kind == "circuit_fuzz":
                t = s.get("totals", {})
                row.update(
                    cases=t.get("cases"),
                    referenceDisagrees=t.get("referenceDisagrees"),
                    attackerDisagrees=t.get("attackerDisagrees"),
                    proofDisagrees=t.get("proofDisagrees"),
                    mutations=t.get("mutations"),
                    mutationsRejected=t.get("mutationsRejected"),
                    mutationsFreeWires=t.get("mutationsFreeWires"),
                    mutationsPublicChangedSatisfied=t.get("mutationsPublicChangedSatisfied"),
                    mutationsPrivateInputChangedSatisfied=t.get("mutationsPrivateInputChangedSatisfied"),
                    failures=s.get("failures", []),
                )
            elif kind == "forge":
                t = s.get("totals", {})
                row.update(tests=t.get("tests"), passed=t.get("passed"), failed=t.get("failed"), fuzzRuns=t.get("fuzzRuns"), invariantCalls=t.get("invariantCalls"), failures=s.get("failures", []))
            else:
                c = s.get("correctness", {})
                row.update(
                    measuredBlocks=s.get("blocks", {}).get("measuredOk"),
                    errorsThroughputCells=s.get("errorsThroughputCells"),
                    errorsAllHonest=s.get("errorsAllHonest"),
                    correctnessMeetsRequired=c.get("meetsRequired"),
                    saturation=(s.get("saturation") or {}).get("exceptionAtCap"),
                )
            row["smoke"] = bool(s.get("smoke")) if s else None
            out[kind].append(row)
    return out


def markdown(idx: dict, smoke: bool) -> str:
    L = ["# Robustness results index" + (" (smoke: never quoted)" if smoke else ""), "", "Generated by scripts/robustness/summarize.py. Pre-registration and protocol: docs/v4/ROBUSTNESS.md. Counts and pointers only.", ""]
    if idx["fuzz"]:
        L += [
            "## Fuzzing (package entry points)",
            "",
            "| Campaign | Cases | Targets with violations | Distinct signatures | Incomplete targets | Runner exit | Line coverage of the loaded package modules |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in idx["fuzz"]:
            if "summary" in r and r.get("summary") is None:
                L.append(f"| {r['campaign']} | {r.get('status')} | | | | | |")
                continue
            cov = r.get("coverage") or {}
            lost = r.get("resultLostTargets") or []
            cases = f"{r.get('casesRun')}" + (f" (a lower bound: the result of {len(lost)} target(s) was lost)" if r.get("casesRunIsLowerBound") else "")
            inc = "; ".join(f"{x['target']}: {x['status']}" for x in (r.get("targetStatus") or [])) or ", ".join(r.get("incompleteTargets") or []) or "none"
            ex = r.get("runnerExit")
            exit_text = "not recorded (v1 summary)" if ex is None else str(ex)
            cov_text = f"{cov.get('linePercent', 'n/a')} % ({len(cov.get('unloadedFiles') or [])} files not loaded)" if cov else "not measured"
            L.append(f"| {r['campaign']} | {cases} | {r.get('targetsWithViolations')} | {r.get('distinctSignatures')} | {inc} | {exit_text} | {cov_text} |")
        L.append("")
    if idx["circuit_fuzz"]:
        L += [
            "## Circuit and witness fuzz",
            "",
            "| Campaign | Cases | Disagreements (reference, attacker, Groth16) | Mutations rejected / total | Free hint wires | Satisfied with a changed public wire (critical) | Satisfied with a changed private input |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in idx["circuit_fuzz"]:
            L.append(
                f"| {r['campaign']} | {r.get('cases')} | {r.get('referenceDisagrees')}, {r.get('attackerDisagrees')}, {r.get('proofDisagrees')} | {r.get('mutationsRejected')} / {r.get('mutations')} | {r.get('mutationsFreeWires')} | "
                f"{r.get('mutationsPublicChangedSatisfied')} | {r.get('mutationsPrivateInputChangedSatisfied')} |"
            )
        L.append("")
    if idx["forge"]:
        L += ["## Registry fuzz and invariant tests (forge)", "", "| Campaign | Tests passed / total | Fuzz runs | Invariant calls |", "|---|---|---|---|"]
        for r in idx["forge"]:
            L.append(f"| {r['campaign']} | {r.get('passed')} / {r.get('tests')} | {r.get('fuzzRuns')} | {r.get('invariantCalls')} |")
        L.append("")
    if idx["load"]:
        L += ["## Verifier library under concurrent load", "", "| Campaign | Measured blocks | Errors / attempts (throughput cells) | Errors / attempts (every honest reply) | Correctness meets required | Saturation at cap |", "|---|---|---|---|---|---|"]
        for r in idx["load"]:
            e = r.get("errorsThroughputCells") or {}
            a = r.get("errorsAllHonest") or {}
            L.append(f"| {r['campaign']} | {r.get('measuredBlocks')} | {e.get('errors')} / {e.get('attempts')} | {a.get('errors')} / {a.get('attempts')} | {r.get('correctnessMeetsRequired')} | {r.get('saturation')} |")
        L.append("")
    fails = [f for k in ("fuzz", "circuit_fuzz", "forge") for r in idx[k] for f in (r.get("failures") or [])]
    L += ["## Failure files", ""] + ([f"- `{f}`" for f in fails] if fails else ["None."]) + [""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--smoke", action="store_true")
    a = ap.parse_args()
    held = [m for m in MARKERS if m.exists()]
    if held:
        print(f"refusing: {', '.join(rel(m) for m in held)} exists", file=sys.stderr)
        return 3
    root = ROOT / "_smoke" if a.smoke else ROOT
    idx = collect(root)
    doc = {"schema": "pqid/v4-robustness-index/v1", "smoke": a.smoke, "generatedUtc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), **idx}
    root.mkdir(parents=True, exist_ok=True)
    (root / "summary.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
    (root / "summary.md").write_text(markdown(idx, a.smoke), encoding="utf-8", newline="\n")
    print(f"wrote {rel(root / 'summary.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
