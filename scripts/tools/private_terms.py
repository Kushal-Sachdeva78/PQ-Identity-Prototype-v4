"""Extra lint terms kept outside git (DECISIONS D-030), in private/lint_terms.txt.

No tracked file carries the terms: they live in the gitignored private/ folder. Writers of
public outputs (the IRIS paper build, the snapshot, the export) require the file and fail
closed without it. Other generators use the list when it exists and say so when it does not
(a fresh clone or CI has no private/ folder and publishes nothing).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TERMS_FILE = ROOT / "private" / "lint_terms.txt"
NEUTRAL = "[detail withheld, D-030]"


def available() -> bool:
    return TERMS_FILE.exists()


def terms(required: bool = False) -> tuple[str, ...]:
    if not TERMS_FILE.exists():
        if required:
            raise SystemExit("private term list missing (private/lint_terms.txt): refusing to write a public output (D-030)")
        return ()
    return tuple(
        line.strip().lower()
        for line in TERMS_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def hits(text: str, required: bool = False) -> list[str]:
    low = text.lower()
    return [t for t in terms(required) if t in low]


def redact(text: str, required: bool = False) -> str:
    """Replace every private term (case-insensitive) with the neutral marker."""
    out = text
    for t in sorted(terms(required), key=len, reverse=True):
        out = re.sub(re.escape(t), NEUTRAL, out, flags=re.IGNORECASE)
    return out
