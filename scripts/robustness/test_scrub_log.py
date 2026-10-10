"""Tests for scripts/robustness/scrub_log.py (driver log scrubbing; synthetic text only).

Run: python -m unittest discover -s scripts/robustness -p "test_scrub_log.py" -v
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scrub_log as S  # noqa: E402

BS = chr(92)


class Scrub(unittest.TestCase):
    def test_every_spelling_of_a_windows_path(self) -> None:
        repo = "C:" + BS + "Users" + BS + "someone" + BS + "work" + BS + "repo"
        text = "\n".join(
            [
                "a C:" + BS + "Users" + BS + "someone" + BS + "work" + BS + "repo" + BS + "x.ts",
                "b C:/Users/someone/work/repo/x.ts",
                "c c:/Users/someone/work/repo/x.ts",
                "d /c/Users/someone/work/repo/x.ts",
                "e /mnt/c/Users/someone/work/repo/x.ts",
                "f /cygdrive/c/Users/someone/work/repo/x.ts",
                "g C:/Users/someone/AppData/Local/Temp/w.wtns",
            ]
        )
        out = S.scrub_text(text, [(repo, "<repo>"), ("/c/Users/someone", "~"), ("C:/Users/someone/AppData/Local/Temp", "<tmp>")])
        self.assertNotIn("someone", out)
        for line in out.splitlines()[:6]:
            self.assertIn("<repo>", line)
        self.assertIn("<tmp>/w.wtns", out)

    def test_names_any_case_and_generic_roots_kept(self) -> None:
        out = S.scrub_text("host MY-LAPTOP my-laptop user Someone /tmp/x", [("My-Laptop", "<host>"), ("someone", "<user>"), ("/tmp", "<tmp>"), ("", "<x>"), ("ab", "<y>")])
        self.assertEqual(out, "host <host> <host> user <user> /tmp/x")

    def test_longer_needles_first(self) -> None:
        out = S.scrub_text("/home/u/repo/a and /home/u/b", [("/home/u", "~"), ("/home/u/repo", "<repo>")])
        self.assertEqual(out, "<repo>/a and ~/b")

    def test_main_rewrites_the_file(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.log"
            f.write_text("path /home/u/repo/x\n", encoding="utf-8")
            self.assertEqual(S.main([str(f), "/home/u/repo=<repo>"]), 0)
            self.assertEqual(f.read_text(encoding="utf-8"), "path <repo>/x\n")
            self.assertEqual(S.main([str(f), "no-tag"]), 2)
            # an unreadable log raises, so the script exits non-zero and the driver withholds the log
            with self.assertRaises(OSError):
                S.main([str(Path(d) / "missing.log"), "a=b"])


if __name__ == "__main__":
    unittest.main()
