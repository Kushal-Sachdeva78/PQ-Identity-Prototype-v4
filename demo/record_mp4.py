#!/usr/bin/env python3
"""Recorded fallback for the offline demo (TASKS G): render a demo transcript as an MP4.

Each transcript line appears at its own timestamp (scaled by --pace-factor so the video can
be slower than the run), in a monospace font on a dark background, 1280x720, H.264. No
names, no paths: the transcript is program output of demo/v4_demo.ts.

Usage:
  npx tsx demo/v4_demo.ts                     # writes demo/out/transcript.txt
  python demo/record_mp4.py [--in demo/out/transcript.txt] [--out demo/v4_demo_fallback.mp4]
                            [--pace-factor 12] [--tail 6]
Needs ffmpeg on PATH (any platform) and a monospace TTF (Consolas on Windows, DejaVu Sans Mono
on Linux, Menlo on macOS; --font to choose another).
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FONTS = ["C:/Windows/Fonts/consola.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "/System/Library/Fonts/Menlo.ttc"]
STAMP = re.compile(r"^\[\s*([0-9.]+) s\] ?(.*)$")


def esc(s: str) -> str:
    """Escape text for an ffmpeg drawtext text= value inside a filter script."""
    return s.replace("\\", "\\\\\\\\").replace("'", "\u2019").replace(":", "\\:").replace("%", "\\%").replace(",", "\\,")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="src", default=str(ROOT / "demo" / "out" / "transcript.txt"))
    ap.add_argument("--out", default=str(ROOT / "demo" / "v4_demo_fallback.mp4"))
    ap.add_argument("--pace-factor", type=float, default=12.0, help="video seconds per run second")
    ap.add_argument("--tail", type=float, default=6.0, help="seconds the final frame stays")
    ap.add_argument("--font", default=None)
    a = ap.parse_args(argv)
    ff = shutil.which("ffmpeg")
    if not ff:
        print("ffmpeg not found on PATH")
        return 2
    font = a.font or next((f for f in FONTS if Path(f).exists()), None)
    if not font:
        print("no monospace font found; pass --font")
        return 2
    rows: list[tuple[float, str]] = []
    last = 0.0
    for line in Path(a.src).read_text(encoding="utf-8").splitlines():
        m = STAMP.match(line)
        if m:
            last = float(m.group(1))
            rows.append((last, m.group(2)))
        elif line.strip():
            rows.append((last, line))
    if not rows:
        print("empty transcript")
        return 2
    step = 1.2  # a minimum gap so every line is readable
    t = 0.0
    shown: list[tuple[float, str]] = []
    import textwrap
    for ts, text in rows:
        t = max(t + step, ts * a.pace_factor)
        indent = len(text) - len(text.lstrip(" "))
        parts = textwrap.wrap(text.strip(), 96) or [""]
        for k, part in enumerate(parts):
            shown.append((t, ("  " if indent else "") + ("  " if k else "") + part))
    duration = shown[-1][0] + a.tail
    fontarg = font.replace("\\", "/").replace(":", "\\:")
    lh = 30
    filters = []
    for i, (ts, text) in enumerate(shown):
        y = 36 + i * lh
        filters.append(
            f"drawtext=fontfile='{fontarg}':text='{esc(text)}':fontcolor=0xE6E6E6:fontsize=20:x=36:y={y}:enable='gte(t\\,{ts:.2f})'"
        )
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
        fh.write(",\n".join(filters))
        script = fh.name
    height = max(720, 36 + len(shown) * lh + 36)
    height += height % 2
    cmd = [ff, "-y", "-loglevel", "error", "-f", "lavfi", "-i", f"color=c=0x1E1F24:s=1280x{height}:d={duration:.2f}:r=25",
           "-filter_script:v", script, "-c:v", "libx264", "-pix_fmt", "yuv420p", "-movflags", "+faststart", a.out]
    r = subprocess.run(cmd)
    Path(script).unlink(missing_ok=True)
    if r.returncode != 0:
        return r.returncode
    print(f"wrote {Path(a.out).as_posix()}: {len(shown)} lines, {duration:.1f} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
