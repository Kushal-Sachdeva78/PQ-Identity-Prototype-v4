#!/usr/bin/env python3
"""Scrub a driver log in place (robustness row; scripts/robustness/run_robustness.sh).

Usage: python scripts/robustness/scrub_log.py <log file> <needle>=<tag> [<needle>=<tag> ...]

Every needle (the repository path, the home and temp directories, the user name, the host name)
is replaced by its tag. A Windows path is replaced in every spelling a log can hold (drive letter
with a backslash or a slash, either case; /c/x of Git Bash; /mnt/c/x of WSL; /cygdrive/c/x).
Needles that are not paths (user and host names) are replaced ignoring case. Longer needles go
first. Needles shorter than 3 characters and the bare generic temp roots (/tmp, /var/tmp) are
ignored. Exit status 0 on success; anything else means the log was not scrubbed (the driver then
withholds it).
"""
from __future__ import annotations

import re
import sys

GENERIC = {"/tmp", "/var/tmp"}
BACKSLASH = chr(92)


def spellings(path: str) -> list[str]:
    """The path itself and, for a Windows path in any spelling, its other spellings."""
    out = [path]
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", path) or re.match(r"^/(?:mnt/|cygdrive/)?([A-Za-z])/(.*)$", path)
    if m is None:
        return out
    d, rest = m.group(1), m.group(2).replace(BACKSLASH, "/").rstrip("/")
    out += [
        f"{d.upper()}:{BACKSLASH}" + rest.replace("/", BACKSLASH),
        f"{d.lower()}:{BACKSLASH}" + rest.replace("/", BACKSLASH),
        f"{d.upper()}:/{rest}",
        f"{d.lower()}:/{rest}",
        f"/{d.lower()}/{rest}",
        f"/mnt/{d.lower()}/{rest}",
        f"/cygdrive/{d.lower()}/{rest}",
    ]
    return out


def scrub_text(text: str, pairs: list[tuple[str, str]]) -> str:
    subs: set[tuple[str, str, bool]] = set()
    for needle, tag in pairs:
        if not needle:
            continue
        is_path = "/" in needle or BACKSLASH in needle
        for s in spellings(needle) if is_path else [needle]:
            if len(s) > 3:
                s = s.rstrip("/" + BACKSLASH)
            if len(s) >= 3 and s not in GENERIC:
                subs.add((s, tag, not is_path))
    for s, tag, any_case in sorted(subs, key=lambda x: (-len(x[0]), x[0])):
        if any_case:
            text = re.sub(re.escape(s), lambda _m, t=tag: t, text, flags=re.IGNORECASE)
        else:
            text = text.replace(s, tag)
    return text


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    f = argv[0]
    pairs: list[tuple[str, str]] = []
    for a in argv[1:]:
        if "=" not in a:
            print("bad argument: needle=tag expected", file=sys.stderr)
            return 2
        needle, tag = a.rsplit("=", 1)
        pairs.append((needle, tag))
    with open(f, encoding="utf8", errors="replace") as fh:
        text = fh.read()
    with open(f, "w", encoding="utf8") as fh:
        fh.write(scrub_text(text, pairs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
