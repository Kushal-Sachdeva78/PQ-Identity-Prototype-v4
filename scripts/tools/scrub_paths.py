"""Replace this machine's absolute repo and home paths in tool outputs with <repo> / <home>.

Usage: python scripts/tools/scrub_paths.py <file> [<file> ...]
Results must record the environment without usernames, hostnames or home paths (docs/BENCHMARK_POLICY.md).
"""
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PARENT = os.path.dirname(REPO)
HOME = os.path.expanduser("~")


def variants(p: str) -> list[str]:
    fwd = p.replace("\\", "/")
    out = [
        "\\\\?\\" + p,
        p,
        p.replace("\\", "\\\\"),
        fwd,
        "file:///" + fwd.replace(" ", "%20"),
        "file:///" + fwd,
        "/" + fwd[0].lower() + fwd[2:] if len(fwd) > 2 and fwd[1] == ":" else fwd,
        fwd.replace(" ", "%20"),
    ]
    # relative forms tools print (for example ../../../IRIS%2026-27/Kushal/...): the path
    # below the drive and the last two parent folder names, plain and URL-encoded
    parts = fwd.split("/")
    for k in (2, 3):
        if len(parts) > k:
            tail = "/".join(parts[-k:])
            out += [tail, tail.replace(" ", "%20")]
    return sorted(set(out), key=len, reverse=True)


def scrub(text: str) -> str:
    for v in variants(REPO):
        text = text.replace(v, "<repo>")
    for v in variants(PARENT):
        if v.count("/") + v.count("\\") >= 1:
            text = text.replace(v, "<parent>")
    for v in variants(HOME):
        text = text.replace(v, "<home>")
    return text


if __name__ == "__main__":
    for f in sys.argv[1:]:
        with open(f, encoding="utf-8", errors="surrogateescape") as fh:
            s = fh.read()
        t = scrub(s)
        if t != s:
            with open(f, "w", encoding="utf-8", errors="surrogateescape", newline="\n") as fh:
                fh.write(t)
            print(f"scrubbed {f}")
