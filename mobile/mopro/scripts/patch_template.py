#!/usr/bin/env python3
"""Patch a fresh `mopro init --adapter circom` project into the PQ-Identity v4 prover crate.

Usage: python3 mobile/mopro/scripts/patch_template.py <project-dir>

What it changes (and nothing else):
  1. src/lib.rs: the template's multiplier2 registration (the `mod witness { ... }` block and
     the `set_circom_circuits! { ... }` block) is replaced by mobile/mopro/rust/circuit_glue.rs.
     The template's multiplier2 unit test module is disabled with `#[cfg(any())]` (its zkey is
     no longer registered). The `#[macro_use] mod circom;` line and the re-exports stay.
  2. build.rs: replaced by mobile/mopro/rust/build.rs (transpile the repo's v4 wasm in place).
  3. Config.toml: replaced by mobile/mopro/Config.toml when every key in ours is a key of the
     generated file; otherwise the generated file is kept (a CLI with other config keys).
     The generated file is saved as Config.generated.toml either way.
It refuses (exit 1) when an expected template pattern is missing, so a changed Mopro template
fails loudly instead of building the wrong circuit. It records what it did in PQID_PATCHES.json.
Idempotent: a project that already carries the glue markers is left unchanged.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

KIT = Path(__file__).resolve().parents[1]  # mobile/mopro
GLUE = KIT / "rust" / "circuit_glue.rs"
BUILD_RS = KIT / "rust" / "build.rs"
CONFIG = KIT / "Config.toml"

WITNESS_BLOCK = re.compile(r"mod\s+witness\s*\{\s*rust_witness::witness!\(\s*multiplier2\s*\);\s*\}\s*", re.S)
CIRCUITS_BLOCK = re.compile(r"(?:crate::)?set_circom_circuits!\s*\{[^{}]*multiplier2[^{}]*\}\s*", re.S)
TEST_MODULE = re.compile(r"#\[cfg\(test\)\]\s*\n(\s*)mod\s+circom_tests\b")


def fail(msg: str) -> None:
    print(f"[patch_template] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def patch_lib(project: Path, log: dict) -> None:
    lib = project / "src" / "lib.rs"
    if not lib.exists():
        fail(f"{lib} missing: is this a `mopro init` project?")
    src = lib.read_text(encoding="utf-8")
    if "PQID_V4_GLUE_BEGIN" in src:
        log["lib.rs"] = "already patched"
        return
    if "mod circom" not in src:
        fail("src/lib.rs has no `mod circom`: run `mopro init --adapter circom`")
    w = WITNESS_BLOCK.search(src)
    c = CIRCUITS_BLOCK.search(src)
    if not w or not c:
        fail("template multiplier2 registration not found in src/lib.rs (Mopro template changed?); "
             "patch by hand with mobile/mopro/rust/circuit_glue.rs")
    glue = GLUE.read_text(encoding="utf-8").rstrip() + "\n\n"
    start, end = min(w.start(), c.start()), max(w.end(), c.end())
    between = src[start:end]
    # only the two blocks (and whitespace) may lie between their start and end
    rest = WITNESS_BLOCK.sub("", CIRCUITS_BLOCK.sub("", between)).strip()
    if rest:
        fail(f"unexpected code between the template blocks: {rest[:120]!r}")
    src = src[:start] + glue + src[end:]
    src, n_tests = TEST_MODULE.subn(r"#[cfg(any())] // PQID v4: template multiplier2 test disabled\n\1mod circom_tests", src)
    lib.write_text(src, encoding="utf-8")
    log["lib.rs"] = {"replaced": "multiplier2 witness + set_circom_circuits blocks", "glue": "mobile/mopro/rust/circuit_glue.rs",
                     "templateTestModulesDisabled": n_tests}


def patch_build_rs(project: Path, log: dict) -> None:
    b = project / "build.rs"
    old = b.read_text(encoding="utf-8") if b.exists() else ""
    ours = BUILD_RS.read_text(encoding="utf-8")
    if old == ours:
        log["build.rs"] = "already patched"
        return
    if "transpile_wasm" not in old:
        fail("generated build.rs has no transpile_wasm call (Mopro template changed?)")
    other = [ln.strip() for ln in old.splitlines()
             if ln.strip() and not ln.strip().startswith("//") and "transpile_wasm" not in ln and ln.strip() not in ("fn main() {", "}")]
    if other:
        fail(f"generated build.rs does more than transpile_wasm: {other[:3]}")
    (project / "build.generated.rs").write_text(old, encoding="utf-8")
    b.write_text(ours, encoding="utf-8")
    log["build.rs"] = {"replacedWith": "mobile/mopro/rust/build.rs", "generatedSavedAs": "build.generated.rs"}


def patch_config(project: Path, log: dict) -> None:
    gen = project / "Config.toml"
    if not gen.exists():
        shutil.copyfile(CONFIG, gen)
        log["Config.toml"] = "no generated file; ours copied"
        return
    saved = project / "Config.generated.toml"
    if not saved.exists():
        shutil.copyfile(gen, saved)
    if tomllib is None:
        log["Config.toml"] = "python has no tomllib; generated file kept"
        return
    ours = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    theirs = tomllib.loads(saved.read_text(encoding="utf-8"))
    unknown = sorted(set(ours) - set(theirs))
    if unknown:
        log["Config.toml"] = {"kept": "generated", "unknownKeysInOurs": unknown}
        print(f"[patch_template] warning: keys {unknown} not in the generated Config.toml; keeping the generated file")
        return
    shutil.copyfile(CONFIG, gen)
    log["Config.toml"] = {"replacedWith": "mobile/mopro/Config.toml", "generatedSavedAs": "Config.generated.toml"}


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: patch_template.py <project-dir>")
    project = Path(sys.argv[1]).resolve()
    cargo = project / "Cargo.toml"
    if not cargo.exists():
        fail(f"{cargo} missing")
    cargo_text = cargo.read_text(encoding="utf-8")
    for dep in ("mopro-ffi", "circom-prover", "rust-witness"):
        if dep not in cargo_text:
            fail(f"Cargo.toml has no {dep} dependency (run `mopro init --adapter circom`)")
    log: dict = {"schema": "pqid/v4-mopro-patches/v1", "project": project.name,
                 "timestampUtc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    m = re.search(r'mopro-ffi\s*=\s*\{\s*version\s*=\s*"([^"]+)"', cargo_text)
    log["moproFfiRequirement"] = m.group(1) if m else None
    patch_lib(project, log)
    patch_build_rs(project, log)
    patch_config(project, log)
    (project / "PQID_PATCHES.json").write_text(json.dumps(log, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(log, indent=2))


if __name__ == "__main__":
    main()
