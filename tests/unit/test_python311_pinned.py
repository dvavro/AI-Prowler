"""
AI-Prowler stays on Python 3.11 for now (David, 2026-10-11).

  * the test run itself is on 3.11
  * every tracked .py file compiles under 3.11's grammar (e.g. no backslash or
    reused quotes inside f-string expressions, no `type X = ...` statements,
    no `def f[T]()` generics — all 3.12+)
  * no 3.12+ standard-library features are used
  * the run_script interpreter finders look for Python311 only (then the
    interpreter AI-Prowler itself runs on) — no Python312/Python310 fallbacks
  * the installer bundles python-3.11.x

Run: run_tests.bat tests\\unit\\test_python311_pinned.py -v
"""
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent


def _tracked_py():
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "*.py"], capture_output=True,
                             text=True, encoding="utf-8", check=True).stdout
        return [f for f in out.splitlines() if f]
    except Exception:
        return [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*.py")
                if "__pycache__" not in p.parts and ".git" not in p.parts]


def test_running_on_python_311():
    assert sys.version_info[:2] == (3, 11), f"tests must run on Python 3.11, not {sys.version.split()[0]}"


def test_every_tracked_file_compiles_on_311():
    if sys.version_info[:2] != (3, 11):
        pytest.skip("only meaningful on 3.11")
    bad = []
    for f in _tracked_py():
        try:
            compile((ROOT / f).read_bytes(), f, "exec")
        except SyntaxError as e:
            bad.append(f"{f}:{e.lineno}: {e.msg}")
    assert not bad, "needs a newer Python:\n  " + "\n  ".join(bad)


_NEW_FEATURES = {
    r"\bitertools\.batched\b|from itertools import[^\n]*\bbatched\b": "itertools.batched (3.12)",
    r"\btyping\.override\b|from typing import[^\n]*\boverride\b": "typing.override (3.12)",
    r"\.walk\(top_down": "Path.walk (3.12)",
    r"\bsys\.monitoring\b": "sys.monitoring (3.12)",
}


def test_no_312_library_features():
    hits = []
    for f in _tracked_py():
        # the checkers themselves list the 3.12 names as search patterns
        if f in ("tests/unit/test_python311_pinned.py", "tests/dev/py311_check.py"):
            continue
        text = (ROOT / f).read_text(encoding="utf-8", errors="replace")
        for rx, what in _NEW_FEATURES.items():
            for m in re.finditer(rx, text):
                hits.append(f"{f}: {what}")
    assert not hits, "3.12+ features:\n  " + "\n  ".join(sorted(set(hits)))


def test_run_script_finders_want_311_only():
    src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    for v in ("Python312", "Python313", "Python310"):
        assert f'"{v}"' not in src, f"interpreter finder still falls back to {v}"
    assert src.count('"Programs", "Python", "Python311", "python.exe"') >= 2


def test_installer_bundles_311():
    iss = (ROOT / "AI-Prowler-Setup.iss").read_text(encoding="utf-8", errors="replace")
    bundled = set(re.findall(r"python-(3\.\d+)\.\d+-amd64\.exe", iss))
    assert bundled == {"3.11"}, f"installer bundles {bundled or 'no'} Python installer(s)"
