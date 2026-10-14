"""Release integrity for in-app updates (2026-10-14, after v9.3.0 failed).

v9.3.0 shipped HR Portal PDFs that no client could verify, for two reasons:
  1. git treated the PDFs as text (no zero bytes) and, with core.autocrlf=true,
     stripped their CRs on commit -- GitHub served altered bytes;
  2. scripts/release.py hashed .pdf RAW while every client's updater
     (rag_gui.py _BIN_EXTS) hashes .pdf LF-normalised.

So: the manifest must hash exactly the way the client verifies (release.py
_BINARY_EXTS == client _BIN_EXTS), and every binary file type must be declared
binary in .gitattributes so the repo keeps its exact bytes.
"""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _set_literal(src, name):
    m = re.search(name + r"\s*=\s*\{(.*?)\}", src, re.S)
    assert m, f"{name} not found"
    body = "\n".join(l.split("#", 1)[0] for l in m.group(1).splitlines())   # drop comments
    return set(re.findall(r'"(\.[a-z0-9]+)"', body))


def _release_raw_exts():
    return _set_literal((ROOT / "scripts" / "release.py").read_text(encoding="utf-8"),
                        "_BINARY_EXTS")


def _client_raw_exts():
    return _set_literal((ROOT / "rag_gui.py").read_text(encoding="utf-8"), "_BIN_EXTS")


def _gitattributes_binary_exts():
    txt = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    return {"." + m.group(1).lower()
            for m in re.finditer(r"^\*\.([A-Za-z0-9]+)\s+.*\bbinary\b", txt, re.M)}


def test_manifest_hash_rule_matches_the_client_updater():
    rel, cli = _release_raw_exts(), _client_raw_exts()
    assert ".png" in cli, cli
    assert rel == cli, (f"release.py hashes raw {sorted(rel)} but the updater verifies raw "
                        f"{sorted(cli)} -- every file in the difference would fail on clients")


def test_binary_types_are_binary_in_gitattributes():
    need = _client_raw_exts() | {".pdf", ".xlsx", ".docx", ".db"}
    missing = need - _gitattributes_binary_exts()
    assert not missing, (f"declare these binary in .gitattributes or git may rewrite their "
                         f"bytes on commit: {sorted(missing)}")


def test_hr_portal_pdfs_resolve_as_binary():
    try:
        r = subprocess.run(["git", "-C", str(ROOT), "check-attr", "binary", "--",
                            "hr_portal/docs/AI_Prowler_Employee_Handbook_2026.pdf"],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("git not available")
    if r.returncode != 0:
        pytest.skip("not a git checkout")
    assert r.stdout.strip().endswith("binary: set"), r.stdout
