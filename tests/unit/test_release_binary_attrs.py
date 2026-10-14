"""Release integrity: every file type release.py hashes RAW (no CRLF->LF
normalisation) must be declared binary in .gitattributes.

Why (2026-10-14, v9.3.0): write_update_manifest() hashes binary types byte-for-
byte from the working copy, but git only keeps those bytes if it knows the file
is binary. The HR Portal PDFs have no zero bytes, so git (core.autocrlf=true)
treated them as text and stripped their CRs on commit; raw.githubusercontent.com
then served different bytes and every in-app update failed its integrity check
on 4 PDFs. Declaring the types binary in .gitattributes prevents that.
"""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _binary_exts_from_release_py():
    src = (ROOT / "scripts" / "release.py").read_text(encoding="utf-8")
    m = re.search(r"_BINARY_EXTS\s*=\s*\{(.*?)\}", src, re.S)
    assert m, "_BINARY_EXTS not found in scripts/release.py"
    body = "\n".join(l.split("#", 1)[0] for l in m.group(1).splitlines())   # drop comments
    exts = set(re.findall(r'"(\.[a-z0-9]+)"', body))
    assert ".pdf" in exts and ".png" in exts, exts
    return exts


def _gitattributes_binary_exts():
    txt = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    return {"." + m.group(1).lower()
            for m in re.finditer(r"^\*\.([A-Za-z0-9]+)\s+.*\bbinary\b", txt, re.M)}


def test_every_raw_hashed_type_is_binary_in_gitattributes():
    missing = _binary_exts_from_release_py() - _gitattributes_binary_exts()
    assert not missing, (f"declare these binary in .gitattributes or GitHub may serve "
                         f"different bytes than update_manifest.json hashes: {sorted(missing)}")


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
