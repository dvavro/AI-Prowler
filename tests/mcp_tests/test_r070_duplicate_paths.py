"""
R-070 (2026-10-08): Duplicate index-path detection.

Covers rag_preprocessor.add_to_auto_update_list():
    1. Subdirectory of an already-tracked entry -> warning STRING
       (not False, not True); the path is still added (warning, not block).
    2. Parent of an already-tracked entry      -> warning STRING.
    3. Exact duplicate                         -> False (existing no-op preserved).
    4. Non-overlapping path                    -> True (added normally).
    5. Case-insensitive duplicate (Windows)    -> existing case-variant
       behavior preserved (warning string; old entry replaced with the new
       casing; exactly one entry remains).

Run: run_tests.bat tests\\mcp_tests\\test_r070_duplicate_paths.py -v
"""
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture()
def rag(tmp_path, monkeypatch):
    """rag_preprocessor with the auto-update list redirected into tmp_path and
    the auto-update .bat regeneration stubbed out (no writes outside tmp)."""
    import rag_preprocessor as _rag
    monkeypatch.setattr(_rag, "AUTO_UPDATE_LIST",
                        tmp_path / "auto_update_dirs.json")
    monkeypatch.setattr(_rag, "generate_auto_update_script", lambda: None)
    return _rag


def _norm(rag, p):
    """The canonical stored form of a candidate path."""
    return rag.normalise_path(str(Path(p).resolve()))


# ── 1. subdirectory of an already-tracked entry ────────────────────────────

def test_subdirectory_of_tracked_entry_returns_warning_string(rag, tmp_path):
    parent = str(tmp_path / "r070" / "Docs")
    child = str(tmp_path / "r070" / "Docs" / "Sub")

    assert rag.add_to_auto_update_list(parent) is True

    result = rag.add_to_auto_update_list(child)
    assert isinstance(result, str)
    assert result is not True
    assert result is not False
    assert result.startswith("Warning:")
    assert "is inside already-indexed" in result

    # Warning, not block — the subdirectory was still added to the list.
    assert _norm(rag, child) in rag.load_auto_update_list()


# ── 2. parent of an already-tracked entry ──────────────────────────────────

def test_parent_of_tracked_entry_returns_warning_string(rag, tmp_path):
    child = str(tmp_path / "r070" / "Docs" / "Sub")
    parent = str(tmp_path / "r070" / "Docs")

    assert rag.add_to_auto_update_list(child) is True

    result = rag.add_to_auto_update_list(parent)
    assert isinstance(result, str)
    assert result is not True
    assert result is not False
    assert result.startswith("Warning:")
    assert "contains already-indexed" in result

    # Warning, not block — the parent was still added to the list.
    assert _norm(rag, parent) in rag.load_auto_update_list()


# ── 3. exact duplicate — existing no-op preserved ──────────────────────────

def test_exact_duplicate_is_noop(rag, tmp_path):
    d = str(tmp_path / "r070" / "Docs")

    assert rag.add_to_auto_update_list(d) is True
    assert rag.add_to_auto_update_list(d) is False
    assert rag.load_auto_update_list() == [_norm(rag, d)]


# ── 4. non-overlapping path — added normally ───────────────────────────────

def test_non_overlapping_path_added_normally(rag, tmp_path):
    a = str(tmp_path / "r070" / "Docs")
    b = str(tmp_path / "r070" / "Other")

    assert rag.add_to_auto_update_list(a) is True
    assert rag.add_to_auto_update_list(b) is True
    assert rag.load_auto_update_list() == [_norm(rag, a), _norm(rag, b)]


# ── 5. case-insensitive duplicate — existing behavior preserved ────────────

@pytest.mark.skipif(sys.platform != "win32",
                    reason="case-insensitive path handling is Windows-only")
def test_case_variant_replaces_existing_entry(rag, tmp_path):
    lower = str(tmp_path / "r070" / "docs")
    upper = str(tmp_path / "r070" / "DOCS")

    assert rag.add_to_auto_update_list(lower) is True

    result = rag.add_to_auto_update_list(upper)
    assert isinstance(result, str)
    assert result is not True
    assert result is not False
    assert "already tracked" in result

    # Old casing replaced with the new one; exactly one entry remains.
    entries = rag.load_auto_update_list()
    assert len(entries) == 1
    assert entries[0] == _norm(rag, upper)


# ── 6. case-insensitive overlap detection (Windows) ─────────────────────────

@pytest.mark.skipif(sys.platform != "win32",
                    reason="case-insensitive path handling is Windows-only")
def test_overlap_detection_is_case_insensitive(rag, tmp_path):
    parent = str(tmp_path / "r070" / "Docs")
    child_other_case = str(tmp_path / "R070" / "DOCS" / "Sub")

    assert rag.add_to_auto_update_list(parent) is True

    result = rag.add_to_auto_update_list(child_other_case)
    assert isinstance(result, str)
    assert "is inside already-indexed" in result
