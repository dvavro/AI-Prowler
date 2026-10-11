"""
Access-only folders — the ADD rules (David 2026-10-10), personal mode only.

    1. Folders only — always recursive, never an individual file.
    2. No duplicates.
    3. A folder already covered by an access-only folder is refused ("already
       covered by access-only folder …"); so is one already readable through an
       INDEXED folder (David: "Yes, refuse").
    Adding a folder that CONTAINS access-only folders is allowed and folds them
    in — they're removed from the list (David: "Allow, drop the inner ones").

One shared check (rag_preprocessor.access_only_add_check) used by the desktop
panel, Claude's grant_access and — through grant_access — the Remote app.
Server mode never gets this far (grant_access refuses; see
test_access_only_server_blocked.py).

Run: run_tests.bat tests\\mcp_tests\\test_access_only_add_rules.py -v
"""
import json
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture()
def rag(tmp_path, monkeypatch):
    import rag_preprocessor as _rag
    monkeypatch.setattr(_rag, "AUTO_UPDATE_LIST", tmp_path / "auto_update_dirs.json")
    monkeypatch.setattr(_rag, "generate_auto_update_script", lambda: None)
    return _rag


@pytest.fixture()
def tree(tmp_path):
    root = tmp_path / "ao_rules"
    for p in ("Docs/Manuals/Old", "Docs/Other", "Indexed/Inside", "Plain"):
        (root / p).mkdir(parents=True)
    (root / "Docs" / "note.txt").write_text("x", encoding="utf-8")
    (root / "Indexed" / "single.txt").write_text("x", encoding="utf-8")
    return root


def _chk(rag, path, access, tracked=()):
    return rag.access_only_add_check(str(path), [str(a) for a in access], [str(t) for t in tracked])


# ── the shared check ─────────────────────────────────────────────────────────
def test_rule1_folders_only(rag, tree):
    r = _chk(rag, tree / "Docs" / "note.txt", [])
    assert not r["ok"] and "is a file" in r["error"] and "folders only" in r["error"], r
    assert not _chk(rag, tree / "missing", [])["ok"]
    assert not _chk(rag, "", [])["ok"]


def test_rule2_no_duplicates(rag, tree):
    r = _chk(rag, tree / "Docs", [tree / "Docs"])
    assert not r["ok"] and "already an access-only folder" in r["error"], r
    # same folder spelled with '/' (how some entries are stored)
    r = _chk(rag, tree / "Docs", [str(tree / "Docs").replace("\\", "/")])
    assert not r["ok"] and "already an access-only folder" in r["error"], r
    if sys.platform == "win32":
        r = _chk(rag, str(tree / "Docs").upper(), [tree / "Docs"])
        assert not r["ok"] and "already an access-only folder" in r["error"], r


def test_rule3_covered_by_access_only_folder(rag, tree):
    for inner in (tree / "Docs" / "Manuals", tree / "Docs" / "Manuals" / "Old"):
        r = _chk(rag, inner, [tree / "Docs"])
        assert not r["ok"], r
        assert "already covered by access-only folder" in r["error"] and str(tree / "Docs") in r["error"], r


def test_rule3_covered_by_indexed_folder(rag, tree):
    r = _chk(rag, tree / "Indexed" / "Inside", [], tracked=[tree / "Indexed"])
    assert not r["ok"] and "inside indexed folder" in r["error"], r
    r = _chk(rag, tree / "Indexed", [], tracked=[tree / "Indexed"])
    assert not r["ok"] and "already an indexed folder" in r["error"], r
    # a single tracked FILE covers no folder
    assert _chk(rag, tree / "Indexed", [], tracked=[tree / "Indexed" / "single.txt"])["ok"]


def test_sibling_with_same_prefix_is_not_covered(rag, tree):
    (tree / "DocsArchive").mkdir()
    r = _chk(rag, tree / "DocsArchive", [tree / "Docs"], tracked=[tree / "Doc"])
    assert r["ok"], r


def test_parent_folds_inner_access_only_folders(rag, tree):
    r = _chk(rag, tree / "Docs", [tree / "Docs" / "Manuals", tree / "Docs" / "Other", tree / "Plain"])
    assert r["ok"], r
    assert sorted(r["folded"]) == sorted([str(tree / "Docs" / "Manuals"), str(tree / "Docs" / "Other")]), r
    assert r["path"] == str((tree / "Docs").resolve())


def test_uses_the_real_tracked_list_by_default(rag, tree):
    rag.add_to_auto_update_list(str(tree / "Indexed"))
    r = rag.access_only_add_check(str(tree / "Indexed" / "Inside"), [])
    assert not r["ok"] and "inside indexed folder" in r["error"], r


# ── grant_access (Claude, and the Remote app through /remote-api) ────────────
@pytest.fixture()
def acc(rag, tmp_path, monkeypatch):
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    monkeypatch.setattr(ap, "_ACCESS_ONLY_DIRS_FILE", tmp_path / ".rag_access_only_dirs.json")
    monkeypatch.setattr(ap, "_telemetry_increment_tool_count", lambda *a, **k: None)
    monkeypatch.setattr(ap, "_IS_SERVER_MODE", False)
    return ap


def _list(ap):
    return ap.access_allowlist_load()


def test_grant_access_applies_every_rule(acc, rag, tree):
    assert acc.grant_access(str(tree / "Docs" / "Manuals")).startswith("✅")
    assert acc.grant_access(str(tree / "Docs" / "Other")).startswith("✅")
    # file
    m = acc.grant_access(str(tree / "Docs" / "note.txt"))
    assert m.startswith("❌") and "is a file" in m, m
    # duplicate
    m = acc.grant_access(str(tree / "Docs" / "Manuals"))
    assert m.startswith("❌") and "already an access-only folder" in m, m
    # covered
    m = acc.grant_access(str(tree / "Docs" / "Manuals" / "Old"))
    assert m.startswith("❌") and "already covered by access-only folder" in m, m
    # inside an indexed folder
    rag.add_to_auto_update_list(str(tree / "Indexed"))
    m = acc.grant_access(str(tree / "Indexed" / "Inside"))
    assert m.startswith("❌") and "inside indexed folder" in m, m
    assert sorted(_list(acc)) == sorted([str((tree / "Docs" / "Manuals").resolve()),
                                         str((tree / "Docs" / "Other").resolve())])


def test_grant_access_parent_folds_the_inner_ones(acc, tree):
    acc.grant_access(str(tree / "Docs" / "Manuals"))
    acc.grant_access(str(tree / "Docs" / "Other"))
    acc.grant_access(str(tree / "Plain"))
    m = acc.grant_access(str(tree / "Docs"))
    assert m.startswith("✅") and "Folded in" in m, m
    assert "Manuals" in m and "Other" in m, m
    assert sorted(_list(acc)) == sorted([str((tree / "Plain").resolve()), str((tree / "Docs").resolve())])


def test_grant_access_refused_on_a_server_before_any_rule(acc, tree, monkeypatch):
    monkeypatch.setattr(acc, "_IS_SERVER_MODE", True)
    m = acc.grant_access(str(tree / "Docs"))
    assert m.startswith("❌") and "personal-mode feature" in m, m
    assert not acc._ACCESS_ONLY_DIRS_FILE.exists()


def test_how_to_use_states_the_rules(acc):
    body = acc.how_to_use_ai_prowler(None)
    i = body.find("Access-only folders (personal mode only")
    section = body[i:i + 1600]
    for t in ("Folders only", "duplicate", "already covered", "folded in"):
        assert t in section, f"{t!r} missing:\n{section}"
