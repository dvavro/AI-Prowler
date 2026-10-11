"""
tests/mcp_tests/test_grant_revoke_access.py
============================================
(2026-10-08) grant_access / revoke_access MCP-tool behavior — complements
test_r071_access_only.py (which covers the allowlist save/load round-trip,
the read/write gates, the blocklist override, and the new-tool checklist).

Covers the end-to-end permission lifecycle the R-071 file does not:
1. grant_access -> the folder becomes readable via the read gate
2. revoke_access -> the folder is no longer readable via the read gate
3. An access-only folder is NEVER indexed: it appears only in the
   "Access-only folders (readable, not indexed)" section of
   list_tracked_directories, never in "Indexed directories (in ChromaDB)"
4. grant_access does NOT imply write: a separate grant_write_access is
   still required before the write gate allows the path
5. grant_access + grant_write_access -> write gate allows the path
6. revoke_access -> a later grant_write_access is rejected again
   (the two lists stay in sync)

Run: run_tests.bat tests\\mcp_tests\\test_grant_revoke_access.py -v
"""
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def ap():
    import ai_prowler_mcp as _ap
    _ap._prewarm_event.set()
    return _ap


@pytest.fixture()
def acc(ap, tmp_path, monkeypatch):
    """ai_prowler_mcp with all home-dir state files redirected into tmp_path,
    the tracked read list stubbed empty, and telemetry silenced."""
    monkeypatch.setattr(ap, "_ACCESS_ONLY_DIRS_FILE",
                        tmp_path / ".rag_access_only_dirs.json")
    monkeypatch.setattr(ap, "_WRITABLE_DIRS_FILE",
                        tmp_path / ".rag_writable_dirs.json")
    monkeypatch.setattr(ap, "_WRITE_APPROVAL_QUEUE_FILE",
                        tmp_path / ".rag_writable_pending.json")
    monkeypatch.setattr(ap, "_telemetry_increment_tool_count",
                        lambda *a, **k: None)
    import rag_preprocessor as _rag
    monkeypatch.setattr(_rag, "load_auto_update_list", lambda: [])
    monkeypatch.setattr(ap, "load_auto_update_list", lambda: [])
    return ap


# ── 1. grant -> readable via the read gate ────────────────────────────────

def test_grant_makes_folder_readable_via_read_gate(acc, tmp_path):
    d = tmp_path / "readable"
    d.mkdir()
    (d / "notes.txt").write_text("hello", encoding="utf-8")

    msg = acc.grant_access(str(d))
    assert msg.startswith("✅"), msg

    allowed, info = acc._is_path_under_tracked_roots(str(d / "notes.txt"))
    assert allowed is True, info


# ── 2. revoke -> no longer readable via the read gate ─────────────────────

def test_revoke_makes_folder_unreadable_via_read_gate(acc, tmp_path):
    d = tmp_path / "revoked"
    d.mkdir()
    target = d / "notes.txt"
    target.write_text("hello", encoding="utf-8")

    assert acc.grant_access(str(d)).startswith("✅")
    allowed, _ = acc._is_path_under_tracked_roots(str(target))
    assert allowed is True

    msg = acc.revoke_access(str(d))
    assert msg.startswith("✅"), msg

    allowed2, info2 = acc._is_path_under_tracked_roots(str(target))
    assert allowed2 is False
    # Both allowlists are empty now, so the gate reports the empty-list
    # reason (with a non-empty list it would say "not under any tracked
    # root or access-only folder").
    assert info2 in ("tracked-paths allowlist is empty",
                     "not under any tracked root or access-only folder"), info2


# ── 3. access-only folders are NEVER indexed ──────────────────────────────

def test_access_only_folder_listed_but_never_indexed(acc, tmp_path):
    d = tmp_path / "never_indexed"
    d.mkdir()
    assert acc.grant_access(str(d)).startswith("✅")

    out = acc.list_tracked_directories()
    resolved = str(d.resolve())

    # It shows up in the access-only section ...
    assert "📂 Access-only folders (readable, not indexed):" in out
    assert resolved in out
    # ... but NOT in the indexed (ChromaDB) section.
    indexed_section = out.split("📂 Access-only folders")[0]
    assert "📁 Indexed directories (in ChromaDB):" in indexed_section
    assert "(none)" in indexed_section
    assert resolved not in indexed_section


def test_access_only_folder_not_in_tracked_read_list(acc, tmp_path):
    # The tracked/indexed read list (what the auto-update sweep walks)
    # must not gain the access-only folder.
    d = tmp_path / "not_tracked"
    d.mkdir()
    assert acc.grant_access(str(d)).startswith("✅")
    assert str(d.resolve()) not in acc.load_auto_update_list()


def test_access_only_section_badge_is_read_only(acc, tmp_path):
    d = tmp_path / "badge_check"
    d.mkdir()
    assert acc.grant_access(str(d)).startswith("✅")
    out = acc.list_tracked_directories()
    access_section = out.split("📂 Access-only folders")[1]
    line = next(ln for ln in access_section.splitlines()
                if str(d.resolve()) in ln)
    assert "[R]" in line, line
    assert "[W]" not in line, line


# ── 4/5/6. write still requires a SEPARATE grant_write_access ─────────────

def test_grant_access_does_not_grant_write(acc, tmp_path):
    d = tmp_path / "read_only_still"
    d.mkdir()
    target = d / "f.txt"
    target.write_text("x", encoding="utf-8")

    assert acc.grant_access(str(d)).startswith("✅")
    # Read: allowed. Write: still denied (queues GUI approval instead).
    allowed, _ = acc._is_path_under_tracked_roots(str(target))
    assert allowed is True
    resolved, err = acc._resolve_writable_path(str(target), queue_approval=True)
    assert resolved is None
    assert err is not None
    assert str(d.resolve()) not in acc._writable_allowlist_load()


def test_grant_write_access_after_grant_access_allows_write(acc, tmp_path):
    d = tmp_path / "now_writable"
    d.mkdir()
    target = d / "f.txt"
    target.write_text("x", encoding="utf-8")

    assert acc.grant_access(str(d)).startswith("✅")
    assert acc.grant_write_access(str(d)).startswith("✅")

    resolved, err = acc._resolve_writable_path(str(target), queue_approval=True)
    assert err is None, err
    assert resolved is not None


def test_revoke_access_rejects_later_grant_write_access(acc, tmp_path):
    d = tmp_path / "revoke_then_write"
    d.mkdir()
    assert acc.grant_access(str(d)).startswith("✅")
    assert acc.revoke_access(str(d)).startswith("✅")

    # The folder left the read allowlist, so grant_write_access must
    # refuse it again — the two lists stay in sync.
    msg = acc.grant_write_access(str(d))
    assert "not in the read allowlist" in msg


# ── 7. selective revoke keeps the other folder readable ──────────────────

def test_selective_revoke_keeps_other_folder_readable(acc, tmp_path):
    a = tmp_path / "folder_a"
    b = tmp_path / "folder_b"
    a.mkdir()
    b.mkdir()
    (a / "x.txt").write_text("a", encoding="utf-8")
    (b / "x.txt").write_text("b", encoding="utf-8")

    assert acc.grant_access(str(a)).startswith("✅")
    assert acc.grant_access(str(b)).startswith("✅")
    assert acc.revoke_access(str(a)).startswith("✅")

    allowed_a, _ = acc._is_path_under_tracked_roots(str(a / "x.txt"))
    allowed_b, _ = acc._is_path_under_tracked_roots(str(b / "x.txt"))
    assert allowed_a is False
    assert allowed_b is True
    assert acc.access_allowlist_load() == [str(b.resolve())]
