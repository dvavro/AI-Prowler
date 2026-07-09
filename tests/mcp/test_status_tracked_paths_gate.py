"""
tests/mcp/test_status_tracked_paths_gate.py
==============================================
Tests for check_ai_prowler_status()'s server-mode tracked-paths gate.

Background
----------
check_ai_prowler_status() previously took NO parameters at all — no ctx —
and was explicitly, deliberately built (per its own v7.0.1 comment) to
always enumerate every ChromaDB collection company-wide for the chunk
count. That's reasonable for a basic health-check number, but the SAME
unscoped behavior also applied to the tracked-paths list, which reveals
real internal folder/file names to every role in server mode — the same
class of leak found and fixed in get_knowledge_base_overview's tracked-
dirs footer and list_tracked_directories.

Fixed with a split policy:
  - Chunk count / connectivity: stays unscoped in ALL cases — it's a
    basic "is the server alive" signal, not a data-browsing result.
  - Tracked-paths list: server mode now gates this to owner/manager only,
    via the same _check_db_cap('full') function list_tracked_directories
    and update_tracked_directories already use. Staff/field_crew still
    see everything else (chunk count, health status) — only the
    tracked-paths section is omitted for them.

Personal mode is completely unaffected — the existing 21 tests in
test_status_chunk_count.py / test_database_stats_collections.py all call
with no ctx at all and remain green (verified separately).
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _user(role, uid="test-user"):
    return {"id": uid, "name": "Test User", "role": role, "status": "active"}


def _wire_chroma_mocks(mcp_mod, monkeypatch):
    fake_col = MagicMock()
    fake_col.count.return_value = 5
    fake_col.name = "documents"
    fake_client = MagicMock()
    fake_client.list_collections.return_value = [fake_col]
    fake_client.get_collection.return_value = fake_col

    import rag_preprocessor
    monkeypatch.setattr(rag_preprocessor, "get_chroma_client",
                        lambda: (fake_client, MagicMock()))
    monkeypatch.setattr(rag_preprocessor, "load_auto_update_list",
                        lambda: ["C:/company/private-folder", "C:/company/secret-project.docx"])


class TestChunkCountAlwaysShown:
    """The health-check number stays unscoped for every role — that part
    of the design is unchanged and must remain so."""

    @pytest.mark.parametrize("role", [None, "owner", "manager", "staff", "field_crew"])
    def test_chunk_count_visible_for_every_role(self, mcp_mod, monkeypatch, role):
        user = _user(role) if role else None
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        _wire_chroma_mocks(mcp_mod, monkeypatch)

        result = mcp_mod.check_ai_prowler_status(ctx=_make_ctx(user))
        assert "Chunks" in result
        assert "ChromaDB" in result


class TestTrackedPathsGate:

    def test_personal_mode_shows_tracked_paths(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        _wire_chroma_mocks(mcp_mod, monkeypatch)

        result = mcp_mod.check_ai_prowler_status(ctx=None)
        assert "Tracked paths" in result
        assert "private-folder" in result

    def test_owner_sees_tracked_paths(self, mcp_mod, monkeypatch):
        user = _user("owner")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        _wire_chroma_mocks(mcp_mod, monkeypatch)

        result = mcp_mod.check_ai_prowler_status(ctx=_make_ctx(user))
        assert "Tracked paths" in result
        assert "private-folder" in result

    def test_manager_sees_tracked_paths(self, mcp_mod, monkeypatch):
        user = _user("manager")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        _wire_chroma_mocks(mcp_mod, monkeypatch)

        result = mcp_mod.check_ai_prowler_status(ctx=_make_ctx(user))
        assert "Tracked paths" in result

    def test_staff_does_not_see_tracked_paths(self, mcp_mod, monkeypatch):
        """Core fix: staff must not see the real folder/file names."""
        user = _user("staff")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        _wire_chroma_mocks(mcp_mod, monkeypatch)

        result = mcp_mod.check_ai_prowler_status(ctx=_make_ctx(user))
        assert "Tracked paths" not in result
        assert "private-folder" not in result
        assert "secret-project" not in result
        # But the health check itself must still work.
        assert "Chunks" in result

    def test_field_crew_does_not_see_tracked_paths(self, mcp_mod, monkeypatch):
        user = _user("field_crew")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        _wire_chroma_mocks(mcp_mod, monkeypatch)

        result = mcp_mod.check_ai_prowler_status(ctx=_make_ctx(user))
        assert "Tracked paths" not in result
        assert "private-folder" not in result
        assert "Chunks" in result

    def test_gate_matches_check_db_cap_full(self, mcp_mod, monkeypatch):
        """Locks in that this uses the SAME _check_db_cap('full') gate as
        list_tracked_directories and update_tracked_directories."""
        user = _user("staff")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        _wire_chroma_mocks(mcp_mod, monkeypatch)

        expected_ok, _ = mcp_mod._check_db_cap(user, "full")
        assert expected_ok is False

        result = mcp_mod.check_ai_prowler_status(ctx=_make_ctx(user))
        assert "Tracked paths" not in result
