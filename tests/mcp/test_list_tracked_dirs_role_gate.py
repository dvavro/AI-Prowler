"""
tests/mcp/test_list_tracked_dirs_role_gate.py
================================================
Tests for the owner/manager-only role gate added to
list_tracked_directories().

Background
----------
list_tracked_directories() previously took no ctx parameter at all — it
called load_auto_update_list() directly and returned the full, unscoped,
company-wide list of every tracked path to any role, including
field_crew, with no way to restrict it even in principle.

Its two sibling tools, untrack_directory and update_tracked_directories,
were already gated to owner/manager only via _check_db_cap(user, "full").
list_tracked_directories exists to support that same tracking-
administration workflow, so it now uses the identical gate.

Personal mode (ctx has no user) is completely unaffected — existing tests
in test_mcp_tools.py call it with no ctx at all and must keep passing.
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


class TestRoleGate:

    def test_personal_mode_unrestricted(self, mcp_mod, monkeypatch):
        """Personal mode: no ctx at all, exactly like every existing test —
        must remain fully unrestricted, unchanged from before this gate."""
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/docs"])
        result = mcp_mod.list_tracked_directories()
        assert "⛔" not in result
        assert "C:/docs" in result

    def test_owner_allowed(self, mcp_mod, monkeypatch):
        user = _user("owner")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/docs"])
        result = mcp_mod.list_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" not in result
        assert "C:/docs" in result

    def test_manager_allowed(self, mcp_mod, monkeypatch):
        user = _user("manager")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/docs"])
        result = mcp_mod.list_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" not in result
        assert "C:/docs" in result

    def test_staff_denied(self, mcp_mod, monkeypatch):
        user = _user("staff")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        # If the gate is bypassed, this tripwire path would be hit.
        monkeypatch.setattr(mcp_mod, "load_auto_update_list",
                            lambda: (_ for _ in ()).throw(
                                AssertionError("gate should have short-circuited before this call")))
        result = mcp_mod.list_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" in result

    def test_field_crew_denied(self, mcp_mod, monkeypatch):
        user = _user("field_crew")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list",
                            lambda: (_ for _ in ()).throw(
                                AssertionError("gate should have short-circuited before this call")))
        result = mcp_mod.list_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" in result

    def test_gate_matches_untrack_directory_exactly(self, mcp_mod, monkeypatch):
        """Locks in that this uses the SAME _check_db_cap('full') gate as
        untrack_directory, rather than a separately-maintained check that
        could silently drift out of sync."""
        user = _user("staff")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        expected_ok, expected_reason = mcp_mod._check_db_cap(user, "full")
        result = mcp_mod.list_tracked_directories(ctx=_make_ctx(user))
        assert expected_ok is False
        assert expected_reason in result
