"""
tests/mcp/test_update_tracked_dirs_role_gate.py
==================================================
Tests for update_tracked_directories()'s server-mode role gate — closing
the same class of coverage gap found and fixed for its sibling tool,
list_tracked_directories, earlier in this session.

Background
----------
update_tracked_directories() has always been correctly gated in the code
— _check_db_cap(user, "full") restricts it to owner/manager only, and it
was already collection-aware (_build_collection_resolver) and purge-safe
(_can_purge_chunks) from the start, unlike the bug found in
reindex_file/reindex_directory.

But the existing functional tests (test_mcp_tools.py::G-MCP-03a/03b) only
ever call it with no ctx at all — personal mode. The server-mode role
gate itself had ZERO dedicated regression coverage: nothing would catch
it if a future refactor accidentally broke the gate. A comment in
test_list_tracked_dirs_role_gate.py asserted this tool was "already
gated," based on reading the source, not on any verifying test.

This file closes that gap, mirroring test_list_tracked_dirs_role_gate.py's
exact pattern for consistency.
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
        """Personal mode: no ctx at all — must remain fully unrestricted,
        matching G-MCP-03a/03b's existing no-ctx calls."""
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/docs"])
        monkeypatch.setattr(mcp_mod, "command_update", lambda *a, **k: None)

        result = mcp_mod.update_tracked_directories()
        assert "⛔" not in result

    def test_owner_allowed(self, mcp_mod, monkeypatch):
        user = _user("owner")
        called = {"command_update": False}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/docs"])
        monkeypatch.setattr(mcp_mod, "_build_collection_resolver", lambda u: (lambda fp: "documents"))
        monkeypatch.setattr(mcp_mod, "_owner_user_id", lambda: "owner-id")
        monkeypatch.setattr(mcp_mod, "_can_purge_chunks", lambda u, m, oid: (True, "ok"))

        def _fake_command_update(*a, **k):
            called["command_update"] = True
        monkeypatch.setattr(mcp_mod, "command_update", _fake_command_update)

        result = mcp_mod.update_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" not in result
        assert called["command_update"] is True

    def test_manager_allowed(self, mcp_mod, monkeypatch):
        user = _user("manager")
        called = {"command_update": False}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/docs"])
        monkeypatch.setattr(mcp_mod, "_build_collection_resolver", lambda u: (lambda fp: "documents"))
        monkeypatch.setattr(mcp_mod, "_owner_user_id", lambda: "owner-id")
        monkeypatch.setattr(mcp_mod, "_can_purge_chunks", lambda u, m, oid: (True, "ok"))

        def _fake_command_update(*a, **k):
            called["command_update"] = True
        monkeypatch.setattr(mcp_mod, "command_update", _fake_command_update)

        result = mcp_mod.update_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" not in result
        assert called["command_update"] is True

    def test_staff_denied(self, mcp_mod, monkeypatch):
        user = _user("staff")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        # Tripwires: if the gate is bypassed, either of these paths would
        # be hit — proving the check happens BEFORE any scan/work occurs.
        monkeypatch.setattr(mcp_mod, "load_auto_update_list",
                            lambda: (_ for _ in ()).throw(
                                AssertionError("gate should have short-circuited before this call")))
        monkeypatch.setattr(mcp_mod, "command_update",
                            lambda *a, **k: (_ for _ in ()).throw(
                                AssertionError("gate should have short-circuited before this call")))

        result = mcp_mod.update_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" in result

    def test_field_crew_denied(self, mcp_mod, monkeypatch):
        user = _user("field_crew")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list",
                            lambda: (_ for _ in ()).throw(
                                AssertionError("gate should have short-circuited before this call")))
        monkeypatch.setattr(mcp_mod, "command_update",
                            lambda *a, **k: (_ for _ in ()).throw(
                                AssertionError("gate should have short-circuited before this call")))

        result = mcp_mod.update_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" in result

    def test_gate_matches_untrack_directory_exactly(self, mcp_mod, monkeypatch):
        """Locks in that this uses the SAME _check_db_cap('full') gate as
        untrack_directory and list_tracked_directories, rather than a
        separately-maintained check that could silently drift out of sync."""
        user = _user("staff")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        expected_ok, expected_reason = mcp_mod._check_db_cap(user, "full")
        result = mcp_mod.update_tracked_directories(ctx=_make_ctx(user))
        assert expected_ok is False
        assert expected_reason in result
