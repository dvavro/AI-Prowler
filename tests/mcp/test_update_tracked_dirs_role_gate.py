"""
tests/mcp/test_update_tracked_dirs_role_gate.py
==================================================
Tests for update_tracked_directories()'s access — who may call it.

HISTORY: originally written to close a coverage gap — update_tracked_
directories() was gated via _check_db_cap(user, "full") (owner/manager
only), matching its sibling list_tracked_directories/untrack_directory,
but had zero dedicated regression coverage for that gate.

SUPERSEDED 2026-07-16/17 (SCOPE_SIMPLIFICATION_SPEC.md section 3.7, Phase
7 cutover): direct product decision — indexing isn't a data leak, and
every directory this tool touches was already admin/owner-created and
tracked in the first place, so the role gate is removed here. This was
originally a DELIBERATE divergence from list_tracked_directories/
untrack_directory, which kept their role gate — but both of those have
SINCE (v8.1.5) moved to their own non-role gates too: list_tracked_
directories to a scope gate (test_list_tracked_dirs_role_gate.py) and
untrack_directory to a two-tier own-directory-vs-owner/admin gate
(test_untrack_directory_scope_gate.py). The class below is kept for
historical continuity of the "staff blocked from X but allowed Y" contrast,
but "blocked from untrack" is no longer universally true for staff — only
outside their own personal directory, without delegated admin rights.
Destructive purging of deleted files (this tool's real risk) remains
protected separately by the ownership-based _purge_gate, which is
untouched.
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


class TestAnyRoleCanUpdateTrackedDirectories:

    def test_personal_mode_unrestricted(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/docs"])
        monkeypatch.setattr(mcp_mod, "command_update", lambda *a, **k: None)

        result = mcp_mod.update_tracked_directories()
        assert "⛔" not in result

    def _run_for_role(self, mcp_mod, monkeypatch, role):
        user = _user(role)
        called = {"command_update": False, "kwargs": None}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/docs"])
        monkeypatch.setattr(mcp_mod, "_owner_user_id", lambda: "owner-id")
        monkeypatch.setattr(mcp_mod, "_can_purge_chunks", lambda u, m, oid: (True, "ok"))

        def _fake_command_update(*a, **k):
            called["command_update"] = True
            called["kwargs"] = k
        monkeypatch.setattr(mcp_mod, "command_update", _fake_command_update)

        result = mcp_mod.update_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" not in result
        assert called["command_update"] is True
        return called

    def test_owner_allowed(self, mcp_mod, monkeypatch):
        self._run_for_role(mcp_mod, monkeypatch, "owner")

    def test_manager_allowed(self, mcp_mod, monkeypatch):
        self._run_for_role(mcp_mod, monkeypatch, "manager")

    def test_staff_now_allowed(self, mcp_mod, monkeypatch):
        """The old gate denied staff outright -- now allowed, same as
        every other role."""
        self._run_for_role(mcp_mod, monkeypatch, "staff")

    def test_field_crew_now_allowed(self, mcp_mod, monkeypatch):
        self._run_for_role(mcp_mod, monkeypatch, "field_crew")

    def test_no_collection_resolver_ever_passed(self, mcp_mod, monkeypatch):
        """There is only one physical collection now -- command_update
        must never receive a REAL collection_resolver (None is fine and
        is command_update's own unchanged default)."""
        called = self._run_for_role(mcp_mod, monkeypatch, "owner")
        assert called["kwargs"].get("collection_resolver") is None

    def test_purge_gate_still_wired(self, mcp_mod, monkeypatch):
        """Destructive purging protection (ownership-based, unrelated to
        the role gate) is untouched -- purge_gate is still passed through
        to command_update."""
        called = self._run_for_role(mcp_mod, monkeypatch, "owner")
        assert called["kwargs"].get("purge_gate") is not None


class TestDivergedFromUntrackDirectory:
    """Documents the deliberate divergence from list_tracked_directories/
    untrack_directory, which remain gated -- see
    test_list_tracked_dirs_role_gate.py."""

    def test_staff_blocked_from_untrack_but_allowed_to_update(self, mcp_mod, monkeypatch):
        user = _user("staff")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)

        # untrack_directory still gated -- unaffected by this cutover.
        untrack_result = mcp_mod.untrack_directory(directory="C:/docs", ctx=_make_ctx(user))
        assert "⛔" in untrack_result

        # update_tracked_directories is not -- the intentional divergence.
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/docs"])
        monkeypatch.setattr(mcp_mod, "_owner_user_id", lambda: "owner-id")
        monkeypatch.setattr(mcp_mod, "_can_purge_chunks", lambda u, m, oid: (True, "ok"))
        monkeypatch.setattr(mcp_mod, "command_update", lambda *a, **k: None)
        update_result = mcp_mod.update_tracked_directories(ctx=_make_ctx(user))
        assert "⛔" not in update_result
