"""
tests/mcp/test_untrack_directory_scope_gate.py
================================================
Tests for untrack_directory()'s v8.1.5 TWO-TIER gate, replacing the earlier
blanket owner/manager-only role gate (_check_db_cap(user, 'full')).

Direct product decision:
  • Tier 1 — own personal directory: ANY role may untrack a path inside
    their own personal directory, no admin flag required. Reuses the exact
    same _check_personal_write_scope() check already enforced by
    create_file/write_file/str_replace_in_file/line_replace_in_file, so this
    tool and the write tools always agree on what counts as "your own area."
  • Tier 2 — everywhere else (a shared scope, another user's private
    folder, or general company-wide tracked state): requires the owner, OR
    a manager/staff member with delegated admin rights (can_manage_users —
    the Admin tab's "Can manage users" checkbox). Plain role membership
    alone ('manager' or 'staff' with no flag) is NOT sufficient outside
    their own directory.

Personal mode (ctx has no user) is unaffected — _check_personal_write_scope
already returns None (allowed) immediately for personal mode, so the role/
admin branch is never reached.
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


def _user(role, uid="test-user", can_manage_users=False):
    return {"id": uid, "name": "Test User", "role": role, "status": "active",
            "can_manage_users": can_manage_users}


class TestOwnPersonalDirectoryAnyRole:
    """Tier 1 — inside the caller's own personal directory, every role is
    allowed, no admin flag needed."""

    def _run(self, mcp_mod, monkeypatch, role):
        user = _user(role)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        # Inside own personal directory -> _check_personal_write_scope
        # returns None (allowed), regardless of role/admin flag.
        monkeypatch.setattr(mcp_mod, "_check_personal_write_scope",
                             lambda ctx, path: None)
        monkeypatch.setattr(
            mcp_mod, "remove_directory_from_index",
            lambda directory: {"chunks_removed": 3, "files_removed": 1})
        result = mcp_mod.untrack_directory(
            directory="C:/field/some-users-private/notes.txt",
            ctx=_make_ctx(user))
        assert "⛔" not in result
        assert "3 chunk" in result

    def test_owner_own_dir(self, mcp_mod, monkeypatch):
        self._run(mcp_mod, monkeypatch, "owner")

    def test_manager_own_dir(self, mcp_mod, monkeypatch):
        self._run(mcp_mod, monkeypatch, "manager")

    def test_staff_own_dir(self, mcp_mod, monkeypatch):
        self._run(mcp_mod, monkeypatch, "staff")

    def test_field_crew_own_dir(self, mcp_mod, monkeypatch):
        """The key case David asked for: field crew, who typically can only
        add files to their own private directory, must be able to untrack
        there too."""
        self._run(mcp_mod, monkeypatch, "field_crew")


class TestOutsideOwnDirectoryRequiresOwnerOrAdmin:
    """Tier 2 — a path outside the caller's own personal directory."""

    def _run(self, mcp_mod, monkeypatch, user, expect_denied):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        # Outside own personal directory -> _check_personal_write_scope
        # returns a denial string (content doesn't matter here; only that
        # it's non-None, meaning "not your own directory").
        monkeypatch.setattr(
            mcp_mod, "_check_personal_write_scope",
            lambda ctx, path: "🚫 outside your personal directory")
        monkeypatch.setattr(
            mcp_mod, "remove_directory_from_index",
            lambda directory: {"chunks_removed": 5, "files_removed": 2})
        result = mcp_mod.untrack_directory(
            directory="C:/shared/company-docs", ctx=_make_ctx(user))
        if expect_denied:
            assert "⛔" in result
        else:
            assert "⛔" not in result
            assert "5 chunk" in result

    def test_owner_allowed_anywhere(self, mcp_mod, monkeypatch):
        self._run(mcp_mod, monkeypatch, _user("owner"), expect_denied=False)

    def test_plain_manager_denied(self, mcp_mod, monkeypatch):
        """A plain manager with no delegated admin flag is denied outside
        their own directory — role membership alone is not enough."""
        self._run(mcp_mod, monkeypatch, _user("manager", can_manage_users=False),
                   expect_denied=True)

    def test_manager_with_admin_flag_allowed(self, mcp_mod, monkeypatch):
        self._run(mcp_mod, monkeypatch, _user("manager", can_manage_users=True),
                   expect_denied=False)

    def test_plain_staff_denied(self, mcp_mod, monkeypatch):
        self._run(mcp_mod, monkeypatch, _user("staff", can_manage_users=False),
                   expect_denied=True)

    def test_staff_with_admin_flag_allowed(self, mcp_mod, monkeypatch):
        """Direct product decision: 'staff with admin privileges' must be
        allowed too — the delegated flag, not the role name, is what
        actually grants it."""
        self._run(mcp_mod, monkeypatch, _user("staff", can_manage_users=True),
                   expect_denied=False)

    def test_plain_field_crew_denied(self, mcp_mod, monkeypatch):
        self._run(mcp_mod, monkeypatch, _user("field_crew", can_manage_users=False),
                   expect_denied=True)

    def test_field_crew_with_admin_flag_allowed(self, mcp_mod, monkeypatch):
        """Even field_crew, if delegated admin rights, is allowed outside
        their own directory — the flag is role-independent."""
        self._run(mcp_mod, monkeypatch, _user("field_crew", can_manage_users=True),
                   expect_denied=False)


class TestPersonalModeUnaffected:

    def test_personal_mode_no_ctx(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        # Personal mode -> _check_personal_write_scope returns None itself
        # via its own status=="personal" branch; simulate that directly.
        monkeypatch.setattr(mcp_mod, "_check_personal_write_scope",
                             lambda ctx, path: None)
        monkeypatch.setattr(
            mcp_mod, "remove_directory_from_index",
            lambda directory: {"chunks_removed": 1, "files_removed": 1})
        result = mcp_mod.untrack_directory(directory="C:/docs")
        assert "⛔" not in result


class TestDeniedMessageContent:

    def test_denial_mentions_admin_rights_path(self, mcp_mod, monkeypatch):
        """The denial message should point the user toward the actual
        remedy (owner/admin, or ask for delegated rights) rather than a
        generic 'not allowed'."""
        user = _user("staff", can_manage_users=False)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(
            mcp_mod, "_check_personal_write_scope",
            lambda ctx, path: "🚫 outside your personal directory")
        result = mcp_mod.untrack_directory(
            directory="C:/shared/company-docs", ctx=_make_ctx(user))
        assert "⛔" in result
        assert "admin" in result.lower()
