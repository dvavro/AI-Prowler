"""
tests/mcp/test_writable_dirs_server_scope.py
===============================================
Tests for list_writable_directories()'s server-mode split.

Background
----------
list_writable_directories() previously took a ctx parameter but never
read it — every server-mode role saw the full, company-wide write-zone
and read-zone allowlist (arbitrary host filesystem paths unrelated to
their own work).

Design (confirmed): rather than blanket-suppressing the tool (its
siblings grant_write_access/revoke_write_access ARE Tier A suppressed),
it's now split by capability:

  - Personal mode: unchanged, full list.
  - Server mode, owner/manager (full DB-management capability): full
    company-wide list, same as personal mode — they're the ones who
    manage the write-zone via the Admin tab.
  - Server mode, staff/field_crew: ONLY their own personal directory's
    read/write status, via _user_private_write_dir() (the same helper
    the write-scoping feature already uses) — not the company-wide list.
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


class TestPersonalModeUnchanged:

    def test_personal_mode_full_list(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_writable_allowlist_load", lambda: ["C:/proj-a", "C:/proj-b"])
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/proj-a", "C:/proj-b", "C:/readonly-docs"])
        result = mcp_mod.list_writable_directories()
        assert "C:/proj-a" in result
        assert "C:/proj-b" in result
        assert "C:/readonly-docs" in result


class TestServerModeOwnerManager:

    def test_owner_sees_full_list(self, mcp_mod, monkeypatch):
        user = _user("owner")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_writable_allowlist_load", lambda: ["C:/proj-a"])
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/proj-a", "C:/readonly-docs"])
        result = mcp_mod.list_writable_directories(ctx=_make_ctx(user))
        assert "C:/proj-a" in result
        assert "C:/readonly-docs" in result

    def test_manager_sees_full_list(self, mcp_mod, monkeypatch):
        user = _user("manager")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_writable_allowlist_load", lambda: ["C:/proj-a"])
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/proj-a", "C:/readonly-docs"])
        result = mcp_mod.list_writable_directories(ctx=_make_ctx(user))
        assert "C:/proj-a" in result
        assert "C:/readonly-docs" in result


class TestServerModeStaffFieldCrew:

    def test_staff_sees_only_own_dir_not_company_list(self, mcp_mod, monkeypatch, tmp_path):
        """Core fix: staff must NOT see other company paths — only their own
        personal directory's status."""
        user = _user("staff", uid="karen-s")
        private_dir = tmp_path / "karen-s-private"
        private_dir.mkdir()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("scoped", private_dir))
        monkeypatch.setattr(mcp_mod, "_writable_allowlist_load",
                            lambda: [str(private_dir), "C:/some/other/company/project"])

        result = mcp_mod.list_writable_directories(ctx=_make_ctx(user))
        assert str(private_dir) in result
        assert "C:/some/other/company/project" not in result

    def test_field_crew_writable_dir_shown_as_writable(self, mcp_mod, monkeypatch, tmp_path):
        user = _user("field_crew", uid="jake-r")
        private_dir = tmp_path / "jake-r-private"
        private_dir.mkdir()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("scoped", private_dir))
        monkeypatch.setattr(mcp_mod, "_writable_allowlist_load", lambda: [str(private_dir)])

        result = mcp_mod.list_writable_directories(ctx=_make_ctx(user))
        assert "✅" in result
        assert "read + write" in result.lower() or "read+write" in result.lower()

    def test_field_crew_read_only_dir_shown_correctly(self, mcp_mod, monkeypatch, tmp_path):
        """Personal dir exists (read-scoped) but is NOT in the writable
        allowlist yet — must show read-only status, not writable."""
        user = _user("field_crew", uid="jake-r")
        private_dir = tmp_path / "jake-r-private"
        private_dir.mkdir()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("scoped", private_dir))
        monkeypatch.setattr(mcp_mod, "_writable_allowlist_load", lambda: [])

        result = mcp_mod.list_writable_directories(ctx=_make_ctx(user))
        assert "📖" in result
        assert "read-only" in result.lower()

    def test_field_crew_no_personal_dir_gets_clear_message(self, mcp_mod, monkeypatch):
        user = _user("field_crew", uid="new-hire")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("blocked", None))

        result = mcp_mod.list_writable_directories(ctx=_make_ctx(user))
        assert "🚫" in result
        assert "personal directory" in result.lower()

    def test_staff_gate_matches_check_db_cap_full(self, mcp_mod, monkeypatch, tmp_path):
        """Locks in that the owner/manager-vs-staff split uses the same
        _check_db_cap('full') function as list_tracked_directories, rather
        than a separately-maintained role check."""
        user = _user("staff", uid="karen-s")
        private_dir = tmp_path / "karen-s-private"
        private_dir.mkdir()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("scoped", private_dir))
        monkeypatch.setattr(mcp_mod, "_writable_allowlist_load", lambda: [])

        expected_ok, _ = mcp_mod._check_db_cap(user, "full")
        assert expected_ok is False  # staff must NOT have full capability
        result = mcp_mod.list_writable_directories(ctx=_make_ctx(user))
        assert "Personal Directory Status" in result
