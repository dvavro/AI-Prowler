"""
tests/mcp/test_personal_write_scope.py
========================================
Tests for the server-mode personal-directory write scoping feature.

Background
----------
create_file, write_file, str_replace_in_file, fuzzy_replace_in_file,
line_replace_in_file, and create_directory were previously either fully
Tier-A-suppressed in server mode (the first four) or accidentally
un-suppressed with no scoping at all (the last two — a real gap found and
fixed in this same change).

All six are now registered in BOTH personal and server mode, but
in server mode every write is gated per-call via _check_personal_write_scope():

  - Personal mode (ctx has no user): fully unrestricted — unchanged from
    all prior versions.
  - Server mode, user has a configured personal (private) directory:
    writes must resolve to a path inside that directory. Anything else —
    shared scopes, another user's private dir, the job tracker, etc. — is
    denied.
  - Server mode, user has NO personal directory configured
    (private_collection_enabled=False, or the folder was never set up):
    ALL writes are denied. Read tools remain unaffected.

Sections:
  A. _user_private_write_dir()      — status resolution (personal/scoped/blocked)
  B. _check_personal_write_scope()  — the gate itself
  C. Tier A membership               — the 6 tools must NOT be blanket-suppressed
  D. Integration — create_file() end-to-end through the real tool function
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    """Minimal ctx stub matching _current_user()'s expected shape."""
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _server_user(uid="jake-r", private_enabled=True):
    return {
        "id": uid, "name": "Jake R", "role": "field_crew",
        "status": "active", "scopes": [],
        "private_collection_enabled": private_enabled,
        "can_manage_users": False,
    }


# ═══════════════════════════════════════════════════════════════════════════
# SECTION A — _user_private_write_dir()
# ═══════════════════════════════════════════════════════════════════════════

class TestUserPrivateWriteDir:

    def test_A01_personal_mode_ctx_none(self, mcp_mod):
        """No ctx at all (personal mode) -> ('personal', None)."""
        status, path = mcp_mod._user_private_write_dir(None)
        assert status == "personal"
        assert path is None

    def test_A02_server_mode_private_disabled(self, mcp_mod, monkeypatch):
        """User exists but private_collection_enabled=False -> blocked."""
        user = _server_user(private_enabled=False)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        status, path = mcp_mod._user_private_write_dir(_make_ctx(user))
        assert status == "blocked"
        assert path is None

    def test_A03_server_mode_private_enabled_no_rule(self, mcp_mod, monkeypatch, tmp_path):
        """private_collection_enabled=True but no matching collection_map rule
        -> fail-closed to blocked (not silently unrestricted)."""
        user = _server_user(private_enabled=True)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_company_collection_map",
                            lambda *a, **k: {"rules": [], "default_collection": "shared"})
        status, path = mcp_mod._user_private_write_dir(_make_ctx(user))
        assert status == "blocked"
        assert path is None

    def test_A04_server_mode_rule_points_to_missing_dir(self, mcp_mod, monkeypatch, tmp_path):
        """Rule exists but the folder doesn't actually exist on disk ->
        fail-closed to blocked."""
        user = _server_user(private_enabled=True)
        ghost = tmp_path / "does-not-exist" / "jake-r-private"
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_company_collection_map", lambda *a, **k: {
            "rules": [{"prefix": str(ghost), "collection": "user:jake-r"}],
            "default_collection": "shared",
        })
        status, path = mcp_mod._user_private_write_dir(_make_ctx(user))
        assert status == "blocked"

    def test_A05_server_mode_valid_private_dir(self, mcp_mod, monkeypatch, tmp_path):
        """Rule exists, folder exists on disk -> scoped to that path."""
        user = _server_user(private_enabled=True)
        real_dir = tmp_path / "jake-r-private"
        real_dir.mkdir()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_company_collection_map", lambda *a, **k: {
            "rules": [{"prefix": str(real_dir), "collection": "user:jake-r"}],
            "default_collection": "shared",
        })
        status, path = mcp_mod._user_private_write_dir(_make_ctx(user))
        assert status == "scoped"
        assert Path(path).resolve() == real_dir.resolve()

    def test_A06_wrong_users_rule_is_ignored(self, mcp_mod, monkeypatch, tmp_path):
        """A collection_map rule for a DIFFERENT user's private dir must not
        match — only 'user:<this user's id>' counts."""
        user = _server_user(uid="jake-r", private_enabled=True)
        someone_elses_dir = tmp_path / "vicki-vavro-private"
        someone_elses_dir.mkdir()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_company_collection_map", lambda *a, **k: {
            "rules": [{"prefix": str(someone_elses_dir), "collection": "user:vicki-vavro"}],
            "default_collection": "shared",
        })
        status, path = mcp_mod._user_private_write_dir(_make_ctx(user))
        assert status == "blocked"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION B — _check_personal_write_scope()
# ═══════════════════════════════════════════════════════════════════════════

class TestCheckPersonalWriteScope:

    def test_B01_personal_mode_always_allowed(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("personal", None))
        assert mcp_mod._check_personal_write_scope(None, "C:/anything/at/all.txt") is None

    def test_B02_blocked_status_denies_with_clear_reason(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("blocked", None))
        denial = mcp_mod._check_personal_write_scope(object(), "C:/some/file.txt")
        assert denial is not None
        assert "personal directory" in denial.lower()

    def test_B03_scoped_inside_own_dir_allowed(self, mcp_mod, monkeypatch, tmp_path):
        private_dir = tmp_path / "jake-r-private"
        private_dir.mkdir()
        target = private_dir / "notes.txt"
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("scoped", private_dir))
        assert mcp_mod._check_personal_write_scope(object(), str(target)) is None

    def test_B04_scoped_outside_own_dir_denied(self, mcp_mod, monkeypatch, tmp_path):
        """The exact 'Vicki bug' shape, but for writes: a field_crew member's
        own private dir must not authorize writes to a shared or another
        user's directory."""
        private_dir = tmp_path / "jake-r-private"
        private_dir.mkdir()
        other_dir = tmp_path / "shared-docs"
        other_dir.mkdir()
        target = other_dir / "price_list.xlsx"
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("scoped", private_dir))
        denial = mcp_mod._check_personal_write_scope(object(), str(target))
        assert denial is not None
        assert "personal directory" in denial.lower()

    def test_B05_scoped_sibling_dir_with_similar_name_denied(self, mcp_mod, monkeypatch, tmp_path):
        """Prefix-collision guard: 'jake-r-private' must not authorize writes
        into 'jake-r-private-archive' or similar look-alike siblings."""
        private_dir = tmp_path / "jake-r-private"
        private_dir.mkdir()
        sneaky = tmp_path / "jake-r-private-archive"
        sneaky.mkdir()
        target = sneaky / "leak.txt"
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("scoped", private_dir))
        denial = mcp_mod._check_personal_write_scope(object(), str(target))
        assert denial is not None

    def test_B06_scoped_exact_dir_root_allowed(self, mcp_mod, monkeypatch, tmp_path):
        """Writing to the private dir's root path itself (not a file inside
        it) still counts as 'inside' — edge case for create_directory."""
        private_dir = tmp_path / "jake-r-private"
        private_dir.mkdir()
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("scoped", private_dir))
        assert mcp_mod._check_personal_write_scope(object(), str(private_dir)) is None


# ═══════════════════════════════════════════════════════════════════════════
# SECTION C — Tier A membership: these 6 tools must NOT be blanket-suppressed
# ═══════════════════════════════════════════════════════════════════════════

class TestNotBlanketSuppressed:
    """
    These tools are gated per-call via _check_personal_write_scope(), not
    via blanket Tier A suppression. If any of them end up back in
    _TIER_A_SUPPRESSED, server-mode users would lose write access to their
    own personal directory entirely — this locks in the intended design.
    """

    @pytest.mark.parametrize("tool_name", [
        "create_file", "write_file", "str_replace_in_file",
        "fuzzy_replace_in_file", "line_replace_in_file", "create_directory",
    ])
    def test_C01_write_tools_not_tier_a_suppressed(self, mcp_mod, tool_name):
        assert tool_name not in mcp_mod._TIER_A_SUPPRESSED, (
            f"{tool_name} must NOT be blanket Tier A suppressed — it's gated "
            f"per-call via _check_personal_write_scope() instead, so "
            f"server-mode users can still write inside their own personal "
            f"directory."
        )

    def test_C02_backup_and_approval_tools_still_suppressed(self, mcp_mod):
        """The tools that manage the write allowlist/backups/circuit-breaker
        itself remain operator/dev-only — scoping a personal-directory write
        doesn't extend to managing the write infrastructure."""
        for tool_name in (
            "copy_to_backup", "restore_backup", "list_backups",
            "reset_write_counter", "grant_write_access", "revoke_write_access",
            "cleanup_backups",
        ):
            assert tool_name in mcp_mod._TIER_A_SUPPRESSED, (
                f"{tool_name} should remain Tier A suppressed"
            )


# ═══════════════════════════════════════════════════════════════════════════
# SECTION D — Integration: create_file() end-to-end through the real tool
# ═══════════════════════════════════════════════════════════════════════════

class TestCreateFileIntegration:
    """
    Exercises the real create_file() tool function with the allowlist layer
    bypassed (that layer has its own dedicated tests elsewhere) so only the
    NEW personal-write-scope logic is under test here.
    """

    def _bypass_allowlist(self, monkeypatch, mcp_mod):
        """Make _resolve_writable_path a passthrough so only the scope
        gate (not the read/write allowlist) determines the outcome."""
        monkeypatch.setattr(
            mcp_mod, "_resolve_writable_path",
            lambda filepath, **kw: (filepath, None)
        )

    def test_D01_personal_mode_unaffected(self, mcp_mod, monkeypatch, tmp_path):
        """ctx=None (personal mode): create_file works exactly as before —
        no scope restriction at all."""
        self._bypass_allowlist(monkeypatch, mcp_mod)
        target = tmp_path / "notes.txt"
        result = mcp_mod.create_file(filepath=str(target), content="hello", ctx=None)
        assert "✅" in result or "success" in result.lower() or target.exists()
        assert target.exists()
        assert target.read_text() == "hello"

    def test_D02_server_mode_write_inside_own_dir_succeeds(self, mcp_mod, monkeypatch, tmp_path):
        self._bypass_allowlist(monkeypatch, mcp_mod)
        private_dir = tmp_path / "jake-r-private"
        private_dir.mkdir()
        user = _server_user(private_enabled=True)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_company_collection_map", lambda *a, **k: {
            "rules": [{"prefix": str(private_dir), "collection": "user:jake-r"}],
        })
        target = private_dir / "field_notes.txt"
        result = mcp_mod.create_file(filepath=str(target), content="job 1042 done",
                                     ctx=_make_ctx(user))
        assert target.exists()
        assert target.read_text() == "job 1042 done"

    def test_D03_server_mode_write_outside_own_dir_denied(self, mcp_mod, monkeypatch, tmp_path):
        self._bypass_allowlist(monkeypatch, mcp_mod)
        private_dir = tmp_path / "jake-r-private"
        private_dir.mkdir()
        shared_dir = tmp_path / "shared"
        shared_dir.mkdir()
        user = _server_user(private_enabled=True)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_company_collection_map", lambda *a, **k: {
            "rules": [{"prefix": str(private_dir), "collection": "user:jake-r"}],
        })
        target = shared_dir / "sneaky.txt"
        result = mcp_mod.create_file(filepath=str(target), content="should not land",
                                     ctx=_make_ctx(user))
        assert "🚫" in result
        assert not target.exists()

    def test_D04_server_mode_no_private_dir_denied_everywhere(self, mcp_mod, monkeypatch, tmp_path):
        """User with private_collection_enabled=False cannot write ANYWHERE,
        including a path that would otherwise be perfectly valid."""
        self._bypass_allowlist(monkeypatch, mcp_mod)
        user = _server_user(private_enabled=False)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        target = tmp_path / "anything.txt"
        result = mcp_mod.create_file(filepath=str(target), content="nope",
                                     ctx=_make_ctx(user))
        assert "🚫" in result
        assert "personal directory" in result.lower()
        assert not target.exists()
