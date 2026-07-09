"""
tests/mcp/test_check_tools_status_dev_section.py
===================================================
Tests for check_tools_status()'s DEV TOOLS & FILE EDITING section —
previously ZERO test coverage existed for this tool anywhere in the suite,
and the section blanket-labeled everything "always available, no setup
required" with no awareness of mode or caller at all.

Background
----------
Cross-checked against _TIER_A_SUPPRESSED, most of what this section
claimed was available in server mode was actually completely blocked:
compile_check/syntax_check/check_python_import/lint_check, all four
run_script* tools, list_directory, copy_to_backup/list_backups/
restore_backup/cleanup_backups, and reset_write_counter are all Tier A
suppressed. The six write/edit tools (create_file, write_file,
str_replace_in_file, fuzzy_replace_in_file, line_replace_in_file,
create_directory) aren't suppressed, but ARE scoped to the caller's own
personal directory (or blocked entirely without one) per the earlier
personal-directory write-scoping feature — also not "always available."

Fixed by making the section mode-aware:
  - Personal mode: unchanged — everything shown as available, exactly as
    before this fix.
  - Server mode: Tier-A-suppressed tools shown as unavailable; the six
    write tools show a LIVE per-caller status via _user_private_write_dir
    (scoped to their own directory, or blocked with a clear reason);
    diff_files remains correctly shown as available (it was never
    suppressed and has its own internal scope check).
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


def _wire_common_mocks(mcp_mod, monkeypatch):
    """Mocks unrelated sections (SMS/email/spreadsheet) so only the dev-tools
    section content is under test, without needing real config files."""
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: "")
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: None)
    monkeypatch.setattr(mcp_mod, "_contacts_cache_load", lambda u: {"contacts": {}})
    import sms_backends
    fake_backend = MagicMock()
    fake_backend.validate_config.return_value = (False, "not configured")
    fake_backend.provider_name = "twilio"
    monkeypatch.setattr(sms_backends, "get_sms_backend", lambda cfg: fake_backend)
    monkeypatch.setattr(sms_backends, "get_whatsapp_backend", lambda cfg: fake_backend)
    monkeypatch.setattr(sms_backends, "load_sms_config", lambda: {})


class TestPersonalModeUnchanged:

    def test_all_dev_tools_shown_available(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        _wire_common_mocks(mcp_mod, monkeypatch)

        result = mcp_mod.check_tools_status(ctx=None)

        assert "always available — no setup required" not in result  # header simplified
        assert "✅ syntax_check" in result
        assert "✅ run_script" in result
        assert "✅ create_file" in result
        assert "✅ copy_to_backup" in result
        assert "✅ diff_files / reset_write_counter" in result
        assert "❌" not in result.split("DEV TOOLS")[1].split("SMS / WhatsApp")[0]


class TestServerModeTierASuppressed:

    def test_suppressed_tools_shown_unavailable(self, mcp_mod, monkeypatch):
        user = _user("owner")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("blocked", None))
        _wire_common_mocks(mcp_mod, monkeypatch)

        result = mcp_mod.check_tools_status(ctx=_make_ctx(user))
        dev_section = result.split("DEV TOOLS")[1].split("SMS / WhatsApp")[0]

        assert "❌ syntax_check" in dev_section
        assert "❌ run_script" in dev_section
        assert "❌ list_directory" in dev_section
        assert "❌ copy_to_backup" in dev_section
        assert "Not available in server mode" in dev_section

    def test_diff_files_still_available_in_server_mode(self, mcp_mod, monkeypatch):
        """diff_files was never Tier A suppressed — must still show as
        available, distinguishing it from everything else in this section."""
        user = _user("field_crew")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("blocked", None))
        _wire_common_mocks(mcp_mod, monkeypatch)

        result = mcp_mod.check_tools_status(ctx=_make_ctx(user))
        dev_section = result.split("DEV TOOLS")[1].split("SMS / WhatsApp")[0]

        assert "✅ diff_files" in dev_section


class TestServerModeWriteToolsLiveStatus:

    def test_user_with_private_dir_shows_scoped_status(self, mcp_mod, monkeypatch, tmp_path):
        user = _user("field_crew", uid="jake-r")
        private_dir = tmp_path / "jake-r-private"
        private_dir.mkdir()
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("scoped", private_dir))
        _wire_common_mocks(mcp_mod, monkeypatch)

        result = mcp_mod.check_tools_status(ctx=_make_ctx(user))
        dev_section = result.split("DEV TOOLS")[1].split("SMS / WhatsApp")[0]

        assert "✅ Scoped to your personal directory" in dev_section
        assert str(private_dir) in dev_section

    def test_user_without_private_dir_shows_blocked_status(self, mcp_mod, monkeypatch):
        user = _user("field_crew", uid="new-hire")
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("blocked", None))
        _wire_common_mocks(mcp_mod, monkeypatch)

        result = mcp_mod.check_tools_status(ctx=_make_ctx(user))
        dev_section = result.split("DEV TOOLS")[1].split("SMS / WhatsApp")[0]

        assert "⚠️" in dev_section
        assert "no personal directory configured" in dev_section.lower()

    def test_different_users_see_different_write_status(self, mcp_mod, monkeypatch, tmp_path):
        """Confirms this is genuinely a live, per-caller check — not a
        cached or role-wide value."""
        jake = _user("field_crew", uid="jake-r")
        karen = _user("staff", uid="karen-s")
        jake_dir = tmp_path / "jake-r-private"
        jake_dir.mkdir()
        _wire_common_mocks(mcp_mod, monkeypatch)

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: jake)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("scoped", jake_dir))
        jake_result = mcp_mod.check_tools_status(ctx=_make_ctx(jake))

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: karen)
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: ("blocked", None))
        karen_result = mcp_mod.check_tools_status(ctx=_make_ctx(karen))

        assert "Scoped to your personal directory" in jake_result
        assert "no personal directory configured" in karen_result.lower()
        assert jake_result != karen_result
