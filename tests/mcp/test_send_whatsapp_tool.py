"""
tests/mcp/test_send_whatsapp_tool.py
======================================
Tests for the send_whatsapp() MCP tool itself — previously ZERO coverage
existed at the tool level. The two pre-existing "send_whatsapp" tests in
test_sms_tools.py (SMS-TL-07, SMS-TL-08) both call get_whatsapp_backend(...)
directly, bypassing the tool wrapper entirely, so none of the following
had ever been tested:

  1. Role gating via _send_sms_cap (all roles allowed, personal mode
     always allowed).
  2. The personal-contacts fallback: when `to` doesn't look like a phone
     number (fewer than 10 digits), send_whatsapp() resolves it via
     _contact_lookup(to, user) — same mechanism send_email() uses, and
     with the SAME server-mode per-user isolation requirement (Jake's
     saved "Karen" must not resolve for a different employee's call).
  3. Server-mode attribution: sms_thread_log(sent_by=<user_id>, ...) must
     stamp the ACTUAL calling user, since check_sms_replies(),
     get_sms_thread(), and list_sms_contacts_with_replies() all depend on
     this field being correct for their own isolation to work.

Uses the real AIPROWLER_TEST_STATE_DIR sandbox (same mechanism
test_save_contact.py / test_send_email_contact_fallback.py use) so
save_contact()/_contact_lookup() are exercised for real, not mocked.
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


@pytest.fixture
def sandboxed_state(monkeypatch, tmp_path):
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    return tmp_path


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _user(role, uid, name):
    return {"id": uid, "name": name, "role": role, "status": "active"}


def _wire_backend_mocks(mcp_mod, monkeypatch, captured, send_ok=True):
    """Mocks the Twilio WhatsApp backend + inbox log so only send_whatsapp()'s
    own logic (gate, contact resolution, attribution) is exercised for real."""
    fake_backend = MagicMock()
    fake_backend.validate_config.return_value = (True, "")
    def _fake_send(to, message):
        captured["to"] = to
        captured["message"] = message
        return (send_ok, "✅ WhatsApp sent (SID: SMxxxx)" if send_ok else "❌ failed")
    fake_backend.send = _fake_send

    import sms_backends
    monkeypatch.setattr(sms_backends, "get_whatsapp_backend", lambda cfg: fake_backend)
    monkeypatch.setattr(sms_backends, "load_sms_config", lambda: {"provider": "twilio"})

    import sms_inbox
    def _fake_thread_log(**kwargs):
        captured["thread_log"] = kwargs
    monkeypatch.setattr(sms_inbox, "sms_thread_log", _fake_thread_log)


class TestRoleGate:

    @pytest.mark.parametrize("role", ["owner", "manager", "staff", "field_crew"])
    def test_all_roles_allowed_in_server_mode(self, mcp_mod, sandboxed_state, monkeypatch, role):
        user = _user(role, f"{role}-1", f"{role.title()} Person")
        captured = {}
        _wire_backend_mocks(mcp_mod, monkeypatch, captured)

        result = mcp_mod.send_whatsapp(to="3865550101", message="Job done",
                                       ctx=_make_ctx(user))

        assert "❌" not in result
        assert captured.get("to") == "3865550101"

    def test_personal_mode_allowed(self, mcp_mod, sandboxed_state, monkeypatch):
        captured = {}
        _wire_backend_mocks(mcp_mod, monkeypatch, captured)

        result = mcp_mod.send_whatsapp(to="3865550101", message="Job done", ctx=None)

        assert "❌" not in result
        assert captured.get("to") == "3865550101"


class TestContactLookupFallback:

    def test_phone_number_bypasses_contact_lookup(self, mcp_mod, sandboxed_state, monkeypatch):
        """A real-looking phone number (10+ digits) must be used as-is,
        never routed through _contact_lookup."""
        captured = {}
        _wire_backend_mocks(mcp_mod, monkeypatch, captured)

        mcp_mod.send_whatsapp(to="(386) 555-0101", message="Hi", ctx=None)

        assert captured.get("to") == "(386) 555-0101"

    def test_name_resolves_via_saved_contact_personal_mode(self, mcp_mod, sandboxed_state, monkeypatch):
        mcp_mod.save_contact(name="Karen", phone="3865550199", ctx=None)
        captured = {}
        _wire_backend_mocks(mcp_mod, monkeypatch, captured)

        result = mcp_mod.send_whatsapp(to="Karen", message="On our way", ctx=None)

        assert "❌" not in result
        assert captured.get("to") == "3865550199"

    def test_name_resolves_via_own_saved_contact_server_mode(self, mcp_mod, sandboxed_state, monkeypatch):
        jake = _user("field_crew", "jake-r", "Jake R")
        mcp_mod.save_contact(name="Karen", phone="3865550199", ctx=_make_ctx(jake))

        captured = {}
        _wire_backend_mocks(mcp_mod, monkeypatch, captured)

        result = mcp_mod.send_whatsapp(to="Karen", message="On our way", ctx=_make_ctx(jake))

        assert "❌" not in result
        assert captured.get("to") == "3865550199"


class TestContactLookupIsolation:
    """The actual leak this closes: two server-mode users' saved contacts
    with the same name must never cross-resolve."""

    def test_jakes_karen_is_not_vickis_karen(self, mcp_mod, sandboxed_state, monkeypatch):
        jake = _user("field_crew", "jake-r", "Jake R")
        vicki = _user("manager", "vicki-vavro", "Vicki Vavro")

        mcp_mod.save_contact(name="Karen", phone="3865550001", ctx=_make_ctx(jake))
        mcp_mod.save_contact(name="Karen", phone="3865559999", ctx=_make_ctx(vicki))

        captured = {}
        _wire_backend_mocks(mcp_mod, monkeypatch, captured)

        mcp_mod.send_whatsapp(to="Karen", message="x", ctx=_make_ctx(jake))
        assert captured.get("to") == "3865550001"

        captured.clear()
        mcp_mod.send_whatsapp(to="Karen", message="x", ctx=_make_ctx(vicki))
        assert captured.get("to") == "3865559999"


class TestServerModeAttribution:

    def test_thread_log_stamps_calling_user_id(self, mcp_mod, sandboxed_state, monkeypatch):
        """Core attribution fix dependency: check_sms_replies / get_sms_thread /
        list_sms_contacts_with_replies all rely on sms_thread_log's sent_by
        being the REAL calling user — verify send_whatsapp actually stamps it."""
        jake = _user("field_crew", "jake-r", "Jake R")
        captured = {}
        _wire_backend_mocks(mcp_mod, monkeypatch, captured)

        mcp_mod.send_whatsapp(to="3865550101", message="Job done", ctx=_make_ctx(jake))

        assert captured["thread_log"]["sent_by"] == "jake-r"
        assert captured["thread_log"]["provider"] == "whatsapp"

    def test_personal_mode_stamps_personal(self, mcp_mod, sandboxed_state, monkeypatch):
        captured = {}
        _wire_backend_mocks(mcp_mod, monkeypatch, captured)

        mcp_mod.send_whatsapp(to="3865550101", message="Job done", ctx=None)

        assert captured["thread_log"]["sent_by"] == "personal"

    def test_different_users_stamp_different_ids(self, mcp_mod, sandboxed_state, monkeypatch):
        jake = _user("field_crew", "jake-r", "Jake R")
        vicki = _user("manager", "vicki-vavro", "Vicki Vavro")
        captured = {}
        _wire_backend_mocks(mcp_mod, monkeypatch, captured)

        mcp_mod.send_whatsapp(to="3865550101", message="x", ctx=_make_ctx(jake))
        jake_sent_by = captured["thread_log"]["sent_by"]

        mcp_mod.send_whatsapp(to="3865550101", message="x", ctx=_make_ctx(vicki))
        vicki_sent_by = captured["thread_log"]["sent_by"]

        assert jake_sent_by == "jake-r"
        assert vicki_sent_by == "vicki-vavro"
        assert jake_sent_by != vicki_sent_by
