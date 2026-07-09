"""
tests/mcp/test_whatsapp_and_thread_scope.py
=============================================
Tests for two server-mode scoping fixes:

1. check_whatsapp_replies() — previously called check_sms_inbox() directly
   as a plain Python function call, which bypasses MCP-level Tier A
   suppression entirely (that suppression only blocks tool *registration*,
   not the underlying function itself). Since check_sms_inbox's own body
   has no per-user filtering, this gave every server-mode role — including
   field_crew — an unscoped, company-wide WhatsApp message dump, exactly
   the leak check_sms_inbox's suppression was supposed to prevent.

   Fixed by rewriting check_whatsapp_replies to use the same
   sms_inbox_read_for_user() ownership check check_sms_replies() already
   uses, filtered to provider='whatsapp', instead of delegating to
   check_sms_inbox() at all.

2. get_sms_thread() — never read ctx at all. Threads are keyed by phone
   number alone (not per employee), so if two employees have each texted
   the same contact, get_sms_thread(contact) would show the WHOLE combined
   history to whichever employee asks, including the other employee's
   messages. Fixed by only returning the thread if the caller is the one
   who last sent to that contact (same last_sent_by ownership field used
   throughout the SMS scoping work today).

Both fixes leave personal mode (ctx has no user) completely unrestricted,
unchanged from every prior version.
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


def _wa_msg(msg_id, from_, body, provider="whatsapp", read_by=None):
    return {
        "id": msg_id, "from": from_, "body": body, "provider": provider,
        "timestamp": "2026-07-08T10:00:00Z", "read_by": read_by or [],
        "contact_name": from_,
    }


class TestCheckWhatsappRepliesNoLongerBypassesSuppression:

    def test_no_longer_calls_check_sms_inbox_at_all(self, mcp_mod, monkeypatch):
        """The bypass is closed at the source: check_whatsapp_replies must
        not call check_sms_inbox internally anymore."""
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        called = {"check_sms_inbox": False}

        def _tripwire(*a, **k):
            called["check_sms_inbox"] = True
            return "should never be reached"

        monkeypatch.setattr(mcp_mod, "check_sms_inbox", _tripwire)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_inbox_read_for_user", lambda uid, since_hours: [])

        mcp_mod.check_whatsapp_replies(ctx=_make_ctx(user))
        assert called["check_sms_inbox"] is False

    def test_server_mode_scoped_to_own_threads(self, mcp_mod, monkeypatch):
        """Core fix: server-mode WhatsApp replies are scoped per-user,
        exactly like check_sms_replies."""
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        all_msgs = [
            _wa_msg("m1", "+13865551234", "Job confirmed", provider="whatsapp"),
        ]
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_inbox_read_for_user",
                            lambda uid, since_hours: all_msgs if uid == "jake-r" else [])

        result = mcp_mod.check_whatsapp_replies(ctx=_make_ctx(user))
        assert "Job confirmed" in result

    def test_server_mode_excludes_other_users_threads(self, mcp_mod, monkeypatch):
        """A user whose scoped threads contain nothing sees nothing —
        proving isolation, not just that the happy path works."""
        user = {"id": "new-guy", "name": "New Guy", "role": "field_crew"}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_inbox_read_for_user", lambda uid, since_hours: [])

        result = mcp_mod.check_whatsapp_replies(ctx=_make_ctx(user))
        assert "📭" in result

    def test_only_whatsapp_provider_included(self, mcp_mod, monkeypatch):
        """SMS messages in the same scoped set must be filtered out —
        this tool is WhatsApp-only."""
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        mixed = [
            _wa_msg("m1", "+13865551234", "WhatsApp message", provider="whatsapp"),
            _wa_msg("m2", "+13865555678", "Regular SMS", provider="twilio"),
        ]
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_inbox_read_for_user", lambda uid, since_hours: mixed)

        result = mcp_mod.check_whatsapp_replies(ctx=_make_ctx(user))
        assert "WhatsApp message" in result
        assert "Regular SMS" not in result

    def test_personal_mode_unrestricted(self, mcp_mod, monkeypatch):
        """Personal mode: identical to behavior before this fix — full
        access, no per-user scoping applied."""
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        all_msgs = [_wa_msg("m1", "+13865551234", "Owner's message", provider="whatsapp")]
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_inbox_read",
                            lambda **kw: all_msgs if kw.get("provider") == "whatsapp" else [])

        result = mcp_mod.check_whatsapp_replies(ctx=None)
        assert "Owner's message" in result


class TestGetSmsThreadScoping:

    def test_server_mode_own_thread_visible(self, mcp_mod, monkeypatch):
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        conv = {
            "thread_id": "3865551234", "contact_name": "Crabby's Daytona",
            "last_sent_by": "jake-r", "provider": "twilio",
            "messages": [{"direction": "outbound", "body": "On our way", "timestamp": ""}],
        }
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_thread_get_with_replies", lambda c, since_hours: conv)

        result = mcp_mod.get_sms_thread(contact="Crabby's", ctx=_make_ctx(user))
        assert "Crabby's Daytona" in result
        assert "On our way" in result

    def test_server_mode_other_users_thread_hidden(self, mcp_mod, monkeypatch):
        """The actual leak this closes: a thread belonging to a DIFFERENT
        employee must not be visible just by naming the contact."""
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        conv = {
            "thread_id": "3865559999", "contact_name": "Sunshine Realty",
            "last_sent_by": "vicki-vavro", "provider": "twilio",
            "messages": [{"direction": "outbound", "body": "Confidential pricing note", "timestamp": ""}],
        }
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_thread_get_with_replies", lambda c, since_hours: conv)

        result = mcp_mod.get_sms_thread(contact="Sunshine Realty", ctx=_make_ctx(user))
        assert "Confidential pricing note" not in result
        assert "📭" in result

    def test_personal_mode_unrestricted(self, mcp_mod, monkeypatch):
        """Personal mode: unchanged — a single-user install has no
        ownership ambiguity to resolve."""
        conv = {
            "thread_id": "3865551234", "contact_name": "Crabby's Daytona",
            "last_sent_by": "david-vavro", "provider": "twilio",
            "messages": [{"direction": "outbound", "body": "On our way", "timestamp": ""}],
        }
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_thread_get_with_replies", lambda c, since_hours: conv)

        result = mcp_mod.get_sms_thread(contact="Crabby's", ctx=None)
        assert "On our way" in result

    def test_no_thread_at_all_unaffected(self, mcp_mod, monkeypatch):
        """A contact with no thread at all still gets the normal
        'no thread found, start a conversation' message, not the
        ownership-denial message — these are different situations."""
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_thread_get_with_replies", lambda c, since_hours: None)

        result = mcp_mod.get_sms_thread(contact="Nobody", ctx=_make_ctx(user))
        assert "Start a conversation" in result
