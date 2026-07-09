"""
tests/mcp/test_sms_contacts_scope.py
======================================
Tests for list_sms_contacts_with_replies()'s server-mode scoping fix.

Background
----------
list_sms_contacts_with_replies() accepted a ctx parameter but never
actually read a user from it — it called sms_active_threads(since_hours),
which has no user parameter at all and returns EVERY active SMS thread
company-wide. In server mode, any role (including field_crew) saw every
employee's conversation list — contact names, unread counts, everything.

Fixed by filtering the returned threads down to ones where
thread['last_sent_by'] == the calling user's id — the exact same
ownership check sms_inbox_read_for_user() already uses for
check_sms_replies (see test_sms_reply_isolation-equivalent coverage).

A brand-new user with no thread history at all falls back to seeing
everything (matching sms_inbox_read_for_user()'s identical fallback) —
this is intentional, not a regression, and locked in by a dedicated test.

Personal mode (ctx has no user) is completely unaffected.
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


def _thread(contact_name, last_sent_by, unread=0, total=1):
    return {
        "thread_id": contact_name.lower().replace(" ", "-"),
        "contact_name": contact_name,
        "last_sent_by": last_sent_by,
        "provider": "twilio",
        "unread_replies": unread,
        "total_replies": total,
    }


class TestServerModeScoping:

    def test_scoped_to_own_threads_only(self, mcp_mod, monkeypatch):
        """Core fix: a server-mode user must only see threads THEY sent."""
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        all_threads = [
            _thread("Crabby's Daytona", last_sent_by="jake-r"),
            _thread("Sunshine Realty", last_sent_by="vicki-vavro"),
            _thread("Blue Wave Cafe", last_sent_by="karen-s"),
        ]
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_active_threads", lambda since_hours: all_threads)

        result = mcp_mod.list_sms_contacts_with_replies(ctx=_make_ctx(user))
        assert "Crabby's Daytona" in result
        assert "Sunshine Realty" not in result
        assert "Blue Wave Cafe" not in result

    def test_new_user_no_history_falls_back_to_all(self, mcp_mod, monkeypatch):
        """A brand-new user with zero thread history sees everything —
        matching sms_inbox_read_for_user()'s identical fallback, not a bug."""
        user = {"id": "new-hire", "name": "New Hire", "role": "field_crew"}
        all_threads = [
            _thread("Crabby's Daytona", last_sent_by="jake-r"),
            _thread("Sunshine Realty", last_sent_by="vicki-vavro"),
        ]
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_active_threads", lambda since_hours: all_threads)

        result = mcp_mod.list_sms_contacts_with_replies(ctx=_make_ctx(user))
        assert "Crabby's Daytona" in result
        assert "Sunshine Realty" in result

    def test_personal_mode_sees_all_unchanged(self, mcp_mod, monkeypatch):
        """Personal mode: no user on ctx, so no filtering applies at all —
        identical to behavior before this fix existed."""
        all_threads = [
            _thread("Crabby's Daytona", last_sent_by="david-vavro"),
            _thread("Sunshine Realty", last_sent_by="david-vavro"),
        ]
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_active_threads", lambda since_hours: all_threads)

        result = mcp_mod.list_sms_contacts_with_replies(ctx=None)
        assert "Crabby's Daytona" in result
        assert "Sunshine Realty" in result

    def test_two_users_see_different_lists(self, mcp_mod, monkeypatch):
        """The actual leak this closes: two different server-mode users
        must see DIFFERENT conversation lists."""
        jake = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        vicki = {"id": "vicki-vavro", "name": "Vicki Vavro", "role": "manager"}
        all_threads = [
            _thread("Crabby's Daytona", last_sent_by="jake-r"),
            _thread("Sunshine Realty", last_sent_by="vicki-vavro"),
        ]
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_active_threads", lambda since_hours: all_threads)

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: jake)
        result_jake = mcp_mod.list_sms_contacts_with_replies(ctx=_make_ctx(jake))

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: vicki)
        result_vicki = mcp_mod.list_sms_contacts_with_replies(ctx=_make_ctx(vicki))

        assert "Crabby's Daytona" in result_jake
        assert "Sunshine Realty" not in result_jake
        assert "Sunshine Realty" in result_vicki
        assert "Crabby's Daytona" not in result_vicki
        assert result_jake != result_vicki

    def test_empty_after_scoping_shows_friendly_message(self, mcp_mod, monkeypatch):
        """A user with genuinely zero activity (not 'new user with no
        history' — there IS activity, just none of theirs, is impossible
        given the fallback; this covers the true globally-empty case)."""
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        import sms_inbox
        monkeypatch.setattr(sms_inbox, "sms_active_threads", lambda since_hours: [])

        result = mcp_mod.list_sms_contacts_with_replies(ctx=_make_ctx(user))
        assert "📭" in result
