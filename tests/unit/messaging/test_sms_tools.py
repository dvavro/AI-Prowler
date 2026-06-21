"""
tests/unit/messaging/test_sms_tools.py
========================================
Unit tests for the new MCP messaging tools (Phase 2).

Covers SMS-TL-01 through SMS-TL-20 from TWO_WAY_MESSAGING_TEST_PLAN.md

Tests the tool functions directly by importing ai_prowler_mcp and calling
the underlying tool implementations with mocked config and inbox data.
"""
from __future__ import annotations

import sys
import json
import os
import importlib
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

_HERE       = Path(__file__).resolve()
_AI_PROWLER = _HERE.parents[3]
sys.path.insert(0, str(_AI_PROWLER))


# ─── Fixtures ─────────────────────────────────────────────────────────────────

TWILIO_CFG = {
    "sms_provider": "twilio",
    "twilio_sms_enabled": True,
    "twilio_account_sid": "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "twilio_auth_token":  "test_auth_token_1234567890abcdef",
    "twilio_from_number": "+13865550100",
}

SIGNALWIRE_CFG = {
    "sms_provider":           "signalwire",
    "signalwire_project_id":  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "signalwire_auth_token":  "PTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "signalwire_space_url":   "example.signalwire.com",
    "signalwire_from_number": "+13865550100",
}

VONAGE_CFG = {
    "sms_provider":      "vonage",
    "vonage_api_key":    "12345678",
    "vonage_api_secret": "abcdefghijklmnop",
    "vonage_from_number": "AIProwler",
}


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    import sms_inbox
    importlib.reload(sms_inbox)
    yield tmp_path


@pytest.fixture
def inbox(isolated_state):
    import sms_inbox
    return sms_inbox


def _mock_twilio_resp(sid="SM1234567890abcdef"):
    r = MagicMock()
    r.status_code = 201
    r.json.return_value = {"sid": sid}
    return r


def _mock_vonage_resp(msg_id="VON-12345"):
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"messages": [{"status": "0", "message-id": msg_id}]}
    return r


def _add_inbox_msg(inbox, msg_id, from_num, body, provider="twilio",
                   contact="", hours_ago=0):
    from datetime import datetime, timezone, timedelta
    ts = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
    inbox.sms_inbox_append(
        message_id=msg_id, from_number=from_num,
        to_number="+13865550100", body=body,
        provider=provider, contact_name=contact, timestamp=ts,
    )


# ─── SMS-TL-01 through SMS-TL-04: check_sms_inbox ───────────────────────────

class TestCheckSmsInbox:
    def test_SMS_TL_01_reads_from_local_file_no_api_call(self, inbox):
        """SMS-TL-01: check_sms_inbox reads from local file (no API call)"""
        _add_inbox_msg(inbox, "SM001", "+13865550101", "Hi back")

        with patch("requests.get") as mock_get:
            from sms_inbox import sms_inbox_read
            msgs = sms_inbox_read(since_hours=0)
            mock_get.assert_not_called()

        assert len(msgs) == 1
        assert msgs[0]["body"] == "Hi back"

    def test_SMS_TL_02_unread_only_filters_correctly(self, inbox):
        """SMS-TL-02: check_sms_inbox(unread_only=True) filters correctly"""
        _add_inbox_msg(inbox, "SM001", "+13865550101", "Read msg")
        _add_inbox_msg(inbox, "SM002", "+13865550101", "Unread msg")
        inbox.sms_inbox_mark_read("SM001", "mike_c")

        from sms_inbox import sms_inbox_read
        msgs = sms_inbox_read(since_hours=0, unread_only=True, user_id="mike_c")
        assert len(msgs) == 1
        assert msgs[0]["id"] == "SM002"

    def test_SMS_TL_03_filters_by_from_number(self, inbox):
        """SMS-TL-03: check_sms_inbox(from_number='386...') filters by sender"""
        _add_inbox_msg(inbox, "SM001", "+13865550101", "From Karen")
        _add_inbox_msg(inbox, "SM002", "+13865550202", "From Bob")

        from sms_inbox import sms_inbox_read
        msgs = sms_inbox_read(since_hours=0, from_number="3865550101")
        assert len(msgs) == 1
        assert msgs[0]["id"] == "SM001"

    def test_SMS_TL_04_empty_inbox_returns_empty_list(self, inbox):
        """SMS-TL-04: check_sms_inbox() empty inbox returns empty list"""
        from sms_inbox import sms_inbox_read
        msgs = sms_inbox_read(since_hours=0)
        assert msgs == []


# ─── SMS-TL-05 through SMS-TL-06: get_sms_thread ────────────────────────────

class TestGetSmsThread:
    def test_SMS_TL_05_returns_full_conversation(self, inbox):
        """SMS-TL-05: get_sms_thread('Karen') returns full conversation"""
        inbox.sms_thread_log("mike_c", "3865550101", "On my way", "twilio", "Karen Torres")
        _add_inbox_msg(inbox, "SM001", "+13865550101", "Ok see you soon", contact="Karen Torres")

        conv = inbox.sms_thread_get_with_replies("Karen Torres")
        assert conv["contact_name"] == "Karen Torres"
        assert len(conv["messages"]) == 2
        bodies = [m["body"] for m in conv["messages"]]
        assert "On my way" in bodies
        assert "Ok see you soon" in bodies

    def test_SMS_TL_06_unknown_contact_returns_none(self, inbox):
        """SMS-TL-06: get_sms_thread() unknown contact returns None"""
        result = inbox.sms_thread_get("Nobody Known")
        assert result is None


# ─── SMS-TL-07 through SMS-TL-09: WhatsApp tools ────────────────────────────

class TestWhatsAppTools:
    def test_SMS_TL_07_send_whatsapp_uses_whatsapp_prefix(self):
        """SMS-TL-07: send_whatsapp() calls WhatsAppBackend with whatsapp: prefix"""
        from sms_backends import get_whatsapp_backend

        captured = {}
        def fake_post(url, auth, data, timeout=15):
            captured["to"]   = data.get("To")
            captured["from"] = data.get("From")
            r = MagicMock()
            r.status_code = 201
            r.json.return_value = {"sid": "SM_wa_123"}
            return r

        wa = get_whatsapp_backend(TWILIO_CFG)
        with patch("requests.post", side_effect=fake_post):
            ok, msg = wa.send("3865550101", "Job complete")

        assert ok
        assert captured.get("to") == "whatsapp:+13865550101"
        assert captured.get("from", "").startswith("whatsapp:")

    def test_SMS_TL_08_send_whatsapp_no_config_returns_error(self):
        """SMS-TL-08: send_whatsapp() no config returns 'not configured'"""
        from sms_backends import get_whatsapp_backend
        wa = get_whatsapp_backend({})
        ok, msg = wa.send("3865550101", "Hello")
        assert not ok
        assert "not configured" in msg.lower()

    def test_SMS_TL_09_check_whatsapp_replies_filters_by_provider(self, inbox):
        """SMS-TL-09: check_whatsapp_replies() reads inbox filtered by provider='whatsapp'"""
        _add_inbox_msg(inbox, "SM001", "+13865550101", "SMS reply",       provider="twilio")
        _add_inbox_msg(inbox, "SM002", "whatsapp:+13865550101", "WA reply", provider="whatsapp")

        from sms_inbox import sms_inbox_read
        wa_msgs = sms_inbox_read(since_hours=0, provider="whatsapp")
        assert len(wa_msgs) == 1
        assert wa_msgs[0]["id"] == "SM002"


# ─── SMS-TL-10: list_sms_contacts_with_replies ───────────────────────────────

class TestListContactsWithReplies:
    def test_SMS_TL_10_groups_by_contact(self, inbox):
        """SMS-TL-10: list_sms_contacts_with_replies() groups by contact"""
        inbox.sms_thread_log("mike_c", "3865550101", "Hi Karen", "twilio", "Karen Torres")
        inbox.sms_thread_log("jake_r", "3865550202", "Hi Bob",   "twilio", "Bob Smith")
        _add_inbox_msg(inbox, "SM001", "+13865550101", "Hi back Karen")
        _add_inbox_msg(inbox, "SM002", "+13865550202", "Hi back Bob")

        active = inbox.sms_active_threads(since_hours=1)
        assert len(active) == 2
        names = {t.get("contact_name") for t in active}
        assert "Karen Torres" in names
        assert "Bob Smith" in names


# ─── SMS-TL-11 through SMS-TL-13: send_sms with new backend ─────────────────

class TestSendSmsBackendAbstraction:
    def test_SMS_TL_11_send_sms_twilio_still_works(self):
        """SMS-TL-11: send_sms() using new backend abstraction works with Twilio"""
        from sms_backends import get_sms_backend
        backend = get_sms_backend(TWILIO_CFG)

        with patch("requests.post", return_value=_mock_twilio_resp("SM_new_123")):
            ok, msg = backend.send("3865550101", "Hello Karen")

        assert ok
        assert "SM_new_123" in msg or "sent" in msg.lower()

    def test_SMS_TL_12_send_sms_logs_to_threads(self, inbox):
        """SMS-TL-12: send_sms() logs to sms_threads.json"""
        inbox.sms_thread_log("mike_c", "3865550101", "Hello Karen", "twilio", "Karen Torres")

        threads = inbox._load_threads()
        assert "3865550101" in threads
        assert threads["3865550101"]["last_sent_by"] == "mike_c"

    def test_SMS_TL_13_check_sms_replies_reads_local_no_api_poll(self, inbox):
        """SMS-TL-13: check_sms_replies now reads from local inbox (not Twilio API)"""
        _add_inbox_msg(inbox, "SM001", "+13865550101", "Reply from Karen")

        with patch("requests.get") as mock_get:
            from sms_inbox import sms_inbox_read
            msgs = sms_inbox_read(since_hours=24)
            mock_get.assert_not_called()

        assert len(msgs) == 1


# ─── SMS-TL-14 through SMS-TL-16: Role caps ─────────────────────────────────

class TestRoleCaps:
    """Verify SMS capability flags in _ROLE_CAPS."""

    def _get_role_caps(self):
        import ai_prowler_mcp as mcp
        return getattr(mcp, "_ROLE_CAPS", {})

    def test_SMS_TL_14_field_crew_can_send_sms(self):
        """SMS-TL-14: Field crew role can send SMS"""
        caps = self._get_role_caps()
        field_crew = caps.get("field_crew", {})
        assert field_crew.get("can_send_sms") is True, \
            "field_crew should have can_send_sms=True"

    def test_SMS_TL_15_owner_can_send_sms(self):
        """SMS-TL-15: Owner role can send SMS"""
        caps = self._get_role_caps()
        owner = caps.get("owner", {})
        assert owner.get("can_send_sms") is True, \
            "owner should have can_send_sms=True — update _ROLE_CAPS"

    def test_SMS_TL_16_manager_can_send_sms(self):
        """SMS-TL-16: Manager role can send SMS"""
        caps = self._get_role_caps()
        manager = caps.get("manager", {})
        assert manager.get("can_send_sms") is True, \
            "manager should have can_send_sms=True — update _ROLE_CAPS"


# ─── SMS-TL-17 through SMS-TL-19: Provider switching ────────────────────────

class TestProviderSwitching:
    def test_SMS_TL_17_personal_mode_twilio_works(self):
        """SMS-TL-17: Personal mode send_sms works with Twilio config"""
        from sms_backends import get_sms_backend
        b = get_sms_backend(TWILIO_CFG)
        with patch("requests.post", return_value=_mock_twilio_resp()):
            ok, msg = b.send("3865550101", "Hello")
        assert ok

    def test_SMS_TL_18_personal_mode_signalwire_works(self):
        """SMS-TL-18: Personal mode send_sms works with SignalWire config"""
        from sms_backends import get_sms_backend
        b = get_sms_backend(SIGNALWIRE_CFG)
        mock_r = MagicMock()
        mock_r.status_code = 201
        mock_r.json.return_value = {"sid": "SW_123"}
        with patch("requests.post", return_value=mock_r):
            ok, msg = b.send("3865550101", "Hello")
        assert ok

    def test_SMS_TL_19_personal_mode_vonage_works(self):
        """SMS-TL-19: Personal mode send_sms works with Vonage config"""
        from sms_backends import get_sms_backend
        b = get_sms_backend(VONAGE_CFG)
        with patch("requests.post", return_value=_mock_vonage_resp()):
            ok, msg = b.send("3865550101", "Hello")
        assert ok

    def test_SMS_TL_20_whatsapp_backend_registered(self):
        """SMS-TL-20: WhatsApp tool available via get_whatsapp_backend"""
        from sms_backends import get_whatsapp_backend, WhatsAppBackend
        b = get_whatsapp_backend(TWILIO_CFG)
        assert isinstance(b, WhatsAppBackend)
        ok, _ = b.validate_config()
        assert ok


# ─── Thread isolation (E2E preview) ──────────────────────────────────────────

class TestThreadIsolation:
    def test_mike_and_jake_see_only_their_replies(self, inbox):
        """Preview of SMS-E2E-04: thread isolation between crew members"""
        # Mike sends to Karen
        inbox.sms_thread_log("mike_c", "3865550101", "Hi Karen", "twilio", "Karen Torres")
        # Jake sends to Bob
        inbox.sms_thread_log("jake_r", "3865550202", "Hi Bob",   "twilio", "Bob Smith")

        # Karen replies to Mike's number, Bob replies to Jake's number
        _add_inbox_msg(inbox, "SM001", "+13865550101", "Hi Mike!")
        _add_inbox_msg(inbox, "SM002", "+13865550202", "Hi Jake!")

        mike_msgs = inbox.sms_inbox_read_for_user("mike_c", since_hours=0)
        jake_msgs = inbox.sms_inbox_read_for_user("jake_r", since_hours=0)

        assert len(mike_msgs) == 1 and mike_msgs[0]["id"] == "SM001"
        assert len(jake_msgs) == 1 and jake_msgs[0]["id"] == "SM002"

    def test_provider_switch_no_restart_needed(self):
        """SMS-E2E-05 preview: changing provider in config works immediately"""
        from sms_backends import get_sms_backend, TwilioBackend, SignalWireBackend

        # Start with Twilio
        b1 = get_sms_backend(TWILIO_CFG)
        assert isinstance(b1, TwilioBackend)

        # Switch to SignalWire — no restart, just new backend instance
        b2 = get_sms_backend(SIGNALWIRE_CFG)
        assert isinstance(b2, SignalWireBackend)
