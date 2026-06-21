"""
tests/unit/messaging/test_sms_inbox.py
========================================
Unit tests for sms_inbox.py — inbox storage, thread model, and signature validation.

Covers SMS-IN-01 through SMS-IN-12 and SMS-WH-02/03/07/08 (signature tests)
from TWO_WAY_MESSAGING_TEST_PLAN.md
"""
from __future__ import annotations

import sys
import os
import json
import time
import threading
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta

import pytest

_HERE       = Path(__file__).resolve()
_AI_PROWLER = _HERE.parents[3]
sys.path.insert(0, str(_AI_PROWLER))


# ─── Fixture: isolated temp state dir ────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Give each test its own ~/.ai-prowler directory so tests don't share state."""
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    # Force sms_inbox to re-read the env var on every call by reloading
    import importlib
    import sms_inbox as _mod
    importlib.reload(_mod)
    yield tmp_path
    # Cleanup handled by tmp_path fixture


@pytest.fixture
def inbox():
    import sms_inbox
    return sms_inbox


def _ts(hours_ago=0):
    """ISO timestamp N hours in the past."""
    dt = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return dt.isoformat()


def _msg(msg_id="SM001", from_num="+13865550101", body="Hello",
         provider="twilio", hours_ago=0):
    return dict(
        message_id   = msg_id,
        from_number  = from_num,
        to_number    = "+13865550100",
        body         = body,
        provider     = provider,
        contact_name = "",
        timestamp    = _ts(hours_ago),
    )


# ─── SMS-IN-01: append writes to file ────────────────────────────────────────

class TestInboxAppend:
    def test_SMS_IN_01_append_writes_to_file(self, inbox, isolated_state):
        """SMS-IN-01: sms_inbox_append() writes message to sms_inbox.json"""
        result = inbox.sms_inbox_append(**_msg())
        assert result is True
        p = isolated_state / "sms_inbox.json"
        assert p.exists()
        data = json.loads(p.read_text())
        assert len(data["messages"]) == 1
        assert data["messages"][0]["id"] == "SM001"

    def test_SMS_IN_02_append_idempotent_on_duplicate(self, inbox, isolated_state):
        """SMS-IN-02: sms_inbox_append() is idempotent on duplicate message_id"""
        inbox.sms_inbox_append(**_msg("SM001"))
        result = inbox.sms_inbox_append(**_msg("SM001"))
        assert result is False  # duplicate
        msgs = inbox.sms_inbox_read(since_hours=0)
        assert len(msgs) == 1

    def test_append_multiple_distinct_messages(self, inbox):
        inbox.sms_inbox_append(**_msg("SM001"))
        inbox.sms_inbox_append(**_msg("SM002"))
        inbox.sms_inbox_append(**_msg("SM003"))
        msgs = inbox.sms_inbox_read(since_hours=0)
        assert len(msgs) == 3

    def test_append_stores_contact_name(self, inbox):
        inbox.sms_inbox_append(**{**_msg(), "contact_name": "Karen Torres"})
        msgs = inbox.sms_inbox_read(since_hours=0)
        assert msgs[0]["contact_name"] == "Karen Torres"

    def test_append_normalises_phone_to_e164(self, inbox):
        inbox.sms_inbox_append(**{**_msg(), "from_number": "3865550101"})
        msgs = inbox.sms_inbox_read(since_hours=0)
        assert msgs[0]["from"] == "+13865550101"


# ─── SMS-IN-03 through SMS-IN-07: read and filter ────────────────────────────

class TestInboxRead:
    def _populate(self, inbox):
        inbox.sms_inbox_append(**_msg("SM001", "+13865550101", "Hello", hours_ago=0))
        inbox.sms_inbox_append(**_msg("SM002", "+13865550202", "Hi",    hours_ago=2))
        inbox.sms_inbox_append(**_msg("SM003", "+13865550101", "Ok",    hours_ago=25))

    def test_SMS_IN_03_read_returns_all(self, inbox):
        """SMS-IN-03: sms_inbox_read() returns all messages"""
        self._populate(inbox)
        msgs = inbox.sms_inbox_read(since_hours=0)
        assert len(msgs) == 3

    def test_SMS_IN_04_read_filters_by_time(self, inbox):
        """SMS-IN-04: sms_inbox_read(since_hours=1) filters by timestamp"""
        self._populate(inbox)
        msgs = inbox.sms_inbox_read(since_hours=1)
        assert len(msgs) == 1
        assert msgs[0]["id"] == "SM001"

    def test_read_last_24h(self, inbox):
        self._populate(inbox)
        msgs = inbox.sms_inbox_read(since_hours=24)
        assert len(msgs) == 2
        ids = {m["id"] for m in msgs}
        assert "SM001" in ids and "SM002" in ids

    def test_SMS_IN_05_read_filters_by_sender(self, inbox):
        """SMS-IN-05: sms_inbox_read(from_number='...') filters by sender"""
        self._populate(inbox)
        msgs = inbox.sms_inbox_read(since_hours=0, from_number="3865550101")
        assert len(msgs) == 2
        for m in msgs:
            assert "3865550101" in m["from"]

    def test_SMS_IN_06_read_unread_only(self, inbox):
        """SMS-IN-06: sms_inbox_read(unread_only=True) returns only unread"""
        self._populate(inbox)
        inbox.sms_inbox_mark_read("SM001", "mike_c")
        msgs = inbox.sms_inbox_read(since_hours=0, unread_only=True, user_id="mike_c")
        ids = {m["id"] for m in msgs}
        assert "SM001" not in ids
        assert "SM002" in ids

    def test_SMS_IN_07_mark_read_adds_user_to_read_by(self, inbox):
        """SMS-IN-07: sms_inbox_mark_read() adds user to read_by"""
        inbox.sms_inbox_append(**_msg("SM001"))
        result = inbox.sms_inbox_mark_read("SM001", "mike_c")
        assert result is True
        msgs = inbox.sms_inbox_read(since_hours=0)
        assert "mike_c" in msgs[0]["read_by"]

    def test_mark_read_returns_false_for_unknown_id(self, inbox):
        result = inbox.sms_inbox_mark_read("NONEXISTENT", "mike_c")
        assert result is False

    def test_read_filters_by_provider(self, inbox):
        inbox.sms_inbox_append(**{**_msg("SM001"), "provider": "twilio"})
        inbox.sms_inbox_append(**{**_msg("SM002"), "provider": "whatsapp"})
        msgs = inbox.sms_inbox_read(since_hours=0, provider="whatsapp")
        assert len(msgs) == 1
        assert msgs[0]["id"] == "SM002"

    def test_SMS_IN_11_corrupted_file_returns_empty(self, inbox, isolated_state):
        """SMS-IN-11: Inbox file corrupted — read returns [] not crash"""
        p = isolated_state / "sms_inbox.json"
        p.write_text("{NOT VALID JSON{{{{", encoding="utf-8")
        msgs = inbox.sms_inbox_read(since_hours=0)
        assert msgs == []

    def test_SMS_IN_12_concurrent_writes_dont_corrupt(self, inbox, isolated_state):
        """SMS-IN-12: Concurrent writes don't corrupt inbox"""
        errors = []

        def write_msg(i):
            try:
                inbox.sms_inbox_append(**_msg(f"SM{i:04d}", body=f"msg {i}"))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=write_msg, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrent write errors: {errors}"
        msgs = inbox.sms_inbox_read(since_hours=0)
        assert len(msgs) == 20


# ─── SMS-IN-08 through SMS-IN-10: Thread log ─────────────────────────────────

class TestThreadLog:
    def test_SMS_IN_08_thread_log_creates_entry(self, inbox, isolated_state):
        """SMS-IN-08: sms_thread_log() creates thread entry when send_sms called"""
        inbox.sms_thread_log(
            sent_by      = "mike_c",
            to_number    = "3865550101",
            body         = "On my way!",
            provider     = "twilio",
            contact_name = "Karen Torres",
        )
        p = isolated_state / "sms_threads.json"
        assert p.exists()
        data = json.loads(p.read_text())
        assert "3865550101" in data
        assert data["3865550101"]["contact_name"] == "Karen Torres"
        assert data["3865550101"]["last_sent_by"] == "mike_c"

    def test_SMS_IN_09_thread_log_updates_existing(self, inbox, isolated_state):
        """SMS-IN-09: sms_thread_log() updates existing thread on second send"""
        inbox.sms_thread_log("mike_c", "3865550101", "First msg", "twilio")
        inbox.sms_thread_log("mike_c", "3865550101", "Second msg", "twilio")

        data = json.loads((isolated_state / "sms_threads.json").read_text())
        # Only one thread entry
        assert len(data) == 1
        # But two messages in it
        assert len(data["3865550101"]["messages"]) == 2

    def test_SMS_IN_10_read_for_user_filters_by_thread(self, inbox):
        """SMS-IN-10: sms_inbox_read_for_user() returns only threads user participated in"""
        # Mike sends to Karen (3865550101)
        inbox.sms_thread_log("mike_c", "3865550101", "Hi Karen", "twilio", "Karen Torres")
        # Jake sends to Bob (3865550202)
        inbox.sms_thread_log("jake_r", "3865550202", "Hi Bob",   "twilio", "Bob Smith")

        # Karen replies
        inbox.sms_inbox_append(**_msg("SM001", "+13865550101", "On my way"))
        # Bob replies
        inbox.sms_inbox_append(**_msg("SM002", "+13865550202", "See you then"))

        # Mike should only see Karen's reply
        mike_msgs = inbox.sms_inbox_read_for_user("mike_c", since_hours=0)
        assert len(mike_msgs) == 1
        assert mike_msgs[0]["id"] == "SM001"

        # Jake should only see Bob's reply
        jake_msgs = inbox.sms_inbox_read_for_user("jake_r", since_hours=0)
        assert len(jake_msgs) == 1
        assert jake_msgs[0]["id"] == "SM002"

    def test_thread_get_by_phone(self, inbox):
        inbox.sms_thread_log("mike_c", "3865550101", "Hi", "twilio", "Karen Torres")
        t = inbox.sms_thread_get("3865550101")
        assert t is not None
        assert t["contact_name"] == "Karen Torres"

    def test_thread_get_by_name(self, inbox):
        inbox.sms_thread_log("mike_c", "3865550101", "Hi", "twilio", "Karen Torres")
        t = inbox.sms_thread_get("Karen Torres")
        assert t is not None
        assert t["thread_id"] == "3865550101"

    def test_thread_get_unknown_returns_none(self, inbox):
        t = inbox.sms_thread_get("9999999999")
        assert t is None

    def test_thread_get_with_replies_combines_sent_and_received(self, inbox):
        inbox.sms_thread_log("mike_c", "3865550101", "Hi Karen", "twilio", "Karen Torres")
        inbox.sms_inbox_append(**_msg("SM001", "+13865550101", "Hi Mike"))
        conv = inbox.sms_thread_get_with_replies("3865550101")
        assert conv["contact_name"] == "Karen Torres"
        assert len(conv["messages"]) == 2

    def test_active_threads_filtered_by_time(self, inbox):
        inbox.sms_thread_log("mike_c", "3865550101", "Hi", "twilio")
        inbox.sms_thread_log("jake_r", "3865550202", "Hi", "twilio")
        active = inbox.sms_active_threads(since_hours=1)
        assert len(active) == 2


# ─── Signature validation ─────────────────────────────────────────────────────

class TestSignatureValidation:
    def test_twilio_valid_signature(self):
        from sms_inbox import validate_twilio_signature
        import hmac, hashlib, base64

        auth_token = "test_auth_token_1234567890abcdef"
        url        = "https://mobile.example.com/sms-webhook"
        params     = {"From": "+13865550101", "Body": "Hello", "To": "+13865550100"}

        # Compute the expected signature
        s = url + "".join(k + params[k] for k in sorted(params.keys()))
        mac = hmac.new(auth_token.encode(), s.encode(), hashlib.sha1)
        valid_sig = base64.b64encode(mac.digest()).decode()

        assert validate_twilio_signature(auth_token, valid_sig, url, params)

    def test_twilio_invalid_signature(self):
        from sms_inbox import validate_twilio_signature
        result = validate_twilio_signature(
            "real_token", "BADSIGNATURE==", "https://example.com/sms-webhook", {}
        )
        assert result is False

    def test_twilio_empty_signature_fails(self):
        from sms_inbox import validate_twilio_signature
        result = validate_twilio_signature("token", "", "https://example.com/", {})
        assert result is False

    def test_signalwire_uses_same_algorithm_as_twilio(self):
        from sms_inbox import validate_twilio_signature, validate_signalwire_signature
        import hmac, hashlib, base64

        auth_token = "sw_auth_token"
        url        = "https://example.com/sms-webhook"
        params     = {"From": "+13865550101", "Body": "Test"}

        s   = url + "".join(k + params[k] for k in sorted(params.keys()))
        mac = hmac.new(auth_token.encode(), s.encode(), hashlib.sha1)
        sig = base64.b64encode(mac.digest()).decode()

        assert validate_signalwire_signature(auth_token, sig, url, params)

    def test_vonage_valid_signature(self):
        from sms_inbox import validate_vonage_signature
        import hashlib

        api_secret = "mysecret"
        params     = {"msisdn": "13865550101", "text": "Hello", "timestamp": "12345"}

        # Compute expected
        s        = "&".join(f"{k}={params[k]}" for k in sorted(params.keys()))
        s       += api_secret
        expected = hashlib.md5(s.encode()).hexdigest()
        params["sig"] = expected

        assert validate_vonage_signature(api_secret, params)

    def test_vonage_invalid_signature(self):
        from sms_inbox import validate_vonage_signature
        params = {"msisdn": "13865550101", "sig": "WRONG"}
        assert not validate_vonage_signature("mysecret", params)
