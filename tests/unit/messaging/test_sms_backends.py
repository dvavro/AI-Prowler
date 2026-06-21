"""
tests/unit/messaging/test_sms_backends.py
==========================================
Unit tests for sms_backends.py — the SMS/WhatsApp provider abstraction layer.

Covers SMS-BK-01 through SMS-BK-10 from TWO_WAY_MESSAGING_TEST_PLAN.md

All network calls are mocked — no real Twilio/SignalWire/Vonage account needed.
"""
from __future__ import annotations

import sys
import os
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the work-copy AI-Prowler directory is on the path
_HERE = Path(__file__).resolve()
_AI_PROWLER = _HERE.parents[3]   # tests/unit/messaging -> tests/unit -> tests -> AI-Prowler
sys.path.insert(0, str(_AI_PROWLER))

from sms_backends import (
    TwilioBackend,
    SignalWireBackend,
    VonageBackend,
    WhatsAppBackend,
    get_sms_backend,
    get_whatsapp_backend,
    normalise_phone,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

TWILIO_CFG = {
    "sms_provider":       "twilio",
    "twilio_sms_enabled": True,
    "twilio_account_sid": "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "twilio_auth_token":  "test_auth_token_1234567890abcdef",
    "twilio_from_number": "+13865550100",
}

SIGNALWIRE_CFG = {
    "sms_provider":             "signalwire",
    "signalwire_project_id":    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "signalwire_auth_token":    "PTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "signalwire_space_url":     "example.signalwire.com",
    "signalwire_from_number":   "+13865550100",
}

VONAGE_CFG = {
    "sms_provider":      "vonage",
    "vonage_api_key":    "12345678",
    "vonage_api_secret": "abcdefghijklmnop",
    "vonage_from_number": "AIProwler",
}

def _twilio_resp(status=201, sid="SM1234567890abcdef"):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = {"sid": sid}
    r.text = json.dumps({"sid": sid})
    return r

def _twilio_error_resp(status=400, message="Invalid phone number"):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = {"message": message}
    r.text = json.dumps({"message": message})
    return r

def _vonage_resp(status="0", msg_id="VON-12345"):
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"messages": [{"status": status, "message-id": msg_id}]}
    return r


# ─── normalise_phone ──────────────────────────────────────────────────────────

class TestNormalisePhone:
    def test_10_digit_bare(self):
        ok, result = normalise_phone("3865550101")
        assert ok
        assert result == "+13865550101"

    def test_11_digit_with_1(self):
        ok, result = normalise_phone("13865550101")
        assert ok
        assert result == "+13865550101"

    def test_formatted(self):
        ok, result = normalise_phone("(386) 555-0101")
        assert ok
        assert result == "+13865550101"

    def test_already_e164(self):
        ok, result = normalise_phone("+13865550101")
        assert ok
        assert result == "+13865550101"

    def test_invalid_too_short(self):
        ok, result = normalise_phone("386555")
        assert not ok
        assert "valid 10-digit" in result

    def test_invalid_empty(self):
        ok, result = normalise_phone("")
        assert not ok


# ─── SMS-BK-01 through SMS-BK-04: TwilioBackend ──────────────────────────────

class TestTwilioBackend:
    def _backend(self):
        return TwilioBackend(
            account_sid  = TWILIO_CFG["twilio_account_sid"],
            auth_token   = TWILIO_CFG["twilio_auth_token"],
            from_number  = TWILIO_CFG["twilio_from_number"],
        )

    def test_SMS_BK_01_send_success_returns_sid(self):
        """SMS-BK-01: send() with mocked requests.post returns SID"""
        with patch("requests.post", return_value=_twilio_resp(201, "SM1234567890abcdef")):
            ok, msg = self._backend().send("3865550101", "Hello Karen")
        assert ok
        assert "SM1234567890abcdef" in msg or "sent" in msg.lower()

    def test_SMS_BK_02_missing_credentials_returns_error(self):
        """SMS-BK-02: send() with missing credentials returns clear error"""
        b = TwilioBackend("", "", "")
        ok, msg = b.send("3865550101", "Hello")
        assert not ok
        assert "not configured" in msg.lower() or "missing" in msg.lower()

    def test_SMS_BK_03_twilio_400_surfaces_error(self):
        """SMS-BK-03: Twilio 400 response surfaces error message"""
        with patch("requests.post", return_value=_twilio_error_resp(400, "Invalid phone number format")):
            ok, msg = self._backend().send("3865550101", "Hello")
        assert not ok
        assert "400" in msg or "invalid" in msg.lower() or "error" in msg.lower()

    def test_SMS_BK_04_normalises_10_digit_number(self):
        """SMS-BK-04: send() normalises 10-digit number to +1XXXXXXXXXX"""
        captured = {}
        def fake_post(url, auth, data, timeout=15):
            captured["to"] = data.get("To")
            return _twilio_resp()
        with patch("requests.post", side_effect=fake_post):
            self._backend().send("3865550101", "Hello")
        assert captured.get("to") == "+13865550101"

    def test_empty_message_returns_error(self):
        ok, msg = self._backend().send("3865550101", "")
        assert not ok
        assert "empty" in msg.lower()

    def test_validate_config_ok(self):
        ok, hint = self._backend().validate_config()
        assert ok
        assert hint == ""

    def test_validate_config_missing_sid(self):
        b = TwilioBackend("", "token", "+13865550100")
        ok, hint = b.validate_config()
        assert not ok
        assert "Account SID" in hint


# ─── SMS-BK-05: SignalWireBackend ────────────────────────────────────────────

class TestSignalWireBackend:
    def _backend(self):
        return SignalWireBackend(
            project_id  = SIGNALWIRE_CFG["signalwire_project_id"],
            auth_token  = SIGNALWIRE_CFG["signalwire_auth_token"],
            space_url   = SIGNALWIRE_CFG["signalwire_space_url"],
            from_number = SIGNALWIRE_CFG["signalwire_from_number"],
        )

    def test_SMS_BK_05_uses_signalwire_url(self):
        """SMS-BK-05: send() POSTs to signalwire.com URL"""
        captured = {}
        def fake_post(url, auth, data, timeout=15):
            captured["url"] = url
            return _twilio_resp()
        with patch("requests.post", side_effect=fake_post):
            ok, msg = self._backend().send("3865550101", "Hello")
        assert ok
        assert "signalwire.com" in captured.get("url", "")

    def test_normalises_phone(self):
        captured = {}
        def fake_post(url, auth, data, timeout=15):
            captured["to"] = data.get("To")
            return _twilio_resp()
        with patch("requests.post", side_effect=fake_post):
            self._backend().send("3865550101", "Hello")
        assert captured.get("to") == "+13865550101"

    def test_missing_config_returns_error(self):
        b = SignalWireBackend("", "", "", "")
        ok, msg = b.send("3865550101", "Hello")
        assert not ok
        assert "not configured" in msg.lower()

    def test_validate_config_ok(self):
        ok, _ = self._backend().validate_config()
        assert ok

    def test_validate_config_missing_space_url(self):
        b = SignalWireBackend("proj", "tok", "", "+13865550100")
        ok, hint = b.validate_config()
        assert not ok
        assert "Space URL" in hint


# ─── SMS-BK-06: VonageBackend ────────────────────────────────────────────────

class TestVonageBackend:
    def _backend(self):
        return VonageBackend(
            api_key     = VONAGE_CFG["vonage_api_key"],
            api_secret  = VONAGE_CFG["vonage_api_secret"],
            from_number = VONAGE_CFG["vonage_from_number"],
        )

    def test_SMS_BK_06_uses_api_key_in_body(self):
        """SMS-BK-06: send() POSTs api_key in request body"""
        captured = {}
        def fake_post(url, data, timeout=15):
            captured["data"] = data
            return _vonage_resp()
        with patch("requests.post", side_effect=fake_post):
            ok, msg = self._backend().send("3865550101", "Hello")
        assert ok
        assert "api_key" in captured.get("data", {})
        assert captured["data"]["api_key"] == "12345678"

    def test_vonage_success_returns_message_id(self):
        with patch("requests.post", return_value=_vonage_resp("0", "VON-12345")):
            ok, msg = self._backend().send("3865550101", "Hello")
        assert ok
        assert "VON-12345" in msg or "sent" in msg.lower()

    def test_vonage_error_status_returned(self):
        r = MagicMock()
        r.status_code = 200
        r.json.return_value = {"messages": [{"status": "4", "error-text": "Invalid credentials"}]}
        with patch("requests.post", return_value=r):
            ok, msg = self._backend().send("3865550101", "Hello")
        assert not ok
        assert "Invalid credentials" in msg

    def test_missing_config_returns_error(self):
        b = VonageBackend("", "", "")
        ok, msg = b.send("3865550101", "Hello")
        assert not ok

    def test_validate_config_ok(self):
        ok, _ = self._backend().validate_config()
        assert ok


# ─── SMS-BK-07: WhatsAppBackend ──────────────────────────────────────────────

class TestWhatsAppBackend:
    def _backend(self):
        return WhatsAppBackend(
            account_sid  = TWILIO_CFG["twilio_account_sid"],
            auth_token   = TWILIO_CFG["twilio_auth_token"],
            from_number  = TWILIO_CFG["twilio_from_number"],
        )

    def test_SMS_BK_07_prefixes_to_with_whatsapp(self):
        """SMS-BK-07: send() calls Twilio with To=whatsapp:+1XXXXXXXXXX"""
        captured = {}
        def fake_post(url, auth, data, timeout=15):
            captured["to"]   = data.get("To")
            captured["from"] = data.get("From")
            return _twilio_resp()
        with patch("requests.post", side_effect=fake_post):
            ok, msg = self._backend().send("3865550101", "Job complete")
        assert ok
        assert captured.get("to") == "whatsapp:+13865550101"
        assert captured.get("from", "").startswith("whatsapp:")

    def test_success_message_mentions_whatsapp(self):
        with patch("requests.post", return_value=_twilio_resp()):
            ok, msg = self._backend().send("3865550101", "Hello")
        assert ok
        assert "whatsapp" in msg.lower() or "sent" in msg.lower()

    def test_missing_credentials_returns_error(self):
        b = WhatsAppBackend("", "", "")
        ok, msg = b.send("3865550101", "Hello")
        assert not ok

    def test_validate_config_ok(self):
        ok, _ = self._backend().validate_config()
        assert ok


# ─── SMS-BK-08 through SMS-BK-10: Factory functions ──────────────────────────

class TestGetSmsBackend:
    def test_SMS_BK_08_twilio_provider_returns_twilio_backend(self):
        """SMS-BK-08: get_sms_backend() returns TwilioBackend for provider='twilio'"""
        b = get_sms_backend(TWILIO_CFG)
        assert isinstance(b, TwilioBackend)

    def test_twilio_default_when_no_provider_key(self):
        cfg = dict(TWILIO_CFG)
        del cfg["sms_provider"]
        b = get_sms_backend(cfg)
        assert isinstance(b, TwilioBackend)

    def test_SMS_BK_09_signalwire_provider_returns_signalwire_backend(self):
        """SMS-BK-09: get_sms_backend() returns SignalWireBackend for provider='signalwire'"""
        b = get_sms_backend(SIGNALWIRE_CFG)
        assert isinstance(b, SignalWireBackend)

    def test_vonage_provider_returns_vonage_backend(self):
        b = get_sms_backend(VONAGE_CFG)
        assert isinstance(b, VonageBackend)

    def test_SMS_BK_10_unknown_provider_returns_error_on_send(self):
        """SMS-BK-10: get_sms_backend() for unknown provider returns error on send"""
        b = get_sms_backend({"sms_provider": "carrier_pigeon"})
        ok, msg = b.send("3865550101", "Hello")
        assert not ok
        assert "unknown provider" in msg.lower() or "carrier_pigeon" in msg

    def test_get_whatsapp_backend_returns_whatsapp_backend(self):
        b = get_whatsapp_backend(TWILIO_CFG)
        assert isinstance(b, WhatsAppBackend)
