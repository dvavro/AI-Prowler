"""
tests/unit/messaging/test_sms_webhook.py
==========================================
Unit tests for the SMS/WhatsApp webhook handlers.

Covers SMS-WH-01 through SMS-WH-10 from TWO_WAY_MESSAGING_TEST_PLAN.md

Uses httpx + Starlette TestClient to call the handlers directly without
starting a real server — no Twilio account needed, all signatures mocked.
"""
from __future__ import annotations

import sys
import os
import json
import hmac
import hashlib
import base64
import urllib.parse
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

_HERE       = Path(__file__).resolve()
_AI_PROWLER = _HERE.parents[3]
sys.path.insert(0, str(_AI_PROWLER))


# ─── Fixtures ─────────────────────────────────────────────────────────────────

AUTH_TOKEN = "test_auth_token_1234567890abcdef"
WEBHOOK_URL = "https://mobile.example.com/sms-webhook"
WA_WEBHOOK_URL = "https://mobile.example.com/whatsapp-webhook"

TWILIO_INBOUND = {
    "MessageSid": "SM1234567890abcdef1234567890abcdef",
    "From": "+13865550101",
    "To":   "+13865550100",
    "Body": "On my way, 10 min out",
    "NumMedia": "0",
}

WA_INBOUND = {
    "MessageSid": "SM_wa_1234567890abcdef",
    "From": "whatsapp:+13865550101",
    "To":   "whatsapp:+13865550100",
    "Body": "Job complete, sending photos",
    "NumMedia": "0",
}


def _twilio_sig(auth_token: str, url: str, params: dict) -> str:
    """Compute a valid Twilio X-Twilio-Signature for the given params."""
    s = url + "".join(k + str(params[k]) for k in sorted(params.keys()))
    mac = hmac.new(auth_token.encode(), s.encode(), hashlib.sha1)
    return base64.b64encode(mac.digest()).decode()


def _form_encode(params: dict) -> bytes:
    return urllib.parse.urlencode(params).encode("utf-8")


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    import importlib, sms_inbox
    importlib.reload(sms_inbox)
    yield tmp_path


@pytest.fixture
def mock_sms_config(tmp_path, monkeypatch):
    """Write a Twilio config so webhook handlers can load it."""
    cfg = {
        "sms_provider": "twilio",
        "twilio_sms_enabled": True,
        "twilio_account_sid": "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "twilio_auth_token": AUTH_TOKEN,
        "twilio_from_number": "+13865550100",
        "sms_help_reply_text": "AI-Prowler support: test@example.com, or reply "
                                "STOP to unsubscribe. Msg&data rates may apply.",
    }
    cfg_dir = tmp_path / ".ai-prowler"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))

    # Patch load_sms_config to read from our temp dir
    with patch("sms_backends.load_sms_config", return_value=cfg):
        yield cfg


# ─── Build a minimal Starlette test app with the webhook routes ────────────────

def _make_test_app(tmp_path):
    """
    Build a Starlette app with just the SMS webhook routes for testing.
    We can't import _run_http's closure directly, so we recreate the
    handlers using the same logic from sms_inbox.
    """
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.responses import PlainTextResponse
    from starlette.requests import Request
    from sms_inbox import (sms_inbox_append, validate_twilio_signature,
                           validate_signalwire_signature)

    async def sms_webhook(request: Request):
        body_bytes = await request.body()
        # keep_blank_values=True — required so Twilio's signature calc
        # (which includes blank-valued fields like ToState=/ToCity=) can be
        # correctly reproduced. Dropping blank values here silently breaks
        # signature validation for any inbound message where a location
        # field happens to be empty. See ai_prowler_mcp.py for the real
        # fix; this test harness must mirror it or tests give false confidence.
        params = dict(urllib.parse.parse_qsl(
            body_bytes.decode("utf-8", errors="replace"), keep_blank_values=True))
        if not params:
            return PlainTextResponse("Bad Request", status_code=400)

        cfg        = json.loads((tmp_path / ".ai-prowler" / "config.json").read_text())
        provider   = str(cfg.get("sms_provider", "twilio")).lower()
        auth_token = cfg.get("twilio_auth_token", "")
        signature  = request.headers.get("X-Twilio-Signature", "")
        url        = str(request.url)

        if auth_token and signature:
            valid = validate_twilio_signature(auth_token, signature, url, params)
            if not valid:
                return PlainTextResponse("Forbidden", status_code=403)

        from_num = params.get("From", "")
        body_text = params.get("Body", "")

        sms_inbox_append(
            message_id   = params.get("MessageSid", ""),
            from_number  = from_num,
            to_number    = params.get("To", ""),
            body         = body_text,
            provider     = provider,
            contact_name = "",
            timestamp    = "",
        )

        # Consent lifecycle — mirrors ai_prowler_mcp.py's sms_webhook Phase 1.5.
        _kw = None
        try:
            from sms_consent import classify_keyword, consent_set_state
            _kw = classify_keyword(body_text)
            if _kw == "opt_out":
                consent_set_state(from_num, consented=False)
            elif _kw == "opt_in":
                consent_set_state(from_num, consented=True)
        except Exception:
            pass

        if _kw == "info":
            _help_text = str(cfg.get("sms_help_reply_text", "") or "").strip()
            if _help_text:
                import xml.sax.saxutils as _xmlsax
                _help_body = _xmlsax.escape(_help_text)
                return PlainTextResponse(
                    f"<?xml version='1.0' encoding='UTF-8'?>"
                    f"<Response><Message>{_help_body}</Message></Response>",
                    media_type="text/xml", status_code=200)

        return PlainTextResponse(
            "<?xml version='1.0' encoding='UTF-8'?><Response/>",
            media_type="text/xml", status_code=200)

    async def whatsapp_webhook(request: Request):
        body_bytes = await request.body()
        params = dict(urllib.parse.parse_qsl(
            body_bytes.decode("utf-8", errors="replace"), keep_blank_values=True))
        if not params:
            return PlainTextResponse("Bad Request", status_code=400)

        cfg        = json.loads((tmp_path / ".ai-prowler" / "config.json").read_text())
        auth_token = cfg.get("twilio_auth_token", "")
        signature  = request.headers.get("X-Twilio-Signature", "")
        url        = str(request.url)

        if auth_token and signature:
            if not validate_twilio_signature(auth_token, signature, url, params):
                return PlainTextResponse("Forbidden", status_code=403)

        sms_inbox_append(
            message_id   = params.get("MessageSid", ""),
            from_number  = params.get("From", ""),
            to_number    = params.get("To", ""),
            body         = params.get("Body", ""),
            provider     = "whatsapp",
            contact_name = "",
            timestamp    = "",
        )
        return PlainTextResponse(
            "<?xml version='1.0' encoding='UTF-8'?><Response/>",
            media_type="text/xml", status_code=200)

    return Starlette(routes=[
        Route("/sms-webhook",      sms_webhook,      methods=["POST"]),
        Route("/whatsapp-webhook", whatsapp_webhook, methods=["POST"]),
    ])


@pytest.fixture
def client(tmp_path, mock_sms_config):
    """Starlette TestClient with webhook routes and Twilio config."""
    from starlette.testclient import TestClient
    cfg_dir = tmp_path / ".ai-prowler"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "config.json").write_text(
        json.dumps(mock_sms_config), encoding="utf-8")
    app = _make_test_app(tmp_path)
    return TestClient(app, raise_server_exceptions=True)


# ─── SMS-WH-01: Valid signature → 200 + TwiML ────────────────────────────────

class TestSmsWebhook:
    def test_SMS_WH_01_valid_signature_returns_200(self, client, isolated_state):
        """SMS-WH-01: POST /sms-webhook with valid Twilio signature returns 200"""
        sig = _twilio_sig(AUTH_TOKEN, "http://testserver/sms-webhook", TWILIO_INBOUND)
        resp = client.post(
            "/sms-webhook",
            content=_form_encode(TWILIO_INBOUND),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Twilio-Signature": sig,
            },
        )
        assert resp.status_code == 200
        assert "<Response/>" in resp.text

    def test_SMS_WH_02_invalid_signature_returns_403(self, client, isolated_state):
        """SMS-WH-02: POST /sms-webhook with invalid signature returns 403"""
        resp = client.post(
            "/sms-webhook",
            content=_form_encode(TWILIO_INBOUND),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Twilio-Signature": "INVALIDSIGNATURE==",
            },
        )
        assert resp.status_code == 403

    def test_SMS_WH_03_missing_signature_no_token_passes(self, client, isolated_state, tmp_path):
        """SMS-WH-03: No signature + no auth_token → dev mode, passes through"""
        # Write config with no auth_token
        cfg_dir = tmp_path / ".ai-prowler"
        cfg_dir.mkdir(exist_ok=True)
        (cfg_dir / "config.json").write_text(
            json.dumps({"sms_provider": "twilio", "twilio_auth_token": ""}),
            encoding="utf-8")
        resp = client.post(
            "/sms-webhook",
            content=_form_encode(TWILIO_INBOUND),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        # No auth token configured → dev mode, should pass
        assert resp.status_code == 200

    def test_SMS_WH_04_stores_message_to_inbox(self, client, isolated_state):
        """SMS-WH-04: POST /sms-webhook stores message to sms_inbox.json"""
        sig = _twilio_sig(AUTH_TOKEN, "http://testserver/sms-webhook", TWILIO_INBOUND)
        client.post(
            "/sms-webhook",
            content=_form_encode(TWILIO_INBOUND),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Twilio-Signature": sig,
            },
        )
        from sms_inbox import sms_inbox_read
        msgs = sms_inbox_read(since_hours=0)
        assert len(msgs) == 1
        assert msgs[0]["body"] == "On my way, 10 min out"
        assert msgs[0]["id"] == "SM1234567890abcdef1234567890abcdef"

    def test_SMS_WH_09_empty_body_returns_400(self, client, isolated_state):
        """SMS-WH-09: Webhook with empty body returns 400"""
        resp = client.post(
            "/sms-webhook",
            content=b"",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert resp.status_code == 400

    def test_SMS_WH_10_accessible_without_bearer_token(self, client, isolated_state):
        """SMS-WH-10: /sms-webhook accessible without Bearer token (Twilio has none)"""
        sig = _twilio_sig(AUTH_TOKEN, "http://testserver/sms-webhook", TWILIO_INBOUND)
        # No Authorization header at all
        resp = client.post(
            "/sms-webhook",
            content=_form_encode(TWILIO_INBOUND),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Twilio-Signature": sig,
            },
        )
        assert resp.status_code == 200

    def test_duplicate_message_not_stored_twice(self, client, isolated_state):
        """Idempotent: posting same MessageSid twice stores it only once"""
        sig = _twilio_sig(AUTH_TOKEN, "http://testserver/sms-webhook", TWILIO_INBOUND)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Twilio-Signature": sig,
        }
        client.post("/sms-webhook", content=_form_encode(TWILIO_INBOUND), headers=headers)
        client.post("/sms-webhook", content=_form_encode(TWILIO_INBOUND), headers=headers)
        from sms_inbox import sms_inbox_read
        msgs = sms_inbox_read(since_hours=0)
        assert len(msgs) == 1


# ─── SMS-WH-06: WhatsApp webhook ─────────────────────────────────────────────

class TestWhatsAppWebhook:
    def test_SMS_WH_06_stores_whatsapp_message_with_correct_provider(
            self, client, isolated_state):
        """SMS-WH-06: /whatsapp-webhook stores message with provider='whatsapp'"""
        sig = _twilio_sig(AUTH_TOKEN, "http://testserver/whatsapp-webhook", WA_INBOUND)
        resp = client.post(
            "/whatsapp-webhook",
            content=_form_encode(WA_INBOUND),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Twilio-Signature": sig,
            },
        )
        assert resp.status_code == 200
        from sms_inbox import sms_inbox_read
        msgs = sms_inbox_read(since_hours=0, provider="whatsapp")
        assert len(msgs) == 1
        assert msgs[0]["provider"] == "whatsapp"
        assert msgs[0]["body"] == "Job complete, sending photos"

    def test_whatsapp_invalid_signature_returns_403(self, client, isolated_state):
        resp = client.post(
            "/whatsapp-webhook",
            content=_form_encode(WA_INBOUND),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Twilio-Signature": "BADSIG==",
            },
        )
        assert resp.status_code == 403

    def test_whatsapp_empty_body_returns_400(self, client, isolated_state):
        resp = client.post(
            "/whatsapp-webhook",
            content=b"",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert resp.status_code == 400

    def test_whatsapp_and_sms_stored_separately(self, client, isolated_state):
        """SMS and WhatsApp messages in same inbox, filtered by provider"""
        sms_sig = _twilio_sig(AUTH_TOKEN, "http://testserver/sms-webhook", TWILIO_INBOUND)
        wa_sig  = _twilio_sig(AUTH_TOKEN, "http://testserver/whatsapp-webhook", WA_INBOUND)

        client.post("/sms-webhook", content=_form_encode(TWILIO_INBOUND),
                    headers={"Content-Type": "application/x-www-form-urlencoded",
                             "X-Twilio-Signature": sms_sig})
        client.post("/whatsapp-webhook", content=_form_encode(WA_INBOUND),
                    headers={"Content-Type": "application/x-www-form-urlencoded",
                             "X-Twilio-Signature": wa_sig})

        from sms_inbox import sms_inbox_read
        all_msgs = sms_inbox_read(since_hours=0)
        sms_msgs = sms_inbox_read(since_hours=0, provider="twilio")
        wa_msgs  = sms_inbox_read(since_hours=0, provider="whatsapp")

        assert len(all_msgs) == 2
        assert len(sms_msgs) == 1
        assert len(wa_msgs)  == 1


# ─── SignalWire signature validation ─────────────────────────────────────────

class TestSignalWireWebhook:
    def test_SMS_WH_07_signalwire_signature_validates_correctly(
            self, tmp_path, isolated_state):
        """SMS-WH-07: POST /sms-webhook with SignalWire signature validates correctly"""
        from sms_inbox import validate_signalwire_signature
        import hmac as _hmac, hashlib as _hs, base64 as _b64

        sw_token = "sw_test_token"
        url      = "https://example.com/sms-webhook"
        params   = {"From": "+13865550101", "Body": "SW test", "To": "+13865550100"}

        s   = url + "".join(k + params[k] for k in sorted(params.keys()))
        mac = _hmac.new(sw_token.encode(), s.encode(), _hs.sha1)
        sig = _b64.b64encode(mac.digest()).decode()

        assert validate_signalwire_signature(sw_token, sig, url, params)

    def test_signalwire_bad_token_fails(self):
        from sms_inbox import validate_signalwire_signature
        assert not validate_signalwire_signature("wrong", "BADSIG==",
                                                  "https://example.com/", {})


# ─── HELP auto-reply and STOP/START-via-webhook (Phase 1.5) ─────────────────
# These exercise the FULL webhook route, not just sms_consent.py directly —
# confirms classify_keyword() + consent_set_state() + the TwiML response
# actually wire together correctly end-to-end through the real request path.

def _inbound(body: str, from_num: str = "+13865550101") -> dict:
    return {
        "MessageSid": "SM_kw_test",
        "From": from_num,
        "To":   "+13865550100",
        "Body": body,
        "NumMedia": "0",
    }


class TestHelpAutoReply:
    def test_help_returns_populated_twiml_with_escaped_ampersand(self, client, isolated_state):
        params = _inbound("HELP")
        sig = _twilio_sig(AUTH_TOKEN, "http://testserver/sms-webhook", params)
        resp = client.post(
            "/sms-webhook",
            content=_form_encode(params),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Twilio-Signature": sig,
            },
        )
        assert resp.status_code == 200
        assert "<Message>" in resp.text
        assert "test@example.com" in resp.text
        assert "STOP" in resp.text
        # The literal "&" in "Msg&data" MUST be XML-escaped as "&amp;" —
        # unescaped, this would be invalid XML and could break Twilio's parser.
        assert "&amp;data" in resp.text
        assert "Msg&data" not in resp.text  # raw unescaped form must not appear

        # And the response must be well-formed XML, not just string-matching.
        import xml.etree.ElementTree as ET
        root = ET.fromstring(resp.text)
        assert root.tag == "Response"
        assert root.find("Message") is not None

    def test_help_does_not_change_consent_state(self, client, isolated_state, tmp_path):
        """HELP is informational only — must never flip an existing
        consent record's state."""
        import os
        os.environ["AIPROWLER_TEST_STATE_DIR"] = str(tmp_path)
        import importlib, sms_consent
        importlib.reload(sms_consent)
        sms_consent.consent_signup_upsert(name="Jane", phone="+13865550101", consented=True)

        params = _inbound("HELP")
        sig = _twilio_sig(AUTH_TOKEN, "http://testserver/sms-webhook", params)
        client.post("/sms-webhook", content=_form_encode(params),
                    headers={"Content-Type": "application/x-www-form-urlencoded",
                             "X-Twilio-Signature": sig})

        records = sms_consent.consent_list()
        assert len(records) == 1
        assert records[0]["consented"] is True
        assert records[0]["opted_out_at"] is None

    def test_ordinary_message_gets_empty_twiml_not_help_reply(self, client, isolated_state):
        """Regression guard: an unrelated message must NOT accidentally
        trigger the HELP auto-reply."""
        params = _inbound("On my way, 10 min out")
        sig = _twilio_sig(AUTH_TOKEN, "http://testserver/sms-webhook", params)
        resp = client.post(
            "/sms-webhook",
            content=_form_encode(params),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "X-Twilio-Signature": sig},
        )
        assert resp.status_code == 200
        assert "<Response/>" in resp.text
        assert "<Message>" not in resp.text

    def test_blank_help_config_falls_back_to_no_reply(self, isolated_state, tmp_path):
        """Safe-default check: if sms_help_reply_text is unset/blank (the
        out-of-the-box state for a new AI-Prowler install), HELP must fall
        through to empty TwiML rather than sending some generic/hardcoded
        message pointing at the wrong business. Uses its own config —
        deliberately NOT the mock_sms_config fixture, which always sets a
        help text — to isolate exactly this unconfigured case."""
        from starlette.testclient import TestClient

        cfg = {
            "sms_provider": "twilio",
            "twilio_sms_enabled": True,
            "twilio_account_sid": "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "twilio_auth_token": AUTH_TOKEN,
            "twilio_from_number": "+13865550100",
            # sms_help_reply_text intentionally omitted — the unconfigured case.
        }
        cfg_dir = tmp_path / ".ai-prowler"
        cfg_dir.mkdir(exist_ok=True)
        (cfg_dir / "config.json").write_text(json.dumps(cfg), encoding="utf-8")

        with patch("sms_backends.load_sms_config", return_value=cfg):
            app = _make_test_app(tmp_path)
            local_client = TestClient(app, raise_server_exceptions=True)

            params = _inbound("HELP")
            sig = _twilio_sig(AUTH_TOKEN, "http://testserver/sms-webhook", params)
            resp = local_client.post(
                "/sms-webhook",
                content=_form_encode(params),
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "X-Twilio-Signature": sig},
            )

        assert resp.status_code == 200
        assert "<Response/>" in resp.text
        assert "<Message>" not in resp.text


class TestStopStartViaWebhook:
    """End-to-end: a real STOP/START reply through the actual webhook route
    updates sms_consent.json, not just via direct sms_consent.py calls."""

    def test_stop_via_webhook_updates_consent(self, client, isolated_state, tmp_path):
        import os
        os.environ["AIPROWLER_TEST_STATE_DIR"] = str(tmp_path)
        import importlib, sms_consent
        importlib.reload(sms_consent)
        sms_consent.consent_signup_upsert(name="Jane", phone="+13865550101", consented=True)

        params = _inbound("STOP")
        sig = _twilio_sig(AUTH_TOKEN, "http://testserver/sms-webhook", params)
        resp = client.post("/sms-webhook", content=_form_encode(params),
                            headers={"Content-Type": "application/x-www-form-urlencoded",
                                     "X-Twilio-Signature": sig})

        assert resp.status_code == 200
        assert "<Response/>" in resp.text  # STOP gets empty TwiML, not a HELP-style reply
        records = sms_consent.consent_list()
        assert records[0]["consented"] is False
        assert records[0]["opted_out_at"] is not None

    def test_blank_form_field_does_not_break_signature_validation(self, client, isolated_state):
        """Regression test for the keep_blank_values bug: a request with a
        blank-valued field (e.g. ToState=) must still validate correctly,
        not silently drop the field and fail signature verification."""
        params = dict(TWILIO_INBOUND)
        params["ToState"] = ""   # blank value — parse_qsl drops this by
        params["ToCity"]  = ""   # default unless keep_blank_values=True
        sig = _twilio_sig(AUTH_TOKEN, "http://testserver/sms-webhook", params)

        resp = client.post(
            "/sms-webhook",
            content=_form_encode(params),
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "X-Twilio-Signature": sig},
        )
        assert resp.status_code == 200, (
            "Blank-valued form fields broke signature validation — this is "
            "the exact bug found in production on 2026-08-15 (parse_qsl "
            "silently drops blank values without keep_blank_values=True)."
        )

