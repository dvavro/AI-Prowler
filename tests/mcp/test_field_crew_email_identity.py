"""
tests/mcp/test_field_crew_email_identity.py
============================================
Tests for the field-crew email personalisation feature (v7.0.0+).

When a field_crew member sends email in server mode, AI-Prowler:
  1. Sets the From display name to  "Employee Name via Company Name"
  2. Sets the Reply-To header to    "Employee Name <emp@email.com>"

This ensures the customer's reply goes directly to the employee's
personal email, not the generic company SMTP address.

Tests are grouped into four classes:

  TestSendSmtpHeaders        — _send_smtp() itself sets headers correctly
  TestSendEmailPersonalised  — send_email() builds and passes correct kwargs
  TestSendAlertPersonalised  — send_alert() builds and passes correct kwargs
  TestEdgeCases              — missing name / missing email / personal mode

All tests are in-process; no real SMTP connections are made.
"""
from __future__ import annotations

import base64
import email as _email_stdlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

# mcp_module session fixture is defined in tests/mcp/conftest.py and is
# auto-discovered by pytest — no import needed here.


# ── Shared helpers ────────────────────────────────────────────────────────────

class _Stub:
    """Minimal attribute-stub used to build mock FastMCP Context objects."""
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def _make_ctx(user: dict | None):
    """Build a minimal FastMCP Context whose _current_user() reads `user`."""
    if user is None:
        return None
    return _Stub(
        request_context=_Stub(
            request=_Stub(
                state=_Stub(user=user)
            )
        )
    )


def _make_field_crew(name="Jake Smith",
                     email="jake.smith@gmail.com",
                     uid="tok_jake") -> dict:
    return {
        "id":     uid,
        "name":   name,
        "role":   "field_crew",
        "email":  email,
        "status": "active",
        "scopes": ["scope:field"],
        "private_collection_enabled": False,
        "can_manage_users": False,
    }


def _write_email_cfg(path: Path, from_name="ABC Window Cleaning",
                     default_to="admin@company.com") -> None:
    """Write a minimal valid email_config.json to `path`."""
    cfg = {
        "smtp_host":     "smtp.gmail.com",
        "smtp_port":     587,
        "username":      "service@abcwindows.com",
        "from_name":     from_name,
        "default_to":    default_to,
        "use_tls":       True,
        "_password_b64": base64.b64encode(b"app_password").decode(),
    }
    path.write_text(json.dumps(cfg), encoding="utf-8")


class _FakeSmtp:
    """Captures sendmail() calls so tests can inspect the sent message."""
    def __init__(self):
        self.sent = []          # list of (from, to_list, msg_bytes)

    def __call__(self, host, port, timeout=None):
        return self             # acts as context manager AND connection

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def ehlo(self):
        pass

    def starttls(self, context=None):
        pass

    def login(self, user, password):
        pass

    def sendmail(self, from_addr, to_list, msg_bytes):
        self.sent.append((from_addr, to_list, msg_bytes))


def _parse_msg(msg_bytes: bytes) -> _email_stdlib.message.Message:
    return _email_stdlib.message_from_bytes(msg_bytes)


# ═════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def email_env(tmp_path, mcp_module, monkeypatch):
    """Redirect _EMAIL_CONFIG_PATH to a temp file with a valid config.
    Uses the session-scoped mcp_module fixture from tests/mcp/conftest.py."""
    cfg_path = tmp_path / "email_config.json"
    _write_email_cfg(cfg_path)
    monkeypatch.setattr(mcp_module, "_EMAIL_CONFIG_PATH", lambda: cfg_path)
    return SimpleNamespace(mcp=mcp_module, cfg_path=cfg_path, tmp=tmp_path)


# ═════════════════════════════════════════════════════════════════════════════
# 1. _send_smtp — header correctness
# ═════════════════════════════════════════════════════════════════════════════

class TestSendSmtpHeaders:
    """Unit-test _send_smtp() directly, intercepting smtplib.SMTP."""

    def test_reply_to_header_is_set(self, email_env):
        """reply_to kwarg → Reply-To header in outbound message."""
        smtp = _FakeSmtp()
        with patch("smtplib.SMTP", smtp):
            ok, _ = email_env.mcp._send_smtp(
                to="customer@example.com",
                subject="Job done",
                body="All finished.",
                reply_to="Jake Smith <jake.smith@gmail.com>",
            )

        assert ok is True
        assert smtp.sent, "No message was sent"
        msg = _parse_msg(smtp.sent[0][2])
        assert msg["Reply-To"] == "Jake Smith <jake.smith@gmail.com>"

    def test_sender_display_overrides_from_name(self, email_env):
        """sender_display kwarg → From display name in outbound message."""
        smtp = _FakeSmtp()
        with patch("smtplib.SMTP", smtp):
            ok, _ = email_env.mcp._send_smtp(
                to="customer@example.com",
                subject="Update",
                body="On my way.",
                sender_display="Jake Smith via ABC Window Cleaning",
            )

        assert ok is True
        msg = _parse_msg(smtp.sent[0][2])
        from_hdr = msg["From"]
        assert "Jake Smith via ABC Window Cleaning" in from_hdr

    def test_smtp_address_unchanged_when_sender_display_set(self, email_env):
        """SMTP sending address stays as the server's address
        regardless of sender_display."""
        smtp = _FakeSmtp()
        with patch("smtplib.SMTP", smtp):
            email_env.mcp._send_smtp(
                to="customer@example.com",
                subject="s",
                body="b",
                sender_display="Jake Smith via ABC",
            )

        # sendmail() 1st arg is the envelope From — must be the SMTP account
        envelope_from = smtp.sent[0][0]
        assert envelope_from == "service@abcwindows.com"

    def test_no_reply_to_header_when_omitted(self, email_env):
        """When reply_to is not passed, Reply-To header must not appear."""
        smtp = _FakeSmtp()
        with patch("smtplib.SMTP", smtp):
            email_env.mcp._send_smtp(
                to="customer@example.com",
                subject="s",
                body="b",
            )

        msg = _parse_msg(smtp.sent[0][2])
        assert msg["Reply-To"] is None

    def test_default_from_name_used_when_sender_display_omitted(self, email_env):
        """from_name from email_config.json is used when sender_display is None."""
        smtp = _FakeSmtp()
        with patch("smtplib.SMTP", smtp):
            email_env.mcp._send_smtp(
                to="customer@example.com",
                subject="s",
                body="b",
            )

        msg = _parse_msg(smtp.sent[0][2])
        assert "ABC Window Cleaning" in msg["From"]

    def test_both_reply_to_and_sender_display_together(self, email_env):
        """Both kwargs can be set simultaneously — both appear in message."""
        smtp = _FakeSmtp()
        with patch("smtplib.SMTP", smtp):
            email_env.mcp._send_smtp(
                to="customer@example.com",
                subject="Done",
                body="Job complete.",
                reply_to="Jake Smith <jake@gmail.com>",
                sender_display="Jake Smith via ABC Cleaning",
            )

        msg = _parse_msg(smtp.sent[0][2])
        assert msg["Reply-To"] == "Jake Smith <jake@gmail.com>"
        assert "Jake Smith via ABC Cleaning" in msg["From"]


# ═════════════════════════════════════════════════════════════════════════════
# 2. send_email — field_crew personalisation
# ═════════════════════════════════════════════════════════════════════════════

class TestSendEmailPersonalised:
    """send_email() passes correct reply_to and sender_display to _send_smtp
    when a server-mode user with a registered email calls the tool."""

    def _capture_smtp_kwargs(self, email_env, monkeypatch):
        """Monkeypatch _send_smtp to capture kwargs without hitting SMTP."""
        captured = {}

        def fake_send(to, subject, body, **kw):
            captured.update(kw)
            captured["to"] = to
            return (True, f"✅ Email sent to {to}")

        monkeypatch.setattr(email_env.mcp, "_send_smtp", fake_send)
        return captured

    def test_reply_to_set_from_user_email(self, email_env, monkeypatch):
        """send_email passes employee email as Reply-To."""
        captured = self._capture_smtp_kwargs(email_env, monkeypatch)
        user = _make_field_crew(name="Jake Smith", email="jake@gmail.com")
        ctx  = _make_ctx(user)

        email_env.mcp.send_email(
            to="customer@example.com", subject="Job done",
            body="All complete.", ctx=ctx)

        assert "reply_to" in captured
        assert "jake@gmail.com" in captured["reply_to"]
        assert "Jake Smith" in captured["reply_to"]

    def test_sender_display_includes_employee_name(self, email_env, monkeypatch):
        """send_email builds sender_display as 'Name via Company'."""
        captured = self._capture_smtp_kwargs(email_env, monkeypatch)
        user = _make_field_crew(name="Jake Smith", email="jake@gmail.com")
        ctx  = _make_ctx(user)

        email_env.mcp.send_email(
            to="customer@example.com", subject="s",
            body="b", ctx=ctx)

        assert "sender_display" in captured
        display = captured["sender_display"]
        assert "Jake Smith" in display

    def test_sender_display_includes_company_name(self, email_env, monkeypatch):
        """sender_display appends the server's configured from_name."""
        captured = self._capture_smtp_kwargs(email_env, monkeypatch)
        user = _make_field_crew(name="Jake Smith", email="jake@gmail.com")
        ctx  = _make_ctx(user)

        email_env.mcp.send_email(
            to="customer@example.com", subject="s",
            body="b", ctx=ctx)

        assert "ABC Window Cleaning" in captured.get("sender_display", "")

    def test_no_reply_to_when_employee_has_no_email(self, email_env, monkeypatch):
        """Graceful fallback: no Reply-To if employee has no email on record."""
        captured = self._capture_smtp_kwargs(email_env, monkeypatch)
        user = _make_field_crew(name="Jake Smith", email="")
        ctx  = _make_ctx(user)

        email_env.mcp.send_email(
            to="customer@example.com", subject="s",
            body="b", ctx=ctx)

        assert captured.get("reply_to") is None

    def test_no_personalisation_in_personal_mode(self, email_env, monkeypatch):
        """Personal mode (ctx=None / no user): no reply_to, no sender_display."""
        captured = self._capture_smtp_kwargs(email_env, monkeypatch)

        email_env.mcp.send_email(
            to="customer@example.com", subject="s",
            body="b", ctx=None)

        assert captured.get("reply_to") is None
        assert captured.get("sender_display") is None

    def test_reply_to_format_name_plus_email(self, email_env, monkeypatch):
        """Reply-To is formatted as 'Name <email>' when both name and email exist."""
        captured = self._capture_smtp_kwargs(email_env, monkeypatch)
        user = _make_field_crew(name="Maria Lopez", email="maria@company.com")
        ctx  = _make_ctx(user)

        email_env.mcp.send_email(
            to="cust@example.com", subject="s", body="b", ctx=ctx)

        assert captured.get("reply_to") == "Maria Lopez <maria@company.com>"

    def test_reply_to_is_just_email_when_no_name(self, email_env, monkeypatch):
        """When employee has no name, Reply-To is just the bare email address."""
        captured = self._capture_smtp_kwargs(email_env, monkeypatch)
        user = _make_field_crew(name="", email="noname@example.com")
        ctx  = _make_ctx(user)

        email_env.mcp.send_email(
            to="cust@example.com", subject="s", body="b", ctx=ctx)

        assert captured.get("reply_to") == "noname@example.com"


# ═════════════════════════════════════════════════════════════════════════════
# 3. send_alert — field_crew personalisation
# ═════════════════════════════════════════════════════════════════════════════

class TestSendAlertPersonalised:
    """send_alert() passes correct reply_to and sender_display to _send_smtp."""

    def _capture_smtp_kwargs(self, email_env, monkeypatch):
        captured = {}

        def fake_send(to, subject, body, **kw):
            captured.update(kw)
            return (True, f"✅ Alert sent to {to}")

        monkeypatch.setattr(email_env.mcp, "_send_smtp", fake_send)
        return captured

    def test_reply_to_set_from_user_email(self, email_env, monkeypatch):
        """send_alert passes employee email as Reply-To."""
        captured = self._capture_smtp_kwargs(email_env, monkeypatch)
        user = _make_field_crew(name="Jake Smith", email="jake@gmail.com")
        ctx  = _make_ctx(user)

        email_env.mcp.send_alert(
            message="Running 10 mins late.", ctx=ctx)

        assert "jake@gmail.com" in captured.get("reply_to", "")

    def test_sender_display_set_for_alert(self, email_env, monkeypatch):
        """send_alert builds sender_display with employee name."""
        captured = self._capture_smtp_kwargs(email_env, monkeypatch)
        user = _make_field_crew(name="Jake Smith", email="jake@gmail.com")
        ctx  = _make_ctx(user)

        email_env.mcp.send_alert(message="Job complete.", ctx=ctx)

        assert "Jake Smith" in captured.get("sender_display", "")

    def test_no_reply_to_without_employee_email(self, email_env, monkeypatch):
        """send_alert graceful fallback when employee has no email."""
        captured = self._capture_smtp_kwargs(email_env, monkeypatch)
        user = _make_field_crew(name="Jake Smith", email="")
        ctx  = _make_ctx(user)

        email_env.mcp.send_alert(message="Done.", ctx=ctx)

        assert captured.get("reply_to") is None

    def test_no_personalisation_in_personal_mode(self, email_env, monkeypatch):
        """Personal mode send_alert: no reply_to, no sender_display."""
        captured = self._capture_smtp_kwargs(email_env, monkeypatch)

        email_env.mcp.send_alert(
            message="Alert.", to="admin@company.com", ctx=None)

        assert captured.get("reply_to") is None
        assert captured.get("sender_display") is None


# ═════════════════════════════════════════════════════════════════════════════
# 4. Edge cases
# ═════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def _capture(self, email_env, monkeypatch):
        captured = {}

        def fake_send(to, subject, body, **kw):
            captured.update(kw)
            return (True, "✅")

        monkeypatch.setattr(email_env.mcp, "_send_smtp", fake_send)
        return captured

    def test_email_with_unicode_name(self, email_env, monkeypatch):
        """Employee names with accented characters are passed through cleanly."""
        captured = self._capture(email_env, monkeypatch)
        user = _make_field_crew(name="José García", email="jose@example.com")
        ctx  = _make_ctx(user)

        email_env.mcp.send_email(
            to="cust@example.com", subject="s", body="b", ctx=ctx)

        assert "José García" in captured.get("reply_to", "")
        assert "José García" in captured.get("sender_display", "")

    def test_sender_display_falls_back_to_name_only_if_no_company_name(
            self, tmp_path, mcp_module, monkeypatch):
        """If from_name is empty in config, sender_display is just the
        employee name with no ' via ...' suffix."""
        cfg_path = tmp_path / "email_cfg2.json"
        _write_email_cfg(cfg_path, from_name="")   # empty company name
        monkeypatch.setattr(mcp_module, "_EMAIL_CONFIG_PATH", lambda: cfg_path)

        captured = {}

        def fake_send(to, subject, body, **kw):
            captured.update(kw)
            return (True, "✅")

        monkeypatch.setattr(mcp_module, "_send_smtp", fake_send)

        user = _make_field_crew(name="Jake Smith", email="jake@gmail.com")
        ctx  = _make_ctx(user)

        mcp_module.send_email(
            to="cust@example.com", subject="s", body="b", ctx=ctx)

        display = captured.get("sender_display", "")
        assert display == "Jake Smith"
        assert "via" not in display

    def test_different_employees_get_different_reply_to(
            self, email_env, monkeypatch):
        """Each employee's reply_to reflects their own email, not a shared one."""
        results = []

        def fake_send(to, subject, body, **kw):
            results.append(kw.get("reply_to"))
            return (True, "✅")

        monkeypatch.setattr(email_env.mcp, "_send_smtp", fake_send)

        for name, emp_email in [
            ("Jake Smith",  "jake@gmail.com"),
            ("Maria Lopez", "maria@company.com"),
            ("Sam Chen",    "sam@outlook.com"),
        ]:
            user = _make_field_crew(name=name, email=emp_email)
            ctx  = _make_ctx(user)
            email_env.mcp.send_email(
                to="cust@example.com", subject="s", body="b", ctx=ctx)

        assert "jake@gmail.com"   in results[0]
        assert "maria@company.com" in results[1]
        assert "sam@outlook.com"  in results[2]

    def test_send_email_succeeds_end_to_end_with_real_smtp_mock(
            self, email_env):
        """Full end-to-end: field_crew send_email goes through _send_smtp
        with the right headers — no monkeypatching of _send_smtp itself."""
        smtp = _FakeSmtp()
        user = _make_field_crew(name="Jake Smith", email="jake@gmail.com")
        ctx  = _make_ctx(user)

        # Patch _send_email_cap to allow field_crew through
        with patch.object(
            email_env.mcp, "_send_email_cap",
            return_value=(True, "allowed")
        ), patch("smtplib.SMTP", smtp):
            result = email_env.mcp.send_email(
                to="customer@example.com",
                subject="Window cleaning complete",
                body="Hi, this is Jake. Your windows are done.",
                ctx=ctx)

        assert "✅" in result
        assert smtp.sent, "No message was sent"
        msg = _parse_msg(smtp.sent[0][2])

        assert "jake@gmail.com" in msg["Reply-To"]
        assert "Jake Smith"     in msg["From"]
        assert "ABC Window Cleaning" in msg["From"]
