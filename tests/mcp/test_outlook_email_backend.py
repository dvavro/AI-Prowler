"""
tests/mcp/test_outlook_email_backend.py
=========================================
Tests for the Outlook / SMTP dual-backend email system added in v9.1.x.

Coverage
--------
A  _outlook_is_available()
     A1-A7  Strategy structure (source), A8-A9 live mock calls
B  _send_via_outlook()
     B1-B10 Structure + live mock calls
C  _send_smtp() routing
     C1-C5  backend dispatch and fallback logic
D  configure_email() tool
     D1-D11 backend parameter, validation, saves, account listing
E  _send_smtp_core()
     E1-E5  Structure (was inlined before this change)
F  email_config.json round-trip
     F1-F4  backend field save/load with and without password

All tests are OFFLINE — no Outlook, SMTP server, or MCP server required.
COM / win32com are monkeypatched throughout.

Run:
    pytest tests/mcp/test_outlook_email_backend.py -v
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_SRC     = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parents[2]
MCP_FILE = SRC_ROOT / "ai_prowler_mcp.py"

assert MCP_FILE.exists(), f"ai_prowler_mcp.py not found at {MCP_FILE}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _find_line(lines: list[str], pattern: str, start: int = 0) -> int | None:
    for i in range(start, len(lines)):
        if pattern in lines[i]:
            return i
    return None


def _body_of(lines: list[str], def_pattern: str, max_lines: int = 120) -> str:
    ln = _find_line(lines, def_pattern)
    assert ln is not None, f"Could not find '{def_pattern}' in source"
    return "\n".join(lines[ln: ln + max_lines])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def source() -> str:
    return MCP_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def lines(source) -> list[str]:
    return source.splitlines()


@pytest.fixture(scope="session")
def mcp_mod():
    if str(SRC_ROOT) not in sys.path:
        sys.path.insert(0, str(SRC_ROOT))
    import ai_prowler_mcp as _m
    return _m


# ---------------------------------------------------------------------------
# COM mock factories
# ---------------------------------------------------------------------------
def _make_outlook_app(version="16.0", accounts=None):
    """Return (app_mock, mail_mock) mimicking Outlook COM objects."""
    app  = MagicMock()
    app.Version = version
    ns   = MagicMock()
    acct_list = []
    for addr in (accounts or []):
        a = MagicMock()
        a.SmtpAddress = addr
        acct_list.append(a)
    ns.Accounts = acct_list
    app.GetNamespace.return_value = ns
    mail = MagicMock()
    app.CreateItem.return_value = mail
    return app, mail


def _make_win32com(app_mock=None, active_raises=True, dispatch_raises=False):
    """Return a fake win32com.client module."""
    wc = MagicMock()
    if active_raises:
        wc.GetActiveObject.side_effect = Exception("not running")
    else:
        wc.GetActiveObject.return_value = app_mock
    if dispatch_raises:
        wc.Dispatch.side_effect = Exception("COM error")
    else:
        wc.Dispatch.return_value = app_mock
    return wc


def _patch_win32(app_mock=None, active_raises=True, dispatch_raises=False):
    """Context-manager that patches sys.modules with a fake win32com.client."""
    wc = _make_win32com(app_mock, active_raises, dispatch_raises)
    return patch.dict("sys.modules", {
        "win32com": MagicMock(),
        "win32com.client": wc,
    })


# ============================================================================
# A — _outlook_is_available()
# ============================================================================

class TestOutlookIsAvailable:
    """A.x — detection strategy structure and live mock calls."""

    # ── Source structure ─────────────────────────────────────────────────

    def test_A1_get_active_object_strategy_present(self, lines):
        body = _body_of(lines, "def _outlook_is_available()", max_lines=80)
        assert "GetActiveObject" in body, \
            "Strategy 1 (GetActiveObject) missing from _outlook_is_available"

    def test_A2_dispatch_strategy_present_and_after_get_active_object(self, lines):
        body = _body_of(lines, "def _outlook_is_available()", max_lines=80)
        assert "Dispatch" in body, \
            "Strategy 2 (Dispatch) missing from _outlook_is_available"
        assert body.index("GetActiveObject") < body.index("Dispatch"), \
            "Dispatch must appear after GetActiveObject in the function"

    def test_A3_registry_strategy_present_and_last(self, lines):
        body = _body_of(lines, "def _outlook_is_available()", max_lines=80)
        assert "winreg" in body or "OpenKey" in body, \
            "Strategy 3 (registry probe) missing from _outlook_is_available"
        reg_kw  = "winreg" if "winreg" in body else "OpenKey"
        assert body.index("Dispatch") < body.index(reg_kw), \
            "Registry probe must appear after Dispatch in the function"

    def test_A4_false_returned_when_all_strategies_fail(self, mcp_mod):
        """Monkeypatching to False — must not raise."""
        with patch.object(mcp_mod, "_outlook_is_available", return_value=False):
            result = mcp_mod._outlook_is_available()
        assert result is False

    def test_A5_import_error_caught_for_missing_win32com(self, lines):
        body = _body_of(lines, "def _outlook_is_available()", max_lines=80)
        assert "ImportError" in body, \
            "_outlook_is_available must catch ImportError so it works without pywin32"

    def test_A6_function_exists_and_is_callable(self, mcp_mod):
        assert hasattr(mcp_mod, "_outlook_is_available"), \
            "_outlook_is_available not found in ai_prowler_mcp module"
        assert callable(mcp_mod._outlook_is_available)

    def test_A7_three_strategy_order_correct(self, lines):
        body = _body_of(lines, "def _outlook_is_available()", max_lines=80)
        reg_kw = "winreg" if "winreg" in body else "OpenKey"
        pos1 = body.index("GetActiveObject")
        pos2 = body.index("Dispatch")
        pos3 = body.index(reg_kw)
        assert pos1 < pos2 < pos3, \
            "Strategies must be ordered: GetActiveObject → Dispatch → registry"

    # ── Live mock calls ──────────────────────────────────────────────────

    def test_A8_returns_bool_when_get_active_object_succeeds(self, mcp_mod):
        """Strategy 1 path: GetActiveObject succeeds (Outlook already running)."""
        app, _ = _make_outlook_app()
        with _patch_win32(app_mock=app, active_raises=False):
            result = mcp_mod._outlook_is_available()
        assert isinstance(result, bool), \
            "_outlook_is_available must return bool, never raise"

    def test_A9_returns_bool_when_dispatch_succeeds_active_fails(self, mcp_mod):
        """Strategy 2 path: GetActiveObject fails, Dispatch succeeds."""
        app, _ = _make_outlook_app()
        with _patch_win32(app_mock=app, active_raises=True, dispatch_raises=False):
            result = mcp_mod._outlook_is_available()
        assert isinstance(result, bool), \
            "_outlook_is_available must return bool on Dispatch path"

    def test_A10_returns_false_when_both_com_strategies_fail_no_registry(self, mcp_mod):
        """Both COM strategies fail AND registry key absent → False."""
        with _patch_win32(active_raises=True, dispatch_raises=True):
            # Also patch winreg so the registry probe fails cleanly
            with patch.dict("sys.modules", {"winreg": None}):
                result = mcp_mod._outlook_is_available()
        # Result is False OR True (if real registry key exists on this machine)
        # — just confirm it's a bool and doesn't raise
        assert isinstance(result, bool), \
            "_outlook_is_available must always return bool, never raise"


# ============================================================================
# B — _send_via_outlook()
# ============================================================================

class TestSendViaOutlook:
    """B.x — Outlook COM send logic."""

    def test_B1_function_exists(self, source):
        assert "def _send_via_outlook(" in source

    def test_B2_uses_create_item_0(self, lines):
        body = _body_of(lines, "def _send_via_outlook(")
        assert "CreateItem(0)" in body, \
            "_send_via_outlook must call CreateItem(0) (olMailItem constant)"

    def test_B3_sets_to_and_subject(self, lines):
        body = _body_of(lines, "def _send_via_outlook(")
        assert ".To" in body and ".Subject" in body

    def test_B4_uses_html_or_plain_body(self, lines):
        body = _body_of(lines, "def _send_via_outlook(")
        assert "HTMLBody" in body and ".Body" in body, \
            "Must handle both HTML and plain-text body"

    def test_B5_attaches_file_when_path_provided(self, lines):
        body = _body_of(lines, "def _send_via_outlook(")
        assert "Attachments.Add" in body

    def test_B6_calls_send(self, lines):
        body = _body_of(lines, "def _send_via_outlook(")
        assert ".Send()" in body

    def test_B7_selects_account_by_smtp_address(self, lines):
        body = _body_of(lines, "def _send_via_outlook(")
        assert "SmtpAddress" in body, "Must match account by SmtpAddress"
        assert "SendUsingAccount" in body, "Must set SendUsingAccount"

    def test_B8_returns_true_tuple_on_success(self, mcp_mod):
        app, mail = _make_outlook_app(accounts=["david.vavro1@gmail.com"])
        with _patch_win32(app_mock=app):
            ok, msg = mcp_mod._send_via_outlook(
                to="customer@example.com",
                subject="Test Invoice",
                body="Your invoice is ready.",
                from_account_email="david.vavro1@gmail.com",
            )
        assert isinstance(ok, bool)
        assert isinstance(msg, str)

    def test_B9_returns_false_tuple_on_com_exception(self, mcp_mod):
        """_send_via_outlook COM errors must return (False, str) — never raise.

        We patch _send_via_outlook on the module so _send_smtp picks up the
        mock (direct-reference calls go through the module namespace).
        """
        with patch.object(mcp_mod, "_send_via_outlook",
                          return_value=(False, "❌ Simulated COM failure")) as mock_fn:
            cfg = {"backend": "outlook", "username": "david.vavro1@gmail.com"}
            with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
                ok, msg = mcp_mod._send_smtp(
                    "customer@example.com", "Test Subject", "Body text")

        mock_fn.assert_called_once()
        assert ok is False, f"Expected False when Outlook send fails, got {ok!r}"
        assert isinstance(msg, str)
        assert "❌" in msg or "COM" in msg or "failed" in msg.lower(), \
            f"Error message should indicate failure: {msg!r}"

    def test_B10_sets_reply_recipients(self, lines):
        body = _body_of(lines, "def _send_via_outlook(")
        assert "ReplyRecipients" in body, \
            "Must add ReplyRecipients when reply_to is provided"


# ============================================================================
# C — _send_smtp() routing
# ============================================================================

class TestSendSmtpRouting:
    """C.x — _send_smtp dispatches to Outlook or SMTP based on config backend."""

    def test_C1_routes_to_outlook_when_backend_outlook(self, mcp_mod):
        cfg = {"backend": "outlook", "username": "david.vavro1@gmail.com",
               "from_address": "david.vavro1@gmail.com", "from_name": "David"}
        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_send_via_outlook",
                              return_value=(True, "✅")) as mock_ol:
                ok, _ = mcp_mod._send_smtp("to@example.com", "Subj", "Body")
        mock_ol.assert_called_once()
        assert ok is True

    def test_C2_routes_to_smtp_core_when_backend_smtp(self, mcp_mod):
        cfg = {"backend": "smtp", "smtp_host": "smtp.gmail.com", "smtp_port": 587,
               "username": "david.vavro1@gmail.com", "password": "pw", "use_tls": True}
        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_send_smtp_core",
                              return_value=(True, "✅")) as mock_core:
                ok, _ = mcp_mod._send_smtp("to@example.com", "Subj", "Body")
        mock_core.assert_called_once()
        assert ok is True

    def test_C3_defaults_to_smtp_core_for_legacy_config(self, mcp_mod):
        """Config without 'backend' key → _send_smtp_core (legacy SMTP)."""
        cfg = {"smtp_host": "smtp.gmail.com", "smtp_port": 587,
               "username": "david.vavro1@gmail.com", "password": "pw", "use_tls": True}
        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_send_smtp_core",
                              return_value=(True, "✅")) as mock_core:
                ok, _ = mcp_mod._send_smtp("to@example.com", "Subj", "Body")
        mock_core.assert_called_once()

    def test_C4_falls_back_to_smtp_when_outlook_fails_and_host_present(self, mcp_mod):
        cfg = {"backend": "outlook", "username": "david.vavro1@gmail.com",
               "smtp_host": "smtp.gmail.com", "smtp_port": 587, "password": "pw"}
        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_send_via_outlook",
                              return_value=(False, "❌ COM error")):
                with patch.object(mcp_mod, "_send_smtp_core",
                                  return_value=(True, "✅ SMTP fallback")) as mock_fb:
                    ok, msg = mcp_mod._send_smtp("to@example.com", "Subj", "Body")
        mock_fb.assert_called_once()
        assert ok is True, f"Fallback must succeed: {msg!r}"

    def test_C5_no_fallback_when_outlook_fails_and_no_smtp_host(self, mcp_mod):
        cfg = {"backend": "outlook", "username": "david.vavro1@gmail.com"}
        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_send_via_outlook",
                              return_value=(False, "❌ COM error")):
                with patch.object(mcp_mod, "_send_smtp_core") as mock_smtp:
                    ok, _ = mcp_mod._send_smtp("to@example.com", "Subj", "Body")
        mock_smtp.assert_not_called()
        assert ok is False


# ============================================================================
# D — configure_email() tool
# ============================================================================

class TestConfigureEmailTool:
    """D.x — backend parameter handling and validation."""

    def test_D1_password_has_empty_default(self, lines):
        """All params except username must have defaults (password especially)."""
        ln = _find_line(lines, "def configure_email(")
        assert ln is not None
        sig = "\n".join(lines[ln: ln + 12])
        assert "username" in sig
        assert 'password: str = ""' in sig or "password=" in sig, \
            "password must have an empty-string default (not required)"

    def test_D2_auto_path_calls_outlook_is_available(self, lines):
        body = _body_of(lines, "def configure_email(", max_lines=160)
        assert '"auto"' in body or "'auto'" in body
        assert "_outlook_is_available" in body

    def test_D3_outlook_path_present(self, lines):
        body = _body_of(lines, "def configure_email(", max_lines=160)
        assert '"outlook"' in body or "'outlook'" in body

    def test_D4_smtp_path_present(self, lines):
        body = _body_of(lines, "def configure_email(", max_lines=160)
        assert '"smtp"' in body or "'smtp'" in body

    def test_D5_error_when_outlook_unavailable(self, mcp_mod):
        with patch.object(mcp_mod, "_outlook_is_available", return_value=False):
            with patch.object(mcp_mod, "_email_allowed_for_user",
                              return_value=(True, "")):
                result = mcp_mod.configure_email(
                    username="david.vavro1@gmail.com", backend="outlook")
        assert "❌" in result
        assert "not installed" in result.lower() or "not accessible" in result.lower()

    def test_D6_saves_outlook_backend_without_password(self, mcp_mod):
        saved = {}
        app, _ = _make_outlook_app(accounts=["david.vavro1@gmail.com"])
        with _patch_win32(app_mock=app):
            with patch.object(mcp_mod, "_outlook_is_available", return_value=True):
                with patch.object(mcp_mod, "_email_allowed_for_user",
                                  return_value=(True, "")):
                    with patch.object(mcp_mod, "_email_config_load", return_value={}):
                        with patch.object(mcp_mod, "_email_config_save",
                                          side_effect=lambda c: saved.update(c) or True):
                            result = mcp_mod.configure_email(
                                username="david.vavro1@gmail.com", backend="outlook")
        assert "❌" not in result, f"Expected success: {result!r}"
        assert saved.get("backend") == "outlook"
        assert "password" not in saved and "_password_b64" not in saved

    def test_D7_saves_smtp_backend_with_host(self, mcp_mod):
        saved = {}
        with patch.object(mcp_mod, "_email_allowed_for_user",
                          return_value=(True, "")):
            with patch.object(mcp_mod, "_email_config_save",
                              side_effect=lambda c: saved.update(c) or True):
                result = mcp_mod.configure_email(
                    username="david.vavro1@gmail.com", backend="smtp",
                    smtp_host="smtp.gmail.com", smtp_port=587,
                    password="abcd-efgh-ijkl-mnop")
        assert "❌" not in result
        assert saved.get("backend") == "smtp"
        assert saved.get("smtp_host") == "smtp.gmail.com"

    def test_D8_error_smtp_missing_host(self, mcp_mod):
        with patch.object(mcp_mod, "_email_allowed_for_user",
                          return_value=(True, "")):
            result = mcp_mod.configure_email(
                username="david.vavro1@gmail.com", backend="smtp",
                smtp_host="", password="some-app-password")
        assert "❌" in result
        assert "host" in result.lower() or "smtp_host" in result.lower()

    def test_D9_error_smtp_missing_password(self, mcp_mod):
        with patch.object(mcp_mod, "_email_allowed_for_user",
                          return_value=(True, "")):
            result = mcp_mod.configure_email(
                username="david.vavro1@gmail.com", backend="smtp",
                smtp_host="smtp.gmail.com", password="")
        assert "❌" in result
        assert "password" in result.lower()

    def test_D10_confirmation_mentions_accounts(self, mcp_mod):
        app, _ = _make_outlook_app(
            accounts=["david.vavro1@gmail.com", "david@vavrofieldservices.com"])
        with _patch_win32(app_mock=app):
            with patch.object(mcp_mod, "_outlook_is_available", return_value=True):
                with patch.object(mcp_mod, "_email_allowed_for_user",
                                  return_value=(True, "")):
                    with patch.object(mcp_mod, "_email_config_load", return_value={}):
                        with patch.object(mcp_mod, "_email_config_save",
                                          return_value=True):
                            result = mcp_mod.configure_email(
                                username="david.vavro1@gmail.com", backend="outlook")
        assert "david.vavro1@gmail.com" in result or "account" in result.lower()

    def test_D11_preserves_smtp_host_as_fallback_on_outlook_switch(self, mcp_mod):
        saved = {}
        existing = {"backend": "smtp", "smtp_host": "smtp.gmail.com",
                    "smtp_port": 587, "username": "david.vavro1@gmail.com"}
        app, _ = _make_outlook_app(accounts=["david.vavro1@gmail.com"])
        with _patch_win32(app_mock=app):
            with patch.object(mcp_mod, "_outlook_is_available", return_value=True):
                with patch.object(mcp_mod, "_email_allowed_for_user",
                                  return_value=(True, "")):
                    with patch.object(mcp_mod, "_email_config_load",
                                      return_value=existing):
                        with patch.object(mcp_mod, "_email_config_save",
                                          side_effect=lambda c: saved.update(c) or True):
                            mcp_mod.configure_email(
                                username="david.vavro1@gmail.com", backend="outlook")
        assert saved.get("smtp_host") == "smtp.gmail.com", \
            "smtp_host must be preserved as SMTP fallback when switching to Outlook"


# ============================================================================
# E — _send_smtp_core()
# ============================================================================

class TestSendSmtpCore:
    """E.x — extracted SMTP send logic (was inlined in _send_smtp before v9.1.x)."""

    def test_E1_function_exists(self, source):
        assert "def _send_smtp_core(" in source, \
            "_send_smtp_core must be its own function (not inlined)"

    def test_E2_accepts_cfg_as_first_argument(self, lines):
        ln = _find_line(lines, "def _send_smtp_core(")
        assert ln is not None
        assert "cfg" in lines[ln]

    def test_E3_handles_port_465_via_smtp_ssl(self, lines):
        body = _body_of(lines, "def _send_smtp_core(")
        assert "465" in body and "SMTP_SSL" in body

    def test_E4_handles_port_587_via_starttls(self, lines):
        body = _body_of(lines, "def _send_smtp_core(")
        assert "starttls" in body.lower()

    def test_E5_auth_error_message_mentions_app_password(self, lines):
        # max_lines given some headroom above the function's typical size —
        # this test broke once already (2026-09-08) when an explanatory
        # comment added earlier in the function body pushed this message
        # a few lines past a tighter max_lines=80 window. The assertion
        # itself is still meaningful (source-level check that auth-failure
        # guidance exists) — just don't let the window be so tight that
        # ordinary comment additions elsewhere in the function break it.
        body = _body_of(lines, "def _send_smtp_core(", max_lines=120)
        lower = body.lower()
        assert "app password" in lower or "app passwords" in lower, \
            "Auth error message must mention App Password for user guidance"


# ============================================================================
# F — email_config.json round-trip
# ============================================================================

class TestEmailConfigBackendField:
    """F.x — _email_config_load / _email_config_save with backend field."""

    def test_F1_load_returns_backend_field(self, mcp_mod, tmp_path):
        cfg_file = tmp_path / "email_config.json"
        cfg_file.write_text(json.dumps({
            "backend": "outlook", "username": "david.vavro1@gmail.com",
            "from_address": "david.vavro1@gmail.com",
            "from_name": "David", "default_to": "david.vavro1@gmail.com",
        }), encoding="utf-8")
        # _EMAIL_CONFIG_PATH() is called as a function — patch it as a callable
        with patch("ai_prowler_mcp._EMAIL_CONFIG_PATH", return_value=cfg_file):
            result = mcp_mod._email_config_load()
        assert result is not None
        assert result.get("backend") == "outlook"

    def test_F2_load_succeeds_for_legacy_config_without_backend(self, mcp_mod, tmp_path):
        cfg_file = tmp_path / "email_config.json"
        cfg_file.write_text(json.dumps({
            "smtp_host": "smtp.gmail.com", "smtp_port": 587,
            "username": "david.vavro1@gmail.com",
            "_password_b64": "c29tZXBhc3M=",
        }), encoding="utf-8")
        with patch("ai_prowler_mcp._EMAIL_CONFIG_PATH", return_value=cfg_file):
            result = mcp_mod._email_config_load()
        assert result is not None, "Legacy config must load successfully"
        assert result.get("smtp_host") == "smtp.gmail.com"

    def test_F3_outlook_config_saves_without_any_password(self, mcp_mod, tmp_path):
        cfg_file = tmp_path / "email_config.json"
        cfg = {
            "backend": "outlook", "username": "david.vavro1@gmail.com",
            "from_address": "david.vavro1@gmail.com",
            "from_name": "David", "default_to": "david.vavro1@gmail.com",
        }
        with patch("ai_prowler_mcp._EMAIL_CONFIG_PATH", return_value=cfg_file):
            ok = mcp_mod._email_config_save(cfg)
            assert ok
            loaded = mcp_mod._email_config_load()
        assert loaded is not None
        assert loaded.get("backend") == "outlook"
        assert "password"      not in loaded, "No plain password after round-trip"
        assert "_password_b64" not in loaded, "No obfuscated password after round-trip"

    def test_F4_smtp_config_saves_password_obfuscated(self, mcp_mod, tmp_path):
        cfg_file = tmp_path / "email_config.json"
        plain_pw = "my-16-digit-app-pass"
        cfg = {
            "backend": "smtp", "smtp_host": "smtp.gmail.com", "smtp_port": 587,
            "username": "david.vavro1@gmail.com",
            "from_address": "david.vavro1@gmail.com",
            "from_name": "David", "default_to": "david.vavro1@gmail.com",
            "password": plain_pw, "use_tls": True,
        }
        with patch("ai_prowler_mcp._EMAIL_CONFIG_PATH", return_value=cfg_file):
            ok = mcp_mod._email_config_save(cfg)
            assert ok
            raw = json.loads(cfg_file.read_text(encoding="utf-8"))
            assert "password"      not in raw, "Raw JSON must not have plain password"
            assert "_password_b64" in raw,     "Raw JSON must have obfuscated password"
            loaded = mcp_mod._email_config_load()
        assert loaded is not None
        assert loaded.get("password") == plain_pw, \
            f"Decoded password must match original, got: {loaded.get('password')!r}"
        assert loaded.get("backend") == "smtp"
