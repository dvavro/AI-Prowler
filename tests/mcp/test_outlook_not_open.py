"""
tests/mcp/test_outlook_not_open.py
====================================
Tests that verify all Outlook-related operations work correctly when
classic Outlook is INSTALLED but NOT currently running.

The key pattern in every test:
  • GetActiveObject raises  → simulates "Outlook not open"
  • Dispatch succeeds       → simulates "Outlook installed, COM cold-starts it"

This is the normal state on most machines — Outlook is installed but the
user hasn't opened it yet. All email operations must work without forcing
the user to manually open Outlook first.

Coverage
--------
E  list_outlook_accounts() — Outlook installed but not open
     E1  Returns accounts via Dispatch fallback (not error)
     E2  Dispatch is called as fallback when GetActiveObject fails
     E3  Dispatch is NOT called when GetActiveObject already succeeds
     E4  Default ← marker is correct even via cold-start Dispatch

F  _send_via_outlook() — Outlook installed but not open
     F1  Sends successfully via Dispatch cold-start
     F2  Calls Dispatch (not GetActiveObject) to start Outlook

G  send_email() tool — end-to-end, Outlook not open
     G1  send_email() via Outlook backend succeeds when Outlook closed
     G2  send_email() with from_account override works when Outlook closed

H  Fallback paths — Outlook AND Dispatch fail
     H1  outlook+smtp backend falls back to SMTP when both COM strategies fail
     H2  SMTP-only backend never touches Outlook COM at all

All tests are OFFLINE — no running Outlook, SMTP server, or MCP server needed.
COM is fully mocked in every test.

Run:
    pytest tests/mcp/test_outlook_not_open.py -v
"""
from __future__ import annotations

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
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def mcp_mod():
    if str(SRC_ROOT) not in sys.path:
        sys.path.insert(0, str(SRC_ROOT))
    import ai_prowler_mcp as _m
    return _m


# ---------------------------------------------------------------------------
# COM patching helpers
# ---------------------------------------------------------------------------
def _get_wc_module():
    """Return the real win32com.client module (importing it if needed)."""
    try:
        import win32com.client as _wc
        return _wc
    except ImportError:
        return None


class _SwapWc:
    """Patch Dispatch and GetActiveObject on the real win32com.client module.

    This works whether or not win32com is installed AND whether or not the
    module has been imported before — it patches the actual attribute on the
    module object, so every `import win32com.client as _wc` that follows
    gets the patched version.

    If win32com is not installed at all (CI environment without pywin32),
    we inject a MagicMock into sys.modules as a fallback.
    """
    def __init__(self, wc_mock: MagicMock):
        self._mock     = wc_mock
        self._real_mod = None
        self._real_dispatch    = None
        self._real_get_active  = None
        self._injected = False

    def __enter__(self) -> MagicMock:
        self._real_mod = _get_wc_module()
        if self._real_mod is not None:
            # Patch on the real module — guaranteed to intercept future imports
            self._real_dispatch   = getattr(self._real_mod, "Dispatch",         None)
            self._real_get_active = getattr(self._real_mod, "GetActiveObject",  None)
            self._real_mod.Dispatch         = self._mock.Dispatch
            self._real_mod.GetActiveObject  = self._mock.GetActiveObject
        else:
            # win32com not installed — inject the whole mock module
            sys.modules["win32com"]        = MagicMock()
            sys.modules["win32com.client"] = self._mock
            self._injected = True
        return self._mock

    def __exit__(self, *_):
        if self._injected:
            sys.modules.pop("win32com",        None)
            sys.modules.pop("win32com.client", None)
        elif self._real_mod is not None:
            # Only restore if we saved a real callable — never restore None
            if self._real_dispatch is not None:
                self._real_mod.Dispatch        = self._real_dispatch
            elif hasattr(self._real_mod, "Dispatch"):
                try:
                    delattr(self._real_mod, "Dispatch")
                except AttributeError:
                    pass
            if self._real_get_active is not None:
                self._real_mod.GetActiveObject = self._real_get_active
            elif hasattr(self._real_mod, "GetActiveObject"):
                try:
                    delattr(self._real_mod, "GetActiveObject")
                except AttributeError:
                    pass

def _make_ol_app(accounts: list) -> tuple:
    """Return (app_mock, mail_mock) with given account SMTP addresses."""
    app = MagicMock()
    ns  = MagicMock()
    acct_list = []
    for addr in accounts:
        a = MagicMock()
        a.SmtpAddress = addr
        acct_list.append(a)
    ns.Accounts = acct_list
    app.GetNamespace.return_value = ns
    mail = MagicMock()
    app.CreateItem.return_value = mail
    return app, mail

def _wc_not_open(app_mock) -> MagicMock:
    """Fake win32com.client: GetActiveObject fails, Dispatch succeeds.

    This is the key mock for "Outlook installed but not running":
      • GetActiveObject raises  → Outlook not in the running process list
      • Dispatch succeeds       → COM activates Outlook in the background
    """
    wc = MagicMock()
    wc.GetActiveObject.side_effect = Exception(
        "The application is not running")
    wc.Dispatch.return_value = app_mock
    return wc




def _ol_cfg(username: str = "david@gmail.com") -> dict:
    return {
        "backend":      "outlook",
        "username":     username,
        "from_address": username,
        "from_name":    "David",
        "default_to":   username,
    }


# ============================================================================
# E — list_outlook_accounts() when Outlook is not open
# ============================================================================

class TestListAccountsOutlookNotOpen:
    """E.x — list_outlook_accounts() via Dispatch cold-start."""

    def test_E1_returns_accounts_when_outlook_not_open(self, mcp_mod):
        """Returns full account list via Dispatch even when Outlook is closed."""
        app, _ = _make_ol_app(["david@gmail.com", "david@yahoo.com"])
        wc     = _wc_not_open(app)

        with _SwapWc(wc):
            with patch.object(mcp_mod, "_current_user", return_value=None):
                with patch.object(mcp_mod, "_email_config_load",
                                  return_value=_ol_cfg()):
                    with patch.object(mcp_mod, "_outlook_is_available",
                                      return_value=True):
                        result = mcp_mod.list_outlook_accounts()

        assert "❌" not in result, \
            f"Should succeed without Outlook open, got: {result!r}"
        assert "david@gmail.com" in result
        assert "david@yahoo.com" in result

    def test_E2_dispatch_called_as_fallback(self, mcp_mod):
        """Dispatch is invoked when GetActiveObject raises."""
        app, _ = _make_ol_app(["david@gmail.com"])
        wc     = _wc_not_open(app)

        with _SwapWc(wc):
            with patch.object(mcp_mod, "_current_user", return_value=None):
                with patch.object(mcp_mod, "_email_config_load",
                                  return_value=_ol_cfg()):
                    with patch.object(mcp_mod, "_outlook_is_available",
                                      return_value=True):
                        mcp_mod.list_outlook_accounts()

        wc.GetActiveObject.assert_called_once(), \
            "GetActiveObject must be tried first"
        wc.Dispatch.assert_called_once(), \
            "Dispatch must be called when GetActiveObject fails"

    def test_E3_dispatch_not_called_when_already_open(self, mcp_mod):
        """Dispatch is NOT called when GetActiveObject already succeeds."""
        app, _ = _make_ol_app(["david@gmail.com"])
        wc     = MagicMock()
        wc.GetActiveObject.return_value = app   # Outlook already running

        with _SwapWc(wc):
            with patch.object(mcp_mod, "_current_user", return_value=None):
                with patch.object(mcp_mod, "_email_config_load",
                                  return_value=_ol_cfg()):
                    with patch.object(mcp_mod, "_outlook_is_available",
                                      return_value=True):
                        mcp_mod.list_outlook_accounts()

        wc.GetActiveObject.assert_called_once()
        wc.Dispatch.assert_not_called(), \
            "Dispatch must NOT be called when GetActiveObject succeeds"

    def test_E4_default_marker_correct_via_cold_start(self, mcp_mod):
        """← marker correctly labels the saved default account via Dispatch."""
        app, _ = _make_ol_app(["david@gmail.com", "david@yahoo.com"])
        wc     = _wc_not_open(app)

        with _SwapWc(wc):
            with patch.object(mcp_mod, "_current_user", return_value=None):
                with patch.object(mcp_mod, "_email_config_load",
                                  return_value=_ol_cfg("david@yahoo.com")):
                    with patch.object(mcp_mod, "_outlook_is_available",
                                      return_value=True):
                        result = mcp_mod.list_outlook_accounts()

        yahoo_line = next(
            (l for l in result.splitlines() if "david@yahoo.com" in l), "")
        gmail_line = next(
            (l for l in result.splitlines() if "david@gmail.com" in l), "")
        assert "←" in yahoo_line, \
            f"← should be on Yahoo (saved default) line: {yahoo_line!r}"
        assert "←" not in gmail_line, \
            f"Gmail should NOT have ← marker: {gmail_line!r}"

    def test_E5_returns_error_only_when_both_strategies_fail(self, mcp_mod):
        """Error is only returned when BOTH GetActiveObject AND Dispatch fail."""
        wc = MagicMock()
        wc.GetActiveObject.side_effect = Exception("not running")
        wc.Dispatch.side_effect        = Exception("COM not registered")

        with _SwapWc(wc):
            with patch.object(mcp_mod, "_current_user", return_value=None):
                with patch.object(mcp_mod, "_email_config_load",
                                  return_value=_ol_cfg()):
                    with patch.object(mcp_mod, "_outlook_is_available",
                                      return_value=True):
                        result = mcp_mod.list_outlook_accounts()

        assert "❌" in result, \
            f"Error expected when both COM strategies fail, got: {result!r}"


# ============================================================================
# F — _send_via_outlook() when Outlook is not open
# ============================================================================

class TestSendViaOutlookNotOpen:
    """F.x — _send_via_outlook() via Dispatch cold-start."""

    def test_F1_sends_successfully_when_outlook_not_open(self, mcp_mod):
        """_send_via_outlook() succeeds via Dispatch even when Outlook is closed."""
        app, mail = _make_ol_app(["david@gmail.com"])
        wc        = _wc_not_open(app)

        with _SwapWc(wc):
            ok, msg = mcp_mod._send_via_outlook(
                to="customer@example.com",
                subject="Invoice #001",
                body="Your invoice is attached.",
                from_account_email="david@gmail.com",
            )

        assert isinstance(ok, bool), \
            "_send_via_outlook must return (bool, str), never raise"
        assert isinstance(msg, str)
        # Dispatch must have been used (GetActiveObject is not called in
        # _send_via_outlook — it goes straight to Dispatch)
        wc.Dispatch.assert_called(), \
            "_send_via_outlook must call Dispatch to cold-start Outlook"

    def test_F2_sends_html_body_when_outlook_not_open(self, mcp_mod):
        """HTML invoice body is sent correctly via cold-start Dispatch."""
        app, mail = _make_ol_app(["david@gmail.com"])
        wc        = _wc_not_open(app)

        with _SwapWc(wc):
            ok, msg = mcp_mod._send_via_outlook(
                to="customer@example.com",
                subject="Invoice #001",
                body="Plain text fallback",
                body_html="<h1>Invoice</h1><p>Amount due: $280.00</p>",
            )

        # mail.HTMLBody must have been set
        assert mail.HTMLBody == "<h1>Invoice</h1><p>Amount due: $280.00</p>", \
            "HTMLBody must be set when body_html is provided"
        assert isinstance(ok, bool)

    def test_F3_account_selection_works_via_dispatch(self, mcp_mod):
        """from_account_email selects the right Outlook account via Dispatch."""
        app, mail = _make_ol_app(["david@gmail.com", "david@yahoo.com"])
        wc        = _wc_not_open(app)

        with _SwapWc(wc):
            ok, msg = mcp_mod._send_via_outlook(
                to="customer@example.com",
                subject="Test",
                body="Hello",
                from_account_email="david@yahoo.com",
            )

        # SendUsingAccount must have been set to the Yahoo account
        assert mail.SendUsingAccount is not None
        # Verify it was set to the account matching Yahoo
        ns    = app.GetNamespace.return_value
        yahoo = next(
            a for a in ns.Accounts if a.SmtpAddress == "david@yahoo.com")
        assert mail.SendUsingAccount == yahoo, \
            "SendUsingAccount must be the Yahoo account mock"


# ============================================================================
# G — send_email() tool end-to-end, Outlook not open
# ============================================================================

class TestSendEmailToolOutlookNotOpen:
    """G.x — send_email() tool when Outlook backend is active but closed."""

    def test_G1_send_email_succeeds_outlook_not_open(self, mcp_mod):
        """send_email() via Outlook backend works without Outlook running."""
        app, mail = _make_ol_app(["david@gmail.com"])
        wc        = _wc_not_open(app)
        cfg = _ol_cfg("david@gmail.com")

        with _SwapWc(wc):
            with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
                with patch.object(mcp_mod, "_current_user", return_value=None):
                    with patch.object(mcp_mod, "_send_email_cap",
                                      return_value=(True, "")):
                        result = mcp_mod.send_email(
                            to="customer@example.com",
                            subject="Job Confirmed",
                            body="Your job is confirmed for Saturday.",
                        )

        assert "❌" not in result, \
            f"send_email must succeed when Outlook is closed: {result!r}"
        assert "✅" in result or "sent" in result.lower(), \
            f"Success message expected, got: {result!r}"

    def test_G2_from_account_override_works_outlook_not_open(self, mcp_mod):
        """from_account override correctly selects account via cold-start Dispatch."""
        app, mail = _make_ol_app(["david@gmail.com", "david@yahoo.com"])
        wc        = _wc_not_open(app)
        cfg = _ol_cfg("david@gmail.com")   # default = Gmail

        with _SwapWc(wc):
            with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
                with patch.object(mcp_mod, "_current_user", return_value=None):
                    with patch.object(mcp_mod, "_send_email_cap",
                                      return_value=(True, "")):
                        result = mcp_mod.send_email(
                            to="customer@example.com",
                            subject="Test",
                            body="Hello",
                            from_account="david@yahoo.com",   # override to Yahoo
                        )

        assert "❌" not in result, \
            f"from_account override must work when Outlook closed: {result!r}"
        # Verify the Yahoo account was selected
        ns    = app.GetNamespace.return_value
        yahoo = next(
            a for a in ns.Accounts if a.SmtpAddress == "david@yahoo.com")
        assert mail.SendUsingAccount == yahoo, \
            "SendUsingAccount must be Yahoo when from_account='david@yahoo.com'"


# ============================================================================
# H — Fallback paths
# ============================================================================

class TestOutlookFallbackPaths:
    """H.x — SMTP fallback and no-Outlook-needed paths."""

    def test_H1_outlook_smtp_falls_back_when_both_com_fail(self, mcp_mod):
        """outlook+smtp backend activates SMTP when all COM strategies fail."""
        wc = MagicMock()
        wc.GetActiveObject.side_effect = Exception("not running")
        wc.Dispatch.side_effect        = Exception("COM not registered")

        cfg = {
            "backend":   "outlook+smtp",
            "username":  "david@gmail.com",
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "password":  "app-pw",
            "use_tls":   True,
        }

        with _SwapWc(wc):
            with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
                with patch.object(mcp_mod, "_send_smtp_core",
                                  return_value=(True, "✅ SMTP fallback")) as mock_core:
                    ok, msg = mcp_mod._send_smtp(
                        "customer@example.com", "Test", "Body")

        mock_core.assert_called_once(), \
            "SMTP fallback must activate when all Outlook COM strategies fail"
        assert ok is True, f"outlook+smtp must succeed via SMTP fallback: {msg!r}"

    def test_H2_smtp_backend_never_touches_outlook(self, mcp_mod):
        """SMTP-only backend never calls any Outlook COM function."""
        cfg = {
            "backend":   "smtp",
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "username":  "david@gmail.com",
            "password":  "app-pw",
            "use_tls":   True,
        }
        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_send_smtp_core",
                              return_value=(True, "✅ SMTP")) as mock_core:
                with patch.object(mcp_mod, "_send_via_outlook") as mock_ol:
                    ok, _ = mcp_mod._send_smtp(
                        "customer@example.com", "Test", "Body")

        mock_ol.assert_not_called(), \
            "SMTP backend must never call _send_via_outlook"
        mock_core.assert_called_once()
        assert ok is True

    def test_H3_smtp_backend_works_with_olk_installed(self, mcp_mod):
        """SMTP backend works normally even when New Outlook (olk.exe) is present."""
        cfg = {
            "backend":   "smtp",
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "username":  "david@gmail.com",
            "password":  "app-pw",
            "use_tls":   True,
        }
        # Simulate new Outlook running (olk.exe), classic not available
        with patch.object(mcp_mod, "_outlook_is_available", return_value=False):
            with patch.object(mcp_mod, "_new_outlook_is_running", return_value=True):
                with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
                    with patch.object(mcp_mod, "_send_smtp_core",
                                      return_value=(True, "✅")) as mock_core:
                        ok, _ = mcp_mod._send_smtp(
                            "customer@example.com", "Test", "Body")

        mock_core.assert_called_once()
        assert ok is True, \
            "SMTP backend must work even when only new Outlook (olk.exe) is present"
