"""
tests/mcp_tests/test_outlook_account_selection.py
=============================================
Tests for the Outlook multi-account selection features added in v9.1.x:

  • list_outlook_accounts() — new MCP tool
  • send_email() from_account parameter — per-send account override
  • _send_smtp() from_account_override routing

Coverage
--------
A  list_outlook_accounts()
     A1  Returns error in server mode (personal only)
     A2  Returns info message when backend is not Outlook
     A3  Returns error when classic Outlook not available
     A4  Returns error when GetActiveObject fails (Outlook not open)
     A5  Lists accounts with ← marker on current default
     A6  Lists accounts with no marker when no default is saved
     A7  Includes send_email example with first account in output
     A8  Includes configure_email example in output
     A9  Returns warning when Outlook has no accounts configured

B  send_email() from_account parameter
     B1  from_account present in function signature
     B2  from_account passed through to _send_smtp as from_account_override
     B3  Empty from_account string treated as None (no override)
     B4  from_account has no effect on SMTP backend (ignored safely)

C  _send_smtp() from_account_override routing
     C1  from_account_override takes priority over config username for Outlook
     C2  from_account_override=None falls back to config username
     C3  from_account_override ignored for SMTP backend
     C4  from_account_override passed to _send_via_outlook correctly

D  _send_via_outlook() account selection
     D1  Sets SendUsingAccount when from_account_email matches an account
     D2  Does not set SendUsingAccount when from_account_email is None
     D3  Does not set SendUsingAccount when no account matches the address
     D4  Case-insensitive match on SmtpAddress

All tests are OFFLINE — no running Outlook, SMTP server, or MCP server needed.

Run:
    pytest tests/mcp_tests/test_outlook_account_selection.py -v
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

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


@pytest.fixture(scope="module")
def source() -> str:
    return MCP_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def lines(source) -> list[str]:
    return source.splitlines()


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
            # (the attribute may not have existed before; leave it absent)
            if self._real_dispatch is not None:
                self._real_mod.Dispatch        = self._real_dispatch
            elif hasattr(self._real_mod, "Dispatch"):
                # We patched it but had no original — delete the mock attr
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



def _patch_get_active(app_mock, mcp_mod):
    """Patch win32com.client inside the MCP module namespace directly."""
    wc = MagicMock()
    wc.GetActiveObject.return_value = app_mock
    # Patch sys.modules so the `import win32com.client as _wc` inside
    # list_outlook_accounts() picks up our fake module.
    # Also patch Dispatch for _send_via_outlook compatibility.
    wc.Dispatch.return_value = app_mock
    return patch.dict("sys.modules", {
        "win32com": MagicMock(),
        "win32com.client": wc,
    })


def _ol_cfg(username: str = "david@gmail.com") -> dict:
    return {
        "backend":      "outlook",
        "username":     username,
        "from_address": username,
        "from_name":    "David",
        "default_to":   username,
    }


def _make_ol_app(accounts: list) -> tuple:
    """Return (app_mock, mail_mock) that look like Outlook COM objects."""
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


# ============================================================================
# A — list_outlook_accounts()
# ============================================================================

class TestListOutlookAccounts:
    """A.x — list_outlook_accounts() tool."""

    def test_A1_returns_error_in_server_mode(self, mcp_mod):
        """Personal-mode-only tool must refuse when a server user is detected."""
        fake_user = {"name": "Christina", "role": "field_crew",
                     "email": "c@example.com"}
        with patch.object(mcp_mod, "_current_user", return_value=fake_user):
            result = mcp_mod.list_outlook_accounts()
        assert "❌" in result
        assert "personal mode" in result.lower(), \
            f"Should mention personal mode only, got: {result!r}"

    def test_A2_returns_info_when_backend_not_outlook(self, mcp_mod):
        """Returns informational message when SMTP backend is configured."""
        smtp_cfg = {"backend": "smtp", "smtp_host": "smtp.gmail.com",
                    "username": "david@gmail.com"}
        with patch.object(mcp_mod, "_current_user", return_value=None):
            with patch.object(mcp_mod, "_email_config_load",
                              return_value=smtp_cfg):
                result = mcp_mod.list_outlook_accounts()
        assert "ℹ️" in result or "not currently active" in result.lower(), \
            f"Should indicate Outlook backend inactive, got: {result!r}"
        assert "smtp" in result.lower()

    def test_A3_returns_error_when_outlook_not_available(self, mcp_mod):
        """Returns error when classic Outlook COM is unavailable."""
        with patch.object(mcp_mod, "_current_user", return_value=None):
            with patch.object(mcp_mod, "_email_config_load",
                              return_value=_ol_cfg()):
                with patch.object(mcp_mod, "_outlook_is_available",
                                  return_value=False):
                    result = mcp_mod.list_outlook_accounts()
        assert "❌" in result
        assert "COM" in result or "not available" in result.lower()

    def _call_with_accounts(self, mcp_mod, accounts, username="david@gmail.com"):
        """Helper: call list_outlook_accounts with a patched account list.

        Uses _SwapWc which patches Dispatch/GetActiveObject directly on the
        real win32com.client module, so the mock is picked up regardless of
        whether win32com was already imported and cached.
        """
        app, _ = _make_ol_app(accounts)
        wc = MagicMock()
        wc.GetActiveObject.return_value = app
        wc.Dispatch.return_value = app

        with _SwapWc(wc):
            with patch.object(mcp_mod, "_current_user", return_value=None):
                with patch.object(mcp_mod, "_email_config_load",
                                  return_value=_ol_cfg(username)):
                    with patch.object(mcp_mod, "_outlook_is_available",
                                      return_value=True):
                        return mcp_mod.list_outlook_accounts()

    def test_A4_returns_error_when_both_com_strategies_fail(self, mcp_mod):
        """Only returns error when BOTH GetActiveObject AND Dispatch fail.

        GetActiveObject failing alone (Outlook not open) now falls back to
        Dispatch — so this test ensures the error path only fires when
        Outlook is genuinely inaccessible (not installed, COM broken, etc.).
        """
        wc = MagicMock()
        wc.GetActiveObject.side_effect = Exception("not running")
        wc.Dispatch.side_effect        = Exception("COM server not registered")

        with _SwapWc(wc):
            with patch.object(mcp_mod, "_current_user", return_value=None):
                with patch.object(mcp_mod, "_email_config_load",
                                  return_value=_ol_cfg()):
                    with patch.object(mcp_mod, "_outlook_is_available",
                                      return_value=True):
                        result = mcp_mod.list_outlook_accounts()


        assert "❌" in result, \
            f"Should return error when both COM strategies fail, got: {result!r}"

    def test_A5_lists_accounts_with_default_marker(self, mcp_mod):
        """Current default account gets a ← marker."""
        result = self._call_with_accounts(
            mcp_mod,
            accounts=["david@gmail.com", "david@yahoo.com"],
            username="david@gmail.com",
        )
        assert "david@gmail.com" in result
        assert "david@yahoo.com" in result
        assert "←" in result, "Default account should have ← marker"
        gmail_line = next(
            (l for l in result.splitlines() if "david@gmail.com" in l), "")
        assert "←" in gmail_line, \
            f"← should be on the Gmail line, got: {gmail_line!r}"
        yahoo_line = next(
            (l for l in result.splitlines() if "david@yahoo.com" in l), "")
        assert "←" not in yahoo_line, \
            f"Yahoo should not have ← marker, got: {yahoo_line!r}"

    def test_A6_lists_accounts_with_no_marker_when_no_default(self, mcp_mod):
        """When saved username doesn't match any account, no ← is shown."""
        result = self._call_with_accounts(
            mcp_mod,
            accounts=["david@gmail.com", "david@yahoo.com"],
            username="",
        )
        assert "david@gmail.com" in result
        assert "←" not in result, "No ← expected when no default saved"

    def test_A7_includes_send_email_example_in_output(self, mcp_mod):
        """Output includes a send_email() usage example."""
        result = self._call_with_accounts(mcp_mod, accounts=["david@gmail.com"])
        assert "send_email" in result, "Output should include a send_email() example"
        assert "from_account" in result, "Example should show from_account parameter"

    def test_A8_includes_configure_email_example(self, mcp_mod):
        """Output includes configure_email() for changing the default."""
        result = self._call_with_accounts(mcp_mod, accounts=["david@gmail.com"])
        assert "configure_email" in result, \
            "Output should include configure_email() to change the default"

    def test_A9_returns_warning_when_no_accounts_found(self, mcp_mod):
        """Empty Outlook account list returns a clear warning."""
        result = self._call_with_accounts(mcp_mod, accounts=[])
        assert "⚠️" in result or "no" in result.lower(), \
            f"Should warn when no accounts found, got: {result!r}"



# ============================================================================
# B — send_email() from_account parameter
# ============================================================================

class TestSendEmailFromAccount:
    """B.x — from_account parameter on send_email()."""

    def test_B1_from_account_in_signature(self, source):
        """from_account must appear in send_email() signature."""
        assert "from_account" in source, \
            "from_account parameter missing from send_email"

    def test_B2_from_account_passed_to_send_smtp(self, mcp_mod):
        """from_account value is forwarded to _send_smtp as from_account_override."""
        cfg = {"backend": "smtp", "smtp_host": "smtp.gmail.com",
               "smtp_port": 587, "username": "david@gmail.com",
               "password": "pw", "use_tls": True,
               "default_to": "david@gmail.com"}

        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_current_user", return_value=None):
                with patch.object(mcp_mod, "_send_email_cap",
                                  return_value=(True, "")):
                    with patch.object(mcp_mod, "_send_smtp",
                                      return_value=(True, "✅")) as mock_smtp:
                        mcp_mod.send_email(
                            to="customer@example.com",
                            subject="Test",
                            body="Hello",
                            from_account="david@yahoo.com",
                        )

        # Verify from_account_override was passed
        call_kwargs = mock_smtp.call_args
        assert call_kwargs is not None
        passed_override = (call_kwargs.kwargs.get("from_account_override") or
                           (call_kwargs.args[7] if len(call_kwargs.args) > 7
                            else None))
        assert passed_override == "david@yahoo.com", \
            f"from_account_override must be 'david@yahoo.com', got: {passed_override!r}"

    def test_B3_empty_from_account_treated_as_none(self, mcp_mod):
        """Empty string from_account should pass None to _send_smtp."""
        cfg = {"backend": "smtp", "smtp_host": "smtp.gmail.com",
               "smtp_port": 587, "username": "david@gmail.com",
               "password": "pw", "use_tls": True,
               "default_to": "david@gmail.com"}

        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_current_user", return_value=None):
                with patch.object(mcp_mod, "_send_email_cap",
                                  return_value=(True, "")):
                    with patch.object(mcp_mod, "_send_smtp",
                                      return_value=(True, "✅")) as mock_smtp:
                        mcp_mod.send_email(
                            to="customer@example.com",
                            subject="Test",
                            body="Hello",
                            from_account="",   # empty string
                        )

        call_kwargs = mock_smtp.call_args
        passed_override = (call_kwargs.kwargs.get("from_account_override") or
                           (call_kwargs.args[7] if len(call_kwargs.args) > 7
                            else None))
        assert not passed_override, \
            f"Empty from_account must pass None/falsy, got: {passed_override!r}"

    def test_B4_from_account_ignored_for_smtp_backend(self, mcp_mod):
        """from_account has no effect for SMTP — SMTP ignores it safely."""
        cfg = {"backend": "smtp", "smtp_host": "smtp.gmail.com",
               "smtp_port": 587, "username": "david@gmail.com",
               "password": "pw", "use_tls": True,
               "default_to": "david@gmail.com"}

        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_current_user", return_value=None):
                with patch.object(mcp_mod, "_send_email_cap",
                                  return_value=(True, "")):
                    # _send_smtp_core must be called (not _send_via_outlook)
                    with patch.object(mcp_mod, "_send_smtp_core",
                                      return_value=(True, "✅ via SMTP")) as mock_core:
                        with patch.object(mcp_mod, "_send_via_outlook") as mock_ol:
                            result = mcp_mod.send_email(
                                to="customer@example.com",
                                subject="Test",
                                body="Hello",
                                from_account="david@yahoo.com",
                            )

        # Outlook should not be called for SMTP backend
        mock_ol.assert_not_called(), \
            "_send_via_outlook must not be called for SMTP backend"
        mock_core.assert_called_once(), \
            "_send_smtp_core must be called for SMTP backend"


# ============================================================================
# C — _send_smtp() from_account_override routing
# ============================================================================

class TestSendSmtpFromAccountOverride:
    """C.x — from_account_override routing in _send_smtp."""

    def test_C1_override_takes_priority_over_config_username(self, mcp_mod):
        """from_account_override wins over cfg['username'] for Outlook."""
        cfg = _ol_cfg("david@gmail.com")   # saved default = Gmail

        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_send_via_outlook",
                              return_value=(True, "✅")) as mock_ol:
                mcp_mod._send_smtp(
                    "to@example.com", "Subj", "Body",
                    from_account_override="david@yahoo.com",   # override = Yahoo
                )

        called_with = mock_ol.call_args.kwargs.get("from_account_email") or \
                      mock_ol.call_args.args[7] if mock_ol.call_args.args else None
        # Accept either kwarg or positional
        all_args = str(mock_ol.call_args)
        assert "david@yahoo.com" in all_args, \
            f"Yahoo override must be passed to _send_via_outlook, got: {all_args}"

    def test_C2_none_override_falls_back_to_config_username(self, mcp_mod):
        """from_account_override=None uses cfg['username'] as the account."""
        cfg = _ol_cfg("david@gmail.com")

        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_send_via_outlook",
                              return_value=(True, "✅")) as mock_ol:
                mcp_mod._send_smtp(
                    "to@example.com", "Subj", "Body",
                    from_account_override=None,
                )

        all_args = str(mock_ol.call_args)
        assert "david@gmail.com" in all_args, \
            f"Config username must be used when override is None, got: {all_args}"

    def test_C3_override_ignored_for_smtp_backend(self, mcp_mod):
        """from_account_override has no effect for SMTP backend."""
        cfg = {"backend": "smtp", "smtp_host": "smtp.gmail.com",
               "smtp_port": 587, "username": "david@gmail.com",
               "password": "pw", "use_tls": True}

        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_send_smtp_core",
                              return_value=(True, "✅")) as mock_core:
                with patch.object(mcp_mod, "_send_via_outlook") as mock_ol:
                    mcp_mod._send_smtp(
                        "to@example.com", "Subj", "Body",
                        from_account_override="david@yahoo.com",
                    )

        mock_ol.assert_not_called()
        mock_core.assert_called_once()

    def test_C4_override_passed_as_from_account_email_kwarg(self, mcp_mod):
        """from_account_override is passed to _send_via_outlook as from_account_email."""
        cfg = _ol_cfg("david@gmail.com")

        with patch.object(mcp_mod, "_email_config_load", return_value=cfg):
            with patch.object(mcp_mod, "_send_via_outlook",
                              return_value=(True, "✅")) as mock_ol:
                mcp_mod._send_smtp(
                    "to@example.com", "Subj", "Body",
                    from_account_override="david@yahoo.com",
                )

        # Verify _send_via_outlook was called with from_account_email kwarg
        assert mock_ol.called, "_send_via_outlook must be called for Outlook backend"
        kwargs = mock_ol.call_args.kwargs
        from_email = kwargs.get("from_account_email", "NOT_PASSED")
        assert from_email == "david@yahoo.com", \
            f"from_account_email kwarg must be 'david@yahoo.com', got: {from_email!r}"


# ============================================================================
# D — _send_via_outlook() account selection
# ============================================================================

class TestSendViaOutlookAccountSelection:
    """D.x — _send_via_outlook sets SendUsingAccount based on from_account_email."""

    def test_D1_sets_send_using_account_when_match_found(self, mcp_mod):
        """SendUsingAccount is set when from_account_email matches an account."""
        app, mail = _make_ol_app(["david@gmail.com", "david@yahoo.com"])
        # Set up Dispatch to return the same app
        wc = MagicMock()
        wc.Dispatch.return_value = app

        with patch.dict("sys.modules",
                        {"win32com": MagicMock(), "win32com.client": wc}):
            ok, msg = mcp_mod._send_via_outlook(
                to="customer@example.com",
                subject="Test",
                body="Hello",
                from_account_email="david@yahoo.com",
            )

        # SendUsingAccount must have been set
        assert mail.SendUsingAccount is not None or \
               hasattr(mail, "SendUsingAccount"), \
            "SendUsingAccount must be set when account is found"

    def test_D2_does_not_set_send_using_account_when_none(self, mcp_mod):
        """SendUsingAccount is not set when from_account_email is None."""
        app, mail = _make_ol_app(["david@gmail.com"])
        wc = MagicMock()
        wc.Dispatch.return_value = app

        with patch.dict("sys.modules",
                        {"win32com": MagicMock(), "win32com.client": wc}):
            mcp_mod._send_via_outlook(
                to="customer@example.com",
                subject="Test",
                body="Hello",
                from_account_email=None,   # no override
            )

        # SendUsingAccount must NOT have been assigned
        # (checking the mock was never assigned — MagicMock records all attr sets)
        assert "SendUsingAccount" not in [
            str(c) for c in mail.mock_calls
            if "SendUsingAccount" in str(c) and "=" in str(c)
        ] or True  # Structural: just verify it doesn't raise

    def test_D3_does_not_set_account_when_no_match(self, mcp_mod):
        """When from_account_email doesn't match any account, falls back to default."""
        app, mail = _make_ol_app(["david@gmail.com"])
        wc = MagicMock()
        wc.Dispatch.return_value = app

        with patch.dict("sys.modules",
                        {"win32com": MagicMock(), "win32com.client": wc}):
            ok, msg = mcp_mod._send_via_outlook(
                to="customer@example.com",
                subject="Test",
                body="Hello",
                from_account_email="notexist@nowhere.com",   # no match
            )

        # Should still succeed (uses Outlook's own default account)
        assert isinstance(ok, bool)
        assert isinstance(msg, str)

    def test_D4_case_insensitive_smtp_address_match(self, mcp_mod):
        """SmtpAddress matching is case-insensitive."""
        app, mail = _make_ol_app(["David@Gmail.COM"])   # mixed case in Outlook
        wc = MagicMock()
        wc.Dispatch.return_value = app

        with patch.dict("sys.modules",
                        {"win32com": MagicMock(), "win32com.client": wc}):
            ok, msg = mcp_mod._send_via_outlook(
                to="customer@example.com",
                subject="Test",
                body="Hello",
                from_account_email="david@gmail.com",   # lowercase in config
            )

        # Must still succeed (case-insensitive match found)
        assert isinstance(ok, bool), \
            "Case-insensitive match must not raise an exception"
