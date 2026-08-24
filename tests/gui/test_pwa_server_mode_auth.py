"""
tests/gui/test_pwa_server_mode_auth.py
========================================
Structural tests for the Jobs PWA's server-mode login persistence
(pwa/index.html). Confirms:

  - Login state persists in localStorage, not sessionStorage — a crew
    member should only need to log in once, ever, not once per app-open.
  - Server-mode login actually calls the real /pwa-login endpoint and uses
    the returned access_token, rather than comparing against the personal-
    mode owner token (which was the pre-existing bug for server mode).
  - Every subsequent /pwa-api and /photos/upload call attaches the
    Authorization: Bearer header in server mode.
  - Personal mode's original behavior (no auth header, single owner token
    comparison) is left completely unchanged.

Plain string-presence checks against the source, matching the same
structural-verification approach used for _ServerRouterASGI (a JS file
can't be usefully unit-tested the way Python tool functions can without a
full browser/DOM harness).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
PWA_FILE = SRC_ROOT / "jobs" / "index.html"
MCP_FILE = SRC_ROOT / "ai_prowler_mcp.py"


@pytest.fixture(scope="module")
def mcp_source():
    return MCP_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def source():
    return PWA_FILE.read_text(encoding="utf-8")


class TestNoLeftoverSessionStorage:
    def test_no_active_sessionstorage_calls(self, source):
        """sessionStorage.* calls would mean login doesn't survive closing
        the app — only comments are allowed to still mention the word."""
        for line in source.splitlines():
            code_part = line.split("//")[0]
            assert "sessionStorage." not in code_part, (
                f"Found an active sessionStorage call outside a comment: {line!r}. "
                "Login must persist in localStorage so it survives closing the app."
            )

    def test_localstorage_used_for_auth_persistence(self, source):
        assert "localStorage.setItem('ap_auth'" in source
        assert "localStorage.getItem('ap_auth')" in source
        assert "localStorage.removeItem('ap_auth')" in source


class TestServerModeLoginCallsRealEndpoint:
    def test_doauth_calls_pwa_login_for_server_mode(self, source):
        assert "/pwa-login" in source
        idx = source.index("/pwa-login")
        nearby = source[idx - 200:idx + 400]
        assert "state.serverMode" in nearby

    def test_access_token_stored_separately_from_bearer_token(self, source):
        """The pre-existing bug: server mode's login compared the entered
        token against BEARER_TOKEN (the personal-mode owner's single
        token, unrelated to any individual crew member). ACCESS_TOKEN must
        be a distinct variable, populated only from /pwa-login's response."""
        assert "let ACCESS_TOKEN" in source
        assert "let BEARER_TOKEN" in source
        assert "ACCESS_TOKEN    = data.access_token" in source or \
               "ACCESS_TOKEN = data.access_token" in source

    def test_personal_mode_comparison_still_present_unchanged(self, source):
        """Regression guard: personal mode's original single-owner-token
        comparison must still exist for the non-server-mode branch."""
        assert "entered !== BEARER_TOKEN" in source


class TestAuthorizationHeaderAttached:
    def test_mcp_call_attaches_bearer_header_in_server_mode(self, source):
        idx = source.index("async function mcpCall")
        nearby = source[idx:idx + 600]
        assert "state.serverMode" in nearby
        assert "ACCESS_TOKEN" in nearby
        assert "Authorization" in nearby
        assert "Bearer " in nearby

    def test_photo_upload_attaches_bearer_header_in_server_mode(self, source):
        idx = source.index("/photos/upload'")
        nearby = source[idx - 300:idx + 300]
        assert "Authorization" in nearby
        assert "ACCESS_TOKEN" in nearby

    def test_personal_mode_sends_no_auth_header(self, source):
        """Personal mode's /pwa-api and /photos/upload require no auth at
        all — the header must be conditional on state.serverMode, not
        always sent."""
        idx = source.index("async function mcpCall")
        nearby = source[idx:idx + 600]
        assert "if (state.serverMode" in nearby


class TestSignOutClearsServerModeToken:
    def test_signout_resets_access_token(self, source):
        idx = source.index("function signOut()")
        nearby = source[idx:idx + 200]
        assert "ACCESS_TOKEN = ''" in nearby
        assert "localStorage.removeItem" in nearby


class TestResumeFromStorageHandlesBothModes:
    def test_resume_branches_on_saved_mode(self, source):
        idx = source.index("localStorage.getItem('ap_auth')")
        nearby = source[idx:idx + 700]
        assert "s.mode === 'server'" in nearby
        assert "s.access_token" in nearby


class TestNameFieldForServerModeLogin:
    """Server mode login asks for name + token, not just token — catches
    "right password, wrong person" typos and reads like a normal login
    rather than a single shared password prompt. Personal mode (single
    user) is unaffected."""

    def test_name_field_exists_in_markup(self, source):
        assert 'id="authName"' in source

    def test_name_field_hidden_by_default(self, source):
        idx = source.index('id="authName"')
        nearby = source[idx:idx + 200]
        assert "display:none" in nearby

    def test_show_auth_reveals_name_field_only_for_server_mode(self, source):
        idx = source.index("function showAuth()")
        nearby = source[idx:idx + 900]
        assert "nameEl.style.display" in nearby
        assert "state.serverMode" in nearby

    def test_doauth_sends_name_alongside_token_for_server_mode(self, source):
        idx = source.index("async function doAuth()")
        nearby = source[idx:idx + 2500]
        assert "/pwa-login" in nearby
        assert "name: enteredName" in nearby
        assert "token: entered" in nearby

    def test_doauth_requires_name_before_submitting_in_server_mode(self, source):
        idx = source.index("async function doAuth()")
        nearby = source[idx:idx + 1500]
        assert "Please enter your name" in nearby


class TestBackendVerifiesNameMatchesToken:
    """The whole point of adding the name field: a valid token entered
    under the WRONG name must be rejected, not silently accepted."""

    def test_mcp_source_available(self):
        assert MCP_FILE.exists(), f"Expected ai_prowler_mcp.py at {MCP_FILE}"

    def test_pwa_login_compares_resolved_user_name_to_entered_name(self, mcp_source):
        idx = mcp_source.index('path == "/pwa-login"')
        nearby = mcp_source[idx:idx + 2000]
        assert '_srv_pl_user.get("name"' in nearby
        assert "_srv_pl_name.lower()" in nearby

    def test_pwa_login_uses_one_generic_error_for_both_failure_modes(self, mcp_source):
        """Must not reveal via the error message whether the name or the
        token was the actual problem — that's an enumeration/probing risk."""
        idx = mcp_source.index('path == "/pwa-login"')
        nearby = mcp_source[idx:idx + 2000]
        assert nearby.count("_srv_pl_generic_error") >= 3


class TestExpiredTokenRecovery:
    """access_token is held in memory only on the server — a restart (e.g.
    deploying an update, which happens often during active development)
    silently invalidates every logged-in session. Without this fix, the
    app got stuck showing a dead-end 'Could not reach AI-Prowler / HTTP
    401' error forever, since retrying just resent the same dead token."""

    def test_handle_auth_expired_function_exists(self, source):
        assert "function handleAuthExpired()" in source

    def test_handle_auth_expired_clears_stored_session(self, source):
        idx = source.index("function handleAuthExpired()")
        nearby = source[idx:idx + 700]
        assert "localStorage.removeItem('ap_auth')" in nearby
        assert "ACCESS_TOKEN = ''" in nearby
        assert "showAuth()" in nearby

    def test_mcp_call_detects_401_and_recovers(self, source):
        idx = source.index("async function mcpCall(tool")
        nearby = source[idx:idx + 900]
        assert "res.status === 401" in nearby
        assert "handleAuthExpired()" in nearby

    def test_photo_upload_detects_401_and_recovers(self, source):
        idx = source.index("/photos/upload'")
        nearby = source[idx:idx + 600]
        assert "res.status === 401" in nearby
        assert "handleAuthExpired()" in nearby

    def test_401_check_happens_before_generic_error_check(self, source):
        """Ordering matters — a generic `if (!res.ok)` check placed first
        would catch 401s too and never reach the recovery path."""
        idx = source.index("async function mcpCall(tool")
        nearby = source[idx:idx + 900]
        auth_check_pos = nearby.index("res.status === 401")
        generic_check_pos = nearby.index("if (!res.ok)")
        assert auth_check_pos < generic_check_pos
