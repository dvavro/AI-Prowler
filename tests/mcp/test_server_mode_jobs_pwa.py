"""
tests/mcp/test_server_mode_jobs_pwa.py
========================================
Structural regression tests for the server-mode Jobs PWA additions
(_ServerRouterASGI in _run_server_mode()): Phase 0 (Remote Control
suppression), Phase 1 (/jobs/ static serving), Phase 2 (/pwa-login +
/pwa-api bridge), and Phase 4 (photo upload crew scoping).

_ServerRouterASGI is a class nested inside _run_server_mode() — it can't be
imported and exercised directly the way module-level tool functions can.
Following the same structural-verification approach already established
in test_pwa_api_route.py for this exact situation: confirm the routes
exist, sit in the correct order relative to the Bearer-auth gate, and
call the expected scoping helpers — rather than spinning up a live server.

Run with:
    pytest tests/mcp/test_server_mode_jobs_pwa.py -v
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
MCP_FILE = SRC_ROOT / "ai_prowler_mcp.py"


@pytest.fixture(scope="module")
def lines():
    return MCP_FILE.read_text(encoding="utf-8").splitlines()


@pytest.fixture(scope="module")
def source():
    return MCP_FILE.read_text(encoding="utf-8")


def _find(lines, pattern, start=0):
    for i in range(start, len(lines)):
        if pattern in lines[i]:
            return i
    return None


def _server_mode_bounds(lines):
    """Returns (start, end) line indices for _run_server_mode()."""
    start = _find(lines, "def _run_server_mode(")
    assert start is not None, "_run_server_mode() not found — has it been renamed?"
    end = _find(lines, "def _run_http(", start)
    assert end is not None, "_run_http() not found after _run_server_mode()"
    return start, end


class TestServerModeSourceIsValid:
    def test_no_syntax_error(self):
        import py_compile, shutil, tempfile
        tmp = Path(tempfile.mkdtemp())
        try:
            dst = tmp / "ai_prowler_mcp.py"
            shutil.copy(MCP_FILE, dst)
            try:
                py_compile.compile(str(dst), doraise=True)
            except py_compile.PyCompileError as exc:
                pytest.fail(f"IndentationError / SyntaxError:\n{exc}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestPhase0RemoteControlSuppression:
    def test_remote_path_handled_within_server_mode(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path.startswith("/remote")', start)
        assert ln is not None and ln < end, (
            "/remote handling missing from _run_server_mode() — Phase 0 regressed."
        )

    def test_remote_response_is_not_available_message_not_bearer_error(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path.startswith("/remote")', start)
        assert ln is not None
        # The response text should be within the next ~15 lines.
        nearby = "\n".join(lines[ln:ln + 15])
        assert "not available" in nearby.lower() or "isn't available" in nearby.lower()


class TestPhase1JobsStaticServing:
    def test_jobs_path_handled_within_server_mode(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path.startswith("/jobs")', start)
        assert ln is not None and ln < end, (
            "/jobs static serving missing from _run_server_mode() — Phase 1 regressed."
        )

    def test_path_traversal_guard_present(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path.startswith("/jobs")', start)
        assert ln is not None
        nearby = "\n".join(lines[ln:ln + 20])
        assert "Forbidden" in nearby or "403" in nearby


class TestPhase2PwaModeSignal:
    """Regression guard for a real bug: /pwa-token was never ported to
    server mode at all. The PWA's frontend reads ONLY the `mode` field out
    of that response to decide whether it's running in server mode —
    missing the route entirely meant loadBearerToken() silently failed,
    state.serverMode never became true, and the whole app quietly behaved
    as personal mode (no name field, wrong copy, no Authorization headers
    on any subsequent call) with no visible error anywhere."""

    def test_pwa_token_route_present_in_server_mode(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path == "/pwa-token"', start)
        assert ln is not None and ln < end, (
            "/pwa-token missing from _run_server_mode() — the PWA has no "
            "way to detect it's running in server mode at all."
        )

    def test_pwa_token_reports_server_mode(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path == "/pwa-token"', start)
        assert ln is not None
        nearby = "\n".join(lines[ln:ln + 5])
        assert '"mode": "server"' in nearby

    def test_pwa_token_appears_before_pwa_login(self, lines):
        """Route ordering sanity check — not load-bearing for correctness
        (each is its own `if path == ...` check), but keeps the file
        readable in the order the login flow actually happens."""
        start, end = _server_mode_bounds(lines)
        token_ln = _find(lines, 'path == "/pwa-token"', start)
        login_ln = _find(lines, 'path == "/pwa-login"', start)
        assert token_ln is not None and login_ln is not None
        assert token_ln < login_ln


class TestPhase2PwaLoginAndApiBridge:
    def test_pwa_login_route_present(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path == "/pwa-login"', start)
        assert ln is not None and ln < end

    def test_pwa_login_validates_via_resolve_user(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path == "/pwa-login"', start)
        assert ln is not None
        nearby = "\n".join(lines[ln:ln + 20])
        assert "_resolve_user(" in nearby

    def test_pwa_api_route_present(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path == "/pwa-api"', start)
        assert ln is not None and ln < end

    def test_pwa_api_requires_bearer_token(self, lines):
        """The critical difference from personal mode's /pwa-api (no auth):
        server mode MUST resolve a real user, or crew scoping never
        activates for PWA-originated calls."""
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path == "/pwa-api"', start)
        assert ln is not None
        nearby = "\n".join(lines[ln:ln + 15])
        assert "_bearer_from_scope" in nearby
        assert "Missing bearer token" in nearby

    def test_pwa_api_constructs_real_user_ctx_not_none(self, lines):
        """Regression guard for the exact bug this design avoids: calling
        tools with ctx=None (or no ctx) would make _current_user(ctx)
        return None, silently disabling all crew scoping for every PWA
        call in server mode."""
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path == "/pwa-api"', start)
        assert ln is not None
        nearby = "\n".join(lines[ln:ln + 90])
        assert "request_context.request.state" in nearby, (
            "Server-mode /pwa-api must construct a Context-shaped object "
            "carrying the real resolved user, matching what _current_user() "
            "reads — otherwise crew scoping silently never activates."
        )
        assert "ctx=_srv_pa_ctx" in nearby

    def test_pwa_api_allowed_tools_include_job_tools(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path == "/pwa-api"', start)
        assert ln is not None
        nearby = "\n".join(lines[ln:ln + 40])
        for tool in ("read_job_spreadsheet", "log_time_entry",
                     "update_job_spreadsheet", "email_invoice"):
            assert tool in nearby, f"{tool} missing from server-mode /pwa-api allowed tools"


class TestPhase4PhotoUploadScoping:
    def test_photo_upload_route_present_in_server_mode(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path == "/photos/upload"', start)
        assert ln is not None and ln < end, (
            "/photos/upload missing from _run_server_mode() — Phase 4 photo "
            "upload was never ported to server mode."
        )

    def test_photo_upload_requires_bearer_token(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path == "/photos/upload"', start)
        assert ln is not None
        nearby = "\n".join(lines[ln:ln + 15])
        assert "_bearer_from_scope" in nearby
        assert "Missing bearer token" in nearby

    def test_photo_upload_calls_shared_crew_scope_helper(self, lines):
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path == "/photos/upload"', start)
        assert ln is not None
        nearby = "\n".join(lines[ln:ln + 150])
        assert "_job_crew_scope(" in nearby, (
            "Photo upload must use the SAME _job_crew_scope() helper as "
            "read_job_spreadsheet/update_job_spreadsheet/log_time_entry/"
            "email_invoice — a second, drifted implementation defeats the "
            "point of having a shared rule."
        )

    def test_photo_upload_rejects_before_writing_any_file(self, lines):
        """The crew-scoping check must appear BEFORE mkdir/write_bytes,
        not after — otherwise a rejected upload could still leave a file
        on disk."""
        start, end = _server_mode_bounds(lines)
        ln = _find(lines, 'path == "/photos/upload"', start)
        assert ln is not None
        scope_check_ln = _find(lines, "_job_crew_scope(", ln)
        mkdir_ln = _find(lines, "_photo_dir4.mkdir(", ln)
        assert scope_check_ln is not None
        assert mkdir_ln is not None
        assert scope_check_ln < mkdir_ln


class TestSharedCrewScopeHelper:
    def test_job_crew_scope_helper_exists(self, source):
        assert "def _job_crew_scope(" in source

    def test_read_job_spreadsheet_uses_shared_helper(self, source):
        assert "_job_crew_scope(ctx, fp)" in source

    def test_update_job_spreadsheet_uses_shared_helper(self, lines):
        ln = _find(lines, "def update_job_spreadsheet(")
        assert ln is not None
        nearby = "\n".join(lines[ln:ln + 220])
        assert "_job_crew_scope(" in nearby

    def test_log_time_entry_uses_shared_helper(self, lines):
        ln = _find(lines, "def _log_time_entry_impl(")
        assert ln is not None
        nearby = "\n".join(lines[ln:ln + 220])
        assert "_job_crew_scope(" in nearby

    def test_email_invoice_uses_shared_helper(self, lines):
        ln = _find(lines, "def email_invoice(")
        assert ln is not None
        # Use a 120-line window and accept _find_invoice_row as the delegating
        # helper — it internally calls _resolve_job_spreadsheet_path and handles
        # crew scoping in one shared place for both email_invoice and text_invoice.
        nearby = "\n".join(lines[ln:ln + 120])
        assert (
            "_resolve_job_spreadsheet_path(" in nearby
            or "_job_crew_scope(" in nearby
            or "_find_invoice_row(" in nearby
        ), "email_invoice must delegate to _find_invoice_row, _resolve_job_spreadsheet_path, or _job_crew_scope for ctx/scoping"
