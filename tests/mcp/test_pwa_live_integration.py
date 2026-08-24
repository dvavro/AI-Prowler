"""
test_pwa_live_integration.py
============================
Live integration tests for the PWA endpoints on the running AI-Prowler
HTTP server. These tests require AI-Prowler to be running locally.

What these tests verify (end-to-end, against the real server):
  1. /pwa/          — serves index.html with correct content-type
  2. /pwa/manifest.json — serves manifest with correct content-type
  3. /pwa/sw.js     — serves service worker
  4. /pwa-token     — returns JSON with a non-empty token field
  5. /pwa-api       — read_job_spreadsheet returns job data
  6. /pwa-api       — unknown tool returns {"ok": false}
  7. /pwa-api       — malformed JSON returns 400
  8. /mcp           — still requires Bearer auth (not broken by PWA routes)
  9. /pwa/nonexistent — returns 404

Run with:
    pytest tests/mcp/test_pwa_live_integration.py -v -m live_pwa

Or directly:
    run_tests.bat tests\\mcp\\test_pwa_live_integration.py -v -m live_pwa

IMPORTANT: AI-Prowler HTTP server must be running on localhost:8000.
These tests are marked @pytest.mark.live_pwa so they are excluded from
the normal test run (pytest.ini: -m "not e2e and not live_worker").
Add -m live_pwa to run them explicitly.
"""
from __future__ import annotations

import json
import os
import socket
import time
from pathlib import Path

import pytest
import urllib.request
import urllib.error

# ── Config ────────────────────────────────────────────────────────────────
PORT      = int(os.environ.get("AI_PROWLER_PORT", 8000))
BASE_URL  = f"http://127.0.0.1:{PORT}"
TIMEOUT   = 10  # seconds per request

# Load bearer token from config so we can test /mcp auth is still intact
_CONFIG_PATH = Path.home() / ".ai-prowler" / "config.json"
try:
    _cfg         = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
    BEARER_TOKEN = _cfg.get("remote_token", "")
except Exception:
    BEARER_TOKEN = ""


# ── Helpers ───────────────────────────────────────────────────────────────

def _get(path: str, headers: dict = None, auth: bool = True) -> tuple[int, dict, bytes]:
    """Make a GET request. Returns (status, headers, body).
    auth=True (default) sends the Bearer token so the PWA login is satisfied.
    Pass auth=False to test unauthenticated behaviour."""
    url = BASE_URL + path
    h = {}
    if auth and BEARER_TOKEN:
        h["Authorization"] = f"Bearer {BEARER_TOKEN}"
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, {k.lower(): v for k, v in dict(r.headers).items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in dict(e.headers).items()}, e.read()


def _post(path: str, body: bytes, headers: dict = None, auth: bool = True) -> tuple[int, dict, bytes]:
    """Make a POST request. Returns (status, headers, body).
    auth=True (default) sends the Bearer token so the PWA login is satisfied.
    Pass auth=False to test unauthenticated behaviour."""
    url = BASE_URL + path
    h = {"Content-Type": "application/json"}
    if auth and BEARER_TOKEN:
        h["Authorization"] = f"Bearer {BEARER_TOKEN}"
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, {k.lower(): v for k, v in dict(r.headers).items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in dict(e.headers).items()}, e.read()


def _server_running() -> bool:
    """Check if AI-Prowler HTTP server is listening on PORT."""
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False


# ── Skip if server not running or no token configured ─────────────────────
pytestmark = pytest.mark.live_pwa

@pytest.fixture(scope="session", autouse=True)
def require_server():
    if not _server_running():
        pytest.skip(
            f"AI-Prowler HTTP server is not running on port {PORT}. "
            f"Start it in the Settings tab then re-run with -m live_pwa."
        )
    if not BEARER_TOKEN:
        pytest.skip(
            "No Bearer token found in ~/.ai-prowler/config.json (remote_token). "
            "Configure Remote Access in the Settings tab first."
        )


# ══════════════════════════════════════════════════════════════════════════
# 1. PWA STATIC FILES
# ══════════════════════════════════════════════════════════════════════════

class TestPwaStaticLive:

      def test_index_html_200(self):
          status, hdrs, body = _get("/jobs/")
          assert status == 200, f"Expected 200, got {status}"
          assert "text/html" in hdrs.get("content-type", ""), \
              f"Expected text/html, got {hdrs.get('content-type')}"
          assert b"AI-Prowler" in body, "index.html missing AI-Prowler content"

      def test_manifest_json_200(self):
          status, hdrs, body = _get("/jobs/manifest.json")
          assert status == 200, f"Expected 200, got {status}"
          assert "json" in hdrs.get("content-type", ""), \
              f"Expected JSON content-type, got {hdrs.get('content-type')}"
          data = json.loads(body)
          assert "name" in data, "manifest.json missing 'name' field"

      def test_sw_js_200(self):
          status, hdrs, body = _get("/jobs/sw.js")
          assert status == 200, f"Expected 200, got {status}"
          assert b"cache" in body.lower() or b"service" in body.lower(), \
              "sw.js content looks wrong"

      def test_missing_file_404(self):
          status, _, _ = _get("/jobs/does_not_exist_xyz.png")
          assert status == 404, f"Expected 404 for missing file, got {status}"

      def test_path_traversal_blocked(self):
          status, _, _ = _get("/jobs/../../../etc/passwd")
          assert status in (403, 404, 400), \
              f"Path traversal should be blocked, got {status}"


# ══════════════════════════════════════════════════════════════════════════
# 2. PWA TOKEN ENDPOINT
# ══════════════════════════════════════════════════════════════════════════

class TestPwaTokenLive:

    def test_pwa_token_returns_200(self):
        status, hdrs, body = _get("/pwa-token")
        assert status == 200, f"/pwa-token returned {status}"

    def test_pwa_token_returns_json(self):
        status, hdrs, body = _get("/pwa-token")
        assert "json" in hdrs.get("content-type", ""), \
            f"Expected JSON, got {hdrs.get('content-type')}"
        data = json.loads(body)
        assert "token" in data, "Response missing 'token' field"

    def test_pwa_token_is_non_empty(self):
        status, _, body = _get("/pwa-token")
        data = json.loads(body)
        assert data.get("token"), \
            "Bearer token is empty — check config.json remote_token field"

    def test_pwa_token_matches_config(self):
        if not BEARER_TOKEN:
            pytest.skip("Could not read bearer token from config.json")
        status, _, body = _get("/pwa-token")
        data = json.loads(body)
        assert data.get("token") == BEARER_TOKEN, \
            "Token from /pwa-token doesn't match config.json remote_token"


# ══════════════════════════════════════════════════════════════════════════
# 3. PWA API ENDPOINT
# ══════════════════════════════════════════════════════════════════════════

class TestPwaApiLive:

    def test_read_jobs_returns_200(self):
        body = json.dumps({"tool": "read_job_spreadsheet", "args": {"max_rows": 5}}).encode()
        status, hdrs, resp = _post("/pwa-api", body)
        assert status == 200, f"/pwa-api returned {status}: {resp[:200]}"

    def test_read_jobs_returns_ok_true(self):
        body = json.dumps({"tool": "read_job_spreadsheet", "args": {"max_rows": 5}}).encode()
        status, _, resp = _post("/pwa-api", body)
        data = json.loads(resp)
        assert data.get("ok") is True, \
            f"Expected ok=true, got: {data.get('error', resp[:200])}"

    def test_read_jobs_result_has_content(self):
        body = json.dumps({"tool": "read_job_spreadsheet", "args": {"max_rows": 5}}).encode()
        status, _, resp = _post("/pwa-api", body)
        data = json.loads(resp)
        assert data.get("result"), "result field is empty"

    def test_unknown_tool_returns_400(self):
        body = json.dumps({"tool": "delete_everything", "args": {}}).encode()
        status, _, resp = _post("/pwa-api", body)
        assert status == 400, f"Expected 400 for unknown tool, got {status}"
        data = json.loads(resp)
        assert data.get("ok") is False

    def test_malformed_json_returns_400(self):
        status, _, resp = _post("/pwa-api", b"{{not valid json")
        assert status == 400, f"Expected 400 for bad JSON, got {status}"

    def test_response_is_json(self):
        body = json.dumps({"tool": "read_job_spreadsheet", "args": {}}).encode()
        status, hdrs, _ = _post("/pwa-api", body)
        assert "json" in hdrs.get("content-type", ""), \
            f"Expected JSON response, got {hdrs.get('content-type')}"

    def test_check_status_tool_works(self):
        body = json.dumps({"tool": "check_ai_prowler_status", "args": {}}).encode()
        status, _, resp = _post("/pwa-api", body)
        assert status == 200, f"check_ai_prowler_status returned {status}"
        data = json.loads(resp)
        assert data.get("ok") is True, f"Error: {data.get('error')}"
        assert "ChromaDB" in data.get("result", "") or "AI-Prowler" in data.get("result", ""), \
            "Status result missing expected content"


# ══════════════════════════════════════════════════════════════════════════
# 4. /mcp STILL REQUIRES AUTH (regression — PWA routes must not break it)
# ══════════════════════════════════════════════════════════════════════════

class TestMcpAuthStillWorksLive:

    def test_mcp_without_token_returns_401(self):
        """The /mcp endpoint must still require Bearer auth."""
        body = json.dumps({"jsonrpc": "2.0", "id": 1,
                           "method": "tools/list", "params": {}}).encode()
        status, _, _ = _post("/mcp", body, auth=False)
        assert status == 401, \
            f"Expected 401 from /mcp without token, got {status}. " \
            f"PWA routes may have accidentally removed auth from /mcp!"

    def test_mcp_with_token_reaches_server(self):
        """With a valid Bearer token /mcp should not return 401."""
        if not BEARER_TOKEN:
            pytest.skip("No bearer token in config.json")
        body = json.dumps({"jsonrpc": "2.0", "id": 1,
                           "method": "tools/list", "params": {}}).encode()
        status, _, _ = _post("/mcp", body,
                              headers={"Authorization": f"Bearer {BEARER_TOKEN}"})
        assert status != 401, \
            f"Valid Bearer token rejected — token mismatch or server issue"
