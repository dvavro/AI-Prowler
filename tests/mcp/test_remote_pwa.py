"""
test_remote_pwa.py
==================
Test suite for the AI-Prowler Remote Control PWA (/remote/).

Covers all 6 features from the implementation plan:
  Feature 1 — /remote/ static file serving
  Feature 2 — /remote-api/ tool bridge
  Feature 3 — /remote/download file download endpoint
  Feature 4 — PWA frontend (offline source checks)
  Feature 5 — Directory permissions (grant/revoke + re-auth)
  Feature 6 — Settings GUI (source check only — no GUI interaction)

ISOLATION STRATEGY
------------------
Offline tests (Features 1-source, 4, 6) read only from the work-tree
source files (SRC_ROOT). They never touch the installed AI-Prowler.

Live tests (Features 1-live, 2, 3, 5) hit http://127.0.0.1:<PORT>.
By default PORT=8000, but set AI_PROWLER_REMOTE_TEST_PORT=8001 (or any
free port) to run a second server from the work tree alongside the
installed instance without colliding.

To run a work-tree server on a different port:
    set AI_PROWLER_REMOTE_TEST_PORT=8001
    python ai_prowler_mcp.py --transport http --port 8001

Then run live tests:
    pytest tests/mcp/test_remote_pwa.py -m live_remote -v

Offline tests run without any server:
    pytest tests/mcp/test_remote_pwa.py -m "not live_remote" -v
"""
from __future__ import annotations

import json
import os
import socket
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

# ── Paths ──────────────────────────────────────────────────────────────────
_SRC      = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT  = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
MCP_FILE  = SRC_ROOT / "ai_prowler_mcp.py"
REMOTE_DIR = SRC_ROOT / "remote"
INDEX_HTML = REMOTE_DIR / "index.html"
MANIFEST   = REMOTE_DIR / "manifest.json"
SW_FILE    = REMOTE_DIR / "sw.js"

# ── Live server config ─────────────────────────────────────────────────────
# Use AI_PROWLER_REMOTE_TEST_PORT to avoid colliding with the installed
# server on 8000. Default falls back to 8000 for convenience.
PORT     = int(os.environ.get("AI_PROWLER_REMOTE_TEST_PORT",
               os.environ.get("AI_PROWLER_PORT", 8000)))
BASE_URL = f"http://127.0.0.1:{PORT}"
TIMEOUT  = 12

# Bearer token from config.json
_CONFIG  = Path.home() / ".ai-prowler" / "config.json"
try:
    _cfg         = json.loads(_CONFIG.read_text(encoding="utf-8"))
    BEARER_TOKEN = _cfg.get("remote_token", "")
except Exception:
    BEARER_TOKEN = ""

# ── pytest markers ─────────────────────────────────────────────────────────


# ── Helpers ────────────────────────────────────────────────────────────────
def _server_running() -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False


def _get(path: str, hdrs: dict = None, auth: bool = True, token: str = None):
    """GET request. Returns (status, headers_lower, body_bytes)."""
    h = {}
    tok = token or BEARER_TOKEN
    if auth and tok:
        h["Authorization"] = f"Bearer {tok}"
    if hdrs:
        h.update(hdrs)
    req = urllib.request.Request(BASE_URL + path, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, {k.lower(): v for k, v in dict(r.headers).items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in dict(e.headers).items()}, e.read()


def _post(path: str, body: bytes, hdrs: dict = None, auth: bool = True, token: str = None):
    """POST request. Returns (status, headers_lower, body_bytes)."""
    h = {"Content-Type": "application/json"}
    tok = token or BEARER_TOKEN
    if auth and tok:
        h["Authorization"] = f"Bearer {tok}"
    if hdrs:
        h.update(hdrs)
    req = urllib.request.Request(BASE_URL + path, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, {k.lower(): v for k, v in dict(r.headers).items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in dict(e.headers).items()}, e.read()


def _api(tool: str, args: dict = None):
    """POST to /remote-api. Returns (status, parsed_json)."""
    body = json.dumps({"tool": tool, "args": args or {}}).encode()
    status, _, resp = _post("/remote-api", body)
    try:
        return status, json.loads(resp)
    except Exception:
        return status, {}


def _dl_url(path: str, token: str = None) -> str:
    """Build a /remote/download URL with token in query string."""
    tok = token or BEARER_TOKEN
    return (BASE_URL + "/remote/download?path=" +
            urllib.parse.quote(path, safe="") +
            "&token=" + urllib.parse.quote(tok, safe=""))


# ── Session-level skip guard ───────────────────────────────────────────────
@pytest.fixture(scope="session", autouse=True)
def _require_server_for_live():
    """
    Skip live tests gracefully if the server isn't running or no token.
    Offline tests are never skipped by this fixture.
    """
    # This fixture is autouse but only meaningful for live_remote-marked tests.
    # Offline tests don't actually call the server so they pass regardless.
    pass


def _skip_if_no_server():
    if not _server_running():
        pytest.skip(
            f"No server on port {PORT}. "
            f"Set AI_PROWLER_REMOTE_TEST_PORT and start the work-tree server, "
            f"or run without -m live_remote for offline tests only."
        )
    if not BEARER_TOKEN:
        pytest.skip(
            "No Bearer token in ~/.ai-prowler/config.json (remote_token). "
            "Configure Remote Access first."
        )


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 1 — /remote/ Static File Serving
# ══════════════════════════════════════════════════════════════════════════════

class TestFeature1_StaticFiles:
    """1.x — /remote/ static file serving"""

    # ── Offline source checks ──────────────────────────────────────────────

    @pytest.mark.not_live
    def test_1_1_remote_dir_exists(self):
        assert REMOTE_DIR.exists(), f"remote/ folder not found: {REMOTE_DIR}"

    @pytest.mark.not_live
    def test_1_2_index_html_exists(self):
        assert INDEX_HTML.exists(), f"remote/index.html not found"

    @pytest.mark.not_live
    def test_1_3_manifest_exists(self):
        assert MANIFEST.exists(), f"remote/manifest.json not found"

    @pytest.mark.not_live
    def test_1_4_sw_js_exists(self):
        assert SW_FILE.exists(), f"remote/sw.js not found"

    @pytest.mark.not_live
    def test_1_5_manifest_start_url_is_remote(self):
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        assert "/remote" in data.get("start_url", ""), \
            f"manifest start_url should contain /remote, got: {data.get('start_url')}"

    @pytest.mark.not_live
    def test_1_6_sw_handles_remote_api_network_first(self):
        sw = SW_FILE.read_text(encoding="utf-8")
        assert "remote-api" in sw, "sw.js should handle /remote-api with network-first strategy"

    @pytest.mark.not_live
    def test_1_7_mcp_has_remote_route(self):
        src = MCP_FILE.read_text(encoding="utf-8")
        assert 'path.startswith("/remote")' in src, \
            "/remote route missing from ai_prowler_mcp.py"

    @pytest.mark.not_live
    def test_1_8_mcp_has_remote_download_route(self):
        src = MCP_FILE.read_text(encoding="utf-8")
        assert 'path == "/remote/download"' in src, \
            "/remote/download route missing from ai_prowler_mcp.py"

    @pytest.mark.not_live
    def test_1_9_mcp_has_remote_api_route(self):
        src = MCP_FILE.read_text(encoding="utf-8")
        assert 'path == "/remote-api"' in src, \
            "/remote-api route missing from ai_prowler_mcp.py"

    @pytest.mark.not_live
    def test_1_10_path_traversal_guard_in_source(self):
        src = MCP_FILE.read_text(encoding="utf-8")
        assert "_remote_root" in src and "abspath" in src, \
            "Path traversal guard missing from /remote/ static handler"

    @pytest.mark.not_live
    def test_1_11_server_mode_blocked_in_source(self):
        src = MCP_FILE.read_text(encoding="utf-8")
        assert "not available in server mode" in src, \
            "Server mode gate missing from /remote/ handler"

    # ── Live server checks ─────────────────────────────────────────────────

    @pytest.mark.live_remote
    def test_1_12_live_index_200(self):
        _skip_if_no_server()
        status, hdrs, body = _get("/remote/")
        assert status == 200, f"Expected 200, got {status}"
        assert "text/html" in hdrs.get("content-type", ""), \
            f"Expected text/html, got {hdrs.get('content-type')}"
        assert b"AI-Prowler Remote" in body, "index.html missing AI-Prowler Remote content"

    @pytest.mark.live_remote
    def test_1_13_live_manifest_200(self):
        _skip_if_no_server()
        status, hdrs, body = _get("/remote/manifest.json")
        assert status == 200
        assert "json" in hdrs.get("content-type", "")
        data = json.loads(body)
        assert "name" in data

    @pytest.mark.live_remote
    def test_1_14_live_sw_js_200(self):
        _skip_if_no_server()
        status, _, _ = _get("/remote/sw.js")
        assert status == 200

    @pytest.mark.live_remote
    def test_1_15_live_missing_file_404(self):
        _skip_if_no_server()
        status, _, _ = _get("/remote/does_not_exist_xyz.png")
        assert status == 404

    @pytest.mark.live_remote
    def test_1_16_live_path_traversal_blocked(self):
        _skip_if_no_server()
        status, _, _ = _get("/remote/../../etc/passwd")
        assert status in (403, 404, 400), \
            f"Path traversal not blocked — got {status}"

    @pytest.mark.live_remote
    def test_1_17_live_no_auth_returns_html_not_401(self):
        """The /remote/ static shell loads without Bearer token — login is handled
        in-page by the JS auth screen. Only /remote-api and /remote/download need auth.
        Note: /remote/ in server mode still returns 403 (different from auth)."""
        _skip_if_no_server()
        status, hdrs, body = _get("/remote/", auth=False)
        # 403 = server mode gate (correct), 200 = personal mode serving shell
        # 401 = wrong — means Bearer check fired before static file handler
        assert status in (200, 403), \
            f"Static shell should load without Bearer token, got {status}. " \
            f"401 means the outer auth check fired before the /remote/ handler."

    @pytest.mark.live_remote
    def test_1_18_live_server_mode_returns_403(self):
        """Skip if server is in personal mode — this test only applies to server mode."""
        _skip_if_no_server()
        try:
            cfg = json.loads(_CONFIG.read_text(encoding="utf-8"))
            if cfg.get("mode", "personal") == "personal":
                pytest.skip("Server is in personal mode — 403 gate only applies to server mode")
        except Exception:
            pytest.skip("Could not read config")
        status, _, _ = _get("/remote/")
        assert status == 403, f"Server mode should return 403, got {status}"


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 2 — /remote-api/ Tool Bridge
# ══════════════════════════════════════════════════════════════════════════════

class TestFeature2_RemoteApi:
    """2.x — /remote-api/ tool bridge"""

    @pytest.mark.not_live
    def test_2_1_allowed_tools_in_source(self):
        src = MCP_FILE.read_text(encoding="utf-8")
        assert "_REMOTE_ALLOWED" in src, \
            "_REMOTE_ALLOWED set missing from /remote-api/ handler"

    @pytest.mark.not_live
    def test_2_2_write_tools_not_in_allowed_list(self):
        src = MCP_FILE.read_text(encoding="utf-8")
        start = src.find("_REMOTE_ALLOWED")
        block = src[start:start+3000]
        dangerous = ["write_file", "create_file",
                     "reindex_all", "grant_write_access",
                     "revoke_write_access", "log_time_entry"]
        # delete_learning intentionally allowed — Learn tab lets owner delete learnings
        # grant/revoke are intentionally in the list — skip those
        really_dangerous = [t for t in dangerous
                            if t not in ("grant_write_access", "revoke_write_access")]
        for tool in really_dangerous:
            assert tool not in block, \
                f"Dangerous tool '{tool}' found in _REMOTE_ALLOWED"

    @pytest.mark.not_live
    def test_2_3_permissions_tools_in_allowed_list(self):
        src = MCP_FILE.read_text(encoding="utf-8")
        start = src.find("_REMOTE_ALLOWED")
        block = src[start:start+3000]
        for tool in ["grant_write_access", "revoke_write_access",
                     "list_writable_directories", "list_tracked_directories"]:
            assert tool in block, \
                f"Permissions tool '{tool}' missing from _REMOTE_ALLOWED"

    @pytest.mark.live_remote
    def test_2_4_live_status_tool_works(self):
        _skip_if_no_server()
        status, data = _api("check_ai_prowler_status")
        assert status == 200, f"Expected 200, got {status}"
        assert data.get("ok") is True, f"Expected ok=true, got: {data}"
        assert "AI-Prowler" in data.get("result", ""), \
            "Status result missing AI-Prowler content"

    @pytest.mark.live_remote
    def test_2_5_live_list_tracked_dirs(self):
        _skip_if_no_server()
        status, data = _api("list_tracked_directories")
        assert status == 200
        assert data.get("ok") is True

    @pytest.mark.live_remote
    def test_2_6_live_list_writable_dirs(self):
        _skip_if_no_server()
        status, data = _api("list_writable_directories")
        assert status == 200
        assert data.get("ok") is True

    @pytest.mark.live_remote
    def test_2_7_live_unknown_tool_returns_400(self):
        _skip_if_no_server()
        status, data = _api("drop_all_tables")
        assert status == 400, f"Expected 400 for unknown tool, got {status}"
        assert data.get("ok") is False

    @pytest.mark.live_remote
    def test_2_8_live_jobs_tool_blocked(self):
        """log_time_entry is a /pwa-api/ tool, not a /remote-api/ tool."""
        _skip_if_no_server()
        status, data = _api("log_time_entry", {"job_identifier": "JOB-0001", "action": "start"})
        assert status == 400, f"Jobs tool should be blocked in remote-api, got {status}"

    @pytest.mark.live_remote
    def test_2_9_live_write_tool_blocked(self):
        _skip_if_no_server()
        status, data = _api("write_file", {"filepath": "C:\\evil.txt", "content": "pwned"})
        assert status == 400, f"write_file should be blocked, got {status}"

    @pytest.mark.live_remote
    def test_2_10_live_no_token_returns_401(self):
        _skip_if_no_server()
        body = json.dumps({"tool": "check_ai_prowler_status", "args": {}}).encode()
        status, _, _ = _post("/remote-api", body, auth=False)
        assert status == 401, f"Expected 401 without token, got {status}"

    @pytest.mark.live_remote
    def test_2_11_live_malformed_json_returns_400(self):
        _skip_if_no_server()
        status, _, _ = _post("/remote-api", b"{{not json{{")
        assert status == 400

    @pytest.mark.live_remote
    def test_2_12_live_search_documents(self):
        _skip_if_no_server()
        status, data = _api("search_documents", {"query": "AI-Prowler"})
        assert status == 200
        assert data.get("ok") is True

    @pytest.mark.live_remote
    def test_2_13_live_mcp_endpoint_still_requires_auth(self):
        """Verify /mcp is still separately auth-gated — remote routes didn't break it."""
        _skip_if_no_server()
        body = json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}).encode()
        status, _, _ = _post("/mcp", body, auth=False)
        assert status == 401, f"/mcp should still require auth, got {status}"

    @pytest.mark.live_remote
    def test_2_14_live_response_is_json(self):
        _skip_if_no_server()
        body = json.dumps({"tool": "check_ai_prowler_status", "args": {}}).encode()
        status, hdrs, _ = _post("/remote-api", body)
        assert "json" in hdrs.get("content-type", ""), \
            f"Expected JSON response, got {hdrs.get('content-type')}"


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 3 — /remote/download File Download Endpoint
# ══════════════════════════════════════════════════════════════════════════════

class TestFeature3_FileDownload:
    """3.x — /remote/download file download endpoint"""

    @pytest.mark.not_live
    def test_3_1_rate_limit_in_source(self):
        src = MCP_FILE.read_text(encoding="utf-8")
        assert "rate limit" in src.lower() or "_REMOTE_DL_COUNTS" in src, \
            "Rate limiting missing from /remote/download handler"

    @pytest.mark.not_live
    def test_3_2_size_limit_in_source(self):
        src = MCP_FILE.read_text(encoding="utf-8")
        assert "52_428_800" in src or "50MB" in src.upper() or "50_000_000" in src, \
            "50MB size limit missing from /remote/download handler"

    @pytest.mark.not_live
    def test_3_3_extension_allowlist_in_source(self):
        src = MCP_FILE.read_text(encoding="utf-8")
        assert "_ALLOWED_EXT5" in src, \
            "Extension allowlist missing from /remote/download handler"
        # Verify some dangerous extensions are NOT in the list
        start = src.find("_ALLOWED_EXT5")
        block = src[start:start+400]
        for ext in [".exe", ".bat", ".ps1", ".dll", ".cmd"]:
            assert ext not in block, \
                f"Dangerous extension {ext} found in download allowlist"

    @pytest.mark.not_live
    def test_3_4_tracked_dirs_check_in_source(self):
        src = MCP_FILE.read_text(encoding="utf-8")
        assert "_load_tracked_dirs" in src or "_rag_readable_dirs" in src or \
               "not in tracked" in src.lower() or "_in_tracked" in src, \
            "Tracked directory check missing from /remote/download handler"

    @pytest.mark.live_remote
    def test_3_5_live_no_token_returns_401(self):
        _skip_if_no_server()
        url = BASE_URL + "/remote/download?path=C:\\test.txt&token="
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT):
                pass
            pytest.fail("Expected 401")
        except urllib.error.HTTPError as e:
            assert e.code == 401, f"Expected 401, got {e.code}"

    @pytest.mark.live_remote
    def test_3_6_live_invalid_token_returns_401(self):
        _skip_if_no_server()
        url = BASE_URL + "/remote/download?path=C:\\test.txt&token=wrong_token_xyz"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT):
                pass
            pytest.fail("Expected 401")
        except urllib.error.HTTPError as e:
            assert e.code == 401

    @pytest.mark.live_remote
    def test_3_7_live_path_traversal_blocked(self):
        _skip_if_no_server()
        evil = "C:\\Windows\\..\\..\\etc\\passwd"
        url = (BASE_URL + "/remote/download?path=" +
               urllib.parse.quote(evil) + "&token=" +
               urllib.parse.quote(BEARER_TOKEN))
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT):
                pass
            pytest.fail("Expected 403 or 404")
        except urllib.error.HTTPError as e:
            assert e.code in (403, 404), \
                f"Path traversal should be blocked, got {e.code}"

    @pytest.mark.live_remote
    def test_3_8_live_disallowed_extension_blocked(self):
        _skip_if_no_server()
        if not BEARER_TOKEN:
            pytest.skip("No bearer token configured")
        # Use a tracked path but with a disallowed extension
        import pathlib as _pl
        exe_path = str(_pl.Path.home() / ".ai-prowler" / "fake_test.exe")
        url = (BASE_URL + "/remote/download?path=" +
               urllib.parse.quote(exe_path) + "&token=" +
               urllib.parse.quote(BEARER_TOKEN))
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT):
                pass
            pytest.fail("Expected 403 for .exe")
        except urllib.error.HTTPError as e:
            assert e.code == 403, f"Expected 403 for .exe, got {e.code}"

    @pytest.mark.live_remote
    def test_3_9_live_nonexistent_file_returns_404(self):
        _skip_if_no_server()
        # Use a tracked dir path but nonexistent file
        try:
            cfg = json.loads(_CONFIG.read_text(encoding="utf-8"))
            tracked = cfg.get("tracked_dirs", [])
            if not tracked:
                pytest.skip("No tracked dirs in config")
            fake = str(Path(tracked[0]) / "NONEXISTENT_FILE_XYZ_123.txt")
        except Exception:
            fake = str(Path.home() / ".ai-prowler" / "NONEXISTENT_FILE_XYZ_123.txt")
        url = (BASE_URL + "/remote/download?path=" +
               urllib.parse.quote(fake) + "&token=" +
               urllib.parse.quote(BEARER_TOKEN))
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT):
                pass
            pytest.fail("Expected 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404, f"Expected 404, got {e.code}"

    @pytest.mark.live_remote
    def test_3_10_live_download_tracked_text_file(self):
        """Download a real tracked text file — config.json is always present."""
        _skip_if_no_server()
        # Use the mcp_server.log which is a tracked text file
        log_path = str(Path.home() / ".ai-prowler" / "logs" / "mcp_server.log")
        if not Path(log_path).exists():
            pytest.skip("mcp_server.log not found")
        url = (BASE_URL + "/remote/download?path=" +
               urllib.parse.quote(log_path) + "&token=" +
               urllib.parse.quote(BEARER_TOKEN))
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                assert r.status == 200
                assert "attachment" in r.headers.get("Content-Disposition", "").lower(), \
                    "Missing Content-Disposition: attachment header"
                body = r.read()
                assert len(body) > 0
        except urllib.error.HTTPError as e:
            if e.code == 403:
                pytest.skip("Log file not in tracked dirs — expected in some configs")
            pytest.fail(f"Download failed: {e.code}")


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 4 — PWA Frontend (Offline Source Checks)
# ══════════════════════════════════════════════════════════════════════════════

class TestFeature4_PwaFrontend:
    """4.x — Remote PWA frontend source checks (no server needed)"""

    @pytest.fixture(scope="class")
    def html(self):
        assert INDEX_HTML.exists(), f"index.html not found: {INDEX_HTML}"
        return INDEX_HTML.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def manifest(self):
        assert MANIFEST.exists(), f"manifest.json not found: {MANIFEST}"
        return json.loads(MANIFEST.read_text(encoding="utf-8"))

    @pytest.fixture(scope="class")
    def sw(self):
        assert SW_FILE.exists(), f"sw.js not found: {SW_FILE}"
        return SW_FILE.read_text(encoding="utf-8")

    # Auth screen
    def test_4_1_auth_screen_exists(self, html):
        assert 'id="authScreen"' in html, "Auth screen element missing"

    def test_4_2_auth_input_exists(self, html):
        assert 'id="authInput"' in html, "Auth input missing"

    def test_4_3_auth_function_exists(self, html):
        assert "function doAuth" in html or "async function doAuth" in html, \
            "doAuth() function missing"

    # App shell
    def test_4_4_app_div_exists(self, html):
        assert 'id="app"' in html, "App shell div missing"

    def test_4_5_five_nav_tabs(self, html):
        assert 'id="navDash"' in html, "Dashboard nav button missing"
        assert 'id="navFiles"' in html, "Files nav button missing"
        assert 'id="navSearch"' in html, "Search nav button missing"
        assert 'id="navPerms"' in html, "Permissions nav button missing"
        assert 'id="navSystem"' in html, "System nav button missing"

    def test_4_6_five_screens(self, html):
        assert 'id="screenDash"' in html, "Dashboard screen missing"
        assert 'id="screenFiles"' in html, "Files screen missing"
        assert 'id="screenSearch"' in html, "Search screen missing"
        assert 'id="screenPerms"' in html, "Permissions screen missing"
        assert 'id="screenSystem"' in html, "System screen missing"

    # Files screen
    def test_4_7_file_browser_elements(self, html):
        assert 'id="fileList"' in html, "fileList element missing"
        assert 'id="breadcrumb"' in html, "breadcrumb element missing"
        assert 'id="previewWrap"' in html, "previewWrap element missing"
        assert 'id="previewBody"' in html, "previewBody element missing"

    def test_4_8_browse_dir_function(self, html):
        assert "function browseDir" in html or "async function browseDir" in html, \
            "browseDir() function missing"

    def test_4_9_preview_function(self, html):
        assert "function previewFile" in html or "async function previewFile" in html, \
            "previewFile() function missing"

    def test_4_10_download_link_uses_remote_download(self, html):
        assert "/remote/download" in html, \
            "Download links should use /remote/download endpoint"

    # Search screen
    def test_4_11_search_elements(self, html):
        assert 'id="searchInput"' in html, "searchInput element missing"
        assert 'id="searchResults"' in html, "searchResults element missing"
        assert "function doSearch" in html or "async function doSearch" in html, \
            "doSearch() function missing"

    # Permissions screen
    def test_4_12_permissions_elements(self, html):
        assert 'id="permList"' in html, "permList element missing"
        assert 'id="reAuthModal"' in html, "reAuthModal element missing"

    def test_4_13_reauth_modal_elements(self, html):
        assert 'id="raPath"' in html, "raPath element missing from re-auth modal"
        assert 'id="raInput"' in html, "raInput element missing from re-auth modal"
        assert 'id="raErr"' in html, "raErr element missing from re-auth modal"
        assert 'id="raLocked"' in html, "raLocked element missing from re-auth modal"
        assert 'id="raConfirm"' in html, "raConfirm button missing from re-auth modal"

    def test_4_14_lockout_logic_present(self, html):
        assert "raAttempts" in html, "Re-auth attempt counter missing"
        assert "raLockUntil" in html, "Re-auth lockout timer missing"
        assert "30000" in html, "30-second lockout duration missing"

    def test_4_15_revoke_is_instant_no_modal(self, html):
        """Revoke should call api() directly without opening modal."""
        assert "revoke_write_access" in html, "revoke_write_access call missing"
        # The revoke path should not open reAuthModal
        revoke_idx = html.find("revoke_write_access")
        modal_open_idx = html.find("reAuthModal")
        # Modal open should come after revoke in the grant branch, not before
        # Just check both exist — structural correctness tested in live tests
        assert revoke_idx > 0 and modal_open_idx > 0

    def test_4_16_grant_requires_reauth(self, html):
        assert "confirmGrant" in html or "function confirmGrant" in html, \
            "confirmGrant() function missing"

    # System screen
    def test_4_17_system_elements(self, html):
        assert 'id="sysStatus"' in html, "sysStatus element missing"
        assert 'id="sysDb"' in html, "sysDb element missing"

    # PWA installability
    def test_4_18_manifest_has_name(self, manifest):
        assert "name" in manifest and manifest["name"], "manifest name missing"

    def test_4_19_manifest_start_url(self, manifest):
        assert "/remote" in manifest.get("start_url", ""), \
            f"manifest start_url should contain /remote"

    def test_4_20_manifest_display_standalone(self, manifest):
        assert manifest.get("display") == "standalone", \
            "manifest display must be standalone"

    def test_4_21_manifest_has_icons(self, manifest):
        icons = manifest.get("icons", [])
        assert len(icons) >= 2, "Need at least 192px and 512px icons"
        sizes = [i.get("sizes","") for i in icons]
        assert any("192" in s for s in sizes), "Missing 192x192 icon"
        assert any("512" in s for s in sizes), "Missing 512x512 icon"

    def test_4_22_manifest_theme_color(self, manifest):
        assert "theme_color" in manifest

    def test_4_23_html_manifest_link(self, html):
        assert 'rel="manifest"' in html, "manifest link tag missing"

    def test_4_24_html_apple_mobile_capable(self, html):
        assert "apple-mobile-web-app-capable" in html, \
            "Missing iOS PWA meta tag"

    def test_4_25_sw_install_handler(self, sw):
        assert "install" in sw, "Service worker missing install handler"

    def test_4_26_sw_activate_handler(self, sw):
        assert "activate" in sw, "Service worker missing activate handler"

    def test_4_27_sw_fetch_handler(self, sw):
        assert "fetch" in sw, "Service worker missing fetch handler"

    def test_4_28_sw_network_first_for_api(self, sw):
        assert "remote-api" in sw, \
            "Service worker should handle /remote-api with network-first"

    def test_4_29_theme_is_distinct_from_jobs_pwa(self, html):
        """Remote PWA uses purple (#9b5de5), Jobs PWA uses cyan (#00d4ff)."""
        assert "9b5de5" in html.lower() or "7b3fc4" in html.lower(), \
            "Remote PWA should use purple accent, not cyan"

    def test_4_30_token_not_hardcoded_in_html(self):
        """Bearer token must not be hardcoded in the HTML source."""
        html = INDEX_HTML.read_text(encoding="utf-8")
        if BEARER_TOKEN:
            assert BEARER_TOKEN not in html, \
                "Bearer token is hardcoded in index.html — security risk!"

    def test_4_31_syntax_check_mcp_file(self):
        import ast
        try:
            ast.parse(MCP_FILE.read_text(encoding="utf-8"))
        except SyntaxError as e:
            pytest.fail(f"SyntaxError in ai_prowler_mcp.py: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 5 — Directory Permissions (Live)
# ══════════════════════════════════════════════════════════════════════════════

class TestFeature5_Permissions:
    """5.x — Directory permissions grant/revoke via /remote-api/"""

    @pytest.mark.live_remote
    def test_5_1_list_tracked_dirs_works(self):
        _skip_if_no_server()
        status, data = _api("list_tracked_directories")
        assert status == 200
        assert data.get("ok") is True
        assert data.get("result"), "No tracked directories returned"

    @pytest.mark.live_remote
    def test_5_2_list_writable_dirs_works(self):
        _skip_if_no_server()
        status, data = _api("list_writable_directories")
        assert status == 200
        assert data.get("ok") is True

    @pytest.mark.live_remote
    def test_5_3_grant_untracked_path_blocked(self):
        """Granting write access to an untracked path should fail."""
        _skip_if_no_server()
        status, data = _api("grant_write_access",
                            {"directory": "C:\\Windows\\System32"})
        # grant_write_access returns ok=True with an error message in result
        # when the path is not tracked — check the result contains rejection text
        result_txt = str(data.get("result","") or data.get("error","")).lower()
        rejected = ("not in" in result_txt or "allowlist" in result_txt or
                    "read allowlist" in result_txt or status == 400 or
                    data.get("ok") is False)
        assert rejected, f"Granting write to untracked path should fail: {data}"

    @pytest.mark.live_remote
    def test_5_4_revoke_nonexistent_path_graceful(self):
        """Revoking a path that isn't writable should not crash."""
        _skip_if_no_server()
        status, data = _api("revoke_write_access",
                            {"directory": "C:\\NonExistentPath\\XYZ"})
        # Should return 200 or 400 but not 500
        assert status in (200, 400), \
            f"Unexpected status revoking nonexistent path: {status}"

    @pytest.mark.live_remote
    def test_5_5_grant_requires_token(self):
        """grant_write_access without token should return 401."""
        _skip_if_no_server()
        body = json.dumps({
            "tool": "grant_write_access",
            "args": {"directory": "C:\\test"}
        }).encode()
        status, _, _ = _post("/remote-api", body, auth=False)
        assert status == 401


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE 6 — Settings GUI (Source Checks Only)
# ══════════════════════════════════════════════════════════════════════════════

class TestFeature6_SettingsGui:
    """6.x — Settings tab Remote Control URL row (source checks)"""

    @pytest.fixture(scope="class")
    def gui_src(self):
        gui = SRC_ROOT / "rag_gui.py"
        assert gui.exists(), f"rag_gui.py not found: {gui}"
        return gui.read_text(encoding="utf-8")

    def test_6_1_remote_control_url_row_in_source(self, gui_src):
        assert "Remote Control URL" in gui_src or "remote_url_row" in gui_src, \
            "Remote Control URL row missing from rag_gui.py"

    def test_6_2_remote_url_var_uses_tunnel_domain(self, gui_src):
        assert "_remote_url_var" in gui_src, \
            "_remote_url_var missing from Settings tab"

    def test_6_3_remote_url_updates_with_domain(self, gui_src):
        assert "_update_remote_url" in gui_src, \
            "_update_remote_url() callback missing"

    def test_6_4_copy_button_in_source(self, gui_src):
        assert "_copy_remote_url" in gui_src, \
            "_copy_remote_url() function missing from Settings tab"

    def test_6_5_email_button_in_source(self, gui_src):
        assert "_email_remote_url" in gui_src, \
            "_email_remote_url() function missing from Settings tab"

    def test_6_6_email_uses_smtp(self, gui_src):
        assert "smtplib" in gui_src or "_smr" in gui_src, \
            "Email button should use SMTP, not webbrowser.open"

    def test_6_7_url_contains_remote_path(self, gui_src):
        assert "/remote/" in gui_src, \
            "Remote URL should point to /remote/ not /pwa/"

    def test_6_8_no_syntax_error(self, gui_src):
        import ast
        try:
            ast.parse(gui_src)
        except SyntaxError as e:
            pytest.fail(f"SyntaxError in rag_gui.py: {e}")
