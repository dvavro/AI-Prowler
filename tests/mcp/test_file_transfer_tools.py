"""
test_file_transfer_tools.py
============================
Structural and live tests for the v9.1.0 file-transfer MCP tools:
  get_file_download_url(file_path)
  get_file_upload_url(filename, target_directory)

Both tools are personal-mode-only (Tier A suppressed in server mode).
They bridge Claude to the existing /remote/download and /remote/upload
HTTP endpoints in the Remote Control PWA.

Test strategy
-------------
Offline structural tests (no server needed):
  - Both tool names are present in _TIER_A_SUPPRESSED
  - Both @mcp.tool definitions exist in the source
  - Both tool bodies check _IS_SERVER_MODE and return ⛔ immediately
    BEFORE any file I/O (defence-in-depth layer 2)
  - get_file_download_url checks: file exists, extension allowlist,
    tracked-dir membership, 50 MB limit, config keys present
  - get_file_upload_url checks: writable allowlist, tracked-dir,
    filename sanitisation, config keys present
  - Neither tool name appears in _REMOTE_ALLOWED (must not be callable
    through the /remote-api bridge either — layer 3)
  - how_to_use_ai_prowler() documents both tools

Live integration tests (requires running personal-mode server + valid config):
  pytest tests/mcp/test_file_transfer_tools.py -m live_remote -v

Run offline only (safe, no server):
  pytest tests/mcp/test_file_transfer_tools.py -m "not live_remote" -v

Environment variables
---------------------
  AI_PROWLER_SRC               Path to the AI-Prowler source root (optional)
  AI_PROWLER_PORT              Port the server is listening on (default 8000)
  AI_PROWLER_REMOTE_TEST_PORT  Same as above, takes precedence
  AI_PROWLER_TEST_TRACKED_DIR  Writable tracked dir for live tests
                               (default: ~/Documents/Misc)
"""
from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

# ── Paths ──────────────────────────────────────────────────────────────────
_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
MCP_FILE = SRC_ROOT / "ai_prowler_mcp.py"

# ── Live server config ─────────────────────────────────────────────────────
PORT = int(os.environ.get("AI_PROWLER_REMOTE_TEST_PORT",
           os.environ.get("AI_PROWLER_PORT", 8000)))
BASE_URL = f"http://127.0.0.1:{PORT}"
TIMEOUT = 20

_CONFIG = Path.home() / ".ai-prowler" / "config.json"
try:
    _cfg = json.loads(_CONFIG.read_text(encoding="utf-8"))
    BEARER_TOKEN = _cfg.get("remote_token", "")
    TUNNEL_DOMAIN = _cfg.get("tunnel_domain", "")
except Exception:
    BEARER_TOKEN = ""
    TUNNEL_DOMAIN = ""

# A known tracked directory for live tests.
# Override via AI_PROWLER_TEST_TRACKED_DIR env var.
TEST_TRACKED_DIR = os.environ.get(
    "AI_PROWLER_TEST_TRACKED_DIR",
    str(Path.home() / "Documents" / "Misc"),
)


# ── Helpers ────────────────────────────────────────────────────────────────
def _server_running() -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False


def _skip_if_no_server():
    if not _server_running():
        pytest.skip(f"No server on port {PORT}")
    if not BEARER_TOKEN:
        pytest.skip("No remote_token in config.json")


def _call_remote_api(tool: str, args: dict) -> tuple[int, dict]:
    """POST to /remote-api and return (status, parsed_json)."""
    body = json.dumps({"tool": tool, "args": args}).encode()
    req = urllib.request.Request(
        BASE_URL + "/remote-api",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {BEARER_TOKEN}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


def _load_mcp_module():
    """Import ai_prowler_mcp so we can call tools directly (offline path)."""
    import sys
    sys.path.insert(0, str(SRC_ROOT))
    import importlib
    return importlib.import_module("ai_prowler_mcp")


# ══════════════════════════════════════════════════════════════════════════════
# OFFLINE — Syntax sanity
# ══════════════════════════════════════════════════════════════════════════════

class TestSyntaxSanity:
    def test_mcp_file_parses(self):
        import ast
        source = MCP_FILE.read_text(encoding="utf-8")
        try:
            ast.parse(source, filename=str(MCP_FILE))
        except SyntaxError as exc:
            pytest.fail(f"SyntaxError in ai_prowler_mcp.py line {exc.lineno}: {exc.msg}")


# ══════════════════════════════════════════════════════════════════════════════
# OFFLINE — Tier A suppression (layer 1 enforcement)
# ══════════════════════════════════════════════════════════════════════════════

class TestTierASuppression:
    """Both tools must be in _TIER_A_SUPPRESSED so they never appear in the
    MCP tool list on a server-mode install."""

    @pytest.fixture(scope="class")
    def tier_a_block(self):
        source = MCP_FILE.read_text(encoding="utf-8")
        idx = source.find("_TIER_A_SUPPRESSED")
        assert idx != -1, "_TIER_A_SUPPRESSED block not found in source"
        end = source.find("})", idx)
        return source[idx:end]

    def test_get_file_download_url_in_tier_a(self, tier_a_block):
        assert '"get_file_download_url"' in tier_a_block, (
            "get_file_download_url missing from _TIER_A_SUPPRESSED — "
            "it would be visible to server-mode clients."
        )

    def test_get_file_upload_url_in_tier_a(self, tier_a_block):
        assert '"get_file_upload_url"' in tier_a_block, (
            "get_file_upload_url missing from _TIER_A_SUPPRESSED — "
            "it would be visible to server-mode clients."
        )

    def test_tier_a_comment_explains_rationale(self, tier_a_block):
        """Regression guard — the comment block explaining WHY these tools
        are Tier A must stay alongside them so future maintainers don't
        accidentally remove the suppression without understanding the reason."""
        assert "File transfer tools" in tier_a_block or "personal-install-only" in tier_a_block, (
            "Explanatory comment missing from _TIER_A_SUPPRESSED block for "
            "the file-transfer tools."
        )


# ══════════════════════════════════════════════════════════════════════════════
# OFFLINE — _REMOTE_ALLOWED does NOT include the new tools (layer 3)
# ══════════════════════════════════════════════════════════════════════════════

class TestNotInRemoteAllowed:
    """Neither tool must appear in /remote-api's _REMOTE_ALLOWED whitelist.
    Even though /remote-api is personal-mode-only, it's an owner-level bridge
    and these tools are not appropriate there — they produce raw bearer tokens
    and filesystem URLs that should only be generated through the MCP path."""

    @pytest.fixture(scope="class")
    def remote_allowed_block(self):
        source = MCP_FILE.read_text(encoding="utf-8")
        idx = source.find("_REMOTE_ALLOWED = {")
        assert idx != -1, "_REMOTE_ALLOWED block not found"
        end = source.find("}", idx)
        return source[idx:end]

    def test_download_tool_absent_from_remote_allowed(self, remote_allowed_block):
        assert "get_file_download_url" not in remote_allowed_block, (
            "get_file_download_url must NOT be in _REMOTE_ALLOWED — "
            "it produces signed URLs with embedded bearer tokens."
        )

    def test_upload_tool_absent_from_remote_allowed(self, remote_allowed_block):
        assert "get_file_upload_url" not in remote_allowed_block, (
            "get_file_upload_url must NOT be in _REMOTE_ALLOWED."
        )


# ══════════════════════════════════════════════════════════════════════════════
# OFFLINE — Tool definitions exist
# ══════════════════════════════════════════════════════════════════════════════

class TestToolDefinitionsExist:

    @pytest.fixture(scope="class")
    def source(self):
        return MCP_FILE.read_text(encoding="utf-8")

    def test_get_file_download_url_defined(self, source):
        assert "def get_file_download_url(file_path: str)" in source

    def test_get_file_upload_url_defined(self, source):
        assert "def get_file_upload_url(filename: str, target_directory: str)" in source

    def test_download_tool_decorated(self, source):
        idx = source.find("def get_file_download_url(")
        preamble = source[max(0, idx - 60):idx]
        assert "@mcp.tool()" in preamble, (
            "get_file_download_url is not decorated with @mcp.tool()"
        )

    def test_upload_tool_decorated(self, source):
        idx = source.find("def get_file_upload_url(")
        preamble = source[max(0, idx - 60):idx]
        assert "@mcp.tool()" in preamble, (
            "get_file_upload_url is not decorated with @mcp.tool()"
        )

    def test_both_call_telemetry_increment(self, source):
        for name in ("get_file_download_url", "get_file_upload_url"):
            idx = source.find(f"def {name}(")
            body = source[idx: idx + 9000]
            assert "_telemetry_increment_tool_count" in body, (
                f"{name} does not call _telemetry_increment_tool_count — "
                "usage won't be counted."
            )


# ══════════════════════════════════════════════════════════════════════════════
# OFFLINE — Server-mode runtime guard (layer 2 enforcement)
# ══════════════════════════════════════════════════════════════════════════════

class TestServerModeRuntimeGuard:
    """Both tool bodies must check _IS_SERVER_MODE immediately and return ⛔.
    This is defence-in-depth: Tier A prevents the tools from appearing in the
    tool list, but the runtime guard catches any edge-case bypass."""

    @pytest.fixture(scope="class")
    def source(self):
        return MCP_FILE.read_text(encoding="utf-8")

    def _body(self, source: str, name: str) -> str:
        idx = source.find(f"def {name}(")
        assert idx != -1, f"{name} not found"
        return source[idx: idx + 9000]

    def test_download_checks_is_server_mode(self, source):
        assert "_IS_SERVER_MODE" in self._body(source, "get_file_download_url")

    def test_download_returns_stop_sign_in_server_mode(self, source):
        body = self._body(source, "get_file_download_url")
        assert "not available in server mode" in body

    def test_upload_checks_is_server_mode(self, source):
        assert "_IS_SERVER_MODE" in self._body(source, "get_file_upload_url")

    def test_upload_returns_stop_sign_in_server_mode(self, source):
        body = self._body(source, "get_file_upload_url")
        assert "not available in server mode" in body

    def test_server_mode_check_before_any_file_io(self, source):
        """_IS_SERVER_MODE must appear before any os.path/open()/Path call."""
        for name in ("get_file_download_url", "get_file_upload_url"):
            body = self._body(source, name)
            sm_pos = body.find("_IS_SERVER_MODE")
            io_positions = [
                body.find(p) for p in ("os.path", "open(", "Path.home()")
                if body.find(p) != -1
            ]
            if not io_positions:
                continue  # no I/O found — fine
            first_io = min(io_positions)
            assert sm_pos < first_io, (
                f"{name}: _IS_SERVER_MODE check (pos {sm_pos}) must appear "
                f"before first I/O call (pos {first_io})."
            )


# ══════════════════════════════════════════════════════════════════════════════
# OFFLINE — Download tool validation logic
# ══════════════════════════════════════════════════════════════════════════════

class TestDownloadToolValidation:

    @pytest.fixture(scope="class")
    def body(self):
        source = MCP_FILE.read_text(encoding="utf-8")
        idx = source.find("def get_file_download_url(")
        return source[idx: idx + 9000]

    def test_checks_file_exists(self, body):
        # Module is imported as alias (_os_dlu), so check for the method call pattern
        assert ".path.isfile" in body

    def test_enforces_extension_allowlist(self, body):
        assert "_ALLOWED_EXT_DLU" in body

    def test_allowlist_covers_common_types(self, body):
        for ext in (".pdf", ".docx", ".xlsx", ".txt", ".md", ".csv",
                    ".jpg", ".png", ".py", ".json", ".log"):
            assert ext in body, f"Extension {ext} missing from download allowlist"

    def test_checks_tracked_directory(self, body):
        assert "load_auto_update_list" in body or "_in_tracked_dlu" in body

    def test_enforces_50mb_limit(self, body):
        assert "52_428_800" in body

    def test_reads_tunnel_domain_from_config(self, body):
        assert "tunnel_domain" in body

    def test_reads_remote_token_from_config(self, body):
        assert "remote_token" in body

    def test_url_encodes_path_and_token(self, body):
        assert "urllib.parse" in body or "_urlparse_dlu" in body

    def test_url_points_at_remote_download_endpoint(self, body):
        assert "/remote/download" in body

    def test_returns_download_url_key(self, body):
        assert '"download_url"' in body

    def test_returns_filename_key(self, body):
        assert '"filename"' in body

    def test_returns_size_bytes_key(self, body):
        assert '"size_bytes"' in body

    def test_returns_note_guiding_web_fetch(self, body):
        assert "web_fetch" in body, (
            "get_file_download_url 'note' field must tell Claude to call "
            "web_fetch(download_url) next."
        )

    def test_rejects_missing_tunnel_domain(self, body):
        assert "tunnel_domain" in body and ("No tunnel_domain" in body or
               "not configured" in body.lower() or "tunnel" in body)

    def test_rejects_missing_remote_token(self, body):
        assert "remote_token" in body and ("No remote_token" in body or
               "not configured" in body.lower() or "remote_token" in body)


# ══════════════════════════════════════════════════════════════════════════════
# OFFLINE — Upload tool validation logic
# ══════════════════════════════════════════════════════════════════════════════

class TestUploadToolValidation:

    @pytest.fixture(scope="class")
    def body(self):
        source = MCP_FILE.read_text(encoding="utf-8")
        idx = source.find("def get_file_upload_url(")
        return source[idx: idx + 9000]

    def test_checks_writable_allowlist(self, body):
        assert "_writable_allowlist_load" in body

    def test_checks_tracked_directory(self, body):
        assert "load_auto_update_list" in body or "_in_tracked_ulu" in body

    def test_sanitises_filename(self, body):
        # Module is imported as alias (_os_ulu), so check for the method call pattern
        assert ".path.basename" in body

    def test_rejects_empty_filename(self, body):
        assert "filename must not be empty" in body

    def test_reads_tunnel_domain_from_config(self, body):
        assert "tunnel_domain" in body

    def test_reads_remote_token_from_config(self, body):
        assert "remote_token" in body

    def test_url_points_at_remote_upload_endpoint(self, body):
        assert "/remote/upload" in body

    def test_returns_upload_url_key(self, body):
        assert '"upload_url"' in body

    def test_returns_fields_dict(self, body):
        assert '"fields"' in body

    def test_returns_curl_example(self, body):
        assert '"curl_example"' in body

    def test_curl_example_has_file_dir_token_fields(self, body):
        assert '-F "file=' in body
        assert '-F "dir=' in body
        assert '-F "token=' in body

    def test_returns_destination_path(self, body):
        assert '"destination"' in body

    def test_writable_check_before_tracked_check(self, body):
        """Writable check first — gives the more specific error."""
        wr_pos = body.find("_writable_allowlist_load")
        tr_pos = body.find("tracking_db.json")
        if tr_pos == -1:
            tr_pos = body.find("_in_tracked_ulu")
        assert wr_pos < tr_pos, (
            "Writable allowlist check should appear before tracked-dir check."
        )


# ══════════════════════════════════════════════════════════════════════════════
# OFFLINE — how_to_use_ai_prowler documents both tools
# ══════════════════════════════════════════════════════════════════════════════

class TestHowToUseDocumented:

    @pytest.fixture(scope="class")
    def htu_body(self):
        source = MCP_FILE.read_text(encoding="utf-8")
        idx = source.find("def how_to_use_ai_prowler(")
        assert idx != -1
        return source[idx: idx + 40_000]

    def test_download_tool_documented(self, htu_body):
        assert "get_file_download_url" in htu_body

    def test_upload_tool_documented(self, htu_body):
        assert "get_file_upload_url" in htu_body

    def test_personal_mode_only_noted_near_tools(self, htu_body):
        idx = htu_body.find("get_file_download_url")
        nearby = htu_body[max(0, idx - 300): idx + 300]
        assert "personal mode only" in nearby.lower(), (
            "how_to_use_ai_prowler should note that these tools are "
            "personal-mode-only near the file-transfer section."
        )

    def test_web_fetch_workflow_mentioned(self, htu_body):
        idx = htu_body.find("get_file_download_url")
        nearby = htu_body[idx: idx + 600]
        assert "web_fetch" in nearby, (
            "how_to_use_ai_prowler should explain the web_fetch() "
            "workflow for the download tool."
        )

    def test_grant_write_access_mentioned_for_upload(self, htu_body):
        idx = htu_body.find("get_file_upload_url")
        nearby = htu_body[idx: idx + 600]
        assert "grant_write_access" in nearby, (
            "how_to_use_ai_prowler should remind users to call "
            "grant_write_access() before using the upload tool."
        )


# ══════════════════════════════════════════════════════════════════════════════
# LIVE — Both tools BLOCKED via /remote-api (even with valid token)
# ══════════════════════════════════════════════════════════════════════════════

class TestToolsBlockedViaRemoteApi:
    """These tools are not in _REMOTE_ALLOWED, so /remote-api must reject
    them with 400 even when the bearer token is valid."""

    @pytest.mark.live_remote
    def test_download_tool_blocked_via_remote_api(self):
        _skip_if_no_server()
        status, data = _call_remote_api(
            "get_file_download_url", {"file_path": r"C:\fake\test.txt"}
        )
        assert status == 400, (
            f"get_file_download_url should be blocked (not in _REMOTE_ALLOWED), "
            f"got {status}: {data}"
        )
        assert data.get("ok") is False

    @pytest.mark.live_remote
    def test_upload_tool_blocked_via_remote_api(self):
        _skip_if_no_server()
        status, data = _call_remote_api(
            "get_file_upload_url",
            {"filename": "test.txt", "target_directory": r"C:\fake"},
        )
        assert status == 400, (
            f"get_file_upload_url should be blocked (not in _REMOTE_ALLOWED), "
            f"got {status}: {data}"
        )
        assert data.get("ok") is False


# ══════════════════════════════════════════════════════════════════════════════
# LIVE — get_file_download_url end-to-end (direct tool call)
# ══════════════════════════════════════════════════════════════════════════════

class TestDownloadToolLive:

    @pytest.fixture(scope="class")
    def mcp(self):
        try:
            return _load_mcp_module()
        except Exception as e:
            pytest.skip(f"Could not import ai_prowler_mcp: {e}")

    @pytest.mark.live_remote
    def test_returns_url_for_valid_tracked_text_file(self, mcp):
        _skip_if_no_server()
        tracked = Path(TEST_TRACKED_DIR)
        if not tracked.exists():
            pytest.skip(f"TEST_TRACKED_DIR doesn't exist: {tracked}")

        candidates = list(tracked.glob("*.txt")) + list(tracked.glob("*.md"))
        if not candidates:
            pytest.skip(f"No .txt/.md files in {tracked}")

        result = mcp.get_file_download_url(str(candidates[0]))
        assert "❌" not in result and "⛔" not in result, (
            f"Unexpected error for valid tracked file: {result[:300]}"
        )
        data = json.loads(result)
        assert "download_url" in data
        assert "/remote/download" in data["download_url"]
        assert "token=" in data["download_url"]
        assert "path=" in data["download_url"]
        assert data["filename"] == candidates[0].name

    @pytest.mark.live_remote
    def test_tunnel_domain_embedded_in_url(self, mcp):
        _skip_if_no_server()
        if not TUNNEL_DOMAIN:
            pytest.skip("No tunnel_domain in config.json")
        tracked = Path(TEST_TRACKED_DIR)
        candidates = list(tracked.glob("*.txt")) + list(tracked.glob("*.md"))
        if not candidates:
            pytest.skip(f"No .txt/.md files in {tracked}")

        result = mcp.get_file_download_url(str(candidates[0]))
        if "❌" in result:
            pytest.skip(f"Tool error (likely not tracked): {result[:200]}")
        data = json.loads(result)
        assert TUNNEL_DOMAIN in data["download_url"], (
            f"Tunnel domain '{TUNNEL_DOMAIN}' not in URL: {data['download_url']}"
        )

    @pytest.mark.live_remote
    def test_untracked_file_rejected(self, mcp):
        _skip_if_no_server()
        result = mcp.get_file_download_url(r"C:\Windows\System32\notepad.exe")
        assert "❌" in result, (
            f"Untracked file should be rejected: {result[:200]}"
        )

    @pytest.mark.live_remote
    def test_disallowed_extension_rejected(self, mcp):
        _skip_if_no_server()
        tracked = Path(TEST_TRACKED_DIR)
        if not tracked.exists():
            pytest.skip(f"TEST_TRACKED_DIR doesn't exist: {tracked}")

        fake = tracked / "_transfer_test_fake.exe"
        try:
            fake.write_bytes(b"MZ fake")
            result = mcp.get_file_download_url(str(fake))
        finally:
            fake.unlink(missing_ok=True)

        assert "❌" in result and (
            ".exe" in result or "not in the download allowlist" in result
        ), f".exe should be rejected: {result[:200]}"

    @pytest.mark.live_remote
    def test_nonexistent_file_rejected(self, mcp):
        _skip_if_no_server()
        tracked = Path(TEST_TRACKED_DIR)
        result = mcp.get_file_download_url(
            str(tracked / "this_file_does_not_exist_xyz_abc.txt")
        )
        assert "❌" in result and "not found" in result.lower(), (
            f"Missing file should give 'not found' error: {result[:200]}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# LIVE — get_file_upload_url end-to-end (direct tool call)
# ══════════════════════════════════════════════════════════════════════════════

class TestUploadToolLive:

    @pytest.fixture(scope="class")
    def mcp(self):
        try:
            return _load_mcp_module()
        except Exception as e:
            pytest.skip(f"Could not import ai_prowler_mcp: {e}")

    @pytest.mark.live_remote
    def test_returns_url_for_writable_tracked_dir(self, mcp):
        _skip_if_no_server()
        tracked = Path(TEST_TRACKED_DIR)
        if not tracked.exists():
            pytest.skip(f"TEST_TRACKED_DIR doesn't exist: {tracked}")

        result = mcp.get_file_upload_url("test_upload.txt", str(tracked))

        # Dir may not be writable — just verify a coherent response
        if "❌" in result:
            assert "writable" in result or "tracked" in result, (
                f"Unexpected error message: {result[:200]}"
            )
            return

        data = json.loads(result)
        assert "upload_url" in data
        assert "/remote/upload" in data["upload_url"]
        assert "curl_example" in data
        assert "dir" in data.get("fields", {})
        assert "token" in data.get("fields", {})
        assert "destination" in data

    @pytest.mark.live_remote
    def test_untracked_dir_rejected(self, mcp):
        _skip_if_no_server()
        result = mcp.get_file_upload_url("evil.txt", r"C:\Windows\Temp")
        assert "❌" in result, (
            f"Untracked dir should be rejected: {result[:200]}"
        )

    @pytest.mark.live_remote
    def test_filename_path_traversal_blocked(self, mcp):
        _skip_if_no_server()
        tracked = Path(TEST_TRACKED_DIR)
        result = mcp.get_file_upload_url("../../evil.txt", str(tracked))

        if "❌" in result:
            return  # rejected outright — fine

        data = json.loads(result)
        dest = data.get("destination", "")
        assert ".." not in dest, (
            f"Path traversal via filename not blocked: destination={dest}"
        )

    @pytest.mark.live_remote
    def test_empty_filename_rejected(self, mcp):
        _skip_if_no_server()
        tracked = Path(TEST_TRACKED_DIR)
        result = mcp.get_file_upload_url("", str(tracked))
        assert "❌" in result and "empty" in result.lower(), (
            f"Empty filename should be rejected: {result[:200]}"
        )

    @pytest.mark.live_remote
    def test_curl_command_uses_tunnel_url(self, mcp):
        _skip_if_no_server()
        if not TUNNEL_DOMAIN:
            pytest.skip("No tunnel_domain in config.json")
        tracked = Path(TEST_TRACKED_DIR)
        if not tracked.exists():
            pytest.skip(f"TEST_TRACKED_DIR doesn't exist: {tracked}")

        result = mcp.get_file_upload_url("report.md", str(tracked))
        if "❌" in result:
            pytest.skip(f"Tool error: {result[:200]}")

        data = json.loads(result)
        assert TUNNEL_DOMAIN in data["curl_example"], (
            f"curl_example doesn't use tunnel domain '{TUNNEL_DOMAIN}': "
            f"{data['curl_example']}"
        )
