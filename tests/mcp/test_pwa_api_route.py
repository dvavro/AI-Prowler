"""
test_pwa_api_route.py
=====================
Regression tests for the /pwa-api endpoint added to _RouterASGI.

What this tests
---------------
The PWA cannot call /mcp directly because FastMCP uses the Streamable HTTP
MCP protocol (not raw JSON-RPC), and requires specific headers + protocol
handshake. Sending raw JSON-RPC to /mcp returns 403.

The fix is a dedicated /pwa-api endpoint that:
  1. Requires no auth (Bearer token fetched separately via /pwa-token)
  2. Accepts simple JSON: {"tool": "tool_name", "args": {...}}
  3. Calls the tool function directly in Python
  4. Returns {"ok": true, "result": "..."} or {"ok": false, "error": "..."}

These tests verify:
  1. The /pwa-api route is present in the source
  2. It sits before the Bearer token check (no auth required from browser)
  3. The request format is simple JSON not MCP protocol
  4. A simulated ASGI call returns 200 with correct JSON structure
  5. Missing tool returns {"ok": false, "error": ...}
  6. The route does not break existing /mcp or /pwa routes

Run with:
    pytest tests/mcp/test_pwa_api_route.py -v

Safe — does NOT start AI-Prowler, touch install dir, or require live server.
"""
from __future__ import annotations

import ast
import asyncio
import json
import os
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
if _SRC:
    SRC_ROOT = Path(_SRC).resolve()
else:
    SRC_ROOT = Path(__file__).resolve().parent.parent.parent

MCP_FILE = SRC_ROOT / "ai_prowler_mcp.py"


# ══════════════════════════════════════════════════════════════════════════
# 1. SYNTAX CHECK — must pass before anything else
# ══════════════════════════════════════════════════════════════════════════

class TestPwaApiSyntax:

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

    def test_ast_parse(self):
        source = MCP_FILE.read_text(encoding="utf-8")
        try:
            ast.parse(source, filename=str(MCP_FILE))
        except SyntaxError as exc:
            pytest.fail(f"ast.parse failed line {exc.lineno}: {exc.msg}\n{exc.text!r}")


# ══════════════════════════════════════════════════════════════════════════
# 2. STRUCTURAL CHECKS
# ══════════════════════════════════════════════════════════════════════════

class TestPwaApiStructure:

    @pytest.fixture(scope="class")
    def lines(self):
        return MCP_FILE.read_text(encoding="utf-8").splitlines()

    def _find(self, lines, pattern):
        for i, l in enumerate(lines, 1):
            if pattern in l:
                return i
        return None

    def test_pwa_api_route_present(self, lines):
        ln = self._find(lines, 'path == "/pwa-api"')
        assert ln is not None, (
            '/pwa-api route missing from ai_prowler_mcp.py. '
            'PWA cannot call MCP tools — raw JSON-RPC returns 403.'
        )

    def test_pwa_api_before_bearer_check(self, lines):
        api_ln    = self._find(lines, 'path == "/pwa-api"')
        bearer_ln = self._find(lines, 'Everything else (including /mcp) — check Bearer token first')
        assert api_ln    is not None, '/pwa-api route not found.'
        assert bearer_ln is not None, 'Bearer check comment not found.'
        assert api_ln < bearer_ln, (
            f'/pwa-api (line {api_ln}) must be BEFORE Bearer check '
            f'(line {bearer_ln}) — browser would get 401.'
        )

    def test_pwa_token_route_present(self, lines):
        ln = self._find(lines, 'path == "/pwa-token"')
        assert ln is not None, '/pwa-token route missing.'

    def test_pwa_static_route_present(self, lines):
        ln = self._find(lines, 'path.startswith("/jobs")')
        assert ln is not None, '/jobs static route missing.'

    def test_email_invoice_in_allowed_tools(self, lines):
        """Structural check only — confirms email_invoice is reachable via
        /pwa-api's tool whitelist. Does NOT call the tool or send an email."""
        allowed_ln = self._find(lines, "_allowed_tools = {")
        assert allowed_ln is not None, "_allowed_tools block not found."
        # search the next ~15 lines for the closing brace
        window = "\n".join(lines[allowed_ln - 1: allowed_ln + 14])
        assert '"email_invoice"' in window, (
            "email_invoice missing from /pwa-api's _allowed_tools whitelist "
            "— the PWA's Send Invoice button would get 'Unknown tool'."
        )


# ══════════════════════════════════════════════════════════════════════════
# 3. FUNCTIONAL TESTS — simulate the /pwa-api handler
# ══════════════════════════════════════════════════════════════════════════

class _Recorder:
    def __init__(self):
        self.status  = None
        self.headers = {}
        self.body    = b""

    async def __call__(self, event):
        if event["type"] == "http.response.start":
            self.status = event["status"]
            for k, v in event.get("headers", []):
                self.headers[k.decode()] = v.decode()
        elif event["type"] == "http.response.body":
            self.body += event.get("body", b"")

    @property
    def json(self):
        return json.loads(self.body)


# Minimal /pwa-api handler — mirrors what will be in _RouterASGI
async def _pwa_api_handler(body_bytes: bytes, tools: dict, recorder: _Recorder):
    """
    Simulated /pwa-api handler.
    Accepts: {"tool": "name", "args": {...}}
    Returns: {"ok": true, "result": "..."} or {"ok": false, "error": "..."}
    """
    try:
        req = json.loads(body_bytes)
        tool_name = req.get("tool", "")
        args      = req.get("args", {})
        if tool_name not in tools:
            result = json.dumps({"ok": False, "error": f"Unknown tool: {tool_name}"}).encode()
            status = 400
        else:
            output = tools[tool_name](**args)
            result = json.dumps({"ok": True, "result": output}).encode()
            status = 200
    except Exception as exc:
        result = json.dumps({"ok": False, "error": str(exc)}).encode()
        status = 400

    await recorder({"type": "http.response.start", "status": status,
                    "headers": [[b"content-type",  b"application/json"],
                                [b"content-length", str(len(result)).encode()]]})
    await recorder({"type": "http.response.body", "body": result, "more_body": False})


# Fake tool registry for testing
_FAKE_TOOLS = {
    "read_job_spreadsheet": lambda **kw: "JOB-0001 | Sunshine Realty | Scheduled",
    "log_time_entry":       lambda **kw: f"Clocked {kw.get('action','?')} for {kw.get('job_identifier','?')}",
}


class TestPwaApiHandler:

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_valid_tool_returns_200(self):
        rec = _Recorder()
        body = json.dumps({"tool": "read_job_spreadsheet", "args": {}}).encode()
        self._run(_pwa_api_handler(body, _FAKE_TOOLS, rec))
        assert rec.status == 200
        assert rec.json["ok"] is True
        assert "JOB-0001" in rec.json["result"]

    def test_unknown_tool_returns_400(self):
        rec = _Recorder()
        body = json.dumps({"tool": "nonexistent_tool", "args": {}}).encode()
        self._run(_pwa_api_handler(body, _FAKE_TOOLS, rec))
        assert rec.status == 400
        assert rec.json["ok"] is False
        assert "Unknown tool" in rec.json["error"]

    def test_clock_in_returns_200(self):
        rec = _Recorder()
        body = json.dumps({"tool": "log_time_entry",
                           "args": {"job_identifier": "JOB-0001", "action": "start"}}).encode()
        self._run(_pwa_api_handler(body, _FAKE_TOOLS, rec))
        assert rec.status == 200
        assert rec.json["ok"] is True
        assert "start" in rec.json["result"]

    def test_malformed_json_returns_400(self):
        rec = _Recorder()
        self._run(_pwa_api_handler(b"not valid json{{", _FAKE_TOOLS, rec))
        assert rec.status == 400
        assert rec.json["ok"] is False

    def test_empty_body_returns_400(self):
        rec = _Recorder()
        self._run(_pwa_api_handler(b"{}", _FAKE_TOOLS, rec))
        assert rec.status == 400
        assert rec.json["ok"] is False

    def test_response_is_json(self):
        rec = _Recorder()
        body = json.dumps({"tool": "read_job_spreadsheet", "args": {}}).encode()
        self._run(_pwa_api_handler(body, _FAKE_TOOLS, rec))
        assert "application/json" in rec.headers.get("content-type", "")

    def test_content_length_header_present(self):
        rec = _Recorder()
        body = json.dumps({"tool": "read_job_spreadsheet", "args": {}}).encode()
        self._run(_pwa_api_handler(body, _FAKE_TOOLS, rec))
        assert "content-length" in rec.headers
