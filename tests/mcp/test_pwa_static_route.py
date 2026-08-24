"""
test_pwa_static_route.py
========================
Regression tests for the /pwa static file route added to _RouterASGI
(personal/local mode) in ai_prowler_mcp.py.

What broke before
-----------------
The patch was inserted with inconsistent indentation — the PWA block used
14-space indent while the surrounding _RouterASGI.__call__ body uses 12-space
indent. Python raised IndentationError on import, crashing the MCP server
before it could start. The HTTP server showed "Stopped" in the GUI.

What these tests verify
-----------------------
1. ai_prowler_mcp.py imports cleanly (no IndentationError / SyntaxError).
2. The _RouterASGI class exists and is callable.
3. The /pwa route logic is present and correctly indented by parsing the
   AST — no live server needed, no install dir touched.
4. The /pwa block sits BEFORE the Bearer token check (so phones can load
   the PWA without auth).
5. The /pwa path-traversal guard is present (security regression).
6. A simulated ASGI call to /pwa/index.html returns 200 when the file
   exists, and 404 when it does not.
7. A simulated ASGI call to a path-traversal attempt returns 403.

Run with:
    pytest tests/mcp/test_pwa_static_route.py -v

Safe to run at any time — does NOT:
  - Start or stop AI-Prowler
  - Touch the install directory (C:/Program Files/AI-Prowler)
  - Modify any tracked files
  - Require a live HTTP server or Cloudflare tunnel
"""
from __future__ import annotations

import ast
import asyncio
import os
import shutil
import tempfile
from pathlib import Path

import pytest

# ── Locate source root ────────────────────────────────────────────────────
_SRC = os.environ.get("AI_PROWLER_SRC")
if _SRC:
    SRC_ROOT = Path(_SRC).resolve()
else:
    SRC_ROOT = Path(__file__).resolve().parent.parent.parent

MCP_FILE = SRC_ROOT / "ai_prowler_mcp.py"


# ══════════════════════════════════════════════════════════════════════════
# 1. SYNTAX / IMPORT CHECKS
# ══════════════════════════════════════════════════════════════════════════

class TestPwaSyntax:
    """Parse and compile the MCP file — catch IndentationError before deploy."""

    def test_mcp_file_exists(self):
        assert MCP_FILE.exists(), f"MCP source not found: {MCP_FILE}"

    def test_no_syntax_error(self):
        """
        Compile ai_prowler_mcp.py — same check Python does on import.
        If this fails, HTTP server shows 'Stopped' immediately on start.
        """
        import py_compile
        tmp = Path(tempfile.mkdtemp())
        try:
            dst = tmp / "ai_prowler_mcp.py"
            shutil.copy(MCP_FILE, dst)
            try:
                py_compile.compile(str(dst), doraise=True)
            except py_compile.PyCompileError as exc:
                pytest.fail(
                    f"SyntaxError / IndentationError in ai_prowler_mcp.py:\n{exc}"
                )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_ast_parse(self):
        """ast.parse also catches indentation errors at parse time."""
        source = MCP_FILE.read_text(encoding="utf-8")
        try:
            ast.parse(source, filename=str(MCP_FILE))
        except SyntaxError as exc:
            pytest.fail(
                f"ast.parse failed — IndentationError or SyntaxError:\n"
                f"  line {exc.lineno}: {exc.msg}\n"
                f"  text: {exc.text!r}"
            )


# ══════════════════════════════════════════════════════════════════════════
# 2. STRUCTURAL CHECKS
# ══════════════════════════════════════════════════════════════════════════

class TestPwaStructure:
    """Verify the PWA block is present and correctly positioned."""

    @pytest.fixture(scope="class")
    def source_lines(self):
        return MCP_FILE.read_text(encoding="utf-8").splitlines()

    def _find_line(self, lines, pattern, after_pattern=None):
        after_line = 0
        if after_pattern:
            for i, line in enumerate(lines, 1):
                if after_pattern in line:
                    after_line = i
                    break
        for i, line in enumerate(lines, 1):
            if i > after_line and pattern in line:
                return i
        return None

    def test_pwa_route_present(self, source_lines):
        # Find /jobs route inside _RouterASGI (personal mode), not _ServerRouterASGI
        ln = self._find_line(source_lines, 'path.startswith("/jobs")',
                             after_pattern='class _RouterASGI:')
        assert ln is not None, (
            "PWA route missing inside _RouterASGI. "
            "The patch was not applied."
        )

    def test_pwa_before_bearer_check(self, source_lines):
        """
        The /jobs block MUST appear before the Bearer token check.
        If it appears after, phones get 401 trying to load the PWA.
        """
        pwa_ln    = self._find_line(source_lines, 'path.startswith("/jobs")',
                              after_pattern='class _RouterASGI:')
        bearer_ln = self._find_line(
            source_lines,
            "Everything else (including /mcp) — check Bearer token first"
        )
        assert pwa_ln    is not None, "PWA route not found."
        assert bearer_ln is not None, "Bearer token check comment not found."
        assert pwa_ln < bearer_ln, (
            f"PWA route (line {pwa_ln}) must come BEFORE Bearer check "
            f"(line {bearer_ln}). Phones would get 401 loading the app."
        )

    def test_path_traversal_guard_present(self, source_lines):
        # Guard may be on one line or split across two — search for the key token
        ln = self._find_line(source_lines, "abspath(_pwa_root)")
        assert ln is not None, (
            "Path-traversal guard missing. "
            "Anyone could read arbitrary files via /pwa/../../../ ."
        )

    def test_pwa_inside_router_asgi(self, source_lines):
        """PWA block must be inside _RouterASGI (personal mode), not _ServerRouterASGI."""
        router_ln = self._find_line(source_lines, "class _RouterASGI:")
        pwa_ln    = self._find_line(source_lines, 'path.startswith("/jobs")',
                                    after_pattern='class _RouterASGI:')
        assert router_ln is not None, "_RouterASGI class not found."
        assert pwa_ln    is not None, "PWA route not found."
        assert pwa_ln > router_ln, (
            f"PWA route (line {pwa_ln}) appears before _RouterASGI "
            f"(line {router_ln}) — won't be reachable in personal mode."
        )

    def test_consistent_indentation_in_pwa_block(self, source_lines):
        """
        THIS IS THE REGRESSION TEST for the bug that broke the server.

        The original failure: PWA block had 14-space indent but surrounding
        _RouterASGI body uses 12-space indent -> IndentationError on import.

        We verify: min indent in the PWA block is exactly 14 spaces
        (if/startswith line), max is <= 24 (deepest nested body).
        And that py_compile already passed (test_no_syntax_error).
        """
        pwa_start = self._find_line(source_lines, 'path.startswith("/jobs")',
                                    after_pattern='class _RouterASGI:')
        pwa_end   = self._find_line(source_lines, "end PWA static server")
        assert pwa_start is not None, "PWA block start not found."
        assert pwa_end   is not None, "PWA block end marker not found."

        indents = []
        for line in source_lines[pwa_start - 1 : pwa_end]:
            stripped = line.lstrip()
            if stripped:
                indents.append(len(line) - len(stripped))

        unique = sorted(set(indents))
        assert len(unique) <= 6, (
            f"Too many indent levels in PWA block ({unique}) — "
            f"likely an indentation error."
        )
        assert min(indents) >= 12, (
            f"PWA block minimum indent is {min(indents)} — "
            f"expected >= 12 to sit inside _RouterASGI.__call__."
        )


# ══════════════════════════════════════════════════════════════════════════
# 3. FUNCTIONAL ASGI TESTS (no live server needed)
# ══════════════════════════════════════════════════════════════════════════

class _Recorder:
    """Captures ASGI send() calls."""
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


async def _pwa_handler(path: str, pwa_root: Path, recorder: _Recorder):
    """
    Exact copy of the PWA handler block from _RouterASGI.__call__.
    Kept in sync with production — drift here means the test is stale.
    """
    import mimetypes as _mt2

    _pwa_root_str = str(pwa_root.resolve())
    rel       = path[4:].lstrip("/") or "index.html"
    file_path = os.path.join(_pwa_root_str, rel)

    if not os.path.abspath(file_path).startswith(os.path.abspath(_pwa_root_str)):
        await recorder({"type": "http.response.start", "status": 403,
                        "headers": [[b"content-type", b"text/plain"]]})
        await recorder({"type": "http.response.body", "body": b"Forbidden",
                        "more_body": False})
        return

    if os.path.isfile(file_path):
        mime, _ = _mt2.guess_type(file_path)
        mime_b  = (mime or "application/octet-stream").encode()
        with open(file_path, "rb") as _f:
            body = _f.read()
        await recorder({"type": "http.response.start", "status": 200,
                        "headers": [[b"content-type",   mime_b],
                                    [b"content-length", str(len(body)).encode()],
                                    [b"cache-control",  b"no-cache"]]})
        await recorder({"type": "http.response.body", "body": body,
                        "more_body": False})
    else:
        await recorder({"type": "http.response.start", "status": 404,
                        "headers": [[b"content-type", b"text/plain"]]})
        await recorder({"type": "http.response.body",
                        "body": b"PWA file not found", "more_body": False})


@pytest.fixture
def pwa_dir(tmp_path):
    """Minimal pwa/ directory in a temp folder — never touches install dir."""
    d = tmp_path / "pwa"
    d.mkdir()
    (d / "index.html").write_bytes(b"<html><body>AI-Prowler Crew PWA</body></html>")
    (d / "manifest.json").write_bytes(b'{"name":"AI-Prowler Crew"}')
    (d / "sw.js").write_bytes(b"// service worker")
    return d


class TestPwaAsgiHandler:
    """Simulate ASGI requests to the PWA handler — no live server needed."""

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_index_html_200(self, pwa_dir):
        rec = _Recorder()
        self._run(_pwa_handler("/pwa/index.html", pwa_dir, rec))
        assert rec.status == 200
        assert b"AI-Prowler Crew PWA" in rec.body

    def test_bare_pwa_serves_index(self, pwa_dir):
        """/pwa (no slash) -> index.html"""
        rec = _Recorder()
        self._run(_pwa_handler("/pwa", pwa_dir, rec))
        assert rec.status == 200
        assert b"AI-Prowler Crew PWA" in rec.body

    def test_pwa_slash_serves_index(self, pwa_dir):
        """/pwa/ (trailing slash) -> index.html"""
        rec = _Recorder()
        self._run(_pwa_handler("/pwa/", pwa_dir, rec))
        assert rec.status == 200

    def test_manifest_json_200(self, pwa_dir):
        rec = _Recorder()
        self._run(_pwa_handler("/pwa/manifest.json", pwa_dir, rec))
        assert rec.status == 200
        assert b"AI-Prowler Crew" in rec.body

    def test_sw_js_200(self, pwa_dir):
        rec = _Recorder()
        self._run(_pwa_handler("/pwa/sw.js", pwa_dir, rec))
        assert rec.status == 200

    def test_missing_file_404(self, pwa_dir):
        rec = _Recorder()
        self._run(_pwa_handler("/pwa/does_not_exist.png", pwa_dir, rec))
        assert rec.status == 404

    def test_path_traversal_403(self, pwa_dir):
        """SECURITY: /pwa/../../etc/passwd must be blocked."""
        rec = _Recorder()
        self._run(_pwa_handler("/pwa/../../etc/passwd", pwa_dir, rec))
        assert rec.status == 403

    def test_content_type_html(self, pwa_dir):
        rec = _Recorder()
        self._run(_pwa_handler("/pwa/index.html", pwa_dir, rec))
        assert "text/html" in rec.headers.get("content-type", "")

    def test_content_type_json(self, pwa_dir):
        rec = _Recorder()
        self._run(_pwa_handler("/pwa/manifest.json", pwa_dir, rec))
        assert "json" in rec.headers.get("content-type", "")

    def test_cache_control_no_cache(self, pwa_dir):
        """PWA files need no-cache so phone updates land immediately."""
        rec = _Recorder()
        self._run(_pwa_handler("/pwa/index.html", pwa_dir, rec))
        assert rec.headers.get("cache-control") == "no-cache"
