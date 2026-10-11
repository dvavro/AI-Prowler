"""
R-054 (2026-10-08): unauthenticated /health endpoint.

The GUI's _http_health_check() polls GET http://127.0.0.1:8000/health with NO
Authorization header. The _RouterASGI class had no /health bypass, so the
Bearer token check returned 401, urlopen raised HTTPError, and the GUI LED
falsely showed "Stopped" for a perfectly healthy server.

Fix: an unauthenticated /health handler in _RouterASGI.__call__ BEFORE the
Bearer token check, returning HTTP 200 with {"status":"ok"}. Health checks
must never require auth (standard pattern).

Run: run_tests.bat tests\\mcp_tests\\test_r054_health_no_auth.py -v
"""
import ast
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_MCP_SRC = _SRC / "ai_prowler_mcp.py"


def _find_class(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    return None


def test_health_endpoint_bypasses_auth():
    """_RouterASGI.__call__ must handle /health WITHOUT requiring a Bearer
    token. The /health branch must appear BEFORE the auth check — otherwise
    the GUI's unauthenticated probe gets 401 and the LED falsely shows
    "Stopped" for a healthy server (R-054)."""
    src = _MCP_SRC.read_text(encoding="utf-8")
    tree = ast.parse(src)
    router = _find_class(tree, "_RouterASGI")
    assert router is not None, "_RouterASGI not found in ai_prowler_mcp.py"

    call_fn = None
    for node in ast.walk(router):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "__call__":
            call_fn = node
            break
    assert call_fn is not None, "_RouterASGI.__call__ not found"

    health_line = None
    auth_line = None
    for node in ast.walk(call_fn):
        if isinstance(node, ast.Compare):
            # /health check: compares `path` against a "/health" string
            left = node.left
            if isinstance(left, ast.Name) and left.id == "path":
                for comp in node.comparators:
                    if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                        if "/health" in comp.value:
                            if health_line is None or node.lineno < health_line:
                                health_line = node.lineno
            # Auth check: `tok not in _access_tokens`
            if isinstance(left, ast.Name) and left.id == "tok":
                for op, comp in zip(node.ops, node.comparators):
                    if isinstance(op, ast.NotIn) and isinstance(comp, ast.Name):
                        if comp.id == "_access_tokens":
                            if auth_line is None or node.lineno < auth_line:
                                auth_line = node.lineno

    assert health_line is not None, (
        "No /health bypass found in _RouterASGI.__call__ — "
        "unauthenticated GET /health will get 401 and the GUI LED will "
        "falsely show Stopped for a healthy server (R-054)"
    )
    assert auth_line is not None, "Bearer token auth check not found (unexpected)"
    assert health_line < auth_line, (
        f"/health bypass (line {health_line}) must come BEFORE the Bearer "
        f"auth check (line {auth_line}), or unauthenticated probes get 401 (R-054)"
    )
