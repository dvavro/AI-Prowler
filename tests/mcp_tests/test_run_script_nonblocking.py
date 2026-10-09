"""run_script must not freeze the server (2026-09-26).

Found while running the Jobs-app E2E work: run_script was registered as a
plain (sync) MCP tool, and the MCP SDK runs sync tools directly on the
server's one event loop — so while a script ran, the whole server stopped
answering (/health, the Jobs app, every other tool). Measured live: a 15 s
script left the server unanswered for 14.8 s and the desktop app's LED showed
"Stopped" until it finished.

The MCP-facing "run_script" is now an async wrapper that waits for the script
on a worker thread. These tests use a fake run_script that just sleeps, so
they need no allowlist setup and run no real scripts.
"""
import asyncio


def _fresh_loop_run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
import inspect
import sys
import time
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _registered_tool(mcp_mod, name):
    tm = mcp_mod.mcp._tool_manager
    return tm.get_tool(name) if hasattr(tm, "get_tool") else tm._tools[name]


def test_the_registered_run_script_tool_is_async(mcp_mod):
    tool = _registered_tool(mcp_mod, "run_script")
    assert tool is not None, "no MCP tool named run_script"
    assert inspect.iscoroutinefunction(tool.fn), \
        "run_script is registered as a sync tool — it will block the whole server"


def test_the_tool_keeps_the_same_arguments_and_description(mcp_mod):
    tool = _registered_tool(mcp_mod, "run_script")
    params = list(inspect.signature(tool.fn).parameters)
    assert params == ["script_path", "args", "timeout_sec", "max_output_lines"]
    assert "Execute a script" in (tool.description or "")


def test_tool_gates_use_the_registered_name_not_the_function_name(mcp_mod, monkeypatch):
    """Server mode hides run_script from crew (Tier A). The async wrapper's
    Python name is run_script_tool — the gate must still see 'run_script'."""
    assert "run_script" in mcp_mod._TIER_A_SUPPRESSED
    monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", True)
    registered = []
    monkeypatch.setattr(mcp_mod, "_orig_mcp_tool",
                        lambda *a, **k: (lambda fn: registered.append(k.get("name")) or fn))

    async def run_script_tool(script_path: str) -> str:
        return "x"
    mcp_mod._counting_mcp_tool(name="run_script")(run_script_tool)
    assert registered == [], "run_script was registered in server mode (Tier A bypassed)"


def test_async_tools_stay_async_through_the_audit_wrapper(mcp_mod, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", False)
    # don't touch the real telemetry counter / audit log
    monkeypatch.setattr(mcp_mod, "_telemetry_increment_tool_count", lambda *a, **k: None)
    monkeypatch.setattr(mcp_mod, "_append_audit_log", lambda *a, **k: None)
    seen = {}
    monkeypatch.setattr(mcp_mod, "_orig_mcp_tool",
                        lambda *a, **k: (lambda fn: seen.setdefault("fn", fn)))

    async def some_async_tool(x: int) -> int:
        return x + 1
    mcp_mod._counting_mcp_tool(name="zz_e2e_async_probe")(some_async_tool)
    assert inspect.iscoroutinefunction(seen["fn"])
    assert _fresh_loop_run(seen["fn"](x=1)) == 2


def test_plain_run_script_is_still_callable_directly(mcp_mod):
    # 12 existing tests (test_dev_tools.py) call mcp_mod.run_script(...) as a
    # normal function — that must keep working.
    assert not inspect.iscoroutinefunction(mcp_mod.run_script)


def test_the_server_keeps_answering_while_a_script_runs(mcp_mod, monkeypatch):
    """While the tool waits 1.5 s on a 'script', other work on the same event
    loop (standing in for /health and other requests) keeps running."""
    def slow_script(script_path, args="", timeout_sec=120, max_output_lines=200):
        time.sleep(1.5)
        return "✅ rc=0 — fake"
    monkeypatch.setattr(mcp_mod, "run_script", slow_script)

    async def scenario():
        ticks = 0
        async def other_requests():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.05)
                ticks += 1
        other = asyncio.ensure_future(other_requests())
        result = await mcp_mod.run_script_tool("C:/x.py")
        other.cancel()
        return result, ticks

    result, ticks = _fresh_loop_run(scenario())
    assert result == "✅ rc=0 — fake"
    # 1.5 s at one tick per 50 ms ≈ 30; the old sync tool would give 0.
    assert ticks >= 15, f"event loop was blocked while the script ran (only {ticks} ticks)"
