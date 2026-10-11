"""The 'AI' edit path for the Jobs-app E2E suites (2026-10-09).

Claude changes jobs and customers by calling AI-Prowler's MCP tools over the
/mcp endpoint (Streamable HTTP) with a user's bearer token — not through the
Jobs app's /pwa-api. AiClient does exactly that, as one user, so a test can
make a change "the way Claude would" and then check it in the Jobs app GUI.

Every call goes through the same write Guard as the browser and the setup
client (safety.py): only ZTEST test data can be written.

Personal suite: origin = the local AI-Prowler (http://127.0.0.1:8000), token =
the personal Bearer Token. Server suite: origin = the AI-Prowler Server's
public address, token = that user's own bearer token (the one they sign in to
the Jobs app with).
"""
from __future__ import annotations

import concurrent.futures
import time

import anyio

from safety import Guard, GuardViolation

# Cloudflare answers 403 to library default User-Agents (see api.py).
USER_AGENT = "AI-Prowler-E2E/1.0 (+tests/gui_jobs_e2e ai_client)"


class AiError(Exception):
    pass


class AiClient:
    def __init__(self, origin: str, token: str, guard: Guard, who: str, log=None, api_log=None):
        self.url = origin.rstrip("/") + "/mcp"
        self.token = token
        self.guard = guard
        self.who = who
        self.log = log or (lambda *a: None)
        self.api_log = api_log or (lambda *a: None)

    async def _call(self, tool: str, args: dict) -> tuple[str, bool]:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client
        headers = {"Authorization": "Bearer " + self.token, "User-Agent": USER_AGENT}
        async with streamablehttp_client(self.url, headers=headers, timeout=60) as (read, write, _sid):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.call_tool(tool, args)
        text = "\n".join(getattr(c, "text", "") for c in (res.content or []))
        return text, bool(getattr(res, "isError", False))

    async def _list_tools(self) -> list[str]:
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client
        headers = {"Authorization": "Bearer " + self.token, "User-Agent": USER_AGENT}
        async with streamablehttp_client(self.url, headers=headers, timeout=60) as (read, write, _sid):
            async with ClientSession(read, write) as session:
                await session.initialize()
                res = await session.list_tools()
        return sorted(t.name for t in (res.tools or []))

    def list_tools(self) -> list[str]:
        """The tool names this user's Claude is offered (read-only, no guard needed)."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            names = ex.submit(anyio.run, self._list_tools).result(timeout=120)
        self.api_log({"source": f"ai:{self.who}", "tool": "(list_tools)", "args": {},
                      "status": "mcp", "ok": True, "excerpt": f"{len(names)} tools"})
        return names

    # Read-only MCP tools a test may call without going through the write guard.
    READ_ONLY = frozenset({"list_tracked_directories"})

    def call_read(self, tool: str, args: dict | None = None) -> str:
        if tool not in self.READ_ONLY:
            raise GuardViolation(f"call_read is only for {sorted(self.READ_ONLY)}, not {tool}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            text, is_error = ex.submit(anyio.run, self._call, tool, dict(args or {})).result(timeout=120)
        self.api_log({"source": f"ai:{self.who}", "tool": tool, "args": args or {}, "status": "mcp",
                      "ok": not is_error, "excerpt": text[:300]})
        if is_error:
            raise AiError(f"MCP tool {tool} as {self.who} returned an error: {text[:300]}")
        return text

    def call(self, tool: str, args: dict | None = None, *, expect_ok: bool = True) -> str:
        """Call one MCP tool as this user. Returns the tool's text reply."""
        args = dict(args or {})
        decision, why = self.guard.enforce(tool, args, f"ai:{self.who}")
        if decision != "allow":
            raise GuardViolation(f"guard {decision}ed AI call {tool}: {why}")
        t0 = time.time()
        try:
            # Own thread: Playwright's sync API keeps an asyncio loop running in
            # this thread, and anyio.run() refuses to start inside it.
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                text, is_error = ex.submit(anyio.run, self._call, tool, args).result(timeout=120)
        except Exception as e:
            self.api_log({"source": f"ai:{self.who}", "tool": tool, "args": args,
                          "status": "EXC", "ok": False, "excerpt": f"{type(e).__name__}: {e}"[:300]})
            raise AiError(f"MCP call {tool} as {self.who} failed: {type(e).__name__}: {e}") from e
        ms = int((time.time() - t0) * 1000)
        self.api_log({"source": f"ai:{self.who}", "tool": tool, "args": args, "status": "mcp",
                      "ms": ms, "ok": not is_error, "excerpt": text[:300]})
        if not is_error:
            self.guard.note_result(tool, text)
        if is_error:
            raise AiError(f"MCP tool {tool} as {self.who} returned an error: {text[:300]}")
        if expect_ok and text.lstrip().startswith("❌"):
            raise AiError(f"{tool} refused for {self.who}: {text.splitlines()[0]}")
        return text
