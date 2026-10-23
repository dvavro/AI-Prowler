"""
Tests for the Grok (xAI) API-key path in task_queue_automation.py (2026-10-12).

Covers: provider-aware key storage, provider-aware wrapper generation for all
three wrapper builders, the xAI function-calling loop (fully mocked — no
network), and dry-run provider branching.

Isolation follows test_task_queue_automation.py: every test runs against a
fake HOME (never the real ~/.ai-prowler/), no real Scheduled Task is created,
and no test touches the network (urllib is monkeypatched where needed).
"""
import base64
import re
import io
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import task_queue_automation as tqa


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Fake HOME for every test in this module."""
    monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path / ".ai-prowler")
    monkeypatch.setattr(tqa, "CONFIG_PATH",
                        tmp_path / ".ai-prowler" / "task_automation_config.json")
    monkeypatch.setattr(tqa, "STATUS_PATH",
                        tmp_path / ".ai-prowler" / "task_automation_last_run.json")
    monkeypatch.setattr(tqa, "AUDIT_LOG_PATH",
                        tmp_path / ".ai-prowler" / "autonomous_run_audit.log")
    monkeypatch.setattr(tqa, "API_KEY_PATH",
                        tmp_path / ".ai-prowler" / "claude_api_key.txt")
    monkeypatch.setattr(tqa, "GROK_API_KEY_PATH",
                        tmp_path / ".ai-prowler" / "grok_api_key.txt")
    # Points at nothing by default — tests that need the MCP script to
    # "exist" create it explicitly.
    monkeypatch.setattr(tqa, "LOCAL_MCP_SCRIPT_PATH",
                        tmp_path / "_no_such_dir" / "ai_prowler_mcp.py")
    # 2026-10-22: Grok runs use the RUNNING AI-Prowler. Never read the real
    # config.json token, never probe the real localhost:8000, never start the
    # real app. Tests that need a "running" server set these per test.
    monkeypatch.setattr(tqa, "AI_PROWLER_CONFIG_PATH", tmp_path / ".ai-prowler" / "config.json")
    monkeypatch.setattr(tqa, "RUNNING_SERVER_MCP_CONFIG_PATH",
                        tmp_path / ".ai-prowler" / "claude_mcp_config_running.json")
    monkeypatch.setattr(tqa, "_server_answers", lambda *a, **kw: False)
    monkeypatch.setattr(tqa, "_ai_prowler_app_running", lambda: False)
    monkeypatch.setattr(tqa, "_start_ai_prowler_app",
                        lambda: (False, "mocked — tests never start AI-Prowler"))
    _now = [1_000_000.0]          # fake clock: waits finish instantly
    monkeypatch.setattr(tqa.time, "time", lambda: _now[0])
    monkeypatch.setattr(tqa.time, "sleep", lambda s: _now.__setitem__(0, _now[0] + s))
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    return tmp_path


def _running_server(home, monkeypatch, token="tok-grok"):
    """Pretend this PC's AI-Prowler is running with remote access set up."""
    cfg = home / ".ai-prowler" / "config.json"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text('{"remote_token": "%s"}' % token, encoding="utf-8")
    monkeypatch.setattr(tqa, "_server_answers", lambda *a, **kw: True)


# ── Provider-aware key storage ─────────────────────────────────────────────

class TestGrokKeyStorage:
    def test_grok_key_uses_separate_file(self, _isolated_home):
        tqa.save_api_key("xai-test-key-123", "grok")
        assert tqa.GROK_API_KEY_PATH.exists()
        assert not tqa.API_KEY_PATH.exists()
        assert tqa.load_api_key("grok") == "xai-test-key-123"
        assert tqa.has_api_key("grok") is True

    def test_providers_are_independent(self, _isolated_home):
        tqa.save_api_key("anthropic-key", "anthropic")
        tqa.save_api_key("grok-key", "grok")
        assert tqa.load_api_key("anthropic") == "anthropic-key"
        assert tqa.load_api_key("grok") == "grok-key"
        tqa.delete_api_key("grok")
        assert tqa.has_api_key("grok") is False
        assert tqa.has_api_key("anthropic") is True
        # Deleting the anthropic key never touches the (already deleted) grok file.
        tqa.delete_api_key("anthropic")
        assert tqa.has_api_key("anthropic") is False

    def test_default_provider_is_anthropic(self, _isolated_home):
        # Backward compatibility: no-arg calls keep meaning the Claude key.
        tqa.save_api_key("legacy-key")
        assert tqa.load_api_key() == "legacy-key"
        assert tqa.has_api_key() is True
        assert tqa.has_api_key("anthropic") is True
        assert tqa.has_api_key("grok") is False

    def test_save_api_key_strips_whitespace_grok(self, _isolated_home):
        tqa.save_api_key("  xai-k  \n", "grok")
        assert tqa.load_api_key("grok") == "xai-k"

    def test_api_key_path_rejects_unknown_provider(self, _isolated_home):
        with pytest.raises(ValueError):
            tqa.api_key_path("muse")
        with pytest.raises(ValueError):
            tqa.save_api_key("k", "muse")

    def test_normalize_provider(self):
        assert tqa._normalize_provider("grok") == "grok"
        assert tqa._normalize_provider("GROK") == "grok"
        assert tqa._normalize_provider("xai") == "grok"
        assert tqa._normalize_provider("anthropic") == "anthropic"
        assert tqa._normalize_provider("claude") == "anthropic"
        assert tqa._normalize_provider(None) == "anthropic"
        assert tqa._normalize_provider("") == "anthropic"
        assert tqa._normalize_provider("nonsense") == "anthropic"

    def test_effective_api_key_provider(self):
        assert tqa.effective_api_key_provider({"use_api_key": False}) == "oauth"
        assert tqa.effective_api_key_provider({"use_api_key": True}) == "anthropic"
        assert tqa.effective_api_key_provider(
            {"use_api_key": True, "api_key_provider": "grok"}) == "grok"
        # A hand-edited junk value degrades to anthropic, never crashes.
        assert tqa.effective_api_key_provider(
            {"use_api_key": True, "api_key_provider": "junk"}) == "anthropic"


# ── Wrapper generation ─────────────────────────────────────────────────────

class TestGrokWrapperGeneration:
    def test_queue_wrapper_grok_branch(self, _isolated_home):
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", use_api_key=True,
            api_key_provider="grok")
        assert "XAI_API_KEY" in content
        assert "run_grok_queue_headless" in content
        assert str(tqa.GROK_API_KEY_PATH) in content
        assert "claude -p" not in content
        assert "ANTHROPIC_API_KEY" not in content
        # Fails loudly when the key file is absent at runtime.
        assert "exit /b 1" in content

    def test_queue_wrapper_grok_never_embeds_key_value(self, _isolated_home):
        tqa.save_api_key("xai-secret-value-xyz", "grok")
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", use_api_key=True,
            api_key_provider="grok")
        assert "xai-secret-value-xyz" not in content

    def test_queue_wrapper_anthropic_unchanged(self, _isolated_home):
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", use_api_key=True)
        assert "ANTHROPIC_API_KEY" in content
        assert re.search(r'claude(\.exe)?"? -p', content, re.I), "the Claude CLI is invoked"
        assert "XAI_API_KEY" not in content
        assert "run_grok_queue_headless" not in content

    def test_queue_wrapper_oauth_unchanged(self, _isolated_home):
        content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
        assert "CLAUDE_CODE_OAUTH_TOKEN" in content
        assert "XAI_API_KEY" not in content

    def test_install_wrapper_script_forwards_grok(self, _isolated_home, tmp_path):
        target = tmp_path / "wrapper_dir"
        path = tqa.install_wrapper_script(
            target, "x.json", "mcp__ai-prowler__*",
            use_api_key=True, api_key_provider="grok")
        content = path.read_text(encoding="utf-8")
        assert "XAI_API_KEY" in content
        assert "run_grok_queue_headless" in content

    def test_single_prompt_wrapper_grok(self, _isolated_home):
        content = tqa.build_single_prompt_wrapper_content(
            "do the thing", "x.json", "mcp__ai-prowler__*",
            use_api_key=True, api_key_provider="grok")
        assert "XAI_API_KEY" in content
        assert "run_grok_prompt_headless" in content
        assert "claude -p" not in content
        # The ad-hoc prompt travels base64-encoded, never batch-quoted.
        assert base64.b64encode(b"do the thing").decode() in content

    def test_single_prompt_wrapper_anthropic_unchanged(self, _isolated_home):
        content = tqa.build_single_prompt_wrapper_content(
            "do the thing", "x.json", "mcp__ai-prowler__*",
            use_api_key=True)
        assert "claude -p" in content
        assert "XAI_API_KEY" not in content

    # (the two AI Routing wrapper tests were removed 2026-10-22 with the
    # Claude CLI AI Route — build_ai_routing_wrapper_content no longer exists)


# ── Runner unit tests (no network) ─────────────────────────────────────────

class TestGrokRunner:
    def test_queue_prompt_has_no_claude_cli_references(self):
        p = tqa.GROK_QUEUE_RUNNER_PROMPT
        # The Claude-CLI-isms are rewritten for the function-calling runner;
        # if QUEUE_RUNNER_PROMPT drifts, this test names the drift.
        assert "mcp__ai-prowler__" not in p
        assert "WebSearch or WebFetch" not in p
        # 2026-10-12: no web search on /v1/chat/completions (xAI's built-in
        # tools are Responses-API only) — Grok is told to use general knowledge.
        assert "web_search" not in p and "general knowledge" in p
        assert "complete_analysis_task" in p
        assert "get_pending_analysis_tasks" in p   # the queue prompts never named the file

    def test_select_tools_broad_wildcard(self):
        tools = [
            {"name": "a", "description": "d",
             "inputSchema": {"type": "object", "properties": {}}},
            {"name": "b", "description": "d",
             "inputSchema": {"type": "object", "properties": {}}},
        ]
        selected, web = tqa._grok_select_tools("mcp__ai-prowler__*", tools)
        assert [t["function"]["name"] for t in selected] == ["a", "b"]
        assert all(t["type"] == "function" for t in selected)
        assert web is False

    def test_select_tools_specific_and_web_search(self):
        tools = [
            {"name": "a", "description": "d",
             "inputSchema": {"type": "object", "properties": {}}},
            {"name": "b", "description": "d",
             "inputSchema": {"type": "object", "properties": {}}},
        ]
        selected, web = tqa._grok_select_tools("mcp__ai-prowler__a, WebSearch", tools)
        assert [t["function"]["name"] for t in selected] == ["a"]
        assert web is True

    def test_mcp_tool_schema_conversion(self):
        tool = {"name": "t", "description": "desc",
                "inputSchema": {"type": "object",
                                "properties": {"q": {"type": "string"}}}}
        fn = tqa._mcp_tool_to_xai_function(tool)
        assert fn["type"] == "function"
        assert fn["function"]["name"] == "t"
        assert fn["function"]["parameters"]["properties"]["q"]["type"] == "string"

    def test_mcp_tool_missing_schema_gets_empty_object(self):
        fn = tqa._mcp_tool_to_xai_function({"name": "t"})
        assert fn["function"]["parameters"] == {"type": "object", "properties": {}}

    def test_grok_chat_http_error_carries_api_detail(self, monkeypatch):
        def _boom(req, timeout=None):
            raise urllib.error.HTTPError(
                req.full_url, 401, "Unauthorized", {},
                io.BytesIO(b'{"error": {"message": "bad key"}}'))
        monkeypatch.setattr(urllib.request, "urlopen", _boom)
        with pytest.raises(RuntimeError) as exc_info:
            tqa._grok_chat("bad-key", [{"role": "user", "content": "hi"}], [])
        assert "401" in str(exc_info.value)
        assert "bad key" in str(exc_info.value)

    def test_grok_chat_uses_xai_endpoint_and_bearer(self, monkeypatch):
        seen = {}
        class _Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self):
                return b'{"choices": [{"message": {"content": "hi"}}]}'
        def _ok(req, timeout=None):
            seen["url"] = req.full_url
            seen["auth"] = req.headers.get("Authorization")
            return _Resp()
        monkeypatch.setattr(urllib.request, "urlopen", _ok)
        msg = tqa._grok_chat("k", [{"role": "user", "content": "hi"}], [])
        assert seen["url"] == tqa.XAI_API_URL
        assert seen["auth"] == "Bearer k"
        assert msg["content"] == "hi"

    def test_run_grok_headless_no_key_fails_cleanly(self, _isolated_home, monkeypatch):
        _running_server(_isolated_home, monkeypatch)
        ok, detail = tqa._run_grok_headless("do tasks", 60, "test run")
        assert ok is False
        assert "No Grok API key" in detail
        assert tqa.load_last_run()["status"] == "failure"

    def test_run_grok_headless_no_remote_access(self, _isolated_home, monkeypatch):
        """No Bearer Token -> no running-AI-Prowler connection -> clear message,
        and nothing is started."""
        monkeypatch.setattr(tqa, "load_api_key", lambda provider="anthropic": "xai-k")

        def _boom():
            raise AssertionError("must not start AI-Prowler")
        monkeypatch.setattr(tqa, "_start_ai_prowler_app", _boom)
        ok, detail = tqa._run_grok_headless("do tasks", 60, "test run")
        assert ok is False
        assert detail == tqa.NO_REMOTE_ACCESS_MSG
        assert "Remote Access" in tqa.load_last_run()["detail"]

    def test_run_grok_headless_server_not_running(self, _isolated_home, monkeypatch):
        cfg = _isolated_home / ".ai-prowler" / "config.json"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text('{"remote_token": "t"}', encoding="utf-8")
        monkeypatch.setattr(tqa, "load_api_key", lambda provider="anthropic": "xai-k")
        ok, detail = tqa._run_grok_headless("do tasks", 60, "test run", wait_sec=0)
        assert ok is False
        assert "isn't running" in detail

    def test_single_prompt_never_starts_the_app(self, _isolated_home, monkeypatch):
        cfg = _isolated_home / ".ai-prowler" / "config.json"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text('{"remote_token": "t"}', encoding="utf-8")
        monkeypatch.setattr(tqa, "load_api_key", lambda provider="anthropic": "xai-k")

        def _boom():
            raise AssertionError("▶ NOW Grok run must not start AI-Prowler")
        monkeypatch.setattr(tqa, "_start_ai_prowler_app", _boom)
        ok, detail = tqa.run_grok_prompt_headless("hi")
        assert ok is False and "isn't running" in detail

    def test_tool_loop_drives_mcp_and_returns_summary(
            self, _isolated_home, monkeypatch):
        _running_server(_isolated_home, monkeypatch, token="tok-grok")
        monkeypatch.setattr(tqa, "load_api_key",
                            lambda provider="anthropic": "xai-test-key")
        chat_calls = {"n": 0}
        final_messages = {}
        made = {}

        def _fake_chat(api_key, messages, tools, model=None):
            chat_calls["n"] += 1
            assert api_key == "xai-test-key"
            assert model == tqa.GROK_MODEL   # grok-4.3 since 2026-10-12
            assert tools, "MCP tools must be exposed as functions"
            if chat_calls["n"] == 1:
                return {"tool_calls": [
                    {"id": "call_1",
                     "function": {"name": "fake_tool",
                                  "arguments": '{"x": 1}'}}]}
            final_messages["messages"] = messages
            return {"content": "All done."}

        class _FakeMCP:
            def __init__(self, token, url=None):
                made["token"] = token
                made["url"] = url
            def initialize(self, timeout=60): return {}
            def list_tools(self):
                return [{"name": "fake_tool", "description": "d",
                         "inputSchema": {"type": "object", "properties": {}}}]
            def call_tool(self, name, arguments=None, timeout=300):
                assert name == "fake_tool"
                assert arguments == {"x": 1}
                return "tool-output"
            def close(self): made["closed"] = True
        monkeypatch.setattr(tqa, "_grok_chat", _fake_chat)
        monkeypatch.setattr(tqa, "_HttpMCPClient", _FakeMCP)
        monkeypatch.setattr(tqa, "load_config",
                            lambda: {"allowed_tools": "mcp__ai-prowler__*"})
        ok, detail = tqa._run_grok_headless("do tasks", 60, "test run")
        assert ok is True
        assert detail == "All done."
        # Signed in to the running AI-Prowler with this install's token, and
        # the session was closed afterwards.
        assert made["token"] == "tok-grok" and made.get("closed") is True
        assert made["url"] is None            # default = the local connection
        # The tool result was fed back into the conversation correctly.
        tool_msgs = [m for m in final_messages["messages"]
                     if m.get("role") == "tool"]
        assert len(tool_msgs) == 1
        assert tool_msgs[0]["content"] == "tool-output"
        assert tool_msgs[0]["tool_call_id"] == "call_1"
        assert tqa.load_last_run()["status"] == "success"

    def test_tool_loop_surfaces_tool_errors_as_messages(
            self, _isolated_home, monkeypatch):
        _running_server(_isolated_home, monkeypatch)
        monkeypatch.setattr(tqa, "load_api_key",
                            lambda provider="anthropic": "xai-test-key")
        chat_calls = {"n": 0}
        final_messages = {}

        def _fake_chat(api_key, messages, tools, model=None):
            chat_calls["n"] += 1
            if chat_calls["n"] == 1:
                return {"tool_calls": [
                    {"id": "c1",
                     "function": {"name": "broken_tool", "arguments": "{}"}}]}
            final_messages["messages"] = messages
            return {"content": "Recovered."}

        class _FakeMCP:
            def __init__(self, *a, **kw): pass
            def initialize(self, timeout=60): return {}
            def list_tools(self):
                return [{"name": "broken_tool", "description": "d",
                         "inputSchema": {"type": "object", "properties": {}}}]
            def call_tool(self, name, arguments=None, timeout=300):
                raise RuntimeError("boom")
            def close(self): pass
        monkeypatch.setattr(tqa, "_grok_chat", _fake_chat)
        monkeypatch.setattr(tqa, "_HttpMCPClient", _FakeMCP)
        monkeypatch.setattr(tqa, "load_config",
                            lambda: {"allowed_tools": "mcp__ai-prowler__*"})
        ok, detail = tqa._run_grok_headless("do tasks", 60, "test run")
        assert ok is True  # a tool error must not kill the whole run
        tool_msgs = [m for m in final_messages["messages"]
                     if m.get("role") == "tool"]
        assert "ERROR calling broken_tool" in tool_msgs[0]["content"]

    def test_connect_failure_is_reported(self, _isolated_home, monkeypatch):
        _running_server(_isolated_home, monkeypatch)
        monkeypatch.setattr(tqa, "load_api_key", lambda provider="anthropic": "xai-k")

        class _DeadMCP:
            def __init__(self, *a, **kw): pass
            def initialize(self, timeout=60): raise OSError("connection refused")
            def close(self): pass
        monkeypatch.setattr(tqa, "_HttpMCPClient", _DeadMCP)
        ok, detail = tqa._run_grok_headless("do tasks", 60, "test run")
        assert ok is False
        assert "Could not connect to the running AI-Prowler" in detail


# ── Dry-run provider branching ─────────────────────────────────────────────

class TestGrokDryRun:
    def test_dry_run_grok_skips_claude_cli_checks(
            self, _isolated_home, monkeypatch):
        cfg = tqa.load_config()
        cfg["use_api_key"] = True
        cfg["api_key_provider"] = "grok"
        tqa.save_config(cfg)
        tqa.save_api_key("xai-k", "grok")
        class _Resp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda req, timeout=None: _Resp())
        # If the Claude CLI checks ran, this would make them fail.
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.subprocess, "run",
                            lambda *a, **kw: type("R", (), {
                                "returncode": 1, "stdout": "", "stderr": ""})())
        report = tqa.dry_run_check()
        names = [c["name"] for c in report["checks"]]
        assert "xAI API reachable" in names
        assert "Claude Code CLI on PATH" not in names
        assert "Claude Code CLI runs" not in names
        assert "Grok API key (xAI)" in names
        assert "Claude API key" not in names
        assert "Claude Code auth token" not in names
        key_check = next(c for c in report["checks"]
                         if c["name"] == "Grok API key (xAI)")
        assert key_check["ok"] is True

    def test_dry_run_grok_flags_missing_key(
            self, _isolated_home, monkeypatch):
        cfg = tqa.load_config()
        cfg["use_api_key"] = True
        cfg["api_key_provider"] = "grok"
        tqa.save_config(cfg)
        class _Resp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda req, timeout=None: _Resp())
        monkeypatch.setattr(tqa.subprocess, "run",
                            lambda *a, **kw: type("R", (), {
                                "returncode": 1, "stdout": "", "stderr": ""})())
        report = tqa.dry_run_check()
        key_check = next(c for c in report["checks"]
                         if c["name"] == "Grok API key (xAI)")
        assert key_check["ok"] is False
        assert report["all_ok"] is False
