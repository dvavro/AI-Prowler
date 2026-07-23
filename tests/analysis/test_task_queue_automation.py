"""
Tests for task_queue_automation.py.

CRITICAL SAFETY NOTE: every test in this file patches Path.home() to a
pytest tmp_path fixture. Nothing here is allowed to read or write the
REAL ~/.ai-prowler/ directory, and no test creates a real (enabled)
Windows Scheduled Task — the scheduled-task tests explicitly install in
DISABLED state, assert on that, then uninstall in a finally block so a
failed assertion still cleans up.
"""
import json
import os
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import task_queue_automation as tqa


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Every test in this module runs against a fake HOME, never the real
    ~/.ai-prowler/. This is the single most important fixture in this file."""
    monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path / ".ai-prowler")
    monkeypatch.setattr(tqa, "CONFIG_PATH", tmp_path / ".ai-prowler" / "task_automation_config.json")
    monkeypatch.setattr(tqa, "STATUS_PATH", tmp_path / ".ai-prowler" / "task_automation_last_run.json")
    monkeypatch.setattr(tqa, "AUDIT_LOG_PATH", tmp_path / ".ai-prowler" / "autonomous_run_audit.log")
    monkeypatch.setattr(tqa, "AI_PROWLER_CONFIG_PATH", tmp_path / ".ai-prowler" / "config.json")
    monkeypatch.setattr(tqa, "GENERATED_MCP_CONFIG_PATH", tmp_path / ".ai-prowler" / "claude_mcp_config.json")
    # v8.2.x: generate_mcp_config() now tries a local stdio config first
    # (see task_queue_automation.py's module comment above LOCAL_MCP_SCRIPT_PATH).
    # Point it at a path that does NOT exist by default so existing
    # remote-config tests keep exercising the remote path unchanged;
    # individual local-path tests override this per-test.
    monkeypatch.setattr(tqa, "LOCAL_MCP_SCRIPT_PATH",
                         tmp_path / "_no_such_dir" / "ai_prowler_mcp.py")
    monkeypatch.setattr(tqa, "API_KEY_PATH", tmp_path / ".ai-prowler" / "claude_api_key.txt")
    # v8.1.6: same isolation requirement for the new OAuth-token files —
    # without this, tests would read/write the REAL
    # ~/.ai-prowler/claude_oauth_token.json on the machine running them.
    monkeypatch.setattr(tqa, "OAUTH_TOKEN_PATH", tmp_path / ".ai-prowler" / "claude_oauth_token.json")
    monkeypatch.setattr(tqa, "OAUTH_TOKEN_PLAIN_PATH", tmp_path / ".ai-prowler" / "claude_oauth_token.txt")
    monkeypatch.setattr(tqa, "SETUP_TOKEN_OUTPUT_PATH", tmp_path / ".ai-prowler" / "setup_token_output.txt")
    monkeypatch.setattr(tqa, "SETUP_TOKEN_BAT_PATH", tmp_path / ".ai-prowler" / "run_setup_token.bat")
    yield tmp_path


# ── Config I/O ────────────────────────────────────────────────────────────

def test_load_config_returns_defaults_when_missing(_isolated_home):
    cfg = tqa.load_config()
    assert cfg["enabled"] is False
    assert cfg["schedule_time"] == "06:00"


def test_save_then_load_roundtrips(_isolated_home):
    cfg = tqa.load_config()
    cfg["enabled"] = True
    cfg["schedule_time"] = "18:30"
    tqa.save_config(cfg)
    reloaded = tqa.load_config()
    assert reloaded["enabled"] is True
    assert reloaded["schedule_time"] == "18:30"


def test_load_config_survives_corrupt_json(_isolated_home):
    tqa.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tqa.CONFIG_PATH.write_text("{not valid json", encoding="utf-8")
    cfg = tqa.load_config()
    # Must fall back to safe defaults, not raise.
    assert cfg["enabled"] is False


def test_load_last_run_none_when_absent(_isolated_home):
    assert tqa.load_last_run() is None


# ── Wrapper script content (pure function, no file I/O) ───────────────────

def test_wrapper_script_contains_headless_flag():
    content = tqa.build_wrapper_script_content("C:\\fake\\mcp.json", "mcp__ai-prowler__*")
    assert "claude -p" in content
    assert "--mcp-config" in content
    assert "C:\\fake\\mcp.json" in content
    assert "--allowedTools" in content
    assert "mcp__ai-prowler__*" in content


def test_wrapper_script_scopes_tools_not_wildcard_bash():
    # Regression guard for the permission-scoping requirement in the spec
    # (Section 5.1) — the generated script must never grant unscoped Bash.
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    assert '"Bash"' not in content
    assert "--dangerously-skip-permissions" not in content


def test_wrapper_script_no_notify_clause_by_default():
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    assert "send_sms" not in content
    assert "send_whatsapp" not in content


def test_wrapper_script_includes_sms_notify_instruction_when_enabled():
    content = tqa.build_wrapper_script_content(
        "x.json", "mcp__ai-prowler__*", notify_on_complete=True, notify_method="sms")
    assert "send_sms" in content
    assert "send_whatsapp" not in content
    # Must be phrased as best-effort, not a hard requirement — a missing
    # notification tool should never fail the whole run.
    assert "skip this step silently" in content


def test_wrapper_script_includes_whatsapp_notify_instruction_when_configured():
    content = tqa.build_wrapper_script_content(
        "x.json", "mcp__ai-prowler__*", notify_on_complete=True, notify_method="whatsapp")
    assert "send_whatsapp" in content
    assert "send_sms" not in content


def test_install_wrapper_script_writes_expected_file(tmp_path):
    target = tmp_path / "wrapper_dir"
    path = tqa.install_wrapper_script(target, "C:\\x\\mcp.json", "mcp__ai-prowler__*")
    assert path.exists()
    assert path.name == tqa.WRAPPER_SCRIPT_NAME
    assert "claude -p" in path.read_text(encoding="utf-8")


def test_install_wrapper_script_never_targets_program_files(tmp_path):
    # This is the test that directly enforces "does not affect my installed
    # AI-Prowler" — it actually calls the function (not just greps source
    # text, which false-positives on the docstring's explanatory comment)
    # and asserts the real, resulting file path never touches Program Files.
    target = tmp_path / "some_dir"
    path = tqa.install_wrapper_script(target, "x.json", "mcp__ai-prowler__*")
    assert "Program Files" not in str(path)
    assert str(path).startswith(str(tmp_path))
    # And confirm the function signature has no hardcoded default that
    # would bypass the caller-supplied target_dir.
    import inspect
    sig = inspect.signature(tqa.install_wrapper_script)
    assert sig.parameters["target_dir"].default is inspect.Parameter.empty


# ── Dry-run check ───────────────────────────────────────────────────────

def test_dry_run_check_never_calls_claude_dash_p(_isolated_home, monkeypatch):
    """The single most important safety test in this file: dry_run_check()
    must never invoke `claude -p` (a real, unattended, non-dry-run session).
    We monkeypatch subprocess.run to explode if it ever sees "-p" in argv,
    so this fails loudly instead of silently doing a real run during CI."""
    real_run = subprocess.run

    def _guarded_run(args, *a, **kw):
        if isinstance(args, (list, tuple)) and "-p" in args:
            raise AssertionError(f"dry_run_check() must never invoke claude -p! args={args}")
        # Let --version and schtasks calls through to a harmless mock.
        class _FakeResult:
            returncode = 1
            stdout = ""
            stderr = "mocked: not found"
        return _FakeResult()

    monkeypatch.setattr(tqa.subprocess, "run", _guarded_run)
    report = tqa.dry_run_check()
    assert "checks" in report
    assert isinstance(report["all_ok"], bool)


def test_dry_run_check_writes_status_file(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})())
    tqa.dry_run_check()
    status = tqa.load_last_run()
    assert status is not None
    assert status["status"] in ("dry_run_ok", "dry_run_failed")


def test_dry_run_check_reports_missing_claude_cli(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
    report = tqa.dry_run_check()
    claude_check = next(c for c in report["checks"] if c["name"] == "Claude Code CLI on PATH")
    assert claude_check["ok"] is False
    assert report["all_ok"] is False


# ── Scheduled Task management ────────────────────────────────────────────
# These tests actually call schtasks.exe, but ALWAYS in disabled mode, and
# ALWAYS clean up in a finally block — even on assertion failure.

def test_scheduled_task_install_disabled_then_uninstall(tmp_path):
    wrapper = tmp_path / "run_ai_prowler_queue.bat"
    wrapper.write_text("@echo off\r\necho test\r\n", encoding="utf-8")
    try:
        ok, detail = tqa.install_scheduled_task(wrapper, "23:59", enabled=False)
        assert ok, detail
        assert tqa.scheduled_task_exists() is True
        # The real fix: scheduled_task_exists() alone can't prove the task
        # is actually OFF — it returns True for an enabled task just as
        # readily. scheduled_task_enabled() checks the real state.
        assert tqa.scheduled_task_enabled() is False
    finally:
        uninstalled_ok, uninstall_detail = tqa.uninstall_scheduled_task()
        assert uninstalled_ok, uninstall_detail
        assert tqa.scheduled_task_exists() is False


def test_scheduled_task_install_enabled_reports_enabled_state(tmp_path):
    # Complements the disabled-path test above — proves enabled=True
    # actually results in an enabled task, not just "didn't error."
    # Uninstalled immediately in the finally block; the window where a
    # real enabled task exists on this machine is the few milliseconds
    # between install and the immediate state-check + uninstall below.
    wrapper = tmp_path / "run_ai_prowler_queue.bat"
    wrapper.write_text("@echo off\r\necho test\r\n", encoding="utf-8")
    try:
        ok, detail = tqa.install_scheduled_task(wrapper, "23:59", enabled=True)
        assert ok, detail
        assert tqa.scheduled_task_enabled() is True
    finally:
        tqa.uninstall_scheduled_task()
        assert tqa.scheduled_task_exists() is False


def test_scheduled_task_enabled_none_when_not_present(tmp_path):
    # Ensure a clean slate — if a prior failed test somehow left a task
    # behind, this would otherwise false-fail.
    tqa.uninstall_scheduled_task()
    assert tqa.scheduled_task_enabled() is None


def test_install_scheduled_task_reports_failure_on_bad_time_format(tmp_path):
    # schtasks itself rejects malformed /st values — confirm we surface
    # that as a real failure rather than silently reporting success, and
    # confirm no task gets left behind when creation fails.
    wrapper = tmp_path / "run_ai_prowler_queue.bat"
    wrapper.write_text("@echo off\r\necho test\r\n", encoding="utf-8")
    try:
        ok, detail = tqa.install_scheduled_task(wrapper, "99:99", enabled=False)
        assert ok is False
        assert detail  # some real error text, not empty
    finally:
        tqa.uninstall_scheduled_task()
        assert tqa.scheduled_task_exists() is False


def test_uninstall_when_never_installed_is_safe(tmp_path):
    ok, detail = tqa.uninstall_scheduled_task()
    assert ok
    assert "not present" in detail


# ── Audit log read ────────────────────────────────────────────────────────

def test_read_audit_log_tail_when_missing(_isolated_home):
    text = tqa.read_audit_log_tail()
    assert "no audit log yet" in text


def test_read_audit_log_tail_reads_last_n_lines(_isolated_home):
    tqa.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tqa.AUDIT_LOG_PATH.write_text("\n".join(f"line {i}" for i in range(500)), encoding="utf-8")
    tail = tqa.read_audit_log_tail(n_lines=10)
    lines = tail.splitlines()
    assert len(lines) == 10
    assert lines[-1] == "line 499"


# ── Project artifacts (.claude/settings.json, hooks, Skill) sanity ───────

def test_claude_settings_json_is_valid_and_scoped_to_project():
    settings_path = Path(__file__).resolve().parents[2] / ".claude" / "settings.json"
    assert settings_path.exists()
    data = json.loads(settings_path.read_text(encoding="utf-8"))
    assert "PostToolUse" in data["hooks"]
    matcher = data["hooks"]["PostToolUse"][0]["matcher"]
    assert "ai-prowler" in matcher


def test_log_tool_call_hook_ignores_non_ai_prowler_tools(tmp_path, monkeypatch):
    hook_path = Path(__file__).resolve().parents[2] / ".claude" / "hooks" / "log_tool_call.py"
    assert hook_path.exists()
    fake_home = tmp_path
    event = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
    r = subprocess.run([sys.executable, str(hook_path)], input=event,
                        capture_output=True, text=True,
                        env={"HOME": str(fake_home), "USERPROFILE": str(fake_home)})
    assert r.returncode == 0
    # Non-AI-Prowler tool calls must not create a log entry.
    assert not (fake_home / ".ai-prowler" / "autonomous_run_audit.log").exists()


def test_log_tool_call_hook_logs_ai_prowler_tools(tmp_path):
    hook_path = Path(__file__).resolve().parents[2] / ".claude" / "hooks" / "log_tool_call.py"
    fake_home = tmp_path
    event = json.dumps({
        "tool_name": "mcp__ai-prowler__get_pending_analysis_tasks",
        "tool_input": {},
        "tool_response": {"is_error": False},
    })
    r = subprocess.run([sys.executable, str(hook_path)], input=event,
                        capture_output=True, text=True, env={"HOME": str(fake_home),
                                                              "USERPROFILE": str(fake_home)})
    assert r.returncode == 0
    log_path = fake_home / ".ai-prowler" / "autonomous_run_audit.log"
    assert log_path.exists()
    assert "get_pending_analysis_tasks" in log_path.read_text(encoding="utf-8")


# ── Claude Code auth token expiry ─────────────────────────────────────────
# v8.1.6: rewritten against OAUTH_TOKEN_PATH (claude_oauth_token.json,
# {token, issued_at}) instead of the old ~/.claude/.credentials.json
# ({expiresAt} in epoch ms) — `claude setup-token` never wrote that file
# in the first place; see check_token_expiry()'s docstring.

def test_token_expiry_no_credentials_file(_isolated_home):
    info = tqa.check_token_expiry()
    assert info["status"] == "no_credentials"


def test_token_expiry_future_date_is_ok(_isolated_home):
    tqa.OAUTH_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    issued = datetime.now(timezone.utc) - timedelta(days=10)  # 355 days left
    tqa.save_oauth_token("sk-ant-oat01-fake-token-value", issued_at=issued)
    info = tqa.check_token_expiry()
    assert info["status"] == "ok"
    assert info["days_remaining"] > 350


def test_token_expiry_within_7_days_is_expiring_soon(_isolated_home):
    tqa.OAUTH_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    issued = datetime.now(timezone.utc) - timedelta(days=tqa.OAUTH_TOKEN_LIFETIME_DAYS - 3)
    tqa.save_oauth_token("sk-ant-oat01-fake-token-value", issued_at=issued)
    info = tqa.check_token_expiry()
    assert info["status"] == "expiring_soon"


def test_token_expiry_past_date_is_expired(_isolated_home):
    tqa.OAUTH_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    issued = datetime.now(timezone.utc) - timedelta(days=tqa.OAUTH_TOKEN_LIFETIME_DAYS + 1)
    tqa.save_oauth_token("sk-ant-oat01-fake-token-value", issued_at=issued)
    info = tqa.check_token_expiry()
    assert info["status"] == "expired"
    assert info["days_remaining"] < 0


def test_token_expiry_corrupt_file_is_unreadable_not_crash(_isolated_home):
    tqa.OAUTH_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    tqa.OAUTH_TOKEN_PATH.write_text("{not valid json", encoding="utf-8")
    info = tqa.check_token_expiry()
    assert info["status"] == "unreadable"


def test_token_expiry_captures_token_from_setup_token_output(_isolated_home):
    """The core v8.1.6 regression test: a completed `claude setup-token`
    run leaves its printed output in SETUP_TOKEN_OUTPUT_PATH, and
    check_token_expiry() must pick it up on the very next call — no
    separate 'confirm' step, and no dependency on .credentials.json."""
    tqa.AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    tqa.SETUP_TOKEN_OUTPUT_PATH.write_text(
        "Login successful!\nYour OAuth token (valid for 1 year):\n"
        "sk-ant-oat01-oCRdTGIKIRlwpPSpBiREYMW8oGSt-fake-suffix\n",
        encoding="utf-8")
    info = tqa.check_token_expiry()
    assert info["status"] == "ok"
    # Output file should be cleaned up once captured — no plaintext token
    # left lying around longer than necessary.
    assert not tqa.SETUP_TOKEN_OUTPUT_PATH.exists()
    assert tqa.load_oauth_token() == "sk-ant-oat01-oCRdTGIKIRlwpPSpBiREYMW8oGSt-fake-suffix"


def test_token_expiry_backfills_plain_mirror_for_pre_existing_json(_isolated_home):
    """v8.1.6 third-fix regression test: a token saved under the OLD code
    (JSON only, no .txt mirror) must get the .txt mirror backfilled the
    next time check_token_expiry() runs — an already-valid, not-expired
    token should never force the user through browser OAuth again just
    because of an internal storage-format change."""
    tqa.AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
    tqa.OAUTH_TOKEN_PATH.write_text(json.dumps({
        "token": "sk-ant-oat01-pre-existing-token",
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }), encoding="utf-8")
    assert not tqa.OAUTH_TOKEN_PLAIN_PATH.exists()  # simulates a pre-fix install
    info = tqa.check_token_expiry()
    assert info["status"] == "ok"
    assert tqa.OAUTH_TOKEN_PLAIN_PATH.exists()
    assert tqa.OAUTH_TOKEN_PLAIN_PATH.read_text(encoding="utf-8") == "sk-ant-oat01-pre-existing-token"


def test_dry_run_check_includes_token_expiry(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})())
    report = tqa.dry_run_check()
    names = [c["name"] for c in report["checks"]]
    assert "Claude Code auth token" in names


# ── setup-token terminal launch ───────────────────────────────────────────

def test_build_setup_token_batch_content_runs_correct_command():
    content = tqa.build_setup_token_batch_content()
    assert "claude setup-token" in content
    # Must tee to SETUP_TOKEN_OUTPUT_PATH so try_capture_setup_token() can
    # find the printed token afterward.
    assert str(tqa.SETUP_TOKEN_OUTPUT_PATH) in content


def test_build_setup_token_launch_args_runs_correct_command():
    # v8.1.6: this now launches a plain .bat file via `cmd /c` rather
    # than a single quoted command-line string — cmd.exe's own /k
    # parsing of nested quotes + redirection + `&` reliably broke with
    # "The filename, directory name, or volume label syntax is
    # incorrect." A single, simply-quoted path avoids that class of bug
    # entirely. See build_setup_token_batch_content() for the actual
    # command being run.
    args = tqa.build_setup_token_launch_args()
    assert args[0] == "cmd"
    assert args[1] == "/c"
    assert args[2] == str(tqa.SETUP_TOKEN_BAT_PATH)


def test_open_setup_token_terminal_never_blocks_or_hangs(monkeypatch):
    # This must never actually wait on the spawned process — it should
    # fire-and-forget so the GUI button doesn't freeze the Tk mainloop.
    calls = []

    class _FakeProc:
        pass

    def _fake_popen(args, **kwargs):
        calls.append((args, kwargs))
        return _FakeProc()

    monkeypatch.setattr(tqa.subprocess, "Popen", _fake_popen)
    ok, detail = tqa.open_setup_token_terminal()
    assert ok is True
    assert len(calls) == 1
    # Must use CREATE_NEW_CONSOLE so it's a real visible window the user
    # can interact with, not a hidden/attached child process.
    assert calls[0][1].get("creationflags") == subprocess.CREATE_NEW_CONSOLE


def test_open_setup_token_terminal_reports_failure_gracefully(monkeypatch):
    def _fake_popen(args, **kwargs):
        raise OSError("cmd.exe not found")
    monkeypatch.setattr(tqa.subprocess, "Popen", _fake_popen)
    ok, detail = tqa.open_setup_token_terminal()
    assert ok is False
    assert "cmd.exe not found" in detail


# ── AI-Prowler MCP config generation ──────────────────────────────────────

def _write_ai_prowler_config(home, **overrides):
    cfg_path = home / ".ai-prowler" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    data = {"remote_token": "test-token-abc123", "tunnel_domain": "example-tunnel.ai-prowler.com"}
    data.update(overrides)
    cfg_path.write_text(json.dumps(data), encoding="utf-8")
    return cfg_path


def test_generate_mcp_config_missing_ai_prowler_config(_isolated_home):
    ok, detail = tqa.generate_mcp_config()
    assert ok is False
    assert "not found" in detail


def test_generate_mcp_config_missing_token(_isolated_home):
    _write_ai_prowler_config(_isolated_home, remote_token="")
    ok, detail = tqa.generate_mcp_config()
    assert ok is False
    assert "Bearer Token" in detail


def test_generate_mcp_config_missing_domain(_isolated_home):
    _write_ai_prowler_config(_isolated_home, tunnel_domain="")
    ok, detail = tqa.generate_mcp_config()
    assert ok is False
    assert "tunnel domain" in detail


def test_generate_mcp_config_writes_correct_schema(_isolated_home):
    _write_ai_prowler_config(_isolated_home)
    ok, path = tqa.generate_mcp_config()
    assert ok is True
    written = json.loads(Path(path).read_text(encoding="utf-8"))
    server = written["mcpServers"]["ai-prowler"]
    assert server["type"] == "http"
    assert server["url"] == "https://example-tunnel.ai-prowler.com/mcp"
    assert server["headers"]["Authorization"] == "Bearer test-token-abc123"


def test_generate_mcp_config_strips_protocol_from_domain(_isolated_home):
    _write_ai_prowler_config(_isolated_home, tunnel_domain="https://example-tunnel.ai-prowler.com/")
    ok, path = tqa.generate_mcp_config()
    assert ok is True
    written = json.loads(Path(path).read_text(encoding="utf-8"))
    assert written["mcpServers"]["ai-prowler"]["url"] == "https://example-tunnel.ai-prowler.com/mcp"


def test_generate_mcp_config_survives_corrupt_ai_prowler_config(_isolated_home):
    cfg_path = _isolated_home / ".ai-prowler" / "config.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text("{not valid json", encoding="utf-8")
    ok, detail = tqa.generate_mcp_config()
    assert ok is False
    assert "Could not read" in detail


# ── v8.2.x: local stdio MCP config (fresh-install fix) ─────────────────────
# Bug report: on a fresh install / fresh machine, clicking Test Setup (Dry
# Run) never produced an MCP config file even after successfully getting a
# Claude Code token. Root cause: generate_mcp_config() only ever wrote a
# REMOTE config, gated on AI-Prowler's own Bearer Token + tunnel domain
# (Settings -> Remote Access) -- a third, unrelated piece of setup that a
# fresh machine simply doesn't have yet, regardless of the Claude Code
# token being valid. These tests cover the local-first fix.

def _make_fake_mcp_script(home) -> Path:
    """Simulates ai_prowler_mcp.py sitting next to task_queue_automation.py
    on a real install, without needing the real (large) file."""
    script = home / "fake_ai_prowler_mcp.py"
    script.write_text("# fake MCP script for tests\n", encoding="utf-8")
    return script


def test_generate_mcp_config_uses_local_on_fresh_machine(_isolated_home, monkeypatch):
    """THE bug-report scenario: nothing configured at all -- no AI-Prowler
    config.json, no Bearer Token, no tunnel -- just a fresh install with
    the MCP script present. generate_mcp_config() must still succeed."""
    fake_script = _make_fake_mcp_script(_isolated_home)
    monkeypatch.setattr(tqa, "LOCAL_MCP_SCRIPT_PATH", fake_script)
    # No AI-Prowler config.json written at all -- confirms this path does
    # NOT depend on it, unlike the old behavior.
    assert not tqa.AI_PROWLER_CONFIG_PATH.exists()

    ok, path = tqa.generate_mcp_config()

    assert ok is True, path
    assert Path(path) == tqa.GENERATED_MCP_CONFIG_PATH
    assert Path(path).exists()


def test_generate_mcp_config_local_schema_is_stdio(_isolated_home, monkeypatch):
    fake_script = _make_fake_mcp_script(_isolated_home)
    monkeypatch.setattr(tqa, "LOCAL_MCP_SCRIPT_PATH", fake_script)

    ok, path = tqa.generate_mcp_config()
    assert ok is True

    written = json.loads(Path(path).read_text(encoding="utf-8"))
    server = written["mcpServers"]["ai-prowler"]
    assert server["command"] == sys.executable
    assert server["args"] == [str(fake_script)]
    assert "type" not in server  # stdio, not http -- no "type": "http" key
    assert server["env"]["PYTHONUNBUFFERED"] == "1"


def test_generate_mcp_config_falls_back_to_remote_when_local_script_missing(_isolated_home):
    # Default fixture already points LOCAL_MCP_SCRIPT_PATH at a
    # nonexistent file. With a fully valid remote config present, the
    # overall call must still succeed via the remote fallback.
    _write_ai_prowler_config(_isolated_home)
    ok, path = tqa.generate_mcp_config()
    assert ok is True
    written = json.loads(Path(path).read_text(encoding="utf-8"))
    assert written["mcpServers"]["ai-prowler"]["type"] == "http"


def test_generate_mcp_config_fails_when_neither_local_nor_remote_available(_isolated_home):
    # Nothing at all -- matches test_generate_mcp_config_missing_ai_prowler_config
    # but explicit about covering the combined generate_mcp_config() entry
    # point rather than the remote helper directly.
    ok, detail = tqa.generate_mcp_config()
    assert ok is False
    assert "not found" in detail.lower()


def test_generate_mcp_config_prefer_remote_true_uses_remote_when_both_available(_isolated_home, monkeypatch):
    fake_script = _make_fake_mcp_script(_isolated_home)
    monkeypatch.setattr(tqa, "LOCAL_MCP_SCRIPT_PATH", fake_script)
    _write_ai_prowler_config(_isolated_home)

    ok, path = tqa.generate_mcp_config(prefer_remote=True)
    assert ok is True
    written = json.loads(Path(path).read_text(encoding="utf-8"))
    assert written["mcpServers"]["ai-prowler"]["type"] == "http"


def test_generate_mcp_config_prefer_remote_falls_back_to_local(_isolated_home, monkeypatch):
    # prefer_remote=True but remote isn't actually configured -- must not
    # just fail; local is still available and should be used.
    fake_script = _make_fake_mcp_script(_isolated_home)
    monkeypatch.setattr(tqa, "LOCAL_MCP_SCRIPT_PATH", fake_script)

    ok, path = tqa.generate_mcp_config(prefer_remote=True)
    assert ok is True
    written = json.loads(Path(path).read_text(encoding="utf-8"))
    assert "type" not in written["mcpServers"]["ai-prowler"]


def test_generate_mcp_config_default_prefers_local_over_remote(_isolated_home, monkeypatch):
    # Both are fully available -- default (prefer_remote=False) must pick
    # local, since that's the whole point of the fix (zero setup needed).
    fake_script = _make_fake_mcp_script(_isolated_home)
    monkeypatch.setattr(tqa, "LOCAL_MCP_SCRIPT_PATH", fake_script)
    _write_ai_prowler_config(_isolated_home)

    ok, path = tqa.generate_mcp_config()
    assert ok is True
    written = json.loads(Path(path).read_text(encoding="utf-8"))
    assert "type" not in written["mcpServers"]["ai-prowler"]


def test_dry_run_check_mcp_config_check_passes_on_fresh_machine_after_local_generate(
        _isolated_home, monkeypatch):
    """End-to-end regression test for the exact reported bug: on a fresh
    machine (nothing configured), call generate_mcp_config() the way the
    GUI's Test Setup (Dry Run) button does, save the resulting path into
    the automation config, then confirm dry_run_check()'s 'MCP config
    file' check reports ok=True."""
    fake_script = _make_fake_mcp_script(_isolated_home)
    monkeypatch.setattr(tqa, "LOCAL_MCP_SCRIPT_PATH", fake_script)
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})())

    ok, path = tqa.generate_mcp_config()
    assert ok is True
    cfg = tqa.load_config()
    cfg["mcp_config_path"] = path
    tqa.save_config(cfg)

    report = tqa.dry_run_check()
    mcp_check = next(c for c in report["checks"] if c["name"] == "MCP config file")
    assert mcp_check["ok"] is True


# ── ANTHROPIC_API_KEY fallback ─────────────────────────────────────────────

def test_has_api_key_false_when_not_set(_isolated_home):
    assert tqa.has_api_key() is False
    assert tqa.load_api_key() is None


def test_save_then_has_api_key_true(_isolated_home):
    tqa.save_api_key("sk-ant-api03-fake-test-key")
    assert tqa.has_api_key() is True


def test_load_api_key_returns_saved_value(_isolated_home):
    tqa.save_api_key("sk-ant-api03-fake-test-key")
    assert tqa.load_api_key() == "sk-ant-api03-fake-test-key"


def test_save_api_key_strips_whitespace(_isolated_home):
    tqa.save_api_key("  sk-ant-api03-fake-test-key  \n")
    assert tqa.load_api_key() == "sk-ant-api03-fake-test-key"


def test_delete_api_key_removes_file(_isolated_home):
    tqa.save_api_key("sk-ant-api03-fake-test-key")
    assert tqa.has_api_key() is True
    tqa.delete_api_key()
    assert tqa.has_api_key() is False


def test_delete_api_key_safe_when_never_set(_isolated_home):
    tqa.delete_api_key()  # must not raise
    assert tqa.has_api_key() is False


def test_empty_api_key_file_counts_as_not_set(_isolated_home):
    tqa.API_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    tqa.API_KEY_PATH.write_text("   \n", encoding="utf-8")
    assert tqa.has_api_key() is False


# ── Wrapper script: use_api_key branch ─────────────────────────────────────

def test_wrapper_script_no_api_key_block_by_default():
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    assert "ANTHROPIC_API_KEY" not in content


def test_wrapper_script_oauth_block_by_default():
    """v8.1.6 regression test: the default (use_api_key=False) branch must
    read CLAUDE_CODE_OAUTH_TOKEN from OAUTH_TOKEN_PLAIN_PATH via a plain
    `set /p`, matching the already-proven ANTHROPIC_API_KEY pattern — not
    the earlier PowerShell/ConvertFrom-Json approach, which failed at
    runtime with "the token could not be parsed" despite valid JSON."""
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    assert "CLAUDE_CODE_OAUTH_TOKEN" in content
    assert "set /p CLAUDE_CODE_OAUTH_TOKEN=" in content
    assert str(tqa.OAUTH_TOKEN_PLAIN_PATH) in content
    # Must never reintroduce the fragile PowerShell/JSON parsing path.
    assert "ConvertFrom-Json" not in content
    assert "powershell" not in content.lower()


def test_wrapper_script_includes_api_key_block_when_enabled():
    content = tqa.build_wrapper_script_content(
        "x.json", "mcp__ai-prowler__*", use_api_key=True)
    assert "ANTHROPIC_API_KEY" in content
    assert "set /p ANTHROPIC_API_KEY=" in content


def test_wrapper_script_never_embeds_raw_api_key_value():
    # Regression guard: the actual key must never appear in generated script
    # text — only the file-read mechanism. This test can't check "no key
    # anywhere" directly (there is no key passed in), so it asserts the
    # function signature has no parameter that could carry a raw key value.
    import inspect
    sig = inspect.signature(tqa.build_wrapper_script_content)
    assert "api_key" not in sig.parameters  # only "use_api_key" (a bool) should exist
    assert "use_api_key" in sig.parameters


def test_wrapper_script_api_key_block_fails_loudly_if_file_missing():
    content = tqa.build_wrapper_script_content(
        "x.json", "mcp__ai-prowler__*", use_api_key=True)
    assert "exit /b 1" in content
    assert "[ERROR]" in content


def test_install_wrapper_script_passes_through_use_api_key(tmp_path):
    target = tmp_path / "wrapper_dir"
    path = tqa.install_wrapper_script(
        target, "x.json", "mcp__ai-prowler__*", use_api_key=True)
    assert "ANTHROPIC_API_KEY" in path.read_text(encoding="utf-8")


# ── dry_run_check: auth branch ─────────────────────────────────────────────

def test_dry_run_check_shows_oauth_token_when_use_api_key_false(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})())
    report = tqa.dry_run_check()
    names = [c["name"] for c in report["checks"]]
    assert "Claude Code auth token" in names
    assert "Claude API key" not in names


def test_dry_run_check_shows_api_key_when_use_api_key_true(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})())
    cfg = tqa.load_config()
    cfg["use_api_key"] = True
    tqa.save_config(cfg)
    report = tqa.dry_run_check()
    names = [c["name"] for c in report["checks"]]
    assert "Claude API key" in names
    assert "Claude Code auth token" not in names


def test_dry_run_check_api_key_detail_never_shows_value(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})())
    cfg = tqa.load_config()
    cfg["use_api_key"] = True
    tqa.save_config(cfg)
    tqa.save_api_key("sk-ant-api03-super-secret-value")
    report = tqa.dry_run_check()
    key_check = next(c for c in report["checks"] if c["name"] == "Claude API key")
    assert key_check["ok"] is True
    assert "sk-ant-api03-super-secret-value" not in key_check["detail"]


# ── Claude Code CLI presence + install ────────────────────────────────────

def test_claude_code_cli_installed_true_when_on_path(monkeypatch):
    monkeypatch.setattr(tqa.shutil, "which", lambda name: r"C:\fake\claude.exe")
    assert tqa.claude_code_cli_installed() is True


def test_claude_code_cli_installed_false_when_absent(monkeypatch):
    monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
    assert tqa.claude_code_cli_installed() is False


def test_install_claude_code_cli_skips_when_already_installed(monkeypatch):
    # Critical safety test: must NEVER invoke subprocess.run (i.e. never
    # actually run the installer) when claude is already on PATH.
    monkeypatch.setattr(tqa.shutil, "which", lambda name: r"C:\fake\claude.exe")

    def _guarded_run(*a, **kw):
        raise AssertionError("Must not invoke the installer when already installed!")
    monkeypatch.setattr(tqa.subprocess, "run", _guarded_run)

    ok, detail = tqa.install_claude_code_cli()
    assert ok is True
    assert "Already installed" in detail


def test_install_claude_code_cli_runs_installer_when_missing_then_reverifies(monkeypatch):
    # Simulate: not installed -> run installer -> now installed.
    calls = {"which_count": 0}

    def _fake_which(name):
        calls["which_count"] += 1
        # First call (pre-check) -> not found. Second call (post-install
        # re-verify) -> found. Mirrors the installer's own script logic.
        return None if calls["which_count"] == 1 else r"C:\fake\claude.exe"

    monkeypatch.setattr(tqa.shutil, "which", _fake_which)

    run_calls = []
    def _fake_run(args, **kwargs):
        run_calls.append(args)
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    monkeypatch.setattr(tqa.subprocess, "run", _fake_run)

    ok, detail = tqa.install_claude_code_cli()
    assert ok is True
    assert len(run_calls) == 1
    # Must use the native installer, never npm.
    joined = " ".join(run_calls[0])
    assert "install.ps1" in joined
    assert "npm" not in joined


def test_install_claude_code_cli_reports_failure_if_still_missing(monkeypatch):
    monkeypatch.setattr(tqa.shutil, "which", lambda name: None)  # never appears
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": "boom"})())
    ok, detail = tqa.install_claude_code_cli()
    assert ok is False
    assert "not found on PATH" in detail or "boom" in detail


def test_install_claude_code_cli_handles_timeout_gracefully(monkeypatch):
    monkeypatch.setattr(tqa.shutil, "which", lambda name: None)

    def _fake_run(*a, **kw):
        raise tqa.subprocess.TimeoutExpired(cmd="powershell", timeout=120)
    monkeypatch.setattr(tqa.subprocess, "run", _fake_run)

    ok, detail = tqa.install_claude_code_cli()
    assert ok is False
    assert "timed out" in detail.lower()


# ── PATH fix fallback ───────────────────────────────────────────────────────
# Real-world finding: the native installer writes claude.exe to
# ~/.local/bin but does NOT reliably add that folder to PATH itself — it
# can succeed completely while still leaving `claude` unresolvable via
# shutil.which(). These tests cover the fallback that fixes PATH directly
# instead of just reporting a false failure.

class _FakeWinreg:
    """Minimal stand-in for the winreg module, injected via sys.modules
    so `import winreg` inside _add_to_user_path picks this up instead of
    (on non-Windows test runners) failing, or (on Windows) touching the
    real registry."""
    HKEY_CURRENT_USER = "HKCU"
    KEY_READ = 1
    KEY_WRITE = 2
    REG_EXPAND_SZ = 2

    def __init__(self, existing_path=""):
        self.existing_path = existing_path
        self.set_calls = []

    def OpenKey(self, hive, subkey, res, access):
        return _FakeWinregKey(self)

    def QueryValueEx(self, key, name):
        if not self.existing_path:
            raise FileNotFoundError()
        return self.existing_path, self.REG_EXPAND_SZ

    def SetValueEx(self, key, name, res, kind, value):
        self.set_calls.append(value)


class _FakeWinregKey:
    def __init__(self, parent):
        self._parent = parent

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def fake_winreg(monkeypatch):
    fw = _FakeWinreg()
    monkeypatch.setitem(sys.modules, "winreg", fw)
    # OpenKey/QueryValueEx/SetValueEx are looked up as module-level
    # functions (winreg.OpenKey(...)), not FakeWinreg methods with self —
    # patch them onto the fake module object directly.
    fw.OpenKey = lambda hive, subkey, res, access: _FakeWinregKey(fw)
    fw.QueryValueEx = lambda key, name: (
        (fw.existing_path, fw.REG_EXPAND_SZ) if fw.existing_path
        else (_ for _ in ()).throw(FileNotFoundError())
    )
    fw.SetValueEx = lambda key, name, res, kind, value: fw.set_calls.append(value)
    yield fw
    monkeypatch.delitem(sys.modules, "winreg", raising=False)


def test_add_to_user_path_appends_when_not_present(fake_winreg, monkeypatch):
    fake_winreg.existing_path = r"C:\Windows;C:\Windows\System32"
    changed = tqa._add_to_user_path(Path(r"C:\Users\test\.local\bin"))
    assert changed is True
    assert len(fake_winreg.set_calls) == 1
    assert r"C:\Users\test\.local\bin" in fake_winreg.set_calls[0]
    # Also updates THIS process's own environ so an immediate re-check works.
    assert r"C:\Users\test\.local\bin" in os.environ["PATH"]


def test_add_to_user_path_skips_when_already_present(fake_winreg):
    fake_winreg.existing_path = r"C:\Windows;C:\Users\test\.local\bin;C:\Windows\System32"
    changed = tqa._add_to_user_path(Path(r"C:\Users\test\.local\bin"))
    assert changed is False
    assert len(fake_winreg.set_calls) == 0


def test_add_to_user_path_handles_missing_registry_value(fake_winreg):
    fake_winreg.existing_path = ""  # QueryValueEx raises FileNotFoundError
    changed = tqa._add_to_user_path(Path(r"C:\Users\test\.local\bin"))
    assert changed is True
    assert len(fake_winreg.set_calls) == 1


def test_add_to_user_path_never_raises_on_registry_error(monkeypatch):
    class _BoomWinreg:
        HKEY_CURRENT_USER = "HKCU"
        KEY_READ = 1
        KEY_WRITE = 2

        def OpenKey(self, *a, **kw):
            raise OSError("access denied")

    monkeypatch.setitem(sys.modules, "winreg", _BoomWinreg())
    changed = tqa._add_to_user_path(Path(r"C:\Users\test\.local\bin"))
    assert changed is False  # never raises, just reports "nothing changed"


def test_install_claude_code_cli_falls_back_to_path_fix(tmp_path, monkeypatch):
    # Simulate: installer succeeds and drops claude.exe in ~/.local/bin,
    # but shutil.which() never finds it (matches the real-world finding —
    # the installer can succeed while leaving PATH untouched). Confirm
    # the fallback actually gets invoked rather than just reporting failure.
    fake_home = tmp_path
    monkeypatch.setattr(tqa.Path, "home", lambda: fake_home)
    install_dir = fake_home / ".local" / "bin"
    install_dir.mkdir(parents=True)
    (install_dir / "claude.exe").write_text("fake binary", encoding="utf-8")

    monkeypatch.setattr(tqa.shutil, "which", lambda name: None)  # PATH never has it
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())

    fix_calls = []
    monkeypatch.setattr(tqa, "_add_to_user_path", lambda d: fix_calls.append(d) or True)

    ok, detail = tqa.install_claude_code_cli()
    # shutil.which is still mocked to always return None, so even with the
    # fallback "attempted," the final re-check still reports not-found here
    # — this test's job is only to confirm the fallback was REACHED and
    # given the right directory, not to fake a fully working shutil.which.
    assert len(fix_calls) == 1
    assert fix_calls[0] == install_dir


def test_install_claude_code_cli_skips_path_fix_when_binary_not_on_disk(tmp_path, monkeypatch):
    # If the installer genuinely failed (no claude.exe on disk at all),
    # the PATH-fix fallback must not fire — there's nothing to point PATH
    # at, and doing so would be misleading busywork.
    fake_home = tmp_path
    monkeypatch.setattr(tqa.Path, "home", lambda: fake_home)
    # Deliberately do NOT create .local/bin/claude.exe.

    monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": "failed"})())

    fix_calls = []
    monkeypatch.setattr(tqa, "_add_to_user_path", lambda d: fix_calls.append(d) or True)

    ok, detail = tqa.install_claude_code_cli()
    assert len(fix_calls) == 0
    assert ok is False


# ── run_queue_now (the "Run Due Tasks" / "Run Pending Analysis" direct-run flow) ──

def test_run_queue_now_fails_when_cli_not_installed(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: False)

    def _guard(*a, **kw):
        raise AssertionError("Must not attempt a run when CLI isn't installed!")
    monkeypatch.setattr(tqa, "install_wrapper_script", _guard)
    monkeypatch.setattr(tqa.subprocess, "run", _guard)

    ok, detail = tqa.run_queue_now("x.json", "mcp__ai-prowler__*")
    assert ok is False
    assert "not installed" in detail.lower()


def test_run_queue_now_fails_when_no_mcp_config(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)

    def _guard(*a, **kw):
        raise AssertionError("Must not attempt a run without an MCP config!")
    monkeypatch.setattr(tqa, "install_wrapper_script", _guard)
    monkeypatch.setattr(tqa.subprocess, "run", _guard)

    ok, detail = tqa.run_queue_now("", "mcp__ai-prowler__*")
    assert ok is False
    assert "mcp config" in detail.lower() or "MCP Config" in detail


def test_run_queue_now_success_reuses_wrapper_script(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)

    wrapper_calls = []
    def _fake_install_wrapper(target_dir, mcp_config_path, allowed_tools,
                               notify_on_complete=False, notify_method="sms",
                               use_api_key=False):
        wrapper_calls.append((target_dir, mcp_config_path, allowed_tools,
                               notify_on_complete, notify_method, use_api_key))
        return Path("fake_wrapper.bat")
    monkeypatch.setattr(tqa, "install_wrapper_script", _fake_install_wrapper)
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "3 tasks done", "stderr": ""})())

    ok, detail = tqa.run_queue_now("real.json", "mcp__ai-prowler__*",
                                    use_api_key=True, notify_on_complete=True,
                                    notify_method="whatsapp")
    assert ok is True
    assert "3 tasks done" in detail
    assert len(wrapper_calls) == 1
    _, mcp_path, tools, notify, method, api_key = wrapper_calls[0]
    assert mcp_path == "real.json"
    assert tools == "mcp__ai-prowler__*"
    assert notify is True
    assert method == "whatsapp"
    assert api_key is True

    # Also updates the same "Last:" status the dry-run check uses, so the
    # panel's status line reflects manual runs too, not just dry runs.
    last = tqa.load_last_run()
    assert last["status"] == "success"


def test_run_queue_now_reports_failure_on_nonzero_exit(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)
    monkeypatch.setattr(tqa, "install_wrapper_script", lambda *a, **kw: Path("fake_wrapper.bat"))
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": "boom"})())

    ok, detail = tqa.run_queue_now("real.json", "mcp__ai-prowler__*")
    assert ok is False
    assert "boom" in detail
    last = tqa.load_last_run()
    assert last["status"] == "failure"


def test_run_queue_now_handles_timeout(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)
    monkeypatch.setattr(tqa, "install_wrapper_script", lambda *a, **kw: Path("fake_wrapper.bat"))

    def _fake_run(*a, **kw):
        raise tqa.subprocess.TimeoutExpired(cmd="wrapper.bat", timeout=600)
    monkeypatch.setattr(tqa.subprocess, "run", _fake_run)

    ok, detail = tqa.run_queue_now("real.json", "mcp__ai-prowler__*")
    assert ok is False
    assert "timed out" in detail.lower()


def test_run_queue_now_truncates_long_output(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)
    monkeypatch.setattr(tqa, "install_wrapper_script", lambda *a, **kw: Path("fake_wrapper.bat"))
    huge_output = "x" * 50000
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": huge_output, "stderr": ""})())

    ok, detail = tqa.run_queue_now("real.json", "mcp__ai-prowler__*")
    assert ok is True
    assert len(detail) <= 4000


def test_run_queue_now_uses_separate_wrapper_dir_from_scheduled_task(_isolated_home, monkeypatch):
    # Confirms manual runs never share a wrapper file with the Scheduled
    # Task's own — writing to the same path mid-schedule-run would be a
    # real race condition.
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)
    dirs_used = []
    def _fake_install_wrapper(target_dir, *a, **kw):
        dirs_used.append(target_dir)
        return Path("fake_wrapper.bat")
    monkeypatch.setattr(tqa, "install_wrapper_script", _fake_install_wrapper)
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())

    tqa.run_queue_now("real.json", "mcp__ai-prowler__*")
    assert "manual_run" in str(dirs_used[0])
    assert str(dirs_used[0]) != str(tqa.AI_PROWLER_HOME)


# ── build_single_prompt_wrapper_content / run_single_prompt_now ────────────
# v8.1.6: backs the "▶ NOW" button on each Common Business AI Analysis item
# — runs ONE ad-hoc prompt immediately, without touching pending_tasks.json
# or the complete_analysis_task() bookkeeping the queue-processing wrapper
# uses. Mirrors build_wrapper_script_content()/run_queue_now()'s tests.

def test_build_single_prompt_wrapper_embeds_the_prompt():
    content = tqa.build_single_prompt_wrapper_content(
        "Analyze my business.", "x.json", "mcp__ai-prowler__*")
    assert 'claude -p "Analyze my business."' in content


def test_build_single_prompt_wrapper_escapes_double_quotes():
    # A prompt containing a literal double quote must not break the
    # generated batch string.
    content = tqa.build_single_prompt_wrapper_content(
        'Say "hello" to the customer.', "x.json", "mcp__ai-prowler__*")
    assert '""hello""' in content


def test_build_single_prompt_wrapper_never_touches_pending_tasks_json():
    content = tqa.build_single_prompt_wrapper_content(
        "Analyze my business.", "x.json", "mcp__ai-prowler__*")
    # Functional check: never calls the queue-processing tools — an
    # explanatory REM comment mentioning pending_tasks.json by name is
    # fine (and present, deliberately, to explain why); what matters is
    # that the actual claude -p invocation never references the queue
    # tools that would make this behave like the scheduled wrapper.
    assert "get_pending_analysis_tasks" not in content
    assert "complete_analysis_task" not in content


def test_build_single_prompt_wrapper_oauth_block_by_default():
    content = tqa.build_single_prompt_wrapper_content(
        "Analyze my business.", "x.json", "mcp__ai-prowler__*")
    assert "CLAUDE_CODE_OAUTH_TOKEN" in content
    assert "set /p CLAUDE_CODE_OAUTH_TOKEN=" in content
    assert str(tqa.OAUTH_TOKEN_PLAIN_PATH) in content


def test_build_single_prompt_wrapper_api_key_block_when_enabled():
    content = tqa.build_single_prompt_wrapper_content(
        "Analyze my business.", "x.json", "mcp__ai-prowler__*", use_api_key=True)
    assert "ANTHROPIC_API_KEY" in content
    assert "set /p ANTHROPIC_API_KEY=" in content


def test_run_single_prompt_now_fails_when_cli_not_installed(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: False)

    def _guard(*a, **kw):
        raise AssertionError("Must not attempt a run when CLI isn't installed!")
    monkeypatch.setattr(tqa.subprocess, "run", _guard)

    ok, detail = tqa.run_single_prompt_now("Analyze my business.", "x.json", "mcp__ai-prowler__*")
    assert ok is False
    assert "not installed" in detail.lower()


def test_run_single_prompt_now_fails_without_mcp_config(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)

    def _guard(*a, **kw):
        raise AssertionError("Must not attempt a run without an MCP config!")
    monkeypatch.setattr(tqa.subprocess, "run", _guard)

    ok, detail = tqa.run_single_prompt_now("Analyze my business.", "", "mcp__ai-prowler__*")
    assert ok is False
    assert "mcp config" in detail.lower()


def test_run_single_prompt_now_success(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "Found 3 insights.", "stderr": ""})())

    ok, detail = tqa.run_single_prompt_now("Analyze my business.", "real.json", "mcp__ai-prowler__*")
    assert ok is True
    assert "Found 3 insights." in detail


def test_run_single_prompt_now_reports_failure_on_nonzero_exit(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": "boom"})())

    ok, detail = tqa.run_single_prompt_now("Analyze my business.", "real.json", "mcp__ai-prowler__*")
    assert ok is False
    assert "boom" in detail


def test_run_single_prompt_now_handles_timeout(_isolated_home, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)

    def _fake_run(*a, **kw):
        raise tqa.subprocess.TimeoutExpired(cmd="run_single_now.bat", timeout=600)
    monkeypatch.setattr(tqa.subprocess, "run", _fake_run)

    ok, detail = tqa.run_single_prompt_now("Analyze my business.", "real.json", "mcp__ai-prowler__*")
    assert ok is False
    assert "timed out" in detail.lower()


def test_run_single_prompt_now_uses_own_subfolder_not_queue_wrappers(_isolated_home, monkeypatch):
    # Confirms a NOW run never collides with the Scheduled Task's own
    # wrapper or with a manual "run the whole queue" wrapper — same
    # rationale as run_queue_now()'s own separate-subfolder test.
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)
    written_paths = []
    _orig_write_text = tqa.Path.write_text
    def _spy_write_text(self, *a, **kw):
        written_paths.append(self)
        return _orig_write_text(self, *a, **kw)
    monkeypatch.setattr(tqa.Path, "write_text", _spy_write_text)
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())

    tqa.run_single_prompt_now("Analyze my business.", "real.json", "mcp__ai-prowler__*")
    assert any("single_run" in str(p) for p in written_paths)
    assert not any("manual_run" in str(p) for p in written_paths)
