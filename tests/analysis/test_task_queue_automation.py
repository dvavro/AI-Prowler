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
import re
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import task_queue_automation as tqa

# Captured before the _isolated_home autouse fixture (below) monkeypatches
# grant_batch_logon_right to a safe no-op for every other test in this
# file — TestGrantBatchLogonRight explicitly restores this real reference
# to test the actual function's own logic.
_REAL_GRANT_BATCH_LOGON_RIGHT = tqa.grant_batch_logon_right
_REAL_REGISTER_QUEUE_TASK_ELEVATED = tqa._register_queue_task_elevated


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    """Every test in this module runs against a fake HOME, never the real
    ~/.ai-prowler/. This is the single most important fixture in this file."""
    monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path / ".ai-prowler")
    monkeypatch.setattr(tqa, "BATCH_LOGON_MARKER_PATH",
                         tmp_path / ".ai-prowler" / "batch_logon_granted.marker")
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
    # v8.1.11: CRITICAL SAFETY — install_scheduled_task() now also calls
    # grant_batch_logon_right(), which creates a REAL, temporary, elevated
    # Windows Scheduled Task and attempts to actually modify Windows
    # security policy (SeBatchLogonRight via LsaAddAccountRights) as a
    # side effect. That must NEVER happen automatically just from running
    # the test suite — mocked here by default for every test in this
    # file, same rationale as the fake-HOME isolation above. The function
    # itself gets its own dedicated, properly-isolated tests further down
    # (mocking subprocess.run directly, never actually invoking schtasks
    # or PowerShell), rather than relying on this default ever being
    # overridden to exercise the real path.
    monkeypatch.setattr(tqa, "grant_batch_logon_right",
                         lambda *a, **kw: (True, "mocked — see _isolated_home fixture"))
    # v8.1.11: SAME safety rationale as the grant mock above —
    # _register_queue_task_elevated() also creates a real elevated
    # PowerShell process (via Start-Process -Verb RunAs -Wait) and would
    # genuinely register/modify the real AI-Prowler-QueueRunner Scheduled
    # Task on whatever machine runs the test suite. Must never happen
    # automatically just from running pytest. Its own dedicated,
    # properly-isolated tests further down restore the real function and
    # mock subprocess.run directly instead.
    monkeypatch.setattr(tqa, "_register_queue_task_elevated",
                         lambda *a, **kw: (True, "mocked — see _isolated_home fixture"))
    # v8.1.16: same rationale — _unregister_queue_task_elevated() (the
    # uninstall_scheduled_task() fallback added for the "toggle off doesn't
    # actually disarm the real Scheduled Task" bug) also launches a real
    # elevated PowerShell process via Start-Process -Verb RunAs -Wait.
    # Dedicated, properly-isolated tests for it live further down and
    # mock subprocess.run directly instead of relying on this default.
    monkeypatch.setattr(tqa, "_unregister_queue_task_elevated",
                         lambda *a, **kw: (True, "mocked — see _isolated_home fixture"))
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
    # v9.0.0: mcp__ai-prowler__* broadened to mcp__* so third-party
    # connectors (Gmail, QuickBooks, etc.) are also permitted.
    content = tqa.build_wrapper_script_content("C:\\fake\\mcp.json", "mcp__ai-prowler__*")
    assert '" -p "' in content  # exe path is quoted; -p flag is always present
    assert "--mcp-config" in content
    assert "C:\\fake\\mcp.json" in content
    assert "--allowedTools" in content
    assert "mcp__*" in content          # broadened wildcard
    assert "mcp__ai-prowler__*" not in content  # narrow form replaced


def test_wrapper_script_scopes_tools_not_wildcard_bash():
    # Regression guard for the permission-scoping requirement in the spec
    # (Section 5.1) — the generated script must never grant unscoped Bash.
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    assert '"Bash"' not in content
    assert "--dangerously-skip-permissions" not in content


# ── v8.1.10 fix: cd into AI_PROWLER_HOME, not %USERPROFILE% ────────────────
# Regression coverage for the real bug David hit: a genuinely-enabled,
# genuinely-existing Windows Scheduled Task fired at its scheduled time,
# exited 0 ("successful" per Task Scheduler), and did NOTHING — because
# `claude -p "/ai-prowler-run-queue"` was invoked from %USERPROFILE%, which
# has no .claude/skills of its own, so Claude Code resolved the slash
# command as "Unknown command" in ~100ms, 0 turns, $0 cost. The only trace
# was the raw last_headless_run.json transcript; the Task Scheduler status,
# the GUI's "Last: ..." line, and the audit log all looked fine or silent.
#
# v8.1.14 superseding fix: the ORIGINAL v8.1.10 fix cd'd into an
# install_dir PARAMETER (the AI-Prowler code directory, e.g.
# "C:\Program Files\AI-Prowler") that every caller had to compute and pass
# through. That directly caused two further real bugs found later the same
# debugging session: run_queue_now() silently never accepted/forwarded the
# parameter at all (silent %USERPROFILE% fallback), and
# build_single_prompt_wrapper_content() (the "▶ NOW" button) hadn't been
# updated to accept it either — both confirmed live on 2026-07-28. Separately,
# a Program-Files-class install_dir requires admin elevation to write to,
# which broke a LATER fix entirely: the audit-log hook's self-heal
# (_ensure_hook_uses_absolute_python()) runs as a normal non-elevated
# process and could never actually write there. The parameter is removed
# entirely now — build_wrapper_script_content() always cd's into
# AI_PROWLER_HOME, which is non-elevated/writable and needs no caller to
# remember anything. These tests replace the old parameter-forwarding
# tests with coverage for the new, simpler, bug-class-eliminating design.

def test_local_mcp_config_never_uses_pythonw(_isolated_home, monkeypatch):
    """pythonw.exe discards stdout/stderr — using it as the stdio MCP server
    command causes claude -p to hang indefinitely since the MCP server
    produces no pipe output. Confirmed live (2026-07-29): every ▶ NOW run
    with pythonw.exe in the stdio config hung for 10+ minutes.
    _get_python_exe() must always return python.exe, never pythonw.exe,
    regardless of what sys.executable reports (which is pythonw.exe when
    the GUI launches via RAG_RUN.bat)."""
    monkeypatch.setattr(
        tqa.sys, "executable",
        r"C:\Users\david\AppData\Local\Programs\Python\Python311\pythonw.exe")
    exe = tqa._get_python_exe()
    assert exe.lower().endswith("python.exe")


# ── v9.0.0 regression: _SELF_GATE_PYTHON must never be pythonw.exe ─────────
#
# Bug: the GUI launches via pythonw.exe (RAG_RUN.bat), so sys.executable at
# module import time is pythonw.exe. _SELF_GATE_PYTHON was set directly from
# sys.executable, so the generated bat embedded pythonw.exe in the
# active-days gate subshell:
#   for /f "delims=" %%R in ('pythonw.exe -c "..."') do ...
# pythonw.exe discards stdout, so the subshell produces no output,
# AIP_WINDOW_CHECK stays empty, the condition fails, and the bat exits 0
# before ever reaching the claude -p line. last_headless_run.json was 0
# bytes as a result — confirmed live 2026-08-09.
#
# _get_python_exe() correctly substitutes python.exe but it is only called
# at generate time for the MCP config command — _SELF_GATE_PYTHON is a
# module-level constant set at import time, so it needs its own inline fix.
# ─────────────────────────────────────────────────────────────────────────────

def test_self_gate_python_never_pythonw(monkeypatch):
    """_SELF_GATE_PYTHON must be python.exe even when sys.executable is
    pythonw.exe at module import time (GUI launched via RAG_RUN.bat)."""
    monkeypatch.setattr(
        tqa.sys, "executable",
        r"C:\Users\david\AppData\Local\Programs\Python\Python311\pythonw.exe")
    # Re-evaluate the expression the same way the module does at import time
    gate = (tqa.sys.executable or "python").replace(
        "pythonw.exe", "python.exe").replace("pythonw", "python")
    assert "pythonw" not in gate.lower(), (
        f"_SELF_GATE_PYTHON would be {gate!r} — pythonw.exe in the "
        f"active-days gate subshell discards stdout, causing the bat to "
        f"exit 0 before reaching claude -p")
    assert gate.lower().endswith("python.exe")


def test_wrapper_bat_active_days_gate_never_uses_pythonw(monkeypatch):
    """The generated bat's active-days gate must use python.exe not pythonw.
    Regression guard: if pythonw.exe appears in the gate's for /f subshell,
    AIP_WINDOW_CHECK is always empty (pythonw discards stdout), the condition
    always fails, and every scheduled run silently exits without doing anything.
    Confirmed live 2026-08-09: last_headless_run.json was 0 bytes."""
    monkeypatch.setattr(
        tqa.sys, "executable",
        r"C:\Users\david\AppData\Local\Programs\Python\Python311\pythonw.exe")
    content = tqa.build_wrapper_script_content("x.json", "mcp__*")
    # Find the active-days gate line
    gate_lines = [l for l in content.splitlines()
                  if 'AIP_WINDOW_CHECK' in l and 'for /f' in l]
    assert gate_lines, "Active-days gate line not found in bat content"
    for line in gate_lines:
        assert "pythonw" not in line.lower(), (
            f"pythonw.exe in active-days gate will break scheduled runs:\n{line}")


def test_local_mcp_config_command_is_never_pythonw(_isolated_home, monkeypatch,
                                                     tmp_path):
    monkeypatch.setattr(
        tqa.sys, "executable",
        r"C:\Users\david\AppData\Local\Programs\Python\Python311\pythonw.exe")
    monkeypatch.setattr(tqa, "LOCAL_MCP_SCRIPT_PATH",
                        tmp_path / "ai_prowler_mcp.py")
    (tmp_path / "ai_prowler_mcp.py").write_text("")
    ok, path = tqa._generate_local_mcp_config()
    assert ok
    import json
    config = json.loads(Path(path).read_text())
    cmd = config["mcpServers"]["ai-prowler"]["command"]
    assert "pythonw" not in cmd.lower()
    assert cmd.lower().endswith("python.exe")


def test_wrapper_script_always_cds_into_ai_prowler_home(_isolated_home):
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    assert f'cd /d "{tqa.AI_PROWLER_HOME}"' in content
    assert 'cd /d "%USERPROFILE%"' not in content


def test_wrapper_script_cd_target_is_not_configurable(_isolated_home):
    # There is deliberately no install_dir (or similar) parameter anymore —
    # calling with one should fail loudly (TypeError) rather than silently
    # do nothing, which is exactly what happened with run_queue_now() before
    # this fix (it accepted no such parameter, so passing one there would
    # also have raised — the REAL bug was that build_wrapper_script_content()
    # DID have the parameter and run_queue_now() simply never passed it).
    with pytest.raises(TypeError):
        tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", install_dir=r"C:\Program Files\AI-Prowler")


def test_wrapper_cd_target_matches_where_claude_folder_actually_deploys(_isolated_home):
    # Direct regression guard for the actual bug found live: the wrapper's
    # cd target and .claude's real deploy location silently drifted apart
    # (cd'd into the code install dir, while .claude/settings.json's
    # self-heal could only ever write under AI_PROWLER_HOME). This test
    # fails immediately if that drift is ever reintroduced, by asserting
    # both sides against the exact same module-level constant rather than
    # a hardcoded path string on either side.
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    cd_line = next(l for l in content.splitlines() if l.strip().startswith("cd /d"))
    expected_claude_dir = tqa.AI_PROWLER_HOME / ".claude"
    assert str(tqa.AI_PROWLER_HOME) in cd_line
    assert expected_claude_dir.parent == tqa.AI_PROWLER_HOME


def test_single_prompt_wrapper_also_cds_into_ai_prowler_home(_isolated_home):
    # The "▶ NOW" button's wrapper (a separate function, see its own
    # docstring for why) must use the exact same cd target as the
    # scheduled wrapper above — this is exactly the kind of drift that
    # went unnoticed before (build_wrapper_script_content() got the
    # install_dir fix; this function didn't, for one full debugging
    # session).
    content = tqa.build_single_prompt_wrapper_content(
        "do the thing", "x.json", "mcp__ai-prowler__*")
    assert f'cd /d "{tqa.AI_PROWLER_HOME}"' in content
    assert 'cd /d "%USERPROFILE%"' not in content


# ── v8.1.15 fix: arbitrary (e.g. custom-task) prompts must survive .bat
# embedding ───────────────────────────────────────────────────────────────
# Real-world bug: a custom task's "▶ NOW" run failed with cmd.exe reporting
# `'Output:' is not recognized as an internal or external command`.
# custom_tasks_manager.build_task_prompt() joins its output with real
# newlines (correct for its own purpose — multi-line GUI display), and one
# of those lines starts with "Output: ...". Once embedded verbatim into a
# .bat file's single-line `claude -p "..."` invocation, that newline split
# the command in cmd.exe's line-by-line .bat parser — "Output: ..." became
# its own (invalid) command. Unlike QUEUE_RUNNER_PROMPT (a static constant,
# already covered by test_wrapper_prompt_has_no_batch_unsafe_characters
# above), a prompt reaching build_single_prompt_wrapper_content() can come
# from ANY task — built-in or custom — and isn't guaranteed batch-safe by
# construction, so it needs runtime sanitizing.

def test_sanitize_prompt_for_batch_strips_all_newline_styles():
    assert '\n' not in tqa._sanitize_prompt_for_batch("line one\nline two")
    assert '\r' not in tqa._sanitize_prompt_for_batch("line one\r\nline two")
    assert tqa._sanitize_prompt_for_batch("a\nb") == "a b"


def test_sanitize_prompt_for_batch_escapes_percent():
    # A bare % still triggers cmd.exe environment-variable expansion even
    # inside a quoted argument — % must become %% (batch's own escape).
    assert tqa._sanitize_prompt_for_batch("revenue up 15%") == "revenue up 15%%"


# ── v8.1.16 fix: non-ASCII characters corrupted by legacy OEM codepage ─────
# Real-world bug found while live-testing the v8.1.15 fix above: even after
# the newline-splitting bug was fixed, a real "Check NSB" run still behaved
# strangely. Root cause: custom_tasks_manager.py's own generated text
# contains a real em-dash ("email the full analysis via send_email() —
# leave 'to' blank..."), and cmd.exe reads .bat files under the legacy OEM
# codepage (e.g. cp437) by default, silently corrupting every non-ASCII
# byte in the file — confirmed via raw byte inspection: the real em-dash
# (UTF-8 bytes E2 80 94) decodes as literal garbage ("Î"Ã‡Ã¶") under cp437,
# sitting INSIDE the quoted claude -p "..." argument itself, not just in a
# REM comment.
#
# First fix attempt: write the .bat with a UTF-8 BOM (encoding="utf-8-sig").
# Reverted after live testing: subprocess.run(..., shell=True) — the exact
# invocation path this module uses — does NOT auto-detect/strip a BOM the
# way Windows 10 1903+ does for a double-clicked or interactive .bat file.
# The raw BOM bytes showed up as literal garbage ("ï»¿") prepended to the
# very first line, corrupting `@echo off` itself and breaking the script
# outright — worse than the original bug.
#
# Actual fix: `chcp 65001 >nul` as the second line of the generated script
# (right after `@echo off`), switching THIS cmd.exe process to the UTF-8
# codepage explicitly, with no dependency on how the file happens to be
# invoked. Combined with _sanitize_prompt_for_batch()'s ASCII normalization
# as defense-in-depth for the handful of characters it covers.

def test_sanitize_prompt_for_batch_normalizes_em_and_en_dash():
    assert '\u2014' not in tqa._sanitize_prompt_for_batch("a \u2014 b")
    assert '\u2013' not in tqa._sanitize_prompt_for_batch("a \u2013 b")


def test_sanitize_prompt_for_batch_normalizes_curly_quotes_and_ellipsis():
    result = tqa._sanitize_prompt_for_batch(
        "\u201cHello\u201d \u2018world\u2019 \u2026")
    for smart_char in ('\u201c', '\u201d', '\u2018', '\u2019', '\u2026'):
        assert smart_char not in result
    assert '"Hello" \'world\' ...' == result


def test_wrapper_script_sets_utf8_codepage():
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    lines = content.splitlines()
    assert lines[0] == "@echo off"
    assert lines[1].strip() == "chcp 65001 >nul"


def test_wrapper_script_has_no_utf8_bom():
    # The BOM approach was tried and reverted -- confirm it stays reverted.
    # A BOM would show up as the first three bytes of the encoded content;
    # since this returns a plain str (not yet written to disk), check for
    # the BOM character itself, which write_text(encoding="utf-8-sig")
    # would have prepended were it still in use anywhere upstream.
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    assert not content.startswith('\ufeff')


def test_single_prompt_wrapper_sets_utf8_codepage():
    content = tqa.build_single_prompt_wrapper_content(
        "do the thing", "x.json", "mcp__ai-prowler__*")
    lines = content.splitlines()
    assert lines[0] == "@echo off"
    assert lines[1].strip() == "chcp 65001 >nul"


def test_install_wrapper_script_writes_bat_without_bom(tmp_path, _isolated_home):
    target = tmp_path / "wrapper_dir"
    path = tqa.install_wrapper_script(target, "x.json", "mcp__ai-prowler__*")
    raw = path.read_bytes()
    assert not raw.startswith(b'\xef\xbb\xbf'), (
        "Wrapper .bat has a UTF-8 BOM -- this was tried and reverted "
        "because subprocess.run(shell=True) doesn't auto-strip it, "
        "corrupting the file's first line instead. Should be plain utf-8."
    )
    assert raw.startswith(b'@echo off')


def test_single_prompt_wrapper_end_to_end_em_dash_normalized(tmp_path, _isolated_home):
    # Uses the real custom task shape: the prompt line contains no raw
    # smart-dash character (normalized by the sanitizer), and the script
    # sets codepage 65001 as defense-in-depth for anything the sanitizer
    # doesn't cover.
    import custom_tasks_manager as ctm
    task = {
        "task_id": "test-task", "label": "Check NSB",
        "prompt": "Check something.",
        "output_learnings": False, "output_report": False,
        "output_email": True, "scope_dirs": [],
    }
    real_prompt = ctm.build_task_prompt(task)
    assert '\u2014' in real_prompt  # confirms the real function still emits an em-dash

    content = tqa.build_single_prompt_wrapper_content(
        real_prompt, "x.json", "mcp__ai-prowler__*")
    prompt_line = next(l for l in content.splitlines() if l.strip().startswith('claude -p "'))
    assert '\u2014' not in prompt_line
    lines = content.splitlines()
    assert lines[1].strip() == "chcp 65001 >nul"


def test_single_prompt_wrapper_reproduces_and_fixes_the_live_bug():
    # Reproduces the EXACT shape of the real failure: a multi-line prompt
    # whose second line is build_task_prompt()'s own "Output: ..." action
    # summary — the literal text that showed up as cmd.exe's failed command.
    multiline_prompt = (
        "Check something.\n\n"
        "Output: (1) Record key insights as learnings. "
        "(2) Email the full analysis via send_email()."
    )
    content = tqa.build_single_prompt_wrapper_content(
        multiline_prompt, "x.json", "mcp__ai-prowler__*")
    prompt_line = next(l for l in content.splitlines() if l.strip().startswith('claude -p "'))
    # The whole prompt, "Output:" fragment included, must be on this ONE
    # line — not split across separate .bat lines cmd.exe would try to run
    # as independent commands.
    assert "Output:" in prompt_line
    assert not any(l.strip() == "Output:" or l.strip().startswith("Output: (1)")
                    for l in content.splitlines() if l is not prompt_line)


def test_single_prompt_wrapper_sanitizes_real_custom_task_prompt_shape():
    # End-to-end regression using the REAL prompt-building function, not a
    # hand-rolled approximation — ties this test directly to
    # custom_tasks_manager.build_task_prompt()'s actual current output
    # shape, so a future change there that reintroduces batch-unsafe
    # content gets caught here too.
    import custom_tasks_manager as ctm
    task = {
        "task_id": "test-task", "label": "Check NSB",
        "prompt": "Check restaurant deals in New Smyrna Beach.",
        "output_learnings": True, "output_report": False,
        "output_email": True, "scope_dirs": [],
    }
    real_prompt = ctm.build_task_prompt(task)
    assert '\n' in real_prompt  # confirms this test is exercising the real shape

    content = tqa.build_single_prompt_wrapper_content(
        real_prompt, "x.json", "mcp__ai-prowler__*")
    prompt_line = next(l for l in content.splitlines() if l.strip().startswith('claude -p "'))
    assert "Output:" in prompt_line
    # No OTHER line in the generated .bat should be a stray fragment of the
    # prompt (e.g. a bare "Output: ..." line outside the quoted argument).
    other_lines = [l for l in content.splitlines() if l is not prompt_line]
    assert not any("record key insights" in l or l.strip().startswith("Output:")
                    for l in other_lines)


def test_install_wrapper_script_writes_ai_prowler_home_cd(tmp_path, _isolated_home):
    target = tmp_path / "wrapper_dir"
    path = tqa.install_wrapper_script(target, "x.json", "mcp__ai-prowler__*")
    content = path.read_text(encoding="utf-8")
    assert f'cd /d "{tqa.AI_PROWLER_HOME}"' in content


def test_run_queue_now_no_longer_has_install_dir_parameter_to_forget(_isolated_home):
    # Direct regression guard for the specific bug found live: run_queue_now()
    # had an install_dir parameter that install_wrapper_script() supported,
    # but NEVER accepted or forwarded it itself -- silently falling back to
    # the broken %USERPROFILE% cd on every "Run Due Tasks Now" click. With
    # the parameter removed from the whole call chain, there's no longer a
    # signature for a caller to mismatch against -- assert the parameter is
    # simply gone, so a well-intentioned future re-add of a *forgotten*
    # install_dir plumbing bug would show up here as a signature change,
    # not a silent runtime behavior gap.
    import inspect
    sig = inspect.signature(tqa.run_queue_now)
    assert "install_dir" not in sig.parameters

# ── v8.1.11 fix: embedded prompt, not a slash command ───────────────────────
# Regression coverage for a second, deeper bug found AFTER the v8.1.10
# cd-directory fix: two real scheduled runs on 2026-07-25 both fired
# correctly, in the correct directory, and BOTH still got
# "Unknown command: /ai-prowler-run-queue" — because Skills and slash
# commands are different Claude Code mechanisms, and this project never had
# a .claude/commands/ directory. The fix removes the slash-command
# invocation entirely in favor of embedding the actual instructions as the
# prompt text, so headless runs have no dependency on Claude Code's
# project-file discovery working at all.

def test_wrapper_prompt_does_not_use_slash_command():
    # Note: the file's own explanatory comments legitimately still mention
    # "/ai-prowler-run-queue" as historical context for why the cd-directory
    # fix was needed — check the actual claude -p invocation line itself,
    # not the whole file, so this test isn't fooled by that documentation.
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    prompt_line = next(l for l in content.splitlines() if '" -p "' in l)
    assert "/ai-prowler-run-queue" not in prompt_line


def test_wrapper_prompt_embeds_full_sequence_instructions():
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    # v9.0.0: sync_due_tasks_to_queue removed — queue is user-controlled only.
    # Confirm it is NOT present, and that the correct step 1 is.
    assert "sync_due_tasks_to_queue" not in content
    assert "get_pending_analysis_tasks" in content
    assert "complete_analysis_task" in content
    assert "save_analysis_report" in content
    assert "record_learning" in content
    assert "do not retry silently in a loop" in content


def test_wrapper_prompt_has_no_batch_unsafe_characters():
    # The embedded prompt is passed as a quoted argument on a single .bat
    # line — it must not contain characters cmd.exe treats specially
    # (unescaped double quotes, or batch metacharacters like %, ^, &, |)
    # which could break the command line or truncate the prompt silently.
    content = tqa.QUEUE_RUNNER_PROMPT
    for bad_char in ['"', '%', '^', '&', '|', '<', '>']:
        assert bad_char not in content, (
            f"QUEUE_RUNNER_PROMPT contains batch-unsafe character {bad_char!r}"
        )


def test_wrapper_prompt_plus_notify_clause_still_batch_safe():
    content = tqa.build_wrapper_script_content(
        "x.json", "mcp__ai-prowler__*", notify_on_complete=True,
        notify_method="sms")
    assert "send_sms" in content
    # The notify clause is appended to the same prompt string — confirm
    # the combined result still contains no stray unescaped quotes that
    # would prematurely close the -p "..." argument.
    prompt_line = next(l for l in content.splitlines() if '" -p "' in l)
    # The line is: "<exe>" -p "<prompt>" — exactly 4 double-quotes total
    # (opening/closing the exe path + opening/closing the -p argument).
    # Any stray unescaped quote inside the prompt itself would push this above 4.
    assert prompt_line.count('"') == 4


def test_wrapper_script_no_notify_clause_by_default():
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    assert "send_sms" not in content
    assert "send_whatsapp" not in content


# ── v8.1.11: independently configurable check frequency + active window ────
# The checker's own frequency (daily vs. interval) and active window
# (days-of-week, time-of-day) are DELIBERATELY decoupled from any
# individual custom task's own schedule — this covers that layer:
# install_scheduled_task()'s trigger construction, and
# build_wrapper_script_content()'s embedded self-gate logic.

class TestCheckModeDefaultConfig:

    def test_default_check_mode_is_daily(self):
        assert tqa.DEFAULT_CONFIG["check_mode"] == "daily"

    def test_default_active_days_is_all_seven(self):
        assert set(tqa.DEFAULT_CONFIG["active_days"]) == tqa.VALID_DAY_CODES
        assert len(tqa.DEFAULT_CONFIG["active_days"]) == 7

    def test_default_active_window_is_unrestricted(self):
        assert tqa.DEFAULT_CONFIG["active_start_time"] == "00:00"
        assert tqa.DEFAULT_CONFIG["active_end_time"] == "23:59"

    def test_existing_saved_config_without_new_keys_gets_defaults(self, tmp_path, monkeypatch):
        # Simulates a config saved BEFORE v8.1.11 existed — must merge in
        # the new keys with defaults, reproducing prior behavior exactly,
        # not crash or silently omit them.
        monkeypatch.setattr(tqa, "CONFIG_PATH", tmp_path / "old_config.json")
        tqa.CONFIG_PATH.write_text(json.dumps({
            "enabled": True, "schedule_time": "07:30",
        }), encoding="utf-8")
        cfg = tqa.load_config()
        assert cfg["schedule_time"] == "07:30"  # existing value preserved
        assert cfg["check_mode"] == "daily"       # new key, default applied
        assert set(cfg["active_days"]) == tqa.VALID_DAY_CODES


class TestInstallScheduledTaskTriggerMode:
    """v8.1.11: install_scheduled_task() no longer calls schtasks /create
    directly — it delegates to _register_queue_task_elevated(), which
    generates a PowerShell script (_build_register_queue_task_ps1) and
    runs it elevated. Tests the PS1-generation logic directly (pure
    string content, no subprocess involved) rather than trying to
    intercept schtasks args that no longer exist."""

    def test_daily_mode_uses_new_scheduledtasktrigger_daily(self):
        script = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:30", "23:00", "daily", 1, "david", True, "result.txt")
        assert "New-ScheduledTaskTrigger -Daily -At '07:30'" in script
        assert "RepetitionInterval" not in script

    def test_interval_mode_uses_multiple_daily_triggers_not_repetition(self):
        """v9.0.1 REDESIGN: interval mode no longer uses a single hour-
        repetition trigger — it registers N separate -Daily -At triggers
        (one per compute_daily_run_times() slot), combined into a
        PowerShell array. This is what actually fixed the anchor-drift bug
        class (a Daily trigger's time-of-day can't drift the way a
        RepetitionInterval trigger's StartBoundary could)."""
        script = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:00", "23:00", "interval", 3, "david", True, "result.txt")
        assert "RepetitionInterval" not in script
        assert "RepetitionDuration" not in script
        # 3 times/day across 07:00-23:00 -> 07:00, 15:00, 23:00
        assert "New-ScheduledTaskTrigger -Daily -At '07:00'" in script
        assert "New-ScheduledTaskTrigger -Daily -At '15:00'" in script
        assert "New-ScheduledTaskTrigger -Daily -At '23:00'" in script
        assert "-Trigger $trigger" in script
        assert "@($t0, $t1, $t2)" in script

    def test_interval_mode_clamps_zero_or_negative_times_per_day_to_one(self):
        script = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:30", "23:00", "interval", 0, "david", True, "result.txt")
        # times_per_day <= 1 -> compute_daily_run_times just returns [start]
        assert "New-ScheduledTaskTrigger -Daily -At '07:30'" in script
        assert "@($t0)" in script


    # ── v9.0.1: interval-mode anchor time (superseded by the v9.0.1 REDESIGN
    # right above — kept as historical record) ──────────────────────────────
    # Found live: David configured Scheduled time=07:00, Check queue=8
    # times/day (a 3-hour interval) and the panel showed "next: 8/7/2026
    # 1:27:54 AM" -- nowhere near a clean multiple of 3 hours from 07:00.
    # Root cause: the interval trigger anchored at (Get-Date) -- the exact
    # instant Apply was clicked, full seconds precision included -- and
    # completely ignored the schedule_time field. Windows Task Scheduler
    # computes every future occurrence as StartBoundary + N * Repetition
    # Interval, so that arbitrary seconds offset propagated forward forever.
    #
    # First fix attempt: keep the single hour-repetition trigger, but anchor
    # -At at today's schedule_time (seconds zeroed) instead of (Get-Date).
    # That fixed the drift but was still fundamentally a single anchor +
    # fixed-hour-interval design — it couldn't express "N times evenly
    # spread across a Start/End range" (the actual feature request that
    # triggered the REDESIGN above), and non-round divisions of 24 still
    # distorted the true interval. SUPERSEDED, not just fixed: interval mode
    # now has no single "anchor" concept at all — every check time is its
    # own independent Daily trigger, so there's nothing left that CAN drift.
    # The three tests that used to assert on a single -Once -At full-datetime
    # anchor were deleted in v9.0.0. The v9.0.1 redesign removed the single
    # anchor entirely — each check time is now a bare HH:MM -Daily -At trigger.
    # test_interval_mode_uses_multiple_daily_triggers_not_repetition (above)
    # covers everything that still applies.

    def test_interval_mode_schedule_is_deterministic_across_repeated_calls(self):
        """Successor to the old 'anchor stable across repeated calls' test.
        Two registrations with identical inputs must produce byte-identical
        trigger sets — trivially true now (compute_daily_run_times() is a
        pure function of start/end/N, no wall-clock time involved at all),
        but still worth asserting explicitly since it's the property that
        actually matters: the schedule never drifts no matter when or how
        many times Apply gets clicked."""
        script_a = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:00", "23:00", "interval", 3, "david", True, "result.txt")
        script_b = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:00", "23:00", "interval", 3, "david", True, "result.txt")
        assert script_a == script_b, (
            "Identical inputs produced different registration scripts — "
            "the schedule is not deterministic"
        )

    def test_daily_mode_at_unchanged_by_interval_anchor_fix(self):
        """Daily mode's -At must remain the plain HH:MM string — this fix
        only touches the interval branch."""
        script = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:30", "23:00", "daily", 1, "david", True, "result.txt")
        assert "New-ScheduledTaskTrigger -Daily -At '07:30'" in script


# ── v8.1.11: run whether logged on or not, even during a full logoff ──
# Real-world bug report: the checker worked fine while actively logged in,
# but never fired while the screensaver was active / screen locked, even
# with sleep/hibernate already disabled. Root cause #1 (v8.1.11): without
# an explicit /RU, schtasks.exe defaults to "Run only when user is logged
# on" (INTERACTIVE_TOKEN). Root cause #2, found via live testing after #1
# alone still didn't fix it (v8.1.11): schtasks.exe's /RU <user> (without
# /RP) does NOT actually produce S4U logon type through its simple CLI,
# REGARDLESS of holding SeBatchLogonRight — confirmed via direct
# side-by-side testing. PowerShell's ScheduledTasks module
# (New-ScheduledTaskPrincipal -LogonType S4U) DOES produce a genuine S4U
# task — confirmed live: "Logon Mode: Interactive/Background" instead of
# "Interactive only". install_scheduled_task() now delegates entirely to
# the PowerShell-based path.

class TestRegisterQueueTaskPs1UserPrincipal:

    def test_userid_matches_run_as_user(self):
        script = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:30", "23:00", "daily", 1, "david", True, "result.txt")
        assert "-UserId 'david'" in script

    def test_logontype_is_s4u_not_password_based(self):
        # Confirming S4U specifically -- never a stored password. Storing
        # a plaintext Windows login password would be a real security
        # regression and isn't what this mechanism needs.
        script = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:30", "23:00", "daily", 1, "david", True, "result.txt")
        assert "-LogonType S4U" in script
        assert "Password" not in script

    def test_different_username_reflected_in_principal(self):
        script = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:30", "23:00", "daily", 1, "someone_else", True, "result.txt")
        assert "-UserId 'someone_else'" in script

    def test_s4u_principal_present_in_both_daily_and_interval_modes(self):
        daily_script = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:30", "23:00", "daily", 1, "david", True, "result.txt")
        interval_script = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:30", "23:00", "interval", 2, "david", True, "result.txt")
        assert "-LogonType S4U" in daily_script
        assert "-LogonType S4U" in interval_script

    def test_disabled_state_adds_disable_scheduledtask_call(self):
        enabled_script = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:30", "23:00", "daily", 1, "david", True, "result.txt")
        disabled_script = tqa._build_register_queue_task_ps1(
            "fake.bat", "07:30", "23:00", "daily", 1, "david", False, "result.txt")
        assert "Disable-ScheduledTask" not in enabled_script
        assert "Disable-ScheduledTask" in disabled_script

    def test_single_quotes_in_wrapper_path_must_be_pre_escaped(self):
        # Documents the calling contract: _register_queue_task_elevated()
        # is responsible for doubling single quotes before calling this
        # builder -- this function does not do it itself.
        script = tqa._build_register_queue_task_ps1(
            "fake''bat", "07:30", "23:00", "daily", 1, "david", True, "result.txt")
        assert "fake''bat" in script


# ── v8.1.11: real OS-level armed-schedule display info ──────────────────────
# David asked for the Autonomous AI Task Queue panel to show what's
# ACTUALLY armed in Windows Task Scheduler, not just echo back the config
# file / text field values -- so Toggle Off can be visually confirmed as
# genuinely having disarmed the real task, and Apply's effect is visible.

class TestGetScheduledTaskDisplayInfo:

    def _mock_query(self, monkeypatch, stdout, returncode=0):
        def _fake_run(args, **kw):
            class _R:
                pass
            r = _R()
            r.returncode = returncode
            r.stdout = stdout
            r.stderr = ""
            return r
        monkeypatch.setattr(tqa.subprocess, "run", _fake_run)

    def test_task_does_not_exist(self, monkeypatch):
        self._mock_query(monkeypatch, "", returncode=1)
        info = tqa.get_scheduled_task_display_info()
        assert info["exists"] is False
        assert info["enabled"] is None
        assert info["display"] == "🔴 Not armed"

    def test_enabled_daily_task_shows_armed_with_time(self, monkeypatch):
        """v9.0.1: cadence now comes from OUR saved config (schedule_time,
        check_times_per_day), not schtasks's own Start Time field —
        next_run_time in `display` is now computed via compute_next_checker_run()
        (real wall-clock), NOT read straight from schtasks, so we must
        monkeypatch compute_next_checker_run to get a stable date in the output."""
        import datetime as _dt
        _fixed = _dt.datetime(2026, 7, 27, 6, 0, 0)
        monkeypatch.setattr(tqa, "compute_next_checker_run", lambda *a, **kw: _fixed)
        tqa.save_config({
            "enabled": True, "schedule_time": "06:00",
            "check_mode": "daily", "check_times_per_day": 1,
        })
        self._mock_query(monkeypatch,
            "Scheduled Task State:    Enabled\r\n"
            "Schedule Type:           Daily\r\n"
            "Start Time:              06:00:00\r\n"
            "Next Run Time:           7/27/2026 6:00:00 AM\r\n")
        info = tqa.get_scheduled_task_display_info()
        assert info["exists"] is True
        assert info["enabled"] is True
        assert "🟢 Armed" in info["display"]
        assert "Daily at 06:00" in info["display"]
        assert "7/27/2026" in info["display"]

    def test_enabled_multi_trigger_task_shows_computed_check_times(self, monkeypatch):
        """v9.0.1: N times/day > 1 now shows the actual computed check
        times (via compute_daily_run_times), not a raw schtasks "Repeat:
        Every" hour-interval string — the OS trigger mechanism changed
        from hour-repetition to N explicit Daily triggers, and schtasks's
        /v /fo list query has no clean way to describe several independent
        triggers, so it's not used for this anymore.
        compute_next_checker_run() is also monkeypatched here because the
        display's "next:" date is computed from real wall-clock time, not
        read from schtasks, so the assertion needs a pinned return value."""
        import datetime as _dt
        _fixed = _dt.datetime(2026, 7, 27, 15, 0, 0)
        monkeypatch.setattr(tqa, "compute_next_checker_run", lambda *a, **kw: _fixed)
        tqa.save_config({
            "enabled": True, "schedule_time": "07:00",
            "schedule_end_time": "23:00", "check_mode": "interval",
            "check_times_per_day": 3,
        })
        self._mock_query(monkeypatch,
            "Scheduled Task State:    Enabled\r\n"
            "Schedule Type:           Multiple Triggers\r\n"
            "Next Run Time:           7/27/2026 3:00:00 PM\r\n")
        info = tqa.get_scheduled_task_display_info()
        assert info["enabled"] is True
        assert "🟢 Armed" in info["display"]
        assert "3x/day" in info["display"]
        assert "07:00" in info["display"]
        assert "23:00" in info["display"]
        assert "7/27/2026" in info["display"]

    def test_disabled_task_shows_not_armed(self, monkeypatch):
        self._mock_query(monkeypatch,
            "Scheduled Task State:    Disabled\r\n"
            "Schedule Type:           Daily\r\n"
            "Start Time:              06:00:00\r\n")
        info = tqa.get_scheduled_task_display_info()
        assert info["exists"] is True
        assert info["enabled"] is False
        assert "🔴 Not armed" in info["display"]
        assert "disabled" in info["display"].lower()

    def test_display_string_never_crashes_on_missing_fields(self, monkeypatch):
        # Minimal/malformed output -- shouldn't raise, even with almost
        # nothing parseable.
        self._mock_query(monkeypatch, "Scheduled Task State:    Enabled\r\n")
        info = tqa.get_scheduled_task_display_info()
        assert isinstance(info["display"], str)
        assert info["display"]  # non-empty

    def test_display_falls_back_gracefully_on_malformed_saved_times(self, monkeypatch):
        """A corrupt/malformed schedule_time or schedule_end_time in the
        saved config must not crash display info -- falls back to a
        still-informative (if less precise) cadence string."""
        tqa.save_config({
            "enabled": True, "schedule_time": "not-a-time",
            "schedule_end_time": "also-not-a-time",
            "check_mode": "interval", "check_times_per_day": 4,
        })
        self._mock_query(monkeypatch,
            "Scheduled Task State:    Enabled\r\n"
            "Next Run Time:           7/27/2026 3:00:00 PM\r\n")
        info = tqa.get_scheduled_task_display_info()
        assert isinstance(info["display"], str)
        assert "🟢 Armed" in info["display"]
        assert "4x/day" in info["display"]


class TestWrapperActiveWindowSelfGate:

    def test_daily_mode_checks_active_days_only(self):
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="daily",
            active_days=["mon", "tue", "wed", "thu", "fri"])
        assert "active-days self-gate" in content
        assert "'mon','tue','wed','thu','fri'" in content.replace(" ", "")
        # Daily mode must NOT embed a time-window comparison — schedule_time
        # (the /st on the OS trigger) already IS the single trigger point.
        assert "active-window self-gate" not in content

    def test_interval_mode_checks_days_and_time_window(self):
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="interval",
            active_days=["sat", "sun"],
            active_start_time="07:00", active_end_time="22:00")
        assert "active-window self-gate" in content
        assert "'sat','sun'" in content.replace(" ", "")
        assert "07:00" in content
        assert "22:00" in content

    def test_default_all_days_all_hours_reproduces_unrestricted_behavior(self):
        # No active_days passed at all — must fall back to DEFAULT_CONFIG's
        # all-7-days list, not crash or default to an empty/restrictive set.
        content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
        for day in tqa.VALID_DAY_CODES:
            assert f"'{day}'" in content

    def test_skip_writes_a_result_message_not_silent(self):
        # A skipped check should still leave SOMETHING readable in
        # last_headless_run.json — "silently doing nothing with zero
        # trace" was the exact class of bug this whole session's earlier
        # fixes (v8.1.10, v8.1.11) were about avoiding.
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="interval")
        assert "Skipped" in content

    def test_exits_before_claude_dash_p_when_outside_window(self):
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="interval")
        skip_idx = content.index("exit /b 0")
        claude_idx = content.index('" -p "')
        assert skip_idx < claude_idx, (
            "the active-window skip-exit must appear BEFORE the claude -p "
            "invocation in the generated script — otherwise a skipped "
            "check wouldn't actually save any cost at all"
        )


class TestWrapperActiveWindowSelfGatePercentEscaping:
    """Regression coverage for the v8.1.12 %a/%H/%M-escaping bug.

    build_wrapper_script_content() embeds a `python -c "..."` one-liner
    inside a `for /f "delims=" %%R in ('...')` construct written into a
    .bat file. A bare %a (or %H, %M) in that embedded command is consumed
    by cmd.exe's OWN batch-variable substitution before python ever runs
    it — cmd.exe treats %a as a reference to an undefined variable, which
    silently resolves to an empty string. strftime('') then always
    returns '', which never matches any entry in the active-days set, so
    the self-gate printed SKIP unconditionally — every single day,
    regardless of the actual weekday, the configured active_days, or the
    configured time window — while the wrapper still exited 0 ("success").
    Same silent-0x0-zero-actual-work shape as the v8.1.10 %USERPROFILE%
    cd bug already documented above, just one layer earlier: inside the
    self-gate meant to run BEFORE that fix's code ever executes.

    TestWrapperActiveWindowSelfGate above never caught this because it
    only asserts on the SOURCE TEXT (day codes, "active-days self-gate",
    etc.) — never actually runs the generated command through cmd.exe,
    which is exactly where the escaping bug lived. Two layers of coverage
    here: a fast, platform-independent string check that the fix is
    present at all, plus real cmd.exe execution tests (Windows-only) that
    would have caught the original bug outright.
    """

    def test_daily_mode_escapes_percent_a(self):
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="daily",
            active_days=["mon", "tue", "wed", "thu", "fri"])
        assert "%%a" in content
        # No bare, unescaped %a anywhere in the embedded python command —
        # every %a must be part of %%a (i.e. preceded by another %).
        assert not re.search(r"(?<!%)%a\b", content), (
            "found an unescaped %a — cmd.exe will silently eat this as an "
            "undefined-variable reference before python ever sees it"
        )

    def test_interval_mode_escapes_percent_a_and_time_codes(self):
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="interval",
            active_days=["sat", "sun"],
            active_start_time="07:00", active_end_time="22:00")
        assert "%%a" in content
        assert "%%H" in content
        assert "%%M" in content
        assert not re.search(r"(?<!%)%a\b", content)
        assert not re.search(r"(?<!%)%H\b", content)
        assert not re.search(r"(?<!%)%M\b", content)


class TestWrapperActiveWindowSelfGateUsesExplicitPythonPath:
    """Regression coverage for the v8.1.13 bare-`python`-on-PATH bug.

    Confirmed live (2026-07-28, David's machine) AFTER the v8.1.12 %a fix
    was deployed and verified correct in the generated wrapper content:
    the real-world scheduled run still silently did nothing. Root cause
    was a third, independent bug in the exact same self-gate: the
    embedded `for /f ('python -c "..."')` relies on bare `python`
    resolving via PATH, but Python's install directory is present on the
    INTERACTIVE user PATH and silently absent from the PATH inherited by
    non-interactive process launches (Windows Task Scheduler's S4U logon,
    and even this AI-Prowler background process's own environment) —
    `where python` failed and `python -c "print(1)"` produced zero output
    in that context. `for /f` then captures nothing, AIP_WINDOW_CHECK
    stays unset, and the self-gate falls through to the exact same
    generic SKIP branch as the %a bug — an identical-looking symptom from
    a completely different cause, which is exactly why fixing %a alone
    did not resolve the real-world problem. The fix embeds the ABSOLUTE
    path to the interpreter already running task_queue_automation.py
    (sys.executable) instead of relying on PATH lookup at all.
    """

    def test_daily_mode_embeds_python_path_not_bare_python(self, monkeypatch):
        monkeypatch.setattr(tqa, "_SELF_GATE_PYTHON", r"C:\fake\python.exe")
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="daily")
        assert "C:\\fake\\python.exe -c \"" in content
        # No bare, unqualified `python -c` invocation should remain —
        # every python invocation in the self-gate must go through the
        # explicit interpreter path.
        assert "('python -c" not in content

    def test_interval_mode_embeds_python_path_not_bare_python(self, monkeypatch):
        monkeypatch.setattr(tqa, "_SELF_GATE_PYTHON", r"C:\fake\python.exe")
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="interval")
        assert "C:\\fake\\python.exe -c \"" in content
        assert "('python -c" not in content

    def test_self_gate_python_defaults_to_sys_executable(self):
        # Sanity check on the module-level constant itself, not a
        # monkeypatched value — confirms it's actually wired to
        # sys.executable in normal operation, not just a name that
        # happens to exist.
        assert tqa._SELF_GATE_PYTHON == (sys.executable or "python")

    def test_spaceless_path_is_used_unquoted(self, monkeypatch):
        # The common case (and David's actual machine): no spaces in the
        # interpreter path, so no quoting is needed or used. Quoting an
        # unnecessary-to-quote path is what caused the v8.1.13 follow-up
        # cmd.exe quote-corruption bug (see
        # _self_gate_python_invocation()'s docstring) — this pins the
        # correct, simpler unquoted behavior for the common case.
        monkeypatch.setattr(tqa, "_SELF_GATE_PYTHON", r"C:\fake\python.exe")
        assert tqa._self_gate_python_invocation() == r"C:\fake\python.exe"

    def test_path_with_space_is_quoted_and_prefixed_with_call(self, monkeypatch):
        # A path containing a space DOES need quoting to survive as a
        # single token — but naively wrapping it in bare quotes re-creates
        # the exact cmd.exe flanking-quote corruption bug (the command
        # would then start with a `"` character again). `call` sidesteps
        # this: it's a plain word, not a quote character, so cmd's
        # "strip first/last char if both are quotes" heuristic never
        # triggers.
        monkeypatch.setattr(tqa, "_SELF_GATE_PYTHON", r"C:\Program Files\Python311\python.exe")
        result = tqa._self_gate_python_invocation()
        assert result == 'call "C:\\Program Files\\Python311\\python.exe"'
        # Must not start with a bare quote character — that's precisely
        # the condition that triggers cmd's corrupting heuristic.
        assert not result.startswith('"')


@pytest.mark.skipif(sys.platform != "win32",
                     reason="cmd.exe .bat-file percent-substitution semantics are Windows-specific")
class TestWrapperActiveWindowSelfGateExecutesCorrectly:
    """Actually EXECUTES the generated window-check block as a real .bat
    FILE through cmd.exe — not via `cmd /c "<command>"` on a raw command
    line. That distinction is the whole point: cmd.exe's %-substitution
    rules differ between a command handed to `cmd /c` directly and a
    command read line-by-line out of an actual .bat file (the latter is
    where the v8.1.12 bug lived — a `cmd /c "python -c ...%a..."` one-liner
    does NOT reproduce it, since a bare %a with no closing %% is generally
    left alone on a raw /c command line). Only writing the real generated
    content out to a .bat file and running THAT reproduces production
    faithfully. TestWrapperActiveWindowSelfGate's string-only assertions
    passed throughout while the real .bat-file runtime behavior was broken.
    """

    @staticmethod
    def _write_and_run_window_check(content: str, tmp_path) -> str:
        # Truncate the generated content to just the window-check block —
        # everything up to (not including) the cd command that follows it —
        # then append a marker echo so a RUN result is observable on
        # stdout. A SKIP result never reaches that marker: the generated
        # block's own `exit /b 0` inside the if-block terminates the
        # script first, so SKIP is instead confirmed via the
        # last_headless_run.json it writes on the way out.
        #
        # v8.1.14: anchor is the literal `cd /d "` token, not a REM comment
        # — comment wording changed once already (v8.1.10 -> v8.1.14, when
        # the cd target moved from the install directory to
        # AI_PROWLER_HOME) and silently broke this truncation. The cd
        # command itself is a much more stable anchor: it's always present,
        # always unique, and exists specifically to mark the boundary this
        # helper needs regardless of how its surrounding commentary evolves.
        marker = 'cd /d "'
        truncated = content[:content.index(marker)]
        truncated += "\necho WINDOW_CHECK_RESULT=%AIP_WINDOW_CHECK%\n"

        bat_path = tmp_path / "window_check.bat"
        bat_path.write_text(truncated, encoding="utf-8")

        # The generated block writes its SKIP result to
        # "%USERPROFILE%\.ai-prowler\last_headless_run.json" — point
        # USERPROFILE at an isolated temp dir so this never touches the
        # real machine's ~/.ai-prowler/, same isolation principle as the
        # _isolated_home fixture above (which patches tqa.Path.home()
        # in-process; this needs the actual OS env var instead, since
        # we're now shelling out to a real subprocess).
        fake_home = tmp_path / "fake_home"
        (fake_home / ".ai-prowler").mkdir(parents=True)
        env = dict(os.environ)
        env["USERPROFILE"] = str(fake_home)
        # The generated command invokes bare `python -c ...`, resolved via
        # PATH at runtime — guarantee it resolves here regardless of the
        # ambient environment's PATH by prepending the interpreter this
        # very test is running under (sys.executable is always valid;
        # relying on whatever PATH happens to be inherited is what made
        # this flaky across different invocation contexts in the first
        # place, e.g. run_tests.bat vs. a bare pytest invocation vs. an
        # automation sandbox with a minimal PATH).
        env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")

        result = subprocess.run(
            ["cmd.exe", "/c", str(bat_path)],
            capture_output=True, text=True, timeout=30,
            cwd=str(tmp_path), env=env,
        )
        assert result.returncode == 0, (
            f"window-check .bat itself failed (rc={result.returncode}): "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )

        if "WINDOW_CHECK_RESULT=RUN" in result.stdout:
            return "RUN"

        status_file = fake_home / ".ai-prowler" / "last_headless_run.json"
        assert status_file.exists(), (
            "expected either a RUN marker on stdout or a written "
            f"last_headless_run.json on SKIP, got neither. "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert "Skipped" in status_file.read_text(encoding="utf-8")
        return "SKIP"

    def test_daily_mode_runs_when_today_is_active(self, tmp_path):
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="daily",
            active_days=list(tqa.VALID_DAY_CODES))  # every day active
        assert self._write_and_run_window_check(content, tmp_path) == "RUN", (
            "expected RUN with every day active — SKIP here means %a is "
            "being eaten by cmd.exe's .bat-file percent substitution "
            "before python ever sees it (the exact v8.1.12 regression "
            "this test exists to catch)"
        )

    def test_daily_mode_skips_when_today_is_not_active(self, tmp_path):
        today = datetime.now().strftime("%a").lower()[:3]
        other_days = [d for d in tqa.VALID_DAY_CODES if d != today]
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="daily",
            active_days=other_days)
        assert self._write_and_run_window_check(content, tmp_path) == "SKIP"

    def test_interval_mode_runs_when_today_and_time_in_window(self, tmp_path):
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="interval",
            active_days=list(tqa.VALID_DAY_CODES),
            active_start_time="00:00", active_end_time="23:59")
        assert self._write_and_run_window_check(content, tmp_path) == "RUN"

    def test_interval_mode_skips_when_today_not_in_active_days(self, tmp_path):
        today = datetime.now().strftime("%a").lower()[:3]
        other_days = [d for d in tqa.VALID_DAY_CODES if d != today]
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="interval",
            active_days=other_days,
            active_start_time="00:00", active_end_time="23:59")
        assert self._write_and_run_window_check(content, tmp_path) == "SKIP"

    def test_interval_mode_skips_when_outside_time_window(self, tmp_path):
        # 1-minute window at midnight — essentially guaranteed not to be
        # the current time, regardless of when this test runs.
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="interval",
            active_days=list(tqa.VALID_DAY_CODES),
            active_start_time="00:00", active_end_time="00:01")
        assert self._write_and_run_window_check(content, tmp_path) == "SKIP"

    def test_runs_correctly_even_when_pythons_own_directory_is_stripped_from_path(self, tmp_path):
        """THE regression test for the v8.1.13 real-world bug: David's
        machine has Python's install directory present on his interactive
        PATH but absent from the PATH that Task Scheduler / background
        processes actually inherit — `where python` failed there even
        though the file genuinely exists. This test reproduces that exact
        condition directly: build the wrapper, then run it with Python's
        own directory deliberately removed from PATH, and confirm the
        self-gate still correctly returns RUN. If this test used bare
        `python -c` (the pre-fix behavior) it would silently return SKIP
        here instead, for the wrong reason — proving the fix actually
        removes the PATH dependency rather than merely working by
        accident on machines where PATH happens to be configured right.
        """
        content = tqa.build_wrapper_script_content(
            "x.json", "mcp__ai-prowler__*", check_mode="daily",
            active_days=list(tqa.VALID_DAY_CODES))

        marker = 'cd /d "'
        truncated = content[:content.index(marker)]
        truncated += "\necho WINDOW_CHECK_RESULT=%AIP_WINDOW_CHECK%\n"
        bat_path = tmp_path / "window_check.bat"
        bat_path.write_text(truncated, encoding="utf-8")

        fake_home = tmp_path / "fake_home"
        (fake_home / ".ai-prowler").mkdir(parents=True)

        # Build a PATH that deliberately excludes the directory containing
        # sys.executable — the opposite of what _write_and_run_window_check
        # does above. Keep everything else (cmd.exe, System32, etc.) so
        # the .bat file itself can still launch.
        python_dir = str(Path(sys.executable).parent)
        stripped_path = os.pathsep.join(
            p for p in os.environ.get("PATH", "").split(os.pathsep)
            if p and os.path.normcase(os.path.normpath(p)) != os.path.normcase(os.path.normpath(python_dir))
        )
        env = dict(os.environ)
        env["USERPROFILE"] = str(fake_home)
        env["PATH"] = stripped_path

        result = subprocess.run(
            ["cmd.exe", "/c", str(bat_path)],
            capture_output=True, text=True, timeout=30,
            cwd=str(tmp_path), env=env,
        )
        assert result.returncode == 0, (
            f"window-check .bat itself failed (rc={result.returncode}): "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert "WINDOW_CHECK_RESULT=RUN" in result.stdout, (
            "expected RUN even with Python's directory stripped from "
            "PATH — a SKIP here means the wrapper is still depending on "
            "bare `python` resolving via PATH somewhere, which is exactly "
            "the v8.1.13 regression this test exists to catch. "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )


class TestInstallWrapperScriptForwardsWindowParams:

    def test_forwards_check_mode_and_window_to_content(self, tmp_path):
        target = tmp_path / "wrapper_dir"
        path = tqa.install_wrapper_script(
            target, "x.json", "mcp__ai-prowler__*",
            check_mode="interval", active_days=["mon", "wed", "fri"],
            active_start_time="08:00", active_end_time="18:00")
        content = path.read_text(encoding="utf-8")
        assert "active-window self-gate" in content
        assert "08:00" in content and "18:00" in content
        assert "'mon','wed','fri'" in content.replace(" ", "")


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
    assert '" -p "' in path.read_text(encoding="utf-8")  # exe path quoted; -p always present


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
# v8.1.11: install_scheduled_task() now delegates task creation entirely to
# _register_queue_task_elevated() (a real elevated PowerShell call, mocked
# to a safe no-op by the module-wide _isolated_home fixture) — these can no
# longer be real schtasks.exe integration tests the way they were before
# that change (would hang waiting for a UAC prompt in an automated run).
# Rewritten to verify install_scheduled_task()'s own delegation/
# result-interpretation logic instead.

def test_install_scheduled_task_delegates_enabled_flag(monkeypatch, tmp_path):
    captured = {}
    def _fake_register(wrapper_script_path, schedule_time, schedule_end_time,
                        check_mode, times_per_day, enabled, username, **kw):
        captured["enabled"] = enabled
        return True, "ok"
    monkeypatch.setattr(tqa, "_register_queue_task_elevated", _fake_register)

    wrapper = tmp_path / "run_ai_prowler_queue.bat"
    ok, detail = tqa.install_scheduled_task(wrapper, "23:59", enabled=False)
    assert ok, detail
    assert captured["enabled"] is False

    ok, detail = tqa.install_scheduled_task(wrapper, "23:59", enabled=True)
    assert ok, detail
    assert captured["enabled"] is True


def test_install_scheduled_task_reports_registration_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(tqa, "_register_queue_task_elevated",
                         lambda *a, **kw: (False, "elevation was declined"))
    wrapper = tmp_path / "run_ai_prowler_queue.bat"
    ok, detail = tqa.install_scheduled_task(wrapper, "07:30")
    assert ok is False
    assert "declined" in detail


def test_install_scheduled_task_reports_success_when_registration_succeeds(monkeypatch, tmp_path):
    monkeypatch.setattr(tqa, "_register_queue_task_elevated",
                         lambda *a, **kw: (True, "ok"))
    monkeypatch.setattr(tqa, "grant_batch_logon_right",
                         lambda *a, **kw: (True, "granted"))
    wrapper = tmp_path / "run_ai_prowler_queue.bat"
    ok, detail = tqa.install_scheduled_task(wrapper, "07:30")
    assert ok is True
    assert detail == "ok"


def test_install_scheduled_task_notes_grant_failure_but_still_succeeds(monkeypatch, tmp_path):
    # Even if the batch-logon-right grant specifically failed, task
    # creation should still proceed and report overall success (with a
    # note) -- an Interactive-only task is still better than none.
    monkeypatch.setattr(tqa, "_register_queue_task_elevated",
                         lambda *a, **kw: (True, "ok"))
    monkeypatch.setattr(tqa, "grant_batch_logon_right",
                         lambda *a, **kw: (False, "access denied"))
    wrapper = tmp_path / "run_ai_prowler_queue.bat"
    ok, detail = tqa.install_scheduled_task(wrapper, "07:30")
    assert ok is True
    assert "note" in detail.lower()
    assert "access denied" in detail


def test_scheduled_task_enabled_none_when_not_present(monkeypatch, tmp_path):
    # v8.1.16 fix: these two "when not present" tests used to call the
    # REAL, unmocked scheduled_task_exists()/scheduled_task_enabled() —
    # i.e. they depended on there being no real AI-Prowler-QueueRunner task
    # on whatever machine runs the suite, "ensuring" that via a plain
    # tqa.uninstall_scheduled_task() cleanup call. That assumption breaks
    # the moment the Task Queue feature is legitimately armed on the dev
    # machine (a real, currently-enabled use case, not a leftover from a
    # failed test) — and once uninstall_scheduled_task() gained its
    # elevated-fallback retry, whose real implementation is mocked to a
    # no-op success by the module-wide _isolated_home fixture, that
    # "cleanup" call could report success without actually touching the
    # real task, making the false assumption harder to notice. Mock the
    # underlying subprocess.run() directly instead — this test is about
    # the "not present" code path (schtasks /query exiting non-zero), not
    # about whatever's really on this machine. Note scheduled_task_enabled()
    # makes its own independent subprocess.run() call — it does NOT call
    # scheduled_task_exists() internally — so that's what has to be mocked
    # here, not scheduled_task_exists() itself.
    class _FakeNotPresent:
        returncode = 1
        stdout = "ERROR: The system cannot find the file specified.\n"
        stderr = ""

    monkeypatch.setattr(tqa.subprocess, "run", lambda *a, **kw: _FakeNotPresent())
    assert tqa.scheduled_task_enabled() is None


def test_uninstall_when_never_installed_is_safe(monkeypatch, tmp_path):
    # Same fix as above — mock presence directly rather than depending on
    # real system state. uninstall_scheduled_task() DOES call
    # scheduled_task_exists() internally (unlike scheduled_task_enabled()
    # above), so mocking that one function is sufficient here.
    monkeypatch.setattr(tqa, "scheduled_task_exists", lambda: False)
    ok, detail = tqa.uninstall_scheduled_task()
    assert ok
    assert "not present" in detail


# ── v8.1.16: uninstall_scheduled_task() elevated fallback ──────────────────
# Real-world bug: a task registered via _register_queue_task_elevated()'s
# S4U principal requires elevation to modify — confirmed live, a plain
# non-elevated `schtasks /delete` against it returns exit code 1 /
# "ERROR: Access is denied." The GUI's disable path used to call
# uninstall_scheduled_task() and discard the (ok, detail) result entirely,
# so this failure was completely invisible: config said disabled, the
# button showed OFF, but the real Windows Scheduled Task stayed armed.
# These mock subprocess.run and _unregister_queue_task_elevated directly —
# no real schtasks/PowerShell call happens here.

def test_uninstall_succeeds_on_plain_delete_first_try(monkeypatch):
    monkeypatch.setattr(tqa, "scheduled_task_exists", lambda: True)
    calls = {"elevated": 0}

    class _FakeCompletedProcess:
        returncode = 0
        stdout = "SUCCESS: The scheduled task was deleted.\n"
        stderr = ""

    monkeypatch.setattr(tqa.subprocess, "run", lambda *a, **kw: _FakeCompletedProcess())
    monkeypatch.setattr(tqa, "_unregister_queue_task_elevated",
                         lambda *a, **kw: (calls.__setitem__("elevated", calls["elevated"] + 1), (True, "ok"))[1])

    ok, detail = tqa.uninstall_scheduled_task()
    assert ok
    assert detail == "ok"
    assert calls["elevated"] == 0  # elevated fallback must NOT fire when the plain delete already worked


def test_uninstall_falls_back_to_elevated_when_plain_delete_denied(monkeypatch):
    monkeypatch.setattr(tqa, "scheduled_task_exists", lambda: True)

    class _FakeCompletedProcess:
        returncode = 1
        stdout = ""
        stderr = "ERROR: Access is denied.\n"

    monkeypatch.setattr(tqa.subprocess, "run", lambda *a, **kw: _FakeCompletedProcess())
    monkeypatch.setattr(tqa, "_unregister_queue_task_elevated",
                         lambda *a, **kw: (True, "ok"))

    ok, detail = tqa.uninstall_scheduled_task()
    assert ok
    assert "elevation" in detail


def test_uninstall_reports_failure_when_elevated_fallback_also_fails(monkeypatch):
    monkeypatch.setattr(tqa, "scheduled_task_exists", lambda: True)

    class _FakeCompletedProcess:
        returncode = 1
        stdout = ""
        stderr = "ERROR: Access is denied.\n"

    monkeypatch.setattr(tqa.subprocess, "run", lambda *a, **kw: _FakeCompletedProcess())
    monkeypatch.setattr(tqa, "_unregister_queue_task_elevated",
                         lambda *a, **kw: (False, "UAC prompt declined"))

    ok, detail = tqa.uninstall_scheduled_task()
    assert ok is False
    assert "Access is denied" in detail
    assert "UAC prompt declined" in detail


# ── v8.1.11: grant_batch_logon_right() — properly isolated, never invokes
# real schtasks/PowerShell. Real-world root cause: schtasks /RU <username>
# (without /RP) silently degrades to Interactive-only logon type when the
# account lacks SeBatchLogonRight ("Log on as a batch job") — confirmed
# live via `whoami /priv | findstr batch` returning nothing for the
# affected account, and Task Scheduler's own Properties dialog showing
# "Run only when user is logged on" selected despite /RU having been
# correctly passed. LsaAddAccountRights (called via a generated PowerShell
# script, run through a temporary elevated Scheduled Task) is the
# documented, tool-free way to grant this.

class TestGrantBatchLogonRight:

    @pytest.fixture(autouse=True)
    def _restore_real_function(self, monkeypatch):
        """This whole class exists specifically to test
        grant_batch_logon_right()'s own logic — undo the module-wide
        _isolated_home fixture's safety mock of it, just for these tests."""
        monkeypatch.setattr(tqa, "grant_batch_logon_right", _REAL_GRANT_BATCH_LOGON_RIGHT)

    def _mock_uac_success_with_result(self, monkeypatch, result_content):
        """Mocks subprocess.run for the Start-Process -Verb RunAs launcher
        call succeeding, and writes result_content to whatever result
        file path the real code computes -- simulating the elevated PS1
        having already run and reported its outcome, without ever
        actually triggering a real UAC prompt or invoking PowerShell."""
        calls = []
        def _fake_run(args, **kw):
            calls.append(args)
            if args[0] == "powershell.exe":
                ps1_files = list(tqa.AI_PROWLER_HOME.glob("_grant_batch_logon_*.ps1"))
                if ps1_files:
                    content = ps1_files[0].read_text(encoding="utf-8")
                    for line in content.splitlines():
                        if "Set-Content -Path '" in line and "OK" in line:
                            path_str = line.split("'")[1]
                            Path(path_str).write_text(result_content, encoding="utf-8")
                            break
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()
        monkeypatch.setattr(tqa.subprocess, "run", _fake_run)
        return calls

    def test_marker_present_skips_entirely_no_prompt(self, monkeypatch):
        tqa.AI_PROWLER_HOME.mkdir(parents=True, exist_ok=True)
        tqa.BATCH_LOGON_MARKER_PATH.write_text("already granted", encoding="utf-8")
        calls = []
        monkeypatch.setattr(tqa.subprocess, "run",
                             lambda *a, **kw: calls.append(a) or (_ for _ in ()).throw(
                                 AssertionError("should never call subprocess.run when marker exists")))
        ok, detail = tqa.grant_batch_logon_right("david", timeout_sec=5)
        assert ok is True
        assert "already granted" in detail.lower()
        assert calls == []

    def test_success_path_writes_marker_and_returns_true(self, monkeypatch):
        self._mock_uac_success_with_result(
            monkeypatch, f"{tqa._GRANT_BATCH_LOGON_MARKER}OK")
        ok, detail = tqa.grant_batch_logon_right("david", timeout_sec=5)
        assert ok is True
        assert "david" in detail
        assert tqa.BATCH_LOGON_MARKER_PATH.exists()

    def test_second_call_after_success_skips_via_marker(self, monkeypatch):
        calls = self._mock_uac_success_with_result(
            monkeypatch, f"{tqa._GRANT_BATCH_LOGON_MARKER}OK")
        tqa.grant_batch_logon_right("david", timeout_sec=5)
        calls.clear()
        ok, detail = tqa.grant_batch_logon_right("david", timeout_sec=5)
        assert ok is True
        assert calls == []  # no second UAC prompt

    def test_failure_reported_by_ps1_returns_false_no_marker_written(self, monkeypatch):
        self._mock_uac_success_with_result(
            monkeypatch, f"{tqa._GRANT_BATCH_LOGON_MARKER}FAIL: access denied")
        ok, detail = tqa.grant_batch_logon_right("david", timeout_sec=5)
        assert ok is False
        assert "access denied" in detail
        assert not tqa.BATCH_LOGON_MARKER_PATH.exists()

    def test_timeout_when_result_file_never_appears(self, monkeypatch):
        def _fake_run(args, **kw):
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()
        monkeypatch.setattr(tqa.subprocess, "run", _fake_run)
        # Short timeout so this test itself stays fast.
        ok, detail = tqa.grant_batch_logon_right("david", timeout_sec=1)
        assert ok is False
        assert "timed out" in detail.lower()

    def test_defaults_to_current_username_when_omitted(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "david")
        self._mock_uac_success_with_result(
            monkeypatch, f"{tqa._GRANT_BATCH_LOGON_MARKER}OK")
        ok, detail = tqa.grant_batch_logon_right(timeout_sec=5)
        assert ok is True
        assert "david" in detail

    def test_cleanup_removes_temp_ps1_and_result_files(self, monkeypatch):
        self._mock_uac_success_with_result(
            monkeypatch, f"{tqa._GRANT_BATCH_LOGON_MARKER}OK")
        tqa.grant_batch_logon_right("david", timeout_sec=5)
        leftover = list(tqa.AI_PROWLER_HOME.glob("_grant_batch_logon_*"))
        assert leftover == []

    def test_success_recognized_despite_powershell_bom(self, monkeypatch):
        # Real-world bug: Windows PowerShell 5.1's Set-Content -Encoding
        # UTF8 writes a BOM by default (PowerShell 7+ does not). A live
        # test showed the grant genuinely succeeding (the result file's
        # visible text was correct) but still being reported as a
        # failure, because the leading BOM byte broke a plain
        # content.startswith(...) check. This test writes the result file
        # with a real UTF-8 BOM prefix, exactly reproducing that scenario.
        calls = []
        def _fake_run(args, **kw):
            calls.append(args)
            if args[0] == "powershell.exe":
                ps1_files = list(tqa.AI_PROWLER_HOME.glob("_grant_batch_logon_*.ps1"))
                if ps1_files:
                    content = ps1_files[0].read_text(encoding="utf-8")
                    for line in content.splitlines():
                        if "Set-Content -Path '" in line and "OK" in line:
                            path_str = line.split("'")[1]
                            # Write with an actual UTF-8 BOM, matching what
                            # PowerShell 5.1's Set-Content -Encoding UTF8
                            # really produces.
                            Path(path_str).write_bytes(
                                b'\xef\xbb\xbf' +
                                f"{tqa._GRANT_BATCH_LOGON_MARKER}OK".encode("utf-8"))
                            break
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()
        monkeypatch.setattr(tqa.subprocess, "run", _fake_run)

        ok, detail = tqa.grant_batch_logon_right("david", timeout_sec=5)
        assert ok is True
        assert "AI_PROWLER_GRANT_RESULT" not in detail  # the raw marker text
        # must never leak into a user-facing success message


class TestBuildGrantBatchLogonPs1:

    def test_embeds_username_and_result_file(self):
        script = tqa._build_grant_batch_logon_ps1("david", r"C:\fake\result.txt")
        assert "david" in script
        assert r"C:\fake\result.txt" in script

    def test_references_correct_privilege_constant(self):
        script = tqa._build_grant_batch_logon_ps1("david", r"C:\fake\result.txt")
        assert "SeBatchLogonRight" in script

    def test_has_try_catch_for_failure_reporting(self):
        script = tqa._build_grant_batch_logon_ps1("david", r"C:\fake\result.txt")
        assert "try {" in script
        assert "catch {" in script
        assert tqa._GRANT_BATCH_LOGON_MARKER in script


# ── v8.1.11: _register_queue_task_elevated() — properly isolated ──────────
# Same pattern and rationale as TestGrantBatchLogonRight above: restores
# the real function (undoing the module-wide safety mock), and mocks
# subprocess.run directly so no real UAC prompt or PowerShell process is
# ever triggered by running the test suite.

class TestRegisterQueueTaskElevated:

    @pytest.fixture(autouse=True)
    def _restore_real_function(self, monkeypatch):
        monkeypatch.setattr(tqa, "_register_queue_task_elevated",
                             _REAL_REGISTER_QUEUE_TASK_ELEVATED)

    def _mock_uac_success_with_result(self, monkeypatch, result_content):
        def _fake_run(args, **kw):
            if args[0] == "powershell.exe":
                ps1_files = list(tqa.AI_PROWLER_HOME.glob("_register_queue_task_*.ps1"))
                if ps1_files:
                    content = ps1_files[0].read_text(encoding="utf-8")
                    for line in content.splitlines():
                        if "Set-Content -Path '" in line and "OK" in line:
                            path_str = line.split("'")[1]
                            Path(path_str).write_text(result_content, encoding="utf-8")
                            break
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()
        monkeypatch.setattr(tqa.subprocess, "run", _fake_run)

    def test_success_path_returns_true(self, monkeypatch):
        self._mock_uac_success_with_result(monkeypatch, "OK")
        ok, detail = tqa._register_queue_task_elevated(
            Path("fake.bat"), "07:30", "23:00", "daily", 1, True, "david", timeout_sec=5)
        assert ok is True

    def test_failure_reported_by_ps1_returns_false_with_message(self, monkeypatch):
        self._mock_uac_success_with_result(monkeypatch, "FAIL: access denied")
        ok, detail = tqa._register_queue_task_elevated(
            Path("fake.bat"), "07:30", "23:00", "daily", 1, True, "david", timeout_sec=5)
        assert ok is False
        assert "access denied" in detail

    def test_timeout_when_result_file_never_appears(self, monkeypatch):
        def _fake_run(args, **kw):
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()
        monkeypatch.setattr(tqa.subprocess, "run", _fake_run)
        ok, detail = tqa._register_queue_task_elevated(
            Path("fake.bat"), "07:30", "23:00", "daily", 1, True, "david", timeout_sec=1)
        assert ok is False
        assert "timed out" in detail.lower()

    def test_cleanup_removes_temp_ps1_and_result_files(self, monkeypatch):
        self._mock_uac_success_with_result(monkeypatch, "OK")
        tqa._register_queue_task_elevated(
            Path("fake.bat"), "07:30", "23:00", "daily", 1, True, "david", timeout_sec=5)
        leftover = list(tqa.AI_PROWLER_HOME.glob("_register_queue_task_*"))
        assert leftover == []

    def test_success_recognized_despite_powershell_bom(self, monkeypatch):
        # Same real-world bug as grant_batch_logon_right() — Windows
        # PowerShell 5.1's Set-Content -Encoding UTF8 writes a BOM by
        # default, which must not break the success check here either.
        def _fake_run(args, **kw):
            if args[0] == "powershell.exe":
                ps1_files = list(tqa.AI_PROWLER_HOME.glob("_register_queue_task_*.ps1"))
                if ps1_files:
                    content = ps1_files[0].read_text(encoding="utf-8")
                    for line in content.splitlines():
                        if "Set-Content -Path '" in line and "OK" in line:
                            path_str = line.split("'")[1]
                            Path(path_str).write_bytes(b'\xef\xbb\xbfOK')
                            break
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()
        monkeypatch.setattr(tqa.subprocess, "run", _fake_run)
        ok, detail = tqa._register_queue_task_elevated(
            Path("fake.bat"), "07:30", "23:00", "daily", 1, True, "david", timeout_sec=5)
        assert ok is True

    def test_wrapper_path_single_quotes_are_escaped_before_ps1_generation(self, monkeypatch):
        captured_scripts = []
        def _fake_run(args, **kw):
            if args[0] == "powershell.exe":
                ps1_files = list(tqa.AI_PROWLER_HOME.glob("_register_queue_task_*.ps1"))
                if ps1_files:
                    captured_scripts.append(ps1_files[0].read_text(encoding="utf-8"))
            class _R:
                returncode = 0
                stdout = ""
                stderr = ""
            return _R()
        monkeypatch.setattr(tqa.subprocess, "run", _fake_run)
        tqa._register_queue_task_elevated(
            Path("C:/fake's/path.bat"), "07:30", "23:00", "daily", 1, True, "david", timeout_sec=1)
        # Path() normalizes to backslashes on Windows -- check for the
        # doubled single quote specifically, not an exact path string.
        assert "fake''s" in captured_scripts[0]


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


# ── Audit log rotation (v9.0.0) ───────────────────────────────────────────

def test_rotate_audit_log_no_op_when_log_missing(_isolated_home):
    # Nothing to rotate — must not raise and must not create any files.
    assert not tqa.AUDIT_LOG_PATH.exists()
    tqa.rotate_audit_log()
    assert not tqa.AUDIT_LOG_PATH.exists()


def test_rotate_audit_log_renames_current_to_dot1(_isolated_home):
    tqa.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tqa.AUDIT_LOG_PATH.write_text("run 1\n", encoding="utf-8")

    tqa.rotate_audit_log()

    backup1 = Path(str(tqa.AUDIT_LOG_PATH) + ".1")
    assert backup1.exists(), ".log.1 backup must be created"
    assert backup1.read_text(encoding="utf-8") == "run 1\n"
    # Active log restarted fresh (empty)
    assert tqa.AUDIT_LOG_PATH.exists()
    assert tqa.AUDIT_LOG_PATH.read_text(encoding="utf-8") == ""


def test_rotate_audit_log_shifts_existing_backups(_isolated_home):
    base = tqa.AUDIT_LOG_PATH
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text("run 3\n", encoding="utf-8")
    Path(str(base) + ".1").write_text("run 2\n", encoding="utf-8")
    Path(str(base) + ".2").write_text("run 1\n", encoding="utf-8")

    tqa.rotate_audit_log(max_backups=2)

    # After rotation: .1 gets run3, .2 gets run2, run1 is overwritten (oldest slot)
    assert Path(str(base) + ".1").read_text(encoding="utf-8") == "run 3\n"
    assert Path(str(base) + ".2").read_text(encoding="utf-8") == "run 2\n"
    assert base.read_text(encoding="utf-8") == ""


def test_rotate_audit_log_keeps_max_backups_only(_isolated_home):
    base = tqa.AUDIT_LOG_PATH
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text("newest\n", encoding="utf-8")
    # Create a .3 that sits beyond the max_backups=2 window
    Path(str(base) + ".2").write_text("old\n", encoding="utf-8")

    tqa.rotate_audit_log(max_backups=2)

    # .3 must not exist — no backup slot beyond max_backups
    assert not Path(str(base) + ".3").exists()


def test_rotate_audit_log_is_best_effort_never_raises(_isolated_home, monkeypatch):
    # Even if Path.replace fails, rotate_audit_log must not propagate the error.
    tqa.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tqa.AUDIT_LOG_PATH.write_text("data\n", encoding="utf-8")

    def _boom(*a, **kw):
        raise OSError("simulated disk full")

    monkeypatch.setattr(tqa.Path, "replace", _boom)
    tqa.rotate_audit_log()  # must not raise


def test_run_queue_now_rotates_audit_log_before_run(_isolated_home, monkeypatch):
    # Confirms rotate_audit_log() is called when run_queue_now() fires —
    # the key integration point for the Scheduled Task "Run Due Tasks" path.
    tqa.AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tqa.AUDIT_LOG_PATH.write_text("previous run\n", encoding="utf-8")

    rotated = []
    _orig_rotate = tqa.rotate_audit_log
    monkeypatch.setattr(tqa, "rotate_audit_log", lambda *a, **kw: rotated.append(True) or _orig_rotate(*a, **kw))
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)
    monkeypatch.setattr(tqa, "install_wrapper_script", lambda *a, **kw: Path("fake.bat"))
    monkeypatch.setattr(tqa.subprocess, "run",
                         lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())

    tqa.run_queue_now("real.json", "mcp__ai-prowler__*")

    assert len(rotated) == 1, "rotate_audit_log() must be called exactly once per queue run"
    backup = Path(str(tqa.AUDIT_LOG_PATH) + ".1")
    assert backup.exists(), "previous log must be rotated to .1"
    assert backup.read_text(encoding="utf-8") == "previous run\n"


def test_wrapper_bat_content_includes_rotation_call(_isolated_home):
    # Confirms the generated .bat for the Scheduled Task embeds a Python
    # call to rotate_audit_log() before the claude -p invocation, so the
    # rotation fires on the overnight/unattended path too.
    content = tqa.build_wrapper_script_content(
        "real.json", "mcp__ai-prowler__*")
    assert "rotate_audit_log" in content, (
        "Wrapper .bat must call rotate_audit_log() before claude -p so the "
        "Scheduled Task path also rotates the log on each run."
    )
    # Rotation call must appear BEFORE the claude -p line
    rotation_pos = content.index("rotate_audit_log")
    claude_pos = content.index('" -p "')
    assert rotation_pos < claude_pos, (
        "rotate_audit_log() call must precede the claude -p invocation in the .bat"
    )


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


# ── v8.1.14: installer must ship .claude to the SAME place the wrapper cd's
# to ─────────────────────────────────────────────────────────────────────
# This is the actual regression the whole v8.1.14 debugging session was
# about, and none of the three tests above would have caught it: they
# check the hook script itself works correctly (it always did), and that
# the DEV-TREE source copy of .claude/settings.json is well-formed (it
# always was too). What broke live was purely a DEPLOYMENT/wiring bug —
# the .iss installer shipped .claude to {app}\.claude (the code install
# directory, e.g. C:\Program Files\AI-Prowler) while
# build_wrapper_script_content() at the time cd'd there too... until the
# LATER admin-elevation problem surfaced and the cd target needed to
# change. The two sides (installer DestDir, wrapper cd target) were never
# cross-checked against each other by anything, so they were free to
# silently drift apart — which is exactly what would have happened again
# without a test tying them together. These two tests do that tying.

def test_installer_ships_claude_folder_to_ai_prowler_home_not_app_dir():
    """Static check of AI-Prowler-Setup.iss's [Files] section: the three
    .claude Source lines must target {%USERPROFILE}\\.ai-prowler\\.claude
    (matching AI_PROWLER_HOME), never {app}\\.claude. A hand-edit that
    "fixes" the wrapper's cd target without also updating the installer's
    DestDir (or vice versa) is exactly the bug this test exists to catch
    — see the module comment above for the real live incident."""
    iss_path = Path(__file__).resolve().parents[2] / "AI-Prowler-Setup.iss"
    assert iss_path.exists()
    content = iss_path.read_text(encoding="utf-8", errors="replace")
    claude_source_lines = [
        line for line in content.splitlines()
        if line.strip().startswith("Source:") and ".claude" in line
    ]
    assert len(claude_source_lines) == 3, (
        f"Expected exactly 3 .claude Source lines (settings.json, "
        f"hooks\\log_tool_call.py, skills\\...\\SKILL.md), found "
        f"{len(claude_source_lines)}: {claude_source_lines}"
    )
    for line in claude_source_lines:
        assert r"{%USERPROFILE}\.ai-prowler\.claude" in line, (
            f"This .claude Source line does not target "
            f"{{%USERPROFILE}}\\.ai-prowler\\.claude (AI_PROWLER_HOME) — "
            f"it will silently drift from wherever "
            f"build_wrapper_script_content() actually cd's to: {line}"
        )
        assert r"{app}\.claude" not in line, (
            f"This .claude Source line targets {{app}}\\.claude, which can "
            f"be an admin-only Program-Files-class location — the exact "
            f"live bug this test guards against: {line}"
        )


def test_deployed_claude_hook_is_reachable_from_wrapper_cd_target(tmp_path, _isolated_home):
    """True end-to-end regression test: takes the REAL .claude/ folder from
    the dev tree (not a hand-written fixture), deploys it to exactly where
    build_wrapper_script_content() says the wrapper will cd to (under the
    monkeypatched, isolated AI_PROWLER_HOME — never the real one), and
    confirms the hook is actually reachable and functional from there —
    i.e. simulates "Claude Code cd's into AI_PROWLER_HOME, discovers
    .claude/settings.json, and successfully invokes
    .claude/hooks/log_tool_call.py" without needing a real Claude Code
    session to prove it. This is the automated version of the manual
    live verification done during the original debugging session (a
    synthetic hook event piped through the exact configured command),
    generalized so it can never silently start failing again."""
    real_claude_dir = Path(__file__).resolve().parents[2] / ".claude"
    assert real_claude_dir.exists()

    # Deploy to the SAME path the wrapper's cd line actually targets —
    # not a path this test invents independently, so a future change to
    # AI_PROWLER_HOME's definition can't silently desync the two.
    deployed_claude_dir = tqa.AI_PROWLER_HOME / ".claude"
    import shutil as _shutil
    _shutil.copytree(real_claude_dir, deployed_claude_dir)

    # Confirm the wrapper's own cd line matches where we just deployed to.
    content = tqa.build_wrapper_script_content("x.json", "mcp__ai-prowler__*")
    cd_line = next(l for l in content.splitlines() if l.strip().startswith("cd /d"))
    assert str(tqa.AI_PROWLER_HOME) in cd_line

    # Now actually invoke the DEPLOYED hook (not the dev-tree source copy)
    # exactly as Claude Code would, with a synthetic AI-Prowler tool call.
    hook_path = deployed_claude_dir / "hooks" / "log_tool_call.py"
    assert hook_path.exists()
    event = json.dumps({
        "tool_name": "mcp__ai-prowler__sync_due_tasks_to_queue",
        "tool_input": {},
        "tool_response": {"is_error": False},
    })
    r = subprocess.run([sys.executable, str(hook_path)], input=event,
                        capture_output=True, text=True,
                        env={"HOME": str(tmp_path), "USERPROFILE": str(tmp_path)})
    assert r.returncode == 0
    assert tqa.AUDIT_LOG_PATH.exists()
    assert "sync_due_tasks_to_queue" in tqa.AUDIT_LOG_PATH.read_text(encoding="utf-8")


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


# ── v8.1.11 fix: dry_run_check() Skill-file path is cwd-independent ────────
# Real-world bug: a fresh install auto-launched via the AI-Prowler-AutoStart
# Scheduled Task inherited Windows' default working directory
# (C:\Windows\System32) all the way into rag_gui.py, and this check
# reported the Skill file "missing" there instead of the real install
# directory, even though it was genuinely installed correctly.
#
# v8.1.14 update: the skill_path check moved from being __file__-relative
# (independent of BOTH cwd and HOME) to being AI_PROWLER_HOME-relative
# (independent of cwd, but now DELIBERATELY dependent on HOME — see
# build_wrapper_script_content()'s docstring for why). The property this
# test actually cares about — cwd-independence — still holds and is worth
# guarding, but the test needs cwd and HOME to be two clearly DIFFERENT
# directories to tell them apart; the original version happened to use the
# same tmp_path for both (via the file's blanket Path.home() isolation),
# which made the two indistinguishable and this test's own name misleading.

def test_dry_run_skill_check_ignores_current_working_directory(tmp_path, monkeypatch):
    # Simulate exactly the real-world failure mode: change the PROCESS's
    # cwd to somewhere completely unrelated to home/install (standing in
    # for C:\Windows\System32), while HOME (and therefore AI_PROWLER_HOME)
    # points somewhere else entirely — confirm the Skill file check
    # reflects HOME, never the unrelated cwd.
    fake_cwd = tmp_path / "unrelated_cwd_like_system32"
    fake_cwd.mkdir()
    fake_home = tmp_path / "real_home"
    fake_home.mkdir()
    monkeypatch.setattr(tqa.Path, "home", lambda: fake_home)
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", fake_home / ".ai-prowler")
    # dry_run_check() also calls _write_last_run() at the end, which writes
    # to STATUS_PATH -- a separate module constant computed once at import
    # time from the ORIGINAL Path.home(), not re-derived from AI_PROWLER_HOME
    # dynamically. A conftest-level autouse fixture normally keeps this in
    # sync with the default tmp_path-based isolation, but this test
    # deliberately uses a fake_home SUBDIRECTORY of tmp_path (to keep cwd and
    # home distinguishable -- see comment above), which that default no
    # longer matches. Re-patch it explicitly to stay consistent, same
    # pattern _isolated_home uses for every other test in this file.
    monkeypatch.setattr(tqa, "STATUS_PATH", fake_home / ".ai-prowler" / "task_automation_last_run.json")
    monkeypatch.chdir(fake_cwd)

    report = tqa.dry_run_check()
    skill_check = next(c for c in report["checks"] if c["name"] == "AI-Prowler Skill file")
    assert str(fake_cwd) not in skill_check["detail"]
    # The detail path must be anchored to AI_PROWLER_HOME (HOME-relative),
    # never the cwd this test deliberately set to something unrelated.
    assert str(fake_home) in skill_check["detail"]
    expected_path = fake_home / ".ai-prowler" / ".claude" / "skills" / "ai-prowler-tasks" / "SKILL.md"
    assert skill_check["detail"] == str(expected_path)


# ── Claude Code CLI presence + install ────────────────────────────────────

def test_claude_code_cli_installed_true_when_on_path(monkeypatch):
    monkeypatch.setattr(tqa.shutil, "which", lambda name: r"C:\fake\claude.exe")
    assert tqa.claude_code_cli_installed() is True


def test_claude_code_cli_installed_false_when_absent(tmp_path, monkeypatch):
    # v8.1.11: must also isolate the disk-fallback check (Path.home()) --
    # without this, the test's result silently depends on whether THIS
    # machine happens to have ~/.local/bin/claude.exe, rather than testing
    # the function's logic in isolation.
    monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
    monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
    assert tqa.claude_code_cli_installed() is False


# ── v8.1.11 fix: disk-fallback for claude_code_cli_installed() ─────────────
# Real-world bug: Setup.exe's own install log confirmed Claude Code CLI was
# genuinely present ("Already on PATH — skipping install"), but AI-Prowler
# reported "Not Installed" after being reopened -- shutil.which() only
# reflects the CURRENT PROCESS's inherited PATH snapshot, which can be
# stale immediately after a PATH registry write, especially for a process
# spawned via the AI-Prowler-AutoStart Scheduled Task (ONLOGON trigger).

class TestClaudeCodeCliDiskFallback:

    def test_found_via_disk_fallback_when_path_stale(self, tmp_path, monkeypatch):
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)  # PATH stale
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        install_dir = tmp_path / ".local" / "bin"
        install_dir.mkdir(parents=True)
        (install_dir / "claude.exe").write_text("fake binary", encoding="utf-8")

        assert tqa.claude_code_cli_installed() is True

    def test_false_when_neither_path_nor_disk_has_it(self, tmp_path, monkeypatch):
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        # Deliberately do NOT create .local/bin/claude.exe.
        assert tqa.claude_code_cli_installed() is False

    def test_path_takes_priority_no_disk_check_needed(self, monkeypatch):
        # If PATH already resolves it, the function should short-circuit
        # True without even touching the filesystem for the fallback check
        # -- confirmed indirectly: Path.home() is deliberately left
        # unmocked/untouched here and the test still passes regardless of
        # this machine's real home directory contents.
        monkeypatch.setattr(tqa.shutil, "which", lambda name: r"C:\real\claude.exe")
        assert tqa.claude_code_cli_installed() is True


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
    #
    # v8.1.11: claude.exe must NOT exist on disk until the mocked
    # subprocess.run() "installer" call actually runs — claude_code_cli_
    # installed() now also checks this same disk location directly, so if
    # the file were pre-seeded before calling install_claude_code_cli(),
    # its own early "already installed" guard would correctly short-circuit
    # before ever reaching the subprocess call or the fallback logic this
    # test is actually trying to exercise.
    fake_home = tmp_path
    monkeypatch.setattr(tqa.Path, "home", lambda: fake_home)
    install_dir = fake_home / ".local" / "bin"

    monkeypatch.setattr(tqa.shutil, "which", lambda name: None)  # PATH never has it

    def _fake_installer_run(*a, **kw):
        # The real installer writes claude.exe as a side effect of running
        # -- simulate that here, at call time, not before.
        install_dir.mkdir(parents=True, exist_ok=True)
        (install_dir / "claude.exe").write_text("fake binary", encoding="utf-8")
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    monkeypatch.setattr(tqa.subprocess, "run", _fake_installer_run)

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
# build_single_prompt_wrapper_content backs the "▶ NOW" button on My Custom
# Analyses tasks — runs ONE ad-hoc prompt immediately, without touching
# pending_tasks.json. The built-in Common Business AI Analysis section no
# longer has a ▶ NOW button (removed v8.2.x — ChromaDB contention issues).
# run_single_prompt_now() is still live code used by custom tasks.

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


# ── v9.0.2 regression: WebSearch/WebFetch missing from --allowedTools when
#    customer config was written before they were added to DEFAULT_CONFIG ───
#
# Root cause: build_wrapper_script_content() embedded the saved
# allowed_tools string verbatim. A config written with only
# "mcp__ai-prowler__*" produced a bat that silently denied every WebSearch
# and WebFetch call the prompt explicitly instructed Claude to make —
# the permission layer blocked the tool at the claude CLI level with no
# error visible in the run output, producing incomplete task results.
#
# Fix: normalise allowed_tools at generation time to always include
# WebSearch and WebFetch, regardless of what's in the saved config.
# ──────────────────────────────────────────────────────────────────────────

class TestAllowedToolsNormalisation:
    """v9.0.2 — WebSearch/WebFetch always present; mcp__* broadened."""

    def test_websearch_webfetch_added_when_missing_from_config(self):
        """Stale config with only mcp__ai-prowler__* still gets WebSearch
        and WebFetch injected into the generated bat."""
        content = tqa.build_wrapper_script_content(
            mcp_config_path="x.json",
            allowed_tools="mcp__ai-prowler__*",
        )
        assert "WebSearch" in content
        assert "WebFetch" in content

    def test_websearch_webfetch_preserved_when_already_present(self):
        """Current default config already has WebSearch,WebFetch — they
        must still be present after normalisation."""
        content = tqa.build_wrapper_script_content(
            mcp_config_path="x.json",
            allowed_tools="mcp__ai-prowler__*,WebSearch,WebFetch",
        )
        assert content.count("WebSearch") >= 1
        assert content.count("WebFetch") >= 1

    def test_narrow_mcp_wildcard_broadened_to_mcp_star(self):
        """mcp__ai-prowler__* is replaced with mcp__* so third-party
        connectors like QuickBooks or Gmail are also permitted."""
        content = tqa.build_wrapper_script_content(
            mcp_config_path="x.json",
            allowed_tools="mcp__ai-prowler__*",
        )
        assert "mcp__*" in content
        # The narrow wildcard should not appear on its own any more
        assert "mcp__ai-prowler__*" not in content

    def test_broad_mcp_wildcard_preserved_when_already_set(self):
        """If the config already has mcp__* it stays as-is."""
        content = tqa.build_wrapper_script_content(
            mcp_config_path="x.json",
            allowed_tools="mcp__*,WebSearch,WebFetch",
        )
        assert "mcp__*" in content

    def test_empty_allowed_tools_gets_mcp_star_and_web_tools(self):
        """Edge case: empty allowed_tools still gets the full minimum set."""
        content = tqa.build_wrapper_script_content(
            mcp_config_path="x.json",
            allowed_tools="",
        )
        assert "mcp__*" in content
        assert "WebSearch" in content
        assert "WebFetch" in content


# ── v9.0.0 regression tests: prewarm removal + get_best_embedding_device ─────
#
# Root cause of 70s hang in all stdio MCP server contexts (Claude Desktop
# and headless task runner): the prewarm thread imported sentence_transformers
# which at import time caused torch.cuda.is_available() to block indefinitely
# on Blackwell RTX 50xx hardware, holding the GIL and freezing FastMCP's
# asyncio event loop. Claude Desktop kept re-asking for tool permission every
# ~60s because the server never replied.
#
# Fix 1 — ai_prowler_mcp.py: prewarm thread removed entirely.
#   The prewarm pre-loaded ChromaDB + sentence-transformers as a "first
#   search is faster" optimisation unrelated to Ollama. Removed in favour
#   of on-demand loading (~2-3s, acceptable).
#
# Fix 2 — rag_preprocessor.py: get_best_embedding_device() returns 'cpu'
#   directly without calling torch.cuda.is_available().
# ─────────────────────────────────────────────────────────────────────────────

class TestPrewarmRemovalRegression:
    """v9.0.0 — prewarm thread removed; MCP config env is minimal."""

    def test_mcp_config_env_has_no_ai_prowler_headless(self, tmp_path,
                                                         monkeypatch):
        """AI_PROWLER_HEADLESS no longer needed — prewarm is gone entirely.
        The MCP server env block must NOT include it so we don't ship dead
        config to customers."""
        fake_mcp = tmp_path / "ai_prowler_mcp.py"
        fake_mcp.write_text("")
        monkeypatch.setattr(tqa, "LOCAL_MCP_SCRIPT_PATH", fake_mcp)
        ok, path = tqa._generate_local_mcp_config()
        assert ok
        import json
        config = json.loads(Path(path).read_text())
        env = config["mcpServers"]["ai-prowler"]["env"]
        assert "AI_PROWLER_HEADLESS" not in env

    def test_mcp_config_env_has_required_python_vars(self, tmp_path,
                                                       monkeypatch):
        """Standard Python env vars must still be present."""
        fake_mcp = tmp_path / "ai_prowler_mcp.py"
        fake_mcp.write_text("")
        monkeypatch.setattr(tqa, "LOCAL_MCP_SCRIPT_PATH", fake_mcp)
        ok, path = tqa._generate_local_mcp_config()
        assert ok
        import json
        config = json.loads(Path(path).read_text())
        env = config["mcpServers"]["ai-prowler"]["env"]
        assert env.get("PYTHONNOUSERSITE") == "1"
        assert env.get("PYTHONIOENCODING") == "utf-8"
        assert env.get("PYTHONUNBUFFERED") == "1"

    def test_queue_runner_prompt_does_not_call_sync_due_tasks_to_queue(self):
        """sync_due_tasks_to_queue must NOT be in the queue runner prompt.
        The queue is user-controlled — only the user manually queues tasks.
        Auto-promoting custom task definitions was removed in v9.0.0."""
        assert "sync_due_tasks_to_queue" not in tqa.QUEUE_RUNNER_PROMPT

    def test_queue_runner_prompt_starts_with_get_pending(self):
        """Step 1 of the runner must be get_pending_analysis_tasks,
        not sync_due_tasks_to_queue."""
        # The first tool mentioned in the sequence should be
        # get_pending_analysis_tasks
        idx_pending = tqa.QUEUE_RUNNER_PROMPT.find("get_pending_analysis_tasks")
        idx_sync    = tqa.QUEUE_RUNNER_PROMPT.find("sync_due_tasks_to_queue")
        assert idx_pending != -1
        assert idx_sync == -1   # completely absent

    def test_queue_runner_uses_bypass_permissions(self):
        """bypassPermissions is required so MCP tool calls are not
        interactively prompted — acceptEdits only covers file edits."""
        content = tqa.build_wrapper_script_content("x.json", "mcp__*")
        assert "bypassPermissions" in content
        assert "acceptEdits" not in content


class TestGetBestEmbeddingDeviceRegression:
    """v9.0.0 — get_best_embedding_device() always returns 'cpu'."""

    def test_returns_cpu_always(self):
        """Must return 'cpu' unconditionally — no torch.cuda calls allowed.
        torch.cuda.is_available() hangs indefinitely on Blackwell RTX 50xx
        inside any stdio MCP server subprocess context, holding the GIL and
        freezing the asyncio event loop. Ollama uses the GPU independently."""
        import sys
        repo_root = str(Path(__file__).parent.parent.parent)
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        import importlib
        rp = importlib.import_module("rag_preprocessor")
        assert rp.get_best_embedding_device() == 'cpu'

    def test_does_not_call_torch(self):
        """get_best_embedding_device() must not call torch in its body.
        Importing torch triggers CUDA device enumeration at module level
        which hangs on Blackwell hardware. The docstring may mention torch
        for documentation purposes — only the code body matters."""
        import sys, importlib, inspect, ast
        repo_root = str(Path(__file__).parent.parent.parent)
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        rp = importlib.import_module("rag_preprocessor")
        src = inspect.getsource(rp.get_best_embedding_device)
        # Parse the AST to check only the code body, not the docstring
        tree = ast.parse(src)
        func = tree.body[0]
        # Get all nodes AFTER the docstring
        body_nodes = func.body[1:]  # skip docstring
        body_src = ast.unparse(ast.Module(body=body_nodes, type_ignores=[]))
        assert "torch" not in body_src
        assert "cuda" not in body_src.lower()


# ── v9.0.0 regression: sentence_transformers must be pre-imported at module
#    level in rag_preprocessor.py, NOT lazily inside tool handlers ────────────
#
# Root cause of 30-60s hang in check_ai_prowler_status and any other tool
# that calls get_chroma_client(): when sentence_transformers is first imported
# inside _SentenceTransformerEmbedding.__init__() during a live tool call,
# FastMCP's asyncio event loop is already running. PyTorch initialization
# conflicts with the running loop, causing a deadlock until the 60s
# _prewarm_event.wait() timeout fires.
#
# Fix: pre-import sentence_transformers at rag_preprocessor module level
# (lines ~168-175). This import happens when ai_prowler_mcp.py first imports
# rag_preprocessor — BEFORE mcp.run() starts the event loop. Subsequent
# lazy imports inside __init__ are no-ops from sys.modules cache.
#
# Confirmed fix: check_ai_prowler_status now completes in ~10s (was 72s).
# ─────────────────────────────────────────────────────────────────────────────

class TestSentenceTransformersPreImportRegression:
    """v9.0.0 — sentence_transformers pre-imported at module level."""

    def test_sentence_transformers_preloaded_at_module_level(self):
        """rag_preprocessor must pre-import sentence_transformers at module
        level so the lazy import inside _SentenceTransformerEmbedding.__init__
        is a no-op (sys.modules hit) when called from a live tool handler
        with asyncio event loop already running."""
        import sys, importlib
        repo_root = str(Path(__file__).parent.parent.parent)
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        rp = importlib.import_module("rag_preprocessor")
        # The pre-import sets _SENTENCE_TRANSFORMERS_AVAILABLE
        assert hasattr(rp, '_SENTENCE_TRANSFORMERS_AVAILABLE'), (
            "_SENTENCE_TRANSFORMERS_AVAILABLE not set — "
            "sentence_transformers module-level pre-import is missing")
        assert rp._SENTENCE_TRANSFORMERS_AVAILABLE, (
            "sentence_transformers failed to import at module level")

    def test_sentence_transformers_in_sys_modules_after_rag_import(self):
        """After importing rag_preprocessor, sentence_transformers must
        already be in sys.modules so any subsequent lazy import inside
        _SentenceTransformerEmbedding.__init__ is a no-op cache hit."""
        import sys, importlib
        repo_root = str(Path(__file__).parent.parent.parent)
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        importlib.import_module("rag_preprocessor")
        assert "sentence_transformers" in sys.modules, (
            "sentence_transformers not in sys.modules after rag_preprocessor "
            "import — module-level pre-import is missing or failed. "
            "This means the first call to get_chroma_client() from a live "
            "tool handler will trigger a slow lazy import that deadlocks "
            "with FastMCP's asyncio event loop (~60s hang).")


# ── v9.0.1: _get_claude_exe() + .bat absolute path + dry-run Task Scheduler
#            path check + install_claude_code_cli() PATH repair ───────────────
#
# Root cause of 2026-08-10 bug: the generated .bat used bare `claude -p`
# which relies on PATH. Windows Task Scheduler runs in a stripped environment
# that often lacks user PATH entries, so `claude` was not recognized as a
# command. The GUI's dry-run check used shutil.which() which ran in the GUI
# process (full user PATH) so it reported ✅ while the Scheduled Task silently
# failed with "not recognized as a command" in last_headless_run.json.
#
# Three interlocking fixes:
#   _get_claude_exe()           — resolves absolute path at generation time
#   build_wrapper_script_content() — embeds that absolute path in the .bat
#   dry_run_check()             — adds a Task Scheduler-specific check
#   install_claude_code_cli()   — fixes PATH even when claude.exe is on disk
# ─────────────────────────────────────────────────────────────────────────────

class TestGetClaudeExe:
    """_get_claude_exe() must always return an absolute path when claude is
    findable, and degrade gracefully to bare 'claude' when it isn't."""

    def test_returns_which_result_when_on_path(self, monkeypatch):
        monkeypatch.setattr(tqa.shutil, "which",
                            lambda name: r"C:\Users\david\AppData\Local\bin\claude.EXE")
        assert tqa._get_claude_exe() == r"C:\Users\david\AppData\Local\bin\claude.EXE"

    def test_returns_disk_fallback_when_not_on_path(self, monkeypatch, tmp_path):
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        disk_path = tmp_path / ".local" / "bin" / "claude.exe"
        disk_path.parent.mkdir(parents=True)
        disk_path.write_text("")
        result = tqa._get_claude_exe()
        assert result == str(disk_path)

    def test_returns_bare_claude_when_nowhere_found(self, monkeypatch, tmp_path):
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        # Don't create the disk fallback — nothing exists
        assert tqa._get_claude_exe() == "claude"

    def test_which_takes_priority_over_disk(self, monkeypatch, tmp_path):
        """Even if the disk fallback exists, shutil.which() wins."""
        monkeypatch.setattr(tqa.shutil, "which",
                            lambda name: r"C:\custom\claude.exe")
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        disk_path = tmp_path / ".local" / "bin" / "claude.exe"
        disk_path.parent.mkdir(parents=True)
        disk_path.write_text("")
        assert tqa._get_claude_exe() == r"C:\custom\claude.exe"

    def test_result_is_never_pythonw(self, monkeypatch):
        """Sanity guard — _get_claude_exe() must never accidentally return
        a Python interpreter path."""
        monkeypatch.setattr(tqa.shutil, "which",
                            lambda name: r"C:\Python311\python.exe" if name == "python" else None)
        result = tqa._get_claude_exe()
        assert "python" not in result.lower()


class TestWrapperBatUsesAbsoluteClaudePath:
    """The generated .bat must embed the absolute path from _get_claude_exe()
    rather than bare 'claude', so Task Scheduler never has to search PATH.
    This is the regression guard for the 2026-08-10 silent-failure bug."""

    def test_bat_uses_absolute_path_not_bare_claude(self, monkeypatch):
        monkeypatch.setattr(tqa.shutil, "which",
                            lambda name: r"C:\Users\david\AppData\Local\bin\claude.EXE")
        content = tqa.build_wrapper_script_content("x.json", "mcp__*")
        # Must contain the quoted absolute path before -p
        assert r'"C:\Users\david\AppData\Local\bin\claude.EXE" -p' in content

    def test_bat_does_not_use_bare_claude_when_path_resolved(self, monkeypatch):
        monkeypatch.setattr(tqa.shutil, "which",
                            lambda name: r"C:\Users\david\AppData\Local\bin\claude.EXE")
        content = tqa.build_wrapper_script_content("x.json", "mcp__*")
        # No unquoted bare `claude -p` anywhere in the script
        for line in content.splitlines():
            stripped = line.strip()
            assert not stripped.startswith("claude -p"), (
                f"Bare 'claude -p' found — Task Scheduler will fail:\n{line}")

    def test_bat_uses_disk_fallback_path_when_not_on_path(self, monkeypatch, tmp_path):
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        disk_path = tmp_path / ".local" / "bin" / "claude.exe"
        disk_path.parent.mkdir(parents=True)
        disk_path.write_text("")
        content = tqa.build_wrapper_script_content("x.json", "mcp__*")
        assert f'"{disk_path}" -p' in content

    def test_bat_falls_back_to_bare_claude_when_nowhere_found(self, monkeypatch, tmp_path):
        """Last-resort fallback: bare 'claude' is still embedded so the .bat
        fails visibly rather than silently skipping the claude invocation."""
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        content = tqa.build_wrapper_script_content("x.json", "mcp__*")
        assert '"claude" -p' in content

    def test_bat_absolute_path_survives_spaces_in_path(self, monkeypatch):
        """A path with spaces must be quoted correctly so cmd.exe treats it
        as a single token."""
        spaced = r"C:\Program Files\Claude\claude.exe"
        monkeypatch.setattr(tqa.shutil, "which", lambda name: spaced)
        content = tqa.build_wrapper_script_content("x.json", "mcp__*")
        assert f'"{spaced}" -p' in content

    def test_bat_claude_invocation_never_uses_pythonw(self, monkeypatch):
        """Regression guard: _get_claude_exe() must never accidentally return
        a Python interpreter path."""
        monkeypatch.setattr(tqa.shutil, "which",
                            lambda name: r"C:\Python311\claude.exe")
        content = tqa.build_wrapper_script_content("x.json", "mcp__*")
        claude_line = next(
            l for l in content.splitlines()
            if "-p" in l and "mcp-config" not in l and "REM" not in l)
        assert "pythonw" not in claude_line.lower()

    def test_install_wrapper_script_also_uses_absolute_path(self, monkeypatch, tmp_path):
        """install_wrapper_script() writes the .bat to disk — confirm the
        on-disk file also contains the absolute path, not bare 'claude'."""
        monkeypatch.setattr(tqa.shutil, "which",
                            lambda name: r"C:\Users\david\AppData\Local\bin\claude.EXE")
        target = tmp_path / "wrapper_dir"
        path = tqa.install_wrapper_script(target, "C:\\x\\mcp.json", "mcp__*")
        content = path.read_text(encoding="utf-8")
        assert r'"C:\Users\david\AppData\Local\bin\claude.EXE" -p' in content
        assert "claude -p" not in content  # bare form never appears


class TestDryRunTaskSchedulerPathCheck:
    """dry_run_check() must include a Task Scheduler-specific path check
    that is independent of the GUI process's PATH — the check that was
    missing before the 2026-08-10 bug."""

    def test_task_scheduler_check_present_in_report(self, _isolated_home, monkeypatch):
        monkeypatch.setattr(tqa.subprocess, "run",
                            lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "2.1.0", "stderr": ""})())
        monkeypatch.setattr(tqa.shutil, "which",
                            lambda name: r"C:\Users\david\AppData\Local\bin\claude.EXE")
        report = tqa.dry_run_check()
        names = [c["name"] for c in report["checks"]]
        assert "Claude Code CLI — Task Scheduler path" in names, (
            "Task Scheduler path check missing from dry_run_check() — "
            "this was the check that would have caught the 2026-08-10 bug")

    def test_task_scheduler_check_passes_when_absolute_path_resolved(
            self, _isolated_home, monkeypatch):
        monkeypatch.setattr(tqa.subprocess, "run",
                            lambda *a, **kw: type("R", (), {"returncode": 0, "stdout": "2.1.0", "stderr": ""})())
        monkeypatch.setattr(tqa.shutil, "which",
                            lambda name: r"C:\Users\david\AppData\Local\bin\claude.EXE")
        report = tqa.dry_run_check()
        sched_check = next(
            c for c in report["checks"]
            if c["name"] == "Claude Code CLI — Task Scheduler path")
        assert sched_check["ok"] is True
        assert r"C:\Users\david\AppData\Local\bin\claude.EXE" in sched_check["detail"]

    def test_task_scheduler_check_fails_when_only_bare_claude_available(
            self, _isolated_home, monkeypatch, tmp_path):
        """Simulates the exact 2026-08-10 failure: shutil.which() returns None
        (PATH broken in this process) AND no disk fallback exists either."""
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path / ".ai-prowler")
        monkeypatch.setattr(tqa, "STATUS_PATH",
                            tmp_path / ".ai-prowler" / "task_automation_last_run.json")
        monkeypatch.setattr(tqa.subprocess, "run",
                            lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})())
        report = tqa.dry_run_check()
        sched_check = next(
            c for c in report["checks"]
            if c["name"] == "Claude Code CLI — Task Scheduler path")
        assert sched_check["ok"] is False
        assert "Install Claude Code CLI" in sched_check["detail"]

    def test_task_scheduler_check_passes_via_disk_fallback(
            self, _isolated_home, monkeypatch, tmp_path):
        """Disk fallback: not on PATH but on disk — _get_claude_exe() finds it,
        so the Task Scheduler check passes even though the PATH check fails."""
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path / ".ai-prowler")
        monkeypatch.setattr(tqa, "STATUS_PATH",
                            tmp_path / ".ai-prowler" / "task_automation_last_run.json")
        disk_path = tmp_path / ".local" / "bin" / "claude.exe"
        disk_path.parent.mkdir(parents=True)
        disk_path.write_text("")
        monkeypatch.setattr(tqa.subprocess, "run",
                            lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})())
        report = tqa.dry_run_check()
        sched_check = next(
            c for c in report["checks"]
            if c["name"] == "Claude Code CLI — Task Scheduler path")
        assert sched_check["ok"] is True
        assert str(disk_path) in sched_check["detail"]

    def test_path_check_tells_user_to_click_install_when_on_disk_not_path(
            self, _isolated_home, monkeypatch, tmp_path):
        """When claude.exe is on disk but not on PATH, the PATH check detail
        must explicitly tell the user to click Install Claude Code CLI."""
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path / ".ai-prowler")
        monkeypatch.setattr(tqa, "STATUS_PATH",
                            tmp_path / ".ai-prowler" / "task_automation_last_run.json")
        disk_path = tmp_path / ".local" / "bin" / "claude.exe"
        disk_path.parent.mkdir(parents=True)
        disk_path.write_text("")
        monkeypatch.setattr(tqa.subprocess, "run",
                            lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})())
        report = tqa.dry_run_check()
        path_check = next(
            c for c in report["checks"]
            if c["name"] == "Claude Code CLI on PATH")
        assert path_check["ok"] is False
        assert "Install Claude Code CLI" in path_check["detail"]
        assert str(disk_path) in path_check["detail"]

    def test_dry_run_all_ok_requires_task_scheduler_check_to_pass(
            self, _isolated_home, monkeypatch, tmp_path):
        """all_ok must be False if the Task Scheduler check fails, even if
        all other checks pass — this is what would have flagged the bug."""
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path / ".ai-prowler")
        monkeypatch.setattr(tqa, "STATUS_PATH",
                            tmp_path / ".ai-prowler" / "task_automation_last_run.json")
        monkeypatch.setattr(tqa.subprocess, "run",
                            lambda *a, **kw: type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})())
        report = tqa.dry_run_check()
        assert report["all_ok"] is False


class TestInstallClaudeCodeCliPathRepair:
    """install_claude_code_cli() must repair PATH when claude.exe is on disk
    but not on PATH — the case where the button previously said 'Already
    installed' and did nothing, leaving Task Scheduler broken."""

    def test_already_on_path_returns_already_installed(self, monkeypatch):
        monkeypatch.setattr(tqa.shutil, "which",
                            lambda name: r"C:\Users\david\AppData\Local\bin\claude.EXE")
        ok, detail = tqa.install_claude_code_cli()
        assert ok is True
        assert "Already installed" in detail

    def test_on_disk_not_on_path_calls_add_to_user_path(
            self, monkeypatch, tmp_path):
        """Core regression test: when claude.exe exists on disk but PATH is
        broken, the button must call _add_to_user_path() instead of bailing
        out with 'Already installed.'"""
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        disk_path = tmp_path / ".local" / "bin" / "claude.exe"
        disk_path.parent.mkdir(parents=True)
        disk_path.write_text("")
        path_calls = []
        monkeypatch.setattr(tqa, "_add_to_user_path",
                            lambda d: path_calls.append(d) or True)
        # After _add_to_user_path, which() now succeeds (simulate PATH fixed)
        call_count = {"n": 0}
        def _which_after_repair(name):
            call_count["n"] += 1
            return r"C:\fake\claude.exe" if call_count["n"] > 1 else None
        monkeypatch.setattr(tqa.shutil, "which", _which_after_repair)
        ok, detail = tqa.install_claude_code_cli()
        assert ok is True
        assert len(path_calls) == 1, "_add_to_user_path must be called exactly once"
        assert "missing from PATH" in detail or "registered" in detail

    def test_on_disk_not_on_path_does_not_say_already_installed(
            self, monkeypatch, tmp_path):
        """The old broken behaviour: button returned 'Already installed.'
        without fixing PATH. This must never happen again."""
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        disk_path = tmp_path / ".local" / "bin" / "claude.exe"
        disk_path.parent.mkdir(parents=True)
        disk_path.write_text("")
        monkeypatch.setattr(tqa, "_add_to_user_path", lambda d: True)
        call_count = {"n": 0}
        def _which_after_repair(name):
            call_count["n"] += 1
            return r"C:\fake\claude.exe" if call_count["n"] > 1 else None
        monkeypatch.setattr(tqa.shutil, "which", _which_after_repair)
        ok, detail = tqa.install_claude_code_cli()
        assert "Already installed" not in detail, (
            "install_claude_code_cli() still returns 'Already installed.' "
            "when claude.exe is on disk but PATH is broken — this is the "
            "regression that caused the 2026-08-10 bug")

    def test_install_cli_skips_powershell_when_disk_fallback_succeeds(
            self, monkeypatch, tmp_path):
        """When the disk-fallback PATH repair succeeds, no PowerShell installer
        should be invoked — it's already installed, just mis-registered."""
        run_calls = []
        monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
        monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
        disk_path = tmp_path / ".local" / "bin" / "claude.exe"
        disk_path.parent.mkdir(parents=True)
        disk_path.write_text("")
        monkeypatch.setattr(tqa, "_add_to_user_path", lambda d: True)
        call_count = {"n": 0}
        def _which_after_repair(name):
            call_count["n"] += 1
            return r"C:\fake\claude.exe" if call_count["n"] > 1 else None
        monkeypatch.setattr(tqa.shutil, "which", _which_after_repair)
        monkeypatch.setattr(tqa.subprocess, "run",
                            lambda *a, **kw: run_calls.append(a) or
                            type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})())
        tqa.install_claude_code_cli()
        ps_calls = [c for c in run_calls
                    if c and isinstance(c[0], list) and "powershell" in str(c[0]).lower()]
        assert not ps_calls, "PowerShell installer must not run when disk-fallback PATH repair succeeds"
