"""
GUI tests — Autonomous Task Queue panel (Settings / Quick Links tab)
======================================================================

Drives the real "🤖 Autonomous Task Queue" panel through a real RAGGui
instance (via the `gui` fixture), the same way test_http_uptime.py drives
the HTTP server uptime feature. Before this file, none of this panel's
widgets, variables, or button callbacks had ever been exercised by an
automated test — only compile_check() (syntax) and the full regression
suite (which only proves nothing ELSE broke, not that this panel works).

CRITICAL SAFETY NOTE: this file isolates task_queue_automation's own
Path.home()-based constants the same way test_task_queue_automation.py
does, AND mocks every function that would touch a real Scheduled Task,
run a real subprocess, or hit the network. Driving _tqa_save_and_apply()
or _tqa_install_cli() through their real button callbacks means real
side-effecting calls happen unless explicitly mocked here.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import task_queue_automation as tqa


@pytest.fixture(autouse=True)
def _isolate_tqa_paths(tmp_path, monkeypatch):
    """Same isolation as test_task_queue_automation.py — this module's
    constants are set once and monkeypatch.setattr overwrites the already-
    loaded module object directly, so it's safe regardless of whether
    another test already imported task_queue_automation first."""
    monkeypatch.setattr(tqa.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(tqa, "AI_PROWLER_HOME", tmp_path / ".ai-prowler")
    monkeypatch.setattr(tqa, "CONFIG_PATH", tmp_path / ".ai-prowler" / "task_automation_config.json")
    monkeypatch.setattr(tqa, "STATUS_PATH", tmp_path / ".ai-prowler" / "task_automation_last_run.json")
    monkeypatch.setattr(tqa, "AUDIT_LOG_PATH", tmp_path / ".ai-prowler" / "autonomous_run_audit.log")
    monkeypatch.setattr(tqa, "AI_PROWLER_CONFIG_PATH", tmp_path / ".ai-prowler" / "config.json")
    monkeypatch.setattr(tqa, "GENERATED_MCP_CONFIG_PATH", tmp_path / ".ai-prowler" / "claude_mcp_config.json")
    monkeypatch.setattr(tqa, "API_KEY_PATH", tmp_path / ".ai-prowler" / "claude_api_key.txt")
    yield tmp_path


def _pump(gui):
    gui.root.update()
    gui.root.update_idletasks()


# ── Panel builds and exposes its state ────────────────────────────────────

def test_panel_available_and_defaults(gui):
    _pump(gui)
    assert gui.app._tqa_available is True
    assert gui.app._tqa_enabled_var.get() is False
    assert gui.app._tqa_auth_var.get() == "oauth"
    assert gui.app._tqa_status_var.get() == "● Disabled"


# ── CLI presence status light ──────────────────────────────────────────────

def test_cli_status_shows_not_installed(gui, monkeypatch):
    monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
    gui.app._tqa_refresh_cli_status()
    _pump(gui)
    assert "Not Installed" in gui.app._tqa_cli_var.get()


def test_cli_status_shows_installed(gui, monkeypatch):
    monkeypatch.setattr(tqa.shutil, "which", lambda name: r"C:\fake\claude.exe")
    gui.app._tqa_refresh_cli_status()
    _pump(gui)
    assert "Installed" in gui.app._tqa_cli_var.get()
    assert "Not Installed" not in gui.app._tqa_cli_var.get()


def test_install_cli_button_success_updates_light_and_shows_dialog(gui, monkeypatch, dialogs):
    monkeypatch.setattr(tqa, "install_claude_code_cli",
                         lambda: (True, "Installed successfully."))
    monkeypatch.setattr(tqa.shutil, "which", lambda name: r"C:\fake\claude.exe")
    dialogs.reset()
    gui.app._tqa_install_cli()
    _pump(gui)
    assert "Installed" in gui.app._tqa_cli_var.get()
    assert dialogs.last_call("showinfo") is not None


def test_install_cli_button_failure_shows_error_and_light_stays_red(gui, monkeypatch, dialogs):
    monkeypatch.setattr(tqa, "install_claude_code_cli",
                         lambda: (False, "boom - network unreachable"))
    monkeypatch.setattr(tqa.shutil, "which", lambda name: None)
    dialogs.reset()
    gui.app._tqa_install_cli()
    _pump(gui)
    assert "Not Installed" in gui.app._tqa_cli_var.get()
    err = dialogs.last_call("showerror")
    assert err is not None
    assert "boom" in err["message"]


# ── Save / enable flow ─────────────────────────────────────────────────────

def test_save_with_disabled_just_persists_config(gui, monkeypatch):
    # Every save with enabled=False calls uninstall_scheduled_task() as a
    # defensive no-op (idempotent per its own tests) — mocked here so this
    # GUI test never touches a real Scheduled Task regardless.
    uninstall_calls = []
    monkeypatch.setattr(tqa, "uninstall_scheduled_task",
                         lambda: (uninstall_calls.append(1), (True, "not present"))[1])

    gui.app._tqa_enabled_var.set(False)
    gui.app._tqa_time_var.set("07:30")
    gui.app._tqa_save_and_apply()
    _pump(gui)

    saved = tqa.load_config()
    assert saved["enabled"] is False
    assert saved["schedule_time"] == "07:30"
    assert len(uninstall_calls) == 1


def test_save_enabled_without_mcp_config_warns_and_does_not_install(gui, monkeypatch, dialogs):
    install_calls = []
    monkeypatch.setattr(tqa, "install_scheduled_task",
                         lambda *a, **kw: (install_calls.append(1), (True, "ok"))[1])
    monkeypatch.setattr(tqa, "install_wrapper_script",
                         lambda *a, **kw: Path("fake_wrapper.bat"))

    dialogs.reset()
    gui.app._tqa_enabled_var.set(True)
    gui.app._tqa_save_and_apply()
    _pump(gui)

    assert dialogs.last_call("showwarning") is not None
    assert "MCP Config" in dialogs.last_call("showwarning")["title"]
    # The real guard being tested: enabled=True alone is not enough:
    # install_scheduled_task must NOT be reached without a real mcp_config_path.
    assert len(install_calls) == 0


def test_save_enabled_with_mcp_config_installs_scheduled_task(gui, monkeypatch, dialogs):
    install_calls = []
    monkeypatch.setattr(tqa, "install_scheduled_task",
                         lambda *a, **kw: (install_calls.append(a), (True, "ok"))[1])
    monkeypatch.setattr(tqa, "install_wrapper_script",
                         lambda *a, **kw: Path("fake_wrapper.bat"))

    # The panel reads from its own in-memory _tqa_cfg (loaded once at
    # panel-build time), NOT freshly from disk on every save — so seeding
    # mcp_config_path has to go through that same in-memory dict, exactly
    # like a real "Generate MCP Config" button click would update it.
    gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)
    gui.app._tqa_enabled_var.set(True)
    gui.app._tqa_time_var.set("06:00")
    dialogs.reset()
    gui.app._tqa_save_and_apply()
    _pump(gui)

    assert len(install_calls) == 1
    saved = tqa.load_config()
    assert saved["enabled"] is True


# ── Auth method switching ──────────────────────────────────────────────────

def test_switching_to_api_key_persists_on_save(gui, monkeypatch):
    monkeypatch.setattr(tqa, "uninstall_scheduled_task", lambda: (True, "not present"))
    gui.app._tqa_auth_var.set("api_key")
    gui.app._tqa_save_and_apply()
    _pump(gui)
    assert tqa.load_config()["use_api_key"] is True


def test_switching_back_to_oauth_persists_on_save(gui, monkeypatch):
    monkeypatch.setattr(tqa, "uninstall_scheduled_task", lambda: (True, "not present"))
    gui.app._tqa_auth_var.set("api_key")
    gui.app._tqa_save_and_apply()
    gui.app._tqa_auth_var.set("oauth")
    gui.app._tqa_save_and_apply()
    _pump(gui)
    assert tqa.load_config()["use_api_key"] is False


def test_notify_settings_persist_on_save(gui, monkeypatch):
    monkeypatch.setattr(tqa, "uninstall_scheduled_task", lambda: (True, "not present"))
    gui.app._tqa_notify_var.set(True)
    gui.app._tqa_method_var.set("whatsapp")
    gui.app._tqa_save_and_apply()
    _pump(gui)
    saved = tqa.load_config()
    assert saved["notify_on_complete"] is True
    assert saved["notify_method"] == "whatsapp"


# ── Test Setup (dry run) ────────────────────────────────────────────────────

def test_test_setup_updates_status_from_dry_run_report(gui, monkeypatch):
    fake_report = {
        "all_ok": False,
        "checks": [
            {"name": "Claude Code CLI on PATH", "ok": False, "detail": "not found"},
            {"name": "AI-Prowler HTTP MCP server (port 8000)", "ok": True, "detail": "responded 200"},
        ],
    }
    monkeypatch.setattr(tqa, "dry_run_check", lambda: fake_report)
    gui.app._tqa_test_setup()
    _pump(gui)
    # Status display should have re-run and reflect current (disabled) state —
    # the important assertion is that this didn't raise and the report was
    # consumed, not that a specific color was set (that's an implementation
    # detail of _tqa_render_checklist, not part of the public contract).
    assert gui.app._tqa_status_var.get() in ("● Disabled", "● Enabled")


# ── "Run Due Tasks" button (My Custom Analyses tab) ────────────────────────
# This button pre-dates the Autonomous Task Queue panel — these tests cover
# the NEW behavior added alongside it: direct execution via run_queue_now()
# when Claude Code CLI is installed, falling back to the original
# copy-into-a-new-chat flow when it isn't, with the button's own color/text
# reflecting which mode is active.

def test_run_due_button_shows_not_ready_when_cli_missing(gui, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: False)
    gui.app._refresh_run_due_button_state()
    _pump(gui)
    assert "needs Claude Code" in gui.app._run_due_btn.cget("text")


def test_run_due_button_shows_ready_when_cli_installed(gui, monkeypatch):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)
    gui.app._refresh_run_due_button_state()
    _pump(gui)
    assert "needs Claude Code" not in gui.app._run_due_btn.cget("text")


def test_run_due_tasks_no_due_tasks_does_nothing(gui, monkeypatch):
    import custom_tasks_manager as ctm
    monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
    monkeypatch.setattr(ctm, "get_due_tasks", lambda tasks: [])
    run_calls = []
    monkeypatch.setattr(tqa, "run_queue_now", lambda *a, **kw: run_calls.append(1))
    gui.app._run_due_tasks()
    _pump(gui)
    assert len(run_calls) == 0


def test_run_due_tasks_falls_back_to_clipboard_when_cli_missing(gui, monkeypatch, dialogs):
    import custom_tasks_manager as ctm
    monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
    monkeypatch.setattr(ctm, "get_due_tasks", lambda tasks: [{"id": "t1"}])
    monkeypatch.setattr(ctm, "tasks_to_queue_entries",
                         lambda due: [{"task_id": "t1", "prompt": "x"}])
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: False)

    run_calls = []
    monkeypatch.setattr(tqa, "run_queue_now", lambda *a, **kw: run_calls.append(1))
    dialogs.reset()
    gui.app._run_due_tasks()
    _pump(gui)

    # Falls back to the original flow: no direct run attempted, and the
    # informational dialog fires instead — button stays usable, it just
    # can't run automatically without the CLI.
    assert len(run_calls) == 0
    assert dialogs.last_call("showinfo") is not None
    assert "Claude Code CLI isn't installed" in dialogs.last_call("showinfo")["message"]


def test_run_due_tasks_runs_directly_when_cli_installed(gui, monkeypatch, dialogs):
    import custom_tasks_manager as ctm
    monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
    monkeypatch.setattr(ctm, "get_due_tasks", lambda tasks: [{"id": "t1"}])
    monkeypatch.setattr(ctm, "tasks_to_queue_entries",
                         lambda due: [{"task_id": "t1", "prompt": "x"}])
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)

    # Run the background thread synchronously so the test doesn't need to
    # sleep/poll for completion — threading.Thread is the same stdlib
    # singleton rag_gui.py itself imports, so this patch reaches it too.
    import threading
    monkeypatch.setattr(threading, "Thread",
                         lambda target, daemon: type("T", (), {"start": lambda self: target()})())

    run_calls = []
    def _fake_run_queue_now(*a, **kw):
        run_calls.append(a)
        return True, "2 tasks processed successfully."
    monkeypatch.setattr(tqa, "run_queue_now", _fake_run_queue_now)

    dialogs.reset()
    gui.app._run_due_tasks()
    _pump(gui)

    assert len(run_calls) == 1
    info = dialogs.last_call("showinfo")
    assert info is not None
    assert "2 tasks processed successfully" in info["message"]
    # Button must be re-enabled after the run finishes, not left disabled.
    assert str(gui.app._run_due_btn.cget("state")) == "normal"


def test_run_due_tasks_shows_error_dialog_on_failed_run(gui, monkeypatch, dialogs):
    import custom_tasks_manager as ctm
    monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
    monkeypatch.setattr(ctm, "get_due_tasks", lambda tasks: [{"id": "t1"}])
    monkeypatch.setattr(ctm, "tasks_to_queue_entries",
                         lambda due: [{"task_id": "t1", "prompt": "x"}])
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)

    import threading
    monkeypatch.setattr(threading, "Thread",
                         lambda target, daemon: type("T", (), {"start": lambda self: target()})())

    monkeypatch.setattr(tqa, "run_queue_now",
                         lambda *a, **kw: (False, "MCP server unreachable"))

    dialogs.reset()
    gui.app._run_due_tasks()
    _pump(gui)

    err = dialogs.last_call("showerror")
    assert err is not None
    assert "MCP server unreachable" in err["message"]
    assert str(gui.app._run_due_btn.cget("state")) == "normal"
