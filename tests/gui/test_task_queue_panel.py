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
import tkinter as tk
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
    # v8.1.6: same isolation requirement for the new OAuth-token files —
    # without this, tests would read/write the REAL
    # ~/.ai-prowler/claude_oauth_token.json on the machine running them.
    monkeypatch.setattr(tqa, "OAUTH_TOKEN_PATH", tmp_path / ".ai-prowler" / "claude_oauth_token.json")
    monkeypatch.setattr(tqa, "OAUTH_TOKEN_PLAIN_PATH", tmp_path / ".ai-prowler" / "claude_oauth_token.txt")
    monkeypatch.setattr(tqa, "SETUP_TOKEN_OUTPUT_PATH", tmp_path / ".ai-prowler" / "setup_token_output.txt")
    monkeypatch.setattr(tqa, "SETUP_TOKEN_BAT_PATH", tmp_path / ".ai-prowler" / "run_setup_token.bat")
    # v8.1.6: same isolation requirement for custom_tasks_manager's own
    # builtin-analysis settings file — computed at import time, so it
    # would otherwise point at the REAL ~/.ai-prowler/ on this machine.
    import custom_tasks_manager as _ctm_isolate
    monkeypatch.setattr(_ctm_isolate, "BUILTIN_ANALYSIS_CONFIG_PATH",
                         tmp_path / ".ai-prowler" / "builtin_analysis_config.json")
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


# ── v8.1.6: auth-method visibility toggle ───────────────────────────────────
# Only the API-key row + its buttons (Save Key / Clear Key) should be visible
# when API Key is selected; only Get / Renew Token should be visible when
# Subscription (OAuth) is selected. Previously both were always shown
# together regardless of selection, which is exactly the "which field goes
# with which option" confusion this was meant to fix.

def test_oauth_selected_hides_api_key_row_and_shows_get_token(gui):
    gui.app._tqa_auth_var.set("oauth")
    _pump(gui)
    assert not gui.app._tqa_row4.winfo_ismapped()
    assert gui.app._tqa_btn_get_token.winfo_ismapped()
    assert not gui.app._tqa_btn_get_api_key.winfo_ismapped()


def test_api_key_selected_shows_api_key_row_and_hides_get_token(gui):
    gui.app._tqa_auth_var.set("api_key")
    _pump(gui)
    assert gui.app._tqa_row4.winfo_ismapped()
    assert not gui.app._tqa_btn_get_token.winfo_ismapped()
    assert gui.app._tqa_btn_get_api_key.winfo_ismapped()


def test_hint_text_changes_with_auth_selection(gui):
    gui.app._tqa_auth_var.set("oauth")
    _pump(gui)
    oauth_hint = gui.app._tqa_hint_var.get()
    assert "Get / Renew Token" in oauth_hint

    gui.app._tqa_auth_var.set("api_key")
    _pump(gui)
    api_key_hint = gui.app._tqa_hint_var.get()
    assert "console.anthropic.com" in api_key_hint
    assert api_key_hint != oauth_hint


# ── v8.1.6: Clear Key button ─────────────────────────────────────────────────
# Previously there was no way to actually delete a saved API key —
# _tqa_save_api_key() refuses to save an empty value, so a mistakenly saved
# key had no path to removal.

def test_clear_api_key_removes_saved_key(gui, dialogs):
    tqa.save_api_key("sk-ant-api03-fake-key-value")
    assert tqa.has_api_key() is True

    dialogs.set_response("askyesno", True)
    dialogs.reset()
    gui.app._tqa_clear_api_key()
    _pump(gui)

    assert tqa.has_api_key() is False
    assert gui.app._tqa_apikey_var.get() == ""
    assert dialogs.last_call("showinfo") is not None


def test_clear_api_key_respects_cancel(gui, dialogs):
    tqa.save_api_key("sk-ant-api03-fake-key-value")
    dialogs.set_response("askyesno", False)
    gui.app._tqa_clear_api_key()
    _pump(gui)
    # Declining the confirmation must leave the saved key untouched.
    assert tqa.has_api_key() is True


def test_clear_api_key_when_nothing_saved_shows_info_not_confirm(gui, dialogs):
    assert tqa.has_api_key() is False
    dialogs.reset()
    gui.app._tqa_clear_api_key()
    _pump(gui)
    # Nothing to clear — should short-circuit before ever asking for
    # confirmation, and tell the user via showinfo instead.
    assert dialogs.last_call("askyesno") is None
    assert dialogs.last_call("showinfo") is not None


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


# v8.1.6: the "Run Due Tasks" button and its tests were removed here —
# see the removal comment in rag_gui.py where the button used to sit
# (My Custom Analyses panel, next to + New Custom Analysis) for the
# rationale: it's redundant now that the Autonomous Task Queue runs the
# whole pending queue on its own schedule once enabled.


# ── Panel pack order: Autonomous Task Queue -> Show Queue -> Common ────────
# Business AI Analysis. Regression test for the after=_tqa_banner anchoring
# — using before=_analysis_banner on two separate widgets would have had
# ambiguous/order-dependent results in Tk's pack manager.

def test_pack_order_tqa_then_queue_then_analysis(gui):
    _pump(gui)
    siblings = gui.app._tqa_banner.master.pack_slaves()
    assert siblings.index(gui.app._tqa_banner) < siblings.index(gui.app._queue_outer)
    assert siblings.index(gui.app._queue_outer) < siblings.index(gui.app._analysis_banner)


# ── Common Business AI Analysis: full-row redesign ──────────────────────────
# v8.1.6: replaced the 2-column grid of big colored buttons (which opened a
# popup on every click) with full-width rows matching My Custom Analyses'
# own layout — ▶ NOW / ▶ Queue / ✎ Edit per row, no trash (fixed, not
# user-deletable). Settings persist via custom_tasks_manager's new
# get/save_builtin_analysis_settings() so Queue/NOW don't need the popup.

def test_analysis_rows_rendered_for_every_task(gui):
    _pump(gui)
    rows = gui.app._an_list_frame.winfo_children()
    assert len(rows) == len(gui.app._ANALYSIS_TASKS)


def test_build_builtin_prompt_injects_scope_and_output(gui):
    task_def = {"prompt": "Analyze my business."}
    settings = {
        "scope_dirs": ["C:\\Jobs", "C:\\Invoices"],
        "output_learnings": True,
        "output_report": True,
        "report_folder": "C:\\Reports",
    }
    prompt = gui.app._build_builtin_prompt(task_def, settings)
    assert "Analyze my business." in prompt
    assert "C:\\Jobs" in prompt and "C:\\Invoices" in prompt
    assert "record_learning" in prompt
    assert "save_analysis_report" in prompt
    assert "C:\\Reports" in prompt


def test_build_builtin_prompt_omits_sections_when_disabled(gui):
    task_def = {"prompt": "Analyze my business."}
    settings = {"scope_dirs": [], "output_learnings": False, "output_report": False}
    prompt = gui.app._build_builtin_prompt(task_def, settings)
    assert "Scope restriction" not in prompt
    assert "record_learning" not in prompt
    assert "save_analysis_report" not in prompt


def test_queue_task_row_writes_pending_entry_with_saved_settings(gui):
    import custom_tasks_manager as ctm
    ctm.save_builtin_analysis_settings("analyze_business", {
        "scope_dirs": ["C:\\Jobs"],
        "output_learnings": True,
        "output_report": True,
        "report_folder": "C:\\Reports",
        "schedule": "none",
        "first_due": None,
    })
    task_def = next(t for t in gui.app._ANALYSIS_TASKS if t["type"] == "analyze_business")
    gui.app._queue_task_row(task_def)
    _pump(gui)

    p = tqa.AI_PROWLER_HOME / "pending_tasks.json"
    assert p.exists()
    entries = json.loads(p.read_text(encoding="utf-8"))
    matching = [e for e in entries if e.get("type") == "analyze_business"]
    assert len(matching) == 1
    assert "C:\\Jobs" in matching[0]["prompt"]
    assert "record_learning" in matching[0]["prompt"]
    assert "save_analysis_report" in matching[0]["prompt"]
    assert matching[0]["status"] == "pending"


def test_queue_task_row_uses_defaults_when_never_configured(gui):
    """An analysis that was never Edited (no saved settings) should still
    queue successfully using sensible defaults, not error out."""
    task_def = next(t for t in gui.app._ANALYSIS_TASKS if t["type"] == "find_problems")
    ok, err = gui.app._queue_builtin_task(task_def)
    assert ok is True
    assert err is None


def test_edit_settings_persist_across_reopen(gui):
    import custom_tasks_manager as ctm
    ctm.save_builtin_analysis_settings("find_problems", {
        "scope_dirs": [],
        "output_learnings": False,
        "output_report": True,
        "report_folder": "C:\\CustomReports",
        "schedule": "weekly",
        "first_due": "2026-08-01",
    })
    settings = ctm.get_builtin_analysis_settings("find_problems")
    assert settings["output_learnings"] is False
    assert settings["output_report"] is True
    assert settings["report_folder"] == "C:\\CustomReports"
    assert settings["schedule"] == "weekly"
    assert settings["first_due"] == "2026-08-01"


def test_run_analysis_now_uses_saved_settings_not_raw_prompt(gui, monkeypatch):
    """v8.1.6 regression test: ▶ NOW previously used the raw unenriched
    task prompt, silently ignoring any saved scope/output settings. Now it
    must build the SAME enriched prompt ▶ Queue would use."""
    import custom_tasks_manager as ctm
    ctm.save_builtin_analysis_settings("growth_opportunities", {
        "scope_dirs": ["C:\\Data"],
        "output_learnings": True,
        "output_report": False,
        "report_folder": ctm.DEFAULT_REPORT_FOLDER,
        "schedule": "none",
        "first_due": None,
    })
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)
    monkeypatch.setattr(tqa, "load_config", lambda: {
        "mcp_config_path": "x.json",
        "allowed_tools": "mcp__ai-prowler__*",
        "use_api_key": False})

    captured = {}
    def _fake_run_single_prompt_now(prompt, *a, **kw):
        captured["prompt"] = prompt
        return True, "done"
    monkeypatch.setattr(tqa, "run_single_prompt_now", _fake_run_single_prompt_now)
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: True)

    # Run the background thread synchronously, same pattern the old
    # Run Due Tasks tests used — threading.Thread is the same stdlib
    # singleton rag_gui.py itself imports.
    import threading
    monkeypatch.setattr(threading, "Thread",
                         lambda target, daemon: type("T", (), {"start": lambda self: target()})())

    task_def = next(t for t in gui.app._ANALYSIS_TASKS if t["type"] == "growth_opportunities")
    now_btn = tk.Button(gui.root, text="▶ NOW")
    gui.app._run_analysis_now(task_def, now_btn)
    _pump(gui)

    assert "prompt" in captured
    assert "C:\\Data" in captured["prompt"]
    now_btn.destroy()


def test_run_analysis_now_blocked_without_cli(gui, monkeypatch, dialogs):
    monkeypatch.setattr(tqa, "claude_code_cli_installed", lambda: False)
    run_calls = []
    monkeypatch.setattr(tqa, "run_single_prompt_now", lambda *a, **kw: run_calls.append(1))
    dialogs.reset()

    task_def = next(t for t in gui.app._ANALYSIS_TASKS if t["type"] == "analyze_business")
    now_btn = tk.Button(gui.root, text="▶ NOW")
    gui.app._run_analysis_now(task_def, now_btn)
    _pump(gui)

    assert len(run_calls) == 0
    assert dialogs.last_call("showwarning") is not None
    now_btn.destroy()


# ── v8.3: color-coded ON/OFF toggle button — replaces checkbox + status dot ─
#
# History on this one control:
#   1. The original "✅ Enable Autonomous Task Queue" button had no way to
#      turn automation back off at all.
#   2. v8.2.0's label-flip attempt had the mapping backwards and the click
#      handler never actually toggled anything itself.
#   3. v8.2.2 fixed both of those (real toggle, real label), using a
#      checkbox + a text-only ttk.Button.
#   4. v8.3 (this version) replaces the checkbox AND the "● Enabled/
#      Disabled" status dot with a single big color-coded tk.Button: solid
#      red reading "Autonomous AI Task Queue OFF" when disabled, solid
#      green reading "Autonomous AI Task Queue ON" when enabled, with
#      "Toggle On/Off" as a first line inside the button. One widget now
#      both shows the state and is the control that changes it.
#
# The checkbox is gone, so tests that used to drive it via
# gui.app._tqa_checkbox_enable.invoke() now drive the button itself via
# gui.app._tqa_btn_enable.invoke() instead — tk.Button supports the same
# .invoke() as tk.Checkbutton did, firing its `command` exactly like a
# real click.

def test_enable_button_initial_state_is_red_off(gui):
    _pump(gui)
    assert gui.app._tqa_cfg.get("enabled", False) is False
    assert gui.app._tqa_btn_enable.cget("text") == "Toggle On/Off\nAutonomous AI Task Queue OFF"
    assert gui.app._tqa_btn_enable.cget("bg") == "#7a1f1f"
    assert gui.app._tqa_btn_enable.cget("fg") == "#ffffff"


def test_toggle_enabled_turns_on_installs_task_and_turns_button_green(gui, monkeypatch):
    install_calls = []
    monkeypatch.setattr(tqa, "install_scheduled_task",
                         lambda *a, **kw: (install_calls.append(a), (True, "ok"))[1])
    monkeypatch.setattr(tqa, "install_wrapper_script",
                         lambda *a, **kw: Path("fake_wrapper.bat"))
    gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)

    gui.app._tqa_toggle_enabled()
    _pump(gui)

    assert len(install_calls) == 1
    assert tqa.load_config()["enabled"] is True
    assert gui.app._tqa_btn_enable.cget("text") == "Toggle On/Off\nAutonomous AI Task Queue ON"
    assert gui.app._tqa_btn_enable.cget("bg") == "#1f7a3d"
    assert gui.app._tqa_btn_enable.cget("fg") == "#ffffff"


def test_toggle_enabled_turns_off_uninstalls_task_and_turns_button_red(gui, monkeypatch):
    monkeypatch.setattr(tqa, "install_scheduled_task", lambda *a, **kw: (True, "ok"))
    monkeypatch.setattr(tqa, "install_wrapper_script", lambda *a, **kw: Path("fake_wrapper.bat"))
    gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)
    gui.app._tqa_toggle_enabled()
    _pump(gui)
    assert tqa.load_config()["enabled"] is True

    uninstall_calls = []
    monkeypatch.setattr(tqa, "uninstall_scheduled_task",
                         lambda: (uninstall_calls.append(1), (True, "removed"))[1])

    gui.app._tqa_toggle_enabled()
    _pump(gui)

    assert len(uninstall_calls) == 1
    assert tqa.load_config()["enabled"] is False
    assert gui.app._tqa_btn_enable.cget("text") == "Toggle On/Off\nAutonomous AI Task Queue OFF"
    assert gui.app._tqa_btn_enable.cget("bg") == "#7a1f1f"


def test_toggle_enabled_repeated_clicks_cycle_correctly(gui, monkeypatch):
    """Regression for the EXACT reported symptom: clicking the same button
    repeatedly must actually alternate on/off every time, never get stuck
    showing the same label/color or applying the same state twice."""
    install_calls = []
    uninstall_calls = []
    monkeypatch.setattr(tqa, "install_scheduled_task",
                         lambda *a, **kw: (install_calls.append(1), (True, "ok"))[1])
    monkeypatch.setattr(tqa, "install_wrapper_script",
                         lambda *a, **kw: Path("fake_wrapper.bat"))
    monkeypatch.setattr(tqa, "uninstall_scheduled_task",
                         lambda: (uninstall_calls.append(1), (True, "removed"))[1])
    gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)

    expected = [
        (True,  "Toggle On/Off\nAutonomous AI Task Queue ON",  "#1f7a3d"),
        (False, "Toggle On/Off\nAutonomous AI Task Queue OFF", "#7a1f1f"),
        (True,  "Toggle On/Off\nAutonomous AI Task Queue ON",  "#1f7a3d"),
        (False, "Toggle On/Off\nAutonomous AI Task Queue OFF", "#7a1f1f"),
    ]
    for enabled_expected, label_expected, bg_expected in expected:
        gui.app._tqa_toggle_enabled()
        _pump(gui)
        assert tqa.load_config()["enabled"] is enabled_expected
        assert gui.app._tqa_btn_enable.cget("text") == label_expected
        assert gui.app._tqa_btn_enable.cget("bg") == bg_expected

    assert len(install_calls) == 2
    assert len(uninstall_calls) == 2


def test_button_widget_invoke_applies_immediately_like_a_real_click(gui, monkeypatch):
    """Drives the REAL tk.Button via .invoke() — the same call Tkinter
    makes internally on an actual mouse click — rather than calling the
    Python function directly, so this exercises the widget wiring itself,
    not just the underlying logic."""
    install_calls = []
    uninstall_calls = []
    monkeypatch.setattr(tqa, "install_scheduled_task",
                         lambda *a, **kw: (install_calls.append(1), (True, "ok"))[1])
    monkeypatch.setattr(tqa, "install_wrapper_script",
                         lambda *a, **kw: Path("fake_wrapper.bat"))
    monkeypatch.setattr(tqa, "uninstall_scheduled_task",
                         lambda: (uninstall_calls.append(1), (True, "removed"))[1])
    gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)

    gui.app._tqa_btn_enable.invoke()
    _pump(gui)
    assert tqa.load_config()["enabled"] is True
    assert len(install_calls) == 1
    assert gui.app._tqa_btn_enable.cget("bg") == "#1f7a3d"

    gui.app._tqa_btn_enable.invoke()
    _pump(gui)
    assert tqa.load_config()["enabled"] is False
    assert len(uninstall_calls) == 1
    assert gui.app._tqa_btn_enable.cget("bg") == "#7a1f1f"


def test_button_label_does_not_react_to_unsaved_var_edits(gui):
    """Pins down the actual root cause of the v8.2.0 regression: the
    label/color must track the REAL applied state (_tqa_cfg), never the
    raw _tqa_enabled_var on its own. Setting the var directly — without
    going through toggle/apply — must NOT change the button."""
    assert gui.app._tqa_cfg.get("enabled", False) is False
    before_text = gui.app._tqa_btn_enable.cget("text")
    before_bg = gui.app._tqa_btn_enable.cget("bg")
    assert before_text == "Toggle On/Off\nAutonomous AI Task Queue OFF"
    assert before_bg == "#7a1f1f"

    gui.app._tqa_enabled_var.set(True)
    _pump(gui)

    assert gui.app._tqa_btn_enable.cget("text") == before_text
    assert gui.app._tqa_btn_enable.cget("bg") == before_bg


def test_toggle_enabled_when_disabling_does_not_require_mcp_config(gui, monkeypatch):
    """Disabling must always succeed even with no MCP config path set —
    only ENABLING has that dependency (see
    test_save_enabled_without_mcp_config_warns_and_does_not_install)."""
    uninstall_calls = []
    monkeypatch.setattr(tqa, "uninstall_scheduled_task",
                         lambda: (uninstall_calls.append(1), (True, "not present"))[1])
    gui.app._tqa_cfg["enabled"] = True
    gui.app._tqa_enabled_var.set(True)
    gui.app._tqa_update_enable_btn_label()

    gui.app._tqa_toggle_enabled()
    _pump(gui)

    assert len(uninstall_calls) == 1
    assert tqa.load_config()["enabled"] is False
    assert gui.app._tqa_btn_enable.cget("text") == "Toggle On/Off\nAutonomous AI Task Queue OFF"
    assert gui.app._tqa_btn_enable.cget("bg") == "#7a1f1f"


def test_status_dot_no_longer_shown_next_to_header(gui):
    """v8.3: the "● Enabled/Disabled" status dot is redundant with the
    color-coded button now and should no longer be visible, even though
    the underlying StringVar/widget are kept alive internally."""
    _pump(gui)
    assert not gui.app._tqa_status_lbl.winfo_ismapped()


# ── v8.2.0 / v8.2.2: renamed section headers + explanatory notes ───────────
# "🤖 Autonomous Task Queue" -> "🤖 Autonomous AI Task Queue" and
# "📋 My Custom Analyses" -> "📋 My Custom AI Analyses", each with a note
# explaining the AI-assisted / MCP-remote-management angle. These are
# static tk.Label widgets with no backing StringVar, so tests walk the
# real widget tree rather than reading an exposed variable — this proves
# the copy Windows actually renders, not just a string constant somewhere
# in the source.

def _all_label_texts(widget) -> list[str]:
    texts: list[str] = []
    try:
        if isinstance(widget, tk.Label):
            texts.append(widget.cget("text"))
    except tk.TclError:
        pass
    for child in widget.winfo_children():
        texts.extend(_all_label_texts(child))
    return texts


def _joined_label_text(widget) -> str:
    return " ".join(_all_label_texts(widget))


def test_autonomous_ai_task_queue_header_and_note_rendered(gui):
    _pump(gui)
    text = _joined_label_text(gui.app._tqa_banner)
    assert "Autonomous AI Task Queue" in text
    assert "🤖  Autonomous Task Queue" not in text  # old un-renamed header must be gone
    assert "AI-assisted tasks that can be queued and stored" in text
    assert "repeated and/or future execution" in text
    assert "Claude AI has tools to manage" in text
    assert "AI-Prowler MCP tools remotely" in text


def test_my_custom_ai_analyses_header_and_note_rendered(gui):
    _pump(gui)
    container = gui.app._custom_list_frame.master  # = _custom_outer
    text = _joined_label_text(container)
    assert "My Custom AI Analyses" in text
    assert "📋  My Custom Analyses" not in text  # old un-renamed header must be gone
    assert "user custom-defined tasks are AI-assisted tasks" in text
    assert "Claude can also create and add these via AI-Prowler MCP tools remotely" in text
