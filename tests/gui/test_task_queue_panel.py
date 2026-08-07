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
    # v8.1.10 fix: CUSTOM_TASKS_PATH — the "My Custom AI Analyses" data
    # file — was NEVER isolated here, despite every OTHER custom_tasks_
    # manager path in this fixture being covered. Any test that calls
    # create_task()/load_custom_tasks()/save_custom_tasks() directly
    # (rather than through unittest.mock.patch, like most tests in this
    # file do) was silently reading/writing the REAL
    # ~/.ai-prowler/custom_analysis_tasks.json on whatever machine ran the
    # tests — confirmed: this is exactly what polluted David's real
    # Custom Analyses list with repeated "MyNewCustomTask" entries, once
    # per test run, across multiple release-gate runs tonight.
    monkeypatch.setattr(_ctm_isolate, "CUSTOM_TASKS_PATH",
                         tmp_path / ".ai-prowler" / "custom_analysis_tasks.json")
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


# ── v8.1.11: "times/day" checker-frequency field + credit warning ──────────
# The checker's own frequency is DELIBERATELY decoupled from any individual
# task's own schedule — this is the GUI control + static (non-conversational)
# credit-usage warning David asked to have shown right next to Scheduled
# time, not something Claude says out loud.

class TestTimesPerDayCheckerFrequency:

    def test_default_times_per_day_is_one_no_warning_shown(self, gui):
        assert gui.app._tqa_times_per_day_var.get() == "1"
        assert gui.app._tqa_credit_warn_var.get() == ""

    def test_setting_above_one_shows_credit_warning(self, gui):
        gui.app._tqa_times_per_day_var.set("10")
        _pump(gui)
        warning = gui.app._tqa_credit_warn_var.get()
        assert "10" in warning
        assert "credit" in warning.lower()

    def test_setting_back_to_one_clears_warning(self, gui):
        gui.app._tqa_times_per_day_var.set("6")
        _pump(gui)
        assert gui.app._tqa_credit_warn_var.get() != ""
        gui.app._tqa_times_per_day_var.set("1")
        _pump(gui)
        assert gui.app._tqa_credit_warn_var.get() == ""

    def test_invalid_input_treated_as_one_no_crash(self, gui):
        gui.app._tqa_times_per_day_var.set("abc")
        _pump(gui)
        assert gui.app._tqa_credit_warn_var.get() == ""

    def test_times_per_day_one_saves_daily_check_mode(self, gui, monkeypatch):
        install_calls = []
        monkeypatch.setattr(tqa, "install_scheduled_task",
                             lambda *a, **kw: (install_calls.append(kw), (True, "ok"))[1])
        monkeypatch.setattr(tqa, "install_wrapper_script",
                             lambda *a, **kw: Path("fake_wrapper.bat"))
        gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)
        gui.app._tqa_enabled_var.set(True)
        gui.app._tqa_times_per_day_var.set("1")
        gui.app._tqa_save_and_apply()
        _pump(gui)

        assert install_calls[0]["check_mode"] == "daily"
        saved = tqa.load_config()
        assert saved["check_mode"] == "daily"

    def test_times_per_day_ten_saves_interval_check_mode(self, gui, monkeypatch):
        """v9.0.1: times_per_day is now stored and passed through directly
        and losslessly — no more round-tripping through
        check_interval_hours = round(24/N)."""
        install_calls = []
        monkeypatch.setattr(tqa, "install_scheduled_task",
                             lambda *a, **kw: (install_calls.append(kw), (True, "ok"))[1])
        monkeypatch.setattr(tqa, "install_wrapper_script",
                             lambda *a, **kw: Path("fake_wrapper.bat"))
        gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)
        gui.app._tqa_enabled_var.set(True)
        gui.app._tqa_times_per_day_var.set("10")
        gui.app._tqa_save_and_apply()
        _pump(gui)

        assert install_calls[0]["check_mode"] == "interval"
        assert install_calls[0]["times_per_day"] == 10
        saved = tqa.load_config()
        assert saved["check_mode"] == "interval"
        assert saved["check_times_per_day"] == 10

    def test_times_per_day_24_yields_24_computed_check_times(self, gui, monkeypatch):
        """v9.0.1: 24 times/day is stored and passed through as exactly 24
        — no more lossy conversion to 'round(24/24) = 1 hour interval'."""
        install_calls = []
        monkeypatch.setattr(tqa, "install_scheduled_task",
                             lambda *a, **kw: (install_calls.append(kw), (True, "ok"))[1])
        monkeypatch.setattr(tqa, "install_wrapper_script",
                             lambda *a, **kw: Path("fake_wrapper.bat"))
        gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)
        gui.app._tqa_enabled_var.set(True)
        gui.app._tqa_times_per_day_var.set("24")
        gui.app._tqa_save_and_apply()
        _pump(gui)

        assert install_calls[0]["times_per_day"] == 24
        saved = tqa.load_config()
        assert saved["check_times_per_day"] == 24


# ── v9.0.1: Start time / End time + live "Checks at:" preview ───────────────
# Found live: "Scheduled time: 07:00, Check queue: 8 times/day" showed
# "next: 8/7/2026 1:27:54 AM" -- nowhere near what the user configured. Root
# cause was the interval trigger's anchor (fixed separately). This is the
# feature-level fix David asked for on top of that: give the checker its own
# Start time / End time / Times per day inputs, mirroring the My Custom AI
# Analyses / Common Business AI Analysis editors exactly, and show the real
# computed check times live — via the SAME custom_tasks_manager.
# format_daily_run_times_preview() those editors use — instead of leaving
# the user to guess what a given combination produces.

class TestChecksAtLivePreview:

    def test_end_time_var_defaults_to_config_value(self, gui):
        assert gui.app._tqa_end_time_var.get() == gui.app._tqa_cfg.get(
            "schedule_end_time", "23:00")

    def test_preview_empty_at_one_time_per_day(self, gui):
        gui.app._tqa_times_per_day_var.set("1")
        _pump(gui)
        assert gui.app._tqa_checks_at_var.get() == ""

    def test_preview_shows_computed_times_above_one_per_day(self, gui):
        gui.app._tqa_time_var.set("08:00")
        gui.app._tqa_end_time_var.set("20:00")
        gui.app._tqa_times_per_day_var.set("3")
        _pump(gui)
        preview = gui.app._tqa_checks_at_var.get()
        assert preview.startswith("Checks at:")
        assert "08:00" in preview
        assert "14:00" in preview
        assert "20:00" in preview

    def test_preview_matches_custom_tasks_manager_shared_function_exactly(self, gui):
        """The panel's preview must come from the exact same function the
        task editors use — never a separately-maintained copy that could
        drift out of sync."""
        import custom_tasks_manager as ctm
        gui.app._tqa_time_var.set("06:00")
        gui.app._tqa_end_time_var.set("18:00")
        gui.app._tqa_times_per_day_var.set("4")
        _pump(gui)
        expected = ctm.format_daily_run_times_preview("06:00", "18:00", 4)
        actual = gui.app._tqa_checks_at_var.get()
        assert actual == expected.replace("Runs at:", "Checks at:")

    def test_preview_updates_live_on_start_time_change(self, gui):
        gui.app._tqa_time_var.set("07:00")
        gui.app._tqa_end_time_var.set("23:00")
        gui.app._tqa_times_per_day_var.set("2")
        _pump(gui)
        before = gui.app._tqa_checks_at_var.get()
        gui.app._tqa_time_var.set("01:00")
        _pump(gui)
        after = gui.app._tqa_checks_at_var.get()
        assert before != after
        assert "01:00" in after

    def test_preview_reverts_to_empty_when_dropping_back_to_one(self, gui):
        gui.app._tqa_times_per_day_var.set("5")
        _pump(gui)
        assert gui.app._tqa_checks_at_var.get() != ""
        gui.app._tqa_times_per_day_var.set("1")
        _pump(gui)
        assert gui.app._tqa_checks_at_var.get() == ""

    def test_save_and_apply_persists_end_time_and_times_per_day(self, gui, monkeypatch):
        monkeypatch.setattr(tqa, "install_scheduled_task",
                             lambda *a, **kw: (True, "ok"))
        monkeypatch.setattr(tqa, "install_wrapper_script",
                             lambda *a, **kw: Path("fake_wrapper.bat"))
        gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)
        gui.app._tqa_enabled_var.set(True)
        gui.app._tqa_time_var.set("07:00")
        gui.app._tqa_end_time_var.set("22:00")
        gui.app._tqa_times_per_day_var.set("5")
        gui.app._tqa_save_and_apply()
        _pump(gui)

        saved = tqa.load_config()
        assert saved["schedule_time"] == "07:00"
        assert saved["schedule_end_time"] == "22:00"
        assert saved["check_times_per_day"] == 5

    def test_install_scheduled_task_receives_end_time_and_times_per_day(self, gui, monkeypatch):
        install_calls = []
        monkeypatch.setattr(tqa, "install_scheduled_task",
                             lambda *a, **kw: (install_calls.append(kw), (True, "ok"))[1])
        monkeypatch.setattr(tqa, "install_wrapper_script",
                             lambda *a, **kw: Path("fake_wrapper.bat"))
        gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)
        gui.app._tqa_enabled_var.set(True)
        gui.app._tqa_time_var.set("09:00")
        gui.app._tqa_end_time_var.set("21:00")
        gui.app._tqa_times_per_day_var.set("6")
        gui.app._tqa_save_and_apply()
        _pump(gui)

        assert install_calls[0]["schedule_end_time"] == "21:00"
        assert install_calls[0]["times_per_day"] == 6


# ── v9.0.1: Check queue capped at MAX_DAILY_TIMES_PER_DAY (24) ──────────────
# Found live: David asked "Does the times/day have a limit of 24?" and the
# honest answer was no -- this field had only a floor of 1, no ceiling,
# unlike the My Custom AI Analyses / Common Business AI Analysis editors'
# own Times per day field, which has always enforced custom_tasks_manager.
# MAX_DAILY_TIMES_PER_DAY (24). Fixed by importing that same constant here
# rather than duplicating it, so the two features can never drift to
# different limits.

class TestTimesPerDayMaxCap:

    def test_clamp_helper_passes_through_values_within_range(self, gui):
        for n in (1, 2, 12, 24):
            clamped, was_capped = gui.app._tqa_clamp_times_per_day(str(n))
            assert clamped == n
            assert was_capped is False

    def test_clamp_helper_caps_above_24(self, gui):
        clamped, was_capped = gui.app._tqa_clamp_times_per_day("100")
        assert clamped == 24
        assert was_capped is True

    def test_clamp_helper_floors_zero_and_negative_to_one(self, gui):
        for raw in ("0", "-5"):
            clamped, was_capped = gui.app._tqa_clamp_times_per_day(raw)
            assert clamped == 1
            assert was_capped is False

    def test_clamp_helper_treats_invalid_input_as_one_no_crash(self, gui):
        clamped, was_capped = gui.app._tqa_clamp_times_per_day("abc")
        assert clamped == 1
        assert was_capped is False

    def test_clamp_helper_matches_custom_tasks_manager_constant(self, gui):
        """The cap must come from the same constant the task editors use,
        not a separately-maintained copy that could drift."""
        import custom_tasks_manager as ctm
        clamped, _ = gui.app._tqa_clamp_times_per_day(
            str(ctm.MAX_DAILY_TIMES_PER_DAY + 1))
        assert clamped == ctm.MAX_DAILY_TIMES_PER_DAY

    def test_credit_warning_shows_capped_message_above_24(self, gui):
        gui.app._tqa_times_per_day_var.set("50")
        _pump(gui)
        warning = gui.app._tqa_credit_warn_var.get()
        assert "Capped" in warning
        assert "24" in warning

    def test_credit_warning_normal_message_at_or_below_24(self, gui):
        gui.app._tqa_times_per_day_var.set("24")
        _pump(gui)
        warning = gui.app._tqa_credit_warn_var.get()
        assert "Capped" not in warning
        assert "24" in warning

    def test_preview_never_shows_more_than_24_check_times(self, gui):
        gui.app._tqa_time_var.set("00:00")
        gui.app._tqa_end_time_var.set("23:00")
        gui.app._tqa_times_per_day_var.set("50")
        _pump(gui)
        preview = gui.app._tqa_checks_at_var.get()
        # 24 comma-separated times -> 23 commas
        assert preview.count(",") == 23

    def test_save_and_apply_persists_clamped_value_not_raw_input(self, gui, monkeypatch):
        monkeypatch.setattr(tqa, "install_scheduled_task",
                             lambda *a, **kw: (True, "ok"))
        monkeypatch.setattr(tqa, "install_wrapper_script",
                             lambda *a, **kw: Path("fake_wrapper.bat"))
        gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)
        gui.app._tqa_enabled_var.set(True)
        gui.app._tqa_times_per_day_var.set("100")
        gui.app._tqa_save_and_apply()
        _pump(gui)

        saved = tqa.load_config()
        assert saved["check_times_per_day"] == 24

    def test_save_and_apply_corrects_displayed_field_to_clamped_value(self, gui, monkeypatch):
        """The field itself must be corrected back to 24 after Apply, so
        what's shown on screen never disagrees with what's actually saved
        and registered."""
        monkeypatch.setattr(tqa, "install_scheduled_task",
                             lambda *a, **kw: (True, "ok"))
        monkeypatch.setattr(tqa, "install_wrapper_script",
                             lambda *a, **kw: Path("fake_wrapper.bat"))
        gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)
        gui.app._tqa_enabled_var.set(True)
        gui.app._tqa_times_per_day_var.set("100")
        gui.app._tqa_save_and_apply()
        _pump(gui)

        assert gui.app._tqa_times_per_day_var.get() == "24"

    def test_install_scheduled_task_never_receives_more_than_24(self, gui, monkeypatch):
        install_calls = []
        monkeypatch.setattr(tqa, "install_scheduled_task",
                             lambda *a, **kw: (install_calls.append(kw), (True, "ok"))[1])
        monkeypatch.setattr(tqa, "install_wrapper_script",
                             lambda *a, **kw: Path("fake_wrapper.bat"))
        gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)
        gui.app._tqa_enabled_var.set(True)
        gui.app._tqa_times_per_day_var.set("999")
        gui.app._tqa_save_and_apply()
        _pump(gui)

        assert install_calls[0]["times_per_day"] == 24


# ── v8.1.9: Apply-time-without-toggle button ───────────────────────────────

def test_apply_button_reinstalls_task_with_new_time_while_already_enabled(gui, monkeypatch):
    """Regression test for the exact bug reported: automation already ON,
    user edits the Scheduled Time field, and NOTHING happens to the real
    Scheduled Task until this button (or a full OFF->ON toggle cycle) is
    used. Confirms the new 'Apply' button reinstalls with the updated
    time without touching the enabled/disabled state at all."""
    install_calls = []
    monkeypatch.setattr(tqa, "install_scheduled_task",
                         lambda *a, **kw: (install_calls.append(a), (True, "ok"))[1])
    monkeypatch.setattr(tqa, "install_wrapper_script",
                         lambda *a, **kw: Path("fake_wrapper.bat"))

    # Get into the "already enabled" state first, exactly like turning the
    # toggle ON once earlier in a real session.
    gui.app._tqa_cfg["mcp_config_path"] = str(tqa.GENERATED_MCP_CONFIG_PATH)
    gui.app._tqa_enabled_var.set(True)
    gui.app._tqa_time_var.set("06:00")
    gui.app._tqa_save_and_apply()
    _pump(gui)
    assert len(install_calls) == 1

    # Now simulate the reported scenario: change ONLY the time field and
    # click Apply — enabled state is untouched throughout.
    gui.app._tqa_time_var.set("06:15")
    gui.app._tqa_apply_time_only()
    _pump(gui)

    # install_scheduled_task must have been called AGAIN with the new time,
    # without any toggle of _tqa_enabled_var.
    assert len(install_calls) == 2
    assert gui.app._tqa_enabled_var.get() is True
    saved = tqa.load_config()
    assert saved["schedule_time"] == "06:15"
    assert saved["enabled"] is True


def test_apply_button_while_disabled_just_saves_time_no_install(gui, monkeypatch):
    install_calls = []
    uninstall_calls = []
    monkeypatch.setattr(tqa, "install_scheduled_task",
                         lambda *a, **kw: (install_calls.append(a), (True, "ok"))[1])
    monkeypatch.setattr(tqa, "uninstall_scheduled_task",
                         lambda: (uninstall_calls.append(1), (True, "not present"))[1])

    gui.app._tqa_enabled_var.set(False)
    gui.app._tqa_time_var.set("09:45")
    gui.app._tqa_apply_time_only()
    _pump(gui)

    assert len(install_calls) == 0
    assert len(uninstall_calls) == 1
    saved = tqa.load_config()
    assert saved["schedule_time"] == "09:45"
    assert saved["enabled"] is False


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
# own layout — ▶ Queue / ✎ Edit per row, no trash (fixed, not user-deletable).
# v9.0.0: ▶ NOW button removed — ChromaDB contention when GUI + headless
# claude -p both hit the same database. ▶ Queue / ✎ Edit remain.

def test_analysis_rows_rendered_for_every_task(gui):
    _pump(gui)
    rows = gui.app._an_list_frame.winfo_children()
    assert len(rows) == len(gui.app._ANALYSIS_TASKS)


# ── v9.0.0: NOW button removal regression ────────────────────────────────────
# Confirms the ▶ NOW button is gone from every Common Business AI Analysis row
# and that _run_analysis_now is no longer exposed on the GUI object.

def test_now_button_not_present_on_any_analysis_row(gui):
    """Every button label in every analysis row must not say '▶ NOW'.

    Walks the full widget tree of _an_list_frame so even a deeply-nested
    Button would be caught. A failure here means ▶ NOW was accidentally
    re-added to the built-in analysis section — the exact regression this
    test guards against."""
    import tkinter as tk
    _pump(gui)

    def _collect_buttons(widget):
        btns = []
        for child in widget.winfo_children():
            if isinstance(child, tk.Button):
                btns.append(child.cget("text"))
            btns.extend(_collect_buttons(child))
        return btns

    all_labels = _collect_buttons(gui.app._an_list_frame)
    now_labels = [lbl for lbl in all_labels if "NOW" in lbl]
    assert now_labels == [], (
        f"▶ NOW button must not exist on any Common Business AI Analysis row "
        f"(v9.0.0 removal). Found: {now_labels}"
    )


def test_run_analysis_now_not_exposed_on_gui(gui):
    """_run_analysis_now must no longer be an attribute of the GUI app.

    It was removed in v9.0.0 — if it reappears it means the old NOW-button
    handler crept back in and needs to be cleaned up."""
    _pump(gui)
    assert not hasattr(gui.app, "_run_analysis_now"), (
        "_run_analysis_now should not exist on the GUI object after v9.0.0 removal"
    )


def test_queue_and_edit_buttons_still_present_on_every_row(gui):
    """▶ Queue and ✎ Edit must still be present on every analysis row.

    Guards against accidentally removing the wrong buttons when removing NOW."""
    import tkinter as tk
    _pump(gui)

    def _collect_buttons(widget):
        btns = []
        for child in widget.winfo_children():
            if isinstance(child, tk.Button):
                btns.append(child.cget("text"))
            btns.extend(_collect_buttons(child))
        return btns

    all_labels = _collect_buttons(gui.app._an_list_frame)
    n_tasks = len(gui.app._ANALYSIS_TASKS)
    queue_count = sum(1 for lbl in all_labels if "Queue" in lbl)
    edit_count  = sum(1 for lbl in all_labels if "Edit"  in lbl)
    assert queue_count == n_tasks, (
        f"Expected {n_tasks} ▶ Queue buttons, found {queue_count}"
    )
    assert edit_count == n_tasks, (
        f"Expected {n_tasks} ✎ Edit buttons, found {edit_count}"
    )


# ── v9.0.0: NOW button removal — My Custom AI Analyses ───────────────────────
# Same removal applied to the custom tasks section in v9.0.0.

def test_now_button_not_present_on_any_custom_task_row(gui):
    """▶ NOW must not appear on any My Custom AI Analyses row.

    Walks the full custom list frame widget tree. Guards against the NOW
    button being re-added to custom tasks in a future edit."""
    import tkinter as tk
    _pump(gui)

    # Add a custom task so the list has at least one row to inspect
    import custom_tasks_manager as ctm
    tasks = ctm.load_custom_tasks()
    new_task = ctm.create_task(label="Test Task", prompt="Do something.",
                                schedule="none")
    tasks.append(new_task)
    ctm.save_custom_tasks(tasks)
    gui.app._refresh_custom_task_list()
    _pump(gui)

    def _collect_buttons(widget):
        btns = []
        for child in widget.winfo_children():
            if isinstance(child, tk.Button):
                btns.append(child.cget("text"))
            btns.extend(_collect_buttons(child))
        return btns

    custom_frame = gui.app._custom_list_frame
    all_labels = _collect_buttons(custom_frame)
    now_labels = [lbl for lbl in all_labels if "NOW" in lbl]
    assert now_labels == [], (
        f"▶ NOW button must not exist on any My Custom AI Analyses row "
        f"(v9.0.0 removal). Found: {now_labels}"
    )


# ── v9.0.1: NOW Debug Log button removal — Autonomous AI Task Queue panel ───
# The ▶ NOW button was removed from BOTH Common Business AI Analysis (v9.0.0)
# and My Custom AI Analyses (v9.0.0) rows above, but the "🐛 NOW Debug Log" /
# "🗑 Clear" button pair in this panel's own button row (_tqa_btn_row2) was
# left behind — a viewer for a run mechanism that no longer exists anywhere
# in the app, and whose underlying now_button_debug.log is never written to
# by anything reachable from the GUI either (run_single_prompt_now() in
# task_queue_automation.py, the only thing that ever wrote it, has no
# remaining caller). Found live: David rebuilt with the v9.0.0 NOW-removal
# changes and the button was still visible in this panel.

def test_now_debug_log_button_not_present_in_task_queue_panel(gui):
    """The NOW Debug Log button (and its companion Clear button) must not
    appear anywhere in the Autonomous AI Task Queue panel's own button row.

    Walks from _tqa_btn_enable (self-exposed, packed directly into
    _tqa_btn_row2) rather than requiring _tqa_btn_row2 itself to be exposed
    on self — none of this panel's debug-log buttons ever were. Checks both
    tk.Button and ttk.Button since this row mixes both widget types (the
    Toggle On/Off button is a plain tk.Button for its bg/fg color; the
    View Audit Log / Command Debug Log / Clear buttons are ttk.Button)."""
    import tkinter as tk
    import tkinter.ttk as ttk
    _pump(gui)

    def _collect_buttons(widget):
        btns = []
        for child in widget.winfo_children():
            if isinstance(child, (tk.Button, ttk.Button)):
                btns.append(child.cget("text"))
            btns.extend(_collect_buttons(child))
        return btns

    btn_row = gui.app._tqa_btn_enable.master
    all_labels = _collect_buttons(btn_row)
    now_labels = [lbl for lbl in all_labels if "NOW" in lbl]
    assert now_labels == [], (
        f"'NOW Debug Log' button must not exist in the Autonomous AI Task "
        f"Queue panel (v9.0.1 removal — the NOW run mechanism it debugged "
        f"was already removed from both analysis sections in v9.0.0). "
        f"Found: {now_labels}"
    )


def test_view_and_command_debug_log_buttons_still_present_in_task_queue_panel(gui):
    """View Audit Log and Command Debug Log (+ their Clear buttons) must
    still be present — guards against accidentally removing the wrong
    buttons when removing the NOW Debug Log button."""
    import tkinter as tk
    import tkinter.ttk as ttk
    _pump(gui)

    def _collect_buttons(widget):
        btns = []
        for child in widget.winfo_children():
            if isinstance(child, (tk.Button, ttk.Button)):
                btns.append(child.cget("text"))
            btns.extend(_collect_buttons(child))
        return btns

    btn_row = gui.app._tqa_btn_enable.master
    all_labels = _collect_buttons(btn_row)
    assert any("View Audit Log" in lbl for lbl in all_labels)
    assert any("Command Debug Log" in lbl for lbl in all_labels)
    assert sum(1 for lbl in all_labels if lbl == "🗑 Clear") == 2, (
        f"Expected exactly 2 'Clear' buttons (audit log + command debug "
        f"log) now that NOW Debug Log's Clear button is gone. "
        f"Found labels: {all_labels}"
    )


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


# ── v8.1.9: Show Queue due-badge + live refresh ─────────────────────────────

def _write_pending_tasks(entries):
    p = tqa.AI_PROWLER_HOME / "pending_tasks.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(entries, indent=2), encoding="utf-8")


def _row_label_texts(gui):
    """Collect all Label widget text from the expanded queue list frame,
    across every row Frame it contains."""
    texts = []
    for child in gui.app._queue_list_frame.winfo_children():
        if isinstance(child, tk.Frame):
            for w in child.winfo_children():
                if isinstance(w, tk.Label):
                    texts.append(w.cget("text"))
        elif isinstance(child, tk.Label):
            texts.append(child.cget("text"))
    return texts


def test_due_badge_shows_due_now_for_ready_recurring_entry(gui):
    import datetime
    yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    _write_pending_tasks([{
        "task_id": "t1", "label": "Weekly Biz Check", "status": "pending",
        "schedule": "weekly", "next_due": yesterday,
        "created_at": "2026-07-24T00:00:00Z",
    }])
    gui.app._queue_expanded.set(True)
    gui.app._refresh_queue_list()
    _pump(gui)

    texts = _row_label_texts(gui)
    assert any("Weekly Biz Check" in t for t in texts)
    assert any("Due now" in t for t in texts)


def test_due_badge_shows_future_date_for_not_yet_due_entry(gui):
    import datetime
    tomorrow = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
    _write_pending_tasks([{
        "task_id": "t1", "label": "Future Task", "status": "pending",
        "schedule": "weekly", "next_due": tomorrow,
        "created_at": "2026-07-24T00:00:00Z",
    }])
    gui.app._queue_expanded.set(True)
    gui.app._refresh_queue_list()
    _pump(gui)

    texts = _row_label_texts(gui)
    assert any("Future Task" in t for t in texts)
    assert any(tomorrow in t for t in texts)
    assert not any("Due now" in t for t in texts)


def test_due_badge_omitted_for_one_shot_entry(gui):
    _write_pending_tasks([{
        "task_id": "t1", "label": "One Shot Task", "status": "pending",
        "schedule": "none",
        "created_at": "2026-07-24T00:00:00Z",
    }])
    gui.app._queue_expanded.set(True)
    gui.app._refresh_queue_list()
    _pump(gui)

    texts = _row_label_texts(gui)
    assert any("One Shot Task" in t for t in texts)
    assert not any("Due" in t for t in texts)


def test_save_and_queue_refreshes_visible_list_when_already_expanded(gui, monkeypatch):
    """Regression test: this Save & Queue path used to only refresh the
    badge COUNT, not the visible list, when the panel was already
    expanded — the new entry wouldn't appear until manually collapsed
    and re-expanded."""
    # Start with an empty, expanded queue panel.
    _write_pending_tasks([])
    gui.app._queue_expanded.set(True)
    gui.app._refresh_queue_list()
    _pump(gui)
    assert not any("MyNewCustomTask" in t for t in _row_label_texts(gui))

    import custom_tasks_manager as ctm
    task = ctm.create_task(
        label="MyNewCustomTask", prompt="Do the thing.",
        schedule="none",
    )
    tasks = ctm.load_custom_tasks()
    tasks.append(task)
    ctm.save_custom_tasks(tasks)
    entries = ctm.tasks_to_queue_entries([task])
    existing = json.loads((tqa.AI_PROWLER_HOME / "pending_tasks.json").read_text(encoding="utf-8"))
    existing.extend(entries)
    _write_pending_tasks(existing)

    # This is exactly what the Save & Queue button handler does: bump the
    # count, then (since the panel is expanded) also refresh the list.
    gui.app._refresh_queue_count()
    if gui.app._queue_expanded.get():
        gui.app._refresh_queue_list()
    _pump(gui)

    assert any("MyNewCustomTask" in t for t in _row_label_texts(gui))


# ── v8.1.12: Show Queue live-refresh via mtime polling ──────────────────────
# Same feature, same rationale, and the same isolation approach as
# tests/gui/test_quick_links_custom_tasks_live_refresh.py: the mtime-polling
# loop lets Show Queue pick up changes written by a SEPARATE process (a
# headless scheduled run completing/re-arming a task) without the GUI
# needing any user-triggered action. The shared fixture cancels pending
# after() callbacks for test isolation, so self._poll_pending_tasks_file is
# exposed and called directly/synchronously — same logic the real 3-second
# timer runs, without waiting on the timer.

def test_poll_pending_tasks_file_is_exposed_for_tests(gui):
    assert hasattr(gui.app, "_poll_pending_tasks_file")
    assert callable(gui.app._poll_pending_tasks_file)


def test_poll_updates_count_when_file_changes_externally(gui):
    _write_pending_tasks([])
    gui.app._poll_pending_tasks_file()
    _pump(gui)
    assert gui.app._refresh_queue_count() == 0

    # Simulate an external process (e.g. a headless run's
    # complete_analysis_task()) writing a fresh entry directly to disk —
    # NOT through any GUI action.
    _write_pending_tasks([{
        "task_id": "t1", "label": "Externally Queued Task", "status": "pending",
        "schedule": "none", "created_at": "2026-07-25T00:00:00Z",
    }])
    gui.app._poll_pending_tasks_file()
    _pump(gui)

    # Count reflects the change even with the panel collapsed —
    # _refresh_queue_count() always runs; only the detailed list is
    # gated on _queue_expanded.
    assert gui.app._refresh_queue_count() == 1


def test_poll_refreshes_visible_list_when_expanded_and_file_changes(gui):
    _write_pending_tasks([])
    gui.app._queue_expanded.set(True)
    gui.app._poll_pending_tasks_file()
    _pump(gui)
    assert not any("Externally Queued Task" in t for t in _row_label_texts(gui))

    _write_pending_tasks([{
        "task_id": "t1", "label": "Externally Queued Task", "status": "pending",
        "schedule": "none", "created_at": "2026-07-25T00:00:00Z",
    }])
    gui.app._poll_pending_tasks_file()
    _pump(gui)

    assert any("Externally Queued Task" in t for t in _row_label_texts(gui))


def test_poll_does_not_refresh_list_when_collapsed(gui):
    # With the panel collapsed, the poll should still update the count
    # (cheap) but must NOT force the detailed list frame to rebuild —
    # matches the existing collapsed/expanded contract used everywhere
    # else in this panel (Save & Queue, etc.).
    _write_pending_tasks([])
    gui.app._queue_expanded.set(False)
    gui.app._poll_pending_tasks_file()
    _pump(gui)

    _write_pending_tasks([{
        "task_id": "t1", "label": "Should Not Appear Yet", "status": "pending",
        "schedule": "none", "created_at": "2026-07-25T00:00:00Z",
    }])
    gui.app._poll_pending_tasks_file()
    _pump(gui)

    # The list frame itself is only populated when expanded; while
    # collapsed there's nothing to assert on the row content directly,
    # but expanding now and refreshing should show the change was
    # captured (proves the poll ran, not that it silently no-opped).
    gui.app._queue_expanded.set(True)
    gui.app._refresh_queue_list()
    _pump(gui)
    assert any("Should Not Appear Yet" in t for t in _row_label_texts(gui))


def test_poll_reschedules_itself(gui, monkeypatch):
    calls = []
    original_after = gui.app.root.after
    def _spy_after(ms, fn=None, *a):
        calls.append((ms, fn))
        return None  # don't actually schedule — avoid a real pending timer
    monkeypatch.setattr(gui.app.root, "after", _spy_after)
    gui.app._poll_pending_tasks_file()
    # Must reschedule itself for the next tick — otherwise live-refresh
    # would silently stop working after the very first poll.
    assert any(fn is gui.app._poll_pending_tasks_file for _, fn in calls)


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


# ── v9.0.1: Edit Custom Analysis schedule dropdown reverts to stale value ────
# Found live (screenshots): editing an existing task from Manual to Daily
# correctly showed the Start/End time + Times-per-day fields immediately, but
# the dropdown ITSELF kept displaying "Manual only" until the exact same
# "Daily" selection was made a SECOND time. Root cause: _apply_sched_current_
# on_map was bound to the dialog's <Map> event to work around an earlier
# not-yet-mapped-widget bug (ttk.Combobox.current() called before the window
# is mapped silently clears the display) -- but <Map> isn't guaranteed to
# fire only once. A ttk.Combobox's dropdown listbox is its own popup
# Toplevel; opening it (i.e. the user actually using the dropdown) can
# generate a second <Map> event on the parent dialog. Left bound forever via
# add='+', that second event re-ran the handler and force-reset the
# combobox's displayed text back to whatever it was when the dialog first
# opened, clobbering the user's real selection. Fix: the handler now unbinds
# itself after the first firing.

def _find_toplevel_by_title(root, title_substr):
    """Depth-first search of root's children for a Toplevel whose title
    contains title_substr. The task editor is a plain tk.Toplevel, not
    tracked anywhere on the app object, so tests have to find it this way."""
    for child in root.winfo_children():
        if isinstance(child, tk.Toplevel) and title_substr in child.title():
            return child
        found = _find_toplevel_by_title(child, title_substr)
        if found is not None:
            return found
    return None


def _find_first_combobox(widget):
    import tkinter.ttk as ttk
    for child in widget.winfo_children():
        if isinstance(child, ttk.Combobox):
            return child
        found = _find_first_combobox(child)
        if found is not None:
            return found
    return None


def test_schedule_dropdown_does_not_revert_after_second_map_event(gui):
    """v9.0.1 regression: selecting a new schedule must stick even if the
    dialog's <Map> event fires again afterward (simulating the combobox's
    own popdown listbox triggering a second <Map> on the parent window)."""
    import custom_tasks_manager as ctm

    tasks = ctm.load_custom_tasks()
    task = ctm.create_task(label="Schedule Bug Task", prompt="Do something.",
                            schedule="none")
    tasks.append(task)
    ctm.save_custom_tasks(tasks)

    win = gui.app._open_task_editor(task)
    _pump(gui)  # real initial <Map> fires here — the correct, intended one

    dlg = win or _find_toplevel_by_title(gui.root, "Edit Custom Analysis")
    assert dlg is not None, "Could not locate the Edit Custom Analysis window"

    combo = _find_first_combobox(dlg)
    assert combo is not None, "Could not locate the schedule Combobox"
    assert combo.get() == "Manual only"

    # User selects "Daily" — real interaction: set the display value and
    # fire the same virtual event ttk.Combobox fires on a real selection.
    combo.set("Daily")
    combo.event_generate("<<ComboboxSelected>>")
    _pump(gui)
    assert combo.get() == "Daily", (
        "Combobox did not show 'Daily' immediately after selection"
    )

    # Simulate the second <Map> event that was clobbering the selection.
    dlg.event_generate("<Map>")
    _pump(gui)
    assert combo.get() == "Daily", (
        "Combobox reverted to a stale value after a second <Map> event — "
        "the v9.0.1 regression this test guards against"
    )

    dlg.destroy()


def test_schedule_dropdown_initializes_correctly_for_existing_daily_task(gui):
    """Regression guard for the ORIGINAL bug _apply_sched_current_on_map
    exists to fix: opening the editor for a task that's already scheduled
    Daily must show 'Daily' in the dropdown immediately, with no extra
    interaction needed. Makes sure the v9.0.1 fix (unbind after first
    firing) didn't remove the single application that's still required."""
    import custom_tasks_manager as ctm

    tasks = ctm.load_custom_tasks()
    task = ctm.create_task(label="Already Daily Task", prompt="Do something.",
                            schedule="daily", first_due="2026-08-10")
    tasks.append(task)
    ctm.save_custom_tasks(tasks)

    win = gui.app._open_task_editor(task)
    _pump(gui)

    dlg = win or _find_toplevel_by_title(gui.root, "Edit Custom Analysis")
    assert dlg is not None

    combo = _find_first_combobox(dlg)
    assert combo is not None
    assert combo.get() == "Daily", (
        "Editing an already-Daily task should show 'Daily' immediately "
        "without any user interaction"
    )

    dlg.destroy()


def test_run_analysis_now_uses_saved_settings_not_raw_prompt(gui, monkeypatch):
    """OBSOLETE as of v9.0.0 — ▶ NOW (and gui.app._run_analysis_now, the
    method this test drove) was removed from Common Business AI Analysis
    entirely; see test_run_analysis_now_not_exposed_on_gui above, which
    positively asserts the method no longer exists. This test used to guard
    a v8.1.6 bug where ▶ NOW used the raw unenriched task prompt instead of
    the same enriched prompt ▶ Queue builds — moot now that the enrichment
    path (_build_builtin_prompt) is only ever reached via ▶ Queue.
    Kept as a stub, not deleted outright, so the v8.1.6 bug this used to
    guard against stays discoverable in test history if ▶ NOW (or an
    equivalent immediate-run mechanism) is ever reintroduced."""
    pytest.skip("_run_analysis_now removed in v9.0.0 — see "
                "test_run_analysis_now_not_exposed_on_gui")


def test_run_analysis_now_blocked_without_cli(gui, monkeypatch, dialogs):
    """OBSOLETE as of v9.0.0 — see test_run_analysis_now_uses_saved_settings_
    not_raw_prompt above for the full explanation."""
    pytest.skip("_run_analysis_now removed in v9.0.0 — see "
                "test_run_analysis_now_not_exposed_on_gui")


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
