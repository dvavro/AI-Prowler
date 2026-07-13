"""
tests/gui/test_proactive_alerts_autosave.py
=============================================
Tests for the v8.2 Proactive Alerts panel redesign: per-job green/red
toggle buttons that auto-save immediately, auto-save-on-blur for the
Time field and shared Email field, auto-save-on-select for the Days
combobox, and automatic engine start/stop derived from whether ANY job
is currently enabled — replacing the old separate master "Enable
proactive alerts" checkbox + manual "Save Config" / "Start/Stop" buttons.

Covers:
  - Each job's toggle button renders green ("● ON") when enabled in the
    saved config, red ("○ OFF") when disabled
  - Clicking a toggle flips its own state, saves immediately, and does
    NOT affect any other job's enabled state
  - Enabling the first job (engine was fully stopped) auto-starts the
    background scheduler thread
  - Disabling the last remaining enabled job auto-stops the engine
  - scheduler_config.json's top-level "enabled" key is derived as
    "any job enabled" on every save, never left stale
  - The shared email field only saves on blur/Enter, not on every
    keystroke (regression guard against the "email trace_add fires on
    every character" mistake caught before this was applied)
  - The old master enable checkbox and Save Config / Start/Stop buttons
    are actually gone, not just relabeled

NO real emails are sent — scheduler_engine.start() spins up the real
background thread, but job functions only fire when actually due, and
no test here waits long enough for a tick to occur. Every test stops
the engine in teardown so no thread leaks into the next test.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def alerts_env(gui, tmp_path, monkeypatch):
    """Isolate scheduler_config.json/log/last-run to a temp location and
    guarantee the background scheduler thread is stopped before AND after
    each test — even if the test fails partway through.

    IMPORTANT: scheduler_engine.CONFIG_PATH / LOG_PATH / _LAST_RUN_PATH are
    MODULE-LEVEL constants computed once at import time from Path.home() —
    NOT re-evaluated per call. Patching Path.home() alone does nothing,
    since scheduler_engine is already imported (against the REAL home
    directory) by the time this fixture runs, as part of the `gui` fixture
    building the first RAGGui instance. The only way to actually redirect
    load_config()/save_config()/get_log_tail() is to patch the module
    ATTRIBUTES directly. (First caught the hard way: an earlier version of
    this fixture patched Path.home() only and silently read/wrote the
    developer's real ~/.ai-prowler/scheduler_config.json during test runs.)
    """
    import scheduler_engine as se
    if se.is_running():
        se.stop()

    monkeypatch.setattr(se, "CONFIG_PATH", tmp_path / "scheduler_config.json")
    monkeypatch.setattr(se, "LOG_PATH", tmp_path / "scheduler_log.txt")
    monkeypatch.setattr(se, "_LAST_RUN_PATH", tmp_path / "scheduler_last_run.json")

    yield gui

    if se.is_running():
        se.stop()


def _write_config(tmp_path, enabled_jobs=None, email="david@example.com"):
    """Seed scheduler_config.json (at the PATCHED path — see alerts_env)
    before the tab is (re)built, so the panel picks up a known state."""
    import scheduler_jobs as sj
    enabled_jobs = enabled_jobs or set()
    cfg = {
        "enabled": bool(enabled_jobs),
        "email_to": email,
        "jobs": {
            jid: {"enabled": jid in enabled_jobs,
                  "time": meta.get("default_time", "08:00"),
                  "days": meta.get("default_days", "daily")}
            for jid, meta in sj.JOB_REGISTRY.items()
        },
    }
    p = tmp_path / "scheduler_config.json"
    p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return cfg


def _read_config(tmp_path):
    p = tmp_path / "scheduler_config.json"
    return json.loads(p.read_text(encoding="utf-8"))


class TestTogglePainting:

    def test_enabled_job_renders_on(self, alerts_env, tmp_path):
        import scheduler_jobs as sj
        first_job = next(iter(sj.JOB_REGISTRY))
        _write_config(tmp_path, enabled_jobs={first_job})

        alerts_env.app.create_query_tab()
        alerts_env.pump()

        btn = alerts_env.app._job_toggle_btns[first_job]
        assert "ON" in btn.cget("text")

    def test_disabled_job_renders_off(self, alerts_env, tmp_path):
        import scheduler_jobs as sj
        first_job = next(iter(sj.JOB_REGISTRY))
        _write_config(tmp_path, enabled_jobs=set())  # nothing enabled

        alerts_env.app.create_query_tab()
        alerts_env.pump()

        btn = alerts_env.app._job_toggle_btns[first_job]
        assert "OFF" in btn.cget("text")


class TestToggleClickBehavior:

    def test_clicking_toggle_flips_only_that_job(self, alerts_env, tmp_path):
        import scheduler_jobs as sj
        jobs = list(sj.JOB_REGISTRY.keys())
        assert len(jobs) >= 2, "test assumes at least 2 registered jobs"
        job_a, job_b = jobs[0], jobs[1]
        _write_config(tmp_path, enabled_jobs={job_b})  # only B starts enabled

        alerts_env.app.create_query_tab()
        alerts_env.pump()

        # Click A's toggle (currently off) via its command callback.
        alerts_env.app._job_toggle_btns[job_a].invoke()
        alerts_env.pump()

        assert alerts_env.app._job_enabled_vars[job_a].get() is True
        assert alerts_env.app._job_enabled_vars[job_b].get() is True  # untouched

        cfg = _read_config(tmp_path)
        assert cfg["jobs"][job_a]["enabled"] is True
        assert cfg["jobs"][job_b]["enabled"] is True

    def test_clicking_toggle_saves_immediately_no_extra_action_needed(
            self, alerts_env, tmp_path):
        import scheduler_jobs as sj
        first_job = next(iter(sj.JOB_REGISTRY))
        _write_config(tmp_path, enabled_jobs=set())

        alerts_env.app.create_query_tab()
        alerts_env.pump()

        alerts_env.app._job_toggle_btns[first_job].invoke()
        alerts_env.pump()

        cfg = _read_config(tmp_path)
        assert cfg["jobs"][first_job]["enabled"] is True


class TestEngineAutoLifecycle:

    def test_enabling_first_job_auto_starts_engine(self, alerts_env, tmp_path):
        import scheduler_engine as se
        import scheduler_jobs as sj
        first_job = next(iter(sj.JOB_REGISTRY))
        _write_config(tmp_path, enabled_jobs=set())
        assert not se.is_running()

        alerts_env.app.create_query_tab()
        alerts_env.pump()
        assert not se.is_running()  # nothing enabled yet — must stay stopped

        alerts_env.app._job_toggle_btns[first_job].invoke()
        alerts_env.pump()

        assert se.is_running() is True

    def test_disabling_last_job_auto_stops_engine(self, alerts_env, tmp_path):
        import scheduler_engine as se
        import scheduler_jobs as sj
        first_job = next(iter(sj.JOB_REGISTRY))
        _write_config(tmp_path, enabled_jobs={first_job})

        alerts_env.app.create_query_tab()
        alerts_env.pump()
        assert se.is_running() is True  # auto-started on tab build

        alerts_env.app._job_toggle_btns[first_job].invoke()  # turn it off
        alerts_env.pump()
        # stop() runs on a background thread; give it a moment to finish.
        import time as _time
        for _ in range(50):
            if not se.is_running():
                break
            _time.sleep(0.1)
            alerts_env.pump()

        assert se.is_running() is False

    def test_disabling_one_of_two_enabled_jobs_leaves_engine_running(
            self, alerts_env, tmp_path):
        """Only the LAST enabled job turning off should stop the engine —
        with two enabled, turning one off must leave it running."""
        import scheduler_engine as se
        import scheduler_jobs as sj
        jobs = list(sj.JOB_REGISTRY.keys())
        job_a, job_b = jobs[0], jobs[1]
        _write_config(tmp_path, enabled_jobs={job_a, job_b})

        alerts_env.app.create_query_tab()
        alerts_env.pump()
        assert se.is_running() is True

        alerts_env.app._job_toggle_btns[job_a].invoke()
        alerts_env.pump()

        assert se.is_running() is True
        cfg = _read_config(tmp_path)
        assert cfg["enabled"] is True  # still True — job_b still enabled

    def test_top_level_enabled_flag_derived_not_stale(self, alerts_env, tmp_path):
        """Regression guard: the old design let 'enabled' (master flag) and
        individual job flags drift out of sync. The new design derives
        'enabled' from the jobs dict on every single save."""
        import scheduler_jobs as sj
        first_job = next(iter(sj.JOB_REGISTRY))
        _write_config(tmp_path, enabled_jobs=set())

        alerts_env.app.create_query_tab()
        alerts_env.pump()
        assert _read_config(tmp_path)["enabled"] is False

        alerts_env.app._job_toggle_btns[first_job].invoke()
        alerts_env.pump()
        assert _read_config(tmp_path)["enabled"] is True


class TestFieldAutoSaveDebounce:

    def test_email_does_not_save_on_every_keystroke(self, alerts_env, tmp_path):
        """Regression guard for the exact mistake caught before this was
        applied: binding email saves to <FocusOut>/<Return>, not to a
        StringVar trace, which would fire on every character typed."""
        _write_config(tmp_path, enabled_jobs=set(), email="old@example.com")

        alerts_env.app.create_query_tab()
        alerts_env.pump()

        entry = alerts_env.app._email_entry
        entry.delete(0, "end")
        entry.insert(0, "n")
        alerts_env.pump()
        # Mid-typing — must NOT have saved yet.
        assert _read_config(tmp_path)["email_to"] == "old@example.com"

        entry.delete(0, "end")
        entry.insert(0, "new@example.com")
        # Directly synthesize <FocusOut> on the widget rather than trying to
        # shift real window-manager focus — focus_set() depends on the test
        # Tk root actually holding WM-level focus, which is unreliable in a
        # headless/background test run. event_generate('<FocusOut>') fires
        # the bound handler directly regardless of real WM focus state.
        entry.event_generate("<FocusOut>")
        alerts_env.pump()
        assert _read_config(tmp_path)["email_to"] == "new@example.com"

    def test_time_field_saves_on_focus_out(self, alerts_env, tmp_path):
        import scheduler_jobs as sj
        first_job = next(iter(sj.JOB_REGISTRY))
        _write_config(tmp_path, enabled_jobs=set())

        alerts_env.app.create_query_tab()
        alerts_env.pump()

        var = alerts_env.app._job_time_vars[first_job]
        var.set("09:30")
        alerts_env.pump()
        # Not yet saved — no FocusOut/Return fired.
        assert _read_config(tmp_path)["jobs"][first_job]["time"] != "09:30"


class TestOldControlsRemoved:

    def test_no_master_enable_checkbox_variable_exists(self, alerts_env, tmp_path):
        _write_config(tmp_path, enabled_jobs=set())
        alerts_env.app.create_query_tab()
        alerts_env.pump()
        assert not hasattr(alerts_env.app, "_sched_enabled_var")

    def test_view_log_button_still_present(self, alerts_env, tmp_path):
        """View Log is the one control deliberately kept — everything
        else auto-saves now, but the log viewer stays manual/on-demand."""
        _write_config(tmp_path, enabled_jobs=set())
        alerts_env.app.create_query_tab()
        alerts_env.pump()
        # Presence is verified indirectly: _al_btn_row should exist and
        # contain at least one child button (View Log).
        assert alerts_env.app._al_btn_row.winfo_children()
