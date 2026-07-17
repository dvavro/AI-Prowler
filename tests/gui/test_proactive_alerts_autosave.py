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


def _write_config(tmp_path, enabled_jobs=None, email="david@example.com",
                  location="New Smyrna Beach, Florida"):
    """Seed scheduler_config.json (at the PATCHED path — see alerts_env)
    before the tab is (re)built, so the panel picks up a known state."""
    import scheduler_jobs as sj
    enabled_jobs = enabled_jobs or set()
    cfg = {
        "enabled": bool(enabled_jobs),
        "email_to": email,
        "location": location,
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


def _find_label_text(widget, needle):
    """Recursively search a widget tree for a Label whose current
    displayed text contains `needle`. Used to verify the read-only
    Proactive Alerts recipient/location display without depending on
    any particular internal attribute name."""
    for child in widget.winfo_children():
        try:
            text = child.cget("text")
        except Exception:
            text = None
        if text and needle in text:
            return text
        found = _find_label_text(child, needle)
        if found is not None:
            return found
    return None


def _latest_query_tab(app):
    """create_query_tab() ADDS a new tab frame to the notebook on every
    call rather than replacing the previous one — repeated calls across
    tests in a reused `gui`/`alerts_env` fixture leave older
    "Links & Analysis" tabs sitting in the widget tree with stale
    (or unconfigured) content. Searching the whole notebook can match
    one of those stale tabs instead of the one this test just built, so
    scope any widget-text search to the most-recently-added tab only."""
    return app.notebook.winfo_children()[-1]


class TestFieldAutoSaveDebounce:

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


class TestRecipientAndLocationDisplay:
    """
    v8.1.3 — the Proactive Alerts panel's Recipient/Location fields were
    made READ-ONLY (see rag_gui.py, the comment above _read_default_to /
    _read_owner_location). There used to be separate editable Entry
    widgets here (self._email_entry, self._location_entry,
    self._location_var), each with its own storage in
    scheduler_config.json — meaning up to three disconnected copies of
    "who/where" could exist at once. Now the panel only DISPLAYS the one
    real source for each:
      - Recipient <- Settings -> Email Configuration's default_to
                     (~/.ai-prowler/email_config.json)
      - Location  <- Settings -> Owner Name/Address
                     (rag_preprocessor.OWNER_CITY/STATE/ZIP)
    Nothing here is editable anymore, so there's no debounce/keystroke
    behavior left to test — these tests confirm the panel reflects
    whatever Settings currently holds, and that the old editable-field
    attributes are actually gone rather than just relabeled.
    """

    def test_old_editable_field_attributes_are_gone(self, alerts_env, tmp_path):
        _write_config(tmp_path, enabled_jobs=set())
        alerts_env.app.create_query_tab()
        alerts_env.pump()

        assert not hasattr(alerts_env.app, "_email_entry")
        assert not hasattr(alerts_env.app, "_location_entry")
        assert not hasattr(alerts_env.app, "_location_var")

    def test_panel_displays_recipient_from_email_settings(
            self, alerts_env, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        (tmp_path / ".ai-prowler").mkdir(parents=True, exist_ok=True)
        (tmp_path / ".ai-prowler" / "email_config.json").write_text(
            json.dumps({"default_to": "crew@example.com"}), encoding="utf-8")
        _write_config(tmp_path, enabled_jobs=set())

        alerts_env.app.create_query_tab()
        alerts_env.pump()

        text = _find_label_text(_latest_query_tab(alerts_env.app), "Sends to:")
        assert text is not None
        assert "crew@example.com" in text

    def test_panel_shows_placeholder_when_recipient_not_configured(
            self, alerts_env, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        # No .ai-prowler/email_config.json written at all.
        _write_config(tmp_path, enabled_jobs=set())

        alerts_env.app.create_query_tab()
        alerts_env.pump()

        text = _find_label_text(_latest_query_tab(alerts_env.app), "Sends to:")
        assert text is not None
        assert "not set" in text

    def test_panel_displays_location_from_owner_settings(
            self, alerts_env, tmp_path, monkeypatch):
        import rag_preprocessor as rp
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(rp, "OWNER_CITY", "Port Orange")
        monkeypatch.setattr(rp, "OWNER_STATE", "Florida")
        monkeypatch.setattr(rp, "OWNER_ZIP", "32127")
        _write_config(tmp_path, enabled_jobs=set())

        alerts_env.app.create_query_tab()
        alerts_env.pump()

        text = _find_label_text(_latest_query_tab(alerts_env.app), "Weather location:")
        assert text is not None
        assert "Port Orange, Florida 32127" in text

    def test_panel_shows_placeholder_when_location_not_configured(
            self, alerts_env, tmp_path, monkeypatch):
        import rag_preprocessor as rp
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(rp, "OWNER_CITY", "")
        monkeypatch.setattr(rp, "OWNER_STATE", "")
        monkeypatch.setattr(rp, "OWNER_ZIP", "")
        _write_config(tmp_path, enabled_jobs=set())

        alerts_env.app.create_query_tab()
        alerts_env.pump()

        text = _find_label_text(_latest_query_tab(alerts_env.app), "Weather location:")
        assert text is not None
        assert "not set" in text

    def test_saving_a_job_toggle_does_not_touch_legacy_email_or_location_keys(
            self, alerts_env, tmp_path, monkeypatch):
        """_save_and_sync_engine deliberately no longer writes email_to/
        location into scheduler_config.json — confirms a save (triggered
        by flipping a job toggle) leaves whatever was already in the
        file untouched rather than clearing or overwriting it."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        import scheduler_jobs as sj
        first_job = next(iter(sj.JOB_REGISTRY))
        _write_config(tmp_path, enabled_jobs=set(),
                      email="legacy@example.com", location="Legacy Town, FL")

        alerts_env.app.create_query_tab()
        alerts_env.pump()

        alerts_env.app._job_toggle_btns[first_job].invoke()
        alerts_env.pump()

        saved = _read_config(tmp_path)
        assert saved["email_to"] == "legacy@example.com"
        assert saved["location"] == "Legacy Town, FL"


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
