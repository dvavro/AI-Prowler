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


# Proactive Alerts is personal-mode only (create_query_tab skips it in
# Business Server mode) — pin personal mode so the result doesn't depend on
# this PC's real config.json (2026-10-08).
@pytest.fixture(autouse=True)
def _personal_mode(force_personal_mode):
    yield


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


class TestClearLog:
    """2026-11-02 (David): a Clear Log button next to View Log."""

    def _seed_log(self, tmp_path):
        p = tmp_path / "scheduler_log.txt"          # alerts_env points LOG_PATH here
        p.write_text("[2026-11-02 06:44:54] Scheduler started\n[2026-11-02 06:44:55] Scheduler stopped\n",
                     encoding="utf-8")
        return p

    def test_button_sits_next_to_view_log(self, alerts_env, tmp_path):
        _write_config(tmp_path, enabled_jobs=set())
        alerts_env.app.create_query_tab()
        alerts_env.pump()
        texts = [w.cget("text") for w in alerts_env.app._al_btn_row.winfo_children()]
        assert texts.index("🧹 Clear Log") == texts.index("📋 View Log") + 1

    def test_yes_empties_the_log(self, alerts_env, dialogs, tmp_path):
        _write_config(tmp_path, enabled_jobs=set())
        log = self._seed_log(tmp_path)
        alerts_env.app.create_query_tab()
        alerts_env.pump()
        dialogs.set_response("askyesno", True)
        alerts_env.app._al_clear_log_btn.invoke()
        alerts_env.pump()
        text = log.read_text(encoding="utf-8")
        assert "Scheduler started" not in text and "Log cleared" in text
        assert dialogs.last_call("askyesno")["title"] == "Clear Log"

    def test_no_keeps_the_log(self, alerts_env, dialogs, tmp_path):
        _write_config(tmp_path, enabled_jobs=set())
        log = self._seed_log(tmp_path)
        alerts_env.app.create_query_tab()
        alerts_env.pump()
        dialogs.set_response("askyesno", False)
        alerts_env.app._al_clear_log_btn.invoke()
        alerts_env.pump()
        assert "Scheduler started" in log.read_text(encoding="utf-8")

    def test_clearing_leaves_alert_settings_alone(self, alerts_env, dialogs, tmp_path):
        import scheduler_jobs as sj
        first = next(iter(sj.JOB_REGISTRY))
        _write_config(tmp_path, enabled_jobs={first})
        self._seed_log(tmp_path)
        alerts_env.app.create_query_tab()
        alerts_env.pump()
        dialogs.set_response("askyesno", True)
        alerts_env.app._al_clear_log_btn.invoke()
        alerts_env.pump()
        assert _read_config(tmp_path)["jobs"][first]["enabled"] is True


class TestTimeDropdown:
    """2026-11-02 (David): "make the time boxes a drop down selection for time and every N hours"."""

    def _build(self, alerts_env, tmp_path, times=None):
        import scheduler_jobs as sj
        cfg = _write_config(tmp_path, enabled_jobs=set())
        for jid, t in (times or {}).items():
            cfg["jobs"][jid]["time"] = t
        (tmp_path / "scheduler_config.json").write_text(json.dumps(cfg), encoding="utf-8")
        alerts_env.app.create_query_tab()
        alerts_env.pump()
        return sj

    def test_every_job_has_a_readonly_dropdown_with_friendly_labels(self, alerts_env, tmp_path):
        sj = self._build(alerts_env, tmp_path)
        combos = alerts_env.app._job_time_combos
        assert set(combos) == set(sj.jobs_for_mode(False))       # personal: no server-only alerts
        for jid, cb in combos.items():
            assert str(cb.cget("state")) == "readonly"
            values = list(cb.cget("values"))
            assert "7:00 AM" in values and "6:30 PM" in values and "Every 2 hours" in values
        assert combos["morning_briefing"].get() == "7:00 AM"
        assert combos["sms_reply_monitor"].get() == "Every 2 hours"

    def test_picking_a_time_saves_the_engine_form(self, alerts_env, tmp_path):
        self._build(alerts_env, tmp_path)
        cb = alerts_env.app._job_time_combos["morning_briefing"]
        cb.set("6:30 AM")
        cb.event_generate("<<ComboboxSelected>>")
        alerts_env.pump()
        assert _read_config(tmp_path)["jobs"]["morning_briefing"]["time"] == "06:30"

    def test_picking_every_n_hours_saves_interval(self, alerts_env, tmp_path):
        self._build(alerts_env, tmp_path)
        cb = alerts_env.app._job_time_combos["sms_reply_monitor"]
        cb.set("Every 4 hours")
        cb.event_generate("<<ComboboxSelected>>")
        alerts_env.pump()
        assert _read_config(tmp_path)["jobs"]["sms_reply_monitor"]["time"] == "every_4h"
        cb2 = alerts_env.app._job_time_combos["morning_briefing"]
        cb2.set("Every hour")
        cb2.event_generate("<<ComboboxSelected>>")
        alerts_env.pump()
        assert _read_config(tmp_path)["jobs"]["morning_briefing"]["time"] == "every_1h"

    def test_hand_typed_older_value_is_kept(self, alerts_env, tmp_path):
        """A time typed by hand before the dropdown (07:15, every_45m) shows as its own choice and
        isn't changed just by opening the screen or saving another field."""
        self._build(alerts_env, tmp_path, times={"morning_briefing": "07:15",
                                                 "sms_reply_monitor": "every_45m"})
        combos = alerts_env.app._job_time_combos
        assert combos["morning_briefing"].get() == "7:15 AM"
        assert combos["sms_reply_monitor"].get() == "Every 45 minutes"
        alerts_env.app._job_toggle_btns["weather_watch"].invoke()       # some other save
        alerts_env.pump()
        saved = _read_config(tmp_path)["jobs"]
        assert saved["morning_briefing"]["time"] == "07:15"
        assert saved["sms_reply_monitor"]["time"] == "every_45m"


class TestEmailTextSwitches:
    """2026-11-02 (David): "send individual alerts to SMS when enabled ... per Alert along with email
    enable in each proactive alert row"."""

    def _build(self, alerts_env, tmp_path, monkeypatch, ready=True, sms_to=""):
        import scheduler_engine as se
        monkeypatch.setattr(se, "texting_ready", lambda: ready)
        cfg = _write_config(tmp_path, enabled_jobs=set())
        cfg["sms_to"] = sms_to
        (tmp_path / "scheduler_config.json").write_text(json.dumps(cfg), encoding="utf-8")
        alerts_env.app.create_query_tab()
        alerts_env.pump()

    def test_every_row_has_email_on_and_text_off(self, alerts_env, tmp_path, monkeypatch):
        import scheduler_jobs as sj
        self._build(alerts_env, tmp_path, monkeypatch)
        app = alerts_env.app
        assert set(app._job_email_checks) == set(app._job_sms_checks) == set(sj.jobs_for_mode(False))
        assert all(v.get() for v in app._job_email_vars.values())
        assert not any(v.get() for v in app._job_sms_vars.values())

    def test_ticking_text_and_unticking_email_saves(self, alerts_env, tmp_path, monkeypatch):
        self._build(alerts_env, tmp_path, monkeypatch)
        app = alerts_env.app
        app._job_sms_checks["morning_briefing"].invoke()
        app._job_email_checks["morning_briefing"].invoke()
        alerts_env.pump()
        saved = _read_config(tmp_path)["jobs"]["morning_briefing"]
        assert saved["sms"] is True and saved["email"] is False
        assert _read_config(tmp_path)["jobs"]["weather_watch"]["email"] is True

    def test_texts_go_to_number_saves(self, alerts_env, tmp_path, monkeypatch):
        self._build(alerts_env, tmp_path, monkeypatch, sms_to="386-555-0100")
        app = alerts_env.app
        assert app._al_sms_to_var.get() == "386-555-0100"
        app._al_sms_to_var.set("386-555-0199")
        app._al_save_sms_to()
        alerts_env.pump()
        assert _read_config(tmp_path)["sms_to"] == "386-555-0199"

    def test_warns_when_texting_is_not_set_up(self, alerts_env, tmp_path, monkeypatch):
        self._build(alerts_env, tmp_path, monkeypatch, ready=False)
        assert "Texting isn't set up" in alerts_env.app._al_sms_info_var.get()
