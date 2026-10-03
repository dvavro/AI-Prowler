"""
R-060 (2026-09-29, David): the E2E suite may flip only a few Settings
toggles — Email Route On Build, Customer Reminder Email/SMS Enabled, Route
Origin Mode (R-061) and Working Days (Mon–Fri / every day, 2026-10-02) — and
always puts them back. Tests of the guard rule and
the save / restore / crash-recovery logic (tests/gui_jobs_e2e/settings_switch.py)
against a fake Jobs-app API, so nothing real is touched.

Run: run_tests.bat tests\\mcp\\test_r060_settings_toggles.py -v
"""
import importlib.util as _ilu
from pathlib import Path

import pytest

_E2E = Path(__file__).resolve().parent.parent / "gui_jobs_e2e"


def _load(name, file):
    spec = _ilu.spec_from_file_location(name, _E2E / file)
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


safety = _load("e2e_safety_r060", "safety.py")
sw = _load("e2e_settings_switch_r060", "settings_switch.py")

NOTE = "Disabled (default) = no automatic email ..."


class FakeApi:
    """The bits of api.ApiClient the switch uses, with the real guard in front."""

    def __init__(self, guard, values):
        self.guard = guard
        self.rows = {k: {"Setting": k, "Value": v, "Notes": NOTE} for k, v in values.items()}
        self.rows["Tax Rate"] = {"Setting": "Tax Rate", "Value": "0.07", "Notes": ""}
        self.writes = []

    def read(self, sheet):
        assert sheet == "Settings"
        return [dict(r) for r in self.rows.values()]

    def call(self, tool, args, expect_ok=True):
        d, why = self.guard.enforce(tool, args, "setup")
        if d != "allow":
            raise safety.GuardViolation(why)
        k = args["job_identifier"]
        self.rows[k].update(args["updates"])
        self.writes.append((k, args["updates"]["Value"]))
        return "✅ updated"


@pytest.fixture
def env(tmp_path):
    g = safety.Guard(tier="safe")
    api = FakeApi(g, {"Email Route On Build": "Enabled", "Customer Reminder Email Enabled": "Enabled",
                      "Customer Reminder SMS Enabled": "Disabled", "Route Origin Mode": "Jobs Only",
                      "Working Days": "Mon,Tue,Wed,Thu,Fri",
                      "Start/End Street Address": "1500 Shadow Pines Dr", "Start/End City": "New Smyrna Beach",
                      "Start/End State": "Florida", "Start/End ZIP": "32168"})
    s = sw.SettingsSwitch(api, g, state_file=tmp_path / "settings_to_restore.json")
    return g, api, s


def test_nothing_writable_before_the_snapshot(env):
    g, api, s = env
    with pytest.raises(safety.GuardViolation):
        api.call("update_job_spreadsheet", {"sheet_name": "Settings", "id_column": "Setting",
                                            "job_identifier": "Email Route On Build", "updates": {"Value": "Disabled"}})


def test_snapshot_saves_to_file_and_arms_the_guard(env):
    g, api, s = env
    s.snapshot()
    assert set(g.settings_saved) == set(sw.TOGGLES) | set(sw.KEEP_AS_IS)
    assert s.state_file.exists()
    assert g.route_email_on is True                          # read from the real value


def test_set_restore_verify(env):
    g, api, s = env
    s.snapshot()
    s.set("Email Route On Build", "Disabled")
    assert g.route_email_on is False
    s.set("Customer Reminder SMS Enabled", "Enabled")
    assert s.verify() and len(s.verify()) == 2
    assert s.restore() == ["Email Route On Build", "Customer Reminder SMS Enabled"]
    assert s.verify() == [] and not s.state_file.exists()
    assert g.route_email_on is True


def test_other_settings_and_values_blocked(env):
    g, api, s = env
    s.snapshot()
    for args in ({"job_identifier": "Tax Rate", "updates": {"Value": "0.99"}},
                 {"job_identifier": "Email Route On Build", "updates": {"Value": "Maybe"}},
                 {"job_identifier": "Email Route On Build", "updates": {"Value": "Enabled", "Notes": "x"}},
                 {"job_identifier": "Email Route On Build", "updates": {"Value": "Enabled", "Setting": "Other"}}):
        a = {"sheet_name": "Settings", "id_column": "Setting", **args}
        assert g.check("update_job_spreadsheet", a)[0] == "block", args
    # the app's edit form sends Setting + Notes unchanged — allowed
    ok = {"sheet_name": "Settings", "id_column": "Setting", "job_identifier": "Email Route On Build",
          "updates": {"Setting": "Email Route On Build", "Value": "Disabled", "Notes": NOTE}}
    assert g.check("update_job_spreadsheet", ok)[0] == "allow"
    assert g.check("delete_job", {"sheet_name": "Settings", "job_identifier": "Email Route On Build"})[0] == "block"


def test_killed_run_is_put_back_by_the_next_snapshot(env, tmp_path):
    g, api, s = env
    s.snapshot()
    s.set("Email Route On Build", "Disabled")                # ... and the run dies here
    g2 = safety.Guard(tier="safe")
    api.guard = g2
    s2 = sw.SettingsSwitch(api, g2, state_file=s.state_file)
    out = s2.snapshot()
    assert out["recovered"] == ["Email Route On Build"]
    assert api.rows["Email Route On Build"]["Value"] == "Enabled"
    assert s2.saved["Email Route On Build"]["Value"] == "Enabled"    # the true original, not the leftover


def test_disabling_is_believed_only_after_read_back(env):
    g, api, s = env
    s.snapshot()
    g.observe_setting("Email Route On Build", "Disabled", pending=True)
    assert g.route_email_on is True                          # still assume on (safe side)
    g.observe_setting("Email Route On Build", "Enabled", pending=True)
    assert g.route_email_on is True


# ── R-061: the route start/end mode ──────────────────────────────────────────
def test_route_origin_mode_switch(env):
    g, api, s = env
    s.snapshot()
    s.set("Route Origin Mode", "Company Location")
    assert api.rows["Route Origin Mode"]["Value"] == "Company Location"
    with pytest.raises(ValueError):
        s.set("Route Origin Mode", "Enabled")                       # not a mode
    bad = {"sheet_name": "Settings", "id_column": "Setting", "job_identifier": "Route Origin Mode",
           "updates": {"Value": "Somewhere Else"}}
    assert g.check("update_job_spreadsheet", bad)[0] == "block"
    assert s.restore() == ["Route Origin Mode"]
    assert api.rows["Route Origin Mode"]["Value"] == "Jobs Only"


def test_start_end_address_only_resaved_unchanged(env):
    """The app's Route Origin Mode form re-saves the four Start/End Address rows
    with their current values — allowed; any change to them is blocked."""
    g, api, s = env
    s.snapshot()
    same = {"sheet_name": "Settings", "id_column": "Setting", "job_identifier": "Start/End City",
            "updates": {"Value": "New Smyrna Beach"}}
    assert g.check("update_job_spreadsheet", same)[0] == "allow"
    for v in ("Daytona Beach", ""):
        d = dict(same, updates={"Value": v})
        assert g.check("update_job_spreadsheet", d)[0] == "block", v
    with pytest.raises(ValueError):
        s.set("Start/End City", "Daytona Beach")


def test_route_builds_left_alone_when_setting_off(env):
    g, api, s = env
    s.snapshot()
    s.set("Email Route On Build", "Disabled")
    a, note = g.route_email_args("suggest_route_schedule", {"route_date": safety.SANDBOX_DATE})
    assert "email_route" not in a and note == ""
