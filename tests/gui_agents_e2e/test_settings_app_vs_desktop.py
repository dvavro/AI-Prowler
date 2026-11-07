"""David 3 Nov: agent settings changed in an app on a PERSONAL install must reach AI-Prowler on the PC, and on a SERVER no
app may change them at all.

Personal: the desktop tab is built once and stays open, in another process from the apps' server, so these tests leave the
Tk panel OPEN (no rebuild, unlike test_settings_sync.py), change the setting in the app and watch the panel follow.
Server: every way in from outside is tried as the owner, and nothing may change.
"""
from __future__ import annotations

import time

import pytest

from conftest import http
from test_settings_desk_pwa import Card
from test_settings_desktop import Agent, Jobs, LABEL, dga
from test_settings_jobs_pwa import JobsSettings
from test_settings_sync import desktop  # noqa: F401 — the fixture


def _follows(env, var, want, secs=5):
    t0 = time.time()
    while var.get() != want and time.time() - t0 < secs:
        env.root.update()
        time.sleep(0.02)
    assert var.get() == want, f"the open desktop panel still shows {var.get()!r}, the app saved {want!r}"


@pytest.fixture
def quick(monkeypatch):
    monkeypatch.setattr(dga, "LIVE_SYNC_MS", 50, raising=False)


# ── Personal: app → the open desktop panel ───────────────────────────────────
@pytest.mark.parametrize("key,mode", [("agent_stage_intake", "auto"), ("agent_stage_learn", "off"),
                                      ("agent_bk_stage_decide", "auto"), ("agent_bk_stage_track", "off")])
def test_service_desk_app_stage_reaches_open_panel(solo, person, desktop, quick, key, mode):
    card = Card(solo, person)
    panel = Agent(desktop)
    card.pick(key, mode)
    _follows(desktop, panel.v[key], LABEL[mode])
    assert panel.save()[1]                                      # Save afterwards must not put the old value back
    assert card.stored(key) == mode


def test_service_desk_app_switches_reach_open_panel(solo, person, desktop, quick):
    card = Card(solo, person)
    panel = Agent(desktop)
    before = panel.v["agent_shadow"].get()
    card.tick("agent_shadow")
    _follows(desktop, panel.v["agent_shadow"], not before)


@pytest.mark.parametrize("key,mode", [("agent_jb_stage_quotes", "auto"), ("agent_jb_stage_onsite", "off"),
                                      ("agent_jb_rt_stage_send", "off"), ("agent_jb_rt_stage_sort", "auto")])
def test_jobs_app_stage_reaches_open_panel(solo, person, desktop, quick, key, mode):
    js = JobsSettings(solo, person)
    panel = Jobs(desktop)
    js.pick(key, mode)
    _follows(desktop, panel.v[key], LABEL[mode])
    panel.v["agent_jb_quote_days"].set("7")                     # a Save of another field keeps the app's choice
    assert panel.save()[0] == "info"
    assert js.stored(key) == mode and js.stored("agent_jb_quote_days") == 7


def test_a_half_typed_desktop_box_is_left_alone(solo, person, desktop, quick):
    """The person's unsaved edit wins over the refresh — but only for that box."""
    js = JobsSettings(solo, person)
    panel = Jobs(desktop)
    panel.v["agent_jb_quote_days"].set("44")                    # typed, not saved
    js.pick("agent_jb_stage_quotes", "off")
    _follows(desktop, panel.v["agent_jb_stage_quotes"], LABEL["off"])
    assert panel.v["agent_jb_quote_days"].get() == "44"
    assert panel.save()[0] == "info"
    assert js.stored("agent_jb_quote_days") == 44 and js.stored("agent_jb_stage_quotes") == "off"


# ── Server: nothing from outside changes an agent setting, owner included ────
AGENT_KEYS = {"desk": ("agent_enabled", "agent_stage_intake", "agent_bk_stage_check", "agent_shadow"),
              "jobs": ("agent_jb_enabled", "agent_jb_stage_quotes", "agent_jb_rt_stage_send"),
              "hr": ("agent_hr_enabled", "agent_hr_stage_timeoff")}


def _snapshot(box):
    s = box.settings()
    return {sec: {k: s[sec].get(k) for k in keys} for sec, keys in AGENT_KEYS.items()}


@pytest.mark.parametrize("who", ["owner", "manager", "staff", "cris"])
def test_server_refuses_every_app_route(business, who):
    box = business
    before = _snapshot(box)
    for path, body in (("/settings", {"key": "agent_stage_intake", "value": "off"}),
                       ("/settings", {"settings": {"agent_enabled": False}}),
                       ("/agent/jobs", {"settings": {"agent_jb_stage_quotes": "off"}}),
                       ("/agent/jobs", {"key": "agent_jb_enabled", "value": False})):
        st, d = box.desk("POST", path, body, key=who)
        assert st >= 400, (who, path, st, d)
    st, d = box.hr("POST", "/agent/settings", {"settings": {"agent_hr_stage_timeoff": "off"}}, key=who)
    assert st >= 400, (who, st, d)
    assert _snapshot(box) == before


def test_server_refuses_the_tools(business):
    box = business
    before = _snapshot(box)
    r = box.tool("jobs_agent", action="set", settings='{"agent_jb_stage_quotes": "off"}')
    assert "On an AI-Prowler Server" in str(r), r
    assert _snapshot(box) == before


def test_server_refuses_the_jobs_apps_own_door(business):
    """What the Jobs app itself calls, signed in as the owner."""
    box = business
    before = _snapshot(box)
    st, d = http("POST", box.base + "/pwa-login", {"name": "ZAG Owner", "token": box.tokens["owner"]})
    assert st == 200 and d.get("access_token"), d
    st, d = http("POST", box.base + "/pwa-api/jobs_agent",
                 {"action": "set", "settings": '{"agent_jb_stage_quotes": "off"}'}, token=d["access_token"])
    assert "On an AI-Prowler Server" in str(d) or st >= 400, (st, d)
    assert _snapshot(box) == before
