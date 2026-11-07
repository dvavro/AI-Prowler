"""David 5 Nov: every agent setting stays in sync no matter where it's changed, and each app's refresh button really fetches.
Personal mode: the real desktop panels and the real app pages on the same sandbox files.

The desktop tests never press Save. That's the point: David changed On site to Off on the desktop, the panel showed it, and
it was never saved. The tests from 4 Nov all pressed Save first, so they couldn't see it.

The refresh tests stop the page's background timers first, and prove the page is NOT following by itself, so only the
button can be what brings the change in.
"""
from __future__ import annotations

import time

import pytest

import desk_agent_hr_store as hstore
import desk_agent_store as store
from test_matrix import _marks, setup, trigger
from test_review import _hr_tab
from test_settings_desk_pwa import Card
from test_settings_desktop import Agent, Jobs, LABEL, dga, tk
from test_settings_jobs_pwa import JobsSettings
from test_settings_sync import desktop  # noqa: F401 (a fixture)

WAIT = 12_000            # the apps look every 5 s
SETTLE = 1500            # longer than the desktop waits before saving
SLOW = 6500              # longer than the apps' 5 s look


def _value_is(page, sel, want, timeout=WAIT):
    page.wait_for_function("([s, w]) => { const e = document.querySelector(s); return e && e.value === w; }",
                           arg=[sel, str(want)], timeout=timeout)


def _settle(env, secs=SETTLE / 1000):
    """Really let the desktop run: its timers only fire while it's being pumped."""
    end = time.time() + secs
    while time.time() < end:
        env.root.update()
        time.sleep(0.02)


def _follow(env, var, want, secs=12):
    end = time.time() + secs
    while time.time() < end:
        env.show(250)
        if var.get() == want:
            return
    assert var.get() == want, (var.get(), want)


# ── changed on the desktop, nothing else pressed ─────────────────────────────
@pytest.mark.parametrize("key,mode", [("agent_stage_intake", "auto"), ("agent_stage_learn", "off"),     # Service Desk
                                      ("agent_bk_stage_decide", "auto"), ("agent_bk_stage_track", "off")])   # Booking
def test_desktop_to_service_desk_app_with_no_save(solo, person, desktop, key, mode):
    card = Card(solo, person)
    panel = Agent(desktop)
    panel.v[key].set(LABEL[mode])
    _settle(desktop)
    assert card.stored(key) == mode, "the panel shows it, but it was never saved"
    _value_is(card.page, f"#agentCard select[data-ag='{key}']", mode)


@pytest.mark.parametrize("key,mode", [("agent_jb_stage_onsite", "off"), ("agent_jb_stage_quotes", "auto"),      # Jobs, David's own case first
                                      ("agent_jb_rt_stage_route", "auto"), ("agent_jb_rt_stage_replan", "off")])  # Route flow
def test_desktop_to_jobs_app_with_no_save(solo, person, desktop, key, mode):
    app = JobsSettings(solo, person)
    panel = Jobs(desktop)
    panel.v[key].set(LABEL[mode])
    _settle(desktop)
    assert app.stored(key) == mode, "the panel shows it, but it was never saved"
    _value_is(app.page, f"#agSettings select[data-agk='{key}']", mode)


def test_desktop_jobs_change_also_reaches_the_service_desk_card(solo, person, desktop):
    card = Card(solo, person)
    panel = Jobs(desktop)
    panel.v["agent_jb_stage_quotes"].set(LABEL["off"])
    _settle(desktop)
    _value_is(card.page, "#agentCard select[data-agj='agent_jb_stage_quotes']", "off")


def test_desktop_switches_and_numbers_save_with_no_save(solo, person, desktop):
    JobsSettings(solo, person)
    panel = Jobs(desktop)
    panel.v["agent_jb_shadow"].set(False)
    panel.v["agent_jb_quote_days"].set("9")
    _settle(desktop)
    assert store.settings()["agent_jb_shadow"] is False and store.settings()["agent_jb_quote_days"] == 9


def test_desktop_service_desk_switch_and_number_save_with_no_save(solo, person, desktop):
    card = Card(solo, person)
    panel = Agent(desktop)
    panel.v["agent_shadow"].set(False)
    panel.v["agent_wait_hours"].set("33")
    _settle(desktop)
    assert card.stored("agent_shadow") is False and card.stored("agent_wait_hours") == 33


def test_desktop_hr_setting_saves_with_no_save(solo, desktop):
    class App:
        status_var = tk.StringVar(master=desktop.root)
    App.root = desktop.root
    fr = desktop.frame()
    sec = dga.build_standalone_section(App(), fr, "hr")
    sec["frame"].pack(fill="x")
    sec["show"].set(True)
    desktop.show()
    sec["vars"]["agent_hr_stage_compliance"].set(LABEL["off"])
    _settle(desktop)
    assert hstore.settings()["agent_hr_stage_compliance"] == "off"


def test_a_half_typed_bad_number_saves_nothing_and_shows_why(solo, person, desktop):
    JobsSettings(solo, person)
    panel = Jobs(desktop)
    before = store.settings()["agent_jb_quote_days"]
    panel.v["agent_jb_quote_days"].set("abc")
    panel.v["agent_jb_stage_prep"].set(LABEL["off"])
    _settle(desktop)
    assert not desktop.said, ("no popup while typing", desktop.said)
    assert store.settings()["agent_jb_quote_days"] == before
    panel.v["agent_jb_quote_days"].set("6")
    _settle(desktop)
    s = store.settings()
    assert s["agent_jb_quote_days"] == 6 and s["agent_jb_stage_prep"] == "off", "fixing it saves what was waiting"


def test_desktop_save_button_still_works(solo, person, desktop):
    JobsSettings(solo, person)
    panel = Jobs(desktop)
    panel.v["agent_jb_stage_learn"].set(LABEL["off"])
    panel.save()
    assert store.settings()["agent_jb_stage_learn"] == "off"


# ── changed in the app: the desktop follows ──────────────────────────────────
@pytest.mark.parametrize("key,mode", [("agent_stage_intake", "auto"), ("agent_bk_stage_decide", "auto")])
def test_service_desk_app_to_desktop(solo, person, desktop, key, mode):
    card = Card(solo, person)
    panel = Agent(desktop)
    card.pick(key, mode)
    _follow(desktop, panel.v[key], LABEL[mode])


@pytest.mark.parametrize("key,mode", [("agent_jb_stage_onsite", "off"), ("agent_jb_rt_stage_route", "auto")])
def test_jobs_app_to_desktop(solo, person, desktop, key, mode):
    app = JobsSettings(solo, person)
    panel = Jobs(desktop)
    app.pick(key, mode)
    _follow(desktop, panel.v[key], LABEL[mode])


def test_changes_from_both_places_are_both_kept(solo, person, desktop):
    app = JobsSettings(solo, person)
    panel = Jobs(desktop)
    panel.v["agent_jb_stage_prep"].set(LABEL["off"])     # on the desktop
    app.pick("agent_jb_stage_learn", "off")               # and in the app, before the desktop has saved
    _settle(desktop)
    _follow(desktop, panel.v["agent_jb_stage_learn"], LABEL["off"])
    s = store.settings()
    assert s["agent_jb_stage_prep"] == "off" and s["agent_jb_stage_learn"] == "off"
    _settle(desktop)
    assert panel.v["agent_jb_stage_prep"].get() == LABEL["off"], "the desktop's own change was put back"


def test_a_change_from_the_app_does_not_echo_a_save_back(solo, person, desktop):
    app = JobsSettings(solo, person)
    panel = Jobs(desktop)
    app.pick("agent_jb_stage_learn", "auto")
    _follow(desktop, panel.v["agent_jb_stage_learn"], LABEL["auto"])
    app.pick("agent_jb_stage_learn", "off")               # a stale echo from the desktop would undo this
    _follow(desktop, panel.v["agent_jb_stage_learn"], LABEL["off"])
    _settle(desktop)
    assert store.settings()["agent_jb_stage_learn"] == "off"


# ── the refresh button, with the background timers stopped ───────────────────
STOP = "() => { for (let i = 1; i < 100000; i++) { clearInterval(i); clearTimeout(i); } }"


def _big(btn):
    btn.wait_for(timeout=5000)
    b = btn.bounding_box()
    assert b["height"] >= 40 and b["width"] >= 100, b
    assert "Refresh" in btn.inner_text(), btn.inner_text()


def test_jobs_refresh_brings_in_a_saved_setting(solo, person):
    app = JobsSettings(solo, person)
    sel = "#agSettings select[data-agk='agent_jb_stage_onsite']"
    p = app.page
    p.evaluate(STOP)
    solo.settings(jobs={"agent_jb_stage_onsite": "off"})
    p.wait_for_timeout(SLOW)
    assert p.locator(sel).input_value() == "auto", "not stopped: the timer brought it in, so this proves nothing"
    p.locator("#agRefresh").click(timeout=5000)
    _value_is(p, sel, "off", timeout=4000)


def test_jobs_refresh_brings_in_the_status_too(solo, person):
    app = JobsSettings(solo, person)
    p = app.page
    p.evaluate(STOP)
    assert "practice mode" in p.locator("#agStatus").inner_text()
    solo.settings(jobs={"agent_jb_shadow": False})
    p.locator("#agRefresh").click(timeout=5000)
    p.wait_for_function("() => !document.querySelector('#agStatus').innerText.includes('Jobs agent on — practice mode')", timeout=4000)


def test_jobs_refresh_keeps_the_settings_open_and_is_big(solo, person):
    app = JobsSettings(solo, person)
    p = app.page
    _big(p.locator("#agRefresh"))
    p.locator("#agRefresh").click()
    p.wait_for_timeout(800)
    assert p.locator("#agSettings select").first.is_visible(), "the refresh closed the settings"


def test_desk_settings_refresh_brings_in_a_saved_setting(solo, person):
    card = Card(solo, person)
    sel = "#agentCard select[data-ag='agent_stage_learn']"
    before = card.page.locator(sel).input_value()
    want = "off" if before != "off" else "auto"
    p = card.page
    p.evaluate(STOP)
    solo.settings(desk={"agent_stage_learn": want})
    p.wait_for_timeout(SLOW)
    assert p.locator(sel).input_value() == before, "not stopped: the timer brought it in, so this proves nothing"
    p.locator("#refreshBtn").click(timeout=5000)
    _value_is(p, sel, want, timeout=4000)


def test_desk_agent_tab_refresh_brings_in_a_new_suggestion_and_is_big(business, person):
    from test_matrix import all_off
    box = business
    all_off(box)
    try:
        setup(box, "SD", "SUG")
        box.ai_reset("good", {"ticket:first_reply": [{"action": "reply", "body": "ZAG draft for refresh", "why": "ZAG", "confidence": 0.9}]})
        who = person(box, "owner")
        who.desk_sign_in("owner")
        who.page.locator("#tabAgent").click()
        p = who.page
        _big(p.locator("#agRefresh"))
        p.evaluate(STOP)
        trigger(box, "SD")
        box.agents_pass()
        box.agents_pass()
        p.wait_for_timeout(1000)
        assert not p.get_by_text("ZAG draft for refresh").count()
        p.locator("#agRefresh").click(timeout=5000)
        p.get_by_text("ZAG draft for refresh").first.wait_for(timeout=4000)
    finally:
        all_off(box)


def test_hr_refresh_brings_in_a_saved_setting_and_is_big(business, person):
    from test_matrix import all_off
    box = business
    all_off(box)
    try:
        setup(box, "HR", "SUG")
        admin = _hr_tab(person, box)
        p = admin.page
        _big(p.locator("#hrag-refresh"))
        sel = "#hrag-settings select[data-hrk='agent_hr_stage_compliance']"
        p.locator(sel).wait_for()
        p.evaluate(STOP)
        before = p.locator(sel).input_value()
        want = "off" if before != "off" else "auto"
        box.settings(hr={"agent_hr_stage_compliance": want})
        p.wait_for_timeout(SLOW)
        assert p.locator(sel).input_value() == before, "not stopped: the timer brought it in, so this proves nothing"
        p.locator("#hrag-refresh").click(timeout=5000)
        _value_is(p, sel, want, timeout=4000)
    finally:
        all_off(box)
