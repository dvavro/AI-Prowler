"""David 4 Nov: a change saved in AI-Prowler on the PC shows in the open app by itself, and the ↻ control on each app
fetches it at once. The app page stays open (no reload) while the real desktop panel saves into the same sandbox files.
"""
from __future__ import annotations

import re

import pytest

from conftest import http
from test_settings_desk_pwa import Card
from test_settings_desktop import Agent, Jobs, LABEL, dga
from test_settings_jobs_pwa import JobsSettings
from test_settings_sync import desktop  # noqa: F401 — the fixture

WAIT = 12_000                                                   # the apps look every 5 s


def _value_is(page, sel, want, timeout=WAIT):
    page.wait_for_function("([s, w]) => { const e = document.querySelector(s); return e && e.value === w; }",
                           arg=[sel, str(want)], timeout=timeout)


# ── Service Desk app, card left open ─────────────────────────────────────────
@pytest.mark.parametrize("key,mode", [("agent_stage_intake", "auto"), ("agent_stage_learn", "off"),
                                      ("agent_bk_stage_decide", "auto"), ("agent_bk_stage_track", "off")])
def test_desk_app_follows_a_desktop_stage(solo, person, desktop, key, mode):
    card = Card(solo, person)
    panel = Agent(desktop)
    panel.v[key].set(LABEL[mode])
    assert panel.save()[0] == "ok"
    _value_is(card.page, f"#agentCard select[data-ag='{key}']", mode)


def test_desk_app_follows_numbers_text_and_switches(solo, person, desktop):
    card = Card(solo, person)
    panel = Agent(desktop)
    shadow = panel.v["agent_shadow"].get()
    panel.v["agent_wait_hours"].set("11")
    panel.v["agent_name"].set("Desk Top")
    panel.v["agent_shadow"].set(not shadow)
    panel.v["h0"].set("8")
    assert panel.save()[0] == "ok"
    p = card.page
    _value_is(p, "#agWait", "11")
    _value_is(p, "#agName", "Desk Top")
    _value_is(p, "#agH0", "8")
    assert p.locator("#agentCard [data-agb='agent_shadow']").is_checked() is (not shadow)
    p.get_by_text("Desk Top", exact=False).first.wait_for()    # the "how customers see it" line too


def test_desk_app_follows_the_jobs_section_of_its_card(solo, person, desktop):
    card = Card(solo, person)
    panel = Jobs(desktop)
    panel.v["agent_jb_stage_quotes"].set(LABEL["off"])
    panel.v["agent_jb_quote_days"].set("13")
    assert panel.save()[0] == "info"
    _value_is(card.page, "#agentCard select[data-agj='agent_jb_stage_quotes']", "off")
    _value_is(card.page, "#jbQuote", "13")


def test_desk_app_leaves_a_half_typed_box_alone(solo, person, desktop):
    card = Card(solo, person)
    card.type("#agWait", "77")                                  # typed, not saved
    card.page.locator("#agSignoff").click()                     # focus moves on
    panel = Agent(desktop)
    panel.v["agent_stage_intake"].set(LABEL["off"])
    panel.v["agent_wait_hours"].set("9")
    assert panel.save()[0] == "ok"
    _value_is(card.page, "#agentCard select[data-ag='agent_stage_intake']", "off")
    assert card.page.locator("#agWait").input_value() == "77"


def test_desk_app_tab_follows_agent_on(solo, person, desktop):
    card = Card(solo, person)
    assert card.page.locator("#tabAgent").is_visible()
    panel = Agent(desktop)
    panel.v["agent_enabled"].set(False)
    assert panel.save()[0] == "ok"
    card.page.locator("#tabAgent").wait_for(state="hidden", timeout=WAIT)
    panel.v["agent_enabled"].set(True)
    assert panel.save()[0] == "ok"
    card.page.locator("#tabAgent").wait_for(state="visible", timeout=WAIT)


def test_desk_refresh_button_shows_it_at_once(solo, person, desktop):
    card = Card(solo, person)
    panel = Agent(desktop)
    panel.v["agent_stage_resolution"].set(LABEL["off"])
    assert panel.save()[0] == "ok"
    card.page.locator("#refreshBtn").click()
    _value_is(card.page, "#agentCard select[data-ag='agent_stage_resolution']", "off", timeout=4_000)


# ── Jobs app, settings left open ─────────────────────────────────────────────
@pytest.mark.parametrize("key,mode", [("agent_jb_stage_quotes", "auto"), ("agent_jb_stage_onsite", "off"),
                                      ("agent_jb_rt_stage_send", "off")])
def test_jobs_app_follows_a_desktop_stage(solo, person, desktop, key, mode):
    js = JobsSettings(solo, person)
    panel = Jobs(desktop)
    panel.v[key].set(LABEL[mode])
    assert panel.save()[0] == "info"
    _value_is(js.page, f"#agSettings select[data-agk='{key}']", mode)
    assert js.page.locator("#agSettingsBox").get_attribute("open") is not None     # it didn't collapse


def test_jobs_app_follows_numbers_and_the_status_line(solo, person, desktop):
    js = JobsSettings(solo, person)
    panel = Jobs(desktop)
    panel.v["agent_jb_quote_days"].set("13")
    panel.v["agent_jb_remind_days"].set("5, 10")
    panel.v["agent_jb_route_send_hour"].set("7")
    panel.v["agent_jb_enabled"].set(False)
    assert panel.save()[0] == "info"
    p = js.page
    _value_is(p, "#agQuote", "13")
    _value_is(p, "#agRemind", "5, 10")
    _value_is(p, "#agRtHour", "7")
    p.locator("#agStatus", has_text="Jobs agent off").wait_for(timeout=WAIT)


def test_jobs_app_leaves_a_half_typed_box_alone(solo, person, desktop):
    js = JobsSettings(solo, person)
    js.p.type("#agQuote", "44")                                 # typed, not saved
    js.page.locator("#agPrep").click()
    panel = Jobs(desktop)
    panel.v["agent_jb_stage_learn"].set(LABEL["off"])
    panel.v["agent_jb_quote_days"].set("9")
    assert panel.save()[0] == "info"
    _value_is(js.page, "#agSettings select[data-agk='agent_jb_stage_learn']", "off")
    assert js.page.locator("#agQuote").input_value() == "44"


def test_jobs_refresh_button_shows_it_at_once(solo, person, desktop):
    js = JobsSettings(solo, person)
    panel = Jobs(desktop)
    panel.v["agent_jb_stage_prep"].set(LABEL["off"])
    assert panel.save()[0] == "info"
    js.page.locator("#screen-agent button[title='Refresh']").click()
    _value_is(js.page, "#agSettings select[data-agk='agent_jb_stage_prep']", "off", timeout=4_000)


# ── The ↻ on the other screens ───────────────────────────────────────────────
def test_hr_admin_refresh_and_auto_follow_on_a_server(business, person):
    box = business
    st, j = box.hr("POST", "/setup/complete", {"company_name": "ZAG Agents Co", "work_states": ["FL"], "setup_complete": True,
                                               "hr_admin_email": "owner@time-machine.test",
                                               "owner_email": "owner@time-machine.test"})
    assert st == 200, j
    box.settings(hr={"agent_hr_enabled": True, "agent_hr_stage_recruit": "suggest", "agent_hr_stage_learn": "suggest"})
    admin = person(box, "hr-admin")
    admin.hr_admin_sign_in()
    p = admin.page
    p.locator("[data-tab='agent']").first.evaluate("b => { b.scrollIntoView({block: 'center'}); b.click(); }")
    p.locator("#hrag-settings select").first.wait_for()
    box.settings(hr={"agent_hr_stage_recruit": "off"})          # what the server PC's desktop does
    p.locator("#btn-global-refresh").evaluate("b => b.click()")
    _value_is(p, "#hrag-settings select[data-hrk='agent_hr_stage_recruit']", "off", timeout=4_000)
    box.settings(hr={"agent_hr_stage_learn": "off"})            # no click: it follows by itself
    _value_is(p, "#hrag-settings select[data-hrk='agent_hr_stage_learn']", "off")
    box.settings(hr={"agent_hr_enabled": False})


def test_jobs_server_read_only_settings_follow_too(business, person):
    box = business
    box.settings(jobs={"agent_jb_enabled": True, "agent_jb_stage_repeat": "suggest"})
    owner = person(box, "owner")
    owner.jobs_sign_in()
    owner.page.locator("#navAgent").click()
    owner.page.locator("#agSettingsBox summary").click()
    owner.page.locator("#agSettings select").first.wait_for()
    box.settings(jobs={"agent_jb_stage_repeat": "off"})
    _value_is(owner.page, "#agSettings select[data-agk='agent_jb_stage_repeat']", "off")
    assert owner.page.locator("#agSettings select[data-agk='agent_jb_stage_repeat']").is_disabled()
    box.settings(jobs={"agent_jb_enabled": False})


def test_remote_app_refresh_button(solo, person):
    """The field app has no agent settings; its ↻ must still work and fetch again."""
    who = person(solo, "crew")
    p = who.page
    p.goto(solo.base + "/remote/")
    p.locator("#authInput").wait_for()
    who.type("#authInput", solo.token)
    p.keyboard.press("Enter")
    p.locator("#refreshBtn").wait_for(state="visible")
    who.pause(800)
    calls = []
    p.on("request", lambda r: calls.append(r.url) if re.search(r"/(mcp|api|pwa|remote)", r.url) else None)
    p.locator("#refreshBtn").click()
    p.wait_for_timeout(1500)
    assert calls, "the Remote app's refresh button fetched nothing"
    assert not who.errors, who.errors


def test_hr_portal_refresh_handlers_exist(business, person):
    """The employee portal's three ↻ buttons call these. Signing in as an employee comes with the HR workflows."""
    who = person(business, "employee")
    who.page.goto(business.base + "/hr_portal/")
    for fn in ("renderMyTeam", "loadPortalMessages", "loadSentReports"):
        assert who.page.evaluate(f"typeof {fn}") == "function", fn


# ── The Service Desk card's own Jobs boxes (they skipped the F-3 to F-6 fixes) ────
@pytest.fixture
def card(solo, person):
    return Card(solo, person)


def _jobs_stored(box, key):
    return box.settings()["jobs"][key]


@pytest.mark.parametrize("box_id,value,key", [("#jbMax", "-1", "agent_jb_invoice_max"), ("#jbMax", "12.50", "agent_jb_invoice_max"),
                                              ("#jbPerDay", "0", "agent_jb_invoices_per_day"),
                                              ("#jbQuote", "0", "agent_jb_quote_days"), ("#jbHour", "24", "agent_jb_prep_hour")])
def test_desk_card_jobs_box_refuses_bad_values(card, box_id, value, key):
    before = _jobs_stored(card.box, key)
    card.type(box_id, value)
    card.save("#jbSave")
    card.page.locator("#toast", has_text="whole number").first.wait_for(state="visible", timeout=5_000)
    assert _jobs_stored(card.box, key) == before


def test_desk_card_jobs_save_is_all_or_nothing(card):
    before = _jobs_stored(card.box, "agent_jb_quote_days")
    st, d = card.box.desk("POST", "/agent/jobs", {"settings": {"agent_jb_quote_days": before + 1,
                                                               "agent_jb_remind_days": [30, 7]}})
    assert st == 400, (st, d)
    assert _jobs_stored(card.box, "agent_jb_quote_days") == before


def test_desk_card_route_hour_refuses_decimals(card):
    before = _jobs_stored(card.box, "agent_jb_route_send_hour")
    card.type("#rtHour", "7.5")
    card.save("#rtSave")
    card.page.locator("#toast", has_text="Hour").first.wait_for(state="visible", timeout=5_000)
    assert _jobs_stored(card.box, "agent_jb_route_send_hour") == before


def test_server_login_api_still_refuses_the_card_route(business):
    st, d = http("POST", business.base + "/desk-api/agent/jobs", {"key": "agent_jb_enabled", "value": True},
                 token=business.desk_token("owner"))
    assert st >= 400, (st, d)
