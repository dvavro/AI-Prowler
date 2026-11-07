"""AG-JB-01…10 and AG-RT-01…06 — the Jobs app's 🤖 Agent → ⚙️ Jobs agent settings, field by field, on the Solo
sandbox (owner). On a server these are greyed out — test_settings_server_readonly.py.

Known differences from the spec are xfail(strict=True) findings (see test_settings_desk_pwa.py for the idea).
"""
from __future__ import annotations

import pytest

from conftest import HUMAN

JB_STAGES = ("quotes", "schedule", "prep", "onsite", "closeout", "collect", "repeat", "learn")
RT_STAGES = ("sort", "plan", "route", "send", "replan")
DEFAULTS = {"agent_jb_enabled": True, "agent_jb_shadow": True, "agent_jb_can_send_invoices": False,
            "agent_jb_invoice_max": 1000, "agent_jb_invoices_per_day": 10, "agent_jb_quote_days": 5,
            "agent_jb_remind_days": [7, 14, 30], "agent_jb_prep_hour": 16, "agent_jb_weather": True,
            "agent_jb_rt_enabled": False, "agent_jb_rt_shadow": True, "agent_jb_route_scope": "day",
            "agent_jb_sort_weekday": 4, "agent_jb_route_send_hour": 18,
            **{f"agent_jb_stage_{k}": ("auto" if k == "onsite" else "suggest") for k in JB_STAGES},
            **{f"agent_jb_rt_stage_{k}": "suggest" for k in RT_STAGES}}


class JobsSettings:
    def __init__(self, box, person):
        box.settings(jobs=DEFAULTS)
        self.box = box
        self.p = person(box, "owner")
        self.page = self.p.page
        self.p.jobs_sign_in()
        self.page.locator("#navAgent").click()
        self.page.locator("#agSettingsBox summary").click()
        self.page.locator("#agSettings select").first.wait_for()
        self.p.pause(600)

    def stored(self, key):
        return self.box.settings()["jobs"][key]

    def toast(self, text):
        self.page.locator("#toast.show", has_text=text).first.wait_for(timeout=10_000)
        self.page.wait_for_timeout(300 if not HUMAN else 900)
        self.page.evaluate("document.getElementById('toast').className = 'toast'")     # ready for the next one
        self.page.wait_for_load_state("networkidle")       # each save redraws the box (loadAgent) — let it finish

    def tick(self, key):
        c = self.page.locator(f"#agSettings input[data-agk='{key}']")
        c.scroll_into_view_if_needed()
        c.click()
        self.toast("Saved.")

    def pick(self, key, value):
        c = self.page.locator(f"#agSettings select[data-agk='{key}']")
        c.scroll_into_view_if_needed()
        c.select_option(str(value))
        self.toast("Saved.")

    def fill(self, **ids):
        for sel, v in ids.items():
            self.page.locator(f"#{sel}").scroll_into_view_if_needed()
            self.p.type(f"#{sel}", v)

    def save_jobs(self, **ids):
        base = {"agMax": 1000, "agPerDay": 10, "agQuote": 5, "agRemind": "7, 14, 30", "agPrep": 16}
        self.fill(**{**base, **ids})
        self.page.locator("#agSaveJ").click()


@pytest.fixture
def js(solo, person):
    return JobsSettings(solo, person)


def test_a_second_toast_gets_its_full_time(js):
    """showToast never cancelled the last toast's timer, so a second message could vanish at once (2026-11-03)."""
    js.page.evaluate("showToast('ZAG first')")
    js.page.wait_for_timeout(2400)
    js.page.evaluate("showToast('ZAG second')")
    js.page.wait_for_timeout(1000)                              # the first toast's timer has fired by now
    assert "show" in js.page.locator("#toast").get_attribute("class")


def test_jb_01_02_04_09_switches(js):
    for key in ("agent_jb_enabled", "agent_jb_shadow", "agent_jb_can_send_invoices", "agent_jb_weather"):
        before = js.stored(key)
        js.tick(key)
        assert js.stored(key) is (not before), key
        js.tick(key)
        assert js.stored(key) is before, key


@pytest.mark.parametrize("stage", JB_STAGES)
def test_jb_03_stage_modes(js, stage):
    js.tick("agent_jb_shadow")                                      # practice off: the diagram shows the mode itself
    for mode in ("off", "auto", "suggest"):
        js.pick(f"agent_jb_stage_{stage}", mode)
        assert js.stored(f"agent_jb_stage_{stage}") == mode
        step = js.page.locator(f"#agJbFlow [data-step='{stage}']")
        step.wait_for()
        assert step.get_attribute("data-chosen") == mode, (stage, mode)


def test_jb_05_to_10_numbers_valid(js):
    for vals in ({"agMax": 0, "agPerDay": 1, "agQuote": 1, "agRemind": "7", "agPrep": 0},
                 {"agMax": 100000, "agPerDay": 100, "agQuote": 60, "agRemind": "1, 120", "agPrep": 23},
                 {"agMax": 1000, "agPerDay": 10, "agQuote": 5, "agRemind": "7, 14, 30", "agPrep": 16}):
        js.save_jobs(**vals)
        js.toast("Saved.")
        got = js.box.settings()["jobs"]
        assert (got["agent_jb_invoice_max"], got["agent_jb_invoices_per_day"], got["agent_jb_quote_days"],
                got["agent_jb_remind_days"], got["agent_jb_prep_hour"]) == (
            vals["agMax"], vals["agPerDay"], vals["agQuote"],
            [int(x) for x in str(vals["agRemind"]).replace(",", " ").split()], vals["agPrep"]), vals


@pytest.mark.parametrize("field,value,msg,key", [
    ("agMax", 100001, "between", "agent_jb_invoice_max"),
    ("agPerDay", 101, "between", "agent_jb_invoices_per_day"),
    ("agQuote", 61, "between", "agent_jb_quote_days"),
    ("agPrep", 24, "between", "agent_jb_prep_hour"),
    ("agRemind", "30, 7", "smallest first", "agent_jb_remind_days"),
    ("agRemind", "7, 7", "different", "agent_jb_remind_days"),
    ("agRemind", "7, 14, 30, 60", "1-3", "agent_jb_remind_days"),
    ("agRemind", "0", "1 to 120", "agent_jb_remind_days"),
    ("agRemind", "121", "1 to 120", "agent_jb_remind_days"),
    ("agRemind", "7 x", "1 to 120", "agent_jb_remind_days"),
    ("agRemind", "", "1-3", "agent_jb_remind_days"),
])
def test_jb_05_to_10_numbers_refused(js, field, value, msg, key):
    before = js.stored(key)
    js.save_jobs(**{field: value})
    js.toast(msg)
    assert js.stored(key) == before, (field, value)


def test_jb_refused_value_saves_nothing_else(js):
    """A refused field must not leave the other fields of the same Save half-saved (F-6, fixed 2026-11-03)."""
    js.save_jobs(agMax=500, agPerDay=20, agQuote=9, agRemind="30, 7")
    js.toast("smallest first")
    got = js.box.settings()["jobs"]
    assert (got["agent_jb_invoice_max"], got["agent_jb_invoices_per_day"], got["agent_jb_quote_days"]) == (1000, 10, 5)


def test_jb_05_invoice_max_negative_refused(js):
    """F-3, fixed 2026-11-03: -1 used to be saved as $0."""
    js.save_jobs(agMax=-1)
    js.page.wait_for_timeout(1500)
    assert js.stored("agent_jb_invoice_max") == 1000


def test_jb_05_invoice_max_cents_refused(js):
    """F-4, fixed 2026-11-03: 12.50 used to be saved as 12."""
    js.save_jobs(agMax="12.50")
    js.page.wait_for_timeout(1500)
    assert js.stored("agent_jb_invoice_max") == 1000


def test_jb_06_07_zero_refused(js):
    """F-5, fixed 2026-11-03: 0 used to be saved as 10 / 5."""
    js.save_jobs(agPerDay=3, agQuote=4)
    js.toast("Saved.")
    js.save_jobs(agPerDay=0, agQuote=0)
    js.page.wait_for_timeout(1500)
    got = js.box.settings()["jobs"]
    assert (got["agent_jb_invoices_per_day"], got["agent_jb_quote_days"]) == (3, 4)


# ── Route flow ───────────────────────────────────────────────────────────────
def test_rt_01_02_switches(js):
    for key in ("agent_jb_rt_enabled", "agent_jb_rt_shadow"):
        before = js.stored(key)
        js.tick(key)
        assert js.stored(key) is (not before), key
        js.tick(key)
        assert js.stored(key) is before, key


@pytest.mark.parametrize("stage", RT_STAGES)
def test_rt_03_stage_modes(js, stage):
    js.tick("agent_jb_rt_enabled")
    js.tick("agent_jb_rt_shadow")
    for mode in ("off", "auto", "suggest"):
        js.pick(f"agent_jb_rt_stage_{stage}", mode)
        assert js.stored(f"agent_jb_rt_stage_{stage}") == mode
        step = js.page.locator(f"#agRtFlow [data-step='{stage}']")
        step.wait_for()
        assert step.get_attribute("data-chosen") == mode, (stage, mode)


def test_rt_04_05_scope_and_sort_day(js):
    for scope in ("week", "day"):
        js.pick("agent_jb_route_scope", scope)
        assert js.stored("agent_jb_route_scope") == scope
    for day in range(7):
        js.pick("agent_jb_sort_weekday", day)
        assert js.stored("agent_jb_sort_weekday") == day


def test_rt_06_send_hour(js):
    for h in (0, 23, 18):
        js.fill(agRtHour=h)
        js.page.locator("#agSaveR").click()
        js.toast("Saved.")
        assert js.stored("agent_jb_route_send_hour") == h
    for h in (-1, 24):
        js.fill(agRtHour=h)
        js.page.locator("#agSaveR").click()
        js.toast("0 to 23")
        assert js.stored("agent_jb_route_send_hour") == 18
