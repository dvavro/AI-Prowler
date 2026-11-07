"""AG-GR-40…52: HR time off on Auto, one condition broken at a time. The request goes in through HR's own API on the Business
sandbox; the agent answers "approve", and the guard decides. Any failed check leaves it with a person.
"""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START
from test_matrix import CUST_RE, HR_STAGES, JOB_RE, _marks, _new, all_off, off_stages

_n = itertools.count(1)
APPROVE = [{"action": "hr_approve_timeoff", "why": "ZAG every check passed", "confidence": 0.9}]


@pytest.fixture
def box(business):
    all_off(business)
    # a Tuesday, a week apart per test, so "approvals today" starts at zero
    day = START + dt.timedelta(days=(500 + 7 * next(_n)))
    day += dt.timedelta(days=(1 - day.weekday()) % 7)
    business.clock(day, "10:00")
    st, j = business.hr("POST", "/setup/complete", {"company_name": "ZAG Agents Co", "work_states": ["FL"], "setup_complete": True,
                                                    "hr_admin_email": "owner@time-machine.test",
                                                    "owner_email": "owner@time-machine.test"})
    assert st == 200, j
    business.today = day
    yield business
    all_off(business)


def _setup(box, *, mode="auto", practice=False, can=True, per_day=50, rule=None, **extra):
    box.ai_reset("good", {"hr:timeoff": rule or APPROVE})
    box.settings(hr={"agent_hr_enabled": True, "agent_hr_shadow": practice, "agent_hr_can_approve_timeoff": can,
                     "agent_hr_timeoff_max_days": 2, "agent_hr_timeoff_notice_days": 14, "agent_hr_timeoff_max_off": 1,
                     "agent_hr_timeoff_per_day": per_day, **off_stages("agent_hr_stage_", HR_STAGES, "timeoff", mode), **extra})


def _employee(box, *, dept=None, days=10):
    n = next(_n)
    st, j = box.hr("POST", "/employees", {
        "personal": {"first_name": "ZAG", "last_name": f"Off{n}", "personal_email": f"off{n}@time-machine.test", "phone": "", "address": ""},
        "employment": {"title": "Window tech", "department": dept or f"ZAG Dept {n}", "start_date": "2020-01-06", "work_state": "FL",
                       "employment_type": "full_time", "remote_status": "onsite", "manager_name": ""},
        "compensation": {"pay_type": "hourly", "pay_rate": 22}})
    assert st in (200, 201), j
    eid = (j.get("employee") or j)["id"]
    year = box.today.isoformat()
    for kind in ("pto", "sick"):
        st, a = box.hr("POST", "/pto/adjust", {"employee_id": eid, "days": days, "kind": kind, "date": year, "note": "ZAG"})
        assert st == 200, a
    return eid


def _weekday(box, plus):
    """A working day that isn't a company holiday (a holiday holds the request for its own reason, GR-46)."""
    d = box.today + dt.timedelta(days=plus)
    while True:
        st, j = box.hr("GET", f"/holidays?year={d.year}")
        off = {h["observed"] for h in (j.get("holidays") or [])} if st == 200 else set()
        if d.weekday() < 5 and d.isoformat() not in off:
            return d
        d += dt.timedelta(days=1)


def _ask(box, eid, *, plus=21, days=1, type_="PTO (Vacation)"):
    a = _weekday(box, plus)
    b = a + dt.timedelta(days=days - 1)
    st, j = box.hr("POST", "/pto/request", {"employee_id": eid, "type": type_, "start_date": a.isoformat(), "end_date": b.isoformat()})
    assert st == 201, j
    return j["request"]["id"]


def _run(box, eid, **kw):
    marks = _marks(box)
    rid = _ask(box, eid, **kw)
    props = []
    for _ in range(5):          # other tests' waiting requests can take the first passes
        box.agents_pass()
        props = [p for p in _new(box, marks, "HR")[1] if p["ref"] == f"pto:{rid}"]
        if props:
            break
    return rid, props


def _status(box, rid):
    st, j = box.hr("GET", "/pto")
    assert st == 200, j
    rows = j.get("requests") or j
    return next(r for r in rows if r["id"] == rid)["status"]


def test_gr_51_all_checks_hold_it_is_approved(box):
    _setup(box)
    rid, props = _run(box, _employee(box))
    assert props and props[0]["status"] == "applied", props
    assert _status(box, rid) == "approved"


def test_gr_sick_day_needs_no_notice(box):
    _setup(box)
    rid, props = _run(box, _employee(box), plus=1, type_="Sick")
    assert props and props[0]["status"] == "applied", props


@pytest.mark.parametrize("settings,ask,balance,why", [
    ({"can": False}, {}, 10, "isn't allowed to approve"),
    ({"mode": "suggest"}, {}, 10, "isn't allowed to approve"),
    ({}, {"type_": "Unpaid leave"}, 10, "not paid time off"),
    ({}, {"type_": "FMLA"}, 10, "not paid time off"),
    ({}, {"type_": "Jury duty"}, 10, "not paid time off"),
    ({}, {"type_": "Other"}, 10, "not paid time off"),
    ({}, {"days": 3, "plus": 22}, 10, "longer than the agent may approve"),
    ({}, {"plus": 5}, 10, "not enough notice"),
    ({}, {}, -300, "the balance doesn't cover it"),
], ids=["gr40-switch-off", "gr41-suggest", "gr42-unpaid", "gr42-fmla", "gr42-jury", "gr42-other", "gr44-too-long", "gr45-notice", "gr43-balance"])
def test_gr_40_to_45_a_person_decides(box, settings, ask, balance, why):
    _setup(box, **settings)
    rid, props = _run(box, _employee(box, days=balance), **ask)
    approve = [p for p in props if p["action"] == "hr_approve_timeoff"]
    assert approve and approve[0]["status"] == "pending" and why in approve[0]["hold_reason"], props
    assert _status(box, rid) == "pending"


def test_gr_41_practice_only_shows(box):
    _setup(box, practice=True)
    rid, props = _run(box, _employee(box))
    assert props and props[0]["status"] == "practice", props
    assert _status(box, rid) == "pending"


def test_gr_47_most_off_a_day(box):
    _setup(box)
    dept = f"ZAG Shared {next(_n)}"
    first, props = _run(box, _employee(box, dept=dept))
    assert props[0]["status"] == "applied", props
    rid, props = _run(box, _employee(box, dept=dept))
    assert props[0]["status"] == "pending" and "too many people off" in props[0]["hold_reason"], props


def test_gr_49_something_flagged_on_them(box):
    eid = _employee(box)
    box.ai_reset("good", {"hr:onboard": [{"action": "hr_flag", "flag": "other", "detail": f"ZAG about {eid}", "why": "ZAG",
                                          "confidence": 0.9}], "hr:timeoff": APPROVE})
    box.settings(hr={"agent_hr_enabled": True, "agent_hr_shadow": False, "agent_hr_can_approve_timeoff": True,
                     "agent_hr_timeoff_max_days": 2, "agent_hr_timeoff_notice_days": 14, "agent_hr_timeoff_max_off": 1,
                     "agent_hr_timeoff_per_day": 50, **off_stages("agent_hr_stage_", HR_STAGES, "onboard", "auto"),
                     "agent_hr_stage_timeoff": "auto"})
    box.agents_pass()
    rid, props = _run(box, eid)
    assert props and props[0]["status"] == "pending" and "flagged" in props[0]["hold_reason"], props


def test_gr_50_approvals_a_day(box):
    _setup(box, per_day=1)
    _, props = _run(box, _employee(box))
    assert props[0]["status"] == "applied", props
    _, props = _run(box, _employee(box))
    assert props[0]["status"] == "pending" and "daily limit" in props[0]["hold_reason"], props


def test_gr_confidence_075_waits(box):
    _setup(box, rule=[{**APPROVE[0], "confidence": 0.75}])
    _, props = _run(box, _employee(box))
    assert props[0]["status"] == "pending" and "confidence 0.75" in props[0]["hold_reason"], props


def test_gr_52_the_agent_can_never_deny(box):
    _setup(box, rule=[{"action": "hr_deny", "why": "ZAG", "confidence": 0.99}])
    rid, props = _run(box, _employee(box))
    assert not [p for p in props if p["status"] == "applied"], props
    assert _status(box, rid) == "pending"


# ── GR-46: blackout dates (HR Admin → Settings → Time Off Policy) and paid holidays (David 4 Nov) ─────
def _blackouts(box, entries):
    return box.hr("POST", "/pto/policy", {"blackout_dates": entries})


@pytest.fixture
def clean(box):
    yield box
    assert _blackouts(box, [])[0] == 200


@pytest.mark.parametrize("shape", ["one-day", "range"])
def test_gr_46_a_blackout_date_waits_for_a_person(clean, shape):
    box = clean
    _setup(box)
    day = _weekday(box, 21)
    entry = day.isoformat() if shape == "one-day" else f"{day - dt.timedelta(days=1)} to {day + dt.timedelta(days=1)}"
    assert _blackouts(box, [entry])[0] == 200
    rid, props = _run(box, _employee(box))
    assert props and props[0]["status"] == "pending" and "a blackout date" in props[0]["hold_reason"], props
    assert _status(box, rid) == "pending"


def test_gr_46_other_days_still_go_through(clean):
    box = clean
    _setup(box)
    assert _blackouts(box, [_weekday(box, 40).isoformat()])[0] == 200
    rid, props = _run(box, _employee(box))
    assert props and props[0]["status"] == "applied", props


def test_gr_46_a_paid_holiday_waits_for_a_person(box):
    _setup(box)
    st, j = box.hr("GET", f"/holidays?year={box.today.year + 1}")
    assert st == 200, j
    day = next(h["observed"] for h in j["holidays"] if h["paid"] and dt.date.fromisoformat(h["observed"]).weekday() < 5)
    eid = _employee(box)
    marks = _marks(box)
    st, r = box.hr("POST", "/pto/request", {"employee_id": eid, "type": "PTO (Vacation)", "start_date": day, "end_date": day})
    assert st == 201, r
    box.agents_pass()
    props = [p for p in _new(box, marks, "HR")[1] if p["ref"] == f"pto:{r['request']['id']}"]
    assert props and props[0]["status"] == "pending" and "a company holiday" in props[0]["hold_reason"], props


@pytest.mark.parametrize("bad", ["next friday", "2026-13-01", "2026-12-31 to 2026-12-24", "2026-01-01 to 2028-01-01",
                                 "2026-12-01 to 2026-12-02 to 2026-12-03"])
def test_blackout_bad_values_are_refused_and_nothing_changes(clean, bad):
    box = clean
    assert _blackouts(box, ["2030-01-02"])[0] == 200
    st, j = _blackouts(box, ["2030-01-03", bad])
    assert st == 400 and j.get("error"), (st, j)
    assert box.hr("GET", "/pto/policy")[1]["blackout_dates"] == ["2030-01-02"]


def test_blackout_only_hr_admin_can_set_them(clean):
    box = clean
    st, _ = box.hr("POST", "/pto/policy", {"blackout_dates": ["2030-01-02"]}, key="cris")
    assert st in (401, 403)
    assert box.hr("GET", "/pto/policy")[1]["blackout_dates"] == []


def test_blackout_box_in_hr_admin_saves_and_stays(clean, person):
    box = clean
    admin = person(box, "hr-admin")
    admin.hr_admin_sign_in()
    p = admin.page
    p.locator("[data-tab='settings']").first.evaluate("b => { b.scrollIntoView({block: 'center'}); b.click(); }")
    p.locator("#pp-blackout").wait_for()
    p.locator("#pp-blackout").fill("2030-12-24 to 2030-12-31\n2030-07-04")
    p.locator("#pto-policy-body button.btn-primary").click()
    p.locator("text=Time-off policy saved").first.wait_for()
    assert box.hr("GET", "/pto/policy")[1]["blackout_dates"] == ["2030-07-04", "2030-12-24 to 2030-12-31"]
    p.wait_for_function("document.getElementById('pp-blackout').value.includes('2030-07-04')")
    assert not admin.errors, admin.errors


@pytest.mark.parametrize("crew", ["{name}", "Pat Other, {name}"], ids=["alone", "shared"])
def test_gr_48_booked_jobs_that_day_wait_for_a_person(box, crew):
    _setup(box)
    eid = _employee(box)
    st, e = box.hr("GET", f"/employees/{eid}")
    assert st == 200, e
    name = f"{(e.get('employee') or e)['first_name']} {(e.get('employee') or e)['last_name']}"
    r = box.tool("create_customer", updates={"Customer Name / Company": f"ZAG Crew Job {eid}", "Phone": "386-555-0177"})
    cid = re.search(CUST_RE, r or "")
    assert cid, r
    made = box.tool("create_job", updates={"CustomerID": cid.group(0), "Customer Name / Company": f"ZAG Crew Job {eid}",
                                           "Service Type": "Window", "Job Status": "Scheduled",
                                           "Crew / Technician": crew.format(name=name),
                                           "Service Date": _weekday(box, 21).isoformat()})
    assert re.search(JOB_RE, made or ""), made
    rid, props = _run(box, eid)
    assert props and props[0]["status"] == "pending" and "booked jobs" in props[0]["hold_reason"], props
