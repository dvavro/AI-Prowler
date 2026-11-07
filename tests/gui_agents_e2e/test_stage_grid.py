"""AG-ST (AGENTS_GUI_E2E_TEST_SPEC.md §5.3): one stage on its own, in each mode, with its own real trigger and one agent pass.
Stages with no trigger here yet are listed in the spec, §17. Notes and flags are FREE, so Suggest may apply them (§12): the
check on Suggest and Auto is that the stage ran and nothing failed.
"""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START, code_from, http
from test_env import CUST_RE, JOB_RE
from test_guardrails_booking import CODE, _book, _windows
from test_customer_book_quote import _services
from test_matrix import DB, KIND, _api_calls, _marks, _new, all_off, setup, trigger

_n = itertools.count(1)
MODES = ["off", "inactive", "practice", "suggest", "auto"]


def _day(box):
    day = START + dt.timedelta(days=1000 + 7 * next(_n))
    box.clock(day, "10:00")
    return day


def _customer(box):
    n = next(_n)
    r = box.tool("create_customer", updates={"Customer Name / Company": f"ZAG Grid {n}", "Phone": "386-555-0177",
                                             "Street Address": "200 Canal St", "City": "New Smyrna Beach", "State": "FL", "Zip": "32168"})
    return re.search(CUST_RE, r or "").group(0), f"ZAG Grid {n}"


def _job(box, day, **more):
    cid, name = _customer(box)
    r = box.tool("create_job", updates={"CustomerID": cid, "Customer Name / Company": name, "Service Type": "Window",
                                        "Street Address": "200 Canal St", **more})
    assert "JOB-" in (r or ""), r
    return r


def t_ticket(box):
    trigger(box, "SD")


def t_booked(box):
    _day(box)
    box.settings(desk={"portal_enabled": True, "booking_paths": ["book", "new", "problem"], "booking_approval": "approve_all"})
    _services(box)
    _book(box, _windows(box)[0])


def t_no_date(box):
    trigger(box, "BK")


def t_schedule(box):
    _job(box, _day(box), **{"Job Status": "Unscheduled"})


def t_prep(box):
    trigger(box, "JB")


def t_done_today(box):
    d = _day(box)
    _job(box, d, **{"Job Status": "Completed", "Service Date": d.isoformat()})


def t_recurring_done(box):
    d = _day(box)
    _job(box, d, **{"Job Status": "Completed", "Service Date": d.isoformat(), "Recurrence": "Monthly"})


def t_routed(box):
    d = _day(box)
    _job(box, d, **{"Job Status": "Scheduled", "Service Date": (d + dt.timedelta(days=1)).isoformat()})


def t_sort(box):
    trigger(box, "RT")


def t_new_hire(box):
    trigger(box, "HR")


def _sql(box, sql, args=()):
    from pathlib import Path
    from db_access import DEFAULT_DB_FILENAME, DEFAULT_DB_SUBDIR, get_connection
    c = get_connection(str(Path(box.control("GET", "/state")["sandbox"]) / DEFAULT_DB_SUBDIR / DEFAULT_DB_FILENAME))
    try:
        rows = c.execute(sql, args).fetchall()
        c.commit()
        return rows
    finally:
        c.close()


def _customer_ticket(box):
    st, d = box.desk("POST", "/tickets", {"kind": "external", "title": f"ZAG grid {next(_n)}", "contact_name": "ZAG Maria",
                                          "contact_phone": "386-555-0142", "contact_email": "maria@time-machine.test"})
    assert st == 201, d
    return d["ticket"]["ticket_id"]


def t_closed_with_a_fix(box):
    tid = _customer_ticket(box)
    st, d = box.desk("POST", f"/tickets/{tid}/update", {"fields": {"resolution": "ZAG rewashed the windows"}, "reason": "ZAG"})
    assert st == 200, d
    st, d = box.desk("POST", f"/tickets/{tid}/state", {"to_state": "Closed", "reason": "ZAG fixed on site"})
    assert st == 200, d


def t_customer_replied_after_first_response(box):
    _day(box)
    box.settings(desk={"portal_enabled": True, "booking_paths": ["book", "new", "problem"]})
    n = next(_n)
    email = f"res{n}@time-machine.test"
    st, d = http("POST", box.base + "/support-api/start", {"name": f"ZAG Res {n}", "phone": f"386559{n:04d}", "email": email, "send_by": "email"})
    assert st == 200, d
    code = code_from([m for m in box.outbox() if m.get("to") == email and "request code" in str(m.get("subject"))][-1]["body"])
    st, v = http("POST", box.base + "/support-api/verify", {"contact_id": d["contact_id"], "code": code, "path": "problem", "title": "ZAG streaks"})
    assert st == 201, v
    st, view = http("GET", f"{box.base}/support-api/t/{v['token']}")
    tid = view["ticket"]["ticket_id"]
    st, m = box.desk("POST", f"/tickets/{tid}/messages", {"body": "ZAG we are on it", "visibility": "public"})
    assert st in (200, 201), m
    st, r = http("POST", f"{box.base}/support-api/t/{v['token']}/reply", {"body": "ZAG it still streaks"})
    assert st == 201, r


def t_customer_wrote_on_booking(box):
    t_booked(box)
    st, r = http("POST", f"{box.base}/support-api/t/{box.last_token}/reply", {"body": "ZAG can you come earlier?"})
    assert st == 201, r


def t_booked_visit_done(box):
    t_booked(box)
    jid = _sql(box, "SELECT job_id FROM booking_requests ORDER BY rowid DESC LIMIT 1")[0][0]
    _sql(box, "UPDATE jobs SET job_status = 'Completed' WHERE job_id = ?", (jid,))


def t_quote_open_past_followup(box):
    d = _day(box)
    cid, name = _customer(box)
    r = box.tool("create_quote", updates={"CustomerID": cid, "Customer Name / Company": name, "Service Type": "Window",
                                          "Quote Amount": 150, "Status": "Open", "Quote Date": d.isoformat()})
    assert "QUO" in (r or "").upper() or "quote" in (r or "").lower(), r
    box.clock(d + dt.timedelta(days=6), "10:00")


def t_invoice_unpaid_past_first_reminder(box):
    d = _day(box)
    r = _job(box, d, **{"Job Status": "Completed", "Service Date": d.isoformat()})
    jid = re.search(JOB_RE, r).group(0)
    r = box.tool("create_invoice", job_identifier=jid, quote_amount=100.0)
    assert "INV" in (r or "").upper(), r
    _sql(box, "UPDATE jobs SET invoice_sent_date = ? WHERE job_id = ?", (d.isoformat(), jid))
    box.clock(d + dt.timedelta(days=8), "10:00")


def t_new_applicant(box):
    st, j = box.hr("GET", "/recruiting")
    assert st == 200, j
    rec = j["recruiting"]
    rec["candidates"] = list(rec.get("candidates") or []) + [{"id": f"ZAG-CAND-{next(_n)}", "name": "ZAG Applicant", "status": "applied"}]
    st, d = box.hr("POST", "/recruiting", {**rec, "version": j["version"]})
    assert st == 200, d


def t_customer_waiting(box):
    from test_workflows import _customer_reports
    d = _day(box)
    box.settings(desk={"portal_enabled": True})
    _customer_reports(box, "ZAG nobody answered")
    box.clock(d, "16:00")


def t_visit_tomorrow_outdoors(box):
    t_booked(box)
    jid = _sql(box, "SELECT job_id FROM booking_requests ORDER BY rowid DESC LIMIT 1")[0][0]
    _sql(box, "UPDATE booking_requests SET status = 'scheduled' WHERE job_id = ?", (jid,))
    day = box.now().date() + dt.timedelta(days=1)
    _sql(box, "UPDATE jobs SET job_status = 'Scheduled', service_date = ? WHERE job_id = ?", (day.isoformat(), jid))
    _sql(box, "UPDATE booking_services SET outdoor = 1")
    box.settings(desk={"agent_bk_weather": True, "agent_bk_check_hour": 9})


def _hr_employee(box):
    return trigger(box, "HR")


def t_time_off(box):
    e = _hr_employee(box)
    eid = (e.get("employee") or e)["id"]
    day = (START + dt.timedelta(days=30)).isoformat()
    st, j = box.hr("POST", "/pto/request", {"employee_id": eid, "type": "PTO (Vacation)", "start_date": day, "end_date": day})
    assert st == 201, j


def t_training_overdue(box):
    e = _hr_employee(box)
    st, j = box.hr("POST", "/training", {"employee_id": (e.get("employee") or e)["id"], "title": "ZAG ladder safety",
                                         "due_date": (START - dt.timedelta(days=3)).isoformat()})
    assert st in (200, 201), j


def t_employee_message(box):
    st, j = box.hr("POST", "/messages", {"subject": "ZAG question", "message": "ZAG how many sick days do I get?", "body": "ZAG how many sick days do I get?"})
    assert st in (200, 201), j


def t_incident(box):
    st, j = box.hr("POST", "/incidents", {"type": "Injury", "description": "ZAG cut on a ladder"})
    assert st == 200, j


def t_monday(box):
    day = START + dt.timedelta(days=(7 - START.weekday()) % 7 + 7 * next(_n))
    box.clock(day, "09:00")


GRID = [("SD", "intake", t_ticket), ("SD", "first_reply", t_ticket), ("BK", "check", t_booked), ("BK", "decide", t_booked),
        ("BK", "offer", t_no_date), ("JB", "schedule", t_schedule), ("JB", "prep", t_prep), ("JB", "onsite", t_done_today),
        ("JB", "closeout", t_done_today), ("JB", "repeat", t_recurring_done), ("RT", "sort", t_sort), ("RT", "route", t_routed),
        ("HR", "onboard", t_new_hire),
        ("SD", "resolution", t_customer_replied_after_first_response), ("SD", "learn", t_closed_with_a_fix),
        ("SD", "follow_through", t_customer_waiting),
        ("BK", "reply", t_customer_wrote_on_booking), ("BK", "learn", t_booked_visit_done), ("BK", "track", t_visit_tomorrow_outdoors),
        ("JB", "quotes", t_quote_open_past_followup), ("JB", "collect", t_invoice_unpaid_past_first_reminder),
        ("HR", "recruit", t_new_applicant), ("HR", "timeoff", t_time_off), ("HR", "compliance", t_training_overdue),
        ("HR", "answer", t_employee_message), ("HR", "incidents", t_incident), ("HR", "learn", t_monday)]


def _set(box, section, stage, mode):
    if mode == "off":
        setup(box, section, "SUG", stage="none-of-them")
    elif mode == "inactive":
        setup(box, section, "OFF", stage=stage)
    else:
        setup(box, section, {"practice": "PRAC", "suggest": "SUG", "auto": "AUTO"}[mode], stage=stage)


def _cases():
    for section, stage, fn in GRID:
        for mode in MODES:
            for edition in (["business"] if section == "HR" else ["solo", "business"]):
                yield pytest.param(section, stage, fn, mode, edition, id=f"{KIND[section]}-{stage}-{mode}-{edition}")


@pytest.mark.parametrize("section,stage,fn,mode,edition", list(_cases()))
def test_st(request, section, stage, fn, mode, edition):
    box = request.getfixturevalue(edition)
    all_off(box)
    box.ai_reset("good", {})
    _set(box, section, stage, mode)
    marks = _marks(box)
    fn(box)
    box.agents_pass()
    q, p = _new(box, marks, section)
    q = [x for x in q if x["stage"] == stage]
    p = [x for x in p if x["stage"] == stage]
    calls = [c for c in _api_calls(box, KIND[section]) if c.get("stage") == stage]
    try:
        if mode in ("off", "inactive"):
            assert not q and not p and not calls, (q, p, calls)
            return
        assert q, ("nothing queued", _new(box, marks, section)[0])
        assert calls, "no AI call"
        assert not [x for x in p if x["status"] == "failed"], p
        if mode == "practice":
            assert all(x["status"] == "practice" for x in p), p
    finally:
        all_off(box)
