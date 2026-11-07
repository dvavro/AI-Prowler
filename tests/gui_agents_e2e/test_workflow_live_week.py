"""AG-WF-13: a live week. Every agent on Auto at once, Monday to Friday, in the Business sandbox. One test, because the point is that they run together."""
from __future__ import annotations

import datetime as dt

from conftest import START, http
from test_customer_book_quote import _services
from test_guardrails_booking import _windows
from test_matrix import BK_STAGES, DB, HR_STAGES, HR_TEXT, JB_STAGES, REPLY, RT_STAGES, SD_STAGES, _rows, all_off, setup, trigger
from test_stage_grid import _sql
from test_workflows_3 import _request_no_date
from test_workflows_routes import _job

PREP = "ZAG live week prep note."
KINDS = {"tickets": {"ticket", "booking"}, "jobs_agent": {"job", "route"}, "hr_agent": {"hr"}}


def _auto(prefix, stages, *on):
    return {f"{prefix}{s}": ("auto" if s in on else "off") for s in stages}


def _passes(box, n=3):
    for _ in range(n):
        box.agents_pass()


def _done(box, db, action, marks):
    return [p for p in _rows(box, db) if p["proposal_id"] not in marks[db] and p["action"] == action]


def test_wf_13_a_live_week_with_every_agent_on(business):
    box = business
    all_off(box)
    try:
        monday = START + dt.timedelta(days=28000)
        while monday.weekday() != 0:
            monday += dt.timedelta(days=1)
        box.clock(monday, "10:00")
        _sql(box, "UPDATE jobs SET job_status = 'Complete' WHERE LOWER(COALESCE(job_status, '')) NOT IN ('complete', 'completed', 'cancelled', 'canceled')")
        _sql(box, "UPDATE booking_requests SET status = 'cancelled' WHERE status IN ('pending', 'requested', 'suggested', 'reschedule')")
        box.settings(desk={"portal_enabled": True, "booking_paths": ["book", "new", "problem"], "booking_approval": "approve_all"})
        _services(box)
        setup(box, "HR", "AUTO")               # finishes HR setup too
        box.clock(monday + dt.timedelta(days=1), "10:00")      # times that are still open on Tuesday, when they're offered
        keys = _windows(box)[:3]
        assert keys
        box.clock(monday, "10:00")
        box.ai_reset("good", {
            "ticket:first_reply": [{"action": "reply", "body": REPLY, "why": "ZAG", "confidence": 0.9}],
            "booking:offer": [{"action": "bk_offer_times", "window_keys": keys, "note": "ZAG", "why": "ZAG", "confidence": 0.9}],
            "booking:decide": [{"action": "bk_approve", "window_key": keys[0], "why": "ZAG", "confidence": 0.9}],
            "job:prep": [{"action": "jb_prep_note", "body": PREP, "why": "ZAG", "confidence": 0.9}],
            "route:route": [{"action": "rt_route_day", "why": "ZAG", "confidence": 0.9}],
            "route:send": [{"action": "rt_send", "why": "ZAG", "confidence": 0.9}],
            "hr:onboard": [{"action": "hr_remind_employee", "body": HR_TEXT, "why": "ZAG", "confidence": 0.9}]})
        box.settings(desk={"agent_enabled": True, "agent_shadow": False, "agent_bk_enabled": True, "agent_bk_shadow": False,
                           "agent_bk_can_confirm": True, "agent_bk_confirm_per_day": 50,
                           **_auto("agent_stage_", SD_STAGES, "first_reply"), **_auto("agent_bk_stage_", BK_STAGES, "offer", "decide")},
                     jobs={"agent_jb_enabled": True, "agent_jb_shadow": False, "agent_jb_rt_enabled": True, "agent_jb_rt_shadow": False,
                           **_auto("agent_jb_stage_", JB_STAGES, "prep"), **_auto("agent_jb_rt_stage_", RT_STAGES, "route", "send")},
                     hr={"agent_hr_enabled": True, "agent_hr_shadow": False, **_auto("agent_hr_stage_", HR_STAGES, "onboard")})
        marks = {db: {p["proposal_id"] for p in _rows(box, db)} for db in KINDS}
        blocked0, calls0 = len(box.blocked()), len(box.ai_calls())
        spent0 = box.desk("GET", "/agent/inbox")[1]["status"].get("spent_usd") or 0

        # Monday: a customer's ticket, and a new hire
        tid = trigger(box, "SD")
        trigger(box, "HR")
        _passes(box)
        assert any(p["status"] == "applied" and p["ref"] == tid for p in _done(box, DB["SD"], "reply", marks)), _rows(box, "tickets")[-3:]
        assert [p for p in _done(box, DB["HR"], "hr_remind_employee", marks) if p["status"] == "applied"], _rows(box, "hr_agent")[-3:]

        # Tuesday: a booking request with no date gets times, the customer accepts, Decide confirms
        tue = monday + dt.timedelta(days=1)
        box.clock(tue, "10:00")
        token, email = _request_no_date(box)
        booked = _sql(box, "SELECT job_id FROM booking_requests ORDER BY rowid DESC LIMIT 1")[0][0]
        _sql(box, "UPDATE jobs SET latitude = 29.03, longitude = -80.90, crew = 'ZAG Crew Dee' WHERE job_id = ?", (booked,))   # no geocoding offline
        _passes(box)
        assert [p for p in _done(box, DB["BK"], "bk_offer_times", marks) if p["ref"] == booked and p["status"] == "applied"], _rows(box, "tickets")[:4]
        ticket = _sql(box, "SELECT ticket_id FROM booking_requests WHERE job_id = ?", (booked,))[0][0]
        assert not [p for p in _done(box, "tickets", "reply", marks) if p["ref"] == ticket], "F-24: the Service Desk agent answered a booking's ticket"
        st, r = http("POST", f"{box.base}/support-api/t/{token}/booking/accept", {})
        assert st == 200, r
        box.clock(tue, "10:30")
        _passes(box)
        assert _sql(box, "SELECT job_status FROM jobs WHERE job_id = ?", (booked,))[0][0] == "Scheduled"

        # Wednesday: tomorrow's jobs are routed, sent to the right person at the send hour, and a job with no address is flagged at Prep
        wed = monday + dt.timedelta(days=2)
        thu = wed + dt.timedelta(days=1)
        box.clock(wed, "10:00")
        cris, dee = _job(box, thu, 0, crew="ZAG Crew Cris"), _job(box, thu, 1, crew="ZAG Crew Dee")
        _passes(box)
        assert len([p for p in _done(box, "jobs_agent", "rt_route_day", marks) if thu.isoformat() in p["ref"] and p["status"] == "applied"]) == 2
        no_addr = _job(box, thu, 2, crew="ZAG Crew Cris")
        _sql(box, "UPDATE jobs SET street_address = '', latitude = NULL, longitude = NULL WHERE job_id = ?", (no_addr,))
        sent = len(box.outbox())
        box.clock(wed, "18:30")
        _passes(box)
        got = {m.get("to") for m in box.outbox()[sent:] if "Route for" in str(m.get("subject"))}
        assert got == {"cris@time-machine.test", "dee@time-machine.test"}, box.outbox()[sent:]
        assert [p for p in _done(box, "jobs_agent", "jb_prep_note", marks) if p["ref"] == no_addr and p["status"] == "applied"], str([(q["ref"], q["stage"], q["status"], q.get("reason"), q.get("note")) for q in _rows(box, "jobs_agent", "agent_queue")]) + str([(p["ref"], p["action"], p["status"], p.get("hold_reason"), p.get("result")) for p in _rows(box, "jobs_agent")]) + str(no_addr) + str(_sql(box, "SELECT job_status, service_date, street_address FROM jobs WHERE job_id = ?", (no_addr,))[0][0:3])

        # Friday: a quiet pass doesn't redo the week
        fri = monday + dt.timedelta(days=4)
        box.clock(fri, "10:00")
        total = sum(len(_rows(box, db)) for db in KINDS)
        _passes(box)
        assert sum(len(_rows(box, db)) for db in KINDS) == total, "something was worked twice"

        # The whole week
        for db, kinds in KINDS.items():
            new = [p for p in _rows(box, db) if p["proposal_id"] not in marks[db]]
            assert new and {p["kind"] for p in new} <= kinds, (db, new)
            assert not [p for p in new if p["status"] == "failed"], str([(p["ref"], p["action"], p.get("result")) for p in new if p["status"] == "failed"])
        used = {c["kind"] for c in box.ai_calls()[calls0:]}
        assert {"ticket", "booking", "job", "route", "hr"} <= used, used
        assert len(box.blocked()) == blocked0, box.blocked()[blocked0:]
        spent = box.desk("GET", "/agent/inbox")[1]["status"].get("spent_usd") or 0
        assert spent >= spent0, (spent0, spent)
    finally:
        all_off(box)
