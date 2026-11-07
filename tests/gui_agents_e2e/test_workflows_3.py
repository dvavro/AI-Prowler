"""AG-WF-04, 05, 07 (AGENTS_GUI_E2E_TEST_SPEC.md §7), by route, plus GR-19 with a real mild forecast. The wait list in WF-05 and the
/remote/ check in WF-07 aren't here."""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START, code_from, http
from test_customer_book_quote import _services
from test_env import CUST_RE, JOB_RE
from test_guardrails_booking import CODE, _book, _windows
from test_matrix import BK_STAGES, JB_STAGES, SD_STAGES, _marks, _new, all_off, off_stages
from test_stage_grid import _sql

_n = itertools.count(1)


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    b.today = START + dt.timedelta(days=14000 + 28 * next(_n))
    while b.today.weekday() != 1:
        b.today += dt.timedelta(days=1)
    b.clock(b.today, "10:00")
    b.settings(desk={"portal_enabled": True, "booking_paths": ["book", "new", "problem"], "booking_approval": "approve_all"})
    _services(b)
    # Leftovers from other files would take the agent's turn before this test's own booking.
    _sql(b, "UPDATE booking_requests SET status = 'cancelled' WHERE status IN ('pending', 'requested', 'suggested', 'reschedule')")
    yield b
    b.control("POST", "/weather", {})
    all_off(b)


def _booking_on(box, *stages, **more):
    box.settings(desk={"agent_enabled": True, "agent_shadow": False, "agent_bk_enabled": True, "agent_bk_shadow": False,
                       **off_stages("agent_stage_", SD_STAGES),
                       **{f"agent_bk_stage_{s}": ("auto" if s in stages else "off") for s in BK_STAGES}, **more})


# ── WF-04: a request with no date, to confirmed ──────────────────────────────
def _request_no_date(box):
    n = next(_n)
    email = f"wf4{n}@time-machine.test"
    st, d = http("POST", box.base + "/support-api/start", {"name": f"ZAG Req {n}", "phone": f"386562{n:04d}", "email": email, "send_by": "email"})
    assert st == 200, d
    code = code_from([m for m in box.outbox() if m.get("to") == email and "request code" in str(m.get("subject"))][-1]["body"])
    st, v = http("POST", box.base + "/support-api/verify", {
        "contact_id": d["contact_id"], "code": code, "path": "new", "service_code": CODE, "service": "ZAG Exterior windows",
        "address": {"street": "300 Flagler Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169"},
        "preferred": "next week, mornings", "description": "ZAG no date"})
    assert st == 201, v
    return v["token"], email


def _offer(box, can_confirm=True, approve=0, mode="auto"):
    keys = _windows(box)[:3]
    box.ai_reset("good", {"booking:offer": [{"action": "bk_offer_times", "window_keys": keys, "note": "ZAG", "why": "ZAG", "confidence": 0.9}],
                          "booking:decide": [{"action": "bk_approve", "window_key": keys[approve], "why": "ZAG", "confidence": 0.9}]})
    _booking_on(box, "offer", "decide", agent_bk_can_confirm=can_confirm, agent_bk_confirm_per_day=50, agent_bk_stage_offer=mode)
    marks = _marks(box)
    token, email = _request_no_date(box)
    jid = _sql(box, "SELECT job_id FROM booking_requests ORDER BY rowid DESC LIMIT 1")[0][0]
    offer = []
    for _ in range(4):           # the queue may hold other files' items
        box.agents_pass()
        offer = [p for p in _new(box, marks, "BK")[1] if p["action"] == "bk_offer_times" and p["ref"] == jid]
        if offer:
            break
    assert offer, _new(box, marks, "BK")
    return keys, marks, token, email, offer[0]


def _job_now(box, jid):
    return dict(_sql(box, "SELECT job_status, service_date FROM jobs WHERE job_id = ?", (jid,))[0])


def _accept(box, token):
    st, r = http("POST", f"{box.base}/support-api/t/{token}/booking/accept", {})
    assert st == 200, r
    box.clock(box.today, "10:30")
    for _ in range(3):
        box.agents_pass()


def test_wf_04_accepting_an_ai_offer_is_confirmed_by_decide(box):
    keys, marks, token, email, offer = _offer(box)
    assert offer["status"] == "applied", offer
    _accept(box, token)
    ok = [p for p in _new(box, marks, "BK")[1] if p["action"] == "bk_approve"]
    assert ok and ok[0]["status"] == "applied", (ok, _new(box, marks, "BK")[0])
    row = _job_now(box, offer["ref"])
    assert row["job_status"] == "Scheduled" and row["service_date"] == keys[0][:10], row
    assert [m for m in box.outbox() if m.get("to") == email and "confirm" in (str(m.get("subject")) + str(m.get("body"))).lower()]


def test_wf_04_picking_another_time_goes_to_decide(box):
    keys, marks, token, email, offer = _offer(box, approve=1)
    st, r = http("POST", f"{box.base}/support-api/t/{token}/booking/pick", {"window_key": keys[1]})
    assert st == 200, r
    box.clock(box.today, "10:30")
    box.agents_pass()
    ok = [p for p in _new(box, marks, "BK")[1] if p["action"] == "bk_approve"]
    assert ok and ok[0]["status"] == "applied", (ok, _new(box, marks, "BK")[0])
    row = _job_now(box, offer["ref"])
    assert row["job_status"] == "Scheduled" and row["service_date"] == keys[1][:10], row


def test_f19_agent_confirm_off_an_accepted_ai_offer_waits_for_a_person(box):
    keys, marks, token, email, offer = _offer(box, can_confirm=False)
    _accept(box, token)
    assert _job_now(box, offer["ref"])["job_status"] != "Scheduled", "booked with no person and the switch off"
    ok = [p for p in _new(box, marks, "BK")[1] if p["action"] == "bk_approve"]
    assert ok and ok[0]["status"] == "pending" and "isn't allowed to confirm" in ok[0]["hold_reason"], ok
    box.tool("desk_agent_review", action="approve", proposal_id=ok[0]["proposal_id"])
    assert _job_now(box, offer["ref"])["job_status"] == "Scheduled"


def test_f19_an_offer_a_person_approved_books_when_accepted(box):
    keys, marks, token, email, offer = _offer(box, can_confirm=False, mode="suggest")
    assert offer["status"] == "pending", offer
    box.tool("desk_agent_review", action="approve", proposal_id=offer["proposal_id"])
    st, r = http("POST", f"{box.base}/support-api/t/{token}/booking/accept", {})
    assert st == 200, r
    assert _job_now(box, offer["ref"])["job_status"] == "Scheduled"


# ── WF-05 and GR-19: the weather ─────────────────────────────────────────────
def _visit_tomorrow(box):
    _book(box, _windows(box)[0])
    jid = _sql(box, "SELECT job_id FROM booking_requests ORDER BY rowid DESC LIMIT 1")[0][0]
    tomorrow = (box.today + dt.timedelta(days=1)).isoformat()
    _sql(box, "UPDATE booking_requests SET status = 'scheduled' WHERE job_id = ?", (jid,))
    _sql(box, "UPDATE jobs SET job_status = 'Scheduled', service_date = ?, latitude = 29.03, longitude = -80.92 WHERE job_id = ?", (tomorrow, jid))
    _sql(box, "UPDATE booking_services SET outdoor = 1")
    return jid, tomorrow


@pytest.mark.parametrize("rain,held", [(90, False), (5, True)], ids=["heavy rain", "a mild forecast (GR-19)"])
def test_wf_05_only_a_bad_forecast_offers_a_new_time(box, rain, held):
    _booking_on(box, "track", agent_bk_weather=True, agent_bk_check_hour=9)
    box.control("POST", "/weather", {"rain": rain})
    later = _windows(box)[-1]
    jid, tomorrow = _visit_tomorrow(box)
    box.ai_reset("good", {"booking:track": [{"action": "bk_suggest_time", "window_key": later, "note": "ZAG rain", "why": "ZAG", "confidence": 0.9}]})
    marks = _marks(box)
    box.agents_pass()
    props = [p for p in _new(box, marks, "BK")[1] if p["action"] == "bk_suggest_time" and p["ref"] == jid]
    assert props, _new(box, marks, "BK")
    if held:
        assert props[0]["status"] != "applied" and "isn't bad enough" in props[0]["hold_reason"], props
    else:
        assert props[0]["status"] == "applied", props
    assert _sql(box, "SELECT service_date FROM jobs WHERE job_id = ?", (jid,))[0][0] == tomorrow, "the visit moved without the customer agreeing"


# ── WF-07: prep and on site ──────────────────────────────────────────────────
def _jobs_on(box, *stages, **more):
    box.settings(jobs={"agent_jb_enabled": True, "agent_jb_shadow": False,
                       **{f"agent_jb_stage_{s}": ("auto" if s in stages else "off") for s in JB_STAGES}, **more})


def _job(box, day, **more):
    n = next(_n)
    r = box.tool("create_customer", updates={"Customer Name / Company": f"ZAG Site {n}", "Phone": "386-555-0183"})
    cid = re.search(CUST_RE, r).group(0)
    r = box.tool("create_job", updates={"CustomerID": cid, "Customer Name / Company": f"ZAG Site {n}", "Service Type": "Window",
                                        "Job Status": "Scheduled", "Service Date": day.isoformat(), **more})
    return re.search(JOB_RE, r).group(0)


def test_wf_07_prep_flags_bad_weather_the_day_before(box):
    box.ai_reset("good", {"job:prep": [{"action": "jb_flag", "flag": "bad_weather", "detail": "ZAG rain", "why": "ZAG", "confidence": 0.9}]})
    _jobs_on(box, "prep", agent_jb_weather=True, agent_jb_prep_hour=16)
    box.control("POST", "/weather", {"rain": 90})
    tomorrow = box.today + dt.timedelta(days=1)
    jid = _job(box, tomorrow, **{"Street Address": "100 Flagler Ave"})
    _sql(box, "UPDATE jobs SET latitude = 29.03, longitude = -80.92 WHERE job_id = ?", (jid,))
    marks = _marks(box)
    box.agents_pass()
    assert not [q for q in _new(box, marks, "JB")[0] if q["ref"] == jid], "before the prep hour"
    box.clock(box.today, "16:30")
    box.agents_pass()
    props = [p for p in _new(box, marks, "JB")[1] if p["ref"] == jid and p["action"] == "jb_flag"]
    assert props and props[0]["status"] == "applied", (props, _new(box, marks, "JB")[0])
    assert any("bad_weather" in str(q.get("reason")) for q in _new(box, marks, "JB")[0] if q["ref"] == jid)


def test_wf_07_a_job_running_long_is_flagged(box):
    box.ai_reset("good", {"job:onsite": [{"action": "jb_flag", "flag": "running_long", "detail": "ZAG", "why": "ZAG", "confidence": 0.9}]})
    _jobs_on(box, "onsite")
    jid = _job(box, box.today, **{"Est Duration": 30, "Est Duration Unit": "Minutes"})
    _sql(box, "UPDATE jobs SET est_duration = 30, est_duration_unit = 'min' WHERE job_id = ?", (jid,))
    r = box.tool("log_time_entry", job_identifier=jid, action="start")
    assert "❌" not in str(r), r
    marks = _marks(box)
    box.clock(box.today, "10:20")
    box.agents_pass()
    assert not [q for q in _new(box, marks, "JB")[0] if q["ref"] == jid and q.get("reason") == "running_long"], "20 minutes of 30"
    box.clock(box.today, "11:00")
    box.agents_pass()
    props = [p for p in _new(box, marks, "JB")[1] if p["ref"] == jid and p["action"] == "jb_flag"]
    assert props and props[0]["status"] == "applied", (props, _new(box, marks, "JB")[0])
