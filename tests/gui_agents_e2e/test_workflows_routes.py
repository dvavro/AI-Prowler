"""AG-WF-09: the week's routes, with the app's real route tools. Covers the Route stages: sort, plan, route, send, replan."""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START
from test_env import CUST_RE, JOB_RE
from test_matrix import RT_STAGES, _marks, _new, all_off
from test_stage_grid import _sql

_n = itertools.count(1)
SPOTS = [("100 Flagler Ave", 29.030, -80.900), ("400 Canal St", 29.025, -80.925), ("700 Third Ave", 29.020, -80.895)]


def _day(weekday):
    d = START + dt.timedelta(days=18000 + 28 * next(_n))
    while d.weekday() != weekday:
        d += dt.timedelta(days=1)
    return d


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    # By design (R-058) a route also carries unfinished jobs from earlier days, so close other tests' jobs.
    _sql(b, "UPDATE jobs SET job_status = 'Complete' WHERE LOWER(COALESCE(job_status, '')) NOT IN ('complete', 'completed', 'cancelled', 'canceled')")
    yield b
    all_off(b)


def _on(box, *stages, **more):
    box.settings(jobs={"agent_jb_enabled": False, "agent_jb_rt_enabled": True, "agent_jb_rt_shadow": False,
                       **{f"agent_jb_rt_stage_{s}": ("auto" if s in stages else "off") for s in RT_STAGES}, **more})


def _job(box, day, spot=0, kind="Flexible", crew="ZAG Crew Cris"):
    n = next(_n)
    street, lat, lon = SPOTS[spot]
    r = box.tool("create_customer", updates={"Customer Name / Company": f"ZAG Route {n}", "Phone": "386-555-0184"})
    cid = re.search(CUST_RE, str(r)).group(0)
    r = box.tool("create_job", updates={"CustomerID": cid, "Customer Name / Company": f"ZAG Route {n}", "Service Type": "Window",
                                        "Job Status": "Scheduled", "Service Date": day.isoformat(), "Street Address": street,
                                        "City": "New Smyrna Beach", "State": "FL", "ZIP": "32169", "Est Duration": 30})
    jid = re.search(JOB_RE, str(r)).group(0)
    _sql(box, "UPDATE jobs SET latitude = ?, longitude = ?, schedule_type = ?, crew = ? WHERE job_id = ?",
         (lat, lon, kind, crew if box.edition == "business" else "", jid))
    return jid


def _props(box, marks, action):
    return [p for p in _new(box, marks, "RT")[1] if p["action"] == action]


def _pass(box, marks, action, ref=None, tries=4):
    for _ in range(tries):
        box.agents_pass()
        got = [p for p in _props(box, marks, action) if not ref or ref in p["ref"]]
        if got:
            return got
    return []


def test_wf_09_sort_then_schedule_the_week(box):
    friday = _day(4)
    box.clock(friday, "09:00")
    monday = friday + dt.timedelta(days=3)
    wed = monday + dt.timedelta(days=2)
    jid = _job(box, monday)
    _job(box, monday, 1)
    box.ai_reset("good", {"route:sort": [{"action": "rt_propose_week", "moves": [{"job_id": jid, "to": wed.isoformat(), "reason": "ZAG"}], "why": "ZAG", "confidence": 0.9}],
                          "route:plan": [{"action": "rt_apply_week", "why": "ZAG", "confidence": 0.9}]})
    _on(box, "sort")
    marks = _marks(box)
    sort = _pass(box, marks, "rt_propose_week", monday.isoformat())
    assert sort and sort[0]["status"] == "applied", (sort, _new(box, marks, "RT"))
    assert _sql(box, "SELECT service_date FROM jobs WHERE job_id = ?", (jid,))[0][0] == monday.isoformat(), "a plan alone moved a job"
    _on(box, "plan")
    plan = _pass(box, marks, "rt_apply_week", monday.isoformat())
    assert plan and plan[0]["status"] == "applied", (plan, _new(box, marks, "RT"))
    assert _sql(box, "SELECT service_date FROM jobs WHERE job_id = ?", (jid,))[0][0] == wed.isoformat()


def _routed(box, tue):
    box.clock(tue, "10:00")
    wed = tue + dt.timedelta(days=1)
    ids = [_job(box, wed, 0), _job(box, wed, 1), _job(box, wed, 2)]
    box.ai_reset("good", {"route:route": [{"action": "rt_route_day", "why": "ZAG", "confidence": 0.9}],
                          "route:send": [{"action": "rt_send", "why": "ZAG", "confidence": 0.9}],
                          "route:replan": [{"action": "rt_replan", "why": "ZAG", "confidence": 0.9}]})
    _on(box, "route", "send", "replan")
    marks = _marks(box)
    p = _pass(box, marks, "rt_route_day", wed.isoformat())
    assert p and p[0]["status"] == "applied", (p, _new(box, marks, "RT"))
    n = _sql(box, "SELECT COUNT(*) FROM route_stops WHERE route_date = ?", (wed.isoformat(),))[0][0]
    rows = [dict(r) for r in _sql(box, "SELECT * FROM route_stops WHERE route_date = ?", (wed.isoformat(),))]
    assert n == 3, (n, ids, wed.isoformat(), [{k: v for k, v in r.items() if k in ("job_id", "crew_id", "route_date", "stop_order", "stop_type", "address")} for r in rows],
                    [dict(r) for r in _sql(box, "SELECT job_id, service_date, job_status FROM jobs WHERE service_date = ?", (wed.isoformat(),))])
    return wed, ids, marks


def test_wf_09_route_a_day_waits_to_be_approved(box):
    wed, ids, marks = _routed(box, _day(1))
    assert not _sql(box, "SELECT 1 FROM route_approvals WHERE route_date = ?", (wed.isoformat(),)), "routed is not approved"


def test_wf_09_send_only_after_the_send_hour(box):
    tue = _day(1)
    wed, ids, marks = _routed(box, tue)
    box.agents_pass()
    assert not _props(box, marks, "rt_send"), "before 18:00"
    sent = len(box.outbox())
    box.clock(tue, "18:30")
    p = _pass(box, marks, "rt_send", wed.isoformat())
    assert p and p[0]["status"] == "applied", (p, _new(box, marks, "RT"))
    assert _sql(box, "SELECT 1 FROM route_approvals WHERE route_date = ?", (wed.isoformat(),))
    assert box.outbox()[sent:], "nothing went to the crew"
    if box.edition == "business":
        assert {m["to"] for m in box.outbox()[sent:]} == {"cris@time-machine.test"}, box.outbox()[sent:]


def test_wf_09_a_cancellation_replans_and_hard_jobs_keep_their_times(box):
    tue = _day(1)
    wed, ids, marks = _routed(box, tue)
    box.clock(tue, "18:30")
    _pass(box, marks, "rt_send", wed.isoformat())
    _sql(box, "UPDATE jobs SET schedule_type = 'Hard', start_time = '13:00', original_start_time = '13:00' WHERE job_id = ?", (ids[2],))
    box.clock(wed, "07:00")
    _sql(box, "UPDATE jobs SET job_status = 'Cancelled' WHERE job_id = ?", (ids[0],))
    p = _pass(box, marks, "rt_replan", wed.isoformat())
    assert p and p[0]["status"] == "applied", (p, _new(box, marks, "RT"))
    assert _sql(box, "SELECT start_time FROM jobs WHERE job_id = ?", (ids[2],))[0][0] == "13:00"
    left = [r[0] for r in _sql(box, "SELECT job_id FROM route_stops WHERE route_date = ?", (wed.isoformat(),))]
    assert ids[0] not in left and ids[1] in left, left
    assert "crew was told" in str(p[0].get("result")), p
    assert _sql(box, "SELECT 1 FROM route_approvals WHERE route_date = ?", (wed.isoformat(),)), "the crew's route lost its approval"


def _send_day(box, tue, jobs):
    """jobs: [(spot, crew)]. Returns ids, wed, marks, what was sent, and the send proposals, once the send hour has passed."""
    box.clock(tue, "10:00")
    wed = tue + dt.timedelta(days=1)
    ids = [_job(box, wed, s, crew=c) for s, c in jobs]
    box.ai_reset("good", {"route:route": [{"action": "rt_route_day", "why": "ZAG", "confidence": 0.9}],
                          "route:send": [{"action": "rt_send", "why": "ZAG", "confidence": 0.9}]})
    _on(box, "route", "send")
    marks = _marks(box)
    for _ in range(3):
        box.agents_pass()
    box.clock(tue, "18:30")
    sent = len(box.outbox())
    for _ in range(3):
        box.agents_pass()
    return ids, wed, marks, box.outbox()[sent:], _props(box, marks, "rt_send")


@pytest.fixture
def biz(business):
    all_off(business)
    _sql(business, "UPDATE jobs SET job_status = 'Complete' WHERE LOWER(COALESCE(job_status, '')) NOT IN ('complete', 'completed', 'cancelled', 'canceled')")
    yield business
    all_off(business)


def test_f20_each_crew_gets_only_its_own_route(biz):
    ids, wed, marks, mail, props = _send_day(biz, _day(1), [(0, "ZAG Crew Cris"), (1, "ZAG Crew Dee")])
    assert len(props) == 2 and all(p["status"] == "applied" for p in props), props
    who = {m["to"]: str(m.get("body")) for m in mail}
    assert set(who) == {"cris@time-machine.test", "dee@time-machine.test"}, mail
    assert SPOTS[0][0] in who["cris@time-machine.test"] and SPOTS[1][0] not in who["cris@time-machine.test"], who
    assert SPOTS[1][0] in who["dee@time-machine.test"] and SPOTS[0][0] not in who["dee@time-machine.test"], who


def test_f20_a_job_shared_by_two_goes_to_both(biz):
    ids, wed, marks, mail, props = _send_day(biz, _day(1), [(0, "ZAG Crew Cris, ZAG Crew Dee")])
    assert props and props[0]["status"] == "applied", (props, _new(biz, marks, "RT"))
    assert {m["to"] for m in mail} == {"cris@time-machine.test", "dee@time-machine.test"}, (mail, props)


def test_f21_no_email_on_file_is_reported_not_claimed_as_sent(biz):
    ids, wed, marks, mail, props = _send_day(biz, _day(1), [(0, "ZAG Nobody")])
    assert props and props[0]["status"] == "failed" and "no email on file" in str(props[0].get("result")), props
    assert not mail, mail


def test_wf_09_scope_week_routes_the_days_ahead(box):
    tue = _day(1)
    box.clock(tue, "10:00")
    later = tue + dt.timedelta(days=3)
    _job(box, later)
    box.ai_reset("good", {"route:route": [{"action": "rt_route_day", "why": "ZAG", "confidence": 0.9}]})
    _on(box, "route", agent_jb_route_scope="day")
    marks = _marks(box)
    assert not _pass(box, marks, "rt_route_day", later.isoformat(), tries=1), "one day ahead only"
    _on(box, "route", agent_jb_route_scope="week")
    assert _pass(box, marks, "rt_route_day", later.isoformat())
