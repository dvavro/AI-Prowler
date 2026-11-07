"""AG-WF (AGENTS_GUI_E2E_TEST_SPEC.md §7): whole journeys, in Practice, Suggest and Auto. Written so far: WF-01, 03, 10.
SUG approves through the same route the app's Agent tab uses; test_review.py clicks those buttons in the app itself.
"""
from __future__ import annotations

import datetime as dt
import itertools

import pytest

from conftest import START, code_from, http
from test_guardrails_hr import _employee, _weekday
from test_matrix import SD_STAGES, _marks, _new, all_off, off_stages

_n = itertools.count(1)
REPLY = "ZAG sorry about the streaks, we'll come back and rewash them."
MODES = ["PRAC", "SUG", "AUTO"]


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    b.clock(START + dt.timedelta(days=1500 + next(_n)), "10:00")
    yield b
    all_off(b)


def _desk_agent(box, state, *stages):
    mode = "auto" if state == "AUTO" else "suggest"
    box.settings(desk={"agent_enabled": True, "agent_shadow": state == "PRAC", "portal_enabled": True, "agent_name": "Sam",
                       **{f"agent_stage_{s}": (mode if s in stages else "off") for s in SD_STAGES}})


def _customer_reports(box, title):
    n = next(_n)
    email = f"wf{n}@time-machine.test"
    st, d = http("POST", box.base + "/support-api/start", {"name": f"ZAG WF {n}", "phone": f"386560{n:04d}", "email": email, "send_by": "email"})
    assert st == 200, d
    code = code_from([m for m in box.outbox() if m.get("to") == email and "request code" in str(m.get("subject"))][-1]["body"])
    st, v = http("POST", box.base + "/support-api/verify", {"contact_id": d["contact_id"], "code": code, "path": "problem", "title": title})
    assert st == 201, v
    return v["token"], email


def _customer_sees(box, token):
    st, d = http("GET", f"{box.base}/support-api/t/{token}")
    assert st == 200, d
    return d["ticket"]


@pytest.mark.parametrize("state", MODES)
def test_wf_01_problem_to_first_reply(box, state):
    _desk_agent(box, state, "intake", "first_reply")
    box.ai_reset("good", {
        "ticket:intake": [{"action": "set_type", "type": "Complaint", "why": "ZAG", "confidence": 0.9}],
        "ticket:first_reply": [{"action": "reply", "body": REPLY, "why": "ZAG", "confidence": 0.9}]})
    marks, sent = _marks(box), len(box.outbox())
    token, email = _customer_reports(box, "ZAG streaks on the front windows")
    box.agents_pass()
    props = _new(box, marks, "SD")[1]
    reply = next(p for p in props if p["action"] == "reply")

    def reached():
        return [m for m in box.outbox()[sent:] if REPLY in str(m)]

    if state == "PRAC":
        assert all(p["status"] == "practice" for p in props), props
        assert not reached() and REPLY not in str(_customer_sees(box, token)["messages"])     # the customer sees nothing
        return
    if state == "SUG":
        assert reply["status"] == "pending" and not reached(), reply
        assert REPLY not in str(_customer_sees(box, token)["messages"])
        st, d = box.desk("POST", f"/agent/proposals/{reply['proposal_id']}/approve", {})
        assert st == 200, d
    else:
        assert reply["status"] == "applied", reply
    msgs = _customer_sees(box, token)["messages"]
    assert REPLY in str(msgs), msgs
    for _ in range(50):                                 # sent on a background thread
        if reached():
            break
        import time
        time.sleep(0.1)
    assert reached() and reached()[0].get("to") == email, box.outbox()[sent:]


def test_wf_03_p1_waits_for_a_person(box):
    _desk_agent(box, "AUTO", "first_reply")
    box.ai_reset("good", {"ticket:first_reply": [{"action": "reply", "body": REPLY, "why": "ZAG", "confidence": 0.9}]})
    marks = _marks(box)
    st, d = box.desk("POST", "/tickets", {"kind": "external", "title": "ZAG flooded basement", "priority": "P1", "contact_name": "ZAG P",
                                          "contact_phone": "386-555-0190", "contact_email": "p1@time-machine.test"})
    assert st == 201, d
    box.agents_pass()
    props = [p for p in _new(box, marks, "SD")[1] if p["action"] == "reply"]
    assert props and props[0]["status"] == "pending" and "P1" in props[0]["hold_reason"], props


def test_wf_03_private_ticket_never_reaches_the_ai(box):
    _desk_agent(box, "AUTO", "intake", "first_reply")
    box.ai_reset("good", {})
    marks = _marks(box)
    st, d = box.desk("POST", "/tickets", {"kind": "internal", "title": "ZAG private matter", "private": True})
    assert st == 201, d
    tid = d["ticket"]["ticket_id"]
    st, full = box.desk("GET", f"/tickets/{tid}")
    assert st == 200 and "private" in str(full), full      # it really is private
    box.agents_pass()
    assert not [q for q in _new(box, marks, "SD")[0] if q["ref"] == tid]
    assert not [c for c in box.ai_calls() if tid in str(c)], "the AI saw a private ticket"


# ── WF-10: time off, Business only ───────────────────────────────────────────
@pytest.fixture
def biz(business):
    all_off(business)
    day = START + dt.timedelta(days=1700 + 7 * next(_n))
    day += dt.timedelta(days=(1 - day.weekday()) % 7)
    business.clock(day, "10:00")
    business.today = day
    st, j = business.hr("POST", "/setup/complete", {"company_name": "ZAG Agents Co", "work_states": ["FL"], "setup_complete": True,
                                                    "hr_admin_email": "owner@time-machine.test", "owner_email": "owner@time-machine.test"})
    assert st == 200, j
    yield business
    all_off(business)


@pytest.mark.parametrize("state", MODES)
def test_wf_10_two_days_off(biz, state):
    box = biz
    from test_matrix import HR_STAGES
    mode = "auto" if state == "AUTO" else "suggest"
    box.ai_reset("good", {"hr:timeoff": [{"action": "hr_approve_timeoff", "why": "ZAG every check passed", "confidence": 0.9}]})
    box.settings(hr={"agent_hr_enabled": True, "agent_hr_shadow": state == "PRAC", "agent_hr_can_approve_timeoff": state == "AUTO",
                     "agent_hr_timeoff_max_days": 3, "agent_hr_timeoff_notice_days": 14, "agent_hr_timeoff_max_off": 1,
                     "agent_hr_timeoff_per_day": 50, **off_stages("agent_hr_stage_", HR_STAGES, "timeoff", mode)})
    eid = _employee(box)
    a = _weekday(box, 20)
    b = a + dt.timedelta(days=1)
    if b.weekday() >= 5:
        a, b = a + dt.timedelta(days=2), b + dt.timedelta(days=2)
    marks = _marks(box)
    st, j = box.hr("POST", "/pto/request", {"employee_id": eid, "type": "PTO (Vacation)", "start_date": a.isoformat(), "end_date": b.isoformat()})
    assert st == 201, j
    rid = j["request"]["id"]
    box.agents_pass()
    props = [p for p in _new(box, marks, "HR")[1] if p["ref"] == f"pto:{rid}"]
    st, rows = box.hr("GET", "/pto")
    row = next(r for r in (rows.get("requests") or rows) if r["id"] == rid)
    want = {"PRAC": ("practice", "pending"), "SUG": ("pending", "pending"), "AUTO": ("applied", "approved")}[state]
    assert props and props[0]["status"] == want[0], props
    assert row["status"] == want[1], row
