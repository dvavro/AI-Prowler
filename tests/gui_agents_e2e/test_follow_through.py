"""F-12, built 4 Nov: the Follow-through stage. A customer waiting, On Hold past its date, a question after Fixed. And WF-02."""
from __future__ import annotations

import datetime as dt
import itertools
import time

import pytest

from conftest import START, http
from test_matrix import SD_STAGES, _marks, _new, all_off, off_stages
from test_workflows import _customer_reports, _customer_sees

_n = itertools.count(1)
NUDGE = "ZAG just checking in: we haven't forgotten you."


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    b.today = START + dt.timedelta(days=2000 + 40 * next(_n))     # past the 30-day cutoff: earlier tests' open tickets stay out
    b.clock(b.today, "08:00")
    yield b
    all_off(b)


def _on(box, mode="auto", **more):
    box.ai_reset("good", {"ticket:follow_through": [{"action": "reply", "body": NUDGE, "why": "ZAG quiet", "confidence": 0.9}]})
    box.settings(desk={"agent_enabled": True, "agent_shadow": False, "portal_enabled": True, "agent_wait_hours": 4,
                       **off_stages("agent_stage_", SD_STAGES, "follow_through", mode), **more})


def _ticket_id(box, token):
    return _customer_sees(box, token)["ticket_id"]


def _pass(box):
    marks = _marks(box)
    box.agents_pass()
    return [p for p in _new(box, marks, "SD")[1] if p["stage"] == "follow_through"]


def _start_work(box, tid):
    """On Business a new ticket is Open until someone has it; on Solo it's already the owner's."""
    st, d = box.desk("GET", f"/tickets/{tid}")
    assert st == 200, d
    if (d.get("ticket") or d)["state"] == "Open":
        st, me = box.desk("GET", "/me")
        assert st == 200, me
        st, r = box.desk("POST", f"/tickets/{tid}/assign", {"assignee": me["actor"]["id"]})
        assert st == 200, r
    _state(box, tid, "In Progress")


def _state(box, tid, to, reason="ZAG"):
    st, d = box.desk("POST", f"/tickets/{tid}/state", {"to_state": to, "reason": reason})
    assert st == 200, d


def test_waits_the_set_hours_then_once(box):
    _on(box)
    token, email = _customer_reports(box, "ZAG nobody answered")
    box.clock(box.today, "10:00")
    assert not _pass(box), "2 hours isn't 4"
    box.clock(box.today, "13:00")
    props = _pass(box)
    assert len(props) == 1 and props[0]["status"] == "applied", props
    assert NUDGE in str(_customer_sees(box, token)["messages"])
    box.clock(box.today + dt.timedelta(days=1), "13:00")
    assert not _pass(box), "the agent has answered: nobody is waiting now"


def test_a_customers_new_message_starts_a_new_wait(box):
    _on(box)
    token, _ = _customer_reports(box, "ZAG second wait")
    box.clock(box.today, "13:00")
    assert len(_pass(box)) == 1
    st, r = http("POST", f"{box.base}/support-api/t/{token}/reply", {"body": "ZAG still nothing"})
    assert st == 201, r
    assert not _pass(box), "they only just wrote"
    box.clock(box.today, "18:00")
    assert len(_pass(box)) == 1


def test_staff_answer_stops_it(box):
    _on(box)
    token, _ = _customer_reports(box, "ZAG staff got it")
    st, m = box.desk("POST", f"/tickets/{_ticket_id(box, token)}/messages", {"body": "ZAG on it", "visibility": "public"})
    assert st in (200, 201), m
    box.clock(box.today, "18:00")
    assert not _pass(box)


def test_suggest_waits_for_a_person_and_stage_off_never_runs(box):
    _on(box, mode="suggest")
    token, _ = _customer_reports(box, "ZAG suggest")
    box.clock(box.today, "13:00")
    props = _pass(box)
    assert props and props[0]["status"] == "pending", props
    assert NUDGE not in str(_customer_sees(box, token)["messages"])
    box.desk("POST", f"/agent/proposals/{props[0]['proposal_id']}/reject", {})
    _on(box, mode="off")
    _customer_reports(box, "ZAG off")
    box.clock(box.today, "20:00")
    assert not _pass(box) and not [c for c in box.ai_calls() if c.get("stage") == "follow_through"]


def test_on_hold_past_its_week(box):
    _on(box)
    token, _ = _customer_reports(box, "ZAG on hold")
    tid = _ticket_id(box, token)
    st, m = box.desk("POST", f"/tickets/{tid}/messages", {"body": "ZAG waiting on a part", "visibility": "public"})
    assert st in (200, 201), m
    _start_work(box, tid)
    _state(box, tid, "On Hold", "ZAG part ordered")
    box.clock(box.today + dt.timedelta(days=3), "09:00")
    assert not _pass(box), "only 3 days on hold"
    box.clock(box.today + dt.timedelta(days=8), "09:00")
    assert len(_pass(box)) == 1


def test_question_after_fixed_needs_no_wait(box):
    _on(box)
    token, _ = _customer_reports(box, "ZAG fixed question")
    tid = _ticket_id(box, token)
    st, m = box.desk("POST", f"/tickets/{tid}/messages", {"body": "ZAG done", "visibility": "public"})
    assert st in (200, 201), m
    _start_work(box, tid)
    _state(box, tid, "Fixed")
    assert not _pass(box), "no question yet"
    st, r = http("POST", f"{box.base}/support-api/t/{token}/reply", {"body": "ZAG will it streak again?"})
    assert st == 201, r
    assert len(_pass(box)) == 1


def test_guardrails_still_apply(box):
    _on(box)
    st, d = box.desk("POST", "/tickets", {"kind": "external", "title": "ZAG P1 quiet", "priority": "P1", "contact_name": "ZAG P",
                                          "contact_phone": "386-555-0191", "contact_email": "ftp1@time-machine.test"})
    assert st == 201, d
    box.clock(box.today, "13:00")
    props = _pass(box)
    assert props and props[0]["status"] == "pending" and "P1" in props[0]["hold_reason"], props


def test_private_never(box):
    _on(box)
    st, d = box.desk("POST", "/tickets", {"kind": "external", "title": "ZAG private quiet", "private": True, "contact_name": "ZAG Q",
                                          "contact_phone": "386-555-0192", "contact_email": "ftq@time-machine.test"})
    assert st == 201, d
    box.clock(box.today, "20:00")
    assert not [p for p in _pass(box) if p["ref"] == d["ticket"]["ticket_id"]]


def test_tickets_older_than_30_days_are_left_alone(box):
    _on(box, mode="off")
    _customer_reports(box, "ZAG ancient")
    box.clock(box.today + dt.timedelta(days=31), "09:00")
    _on(box)
    assert not _pass(box)


def test_wf_02_follow_through_and_learning(box):
    _on(box, mode="suggest", agent_stage_learn="suggest")
    box.ai_reset("good", {"ticket:follow_through": [{"action": "reply", "body": NUDGE, "why": "ZAG", "confidence": 0.9}],
                          "ticket:learn": [{"action": "propose_learning", "title": "ZAG streaks come from hard water",
                                            "body": "ZAG rinse twice on hard-water streets.", "why": "ZAG", "confidence": 0.9}]})
    token, email = _customer_reports(box, "ZAG streaks again")
    tid = _ticket_id(box, token)
    box.clock(box.today, "13:00")
    props = _pass(box)
    assert props and props[0]["status"] == "pending", props
    st, d = box.desk("POST", f"/agent/proposals/{props[0]['proposal_id']}/approve", {})
    assert st == 200, d
    assert NUDGE in str(_customer_sees(box, token)["messages"])
    st, d = box.desk("POST", f"/tickets/{tid}/update", {"fields": {"resolution": "ZAG rewashed"}, "reason": "ZAG"})
    assert st == 200, d
    _start_work(box, tid)
    _state(box, tid, "Fixed")
    st, r = http("POST", f"{box.base}/support-api/t/{token}/state", {"to_state": "Closed", "reason": ""})     # "Yes, all good"
    assert st == 200, r
    marks = _marks(box)
    box.agents_pass()
    learn = [p for p in _new(box, marks, "SD")[1] if p["action"] == "propose_learning"]
    assert learn and learn[0]["status"] == "pending", learn
    assert "streaks come from hard water" not in str(box.tool("search_learnings", query="hard water streaks")).lower(), \
        "saved before anyone approved"
    st, d = box.desk("POST", f"/agent/proposals/{learn[0]['proposal_id']}/approve", {})
    assert st == 200, d
    time.sleep(0.2)
    assert "streaks come from hard water" in str(box.tool("search_learnings", query="hard water streaks")).lower()
