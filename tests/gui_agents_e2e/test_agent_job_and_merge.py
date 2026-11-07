"""David 4 Nov: approving the agent's "create a re-do job" and "merge tickets" really does them. Always a person first."""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START, http
from test_env import CUST_RE, JOB_RE
from test_follow_through import _ticket_id
from test_matrix import SD_STAGES, _marks, _new, all_off, off_stages
from test_stage_grid import _sql
from test_workflows import _customer_reports, _customer_sees

_n = itertools.count(1)


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    b.today = START + dt.timedelta(days=4000 + 40 * next(_n))
    b.clock(b.today, "09:00")
    b.settings(desk={"portal_enabled": True, "agent_enabled": True, "agent_shadow": False,
                     **off_stages("agent_stage_", SD_STAGES, "resolution", "auto")})
    yield b
    all_off(b)


def _customer(box):
    n = next(_n)
    r = box.tool("create_customer", updates={"Customer Name / Company": f"ZAG Redo {n}", "Phone": "386-555-0177"})
    return re.search(CUST_RE, r).group(0)


def _ticket(box, *, link=True):
    token, _email = _customer_reports(box, f"ZAG redo {next(_n)}")
    tid = _ticket_id(box, token)
    if link:
        st, d = box.desk("POST", f"/tickets/{tid}/update", {"fields": {"customer_id": _customer(box)}, "reason": "ZAG"})
        assert st == 200, d
    st, m = box.desk("POST", f"/tickets/{tid}/messages", {"body": "ZAG looking at it", "visibility": "public"})
    assert st in (200, 201), m
    return token, tid


def _propose(box, token, tid, action):
    """The customer writes back, which queues Resolution; the stand-in answers with this action."""
    box.ai_reset("good", {"ticket:resolution": [{"why": "ZAG", "confidence": 0.95, **action}]})
    marks = _marks(box)
    st, r = http("POST", f"{box.base}/support-api/t/{token}/reply", {"body": "ZAG it is still wrong"})
    assert st == 201, r
    box.agents_pass()
    return [p for p in _new(box, marks, "SD")[1] if p["ref"] == tid and p["action"] == action["action"]]


def _approve(box, p):
    return box.desk("POST", f"/agent/proposals/{p['proposal_id']}/approve", {})


def test_job_on_auto_still_waits_for_a_person(box):
    token, tid = _ticket(box)
    p = _propose(box, token, tid, {"action": "propose_job", "notes": "ZAG rewash"})
    assert p and p[0]["status"] == "pending" and "high risk" in p[0]["hold_reason"], p


def test_job_with_a_date_is_scheduled_and_the_customer_is_told(box):
    token, tid = _ticket(box)
    day = (box.today + dt.timedelta(days=5)).isoformat()
    p = _propose(box, token, tid, {"action": "propose_job", "notes": "ZAG rewash", "service_date": day})
    st, d = _approve(box, p[0])
    assert st == 200, d
    jid = re.search(JOB_RE, str(d)).group(0)
    row = dict(_sql(box, "SELECT * FROM jobs WHERE job_id = ?", (jid,))[0])
    assert row["job_status"] == "Scheduled" and row["service_date"] == day and "ZAG rewash" in str(row), row
    assert day in str(_customer_sees(box, token)["messages"])


def test_job_with_no_date_is_unscheduled_and_the_customer_hears_nothing(box):
    token, tid = _ticket(box)
    before = str(_customer_sees(box, token)["messages"])
    p = _propose(box, token, tid, {"action": "propose_job", "notes": "ZAG rewash"})
    st, d = _approve(box, p[0])
    assert st == 200, d
    jid = re.search(JOB_RE, str(d)).group(0)
    assert _sql(box, "SELECT job_status FROM jobs WHERE job_id = ?", (jid,))[0]["job_status"] == "Unscheduled"
    assert "scheduled a return visit" not in str(_customer_sees(box, token)["messages"]) and before is not None


@pytest.mark.parametrize("bad", ["next tuesday", "today"])
def test_a_bad_date_is_refused_before_anyone_sees_it(box, bad):
    token, tid = _ticket(box)
    when = box.today.isoformat() if bad == "today" else bad
    # F-25: nothing can act on it. It only shows as a notice with the reason, and Approve is refused
    props = _propose(box, token, tid, {"action": "propose_job", "notes": "ZAG", "service_date": when})
    assert props and all('"refused": true' in p["payload_json"] and "Refused by the rules" in p["hold_reason"] for p in props), props
    st, d = _approve(box, props[0])
    assert st != 200 and "refused" in str(d), (st, d)


def test_no_jobs_customer_says_how_to_fix_it(box):
    token, tid = _ticket(box, link=False)
    p = _propose(box, token, tid, {"action": "propose_job", "notes": "ZAG"})
    st, d = _approve(box, p[0])
    assert st >= 400 and "customer" in str(d).lower(), (st, d)


def _same_customer_pair(box):
    n = next(_n)
    who = {"name": f"ZAG Merge {n}", "phone": f"386561{n:04d}", "email": f"merge{n}@time-machine.test", "send_by": "email"}
    from conftest import code_from
    toks = []
    for title in ("ZAG first report", "ZAG same thing again"):
        st, d = http("POST", box.base + "/support-api/start", who)
        assert st == 200, d
        code = code_from([m for m in box.outbox() if m.get("to") == who["email"] and "request code" in str(m.get("subject"))][-1]["body"])
        st, v = http("POST", box.base + "/support-api/verify", {"contact_id": d["contact_id"], "code": code, "path": "problem", "title": title})
        assert st == 201, v
        toks.append(v["token"])
    return toks


def test_merge_moves_the_messages_and_closes_the_duplicate(box):
    a, b = _same_customer_pair(box)
    pid, did = _ticket_id(box, a), _ticket_id(box, b)
    st, m = box.desk("POST", f"/tickets/{did}/messages", {"body": "ZAG got it", "visibility": "public"})
    assert st in (200, 201), m
    p = _propose(box, b, did, {"action": "propose_merge", "primary_id": pid})
    assert p and p[0]["status"] == "pending", p
    st, d = _approve(box, p[0])
    assert st == 200 and "merged" in str(d), (st, d)
    st, dup = box.desk("GET", f"/tickets/{did}")
    assert (dup.get("ticket") or dup)["state"] == "Closed"
    st, prim = box.desk("GET", f"/tickets/{pid}")
    assert "ZAG it is still wrong" in str(prim)


def test_merge_across_customers_is_refused_and_nothing_moves(box):
    t1, id1 = _ticket(box)
    t2, id2 = _ticket(box)
    p = _propose(box, t2, id2, {"action": "propose_merge", "primary_id": id1})
    st, d = _approve(box, p[0])
    assert st >= 400 and "different customers" in str(d), (st, d)
    st, dup = box.desk("GET", f"/tickets/{id2}")
    assert (dup.get("ticket") or dup)["state"] != "Closed"
    assert "ZAG it is still wrong" not in str(_customer_sees(box, t1)["messages"])


def test_merge_into_a_private_ticket_is_refused(box):
    t2, id2 = _ticket(box)
    st, d = box.desk("POST", "/tickets", {"kind": "internal", "title": "ZAG private", "private": True})
    assert st == 201, d
    p = _propose(box, t2, id2, {"action": "propose_merge", "primary_id": d["ticket"]["ticket_id"]})
    st, r = _approve(box, p[0])
    assert st >= 400, (st, r)
