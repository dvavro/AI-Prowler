"""AG-X-04, AG-JB-01: Service Desk off. The Jobs and Route agents and their approvals keep working; the Service Desk agents don't run."""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START
from test_env import CUST_RE, JOB_RE
from test_matrix import JB_STAGES, RT_STAGES, SD_STAGES, _marks, _new, all_off, off_stages
from test_stage_grid import _sql

_n = itertools.count(1)
PREP = "ZAG desk-off prep note."


@pytest.fixture(params=["solo", "business"])
def box(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    b.today = START + dt.timedelta(days=26000 + 28 * next(_n))
    while b.today.weekday() != 1:
        b.today += dt.timedelta(days=1)
    b.clock(b.today, "16:30")
    assert b.control("POST", "/desk-off", {"off": True})["off"] is True
    yield b
    b.control("POST", "/desk-off", {"off": False})
    all_off(b)


def _job(box, street="100 Flagler Ave"):
    n = next(_n)
    r = box.tool("create_customer", updates={"Customer Name / Company": f"ZAG Off {n}", "Phone": "386-555-0185"})
    cid = re.search(CUST_RE, str(r)).group(0)
    r = box.tool("create_job", updates={"CustomerID": cid, "Customer Name / Company": f"ZAG Off {n}", "Service Type": "Window", "Job Status": "Scheduled",
                                        "Service Date": (box.today + dt.timedelta(days=1)).isoformat(), "Street Address": street})
    return re.search(JOB_RE, str(r)).group(0)


def _prep(box, mode):
    box.ai_reset("good", {"job:prep": [{"action": "jb_prep_note", "body": PREP, "why": "ZAG", "confidence": 0.9}]})
    box.settings(jobs={"agent_jb_enabled": True, "agent_jb_shadow": False, "agent_jb_rt_enabled": False, **off_stages("agent_jb_stage_", JB_STAGES, "prep", mode)})
    jid = _job(box, street="")          # Prep only queues a job with something wrong
    marks = _marks(box)
    got = []
    for _ in range(4):
        box.agents_pass()
        got = [p for p in _new(box, marks, "JB")[1] if p["ref"] == jid]
        if got:
            break
    assert got, (_new(box, marks, "JB"), box.ai_calls()[-1:])
    return jid, got[0]


def test_x04_jobs_agent_works_with_service_desk_off(box):
    jid, p = _prep(box, "auto")
    assert p["status"] == "applied", p
    assert p["action"] == "jb_prep_note" and p["result"], p


def test_x04_a_suggestion_can_still_be_approved_from_the_jobs_side(box):
    jid, p = _prep(box, "suggest")
    assert p["status"] == "pending", p
    out = box.tool("jobs_agent", action="approve", proposal_id=str(p["proposal_id"]))
    assert "turned off" not in str(out).lower() and "❌" not in str(out), out
    now = [q for q in (box.agent_db().get("jobs_agent") or {}).get("agent_proposals", []) if q["proposal_id"] == p["proposal_id"]][0]
    assert now["status"] == "applied", (out, now)


def test_x04_the_route_flow_works_with_service_desk_off(box):
    box.clock(box.today, "10:00")
    jid = _job(box)
    box.ai_reset("good", {"route:route": [{"action": "rt_route_day", "why": "ZAG", "confidence": 0.9}]})
    box.settings(jobs={"agent_jb_enabled": False, "agent_jb_rt_enabled": True, "agent_jb_rt_shadow": False,
                       **{f"agent_jb_rt_stage_{s}": ("auto" if s == "route" else "off") for s in RT_STAGES}})
    marks = _marks(box)
    got = []
    for _ in range(4):
        box.agents_pass()
        got = [p for p in _new(box, marks, "RT")[1] if p["action"] == "rt_route_day"]
        if got:
            break
    assert got and got[0]["status"] == "applied", (got, _new(box, marks, "RT"))


def test_x04_the_service_desk_agents_do_not_run(box):
    box.settings(desk={"agent_enabled": True, "agent_shadow": False, **off_stages("agent_stage_", SD_STAGES, "first_reply", "auto")})
    n = lambda: len((box.agent_db().get("tickets") or {}).get("agent_queue", []))  # noqa: E731
    before, calls = n(), len(box.ai_calls())
    box.agents_pass()
    assert n() == before and len(box.ai_calls()) == calls


def test_x04_turning_it_back_on_resumes(box):
    box.control("POST", "/desk-off", {"off": False})
    assert "skipped" not in box.agents_pass()
