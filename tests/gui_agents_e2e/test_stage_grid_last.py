"""The stage grid's last three: JB-learn, HR-timeclock, HR-offboard. Each stage alone, in Off, Suggest and Auto."""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START
from test_env import CUST_RE
from test_matrix import HR_STAGES, JB_STAGES, _marks, _new, all_off, off_stages, setup
from test_stage_grid import _sql

_n = itertools.count(1)
MODES = [("off", None), ("suggest", "pending"), ("auto", "applied")]
NOTE = {"action": "jb_set_estimate", "minutes": 90, "why": "ZAG", "confidence": 0.9}


@pytest.fixture(params=["solo", "business"])
def jb(request):
    b = request.getfixturevalue(request.param)
    all_off(b)
    b.today = START + dt.timedelta(days=24000 + 60 * next(_n))
    b.clock(b.today, "10:00")
    yield b
    all_off(b)


@pytest.fixture
def hr(business):
    all_off(business)
    setup(business, "HR", "OFF")                    # finishes HR setup
    business.today = START + dt.timedelta(days=24000 + 60 * next(_n))
    while business.today.weekday() != 1:
        business.today += dt.timedelta(days=1)
    business.clock(business.today, "10:00")
    yield business
    all_off(business)


# jb_set_estimate is high risk: on Auto it still waits for a person
@pytest.mark.parametrize("mode,want", [("off", None), ("suggest", "pending"), ("auto", "pending")], ids=["off", "suggest", "auto"])
def test_jb_learn(jb, mode, want):
    box = jb
    n = next(_n)
    r = box.tool("create_customer", updates={"Customer Name / Company": f"ZAG Learn {n}", "Phone": "386-555-0186"})
    cid = re.search(CUST_RE, str(r)).group(0)
    for k in range(1, 6):
        box.tool("create_job", updates={"CustomerID": cid, "Customer Name / Company": f"ZAG Learn {n}", "Service Type": "Window", "Job Status": "Complete",
                                        "Service Date": (box.today - dt.timedelta(days=k)).isoformat(), "Actual Duration": 90, "Actual Duration Unit": "Minutes",
                                        "Est Duration": 30, "Est Duration Unit": "Minutes"})
    _sql(box, "UPDATE jobs SET actual_duration = 90, actual_duration_unit = 'min', est_duration = 30, est_duration_unit = 'min' WHERE customer_id = ?", (cid,))
    box.ai_reset("good", {"job:learn": [NOTE]})
    box.settings(jobs={"agent_jb_enabled": True, "agent_jb_shadow": False, **off_stages("agent_jb_stage_", JB_STAGES, "learn", mode)})
    marks = _marks(box)
    props = []
    for _ in range(3):
        box.agents_pass()
        props = [p for p in _new(box, marks, "JB")[1] if p["ref"] == cid]
        if props:
            break
    if want is None:
        assert not props, props
    else:
        assert props and props[0]["status"] == want, (props, _new(box, marks, "JB")[0])


def _employee(box):
    n = next(_n)
    st, j = box.hr("POST", "/employees", {
        "personal": {"first_name": "ZAG", "last_name": f"Grid{n}", "personal_email": f"grid{n}@time-machine.test", "phone": "", "address": ""},
        "employment": {"title": "Window tech", "department": "Field", "start_date": "2020-01-06", "work_state": "FL", "employment_type": "full_time",
                       "remote_status": "onsite", "manager_name": ""},
        "compensation": {"pay_type": "hourly", "pay_rate": 22}})
    assert st in (200, 201), j
    return (j.get("employee") or j)["id"]


def _hr(box, stage, mode, rule):
    box.ai_reset("good", {f"hr:{stage}": [rule]})
    box.settings(hr={"agent_hr_enabled": True, "agent_hr_shadow": False, **off_stages("agent_hr_stage_", HR_STAGES, stage, mode)})


@pytest.mark.parametrize("mode", ["off", "suggest", "auto"])
def test_hr_timeclock_a_missed_clock_out(hr, mode):
    box = hr
    eid = _employee(box)
    rid = f"ZAG-T{next(_n)}"
    yesterday = (box.today - dt.timedelta(days=1)).isoformat()
    box.control("POST", "/hr-clock-in", {"id": rid, "employee_id": eid, "clock_in": yesterday + "T08:00:00"})
    _hr(box, "timeclock", mode, {"action": "hr_flag", "flag": "missed_clock_out", "detail": "ZAG", "why": "ZAG", "confidence": 0.9})
    marks = _marks(box)
    box.agents_pass()
    q, p = _new(box, marks, "HR")
    mine = [x for x in p if x["ref"] == f"time:{rid}"]
    if mode == "off":
        assert not mine, mine
    else:
        assert [x for x in q if x["ref"] == f"time:{rid}" and "missed_clock_out" in str(x["reason"])], q
        assert mine and mine[0]["status"] == "applied", mine           # a flag changes nothing, so it's applied even on Suggest


@pytest.mark.parametrize("mode,want", MODES, ids=[m for m, _ in MODES])
def test_hr_offboard_a_person_leaving(hr, mode, want):
    box = hr
    eid = _employee(box)
    out = box.tool("hr_initiate_termination", employee_id=eid, type="voluntary", effective_date=(box.today + dt.timedelta(days=14)).isoformat(), reason="ZAG")
    assert "error" not in str(out).lower()[:60], out
    _hr(box, "offboard", mode, {"action": "hr_task", "title": "ZAG collect the keys", "priority": "MEDIUM", "why": "ZAG", "confidence": 0.9})
    marks = _marks(box)
    box.agents_pass()
    mine = [x for x in _new(box, marks, "HR")[1] if x["ref"] == f"emp:{eid}"]
    if want is None:
        assert not mine, mine
    else:
        assert mine and mine[0]["status"] == want, (mine, _new(box, marks, "HR")[0])
