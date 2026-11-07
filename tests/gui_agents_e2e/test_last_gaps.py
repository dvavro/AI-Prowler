"""The last small gaps: what a crew member can read of the routes (WF-07, WF-09 /remote/ side), and the rest of RV-12."""
from __future__ import annotations

import datetime as dt

from conftest import USERS, http
from test_guardrails_hr import box as hr_box  # noqa: F401 (a fixture)
from test_matrix import HR_TEXT, _marks, _new, off_stages, HR_STAGES
from test_workflows_routes import SPOTS, _day, _send_day, biz  # noqa: F401 (biz is a fixture)
from test_small_gaps import _team_employee


def _crew_call(box, key, tool, **args):
    st, d = http("POST", box.base + "/pwa-login", {"name": USERS[key][0], "token": box.tokens[key]})
    assert d.get("access_token"), (st, d)
    st, r = http("POST", box.base + "/pwa-api", {"tool": tool, "args": args}, token=d["access_token"])
    assert st == 200, (st, r)
    return str(r)


def test_a_crew_member_reads_only_their_own_route(biz):
    ids, wed, marks, mail, props = _send_day(biz, _day(1), [(0, "ZAG Crew Cris"), (1, "ZAG Crew Dee")])
    assert len(props) == 2 and all(p["status"] == "applied" for p in props), props
    mine = _crew_call(biz, "cris", "get_approved_route_stops", start_date=wed.isoformat())
    assert ids[0] in mine and ids[1] not in mine, mine[:600]
    asked = _crew_call(biz, "cris", "get_approved_route_stops", start_date=wed.isoformat(), crew="ZAG Crew Dee")
    assert ids[1] not in asked, "a crew member read someone else's route: " + asked[:600]


def test_a_crew_member_can_not_run_or_read_the_agents(biz):
    out = _crew_call(biz, "cris", "jobs_agent", action="list")
    assert "only" in out.lower() or "not" in out.lower() or "❌" in out, out[:400]
    assert '"proposal_id"' not in out, out[:400]


def test_rv_12_a_manager_never_sees_onboarding_even_for_their_team(hr_box):
    box = hr_box
    box.ai_reset("good", {"hr:onboard": [{"action": "hr_remind_employee", "body": HR_TEXT, "why": "ZAG", "confidence": 0.9}]})
    box.settings(hr={"agent_hr_enabled": True, "agent_hr_shadow": False, "agent_hr_reviewers": "hr_admin_managers",
                     **off_stages("agent_hr_stage_", HR_STAGES, "onboard", "suggest")})
    marks = _marks(box)
    _team_employee(box, "ZAG Manager")
    box.agents_pass()
    props = [p for p in _new(box, marks, "HR")[1] if p["status"] == "pending"]
    assert props, _new(box, marks, "HR")
    st, d = box.desk("GET", "/agent/inbox", key="manager")
    assert st == 200 and not {p["ref"] for p in props} & {p["ref"] for p in d["pending"]}, d["pending"]
    st, d = box.desk("POST", f"/agent/proposals/H{props[0]['proposal_id']}/approve", {}, key="manager")
    assert st != 200 and "time off" in str(d), (st, d)
