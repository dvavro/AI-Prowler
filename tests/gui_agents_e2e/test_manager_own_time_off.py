"""AG-RV-12, the last part: a manager asks for their own time off like anyone else, and someone else decides it."""
from __future__ import annotations

from conftest import USERS
from test_guardrails_hr import _setup as _hr_setup, _weekday
from test_guardrails_hr import box as hr_box  # noqa: F401 (a fixture)
from test_matrix import _marks, _new


def _portal(person, box):
    who = person(box, "manager")
    p = who.page
    p.goto(box.base + "/hr_portal/")
    who.type("#login-name", USERS["manager"][0])
    who.type("#login-pass", box.tokens["manager"])
    p.locator("#login-btn").click()
    p.wait_for_selector("#app.visible", timeout=20_000)
    return p


def test_a_manager_requests_time_off_and_can_not_approve_it_themselves(hr_box, person):
    box = hr_box
    _hr_setup(box, mode="suggest", agent_hr_reviewers="hr_admin_managers")
    p = _portal(person, box)
    day = _weekday(box, 21).isoformat()
    marks = _marks(box)
    st, j = p.evaluate("""async (d) => { const r = await fetch('/hr-api/pto/request', {method: 'POST', headers: {'Content-Type': 'application/json',
        'X-Employee-Session': JSON.stringify(authState.session)}, body: JSON.stringify({type: 'PTO (Vacation)', start_date: d, end_date: d, notes: 'ZAG'})});
        return [r.status, await r.json()]; }""", day)
    assert st == 201, j                                                # they can ask
    rid = j["request"]["id"]
    st, d = box.hr("GET", "/employees")
    me = [e for e in (d.get("employees") or d) if e.get("id") == j["request"]["employee_id"]][0]
    st, u = box.hr("PATCH", f"/employees/{me['id']}", {"employment": {**(me.get("employment") or {}), "manager_name": USERS["manager"][0]}})
    assert st == 200, u                                                # even listed under themselves
    props = []
    for _ in range(4):
        box.agents_pass()
        props = [x for x in _new(box, marks, "HR")[1] if x["ref"] == f"pto:{rid}"]
        if props:
            break
    assert props and props[0]["status"] == "pending", _new(box, marks, "HR")
    pid = props[0]["proposal_id"]
    st, d = box.desk("POST", f"/agent/proposals/H{pid}/approve", {}, key="manager")
    assert st != 200 and "not your own" in str(d), (st, d)             # someone else decides
    st, d = box.desk("POST", f"/agent/proposals/H{pid}/approve", {}, key="owner")
    assert st == 200, (st, d)
    st, d = box.hr("GET", "/pto")
    assert [r for r in d["requests"] if r["id"] == rid][0]["status"] == "approved"
