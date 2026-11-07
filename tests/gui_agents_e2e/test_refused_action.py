"""F-25, David 4 Nov (option A): what the rules refuse shows in the approval list with the reason, and can never be approved."""
from __future__ import annotations

import pytest

from test_matrix import _marks, _new
from test_workflows_3 import _booking_on, _job_now, _request_no_date, box  # noqa: F401 (box is a fixture)
from test_stage_grid import _sql
from test_review import _hr_tab, _jobs_tab
from test_workflows_3 import _job, _jobs_on
from test_guardrails_hr import _ask, _employee, _setup as _hr_setup
from test_guardrails_hr import box as hr_box  # noqa: F401 (a fixture)

BAD = "2031-01-01T07:00-09:00"


def _refused(box, mode="auto", **more):
    box.ai_reset("good", {"booking:offer": [{"action": "bk_offer_times", "window_keys": [BAD], "note": "ZAG", "why": "ZAG", "confidence": 0.9}]})
    _booking_on(box, "offer", agent_bk_stage_offer=mode, **more)
    marks = _marks(box)
    _request_no_date(box)
    jid = _sql(box, "SELECT job_id FROM booking_requests ORDER BY rowid DESC LIMIT 1")[0][0]
    for _ in range(3):
        box.agents_pass()
    return jid, [p for p in _new(box, marks, "BK")[1] if p["ref"] == jid], [q for q in _new(box, marks, "BK")[0] if q["ref"] == jid]


def test_a_refused_action_waits_for_a_person_with_the_reason(box):
    jid, props, _ = _refused(box)
    assert props and props[0]["status"] == "pending" and "Refused by the rules, nothing was done" in props[0]["hold_reason"], props


def test_it_can_not_be_approved_or_edited_only_cleared(box):
    jid, props, _ = _refused(box)
    pid = props[0]["proposal_id"]
    for how in ("approve", "edit"):
        st, d = box.desk("POST", f"/agent/proposals/{pid}/{how}", {})
        assert st != 200 and "refused" in str(d), (how, st, d)
    assert _job_now(box, jid)["job_status"] != "Suggested", "the refused offer was applied"
    st, d = box.desk("POST", f"/agent/proposals/{pid}/reject", {})
    assert st == 200 and d["status"] == "rejected", (st, d)


def test_practice_makes_no_notice(box):
    jid, props, _ = _refused(box, mode="auto", agent_bk_shadow=True)
    assert not [p for p in props if p["status"] == "pending"], props


# ── on screen: its own line, and only Reject ─────────────────────────────────
def _check(card, reject):
    card.wait_for()
    line = card.locator(".agRefused")
    line.wait_for()
    assert "Refused by the rules, nothing was done" in line.inner_text() and "⛔" in line.inner_text(), line.inner_text()
    assert "waiting because" not in card.inner_text(), card.inner_text()
    assert not card.get_by_role("button", name="Approve").count() and not card.get_by_role("button", name="Edit").count(), card.inner_text()
    card.get_by_role("button", name="Reject").wait_for()


def test_the_service_desk_card(box, person):
    jid, props, _ = _refused(box)
    who = person(box, "owner")
    who.desk_sign_in("owner")
    who.page.locator("#tabAgent").click()
    card = who.page.locator(f".agp[data-pid='{props[0]['proposal_id']}']")
    _check(card, "reject")
    card.locator("[data-do='reject']").click()
    card.wait_for(state="detached")


def test_the_jobs_card(box, person):
    import datetime as dt
    box.ai_reset("good", {"job:prep": [{"action": "delete_everything", "why": "ZAG", "confidence": 0.9}]})
    _jobs_on(box, "prep", agent_jb_prep_hour=16)
    jid = _job(box, box.today + dt.timedelta(days=1))
    box.clock(box.today, "16:30")
    marks = _marks(box)
    props = []
    for _ in range(4):
        box.agents_pass()
        props = [p for p in _new(box, marks, "JB")[1] if p["ref"] == jid]
        if props:
            break
    assert props and props[0]["status"] == "pending", _new(box, marks, "JB")
    who = _jobs_tab(person, box)
    _check(who.page.locator("[data-testid='agent-card']", has_text=jid).first, "reject")
    box.desk("POST", f"/agent/proposals/J{props[0]['proposal_id']}/reject", {})


def test_the_hr_card(hr_box, person):
    box = hr_box
    _hr_setup(box, mode="suggest", rule=[{"action": "delete_everything", "why": "ZAG", "confidence": 0.9}])
    marks = _marks(box)
    rid = _ask(box, _employee(box))
    props = []
    for _ in range(4):
        box.agents_pass()
        props = [p for p in _new(box, marks, "HR")[1] if p["ref"] == f"pto:{rid}"]
        if props:
            break
    assert props and props[0]["status"] == "pending", _new(box, marks, "HR")
    admin = _hr_tab(person, box)
    _check(admin.page.locator("[data-testid='hrag-card']", has_text=f"pto:{rid}").first, "reject")
