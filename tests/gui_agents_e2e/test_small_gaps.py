"""AG-RV-08, 11, 12 and AG-MD-08, 10."""
from __future__ import annotations

import pytest

import desk_agent_providers as prov
from test_guardrails_booking import FIRST, _run as _bk_run, _setup as _bk_setup
from test_guardrails_booking import box as bk_box  # noqa: F401 (a fixture)
from test_guardrails_hr import _ask, _employee, _setup as _hr_setup
from test_guardrails_hr import box as hr_box  # noqa: F401 (a fixture)
from test_matrix import _api_calls, _marks, _new, all_off, setup, trigger


REC = lambda keys: [{"action": "bk_recommend", "choice": "approve", "window_key": keys[0], "why": "ZAG fits", "confidence": 0.9}]  # noqa: E731
HR_REC = [{"action": "hr_recommend", "choice": "approve", "why": "ZAG fits", "confidence": 0.9}]


# ── RV-08: the booking card ──────────────────────────────────────────────────
def _card(person, box):
    who = person(box, "owner")
    who.desk_sign_in("owner")
    who.page.locator("#tabBookings").click()
    return who, who.page


def test_rv_08_suggestion_line_and_use_this(bk_box, person):
    box = bk_box
    _bk_setup(box, mode="suggest")
    p, *_ = _bk_run(box, REC)
    who, page = _card(person, box)
    line = page.get_by_text("suggests:").first
    line.wait_for()
    page.locator("[data-use]").first.click()
    page.locator("#toast", has_text="Filled in").first.wait_for(state="visible")
    st, d = box.desk("GET", "/bookings")
    assert not [b for b in (d.get("scheduled") or []) if b.get("job_id") == p["ref"]], "Use this only fills the card in; you still tap Approve"


def test_rv_08_practice_shows_it_with_thumbs(bk_box, person):
    box = bk_box
    _bk_setup(box, mode="suggest")
    box.settings(desk={"agent_bk_shadow": True})
    p, *_ = _bk_run(box, REC)
    assert p["status"] == "practice", p
    who, page = _card(person, box)
    page.get_by_text("(practice)").first.wait_for()
    page.locator("[data-fb='up']").first.click()
    page.locator("#toast", has_text="noted").first.wait_for(state="visible")
    box.settings(desk={"agent_bk_shadow": False})


# ── RV-11: HR time-off rows ──────────────────────────────────────────────────
def _hr_row(person, box):
    admin = person(box, "hr-admin")
    admin.hr_admin_sign_in()
    admin.page.locator("[data-tab='attendance']").first.evaluate("b => { b.scrollIntoView({block: 'center'}); b.click(); }")
    return admin.page


def _hr_rec(box, **kw):
    _hr_setup(box, mode="suggest", rule=HR_REC, **kw)
    marks = _marks(box)
    rid = _ask(box, _employee(box))
    box.agents_pass()
    props = [p for p in _new(box, marks, "HR")[1] if p["ref"] == f"pto:{rid}"]
    assert props, _new(box, marks, "HR")
    return props[0]


def test_rv_11_time_off_row_shows_the_suggestion(hr_box, person):
    p = _hr_rec(hr_box)
    page = _hr_row(person, hr_box)
    page.locator("[data-testid='hrag-rec']", has_text="suggests approve").first.wait_for()


def test_rv_11_the_time_off_tab_shows_it_too(hr_box, person):
    _hr_rec(hr_box)
    admin = person(hr_box, "hr-admin")
    admin.hr_admin_sign_in()
    admin.page.locator("[data-tab='timeoff']").first.evaluate("b => { b.scrollIntoView({block: 'center'}); b.click(); }")
    admin.page.locator("#tab-timeoff [data-testid='hrag-rec']", has_text="suggests approve").first.wait_for()


def test_rv_11_in_practice_it_says_so(hr_box, person):
    p = _hr_rec(hr_box, practice=True)
    assert p["status"] == "practice", p
    page = _hr_row(person, hr_box)
    page.locator("[data-testid='hrag-rec']", has_text="(practice)").first.wait_for()


def test_a_rated_hr_practice_card_leaves_and_its_rating_stays(hr_box, person):
    from test_review import _hr_tab
    box = hr_box
    p = _hr_rec(box, practice=True)
    admin = _hr_tab(person, box)
    card = admin.page.locator(f"#tab-agent [data-pid='H{p['proposal_id']}']")
    card.locator("[data-hrag='up']").click()
    card.wait_for(state="detached")
    admin.page.locator("#agRatings", has_text="good").wait_for()
    row = [q for q in box.agent_db()["hr_agent"]["agent_proposals"] if q["proposal_id"] == p["proposal_id"]][0]
    assert row["feedback"] == "up" and row["status"] == "practice"


# ── RV-12: what a manager may review ─────────────────────────────────────────
def _team_employee(box, manager):
    import itertools
    n = next(_ids)
    st, j = box.hr("POST", "/employees", {
        "personal": {"first_name": "ZAG", "last_name": f"Team{n}", "personal_email": f"team{n}@time-machine.test", "phone": "", "address": ""},
        "employment": {"title": "Window tech", "department": f"ZAG Team {n}", "start_date": "2020-01-06", "work_state": "FL",
                       "employment_type": "full_time", "remote_status": "onsite", "manager_name": manager},
        "compensation": {"pay_type": "hourly", "pay_rate": 22}})
    assert st in (200, 201), j
    eid = (j.get("employee") or j)["id"]
    for kind in ("pto", "sick"):
        box.hr("POST", "/pto/adjust", {"employee_id": eid, "days": 10, "kind": kind, "date": box.today.isoformat(), "note": "ZAG"})
    return eid


import itertools  # noqa: E402
_ids = itertools.count(1)


def _manager_sees(box):
    st, d = box.desk("GET", "/agent/inbox", key="manager")
    assert st == 200, d
    return {p["ref"] for p in d["pending"]}


def _rid_refs(box, reviewers):
    _hr_setup(box, mode="suggest", agent_hr_reviewers=reviewers)
    mine = _ask(box, _team_employee(box, "ZAG Manager"))
    other = _ask(box, _team_employee(box, "Someone Else"))
    box.agents_pass()
    return f"pto:{mine}", f"pto:{other}"


def test_rv_12_managers_not_allowed_see_none(hr_box):
    mine, other = _rid_refs(hr_box, "hr_admin")
    assert not {mine, other} & _manager_sees(hr_box)


def test_rv_12_a_manager_sees_only_their_own_team(hr_box):
    mine, other = _rid_refs(hr_box, "hr_admin_managers")
    seen = _manager_sees(hr_box)
    assert mine in seen and other not in seen, seen


def test_rv_12_a_manager_can_not_decide_for_another_team(hr_box):
    mine, other = _rid_refs(hr_box, "hr_admin_managers")
    rows = {p["ref"]: p for p in (hr_box.agent_db().get("hr_agent") or {}).get("agent_proposals", [])}
    st, d = hr_box.desk("POST", f"/agent/proposals/H{rows[other]['proposal_id']}/approve", {}, key="manager")
    assert st != 200 and "own team" in str(d), (st, d)
    st, d = hr_box.desk("POST", f"/agent/proposals/H{rows[mine]['proposal_id']}/approve", {}, key="manager")
    assert st == 200, (st, d)


# ── MD-08, 10 ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("section,db", [("SD", "tickets"), ("JB", "jobs_agent")])
def test_md_08_recorded_spend_matches_tokens_and_price_table(business, section, db):
    box = business
    all_off(box)
    try:
        box.ai_reset("good", {})
        setup(box, section, "SUG")
        trigger(box, section)
        box.agents_pass()
        calls = [c for c in box.ai_calls()]
        assert calls
        runs = (box.agent_db().get(db) or {}).get("agent_runs") or []
        assert runs, list((box.agent_db().get(db) or {}).keys())
        r = sorted(runs, key=lambda x: x["run_id"])[-1]
        model = r["model"]
        price = prov.DEFAULT_PRICES[model]
        want = r["input_tokens"] * price[0] / 1e6 + r["output_tokens"] * price[1] / 1e6
        assert r["input_tokens"] > 0 and abs(r["cost_usd"] - want) < 0.00002, (r, want)
    finally:
        all_off(box)


def test_md_10_hr_runs_on_the_key_with_its_own_model(business):
    box = business
    all_off(box)
    try:
        setup(box, "HR", "SUG")
        marks = _marks(box)
        box.ai_reset("good", {})
        trigger(box, "HR")
        box.agents_pass()
        got = _api_calls(box, "hr")
        assert got and _new(box, marks, "HR")[1], (got, _new(box, marks, "HR"))
        assert {c["model"] for c in got} == {"claude-haiku-5-5"}, got
    finally:
        all_off(box)
