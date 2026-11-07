"""AG-ENV — the harness itself, and one smoke test per agent (AGENTS_GUI_E2E_TEST_SPEC.md §1.7).

The smoke tests run each agent once in PRACTICE mode on the Claude API runner (answered by the stand-in AI),
check what was queued, what the AI was asked (and with which model), that nothing changed or was sent — and
then show the result in that agent's own app, so you can watch it in human mode.
"""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

import pytest

from conftest import START, http

MAIN, LIGHT = "claude-sonnet-5-5", "claude-haiku-5-5"
CUST_RE, JOB_RE = r"CUST-\d{4}-\d+", r"JOB-(?:\d{4}-)?\d+"         # CUST-2026-1 (CUST-YEAR-N since 2026-10-04)
REAL_STATE = Path.home() / ".ai-prowler"


def _fingerprint():
    """The real install's agent and job databases: size + modified time (they must not change)."""
    files = [REAL_STATE / "tickets_database" / "ai_prowler_tickets.db", REAL_STATE / "agent_database" / "agent.db",
             REAL_STATE / "hr" / "agent" / "hr_agent.db"]
    return {str(f): (f.stat().st_size, int(f.stat().st_mtime)) for f in files if f.exists()}


_BEFORE = _fingerprint()


def _rows(box, db, table):
    return (box.agent_db().get(db) or {}).get(table) or []


def _agent_on(box, *, desk=None, jobs=None, hr=None):
    base = {"agent_provider": "claude_api", "agent_batch_seconds": 0}
    return box.settings(desk={**base, **(desk or {})}, jobs=jobs, hr=hr)


# ── AG-ENV-01 … 07 ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("kind", ["solo", "business"])
def test_env_01_sandbox_starts(kind, request):
    box = request.getfixturevalue(kind)
    st = box.control("GET", "/state")
    assert st["today"] == START.isoformat() and "_home" in st["sandbox"], st
    assert http("GET", box.base + "/desk/")[0] == 200


@pytest.mark.parametrize("kind", ["solo", "business"])
def test_env_03_nothing_gets_out(kind, request):
    box = request.getfixturevalue(kind)
    out = box.control("POST", "/probe-net", {})
    assert out["urllib"].startswith("blocked") and out["requests"].startswith("blocked"), out
    hosts = {m["to"] for m in box.blocked()}
    assert {"api.anthropic.com", "api.x.ai"} <= hosts, hosts


def test_env_05_no_key_nothing_runs(solo):
    """David 5 Nov: no saved key, no agent: nothing is queued, nothing reaches an AI."""
    box = solo
    box.ai_reset()
    box.settings(desk={"agent_enabled": True, "agent_shadow": True})
    box.no_key()
    try:
        before = len(_rows(box, "tickets", "agent_queue"))
        st, d = box.desk("POST", "/tickets", {"kind": "external", "title": "ZAG no key ticket", "contact_name": "ZAG No Key", "contact_phone": "386-555-0190"})
        assert st == 201, d
        box.agents_pass()
        assert not box.ai_calls() and len(_rows(box, "tickets", "agent_queue")) == before
        assert "API key" in box.desk("GET", "/agent/inbox")[1]["status"]["ready_note"]
    finally:
        box.no_key(False)
        box.settings(desk={"agent_enabled": False})


def test_env_06_clock_moves(solo):
    solo.clock(START + dt.timedelta(days=4), "16:30")
    assert solo.now().strftime("%Y-%m-%d %H:%M") == f"{START + dt.timedelta(days=4)} 16:30"
    solo.clock(START, "09:00")


# ── AG-ENV-08 smoke: one per agent, practice mode, Claude API runner ─────────
def test_env_08_smoke_service_desk(solo, person):
    box = solo
    box.clock(START, "09:00")
    box.ai_reset()
    _agent_on(box, desk={"agent_enabled": True, "agent_shadow": True})
    st, d = box.desk("POST", "/tickets", {"kind": "external", "title": "ZAG streaks on the front windows",
                                          "contact_name": "ZAG Maria", "contact_phone": "386-555-0142",
                                          "description": "Left side is streaky after Tuesday's clean."})
    assert st == 201, d
    tid = d["ticket"]["ticket_id"]
    out_before = len(box.outbox())
    res = box.agents_pass()
    calls = [c for c in box.ai_calls() if c["kind"] == "ticket"]
    assert {(c["stage"], c["model"]) for c in calls} >= {("intake", LIGHT), ("first_reply", MAIN)}, (calls, res)
    props = [p for p in _rows(box, "tickets", "agent_proposals") if p["ref"] == tid]
    assert props and all(p["status"] == "practice" for p in props), props
    assert not [m for m in box.outbox()[out_before:] if m.get("kind") in ("email", "sms")], "practice sent something"
    assert not box.blocked() or {m["to"] for m in box.blocked()} <= {"api.anthropic.com", "api.x.ai"}
    # watch it: the owner's 🤖 Agent tab shows the practice results
    owner = person(box, "owner")
    owner.desk_sign_in()
    owner.page.locator("#tabAgent").click()
    owner.page.get_by_text("Practice — what it would have done").wait_for()
    assert owner.page.locator(".agp", has_text=tid).count() >= 1
    owner.pause(2500)
    box.settings(desk={"agent_enabled": False})


def test_env_08_smoke_bookings(solo, person):
    """A service request with no date (filed by the owner for a caller) → Check (internal step, light model) and
    Offer times (complex step, main model), both in practice."""
    box = solo
    box.clock(START, "09:00")
    box.ai_reset()
    _agent_on(box, desk={"agent_enabled": True, "agent_shadow": True, "agent_bk_enabled": True,
                         "agent_bk_shadow": True, "portal_enabled": True, "staff_booking": True,
                         "booking_paths": ["book", "new", "problem"]})
    st, d = box.desk("POST", "/book", {"path": "new", "name": "ZAG Booking Smoke", "phone": "386-555-0155",
                                       "address": {"street": "300 Flagler Ave", "city": "New Smyrna Beach",
                                                   "state": "FL", "zip": "32169"},
                                       "service": "Gutter cleaning", "preferred": "Tuesday or Thursday mornings",
                                       "description": "ZAG two-storey house", "notify": False, "source": "phone"})
    assert st in (200, 201), d
    out_before = len(box.outbox())
    box.agents_pass()
    calls = [c for c in box.ai_calls() if c["kind"] == "booking"]
    got = {(c["stage"], c["model"]) for c in calls}
    assert {("check", LIGHT), ("offer", MAIN)} <= got, (calls, d)
    props = [p for p in _rows(box, "tickets", "agent_proposals") if p["kind"] == "booking"]
    assert props and all(p["status"] == "practice" for p in props), props
    assert not [m for m in box.outbox()[out_before:] if m.get("kind") in ("email", "sms")], "practice sent something"
    owner = person(box, "owner")
    owner.desk_sign_in()
    owner.page.locator("#tabAgent").click()
    owner.page.locator(".agp", has_text="Booking").first.wait_for()
    owner.pause(2500)
    box.settings(desk={"agent_enabled": False, "agent_bk_enabled": False})


def test_env_08_smoke_jobs(solo, person):
    box = solo
    box.clock(START, "09:00")
    box.ai_reset()
    _agent_on(box, jobs={"agent_jb_enabled": True, "agent_jb_shadow": True})
    r = box.tool("create_customer", updates={"Customer Name / Company": "ZAG Jobs Smoke Customer",
                                              "Street Address": "100 Flagler Ave", "City": "New Smyrna Beach",
                                              "State": "FL", "Zip": "32169", "Phone": "386-555-0177"})
    cid = re.search(CUST_RE, r or "")
    assert cid, r
    r = box.tool("create_job", updates={"CustomerID": cid.group(0), "Customer Name / Company": "ZAG Jobs Smoke Customer",
                                         "Street Address": "100 Flagler Ave", "Service Type": "Window",
                                         "Job Status": "Unscheduled"})
    jid = re.search(JOB_RE, r or "")
    assert jid, r
    box.agents_pass()
    calls = [c for c in box.ai_calls() if c["kind"] == "job"]
    assert ("schedule", MAIN) in {(c["stage"], c["model"]) for c in calls}, calls
    props = [p for p in _rows(box, "jobs_agent", "agent_proposals") if p["ref"] == jid.group(0)]
    assert props and all(p["status"] == "practice" for p in props), props
    owner = person(box, "owner")
    owner.jobs_sign_in()
    owner.page.locator("#navAgent").click()
    owner.page.locator("#agPractice [data-testid='agent-card']").first.wait_for()
    owner.pause(2500)
    box.settings(jobs={"agent_jb_enabled": False})


def test_env_08_smoke_route_flow(solo):
    """Sort the week runs on the sort weekday (Friday) for next week's jobs — a complex step, main model."""
    box = solo
    box.ai_reset()
    _agent_on(box, jobs={"agent_jb_rt_enabled": True, "agent_jb_rt_shadow": True})
    r = box.tool("create_customer", updates={"Customer Name / Company": "ZAG Route Smoke Customer",
                                              "Street Address": "200 Canal St", "City": "New Smyrna Beach",
                                              "State": "FL", "Zip": "32168"})
    cid = re.search(CUST_RE, r or "").group(0)
    for day in ("2026-11-16", "2026-11-17"):
        box.tool("create_job", updates={"CustomerID": cid, "Customer Name / Company": "ZAG Route Smoke Customer",
                                        "Street Address": "200 Canal St", "Service Type": "Window",
                                        "Service Date": day, "Job Status": "Scheduled"})
    box.clock(START + dt.timedelta(days=4), "09:00")        # Friday 13 Nov
    box.agents_pass()
    calls = [c for c in box.ai_calls() if c["kind"] == "route"]
    assert calls and all(c["model"] == MAIN for c in calls), calls
    assert "sort" in {c["stage"] for c in calls}, calls
    box.clock(START, "09:00")
    box.settings(jobs={"agent_jb_rt_enabled": False})


def test_env_08_smoke_hr(business, person):
    box = business
    box.clock(START, "09:00")
    box.ai_reset()
    st, j = box.hr("POST", "/setup/complete", {"company_name": "ZAG Agents Co", "work_states": ["FL"],
                                               "setup_complete": True, "hr_admin_email": "owner@time-machine.test",
                                               "owner_email": "owner@time-machine.test"})
    assert st == 200, j
    _agent_on(box, hr={"agent_hr_enabled": True, "agent_hr_shadow": True})
    st, j = box.hr("POST", "/employees", {
        "personal": {"first_name": "ZAG", "last_name": "Newhire", "personal_email": "newhire@time-machine.test",
                     "phone": "", "address": ""},
        "employment": {"title": "Window tech", "department": "Field", "start_date": "2026-11-12",
                       "work_state": "FL", "employment_type": "full_time", "remote_status": "onsite",
                       "manager_name": ""},
        "compensation": {"pay_type": "hourly", "pay_rate": 22}})
    assert st in (200, 201), j
    box.agents_pass()
    calls = [c for c in box.ai_calls() if c["kind"] == "hr"]
    assert ("onboard", LIGHT) in {(c["stage"], c["model"]) for c in calls}, (calls, box.agent_db().get("hr_agent"))
    props = _rows(box, "hr_agent", "agent_proposals")
    assert props and all(p["status"] == "practice" for p in props), props
    admin = person(box, "hr-admin")
    admin.hr_admin_sign_in()
    btn = admin.page.locator("[data-tab='agent']").first          # low in a long sidebar, outside the viewport:
    btn.evaluate("b => { b.scrollIntoView({block: 'center'}); b.click(); }")   # scroll it into sight, then press it
    admin.page.locator("#hrag-practice [data-testid='hrag-card']").first.wait_for()
    admin.pause(2500)
    box.settings(hr={"agent_hr_enabled": False})


# ── AG-ENV-02 last: the real install wasn't touched ──────────────────────────
def test_env_zz_real_install_untouched(solo):
    assert _fingerprint() == _BEFORE, "a real AI-Prowler database changed during the run"
