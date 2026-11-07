"""AG-RV-01…07, 09, 10, 13, 14 — the 🤖 Agent review screens in the Service Desk app, the Jobs app and HR Admin:
waiting and practice lists, Approve, Edit, Reject, 👍 / 👎, Run now, who can see them, and a suggestion decided twice.

The clicks are real; the check behind each click reads the sandbox's agent database and outbox. Still to write:
AG-RV-08 (booking suggestion line), AG-RV-11 and AG-RV-12 (HR time-off rows, manager filter).
"""
from __future__ import annotations

import datetime as dt
import itertools
import re

import pytest

from conftest import START, http
from test_env import CUST_RE, JOB_RE

REPLY = "ZAG stand-in reply: sorry about the streaks, we can come back Thursday."
EDITED = "ZAG edited by the owner: we'll be back Thursday morning."
TICKET_STAGES = ("intake", "first_reply", "resolution", "follow_through", "learn")
JB_STAGES = ("quotes", "schedule", "prep", "onsite", "closeout", "collect", "repeat", "learn")
PREP = "ZAG stand-in prep note: gate code is 4417, side door."
HR_TEXT = "ZAG stand-in: please finish your first-week forms."
_n = itertools.count(1)
_days = itertools.count(0)                       # Prep runs once a day: each Jobs review test gets its own day
BOTH = ["solo", "business"]


@pytest.fixture(params=BOTH)
def box(request):
    return request.getfixturevalue(request.param)


@pytest.fixture(autouse=True)
def leave_it_clean(request):
    """Waiting suggestions keep the Service Desk 🤖 tab showing with the agent off (David 3 Nov), and the sandboxes
    are shared by the whole run: reject what's left, switch the agents off and put the clock back."""
    boxes = [request.getfixturevalue(n) for n in ("box", "solo", "business") if n in request.fixturenames]
    yield
    for b in boxes:
        st, d = b.desk("GET", "/agent/inbox")
        for p in (d.get("pending") or []) if st == 200 else []:
            b.desk("POST", f"/agent/proposals/{p['proposal_id']}/reject", {})
        b.settings(desk={"agent_enabled": False}, jobs={"agent_jb_enabled": False},
                   hr={"agent_hr_enabled": False})
        b.clock(START, "09:00")


def _rows(box, db, table="agent_proposals"):
    return (box.agent_db().get(db) or {}).get(table) or []


def _prop(box, db, pid):
    pid = int(re.sub(r"\D", "", str(pid)))
    return next(p for p in _rows(box, db) if p["proposal_id"] == pid)


def _desk_setup(box, practice):
    """Only First reply on Suggest, on the Claude runner; it drafts REPLY."""
    box.clock(START, "09:00")
    box.ai_reset("good", {"ticket:first_reply": [{"action": "reply", "body": REPLY, "why": "ZAG customer asked",
                                                  "confidence": 0.9}]})
    box.settings(desk={"agent_enabled": True, "agent_shadow": practice, "agent_provider": "claude_api",
                       "agent_batch_seconds": 0, "agent_include_service_link": False, "agent_hours": [0, 24],
                       "agent_monthly_budget_usd": 20,
                       **{f"agent_stage_{s}": ("suggest" if s == "first_reply" else "off") for s in TICKET_STAGES}})


def _ticket(box, title="ZAG streaks on the windows"):
    title = f"{title} {next(_n)}"
    st, d = box.desk("POST", "/tickets", {"kind": "external", "title": title, "contact_name": "ZAG Maria",
                                          "contact_phone": "386-555-0142", "contact_email": "maria@time-machine.test"})
    assert st == 201, d
    return d["ticket"]["ticket_id"]


def _desk_pending(box, practice=False):
    _desk_setup(box, practice)
    tid = _ticket(box)
    box.agents_pass()
    st, d = box.desk("GET", "/agent/inbox")
    assert st == 200, d
    got = [p for p in d["practice" if practice else "pending"] if p["ref"] == tid and p["action"] == "reply"]
    assert got, (tid, d, box.ai_calls())
    return tid, got[0]


def _desk_tab(person, box, key="owner"):
    who = person(box, key)
    who.desk_sign_in(key)
    who.page.locator("#tabAgent").click()
    who.page.locator("#agHead").wait_for()
    return who


def _card(who, tid):
    c = who.page.locator(".agp", has_text=tid).filter(has_text="first_reply").first
    c.wait_for()
    return c


def _sent(box, text, since=0):
    return [m for m in box.outbox()[since:] if m.get("kind") != "blocked_http" and text in str(m)]


def _desk_off(box):
    box.settings(desk={"agent_enabled": False})


# ── Service Desk ─────────────────────────────────────────────────────────────
def test_rv_01_lists_pending_and_practice(box, person):
    tid, _ = _desk_pending(box)
    tid2, _ = _desk_pending(box, practice=True)
    box.settings(desk={"agent_shadow": False})
    who = _desk_tab(person, box)
    page = who.page
    page.get_by_text("Waiting for your OK").wait_for()
    page.get_by_text("Practice — what it would have done").wait_for()
    pend, prac = _card(who, tid), _card(who, tid2)
    assert pend.locator("[data-do='approve']").is_visible() and pend.locator("[data-do='reject']").is_visible()
    assert pend.locator("[data-do='edit']").is_visible() and REPLY in pend.inner_text()
    assert "waiting because" in pend.inner_text(), pend.inner_text()
    assert prac.locator("[data-do='up']").is_visible() and prac.locator("[data-do='down']").is_visible()
    assert prac.locator("[data-do='approve']").count() == 0
    who.pause(1500)
    _desk_off(box)


def test_rv_02_approve_sends_it(box, person):
    tid, p = _desk_pending(box)
    before = len(box.outbox())
    assert not _sent(box, REPLY, before)
    who = _desk_tab(person, box)
    _card(who, tid).locator("[data-do='approve']").click()
    who.page.locator("#toast", has_text="Done").first.wait_for(state="visible")
    assert _prop(box, "tickets", p["proposal_id"])["status"] == "applied"
    for _ in range(50):                                         # the email goes out on a background thread
        if _sent(box, REPLY, before):
            break
        who.page.wait_for_timeout(100)
    assert _sent(box, REPLY, before), box.outbox()[before:]
    st, d = box.desk("GET", f"/tickets/{tid}")
    assert st == 200 and REPLY in str(d), d
    who.pause(1200)
    _desk_off(box)


def test_rv_03_edit_then_approve_sends_the_edit(box, person):
    tid, p = _desk_pending(box)
    before = len(box.outbox())
    who = _desk_tab(person, box)
    seen = []

    def answer(dlg):
        seen.append(dlg.default_value)
        dlg.accept(EDITED)
    who.page.on("dialog", answer)
    _card(who, tid).locator("[data-do='edit']").click()
    who.page.locator("#toast", has_text="Done").first.wait_for(state="visible")
    assert seen == [REPLY]
    assert _prop(box, "tickets", p["proposal_id"])["status"] == "applied"
    for _ in range(50):                                         # the email goes out on a background thread
        if _sent(box, EDITED, before):
            break
        who.page.wait_for_timeout(100)
    assert _sent(box, EDITED, before) and not _sent(box, REPLY, before), box.outbox()[before:]
    who.pause(1200)
    _desk_off(box)


def test_rv_03_cancel_the_edit_changes_nothing(box, person):
    tid, p = _desk_pending(box)
    before = len(box.outbox())
    who = _desk_tab(person, box)
    who.page.on("dialog", lambda dlg: dlg.dismiss())
    _card(who, tid).locator("[data-do='edit']").click()
    who.page.wait_for_timeout(500)
    assert _prop(box, "tickets", p["proposal_id"])["status"] == "pending"
    assert not _sent(box, REPLY, before)
    _desk_off(box)


def test_rv_04_reject_sends_nothing(box, person):
    tid, p = _desk_pending(box)
    before = len(box.outbox())
    who = _desk_tab(person, box)
    _card(who, tid).locator("[data-do='reject']").click()
    who.page.locator("#toast", has_text="Rejected").first.wait_for(state="visible")
    assert _prop(box, "tickets", p["proposal_id"])["status"] == "rejected"
    assert not _sent(box, REPLY, before)
    who.page.locator(".agp", has_text=tid).filter(has_text="first_reply").first.wait_for(state="detached")
    who.pause(800)
    _desk_off(box)


def test_rv_05_thumbs_on_practice_apply_nothing(box, person):
    tid, p = _desk_pending(box, practice=True)
    before = len(box.outbox())
    who = _desk_tab(person, box)
    _card(who, tid).locator("[data-do='up']").click()
    who.page.locator(f".agp[data-pid='{p['proposal_id']}']").wait_for(state="detached")   # rated: it leaves the list
    row = _prop(box, "tickets", p["proposal_id"])
    assert row["feedback"] == "up" and row["status"] == "practice"                        # and the rating stays
    who.page.locator("#agRatings [data-rated='ticket']", has_text="good").wait_for()
    assert not _sent(box, REPLY, before)
    who.pause(800)
    _desk_off(box)


def test_rv_06_staff_and_crew_cant_review(business, person):
    box = business
    _desk_pending(box)
    for key in ("staff", "cris"):
        who = person(box, key)
        who.desk_sign_in(key)
        assert not who.page.locator("#tabAgent").is_visible(), key
        st, d = box.desk("GET", "/agent/inbox", key=key)
        assert st >= 400 and "only the owner or a manager" in str(d), (key, st, d)
        st, d = box.hr("GET", "/agent/pending", key=key)
        assert st in (401, 403), (key, st, d)
        who.pause(800)
    who = person(box, "manager")
    who.desk_sign_in("manager")
    assert who.page.locator("#tabAgent").is_visible()
    assert box.desk("GET", "/agent/inbox", key="manager")[0] == 200
    _desk_off(box)


def test_rv_07_run_now(box, person):
    _desk_setup(box, False)
    who = _desk_tab(person, box)
    tid = _ticket(box)
    assert who.page.locator(".agp", has_text=tid).count() == 0
    who.page.locator("#tabAgent").click()                      # read the head again: the ticket is waiting
    who.page.locator("#agRun").click()
    who.page.locator("#toast", has_text="Started").first.wait_for(state="visible")
    who.page.locator("#tabAgent").click()
    _card(who, tid)
    who.pause(1200)
    _desk_off(box)


def test_rv_13_status_lines_for_the_other_agents(solo, person):
    box = solo
    _desk_setup(box, False)
    box.settings(jobs={"agent_jb_enabled": True, "agent_jb_shadow": False})
    who = _desk_tab(person, box)
    head = who.page.locator("#agHead")
    assert re.search(r"Jobs agent: \d+ waiting in its queue · \d+ for your OK", head.inner_text()), head.inner_text()
    who.pause(1000)
    box.settings(jobs={"agent_jb_enabled": False})
    _desk_off(box)


def test_rv_14_a_second_decision_is_refused(box, person):
    tid, p = _desk_pending(box)
    who = _desk_tab(person, box)
    card = _card(who, tid)
    before = len(box.outbox())
    st, d = box.desk("POST", f"/agent/proposals/{p['proposal_id']}/approve", {})     # the other window got there first
    assert st == 200, d
    card.locator("[data-do='approve']").click()
    card.locator(".err", has_text="is applied, not waiting").wait_for()
    who.page.wait_for_timeout(500)
    assert len(_sent(box, tid, before)) == 1, box.outbox()[before:]    # sent once, not twice
    who.pause(1000)
    _desk_off(box)


# ── Jobs app (AG-RV-09) ──────────────────────────────────────────────────────
def _job_pending(box, practice=False):
    """Prep the day before, for a job with no address (Prep only queues jobs with a problem): a note for the crew,
    which waits on Suggest (jb_note would be applied at once)."""
    day = START + dt.timedelta(days=next(_days))
    box.clock(day, "16:30")
    box.ai_reset("good", {"job:prep": [{"action": "jb_prep_note", "body": PREP, "why": "ZAG gate code",
                                        "confidence": 0.9}]})
    box.settings(desk={"agent_provider": "claude_api", "agent_batch_seconds": 0, "agent_hours": [0, 24]},
                 jobs={"agent_jb_enabled": True, "agent_jb_shadow": practice, "agent_jb_prep_hour": 16,
                       **{f"agent_jb_stage_{s}": ("suggest" if s == "prep" else "off") for s in JB_STAGES}})
    seen = {p["proposal_id"] for p in _rows(box, "jobs_agent")}
    name = f"ZAG Review Customer {next(_n)}"
    r = box.tool("create_customer", updates={"Customer Name / Company": name, "Phone": "386-555-0177"})
    cid = re.search(CUST_RE, r or "")
    assert cid, r
    r = box.tool("create_job", updates={"CustomerID": cid.group(0), "Customer Name / Company": name,
                                         "Service Type": "Window",
                                         "Service Date": (day + dt.timedelta(days=1)).isoformat(),
                                         "Job Status": "Scheduled"})
    jid = re.search(JOB_RE, r or "")
    assert jid, r
    box.agents_pass()
    want = "practice" if practice else "pending"
    props = [p for p in _rows(box, "jobs_agent") if p["proposal_id"] not in seen and p["stage"] == "prep"
             and p["status"] == want]
    assert props, (jid.group(0), [(p["ref"], p["stage"], p["status"]) for p in _rows(box, "jobs_agent")[:6]],
                   [(c["kind"], c["stage"]) for c in box.ai_calls()])
    return props[0]["ref"], props[0]["proposal_id"]


def _jobs_tab(person, box):
    who = person(box, "owner")
    who.jobs_sign_in()
    who.page.locator("#navAgent").click()
    who.page.locator("#agStatus b").first.wait_for()
    return who


def _jcard(who, pid):
    c = who.page.locator(f"#screen-agent [data-pid='{pid}'], #screen-agent [data-pid='J{pid}']").first
    c.wait_for()
    return c


def test_rv_09_jobs_status_line_lists_and_approve(box, person):
    jid, pid = _job_pending(box)
    who = _jobs_tab(person, box)
    assert re.search(r"\d+ waiting in its queue · [1-9]\d* for your OK", who.page.locator("#agStatus").inner_text())
    card = _jcard(who, pid)
    assert jid in card.inner_text() and "waiting because" in card.inner_text(), card.inner_text()
    card.locator("[data-ag='approve']").click()
    who.page.locator("#toast", has_text="Done").first.wait_for(state="visible")
    assert _prop(box, "jobs_agent", pid)["status"] == "applied"
    who.pause(800)
    box.settings(jobs={"agent_jb_enabled": False})


def test_rv_09_jobs_edit_and_reject(box, person):
    _, pid = _job_pending(box)
    _, pid2 = _job_pending(box)
    who = _jobs_tab(person, box)
    who.page.on("dialog", lambda dlg: dlg.accept(EDITED))
    _jcard(who, pid).locator("[data-ag='edit']").click()
    who.page.locator("#toast", has_text="Done").first.wait_for(state="visible")
    row = _prop(box, "jobs_agent", pid)
    assert row["status"] == "applied"
    st = box.tool("read_job_spreadsheet", sheet_name="Jobs_Schedule", max_rows=500)
    assert EDITED in str(st), str(st)[:800]
    _jcard(who, pid2).locator("[data-ag='reject']").click()
    who.page.locator("#toast", has_text="Rejected").first.wait_for(state="visible")
    assert _prop(box, "jobs_agent", pid2)["status"] == "rejected"
    who.pause(800)
    box.settings(jobs={"agent_jb_enabled": False})


def test_rv_09_jobs_thumbs_and_run_now(solo, person):
    box = solo
    _, pid = _job_pending(box, practice=True)
    who = _jobs_tab(person, box)
    _jcard(who, pid).locator("[data-ag='down']").click()
    who.page.locator("#agRatings [data-rated='job']", has_text="not right").wait_for()    # rated: it leaves the list
    assert not who.page.locator(f"#screen-agent [data-pid='J{pid}']").count()
    row = _prop(box, "jobs_agent", pid)
    assert row["feedback"] == "down" and row["status"] == "practice"                      # and the rating stays
    who.page.locator("#agRunNow").click()
    who.page.locator("#toast.show").first.wait_for()
    who.pause(800)
    box.settings(jobs={"agent_jb_enabled": False})


def test_rv_06_jobs_agent_refuses_crew(business):
    st, d = http("POST", business.base + "/pwa-login", {"name": "ZAG Crew Cris", "token": business.tokens["cris"]})
    assert st == 200 and d.get("access_token"), d
    r = http("POST", business.base + "/desk-api/agent/proposals/1/approve", {}, token=business.desk_token("cris"))
    assert r[0] >= 400 and "only the owner or a manager" in str(r[1]), r


# ── HR Admin (AG-RV-10) ──────────────────────────────────────────────────────
def _hr_pending(box, practice=False):
    box.clock(START, "09:00")
    box.ai_reset("good", {"hr:onboard": [{"action": "hr_remind_employee", "body": HR_TEXT, "why": "ZAG first week",
                                          "confidence": 0.9}]})
    st, j = box.hr("POST", "/setup/complete", {"company_name": "ZAG Agents Co", "work_states": ["FL"],
                                               "setup_complete": True, "hr_admin_email": "owner@time-machine.test",
                                               "owner_email": "owner@time-machine.test"})
    assert st == 200, j
    box.settings(desk={"agent_provider": "claude_api", "agent_batch_seconds": 0},
                 hr={"agent_hr_enabled": True, "agent_hr_shadow": practice, "agent_hr_stage_onboard": "suggest"})
    seen = {p["proposal_id"] for p in _rows(box, "hr_agent")}
    st, j = box.hr("POST", "/employees", {
        "personal": {"first_name": "ZAG", "last_name": f"Review{next(_n)}", "personal_email": "rv@time-machine.test",
                     "phone": "", "address": ""},
        "employment": {"title": "Window tech", "department": "Field", "start_date": "2026-11-12", "work_state": "FL",
                       "employment_type": "full_time", "remote_status": "onsite", "manager_name": ""},
        "compensation": {"pay_type": "hourly", "pay_rate": 22}})
    assert st in (200, 201), j
    box.agents_pass()
    want = "practice" if practice else "pending"
    new = [p for p in _rows(box, "hr_agent") if p["proposal_id"] not in seen and p["status"] == want
           and p["stage"] == "onboard"]
    assert new, ([(p["ref"], p["stage"], p["status"]) for p in _rows(box, "hr_agent")[:6]],
                 [(c["kind"], c["stage"]) for c in box.ai_calls()])
    return new[0]["proposal_id"]


def _hr_tab(person, box):
    admin = person(box, "hr-admin")
    admin.hr_admin_sign_in()
    admin.page.locator("[data-tab='agent']").first.evaluate("b => { b.scrollIntoView({block: 'center'}); b.click(); }")
    admin.page.locator("#hrag-run").wait_for()
    return admin


def _hcard(admin, pid):
    c = admin.page.locator(f"#tab-agent [data-pid='H{pid}']")
    c.wait_for()
    return c


def test_rv_10_hr_status_approve_reject_badge_run_now(business, person):
    box = business
    pid = _hr_pending(box)
    pid2 = _hr_pending(box)
    admin = _hr_tab(person, box)
    assert "HR agent on" in admin.page.locator("#hrag-status").inner_text()
    badge = admin.page.locator("#sb-badge-agent")
    assert int(badge.inner_text() or 0) >= 2
    _hcard(admin, pid).locator("[data-hrag='approve']").click()
    admin.page.locator(f"#tab-agent [data-pid='H{pid}']").wait_for(state="detached")
    assert _prop(box, "hr_agent", pid)["status"] == "applied"
    _hcard(admin, pid2).locator("[data-hrag='reject']").click()
    admin.page.locator(f"#tab-agent [data-pid='H{pid2}']").wait_for(state="detached")
    assert _prop(box, "hr_agent", pid2)["status"] == "rejected"
    admin.page.locator("#hrag-run").click()
    admin.page.wait_for_timeout(800)
    admin.pause(800)
    box.settings(hr={"agent_hr_enabled": False})


def test_rv_10_hr_thumbs_on_practice(business, person):
    box = business
    pid = _hr_pending(box, practice=True)
    admin = _hr_tab(person, box)
    _hcard(admin, pid).locator("[data-hrag='down']").click()
    admin.page.locator(f"#tab-agent [data-pid='H{pid}']").wait_for(state="detached")      # rated: it leaves the list
    row = _prop(box, "hr_agent", pid)
    assert row["feedback"] == "down" and row["status"] == "practice"                      # and the rating stays
    admin.page.locator("#agRatings", has_text="not right").wait_for()
    admin.pause(800)
    box.settings(hr={"agent_hr_enabled": False})
