"""
HR onboarding -> offboarding, walked day by day in a real browser against the
HR TIME MACHINE sandbox (see conftest.py / hr_tm_server.py). The tests run in
order and share one story:

  01 hire day: HR hires the new hire with HR Admin's + New Employee form (the
     owner had already added them in the Admin tab, so their automatic
     placeholder becomes the hire) -> Pre-Start, login linked, onboarding tasks
     dated exactly per hr_task_templates.json
  02 the new hire signs in to the HR Portal and sees their own tasks
  03 walk to day one: welcome email once, 7 days before the start; Pre-Start
     until then, Onboarding on the first day
  04 the new hire marks a task done in the Portal
  05 walk on: due-today / first-overdue / escalation emails on the right days to
     the right people (CRITICAL next day, HIGH after two, never MEDIUM/LOW);
     nothing for the task done early
  06 onboarding finished -> Active the next morning (HR Admin shows it)
  07 HR terminates through HR Admin's Initiate Termination -> offboarding tasks
     dated per template, Offboarding until the last day, listed on Offboarding
  08 the employee still uses the Portal while working their notice
  09 walk past the last day: Terminated the day after, offboarding escalations
     on time, Termination Records lists them, the Portal turns them away
  10 the outbox: nothing sent twice, every email to a test address

Run on its own: tests\\run_tests_hr_gui_e2e.bat --timemachine [--headed]
"""
import datetime as dt
from collections import Counter

import pytest

from hr_tm_helpers import (HIRE_DAY, HR_EMAIL, START_DAY, TERM_DAY, TERM_NOTICE_DAY, USERS, expected_tasks,
                           mails_for, new_page, sign_in_admin, sign_in_portal)

D = dt.timedelta
S = {}                                   # the story's shared state
OPEN = ("Not Started", "In Progress", "Awaiting Document", "Overdue")


def _emp(tm):
    return tm.api("GET", f"/employees/{S['emp_id']}")[1]


def _tasks(tm):
    st, j = tm.api("GET", f"/tasks?employee_id={S['emp_id']}")
    return [t for t in (j.get("tasks") if isinstance(j, dict) else j) if t.get("employee_id") == S["emp_id"]]


# ── 01 ──────────────────────────────────────────────────────────────────────
def test_01_hr_hires_through_the_new_employee_form(browser, tm):
    tm.clock(HIRE_DAY, "09:00")
    ctx, page, watch = new_page(browser, "admin")
    sign_in_admin(page, tm)                                   # loads the list -> placeholders for server users
    st, j = tm.api("GET", "/employees")
    ph = [e for e in j["employees"] if e["last_name"] == "Newhire"]
    assert len(ph) == 1 and ph[0].get("created_by") == "server_user_sync", ph   # owner added them first
    loc = page.locator('[onclick="openNewEmployee()"]').first
    loc.click() if loc.is_visible() else page.evaluate("openNewEmployee()")
    page.wait_for_selector("#nef-first", state="visible")
    page.fill("#nef-first", "ZTEST")
    page.fill("#nef-last", "Newhire")
    page.fill("#nef-personal-email", USERS["newhire"][3])
    page.fill("#nef-title", "Field Technician")
    page.fill("#nef-start-date", START_DAY.isoformat())
    page.select_option("#nef-work-state", "FL")
    page.select_option("#nef-pay-type", "hourly")
    page.fill("#nef-pay-rate", "22")
    page.click('[onclick="saveNewEmployee()"]')
    page.wait_for_timeout(2500)
    st, j = tm.api("GET", "/employees")
    hires = [e for e in j["employees"] if e["last_name"] == "Newhire"]
    assert len(hires) == 1, hires                            # the placeholder became the hire - no duplicate
    emp = hires[0]
    S["emp_id"] = emp["id"]
    assert emp["status"] == "Pre-Start" and emp["start_date"] == START_DAY.isoformat()
    assert emp.get("aiprowler_user_id") == "ztest-newhire", emp
    mine = {t["template_id"]: t for t in _tasks(tm)}
    exp = expected_tasks("base", "FL", {"default": START_DAY, "hire_date": HIRE_DAY})
    assert set(mine) == set(exp), f"missing {set(exp) - set(mine)}, extra {set(mine) - set(exp)}"
    wrong = {k: (mine[k]["due_date"], v) for k, v in exp.items() if mine[k]["due_date"] != v}
    assert not wrong, f"due dates off (got, expected): {wrong}"
    assert "ZTEST Newhire" in page.inner_text("#tab-employees")
    assert not watch.errors, watch.errors
    ctx.close()


# ── 02 ──────────────────────────────────────────────────────────────────────
def test_02_new_hire_sees_their_tasks_in_the_portal(browser, tm):
    ctx, page, watch = new_page(browser, "newhire")
    assert sign_in_portal(page, tm, "newhire") == ""
    page.locator('.nav-item[data-page="tasks"]').first.evaluate("e => e.click()")
    page.wait_for_timeout(1500)
    txt = page.inner_text("#page-tasks")
    theirs = [t["name"] for t in _tasks(tm) if t.get("assigned_to_role") == "Employee"]
    assert theirs and any(n in txt for n in theirs), (theirs[:3], txt[:400])
    assert "Coworker" not in txt
    assert not watch.errors, watch.errors
    ctx.close()


# ── 03 ──────────────────────────────────────────────────────────────────────
def test_03_walk_to_the_first_day(tm):
    tm.walk(HIRE_DAY, START_DAY - D(days=1))
    assert _emp(tm)["status"] == "Pre-Start"
    welcome = [m for m in tm.outbox() if m.get("source") == "hr_scheduler" and "Welcome to the team" in m["subject"]]
    assert [(m["day"], m["to"]) for m in welcome] == [((START_DAY - D(days=7)).isoformat(), USERS["newhire"][3])], welcome
    tm.run_day(START_DAY)
    assert _emp(tm)["status"] == "Onboarding"


# ── 04 ──────────────────────────────────────────────────────────────────────
def test_04_new_hire_marks_a_task_done_in_the_portal(browser, tm):
    ctx, page, watch = new_page(browser, "newhire-day1")
    assert sign_in_portal(page, tm, "newhire") == ""
    page.locator('.nav-item[data-page="tasks"]').first.evaluate("e => e.click()")
    page.wait_for_timeout(1500)
    before = {t["id"]: t["status"] for t in _tasks(tm)}
    btn = page.locator('#page-tasks button:has-text("Mark done")').first
    assert btn.count() == 1, "no task the new hire can mark done"
    btn.click()
    page.wait_for_timeout(1500)
    after = {t["id"]: t["status"] for t in _tasks(tm)}
    done = [i for i in after if after[i] == "Completed" and before.get(i) != "Completed"]
    assert len(done) == 1, (before, after)
    S["done_in_portal"] = done[0]
    S["done_day"] = START_DAY
    assert not watch.errors, watch.errors
    ctx.close()


# ── 05 ──────────────────────────────────────────────────────────────────────
def test_05_reminders_notices_escalations_follow_the_calendar(tm):
    end = START_DAY + D(days=9)
    tm.walk(START_DAY + D(days=1), end)
    out = tm.outbox()
    days = lambda ms: sorted(m["day"] for m in ms)                       # noqa: E731
    problems, checked = [], 0
    for t in _tasks(tm):
        due = dt.date.fromisoformat(t["due_date"])
        if due < HIRE_DAY or due + D(days=2) > end:
            continue
        name, want_to = t["name"], (USERS["newhire"][3] if t.get("assigned_to_role") == "Employee" else HR_EMAIL)
        if t["id"] == S["done_in_portal"]:
            later = [m for k in ("today", "overdue", "esc") for m in mails_for(out, t, k)
                     if m["day"] > S["done_day"].isoformat()]
            if later:
                problems.append(f"{name}: done in the Portal but still got {[(m['day'], m['subject']) for m in later]}")
            continue
        checked += 1
        if days(mails_for(out, t, "today")) != [due.isoformat()]:
            problems.append(f"{name}: due-today on {days(mails_for(out, t, 'today'))}, expected [{due}]")
        if days(mails_for(out, t, "overdue")) != [(due + D(days=1)).isoformat()]:
            problems.append(f"{name}: first overdue notice on {days(mails_for(out, t, 'overdue'))}, expected [{due + D(days=1)}]")
        for k in ("today", "overdue"):
            for m in mails_for(out, t, k):
                if m["to"] != want_to:
                    problems.append(f"{name}: '{k}' went to {m['to']}, expected {want_to}")
        lag = {"CRITICAL": 1, "HIGH": 2}.get(t["priority"])
        exp_esc = [(due + D(days=lag)).isoformat()] if lag else []
        if days(mails_for(out, t, "esc")) != exp_esc:
            problems.append(f"{name} ({t['priority']}): escalation on {days(mails_for(out, t, 'esc'))}, expected {exp_esc}")
        if any(m["to"] != HR_EMAIL for m in mails_for(out, t, "esc")):
            problems.append(f"{name}: an escalation didn't go to HR")
        if t["status"] != "Overdue":
            problems.append(f"{name}: status {t['status']} after its due date, expected Overdue")
    assert checked >= 3, "too few tasks fell in the walked window to check"
    assert not problems, "\n".join(problems)
    assert _emp(tm)["status"] == "Onboarding"                  # tasks still open


# ── 06 ──────────────────────────────────────────────────────────────────────
def test_06_onboarding_finished_makes_them_active(browser, tm):
    day = START_DAY + D(days=10)
    tm.clock(day - D(days=1), "15:00")
    for t in _tasks(tm):
        if t["status"] in OPEN:
            st, j = tm.api("POST", f"/tasks/{t['id']}/complete", {"notes": "ZTEST done"})
            assert st in (200, 201), j
    assert _emp(tm)["status"] == "Onboarding"                  # changes with the next morning's run
    tm.run_day(day)
    assert _emp(tm)["status"] == "Active"
    ctx, page, watch = new_page(browser, "admin-active")
    sign_in_admin(page, tm)
    page.evaluate(f"openEmpSheet('{S['emp_id']}')")
    page.wait_for_timeout(1500)
    assert "active" in page.inner_text("#emp-sheet").lower()
    assert not watch.errors, watch.errors
    ctx.close()


# ── 07 ──────────────────────────────────────────────────────────────────────
def test_07_hr_terminates_through_hr_admin(browser, tm):
    tm.clock(TERM_NOTICE_DAY, "10:00")
    ctx, page, watch = new_page(browser, "admin-term")
    sign_in_admin(page, tm)
    page.evaluate(f"openEmpSheet('{S['emp_id']}')")
    page.wait_for_timeout(1200)
    page.evaluate(f"openInitiateTermination('{S['emp_id']}')")
    page.wait_for_selector("#term-date", state="visible")
    page.select_option("#term-type", "voluntary")
    page.fill("#term-date", TERM_DAY.isoformat())
    page.fill("#term-notes", "ZTEST resignation")
    page.click("#generic-modal button:has-text('Confirm Termination')")
    page.wait_for_timeout(1500)
    toast = page.inner_text("#toast") if page.locator("#toast").count() else ""
    emp = _emp(tm)
    assert emp["status"] == "Offboarding" and emp["end_date"] == TERM_DAY.isoformat(), emp
    off = {t["template_id"]: t["due_date"] for t in _tasks(tm) if str(t.get("template_id") or "").startswith("TMPL-TERM")}
    exp = expected_tasks("offboarding", "FL", {"default": TERM_DAY})
    assert off == exp, (off, exp)
    assert "offboarding tasks created" in toast and "Offboarding until" in toast, toast
    page.evaluate("closeEmpSheet && closeEmpSheet()")
    page.click("#btn-hamburger"); page.wait_for_timeout(400)
    page.click('#sidebar-nav [data-tab="offboarding"]'); page.wait_for_timeout(1500)
    assert "ZTEST Newhire" in page.inner_text("#tab-offboarding")
    assert not watch.errors, watch.errors
    ctx.close()


# ── 08 ──────────────────────────────────────────────────────────────────────
def test_08_portal_still_works_during_the_notice_period(browser, tm):
    tm.clock(TERM_NOTICE_DAY + D(days=3), "09:00")
    ctx, page, watch = new_page(browser, "newhire-notice")
    assert sign_in_portal(page, tm, "newhire") == ""
    assert not watch.errors, watch.errors
    ctx.close()


# ── 09 ──────────────────────────────────────────────────────────────────────
def test_09_walk_past_the_last_day(browser, tm):
    tm.walk(TERM_NOTICE_DAY + D(days=1), TERM_DAY)
    assert _emp(tm)["status"] == "Offboarding"                 # still working their last day
    end = TERM_DAY + D(days=5)
    tm.walk(TERM_DAY + D(days=1), end)
    assert _emp(tm)["status"] == "Terminated"
    out = tm.outbox()
    problems = []
    for t in _tasks(tm):
        if not str(t.get("template_id") or "").startswith("TMPL-TERM"):
            continue
        due = dt.date.fromisoformat(t["due_date"])
        lag = {"CRITICAL": 1, "HIGH": 2}.get(t["priority"])
        exp_esc = [(due + D(days=lag)).isoformat()] if lag and due + D(days=lag) <= end else []
        got = sorted(m["day"] for m in mails_for(out, t, "esc"))
        if got != exp_esc:
            problems.append(f"{t['name']} ({t['priority']}): escalation {got}, expected {exp_esc}")
        if due <= end and sorted(m["day"] for m in mails_for(out, t, "today")) != [due.isoformat()]:
            problems.append(f"{t['name']}: due-today notice not exactly on {due}")
    assert not problems, "\n".join(problems)
    cobra = [t for t in _tasks(tm) if t.get("template_id") == "TMPL-TERM-004"]
    assert cobra and cobra[0]["due_date"] == (TERM_DAY + D(days=30)).isoformat(), cobra
    # HR Admin: Termination Records lists them
    ctx, page, watch = new_page(browser, "admin-after")
    sign_in_admin(page, tm)
    page.click("#btn-hamburger"); page.wait_for_timeout(400)
    page.click('#sidebar-nav [data-tab="terminations"]'); page.wait_for_timeout(1500)
    assert "ZTEST Newhire" in page.inner_text("#tab-terminations")
    assert not watch.errors, watch.errors
    ctx.close()
    # the Portal turns them away now
    ctx, page, watch = new_page(browser, "newhire-after")
    err = sign_in_portal(page, tm, "newhire")
    assert err and "closed" in err.lower(), err
    ctx.close()


# ── 10 ──────────────────────────────────────────────────────────────────────
def test_10_the_outbox_is_clean(tm):
    out = tm.outbox()
    assert out, "the time machine caught no email at all"
    dup = [k for k, n in Counter((m["day"], m["subject"], m["to"]) for m in out).items() if n > 1]
    assert not dup, f"emails sent twice: {dup[:5]}"
    bad = [m for m in out if m.get("source") != "blocked_http"
           and not all(a.strip().endswith("+hrtest@example.com") for a in str(m["to"]).split(",") if a.strip())]
    assert not bad, f"email to a non-test address: {bad[:3]}"
    assert not [m for m in out if m.get("source") == "blocked_http"], "the app tried to reach the internet"
