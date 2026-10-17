"""
HR onboarding / offboarding sequence and timing — TIME MACHINE (David, 2026-10-12).

The HR apps are AI-Prowler SERVER only, and a live server's clock can't be
moved, so these run the REAL HR code on this PC against a throwaway HR
database while `time_machine` walks the calendar one simulated morning at a
time. Each day every hr_scheduler job runs in its real daily order; every email
it would send is captured (never sent).

Expectations are computed from hr_task_templates.json itself (via the same
_hr_template_applies the app uses), so a template edit can't silently drift
from the test.

  TM-ON-01   hire with a future start date -> the right onboarding tasks, dated
             exactly per template (start_date / hire-day anchors)
  TM-ON-02   walk hire day -> end of December: welcome email 7 days before
             start, 48-hour reminder / due today / first overdue notice once
             each on the right day to the right person, CRITICAL escalates
             1 day overdue and HIGH 2 days, MEDIUM/LOW never, benefits warning
             on start+25, early-completed tasks get no notices, daily digest
             only when there's something to report, owner summary on Mondays
  TM-OFF-01  termination -> 7 offboarding tasks dated from the effective date;
             CRITICAL ones escalate the day after; LOW exit interview never;
             COBRA notice due term+30
  TM-DOC-01  a document expiring in 48 days gets a HIGH "reverify" task 30
             days before expiry, one alert to HR, then the normal reminders
  TM-LIFE-01..03  employee status follows the sequence (Pre-Start ->
             Onboarding on day one, -> Active when onboarding is done,
             Offboarding -> Terminated after the last day) — R-090, fixed by
             hr_scheduler.job_lifecycle_advance (daily 5am).

Run: run_tests.bat tests\\mcp_tests\\test_hr_timemachine_flow.py -v
"""
import datetime as dt
import json
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

HR_ADMIN = "hr-admin@ztest.example"
OWNER = "owner@ztest.example"
EMP_EMAIL = "ztest.newhire+hrtest@example.com"
OPEN = ("Not Started", "In Progress", "Awaiting Document")


# ── harness ──────────────────────────────────────────────────────────────────
@pytest.fixture()
def hr(tmp_path, monkeypatch, time_machine):
    import ai_prowler_mcp as ap
    import hr_scheduler as hs
    monkeypatch.setattr(ap, "_HR_DB_PATH", str(tmp_path / "hr_db.json"))
    monkeypatch.setattr(hs, "_HR_TRACKING_PATH", str(tmp_path / "company" / "scheduler_state.json"))
    ap._hr_save_db({       # 2026-10-16: seed through the real per-folder storage
        "config": {"company_name": "ZTEST Co", "setup_complete": True, "work_states": ["FL"],
                   "hr_admin_email": HR_ADMIN, "owner_email": OWNER,
                   "doc_root": str(tmp_path / "hr_documents")},
        "employees": [], "tasks": [], "documents": [], "audit_log": []})
    mails = []

    def capture(subject, html, to_addr):
        mails.append({"day": dt.date.today().isoformat(), "subject": subject, "to": to_addr, "html": html})
        return bool(to_addr)
    monkeypatch.setattr(hs, "_send_mail", capture)

    class H:
        pass
    h = H()
    h.ap, h.hs, h.mails, h.tm = ap, hs, mails, time_machine

    def go(day):                                   # move to 06:00 local on `day`
        time_machine.move_to(dt.datetime.combine(day, dt.time(6, 0)), tick=False)
    h.go = go

    def run_day(day):
        go(day)
        for job in (hs.job_lifecycle_advance, hs.job_overdue_checker, hs.job_reminder_48h,
                    hs.job_prestart_welcome,
                    hs.job_benefits_window_warning, hs.job_doc_expiration_check,
                    hs.job_daily_digest, hs.job_reminder_email, hs.job_due_today_sender,
                    hs.job_overdue_first_notice, hs.job_escalation_check):
            r = job()
            assert "error" not in r, f"{day}: {job.__name__} -> {r}"
        if day.weekday() == 0:
            assert "error" not in hs.job_weekly_owner_summary()
    h.run_day = run_day

    def walk(start, end):
        d = start
        while d <= end:
            run_day(d)
            d += dt.timedelta(days=1)
    h.walk = walk

    def db():
        return ap._hr_load_db()
    h.db = db

    def save(d):
        ap._hr_save_db(d)
    h.save = save

    def hire(start_date, state="FL", first="ZTEST", last="Newhire", email=EMP_EMAIL):
        with ap._hr_db_lock:
            d = ap._hr_load_db()
            emp = ap._hr_create_employee_impl(
                {"first_name": first, "last_name": last, "personal_email": email},
                {"start_date": start_date.isoformat(), "work_state": state, "title": "Technician"},
                {"pay_type": "hourly", "pay_rate": 20}, d)
            ap._hr_save_db(d)
        return emp["id"]
    h.hire = hire

    def mails_for(task, kind):
        key = {"48h": "Task due in 48 hours", "today": "Task due today",
               "overdue": "Task overdue", "esc": "ESCALATION"}[kind]
        return [m for m in mails if key in m["subject"] and m["subject"].endswith(task["name"])]
    h.mails_for = mails_for
    return h


def _expected_tasks(ap, group, emp, anchor_dates):
    tmpls = json.loads((ROOT / "hr_task_templates.json").read_text(encoding="utf-8"))[group]
    out = {}
    for t in tmpls:
        if not ap._hr_template_applies(t, emp.get("work_state", "")):
            continue
        merged = {**t, **((t.get("state_overrides") or {}).get(emp.get("work_state", ""), {}))}
        anchor = anchor_dates[t.get("due_anchor") or "default"] if (t.get("due_anchor") in anchor_dates) \
            else anchor_dates["default"]
        out[t["template_id"]] = (anchor + dt.timedelta(days=int(merged.get("due_offset_days", 0)))).isoformat()
    return out


HIRE_DAY = dt.date(2026, 11, 2)          # a Monday
START_DAY = dt.date(2026, 11, 16)        # two weeks later


# ── onboarding ───────────────────────────────────────────────────────────────
def test_TM_ON_01_hire_creates_the_right_dated_tasks(hr):
    hr.go(HIRE_DAY)
    emp_id = hr.hire(START_DAY)
    d = hr.db()
    emp = next(e for e in d["employees"] if e["id"] == emp_id)
    assert emp["status"] == "Pre-Start"
    mine = {t["template_id"]: t for t in d["tasks"] if t["employee_id"] == emp_id}
    # hire_date-anchored templates use the day the record was created (no hire_date field)
    exp = _expected_tasks(hr.ap, "base", emp, {"default": START_DAY, "hire_date": HIRE_DAY})
    assert set(mine) == set(exp), f"missing {set(exp) - set(mine)}, extra {set(mine) - set(exp)}"
    wrong = {k: (mine[k]["due_date"], v) for k, v in exp.items() if mine[k]["due_date"] != v}
    assert not wrong, f"due dates off (got, expected): {wrong}"
    assert "TMPL-30D-004" not in mine, "WA Cares disclosure must not apply to a FL employee"


def test_TM_ON_02_reminders_notices_escalations_follow_the_calendar(hr):
    hr.go(HIRE_DAY)
    emp_id = hr.hire(START_DAY)
    # complete two tasks early — they must never get a due-today/overdue/escalation notice
    early = {"TMPL-D1-007", "TMPL-W1-004"}       # Emergency contact form, Team introductions
    d = hr.db()
    for t in d["tasks"]:
        if t["template_id"] in early:
            t["status"], t["completed_at"] = "Completed", HIRE_DAY.isoformat()
    hr.save(d)

    end = dt.date(2026, 12, 31)
    hr.walk(HIRE_DAY, end)
    d = hr.db()
    tasks = [t for t in d["tasks"] if t["employee_id"] == emp_id]
    days = lambda ms: sorted(m["day"] for m in ms)

    # welcome: once, exactly 7 days before the start date, to the employee
    welcome = [m for m in hr.mails if m["subject"].startswith("\U0001f44b Welcome to the team")]
    assert days(welcome) == [(START_DAY - dt.timedelta(days=7)).isoformat()], welcome
    assert welcome[0]["to"] == EMP_EMAIL

    problems = []
    for t in tasks:
        due = dt.date.fromisoformat(t["due_date"])
        name = t["name"]
        if t["template_id"] in early:
            for kind in ("today", "overdue", "esc"):
                if hr.mails_for(t, kind):
                    problems.append(f"{name}: completed early but got a '{kind}' notice")
            continue
        if due > end:
            continue
        want_to = EMP_EMAIL if t.get("assigned_to_role") == "Employee" else HR_ADMIN
        # 48h reminder: once, on due-2 — only if that day was on/after hire day
        r48 = hr.mails_for(t, "48h")
        exp48 = [(due - dt.timedelta(days=2)).isoformat()] if due - dt.timedelta(days=2) >= HIRE_DAY else []
        if days(r48) != exp48:
            problems.append(f"{name}: 48h reminder on {days(r48)}, expected {exp48}")
        # due today: once, on the due date
        if days(hr.mails_for(t, "today")) != [due.isoformat()]:
            problems.append(f"{name}: due-today on {days(hr.mails_for(t, 'today'))}, expected [{due}]")
        # first overdue notice: once, the day after
        nxt = (due + dt.timedelta(days=1))
        if nxt <= end and days(hr.mails_for(t, "overdue")) != [nxt.isoformat()]:
            problems.append(f"{name}: overdue notice on {days(hr.mails_for(t, 'overdue'))}, expected [{nxt}]")
        for kind in ("48h", "today", "overdue"):
            for m in hr.mails_for(t, kind):
                if m["to"] != want_to:
                    problems.append(f"{name}: '{kind}' went to {m['to']}, expected {want_to}")
        # escalation: CRITICAL due+1, HIGH due+2, never for MEDIUM/LOW; always to HR
        esc = hr.mails_for(t, "esc")
        lag = {"CRITICAL": 1, "HIGH": 2}.get(t["priority"])
        exp_esc = [(due + dt.timedelta(days=lag)).isoformat()] if lag and due + dt.timedelta(days=lag) <= end else []
        if days(esc) != exp_esc:
            problems.append(f"{name} ({t['priority']}): escalation on {days(esc)}, expected {exp_esc}")
        if any(m["to"] != HR_ADMIN for m in esc):
            problems.append(f"{name}: escalation not sent to HR")
        if due < end and t["status"] != "Overdue":
            problems.append(f"{name}: status {t['status']} after its due date, expected Overdue")
    assert not problems, "\n".join(problems)

    # benefits warning: once, start+25, while the benefits task is open
    ben = [m for m in hr.mails if "enroll in benefits" in m["subject"]]
    assert days(ben) == [(START_DAY + dt.timedelta(days=25)).isoformat()], days(ben)

    # daily digest: only on days with something overdue or due today — never empty
    digests = [m for m in hr.mails if m["subject"].startswith("\U0001f4cb HR Daily Digest")]
    assert digests and all(m["to"] == HR_ADMIN for m in digests)
    assert len({m["day"] for m in digests}) == len(digests), "more than one digest on a day"
    assert all(("Overdue (" in m["html"]) or ("Due Today (" in m["html"]) for m in digests)

    # owner summary: every Monday in the walk, to the owner
    mondays = [(HIRE_DAY + dt.timedelta(days=i)).isoformat()
               for i in range((end - HIRE_DAY).days + 1) if (HIRE_DAY + dt.timedelta(days=i)).weekday() == 0]
    weekly = [m for m in hr.mails if "Weekly HR Summary" in m["subject"]]
    assert days(weekly) == mondays and all(m["to"] == OWNER for m in weekly)

    # nothing went out twice
    dup = [k for k, n in Counter((m["day"], m["subject"], m["to"]) for m in hr.mails).items() if n > 1]
    assert not dup, f"duplicate emails: {dup[:5]}"


# ── offboarding ──────────────────────────────────────────────────────────────
TERM_NOTICE_DAY = dt.date(2026, 11, 2)
TERM_DAY = dt.date(2026, 11, 13)


def _active_employee(hr, state="FL"):
    hr.go(dt.date(2025, 1, 6))
    emp_id = hr.hire(dt.date(2025, 1, 6), state=state, last=f"Leaver{state}",
                     email=f"ztest.leaver{state.lower()}+hrtest@example.com")
    d = hr.db()                                     # onboarding long done
    for t in d["tasks"]:
        if t["employee_id"] == emp_id:
            t["status"] = "Completed"
    next(e for e in d["employees"] if e["id"] == emp_id)["status"] = "Active"
    hr.save(d)
    return emp_id


def test_TM_OFF_01_termination_sequence_and_deadlines(hr):
    emp_id = _active_employee(hr)
    hr.go(TERM_NOTICE_DAY)
    out = hr.ap.hr_initiate_termination(emp_id, "Voluntary", TERM_DAY.isoformat(), "ZTEST resignation")
    assert "Termination initiated" in out, out
    d = hr.db()
    emp = next(e for e in d["employees"] if e["id"] == emp_id)
    assert emp["status"] == "Offboarding" and emp["end_date"] == TERM_DAY.isoformat()
    off = {t["template_id"]: t for t in d["tasks"] if t["employee_id"] == emp_id and t.get("phase") != "Compliance"
           and (t["template_id"] or "").startswith("TMPL-TERM")}
    exp = _expected_tasks(hr.ap, "offboarding", emp, {"default": TERM_DAY})
    assert set(off) == set(exp), f"missing {set(exp) - set(off)}, extra {set(off) - set(exp)}"
    assert {k: v["due_date"] for k, v in off.items()} == exp

    end = dt.date(2026, 12, 31)
    hr.walk(TERM_NOTICE_DAY, end)
    d = hr.db()
    problems = []
    for t in (x for x in d["tasks"] if x["employee_id"] == emp_id and (x["template_id"] or "").startswith("TMPL-TERM")):
        due = dt.date.fromisoformat(t["due_date"])
        esc = sorted(m["day"] for m in hr.mails_for(t, "esc"))
        lag = {"CRITICAL": 1, "HIGH": 2}.get(t["priority"])
        exp_esc = [(due + dt.timedelta(days=lag)).isoformat()] if lag and due + dt.timedelta(days=lag) <= end else []
        if esc != exp_esc:
            problems.append(f"{t['name']} ({t['priority']}): escalation {esc}, expected {exp_esc}")
        if sorted(m["day"] for m in hr.mails_for(t, "today")) != [due.isoformat()]:
            problems.append(f"{t['name']}: due-today notice not exactly on {due}")
    assert not problems, "\n".join(problems)
    cobra = next(t for t in d["tasks"] if t["employee_id"] == emp_id and t["template_id"] == "TMPL-TERM-004")
    assert cobra["due_date"] == (TERM_DAY + dt.timedelta(days=30)).isoformat()


def test_TM_OFF_02_final_pay_follows_state_rules(hr):
    """Same termination, FL vs CA employee — final-pay task uses each state's rule."""
    fl, ca = _active_employee(hr, "FL"), _active_employee(hr, "CA")
    hr.go(TERM_NOTICE_DAY)
    for e in (fl, ca):
        hr.ap.hr_initiate_termination(e, "Involuntary", TERM_DAY.isoformat(), "ZTEST")
    d = hr.db()
    for emp_id, state in ((fl, "FL"), (ca, "CA")):
        emp = next(e for e in d["employees"] if e["id"] == emp_id)
        exp = _expected_tasks(hr.ap, "offboarding", emp, {"default": TERM_DAY})
        got = next(t for t in d["tasks"] if t["employee_id"] == emp_id and t["template_id"] == "TMPL-TERM-003")
        assert got["due_date"] == exp["TMPL-TERM-003"], (state, got["due_date"], exp["TMPL-TERM-003"])


# ── document expiry ──────────────────────────────────────────────────────────
def test_TM_DOC_01_expiring_document_reverification(hr):
    emp_id = _active_employee(hr)
    exp_day = dt.date(2026, 12, 20)
    hr.go(TERM_NOTICE_DAY)
    d = hr.db()
    d["documents"].append({"id": "DOC-ZT1", "employee_id": emp_id, "name": "ZTEST Work permit",
                           "expiration_date": exp_day.isoformat()})
    hr.save(d)
    hr.walk(TERM_NOTICE_DAY, dt.date(2026, 12, 31))
    d = hr.db()
    doc = next(x for x in d["documents"] if x["id"] == "DOC-ZT1")
    task = next(t for t in d["tasks"] if t["id"] == doc.get("reverification_task_id"))
    assert task["priority"] == "HIGH" and task["due_date"] == exp_day.isoformat()
    alerts = [m for m in hr.mails if m["subject"].startswith("\U0001f4c4 Document expiring soon")]
    assert [m["day"] for m in alerts] == [(exp_day - dt.timedelta(days=30)).isoformat()]
    assert alerts[0]["to"] == HR_ADMIN
    assert sorted(m["day"] for m in hr.mails_for(task, "esc")) == [(exp_day + dt.timedelta(days=2)).isoformat()]


# ── lifecycle status (R-090, fixed 2026-10-12: job_lifecycle_advance, daily 5am) ─
def test_TM_LIFE_01_pre_start_becomes_onboarding_on_day_one(hr):
    hr.go(HIRE_DAY)
    emp_id = hr.hire(START_DAY)
    hr.walk(HIRE_DAY, START_DAY)
    assert next(e for e in hr.db()["employees"] if e["id"] == emp_id)["status"] == "Onboarding"


def test_TM_LIFE_02_onboarding_becomes_active_when_onboarding_is_done(hr):
    hr.go(HIRE_DAY)
    emp_id = hr.hire(START_DAY)
    d = hr.db()
    for t in d["tasks"]:
        if t["employee_id"] == emp_id:
            t["status"] = "Completed"
    hr.save(d)
    hr.walk(HIRE_DAY, START_DAY + dt.timedelta(days=1))
    assert next(e for e in hr.db()["employees"] if e["id"] == emp_id)["status"] == "Active"


def test_TM_LIFE_03_offboarding_becomes_terminated_after_the_last_day(hr):
    emp_id = _active_employee(hr)
    hr.go(TERM_NOTICE_DAY)
    hr.ap.hr_initiate_termination(emp_id, "Voluntary", TERM_DAY.isoformat(), "ZTEST")
    hr.walk(TERM_NOTICE_DAY, TERM_DAY + dt.timedelta(days=1))
    assert next(e for e in hr.db()["employees"] if e["id"] == emp_id)["status"] == "Terminated"
