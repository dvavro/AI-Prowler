"""
R-090 + R-091 (David, 2026-10-12).

R-090  a daily job advances employee status: Pre-Start -> Onboarding on the
       start date, Onboarding -> Active when every onboarding task is
       Completed/Waived, Offboarding -> Terminated the day after the last day.
R-091  HR Admin's termination (PATCH {status:'terminated', ...}) starts the FULL
       offboarding flow — the same one hr_initiate_termination uses — and
       HR Portal access ends: at both sign-ins and on every portal request.
       Someone working out their notice keeps access until their last day.

Each test uses a throwaway HR database. Run:
  run_tests.bat tests\\mcp_tests\\test_hr_lifecycle_r090_r091.py -v
"""
import datetime as dt
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TODAY = dt.date.today()
D = lambda n: (TODAY + dt.timedelta(days=n)).isoformat()      # noqa: E731


@pytest.fixture()
def ap(tmp_path, monkeypatch):
    import ai_prowler_mcp as m
    monkeypatch.setattr(m, "_HR_DB_PATH", str(tmp_path / "hr_db.json"))
    m._hr_save_db({        # 2026-10-16: seed through the real per-folder storage
        "config": {"company_name": "ZTEST", "setup_complete": True, "doc_root": str(tmp_path / "docs")},
        "employees": [], "tasks": [], "documents": [], "audit_log": []})
    return m


def _hire(ap, start, state="FL", email="z+hrtest@example.com"):
    with ap._hr_db_lock:
        db = ap._hr_load_db()
        emp = ap._hr_create_employee_impl({"first_name": "ZTEST", "last_name": "Emp", "personal_email": email},
                                          {"start_date": start, "work_state": state}, {}, db)
        ap._hr_save_db(db)
    return emp["id"]


def _emp(ap, emp_id):
    return next(e for e in ap._hr_load_db()["employees"] if e["id"] == emp_id)


def _patch(ap, emp_id, body):
    st, _ct, b = ap._hr_api_route("PATCH", f"/employees/{emp_id}", {}, body, {"role": "admin"})
    return st, json.loads(b)


def _term_tasks(ap, emp_id):
    return [t for t in ap._hr_load_db()["tasks"]
            if t["employee_id"] == emp_id and str(t.get("template_id") or "").startswith("TMPL-TERM")]


# ── R-091: HR Admin termination ──────────────────────────────────────────────
def test_hr_admin_termination_future_last_day_starts_offboarding(ap):
    e = _hire(ap, D(-200))
    st, r = _patch(ap, e, {"status": "terminated", "termination_type": "voluntary",
                           "end_date": D(10), "termination_notes": "moving"})
    assert st == 200 and r["offboarding_tasks_created"] >= 5, r
    emp = _emp(ap, e)
    assert (emp["status"], emp["end_date"], emp["termination_type"]) == ("Offboarding", D(10), "voluntary")
    tasks = _term_tasks(ap, e)
    exp = {t["template_id"] for t in json.loads((ROOT / "hr_task_templates.json").read_text(encoding="utf-8"))["offboarding"]
           if ap._hr_template_applies(t, "FL")}
    assert {t["template_id"] for t in tasks} == exp
    assert all(t["due_date"] >= D(10) for t in tasks), "offboarding deadlines anchor on the last day"


def test_hr_admin_termination_past_last_day_is_terminated_at_once(ap):
    e = _hire(ap, D(-200))
    st, r = _patch(ap, e, {"status": "terminated", "end_date": D(-1)})
    assert st == 200 and _emp(ap, e)["status"] == "Terminated" and _term_tasks(ap, e)


def test_saving_again_never_duplicates_offboarding_tasks(ap):
    e = _hire(ap, D(-200))
    _patch(ap, e, {"status": "terminated", "end_date": D(10)})
    n = len(_term_tasks(ap, e))
    _patch(ap, e, {"status": "terminated", "end_date": D(10), "termination_notes": "edit"})
    assert len(_term_tasks(ap, e)) == n
    assert _emp(ap, e)["status"] == "Offboarding", "a stale 'terminated' ended the notice period early"


def test_mcp_tool_uses_the_same_flow(ap):
    e = _hire(ap, D(-200))
    out = ap.hr_initiate_termination(e, "Layoff", D(5), "ZTEST")
    assert "Termination initiated" in out and _emp(ap, e)["status"] == "Offboarding"
    _patch(ap, e, {"status": "terminated", "end_date": D(5)})
    assert len(_term_tasks(ap, e)) == len({t["template_id"] for t in _term_tasks(ap, e)}), "duplicates"


def test_other_status_edits_are_saved_canonical(ap):
    e = _hire(ap, D(-30))
    _patch(ap, e, {"status": "active"})
    assert _emp(ap, e)["status"] == "Active"
    _patch(ap, e, {"status": "on leave"})
    assert _emp(ap, e)["status"] == "On Leave"


# ── R-091: portal access ends ────────────────────────────────────────────────
def test_pin_sign_in_refused_once_terminated(ap):
    e = _hire(ap, D(-200), email="leaver+hrtest@example.com")
    with ap._hr_db_lock:
        db = ap._hr_load_db()
        emp = next(x for x in db["employees"] if x["id"] == e)
        emp["pin_hash"] = ap._hr_pin_hash("4321", e)
        ap._hr_save_db(db)
    body = {"email": "leaver+hrtest@example.com", "pin": "4321"}
    assert ap._hr_api_route("POST", "/auth/employee", {}, body, {"role": None})[0] == 200
    _patch(ap, e, {"status": "terminated", "end_date": D(5)})          # still working notice
    assert ap._hr_api_route("POST", "/auth/employee", {}, body, {"role": None})[0] == 200
    _patch(ap, e, {"status": "terminated", "end_date": D(-1)}) if False else None
    with ap._hr_db_lock:
        db = ap._hr_load_db()
        next(x for x in db["employees"] if x["id"] == e)["end_date"] = D(-1)
        ap._hr_advance_lifecycle(db)
        ap._hr_save_db(db)
    assert _emp(ap, e)["status"] == "Terminated"
    st, _ct, b = ap._hr_api_route("POST", "/auth/employee", {}, body, {"role": None})
    assert st == 403 and json.loads(b)["error"] == "employment_ended"


def test_server_refuses_terminated_sessions_and_sign_ins():
    src = (ROOT / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    blk = src[src.index("# ── HR apps — HR Admin + HR Portal, AI-Prowler SERVER only"):]
    blk = blk[:blk.index("# ── end HR REST API")]
    # 2026-10-16: sign-in finds/links/creates the record, then refuses a Terminated one.
    assert "if _hr_is_terminated(_hrl_emp):" in blk and '"error": "terminated"' in blk, \
        "AI-Prowler portal sign-in"
    assert re.search(r"_hrsrv_emp_id and _hr_is_terminated\(next\(", blk), "every portal request"


# ── R-090: the daily job ─────────────────────────────────────────────────────
def test_lifecycle_rules(ap):
    pre = _hire(ap, D(0))                   # starts today
    with ap._hr_db_lock:
        db = ap._hr_load_db()
        for x in db["employees"]:
            x["status"] = "Pre-Start"
        ap._hr_save_db(db)
    fut = _hire(ap, D(5), email="f+hrtest@example.com")
    done = _hire(ap, D(-10), email="d+hrtest@example.com")
    half = _hire(ap, D(-10), email="h+hrtest@example.com")
    leaving = _hire(ap, D(-300), email="l+hrtest@example.com")
    gone = _hire(ap, D(-300), email="g+hrtest@example.com")
    with ap._hr_db_lock:
        db = ap._hr_load_db()
        for t in db["tasks"]:
            if t["employee_id"] == done:
                t["status"] = "Completed"
            if t["employee_id"] == half and t["template_id"] == "TMPL-D1-001":
                t["status"] = "Waived"
        ap._hr_start_offboarding(next(x for x in db["employees"] if x["id"] == leaving), db, "voluntary", D(0))
        ap._hr_start_offboarding(next(x for x in db["employees"] if x["id"] == gone), db, "voluntary", D(3))
        next(x for x in db["employees"] if x["id"] == gone)["end_date"] = D(-1)
        changes = ap._hr_advance_lifecycle(db)
        ap._hr_save_db(db)
    st = {e: _emp(ap, e)["status"] for e in (pre, fut, done, half, leaving, gone)}
    assert st == {pre: "Onboarding", fut: "Pre-Start", done: "Active", half: "Onboarding",
                  leaving: "Offboarding", gone: "Terminated"}, st
    assert {c[0] for c in changes} == {pre, done, gone}
    log = [a for a in ap._hr_load_db()["audit_log"] if a.get("action") == "status_advanced"]
    assert {a["employee_id"] for a in log} == {pre, done, gone}


def test_job_is_scheduled_daily_at_5am():
    import hr_scheduler as hs
    j = hs.JOB_REGISTRY["lifecycle_advance"]
    assert j["cadence"] == ("daily", 5, 0) and j["fn"] is hs.job_lifecycle_advance


# ── HR Admin reads statuses consistently ─────────────────────────────────────
def test_hr_admin_normalises_status_in_one_place():
    s = (ROOT / "hr_admin" / "index.html").read_text(encoding="utf-8")
    i = s.index("async function apiGet(path)")
    assert "_hrUiEmployee" in s[i:i + 900]
    assert "return v === 'offboarding' ? 'terminated' : v;" in s
    assert "e.status !== 'Terminated'" not in s, "a screen still compares the capitalised value"
