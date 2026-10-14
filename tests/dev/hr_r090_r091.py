"""2026-10-12 (David): R-090 daily status job + R-091 HR Admin termination =
full offboarding, portal access ends. ai_prowler_mcp.py + hr_scheduler.py.
Checks every anchor; writes only files that compile. ASCII output."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def edit(rel, pairs):
    p = ROOT / rel
    raw = p.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in raw else "\n"
    s = raw.replace("\r\n", "\n")
    for old, new in pairs:
        assert s.count(old) == 1, f"{rel}: expected once: {old[:90]!r} (found {s.count(old)})"
        s = s.replace(old, new)
    compile(s, rel, "exec")
    p.write_bytes(s.replace("\n", nl).encode("utf-8"))
    print(f"{rel}: {len(pairs)} change(s)")


HELPERS = '''

# ── Employee status lifecycle (2026-10-12, David: R-090 / R-091) ─────────────
# Stored statuses are capitalised; HR Admin sends lower-case. One canonical form.
_HR_STATUS_CANON = {"pre-start": "Pre-Start", "onboarding": "Onboarding", "active": "Active",
                    "on leave": "On Leave", "offboarding": "Offboarding", "terminated": "Terminated"}


def _hr_canon_status(s) -> str:
    v = str(s or "").strip()
    return _HR_STATUS_CANON.get(v.lower(), v)


def _hr_is_terminated(emp) -> bool:
    return str((emp or {}).get("status") or "").strip().lower() == "terminated"


def _hr_start_offboarding(emp: dict, db: dict, term_type: str, effective_date: str,
                          reason: str = "", source: str = "") -> list:
    """The ONE termination flow (R-091) — used by hr_initiate_termination (Claude,
    Muse, or Grok) and by HR Admin's Terminations screen (PATCH status
    'terminated'). Status: Offboarding until the last day (they keep HR Portal
    access while working their notice), Terminated at once if the last day has
    already passed; the daily lifecycle job moves Offboarding -> Terminated the
    day after the last day. Offboarding tasks are generated once only."""
    today = _hrdt.date.today().isoformat()
    eff = str(effective_date or today)[:10]
    emp["termination_type"] = term_type or emp.get("termination_type") or ""
    emp["end_date"] = eff
    if reason:
        emp["termination_reason"] = reason
    emp["status"] = "Terminated" if eff < today else "Offboarding"
    have = any(t.get("employee_id") == emp["id"] and str(t.get("template_id") or "").startswith("TMPL-TERM")
               for t in db.get("tasks", []))
    new_tasks = [] if have else _hr_generate_offboarding_tasks(emp, db, eff)
    db.setdefault("tasks", []).extend(new_tasks)
    db.setdefault("audit_log", []).append({
        "at": _hrdt.datetime.utcnow().isoformat() + "Z", "action": "termination_initiated",
        "employee_id": emp["id"], "type": emp["termination_type"], "effective_date": eff,
        "task_count": len(new_tasks), "source": source or "unknown"})
    return new_tasks


def _hr_advance_lifecycle(db: dict, today: str = None) -> list:
    """R-090 — advance employee status with the calendar (run daily by
    hr_scheduler.job_lifecycle_advance):
      Pre-Start   -> Onboarding   on the start date
      Onboarding  -> Active       once every onboarding task is Completed/Waived
      Offboarding -> Terminated   the day after the last day (portal access ends)
    Returns [(employee_id, old, new), ...]; the caller saves."""
    today = today or _hrdt.date.today().isoformat()
    changes = []
    for e in db.get("employees", []):
        st = str(e.get("status") or "").strip().lower()
        new = None
        if st == "pre-start" and e.get("start_date") and e["start_date"] <= today:
            new = "Onboarding"
        elif st == "onboarding" and (e.get("start_date") or "") <= today:
            onb = [t for t in db.get("tasks", []) if t.get("employee_id") == e["id"]
                   and str(t.get("template_id") or "").startswith("TMPL-")
                   and not str(t.get("template_id")).startswith("TMPL-TERM")]
            if onb and all(t.get("status") in ("Completed", "Waived") for t in onb):
                new = "Active"
        elif st == "offboarding" and e.get("end_date") and e["end_date"] < today:
            new = "Terminated"
        if new:
            old = e.get("status")
            e["status"] = new
            db.setdefault("audit_log", []).append({
                "at": _hrdt.datetime.utcnow().isoformat() + "Z", "action": "status_advanced",
                "employee_id": e["id"], "from": old, "to": new})
            changes.append((e["id"], old, new))
    return changes
'''

edit("ai_prowler_mcp.py", [
    # helpers after _hr_sweep_overdue
    ('''            t["status"] = "Overdue"
            changed = True
    return changed
''',
     '''            t["status"] = "Overdue"
            changed = True
    return changed
''' + HELPERS),
    # hr_initiate_termination -> shared flow
    ('''        emp["status"] = "Offboarding"
        emp["termination_type"] = type
        emp["end_date"] = effective_date
        emp["termination_reason"] = reason
        new_tasks = _hr_generate_offboarding_tasks(emp, db, effective_date)
        db["tasks"].extend(new_tasks)
        db.setdefault("audit_log", []).append({
            "at": _hrdt.datetime.utcnow().isoformat() + "Z", "action": "termination_initiated",
            "employee_id": employee_id, "type": type, "effective_date": effective_date,
            "task_count": len(new_tasks),
        })
        _hr_save_db(db)''',
     '''        new_tasks = _hr_start_offboarding(emp, db, type, effective_date, reason, "mcp_tool")
        _hr_save_db(db)'''),
    # PATCH /employees: termination starts the full flow; statuses canonical
    ('''            changed = [k for k, v in body.items() if k not in BLOCKED and emp.get(k) != v]
            for k in changed:
                emp[k] = body[k]
            if changed:
                db.setdefault("audit_log", []).append({
                    "at": _hrdt.datetime.utcnow().isoformat() + "Z",
                    "action": "employee_updated_via_http",''',
     '''            # R-091 (2026-10-12): HR Admin's Terminations screen sends
            # {status:'terminated', termination_type, end_date, termination_notes}.
            # That now starts the FULL offboarding flow (tasks + deadlines), the
            # same one hr_initiate_termination uses; a stale 'terminated' for
            # someone already offboarding is ignored (the daily job ends it).
            _offb_tasks = None
            if "status" in body:
                _new_st = _hr_canon_status(body.get("status"))
                _cur_st = _hr_canon_status(emp.get("status"))
                if _new_st in ("Offboarding", "Terminated"):
                    if _cur_st not in ("Offboarding", "Terminated"):
                        _offb_tasks = _hr_start_offboarding(
                            emp, db, body.get("termination_type") or "",
                            body.get("end_date") or emp.get("end_date") or "",
                            body.get("termination_notes") or body.get("termination_reason") or "",
                            "hr_admin")
                    body.pop("status", None)
                    body.pop("end_date", None) if _offb_tasks is not None else None
                else:
                    body["status"] = _new_st
            changed = [k for k, v in body.items() if k not in BLOCKED and emp.get(k) != v]
            for k in changed:
                emp[k] = body[k]
            if _offb_tasks is not None:
                changed = sorted(set(changed) | {"status", "end_date"})
            if changed:
                db.setdefault("audit_log", []).append({
                    "at": _hrdt.datetime.utcnow().isoformat() + "Z",
                    "action": "employee_updated_via_http",'''),
    ('''                _hr_save_db(db)
            return _hr_json_response(200, {"ok": True, "employee": emp, "changed": changed})''',
     '''                _hr_save_db(db)
            _resp = {"ok": True, "employee": emp, "changed": changed}
            if _offb_tasks is not None:
                _resp["offboarding_tasks_created"] = len(_offb_tasks)
            return _hr_json_response(200, _resp)'''),
    # PIN sign-in refuses terminated employees
    ('''            if not match:
                return _hr_json_response(401, {"error": "invalid_credentials"})
            # Check against THIS employee's own bearer token first''',
     '''            if not match:
                return _hr_json_response(401, {"error": "invalid_credentials"})
            if _hr_is_terminated(match):                      # R-091: access ends
                return _hr_json_response(403, {"error": "employment_ended"})
            # Check against THIS employee's own bearer token first'''),
    # AI-Prowler portal sign-in: any capitalisation of Terminated
    ('''                                     if e.get("aiprowler_user_id") == _hrl_user.get("id")
                                     and e.get("status") != "Terminated"), None)''',
     '''                                     if e.get("aiprowler_user_id") == _hrl_user.get("id")
                                     and not _hr_is_terminated(e)), None)'''),
    # every portal request: a terminated employee's session stops working
    ('''                        if _hrsrv_emp_id:
                            # An AI-Prowler sign-in session is only good while the
                            # employee is still linked to that same user.''',
     '''                        if _hrsrv_emp_id and _hr_is_terminated(next(
                                (e for e in _hrsrv_db_peek.get("employees", [])
                                 if e.get("id") == _hrsrv_emp_id), {})):
                            _hrsrv_emp_id = None          # R-091: employment ended
                        if _hrsrv_emp_id:
                            # An AI-Prowler sign-in session is only good while the
                            # employee is still linked to that same user.'''),
])

edit("hr_scheduler.py", [
    ('''def job_weekly_owner_summary() -> str:''',
     '''def job_lifecycle_advance() -> str:
    """Job 13 — daily 5am (2026-10-12, R-090). Advance employee status with the
    calendar: Pre-Start -> Onboarding on the start date, Onboarding -> Active
    when every onboarding task is done, Offboarding -> Terminated the day after
    the last day (which ends HR Portal access). Rules in
    ai_prowler_mcp._hr_advance_lifecycle."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db, _hr_save_db, _hr_advance_lifecycle
    except Exception:
        return "lifecycle_advance: HR backend not importable, skipped"
    try:
        with _hr_db_lock:
            db = _hr_load_db()
            changes = _hr_advance_lifecycle(db)
            if changes:
                _hr_save_db(db)
        return "lifecycle_advance: " + (", ".join(f"{i} {o}->{n}" for i, o, n in changes) or "no changes")
    except Exception:
        _log.warning("job_lifecycle_advance failed:\\n%s", traceback.format_exc())
        return "lifecycle_advance: error"


def job_weekly_owner_summary() -> str:'''),
    ('''    "employee_backup":         {"cadence": _employee_backup_cadence, "tracking_key": "last_employee_backup",''',
     '''    "lifecycle_advance":       {"cadence": ("daily", 5, 0), "tracking_key": "last_lifecycle_advance",
                                 "fn": job_lifecycle_advance,
                                 "label": "Employee Status Advance"},
    "employee_backup":         {"cadence": _employee_backup_cadence, "tracking_key": "last_employee_backup",'''),
])
