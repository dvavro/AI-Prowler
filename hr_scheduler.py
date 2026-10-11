"""
hr_scheduler.py
================
Background scheduler for the AI-Prowler HR module (Implementation Plan v2.1
Section 11 — 10 compliance jobs).

IMPORTANT — why this is a SEPARATE engine from scheduler_engine.py:
scheduler_engine.py / scheduler_jobs.py ("Proactive Alerts") are explicitly
personal-mode only — their own module docstrings say so, and rag_gui.py (the
Tkinter desktop GUI) is the thing that imports and starts that engine, so it
only ever runs while the desktop app's GUI process is open. HR compliance
deadlines (I-9 windows, state new-hire reporting, benefits enrollment
windows, document expiration) do not care whether a desktop GUI window is
open, and the HR module itself (_hr_api_route / the /hr and /hr-api routes)
is already wired identically into BOTH personal-mode and server-mode ASGI
routers — there is no "personal mode only" restriction anywhere else in HR.
So this engine:
  - is started directly by ai_prowler_mcp.py's own process entrypoint
    (once, near the top of `if __name__ == "__main__":`, before the
    stdio/http/server-mode branch split — see that file's comment marked
    "HR SCHEDULER" for the call site), NOT by rag_gui.py, and NOT gated by
    _IS_SERVER_MODE.
  - runs identically whether ai_prowler_mcp.py was launched as an MCP stdio
    server (Claude Desktop), personal-mode HTTP, or server-mode HTTP.
  - never imports ai_prowler_mcp at module load time (that would be a
    circular import — this module is imported *by* ai_prowler_mcp.py). Every
    job function does a lazy `from ai_prowler_mcp import ...` inside a
    try/except at call time instead, matching the established defensive-
    import idiom already used by scheduler_jobs.py's own helper functions
    (_ar_aging(), _sms_replies(), etc.) for the exact same reason.

State lives in hr_task_tracking.json (schema already scaffolded alongside
hr_db.json when the HR module was built) — this file owns reading/writing
its "scheduler" and "digest_state" sections. Never touches hr_db.json's
schema directly except through the existing _hr_load_db/_hr_save_db helpers
in ai_prowler_mcp.py, so there remains exactly one place that knows the
employees/tasks/documents schema.

Safety note for anyone testing this file: job functions are pure/side-effect
functions that mutate the REAL hr_db.json and send REAL email when actually
invoked with the real _hr_load_db/_hr_save_db imports available. Tests must
never import this module directly for behavioral assertions (that would
either import ai_prowler_mcp transitively or hit a real file) — mirror the
scheduling-math functions (_is_interval_due / _is_fixed_time_due /
_already_ran_today) locally instead, exactly like tests/analysis/
test_scheduler.py already does for scheduler_engine.py's equivalents.
"""

import os
import json
import time
import logging
import datetime
import traceback
import threading

_log = logging.getLogger("hr_scheduler")

# ── Paths ────────────────────────────────────────────────────────────────────
# _HR_SCHED_ROOT_DIR is still the install directory (hr_scheduler.py ships
# next to ai_prowler_mcp.py) -- but that's read-only shipped-code territory.
#
# hr_task_tracking.json is mutable state (the scheduler writes to it every
# tick), so -- matching the fix made to ai_prowler_mcp.py's _HR_STATE_DIR on
# 2026-08-29 after real installs hit PermissionError writing
# hr_task_tracking.json.tmp under C:\Program Files\AI-Prowler -- it now
# defaults to a per-user, always-writable folder instead of the install dir.
# AIPROWLER_TEST_STATE_DIR still overrides it for the test sandbox exactly as
# before, so a sandboxed test process can run the real scheduler loop against
# a private tracking file instead of ever touching the operator's real
# hr_task_tracking.json.
_HR_SCHED_ROOT_DIR    = os.path.dirname(os.path.abspath(__file__))
_HR_SCHED_STATE_DIR   = (os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip()
                          or os.path.join(os.path.expanduser("~"), ".ai-prowler", "hr"))
os.makedirs(_HR_SCHED_STATE_DIR, exist_ok=True)
_HR_TRACKING_PATH     = os.path.join(_HR_SCHED_STATE_DIR, "hr_task_tracking.json")

_HR_TRACKING_DEFAULT = {
    "_meta": {
        "description": "HR task scheduler state: digest timestamps, notification "
                        "logs, and scheduler heartbeat. Managed by the background "
                        "scheduler — do not edit manually.",
        "spec_version": "v2.1",
    },
    "scheduler": {
        "last_run": None,
        "last_overdue_check": None,
        "last_digest_sent": None,
        "last_48h_check": None,
        "last_due_today_check": None,
        "last_overdue_first_notice_check": None,
        "last_escalation_check": None,
        "last_welcome_email_check": None,
        "last_benefits_warning_check": None,
        "last_doc_expiration_check": None,
        "last_weekly_owner_summary": None,
        "last_reminder_email_check": None,
        "last_employee_backup": None,
    },
    "digest_state": {
        "last_digest_at": None,
        "last_digest_recipients": [],
        "last_digest_task_count": 0,
        "last_digest_overdue_count": 0,
        "last_digest_due_today_count": 0,
    },
    "notification_acks": [],
}

_hr_tracking_lock = threading.RLock()


def _load_tracking() -> dict:
    try:
        with open(_HR_TRACKING_PATH, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except Exception:
        data = {}
    # Defensively fill in any missing top-level/nested keys rather than
    # replacing the whole structure, so a partially-hand-edited file (or an
    # older schema) doesn't lose fields this code doesn't know about.
    merged = json.loads(json.dumps(_HR_TRACKING_DEFAULT))  # deep copy
    for k, v in data.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k].update(v)
        else:
            merged[k] = v
    return merged


def _save_tracking(data: dict) -> None:
    tmp = _HR_TRACKING_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, _HR_TRACKING_PATH)


# ── Scheduling math (pure functions — mirror these in tests, never import
#    this module for behavioral assertions) ──────────────────────────────────

def _parse_iso(ts):
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(str(ts).replace("Z", ""))
    except Exception:
        return None


def _is_interval_due(last_run_iso, interval_minutes: int, now: datetime.datetime) -> bool:
    """True if `interval_minutes` have elapsed since last_run_iso (or if the
    job has never run)."""
    last = _parse_iso(last_run_iso)
    if last is None:
        return True
    return (now - last) >= datetime.timedelta(minutes=interval_minutes)


def _is_fixed_time_due(last_run_iso, hour: int, minute: int, now: datetime.datetime) -> bool:
    """True at the exact HH:MM tick, but only once per calendar day — mirrors
    scheduler_engine.py's _is_time_due()/_already_ran_today() pair, collapsed
    into one function since each HR job tracks its own single last-run field."""
    if now.hour != hour or now.minute != minute:
        return False
    last = _parse_iso(last_run_iso)
    if last is not None and last.date() == now.date():
        return False  # already fired today
    return True


def _is_weekly_due(last_run_iso, weekday: int, hour: int, minute: int,
                    now: datetime.datetime) -> bool:
    """weekday: 0=Monday .. 6=Sunday (datetime.weekday() convention)."""
    if now.weekday() != weekday or now.hour != hour or now.minute != minute:
        return False
    last = _parse_iso(last_run_iso)
    if last is not None and last.date() == now.date():
        return False
    return True


def _is_monthly_due(last_run_iso, day_of_month: int, hour: int, minute: int,
                     now: datetime.datetime) -> bool:
    """day_of_month: 1-28 (callers cap it at 28 so it always exists in every
    month, including February)."""
    if now.day != day_of_month or now.hour != hour or now.minute != minute:
        return False
    last = _parse_iso(last_run_iso)
    if last is not None and last.date() == now.date():
        return False
    return True


# ── Recipient / mail helpers (lazy-import ai_prowler_mcp; safe no-ops on
#    failure — same defensive idiom as scheduler_jobs.py's helpers) ──────────

def _send_mail(subject: str, html_body: str, to_addr: str) -> bool:
    if not to_addr:
        return False
    try:
        from ai_prowler_mcp import send_email  # noqa: local import, see module docstring
    except Exception:
        _log.warning("hr_scheduler: send_email not importable — mail not sent (%s)", subject)
        return False
    try:
        send_email(to_addr, subject, html_body)
        return True
    except Exception:
        _log.warning("hr_scheduler: send_email raised — mail not sent (%s)\n%s",
                      subject, traceback.format_exc())
        return False


def _default_recipient() -> str:
    """Best-effort fallback recipient, reusing scheduler_engine's own
    email_config.json reader so there's exactly one place that knows how to
    resolve 'the configured default_to email' — that file's config schema is
    installation-wide, not personal-mode-specific, unlike its thread/GUI."""
    try:
        from scheduler_engine import _read_default_to_email  # noqa: local import
        return _read_default_to_email() or ""
    except Exception:
        return ""


def _hr_admin_recipient(db: dict) -> str:
    return (db.get("config", {}) or {}).get("hr_admin_email") or _default_recipient()


def _owner_recipient(db: dict) -> str:
    return (db.get("config", {}) or {}).get("owner_email") or _default_recipient()


def _employee_recipient(emp: dict) -> str:
    return (emp or {}).get("work_email") or (emp or {}).get("personal_email") or ""


def _recipient_for_task(db: dict, task: dict) -> str:
    if task.get("assigned_to_role") == "Employee":
        emp = next((e for e in db.get("employees", []) if e.get("id") == task.get("employee_id")), None)
        addr = _employee_recipient(emp)
        if addr:
            return addr
    return _hr_admin_recipient(db)


def _today_iso() -> str:
    return datetime.date.today().isoformat()


def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


# ── Job functions ─────────────────────────────────────────────────────────
# Each job: no args, returns a short string for logging, never raises (all
# wrapped in try/except so one broken job can never take down the tick loop
# or the other 9 jobs).

def job_overdue_checker() -> str:
    """Job 1 — every 15 min. Flip Not Started/In Progress/Awaiting Document
    tasks whose due_date has passed to Overdue. Reuses the exact same
    _hr_sweep_overdue() the HTTP routes already call on-read; this job's only
    purpose is making sure the flip happens even when nobody is actively
    hitting the PWA or MCP tools."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db, _hr_save_db, _hr_sweep_overdue
    except Exception:
        return "overdue_checker: HR backend not importable, skipped"
    try:
        with _hr_db_lock:
            db = _hr_load_db()
            changed = _hr_sweep_overdue(db)
            if changed:
                _hr_save_db(db)
        return f"overdue_checker: swept overdue tasks (changed={changed})"
    except Exception:
        _log.warning("job_overdue_checker failed:\n%s", traceback.format_exc())
        return "overdue_checker: error"


def job_reminder_48h() -> str:
    """Job 2 — hourly. Tasks due in exactly 48h that haven't been reminded
    yet (last_reminder_sent_at is falsy): send a reminder, stamp the field so
    it never re-sends."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db, _hr_save_db
    except Exception:
        return "reminder_48h: HR backend not importable, skipped"
    try:
        target = (datetime.date.today() + datetime.timedelta(days=2)).isoformat()
        sent = 0
        with _hr_db_lock:
            db = _hr_load_db()
            for t in db.get("tasks", []):
                if t.get("status") not in ("Not Started", "In Progress", "Awaiting Document"):
                    continue
                if t.get("due_date") != target or t.get("last_reminder_sent_at"):
                    continue
                to_addr = _recipient_for_task(db, t)
                _send_mail(
                    f"⏰ Task due in 48 hours — {t.get('name', t.get('id'))}",
                    f"<p>Task <b>{t.get('name')}</b> (employee {t.get('employee_id')}) "
                    f"is due on {t.get('due_date')} (in 48 hours).</p>",
                    to_addr,
                )
                t["last_reminder_sent_at"] = _now_iso()
                sent += 1
            if sent:
                _hr_save_db(db)
        return f"reminder_48h: sent {sent} reminder(s)"
    except Exception:
        _log.warning("job_reminder_48h failed:\n%s", traceback.format_exc())
        return "reminder_48h: error"


def job_due_today_sender() -> str:
    """Job 3 — daily 8am. Tasks due today, not yet notified today: email the
    assigned actor. Uses due_today_notified_at (date-guarded) rather than
    last_reminder_sent_at so it doesn't collide with job 2's 48h marker."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db, _hr_save_db
    except Exception:
        return "due_today_sender: HR backend not importable, skipped"
    try:
        today = _today_iso()
        sent = 0
        with _hr_db_lock:
            db = _hr_load_db()
            for t in db.get("tasks", []):
                if t.get("status") not in ("Not Started", "In Progress", "Awaiting Document"):
                    continue
                if t.get("due_date") != today:
                    continue
                if (t.get("due_today_notified_at") or "")[:10] == today:
                    continue
                to_addr = _recipient_for_task(db, t)
                _send_mail(
                    f"📌 Task due today — {t.get('name', t.get('id'))}",
                    f"<p>Task <b>{t.get('name')}</b> (employee {t.get('employee_id')}) "
                    f"is due today ({today}).</p>",
                    to_addr,
                )
                t["due_today_notified_at"] = _now_iso()
                sent += 1
            if sent:
                _hr_save_db(db)
        return f"due_today_sender: sent {sent} notice(s)"
    except Exception:
        _log.warning("job_due_today_sender failed:\n%s", traceback.format_exc())
        return "due_today_sender: error"


def job_overdue_first_notice() -> str:
    """Job 4 — daily 9am. Tasks that are Overdue and have never had a first
    overdue notice sent: send one, stamp overdue_first_notice_sent_at."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db, _hr_save_db
    except Exception:
        return "overdue_first_notice: HR backend not importable, skipped"
    try:
        sent = 0
        with _hr_db_lock:
            db = _hr_load_db()
            for t in db.get("tasks", []):
                if t.get("status") != "Overdue" or t.get("overdue_first_notice_sent_at"):
                    continue
                to_addr = _recipient_for_task(db, t)
                _send_mail(
                    f"⚠️ Task overdue — {t.get('name', t.get('id'))}",
                    f"<p>Task <b>{t.get('name')}</b> (employee {t.get('employee_id')}) "
                    f"was due {t.get('due_date')} and is now overdue.</p>",
                    to_addr,
                )
                t["overdue_first_notice_sent_at"] = _now_iso()
                sent += 1
            if sent:
                _hr_save_db(db)
        return f"overdue_first_notice: sent {sent} notice(s)"
    except Exception:
        _log.warning("job_overdue_first_notice failed:\n%s", traceback.format_exc())
        return "overdue_first_notice: error"


def job_escalation_check() -> str:
    """Job 5 — daily 10am. CRITICAL tasks overdue 24h+ (due_date <= today-1)
    or HIGH tasks overdue 48h+ (due_date <= today-2), not yet escalated:
    escalate + send an escalation email. Uses the escalated/escalation_sent_at
    fields that already exist on every task record (_hr_build_task)."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db, _hr_save_db
    except Exception:
        return "escalation_check: HR backend not importable, skipped"
    try:
        today = datetime.date.today()
        crit_cutoff = (today - datetime.timedelta(days=1)).isoformat()
        high_cutoff = (today - datetime.timedelta(days=2)).isoformat()
        escalated = 0
        with _hr_db_lock:
            db = _hr_load_db()
            for t in db.get("tasks", []):
                if t.get("status") != "Overdue" or t.get("escalated"):
                    continue
                due = t.get("due_date") or ""
                priority = t.get("priority")
                should = (priority == "CRITICAL" and due <= crit_cutoff) or \
                         (priority == "HIGH" and due <= high_cutoff)
                if not should:
                    continue
                to_addr = _hr_admin_recipient(db)
                _send_mail(
                    f"🚨 ESCALATION — {t.get('name', t.get('id'))}",
                    f"<p><b style='color:#c00'>Escalated:</b> {priority} task "
                    f"<b>{t.get('name')}</b> (employee {t.get('employee_id')}) "
                    f"was due {due} and remains incomplete.</p>",
                    to_addr,
                )
                t["escalated"] = True
                t["escalation_sent_at"] = _now_iso()
                escalated += 1
            if escalated:
                _hr_save_db(db)
        return f"escalation_check: escalated {escalated} task(s)"
    except Exception:
        _log.warning("job_escalation_check failed:\n%s", traceback.format_exc())
        return "escalation_check: error"


def job_daily_digest() -> str:
    """Job 6 — daily 7am. Digest of all overdue + due-today tasks to HR
    Admin. Silent (no email, no state update beyond the check timestamp) when
    there is nothing to report.
    NOTE (documented simplification): the plan says "HR Admin and managers
    (filtered)" — the employee schema has no manager-email field yet (only
    manager_name, a free-text string), so this sends to the single configured
    HR admin recipient only. Extending to per-manager routing needs a real
    manager_id/manager_email link on the employee record."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db
    except Exception:
        return "daily_digest: HR backend not importable, skipped"
    try:
        today = _today_iso()
        with _hr_db_lock:
            db = _hr_load_db()
        overdue = [t for t in db.get("tasks", []) if t.get("status") == "Overdue"]
        due_today = [t for t in db.get("tasks", []) if t.get("due_date") == today
                     and t.get("status") in ("Not Started", "In Progress", "Awaiting Document")]
        if not overdue and not due_today:
            return "daily_digest: nothing to report, skipped"
        to_addr = _hr_admin_recipient(db)
        parts = [f"<h2>📋 HR Daily Digest — {today}</h2>"]
        if overdue:
            parts.append(f"<h3>⚠️ Overdue ({len(overdue)})</h3><ul>" + "".join(
                f"<li>{t.get('name')} — {t.get('employee_id')} (due {t.get('due_date')})</li>"
                for t in overdue) + "</ul>")
        if due_today:
            parts.append(f"<h3>📌 Due Today ({len(due_today)})</h3><ul>" + "".join(
                f"<li>{t.get('name')} — {t.get('employee_id')}</li>" for t in due_today) + "</ul>")
        sent = _send_mail(f"📋 HR Daily Digest — {today}", "\n".join(parts), to_addr)
        if sent:
            with _hr_tracking_lock:
                tr = _load_tracking()
                tr["digest_state"]["last_digest_at"] = _now_iso()
                tr["digest_state"]["last_digest_recipients"] = [to_addr] if to_addr else []
                tr["digest_state"]["last_digest_task_count"] = len(overdue) + len(due_today)
                tr["digest_state"]["last_digest_overdue_count"] = len(overdue)
                tr["digest_state"]["last_digest_due_today_count"] = len(due_today)
                _save_tracking(tr)
        return f"daily_digest: sent={sent} overdue={len(overdue)} due_today={len(due_today)}"
    except Exception:
        _log.warning("job_daily_digest failed:\n%s", traceback.format_exc())
        return "daily_digest: error"


def job_prestart_welcome() -> str:
    """Job 7 — daily 6am. Employees whose start_date is exactly 7 days from
    today: send a welcome email to their personal_email. Guarded by
    prestart_welcome_sent_at so a same-day double-tick can't double-send."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db, _hr_save_db
    except Exception:
        return "prestart_welcome: HR backend not importable, skipped"
    try:
        target = (datetime.date.today() + datetime.timedelta(days=7)).isoformat()
        sent = 0
        with _hr_db_lock:
            db = _hr_load_db()
            for e in db.get("employees", []):
                if e.get("start_date") != target or e.get("prestart_welcome_sent_at"):
                    continue
                to_addr = e.get("personal_email") or ""
                _send_mail(
                    f"👋 Welcome to the team, {e.get('first_name', '')}!",
                    f"<p>Hi {e.get('first_name', '')}, we're looking forward to your "
                    f"first day on {e.get('start_date')}!</p>",
                    to_addr,
                )
                e["prestart_welcome_sent_at"] = _now_iso()
                sent += 1
            if sent:
                _hr_save_db(db)
        return f"prestart_welcome: sent {sent} welcome email(s)"
    except Exception:
        _log.warning("job_prestart_welcome failed:\n%s", traceback.format_exc())
        return "prestart_welcome: error"


def job_benefits_window_warning() -> str:
    """Job 8 — daily 6am. Employees whose start_date was exactly 25 days ago
    (5 days before a typical 30-day benefits enrollment deadline) with an
    incomplete benefits-related task: send a 5-day warning. A task is treated
    as "benefits-related" by a case-insensitive 'benefit' substring in its
    name — matching the same lightweight-keyword style _hr_sweep_overdue's
    neighbors use elsewhere in this file rather than requiring a new
    template-schema field."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db, _hr_save_db
    except Exception:
        return "benefits_window_warning: HR backend not importable, skipped"
    try:
        target = (datetime.date.today() - datetime.timedelta(days=25)).isoformat()
        sent = 0
        with _hr_db_lock:
            db = _hr_load_db()
            for e in db.get("employees", []):
                if e.get("start_date") != target or e.get("benefits_warning_sent_at"):
                    continue
                incomplete = [
                    t for t in db.get("tasks", [])
                    if t.get("employee_id") == e["id"]
                    and "benefit" in (t.get("name") or "").lower()
                    and t.get("status") not in ("Completed", "Waived")
                ]
                if not incomplete:
                    continue
                to_addr = _employee_recipient(e) or _hr_admin_recipient(db)
                _send_mail(
                    f"⏳ 5 days left to enroll in benefits — {e.get('first_name', '')}",
                    f"<p>{e.get('first_name', '')} {e.get('last_name', '')} has "
                    f"{len(incomplete)} incomplete benefits task(s) with the enrollment "
                    f"window closing in 5 days.</p>",
                    to_addr,
                )
                e["benefits_warning_sent_at"] = _now_iso()
                sent += 1
            if sent:
                _hr_save_db(db)
        return f"benefits_window_warning: sent {sent} warning(s)"
    except Exception:
        _log.warning("job_benefits_window_warning failed:\n%s", traceback.format_exc())
        return "benefits_window_warning: error"


def job_reminder_email() -> str:
    """Job 11 — daily 7am. Business calendar reminders (hr/index.html's
    Schedule tab, month-grid view, added 2026-08-29) whose date is today and
    that haven't already had a reminder email sent: email the HR admin.
    Guarded by each reminder's own email_sent flag (set here, and reset by
    the /reminders PATCH route whenever a reminder's date is moved), so a
    same-day double-tick can't double-send and an edited reminder still
    gets a fresh email on its new date."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db, _hr_save_db
    except Exception:
        return "reminder_email: HR backend not importable, skipped"
    try:
        today = _today_iso()
        sent = 0
        with _hr_db_lock:
            db = _hr_load_db()
            events = db.get("events", [])
            to_addr = _hr_admin_recipient(db)
            for r in events:
                if r.get("date") != today or r.get("email_sent"):
                    continue
                _send_mail(
                    f"📅 Reminder today: {r.get('title', '')}",
                    f"<p><strong>{r.get('title', '')}</strong> is scheduled for today "
                    f"({r.get('date', '')}).</p>"
                    + (f"<p>{r.get('note', '')}</p>" if r.get("note") else ""),
                    to_addr,
                )
                r["email_sent"] = True
                r["email_sent_at"] = _now_iso()
                sent += 1
            if sent:
                _hr_save_db(db)
        return f"reminder_email: sent {sent} reminder email(s)"
    except Exception:
        _log.warning("job_reminder_email failed:\n%s", traceback.format_exc())
        return "reminder_email: error"


def job_doc_expiration_check() -> str:
    """Job 9 — daily 6am. Documents expiring within 30 days that don't
    already have a reverification task on file (doc['reverification_task_id']
    unset): create one (HIGH priority, assigned to HR, due on the expiration
    date) and alert HR Admin. Idempotent via reverification_task_id."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db, _hr_save_db, _hr_next_id
    except Exception:
        return "doc_expiration_check: HR backend not importable, skipped"
    try:
        soon = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        created = 0
        with _hr_db_lock:
            db = _hr_load_db()
            for d in db.get("documents", []):
                exp = d.get("expiration_date")
                if not exp or exp > soon or d.get("reverification_task_id"):
                    continue
                task = {
                    "id": _hr_next_id(db["tasks"], "TASK"),
                    "employee_id": d.get("employee_id"),
                    "template_id": None,
                    "phase": "Compliance",
                    "name": f"Reverify expiring document: {d.get('name', d.get('id'))}",
                    "priority": "HIGH",
                    "assigned_to_role": "HR",
                    "assigned_to_id": None,
                    "due_date": exp,
                    "status": "Not Started",
                    "federal_required": False,
                    "state_specific": False,
                    "instructions": f"Document '{d.get('name')}' expires {exp} — "
                                    f"obtain and verify a renewed copy.",
                    "form_ref": None, "portal_url": "", "penalty": "",
                    "escalation_hours": None,
                    "upload_required": True, "upload_folder": None,
                    "completed_at": None, "completed_by": None, "completion_notes": None,
                    "waived_at": None, "waived_by": None, "waive_reason": None,
                    "escalated": False, "escalation_sent_at": None, "last_reminder_sent_at": None,
                    "reassignments": [],
                    "created_at": _now_iso(),
                }
                db["tasks"].append(task)
                d["reverification_task_id"] = task["id"]
                _send_mail(
                    f"📄 Document expiring soon — {d.get('name', d.get('id'))}",
                    f"<p>Document <b>{d.get('name')}</b> (employee {d.get('employee_id')}) "
                    f"expires {exp}. A reverification task ({task['id']}) has been created.</p>",
                    _hr_admin_recipient(db),
                )
                created += 1
            if created:
                _hr_save_db(db)
        return f"doc_expiration_check: created {created} reverification task(s)"
    except Exception:
        _log.warning("job_doc_expiration_check failed:\n%s", traceback.format_exc())
        return "doc_expiration_check: error"


def job_weekly_owner_summary() -> str:
    """Job 10 — Monday 7am. New hires (start_date within the last 7 days),
    CRITICAL-overdue count, and employees at 0% task completion: email the
    Owner. Always sends (unlike the daily digest) since a weekly owner
    summary reporting "all clear" is itself useful signal."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db, _hr_employee_task_stats
    except Exception:
        return "weekly_owner_summary: HR backend not importable, skipped"
    try:
        today = datetime.date.today()
        week_ago = (today - datetime.timedelta(days=7)).isoformat()
        with _hr_db_lock:
            db = _hr_load_db()
        new_hires = [e for e in db.get("employees", [])
                     if e.get("start_date") and week_ago <= e["start_date"] <= today.isoformat()]
        critical_overdue = [t for t in db.get("tasks", [])
                            if t.get("priority") == "CRITICAL" and t.get("status") == "Overdue"]
        zero_pct = []
        for e in db.get("employees", []):
            stats = _hr_employee_task_stats(e["id"], db.get("tasks", []))
            if stats.get("task_completion_pct") == 0:
                zero_pct.append(e)
        to_addr = _owner_recipient(db)
        parts = [f"<h2>🗓️ Weekly HR Summary — week of {today.isoformat()}</h2>",
                 f"<p><b>New hires this week:</b> {len(new_hires)}</p>",
                 f"<p><b>CRITICAL tasks overdue:</b> {len(critical_overdue)}</p>",
                 f"<p><b>Employees at 0% onboarding progress:</b> {len(zero_pct)}</p>"]
        if new_hires:
            parts.append("<ul>" + "".join(
                f"<li>{e.get('first_name')} {e.get('last_name')} (started {e.get('start_date')})</li>"
                for e in new_hires) + "</ul>")
        sent = _send_mail(f"🗓️ Weekly HR Summary — {today.isoformat()}", "\n".join(parts), to_addr)
        return (f"weekly_owner_summary: sent={sent} new_hires={len(new_hires)} "
                f"critical_overdue={len(critical_overdue)} zero_pct={len(zero_pct)}")
    except Exception:
        _log.warning("job_weekly_owner_summary failed:\n%s", traceback.format_exc())
        return "weekly_owner_summary: error"


def job_employee_backup() -> str:
    """Recurring full backup of every actively-employed employee's own
    directory (record.json + all uploaded documents) to an admin-configured
    destination, for disaster recovery. Unlike the compliance jobs above,
    this one's schedule (weekly/monthly, day, time) and destination are
    GUI/tool-configurable — see hr_set_backup_settings in ai_prowler_mcp.py —
    so its cadence is resolved live each tick by _employee_backup_cadence()
    below instead of being a fixed tuple in JOB_REGISTRY. Retention (how many
    snapshots to keep per employee) is enforced by the shared
    _hr_run_employee_backup() helper itself — the same helper hr_backup_now()
    calls for an on-demand run, so there is exactly one place that knows how
    a backup actually happens."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db, _hr_run_employee_backup
    except Exception:
        return "employee_backup: HR backend not importable, skipped"
    try:
        with _hr_db_lock:
            db = _hr_load_db()
        result = _hr_run_employee_backup(db)
        return (f"employee_backup: backed_up={result['backed_up']} "
                f"skipped={result['skipped']} errors={len(result['errors'])} "
                f"dest={result['backup_dir']}")
    except Exception:
        _log.warning("job_employee_backup failed:\n%s", traceback.format_exc())
        return "employee_backup: error"


def _employee_backup_cadence():
    """Resolved fresh on every tick (not a fixed JOB_REGISTRY tuple) since
    the schedule lives in admin-editable config. Returns None when backups
    are disabled or unconfigured, so _tick() simply skips this job that
    round — matching how a job with a static cadence just never becomes due."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db
    except Exception:
        return None
    try:
        with _hr_db_lock:
            db = _hr_load_db()
        cfg = (db.get("config", {}) or {}).get("employee_backup", {}) or {}
        if not cfg.get("enabled") or not (cfg.get("backup_dir") or "").strip():
            return None
        hour = max(0, min(23, int(cfg.get("hour", 2))))
        minute = max(0, min(59, int(cfg.get("minute", 0))))
        if cfg.get("schedule") == "monthly":
            day = max(1, min(28, int(cfg.get("day_of_month", 1))))
            return ("monthly", day, hour, minute)
        weekday = max(0, min(6, int(cfg.get("weekday", 6))))  # default Sunday
        return ("weekly", weekday, hour, minute)
    except Exception:
        return None


# ── Job registry ─────────────────────────────────────────────────────────────
# cadence encodes each job's fixed Implementation Plan §11 schedule (these are
# compliance deadlines, not user-configurable alerts, so — unlike Proactive
# Alerts' scheduler_config.json — there is deliberately no GUI-editable time/
# days for these; only a single master on/off switch, see _scheduler_enabled()).
#   ("interval", minutes)
#   ("daily", hour, minute)
#   ("weekly", weekday[0=Mon..6=Sun], hour, minute)
#   ("monthly", day_of_month[1-28], hour, minute)
# A registry entry's "cadence" may instead be a zero-arg callable — used only
# by employee_backup, whose schedule is admin-editable at runtime — which
# _tick() calls fresh each round to resolve the live cadence tuple (or None
# to skip this round; see _employee_backup_cadence() above).
JOB_REGISTRY = {
    "overdue_checker":         {"cadence": ("interval", 15), "tracking_key": "last_overdue_check",
                                 "fn": job_overdue_checker,
                                 "label": "Overdue Checker"},
    "reminder_48h":            {"cadence": ("interval", 60), "tracking_key": "last_48h_check",
                                 "fn": job_reminder_48h,
                                 "label": "48-Hour Reminder Sender"},
    "due_today_sender":        {"cadence": ("daily", 8, 0), "tracking_key": "last_due_today_check",
                                 "fn": job_due_today_sender,
                                 "label": "Due-Today Sender"},
    "overdue_first_notice":    {"cadence": ("daily", 9, 0), "tracking_key": "last_overdue_first_notice_check",
                                 "fn": job_overdue_first_notice,
                                 "label": "Overdue First Notice"},
    "escalation_check":        {"cadence": ("daily", 10, 0), "tracking_key": "last_escalation_check",
                                 "fn": job_escalation_check,
                                 "label": "Escalation Check"},
    "daily_digest":            {"cadence": ("daily", 7, 0), "tracking_key": "last_digest_sent",
                                 "fn": job_daily_digest,
                                 "label": "Daily Digest"},
    "prestart_welcome":        {"cadence": ("daily", 6, 0), "tracking_key": "last_welcome_email_check",
                                 "fn": job_prestart_welcome,
                                 "label": "Pre-Start Welcome Email"},
    "benefits_window_warning": {"cadence": ("daily", 6, 0), "tracking_key": "last_benefits_warning_check",
                                 "fn": job_benefits_window_warning,
                                 "label": "Benefits Window Warning"},
    "doc_expiration_check":    {"cadence": ("daily", 6, 0), "tracking_key": "last_doc_expiration_check",
                                 "fn": job_doc_expiration_check,
                                 "label": "Document Expiration Check"},
    "weekly_owner_summary":    {"cadence": ("weekly", 0, 7, 0), "tracking_key": "last_weekly_owner_summary",
                                 "fn": job_weekly_owner_summary,
                                 "label": "Weekly Owner Summary"},
    "reminder_email":          {"cadence": ("daily", 7, 0), "tracking_key": "last_reminder_email_check",
                                 "fn": job_reminder_email,
                                 "label": "Business Reminder Email"},
    "employee_backup":         {"cadence": _employee_backup_cadence, "tracking_key": "last_employee_backup",
                                 "fn": job_employee_backup,
                                 "label": "Employee Backup"},
}


def _is_due(cadence: tuple, last_run_iso, now: datetime.datetime) -> bool:
    kind = cadence[0]
    if kind == "interval":
        return _is_interval_due(last_run_iso, cadence[1], now)
    if kind == "daily":
        return _is_fixed_time_due(last_run_iso, cadence[1], cadence[2], now)
    if kind == "weekly":
        return _is_weekly_due(last_run_iso, cadence[1], cadence[2], cadence[3], now)
    if kind == "monthly":
        return _is_monthly_due(last_run_iso, cadence[1], cadence[2], cadence[3], now)
    return False


def _scheduler_enabled() -> bool:
    """Master kill-switch, read from hr_db.json's config so a future HR
    Settings UI can flip it without touching this file. Defaults to enabled —
    absence of the key (e.g. before setup is complete) does not disable
    compliance tracking."""
    try:
        from ai_prowler_mcp import _hr_db_lock, _hr_load_db
    except Exception:
        return True
    try:
        with _hr_db_lock:
            db = _hr_load_db()
        return (db.get("config", {}) or {}).get("scheduler_enabled", True) is not False
    except Exception:
        return True


def _tick() -> None:
    if not _scheduler_enabled():
        return
    now = datetime.datetime.utcnow()
    with _hr_tracking_lock:
        tracking = _load_tracking()
        sched = tracking.setdefault("scheduler", {})
        for job_id, meta in JOB_REGISTRY.items():
            key = meta["tracking_key"]
            try:
                cadence = meta["cadence"]
                if callable(cadence):
                    cadence = cadence()
                    if cadence is None:
                        continue  # disabled / unconfigured this round (e.g. employee_backup)
                if _is_due(cadence, sched.get(key), now):
                    result = meta["fn"]()
                    _log.info("hr_scheduler: %s -> %s", job_id, result)
                    sched[key] = now.isoformat() + "Z"
            except Exception:
                # A single misbehaving job must never take down the tick loop
                # or block the other 9 jobs from running this minute.
                _log.warning("hr_scheduler: job '%s' raised:\n%s", job_id, traceback.format_exc())
        sched["last_run"] = now.isoformat() + "Z"
        _save_tracking(tracking)


# ── Thread lifecycle (mirrors scheduler_engine.py's start/stop/is_running
#    public API, minus the config-driven enable/day/time fields those jobs
#    need — HR's schedule is fixed, see JOB_REGISTRY comment above) ─────────

_thread: "threading.Thread | None" = None
_stop_event = threading.Event()
_start_lock = threading.Lock()


def _loop() -> None:
    _log.info("hr_scheduler: background thread started (tid=%s)", threading.get_ident())
    while not _stop_event.wait(60):
        try:
            _tick()
        except Exception:
            _log.warning("hr_scheduler: tick raised:\n%s", traceback.format_exc())


def start() -> None:
    """Idempotent — safe to call from multiple entry points (stdio / http /
    server-mode) since only the first call actually spawns the thread."""
    global _thread
    with _start_lock:
        if _thread is not None and _thread.is_alive():
            return
        _stop_event.clear()
        _thread = threading.Thread(target=_loop, name="AI-Prowler-HR-Scheduler", daemon=True)
        _thread.start()
        _log.info("hr_scheduler: started")


def stop() -> None:
    global _thread
    with _start_lock:
        _stop_event.set()
        _thread = None


def is_running() -> bool:
    return _thread is not None and _thread.is_alive()


def run_job_now(job_id: str) -> str:
    """Manual trigger, bypassing the schedule check — useful for admin tools
    and manual verification. Does not update the tracking timestamp (so the
    regular schedule is undisturbed by a manual run)."""
    meta = JOB_REGISTRY.get(job_id)
    if not meta:
        return f"unknown job_id '{job_id}'"
    return meta["fn"]()
