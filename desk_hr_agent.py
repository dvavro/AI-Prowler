"""
desk_hr_agent.py — the HR agent (hr-agent-spec.md, H1 + H2): the shared agent engine
(desk_agent.py) working the HR Admin and HR Portal apps, kind 'hr', kept in its own database
inside the HR data folder (desk_agent_hr_store.py).

Vicki's decisions (2026-10-31): 1 approving time off is configurable (off by default, with
limits); 2 who reviews is configurable (owner + HR Admin, or managers too for their own team's
time off); 3 whether the AI may read incident reports is configurable (type only by default);
4 its own database in the HR data folder; 5 only AIs that run with a key you control — never a chat; 6 settings and
diagram first.

Deliberately narrow: it watches deadlines, prepares paperwork and drafts answers. People make
every decision about a person. There is no action to hire, reject, discipline, terminate, change
pay or a PTO balance, edit or delete a time entry, verify a document, change access or delete
anything.

PRIVACY — what the AI is never given (enforced here, in code): ID numbers, date of birth, home
address, phone, email, pay rate, bank / deposit details, emergency contacts, medical notes,
photos, PIN / token hashes, protected traits, the text of a message about a sensitive topic,
and the text of an incident report unless the owner chose "Read the report". Packs are built
from an allow-list of fields (SAFE_EMP), never by removing fields from a record.

The HR data is reached through `hr` (set by ai_prowler_mcp.py; tests put fakes in):
    load()                  -> the HR data dict (read only)
    mutate(fn)              -> load under the HR lock, fn(db), save
    api(method, path, body) -> (status, payload) through HR's own /hr-api routes as HR Admin
    balance(db, emp)        -> HR's PTO balance for the employee
    notify(to, subject, body) -> email an employee (HR's notification sender)
    booked_jobs(emp, dates) -> how many Jobs-app jobs the person has on those dates (optional)
    paid_holidays(db, year) -> the observed dates of the company's paid holidays that year (optional)
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re

import desk_agent as engine
import desk_agent_settings as das
from db_access import get_connection

HR = "hr"
ACTOR = "assistant"
hr: dict = {}
clock = None                      # tests: fn() -> naive local datetime

SAFE_EMP = ("id", "first_name", "last_name", "title", "department", "manager_name", "status", "start_date",
            "end_date", "work_state", "employment_type", "remote_status", "pay_frequency")
SENSITIVE = re.compile(
    r"harass|discriminat|retaliat|hostile|assault|abuse|threat|unsafe|injur|hurt|accident|medical|doctor|"
    r"hospital|surgery|pregnan|maternity|paternity|disab|accommodat|fmla|leave of absence|diagnos|therapy|"
    r"mental health|immigra|visa|green card|lawsuit|lawyer|attorney|sue\b|union|wage|overtime pay|unpaid|"
    r"paycheck (is )?wrong|short(ed)? on pay|resign|quit\b|two weeks|fired|termination|whistle|osha|"
    r"drug|alcohol|police|arrest|suicid|self-harm|kill", re.I)
UNPAID_TYPES = re.compile(r"unpaid|fmla|jury|bereave|military|leave of absence|other|personal leave", re.I)
REMIND_GAP_DAYS = 2
FLAGS = ("missed_clock_out", "still_clocked_in", "overtime_coming", "overdue_task", "missing_document",
         "expiring_document", "training_due", "incident_unacknowledged", "final_pay_deadline", "other")


class HRAgentError(engine.AgentError):
    pass


# ── actions, risk, which stage may use them ──────────────────────────────────

RISK = {"hr_note": "low", "hr_flag": "low", "hr_recommend": "low", "hr_draft_email": "low",
        "hr_task": "low", "hr_remind_employee": "medium", "hr_reply": "medium", "hr_ack_sensitive": "medium",
        "hr_ack_incident": "medium", "hr_approve_timeoff": "high", "hr_suggest_policy": "high"}
ALLOWED = {
    (HR, "recruit"): ("hr_draft_email", "hr_task", "hr_note", "no_action"),
    (HR, "onboard"): ("hr_remind_employee", "hr_task", "hr_flag", "hr_note", "no_action"),
    (HR, "timeoff"): ("hr_recommend", "hr_approve_timeoff", "hr_note", "no_action"),
    (HR, "timeclock"): ("hr_flag", "hr_remind_employee", "hr_note", "no_action"),
    (HR, "compliance"): ("hr_remind_employee", "hr_task", "hr_flag", "hr_note", "no_action"),
    (HR, "answer"): ("hr_reply", "hr_ack_sensitive", "hr_note", "no_action"),
    (HR, "incidents"): ("hr_ack_incident", "hr_task", "hr_note", "no_action"),
    (HR, "offboard"): ("hr_task", "hr_draft_email", "hr_flag", "hr_note", "no_action"),
    (HR, "learn"): ("hr_suggest_policy", "hr_note", "no_action"),
}
# Change nothing in HR (shown in the 🤖 tab; a draft is only a draft) — applied even on Suggest.
FREE = ("hr_note", "hr_flag", "hr_recommend", "hr_draft_email")
MESSAGES = ("hr_remind_employee", "hr_reply", "hr_ack_sensitive", "hr_ack_incident")
ANSWERS = ("hr_reply", "hr_ack_sensitive", "hr_ack_incident")
GUARDED = ("hr_approve_timeoff",)
ACTION_FIELDS = {
    "hr_note": "{body} — a note for HR in the 🤖 tab (changes nothing)",
    "hr_flag": "{flag: " + "|".join(FLAGS) + ", detail}",
    "hr_recommend": "{choice: approve|deny|ask, why} — shown to HR on the request",
    "hr_draft_email": "{to_role: applicant|employee|hr, subject, body} — a draft HR sends (never sent by you)",
    "hr_task": "{title, due (YYYY-MM-DD), priority: LOW|MEDIUM|HIGH} — an HR task",
    "hr_remind_employee": "{body} — a short, friendly reminder to the employee (signed for you)",
    "hr_reply": "{body} — the answer to the employee's message, from the policies in the pack only",
    "hr_ack_sensitive": "{} — sends the standard \"HR has your message and will get back to you\"",
    "hr_ack_incident": "{} — sends the standard acknowledgement and assigns the report to HR",
    "hr_approve_timeoff": "{} — approves the request (only when the owner allowed it and every check passes)",
    "hr_suggest_policy": "{topic, body} — a suggested handbook change for HR",
    "no_action": "{}",
}
RULES = [
    "People make every decision about a person. You never hire, reject, discipline, terminate, change pay or "
    "balances, edit time, verify documents or delete anything.",
    "Use only the facts in the pack. Never guess a policy; if the answer isn't in the pack, say HR will follow up "
    "(or leave a note).",
    "If \"sensitive\" is true, don't answer the question — use hr_ack_sensitive or a note for HR.",
    "Messages: short, kind, plain; never mention another employee's details.",
]


def mode(kind, s, stage):
    return das.hr_stage_mode(s, stage)


def stages(kind):
    return tuple(k for k, _ in das.HR_STAGES)


def enabled(s) -> bool:
    return bool(s.get("agent_hr_enabled"))


# ── helpers ──────────────────────────────────────────────────────────────────

def _now(now=None) -> dt.datetime:
    if now is None:
        now = clock() if clock else dt.datetime.now()
    return now.astimezone().replace(tzinfo=None) if now.tzinfo else now


def _d(s):
    try:
        return dt.date.fromisoformat(str(s or "")[:10])
    except ValueError:
        return None


def _ts(s):
    try:
        return dt.datetime.fromisoformat(str(s or "").replace("Z", "")[:19])
    except ValueError:
        return None


def _sig(*parts) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _business_days(a: dt.date, b: dt.date) -> int:
    n, d = 0, a
    while d < b:
        d += dt.timedelta(days=1)
        if d.weekday() < 5:
            n += 1
    return n


def _db() -> dict:
    return hr["load"]() if hr.get("load") else {}


def _emp(db, emp_id) -> dict | None:
    return next((e for e in db.get("employees", []) if e.get("id") == emp_id), None)


def safe_employee(e) -> dict:
    """The only employee fields the AI ever sees (an allow-list)."""
    if not e:
        return {}
    out = {k: e.get(k) for k in SAFE_EMP if e.get(k) not in (None, "")}
    fl = str(e.get("flsa_classification") or "").lower()
    out["hourly"] = "non" in fl or str(e.get("pay_type") or "").lower() == "hourly"
    return out


def _schema(adb):
    conn = get_connection(adb)
    conn.executescript("CREATE TABLE IF NOT EXISTS hr_sent (ref TEXT NOT NULL, employee_id TEXT, kind TEXT, "
                       "sent_at TEXT NOT NULL)")
    return conn


def _sent(adb, employee_id=None, ref=None) -> list:
    conn = _schema(adb)
    try:
        q, a = "SELECT * FROM hr_sent WHERE 1=1", []
        if employee_id:
            q, a = q + " AND employee_id = ?", a + [employee_id]
        if ref:
            q, a = q + " AND ref = ?", a + [ref]
        return [dict(r) for r in conn.execute(q + " ORDER BY sent_at", a)]
    finally:
        conn.close()


def _mark(adb, ref, employee_id, kind) -> None:
    conn = _schema(adb)
    try:
        conn.execute("INSERT INTO hr_sent (ref, employee_id, kind, sent_at) VALUES (?, ?, ?, ?)",
                     (ref, employee_id, kind, _now().isoformat(timespec="seconds")))
    finally:
        conn.close()


def _q(adb, ref, stage, reason, version, s) -> int:
    return 1 if engine.enqueue(adb, HR, ref, stage, reason, version=version, settings=s) else 0


# ── H2: the timer's scan ─────────────────────────────────────────────────────

def scan(adb, jobs_db=None, *, settings=None, edition="business", now=None) -> int:
    s = settings if settings is not None else engine.desk_db.get_settings(adb)
    if not enabled(s) or not hr.get("load"):
        return 0
    now = _now(now)
    try:
        db = _db()
    except Exception:  # noqa: BLE001
        return 0
    n = 0
    for fn in (_scan_recruit, _scan_people, _scan_timeoff, _scan_timeclock, _scan_compliance, _scan_messages,
               _scan_incidents, _scan_learn):
        try:
            n += fn(adb, db, s, now)
        except Exception:  # noqa: BLE001 — one bad check never stops the others
            pass
    return n


def _scan_recruit(adb, db, s, now) -> int:
    n = 0
    for c in (db.get("recruiting") or {}).get("candidates", []) or []:
        cid = str(c.get("id") or "")
        st = str(c.get("status") or c.get("stage") or "").lower()
        if not cid or st in ("hired", "rejected", "declined", "withdrawn", "closed"):
            continue
        n += _q(adb, f"cand:{cid}", "recruit", "new applicant", "new", s)
        since = _d(c.get("updated_at") or c.get("applied_date") or c.get("created_at"))
        if since and (now.date() - since).days >= 5:
            n += _q(adb, f"cand:{cid}", "recruit", "waiting 5+ days", f"wait|{now.date().isocalendar()[1]}", s)
    return n


def _scan_people(adb, db, s, now) -> int:
    n = 0
    today = now.date()
    for e in db.get("employees", []):
        st = str(e.get("status") or "").lower()
        tasks = [t for t in db.get("tasks", []) if t.get("employee_id") == e.get("id")
                 and t.get("status") not in ("Completed", "Waived")]
        sig = _sig(*sorted((t.get("id"), t.get("status")) for t in tasks))
        soon = [t for t in tasks if _d(t.get("due_date")) and (_d(t["due_date"]) - today).days <= 2]
        if st in ("pre-start", "onboarding") and (soon or st == "pre-start" and _d(e.get("start_date"))
                                                  and (_d(e["start_date"]) - today).days <= 7):
            n += _q(adb, f"emp:{e['id']}", "onboard", "onboarding checklist", f"onb|{sig}", s)
        if st == "offboarding" and tasks:
            n += _q(adb, f"emp:{e['id']}", "offboard", "leaving", f"off|{sig}", s)
    return n


def _scan_timeoff(adb, db, s, now) -> int:
    n = 0
    for r in db.get("pto_requests", []):
        if r.get("status") != "pending":
            continue
        n += _q(adb, f"pto:{r['id']}", "timeoff", "time-off request", "pending", s)
        made = _ts(r.get("created_at"))
        if made and _business_days(made.date(), now.date()) >= 1:
            n += _q(adb, f"pto:{r['id']}", "timeoff", "waiting a business day", "late", s)
    for r in db.get("schedule_change_requests", []):
        if r.get("status") == "pending":
            n += _q(adb, f"sched:{r['id']}", "timeoff", "schedule change request", "pending", s)
    return n


def _scan_timeclock(adb, db, s, now) -> int:
    n = 0
    for t in db.get("time_entries", []):
        if t.get("clock_out") is not None:
            continue
        start = _ts(t.get("clock_in"))
        if not start:
            continue
        if start.date() < now.date():
            n += _q(adb, f"time:{t['id']}", "timeclock", "missed_clock_out", "missed", s)
        elif now.hour >= 20 or (now - start).total_seconds() > 12 * 3600:
            n += _q(adb, f"time:{t['id']}", "timeclock", "still_clocked_in", "late", s)
    monday = now.date() - dt.timedelta(days=now.weekday())
    warn = int(s.get("agent_hr_overtime_warn_hours", 36)) * 60
    mins: dict = {}
    for t in db.get("time_entries", []):
        d = _d(t.get("date") or t.get("clock_in"))
        if d and d >= monday:
            mins[t.get("employee_id")] = mins.get(t.get("employee_id"), 0) + int(t.get("duration_minutes") or 0)
    for emp_id, m in mins.items():
        e = _emp(db, emp_id)
        if e and safe_employee(e).get("hourly") and m >= warn:
            n += _q(adb, f"ot:{emp_id}", "timeclock", "overtime_coming", f"ot|{monday}", s)
    return n


def _scan_compliance(adb, db, s, now) -> int:
    n = 0
    days = list(s.get("agent_hr_expiry_days") or [60, 30, 7])
    for d in db.get("documents", []):
        exp = _d(d.get("expiration_date"))
        if not exp or not d.get("employee_id"):
            continue
        left = (exp - now.date()).days
        hit = [x for x in days if left <= x]
        if hit and left >= -30:
            n += _q(adb, f"doc:{d['id']}", "compliance", "expiring_document", f"exp|{min(hit)}", s)
    for t in db.get("training", []):
        due = _d(t.get("due_date"))
        if due and due < now.date() and str(t.get("status") or "").lower() not in ("completed", "complete", "done"):
            n += _q(adb, f"train:{t.get('id')}", "compliance", "training_due", "due", s)
    return n


def _is_incident(m) -> bool:
    return m.get("message_type") == "incident_report"


def _scan_messages(adb, db, s, now) -> int:
    n = 0
    for m in db.get("messages", []):
        if _is_incident(m) or m.get("message_type") in ("training_result", "hr_outbound") or m.get("reply") \
                or m.get("needs_person"):            # the employee asked for a person (or it's sensitive)
            continue
        n += _q(adb, f"msg:{m['id']}", "answer", "employee message", "new", s)
    return n


def _scan_incidents(adb, db, s, now) -> int:
    n = 0
    for r in list(db.get("incidents", [])) + [m for m in db.get("messages", []) if _is_incident(m)]:
        if r.get("ack_at") or str(r.get("hr_status") or r.get("status") or "new").lower() in ("resolved", "closed"):
            continue
        n += _q(adb, f"inc:{r['id']}", "incidents", "incident report", "new", s)
        made = _ts(r.get("submitted_at") or r.get("sent_at"))
        if made and _business_days(made.date(), now.date()) >= 1:
            n += _q(adb, f"inc:{r['id']}", "incidents", "incident_unacknowledged", "late", s)
    return n


def _scan_learn(adb, db, s, now) -> int:
    if now.weekday() != 0:
        return 0
    week = now.date().isocalendar()
    return _q(adb, f"learn:{week[0]}-W{week[1]}", "learn", "weekly look-back", "week", s)


# ── facts: what the pack shows and the policy checks (read fresh) ───────────

def _kind_of(ref):
    return ref.split(":", 1)


def _incident_view(r, s) -> dict:
    out = {"id": r.get("id"), "type": r.get("incident_type") or r.get("type") or r.get("category") or
           ("conduct" if _is_incident(r) else "other"),
           "submitted_at": r.get("submitted_at") or r.get("sent_at"), "status": r.get("hr_status") or r.get("status"),
           "acknowledged": bool(r.get("ack_at")), "anonymous": bool(r.get("anonymous"))}
    if s.get("agent_hr_incidents_access") == "read":       # decision 3 — only when the owner allowed it
        text = r.get("description") or r.get("body") or r.get("details") or ""
        out["report"] = str(text)[:2000]
        out["date_of_incident"] = r.get("incident_date") or r.get("date")
    return out


def facts(adb, item, s, edition) -> dict | None:
    ref, stage = item["ref"], item["stage"]
    kind, key = _kind_of(ref)
    db = _db()
    now = _now()
    f = {"ref": ref, "today": now.date().isoformat(), "_db": db}
    if kind == "pto":
        r = next((x for x in db.get("pto_requests", []) if x.get("id") == key), None)
        if not r:
            return None
        e = _emp(db, r.get("employee_id"))
        f["_req"], f["_emp"] = r, e
        f["request"] = {k: r.get(k) for k in ("id", "type", "start_date", "end_date", "half_day", "status",
                                              "created_at")}
        f["employee"] = safe_employee(e)
        try:
            bal = hr["balance"](db, e) if hr.get("balance") and e else {}
            f["balance"] = {"pto_remaining": (bal.get("pto") or {}).get("remaining"),
                            "sick_remaining": (bal.get("sick") or {}).get("remaining")}
        except Exception:  # noqa: BLE001
            f["balance"] = {}
        f["checks"] = timeoff_checks(db, r, e, s, adb)
        f["version"] = f"{r.get('status')}|{r.get('decided_at')}"
    elif kind == "sched":
        r = next((x for x in db.get("schedule_change_requests", []) if x.get("id") == key), None)
        if not r:
            return None
        f["request"] = {k: r.get(k) for k in ("id", "request_type", "current_shift", "requested_change", "status")}
        f["employee"] = safe_employee(_emp(db, r.get("employee_id")))
        f["_emp"] = _emp(db, r.get("employee_id"))
        f["version"] = str(r.get("status"))
    elif kind == "emp":
        e = _emp(db, key)
        if not e:
            return None
        tasks = [t for t in db.get("tasks", []) if t.get("employee_id") == key]
        f["_emp"], f["employee"] = e, safe_employee(e)
        f["tasks"] = [{k: t.get(k) for k in ("id", "name", "phase", "due_date", "status", "priority",
                                             "assigned_to_role", "federal_required", "upload_required")}
                      for t in tasks if t.get("status") not in ("Completed", "Waived")]
        if stage == "offboard":
            rules = (hr.get("state_rules") or (lambda st: {}))(e.get("work_state") or "") or {}
            f["final_pay_rule"] = str(rules.get("final_pay") or rules.get("final_paycheck") or "")[:300]
        f["version"] = _sig(*sorted((t.get("id"), t.get("status")) for t in tasks), e.get("status"))
    elif kind == "time":
        t = next((x for x in db.get("time_entries", []) if x.get("id") == key), None)
        if not t:
            return None
        f["entry"] = {"id": t.get("id"), "date": t.get("date"), "clock_in": t.get("clock_in"),
                      "clocked_out": t.get("clock_out") is not None}
        f["_emp"] = _emp(db, t.get("employee_id"))
        f["employee"] = safe_employee(f["_emp"])
        f["version"] = str(t.get("clock_out"))
    elif kind == "ot":
        e = _emp(db, key)
        if not e:
            return None
        monday = now.date() - dt.timedelta(days=now.weekday())
        m = sum(int(t.get("duration_minutes") or 0) for t in db.get("time_entries", [])
                if t.get("employee_id") == key and (_d(t.get("date") or t.get("clock_in")) or monday) >= monday)
        f["_emp"], f["employee"] = e, safe_employee(e)
        f["week"] = {"hours_so_far": round(m / 60, 1), "warn_at": s.get("agent_hr_overtime_warn_hours", 36)}
        f["version"] = f"{monday}|{m // 60}"
    elif kind == "doc":
        d = next((x for x in db.get("documents", []) if x.get("id") == key), None)
        if not d:
            return None
        f["document"] = {"id": d.get("id"), "name": d.get("name"), "category": d.get("category"),
                         "expiration_date": d.get("expiration_date")}
        f["_emp"] = _emp(db, d.get("employee_id"))
        f["employee"] = safe_employee(f["_emp"])
        f["version"] = f"{d.get('expiration_date')}|{d.get('reverification_task_id')}"
    elif kind == "train":
        t = next((x for x in db.get("training", []) if str(x.get("id")) == key), None)
        if not t:
            return None
        f["training"] = {k: t.get(k) for k in ("id", "title", "name", "due_date", "status")}
        f["_emp"] = _emp(db, t.get("employee_id"))
        f["employee"] = safe_employee(f["_emp"])
        f["version"] = str(t.get("status"))
    elif kind == "msg":
        m = next((x for x in db.get("messages", []) if x.get("id") == key), None)
        if not m:
            return None
        text = f"{m.get('subject') or ''}\n{m.get('body') or m.get('message') or ''}"
        sensitive = bool(SENSITIVE.search(text))
        f["_msg"], f["_emp"] = m, _emp(db, m.get("employee_id"))
        f["employee"] = safe_employee(f["_emp"]) if f["_emp"] else {"anonymous": True}
        f["message"] = {"id": m.get("id"), "sent_at": m.get("sent_at"), "sensitive": sensitive,
                        "anonymous": bool(m.get("anonymous")), "help_question": m.get("message_type") == "help_question",
                        "wants_a_person": bool(m.get("needs_person"))}
        if not sensitive:                       # a sensitive message's words never go to the AI
            f["message"]["subject"] = str(m.get("subject") or "")[:200]
            f["message"]["body"] = str(m.get("body") or m.get("message") or "")[:1500]
            f["policies"] = _policies(db, f["_emp"])
        f["sensitive"] = sensitive
        f["version"] = f"{bool(m.get('reply'))}|{bool(m.get('needs_person'))}"
    elif kind == "inc":
        r = next((x for x in list(db.get("incidents", [])) + db.get("messages", []) if x.get("id") == key), None)
        if not r:
            return None
        f["_inc"] = r
        f["incident"] = _incident_view(r, s)
        f["_emp"] = _emp(db, r.get("employee_id"))
        f["version"] = f"{r.get('ack_at')}|{r.get('hr_status') or r.get('status')}"
    elif kind == "cand":
        c = next((x for x in (db.get("recruiting") or {}).get("candidates", []) or [] if str(x.get("id")) == key),
                 None)
        if not c:
            return None
        f["candidate"] = {"id": c.get("id"), "first_name": str(c.get("first_name") or c.get("name") or "").split(" ")[0],
                          "position": c.get("position") or c.get("position_title") or c.get("role"),
                          "status": c.get("status") or c.get("stage"),
                          "applied": c.get("applied_date") or c.get("created_at")}
        f["version"] = str(c.get("status") or c.get("stage"))
    elif kind == "learn":
        msgs = [m for m in db.get("messages", []) if not _is_incident(m)
                and not SENSITIVE.search(f"{m.get('subject') or ''} {m.get('body') or ''}")]
        f["recent_questions"] = [str(m.get("subject") or m.get("body") or "")[:120] for m in msgs[-30:]]
        late = [t for t in db.get("tasks", []) if t.get("status") == "Overdue"]
        f["often_late"] = sorted({t.get("name") for t in late if t.get("name")})[:20]
        f["policies"] = _policies(db, None)
        f["version"] = key
    else:
        return None
    return f


def _policies(db, e) -> dict:
    cfg = db.get("config") or {}
    pol = {"pto": {k: cfg.get(k) for k in ("pto_days_per_year", "sick_days_per_year", "carryover_max") if k in cfg}}
    for k in ("handbook", "policies", "faq"):
        if cfg.get(k):
            pol[k] = str(cfg[k])[:3000]
    if e:
        pol["your_pay_frequency"] = e.get("pay_frequency")
    return pol


def blackout_days(entries) -> set:
    """HR's blackout dates and ranges ("2026-12-24", "2026-12-24 to 2026-12-31") as a set of ISO days."""
    days = set()
    for text in entries or []:
        parts = [_d(x.strip()) for x in str(text).split(" to ")]
        if not all(parts):
            continue
        for i in range((parts[-1] - parts[0]).days + 1):
            days.add((parts[0] + dt.timedelta(days=i)).isoformat())
    return days


def timeoff_checks(db, r, e, s, adb=None) -> dict:
    """Decision 1's guardrails, worked out in code for HR to see and for the policy."""
    out = {}
    typ = str(r.get("type") or "")
    sick = "sick" in typ.lower()
    out["paid_type"] = not UNPAID_TYPES.search(typ) and ("pto" in typ.lower() or "vacation" in typ.lower() or sick)
    a, b = _d(r.get("start_date")), _d(r.get("end_date"))
    days = 0.5 if r.get("half_day") else sum(1 for i in range(((b - a).days + 1) if a and b else 0)
                                             if (a + dt.timedelta(days=i)).weekday() < 5)
    out["days"] = days
    out["within_max_days"] = days <= int(s.get("agent_hr_timeoff_max_days", 2))
    made = _ts(r.get("created_at"))
    notice = (a - made.date()).days if a and made else 0
    out["notice_days"] = notice
    out["enough_notice"] = sick or notice >= int(s.get("agent_hr_timeoff_notice_days", 14))
    try:
        bal = hr["balance"](db, e) if hr.get("balance") and e else None
    except Exception:  # noqa: BLE001
        bal = None
    rem = ((bal or {}).get("sick" if sick else "pto") or {}).get("remaining")
    out["balance_covers"] = rem is not None and float(rem) >= days
    blackout = blackout_days((db.get("config") or {}).get("pto_blackout_dates"))
    span = [(a + dt.timedelta(days=i)).isoformat() for i in range(((b - a).days + 1) if a and b else 0)]
    out["no_blackout"] = not (blackout & set(span))
    # 2026-11-04 (David): a paid company holiday in the request goes to a person. A failed lookup counts as a clash.
    try:
        holidays = set()
        for year in sorted({d[:4] for d in span}):
            holidays |= set(hr["paid_holidays"](db, int(year))) if hr.get("paid_holidays") else set()
        out["no_holiday"] = not (holidays & set(span))
    except Exception:  # noqa: BLE001
        out["no_holiday"] = False
    dept = (e or {}).get("department") or ""
    worst = 0
    for day in span:
        off = sum(1 for x in db.get("pto_requests", []) if x.get("status") == "approved" and x.get("id") != r.get("id")
                  and (x.get("start_date") or "") <= day <= (x.get("end_date") or "")
                  and (_emp(db, x.get("employee_id")) or {}).get("department", "") == dept)
        worst = max(worst, off)
    out["others_off"] = worst
    out["room_that_day"] = worst < int(s.get("agent_hr_timeoff_max_off", 1))
    try:
        jobs = hr["booked_jobs"](e, span) if hr.get("booked_jobs") and e else 0
    except Exception:  # noqa: BLE001
        jobs = 1                                 # couldn't tell: a person looks (the check fails safe)
    out["booked_jobs"] = jobs
    out["no_booked_jobs"] = not jobs
    flagged = False
    if adb and e:
        conn = engine._conn(adb)
        try:
            flagged = bool(conn.execute("SELECT 1 FROM agent_proposals WHERE action = 'hr_flag' AND status IN "
                                        "('pending', 'applied') AND payload_json LIKE ?",
                                        (f"%{e.get('id')}%",)).fetchone())
        finally:
            conn.close()
    out["nothing_flagged"] = not flagged
    return out


def pack(adb, jobs_db, item, s, edition, business) -> dict | None:
    f = facts(adb, item, s, edition)
    if f is None:
        return None
    out = {k: v for k, v in f.items() if not k.startswith("_")}
    out["why_queued"] = item.get("reason") or ""
    out["rules"] = RULES
    out["action_fields"] = {a: ACTION_FIELDS[a] for a in ALLOWED[(HR, item["stage"])]}
    if f.get("sensitive"):
        out["hint"] = "Sensitive — don't answer it. Use hr_ack_sensitive (if allowed) or a note for HR."
    return out


def context(adb, jobs_db, item, s, edition, business) -> dict:
    f = facts(adb, item, s, edition)
    if f is None:
        return {"gone": True, "stale": False}
    f["stale"] = bool(item.get("read_version")) and str(f.get("version")) != str(item["read_version"])
    conn = engine._conn(adb)
    try:
        f["approved_today"] = conn.execute(
            "SELECT COUNT(*) FROM agent_proposals WHERE action = 'hr_approve_timeoff' AND status = 'applied' AND "
            "decided_by = 'policy:auto' AND substr(decided_at, 1, 10) = ?", (engine.utcnow_iso()[:10],)).fetchone()[0]
    finally:
        conn.close()
    f["_adb"] = adb
    return f


# ── the policy's HR rules ────────────────────────────────────────────────────

def holds(kind, stage, act, s, ctx, conf, mode_) -> tuple:
    name = act.get("action")
    out = []
    if ctx.get("gone"):
        out.append("it's no longer in the HR apps")
    e = ctx.get("_emp") or {}
    if name in MESSAGES:
        if str(e.get("status") or "").lower() == "terminated":
            out.append("a former employee — HR writes to them")
        h0, h1 = (s.get("agent_hr_quiet_hours") or [8, 18])[:2]
        now = _now()
        # 2026-11-04 (David: the AI can answer 24 hours a day, so it should): an answer to what someone just asked goes
        # out at any hour. Only what the agent starts itself (reminders) keeps to the hours.
        if name not in ANSWERS and (not (h0 <= now.hour < h1) or now.weekday() >= 5):
            out.append(f"outside the hours employees are messaged ({h0}:00–{h1}:00, weekdays)")
        if name in ("hr_remind_employee",) and e.get("id") and ctx.get("_adb"):
            recent = [x for x in _sent(ctx.get("_adb"), employee_id=e["id"], ref=ctx.get("ref"))
                      if (_now() - (_ts(x["sent_at"]) or _now())).days < REMIND_GAP_DAYS]
            if recent:
                out.append("a reminder about this went in the last 2 days")
        out += engine._text_problems(str(act.get("body") or ""))
    if name == "hr_reply" and ctx.get("sensitive"):
        out.append("a sensitive message — a person answers it")
    if name in ("hr_reply", "hr_ack_sensitive") and (ctx.get("message") or {}).get("wants_a_person"):
        out.append("the employee asked for a person")
    if name in ("hr_reply", "hr_ack_sensitive") and (ctx.get("_msg") or {}).get("reply"):
        out.append("it already has an answer")
    if name == "hr_ack_sensitive" and not s.get("agent_hr_ack_sensitive", True):
        out.append("sending the standard acknowledgement is switched off")
    if name in ("hr_reply", "hr_remind_employee") and (ctx.get("message") or {}).get("anonymous"):
        out.append("anonymous — there's no one to reply to")
    guarded = _timeoff_guard(s, ctx, conf) if name in GUARDED else None
    return out, guarded


def _timeoff_guard(s, ctx, conf) -> tuple:
    if not das.can_approve_timeoff(s):
        return False, "the agent isn't allowed to approve time off (or Time off isn't on Auto)"
    c = ctx.get("checks") or {}
    names = {"paid_type": "not paid time off or sick days", "within_max_days": "longer than the agent may approve",
             "enough_notice": "not enough notice", "balance_covers": "the balance doesn't cover it",
             "no_blackout": "a blackout date", "no_holiday": "a company holiday", "room_that_day": "too many people off that day",
             "no_booked_jobs": "they have booked jobs those days", "nothing_flagged": "something is flagged on them"}
    for k, why in names.items():
        if not c.get(k):
            return False, why
    if ctx.get("approved_today", 0) >= int(s.get("agent_hr_timeoff_per_day", 5)):
        return False, "the agent's daily limit is reached"
    if conf < engine.CONFIRM_CONFIDENCE:
        return False, f"confidence {conf:.2f} < {engine.CONFIRM_CONFIDENCE}"
    return True, ""


def validate(item, act, ctx) -> None:
    name = act["action"]
    if ctx.get("gone"):
        raise HRAgentError("it's no longer in the HR apps")
    if name in ("hr_note", "hr_remind_employee", "hr_reply", "hr_draft_email", "hr_suggest_policy") and \
            not str(act.get("body") or "").strip():
        raise HRAgentError(f"{name} needs a body")
    if name == "hr_flag" and act.get("flag") not in FLAGS:
        raise HRAgentError(f"flag must be one of {', '.join(FLAGS)}")
    if name == "hr_recommend" and act.get("choice") not in ("approve", "deny", "ask"):
        raise HRAgentError("choice must be approve, deny or ask")
    if name == "hr_task":
        if not str(act.get("title") or "").strip():
            raise HRAgentError("hr_task needs a title")
        if act.get("due") and not _d(act["due"]):
            raise HRAgentError("due must be a date like 2026-11-05")
        if str(act.get("priority") or "MEDIUM").upper() not in ("LOW", "MEDIUM", "HIGH"):
            raise HRAgentError("priority must be LOW, MEDIUM or HIGH")
    if name == "hr_draft_email" and act.get("to_role") not in ("applicant", "employee", "hr"):
        raise HRAgentError("to_role must be applicant, employee or hr")
    if name == "hr_approve_timeoff" and (ctx.get("_req") or {}).get("status") != "pending":
        raise HRAgentError("the request isn't waiting any more")
    if name in ("hr_remind_employee",) and not (ctx.get("_emp") or {}).get("id"):
        raise HRAgentError("no employee to remind")


def can_review(actor, p, s) -> tuple:
    """Decision 2: owner (and HR Admin, who sign in as the owner's HR role) always; managers only
    when allowed, only for time off / schedule changes of their own team, never their own."""
    from desk_rules import MANAGER, OWNER, normalize_actor
    a = normalize_actor(actor)
    if a["role"] == OWNER or a.get("hr_admin"):
        return True, ""
    if a["role"] != MANAGER:
        return False, "only the owner, HR Admin or (if allowed) a manager can review the HR agent's work"
    if s.get("agent_hr_reviewers") != "hr_admin_managers":
        return False, "only the owner and HR Admin review the HR agent's work"
    if p.get("stage") != "timeoff":
        return False, "managers review only time off and schedule changes"
    try:
        f = facts(None, {"ref": p["ref"], "stage": p["stage"]}, s, "business") or {}
    except Exception:  # noqa: BLE001
        f = {}
    e = f.get("_emp") or {}
    if e.get("aiprowler_user_id") and e.get("aiprowler_user_id") == a.get("id"):
        return False, "not your own request"
    if str(e.get("manager_name") or "").strip().lower() != str(a.get("name") or "").strip().lower():
        return False, "only for your own team"
    return True, ""


# ── applying (only through here) ─────────────────────────────────────────────

def _api(method, path, body=None):
    fn = hr.get("api")
    if not fn:
        raise HRAgentError("the HR apps aren't available here")
    st, payload = fn(method, path, body or {})
    if st >= 400:
        raise HRAgentError((payload or {}).get("error") or f"HR said {st}")
    return payload


def _email_of(e):
    return str(e.get("work_email") or e.get("personal_email") or "").strip()


def _notify(e, subject, body):
    to = _email_of(e or {})
    if not to:
        raise HRAgentError("no email on file for the employee")
    if not hr.get("notify"):
        raise HRAgentError("HR email isn't set up here")
    r = str(hr["notify"](to, subject, body) or "")
    if r.lstrip().startswith("❌"):
        raise HRAgentError(r.strip().splitlines()[0][:200])


def _sig_line(s, business):
    p = das.persona(s, business)
    return f"— {p['display']}, HR"


def apply(adb, jobs_db, item, act, s, edition, business, *, approved_by: str) -> str:
    name = act["action"]
    ctx = context(adb, jobs_db, item, s, edition, business)
    if ctx.get("gone"):
        raise HRAgentError("it's no longer in the HR apps")
    body = str(act.get("body") or "").strip()
    sig = _sig_line(s, business)
    e = ctx.get("_emp") or {}
    if name in FREE:
        return "shown in the 🤖 tab" if name != "hr_draft_email" else "draft saved for HR to send"
    if name == "hr_task" or name == "hr_suggest_policy":
        title = (str(act.get("title") or "").strip() if name == "hr_task"
                 else f"Consider a handbook change: {str(act.get('topic') or 'policy')[:80]}")

        def add(db):
            tasks = db.setdefault("tasks", [])
            nums = [int(m.group(1)) for t in tasks for m in [re.search(r"(\d+)$", str(t.get("id") or ""))] if m]
            tid = f"TASK-{(max(nums) + 1 if nums else 1):05d}"
            tasks.append({"id": tid, "employee_id": e.get("id"), "template_id": None, "phase": "Agent",
                          "name": title[:200], "priority": str(act.get("priority") or "MEDIUM").upper(),
                          "assigned_to_role": "HR", "assigned_to_id": None,
                          "due_date": act.get("due") or (_now().date() + dt.timedelta(days=3)).isoformat(),
                          "status": "Not Started", "instructions": f"🤖 {body or act.get('why') or ''}"[:2000],
                          "created_by": f"{ACTOR} (approved by {approved_by})",
                          "created_at": engine.utcnow_iso()})
            return tid
        tid = hr["mutate"](add)
        return f"HR task {tid or ''} added".replace("  ", " ")
    if name == "hr_remind_employee":
        _notify(e, "A reminder from HR", f"Hi {e.get('first_name') or ''},\n\n{body}\n\n{sig}")
        _mark(adb, item["ref"], e.get("id"), "reminder")
        return "reminder emailed to the employee"
    if name in ("hr_reply", "hr_ack_sensitive"):
        m = ctx.get("_msg") or {}
        text = (body if name == "hr_reply" else
                "Thanks for your message — HR has it and a person will get back to you soon.")
        if m.get("needs_person"):
            raise HRAgentError("the employee asked for a person")
        text = f"{text}\n\n{sig}\n(Want a person? Tap 🙋 Talk to a person and HR will answer.)"
        _api("POST", "/messages/reply", {"id": m.get("id"), "reply": text, "by": "assistant"})
        if e.get("id"):
            _mark(adb, item["ref"], e.get("id"), "reply")
        return "answer added to the employee's message (HR Portal)"
    if name == "hr_ack_incident":
        r = ctx.get("_inc") or {}

        def ack(db):
            for x in list(db.get("incidents", [])) + db.get("messages", []):
                if x.get("id") == r.get("id"):
                    x["ack_at"] = engine.utcnow_iso()
                    x["ack_by"] = f"{ACTOR} (approved by {approved_by})"
                    x["assigned_to"] = x.get("assigned_to") or "HR"
                    if _is_incident(x) and not x.get("hr_status"):
                        x["hr_status"] = "open"
        hr["mutate"](ack)
        if e and _email_of(e):
            _notify(e, "We received your report",
                    f"Hi {e.get('first_name') or ''},\n\nThank you for your report. HR has received it and will "
                    f"follow up with you. If anyone is in danger, call 911.\n\n{sig}")
        return "acknowledged and assigned to HR"
    if name == "hr_approve_timeoff":
        r = ctx["_req"]
        _api("POST", f"/pto/{r['id']}/approve", {"decided_by": f"{ACTOR} (approved by {approved_by})",
                                                 "note": "Approved by the HR assistant — every check passed."})
        return f"time off {r['start_date']}–{r['end_date']} approved"
    raise HRAgentError(f"can't apply {name}")


def recommendations(adb) -> dict:
    """The latest recommendation per time-off / schedule-change request, for HR Admin's request
    cards (hr-agent-spec.md §7): {"pto:PTOREQ-1": {"choice", "why", "at", "practice"}}."""
    conn = engine._conn(adb)
    try:
        rows = conn.execute("SELECT ref, payload_json, why, status, created_at FROM agent_proposals WHERE kind = ? AND "
                            "action = 'hr_recommend' AND status IN ('applied', 'practice') AND "
                            "(ref LIKE 'pto:%' OR ref LIKE 'sched:%') ORDER BY proposal_id", (HR,)).fetchall()
    finally:
        conn.close()
    out = {}
    for r in rows:
        try:
            p = json.loads(r["payload_json"] or "{}")
        except ValueError:
            p = {}
        if p.get("choice") in ("approve", "deny", "ask"):
            out[r["ref"]] = {"choice": p["choice"], "why": str(r["why"] or p.get("why") or "")[:300],
                             "at": r["created_at"], "practice": r["status"] == "practice"}
    return out


def install(**fns) -> None:
    """ai_prowler_mcp.py hands over HR's own data functions (see the module docstring)."""
    hr.update({k: v for k, v in fns.items() if v})


def _register() -> None:
    engine.RISK.update(RISK)
    engine.ALLOWED.update(ALLOWED)
    import sys
    engine.KINDS[HR] = sys.modules[__name__]
    if scan not in engine.SCANNERS:
        engine.SCANNERS.append(scan)


_register()
