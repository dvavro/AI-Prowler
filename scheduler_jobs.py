"""
scheduler_jobs.py
=================
Proactive alert job functions for AI-Prowler's background scheduler.
Personal mode only — automatically suppressed in server mode via GUI guard.

Each job function:
  - Accepts a config dict
  - Calls AI-Prowler Python functions directly (no MCP, no API cost)
  - Returns (subject: str, body_html: str) or None if nothing to report
  - Never raises — all exceptions caught internally
"""
from __future__ import annotations
import datetime, traceback, json
from pathlib import Path


# ── Helpers ──────────────────────────────────────────────────────────────────

def _today() -> str:
    return datetime.date.today().isoformat()

def _now_str() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

def _due_date_prefix(t: dict, fallback: str = "") -> str:
    """Return a task's due-date string, truncated to a YYYY-MM-DD prefix,
    falling back from next_due -> created_at -> fallback.

    dict.get(key, default) only substitutes default when the key is
    MISSING from the dict -- a key that's PRESENT but explicitly None
    (the normal state for a one-shot/manual-only task with no schedule,
    e.g. custom_tasks_manager.create_task(..., schedule="none") stores
    next_due=None) sails straight through unchanged. The old inline
    `t.get("next_due", t.get("created_at", ""))[:10]` pattern crashed with
    "'NoneType' object is not subscriptable" the moment such a task showed
    up in the pending queue -- this treats a None value the same as a
    missing key at every step of the fallback chain.
    """
    value = t.get("next_due") or t.get("created_at") or fallback
    return (value or "")[:10]

def _footer() -> str:
    return f"<hr><p style='color:gray;font-size:11px'>AI-Prowler Proactive Alert · {_now_str()}</p>"

def _ar_aging() -> str:
    try:
        from ai_prowler_mcp import get_ar_aging_report
        return get_ar_aging_report()
    except Exception:
        return ""


# R-067 (2026-09-29, found by the time-machine E2E TM-07): the AR aging report
# writes its buckets as "31 – 60 days overdue" / "61 – 90 days overdue" (en
# dash, spaces), and puts each invoice on its own line under that header. The
# overdue alert and the briefing looked for the literal "31-60" / "61-90" on a
# line, so a 31–90-day-overdue invoice never raised anything (only 90+ did,
# and then only the header line, without the invoices). This reads the real
# layout — every invoice row under an overdue (31+) header — and still accepts
# a one-line "31-60 …" form.
import re as _re
_OD_BUCKET_RE = _re.compile(r"(31\s*[-–—]\s*60|61\s*[-–—]\s*90|90\+)")
_BUCKET_HEADER_RE = _re.compile(
    r"(Current \(not yet due\)|\d+\s*[-–—]\s*\d+\s+days overdue|90\+\s+days overdue)")


def _overdue_ar_lines(ar: str) -> list:
    """Lines of the AR aging report that are 31+ days overdue: each such
    bucket's header, then its invoice rows (no rulers/column heads/subtotals)."""
    out, in_od = [], False
    for raw in (ar or "").splitlines():
        l = raw.strip()
        if not l:
            continue
        if _BUCKET_HEADER_RE.search(l):
            in_od = bool(_OD_BUCKET_RE.search(l))
            if in_od:
                out.append(l)
            continue
        if l[0] in "═" or l.upper().startswith("TOTAL"):
            in_od = False
            continue
        if in_od:
            if l[0] == "─" or l.startswith("Invoice ") or l.startswith("Subtotal"):
                continue
            out.append(l)
        elif _OD_BUCKET_RE.search(l):
            out.append(l)   # a one-line "31-60 days: …" style report
    return out

def _sms_replies() -> str:
    try:
        from ai_prowler_mcp import list_sms_contacts_with_replies
        return list_sms_contacts_with_replies()
    except Exception:
        return ""

def _weather(location: str, days: int = 3) -> str:
    try:
        from ai_prowler_mcp import get_weather
        return get_weather(location=location, days=days)
    except Exception:
        return ""

def _owner_name() -> str:
    """v8.1.3 — the owner's display name now comes from Settings -> Owner
    Name, not config['name'] (which used to default to the hardcoded
    string "David" with no relationship to Settings at all)."""
    try:
        from ai_prowler_mcp import _get_personal_owner_name
        return _get_personal_owner_name() or "there"
    except Exception:
        return "there"

def _owner_location() -> str:
    """v8.1.3 — the owner's weather-lookup location now comes from
    Settings -> Owner Name -> Home address (City/State/ZIP), not
    config['location'] (which used to default to a hardcoded town with
    no GUI field to change it at all). Returns "" (not a hardcoded
    fallback town) when nothing is configured — callers must handle
    that explicitly rather than silently defaulting to any particular
    person's real address."""
    try:
        from ai_prowler_mcp import _get_personal_owner_location_string
        return _get_personal_owner_location_string()
    except Exception:
        return ""

def _job_rows(sheet: str = "Jobs_Schedule") -> list[str]:
    try:
        from ai_prowler_mcp import read_job_spreadsheet
        result = read_job_spreadsheet(sheet_name=sheet)
        return [l for l in result.splitlines()
                if l.strip() and not l.startswith(("=", "-", "#"))]
    except Exception:
        return []

def _jobs_on(day: str) -> list[dict]:
    """The jobs worked on `day` (YYYY-MM-DD) straight from the job database, as dicts with whatever of
    job_id, customer, city, state, service_type, crew, status, start_time are filled in.

    Multi-day jobs count on each working day of their span, and a job still open past its planned end
    counts too (R-058, Settings → Working Days). [] on any error, no database, or no jobs — callers treat
    that as "nothing to report", never a failure. (2026-09-13: the old version opened the retired .xlsx
    Job Tracker and silently returned [] every day.)"""
    try:
        from ai_prowler_mcp import _resolve_job_db_path
        import sqlite3

        db_path = _resolve_job_db_path(None, "")
        if not db_path:
            return []
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            from db_write_ops import job_day_number, working_days_conn
            _wd = working_days_conn(conn)      # Settings → Working Days (default Mon–Fri)
            rows = [r for r in conn.execute(
                "SELECT job_id, customer_id, customer_name, street_address, city, state, zip, service_type, "
                "service_details, crew, service_date, end_date, job_status, start_time, end_time, "
                "schedule_type FROM jobs WHERE service_date = ? OR (COALESCE(service_date, '') <> '' "
                "AND service_date < ?) ORDER BY start_time, job_id",
                (day, day),
            ).fetchall() if r["service_date"] == day or job_day_number(
                r["service_date"], r["end_date"], day, status=r["job_status"] or "", days=_wd)]
        finally:
            conn.close()

        col_map = {"job_id": "job_id", "customer_id": "customer_id", "customer_name": "customer",
                   "street_address": "address", "city": "city", "state": "state", "zip": "zip",
                   "service_type": "service_type", "service_details": "details", "crew": "crew",
                   "job_status": "status", "start_time": "start_time", "end_time": "end_time",
                   "service_date": "service_date", "schedule_type": "schedule_type"}
        results = []
        for row in rows:
            entry = {}
            for db_col, out_key in col_map.items():
                v = row[db_col]
                if v is not None and str(v).strip():
                    entry[out_key] = str(v).strip()
            if entry:
                results.append(entry)
        return results
    except Exception:
        return []


def _todays_jobs_structured() -> list[dict]:
    """Today's jobs (see _jobs_on). Kept for older callers and tests."""
    return _jobs_on(datetime.date.today().isoformat())


def _is_closed(status: str) -> bool:
    return str(status or "").strip().lower() in ("complete", "completed", "cancelled", "canceled", "declined")


def _is_done(status: str) -> bool:
    return str(status or "").strip().lower() in ("complete", "completed")


def _server_mode() -> bool:
    """True on an AI-Prowler Server (Business edition, mode=server). Uses the running server's own answer
    when it's loaded; otherwise reads config.json (the desktop window on a server)."""
    import sys as _sys
    m = _sys.modules.get("ai_prowler_mcp")
    if m is not None and hasattr(m, "_IS_SERVER_MODE"):
        return bool(m._IS_SERVER_MODE)
    try:
        cfg = json.loads((Path.home() / ".ai-prowler" / "config.json").read_text(encoding="utf-8-sig")) or {}
        return (str(cfg.get("edition", "")).strip().lower() == "business"
                and str(cfg.get("mode", "")).strip().lower() == "server")
    except Exception:
        return False


def _app_on(group: str) -> bool:
    """Is this optional app switched on (Settings → MCP Tool Configuration)? job_tracker = the Jobs app,
    service_desk = Service Desk + bookings, sms_whatsapp = texting. An alert never reports on an app that's
    off. Unknown / unreadable → on (the data simply comes back empty)."""
    try:
        import tool_config_store as _tcs
        return bool(_tcs.group_enabled("server" if _server_mode() else "personal", group))
    except Exception:
        return True


# ── Who is reading (2026-11-02, server alerts) ───────────────────────────────────────────────────────
# On a server the engine runs each alert once per recipient with config["_viewer"] = that person
# ({"name", "role", "email"}); in personal mode there is no viewer and the owner sees everything.
# The limits match the Jobs app and the MCP tools exactly:
#   owner, manager   → everything, including money (invoices, quotes, billing, scorecard)
#   staff            → every crew's jobs and the Service Desk, but no money
#   field_crew       → only the jobs whose Crew / Technician includes their name; nothing else
def _viewer(config) -> dict | None:
    v = (config or {}).get("_viewer")
    return v if isinstance(v, dict) else None


def _role(config) -> str:
    v = _viewer(config)
    return str(v.get("role") or "field_crew").strip().lower() if v else "owner"


def _sees_money(config) -> bool:
    return _role(config) in ("owner", "manager")


def _sees_desk(config) -> bool:
    return _role(config) in ("owner", "manager", "staff")


def _is_crew(config) -> bool:
    return _role(config) == "field_crew"


def _crew_has(cell, name: str) -> bool:
    """Same rule as the Jobs app (_crew_name_in_cell): name is one of the comma-separated names."""
    me = str(name or "").strip().lower()
    return bool(me) and me in [n.strip().lower() for n in str(cell or "").split(",")]


def _limit_jobs(jobs: list, config) -> list:
    """Field crew see only their own jobs; everyone else sees them all."""
    if not _is_crew(config):
        return list(jobs or [])
    name = (_viewer(config) or {}).get("name", "")
    return [j for j in (jobs or []) if _crew_has(j.get("crew", ""), name)]


def _job_enabled(config, job_id: str) -> bool:
    try:
        return bool(((config or {}).get("jobs") or {}).get(job_id, {}).get("enabled"))
    except Exception:
        return False


def _esc(s) -> str:
    import html
    return html.escape(str(s if s is not None else ""))


def _ticket_lines(**filters) -> list[str]:
    """Service Desk tickets as one line each (e.g. overdue=True), [] when none / Service Desk off."""
    if not _app_on("service_desk"):
        return []
    try:
        from ai_prowler_mcp import list_tickets
        out = list_tickets(**filters)
        if not out or not out[0].isdigit():          # "No tickets match." / an error
            return []
        return [l.strip() for l in out.splitlines()[1:] if l.strip()]
    except Exception:
        return []


def _bookings_waiting() -> list[str]:
    """Website bookings waiting for approval, one line each. [] when none or Service Desk / Jobs off."""
    if not (_app_on("service_desk") and _app_on("job_tracker")):
        return []
    try:
        from ai_prowler_mcp import review_booking
        out = review_booking(action="list")
        if not out.startswith("📅") or "No bookings" in out:
            return []
        return [l.lstrip("• ").strip() for l in out.splitlines() if l.startswith("•")]
    except Exception:
        return []


def _unread_sms_threads() -> list[dict]:
    """Customer text threads with unread replies: [{'name', 'unread'}]. [] when texting is off."""
    if not _app_on("sms_whatsapp"):
        return []
    try:
        from sms_inbox import sms_active_threads
        return [{"name": t.get("contact_name") or t.get("thread_id", "unknown"),
                 "unread": int(t.get("unread_replies") or 0)}
                for t in sms_active_threads(since_hours=168) if int(t.get("unread_replies") or 0) > 0]
    except Exception:
        return []


def _stale_quotes(days: int = 14) -> list[str]:
    """Open quotes older than `days` with no answer yet."""
    try:
        from ai_prowler_mcp import _resolve_job_db_path
        import sqlite3
        db = _resolve_job_db_path(None, "")
        if not db:
            return []
        cut = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
        conn = sqlite3.connect(db)
        try:
            rows = conn.execute(
                "SELECT quote_id, customer_name, quote_date, service_type FROM quotes "
                "WHERE LOWER(COALESCE(status, 'open')) = 'open' AND COALESCE(quote_date, '') <> '' "
                "AND quote_date <= ? ORDER BY quote_date", (cut,)).fetchall()
        finally:
            conn.close()
        return [f"{q} — {c or 'customer'}" + (f" ({s})" if s else "") + f", sent {d}" for q, c, d, s in rows]
    except Exception:
        return []


def _hr_due_count() -> int:
    """How many HR tasks are due today or overdue (server with the HR apps on). 0 otherwise."""
    try:
        import sys as _sys
        m = _sys.modules.get("ai_prowler_mcp")
        if m is None or not getattr(m, "_IS_SERVER_MODE", False) or not m._hr_apps_switch_on():
            return 0
        today = _today()
        n = 0
        for t in (m._hr_load_db().get("tasks") or []):
            st = str(t.get("status") or "").strip().lower()
            due = str(t.get("due_date") or "")[:10]
            if st in ("completed", "waived"):                 # same statuses as hr_get_task_digest
                continue
            if st == "overdue" or (due and due <= today):
                n += 1
        return n
    except Exception:
        return 0


def _db_connect():
    """The job database (sqlite3 connection with Row access), or None."""
    try:
        from ai_prowler_mcp import _resolve_job_db_path
        import sqlite3
        db = _resolve_job_db_path(None, "")
        if not db:
            return None
        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None


def _rain_today(w: str) -> bool:
    """Is rain likely TODAY in this forecast? get_weather prints one line per day ("  2026-11-02: High …
    ⚠️  RAIN RISK — …"). Only today's line counts — it used to flag a job if rain showed up anywhere in the
    3-day text, so a dry day got a rain warning because of the day after tomorrow. Text with no dated lines
    (short summaries) falls back to a plain look for rain words."""
    if not w or w.startswith("❌"):
        return False
    dated = [l for l in w.splitlines() if _re.match(r"\s*\d{4}-\d{2}-\d{2}:", l)]
    if dated:
        today = _today()
        line = next((l for l in dated if l.strip().startswith(today)), dated[0])
        return "RAIN RISK" in line.upper()
    return any(x in w for x in ("⚠️", "rain", "Rain"))


_STATE_PATH = Path.home() / ".ai-prowler" / "scheduler_alert_state.json"


def _changed_since_last(key: str, signature: str) -> bool:
    """True the first time a signature is seen for `key` (and remembers it) — so a repeating alert only
    emails when something NEW shows up, not the same list every 2 hours."""
    try:
        state = json.loads(_STATE_PATH.read_text(encoding="utf-8")) if _STATE_PATH.exists() else {}
    except Exception:
        state = {}
    if state.get(key) == signature:
        return False
    state[key] = signature
    try:
        _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
    except Exception:
        pass
    return True

def _mileage_db_path() -> str:
    try:
        from ai_prowler_mcp import _resolve_job_db_path
        return _resolve_job_db_path(None, "") or ""
    except Exception:
        return ""


def _mileage_brief_lines() -> list[str]:
    """Owner's mileage lines for the morning / Monday brief. [] when mileage
    tracking is off, there's no job database, or anything fails."""
    try:
        import html
        import db_mileage_ops
        db = _mileage_db_path()
        if not db:
            return []
        return [html.escape(l) for l in db_mileage_ops.brief_lines(db)]
    except Exception:
        return []


def _pending_tasks() -> list[dict]:
    """Tasks a chat should run now (2026-11-01: each task has its own schedule; no queue file). Auto-run
    tasks are left out — AI-Prowler runs those itself. Shaped like the old entries (status 'pending')."""
    try:
        import custom_tasks_manager as _ctm
        out = []
        for t in _ctm.chat_due_tasks(_ctm.load_custom_tasks()):
            e = dict(t)
            e["status"] = "pending"
            out.append(e)
        return out
    except Exception:
        return []


# ── Job functions ─────────────────────────────────────────────────────────────

def job_morning_briefing(config: dict):
    """Daily: jobs today (with per-job weather by town), overdue invoices,
    unanswered SMS, due tasks.

    Per-job weather (added v8.1.3): each of today's jobs is checked against
    the weather for ITS OWN City/State — not one fixed location — since a
    field-service day's jobs are frequently scattered across several towns.
    Weather is fetched once per UNIQUE town among today's jobs (dedup), not
    once per job, to avoid redundant API calls when multiple jobs share a
    town. Falls back to the Settings-tab owner address only when a job has
    no City on file, or when the spreadsheet can't be read at all
    (personal-mode-only feature — see _todays_jobs_structured's docstring).

    name/location no longer come from the config dict passed in (v8.1.3) —
    see _owner_name()/_owner_location(). config is still accepted (and
    still used for nothing else here) purely so the scheduler's uniform
    fn(config) calling convention in JOB_REGISTRY doesn't need special-
    casing for this one job.
    """
    try:
        viewer = _viewer(config)
        name = (viewer or {}).get("name") or _owner_name()
        loc  = _owner_location()
        dow  = datetime.date.today().strftime("%A, %B %d")
        server = _server_mode()

        parts = [f"<h2>☀️ Good morning, {_esc(name)}!</h2><p><b>{dow}</b></p><hr>"]

        # Today's jobs — structured, with per-job weather by town. Field crew see only their own
        # (2026-11-02, server alerts), and get nothing at all on a day with no jobs of theirs.
        jobs = _limit_jobs(_todays_jobs_structured(), config)
        if _is_crew(config) and not jobs:
            return None
        if jobs:
            # Fetch weather once per unique town, not once per job.
            weather_cache: dict[str, str] = {}
            def _job_weather(job: dict) -> str:
                city, state = job.get("city", ""), job.get("state", "")
                job_loc = f"{city}, {state}".strip(", ") if (city or state) else loc
                if job_loc not in weather_cache:
                    weather_cache[job_loc] = _weather(job_loc)
                return weather_cache[job_loc]

            parts.append(f"<h3>📋 Today's Jobs ({len(jobs)})</h3><ul>")
            for j in jobs[:10]:
                label = j.get("customer", "Job")
                where = ", ".join(x for x in (j.get("city"), j.get("state")) if x)
                if where:
                    label += f" — {where}"
                if j.get("service_type"):
                    label += f" ({j['service_type']})"
                if j.get("start_time"):
                    label = f"{j['start_time']} {label}"
                rain_flag = " <b style='color:#c00'>⚠️ Rain risk</b>" if _rain_today(_job_weather(j)) else ""
                parts.append(f"<li>{_esc(label)}{rain_flag}</li>")
            if len(jobs) > 10:
                parts.append(f"<li><i>…and {len(jobs) - 10} more</i></li>")
            parts.append("</ul>")
        else:
            parts.append("<p>📋 No jobs scheduled today.</p>")
            # No per-job locations to check — fall back to the single
            # configured location so the briefing still shows something.
            # Skip the lookup entirely (rather than calling _weather("")
            # and relying on it to fail gracefully) when nothing is
            # configured in Settings at all.
            if loc:
                w = _weather(loc)
                if w:
                    wl = [l for l in w.splitlines() if l.strip()][:4]
                    parts.append(f"<h3>🌤️ Weather — {_esc(loc)}</h3><p>{'<br>'.join(_esc(l) for l in wl)}</p>")

        # Overdue invoices — owner and managers only
        ar = _ar_aging() if _sees_money(config) else ""
        if ar:
            od = _overdue_ar_lines(ar)   # R-067
            if od:
                parts.append("<h3>⚠️ Overdue Invoices</h3><ul>")
                for l in od:
                    parts.append(f"<li style='color:red'>{_esc(l)}</li>")
                parts.append("</ul>")

        # 2026-11-02 (David: "we have more apps now"): Service Desk, bookings and old quotes. Each section
        # only shows when that app is on and there's something to say — and only to people who can see
        # it in the apps (Service Desk: not field crew; quotes: owner and managers).
        bookings = _bookings_waiting() if _sees_desk(config) else []
        if bookings:
            parts.append(f"<h3>📅 Bookings Waiting for Approval ({len(bookings)})</h3><ul>"
                         + "".join(f"<li>{_esc(b)}</li>" for b in bookings[:10]) + "</ul>")
        overdue_t = _ticket_lines(overdue=True) if _sees_desk(config) else []
        new_t = _ticket_lines(state="Open") if _sees_desk(config) else []
        if overdue_t or new_t:
            parts.append("<h3>🎫 Service Desk</h3><ul>")
            for t in overdue_t[:10]:
                parts.append(f"<li style='color:#c00'>⏰ Overdue: {_esc(t)}</li>")
            for t in new_t[:10]:
                parts.append(f"<li>🆕 New: {_esc(t)}</li>")
            parts.append("</ul>")
        # (On a server with 📝 Quote Follow-up on, old quotes go out in that alert instead — not twice.)
        if _sees_money(config) and _app_on("job_tracker") and not (server and _job_enabled(config, "quote_followup")):
            sq = _stale_quotes()
            if sq:
                parts.append(f"<h3>📝 Quotes With No Answer Yet ({len(sq)})</h3><ul>"
                             + "".join(f"<li>{_esc(q)}</li>" for q in sq[:10])
                             + "</ul><p><i>A quick follow-up call often wins these.</i></p>")

        # HR (server, owner and managers): one line pointing at HR Admin — the HR reminder emails
        # themselves come from HR's own scheduler, so they aren't repeated here.
        if server and _sees_money(config):
            hr = _hr_due_count()
            if hr:
                parts.append(f"<h3>👥 HR</h3><p>{hr} HR item{'s' if hr != 1 else ''} due or overdue — "
                             f"see HR Admin.</p>")

        # Unread customer texts — personal only. On a server the shared inbox holds every employee's
        # threads; each person reads their own in the Jobs app.
        threads = _unread_sms_threads() if not server else []
        if threads:
            parts.append(f"<h3>💬 Unanswered Messages ({len(threads)})</h3><ul>"
                         + "".join(f"<li>{_esc(t['name'])} — {t['unread']} unread</li>" for t in threads[:10])
                         + "</ul>")

        # Mileage (2026-10-24, mileage spec FR-19/24/25): reminders, IRS
        # record warnings, and on Mondays a short AI review of last week. Owner and managers.
        mi = _mileage_brief_lines() if _sees_money(config) else []
        if mi:
            parts.append("<h3>🚗 Mileage</h3><ul>")
            for l in mi:
                parts.append(f"<li>{l}</li>")
            parts.append("</ul>")

        # Due analysis tasks — personal only (a server runs every task itself; no chat runner there)
        tasks = [t for t in _pending_tasks()
                 if t.get("status") == "pending"
                 and _due_date_prefix(t) <= _today()] if not server else []
        if tasks:
            parts.append(f"<h3>🧠 Analysis Tasks Due ({len(tasks)})</h3><ul>")
            for t in tasks:
                parts.append(f"<li>{_esc(t.get('label','?'))}</li>")
            parts.append("</ul><p><i>Ask Claude, Muse, or Grok to \"run my due analysis tasks\".</i></p>")

        parts.append(_footer())
        return f"☀️ Morning Briefing — {dow}", "\n".join(parts)
    except Exception:
        return "⚠️ Morning Briefing Error", f"<pre>{traceback.format_exc()}</pre>"


def job_overdue_invoice_alert(config: dict):
    """Daily: silent unless invoices are 31+ days overdue. Owner and managers only."""
    try:
        if not _sees_money(config):
            return None
        ar = _ar_aging()
        if not ar:
            return None
        od = _overdue_ar_lines(ar)   # R-067
        if not od:
            return None
        parts = ["<h2>⚠️ Overdue Invoice Alert</h2>",
                 "<table border='1' cellpadding='6'>"]
        for l in od:
            parts.append(f"<tr><td>{l}</td></tr>")
        parts += ["</table>",
                  "<p><i>Consider sending payment reminders via Claude, Muse, or Grok + Square.</i></p>",
                  _footer()]
        return f"⚠️ Overdue Invoices — {_today()}", "\n".join(parts)
    except Exception:
        return None


def job_due_analysis_tasks(config: dict):
    """Daily: alert when scheduled analysis tasks are due or overdue."""
    try:
        due = [t for t in _pending_tasks()
               if t.get("status") == "pending"
               and _due_date_prefix(t) <= _today()]
        if not due:
            return None
        parts = [f"<h2>🧠 {len(due)} Analysis Task(s) Due</h2><ul>"]
        for t in due:
            parts.append(f"<li><b>{t.get('label','?')}</b> "
                         f"(due: {_due_date_prefix(t, fallback='?')}, "
                         f"schedule: {t.get('schedule','?')})</li>")
        parts += ["</ul>",
                  "<p><b>Ask Claude, Muse, or Grok to \"run my due analysis tasks\". Tasks with "
                  "Auto-run on are run by AI-Prowler itself and aren't listed here.</b></p>",
                  _footer()]
        return f"🧠 {len(due)} Task(s) Due — {_today()}", "\n".join(parts)
    except Exception:
        return None


def job_sms_reply_monitor(config: dict):
    """Every N hours: customer texts nobody has read yet. 2026-11-02: lists only the conversations with
    unread replies (it used to paste every recent thread), and emails only when something NEW came in —
    not the same list every 2 hours. Silent when texting is off."""
    try:
        threads = _unread_sms_threads()
        if not threads:
            _changed_since_last("sms_unread", "")
            return None
        sig = "|".join(f"{t['name']}:{t['unread']}" for t in sorted(threads, key=lambda x: x["name"]))
        if not _changed_since_last("sms_unread", sig):
            return None
        parts = [f"<h2>💬 Unanswered Customer Messages ({len(threads)})</h2><ul>"]
        for t in threads:
            parts.append(f"<li><b>{_esc(t['name'])}</b> — {t['unread']} unread</li>")
        parts += ["</ul><p><i>Ask Claude, Muse, or Grok to \"read my new texts\" and reply.</i></p>",
                  _footer()]
        return f"💬 Unanswered Messages — {_now_str()}", "\n".join(parts)
    except Exception:
        return None


def job_weather_watch(config: dict):
    """Weekly: the 7-day forecast for the home address, and — new 2026-11-02 — the jobs booked on each
    rain-risk day, so they can be moved before the customers are affected. (It used to fetch only 3 days
    while saying "5-day forecast", and never looked at the schedule.)

    Each job is checked against ITS OWN town's forecast (the home forecast when the job has no town) —
    that also makes it work on a server, which has no single home address. Field crew get only their own
    jobs, and only when one of them is on a rain-risk day. Silent when there's nothing to go on."""
    try:
        loc = _owner_location()
        server = _server_mode()
        if not loc and not server:
            return None
        w = _weather(loc, days=7) if loc else ""
        if loc and (not w or w.startswith("❌")):
            return None

        def rain_days(text):
            return {m.group(1) for m in (_re.match(r"\s*(\d{4}-\d{2}-\d{2}):.*RAIN RISK", l)
                                         for l in str(text or "").splitlines()) if m}

        rainy = sorted(rain_days(w))
        hits: dict = {}                               # day -> [jobs on a rain-risk day in their own town]
        any_rain = bool(rainy)
        if _app_on("job_tracker"):
            cache = {loc: w} if loc else {}
            for i in range(7):
                d = (datetime.date.today() + datetime.timedelta(days=i)).isoformat()
                for j in _limit_jobs(_jobs_on(d), config):
                    if _is_closed(j.get("status", "")):
                        continue
                    town = ", ".join(x for x in (j.get("city"), j.get("state")) if x) or loc
                    if not town:
                        continue
                    if town not in cache:
                        cache[town] = _weather(town, days=7)
                    days = rain_days(cache[town])
                    any_rain = any_rain or bool(days)
                    if d in days:
                        hits.setdefault(d, []).append(j)
        if (_is_crew(config) or not loc) and not hits:
            return None                               # nothing for this person to act on

        parts = ["<h2>🌤️ Weekly Weather Watch</h2>"]
        if loc and not _is_crew(config):
            parts += [f"<p><b>{_esc(loc)}</b> — 7-day forecast:</p>", f"<pre>{_esc(w[:2500])}</pre>"]
        if hits:
            parts.append("<h3>☔ Jobs on rain-risk days</h3>")
            for d in sorted(hits):
                day = datetime.date.fromisoformat(d).strftime("%A %b %d")
                parts.append(f"<p><b>{day}</b></p><ul>")
                for j in hits[d]:
                    parts.append("<li>" + _esc(" — ".join(x for x in (
                        j.get("customer", "Job"), j.get("service_type", ""),
                        ", ".join(y for y in (j.get("city"), j.get("state")) if y), j.get("crew", "")) if x))
                        + "</li>")
                parts.append("</ul>")
            parts.append("<p><i>Move them in the Jobs app, or ask Claude, Muse, or Grok to "
                         "\"plan my week around the rain\".</i></p>" if not _is_crew(config) else
                         "<p><i>Your office may move these — check the Jobs app.</i></p>")
        elif any_rain and _app_on("job_tracker"):
            parts.append("<p>No jobs booked on the rain-risk days.</p>")
        else:
            parts.append("<p>☀️ No rain-risk days this week.</p>")
        parts.append(_footer())
        return f"🌤️ Weather Watch — Week of {_today()}", "\n".join(parts)
    except Exception:
        return None


def job_end_of_day_summary(config: dict):
    """Evening: today's jobs completed vs still open, jobs worked today with no time entry, and
    tomorrow's schedule. 2026-11-02 rewrite: the old version searched the formatted job list for today's
    date in YYYY-MM-DD form, but that list shows dates as MM/DD/YYYY — so it said "No jobs scheduled
    today" every single day. Now it reads the job database directly. Silent when the Jobs app is off."""
    try:
        if not _app_on("job_tracker"):
            return None
        today = _today()
        jobs = [j for j in _limit_jobs(_jobs_on(today), config)                 # crew: their own only
                if str(j.get("status", "")).lower() not in ("cancelled", "canceled")]
        tomorrow = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
        nxt = [j for j in _limit_jobs(_jobs_on(tomorrow), config) if not _is_closed(j.get("status", ""))]
        if _is_crew(config) and not jobs and not nxt:
            return None
        done = [j for j in jobs if _is_done(j.get("status", ""))]
        open_ = [j for j in jobs if not _is_done(j.get("status", ""))]

        def line(j):
            return _esc(" — ".join(x for x in (
                j.get("job_id", ""), j.get("customer", "Job"), j.get("service_type", ""), j.get("crew", ""),
                j.get("status", "") if j in open_ else "") if x))

        no_time = []
        try:
            from ai_prowler_mcp import _resolve_job_db_path
            import sqlite3
            db = _resolve_job_db_path(None, "")
            if db and jobs:
                conn = sqlite3.connect(db)
                try:
                    logged = {r[0] for r in conn.execute(
                        "SELECT DISTINCT job_id FROM time_entries WHERE entry_date = ?", (today,))}
                finally:
                    conn.close()
                no_time = [j for j in jobs if j.get("job_id") and j["job_id"] not in logged
                           and (_is_done(j.get("status", "")) or "progress" in str(j.get("status", "")).lower())]
        except Exception:
            no_time = []

        parts = [f"<h2>🌙 End of Day — {datetime.date.today().strftime('%A, %B %d')}</h2>"]
        if not jobs:
            parts.append("<p>No jobs scheduled today.</p>")
        if done:
            parts.append(f"<h3>✅ Completed ({len(done)})</h3><ul>" + "".join(f"<li>{line(j)}</li>" for j in done)
                         + "</ul>")
        if open_:
            parts.append(f"<h3>⏳ Still open ({len(open_)})</h3><ul>" + "".join(f"<li>{line(j)}</li>" for j in open_)
                         + "</ul><p><i>Mark them Complete in the Jobs app, or move them to another day.</i></p>")
        if no_time:
            parts.append(f"<h3>⏱️ No time logged today ({len(no_time)})</h3><ul>"
                         + "".join(f"<li>{line(j)}</li>" for j in no_time)
                         + "</ul><p><i>Add the clock-in / clock-out for them in the Jobs app.</i></p>")
        parts.append(f"<h3>📅 Tomorrow ({len(nxt)} job{'s' if len(nxt) != 1 else ''})</h3>")
        if nxt:
            parts.append("<ul>" + "".join("<li>" + _esc(" — ".join(x for x in (
                j.get("start_time", ""), j.get("customer", "Job"), j.get("service_type", ""), j.get("crew", ""))
                if x)) + "</li>" for j in nxt) + "</ul>")
        parts.append(_footer())
        return f"🌙 End of Day — {today}", "\n".join(parts)
    except Exception:
        return None


def job_service_desk_watch(config: dict):
    """New 2026-11-02 (David: "we have more apps now"): Service Desk tickets that are overdue, new tickets
    nobody has picked up, and website bookings waiting for your approval. Silent when there's nothing, or
    when Service Desk is off; on repeat runs it emails only when the list changed."""
    try:
        if not _sees_desk(config):                    # field crew: not theirs (same as the Service Desk app)
            return None
        overdue = _ticket_lines(overdue=True)
        new = _ticket_lines(state="Open")
        bookings = _bookings_waiting()
        # each recipient has their own "already emailed" memory
        key = "service_desk" + (f":{(_viewer(config) or {}).get('email', '')}" if _viewer(config) else "")
        if not (overdue or new or bookings):
            _changed_since_last(key, "")
            return None
        if not _changed_since_last(key, "|".join(overdue + new + bookings)):
            return None
        parts = ["<h2>🎫 Service Desk & Bookings</h2>"]
        if bookings:
            parts.append(f"<h3>📅 Bookings waiting for your approval ({len(bookings)})</h3><ul>"
                         + "".join(f"<li>{_esc(b)}</li>" for b in bookings) + "</ul>")
        if overdue:
            parts.append(f"<h3>⏰ Overdue tickets ({len(overdue)})</h3><ul>"
                         + "".join(f"<li style='color:#c00'>{_esc(t)}</li>" for t in overdue) + "</ul>")
        if new:
            parts.append(f"<h3>🆕 New tickets nobody has picked up ({len(new)})</h3><ul>"
                         + "".join(f"<li>{_esc(t)}</li>" for t in new) + "</ul>")
        parts += ["<p><i>Open the Service Desk app, or ask Claude, Muse, or Grok (\"triage my tickets\", "
                  "\"review my bookings\").</i></p>", _footer()]
        return f"🎫 Service Desk — {_now_str()}", "\n".join(parts)
    except Exception:
        return None


def job_mileage_reminders(config: dict):
    """Evening (7 PM): mileage reminders for the owner — days with gaps,
    Monday's weekly review, crew reimbursements to submit / approve / pay,
    and odometer readings due (each switchable in the Jobs app → Profile →
    Mileage tracking). Silent when there's nothing to do. Owner and managers (crew get their own
    mileage reminders inside the Jobs app)."""
    try:
        if not _sees_money(config):
            return None
        import html
        import db_mileage_ops
        db = _mileage_db_path()
        if not db:
            return None
        due = db_mileage_ops.due_reminders(db, "owner", True)
        if not due:
            return None
        parts = ["<h2>🚗 Mileage reminders</h2><ul>"]
        for r in due:
            parts.append(f"<li>{html.escape(r['text'])}</li>")
        parts += ["</ul>", "<p><i>Open the Jobs app → Mileage, or ask Claude, Muse, or Grok "
                  "(\"review this week's mileage\", \"approve Sam's mileage\").</i></p>", _footer()]
        return f"🚗 Mileage reminders — {_today()}", "\n".join(parts)
    except Exception:
        return None


# ── New business alerts (2026-11-02, David: "New alerts a business owner would pay for (no AI cost)") ──
# All read the job database directly — no AI, no cost. Money alerts go to the owner and managers only.

def _money(v) -> str:
    try:
        return f"${float(v or 0):,.2f}"
    except Exception:
        return "$0.00"


def _business_info() -> dict:
    try:
        from ai_prowler_mcp import _read_business_info
        db = _mileage_db_path()
        return _read_business_info(db) if db else {}
    except Exception:
        return {}


def _billing_leaks(days: int = 60) -> list:
    """Completed jobs from the last `days` days with no invoice — work done but not billed — with the
    hours logged on each and the quoted amount."""
    conn = _db_connect()
    if conn is None:
        return []
    try:
        since = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
        rows = conn.execute(
            "SELECT j.job_id, j.customer_name, j.service_date, j.service_type, j.crew, j.quote_amount, "
            "(SELECT COALESCE(SUM(t.elapsed_min), 0) FROM time_entries t WHERE t.job_id = j.job_id) AS mins "
            "FROM jobs j WHERE LOWER(COALESCE(j.job_status, '')) IN ('complete', 'completed') "
            "AND COALESCE(j.invoice_id, '') = '' "
            "AND NOT EXISTS (SELECT 1 FROM invoices i WHERE i.job_id = j.job_id) "
            "AND COALESCE(j.service_date, '') >= ? ORDER BY j.service_date, j.job_id", (since,)).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


def job_billing_leak(config: dict):
    """Completed jobs with no invoice yet (last 60 days) — money earned but not billed — with the hours
    logged and the quoted amount. Owner and managers. Silent when everything is invoiced."""
    try:
        if not _sees_money(config) or not _app_on("job_tracker"):
            return None
        leaks = _billing_leaks()
        if not leaks:
            return None
        total = sum(float(r.get("quote_amount") or 0) for r in leaks)
        hours = sum(float(r.get("mins") or 0) for r in leaks) / 60.0
        parts = [f"<h2>💸 Work Done, Not Invoiced ({len(leaks)})</h2>",
                 f"<p>About <b>{_money(total)}</b> quoted and <b>{hours:.1f} hours</b> logged on completed jobs "
                 f"with no invoice.</p><ul>"]
        for r in leaks[:40]:
            bits = [r.get("job_id"), r.get("customer_name") or "Customer", r.get("service_type"),
                    f"done {r.get('service_date')}" if r.get("service_date") else "", r.get("crew"),
                    _money(r.get("quote_amount")) if r.get("quote_amount") else "",
                    f"{float(r.get('mins') or 0) / 60:.1f} h logged" if r.get("mins") else ""]
            parts.append("<li>" + _esc(" — ".join(str(b) for b in bits if b)) + "</li>")
        if len(leaks) > 40:
            parts.append(f"<li><i>…and {len(leaks) - 40} more</i></li>")
        parts += ["</ul><p><i>Create the invoices in the Jobs app, or ask Claude, Muse, or Grok to "
                  "\"invoice my completed jobs\".</i></p>", _footer()]
        return f"💸 {len(leaks)} job(s) not invoiced — {_money(total)}", "\n".join(parts)
    except Exception:
        return None


def _scorecard(start: str, end: str) -> dict:
    """Business numbers for start..end (YYYY-MM-DD, inclusive)."""
    out = {"invoiced": 0.0, "collected": 0.0, "scheduled": 0, "completed": 0, "hours": 0.0,
           "billed_hours": 0.0, "quotes_won": 0, "quotes_lost": 0, "quotes_open": 0}
    conn = _db_connect()
    if conn is None:
        return out
    try:
        q = lambda sql, *a: conn.execute(sql, a).fetchone()[0] or 0
        out["invoiced"] = float(q("SELECT SUM(total_due) FROM invoices WHERE substr(invoice_date,1,10) "
                                  "BETWEEN ? AND ?", start, end))
        out["collected"] = float(q("SELECT SUM(amount_paid) FROM invoices WHERE substr(payment_date,1,10) "
                                   "BETWEEN ? AND ?", start, end))
        out["scheduled"] = int(q("SELECT COUNT(*) FROM jobs WHERE service_date BETWEEN ? AND ? AND "
                                 "LOWER(COALESCE(job_status,'')) NOT IN ('cancelled','canceled','declined')",
                                 start, end))
        out["completed"] = int(q("SELECT COUNT(*) FROM jobs WHERE service_date BETWEEN ? AND ? AND "
                                 "LOWER(COALESCE(job_status,'')) IN ('complete','completed')", start, end))
        out["hours"] = float(q("SELECT SUM(elapsed_min) FROM time_entries WHERE entry_date BETWEEN ? AND ?",
                               start, end)) / 60.0
        out["billed_hours"] = float(q(
            "SELECT SUM(t.elapsed_min) FROM time_entries t JOIN jobs j ON j.job_id = t.job_id "
            "WHERE t.entry_date BETWEEN ? AND ? AND (COALESCE(j.invoice_id,'') <> '' OR EXISTS "
            "(SELECT 1 FROM invoices i WHERE i.job_id = j.job_id))", start, end)) / 60.0
        since30 = (datetime.date.fromisoformat(end) - datetime.timedelta(days=29)).isoformat()
        for st, key in (("approved", "quotes_won"), ("declined", "quotes_lost"), ("open", "quotes_open")):
            out[key] = int(q("SELECT COUNT(*) FROM quotes WHERE LOWER(COALESCE(status,'open')) = ? AND "
                             "substr(quote_date,1,10) BETWEEN ? AND ?", st, since30, end))
    except Exception:
        pass
    finally:
        conn.close()
    return out


def _desk_week(start: str, end: str) -> dict:
    """Service Desk: tickets opened / closed in start..end and the average hours to first response."""
    out = {"opened": 0, "closed": 0, "response_h": None}
    if not _app_on("service_desk"):
        return out
    try:
        import desk_db, sqlite3
        conn = sqlite3.connect(desk_db.default_db_path())
        try:
            out["opened"] = conn.execute("SELECT COUNT(*) FROM tickets WHERE substr(created_at,1,10) "
                                         "BETWEEN ? AND ?", (start, end)).fetchone()[0] or 0
            out["closed"] = conn.execute("SELECT COUNT(*) FROM tickets WHERE substr(closed_at,1,10) "
                                         "BETWEEN ? AND ?", (start, end)).fetchone()[0] or 0
            hrs = [(datetime.datetime.fromisoformat(f[:19]) - datetime.datetime.fromisoformat(c[:19]))
                   .total_seconds() / 3600 for c, f in conn.execute(
                       "SELECT created_at, first_response_at FROM tickets WHERE COALESCE(first_response_at,'') "
                       "<> '' AND substr(created_at,1,10) BETWEEN ? AND ?", (start, end))]
            if hrs:
                out["response_h"] = sum(hrs) / len(hrs)
        finally:
            conn.close()
    except Exception:
        pass
    return out


def job_weekly_scorecard(config: dict):
    """Monday: last week's numbers next to the week before — invoiced vs collected, jobs completed vs
    scheduled, crew hours logged vs billed, quote win rate (30 days) and Service Desk response time.
    Owner and managers."""
    try:
        if not _sees_money(config) or not _app_on("job_tracker"):
            return None
        end = datetime.date.today() - datetime.timedelta(days=1)
        start = end - datetime.timedelta(days=6)
        pend, pstart = start - datetime.timedelta(days=1), start - datetime.timedelta(days=7)
        cur, prev = _scorecard(start.isoformat(), end.isoformat()), _scorecard(pstart.isoformat(), pend.isoformat())
        desk = _desk_week(start.isoformat(), end.isoformat())

        def arrow(a, b):
            return "" if a == b else (" <span style='color:#080'>▲</span>" if a > b else
                                      " <span style='color:#c00'>▼</span>")
        decided = cur["quotes_won"] + cur["quotes_lost"]
        win = f"{cur['quotes_won'] * 100 // decided}%" if decided else "—"
        unbilled = max(0.0, cur["hours"] - cur["billed_hours"])
        rows = [
            ("Invoiced", _money(cur["invoiced"]) + arrow(cur["invoiced"], prev["invoiced"]), _money(prev["invoiced"])),
            ("Collected", _money(cur["collected"]) + arrow(cur["collected"], prev["collected"]), _money(prev["collected"])),
            ("Jobs completed / scheduled", f"{cur['completed']} / {cur['scheduled']}"
             + arrow(cur["completed"], prev["completed"]), f"{prev['completed']} / {prev['scheduled']}"),
            ("Crew hours logged", f"{cur['hours']:.1f}" + arrow(cur["hours"], prev["hours"]), f"{prev['hours']:.1f}"),
            ("…of those, on invoiced jobs", f"{cur['billed_hours']:.1f}", f"{prev['billed_hours']:.1f}"),
            ("Quotes won (last 30 days)", f"{win} — {cur['quotes_won']} won, {cur['quotes_lost']} lost, "
                                          f"{cur['quotes_open']} open", ""),
        ]
        if _app_on("service_desk"):
            rows.append(("Tickets opened / closed", f"{desk['opened']} / {desk['closed']}", ""))
            if desk["response_h"] is not None:
                rows.append(("Avg. first response", f"{desk['response_h']:.1f} h", ""))
        parts = [f"<h2>📊 Weekly Scorecard — {start.strftime('%b %d')} to {end.strftime('%b %d')}</h2>",
                 "<table border='1' cellpadding='6' style='border-collapse:collapse'>"
                 "<tr><th align='left'></th><th>Last week</th><th>Week before</th></tr>"]
        for label, now_v, prev_v in rows:
            parts.append(f"<tr><td>{_esc(label)}</td><td>{now_v}</td><td>{_esc(prev_v)}</td></tr>")
        parts.append("</table>")
        if unbilled >= 1:
            parts.append(f"<p>⚠️ {unbilled:.1f} crew hours last week were on jobs with no invoice yet — "
                         f"see 💸 Work Done, Not Invoiced.</p>")
        parts.append(_footer())
        return f"📊 Weekly Scorecard — {_money(cur['invoiced'])} invoiced, {_money(cur['collected'])} collected", \
            "\n".join(parts)
    except Exception:
        return None


def _stale_quote_rows(days: int = 14) -> list:
    conn = _db_connect()
    if conn is None:
        return []
    try:
        cut = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
        return [dict(r) for r in conn.execute(
            "SELECT quote_id, customer_name, quote_date, service_type, quote_total, created_by FROM quotes "
            "WHERE LOWER(COALESCE(status,'open')) = 'open' AND COALESCE(quote_date,'') <> '' "
            "AND substr(quote_date,1,10) <= ? ORDER BY quote_date", (cut,)).fetchall()]
    except Exception:
        return []
    finally:
        conn.close()


def _quote_html(rows: list, who: str = "") -> str:
    total = sum(float(r.get("quote_total") or 0) for r in rows)
    out = [f"<h2>📝 Quotes Waiting for an Answer{(' — ' + _esc(who)) if who else ''} ({len(rows)})</h2>",
           f"<p>{_money(total)} in quotes sent 14+ days ago with no yes or no.</p><ul>"]
    for r in rows:
        out.append("<li>" + _esc(" — ".join(str(b) for b in (
            r.get("quote_id"), r.get("customer_name") or "Customer", r.get("service_type"),
            _money(r.get("quote_total")) if r.get("quote_total") else "", f"sent {str(r.get('quote_date'))[:10]}")
            if b)) + "</li>")
    out += ["</ul><p><i>A quick call or text often wins these. Mark them Approved or Declined in the Jobs app "
            "so they stop showing here.</i></p>", _footer()]
    return "\n".join(out)


def job_quote_followup(config: dict):
    """Server: quotes sent 14+ days ago with no answer. Audience "owner" → one list to the owner;
    "senders" → each person gets the quotes they wrote (anything unmatched still goes to the owner).
    Each quote is mentioned at most once a week, so it's a nudge, not a nag."""
    try:
        if not _app_on("job_tracker"):
            return None
        rows = _stale_quote_rows()
        week = datetime.date.today().isocalendar()[:2]
        fresh = [r for r in rows if _changed_since_last(f"quote:{r['quote_id']}", f"{week[0]}-{week[1]}")]
        if not fresh:
            return None
        # ("" = "for the owner(s)" — the engine sends it to each owner by email and/or text)
        if (config or {}).get("_audience", "owner") == "owner":
            return [("", f"📝 {len(fresh)} quote(s) waiting for an answer", _quote_html(fresh))]
        team = [p for p in ((config or {}).get("_team") or []) if p.get("email")
                and str(p.get("role", "")).lower() in ("owner", "manager", "staff")]

        def sender(created_by):
            cb = str(created_by or "").strip().lower()
            for p in team:
                if cb and cb in (str(p.get("id", "")).lower(), str(p.get("name", "")).lower(),
                                 str(p.get("email", "")).lower()):
                    return p
            return None
        by_person, rest = {}, []
        for r in fresh:
            p = sender(r.get("created_by"))
            (by_person.setdefault(p["email"], (p, []))[1].append(r) if p else rest.append(r))
        out = [(email, f"📝 {len(rs)} of your quote(s) waiting for an answer", _quote_html(rs, p.get("name", "")),
                {"phone": p.get("phone", "")})
               for email, (p, rs) in by_person.items()]
        if rest:
            out.append(("", f"📝 {len(rest)} quote(s) waiting for an answer", _quote_html(rest)))
        return out or None
    except Exception:
        return None


def _tomorrow_reminders() -> list:
    """Tomorrow's open jobs with the customer's email and phone (from the Customers list)."""
    tomorrow = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
    jobs = [j for j in _jobs_on(tomorrow) if not _is_closed(j.get("status", ""))
            and j.get("service_date") == tomorrow]               # first day only — not every day of a long job
    conn = _db_connect()
    info = {}
    if conn is not None:
        try:
            for r in conn.execute("SELECT customer_id, email, phone, first_name, company_name FROM customers"):
                info[r["customer_id"]] = (str(r["email"] or "").strip(), str(r["phone"] or "").strip(),
                                          r["first_name"] or r["company_name"] or "")
        except Exception:
            pass
        finally:
            conn.close()
    out = []
    for j in jobs:
        email, phone, first = info.get(j.get("customer_id", ""), ("", "", ""))
        out.append({**j, "email": email, "phone": phone, "first": first})
    return out


def _sms_opted_out(phone: str) -> bool:
    """The customer texted STOP (same rule as the Jobs agent) — never text them."""
    if not phone:
        return False
    try:
        import sms_consent as sc
        p = sc._norm_e164(phone)
        return any(r.get("phone") == p and not r.get("consented") for r in sc.consent_list())
    except Exception:
        return False


def _when_text(j: dict) -> str:
    st, en = j.get("start_time", ""), j.get("end_time", "")
    if str(j.get("schedule_type", "")).lower() == "hard" and st:
        return f" at {st}"
    if st and en:
        return f" between {st} and {en}"
    return ""


def job_appointment_reminders(config: dict):
    """Afternoon: emails (✉) and/or texts (📱) each customer booked for tomorrow a friendly reminder (date,
    time window, address, and how to reach you), so fewer people are out or forget. Off by default — it
    writes to customers. Email/phone come from the Customers list; a customer who texted STOP is never
    texted. Each job is reminded once. You get a short list of who was reminded and who couldn't be."""
    try:
        if not _app_on("job_tracker"):
            return None
        biz = _business_info()
        bname = biz.get("name") or "Your service company"
        contact = " or ".join(x for x in (biz.get("phone"), biz.get("email")) if x)
        day = (datetime.date.today() + datetime.timedelta(days=1)).strftime("%A, %B %d")
        email_on = (config or {}).get("_email_on", True) is not False
        sms_on = bool((config or {}).get("_sms_on", False))
        out, sent, missing = [], [], []
        for j in _tomorrow_reminders():
            email = j.get("email", "") if email_on else ""
            phone = j.get("phone", "") if (sms_on and not _sms_opted_out(j.get("phone", ""))) else ""
            if not (email or phone):
                if _changed_since_last(f"appt-missing:{j.get('job_id')}", j.get("service_date", "")):
                    missing.append(j)                      # listed once; reminded later if they're added
                continue
            if not _changed_since_last(f"appt:{j.get('job_id')}", j.get("service_date", "")):
                continue                                   # already reminded for this date
            where = ", ".join(x for x in (j.get("address"), j.get("city")) if x)
            body = (f"<p>Hi {_esc(j.get('first') or 'there')},</p>"
                    f"<p>This is a reminder that <b>{_esc(bname)}</b> is scheduled for "
                    f"{_esc(j.get('service_type') or 'your service')} tomorrow, <b>{day}</b>"
                    f"{_esc(_when_text(j))}{(' at ' + _esc(where)) if where else ''}.</p>"
                    + (f"<p>If you need to reschedule, please reply to this email or contact us at "
                       f"{_esc(contact)}.</p>" if contact else
                       "<p>If you need to reschedule, please reply to this email.</p>")
                    + f"<p>Thank you,<br>{_esc(bname)}</p>")
            text = (f"Reminder from {bname}: your {j.get('service_type') or 'service'} is tomorrow, {day}"
                    f"{_when_text(j)}{(' at ' + where) if where else ''}."
                    + (f" To reschedule, reply or call {biz.get('phone')}." if biz.get("phone") else
                       " Reply to reschedule."))
            out.append((email, f"Reminder: your appointment tomorrow, {day}", body,
                        {"phone": phone, "sms": text}))
            sent.append({**j, "_by": " + ".join(x for x in (email, phone) if x)})
        if not (sent or missing):
            return None
        how = "email or text" if (email_on and sms_on) else ("mobile phone" if sms_on else "email")
        summary = [f"<h2>📨 Appointment Reminders for {day}</h2>"]
        if sent:
            summary.append(f"<p>Reminded {len(sent)} customer(s):</p><ul>" + "".join(
                f"<li>{_esc(j.get('customer', 'Customer'))} — {_esc(j.get('_by'))}</li>" for j in sent) + "</ul>")
        if missing:
            opt = " (or they opted out of texts)" if sms_on else ""
            summary.append(f"<p>⚠️ No {how} on file{opt} for {len(missing)} — "
                           f"call them:</p><ul>" + "".join(
                f"<li>{_esc(j.get('customer', 'Customer'))} ({_esc(j.get('job_id', ''))})</li>" for j in missing)
                + "</ul>")
        summary.append(_footer())
        # "" = for the owner(s): the engine sends this to each owner by email and/or text
        out.append(("", f"📨 {len(sent)} appointment reminder(s) sent for {day}", "\n".join(summary)))
        return out
    except Exception:
        return None


def job_crew_my_day(config: dict):
    """Server, early morning: each person with jobs assigned to them today gets their own list — start
    time, customer, address with a map link, the job notes, and a rain flag. Only their own jobs (the
    same rule the Jobs app uses). Nobody with no jobs today gets an email."""
    try:
        v = _viewer(config)
        if not v or not _app_on("job_tracker"):
            return None
        mine = [j for j in _todays_jobs_structured()
                if _crew_has(j.get("crew", ""), v.get("name", "")) and not _is_closed(j.get("status", ""))]
        if not mine:
            return None
        from urllib.parse import quote_plus
        wcache: dict = {}
        parts = [f"<h2>🧰 Your Day — {datetime.date.today().strftime('%A, %B %d')}</h2>",
                 f"<p>Good morning, {_esc(v.get('name', ''))}. You have {len(mine)} job"
                 f"{'s' if len(mine) != 1 else ''} today:</p><ol>"]
        for j in mine:
            addr = ", ".join(x for x in (j.get("address"), j.get("city"), j.get("state"), j.get("zip")) if x)
            town = ", ".join(x for x in (j.get("city"), j.get("state")) if x)
            if town and town not in wcache:
                wcache[town] = _weather(town)
            rain = " <b style='color:#c00'>⚠️ Rain risk</b>" if town and _rain_today(wcache[town]) else ""
            head = " — ".join(x for x in (j.get("start_time", ""), j.get("customer", "Job"),
                                          j.get("service_type", "")) if x)
            item = f"<li><b>{_esc(head)}</b>{rain}"
            if addr:
                item += (f"<br>{_esc(addr)} — <a href='https://www.google.com/maps/search/?api=1&query="
                         f"{quote_plus(addr)}'>map</a>")
            if j.get("details"):
                item += f"<br><i>{_esc(j['details'][:300])}</i>"
            parts.append(item + "</li>")
        parts += ["</ol><p><i>Clock in and out for each job in the Jobs app.</i></p>", _footer()]
        return f"🧰 Your day: {len(mine)} job(s)", "\n".join(parts)
    except Exception:
        return None


# ── Registry ─────────────────────────────────────────────────────────────────

JOB_REGISTRY: dict[str, dict] = {
    "morning_briefing": {
        "label":        "☀️ Morning Briefing",
        "description":  "Today\'s jobs with rain flags, overdue invoices, tickets & bookings, old quotes, "
                        "unread texts, mileage, due tasks",
        "fn":           job_morning_briefing,
        "default_time": "07:00",
        "default_days": "weekdays",
    },
    "overdue_invoice_alert": {
        "label":        "⚠️ Overdue Invoice Alert",
        "description":  "Silent unless invoices are 31-60, 61-90, or 90+ days overdue",
        "fn":           job_overdue_invoice_alert,
        "default_time": "08:00",
        "default_days": "daily",
    },
    "due_analysis_tasks": {
        "label":        "🧠 Due Analysis Tasks",
        "description":  "Alerts when scheduled AI analysis tasks are due or overdue",
        "fn":           job_due_analysis_tasks,
        "default_time": "08:05",
        "default_days": "daily",
    },
    "sms_reply_monitor": {
        "label":        "💬 SMS Reply Monitor",
        "description":  "Unread customer texts — emails only when a new one comes in (every 2 hours 8am–8pm)",
        "fn":           job_sms_reply_monitor,
        "default_time": "every_2h",
        "default_days": "daily",
    },
    "service_desk_watch": {
        "label":        "🎫 Service Desk & Bookings",
        "description":  "Overdue and new tickets, bookings waiting for approval — emails only when something "
                        "changed (every 2 hours 8am–8pm)",
        "fn":           job_service_desk_watch,
        "default_time": "every_2h",
        "default_days": "daily",
    },
    "weather_watch": {
        "label":        "🌤️ Weekly Weather Watch",
        "description":  "Sunday evening 7-day forecast — lists the jobs booked on each rain-risk day",
        "fn":           job_weather_watch,
        "default_time": "19:00",
        "default_days": "sunday",
    },
    "end_of_day_summary": {
        "label":        "🌙 End of Day Summary",
        "description":  "Jobs completed vs still open, jobs with no time logged, tomorrow's schedule",
        "fn":           job_end_of_day_summary,
        "default_time": "18:00",
        "default_days": "daily",
    },
    "mileage_reminders": {
        "label":        "🚗 Mileage Reminders",
        "description":  "Mileage gaps to fix, weekly review, crew reimbursements to approve/pay, odometer readings",
        "fn":           job_mileage_reminders,
        "default_time": "19:00",
        "default_days": "daily",
    },
    # ── 2026-11-02: new business alerts (no AI cost) ──
    "billing_leak": {
        "label":        "💸 Work Done, Not Invoiced",
        "description":  "Completed jobs with no invoice yet (last 60 days), with hours logged and the quoted amount",
        "fn":           job_billing_leak,
        "default_time": "08:15",
        "default_days": "weekdays",
    },
    "weekly_scorecard": {
        "label":        "📊 Weekly Scorecard",
        "description":  "Last week vs the week before: invoiced, collected, jobs completed, crew hours logged vs "
                        "billed, quote win rate, ticket response time",
        "fn":           job_weekly_scorecard,
        "default_time": "07:30",
        "default_days": "monday",
    },
    "quote_followup": {
        "label":        "📝 Quote Follow-up",
        "description":  "Quotes sent 14+ days ago with no answer — once a week per quote; to the owner, or to "
                        "whoever wrote each quote",
        "fn":           job_quote_followup,
        "default_time": "08:30",
        "default_days": "weekdays",
    },
    "appointment_reminders": {
        "label":        "📨 Customer Appointment Reminders",
        "description":  "Emails each customer booked for tomorrow a reminder (date, time, address, how to reach "
                        "you); you get the list. Writes to customers — off until you turn it on",
        "fn":           job_appointment_reminders,
        "default_time": "15:00",
        "default_days": "daily",
    },
    "crew_my_day": {
        "label":        "🧰 Crew \"My Day\"",
        "description":  "Each person gets only their own jobs for today: times, addresses with map links, notes, "
                        "rain flags. If you already email approved routes to your crew, you may not need both",
        "fn":           job_crew_my_day,
        "default_time": "06:30",
        "default_days": "weekdays",
    },
}

# ── Where each alert runs and who may get it (2026-11-02, server alerts) ─────────────────────────────
# modes: "personal" / "server". audiences (server only), widest last:
#   "owner"     → the owner(s) only (the default for every alert — David: "go only to the owner")
#   "managers"  → owner + managers
#   "team"      → everyone with an email; each person sees only what applies to them
#   "senders"   → (quote follow-up) each person gets the quotes they wrote
#   "crew"      → (my day) each person with jobs assigned to them today, their own jobs only
#   "customers" → (appointment reminders) the customers, with a summary to the owner
# delivery "self": the alert addresses its own emails (customers, quote writers) and the engine runs it
# once; otherwise the engine runs it once per recipient, as that person.
_BOTH = ("personal", "server")
_SERVER_META = {
    "morning_briefing":      {"modes": _BOTH, "audiences": ("owner", "managers", "team")},
    "overdue_invoice_alert": {"modes": _BOTH, "audiences": ("owner", "managers")},
    "due_analysis_tasks":    {"modes": ("personal",), "audiences": ("owner",)},     # no chat runner on a server
    "sms_reply_monitor":     {"modes": ("personal",), "audiences": ("owner",)},     # server: per-person in the Jobs app
    "service_desk_watch":    {"modes": _BOTH, "audiences": ("owner", "managers", "team")},
    "weather_watch":         {"modes": _BOTH, "audiences": ("owner", "managers", "team")},
    "end_of_day_summary":    {"modes": _BOTH, "audiences": ("owner", "managers", "team")},
    "mileage_reminders":     {"modes": _BOTH, "audiences": ("owner", "managers")},
    "billing_leak":          {"modes": _BOTH, "audiences": ("owner", "managers")},
    "weekly_scorecard":      {"modes": _BOTH, "audiences": ("owner", "managers")},
    "quote_followup":        {"modes": ("server",), "audiences": ("owner", "senders"), "delivery": "self"},
    "appointment_reminders": {"modes": _BOTH, "audiences": ("customers",), "delivery": "self"},
    "crew_my_day":           {"modes": ("server",), "audiences": ("crew",)},
}
for _jid, _m in _SERVER_META.items():
    JOB_REGISTRY[_jid].update(_m)
    JOB_REGISTRY[_jid].setdefault("delivery", "per_person")
    JOB_REGISTRY[_jid]["default_audience"] = _m["audiences"][0]

AUDIENCE_LABELS = {
    "owner":     "Owner only",
    "managers":  "Owner + managers",
    "team":      "Everyone (their own part)",
    "senders":   "Whoever wrote each quote",
    "crew":      "Each crew member (own jobs)",
    "customers": "Customers (summary to owner)",
}


def jobs_for_mode(server: bool | None = None) -> dict:
    """The alerts this install offers: personal or server."""
    mode = "server" if (_server_mode() if server is None else server) else "personal"
    return {jid: m for jid, m in JOB_REGISTRY.items() if mode in m.get("modes", _BOTH)}
