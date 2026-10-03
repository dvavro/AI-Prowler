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

def _weather(location: str) -> str:
    try:
        from ai_prowler_mcp import get_weather
        return get_weather(location=location)
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

def _todays_jobs_structured() -> list[dict]:
    """Read TODAY's rows directly from the jobs table as structured dicts
    (not the pre-formatted multi-line-per-job text _job_rows() returns),
    so callers can access each job's own City/State individually — needed
    for per-job weather cross-referencing in the Morning Briefing.

    2026-09-13 fix: this was still fully openpyxl-based, opening the old
    .xlsx Job Tracker directly — found during a system-wide openpyxl
    audit. Since that file generally no longer exists (or isn't
    maintained) once an install has moved to the SQLite-backed job store,
    this had been silently returning [] every single day, meaning the
    Morning Briefing's per-job weather feature quietly fell back to the
    generic report unconditionally — not a crash, just a real feature
    that stopped doing anything, with no visible error anywhere.

    Returns a list of dicts, each with whatever of these keys were found
    as actual columns (missing columns are simply absent, never guessed):
        customer, city, state, service_type, crew
    Empty list on any error, missing database, or no matching rows —
    callers must treat this as "couldn't determine, fall back to the
    generic report", never a hard failure. Personal-mode only, matching
    this module's own scope (see module docstring).
    """
    try:
        from ai_prowler_mcp import _resolve_job_db_path
        import sqlite3
        import datetime as _dt

        db_path = _resolve_job_db_path(None, "")
        if not db_path:
            return []

        today_iso = _dt.date.today().isoformat()
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            # R-058: multi-day jobs worked today count too, not only ones starting
            # today — and any job still open past its planned end (overrun)
            from db_write_ops import job_day_number, working_days_conn
            _wd = working_days_conn(conn)      # Settings → Working Days (default Mon–Fri)
            rows = [r for r in conn.execute(
                "SELECT customer_name, city, state, service_type, crew, service_date, end_date, "
                "job_status FROM jobs WHERE service_date = ? OR (COALESCE(service_date, '') <> '' "
                "AND service_date < ?)",
                (today_iso, today_iso),
            ).fetchall() if job_day_number(r["service_date"], r["end_date"], today_iso,
                                           status=r["job_status"] or "", days=_wd)]
        finally:
            conn.close()

        col_map = {
            "customer_name": "customer",
            "city": "city",
            "state": "state",
            "service_type": "service_type",
            "crew": "crew",
        }
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

def _pending_tasks() -> list[dict]:
    try:
        p = Path.home() / ".ai-prowler" / "pending_tasks.json"
        if not p.exists():
            return []
        return json.loads(p.read_text(encoding="utf-8")) or []
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
        name = _owner_name()
        loc  = _owner_location()
        dow  = datetime.date.today().strftime("%A, %B %d")

        parts = [f"<h2>☀️ Good morning, {name}!</h2><p><b>{dow}</b></p><hr>"]

        # Today's jobs — structured, with per-job weather by town
        jobs = _todays_jobs_structured()
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
                w = _job_weather(j)
                rain_flag = ""
                if w and any(x in w for x in ("⚠️", "rain", "Rain")):
                    rain_flag = " <b style='color:#c00'>⚠️ Rain risk</b>"
                parts.append(f"<li>{label}{rain_flag}</li>")
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
                    parts.append(f"<h3>🌤️ Weather — {loc}</h3><p>{'<br>'.join(wl)}</p>")

        # Overdue invoices
        ar = _ar_aging()
        if ar:
            od = _overdue_ar_lines(ar)   # R-067
            if od:
                parts.append("<h3>⚠️ Overdue Invoices</h3><ul>")
                for l in od:
                    parts.append(f"<li style='color:red'>{l}</li>")
                parts.append("</ul>")

        # SMS replies
        sms = _sms_replies()
        if sms and "unread" in sms.lower():
            parts.append(f"<h3>💬 Unanswered Messages</h3><pre>{sms[:500]}</pre>")

        # Due analysis tasks
        tasks = [t for t in _pending_tasks()
                 if t.get("status") == "pending"
                 and _due_date_prefix(t) <= _today()]
        if tasks:
            parts.append(f"<h3>🧠 Analysis Tasks Due ({len(tasks)})</h3><ul>")
            for t in tasks:
                parts.append(f"<li>{t.get('label','?')}</li>")
            parts.append("</ul><p><i>Open Claude and press Ctrl+V to run them.</i></p>")

        parts.append(_footer())
        return f"☀️ Morning Briefing — {dow}", "\n".join(parts)
    except Exception:
        return "⚠️ Morning Briefing Error", f"<pre>{traceback.format_exc()}</pre>"


def job_overdue_invoice_alert(config: dict):
    """Daily: silent unless invoices are 31+ days overdue."""
    try:
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
                  "<p><i>Consider sending payment reminders via Claude + Square.</i></p>",
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
                  "<p><b>Open Claude and press Ctrl+V to run all pending tasks.</b></p>",
                  _footer()]
        return f"🧠 {len(due)} Task(s) Due — {_today()}", "\n".join(parts)
    except Exception:
        return None


def job_sms_reply_monitor(config: dict):
    """Every N hours: alert on unanswered customer messages."""
    try:
        sms = _sms_replies()
        if not sms or "unread" not in sms.lower():
            return None
        parts = ["<h2>💬 Unanswered Customer Messages</h2>",
                 f"<pre>{sms[:1000]}</pre>", _footer()]
        return f"💬 Unanswered Messages — {_now_str()}", "\n".join(parts)
    except Exception:
        return None


def job_weather_watch(config: dict):
    """Sunday: 5-day forecast.

    location now comes from Settings -> Owner Name -> Home address
    (v8.1.3), not config['location']. Returns None (no output, same as
    the existing "no weather data" case) rather than showing a report
    for a hardcoded default town when nothing is configured — silence,
    not a guess."""
    try:
        loc = _owner_location()
        if not loc:
            return None
        w = _weather(loc)
        if not w:
            return None
        parts = [f"<h2>🌤️ Weekly Weather Watch</h2>",
                 f"<p><b>{loc}</b> — 5-day forecast:</p>",
                 f"<pre>{w[:1500]}</pre>",
                 "<p><i>Check your job schedule for outdoor jobs on rainy days.</i></p>",
                 _footer()]
        return f"🌤️ Weather Watch — Week of {_today()}", "\n".join(parts)
    except Exception:
        return None


def job_end_of_day_summary(config: dict):
    """Evening: jobs completed vs scheduled today."""
    try:
        rows  = _job_rows()
        today = [r for r in rows if _today() in r]
        done  = [r for r in today if any(
            w in r.lower() for w in ["complete", "done", "paid", "invoiced"])]
        open_ = [r for r in today if r not in done]

        parts = [f"<h2>🌙 End of Day — {_today()}</h2>"]
        if done:
            parts += [f"<h3>✅ Completed ({len(done)})</h3><ul>"]
            for r in done:
                parts.append(f"<li>{r}</li>")
            parts.append("</ul>")
        if open_:
            parts += [f"<h3>⏳ Still Open ({len(open_)})</h3><ul>"]
            for r in open_:
                parts.append(f"<li>{r}</li>")
            parts += ["</ul>",
                      "<p><i>Don\'t forget to log time entries and mark jobs complete.</i></p>"]
        if not today:
            parts.append("<p>No jobs scheduled today.</p>")
        parts.append(_footer())
        return f"🌙 End of Day — {_today()}", "\n".join(parts)
    except Exception:
        return None


# ── Registry ─────────────────────────────────────────────────────────────────

JOB_REGISTRY: dict[str, dict] = {
    "morning_briefing": {
        "label":        "☀️ Morning Briefing",
        "description":  "Today\'s jobs, weather, overdue invoices, unanswered SMS, due tasks",
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
        "description":  "Alerts on unanswered customer messages (runs every 2 hours 8am–8pm)",
        "fn":           job_sms_reply_monitor,
        "default_time": "every_2h",
        "default_days": "daily",
    },
    "weather_watch": {
        "label":        "🌤️ Weekly Weather Watch",
        "description":  "Sunday evening 5-day forecast — flag rain days with outdoor jobs",
        "fn":           job_weather_watch,
        "default_time": "19:00",
        "default_days": "sunday",
    },
    "end_of_day_summary": {
        "label":        "🌙 End of Day Summary",
        "description":  "Jobs completed vs scheduled today, missing time entries",
        "fn":           job_end_of_day_summary,
        "default_time": "18:00",
        "default_days": "daily",
    },
}
