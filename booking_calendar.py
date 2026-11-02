"""
booking_calendar.py — the one business Google Calendar, synced through Claude, Muse or Grok
(booking-spec.md §6, Phase 5). PERSONAL INSTALLS ONLY: a server uses the Jobs app's own
schedule and every function here refuses there.

AI-Prowler has no Google code. An AI with a Google Calendar connector follows the sync prompt:
    1. read the business calendar's busy times for the next N days  → sync_busy()
    2. ask what needs writing                                        → pending()
    3. create / update / delete those events, then report back       → mark_synced()
It runs from a chat ("sync my calendar"), from a scheduled task, or from Copy sync prompt.

What's pushed is worked out fresh every time (no hooks to forget): every booking whose job is
Scheduled and still ahead gets one event; when its time or address changes the event is
updated; when it's cancelled, declined or back to waiting, the event is deleted. The last
pushed copy and the Google event id live in calendar_sync_queue (one row per job).

Safety (§6.4): when the busy picture is older than calendar_fresh_hours, booking_flow.decide()
sends every booking to an approver. A busy block that lands on a confirmed visit opens an
internal "Calendar clash" ticket once; nothing is moved automatically.
"""
from __future__ import annotations

import datetime as dt
import json

import booking_db as bdb
import booking_slots as bs
from db_access import get_connection, transaction, utcnow_iso

BUSINESS = "business"
ON_SERVER = "the server uses the Jobs app calendar only — Google Calendar isn't used there"
EVENT_PREFIX = "Job:"                 # pushed events' titles; the sync prompt skips these when reading busy times
_LIVE = ("scheduled",)                # job_status (lower case) whose visit is on the calendar
_CANCELLED = ("cancelled", "canceled", "declined", "requested", "pending approval")   # → delete the event

CalendarError = bdb.BookingError


def _check(edition: str) -> None:
    if edition == BUSINESS:
        raise CalendarError(ON_SERVER)


def is_on(settings: dict, edition: str | None) -> bool:
    return edition != BUSINESS and settings.get("calendar_sync", "off") == "ai"


def _ensure(conn) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS calendar_clashes (job_id TEXT NOT NULL, start_at TEXT NOT NULL, "
                 "end_at TEXT NOT NULL, ticket_id TEXT, created_at TEXT NOT NULL, "
                 "PRIMARY KEY (job_id, start_at, end_at))")


def _utc(s: str | None) -> dt.datetime | None:
    if not s:
        return None
    try:
        t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


# ── is the picture fresh? (§6.4) ─────────────────────────────────────────────

def age_hours(jobs_db: str) -> float | None:
    """Hours since the last busy-times sync, or None if it never ran."""
    t = _utc(bdb.last_busy_sync(jobs_db))
    if not t:
        return None
    return max(0.0, (dt.datetime.now(dt.timezone.utc) - t).total_seconds() / 3600)


def stale(jobs_db: str, settings: dict, edition: str | None = None) -> tuple:
    """(True, why) when calendar sync is on and the busy picture is too old to trust."""
    if not is_on(settings, edition) or not jobs_db:
        return False, ""
    try:
        age = age_hours(jobs_db)
    except Exception:  # noqa: BLE001 — a missing table means "never synced"
        age = None
    limit = int(settings.get("calendar_fresh_hours", 4))
    if age is None:
        return True, "the business calendar hasn't been synced yet"
    if age > limit:
        return True, f"the business calendar hasn't synced for {age:.0f} h"
    return False, ""


# ── 1. busy times in ─────────────────────────────────────────────────────────

def sync_busy(jobs_db: str, d_from: str, d_to: str, blocks: list, *, edition: str, tickets_db: str = "",
              settings: dict | None = None) -> dict:
    """Replace the cached busy times for d_from..d_to with what the AI read. Blocks for
    AI-Prowler's own events (a known event id, or a title starting "Job:") are dropped, so a
    visit never blocks itself. Opens a clash ticket for each confirmed visit a block now lands on."""
    _check(edition)
    own = _own_event_ids(jobs_db)
    keep, skipped = [], 0
    for b in blocks or []:
        if not isinstance(b, dict):
            raise CalendarError("each busy block must be an object with start and end")
        if (b.get("event_id") and str(b["event_id"]) in own) or str(b.get("title") or "").startswith(EVENT_PREFIX):
            skipped += 1
            continue
        keep.append({"start": b.get("start"), "end": b.get("end"), "all_day": bool(b.get("all_day"))})
    n = bdb.replace_busy(jobs_db, d_from, d_to, keep, edition=edition)
    clashes = find_clashes(jobs_db, d_from, d_to)
    opened = _open_clash_tickets(jobs_db, tickets_db, clashes, edition=edition) if tickets_db else []
    return {"blocks": n, "skipped_own": skipped, "clashes": clashes, "tickets": opened}


def _own_event_ids(jobs_db) -> set:
    conn = get_connection(jobs_db)
    try:
        return {r[0] for r in conn.execute("SELECT google_event_id FROM calendar_sync_queue "
                                           "WHERE google_event_id IS NOT NULL AND google_event_id != ''")}
    finally:
        conn.close()


def _visits(conn, d_from: str, d_to: str) -> list:
    """Confirmed visits with a time (window or hard start/end) between the dates."""
    out = []
    for r in conn.execute("SELECT job_id, customer_name, service_type, service_date, start_time, end_time, "
                          "original_start_time, original_end_time, job_status FROM jobs "
                          "WHERE service_date BETWEEN ? AND ?", (d_from, d_to)):
        if str(r["job_status"] or "").strip().lower() not in _LIVE:
            continue
        s = bs.hhmm(r["original_start_time"] or r["start_time"])
        e = bs.hhmm(r["original_end_time"] or r["end_time"])
        if s is None or e is None or e <= s:
            continue
        day = dt.date.fromisoformat(r["service_date"])
        start = dt.datetime.combine(day, dt.time()) + dt.timedelta(minutes=s)
        out.append({"job_id": r["job_id"], "customer": r["customer_name"] or "", "service": r["service_type"] or "",
                    "start": start, "end": start + dt.timedelta(minutes=e - s)})
    return out


def find_clashes(jobs_db: str, d_from: str, d_to: str) -> list:
    conn = get_connection(jobs_db)
    try:
        visits = _visits(conn, d_from, d_to)
        busy = [dict(b) for b in conn.execute("SELECT * FROM calendar_busy WHERE start_at <= ? AND end_at >= ?",
                                              (d_to + "T23:59", d_from))]
    finally:
        conn.close()
    out = []
    for v in visits:
        for b in busy:
            bs_, be = dt.datetime.fromisoformat(b["start_at"]), dt.datetime.fromisoformat(b["end_at"])
            if bs_ < v["end"] and be > v["start"]:
                out.append({"job_id": v["job_id"], "customer": v["customer"], "service": v["service"],
                            "visit": f"{v['start']:%a %d %b} {v['start']:%H:%M}–{v['end']:%H:%M}",
                            "busy_start": b["start_at"], "busy_end": b["end_at"], "all_day": bool(b["all_day"])})
    return out


def _busy_label(c) -> str:
    s, e = dt.datetime.fromisoformat(c["busy_start"]), dt.datetime.fromisoformat(c["busy_end"])
    if c["all_day"]:
        return f"an all-day event ({s:%a %d %b})"
    return f"a busy block ({s:%a %d %b} {s:%H:%M}–{e:%H:%M})"


def _open_clash_tickets(jobs_db, tickets_db, clashes, *, edition) -> list:
    import booking_flow
    import desk_db
    import desk_rules as rules
    opened = []
    for c in clashes:
        with transaction(jobs_db) as conn:
            _ensure(conn)
            seen = conn.execute("SELECT 1 FROM calendar_clashes WHERE job_id = ? AND start_at = ? AND end_at = ?",
                                (c["job_id"], c["busy_start"], c["busy_end"])).fetchone()
            if seen:
                continue
            conn.execute("INSERT INTO calendar_clashes (job_id, start_at, end_at, created_at) VALUES (?, ?, ?, ?)",
                         (c["job_id"], c["busy_start"], c["busy_end"], utcnow_iso()))
        try:
            t = desk_db.create_ticket(
                tickets_db, title=f"Calendar clash: {c['job_id']} vs {_busy_label(c)}", kind=rules.INTERNAL,
                actor=booking_flow.SYSTEM, edition=edition, priority="P2", source="system", job_id=c["job_id"],
                description=(f"The business calendar now has {_busy_label(c)} during {c['customer'] or 'a customer'}'s "
                             f"{c['service'] or 'visit'} ({c['visit']}, {c['job_id']}). Nothing was moved — "
                             "move the visit or the calendar event, then close this ticket."))
        except Exception:  # noqa: BLE001 — the clash is still listed in calendar_sync_status
            continue
        conn = get_connection(jobs_db)
        try:
            conn.execute("UPDATE calendar_clashes SET ticket_id = ? WHERE job_id = ? AND start_at = ? AND end_at = ?",
                         (t["ticket_id"], c["job_id"], c["busy_start"], c["busy_end"]))
        finally:
            conn.close()
        opened.append(t["ticket_id"])
    return opened


# ── 2. bookings out ──────────────────────────────────────────────────────────

def _first(name: str) -> str:
    return (str(name or "").strip().split() or [""])[0]


def _event(job: dict, svc_name: str) -> dict:
    s = bs.hhmm(job.get("original_start_time") or job.get("start_time"))
    e = bs.hhmm(job.get("original_end_time") or job.get("end_time"))
    addr = bdb.address_line({"street": job.get("street_address") or "", "city": job.get("city") or "",
                             "state": job.get("state") or "", "zip": job.get("zip") or ""})
    return {"title": f"{EVENT_PREFIX} {svc_name or 'visit'} — {_first(job.get('customer_name'))}".strip(),
            "date": job["service_date"], "start": bs.fmt(s) if s is not None else "",
            "end": bs.fmt(e) if e is not None else "", "all_day": s is None or e is None,
            "address": addr, "description": f"AI-Prowler {job['job_id']} — arrival window. Phone and details are "
                                            "in the Jobs app."}


def pending(jobs_db: str, *, edition: str, settings: dict | None = None, today: dt.date | None = None) -> list:
    """What the AI should write to the business calendar now: new / update / cancel items.
    Bookings still waiting for approval are never pushed."""
    _check(edition)
    today = today or dt.date.today()
    conn = get_connection(jobs_db)
    try:
        rows = conn.execute("SELECT j.*, r.job_id AS bk_job_id, r.status AS req_status, r.service_code "
                            "FROM booking_requests r LEFT JOIN jobs j ON j.job_id = r.job_id "
                            "WHERE r.path = 'book'").fetchall()
        synced = {r["item_id"]: dict(r) for r in conn.execute("SELECT * FROM calendar_sync_queue")}
        names = {r["service_code"]: r["name"] for r in conn.execute("SELECT service_code, name FROM service_pricing")}
    finally:
        conn.close()
    out = []
    for r in rows:
        r = dict(r)
        jid = r["bk_job_id"]
        r["job_id"] = jid
        q = synced.get(jid) or {}
        err = (q.get("error") or "") if q.get("status") == "error" else ""
        status = str(r.get("job_status") or "").strip().lower()
        ahead = not r.get("service_date") or r["service_date"] >= today.isoformat()
        if status in _LIVE and r.get("service_date") and ahead:
            ev = _event(r, names.get(r.get("service_code")) or r.get("service_type") or "")
            last = json.loads(q.get("payload_json") or "null")
            if q.get("google_event_id") and last == ev and q.get("status") == "done":
                continue
            out.append({"item": jid, "job_id": jid, "action": "update" if q.get("google_event_id") else "new",
                        "event_id": q.get("google_event_id") or "", **ev, "retry_of_error": err})
        elif q.get("google_event_id") and ahead and (status in _CANCELLED or r.get("job_status") is None):
            # cancelled, declined or back to waiting (or the job was deleted) — past visits are left alone
            out.append({"item": jid, "job_id": jid, "action": "cancel", "event_id": q["google_event_id"],
                        "retry_of_error": err})
    return out


def mark_synced(jobs_db: str, items: list, *, edition: str, runner: str = "ai") -> dict:
    """The AI reports each item: {job_id, action, event_id} on success, or {job_id, error}.
    A failed item stays pending and is offered again next sync."""
    _check(edition)
    want = {p["job_id"]: p for p in pending(jobs_db, edition=edition)}
    ok, errors, unknown = 0, 0, []
    now = utcnow_iso()
    with transaction(jobs_db) as conn:
        for it in items or []:
            if not isinstance(it, dict):
                continue
            jid = str(it.get("job_id") or it.get("item") or "")
            p = want.get(jid)
            if not p:
                unknown.append(jid)
                continue
            payload = {k: p[k] for k in ("title", "date", "start", "end", "all_day", "address", "description")
                       if k in p}
            err = str(it.get("error") or "").strip()
            if err:
                errors += 1
                conn.execute("INSERT INTO calendar_sync_queue (item_id, job_id, action, status, error, created_at, "
                             "google_event_id) VALUES (?, ?, ?, 'error', ?, ?, ?) ON CONFLICT(item_id) DO UPDATE SET "
                             "action = excluded.action, status = 'error', error = excluded.error",
                             (jid, jid, p["action"], err[:300], now, p.get("event_id") or None))
                continue
            if p["action"] == "cancel":
                conn.execute("UPDATE calendar_sync_queue SET action = 'cancel', status = 'done', error = NULL, "
                             "google_event_id = NULL, payload_json = NULL, synced_at = ? WHERE item_id = ?", (now, jid))
            else:
                ev_id = str(it.get("event_id") or p.get("event_id") or "").strip()
                if not ev_id:
                    errors += 1
                    unknown.append(f"{jid} (no event_id)")
                    continue
                conn.execute("INSERT INTO calendar_sync_queue (item_id, job_id, action, payload_json, google_event_id, "
                             "status, error, created_at, synced_at) VALUES (?, ?, ?, ?, ?, 'done', NULL, ?, ?) "
                             "ON CONFLICT(item_id) DO UPDATE SET action = excluded.action, payload_json = "
                             "excluded.payload_json, google_event_id = excluded.google_event_id, status = 'done', "
                             "error = NULL, synced_at = excluded.synced_at",
                             (jid, jid, p["action"], json.dumps(payload), ev_id, now, now))
            ok += 1
        conn.execute("INSERT INTO calendar_sync_log (ran_at, blocks, pushed, errors, runner) VALUES (?, 0, ?, ?, ?)",
                     (now, ok, errors, "push:" + str(runner)[:20]))
    return {"done": ok, "errors": errors, "unknown": unknown}


# ── status, the prompt ───────────────────────────────────────────────────────

def status(jobs_db: str, settings: dict, *, edition: str) -> dict:
    _check(edition)
    age = age_hours(jobs_db)
    st, why = stale(jobs_db, settings, edition)
    pend = pending(jobs_db, edition=edition)
    conn = get_connection(jobs_db)
    try:
        _ensure(conn)
        last_push = conn.execute("SELECT MAX(ran_at) FROM calendar_sync_log WHERE runner LIKE 'push:%'").fetchone()[0]
        errs = [dict(r) for r in conn.execute("SELECT job_id, action, error FROM calendar_sync_queue "
                                              "WHERE status = 'error' ORDER BY job_id")]
        clashes = [dict(r) for r in conn.execute("SELECT * FROM calendar_clashes ORDER BY created_at DESC LIMIT 20")]
    finally:
        conn.close()
    return {"on": is_on(settings, edition), "calendar": settings.get("calendar_name", ""),
            "last_busy_sync": bdb.last_busy_sync(jobs_db), "age_hours": None if age is None else round(age, 1),
            "stale": st, "stale_why": why, "last_push": last_push, "waiting": len(pend),
            "errors": errs, "clashes": clashes}


def status_line(st: dict) -> str:
    """One line for settings and the morning digest."""
    if not st.get("on"):
        return "Calendar sync is off."
    bits = []
    if st["age_hours"] is None:
        bits.append("never synced")
    else:
        bits.append(f"busy times synced {st['age_hours']:.0f} h ago" if st["age_hours"] >= 1 else
                    "busy times synced in the last hour")
    if st["stale"]:
        bits.append("⚠️ bookings wait for approval until it syncs")
    if st["waiting"]:
        bits.append(f"{st['waiting']} booking(s) to write to the calendar")
    if st["errors"]:
        bits.append(f"{len(st['errors'])} couldn't be written")
    return f"📅 {st['calendar'] or 'Business calendar'}: " + "; ".join(bits) + "."


def days_ahead(settings: dict) -> int:
    return int(settings.get("calendar_days") or 0) or int(settings.get("booking_horizon_days", 21))


SYNC_TASK_LABEL = "Business calendar sync"


def create_scheduled_sync(settings: dict, *, edition: str, start: str = "07:00", end: str = "19:00",
                          per_day: int = 13, today: dt.date | None = None) -> str:
    """Create (or refresh) a Task Queue task that runs the sync prompt through the user's AI
    runner — hourly 7:00–19:00 by default. Its runs need a Google Calendar connector on that AI.
    Saves nothing as learnings, reports or emails (the sync's results live in AI-Prowler)."""
    _check(edition)
    import custom_tasks_manager as ctm
    tasks = ctm.load_custom_tasks()
    prompt = sync_prompt(settings)
    old = next((t for t in tasks if t.get("label") == SYNC_TASK_LABEL), None)
    if old:
        old.update({"prompt": prompt, "updated_at": ctm._now_iso()})
        ctm.save_custom_tasks(tasks)
        return f"Updated the \"{SYNC_TASK_LABEL}\" task with the current sync prompt."
    t = ctm.create_task(SYNC_TASK_LABEL, prompt, schedule="daily",
                        first_due=(today or dt.date.today()).isoformat(), output_learnings=True,
                        daily_start_time=start, daily_end_time=end, daily_times_per_day=per_day)
    t["output_learnings"] = False         # nothing to record: the sync's results are saved in AI-Prowler
    tasks.append(t)
    if not ctm.save_custom_tasks(tasks):
        raise CalendarError("couldn't save the task list")
    return (f"Created the \"{SYNC_TASK_LABEL}\" task: {per_day} runs a day, {start}–{end}, through the Autonomous "
            "AI Task Queue. Its AI needs a Google Calendar connector (and the Task Queue's schedule switched on).")


def sync_prompt(settings: dict) -> str:
    """The short prompt any AI with a Google Calendar connector can follow (Copy sync prompt,
    the scheduled task)."""
    cal = settings.get("calendar_name") or "my business calendar"
    n = days_ahead(settings)
    return (f"Sync my AI-Prowler bookings with the Google Calendar \"{cal}\" (only that calendar). "
            f"1) Read its events from today for the next {n} days. Call calendar_sync_busy with from = today, "
            f"to = today + {n} days, and blocks = each event's start, end (local time, YYYY-MM-DDTHH:MM), "
            f"all_day and event_id — no titles or details, except leave out events whose title starts with "
            f"\"{EVENT_PREFIX}\" (those are AI-Prowler's own). "
            "2) Call calendar_pending_events. For each item: action new → create the event on that calendar "
            "with the given title, date, start, end, address (location) and description; update → change event "
            "event_id to match; cancel → delete event event_id. "
            "3) Call calendar_mark_synced with each item's job_id, action and the Google event id — or an "
            "error message for any you couldn't do. Don't change anything else on the calendar.")
