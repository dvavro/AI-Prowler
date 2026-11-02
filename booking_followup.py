"""
booking_followup.py — after a booking is made (booking-spec.md §9.4, §13.4; Phase 6):

  Waitlist  A customer with a booking can ask "tell me if something earlier opens" on their
            request page. When an earlier window opens (a cancellation, a moved or declined
            booking, an extra opening, a calendar event removed in sync) the first waiting
            customer for that service is offered it: the window is held for them for
            booking_waitlist_hold_hours and they're told. Taking it goes through approval
            (booking_waitlist_approval, or the approval setting when that's off). Not taken in
            time → it passes to the next person. The owner still decides.

  Reminders The day before a confirmed visit (at booking_reminder_hour), and optionally the
            morning of it, by booking_reminders = email | text | both (text falls back to
            email when texting isn't set up). Each reminder goes once per visit time — a moved
            visit is reminded again.

Both are run by desk_scheduler's tick. Nothing here takes money or shows other customers.
"""
from __future__ import annotations

import datetime as dt
import json
import secrets

import booking_db as bdb
import booking_flow as bf
from db_access import get_connection, transaction, utcnow_iso

BookingError = bdb.BookingError
_WAIT_COLS = (("job_id", "TEXT"), ("ticket_id", "TEXT"), ("offered_key", "TEXT"), ("offered_until", "TEXT"),
              ("passed_json", "TEXT"))
_OPEN = ("pending", "suggested", "scheduled", "reschedule")


def _ensure(conn) -> None:
    have = {r[1] for r in conn.execute("PRAGMA table_info(booking_waitlist)")}
    for col, typ in _WAIT_COLS:
        if col not in have:
            conn.execute(f"ALTER TABLE booking_waitlist ADD COLUMN {col} {typ}")
    conn.execute("CREATE TABLE IF NOT EXISTS booking_reminders (job_id TEXT NOT NULL, kind TEXT NOT NULL, "
                 "visit_key TEXT NOT NULL, sent_at TEXT NOT NULL, channels TEXT, "
                 "PRIMARY KEY (job_id, kind, visit_key))")


def _iso(t: dt.datetime) -> str:
    return t.isoformat(timespec="seconds")


def _current_key(b: dict) -> str:
    st = b["req"]["status"]
    if st in ("scheduled", "reschedule"):
        return b["scheduled_key"]
    return b["held_key"] or (b["suggested"] or {}).get("key", "")


# ── the waitlist ─────────────────────────────────────────────────────────────

def entry_for(jobs_db: str, job_id: str) -> dict | None:
    with transaction(jobs_db) as conn:
        _ensure(conn)
        r = conn.execute("SELECT * FROM booking_waitlist WHERE job_id = ? AND status IN ('waiting', 'offered') "
                         "ORDER BY created_at DESC LIMIT 1", (job_id,)).fetchone()
    return dict(r) if r else None


def join(jobs_db: str, job_id: str, *, settings: dict, now=None) -> dict:
    """The customer asks to hear about an earlier time for this booking."""
    if not settings.get("booking_waitlist"):
        raise BookingError("the waitlist isn't on")
    b = bf.get(jobs_db, job_id)
    if b["req"]["status"] not in _OPEN or not _current_key(b):
        raise BookingError("only a booking with a time can wait for an earlier one")
    old = entry_for(jobs_db, job_id)
    if old:
        return old
    j = b["job"]
    wid = "WL-" + secrets.token_hex(4).upper()
    with transaction(jobs_db) as conn:
        _ensure(conn)
        conn.execute("INSERT INTO booking_waitlist (wait_id, customer_id, service_code, zip, earliest_date, status, "
                     "created_at, job_id, ticket_id, passed_json) VALUES (?, ?, ?, ?, ?, 'waiting', ?, ?, ?, '[]')",
                     (wid, j.get("customer_id"), b["req"]["service_code"], j.get("zip") or "",
                      _current_key(b)[:10], utcnow_iso(), job_id, b["req"].get("ticket_id")))
    return entry_for(jobs_db, job_id)


def leave(jobs_db: str, job_id: str) -> bool:
    with transaction(jobs_db) as conn:
        _ensure(conn)
        rows = conn.execute("SELECT offered_hold_id FROM booking_waitlist WHERE job_id = ? AND status IN "
                            "('waiting', 'offered')", (job_id,)).fetchall()
        for r in rows:
            if r["offered_hold_id"]:
                conn.execute("DELETE FROM booking_holds WHERE hold_id = ?", (r["offered_hold_id"],))
        n = conn.execute("UPDATE booking_waitlist SET status = 'expired' WHERE job_id = ? AND status IN "
                         "('waiting', 'offered')", (job_id,)).rowcount
    return n > 0


def view(jobs_db: str, job_id: str, settings: dict, *, now=None) -> dict:
    """What the request page shows: can join, waiting, or an offer to take."""
    now = bf._now(now)
    e = entry_for(jobs_db, job_id)
    if not e:
        return {"on": bool(settings.get("booking_waitlist")), "waiting": False, "offer": "", "offer_until": ""}
    offer = e["status"] == "offered" and (e.get("offered_until") or "") > _iso(now)
    return {"on": True, "waiting": True, "offer": bf.label_of(e["offered_key"]) if offer else "",
            "offer_key": e["offered_key"] if offer else "", "offer_until": e["offered_until"] if offer else ""}


def sweep_waitlist(jobs_db: str, tickets_db: str, settings: dict, *, edition: str, now=None) -> dict:
    """Pass on lapsed offers, close entries whose booking ended, then offer each waiting
    customer (first come, first served) the earliest open window before their visit."""
    now = bf._now(now)
    out = {"offered": [], "passed": [], "closed": []}
    if not settings.get("booking_waitlist"):
        return out
    with transaction(jobs_db) as conn:
        _ensure(conn)
        for r in conn.execute("SELECT * FROM booking_waitlist WHERE status = 'offered' AND offered_until <= ?",
                              (_iso(now),)).fetchall():
            passed = json.loads(r["passed_json"] or "[]") + [r["offered_key"]]
            if r["offered_hold_id"]:
                conn.execute("DELETE FROM booking_holds WHERE hold_id = ?", (r["offered_hold_id"],))
            conn.execute("UPDATE booking_waitlist SET status = 'waiting', offered_hold_id = NULL, offered_key = NULL, "
                         "offered_until = NULL, passed_json = ? WHERE wait_id = ?", (json.dumps(passed), r["wait_id"]))
            out["passed"].append({"job_id": r["job_id"], "key": r["offered_key"]})
        waiting = [dict(r) for r in conn.execute("SELECT * FROM booking_waitlist WHERE status = 'waiting' "
                                                 "ORDER BY created_at")]
    agent = agent_mode(settings)
    taken = set()
    for e in waiting:
        try:
            b = bf.get(jobs_db, e["job_id"])
        except BookingError:
            b = None
        cur = _current_key(b) if b else ""
        if not b or b["req"]["status"] not in _OPEN or not cur or cur[:10] <= now.date().isoformat():
            _close(jobs_db, e["wait_id"])
            out["closed"].append(e["job_id"])
            continue
        if agent and _agent_busy(tickets_db, e["job_id"]):
            continue                                   # the agent is already deciding on an opening for them
        passed = set(json.loads(e.get("passed_json") or "[]"))
        try:
            wins = bf.windows(jobs_db, settings, b["req"]["service_code"] or "", edition, now=now)
        except BookingError:
            continue
        pick = next((w for w in wins if w["key"][:10] < cur[:10] and w["key"] not in passed and w["key"] not in taken),
                    None)
        if not pick:
            continue
        taken.add(pick["key"])
        if agent:
            # booking-agent-spec §4 (David's decision 4): Keep on track decides — Suggest waits for
            # the owner in 🤖 Agent, Auto offers at once. The key is marked considered so the next
            # sweep moves on if the agent passes on it.
            import desk_agent
            if desk_agent.enqueue(tickets_db, desk_agent.BOOKING, e["job_id"], "track", f"waitlist:{pick['key']}",
                                  version=f"waitlist|{e['wait_id']}|{pick['key']}", settings=settings):
                passed.add(pick["key"])
                conn = get_connection(jobs_db)
                try:
                    conn.execute("UPDATE booking_waitlist SET passed_json = ? WHERE wait_id = ?",
                                 (json.dumps(sorted(passed)), e["wait_id"]))
                finally:
                    conn.close()
                out.setdefault("queued", []).append({"job_id": e["job_id"], "key": pick["key"]})
            continue
        if offer_opening(jobs_db, tickets_db, e["job_id"], pick["key"], settings=settings, edition=edition, now=now):
            out["offered"].append({"job_id": e["job_id"], "key": pick["key"], "label": bf.label_of(pick["key"])})
    return out


def agent_mode(settings: dict) -> str:
    """'' when the waitlist offers by itself (agent off, or Keep on track off), else the
    Keep on track mode (suggest / auto / practice) that decides each offer."""
    try:
        import desk_agent_settings as das
        if not (settings.get("agent_enabled") and settings.get("agent_bk_enabled")):
            return ""
        mode = das.bk_stage_mode(settings, "track")
    except Exception:  # noqa: BLE001
        return ""
    return mode if mode in ("suggest", "auto", "practice") else ""


def _agent_busy(tickets_db: str, job_id: str) -> bool:
    try:
        import desk_agent
        desk_agent.ensure_schema(tickets_db)
        conn = get_connection(tickets_db)
        try:
            return bool(conn.execute(
                "SELECT 1 FROM agent_queue WHERE kind = 'booking' AND ref = ? AND stage = 'track' AND "
                "reason LIKE 'waitlist:%' AND status IN ('waiting', 'claimed') UNION ALL "
                "SELECT 1 FROM agent_proposals WHERE kind = 'booking' AND ref = ? AND action = 'bk_offer_opening' "
                "AND status = 'pending'", (job_id, job_id)).fetchone())
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        return False


def offer_opening(jobs_db: str, tickets_db: str, job_id: str, key: str, *, settings: dict, edition: str,
                  now=None) -> dict | None:
    """Hold `key` for this waitlisted booking for booking_waitlist_hold_hours and tell the
    customer. None when it isn't open any more or they aren't waiting."""
    now = bf._now(now)
    e = entry_for(jobs_db, job_id)
    if not e or e["status"] != "waiting":
        return None
    b = bf.get(jobs_db, job_id)
    cur = _current_key(b)
    if not cur or key[:10] >= cur[:10]:
        return None
    hours = int(settings.get("booking_waitlist_hold_hours", 2))
    h = bf._hold(jobs_db, settings, b["req"]["service_code"], key, kind="waitlist", minutes=hours * 60,
                 edition=edition, now=now, job_id=job_id)
    if not h:
        return None
    until = _iso(now + dt.timedelta(hours=hours))
    conn = get_connection(jobs_db)
    try:
        conn.execute("UPDATE booking_waitlist SET status = 'offered', offered_hold_id = ?, offered_key = ?, "
                     "offered_until = ? WHERE wait_id = ?", (h["hold_id"], key, until, e["wait_id"]))
    finally:
        conn.close()
    bf._tell(tickets_db, b["req"].get("ticket_id"),
             f"Good news — an earlier time opened: {bf.label_of(key)} (arrival window). It's held for you "
             f"for {hours} hour{'s' if hours != 1 else ''} — open your request page and tap \"Take it\" if you'd "
             "like it. Your current visit stays as it is otherwise.", edition)
    return {"job_id": job_id, "key": key, "label": bf.label_of(key), "until": until}


def _close(jobs_db, wait_id) -> None:
    with transaction(jobs_db) as conn:
        r = conn.execute("SELECT offered_hold_id FROM booking_waitlist WHERE wait_id = ?", (wait_id,)).fetchone()
        if r and r["offered_hold_id"]:
            conn.execute("DELETE FROM booking_holds WHERE hold_id = ?", (r["offered_hold_id"],))
        conn.execute("UPDATE booking_waitlist SET status = 'expired' WHERE wait_id = ?", (wait_id,))


def take(jobs_db: str, tickets_db: str, job_id: str, *, settings: dict, edition: str, now=None) -> dict:
    """The customer takes the offered opening. It replaces the time they're waiting on (a
    pending booking) or becomes a reschedule of their visit; then the usual approval decides."""
    now = bf._now(now)
    e = entry_for(jobs_db, job_id)
    if not e or e["status"] != "offered" or (e.get("offered_until") or "") <= _iso(now):
        raise BookingError("that opening isn't held for you any more")
    hold = bdb.get_hold(jobs_db, e["offered_hold_id"]) if e.get("offered_hold_id") else None
    if not hold:
        raise BookingError("that opening isn't held for you any more")
    b = bf.get(jobs_db, job_id)
    key, st = e["offered_key"], b["req"]["status"]
    release = _iso(now + dt.timedelta(hours=int(settings.get("booking_release_hours", 72))))
    with transaction(jobs_db) as conn:
        conn.execute("DELETE FROM booking_holds WHERE job_id = ? AND kind IN ('pending', 'suggested') "
                     "AND hold_id != ?", (job_id, hold["hold_id"]))
        conn.execute("UPDATE booking_holds SET kind = 'pending', expires_at = ? WHERE hold_id = ?",
                     (release, hold["hold_id"]))
        if st in ("scheduled", "reschedule"):
            conn.execute("UPDATE booking_requests SET status = 'reschedule', suggested_json = NULL, reminded_at = NULL, "
                         "choices_json = ? WHERE job_id = ?",
                         (json.dumps({**b["choices"], "reschedule_to": key, "reschedule_label": bf.label_of(key),
                                      "from_waitlist": True}), job_id))
        else:
            conn.execute("UPDATE jobs SET job_status = 'Pending Approval', last_edited_by = 'customer', "
                         "last_edited_at = ?, version = version + 1 WHERE job_id = ?", (utcnow_iso(), job_id))
            conn.execute("UPDATE booking_requests SET status = 'pending', suggested_json = NULL, reminded_at = NULL, "
                         "choices_json = ? WHERE job_id = ?",
                         (json.dumps({**b["choices"], "first": key, "first_label": bf.label_of(key), "backups": [],
                                      "from_waitlist": True}), job_id))
        conn.execute("UPDATE booking_waitlist SET status = 'booked' WHERE wait_id = ?", (e["wait_id"],))
    bf._tell(tickets_db, b["req"].get("ticket_id"),
             f"The customer took an earlier opening from the waitlist: {bf.label_of(key)}"
             + (f" (instead of {bf.label_of(b['scheduled_key'])})." if st in ("scheduled", "reschedule") else "."),
             edition, public=False)
    ok, why, decision = bf.decide(jobs_db, settings, job_id, key, kind="waitlist", now=now, edition=edition)
    if ok:
        return bf.approve(jobs_db, tickets_db, job_id, actor=bf.SYSTEM, edition=edition, settings=settings,
                          window_key=key, now=now, system=True, decision=decision)
    return {"ok": True, "job_id": job_id, "status": "reschedule" if st in ("scheduled", "reschedule") else "pending",
            "label": bf.label_of(key)}


# ── reminders ────────────────────────────────────────────────────────────────

def _reminder_text(kind, label, service, address, business) -> tuple:
    who = business or "us"
    if kind == "morning":
        return (f"Today: your {service or 'visit'}", f"Reminder: {who} is coming today, {label} (arrival window)"
                + (f" at {address}" if address else "") + ".")
    return (f"Tomorrow: your {service or 'visit'}",
            f"Reminder: your {service or 'visit'} with {who} is tomorrow, {label} (that's the window we'll arrive in)"
            + (f", at {address}" if address else "") + ". Need to change it? Reply to this message or open your "
            "request page.")


def due_reminders(jobs_db: str, settings: dict, *, now=None) -> list:
    """Confirmed visits whose reminder is due now and hasn't gone for this visit time."""
    now = bf._now(now)
    mode = settings.get("booking_reminders", "email")
    if mode == "off":
        return []
    kinds = []
    if now.hour >= int(settings.get("booking_reminder_hour", 17)):
        kinds.append(("day_before", (now.date() + dt.timedelta(days=1)).isoformat()))
    if settings.get("booking_reminder_morning") and 6 <= now.hour < 12:
        kinds.append(("morning", now.date().isoformat()))
    out = []
    with transaction(jobs_db) as conn:
        _ensure(conn)
        for kind, day in kinds:
            for r in conn.execute("SELECT r.job_id, r.ticket_id, j.* FROM booking_requests r JOIN jobs j ON "
                                  "j.job_id = r.job_id WHERE r.status IN ('scheduled', 'reschedule') AND "
                                  "j.service_date = ? AND LOWER(j.job_status) = 'scheduled'", (day,)).fetchall():
                r = dict(r)
                key = bf._scheduled_key(r)
                if kind == "morning" and key[11:16] and key[11:16] < f"{now.hour:02d}:00":
                    continue                        # the window has started — too late for "today"
                if conn.execute("SELECT 1 FROM booking_reminders WHERE job_id = ? AND kind = ? AND visit_key = ?",
                                (r["job_id"], kind, key)).fetchone():
                    continue
                out.append({"job_id": r["job_id"], "ticket_id": r["ticket_id"], "kind": kind, "key": key,
                            "label": bf.label_of(key), "service": r.get("service_type") or "",
                            "address": ", ".join(x for x in (r.get("street_address"), r.get("city")) if x)})
    return out


def channels_for(mode: str, have: dict) -> list:
    """booking_reminders → the channels to use now. Text falls back to email."""
    want = {"email": ["email"], "text": ["sms"], "both": ["email", "sms"]}.get(mode, [])
    use = [c for c in want if have.get(c)]
    if "sms" in want and not have.get("sms") and have.get("email") and "email" not in use:
        use.append("email")
    return use


def send_reminders(jobs_db: str, tickets_db: str, settings: dict, *, edition: str, business: str = "",
                   now=None) -> list:
    """Send what's due by the chosen channel(s), straight to the customer on the booking's
    ticket. Recorded (once per visit time) even when there's no way to reach them, so it
    isn't retried every tick; the ticket gets an internal note either way."""
    import desk_db
    import desk_portal
    sent = []
    have = desk_portal.channels()
    for r in due_reminders(jobs_db, settings, now=now):
        use = channels_for(settings.get("booking_reminders", "email"), have)
        subject, text = _reminder_text(r["kind"], r["label"], r["service"], r["address"], business)
        went = []
        contact = {}
        if tickets_db and r["ticket_id"]:
            try:
                t = desk_db.get_ticket(tickets_db, r["ticket_id"], actor=None, edition=edition) or {}
                contact = desk_db.get_contact(tickets_db, t.get("contact_id")) or {} if t.get("contact_id") else {}
            except Exception:  # noqa: BLE001
                contact = {}
        for ch in use:
            to = contact.get("phone") if ch == "sms" else contact.get("email")
            if to and desk_portal._send(ch, to, subject, text):
                went.append(ch)
        conn = get_connection(jobs_db)
        try:
            conn.execute("INSERT OR IGNORE INTO booking_reminders (job_id, kind, visit_key, sent_at, channels) "
                         "VALUES (?, ?, ?, ?, ?)", (r["job_id"], r["kind"], r["key"], utcnow_iso(), ",".join(went)))
        finally:
            conn.close()
        bf._tell(tickets_db, r["ticket_id"],
                 (f"{'Day-before' if r['kind'] == 'day_before' else 'Morning'} reminder sent by "
                  f"{' and '.join('text' if c == 'sms' else c for c in went)}." if went else
                  "The visit reminder couldn't be sent (no email / mobile on file, or no way to send set up)."),
                 edition, public=False)
        sent.append({**r, "channels": went})
    return sent
