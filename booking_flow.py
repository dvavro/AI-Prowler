"""
booking_flow.py — a booking's life (booking-spec.md §3, §7, §7a; Phase 2).

    customer picks a window ─► checkout hold (10 min, while they enter the code)
          │ code OK
          ▼
    job "Pending Approval" (NO date) + window held ─► approver: ✅ Approve  → "Scheduled" (date set)
          │                                                    ↔ Suggest  → "Suggested" (new window held)
          │                                                    ✖ Decline  → "Declined" / "Requested"
          ▼
    customer on a suggestion: Accept → Scheduled · Pick another → back to approval · Call me
    customer on a Scheduled visit: Reschedule (back to approval; the old visit stays until a
    decision) · Cancel (until booking_change_hours before)

Approval is configurable (David 2026-10-30, setting booking_approval):
    approve_all  every booking waits for an approver (default)
    preapprove   instant booking — windows that meet the rules are booked at once
    auto         every open window is confirmed at once
Who approves: the owner; on a server also managers when booking_approve_managers is on
(default on). Nobody else — the agent and customers never approve.

Only a Scheduled job ever has a service_date, so routing / the Calendar / mileage never see
a booking that's still waiting. Times are local and naive throughout (like booking_db).
"""
from __future__ import annotations

import datetime as dt
import json

import booking_db as bdb
import booking_slots as bs
from db_access import get_connection, transaction, utcnow_iso

APPROVE_ALL, PREAPPROVE, AUTO = "approve_all", "preapprove", "auto"
SYSTEM = {"id": "system", "role": "owner"}
OPEN = ("pending", "suggested", "reschedule")          # booking_requests still waiting on someone


BookingError = bdb.BookingError          # one error type for the whole booking layer
clock = None                             # tests: a function returning a fixed local datetime


def _now(now=None) -> dt.datetime:
    n = now or (clock() if clock else dt.datetime.now())
    return n.replace(tzinfo=None) if n.tzinfo else n


# ── who, which crews ─────────────────────────────────────────────────────────

def can_approve(actor, edition: str, settings: dict) -> bool:
    """Owner always; on a server, managers too when booking_approve_managers is on."""
    import desk_rules as rules
    a = rules.normalize_actor(actor)
    if a["role"] == rules.OWNER:
        return True
    return (edition == rules.BUSINESS and a["role"] == rules.MANAGER
            and bool(settings.get("booking_approve_managers", True)))


def crews_for(jobs_db: str, edition: str) -> list:
    """Personal: one crew (the owner). Server: the Jobs app's field-crew users; if there are
    none yet, one shared crew so booking still works."""
    if edition != "business":
        return [bs.Crew("owner")]
    try:
        conn = get_connection(jobs_db)
        try:
            ids = [r["id"] for r in conn.execute(
                "SELECT id FROM users WHERE LOWER(REPLACE(COALESCE(role, ''), ' ', '_')) IN "
                "('field_crew', 'crew', 'technician') ORDER BY id")]
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        ids = []
    return [bs.Crew(i) for i in ids] or [bs.Crew("team")]


def _is_user(conn, crew) -> bool:
    return bool(crew) and conn.execute("SELECT 1 FROM users WHERE id = ?", (crew,)).fetchone() is not None


# ── labels ───────────────────────────────────────────────────────────────────

def key_of(hold: dict) -> str:
    return f"{hold['hold_date']}T{hold['start_time']}-{hold['end_time']}"


def label_of(key: str) -> str:
    """'2026-11-03T07:00-09:00' -> 'Tue 03 Nov, 7–9'."""
    try:
        d = dt.date.fromisoformat(key[:10])
        s, e = key[11:].split("-")
        return bs.Window(d, bs.hhmm(s), bs.hhmm(e), "", 0).label()
    except (ValueError, TypeError, AttributeError):
        return key


def _parse_key(key: str) -> tuple:
    d = dt.date.fromisoformat(key[:10])
    s, e = key[11:].split("-")
    return d, s, e


# ── windows the page / the approver can pick ─────────────────────────────────

def windows(jobs_db: str, settings: dict, service_code: str, edition: str, *, now=None,
            online_only: bool = True, from_date=None, to_date=None) -> list:
    return bdb.to_json(bdb.windows_for(jobs_db, service_code, booking=settings, now=_now(now), edition=edition,
                                       crews=crews_for(jobs_db, edition), online_only=online_only,
                                       from_date=from_date, to_date=to_date))


def _hold(jobs_db, settings, service_code, key, *, kind, minutes, edition, now, job_id="", who="",
          online_only=True):
    return bdb.hold_window(jobs_db, service_code, key, kind=kind, minutes_to_live=minutes, contact_hash=who,
                           job_id=job_id, booking=settings, now=_now(now), edition=edition,
                           crews=crews_for(jobs_db, edition), online_only=online_only)


def hold_for_checkout(jobs_db: str, settings: dict, service_code: str, window_key: str, *, who: str,
                      edition: str, now=None) -> dict:
    """Hold the customer's first choice for 10 minutes while they enter the code. One
    checkout hold per visitor: picking again releases their previous one."""
    now = _now(now)
    if who:
        conn = get_connection(jobs_db)
        try:
            conn.execute("DELETE FROM booking_holds WHERE kind = 'checkout' AND contact_hash = ?", (who,))
        finally:
            conn.close()
    h = _hold(jobs_db, settings, service_code, window_key, kind="checkout", minutes=bdb.CHECKOUT_MINUTES,
              edition=edition, now=now, who=who)
    if not h:
        raise BookingError("sorry — that time was just taken. Please pick another.")
    return {"hold_id": h["hold_id"], "key": key_of(h), "label": label_of(key_of(h)), "expires_at": h["expires_at"]}


def ensure_hold(jobs_db: str, settings: dict, service_code: str, hold_id: str, window_key: str, *,
                edition: str, now=None) -> dict:
    """Before the code is used up: the checkout hold still stands, or the same window is
    held again. Raises when the window has gone (the customer picks another; their code
    still works because it hasn't been used)."""
    now = _now(now)
    h = bdb.get_hold(jobs_db, hold_id) if hold_id else None
    if h and h["kind"] == "checkout" and h["expires_at"] > now.isoformat(timespec="seconds") \
            and h["service_code"] == service_code and (not window_key or key_of(h) == window_key):
        return h
    if h:
        bdb.release_hold(jobs_db, h["hold_id"])
    key = window_key or (key_of(h) if h else "")
    if not key:
        raise BookingError("pick a time first")
    h = _hold(jobs_db, settings, service_code, key, kind="checkout", minutes=bdb.CHECKOUT_MINUTES,
              edition=edition, now=now)
    if not h:
        raise BookingError("sorry — that time was just taken. Please pick another.")
    return h


# ── after the code: the booking itself ───────────────────────────────────────

def create_pending(jobs_db: str, settings: dict, hold: dict, *, backups=(), customer_id: str,
                   customer_name: str, service_name: str, notes: str = "", street: str = "", city: str = "",
                   state: str = "", zip_code: str = "", edition: str, now=None, made_by: str = "",
                   check_backups: bool = True) -> dict:
    """The job (Pending Approval, no date) + its booking_requests record; the checkout hold
    becomes the booking's pending hold. Returns {"job_id", "label", "backups"}.
    made_by: the staff member booking for the customer (Phase 3); '' = the website."""
    from db_write_ops import generate_next_id
    now = _now(now)
    first = key_of(hold)
    svc = bdb.service(jobs_db, hold["service_code"])
    allowed = int(settings.get("booking_backups", 2))
    picked = []
    if backups:
        open_now = {w["key"] for w in windows(jobs_db, settings, hold["service_code"], edition, now=now,
                                              online_only=not made_by)}
        for k in backups:
            if k and k != first and (k in open_now or not check_backups) and k not in picked \
                    and len(picked) < allowed:
                picked.append(k)
    choices = {"first": first, "first_label": label_of(first),
               "backups": [{"key": k, "label": label_of(k)} for k in picked]}
    by = (made_by or "").strip()[:80]
    details = "\n".join(x for x in (notes.strip(), f"Wants: {label_of(first)}",
                                    ("Or: " + "; ".join(label_of(k) for k in picked)) if picked else "",
                                    f"Booked by {by} for the customer." if by else
                                    "Booked on the website — waiting for approval.") if x)
    with transaction(jobs_db) as conn:
        jid = generate_next_id(conn, "jobs", "job_id", "JOB", 4)
        stamp = utcnow_iso()
        conn.execute("INSERT INTO jobs (job_id, customer_id, customer_name, customer_type, street_address, city, "
                     "state, zip, service_type, service_details, est_duration, est_duration_unit, job_status, "
                     "schedule_type, created_by, last_edited_by, last_edited_at) "
                     "VALUES (?, ?, ?, 'Residential', ?, ?, ?, ?, ?, ?, ?, 'min', 'Pending Approval', 'Soft', ?, ?, ?)",
                     (jid, customer_id, customer_name or None, street or None, city or None, state or None,
                      zip_code or None, service_name or svc.code, details, svc.minutes, by or bdb.WEB_BOOKING,
                      by or bdb.WEB_BOOKING, stamp))
        conn.execute("INSERT INTO booking_requests (job_id, path, service_code, choices_json, status, created_at) "
                     "VALUES (?, 'book', ?, ?, 'pending', ?)", (jid, svc.code, json.dumps(choices), stamp))
        conn.execute("UPDATE booking_holds SET kind = 'pending', job_id = ?, contact_hash = NULL, expires_at = ? "
                     "WHERE hold_id = ?",
                     (jid, (now + dt.timedelta(hours=int(settings.get("booking_release_hours", 72))))
                      .isoformat(timespec="seconds"), hold["hold_id"]))
    return {"job_id": jid, "label": choices["first_label"], "backups": [b["label"] for b in choices["backups"]]}


def link_ticket(jobs_db: str, job_id: str, ticket_id: str) -> None:
    bdb.link_request_ticket(jobs_db, job_id, ticket_id)


def needs_approval(settings: dict, *, calendar_stale: bool = False) -> bool:
    """approve_all → yes. preapprove / auto → no, unless the business calendar picture is
    stale (personal installs, spec §6.4). The per-booking answer (with the instant-booking
    limits) is decide()."""
    return calendar_stale or settings.get("booking_approval", APPROVE_ALL) == APPROVE_ALL


# ── instant booking (Phase 4, booking-spec.md §7a.1) ─────────────────────────

PRE_APPROVED, AUTOMATIC = "pre-approved", "automatic"     # booking_requests.decision when no person decided
_NOT_YET = ("pending approval", "suggested", "requested", "declined", "cancelled", "canceled", "")


def _returning(conn, customer_id, job_id) -> bool:
    """A returning customer has another job that went ahead (anything but a booking still
    waiting, a request, or a declined / cancelled one)."""
    if not customer_id:
        return False
    for r in conn.execute("SELECT job_status FROM jobs WHERE customer_id = ? AND job_id != ?", (customer_id, job_id)):
        if str(r["job_status"] or "").strip().lower() not in _NOT_YET:
            return True
    return False


def preapproved(jobs_db: str, settings: dict, job_id: str, window_key: str, *, now=None) -> tuple:
    """(True, why) when instant booking may confirm this booking on its own: every limit the
    owner set is met — instant services, at least N days away, returning customers only,
    at most N instant bookings that day."""
    now = _now(now)
    b = get(jobs_db, job_id)
    code = b["req"]["service_code"] or ""
    only = [str(x) for x in (settings.get("booking_pre_services") or [])]
    if only and code not in only:
        return False, f"{b['job'].get('service_type') or code} isn't set for instant booking"
    try:
        day = dt.date.fromisoformat(window_key[:10])
    except (TypeError, ValueError):
        return False, "no time chosen"
    n = int(settings.get("booking_pre_min_days") or 0)
    if n and (day - now.date()).days < n:
        return False, f"it's less than {n} day{'s' if n != 1 else ''} away"
    conn = get_connection(jobs_db)
    try:
        if settings.get("booking_pre_returning") and not _returning(conn, b["job"].get("customer_id"), job_id):
            return False, "new customers wait for approval"
        cap = int(settings.get("booking_pre_per_day") or 0)
        if cap:
            done = conn.execute("SELECT COUNT(*) FROM booking_requests r JOIN jobs j ON j.job_id = r.job_id "
                                "WHERE r.decision = ? AND j.service_date = ? AND r.job_id != ?",
                                (PRE_APPROVED, day.isoformat(), job_id)).fetchone()[0]
            if done >= cap:
                return False, f"{day:%a %d %b} already has {cap} instant booking{'s' if cap != 1 else ''}"
    finally:
        conn.close()
    return True, "within the instant-booking limits"


def decide(jobs_db: str, settings: dict, job_id: str, window_key: str, *, kind: str = "new", now=None,
           edition: str | None = None) -> tuple:
    """(confirm_now, why, decision). kind: "new" (a booking or a new pick), "reschedule" or
    "waitlist" (a customer taking an offered opening)."""
    mode = settings.get("booking_approval", APPROVE_ALL)
    if mode == APPROVE_ALL:
        return False, "every booking waits for approval", ""
    import booking_calendar               # personal installs: a stale business calendar → approval (§6.4)
    stale, why = booking_calendar.stale(jobs_db, settings, edition)
    if stale:
        return False, why + " — bookings wait for approval until it does", ""
    if kind == "waitlist" and settings.get("booking_waitlist_approval", True):
        return False, "openings taken from the waitlist wait for approval", ""
    if kind == "reschedule":
        if settings.get("booking_reschedule_approval", True):
            return False, "reschedules wait for approval", ""
        return True, "reschedules into an open time are confirmed", AUTOMATIC
    if mode == AUTO:
        return True, "every open time is confirmed automatically", AUTOMATIC
    ok, why = preapproved(jobs_db, settings, job_id, window_key, now=now)
    return ok, why, PRE_APPROVED if ok else ""


def confirmed_on_their_own(jobs_db: str, since_iso: str) -> list:
    """Bookings confirmed with no person deciding since `since_iso` (UTC) — for the FYI line."""
    conn = get_connection(jobs_db)
    try:
        rows = conn.execute("SELECT r.job_id, r.ticket_id, j.customer_name, j.service_date, j.start_time, j.end_time, "
                            "j.original_start_time, j.original_end_time FROM booking_requests r "
                            "JOIN jobs j ON j.job_id = r.job_id WHERE r.decision IN (?, ?, 'agent') AND r.decided_at >= ? "
                            "ORDER BY r.decided_at", (PRE_APPROVED, AUTOMATIC, since_iso)).fetchall()
        return [{"job_id": r["job_id"], "ticket_id": r["ticket_id"], "customer": r["customer_name"] or "",
                 "label": label_of(_scheduled_key(dict(r)))} for r in rows]
    finally:
        conn.close()


# ── reading a booking ────────────────────────────────────────────────────────

def _req(conn, job_id) -> dict | None:
    r = conn.execute("SELECT * FROM booking_requests WHERE job_id = ?", (job_id,)).fetchone()
    return dict(r) if r else None


def _job(conn, job_id) -> dict:
    r = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if not r:
        raise BookingError(f"no job {job_id}")
    return dict(r)


def _holds(conn, job_id, kinds=("pending", "suggested")) -> list:
    q = ",".join("?" * len(kinds))
    return [dict(r) for r in conn.execute(f"SELECT * FROM booking_holds WHERE job_id = ? AND kind IN ({q}) "
                                          "ORDER BY created_at", (job_id, *kinds))]


def _scheduled_key(job) -> str:
    if not job.get("service_date"):
        return ""
    s = bs.hhmm(job.get("original_start_time") or job.get("start_time"))
    e = bs.hhmm(job.get("original_end_time") or job.get("end_time"))
    return f"{job['service_date']}T{bs.fmt(s)}-{bs.fmt(e)}" if s is not None and e is not None else job["service_date"]


def get(jobs_db: str, job_id: str) -> dict:
    conn = get_connection(jobs_db)
    try:
        job = _job(conn, job_id)
        req = _req(conn, job_id)
        if not req:
            raise BookingError(f"{job_id} isn't a booking")
        holds = _holds(conn, job_id)
    finally:
        conn.close()
    choices = json.loads(req.get("choices_json") or "{}")
    sugg = json.loads(req.get("suggested_json") or "null")
    held = next((h for h in holds if h["kind"] == "pending"), None)
    return {"job": job, "req": req, "choices": choices, "suggested": sugg, "holds": holds,
            "held_key": key_of(held) if held else "", "scheduled_key": _scheduled_key(job)}


# ── telling the customer (a public message on the ticket → emailed / texted) ─

def _tell(tickets_db: str, ticket_id, text: str, edition: str, *, public: bool = True) -> None:
    if not (tickets_db and ticket_id):
        return
    try:
        import desk_db
        desk_db.add_message(tickets_db, ticket_id, text, actor=SYSTEM, edition=edition,
                            visibility="public" if public else "internal", channel="system",
                            author_kind="staff" if public else None)
    except Exception:  # noqa: BLE001 — a message failing never undoes the booking
        pass


# ── the approver's choices (§7a.4) ───────────────────────────────────────────

def _check(actor, edition, settings, system):
    if not system and not can_approve(actor, edition, settings):
        raise BookingError("only the owner" + (" or a manager" if edition == "business"
                                               and settings.get("booking_approve_managers", True) else "")
                           + " can approve, suggest or decline bookings")


def approve(jobs_db: str, tickets_db: str, job_id: str, *, actor, edition: str, settings: dict,
            window_key: str = "", crew: str | None = None, now=None, system: bool = False,
            quiet: bool = False, decision: str = "") -> dict:
    """✅ Approve the held window (or another open one — a backup, or any time the approver
    picks). The job gets its date and becomes Scheduled; the customer is told (quiet=True:
    an internal note instead — staff unticked "send the customer a confirmation")."""
    _check(actor, edition, settings, system)
    now = _now(now)
    b = get(jobs_db, job_id)
    if b["req"]["status"] not in OPEN:
        raise BookingError(f"{job_id} isn't waiting for a decision (it's {b['req']['status']})")
    sugg_hold = next((h for h in b["holds"] if h["kind"] == "suggested"), None)
    held = next((h for h in b["holds"] if h["kind"] == "pending"), None) or sugg_hold
    target = window_key or (key_of(held) if held else "")
    if not target:
        raise BookingError("pick a time to approve")
    if held and key_of(held) == target:
        use = held
    else:
        if held:
            bdb.release_hold(jobs_db, held["hold_id"])
        use = _hold(jobs_db, settings, b["req"]["service_code"], target, kind="pending", minutes=60,
                    edition=edition, now=now, job_id=job_id, online_only=False)
        if not use:
            if held:          # put the customer's hold back
                _hold(jobs_db, settings, b["req"]["service_code"], key_of(held), kind=held["kind"],
                      minutes=int(settings.get("booking_release_hours", 72)) * 60, edition=edition, now=now,
                      job_id=job_id, online_only=False)
            raise BookingError(f"{label_of(target)} isn't open any more — pick another time")
    mode = settings.get("booking_crew_mode", "approver")
    who = crew if crew is not None else (None if mode == "office" else use.get("crew"))
    d, s, e = _parse_key(target)
    with transaction(jobs_db) as conn:
        uid = who if _is_user(conn, who) else None
        conn.execute("UPDATE jobs SET service_date = ?, start_time = ?, end_time = ?, original_start_time = ?, "
                     "original_end_time = ?, job_status = 'Scheduled', schedule_type = COALESCE(schedule_type, 'Soft'), "
                     "crew_user_id = COALESCE(?, crew_user_id), last_edited_by = ?, last_edited_at = ?, "
                     "version = version + 1 WHERE job_id = ?",
                     (d.isoformat(), s, e, s, e, uid, _actor_name(actor, system), utcnow_iso(), job_id))
        conn.execute("DELETE FROM booking_holds WHERE job_id = ?", (job_id,))
        conn.execute("UPDATE booking_requests SET status = 'scheduled', decided_by = ?, decided_at = ?, "
                     "decision = ?, suggested_json = NULL WHERE job_id = ?",
                     (_actor_name(actor, system), utcnow_iso(),
                      decision or ("rescheduled" if b["req"]["status"] == "reschedule" else "approved"), job_id))
    label = label_of(target)
    moved = b["req"]["status"] == "reschedule" or (sugg_hold and sugg_hold is use)
    _tell(tickets_db, b["req"]["ticket_id"],
          (f"Your visit is now {label} (arrival window)." if b["req"]["status"] == "reschedule" else
           f"Confirmed: {label} (that's the window we'll arrive in).")
          + " You can add it to your calendar from your request page.", edition, public=not quiet)
    return {"ok": True, "job_id": job_id, "status": "scheduled", "window": target, "label": label,
            "crew": uid or who or "", "moved": bool(moved)}


def suggest(jobs_db: str, tickets_db: str, job_id: str, window_key: str, *, actor, edition: str,
            settings: dict, note: str = "", by_agent: bool = False, now=None) -> dict:
    """↔ Suggest another time: hold it for the customer (booking_suggest_hours) and ask them."""
    _check(actor, edition, settings, False)
    now = _now(now)
    b = get(jobs_db, job_id)
    status = b["req"]["status"]
    if status not in OPEN + ("scheduled",):          # Phase 4: "suggest a change" on a booked visit too
        raise BookingError(f"{job_id} isn't waiting for a decision (it's {status})")
    if status == "scheduled" and window_key == b["scheduled_key"]:
        raise BookingError("that's the time they already have")
    resched = status in ("reschedule", "scheduled") or bool((b["suggested"] or {}).get("reschedule"))
    for h in b["holds"]:
        bdb.release_hold(jobs_db, h["hold_id"])
    h = _hold(jobs_db, settings, b["req"]["service_code"], window_key, kind="suggested",
              minutes=int(settings.get("booking_suggest_hours", 48)) * 60, edition=edition, now=now,
              job_id=job_id, online_only=False)
    if not h:
        for old in b["holds"]:          # put back what the customer had
            _hold(jobs_db, settings, b["req"]["service_code"], key_of(old), kind=old["kind"],
                  minutes=int(settings.get("booking_release_hours", 72)) * 60, edition=edition, now=now,
                  job_id=job_id, online_only=False)
        raise BookingError(f"{label_of(window_key)} isn't open any more — pick another time")
    label = label_of(window_key)
    with transaction(jobs_db) as conn:
        if not resched:
            conn.execute("UPDATE jobs SET job_status = 'Suggested', last_edited_by = ?, last_edited_at = ?, "
                         "version = version + 1 WHERE job_id = ?", (_actor_name(actor), utcnow_iso(), job_id))
        conn.execute("UPDATE booking_requests SET status = 'suggested', suggested_json = ?, decided_by = ?, "
                     "decided_at = ?, decision = 'suggested', note = ? WHERE job_id = ?",
                     (json.dumps({"key": window_key, "label": label, "reschedule": resched, "by_agent": bool(by_agent)}), _actor_name(actor),
                      utcnow_iso(), (note or "").strip()[:500] or None, job_id))
    _tell(tickets_db, b["req"]["ticket_id"],
          f"We'd like to come {label} instead (arrival window)."
          + (f" {note.strip()}" if (note or "").strip() else "")
          + (f" Your visit stays {label_of(b['scheduled_key'])} unless you accept." if status == "scheduled" else "")
          + " Open your request page to accept it, pick another time, or ask us to call you.", edition)
    return {"ok": True, "job_id": job_id, "status": "suggested", "window": window_key, "label": label}


def offer(jobs_db: str, tickets_db: str, job_id: str, window_keys: list, *, edition: str, settings: dict,
          note: str = "", by: str = "assistant", by_agent: bool = False, now=None) -> dict:
    """Offer times to a request with no date (a new service request, or a booking that was
    released / declined-keep) — booking-agent-spec §4 "Offer times". The first open time is held
    for the customer as a suggestion (booking_suggest_hours); the others are listed in the
    message. The customer Accepts, picks another or asks for a call on their request page."""
    now = _now(now)
    b = get(jobs_db, job_id)
    if b["req"]["status"] != "requested":
        raise BookingError(f"{job_id} isn't a request waiting for a time (it's {b['req']['status']})")
    code = b["req"]["service_code"] or ""
    if not code:
        raise BookingError("this request has no service from the list — offer times by phone")
    keys = [str(k) for k in (window_keys or []) if k][:3]
    if not keys:
        raise BookingError("pick at least one time to offer")
    h = _hold(jobs_db, settings, code, keys[0], kind="suggested",
              minutes=int(settings.get("booking_suggest_hours", 48)) * 60, edition=edition, now=now,
              job_id=job_id, online_only=False)
    if not h:
        raise BookingError(f"{label_of(keys[0])} isn't open any more — pick another time")
    label, others = label_of(keys[0]), [label_of(k) for k in keys[1:]]
    with transaction(jobs_db) as conn:
        conn.execute("UPDATE jobs SET job_status = 'Suggested', last_edited_by = ?, last_edited_at = ?, "
                     "version = version + 1 WHERE job_id = ?", (by, utcnow_iso(), job_id))
        conn.execute("UPDATE booking_requests SET path = 'book', status = 'suggested', suggested_json = ?, "
                     "decided_by = ?, decided_at = ?, decision = 'offered', note = ? WHERE job_id = ?",
                     (json.dumps({"key": keys[0], "label": label, "reschedule": False, "others": keys[1:], "by_agent": bool(by_agent)}), by,
                      utcnow_iso(), (note or "").strip()[:500] or None, job_id))
    _tell(tickets_db, b["req"]["ticket_id"],
          f"We can come {label} (arrival window)."
          + (f" Other times that work: {'; '.join(others)}." if others else "")
          + (f" {note.strip()}" if (note or "").strip() else "")
          + " Open your request page to accept it, pick another time, or ask us to call you.", edition)
    return {"ok": True, "job_id": job_id, "status": "suggested", "window": keys[0], "label": label}


def decline(jobs_db: str, tickets_db: str, job_id: str, *, actor, edition: str, settings: dict,
            message: str = "", keep_request: bool = False, now=None) -> dict:
    """✖ Decline: free the window. A declined reschedule keeps the original visit."""
    _check(actor, edition, settings, False)
    b = get(jobs_db, job_id)
    status = b["req"]["status"]
    if status not in OPEN:
        raise BookingError(f"{job_id} isn't waiting for a decision (it's {status})")
    resched = status == "reschedule" or bool((b["suggested"] or {}).get("reschedule"))
    with transaction(jobs_db) as conn:
        conn.execute("DELETE FROM booking_holds WHERE job_id = ?", (job_id,))
        if resched:
            conn.execute("UPDATE booking_requests SET status = 'scheduled', suggested_json = NULL, decided_by = ?, "
                         "decided_at = ?, decision = 'reschedule declined' WHERE job_id = ?",
                         (_actor_name(actor), utcnow_iso(), job_id))
        else:
            new = "Requested" if keep_request else "Declined"
            conn.execute("UPDATE jobs SET job_status = ?, last_edited_by = ?, last_edited_at = ?, "
                         "version = version + 1 WHERE job_id = ?", (new, _actor_name(actor), utcnow_iso(), job_id))
            conn.execute("UPDATE booking_requests SET status = ?, suggested_json = NULL, decided_by = ?, "
                         "decided_at = ?, decision = 'declined' WHERE job_id = ?",
                         (new.lower(), _actor_name(actor), utcnow_iso(), job_id))
    msg = (message or "").strip()
    if resched:
        text = (msg or "We couldn't move your visit to that time.") + \
               f" Your visit stays {label_of(b['scheduled_key'])}."
    else:
        text = msg or "Sorry — we can't book that time. We'll be in touch to find another."
    _tell(tickets_db, b["req"]["ticket_id"], text, edition)
    return {"ok": True, "job_id": job_id, "status": "scheduled" if resched else
            ("requested" if keep_request else "declined")}


def _actor_name(actor, system: bool = False) -> str:
    if system:
        return "system"
    import desk_rules as rules
    a = rules.normalize_actor(actor)
    return str(a.get("name") or a.get("id") or a["role"])


# ── the customer's choices (status page) ─────────────────────────────────────

def customer_accept(jobs_db: str, tickets_db: str, job_id: str, *, edition: str, settings: dict,
                    now=None) -> dict:
    """Accept the suggested time — confirmed at once when a person proposed it.

    F-19, 2026-11-04 (David): when the agent proposed a new visit on its own, no person has approved it. It goes back to
    pending, so Decide applies Let the agent confirm, the daily limit and the other checks; or a person approves it.
    A move of a visit already confirmed isn't new: it stays as it was."""
    b = get(jobs_db, job_id)
    if b["req"]["status"] != "suggested" or not b["suggested"]:
        raise BookingError("there's no suggested time to accept")
    if b["suggested"].get("by_agent") and not b["suggested"].get("reschedule"):
        return customer_pick(jobs_db, tickets_db, job_id, b["suggested"]["key"], edition=edition, settings=settings, now=now)
    out = approve(jobs_db, tickets_db, job_id, actor=SYSTEM, edition=edition, settings=settings,
                  window_key=b["suggested"]["key"], now=now, system=True)
    return out


def _hold_new_choice(jobs_db, settings, b, window_key, *, edition, now):
    h = _hold(jobs_db, settings, b["req"]["service_code"], window_key, kind="pending",
              minutes=int(settings.get("booking_release_hours", 72)) * 60, edition=edition, now=now,
              job_id=b["job"]["job_id"])
    if not h:
        raise BookingError("sorry — that time was just taken. Please pick another.")
    return h


def customer_pick(jobs_db: str, tickets_db: str, job_id: str, window_key: str, *, edition: str,
                  settings: dict, now=None) -> dict:
    """Pick another time instead of the suggestion — back to the approver (or confirmed at
    once when approval isn't needed)."""
    now = _now(now)
    b = get(jobs_db, job_id)
    if b["req"]["status"] not in ("suggested", "pending"):
        raise BookingError("this booking can't take a new time now")
    resched = bool((b["suggested"] or {}).get("reschedule"))
    for h in b["holds"]:
        bdb.release_hold(jobs_db, h["hold_id"])
    try:
        _hold_new_choice(jobs_db, settings, b, window_key, edition=edition, now=now)
    except BookingError:
        for old in b["holds"]:
            _hold(jobs_db, settings, b["req"]["service_code"], key_of(old), kind=old["kind"],
                  minutes=int(settings.get("booking_suggest_hours", 48)) * 60, edition=edition, now=now,
                  job_id=job_id, online_only=False)
        raise
    with transaction(jobs_db) as conn:
        if not resched:
            conn.execute("UPDATE jobs SET job_status = 'Pending Approval', last_edited_by = 'customer', "
                         "last_edited_at = ?, version = version + 1 WHERE job_id = ?", (utcnow_iso(), job_id))
        conn.execute("UPDATE booking_requests SET status = ?, suggested_json = NULL, reminded_at = NULL, "
                     "choices_json = ? WHERE job_id = ?",
                     ("reschedule" if resched else "pending",
                      json.dumps({**b["choices"], "first": window_key, "first_label": label_of(window_key),
                                  "backups": []}), job_id))
    _tell(tickets_db, b["req"]["ticket_id"], f"The customer asked for {label_of(window_key)} instead.", edition,
          public=False)
    ok, why, decision = decide(jobs_db, settings, job_id, window_key, kind="reschedule" if resched else "new", now=now,
                               edition=edition)
    if ok:
        return approve(jobs_db, tickets_db, job_id, actor=SYSTEM, edition=edition, settings=settings,
                       window_key=window_key, now=now, system=True, decision=decision)
    return {"ok": True, "job_id": job_id, "status": "reschedule" if resched else "pending",
            "label": label_of(window_key)}


def _changeable(b, settings, now) -> tuple:
    """(ok, why). Customers can change a booking until booking_change_hours before the visit."""
    if not settings.get("booking_customer_changes", True):
        return False, "please call us to change your booking"
    if b["req"]["status"] in ("pending", "suggested"):
        return True, ""
    if b["req"]["status"] not in ("scheduled", "reschedule") or not b["job"].get("service_date"):
        return False, "this booking can't be changed online"
    start = bs.hhmm(b["job"].get("original_start_time") or b["job"].get("start_time")) or 0
    at = dt.datetime.combine(dt.date.fromisoformat(b["job"]["service_date"]), dt.time()) + dt.timedelta(minutes=start)
    if at - now < dt.timedelta(hours=int(settings.get("booking_change_hours", 24))):
        return False, "it's too close to your visit to change it online — please call us"
    return True, ""


def customer_reschedule(jobs_db: str, tickets_db: str, job_id: str, window_key: str, *, edition: str,
                        settings: dict, now=None) -> dict:
    """A Scheduled visit asks for a new time. The old visit stays booked until it's decided."""
    now = _now(now)
    b = get(jobs_db, job_id)
    if b["req"]["status"] in ("pending", "suggested"):
        return customer_pick(jobs_db, tickets_db, job_id, window_key, edition=edition, settings=settings, now=now)
    ok, why = _changeable(b, settings, now)
    if not ok:
        raise BookingError(why)
    if window_key == b["scheduled_key"]:
        raise BookingError("that's the time you already have")
    for h in b["holds"]:
        bdb.release_hold(jobs_db, h["hold_id"])
    _hold_new_choice(jobs_db, settings, b, window_key, edition=edition, now=now)
    with transaction(jobs_db) as conn:
        conn.execute("UPDATE booking_requests SET status = 'reschedule', suggested_json = NULL, reminded_at = NULL, "
                     "choices_json = ? WHERE job_id = ?",
                     (json.dumps({**b["choices"], "reschedule_to": window_key,
                                  "reschedule_label": label_of(window_key)}), job_id))
    _tell(tickets_db, b["req"]["ticket_id"],
          f"The customer asked to move their visit from {label_of(b['scheduled_key'])} to {label_of(window_key)}.",
          edition, public=False)
    ok, why, decision = decide(jobs_db, settings, job_id, window_key, kind="reschedule", now=now, edition=edition)
    if ok:
        return approve(jobs_db, tickets_db, job_id, actor=SYSTEM, edition=edition, settings=settings,
                       window_key=window_key, now=now, system=True, decision=decision)
    return {"ok": True, "job_id": job_id, "status": "reschedule", "label": label_of(window_key)}


def customer_cancel(jobs_db: str, tickets_db: str, job_id: str, *, edition: str, settings: dict,
                    now=None) -> dict:
    now = _now(now)
    b = get(jobs_db, job_id)
    ok, why = _changeable(b, settings, now)
    if not ok:
        raise BookingError(why)
    with transaction(jobs_db) as conn:
        conn.execute("DELETE FROM booking_holds WHERE job_id = ?", (job_id,))
        conn.execute("UPDATE jobs SET job_status = 'Cancelled', last_edited_by = 'customer', last_edited_at = ?, "
                     "version = version + 1 WHERE job_id = ?", (utcnow_iso(), job_id))
        conn.execute("UPDATE booking_requests SET status = 'cancelled', suggested_json = NULL, decided_by = 'customer', "
                     "decided_at = ?, decision = 'cancelled by customer' WHERE job_id = ?", (utcnow_iso(), job_id))
    return {"ok": True, "job_id": job_id, "status": "cancelled"}


# ── what the customer's page and the approver's list show ────────────────────

def view(jobs_db: str, job_id: str, settings: dict, *, now=None) -> dict | None:
    """The booking as the customer's status page shows it (never crews or other customers)."""
    now = _now(now)
    try:
        b = get(jobs_db, job_id)
    except BookingError:
        return None
    if b["req"]["path"] != "book":
        return None
    st = b["req"]["status"]
    can_change, why = _changeable(b, settings, now)
    out = {"state": st, "service_code": b["req"]["service_code"] or "",
           "service": b["job"].get("service_type") or "",
           "waiting_for": label_of(b["held_key"]) if b["held_key"] else "",
           "confirmed": label_of(b["scheduled_key"]) if b["scheduled_key"] and st in ("scheduled", "reschedule")
           or (b["scheduled_key"] and (b["suggested"] or {}).get("reschedule")) else "",
           "suggested": (b["suggested"] or {}).get("label", "") if st == "suggested" else "",
           "reschedule_to": b["choices"].get("reschedule_label", "") if st == "reschedule" else "",
           "can_accept": st == "suggested", "can_pick": st == "suggested",
           "can_reschedule": can_change and st in ("scheduled",),
           "can_cancel": can_change and st in ("pending", "suggested", "scheduled", "reschedule"),
           "change_note": "" if can_change else why,
           "ics": st in ("scheduled", "reschedule") and bool(b["scheduled_key"])}
    return out


def to_approve(jobs_db: str) -> list:
    """Bookings waiting on the approver (pending / reschedule), soonest-asked first, plus
    suggestions waiting on the customer (so the approver can see them)."""
    conn = get_connection(jobs_db)
    try:
        rows = conn.execute("SELECT r.*, j.customer_name, j.service_type, j.street_address, j.city, j.zip, "
                            "j.service_date, j.start_time, j.end_time, j.original_start_time, j.original_end_time, "
                            "j.customer_id, j.service_details, j.created_by FROM booking_requests r JOIN jobs j ON j.job_id = r.job_id "
                            "WHERE r.path = 'book' AND r.status IN ('pending', 'suggested', 'reschedule') "
                            "ORDER BY r.created_at").fetchall()
        out = []
        for r in rows:
            r = dict(r)
            held = next((h for h in _holds(conn, r["job_id"]) if h["kind"] == "pending"), None)
            phone = ""
            if r.get("customer_id"):
                c = conn.execute("SELECT phone FROM customers WHERE customer_id = ?", (r["customer_id"],)).fetchone()
                phone = (c["phone"] if c else "") or ""
            choices = json.loads(r.get("choices_json") or "{}")
            out.append({"job_id": r["job_id"], "ticket_id": r.get("ticket_id") or "", "status": r["status"],
                        "service_code": r.get("service_code") or "", "service": r.get("service_type") or "",
                        "customer": r.get("customer_name") or "", "phone": phone,
                        "address": ", ".join(x for x in (r.get("street_address"), r.get("city"), r.get("zip")) if x),
                        "held": key_of(held) if held else "", "held_label": label_of(key_of(held)) if held else "",
                        "backups": choices.get("backups", []),
                        "current": label_of(_scheduled_key(r)) if r.get("service_date") else "",
                        "suggested": json.loads(r.get("suggested_json") or "null"),
                        "asked_at": r["created_at"], "crew": held.get("crew") if held else "",
                        "booked_by": "" if (r.get("created_by") or bdb.WEB_BOOKING) == bdb.WEB_BOOKING
                        else r["created_by"]})
        return out
    finally:
        conn.close()


def upcoming(jobs_db: str, *, now=None, days: int = 21, limit: int = 40) -> list:
    """Booked visits (online or by staff) in the next `days` — where an approver can
    "suggest a change" (Phase 4). Shows how each was confirmed."""
    now = _now(now)
    conn = get_connection(jobs_db)
    try:
        rows = conn.execute("SELECT r.job_id, r.ticket_id, r.service_code, r.decision, j.customer_name, j.service_type, "
                            "j.service_date, j.start_time, j.end_time, j.original_start_time, j.original_end_time, "
                            "j.street_address, j.city, j.created_by FROM booking_requests r JOIN jobs j ON j.job_id = r.job_id "
                            "WHERE r.path = 'book' AND r.status = 'scheduled' AND j.service_date BETWEEN ? AND ? "
                            "ORDER BY j.service_date, COALESCE(j.original_start_time, j.start_time) LIMIT ?",
                            (now.date().isoformat(), (now.date() + dt.timedelta(days=days)).isoformat(), limit)).fetchall()
        how = {PRE_APPROVED: "instant booking", AUTOMATIC: "confirmed automatically",
               "agent": "confirmed by the assistant"}
        return [{"job_id": r["job_id"], "ticket_id": r["ticket_id"] or "", "service_code": r["service_code"] or "",
                 "service": r["service_type"] or "", "customer": r["customer_name"] or "",
                 "address": ", ".join(x for x in (r["street_address"], r["city"]) if x),
                 "key": _scheduled_key(dict(r)), "label": label_of(_scheduled_key(dict(r))),
                 "how": how.get(r["decision"] or "", "approved")} for r in rows]
    finally:
        conn.close()


# ── the calendar file for a confirmed visit ──────────────────────────────────

def ics(jobs_db: str, job_id: str, *, business: str = "", uid_host: str = "ai-prowler") -> str:
    b = get(jobs_db, job_id)
    if b["req"]["status"] not in ("scheduled", "reschedule") or not b["scheduled_key"]:
        raise BookingError("this visit isn't confirmed yet")
    d, s, e = _parse_key(b["scheduled_key"])
    f = lambda t: f"{d:%Y%m%d}T{t.replace(':', '')}00"   # noqa: E731 — local ("floating") time
    clean = lambda t: str(t or "").replace("\\", "\\\\").replace(",", "\\,").replace(";", "\\;").replace("\n", " ")  # noqa: E731
    where = ", ".join(x for x in (b["job"].get("street_address"), b["job"].get("city")) if x)
    return "\r\n".join([
        "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//AI-Prowler//Service booking//EN", "BEGIN:VEVENT",
        f"UID:{job_id}@{uid_host}", f"DTSTAMP:{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}",
        f"DTSTART:{f(s)}", f"DTEND:{f(e)}",
        f"SUMMARY:{clean((business + ': ' if business else '') + (b['job'].get('service_type') or 'Service visit'))}",
        f"DESCRIPTION:{clean('Arrival window ' + label_of(b['scheduled_key']))}",
        f"LOCATION:{clean(where)}", "END:VEVENT", "END:VCALENDAR", ""])


# ── the timer: reminders and releases (§7a.5) ────────────────────────────────

def sweep(jobs_db: str, tickets_db: str, settings: dict, *, edition: str, now=None) -> dict:
    """Remind approvers about bookings waiting longer than booking_hold_hours (once), and
    act on holds past their expiry: an undecided booking becomes Requested and the
    customer is told you'll call; an unanswered suggestion frees its window and the team
    is asked to call; a waiting reschedule just lapses (the visit stays)."""
    now = _now(now)
    out = {"remind": [], "released": []}
    rel, hold = int(settings.get("booking_release_hours", 72)), int(settings.get("booking_hold_hours", 48))
    remind_from = (now + dt.timedelta(hours=max(0, rel - hold))).isoformat(timespec="seconds")
    conn = get_connection(jobs_db)
    try:
        rows = conn.execute("SELECT h.job_id, h.hold_date, h.start_time, h.end_time, r.ticket_id, j.customer_name "
                            "FROM booking_holds h JOIN booking_requests r ON r.job_id = h.job_id "
                            "JOIN jobs j ON j.job_id = h.job_id WHERE h.kind = 'pending' AND h.expires_at <= ? "
                            "AND h.expires_at > ? AND r.reminded_at IS NULL AND r.status IN ('pending', 'reschedule')",
                            (remind_from, now.isoformat(timespec="seconds"))).fetchall()
        for r in rows:
            out["remind"].append({"job_id": r["job_id"], "ticket_id": r["ticket_id"], "customer": r["customer_name"],
                                  "label": label_of(f"{r['hold_date']}T{r['start_time']}-{r['end_time']}")})
            conn.execute("UPDATE booking_requests SET reminded_at = ? WHERE job_id = ?", (utcnow_iso(), r["job_id"]))
    finally:
        conn.close()
    for h in bdb.expire_holds(jobs_db, now=now):
        jid = h.get("job_id")
        if not jid or h["kind"] in ("checkout", "waitlist"):     # waitlist offers: booking_followup
            continue
        try:
            b = get(jobs_db, jid)
        except BookingError:
            continue
        st, resched = b["req"]["status"], bool((b["suggested"] or {}).get("reschedule"))
        with transaction(jobs_db) as conn:
            if st == "reschedule" or resched:
                conn.execute("UPDATE booking_requests SET status = 'scheduled', suggested_json = NULL, "
                             "decision = 'reschedule lapsed' WHERE job_id = ?", (jid,))
            elif st in ("pending", "suggested"):
                conn.execute("UPDATE jobs SET job_status = 'Requested', last_edited_by = 'system', last_edited_at = ?, "
                             "version = version + 1 WHERE job_id = ?", (utcnow_iso(), jid))
                conn.execute("UPDATE booking_requests SET status = 'requested', suggested_json = NULL, "
                             "decision = ? WHERE job_id = ?", ("lapsed" if st == "pending" else "suggestion lapsed", jid))
            else:
                continue
        t = b["req"]["ticket_id"]
        if st == "pending":
            _tell(tickets_db, t, "Sorry for the wait — we couldn't confirm your time online. We'll call you to "
                                 "arrange your visit.", edition)
            _tell(tickets_db, t, "Booking wasn't decided in time: the window was freed and the job is now "
                                 "Requested. Please call the customer.", edition, public=False)
        elif st == "suggested" and not resched:
            _tell(tickets_db, t, "The customer didn't answer the suggested time, so it was freed and the job is "
                                 "now Requested. Please call them.", edition, public=False)
        else:
            _tell(tickets_db, t, "The reschedule wasn't decided in time — the original visit stays.", edition,
                  public=False)
        out["released"].append({"job_id": jid, "was": st})
    return out
