"""The Director's watcher: checks every open job on its own while AI-Prowler runs.

Each check (tick) is safe to repeat: every event becomes one notice at most (a
dedupe key per event), so running it every 15 minutes never repeats itself.

A tick:
1. marks sent quotes past their valid-until date as expired (setting auto_expire_bids)
2. adds notices for follow-ups due and quotes expiring within 3 days
3. adds notices for jobs waiting on a reviewer or approver too long, jobs that
   haven't moved, and jobs near or past their due date
4. once a day, after briefing_time, makes the daily briefing and delivers it
   (inbox for chat/pwa, or email through AI-Prowler's send_email)

It never sends anything to a customer and never approves anything. Notices
land in the Director inbox (est_director_inbox) and in the briefing.

start_background() runs ticks in a daemon thread inside AI-Prowler's process.
It's light work (a few database reads per company), so it also runs in Server
mode. Set ESTIMATOR_WATCHER=off to stop it.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import date, datetime, timedelta, timezone

from estimator.context import PERSONAL_COMPANY_ID, RequestContext
from estimator.core.dates import local_date
from estimator.core.units.money import format_cents
from estimator.director import briefing as briefing_mod
from estimator.director.settings import get_settings
from estimator.errors import EstimatorError
from estimator.estimating import service

log = logging.getLogger("estimator.watch")
MAX_EMAIL_ATTEMPTS = 5
WAITING_FOR = {"reviewer": "a reviewer", "approver": "an approval", "staff": "staff to make the quote",
               "takeoff": "trade takeoffs"}


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def director_context(company_id: str) -> RequestContext:
    """Who the watcher acts as: the Director agent with owner rights, for the audit log."""
    mode = "personal" if company_id == PERSONAL_COMPANY_ID else "server"
    return RequestContext(company_id=company_id, user_id="director", role="owner", mode=mode, agent="agent:director")


def _notice(conn, ctx, kind: str, key: str, message: str, *, job_id=None, estimate_id=None, bid_id=None) -> dict | None:
    cur = conn.execute(
        "INSERT OR IGNORE INTO director_notices (company_id, kind, dedupe_key, job_id, estimate_id, bid_id, message,"
        " created_at) VALUES (?,?,?,?,?,?,?,?)",
        (ctx.company_id, kind, key, job_id, estimate_id, bid_id, message, _utc()))
    if cur.rowcount != 1:
        return None
    return {"id": cur.lastrowid, "kind": kind, "message": message, "job_id": job_id, "bid_id": bid_id}


def _expire_bids(conn, ctx, today: date) -> list[dict]:
    from estimator.bids import service as bids
    out = []
    rows = conn.execute("SELECT b.id, b.number, b.valid_until, b.total_cents, e.title FROM bids b JOIN estimates e"
                        " ON e.id = b.estimate_id WHERE b.company_id = ? AND b.status IN ('sent', 'viewed')",
                        (ctx.company_id,)).fetchall()
    for b in rows:
        valid = local_date(b["valid_until"])
        if valid and valid < today:
            try:
                bids.set_status(conn, ctx, b["id"], "expired")
            except EstimatorError as exc:
                log.warning("couldn't expire bid %s: %s", b["id"], exc)
                continue
            out.append({"bid_id": b["id"], "number": b["number"]})
            with service.transaction(conn):
                _notice(conn, ctx, "expired", f"expired:{b['id']}",
                        f"Quote {b['number']} ({b['title']}, {format_cents(b['total_cents'])}) expired on "
                        f"{valid.isoformat()} without an answer. Revise it (revise=true) to send a fresh one.",
                        bid_id=b["id"])
    return out


def _job_notices(conn, ctx, today: date, s: dict) -> list[dict]:
    made = []
    remind = s["review_reminder_days"]
    rows = conn.execute("SELECT id, stage, state, waiting_on, request_text, due_date, estimate_id, updated_at"
                        " FROM director_jobs WHERE company_id = ? AND state NOT IN ('done', 'cancelled')",
                        (ctx.company_id,)).fetchall()
    for j in rows:
        what = (j["request_text"] or "")[:60]
        upd = local_date(j["updated_at"])
        days = (today - upd).days if upd else 0
        if j["state"] == "waiting_on_user" and j["waiting_on"] in WAITING_FOR and days >= remind:
            n = _notice(conn, ctx, "review_reminder", f"review:{j['id']}:{j['stage']}:{days // remind}",
                        f"Job {j['id']} ({what}) has waited {days} days for {WAITING_FOR[j['waiting_on']]}.",
                        job_id=j["id"], estimate_id=j["estimate_id"])
            made += [n] if n else []
        elif j["state"] in ("waiting_on_user", "active") and days >= remind:
            n = _notice(conn, ctx, "stuck", f"stuck:{j['id']}:{j['stage']}:{days // remind}",
                        f"Job {j['id']} ({what}) hasn't moved in {days} days (step: {j['stage'].replace('_', ' ')}).",
                        job_id=j["id"], estimate_id=j["estimate_id"])
            made += [n] if n else []
        due = local_date(j["due_date"]) if j["due_date"] else None
        if due and j["state"] != "waiting_on_customer" and j["stage"] not in ("follow_up",):
            if due < today:
                n = _notice(conn, ctx, "overdue", f"overdue:{j['id']}",
                            f"Job {j['id']} ({what}) was due {due.isoformat()} and the quote isn't out yet.",
                            job_id=j["id"], estimate_id=j["estimate_id"])
                made += [n] if n else []
            elif (due - today).days <= s["due_soon_days"]:
                left = (due - today).days
                n = _notice(conn, ctx, "due_soon", f"due_soon:{j['id']}",
                            f"Job {j['id']} ({what}) is due " + ("today" if left == 0 else f"in {left} day(s)")
                            + f" ({due.isoformat()}).", job_id=j["id"], estimate_id=j["estimate_id"])
                made += [n] if n else []
    return made


def _quote_notices(conn, ctx, today: date) -> list[dict]:
    made = []
    due = briefing_mod.followups_due(conn, ctx, today)
    for f in due["follow_ups"]:
        n = _notice(conn, ctx, "follow_up", f"follow_up:{f['bid_id']}",
                    f"Follow up on quote {f['number']} ({f['title']}, {f['total']}): sent to {f['sent_to']} on "
                    f"{f['sent_on']}, {f['days_since_sent']} days ago.", bid_id=f["bid_id"])
        made += [n] if n else []
    for e in due["expiring_soon"]:
        n = _notice(conn, ctx, "expiring", f"expiring:{e['bid_id']}",
                    f"Quote {e['number']} ({e['title']}, {e['total']}) expires {e['valid_until']} "
                    f"({e['days_left']} day(s) left).", bid_id=e["bid_id"])
        made += [n] if n else []
    return made


def _deliver(conn, ctx, notice_id: int, s: dict, subject: str, text: str) -> dict:
    """Deliver one notice: the inbox always has it; email when the briefing channel is email."""
    from estimator.integrations import host
    if s["briefing_channel"] != "email":
        conn.execute("UPDATE director_notices SET delivered_via = 'chat', delivered_at = ? WHERE id = ?",
                     (_utc(), notice_id))
        return {"via": "chat"}
    try:
        host.call("send_email", to=s["briefing_email"], subject=subject, body=text)
    except EstimatorError as exc:
        conn.execute("UPDATE director_notices SET delivery_attempts = delivery_attempts + 1, last_error = ?"
                     " WHERE id = ?", (exc.message[:300], notice_id))
        return {"via": "email", "error": exc.message[:300]}
    conn.execute("UPDATE director_notices SET delivered_via = 'email', delivered_at = ?,"
                 " delivery_attempts = delivery_attempts + 1, last_error = NULL WHERE id = ?", (_utc(), notice_id))
    return {"via": "email", "to": s["briefing_email"]}


def _briefing(conn, ctx, now: datetime, s: dict) -> dict | None:
    today = now.date()
    if not s["briefing_enabled"] or now.strftime("%H:%M") < s["briefing_time"]:
        return None
    text = briefing_mod.briefing(conn, ctx, today)["text"]
    with service.transaction(conn):
        n = _notice(conn, ctx, "briefing", f"briefing:{today.isoformat()}", text)
    if n is None:
        return None
    subject = text.splitlines()[0]
    with service.transaction(conn):
        out = _deliver(conn, ctx, n["id"], s, subject, text)
    return {"notice_id": n["id"], **out}


def _retry_email(conn, ctx, s: dict) -> list[dict]:
    if s["briefing_channel"] != "email":
        return []
    out = []
    for r in conn.execute("SELECT id, message FROM director_notices WHERE company_id = ? AND kind = 'briefing'"
                          " AND delivered_at IS NULL AND delivery_attempts < ? ORDER BY id",
                          (ctx.company_id, MAX_EMAIL_ATTEMPTS)).fetchall():
        with service.transaction(conn):
            out.append({"notice_id": r["id"], **_deliver(conn, ctx, r["id"], s, r["message"].splitlines()[0],
                                                          r["message"])})
    return out


def _agents(conn, ctx, now) -> dict:
    """Queue and run unattended agent work (Reviewer notes, Bid Writer drafts, Follow-up drafts). A problem
    here never stops the rest of the check."""
    from estimator.agents import queue
    try:
        out = queue.run(conn, ctx, now)
        return {"queued": len(out["queued"]), "ran": len(out["ran"]), "paused": out["paused"]}
    except Exception as exc:  # noqa: BLE001
        log.warning("agent run failed for %s: %s", ctx.company_id, exc)
        return {"error": str(exc)[:200]}


def tick(conn, ctx: RequestContext, now: datetime | None = None) -> dict:
    """One check of everything for this company. Safe to run as often as you like."""
    now = now or datetime.now().astimezone()
    today = now.date()
    s = get_settings(conn, ctx.company_id)
    started = _utc()
    expired = _expire_bids(conn, ctx, today) if s["auto_expire_bids"] else []
    with service.transaction(conn):
        made = _quote_notices(conn, ctx, today) + _job_notices(conn, ctx, today, s)
    retried = _retry_email(conn, ctx, s)
    plans = []
    if ctx.mode == "server":                      # take in plan results published by processing PCs
        from estimator.drawing_model import server_jobs
        try:
            plans = server_jobs.import_published(conn, ctx)
        except (OSError, EstimatorError) as exc:
            log.warning("couldn't check published plans: %s", exc)
    projects = []
    if ctx.mode == "server":                      # take in projects PCs copied to the shared inbox (office network)
        from estimator import project_sync
        try:
            projects = project_sync.take_in_inbox(conn, ctx)
        except (OSError, EstimatorError) as exc:
            log.warning("couldn't check the projects inbox: %s", exc)
    agents = _agents(conn, ctx, now)
    brief = _briefing(conn, ctx, now, s)
    result = {"ok": True, "company_id": ctx.company_id, "ran_at": now.isoformat(timespec="seconds"),
              "new_notices": made, "expired_bids": expired, "briefing": brief, "email_retries": retried,
              "agents": agents, "plans_published": plans, "projects_received": projects,
              "unread": unread_count(conn, ctx)}
    with service.transaction(conn):
        conn.execute("INSERT INTO director_watch_runs (company_id, started_at, finished_at, result_json)"
                     " VALUES (?,?,?,?)", (ctx.company_id, started, _utc(),
                                           json.dumps({k: (len(v) if isinstance(v, list) else v)
                                                       for k, v in result.items() if k != "ok"}, default=str)))
        conn.execute("DELETE FROM director_watch_runs WHERE company_id = ? AND id NOT IN (SELECT id FROM"
                     " director_watch_runs WHERE company_id = ? ORDER BY id DESC LIMIT 200)",
                     (ctx.company_id, ctx.company_id))
    return result


# ---------------------------------------------------------------- inbox

def unread_count(conn, ctx) -> int:
    return conn.execute("SELECT COUNT(*) FROM director_notices WHERE company_id = ? AND read_at IS NULL"
                        " AND (for_user IS NULL OR for_user = ?)", (ctx.company_id, ctx.user_id)).fetchone()[0]


def inbox(conn, ctx: RequestContext, unread_only: bool = True, mark_read: bool = False, limit: int = 50) -> dict:
    sql = "SELECT * FROM director_notices WHERE company_id = ? AND (for_user IS NULL OR for_user = ?)"
    if unread_only:
        sql += " AND read_at IS NULL"
    sql += " ORDER BY id DESC LIMIT ?"
    rows = [dict(r) for r in conn.execute(sql, (ctx.company_id, ctx.user_id, max(1, min(int(limit), 500))))]
    if mark_read and rows:
        with service.transaction(conn):
            conn.execute(f"UPDATE director_notices SET read_at = ? WHERE company_id = ? AND read_at IS NULL"
                         f" AND id IN ({','.join('?' for _ in rows)})", [_utc(), ctx.company_id, *[r["id"] for r in rows]])
    notices = [{"id": r["id"], "kind": r["kind"], "message": r["message"], "job_id": r["job_id"], "bid_id": r["bid_id"],
                "estimate_id": r["estimate_id"], "created_on": local_date(r["created_at"]).isoformat(),
                "delivered_via": r["delivered_via"], "delivery_error": r["last_error"], "read": bool(r["read_at"])}
               for r in rows]
    return {"ok": True, "count": len(notices), "unread_left": unread_count(conn, ctx), "notices": notices}


def status(conn, ctx: RequestContext) -> dict:
    s = get_settings(conn, ctx.company_id)
    last = conn.execute("SELECT * FROM director_watch_runs WHERE company_id = ? ORDER BY id DESC LIMIT 1",
                        (ctx.company_id,)).fetchone()
    last_at = last["finished_at"] if last else None
    nxt = None
    if last_at and s["watcher_enabled"]:
        nxt = (datetime.fromisoformat(last_at) + timedelta(minutes=s["watch_interval_minutes"])).astimezone()
    return {"ok": True, "enabled": s["watcher_enabled"], "running_in_background": is_running(),
            "interval_minutes": s["watch_interval_minutes"], "last_run": last_at,
            "last_result": json.loads(last["result_json"]) if last else None,
            "next_run_after": nxt.isoformat(timespec="minutes") if nxt else None,
            "briefing": {"enabled": s["briefing_enabled"], "time": s["briefing_time"], "channel": s["briefing_channel"],
                         "email": s["briefing_email"]},
            "unread": unread_count(conn, ctx)}


# ---------------------------------------------------------------- background thread

_thread: threading.Thread | None = None
_stop = threading.Event()


def companies(conn) -> list[str]:
    rows = conn.execute("SELECT company_id FROM director_settings UNION SELECT company_id FROM director_jobs"
                        " UNION SELECT company_id FROM bids").fetchall()
    return sorted({r[0] for r in rows}) or [PERSONAL_COMPANY_ID]


def run_due(now: datetime | None = None, conn=None) -> list[dict]:
    """Run a tick for every company whose interval has passed. Used by the background thread."""
    from estimator.database import open_database
    now = now or datetime.now().astimezone()
    own = conn is None
    conn = conn or open_database()
    results = []
    try:
        for company in companies(conn):
            s = get_settings(conn, company)
            if not s["watcher_enabled"]:
                continue
            last = conn.execute("SELECT finished_at FROM director_watch_runs WHERE company_id = ? ORDER BY id DESC"
                                " LIMIT 1", (company,)).fetchone()
            if last and last[0] and now - datetime.fromisoformat(last[0]) < timedelta(minutes=s["watch_interval_minutes"]):
                continue
            try:
                results.append(tick(conn, director_context(company), now))
            except Exception as exc:          # one company's problem must not stop the others
                log.exception("Estimator watcher failed for %s", company)
                results.append({"ok": False, "company_id": company, "error": f"{type(exc).__name__}: {exc}"})
    finally:
        if own:
            conn.close()
    return results


def _loop(poll_seconds: int) -> None:
    while not _stop.wait(poll_seconds):
        try:
            run_due()
        except Exception:
            log.exception("Estimator watcher loop error")


def watcher_disabled_by_env() -> bool:
    return os.environ.get("ESTIMATOR_WATCHER", "on").strip().lower() in ("off", "0", "false", "no")


def start_background(poll_seconds: int = 60) -> bool:
    """Start the watcher thread once per process. Returns True if it's running."""
    global _thread
    if watcher_disabled_by_env():
        return False
    if _thread and _thread.is_alive():
        return True
    _stop.clear()
    _thread = threading.Thread(target=_loop, args=(poll_seconds,), name="estimator-director-watch", daemon=True)
    _thread.start()
    log.info("Estimator Director watcher started (checks every %ss)", poll_seconds)
    return True


def stop_background(timeout: float = 5) -> None:
    global _thread
    _stop.set()
    if _thread:
        _thread.join(timeout)
    _thread = None


def is_running() -> bool:
    return bool(_thread and _thread.is_alive())
