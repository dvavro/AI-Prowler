"""
desk_scheduler.py — AI-Prowler Service Desk, Phase 3: the timed jobs.

One background thread (both modes), started by ai_prowler_mcp.py:
  * every 5 minutes (Business): SLA warnings / breaches / escalations
  * every tick (both): auto-close Fixed customer tickets after
    "auto_close_days" with no word from the customer
  * once a day at "digest_hour": the morning digest — Business: to the owner
    and managers; Solo: to the owner's alert contacts
  * scheduled backups ("backup_frequency" / "backup_hour"), then retention
    pruning; two failed backups in a row alert the owner
run_once() does one pass and is what the tests call (with a fixed clock).
Last-run times live in the tickets DB (desk_state), so a restart doesn't
repeat or skip anything.
"""
from __future__ import annotations

import datetime
import logging
import threading

import desk_backup
import desk_db
import desk_reports
import desk_rules as rules

log = logging.getLogger("desk_scheduler")
TICK_SECONDS = 60
SLA_EVERY = datetime.timedelta(minutes=5)

_thread = None
_stop = threading.Event()


def _get(db_path, key):
    conn = desk_db.get_connection(db_path)
    try:
        r = conn.execute("SELECT value FROM desk_state WHERE key = ?", (key,)).fetchone()
        return r[0] if r else None
    finally:
        conn.close()


def _set(db_path, key, value):
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("INSERT INTO desk_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE "
                     "SET value = excluded.value", (key, str(value)))
    finally:
        conn.close()


def _booking_on(s: dict) -> bool:
    """Bookings exist when the page offers "Book a service" or staff book in the app (Phase 3)."""
    import desk_portal
    return "book" in desk_portal.page_paths(s) or bool(s.get("staff_booking"))


def booking_digest_line(db_path: str, s: dict, now=None, *, edition: str = "business") -> str:
    """'📅 Bookings to approve: 2 (…)' plus the FYI '📅 Booked on their own since yesterday: …'
    for the morning digest, or '' (booking-spec.md §7a.1, §7a.3)."""
    try:
        import desk_portal
        jobs_db = desk_portal._jobs_db()
        if not jobs_db or not _booking_on(s):
            return ""
        import booking_flow
        rows = [b for b in booking_flow.to_approve(jobs_db) if b["status"] in ("pending", "reschedule")]
        since = ((now or datetime.datetime.now(datetime.timezone.utc)).astimezone(datetime.timezone.utc)
                 - datetime.timedelta(days=1)).isoformat(timespec="seconds")
        fyi = booking_flow.confirmed_on_their_own(jobs_db, since)
    except Exception:  # noqa: BLE001
        return ""
    out = []
    if rows:
        items = "; ".join(f"{b['customer'] or 'customer'} {b['held_label'] or b['current']}" for b in rows[:5])
        out.append(f"📅 Bookings to approve: {len(rows)} — {items}" + (" …" if len(rows) > 5 else "")
                   + ". Open the Service Desk app → 📅 To approve.")
    if fyi:
        items = "; ".join(f"{b['customer'] or 'customer'} {b['label']}" for b in fyi[:5])
        out.append(f"📅 Booked on their own since yesterday (FYI): {len(fyi)} — {items}" + (" …" if len(fyi) > 5 else "")
                   + ". You can suggest a change from 📅 To approve → Booked.")
    try:                                   # personal installs: the business calendar's freshness (§6.4)
        import booking_calendar
        if booking_calendar.stale(jobs_db, s, edition)[0]:
            out.append(booking_calendar.status_line(booking_calendar.status(jobs_db, s, edition=edition)))
    except Exception:  # noqa: BLE001
        pass
    return "\n".join(out)


def agent_digest_line(db_path: str, s: dict) -> str:
    """'🤖 Agent: 3 items waiting in its queue, 2 suggestions waiting for you' (desk-agent-spec §13.3)."""
    if not s.get("agent_enabled"):
        return ""
    try:
        import desk_agent
        st = desk_agent.status(db_path)
    except Exception:  # noqa: BLE001
        return ""
    parts = []
    if st["waiting"]:
        parts.append(f"{st['waiting']} item(s) waiting in its queue"
                     + (f" — in Claude, Muse or Grok say: \"{st['chat_prompt']}\"" if st["provider"] == "chat_only" else ""))
    if st["pending"]:
        parts.append(f"{st['pending']} suggestion(s) waiting for your OK (Service Desk app → 🤖 Agent)")
    return ("🤖 Agent: " + "; ".join(parts) + ".") if parts else ""


JOBS_SCAN_EVERY = datetime.timedelta(minutes=5)
_jobs_last = {"scan": None}


def jobs_agent_tick(tickets_db: str | None, *, edition: str, now: datetime.datetime | None = None,
                    business: str = "") -> dict:
    """The Jobs agent (jobs-agent-spec.md; its own database, desk_agent_store.py): copy the shared
    runner settings, look at the Jobs database every 5 minutes, start a run when one is due.
    Runs whether or not Service Desk is on. Never raises."""
    did = {}
    try:
        import desk_agent
        import desk_agent_store
        import desk_jobs_agent
        import desk_portal
        from pathlib import Path
        if not Path(desk_agent_store.path()).exists():
            return did                                     # never turned on — nothing to do
        s = desk_agent_store.sync_shared(tickets_db)
        if not (s.get("agent_jb_enabled") or s.get("agent_jb_rt_enabled")):     # jobs or the Route flow
            return did
        jobs_db = desk_portal._jobs_db()
        now = now or datetime.datetime.now().astimezone()
        adb = desk_agent_store.path()
        last = _jobs_last["scan"]
        if jobs_db and (last is None or now - last >= JOBS_SCAN_EVERY or now < last):
            _jobs_last["scan"] = now
            n = desk_jobs_agent.scan(adb, jobs_db, settings=s, edition=edition, now=now)
            if n:
                did["jobs_agent_queued"] = n
        if s.get("agent_provider", "chat_only") != "chat_only" and \
                not desk_agent.why_not_run(adb, s, edition=edition, now=now):
            if desk_agent.run_in_background(adb, edition=edition, business=business, jobs_db=jobs_db):
                did["jobs_agent_run"] = True
    except Exception as e:  # noqa: BLE001
        log.warning("Jobs agent tick failed: %s", e)
    return did


_hr_last = {"scan": None}


def hr_agent_tick(tickets_db: str | None, *, edition: str, now: datetime.datetime | None = None,
                  business: str = "") -> dict:
    """The HR agent (hr-agent-spec.md; its own database in the HR data folder): copy the shared
    runner settings, look at the HR data every 15 minutes, and start a run — only on a key-based
    runner or the Claude CLI (decision 5; never a chat). Never raises."""
    did = {}
    try:
        from pathlib import Path

        import desk_agent
        import desk_agent_hr_store
        import desk_agent_settings as das
        import desk_hr_agent
        if not Path(desk_agent_hr_store.path()).exists():
            return did
        adb = desk_agent_hr_store.path()
        s = desk_agent_hr_store.sync_shared(tickets_db, adb)
        if not s.get("agent_hr_enabled") or not desk_hr_agent.hr.get("load"):
            return did
        now = now or datetime.datetime.now().astimezone()
        last = _hr_last["scan"]
        if last is None or now - last >= datetime.timedelta(minutes=15) or now < last:
            _hr_last["scan"] = now
            n = desk_hr_agent.scan(adb, None, settings=s, edition=edition, now=now)
            if n:
                did["hr_agent_queued"] = n
        provider, why = das.hr_runner(s, edition)
        if provider and not desk_agent.why_not_run(adb, s, edition=edition, now=now):
            if desk_agent.run_in_background(adb, edition=edition, business=business):
                did["hr_agent_run"] = True
    except Exception as e:  # noqa: BLE001
        log.warning("HR agent tick failed: %s", e)
    return did


def hr_agent_digest_line() -> str:
    """'👥 HR agent: 3 suggestions waiting …' or '' (counts only — no HR details in the digest)."""
    try:
        from pathlib import Path

        import desk_agent
        import desk_agent_hr_store
        p = desk_agent_hr_store.path()
        if not Path(p).exists() or not desk_agent_hr_store.settings(p).get("agent_hr_enabled"):
            return ""
        st = desk_agent.status(p)
    except Exception:  # noqa: BLE001
        return ""
    return (f"👥 HR agent: {st['pending']} suggestion(s) waiting for HR (HR Admin → 🤖 Agent)."
            if st["pending"] else "")


def jobs_agent_digest_line() -> str:
    """'🧰 Jobs agent: 2 suggestions waiting for your OK …' or ''."""
    try:
        import desk_agent
        import desk_agent_store
        from pathlib import Path
        p = desk_agent_store.path()
        if not Path(p).exists():
            return ""
        js = desk_agent_store.settings(p)
        if not (js.get("agent_jb_enabled") or js.get("agent_jb_rt_enabled")):
            return ""
        st = desk_agent.status(p)
    except Exception:  # noqa: BLE001
        return ""
    parts = []
    if st["pending"]:
        parts.append(f"{st['pending']} suggestion(s) waiting for your OK (Jobs app → 🤖 Agent)")
    if st["waiting"] and st["provider"] == "chat_only":
        parts.append(f"{st['waiting']} item(s) waiting — in Claude, Muse or Grok say: \"{st['chat_prompt']}\"")
    return ("🧰 Jobs agent: " + "; ".join(parts) + ".") if parts else ""


def run_once(db_path: str, *, edition: str, now: datetime.datetime | None = None,
             send_digest=None, alert_owner=None) -> dict:
    """One pass. send_digest(text) delivers the digest; alert_owner(text) is for
    backup failures. Both best-effort. `now` is local, naive or aware."""
    now = now or datetime.datetime.now().astimezone()
    if now.tzinfo is None:
        now = now.astimezone()
    did = {}
    utc = now.astimezone(datetime.timezone.utc)

    last_sla = _get(db_path, "last_sla_check")
    if rules.feature_enabled(edition, "sla_escalation") and (
            not last_sla or utc - datetime.datetime.fromisoformat(last_sla) >= SLA_EVERY):
        did["sla"] = desk_reports.sla_check(db_path, edition=edition, now=utc)
        _set(db_path, "last_sla_check", utc.isoformat(timespec="seconds"))

    closed = desk_reports.auto_close(db_path, edition=edition, now=utc)
    if closed:
        did["auto_closed"] = closed

    s = desk_db.get_settings(db_path)
    # Service booking (booking-spec.md §7a.5): remind approvers about bookings still waiting,
    # free windows nobody decided on, and tell the customer. Cheap — every tick.
    try:
        import desk_portal
        jobs_db = desk_portal._jobs_db()
        if jobs_db and _booking_on(s):
            import booking_flow
            sw = booking_flow.sweep(jobs_db, db_path, s, edition=edition, now=now.replace(tzinfo=None))
            if s.get("agent_enabled") and s.get("agent_bk_enabled"):
                import desk_agent                      # queue new bookings / requests for the agent
                queued = desk_agent.scan_bookings(db_path, jobs_db, settings=s)
                if queued:
                    did["agent_queued"] = queued
            if sw["remind"] or sw["released"]:
                did["bookings"] = sw
            if sw["remind"] and alert_owner:
                lines = [f"• {x['customer'] or 'A customer'} — {x['label']} ({x['ticket_id'] or x['job_id']})"
                         for x in sw["remind"]]
                try:
                    alert_owner("📅 Bookings still waiting for your OK — approve, suggest another time or decline "
                                "them in the Service Desk app (📅 To approve):\n" + "\n".join(lines))
                except Exception:  # noqa: BLE001
                    pass
            # Phase 6: offer earlier openings to the waitlist, and send visit reminders.
            import booking_followup
            wl = booking_followup.sweep_waitlist(jobs_db, db_path, s, edition=edition, now=now.replace(tzinfo=None))
            if wl["offered"] or wl["passed"]:
                did["waitlist"] = wl
            import desk_alerts
            sent = booking_followup.send_reminders(jobs_db, db_path, s, edition=edition,
                                                   business=desk_alerts._call("business", default="") or "",
                                                   now=now.replace(tzinfo=None))
            if sent:
                did["reminders"] = len(sent)
    except Exception as e:  # noqa: BLE001
        log.warning("Service Desk booking sweep failed: %s", e)
    # The self-running agent (desk_agent.run; Claude API / Claude subscription / Grok bot). It decides
    # itself whether to start (hours, budget, batching, nothing waiting) and runs on its own thread.
    if s.get("agent_enabled") and s.get("agent_provider", "chat_only") != "chat_only":
        try:
            import desk_agent
            import desk_alerts
            if not desk_agent.why_not_run(db_path, s, edition=edition, now=now):
                biz = desk_alerts._call("business", default="") or ""
                if desk_agent.run_in_background(db_path, edition=edition, business=biz):
                    did["agent_run"] = True
        except Exception as e:  # noqa: BLE001
            log.warning("Service Desk agent run not started: %s", e)
    try:
        import desk_alerts
        biz = desk_alerts._call("business", default="") or ""
        did.update(jobs_agent_tick(db_path, edition=edition, now=now, business=biz))
        did.update(hr_agent_tick(db_path, edition=edition, now=now, business=biz))
    except Exception as e:  # noqa: BLE001
        log.warning("Jobs agent tick failed: %s", e)
    today = now.date().isoformat()
    if now.hour >= int(s.get("digest_hour", 7)) and _get(db_path, "last_digest_date") != today:
        text = desk_reports.digest_text(db_path, edition=edition, now=utc)
        waiting = booking_digest_line(db_path, s, edition=edition)
        if waiting:
            text = (text + "\n\n" if text else "") + waiting
        agent = agent_digest_line(db_path, s)
        if agent:
            text = (text + "\n\n" if text else "") + agent
        jagent = jobs_agent_digest_line()
        if jagent:
            text = (text + "\n\n" if text else "") + jagent
        hagent = hr_agent_digest_line()
        if hagent:
            text = (text + "\n\n" if text else "") + hagent
        if text and send_digest:
            try:
                send_digest(text)
            except Exception as e:  # noqa: BLE001
                log.warning("Service Desk digest failed: %s", e)
        did["digest"] = bool(text)
        _set(db_path, "last_digest_date", today)

    naive = now.replace(tzinfo=None)
    if desk_backup.due(s, _get(db_path, "last_backup"), naive):
        try:
            b = desk_backup.backup_now(db_path, "scheduled", now=naive)
            if not b["verified"]:
                raise RuntimeError("the backup copy failed its integrity check")
            _set(db_path, "backup_failures", 0)
            desk_backup.prune(db_path, now=naive)
            did["backup"] = b["name"]
        except Exception as e:  # noqa: BLE001
            fails = int(_get(db_path, "backup_failures") or 0) + 1
            _set(db_path, "backup_failures", fails)
            did["backup_error"] = str(e)
            if fails >= 2 and alert_owner:
                try:
                    alert_owner(f"Service Desk backups have failed {fails} times in a row: {e}")
                except Exception:  # noqa: BLE001
                    pass
        _set(db_path, "last_backup", naive.isoformat(timespec="seconds"))
    return did


def start(get_db, get_edition, is_on, send_digest=None, alert_owner=None) -> None:
    """Start the loop once. Each tick re-checks that Service Desk is on."""
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()

    def loop():
        while not _stop.wait(TICK_SECONDS):
            try:
                if is_on():
                    run_once(get_db(), edition=get_edition(), send_digest=send_digest,
                             alert_owner=alert_owner)
            except Exception as e:  # noqa: BLE001
                log.warning("Service Desk scheduler tick failed: %s", e)

    _thread = threading.Thread(target=loop, name="desk-scheduler", daemon=True)
    _thread.start()


def stop() -> None:
    _stop.set()


_jobs_thread = None


def start_jobs_agent(get_edition, desk_on, get_tickets_db=None) -> None:
    """The Jobs agent's own timer, for installs where Service Desk is off (when it's on,
    run_once() does the same work every tick). Started once at start-up."""
    global _jobs_thread
    if _jobs_thread and _jobs_thread.is_alive():
        return

    def loop():
        while not _stop.wait(TICK_SECONDS):
            try:
                if not desk_on():
                    tdb = get_tickets_db() if get_tickets_db else None
                    jobs_agent_tick(tdb, edition=get_edition())
                    hr_agent_tick(tdb, edition=get_edition())
            except Exception as e:  # noqa: BLE001
                log.warning("Jobs agent timer tick failed: %s", e)

    _jobs_thread = threading.Thread(target=loop, name="jobs-agent", daemon=True)
    _jobs_thread.start()
