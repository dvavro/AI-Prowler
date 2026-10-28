"""
desk_scheduler.py — AI-Prowler Service Desk, Phase 3: the timed jobs.

One background thread (both modes), started by ai_prowler_mcp.py:
  * every 5 minutes (Business): SLA warnings / breaches / escalations
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

    s = desk_db.get_settings(db_path)
    today = now.date().isoformat()
    if now.hour >= int(s.get("digest_hour", 7)) and _get(db_path, "last_digest_date") != today:
        text = desk_reports.digest_text(db_path, edition=edition, now=utc)
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
