"""
desk_backup.py — AI-Prowler Service Desk, Phase 3: backup and restore.

backup_now()   SQLite online Backup API (safe while people work) -> a dated zip
               holding the database copy, every ticket's folder (ticket.json and,
               unless switched off, its photos/documents) and the settings. The
               copy is checked with PRAGMA integrity_check and marked verified or
               failed. Optional second destination (drive, NAS, synced folder).
prune()        keeps 14 daily, 8 weekly and 12 monthly scheduled backups by
               default; safety backups (manual, pre-import, pre-restore,
               pre-upgrade) are kept 30 days.
restore()      whole database + folders, or ONE ticket. Owner only, needs
               confirm=True, and takes a safety backup of the live data first.
due()          is a scheduled backup due now (hourly / daily / weekly at the hour)?
"""
from __future__ import annotations

import datetime
import io
import json
import re
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path

import desk_db
import desk_files
import desk_rules as rules
from db_access import utcnow_iso

SAFETY_KEEP_DAYS = 30
SAFETY_TRIGGERS = ("manual", "pre-import", "pre-restore", "pre-upgrade")
_NAME = re.compile(r"^desk-(\d{8})-(\d{6})-([a-z-]+)\.zip$")


def backup_dir(db_path: str) -> Path:
    return desk_db.root_for(db_path) / "backups"


def _parse_name(name: str):
    m = _NAME.match(name)
    if not m:
        return None
    at = datetime.datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")
    return at, m.group(3)


def backup_now(db_path: str, trigger: str = "manual", *, now: datetime.datetime | None = None) -> dict:
    """Make one backup. Returns {"name", "path", "bytes", "verified", "second_copy"}."""
    trigger = re.sub(r"[^a-z-]", "", trigger.lower()) or "manual"
    now = now or datetime.datetime.now()
    settings = desk_db.get_settings(db_path)
    root = desk_db.root_for(db_path)
    out_dir = backup_dir(db_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"desk-{now:%Y%m%d-%H%M%S}-{trigger}.zip"
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / desk_db.DEFAULT_DB_FILENAME
        src = sqlite3.connect(db_path)
        dst = sqlite3.connect(str(copy))
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        chk = sqlite3.connect(str(copy))
        try:
            verified = chk.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        finally:
            chk.close()
        path = out_dir / name
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(copy, desk_db.DEFAULT_DB_FILENAME)
            tickets = root / "tickets"
            if tickets.exists():
                for f in tickets.rglob("*"):
                    if not f.is_file() or f.suffix.endswith(".tmp"):
                        continue
                    if not settings.get("backup_attachments") and desk_files.ATTACHMENTS_DIR in f.parts:
                        continue
                    z.write(f, f.relative_to(root).as_posix())
            z.writestr("settings.json", json.dumps(settings, indent=2))
            z.writestr("manifest.json", json.dumps({"format": "ai-prowler-service-desk-backup", "version": 1,
                                                    "trigger": trigger, "made_at": utcnow_iso(),
                                                    "verified": verified,
                                                    "attachments": bool(settings.get("backup_attachments"))}))
    second = ""
    if settings.get("backup_second_dir"):
        try:
            d2 = Path(settings["backup_second_dir"])
            d2.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, d2 / name)
            second = str(d2 / name)
        except OSError as e:
            second = f"failed: {e}"
    return {"name": name, "path": str(path), "bytes": path.stat().st_size, "verified": verified,
            "second_copy": second, "trigger": trigger}


def list_backups(db_path: str) -> list[dict]:
    out = []
    d = backup_dir(db_path)
    if not d.exists():
        return out
    for f in sorted(d.glob("desk-*.zip"), reverse=True):
        parsed = _parse_name(f.name)
        if not parsed:
            continue
        verified = None
        try:
            with zipfile.ZipFile(f) as z:
                verified = json.loads(z.read("manifest.json")).get("verified")
        except (zipfile.BadZipFile, KeyError, ValueError):
            verified = False
        out.append({"name": f.name, "made_at": parsed[0].isoformat(timespec="seconds"),
                    "trigger": parsed[1], "bytes": f.stat().st_size, "verified": verified})
    return out


def prune(db_path: str, *, now: datetime.datetime | None = None) -> list[str]:
    """Delete backups beyond the retention rules. Returns deleted names."""
    s = desk_db.get_settings(db_path)
    now = now or datetime.datetime.now()
    keep, seen_d, seen_w, seen_m = set(), set(), set(), set()
    items = list_backups(db_path)
    for b in items:                                   # newest first
        at = datetime.datetime.fromisoformat(b["made_at"])
        if b["trigger"] in SAFETY_TRIGGERS:
            if now - at <= datetime.timedelta(days=SAFETY_KEEP_DAYS):
                keep.add(b["name"])
            continue
        day, week, month = at.date(), at.isocalendar()[:2], (at.year, at.month)
        if day not in seen_d and len(seen_d) < int(s["backup_keep_daily"]):
            seen_d.add(day)
            keep.add(b["name"])
        if week not in seen_w and len(seen_w) < int(s["backup_keep_weekly"]):
            seen_w.add(week)
            keep.add(b["name"])
        if month not in seen_m and len(seen_m) < int(s["backup_keep_monthly"]):
            seen_m.add(month)
            keep.add(b["name"])
    gone = []
    for b in items:
        if b["name"] not in keep:
            (backup_dir(db_path) / b["name"]).unlink(missing_ok=True)
            gone.append(b["name"])
    return gone


def due(settings: dict, last_run: str | None, now: datetime.datetime) -> bool:
    if not settings.get("backup_enabled"):
        return False
    last = datetime.datetime.fromisoformat(last_run) if last_run else None
    freq, hour = settings.get("backup_frequency", "daily"), int(settings.get("backup_hour", 2))
    if freq == "hourly":
        return last is None or now - last >= datetime.timedelta(hours=1)
    slot = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if freq == "weekly":
        slot -= datetime.timedelta(days=(slot.weekday() - 6) % 7)     # Sundays
    if now < slot:
        slot -= datetime.timedelta(days=7 if freq == "weekly" else 1)
    return last is None or last < slot


def restore(db_path: str, name: str, *, actor=None, edition: str = rules.BUSINESS,
            confirm: bool = False, ticket_id: str = "") -> dict:
    d = rules.can(actor, "restore", edition=edition)
    if not d:
        raise desk_db.DeskError(d.reason)
    path = backup_dir(db_path) / Path(name).name
    if not _parse_name(path.name) or not path.exists():
        raise desk_db.DeskError(f"no backup named {name}")
    if not confirm:
        what = f"ticket {ticket_id}" if ticket_id else "ALL Service Desk data"
        return {"ok": False, "needs_confirm": True,
                "message": f"Restoring {path.name} replaces {what} with the backup's copy. A safety "
                           f"backup of the live data is taken first. Call again with confirm=True."}
    safety = backup_now(db_path, "pre-restore")
    root = desk_db.root_for(db_path)
    with zipfile.ZipFile(path) as z:
        if ticket_id:
            tid = ticket_id.strip().upper()
            json_name = next((n for n in z.namelist() if re.fullmatch(rf"tickets/\d{{4}}/{tid}/ticket\.json", n)), None)
            if not json_name:
                raise desk_db.DeskError(f"{tid} is not in {path.name}")
            doc = json.loads(z.read(json_name))
            conn = desk_db.get_connection(db_path)
            try:
                conn.execute("BEGIN IMMEDIATE")
                for table in ("ticket_watchers", "ticket_relations", "ticket_attachments", "ticket_messages",
                              "ticket_events", "tickets"):
                    conn.execute(f"DELETE FROM {table} WHERE ticket_id = ?", (tid,))
                conn.execute("COMMIT")
                desk_files._insert_from_doc(conn, doc)
                folder_prefix = json_name.rsplit("/", 1)[0] + "/"
                for n in z.namelist():
                    if n.startswith(folder_prefix) and not n.endswith("/"):
                        dest = root / n
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(z.read(n))
                desk_files.write_ticket_json(root, conn, tid)
            finally:
                conn.close()
            return {"ok": True, "restored": tid, "safety_backup": safety["name"]}
        with tempfile.TemporaryDirectory() as tmp:
            z.extract(desk_db.DEFAULT_DB_FILENAME, tmp)
            src = sqlite3.connect(str(Path(tmp) / desk_db.DEFAULT_DB_FILENAME))
            dst = sqlite3.connect(db_path)
            try:
                src.backup(dst)                     # online copy INTO the live file
            finally:
                dst.close()
                src.close()
        tickets = root / "tickets"
        if tickets.exists():
            shutil.rmtree(tickets)
        for n in z.namelist():
            if n.startswith("tickets/") and not n.endswith("/"):
                dest = root / n
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(z.read(n))
    return {"ok": True, "restored": "all", "safety_backup": safety["name"]}
