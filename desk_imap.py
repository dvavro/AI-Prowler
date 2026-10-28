"""
desk_imap.py — AI-Prowler Service Desk, Phase 2: email intake by IMAP polling.

Uses the email account AI-Prowler already sends from (email_config.json:
username / password; IMAP host = cfg["imap_host"] if set, else the SMTP host
with "smtp." changed to "imap."; port 993, SSL). Only runs when the owner
turns on "email_intake" in Service Desk settings.

It never disturbs the owner's normal inbox: messages are read with
BODY.PEEK (stay unread), and only a message Service Desk actually used
(threaded onto a ticket or filed as a new one) is marked read. Every
processed Message-ID is remembered so nothing is handled twice.
"""
from __future__ import annotations

import email
import email.header
import email.policy
import imaplib
import logging
import threading
import time

import desk_db

log = logging.getLogger("desk_imap")

POLL_SECONDS = 120
LOOKBACK_DAYS = 3


def imap_settings(cfg: dict) -> dict | None:
    """Host/port/user/password for IMAP from the AI-Prowler email config, or
    None when this account can't be polled (Outlook-only, or not set up)."""
    if not cfg:
        return None
    host = (cfg.get("imap_host") or "").strip()
    if not host:
        smtp = (cfg.get("smtp_host") or "").strip().lower()
        if not smtp:
            return None
        host = "imap." + smtp[5:] if smtp.startswith("smtp.") else smtp
    user = (cfg.get("username") or "").strip()
    pw = cfg.get("password") or ""
    if not user or not pw:
        return None
    return {"host": host, "port": int(cfg.get("imap_port") or 993), "user": user, "password": pw}


def _text_of(msg) -> str:
    if msg.is_multipart():
        part = msg.get_body(preferencelist=("plain", "html"))
        if part is None:
            return ""
        content = part.get_content()
    else:
        content = msg.get_content()
    if isinstance(content, bytes):
        content = content.decode("utf-8", "replace")
    if msg.get_content_type() == "text/html" or "<html" in content[:200].lower():
        import re
        content = re.sub(r"<[^>]+>", " ", content)
    return content


def _seen(db_path: str, message_id: str) -> bool:
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS processed_mail (message_id TEXT PRIMARY KEY, at TEXT)")
        return bool(conn.execute("SELECT 1 FROM processed_mail WHERE message_id = ?",
                                 (message_id,)).fetchone())
    finally:
        conn.close()


def _remember(db_path: str, message_id: str) -> None:
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("INSERT OR IGNORE INTO processed_mail (message_id, at) VALUES (?, ?)",
                     (message_id, desk_db.utcnow_iso()))
    finally:
        conn.close()


def poll_once(db_path: str, cfg: dict, handle, *, imap_factory=imaplib.IMAP4_SSL) -> dict:
    """One pass over recent mail. `handle(from, subject, body) -> str` is
    desk_inbound.handle_email bound to the edition/base URL. Returns counts."""
    s = imap_settings(cfg)
    if s is None:
        return {"ok": False, "error": "this email account can't be read by IMAP (Outlook-only or not set up)"}
    counts = {"ok": True, "checked": 0, "threaded": 0, "created": 0, "ignored": 0}
    box = imap_factory(s["host"], s["port"])
    try:
        box.login(s["user"], s["password"])
        box.select("INBOX")
        since = time.strftime("%d-%b-%Y", time.gmtime(time.time() - LOOKBACK_DAYS * 86400))
        typ, data = box.search(None, "SINCE", since)
        for num in (data[0].split() if data and data[0] else []):
            typ, parts = box.fetch(num, "(BODY.PEEK[])")
            raw = next((p[1] for p in parts if isinstance(p, tuple)), None)
            if not raw:
                continue
            msg = email.message_from_bytes(raw, policy=email.policy.default)
            mid = (msg.get("Message-ID") or "").strip() or f"num:{num.decode()}"
            if _seen(db_path, mid):
                continue
            counts["checked"] += 1
            subject = str(email.header.make_header(email.header.decode_header(msg.get("Subject", ""))))
            result = handle(msg.get("From", ""), subject, _text_of(msg))
            counts[result] = counts.get(result, 0) + 1
            _remember(db_path, mid)
            if result in ("threaded", "created"):
                box.store(num, "+FLAGS", "\\Seen")
    finally:
        try:
            box.logout()
        except Exception:  # noqa: BLE001
            pass
    return counts


_thread = None
_stop = threading.Event()


def start_poller(get_db, get_cfg, handle_factory, is_on) -> None:
    """Start the background poller once. Each round re-reads the switch, so
    turning email intake off (or Service Desk off) stops it at the next round."""
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()

    def loop():
        while not _stop.wait(POLL_SECONDS):
            try:
                db = get_db()
                if not is_on() or not desk_db.get_settings(db).get("email_intake"):
                    continue
                out = poll_once(db, get_cfg(), handle_factory())
                if not out.get("ok"):
                    log.warning("Service Desk email intake: %s", out.get("error"))
            except Exception as e:  # noqa: BLE001
                log.warning("Service Desk email intake round failed: %s", e)

    _thread = threading.Thread(target=loop, name="desk-imap", daemon=True)
    _thread.start()


def stop_poller() -> None:
    _stop.set()
