"""
desk_inbound.py — AI-Prowler Service Desk, Phase 2: inbound texts and emails.

SMS (called from both /sms-webhook handlers AFTER their STOP/START/HELP
handling, so consent keywords never reach a ticket):
  1. From a team member's phone -> ignored (that's crew chatter, not a customer).
  2. The sender has an open customer or subcontractor ticket -> the text is
     added to that ticket's thread as their reply.
  3. Otherwise the owner's "sms_new_request_mode" decides:
       off    nothing (default — existing installs already get job texts)
       create open a ticket and text back its status link
       ask    text back "Want us to open a service request? Reply YES or NO"
              and wait (24 h) for the answer
       link   text back the request-form link
  Returns the text to send back in the TwiML reply ("" = no reply).

Email (from the IMAP poller):
  * Subject carries [T-####] and the sender is that ticket's contact -> reply
    added to the thread.
  * Otherwise "email_new_request_mode": off (default) or create.
"""
from __future__ import annotations

import datetime
import email.utils
import re

import desk_db
import desk_portal
import desk_rules as rules
from db_access import utcnow_iso

PENDING_HOURS = 24
YES = {"YES", "Y", "YEP", "YEAH", "SURE", "OK", "OKAY"}
NO = {"NO", "N", "NOPE"}


def _open_thread(db_path: str, *, phone: str | None = None, email_addr: str | None = None):
    conn = desk_db.get_connection(db_path)
    try:
        col, val = ("c.phone", phone) if phone else ("c.email", email_addr)
        r = conn.execute(
            f"SELECT t.*, c.contact_type AS c_type FROM tickets t JOIN customer_contacts c "
            f"ON t.contact_id = c.contact_id WHERE {col} = ? AND t.state != 'Closed' "
            f"AND t.kind IN ('external', 'subcontractor') ORDER BY t.last_edited_at DESC LIMIT 1",
            (val,)).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def _first_line(body: str, n: int = 80) -> str:
    line = next((l.strip() for l in (body or "").splitlines() if l.strip()), "") or "Request by text"
    return line if len(line) <= n else line[: n - 1].rstrip() + "…"


def _file_from(db_path, contact, body, *, source, edition, base_url, title=None):
    actor = desk_portal.actor_for(contact)
    t = desk_db.create_ticket(db_path, title=title or _first_line(body), kind=rules.EXTERNAL,
                              actor=actor, edition=edition, description=(body or "")[:5000],
                              source=source, contact_id=contact["contact_id"],
                              customer_id=contact.get("linked_customer_id"))
    url = desk_portal.link_url(base_url, desk_portal.issue_link(db_path, t["ticket_id"],
                                                                 contact["contact_id"]))
    return t, url


def handle_sms(db_path: str, from_number: str, body: str, *, edition: str,
               team_phones=(), base_url: str = "", business: str = "", now=None) -> str:
    phone = desk_db._norm_phone(from_number)
    text = (body or "").strip()
    if not phone or not text:
        return ""
    if phone in {desk_db._norm_phone(p) for p in team_phones if p}:
        return ""
    who = f"{business}: " if business else ""

    open_t = _open_thread(db_path, phone=phone)
    if open_t:
        contact = desk_db.get_contact(db_path, open_t["contact_id"])
        desk_db.add_message(db_path, open_t["ticket_id"], text, actor=desk_portal.actor_for(contact),
                            edition=edition, visibility="public", channel="sms")
        return ""

    now_dt = now or datetime.datetime.now(datetime.timezone.utc)
    cutoff = (now_dt - datetime.timedelta(hours=PENDING_HOURS)).isoformat(timespec="seconds")
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("DELETE FROM sms_pending WHERE asked_at < ?", (cutoff,))
        pending = conn.execute("SELECT * FROM sms_pending WHERE phone = ?", (phone,)).fetchone()
        pending = dict(pending) if pending else None
    finally:
        conn.close()

    word = re.sub(r"[^A-Z]", "", text.upper())
    if pending and word in YES | NO:
        conn = desk_db.get_connection(db_path)
        try:
            conn.execute("DELETE FROM sms_pending WHERE phone = ?", (phone,))
        finally:
            conn.close()
        if word in NO:
            return f"{who}OK — we won't open a request. Text us any time."
        contact = desk_db.upsert_contact(db_path, phone=phone, contact_type="customer",
                                         actor={"id": "sms", "role": "customer"})
        t, url = _file_from(db_path, contact, pending["body"], source="sms", edition=edition,
                            base_url=base_url)
        return f"{who}Thanks — we opened request {t['ticket_id']}. Track it or add photos: {url}"

    mode = desk_db.get_settings(db_path).get("sms_new_request_mode", "off")
    if mode == "off":
        return ""
    if mode == "link":
        base = (base_url or "").rstrip("/")
        return f"{who}To open a service request, use this form: {base}/support/new" if base else ""
    if mode == "ask":
        conn = desk_db.get_connection(db_path)
        try:
            conn.execute("INSERT INTO sms_pending (phone, body, asked_at) VALUES (?, ?, ?) "
                         "ON CONFLICT(phone) DO UPDATE SET body = excluded.body, asked_at = excluded.asked_at",
                         (phone, text[:5000], now_dt.isoformat(timespec="seconds")))
        finally:
            conn.close()
        return f"{who}Would you like us to open a service request for this? Reply YES or NO."
    # create
    contact = desk_db.upsert_contact(db_path, phone=phone, contact_type="customer",
                                     actor={"id": "sms", "role": "customer"})
    t, url = _file_from(db_path, contact, text, source="sms", edition=edition, base_url=base_url)
    return f"{who}Thanks — we opened request {t['ticket_id']}. Track it or add photos: {url}"


# ── email ────────────────────────────────────────────────────────────────────

_QUOTE_START = re.compile(r"^(On .{5,200} wrote:|-{2,}\s*Original Message\s*-{2,}|From:\s.+)$",
                          re.IGNORECASE)


def strip_quoted(body: str) -> str:
    """Keep only the new part of an email reply."""
    out = []
    for line in (body or "").splitlines():
        if _QUOTE_START.match(line.strip()):
            break
        if line.lstrip().startswith(">"):
            continue
        out.append(line)
    return "\n".join(out).strip()


def handle_email(db_path: str, from_header: str, subject: str, body: str, *, edition: str,
                 team_emails=(), base_url: str = "") -> str:
    """Returns what happened: threaded | created | ignored."""
    addr = (email.utils.parseaddr(from_header or "")[1] or "").strip().lower()
    if not addr or addr in {e.strip().lower() for e in team_emails if e}:
        return "ignored"
    text = strip_quoted(body)
    m = re.search(r"\[(T-\d{4,})\]", subject or "")
    if m:
        t = desk_db.get_ticket(db_path, m.group(1))
        c = desk_db.get_contact(db_path, t["contact_id"]) if t and t.get("contact_id") else None
        if t and c and (c.get("email") or "").lower() == addr and text:
            if t["state"] == rules.CLOSED:
                return "ignored"           # a reply to a closed ticket: they can reopen from the link
            desk_db.add_message(db_path, t["ticket_id"], text, actor=desk_portal.actor_for(c),
                                edition=edition, visibility="public", channel="email")
            return "threaded"
        return "ignored"
    if desk_db.get_settings(db_path).get("email_new_request_mode", "off") != "create" or not text:
        return "ignored"
    name = email.utils.parseaddr(from_header or "")[0]
    contact = desk_db.upsert_contact(db_path, name=name, email=addr, contact_type="customer",
                                     actor={"id": "email", "role": "customer"})
    t, url = _file_from(db_path, contact, text, source="email", edition=edition,
                        base_url=base_url, title=_first_line(subject or text))
    desk_portal._send("email", addr, f"We got your request [{t['ticket_id']}]",
                      f"We got your request {t['ticket_id']}: {t['title']}. Track it here: {url}")
    return "created"
