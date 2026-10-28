"""
desk_portal.py — AI-Prowler Service Desk, Phase 2: the public side.

  /support/new                 request form (customer verifies phone/email with a code)
  /support/t/<token>           a customer's or subcontractor's status page for ONE ticket
  /support-api/*               the JSON behind both pages (no sign-in; the code or
                               the status-link token is the credential)

Status links: a random 32-byte token, stored only as a SHA-256. A link works
while its ticket is open and for 30 days after it closes; the owner can
revoke all links for a ticket. A link shows only the public thread, never
internal notes, internal files, staff last names or the event log
(desk_db.get_ticket_detail trims for outside parties).

Abuse controls on the request form: hidden honeypot field, 6-digit code
(10 minutes, 5 tries), and at most 5 codes and 5 tickets per hour per phone/
email and per IP. Every permission still goes through desk_rules.can() with
the contact as a 'customer' or 'subcontractor' actor.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
import secrets

import desk_attachments
import desk_db
import desk_rules as rules
from db_access import utcnow_iso

LINK_DAYS_AFTER_CLOSE = 30
CODE_TTL_MINUTES = 10
CODE_MAX_ATTEMPTS = 5
RATE_LIMITS = {"code": (5, 3600), "ticket": (5, 3600)}
JSON = b"application/json"

# Injected by ai_prowler_mcp.py through desk_alerts (fn(channel, to, subject, text) -> bool)
send_fn = None


def _h(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now(now=None) -> datetime.datetime:
    return now or datetime.datetime.now(datetime.timezone.utc)


def _iso(dt: datetime.datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _send(channel, to, subject, text) -> bool:
    if not send_fn:
        return False
    try:
        return bool(send_fn(channel, to, subject, text))
    except Exception:  # noqa: BLE001
        return False


# ── status links ─────────────────────────────────────────────────────────────

def issue_link(db_path: str, ticket_id: str, contact_id: str) -> str:
    token = secrets.token_urlsafe(32)
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("INSERT INTO ticket_links (token_hash, ticket_id, contact_id, created_at) "
                     "VALUES (?, ?, ?, ?)", (_h(token), ticket_id, contact_id, utcnow_iso()))
    finally:
        conn.close()
    return token


def revoke_links(db_path: str, ticket_id: str, *, actor=None, edition=rules.BUSINESS) -> int:
    t = desk_db.get_ticket(db_path, ticket_id, actor=actor, edition=edition)
    if t is None:
        raise desk_db.NotFoundError(f"no ticket {ticket_id} that you can see")
    if rules.normalize_actor(actor)["role"] not in (rules.OWNER, rules.MANAGER):
        raise desk_db.DeskError("only the owner or a manager can revoke status links")
    conn = desk_db.get_connection(db_path)
    try:
        return conn.execute("UPDATE ticket_links SET revoked = 1 WHERE ticket_id = ? AND revoked = 0",
                            (ticket_id,)).rowcount
    finally:
        conn.close()


def link_url(base_url: str, token: str) -> str:
    base = (base_url or "").rstrip("/")
    return f"{base}/support/t/{token}" if base else f"/support/t/{token}"


def actor_for(contact: dict) -> dict:
    return {"id": f"contact:{contact['contact_id']}", "role": contact["contact_type"],
            "contact_id": contact["contact_id"], "name": contact.get("name") or ""}


def resolve_link(db_path: str, token: str, now=None) -> tuple[dict, dict, dict]:
    """(ticket, contact, actor) for a valid status-link token, else NotFoundError
    (one answer for unknown, revoked and expired, so links can't be probed)."""
    nf = desk_db.NotFoundError("this status link is not valid any more — ask for a new one")
    if not token or len(token) > 200:
        raise nf
    conn = desk_db.get_connection(db_path)
    try:
        r = conn.execute("SELECT * FROM ticket_links WHERE token_hash = ?", (_h(token),)).fetchone()
        if r is None or r["revoked"]:
            raise nf
        t = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (r["ticket_id"],)).fetchone()
        c = conn.execute("SELECT * FROM customer_contacts WHERE contact_id = ?",
                         (r["contact_id"],)).fetchone()
    finally:
        conn.close()
    if t is None or c is None or t["contact_id"] != c["contact_id"]:
        raise nf
    t, c = dict(t), dict(c)
    if t["state"] == rules.CLOSED and t["closed_at"]:
        closed = datetime.datetime.fromisoformat(t["closed_at"].replace("Z", "+00:00"))
        if closed.tzinfo is None:
            closed = closed.replace(tzinfo=datetime.timezone.utc)
        if _now(now) - closed > datetime.timedelta(days=LINK_DAYS_AFTER_CLOSE):
            raise nf
    return t, c, actor_for(c)


# ── rate limits ──────────────────────────────────────────────────────────────

def _rate_ok(conn, kind: str, keys: list, now: datetime.datetime) -> bool:
    limit, window = RATE_LIMITS[kind]
    since = _iso(now - datetime.timedelta(seconds=window))
    conn.execute("DELETE FROM portal_hits WHERE at < ?", (_iso(now - datetime.timedelta(days=1)),))
    for k in keys:
        n = conn.execute("SELECT COUNT(*) FROM portal_hits WHERE key = ? AND at >= ?",
                         (f"{kind}:{k}", since)).fetchone()[0]
        if n >= limit:
            return False
    for k in keys:
        conn.execute("INSERT INTO portal_hits (key, at) VALUES (?, ?)", (f"{kind}:{k}", _iso(now)))
    return True


# ── request form ─────────────────────────────────────────────────────────────

def start_request(db_path: str, *, name: str = "", phone: str = "", email: str = "",
                  ip: str = "", honeypot: str = "", now=None) -> dict:
    """Step 1: send a 6-digit code to the customer's phone (preferred) or email."""
    s = desk_db.get_settings(db_path)
    if not s.get("portal_enabled"):
        raise desk_db.DeskError("online requests are turned off — please call or text us")
    if (honeypot or "").strip():
        return {"ok": True, "contact_id": "", "sent_via": "sms"}      # quietly drop bots
    if not (phone or email):
        raise desk_db.DeskError("enter a mobile number or an email address")
    c = desk_db.upsert_contact(db_path, name=(name or "").strip()[:80], phone=phone or None,
                               email=email or None, contact_type="customer",
                               actor={"id": "portal", "role": "customer"})
    now = _now(now)
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")     # count + record the hit as one step
        if not _rate_ok(conn, "code", [f"ip:{ip}", f"c:{c['contact_id']}"], now):
            conn.execute("ROLLBACK")
            raise desk_db.DeskError("too many codes requested — please try again in an hour")
        code = f"{secrets.randbelow(1_000_000):06d}"
        conn.execute(
            "INSERT INTO verify_codes (contact_id, code_hash, expires_at, attempts, sent_at) "
            "VALUES (?, ?, ?, 0, ?) ON CONFLICT(contact_id) DO UPDATE SET code_hash = excluded.code_hash, "
            "expires_at = excluded.expires_at, attempts = 0, sent_at = excluded.sent_at",
            (c["contact_id"], _h(f"{c['contact_id']}:{code}"),
             _iso(now + datetime.timedelta(minutes=CODE_TTL_MINUTES)), _iso(now)))
        conn.execute("COMMIT")
    except desk_db.DeskError:
        raise
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    channel, to = ("sms", c["phone"]) if c.get("phone") else ("email", c["email"])
    text = f"Your service request code is {code}. It expires in {CODE_TTL_MINUTES} minutes."
    if not _send(channel, to, "Your service request code", text):
        raise desk_db.DeskError("we couldn't send a code right now — please call or text us")
    return {"ok": True, "contact_id": c["contact_id"], "sent_via": channel}


def verify_and_file(db_path: str, *, contact_id: str, code: str, title: str,
                    description: str = "", job_id: str = "", ip: str = "",
                    edition: str = rules.BUSINESS, base_url: str = "", now=None) -> dict:
    """Step 2: check the code, then file the ticket and return its status link."""
    now = _now(now)
    bad = desk_db.DeskError("that code is not right — check it or ask for a new one")
    # Check the code and use it up in ONE locked step (2026-10-28): a double-
    # tapped Submit used to pass the check twice and file two tickets. A
    # refusal still commits (a wrong try counts; an expired code is cleared).
    refused = None
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        r = conn.execute("SELECT * FROM verify_codes WHERE contact_id = ?", (contact_id,)).fetchone()
        if r is None:
            refused = bad
        elif r["attempts"] >= CODE_MAX_ATTEMPTS or r["expires_at"] < _iso(now):
            conn.execute("DELETE FROM verify_codes WHERE contact_id = ?", (contact_id,))
            refused = desk_db.DeskError("that code has expired — ask for a new one")
        elif not secrets.compare_digest(r["code_hash"], _h(f"{contact_id}:{(code or '').strip()}")):
            conn.execute("UPDATE verify_codes SET attempts = attempts + 1 WHERE contact_id = ?",
                         (contact_id,))
            refused = bad
        elif not _rate_ok(conn, "ticket", [f"ip:{ip}", f"c:{contact_id}"], now):
            refused = desk_db.DeskError("too many requests today — please call or text us")
        else:
            conn.execute("DELETE FROM verify_codes WHERE contact_id = ?", (contact_id,))
            conn.execute("UPDATE customer_contacts SET verified_at = ? WHERE contact_id = ?",
                         (_iso(now), contact_id))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    if refused is not None:
        raise refused
    contact = desk_db.get_contact(db_path, contact_id)
    actor = actor_for(contact)
    t = desk_db.create_ticket(db_path, title=(title or "").strip()[:200], kind=rules.EXTERNAL,
                              actor=actor, edition=edition, description=(description or "")[:5000],
                              source="portal", contact_id=contact_id,
                              customer_id=contact.get("linked_customer_id"),
                              job_id=(job_id or "").strip() or None)
    token = issue_link(db_path, t["ticket_id"], contact_id)
    url = link_url(base_url, token)
    channel, to = ("sms", contact["phone"]) if contact.get("phone") else ("email", contact["email"])
    _send(channel, to, f"We got your request [{t['ticket_id']}]",
          f"We got your request {t['ticket_id']}: {t['title']}. Track it here: {url}")
    return {"ok": True, "ticket_id": t["ticket_id"], "token": token, "url": url}


# ── things an outside party does from the status page ────────────────────────

def status_view(db_path: str, token: str, *, edition: str, now=None) -> dict:
    t, c, actor = resolve_link(db_path, token, now)
    detail = desk_db.get_ticket_detail(db_path, t["ticket_id"], actor=actor, edition=edition)
    s = desk_db.get_settings(db_path)
    can = lambda **kw: bool(rules.can(actor, "change_state", t, edition=edition, now=now, **kw))  # noqa: E731
    detail.update({
        "who": {"name": c.get("name") or "", "role": c["contact_type"]},
        "can_confirm": can(to_state=rules.CLOSED, reason="") if t["state"] == rules.FIXED else False,
        "can_reject": can(to_state=rules.IN_PROGRESS, reason="x") if t["state"] == rules.FIXED else False,
        "can_reopen": can(to_state=rules.ASSIGNED, reason="x") if t["state"] == rules.CLOSED else False,
        "can_mark_done": can(to_state=rules.FIXED) if c["contact_type"] == "subcontractor" else False,
        "can_rate": (c["contact_type"] == "customer" and t["state"] == rules.CLOSED
                     and t["csat_score"] is None and bool(s.get("csat_enabled"))),
    })
    return detail


def set_csat(db_path: str, token: str, score, comment: str = "", *, edition: str, now=None) -> dict:
    t, c, actor = resolve_link(db_path, token, now)
    try:
        score = int(score)
    except (TypeError, ValueError):
        raise desk_db.DeskError("rating must be 1 to 5")
    if not 1 <= score <= 5:
        raise desk_db.DeskError("rating must be 1 to 5")
    if c["contact_type"] != "customer" or t["state"] != rules.CLOSED:
        raise desk_db.DeskError("you can rate a request once it is closed")
    if t["csat_score"] is not None:
        raise desk_db.DeskError("thanks — this request was already rated")
    with desk_db.ticket_transaction(db_path) as (conn, touched):
        conn.execute("UPDATE tickets SET csat_score = ?, csat_comment = ? WHERE ticket_id = ?",
                     (score, (comment or "").strip()[:1000] or None, t["ticket_id"]))
        desk_db._event(conn, t["ticket_id"], actor["id"], "csat", to_value=str(score),
                       reason=(comment or "").strip()[:200] or None)
        desk_db._touch(conn, t["ticket_id"], actor["id"])
        touched.add(t["ticket_id"])
    return {"ok": True}


# ── /support-api router ──────────────────────────────────────────────────────

def _j(status, payload):
    return status, JSON, json.dumps(payload, default=str).encode("utf-8")


def _body(raw: bytes) -> dict:
    if not raw:
        return {}
    try:
        v = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise desk_db.DeskError("the request body is not valid JSON")
    if not isinstance(v, dict):
        raise desk_db.DeskError("the request body must be a JSON object")
    return v


def route(method: str, path: str, *, query: dict, body: bytes, content_type: str, ip: str,
          db_path: str, edition: str, base_url: str = "", business: str = "", now=None) -> tuple:
    sub = path[len("/support-api"):] or "/"
    try:
        return _route(method.upper(), sub, query or {}, body or b"", content_type or "", ip,
                      db_path, edition, base_url, business, now)
    except desk_db.NotFoundError as e:
        return _j(404, {"ok": False, "error": "not_found", "message": str(e)})
    except desk_db.DeskError as e:
        return _j(400, {"ok": False, "error": "refused", "message": str(e)})


def _route(method, sub, q, raw, ctype, ip, db, edition, base_url, business, now):
    if sub == "/info" and method == "GET":
        s = desk_db.get_settings(db)
        return _j(200, {"ok": True, "business": business or "", "portal_enabled": bool(s.get("portal_enabled"))})
    if sub == "/start" and method == "POST":
        b = _body(raw)
        return _j(200, start_request(db, name=b.get("name", ""), phone=b.get("phone", ""),
                                     email=b.get("email", ""), ip=ip, honeypot=b.get("website", ""),
                                     now=now))
    if sub == "/verify" and method == "POST":
        b = _body(raw)
        if not (b.get("title") or "").strip():
            raise desk_db.DeskError("tell us briefly what you need")
        out = verify_and_file(db, contact_id=b.get("contact_id", ""), code=b.get("code", ""),
                              title=b.get("title", ""), description=b.get("description", ""),
                              job_id=b.get("job_id", ""), ip=ip, edition=edition,
                              base_url=base_url, now=now)
        return _j(201, out)

    m = re.fullmatch(r"/t/([A-Za-z0-9_-]{20,100})(/.*)?", sub)
    if not m:
        return _j(404, {"ok": False, "error": "unknown_route", "message": "not found"})
    token, rest = m.group(1), m.group(2) or ""
    if rest == "" and method == "GET":
        return _j(200, {"ok": True, "ticket": status_view(db, token, edition=edition, now=now),
                        "business": business or ""})
    t, c, actor = resolve_link(db, token, now)
    tid = t["ticket_id"]
    if rest == "/reply" and method == "POST":
        b = _body(raw)
        desk_db.add_message(db, tid, b.get("body", ""), actor=actor, edition=edition,
                            visibility="public", channel="portal")
        return _j(201, {"ok": True})
    if rest == "/state" and method == "POST":
        b = _body(raw)
        desk_db.change_state(db, tid, b.get("to_state", ""), actor=actor, edition=edition,
                             reason=b.get("reason", ""), now=now)
        return _j(200, {"ok": True})
    if rest == "/rating" and method == "POST":
        b = _body(raw)
        return _j(200, set_csat(db, token, b.get("score"), b.get("comment", ""), edition=edition,
                                now=now))
    if rest == "/attachments" and method == "POST":
        import desk_http
        fields, files = desk_http.parse_multipart(raw, ctype)
        if not files:
            raise desk_db.DeskError("no file in the upload")
        saved = [desk_attachments.store_attachment(db, tid, data, name, actor=actor,
                                                   edition=edition) for name, data in files[:5]]
        return _j(201, {"ok": True, "attachments": [{"attachment_id": a["attachment_id"],
                                                     "filename": a["filename"]} for a in saved]})
    m2 = re.fullmatch(r"/attachments/(\d+)", rest)
    if m2 and method == "GET":
        att, path = desk_db.get_attachment(db, int(m2.group(1)), actor=actor, edition=edition)
        if att["ticket_id"] != tid:
            raise desk_db.NotFoundError("no such attachment")
        if str(q.get("thumb", "")) == "1" and att.get("thumb_path"):
            path = path.parent.parent / att["thumb_path"]
        if not path.exists():
            raise desk_db.NotFoundError("that file is missing")
        return 200, (att.get("mime") if path.name == att["filename"] else "image/jpeg").encode(), path.read_bytes()
    return _j(404, {"ok": False, "error": "unknown_route", "message": "not found"})


def static_page(path: str) -> tuple:
    """/support/new and /support/t/<token> both serve desk/support.html."""
    import desk_http
    st, ct, body, rel = desk_http.static_file("/desk/support.html")
    return st, ct, body
