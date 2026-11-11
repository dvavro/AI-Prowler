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
RATE_LIMITS = {"code": (5, 3600), "ticket": (5, 3600), "ask": (10, 3600)}
JSON = b"application/json"

# Injected by ai_prowler_mcp.py through desk_alerts (fn(channel, to, subject, text) -> bool)
send_fn = None
# Injected by ai_prowler_mcp.py: fn() -> {"email": bool, "sms": bool} - which ways
# AI-Prowler can reach a customer right now (2026-10-28, David: no email set up ->
# no online requests; no texting set up / switched off -> no mobile box).
channels_fn = None
# Injected by ai_prowler_mcp.py: fn() -> the Jobs database path. "Request a new service"
# creates a Requested job there; "Report a problem" links the customer's recent job
# (booking-spec.md §3). None (unit tests, tools) = tickets only.
jobs_db_fn = None
# Injected by ai_prowler_mcp.py for "Buy a product" (2026-11-02): the Small Business →
# Online Payment Links checkout. checkout_ready_fn() -> bool (a Stripe Secret Key or Square
# Access Token is set); checkout_fn(amount, description, ref, return_url) -> url or None.
# None (unit tests, tools) = orders are taken, and the office sends the invoice.
checkout_ready_fn = None
checkout_fn = None


def pay_online() -> bool:
    try:
        return bool(checkout_fn) and bool(checkout_ready_fn() if checkout_ready_fn else True)
    except Exception:  # noqa: BLE001
        return False


def channels() -> dict:
    """{"email": bool, "sms": bool}. Without channels_fn (unit tests, tools),
    both follow whether a sender is installed at all."""
    if channels_fn is None:
        return {"email": bool(send_fn), "sms": bool(send_fn)}
    try:
        c = channels_fn() or {}
        return {"email": bool(c.get("email")), "sms": bool(c.get("sms"))}
    except Exception:  # noqa: BLE001
        return {"email": False, "sms": False}


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


# ── public chat: ask tokens + page purposes (2026-11-10) ───────────────────
# A verified visitor asks with a 24-hour token (same shape as a status link:
# random token, only its hash is stored). The token is the credential, so the
# visitor verifies once and can ask on every page for a day.
ASK_TOKEN_TTL_HOURS = 24

# What the visitor is doing on each page the chat appears on (David 2026-11-10:
# "when the chat is visible in a page, it should answer questions to the page
# purpose"). The assistant is told this, and only gets the facts for that page.
ASK_PAGE_PURPOSE = {
    "landing": "choosing what they need on the 'How can we help?' page",
    "book": "booking a service",
    "buy": "shopping for products",
    "new": "asking for a quote",
    "problem": "reporting a problem",
}


def issue_ask_token(db_path: str, contact_id: str) -> str:
    token = secrets.token_urlsafe(32)
    now = _now()
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("INSERT INTO ask_tokens (token_hash, contact_id, created_at, expires_at) "
                     "VALUES (?, ?, ?, ?)",
                     (_h(token), contact_id, _iso(now),
                      _iso(now + datetime.timedelta(hours=ASK_TOKEN_TTL_HOURS))))
        conn.commit()
    finally:
        conn.close()
    return token


def resolve_ask_token(db_path: str, token: str, now=None) -> dict:
    """The contact for a valid ask token, else NotFoundError (one answer for
    unknown and expired, so tokens can't be probed)."""
    nf = desk_db.NotFoundError("that verification has expired - please verify again")
    if not token or len(token) > 200:
        raise nf
    conn = desk_db.get_connection(db_path)
    try:
        r = conn.execute("SELECT * FROM ask_tokens WHERE token_hash = ?", (_h(token),)).fetchone()
        if r is None:
            raise nf
        c = conn.execute("SELECT * FROM customer_contacts WHERE contact_id = ?",
                         (r["contact_id"],)).fetchone()
    finally:
        conn.close()
    if c is None:
        raise nf
    exp = datetime.datetime.fromisoformat(r["expires_at"].replace("Z", "+00:00"))
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=datetime.timezone.utc)
    if _now(now) > exp:
        raise nf
    return dict(c)


def _ask_rate_ok(db_path: str, s: dict, ip: str, now) -> None:
    """Count this question against the per-visitor hourly limit (2026-11-10,
    David: rate limit). Raises DeskError when the limit is hit. 0 = no limit.
    Only questions that reach the model count, so this runs after the other
    gates and before the model call."""
    per_hour = s.get("agent_ask_per_hour")
    if per_hour is None:
        per_hour = 10
    if not per_hour:
        return
    now = _now(now)
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        ok = _rate_ok(conn, "ask", [f"ip:{ip}"], now, limit=int(per_hour))
        conn.execute("COMMIT" if ok else "ROLLBACK")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    if not ok:
        raise desk_db.DeskError("you've asked a lot of questions - please try again in an hour")


# ── rate limits ──────────────────────────────────────────────────────────────

def _rate_ok(conn, kind: str, keys: list, now: datetime.datetime, limit: int | None = None) -> bool:
    _limit, window = RATE_LIMITS[kind]
    if limit is not None:
        _limit = limit
    since = _iso(now - datetime.timedelta(seconds=window))
    conn.execute("DELETE FROM portal_hits WHERE at < ?", (_iso(now - datetime.timedelta(days=1)),))
    for k in keys:
        n = conn.execute("SELECT COUNT(*) FROM portal_hits WHERE key = ? AND at >= ?",
                         (f"{kind}:{k}", since)).fetchone()[0]
        if n >= _limit:
            return False
    for k in keys:
        conn.execute("INSERT INTO portal_hits (key, at) VALUES (?, ?)", (f"{kind}:{k}", _iso(now)))
    return True


# ── request form ─────────────────────────────────────────────────────────────

def clean_phone(phone) -> str:
    """The customer's phone in +<digits> form, or a friendly error. Required on every
    path (David 2026-10-30: "make sure a phone number is collected so an in person
    follow-up can be made"): 10 digits = US, 11 starting with 1 = US, or + and 8–15
    digits for other countries."""
    raw = str(phone or "").strip()
    d = "".join(ch for ch in raw if ch.isdigit())
    if len(d) == 10 and not raw.startswith("+"):
        return "+1" + d
    if len(d) == 11 and d.startswith("1"):
        return "+" + d
    if raw.startswith("+") and 8 <= len(d) <= 15:
        return "+" + d
    if not d:
        raise desk_db.DeskError("enter a phone number so we can reach you")
    raise desk_db.DeskError("that phone number doesn't look right — use 10 digits, like 386-555-0100")


def page_paths(settings: dict) -> list:
    """The paths the page offers, in page order (Phase 2: 'book' — live arrival windows)."""
    return [p for p in desk_db.BOOKING_PATHS if p in (settings.get("booking_paths") or ["problem"])] or ["problem"]


def start_request(db_path: str, *, name: str = "", phone: str = "", email: str = "",
                  send_by: str = "", ip: str = "", honeypot: str = "", now=None) -> dict:
    """Step 1: send a 6-digit code to confirm it's them. The phone is always required (so
    the team can call back); the code goes by text or email — the customer's choice,
    text by default when texting is set up."""
    s = desk_db.get_settings(db_path)
    if not s.get("portal_enabled"):
        raise desk_db.DeskError("online requests are turned off — please call or text us")
    if (honeypot or "").strip():
        return {"ok": True, "contact_id": "", "sent_via": "sms"}      # quietly drop bots
    ch = channels()
    if not ch["email"]:
        raise desk_db.DeskError("online requests aren't available right now — please call or text us")
    phone = clean_phone(phone)
    email = (email or "").strip()
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise desk_db.DeskError("that email address doesn't look right — like name@example.com")
    want = (send_by or "").strip().lower() or ("sms" if ch["sms"] else "email")
    if want not in ("sms", "email") or (want == "sms" and not ch["sms"]):
        want = "email"
    if want == "email" and not email:
        raise desk_db.DeskError("enter your email address so we can send your code"
                                + (" — or choose to get it by text" if ch["sms"] else ""))
    c = desk_db.upsert_contact(db_path, name=(name or "").strip()[:80], phone=phone,
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
    # Send the code the way the customer chose THIS time (2026-10-28: never by
    # wherever an old contact record points). Text first if chosen; email if the
    # text fails and they gave an email.
    routes = [("sms", c["phone"])] if want == "sms" else []
    if email and c.get("email"):
        routes.append(("email", c["email"]))
    text = f"Your service request code is {code}. It expires in {CODE_TTL_MINUTES} minutes."
    for channel, to in routes:
        if _send(channel, to, "Your service request code", text):
            return {"ok": True, "contact_id": c["contact_id"], "sent_via": channel}
    if [ch_ for ch_, _ in routes] == ["sms"]:
        raise desk_db.DeskError("we couldn't text a code to that number — enter your email "
                                "address instead, or call or text us")
    raise desk_db.DeskError("we couldn't send a code right now — please call or text us")


def _jobs_db() -> str:
    """The Jobs database (injected by ai_prowler_mcp.py); '' when unavailable."""
    try:
        return str(jobs_db_fn() or "") if jobs_db_fn else ""
    except Exception:  # noqa: BLE001
        return ""


def _address_text(a: dict) -> str:
    line2 = " ".join(x for x in (a.get("city", ""), a.get("state", ""), a.get("zip", "")) if x)
    return ", ".join(x for x in (a.get("street", ""), line2) if x)


def verify_and_file(db_path: str, *, contact_id: str, code: str, title: str = "",
                    description: str = "", job_id: str = "", ip: str = "",
                    edition: str = rules.BUSINESS, base_url: str = "", now=None,
                    path: str = "problem", service: str = "", service_code: str = "",
                    address: dict | None = None, preferred: str = "", window_key: str = "",
                    hold_id: str = "", backups: list | None = None, qty=1) -> dict:
    """Step 2: check the code, then file. Paths (booking-spec.md §3):
      problem — a Customer request ticket, linked to the customer's recent job if any
      new     — a Requested job (no date) in the Jobs app + a linked ticket, so the
                office can quote and schedule it
      book    — the chosen arrival window is held; a "Pending Approval" job (no date) + a
                linked ticket; confirmed at once only when approval is switched off (§7a)
      buy     — an order for a product: a Requested job to ship it, an Unpaid invoice for
                items + shipping & handling + tax, and a ticket whose page has 'Pay now'"""
    s = desk_db.get_settings(db_path)
    path = (path or "problem").strip().lower()
    if path not in page_paths(s):
        raise desk_db.DeskError("that choice isn't available on this page")
    a = {k: str((address or {}).get(k, "") or "").strip()[:120] for k in ("street", "city", "state", "zip")}
    service = (service or "").strip()[:120]
    service_code = (service_code or "").strip()[:40]
    quote = None
    if path == "buy":
        # Checked BEFORE the code is used up, so a mistake doesn't cost the customer their code.
        if not service_code:
            raise desk_db.DeskError("pick a product")
        if not a["street"] or not (a["city"] or a["zip"]):
            raise desk_db.DeskError("enter the shipping address (street, and city or ZIP)")
        if not _jobs_db():
            raise desk_db.DeskError("online ordering isn't available right now — please call or text us")
        import booking_db
        try:
            quote = booking_db.order_quote(_jobs_db(), service_code, qty)
        except booking_db.BookingError as e:
            raise desk_db.DeskError(str(e)) from None
    elif path in ("new", "book"):
        if path == "book" and not service_code:
            raise desk_db.DeskError("pick a service")
        if path == "new" and not service and not (title or "").strip():
            raise desk_db.DeskError("tell us which service you'd like")
        if not a["street"] or not (a["city"] or a["zip"]):
            raise desk_db.DeskError("enter the address (street, and city or ZIP) where you'd like the service")
    elif not (title or "").strip():
        raise desk_db.DeskError("tell us briefly what you need")
    held = None
    area_ok, area_why = True, ""
    if path in ("new", "book"):
        # Service area (booking-spec.md §5): ZIP list and/or miles from the Start/End Address.
        import booking_db
        area_ok, area_why = booking_db.area_check(_jobs_db(), s, a)
    if path == "book":
        if not area_ok:
            path, service = "new", service or service_code     # outside the area: a call-back request
            if hold_id:
                try:
                    import booking_db
                    booking_db.release_hold(_jobs_db(), hold_id)
                except Exception:  # noqa: BLE001
                    pass
        else:
            # Before the code is used up: the window is still ours (or taken again). If it's
            # gone, the customer picks another — and their code still works.
            import booking_flow
            if not _jobs_db():
                raise desk_db.DeskError("online booking isn't available right now — please call or text us")
            try:
                held = booking_flow.ensure_hold(_jobs_db(), s, service_code, hold_id, window_key, edition=edition)
            except booking_flow.BookingError as e:
                raise desk_db.DeskError(str(e)) from None
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
    jobs_db, customer_id, note = _jobs_db(), contact.get("linked_customer_id"), ""
    phone, email = contact.get("phone") or "", contact.get("email") or ""
    body = (description or "").strip()
    out_of_area = False
    if path == "new":
        # Service area (booking-spec.md §5): outside it the request is still taken — the
        # phone number lets the team call back — but it's flagged for them.
        out_of_area = not area_ok
        if out_of_area:
            why = (area_why if area_why and not area_why.startswith("ZIP")
                   else f"ZIP {a['zip'] or 'not given'}")
            note = f"Outside your service area ({why}) — the customer was told you'll call them."
        title = (f"New service request — {service or title.strip()}"
                 + (" (outside service area)" if out_of_area else ""))
        body = "\n".join(x for x in (body, f"Address: {_address_text(a)}",
                                     f"Preferred: {preferred.strip()}" if preferred.strip() else "",
                                     f"Phone: {phone}") if x)
        if jobs_db:
            try:
                import booking_db
                customer_id, _created = booking_db.find_or_create_customer(
                    jobs_db, name=contact.get("name") or "", phone=phone, email=email, street=a["street"],
                    city=a["city"], state=a["state"], zip_code=a["zip"])
                job_id = booking_db.create_request_job(
                    jobs_db, customer_id=customer_id, customer_name=contact.get("name") or "",
                    service=service or title, service_code=service_code, notes=(description or ""),
                    preferred=preferred, street=a["street"], city=a["city"], state=a["state"], zip_code=a["zip"])
            except Exception as e:  # noqa: BLE001 — the ticket still gets filed
                note = ((note + "\n") if note else "") + (
                    f"Couldn't add this to the Jobs app automatically ({e}) — please add the job by hand.")
    elif path == "book":
        import booking_db
        import booking_flow
        label = booking_flow.label_of(booking_flow.key_of(held))
        needs = booking_flow.needs_approval(s)
        svc_name = service or service_code
        title = f"{svc_name} — {label}"            # the customer sees the title: no staff wording
        body = "\n".join(x for x in (body, f"Wants: {label} (arrival window)", f"Address: {_address_text(a)}",
                                     f"Phone: {phone}") if x)
        try:
            customer_id, _created = booking_db.find_or_create_customer(
                jobs_db, name=contact.get("name") or "", phone=phone, email=email, street=a["street"],
                city=a["city"], state=a["state"], zip_code=a["zip"])
            made = booking_flow.create_pending(
                jobs_db, s, held, backups=[str(k) for k in (backups or [])][:5], customer_id=customer_id,
                customer_name=contact.get("name") or "", service_name=svc_name, notes=description or "",
                street=a["street"], city=a["city"], state=a["state"], zip_code=a["zip"], edition=edition)
            job_id = made["job_id"]
            if made["backups"]:
                body += "\nOr: " + "; ".join(made["backups"])
        except Exception as e:  # noqa: BLE001 — the ticket still gets filed
            booking_db.release_hold(jobs_db, held["hold_id"])
            note = f"Couldn't add this booking to the Jobs app automatically ({e}) — please call the customer."
            title = f"{svc_name} — {label} (call the customer)"
    elif path == "buy":
        import booking_db
        title = f"Order: {booking_db.order_text(quote)}"     # the customer sees the title
        try:
            customer_id, _created = booking_db.find_or_create_customer(
                jobs_db, name=contact.get("name") or "", phone=phone, email=email, street=a["street"],
                city=a["city"], state=a["state"], zip_code=a["zip"], by=booking_db.ORDER_BY)
            quote = booking_db.create_order(
                jobs_db, customer_id=customer_id, customer_name=contact.get("name") or "", code=service_code,
                qty=quote["qty"], street=a["street"], city=a["city"], state=a["state"], zip_code=a["zip"],
                notes=description or "")
            job_id = quote["job_id"]
            note = (f"🛒 Online order — invoice {quote['invoice_id']} for ${quote['total']:,.2f} (unpaid). "
                    + ("The customer can pay it from their page (Pay now). Mark the invoice paid when the "
                       "money arrives, then ship it." if pay_online() else
                       "Online payment isn't set up (Small Business → Online Payment Links) — send the "
                       "customer the invoice, then ship it when it's paid."))
        except Exception as e:  # noqa: BLE001 — the ticket still gets filed
            note = f"Couldn't add this order to the Jobs app automatically ({e}) — please call the customer."
            title += " (call the customer)"
        body = "\n".join(x for x in (
            body, f"{quote['name']} × {quote['qty']} at ${quote['unit_price']:,.2f} = ${quote['items']:,.2f}",
            f"Shipping & handling: ${quote['shipping']:,.2f}" if quote["shipping"] else "",
            f"Sales tax: ${quote['tax']:,.2f}" if quote["tax"] else "",
            f"Total: ${quote['total']:,.2f}", f"Ship to: {_address_text(a)}", f"Phone: {phone}") if x)
    elif jobs_db and not (job_id or "").strip():
        try:
            import booking_db
            recent = booking_db.recent_job(jobs_db, phone=phone, email=email)
            if recent:
                job_id, customer_id = recent["job_id"], recent["customer_id"]
                note = (f"Probably about {recent['job_id']} ({recent.get('service_type') or 'visit'} on "
                        f"{recent['service_date']}) — the customer's most recent job.")
        except Exception:  # noqa: BLE001
            pass
    if customer_id and not contact.get("linked_customer_id"):
        try:
            desk_db.upsert_contact(db_path, name=contact.get("name") or "", phone=phone or None, email=email or None,
                                   linked_customer_id=customer_id, actor={"id": "portal", "role": "customer"})
        except Exception:  # noqa: BLE001
            pass
    t = desk_db.create_ticket(db_path, title=(title or "").strip()[:200], kind=rules.EXTERNAL,
                              actor=actor, edition=edition, description=body[:5000],
                              source="portal", contact_id=contact_id,
                              customer_id=customer_id, job_id=(job_id or "").strip() or None)
    if path in ("new", "book", "buy") and job_id and jobs_db:
        try:
            import booking_db
            booking_db.link_request_ticket(jobs_db, job_id, t["ticket_id"])
        except Exception:  # noqa: BLE001
            pass
    booking = None
    if path == "book" and job_id and jobs_db:
        import booking_flow
        booking = {"status": "pending", "label": booking_flow.label_of(booking_flow.key_of(held))}
        # Instant booking (Phase 4): confirmed now when the approval setting and its limits allow.
        ok_now, why, decision = booking_flow.decide(jobs_db, s, job_id, booking_flow.key_of(held), kind="new",
                                                            edition=edition)
        if ok_now:
            try:
                done = booking_flow.approve(jobs_db, db_path, job_id, actor=booking_flow.SYSTEM, edition=edition,
                                            settings=s, system=True, decision=decision)
                booking = {"status": "scheduled", "label": done["label"]}
                note = ((note + "\n") if note else "") + (
                    f"📅 FYI — booked on its own ({why}). You can still suggest a change from 📅 To approve.")
            except Exception as e:  # noqa: BLE001 — stays pending for an approver
                note = ((note + "\n") if note else "") + f"Couldn't confirm automatically ({e}) — please approve it."
        elif s.get("booking_approval") == booking_flow.PREAPPROVE:
            note = ((note + "\n") if note else "") + f"Waiting for your OK — not booked instantly because {why}."
    if note:
        try:
            desk_db.add_message(db_path, t["ticket_id"], note, actor={"id": "system", "role": "owner"},
                                edition=edition, visibility="internal", channel="system")
        except Exception:  # noqa: BLE001
            pass
    token = issue_link(db_path, t["ticket_id"], contact_id)
    url = link_url(base_url, token)
    # Confirmation: text if we can, otherwise email (the page already shows
    # the request, so this is a courtesy - never an error).
    ch = channels()
    if booking and booking["status"] == "pending":
        said = (f"We're holding {booking['label']} for you (ref {t['ticket_id']}) — we'll confirm it or suggest "
                f"another time shortly. Track it here: {url}")
    elif booking:
        said = f"Booked: {booking['label']} (arrival window), ref {t['ticket_id']}. Details: {url}"
    elif path == "buy":
        said = (f"Thanks for your order {t['ticket_id']}: {t['title']} — total ${quote['total']:,.2f}. "
                + (f"Pay and track it here: {url}" if pay_online() and job_id else
                   f"We'll send you the invoice. Track it here: {url}"))
    else:
        said = f"We got your request {t['ticket_id']}: {t['title']}. Track it here: {url}"
    for channel, to in (("sms", contact.get("phone")), ("email", contact.get("email"))):
        if to and ch[channel] and _send(channel, to, f"We got your request [{t['ticket_id']}]", said):
            break
    out = {"ok": True, "ticket_id": t["ticket_id"], "token": token, "url": url,
           "job_id": (job_id or "") if path in ("new", "book", "buy") else "", "out_of_area": out_of_area,
           "booking": booking}
    if path == "buy":
        out["order"] = {k: quote[k] for k in ("name", "qty", "items", "shipping", "tax", "total")}
    return out


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
        "booking": _booking_view(t, c, s),
        "order": _order_view(t, c),
    })
    for m in detail.get("messages") or []:       # David 4 Nov: the page shows the agent's name, label and photo on its messages
        m["from_agent"] = str(m.get("author") or "").startswith("agent")
    return detail


def ask_assistant(db_path: str, token: str, question: str, *, edition: str, business: str = "",
                  ip: str = "", now=None) -> dict:
    """The customer's question to the AI assistant on their status page (2026-11-10).

    The assistant answers from this ticket and the business's facts only. It never
    changes, books, cancels or promises anything. The answer is labelled with the
    assistant's name and "AI assistant" label, and it says it's an assistant if asked.
    It works when the agent is on and a key is saved, practice mode or not: the
    customer asked the question themselves, so answering it is a reply, not the agent
    acting on its own. Every answer is charged to the shared monthly AI budget and
    recorded as an agent run, so the Agent tab's spend meter counts it.
    """
    t, c, actor = resolve_link(db_path, token, now)
    q = (question or "").strip()
    if not q:
        raise desk_db.DeskError("write your question first")
    if len(q) > 500:
        raise desk_db.DeskError("keep your question under 500 characters")
    import desk_agent_settings as das
    import desk_agent_providers as prov
    import desk_agent
    s = desk_db.get_settings(db_path)
    if not s.get("agent_enabled"):
        raise desk_db.DeskError("the AI assistant is off - please call or text us instead")
    provider = das.effective_provider(s, edition)
    ok, why = prov.ready(provider)
    if not ok:
        raise desk_db.DeskError(why + " - please call or text us instead")
    spent = desk_agent.spend(db_path, s, now)
    if spent["budget_usd"] and spent["spent_usd"] >= spent["budget_usd"]:
        raise desk_db.DeskError("the AI assistant has used its monthly budget - please call or text us instead")
    _ask_rate_ok(db_path, s, ip, now)
    detail = desk_db.get_ticket_detail(db_path, t["ticket_id"], actor=actor, edition=edition)
    prof = das.public_profile(db_path, business)
    name = prof.get("display") or prof.get("name") or "Virtual assistant"
    biz = business or ""
    msgs = detail.get("messages") or []
    recent = "\n".join(
        f"- {'You' if m.get('author_kind') == c.get('contact_type') else (biz or 'Us')}: "
        f"{(m.get('body') or '')[:400]}"
        for m in msgs[-8:])
    bk = _booking_view(t, c, s)
    bk_line = ""
    if bk:
        bits = [x for x in (bk.get("service"), bk.get("confirmed") or bk.get("status")) if x]
        if bits:
            bk_line = "\nBooking: " + " - ".join(str(x) for x in bits)
    # the booked service/product's full specs, so the assistant can answer
    # detail questions about what the customer ordered (2026-11-10)
    spec_line = ""
    if bk and bk.get("service"):
        try:
            _svcs, _prods = _public_offerings(db_path, s)
            for _x in list(_svcs) + list(_prods):
                if _x.get("name") == bk.get("service") and _x.get("specs"):
                    spec_line = f"\nBooked item specs: {_x['specs']}"
                    break
        except Exception:  # noqa: BLE001
            spec_line = ""
    # the ticket's own facts, so the assistant can answer "what happened",
    # "when was it fixed" and "why did it close" from the record, not just the title
    _facts = []
    _kind = " / ".join(x for x in (detail.get("kind"), detail.get("type")) if x)
    if _kind:
        _facts.append(f"Kind: {_kind}")
    if detail.get("priority"):
        _facts.append(f"Priority: {detail['priority']}")
    if detail.get("created_at"):
        _facts.append(f"Filed: {detail['created_at']}")
    if detail.get("fixed_at"):
        _facts.append(f"Fixed: {detail['fixed_at']}")
    if detail.get("closed_at"):
        _facts.append(f"Closed: {detail['closed_at']}")
    if detail.get("resolution"):
        _facts.append(f"Resolution: {detail['resolution']}")
    if detail.get("close_reason"):
        _facts.append(f"Close reason: {detail['close_reason']}")
    fact_lines = ("\n" + "\n".join(_facts)) if _facts else ""
    system = (f"You are {name}, the AI assistant for {biz or 'this business'}. You answer a customer's "
              f"question about their own service request. You are an AI assistant - never pretend to be a "
              f"person, and say so if asked. Answer from the request details below only. If the answer "
              f"isn't in those facts, say you don't know and that someone from {biz or 'the business'} "
              f"will follow up. Never change, book, cancel or promise anything - only answer the "
              f"question. Keep it short, a few sentences.")
    try:
        context = das.ask_context_text(db_path)
    except Exception:  # noqa: BLE001 - the ask never fails because of the context file
        context = ""
    context_block = f"\nAdditional business information:\n{context}" if context else ""
    user = (f"Request: {t.get('ticket_id')} - {detail.get('title') or ''}\n"
            f"Status: {detail.get('state') or ''}{fact_lines}\n"
            f"Details: {detail.get('description') or ''}"
            f"{bk_line}{spec_line}{context_block}\n"
            f"Recent messages:\n{recent or '(none)'}\n\n"
            f"Customer's question: {q}")
    model = prov.model_for(provider)
    conn = desk_agent._conn(db_path)
    try:
        run_id = conn.execute(
            "INSERT INTO agent_runs (provider, model, started_at, items, ok) VALUES (?, ?, ?, 0, 0)",
            (provider, model, utcnow_iso())).lastrowid
        conn.commit()
    finally:
        conn.close()
    try:
        text, usage = prov.ask(provider, system, user, model=model)
    except prov.ProviderError as e:
        raise desk_db.DeskError(str(e) + " - please call or text us instead") from None
    cost = prov.cost(model, usage)
    conn = desk_agent._conn(db_path)
    try:
        conn.execute(
            "UPDATE agent_runs SET ended_at = ?, items = ?, ok = ?, input_tokens = ?, output_tokens = ?, "
            "cost_usd = ?, summary = ?, model = ? WHERE run_id = ?",
            (utcnow_iso(), 1, 1, int(usage.get("input", 0)), int(usage.get("output", 0)), cost,
             "customer ask", model, run_id))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "answer": (text or "").strip(),
            "name": prof.get("display") or name, "photo_url": prof.get("photo_url") or ""}


def _public_offerings(db_path: str, s: dict) -> tuple:
    """The services and products the public pages show (same source and gating as /info).

    The full record is kept (2026-11-10): the assistant answers from these facts,
    so the specs, shipping and duration travel with the name and price. Dropping
    them is why the assistant could not answer "how much RAM does the server have"
    even though the specs were in the database and on the page.
    """
    services, products = [], []
    if not _jobs_db():
        return services, products
    paths = set(page_paths(s))
    try:
        import booking_db
        if {"new", "book"} & paths:
            services = [{"code": x["code"], "name": x["name"], "description": x["description"],
                         "price": x["price"], "specs": x.get("specs") or "",
                         "minutes": x.get("minutes") or 0}
                        for x in booking_db.list_services(_jobs_db(), online_only=True)]
        if "buy" in paths:
            products = [{"code": x["code"], "name": x["name"], "description": x["description"],
                         "unit_price": x["unit_price"], "specs": x.get("specs") or "",
                         "shipping": x.get("shipping")}
                        for x in booking_db.list_services(_jobs_db(), online_only=True)
                        if x["mode"] == "request"]
    except Exception:  # noqa: BLE001
        services, products = [], []
    return services, products


def _fmt_price(v) -> str:
    """A price for the assistant's fact list. Service prices are often text
    like 'from $500', not a number — formatting one with :,.2f raised
    ValueError and the whole /ask call 500'd (2026-11-10, live /support/new).
    Numbers render as ($X.XX); text renders as-is; blank or zero renders
    as nothing."""
    if v is None or v == "" or v == 0:
        return ""
    if isinstance(v, (int, float)):
        return f" (${v:,.2f})"
    return f" ({v})"


def _offering_block(x: dict, price_key: str) -> str:
    """One service/product as the assistant sees it: name, description and price,
    then the full specs and the shipping / duration on their own lines, so the
    model can answer detail questions ("how much RAM?", "is shipping free?",
    "how long does it take?") instead of only what the tile shows."""
    lines = ["- " + x["name"] + (": " + x["description"] if x.get("description") else "") +
             _fmt_price(x.get(price_key))]
    if x.get("specs"):
        lines.append("  Specs: " + str(x["specs"]))
    if price_key == "unit_price" and x.get("shipping") is not None:
        try:
            ship = float(x["shipping"])
        except (TypeError, ValueError):
            ship = None
        if ship is not None:
            lines.append("  Shipping: free" if ship == 0 else f"  Shipping: ${ship:,.2f}")
    if price_key == "price" and x.get("minutes"):
        try:
            mins = int(x["minutes"])
        except (TypeError, ValueError):
            mins = 0
        if mins:
            lines.append(f"  Takes about {mins} minutes")
    return "\n".join(lines)


def ask_general(db_path: str, question: str, *, edition: str, business: str = "",
                page: str = "landing", ask_token: str = "", ip: str = "",
                now=None) -> dict:
    """A visitor's question on the public pages (2026-11-10, extended 2026-11-10).

    The chat is on the main page and on each of the four form pages, and it
    answers to the page's purpose (David: "when the chat is visible in a page,
    it should answer questions to the page purpose"). There is no ticket yet,
    so the assistant answers from the business's public facts only, filtered
    to the page: booking is about services, shopping is about products, a quote
    is about services, a problem can be about either, and the main page covers
    both. The services / products toggles in the Agent settings turn those
    sources off entirely.

    Who may ask is set in the Agent settings: anyone, verified visitors (a
    6-digit code first, then a 24-hour token), or ticket holders only (the
    chat is off here - only a ticket's own page answers). Questions are
    limited per visitor per hour. It never changes, books, cancels or promises
    anything. It works in practice mode too: the visitor asked, so answering
    is a reply, not the agent acting on its own. Every answer is charged to
    the shared monthly AI budget and recorded as an agent run.
    """
    q = (question or "").strip()
    if not q:
        raise desk_db.DeskError("write your question first")
    if len(q) > 500:
        raise desk_db.DeskError("keep your question under 500 characters")
    import desk_agent_settings as das
    import desk_agent_providers as prov
    import desk_agent
    s = desk_db.get_settings(db_path)
    if not s.get("agent_enabled"):
        raise desk_db.DeskError("the AI assistant is off - please call or text us instead")
    who = s.get("agent_ask_who") or "anyone"
    if who == "ticket":
        raise desk_db.DeskError("the AI assistant only answers questions on a service request - file a request first")
    if who == "verified":
        try:
            resolve_ask_token(db_path, ask_token, now)
        except desk_db.NotFoundError:
            raise desk_db.DeskError("please verify first - enter your phone number and we'll text or email you a code") from None
    provider = das.effective_provider(s, edition)
    ok, why = prov.ready(provider)
    if not ok:
        raise desk_db.DeskError(why + " - please call or text us instead")
    spent = desk_agent.spend(db_path, s, now)
    if spent["budget_usd"] and spent["spent_usd"] >= spent["budget_usd"]:
        raise desk_db.DeskError("the AI assistant has used its monthly budget - please call or text us instead")
    _ask_rate_ok(db_path, s, ip, now)
    prof = das.public_profile(db_path, business)
    name = prof.get("display") or prof.get("name") or "Virtual assistant"
    biz = business or ""
    page = (page or "landing").strip().lower()
    if page not in ASK_PAGE_PURPOSE:
        page = "landing"
    services, products = _public_offerings(db_path, s)
    if not s.get("agent_ask_services", True):
        services = []
    if not s.get("agent_ask_products", True):
        products = []
    if page == "book":
        products = []
    elif page == "buy":
        services = []
    elif page == "new":
        products = []
    svc_lines = "\n".join(_offering_block(x, "price") for x in services) or "(none listed)"
    prod_lines = "\n".join(_offering_block(x, "unit_price") for x in products) or "(none listed)"
    purpose = ASK_PAGE_PURPOSE[page]
    system = (f"You are {name}, the AI assistant for {biz or 'this business'}. You answer a visitor's "
              f"question while they are {purpose}. You are an AI assistant - never pretend to be a person, "
              f"and say so if asked. Answer from the facts below only, and keep to what this page is about: "
              f"if the question is about something else, say you don't know and point them to the page "
              f"where that belongs (book a service, shop products, get a quote, report a problem) or to "
              f"call or text us. Never change, book, cancel or promise anything - only answer the question. "
              f"Keep it short, a few sentences.")
    try:
        context = das.ask_context_text(db_path)
    except Exception:  # noqa: BLE001 - the ask never fails because of the context file
        context = ""
    context_block = f"Additional business information:\n{context}\n" if context else ""
    user = (f"Business: {biz or ''}\n"
            f"Welcome: {s.get('booking_welcome') or ''}\n"
            f"The visitor is {purpose}.\n"
            f"Services offered:\n{svc_lines}\n"
            f"Products for sale:\n{prod_lines}\n"
            f"{context_block}\n"
            f"Visitor's question: {q}")
    model = prov.model_for(provider)
    conn = desk_agent._conn(db_path)
    try:
        run_id = conn.execute(
            "INSERT INTO agent_runs (provider, model, started_at, items, ok) VALUES (?, ?, ?, 0, 0)",
            (provider, model, utcnow_iso())).lastrowid
        conn.commit()
    finally:
        conn.close()
    try:
        text, usage = prov.ask(provider, system, user, model=model)
    except prov.ProviderError as e:
        raise desk_db.DeskError(str(e) + " - please call or text us instead") from None
    cost = prov.cost(model, usage)
    conn = desk_agent._conn(db_path)
    try:
        conn.execute(
            "UPDATE agent_runs SET ended_at = ?, items = ?, ok = ?, input_tokens = ?, output_tokens = ?, "
            "cost_usd = ?, summary = ?, model = ? WHERE run_id = ?",
            (utcnow_iso(), 1, 1, int(usage.get("input", 0)), int(usage.get("output", 0)), cost,
             "visitor ask", model, run_id))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True, "answer": (text or "").strip(),
            "name": prof.get("display") or name, "photo_url": prof.get("photo_url") or ""}


def start_ask_code(db_path: str, *, phone: str = "", email: str = "", send_by: str = "",
                   ip: str = "", now=None) -> dict:
    """Step 1 of verify-first asking (2026-11-10): send a 6-digit code so a
    visitor can ask questions. Same shape as start_request, but the code goes
    in ask_codes (not verify_codes), so asking never invalidates a code for
    filing a request, and the message says verification, not service request.
    The phone is always required; the code goes by text or email."""
    s = desk_db.get_settings(db_path)
    ch = channels()
    if not ch["email"]:
        raise desk_db.DeskError("asking isn't available right now - please call or text us")
    phone = clean_phone(phone)
    email = (email or "").strip()
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise desk_db.DeskError("that email address doesn't look right - like name@example.com")
    want = (send_by or "").strip().lower() or ("sms" if ch["sms"] else "email")
    if want not in ("sms", "email") or (want == "sms" and not ch["sms"]):
        want = "email"
    if want == "email" and not email:
        raise desk_db.DeskError("enter your email address so we can send your code"
                                + (" - or choose to get it by text" if ch["sms"] else ""))
    c = desk_db.upsert_contact(db_path, name="", phone=phone,
                               email=email or None, contact_type="customer",
                               actor={"id": "portal", "role": "customer"})
    now = _now(now)
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        if not _rate_ok(conn, "code", [f"ip:{ip}", f"c:{c['contact_id']}"], now):
            conn.execute("ROLLBACK")
            raise desk_db.DeskError("too many codes requested - please try again in an hour")
        code = f"{secrets.randbelow(1_000_000):06d}"
        conn.execute(
            "INSERT INTO ask_codes (contact_id, code_hash, expires_at, attempts, sent_at) "
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
    routes = [("sms", c["phone"])] if want == "sms" else []
    if email and c.get("email"):
        routes.append(("email", c["email"]))
    text = f"Your verification code is {code}. It expires in {CODE_TTL_MINUTES} minutes."
    for channel, to in routes:
        if _send(channel, to, "Your verification code", text):
            return {"ok": True, "contact_id": c["contact_id"], "sent_via": channel}
    if [ch_ for ch_, _ in routes] == ["sms"]:
        raise desk_db.DeskError("we couldn't text a code to that number - enter your email "
                                "address and we'll send it there instead")
    raise desk_db.DeskError("we couldn't send a code - please call or text us")


def verify_ask_code(db_path: str, *, contact_id: str, code: str, ip: str = "",
                    now=None) -> dict:
    """Step 2 of verify-first asking (2026-11-10): check the 6-digit code.
    Same shape as the request form's code check: a wrong try counts, an
    expired code is cleared, and the code is single-use. On success the
    visitor gets a 24-hour ask token to ask with."""
    now = _now(now)
    bad = desk_db.DeskError("that code is not right - check it or ask for a new one")
    refused = None
    conn = desk_db.get_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        r = conn.execute("SELECT * FROM ask_codes WHERE contact_id = ?", (contact_id,)).fetchone()
        if r is None:
            refused = bad
        elif r["attempts"] >= CODE_MAX_ATTEMPTS or r["expires_at"] < _iso(now):
            conn.execute("DELETE FROM ask_codes WHERE contact_id = ?", (contact_id,))
            refused = desk_db.DeskError("that code has expired - ask for a new one")
        elif not secrets.compare_digest(r["code_hash"], _h(f"{contact_id}:{(code or '').strip()}")):
            conn.execute("UPDATE ask_codes SET attempts = attempts + 1 WHERE contact_id = ?",
                         (contact_id,))
            refused = bad
        else:
            conn.execute("DELETE FROM ask_codes WHERE contact_id = ?", (contact_id,))
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
    return {"ok": True, "ask_token": issue_ask_token(db_path, contact_id)}


def _order_view(t: dict, c: dict) -> dict | None:
    """The order behind this ticket ("Buy a product"), as the customer sees it, or None."""
    if c.get("contact_type") != "customer" or not t.get("job_id") or not _jobs_db():
        return None
    try:
        import booking_db
        o = booking_db.order_view(_jobs_db(), t["job_id"])
    except Exception:  # noqa: BLE001
        return None
    if o:
        o["pay_online"] = pay_online()
    return o


def pay_link(db_path: str, token: str, *, base_url: str = "", now=None) -> dict:
    """A fresh checkout link for what's still owed on this order (made when the customer taps
    Pay now, so it never goes stale — Stripe's links expire after a day)."""
    t, c, _actor = resolve_link(db_path, token, now)
    o = _order_view(t, c)
    if not o:
        raise desk_db.NotFoundError("this request isn't an order")
    if o["paid"]:
        raise desk_db.DeskError("this order is already paid — thank you")
    if not o["can_pay"]:
        raise desk_db.DeskError("this order can't be paid online — please call us")
    if not pay_online():
        raise desk_db.DeskError("online payment isn't available — we'll send you the invoice")
    what = f"{o['name']} × {o['qty']}" + (" + shipping & handling" if o.get("shipping") else "")
    try:
        url = checkout_fn(float(o["due"]), f"{what} — order {t['ticket_id']}", o["invoice_id"] or t["ticket_id"],
                          link_url(base_url, token) if base_url else "")
    except Exception:  # noqa: BLE001
        url = None
    if not url:
        raise desk_db.DeskError("we couldn't open the payment page right now — please try again in a minute, "
                                "or call us")
    return {"ok": True, "url": url, "amount": o["due"]}


def _booking_view(t: dict, c: dict, s: dict) -> dict | None:
    """The booking behind this ticket as the customer sees it (booking_flow.view), or None."""
    if c.get("contact_type") != "customer" or not t.get("job_id") or not _jobs_db():
        return None
    try:
        import booking_flow
        v = booking_flow.view(_jobs_db(), t["job_id"], s)
    except Exception:  # noqa: BLE001
        return None
    if v and s.get("booking_waitlist"):          # Phase 6: "tell me if something earlier opens"
        try:
            import booking_followup
            w = booking_followup.view(_jobs_db(), t["job_id"], s)
            v["waitlist"] = {**w, "can_join": v["state"] in ("pending", "scheduled") and not w["waiting"]}
        except Exception:  # noqa: BLE001
            pass
    return v


def _booking_action(db_path: str, token: str, what: str, body: dict, *, edition: str, now=None) -> dict:
    """The customer's choices on their status page: accept / pick / reschedule / cancel / call,
    and the waitlist: wait / unwait / take."""
    import booking_flow
    t, c, actor = resolve_link(db_path, token, now)
    s = desk_db.get_settings(db_path)
    if not _booking_view(t, c, s):
        raise desk_db.DeskError("this request isn't a booking")
    jobs_db, jid, tid = _jobs_db(), t["job_id"], t["ticket_id"]
    key = str(body.get("window_key") or "")
    say = lambda text: desk_db.add_message(db_path, tid, text, actor=actor, edition=edition,  # noqa: E731
                                           visibility="public", channel="portal")
    try:
        if what == "accept":
            out = booking_flow.customer_accept(jobs_db, db_path, jid, edition=edition, settings=s)
            say(f"I accept {out['label']}.")
        elif what == "pick":
            out = booking_flow.customer_pick(jobs_db, db_path, jid, key, edition=edition, settings=s)
            say(f"Could you come {booking_flow.label_of(key)} instead?")
        elif what == "reschedule":
            out = booking_flow.customer_reschedule(jobs_db, db_path, jid, key, edition=edition, settings=s)
            say(f"Please move my visit to {booking_flow.label_of(key)}.")
        elif what == "cancel":
            out = booking_flow.customer_cancel(jobs_db, db_path, jid, edition=edition, settings=s)
            say("I've cancelled this booking.")
        elif what == "call":
            say("Please call me about the time.")
            out = {"ok": True}
        elif what in ("wait", "unwait", "take"):
            import booking_followup
            if what == "wait":
                booking_followup.join(jobs_db, jid, settings=s)
                say("Please tell me if an earlier time opens.")
                out = {"ok": True, "status": "waiting"}
            elif what == "unwait":
                booking_followup.leave(jobs_db, jid)
                out = {"ok": True, "status": "left"}
            else:
                out = booking_followup.take(jobs_db, db_path, jid, settings=s, edition=edition)
                say(f"I'll take the earlier time, {out['label']}.")
        else:
            raise desk_db.NotFoundError("not found")
    except booking_flow.BookingError as e:
        raise desk_db.DeskError(str(e)) from None
    return {"ok": True, **{k: v for k, v in out.items() if k in ("status", "label")}}


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
        row = desk_db._row(conn, t["ticket_id"])
    # Tell whoever handled it (2026-10-28: ratings were saved but nobody heard).
    desk_db._emit("rated", row, actor, edition=edition, score=score,
                  comment=(comment or "").strip()[:1000])
    return {"ok": True}


# ── /support-api router ──────────────────────────────────────────────────────

def _booking_on(db: str) -> dict:
    """The settings, when online booking is on (page switched on, email set up, "book" offered,
    Jobs app reachable). Raises otherwise."""
    s = desk_db.get_settings(db)
    if not s.get("portal_enabled") or not channels()["email"] or "book" not in page_paths(s) or not _jobs_db():
        raise desk_db.DeskError("online booking isn't available right now — please call or text us")
    return s


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
        ch = channels()
        # The form takes requests only with the owner's switch on AND email set
        # up; the mobile box shows only when texting works too.
        services = []
        if {"new", "book"} & set(page_paths(s)) and _jobs_db():
            try:
                import booking_db
                services = [{"code": x["code"], "name": x["name"], "description": x["description"],
                             "price": x["price"], "bookable": x["mode"] == "instant",
                             # 2026-11-02: a Product can be asked for, never booked in a time window
                             "kind": "product" if x["mode"] == "request" else "service"}
                            for x in booking_db.list_services(_jobs_db(), online_only=True)]
            except Exception:  # noqa: BLE001
                services = []
        # "Buy a product" (2026-11-02): online products that have a price, with shipping & handling
        products, tax_rate = [], 0.0
        if "buy" in page_paths(s) and _jobs_db():
            try:
                import booking_db
                from db_write_ops import db_read_settings_tax_rate
                tax_rate = float(db_read_settings_tax_rate(_jobs_db()) or 0)
                import desk_product_media as media
                # every online product (2026-11-02, "show the products (pictures and specs)"): one with
                # a price can be bought; one without shows "Ask about it" (a quote request)
                products = [{"code": x["code"], "name": x["name"], "description": x["description"],
                             "unit_price": x["unit_price"], "shipping": x["shipping"],
                             "buyable": x["unit_price"] > 0, "specs": x.get("specs") or "",
                             "photos": media.photo_urls(db, x["code"])}
                            for x in booking_db.list_services(_jobs_db(), online_only=True)
                            if x["mode"] == "request"]
            except Exception:  # noqa: BLE001
                products = []
        import desk_page_look
        return _j(200, {"ok": True, "business": business or "",
                        "portal_enabled": bool(s.get("portal_enabled")) and ch["email"],
                        "sms": ch["sms"], "paths": page_paths(s), "welcome": s.get("booking_welcome") or "",
                        "services": services, "products": products, "pay_online": pay_online(),
                        "tax_rate": tax_rate, "max_qty": 20, "phone_required": True,
                        "backups": int(s.get("booking_backups", 2)),
                        "approval": s.get("booking_approval", "approve_all"),
                        "look": desk_page_look.public_look(db)})
    # The page look (2026-10-30): the business's icon and background picture.
    if sub in ("/page/logo", "/page/background") and method == "GET":
        import desk_page_look
        got = desk_page_look.file_bytes(db, sub.rsplit("/", 1)[1])
        if got is None:
            raise desk_db.NotFoundError("not set")
        return 200, got[1].encode(), got[0]
    # 🛒 Shop (2026-11-02): a product's photos — only for products shown online
    mp = re.fullmatch(r"/product/([^/]{1,120})/photo/(\d{1,2})", sub)
    if mp and method == "GET":
        from urllib.parse import unquote
        code = unquote(mp.group(1))
        import booking_db
        import desk_product_media as media
        shown = _jobs_db() and any(x["code"] == code and x["mode"] == "request"
                                   for x in booking_db.list_services(_jobs_db(), online_only=True))
        data = media.photo_bytes(db, code, int(mp.group(2))) if shown else None
        if data is None:
            raise desk_db.NotFoundError("no such photo")
        return 200, b"image/jpeg", data
    # Online booking (Phase 2): open arrival windows, and holding one while the code is entered.
    if sub == "/windows" and method == "GET":
        s = _booking_on(db)
        import booking_flow
        try:
            frm = datetime.date.fromisoformat(str(q.get("from") or "")) if q.get("from") else None
        except ValueError:
            raise desk_db.DeskError("from must be YYYY-MM-DD") from None
        try:
            w = booking_flow.windows(_jobs_db(), s, str(q.get("service") or ""), edition, from_date=frm,
                                     to_date=(frm + datetime.timedelta(days=13)) if frm else None)
        except booking_flow.BookingError as e:
            raise desk_db.DeskError(str(e)) from None
        return _j(200, {"ok": True, "windows": w})
    if sub == "/hold" and method == "POST":
        s = _booking_on(db)
        b = _body(raw)
        import booking_flow
        try:
            h = booking_flow.hold_for_checkout(_jobs_db(), s, str(b.get("service_code") or ""),
                                               str(b.get("window_key") or ""), who="ip:" + _h(ip or "?")[:16],
                                               edition=edition)
        except booking_flow.BookingError as e:
            raise desk_db.DeskError(str(e)) from None
        return _j(200, {"ok": True, **h})
    # The agent as customers see it (2026-10-29): name, "Virtual assistant" label
    # and photo — shown beside its messages on the status page.
    if sub == "/agent" and method == "GET":
        import desk_agent_settings as das
        return _j(200, {"ok": True, **das.public_profile(db, business)})
    if sub == "/agent/photo" and method == "GET":
        import desk_agent_settings as das
        data = das.photo_bytes(db)
        if data is None:
            raise desk_db.NotFoundError("no agent photo")
        return 200, b"image/jpeg", data
    if sub == "/start" and method == "POST":
        b = _body(raw)
        return _j(200, start_request(db, name=b.get("name", ""), phone=b.get("phone", ""),
                                     email=b.get("email", ""), send_by=b.get("send_by", ""), ip=ip,
                                     honeypot=b.get("website", ""), now=now))
    if sub == "/verify" and method == "POST":
        b = _body(raw)
        addr = b.get("address") if isinstance(b.get("address"), dict) else {}
        out = verify_and_file(db, contact_id=b.get("contact_id", ""), code=b.get("code", ""),
                              title=b.get("title", ""), description=b.get("description", ""),
                              job_id=b.get("job_id", ""), ip=ip, edition=edition,
                              base_url=base_url, now=now, path=b.get("path", "problem") or "problem",
                              service=b.get("service", ""), service_code=b.get("service_code", ""),
                              address=addr, preferred=b.get("preferred", ""),
                              window_key=b.get("window_key", ""), hold_id=b.get("hold_id", ""),
                              backups=b.get("backups") if isinstance(b.get("backups"), list) else [],
                              qty=b.get("qty", 1))
        return _j(201, out)

    if sub == "/ask" and method == "POST":
        b = _body(raw)
        return _j(200, ask_general(db, b.get("question", ""), edition=edition,
                                   business=business, page=b.get("page", "landing"),
                                   ask_token=b.get("ask_token", ""), ip=ip, now=now))
    if sub == "/ask/start" and method == "POST":
        b = _body(raw)
        return _j(200, start_ask_code(db, phone=b.get("phone", ""), email=b.get("email", ""),
                                      send_by=b.get("send_by", ""), ip=ip, now=now))
    if sub == "/ask/verify" and method == "POST":
        b = _body(raw)
        return _j(200, verify_ask_code(db, contact_id=b.get("contact_id", ""),
                                       code=b.get("code", ""), ip=ip, now=now))

    m = re.fullmatch(r"/t/([A-Za-z0-9_-]{20,100})(/.*)?", sub)
    if not m:
        return _j(404, {"ok": False, "error": "unknown_route", "message": "not found"})
    token, rest = m.group(1), m.group(2) or ""
    if rest == "" and method == "GET":
        return _j(200, {"ok": True, "ticket": status_view(db, token, edition=edition, now=now),
                        "business": business or ""})
    if rest == "/order/pay" and method == "POST":         # "Buy a product": Pay now
        return _j(200, pay_link(db, token, base_url=base_url, now=now))
    m3 = re.fullmatch(r"/booking/(accept|pick|reschedule|cancel|call|wait|unwait|take)", rest)
    if m3 and method == "POST":
        return _j(200, _booking_action(db, token, m3.group(1), _body(raw), edition=edition, now=now))
    if rest in ("/booking/windows", "/visit.ics") and method == "GET":
        t, c, _a = resolve_link(db, token, now)
        s = desk_db.get_settings(db)
        v = _booking_view(t, c, s)
        if not v:
            raise desk_db.NotFoundError("this request isn't a booking")
        import booking_flow
        try:
            if rest == "/visit.ics":
                return 200, b"text/calendar; charset=utf-8", booking_flow.ics(
                    _jobs_db(), t["job_id"], business=business or "").encode("utf-8")
            frm = datetime.date.fromisoformat(str(q.get("from"))) if q.get("from") else None
            return _j(200, {"ok": True, "windows": booking_flow.windows(
                _jobs_db(), s, v["service_code"], edition, from_date=frm,
                to_date=(frm + datetime.timedelta(days=13)) if frm else None)})
        except (booking_flow.BookingError, ValueError) as e:
            raise desk_db.DeskError(str(e)) from None
    t, c, actor = resolve_link(db, token, now)
    tid = t["ticket_id"]
    if rest == "/reply" and method == "POST":
        b = _body(raw)
        desk_db.add_message(db, tid, b.get("body", ""), actor=actor, edition=edition,
                            visibility="public", channel="portal")
        return _j(201, {"ok": True})
    if rest == "/ask" and method == "POST":
        b = _body(raw)
        return _j(200, ask_assistant(db, token, b.get("question", ""), edition=edition,
                                     business=business, ip=ip, now=now))
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


def frame_policy(db_path: str) -> bytes:
    """The Content-Security-Policy for the customer page (booking-spec.md §4): it may be shown
    in a frame only on the websites listed in Allowed websites; none listed = no framing."""
    try:
        sites = desk_db.get_settings(db_path).get("booking_allowed_sites") or []
    except Exception:  # noqa: BLE001
        sites = []
    src = " ".join(["'self'"] + [f"https://{x}" for x in sites if isinstance(x, str) and x and " " not in x and ";" not in x])
    return f"frame-ancestors {src}".encode("ascii", "ignore")


def static_page(path: str) -> tuple:
    """/book, /support/new and /support/t/<token> all serve desk/support.html."""
    import desk_http
    st, ct, body, rel = desk_http.static_file("/desk/support.html")
    return st, ct, body
