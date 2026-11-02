"""
desk_staff_booking.py — booking for a customer from the Service Desk app's + (booking-spec.md
§9.2, Phase 3).

A customer phones (or walks up); someone on the team opens + → Customer request and picks
  • Book a visit         — an arrival window from the same live list the website uses
                           (any Services & Pricing item when allowed), or, for people who may
                           override, any date and times ("outside the rules")
  • New service request  — a Requested job (no date) + ticket, same as the website's
  • Problem              — the ordinary ticket form (unchanged; not handled here)

The customer's phone is always required. The booking makes the same job, booking record and
ticket (with a status link) as the website, so it shows in 📅 To approve, the status page and the
timer exactly like one booked online. Approval follows staff_booking_approval: a booking made by
an approver (owner; managers on a server when allowed) is confirmed as it's made.

Settings (desk_db.SETTING_DEFAULTS): staff_booking, staff_booking_roles, staff_booking_approval,
staff_booking_override, staff_booking_double_book, staff_booking_all_services,
staff_booking_notify. Crew choice follows booking_crew_mode (approver | suggested | office).
"""
from __future__ import annotations

import desk_db
import desk_rules as rules

STAFF_PATHS = ("book", "new")


class StaffBookingError(desk_db.DeskError):
    pass


def _actor(actor) -> dict:
    return rules.normalize_actor(actor)


def actor_name(actor) -> str:
    a = _actor(actor)
    return (a.get("name") or a.get("email") or a.get("id") or "staff").strip()[:80]


def can_book(actor, edition: str, settings: dict) -> bool:
    """The owner always (when staff booking is on); on a server also the roles listed in
    staff_booking_roles. Customers and subcontractors never."""
    if not settings.get("staff_booking"):
        return False
    a = _actor(actor)
    if a["role"] == rules.OWNER:
        return True
    if rules.is_external(actor) or edition != rules.BUSINESS:
        return False
    return a["role"] in (settings.get("staff_booking_roles") or [])


def can_override(actor, edition: str, settings: dict) -> bool:
    import booking_flow
    if not can_book(actor, edition, settings):
        return False
    who = settings.get("staff_booking_override", "approvers")
    if who == "everyone":
        return True
    if who == "approvers":
        return booking_flow.can_approve(actor, edition, settings)
    return False


def confirms_at_once(actor, edition: str, settings: dict) -> bool:
    """Approvers' bookings are approved by making them; otherwise staff_booking_approval decides."""
    import booking_flow
    return booking_flow.can_approve(actor, edition, settings) or not settings.get("staff_booking_approval", True)


def _jobs_db(jobs_db: str | None) -> str:
    if jobs_db:
        return jobs_db
    import desk_portal
    j = desk_portal._jobs_db()
    if not j:
        raise StaffBookingError("the Jobs app is not available on this AI-Prowler")
    return j


def _check_can_book(actor, edition, s):
    if not s.get("staff_booking"):
        raise StaffBookingError("booking for customers is switched off — turn it on in AI-Prowler → "
                                "Service Desk settings → 🌐 Web forms")
    if not can_book(actor, edition, s):
        raise StaffBookingError("you can't book visits for customers — ask the owner")


# ── what the form needs ──────────────────────────────────────────────────────

def options(tickets_db: str, *, actor, edition: str, jobs_db: str | None = None, team=None) -> dict:
    """GET /desk-api/book — services, crews and what this person may do."""
    import booking_db
    import booking_flow
    s = desk_db.get_settings(tickets_db)
    _check_can_book(actor, edition, s)
    jdb = _jobs_db(jobs_db)
    all_services = bool(s.get("staff_booking_all_services", True))
    try:
        booking_db.sync_services(jdb, by=actor_name(actor))
    except Exception:  # noqa: BLE001 — a stale list is still a list
        pass
    services = [{"code": x["code"], "name": x.get("name") or x["code"], "online": bool(x.get("online")),
                 "minutes": x.get("minutes")}
                for x in booking_db.list_services(jdb, online_only=not all_services)]
    crews = []
    if edition == rules.BUSINESS:
        names = {}
        try:
            names = {u["id"]: u.get("name") or u["id"] for u in (team() if team else [])}
        except Exception:  # noqa: BLE001
            names = {}
        crews = [{"id": c.crew_id, "name": names.get(c.crew_id, c.crew_id)}
                 for c in booking_flow.crews_for(jdb, edition) if c.crew_id != "team"]
    return {"paths": list(STAFF_PATHS), "services": services, "crews": crews,
            "crew_mode": s.get("booking_crew_mode", "approver"),
            "can_override": can_override(actor, edition, s),
            "can_double_book": bool(s.get("staff_booking_double_book")),
            "confirms_at_once": confirms_at_once(actor, edition, s),
            "notify": bool(s.get("staff_booking_notify", True)),
            "area_note": _area_note(s)}


def _area_note(s) -> str:
    zips, miles = s.get("booking_area_zips") or [], int(s.get("booking_area_miles") or 0)
    if not zips and not miles:
        return ""
    parts = ([f"ZIPs {', '.join(zips[:6])}{'…' if len(zips) > 6 else ''}"] if zips else []) + \
            ([f"within {miles} miles"] if miles else [])
    return "Service area: " + " or ".join(parts)


def windows(tickets_db: str, service_code: str, *, actor, edition: str, jobs_db: str | None = None,
            from_date=None) -> list:
    import datetime as dt

    import booking_flow
    s = desk_db.get_settings(tickets_db)
    _check_can_book(actor, edition, s)
    frm = dt.date.fromisoformat(from_date) if from_date else None
    try:
        return booking_flow.windows(_jobs_db(jobs_db), s, service_code, edition,
                                    online_only=not s.get("staff_booking_all_services", True), from_date=frm,
                                    to_date=(frm + dt.timedelta(days=13)) if frm else None)
    except booking_flow.BookingError as e:
        raise StaffBookingError(str(e)) from None


# ── booking ──────────────────────────────────────────────────────────────────

def book(tickets_db: str, *, actor, edition: str, path: str = "book", name: str = "", phone: str = "",
         email: str = "", address: dict | None = None, service_code: str = "", service: str = "",
         window_key: str = "", custom: dict | None = None, crew: str = "", notify: bool | None = None,
         description: str = "", preferred: str = "", source: str = "phone", base_url: str = "",
         jobs_db: str | None = None, now=None) -> dict:
    """POST /desk-api/book. Returns {ticket_id, job_id, booking, warnings, url}.
    custom = {"date": "YYYY-MM-DD", "start": "HH:MM", "end": "HH:MM"} books outside the rules
    (only for people who may override)."""
    import booking_db
    import booking_flow
    import desk_portal
    s = desk_db.get_settings(tickets_db)
    _check_can_book(actor, edition, s)
    jdb = _jobs_db(jobs_db)
    path = (path or "book").strip().lower()
    if path not in STAFF_PATHS:
        raise StaffBookingError("choose Book a visit or New service request")
    name = (name or "").strip()[:80]
    if not name:
        raise StaffBookingError("enter the customer's name")
    phone = desk_portal.clean_phone(phone)                      # always required (spec §3)
    email = (email or "").strip()[:120]
    a = {k: str((address or {}).get(k, "") or "").strip()[:120] for k in ("street", "city", "state", "zip")}
    if not a["street"] or not (a["city"] or a["zip"]):
        raise StaffBookingError("enter the service address (street, and city or ZIP)")
    service_code = (service_code or "").strip()[:40]
    service = (service or "").strip()[:120]
    who = actor_name(actor)
    notify = bool(s.get("staff_booking_notify", True)) if notify is None else bool(notify)
    warnings, held, override = [], None, False
    if path == "book" and not service_code:
        raise StaffBookingError("pick a service")
    if path == "new" and not (service or service_code):
        raise StaffBookingError("say which service they'd like")
    in_area, why = booking_db.area_check(jdb, s, a)
    if not in_area:
        warnings.append(f"Outside your service area ({why}).")

    if path == "book":
        try:
            svc = booking_db.service(jdb, service_code,
                                     online_only=not s.get("staff_booking_all_services", True))
        except booking_flow.BookingError as e:
            raise StaffBookingError(str(e)) from None
        if not service:
            row = next((x for x in booking_db.list_services(jdb) if x["code"] == svc.code), {})
            service = row.get("name") or svc.code
        mode = s.get("booking_crew_mode", "approver")
        if crew and (edition != rules.BUSINESS or mode == "office"):
            crew = ""                                   # personal installs have one crew; "office" assigns later
        if custom:
            if not can_override(actor, edition, s):
                raise StaffBookingError("only " + {"approvers": "approvers", "everyone": "people who can book",
                                                   "nobody": "nobody"}[s.get("staff_booking_override", "approvers")]
                                        + " can book outside the open times")
            override = True
            try:
                held = booking_db.force_hold(jdb, service_code, custom.get("date", ""), custom.get("start", ""),
                                             custom.get("end", ""), crew=crew, now=booking_flow._now(now))
            except booking_flow.BookingError as e:
                raise StaffBookingError(str(e)) from None
        else:
            if not window_key:
                raise StaffBookingError("pick a time")
            try:
                held = booking_flow._hold(jdb, s, service_code, window_key, kind="checkout", minutes=10,
                                          edition=edition, now=now,
                                          online_only=not s.get("staff_booking_all_services", True))
            except booking_flow.BookingError as e:
                raise StaffBookingError(str(e)) from None
            if not held:
                raise StaffBookingError(f"{booking_flow.label_of(window_key)} isn't open any more — pick another time")
        if crew and (override or crew != held.get("crew")):     # the engine didn't place this crew
            clash = booking_db.crew_clash(jdb, crew, held["hold_date"], held["start_time"], held["end_time"],
                                          skip_hold=held["hold_id"], now=booking_flow._now(now))
            if clash:
                if not s.get("staff_booking_double_book"):
                    booking_db.release_hold(jdb, held["hold_id"])
                    raise StaffBookingError(f"{crew} already has {', '.join(clash)} then — pick another crew or time")
                warnings.append(f"Double-booked: {crew} already has {', '.join(clash)}.")
            _set_hold_crew(jdb, held["hold_id"], crew)
            held["crew"] = crew
        if override:
            warnings.append("Booked outside the open times (override).")

    # ── the customer: ticket contact + Jobs customer ──
    contact = desk_db.upsert_contact(tickets_db, name=name, phone=phone, email=email or None,
                                     contact_type="customer", actor=actor)
    try:
        customer_id, _created = booking_db.find_or_create_customer(
            jdb, name=name, phone=phone, email=email, street=a["street"], city=a["city"], state=a["state"],
            zip_code=a["zip"])
    except Exception as e:  # noqa: BLE001
        if held:
            booking_db.release_hold(jdb, held["hold_id"])
        raise StaffBookingError(f"couldn't add the customer to the Jobs app: {e}") from None
    if not contact.get("linked_customer_id"):
        try:
            desk_db.upsert_contact(tickets_db, name=name, phone=phone, email=email or None,
                                   linked_customer_id=customer_id, actor=actor)
        except Exception:  # noqa: BLE001
            pass

    addr_text = desk_portal._address_text(a)
    if path == "book":
        label = booking_flow.label_of(booking_flow.key_of(held))
        try:
            made = booking_flow.create_pending(jdb, s, held, customer_id=customer_id, customer_name=name,
                                               service_name=service, notes=description or "", street=a["street"],
                                               city=a["city"], state=a["state"], zip_code=a["zip"],
                                               edition=edition, now=now, made_by=who)
        except Exception as e:  # noqa: BLE001
            booking_db.release_hold(jdb, held["hold_id"])
            raise StaffBookingError(f"couldn't make the booking: {e}") from None
        job_id = made["job_id"]
        title = f"{service} — {label}"
        body = "\n".join(x for x in ((description or "").strip(), f"Wants: {label} (arrival window)",
                                     f"Address: {addr_text}", f"Phone: {phone}", f"Booked by {who}.") if x)
    else:
        job_id = booking_db.create_request_job(jdb, customer_id=customer_id, customer_name=name,
                                               service=service or service_code, service_code=service_code,
                                               notes=description or "", preferred=preferred or "",
                                               street=a["street"], city=a["city"], state=a["state"], zip_code=a["zip"])
        title = f"New service request — {service or service_code}"
        body = "\n".join(x for x in ((description or "").strip(), f"Address: {addr_text}",
                                     f"Preferred: {preferred.strip()}" if (preferred or "").strip() else "",
                                     f"Phone: {phone}", f"Taken by {who}.") if x)
    src = source if source in ("phone", "sms", "email", "walk_in", "pwa") else "phone"
    t = desk_db.create_ticket(tickets_db, title=title[:200], kind=rules.EXTERNAL, actor=actor, edition=edition,
                              description=body[:5000], source=src, contact_id=contact["contact_id"],
                              customer_id=customer_id, job_id=job_id)
    booking_db.link_request_ticket(jdb, job_id, t["ticket_id"])
    booking = None
    if path == "book":
        booking = {"status": "pending", "label": label}
        if confirms_at_once(actor, edition, s):
            try:
                done = booking_flow.approve(jdb, tickets_db, job_id, actor=actor, edition=edition, settings=s,
                                            crew=(crew or None), now=now, quiet=True,
                                            system=not booking_flow.can_approve(actor, edition, s))
                booking = {"status": "scheduled", "label": done["label"]}
            except Exception as e:  # noqa: BLE001 — stays in 📅 To approve
                warnings.append(f"Couldn't confirm it straight away ({e}) — it's waiting in 📅 To approve.")
    for w in warnings:
        try:
            desk_db.add_message(tickets_db, t["ticket_id"], w, actor={"id": "system", "role": "owner"},
                                edition=edition, visibility="internal", channel="system")
        except Exception:  # noqa: BLE001
            pass
    token = desk_portal.issue_link(tickets_db, t["ticket_id"], contact["contact_id"])
    url = desk_portal.link_url(base_url, token)
    sent = ""
    if notify:
        if booking and booking["status"] == "scheduled":
            said = f"Booked: {booking['label']} (arrival window), ref {t['ticket_id']}. Details: {url}"
        elif booking:
            said = (f"We're holding {booking['label']} for you (ref {t['ticket_id']}) — we'll confirm it shortly. "
                    f"Details: {url}")
        else:
            said = f"We got your request {t['ticket_id']}: {title}. We'll call you to schedule it. Details: {url}"
        ch = desk_portal.channels()
        for channel, to in (("sms", contact.get("phone")), ("email", contact.get("email"))):
            if to and ch.get(channel) and desk_portal._send(channel, to, f"Your booking [{t['ticket_id']}]", said):
                sent = channel
                break
        if not sent:
            warnings.append("Couldn't send the customer a confirmation — let them know yourself.")
    return {"ok": True, "ticket_id": t["ticket_id"], "job_id": job_id, "booking": booking, "url": url,
            "warnings": warnings, "sent_via": sent, "out_of_area": not in_area}


def _set_hold_crew(jobs_db: str, hold_id: str, crew: str) -> None:
    from db_access import get_connection
    conn = get_connection(jobs_db)
    try:
        conn.execute("UPDATE booking_holds SET crew = ? WHERE hold_id = ?", (crew or None, hold_id))
    finally:
        conn.close()
