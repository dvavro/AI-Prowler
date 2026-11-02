"""
booking_db.py — service booking's data layer (booking-spec.md §5, §8, §11).

Reads the Jobs database and turns it into booking_slots inputs:
  * rules      — Jobs Settings (Working Days, Workday Start/End, Lunch) + the booking
                 rules from Service Desk settings
  * booked     — the jobs worked on each day (same R-058 rules routing uses, so
                 multi-day jobs and overruns count), active holds, and — personal
                 installs only — the ONE business Google Calendar's busy times
  * openings   — extra openings and closed days
Also: the online service list (loaded from Services & Pricing), holds (with the
"re-check then hold" step that stops two people taking the same last window),
openings, and the calendar busy cache.

Held windows never touch jobs.service_date — see db_schema.py "Service booking".
"""
from __future__ import annotations

import datetime as dt
import secrets

import booking_slots as bs
from db_access import get_connection, transaction, utcnow_iso

BUSINESS = "business"
PERSONAL = "solo"

# Booking rules that live in Service Desk settings (desk_db.SETTING_DEFAULTS) → Rules fields.
RULE_SETTINGS = {
    "booking_window_minutes": "window_minutes",
    "booking_lead_hours": "lead_hours",
    "booking_horizon_days": "horizon_days",
    "booking_max_per_day": "max_per_day",
    "booking_full_pct": "full_pct",
}
PRICE_DISPLAYS = ("none", "from", "exact")
SERVICE_MODES = ("instant", "request")
HOLD_KINDS = ("checkout", "pending", "suggested", "waitlist")
CHECKOUT_MINUTES = 10                      # spec §3: held while the customer enters the code
WEB_BOOKING = "web booking"                # jobs.created_by for bookings from the page


class BookingError(ValueError):
    pass


def _now() -> dt.datetime:
    return dt.datetime.now()


# ── service area (booking-spec.md §5) ────────────────────────────────────────
# A ZIP list and/or a radius in miles. The radius is measured from the Jobs app's
# Start/End Address (where the crews leave from), else its Business Address.

GEOCODE = None          # tests swap in a fake; None = the Jobs app's Nominatim lookup


def _geocode(address: str):
    if not str(address or "").strip():
        return None
    fn = GEOCODE
    if fn is None:
        from db_write_ops import _geocode as fn
    try:
        hit = fn(address)
        return (float(hit[0]), float(hit[1])) if hit else None
    except Exception:  # noqa: BLE001 — a lookup failure just means "can't check"
        return None


def area_origin(jobs_db: str) -> tuple:
    """(lat, lon, address) the radius is measured from, or (None, None, address-or-"")."""
    addr = ""
    try:
        from db_write_ops import db_read_route_address
        addr = db_read_route_address(jobs_db) if jobs_db else ""
        if not addr and jobs_db:
            conn = get_connection(jobs_db)
            try:
                addr = _jobs_setting(conn, "Business Address", "").strip()
            finally:
                conn.close()
    except Exception:  # noqa: BLE001
        pass
    hit = _geocode(addr)
    return (hit[0], hit[1], addr) if hit else (None, None, addr)


def address_line(a: dict) -> str:
    a = a or {}
    tail = " ".join(x for x in (str(a.get("state") or "").strip(), str(a.get("zip") or "").strip()) if x)
    return ", ".join(x for x in (str(a.get("street") or "").strip(), str(a.get("city") or "").strip(), tail) if x)


def area_check(jobs_db: str, settings: dict, address: dict) -> tuple:
    """(in_area, reason) for a customer address, using booking_area_zips and
    booking_area_miles. A ZIP on the list is in without any lookup; the radius
    needs both the start point and the address found on the map — if either
    can't be found, the reason says so (the page then takes a call-back request)."""
    s = settings or {}
    zips = s.get("booking_area_zips") or []
    try:
        miles = float(s.get("booking_area_miles") or 0)
    except (TypeError, ValueError):
        miles = 0.0
    z = str((address or {}).get("zip") or "").strip()[:5]
    if not zips and miles <= 0:
        return True, "no service area set"
    if zips and z in [str(x).strip()[:5] for x in zips]:
        return True, f"ZIP {z} is in the service area"
    if miles <= 0:
        return bs.in_service_area(z, zips=zips)
    olat, olon, oaddr = area_origin(jobs_db)
    if olat is None:
        return False, ("couldn't find your Start/End Address on the map to measure the distance"
                       if oaddr else "no Start/End Address set in the Jobs app to measure the distance from")
    hit = _geocode(address_line(address))
    if not hit:
        return False, "couldn't find that address on the map to check the distance"
    return bs.in_service_area(z, hit[0], hit[1], zips=zips, miles=miles, origin=(olat, olon))


# ── rules ────────────────────────────────────────────────────────────────────

def _jobs_setting(conn, key: str, default: str = "") -> str:
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return (row["value"] if row and row["value"] not in (None, "") else default) or default
    except Exception:  # noqa: BLE001
        return default


def rules_for(db_path: str, booking: dict | None = None) -> bs.Rules:
    """The Jobs app's working days/hours/lunch + the booking rules (Service Desk settings)."""
    from db_write_ops import working_days_conn
    conn = get_connection(db_path)
    try:
        days = working_days_conn(conn)
        start = bs.hhmm(_jobs_setting(conn, "Workday Start Time", "07:00"))
        end = bs.hhmm(_jobs_setting(conn, "Workday End Time", "17:00"))
        lunch = bs.hhmm(_jobs_setting(conn, "Lunch Break Start", "12:00"))
        try:
            lunch_min = int(float(_jobs_setting(conn, "Lunch Break Duration (min)", "60")))
        except ValueError:
            lunch_min = 60
    finally:
        conn.close()
    if start is None or end is None or end <= start:
        start, end = 7 * 60, 17 * 60
    kw = dict(working_days=days, day_start=start, day_end=end,
              lunch_start=lunch if lunch_min > 0 else None, lunch_minutes=max(0, lunch_min))
    for key, field in RULE_SETTINGS.items():
        if booking and booking.get(key) not in (None, ""):
            try:
                kw[field] = type(getattr(bs.Rules, field))(booking[key])
            except (TypeError, ValueError):
                pass
    return bs.Rules(**kw)


# ── services offered online (spec §8) ────────────────────────────────────────

def sync_services(db_path: str, by: str = "system") -> dict:
    """Make booking_services match Services & Pricing: new services are added (not shown
    online until the owner says so); services deleted there drop off. Returns counts."""
    with transaction(db_path) as conn:
        codes = {r["service_code"] for r in conn.execute("SELECT service_code FROM service_pricing")}
        have = {r["service_code"] for r in conn.execute("SELECT service_code FROM booking_services")}
        now = utcnow_iso()
        for i, code in enumerate(sorted(codes - have)):
            conn.execute("INSERT INTO booking_services (service_code, sort_order, last_edited_by, last_edited_at) "
                         "VALUES (?, ?, ?, ?)", (code, len(have) + i, by, now))
        gone = sorted(have - codes)
        for code in gone:
            conn.execute("DELETE FROM booking_services WHERE service_code = ?", (code,))
    return {"added": len(codes - have), "removed": len(gone)}


def _price_text(row) -> str:
    disp = row["price_display"] or "from"
    base, low = row["base_price"], row["min_charge"]
    if disp == "none":
        return ""
    if disp == "exact" and base:
        return f"${base:,.0f}" if float(base).is_integer() else f"${base:,.2f}"
    amount = low or base
    if not amount:
        return ""
    return f"from ${amount:,.0f}" if float(amount).is_integer() else f"from ${amount:,.2f}"


def list_services(db_path: str, online_only: bool = False) -> list:
    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            "SELECT b.*, p.name AS pricing_name, p.category, p.base_price, p.min_charge, p.unit_basis "
            "FROM booking_services b JOIN service_pricing p ON p.service_code = b.service_code "
            + ("WHERE b.online = 1 " if online_only else "")
            + "ORDER BY b.sort_order, p.name").fetchall()
    finally:
        conn.close()
    return [{"code": r["service_code"], "name": r["label"] or r["pricing_name"] or r["service_code"],
             "pricing_name": r["pricing_name"], "category": r["category"] or "",
             "description": r["description"] or "", "online": bool(r["online"]),
             "minutes": int(r["minutes"]), "people": int(r["people"]), "buffer_min": int(r["buffer_min"]),
             "price_display": r["price_display"], "price": _price_text(r), "mode": r["mode"],
             "needs_photos": bool(r["needs_photos"]),
             "outdoor": bool(r["outdoor"]) if "outdoor" in r.keys() else False,
             # "Buy a product" (2026-11-02): the price charged (Services & Pricing → Base Price)
             # and shipping & handling per item
             "unit_price": round(float(r["base_price"] or 0), 2),
             "shipping": round(float(r["shipping"] or 0), 2) if "shipping" in r.keys() else 0.0,
             "specs": (r["specs"] or "") if "specs" in r.keys() else ""} for r in rows]


def update_service(db_path: str, code: str, by: str = "system", **fields) -> dict:
    """Change one service's booking settings (validated). Returns the new row as listed."""
    checks = {
        "online": lambda v: int(bool(v)),
        "label": lambda v: (str(v).strip()[:80] or None) if v is not None else None,
        "description": lambda v: (str(v).strip()[:300] or None) if v is not None else None,
        "minutes": lambda v: _int_in(v, 15, 600, "minutes"),
        "people": lambda v: _int_in(v, 1, 20, "people needed"),
        "buffer_min": lambda v: _int_in(v, 0, 240, "buffer"),
        "price_display": lambda v: _one_of(v, PRICE_DISPLAYS, "price display"),
        "mode": lambda v: _one_of(v, SERVICE_MODES, "bookable"),
        "needs_photos": lambda v: int(bool(v)),
        "outdoor": lambda v: int(bool(v)),           # the booking agent's weather check
        "shipping": lambda v: _money(v, "shipping & handling"),   # per item, products only
        "specs": lambda v: _specs(v),                            # the product card's specs lines
        "sort_order": lambda v: _int_in(v, 0, 9999, "order"),
    }
    bad = sorted(set(fields) - set(checks))
    if bad:
        raise BookingError(f"unknown service setting(s): {', '.join(bad)}")
    vals = {k: checks[k](v) for k, v in fields.items()}
    with transaction(db_path) as conn:
        if not conn.execute("SELECT 1 FROM booking_services WHERE service_code = ?", (code,)).fetchone():
            raise BookingError(f"no service {code} — load services from Services & Pricing first")
        if vals:
            sets = ", ".join(f"{k} = ?" for k in vals)
            conn.execute(f"UPDATE booking_services SET {sets}, last_edited_by = ?, last_edited_at = ? "
                         "WHERE service_code = ?", (*vals.values(), by, utcnow_iso(), code))
    return next(s for s in list_services(db_path) if s["code"] == code)


def _int_in(v, lo, hi, what):
    try:
        n = int(float(v))
    except (TypeError, ValueError):
        raise BookingError(f"{what} must be a number") from None
    if not lo <= n <= hi:
        raise BookingError(f"{what} must be {lo}–{hi}")
    return n


SPECS_MAX = 2000


def _specs(v) -> str | None:
    """Specs text: trimmed lines, blank lines dropped, at most SPECS_MAX characters."""
    lines = [ln.strip() for ln in str(v or "").replace("\r", "").split("\n")]
    text = "\n".join(ln for ln in lines if ln)
    if len(text) > SPECS_MAX:
        raise BookingError(f"specs can be up to {SPECS_MAX} characters")
    return text or None


def _money(v, what, hi: float = 10000.0) -> float:
    """'$12.50' / '12.5' / '' -> 12.5 / 12.5 / 0.0, checked 0..hi."""
    s = str(v if v is not None else "").strip().replace("$", "").replace(",", "")
    if s == "":
        return 0.0
    try:
        n = float(s)
    except ValueError:
        raise BookingError(f"{what} must be an amount, like 12.50") from None
    if n != n or not 0 <= n <= hi:
        raise BookingError(f"{what} must be $0 to ${hi:,.0f}")
    return round(n, 2)


def _one_of(v, allowed, what):
    v = str(v or "").strip().lower()
    if v not in allowed:
        raise BookingError(f"{what} must be one of: {', '.join(allowed)}")
    return v


def service(db_path: str, code: str, *, online_only: bool = False) -> bs.Service:
    s = next((x for x in list_services(db_path, online_only=online_only) if x["code"] == code), None)
    if not s:
        raise BookingError(f"{code} isn't a service offered online" if online_only else f"no service {code}")
    if online_only and s.get("mode") == "request":
        # 2026-11-02: a Product (Type = Product in Web forms) is asked for, never booked in a time window
        raise BookingError(f"{s['name']} can't be booked online — ask for it with \"Request a new service\"")
    return bs.Service(code, s["minutes"], s["people"], s["buffer_min"])


# ── what's already booked (spec §5) ──────────────────────────────────────────

_GONE = ("cancelled", "canceled", "declined")


def _job_crew(row, crew_ids) -> str | None:
    cid = str(row["crew_user_id"] or "").strip()
    return cid if cid and cid in crew_ids else None


def booked_for(db_path: str, d_from: dt.date, d_to: dt.date, rules: bs.Rules, *, crews=(bs.Crew("owner"),),
               edition: str = PERSONAL, now: dt.datetime | None = None) -> list:
    """Every Booked item between the dates: jobs (R-058 day rules), active holds and,
    on a personal install only, the business calendar's busy times."""
    from db_route_ops import _jobs_worked_on
    now = now or _now()
    crew_ids = {c.crew_id for c in crews}
    out = []
    try:                                  # bookings made by staff keep their window too (Phase 3)
        _c = get_connection(db_path)
        try:
            booked_ids = {r[0] for r in _c.execute("SELECT job_id FROM booking_requests WHERE path = 'book'")}
        finally:
            _c.close()
    except Exception:  # noqa: BLE001
        booked_ids = set()
    d = d_from
    while d <= d_to:
        for row, _n in _jobs_worked_on(db_path, d.isoformat()):
            if str(row["job_status"] or "").strip().lower() in _GONE:
                continue
            minutes = bs.job_minutes(row["est_duration"], row["est_duration_unit"], rules)
            multi = bool(row["end_date"]) and row["end_date"] != row["service_date"]
            if multi:
                minutes = bs.work_minutes([(rules.day_start, rules.day_end)], rules)
            hard = str(row["schedule_type"] or "").strip().lower() == "hard"
            start = bs.hhmm(row["start_time"]) if hard and not multi else None
            # A visit booked online keeps its arrival window: it blocks the window's start for
            # its work + the usual buffer, even though it's a soft job for routing (2026-10-30).
            kind, end = "job", None
            windowed = (row["created_by"] or "") == WEB_BOOKING or row["job_id"] in booked_ids
            if start is None and not multi and windowed and row["start_time"]:
                start, end = bs.hhmm(row["start_time"]), bs.hhmm(row["end_time"])
                if start is not None:
                    minutes += bs.Service("").buffer_min
                    kind = "window" if end is not None and end > start else "job"
            out.append(bs.Booked(d, minutes, start=start, end=end if kind == "window" else None,
                                 crew=_job_crew(row, crew_ids), kind=kind,
                                 online=(row["created_by"] or "") == WEB_BOOKING))
        d += dt.timedelta(days=1)
    conn = get_connection(db_path)
    try:
        for h in conn.execute("SELECT * FROM booking_holds WHERE hold_date BETWEEN ? AND ? AND expires_at > ?",
                              (d_from.isoformat(), d_to.isoformat(), now.isoformat(timespec="seconds"))):
            out.append(bs.Booked(dt.date.fromisoformat(h["hold_date"]), int(h["minutes"]),
                                 start=bs.hhmm(h["start_time"]), end=bs.hhmm(h["end_time"]),
                                 crew=h["crew"] if h["crew"] in crew_ids else None, kind="hold", online=True))
        if edition != BUSINESS:                       # servers use the Jobs app calendar only
            lo = d_from.isoformat()
            hi = (d_to + dt.timedelta(days=1)).isoformat()
            for b in conn.execute("SELECT * FROM calendar_busy WHERE end_at > ? AND start_at < ?", (lo, hi)):
                out.extend(_busy_days(b, d_from, d_to))
    finally:
        conn.close()
    return out


def _busy_days(b, d_from, d_to) -> list:
    """One calendar busy block split into per-day Booked items (business-wide)."""
    try:
        s = dt.datetime.fromisoformat(b["start_at"])
        e = dt.datetime.fromisoformat(b["end_at"])
    except ValueError:
        return []
    out = []
    d = max(s.date(), d_from)
    while d <= min(e.date(), d_to):
        if b["all_day"]:
            a, z = 0, bs.DAY
        else:
            a = s.hour * 60 + s.minute if d == s.date() else 0
            z = e.hour * 60 + e.minute if d == e.date() else bs.DAY
        if z > a:
            out.append(bs.Booked(d, z - a, start=a, end=z, crew=None, kind="busy"))
        d += dt.timedelta(days=1)
    return out


# ── openings and closed days (spec §9.3) ────────────────────────────────────

def add_opening(db_path: str, kind: str, date: str, start: str = "", end: str = "", who: str = "",
                note: str = "", by: str = "system") -> str:
    kind = _one_of(kind, ("open", "closed"), "kind")
    try:
        dt.date.fromisoformat(date)
    except (TypeError, ValueError):
        raise BookingError("date must be YYYY-MM-DD") from None
    s, e = bs.hhmm(start), bs.hhmm(end)
    if (start and s is None) or (end and e is None):
        raise BookingError("times must look like 08:00")
    if s is not None and e is not None and e <= s:
        raise BookingError("the end time must be after the start time")
    if kind == "open" and (s is None or e is None):
        raise BookingError("an extra opening needs a start and end time")
    oid = "OPN-" + secrets.token_hex(4).upper()
    conn = get_connection(db_path)
    try:
        conn.execute("INSERT INTO booking_openings (opening_id, kind, open_date, start_time, end_time, who, note, "
                     "created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (oid, kind, date, bs.fmt(s) if s is not None else None, bs.fmt(e) if e is not None else None,
                      who or None, note or None, by, utcnow_iso()))
    finally:
        conn.close()
    return oid


def delete_opening(db_path: str, opening_id: str) -> bool:
    conn = get_connection(db_path)
    try:
        return conn.execute("DELETE FROM booking_openings WHERE opening_id = ?", (opening_id,)).rowcount > 0
    finally:
        conn.close()


def openings_for(db_path: str, d_from: dt.date, d_to: dt.date) -> list:
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT * FROM booking_openings WHERE open_date BETWEEN ? AND ? ORDER BY open_date",
                            (d_from.isoformat(), d_to.isoformat())).fetchall()
    finally:
        conn.close()
    return [bs.Opening(dt.date.fromisoformat(r["open_date"]), r["kind"], bs.hhmm(r["start_time"]),
                       bs.hhmm(r["end_time"]), r["who"] or None) for r in rows]


# ── open windows ─────────────────────────────────────────────────────────────

def windows_for(db_path: str, service_code: str, *, booking: dict | None = None, now: dt.datetime | None = None,
                edition: str = PERSONAL, crews=(bs.Crew("owner"),), online_only: bool = True,
                from_date: dt.date | None = None, to_date: dt.date | None = None) -> list:
    now = now or _now()
    rules = rules_for(db_path, booking)
    svc = service(db_path, service_code, online_only=online_only)
    d_from = max(from_date or now.date(), now.date())
    d_to = now.date() + dt.timedelta(days=rules.horizon_days)
    if to_date and to_date < d_to:
        d_to = to_date
    if d_to < d_from:
        return []
    return bs.open_windows(svc, rules=rules, now=now, crews=crews,
                           booked=booked_for(db_path, d_from, d_to, rules, crews=crews, edition=edition, now=now),
                           openings=openings_for(db_path, d_from, d_to), from_date=d_from, to_date=d_to)


# ── holds (spec §3, §7a) ─────────────────────────────────────────────────────

def hold_window(db_path: str, service_code: str, window_key: str, *, kind: str = "checkout",
                minutes_to_live: int = CHECKOUT_MINUTES, contact_hash: str = "", job_id: str = "",
                booking: dict | None = None, now: dt.datetime | None = None, edition: str = PERSONAL,
                crews=(bs.Crew("owner"),), online_only: bool = True) -> dict | None:
    """Re-check that `window_key` (Window.key) is still open and hold it, inside one write
    transaction — so two people racing for the last window can't both get it. Returns
    the hold (dict) or None when the window has gone."""
    kind = _one_of(kind, HOLD_KINDS, "hold kind")
    now = now or _now()
    try:
        day = dt.date.fromisoformat(window_key[:10])
    except ValueError:
        raise BookingError("bad window") from None
    svc = service(db_path, service_code, online_only=online_only)
    with transaction(db_path) as conn:                    # BEGIN IMMEDIATE: one booker at a time
        found = next((w for w in windows_for(db_path, service_code, booking=booking, now=now, edition=edition,
                                             crews=crews, online_only=online_only, from_date=day, to_date=day)
                      if w.key == window_key), None)
        if not found:
            return None
        hold = {"hold_id": "HLD-" + secrets.token_hex(5).upper(), "job_id": job_id or None, "kind": kind,
                "hold_date": found.date.isoformat(), "start_time": bs.fmt(found.start), "end_time": bs.fmt(found.end),
                "minutes": svc.need, "crew": found.crew, "service_code": service_code,
                "contact_hash": contact_hash or None, "created_at": utcnow_iso(),
                "expires_at": (now + dt.timedelta(minutes=minutes_to_live)).isoformat(timespec="seconds")}
        conn.execute(f"INSERT INTO booking_holds ({', '.join(hold)}) VALUES ({', '.join('?' * len(hold))})",
                     tuple(hold.values()))
    return hold


def force_hold(db_path: str, service_code: str, date: str, start: str, end: str, *, kind: str = "checkout",
               minutes_to_live: int = CHECKOUT_MINUTES, crew: str = "", job_id: str = "",
               now: dt.datetime | None = None) -> dict:
    """Staff override (booking-spec.md §9.2): hold a window the rules wouldn't offer —
    outside hours, past the daily cap, over a soft job. No availability check; the
    caller has already checked the person may override."""
    kind = _one_of(kind, HOLD_KINDS, "hold kind")
    now = now or _now()
    try:
        day = dt.date.fromisoformat(str(date)[:10])
    except ValueError:
        raise BookingError("pick a date") from None
    s, e = bs.hhmm(start), bs.hhmm(end)
    if s is None or e is None or e <= s:
        raise BookingError("the window needs a start time before its end time")
    if day < now.date():
        raise BookingError("that date has passed")
    svc = service(db_path, service_code)
    hold = {"hold_id": "HLD-" + secrets.token_hex(5).upper(), "job_id": job_id or None, "kind": kind,
            "hold_date": day.isoformat(), "start_time": bs.fmt(s), "end_time": bs.fmt(e),
            "minutes": svc.need, "crew": crew or None, "service_code": service_code,
            "contact_hash": None, "created_at": utcnow_iso(),
            "expires_at": (now + dt.timedelta(minutes=minutes_to_live)).isoformat(timespec="seconds")}
    with transaction(db_path) as conn:
        conn.execute(f"INSERT INTO booking_holds ({', '.join(hold)}) VALUES ({', '.join('?' * len(hold))})",
                     tuple(hold.values()))
    return hold


def crew_clash(db_path: str, crew: str, date: str, start: str, end: str, *, skip_hold: str = "",
               now: dt.datetime | None = None) -> list:
    """What `crew` already has overlapping date start–end: timed jobs and live holds.
    Returns short labels ('JOB-0012 8:00–10:00'). Untimed (soft) jobs aren't counted."""
    if not crew:
        return []
    s, e = bs.hhmm(start), bs.hhmm(end)
    if s is None or e is None:
        return []
    now = (now or _now()).isoformat(timespec="seconds")
    out = []
    conn = get_connection(db_path)
    try:
        for r in conn.execute("SELECT job_id, start_time, end_time, job_status FROM jobs WHERE service_date = ? "
                              "AND crew_user_id = ?", (str(date)[:10], crew)):
            if str(r["job_status"] or "").strip().lower() in _GONE:
                continue
            a, b = bs.hhmm(r["start_time"]), bs.hhmm(r["end_time"])
            if a is not None and b is not None and a < e and s < b:
                out.append(f"{r['job_id']} {bs.nice(a)}–{bs.nice(b)}")
        for h in conn.execute("SELECT hold_id, job_id, start_time, end_time FROM booking_holds WHERE hold_date = ? "
                              "AND crew = ? AND expires_at > ? AND hold_id != ?", (str(date)[:10], crew, now, skip_hold)):
            a, b = bs.hhmm(h["start_time"]), bs.hhmm(h["end_time"])
            if a is not None and b is not None and a < e and s < b:
                out.append(f"{h['job_id'] or 'a held booking'} {bs.nice(a)}–{bs.nice(b)}")
    finally:
        conn.close()
    return out


def extend_hold(db_path: str, hold_id: str, *, kind: str, minutes_to_live: int, job_id: str = "",
                now: dt.datetime | None = None) -> bool:
    """Turn a checkout hold into a pending / suggested one (after the code), with a new expiry."""
    kind = _one_of(kind, HOLD_KINDS, "hold kind")
    now = now or _now()
    conn = get_connection(db_path)
    try:
        return conn.execute(
            "UPDATE booking_holds SET kind = ?, expires_at = ?, job_id = COALESCE(NULLIF(?, ''), job_id) "
            "WHERE hold_id = ? AND expires_at > ?",
            (kind, (now + dt.timedelta(minutes=minutes_to_live)).isoformat(timespec="seconds"), job_id,
             hold_id, now.isoformat(timespec="seconds"))).rowcount > 0
    finally:
        conn.close()


def release_hold(db_path: str, hold_id: str) -> bool:
    conn = get_connection(db_path)
    try:
        return conn.execute("DELETE FROM booking_holds WHERE hold_id = ?", (hold_id,)).rowcount > 0
    finally:
        conn.close()


def get_hold(db_path: str, hold_id: str) -> dict | None:
    conn = get_connection(db_path)
    try:
        r = conn.execute("SELECT * FROM booking_holds WHERE hold_id = ?", (hold_id,)).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def expire_holds(db_path: str, now: dt.datetime | None = None) -> list:
    """Delete holds past their expiry. Returns them (the caller tells people / the waitlist)."""
    now = (now or _now()).isoformat(timespec="seconds")
    with transaction(db_path) as conn:
        gone = [dict(r) for r in conn.execute("SELECT * FROM booking_holds WHERE expires_at <= ?", (now,))]
        conn.execute("DELETE FROM booking_holds WHERE expires_at <= ?", (now,))
    return gone


# ── business calendar busy cache (personal installs only, spec §6) ──────────

def replace_busy(db_path: str, d_from: str, d_to: str, blocks: list, *, edition: str = PERSONAL) -> int:
    """Replace the cached busy times between two dates (inclusive) with `blocks`
    [{"start": "YYYY-MM-DDTHH:MM", "end": …, "all_day": bool}] — so an event deleted on
    Google stops blocking. Refused on a server (it uses the Jobs app calendar only)."""
    if edition == BUSINESS:
        raise BookingError("the server uses the Jobs app calendar only — no Google Calendar")
    try:
        lo, hi = dt.date.fromisoformat(d_from), dt.date.fromisoformat(d_to)
    except (TypeError, ValueError):
        raise BookingError("dates must be YYYY-MM-DD") from None
    rows = []
    for b in blocks or []:
        try:
            s = dt.datetime.fromisoformat(str(b["start"]))
            e = dt.datetime.fromisoformat(str(b["end"]))
        except (KeyError, ValueError):
            raise BookingError("each busy block needs a start and end like 2026-11-04T10:00") from None
        if e <= s:
            raise BookingError("a busy block must end after it starts")
        rows.append((s.isoformat(timespec="minutes"), e.isoformat(timespec="minutes"), int(bool(b.get("all_day")))))
    synced = utcnow_iso()
    with transaction(db_path) as conn:
        conn.execute("DELETE FROM calendar_busy WHERE start_at < ? AND end_at > ?",
                     ((hi + dt.timedelta(days=1)).isoformat(), lo.isoformat()))
        conn.executemany("INSERT INTO calendar_busy (start_at, end_at, all_day, synced_at) VALUES (?, ?, ?, ?)",
                         [(*r, synced) for r in rows])
        conn.execute("INSERT INTO calendar_sync_log (ran_at, blocks, pushed, errors, runner) VALUES (?, ?, 0, 0, ?)",
                     (synced, len(rows), "busy"))
    return len(rows)


def last_busy_sync(db_path: str) -> str | None:
    conn = get_connection(db_path)
    try:
        r = conn.execute("SELECT MAX(ran_at) AS t FROM calendar_sync_log WHERE runner = 'busy'").fetchone()
        return r["t"] if r else None
    finally:
        conn.close()


# ── customers and jobs from the web page (spec §3, §7; Phase 1) ─────────────

def _digits10(phone) -> str:
    d = "".join(ch for ch in str(phone or "") if ch.isdigit())
    return d[-10:] if len(d) >= 10 else d


def find_customer(conn, phone: str = "", email: str = "") -> dict | None:
    """An existing Jobs customer with this phone (last 10 digits) or, failing that, email."""
    p, e = _digits10(phone), (email or "").strip().lower()
    if p:
        for r in conn.execute("SELECT * FROM customers WHERE COALESCE(phone, '') <> ''"):
            if _digits10(r["phone"]) == p:
                return dict(r)
    if e:
        r = conn.execute("SELECT * FROM customers WHERE LOWER(TRIM(COALESCE(email, ''))) = ?", (e,)).fetchone()
        if r:
            return dict(r)
    return None


def find_or_create_customer(db_path: str, *, name: str = "", phone: str = "", email: str = "",
                            street: str = "", city: str = "", state: str = "", zip_code: str = "",
                            by: str = WEB_BOOKING) -> tuple:
    """(customer_id, created?). Matched by phone then email; an existing customer's
    details are never overwritten from the web (only blanks are filled in)."""
    from db_write_ops import generate_next_id
    with transaction(db_path) as conn:
        found = find_customer(conn, phone, email)
        now = utcnow_iso()
        if found:
            fill = {k: v for k, v in (("phone", phone), ("email", email), ("street_address", street),
                                      ("city", city), ("state", state), ("zip", zip_code))
                    if v and not str(found.get(k) or "").strip()}
            if fill:
                sets = ", ".join(f"{k} = ?" for k in fill)
                conn.execute(f"UPDATE customers SET {sets}, last_edited_by = ?, last_edited_at = ?, "
                             "version = version + 1 WHERE customer_id = ?",
                             (*fill.values(), by, now, found["customer_id"]))
            return found["customer_id"], False
        first, _, last = (name or "").strip().partition(" ")
        cid = generate_next_id(conn, "customers", "customer_id", "CUST", 0)
        conn.execute("INSERT INTO customers (customer_id, customer_type, first_name, last_name, phone, email, "
                     "street_address, city, state, zip, status, created_by, last_edited_by, last_edited_at) "
                     "VALUES (?, 'Residential', ?, ?, ?, ?, ?, ?, ?, ?, 'Active', ?, ?, ?)",
                     (cid, first or None, last.strip() or None, phone or None, (email or "").strip().lower() or None,
                      street or None, city or None, state or None, zip_code or None, by, by, now))
        return cid, True


def create_request_job(db_path: str, *, customer_id: str, customer_name: str, service: str,
                       service_code: str = "", notes: str = "", preferred: str = "", street: str = "",
                       city: str = "", state: str = "", zip_code: str = "", path: str = "new",
                       by: str = WEB_BOOKING) -> str:
    """A 'Requested' job with NO date (routing, the Calendar and mileage never see it) for the
    office to quote and schedule, plus its booking_requests record. Returns the job id."""
    import json
    from db_write_ops import generate_next_id
    details = "\n".join(x for x in (notes.strip(), f"Preferred: {preferred.strip()}" if preferred.strip() else "",
                                    "From the website request page.") if x)
    with transaction(db_path) as conn:
        jid = generate_next_id(conn, "jobs", "job_id", "JOB", 4)
        now = utcnow_iso()
        conn.execute("INSERT INTO jobs (job_id, customer_id, customer_name, customer_type, street_address, city, "
                     "state, zip, service_type, service_details, job_status, schedule_type, preferred_days, "
                     "created_by, last_edited_by, last_edited_at) "
                     "VALUES (?, ?, ?, 'Residential', ?, ?, ?, ?, ?, ?, 'Requested', 'Soft', ?, ?, ?, ?)",
                     (jid, customer_id, customer_name or None, street or None, city or None, state or None,
                      zip_code or None, service or None, details, _preferred_days(preferred), by, by, now))
        conn.execute("INSERT INTO booking_requests (job_id, path, service_code, choices_json, status, created_at) "
                     "VALUES (?, ?, ?, ?, 'requested', ?)",
                     (jid, path, service_code or None, json.dumps({"preferred": preferred.strip()}), now))
    return jid


def _preferred_days(text: str) -> str | None:
    """The weekdays named in the customer's 'preferred' text, in the Jobs app's notation
    (e.g. 'Tuesday or Thursday mornings' -> 'Tue,Thu'); None when it names none."""
    import re
    from db_write_ops import _DAY_ALIASES, format_working_days
    days = {_DAY_ALIASES[w] for w in re.findall(r"[a-z]+", (text or "").lower()) if w in _DAY_ALIASES}
    return format_working_days(days) if days else None


def link_request_ticket(db_path: str, job_id: str, ticket_id: str) -> None:
    conn = get_connection(db_path)
    try:
        conn.execute("UPDATE booking_requests SET ticket_id = ? WHERE job_id = ?", (ticket_id, job_id))
    finally:
        conn.close()


def recent_job(db_path: str, *, phone: str = "", email: str = "", days: int = 45,
               today: dt.date | None = None) -> dict | None:
    """The matched customer's most recent job dated within the last `days` (for 'Report a
    problem': the ticket is linked to it). None when there's no clear match."""
    today = today or dt.date.today()
    conn = get_connection(db_path)
    try:
        c = find_customer(conn, phone, email)
        if not c:
            return None
        r = conn.execute("SELECT job_id, service_date, service_type FROM jobs WHERE customer_id = ? "
                         "AND COALESCE(service_date, '') BETWEEN ? AND ? "
                         "AND LOWER(COALESCE(job_status, '')) NOT IN ('cancelled', 'canceled', 'declined') "
                         "ORDER BY service_date DESC LIMIT 1",
                         (c["customer_id"], (today - dt.timedelta(days=days)).isoformat(),
                          today.isoformat())).fetchone()
        return (dict(r) | {"customer_id": c["customer_id"]}) if r else None
    finally:
        conn.close()


# ── "Buy a product" (2026-11-02) ─────────────────────────────────────────────
# David: "Allow a product to be purchased ... add the Online Payment Link for each product
# ... shipping and handling needs to be added in." An order is a 'Requested' job (no date —
# routing, the Calendar and mileage never see it) for the office to ship, an Unpaid invoice
# for the full amount, and a booking_requests row (path 'buy', status 'ordered') holding the
# totals the customer saw. Payment is by the Stripe / Square checkout link made from the
# invoice amount (Small Business → Online Payment Links).

MAX_ORDER_QTY = 20
ORDER_BY = "web order"


def order_quote(db_path: str, code: str, qty) -> dict:
    """The price of `qty` of one product sold online: items + shipping & handling (per item)
    + sales tax (Jobs app Settings → tax rate, on the items and the shipping — the same math
    every invoice uses). Raises BookingError for anything that can't be bought."""
    try:
        qty = int(qty)
    except (TypeError, ValueError):
        raise BookingError("enter how many you'd like") from None
    if not 1 <= qty <= MAX_ORDER_QTY:
        raise BookingError(f"you can order 1 to {MAX_ORDER_QTY} at a time — call us for more")
    p = next((x for x in list_services(db_path, online_only=True) if x["code"] == code), None)
    if not p or p["mode"] != "request":
        raise BookingError("that product isn't sold online")
    if p["unit_price"] <= 0:
        raise BookingError(f"{p['name']} has no price yet — ask for it with \"Request a new service\"")
    try:
        from db_write_ops import db_read_settings_tax_rate
        rate = float(db_read_settings_tax_rate(db_path) or 0)
    except Exception:  # noqa: BLE001
        rate = 0.0
    items = round(p["unit_price"] * qty, 2)
    shipping = round(p["shipping"] * qty, 2)
    subtotal = round(items + shipping, 2)
    tax = round(subtotal * rate, 2)
    return {"code": code, "name": p["name"], "qty": qty, "unit_price": p["unit_price"],
            "shipping_each": p["shipping"], "items": items, "shipping": shipping, "subtotal": subtotal,
            "tax_rate": rate, "tax": tax, "total": round(subtotal + tax, 2)}


def order_text(q: dict) -> str:
    """One line for the ticket, the job and the checkout page."""
    return f"{q['name']} × {q['qty']}" + (" + shipping & handling" if q["shipping"] else "")


def create_order(db_path: str, *, customer_id: str, customer_name: str, code: str, qty, street: str = "",
                 city: str = "", state: str = "", zip_code: str = "", notes: str = "", by: str = ORDER_BY) -> dict:
    """Records an order (see the section note). Returns the quote + job_id + invoice_id."""
    import json
    from db_write_ops import generate_next_id
    q = order_quote(db_path, code, qty)
    ship_to = address_line({"street": street, "city": city, "state": state, "zip": zip_code})
    lines = [f"Online order: {q['name']} × {q['qty']} at ${q['unit_price']:,.2f}",
             f"Shipping & handling: ${q['shipping']:,.2f}" if q["shipping"] else "",
             f"Sales tax: ${q['tax']:,.2f}" if q["tax"] else "",
             f"Total: ${q['total']:,.2f}", f"Ship to: {ship_to}", notes.strip(),
             "From the website order page."]
    details = "\n".join(x for x in lines if x)
    today = dt.date.today().isoformat()
    with transaction(db_path) as conn:
        jid = generate_next_id(conn, "jobs", "job_id", "JOB", 4)
        inv = generate_next_id(conn, "invoices", "invoice_id", "INV", 4)
        now = utcnow_iso()
        conn.execute("INSERT INTO jobs (job_id, customer_id, customer_name, customer_type, street_address, city, "
                     "state, zip, service_type, service_details, job_status, schedule_type, quote_amount, "
                     "payment_status, created_by, last_edited_by, last_edited_at) "
                     "VALUES (?, ?, ?, 'Residential', ?, ?, ?, ?, ?, ?, 'Requested', 'Soft', ?, 'Unpaid', ?, ?, ?)",
                     (jid, customer_id, customer_name or None, street or None, city or None, state or None,
                      zip_code or None, f"Order: {q['name']}", details, q["subtotal"], by, by, now))
        conn.execute("INSERT INTO invoices (invoice_id, job_id, customer_id, customer_name, customer_type, "
                     "invoice_date, due_date, service_type, description, subtotal, discount, taxable_amt, tax, "
                     "total_due, amount_paid, payment_status, days_overdue, created_by, last_edited_by, last_edited_at) "
                     "VALUES (?, ?, ?, ?, 'Residential', ?, ?, ?, ?, ?, 0, ?, ?, ?, 0, 'Unpaid', 0, ?, ?, ?)",
                     (inv, jid, customer_id, customer_name or None, today, today, f"Order: {q['name']}",
                      order_text(q), q["subtotal"], q["subtotal"], q["tax"], q["total"], by, by, now))
        # job first, then its invoice, then link them (each points at the other)
        conn.execute("UPDATE jobs SET invoice_id = ? WHERE job_id = ?", (inv, jid))
        conn.execute("INSERT INTO booking_requests (job_id, path, service_code, choices_json, status, created_at) "
                     "VALUES (?, 'buy', ?, ?, 'ordered', ?)",
                     (jid, code, json.dumps({**q, "invoice_id": inv, "ship_to": ship_to}), now))
    return {**q, "job_id": jid, "invoice_id": inv, "ship_to": ship_to}


def order_view(db_path: str, job_id: str) -> dict | None:
    """The order behind a job as the customer's status page shows it, or None. 'paid' follows the
    invoice (marked paid in the Jobs app, or by your payment tools)."""
    import json
    conn = get_connection(db_path)
    try:
        r = conn.execute("SELECT * FROM booking_requests WHERE job_id = ? AND path = 'buy'", (job_id,)).fetchone()
        if not r:
            return None
        o = json.loads(r["choices_json"] or "{}")
        inv = conn.execute("SELECT payment_status, amount_paid, total_due FROM invoices WHERE invoice_id = ?",
                           (o.get("invoice_id") or "",)).fetchone()
        job = conn.execute("SELECT job_status FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    finally:
        conn.close()
    status = str(inv["payment_status"] or "") if inv else ""
    paid = status.lower() == "paid" or bool(inv and inv["total_due"] and (inv["amount_paid"] or 0) >= inv["total_due"])
    gone = bool(job and str(job["job_status"] or "").lower() in _GONE)
    keep = ("name", "qty", "unit_price", "items", "shipping", "tax", "total", "invoice_id", "ship_to")
    # what's still owed: the invoice as it stands now (the office may have adjusted it)
    due = round(float(inv["total_due"] or 0) - float(inv["amount_paid"] or 0), 2) if inv else 0.0
    return {**{k: o.get(k) for k in keep}, "due": due, "paid": paid, "cancelled": gone,
            "can_pay": not paid and not gone and due > 0}


def to_json(windows: list) -> list:
    """Windows as the page shows them — date and window only, never the crew."""
    return [{"key": w.key, "date": w.date.isoformat(), "start": bs.fmt(w.start), "end": bs.fmt(w.end),
             "label": w.label()} for w in windows]


__all__ = ["BookingError", "rules_for", "sync_services", "list_services", "update_service", "service",
           "booked_for", "add_opening", "delete_opening", "openings_for", "windows_for", "hold_window",
           "extend_hold", "release_hold", "get_hold", "expire_holds", "replace_busy", "last_busy_sync",
           "to_json"]
