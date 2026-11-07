"""Director settings, per company. Defaults apply until the owner changes them."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from estimator.context import RequestContext
from estimator.errors import InvalidInput, PermissionDenied
from estimator.estimating import service

DEFAULTS = {
    "quick_send_limit_cents": 10000,     # $100: quotes at or under this can be sent with one tap
    "review_required_over_cents": 50000,  # $500: standard estimates over this need a Reviewer's sign-off
    "calendar_booking_enabled": False,   # Director may book site visits on AI-Prowler's calendar
    "customer_intake_enabled": False,    # customers talking to the Director directly (later release)
    "follow_up_days": 5,
    "review_reminder_days": 2,
    "briefing_enabled": True,
    "briefing_time": "07:00",
    "briefing_channel": "chat",
    "briefing_email": None,              # where an emailed briefing goes
    "watcher_enabled": True,             # the Director checks jobs on its own while AI-Prowler runs
    "watch_interval_minutes": 15,
    "auto_expire_bids": True,            # sent quotes past their valid-until date are marked expired
    "due_soon_days": 2,                  # warn this many days before a job's due date
}
BOOL_KEYS = ("calendar_booking_enabled", "customer_intake_enabled", "briefing_enabled", "watcher_enabled",
             "auto_expire_bids")
CHANNELS = ("chat", "pwa", "email")
SETTINGS_ROLES = ("owner",)
_COLUMNS = tuple(DEFAULTS)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_settings(conn, company_id: str) -> dict:
    row = conn.execute("SELECT * FROM director_settings WHERE company_id = ?", (company_id,)).fetchone()
    out = dict(DEFAULTS)
    if row:
        for k in DEFAULTS:
            out[k] = bool(row[k]) if k in BOOL_KEYS else row[k]
    return out


def _int(value, name, lo, hi):
    if isinstance(value, bool) or isinstance(value, float):
        raise InvalidInput(f"{name} must be a whole number", field=name)
    try:
        v = int(str(value).strip())
    except ValueError:
        raise InvalidInput(f"{name} must be a whole number", field=name) from None
    if not lo <= v <= hi:
        raise InvalidInput(f"{name} must be between {lo} and {hi}", field=name)
    return v


def _bool(value, name):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "yes", "on", "1", "false", "no", "off", "0"):
        return value.strip().lower() in ("true", "yes", "on", "1")
    raise InvalidInput(f"{name} must be true or false", field=name)


def update_settings(conn, ctx: RequestContext, changes: dict) -> dict:
    if ctx.role not in SETTINGS_ROLES:
        raise PermissionDenied("only the owner can change Director settings", role=ctx.role)
    unknown = sorted(set(changes) - set(DEFAULTS))
    if unknown:
        raise InvalidInput(f"unknown settings: {unknown}", valid=sorted(DEFAULTS))
    new = get_settings(conn, ctx.company_id)
    before = dict(new)
    for k, v in changes.items():
        if k in ("quick_send_limit_cents", "review_required_over_cents"):
            new[k] = _int(v, k, 0, 100_000_000)
        elif k == "follow_up_days":
            new[k] = _int(v, k, 1, 60)
        elif k == "review_reminder_days":
            new[k] = _int(v, k, 1, 30)
        elif k == "watch_interval_minutes":
            new[k] = _int(v, k, 5, 240)
        elif k == "due_soon_days":
            new[k] = _int(v, k, 0, 30)
        elif k in BOOL_KEYS:
            new[k] = _bool(v, k)
        elif k == "briefing_time":
            if not isinstance(v, str) or not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", v.strip()):
                raise InvalidInput("briefing_time must be HH:MM (24-hour), e.g. 07:00", field=k)
            new[k] = v.strip()
        elif k == "briefing_channel":
            if v not in CHANNELS:
                raise InvalidInput(f"briefing_channel must be one of {CHANNELS}", field=k)
            new[k] = v
        elif k == "briefing_email":
            if v in (None, ""):
                new[k] = None
            elif not isinstance(v, str) or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v.strip()):
                raise InvalidInput("briefing_email doesn't look like an email address", field=k)
            else:
                new[k] = v.strip()
    if new["briefing_channel"] == "email" and not new["briefing_email"]:
        raise InvalidInput("set briefing_email too, so the emailed briefing has somewhere to go", field="briefing_email")
    values = [int(new[k]) if k in BOOL_KEYS else new[k] for k in _COLUMNS]
    cols = ", ".join(_COLUMNS)
    updates = ", ".join(f"{k} = excluded.{k}" for k in _COLUMNS)
    with service.transaction(conn):
        conn.execute(
            f"INSERT INTO director_settings (company_id, {cols}, updated_by, updated_at)"
            f" VALUES (?, {', '.join('?' for _ in _COLUMNS)}, ?, ?)"
            f" ON CONFLICT (company_id) DO UPDATE SET {updates}, updated_by = excluded.updated_by,"
            " updated_at = excluded.updated_at",
            [ctx.company_id, *values, ctx.actor, _now()])
        service._log(conn, ctx, None, "director_settings_changed",
                     {k: new[k] for k in changes}, {k: before[k] for k in changes})
    return {"ok": True, "settings": new}
