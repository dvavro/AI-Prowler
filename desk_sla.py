"""
desk_sla.py — AI-Prowler Service Desk, Phase 3: SLA clocks.

Business-hours arithmetic (working days from the Jobs app's Working Days
setting, hours from Service Desk settings), the default targets per
priority, On Hold pausing, and the warning / breach / escalation checks the
scheduler runs.

Default targets (spec, editable in settings "sla_targets", minutes of
BUSINESS time; resolve None = best effort):
    P1  respond 60      resolve: end of the same business day
    P2  respond 240     resolve 2 business days
    P3  respond 1 day   resolve 5 business days
    P4  respond 3 days  resolve none

Solo has no SLA escalation (feature "sla_escalation" is Business only) —
only the due date the owner set and the morning digest.
"""
from __future__ import annotations

import datetime

import desk_rules as rules

UTC = datetime.timezone.utc
DAY = "day"                           # marker: "a business day" for the default table

DEFAULT_HOURS = (8, 17)               # 8:00-17:00 local
DEFAULT_WORKING_DAYS = (0, 1, 2, 3, 4)  # Mon-Fri (datetime.weekday())
WARN_AT = 0.75                        # warn at 75% of the target
ESCALATE_AT = 2.0                     # escalate to managers at 2x the target

DEFAULT_TARGETS = {                   # priority -> (respond, resolve) in business minutes
    "P1": (60, "eod"),
    "P2": (240, 2 * 9 * 60),
    "P3": (9 * 60, 5 * 9 * 60),
    "P4": (3 * 9 * 60, None),
}


# Set by ai_prowler_mcp.py from the Jobs app's Working Days setting:
# fn() -> iterable of weekday numbers (Mon=0). Default Mon-Fri.
working_days_fn = None
_DAY_NAMES = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def working_days() -> tuple:
    if working_days_fn:
        try:
            raw = working_days_fn()
            days = tuple(sorted({_DAY_NAMES.get(str(d).strip().lower()[:3], d) for d in raw
                                 if str(d).strip()}))
            days = tuple(d for d in days if isinstance(d, int) and 0 <= d <= 6)
            if days:
                return days
        except Exception:  # noqa: BLE001
            pass
    return DEFAULT_WORKING_DAYS


def _local(dt: datetime.datetime) -> datetime.datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone()


def parse(iso: str | None) -> datetime.datetime | None:
    if not iso:
        return None
    dt = datetime.datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def to_iso(dt: datetime.datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def _is_workday(d: datetime.date, days) -> bool:
    return d.weekday() in days


def add_business_minutes(start: datetime.datetime, minutes: int, *, hours=DEFAULT_HOURS,
                         days=DEFAULT_WORKING_DAYS, tz=None) -> datetime.datetime:
    """start + `minutes` of business time. `tz` (tests) overrides the local zone."""
    cur = start.astimezone(tz) if tz else _local(start)
    open_h, close_h = hours
    left = int(minutes)
    while True:
        day_open = cur.replace(hour=open_h, minute=0, second=0, microsecond=0)
        day_close = cur.replace(hour=close_h, minute=0, second=0, microsecond=0)
        if not _is_workday(cur.date(), days) or cur >= day_close:
            cur = (cur + datetime.timedelta(days=1)).replace(hour=open_h, minute=0, second=0,
                                                             microsecond=0)
            continue
        if cur < day_open:
            cur = day_open
        avail = int((day_close - cur).total_seconds() // 60)
        if left <= avail:
            return cur + datetime.timedelta(minutes=left)
        left -= avail
        cur = (cur + datetime.timedelta(days=1)).replace(hour=open_h, minute=0, second=0,
                                                         microsecond=0)


def end_of_business_day(start: datetime.datetime, *, hours=DEFAULT_HOURS,
                        days=DEFAULT_WORKING_DAYS, tz=None) -> datetime.datetime:
    """Close of the business day `start` falls in (or the next one if after hours)."""
    cur = start.astimezone(tz) if tz else _local(start)
    while True:
        close = cur.replace(hour=hours[1], minute=0, second=0, microsecond=0)
        if _is_workday(cur.date(), days) and cur < close:
            return close
        cur = (cur + datetime.timedelta(days=1)).replace(hour=hours[0], minute=0, second=0,
                                                         microsecond=0)


def targets(settings: dict | None = None) -> dict:
    custom = (settings or {}).get("sla_targets") or {}
    out = dict(DEFAULT_TARGETS)
    for p, v in custom.items():
        if p in out and isinstance(v, (list, tuple)) and len(v) == 2:
            out[p] = tuple(v)
    return out


def due_times(priority: str, created: datetime.datetime, *, settings: dict | None = None,
              days=DEFAULT_WORKING_DAYS, tz=None) -> tuple[str | None, str | None]:
    """(due_response_at, due_resolve_at) as UTC ISO strings for a new ticket."""
    hours = tuple((settings or {}).get("business_hours") or DEFAULT_HOURS)
    respond, resolve = targets(settings).get(priority, DEFAULT_TARGETS["P3"])
    r = to_iso(add_business_minutes(created, respond, hours=hours, days=days, tz=tz)) if respond else None
    if resolve == "eod":
        v = to_iso(end_of_business_day(created, hours=hours, days=days, tz=tz))
    elif resolve:
        v = to_iso(add_business_minutes(created, resolve, hours=hours, days=days, tz=tz))
    else:
        v = None
    return r, v


def shift(iso: str | None, delta: datetime.timedelta) -> str | None:
    """Move a due time later by the time a ticket spent On Hold."""
    dt = parse(iso)
    return to_iso(dt + delta) if dt else None


def status(ticket: dict, now: datetime.datetime) -> dict:
    """Where a ticket stands against its clocks: {"response": ok|warn|breach|met,
    "resolve": ..., "escalate": bool}. On Hold, Fixed and Closed tickets are not
    running."""
    out = {"response": "met" if ticket.get("first_response_at") else "ok", "resolve": "ok",
           "escalate": False}
    if ticket["state"] in (rules.ON_HOLD, rules.FIXED, rules.CLOSED):
        out["resolve"] = "paused" if ticket["state"] == rules.ON_HOLD else "met"
        return out
    created = parse(ticket["created_at"])

    def judge(due_iso):
        due = parse(due_iso)
        if not due:
            return "ok", False
        total = max((due - created).total_seconds(), 60)
        used = (now - created).total_seconds()
        if now >= due:
            return "breach", used >= ESCALATE_AT * total
        return ("warn" if used >= WARN_AT * total else "ok"), False

    if not ticket.get("first_response_at") and ticket.get("kind") == rules.EXTERNAL:
        out["response"], esc1 = judge(ticket.get("due_response_at"))
    else:
        esc1 = False
    out["resolve"], esc2 = judge(ticket.get("due_resolve_at"))
    out["escalate"] = esc1 or esc2
    return out
