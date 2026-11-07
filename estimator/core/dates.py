"""Dates: timestamps are stored in UTC; people see and compare dates in local time."""
from __future__ import annotations

from datetime import date, datetime


def local_date(ts: str | None) -> date | None:
    """The local calendar date of a stored UTC timestamp (or a plain YYYY-MM-DD date)."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        try:
            return date.fromisoformat(ts[:10])
        except ValueError:
            return None
    if dt.tzinfo is None:
        return dt.date()
    return dt.astimezone().date()


def local_date_text(ts: str | None) -> str:
    d = local_date(ts)
    return d.isoformat() if d else ""
