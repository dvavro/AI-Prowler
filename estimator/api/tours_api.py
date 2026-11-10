"""Guided-tour progress - Coder 2 Sprint 18 (spec: How-to-use guide and guided tour; DB schema help_progress).

  GET  /help/tours/progress                  the tours this user has completed or skipped
  POST /help/tours/progress {tour_id, status}  mark one tour completed, skipped, or not_started (reset)
  GET  /help/practice                       the practice project ("Practice: Garcia house") if it exists

Progress is per user (ctx.user_id): every role reads and writes only its own
rows, and nobody sees another user's. A tour the user has never touched is
simply absent from the progress map, which the web app reads as not_started.
The tour ids here are the same list as TOURS in estimator/ui/web/tour.js -
keep both in step when a tour is added.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

# Every tour the web app can start, in menu order (plus the practice and mobile tours).
TOUR_IDS = (
    "dashboard", "projects", "project", "plans", "plan_set", "sheet", "takeoffs", "takeoff",
    "reviews", "symbol_review", "estimates", "estimate", "quantities", "bids", "bid",
    "price_book", "symbol_library", "agents", "reports", "revision", "settings",
    "jobs", "job", "quick", "help", "practice", "mobile",
)
STATUSES = ("not_started", "completed", "skipped")
_TOUR_ID = re.compile(r"^[a-z0-9_]{1,64}$")


def handles(sub: str) -> bool:
    return sub == "/help/tours/progress" or sub.startswith("/help/tours/") or sub == "/help/practice"


def _refuse(message: str, status: int = 400, error: str = "invalid_input"):
    from estimator.api.router import _Refuse
    return _Refuse(status, error, message)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def route(m: str, sub: str, req, ctx, conn):
    from estimator.api.router import _body, _ok

    if sub == "/help/tours/progress" and m == "GET":
        rows = conn.execute(
            "SELECT tour_id, status FROM help_progress WHERE user_id = ?", (ctx.user_id,)
        ).fetchall()
        return _ok(tours={r["tour_id"]: r["status"] for r in rows})

    if sub == "/help/tours/progress" and m == "POST":
        b = _body(req)
        tour_id = str(b.get("tour_id") or "").strip()
        status = str(b.get("status") or "").strip()
        if not _TOUR_ID.match(tour_id) or tour_id not in TOUR_IDS:
            raise _refuse(f"no such tour: {tour_id or '(missing)'}", 404, "not_found")
        if status not in STATUSES:
            raise _refuse("status must be not_started, completed or skipped")
        conn.execute(
            "INSERT INTO help_progress (user_id, tour_id, status, updated_at) VALUES (?, ?, ?, ?)"
            " ON CONFLICT (user_id, tour_id) DO UPDATE SET status = excluded.status,"
            " updated_at = excluded.updated_at",
            (ctx.user_id, tour_id, status, _now()),
        )
        conn.commit()
        return _ok(tour_id=tour_id, status=status)

    if sub == "/help/practice" and m == "GET":
        row = conn.execute(
            "SELECT id, title FROM estimates WHERE company_id = ? AND is_practice = 1"
            " ORDER BY id LIMIT 1",
            (ctx.company_id,),
        ).fetchone()
        if row is None:
            return _ok(estimate_id=None, title=None)
        return _ok(estimate_id=row["id"], title=row["title"])

    raise _refuse(f"no such Estimator API call: {m} {sub}", 404, "not_found")
