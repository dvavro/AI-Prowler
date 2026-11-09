"""Plan quantities page - Coder 2 Sprint 12.

  GET /estimates/<id>/quantities?height=&proposed=   the shared wall-and-room model of the project's current plan
      sets (plan_get_rooms_walls) and every plan-read trade's answers from it (plan_trade_answers). Read only.
      height: ceiling height in feet for rooms the finish schedule doesn't give (4-40; default 8).
      proposed=1 also counts electrical and plumbing symbols still waiting to be checked.
Owner, estimator and reviewer (the Takeoffs roles); the service checks the company again.
"""
from __future__ import annotations

import re

from estimator.api import nav

_QTY = re.compile(r"^/estimates/(\d+)/quantities$")


def handles(sub: str) -> bool:
    return bool(_QTY.match(sub))


def _refuse(message: str, status: int = 400, error: str = "invalid_input"):
    from estimator.api.router import _Refuse
    return _Refuse(status, error, message)


def route(m: str, sub: str, req, ctx, conn):
    from estimator.api.router import _ok
    if m != "GET":
        raise _refuse(f"use GET for {sub}", 405, "method_not_allowed")
    if not nav.can_open(ctx.role, "takeoffs"):
        raise _refuse("your role can't open plan quantities", 403, "permission_denied")
    estimate_id = int(_QTY.match(sub).group(1))
    q = req.query
    height = (q.get("height") or "").strip()
    if height:
        try:
            height = float(height)
        except ValueError:
            raise _refuse("height must be a number of feet")
    else:
        height = None
    proposed = (q.get("proposed") or "").strip().lower() in ("1", "true", "yes")
    from estimator.building import trades
    got = trades.all_answers(conn, ctx, estimate_id=estimate_id, height_ft=height, include_proposed=proposed)
    row = conn.execute("SELECT title FROM estimates WHERE id = ? AND company_id = ?",          # checked by the model
                       (estimate_id, ctx.company_id)).fetchone()
    return _ok(estimate_id=estimate_id, estimate_title=row["title"] if row else "", model=got["model"],
               trades=got["trades"], include_proposed=proposed)
