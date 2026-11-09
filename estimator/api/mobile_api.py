"""Reviews on a phone or tablet - Coder 2 Sprint 13 (the page is #/m/reviews, in the Jobs app's Estimates tab).

  GET /mobile/reviews?estimate_id=&kind=symbol|measurement&limit=   symbols to check and measurements waiting for
      approval, least sure first, with counts, the projects they're on, what this role may decide, and the standard
      item types for relabelling. Read only.
  GET /mobile/symbols/<id>/view.png        the symbol in place on its sheet, outlined (the highlight)
  GET /mobile/measurements/<id>/view.png   the measurement in place on its sheet, outlined

Decisions use the desktop calls, so the same rules hold (asks first, people only, logged):
  POST /symbol-detections/review (approve, reject, relabel)   POST /measurements/approve   POST /measurements/<id>/reject
Who: the Reviews screen's roles see symbols (field staff look only); the Takeoffs screen's roles see measurements.
"""
from __future__ import annotations

import re

from estimator.api import nav

_VIEW = re.compile(r"^/mobile/(symbols|measurements)/(\d+)/view\.png$")


def handles(sub: str) -> bool:
    return sub == "/mobile/reviews" or bool(_VIEW.match(sub))


def _refuse(message: str, status: int = 400, error: str = "invalid_input"):
    from estimator.api.router import _Refuse
    return _Refuse(status, error, message)


def route(m: str, sub: str, req, ctx, conn):
    from estimator.api.router import _ok
    if m != "GET":
        raise _refuse(f"use GET for {sub}", 405, "method_not_allowed")
    if not (nav.can_open(ctx.role, "reviews") or nav.can_open(ctx.role, "takeoffs")):
        raise _refuse("your role can't review plans", 403, "permission_denied")

    if sub == "/mobile/reviews":
        from estimator.mobile import queue
        q = req.query
        eid = (q.get("estimate_id") or "").strip()
        if eid and not eid.isdigit():
            raise _refuse("estimate_id must be a number")
        limit = (q.get("limit") or "50").strip()
        if not limit.isdigit():
            raise _refuse("limit must be a number")
        got = queue.review_queue(conn, ctx, int(eid) if eid else None, (q.get("kind") or "").strip() or None, int(limit))
        return _ok(**{k: v for k, v in got.items() if k != "ok"})

    mm = _VIEW.match(sub)
    kind = "symbol" if mm.group(1) == "symbols" else "measurement"
    if not nav.can_open(ctx.role, "reviews" if kind == "symbol" else "takeoffs"):
        raise _refuse(f"your role can't look at {mm.group(1)}", 403, "permission_denied")
    from estimator import config
    from estimator.api.router import SECURITY_HEADERS, Response
    from estimator.mobile import view
    try:
        path = view.view_png(conn, ctx, kind, int(mm.group(2)), config.data_dir())
    except (OSError, ValueError) as e:
        raise _refuse(f"no picture of this {kind}: {e}", 404, "not_found") from None
    return Response(200, "image/png", path.read_bytes(), {"Cache-Control": "private, max-age=3600", **SECURITY_HEADERS})
