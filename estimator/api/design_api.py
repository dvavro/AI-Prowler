"""AI design's JSON calls (Measure screen, 2026-11-21, David: "type in a command like here's my shed drawings, I want to
add electricity to it, design me the lighting and receptacles").

  GET  /design/<estimate id>                       the trades, the plan sets a design can go on, whether the AI is on,
                                                   and each trade's design (estimator/design/runs.py)
  POST /design/<estimate id>/<trade>               start: {"request", "specs", "plan_set_id", "images"} - in the background
  POST /design/<estimate id>/<trade>/change        a change in plain words: {"text", "images"}
                                                   images: up to 3 screenshots as data: URLs (2026-11-23)
  GET  /design/<estimate id>/<trade>/reference     the numbered reference picture (PNG): 5 ft grid, devices numbered
  POST /design/<estimate id>/<trade>/approve       {"confirm": true} - becomes plan sets (asks first)
  POST /design/<estimate id>/<trade>/discard
  GET  /design/<estimate id>/<trade>/(plan|panel)  the drawing (DXF download); .../svg the same as a picture

Who: anyone who can open the Measure screen sees it; owners and estimators design.
"""
from __future__ import annotations

import re

from estimator.api import nav

_ONE = re.compile(r"^/design/(\d+)$")
_TRADE = re.compile(r"^/design/(\d+)/([a-z_]+)(?:/(change|approve|discard))?$")
_DRAW = re.compile(r"^/design/(\d+)/([a-z_]+)/(plan|panel)(/svg)?$")
_REF = re.compile(r"^/design/(\d+)/([a-z_]+)/reference$")


def handles(sub: str) -> bool:
    return sub.startswith("/design/")


def route(m: str, sub: str, req, ctx, conn):
    from estimator.api.router import SECURITY_HEADERS, Response, _Refuse, _ask_first, _body, _fail, _ok, _open_db
    from estimator.design import runs
    from estimator.estimating import service

    if not nav.can_open(ctx.role, "takeoffs"):
        raise _Refuse(403, "permission_denied", "your role can't open the Measure screen")
    open_conn = None if runs.RUN_INLINE else _open_db

    mm = _ONE.match(sub)
    if mm and m == "GET":
        est = service.get_estimate(conn, ctx, int(mm.group(1)))
        return _ok(**runs.options(conn, ctx, est["id"]),
                   designs={t: runs.get(conn, ctx, est["id"], t) for t, v in runs.TRADES.items() if v["ready"]})

    # 2026-11-23: the numbered reference picture (5 ft grid, every device numbered) - what the AI sees with screenshots
    mm = _REF.match(sub)
    if mm and m == "GET":
        from estimator.design import reference
        est = service.get_estimate(conn, ctx, int(mm.group(1)))
        st = runs.load(est["id"], mm.group(2))
        if not st or not st.get("building") or not st.get("design"):
            return _fail(404, "not_found", "there's no AI design to show yet")
        name = f"AI design - {mm.group(2)} numbered plan (estimate {est['id']}).png"
        return Response(200, "image/png", reference.render(st["building"], st["design"]),
                        {"Cache-Control": "no-store", **SECURITY_HEADERS,
                         "Content-Disposition": f'inline; filename="{name}"'})

    mm = _DRAW.match(sub)
    if mm and m == "GET":
        est = service.get_estimate(conn, ctx, int(mm.group(1)))
        path = runs.drawing(est["id"], mm.group(2), mm.group(3))
        if mm.group(4):
            from estimator.takeoff import wiring_svg
            return Response(200, "image/svg+xml", wiring_svg.get(path).encode("utf-8"),
                            {"Cache-Control": "no-store", **SECURITY_HEADERS})
        name = f"AI design - {mm.group(2)} {'panel schedule' if mm.group(3) == 'panel' else 'plan'} (estimate {est['id']}).dxf"
        return Response(200, "application/dxf", path.read_bytes(),
                        {"Cache-Control": "no-store", **SECURITY_HEADERS,
                         "Content-Disposition": f'attachment; filename="{name}"'})

    mm = _TRADE.match(sub)
    if mm:
        eid, trade, action = int(mm.group(1)), mm.group(2), mm.group(3)
        if m == "GET" and not action:
            return _ok(design=runs.get(conn, ctx, eid, trade))
        if m == "POST":
            b = _body(req)
            if not action:
                return _ok(design=runs.start(conn, ctx, eid, trade, str(b.get("request") or ""),
                                             int(b.get("plan_set_id") or 0), str(b.get("specs") or ""),
                                             open_conn=open_conn, images=b.get("images") or None))
            if action == "change":
                return _ok(design=runs.change(conn, ctx, eid, trade, str(b.get("text") or ""), open_conn=open_conn,
                                              images=b.get("images") or None))
            if action == "approve":
                return _ask_first(lambda: runs.approve(conn, ctx, eid, trade, confirm=b.get("confirm") is True,
                                                       open_conn=open_conn))
            if action == "discard":
                return _ok(design=runs.discard(conn, ctx, eid, trade))

    return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
