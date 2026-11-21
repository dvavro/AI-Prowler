"""The Wiring run's JSON calls (Measure screen, 2026-11-19, David).

  GET  /wiring/<estimate id>          the last run (routes, cable totals, flags) and which drawings it would use
  POST /wiring/<estimate id>          run it: {"settings": {...}, "overrides": {device: circuit}} - proposes the cable
                                      measurements (estimator/takeoff/wiring_run.py)
  GET  /wiring/<estimate id>/dxf      the wiring drawing (DXF download)
  GET  /wiring/<estimate id>/schematic  the wiring schematic: panel, breakers, every circuit's conductors (DXF)
  GET  /wiring/defaults               the routing options: the company's saved defaults and the built-in ones
  POST /wiring/defaults               save routing options as the company's defaults: {"settings": {...}}

Who: anyone who can open the Measure screen sees it; owners and estimators run it.
"""
from __future__ import annotations

import re

from estimator.api import nav

_ONE = re.compile(r"^/wiring/(\d+)$")
_DXF = re.compile(r"^/wiring/(\d+)/(dxf|schematic)$")


def handles(sub: str) -> bool:
    return sub.startswith("/wiring/")


def route(m: str, sub: str, req, ctx, conn):
    from estimator.api.router import SECURITY_HEADERS, Response, _Refuse, _body, _fail, _ok
    from estimator.errors import PermissionDenied
    from estimator.estimating import service
    from estimator.takeoff import measurements as ms
    from estimator.takeoff import wiring_run

    if not nav.can_open(ctx.role, "takeoffs"):
        raise _Refuse(403, "permission_denied", "your role can't open the Measure screen")

    # 2026-11-21 (David: "I like the user setting defaults for routing wires"): the saved routing defaults.
    if sub == "/wiring/defaults":
        if m == "GET":
            return _ok(**wiring_run.options(ctx))
        if m == "POST":
            b = _body(req)
            wiring_run.save_defaults(ctx, b.get("settings") if isinstance(b.get("settings"), dict) else {})
            return _ok(**wiring_run.options(ctx))                     # "saved": what is saved now

    mm = _ONE.match(sub)
    if mm and m == "GET":
        est = service.get_estimate(conn, ctx, int(mm.group(1)))
        src = wiring_run.sources(conn, ctx, est["id"])
        return _ok(run=wiring_run.latest(ctx, est["id"]),
                   sources={k: {kk: vv for kk, vv in v.items() if kk != "path"} if v else None for k, v in src.items()},
                   can_run=ctx.role in ms.PROPOSE_ROLES,
                   options=wiring_run.options(ctx, est["id"]))           # 2026-11-21: the routing options box
    if mm and m == "POST":
        if ctx.role not in ms.PROPOSE_ROLES:
            raise PermissionDenied(f"only {', '.join(ms.PROPOSE_ROLES)} can run the wiring takeoff", role=ctx.role)
        b = _body(req)
        settings = b.get("settings") if isinstance(b.get("settings"), dict) else {}
        overrides = b.get("overrides") if isinstance(b.get("overrides"), dict) else {}
        keep = b.get("keep_approved", True)
        keep = not (keep is False or str(keep).strip().lower() in ("0", "false", "no", "off"))
        return _ok(run=wiring_run.run(conn, ctx, int(mm.group(1)), settings, overrides, keep_approved=keep))

    mm = _DXF.match(sub)
    if mm and m == "GET":
        est = service.get_estimate(conn, ctx, int(mm.group(1)))
        what = mm.group(2) or "dxf"
        path = wiring_run.schematic_path(est["id"]) if what == "schematic" else wiring_run.dxf_path(est["id"])
        if not path.is_file():
            return _fail(404, "not_found", "run the wiring takeoff first - there's no wiring "
                         + ("schematic" if what == "schematic" else "drawing") + " yet")
        name = wiring_run.download_name(est["id"], "schematic" if what == "schematic" else "wiring")
        return Response(200, "application/dxf", path.read_bytes(),
                        {"Cache-Control": "no-store", **SECURITY_HEADERS,
                         "Content-Disposition": f'attachment; filename="{name}"'})

    return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
