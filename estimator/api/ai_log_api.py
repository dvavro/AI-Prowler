"""The AI Log's JSON calls (the Agents screen's AI Log page, #/agents/ai-log).

  GET  /ai-log?limit=&offset=&auto_run_id=&task_id=&role=&estimate_id=
                                         entries, newest first, paginated (ai_log.list_entries)
  GET  /ai-log/<id>                      one entry in full: prompt, images, raw reply, parsed result
  GET  /ai-log/<id>/image/<n>            one image the AI was sent, as the picture itself

Who: the owner and estimators - the Agents screen's roles (estimator/api/nav.py).
The image files are served like a sheet's image: the file must be a picture
inside the Estimator's data folder, and the browser never sees its path.
"""
from __future__ import annotations

import re

from estimator.api import nav

_ONE = re.compile(r"^/ai-log/(\d+)$")
_IMAGE = re.compile(r"^/ai-log/(\d+)/image/(\d+)$")


def handles(sub: str) -> bool:
    return sub == "/ai-log" or sub.startswith("/ai-log/")


def _refuse(message: str, status: int = 400, error: str = "invalid_input"):
    from estimator.api.router import _Refuse
    return _Refuse(status, error, message)


def _page_int(value, default: int, maximum: int) -> int:
    if value in (None, ""):
        return default
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise _refuse("that should be a whole number") from None
    if n < 0:
        raise _refuse("that should be a positive number")
    return min(n, maximum)


def route(m: str, sub: str, req, ctx, conn):
    from estimator.agents import ai_log
    from estimator.api.router import Response, SECURITY_HEADERS, _fail, _int_opt, _ok

    if not nav.can_open(ctx.role, "agents"):
        raise _refuse("your role can't open the AI Log", 403, "permission_denied")

    if sub == "/ai-log" and m == "GET":
        return _ok(**ai_log.list_entries(
            conn, ctx, auto_run_id=_int_opt(req.query.get("auto_run_id")),
            task_id=_int_opt(req.query.get("task_id")),
            role=(req.query.get("role") or "").strip() or None,
            estimate_id=_int_opt(req.query.get("estimate_id")),
            limit=_page_int(req.query.get("limit"), 50, 200),
            offset=_page_int(req.query.get("offset"), 0, 1_000_000)))

    mm = _ONE.match(sub)
    if mm and m == "GET":
        return _ok(**ai_log.get_entry(conn, ctx, int(mm.group(1))))

    mm = _IMAGE.match(sub)
    if mm and m == "GET":
        path = ai_log.image_file(conn, ctx, int(mm.group(1)), int(mm.group(2)))
        ctype = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
        return Response(200, ctype, path.read_bytes(),
                        {"Cache-Control": "private, max-age=300", **SECURITY_HEADERS})

    return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
