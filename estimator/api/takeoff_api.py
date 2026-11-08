"""Blueprint Review (the Takeoffs screen) - Coder 2 Sprint 7.

The JSON calls behind the review page, all through Jamie's measurement service (estimator/takeoff/measurements.py),
the same rules as the takeoff_* MCP tools: only approved measurements are priced, approved ones are locked, agents
never approve, and every change asks first and is logged.

  GET  /takeoffs                            projects with plans or measurements, and their measurement counts
  GET  /estimates/<id>/takeoff              the review page: sheets, the trades and the questions a measurement can
                                            feed, every measurement (takeoff_list) with its shape, and what I may do
  POST /estimates/<id>/measurements {module_id, feeds?, kind?, label?, room?, viewport_id + geometry | qty + unit,
                                    approve?, confirm?}                         takeoff_manual (asks first)
  POST /estimates/<id>/measurements/propose {module_id, object_ids, feeds?, kind?, label?, room?, one_per_object?,
                                    approve?, confirm?}                         takeoff_propose (+ takeoff_confirm)
  GET  /measurements/<id>                   takeoff_detail
  POST /measurements/approve {measurement_ids | estimate_id + above_confidence (+ module_id), accept_suggestion?,
                                    confirm?}                                   takeoff_confirm (asks first)
  POST /measurements/<id>/edit {qty?, label?, room?, feeds?, confirm?}         takeoff_edit (asks first)
  POST /measurements/<id>/reject {reason?, confirm?}                           takeoff_delete (asks first)
  POST /measurements/<id>/suggest {qty, reason, confirm?}                       takeoff_suggest_change (asks first)

Who: the Takeoffs screen's roles (owner, estimator, reviewer). Owner and estimator measure; owner, estimator and
reviewer approve, correct and reject (the service checks each call again).
"""
from __future__ import annotations

import json
import re

from estimator.api import nav

_TAKEOFF = re.compile(r"^/estimates/(\d+)/takeoff$")
_ADD = re.compile(r"^/estimates/(\d+)/measurements$")
_PROPOSE = re.compile(r"^/estimates/(\d+)/measurements/propose$")
_ONE = re.compile(r"^/measurements/(\d+)$")
_ACT = re.compile(r"^/measurements/(\d+)/(edit|reject|suggest)$")
MAX_TEXT = 200
MAX_IDS = 5000


def handles(sub: str) -> bool:
    return (sub == "/takeoffs" or sub.startswith("/measurements/") or bool(_TAKEOFF.match(sub))
            or bool(_ADD.match(sub)) or bool(_PROPOSE.match(sub)))


def _text(b: dict, key: str) -> str | None:
    v = b.get(key)
    if v is None:
        return None
    if not isinstance(v, (str, int, float)) or isinstance(v, bool):
        raise _refuse(f"{key} must be text")
    v = str(v).strip()
    if len(v) > MAX_TEXT:
        raise _refuse(f"{key} is too long ({MAX_TEXT} characters at most)")
    return v


def _refuse(message: str, status: int = 400, error: str = "invalid_input"):
    from estimator.api.router import _Refuse
    return _Refuse(status, error, message)


def _ids(value, field: str) -> list[int]:
    if not isinstance(value, list) or not value:
        raise _refuse(f"{field} must be a list of ids")
    if len(value) > MAX_IDS:
        raise _refuse(f"at most {MAX_IDS} at a time")
    out = []
    for v in value:
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise _refuse(f"{field} must be a list of ids")
        out.append(v)
    return out


def _ask(fn, extra: str = ""):
    """Like router._ask_first, with a sentence added to the question (e.g. 'They'll be approved and locked.')."""
    from estimator.api.router import _ok, _question
    from estimator.errors import ConfirmationRequired
    try:
        return _ok(**fn())
    except ConfirmationRequired as e:
        q = _question(e.message)
        if extra:
            q = q.rstrip("?") + "? " + extra if q.endswith("?") else q + " " + extra
        return _ok(needs_confirmation=True, question=q, **e.details)


def _trade(mod) -> dict:
    return {"module_id": mod.id, "name": mod.name,
            "questions": [{"id": q.id, "label": q.label, "unit": q.unit, "type": q.type}
                          for q in mod.questions if q.type in ("number", "integer")]}


def route(m: str, sub: str, req, ctx, conn):
    from estimator.api.router import _body, _fail, _int_opt, _ok
    from estimator.drawing_model import store
    from estimator.estimating import service
    from estimator.takeoff import measurements as ms

    if not nav.can_open(ctx.role, "takeoffs"):
        raise _refuse("your role can't open takeoffs", 403, "permission_denied")
    can_measure = ctx.role in ms.PROPOSE_ROLES
    can_approve = ctx.role in ms.APPROVE_ROLES and not ctx.agent
    can_correct = ctx.role in ms.PROPOSE_ROLES + ("reviewer",)

    if sub == "/takeoffs" and m == "GET":
        counts: dict[int, dict] = {}
        for eid, status, n in conn.execute("SELECT estimate_id, status, COUNT(*) FROM measurements WHERE company_id = ?"
                                           " GROUP BY estimate_id, status", (ctx.company_id,)):
            counts.setdefault(eid, {"proposed": 0, "approved": 0, "rejected": 0})[status] = n
        out = []
        for e in service.list_estimates(conn, ctx, limit=200)["estimates"]:
            sets = store.list_plan_sets(conn, ctx, e["id"])["plan_sets"]
            c = counts.get(e["id"], {"proposed": 0, "approved": 0, "rejected": 0})
            if not sets and not any(c.values()):
                continue
            out.append({"estimate_id": e["id"], "title": e["title"], "status": e["status"],
                        "plan_sets": len(sets), "read": sum(1 for s in sets if s["status"] == "processed"),
                        "measurements": c, "to_review": c["proposed"]})
        return _ok(projects=out, count=len(out), can_measure=can_measure, can_approve=can_approve)

    mm = _TAKEOFF.match(sub)
    if mm and m == "GET":
        from estimator.modules import get_registry
        eid = int(mm.group(1))
        est = service.get_estimate(conn, ctx, eid)
        reg = get_registry()
        sheets = []
        sets = store.list_plan_sets(conn, ctx, eid)["plan_sets"]
        for ps in sets:
            if ps["status"] != "processed":
                continue
            for s in store.sheets(conn, ctx, ps["id"])["sheets"]:
                sheets.append({**s, "plan_set_id": ps["id"], "file": ps.get("original_name")})
        mine, trades = set(), []
        for sec in est["sections"]:
            if sec["module_id"] in mine:
                continue
            try:
                mod = reg.get(sec["module_id"])
            except Exception:  # noqa: BLE001 - a module that was removed
                continue
            mine.add(mod.id)
            t = _trade(mod)
            if t["questions"]:
                trades.append(t)
        others = sorted((t for t in (_trade(x) for x in reg.list() if x.id not in mine) if t["questions"]),
                        key=lambda t: t["name"].lower())
        listing = ms.list_measurements(conn, ctx, eid)
        shapes = {r[0]: json.loads(r[1]) for r in conn.execute(
            "SELECT id, geometry_json FROM measurements WHERE company_id = ? AND estimate_id = ?"
            " AND geometry_json IS NOT NULL", (ctx.company_id, eid))}
        for x in listing["measurements"]:
            x["geometry"] = shapes.get(x["id"])
        return _ok(estimate={"id": est["id"], "title": est["title"], "status": est["status"]},
                   plan_sets=[{"id": p["id"], "file": p.get("original_name"), "status": p["status"]} for p in sets],
                   sheets=sheets, trades=trades, other_trades=others, takeoff=listing,
                   can_measure=can_measure, can_approve=can_approve, can_correct=can_correct)

    mm = _ADD.match(sub)
    if mm and m == "POST":
        b = _body(req)
        geometry = b.get("geometry")
        if geometry is not None and not isinstance(geometry, dict):
            raise _refuse('geometry must be {"type": "polygon", "points": [[x, y], ...]}')
        module_id = _text(b, "module_id")
        if not module_id:
            raise _refuse("say which trade the measurement is for (module_id)")
        return _ask(lambda: ms.manual(
            conn, ctx, int(mm.group(1)), module_id, feeds=_text(b, "feeds") or None, qty=_text(b, "qty") or None,
            unit=_text(b, "unit") or None, kind=_text(b, "kind") or None, label=_text(b, "label") or None,
            room=_text(b, "room") or None, viewport_id=_int_opt(b.get("viewport_id")), geometry=geometry,
            approve=b.get("approve") is True, confirm=b.get("confirm") is True))

    mm = _PROPOSE.match(sub)
    if mm and m == "POST":
        b = _body(req)
        module_id = _text(b, "module_id")
        if not module_id:
            raise _refuse("say which trade the measurement is for (module_id)")
        ids = _ids(b.get("object_ids"), "object_ids")
        approve = b.get("approve") is True
        if approve:
            ms._person(ctx, "approve measurements")          # before anything is saved

        def go():
            out = ms.propose(conn, ctx, int(mm.group(1)), module_id, ids, feeds=_text(b, "feeds") or None,
                             kind=_text(b, "kind") or None, label=_text(b, "label") or None,
                             room=_text(b, "room") or None, one_per_object=b.get("one_per_object") is True,
                             confirm=b.get("confirm") is True)
            if approve:
                done = ms.confirm_measurements(conn, ctx, [p["id"] for p in out["proposed"]], confirm=True)
                out["approved"] = done["done"]
            return out
        return _ask(go, "They'll be approved and locked." if approve else "")

    if sub == "/measurements/approve" and m == "POST":
        b = _body(req)
        raw = b.get("measurement_ids")
        ids = _ids(raw, "measurement_ids") if raw not in (None, []) else None
        above = b.get("above_confidence")
        if above is not None and (isinstance(above, bool) or not isinstance(above, (int, float, str))):
            raise _refuse("above_confidence must be a number from 0 to 1")
        return _ask(lambda: ms.confirm_measurements(
            conn, ctx, ids, estimate_id=_int_opt(b.get("estimate_id")), module_id=_text(b, "module_id") or None,
            above_confidence=None if above in (None, "") else str(above),
            accept_suggestion=b.get("accept_suggestion") is True, confirm=b.get("confirm") is True))

    mm = _ONE.match(sub)
    if mm and m == "GET":
        return _ok(**{k: v for k, v in ms.detail(conn, ctx, int(mm.group(1))).items() if k != "ok"})

    mm = _ACT.match(sub)
    if mm and m == "POST":
        b, mid, act = _body(req), int(mm.group(1)), mm.group(2)
        confirm = b.get("confirm") is True
        if act == "edit":
            return _ask(lambda: ms.edit(conn, ctx, mid, qty=_text(b, "qty") or None, label=_text(b, "label"),
                                        room=_text(b, "room"), feeds=_text(b, "feeds") or None, confirm=confirm))
        if act == "reject":
            return _ask(lambda: ms.reject(conn, ctx, mid, _text(b, "reason") or "", confirm))
        return _ask(lambda: ms.suggest_change(conn, ctx, mid, _text(b, "qty") or "", _text(b, "reason") or "",
                                              confirm))

    return _fail(404, "not_found", f"no such Estimator API call: {m} {sub}")
