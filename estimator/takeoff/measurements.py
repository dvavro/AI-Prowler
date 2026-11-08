"""Measurements: the quantities that feed a trade's pricing (spec: Blueprint Review screen, Data model `measurements`).

A measurement is one quantity for one trade question (for example flooring's floor area), with where it came from:
drawing objects on a sheet (proposed by an agent or a person), a shape drawn on a sheet, or a typed number.

States and the lock rule (spec: "Human-approved measurements are locked"):
- proposed: waiting for a person. Anyone who can edit may change or reject it.
- approved: a person approved it; it is locked. Agents can never change it. A changed value (a re-run, a new scale,
  re-read plans, or an agent's suggestion) is stored beside it as a suggested change, and only a person can accept it.
- rejected: kept for history with the reason; never priced.

Only approved measurements are priced. takeoff_list sums them by trade question (converted to the question's unit),
and runner_submit_takeoff(from_measurements=true) hands those sums to the Estimate Runner.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal

from estimator.context import RequestContext
from estimator.core.units.units import UnitError, convert, normalize_unit
from estimator.drawing_model import geometry as geo
from estimator.errors import ConfirmationRequired, InvalidInput, NotEditable, NotFound, PermissionDenied
from estimator.estimating import service

PROPOSE_ROLES = service.EDIT_ROLES               # owner, estimator (and agents acting as estimator)
APPROVE_ROLES = service.APPROVE_ROLES            # owner, estimator, reviewer, and never an agent
KINDS = ("area", "length", "perimeter", "count", "volume", "other")
KIND_UNITS = {"area": "sqft", "length": "lf", "perimeter": "lf", "count": "ea"}
SOURCE_METHODS = {"cad": "cad", "vector": "vector", "raster": "raster", "ai": "ai", "manual": "manual"}
MAX_OBJECTS = 5000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _confirm(confirm: bool, message: str, **details) -> None:
    if not confirm:
        raise ConfirmationRequired(message + " Call again with confirm=true.", **details)


def _role(ctx: RequestContext, roles, what: str) -> None:
    if ctx.role not in roles:
        raise PermissionDenied(f"only {', '.join(roles)} can {what}", role=ctx.role)


def _person(ctx: RequestContext, what: str) -> None:
    """Approving and accepting changes are a person's decisions (spec: only a person can accept)."""
    _role(ctx, APPROVE_ROLES, what)
    if ctx.agent:
        raise PermissionDenied(f"an agent can't {what}; a person has to", agent=ctx.agent)


def _registry(registry=None):
    from estimator.modules import get_registry
    return registry or get_registry()


def _load(conn, ctx, measurement_id: int) -> dict:
    row = conn.execute("SELECT * FROM measurements WHERE id = ? AND company_id = ?",
                       (int(measurement_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"measurement {measurement_id} not found", measurement_id=measurement_id)
    return dict(row)


def _q(d: Decimal) -> str:
    return str(d.quantize(Decimal("0.01")))


def _feed(reg, module_id: str | None, feeds: str | None):
    """Check the trade and question a measurement feeds. Returns (module, question) or (None, None)."""
    if not module_id:
        if feeds:
            raise InvalidInput("say which trade (module_id) the question belongs to", field="module_id")
        return None, None
    try:
        mod = reg.get(module_id)
    except Exception:
        raise InvalidInput(f"there's no trade module '{module_id}'", field="module_id") from None
    if not feeds:
        return mod, None
    q = next((q for q in mod.questions if q.id == feeds), None)
    if q is None or q.type not in ("number", "integer"):
        numeric = [q.id for q in mod.questions if q.type in ("number", "integer")]
        raise InvalidInput(f"{mod.name} has no number question '{feeds}'. It has: {', '.join(numeric)}",
                           field="feeds", questions=numeric)
    return mod, q


def _in_question_unit(qty: Decimal, unit: str, question) -> Decimal:
    if question is None or not question.unit:
        return qty
    try:
        return convert(qty, unit, question.unit)
    except (UnitError, Exception):
        raise InvalidInput(f"a measurement in {unit} can't feed '{question.id}', which is in {question.unit}",
                           field="unit") from None


def _out(m: dict) -> dict:
    return {"id": m["id"], "estimate_id": m["estimate_id"], "module_id": m["module_id"], "feeds": m["feeds"],
            "kind": m["kind"], "label": m["label"], "room": m["room"], "qty": m["qty"], "unit": m["unit"],
            "status": m["status"], "locked": bool(m["locked"]), "method": m["method"],
            "confidence": m["confidence"], "sheet_id": m["sheet_id"], "viewport_id": m["viewport_id"],
            "source_object_ids": json.loads(m["source_object_ids"] or "[]"),
            "suggested_qty": m["suggested_qty"], "suggested_reason": m["suggested_reason"],
            "needs_remeasure": bool(m["needs_remeasure"]), "reject_reason": m["reject_reason"],
            "proposed_by": m["proposed_by"], "approved_by": m["approved_by"], "approved_at": m["approved_at"]}


def _log(conn, ctx, m: dict, action: str, after: dict | None = None, before: dict | None = None) -> None:
    service._log(conn, ctx, m["estimate_id"], action, {"measurement_id": m["id"], **(after or {})}, before=before)


# ---------------------------------------------------------------- measuring drawing objects

def _objects(conn, ctx, object_ids: list[int]) -> list[dict]:
    ids = sorted({int(i) for i in object_ids})
    if not ids:
        raise InvalidInput("give the drawing objects to measure (object_ids from plan_get_objects)")
    if len(ids) > MAX_OBJECTS:
        raise InvalidInput(f"at most {MAX_OBJECTS} objects in one measurement")
    rows = [dict(r) for r in conn.execute(
        f"SELECT o.*, s.plan_set_id, s.sheet_no, s.page_no, s.units FROM drawing_objects o"
        f" JOIN sheets s ON s.id = o.sheet_id WHERE o.company_id = ? AND o.id IN ({','.join('?' for _ in ids)})",
        [ctx.company_id, *ids])]
    missing = sorted(set(ids) - {r["id"] for r in rows})
    if missing:
        raise NotFound(f"drawing object(s) {missing} not found", object_ids=missing)
    return rows


def _measure_objects(rows: list[dict], kind: str) -> tuple[Decimal, list[int]]:
    """Add up the objects' real sizes for a kind. Returns (qty, ids that couldn't be measured)."""
    if kind == "count":
        return Decimal(len(rows)), []
    field = {"area": "area_sqft", "perimeter": "perimeter_ft", "length": "length_ft"}[kind]
    total, bad = Decimal(0), []
    for r in rows:
        real = json.loads(r["real_units_json"]) if r["real_units_json"] else None
        if not real or field not in real:
            bad.append(r["id"])
        else:
            total += Decimal(real[field])
    return total, bad


def _auto_kind(rows: list[dict]) -> str:
    gtypes = {json.loads(r["geometry_json"])["type"] for r in rows}
    if gtypes == {"polygon"}:
        return "area"
    if gtypes <= {"line", "polyline"}:
        return "length"
    if gtypes == {"point"}:
        return "count"
    raise InvalidInput("these objects are different shapes; say what to measure: kind = area, perimeter, length "
                       "or count", field="kind")


def _calc_from_objects(rows: list[dict], kind: str, qty: Decimal) -> dict:
    sheets = sorted({(r["plan_set_id"], r["sheet_id"], r["sheet_no"], r["page_no"]) for r in rows})
    return {"how": f"{kind} of {len(rows)} drawing object(s)", "qty": _q(qty), "objects": len(rows),
            "sheets": [{"plan_set_id": p, "sheet_id": s, "sheet_no": n, "page_no": g} for p, s, n, g in sheets],
            "viewports": sorted({r["viewport_id"] for r in rows if r["viewport_id"]})}


def propose(conn, ctx: RequestContext, estimate_id: int, module_id: str, object_ids: list, *, feeds: str | None = None,
            kind: str | None = None, label: str | None = None, room: str | None = None, layer: str | None = None,
            confidence=None, one_per_object: bool = False, confirm: bool = False, registry=None) -> dict:
    """Propose measurements for a trade from drawing objects. The quantity always comes from the drawing model
    (never typed by the AI); objects that can't be measured (no scale, NTS) are refused with the reason."""
    _role(ctx, PROPOSE_ROLES, "propose measurements")
    est = service._load_row(conn, ctx, int(estimate_id))
    reg = _registry(registry)
    mod, question = _feed(reg, module_id, feeds)
    rows = _objects(conn, ctx, object_ids)
    kind = (kind or _auto_kind(rows)).strip().lower()
    if kind not in ("area", "perimeter", "length", "count"):
        raise InvalidInput("from drawing objects, kind must be area, perimeter, length or count", field="kind")
    groups = [[r] for r in rows] if one_per_object else [rows]
    planned = []
    for g in groups:
        qty, bad = _measure_objects(g, kind)
        if bad:
            raise InvalidInput(f"object(s) {bad} have no real {kind} (their viewport has no scale or is NTS); set the "
                               "scale with plan_set_scale first", object_ids=bad)
        unit = KIND_UNITS[kind]
        _in_question_unit(qty, unit, question)
        planned.append((g, qty, unit))
    conf = None if confidence in (None, "") else geo.dec(confidence, "confidence")
    if conf is not None and not (0 <= conf <= 1):
        raise InvalidInput("confidence must be between 0 and 1", field="confidence")
    total = sum((p[1] for p in planned), Decimal(0))
    _confirm(confirm, f"Propose {len(planned)} {kind} measurement(s) for {mod.name}"
             + (f" ({feeds})" if feeds else "") + f": {_q(total)} {planned[0][2]} in all?",
             count=len(planned), total=_q(total), unit=planned[0][2])
    made = []
    now = _now()
    with service.transaction(conn):
        for g, qty, unit in planned:
            methods = {SOURCE_METHODS[r["source"]] for r in g}
            obj_conf = [Decimal(r["confidence"]) for r in g if r["confidence"] is not None]
            c = conf if conf is not None else (min(obj_conf) if obj_conf else None)
            first = g[0]
            mid = conn.execute(
                "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id, layer,"
                " kind, label, room, qty, unit, source_object_ids, calc_json, method, confidence, proposed_by,"
                " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ctx.company_id, est["id"], mod.id, feeds, first["sheet_id"] if len({r["sheet_id"] for r in g}) == 1
                 else None, first["viewport_id"] if len({r["viewport_id"] for r in g}) == 1 else None,
                 layer or first["layer"], kind, label or (first["label"] if len(g) == 1 else None), room,
                 _q(qty), unit, json.dumps([r["id"] for r in g]), json.dumps(_calc_from_objects(g, kind, qty)),
                 methods.pop() if len(methods) == 1 else "ai", None if c is None else str(c), ctx.actor, now,
                 now)).lastrowid
            m = _load(conn, ctx, mid)
            _log(conn, ctx, m, "measurement_proposed", {"qty": m["qty"], "unit": unit, "feeds": feeds})
            made.append(_out(m))
    return {"ok": True, "proposed": made, "count": len(made),
            "next": "a person approves them with takeoff_confirm (they're not priced until approved)"}


def manual(conn, ctx: RequestContext, estimate_id: int, module_id: str, *, feeds: str | None = None, qty=None,
           unit: str | None = None, kind: str | None = None, label: str | None = None, room: str | None = None,
           sheet_id: int | None = None, viewport_id: int | None = None, geometry: dict | None = None,
           approve: bool = False, confirm: bool = False, registry=None) -> dict:
    """Add a typed measurement (qty and unit) or a drawn one (a shape on a sheet, measured with its viewport's scale).
    A person can approve it in the same step."""
    _role(ctx, PROPOSE_ROLES, "add measurements")
    est = service._load_row(conn, ctx, int(estimate_id))
    reg = _registry(registry)
    mod, question = _feed(reg, module_id, feeds)
    calc, geom_json, method = {}, None, "typed"
    if geometry is not None:
        if not viewport_id:
            raise InvalidInput("a drawn shape needs the viewport it's drawn in (its scale measures it)",
                               field="viewport_id")
        vp = conn.execute("SELECT v.*, s.units, s.id AS sid, s.sheet_no, s.plan_set_id FROM viewports v JOIN sheets s"
                          " ON s.id = v.sheet_id WHERE v.id = ? AND v.company_id = ?",
                          (int(viewport_id), ctx.company_id)).fetchone()
        if vp is None:
            raise NotFound(f"viewport {viewport_id} not found", viewport_id=viewport_id)
        g = geo.check_geometry(geometry)
        factor = geo.feet_per_unit(vp["units"], Decimal(vp["scale_ratio"]) if vp["scale_ratio"] else None,
                                   bool(vp["is_nts"]))
        real = geo.measure(g, factor)
        if real is None:
            raise InvalidInput("that viewport has no scale (or is NTS), so the shape can't be measured; set the scale "
                               "first", viewport_id=vp["id"])
        auto = {"polygon": "area", "line": "length", "polyline": "length", "point": "count"}[g["type"]]
        kind = (kind or auto).lower()
        field = {"area": "area_sqft", "perimeter": "perimeter_ft", "length": "length_ft"}.get(kind)
        if kind == "count":
            value = Decimal(len(g["points"]))
        elif field and field in real:
            value = Decimal(real[field])
        else:
            raise InvalidInput(f"a {g['type']} can't give a {kind}", field="kind")
        unit, sheet_id, method = KIND_UNITS[kind], vp["sid"], "manual"
        geom_json = json.dumps(geo.to_json_geometry(g))
        calc = {"how": f"{kind} of a shape drawn on sheet {vp['sheet_no'] or vp['sid']}", "qty": _q(value),
                "scale_ratio": vp["scale_ratio"], "sheets": [{"plan_set_id": vp["plan_set_id"], "sheet_id": vp["sid"],
                                                             "sheet_no": vp["sheet_no"]}]}
    else:
        if qty in (None, "") or not unit:
            raise InvalidInput("give qty and unit for a typed measurement, or a geometry drawn in a viewport")
        value = geo.dec(qty, "qty")
        try:
            unit = normalize_unit(unit)
        except Exception:
            raise InvalidInput(f"unknown unit '{unit}'", field="unit") from None
        kind = (kind or {"sqft": "area", "lf": "length", "ea": "count"}.get(unit, "other")).lower()
        calc = {"how": "typed by " + ctx.actor, "qty": _q(value)}
    if kind not in KINDS:
        raise InvalidInput(f"kind must be one of {', '.join(KINDS)}", field="kind")
    if value < 0:
        raise InvalidInput("a measurement can't be negative", field="qty")
    _in_question_unit(value, unit, question)
    if approve:
        _person(ctx, "approve measurements")
    _confirm(confirm, f"Add {_q(value)} {unit} ({kind}) for {mod.name}" + (f" → {feeds}" if feeds else "")
             + (" and approve it" if approve else "") + "?", qty=_q(value), unit=unit)
    now = _now()
    with service.transaction(conn):
        mid = conn.execute(
            "INSERT INTO measurements (company_id, estimate_id, module_id, feeds, sheet_id, viewport_id, kind, label,"
            " room, qty, unit, calc_json, geometry_json, method, confidence, status, locked, proposed_by, created_at,"
            " updated_at, approved_by, approved_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'1',?,?,?,?,?,?,?)",
            (ctx.company_id, est["id"], mod.id, feeds, sheet_id, viewport_id, kind, label, room, _q(value), unit,
             json.dumps(calc), geom_json, method, "approved" if approve else "proposed", int(approve), ctx.actor,
             now, now, ctx.actor if approve else None, now if approve else None)).lastrowid
        m = _load(conn, ctx, mid)
        _log(conn, ctx, m, "measurement_added", {"qty": m["qty"], "unit": unit, "approved": approve})
    return {"ok": True, "measurement": _out(m)}


# ---------------------------------------------------------------- review actions

def confirm_measurements(conn, ctx: RequestContext, measurement_ids: list | None = None, *,
                         estimate_id: int | None = None, module_id: str | None = None, above_confidence=None,
                         accept_suggestion: bool = False, confirm: bool = False) -> dict:
    """Approve (and lock) proposed measurements: by id, or all of a trade above a confidence (bulk approve).
    accept_suggestion=true instead accepts the suggested change on approved ones."""
    _person(ctx, "approve measurements")
    if measurement_ids:
        rows = [_load(conn, ctx, i) for i in measurement_ids]
    elif estimate_id and above_confidence not in (None, ""):
        floor = geo.dec(above_confidence, "above_confidence")
        sql = ("SELECT * FROM measurements WHERE company_id = ? AND estimate_id = ? AND status = 'proposed'"
               " AND confidence IS NOT NULL")
        args = [ctx.company_id, int(estimate_id)]
        if module_id:
            sql += " AND module_id = ?"
            args.append(module_id)
        rows = [dict(r) for r in conn.execute(sql, args) if Decimal(r["confidence"]) >= floor]
    else:
        raise InvalidInput("give measurement_ids, or estimate_id with above_confidence for a bulk approve")
    if accept_suggestion:
        todo = [m for m in rows if m["status"] == "approved" and m["suggested_qty"] is not None]
        skipped = [m["id"] for m in rows if m not in todo]
        what = f"Accept the suggested change on {len(todo)} approved measurement(s)"
    else:
        todo = [m for m in rows if m["status"] == "proposed"]
        skipped = [m["id"] for m in rows if m not in todo]
        what = f"Approve and lock {len(todo)} measurement(s)"
    if not todo:
        raise InvalidInput("nothing to do: none of these are " + ("approved with a suggested change"
                                                                 if accept_suggestion else "waiting for approval"),
                           skipped=skipped)
    _confirm(confirm, what + "?", ids=[m["id"] for m in todo], skipped=skipped)
    now = _now()
    with service.transaction(conn):
        for m in todo:
            if accept_suggestion:
                conn.execute("UPDATE measurements SET qty = suggested_qty, suggested_qty = NULL, suggested_by = NULL,"
                             " suggested_reason = NULL, suggested_at = NULL, needs_remeasure = 0, approved_by = ?,"
                             " approved_at = ?, updated_at = ? WHERE id = ?", (ctx.actor, now, now, m["id"]))
                _log(conn, ctx, m, "measurement_suggestion_accepted", {"qty": m["suggested_qty"]}, before={"qty": m["qty"]})
            else:
                conn.execute("UPDATE measurements SET status = 'approved', locked = 1, approved_by = ?, approved_at = ?,"
                             " updated_at = ? WHERE id = ?", (ctx.actor, now, now, m["id"]))
                _log(conn, ctx, m, "measurement_approved", {"qty": m["qty"]})
    return {"ok": True, "done": [m["id"] for m in todo], "skipped": skipped}


def edit(conn, ctx: RequestContext, measurement_id: int, *, qty=None, label: str | None = None,
         room: str | None = None, feeds: str | None = None, confirm: bool = False, registry=None) -> dict:
    """Change a measurement. Agents can only change proposed ones; an approved one is changed only by a person
    (it stays approved, and the change is logged)."""
    m = _load(conn, ctx, measurement_id)
    _role(ctx, PROPOSE_ROLES + ("reviewer",), "edit measurements")
    if m["status"] == "rejected":
        raise NotEditable("that measurement was rejected; add a new one instead", measurement_id=m["id"])
    if m["locked"]:
        if ctx.agent:
            raise NotEditable("that measurement is approved and locked; an agent can only suggest a change "
                              "(takeoff_suggest_change)", measurement_id=m["id"])
        _person(ctx, "change an approved measurement")
    question = None
    if feeds is not None:
        _, question = _feed(_registry(registry), m["module_id"], feeds)
    elif m["feeds"]:
        _, question = _feed(_registry(registry), m["module_id"], m["feeds"])
    changes = {}
    if qty not in (None, ""):
        value = geo.dec(qty, "qty")
        if value < 0:
            raise InvalidInput("a measurement can't be negative", field="qty")
        changes["qty"] = _q(value)
    for k, v in (("label", label), ("room", room), ("feeds", feeds)):
        if v is not None:
            changes[k] = v
    if not changes:
        raise InvalidInput("give what to change: qty, label, room or feeds")
    if "qty" in changes or "feeds" in changes:
        _in_question_unit(Decimal(changes.get("qty", m["qty"])), m["unit"], question)
    _confirm(confirm, f"Change measurement {m['id']}: " + ", ".join(f"{k} {m[k]} → {v}" for k, v in changes.items())
             + ("; it's approved, so this is a person's correction" if m["locked"] else "") + "?",
             measurement_id=m["id"], changes=changes)
    with service.transaction(conn):
        sets = ", ".join(f"{k} = ?" for k in changes)
        extra = ", calc_json = ?, method = CASE WHEN method = 'typed' THEN 'typed' ELSE 'manual' END" \
            if "qty" in changes else ""
        args = list(changes.values())
        if "qty" in changes:
            calc = json.loads(m["calc_json"] or "{}")
            calc["edited"] = {"by": ctx.actor, "from": m["qty"], "to": changes["qty"], "at": _now()}
            args.append(json.dumps(calc))
        conn.execute(f"UPDATE measurements SET {sets}{extra}, needs_remeasure = 0, updated_at = ? WHERE id = ?",
                     args + [_now(), m["id"]])
        _log(conn, ctx, m, "measurement_edited", changes, before={k: m[k] for k in changes})
    return {"ok": True, "measurement": _out(_load(conn, ctx, m["id"]))}


def reject(conn, ctx: RequestContext, measurement_id: int, reason: str = "", confirm: bool = False) -> dict:
    """takeoff_delete: reject a measurement. It's kept with the reason (history is never rewritten) and never priced.
    An approved one can only be rejected by a person."""
    m = _load(conn, ctx, measurement_id)
    _role(ctx, PROPOSE_ROLES + ("reviewer",), "reject measurements")
    if m["status"] == "rejected":
        return {"ok": True, "measurement": _out(m), "note": "already rejected"}
    if m["locked"]:
        if ctx.agent:
            raise NotEditable("that measurement is approved and locked; an agent can't remove it",
                              measurement_id=m["id"])
        _person(ctx, "reject an approved measurement")
    _confirm(confirm, f"Reject measurement {m['id']} ({m['qty']} {m['unit']}"
             + (f", {m['label']}" if m["label"] else "") + ")? It stays in the history but is never priced.",
             measurement_id=m["id"])
    with service.transaction(conn):
        conn.execute("UPDATE measurements SET status = 'rejected', locked = 0, reject_reason = ?, updated_at = ?"
                     " WHERE id = ?", (reason or None, _now(), m["id"]))
        _log(conn, ctx, m, "measurement_rejected", {"reason": reason})
    return {"ok": True, "measurement": _out(_load(conn, ctx, m["id"]))}


def suggest_change(conn, ctx: RequestContext, measurement_id: int, qty, reason: str = "", confirm: bool = False) -> dict:
    """Propose a new value for an approved (locked) measurement. It is stored beside the approved value and never
    replaces it; a person accepts it with takeoff_confirm(accept_suggestion=true) or edits the measurement."""
    m = _load(conn, ctx, measurement_id)
    _role(ctx, PROPOSE_ROLES + ("reviewer",), "suggest changes")
    if m["status"] != "approved":
        raise InvalidInput("only approved measurements take suggestions; change a proposed one with takeoff_edit",
                           measurement_id=m["id"], status=m["status"])
    value = geo.dec(qty, "qty")
    if value < 0:
        raise InvalidInput("a measurement can't be negative", field="qty")
    if not reason:
        raise InvalidInput("say why the value should change (reason)", field="reason")
    _confirm(confirm, f"Suggest {_q(value)} {m['unit']} for approved measurement {m['id']} (now {m['qty']})?",
             measurement_id=m["id"])
    _suggest(conn, ctx, m, value, reason)
    return {"ok": True, "measurement": _out(_load(conn, ctx, m["id"]))}


def _suggest(conn, ctx, m: dict, value: Decimal, reason: str) -> None:
    conn.execute("UPDATE measurements SET suggested_qty = ?, suggested_by = ?, suggested_reason = ?, suggested_at = ?,"
                 " updated_at = ? WHERE id = ?", (_q(value), ctx.actor, reason, _now(), _now(), m["id"]))
    _log(conn, ctx, m, "measurement_change_suggested", {"suggested_qty": _q(value), "reason": reason})


# ---------------------------------------------------------------- reading

def list_measurements(conn, ctx: RequestContext, estimate_id: int, module_id: str | None = None,
                      status: str | None = None, sheet_id: int | None = None, registry=None) -> dict:
    """Measurements with status and confidence, the review queue (lowest confidence first), and the approved totals
    per trade question, already in each question's unit (what runner_submit_takeoff(from_measurements) uses)."""
    service._load_row(conn, ctx, int(estimate_id))
    sql, args = "SELECT * FROM measurements WHERE company_id = ? AND estimate_id = ?", [ctx.company_id, int(estimate_id)]
    if module_id:
        sql += " AND module_id = ?"
        args.append(module_id)
    if status:
        if status not in ("proposed", "approved", "rejected"):
            raise InvalidInput("status must be proposed, approved or rejected", field="status")
        sql += " AND status = ?"
        args.append(status)
    if sheet_id:
        sql += " AND sheet_id = ?"
        args.append(int(sheet_id))
    rows = [dict(r) for r in conn.execute(sql + " ORDER BY module_id, id", args)]
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in ("proposed", "approved", "rejected")}
    queue = sorted((r for r in rows if r["status"] == "proposed"),
                   key=lambda r: (Decimal(r["confidence"]) if r["confidence"] is not None else Decimal(-1), r["id"]))
    answers = approved_answers(conn, ctx, int(estimate_id), module_id, registry)
    return {"ok": True, "estimate_id": int(estimate_id), "count": len(rows), "counts": counts,
            "measurements": [_out(r) for r in rows], "review_queue": [r["id"] for r in queue],
            "approved_answers": answers,
            "needs_remeasure": [r["id"] for r in rows if r["needs_remeasure"] and r["status"] != "rejected"],
            "suggestions_waiting": [r["id"] for r in rows if r["suggested_qty"] is not None
                                    and r["status"] == "approved"]}


def approved_answers(conn, ctx: RequestContext, estimate_id: int, module_id: str | None = None,
                     registry=None) -> dict:
    """{module_id: {question: total}} from approved measurements, in each question's unit."""
    reg = _registry(registry)
    sql = ("SELECT module_id, feeds, qty, unit FROM measurements WHERE company_id = ? AND estimate_id = ?"
           " AND status = 'approved' AND feeds IS NOT NULL")
    args = [ctx.company_id, int(estimate_id)]
    if module_id:
        sql += " AND module_id = ?"
        args.append(module_id)
    out: dict[str, dict] = {}
    for r in conn.execute(sql, args):
        try:
            _, q = _feed(reg, r["module_id"], r["feeds"])
        except InvalidInput:
            continue                                  # the module changed; the measurement no longer fits
        value = _in_question_unit(Decimal(r["qty"]), r["unit"], q)
        bucket = out.setdefault(r["module_id"], {})
        bucket[r["feeds"]] = bucket.get(r["feeds"], Decimal(0)) + value
    result = {}
    for mid, answers in out.items():
        mod = reg.get(mid)
        result[mid] = {}
        for qid, total in answers.items():
            q = mod.question(qid)
            result[mid][qid] = int(total.to_integral_value()) if q.type == "integer" else float(_q(total))
    return result


def detail(conn, ctx: RequestContext, measurement_id: int) -> dict:
    """Everything behind one measurement: the calculation, sheet and viewport (with its scale), source drawing objects,
    method, confidence, who proposed and approved it, and its history."""
    m = _load(conn, ctx, measurement_id)
    sheet = vp = None
    if m["sheet_id"]:
        s = conn.execute("SELECT id, plan_set_id, page_no, sheet_no, title, units FROM sheets WHERE id = ?",
                         (m["sheet_id"],)).fetchone()
        sheet = dict(s) if s else None
    if m["viewport_id"]:
        v = conn.execute("SELECT id, label, scale_note, scale_ratio, scale_method, is_nts FROM viewports WHERE id = ?",
                         (m["viewport_id"],)).fetchone()
        vp = dict(v) if v else None
    ids = json.loads(m["source_object_ids"] or "[]")
    objs = [{"id": r["id"], "kind": r["kind"], "label": r["label"], "tag": r["tag"], "source": r["source"],
             "confidence": r["confidence"],
             "real_units": json.loads(r["real_units_json"]) if r["real_units_json"] else None}
            for r in conn.execute(f"SELECT * FROM drawing_objects WHERE id IN ({','.join('?' for _ in ids)})", ids)] \
        if ids else []
    history = []
    for e in conn.execute("SELECT actor, action, before_json, after_json, at FROM estimate_events WHERE estimate_id = ?"
                          " AND action LIKE 'measurement_%' ORDER BY id", (m["estimate_id"],)):
        after = json.loads(e["after_json"] or "{}")
        if after.get("measurement_id") == m["id"]:
            history.append({"at": e["at"], "by": e["actor"], "action": e["action"], "after": after,
                            "before": json.loads(e["before_json"]) if e["before_json"] else None})
    return {"ok": True, "measurement": _out(m), "calc": json.loads(m["calc_json"] or "{}"),
            "geometry": json.loads(m["geometry_json"]) if m["geometry_json"] else None, "sheet": sheet,
            "viewport": vp, "source_objects": objs, "missing_objects": sorted(set(ids) - {o["id"] for o in objs}),
            "history": history}


# ---------------------------------------------------------------- when the drawing model changes

def objects_changed(conn, ctx: RequestContext, object_ids: list[int]) -> dict:
    """Called inside the caller's transaction after objects were re-measured (a new viewport scale). Proposed
    measurements are updated; approved ones keep their value and get a suggested change (never overwritten)."""
    ids = set(object_ids)
    if not ids:
        return {"updated": 0, "suggested": 0, "flagged": 0}
    counts = {"updated": 0, "suggested": 0, "flagged": 0}
    for m in [dict(r) for r in conn.execute("SELECT * FROM measurements WHERE company_id = ? AND status != 'rejected'"
                                            " AND kind IN ('area', 'length', 'perimeter', 'count')",
                                            (ctx.company_id,))]:
        mine = json.loads(m["source_object_ids"] or "[]")
        if not ids.intersection(mine):
            continue
        rows = [dict(r) for r in conn.execute(
            f"SELECT o.*, s.plan_set_id, s.sheet_no, s.page_no FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id"
            f" WHERE o.id IN ({','.join('?' for _ in mine)})", mine)]
        qty, bad = _measure_objects(rows, m["kind"]) if len(rows) == len(mine) else (None, mine)
        if bad or qty is None:
            conn.execute("UPDATE measurements SET needs_remeasure = 1, updated_at = ? WHERE id = ?", (_now(), m["id"]))
            counts["flagged"] += 1
            continue
        if _q(qty) == m["qty"]:
            continue
        if m["locked"]:
            _suggest(conn, ctx, m, qty, "the viewport scale changed")
            counts["suggested"] += 1
        else:
            conn.execute("UPDATE measurements SET qty = ?, calc_json = ?, needs_remeasure = 0, updated_at = ?"
                         " WHERE id = ?", (_q(qty), json.dumps(_calc_from_objects(rows, m["kind"], qty)), _now(),
                                           m["id"]))
            _log(conn, ctx, m, "measurement_remeasured", {"qty": _q(qty)}, before={"qty": m["qty"]})
            counts["updated"] += 1
    return counts


def plan_set_reread(conn, ctx: RequestContext, plan_set_id: int) -> dict:
    """Called inside save_results before a plan set's drawing model is replaced. Proposed measurements from it are
    rejected (their objects are gone); approved ones keep their value and are flagged to re-measure."""
    sheet_ids = [r[0] for r in conn.execute("SELECT id FROM sheets WHERE plan_set_id = ?", (int(plan_set_id),))]
    if not sheet_ids:
        return {"rejected": 0, "flagged": 0}
    marks = ",".join("?" for _ in sheet_ids)
    obj_ids = {r[0] for r in conn.execute(f"SELECT id FROM drawing_objects WHERE sheet_id IN ({marks})", sheet_ids)}
    counts = {"rejected": 0, "flagged": 0}
    for m in [dict(r) for r in conn.execute("SELECT * FROM measurements WHERE company_id = ? AND status != 'rejected'",
                                            (ctx.company_id,))]:
        mine = set(json.loads(m["source_object_ids"] or "[]"))
        if not (mine & obj_ids or m["sheet_id"] in sheet_ids):
            continue
        if m["locked"]:
            conn.execute("UPDATE measurements SET needs_remeasure = 1, updated_at = ? WHERE id = ?", (_now(), m["id"]))
            _log(conn, ctx, m, "measurement_flagged", {"reason": "the plans were read again"})
            counts["flagged"] += 1
        else:
            conn.execute("UPDATE measurements SET status = 'rejected', reject_reason = 'the plans were read again',"
                         " updated_at = ? WHERE id = ?", (_now(), m["id"]))
            _log(conn, ctx, m, "measurement_rejected", {"reason": "the plans were read again"})
            counts["rejected"] += 1
    return counts
