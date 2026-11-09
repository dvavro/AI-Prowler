"""The review queue for phones and tablets: symbols the plan engine counted that a person hasn't checked yet, and
measurements waiting for approval, in one list, least sure first. Read only."""
from __future__ import annotations

from estimator.api import nav
from estimator.context import RequestContext
from estimator.errors import InvalidInput

KINDS = ("symbol", "measurement")
MAX_LIMIT = 200


def _conf(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _words(s) -> str:
    return str(s or "").replace("_", " ")


def _name(s: str) -> str:
    """Sentence case for a phone: legend text is often in capitals ("DUPLEX RECEPTACLE" -> "Duplex receptacle")."""
    s = (s or "").strip()
    if s.isupper():
        s = s.lower()
    return s[:1].upper() + s[1:]


def can_see(ctx: RequestContext) -> dict:
    """Which kinds this role can look at (the Reviews and Takeoffs screens' roles) and decide on."""
    from estimator.symbols import review
    from estimator.takeoff import measurements as ms
    return {"symbol": nav.can_open(ctx.role, "reviews"), "measurement": nav.can_open(ctx.role, "takeoffs"),
            "review_symbols": ctx.role in review.REVIEW_ROLES and not ctx.agent,
            "approve_measurements": ctx.role in ms.APPROVE_ROLES and not ctx.agent}


def _symbols(conn, ctx, estimate_id, limit):
    sql = ("SELECT d.id, d.item_type, d.label, d.trade, d.confidence, d.needs_review, d.sheet_id, d.plan_set_id,"
           " ps.estimate_id, e.title AS estimate_title, s.sheet_no, s.page_no, def.description"
           " FROM symbol_detections d JOIN plan_sets ps ON ps.id = d.plan_set_id"
           " JOIN estimates e ON e.id = ps.estimate_id AND e.company_id = d.company_id"
           " JOIN sheets s ON s.id = d.sheet_id LEFT JOIN symbol_definitions def ON def.id = d.definition_id"
           " WHERE d.company_id = ? AND d.status = 'proposed'")
    args: list = [ctx.company_id]
    if estimate_id:
        sql += " AND ps.estimate_id = ?"
        args.append(estimate_id)
    sql += " ORDER BY CAST(COALESCE(d.confidence, '0') AS REAL), d.id LIMIT ?"
    out = []
    for r in conn.execute(sql, (*args, limit)):
        what = r["label"] or r["description"] or _words(r["item_type"]) or "unidentified symbol"
        out.append({"kind": "symbol", "id": r["id"], "estimate_id": r["estimate_id"], "estimate_title": r["estimate_title"],
                    "plan_set_id": r["plan_set_id"], "sheet_id": r["sheet_id"],
                    "sheet_no": r["sheet_no"] or f"page {r['page_no']}", "title": _name(what),
                    "item_type": r["item_type"], "trade": r["trade"], "confidence": r["confidence"],
                    "needs_review": bool(r["needs_review"]), "detail": "symbol" + (f" · {r['trade']}" if r["trade"] else ""),
                    "picture": f"/estimator-api/mobile/symbols/{r['id']}/view.png",
                    "plan_link": f"#/takeoffs/{r['estimate_id']}?sheet={r['sheet_id']}&symbol={r['id']}"})
    return out


def _measurements(conn, ctx, estimate_id, limit):
    from estimator.modules import get_registry
    reg = get_registry()
    sql = ("SELECT m.id, m.module_id, m.feeds, m.kind, m.label, m.room, m.qty, m.unit, m.confidence, m.sheet_id,"
           " m.estimate_id, m.suggested_qty, m.needs_remeasure, m.geometry_json IS NOT NULL OR m.source_object_ids != '[]'"
           " AS has_shape, e.title AS estimate_title, s.sheet_no, s.page_no"
           " FROM measurements m JOIN estimates e ON e.id = m.estimate_id AND e.company_id = m.company_id"
           " LEFT JOIN sheets s ON s.id = m.sheet_id WHERE m.company_id = ? AND m.status = 'proposed'")
    args: list = [ctx.company_id]
    if estimate_id:
        sql += " AND m.estimate_id = ?"
        args.append(estimate_id)
    sql += " ORDER BY CAST(COALESCE(m.confidence, '0') AS REAL), m.id LIMIT ?"
    out = []
    for r in conn.execute(sql, (*args, limit)):
        try:
            trade = reg.get(r["module_id"]).name if r["module_id"] else ""
        except Exception:  # noqa: BLE001 - a module that was removed
            trade = r["module_id"] or ""
        what = r["label"] or _words(r["feeds"]) or _words(r["kind"])
        notes = []
        if r["suggested_qty"]:
            notes.append(f"a change to {r['suggested_qty']} {r['unit']} is suggested: check it on the desktop")
        if r["needs_remeasure"]:
            notes.append("marked to measure again")
        sheet = r["sheet_no"] or (f"page {r['page_no']}" if r["page_no"] else None)
        out.append({"kind": "measurement", "id": r["id"], "estimate_id": r["estimate_id"],
                    "estimate_title": r["estimate_title"], "sheet_id": r["sheet_id"], "sheet_no": sheet,
                    "title": _name(what), "qty": r["qty"], "unit": r["unit"], "room": r["room"],
                    "trade": trade, "confidence": r["confidence"], "needs_review": True,
                    "detail": " · ".join(x for x in (f"{r['qty']} {r['unit']}", trade, r["room"] or "") if x),
                    "notes": notes,
                    "picture": f"/estimator-api/mobile/measurements/{r['id']}/view.png"
                    if r["sheet_id"] and r["has_shape"] else None,
                    "plan_link": f"#/takeoffs/{r['estimate_id']}?m={r['id']}"})
    return out


def review_queue(conn, ctx: RequestContext, estimate_id: int | None = None, kind: str | None = None,
                 limit: int = 50) -> dict:
    """What's waiting for a person, least sure first: symbols to check and measurements to approve."""
    if kind is not None and kind not in KINDS:
        raise InvalidInput(f"kind must be one of {KINDS}", field="kind")
    try:
        limit = max(1, min(int(limit), MAX_LIMIT))
    except (TypeError, ValueError):
        raise InvalidInput("limit must be a number", field="limit") from None
    see = can_see(ctx)
    items: list[dict] = []
    counts = {"symbols": 0, "measurements": 0}
    est_filter, est_args = ("", ()) if not estimate_id else (" AND x.estimate_id = ?", (estimate_id,))
    if see["symbol"] and kind in (None, "symbol"):
        items += _symbols(conn, ctx, estimate_id, limit)
        counts["symbols"] = conn.execute(
            "SELECT COUNT(*) FROM symbol_detections d JOIN plan_sets x ON x.id = d.plan_set_id"
            " WHERE d.company_id = ? AND d.status = 'proposed'" + est_filter, (ctx.company_id, *est_args)).fetchone()[0]
    if see["measurement"] and kind in (None, "measurement"):
        items += _measurements(conn, ctx, estimate_id, limit)
        counts["measurements"] = conn.execute(
            "SELECT COUNT(*) FROM measurements x WHERE x.company_id = ? AND x.status = 'proposed'" + est_filter,
            (ctx.company_id, *est_args)).fetchone()[0]
    items.sort(key=lambda x: (_conf(x["confidence"]), x["kind"], x["id"]))
    items = items[:limit]
    projects: dict[int, dict] = {}
    for x in items:
        p = projects.setdefault(x["estimate_id"], {"estimate_id": x["estimate_id"], "title": x["estimate_title"],
                                                   "symbols": 0, "measurements": 0})
        p["symbols" if x["kind"] == "symbol" else "measurements"] += 1
    from estimator.plan_engine import symbol_library as lib
    types = sorted(({"item_type": e["item_type"], "label": e["description"], "trade": e["trade"]} for e in lib.STANDARD),
                   key=lambda t: (t["trade"] or "", t["label"].lower()))
    return {"ok": True, "items": items, "count": len(items), "waiting": counts["symbols"] + counts["measurements"],
            "counts": counts, "projects": list(projects.values()), "can": see, "item_types": types}
