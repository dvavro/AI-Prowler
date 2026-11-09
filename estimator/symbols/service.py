"""Reading the Symbol Recognition Engine's results: symbol_detections_list (spec: "Detections by type, sheet, room,
status and confidence, with counts") and the plan-set dictionary for plan_get_legends.

Read-only. Anyone who can open the plans can list detections (field staff count devices too). Approving, relabelling
and rejecting detections (symbol_detection_review) and find-similar come with Blueprint Review's symbol panel
(Sprint 11).
"""
from __future__ import annotations

import json

from estimator.context import RequestContext
from estimator.errors import InvalidInput

STATUSES = ("proposed", "approved", "rejected")
MAX_LIMIT = 1000


def _plan_sets(conn, ctx, plan_set_id, estimate_id) -> list[int]:
    from estimator.drawing_model import store
    from estimator.estimating import service
    if plan_set_id:
        return [store.load_plan_set(conn, ctx, int(plan_set_id))["id"]]
    if estimate_id:
        service.get_estimate(conn, ctx, int(estimate_id))           # not found / another company's estimate
        return [r["id"] for r in conn.execute("SELECT id FROM plan_sets WHERE company_id = ? AND estimate_id = ?",
                                              (ctx.company_id, int(estimate_id)))]
    raise InvalidInput("give a plan_set_id or an estimate_id")


def detections_list(conn, ctx: RequestContext, plan_set_id: int | None = None, estimate_id: int | None = None,
                    item_type: str | None = None, sheet_id: int | None = None, room: str | None = None,
                    status: str | None = None, min_confidence=None, needs_review: bool | None = None,
                    limit: int = 200, offset: int = 0) -> dict:
    """Detections with counts by type, by sheet and by room. Filters narrow both the list and the counts."""
    ids = _plan_sets(conn, ctx, plan_set_id, estimate_id)
    if status is not None and status not in STATUSES:
        raise InvalidInput(f"status must be one of {', '.join(STATUSES)}", field="status", valid=list(STATUSES))
    try:
        limit = max(1, min(int(limit), MAX_LIMIT))
        offset = max(0, int(offset))
        min_conf = None if min_confidence in (None, "") else float(min_confidence)
    except (TypeError, ValueError):
        raise InvalidInput("limit, offset and min_confidence must be numbers") from None
    if not ids:
        return {"ok": True, "plan_set_ids": [], "count": 0, "returned": 0, "offset": offset, "counts": _empty(),
                "detections": []}
    where = [f"d.plan_set_id IN ({','.join('?' for _ in ids)})", "d.company_id = ?"]
    args: list = [*ids, ctx.company_id]
    if item_type:
        where.append("d.item_type = ?")
        args.append(item_type.strip())
    if sheet_id:
        where.append("d.sheet_id = ?")
        args.append(int(sheet_id))
    if status:
        where.append("d.status = ?")
        args.append(status)
    if needs_review is not None:
        where.append("d.needs_review = ?")
        args.append(int(bool(needs_review)))
    if room:
        where.append("UPPER(r.label) = UPPER(?)")
        args.append(room.strip())
    sql = ("SELECT d.*, s.sheet_no, s.page_no, r.label AS room_label, f.code AS def_code, f.description AS def_description,"
           " f.library_id AS def_library, f.entry_key AS def_entry, lb.level AS def_level FROM symbol_detections d"
           " JOIN sheets s ON s.id = d.sheet_id LEFT JOIN drawing_objects r ON r.id = d.room_id"
           " LEFT JOIN symbol_definitions f ON f.id = d.definition_id LEFT JOIN symbol_libraries lb ON lb.id = f.library_id"
           " WHERE " + " AND ".join(where) +
           " ORDER BY s.page_no, d.item_type, d.id")
    rows = [dict(r) for r in conn.execute(sql, args)]
    if min_conf is not None:
        rows = [r for r in rows if r["confidence"] is not None and float(r["confidence"]) >= min_conf]
    counts = _empty()
    for r in rows:
        key = r["item_type"] or "unknown"
        t = counts["by_type"].setdefault(key, {"item_type": r["item_type"], "trade": r["trade"], "count": 0,
                                                "approved": 0, "proposed": 0, "rejected": 0, "needs_review": 0,
                                                "label": r["def_description"] or r["label"]})
        t[r["status"]] += 1
        if r["status"] == "rejected":                 # taken out of the count in review (Sprint 11): listed, not counted
            continue
        t["count"] += 1
        t["needs_review"] += r["needs_review"] if r["status"] == "proposed" else 0
        sh = counts["by_sheet"].setdefault(r["sheet_id"], {"sheet_id": r["sheet_id"], "sheet_no": r["sheet_no"],
                                                           "page_no": r["page_no"], "count": 0, "by_type": {}})
        sh["count"] += 1
        sh["by_type"][key] = sh["by_type"].get(key, 0) + 1
        rm = counts["by_room"].setdefault(r["room_label"] or "(no room)", {"room": r["room_label"], "count": 0, "by_type": {}})
        rm["count"] += 1
        rm["by_type"][key] = rm["by_type"].get(key, 0) + 1
    page = rows[offset:offset + limit]
    return {"ok": True, "plan_set_ids": ids, "count": len(rows), "returned": len(page), "offset": offset,
            "counts": {"by_type": sorted(counts["by_type"].values(), key=lambda t: (-t["count"], t["item_type"] or "")),
                       "by_sheet": sorted(counts["by_sheet"].values(), key=lambda s: s["page_no"]),
                       "by_room": sorted(counts["by_room"].values(), key=lambda m: (m["room"] is None, m["room"] or ""))},
            "detections": [_out(r) for r in page]}


def _empty() -> dict:
    return {"by_type": {}, "by_sheet": {}, "by_room": {}}


def _out(r: dict) -> dict:
    loc = json.loads(r["location_json"])
    source = "plan-set legend" if r["def_entry"] else (r["def_level"] + " library" if r.get("def_level") else None)
    if r["method"] == "cad" and not source:
        source = "CAD block name"
    original = json.loads(r["original_json"]) if r.get("original_json") else None
    return {"id": r["id"], "plan_set_id": r["plan_set_id"], "sheet_id": r["sheet_id"], "sheet_no": r["sheet_no"],
            "drawing_object_id": r["drawing_object_id"], "definition_id": r["definition_id"],
            "item_type": r["item_type"], "trade": r["trade"], "label": r["label"], "code": r["def_code"],
            "room_id": r["room_id"], "room": r["room_label"], "viewport_id": r["viewport_id"],
            "point": loc.get("point"), "bbox": loc.get("bbox"),
            "rotation": float(r["rotation"]) if r["rotation"] is not None else None, "mirrored": bool(r["mirrored"]),
            "method": r["method"], "definition_from": source, "scores": json.loads(r["scores_json"]),
            "confidence": r["confidence"], "needs_review": bool(r["needs_review"]), "status": r["status"],
            "reviewed_by": r["reviewed_by"], "origin": r.get("origin") or "engine",
            "original": original if original and (original.get("item_type") != r["item_type"]
                                                  or original.get("status") != r["status"]) else None}


def dictionary(conn, plan_set_id: int) -> list[dict] | None:
    """The plan-set symbol dictionary (definitions read from its legends), or None when it has none in the table."""
    rows = conn.execute(
        "SELECT f.*, l.title AS legend_title, s.sheet_no, (SELECT COUNT(*) FROM symbol_examples x"
        " WHERE x.definition_id = f.id) AS examples, (SELECT COUNT(*) FROM symbol_detections d WHERE d.definition_id = f.id)"
        " AS detections FROM symbol_definitions f LEFT JOIN legends l ON l.id = f.legend_id"
        " LEFT JOIN sheets s ON s.id = l.sheet_id WHERE f.plan_set_id = ? ORDER BY f.id", (plan_set_id,)).fetchall()
    if not rows:
        return None
    return [{"id": r["id"], "sheet_no": r["sheet_no"], "legend": r["legend_title"], "code": r["code"],
             "description": r["description"], "item_type": r["item_type"], "trade": r["trade"],
             "has_symbol": bool(r["examples"]), "confidence": float(r["confidence"]) if r["confidence"] else None,
             "needs_confirming": bool(r["needs_confirming"]), "status": r["status"], "found": r["detections"]}
            for r in rows]
