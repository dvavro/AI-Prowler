"""Saving the Symbol Recognition Engine's results: the plan-set dictionary (symbol_definitions + symbol_examples) and
one symbol_detections row per symbol found (spec: "Standardized symbol result"), linked into the drawing model.

Called by drawing_model.store.save_results inside its transaction, after the sheets, objects and legends are written.
The engine's extra keys are read from the raw results (store._check_results ignores them):
  results["symbol_dictionary"]: [{key, page_no, legend_index, code, description, item_type, trade, confidence,
                                  needs_confirming, has_symbol, template, abbreviations}]
  sheet["objects"][i]["symbol"]: {entry, standard, item_type, trade, scores, confidence, rotation, mirrored, bbox,
                                  method, needs_review}
Anything malformed is skipped, never fatal: the drawing model is already checked and the symbols are extra.
"""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path

METHODS = ("cad", "vector", "raster", "ocr", "ai", "manual")
SCORE_KEYS = ("legend", "vision", "ocr", "ai", "cad")
MAX_ENTRIES = 2000
MAX_TEXT = 300


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _txt(v, n=MAX_TEXT):
    return v.strip()[:n] if isinstance(v, str) and v.strip() else None


def _conf(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return str(round(f, 3)) if 0 <= f <= 1 and not math.isnan(f) else None


def _num(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(f) or math.isinf(f) else f


def _point_in(p, poly) -> bool:
    inside = False
    n = len(poly)
    for i in range(n):
        (x1, y1), (x2, y2) = poly[i], poly[(i + 1) % n]
        if (y1 > p[1]) != (y2 > p[1]) and p[0] < (x2 - x1) * (p[1] - y1) / ((y2 - y1) or 1e-12) + x1:
            inside = not inside
    return inside


def save(conn, ctx, plan_set: dict, results: dict, saved: list[dict]) -> dict:
    """saved: per sheet in results order {page_no, sheet_id, object_ids, legend_ids}. Returns counts."""
    from estimator.symbols import library

    out = {"symbol_definitions": 0, "symbol_detections": 0}
    sheets_raw = results.get("sheets") or []
    entries = results.get("symbol_dictionary") if isinstance(results.get("symbol_dictionary"), list) else []
    has_symbols = any(isinstance(o, dict) and isinstance(o.get("symbol"), dict)
                      for s in sheets_raw if isinstance(s, dict) for o in (s.get("objects") or []))
    if not entries and not has_symbols:
        return out
    company, now = ctx.company_id, _now()
    std = library.ensure_standard(conn, company)
    by_page = {s["page_no"]: s for s in saved}

    defs: dict[str, int] = {}
    for e in entries[:MAX_ENTRIES]:
        if not isinstance(e, dict) or not isinstance(e.get("key"), str):
            continue
        s = by_page.get(e.get("page_no"))
        li = e.get("legend_index")
        legend_id = s["legend_ids"][li] if s and isinstance(li, int) and 0 <= li < len(s["legend_ids"]) else None
        code = _txt(e.get("code"), 40)
        did = conn.execute(
            "INSERT INTO symbol_definitions (company_id, plan_set_id, legend_id, entry_key, code, description, item_type,"
            " trade, ocr_aliases_json, confidence, needs_confirming, status, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,'proposed',?)",
            (company, plan_set["id"], legend_id, e["key"][:60], code, _txt(e.get("description")),
             _txt(e.get("item_type"), 60), _txt(e.get("trade"), 40), json.dumps([code] if code else []),
             _conf(e.get("confidence")), int(bool(e.get("needs_confirming"))), now)).lastrowid
        defs[e["key"]] = did
        out["symbol_definitions"] += 1
        tpl = _txt(e.get("template"), 120)
        if s and tpl and "/" not in tpl and "\\" not in tpl and ".." not in tpl:
            img = conn.execute("SELECT image_path FROM sheets WHERE id = ?", (s["sheet_id"],)).fetchone()
            if img and img["image_path"]:
                path = Path(img["image_path"]).parent / tpl
                if path.is_file():
                    conn.execute("INSERT INTO symbol_examples (company_id, definition_id, image_path, source_sheet_id,"
                                 " source, created_at) VALUES (?,?,?,?, 'legend', ?)",
                                 (company, did, str(path), s["sheet_id"], now))

    for si, raw in enumerate(sheets_raw):
        if si >= len(saved) or not isinstance(raw, dict):
            continue
        s = saved[si]
        objs = raw.get("objects") or []
        rooms = None
        for oi, o in enumerate(objs):
            rec = o.get("symbol") if isinstance(o, dict) else None
            if not isinstance(rec, dict) or oi >= len(s["object_ids"]):
                continue
            method = rec.get("method") if rec.get("method") in METHODS else None
            if method is None:
                continue
            obj_id = s["object_ids"][oi]
            row = conn.execute("SELECT viewport_id, geometry_json FROM drawing_objects WHERE id = ?", (obj_id,)).fetchone()
            geom = json.loads(row["geometry_json"]) if row else {}
            pts = geom.get("points") or []
            if not pts:
                continue
            p = (sum(float(q[0]) for q in pts) / len(pts), sum(float(q[1]) for q in pts) / len(pts))
            if rooms is None:
                rooms = []
                for r in conn.execute("SELECT id, geometry_json FROM drawing_objects WHERE sheet_id = ? AND kind = 'room'",
                                      (s["sheet_id"],)):
                    g = json.loads(r["geometry_json"])
                    if len(g.get("points") or []) >= 3:
                        rooms.append((r["id"], [(float(a), float(b)) for a, b in g["points"]]))
            room_id = next((rid for rid, poly in rooms if _point_in(p, poly)), None)
            item_type = _txt(rec.get("item_type"), 60)
            # A refined type (plain legend symbol + "GFI" beside it) is the standard library's definition.
            definition = std.get(rec["standard"]) if rec.get("standard") else None
            if definition is None and rec.get("entry"):
                definition = defs.get(rec["entry"])
            scores_in = rec.get("scores") if isinstance(rec.get("scores"), dict) else {}
            scores = {k: (round(_num(scores_in.get(k)), 3) if _num(scores_in.get(k)) is not None else None)
                      for k in SCORE_KEYS}
            bbox = rec.get("bbox")
            bbox = [_num(v) for v in bbox] if isinstance(bbox, list) and len(bbox) == 4 else None
            if bbox and any(v is None for v in bbox):
                bbox = None
            rot = _num(rec.get("rotation"))
            conn.execute(
                "INSERT INTO symbol_detections (company_id, plan_set_id, drawing_object_id, definition_id, sheet_id,"
                " viewport_id, room_id, item_type, trade, label, location_json, rotation, mirrored, method, scores_json,"
                " confidence, needs_review, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'proposed',?)",
                (company, plan_set["id"], obj_id, definition, s["sheet_id"], row["viewport_id"] if row else None,
                 room_id, item_type, _txt(rec.get("trade"), 40), _txt(o.get("label")) or _txt(o.get("block_name")),
                 json.dumps({"point": [round(p[0], 4), round(p[1], 4)], "bbox": bbox}),
                 None if rot is None else str(round(rot, 1)), int(bool(rec.get("mirrored"))), method,
                 json.dumps(scores), _conf(rec.get("confidence")), int(bool(rec.get("needs_review")) or not item_type),
                 now))
            out["symbol_detections"] += 1
    return out
