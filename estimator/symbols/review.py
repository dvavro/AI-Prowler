"""Visual verification of symbol detections (spec: "Visual verification of counts and detections").

- Approve, reject (deselect) or relabel detections, one, a selection, or every identical match on the plan set
  (apply_to_matches: the same definition and type). Relabelling picks the company's definition for the new type, else
  the standard library's.
- Add a missed symbol where a person clicks on the plan.
- Find similar: the selected symbol's line work (or picture, on scans) is searched for on every sheet; new hits are
  added as proposed matches.
- History is never rewritten: each detection keeps what it first said (original_json); every change is logged.
- Corrections teach the system: approved, relabelled and added symbols become approved examples in the company
  library (library.learn), so future plan sets find them.

Who: owner, estimator and reviewer (the roles that approve counts); never an agent. Everything that changes the
count asks first. Pricing from the approved counts is the takeoff's job (takeoff_propose with the counts).
"""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path

from estimator.context import RequestContext
from estimator.errors import ConfirmationRequired, InvalidInput, NotFound, PermissionDenied

REVIEW_ROLES = ("owner", "estimator", "reviewer")
ACTIONS = ("approve", "reject", "relabel", "reset", "add")
MAX_IDS = 5000
EXAMPLES_PER_REVIEW = 3


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _person(ctx: RequestContext, what: str) -> None:
    if ctx.role not in REVIEW_ROLES:
        raise PermissionDenied(f"only {', '.join(REVIEW_ROLES)} can {what}", role=ctx.role)
    if getattr(ctx, "agent", None):
        raise PermissionDenied(f"an agent can't {what}; a person has to", agent=ctx.agent)


def load_detections(conn, ctx: RequestContext, ids) -> list[dict]:
    try:
        ids = sorted({int(i) for i in ids})
    except (TypeError, ValueError):
        raise InvalidInput("detection_ids must be numbers") from None
    if not ids:
        raise InvalidInput("give one or more detection_ids")
    if len(ids) > MAX_IDS:
        raise InvalidInput(f"at most {MAX_IDS} detections at a time")
    rows = []
    for i in range(0, len(ids), 500):
        part = ids[i:i + 500]
        rows += [dict(r) for r in conn.execute(
            f"SELECT d.*, p.estimate_id, p.file_path, p.file_type, s.page_no, s.image_path, s.width, s.height"
            f" FROM symbol_detections d JOIN plan_sets p ON p.id = d.plan_set_id JOIN sheets s ON s.id = d.sheet_id"
            f" WHERE d.company_id = ? AND d.id IN ({','.join('?' for _ in part)})", (ctx.company_id, *part))]
    found = {r["id"] for r in rows}
    missing = [i for i in ids if i not in found]
    if missing:
        raise NotFound(f"symbol detection {missing[0]} not found", detection_id=missing[0])
    return rows


def _point(d: dict) -> tuple[float, float]:
    p = json.loads(d["location_json"]).get("point") or [0, 0]
    return float(p[0]), float(p[1])


def _box(d: dict, pad: float = 0.02) -> list[float]:
    loc = json.loads(d["location_json"])
    b = loc.get("bbox")
    if b:
        return [b[0] - pad, b[1] - pad, b[2] + pad, b[3] + pad]
    x, y = _point(d)
    return [x - 0.2, y - 0.2, x + 0.2, y + 0.2]


def example_of(conn, d: dict) -> dict:
    """The line work of one detection on its sheet (vector PDFs), to learn from. None template when it has none."""
    tpl = None
    if (d.get("file_type") or "").lower() == "pdf" and d.get("file_path"):
        try:
            from estimator.plan_engine import pdf_pages, symbols
            t = symbols.template_from(pdf_pages.page_segments(d["file_path"], d["page_no"]), _box(d))
            tpl = symbols.template_to_json(t) if t else None
        except Exception:  # noqa: BLE001 - a missing or changed file just means no example line work
            tpl = None
    return {"template": tpl, "image_path": None, "sheet_id": d["sheet_id"], "detection_id": d["id"]}


def _matches(conn, ctx, dets: list[dict]) -> list[dict]:
    """Every other detection identical to the chosen ones: same plan set, same definition (or same type), not rejected."""
    keys = {(d["plan_set_id"], d["definition_id"], d["item_type"]) for d in dets}
    more = []
    for ps, did, it in keys:
        sql = ("SELECT id FROM symbol_detections WHERE company_id = ? AND plan_set_id = ? AND status != 'rejected'"
               " AND " + ("definition_id = ?" if did is not None else "definition_id IS NULL AND item_type IS ?"))
        more += [r["id"] for r in conn.execute(sql, (ctx.company_id, ps, did if did is not None else it))]
    ids = {d["id"] for d in dets} | set(more)
    return load_detections(conn, ctx, ids)


def review(conn, ctx: RequestContext, detection_ids=None, action: str = "approve", item_type: str | None = None,
           apply_to_matches: bool = False, sheet_id: int | None = None, point=None, note: str | None = None,
           confirm: bool = False) -> dict:
    """symbol_detection_review. Actions: approve, reject, relabel (needs item_type), reset (back to proposed), and add
    (a missed symbol at point on sheet_id, needs item_type). Asks first."""
    from estimator.estimating import service
    from estimator.symbols import library

    action = (action or "").strip().lower()
    if action not in ACTIONS:
        raise InvalidInput(f"action must be one of {', '.join(ACTIONS)}", field="action", valid=list(ACTIONS))
    _person(ctx, "review symbols")
    if action == "add":
        return add(conn, ctx, sheet_id, point, item_type, confirm=confirm)
    dets = load_detections(conn, ctx, detection_ids or [])
    if apply_to_matches:
        dets = _matches(conn, ctx, dets)
    new_type, definition = None, None
    if action == "relabel":
        if not item_type:
            raise InvalidInput("relabel needs the item_type it really is (e.g. floor_box)", field="item_type")
        new_type = library.check_item_type(item_type)
        definition = library.definition_for(conn, ctx.company_id, new_type)
    estimates = sorted({d["estimate_id"] for d in dets})
    counts: dict[str, int] = {}
    for d in dets:
        counts[d["item_type"] or "unknown"] = counts.get(d["item_type"] or "unknown", 0) + 1
    what = ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in sorted(counts.items()))
    question = {"approve": f"Approve {len(dets)} symbol(s) ({what})?",
                "reject": f"Take {len(dets)} symbol(s) out of the count ({what})?",
                "relabel": f"Relabel {len(dets)} symbol(s) ({what}) as {(new_type or '').replace('_', ' ')}?",
                "reset": f"Put {len(dets)} symbol(s) ({what}) back to proposed?"}[action]
    if not confirm:
        raise ConfirmationRequired(question + " The first result is kept in the history. Call again with confirm=true.",
                                   action=action, detections=len(dets), by_type=counts, item_type=new_type)
    now = _now()
    learned = None
    with service.transaction(conn):
        for d in dets:
            if action == "approve":
                conn.execute("UPDATE symbol_detections SET status = 'approved', needs_review = 0, reviewed_by = ?,"
                             " reviewed_at = ? WHERE id = ?", (ctx.actor, now, d["id"]))
            elif action == "reject":
                conn.execute("UPDATE symbol_detections SET status = 'rejected', reviewed_by = ?, reviewed_at = ?"
                             " WHERE id = ?", (ctx.actor, now, d["id"]))
            elif action == "reset":
                conn.execute("UPDATE symbol_detections SET status = 'proposed', reviewed_by = NULL, reviewed_at = NULL"
                             " WHERE id = ?", (d["id"],))
            else:
                conn.execute("UPDATE symbol_detections SET item_type = ?, trade = COALESCE(?, trade), definition_id = ?,"
                             " label = ?, status = 'approved', needs_review = 0, reviewed_by = ?, reviewed_at = ?"
                             " WHERE id = ?", (new_type, definition.get("trade"), definition.get("id"),
                                               definition.get("description"), ctx.actor, now, d["id"]))
                if d["drawing_object_id"]:
                    conn.execute("UPDATE drawing_objects SET label = ? WHERE id = ?",
                                 (definition.get("description"), d["drawing_object_id"]))
        if action in ("approve", "relabel"):
            learn_type = new_type or next((d["item_type"] for d in dets if d["item_type"]), None)
            if learn_type and len({d["item_type"] for d in dets}) <= 1 or new_type:
                best = sorted(dets, key=lambda d: -float(d["confidence"] or 0))[:EXAMPLES_PER_REVIEW]
                examples = [example_of(conn, d) for d in best if d["origin"] != "library"]
                if examples and any(e["template"] for e in examples):
                    learned = library.learn(conn, ctx, learn_type, examples)
        for eid in estimates:
            service._log(conn, ctx, eid, "symbols_reviewed",
                         {"action": action, "detections": len([d for d in dets if d["estimate_id"] == eid]),
                          "by_type": counts, "item_type": new_type, "note": (note or "")[:300] or None,
                          "learned_definition": learned})
    return {"ok": True, "action": action, "changed": len(dets), "by_type": counts, "item_type": new_type,
            "learned_definition_id": learned}


def _room_at(conn, sheet_id: int, p) -> int | None:
    from estimator.symbols.results import _point_in
    for r in conn.execute("SELECT id, geometry_json FROM drawing_objects WHERE sheet_id = ? AND kind = 'room'", (sheet_id,)):
        g = json.loads(r["geometry_json"])
        pts = g.get("points") or []
        if len(pts) >= 3 and _point_in(p, [(float(a), float(b)) for a, b in pts]):
            return r["id"]
    return None


def _viewport_at(conn, sheet_id: int, p) -> int | None:
    best = None
    for v in conn.execute("SELECT id, bbox_json FROM viewports WHERE sheet_id = ?", (sheet_id,)):
        b = json.loads(v["bbox_json"]) if v["bbox_json"] else None
        if b and b[0] <= p[0] <= b[2] and b[1] <= p[1] <= b[3]:
            area = (b[2] - b[0]) * (b[3] - b[1])
            if best is None or area < best[1]:
                best = (v["id"], area)
    return best[0] if best else None


def _new_detection(conn, ctx, sheet: dict, p, *, item_type, definition, method, origin, scores, confidence,
                   status, bbox=None, rotation=None, mirrored=False, needs_review=False) -> int:
    from estimator.drawing_model import geometry as geo
    from estimator.symbols.results import insert_detection
    vp = _viewport_at(conn, sheet["id"], p)
    geom = {"type": "point", "points": [[round(p[0], 4), round(p[1], 4)]]}
    obj = conn.execute(
        "INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind, geometry_json, label, source, confidence)"
        " VALUES (?,?,?, 'symbol', ?, ?, ?, ?)",
        (ctx.company_id, sheet["id"], vp, json.dumps(geo.to_json_geometry(geo.check_geometry(geom))),
         definition.get("description"), "manual" if method == "manual" else method, str(confidence))).lastrowid
    return insert_detection(conn, ctx.company_id, sheet["plan_set_id"], sheet_id=sheet["id"], object_id=obj,
                            definition_id=definition.get("id"), viewport_id=vp, room_id=_room_at(conn, sheet["id"], p),
                            item_type=item_type, trade=definition.get("trade"), label=definition.get("description"),
                            point=p, bbox=bbox, rotation=rotation, mirrored=mirrored, method=method, scores=scores,
                            confidence=str(confidence), needs_review=needs_review, origin=origin, now=_now(),
                            status=status, reviewed_by=ctx.actor if status == "approved" else None)


def _sheet(conn, ctx, sheet_id) -> dict:
    from estimator.drawing_model import store
    s = store._load_sheet(conn, ctx, int(sheet_id))
    ps = store.load_plan_set(conn, ctx, s["plan_set_id"])
    return {**dict(s), "estimate_id": ps["estimate_id"], "file_path": ps["file_path"], "file_type": ps["file_type"]}


def add(conn, ctx: RequestContext, sheet_id, point, item_type, confirm: bool = False) -> dict:
    """A missed symbol: a person clicked it on the plan. Saved approved, and learned when its line work can be read."""
    from estimator.estimating import service
    from estimator.symbols import library
    _person(ctx, "add symbols")
    if not sheet_id or not isinstance(point, (list, tuple)) or len(point) != 2:
        raise InvalidInput("give sheet_id and point [x, y] where the symbol is", field="point")
    try:
        p = (float(point[0]), float(point[1]))
    except (TypeError, ValueError):
        raise InvalidInput("point must be two numbers [x, y]", field="point") from None
    it = library.check_item_type(item_type or "")
    sheet = _sheet(conn, ctx, sheet_id)
    w, h = float(sheet["width"] or 0), float(sheet["height"] or 0)
    if not (0 <= p[0] <= w and 0 <= p[1] <= h):
        raise InvalidInput("that point isn't on the sheet", field="point")
    definition = library.definition_for(conn, ctx.company_id, it)
    if not confirm:
        raise ConfirmationRequired(f"Add a {it.replace('_', ' ')} at this spot on {sheet['sheet_no'] or 'the sheet'}? "
                                   "Call again with confirm=true.", item_type=it, sheet_id=sheet["id"])
    with service.transaction(conn):
        did = _new_detection(conn, ctx, sheet, p, item_type=it, definition=definition, method="manual", origin="manual",
                             scores={"legend": None, "vision": None, "ocr": None, "ai": None, "cad": None},
                             confidence=1, status="approved", bbox=[p[0] - 0.15, p[1] - 0.15, p[0] + 0.15, p[1] + 0.15])
        d = load_detections(conn, ctx, [did])[0]
        ex = example_of(conn, d)
        learned = library.learn(conn, ctx, it, [ex]) if ex["template"] else None
        service._log(conn, ctx, sheet["estimate_id"], "symbol_added", {"detection_id": did, "item_type": it,
                                                                       "sheet_id": sheet["id"], "learned": learned})
    return {"ok": True, "action": "add", "detection_id": did, "item_type": it, "learned_definition_id": learned}


def find_similar(conn, ctx: RequestContext, detection_id: int | None = None, sheet_id: int | None = None, box=None,
                 item_type: str | None = None, confirm: bool = False) -> dict:
    """symbol_find_similar: search every sheet of the plan set for more of the selected symbol's shape. New hits (not
    already found) are added as proposed matches. Asks first, saying how many it found."""
    from estimator.estimating import service
    from estimator.plan_engine import symbols as engine_symbols
    from estimator.symbols import library
    _person(ctx, "find similar symbols")
    if detection_id:
        src = load_detections(conn, ctx, [detection_id])[0]
        sheet = _sheet(conn, ctx, src["sheet_id"])
        box = _box(src)
        it = src["item_type"]
        definition = ({"id": src["definition_id"], "trade": src["trade"], "description": src["label"]}
                      if src["definition_id"] else library.definition_for(conn, ctx.company_id, it) if it else
                      {"id": None, "trade": src["trade"], "description": src["label"]})
    else:
        if not sheet_id or not isinstance(box, (list, tuple)) or len(box) != 4:
            raise InvalidInput("give a detection_id, or a sheet_id and box [x0, y0, x1, y1] around the symbol")
        sheet = _sheet(conn, ctx, sheet_id)
        box = [float(v) for v in box]
        it = library.check_item_type(item_type) if item_type else None
        definition = library.definition_for(conn, ctx.company_id, it) if it else {"id": None, "trade": None,
                                                                                   "description": None}
    if (sheet["file_type"] or "").lower() not in ("pdf", "image"):
        raise InvalidInput("find similar works on PDF and image plans; CAD symbols are named from their block names")
    sheets = [dict(r) for r in conn.execute("SELECT id, page_no, width, height, image_path, plan_set_id FROM sheets"
                                            " WHERE plan_set_id = ? ORDER BY page_no", (sheet["plan_set_id"],))]
    for s in sheets:
        s["width"], s["height"] = float(s["width"] or 0), float(s["height"] or 0)
    # Like the plan engine's own scan, the legend's samples and the schedules aren't symbols on the drawing.
    page_of = {s["id"]: s["page_no"] for s in sheets}
    skip_by_page: dict[int, list] = {}
    for r in conn.execute("SELECT sheet_id, bbox_json FROM legends WHERE sheet_id IN (SELECT id FROM sheets WHERE"
                          " plan_set_id = ?) UNION ALL SELECT sheet_id, bbox_json FROM schedules WHERE sheet_id IN"
                          " (SELECT id FROM sheets WHERE plan_set_id = ?)", (sheet["plan_set_id"], sheet["plan_set_id"])):
        try:
            b = json.loads(r["bbox_json"]) if r["bbox_json"] else None
        except ValueError:
            b = None
        if isinstance(b, list) and len(b) == 4 and r["sheet_id"] in page_of:
            skip_by_page.setdefault(page_of[r["sheet_id"]], []).append([float(v) for v in b])
    try:
        got = engine_symbols.find_similar(sheet["file_path"], sheet["file_type"], sheets, sheet["page_no"], box,
                                          skip_by_page)
    except ImportError as exc:
        raise InvalidInput(f"symbol matching needs numpy and scipy ({exc})") from None
    if not got["kind"]:
        raise InvalidInput("there's no line work or picture in that box to search for; draw the box round the symbol")
    existing: dict[int, list] = {}
    for r in conn.execute("SELECT sheet_id, location_json FROM symbol_detections WHERE plan_set_id = ? AND status != 'rejected'",
                          (sheet["plan_set_id"],)):
        existing.setdefault(r["sheet_id"], []).append(json.loads(r["location_json"]).get("point"))
    page_to_sheet = {s["page_no"]: s for s in sheets}
    new = []
    radius = 0.15
    for page_no, hits in got["hits"].items():
        s = page_to_sheet[page_no]
        for h in hits:
            c = h["centre"]
            if any(q and math.hypot(c[0] - q[0], c[1] - q[1]) < radius for q in existing.get(s["id"], [])):
                continue
            new.append((s, h))
    per_sheet: dict[str, int] = {}
    for s, _ in new:
        per_sheet[str(s["page_no"])] = per_sheet.get(str(s["page_no"]), 0) + 1
    if not confirm:
        raise ConfirmationRequired(
            f"Found {len(new)} more like it on {len(per_sheet)} sheet(s). Add them as proposed matches"
            f"{' (' + it.replace('_', ' ') + ')' if it else ''}? Call again with confirm=true.",
            found=len(new), by_page=per_sheet, item_type=it)
    ids = []
    with service.transaction(conn):
        for s, h in new:
            s_full = {"id": s["id"], "plan_set_id": s["plan_set_id"]}
            vision = round(float(h["score"]), 3)
            ids.append(_new_detection(conn, ctx, s_full, h["centre"], item_type=it, definition=definition,
                                      method="vector" if got["kind"] == "vector" else "raster", origin="similar",
                                      scores={"legend": None, "vision": vision, "ocr": None, "ai": None, "cad": None},
                                      confidence=round(vision * 0.9, 3), status="proposed",
                                      bbox=[round(v, 4) for v in h["bbox"]], rotation=h.get("rotation"),
                                      mirrored=h.get("mirrored"), needs_review=True))
        service._log(conn, ctx, sheet["estimate_id"], "symbols_found_similar",
                     {"source_detection_id": detection_id, "added": len(ids), "item_type": it, "by_page": per_sheet})
    return {"ok": True, "added": len(ids), "detection_ids": ids, "by_page": per_sheet, "item_type": it}


# ---------------------------------------------------------------- thumbnails for the detection panel

def crop_png(conn, ctx: RequestContext, detection_id: int, data_dir: Path) -> Path:
    """A small picture of one detection cut from its sheet image (cached), for the Reviews thumbnail grid. Local
    only: nothing here is sent to an AI provider (that goes through drawing_model.crops.prepare)."""
    from PIL import Image
    d = load_detections(conn, ctx, [detection_id])[0]
    out_dir = Path(data_dir) / "symbol_crops"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{ctx.company_id}_{d['sheet_id']}_{d['id']}.png"
    if out.is_file():
        return out
    if not d["image_path"] or not Path(d["image_path"]).is_file():
        raise NotFound("this sheet has no picture", detection_id=detection_id)
    x0, y0, x1, y1 = _box(d, pad=0.12)
    with Image.open(d["image_path"]) as src:
        k = src.size[0] / float(d["width"])
        crop = src.crop((max(0, int(x0 * k)), max(0, int(y0 * k)), min(src.size[0], int(x1 * k)),
                         min(src.size[1], int(y1 * k)))).convert("RGB")
    crop.thumbnail((160, 160))
    crop.save(out, "PNG")
    return out
