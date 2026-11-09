"""The shared drawing model (spec: Blueprint processing, stage 8, and Data model).

A plan set is processed once; every trade reads the same sheets, viewports, drawing objects, schedules and legends.

Who writes what:
- The Estimator (this file) stores uploads, checks and saves the plan engine's results, measures every object in real
  units with the scale of the viewport it sits in, links schedule rows to the tags on the plans, and answers queries.
- The plan engine (Coder 2 track) reads the file and returns plain results; see estimator/drawing_model/engine.py for
  the exact format. It never touches the database, so it can be built and tested on its own.

Rules from the spec:
- Scale lives on the viewport, because one sheet often mixes scales. An object is measured with its own viewport's
  scale; NTS viewports and unscaled paper geometry are never measured (real_units stays empty, with the reason).
- A person can set a viewport's scale or calibrate it from two points; every object in that viewport is re-measured.
- Schedule rows link to plan tags by mark (door tag "D3" finds row D3). A corrected row is marked reviewed.
- Re-processing replaces the drawing model of that plan set; corrections to its schedules are lost, so it asks first.
"""
from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from decimal import Decimal

from estimator.context import RequestContext
from estimator.drawing_model import geometry as geo
from estimator.drawing_model import uploads
from estimator.errors import ConfirmationRequired, InvalidInput, NotFound, PermissionDenied
from estimator.estimating import service

UPLOAD_ROLES = ("owner", "estimator", "office")
EDIT_ROLES = service.EDIT_ROLES                      # owner, estimator: scales, schedule fixes, processing
DISCIPLINES = ("architectural", "structural", "plumbing", "electrical", "mechanical", "landscape", "roof", "site",
               "civil", "fire", "general", "other")
KINDS = ("line", "polyline", "polygon", "room", "wall", "opening", "symbol", "text", "dimension")
SOURCES = ("cad", "vector", "raster", "ai", "manual")
SCALE_METHODS = ("note", "bar", "dimension", "calibration", "cad", "ai", "manual", "none")
SCHEDULE_TYPES = ("door", "window", "finish", "plumbing", "lighting", "panel", "equipment", "wall-type", "other")
MAX_SHEETS = 2000
MAX_OBJECTS = 200000
MAX_TEXT = 300
MAX_FIELDS = 60
OBJECT_LIMIT = 1000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _role(ctx: RequestContext, roles, what: str) -> None:
    if ctx.role not in roles:
        raise PermissionDenied(f"only {', '.join(roles)} can {what}", role=ctx.role)


def _confirm(confirm: bool, message: str, **details) -> None:
    if not confirm:
        raise ConfirmationRequired(message + " Call again with confirm=true.", **details)


# ---------------------------------------------------------------- loading with company checks

def load_plan_set(conn, ctx: RequestContext, plan_set_id: int) -> dict:
    row = conn.execute("SELECT * FROM plan_sets WHERE id = ? AND company_id = ?",
                       (int(plan_set_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"plan set {plan_set_id} not found", plan_set_id=plan_set_id)
    return dict(row)


def _load_sheet(conn, ctx, sheet_id: int) -> dict:
    row = conn.execute("SELECT * FROM sheets WHERE id = ? AND company_id = ?", (int(sheet_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"sheet {sheet_id} not found", sheet_id=sheet_id)
    return dict(row)


def _load_viewport(conn, ctx, viewport_id: int) -> dict:
    row = conn.execute("SELECT * FROM viewports WHERE id = ? AND company_id = ?",
                       (int(viewport_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"viewport {viewport_id} not found", viewport_id=viewport_id)
    return dict(row)


# ---------------------------------------------------------------- upload

def upload(conn, ctx: RequestContext, estimate_id: int, file_path: str, supersedes_plan_set_id: int | None = None,
           confirm: bool = False) -> dict:
    """Attach a plan file (PDF, image, DXF, DWG) to an estimate after checking it. Asks first."""
    _role(ctx, UPLOAD_ROLES, "upload plans")
    est = service._load_row(conn, ctx, int(estimate_id))
    checked = uploads.check_file(file_path)
    dup = conn.execute("SELECT id FROM plan_sets WHERE company_id = ? AND estimate_id = ? AND sha256 = ?",
                       (ctx.company_id, est["id"], checked["sha256"])).fetchone()
    if dup:
        raise InvalidInput(f"{checked['name']} is already on this estimate as plan set {dup['id']}",
                           plan_set_id=dup["id"])
    revision, prev = 1, None
    if supersedes_plan_set_id:
        prev = load_plan_set(conn, ctx, int(supersedes_plan_set_id))
        if prev["estimate_id"] != est["id"]:
            raise InvalidInput("a revised plan set must replace one on the same estimate")
        revision = prev["revision"] + 1
    summary = {"file": checked["name"], "file_type": checked["file_type"],
               "size_mb": round(checked["size"] / (1024 * 1024), 2), "revision": revision,
               "warnings": checked["warnings"]}
    _confirm(confirm, f"Attach {checked['name']} ({checked['file_type'].upper()}, {summary['size_mb']} MB) to "
             f"estimate {est['id']}" + (f" as revision {revision} of plan set {prev['id']}" if prev else "") + "?",
             **summary)
    folder = uploads.plans_folder(est["id"])
    with service.transaction(conn):
        cur = conn.execute(
            "INSERT INTO plan_sets (company_id, estimate_id, file_path, original_name, file_type, file_size, sha256,"
            " revision, supersedes_plan_set_id, validation_json, uploaded_by, created_at)"
            " VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ctx.company_id, est["id"], checked["name"], checked["file_type"], checked["size"], checked["sha256"],
             revision, prev["id"] if prev else None, json.dumps({"warnings": checked["warnings"]}), ctx.actor,
             _now()))
        plan_set_id = cur.lastrowid
        dest = folder / uploads.stored_name(plan_set_id, checked["name"])
        try:
            shutil.copy2(checked["path"], dest)
        except OSError as exc:
            raise InvalidInput(f"the file couldn't be copied into the Estimator's folder: {exc}") from None
        conn.execute("UPDATE plan_sets SET file_path = ? WHERE id = ?", (str(dest), plan_set_id))
        service._log(conn, ctx, est["id"], "plan_uploaded",
                     {"plan_set_id": plan_set_id, "file": checked["name"], "revision": revision})
    return {"ok": True, "plan_set_id": plan_set_id, "estimate_id": est["id"], "status": "uploaded", **summary,
            "next": "plan_process to read the sheets (needs the plan engine), then plan_get_sheets"}


def list_plan_sets(conn, ctx: RequestContext, estimate_id: int) -> dict:
    service._load_row(conn, ctx, int(estimate_id))
    rows = [_plan_set_out(conn, dict(r)) for r in conn.execute(
        "SELECT * FROM plan_sets WHERE company_id = ? AND estimate_id = ? ORDER BY id", (ctx.company_id,
                                                                                      int(estimate_id)))]
    return {"ok": True, "estimate_id": int(estimate_id), "count": len(rows), "plan_sets": rows}


def _plan_set_out(conn, ps: dict) -> dict:
    counts = conn.execute(
        "SELECT COUNT(DISTINCT s.id) AS sheets, COUNT(DISTINCT v.id) AS viewports FROM sheets s"
        " LEFT JOIN viewports v ON v.sheet_id = s.id WHERE s.plan_set_id = ?", (ps["id"],)).fetchone()
    objects = conn.execute("SELECT COUNT(*) FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id"
                           " WHERE s.plan_set_id = ?", (ps["id"],)).fetchone()[0]
    return {"id": ps["id"], "estimate_id": ps["estimate_id"], "file": ps["original_name"], "file_type": ps["file_type"],
            "revision": ps["revision"], "supersedes_plan_set_id": ps["supersedes_plan_set_id"],
            "status": ps["status"], "error": ps["error"], "engine": ps["engine"], "page_count": ps["page_count"],
            "sheets": counts["sheets"], "viewports": counts["viewports"], "objects": objects,
            "warnings": json.loads(ps["validation_json"] or "{}").get("warnings", []),
            "uploaded_by": ps["uploaded_by"], "created_at": ps["created_at"], "processed_at": ps["processed_at"]}


def status(conn, ctx: RequestContext, plan_set_id: int) -> dict:
    ps = load_plan_set(conn, ctx, plan_set_id)
    out = _plan_set_out(conn, ps)
    unscaled = [s["id"] for s in sheets(conn, ctx, ps["id"])["sheets"] if s["needs_scale"]]
    say = {"uploaded": "Uploaded, not read yet. Start it with plan_process.",
           "processing": "The plan engine is reading the sheets.",
           "processed": f"Read: {out['sheets']} sheet(s), {out['objects']} object(s).",
           "failed": f"Reading failed: {ps['error']}"}[ps["status"]]
    if ps["status"] == "processed" and unscaled:
        say += f" {len(unscaled)} sheet(s) need a scale before measuring (plan_set_scale)."
    return {"ok": True, **out, "sheets_needing_scale": unscaled, "say": say}


# ---------------------------------------------------------------- the plan engine's results

def _text(value, field: str, required: bool = False) -> str | None:
    if value is None or value == "":
        if required:
            raise InvalidInput(f"{field} is required", field=field)
        return None
    if not isinstance(value, (str, int, float)):
        raise InvalidInput(f"{field} must be text", field=field)
    text = str(value).strip()
    if len(text) > MAX_TEXT:
        raise InvalidInput(f"{field} is longer than {MAX_TEXT} characters", field=field)
    return text or None


def _confidence(value, field: str) -> str | None:
    if value is None or value == "":
        return None
    d = geo.dec(value, field)
    if d < 0 or d > 1:
        raise InvalidInput(f"{field} must be between 0 and 1", field=field)
    return str(d)


def _bbox(value, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        raise InvalidInput(f"{field} must be [x0, y0, x1, y1]", field=field)
    nums = [geo.dec(v, field) for v in value]
    return json.dumps([int(n) if n == n.to_integral_value() else float(n) for n in nums])


def _check_results(results) -> list[dict]:
    """Validate everything before anything is written, so a bad result never leaves half a drawing model."""
    if not isinstance(results, dict) or not isinstance(results.get("sheets"), list):
        raise InvalidInput("plan engine results must be an object with a 'sheets' list")
    sheets_in = results["sheets"]
    if len(sheets_in) > MAX_SHEETS:
        raise InvalidInput(f"a plan set can have at most {MAX_SHEETS} sheets")
    total_objects, pages, out = 0, set(), []
    for si, s in enumerate(sheets_in):
        where = f"sheets[{si}]"
        if not isinstance(s, dict):
            raise InvalidInput(f"{where} must be an object")
        page = s.get("page_no")
        if not isinstance(page, int) or isinstance(page, bool) or page < 1:
            raise InvalidInput(f"{where}.page_no must be a whole number from 1", field=f"{where}.page_no")
        if page in pages:
            raise InvalidInput(f"page {page} appears twice", field=f"{where}.page_no")
        pages.add(page)
        discipline = (s.get("discipline") or "other").strip().lower()
        if discipline not in DISCIPLINES:
            raise InvalidInput(f"{where}.discipline must be one of {', '.join(DISCIPLINES)}", field=f"{where}.discipline")
        units = (s.get("units") or "paper_in").strip().lower()
        if units not in geo.SHEET_UNITS:
            raise InvalidInput(f"{where}.units must be one of {', '.join(geo.SHEET_UNITS)}", field=f"{where}.units")
        sheet = {"page_no": page, "sheet_no": _text(s.get("sheet_no"), f"{where}.sheet_no"),
                 "title": _text(s.get("title"), f"{where}.title"), "discipline": discipline,
                 "revision": _text(s.get("revision"), f"{where}.revision"),
                 "revision_date": _text(s.get("revision_date"), f"{where}.revision_date"), "units": units,
                 "width": str(geo.dec(s["width"], f"{where}.width")) if s.get("width") is not None else None,
                 "height": str(geo.dec(s["height"], f"{where}.height")) if s.get("height") is not None else None,
                 "image_path": _text(s.get("image_path"), f"{where}.image_path"),
                 "confidence": _confidence(s.get("confidence"), f"{where}.confidence"),
                 "viewports": [], "objects": [], "schedules": [], "legends": []}
        keys = set()
        for vi, v in enumerate(s.get("viewports") or []):
            vw = f"{where}.viewports[{vi}]"
            if not isinstance(v, dict):
                raise InvalidInput(f"{vw} must be an object")
            key = _text(v.get("key"), f"{vw}.key", required=True)
            if key in keys:
                raise InvalidInput(f"viewport key '{key}' appears twice on page {page}", field=f"{vw}.key")
            keys.add(key)
            ratio, is_nts, note = None, bool(v.get("is_nts")), _text(v.get("scale_note"), f"{vw}.scale_note")
            if note:
                ratio, nts_from_note = geo.parse_scale(note)
                is_nts = is_nts or nts_from_note
            if v.get("scale_ratio") not in (None, ""):
                ratio = geo.dec(v["scale_ratio"], f"{vw}.scale_ratio")
                if ratio <= 0:
                    raise InvalidInput(f"{vw}.scale_ratio must be more than zero", field=f"{vw}.scale_ratio")
            method = (v.get("scale_method") or ("note" if note else "none")).strip().lower()
            if method not in SCALE_METHODS:
                raise InvalidInput(f"{vw}.scale_method must be one of {', '.join(SCALE_METHODS)}",
                                   field=f"{vw}.scale_method")
            sheet["viewports"].append({
                "key": key, "label": _text(v.get("label"), f"{vw}.label"), "bbox_json": _bbox(v.get("bbox"),
                                                                                               f"{vw}.bbox"),
                "scale_note": note, "scale_ratio": None if is_nts or ratio is None else ratio, "is_nts": is_nts,
                "scale_method": method, "scale_confidence": _confidence(v.get("scale_confidence"),
                                                                        f"{vw}.scale_confidence")})
        for oi, o in enumerate(s.get("objects") or []):
            ow = f"{where}.objects[{oi}]"
            if not isinstance(o, dict):
                raise InvalidInput(f"{ow} must be an object")
            kind = o.get("kind")
            if kind not in KINDS:
                raise InvalidInput(f"{ow}.kind must be one of {', '.join(KINDS)}", field=f"{ow}.kind")
            source = o.get("source")
            if source not in SOURCES:
                raise InvalidInput(f"{ow}.source must be one of {', '.join(SOURCES)}", field=f"{ow}.source")
            vkey = _text(o.get("viewport"), f"{ow}.viewport")
            if vkey is not None and vkey not in keys:
                raise InvalidInput(f"{ow}.viewport '{vkey}' isn't a viewport on page {page}", field=f"{ow}.viewport")
            sheet["objects"].append({
                "viewport": vkey, "kind": kind, "geometry": geo.check_geometry(o.get("geometry")),
                "layer": _text(o.get("layer"), f"{ow}.layer"), "block_name": _text(o.get("block_name"),
                                                                                   f"{ow}.block_name"),
                "label": _text(o.get("label"), f"{ow}.label"), "tag": _text(o.get("tag"), f"{ow}.tag"),
                "source": source, "confidence": _confidence(o.get("confidence"), f"{ow}.confidence")})
        total_objects += len(sheet["objects"])
        if total_objects > MAX_OBJECTS:
            raise InvalidInput(f"a plan set can have at most {MAX_OBJECTS} drawing objects")
        for ci, sc in enumerate(s.get("schedules") or []):
            cw = f"{where}.schedules[{ci}]"
            if not isinstance(sc, dict):
                raise InvalidInput(f"{cw} must be an object")
            stype = (sc.get("schedule_type") or "").strip().lower()
            if stype not in SCHEDULE_TYPES:
                raise InvalidInput(f"{cw}.schedule_type must be one of {', '.join(SCHEDULE_TYPES)}",
                                   field=f"{cw}.schedule_type")
            rows = []
            for ri, r in enumerate(sc.get("rows") or []):
                rw = f"{cw}.rows[{ri}]"
                if not isinstance(r, dict):
                    raise InvalidInput(f"{rw} must be an object")
                rows.append({"mark": _text(r.get("mark"), f"{rw}.mark"), "fields": _fields(r.get("fields"), rw),
                             "confidence": _confidence(r.get("confidence"), f"{rw}.confidence")})
            sheet["schedules"].append({"schedule_type": stype, "title": _text(sc.get("title"), f"{cw}.title"),
                                       "bbox_json": _bbox(sc.get("bbox"), f"{cw}.bbox"),
                                       "confidence": _confidence(sc.get("confidence"), f"{cw}.confidence"),
                                       "rows": rows})
        for li, lg in enumerate(s.get("legends") or []):
            lw = f"{where}.legends[{li}]"
            if not isinstance(lg, dict):
                raise InvalidInput(f"{lw} must be an object")
            d = (lg.get("discipline") or "").strip().lower() or None
            if d is not None and d not in DISCIPLINES:
                raise InvalidInput(f"{lw}.discipline must be one of {', '.join(DISCIPLINES)}", field=f"{lw}.discipline")
            sheet["legends"].append({"discipline": d, "title": _text(lg.get("title"), f"{lw}.title"),
                                     "bbox_json": _bbox(lg.get("bbox"), f"{lw}.bbox"),
                                     "confidence": _confidence(lg.get("confidence"), f"{lw}.confidence")})
        out.append(sheet)
    return out


def _fields(value, where: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise InvalidInput(f"{where}.fields must be an object", field=f"{where}.fields")
    if len(value) > MAX_FIELDS:
        raise InvalidInput(f"{where}.fields can have at most {MAX_FIELDS} columns", field=f"{where}.fields")
    out = {}
    for k, v in value.items():
        key = _text(k, f"{where}.fields key", required=True)
        if v is not None and not isinstance(v, (str, int, float, bool)):
            raise InvalidInput(f"{where}.fields['{key}'] must be text, a number or true/false", field=f"{where}.fields")
        out[key] = v.strip()[:MAX_TEXT] if isinstance(v, str) else v
    return out


def _real_units(units: str, viewport: dict | None, geometry: dict) -> str | None:
    if units == "paper_in":
        if viewport is None:
            return None
        ratio = Decimal(viewport["scale_ratio"]) if viewport["scale_ratio"] else None
        factor = geo.feet_per_unit(units, ratio, bool(viewport["is_nts"]))
    else:
        factor = geo.feet_per_unit(units, None, False)
    measured = geo.measure(geometry, factor)
    return None if measured is None else json.dumps(measured)


def save_results(conn, ctx: RequestContext, plan_set_id: int, results: dict, engine_name: str = "") -> dict:
    """Check the plan engine's results and replace this plan set's drawing model with them, in one transaction."""
    ps = load_plan_set(conn, ctx, plan_set_id)
    checked = _check_results(results)
    page_count = results.get("page_count")
    if page_count is not None and (not isinstance(page_count, int) or isinstance(page_count, bool) or page_count < 0):
        raise InvalidInput("page_count must be a whole number")
    counts = {"sheets": 0, "viewports": 0, "objects": 0, "measured": 0, "schedules": 0, "schedule_rows": 0,
              "linked_rows": 0, "legends": 0}
    company = ctx.company_id
    with service.transaction(conn):
        from estimator.takeoff import measurements
        reread = measurements.plan_set_reread(conn, ctx, ps["id"])            # approved ones are flagged, never lost
        conn.execute("DELETE FROM sheets WHERE plan_set_id = ?", (ps["id"],))     # cascades to everything below
        for s in checked:
            sheet_id = conn.execute(
                "INSERT INTO sheets (company_id, plan_set_id, page_no, sheet_no, title, discipline, revision,"
                " revision_date, units, width, height, image_path, confidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (company, ps["id"], s["page_no"], s["sheet_no"], s["title"], s["discipline"], s["revision"],
                 s["revision_date"], s["units"], s["width"], s["height"], s["image_path"], s["confidence"])).lastrowid
            counts["sheets"] += 1
            vp_rows = {}
            for v in s["viewports"]:
                vid = conn.execute(
                    "INSERT INTO viewports (company_id, sheet_id, label, bbox_json, scale_note, scale_ratio,"
                    " scale_method, scale_confidence, is_nts) VALUES (?,?,?,?,?,?,?,?,?)",
                    (company, sheet_id, v["label"], v["bbox_json"], v["scale_note"],
                     str(v["scale_ratio"]) if v["scale_ratio"] is not None else None, v["scale_method"],
                     v["scale_confidence"], int(v["is_nts"]))).lastrowid
                vp_rows[v["key"]] = {"id": vid, "scale_ratio": str(v["scale_ratio"]) if v["scale_ratio"] else None,
                                     "is_nts": v["is_nts"]}
                counts["viewports"] += 1
            for o in s["objects"]:
                vp = vp_rows.get(o["viewport"]) if o["viewport"] else None
                real = _real_units(s["units"], vp, o["geometry"])
                conn.execute(
                    "INSERT INTO drawing_objects (company_id, sheet_id, viewport_id, kind, geometry_json,"
                    " real_units_json, layer, block_name, label, tag, source, confidence)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (company, sheet_id, vp["id"] if vp else None, o["kind"],
                     json.dumps(geo.to_json_geometry(o["geometry"])), real, o["layer"], o["block_name"], o["label"],
                     o["tag"], o["source"], o["confidence"]))
                counts["objects"] += 1
                counts["measured"] += real is not None and real != "{}"
            for sc in s["schedules"]:
                sid = conn.execute(
                    "INSERT INTO schedules (company_id, sheet_id, schedule_type, title, bbox_json, confidence)"
                    " VALUES (?,?,?,?,?,?)", (company, sheet_id, sc["schedule_type"], sc["title"], sc["bbox_json"],
                                              sc["confidence"])).lastrowid
                counts["schedules"] += 1
                for r in sc["rows"]:
                    conn.execute("INSERT INTO schedule_rows (company_id, schedule_id, mark, fields_json, confidence)"
                                 " VALUES (?,?,?,?,?)", (company, sid, r["mark"], json.dumps(r["fields"]),
                                                         r["confidence"]))
                    counts["schedule_rows"] += 1
            for lg in s["legends"]:
                conn.execute("INSERT INTO legends (company_id, sheet_id, discipline, title, bbox_json, confidence)"
                             " VALUES (?,?,?,?,?,?)", (company, sheet_id, lg["discipline"], lg["title"],
                                                       lg["bbox_json"], lg["confidence"]))
                counts["legends"] += 1
        counts["linked_rows"] = _link_rows(conn, ps["id"])
        conn.execute("UPDATE plan_sets SET status = 'processed', error = NULL, processed_at = ?, engine = ?,"
                     " page_count = COALESCE(?, page_count, ?) WHERE id = ?",
                     (_now(), engine_name or None, page_count, counts["sheets"], ps["id"]))
        service._log(conn, ctx, ps["estimate_id"], "plan_processed", {"plan_set_id": ps["id"], **counts})
    return {"ok": True, "plan_set_id": ps["id"], "status": "processed", **counts,
            "measurements": reread}


def _link_rows(conn, plan_set_id: int, only_row_id: int | None = None) -> int:
    """Link schedule rows to plan objects whose tag equals the row's mark (same plan set, case and spaces ignored)."""
    tags: dict[str, list[int]] = {}
    for r in conn.execute("SELECT o.id, o.tag FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id"
                          " WHERE s.plan_set_id = ? AND o.tag IS NOT NULL ORDER BY o.id", (plan_set_id,)):
        tags.setdefault(_norm(r["tag"]), []).append(r["id"])
    sql = ("SELECT r.id, r.mark FROM schedule_rows r JOIN schedules c ON c.id = r.schedule_id"
           " JOIN sheets s ON s.id = c.sheet_id WHERE s.plan_set_id = ?")
    args = [plan_set_id]
    if only_row_id is not None:
        sql += " AND r.id = ?"
        args.append(only_row_id)
    linked = 0
    for r in conn.execute(sql, args).fetchall():
        ids = tags.get(_norm(r["mark"]), []) if r["mark"] else []
        conn.execute("UPDATE schedule_rows SET linked_object_ids = ? WHERE id = ?", (json.dumps(ids), r["id"]))
        linked += bool(ids)
    return linked


def _norm(text: str | None) -> str:
    return "".join((text or "").split()).upper()


def mark_processing(conn, ctx: RequestContext, plan_set_id: int, engine_name: str) -> None:
    conn.execute("UPDATE plan_sets SET status = 'processing', error = NULL, engine = ? WHERE id = ? AND company_id = ?",
                 (engine_name, int(plan_set_id), ctx.company_id))


def mark_failed(conn, ctx: RequestContext, plan_set_id: int, reason: str) -> None:
    conn.execute("UPDATE plan_sets SET status = 'failed', error = ? WHERE id = ? AND company_id = ?",
                 (str(reason)[:500], int(plan_set_id), ctx.company_id))


# ---------------------------------------------------------------- reading the drawing model

def _vp_out(v: dict) -> dict:
    return {"id": v["id"], "sheet_id": v["sheet_id"], "label": v["label"],
            "bbox": json.loads(v["bbox_json"]) if v["bbox_json"] else None, "scale_note": v["scale_note"],
            "scale_ratio": v["scale_ratio"], "scale_method": v["scale_method"],
            "scale_confidence": v["scale_confidence"], "is_nts": bool(v["is_nts"]),
            "measurable": bool(v["scale_ratio"]) and not v["is_nts"], "scale_set_by": v["scale_set_by"]}


def sheets(conn, ctx: RequestContext, plan_set_id: int, discipline: str | None = None) -> dict:
    ps = load_plan_set(conn, ctx, plan_set_id)
    sql, args = "SELECT * FROM sheets WHERE plan_set_id = ?", [ps["id"]]
    if discipline:
        sql += " AND discipline = ?"
        args.append(discipline.strip().lower())
    out = []
    for s in conn.execute(sql + " ORDER BY page_no", args).fetchall():
        vps = [_vp_out(dict(v)) for v in conn.execute("SELECT * FROM viewports WHERE sheet_id = ? ORDER BY id",
                                                     (s["id"],))]
        n_objects = conn.execute("SELECT COUNT(*) FROM drawing_objects WHERE sheet_id = ?", (s["id"],)).fetchone()[0]
        paper = s["units"] == "paper_in"
        needs = paper and (not vps or any(not v["measurable"] and not v["is_nts"] for v in vps))
        out.append({"id": s["id"], "page_no": s["page_no"], "sheet_no": s["sheet_no"], "title": s["title"],
                    "discipline": s["discipline"], "revision": s["revision"], "revision_date": s["revision_date"],
                    "units": s["units"], "has_image": bool(s["image_path"]), "objects": n_objects,
                    "viewports": [{k: v[k] for k in ("id", "label", "scale_note", "scale_ratio", "is_nts",
                                                     "measurable")} for v in vps],
                    "needs_scale": bool(needs)})
    return {"ok": True, "plan_set_id": ps["id"], "status": ps["status"], "count": len(out), "sheets": out}


def sheet_image(conn, ctx: RequestContext, sheet_id: int) -> dict:
    from pathlib import Path
    s = _load_sheet(conn, ctx, sheet_id)
    path = Path(s["image_path"]) if s["image_path"] else None
    if path is None or not path.is_file():
        return {"ok": False, "error": "not_available", "sheet_id": s["id"],
                "message": "this sheet has no rendered image yet; the plan engine makes one when it reads the plans"}
    return {"ok": True, "sheet_id": s["id"], "sheet_no": s["sheet_no"], "path": str(path),
            "size_kb": round(path.stat().st_size / 1024, 1)}


def viewports(conn, ctx: RequestContext, sheet_id: int) -> dict:
    s = _load_sheet(conn, ctx, sheet_id)
    vps = [_vp_out(dict(v)) for v in conn.execute("SELECT * FROM viewports WHERE sheet_id = ? ORDER BY id",
                                                  (s["id"],))]
    return {"ok": True, "sheet_id": s["id"], "sheet_no": s["sheet_no"], "units": s["units"], "count": len(vps),
            "viewports": vps}


def _obj_out(r: dict, units: str, vp: dict | None, include_geometry: bool) -> dict:
    real = json.loads(r["real_units_json"]) if r["real_units_json"] else None
    out = {"id": r["id"], "sheet_id": r["sheet_id"], "viewport_id": r["viewport_id"], "kind": r["kind"],
           "layer": r["layer"], "block_name": r["block_name"], "label": r["label"], "tag": r["tag"],
           "source": r["source"], "confidence": r["confidence"], "real_units": real}
    if real is None:
        if vp is None:
            out["not_measured"] = "not inside a viewport, so its scale is unknown"
        elif vp["is_nts"]:
            out["not_measured"] = "its viewport is marked NTS (not to scale)"
        else:
            out["not_measured"] = "its viewport has no scale yet; set one with plan_set_scale"
    if include_geometry:
        out["geometry"] = json.loads(r["geometry_json"])
    return out


def _intersects(geom: dict, box: list) -> bool:
    xs = [p[0] for p in geom["points"]]
    ys = [p[1] for p in geom["points"]]
    x0, y0, x1, y1 = min(box[0], box[2]), min(box[1], box[3]), max(box[0], box[2]), max(box[1], box[3])
    return not (max(xs) < x0 or min(xs) > x1 or max(ys) < y0 or min(ys) > y1)


def objects(conn, ctx: RequestContext, plan_set_id: int | None = None, sheet_id: int | None = None,
            kind: str | None = None, layer: str | None = None, tag: str | None = None,
            viewport_id: int | None = None, area: list | None = None, include_geometry: bool = False,
            limit: int = 200, offset: int = 0) -> dict:
    """Query the drawing model by plan set or sheet, kind, layer, tag, viewport or an area of the sheet."""
    if not plan_set_id and not sheet_id:
        raise InvalidInput("give a plan_set_id or a sheet_id")
    sql = ("SELECT o.*, s.units, s.plan_set_id FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id"
           " WHERE o.company_id = ?")
    args: list = [ctx.company_id]
    if sheet_id:
        s = _load_sheet(conn, ctx, sheet_id)
        sql += " AND o.sheet_id = ?"
        args.append(s["id"])
    if plan_set_id:
        ps = load_plan_set(conn, ctx, plan_set_id)
        sql += " AND s.plan_set_id = ?"
        args.append(ps["id"])
    if kind:
        kinds = [k.strip() for k in str(kind).split(",") if k.strip()]
        bad = [k for k in kinds if k not in KINDS]
        if bad:
            raise InvalidInput(f"kind must be one of {', '.join(KINDS)}", field="kind")
        sql += f" AND o.kind IN ({','.join('?' for _ in kinds)})"
        args += kinds
    if layer:
        sql += " AND o.layer = ?"
        args.append(layer)
    if tag:
        sql += " AND REPLACE(UPPER(o.tag), ' ', '') = ?"
        args.append(_norm(tag))
    if viewport_id:
        sql += " AND o.viewport_id = ?"
        args.append(int(viewport_id))
    box = None
    if area is not None:
        box = [float(geo.dec(v, "area")) for v in area] if isinstance(area, (list, tuple)) and len(area) == 4 else None
        if box is None:
            raise InvalidInput("area must be [x0, y0, x1, y1] on the sheet", field="area")
        if not sheet_id:
            raise InvalidInput("an area only makes sense on one sheet; give sheet_id too", field="area")
    limit = max(1, min(int(limit), OBJECT_LIMIT))
    rows = [dict(r) for r in conn.execute(sql + " ORDER BY o.sheet_id, o.id", args)]
    if box is not None:
        rows = [r for r in rows if _intersects(json.loads(r["geometry_json"]), box)]
    totals: dict[str, dict] = {}
    for r in rows:
        t = totals.setdefault(r["kind"], {"count": 0, "measured": 0, "area_sqft": Decimal(0),
                                          "length_ft": Decimal(0)})
        t["count"] += 1
        real = json.loads(r["real_units_json"]) if r["real_units_json"] else None
        if real:
            t["measured"] += 1
            t["area_sqft"] += Decimal(real.get("area_sqft", "0"))
            t["length_ft"] += Decimal(real.get("length_ft", "0"))
    page = rows[int(offset):int(offset) + limit]
    vp_ids = sorted({r["viewport_id"] for r in page if r["viewport_id"]})
    vps = {v["id"]: dict(v) for v in conn.execute(
        f"SELECT * FROM viewports WHERE id IN ({','.join('?' for _ in vp_ids)})", vp_ids)} if vp_ids else {}
    return {"ok": True, "count": len(rows), "returned": len(page), "offset": int(offset),
            "totals": {k: {"count": v["count"], "measured": v["measured"], "area_sqft": geo.q(v["area_sqft"]),
                           "length_ft": geo.q(v["length_ft"])} for k, v in totals.items()},
            "objects": [_obj_out(r, r["units"], vps.get(r["viewport_id"]), include_geometry) for r in page]}


def schedules(conn, ctx: RequestContext, plan_set_id: int, schedule_type: str | None = None) -> dict:
    ps = load_plan_set(conn, ctx, plan_set_id)
    sql = ("SELECT c.*, s.sheet_no, s.page_no FROM schedules c JOIN sheets s ON s.id = c.sheet_id"
           " WHERE s.plan_set_id = ?")
    args = [ps["id"]]
    if schedule_type:
        sql += " AND c.schedule_type = ?"
        args.append(schedule_type.strip().lower())
    out = []
    for c in conn.execute(sql + " ORDER BY s.page_no, c.id", args).fetchall():
        rows = [{"id": r["id"], "mark": r["mark"], "fields": json.loads(r["fields_json"]),
                 "linked_object_ids": json.loads(r["linked_object_ids"]), "confidence": r["confidence"],
                 "reviewed_by": r["reviewed_by"]}
                for r in conn.execute("SELECT * FROM schedule_rows WHERE schedule_id = ? ORDER BY id", (c["id"],))]
        out.append({"id": c["id"], "sheet_id": c["sheet_id"], "sheet_no": c["sheet_no"], "page_no": c["page_no"],
                    "schedule_type": c["schedule_type"], "title": c["title"], "confidence": c["confidence"],
                    "rows": rows, "unlinked_marks": [r["mark"] for r in rows if r["mark"]
                                                     and not r["linked_object_ids"]]})
    return {"ok": True, "plan_set_id": ps["id"], "count": len(out), "schedules": out}


def legends(conn, ctx: RequestContext, plan_set_id: int) -> dict:
    ps = load_plan_set(conn, ctx, plan_set_id)
    out = [{"id": r["id"], "sheet_id": r["sheet_id"], "sheet_no": r["sheet_no"], "discipline": r["discipline"],
            "title": r["title"], "bbox": json.loads(r["bbox_json"]) if r["bbox_json"] else None,
            "confidence": r["confidence"]}
           for r in conn.execute("SELECT l.*, s.sheet_no FROM legends l JOIN sheets s ON s.id = l.sheet_id"
                                 " WHERE s.plan_set_id = ? ORDER BY s.page_no, l.id", (ps["id"],))]
    entries = _symbol_dictionary(conn, ps["id"])
    if entries is None:
        return {"ok": True, "plan_set_id": ps["id"], "count": len(out), "legends": out,
                "symbol_dictionary": None, "note": "no symbol dictionary yet: the plan engine builds one from the "
                                                   "legends when it reads the plans"}
    return {"ok": True, "plan_set_id": ps["id"], "count": len(out), "legends": out, "symbol_dictionary": entries,
            "note": "dictionary entries were read from the legends; ones marked needs_confirming want a person"}


def _symbol_dictionary(conn, plan_set_id: int) -> list[dict] | None:
    """The plan engine's symbol dictionary (Sprint 9, Coder 2): symbol_dictionary.json beside the sheet images, until
    the spec's symbol_definitions table exists. Entries: {sheet_no, legend, code, description, item_type, trade,
    has_symbol, confidence, needs_confirming}."""
    from pathlib import Path
    r = conn.execute("SELECT image_path FROM sheets WHERE plan_set_id = ? AND image_path IS NOT NULL ORDER BY page_no"
                     " LIMIT 1", (plan_set_id,)).fetchone()
    if not r or not r["image_path"]:
        return None
    path = Path(r["image_path"]).parent / "symbol_dictionary.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    keep = ("code", "description", "item_type", "trade", "has_symbol", "confidence", "needs_confirming")
    return [{"sheet_no": lg.get("sheet_no"), "legend": lg.get("title"), **{k: e.get(k) for k in keep}}
            for lg in data.get("legends", []) for e in lg.get("entries", [])][:2000]


# ---------------------------------------------------------------- corrections by a person

def set_scale(conn, ctx: RequestContext, viewport_id: int, scale_note: str | None = None,
              scale_ratio=None, calibration: dict | None = None, confirm: bool = False) -> dict:
    """Set a viewport's scale from a note (1/4" = 1'-0"), a ratio (48) or two points and a real distance, then
    re-measure every object in it. NTS marks it not-to-scale (nothing in it is measured)."""
    _role(ctx, EDIT_ROLES, "set plan scales")
    vp = _load_viewport(conn, ctx, viewport_id)
    sheet = _load_sheet(conn, ctx, vp["sheet_id"])
    given = [x for x in (scale_note, scale_ratio, calibration) if x not in (None, "", {})]
    if len(given) != 1:
        raise InvalidInput("give exactly one of scale_note, scale_ratio or calibration")
    is_nts, method = False, "manual"
    if scale_note:
        ratio, is_nts = geo.parse_scale(scale_note)
        method = "note"
    elif scale_ratio not in (None, ""):
        ratio = geo.dec(scale_ratio, "scale_ratio")
        if ratio <= 0:
            raise InvalidInput("scale_ratio must be more than zero", field="scale_ratio")
    else:
        if not isinstance(calibration, dict):
            raise InvalidInput("calibration must be {\"p1\": [x, y], \"p2\": [x, y], \"distance\": \"12'-6\\\"\"}")
        ratio = geo.calibrate(calibration.get("p1"), calibration.get("p2"), calibration.get("distance"))
        method = "calibration"
    if sheet["units"] != "paper_in":
        raise InvalidInput(f"sheet {sheet['sheet_no'] or sheet['page_no']} is a CAD drawing in real {sheet['units']}; "
                           "it doesn't need a scale")
    n = conn.execute("SELECT COUNT(*) FROM drawing_objects WHERE viewport_id = ?", (vp["id"],)).fetchone()[0]
    label = vp["label"] or f"viewport {vp['id']}"
    what = "not to scale (NTS)" if is_nts else f"1 paper inch = {geo.q(ratio)} real inches"
    _confirm(confirm, f"Set {label} on sheet {sheet['sheet_no'] or sheet['page_no']} to {what} and re-measure its "
             f"{n} object(s)?", viewport_id=vp["id"], scale_ratio=None if is_nts else geo.q(ratio), is_nts=is_nts,
             objects=n)
    new_ratio = None if is_nts else str(ratio.normalize() if ratio == ratio.to_integral_value() else ratio)
    with service.transaction(conn):
        conn.execute("UPDATE viewports SET scale_ratio = ?, is_nts = ?, scale_method = ?, scale_confidence = '1',"
                     " scale_note = COALESCE(?, scale_note), scale_set_by = ?, scale_set_at = ? WHERE id = ?",
                     (new_ratio, int(is_nts), method, scale_note if scale_note else None, ctx.actor, _now(), vp["id"]))
        vp_now = {"scale_ratio": new_ratio, "is_nts": is_nts}
        measured = 0
        changed = []
        for o in conn.execute("SELECT id, geometry_json FROM drawing_objects WHERE viewport_id = ?",
                              (vp["id"],)).fetchall():
            changed.append(o["id"])
            g = geo.check_geometry(json.loads(o["geometry_json"]))
            real = _real_units(sheet["units"], vp_now, g)
            conn.execute("UPDATE drawing_objects SET real_units_json = ? WHERE id = ?", (real, o["id"]))
            measured += real is not None and real != "{}"
        from estimator.takeoff import measurements
        affected = measurements.objects_changed(conn, ctx, changed)
        ps = load_plan_set(conn, ctx, sheet["plan_set_id"])
        service._log(conn, ctx, ps["estimate_id"], "plan_scale_set",
                     {"viewport_id": vp["id"], "scale_ratio": new_ratio, "is_nts": is_nts, "method": method})
    return {"ok": True, "viewport": _vp_out(_load_viewport(conn, ctx, vp["id"])), "objects": n, "measured": measured,
            "measurements": affected}


def update_schedule_row(conn, ctx: RequestContext, row_id: int, fields: dict | None = None, mark: str | None = None,
                        confirm: bool = False) -> dict:
    """Correct a schedule row read from the plans (its mark or some of its columns). The row is marked reviewed."""
    _role(ctx, EDIT_ROLES, "correct schedules")
    row = conn.execute("SELECT r.*, s.plan_set_id FROM schedule_rows r JOIN schedules c ON c.id = r.schedule_id"
                       " JOIN sheets s ON s.id = c.sheet_id WHERE r.id = ? AND r.company_id = ?",
                       (int(row_id), ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"schedule row {row_id} not found", row_id=row_id)
    if fields is None and mark is None:
        raise InvalidInput("give the corrected fields and/or mark")
    current = json.loads(row["fields_json"])
    changes = _fields(fields, "fields") if fields is not None else {}
    new_fields = {**current, **changes}
    new_mark = _text(mark, "mark") if mark is not None else row["mark"]
    _confirm(confirm, f"Change schedule row {row['mark'] or row['id']}"
             + (f" to mark {new_mark}" if new_mark != row["mark"] else "")
             + (f": {', '.join(f'{k} = {v}' for k, v in changes.items())}" if changes else "") + "?",
             row_id=row["id"], before={"mark": row["mark"], "fields": current},
             after={"mark": new_mark, "fields": new_fields})
    with service.transaction(conn):
        conn.execute("UPDATE schedule_rows SET mark = ?, fields_json = ?, confidence = '1', reviewed_by = ?,"
                     " reviewed_at = ? WHERE id = ?", (new_mark, json.dumps(new_fields), ctx.actor, _now(), row["id"]))
        _link_rows(conn, row["plan_set_id"], only_row_id=row["id"])
        ps = load_plan_set(conn, ctx, row["plan_set_id"])
        service._log(conn, ctx, ps["estimate_id"], "schedule_row_corrected",
                     {"row_id": row["id"], "mark": new_mark, "fields": changes},
                     before={"mark": row["mark"], "fields": current})
    r = conn.execute("SELECT * FROM schedule_rows WHERE id = ?", (row["id"],)).fetchone()
    return {"ok": True, "row": {"id": r["id"], "mark": r["mark"], "fields": json.loads(r["fields_json"]),
                                "linked_object_ids": json.loads(r["linked_object_ids"]),
                                "reviewed_by": r["reviewed_by"]}}
