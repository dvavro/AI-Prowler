"""The shared wall-and-room model (Coder 2 Sprint 12).

One model per project, built from the drawing model the plan engine saved, so framing, drywall, painting, insulation
and flooring all take their quantities from the same rooms, walls and openings and always agree (spec trade table:
"Wall lengths + room ceilings from framing takeoff", "Reuses drywall surfaces", "Reuses wall-and-room model").

- Rooms: the plan's closed rooms with their name, floor area and perimeter (the length of wall face in the room).
- Walls: wall centerlines with their length and thickness. A wall with a room on both sides is interior; with a room on
  one side, exterior; with none, it's left out of the trades (site walls, details) and listed as such.
- Openings: door and window tags on the plan, sized from their schedule row (WIDTH / HEIGHT or SIZE), else a standard
  size (door 3'-0" x 6'-8", window 3'-0" x 5'-0"), on the nearest wall and so in the rooms that wall bounds.
- Heights: a room's ceiling height from the room finish schedule (CEILING HEIGHT / CLG HT), else the height given for
  the project, else 8 ft.
- Which sheets: floor plans only, so the same rooms drawn again on an electrical or a ceiling plan aren't counted twice
  (architectural sheets when there are any; a sheet whose rooms are all already counted is a repeat view).

It never changes anything and nothing is priced from it directly: answers_for(module) gives a trade's measured answers
with where each came from, for a person (or the trade's takeoff agent, through the Runner) to use.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from decimal import Decimal

from estimator.context import RequestContext
from estimator.errors import InvalidInput

DEFAULT_HEIGHT_FT = 8.0
DOOR = (3.0, 6.667)                 # width, height in feet
WINDOW = (3.0, 5.0)
OPENING_REACH_FT = 3.0              # a tag this close to a wall is in that wall
DEFAULT_THICKNESS_IN = 6.0
REPEAT_VIEW = 0.8                   # share of a sheet's rooms already counted that makes it a repeat view
THICKNESS_RE = re.compile(r'(\d+(?:\.\d+)?)"\s*wall', re.I)
HEIGHT_KEYS = re.compile(r"CEIL(?:ING)?\.?\s*(?:HT|HEIGHT|HGT)|CLG\.?\s*(?:HT|HEIGHT|HGT)|^HEIGHT$|^HT$", re.I)
NAME_KEYS = re.compile(r"ROOM|SPACE|NAME", re.I)
WIDTH_KEYS = re.compile(r"^(?:W|WD|WIDTH)\.?$", re.I)
HIGH_KEYS = re.compile(r"^(?:H|HT|HGT|HEIGHT)\.?$", re.I)
SIZE_KEYS = re.compile(r"SIZE|DIM", re.I)
WALL_TRADES = ("framing", "drywall", "painting", "insulation", "flooring")
# Sprint 14: the other trades the model answers - windows and doors (schedule linking), siding (elevations), HVAC (area).
MODEL_TRADES = WALL_TRADES + ("windows_doors", "siding", "hvac", "fencing", "landscaping")
SITE_TRADES = ("fencing", "landscaping")            # Sprint 15: from the site and landscape plans (building.site)
TYPE_KEYS = re.compile(r"TYPE|DESC|REMARK|OPERATION|STYLE|MATERIAL", re.I)
QTY_KEYS = re.compile(r"^(?:QTY|QUANTITY|NO\.?|COUNT)$", re.I)
WINDOW_SMALL_SQFT = 15.0                    # the windows and doors trade's line between small and large windows
GARAGE_RE = re.compile(r"GARAGE|OVERHEAD|\bO\.?H\.?\b|ROLL[- ]?UP", re.I)
PATIO_RE = re.compile(r"SLID|PATIO|FRENCH|GLIDER|BIFOLD EXT|MULTI[- ]?SLIDE", re.I)
UNCONDITIONED_RE = re.compile(r"GARAGE|PORCH|PATIO|DECK|BALCONY|LANAI|CARPORT|ATTIC|CRAWL|BREEZEWAY|SCREEN|STOOP|"
                              r"TERRACE|VERANDA|PERGOLA|COVERED", re.I)
ALL_SIDES = 4                               # elevations of every side: a house has four


# ---------------------------------------------------------------------------------------------------- small helpers

def _f(v) -> float | None:
    try:
        return None if v in (None, "") else float(v)
    except (TypeError, ValueError):
        return None


def _r(v: float, nd: int = 1) -> float:
    return round(float(v) + 0.0, nd)


def _norm(s: str | None) -> str:
    return re.sub(r"[^A-Z0-9]+", " ", (s or "").upper()).strip()


def _length_ft(text) -> float | None:
    """A length written in a schedule (3'-0", 36", 9', 2'6) in feet, or None."""
    from estimator.drawing_model.geometry import parse_length
    s = str(text or "").strip()
    if not s:
        return None
    try:
        v = float(parse_length(s, default_unit="ft"))
    except Exception:  # noqa: BLE001 - not a length
        return None
    return v if 0 < v < 100 else None


def _size_ft(text) -> tuple[float | None, float | None]:
    """'3'-0" x 6'-8"' or '3068' (door shorthand) -> (width, height) in feet."""
    s = str(text or "").strip()
    m = re.fullmatch(r"(\d)(\d)(\d)(\d)", s)                         # 3068 = 3'-0" x 6'-8"
    if m:
        return int(m[1]) + int(m[2]) / 12, int(m[3]) + int(m[4]) / 12
    parts = re.split(r"\s*[xX×]\s*", s)
    if len(parts) == 2:
        return _length_ft(parts[0]), _length_ft(parts[1])
    return None, None


def _seg_dist(p, a, b) -> tuple[float, float]:
    """Distance from p to segment ab, and where along it (0..1)."""
    ax, ay = a
    bx, by = b
    dx, dy = bx - ax, by - ay
    L2 = dx * dx + dy * dy
    t = 0.0 if L2 == 0 else max(0.0, min(1.0, ((p[0] - ax) * dx + (p[1] - ay) * dy) / L2))
    qx, qy = ax + t * dx, ay + t * dy
    return math.hypot(p[0] - qx, p[1] - qy), t


def _inside(p, poly) -> bool:
    x, y, inside = p[0], p[1], False
    n = len(poly)
    for i in range(n):
        x1, y1 = poly[i]
        x2, y2 = poly[(i + 1) % n]
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / ((y2 - y1) or 1e-12) + x1:
            inside = not inside
    return inside


# ---------------------------------------------------------------------------------------------------- reading

def _plan_sets(conn, ctx, plan_set_id, estimate_id) -> list[dict]:
    from estimator.drawing_model import store
    from estimator.estimating import service
    if plan_set_id:
        ps = store.load_plan_set(conn, ctx, int(plan_set_id))
        return [dict(ps)]
    if not estimate_id:
        raise InvalidInput("give an estimate_id or a plan_set_id")
    service.get_estimate(conn, ctx, int(estimate_id))                  # not found / another company's estimate
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM plan_sets WHERE company_id = ? AND estimate_id = ? ORDER BY id", (ctx.company_id, int(estimate_id)))]
    replaced = {r["supersedes_plan_set_id"] for r in rows if r["supersedes_plan_set_id"]}
    return [r for r in rows if r["id"] not in replaced]                   # the current revision of each set


RASTER_NOTE = ("read from scanned or photographed plans: every quantity is marked to check - look at each one on the plan "
               "before approving it")


def plan_method(conn, sets: list[dict]) -> str:
    """How the plans were read (Sprint 16): "raster" when any sheet is a scan or photo, "cad" when every set is a DXF or
    DWG drawing, else "vector"."""
    ids = [p["id"] for p in sets]
    if not ids:
        return "vector"
    if any(p.get("file_type") == "image" for p in sets):
        return "raster"
    q = ",".join("?" * len(ids))
    if conn.execute(f"SELECT 1 FROM drawing_objects o JOIN sheets s ON s.id = o.sheet_id WHERE s.plan_set_id IN ({q})"
                    " AND o.source = 'raster' LIMIT 1", ids).fetchone():
        return "raster"
    if all(p.get("file_type") in ("dxf", "dwg") for p in sets):
        return "cad"
    return "vector"


def _sheet_rows(conn, plan_set_ids: list[int]) -> list[dict]:
    if not plan_set_ids:
        return []
    q = ",".join("?" * len(plan_set_ids))
    return [dict(r) for r in conn.execute(
        f"SELECT id, plan_set_id, page_no, sheet_no, title, discipline, units FROM sheets WHERE plan_set_id IN ({q})"
        " ORDER BY plan_set_id, page_no", plan_set_ids)]


def _factors(conn, sheet: dict) -> dict:
    """{viewport id: real feet per drawing unit} for the sheet's measurable viewports."""
    from estimator.drawing_model import geometry as geo
    out = {}
    for v in conn.execute("SELECT id, scale_ratio, is_nts FROM viewports WHERE sheet_id = ?", (sheet["id"],)):
        try:
            f = geo.feet_per_unit(sheet["units"], Decimal(v["scale_ratio"]) if v["scale_ratio"] else None,
                                  bool(v["is_nts"]))
        except Exception:  # noqa: BLE001
            f = None
        if f:
            out[v["id"]] = float(f)
    return out


def _objects(conn, sheet_id: int, kinds: tuple) -> list[dict]:
    q = ",".join("?" * len(kinds))
    out = []
    for r in conn.execute(f"SELECT id, viewport_id, kind, geometry_json, real_units_json, label, tag FROM drawing_objects"
                          f" WHERE sheet_id = ? AND kind IN ({q}) ORDER BY id", (sheet_id, *kinds)):
        o = dict(r)
        o["geometry"] = json.loads(o.pop("geometry_json"))
        o["real"] = json.loads(o.pop("real_units_json")) if o["real_units_json"] else None
        out.append(o)
    return out


def _schedule_rows(conn, plan_set_ids: list[int]) -> list[dict]:
    if not plan_set_ids:
        return []
    q = ",".join("?" * len(plan_set_ids))
    out = []
    for r in conn.execute(
            "SELECT r.id, r.mark, r.fields_json, r.linked_object_ids, c.schedule_type FROM schedule_rows r"
            " JOIN schedules c ON c.id = r.schedule_id JOIN sheets s ON s.id = c.sheet_id"
            f" WHERE s.plan_set_id IN ({q})", plan_set_ids):
        d = dict(r)
        d["fields"] = json.loads(d.pop("fields_json") or "{}")
        d["linked"] = json.loads(d.pop("linked_object_ids") or "[]")
        out.append(d)
    return out


# ---------------------------------------------------------------------------------------------------- the model

def build(conn, ctx: RequestContext, *, estimate_id: int | None = None, plan_set_id: int | None = None,
          height_ft: float | None = None) -> dict:
    """The wall-and-room model of a project (its current plan sets) or of one plan set. Changes nothing."""
    if height_ft is not None:
        height_ft = _f(height_ft)
        if height_ft is None or not 6 <= height_ft <= 30:
            raise InvalidInput("height_ft is the ceiling height in feet, 6 to 30")
    sets = _plan_sets(conn, ctx, plan_set_id, estimate_id)
    ps_ids = [p["id"] for p in sets]
    sheets = _sheet_rows(conn, ps_ids)
    rows = _schedule_rows(conn, ps_ids)
    default_h = height_ft or DEFAULT_HEIGHT_FT
    notes, skipped = [], []
    method = plan_method(conn, sets)                                       # Sprint 16: scans and photos are checked
    if method == "raster":
        notes.append(RASTER_NOTE)

    # Which sheets: floor plans with measured rooms; architectural ones when there are any; repeat views left out.
    per_sheet = []
    for s in sheets:
        objs = _objects(conn, s["id"], ("room", "wall", "text"))
        rooms = [o for o in objs if o["kind"] == "room" and o["geometry"].get("type") == "polygon"]
        if rooms:
            per_sheet.append((s, objs, rooms))
    archi = [x for x in per_sheet if (x[0]["discipline"] or "") == "architectural"]
    chosen_from = archi or per_sheet
    for x in per_sheet:
        if x not in chosen_from:
            skipped.append({"sheet_id": x[0]["id"], "sheet_no": x[0]["sheet_no"],
                            "why": f"{x[0]['discipline']} sheet; the rooms come from the architectural floor plans"})
    seen_names: set[str] = set()
    chosen = []
    for s, objs, rooms in chosen_from:
        names = {_norm(r["label"]) for r in rooms if r["label"]}
        if names and seen_names and len(names & seen_names) >= REPEAT_VIEW * len(names):
            skipped.append({"sheet_id": s["id"], "sheet_no": s["sheet_no"],
                            "why": "its rooms are already counted from another sheet (a repeat view, e.g. a ceiling plan)"})
            continue
        seen_names |= names
        chosen.append((s, objs, rooms))

    # Room heights from finish schedules.
    heights_by_name = {}
    for r in rows:
        if r["schedule_type"] != "finish":
            continue
        # A NAME column first (ROOM is often the room number), then ROOM / SPACE, then the mark.
        names = [v for k, v in r["fields"].items() if re.search(r"NAME", k, re.I) and v] + \
                [v for k, v in r["fields"].items() if NAME_KEYS.search(k) and v]
        name = names[0] if names else r["mark"]
        h = next((_length_ft(v) for k, v in r["fields"].items() if HEIGHT_KEYS.search(k.strip()) and _length_ft(v)), None)
        if name and h:
            for n in {name, r["mark"], *names}:
                if n:
                    heights_by_name[_norm(n)] = h

    # Door and window sizes from their schedules, by tag object.
    size_by_obj: dict[int, dict] = {}
    marks: list[dict] = []                                     # Sprint 14: each door and window schedule row
    for r in rows:
        if r["schedule_type"] not in ("door", "window"):
            continue
        w = h = qty = None
        types = []
        for k, v in r["fields"].items():
            k2 = k.strip()
            if WIDTH_KEYS.match(k2):
                w = w or _length_ft(v)
            elif HIGH_KEYS.match(k2):
                h = h or _length_ft(v)
            elif SIZE_KEYS.search(k2):
                sw, sh = _size_ft(v)
                w, h = w or sw, h or sh
            elif QTY_KEYS.match(k2) and str(v or "").strip().isdigit():
                qty = int(str(v).strip())
            elif TYPE_KEYS.search(k2) and v:
                types.append(str(v).strip())
        typ = " ".join(types)[:80] or None
        marks.append({"schedule_row_id": r["id"], "mark": r["mark"], "kind": r["schedule_type"], "width_ft": w,
                      "height_ft": h, "type": typ, "schedule_qty": qty, "on_plans": 0})
        for oid in r["linked"]:
            size_by_obj[int(oid)] = {"width_ft": w, "height_ft": h, "schedule_row_id": r["id"], "mark": r["mark"],
                                     "type": typ}

    out_rooms, out_walls, out_openings, not_measured, corners = [], [], [], 0, 0
    footprint = (0, 0)                                             # outside and inside corners of the building
    for s, objs, rooms in chosen:
        factors = _factors(conn, s)
        # ---- rooms
        sheet_rooms = []
        for o in rooms:
            if not o["real"] or "area_sqft" not in o["real"] or o["viewport_id"] not in factors:
                not_measured += 1
                continue
            name = o["label"] or f"Room {o['id']}"
            h = heights_by_name.get(_norm(o["label"])) or heights_by_name.get(_norm(o["tag"]))
            room = {"id": o["id"], "sheet_id": s["id"], "sheet_no": s["sheet_no"], "name": name,
                    "area_sqft": _r(o["real"]["area_sqft"]), "perimeter_ft": _r(o["real"].get("perimeter_ft", 0)),
                    "height_ft": _r(h or default_h, 2), "height_from": "finish schedule" if h else (
                        "given" if height_ft else "standard 8 ft"),
                    "walls": [], "openings": [], "_poly": o["geometry"]["points"], "_vp": o["viewport_id"]}
            sheet_rooms.append(room)
        # ---- walls
        sheet_walls = []
        for o in objs:
            if o["kind"] != "wall" or o["geometry"].get("type") not in ("line", "polyline"):
                continue
            f = factors.get(o["viewport_id"])
            if not f or not o["real"] or "length_ft" not in o["real"]:
                not_measured += 1
                continue
            m = THICKNESS_RE.search(o["label"] or "")
            t_in = float(m.group(1)) if m else DEFAULT_THICKNESS_IN
            pts = o["geometry"]["points"]
            half = (t_in / 12.0) / f / 2.0                              # half the thickness, in drawing units
            sides: set[int] = set()
            for i in range(len(pts) - 1):
                a, b = pts[i], pts[i + 1]
                dx, dy = b[0] - a[0], b[1] - a[1]
                L = math.hypot(dx, dy) or 1e-9
                nx, ny = -dy / L, dx / L
                for frac in (0.25, 0.5, 0.75):
                    cx, cy = a[0] + dx * frac, a[1] + dy * frac
                    for sgn in (1, -1):
                        p = (cx + sgn * nx * half * 2.2, cy + sgn * ny * half * 2.2)
                        for rm in sheet_rooms:
                            if rm["_vp"] == o["viewport_id"] and _inside(p, rm["_poly"]):
                                sides.add(rm["id"])
            n_sides = _sides(pts, half, [rm for rm in sheet_rooms if rm["id"] in sides])
            kind = "interior" if n_sides >= 2 else "exterior" if n_sides == 1 else "other"
            wall = {"id": o["id"], "sheet_id": s["id"], "type": kind, "length_ft": _r(o["real"]["length_ft"]),
                    "thickness_in": _r(t_in), "rooms": sorted(sides), "openings": [],
                    "_pts": pts, "_f": f, "_vp": o["viewport_id"]}
            sheet_walls.append(wall)
            for rm in sheet_rooms:
                if rm["id"] in sides:
                    rm["walls"].append(o["id"])
        for w in sheet_walls:
            hs = [rm["height_ft"] for rm in sheet_rooms if rm["id"] in w["rooms"]]
            w["height_ft"] = _r(max(hs) if hs else default_h, 2)
        corners += _corners([w for w in sheet_walls if w["type"] != "other"])
        out_c, in_c = _footprint_corners(sheet_rooms, sheet_walls, factors)
        if out_c + in_c > footprint[0] + footprint[1]:                 # the biggest floor's outline (stories line up)
            footprint = (out_c, in_c)
        # ---- openings (door and window tags)
        for o in objs:
            if o["kind"] != "text" or not o["tag"] or o["label"] not in ("door tag", "window tag"):
                continue
            kind = o["label"].split()[0]
            p = o["geometry"]["points"][0]
            best = None
            for w in sheet_walls:
                if w["_vp"] != o["viewport_id"]:
                    continue
                d = min(_seg_dist(p, w["_pts"][i], w["_pts"][i + 1])[0] for i in range(len(w["_pts"]) - 1)) * w["_f"]
                if d <= OPENING_REACH_FT and (best is None or d < best[0]):
                    best = (d, w)
            size = size_by_obj.get(o["id"], {})
            std = DOOR if kind == "door" else WINDOW
            wd, ht = size.get("width_ft") or std[0], size.get("height_ft") or std[1]
            op = {"id": o["id"], "sheet_id": s["id"], "kind": kind, "mark": o["tag"], "width_ft": _r(wd, 2),
                  "height_ft": _r(ht, 2), "area_sqft": _r(wd * ht), "size_from":
                      "schedule" if size.get("width_ft") and size.get("height_ft") else "standard size",
                  "schedule_row_id": size.get("schedule_row_id"), "type": size.get("type"),
                  "wall_id": best[1]["id"] if best else None, "rooms": list(best[1]["rooms"]) if best else [],
                  "wall_type": best[1]["type"] if best else None}
            if best:
                best[1]["openings"].append(o["id"])
            for rm in sheet_rooms:
                if rm["id"] in op["rooms"]:
                    rm["openings"].append(o["id"])
            out_openings.append(op)
        out_rooms += sheet_rooms
        out_walls += sheet_walls

    # ---- per-room surfaces
    op_by_id = {op["id"]: op for op in out_openings}
    for rm in out_rooms:
        ops = [op_by_id[i] for i in rm["openings"]]
        open_sqft = sum(op["area_sqft"] for op in ops)
        door_w = sum(op["width_ft"] for op in ops if op["kind"] == "door")
        rm["openings_sqft"] = _r(open_sqft)
        rm["wall_sqft"] = _r(max(rm["perimeter_ft"] * rm["height_ft"] - open_sqft, 0))
        rm["ceiling_sqft"] = rm["area_sqft"]
        rm["base_lf"] = _r(max(rm["perimeter_ft"] - door_w, 0))
    if not out_rooms and not out_walls:
        notes.append("No measured rooms or walls yet: read the plans, and set the scale on any view that needs one.")
    if not_measured:
        notes.append(f"{not_measured} room(s) or wall(s) on unscaled views aren't counted; set their scale to include them.")
    unplaced = [op for op in out_openings if not op["wall_id"]]
    if unplaced:
        notes.append(f"{len(unplaced)} door or window tag(s) aren't near a wall, so they aren't taken off any room.")
    std = [op for op in out_openings if op["size_from"] == "standard size"]
    if std:
        notes.append(f"{len(std)} opening(s) have no size in a schedule; a standard size is used.")

    # Sprint 14: door and window schedule linking - how many of each mark are tagged on the floor plans.
    for m in marks:
        m["on_plans"] = sum(1 for op in out_openings if op["schedule_row_id"] == m["schedule_row_id"])
        for k in ("width_ft", "height_ft"):
            m[k] = _r(m[k], 2) if m[k] else None
    untagged = [m for m in marks if not m["on_plans"]]
    if untagged:
        notes.append("not tagged on the floor plans, so not counted: " + ", ".join(
            f"{m['mark']}" + (f" ({m['schedule_qty']} in the schedule)" if m["schedule_qty"] else "") for m in untagged))
    differs = [m for m in marks if m["on_plans"] and m["schedule_qty"] and m["schedule_qty"] != m["on_plans"]]
    for m in differs:
        notes.append(f"{m['mark']}: {m['on_plans']} tagged on the plans but {m['schedule_qty']} in the schedule - check")

    # Sprint 14: exterior elevations (every sheet of the current plan sets).
    from estimator.building import elevations as elev
    ev = elev.read(conn, sheets, lambda s: _factors(conn, s))
    notes += ev["notes"]
    if ev["elevations"] and len(ev["elevations"]) < ALL_SIDES:
        notes.append(f"only {len(ev['elevations'])} exterior elevation(s) found; siding and exterior paint use the floor "
                     "plans' outside walls until every side is drawn")

    # Sprint 15: the site - landscape zones, fence lines, gates and the plant schedule.
    from estimator.building import site as site_mod
    site = site_mod.read(conn, sheets, lambda s: _factors(conn, s), rows)

    for x in out_rooms:
        x.pop("_poly"), x.pop("_vp")
    for x in out_walls:
        x.pop("_pts"), x.pop("_f"), x.pop("_vp")
    totals = _totals(out_rooms, out_walls, out_openings, default_h, corners)
    totals.update(_more_totals(out_rooms, out_openings, ev["elevations"], footprint))
    totals.update(fence_lf=site["fence_lf"], **{f"{k}_sqft": v for k, v in site["zone_sqft"].items()})
    key = hashlib.sha1(json.dumps({"r": out_rooms, "w": out_walls, "o": out_openings, "e": ev["elevations"],
                                   "s": [site["zones"], site["fences"], site["gates"], site["plants"]]},
                                  sort_keys=True, default=str).encode()).hexdigest()[:12]
    return {"ok": True, "plan_set_ids": ps_ids, "model_key": key, "method": method, "needs_review": method == "raster",
            "rooms": out_rooms, "walls": out_walls,
            "openings": out_openings, "elevations": ev["elevations"], "schedule_marks": marks, "site": site,
            "totals": totals,
            "skipped_sheets": skipped, "notes": notes, "trades": list(MODEL_TRADES),
            "summary": (f"{len(out_rooms)} room(s), {totals['floor_sqft']:g} sq ft; walls {totals['exterior_wall_lf']:g} lf "
                        f"exterior and {totals['interior_wall_lf']:g} lf interior; {totals['doors']} door(s) and "
                        f"{totals['windows']} window(s).")}


def _sides(pts, half, rooms) -> int:
    """How many sides of the wall have a room: rooms on the same side (one room on each of two walls of an L) count once."""
    if not rooms:
        return 0
    a, b = pts[0], pts[-1]
    dx, dy = b[0] - a[0], b[1] - a[1]
    side = set()
    for rm in rooms:
        poly = rm["_poly"]
        cx = sum(p[0] for p in poly) / len(poly)
        cy = sum(p[1] for p in poly) / len(poly)
        side.add(1 if dx * (cy - a[1]) - dy * (cx - a[0]) > 0 else -1)
    return len(side)


def _totals(rooms, walls, openings, default_h, corners: int) -> dict:
    ext = [w for w in walls if w["type"] == "exterior"]
    inn = [w for w in walls if w["type"] == "interior"]
    counted = ext + inn
    ext_ops = [op for op in openings if op["wall_id"] in {w["id"] for w in ext}]
    heights = [rm["height_ft"] for rm in rooms] or [default_h]
    return {
        "rooms": len(rooms),
        "floor_sqft": _r(sum(rm["area_sqft"] for rm in rooms)),
        "ceiling_sqft": _r(sum(rm["ceiling_sqft"] for rm in rooms)),
        "room_perimeter_lf": _r(sum(rm["perimeter_ft"] for rm in rooms)),
        "wall_face_sqft": _r(sum(rm["wall_sqft"] for rm in rooms)),
        "room_openings_sqft": _r(sum(rm["openings_sqft"] for rm in rooms)),
        "base_lf": _r(sum(rm["base_lf"] for rm in rooms)),
        "exterior_wall_lf": _r(sum(w["length_ft"] for w in ext)),
        "interior_wall_lf": _r(sum(w["length_ft"] for w in inn)),
        "other_wall_lf": _r(sum(w["length_ft"] for w in walls if w["type"] == "other")),
        "wall_lf": _r(sum(w["length_ft"] for w in counted)),
        "exterior_wall_sqft": _r(max(sum(w["length_ft"] * w["height_ft"] for w in ext)
                                     - sum(op["area_sqft"] for op in ext_ops), 0)),
        "doors": sum(1 for op in openings if op["kind"] == "door"),
        "windows": sum(1 for op in openings if op["kind"] == "window"),
        "openings": sum(1 for op in openings if op["wall_id"]),
        # the most common ceiling height (the higher one on a tie, so walls are never short)
        "height_ft": _r(max(set(heights), key=lambda h: (heights.count(h), h)), 2),
        "corners": corners,
    }


def _door_class(op: dict) -> str:
    """Which windows-and-doors question a door answers: garage, patio (sliding / French), exterior or interior."""
    text = f"{op.get('type') or ''} {op.get('mark') or ''}"
    if GARAGE_RE.search(text) or op["width_ft"] >= 8:
        return "garage_doors"
    if PATIO_RE.search(text) or (op["width_ft"] >= 5 and op.get("wall_type") == "exterior"):
        return "patio_doors"
    if op.get("wall_type") == "exterior" or re.search(r"\bEXT", text, re.I):
        return "exterior_doors"
    return "interior_doors"


def _more_totals(rooms, openings, elevs, footprint) -> dict:
    """Sprint 14 totals: windows and doors by kind, conditioned area, the outline's corners and the elevations."""
    wd = {"windows_small": 0, "windows_large": 0, "patio_doors": 0, "exterior_doors": 0, "interior_doors": 0,
          "garage_doors": 0}
    for op in openings:
        if op["kind"] == "window":
            wd["windows_large" if op["area_sqft"] >= WINDOW_SMALL_SQFT else "windows_small"] += 1
        else:
            wd[_door_class(op)] += 1
    ext_ops = [op for op in openings if op.get("wall_type") == "exterior"]
    return {
        **wd,
        "conditioned_sqft": _r(sum(rm["area_sqft"] for rm in rooms if not UNCONDITIONED_RE.search(rm["name"] or ""))),
        "unconditioned_sqft": _r(sum(rm["area_sqft"] for rm in rooms if UNCONDITIONED_RE.search(rm["name"] or ""))),
        "outside_corners": footprint[0], "inside_corners": footprint[1],
        "exterior_openings": len(ext_ops), "exterior_openings_sqft": _r(sum(op["area_sqft"] for op in ext_ops)),
        "elevations": len(elevs),
        "elevation_wall_sqft": _r(sum(e["wall_sqft"] for e in elevs)),
        "elevation_openings": sum(len(e["openings"]) for e in elevs),
        "elevation_net_sqft": _r(sum(e["net_sqft"] for e in elevs)),
        "stories": max([e["stories"] for e in elevs] or [1]),
    }


def _footprint_corners(rooms, walls, factors) -> tuple[int, int]:
    """(outside, inside) corners of the building's outline on one floor plan: the rooms joined with their walls
    (each room grown by a wall's thickness), and each turn of the outline that's more than 20 degrees."""
    try:
        from shapely.geometry import Polygon
        from shapely.ops import unary_union
    except ImportError:
        return 0, 0
    by_vp: dict = {}
    for rm in rooms:
        by_vp.setdefault(rm["_vp"], []).append(rm)
    if not by_vp:
        return 0, 0
    vp, rms = max(by_vp.items(), key=lambda kv: sum(r["area_sqft"] for r in kv[1]))
    f = factors.get(vp)
    if not f:
        return 0, 0
    ts = [w["thickness_in"] for w in walls if w["_vp"] == vp] or [DEFAULT_THICKNESS_IN]
    t = (max(ts) / 12.0) / f
    try:
        shape = unary_union([Polygon(r["_poly"]).buffer(t, join_style=2) for r in rms])
    except Exception:  # noqa: BLE001 - a broken room outline: no corners rather than a wrong count
        return 0, 0
    if shape.is_empty:
        return 0, 0
    shape = max(getattr(shape, "geoms", [shape]), key=lambda g: g.area)
    ring = list(shape.simplify(t / 2, preserve_topology=True).exterior.coords)[:-1]
    n = len(ring)
    area2 = sum(ring[i][0] * ring[(i + 1) % n][1] - ring[(i + 1) % n][0] * ring[i][1] for i in range(n))
    orient = 1 if area2 > 0 else -1
    out_c = in_c = 0
    for i in range(n):
        (ax, ay), (bx, by), (cx, cy) = ring[i - 1], ring[i], ring[(i + 1) % n]
        v1, v2 = (bx - ax, by - ay), (cx - bx, cy - by)
        cross = v1[0] * v2[1] - v1[1] * v2[0]
        dot = v1[0] * v2[0] + v1[1] * v2[1]
        if abs(math.degrees(math.atan2(cross, dot))) < 20:
            continue
        if cross * orient > 0:
            out_c += 1
        else:
            in_c += 1
    return out_c, in_c


def _corners(walls) -> int:
    """Corners and wall ends for framing: one per cluster of wall end points on a sheet (walls meeting at a corner or
    a tee share one; a free end is one too). Ends closer than a wall thickness are the same place."""
    ends = []
    for w in walls:
        tol = (w["thickness_in"] / 12.0) / w["_f"] * 1.2
        ends += [(w["_pts"][0], tol), (w["_pts"][-1], tol)]
    clusters: list[tuple[float, float, float]] = []
    for (p, tol) in ends:
        for i, (cx, cy, ct) in enumerate(clusters):
            if math.hypot(p[0] - cx, p[1] - cy) <= max(tol, ct):
                break
        else:
            clusters.append((p[0], p[1], tol))
    return len(clusters)


# ---------------------------------------------------------------------------------------------------- trade answers

def _choice_height(h: float) -> tuple[str, str | None]:
    options = (8, 9, 10)
    best = min(options, key=lambda o: abs(o - h))
    note = None if abs(best - h) < 0.01 else f"ceiling height {h:g} ft is closest to the {best} ft choice"
    return str(best), note


def answers_for(model: dict, module_id: str) -> dict:
    """A trade's measured answers from the model, with where each came from. The same model gives every trade the
    same rooms, walls and openings."""
    t = model["totals"]
    notes = []
    if module_id == "framing":
        h, n = _choice_height(t["height_ft"])
        ans = {"wall_lf": t["wall_lf"], "wall_height": h, "corners": t["corners"], "openings": t["openings"],
               "exterior": t["exterior_wall_lf"] > 0}
        src = {"wall_lf": "exterior + interior wall centerlines", "corners": "wall ends and corners",
               "openings": "door and window tags on a wall", "exterior": "walls with a room on one side",
               "wall_height": "most common ceiling height"}
        notes += [n] if n else []
    elif module_id == "drywall":
        h, n = _choice_height(t["height_ft"])
        # Drywall goes on every room face, so its wall length is the rooms' perimeters, and each face loses its openings.
        ans = {"wall_lf": t["room_perimeter_lf"], "wall_height": h, "ceiling_sqft": t["ceiling_sqft"],
               "openings_sqft": t["room_openings_sqft"]}
        src = {"wall_lf": "room perimeters (both faces of interior walls)", "ceiling_sqft": "room floor areas",
               "openings_sqft": "doors and windows, once for each room they open into", "wall_height":
                   "most common ceiling height"}
        notes += [n] if n else []
        if any(abs(rm["height_ft"] - float(h)) > 0.01 for rm in model["rooms"]):
            notes.append("rooms have different ceiling heights; the wall area per room is in the model (wall_sqft)")
    elif module_id == "painting":
        ans = {"wall_sqft": t["wall_face_sqft"], "ceiling_sqft": t["ceiling_sqft"], "doors": t["doors"],
               "trim_lf": t["base_lf"]}
        src = {"wall_sqft": "room wall faces x ceiling height, less openings (the drywall surfaces)",
               "ceiling_sqft": "room floor areas", "doors": "door tags", "trim_lf": "baseboard: room perimeters less doors"}
        # Sprint 14: the outside walls - from the elevations when every side is drawn (real heights, no gables).
        if t["elevations"] >= ALL_SIDES:
            ans["exterior_sqft"] = t["elevation_net_sqft"]
            src["exterior_sqft"] = f"{t['elevations']} exterior elevations, less their doors and windows"
        elif t["exterior_wall_lf"]:
            ans["exterior_sqft"] = t["exterior_wall_sqft"]
            src["exterior_sqft"] = "outside walls on the floor plans x ceiling height, less their doors and windows"
    elif module_id == "insulation":
        ans = {"wall_sqft": t["exterior_wall_sqft"], "attic_sqft": t["ceiling_sqft"]}
        src = {"wall_sqft": "exterior walls x height, less their doors and windows",
               "attic_sqft": "ceiling area under the attic (all rooms; check for a second floor)"}
    elif module_id == "flooring":
        ans = {"area_sqft": t["floor_sqft"], "baseboard_lf": t["base_lf"]}
        src = {"area_sqft": "room floor areas", "baseboard_lf": "room perimeters less door widths"}
    elif module_id == "windows_doors":
        keys = ("windows_small", "windows_large", "patio_doors", "exterior_doors", "interior_doors", "garage_doors")
        ans = {k: t[k] for k in keys if t[k]}
        src = {k: v for k, v in {
            "windows_small": "window tags, under 15 sq ft by their schedule size",
            "windows_large": "window tags, 15 sq ft and over by their schedule size",
            "patio_doors": "door tags typed sliding, French or patio (or 5 ft and wider in an outside wall)",
            "exterior_doors": "door tags in outside walls", "interior_doors": "door tags in inside walls",
            "garage_doors": "door tags typed garage or overhead (or 8 ft and wider)"}.items() if k in ans}
        if not model["schedule_marks"]:
            notes.append("no door or window schedule found: sizes are standard and types unknown")
    elif module_id == "siding":
        if t["elevations"] >= ALL_SIDES:
            ans = {"wall_sqft": t["elevation_wall_sqft"], "openings": t["elevation_openings"]}
            src = {"wall_sqft": f"{t['elevations']} exterior elevations, floor line to plate line (gables left out)",
                   "openings": "doors and windows drawn on the elevations"}
        else:
            ans = {"wall_sqft": _r(t["exterior_wall_sqft"] + t["exterior_openings_sqft"]),
                   "openings": t["exterior_openings"]}
            src = {"wall_sqft": "outside walls on the floor plans x ceiling height (no gables)",
                   "openings": "door and window tags in outside walls"}
        ans["stories"] = "two" if t["stories"] >= 2 else "one"
        src["stories"] = "plate lines on the elevations" if t["elevations"] else "one floor unless the elevations say more"
        if t["outside_corners"]:
            ans.update(outside_corners=t["outside_corners"], inside_corners=t["inside_corners"],
                       walls="complex" if t["inside_corners"] >= 2 or t["outside_corners"] > 6 else "simple")
            src.update(outside_corners="the building's outline on the floor plan",
                       inside_corners="the building's outline on the floor plan",
                       walls="simple: a plain box (4-6 outside corners, at most 1 inside)")
    elif module_id == "hvac":
        ans = {"conditioned_sqft": t["conditioned_sqft"]} if t["conditioned_sqft"] else {}
        src = {"conditioned_sqft": "room floor areas, not counting garages, porches, patios and other outside rooms"} \
            if ans else {}
        if t["unconditioned_sqft"]:
            notes.append(f"{t['unconditioned_sqft']:g} sq ft of garages, porches and similar rooms isn't heated or cooled")
    elif module_id in SITE_TRADES:
        # Sprint 15: from the site and landscape plans; the house's room and wall notes don't apply to them.
        from estimator.building import site as site_mod
        fn = site_mod.fencing_answers if module_id == "fencing" else site_mod.landscaping_answers
        ans, src, notes = fn(model["site"])
        raster = [RASTER_NOTE] if model.get("needs_review") else []
        return {"ok": True, "module_id": module_id, "model_key": model["model_key"], "answers": ans, "from": src,
                "method": model.get("method", "vector"), "needs_review": bool(model.get("needs_review")),
                "notes": raster + notes + model["site"]["notes"]}
    else:
        raise InvalidInput(f"the wall-and-room model gives answers for {', '.join(MODEL_TRADES)}", module_id=module_id)
    return {"ok": True, "module_id": module_id, "model_key": model["model_key"], "answers": ans, "from": src,
            "method": model.get("method", "vector"), "needs_review": bool(model.get("needs_review")),
            "notes": notes + model["notes"]}
