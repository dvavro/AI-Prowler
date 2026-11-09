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
    for r in rows:
        if r["schedule_type"] not in ("door", "window"):
            continue
        w = h = None
        for k, v in r["fields"].items():
            k2 = k.strip()
            if WIDTH_KEYS.match(k2):
                w = w or _length_ft(v)
            elif HIGH_KEYS.match(k2):
                h = h or _length_ft(v)
            elif SIZE_KEYS.search(k2):
                sw, sh = _size_ft(v)
                w, h = w or sw, h or sh
        for oid in r["linked"]:
            size_by_obj[int(oid)] = {"width_ft": w, "height_ft": h, "schedule_row_id": r["id"], "mark": r["mark"]}

    out_rooms, out_walls, out_openings, not_measured, corners = [], [], [], 0, 0
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
                  "schedule_row_id": size.get("schedule_row_id"),
                  "wall_id": best[1]["id"] if best else None, "rooms": list(best[1]["rooms"]) if best else []}
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

    for x in out_rooms:
        x.pop("_poly"), x.pop("_vp")
    for x in out_walls:
        x.pop("_pts"), x.pop("_f"), x.pop("_vp")
    totals = _totals(out_rooms, out_walls, out_openings, default_h, corners)
    key = hashlib.sha1(json.dumps({"r": out_rooms, "w": out_walls, "o": out_openings}, sort_keys=True,
                                  default=str).encode()).hexdigest()[:12]
    return {"ok": True, "plan_set_ids": ps_ids, "model_key": key, "rooms": out_rooms, "walls": out_walls,
            "openings": out_openings, "totals": totals, "skipped_sheets": skipped, "notes": notes,
            "trades": list(WALL_TRADES),
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
    elif module_id == "insulation":
        ans = {"wall_sqft": t["exterior_wall_sqft"], "attic_sqft": t["ceiling_sqft"]}
        src = {"wall_sqft": "exterior walls x height, less their doors and windows",
               "attic_sqft": "ceiling area under the attic (all rooms; check for a second floor)"}
    elif module_id == "flooring":
        ans = {"area_sqft": t["floor_sqft"], "baseboard_lf": t["base_lf"]}
        src = {"area_sqft": "room floor areas", "baseboard_lf": "room perimeters less door widths"}
    else:
        raise InvalidInput(f"the wall-and-room model gives answers for {', '.join(WALL_TRADES)}", module_id=module_id)
    return {"ok": True, "module_id": module_id, "model_key": model["model_key"], "answers": ans, "from": src,
            "notes": notes + model["notes"]}
