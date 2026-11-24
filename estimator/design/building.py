"""The building a design goes on (2026-11-21, David: AI design - "here's my shed drawings, I want to add electricity").

One shape for every source, in feet, origin at the front-left outside corner of the ground floor, x along the front
wall, y toward the rear:

    {"name": "...", "kind": "accessory" | "dwelling" | "commercial", "source": "dxf" | "ai", "notes": "...",
     "floors": [{"name": "GROUND", "ceiling_ft": 9,
                 "outline": [[x, y], ...],                                   the exterior walls, in order
                 "openings": [{"kind": "door" | "overhead_door" | "window" | "opening", "a": [x, y], "b": [x, y],
                               "label": "12'x12' roll-up"}],                 on the walls
                 "interior_walls": [[[x, y], [x, y]], ...],
                 "rooms": [{"name": "SHOP", "x0": 0, "y0": 0, "x1": 46, "y1": 45}]}]}

from_dxf reads a CAD drawing (exterior walls on a WALL+EXT layer, door gaps and DOOR-layer items, WINDOW-layer items,
room names on A- layers) - plain geometry, no AI. from_sheets has the AI read the plan set's sheet images (a PDF, a
scan, a photo) - one vision call with up to four sheets and the dimension labels the plan engine found, answered as the
JSON above; the app checks the answer before anything is drawn on it.
"""
from __future__ import annotations

import json
import math
import re

KINDS = ("door", "overhead_door", "window", "opening")
MAX_FT = 600.0
READ_SYSTEM = ("You read construction drawings (floor plans, elevations, foundation plans) and describe the building's "
               "walls, doors, windows and rooms in feet. Reply with ONLY one JSON object, nothing else.")
READ_MAX_SHEETS = 4
READ_MAX_PX = 1600


class BuildingError(Exception):
    """The building couldn't be read. The message is safe to show."""


# ------------------------------------------------------------------ checking a building (any source)
def _pt(v, what):
    if not isinstance(v, (list, tuple)) or len(v) != 2:
        raise BuildingError(f"{what} isn't an [x, y] point")
    try:
        x, y = float(v[0]), float(v[1])
    except (TypeError, ValueError):
        raise BuildingError(f"{what} isn't an [x, y] point") from None
    if not (math.isfinite(x) and math.isfinite(y)) or abs(x) > MAX_FT or abs(y) > MAX_FT:
        raise BuildingError(f"{what} ({x}, {y}) is off the building")
    return [round(x, 2), round(y, 2)]


def clean(b: dict, source: str) -> dict:
    """A building checked and tidied: numbers, at least a 3-corner outline per floor, known opening kinds."""
    if not isinstance(b, dict) or not isinstance(b.get("floors"), list) or not b["floors"]:
        raise BuildingError("no floors were read")
    floors = []
    for fi, f in enumerate(b["floors"][:4]):
        if not isinstance(f, dict):
            raise BuildingError(f"floor {fi + 1} isn't an object")
        outline = [_pt(p, f"floor {fi + 1} outline corner") for p in f.get("outline") or []]
        if len(outline) < 3:
            raise BuildingError(f"floor {fi + 1} has no outline (its exterior walls)")
        xs, ys = [p[0] for p in outline], [p[1] for p in outline]
        if max(xs) - min(xs) < 4 or max(ys) - min(ys) < 4:
            raise BuildingError(f"floor {fi + 1} is under 4 ft across - the dimensions weren't read")
        ops = []
        for o in f.get("openings") or []:
            if isinstance(o, dict) and o.get("a") is not None and o.get("b") is not None:
                kind = str(o.get("kind") or "door").lower().replace(" ", "_")
                kind = "overhead_door" if kind in ("garage_door", "roll_up", "rollup", "roll-up", "overhead") else kind
                ops.append({"kind": kind if kind in KINDS else "door", "a": _pt(o["a"], "an opening"),
                            "b": _pt(o["b"], "an opening"), "label": str(o.get("label") or "")[:40]})
        walls = []
        for w in f.get("interior_walls") or []:
            if isinstance(w, (list, tuple)) and len(w) == 2:
                walls.append([_pt(w[0], "an interior wall"), _pt(w[1], "an interior wall")])
        rooms = []
        for r in f.get("rooms") or []:
            if isinstance(r, dict) and r.get("name"):
                try:
                    x0, y0, x1, y1 = (float(r[k]) for k in ("x0", "y0", "x1", "y1"))
                except (KeyError, TypeError, ValueError):
                    continue
                rooms.append({"name": str(r["name"]).strip().upper()[:30], "x0": round(min(x0, x1), 2),
                              "y0": round(min(y0, y1), 2), "x1": round(max(x0, x1), 2), "y1": round(max(y0, y1), 2)})
        if not rooms:                                       # one room: the whole floor
            rooms = [{"name": str(b.get("name") or "ROOM").upper()[:30] if len(b["floors"]) == 1 else "FLOOR",
                      "x0": min(xs), "y0": min(ys), "x1": max(xs), "y1": max(ys)}]
        try:
            ceil = float(f.get("ceiling_ft") or 9)
        except (TypeError, ValueError):
            ceil = 9.0
        floors.append({"name": str(f.get("name") or ("GROUND" if fi == 0 else f"FLOOR {fi + 1}")).upper()[:20],
                       "ceiling_ft": max(7.0, min(40.0, ceil)), "outline": outline, "openings": ops,
                       "interior_walls": walls, "rooms": rooms})
    kind = str(b.get("kind") or "").lower()
    if kind not in ("accessory", "dwelling", "commercial"):
        kind = "accessory" if re.search(r"SHED|SHOP|BARN|GARAGE|WORKSHOP|STORAGE|POLE",
                                        json.dumps(b).upper()) and len(floors) == 1 else "dwelling"
    return {"name": str(b.get("name") or "Building")[:60], "kind": kind, "source": source,
            "notes": str(b.get("notes") or "")[:600], "floors": floors}


def size_line(b: dict) -> str:
    f = b["floors"][0]
    xs, ys = [p[0] for p in f["outline"]], [p[1] for p in f["outline"]]
    return f"{max(xs) - min(xs):g}' x {max(ys) - min(ys):g}'" + (f", {len(b['floors'])} floors" if len(b["floors"]) > 1 else "")


# ------------------------------------------------------------------ from a CAD drawing
def _ray(p, d, segs):
    """Distance from p along direction d to the nearest segment, or None."""
    best = None
    for (ax, ay), (bx, by) in segs:
        ex, ey = bx - ax, by - ay
        den = d[0] * ey - d[1] * ex
        if abs(den) < 1e-9:
            continue
        t = ((ax - p[0]) * ey - (ay - p[1]) * ex) / den
        u = ((ax - p[0]) * d[1] - (ay - p[1]) * d[0]) / den
        if t > 0.05 and -1e-6 <= u <= 1 + 1e-6 and (best is None or t < best):
            best = t
    return best


def from_dxf(path: str, name: str = "") -> dict:
    """The building from a CAD floor plan: each floor's exterior walls (their bounding outline), door gaps and DOOR
    items as openings, WINDOW items, interior walls, and rooms from their names (each room reaches to the nearest wall
    on every side)."""
    import ezdxf
    from estimator.takeoff import wiring
    doc = ezdxf.readfile(path)
    msp = doc.modelspace()
    k = wiring._units_to_ft(doc)
    floors = wiring._floors(msp, k)
    if not floors:
        raise BuildingError("the drawing has no exterior walls (lines on a WALL layer)")

    def segs(layer_test):
        out = []
        for e in msp.query("LINE LWPOLYLINE"):
            lay = e.dxf.layer.upper()
            if not layer_test(lay):
                continue
            if e.dxftype() == "LINE":
                pts = [(e.dxf.start.x * k, e.dxf.start.y * k), (e.dxf.end.x * k, e.dxf.end.y * k)]
            else:
                pts = [(p[0] * k, p[1] * k) for p in e.get_points()]
                if e.closed:
                    pts.append(pts[0])
            out += [(pts[i], pts[i + 1]) for i in range(len(pts) - 1)]
        return out
    ext = segs(lambda l: "WALL" in l and "INT" not in l)
    inn = segs(lambda l: "WALL" in l and "INT" in l)
    win_items = segs(lambda l: "WIND" in l or "GLAZ" in l)
    texts = [(wiring._text(e), e.dxf.insert.x * k, e.dxf.insert.y * k, e.dxf.layer.upper())
             for e in msp.query("TEXT MTEXT")]
    out = []
    for f in floors:
        fx, fy = f.x0, f.y0

        def loc(p, fx=fx, fy=fy):                                      # each floor in its own feet, from its corner
            return [round(p[0] - fx, 2), round(p[1] - fy, 2)]
        w, h = f.x1 - f.x0, f.y1 - f.y0
        corners = [(f.x0, f.y0), (f.x1, f.y0), (f.x1, f.y1), (f.x0, f.y1)]
        my_ext = [s for s in ext if all(f.holds(*p, slack=1.0) for p in s)]
        openings = []
        for i in range(4):                                              # gaps along each side of the outline
            a, b = corners[i], corners[(i + 1) % 4]
            L = math.dist(a, b)
            cover = []
            for s0, s1 in my_ext:
                if _near_line(s0, a, b) < 0.8 and _near_line(s1, a, b) < 0.8:
                    t0, t1 = sorted((_along(s0, a, b), _along(s1, a, b)))
                    cover.append((max(0, t0), min(L, t1)))
            cover.sort()
            at = 0.0
            for c0, c1 in cover + [(L, L)]:
                if c0 - at >= 2.0:
                    pa = (a[0] + (b[0] - a[0]) * at / L, a[1] + (b[1] - a[1]) * at / L)
                    pb = (a[0] + (b[0] - a[0]) * c0 / L, a[1] + (b[1] - a[1]) * c0 / L)
                    width = c0 - at
                    kind = "overhead_door" if width >= 7.0 else "door"
                    openings.append({"kind": kind, "a": loc(pa), "b": loc(pb),
                                     "label": f"{width:.0f}' {'overhead door' if kind == 'overhead_door' else 'door'}"})
                at = max(at, c1)
        for s0, s1 in win_items:                                        # windows: the long side of each window mark
            if f.holds(*s0, slack=1.0) and math.dist(s0, s1) >= 1.0 and \
                    min(_near_rect(s0, corners), _near_rect(s1, corners)) < 0.6:
                openings.append({"kind": "window", "a": loc(s0), "b": loc(s1), "label": "window"})
        walls = [[loc(s0), loc(s1)] for s0, s1 in inn if f.holds(*s0, slack=0.5) and f.holds(*s1, slack=0.5)]
        allw = my_ext + [(tuple(s0), tuple(s1)) for s0, s1 in inn if f.holds(*s0, slack=0.5)] + \
            [(corners[i], corners[(i + 1) % 4]) for i in range(4)]
        rooms = []
        for t, x, y, lay in texts:
            u = t.upper().strip()
            if not lay.startswith("A-") or not f.holds(x, y, slack=0.0) or "'" in t or '"' in t or "FLOOR" in u \
                    or not re.search(r"[A-Z]{3}", u):
                continue
            r = [_ray((x, y), d, allw) for d in ((1, 0), (-1, 0), (0, 1), (0, -1))]
            if None in r:
                continue
            rooms.append({"name": u[:30], "x0": round(x - r[1] - fx, 2), "y0": round(y - r[3] - fy, 2),
                          "x1": round(x + r[0] - fx, 2), "y1": round(y + r[2] - fy, 2)})
        out.append({"name": f.name.split()[0].upper(), "outline": [[0, 0], [round(w, 2), 0], [round(w, 2), round(h, 2)],
                                                                   [0, round(h, 2)]],
                    "openings": openings, "interior_walls": walls, "rooms": rooms})
    return clean({"name": name or "Building", "floors": out,
                  "notes": "read from the CAD drawing's walls (the outline is each floor's outside rectangle)"}, "dxf")


def _along(p, a, b):
    L = math.dist(a, b) or 1e-9
    return ((p[0] - a[0]) * (b[0] - a[0]) + (p[1] - a[1]) * (b[1] - a[1])) / L


def _near_line(p, a, b):
    L = math.dist(a, b) or 1e-9
    return abs((b[0] - a[0]) * (a[1] - p[1]) - (a[0] - p[0]) * (b[1] - a[1])) / L


def _near_rect(p, corners):
    return min(_near_line(p, corners[i], corners[(i + 1) % 4]) for i in range(4))


# ------------------------------------------------------------------ from the sheets, read by the AI
def read_prompt(sheets: list[dict], hints: list[str], request: str) -> str:
    listed = "\n".join(f"{i + 1}. sheet {s['id']} ({s.get('sheet_no') or 'page ' + str(s.get('page_no'))}"
                       f"{' ' + repr(s['title']) if s.get('title') else ''})" for i, s in enumerate(sheets))
    return (
        "These are sheets of one plan set, in order:\n" + listed
        + ("\nDimension and text labels found on them: " + "; ".join(hints) if hints else "")
        + "\n\nSomeone wants to design new work on this building: " + request.strip()[:400]
        + "\n\nDescribe the building so the work can be laid out on it. Use the dimensions written on the drawings"
          " (plans are often not to scale - never measure off the picture when a dimension is written). Put the"
          " origin at the FRONT-LEFT outside corner of the ground floor; x runs along the front wall, y toward the"
          " rear, in feet. For each floor give its outline (the outside face of the exterior walls, corners in order),"
          " its openings as segments on those walls (doors, overhead / roll-up doors, windows - with their written"
          " sizes in the label), interior walls as segments, and its rooms as rectangles with their names (an open"
          " shop or shed is one room). Say what kind of building it is: accessory (shed, shop, barn, detached"
          " garage), dwelling or commercial."
          "\nReply with ONLY this JSON:\n"
          '{"name": "e.g. 46x45 metal shop", "kind": "accessory", "notes": "what you read and anything unclear",'
          ' "floors": [{"name": "GROUND", "ceiling_ft": 15, "outline": [[0,0],[46,0],[46,45],[0,45]],'
          ' "openings": [{"kind": "overhead_door", "a": [2,0], "b": [14,0], "label": "12x12 roll-up"},'
          ' {"kind": "door", "a": [0,1], "b": [0,4], "label": "3-0 walk door"},'
          ' {"kind": "window", "a": [0,11.25], "b": [0,13.75], "label": "window"}],'
          ' "interior_walls": [], "rooms": [{"name": "SHOP", "x0": 0, "y0": 0, "x1": 46, "y1": 45}]}],'
          ' "confidence": 0.8}'
          "\nIf a dimension can't be read, give your best reading and say so in notes - never leave the outline out.")


def parse_reading(text: str) -> dict:
    from estimator.takeoff.llm_takeoff import LlmTakeoffError, _parse_json_object
    try:
        obj = _parse_json_object(text)
    except LlmTakeoffError as exc:
        raise BuildingError(str(exc)) from None
    b = clean(obj, "ai")
    try:
        b["confidence"] = max(0.0, min(1.0, float(obj.get("confidence")))) if obj.get("confidence") is not None else None
    except (TypeError, ValueError):
        b["confidence"] = None
    return b


def plan_sheets(conn, company_id: str, plan_set_id: int) -> list[dict]:
    """The plan set's sheets with a picture, plan views first (titles naming a plan or layout), at most four."""
    from estimator.takeoff import llm_takeoff as lt
    rows = lt._sheets_with_images(conn, company_id, plan_set_id)

    def score(s):
        t = (s.get("title") or "").lower()
        return (0 if re.search(r"floor|plan|layout|foundation", t) else 1, s["page_no"])
    return sorted(rows, key=score)[:READ_MAX_SHEETS]
