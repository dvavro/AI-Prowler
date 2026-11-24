"""Draw an electrical design as CAD (2026-11-21, David: AI design on the Measure screen).

Two DXF drawings at full size in feet ($INSUNITS = 2), the same way a designer's CAD set comes in, so the plan engine
reads the symbols (estimator/plan_engine/symbol_library.py) and the wiring run reads the circuits
(estimator/takeoff/wiring.py):

  plan   the building (exterior walls with their door gaps, interior walls, doors, windows, room names), every device
         the design placed - each symbol carries a CIRCUIT attribute, so the wiring run puts it on the circuit the design
         chose - a home run per circuit to the panel (or the riser on an upper floor) with its label, the feeder of a
         subpanel, a legend of the symbols used, the design's notes and a title block. Floors side by side, titled.
  panel  the panel schedule (CIRCUIT / DESCRIPTION / AMPS / POLES / WIRE, MAIN row), the panel elevation, which
         circuits each floor gets (the riser boxes) and a title block.

The design places the symbols; drawing only tidies them: a wall device sits 0.7 ft off its wall, facing it, and slides
out of a door opening. Every such move is reported back so the checks can say so.
"""
from __future__ import annotations

import math
import re
from collections import Counter

INSET = 0.7                      # a wall device's distance off its wall
SNAP_REACH = 3.0                 # a wall device farther than this from every wall is left where it was put (and flagged)
FLOOR_GAP = 25.0                 # space between floors drawn side by side

# The AI's device types: (block, layer, mount, legend label). mount: wall (on the inside of a wall), exterior (outside an
# exterior wall), ceiling (where it was put). The block names are ones the symbol library reads (see test SD-01).
DEVICES = {
    "outlet": ("OUTLET", "E-OUTLET", "wall", "DUPLEX RECEPTACLE 20A"),
    "outlet_gfci": ("OUTLET_GFCI", "E-OUTLET-GFCI", "wall", "GFCI RECEPTACLE"),
    "outlet_wp": ("OUTLET_WP", "E-OUTLET-GFCI", "exterior", "WEATHERPROOF GFCI RECEPTACLE (WP)"),
    "outlet_usb": ("OUTLET_USB", "E-OUTLET", "wall", "DUPLEX RECEPTACLE WITH USB"),
    "outlet_quad": ("FOURPLEX", "E-OUTLET", "wall", "QUAD RECEPTACLE"),
    "outlet_240": ("PWR_240", "E-POWER", "wall", "240V RECEPTACLE"),
    "range_outlet": ("RANGE_RECEPT", "E-POWER", "wall", "RANGE RECEPTACLE (NEMA 14-50R)"),
    "dryer_outlet": ("DRYER_RECEPT", "E-POWER", "wall", "DRYER RECEPTACLE (NEMA 14-30R)"),
    "ev_charger": ("EVSE", "E-POWER", "wall", "EV CHARGER"),
    "disconnect": ("DISCONNECT", "E-POWER", "wall", "DISCONNECT SWITCH"),
    "switch": ("SWITCH", "E-SWITCH", "wall", "SINGLE-POLE SWITCH"),
    "switch_3way": ("SWITCH_3WAY", "E-SWITCH", "wall", "3-WAY SWITCH"),
    "switch_4way": ("SWITCH_4WAY", "E-SWITCH", "wall", "4-WAY SWITCH"),
    "switch_dimmer": ("SWITCH_DIM", "E-SWITCH", "wall", "DIMMER SWITCH"),
    "light": ("LIGHT_CEIL", "E-LIGHT", "ceiling", "CEILING LIGHT"),
    "light_led": ("LIGHT_LED", "E-LIGHT", "ceiling", "LED STRIP / SHOP LIGHT"),
    "light_recessed": ("LIGHT_REC", "E-LIGHT", "ceiling", "RECESSED LIGHT"),
    "light_pendant": ("LIGHT_PEND", "E-LIGHT", "ceiling", "PENDANT LIGHT"),
    "light_wall": ("LIGHT_WALL", "E-LIGHT", "wall", "WALL LIGHT (SCONCE)"),
    "light_undercabinet": ("LIGHT_UC", "E-LIGHT", "wall", "UNDER-CABINET LIGHT"),
    "light_exterior": ("LIGHT_EXT", "E-LIGHT", "exterior", "EXTERIOR LIGHT"),
    "fan": ("FAN", "E-FAN", "ceiling", "CEILING FAN"),
    "exhaust_fan": ("FAN_EXH", "E-FAN", "ceiling", "EXHAUST FAN"),
    "smoke": ("SMOKE", "E-ALARM", "ceiling", "SMOKE DETECTOR"),
    "smoke_co": ("SMOKE_CO", "E-ALARM", "ceiling", "SMOKE / CO DETECTOR"),
    "junction_box": ("JBOX", "E-POWER", "ceiling", "JUNCTION BOX"),
    "data": ("DATA", "E-LOWVOLT", "wall", "DATA OUTLET"),
    "tv": ("CATV", "E-LOWVOLT", "wall", "TV OUTLET"),
}
WALL_LIGHTS = {"light_wall", "light_exterior", "light_undercabinet"}     # flat side to the wall
LAYERS = (("A-WALL-EXT", 7), ("A-WALL-INT", 8), ("A-DOOR", 8), ("A-WINDOW", 8), ("A-TEXT", 7), ("E-OUTLET", 1),
          ("E-OUTLET-GFCI", 1), ("E-POWER", 1), ("E-SWITCH", 6), ("E-LIGHT", 4), ("E-FAN", 5), ("E-ALARM", 30),
          ("E-LOWVOLT", 3), ("E-PANEL", 1), ("E-CIRCUIT", 9), ("E-FEEDER", 1), ("E-TITLE", 7), ("G-NOTE", 7),
          ("E-LEGEND", 7))       # 2026-11-23: the legend's samples - never counted as devices (plan_engine.symbols)
FLOOR_TITLES = ("GROUND", "SECOND", "THIRD")


def panel_block(panel: dict) -> str:
    amps = int(panel.get("amps") or 100)
    return f"SUBPANEL_{amps}A" if (panel.get("kind") or "").lower().startswith("sub") else f"PANEL_{amps}A"


# ------------------------------------------------------------------ blocks
def _blocks(doc, panel_name: str):
    from ezdxf.enums import TextEntityAlignment as TEA

    def att(b):                                  # the circuit the design put the device on
        b.add_attdef("CIRCUIT", (0.45, 0.45), dxfattribs={"height": 0.25, "flags": 1})   # 1 = invisible

    def outlet(b):
        b.add_circle((0, 0), 0.30)
        b.add_line((-0.18, 0.30), (-0.18, 0.70))
        b.add_line((0.18, 0.30), (0.18, 0.70))

    def sw(b):
        b.add_arc((0, 0.18), 0.22, 90, 270)
        b.add_arc((0, -0.18), 0.22, 270, 90)
        b.add_line((0, 0.45), (0, 0.70))

    def mark(b, s, h=0.24, y=-0.7):
        b.add_text(s, dxfattribs={"height": h}).set_placement((0, y), align=TEA.MIDDLE_CENTER)

    def sq(b, r):
        b.add_lwpolyline([(-r, -r), (r, -r), (r, r), (-r, r)], close=True)

    shapes = {
        "OUTLET": lambda b: outlet(b),
        "OUTLET_GFCI": lambda b: (outlet(b), sq(b, 0.42), mark(b, "G", 0.28, -0.62)),
        "OUTLET_WP": lambda b: (outlet(b), b.add_circle((0, 0), 0.52), mark(b, "WP", 0.24, -0.72)),
        "OUTLET_USB": lambda b: (outlet(b), mark(b, "USB", 0.2, -0.55)),
        "FOURPLEX": lambda b: (outlet(b), b.add_line((-0.3, 0), (0.3, 0)), mark(b, "4", 0.22, -0.55)),
        "PWR_240": lambda b: (b.add_circle((0, 0), 0.40), b.add_lwpolyline([(0, 0.25), (-0.22, -0.15), (0.22, -0.15)],
                              close=True), b.add_line((-0.18, 0.40), (-0.18, 0.75)), b.add_line((0.18, 0.40), (0.18, 0.75)),
                              mark(b, "240", 0.22, -0.62)),
        "RANGE_RECEPT": lambda b: (b.add_circle((0, 0), 0.40), b.add_line((-0.18, 0.40), (-0.18, 0.75)),
                                   b.add_line((0.18, 0.40), (0.18, 0.75)), mark(b, "R", 0.3, 0)),
        "DRYER_RECEPT": lambda b: (b.add_circle((0, 0), 0.40), b.add_line((-0.18, 0.40), (-0.18, 0.75)),
                                   b.add_line((0.18, 0.40), (0.18, 0.75)), mark(b, "D", 0.3, 0)),
        "EVSE": lambda b: (sq(b, 0.4), mark(b, "EV", 0.28, 0)),
        "DISCONNECT": lambda b: (sq(b, 0.4), b.add_line((-0.4, -0.4), (0.4, 0.4)), mark(b, "DS", 0.22, -0.62)),
        "SWITCH": sw,
        "SWITCH_3WAY": lambda b: (sw(b), b.add_lwpolyline([(0.36, -0.1), (0.54, -0.1), (0.54, 0.1), (0.36, 0.1)],
                                                          close=True)),
        "SWITCH_4WAY": lambda b: (sw(b), b.add_circle((0.45, 0), 0.1)),
        "SWITCH_DIM": lambda b: (sw(b), b.add_lwpolyline([(0.36, -0.12), (0.56, -0.12), (0.46, 0.12)], close=True)),
        "LIGHT_CEIL": lambda b: (b.add_circle((0, 0), 0.40), b.add_line((-0.4, 0), (0.4, 0)), b.add_line((0, -0.4), (0, 0.4))),
        "LIGHT_LED": lambda b: (b.add_lwpolyline([(-2, -0.35), (2, -0.35), (2, 0.35), (-2, 0.35)], close=True),
                                b.add_line((-2, 0), (2, 0))),
        "LIGHT_REC": lambda b: (b.add_circle((0, 0), 0.30), b.add_circle((0, 0), 0.12)),
        "LIGHT_PEND": lambda b: (b.add_circle((0, 0), 0.35), b.add_circle((0, 0), 0.08)),
        "LIGHT_WALL": lambda b: (b.add_arc((0, 0), 0.40, 0, 180), b.add_line((-0.4, 0), (0.4, 0))),
        "LIGHT_UC": lambda b: (b.add_lwpolyline([(-1, 0), (1, 0), (1, 0.25), (-1, 0.25)], close=True)),
        "LIGHT_EXT": lambda b: (b.add_arc((0, 0), 0.40, 0, 180), b.add_line((-0.4, 0), (0.4, 0)),
                                *[b.add_line((d * 1.2, 0.45), (d * 1.8, 0.75)) for d in (-0.35, 0, 0.35)]),
        "FAN": lambda b: (b.add_circle((0, 0), 0.45), *[b.add_line((0, 0), (sx * 0.32, sy * 0.32))
                                                        for sx, sy in ((1, 1), (-1, 1), (1, -1), (-1, -1))]),
        "FAN_EXH": lambda b: (sq(b, 0.35), b.add_line((-0.35, -0.35), (0.35, 0.35)), b.add_line((-0.35, 0.35), (0.35, -0.35))),
        "SMOKE": lambda b: (b.add_circle((0, 0), 0.35), b.add_lwpolyline([(0, 0.18), (0.18, 0), (0, -0.18), (-0.18, 0)],
                                                                         close=True)),
        "SMOKE_CO": lambda b: (b.add_circle((0, 0), 0.35), mark(b, "CO", 0.2, 0)),
        "JBOX": lambda b: (b.add_circle((0, 0), 0.3), mark(b, "J", 0.28, 0)),
        "DATA": lambda b: (b.add_lwpolyline([(0, 0.42), (-0.38, -0.26), (0.38, -0.26)], close=True), b.add_circle((0, -0.02), 0.09)),
        "CATV": lambda b: (b.add_lwpolyline([(0, 0.42), (-0.38, -0.26), (0.38, -0.26)], close=True), mark(b, "TV", 0.16, -0.05)),
    }
    for name, draw in shapes.items():
        b = doc.blocks.new(name)
        draw(b)
        att(b)
    b = doc.blocks.new(panel_name)                                   # the panel: a box, half hatched with lines
    b.add_lwpolyline([(-0.9, -0.4), (0.9, -0.4), (0.9, 0.4), (-0.9, 0.4)], close=True)
    b.add_line((-0.9, -0.4), (0.9, 0.4))
    for t in (0.2, 0.4, 0.6, 0.8):
        b.add_line((-0.9 + 1.8 * t, -0.4), (-0.9 + 1.8 * t, -0.4 + 0.8 * t))


# ------------------------------------------------------------------ geometry
def _seg_foot(p, a, b):
    ax, ay = a
    dx, dy = b[0] - ax, b[1] - ay
    L2 = dx * dx + dy * dy or 1e-12
    t = max(0.0, min(1.0, ((p[0] - ax) * dx + (p[1] - ay) * dy) / L2))
    q = (ax + t * dx, ay + t * dy)
    return math.dist(p, q), t, q


def _inside(p, poly) -> bool:
    x, y, inside = p[0], p[1], False
    n = len(poly)
    for i in range(n):
        x1, y1 = poly[i]
        x2, y2 = poly[(i + 1) % n]
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / ((y2 - y1) or 1e-12) + x1:
            inside = not inside
    return inside


def _edges(floor: dict) -> list[tuple]:
    pts = [tuple(map(float, p)) for p in floor.get("outline") or []]
    out = [(pts[i], pts[(i + 1) % len(pts)], "ext") for i in range(len(pts))] if len(pts) >= 3 else []
    for w in floor.get("interior_walls") or []:
        out.append((tuple(map(float, w[0])), tuple(map(float, w[1])), "int"))
    return out


def _gap_ranges(a, b, openings, kinds=("door", "overhead_door", "opening")) -> list[tuple[float, float, dict]]:
    """Where along wall a-b (0..1) its door openings are."""
    L = math.dist(a, b) or 1e-9
    out = []
    for o in openings:
        if o.get("kind", "door") not in kinds:
            continue
        pa, pb = tuple(map(float, o["a"])), tuple(map(float, o["b"]))
        da, ta, _ = _seg_foot(pa, a, b)
        db, tb, _ = _seg_foot(pb, a, b)
        if da < 0.6 and db < 0.6 and abs(tb - ta) * L > 0.5:
            out.append((min(ta, tb), max(ta, tb), o))
    return sorted(out, key=lambda r: r[0])


def place(dev: dict, floor: dict) -> dict:
    """Where a device is drawn and how it turns: (x, y, rotation, moved note). A wall device goes 0.7 ft off its nearest
    wall on the side the design put it (an exterior one outside), facing the wall, and out of any door opening."""
    kind = DEVICES[dev["type"]][2]
    p = (float(dev["x"]), float(dev["y"]))
    if kind == "ceiling":
        return {"x": p[0], "y": p[1], "rot": 0.0, "moved": ""}
    poly = [tuple(map(float, q)) for q in floor.get("outline") or []]
    edges = [e for e in _edges(floor) if kind == "wall" or e[2] == "ext"]
    if not edges:
        return {"x": p[0], "y": p[1], "rot": 0.0, "moved": ""}
    a, b, which = min(edges, key=lambda e: _seg_foot(p, e[0], e[1])[0])
    d, t, q = _seg_foot(p, a, b)
    if d > SNAP_REACH:
        return {"x": p[0], "y": p[1], "rot": 0.0, "moved": f"not on a wall ({d:.1f} ft from the nearest)"}
    L = math.dist(a, b) or 1e-9
    moved = ""
    for t0, t1, o in _gap_ranges(a, b, floor.get("openings") or []):           # out of a doorway
        if t0 - 0.4 / L < t < t1 + 0.4 / L:
            t = t0 - 1.0 / L if (t - t0) < (t1 - t) and t0 - 1.0 / L > 0 else t1 + 1.0 / L
            t = max(0.02, min(0.98, t))
            moved = f"moved out of the {o.get('label') or o.get('kind', 'door').replace('_', ' ')} opening"
    q = (a[0] + t * (b[0] - a[0]), a[1] + t * (b[1] - a[1]))
    nx, ny = -(b[1] - a[1]) / L, (b[0] - a[0]) / L                             # a normal to the wall
    side = 1.0 if (p[0] - q[0]) * nx + (p[1] - q[1]) * ny >= 0 else -1.0
    if which == "ext" and len(poly) >= 3:                                       # inside or outside, as the mount says
        probe_in = _inside((q[0] + nx * 0.5, q[1] + ny * 0.5), poly)
        want_out = kind == "exterior"
        side = (-1.0 if probe_in else 1.0) if want_out else (1.0 if probe_in else -1.0)
    x, y = q[0] + side * nx * INSET, q[1] + side * ny * INSET
    # +Y of the block points at the wall: the wall is at -side*n from the device
    wx, wy = -side * nx, -side * ny
    rot = math.degrees(math.atan2(wy, wx)) - 90.0
    if dev["type"] in WALL_LIGHTS:
        rot += 180.0                                                             # flat side to the wall
    if not moved and math.dist(p, (x, y)) > 1.5:
        moved = f"moved {math.dist(p, (x, y)):.1f} ft onto the wall"
    return {"x": round(x, 3), "y": round(y, 3), "rot": round(rot % 360, 1), "moved": moved}


# ------------------------------------------------------------------ the plan
def _text(msp, s, x, y, h, layer, align="MIDDLE_LEFT", rot=0.0):
    from ezdxf.enums import TextEntityAlignment as TEA
    msp.add_text(str(s), dxfattribs={"height": h, "layer": layer, "rotation": rot}).set_placement(
        (x, y), align=TEA[align])


def _wrap(s: str, n: int = 105) -> list[str]:
    words, lines, cur = str(s).split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > n:
            lines.append(cur)
            cur = "   " + w
        else:
            cur = (cur + " " + w).strip() if cur.strip() else ("   " + w if lines else w)
    if cur:
        lines.append(cur)
    return lines


def floor_offsets(building: dict) -> list[float]:
    xs, at = [], 0.0
    for f in building["floors"]:
        xs.append(at)
        pts = f.get("outline") or [[0, 0]]
        at += max(float(p[0]) for p in pts) - min(float(p[0]) for p in pts) + FLOOR_GAP
    return xs


def draw_plan(building: dict, design: dict, out_path: str, title: str = "") -> dict:
    """The electrical plan DXF. Returns {path, placed: [{device index, x, y, rot, moved}], counts}."""
    import ezdxf
    doc = ezdxf.new("R2010", setup=True)
    doc.header["$INSUNITS"] = 2
    for name, color in LAYERS:
        doc.layers.add(name, color=color)
    panel = design.get("panel") or {}
    pname = panel_block(panel)
    _blocks(doc, pname)
    msp = doc.modelspace()
    offs = floor_offsets(building)
    floors = building["floors"]
    ymax = max(float(p[1]) for f in floors for p in f["outline"])
    ymin = min(float(p[1]) for f in floors for p in f["outline"])
    xmax = offs[-1] + max(float(p[0]) for p in floors[-1]["outline"])

    # -- the building
    for fi, f in enumerate(floors):
        ox = offs[fi]
        for a, b, which in _edges(f):
            gaps = _gap_ranges(a, b, f.get("openings") or [])
            t = 0.0
            layer = "A-WALL-EXT" if which == "ext" else "A-WALL-INT"
            for t0, t1, _ in gaps + [(1.0, 1.0, None)]:
                if t0 > t + 1e-6:
                    msp.add_line((ox + a[0] + t * (b[0] - a[0]), a[1] + t * (b[1] - a[1])),
                                 (ox + a[0] + t0 * (b[0] - a[0]), a[1] + t0 * (b[1] - a[1])), dxfattribs={"layer": layer})
                t = max(t, t1)
        for o in f.get("openings") or []:
            (ax, ay), (bx, by) = map(lambda q: (float(q[0]) + ox, float(q[1])), (o["a"], o["b"]))
            L = math.hypot(bx - ax, by - ay) or 1e-9
            ux, uy = (bx - ax) / L, (by - ay) / L
            kind = o.get("kind", "door")
            if kind == "window":
                nx, ny = -uy * 0.18, ux * 0.18
                msp.add_lwpolyline([(ax + nx, ay + ny), (bx + nx, by + ny), (bx - nx, by - ny), (ax - nx, ay - ny)],
                                   close=True, dxfattribs={"layer": "A-WINDOW"})
            elif kind == "overhead_door":
                nx, ny = -uy * 0.35, ux * 0.35
                poly = [tuple(map(float, q)) for q in f["outline"]]
                if not _inside(((ax + bx) / 2 - ox + nx, (ay + by) / 2 + ny), poly):
                    nx, ny = -nx, -ny
                msp.add_lwpolyline([(ax, ay), (bx, by), (bx + nx, by + ny), (ax + nx, ay + ny)], close=True,
                                   dxfattribs={"layer": "A-DOOR"})
            elif kind == "door":
                poly = [tuple(map(float, q)) for q in f["outline"]]
                nx, ny = -uy, ux
                if len(poly) >= 3 and not _inside(((ax + bx) / 2 - ox + nx * 0.5, (ay + by) / 2 + ny * 0.5), poly):
                    nx, ny = -nx, -ny
                msp.add_line((bx, by), (bx + nx * L, by + ny * L), dxfattribs={"layer": "A-DOOR"})
                start = math.degrees(math.atan2(-uy, -ux))
                end = math.degrees(math.atan2(ny, nx))
                if (end - start) % 360 > 180:
                    start, end = end, start
                msp.add_arc((bx, by), L, start, end, dxfattribs={"layer": "A-DOOR"})
        for r in f.get("rooms") or []:
            cx, cy = (float(r["x0"]) + float(r["x1"])) / 2 + ox, (float(r["y0"]) + float(r["y1"])) / 2
            w = abs(float(r["x1"]) - float(r["x0"]))
            near = [d for d in design.get("devices") or [] if int(d.get("floor") or 0) == fi
                    and math.dist((float(d["x"]) + ox, float(d["y"])), (cx, cy)) < 2.0]
            cy += 2.2 if near else 0.0
            h = max(0.4, min(1.2, (w - 1.0) / max(1, len(r["name"])) / 0.75))
            _text(msp, str(r["name"]).upper(), cx, cy, h, "A-TEXT", "MIDDLE_CENTER")
        if len(floors) > 1 or True:
            ttl = (FLOOR_TITLES[fi] if fi < len(FLOOR_TITLES) else f"FLOOR {fi + 1}") + " FLOOR"
            fx0 = min(float(p[0]) for p in f["outline"]) + ox
            fx1 = max(float(p[0]) for p in f["outline"]) + ox
            _text(msp, f"{ttl} - ELECTRICAL", (fx0 + fx1) / 2, ymax + 5.0, 1.3, "A-TEXT", "MIDDLE_CENTER")

    # -- the devices
    placed, used = [], Counter()
    for i, d in enumerate(design.get("devices") or []):
        fi = int(d.get("floor") or 0)
        if d["type"] not in DEVICES or fi >= len(floors):
            placed.append({"index": i, "skipped": True})
            continue
        pl = place(d, floors[fi])
        block, layer, _, _ = DEVICES[d["type"]]
        ref = msp.add_blockref(block, (pl["x"] + offs[fi], pl["y"]), dxfattribs={"layer": layer, "rotation": pl["rot"]})
        if d.get("circuit"):
            ref.add_auto_attribs({"CIRCUIT": str(d["circuit"]).upper()})
        used[d["type"]] += 1
        placed.append({"index": i, **pl})
    pf = int(panel.get("floor") or 0)
    pp = (float(panel.get("x") or 1.0), float(panel.get("y") or 1.0))
    pl = place({"type": "outlet", "x": pp[0], "y": pp[1]}, floors[pf])               # on its wall, like any wall item
    ppx, ppy = pl["x"] + offs[pf], pl["y"]
    msp.add_blockref(pname, (ppx, ppy), dxfattribs={"layer": "E-PANEL", "rotation": (pl["rot"] + 0) % 360})

    # -- home runs: one per circuit, from its device nearest the panel (or the riser, upstairs), with its label
    by_c: dict[str, list] = {}
    for i, d in enumerate(design.get("devices") or []):
        if d.get("circuit") and not placed[i].get("skipped") and d["type"] not in ("data", "tv"):
            by_c.setdefault(str(d["circuit"]).upper(), []).append((i, d))
    risers = {}
    for k, c in enumerate(design.get("circuits") or []):
        cid = str(c["id"]).upper()
        devs = by_c.get(cid) or []
        if not devs:
            continue
        fl = Counter(int(d.get("floor") or 0) for _, d in devs).most_common(1)[0][0]
        on = [(i, d) for i, d in devs if int(d.get("floor") or 0) == fl]
        if fl == pf:
            home = (ppx, ppy)
        else:
            home = risers.setdefault(fl, (offs[fl] + pp[0] + 2.0, pp[1] + 2.0))
        i0, _ = min(on, key=lambda t: math.dist((placed[t[0]]["x"] + offs[fl], placed[t[0]]["y"]), home))
        sx, sy = placed[i0]["x"] + offs[fl], placed[i0]["y"]
        jog = 0.45 * (k % 6)
        mid = (sx, home[1] + jog) if abs(sx - home[0]) > abs(sy - home[1]) else (home[0] + jog, sy)
        pts = [(sx, sy), mid, home]
        msp.add_lwpolyline(pts, dxfattribs={"layer": "E-CIRCUIT"})
        amps = int(c.get("amps") or 20)
        two = int(c.get("poles") or 1) >= 2 or amps >= 30
        label = f"{cid} {amps}A" if (two and not re.fullmatch(r"C-\d+", cid)) else cid
        lx, ly = (pts[0][0] + pts[1][0]) / 2, (pts[0][1] + pts[1][1]) / 2
        _text(msp, label, lx + 0.4, ly + 0.4, 0.6, "E-CIRCUIT")
    for fl, (rx, ry) in risers.items():
        _text(msp, "RISER TO PANEL", rx + 0.6, ry + 0.9, 0.6, "E-CIRCUIT")

    # -- a subpanel's feeder: out through the nearest exterior wall
    if (panel.get("kind") or "").lower().startswith("sub") or panel.get("fed_from"):
        a, b, _ = min([e for e in _edges(floors[pf]) if e[2] == "ext"],
                      key=lambda e: _seg_foot((pl["x"], pl["y"]), e[0], e[1])[0])
        _, _, q = _seg_foot((pl["x"], pl["y"]), a, b)
        L = math.dist(a, b) or 1e-9
        nx, ny = -(b[1] - a[1]) / L, (b[0] - a[0]) / L
        if _inside((q[0] + nx, q[1] + ny), [tuple(map(float, p)) for p in floors[pf]["outline"]]):
            nx, ny = -nx, -ny
        end = (q[0] + nx * 6.0 + offs[pf], q[1] + ny * 6.0)
        msp.add_lwpolyline([(ppx, ppy), (q[0] + offs[pf], q[1]), end],
                           dxfattribs={"layer": "E-FEEDER", "linetype": "DASHED"})
        words = ["FEEDER FROM", str(panel.get("fed_from") or "SUPPLY PANEL").upper()[:40]]
        if panel.get("feeder"):
            words.append(str(panel["feeder"]).upper()[:40])
        align = "MIDDLE_RIGHT" if nx < -0.5 else "MIDDLE_LEFT"
        tx = end[0] + (-0.5 if nx < -0.5 else 0.5)
        for j, w in enumerate(words):
            _text(msp, w, tx, end[1] + 0.9 - j * 0.9 + ny * 1.5, 0.55, "E-FEEDER", align)

    # -- legend, notes, title (below the plans: outside every floor, so none of it is read as a room or a device)
    y = ymin - 9.0
    # 2026-11-23: the samples sit on the E-LEGEND layer (so the plan reader never counts them as devices) and close
    # under the title, so a reader that finds legends by their title and rows finds this one too
    _text(msp, "LEGEND", 0, y, 1.1, "E-LEGEND")
    msp.add_line((0, y - 0.8), (max(xmax, 60), y - 0.8), dxfattribs={"layer": "E-LEGEND"})
    kinds = [t for t in DEVICES if used[t]]
    rows = (len(kinds) + 2) // 2 + 1
    for j, t in enumerate(kinds + ["__panel"]):
        col, row = divmod(j, rows)
        lx, ly = 2 + col * 34, y - 1.8 - row * 1.5
        if t == "__panel":
            msp.add_blockref(pname, (lx, ly), dxfattribs={"layer": "E-LEGEND"})
            _text(msp, f"{int(panel.get('amps') or 100)}A {'SUBPANEL' if pname.startswith('SUB') else 'PANEL'}",
                  lx + 2.6, ly, 0.65, "E-LEGEND")
            continue
        block, _layer, _, lab = DEVICES[t]
        msp.add_blockref(block, (lx, ly), dxfattribs={"layer": "E-LEGEND"})
        _text(msp, lab, lx + 2.6, ly, 0.65, "E-LEGEND")
    y -= 4.0 + rows * 1.5
    notes = [n for n in (design.get("code_notes") or []) if str(n).strip()] + \
            ["ASSUMED: " + str(a) for a in (design.get("assumptions") or []) if str(a).strip()]
    notes.append("AI DESIGN FOR ESTIMATING - A LICENSED ELECTRICIAN AND THE LOCAL AUTHORITY CONFIRM THE FINAL LAYOUT.")
    _text(msp, "NOTES", 0, y, 1.1, "E-TITLE")
    y -= 1.6
    for n, note in enumerate(notes[:16], 1):
        for line in _wrap(f"{n}. {str(note).upper()}"):
            _text(msp, line, 0, y, 0.55, "E-TITLE")
            y -= 0.95
    y -= 1.5
    msp.add_lwpolyline([(0, y), (max(xmax, 60), y), (max(xmax, 60), y - 3.4), (0, y - 3.4)], close=True,
                       dxfattribs={"layer": "E-TITLE"})
    _text(msp, (title or "ELECTRICAL PLAN").upper()[:70], 1, y - 1.1, 1.0, "E-TITLE")
    _text(msp, "AI DESIGN - PROPOSED  |  DRAWN AT FULL SIZE IN FEET  |  E-1", 1, y - 2.5, 0.6, "E-TITLE")
    doc.saveas(out_path)
    return {"path": out_path, "placed": placed, "counts": dict(used)}


# ------------------------------------------------------------------ the panel schedule
def schedule_rows(design: dict) -> tuple[list, tuple]:
    panel = design.get("panel") or {}
    rows = [(str(c["id"]).upper(), str(c.get("description") or "")[:40], int(c.get("amps") or 20),
             int(c.get("poles") or 1), str(c.get("wire") or "12/2")) for c in design.get("circuits") or []]
    sub = (panel.get("kind") or "").lower().startswith("sub")
    amps = int(panel.get("amps") or 100)
    main = ("MAIN", f"{amps}A main bkr - {'subpanel disconnect' if sub else 'service'}", amps, 2,
            ("4-wire feeder" if sub else "Service entrance"))
    return rows, main


def draw_panel(design: dict, out_path: str, title: str = "") -> str:
    import ezdxf
    doc = ezdxf.new("R2010")
    doc.header["$INSUNITS"] = 2
    for name, color in (("E-PANEL", 1), ("E-BREAKER", 5), ("E-SCHEDULE", 3), ("E-RISER", 6), ("E-TEXT", 7), ("A-TITLE", 8)):
        doc.layers.add(name, color=color)
    msp = doc.modelspace()
    panel = design.get("panel") or {}
    rows, main = schedule_rows(design)
    sub = (panel.get("kind") or "").lower().startswith("sub")

    def t(s, x, y, h, align="MIDDLE_LEFT"):
        _text(msp, s, x, y, h, "E-TEXT", align)

    # schedule (columns as gen_panel_wiring: the reader matches the headings and the cells by the table's lines)
    top, rh, x0, x1 = 60.0, 1.1, 24.0, 66.0
    allr = rows + [main]
    bottom = top - (len(allr) + 1) * rh
    t("PANEL SCHEDULE", 24, top + 1.3, 0.9)
    cols = [("CIRCUIT", 24, 31), ("DESCRIPTION", 31, 50), ("AMPS", 50, 54), ("POLES", 54, 58), ("WIRE", 58, 66)]
    for _, a, _b in cols:
        msp.add_line((a, bottom), (a, top), dxfattribs={"layer": "E-SCHEDULE"})
    msp.add_line((x1, bottom), (x1, top), dxfattribs={"layer": "E-SCHEDULE"})
    for i in range(len(allr) + 2):
        msp.add_line((x0, top - i * rh), (x1, top - i * rh), dxfattribs={"layer": "E-SCHEDULE"})
    for name, a, b in cols:
        t(name, (a + b) / 2, top - rh / 2, 0.55, "MIDDLE_CENTER")
    for j, r in enumerate(allr):
        cy = top - (j + 1.5) * rh
        t(r[0], 27.5, cy, 0.5, "MIDDLE_CENTER")
        t(r[1], 31.4, cy, 0.42)
        t(str(r[2]), 52, cy, 0.5, "MIDDLE_CENTER")
        t(str(r[3]), 56, cy, 0.5, "MIDDLE_CENTER")
        t(r[4], 62, cy, 0.42, "MIDDLE_CENTER")
    # the panel elevation: main on top, breakers in two columns
    amps = int(panel.get("amps") or 100)
    n = len(rows)
    half = (n + 1) // 2
    ptop, pbot = top, top - 4.0 - max(1, half) * 1.6
    msp.add_lwpolyline([(2, pbot), (20, pbot), (20, ptop), (2, ptop)], close=True, dxfattribs={"layer": "E-PANEL"})
    t(f"{amps}A {'SUBPANEL' if sub else 'MAIN PANEL'}", 2, ptop + 1.3, 0.9)
    msp.add_lwpolyline([(3, ptop - 2.6), (19, ptop - 2.6), (19, ptop - 0.6), (3, ptop - 0.6)], close=True,
                       dxfattribs={"layer": "E-BREAKER"})
    t(f"MAIN - {amps}A 2-POLE" + (" (DISCONNECT)" if sub else ""), 11, ptop - 1.6, 0.55, "MIDDLE_CENTER")
    for j, r in enumerate(rows):
        col, row = divmod(j, half)
        bx = 3 + col * 8.2
        by = ptop - 4.2 - row * 1.6
        msp.add_lwpolyline([(bx, by), (bx + 7.8, by), (bx + 7.8, by + 1.3), (bx, by + 1.3)], close=True,
                           dxfattribs={"layer": "E-BREAKER"})
        t(f"{r[0]} {r[2]}A{' 2P' if r[3] >= 2 else ''}", bx + 3.9, by + 0.65, 0.45, "MIDDLE_CENTER")
    if sub:
        t("NEUTRAL AND GROUND BARS NOT BONDED (SUBPANEL)", 2, pbot - 1.0, 0.45)
    # which circuits each floor gets (the riser boxes the wiring run reads)
    floors: dict[int, list[str]] = {}
    for c in design.get("circuits") or []:
        if re.fullmatch(r"C-\d+", str(c["id"]).upper()):
            floors.setdefault(int(c.get("floor") or 0), []).append(str(c["id"]).upper())
    ry = bottom - 3.0
    for fl, ids in sorted(floors.items()):
        name = (FLOOR_TITLES[fl] if fl < len(FLOOR_TITLES) else f"FLOOR {fl + 1}") + " FLOOR"
        msp.add_lwpolyline([(48, ry - 3.4), (66, ry - 3.4), (66, ry), (48, ry)], close=True, dxfattribs={"layer": "E-RISER"})
        t(name, 57, ry - 0.8, 0.55, "MIDDLE_CENTER")
        for k in range(0, len(ids), 6):
            t("  ".join(ids[k:k + 6]), 57, ry - 1.9 - (k // 6) * 0.9, 0.45, "MIDDLE_CENTER")
        ry -= 4.4
    if sub or panel.get("fed_from"):
        t("FED FROM: " + str(panel.get("fed_from") or "supply panel").upper()[:50], 24, bottom - 1.4, 0.5)
        fb = panel.get("feeder_breaker_amps")
        t(("FEEDER: " + str(panel.get("feeder") or "4-wire")).upper()[:60]
          + (f"  |  FEEDER BREAKER {int(fb)}A 2P (CONFIRM BY LOAD CALC)" if fb else ""), 24, bottom - 2.3, 0.45)
    yb = min(pbot, ry) - 4.0
    msp.add_lwpolyline([(0, yb), (68, yb), (68, yb + 3.4), (0, yb + 3.4)], close=True, dxfattribs={"layer": "A-TITLE"})
    t(((title or "") + " - PANEL SCHEDULE").strip(" -").upper()[:70], 1, yb + 2.3, 0.9)
    t("AI DESIGN - PROPOSED  |  DRAWN AT FULL SIZE IN FEET  |  E-2", 1, yb + 0.9, 0.55)
    doc.saveas(out_path)
    return out_path
