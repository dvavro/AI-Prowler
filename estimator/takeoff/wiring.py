"""Wiring takeoff: wire lengths and sizes from the electrical floor plan and the panel schedule (2026-11-19, David).

The second Electrical measuring stage, after the device counts. Two drawings go in:

  * the electrical floor plan (DXF, at real size): every device, room names, the floors side by side, the panel,
    the circuit tags (C-1 ...) and the 30 Amp labels (RANGE 30A ...);
  * the panel drawing (DXF): the panel schedule - each circuit's number, what it serves, amps, poles and wire.

What comes out:

  1. every device put on a circuit (room names matched to the schedule, then the nearest circuit tag);
  2. a route for each circuit: a home run from the panel (up a riser for an upper floor), then device to device
     along the shortest tree, square to the walls, through the ceiling (the floor joists above, or the attic) or,
     where there is no ceiling to use, through the walls at box height;
  3. the wire for each circuit at the schedule's size, checked against the breaker (15 A -> 14/2, 20 A -> 12/2,
     30 A -> 10/2), plus 3-way travelers (/3 cable between each pair of 3-way switches), box make-up and waste;
  4. the feet of each cable size to order (and in 250 ft rolls) - the Bill of Materials lines;
  5. a new DXF: the floor plan with each circuit's route on its own layer (E-WIRE-C-1 ...), labelled with its size
     and length, and a wire schedule table.

It is plain geometry - repeatable, no AI tokens. What the drawings can't settle (a device in a room no circuit names
and no tag near it) is listed in "unassigned" for a person (or the AI) to decide.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from estimator.plan_engine import symbol_library as lib

# ------------------------------------------------------------------ settings (each one a default a person can change)
DEFAULTS = {
    "ceiling_ft": 9.0,          # floor to ceiling
    "floor_framing_ft": 1.0,    # floor joists between storeys
    "panel_center_ft": 5.0,     # panel height (center)
    # How the cable runs (2026-11-21, David: "Don't run any electrical through cement slabs, all get routed from
    # basement ceiling" - and the user sets these before a run, with their own defaults):
    "foundation": "basement",   # basement | crawlspace | slab - a slab floor never has cable in it
    "panel_in_basement": True,  # basement: the panel hangs in the basement under where it's drawn
    "basement_ceiling_ft": 8.0, # basement floor to the joists
    "outlets_via": "walls",     # outlets chained: walls (through the studs) | below (floor joists) | above (ceiling)
    "upper_feed": "below",      # upper floors fed through the floor framing under them (below) or the attic (above)
    "wall_max_ft": 15.0,        # an outlet farther along than this (past a door, across a room) goes the feed way
    "receptacle_in": 16.0,      # box heights, inches to the box center
    "switch_in": 48.0,
    "counter_in": 44.0,         # kitchen / bath counter receptacles
    "route": {},                # per floor, forced: floor index -> "ceiling" | "walls" (unset: the options above)
    "wall_run_ft": 1.5,         # a wall route drills through the studs this high
    "wall_detour": 1.15,        # walls go round doors and corners: their runs are this much longer
    "makeup_ft_per_end": 1.0,   # free conductor at each box, per cable end
    "panel_makeup_ft": 3.0,     # inside the panel, per home run
    "waste": 0.10,
    "roll_ft": 250,
}
FOUNDATIONS = ("basement", "crawlspace", "slab")
VIAS = ("walls", "below", "above")

# Where each kind of device sits (feet above its floor). Ceiling items get the ceiling height.
BOX_HEIGHT = {"receptacle": 16 / 12, "wp": 20 / 12, "switch": 4.0, "floor_box": 0.0, "ceiling": None}

RECEPTACLES = {"duplex_receptacle", "duplex_receptacle_usb", "quad_receptacle", "duplex_receptacle_gfci",
               "duplex_receptacle_wp", "floor_box", "receptacle_dedicated"}
SWITCHES = {"switch", "switch_3way", "switch_4way", "switch_dimmer", "switch_occupancy"}
CEILING = {"light_recessed", "light_fixture", "light_pendant", "ceiling_fan", "exhaust_fan", "smoke_detector",
           "smoke_co_detector", "co_detector", "emergency_light", "exit_sign"}
WALL_LIGHTS = {"light_wall", "light_exterior", "light_undercabinet"}
LOW_VOLTAGE = {"data_outlet", "phone_outlet", "tv_outlet", "speaker", "security_camera", "wireless_access_point",
               "doorbell", "motion_sensor", "door_contact", "keypad", "intercom", "card_reader"}

AMPS_WIRE = {15: "14/2", 20: "12/2", 30: "10/2", 40: "8/2", 50: "6/2"}
TRAVELER = {"14/2": "14/3", "12/2": "12/3"}
APPLIANCE_HEIGHT = {"RANGE": 1.0, "DRYER": 3.5, "WTR HTR": 5.0, "WATER HEATER": 5.0, "AC": 3.0, "EV": 4.0}
# 2026-11-20: symbols that are the end of an appliance's 30 A circuit (the appliance names they can serve)
APPLIANCE_ENDS = {"range_receptacle": ("RANGE",), "dryer_receptacle": ("DRYER",),
                  "disconnect": ("AC", "WTR HTR", "WATER HEATER", "EV")}


@dataclass
class Device:
    id: str
    item_type: str
    x: float
    y: float
    floor: int
    room: str = ""
    circuit: str | None = None
    why: str = ""

    @property
    def kind(self) -> str:
        if self.item_type in SWITCHES:
            return "switch"
        if self.item_type in CEILING:
            return "ceiling"
        if self.item_type in WALL_LIGHTS:
            return "wall_light"
        if self.item_type == "floor_box":
            return "floor_box"
        if self.item_type == "duplex_receptacle_wp":
            return "wp"
        if self.item_type == "appliance":
            return "appliance"
        return "receptacle"

    @property
    def lighting(self) -> bool:
        return self.kind in ("switch", "ceiling", "wall_light")


@dataclass
class Floor:
    index: int
    name: str
    x0: float
    y0: float
    x1: float
    y1: float

    def holds(self, x: float, y: float, slack: float = 2.5) -> bool:
        return self.x0 - slack <= x <= self.x1 + slack and self.y0 - slack <= y <= self.y1 + slack


@dataclass
class Circuit:
    id: str
    description: str
    amps: int
    poles: int
    wire: str
    floor: int | None = None
    devices: list = field(default_factory=list)
    flags: list = field(default_factory=list)


# ------------------------------------------------------------------ reading the drawings
def _units_to_ft(doc) -> float:
    return {1: 1 / 12, 2: 1.0, 4: 1 / 304.8, 5: 1 / 30.48, 6: 3.28084}.get(int(doc.header.get("$INSUNITS", 2) or 2), 1.0)


def _text(e) -> str:
    return (e.dxf.text if e.dxftype() == "TEXT" else e.plain_text()).strip()


def read_panel_schedule(path: str) -> dict:
    """The panel schedule from the panel drawing: circuits by row (CIRCUIT, DESCRIPTION, AMPS, POLES, WIRE columns,
    matched by the header texts' x), plus which floor each circuit serves (the riser's GROUND / SECOND FLOOR boxes)."""
    import ezdxf
    msp = ezdxf.readfile(path).modelspace()
    texts = [(_text(e), float(e.dxf.insert.x), float(e.dxf.insert.y)) for e in msp.query("TEXT MTEXT")]
    head = {t.upper(): (x, y) for t, x, y in texts if t.upper() in ("CIRCUIT", "DESCRIPTION", "AMPS", "POLES", "WIRE")}
    if len(head) < 5:
        raise ValueError("no panel schedule found (CIRCUIT / DESCRIPTION / AMPS / POLES / WIRE headings)")
    top = max(y for _, y in head.values())
    # Columns: the table's own vertical lines when it has them (a heading and its cells share a cell), else halfway
    # between the headings.
    verts = sorted({round(e.dxf.start.x, 2) for e in msp.query("LINE")
                    if abs(e.dxf.start.x - e.dxf.end.x) < 1e-6 and min(e.dxf.start.y, e.dxf.end.y) < top
                    < max(e.dxf.start.y, e.dxf.end.y) + 1.5})
    cols = sorted(head.items(), key=lambda kv: kv[1][0])
    if len(verts) >= 2:
        def cell(x):
            return sum(1 for v in verts if v <= x)
        by_cell = {cell(x): name for name, (x, _) in cols}

        def col(x):
            return by_cell.get(cell(x))
    else:
        mids = [(name, (cols[i - 1][1][0] + x) / 2 if i else -1e9) for i, (name, (x, _)) in enumerate(cols)]

        def col(x):
            best = None
            for name, edge in mids:
                if x >= edge:
                    best = name
            return best
    # Only the table's own cells: other text on the sheet at the same heights (the panel elevation) isn't a row.
    x_lo, x_hi = (verts[0], verts[-1]) if len(verts) >= 2 else (cols[0][1][0] - 3, cols[-1][1][0] + 12)
    rows: dict[float, dict] = {}
    for t, x, y in texts:
        if y >= top - 0.2 or y < top - 30 or not x_lo - 0.5 <= x <= x_hi + 0.5:
            continue
        key = next((k for k in rows if abs(k - y) <= 0.45), round(y, 1))
        rows.setdefault(key, {})
        c = col(x)
        if c:
            rows[key][c] = (rows[key].get(c, "") + " " + t).strip()
    circuits, main = [], None
    for _, r in sorted(rows.items(), key=lambda kv: -kv[0]):
        cid, amps = r.get("CIRCUIT"), r.get("AMPS", "")
        if not cid or not re.fullmatch(r"\d+", amps or ""):
            continue
        if cid.upper() == "MAIN":
            main = {"amps": int(amps), "poles": int(r.get("POLES", "2") or 2), "wire": (r.get("WIRE") or "").strip(),
                    "description": r.get("DESCRIPTION", "")}            # for the wiring schematic (2026-11-20)
            continue
        circuits.append(Circuit(cid.upper(), r.get("DESCRIPTION", ""), int(amps), int(r.get("POLES", "1") or 1),
                                (r.get("WIRE") or AMPS_WIRE.get(int(amps), "12/2")).strip()))
    # The riser: "GROUND FLOOR" / "SECOND FLOOR" boxes list their circuits on the lines under them.
    serves = {}
    for t, x, y in texts:
        m = re.fullmatch(r"(GROUND|FIRST|SECOND|THIRD)\s+FLOOR", t.upper().strip())   # the riser's floor boxes only
        if not m:
            continue
        lvl = {"GROUND": 0, "FIRST": 0, "SECOND": 1, "THIRD": 2}[m.group(1)]
        for t2, x2, y2 in texts:
            if abs(x2 - x) < 2 and 0 < y - y2 < 3.5:
                for tok in re.findall(r"C-\d+", t2.upper()):
                    serves[tok] = lvl
    for c in circuits:
        if c.id in serves:
            c.floor = serves[c.id]
        elif c.amps >= 30:
            c.floor = 0
    return {"circuits": circuits, "main": main}


def _floors(msp, k: float) -> list[Floor]:
    """The floors drawn side by side: the exterior walls in clusters along x, named by the "... FLOOR" titles."""
    segs = []
    for want_ext in (True, False):
        for e in msp.query("LINE LWPOLYLINE"):
            lay = e.dxf.layer.upper()
            if "WALL" in lay and ("EXT" in lay or not want_ext):
                p = ([(q[0], q[1]) for q in e.get_points()] if e.dxftype() == "LWPOLYLINE"
                     else [(e.dxf.start.x, e.dxf.start.y), (e.dxf.end.x, e.dxf.end.y)])
                segs.append([(x * k, y * k) for x, y in p])
        if segs:
            break
    # Walls whose x-spans overlap (or nearly touch) belong to one floor; floors drawn side by side are apart.
    segs.sort(key=lambda s: min(x for x, _ in s))
    groups = []
    for s in segs:
        lo, hi = min(x for x, _ in s), max(x for x, _ in s)
        if groups and lo <= groups[-1]["hi"] + 5.0:
            groups[-1]["pts"] += s
            groups[-1]["hi"] = max(groups[-1]["hi"], hi)
        else:
            groups.append({"hi": hi, "pts": list(s)})
    groups = [g["pts"] for g in groups]
    titles = []
    for e in msp.query("TEXT MTEXT"):
        t = _text(e).upper()
        m = re.search(r"\b(GROUND|FIRST|SECOND|THIRD|BASEMENT)\s+FLOOR\b", t)
        if m:
            titles.append((m.group(1), e.dxf.insert.x * k))
    order = {"BASEMENT": -1, "GROUND": 0, "FIRST": 0, "SECOND": 1, "THIRD": 2}
    floors = []
    for i, g in enumerate(groups):
        xs, ys = [p[0] for p in g], [p[1] for p in g]
        cx = (min(xs) + max(xs)) / 2
        name = min(titles, key=lambda t: abs(t[1] - cx))[0] if titles else ("GROUND" if i == 0 else f"FLOOR {i + 1}")
        floors.append(Floor(order.get(name, i), name.title() + " floor", min(xs), min(ys), max(xs), max(ys)))
    floors.sort(key=lambda f: f.index)
    return floors


def read_floor_plan(path: str) -> dict:
    """Devices, rooms, floors, the panel, the riser, circuit tags and 30 Amp labels from the electrical floor plan.
    Symbols outside every floor (the legend) are left out."""
    import ezdxf
    doc = ezdxf.readfile(path)
    msp, k = doc.modelspace(), _units_to_ft(doc)
    floors = _floors(msp, k)

    def floor_of(x, y):
        hit = [f for f in floors if f.holds(x, y)]
        return hit[0].index if hit else None
    devices, panel = [], None
    for n, e in enumerate(msp.query("INSERT")):
        x, y = e.dxf.insert.x * k, e.dxf.insert.y * k
        f = floor_of(x, y)
        if f is None:
            continue                                                  # the legend, or off the plan
        entry = lib.by_block_name(e.dxf.name) or lib.by_block_name(e.dxf.layer)
        it = entry["item_type"] if entry else None
        if it == "panel":
            panel = {"x": x, "y": y, "floor": f}
            continue
        if not it or it in LOW_VOLTAGE:
            continue
        devices.append(Device(f"{e.dxf.name}@{x:.1f},{y:.1f}", it, x, y, f))
    rooms, tags, appliances, riser = [], [], [], None
    for e in msp.query("TEXT MTEXT"):
        t, x, y = _text(e), e.dxf.insert.x * k, e.dxf.insert.y * k
        f = floor_of(x, y)
        if f is None:
            continue
        u = t.upper()
        if re.fullmatch(r"C-\d+", u):
            tags.append({"id": u, "x": x, "y": y, "floor": f})
        elif re.search(r"\b\d{2}\s*A\b", u) and any(a in u for a in APPLIANCE_HEIGHT):
            name = next(a for a in APPLIANCE_HEIGHT if a in u)
            appliances.append(Device(f"{name}@{x:.1f},{y:.1f}", "appliance", x, y, f, room=name))
        elif "RISER" in u:
            riser = {"x": x, "y": y, "floor": f}
        elif e.dxf.layer.upper().startswith("A-") and re.search(r"[A-Z]{3}", u) and "'" not in t and '"' not in t \
                and "FLOOR" not in u and "SQ FT" not in u:
            rooms.append({"name": u, "x": x, "y": y, "floor": f})
    # The riser itself: where the upper floor's home runs meet (the E-CIRCUIT lines' common end), else its label.
    ends = {}
    for e in msp.query("LWPOLYLINE"):
        if "CIRC" in e.dxf.layer.upper():
            p = list(e.get_points())[-1]
            key = (round(p[0] * k, 1), round(p[1] * k, 1))
            ends[key] = ends.get(key, 0) + 1
    if riser:
        upper = [(pt, n) for pt, n in ends.items() if floor_of(*pt) == riser["floor"]]
        if upper:
            pt = max(upper, key=lambda pn: (pn[1], -math.dist(pn[0], (riser["x"], riser["y"]))))[0]
            riser = {"x": float(pt[0]), "y": float(pt[1]), "floor": riser["floor"]}
    # 2026-11-20 (David: the range/dryer receptacles and disconnects drawn on the plan): such a symbol is where its 30 A
    # circuit ends - not a branch-circuit device. Its appliance's route goes to the symbol, not the "RANGE 30A" label.
    drawn_ends = []
    for d in [d for d in devices if d.item_type in APPLIANCE_ENDS]:
        devices.remove(d)
        drawn_ends.append(d.item_type)
        names = APPLIANCE_ENDS[d.item_type]
        near = [a for a in appliances if a.floor == d.floor and a.room in names]
        if near:
            a = min(near, key=lambda a: math.dist((a.x, a.y), (d.x, d.y)))
            if math.dist((a.x, a.y), (d.x, d.y)) <= 15:
                a.x, a.y, a.why = d.x, d.y, f"at its {lib.BY_TYPE[d.item_type]['description'].split(' (')[0].lower()}"
                continue
        if d.item_type != "disconnect":
            appliances.append(Device(f"{names[0]}@{d.x:.1f},{d.y:.1f}", "appliance", d.x, d.y, d.floor, room=names[0]))
    for d in devices:
        same = [r for r in rooms if r["floor"] == d.floor]
        if same:
            d.room = min(same, key=lambda r: math.dist((r["x"], r["y"]), (d.x, d.y)))["name"]
    return {"floors": floors, "devices": devices, "appliances": appliances, "panel": panel, "riser": riser,
            "tags": tags, "rooms": rooms, "doc_units_ft": k, "drawn": _drawn_circuits(msp, k),
            "drawn_ends": sorted(set(drawn_ends))}


# ------------------------------------------------------------------ the designer's circuit lines (2026-11-20, David)
def _seg_dist(p, a, b) -> float:
    dx, dy = b[0] - a[0], b[1] - a[1]
    n = dx * dx + dy * dy
    t = 0.0 if n == 0 else max(0.0, min(1.0, ((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / n))
    return math.hypot(p[0] - a[0] - t * dx, p[1] - a[1] - t * dy)


def _line_dist(p, pts) -> float:
    return min(_seg_dist(p, a, b) for a, b in zip(pts, pts[1:]))


_DEVICE_NAMES = {"duplex_receptacle": "outlet", "duplex_receptacle_gfci": "GFCI outlet", "duplex_receptacle_wp":
                 "weatherproof outlet", "duplex_receptacle_usb": "USB outlet", "quad_receptacle": "4-plex outlet",
                 "switch": "switch", "switch_3way": "3-way switch", "switch_4way": "4-way switch",
                 "switch_dimmer": "dimmer", "light_fixture": "ceiling light", "light_recessed": "recessed light",
                 "light_wall": "wall light", "light_exterior": "exterior light", "ceiling_fan": "ceiling fan",
                 "exhaust_fan": "exhaust fan", "smoke_detector": "smoke detector"}


def device_name(item_type: str) -> str:
    return _DEVICE_NAMES.get(item_type, item_type.replace("_", " "))


def _circuit_name(text: str) -> str | None:
    """'C-3' -> 'C-3'; 'RANGE 30A' -> 'RANGE'; 'WTR HTR 30A' -> 'WTR HTR'; anything else (RISER TO ...) -> None."""
    u = re.sub(r"\s+", " ", text.upper()).strip()
    if re.fullmatch(r"C-\d+", u):
        return u
    m = re.fullmatch(r"(.+?)\s*\d{2,3}\s*A(MPS?)?", u)
    return m.group(1).strip() if m else None


def _drawn_circuits(msp, k: float) -> list[dict]:
    """The designer's circuit lines (E-CIRCUIT ... layers): each line's points (feet) and the circuit it is labelled
    with. A label written straight after its line in the file belongs to it (the usual way a circuit is drawn);
    labels left over go to the nearest line still without one, within a few feet."""
    from estimator.plan_engine.layers import CIRCUIT_LAYER
    lines, loose = [], []
    for e in msp:
        layer = e.dxf.layer if e.dxf.hasattr("layer") else ""
        if not CIRCUIT_LAYER.search(layer or ""):
            continue
        t = e.dxftype()
        if t == "LINE":
            pts = [(e.dxf.start.x * k, e.dxf.start.y * k), (e.dxf.end.x * k, e.dxf.end.y * k)]
        elif t == "LWPOLYLINE" and not e.closed:
            pts = [(p[0] * k, p[1] * k) for p in e.get_points()]
        elif t in ("TEXT", "MTEXT"):
            name = _circuit_name(_text(e))
            if not name:
                continue
            p = (e.dxf.insert.x * k, e.dxf.insert.y * k)
            last = lines[-1] if lines else None
            if last and last["label"] is None and _line_dist(p, last["points"]) <= 8.0:
                last["label"] = name
            else:
                loose.append((name, p))
            continue
        else:
            continue
        if len(pts) >= 2:
            lines.append({"points": pts, "label": None})
    for name, p in loose:
        free = [ln for ln in lines if ln["label"] is None]
        if free:
            best = min(free, key=lambda ln: _line_dist(p, ln["points"]))
            if _line_dist(p, best["points"]) <= 4.0:
                best["label"] = name
    return [ln for ln in lines if ln["label"]]


def drawing_check(plan: dict, schedule: dict) -> dict:
    """Check the wiring run against the circuit lines the designer drew (call after assign). What a drawn line says:
    that its circuit exists, whether it runs to the panel (this floor) or up the riser (the floor above), and - for a
    C-number line - the device it starts at. Each difference becomes a flag on the circuit, for a person to check."""
    drawn = plan.get("drawn") or []
    by_id = {c.id: c for c in schedule["circuits"]}
    panel, riser = plan.get("panel"), plan.get("riser")
    on = {}                                                                     # device id -> circuit the run gave it
    for c in schedule["circuits"]:
        for d in c.devices:
            on[d.id] = c.id
    out = {"lines": len(drawn), "matched": 0, "differ": [], "not_drawn": [], "not_in_schedule": []}
    if not drawn:
        return out
    seen = set()
    for ln in drawn:
        cid = ln["label"]
        c = by_id.get(cid) or next((x for x in schedule["circuits"] if x.id.replace(" ", "") == cid.replace(" ", "")), None)
        if c is None:
            out["not_in_schedule"].append(cid)
            continue
        seen.add(c.id)
        a, b = ln["points"][0], ln["points"][-1]
        home, far = (b, a)
        for pt, label in ((panel, "panel"), (riser, "riser")):
            if pt and math.dist(a, (pt["x"], pt["y"])) < math.dist(b, (pt["x"], pt["y"])) and \
                    math.dist(a, (pt["x"], pt["y"])) <= 1.5:
                home, far = a, b
        ok = True
        to_riser = bool(riser and math.dist(home, (riser["x"], riser["y"])) <= 1.5)
        run_floor = c.devices[0].floor if c.devices else None
        if to_riser and panel and run_floor == panel["floor"]:
            ok = False
            c.flags.append(f"the drawing runs {c.id} up the riser (the floor above); the wiring run has it on the panel's floor - check")
            out["differ"].append({"circuit": c.id, "what": "floor"})
        if re.fullmatch(r"C-\d+", cid):
            devs = [d for d in plan["devices"] if math.dist((d.x, d.y), far) <= 0.5]
            if devs:
                d = min(devs, key=lambda d: math.dist((d.x, d.y), far))
                got = on.get(d.id)
                if got != c.id:
                    ok = False
                    where = f" in {d.room.title()}" if d.room else ""
                    c.flags.append(f"the drawing starts {c.id} at the {device_name(d.item_type)}{where}; the wiring "
                                   f"run has it on {got or 'no circuit'} - check, or move it to {c.id}")
                    out["differ"].append({"circuit": c.id, "what": "device", "device": d.id, "item_type": d.item_type,
                                          "room": d.room, "run_circuit": got})
        if ok:
            out["matched"] += 1
    out["not_drawn"] = [c.id for c in schedule["circuits"] if c.devices and c.id not in seen]
    return out


# ------------------------------------------------------------------ putting each device on a circuit
def _phrases(desc: str) -> list[str]:
    d = re.sub(r"\b(receptacles?|outlets?|lighting|lights)\b", "", desc, flags=re.I)
    return [p.strip().upper() for p in re.split(r"[/,&]| and ", d) if p.strip()]


def assign(plan: dict, schedule: dict, overrides: dict | None = None) -> list[Device]:
    """Each device onto a circuit. Lighting (lights, fans, switches, smoke detectors) goes on its floor's lighting
    circuit; receptacles on the circuit whose description names their room, else the nearest circuit tag on their
    floor; each 30 Amp label is its own circuit. Returns the devices nothing settled (circuit None)."""
    circuits = schedule["circuits"]
    floor_names = {f.index: f.name.split()[0].upper() for f in plan["floors"]}
    lighting = {}
    for c in circuits:
        if re.search(r"light", c.description, re.I):
            m = re.search(r"\b(ground|first|second|third)\b", c.description, re.I)
            lvl = {"GROUND": 0, "FIRST": 0, "SECOND": 1, "THIRD": 2}[m.group(1).upper()] if m else c.floor
            lighting[lvl] = c
    named = [(p, c) for c in circuits if c.amps < 30 and not re.search(r"light", c.description, re.I)
             for p in _phrases(c.description)]
    by_id = {c.id: c for c in circuits}
    left = []
    overrides = {k: str(v).upper() for k, v in (overrides or {}).items() if str(v).upper() in by_id}
    for d in plan["devices"]:
        if d.id in overrides:                                          # a person moved it to this circuit
            d.circuit, d.why = overrides[d.id], "moved by hand"
        elif d.lighting:
            c = lighting.get(d.floor)
            if c:
                d.circuit, d.why = c.id, f"{floor_names.get(d.floor, '')} lighting".strip()
        else:
            room = d.room.upper()
            hit = [c for p, c in named if room == p or room.startswith(p + " ") or room == p.replace(" ", "")
                   or (len(p) > 3 and p in room and not (p == "PRIMARY BR" and "BATH" in room))]
            same_floor = [c for c in hit if c.floor in (None, d.floor)]
            if same_floor:
                d.circuit, d.why = same_floor[0].id, f"room {d.room}"
        if d.circuit is None and not d.lighting and d.id not in overrides:
            tags = [t for t in plan["tags"] if t["floor"] == d.floor and t["id"] in by_id
                    and by_id[t["id"]].amps < 30 and not re.search(r"light", by_id[t["id"]].description, re.I)]
            if tags:
                t = min(tags, key=lambda t: math.dist((t["x"], t["y"]), (d.x, d.y)))
                d.circuit, d.why = t["id"], f"nearest circuit tag {t['id']}"
        if d.circuit is None:
            left.append(d)
        else:
            by_id[d.circuit].devices.append(d)
    for a in plan["appliances"]:
        c = next((c for c in circuits if c.amps >= 30 and c.id.replace(" ", "") in a.room.replace(" ", "")), None) \
            or next((c for c in circuits if c.amps >= 30 and a.room.split()[0] in c.id), None)
        if c:
            a.circuit, a.why = c.id, "30 Amp label"
            c.devices.append(a)
        else:
            left.append(a)
    return left


# ------------------------------------------------------------------ no panel schedule: lay the circuits out (2026-11-21)
# David: "Add the fall back" - many house plans come without a panel schedule; the electrician lays out the circuits.
# Then the run lays them out itself the way residential work usually is (NEC minimums), and says so on every circuit:
#   lighting (lights, fans, smoke detectors and their switches) on 15 A 14/2, by floor, up to LIGHTS_PER_CIRCUIT;
#   kitchen / dining / pantry counter receptacles on at least two 20 A small-appliance circuits (NEC 210.11(C)(1));
#   each bathroom's receptacles on a 20 A circuit (210.11(C)(3)); laundry (210.11(C)(2)) and garage (210.11(C)(4))
#   on their own 20 A circuits; outdoor (WP) receptacles on a 20 A circuit; a dedicated receptacle on its own 20 A;
#   the rest of the receptacles on 20 A 12/2, by floor, nearest together, up to OUTLETS_PER_CIRCUIT;
#   each appliance label (RANGE, DRYER, WTR HTR, AC, EV) on its own 240 V circuit, sized below.
# An uploaded panel schedule always wins over this; the layout is for estimating and the electrician's own layout and
# local code decide the real one.
LIGHTS_PER_CIRCUIT = 12
OUTLETS_PER_CIRCUIT = 10
KITCHEN_ROOMS = ("KITCHEN", "DINING", "PANTRY", "BREAKFAST", "NOOK")
BATH_ROOMS = ("BATH", "POWDER", "LAV")
APPLIANCE_CIRCUITS = {"RANGE": (50, 2, "6/3", "Range"), "DRYER": (30, 2, "10/3", "Dryer"),
                      "WTR HTR": (30, 2, "10/2", "Water heater"), "WATER HEATER": (30, 2, "10/2", "Water heater"),
                      "AC": (30, 2, "10/2", "Air conditioner"), "EV": (50, 2, "6/3", "EV charger")}
LAID_OUT = "laid out by AI-Prowler - no panel schedule"


def _clusters(devs: list, cap: int, start: tuple) -> list[list]:
    """Devices in groups of at most cap, each group the ones nearest together (from the one nearest start)."""
    left, out = list(devs), []
    while left:
        seed = min(left, key=lambda d: math.dist((d.x, d.y), start))
        group = [seed]
        left.remove(seed)
        while left and len(group) < cap:
            nxt = min(left, key=lambda d: min(math.dist((d.x, d.y), (g.x, g.y)) for g in group))
            group.append(nxt)
            left.remove(nxt)
        out.append(group)
    return out


def _split(devs: list, n: int, start: tuple) -> list[list]:
    """Devices into n groups as even as can be (the kitchen's two small-appliance circuits), nearest together."""
    if not devs:
        return []
    cap = max(1, math.ceil(len(devs) / n))
    return _clusters(devs, cap, start)


def layout_circuits(plan: dict, overrides: dict | None = None) -> dict:
    """A panel schedule made from the floor plan when none was uploaded: the circuits, with their devices on them.
    Same shape as read_panel_schedule's ({"circuits", "main"}) plus "generated": True."""
    panel = plan.get("panel") or {}
    floor_names = {f.index: f.name.split()[0].title() for f in plan["floors"]}
    circuits: list[Circuit] = []

    def new(desc, amps, poles, wire, floor, devs, why):
        c = Circuit(f"C-{len(circuits) + 1}", desc, amps, poles, wire, floor)
        c.flags.append(f"circuit {LAID_OUT} (typical residential layout) - check against the electrician's layout")
        for d in devs:
            d.circuit, d.why = c.id, why
            c.devices.append(d)
        circuits.append(c)
        return c

    by_floor: dict[int, list] = {}
    for d in plan["devices"]:
        by_floor.setdefault(d.floor, []).append(d)
    for fl in sorted(by_floor):
        devs = by_floor[fl]
        name = floor_names.get(fl, f"Floor {fl + 1}")
        origin = (panel.get("x", 0.0), panel.get("y", 0.0)) if panel.get("floor") == fl else \
            (plan["riser"]["x"], plan["riser"]["y"]) if plan.get("riser") and plan["riser"]["floor"] == fl else \
            (devs[0].x, devs[0].y)
        # Lighting: the loads in groups, then each switch with the light nearest it.
        loads = [d for d in devs if d.kind in ("ceiling", "wall_light")]
        switches = [d for d in devs if d.kind == "switch"]
        light_circuits = [new(f"{name} floor lighting" + (f" {i + 1}" if len(loads) > LIGHTS_PER_CIRCUIT else ""),
                              15, 1, "14/2", fl, g, f"{name.lower()} floor lighting ({LAID_OUT})")
                          for i, g in enumerate(_clusters(loads, LIGHTS_PER_CIRCUIT, origin))]
        for sw in switches:
            if light_circuits:
                c = min(light_circuits, key=lambda c: min(math.dist((sw.x, sw.y), (d.x, d.y)) for d in c.devices))
            else:
                c = new(f"{name} floor lighting", 15, 1, "14/2", fl, [], f"{name.lower()} floor lighting ({LAID_OUT})")
                light_circuits.append(c)
            sw.circuit, sw.why = c.id, f"{name.lower()} floor lighting ({LAID_OUT})"
            c.devices.append(sw)
        recs = [d for d in devs if d.kind not in ("ceiling", "wall_light", "switch")]
        room = lambda d: (d.room or "").upper()                                       # noqa: E731
        dedicated = [d for d in recs if d.item_type == "receptacle_dedicated"]
        wp = [d for d in recs if d.kind == "wp" and d not in dedicated]
        kitchen = [d for d in recs if d not in dedicated + wp and any(k in room(d) for k in KITCHEN_ROOMS)]
        baths: dict[str, list] = {}
        laundry, garage, general = [], [], []
        for d in recs:
            if d in dedicated or d in wp or d in kitchen:
                continue
            r = room(d)
            if any(b in r for b in BATH_ROOMS):
                baths.setdefault(r, []).append(d)
            elif "LAUNDRY" in r:
                laundry.append(d)
            elif "GARAGE" in r:
                garage.append(d)
            else:
                general.append(d)
        for i, g in enumerate(_split(kitchen, max(2, math.ceil(len(kitchen) / 6)), origin)):
            new(f"Kitchen small appliance {i + 1}", 20, 1, "12/2", fl, g, f"kitchen counter (NEC 210.11(C)(1), {LAID_OUT})")
        for r, g in sorted(baths.items()):
            new(f"{r.title()} receptacles", 20, 1, "12/2", fl, g, f"bathroom 20 A circuit (NEC 210.11(C)(3), {LAID_OUT})")
        if laundry:
            new("Laundry receptacles", 20, 1, "12/2", fl, laundry, f"laundry 20 A circuit (NEC 210.11(C)(2), {LAID_OUT})")
        if garage:
            new("Garage receptacles", 20, 1, "12/2", fl, garage, f"garage 20 A circuit (NEC 210.11(C)(4), {LAID_OUT})")
        for i, g in enumerate(_clusters(general, OUTLETS_PER_CIRCUIT, origin)):
            new(f"{name} floor receptacles" + (f" {i + 1}" if len(general) > OUTLETS_PER_CIRCUIT else ""), 20, 1,
                "12/2", fl, g, f"general receptacles ({LAID_OUT})")
        if wp:
            new(f"{name} floor outdoor receptacles", 20, 1, "12/2", fl, wp, f"outdoor receptacles ({LAID_OUT})")
        for d in dedicated:
            new(f"Dedicated receptacle {(d.room or '').title()}".strip(), 20, 1, "12/2", fl, [d],
                f"dedicated circuit ({LAID_OUT})")
    # Each appliance label on its own 240 V circuit; the 30 Amp labels are matched by name as with a schedule.
    for a in plan["appliances"]:
        amps, poles, wire, label = APPLIANCE_CIRCUITS.get(a.room, (30, 2, "10/2", a.room.title()))
        new(label, amps, poles, wire, a.floor, [a], f"{label.lower()} circuit ({LAID_OUT})")
    # Devices a person moved to another circuit (same floor only - a circuit stays on one floor).
    by_id = {c.id: c for c in circuits}
    for dev_id, cid in (overrides or {}).items():
        target = by_id.get(str(cid).upper())
        src = next((c for c in circuits for d in c.devices if d.id == dev_id), None)
        if target is None or src is None or src is target:
            continue
        d = next(d for d in src.devices if d.id == dev_id)
        if target.floor not in (None, d.floor):
            continue
        src.devices.remove(d)
        d.circuit, d.why = target.id, "moved by hand"
        target.devices.append(d)
    return {"circuits": circuits, "main": {"amps": 200, "poles": 2, "wire": "", "description": "Main (assumed 200 A)"},
            "generated": True}


# ------------------------------------------------------------------ routing
COUNTER_ROOMS = ("KITCHEN", "BATH", "LAV", "POWDER", "WET BAR")


def _z(d: Device, s: dict) -> float:
    """The box's height above its floor (feet)."""
    if d.kind == "ceiling":
        return s["ceiling_ft"]
    if d.kind == "appliance":
        return APPLIANCE_HEIGHT.get(d.room, 3.0)
    if d.kind == "wall_light":
        return 6.5
    if d.kind == "switch":
        return s["switch_in"] / 12
    if d.kind == "receptacle":
        counter = d.item_type == "duplex_receptacle_gfci" and any(r in (d.room or "").upper() for r in COUNTER_ROOMS)
        return (s["counter_in"] if counter else s["receptacle_in"]) / 12
    return BOX_HEIGHT[d.kind]


# ---- where the cable runs (2026-11-21, David). Heights are measured from the ground floor (floor 0 at 0 ft): each
# storey is a ceiling plus the floor framing above it. A run is at one of three levels on a floor: "above" (the
# ceiling joists, or the attic on the top floor), "below" (the floor framing under it - the basement ceiling under the
# ground floor) or "walls" (drilled through the studs). A cable never runs in a concrete slab.
def _storey(s: dict) -> float:
    return s["ceiling_ft"] + s["floor_framing_ft"]


def _run_level(via: str, floor: int, s: dict) -> float:
    base = floor * _storey(s)
    if via == "above":
        return base + s["ceiling_ft"]
    if via == "below":
        return base - s["floor_framing_ft"] / 2
    return base + s["wall_run_ft"]


def _below_ok(floor: int, s: dict) -> bool:
    """Floor framing under this floor to run cable in: not under a slab-on-grade ground floor."""
    return floor > 0 or s["foundation"] != "slab"


def _feed_via(floor: int, s: dict, forced_ok: bool = True) -> str:
    """How the runs from the panel reach a floor: the basement ceiling (or crawlspace) under the ground floor, the
    ceiling / attic over a slab, and the framing under an upper floor (or the attic, as set). forced_ok=False: the way
    the house is built, ignoring a floor forced by hand (the runs passing through to other floors don't change)."""
    forced = s["route"].get(floor, s["route"].get(str(floor))) if forced_ok else None
    if forced:
        return "above" if forced == "ceiling" else "walls"
    if floor == 0:
        return "below" if _below_ok(0, s) else "above"
    return s["upper_feed"] if s["upper_feed"] in ("below", "above") else "below"


def _pair_via(a, b, floor: int, s: dict, across: float) -> str:
    """The way the cable goes between two boxes. a and b are Devices, or None for where the circuit enters the floor
    (that end is already in the feed's run)."""
    forced = s["route"].get(floor, s["route"].get(str(floor)))
    if forced:                                               # a floor set by hand: everything one way, as before
        return "above" if forced == "ceiling" else "walls"
    if a is None or b is None:
        return _feed_via(floor, s)
    kinds = {a.kind, b.kind}
    if kinds & {"ceiling", "wall_light", "switch"}:
        return "above"                                       # lights through the ceiling; switches dropped to
    if kinds & {"appliance", "floor_box"}:
        return "below" if _below_ok(floor, s) else _feed_via(floor, s)
    via = s["outlets_via"] if s["outlets_via"] in VIAS else "walls"
    if via == "below" and not _below_ok(floor, s):
        via = "above"                                        # never through the slab
    if via == "walls" and across > s["wall_max_ft"]:
        via = _feed_via(floor, s)                            # past a door / across a room: the feed way
    return via


def _cost(a, b, pa: tuple, pb: tuple, floor: int, s: dict) -> float:
    """Cable between two points on one floor: from each box to the run level, across square to the walls (a wall run
    a little longer, round doors and corners), and back. pa / pb are (x, y, absolute height)."""
    across = abs(pa[0] - pb[0]) + abs(pa[1] - pb[1])
    via = _pair_via(a, b, floor, s, across)
    lvl = _run_level(via, floor, s)
    va = 0.0 if a is None else abs(pa[2] - lvl)
    vb = 0.0 if b is None else abs(pb[2] - lvl)
    return va + across * (s["wall_detour"] if via == "walls" else 1.0) + vb


def _tree(entry: tuple, devices: list, floor: int, s: dict) -> list[tuple[int, int, float]]:
    """The shortest tree from where the circuit enters the floor (index 0) through every box (Prim): the daisy chain an
    electrician pulls, each link going the way that kind of box is wired. entry is (x, y, absolute height)."""
    base = floor * _storey(s)
    devs = [None] + list(devices)
    pts = [entry] + [(d.x, d.y, base + _z(d, s)) for d in devices]
    best = {i: (_cost(None, devs[i], pts[0], pts[i], floor, s), 0) for i in range(1, len(pts))}
    edges = []
    while best:
        i = min(best, key=lambda j: best[j][0])
        cost, frm = best.pop(i)
        edges.append((frm, i, cost))
        for j in best:
            c = _cost(devs[i], devs[j], pts[i], pts[j], floor, s)
            if c < best[j][0]:
                best[j] = (c, i)
    return edges


def settings_with_defaults(settings: dict | None) -> dict:
    """The run's settings over the built-in defaults, with the slab rule applied (nothing routed below a slab floor)."""
    s = {**DEFAULTS, **(settings or {})}
    s["route"] = dict(s.get("route") or {})
    if s["foundation"] not in FOUNDATIONS:
        s["foundation"] = DEFAULTS["foundation"]
    if s["foundation"] != "basement":
        s["panel_in_basement"] = False
    return s


def routing_summary(s: dict) -> str:
    """One line on how the cable was run, for the Wiring card and the run's summary."""
    s = settings_with_defaults(s)
    found = {"basement": "basement - runs from the basement ceiling", "crawlspace": "crawlspace - runs under the floor",
             "slab": "slab - nothing in the slab; ground floor fed from the ceiling"}[s["foundation"]]
    outlets = {"walls": "outlets through the studs", "below": "outlets from below", "above": "outlets from the ceiling"}
    return (f"{found}; {outlets.get(s['outlets_via'], 'outlets through the studs')}; lights through the ceiling; "
            f"{s['ceiling_ft']:g} ft ceilings")


def _panel_height(panel: dict, s: dict) -> float:
    """The panel's center, measured from the ground floor: in the basement under where it's drawn, or on its floor."""
    if panel["floor"] == 0 and s["foundation"] == "basement" and s["panel_in_basement"]:
        return -(s["floor_framing_ft"] + s["basement_ceiling_ft"]) + s["panel_center_ft"]
    return panel["floor"] * _storey(s) + s["panel_center_ft"]


def route(plan: dict, schedule: dict, settings: dict | None = None) -> dict:
    """Route every circuit and add up the wire. Returns the circuits with their routes, totals by cable size,
    the BOM lines and the flags."""
    s = settings_with_defaults(settings)
    panel = plan["panel"]
    if panel is None:
        raise ValueError("no panel on the plan - click where it is")
    floors = {f.index: f for f in plan["floors"]}
    base = floors[panel["floor"]]
    pz = _panel_height(panel, s)
    trunk = _run_level(_feed_via(panel["floor"], s, False), panel["floor"], s)   # the panel floor's feed run
    out, totals = [], {}

    def add(size, ft):
        totals[size] = totals.get(size, 0.0) + ft
    for c in schedule["circuits"]:
        if not c.devices:
            continue
        floor = c.devices[0].floor
        fl = floors[floor]
        feed = _run_level(_feed_via(floor, s), floor, s)
        # Where the circuit enters its floor's feed run: at the panel (from the panel up or down to it), or for another
        # floor at the riser - along the panel floor's feed run to the riser, then up (or down) the chase.
        if floor == panel["floor"]:
            entry, home = (panel["x"], panel["y"], feed), abs(pz - feed)
            home_path = []
        else:
            r = plan["riser"] or {"x": panel["x"] - base.x0 + fl.x0, "y": panel["y"] - base.y0 + fl.y0}
            px, py = panel["x"] - base.x0 + fl.x0, panel["y"] - base.y0 + fl.y0     # the panel, under the riser's floor
            across = abs(px - r["x"]) + abs(py - r["y"])
            home = abs(pz - trunk) + across + abs(feed - trunk)
            entry = (r["x"], r["y"], feed)
            home_path = [(px, py), (r["x"], py), (r["x"], r["y"])]
        edges = _tree(entry, c.devices, floor, s)
        run = home + sum(e[2] for e in edges)
        ends = 2 * len(c.devices) - 1                                  # each box has a cable in and (mostly) one out
        makeup = ends * s["makeup_ft_per_end"] + s["panel_makeup_ft"]
        size = c.wire
        want = AMPS_WIRE.get(c.amps)
        if want and size.split("/")[0] != want.split("/")[0]:
            c.flags.append(f"schedule says {size} on a {c.amps} A breaker; {want} is the usual size - check")
        if c.amps >= 30 and any(a in c.description.upper() for a in ("DRYER", "RANGE")) and size.endswith("/2"):
            # 2026-11-20 (David: fix it): a range or dryer needs a neutral (NEC 250.140 - 4-wire), so the cable is priced
            # as /3; the flag says the schedule disagrees, for the designer to correct.
            three = size.split("/")[0] + "/3"
            c.flags.append(f"the panel schedule says {size}, priced as {three}: a {c.description.lower()} needs a neutral "
                           f"(NEC 250.140) - check with the designer")
            size = three
        ft = run + makeup
        add(size, ft)
        # 3-way travelers: each pair of 3-way switches (nearest first) gets /3 cable between them.
        trav = 0.0
        threes = [d for d in c.devices if d.item_type == "switch_3way"]
        while len(threes) >= 2:
            a = threes.pop(0)
            b = min(threes, key=lambda o: math.dist((o.x, o.y), (a.x, a.y)))
            threes.remove(b)
            lvl = floor * _storey(s)
            trav += _cost(a, b, (a.x, a.y, lvl + _z(a, s)), (b.x, b.y, lvl + _z(b, s)), floor, s) + 2 * s["makeup_ft_per_end"]
        if trav:
            add(TRAVELER.get(size, size.split("/")[0] + "/3"), trav)
        nodes = [entry[:2]] + [(d.x, d.y) for d in c.devices]
        paths = [[nodes[a], (nodes[b][0], nodes[a][1]), nodes[b]] for a, b, _ in edges]
        out.append({"id": c.id, "description": c.description, "amps": c.amps, "poles": c.poles, "wire": size,
                    "floor": floor, "devices": len(c.devices), "home_run_ft": round(home, 1),
                    "run_ft": round(run, 1), "makeup_ft": round(makeup, 1), "travelers_ft": round(trav, 1),
                    "total_ft": round(ft + trav, 1), "flags": c.flags,
                    "home_path": home_path, "paths": paths,
                    "assigned": [{"device": d.id, "item_type": d.item_type, "room": d.room, "why": d.why,
                                  "x": round(d.x, 2), "y": round(d.y, 2)} for d in c.devices]})
    bom = []
    for size, ft in sorted(totals.items()):
        order = ft * (1 + s["waste"])
        rolls = math.ceil(order / s["roll_ft"])
        bom.append({"cable": f"{size} NM-B" if not size.startswith(("6/", "8/")) else f"{size} NM-B (or SER)",
                    "measured_ft": round(ft, 1), "order_ft": math.ceil(order), "rolls": rolls,
                    "roll_ft": s["roll_ft"]})
    return {"circuits": out, "bom": bom, "settings": s}


# ------------------------------------------------------------------ the wiring drawing
COLORS = [1, 3, 5, 6, 30, 140, 200, 40, 160, 220, 4, 2]
ADDED_LAYER = "E-WIRE-ADDED"
APPLIANCE_RECEPTACLES = (("RANGE", "range_receptacle", "RANGE RECEPTACLE 14-50R"),
                         ("DRYER", "dryer_receptacle", "DRYER RECEPTACLE 14-30R"))


def added_symbols(result: dict) -> list[dict]:
    """2026-11-20 (David: "3 of these items don't have symbols, can they be added to the drawing"): what the wiring run
    prices that the designer's drawing has no symbol for - the range and dryer receptacles (at the appliance their
    circuit feeds) and the branch breakers (at the panel). They're marked on the wiring drawing and the plan overlay,
    never written into the designer's own plan. Positions in feet, like the routes."""
    out = []
    on_plan = set(result.get("drawn_ends") or [])     # the designer (or a revised drawing) drew it: no mark needed
    for c in result["circuits"]:
        if c["amps"] < 30 or not c["assigned"]:
            continue
        for word, kind, label in APPLIANCE_RECEPTACLES:
            if word in c["description"].upper() and kind not in on_plan:
                a = c["assigned"][0]
                out.append({"kind": kind, "feeds": kind + "s", "circuit": c["id"], "x": a["x"], "y": a["y"],
                            "label": f"{label} ({c['id']}, {c['amps']} A {c['wire']})"})
    panel = result.get("panel")
    branch = [c["id"] for c in result["circuits"] if c["amps"] < 30 and c["devices"]]
    if panel and branch:
        two = sum(1 for c in result["circuits"] if c["amps"] >= 30 and c["devices"])
        out.append({"kind": "branch_breakers", "feeds": "branch_circuits", "circuit": None,
                    "circuits": branch, "x": panel["x"], "y": panel["y"],
                    "label": f"PANEL: {len(branch)} BRANCH BREAKERS ({', '.join(branch)})"
                             + (f" + {two} 2-POLE" if two else "")})
    return out


def write_dxf(plan_path: str, result: dict, out_path: str) -> str:
    """The floor plan with every circuit's route on its own layer (E-WIRE-<circuit>), each run labelled with its
    circuit and cable size, home runs to the panel, and a wire schedule table under the drawing."""
    import ezdxf
    doc = ezdxf.readfile(plan_path)
    msp, k = doc.modelspace(), _units_to_ft(doc)
    inv = 1 / k                                                          # feet -> drawing units
    ys = [e.dxf.insert.y for e in msp.query("TEXT MTEXT INSERT")] or [0]
    bottom, left = min(ys), min([e.dxf.insert.x for e in msp.query("TEXT MTEXT INSERT")] or [0])
    for n, c in enumerate(result["circuits"]):
        layer = f"E-WIRE-{c['id']}".replace(" ", "_")
        if layer not in doc.layers:
            doc.layers.add(layer, color=COLORS[n % len(COLORS)])
        if c["home_path"]:
            msp.add_lwpolyline([(x * inv, y * inv) for x, y in c["home_path"]], dxfattribs={"layer": layer,
                                                                                         "linetype": "CONTINUOUS"})
        for p in c["paths"]:
            msp.add_lwpolyline([(x * inv, y * inv) for x, y in p], dxfattribs={"layer": layer})
        if c["paths"]:
            (x, y) = c["paths"][0][-1]
            msp.add_text(f"{c['id']} {c['wire']} {c['total_ft']:.0f}'", height=0.45 * inv,
                         dxfattribs={"layer": layer, "insert": (x * inv + 0.3 * inv, y * inv + 0.3 * inv)})
    # What the run added that the designer drew no symbol for: a receptacle mark at the range and the dryer, the branch
    # breaker count at the panel - on their own layer, so they can be turned off.
    added = result.get("added") or added_symbols(result)
    if added and ADDED_LAYER not in doc.layers:
        doc.layers.add(ADDED_LAYER, color=2)
    for a in added:
        x, y = a["x"] * inv, a["y"] * inv
        att = {"layer": ADDED_LAYER}
        if a["kind"] == "branch_breakers":
            msp.add_lwpolyline([(x - 0.6 * inv, y - 0.6 * inv), (x + 0.6 * inv, y - 0.6 * inv),
                                (x + 0.6 * inv, y + 0.6 * inv), (x - 0.6 * inv, y + 0.6 * inv)], close=True,
                               dxfattribs=att)
        else:
            msp.add_circle((x, y), 0.6 * inv, dxfattribs=att)
            msp.add_line((x - 0.35 * inv, y), (x + 0.35 * inv, y), dxfattribs=att)        # a 240 V receptacle mark
        msp.add_text(a["label"], height=0.4 * inv, dxfattribs={**att, "insert": (x + 0.9 * inv, y - 0.9 * inv)})
    # The wire schedule table, under everything else on the sheet.
    if "E-WIRE-SCHEDULE" not in doc.layers:
        doc.layers.add("E-WIRE-SCHEDULE", color=7)
    y = bottom - 4 * inv
    h = 0.55 * inv
    att = {"layer": "E-WIRE-SCHEDULE"}
    msp.add_text("WIRE SCHEDULE (AI-Prowler wiring takeoff - estimate, check before ordering)", height=0.8 * inv,
                 dxfattribs={**att, "insert": (left, y)})
    cols = [0, 7, 32, 38, 45, 54, 63, 72]
    heads = ["CIRCUIT", "DESCRIPTION", "AMPS", "CABLE", "DEVICES", "HOME RUN", "RUN+MAKEUP", "TOTAL FT"]
    y -= 1.4 * inv
    for cx, t in zip(cols, heads):
        msp.add_text(t, height=h, dxfattribs={**att, "insert": (left + cx * inv, y)})
    for c in result["circuits"]:
        y -= 1.0 * inv
        row = [c["id"], c["description"][:30], str(c["amps"]), c["wire"], str(c["devices"]), f"{c['home_run_ft']:.0f}",
               f"{c['run_ft'] + c['makeup_ft']:.0f}", f"{c['total_ft']:.0f}"]
        for cx, t in zip(cols, row):
            msp.add_text(t, height=h, dxfattribs={**att, "insert": (left + cx * inv, y)})
        for f in c["flags"]:
            y -= 0.8 * inv
            msp.add_text("   ! " + f, height=h * 0.85, dxfattribs={**att, "insert": (left + 7 * inv, y)})
    y -= 1.6 * inv
    msp.add_text("CABLE TO ORDER", height=0.7 * inv, dxfattribs={**att, "insert": (left, y)})
    for b in result["bom"]:
        y -= 1.0 * inv
        msp.add_text(f"{b['cable']}: {b['measured_ft']:.0f} ft measured, order {b['order_ft']} ft "
                     f"({b['rolls']} x {b['roll_ft']} ft rolls)", height=h, dxfattribs={**att, "insert": (left, y)})
    doc.saveas(out_path)
    return out_path


def takeoff(plan_path: str, panel_path: str | None, settings: dict | None = None, out_path: str | None = None,
            overrides: dict | None = None) -> dict:
    """Both drawings in, the wiring takeoff out (and the wiring DXF when out_path is given). overrides moves devices
    to circuits by hand: {device id: circuit id}. No panel drawing (panel_path None): the circuits are laid out from
    the floor plan (layout_circuits, 2026-11-21) and the result says so ("circuits_from": "laid_out")."""
    plan = read_floor_plan(plan_path)
    if panel_path:
        schedule = read_panel_schedule(panel_path)
        left = assign(plan, schedule, overrides)
        check = drawing_check(plan, schedule)      # before route(), so its flags go out with each circuit
    else:
        schedule = layout_circuits(plan, overrides)
        left = []
        check = {"lines": 0, "matched": 0, "differ": [], "not_drawn": [], "not_in_schedule": []}
    result = route(plan, schedule, settings)
    result["drawing_check"] = check
    result["unassigned"] = [{"device": d.id, "item_type": d.item_type, "room": d.room, "floor": d.floor}
                            for d in left]
    result["floors"] = [{"index": f.index, "name": f.name} for f in plan["floors"]]
    result["panel"] = plan["panel"]
    result["riser"] = plan["riser"]
    result["units_ft"] = plan["doc_units_ft"]                         # feet per drawing unit
    result["drawn_ends"] = plan.get("drawn_ends") or []
    result["main"] = schedule.get("main")
    result["circuits_from"] = "laid_out" if schedule.get("generated") else "schedule"
    result["added"] = added_symbols(result)
    if out_path:
        result["dxf"] = write_dxf(plan_path, result, out_path)
    return result
