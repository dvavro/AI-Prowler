"""The AI electrical designer (2026-11-21, David: "design me the lighting and receptacles ... I'd like for the AI to place
every symbol and to make the design recommendation based on specs and code rules and then the user can have you change
it as needed").

The AI gets the building (estimator/design/building.py: walls, doors, windows, rooms, in feet), the person's request and
the code rules below, and answers with one JSON design: the panel (main or subpanel, where, what feeds it), the
circuits, and every device with its x/y, floor and circuit. parse_design() refuses an answer that isn't a usable design
(unknown device type, a device on a circuit that doesn't exist ...). A change ("add two outlets on the rear wall") sends
the current design back with the request and gets the whole new design, plus a short list of what changed.

check() is the app's own code check on the drawn design - the AI is asked to follow the rules, the app checks it did:
GFCI where it's required, receptacle spacing along habitable walls, breaker and wire sizes, how full each circuit is,
switched lighting in every room, smoke alarms, a 240 V load on a 2-pole breaker, the panel's load, devices outside the
building or not on a wall. Each finding is error (must be fixed before approving), warning (a code concern to look at)
or info. NEC 2023 basics as used for estimating; the local authority's adopted code and a licensed electrician decide.
"""
from __future__ import annotations

import json
import math
import re

from estimator.design.draw_electrical import DEVICES, place

TRADE = "electrical"
DESIGN_SYSTEM = ("You are a licensed residential and light-commercial electrical designer. You design the electrical "
                 "layout for an existing building drawing and place every symbol yourself. Reply with ONLY one JSON "
                 "object, nothing else.")

CODE_RULES = """Design to NEC 2023 as adopted for one- and two-family dwellings and accessory buildings (use the local
amendments the person names). In short:
- 125 V 15/20 A receptacles need GFCI protection in bathrooms, garages, accessory buildings (sheds, shops, barns),
  outdoors, crawl spaces, unfinished basements, kitchens, laundry areas and within 6 ft of a sink (210.8(A)). Protect a
  circuit with a GFCI receptacle placed FIRST on the circuit (nearest the panel), the rest downstream; say so in a note.
- Dwelling habitable rooms: no point along a wall line more than 6 ft from a receptacle (210.52(A)) - in practice one
  every 12 ft of wall and on every wall 2 ft or longer. Kitchen counters: no point more than 2 ft from a receptacle;
  at least two 20 A small-appliance circuits (210.11(C)(1)). Each bathroom: a 20 A circuit (210.11(C)(3)) and a
  receptacle within 3 ft of each basin. Laundry: a 20 A circuit. Garage: a 20 A circuit, one receptacle per vehicle bay.
  Outdoor: a receptacle at the front and back of a dwelling (210.52(E)), weatherproof in-use covers.
- Accessory buildings (sheds, shops): plan receptacles along the walls every 10-12 ft at bench height (48 in) and at
  least one per wall and per roll-up door bay; GFCI on all 120 V receptacles.
- Every habitable room, bathroom, hallway, stairway, garage and attached or detached outbuilding with power has a
  switched lighting outlet (210.70). Switch at each entry door (3-way at two doors, 4-way between); outdoor light at
  each exterior door.
- Breaker and wire: 15 A 14/2, 20 A 12/2, 30 A 10/2 (10/3 when it needs a neutral), 40 A 8/2-8/3, 50 A 6/3. A 240 V load
  is on a 2-pole breaker. About 10 receptacles or 12-16 lighting fixtures (at about 100 W each) per 20 A circuit;
  continuous loads at 80 %.
- Smoke alarms in each sleeping room, outside each sleeping area and on every level of a dwelling (IRC R314), CO alarms
  where there are fuel-burning appliances or an attached garage.
- A panel needs 30 in wide x 36 in deep working space, never in a bathroom or a clothes closet (110.26, 240.24).
- A detached building fed from another panel: one 4-wire feeder (two hots, neutral, ground) from a 2-pole breaker in the
  supply panel, its own disconnect (a main breaker), a grounding electrode (ground rod) at the building, neutral and
  ground kept apart in its panel (250.32). Size the feeder breaker by the building's load.
"""

# What a design answer looks like (the prompt shows it; parse_design enforces it).
SHAPE = """{
  "summary": "one or two sentences: what was designed",
  "panel": {"kind": "subpanel" | "main", "amps": 100, "floor": 0, "x": 1.0, "y": 8.0,
            "fed_from": "what feeds it (subpanel only), e.g. 100A subpanel in the house garage",
            "feeder": "e.g. 4-wire 6 AWG Cu in conduit, underground", "feeder_breaker_amps": 60},
  "circuits": [{"id": "C-1", "description": "Left wall receptacles", "amps": 20, "poles": 1, "wire": "12/2", "floor": 0},
               {"id": "240V", "description": "240V receptacle NEMA 6-30R", "amps": 30, "poles": 2, "wire": "10/2", "floor": 0}],
  "devices": [{"type": "outlet_gfci", "x": 0.7, "y": 13.0, "floor": 0, "circuit": "C-1", "note": "first on C-1"},
              {"type": "light_led", "x": 5.75, "y": 4.5, "floor": 0, "circuit": "C-5"}],
  "wiring": {"method": "nm" | "emt" | "pvc", "structure": "wood" | "steel" | "masonry", "temp_swing_indoor_f": 60},
  "assumptions": ["short sentences: what you assumed that the person should confirm"],
  "code_notes": ["short sentences for the drawing's notes: GFCI, feeder, grounding ..."],
  "changes": ["only when changing an earlier design: what changed, one line each"]
}
wiring (2026-11-23): how it's installed - nm: NM-B cable in wood walls (new construction, open walls); emt: EMT conduit on
the surface (a metal building, a garage, an unfinished basement, adding power to a finished house, or when the specs say
conduit); pvc: PVC conduit on the surface (wet or corrosive places). structure: what the conduit is strapped to.
temp_swing_indoor_f: coldest to hottest inside (heated and cooled 40-60, an unconditioned metal building or garage 90-100)."""

ID_RE = re.compile(r"^(C-\d{1,3}|[A-Z0-9][A-Z0-9 \-]{0,11})$")
PANEL_AMPS = (60, 70, 100, 125, 150, 200, 225, 300, 400)


class DesignError(Exception):
    """The AI's answer isn't a usable design. The message is safe to show."""


def _types_line() -> str:
    return ", ".join(f"{k} ({v[3].lower()}; {v[2]})" for k, v in DEVICES.items())


def design_prompt(building: dict, request: str, specs: str = "") -> str:
    return (
        "BUILDING (feet; x runs along the front wall from the front-left corner, y toward the rear; one outline per "
        "floor, its doors, overhead doors and windows as segments on the walls, its rooms as rectangles):\n"
        + json.dumps(building, separators=(",", ":"))
        + "\n\nWHAT THE PERSON WANTS:\n" + request.strip()
        + ("\n\nTHEIR SPECS AND PREFERENCES:\n" + specs.strip() if specs.strip() else "")
        + "\n\nCODE RULES TO DESIGN BY:\n" + CODE_RULES
        + "\nDEVICE TYPES you may place (type: what it is; where it mounts - wall devices go on the INSIDE face of a wall,"
          " exterior ones on the OUTSIDE face of an exterior wall, ceiling ones where you put them): " + _types_line()
        + "\n\nPLACE EVERY SYMBOL: give each device its x/y in feet on its floor - a wall device right at the wall it"
          " is on (the app sets it 0.7 ft off the wall, facing it), never in a door opening; space receptacles along"
          " the walls by the rules; lay lights out evenly over each room; a switch beside the latch side of each entry"
          " door. Put the panel on an inside wall where it has working space. Every device names its circuit; every"
          " circuit has devices. Circuit ids: C-1, C-2 ... for 120 V branch circuits; a 240 V or appliance circuit is"
          " named for its load: 240V (more: 240V-2), RANGE, DRYER, WTR HTR, AC, EV. Do not invent rooms, doors or"
          " walls that aren't in the building. If the request leaves something open, choose what an electrician would"
          " and list it in assumptions."
        + "\n\nReply with ONLY this JSON (no comments, no trailing text):\n" + SHAPE)


def change_prompt(building: dict, design: dict, change: str, request: str, specs: str = "") -> str:
    current = {k: design.get(k) for k in ("summary", "panel", "circuits", "devices", "assumptions", "code_notes")}
    return (
        "You designed this electrical layout earlier. The person wants a change. Apply exactly what they ask, keep"
        " everything else where it is (same x/y, same circuits) unless the change needs it, keep it to code, and"
        " return the WHOLE new design, with \"changes\" listing what you changed, one short line each.\n\n"
        "BUILDING:\n" + json.dumps(building, separators=(",", ":"))
        + "\n\nTHE ORIGINAL REQUEST:\n" + request.strip()
        + ("\n\nTHEIR SPECS:\n" + specs.strip() if specs.strip() else "")
        + "\n\nTHE CURRENT DESIGN:\n" + json.dumps(current, separators=(",", ":"))
        + "\n\nTHE CHANGE THEY WANT:\n" + change.strip()
        + "\n\nThe person sees the devices numbered by their place in the devices list, 1-based ('device 12' / '#12' is"
          " the 12th), on a plan in feet (x along the front wall from the front-left corner, y toward the rear)."
        + "\n\nCODE RULES:\n" + CODE_RULES + "\nDEVICE TYPES: " + ", ".join(DEVICES)
        + "\n\nReply with ONLY the JSON, same shape as before:\n" + SHAPE)


def images_note(shots: int, has_design: bool) -> str:
    """2026-11-23 (David: "add screenshots ... to give geometric guidance to the AI, for example move this here"): what
    the pictures sent with the request are, and how to use them."""
    from estimator.design.reference import legend_text
    return (
        "\n\nPICTURES: the first picture is the app's REFERENCE drawing of the building in feet, on a 5 ft grid labelled"
        " every 10 ft (x along the front wall from the front-left corner, y toward the rear; the front is at the"
        " bottom)" + (", with every device of the current design as a numbered dot - the number is its place in the"
                       " devices list, 1-based (codes: " + legend_text({"devices": []}) + "), P = the panel"
                       if has_design else "")
        + f". The next {shots} picture(s) are the person's own screenshots or photos - marks, arrows, circles or notes"
          " on them show what they mean ('this', 'here', 'move this there'). Match each screenshot to the reference"
          " drawing (by the walls, doors, rooms and device symbols), read the positions they point at off the grid, and"
          " apply them in feet. If a mark is unclear, do what it most likely means and say so in assumptions.")


def fix_prompt(building: dict, design: dict, findings: list[dict], request: str) -> str:
    errs = [f"- {f['message']}" for f in findings if f["level"] == "error"]
    return change_prompt(building, design, "Fix these problems the code check found, and nothing else:\n"
                         + "\n".join(errs), request)


# ------------------------------------------------------------------ the answer
def _num(v, what) -> float:
    if isinstance(v, bool):
        raise DesignError(f"the AI's design has {what} = {v!r}, not a number")
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise DesignError(f"the AI's design has {what} = {v!r}, not a number") from None
    if not math.isfinite(f):
        raise DesignError(f"the AI's design has {what} = {v!r}")
    return f


def _texts(v, n=12, size=300) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        return []
    return [str(x).strip()[:size] for x in v if str(x).strip()][:n]


def parse_design(text: str, building: dict) -> dict:
    """The AI's design, checked for shape: every device a known type with numbers for x/y on a floor that exists and a
    circuit that exists; every circuit an id, amps, poles, wire. Anything else is refused with the reason."""
    from estimator.takeoff.llm_takeoff import LlmTakeoffError, _parse_json_object
    try:
        obj = _parse_json_object(text)
    except LlmTakeoffError as exc:
        raise DesignError(str(exc)) from None
    nfl = len(building.get("floors") or [])
    p = obj.get("panel")
    if not isinstance(p, dict):
        raise DesignError("the AI's design has no panel")
    kind = str(p.get("kind") or "main").lower()
    kind = "subpanel" if kind.startswith("sub") else "main"
    amps = int(_num(p.get("amps", 100), "panel amps"))
    if amps < 30 or amps > 400:
        raise DesignError(f"the AI's design has a {amps} A panel")
    panel = {"kind": kind, "amps": amps, "floor": int(_num(p.get("floor", 0), "panel floor")),
             "x": _num(p.get("x"), "panel x"), "y": _num(p.get("y"), "panel y"),
             "fed_from": str(p.get("fed_from") or "")[:80], "feeder": str(p.get("feeder") or "")[:80],
             "feeder_breaker_amps": (int(_num(p["feeder_breaker_amps"], "feeder breaker"))
                                     if p.get("feeder_breaker_amps") not in (None, "") else None)}
    if not 0 <= panel["floor"] < max(1, nfl):
        raise DesignError(f"the AI's design puts the panel on floor {panel['floor']}, which isn't in the building")
    circuits, ids = [], set()
    for c in obj.get("circuits") or []:
        if not isinstance(c, dict):
            raise DesignError("the AI's design has a circuit that isn't an object")
        cid = str(c.get("id") or "").strip().upper()
        if not ID_RE.match(cid) or cid == "MAIN":
            raise DesignError(f"the AI's design has a circuit named {c.get('id')!r}")
        if cid in ids:
            raise DesignError(f"the AI's design has circuit {cid} twice")
        ids.add(cid)
        a = int(_num(c.get("amps", 20), f"{cid} amps"))
        poles = int(_num(c.get("poles", 1), f"{cid} poles"))
        if a not in (15, 20, 25, 30, 40, 45, 50, 60, 70, 80, 90, 100) or poles not in (1, 2):
            raise DesignError(f"the AI's design has circuit {cid} at {a} A {poles}-pole")
        wire = str(c.get("wire") or "").strip() or {15: "14/2", 20: "12/2", 30: "10/2", 40: "8/3", 50: "6/3"}.get(a, "6/3")
        circuits.append({"id": cid, "description": str(c.get("description") or "")[:60], "amps": a, "poles": poles,
                         "wire": wire[:12], "floor": int(_num(c.get("floor", 0), f"{cid} floor"))})
    if not circuits:
        raise DesignError("the AI's design has no circuits")
    devices = []
    for i, d in enumerate(obj.get("devices") or []):
        if not isinstance(d, dict):
            raise DesignError(f"device {i + 1} isn't an object")
        t = str(d.get("type") or "").strip().lower()
        if t not in DEVICES:
            raise DesignError(f"device {i + 1} is a {t!r}, not one of the device types")
        fl = int(_num(d.get("floor", 0), f"device {i + 1} floor"))
        if not 0 <= fl < max(1, nfl):
            raise DesignError(f"device {i + 1} is on floor {fl}, which isn't in the building")
        cid = str(d.get("circuit") or "").strip().upper()
        if t not in ("data", "tv") and cid not in ids:
            raise DesignError(f"device {i + 1} ({t}) is on circuit {d.get('circuit')!r}, which isn't in the design")
        devices.append({"type": t, "x": round(_num(d.get("x"), f"device {i + 1} x"), 2),
                        "y": round(_num(d.get("y"), f"device {i + 1} y"), 2), "floor": fl,
                        "circuit": cid if t not in ("data", "tv") else "", "note": str(d.get("note") or "")[:120]})
    if not devices:
        raise DesignError("the AI's design has no devices")
    return {"summary": str(obj.get("summary") or "")[:400], "panel": panel, "circuits": circuits, "devices": devices,
            "wiring": _wiring(obj.get("wiring")),
            "assumptions": _texts(obj.get("assumptions")), "code_notes": _texts(obj.get("code_notes")),
            "changes": _texts(obj.get("changes"), 30, 200)}


def _wiring(w) -> dict:
    """The design's wiring method for the wiring run (2026-11-23) - forgiving: anything odd falls back to NM-B cable."""
    w = w if isinstance(w, dict) else {}
    method = str(w.get("method") or "nm").lower()
    out = {"method": method if method in ("nm", "emt", "pvc") else "nm"}
    structure = str(w.get("structure") or "").lower()
    if structure in ("wood", "steel", "masonry"):
        out["structure"] = structure
    try:
        swing = float(w.get("temp_swing_indoor_f"))
        if 0 <= swing <= 200:
            out["temp_swing_indoor_f"] = swing
    except (TypeError, ValueError):
        pass
    return out


# ------------------------------------------------------------------ the code check
GFCI_ROOMS = re.compile(r"BATH|GARAGE|SHED|SHOP|BARN|WORKSHOP|STORAGE|KITCHEN|LAUNDRY|UTILITY|BASEMENT|CRAWL|POOL|"
                        r"OUTDOOR|PORCH|PATIO|BOAT|BAR\b|WET", re.I)
HABITABLE = re.compile(r"LIVING|FAMILY|DINING|BED|BR\b|DEN|OFFICE|STUDY|GREAT|BONUS|PARLOR|SUNROOM|LIBRARY|REC", re.I)
NEEDS_LIGHT = re.compile(r"LIVING|FAMILY|DINING|BED|BR\b|DEN|OFFICE|STUDY|BATH|HALL|STAIR|GARAGE|KITCHEN|LAUNDRY|SHOP|"
                         r"SHED|STORAGE|GREAT|BONUS|UTILITY|WORKSHOP", re.I)
SLEEP = re.compile(r"BED|BR\b|BEDROOM|PRIMARY", re.I)
RECEPT = {"outlet", "outlet_gfci", "outlet_usb", "outlet_quad", "outlet_wp"}
LIGHTS = {"light", "light_led", "light_recessed", "light_pendant", "light_wall", "light_undercabinet", "light_exterior",
          "fan", "exhaust_fan"}
SWITCHES = {"switch", "switch_3way", "switch_4way", "switch_dimmer"}
BIG = {"outlet_240", "range_outlet", "dryer_outlet", "ev_charger", "disconnect"}
MIN_WIRE = {15: 14, 20: 12, 25: 10, 30: 10, 40: 8, 45: 8, 50: 6, 60: 6, 70: 4, 80: 4, 90: 3, 100: 3}


def _room_at(floor: dict, x: float, y: float) -> str:
    for r in floor.get("rooms") or []:
        if min(r["x0"], r["x1"]) - 0.8 <= x <= max(r["x0"], r["x1"]) + 0.8 and \
                min(r["y0"], r["y1"]) - 0.8 <= y <= max(r["y0"], r["y1"]) + 0.8:
            return str(r["name"]).upper()
    return ""


def _gauge(wire: str) -> int | None:
    m = re.match(r"\s*#?(\d+)", wire or "")
    return int(m.group(1)) if m else None


def check(building: dict, design: dict, placed: list[dict] | None = None, kind: str = "") -> list[dict]:
    """The code check on a design (placed: where each device was drawn, from draw_plan). kind: what the building is
    ("accessory" for a shed, shop or detached garage; else a dwelling)."""
    from estimator.design.draw_electrical import _inside
    out = []

    def add(level, code, msg, devices=None):
        out.append({"level": level, "code": code, "message": msg, "devices": devices or []})
    floors = building["floors"]
    devs = design["devices"]
    circuits = {c["id"]: c for c in design["circuits"]}
    placed = placed or [{"index": i, **place(d, floors[d["floor"]])} for i, d in enumerate(devs)]
    accessory = kind == "accessory" or bool(re.search(r"SHED|SHOP|BARN|WORKSHOP|DETACHED GARAGE|OUTBUILDING",
                                                       json.dumps(building).upper()))
    # -- where things are
    for i, d in enumerate(devs):
        pl = placed[i] if i < len(placed) else {}
        if pl.get("skipped"):
            continue
        poly = [tuple(map(float, p)) for p in floors[d["floor"]]["outline"]]
        mount = DEVICES[d["type"]][2]
        inside = _inside((pl["x"], pl["y"]), poly)
        if mount != "exterior" and not inside:
            add("error", "outside", f"{DEVICES[d['type']][3].lower()} {i + 1} ({d.get('circuit') or '-'}) is outside the"
                f" building at {pl['x']:.1f}, {pl['y']:.1f}", [i])
        elif mount == "exterior" and inside:
            add("warning", "inside", f"{DEVICES[d['type']][3].lower()} {i + 1} is inside the building - it's an outdoor"
                " device", [i])
        if pl.get("moved", "").startswith("not on a wall"):
            add("warning", "off_wall", f"{DEVICES[d['type']][3].lower()} {i + 1} is {pl['moved']} - a wall device", [i])
        elif pl.get("moved"):
            add("info", "moved", f"{DEVICES[d['type']][3].lower()} {i + 1} {pl['moved']}", [i])
    # -- circuits
    used = {}
    for i, d in enumerate(devs):
        if d.get("circuit"):
            used.setdefault(d["circuit"], []).append(i)
    for cid, c in circuits.items():
        idx = used.get(cid) or []
        if not idx:
            add("warning", "empty_circuit", f"circuit {cid} ({c['description']}) has no devices")
            continue
        g = _gauge(c["wire"])
        need = MIN_WIRE.get(c["amps"])
        if g and need and g > need:
            add("error", "wire", f"circuit {cid} is {c['amps']} A on {c['wire']} - it needs {need} AWG or larger")
        types = [devs[i]["type"] for i in idx]
        big = [t for t in types if t in BIG]
        if big and c["poles"] < 2 and any(t in ("outlet_240", "range_outlet", "dryer_outlet", "ev_charger") for t in big):
            add("error", "pole", f"circuit {cid} feeds a 240 V load on a 1-pole breaker - it needs a 2-pole breaker", idx)
        if c["poles"] >= 2 and any(t in RECEPT for t in types):
            add("error", "mixed_240", f"circuit {cid} is a 2-pole circuit with 120 V receptacles on it", idx)
        if any(t in ("range_outlet", "dryer_outlet") for t in types) and not c["wire"].endswith("/3"):
            add("warning", "neutral", f"circuit {cid} feeds a range or dryer: it needs a /3 cable (neutral, NEC 250.140)")
        nrec = sum(1 for t in types if t in RECEPT)
        nlight = sum(1 for t in types if t in LIGHTS)
        cap = 13 if c["amps"] >= 20 else 10
        if nrec > cap:
            add("warning", "full", f"circuit {cid} has {nrec} receptacles on {c['amps']} A - plan about 10 per 20 A circuit")
        if nlight * 100 > c["amps"] * 120 * 0.8:
            add("warning", "full", f"circuit {cid} has {nlight} lights - about {nlight * 100} W on a {c['amps']} A circuit"
                f" (80 % = {int(c['amps'] * 120 * 0.8)} W)")
        # GFCI: a circuit with receptacles in a GFCI room needs a GFCI first (or a GFCI breaker named in its description)
        rooms = {_room_at(floors[devs[i]["floor"]], devs[i]["x"], devs[i]["y"]) for i in idx if devs[i]["type"] in RECEPT}
        needs = accessory or any(GFCI_ROOMS.search(r or "") for r in rooms) or "outlet_wp" in types
        if nrec and needs and "outlet_gfci" not in types and "outlet_wp" not in types and \
                not re.search(r"GFCI|GFI", c["description"], re.I):
            add("error", "gfci", f"circuit {cid}'s receptacles need GFCI protection (NEC 210.8) - put a GFCI receptacle"
                " first on it, or a GFCI breaker", idx)
    for i, d in enumerate(devs):
        if d["type"] not in ("data", "tv") and d.get("circuit") not in circuits:
            add("error", "no_circuit", f"device {i + 1} is on circuit {d.get('circuit')!r}, which isn't in the design", [i])
    # -- each room: switched light, receptacle spacing, smoke alarms
    for fi, f in enumerate(floors):
        here = [(i, d) for i, d in enumerate(devs) if d["floor"] == fi]
        for r in f.get("rooms") or []:
            name = str(r["name"]).upper()
            inr = [(i, d) for i, d in here if _room_at(f, d["x"], d["y"]) == name]
            types = [d["type"] for _, d in inr]
            if NEEDS_LIGHT.search(name) and not any(t in LIGHTS for t in types):
                add("warning", "light", f"{name.title()} has no light (NEC 210.70: a switched lighting outlet)")
            if any(t in LIGHTS for t in types) and not any(t in SWITCHES for t in types) and \
                    NEEDS_LIGHT.search(name):
                add("warning", "switch", f"{name.title()} has lights but no switch in the room")
            per = 2 * (abs(r["x1"] - r["x0"]) + abs(r["y1"] - r["y0"]))
            nrec = sum(1 for t in types if t in RECEPT and t != "outlet_wp")
            if HABITABLE.search(name) and nrec < max(1, math.ceil(per / 12.0) - 1):
                add("warning", "spacing", f"{name.title()} has {nrec} receptacles for about {per:.0f} ft of wall - NEC"
                    f" 210.52(A) needs one within 6 ft of every point (about {math.ceil(per / 12.0)})")
            if accessory and not HABITABLE.search(name) and per > 20 and nrec == 0 and \
                    re.search(r"SHOP|SHED|GARAGE|STORAGE|BARN|WORK", name):
                add("warning", "spacing", f"{name.title()} has no receptacles")
            if SLEEP.search(name) and not accessory and not any(t in ("smoke", "smoke_co") for t in types):
                add("warning", "smoke", f"{name.title()} needs a smoke alarm (IRC R314)")
    # -- the panel's load (a rough demand check, for estimating)
    va = 0.0
    for d in devs:
        t = d["type"]
        va += 180 if t in RECEPT else 100 if t in LIGHTS else 0
    for c in design["circuits"]:
        if c["poles"] >= 2:
            va += c["amps"] * 240 * 0.8
    amps_needed = va / 240.0
    p = design["panel"]
    if amps_needed > p["amps"] * 0.8:
        add("warning", "load", f"connected load about {amps_needed:.0f} A at 240 V on a {p['amps']} A panel - check the"
            " load calculation")
    fb = p.get("feeder_breaker_amps")
    if p["kind"] == "subpanel":
        if fb and fb > p["amps"]:
            add("error", "feeder", f"the feeder breaker ({fb} A) is bigger than the {p['amps']} A subpanel")
        if fb and amps_needed * 0.6 > fb:
            add("warning", "feeder", f"the feeder breaker ({fb} A) may be small for about {amps_needed:.0f} A connected"
                " (check the load calculation)")
        if not p.get("fed_from"):
            add("info", "feeder", "the design doesn't say what feeds the subpanel")
    room = _room_at(floors[p["floor"]], p["x"], p["y"])
    if re.search(r"BATH|CLOSET|CLO\b|WIC", room or ""):
        add("error", "panel_room", f"the panel is in the {room.title()} - not allowed (NEC 240.24)")
    order = {"error": 0, "warning": 1, "info": 2}
    return sorted(out, key=lambda f: order[f["level"]])


def summary(design: dict) -> dict:
    """What the design adds, counted - for the card and the approval."""
    from collections import Counter
    n = Counter(d["type"] for d in design["devices"])
    return {"devices": dict(n), "total": sum(n.values()), "circuits": len(design["circuits"]),
            "panel": f"{design['panel']['amps']} A {'subpanel' if design['panel']['kind'] == 'subpanel' else 'main panel'}"}
