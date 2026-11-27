"""Plans from a description (2026-11-24, David: "If the user does not have plans I want the user to be able to use AI
Design button so the user can just describe the plans and have AI Design it for him" - for every trade, as a drawn plan).

The person describes the job in plain words ("back yard 100 x 80, 6 ft wood privacy fence on 3 sides with a 4 ft walk
gate and a 12 ft drive gate", "a 20 x 30 shed on a 4 in slab, gable roof 4:12, one roll-up door, two windows ..."); the
AI answers with one JSON design of the whole job in feet - the site (lot, fences, gates, landscape zones, concrete
flatwork), the building (floors, walls, rooms, doors, windows, foundation, roof) and the fixtures (plumbing, HVAC,
landscape symbols) - and the app draws it as a set of CAD sheets (estimator/design/draw_plans.py) on the layers the plan
engine already reads, so AI Auto Measure/Count and the plan readers measure it like any designer's plans.

One frame for everything: x to the right along the front (street) line, y toward the back, in feet, origin at the
front-left corner of the lot (or of the work area when there's no lot). The building's corners are in the same frame.

parse_design() refuses an answer that isn't usable (no building and nothing on the site, a fence of one point, a room
outside its building ...). check() is the app's own sanity check on a usable design: error (must be changed before it's
approved), warning (look at it) or info. The person changes the design in plain words; the AI returns the whole new
design and what changed. Nothing is priced until the person approves the drawings (runs.py).
"""
from __future__ import annotations

import json
import math
import re

from estimator.design import building as bmod

TRADE = "plans"
MAX_FT = 2000.0
DESIGN_SYSTEM = ("You are an experienced residential and light-commercial designer and estimator. From a customer's "
                 "description you lay out the whole job as plans a contractor can build and price from: the site, the "
                 "building and the fixtures, in feet. You make sensible, buildable, code-minded choices for anything the "
                 "description leaves open and list them as assumptions. Reply with ONLY one JSON object, nothing else.")

FENCE_MATERIALS = ("wood", "vinyl", "chain_link", "aluminum", "iron", "block")   # the fencing trade's materials
ZONE_KINDS = ("sod", "turf", "mulch", "rock", "pavers", "bed")
FLATWORK_KINDS = ("driveway", "patio", "sidewalk", "pad", "slab", "porch")
ROOF_STYLES = ("gable", "hip", "shed", "flat")
FOUNDATIONS = ("slab", "piers", "crawl", "none")
DOOR_TYPES = ("exterior", "interior", "garage", "patio")
UNITS = ("lf", "sqft", "ea", "cy", "sq")
# The fixtures the plan engine counts by symbol (plan_engine/symbol_library.py): plumbing, HVAC and landscape. Electrical
# devices are designed by the electrical designer once the building is drawn (it places and circuits every device).
FIXTURES = {
    "water_closet": "Toilet", "lavatory": "Bathroom sink", "kitchen_sink": "Kitchen sink", "laundry_sink": "Laundry sink",
    "shower": "Shower", "tub": "Tub", "tub_shower": "Tub and shower", "dishwasher": "Dishwasher",
    "washer_box": "Washer box", "hose_bibb": "Hose bibb", "water_heater": "Water heater (tank)",
    "tankless_water_heater": "Tankless water heater", "floor_drain": "Floor drain",
    "condensing_unit": "A/C condenser (outdoor)", "heat_pump": "Heat pump (outdoor)", "air_handler": "Air handler",
    "furnace": "Furnace", "mini_split_head": "Mini-split indoor head", "supply_diffuser": "Supply register",
    "return_grille": "Return grille", "thermostat": "Thermostat", "exhaust_fan": "Exhaust fan",
    "tree": "Tree", "palm": "Palm", "shrub": "Shrub",
}

SHAPE = """{
  "summary": "one or two sentences: what was laid out",
  "assumptions": ["each choice the description didn't say, e.g. 'posts 8 ft on center', 'slab 4 in thick'"],
  "lot": {"width_ft": 100, "depth_ft": 150} or null (no lot shown),
  "building": null, or {
    "name": "SHED", "kind": "accessory" | "dwelling" | "commercial",
    "floors": [{"name": "GROUND", "ceiling_ft": 9,
                "outline": [[x, y], ...]  (the exterior walls' corners, in order, in the site frame),
                "openings": [{"kind": "door" | "overhead_door" | "window" | "opening", "a": [x, y], "b": [x, y],
                              "mark": "D1"  (its door or window schedule mark), "label": "12'x10' roll-up"}],
                "interior_walls": [[[x, y], [x, y]], ...],
                "rooms": [{"name": "BEDROOM", "x0": 0, "y0": 0, "x1": 12, "y1": 14, "floor": "LVP" | "carpet" |
                           "tile" | "wood" | "concrete" | "", "ceiling_ft": 9}]}],
    "wall_thickness_in": 6,
    "foundation": {"kind": "slab" | "piers" | "crawl" | "none", "thickness_in": 4, "footing_in": 12},
    "roof": {"style": "gable" | "hip" | "shed" | "flat", "pitch": "4:12", "overhang_ft": 1,
             "ridge": "x" | "y" (the ridge runs along x or along y), "material": "architectural shingle"} or null,
    "siding": "vinyl lap" or ""
  },
  "doors": [{"mark": "D1", "width_ft": 3, "height_ft": 6.67, "type": "exterior" | "interior" | "garage" | "patio",
             "description": "36in insulated steel entry"}],
  "windows": [{"mark": "W1", "width_ft": 3, "height_ft": 4, "description": "single hung vinyl"}],
  "fixtures": [{"type": "<one of the fixture types>", "x": 10, "y": 12}],
  "fences": [{"points": [[x, y], [x, y], ...],
              "material": "wood" | "vinyl" | "chain_link" | "aluminum" | "iron" (wrought iron) | "block",
              "style": "privacy" | "picket" | "split rail" | "pool barrier" | "", "height_ft": 6 (4 ft 6 in = 4.5),
              "remove_existing": false,
              "product": {"manufacturer": "<the maker chosen>" or "", "model": "<the model chosen>" or "",
                          "panel": "54 in x 6 ft" or "", "color": "black" or "",
                          "details": "picket size and spacing, rails, finish - as chosen" or ""}}],
  "gates": [{"at": [x, y] (on a fence line), "kind": "walk" | "drive", "width_ft": 4,
             "latch_at": [x, y] (the latch post - the end of the opening the gate latches at) or null,
             "opens_toward": [x, y] (any point on the side the gate swings into) or null,
             "product": {"manufacturer": "<the maker chosen>" or "", "model": "<the model chosen>" or "",
                         "color": "", "hinges": "<the hinges chosen>" or "", "latch": "<the latch chosen>" or ""}}],
  "zones": [{"kind": "sod" | "turf" | "mulch" | "rock" | "pavers" | "bed", "points": [[x, y], ...],
             "description": "St. Augustine sod", "depth_in": 3}],
  "flatwork": [{"kind": "driveway" | "patio" | "sidewalk" | "pad" | "slab" | "porch", "points": [[x, y], ...],
                "thickness_in": 4}],
  "demolition": [{"what": "remove the old chain link fence", "qty": 120, "unit": "lf" | "sqft" | "ea" | "cy" | "sq"}],
  "notes": ["anything the builder must know: permits, setbacks, survey, HOA"],
  "changes": ["on a change only: each thing that changed"]
}"""

RULES = """How to lay it out:
- One frame for everything, in feet: x to the right along the front (street) line, y toward the back, origin at the
  front-left corner of the lot (or of the work area). Building corners, fence points, zones and flatwork all use it.
- Use the sizes the description gives; where it gives none, pick normal sizes and say so in "assumptions".
- A fence: one entry per straight-or-bent run between ends (a run can turn corners: list every corner point). A fence
  around the back yard of a house usually runs from the house's back corners out to the side lot lines and along them.
  Gates sit ON a fence line (their point is on a run). A drive gate is 10-12 ft; a walk gate 4 ft.
  Give every gate its latch post ("latch_at": a point at the end of the opening where it latches - the side the person
  asks for, else the side you choose) and which way it swings ("opens_toward": any point a few feet off the fence on
  the side the gate opens into). A pool barrier gate latches on the side the person asks for and opens OUTWARD, away
  from the pool. A double drive gate swings from both posts and has no latch post (latch_at null).
  The fence and gate "product" is what gets ordered: fill it ONLY with what the person (or the specs) chose - the
  maker, model, panel size, color, hinges and latch. Never invent a maker or model; leave what wasn't chosen "" (the
  drawing says TO BE SELECTED). A change that picks or changes a product updates "product" on every run and gate it
  applies to.
  Use exactly the fence material and height the person asks for ("aluminum powder coated" is aluminum, not iron; 4' 6"
  is 4.5). A pool barrier is usually aluminum, at least 4 ft high, with self-closing, self-latching gates.
- Landscape zones and concrete flatwork are closed outlines (3 or more corners, not repeating the first).
- A building: exterior walls as its outline (corners in order), interior walls as segments, every room as a rectangle
  inside the outline, every door and window as an opening on a wall (a and b are its two ends on that wall) with the mark
  of its row in "doors" or "windows". Give a building only when the job has one (a fence-only job has building null).
- Plumbing, HVAC and landscape items are "fixtures" (types: {types}). Do not place electrical devices: the electrical
  designer does that on the drawn building.
- Demolition: only what the description says comes out (old fence, old slab, ...), with its quantity.
- Keep it buildable: no fence or wall crossing the building, rooms inside their building, gates on a fence."""


class DesignError(Exception):
    """The AI's design isn't usable. The message is safe to show."""


def design_prompt(request: str, specs: str, trades: list[str] | None = None, address: str = "", extra: str = "") -> str:
    """extra: what ✨ Run AI design's choices add (2026-11-27) - the trades' questions to fill in (trade_answers.py)."""
    want = ", ".join(trades or []) or "whatever the description needs"
    return (f"Lay out this job as plans.\n\nThe customer's description:\n{request}\n\n"
            + (f"Specs and preferences:\n{specs}\n\n" if specs else "")
            + (f"Job address: {address}\n\n" if address else "")
            + f"The trades being quoted: {want}. Draw what each of them needs (a fence job needs the fence lines and "
              "gates; a slab needs its outline and thickness; a building needs its walls, rooms, doors, windows, "
              "foundation and roof).\n\n"
            + RULES.replace("{types}", ", ".join(FIXTURES)) + "\n\nAnswer with this JSON:\n" + SHAPE + extra)


def change_prompt(design: dict, change: str, request: str, specs: str, extra: str = "") -> str:
    return (f"Here is the current design of the job (JSON):\n{json.dumps(_for_prompt(design))}\n\nThe original "
            f"description:\n{request}\n\n" + (f"Specs:\n{specs}\n\n" if specs else "")
            + f"Make this change:\n{change}\n\nReturn the WHOLE new design (not only the changed part), with "
              "\"changes\" listing each thing that changed.\n\n" + RULES.replace("{types}", ", ".join(FIXTURES))
            + "\n\nAnswer with this JSON:\n" + SHAPE + extra)


def images_note(shots: int, has_design: bool) -> str:
    """2026-11-25 (David: "I took a screen clip of the area where I want a fence to be added, but there is no way to Ctrl V
    add an image to the design description"): what the pictures sent with a description or a change are, and how to
    use them - an aerial photo, a survey or site map, a photo of the yard, a clip of a drawing, often with marks on it."""
    return (
        f"\n\nPICTURES: the {shots} picture(s) are the person's own screenshots or photos of the job - an aerial or"
        " satellite view, a survey or plot plan, a photo of the yard or building, or a clip of a drawing - often with"
        " marks, lines, arrows, circles or notes on them that show what they mean ('fence here', 'gate', 'this area')."
        " Use them for the layout: where things go, their shapes, which sides, and what is already there (the house,"
        " the driveway, trees). Take sizes from the written description first, then from dimensions or a scale bar"
        " shown on a picture, then from things of known size in it (a car is about 15 ft long, a single garage door"
        " about 9 ft wide, a sidewalk about 4 ft wide); say in assumptions which sizes you estimated and how. Put the"
        " drawing on the lot as the pictures show it, in the one frame of the rules above (x along the street line,"
        " y toward the back, origin at the front-left corner); if a picture's top isn't the back of the lot, turn it in"
        " your head first."
        + (" The design already exists: change only what the pictures and the change ask for." if has_design else "")
        + " If a mark is unclear, do what it most likely means and say so in assumptions.")


def fix_prompt(design: dict, findings: list[dict], request: str) -> str:
    errs = "\n".join(f"- {f['message']}" for f in findings if f["level"] == "error")
    return (f"The design below has errors the app's check found:\n{errs}\n\nThe design (JSON):\n"
            f"{json.dumps(_for_prompt(design))}\n\nThe description:\n{request}\n\nFix every error and return the WHOLE "
            "design, with \"changes\" listing what you fixed.\n\nAnswer with this JSON:\n" + SHAPE)


def _for_prompt(d: dict) -> dict:
    return {k: v for k, v in d.items() if not k.startswith("_")}


# ------------------------------------------------------------------ reading the AI's answer
def _json(text: str) -> dict:
    t = (text or "").strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.I | re.S)
    a, b = t.find("{"), t.rfind("}")
    if a < 0 or b <= a:
        raise DesignError("the AI didn't answer with a design")
    try:
        obj = json.loads(t[a:b + 1])
    except ValueError:
        raise DesignError("the AI's design wasn't readable JSON") from None
    if not isinstance(obj, dict):
        raise DesignError("the AI's design wasn't a JSON object")
    return obj


def _num(v, what, lo=0.0, hi=MAX_FT, default=None):
    if v is None or v == "":
        if default is not None:
            return default
        raise DesignError(f"{what} is missing")
    try:
        x = float(str(v).replace("'", "").replace("ft", "").strip())
    except (TypeError, ValueError):
        if default is not None:
            return default
        raise DesignError(f"{what} isn't a number ({v!r})") from None
    if not math.isfinite(x) or x < lo or x > hi:
        if default is not None:
            return default
        raise DesignError(f"{what} ({x:g}) is out of range")
    return round(x, 2)


def _pt(v, what):
    if not isinstance(v, (list, tuple)) or len(v) != 2:
        raise DesignError(f"{what} isn't an [x, y] point")
    return [_num(v[0], what + " x", -MAX_FT), _num(v[1], what + " y", -MAX_FT)]


FENCE_PRODUCT = ("manufacturer", "model", "panel", "color", "details")
GATE_PRODUCT = ("manufacturer", "model", "color", "hinges", "latch")


def _product(v, keys) -> dict:
    """2026-11-27 (David: "we're gonna need to know the actual fence model in size on the drawing ... when we order the
    fence size and style and type it conforms to ... what he has picked"): the product chosen for a fence run or a gate.
    Only what the AI was told; "" where nothing was chosen (the drawing says TO BE SELECTED)."""
    v = v if isinstance(v, dict) else {}
    return {k: _text(v.get(k), 160) for k in keys}


def _pt_or_none(v):
    """An optional [x, y] point: None when it's missing or not a usable point."""
    if v is None:
        return None
    try:
        return _pt(v, "a point")
    except DesignError:
        return None


def _pts(v, what, closed=False):
    pts = [_pt(p, f"{what} point") for p in (v or [])]
    out = []
    for p in pts:                                   # drop repeated points
        if not out or math.dist(out[-1], p) > 0.05:
            out.append(p)
    if closed and len(out) > 3 and math.dist(out[0], out[-1]) <= 0.05:
        out.pop()
    if len(out) < (3 if closed else 2):
        raise DesignError(f"{what} needs at least {3 if closed else 2} points")
    return out


def _word(v, allowed, default):
    w = str(v or "").strip().lower().replace(" ", "_").replace("-", "_")
    return w if w in allowed else default


def _text(v, n=200):
    return str(v or "").strip()[:n]


def _texts(v, n=20, size=240):
    return [_text(x, size) for x in (v if isinstance(v, list) else [v] if v else []) if _text(x, size)][:n]


def _mark(v, prefix, i):
    m = re.sub(r"[^A-Z0-9\-]", "", str(v or "").upper())[:6]
    return m or f"{prefix}{i}"


def parse_design(text: str, drawing: bool = True) -> dict:
    """The AI's design, checked for shape and tidied. Raises DesignError when it isn't usable. drawing=False (✨ Run AI
    design without "Draw the plans", 2026-11-27): a design with nothing to draw is fine when it fills in the estimate."""
    d = _json(text)
    out = {"summary": _text(d.get("summary"), 400), "assumptions": _texts(d.get("assumptions"), 30),
           # 2026-11-27: a note is kept whole (it was cut at 240 characters, mid-word: "... SO PAV")
           "notes": _texts(d.get("notes"), 30, 1000), "changes": _texts(d.get("changes"), 30, 600)}
    # 2026-11-27: the trades' own answers, when ✨ Run AI design is asked to price the estimate (trade_answers.py)
    from estimator.design import trade_answers
    out["trade_answers"] = trade_answers.parse(d.get("trade_answers"))
    lot = d.get("lot")
    out["lot"] = ({"width_ft": _num(lot.get("width_ft"), "lot width", 5), "depth_ft": _num(lot.get("depth_ft"),
                                                                                           "lot depth", 5)}
                  if isinstance(lot, dict) and lot.get("width_ft") and lot.get("depth_ft") else None)
    # doors and windows (the schedules)
    doors, windows = [], []
    for i, x in enumerate(d.get("doors") or [], 1):
        if isinstance(x, dict):
            doors.append({"mark": _mark(x.get("mark"), "D", i), "width_ft": _num(x.get("width_ft"), "a door width", 1, 40, 3.0),
                          "height_ft": _num(x.get("height_ft"), "a door height", 5, 20, 6.67),
                          "type": _word(x.get("type"), DOOR_TYPES, "exterior"), "description": _text(x.get("description"), 60)})
    for i, x in enumerate(d.get("windows") or [], 1):
        if isinstance(x, dict):
            windows.append({"mark": _mark(x.get("mark"), "W", i), "width_ft": _num(x.get("width_ft"), "a window width", 1, 20, 3.0),
                            "height_ft": _num(x.get("height_ft"), "a window height", 1, 12, 4.0),
                            "description": _text(x.get("description"), 60)})
    out["doors"], out["windows"] = _unique(doors), _unique(windows)
    # the building (the same shape as building.py, plus each opening's mark and each room's finish)
    out["building"] = None
    b = d.get("building")
    if isinstance(b, dict) and b.get("floors"):
        marks, finishes = [], []
        for f in b.get("floors") or []:
            fm, ff = [], {}
            for o in (f.get("openings") or []) if isinstance(f, dict) else []:
                if isinstance(o, dict) and o.get("a") is not None and o.get("b") is not None:
                    fm.append(_mark(o.get("mark"), "", 0) if o.get("mark") else "")
            for r in (f.get("rooms") or []) if isinstance(f, dict) else []:
                if isinstance(r, dict) and r.get("name"):
                    ff[str(r["name"]).strip().upper()[:30]] = {"floor": _text(r.get("floor"), 20),
                                                              "ceiling_ft": _num(r.get("ceiling_ft"), "a ceiling", 7, 40, 0) or None}
            marks.append(fm)
            finishes.append(ff)
        try:
            bb = bmod.clean({**b, "floors": [{**f, "outline": f.get("outline")} for f in b["floors"]]}, "ai")
        except bmod.BuildingError as exc:
            raise DesignError(f"the building isn't usable: {exc}") from None
        for fi, fl in enumerate(bb["floors"]):
            fm = marks[fi] if fi < len(marks) else []
            for oi, op in enumerate(fl["openings"]):
                op["mark"] = fm[oi] if oi < len(fm) else ""
            ff = finishes[fi] if fi < len(finishes) else {}
            for rm in fl["rooms"]:
                extra = ff.get(rm["name"]) or {}
                rm["floor"] = extra.get("floor") or ""
                rm["ceiling_ft"] = extra.get("ceiling_ft") or fl["ceiling_ft"]
        fnd = b.get("foundation") if isinstance(b.get("foundation"), dict) else {}
        roof = b.get("roof") if isinstance(b.get("roof"), dict) else None
        bb["wall_thickness_in"] = _num(b.get("wall_thickness_in"), "the wall thickness", 3, 16, 6.0)
        bb["foundation"] = {"kind": _word(fnd.get("kind"), FOUNDATIONS, "slab"),
                            "thickness_in": _num(fnd.get("thickness_in"), "the slab thickness", 3, 24, 4.0),
                            "footing_in": _num(fnd.get("footing_in"), "the footing", 0, 48, 12.0)}
        bb["roof"] = ({"style": _word(roof.get("style"), ROOF_STYLES, "gable"), "pitch": _pitch(roof.get("pitch")),
                       "overhang_ft": _num(roof.get("overhang_ft"), "the overhang", 0, 6, 1.0),
                       "ridge": "y" if str(roof.get("ridge") or "").lower() == "y" else "x",
                       "material": _text(roof.get("material"), 40) or "architectural shingle"} if roof else None)
        bb["siding"] = _text(b.get("siding"), 40)
        out["building"] = bb
    # fixtures
    out["fixtures"] = []
    for x in d.get("fixtures") or []:
        if isinstance(x, dict) and _word(x.get("type"), FIXTURES, None):
            out["fixtures"].append({"type": _word(x.get("type"), FIXTURES, None),
                                    "x": _num(x.get("x"), "a fixture x", -MAX_FT), "y": _num(x.get("y"), "a fixture y", -MAX_FT)})
    # the site
    out["fences"] = []
    for i, x in enumerate(d.get("fences") or [], 1):
        if isinstance(x, dict):
            out["fences"].append({"points": _pts(x.get("points"), f"fence run {i}"),
                                  "material": _word(x.get("material"), FENCE_MATERIALS, "wood"),
                                  "style": _text(x.get("style"), 20), "height_ft": _num(x.get("height_ft"), "a fence height", 2, 12, 6.0),
                                  "remove_existing": bool(x.get("remove_existing")),
                                  "product": _product(x.get("product"), FENCE_PRODUCT)})
    out["gates"] = []
    for x in d.get("gates") or []:
        if isinstance(x, dict) and x.get("at") is not None:
            w = _num(x.get("width_ft"), "a gate width", 2, 30, 4.0)
            kind = _word(x.get("kind"), ("walk", "drive"), "drive" if w >= 8 else "walk")
            out["gates"].append({"at": _pt(x.get("at"), "a gate"), "kind": kind, "width_ft": w,
                                 # 2026-11-27 (David: show the latch, the hinge and the swing): optional - a bad point is
                                 # dropped (the gate is still drawn, without them)
                                 "latch_at": _pt_or_none(x.get("latch_at")),
                                 "opens_toward": _pt_or_none(x.get("opens_toward")),
                                 "product": _product(x.get("product"), GATE_PRODUCT)})
    out["zones"] = []
    for i, x in enumerate(d.get("zones") or [], 1):
        if isinstance(x, dict):
            out["zones"].append({"kind": _word(x.get("kind"), ZONE_KINDS, "sod"), "points": _pts(x.get("points"), f"zone {i}", True),
                                 "description": _text(x.get("description"), 40),
                                 "depth_in": _num(x.get("depth_in"), "a zone depth", 0, 24, 0) or None})
    out["flatwork"] = []
    for i, x in enumerate(d.get("flatwork") or [], 1):
        if isinstance(x, dict):
            out["flatwork"].append({"kind": _word(x.get("kind"), FLATWORK_KINDS, "slab"),
                                    "points": _pts(x.get("points"), f"concrete area {i}", True),
                                    "thickness_in": _num(x.get("thickness_in"), "a concrete thickness", 3, 24, 4.0)})
    out["demolition"] = []
    for x in d.get("demolition") or []:
        if isinstance(x, dict) and _text(x.get("what")):
            out["demolition"].append({"what": _text(x.get("what"), 80), "qty": _num(x.get("qty"), "a demolition quantity", 0, 1e6, 0),
                                      "unit": _word(x.get("unit"), UNITS, "ea")})
    if not (out["building"] or out["fences"] or out["zones"] or out["flatwork"] or out["fixtures"]):
        if drawing or not (out["trade_answers"] or out["demolition"]):
            raise DesignError("the design has nothing to draw - no building, fence, landscape or concrete"
                              + ("" if drawing else " - and no answers for the estimate"))
    return out


def _unique(rows):
    seen, out = set(), []
    for r in rows:
        if r["mark"] not in seen:
            seen.add(r["mark"])
            out.append(r)
    return out


def _pitch(v) -> str:
    m = re.search(r"(\d{1,2}(?:\.\d)?)\s*(?:[:/]|\s*in\s*)\s*12", str(v or ""))
    rise = float(m.group(1)) if m else 4.0
    return f"{rise:g}:12" if 0 <= rise <= 24 else "4:12"


# ------------------------------------------------------------------ quantities (the drawing prints them; the checks use them)
def poly_len(pts, closed=False) -> float:
    ps = pts + ([pts[0]] if closed else [])
    return sum(math.dist(a, b) for a, b in zip(ps, ps[1:]))


def poly_area(pts) -> float:
    return abs(sum(a[0] * b[1] - b[0] * a[1] for a, b in zip(pts, pts[1:] + pts[:1]))) / 2.0


def concrete_answers(d: dict) -> dict:
    """2026-11-25 (David: "a change to the drawing is treated like the current one and estimates are based on it ... the
    electrical and cement as well"): the concrete trade's quantities straight from the design the AI drew - the building's
    slab (its outline, thickness and thickened edge) and every flatwork pour - so the foundation plan is measured the
    moment it's drawn, with no AI call. {} when the job has no concrete."""
    area = edge = footing = 0.0
    thick = []
    b = d.get("building")
    if b and (b.get("foundation") or {}).get("kind") == "slab" and b.get("floors"):
        outline = b["floors"][0]["outline"]
        area += poly_area(outline)
        edge += poly_len(outline, closed=True)
        if (b["foundation"].get("footing_in") or 0) > 0:
            footing += poly_len(outline, closed=True)
        thick.append(b["foundation"].get("thickness_in") or 4)
    for x in d.get("flatwork") or []:
        area += poly_area(x["points"])
        edge += poly_len(x["points"], closed=True)
        thick.append(x.get("thickness_in") or 4)
    if area <= 0:
        return {}
    t = max(thick) if thick else 4
    out = {"area_sqft": round(area, 1), "perimeter_lf": round(edge, 1),
           "thickness_in": "6" if t >= 5.5 else "5" if t >= 4.5 else "4"}
    if footing:
        out["footing_lf"] = round(footing, 1)
    return out


def roof_numbers(b: dict) -> dict:
    """Plan area under the roof (the outline plus the overhang), the sloped area and squares, eaves, ridge, rakes."""
    r = b.get("roof")
    if not r:
        return {}
    xs = [p[0] for p in b["floors"][0]["outline"]]
    ys = [p[1] for p in b["floors"][0]["outline"]]
    o = r["overhang_ft"]
    w, d = max(xs) - min(xs) + 2 * o, max(ys) - min(ys) + 2 * o
    rise = float(r["pitch"].split(":")[0])
    slope = math.sqrt(1 + (rise / 12.0) ** 2)
    plan = poly_area(b["floors"][0]["outline"]) + 2 * o * (w + d - 2 * o)        # outline + an overhang band
    along, across = (w, d) if r["ridge"] == "x" else (d, w)
    if r["style"] == "flat":
        slope = 1.0
    out = {"plan_sqft": round(plan, 1), "roof_sqft": round(plan * slope, 1), "squares": round(plan * slope / 100.0, 1),
           "pitch": r["pitch"], "eave_lf": round(2 * along if r["style"] in ("gable", "shed") else 2 * (w + d), 1)}
    if r["style"] == "gable":
        out["ridge_lf"] = round(along, 1)
        out["rake_lf"] = round(2 * across * slope, 1)
    elif r["style"] == "hip":
        out["ridge_lf"] = round(max(along - across, 0), 1)
        out["hip_lf"] = round(4 * math.hypot(across / 2, across / 2) * slope, 1)
    elif r["style"] == "shed":
        out["rake_lf"] = round(2 * across * slope, 1)
        out["eave_lf"] = round(2 * along, 1)
    return out


def summary(d: dict) -> dict:
    """What the design has, counted - for the card and the approval question."""
    b = d.get("building")
    rooms = sum(len(f["rooms"]) for f in b["floors"]) if b else 0
    area = sum(poly_area(f["outline"]) for f in b["floors"]) if b else 0
    ops = [o for f in (b["floors"] if b else []) for o in f["openings"]]
    out = {"building": (b or {}).get("name") or "", "floors": len(b["floors"]) if b else 0, "rooms": rooms,
           "floor_sqft": round(area, 1), "doors": sum(1 for o in ops if o["kind"] in ("door", "overhead_door")),
           "windows": sum(1 for o in ops if o["kind"] == "window"),
           "fence_lf": round(sum(poly_len(f["points"]) for f in d.get("fences") or []), 1),
           "gates": len(d.get("gates") or []), "zones_sqft": round(sum(poly_area(z["points"]) for z in d.get("zones") or []), 1),
           "concrete_sqft": round(sum(poly_area(z["points"]) for z in d.get("flatwork") or []), 1),
           "fixtures": len(d.get("fixtures") or []), "demolition": len(d.get("demolition") or [])}
    if b and b["foundation"]["kind"] == "slab":
        out["slab_sqft"] = round(poly_area(b["floors"][0]["outline"]), 1)
    if b and b.get("roof"):
        out["roof_squares"] = roof_numbers(b).get("squares")
    return out


def sheets_for(d: dict) -> list[str]:
    """Which sheets the design draws (draw_plans.SHEETS keys)."""
    b = d.get("building")
    out = []
    if d.get("fences") or d.get("gates") or d.get("zones") or d.get("flatwork") or d.get("lot") or \
            any(f["type"] in ("tree", "palm", "shrub") for f in d.get("fixtures") or []):
        out.append("site")
    if b:
        out.append("floor")
        if b["foundation"]["kind"] == "slab":
            out.append("foundation")
        if b.get("roof"):
            out.append("roof")
    if d.get("demolition"):
        out.append("demolition")
    return out


# ------------------------------------------------------------------ the app's own check
def _inside(p, poly) -> bool:
    x, y = p
    c = False
    for (ax, ay), (bx, by) in zip(poly, poly[1:] + poly[:1]):
        if (ay > y) != (by > y) and x < (bx - ax) * (y - ay) / (by - ay or 1e-12) + ax:
            c = not c
    return c


def _seg_dist(p, a, b) -> float:
    ax, ay = a
    bx, by = b
    dx, dy = bx - ax, by - ay
    L2 = dx * dx + dy * dy or 1e-12
    t = max(0.0, min(1.0, ((p[0] - ax) * dx + (p[1] - ay) * dy) / L2))
    return math.dist(p, (ax + t * dx, ay + t * dy))


def _on_poly(p, pts, closed=False) -> float:
    ps = pts + ([pts[0]] if closed else [])
    return min(_seg_dist(p, a, b) for a, b in zip(ps, ps[1:]))


def check(d: dict, drawing: bool = True) -> list[dict]:
    """Sanity checks on the design: error (change it before approving), warning, info. drawing=False: nothing to measure
    isn't an error when the design fills in the estimate itself (2026-11-27)."""
    out = []

    def f(level, code, message):
        out.append({"level": level, "code": code, "message": message})
    b = d.get("building")
    if b:
        marks = {x["mark"] for x in d.get("doors") or []} | {x["mark"] for x in d.get("windows") or []}
        for fl in b["floors"]:
            poly = fl["outline"]
            if poly_area(poly) < 16:
                f("error", "tiny_building", f"{fl['name']}: the building is under 16 sq ft")
            for rm in fl["rooms"]:
                c = ((rm["x0"] + rm["x1"]) / 2, (rm["y0"] + rm["y1"]) / 2)
                if not _inside(c, poly):
                    f("error", "room_outside", f"{fl['name']}: room {rm['name']} is outside the building")
                if (rm["x1"] - rm["x0"]) < 3 or (rm["y1"] - rm["y0"]) < 3:
                    f("warning", "tiny_room", f"{fl['name']}: room {rm['name']} is under 3 ft across")
            for op in fl["openings"]:
                mid = ((op["a"][0] + op["b"][0]) / 2, (op["a"][1] + op["b"][1]) / 2)
                walls = [w for w in fl["interior_walls"]]
                near = min([_on_poly(mid, poly, True)] + [_seg_dist(mid, w[0], w[1]) for w in walls])
                if near > 1.5:
                    f("error", "opening_off_wall", f"{fl['name']}: the {op['kind'].replace('_', ' ')} {op['mark'] or ''}"
                      f" at ({mid[0]:g}, {mid[1]:g}) isn't on a wall")
                if op["kind"] in ("door", "overhead_door", "window") and op["mark"] and op["mark"] not in marks:
                    f("warning", "no_schedule_row", f"{fl['name']}: {op['mark']} has no row in the door or window schedule"
                                                     " (a standard size is used)")
                if op["kind"] in ("door", "overhead_door", "window") and not op["mark"]:
                    f("info", "no_mark", f"{fl['name']}: a {op['kind'].replace('_', ' ')} has no mark, so a standard size"
                                         " is used")
        if b.get("roof") and b["roof"]["style"] != "flat" and float(b["roof"]["pitch"].split(":")[0]) < 2:
            f("warning", "low_pitch", f"a {b['roof']['pitch']} pitch is too low for shingles (2:12 is the least with"
                                      " special underlayment, 4:12 normal)")
        foot = b["floors"][0]["outline"]
    else:
        foot = None
    for i, fe in enumerate(d.get("fences") or [], 1):
        if poly_len(fe["points"]) < 4:
            f("error", "short_fence", f"fence run {i} is under 4 ft")
        if foot and any(_inside(p, foot) for p in fe["points"][1:-1]):
            f("error", "fence_in_building", f"fence run {i} goes through the building")
        if d.get("lot"):
            W, D = d["lot"]["width_ft"], d["lot"]["depth_ft"]
            if any(p[0] < -1 or p[1] < -1 or p[0] > W + 1 or p[1] > D + 1 for p in fe["points"]):
                f("warning", "fence_off_lot", f"fence run {i} goes past the lot line - check the survey")
    for g in d.get("gates") or []:
        fences = d.get("fences") or []
        if not fences or min(_on_poly(g["at"], fe["points"]) for fe in fences) > 1.0:
            f("error", "gate_off_fence", f"the {g['kind']} gate at ({g['at'][0]:g}, {g['at'][1]:g}) isn't on a fence line")
    for i, z in enumerate(d.get("zones") or [], 1):
        if poly_area(z["points"]) < 4:
            f("warning", "tiny_zone", f"landscape zone {i} ({z['kind']}) is under 4 sq ft")
    for i, z in enumerate(d.get("flatwork") or [], 1):
        if poly_area(z["points"]) < 4:
            f("error", "tiny_concrete", f"concrete area {i} ({z['kind']}) is under 4 sq ft")
    if not b and not d.get("fences") and not d.get("flatwork") and not d.get("zones"):
        if drawing or not (d.get("trade_answers") or d.get("demolition")):
            f("error", "nothing", "the design has nothing a trade can measure")
    return out
