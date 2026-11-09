"""Exterior elevations (Coder 2 Sprint 14): the outside wall of each side of the building, and the doors and windows in
it, from the elevation view's line work. They give siding and exterior paint their wall area (all sides), which a floor
plan can't: real wall heights, gables left out, each side once.

For each view titled "... ELEVATION" (not interior or cabinet elevations) with a scale:
- the line work is joined into closed areas (shapely) and the building's outline is the biggest joined area that isn't
  the view's frame;
- the wall band runs from the floor line up to the plate line, read from the level marks written beside them
  ("T.O. PLATE", "FIN. FLR", "GRADE"...). Without a plate mark the band is the whole outline and the view says the
  roof may be in it (check); without a floor mark it goes to the bottom of the outline;
- openings are the rectangles inside the wall band that are opening-sized (at least 1'-3" each way, at most 150 sq ft,
  narrower than 60% of the wall so lap-siding courses aren't taken for one); a door reaches the floor line and is at
  least 6 ft high, a garage door is a door 7 ft or wider.
Saved as drawing objects: the wall as a polygon on layer ELEVATION-WALL, each opening as an "opening" polygon on layer
ELEVATION-OPENING, so they're measured with the view's scale like everything else. Walls and rooms aren't looked for in
an elevation (a facade's siding lines aren't walls).
"""
from __future__ import annotations

import re

ELEV_RE = re.compile(r"\bELEVATIONS?\b", re.I)
NOT_EXTERIOR_RE = re.compile(r"\b(INTERIOR|INT\.|CABINET|CASEWORK|KITCHEN|BATH|VANITY|FIREPLACE|STAIR)\b", re.I)
PLATE_RE = re.compile(r"\b(T\.?\s?O\.?\s?(PLATE|PL|WALL)|TOP\s+OF\s+(PLATE|WALL)|PLATE(\s+(HT|HEIGHT|LINE))?|BRG\.?|BEARING|EAVE)\b", re.I)
BASE_RE = re.compile(r"\b(F\.?\s?F\.?\s?E?\.?|FIN(ISH(ED)?)?\.?\s*(FLR|FLOOR)|FIRST\s+FLOOR|1ST\s+(FLR|FLOOR)|"
                     r"T\.?\s?O\.?\s?(SLAB|FOUNDATION)|SLAB|GRADE|LEVEL\s+1)\b", re.I)
MIN_OPENING_FT = 1.25
MAX_OPENING_SQFT = 150.0
MAX_OPENING_SHARE = 0.6
RECT = 0.92                     # area / bounding-box area that counts as a rectangle
MAX_SEGMENTS = 25000


def is_exterior_elevation(label: str | None) -> bool:
    return bool(label and ELEV_RE.search(label) and not NOT_EXTERIOR_RE.search(label))


def _level_y(line, segments, which: str) -> float:
    """The y of the level line a mark is written on: the nearest horizontal line just below (or through) the text,
    else the text's own middle."""
    best = None
    for (x0, y0), (x1, y1) in segments:
        if abs(y1 - y0) > 0.01 or abs(x1 - x0) < 0.3:
            continue
        y = (y0 + y1) / 2
        lo, hi = min(x0, x1), max(x0, x1)
        if not (lo - 1.0 <= line.x0 <= hi + 1.0 or lo - 1.0 <= line.x1 <= hi + 1.0):
            continue
        d = abs(y - line.bottom) if y >= line.top - 0.05 else 99
        if d <= 0.25 and (best is None or d < best[0]):
            best = (d, y)
    return best[1] if best else (line.top + line.bottom) / 2


def find(page, vp: dict, segments, ratio: float | None) -> tuple[list[dict], list[str]]:
    """(objects, notes) for one elevation view. ratio: real inches per paper inch."""
    label = (vp.get("label") or vp.get("key") or "elevation").strip()
    if not ratio:
        return [], [f"{label}: no scale, so its wall area can't be measured; set the scale"]
    if len(segments) > MAX_SEGMENTS:
        return [], [f"{label}: too much line work ({len(segments)} lines) to find the wall outline"]
    try:
        from shapely.geometry import LineString, Polygon, box as sbox
        from shapely.ops import polygonize, unary_union
    except ImportError:
        return [], [f"{label}: elevations need the 'shapely' package"]
    k2 = ratio * ratio / 144.0                       # paper sq in -> real sq ft
    kf = ratio / 12.0                                # paper in -> real ft
    vb = vp["bbox"]
    view_area = (vb[2] - vb[0]) * (vb[3] - vb[1])
    merged = unary_union([LineString(s) for s in segments])
    polys = [p for p in polygonize(merged) if p.area * k2 >= 1.0 and p.area <= 0.9 * view_area]
    if not polys:
        return [], [f"{label}: no closed wall outline found"]
    eps = 0.004
    joined = unary_union([p.buffer(eps) for p in polys]).buffer(-eps)
    parts = list(getattr(joined, "geoms", [joined]))
    outline = max(parts, key=lambda g: g.area)
    outline = Polygon(outline.exterior)
    if outline.area * k2 <= MAX_OPENING_SQFT:
        # No bigger than a door or window: the building's outline wasn't closed in this view (the drawing may run past
        # the view's edge, or into the title block). Better no wall than a door counted as one.
        return [], [f"{label}: no wall outline found (the largest closed shape is {outline.area * k2:.0f} sq ft); "
                    "check the view's edges"]
    minx, miny, maxx, maxy = outline.bounds

    # Level marks: the plate line (top of wall) and the floor line, written beside the elevation.
    plates, bases = [], []
    for ln in page.lines:
        cx, cy = (ln.x0 + ln.x1) / 2, (ln.top + ln.bottom) / 2
        if not (vb[0] <= cx <= vb[2] and vb[1] <= cy <= vb[3]):
            continue
        if PLATE_RE.search(ln.text):
            plates.append(_level_y(ln, segments, "plate"))
        elif BASE_RE.search(ln.text):
            bases.append(_level_y(ln, segments, "base"))
    plates = [y for y in plates if miny - 0.5 <= y <= maxy + 0.5]
    bases = [y for y in bases if miny - 0.5 <= y <= maxy + 0.5]
    top = min(plates) if plates else miny                         # the highest plate (page y grows downward)
    bottom = max(bases) if bases else maxy
    notes, conf = [], 0.7
    if not plates:
        notes.append(f"{label}: no plate line marked, so the wall area may include the roof or gable - check it")
        conf = 0.4
    if top >= bottom:
        return [], [f"{label}: the plate line isn't above the floor line"]
    levels: list[float] = []                                      # one plate line per story
    for y in sorted(plates):
        if not levels or y - levels[-1] > 0.2:
            levels.append(y)
    stories = max(1, len(levels))
    wall = outline.intersection(sbox(minx - 1, top, maxx + 1, bottom))
    wall_parts = [g for g in getattr(wall, "geoms", [wall]) if getattr(g, "exterior", None) is not None and g.area * k2 >= 1]
    if not wall_parts:
        return [], notes + [f"{label}: nothing of the outline is between the floor and plate lines"]
    wall_union = unary_union(wall_parts)
    width = maxx - minx

    # Openings: opening-sized rectangles in the wall band (a window's frame and its glass are one opening).
    cands = []
    for p in polys:
        shell = Polygon(p.exterior)
        x0, y0, x1, y1 = shell.bounds
        w_ft, h_ft = (x1 - x0) * kf, (y1 - y0) * kf
        if shell.area / max(shell.envelope.area, 1e-9) < RECT or w_ft < MIN_OPENING_FT or h_ft < MIN_OPENING_FT:
            continue
        if (x1 - x0) > MAX_OPENING_SHARE * width or shell.area * k2 > MAX_OPENING_SQFT:
            continue
        if not wall_union.buffer(eps * 2).contains(shell):
            continue
        cands.append(shell.envelope)
    openings = []
    if cands:
        grouped = unary_union([c.buffer(eps) for c in cands]).buffer(-eps)
        for g in getattr(grouped, "geoms", [grouped]):
            env = g.envelope
            x0, y0, x1, y1 = env.bounds
            w_ft, h_ft = (x1 - x0) * kf, (y1 - y0) * kf
            if env.area * k2 > MAX_OPENING_SQFT or min(w_ft, h_ft) < MIN_OPENING_FT:
                continue
            at_floor = abs(y1 - bottom) * kf <= 0.75
            kind = ("garage door" if w_ft >= 7 else "door") if at_floor and h_ft >= 6 else "window"
            openings.append({"kind": kind, "bounds": (x0, y0, x1, y1)})
    objects = []
    for g in getattr(wall_union, "geoms", [wall_union]):
        pts = [[round(x, 4), round(y, 4)] for x, y in list(g.simplify(0.005, preserve_topology=True).exterior.coords)[:-1]]
        if len(pts) >= 3:
            # The story count rides in the label (never in tag: tags are linked to schedule marks).
            objects.append({"viewport": vp["key"], "kind": "polygon", "layer": "ELEVATION-WALL",
                            "label": f"{label} wall · {stories} stor{'y' if stories == 1 else 'ies'}",
                            "geometry": {"type": "polygon", "points": pts}, "source": "vector", "confidence": conf})
    for o in openings:
        x0, y0, x1, y1 = (round(v, 4) for v in o["bounds"])
        objects.append({"viewport": vp["key"], "kind": "opening", "label": o["kind"], "layer": "ELEVATION-OPENING",
                        "geometry": {"type": "polygon", "points": [[x0, y0], [x1, y0], [x1, y1], [x0, y1]]},
                        "source": "vector", "confidence": 0.6})
    return objects, notes
