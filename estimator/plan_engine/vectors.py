"""Walls and rooms from line work - shared by PDF plans (paper inches) and DXF drawings (real units).

Walls: two parallel lines a wall's thickness apart that run alongside each other for a while. Each pair becomes one
wall with a centerline, so its length can be measured. With a known scale the thickness is checked in real inches
(3" to 16"); without one, on the paper (1/32" to 1/4").

Rooms: the line work is joined where lines cross (shapely), turned into closed areas, and each room name written on
the drawing ("KITCHEN", "BEDROOM 2") picks the smallest area around it that is room-sized. Slivers between the two
lines of a wall never hold a name, so they're never rooms.

Nothing here guesses: a room needs a name inside it, and a wall needs both of its lines.
"""
from __future__ import annotations

import bisect
import math
import re
from dataclasses import dataclass

Segment = tuple[tuple[float, float], tuple[float, float]]

MIN_SEGMENT = 0.02                 # drawing units; shorter strokes are hatching and text noise
MAX_SEGMENTS_FOR_ROOMS = 25000     # bigger drawings skip room finding (and say so) rather than run for minutes
WALL_MIN_IN, WALL_MAX_IN = 3.0, 16.0        # real wall thickness, inches
WALL_MIN_LEN_IN = 24.0                      # a wall is at least 2 ft long
PAPER_MIN_T, PAPER_MAX_T, PAPER_MIN_LEN = 1 / 32, 0.25, 0.25    # unscaled paper: thickness and length, inches
ANGLE_TOL_DEG = 1.5
ROOM_MIN_SQFT = 12.0
ROOM_WORDS_STOP = {"SCALE", "PLAN", "PLANS", "NORTH", "UP", "DN", "DOWN", "TYP", "TYPICAL", "SIM", "SIMILAR",
                   "ELEVATION", "ELEVATIONS", "SECTION", "SECTIONS", "DETAIL", "DETAILS", "NOTE", "NOTES", "SEE",
                   "NTS", "MATCH", "LINE", "REF", "EQ", "CLR", "MIN", "MAX", "DIA", "NEW", "EXISTING", "EXIST",
                   "DEMO", "VERIFY", "FIELD", "ABOVE", "BELOW", "OPEN", "ALIGN", "CL"}
ROOM_RE = re.compile(r"^[A-Z][A-Z0-9 .&/'#-]{2,40}$")


@dataclass
class Wall:
    a: tuple[float, float]
    b: tuple[float, float]
    thickness: float                 # drawing units
    thickness_in: float | None       # real inches when the scale is known


def clean_segments(segments: list[Segment]) -> list[Segment]:
    out = []
    for p, q in segments:
        if math.hypot(q[0] - p[0], q[1] - p[1]) >= MIN_SEGMENT:
            out.append(((float(p[0]), float(p[1])), (float(q[0]), float(q[1]))))
    return out


def inside(seg: Segment, box: list[float] | None, pad: float = 0.0) -> bool:
    if box is None:
        return True
    (x0, y0), (x1, y1) = seg
    lo_x, lo_y, hi_x, hi_y = box[0] - pad, box[1] - pad, box[2] + pad, box[3] + pad
    return lo_x <= x0 <= hi_x and lo_x <= x1 <= hi_x and lo_y <= y0 <= hi_y and lo_y <= y1 <= hi_y


# ---------------------------------------------------------------- walls

def _thresholds(real_in_per_unit: float | None) -> tuple[float, float, float]:
    """(min thickness, max thickness, min length) in drawing units."""
    if real_in_per_unit:
        k = real_in_per_unit
        return WALL_MIN_IN / k, WALL_MAX_IN / k, WALL_MIN_LEN_IN / k
    return PAPER_MIN_T, PAPER_MAX_T, PAPER_MIN_LEN


def find_walls(segments: list[Segment], real_in_per_unit: float | None, limit: int = 5000) -> list[Wall]:
    """Pairs of parallel lines a wall's thickness apart. real_in_per_unit: real inches per drawing unit (the viewport's
    scale ratio for paper inches, 12 for feet, 1 for inches...), or None when unknown."""
    t_min, t_max, len_min = _thresholds(real_in_per_unit)
    groups: dict[int, list] = {}
    for p, q in segments:
        dx, dy = q[0] - p[0], q[1] - p[1]
        length = math.hypot(dx, dy)
        if length < len_min:
            continue
        ang = math.degrees(math.atan2(dy, dx)) % 180.0
        key = int(round(ang / ANGLE_TOL_DEG)) % int(round(180 / ANGLE_TOL_DEG))
        groups.setdefault(key, []).append((p, q, ang))
    walls: list[Wall] = []
    for key, segs in sorted(groups.items()):
        ang = math.radians(key * ANGLE_TOL_DEG)
        ux, uy = math.cos(ang), math.sin(ang)
        nx, ny = -uy, ux
        rows = []
        for p, q, _ in segs:
            off = (p[0] * nx + p[1] * ny + q[0] * nx + q[1] * ny) / 2
            s0, s1 = sorted((p[0] * ux + p[1] * uy, q[0] * ux + q[1] * uy))
            rows.append((off, s0, s1, p, q))
        rows.sort(key=lambda r: r[0])
        offsets = [r[0] for r in rows]
        cand: dict[tuple[int, int], tuple[float, float, float]] = {}
        closest: dict[int, tuple[float, tuple[int, int]]] = {}
        for i, (off_i, a0, a1, _, _) in enumerate(rows):
            # Jump straight to the first line a wall's thickness away: a dashed line is hundreds of pieces at the
            # same offset, and walking through them for every piece would take minutes on a real sheet.
            start = max(i + 1, bisect.bisect_left(offsets, off_i + t_min))
            for j in range(start, len(rows)):
                off_j, b0, b1, _, _ = rows[j]
                d = off_j - off_i
                if d > t_max:
                    break                              # sorted by offset: nothing further is close enough
                o0, o1 = max(a0, b0), min(a1, b1)
                if o1 - o0 < len_min:
                    continue
                cand[(i, j)] = (d, o0, o1)
                for k in (i, j):
                    if k not in closest or d < closest[k][0]:
                        closest[k] = (d, (i, j))
        # A pair is a wall when it is the closest partner for at least one of its two lines, so a long line with
        # doors on the other side still pairs with each piece.
        for i, j in sorted({pair for _, pair in closest.values()}):
            d, o0, o1 = cand[(i, j)]
            mid = (rows[i][0] + rows[j][0]) / 2
            a = (o0 * ux + mid * nx, o0 * uy + mid * ny)
            b = (o1 * ux + mid * nx, o1 * uy + mid * ny)
            walls.append(Wall(a=(round(a[0], 4), round(a[1], 4)), b=(round(b[0], 4), round(b[1], 4)), thickness=d,
                              thickness_in=round(d * real_in_per_unit, 1) if real_in_per_unit else None))
            if len(walls) >= limit:
                return walls
    return walls


# ---------------------------------------------------------------- rooms

def is_room_name(text: str) -> bool:
    raw = re.sub(r"\s+", " ", (text or "").strip())
    if raw != raw.upper() and not raw.istitle():      # "KITCHEN" or "Kitchen", never a sentence of notes
        return False
    t = raw.upper()
    if not ROOM_RE.match(t) or len(re.findall(r"[A-Z]", t)) < 3:
        return False
    words = re.findall(r"[A-Z]+", t)
    if not words or all(w in ROOM_WORDS_STOP for w in words) or any(w in ("SCALE", "PLAN", "PLANS") for w in words):
        return False
    return not re.fullmatch(r"[A-Z]{1,3}-?\d+(\.\d+)?[A-Z]?", t)       # sheet numbers and tags aren't room names


def find_rooms(segments: list[Segment], labels: list[tuple[str, tuple[float, float]]],
               min_area: float, max_area: float, simplify: float) -> tuple[list[dict], str | None]:
    """[{"label", "points"}], note. labels: (room name, (x, y)) where the name is written; areas in drawing units²."""
    if not labels or len(segments) < 3:
        return [], None
    if len(segments) > MAX_SEGMENTS_FOR_ROOMS:
        return [], f"too much line work ({len(segments)} lines) to find rooms automatically on this view"
    try:
        from shapely.geometry import LineString, Point
        from shapely.ops import polygonize, unary_union
    except ImportError:
        return [], "rooms need the 'shapely' package (pip install shapely)"
    merged = unary_union([LineString(s) for s in segments])
    polys = [p for p in polygonize(merged) if min_area <= p.area <= max_area]
    rooms, taken = [], set()
    for name, (x, y) in labels:
        pt = Point(x, y)
        around = [(p.area, i) for i, p in enumerate(polys) if p.contains(pt)]
        if not around:
            continue
        area, i = min(around)
        if i in taken:                                # two names in one area (e.g. "BEDROOM" and "2"): keep the first
            continue
        taken.add(i)
        shape = polys[i].simplify(simplify, preserve_topology=True)
        coords = [(round(cx, 4), round(cy, 4)) for cx, cy in list(shape.exterior.coords)[:-1]]
        if len(coords) >= 3:
            rooms.append({"label": re.sub(r"\s+", " ", name.strip())[:100], "points": coords})
    return rooms, None


def wall_objects(walls: list[Wall], viewport: str | None, source: str, layer: str | None = None) -> list[dict]:
    out = []
    for w in walls:
        label = f'{w.thickness_in:g}" wall' if w.thickness_in else "wall"
        out.append({"viewport": viewport, "kind": "wall", "label": label, "layer": layer,
                    "geometry": {"type": "line", "points": [list(w.a), list(w.b)]}, "source": source,
                    "confidence": 0.7})
    return out


def room_objects(rooms: list[dict], viewport: str | None, source: str) -> list[dict]:
    return [{"viewport": viewport, "kind": "room", "label": r["label"],
             "geometry": {"type": "polygon", "points": [list(p) for p in r["points"]]}, "source": source,
             "confidence": 0.75} for r in rooms]
