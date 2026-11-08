"""Measuring the drawing model: scale notes, typed distances, lengths and areas.

Everything is exact Decimal math (no floats), and results are in feet, square feet and counts.

Units on a sheet:
- "paper_in": the geometry is in inches on the paper (PDFs, scans, photos). A viewport's scale turns it into real
  size: scale_ratio is real length per paper length, so 1/4" = 1'-0" is 48 and 1" = 20' is 240.
- "ft", "in", "m", "cm", "mm": the geometry is already real size (CAD drawings); no scale is needed.

A viewport marked NTS ("not to scale") is never measured, and paper geometry with no known scale isn't either:
those objects keep real_units = None so nothing guesses a size.
"""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

from estimator.errors import InvalidInput

GEOMETRY_TYPES = ("point", "line", "polyline", "polygon")
MIN_POINTS = {"point": 1, "line": 2, "polyline": 2, "polygon": 3}
MAX_POINTS = 20000
REAL_UNITS = {"ft": Decimal(1), "in": Decimal(1) / 12, "m": Decimal("3.280839895013123"),
              "cm": Decimal("0.03280839895013123"), "mm": Decimal("0.003280839895013123")}
SHEET_UNITS = ("paper_in",) + tuple(REAL_UNITS)
TWO = Decimal("0.01")
NTS_RE = re.compile(r"^\s*(?:n\.?\s*t\.?\s*s\.?|not\s+to\s+scale)\s*$", re.I)


def dec(value, field: str = "value") -> Decimal:
    try:
        d = Decimal(str(value).strip())
    except (InvalidOperation, ValueError):
        raise InvalidInput(f"{field} must be a number", field=field) from None
    if not d.is_finite():
        raise InvalidInput(f"{field} must be a number", field=field)
    return d


def q(d: Decimal) -> str:
    return str(d.quantize(TWO))


# ---------------------------------------------------------------- scale notes and typed distances

_FRACTION = r"(\d+(?:\.\d+)?(?:[\s-]+\d+/\d+)?|\d+/\d+)"


def _number(text: str) -> Decimal:
    """'1/4', '1-1/2', '1 1/2', '3', '0.25' -> Decimal."""
    text = text.strip()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)[\s-]+(\d+)/(\d+)", text)
    if m:
        return Decimal(m.group(1)) + Decimal(m.group(2)) / Decimal(m.group(3))
    m = re.fullmatch(r"(\d+)/(\d+)", text)
    if m:
        if Decimal(m.group(2)) == 0:
            raise InvalidInput("a fraction can't divide by zero")
        return Decimal(m.group(1)) / Decimal(m.group(2))
    return dec(text)


def parse_scale(note: str) -> tuple[Decimal | None, bool]:
    """A scale note from a drawing -> (scale_ratio, is_nts).

    1/4" = 1'-0" -> 48;  3/16" = 1'-0" -> 64;  1" = 20' -> 240;  1:100 -> 100;  NTS -> (None, True).
    """
    if note is None or not str(note).strip():
        raise InvalidInput("the scale note is empty")
    text = str(note).strip()
    text = re.sub(r"^\s*scale\s*[:=]?\s*", "", text, flags=re.I).strip()
    if NTS_RE.match(text):
        return None, True
    if re.fullmatch(r"full(\s+size)?", text, re.I):
        return Decimal(1), False
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*:\s*(\d+(?:\.\d+)?)", text)
    if m:
        a, b = Decimal(m.group(1)), Decimal(m.group(2))
        if a <= 0 or b <= 0:
            raise InvalidInput(f"'{note}' isn't a scale I can use")
        return b / a, False
    if "=" in text:
        left, right = (s.strip() for s in text.split("=", 1))
        paper_in = parse_length(left, default_unit="in") * 12
        real_in = parse_length(right, default_unit="ft") * 12
        if paper_in <= 0 or real_in <= 0:
            raise InvalidInput(f"'{note}' isn't a scale I can use")
        return real_in / paper_in, False
    raise InvalidInput(f"I can't read the scale note '{note}'. Try 1/4\" = 1'-0\", 1\" = 20', 1:100 or NTS")


def parse_length(text, default_unit: str = "ft") -> Decimal:
    """A typed distance -> feet. 12'-6", 12' 6", 12.5 ft, 150 in, 6", 3.5 m, 350 cm. A bare number uses default_unit."""
    if isinstance(text, (int, float, Decimal)):
        text = str(text)
    s = str(text or "").strip().lower().replace("’", "'").replace("”", '"').replace("″", '"').replace("′", "'")
    if not s:
        raise InvalidInput("the distance is empty")
    m = re.fullmatch(_FRACTION + r"\s*(?:'|ft|feet|foot)\s*-?\s*(?:" + _FRACTION + r"\s*(?:\"|in|inch|inches)?)?", s)
    if m:
        feet = _number(m.group(1))
        inches = _number(m.group(2)) if m.group(2) else Decimal(0)
        return feet + inches / 12
    m = re.fullmatch(_FRACTION + r"\s*(\"|in|inch|inches|m|meters?|metres?|cm|mm)", s)
    if m:
        value, unit = _number(m.group(1)), m.group(2)
        if unit in ('"', "in", "inch", "inches"):
            return value / 12
        unit = {"meter": "m", "meters": "m", "metre": "m", "metres": "m"}.get(unit, unit)
        return value * REAL_UNITS[unit]
    m = re.fullmatch(_FRACTION, s)
    if m:
        value = _number(m.group(1))
        return value if default_unit == "ft" else value * REAL_UNITS[default_unit]
    raise InvalidInput(f"I can't read the distance '{text}'. Try 12'-6\", 12.5 ft, 150 in or 3.5 m")


# ---------------------------------------------------------------- geometry

def check_geometry(geometry) -> dict:
    """Validate {"type": point|line|polyline|polygon, "points": [[x, y], ...]} and return it with Decimal-safe numbers."""
    if not isinstance(geometry, dict):
        raise InvalidInput("geometry must be an object like {\"type\": \"polygon\", \"points\": [[x, y], ...]}")
    gtype = geometry.get("type")
    if gtype not in GEOMETRY_TYPES:
        raise InvalidInput(f"geometry type must be one of {', '.join(GEOMETRY_TYPES)}", field="geometry.type")
    points = geometry.get("points")
    if not isinstance(points, list) or len(points) < MIN_POINTS[gtype]:
        raise InvalidInput(f"a {gtype} needs at least {MIN_POINTS[gtype]} point(s)", field="geometry.points")
    if len(points) > MAX_POINTS:
        raise InvalidInput(f"a shape can have at most {MAX_POINTS} points", field="geometry.points")
    clean = []
    for p in points:
        if not isinstance(p, (list, tuple)) or len(p) != 2:
            raise InvalidInput("each point must be [x, y]", field="geometry.points")
        clean.append([dec(p[0], "x"), dec(p[1], "y")])
    return {"type": gtype, "points": clean}


def to_json_geometry(geometry: dict) -> dict:
    """Decimal points -> plain numbers for storage (ints stay ints)."""
    def num(d: Decimal):
        return int(d) if d == d.to_integral_value() else float(d)
    return {"type": geometry["type"], "points": [[num(x), num(y)] for x, y in geometry["points"]]}


def _dist(a, b) -> Decimal:
    return ((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2).sqrt()


def path_length(points) -> Decimal:
    return sum((_dist(points[i], points[i + 1]) for i in range(len(points) - 1)), Decimal(0))


def polygon_area(points) -> Decimal:
    """Shoelace formula; works whichever way the points go round."""
    n = len(points)
    twice = sum(points[i][0] * points[(i + 1) % n][1] - points[(i + 1) % n][0] * points[i][1] for i in range(n))
    return abs(twice) / 2


def polygon_perimeter(points) -> Decimal:
    closed = points if points[0] == points[-1] else points + [points[0]]
    return path_length(closed)


def feet_per_unit(sheet_units: str, scale_ratio: Decimal | None, is_nts: bool) -> Decimal | None:
    """How many real feet one drawing unit is, or None when it can't be measured (NTS or no scale)."""
    if sheet_units in REAL_UNITS:
        return REAL_UNITS[sheet_units]
    if sheet_units != "paper_in":
        raise InvalidInput(f"sheet units must be one of {', '.join(SHEET_UNITS)}", field="units")
    if is_nts or scale_ratio is None or scale_ratio <= 0:
        return None
    return scale_ratio / 12


def measure(geometry: dict, factor: Decimal | None) -> dict | None:
    """Real size of a shape: length_ft for lines and paths; area_sqft and perimeter_ft for closed shapes."""
    if factor is None:
        return None
    pts = geometry["points"]
    gtype = geometry["type"]
    if gtype in ("line", "polyline"):
        return {"length_ft": q(path_length(pts) * factor)}
    if gtype == "polygon":
        return {"area_sqft": q(polygon_area(pts) * factor * factor), "perimeter_ft": q(polygon_perimeter(pts) * factor)}
    return {}


def calibrate(p1, p2, real_distance) -> Decimal:
    """Two-point calibration: two points on the paper (inches) and the real distance between them -> scale_ratio."""
    a = [dec(p1[0], "p1.x"), dec(p1[1], "p1.y")] if isinstance(p1, (list, tuple)) and len(p1) == 2 else None
    b = [dec(p2[0], "p2.x"), dec(p2[1], "p2.y")] if isinstance(p2, (list, tuple)) and len(p2) == 2 else None
    if a is None or b is None:
        raise InvalidInput("calibration needs two points, each [x, y]")
    paper = _dist(a, b)
    if paper == 0:
        raise InvalidInput("the two calibration points are the same point")
    real_ft = parse_length(real_distance)
    if real_ft <= 0:
        raise InvalidInput("the real distance must be more than zero")
    return (real_ft * 12 / paper).quantize(Decimal("0.0001"))
