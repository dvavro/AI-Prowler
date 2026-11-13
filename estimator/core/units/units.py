"""Units of measure used by takeoffs and line items.

Every quantity carries an explicit unit (design spec: "units are always
explicit fields"). Conversions only happen between units of the same
dimension; anything else raises UnitError.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal


class UnitError(ValueError):
    pass


@dataclass(frozen=True)
class Unit:
    code: str            # canonical code stored in the database
    name: str
    dimension: str       # length, area, volume, count, time, liquid, weight, lump
    to_base: Decimal     # multiply to convert into the dimension's base unit


# Base units: length=ft, area=sqft, volume=cuft, count=ea, time=hr, liquid=gal, weight=lb, lump=ls
_U = Decimal
UNITS: dict[str, Unit] = {u.code: u for u in (
    Unit("in", "inch", "length", _U(1) / _U(12)),
    Unit("ft", "foot", "length", _U(1)),
    Unit("lf", "linear foot", "length", _U(1)),
    Unit("yd", "yard", "length", _U(3)),
    Unit("m", "meter", "length", _U("3.280839895013123359580052493")),
    Unit("sqin", "square inch", "area", _U(1) / _U(144)),
    Unit("sqft", "square foot", "area", _U(1)),
    Unit("sqyd", "square yard", "area", _U(9)),
    Unit("sq", "roofing square (100 sq ft)", "area", _U(100)),
    Unit("sqm", "square meter", "area", _U("10.76391041670972230833350556")),
    Unit("acre", "acre", "area", _U(43560)),
    Unit("cuft", "cubic foot", "volume", _U(1)),
    Unit("cuyd", "cubic yard", "volume", _U(27)),
    Unit("bdft", "board foot", "volume", _U(1) / _U(12)),
    Unit("ea", "each", "count", _U(1)),
    Unit("hr", "hour", "time", _U(1)),
    Unit("day", "day (8 hours)", "time", _U(8)),
    Unit("gal", "gallon", "liquid", _U(1)),
    Unit("lb", "pound", "weight", _U(1)),
    Unit("ton", "short ton", "weight", _U(2000)),
    Unit("ls", "lump sum", "lump", _U(1)),
)}

_ALIASES = {
    "sf": "sqft", "sq ft": "sqft", "ft2": "sqft", "sq. ft.": "sqft",
    "sy": "sqyd", "sq yd": "sqyd",
    "cy": "cuyd", "cu yd": "cuyd", "yd3": "cuyd",
    "cf": "cuft", "cu ft": "cuft",
    "squares": "sq", "square": "sq",
    "acres": "acre", "ac": "acre",
    "each": "ea", "pcs": "ea", "pc": "ea", "count": "ea",
    "linear ft": "lf", "lin ft": "lf", "feet": "ft", "foot": "ft", "inch": "in", "inches": "in",
    "hours": "hr", "hrs": "hr", "hour": "hr",
    "gallon": "gal", "gallons": "gal",
    "lbs": "lb", "pound": "lb", "pounds": "lb", "tons": "ton",
    "lump sum": "ls", "lump": "ls",
    "bf": "bdft", "board ft": "bdft",
}


def normalize_unit(code: str) -> str:
    """Return the canonical unit code for a code or common alias (case-insensitive)."""
    if not isinstance(code, str):
        raise UnitError(f"unit must be a string, got {type(code).__name__}")
    key = code.strip().lower()
    key = _ALIASES.get(key, key)
    if key not in UNITS:
        raise UnitError(f"unknown unit: {code!r}")
    return key


def get_unit(code: str) -> Unit:
    return UNITS[normalize_unit(code)]


def convert(value: Decimal | int | str, from_unit: str, to_unit: str) -> Decimal:
    """Convert a quantity between units of the same dimension."""
    if isinstance(value, float):
        raise TypeError("use Decimal, int or str for quantities, not float")
    src, dst = get_unit(from_unit), get_unit(to_unit)
    if src.dimension != dst.dimension:
        raise UnitError(f"cannot convert {src.code} ({src.dimension}) to {dst.code} ({dst.dimension})")
    return Decimal(value) * src.to_base / dst.to_base
