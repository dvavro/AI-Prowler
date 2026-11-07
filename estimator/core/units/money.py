"""Money in integer cents.

Rules (design spec, MCP tool conventions):
- Money is stored and passed as integer cents. Floats are rejected.
- Rounding to cents is ROUND_HALF_UP (what customers expect on a bid).
- Bid-level rounding (to the nearest $1, $5, $10, $100…) is a separate,
  explicit step: round_cents_to().
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP, Decimal, InvalidOperation

_ROUNDING = {"half_up": ROUND_HALF_UP, "up": ROUND_CEILING, "down": ROUND_FLOOR}


def cents_from_decimal(value: Decimal | int | str) -> int:
    """Convert a dollar amount (Decimal, int or numeric string) to integer cents, half-up."""
    if isinstance(value, float):
        raise TypeError("float is not allowed for money; use Decimal, int or str")
    if isinstance(value, bool):
        raise TypeError("bool is not a money amount")
    try:
        d = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"not a money amount: {value!r}") from exc
    if not d.is_finite():
        raise ValueError(f"not a finite money amount: {value!r}")
    return int((d * 100).quantize(Decimal(1), rounding=ROUND_HALF_UP))


def parse_money(text: str) -> int:
    """Parse '$1,234.56', '1234.5' or '-12' into cents."""
    if not isinstance(text, str):
        raise TypeError("parse_money expects a string")
    cleaned = text.strip().replace("$", "").replace(",", "")
    neg = cleaned.startswith("(") and cleaned.endswith(")")
    if neg:
        cleaned = cleaned[1:-1]
    cents = cents_from_decimal(cleaned)
    return -cents if neg else cents


def format_cents(cents: int, symbol: str = "$") -> str:
    """Format cents as '$1,234.56' (negative as '-$1,234.56')."""
    _require_int(cents)
    sign = "-" if cents < 0 else ""
    whole, frac = divmod(abs(cents), 100)
    return f"{sign}{symbol}{whole:,}.{frac:02d}"


def round_cents_to(cents: int, increment_cents: int, mode: str = "half_up") -> int:
    """Round an amount in cents to a multiple of increment_cents (e.g. 100 = nearest dollar)."""
    _require_int(cents)
    _require_int(increment_cents)
    if increment_cents <= 0:
        raise ValueError("increment must be positive")
    if mode not in _ROUNDING:
        raise ValueError(f"unknown rounding mode: {mode!r}")
    q = (Decimal(cents) / Decimal(increment_cents)).quantize(Decimal(1), rounding=_ROUNDING[mode])
    return int(q) * increment_cents


def _require_int(value) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"money must be integer cents, got {type(value).__name__}")


@dataclass(frozen=True, order=True)
class Money:
    """Immutable integer-cents amount with safe arithmetic."""

    cents: int

    def __post_init__(self):
        _require_int(self.cents)

    @classmethod
    def from_dollars(cls, value: Decimal | int | str) -> "Money":
        return cls(cents_from_decimal(value))

    def __add__(self, other: "Money") -> "Money":
        if not isinstance(other, Money):
            return NotImplemented
        return Money(self.cents + other.cents)

    def __sub__(self, other: "Money") -> "Money":
        if not isinstance(other, Money):
            return NotImplemented
        return Money(self.cents - other.cents)

    def __neg__(self) -> "Money":
        return Money(-self.cents)

    def times(self, factor: Decimal | int | str) -> "Money":
        """Multiply by a quantity or percentage factor, rounding half-up to the cent."""
        if isinstance(factor, float):
            raise TypeError("use Decimal, int or str for factors, not float")
        d = Decimal(self.cents) * Decimal(factor)
        return Money(int(d.quantize(Decimal(1), rounding=ROUND_HALF_UP)))

    def __str__(self) -> str:
        return format_cents(self.cents)
