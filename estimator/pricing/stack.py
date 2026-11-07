"""The pricing stack.

Order per line item (design spec, Trade module framework → Pricing stack):
  1. base      = unit cost × quantity
  2. waste     = base × waste %
  3. burden    = (base + waste) × labor burden %       (labor lines only)
  4. cost      = base + waste + burden
  5. overhead  = cost × overhead %
  6. profit    = (cost + overhead) × profit %
  7. tax       = taxable base × tax %                   (only kinds listed as taxable, e.g. materials)
  8. total     = cost + overhead + profit + tax
Then at estimate level: optional rounding to an increment and a minimum job charge.

Every step is kept, so a bid can show or hide any layer and every number is
traceable. All money is integer cents; each step rounds half-up to the cent.
Percentages are Decimal fractions (0.10 = 10%).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal

from estimator.core.units.money import round_cents_to
from estimator.core.units.units import normalize_unit

LINE_KINDS = ("material", "labor", "equipment", "sub", "other")
TAX_BASES = ("cost", "price")


class PricingError(ValueError):
    pass


def _pct(value, name: str, upper: Decimal = Decimal(1)) -> Decimal:
    if isinstance(value, float):
        raise PricingError(f"{name}: use Decimal or str, not float")
    d = Decimal(value)
    if d < 0 or d > upper:
        raise PricingError(f"{name} must be between 0 and {upper} (as a fraction, 0.10 = 10%)")
    return d


def _cents(d: Decimal) -> int:
    return int(d.quantize(Decimal(1), rounding=ROUND_HALF_UP))


@dataclass(frozen=True)
class Markups:
    overhead_pct: Decimal = Decimal(0)
    profit_pct: Decimal = Decimal(0)
    labor_burden_pct: Decimal = Decimal(0)
    tax_pct: Decimal = Decimal(0)
    taxable_kinds: tuple[str, ...] = ("material",)
    tax_base: str = "cost"            # "cost": tax on cost (incl. waste); "price": tax on marked-up price

    def __post_init__(self):
        object.__setattr__(self, "overhead_pct", _pct(self.overhead_pct, "overhead_pct"))
        object.__setattr__(self, "profit_pct", _pct(self.profit_pct, "profit_pct", Decimal(5)))
        object.__setattr__(self, "labor_burden_pct", _pct(self.labor_burden_pct, "labor_burden_pct", Decimal(2)))
        object.__setattr__(self, "tax_pct", _pct(self.tax_pct, "tax_pct", Decimal("0.5")))
        bad = [k for k in self.taxable_kinds if k not in LINE_KINDS]
        if bad:
            raise PricingError(f"unknown taxable kinds: {bad}")
        if self.tax_base not in TAX_BASES:
            raise PricingError(f"tax_base must be one of {TAX_BASES}")


@dataclass(frozen=True)
class LineInput:
    kind: str
    quantity: Decimal
    unit: str
    unit_cost_cents: int
    waste_pct: Decimal = Decimal(0)
    description: str = ""
    ref: str = ""                     # caller's id (line item id, price key) for traceability

    def __post_init__(self):
        if self.kind not in LINE_KINDS:
            raise PricingError(f"kind must be one of {LINE_KINDS}")
        if isinstance(self.quantity, float):
            raise PricingError("quantity: use Decimal or str, not float")
        q = Decimal(self.quantity)
        if q < 0:
            raise PricingError("quantity cannot be negative")
        object.__setattr__(self, "quantity", q)
        object.__setattr__(self, "unit", normalize_unit(self.unit))
        if isinstance(self.unit_cost_cents, bool) or not isinstance(self.unit_cost_cents, int):
            raise PricingError("unit_cost_cents must be integer cents")
        if self.unit_cost_cents < 0:
            raise PricingError("unit cost cannot be negative")
        object.__setattr__(self, "waste_pct", _pct(self.waste_pct, "waste_pct"))


@dataclass(frozen=True)
class LinePrice:
    ref: str
    kind: str
    base_cents: int
    waste_cents: int
    burden_cents: int
    cost_cents: int
    overhead_cents: int
    profit_cents: int
    tax_cents: int
    total_cents: int

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def price_line(item: LineInput, m: Markups) -> LinePrice:
    base = _cents(item.quantity * item.unit_cost_cents)
    waste = _cents(base * item.waste_pct)
    burden = _cents((base + waste) * m.labor_burden_pct) if item.kind == "labor" else 0
    cost = base + waste + burden
    overhead = _cents(cost * m.overhead_pct)
    profit = _cents((cost + overhead) * m.profit_pct)
    if item.kind in m.taxable_kinds and m.tax_pct:
        taxable = cost if m.tax_base == "cost" else cost + overhead + profit
        tax = _cents(taxable * m.tax_pct)
    else:
        tax = 0
    return LinePrice(
        ref=item.ref, kind=item.kind, base_cents=base, waste_cents=waste, burden_cents=burden,
        cost_cents=cost, overhead_cents=overhead, profit_cents=profit, tax_cents=tax,
        total_cents=cost + overhead + profit + tax,
    )


@dataclass(frozen=True)
class EstimateTotals:
    lines: tuple[LinePrice, ...]
    cost_by_kind: dict = field(default_factory=dict)
    cost_cents: int = 0
    overhead_cents: int = 0
    profit_cents: int = 0
    tax_cents: int = 0
    subtotal_cents: int = 0           # sum of line totals
    rounding_adjustment_cents: int = 0
    minimum_charge_adjustment_cents: int = 0
    total_cents: int = 0
    margin_pct: Decimal = Decimal(0)  # (price before tax - cost) / price before tax

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["lines"] = [ln.as_dict() for ln in self.lines]
        d["margin_pct"] = str(self.margin_pct)
        return d


def price_estimate(
    items: list[LineInput],
    markups: Markups,
    round_to_cents: int | None = None,
    rounding_mode: str = "half_up",
    minimum_charge_cents: int | None = None,
) -> EstimateTotals:
    lines = tuple(price_line(i, markups) for i in items)
    by_kind: dict[str, int] = {}
    for ln in lines:
        by_kind[ln.kind] = by_kind.get(ln.kind, 0) + ln.cost_cents
    cost = sum(ln.cost_cents for ln in lines)
    overhead = sum(ln.overhead_cents for ln in lines)
    profit = sum(ln.profit_cents for ln in lines)
    tax = sum(ln.tax_cents for ln in lines)
    subtotal = sum(ln.total_cents for ln in lines)

    total = subtotal
    rounding_adj = 0
    if round_to_cents:
        rounded = round_cents_to(total, round_to_cents, rounding_mode)
        rounding_adj = rounded - total
        total = rounded
    min_adj = 0
    if minimum_charge_cents is not None:
        if isinstance(minimum_charge_cents, bool) or not isinstance(minimum_charge_cents, int) or minimum_charge_cents < 0:
            raise PricingError("minimum_charge_cents must be non-negative integer cents")
        if total < minimum_charge_cents:
            min_adj = minimum_charge_cents - total
            total = minimum_charge_cents

    price_before_tax = total - tax
    margin = Decimal(0)
    if price_before_tax > 0:
        margin = ((Decimal(price_before_tax - cost) / Decimal(price_before_tax))
                  .quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP))
    return EstimateTotals(
        lines=lines, cost_by_kind=by_kind, cost_cents=cost, overhead_cents=overhead,
        profit_cents=profit, tax_cents=tax, subtotal_cents=subtotal,
        rounding_adjustment_cents=rounding_adj, minimum_charge_adjustment_cents=min_adj,
        total_cents=total, margin_pct=margin,
    )
