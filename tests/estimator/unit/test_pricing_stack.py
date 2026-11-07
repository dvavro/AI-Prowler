"""Pricing stack: cost → waste → burden → overhead → profit → tax → rounding. Design spec: Pricing stack."""
import random
from decimal import Decimal

import pytest

from estimator.pricing import LineInput, Markups, PricingError, price_estimate, price_line

M = Markups(overhead_pct="0.10", profit_pct="0.15", labor_burden_pct="0.30", tax_pct="0.08")


def test_material_line_hand_calculated():
    # 100 sq ft @ $2.50, 10% waste: base 25000, waste 2500, cost 27500
    # overhead 2750, profit (27500+2750)*0.15 = 4537.5 → 4538, tax 27500*0.08 = 2200
    ln = price_line(LineInput("material", Decimal(100), "sqft", 250, Decimal("0.10")), M)
    assert (ln.base_cents, ln.waste_cents, ln.burden_cents, ln.cost_cents) == (25000, 2500, 0, 27500)
    assert (ln.overhead_cents, ln.profit_cents, ln.tax_cents) == (2750, 4538, 2200)
    assert ln.total_cents == 27500 + 2750 + 4538 + 2200


def test_labor_gets_burden_and_no_tax():
    # 8 hr @ $45: base 36000, burden 10800, cost 46800, overhead 4680, profit 7722, tax 0
    ln = price_line(LineInput("labor", Decimal(8), "hr", 4500), M)
    assert (ln.burden_cents, ln.cost_cents, ln.overhead_cents, ln.profit_cents, ln.tax_cents) == (
        10800, 46800, 4680, 7722, 0)


def test_tax_on_price_option():
    m = Markups(overhead_pct="0.10", profit_pct="0.10", tax_pct="0.10", tax_base="price")
    ln = price_line(LineInput("material", Decimal(1), "ea", 10000), m)
    # cost 10000, overhead 1000, profit 1100, tax (12100)*0.10 = 1210
    assert ln.tax_cents == 1210 and ln.total_cents == 13310


def test_estimate_totals_rounding_and_minimum():
    items = [
        LineInput("material", Decimal(100), "sqft", 250, Decimal("0.10"), ref="a"),
        LineInput("labor", Decimal(8), "hr", 4500, ref="b"),
    ]
    t = price_estimate(items, M, round_to_cents=1000)          # nearest $10
    assert t.subtotal_cents == sum(ln.total_cents for ln in t.lines)
    assert t.total_cents % 1000 == 0
    assert t.total_cents - t.subtotal_cents == t.rounding_adjustment_cents
    assert t.cost_by_kind == {"material": 27500, "labor": 46800}

    small = price_estimate([LineInput("labor", Decimal(1), "hr", 1000)], Markups(), minimum_charge_cents=15000)
    assert small.total_cents == 15000 and small.minimum_charge_adjustment_cents == 14000


def test_margin():
    t = price_estimate([LineInput("labor", Decimal(1), "ea", 10000)], Markups(profit_pct="0.25"))
    assert t.total_cents == 12500
    assert t.margin_pct == Decimal("0.2000")


def test_sum_of_steps_always_equals_total_random():
    rng = random.Random(99)
    for _ in range(3000):
        m = Markups(
            overhead_pct=str(Decimal(rng.randint(0, 30)) / 100),
            profit_pct=str(Decimal(rng.randint(0, 50)) / 100),
            labor_burden_pct=str(Decimal(rng.randint(0, 60)) / 100),
            tax_pct=str(Decimal(rng.randint(0, 1100)) / 10000),
            tax_base=rng.choice(["cost", "price"]),
        )
        item = LineInput(
            rng.choice(["material", "labor", "equipment", "sub", "other"]),
            Decimal(rng.randint(0, 100000)) / 100, "ea", rng.randint(0, 500000),
            Decimal(rng.randint(0, 25)) / 100,
        )
        ln = price_line(item, m)
        assert ln.cost_cents == ln.base_cents + ln.waste_cents + ln.burden_cents
        assert ln.total_cents == ln.cost_cents + ln.overhead_cents + ln.profit_cents + ln.tax_cents
        assert all(isinstance(v, int) and v >= 0 for k, v in ln.as_dict().items() if k.endswith("_cents"))


@pytest.mark.parametrize("kwargs", [
    {"overhead_pct": "-0.1"}, {"overhead_pct": "1.5"}, {"profit_pct": 0.1}, {"tax_pct": "0.9"},
    {"tax_base": "magic"}, {"taxable_kinds": ("gold",)},
])
def test_markups_validation(kwargs):
    with pytest.raises(PricingError):
        Markups(**kwargs)


@pytest.mark.parametrize("args", [
    ("steel", Decimal(1), "ea", 100), ("material", Decimal(-1), "ea", 100), ("material", 1.5, "ea", 100),
    ("material", Decimal(1), "ea", 1.0), ("material", Decimal(1), "ea", -5),
])
def test_line_validation(args):
    with pytest.raises((PricingError, ValueError)):
        LineInput(*args)


def test_unit_alias_normalized():
    assert LineInput("material", Decimal(1), "SF", 100).unit == "sqft"
