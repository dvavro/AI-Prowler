"""Money (integer cents) and units of measure. Design spec: MCP conventions, Test plan 'Unit'."""
import random
from decimal import Decimal

import pytest

from estimator.core.units import (
    Money, UnitError, cents_from_decimal, convert, format_cents, normalize_unit, parse_money, round_cents_to,
)


# ── money ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("value,cents", [
    ("0", 0), ("1", 100), ("1.005", 101), ("1.004", 100), ("-1.005", -101),
    (Decimal("12.345"), 1235), (7, 700), ("0.1", 10),
])
def test_cents_from_decimal_rounds_half_up(value, cents):
    assert cents_from_decimal(value) == cents


@pytest.mark.parametrize("bad", [1.5, True, "abc", "NaN", "Infinity"])
def test_cents_from_decimal_rejects_floats_and_junk(bad):
    with pytest.raises((TypeError, ValueError)):
        cents_from_decimal(bad)


@pytest.mark.parametrize("text,cents", [
    ("$1,234.56", 123456), ("1234.5", 123450), ("-12", -1200), ("($45.00)", -4500), (" $0.99 ", 99),
])
def test_parse_money(text, cents):
    assert parse_money(text) == cents


@pytest.mark.parametrize("cents,text", [(0, "$0.00"), (5, "$0.05"), (123456, "$1,234.56"), (-100, "-$1.00")])
def test_format_cents(cents, text):
    assert format_cents(cents) == text


def test_format_parse_round_trip_random():
    rng = random.Random(20261105)
    for _ in range(2000):
        cents = rng.randint(-10**10, 10**10)
        assert parse_money(format_cents(cents)) == cents


@pytest.mark.parametrize("cents,inc,mode,out", [
    (12349, 100, "half_up", 12300), (12350, 100, "half_up", 12400),
    (12301, 500, "up", 12500), (12499, 1000, "down", 12000), (-150, 100, "half_up", -200),
])
def test_round_cents_to(cents, inc, mode, out):
    assert round_cents_to(cents, inc, mode) == out


def test_round_cents_to_validates():
    with pytest.raises(ValueError):
        round_cents_to(100, 0)
    with pytest.raises(ValueError):
        round_cents_to(100, 100, "sideways")
    with pytest.raises(TypeError):
        round_cents_to(1.0, 100)


def test_money_arithmetic_is_exact():
    total = Money(0)
    for _ in range(10):
        total = total + Money.from_dollars("0.10")
    assert total == Money(100)
    assert (Money(1000) - Money(1)).cents == 999
    assert Money(1999).times("3") == Money(5997)
    assert Money(1000).times("0.0825") == Money(83)          # 82.5 → 83 half-up
    assert str(Money(-250)) == "-$2.50"


def test_money_rejects_floats():
    with pytest.raises(TypeError):
        Money(1.0)
    with pytest.raises(TypeError):
        Money(100).times(1.5)


# ── units ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("alias,code", [
    ("SF", "sqft"), ("sq ft", "sqft"), ("CY", "cuyd"), ("Squares", "sq"), ("each", "ea"), ("LF", "lf"),
])
def test_normalize_unit_aliases(alias, code):
    assert normalize_unit(alias) == code


def test_unknown_unit():
    with pytest.raises(UnitError):
        normalize_unit("furlong")


@pytest.mark.parametrize("value,src,dst,expected", [
    ("27", "cuft", "cuyd", Decimal(1)),
    ("1", "sq", "sqft", Decimal(100)),
    ("9", "sqft", "sqyd", Decimal(1)),
    ("36", "in", "ft", Decimal(3)),
    ("2", "day", "hr", Decimal(16)),
])
def test_convert(value, src, dst, expected):
    assert convert(value, src, dst) == expected


def test_convert_refuses_mixed_dimensions():
    with pytest.raises(UnitError):
        convert("10", "sqft", "lf")


def test_convert_round_trip_random():
    rng = random.Random(7)
    pairs = [("sqft", "sqyd"), ("cuft", "cuyd"), ("ft", "in"), ("sqft", "sq"), ("m", "ft")]
    for _ in range(500):
        a, b = rng.choice(pairs)
        v = Decimal(rng.randint(1, 10**6)) / 100
        assert abs(convert(convert(v, a, b), b, a) - v) < Decimal("1e-20")
