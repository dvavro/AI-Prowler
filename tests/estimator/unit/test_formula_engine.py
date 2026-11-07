"""Sandboxed formula engine. Design spec: Trade module framework; Test plan 'Unit' and 'Manifest validation'."""
import random
from decimal import Decimal

import pytest

from estimator.core.formula_engine import FormulaError, evaluate, formula_variables


# ── real trade formulas from the design spec ────────────────────────────────

def test_concrete_slab_cubic_yards():
    # 1,000 sq ft slab, 4" thick, 5% waste → 1000*4/12/27*1.05 = 12.962962…
    cy = evaluate("area * thickness_in / 12 / 27 * (1 + waste)",
                  {"area": 1000, "thickness_in": 4, "waste": "0.05"})
    assert cy.quantize(Decimal("0.001")) == Decimal("12.963")


def test_framing_studs():
    studs = evaluate("ceil(lf * 12 / spacing) + corners + openings * 2",
                     {"lf": 120, "spacing": 16, "corners": 8, "openings": 6})
    assert studs == 90 + 8 + 12


def test_roof_squares_with_pitch_factor():
    squares = evaluate("ceil_to(plan_area * pitch_factor / 100 * (1 + waste), 1/3)",
                       {"plan_area": 2000, "pitch_factor": "1.118", "waste": "0.10"})
    assert squares >= Decimal("24.596")
    assert (squares * 3) == (squares * 3).to_integral_value()   # whole bundles (3 per square)


def test_paint_gallons_conditional_coats():
    f = "ceil(area * (coats if new_drywall == 0 else coats + 1) / coverage)"
    assert evaluate(f, {"area": 1200, "coats": 2, "new_drywall": 1, "coverage": 350}) == 11
    assert evaluate(f, {"area": 1200, "coats": 2, "new_drywall": 0, "coverage": 350}) == 7


@pytest.mark.parametrize("formula,expected", [
    ("1 + 2 * 3", 7), ("(1 + 2) * 3", 9), ("7 // 2", 3), ("7 % 3", 1), ("2 ** 10", 1024),
    ("-5 + +2", -3), ("min(3, 1, 2)", 1), ("max(3, 1, 2)", 3), ("abs(-4)", 4),
    ("round(2.345, 2)", Decimal("2.35")), ("floor(2.9)", 2), ("ceil(2.1)", 3), ("sqrt(16)", 4),
    ("clamp(15, 0, 10)", 10), ("1 < 2 < 3", 1), ("3 > 2 > 2", 0), ("1 and 0", 0), ("0 or 5", 5),
    ("not 0", 1), ("0.1 + 0.2", Decimal("0.3")),
])
def test_arithmetic(formula, expected):
    assert evaluate(formula) == Decimal(expected)


def test_formula_variables():
    assert formula_variables("ceil(area * (1 + waste)) + max(a, b)") == {"area", "waste", "a", "b"}


# ── safety: nothing outside the whitelist can run ───────────────────────────

@pytest.mark.parametrize("bad", [
    "__import__('os').system('dir')",
    "open('x')",
    "area.__class__",
    "x[0]",
    "(lambda: 1)()",
    "[i for i in range(3)]",
    "'text'",
    "b'bytes'",
    "None",
    "...",
    "x := 5",
    "eval('1')",
    "exec('1')",
    "getattr(area, 'real')",
    "round(1, ndigits=2)",
    "_secret + 1",
    "1 if True else __builtins__",
    "{1: 2}",
    "{1, 2}",
    "(1, 2)",
    "f'{area}'",
    "1j",
])
def test_rejects_unsafe_or_unsupported(bad):
    with pytest.raises(FormulaError):
        evaluate(bad, {"area": 1, "x": 1})


@pytest.mark.parametrize("bad,why", [
    ("1 / 0", "division"), ("5 // 0", "division"), ("5 % 0", "division"),
    ("2 ** 11", "exponent"), ("2 ** 0.5", "exponent"), ("0 ** -1", "division"),
    ("sqrt(-1)", "negative"), ("round(1, 9)", "places"), ("missing + 1", "unknown variable"),
    ("10 ** 10 * 10 ** 10", "too large"), ("min()", "needs"),
])
def test_runtime_errors_are_clean(bad, why):
    with pytest.raises(FormulaError, match=why):
        evaluate(bad)


def test_size_limits():
    with pytest.raises(FormulaError, match="longer"):
        evaluate("1+" * 300 + "1")
    with pytest.raises(FormulaError, match="parts"):
        evaluate("+".join(["a"] * 120), {"a": 1})


def test_rejects_float_variables():
    with pytest.raises(FormulaError):
        evaluate("a + 1", {"a": 1.5})


def test_fuzzed_formulas_never_escape():
    """Random junk must either evaluate to a number or raise FormulaError — never anything else."""
    rng = random.Random(42)
    tokens = list("0123456789+-*/%()<>=.,_ ") + ["**", "//", "a", "b", "ceil(", "min(", "__", "import",
                                                 "os", "lambda", "[", "]", "'", "if", "else", "and", "not"]
    for _ in range(3000):
        expr = "".join(rng.choice(tokens) for _ in range(rng.randint(1, 25)))
        try:
            result = evaluate(expr, {"a": 3, "b": 4})
            assert isinstance(result, Decimal)
        except FormulaError:
            pass
