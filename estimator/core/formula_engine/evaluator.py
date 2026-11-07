"""Sandboxed formula engine.

Module manifests contain formulas such as
    concrete_cy = area * thickness_in / 12 / 27 * (1 + waste)
These must never run arbitrary code (design spec: "Formulas run in a sandboxed
expression evaluator (no eval; a whitelist of math functions)").

How it's safe:
- The formula is parsed with Python's `ast` module in "eval" mode and every node
  is checked against a short whitelist before anything is evaluated.
- Only numbers, variable names, arithmetic, comparisons, and/or/not, the
  `x if cond else y` form and calls to whitelisted functions are allowed.
  Attribute access, subscripts, lambdas, comprehensions, strings and keyword
  arguments are rejected.
- All maths runs on Decimal, so results are exact and repeatable (no float drift).
- Size limits stop expensive expressions: length, node count, exponent size and
  result magnitude.
"""
from __future__ import annotations

import ast
import warnings
from decimal import ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_UP, Decimal, InvalidOperation, localcontext
from functools import lru_cache

MAX_FORMULA_LENGTH = 500
MAX_NODES = 200
MAX_EXPONENT = 10
MAX_ABS_RESULT = Decimal("1e15")
PRECISION = 34


class FormulaError(ValueError):
    """Raised for formulas that are invalid, unsafe, or fail to evaluate."""


def _d(x) -> Decimal:
    if isinstance(x, bool):
        return Decimal(int(x))
    if isinstance(x, float):
        raise FormulaError("float values are not allowed; pass Decimal, int or str")
    try:
        return Decimal(x)
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise FormulaError(f"not a number: {x!r}") from exc


def _round(x, places=0):
    places = int(_d(places))
    if not 0 <= places <= 6:
        raise FormulaError("round() places must be 0-6")
    return _d(x).quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP)


def _ceil(x):
    return _d(x).to_integral_value(rounding=ROUND_CEILING)


def _floor(x):
    return _d(x).to_integral_value(rounding=ROUND_FLOOR)


def _ceil_to(x, step):
    """Round up to a whole multiple of step, e.g. ceil_to(13, 4) = 16 (sheets, bundles, boxes)."""
    step = _d(step)
    if step <= 0:
        raise FormulaError("ceil_to step must be positive")
    return (_d(x) / step).to_integral_value(rounding=ROUND_CEILING) * step


def _sqrt(x):
    x = _d(x)
    if x < 0:
        raise FormulaError("sqrt of a negative number")
    return x.sqrt()


def _min(*args):
    if not args:
        raise FormulaError("min() needs at least one value")
    return min(_d(a) for a in args)


def _max(*args):
    if not args:
        raise FormulaError("max() needs at least one value")
    return max(_d(a) for a in args)


def _clamp(x, lo, hi):
    return min(max(_d(x), _d(lo)), _d(hi))


ALLOWED_FUNCTIONS = {
    "ceil": _ceil,
    "floor": _floor,
    "round": _round,
    "ceil_to": _ceil_to,
    "sqrt": _sqrt,
    "min": _min,
    "max": _max,
    "abs": lambda x: abs(_d(x)),
    "clamp": _clamp,
}

_BIN_OPS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow)
_UNARY_OPS = (ast.UAdd, ast.USub, ast.Not)
_CMP_OPS = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE)
_ALLOWED_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare, ast.IfExp,
    ast.Call, ast.Name, ast.Load, ast.Constant, ast.And, ast.Or,
    *_BIN_OPS, *_UNARY_OPS, *_CMP_OPS,
)


@lru_cache(maxsize=512)
def compile_formula(formula: str) -> ast.Expression:
    """Parse and validate a formula. Raises FormulaError if it is not allowed."""
    if not isinstance(formula, str) or not formula.strip():
        raise FormulaError("formula must be a non-empty string")
    if len(formula) > MAX_FORMULA_LENGTH:
        raise FormulaError(f"formula longer than {MAX_FORMULA_LENGTH} characters")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(formula.strip(), mode="eval")
    except SyntaxError as exc:
        raise FormulaError(f"syntax error: {exc.msg}") from exc
    count = 0
    for node in ast.walk(tree):
        count += 1
        if count > MAX_NODES:
            raise FormulaError(f"formula has more than {MAX_NODES} parts")
        if not isinstance(node, _ALLOWED_NODES):
            raise FormulaError(f"not allowed in formulas: {type(node).__name__}")
        if isinstance(node, ast.Constant) and (
            isinstance(node.value, (str, bytes, complex)) or node.value is None or node.value is Ellipsis
        ):
            raise FormulaError("only numbers are allowed as constants")
        if isinstance(node, ast.Name) and node.id.startswith("_"):
            raise FormulaError(f"names starting with '_' are not allowed: {node.id}")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in ALLOWED_FUNCTIONS:
                raise FormulaError("only these functions are allowed: " + ", ".join(sorted(ALLOWED_FUNCTIONS)))
            if node.keywords:
                raise FormulaError("keyword arguments are not allowed")
    return tree


def formula_variables(formula: str) -> set[str]:
    """Variable names a formula uses (excluding function names)."""
    tree = compile_formula(formula)
    funcs = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call)}
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} - funcs


def evaluate(formula: str, variables: dict | None = None) -> Decimal:
    """Evaluate a validated formula with the given variables. Returns a Decimal."""
    tree = compile_formula(formula)
    env = {}
    for k, v in (variables or {}).items():
        env[k] = _d(v)
    with localcontext() as ctx:
        ctx.prec = PRECISION
        try:
            result = _eval(tree.body, env)
        except FormulaError:
            raise
        except (ArithmeticError, InvalidOperation) as exc:
            raise FormulaError(f"maths error: {exc.__class__.__name__}") from exc
    result = _d(result)
    if not result.is_finite() or abs(result) > MAX_ABS_RESULT:
        raise FormulaError("result is too large")
    return result


def _eval(node, env):
    if isinstance(node, ast.Constant):
        if isinstance(node.value, float):
            # A decimal literal written in the formula (e.g. 2.5): use its exact
            # written value, not the binary float Python parsed it into.
            return Decimal(repr(node.value))
        return _d(node.value)
    if isinstance(node, ast.Name):
        if node.id not in env:
            raise FormulaError(f"unknown variable: {node.id}")
        return env[node.id]
    if isinstance(node, ast.UnaryOp):
        v = _eval(node.operand, env)
        if isinstance(node.op, ast.USub):
            return -v
        if isinstance(node.op, ast.UAdd):
            return +v
        return Decimal(0 if v else 1)
    if isinstance(node, ast.BinOp):
        a, b = _eval(node.left, env), _eval(node.right, env)
        op = node.op
        if isinstance(op, ast.Add):
            return a + b
        if isinstance(op, ast.Sub):
            return a - b
        if isinstance(op, ast.Mult):
            return a * b
        if isinstance(op, (ast.Div, ast.FloorDiv, ast.Mod)) and b == 0:
            raise FormulaError("division by zero")
        if isinstance(op, ast.Div):
            return a / b
        if isinstance(op, ast.FloorDiv):
            return (a / b).to_integral_value(rounding=ROUND_FLOOR)
        if isinstance(op, ast.Mod):
            return a - b * (a / b).to_integral_value(rounding=ROUND_FLOOR)
        if isinstance(op, ast.Pow):
            if b != b.to_integral_value() or abs(b) > MAX_EXPONENT:
                raise FormulaError(f"exponent must be a whole number between -{MAX_EXPONENT} and {MAX_EXPONENT}")
            if a == 0 and b < 0:
                raise FormulaError("division by zero")
            return a ** int(b)
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            result = Decimal(1)
            for v in node.values:
                result = _eval(v, env)
                if not result:
                    return result
            return result
        result = Decimal(0)
        for v in node.values:
            result = _eval(v, env)
            if result:
                return result
        return result
    if isinstance(node, ast.Compare):
        left = _eval(node.left, env)
        for op, comp in zip(node.ops, node.comparators):
            right = _eval(comp, env)
            ok = {
                ast.Eq: left == right, ast.NotEq: left != right, ast.Lt: left < right,
                ast.LtE: left <= right, ast.Gt: left > right, ast.GtE: left >= right,
            }[type(op)]
            if not ok:
                return Decimal(0)
            left = right
        return Decimal(1)
    if isinstance(node, ast.IfExp):
        return _eval(node.body, env) if _eval(node.test, env) else _eval(node.orelse, env)
    if isinstance(node, ast.Call):
        args = [_eval(a, env) for a in node.args]
        try:
            return _d(ALLOWED_FUNCTIONS[node.func.id](*args))
        except TypeError as exc:
            raise FormulaError(f"wrong arguments for {node.func.id}()") from exc
    raise FormulaError(f"not allowed in formulas: {type(node).__name__}")
