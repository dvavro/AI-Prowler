"""Quick estimates: answer a module's questions, get priced line items.

Used for service jobs with no plans (pressure washing, house cleaning…). The
module's manifest lists the questions and the line rules; each line's quantity
is a formula over the answers, run by the sandboxed formula engine.

Answers become formula variables like this:
- number / integer: the number
- boolean: 1 or 0
- choice: the chosen option's factor (e.g. condition "heavy" -> 1.35)

Answering again replaces that section's lines (the answers are stored on the
section, so the estimate always shows where the numbers came from).
"""
from __future__ import annotations

import json
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

from estimator.context import RequestContext
from estimator.core.formula_engine import FormulaError, evaluate
from estimator.errors import InvalidInput, NotFound
from estimator.estimating import service
from estimator.pricing.price_book import ensure_sample_prices, get_price
from estimator.pricing.stack import LineInput

QTY_PLACES = Decimal("0.0001")
_TRUE = {"true", "yes", "y", "1", "on"}
_FALSE = {"false", "no", "n", "0", "off", ""}


def _registry(registry=None):
    from estimator.modules import get_registry
    return registry or get_registry()


def questions(module_id: str, registry=None) -> dict:
    mod = _registry(registry).get(module_id)
    if mod.path not in ("quick_estimate", "both"):
        raise InvalidInput(f"module '{module_id}' doesn't support quick estimates", module_id=module_id)
    return {"ok": True, "module": mod.summary(), "questions": [q.as_dict() for q in mod.questions]}


def _coerce(q, value):
    """Return (stored_answer, variable_value) for one question, or raise InvalidInput."""
    where = {"field": q.id}
    if q.type == "boolean":
        if isinstance(value, bool):
            b = value
        elif isinstance(value, (int, Decimal)) and value in (0, 1):
            b = bool(value)
        elif isinstance(value, str) and value.strip().lower() in _TRUE | _FALSE:
            b = value.strip().lower() in _TRUE
        else:
            raise InvalidInput(f"'{q.label}' must be yes or no", **where)
        return b, Decimal(1 if b else 0)
    if q.type == "choice":
        v = str(value)
        for c in q.choices:
            if c["value"] == v:
                return v, c["factor"]
        raise InvalidInput(f"'{q.label}' must be one of: " + ", ".join(c["value"] for c in q.choices),
                           **where, choices=[c["value"] for c in q.choices])
    # number / integer
    if isinstance(value, bool):
        raise InvalidInput(f"'{q.label}' must be a number", **where)
    if isinstance(value, float):
        value = repr(value)
    try:
        d = Decimal(str(value).strip().replace(",", ""))
    except (InvalidOperation, ValueError):
        raise InvalidInput(f"'{q.label}' must be a number", **where) from None
    if not d.is_finite():
        raise InvalidInput(f"'{q.label}' must be a number", **where)
    if q.type == "integer" and d != d.to_integral_value():
        raise InvalidInput(f"'{q.label}' must be a whole number", **where)
    if q.min is not None and d < q.min:
        raise InvalidInput(f"'{q.label}' must be at least {q.min}", **where)
    if q.max is not None and d > q.max:
        raise InvalidInput(f"'{q.label}' must be at most {q.max}", **where)
    stored = int(d) if d == d.to_integral_value() else str(d)
    return stored, d


def resolve_answers(mod, answers: dict) -> tuple[dict, dict]:
    """Validate answers against the module's questions. Returns (stored answers, formula variables)."""
    if not isinstance(answers, dict):
        raise InvalidInput("answers must be an object of question id -> answer")
    unknown = sorted(set(answers) - {q.id for q in mod.questions})
    if unknown:
        raise InvalidInput(f"unknown questions: {unknown}", unknown=unknown,
                           valid=[q.id for q in mod.questions])
    stored, variables, missing = {}, {}, []
    for q in mod.questions:
        if q.id in answers and answers[q.id] is not None and answers[q.id] != "":
            value = answers[q.id]
        elif q.default is not None:
            value = q.default
        elif q.required:
            missing.append(q.id)
            continue
        else:
            value = False if q.type == "boolean" else 0 if q.type in ("number", "integer") else None
            if value is None:
                missing.append(q.id)
                continue
        stored[q.id], variables[q.id] = _coerce(q, value)
    if missing:
        raise InvalidInput("please answer: " + ", ".join(missing), missing=missing)
    return stored, variables


def build_lines(mod, variables: dict) -> list[dict]:
    """Evaluate the module's line rules. Lines whose `when` is false or quantity is 0 are left out."""
    out = []
    for rule in mod.lines:
        try:
            if rule.when is not None and not evaluate(rule.when, variables):
                continue
            qty = evaluate(rule.quantity, variables).quantize(QTY_PLACES, rounding=ROUND_HALF_UP)
            waste = evaluate(rule.waste, variables)
        except FormulaError as exc:
            raise InvalidInput(f"line '{rule.id}' couldn't be calculated: {exc}", line=rule.id) from None
        if qty < 0:
            raise InvalidInput(f"line '{rule.id}' came out negative ({qty}); check the answers", line=rule.id)
        if qty == 0:
            continue
        out.append({"rule": rule, "quantity": qty,
                    "waste_pct": waste})
    return out


def plan_items(conn, company_id: str, mod, answers: dict) -> tuple[list, bool, dict]:
    """Price a module's answers without saving anything: (pricing-stack lines, uses sample prices, answers)."""
    stored, variables = resolve_answers(mod, answers)
    items, samples = [], False
    for p in build_lines(mod, variables):
        rule = p["rule"]
        price = get_price(conn, company_id, rule.price_key)
        if price is None:
            sp = mod.sample_prices[rule.price_key]
            cost, sample = sp.cost_cents, True
        else:
            cost, sample = price.cost_cents, price.is_sample
        samples = samples or sample
        items.append(LineInput(rule.kind, p["quantity"], rule.unit, cost, p["waste_pct"], rule.description, rule.id))
    return items, samples, stored


def answer(conn, ctx: RequestContext, estimate_id: int, module_id: str, answers: dict, rev: int,
           registry=None) -> dict:
    """Price a quick estimate from answers, replacing that module's section on the estimate."""
    reg = _registry(registry)
    mod = reg.get(module_id)
    if mod.path not in ("quick_estimate", "both"):
        raise InvalidInput(f"module '{module_id}' doesn't support quick estimates", module_id=module_id)
    stored, variables = resolve_answers(mod, answers)
    planned = build_lines(mod, variables)
    warnings: list[str] = []
    with service.transaction(conn):
        service._check_writable(conn, ctx, estimate_id, rev, service.QUICK_ROLES)
        seeded = ensure_sample_prices(conn, ctx.company_id, mod, actor=ctx.actor)
        sid = service._section_id(conn, ctx, estimate_id, module_id, mod.version)
        conn.execute("DELETE FROM line_items WHERE trade_section_id = ?", (sid,))
        conn.execute("UPDATE trade_sections SET params_json = ?, module_version = ?, needs_reprice = 0 WHERE id = ?",
                     (json.dumps(stored), mod.version, sid))
        sample_keys = []
        for order, p in enumerate(planned):
            rule = p["rule"]
            price = get_price(conn, ctx.company_id, rule.price_key)
            if price is None:   # only possible if the price exists with a future date only
                raise NotFound(f"no current price for '{rule.price_key}'", price_key=rule.price_key)
            if price.unit != rule.unit:
                raise InvalidInput(f"your price '{rule.price_key}' is per {price.unit} but this line is per"
                                   f" {rule.unit}; fix the price book", price_key=rule.price_key)
            if price.is_sample:
                sample_keys.append(rule.price_key)
            service._insert_line(
                conn, ctx, sid, kind=rule.kind, description=rule.description, quantity=p["quantity"],
                unit=rule.unit, unit_cost_cents=price.cost_cents, waste_pct=p["waste_pct"],
                price_key=rule.price_key, sort_order=order,
                calc={"rule": rule.id, "formula": rule.quantity, "quantity": service.qty_text(p["quantity"]),
                      "sample_price": price.is_sample},
            )
        if sample_keys:
            warnings.append("These prices are samples, not yours yet: " + ", ".join(sample_keys)
                            + ". Set your own in the price book before sending this bid.")
        service._log(conn, ctx, estimate_id, "quick_estimate_answered",
                     {"module_id": module_id, "answers": stored, "lines": len(planned),
                      "seeded_sample_prices": seeded})
        service._recalculate(conn, ctx, estimate_id, reg)
        service._bump(conn, ctx, estimate_id)
    result = service.get_estimate(conn, ctx, estimate_id)
    result["warnings"] = warnings
    return result
