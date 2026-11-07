"""Good/better/best options (est_scenarios).

An option is a small set of answers that replaces some of a trade's answers,
for example roofing material 3-tab / architectural / metal. Each option is
priced against the whole estimate (other trades, markups, minimum charge)
without changing it; the prices are saved so they can go on the bid. Choosing
an option re-prices that trade with the option's answers.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal

from estimator.context import RequestContext
from estimator.core.units.money import format_cents
from estimator.errors import InvalidInput, NotEditable, NotFound
from estimator.estimating import quick, service
from estimator.pricing.stack import LineInput, price_estimate


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _registry(registry=None):
    from estimator.modules import get_registry
    return registry or get_registry()


def _custom_options(options, mod) -> list[dict]:
    if not isinstance(options, list) or not 2 <= len(options) <= 4:
        raise InvalidInput("give 2 to 4 options, each {id, label, answers}", field="options")
    out, seen = [], set()
    valid = {q.id for q in mod.questions}
    for o in options:
        if not isinstance(o, dict) or not o.get("id") or not isinstance(o.get("answers"), dict) or not o["answers"]:
            raise InvalidInput("each option needs an id and some answers", field="options")
        oid = str(o["id"]).strip()
        if oid in seen:
            raise InvalidInput(f"option id '{oid}' is used twice", field="options")
        seen.add(oid)
        bad = sorted(set(o["answers"]) - valid)
        if bad:
            raise InvalidInput(f"{mod.name} has no questions {bad}", field="options", valid=sorted(valid))
        out.append({"id": oid, "label": str(o.get("label") or oid), "answers": dict(o["answers"])})
    return out


def _pick_section(est: dict, reg, module_id: str | None, custom: bool):
    secs = [s for s in est["sections"] if s["module_id"] in reg.modules]
    if module_id:
        for s in secs:
            if s["module_id"] == module_id:
                return s
        raise NotFound(f"the estimate has no '{module_id}' section", module_id=module_id)
    for s in secs:
        if custom or reg.modules[s["module_id"]].scenarios:
            return s
    raise InvalidInput("none of the trades on this estimate has good/better/best options; give your own options",
                       estimate_id=est["id"])


def _other_items(est: dict, module_id: str) -> list:
    items = []
    for sec in est["sections"]:
        if sec["module_id"] == module_id:
            continue
        for ln in sec["lines"]:
            items.append(LineInput(ln["kind"], Decimal(ln["quantity"]), ln["unit"], int(ln["unit_cost_cents"]),
                                   Decimal(ln["waste_pct"]), ln["description"], str(ln["id"])))
    return items


def price_options(conn, ctx: RequestContext, estimate_id: int, module_id: str | None = None,
                  options: list | None = None, registry=None) -> dict:
    """Price each option for one trade on the estimate. Saves the prices for the bid; changes no line items."""
    service._require_edit_role(ctx, service.QUICK_ROLES)
    reg = _registry(registry)
    est = service.get_estimate(conn, ctx, int(estimate_id))
    sec = _pick_section(est, reg, module_id, custom=options is not None)
    mod = reg.modules[sec["module_id"]]
    opts = _custom_options(options, mod) if options is not None else list(mod.scenarios)
    if not opts:
        raise InvalidInput(f"{mod.name} has no built-in options; give your own (2 to 4)", module_id=mod.id)
    base = dict(sec["answers"] or {})
    if not base:
        raise InvalidInput(f"answer the {mod.name} questions first", module_id=mod.id)
    markups, settings = service.company_markups(conn, ctx.company_id)
    minimum = service._estimate_minimum(conn, est["id"], settings["minimum_charge_cents"], reg)
    others = _other_items(est, mod.id)
    current = int((est["totals"] or {}).get("total_cents", 0))
    priced = []
    for o in opts:
        try:
            items, samples, stored = quick.plan_items(conn, ctx.company_id, mod, {**base, **o["answers"]})
        except InvalidInput as exc:
            raise InvalidInput(f"option '{o['id']}' doesn't work: {exc.message}", option=o["id"]) from None
        totals = price_estimate(others + items, markups, settings["round_to_cents"], settings["rounding_mode"],
                                minimum).as_dict()
        totals.pop("lines")
        is_current = all(str(stored.get(k)) == str(base.get(k)) for k in o["answers"])
        priced.append({"id": o["id"], "label": o["label"], "answers": o["answers"], "total_cents": totals["total_cents"],
                       "total": format_cents(totals["total_cents"]),
                       "difference_cents": totals["total_cents"] - current, "current": is_current,
                       "uses_samples": samples, "totals": totals})
    now = _now()
    with service.transaction(conn):
        conn.execute("DELETE FROM estimate_scenarios WHERE estimate_id = ? AND module_id = ?", (est["id"], mod.id))
        for p in priced:
            conn.execute(
                "INSERT INTO estimate_scenarios (company_id, estimate_id, module_id, option_id, label, answers_json,"
                " total_cents, totals_json, uses_samples, chosen, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (ctx.company_id, est["id"], mod.id, p["id"], p["label"], json.dumps(p["answers"]), p["total_cents"],
                 json.dumps(p["totals"], default=str), int(p["uses_samples"]), int(p["current"]), ctx.actor, now))
        service._log(conn, ctx, est["id"], "options_priced",
                     {"module_id": mod.id, "options": {p["id"]: p["total_cents"] for p in priced}})
    for p in priced:
        p.pop("totals")
    summary = "; ".join(f"{p['label']}: {p['total']}" + (" (this quote)" if p["current"] else "") for p in priced)
    return {"ok": True, "estimate_id": est["id"], "module_id": mod.id, "trade": mod.name, "current_total_cents": current,
            "options": priced, "summary": summary}


def list_options(conn, ctx: RequestContext, estimate_id: int) -> list[dict]:
    return [{"module_id": r["module_id"], "id": r["option_id"], "label": r["label"], "total_cents": r["total_cents"],
             "chosen": bool(r["chosen"]), "answers": json.loads(r["answers_json"])}
            for r in conn.execute("SELECT * FROM estimate_scenarios WHERE estimate_id = ? AND company_id = ? ORDER BY id",
                                  (int(estimate_id), ctx.company_id))]


def choose_option(conn, ctx: RequestContext, estimate_id: int, option_id: str, rev: int, module_id: str | None = None,
                  registry=None) -> dict:
    """Re-price the trade with a saved option's answers (the estimate must still be editable)."""
    reg = _registry(registry)
    sql = "SELECT * FROM estimate_scenarios WHERE estimate_id = ? AND company_id = ? AND option_id = ?"
    args = [int(estimate_id), ctx.company_id, str(option_id)]
    if module_id:
        sql += " AND module_id = ?"
        args.append(module_id)
    rows = conn.execute(sql, args).fetchall()
    if not rows:
        raise NotFound(f"no option '{option_id}' on estimate {estimate_id}; price the options first (est_scenarios)",
                       option=option_id)
    if len(rows) > 1:
        raise InvalidInput("more than one trade has that option; say which (module_id)",
                           modules=[r["module_id"] for r in rows])
    row = rows[0]
    est = service.get_estimate(conn, ctx, int(estimate_id))
    if est["status"] not in service.EDITABLE_STATUSES:
        raise NotEditable(f"the estimate is {est['status']}; make a revision to change options", status=est["status"])
    sec = next(s for s in est["sections"] if s["module_id"] == row["module_id"])
    answers = {**(sec["answers"] or {}), **json.loads(row["answers_json"])}
    out = quick.answer(conn, ctx, est["id"], row["module_id"], answers, rev, reg)
    with service.transaction(conn):
        conn.execute("UPDATE estimate_scenarios SET chosen = (option_id = ?) WHERE estimate_id = ? AND module_id = ?",
                     (row["option_id"], est["id"], row["module_id"]))
        service._log(conn, ctx, est["id"], "option_chosen", {"module_id": row["module_id"], "option": row["option_id"]})
    out["chosen_option"] = {"module_id": row["module_id"], "id": row["option_id"], "label": row["label"],
                            "answers": json.loads(row["answers_json"])}
    return out
