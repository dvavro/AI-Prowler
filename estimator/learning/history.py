"""Actual-vs-estimate learning loop.

record_actuals: after a job is done, what it really cost - per line item, per price, per kind of cost (all the
labor, all the material) or one job total. Saved next to the estimate; the estimate itself never changes.

compare_history: for each price key, the unit costs used on past estimates and the unit costs jobs really came
in at, and how far over or under jobs run. With an estimate, each of its lines is checked against that history.
It suggests price-book changes (with the pricebook_update call to make) but never changes a price itself.
"""
from __future__ import annotations

import json
import statistics
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from estimator.context import RequestContext
from estimator.core.units.money import format_cents, parse_money
from estimator.errors import InvalidInput, NotFound, PermissionDenied
from estimator.estimating import service

KINDS = ("material", "labor", "equipment", "sub", "other")
ACTUALS_STATUSES = ("approved", "sent", "won", "archived")    # the job was sold; a draft has no actual costs
RECORD_ROLES = ("owner", "estimator", "office")
LINE_OFF_RATIO = Decimal("0.25")       # an estimate's unit cost 25% away from the usual one is flagged
SUGGEST_RATIO = Decimal("0.10")        # actuals 10% away from the price book suggest a new price
SUGGEST_MIN_JOBS = 2                   # ...once at least this many jobs show it
HISTORY_MIN = 3                        # past estimates needed before a line is called unusual


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _qty(value, name: str) -> Decimal | None:
    if value in (None, ""):
        return None
    try:
        d = Decimal(str(value).replace(",", "").strip())
    except InvalidOperation:
        raise InvalidInput(f"{name} must be a number", field=name) from None
    if not d.is_finite() or d < 0:
        raise InvalidInput(f"{name} can't be negative", field=name)
    return d


def _money(value, name: str) -> int:
    if isinstance(value, bool) or value is None or value == "":
        raise InvalidInput(f"{name} is needed, in dollars like \"1250.00\"", field=name)
    try:
        cents = parse_money(str(value))
    except (ValueError, TypeError):
        raise InvalidInput(f"{name} must be dollars like \"1250.00\"", field=name) from None
    if cents < 0:
        raise InvalidInput(f"{name} can't be negative", field=name)
    return cents


def _pct(part: Decimal) -> str:
    return f"{(part * 100).quantize(Decimal('0.1'))}%"


# ---------------------------------------------------------------- recording

def record_actuals(conn, ctx: RequestContext, estimate_id: int, actuals: list, *, replace: bool = False,
                   note: str = "") -> dict:
    """Save what a sold job really cost. Each item is one of:
        {"line_id": 12, "cost": "480.00", "quantity": "1900", "hours": "6"}   one line item
        {"price_key": "pw_driveway_sqft", "cost": "480.00"}                  a line found by its price
        {"kind": "labor", "cost": "2200", "hours": "40"}                     all the labor (or material, ...)
        {"total": "9800"}                                                    the whole job
    replace=true clears what was recorded before for this estimate."""
    if ctx.role not in RECORD_ROLES:
        raise PermissionDenied(f"role '{ctx.role}' can't record job costs", role=ctx.role)
    est = service.get_estimate(conn, ctx, int(estimate_id))
    if est["status"] not in ACTUALS_STATUSES:
        raise InvalidInput(f"estimate {est['id']} is '{est['status']}'. Record what a job really cost once it's "
                           "approved, sent or won.", status=est["status"])
    if not isinstance(actuals, list) or not actuals:
        raise InvalidInput('give actuals as a list, e.g. [{"line_id": 12, "cost": "480.00"}] or [{"total": "9800"}]')
    totals = est["totals"] or {}
    lines = {ln["id"]: (sec, ln) for sec in est["sections"] for ln in sec["lines"]}
    by_key: dict[str, list] = {}
    for sec, ln in lines.values():
        if ln["price_key"]:
            by_key.setdefault(ln["price_key"], []).append((sec, ln))
    rows = []
    for i, item in enumerate(actuals, 1):
        if not isinstance(item, dict):
            raise InvalidInput(f"actual #{i} must be an object")
        where = f"actual #{i}"
        hours = _qty(item.get("hours"), f"{where} hours")
        qty = _qty(item.get("quantity"), f"{where} quantity")
        row = {"line_item_id": None, "price_key": None, "module_id": None, "kind": None, "description": "",
               "est_quantity": None, "est_unit_cost_cents": None, "est_total_cents": None,
               "actual_quantity": str(qty) if qty is not None else None,
               "actual_hours": str(hours) if hours is not None else None,
               "note": str(item.get("note") or note or "")[:500] or None}
        if "total" in item:
            row.update(actual_cost_cents=_money(item["total"], f"{where} total"), description="Whole job",
                       est_total_cents=totals.get("cost_cents"))
        else:
            row["actual_cost_cents"] = _money(item.get("cost"), f"{where} cost")
            found = None
            if item.get("line_id") not in (None, ""):
                found = lines.get(int(item["line_id"]))
                if found is None:
                    raise NotFound(f"{where}: line {item['line_id']} isn't on estimate {est['id']}", line_id=item["line_id"])
            elif item.get("price_key"):
                hits = by_key.get(str(item["price_key"]), [])
                if len(hits) != 1:
                    raise InvalidInput(f"{where}: price '{item['price_key']}' is on {len(hits)} lines of this estimate; "
                                       "use line_id instead", price_key=item["price_key"])
                found = hits[0]
            elif item.get("kind"):
                kind = str(item["kind"]).strip().lower()
                if kind not in KINDS:
                    raise InvalidInput(f"{where}: kind must be one of {', '.join(KINDS)}", field="kind")
                row.update(kind=kind, description=f"All {kind}",
                           est_total_cents=int((totals.get("cost_by_kind") or {}).get(kind, 0)))
            else:
                raise InvalidInput(f"{where} needs line_id, price_key, kind or total")
            if found:
                sec, ln = found
                bought = Decimal(ln["quantity"]) * (1 + Decimal(ln["waste_pct"] or "0"))   # with waste, as bought
                row.update(line_item_id=ln["id"], price_key=ln["price_key"], module_id=sec["module_id"],
                           kind=ln["kind"], description=ln["description"], est_quantity=format(bought.normalize(), "f"),
                           est_unit_cost_cents=ln["unit_cost_cents"], est_total_cents=_line_cost(ln))
        rows.append(row)
    with service.transaction(conn):
        if replace:
            conn.execute("DELETE FROM estimate_actuals WHERE company_id = ? AND estimate_id = ?",
                         (ctx.company_id, est["id"]))
        for r in rows:
            conn.execute(
                "INSERT INTO estimate_actuals (company_id, estimate_id, line_item_id, price_key, module_id, kind,"
                " description, est_quantity, est_unit_cost_cents, est_total_cents, actual_quantity, actual_cost_cents,"
                " actual_hours, note, recorded_by, recorded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ctx.company_id, est["id"], r["line_item_id"], r["price_key"], r["module_id"], r["kind"],
                 r["description"], r["est_quantity"], r["est_unit_cost_cents"], r["est_total_cents"],
                 r["actual_quantity"], r["actual_cost_cents"], r["actual_hours"], r["note"], ctx.actor, _now()))
        service._log(conn, ctx, est["id"], "actuals_recorded", {"count": len(rows), "replace": bool(replace)})
    return {"ok": True, "estimate_id": est["id"], "recorded": len(rows), **job_actuals(conn, ctx, est["id"])}


def _line_cost(ln: dict) -> int:
    """A line's estimated cost to you (with waste and labor burden), not its price to the customer."""
    price = (ln.get("calc") or {}).get("price") or {}
    return int(price.get("cost_cents", ln["total_cents"] or 0))


def job_actuals(conn, ctx: RequestContext, estimate_id: int) -> dict:
    """What was recorded for one job, against the estimate."""
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM estimate_actuals WHERE company_id = ? AND estimate_id = ? ORDER BY id",
        (ctx.company_id, int(estimate_id)))]
    items = []
    for r in rows:
        diff = (r["actual_cost_cents"] - r["est_total_cents"]) if r["est_total_cents"] is not None else None
        items.append({"id": r["id"], "description": r["description"], "price_key": r["price_key"], "kind": r["kind"],
                      "estimated": format_cents(r["est_total_cents"]) if r["est_total_cents"] is not None else None,
                      "actual": format_cents(r["actual_cost_cents"]), "actual_cost_cents": r["actual_cost_cents"],
                      "difference": format_cents(diff) if diff is not None else None,
                      "over_by_pct": _pct(Decimal(diff) / r["est_total_cents"]) if diff is not None and r["est_total_cents"]
                      else None, "hours": r["actual_hours"], "note": r["note"]})
    whole = [r for r in rows if r["description"] == "Whole job" and r["line_item_id"] is None and r["kind"] is None]
    out = {"actuals": items}
    if whole:
        w = whole[-1]
        out["job"] = {"estimated_cost": format_cents(w["est_total_cents"] or 0), "actual_cost": format_cents(w["actual_cost_cents"]),
                      "over_by_pct": _pct(Decimal(w["actual_cost_cents"] - w["est_total_cents"]) / w["est_total_cents"])
                      if w["est_total_cents"] else None}
        row = conn.execute("SELECT totals_json FROM estimates WHERE id = ?", (int(estimate_id),)).fetchone()
        t = json.loads(row["totals_json"]) if row and row["totals_json"] else {}
        before_tax = int(t.get("total_cents", 0)) - int(t.get("tax_cents", 0))
        if before_tax > 0:
            real = Decimal(before_tax - w["actual_cost_cents"]) / before_tax
            out["job"]["price_before_tax"] = format_cents(before_tax)
            out["job"]["estimated_margin"] = _pct(Decimal(str(t.get("margin_pct", "0"))))
            out["job"]["real_margin"] = _pct(real)
    return out


# ---------------------------------------------------------------- comparing

def _unit_cost(r) -> Decimal | None:
    """What one unit really cost on a job: actual cost / actual quantity (or the estimated quantity)."""
    qty = r["actual_quantity"] or r["est_quantity"]
    try:
        q = Decimal(qty) if qty not in (None, "") else None
    except InvalidOperation:
        q = None
    if not q:
        return None
    return Decimal(r["actual_cost_cents"]) / q


def _key_history(conn, company_id: str, price_key: str, exclude_estimate: int | None = None) -> dict:
    """Unit costs used for one price key on past estimates, and what jobs really paid."""
    used = [int(r[0]) for r in conn.execute(
        "SELECT li.unit_cost_cents FROM line_items li JOIN trade_sections s ON s.id = li.trade_section_id"
        " JOIN estimates e ON e.id = s.estimate_id WHERE e.company_id = ? AND li.price_key = ? AND e.id != ?"
        " AND e.status NOT IN ('draft', 'archived') AND li.unit_cost_cents > 0 AND e.is_practice = 0",
        (company_id, price_key, exclude_estimate or -1))]
    acts = conn.execute("SELECT * FROM estimate_actuals WHERE company_id = ? AND price_key = ? AND estimate_id != ?"
                        " AND estimate_id NOT IN (SELECT id FROM estimates WHERE is_practice = 1)",
                        (company_id, price_key, exclude_estimate or -1)).fetchall()
    unit_actuals = [u for u in (_unit_cost(r) for r in acts) if u is not None]
    overruns = [Decimal(r["actual_cost_cents"] - r["est_total_cents"]) / r["est_total_cents"]
                for r in acts if r["est_total_cents"]]
    jobs = len({r["estimate_id"] for r in acts})
    return {"used": used, "unit_actuals": unit_actuals, "overruns": overruns, "jobs": jobs}


def _price_summary(conn, ctx, price_key: str, exclude_estimate: int | None = None) -> dict:
    from estimator.pricing.price_book import get_price
    h = _key_history(conn, ctx.company_id, price_key, exclude_estimate)
    cur = get_price(conn, ctx.company_id, price_key)
    out = {"price_key": price_key, "unit": cur.unit if cur else None,
           "price_book": format_cents(cur.cost_cents) if cur else None, "price_book_is_sample": bool(cur and cur.is_sample),
           "estimates_using_it": len(h["used"]), "jobs_with_actuals": h["jobs"]}
    if h["used"]:
        out["usual_estimated_unit_cost"] = format_cents(int(statistics.median(h["used"])))
    if h["unit_actuals"]:
        med = statistics.median(h["unit_actuals"])
        out["actual_unit_cost"] = format_cents(int(med.quantize(Decimal(1))))
        out["_actual_unit_cents"] = int(med.quantize(Decimal(1)))
    if h["overruns"]:
        avg = sum(h["overruns"]) / len(h["overruns"])
        out["jobs_run"] = (f"{_pct(abs(avg))} over the estimate" if avg > 0 else
                           f"{_pct(abs(avg))} under the estimate" if avg < 0 else "on the estimate")
        out["_avg_overrun"] = avg
    if cur and "_actual_unit_cents" in out and h["jobs"] >= SUGGEST_MIN_JOBS and cur.cost_cents:
        gap = Decimal(out["_actual_unit_cents"] - cur.cost_cents) / cur.cost_cents
        if abs(gap) >= SUGGEST_RATIO:
            dollars = str((Decimal(out["_actual_unit_cents"]) / 100).quantize(Decimal("0.01")))
            out["suggestion"] = {
                "message": (f"Jobs paid {out['actual_unit_cost']} per {cur.unit} for {price_key}, "
                            f"{_pct(abs(gap))} {'more' if gap > 0 else 'less'} than your price book "
                            f"({format_cents(cur.cost_cents)}), over {h['jobs']} jobs. Consider updating it."),
                "pricebook_update": {price_key: dollars}}
    return out


def compare_history(conn, ctx: RequestContext, estimate_id: int | None = None, price_key: str | None = None,
                    module_id: str | None = None) -> dict:
    """Unit costs against past estimates and real job costs. Changes nothing."""
    if estimate_id:
        return _compare_estimate(conn, ctx, int(estimate_id))
    if price_key:
        s = _price_summary(conn, ctx, price_key)
        if not s["estimates_using_it"] and not s["jobs_with_actuals"] and s["price_book"] is None:
            raise NotFound(f"no history or price called '{price_key}'", price_key=price_key)
        return {"ok": True, "prices": [_clean(s)], "suggestions": [s["suggestion"]] if "suggestion" in s else []}
    sql = ("SELECT DISTINCT price_key FROM estimate_actuals WHERE company_id = ? AND price_key IS NOT NULL"
           " AND estimate_id NOT IN (SELECT id FROM estimates WHERE is_practice = 1)")
    args: list = [ctx.company_id]
    if module_id:
        sql += " AND module_id = ?"
        args.append(module_id)
    keys = [r[0] for r in conn.execute(sql, args)]
    summaries = [_price_summary(conn, ctx, k) for k in keys]
    summaries.sort(key=lambda s: -abs(s.get("_avg_overrun", Decimal(0))))
    jobs = conn.execute("SELECT COUNT(DISTINCT estimate_id) FROM estimate_actuals WHERE company_id = ?"
                        " AND estimate_id NOT IN (SELECT id FROM estimates WHERE is_practice = 1)",
                        (ctx.company_id,)).fetchone()[0]
    whole = conn.execute("SELECT actual_cost_cents, est_total_cents FROM estimate_actuals WHERE company_id = ?"
                         " AND description = 'Whole job' AND line_item_id IS NULL AND kind IS NULL AND est_total_cents > 0"
                         " AND estimate_id NOT IN (SELECT id FROM estimates WHERE is_practice = 1)",
                         (ctx.company_id,)).fetchall()
    out = {"ok": True, "jobs_with_actuals": jobs, "prices": [_clean(s) for s in summaries],
           "suggestions": [s["suggestion"] for s in summaries if "suggestion" in s]}
    if whole:
        avg = sum(Decimal(a - e) / e for a, e in whole) / len(whole)
        out["whole_jobs"] = {"count": len(whole), "average": f"{_pct(abs(avg))} {'over' if avg > 0 else 'under'} the "
                             "estimated cost" if avg else "on the estimated cost"}
    if not jobs:
        out["note"] = ("No job costs recorded yet. After a job is done, record what it really cost with "
                       "est_record_actuals, and this will show where your prices run high or low.")
    return out


def _compare_estimate(conn, ctx, estimate_id: int) -> dict:
    est = service.get_estimate(conn, ctx, estimate_id)
    lines = []
    for sec in est["sections"]:
        for ln in sec["lines"]:
            if not ln["price_key"]:
                continue
            h = _key_history(conn, ctx.company_id, ln["price_key"], exclude_estimate=est["id"])
            row = {"line_id": ln["id"], "description": ln["description"], "price_key": ln["price_key"],
                   "unit": ln["unit"], "unit_cost": format_cents(ln["unit_cost_cents"]),
                   "past_estimates": len(h["used"]), "jobs_with_actuals": h["jobs"], "flag": None}
            if h["used"]:
                usual = int(statistics.median(h["used"]))
                row["usual_unit_cost"] = format_cents(usual)
                if len(h["used"]) >= HISTORY_MIN and usual:
                    gap = Decimal(ln["unit_cost_cents"] - usual) / usual
                    if abs(gap) >= LINE_OFF_RATIO:
                        row["flag"] = "higher_than_usual" if gap > 0 else "lower_than_usual"
                        row["message"] = (f"{format_cents(ln['unit_cost_cents'])} per {ln['unit']} is {_pct(abs(gap))} "
                                          f"{'above' if gap > 0 else 'below'} your usual {format_cents(usual)}.")
            if h["unit_actuals"]:
                real = int(statistics.median(h["unit_actuals"]).quantize(Decimal(1)))
                row["jobs_really_paid"] = format_cents(real)
                if real and ln["unit_cost_cents"] and Decimal(real - ln["unit_cost_cents"]) / ln["unit_cost_cents"] >= LINE_OFF_RATIO:
                    row["flag"] = row["flag"] or "under_real_cost"
                    row.setdefault("message", f"Past jobs really paid {format_cents(real)} per {ln['unit']}, more than "
                                              f"the {format_cents(ln['unit_cost_cents'])} used here.")
            lines.append(row)
    flagged = [r for r in lines if r["flag"]]
    out = {"ok": True, "estimate_id": est["id"], "title": est["title"], "lines": lines, "flagged": len(flagged),
           "summary": (f"{len(flagged)} line(s) differ from your history." if flagged else
                       "Every line is in line with your history." if any(r["past_estimates"] for r in lines) else
                       "No history yet for these prices.")}
    recorded = job_actuals(conn, ctx, est["id"])
    if recorded["actuals"]:
        out["this_job"] = recorded
    return out


def _clean(s: dict) -> dict:
    return {k: v for k, v in s.items() if not k.startswith("_")}
