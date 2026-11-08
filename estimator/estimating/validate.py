"""Reviewer QA checks for an estimate (est_validate).

Plain reads: nothing is changed. Each finding has a level:
- error: must be fixed before the estimate can be approved
- warning: a person should look at it
- info: a reminder (minimum charge applied, module notes such as hot-weather pours)
"""
from __future__ import annotations

from decimal import Decimal

from estimator.context import RequestContext
from estimator.core.units.money import format_cents
from estimator.estimating import service

MARGIN_FLOOR = Decimal("0.10")     # warn when the margin before tax is under 10%
OUTLIER_RATIO = Decimal(3)         # warn when a unit cost is over 3x, or under 1/3 of, the module's sample


def _registry(registry=None):
    from estimator.modules import get_registry
    return registry or get_registry()


def validate(conn, ctx: RequestContext, estimate_id: int, registry=None) -> dict:
    reg = _registry(registry)
    est = service.get_estimate(conn, ctx, int(estimate_id))
    findings: list[dict] = []

    def add(level, code, message, **extra):
        findings.append({"level": level, "code": code, "message": message, **extra})

    m_rows = conn.execute("SELECT status, needs_remeasure, suggested_qty FROM measurements WHERE company_id = ?"
                          " AND estimate_id = ? AND status != 'rejected'", (ctx.company_id, est["id"])).fetchall()
    waiting = sum(1 for r in m_rows if r["status"] == "proposed")
    remeasure = sum(1 for r in m_rows if r["needs_remeasure"])
    suggested = sum(1 for r in m_rows if r["status"] == "approved" and r["suggested_qty"] is not None)
    if waiting:
        add("warning", "measurements_waiting", f"{waiting} measurement(s) wait for a person's approval and aren't "
            "priced yet (takeoff_list, then takeoff_confirm).", count=waiting)
    if remeasure:
        add("warning", "measurements_remeasure", f"{remeasure} measurement(s) need re-measuring: the plans or a scale "
            "changed under them.", count=remeasure)
    if suggested:
        add("warning", "measurements_suggested", f"{suggested} approved measurement(s) have a suggested change waiting "
            "for a person.", count=suggested)

    lines = [(sec, ln) for sec in est["sections"] for ln in sec["lines"]]
    if not lines:
        add("error", "no_lines", "The estimate has no line items yet.")
    samples = sorted({ln["price_key"] for _, ln in lines if ln["calc"].get("sample_price")})
    if samples:
        add("warning", "sample_prices", "Uses sample prices, not yours: " + ", ".join(samples)
            + ". Set your own with pricebook_update, or confirm them knowingly.", price_keys=samples)
    for sec, ln in lines:
        mod = reg.modules.get(sec["module_id"])
        sp = mod.sample_prices.get(ln["price_key"]) if mod and ln["price_key"] else None
        if ln["unit_cost_cents"] == 0:
            add("warning", "zero_cost", f"'{ln['description']}' has a unit cost of $0.00.", line_id=ln["id"])
        elif sp and sp.cost_cents and not ln["calc"].get("sample_price"):
            ratio = Decimal(ln["unit_cost_cents"]) / Decimal(sp.cost_cents)
            if ratio > OUTLIER_RATIO or ratio < 1 / OUTLIER_RATIO:
                add("warning", "unit_cost_outlier",
                    f"'{ln['description']}' costs {format_cents(ln['unit_cost_cents'])} per {ln['unit']}, far from the "
                    f"usual {format_cents(sp.cost_cents)}. Check the price book.", line_id=ln["id"],
                    price_key=ln["price_key"])
    totals = est["totals"] or {}
    if totals.get("minimum_charge_adjustment_cents"):
        add("info", "minimum_applied", f"The minimum charge added {format_cents(totals['minimum_charge_adjustment_cents'])}"
            " to reach the job minimum.")
    margin = Decimal(str(totals.get("margin_pct", "0")))
    if lines and margin < MARGIN_FLOOR:
        add("warning", "low_margin", f"Margin before tax is {(margin * 100).quantize(Decimal('0.1'))}%, under the "
            f"{int(MARGIN_FLOOR * 100)}% floor. Check overhead and profit in your markups.",
            margin_pct=str(margin))
    for sec in est["sections"]:
        mod = reg.modules.get(sec["module_id"])
        for note in (mod.notes if mod else ()):
            add("info", "module_note", f"{mod.name}: {note}", module_id=mod.id)
    counts = {lvl: sum(1 for f in findings if f["level"] == lvl) for lvl in ("error", "warning", "info")}
    return {"ok": True, "estimate_id": est["id"], "total_cents": totals.get("total_cents", 0),
            "total": format_cents(totals.get("total_cents", 0)), "passed": counts["error"] == 0,
            "errors": counts["error"], "warnings": counts["warning"], "infos": counts["info"], "findings": findings}
