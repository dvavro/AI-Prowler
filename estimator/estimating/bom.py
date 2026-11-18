"""The Bill of Materials: what to order for each construction trade.

(2026-11-18, David): every construction trade on an estimate gets a
shopping list - its material lines, aggregated by price book item, with
the quantity to order (waste included), the supplier from the price
book, and a checklist of what is ordered already. Service trades have
no materials to order, and the "Other lines" section holds hand-entered
lines, so neither gets a list.

The ordered flags live in bom_ordered, keyed on section + item (not
line id), so they survive a re-price: pricing a trade again deletes
its lines and makes new ones, but the items stay the same.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_HALF_UP

from estimator.context import RequestContext
from estimator.errors import NotFound
from estimator.estimating import service
from estimator.modules import get_registry


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _dec(value) -> Decimal:
    """A stored TEXT decimal as a Decimal (0 when it doesn't parse - a stored quantity always should)."""
    try:
        return Decimal(str(value).strip() or "0")
    except InvalidOperation:
        return Decimal("0")


def _order_qty(qty: Decimal, unit: str) -> str:
    """The quantity to order, rounded for buying: whole numbers (rounded up) for 'ea', 2 decimals otherwise."""
    if unit == "ea":
        return str(qty.quantize(Decimal("1"), rounding=ROUND_CEILING))
    return str(qty.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def _is_construction(module_id: str) -> bool:
    """True when the module is a construction trade ('custom' and unknown modules are not)."""
    if module_id == "custom":
        return False
    try:
        return get_registry().get(module_id).category == "construction"
    except Exception:  # noqa: BLE001 - an unknown module has no list
        return False


def _supplier(conn, company_id: str, price_key: str | None) -> str | None:
    """The supplier on the price book's latest price for the key (None when unset or no key)."""
    if not price_key:
        return None
    row = conn.execute(
        "SELECT supplier FROM price_book WHERE company_id = ? AND price_key = ? AND effective_date <= ?"
        " ORDER BY effective_date DESC, id DESC LIMIT 1",
        (company_id, price_key, date.today().isoformat()),
    ).fetchone()
    if row is None or not row["supplier"]:
        return None
    return row["supplier"]


def bom_for_section(conn, company_id: str, section_id: int) -> list[dict]:
    """One trade section's bill of materials: its material lines, aggregated by price book item.

    Only construction trades have one (services and 'custom' return []).
    Lines sharing a price key and unit are one row; hand lines (no price
    key) group by description and unit under item_key 'hand:<description>'.
    The order quantity adds each line's waste before rounding, so lines
    with different waste still order the right amount.
    """
    sec = conn.execute(
        "SELECT s.id, s.estimate_id, s.module_id FROM trade_sections s"
        " JOIN estimates e ON e.id = s.estimate_id WHERE s.id = ? AND e.company_id = ?",
        (section_id, company_id),
    ).fetchone()
    if sec is None:
        raise NotFound(f"no section {section_id}", section_id=section_id)
    if not _is_construction(sec["module_id"]):
        return []
    ordered = {r["item_key"] for r in conn.execute(
        "SELECT item_key FROM bom_ordered WHERE company_id = ? AND estimate_id = ? AND section_id = ?",
        (company_id, sec["estimate_id"], section_id))}
    groups: dict[tuple, dict] = {}
    order: list[tuple] = []
    for ln in conn.execute(
            "SELECT * FROM line_items WHERE trade_section_id = ? AND kind = 'material' ORDER BY sort_order, id",
            (section_id,)):
        if ln["price_key"]:
            key = ("key", ln["price_key"], ln["unit"])
            item_key = ln["price_key"]
        else:
            key = ("hand", ln["description"], ln["unit"])
            item_key = "hand:" + ln["description"]
        group = groups.get(key)
        qty = _dec(ln["quantity"])
        if group is None:
            group = {"item_key": item_key, "price_key": ln["price_key"],
                     "description": ln["description"], "quantity": Decimal("0"),
                     "order_quantity": Decimal("0"), "unit": ln["unit"],
                     "unit_cost_cents": int(ln["unit_cost_cents"]), "line_ids": []}
            groups[key] = group
            order.append(key)
        group["quantity"] += qty
        group["order_quantity"] += qty * (Decimal("1") + _dec(ln["waste_pct"]))
        group["line_ids"].append(int(ln["id"]))
    out = []
    for key in order:
        g = groups[key]
        out.append({
            "item_key": g["item_key"], "price_key": g["price_key"], "description": g["description"],
            "quantity": service.qty_text(g["quantity"]),
            "order_quantity": _order_qty(g["order_quantity"], g["unit"]),
            "unit": g["unit"], "unit_cost_cents": g["unit_cost_cents"],
            "supplier": _supplier(conn, company_id, g["price_key"]),
            "line_ids": g["line_ids"], "ordered": g["item_key"] in ordered,
        })
    return out


def bom_for_estimate(conn, company_id: str, estimate_id: int) -> list[dict]:
    """Every construction section's bill of materials: [{module_id, section_id, items}].

    Construction sections with no material lines are included with an empty
    items list (the UI filters); service and 'custom' sections are not listed.
    """
    row = conn.execute("SELECT id FROM estimates WHERE id = ? AND company_id = ?",
                       (estimate_id, company_id)).fetchone()
    if row is None:
        raise NotFound(f"estimate {estimate_id} not found", estimate_id=estimate_id)
    out = []
    for s in conn.execute("SELECT id, module_id FROM trade_sections WHERE estimate_id = ? ORDER BY sort_order, id",
                          (estimate_id,)):
        if not _is_construction(s["module_id"]):
            continue
        out.append({"module_id": s["module_id"], "section_id": int(s["id"]),
                    "items": bom_for_section(conn, company_id, int(s["id"]))})
    return out


def set_ordered(conn, ctx: RequestContext, estimate_id: int, section_id: int, item_key: str,
                ordered: bool) -> dict:
    """Tick (or untick) one BOM item as ordered. A checklist toggle: no rev, no ask-first.

    The flag is keyed on the item, not the line, so it survives a re-price.
    Ordering happens after approval, so the estimate need not be editable.
    """
    est = service.get_estimate(conn, ctx, estimate_id)
    if not any(s["id"] == section_id for s in est["sections"]):
        raise NotFound(f"estimate {estimate_id} has no section {section_id}",
                       estimate_id=estimate_id, section_id=section_id)
    if not any(i["item_key"] == item_key for i in bom_for_section(conn, ctx.company_id, section_id)):
        raise NotFound(f"no bill-of-materials item '{item_key}' in section {section_id}",
                       item_key=item_key, section_id=section_id)
    with service.transaction(conn):
        if ordered:
            conn.execute("INSERT OR IGNORE INTO bom_ordered"
                         " (company_id, estimate_id, section_id, item_key, ordered_by, ordered_at)"
                         " VALUES (?,?,?,?,?,?)",
                         (ctx.company_id, estimate_id, section_id, item_key, ctx.actor, _now()))
        else:
            conn.execute("DELETE FROM bom_ordered WHERE company_id = ? AND estimate_id = ?"
                         " AND section_id = ? AND item_key = ?",
                         (ctx.company_id, estimate_id, section_id, item_key))
    return {"ordered": bool(ordered), "section_id": section_id, "item_key": item_key}
