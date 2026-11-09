"""Estimate service layer.

Rules every write follows:
- Company scoping: an estimate from another company is reported as not found.
- Roles: owner and estimator can change estimates; reviewer, office and field can read.
- Optimistic concurrency: the caller passes the `rev` it last read. If the
  estimate has changed since (another user, chat or agent), StaleRevision is
  raised and nothing is written. Every write bumps `rev`.
- Finalized lock: approved, sent, won, lost, expired and archived estimates
  can't be edited; a change needs a new revision (later sprint).
- Every write is logged to estimate_events with the actor (user or agent).
- Totals are recalculated in the same transaction as the change, so stored
  totals always match the line items.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from estimator.context import RequestContext
from estimator.core.units.units import UnitError, normalize_unit
from estimator.errors import InvalidInput, NotEditable, NotFound, PermissionDenied, StaleRevision
from estimator.pricing.price_book import get_price
from estimator.pricing.stack import LINE_KINDS, LineInput, Markups, PricingError, price_estimate

EDITABLE_STATUSES = ("draft", "in_review")
STATUSES = ("draft", "in_review", "approved", "sent", "won", "lost", "expired", "archived")
EDIT_ROLES = ("owner", "estimator")
QUICK_ROLES = ("owner", "estimator", "office", "field")   # spec: office and field staff give quick quotes
APPROVE_ROLES = ("owner", "estimator", "reviewer")
CUSTOM_MODULE = "custom"


def qty_text(d: Decimal) -> str:
    """Plain decimal text without exponents or trailing zeros: 1000, 3.7825, 0.5."""
    t = format(d.normalize(), "f")
    return t if "." not in t else t.rstrip("0").rstrip(".") or "0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def transaction(conn: sqlite3.Connection):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def _require_edit_role(ctx: RequestContext, roles=EDIT_ROLES) -> None:
    if ctx.role not in roles:
        raise PermissionDenied(f"role '{ctx.role}' can't change estimates", role=ctx.role)


def _dec(value, name: str) -> Decimal:
    if isinstance(value, float):
        value = repr(value)
    if isinstance(value, bool):
        raise InvalidInput(f"{name} must be a number")
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise InvalidInput(f"{name} must be a number", field=name) from None
    if not d.is_finite():
        raise InvalidInput(f"{name} must be a finite number", field=name)
    return d


def _log(conn, ctx: RequestContext, estimate_id: int | None, action: str, after: dict | None = None,
         before: dict | None = None) -> None:
    conn.execute(
        "INSERT INTO estimate_events (company_id, estimate_id, actor, on_behalf_of, action, before_json,"
        " after_json, at) VALUES (?,?,?,?,?,?,?,?)",
        (ctx.company_id, estimate_id, ctx.actor, ctx.user_id if ctx.agent else None, action,
         json.dumps(before, default=str) if before is not None else None,
         json.dumps(after, default=str) if after is not None else None, _now()),
    )


def _load_row(conn, ctx: RequestContext, estimate_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM estimates WHERE id = ? AND company_id = ?",
                       (estimate_id, ctx.company_id)).fetchone()
    if row is None:
        raise NotFound(f"estimate {estimate_id} not found", estimate_id=estimate_id)
    return row


def _check_writable(conn, ctx: RequestContext, estimate_id: int, rev: int, roles=EDIT_ROLES) -> sqlite3.Row:
    _require_edit_role(ctx, roles)
    row = _load_row(conn, ctx, estimate_id)
    if row["status"] not in EDITABLE_STATUSES:
        raise NotEditable(f"estimate {estimate_id} is {row['status']} and can't be changed",
                          estimate_id=estimate_id, status=row["status"])
    if rev is None or int(rev) != int(row["rev"]):
        raise StaleRevision(
            f"estimate {estimate_id} changed since you read it (you have rev {rev}, current is {row['rev']});"
            " read it again and retry", estimate_id=estimate_id, current_rev=int(row["rev"]))
    return row


def _bump(conn, ctx: RequestContext, estimate_id: int) -> None:
    conn.execute("UPDATE estimates SET rev = rev + 1, updated_by = ?, updated_at = ? WHERE id = ?",
                 (ctx.actor, _now(), estimate_id))


# ---------------------------------------------------------------- markups

def company_markups(conn, company_id: str) -> tuple[Markups, dict]:
    """The company's markups and estimate-level settings (zero markups if none saved yet)."""
    row = conn.execute("SELECT * FROM markups WHERE company_id = ?", (company_id,)).fetchone()
    if row is None:
        return Markups(), {"round_to_cents": None, "rounding_mode": "half_up", "minimum_charge_cents": None}
    kinds = tuple(k for k in (row["taxable_kinds"] or "").split(",") if k)
    m = Markups(Decimal(row["overhead_pct"]), Decimal(row["profit_pct"]), Decimal(row["labor_burden_pct"]),
                Decimal(row["tax_pct"]), kinds, row["tax_base"])
    return m, {"round_to_cents": row["round_to_cents"], "rounding_mode": row["rounding_mode"],
               "minimum_charge_cents": row["minimum_charge_cents"]}


def save_markups(conn, ctx: RequestContext, *, overhead_pct="0", profit_pct="0", labor_burden_pct="0",
                 tax_pct="0", taxable_kinds=("material",), tax_base="cost", round_to_cents=None,
                 rounding_mode="half_up", minimum_charge_cents=None) -> dict:
    _require_edit_role(ctx)
    try:
        m = Markups(Decimal(str(overhead_pct)), Decimal(str(profit_pct)), Decimal(str(labor_burden_pct)),
                    Decimal(str(tax_pct)), tuple(taxable_kinds), tax_base)
    except (PricingError, InvalidOperation) as exc:
        raise InvalidInput(str(exc)) from None
    with transaction(conn):
        conn.execute(
            "INSERT INTO markups (company_id, overhead_pct, profit_pct, labor_burden_pct, tax_pct, taxable_kinds,"
            " tax_base, round_to_cents, rounding_mode, minimum_charge_cents, updated_by, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (company_id) DO UPDATE SET"
            " overhead_pct = excluded.overhead_pct, profit_pct = excluded.profit_pct,"
            " labor_burden_pct = excluded.labor_burden_pct, tax_pct = excluded.tax_pct,"
            " taxable_kinds = excluded.taxable_kinds, tax_base = excluded.tax_base,"
            " round_to_cents = excluded.round_to_cents, rounding_mode = excluded.rounding_mode,"
            " minimum_charge_cents = excluded.minimum_charge_cents, updated_by = excluded.updated_by,"
            " updated_at = excluded.updated_at",
            (ctx.company_id, str(m.overhead_pct), str(m.profit_pct), str(m.labor_burden_pct), str(m.tax_pct),
             ",".join(m.taxable_kinds), m.tax_base, round_to_cents, rounding_mode, minimum_charge_cents,
             ctx.actor, _now()),
        )
        _log(conn, ctx, None, "markups_saved", {"overhead_pct": str(m.overhead_pct), "profit_pct": str(m.profit_pct)})
    return {"ok": True}


# ---------------------------------------------------------------- estimates

def create_estimate(conn, ctx: RequestContext, title: str = "", *, customer_id: str | None = None,
                    job_id: str | None = None, address: str | None = None, due_date: str | None = None) -> dict:
    _require_edit_role(ctx, QUICK_ROLES)
    now = _now()
    with transaction(conn):
        cur = conn.execute(
            "INSERT INTO estimates (company_id, customer_id, job_id, address, title, due_date, assigned_to,"
            " created_by, created_at, updated_by, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (ctx.company_id, customer_id, job_id, address, title or "", due_date, ctx.user_id, ctx.actor, now,
             ctx.actor, now),
        )
        eid = cur.lastrowid
        _log(conn, ctx, eid, "estimate_created", {"title": title, "customer_id": customer_id})
    return get_estimate(conn, ctx, eid)


def _section_id(conn, ctx: RequestContext, estimate_id: int, module_id: str, module_version: str | None = None,
                create: bool = True) -> int | None:
    row = conn.execute("SELECT id FROM trade_sections WHERE estimate_id = ? AND module_id = ?",
                       (estimate_id, module_id)).fetchone()
    if row:
        return int(row["id"])
    if not create:
        return None
    order = conn.execute("SELECT COALESCE(MAX(sort_order), -1) + 1 FROM trade_sections WHERE estimate_id = ?",
                         (estimate_id,)).fetchone()[0]
    cur = conn.execute(
        "INSERT INTO trade_sections (estimate_id, module_id, module_version, sort_order, created_by, created_at)"
        " VALUES (?,?,?,?,?,?)", (estimate_id, module_id, module_version, order, ctx.actor, _now()))
    return int(cur.lastrowid)


def add_trade(conn, ctx: RequestContext, estimate_id: int, module_id: str, rev: int, registry=None) -> dict:
    """Add a trade section for a module (or 'custom' for hand-entered lines)."""
    version = None
    if module_id != CUSTOM_MODULE:
        from estimator.modules import get_registry
        version = (registry or get_registry()).get(module_id).version
    with transaction(conn):
        _check_writable(conn, ctx, estimate_id, rev)
        if _section_id(conn, ctx, estimate_id, module_id, create=False) is not None:
            raise InvalidInput(f"estimate {estimate_id} already has a '{module_id}' section", module_id=module_id)
        _section_id(conn, ctx, estimate_id, module_id, version)
        _log(conn, ctx, estimate_id, "trade_added", {"module_id": module_id})
        _recalculate(conn, ctx, estimate_id)
        _bump(conn, ctx, estimate_id)
    return get_estimate(conn, ctx, estimate_id)


def _insert_line(conn, ctx, section_id: int, *, kind: str, description: str, quantity: Decimal, unit: str,
                 unit_cost_cents: int, waste_pct: Decimal = Decimal(0), price_key: str | None = None,
                 sort_order: int | None = None, calc: dict | None = None) -> int:
    if sort_order is None:
        sort_order = conn.execute(
            "SELECT COALESCE(MAX(sort_order), -1) + 1 FROM line_items WHERE trade_section_id = ?",
            (section_id,)).fetchone()[0]
    now = _now()
    cur = conn.execute(
        "INSERT INTO line_items (trade_section_id, kind, description, quantity, unit, unit_cost_cents, waste_pct,"
        " price_key, calc_json, sort_order, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (section_id, kind, description, qty_text(quantity), unit, unit_cost_cents, str(waste_pct), price_key,
         json.dumps(calc) if calc else None, sort_order, ctx.actor, now, now),
    )
    return int(cur.lastrowid)


def add_line_item(conn, ctx: RequestContext, estimate_id: int, rev: int, *, kind: str, description: str,
                  quantity, unit: str, unit_cost_cents: int | None = None, price_key: str | None = None,
                  waste_pct="0", module_id: str = CUSTOM_MODULE) -> dict:
    """Add a hand-entered line. Give unit_cost_cents, or a price_key from the company price book."""
    if kind not in LINE_KINDS:
        raise InvalidInput(f"kind must be one of {LINE_KINDS}", field="kind")
    q = _dec(quantity, "quantity")
    if q < 0:
        raise InvalidInput("quantity can't be negative", field="quantity")
    w = _dec(waste_pct, "waste_pct")
    if w < 0 or w > 1:
        raise InvalidInput("waste_pct is a fraction between 0 and 1 (0.10 = 10%)", field="waste_pct")
    try:
        unit = normalize_unit(unit)
    except UnitError as exc:
        raise InvalidInput(str(exc), field="unit") from None
    warnings = []
    with transaction(conn):
        _check_writable(conn, ctx, estimate_id, rev)
        if unit_cost_cents is None:
            if not price_key:
                raise InvalidInput("give unit_cost_cents or a price_key", field="unit_cost_cents")
            price = get_price(conn, ctx.company_id, price_key)
            if price is None:
                raise NotFound(f"no price '{price_key}' in the price book", price_key=price_key)
            if price.unit != unit:
                raise InvalidInput(f"price '{price_key}' is per {price.unit}, not per {unit}", field="unit")
            unit_cost_cents = price.cost_cents
            if price.is_sample:
                warnings.append(f"'{price_key}' is a sample price; set your own in the price book")
        if isinstance(unit_cost_cents, bool) or not isinstance(unit_cost_cents, int) or unit_cost_cents < 0:
            raise InvalidInput("unit_cost_cents must be non-negative integer cents", field="unit_cost_cents")
        sid = _section_id(conn, ctx, estimate_id, module_id)
        lid = _insert_line(conn, ctx, sid, kind=kind, description=description, quantity=q, unit=unit,
                           unit_cost_cents=unit_cost_cents, waste_pct=w, price_key=price_key)
        _log(conn, ctx, estimate_id, "line_added", {"line_id": lid, "description": description,
                                                     "quantity": qty_text(q), "unit": unit,
                                                     "unit_cost_cents": unit_cost_cents})
        _recalculate(conn, ctx, estimate_id)
        _bump(conn, ctx, estimate_id)
    result = get_estimate(conn, ctx, estimate_id)
    result["warnings"] = warnings
    return result


def _estimate_minimum(conn, estimate_id: int, company_min: int | None, registry=None) -> int | None:
    mods = [r["module_id"] for r in conn.execute(
        "SELECT module_id FROM trade_sections WHERE estimate_id = ?", (estimate_id,))]
    values = [company_min] if company_min is not None else []
    if any(m != CUSTOM_MODULE for m in mods):
        from estimator.modules import get_registry
        reg = registry or get_registry()
        for m in mods:
            if m in reg.modules and reg.modules[m].minimum_charge_cents is not None:
                values.append(reg.modules[m].minimum_charge_cents)
    return max(values) if values else None


def _recalculate(conn, ctx: RequestContext, estimate_id: int, registry=None) -> dict:
    rows = conn.execute(
        "SELECT li.* FROM line_items li JOIN trade_sections ts ON ts.id = li.trade_section_id"
        " WHERE ts.estimate_id = ? ORDER BY ts.sort_order, li.sort_order, li.id", (estimate_id,)).fetchall()
    markups, settings = company_markups(conn, ctx.company_id)
    items = [LineInput(r["kind"], Decimal(r["quantity"]), r["unit"], int(r["unit_cost_cents"]),
                       Decimal(r["waste_pct"]), r["description"], str(r["id"])) for r in rows]
    totals = price_estimate(items, markups, settings["round_to_cents"], settings["rounding_mode"],
                            _estimate_minimum(conn, estimate_id, settings["minimum_charge_cents"], registry))
    for r, lp in zip(rows, totals.lines):
        calc = json.loads(r["calc_json"]) if r["calc_json"] else {}
        calc["price"] = lp.as_dict()
        conn.execute("UPDATE line_items SET calc_json = ?, total_cents = ? WHERE id = ?",
                     (json.dumps(calc), lp.total_cents, r["id"]))
    summary = totals.as_dict()
    summary.pop("lines")
    conn.execute("UPDATE estimates SET totals_json = ? WHERE id = ?", (json.dumps(summary), estimate_id))
    return summary


def calculate(conn, ctx: RequestContext, estimate_id: int, rev: int) -> dict:
    """Re-run the pricing stack (e.g. after markups or prices changed)."""
    with transaction(conn):
        _check_writable(conn, ctx, estimate_id, rev)
        summary = _recalculate(conn, ctx, estimate_id)
        _log(conn, ctx, estimate_id, "calculated", {"total_cents": summary["total_cents"]})
        _bump(conn, ctx, estimate_id)
    return get_estimate(conn, ctx, estimate_id)


def set_status(conn, ctx: RequestContext, estimate_id: int, rev: int, status: str, roles=EDIT_ROLES) -> dict:
    """Move an estimate between statuses. Finalized estimates can only move on to won/lost/expired/archived."""
    if status not in STATUSES:
        raise InvalidInput(f"status must be one of {STATUSES}", field="status")
    _require_edit_role(ctx, roles)
    with transaction(conn):
        row = _load_row(conn, ctx, estimate_id)
        if int(rev) != int(row["rev"]):
            raise StaleRevision(f"estimate {estimate_id} changed since you read it", estimate_id=estimate_id,
                                current_rev=int(row["rev"]))
        if row["status"] not in EDITABLE_STATUSES and status in EDITABLE_STATUSES:
            raise NotEditable(f"estimate {estimate_id} is {row['status']}; make a new revision to edit it",
                              estimate_id=estimate_id, status=row["status"])
        conn.execute("UPDATE estimates SET status = ? WHERE id = ?", (status, estimate_id))
        _log(conn, ctx, estimate_id, "status_changed", {"status": status}, {"status": row["status"]})
        _bump(conn, ctx, estimate_id)
    return get_estimate(conn, ctx, estimate_id)


def get_estimate(conn, ctx: RequestContext, estimate_id: int) -> dict:
    row = _load_row(conn, ctx, estimate_id)
    sections = []
    for s in conn.execute("SELECT * FROM trade_sections WHERE estimate_id = ? ORDER BY sort_order, id",
                          (estimate_id,)):
        lines = []
        for li in conn.execute("SELECT * FROM line_items WHERE trade_section_id = ? ORDER BY sort_order, id",
                               (s["id"],)):
            calc = json.loads(li["calc_json"]) if li["calc_json"] else {}
            lines.append({
                "id": li["id"], "kind": li["kind"], "description": li["description"], "quantity": li["quantity"],
                "unit": li["unit"], "unit_cost_cents": li["unit_cost_cents"], "waste_pct": li["waste_pct"],
                "price_key": li["price_key"], "total_cents": li["total_cents"], "calc": calc,
                "assembly_use_id": li["assembly_use_id"],
                "override": ({"by": li["override_by"], "reason": li["override_reason"], "at": li["override_at"],
                              "changed": (calc.get("override") or {}).get("changed", {})}
                             if li["override_by"] else None),
            })
        sections.append({
            "id": s["id"], "module_id": s["module_id"], "module_version": s["module_version"],
            "answers": json.loads(s["params_json"]) if s["params_json"] else None,
            "subtotal_cents": sum(ln["total_cents"] or 0 for ln in lines), "lines": lines,
        })
    return {
        "ok": True, "id": row["id"], "title": row["title"], "status": row["status"], "rev": row["rev"],
        "revision": row["revision"], "parent_estimate_id": row["parent_estimate_id"],
        "change_summary": row["change_summary"], "customer_id": row["customer_id"], "job_id": row["job_id"],
        "address": row["address"], "due_date": row["due_date"], "assigned_to": row["assigned_to"],
        "created_by": row["created_by"], "created_at": row["created_at"], "updated_by": row["updated_by"],
        "updated_at": row["updated_at"],
        "totals": json.loads(row["totals_json"]) if row["totals_json"] else None,
        "sections": sections,
        "practice": bool(row["is_practice"]) if "is_practice" in row.keys() else False,
        **_editing(row, ctx),
    }


def _editing(row, ctx: RequestContext) -> dict:
    from estimator.team import editing_warning
    msg = editing_warning(row, ctx)
    return {"editing_warning": msg} if msg else {}


def list_estimates(conn, ctx: RequestContext, status: str | None = None, limit: int = 50) -> dict:
    if status is not None and status not in STATUSES:
        raise InvalidInput(f"status must be one of {STATUSES}", field="status")
    limit = max(1, min(int(limit), 500))
    sql = ("SELECT id, title, status, rev, customer_id, totals_json, updated_at, is_practice, assigned_to FROM estimates"
           " WHERE company_id = ?")
    args: list = [ctx.company_id]
    if status:
        sql += " AND status = ?"
        args.append(status)
    sql += " ORDER BY updated_at DESC, id DESC LIMIT ?"
    args.append(limit)
    items = []
    for r in conn.execute(sql, args):
        totals = json.loads(r["totals_json"]) if r["totals_json"] else {}
        items.append({"id": r["id"], "title": r["title"], "status": r["status"], "rev": r["rev"],
                      "customer_id": r["customer_id"], "total_cents": totals.get("total_cents", 0),
                      "updated_at": r["updated_at"], "assigned_to": r["assigned_to"],
                      **({"practice": True} if r["is_practice"] else {})})
    return {"ok": True, "count": len(items), "estimates": items}


def events(conn, ctx: RequestContext, estimate_id: int) -> list[dict]:
    _load_row(conn, ctx, estimate_id)
    return [dict(r) for r in conn.execute(
        "SELECT actor, on_behalf_of, action, after_json, at FROM estimate_events WHERE estimate_id = ?"
        " ORDER BY id", (estimate_id,))]


def remove_trade(conn, ctx: RequestContext, estimate_id: int, module_id: str, rev: int) -> dict:
    """Take a trade section (and its lines and saved options) off an editable estimate."""
    with transaction(conn):
        _check_writable(conn, ctx, estimate_id, rev, QUICK_ROLES)
        sid = _section_id(conn, ctx, estimate_id, module_id, create=False)
        if sid is None:
            raise NotFound(f"the estimate has no '{module_id}' section", module_id=module_id)
        conn.execute("DELETE FROM line_items WHERE trade_section_id = ?", (sid,))
        conn.execute("DELETE FROM trade_sections WHERE id = ?", (sid,))
        conn.execute("DELETE FROM estimate_scenarios WHERE estimate_id = ? AND module_id = ?", (estimate_id, module_id))
        _log(conn, ctx, estimate_id, "trade_removed", {"module_id": module_id})
        _recalculate(conn, ctx, estimate_id)
        _bump(conn, ctx, estimate_id)
    return get_estimate(conn, ctx, estimate_id)


REVISABLE_STATUSES = ("approved", "sent", "lost", "expired")


def create_revision(conn, ctx: RequestContext, estimate_id: int, change_summary: str) -> dict:
    """Copy a finalized estimate into a new editable draft (v2, v3…). The original stays as it was;
    its unsent or open bids are voided so only the new version can be sent or accepted."""
    _require_edit_role(ctx, QUICK_ROLES)
    if not (change_summary or "").strip():
        raise InvalidInput("say what's changing (change_summary), e.g. 'customer added the back patio'",
                           field="change_summary")
    src = _load_row(conn, ctx, int(estimate_id))
    if src["status"] in EDITABLE_STATUSES:
        raise InvalidInput(f"estimate {src['id']} is still {src['status']}; edit it directly, no revision needed",
                           estimate_id=src["id"], status=src["status"])
    if src["status"] not in REVISABLE_STATUSES:
        raise NotEditable(f"estimate {src['id']} is {src['status']} and can't be revised", estimate_id=src["id"],
                          status=src["status"])
    child = conn.execute("SELECT id FROM estimates WHERE parent_estimate_id = ? AND company_id = ?",
                         (src["id"], ctx.company_id)).fetchone()
    if child:
        raise InvalidInput(f"estimate {src['id']} already has a newer revision ({child['id']}); revise that one",
                           estimate_id=src["id"], newer_estimate_id=child["id"])
    now = _now()
    with transaction(conn):
        cur = conn.execute(
            "INSERT INTO estimates (company_id, customer_id, job_id, address, title, revision, parent_estimate_id,"
            " change_summary, due_date, assigned_to, created_by, created_at, updated_by, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ctx.company_id, src["customer_id"], src["job_id"], src["address"], src["title"], src["revision"] + 1,
             src["id"], change_summary.strip(), src["due_date"], src["assigned_to"], ctx.actor, now, ctx.actor, now))
        new_id = cur.lastrowid
        for sec in conn.execute("SELECT * FROM trade_sections WHERE estimate_id = ? ORDER BY sort_order, id",
                                (src["id"],)).fetchall():
            sc = conn.execute(
                "INSERT INTO trade_sections (estimate_id, module_id, module_version, params_json, sort_order,"
                " created_by, created_at) VALUES (?,?,?,?,?,?,?)",
                (new_id, sec["module_id"], sec["module_version"], sec["params_json"], sec["sort_order"], ctx.actor, now))
            for li in conn.execute("SELECT * FROM line_items WHERE trade_section_id = ? ORDER BY sort_order, id",
                                   (sec["id"],)).fetchall():
                conn.execute(
                    "INSERT INTO line_items (trade_section_id, kind, description, quantity, unit, unit_cost_cents,"
                    " waste_pct, price_key, calc_json, sort_order, created_by, created_at, updated_at, override_by,"
                    " override_reason, override_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (sc.lastrowid, li["kind"], li["description"], li["quantity"], li["unit"], li["unit_cost_cents"],
                     li["waste_pct"], li["price_key"], li["calc_json"], li["sort_order"], ctx.actor, now, now,
                     li["override_by"], li["override_reason"], li["override_at"]))   # hand changes go with it
        conn.execute(
            "INSERT INTO estimate_scenarios (company_id, estimate_id, module_id, option_id, label, answers_json,"
            " total_cents, totals_json, uses_samples, chosen, created_by, created_at) SELECT company_id, ?, module_id,"
            " option_id, label, answers_json, total_cents, totals_json, uses_samples, chosen, ?, ? FROM"
            " estimate_scenarios WHERE estimate_id = ?", (new_id, ctx.actor, now, src["id"]))
        voided = [r["number"] for r in conn.execute(
            "SELECT number FROM bids WHERE estimate_id = ? AND status IN ('draft', 'sent', 'viewed')", (src["id"],))]
        conn.execute("UPDATE bids SET status = 'void', rev = rev + 1, updated_by = ?, updated_at = ?"
                     " WHERE estimate_id = ? AND status IN ('draft', 'sent', 'viewed')", (ctx.actor, now, src["id"]))
        _recalculate(conn, ctx, new_id)
        _log(conn, ctx, src["id"], "revision_created", {"new_estimate_id": new_id, "voided_bids": voided})
        _log(conn, ctx, new_id, "estimate_created", {"revision_of": src["id"], "change_summary": change_summary})
    out = get_estimate(conn, ctx, new_id)
    out["revision_of"] = src["id"]
    out["voided_bids"] = voided
    return out
