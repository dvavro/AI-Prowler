"""Per-trade sheet activation for takeoff.

A plan set usually has sheets only some trades care about: the NSB shed slab
set has two elevations, a foundation plan and a rafter detail, and only the
foundation plan matters for concrete. Switching a sheet off for a trade keeps
that trade's takeoff (and its agent) away from it; the sheet stays openable
and measurable by hand.

Storage is the sheet_trade_active table (migration v21). NO row means active,
so existing users see no change until they toggle something: a row with
active=0 is the only thing that switches a sheet off for a trade.
"""
from __future__ import annotations

from datetime import datetime, timezone

from estimator.context import RequestContext
from estimator.drawing_model import store
from estimator.errors import InvalidInput, PermissionDenied
from estimator.estimating import service

EDIT_ROLES = service.EDIT_ROLES                      # owner, estimator: switching sheets on and off


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _role(ctx: RequestContext, roles, what: str) -> None:
    if ctx.role not in roles:
        raise PermissionDenied(f"only {', '.join(roles)} can {what}", role=ctx.role)


def _check_module(module_id) -> str:
    """A known trade's id, or InvalidInput (400) naming what is available."""
    from estimator.modules import get_registry
    module_id = str(module_id or "").strip()
    if not module_id:
        raise InvalidInput("pick a trade (module_id)")
    reg = get_registry()
    if module_id not in reg.modules:
        raise InvalidInput(f"no trade named '{module_id}'", module_id=module_id,
                           available=sorted(reg.modules))
    return module_id


def is_active(conn, company_id: str, sheet_id: int, module_id: str) -> bool:
    """True when the sheet counts for the trade: no row, or a row with active=1."""
    row = conn.execute(
        "SELECT active FROM sheet_trade_active WHERE company_id = ? AND sheet_id = ? AND module_id = ?",
        (company_id, int(sheet_id), module_id)).fetchone()
    return True if row is None else bool(row[0])


def inactive_for_sheet(conn, company_id: str, sheet_id: int) -> list[str]:
    """The trades this sheet is switched off for, by id."""
    return [r[0] for r in conn.execute(
        "SELECT module_id FROM sheet_trade_active"
        " WHERE company_id = ? AND sheet_id = ? AND active = 0 ORDER BY module_id",
        (company_id, int(sheet_id)))]


def list_for_plan_set(conn, company_id: str, plan_set_id: int, module_id: str) -> list[dict]:
    """Every sheet of a plan set with its active state for one trade, in page order."""
    module_id = _check_module(module_id)
    out = []
    for s in conn.execute(
            "SELECT s.id, COALESCE(a.active, 1) AS active FROM sheets s"
            " LEFT JOIN sheet_trade_active a ON a.company_id = s.company_id AND a.sheet_id = s.id"
            " AND a.module_id = ?"
            " WHERE s.plan_set_id = ? AND s.company_id = ? ORDER BY s.page_no",
            (module_id, int(plan_set_id), company_id)):
        out.append({"sheet_id": s["id"], "active": bool(s["active"])})
    return out


def set_active(conn, ctx: RequestContext, sheet_id: int, module_id, active: bool) -> dict:
    """Switch a sheet on or off for one trade (owner, estimator). Upserts the row."""
    _role(ctx, EDIT_ROLES, "switch sheets on or off for a trade")
    module_id = _check_module(module_id)
    sheet = store._load_sheet(conn, ctx, sheet_id)          # not found / another company's sheet
    on = 1 if active else 0
    conn.execute(
        "INSERT INTO sheet_trade_active (company_id, sheet_id, module_id, active, updated_by, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?)"
        " ON CONFLICT (company_id, sheet_id, module_id) DO UPDATE SET active = excluded.active,"
        " updated_by = excluded.updated_by, updated_at = excluded.updated_at",
        (ctx.company_id, sheet["id"], module_id, on, ctx.actor, _now()))
    return {"ok": True, "sheet_id": sheet["id"], "module_id": module_id, "active": bool(on)}
