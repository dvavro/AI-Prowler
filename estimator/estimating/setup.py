"""Setup wizard backend (first run).

Steps can be done in any order, skipped, and resumed. Some steps change real
settings (company profile, tax, markups, prices); the rest record what was
chosen so the Estimator tab and the hub checklist can show progress.
Sending a first real bid should wait until sample prices have been reviewed.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from estimator.context import RequestContext
from estimator.core.units.money import cents_from_decimal
from estimator.errors import InvalidInput, NotFound, PermissionDenied
from estimator.estimating import service
from estimator.pricing.price_book import get_price, set_price

STEPS = (
    ("company_profile", "Company profile (name, address, phone, license)"),
    ("services", "Services and trades you offer"),
    ("tax", "Sales tax"),
    ("labor_rates", "Labor rates"),
    ("markups", "Overhead, profit and minimum charge"),
    ("price_book_review", "Review sample prices and set your own"),
    ("bid_template", "Bid template and terms"),
    ("team_approvals", "Team and approvals (who can estimate, review, approve and send)"),
    ("ai_check", "AI connection check"),
    ("sample_quote", "Try a sample quote"),
)
STEP_IDS = tuple(s for s, _ in STEPS)
SETUP_ROLES = ("owner",)
PROFILE_FIELDS = ("name", "address", "phone", "license_no", "logo_path")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def current_sample_keys(conn, company_id: str) -> list[str]:
    """Price keys whose current price is still a sample."""
    keys = [r[0] for r in conn.execute("SELECT DISTINCT price_key FROM price_book WHERE company_id = ?", (company_id,))]
    return sorted(k for k in keys if (p := get_price(conn, company_id, k)) is not None and p.is_sample)


def setup_status(conn, ctx: RequestContext) -> dict:
    rows = {r["step"]: r for r in conn.execute("SELECT * FROM setup_progress WHERE company_id = ?",
                                               (ctx.company_id,))}
    steps = []
    for sid, label in STEPS:
        r = rows.get(sid)
        steps.append({"step": sid, "label": label, "status": r["status"] if r else "not_started",
                      "updated_by": r["updated_by"] if r else None, "updated_at": r["updated_at"] if r else None})
    samples = len(current_sample_keys(conn, ctx.company_id))
    done = sum(1 for s in steps if s["status"] == "done")
    nxt = next((s["step"] for s in steps if s["status"] == "not_started"), None)
    reviewed = (rows.get("price_book_review") is not None and rows["price_book_review"]["status"] == "done")
    return {"ok": True, "steps": steps, "done": done, "total": len(steps), "next_step": nxt,
            "sample_prices_in_use": samples, "ready_for_first_bid": reviewed and samples == 0,
            "ready_reason": None if reviewed and samples == 0 else
            "review the sample prices and set your own before sending real bids"}


def _merged_markups(conn, company_id: str, changes: dict) -> dict:
    row = conn.execute("SELECT * FROM markups WHERE company_id = ?", (company_id,)).fetchone()
    cur = {"overhead_pct": "0", "profit_pct": "0", "labor_burden_pct": "0", "tax_pct": "0",
           "taxable_kinds": ("material",), "tax_base": "cost", "round_to_cents": None, "rounding_mode": "half_up",
           "minimum_charge_cents": None}
    if row:
        cur.update(overhead_pct=row["overhead_pct"], profit_pct=row["profit_pct"],
                   labor_burden_pct=row["labor_burden_pct"], tax_pct=row["tax_pct"],
                   taxable_kinds=tuple(k for k in row["taxable_kinds"].split(",") if k), tax_base=row["tax_base"],
                   round_to_cents=row["round_to_cents"], rounding_mode=row["rounding_mode"],
                   minimum_charge_cents=row["minimum_charge_cents"])
    cur.update(changes)
    return cur


def _apply(conn, ctx, step: str, data: dict) -> dict:
    """Apply a step's data to real settings. Returns what was applied."""
    if step == "company_profile":
        bad = sorted(set(data) - set(PROFILE_FIELDS))
        if bad:
            raise InvalidInput(f"unknown company profile fields: {bad}", valid=list(PROFILE_FIELDS))
        if not str(data.get("name", "")).strip():
            raise InvalidInput("company name is required", field="name")
        vals = {f: data.get(f) for f in PROFILE_FIELDS}
        with service.transaction(conn):
            conn.execute(
                "INSERT INTO company_profile (company_id, name, address, phone, license_no, logo_path, updated_by,"
                " updated_at) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT (company_id) DO UPDATE SET name = excluded.name,"
                " address = excluded.address, phone = excluded.phone, license_no = excluded.license_no,"
                " logo_path = excluded.logo_path, updated_by = excluded.updated_by, updated_at = excluded.updated_at",
                (ctx.company_id, vals["name"].strip(), vals["address"], vals["phone"], vals["license_no"],
                 vals["logo_path"], ctx.actor, _now()))
        return {"company_profile": vals}
    if step == "services":
        from estimator.modules import get_registry
        reg = get_registry()
        mods = data.get("modules") or []
        for m in mods:
            reg.get(m)          # raises not_found with the list
        return {"modules": mods}
    if step in ("tax", "markups"):
        allowed = (("tax_pct", "taxable_kinds", "tax_base") if step == "tax" else
                   ("overhead_pct", "profit_pct", "labor_burden_pct", "round_to_cents", "minimum_charge_cents",
                    "minimum_charge"))
        bad = sorted(set(data) - set(allowed))
        if bad:
            raise InvalidInput(f"unknown {step} fields: {bad}", valid=list(allowed))
        changes = dict(data)
        if "minimum_charge" in changes:
            changes["minimum_charge_cents"] = cents_from_decimal(str(changes.pop("minimum_charge")))
        service.save_markups(conn, ctx, **_merged_markups(conn, ctx.company_id, changes))
        return changes
    if step in ("labor_rates", "price_book_review"):
        prices = data.get("prices") or {}
        if not isinstance(prices, dict):
            raise InvalidInput("prices must be an object of price_key -> dollars (e.g. \"0.18\")")
        applied = {}
        with service.transaction(conn):
            for key, dollars in prices.items():
                cur = get_price(conn, ctx.company_id, key)
                if cur is None:
                    raise NotFound(f"no price '{key}' in the price book", price_key=key)
                try:
                    cents = cents_from_decimal(str(dollars))
                except (ValueError, TypeError):
                    raise InvalidInput(f"price for '{key}' must be dollars like \"0.18\"", price_key=key) from None
                set_price(conn, ctx.company_id, key, description=cur.description.replace(" (sample)", ""),
                          kind=cur.kind, unit=cur.unit, cost_cents=cents, actor=ctx.actor)
                applied[key] = cents
            if data.get("keep_samples"):
                # the owner confirms the remaining sample prices are fine to use as their own
                conn.execute("UPDATE price_book SET is_sample = 0 WHERE company_id = ? AND is_sample = 1",
                             (ctx.company_id,))
                applied["kept_samples"] = True
        return {"prices_cents": applied}
    if step == "team_approvals":
        # Spec step 8 (Business mode): who can estimate, review, approve and send is set by
        # the AI-Prowler users and roles (Admin); the Estimator-side setting is the review
        # threshold, which lives with the Director settings. Dollars or cents both accepted.
        allowed = ("review_required_over", "review_required_over_cents", "quick_send_limit",
                   "quick_send_limit_cents")
        bad = sorted(set(data) - set(allowed))
        if bad:
            raise InvalidInput(f"unknown team and approvals fields: {bad}", valid=list(allowed))
        changes = {}
        for dollars_key, cents_key in (("review_required_over", "review_required_over_cents"),
                                       ("quick_send_limit", "quick_send_limit_cents")):
            if dollars_key in data:
                try:
                    changes[cents_key] = cents_from_decimal(str(data[dollars_key]))
                except (ValueError, TypeError):
                    raise InvalidInput(f"{dollars_key} must be dollars like \"750\"", field=dollars_key) from None
            if cents_key in data:
                changes[cents_key] = data[cents_key]
        if changes:
            from estimator.director import settings as director_settings
            director_settings.update_settings(conn, ctx, changes)
        return {"director_settings": changes}
    return {}


def setup_step(conn, ctx: RequestContext, step: str, data: dict | None = None, status: str = "done") -> dict:
    if ctx.role not in SETUP_ROLES:
        raise PermissionDenied("only the owner can run setup", role=ctx.role)
    if step not in STEP_IDS:
        raise InvalidInput(f"step must be one of {STEP_IDS}", field="step")
    if status not in ("done", "skipped"):
        raise InvalidInput("status must be done or skipped", field="status")
    data = data or {}
    if not isinstance(data, dict):
        raise InvalidInput("data must be an object")
    applied = _apply(conn, ctx, step, data) if status == "done" else {}
    with service.transaction(conn):
        conn.execute(
            "INSERT INTO setup_progress (company_id, step, status, data_json, updated_by, updated_at)"
            " VALUES (?,?,?,?,?,?) ON CONFLICT (company_id, step) DO UPDATE SET status = excluded.status,"
            " data_json = excluded.data_json, updated_by = excluded.updated_by, updated_at = excluded.updated_at",
            (ctx.company_id, step, status, json.dumps(data, default=str), ctx.actor, _now()))
        service._log(conn, ctx, None, "setup_step", {"step": step, "status": status})
    out = setup_status(conn, ctx)
    out["applied"] = applied
    return out
