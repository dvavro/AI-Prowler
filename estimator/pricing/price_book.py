"""Company price book lookups.

A price is looked up by (company, price_key) and the latest effective date on or
before the estimate date. When the company has no price for a key yet, the
module's sample price is copied in with is_sample = 1 so the estimate still
works, and the caller gets a warning saying the number is a placeholder.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timezone

SAMPLE_EFFECTIVE_DATE = "2000-01-01"


@dataclass(frozen=True)
class Price:
    price_key: str
    description: str
    kind: str
    unit: str
    cost_cents: int
    is_sample: bool
    effective_date: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_price(conn: sqlite3.Connection, company_id: str, price_key: str, as_of: str | None = None) -> Price | None:
    as_of = as_of or date.today().isoformat()
    row = conn.execute(
        "SELECT price_key, description, kind, unit, cost_cents, is_sample, effective_date FROM price_book"
        " WHERE company_id = ? AND price_key = ? AND effective_date <= ?"
        " ORDER BY effective_date DESC, id DESC LIMIT 1",
        (company_id, price_key, as_of),
    ).fetchone()
    if row is None:
        return None
    return Price(row["price_key"], row["description"], row["kind"], row["unit"], int(row["cost_cents"]),
                 bool(row["is_sample"]), row["effective_date"])


def set_price(conn: sqlite3.Connection, company_id: str, price_key: str, *, description: str, kind: str,
              unit: str, cost_cents: int, effective_date: str | None = None, actor: str = "owner",
              is_sample: bool = False) -> Price:
    """Add (or replace for the same date) a company price. Old dates stay for history."""
    if isinstance(cost_cents, bool) or not isinstance(cost_cents, int) or cost_cents < 0:
        raise ValueError("cost_cents must be non-negative integer cents")
    effective_date = effective_date or date.today().isoformat()
    conn.execute(
        "INSERT INTO price_book (company_id, price_key, description, kind, unit, cost_cents, is_sample,"
        " effective_date, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)"
        " ON CONFLICT (company_id, price_key, effective_date) DO UPDATE SET description = excluded.description,"
        " kind = excluded.kind, unit = excluded.unit, cost_cents = excluded.cost_cents,"
        " is_sample = excluded.is_sample, created_by = excluded.created_by, created_at = excluded.created_at",
        (company_id, price_key, description, kind, unit, cost_cents, 1 if is_sample else 0, effective_date,
         actor, _now()),
    )
    return get_price(conn, company_id, price_key, effective_date)


def ensure_sample_prices(conn: sqlite3.Connection, company_id: str, module, actor: str = "system") -> list[str]:
    """Copy a module's sample prices into the company price book where the company has none.

    Returns the keys that were added. Existing company prices are never touched.
    """
    added = []
    for key, sp in module.sample_prices.items():
        exists = conn.execute(
            "SELECT 1 FROM price_book WHERE company_id = ? AND price_key = ? LIMIT 1", (company_id, key)
        ).fetchone()
        if exists:
            continue
        conn.execute(
            "INSERT INTO price_book (company_id, price_key, description, kind, unit, cost_cents, is_sample,"
            " effective_date, created_by, created_at) VALUES (?,?,?,?,?,?,1,?,?,?)",
            (company_id, key, sp.description, sp.kind, sp.unit, sp.cost_cents, SAMPLE_EFFECTIVE_DATE, actor, _now()),
        )
        added.append(key)
    return added


# ---------------------------------------------------------------- browsing and changing prices

def _module_defaults(registry=None, module_id: str | None = None) -> dict:
    """Sample prices from module folders: price_key -> (module_id, SamplePrice)."""
    from estimator.modules import get_registry
    reg = registry or get_registry()
    mods = [reg.get(module_id)] if module_id else reg.list()
    out = {}
    for m in mods:
        for key, sp in m.sample_prices.items():
            out.setdefault(key, (m.id, sp))
    return out


def list_prices(conn, company_id: str, module_id: str | None = None, samples_only: bool = False,
                registry=None) -> dict:
    """Current price for every key: the company's own, or the module sample if none is saved yet."""
    defaults = _module_defaults(registry, module_id)
    keys = set(defaults)
    if not module_id:
        keys |= {r[0] for r in conn.execute("SELECT DISTINCT price_key FROM price_book WHERE company_id = ?",
                                            (company_id,))}
    rows = []
    for key in sorted(keys):
        p = get_price(conn, company_id, key)
        mod, sp = defaults.get(key, (None, None))
        if p is not None:
            rows.append({"price_key": key, "module_id": mod, "description": p.description, "kind": p.kind,
                         "unit": p.unit, "cost_cents": p.cost_cents, "sample": p.is_sample,
                         "effective_date": p.effective_date, "source": "sample" if p.is_sample else "yours"})
        elif sp is not None:
            rows.append({"price_key": key, "module_id": mod, "description": sp.description, "kind": sp.kind,
                         "unit": sp.unit, "cost_cents": sp.cost_cents, "sample": True, "effective_date": None,
                         "source": "sample (not used yet)"})
    if samples_only:
        rows = [r for r in rows if r["sample"]]
    return {"ok": True, "count": len(rows), "prices": rows,
            "samples_left": sum(1 for r in rows if r["sample"])}


def update_prices(conn, ctx, prices: dict, *, confirm: bool = False, effective_date: str | None = None,
                  registry=None) -> dict:
    """Set the company's own cost for one or more price keys (dollars as text, e.g. "0.18")."""
    from estimator.core.units.money import cents_from_decimal, format_cents
    from estimator.errors import ConfirmationRequired, InvalidInput, NotFound, PermissionDenied
    from estimator.estimating import service
    if ctx.role not in ("owner", "estimator"):
        raise PermissionDenied(f"role '{ctx.role}' can't change prices", role=ctx.role)
    if not isinstance(prices, dict) or not prices:
        raise InvalidInput('give prices as {"price_key": "dollars"}, e.g. {"pw_driveway_sqft": "0.18"}')
    if effective_date:
        try:
            date.fromisoformat(effective_date)
        except ValueError:
            raise InvalidInput("effective_date must be YYYY-MM-DD", field="effective_date") from None
    defaults = _module_defaults(registry)
    changes = []
    for key, dollars in prices.items():
        cur = get_price(conn, ctx.company_id, key)
        if cur is None and key not in defaults:
            raise NotFound(f"no price called '{key}'; use pricebook_get to see the names", price_key=key)
        if isinstance(dollars, float):
            dollars = repr(dollars)
        try:
            cents = cents_from_decimal(str(dollars).strip().lstrip("$"))
        except (ValueError, TypeError):
            raise InvalidInput(f"price for '{key}' must be dollars like \"0.18\"", price_key=key) from None
        if cents < 0:
            raise InvalidInput(f"price for '{key}' can't be negative", price_key=key)
        base = cur or defaults[key][1]
        changes.append({"price_key": key, "description": base.description.replace(" (sample)", ""), "kind": base.kind,
                        "unit": base.unit, "old_cents": base.cost_cents, "new_cents": cents,
                        "was_sample": True if cur is None else cur.is_sample})
    summary = "; ".join(f"{c['price_key']}: {format_cents(c['old_cents'])} → {format_cents(c['new_cents'])} per {c['unit']}"
                        for c in changes)
    if not confirm:
        raise ConfirmationRequired(f"Change these prices? {summary}. Call again with confirm=true once the user says yes.",
                                   changes=changes)
    with service.transaction(conn):
        for c in changes:
            set_price(conn, ctx.company_id, c["price_key"], description=c["description"], kind=c["kind"],
                      unit=c["unit"], cost_cents=c["new_cents"], effective_date=effective_date, actor=ctx.actor)
        service._log(conn, ctx, None, "prices_changed", {"changes": changes, "effective_date": effective_date})
    return {"ok": True, "changed": changes, "summary": summary,
            "note": "New prices apply to new and re-priced estimates; bids already made keep their prices."}
