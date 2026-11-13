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


# update_price_details: module_id=KEEP leaves the trade alone; None takes it off.
KEEP = object()

# The kinds a price can be (same list the import box accepts).
KINDS = ("material", "labor", "equipment", "sub", "other")

@dataclass(frozen=True)
class Price:
    price_key: str
    description: str
    kind: str
    unit: str
    cost_cents: int
    is_sample: bool
    effective_date: str
    module_id: str | None = None       # the trade this price belongs to, when it has one


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_price(conn: sqlite3.Connection, company_id: str, price_key: str, as_of: str | None = None) -> Price | None:
    as_of = as_of or date.today().isoformat()
    row = conn.execute(
        "SELECT price_key, description, kind, unit, cost_cents, is_sample, effective_date, module_id FROM price_book"
        " WHERE company_id = ? AND price_key = ? AND effective_date <= ?"
        " ORDER BY effective_date DESC, id DESC LIMIT 1",
        (company_id, price_key, as_of),
    ).fetchone()
    if row is None:
        return None
    return Price(row["price_key"], row["description"], row["kind"], row["unit"], int(row["cost_cents"]),
                 bool(row["is_sample"]), row["effective_date"], module_id=row["module_id"])


def set_price(conn: sqlite3.Connection, company_id: str, price_key: str, *, description: str, kind: str,
              unit: str, cost_cents: int, effective_date: str | None = None, actor: str = "owner",
              is_sample: bool = False, module_id: str | None = None, clear_module_id: bool = False) -> Price:
    """Add (or replace for the same date) a company price. Old dates stay for history.

    module_id is the trade the price belongs to; when given it is stored on the row.
    When omitted an existing row keeps its trade (a new row gets none). Pass
    clear_module_id=True to take the trade off the row (the price then shows only
    under All trades).
    """
    if isinstance(cost_cents, bool) or not isinstance(cost_cents, int) or cost_cents < 0:
        raise ValueError("cost_cents must be non-negative integer cents")
    effective_date = effective_date or date.today().isoformat()
    cols = ["company_id", "price_key", "description", "kind", "unit", "cost_cents", "is_sample",
            "effective_date", "created_by", "created_at"]
    values = [company_id, price_key, description, kind, unit, cost_cents, 1 if is_sample else 0, effective_date,
              actor, _now()]
    sets = ["description = excluded.description", "kind = excluded.kind", "unit = excluded.unit",
            "cost_cents = excluded.cost_cents", "is_sample = excluded.is_sample",
            "created_by = excluded.created_by", "created_at = excluded.created_at"]
    if module_id is not None or clear_module_id:
        cols.append("module_id")
        values.append(module_id)
        sets.append("module_id = excluded.module_id")
    conn.execute(
        f"INSERT INTO price_book ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})"
        " ON CONFLICT (company_id, price_key, effective_date) DO UPDATE SET " + ", ".join(sets),
        values,
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
    if module_id:
        # The company's own prices for this trade: rows tagged with the trade when they were added.
        keys |= {r[0] for r in conn.execute(
            "SELECT DISTINCT price_key FROM price_book WHERE company_id = ? AND module_id = ?",
            (company_id, module_id))}
    else:
        keys |= {r[0] for r in conn.execute("SELECT DISTINCT price_key FROM price_book WHERE company_id = ?",
                                            (company_id,))}
    rows = []
    for key in sorted(keys):
        p = get_price(conn, company_id, key)
        mod, sp = defaults.get(key, (None, None))
        if p is not None:
            rows.append({"price_key": key, "module_id": p.module_id or mod, "description": p.description,
                         "kind": p.kind, "unit": p.unit, "cost_cents": p.cost_cents, "sample": p.is_sample,
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


def _trade_name(module_id: str | None, registry=None) -> str:
    """A trade's display name, or 'No trade' when the price has no trade."""
    if not module_id:
        return "No trade"
    try:
        from estimator.modules import get_registry
        mod = (registry or get_registry()).get(module_id)
    except Exception:
        return module_id
    return mod.name if mod else module_id


def update_price_details(conn, ctx, price_key: str, *, description: str | None = None, kind: str | None = None,
                         unit: str | None = None, module_id=KEEP, cost: str | None = None,
                         sample: bool | None = None, effective_date: str | None = None, confirm: bool = False,
                         registry=None) -> dict:
    """Change a price's description, kind, unit, trade, cost and sample mark — everything but its key.

    module_id=KEEP (the default) leaves the trade alone; None takes the trade off;
    a module id sets it. cost is dollars as text ("250.00"); None keeps the cost.
    sample=False makes it your own price (the "(sample)" tag comes off the
    description); sample=True marks it a placeholder; None means your own price
    from now on - saving an edit is taking the price as yours (2026-11-12, David:
    "accept the current price and remove the sample wording"). A new dated row is
    written, so the old details stay in the price's history. Asks first unless
    confirm=true.
    """
    from estimator.core.units.money import cents_from_decimal, format_cents
    from estimator.errors import ConfirmationRequired, InvalidInput, NotFound, PermissionDenied
    from estimator.estimating import service
    if ctx.role not in ("owner", "estimator"):
        raise PermissionDenied(f"role '{ctx.role}' can't change prices", role=ctx.role)
    if effective_date:
        try:
            date.fromisoformat(effective_date)
        except ValueError:
            raise InvalidInput("effective_date must be YYYY-MM-DD", field="effective_date") from None
    cur = get_price(conn, ctx.company_id, price_key)
    defaults = _module_defaults(registry)
    if cur is None and price_key not in defaults:
        raise NotFound(f"no price called '{price_key}'; use pricebook_get to see the names", price_key=price_key)
    base = cur or defaults[price_key][1]
    new_desc = base.description if description is None else str(description).strip()
    new_kind = base.kind if kind is None else str(kind).strip()
    new_unit = base.unit if unit is None else str(unit).strip()
    if not new_desc:
        raise InvalidInput("give the price a description", field="description")
    if new_kind not in KINDS:
        raise InvalidInput(f"kind '{new_kind}' must be one of {', '.join(KINDS)}", field="kind")
    if not new_unit:
        raise InvalidInput("give the price a unit, e.g. sqft", field="unit")
    cur_module = cur.module_id if cur else defaults[price_key][0]
    if module_id is KEEP:
        new_module = cur_module
    elif module_id is None:
        new_module = None
    else:
        new_module = str(module_id).strip() or None
    was_sample = True if cur is None else cur.is_sample
    new_sample = False if sample is None else bool(sample)
    if not new_sample and new_desc.endswith(" (sample)"):
        new_desc = new_desc[: -len(" (sample)")].rstrip()          # your own price drops the "(sample)" tag
    changes = []
    if new_desc != base.description:
        changes.append(f'Description: "{base.description}" -> "{new_desc}"')
    if new_kind != base.kind:
        changes.append(f"Kind: {base.kind} -> {new_kind}")
    if new_unit != base.unit:
        changes.append(f"Unit: {base.unit} -> {new_unit}")
    if new_module != cur_module:
        changes.append(f"Trade: {_trade_name(cur_module, registry)} -> {_trade_name(new_module, registry)}")
    new_cents = base.cost_cents
    if cost is not None and str(cost).strip() != "":
        try:
            new_cents = cents_from_decimal(str(cost).strip().lstrip("$").replace(",", ""))
        except (ValueError, TypeError):
            raise InvalidInput('give the cost as dollars, e.g. "250.00"', field="cost") from None
        if new_cents < 0:
            raise InvalidInput("the cost can't be negative", field="cost")
    if new_cents != base.cost_cents:
        changes.append(f"Cost: {format_cents(base.cost_cents)} -> {format_cents(new_cents)} per {new_unit}")
    if new_sample != was_sample:
        changes.append("Sample: no — it's your own price now" if not new_sample else "Sample: yes — marked as a placeholder")
    if not changes:
        return {"ok": True, "changed": [], "message": "Nothing to change."}
    if not confirm:
        raise ConfirmationRequired(
            f"Change '{base.description}'? " + "; ".join(changes) + ". Call again with confirm=true once the user says yes.",
            changes=changes)
    with service.transaction(conn):
        # Always state the trade: a new dated row gets NULL unless told otherwise,
        # so "keep" still has to carry the current trade onto the new row.
        kwargs = {"clear_module_id": True} if new_module is None else {"module_id": new_module}
        set_price(conn, ctx.company_id, price_key, description=new_desc, kind=new_kind, unit=new_unit,
                  cost_cents=new_cents, actor=ctx.actor, is_sample=new_sample, effective_date=effective_date or None,
                  **kwargs)
        service._log(conn, ctx, None, "price_details_changed",
                     {"price_key": price_key, "changes": changes})
    return {"ok": True, "changed": changes, "summary": "; ".join(changes),
            "note": ("The cost is unchanged" if new_cents == base.cost_cents else "New prices apply to new and "
                     "re-priced estimates") + "; bids already made keep their prices."}


def remove_price(conn, ctx, price_key: str, *, confirm: bool = False, registry=None) -> dict:
    """Remove a company's own price for a key (all its dated rows).

    A module key goes back to the trade's sample price; a price added by hand is
    gone from the Price Book entirely. Bids already made keep their prices.
    Asks first unless confirm=true.
    """
    from estimator.errors import ConfirmationRequired, NotFound, PermissionDenied
    from estimator.estimating import service
    if ctx.role not in ("owner", "estimator"):
        raise PermissionDenied(f"role '{ctx.role}' can't change prices", role=ctx.role)
    cur = get_price(conn, ctx.company_id, price_key)
    if cur is None:
        raise NotFound(f"no saved price for '{price_key}' — the trade's sample is already in use",
                       price_key=price_key)
    reverts = price_key in _module_defaults(registry)
    if reverts:
        change = f"Removes your price for '{cur.description}' — it goes back to the trade's sample price."
        question = f"Remove your price for '{cur.description}'? It goes back to the trade's sample price."
    else:
        change = f"Removes '{cur.description}' from the Price Book entirely."
        question = f"Remove '{cur.description}' from the Price Book? It will be gone entirely."
    if not confirm:
        raise ConfirmationRequired(question + " Call again with confirm=true once the user says yes.",
                                   changes=[change])
    with service.transaction(conn):
        conn.execute("DELETE FROM price_book WHERE company_id = ? AND price_key = ?",
                     (ctx.company_id, price_key))
        service._log(conn, ctx, None, "price_removed",
                     {"price_key": price_key, "reverts_to_sample": reverts})
    return {"ok": True, "removed": price_key, "reverts_to_sample": reverts,
            "summary": change}
