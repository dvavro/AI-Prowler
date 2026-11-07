"""Price book import from a supplier's price list (pricebook_import).

The list can be a CSV or Excel file on this PC, or CSV text pasted into chat. Columns are matched to the price
book by name ("Item Code", "Unit Price", ...) or by a mapping you give. Each row updates an existing price, found
by its price key or, failing that, by its description. With add_new=true, rows that match nothing become new
prices of your own (they need a unit). Nothing is saved until confirm=true: the first call shows what would change.

Safety: a row whose unit doesn't match the price's unit (per box vs per each) is skipped, never converted; costs
must be plain dollar amounts; files are limited to CSV/Excel under 5 MB and 5,000 rows.
"""
from __future__ import annotations

import csv
import io
import re
from datetime import date
from pathlib import Path

from estimator.core.units.money import format_cents, parse_money
from estimator.errors import ConfirmationRequired, InvalidInput, PermissionDenied

MAX_BYTES = 5 * 1024 * 1024
MAX_ROWS = 5000
SUFFIXES = (".csv", ".txt", ".xlsx", ".xlsm")
FIELDS = ("price_key", "cost", "description", "unit", "kind", "supplier")
KINDS = ("material", "labor", "equipment", "sub", "other")
GUESS = {
    "price_key": ("price_key", "price key", "key", "item code", "code", "sku", "item #", "item no", "part number",
                  "part #", "item number"),
    "cost": ("cost", "unit cost", "price", "unit price", "your cost", "net price", "cost each", "each", "amount"),
    "description": ("description", "item", "item description", "name", "product", "desc"),
    "unit": ("unit", "uom", "units", "unit of measure", "per"),
    "kind": ("kind", "type", "cost type", "category"),
    "supplier": ("supplier", "vendor", "source"),
}
UNIT_SAME = {"sqft": "sq ft", "sf": "sq ft", "sq. ft.": "sq ft", "square foot": "sq ft", "square feet": "sq ft",
             "lf": "lin ft", "lin. ft.": "lin ft", "linear foot": "lin ft", "linear feet": "lin ft", "ft": "lin ft",
             "ea": "each", "ea.": "each", "pc": "each", "piece": "each", "hr": "hour", "hrs": "hour", "hours": "hour",
             "cy": "cu yd", "cubic yard": "cu yd", "yd3": "cu yd", "sq": "square", "squares": "square",
             "gal": "gallon", "gallons": "gallon"}
SHOW = 25                                   # rows listed in the preview


def _norm(text) -> str:
    return re.sub(r"\s+", " ", str(text or "").strip().lower())


def _unit(text) -> str:
    u = _norm(text).rstrip(".") if text else ""
    return UNIT_SAME.get(u, UNIT_SAME.get(u + ".", u))


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", _norm(text)).strip("_")[:48] or "item"


# ---------------------------------------------------------------- reading the list

def read_table(*, file_path: str | None = None, csv_text: str | None = None, sheet: str | None = None
               ) -> tuple[list[str], list[dict]]:
    """(headers, rows as {header: text}). Blank rows are dropped; the first non-blank row is the header."""
    if bool(file_path) == bool(csv_text):
        raise InvalidInput("give either file_path (a CSV or Excel file on this PC) or csv_text (pasted CSV)")
    if csv_text:
        return _from_csv(csv_text)
    path = Path(str(file_path).strip().strip('"'))
    if path.suffix.lower() not in SUFFIXES:
        raise InvalidInput("the price list must be a .csv or .xlsx file", file=str(path))
    if not path.is_file():
        raise InvalidInput(f"can't find {path}", file=str(path))
    if path.stat().st_size > MAX_BYTES:
        raise InvalidInput("the price list is over 5 MB; split it or save just the columns you need", file=str(path))
    if path.suffix.lower() in (".xlsx", ".xlsm"):
        return _from_excel(path, sheet)
    data = path.read_bytes()
    for enc in ("utf-8-sig", "cp1252"):
        try:
            return _from_csv(data.decode(enc))
        except UnicodeDecodeError:
            continue
    raise InvalidInput("couldn't read the file's text; save it as CSV (UTF-8)", file=str(path))


def _from_csv(text: str) -> tuple[list[str], list[dict]]:
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    rows = [r for r in csv.reader(io.StringIO(text), dialect) if any(c.strip() for c in r)]
    return _table(rows)


def _from_excel(path: Path, sheet: str | None) -> tuple[list[str], list[dict]]:
    try:
        import openpyxl
    except ImportError:
        raise InvalidInput("reading Excel needs openpyxl; save the sheet as CSV instead") from None
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    try:
        if sheet:
            if sheet not in wb.sheetnames:
                raise InvalidInput(f"no sheet called '{sheet}'. Sheets: {', '.join(wb.sheetnames)}", sheets=wb.sheetnames)
            ws = wb[sheet]
        else:
            ws = wb.worksheets[0]
        rows = []
        for r in ws.iter_rows(values_only=True):
            cells = ["" if c is None else str(c) for c in r]
            if any(c.strip() for c in cells):
                rows.append(cells)
            if len(rows) > MAX_ROWS + 1:
                break
    finally:
        wb.close()
    return _table(rows)


def _table(rows: list[list[str]]) -> tuple[list[str], list[dict]]:
    if not rows:
        raise InvalidInput("the price list is empty")
    headers = [h.strip() or f"column {i + 1}" for i, h in enumerate(rows[0])]
    body = rows[1:]
    if len(body) > MAX_ROWS:
        raise InvalidInput(f"the price list has more than {MAX_ROWS:,} rows; split it into smaller files")
    return headers, [{h: (r[i].strip() if i < len(r) else "") for i, h in enumerate(headers)} for r in body]


def guess_mapping(headers: list[str], mapping: dict | None = None) -> dict:
    """{field: header}. A given mapping wins; the rest is guessed from the header names."""
    mapping = dict(mapping or {})
    unknown = set(mapping) - set(FIELDS)
    if unknown:
        raise InvalidInput(f"mapping fields must be among {', '.join(FIELDS)}; not {', '.join(sorted(unknown))}")
    for field, col in mapping.items():
        if col not in headers:
            raise InvalidInput(f"mapping says {field} is in column '{col}', but the columns are: {', '.join(headers)}",
                               columns=headers)
    used = set(mapping.values())
    by_norm = {_norm(h): h for h in headers}
    for field in FIELDS:
        if field in mapping:
            continue
        for name in GUESS[field]:
            if name in by_norm and by_norm[name] not in used:
                mapping[field] = by_norm[name]
                used.add(by_norm[name])
                break
    return mapping


# ---------------------------------------------------------------- matching and saving

def import_prices(conn, ctx, *, file_path: str | None = None, csv_text: str | None = None, mapping: dict | None = None,
                  sheet: str | None = None, effective_date: str | None = None, add_new: bool = False,
                  confirm: bool = False, registry=None) -> dict:
    from estimator.estimating import service
    from estimator.pricing.price_book import _module_defaults, get_price, set_price
    if ctx.role not in ("owner", "estimator"):
        raise PermissionDenied(f"role '{ctx.role}' can't change prices", role=ctx.role)
    if effective_date:
        try:
            date.fromisoformat(effective_date)
        except ValueError:
            raise InvalidInput("effective_date must be YYYY-MM-DD", field="effective_date") from None
    headers, rows = read_table(file_path=file_path, csv_text=csv_text, sheet=sheet)
    cols = guess_mapping(headers, mapping)
    if "cost" not in cols:
        raise InvalidInput("which column has the cost? Give mapping, e.g. {\"cost\": \"Unit Price\"}", columns=headers)
    if "price_key" not in cols and "description" not in cols:
        raise InvalidInput("rows need a price key or a description column to match on. Give mapping, e.g. "
                           "{\"description\": \"Item\"}", columns=headers)

    defaults = _module_defaults(registry)
    current: dict[str, object] = {}
    for key in set(defaults) | {r[0] for r in conn.execute("SELECT DISTINCT price_key FROM price_book WHERE company_id = ?",
                                                           (ctx.company_id,))}:
        p = get_price(conn, ctx.company_id, key)
        current[key] = p if p is not None else defaults[key][1]
    by_desc: dict[str, list[str]] = {}
    for key, p in current.items():
        by_desc.setdefault(_norm(p.description.replace(" (sample)", "")), []).append(key)

    updates, new, unchanged, skipped, seen = [], [], [], [], set()
    for n, row in enumerate(rows, start=2):                   # row 1 is the header
        def skip(why):
            skipped.append({"row": n, "item": row.get(cols.get("description", ""), "") or row.get(cols.get("price_key", ""), ""),
                            "reason": why})
        raw_cost = row.get(cols["cost"], "")
        try:
            cents = parse_money(raw_cost)
        except (ValueError, TypeError):
            skip(f"cost '{raw_cost}' isn't a dollar amount")
            continue
        if cents < 0:
            skip("negative cost")
            continue
        key = row.get(cols["price_key"], "").strip() if "price_key" in cols else ""
        desc = row.get(cols["description"], "").strip() if "description" in cols else ""
        unit = row.get(cols["unit"], "").strip() if "unit" in cols else ""
        kind = _norm(row.get(cols["kind"], "")) if "kind" in cols else ""
        supplier = row.get(cols["supplier"], "").strip() if "supplier" in cols else ""
        match = key if key in current else None
        if match is None and desc:
            hits = by_desc.get(_norm(desc), [])
            if len(hits) == 1:
                match = hits[0]
            elif len(hits) > 1:
                skip(f"description matches {len(hits)} prices ({', '.join(sorted(hits))}); add a price key column")
                continue
        if match is not None:
            base = current[match]
            if unit and _unit(unit) != _unit(base.unit):
                skip(f"unit '{unit}' doesn't match '{base.unit}' for {match}; fix the unit or the price by hand")
                continue
            if match in seen:
                skip(f"{match} appears more than once; the first row was used")
                continue
            seen.add(match)
            change = {"row": n, "price_key": match, "description": base.description.replace(" (sample)", ""),
                      "kind": base.kind, "unit": base.unit, "old_cents": base.cost_cents, "new_cents": cents,
                      "supplier": supplier or None, "was_sample": bool(getattr(base, "is_sample", True))}
            (unchanged if cents == base.cost_cents and not change["was_sample"] else updates).append(change)
            continue
        if not add_new:
            skip("no matching price (use add_new=true to add it as a new price)")
            continue
        if not desc or not unit:
            skip("a new price needs a description and a unit")
            continue
        kind = kind or "material"
        if kind not in KINDS:
            skip(f"kind '{kind}' must be one of {', '.join(KINDS)}")
            continue
        new_key = key if key and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key) else f"custom_{_slug(desc)}"
        if new_key in current or new_key in seen:
            skip(f"{new_key} already exists or appears twice")
            continue
        seen.add(new_key)
        new.append({"row": n, "price_key": new_key, "description": desc, "kind": kind, "unit": unit, "old_cents": None,
                    "new_cents": cents, "supplier": supplier or None, "was_sample": False})

    preview = {"columns_used": cols, "rows_read": len(rows), "updates": len(updates), "new": len(new),
               "unchanged": len(unchanged), "skipped": len(skipped),
               "changes": [_line(c) for c in (updates + new)[:SHOW]], "skipped_rows": skipped[:SHOW],
               "more_not_shown": max(0, len(updates) + len(new) - SHOW)}
    if not updates and not new:
        return {"ok": True, "saved": 0, **preview,
                "message": "Nothing to change: every row was unchanged or skipped (see skipped_rows)."}
    if not confirm:
        raise ConfirmationRequired(
            f"Import {len(updates)} price change(s) and {len(new)} new price(s) from the list "
            f"({len(skipped)} row(s) skipped, {len(unchanged)} unchanged)? Show the user the changes, then call again "
            "with confirm=true.", **preview)
    with service.transaction(conn):
        for c in updates + new:
            set_price(conn, ctx.company_id, c["price_key"], description=c["description"], kind=c["kind"], unit=c["unit"],
                      cost_cents=c["new_cents"], effective_date=effective_date, actor=ctx.actor)
            if c["supplier"]:
                conn.execute("UPDATE price_book SET supplier = ? WHERE company_id = ? AND price_key = ? AND effective_date = ?",
                             (c["supplier"], ctx.company_id, c["price_key"], effective_date or date.today().isoformat()))
        service._log(conn, ctx, None, "prices_imported",
                     {"source": Path(file_path).name if file_path else "pasted text", "updates": len(updates),
                      "new": len(new), "skipped": len(skipped), "effective_date": effective_date})
    return {"ok": True, "saved": len(updates) + len(new), **preview,
            "note": "New prices apply to new and re-priced estimates; bids already made keep their prices."}


def _line(c: dict) -> str:
    old = "new" if c["old_cents"] is None else format_cents(c["old_cents"]) + (" (sample)" if c["was_sample"] else "")
    return f"row {c['row']}: {c['price_key']} ({c['description']}): {old} → {format_cents(c['new_cents'])} per {c['unit']}"
