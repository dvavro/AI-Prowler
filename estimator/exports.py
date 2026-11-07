"""Estimate export to CSV or Excel (est_export).

One estimate: its line items by trade, then the totals. No estimate: a list of estimates (optionally one status).
Files go to the Estimator's exports folder; the result gives the path, so AI-Prowler's own file tools
(send_file, get_file_download_url) can hand it on. Read-only: nothing in the estimate changes.
"""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from estimator import config
from estimator.context import RequestContext
from estimator.errors import InvalidInput
from estimator.estimating import service

FORMATS = ("csv", "xlsx")
LINE_COLUMNS = ("Trade", "Kind", "Description", "Quantity", "Unit", "Unit cost", "Waste %", "Cost", "Price", "Price key")
LIST_COLUMNS = ("Estimate", "Title", "Status", "Customer", "Total", "Updated")


def exports_dir() -> Path:
    d = config.data_dir() / "exports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _dollars(cents) -> str:
    return f"{(cents or 0) / 100:.2f}"


def export(conn, ctx: RequestContext, estimate_id: int | None = None, status: str | None = None, fmt: str = "csv") -> dict:
    fmt = (fmt or "csv").lower().lstrip(".")
    if fmt not in FORMATS:
        raise InvalidInput("format must be csv or xlsx", field="format")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if estimate_id:
        est = service.get_estimate(conn, ctx, int(estimate_id))
        rows = _estimate_rows(est)
        name = f"estimate_{est['id']}_v{est['revision']}_{stamp}.{fmt}"
        sheets = {"Line items": (LINE_COLUMNS, rows["lines"]), "Totals": (("Item", "Amount"), rows["totals"])}
        what = f"estimate {est['id']} ({est['title'] or 'untitled'}): {len(rows['lines'])} line(s)"
    else:
        listed = service.list_estimates(conn, ctx, status=status or None, limit=500)["estimates"]
        body = [(e["id"], e["title"], e["status"], e["customer_id"] or "", _dollars(e["total_cents"]), e["updated_at"])
                for e in listed]
        name = f"estimates{'_' + status if status else ''}_{stamp}.{fmt}"
        sheets = {"Estimates": (LIST_COLUMNS, body)}
        what = f"{len(body)} estimate(s)" + (f" with status {status}" if status else "")
    path = exports_dir() / name
    if fmt == "csv":
        _write_csv(path, sheets)
    else:
        _write_xlsx(path, sheets)
    return {"ok": True, "path": str(path), "file": name, "format": fmt, "what": what,
            "note": "Saved in the Estimator's exports folder. send_file or get_file_download_url can share it."}


def _estimate_rows(est: dict) -> dict:
    lines = []
    for sec in est["sections"]:
        for ln in sec["lines"]:
            price = (ln.get("calc") or {}).get("price") or {}
            waste = ln["waste_pct"] or "0"
            try:
                waste_pct = f"{float(waste) * 100:g}"
            except ValueError:
                waste_pct = waste
            lines.append((sec["module_id"], ln["kind"], ln["description"], ln["quantity"], ln["unit"],
                          _dollars(ln["unit_cost_cents"]), waste_pct, _dollars(price.get("cost_cents")),
                          _dollars(ln["total_cents"]), ln["price_key"] or ""))
    t = est["totals"] or {}
    totals = [("Cost", _dollars(t.get("cost_cents"))), ("Overhead", _dollars(t.get("overhead_cents"))),
              ("Profit", _dollars(t.get("profit_cents"))), ("Tax", _dollars(t.get("tax_cents")))]
    if t.get("minimum_charge_adjustment_cents"):
        totals.append(("Minimum charge adjustment", _dollars(t["minimum_charge_adjustment_cents"])))
    if t.get("rounding_adjustment_cents"):
        totals.append(("Rounding", _dollars(t["rounding_adjustment_cents"])))
    totals.append(("Total", _dollars(t.get("total_cents"))))
    return {"lines": lines, "totals": totals}


def _write_csv(path: Path, sheets: dict) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:          # utf-8-sig: Excel opens it cleanly
        w = csv.writer(f)
        for i, (title, (cols, rows)) in enumerate(sheets.items()):
            if i:
                w.writerow([])
            if len(sheets) > 1:
                w.writerow([title])
            w.writerow(cols)
            w.writerows(rows)


def _write_xlsx(path: Path, sheets: dict) -> None:
    try:
        import openpyxl
        from openpyxl.styles import Font
    except ImportError:
        raise InvalidInput("Excel export needs openpyxl; use format=csv") from None
    wb = openpyxl.Workbook()
    wb.remove(wb.active)
    money_cols = {"Unit cost", "Cost", "Price", "Total", "Amount"}
    for title, (cols, rows) in sheets.items():
        ws = wb.create_sheet(title)
        ws.append(list(cols))
        for c in ws[1]:
            c.font = Font(bold=True)
        for r in rows:
            ws.append([_num(v) if cols[i] in money_cols or cols[i] in ("Quantity", "Waste %") else v
                       for i, v in enumerate(r)])
        for i, col in enumerate(cols, start=1):
            if col in money_cols:
                for cell in ws.iter_cols(min_col=i, max_col=i, min_row=2):
                    for c in cell:
                        c.number_format = "$#,##0.00"
            width = max([len(str(col))] + [len(str(r[i - 1])) for r in rows]) + 2
            ws.column_dimensions[ws.cell(1, i).column_letter].width = min(width, 60)
    wb.save(path)


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return v
