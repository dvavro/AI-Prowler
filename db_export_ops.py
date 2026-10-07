"""
db_export_ops.py — Job Board Architecture Spec, Phase 6 (spec §7, §11).

One-way Excel export: builds a fresh .xlsx snapshot from the current
SQLite state. NEVER a write target — nothing in this module, or anywhere
else in AI-Prowler, reads changes back out of an exported file. Editing
and saving the export has zero effect on the live database; this
module's job ends the moment openpyxl writes the file to disk (spec §7:
"this is a snapshot, not a live file").

Format fidelity is a soft goal (spec §7's own decision), not a hard
requirement: headers match the live schema's canonical display names —
the same ones read_job_spreadsheet/get_board_updates already use for
jobs/customers/invoices/quotes, reused directly from db_read_ops so
there is exactly one source of truth for "what does this column display
as" — but no attempt is made to reproduce the original template's
colors, freeze panes, or exact column widths.
"""

import datetime

from db_access import get_connection
from db_read_ops import (
    _CUSTOMERS_DISPLAY,
    _INVOICES_DISPLAY,
    _JOBS_DISPLAY,
    _QUOTES_DISPLAY,
    _ROUTE_STOPS_DISPLAY,
    _SERVICE_PRICING_DISPLAY,
    _SETTINGS_DISPLAY,
    _TIME_ENTRIES_DISPLAY,
    _apply_live_join_overlays,
)

# time_entries/route_stops/settings/service_pricing display lists now
# live in db_read_ops.py (one source of truth, since Database-tab reads
# and this export need the exact same header text) — imported above
# rather than redefined here, closing the drift risk the original
# hand-built copies in this module had.

# (table, sheet_name, display_pairs) — order is also the sheet order in
# the exported workbook, roughly matching the original template's
# tab order.
_EXPORT_TABLES = [
    ("jobs", "Jobs_Schedule", _JOBS_DISPLAY),
    ("customers", "Customers", _CUSTOMERS_DISPLAY),
    ("invoices", "Invoices", _INVOICES_DISPLAY),
    ("quotes", "Quotes", _QUOTES_DISPLAY),
    ("time_entries", "TimeLog", _TIME_ENTRIES_DISPLAY),
    ("route_stops", "Route_Planner", _ROUTE_STOPS_DISPLAY),
    ("settings", "Settings", _SETTINGS_DISPLAY),
    ("service_pricing", "Services_Pricing", _SERVICE_PRICING_DISPLAY),
]


def db_export_to_excel(db_path: str, output_path: str) -> str:
    """Builds a fresh .xlsx snapshot of every table in db_path and saves
    it to output_path, overwriting any existing file there. One sheet
    per table, a header row from that table's display-pairs list, then
    one data row per DB row in rowid (insertion) order.

    Reads db_path, writes a brand-new file at output_path — nothing
    else. In particular this never opens output_path for reading first,
    never merges with a prior export, and never writes anything back
    into db_path; the whole point of this function is that the two
    files have no relationship after this call returns (spec §7).

    Returns a confirmation string with per-sheet row counts, or a clear
    error if openpyxl isn't installed or the file can't be written.
    """
    try:
        import openpyxl
    except ImportError:
        return "❌ openpyxl not installed. Run: pip install openpyxl"

    wb = openpyxl.Workbook()
    wb.remove(wb.active)  # drop the default blank sheet; every sheet below is one we add

    conn = get_connection(db_path)
    try:
        sheet_counts = []
        for table, sheet_name, display_pairs in _EXPORT_TABLES:
            ws = wb.create_sheet(sheet_name)
            ws.append([h for _, h in display_pairs])
            rows = conn.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            # Spec §13: several display columns (Invoice Total, Actual
            # Amount, Tax%, and the four Customers rollups) no longer
            # have a backing column at all — their value only exists via
            # this live-join overlay, the same one every other read path
            # uses. Without this, the export would show these columns as
            # permanently blank instead of the real, current values.
            rows = _apply_live_join_overlays(conn, table, rows)
            for row in rows:
                ws.append([row[db_col] if db_col in row.keys() else None
                           for db_col, _ in display_pairs])
            sheet_counts.append((sheet_name, len(rows)))
    finally:
        conn.close()

    try:
        wb.save(output_path)
    except Exception as exc:
        return f"❌ Could not save export: {exc}"

    lines = [
        f"✅ Export saved: {output_path}",
        f"   Generated: {datetime.datetime.now().isoformat(timespec='seconds')}",
    ]
    for sheet_name, n in sheet_counts:
        lines.append(f"   {sheet_name}: {n} row(s)")
    lines.append(
        "\nℹ️  This is a one-way snapshot — editing and saving this file "
        "has no effect on the live database. Run the export again for a fresh copy."
    )
    return "\n".join(lines)
