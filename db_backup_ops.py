"""
db_backup_ops.py — Job Board Architecture Spec, Phase 8 (spec §12).

Two real capabilities that emerged as gaps once ai_prowler_jobs.db became
the sole live store and AI-Prowler_Job_Tracker.xlsx stopped being canonical:

  1. Backup / Restore — lossless, round-trippable, operates on the
     database file itself. db_backup_database() / db_restore_database().
     A full-database restore onto new hardware IS a PC migration — no
     separate "migration wizard" exists or is needed (spec §12.4).

  2. CSV export — a general-purpose, lowest-common-denominator export
     for handing data to an accountant or starting a QuickBooks import.
     db_export_to_csv(). Not a QuickBooks-native template match — that's
     flagged as a later phase (spec §12.5, Phase 8b), not built here.

Backup/restore deliberately use sqlite3's own online Backup API
(Connection.backup()) rather than a raw file copy: the Backup API is
safe to run while the database is being concurrently written to (it
copies at the page level under SQLite's own locking), where a naive
`shutil.copy` could catch a write mid-page and produce a corrupt
snapshot. This is the same reasoning spec §12.3 documents.
"""

import csv
import datetime
import os
import shutil
import sqlite3

# The 8 tables every AI-Prowler database has (spec §4.2) — used by
# db_restore_database() to validate an incoming file is actually an
# AI-Prowler database before committing to the swap, and by
# db_export_to_csv() as the default "export everything" table list.
_ALL_TABLES = [
    "jobs", "customers", "invoices", "quotes",
    "time_entries", "route_stops", "settings", "service_pricing",
]

# table -> (display sheet name, display header list) for CSV export.
# Reuses the exact same canonical display-pairs db_export_to_excel()
# already uses — one source of truth for "what does this column display
# as" across every export format.
def _csv_export_tables():
    from db_read_ops import (
        _CUSTOMERS_DISPLAY, _INVOICES_DISPLAY, _JOBS_DISPLAY, _QUOTES_DISPLAY,
        _ROUTE_STOPS_DISPLAY, _SERVICE_PRICING_DISPLAY, _SETTINGS_DISPLAY,
        _TIME_ENTRIES_DISPLAY,
    )
    return [
        ("jobs", "Jobs_Schedule", _JOBS_DISPLAY),
        ("customers", "Customers", _CUSTOMERS_DISPLAY),
        ("invoices", "Invoices", _INVOICES_DISPLAY),
        ("quotes", "Quotes", _QUOTES_DISPLAY),
        ("time_entries", "TimeLog", _TIME_ENTRIES_DISPLAY),
        ("route_stops", "Route_Planner", _ROUTE_STOPS_DISPLAY),
        ("settings", "Settings", _SETTINGS_DISPLAY),
        ("service_pricing", "Services_Pricing", _SERVICE_PRICING_DISPLAY),
    ]


def _table_row_counts(db_path: str) -> dict:
    """{table: row_count} for every table in _ALL_TABLES. Missing tables
    (a file that isn't a real AI-Prowler database) are simply absent from
    the result rather than raising — callers decide what an incomplete
    result set means for their own purposes."""
    counts = {}
    conn = sqlite3.connect(db_path)
    try:
        for table in _ALL_TABLES:
            try:
                counts[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.Error:
                # Covers both "no such table" (OperationalError, a real
                # AI-Prowler db just missing one table) and "file is not
                # a database" (DatabaseError — a genuinely non-SQLite
                # file, e.g. plain text) — the two don't share a common
                # subclass in Python's sqlite3 module, so both are
                # caught explicitly via the shared sqlite3.Error base.
                pass
    finally:
        conn.close()
    return counts


def db_backup_database(db_path: str, destination_path: str = "") -> str:
    """Copy db_path to destination_path using SQLite's own online Backup
    API — safe to run even while db_path is being concurrently written
    to (spec §12.3). Not a re-derived export: byte-faithful, and the
    result is itself a fully valid ai_prowler_jobs.db that
    db_restore_database() (or just renaming it back) can use directly.

    destination_path: full file path for the backup. If omitted,
    defaults to <folder of db_path>/Backups/AI-Prowler-Backup-<timestamp>.db.

    Returns a confirmation with the destination path, file size, and a
    per-table row-count summary, or a clear error if the source doesn't
    exist or the destination can't be written.
    """
    if not db_path or not os.path.exists(db_path):
        return f"❌ Source database not found: {db_path}"

    if not destination_path:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        # 2026-09-16: consolidated with _backup_job_db's own default folder
        # (ai_prowler_mcp.py) — both used to live in separate sibling
        # folders (Backups vs _backups) next to the db file for no real
        # reason; now everything lands in one "backup" folder.
        backups_dir = os.path.join(os.path.dirname(db_path), "backup")
        destination_path = os.path.join(backups_dir, f"AI-Prowler-Backup-{timestamp}.db")

    dest_dir = os.path.dirname(destination_path)
    if dest_dir and not os.path.exists(dest_dir):
        try:
            os.makedirs(dest_dir, exist_ok=True)
        except OSError as exc:
            return f"❌ Could not create destination folder {dest_dir}: {exc}"

    source_conn = sqlite3.connect(db_path)
    try:
        dest_conn = sqlite3.connect(destination_path)
        try:
            source_conn.backup(dest_conn)
        finally:
            dest_conn.close()
    except Exception as exc:
        return f"❌ Backup failed: {exc}"
    finally:
        source_conn.close()

    size_bytes = os.path.getsize(destination_path)
    size_mb = size_bytes / (1024 * 1024)
    counts = _table_row_counts(destination_path)

    lines = [
        f"✅ Backup saved: {destination_path}",
        f"   Size: {size_mb:.2f} MB",
        f"   Created: {datetime.datetime.now().isoformat(timespec='seconds')}",
        "",
        "   Row counts:",
    ]
    for table in _ALL_TABLES:
        if table in counts:
            lines.append(f"     {table}: {counts[table]}")
    return "\n".join(lines)


# R-050 (2026-09-28): the tables that hold real business records. settings
# and service_pricing are left out on purpose — a brand-new install already
# has default rows in those, so counting them would make every fresh
# database look "not empty" and defeat the migration check below.
_BUSINESS_TABLES = [
    "jobs", "customers", "invoices", "quotes", "time_entries", "route_stops",
]


def db_business_row_count(db_path: str) -> int:
    """R-050: total rows across _BUSINESS_TABLES. 0 when the file doesn't
    exist yet or isn't an AI-Prowler database — i.e. "nothing to lose"."""
    if not db_path or not os.path.exists(db_path):
        return 0
    counts = _table_row_counts(db_path)
    return sum(counts.get(t, 0) for t in _BUSINESS_TABLES)


def _business_counts_line(db_path: str) -> str:
    """R-050: one-line 'N jobs, N customers, ...' summary for warnings."""
    if not db_path or not os.path.exists(db_path):
        return "no database yet"
    counts = _table_row_counts(db_path)
    if not counts:
        return "not an AI-Prowler database"
    return ", ".join(f"{counts.get(t, 0)} {t.replace('_', ' ')}" for t in _BUSINESS_TABLES)


def db_restore_database(db_path: str, backup_path: str, confirm: bool = False,
                        require_replace: bool = False,
                        replace_existing: bool = False) -> str:
    """Replace db_path with backup_path. THE one genuinely destructive-to-
    current-state operation in AI-Prowler (spec §12.4) — every other
    write tool in this codebase edits or appends a row; this wholesale-
    replaces the live database. That's why it needs its own explicit
    confirm=True guard nothing else in the system requires.

    Safety sequence, in order:
      1. Refuse outright if confirm is not True — no partial action. The
         warning shows what is live now and what the backup holds (R-050).
      2. Validate backup_path actually looks like an AI-Prowler database
         (has at least one of the 8 expected tables) before touching
         anything live — a corrupt/wrong-format file is rejected with
         nothing changed.
      2b. R-050: when require_replace is True (server mode) and the live
         database already holds business records, refuse unless
         replace_existing=True as well. Restore is meant for moving to a
         new PC (empty database); wiping a working database needs a
         second, explicit yes.
      3. Take a safety backup of the CURRENT live database (reusing
         db_backup_database()) BEFORE overwriting it — a bad restore is
         itself always recoverable from that safety copy.
      4. Only then perform the actual restore, again via the Backup API
         (not a raw file copy) so a restore mid-write can't corrupt
         db_path either.

    Returns a confirmation with the safety-backup path, the new live
    database's per-table row counts, or a clear error at whichever step
    failed — nothing after a failed step has run.
    """
    live_total = db_business_row_count(db_path)
    have_backup = bool(backup_path) and os.path.exists(backup_path)
    counts_block = (
        f"   Live now: {_business_counts_line(db_path)}\n"
        f"   In the backup: {_business_counts_line(backup_path) if have_backup else 'backup file not found'}\n"
    )

    if not confirm:
        msg = (
            "❌ This would replace ALL current data in the live database.\n"
            + counts_block
        )
        if live_total > 0:
            msg += ("⚠️ The live database is NOT empty — restoring wipes those "
                    "records and replaces them with the backup's.\n")
        msg += ("Pass confirm=True to proceed. A safety backup of what's currently "
                "live will be made automatically before anything is overwritten.")
        if require_replace and live_total > 0:
            msg += " Because the live database is not empty you must also pass replace_existing=True."
        return msg

    if not have_backup:
        return f"❌ Backup file not found: {backup_path}"

    # Step 2: validate schema before touching anything live.
    incoming_counts = _table_row_counts(backup_path)
    if not incoming_counts:
        return (
            f"❌ '{backup_path}' does not look like an AI-Prowler database "
            f"(none of the expected tables were found: {', '.join(_ALL_TABLES)}). "
            "Nothing was changed."
        )

    # Step 2b (R-050): a non-empty live database needs a second, explicit yes.
    if require_replace and live_total > 0 and not replace_existing:
        return (
            "❌ Restore refused — the live database is NOT empty, and restore is "
            "meant for setting up a new PC. Nothing was changed.\n"
            + counts_block
            + "If you really mean to WIPE the current data and replace it with the "
              "backup, call again with confirm=True and replace_existing=True. "
              "A safety backup of the current data is still made first."
        )

    # Step 3: safety-backup whatever's currently live, if it exists yet.
    safety_backup_path = ""
    if db_path and os.path.exists(db_path):
        safety_result = db_backup_database(db_path, destination_path="")
        if not safety_result.startswith("✅"):
            return f"❌ Could not safety-backup the current database before restoring — aborted, nothing changed.\n{safety_result}"
        safety_backup_path = safety_result.splitlines()[0].replace("✅ Backup saved: ", "")

    # Step 4: the actual restore, via the Backup API (source=backup_path -> dest=db_path).
    dest_dir = os.path.dirname(db_path)
    if dest_dir and not os.path.exists(dest_dir):
        try:
            os.makedirs(dest_dir, exist_ok=True)
        except OSError as exc:
            return f"❌ Could not create destination folder {dest_dir}: {exc}"

    source_conn = sqlite3.connect(backup_path)
    try:
        dest_conn = sqlite3.connect(db_path)
        try:
            source_conn.backup(dest_conn)
        finally:
            dest_conn.close()
    except Exception as exc:
        return (
            f"❌ Restore failed: {exc}\n"
            f"Your previous data is safe in the pre-restore safety backup: {safety_backup_path}"
        )
    finally:
        source_conn.close()

    new_counts = _table_row_counts(db_path)
    lines = [
        f"✅ Database restored from: {backup_path}",
    ]
    if safety_backup_path:
        lines.append(f"   Your previous data was backed up first to: {safety_backup_path}")
    lines.append("")
    lines.append("   Row counts now live:")
    for table in _ALL_TABLES:
        if table in new_counts:
            lines.append(f"     {table}: {new_counts[table]}")
    return "\n".join(lines)


def db_export_to_csv(db_path: str, output_dir: str, tables: list = None) -> str:
    """Write one .csv file per requested table (default: all 8) into
    output_dir. CSV is the lowest-common-denominator format nearly every
    accounting tool and spreadsheet program accepts directly — more
    reliably than a multi-sheet .xlsx for that purpose (spec §12.5).

    Not a QuickBooks-native template — see db_backup_ops.py's module
    docstring and spec §12.5/Phase 8b. This produces AI-Prowler's own
    column headers, not QBO's exact expected import layout.

    tables: optional list of table names (from _ALL_TABLES) to scope the
    export to just what's needed — e.g. ['invoices', 'customers'] for a
    QuickBooks pass — rather than always writing all 8 files.

    Returns a confirmation listing each file written and its row count,
    or a clear error (bad table name, can't create output_dir, etc.).
    """
    all_export_tables = _csv_export_tables()
    if tables:
        wanted = set(tables)
        unknown = wanted - set(_ALL_TABLES)
        if unknown:
            return f"❌ Unknown table name(s): {', '.join(sorted(unknown))}. Valid tables: {', '.join(_ALL_TABLES)}"
        export_tables = [t for t in all_export_tables if t[0] in wanted]
    else:
        export_tables = all_export_tables

    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as exc:
            return f"❌ Could not create output folder {output_dir}: {exc}"

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        written = []
        for table, sheet_name, display_pairs in export_tables:
            file_path = os.path.join(output_dir, f"{sheet_name}.csv")
            rows = conn.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([h for _, h in display_pairs])
                for row in rows:
                    writer.writerow([row[db_col] if db_col in row.keys() else "" for db_col, _ in display_pairs])
            written.append((file_path, len(rows)))
    except sqlite3.Error as exc:
        return f"❌ Could not read from database: {exc}"
    finally:
        conn.close()

    lines = [f"✅ CSV export complete — {len(written)} file(s) in {output_dir}"]
    for file_path, n in written:
        lines.append(f"   {os.path.basename(file_path)}: {n} row(s)")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════
# QuickBooks Online-labeled CSV export (Job Board Architecture Spec Phase
# 8b). IMPORTANT, verified against QuickBooks Online's own current import
# documentation (2026-09): QBO's Settings -> Import Data tool ALWAYS shows
# an interactive "map your fields" screen after upload, regardless of what
# the CSV's own column headers say — there is no way for an export format
# to skip that screen entirely, it's built into QBO's own import wizard.
# What using QBO's own field names as headers DOES do: the one-time
# mapping step becomes much faster and less error-prone, since the
# columns read as QuickBooks' own terminology instead of AI-Prowler's.
# This is a real, honest improvement over the general export_to_csv() —
# just not the "skips the mapping entirely" promise an earlier draft of
# this feature was framed around before this was verified.
# ══════════════════════════════════════════════════════════════════════════

def db_export_quickbooks_csv(db_path: str, output_dir: str) -> str:
    """Export Customers and Invoices as CSV files labeled with QuickBooks
    Online's own field names, so the one-time column-mapping step in QBO's
    Settings -> Import Data wizard is fast and unambiguous. Does NOT skip
    that mapping screen — nothing can, it's part of QBO's own UI — but
    every column should read as an obvious match once you're there.

    Returns a confirmation listing each file and its row count, or a clear
    error if the database can't be read.
    """
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as exc:
            return f"❌ Could not create output folder {output_dir}: {exc}"

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    written = []
    try:
        # Customers -> QuickBooks Online's own Customer-import field names.
        cust_rows = conn.execute("SELECT * FROM customers ORDER BY rowid").fetchall()
        cust_path = os.path.join(output_dir, "QuickBooks_Customers.csv")
        with open(cust_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Display Name", "Company", "First Name", "Last Name",
                "Email", "Phone", "Billing Address Line 1",
                "Billing Address City", "Billing Address State",
                "Billing Address ZIP",
            ])
            for row in cust_rows:
                company = row["company_name"] or ""
                first = row["first_name"] or ""
                last = row["last_name"] or ""
                display_name = company or f"{first} {last}".strip()
                writer.writerow([
                    display_name, company, first, last,
                    row["email"] or "", row["phone"] or "",
                    row["street_address"] or "", row["city"] or "",
                    row["state"] or "", row["zip"] or "",
                ])
        written.append((cust_path, len(cust_rows)))

        # Invoices -> QuickBooks Online's own Invoice-import field names.
        inv_rows = conn.execute("SELECT * FROM invoices ORDER BY rowid").fetchall()
        inv_path = os.path.join(output_dir, "QuickBooks_Invoices.csv")
        with open(inv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Customer", "Invoice Date", "Due Date", "Invoice No", "Amount", "Status"])
            for row in inv_rows:
                writer.writerow([
                    row["customer_name"] or "", row["invoice_date"] or "",
                    row["due_date"] or "", row["invoice_id"] or "",
                    row["total_due"] if row["total_due"] is not None else "",
                    row["payment_status"] or "",
                ])
        written.append((inv_path, len(inv_rows)))
    except sqlite3.Error as exc:
        return f"❌ Could not read from database: {exc}"
    finally:
        conn.close()

    lines = [
        f"✅ QuickBooks-labeled CSV export complete — {len(written)} file(s) in {output_dir}",
    ]
    for file_path, n in written:
        lines.append(f"   {os.path.basename(file_path)}: {n} row(s)")
    lines.append("")
    lines.append(
        "In QuickBooks Online: Settings (gear icon) → Import Data → Customers "
        "(or Invoices) → Browse → select the matching file above. QBO will "
        "still show its own field-mapping screen — that step can't be "
        "skipped — but every column here already reads as QuickBooks' own "
        "field names, so the mapping should be quick."
    )
    return "\n".join(lines)
