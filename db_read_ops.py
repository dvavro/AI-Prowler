"""
db_read_ops.py — Job Board Architecture Spec, Phase 2 (spec §5, §11).

DB-backed replacement for read_job_spreadsheet()'s internals. Same
governing principle as db_write_ops.py (Phase 1): the MCP tool's name,
arguments, and return-value shape stay the same — only the storage swaps
from an openpyxl worksheet scan to parameterized SQL queries against the
Phase 0 schema (spec §4.2). Crew-scoping and date-filter *behavior* are
carried over unchanged; only how the underlying rows are fetched differs.

This module has no dependency on ai_prowler_mcp.py or openpyxl, so it is
independently unit-testable (see tests/mcp_tests/test_db_read_ops_phase2.py),
matching db_write_ops.py's own testing story.
"""

import datetime

from db_access import get_connection
from db_write_ops import (
    CUSTOMERS_HEADER_MAP,
    INVOICES_HEADER_MAP,
    JOBS_HEADER_MAP,
    QUOTES_HEADER_MAP,
    ROUTE_STOPS_HEADER_MAP,
    SERVICE_PRICING_HEADER_MAP,
    SETTINGS_HEADER_MAP,
    TIME_ENTRIES_HEADER_MAP,
    _crew_name_in_cell,
    _parse_hhmm,
    _maybe_sweep_recurring_jobs,
    _maybe_send_stale_customer_digest,
    _maybe_normalize_choice_fields,
    db_read_settings_hard_time_tolerance_min,
)


def _canonical_display_pairs(header_map: dict) -> list:
    """Inverts a *_HEADER_MAP (display_header -> db_col) into an ordered
    list of (db_col, display_header) pairs, one per db_col, keeping the
    FIRST display header seen for each column. Each header_map already
    lists the decorated/parenthesized form before its bare alias (e.g.
    "CustomerID (CUST-####)" before "CustomerID") and preserves the
    sheet's real column order, so this needs no separate maintenance —
    read and write share one source of truth for header text."""
    seen = set()
    pairs = []
    for header, col in header_map.items():
        if col in seen:
            continue
        seen.add(col)
        pairs.append((col, header))
    return pairs


_JOBS_DISPLAY = _canonical_display_pairs(JOBS_HEADER_MAP)
_CUSTOMERS_DISPLAY = _canonical_display_pairs(CUSTOMERS_HEADER_MAP)
_INVOICES_DISPLAY = _canonical_display_pairs(INVOICES_HEADER_MAP)
_QUOTES_DISPLAY = _canonical_display_pairs(QUOTES_HEADER_MAP)
_TIME_ENTRIES_DISPLAY = _canonical_display_pairs(TIME_ENTRIES_HEADER_MAP)
_ROUTE_STOPS_DISPLAY = _canonical_display_pairs(ROUTE_STOPS_HEADER_MAP)
_SETTINGS_DISPLAY = _canonical_display_pairs(SETTINGS_HEADER_MAP)
_SERVICE_PRICING_DISPLAY = _canonical_display_pairs(SERVICE_PRICING_HEADER_MAP)

# sheet_name -> (table, display_pairs, crew_column_or_None). crew_column
# gates READS the same way it already does for Jobs_Schedule: a
# restricted field_crew caller only sees rows whose crew column includes
# their name. Settings/Services_Pricing stay None (fully readable by
# everyone, matching Customers) — the write side is what actually locks
# those two out for field_crew (make_staff_only_check in db_write_ops.py),
# not the read side; seeing current pricing/config is fine, changing it
# isn't.
_READ_DISPATCH = {
    "Jobs_Schedule":     ("jobs", _JOBS_DISPLAY, "crew"),
    "Customers":         ("customers", _CUSTOMERS_DISPLAY, None),
    "Invoices":          ("invoices", _INVOICES_DISPLAY, None),
    "Quotes":            ("quotes", _QUOTES_DISPLAY, None),
    "TimeLog":           ("time_entries", _TIME_ENTRIES_DISPLAY, "crew"),
    "Route_Planner":     ("route_stops", _ROUTE_STOPS_DISPLAY, "crew_id"),
    "Settings":          ("settings", _SETTINGS_DISPLAY, None),
    "Services_Pricing":  ("service_pricing", _SERVICE_PRICING_DISPLAY, None),
}

_DATE_FMTS = ("%Y-%m-%d", "%m/%d/%Y", "%m-%d-%Y", "%d/%m/%Y")


def _parse_date_str(val) -> "datetime.date | None":
    """Parses a stored value (ISO text, or occasionally a full
    'YYYY-MM-DD HH:MM:SS' timestamp) into a date, or None if blank or
    unparseable. Never raises — an unparseable date is treated as
    absent, matching the spreadsheet version's posture."""
    if val is None or str(val).strip() == "":
        return None
    s = str(val).strip()[:10]
    for fmt in _DATE_FMTS:
        try:
            return datetime.datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


# ── Field Ownership & Live-Join overlays (spec §13) ─────────────────────
# Job Board Architecture Spec §13 (Field Ownership & Live-Join Policy).
# Direct fix for the JOB-0007 bug: marking an invoice paid-cash updated
# invoices.payment_status, but the Jobs tab kept reading the job row's
# own separately-stored Payment Status column — no join existed, so a
# refresh could never surface the change; refresh just re-ran the same
# non-join read. These overlays are the single choke point every read
# path (db_read_job_spreadsheet, db_get_jobs_changed_since) now goes
# through, so there is exactly one place a duplicated field's live value
# is decided — not one per caller.
#
# Governing rule: once a row is linked to its owning record (an
# invoice_id on a job, a customer_id on a job/invoice/quote), the row's
# own stored copy of an owned field is never read again — the owning
# record's current value is substituted in-place before anything is
# displayed. Nothing here mutates the database; these are read-time
# overlays on an in-memory dict copy of the row only.

# Case A — invoice-owned fields (§13.1). Mapped from the jobs column
# name to the *live source* column on invoices. `invoice_total` and
# `actual_amount` are case C (§13.3) — dropped from the jobs schema
# entirely, always read live once an invoice exists.
_INVOICE_OWNED_FIELD_SOURCE = {
    "payment_status":   "payment_status",
    "quote_amount":     "subtotal",
    "discount_applied": "discount",
    "service_type":     "service_type",
    "service_details":  "description",
    "invoice_total":    "total_due",
    "actual_amount":    "taxable_amt",   # = subtotal - discount, before tax
}


def _overlay_invoice_owned_fields(conn, job_dict: dict) -> dict:
    """Case A/C (§13.1/§13.3): once a job has an invoice_id, Payment
    Status / Quote Amount / Discount Applied / Service Type / Service
    Details / Invoice Total / Actual Amount are overwritten in-place
    from the linked invoice row — the job's own stored copies (pre-
    invoice drafts, per spec §13.1) are never shown once an invoice
    exists. A dangling invoice_id (row deleted some other way —
    shouldn't happen, spec §9 forbids deletes, but defensive) falls
    back to the job's own copy rather than blanking the field.

    `tax_pct` has no directly stored equivalent on invoices, which
    records a dollar tax amount, not a rate — it's derived here as the
    invoice's own effective rate (tax ÷ taxable_amt), so a per-invoice
    tax_rate override (create_invoice's tax_rate argument) is reflected
    accurately rather than assuming today's default rate applied
    historically. Left absent (not set) when there's nothing to divide
    by, rather than showing a misleading 0%.
    """
    invoice_id = job_dict.get("invoice_id")
    if not invoice_id:
        return job_dict
    inv = conn.execute(
        "SELECT payment_status, subtotal, discount, service_type, description, "
        "total_due, taxable_amt, tax FROM invoices WHERE invoice_id = ?",
        (invoice_id,),
    ).fetchone()
    if inv is None:
        return job_dict
    for job_col, inv_col in _INVOICE_OWNED_FIELD_SOURCE.items():
        job_dict[job_col] = inv[inv_col]
    taxable = inv["taxable_amt"]
    if taxable:
        job_dict["tax_pct"] = round(inv["tax"] / taxable, 4)
    return job_dict


def _overlay_customer_owned_fields(conn, row_dict: dict) -> dict:
    """Case B: once a jobs/invoices/quotes row has a real customer_id,
    Customer Name / Company and Customer Type are overwritten in-place
    from the customers row — a rename in Customers shows up everywhere
    that references them on the next read, with no propagation step.
    Free-text/no-customer-record rows (no customer_id) keep their own
    typed-in name unchanged — nothing to join to, so the local value is
    legitimately authoritative there (spec §13.2)."""
    customer_id = row_dict.get("customer_id")
    if not customer_id:
        return row_dict
    cust = conn.execute(
        "SELECT company_name, customer_type FROM customers WHERE customer_id = ?",
        (customer_id,),
    ).fetchone()
    if cust is None:
        return row_dict
    if cust["company_name"]:
        row_dict["customer_name"] = cust["company_name"]
    row_dict["customer_type"] = cust["customer_type"]
    return row_dict


def compute_customer_rollups(conn, customer_id: str) -> dict:
    """Case D: Last Service Date / Next Sched. Date / Total Jobs
    Completed / Lifetime Revenue are never trusted as stored numbers —
    always computed live from the real jobs/invoices rows for this
    customer. `total_jobs_completed` counts jobs whose Job Status is
    'Complete'; `lifetime_revenue` sums actual amount paid (invoices.
    amount_paid), not billed totals, so it reflects money actually
    collected, not just invoiced."""
    if not customer_id:
        return {
            "last_service_date": None, "next_scheduled_date": None,
            "total_jobs_completed": 0, "lifetime_revenue": 0.0,
        }
    today_iso = datetime.date.today().isoformat()
    job_row = conn.execute(
        "SELECT MAX(service_date) AS last_service, "
        "MIN(CASE WHEN service_date >= ? THEN service_date END) AS next_sched, "
        "SUM(CASE WHEN LOWER(job_status) = 'complete' THEN 1 ELSE 0 END) AS completed "
        "FROM jobs WHERE customer_id = ?",
        (today_iso, customer_id),
    ).fetchone()
    revenue_row = conn.execute(
        "SELECT COALESCE(SUM(amount_paid), 0) AS revenue FROM invoices WHERE customer_id = ?",
        (customer_id,),
    ).fetchone()
    return {
        "last_service_date": job_row["last_service"],
        "next_scheduled_date": job_row["next_sched"],
        "total_jobs_completed": job_row["completed"] or 0,
        "lifetime_revenue": revenue_row["revenue"] or 0.0,
    }


def _apply_live_join_overlays(conn, table: str, rows) -> list:
    """Single choke point: given a list of sqlite3.Row (or dict) results
    for `table`, returns plain dicts with every owned field (spec §13
    cases A-D) replaced by its live value. Called by both
    db_read_job_spreadsheet and db_get_jobs_changed_since so the two
    read paths can never disagree about what a duplicated field's
    current value is."""
    out = [dict(r) for r in rows]
    if table == "jobs":
        out = [_overlay_invoice_owned_fields(conn, r) for r in out]
    if table in ("jobs", "invoices", "quotes"):
        out = [_overlay_customer_owned_fields(conn, r) for r in out]
    if table == "customers":
        for r in out:
            r.update(compute_customer_rollups(conn, r.get("customer_id")))
    return out


def db_read_job_spreadsheet(db_path: str, sheet_name: str = "", filter_date: str = "",
                             max_rows: int = 200, restrict: bool = False,
                             crew_name: str = "") -> str:
    """DB-backed replacement for read_job_spreadsheet(). Same contract:
    defaults to Jobs_Schedule, filters by Service Date (respecting a
    multi-day job's End Date the same way the spreadsheet version did —
    a blank/invalid/earlier End Date is treated as a single-day job
    rather than hiding it), applies the same field_crew row-scoping via
    _crew_name_in_cell, and returns the same "📋 sheet — N row(s)"
    formatted digest with one "  Header: value" line per populated
    column, trimmed to the last populated column across all matched
    rows. Blank/None fields are omitted, exactly as before.
    """
    target_sheet = (sheet_name or "").strip() or "Jobs_Schedule"
    if target_sheet not in _READ_DISPATCH:
        return (
            f"❌ '{target_sheet}' is not yet wired to the DB-backed job store.\n"
            f"Available sheets: {', '.join(_READ_DISPATCH.keys())}"
        )
    table, display_pairs, crew_col = _READ_DISPATCH[target_sheet]

    # Recurring-job auto-generation (2026-09-23 feature, wired in 2026-09-23):
    # db_generate_upcoming_recurring_jobs / _maybe_sweep_recurring_jobs were
    # built and imported here but never actually CALLED anywhere — this is
    # the missing hook that makes "automatic" real. Runs at most once per
    # calendar day (the function's own throttle), before the query below, so
    # a job created by THIS sweep can appear in the very same read that
    # triggered it — matching the feature's own stated intent ("happens the
    # first time anyone opens the Jobs tab or the Board on a given day").
    # Scoped to Jobs_Schedule reads only (covers both the Jobs tab and the
    # Job Board, which both read this sheet) — not every sheet read, since
    # the sweep is real work and every other sheet has no reason to trigger it.
    _maybe_normalize_choice_fields(db_path)      # R-057 one-time cleanup (one SELECT after that)
    if target_sheet == "Jobs_Schedule":
        _maybe_sweep_recurring_jobs(db_path)
        _maybe_send_stale_customer_digest(db_path)

    max_rows = min(max_rows, 500)

    date_filter = None
    if filter_date:
        fd = filter_date.strip().lower()
        if fd == "today":
            date_filter = datetime.date.today()
        else:
            date_filter = _parse_date_str(filter_date)
            if date_filter is None:
                return f"❌ Could not parse filter_date '{filter_date}'. Use MM/DD/YYYY."

    conn = get_connection(db_path)
    try:
        # TimeLog and Invoices specifically: most-recent-first. Every other
        # sheet keeps its original oldest-first order (unchanged, to avoid any
        # risk to callers/tests relying on it) — but TimeLog is the one sheet
        # the Jobs PWA now defaults to showing "the last 7 days" for, and a
        # table that's grown past max_rows with the OLD ascending order would
        # have truncated at the OLDEST 500 rows, silently dropping this
        # week's entries entirely rather than the years-old ones nobody's
        # asking to see. Real bug found live while wiring that feature.
        # Invoices joins the same rule (2026-09-23): its own Jobs PWA view now
        # defaults to "All time" rather than a 7-day window, but a truncation
        # dropping the NEWEST invoices — including anything recently gone
        # unpaid — would be exactly backwards there too.
        order = "rowid DESC" if table in ("time_entries", "invoices") else "rowid"
        rows = conn.execute(f"SELECT * FROM {table} ORDER BY {order}").fetchall()

        filtered = []
        _wd = None                       # Settings → Working Days, read once if needed
        for row in rows:
            if date_filter is not None and table == "jobs":
                start = _parse_date_str(row["service_date"])
                if start is None:
                    continue
                end = _parse_date_str(row["end_date"]) or start
                if end < start:
                    end = start
                if _wd is None and date_filter != start:
                    from db_write_ops import working_days_conn
                    _wd = working_days_conn(conn)
                if date_filter > end:
                    # R-058 overrun: a job still open past its planned end is
                    # still worked on the following working days (to the horizon)
                    from db_write_ops import job_day_number
                    if not job_day_number(start.isoformat(), end.isoformat(),
                                          date_filter.isoformat(),
                                          status=row["job_status"] or "", days=_wd):
                        continue
                elif not (start <= date_filter <= end):
                    continue
                # R-058: non-working days inside a multi-day job's span aren't
                # worked (Working Days setting, default Mon–Fri; 2026-10-02)
                if date_filter != start and date_filter.weekday() not in _wd:
                    continue

            if restrict and crew_col:
                row_crew = str(row[crew_col] or "").strip().lower()
                if not _crew_name_in_cell(row_crew, crew_name):
                    continue

            filtered.append(row)
            if len(filtered) >= max_rows:
                break

        # Spec §13: replace duplicated fields with their live value before
        # anything is displayed — single source of truth, no propagation
        # step, no stale copy for a refresh to ever surface.
        filtered = _apply_live_join_overlays(conn, table, filtered)
    finally:
        conn.close()

    if not filtered:
        msg = f"📋 No rows found in sheet '{target_sheet}'"
        if date_filter:
            msg += f" for date {date_filter.strftime('%m/%d/%Y')}"
        if restrict:
            msg += " assigned to you"
        return msg + "."

    # Trim to the last populated display column across every matched row —
    # same rule as the spreadsheet version, now checked against dict keys
    # instead of cell indices.
    last_used = 0
    for row in filtered:
        for i in range(len(display_pairs) - 1, -1, -1):
            db_col, _ = display_pairs[i]
            val = row[db_col] if db_col in row.keys() else None
            if val is not None and str(val).strip():
                last_used = max(last_used, i)
                break
    trimmed_pairs = display_pairs[: last_used + 1]

    lines = [
        f"📋 {target_sheet}",
        f"   {len(filtered)} row(s)" + (f" for {date_filter.strftime('%m/%d/%Y')}" if date_filter else ""),
        "─" * 60,
    ]
    for row in filtered:
        lines.append("")
        for db_col, display_name in trimmed_pairs:
            val = row[db_col] if db_col in row.keys() else None
            if val is None or str(val).strip() == "":
                continue
            # Dates are stored as ISO text; display as MM/DD/YYYY to match
            # the spreadsheet version's Excel-native-date formatting.
            if "date" in display_name.lower():
                parsed = _parse_date_str(val)
                if parsed is not None:
                    val = parsed.strftime("%m/%d/%Y")
            lines.append(f"  {display_name}: {val}")
    lines.append("")
    lines.append("─" * 60)
    lines.append("✅ Read complete. Use update_job_spreadsheet() to write changes back.")
    return "\n".join(lines)


# ── get_sheet_columns ─────────────────────────────────────────────────────
# Job Board Architecture Spec — Database-tab expansion (2026-09-12).
# Real bug found while wiring the Database tab's generic add/edit form:
# get_sheet_columns() was still fully openpyxl-based (_resolve_job_
# spreadsheet_path, tries to open the now-obsolete .xlsx file) — meaning
# it had been silently failing for EVERY sheet since Phase 1, not just
# the four newly-wired ones. The Jobs PWA's own JS falls back to
# Object.keys(rowData) when this fails, so EDITING an existing row mostly
# still worked (whatever fields that row happened to have populated), but
# ADDING a new row (rowData={}) got zero fields at all.
#
# No native "Excel data-validation dropdown" concept exists in SQLite, so
# the DROPDOWN lines below are a small hand-maintained map of the columns
# that were genuinely dropdown-backed in the original template, sourced
# from values already used elsewhere in this codebase (Invoices' Payment
# Status list matches the Jobs PWA's own jfPayment <select> options
# verbatim; Quotes' Status list and Customers' three enum columns match
# the values create_customer's/create_quote's own docstrings already
# document) — not invented here.
_KNOWN_DROPDOWNS = {
    "Customers": {
        "Customer Type Comm/Res": ["Commercial", "Residential"],
        "Frequency": ["Weekly", "Biweekly", "Monthly", "Bi-Monthly",
                       "Quarterly", "Semi-Annually", "Annually", "One-time"],
        "Status Active/Inactive": ["Active", "Inactive"],
    },
    "Invoices": {
        "Payment Status": ["Unpaid", "Partial", "Paid", "Cash", "Check",
                             "Zelle", "Venmo", "Other"],
    },
    "Quotes": {
        "Status (Open/Approved/Declined)": ["Open", "Approved", "Declined"],
    },
}


def db_get_sheet_columns(db_path: str, sheet_name: str) -> str:
    """DB-backed replacement for get_sheet_columns(). Same output text
    protocol the Jobs PWA's _getSheetColumns() JS already parses:
        COLUMNS: <col1> | <col2> | <col3> | ...
        DROPDOWN: <column name> = <opt1>,<opt2>,<opt3>
    Column list and order come straight from the same canonical display-
    pairs _READ_DISPATCH already uses for reads — one source of truth,
    so this can never drift out of sync with what read_job_spreadsheet()/
    get_board_updates() actually return for a given sheet.
    """
    target_sheet = (sheet_name or "").strip()
    if target_sheet not in _READ_DISPATCH:
        return (
            f"❌ '{target_sheet}' is not yet wired to the DB-backed job store.\n"
            f"Available sheets: {', '.join(_READ_DISPATCH.keys())}"
        )
    _, display_pairs, _ = _READ_DISPATCH[target_sheet]
    cols = [display_name for _, display_name in display_pairs]

    lines = [f"COLUMNS: {' | '.join(cols)}"]
    for col, opts in _KNOWN_DROPDOWNS.get(target_sheet, {}).items():
        if col in cols:
            lines.append(f"DROPDOWN: {col} = {','.join(opts)}")
    return "\n".join(lines)


def _compute_hard_time_violation(conn, db_path: str, job_row) -> tuple:
    """Job Board Architecture Spec §14.8/§14.11 Phase 13 — standing
    hard-time-violation flag for a Job Board card. Live-computed at read
    time (never stored on `jobs`), same "overlay, don't duplicate" posture
    as the invoice/customer-owned fields in §13: comparing a
    schedule_type='hard' job's committed start_time against its CURRENT
    route-derived ETA means the flag can never drift out of sync with the
    route the way a stored/copied value could.

    Only meaningful for a hard job with a start_time; anything else
    returns (False, None) — a soft job's own placement is never a
    "violation" of anything it committed to.

    Looks up the job's most recently written route_stops row for its own
    service_date (a job can only ever be on one crew's route for a given
    date — see §6.4's per-(route_date, crew_id) partitioning — so this is
    unambiguous). No route built yet for this job → (False, None): an
    as-yet-unrouted hard job isn't a violation, it's simply not evaluated
    yet, matching this system's "advisory, never invented" posture
    elsewhere (e.g. DRIVE TIME UNKNOWN never becomes a false positive).

    Lunch-pause extensions are already folded into route_stops.eta by the
    §14.4/§14.7 timeline math (db_route_ops._build_day_timeline /
    db_write_ops.db_reorder_route_stop), so this needs no separate
    lunch-specific check — comparing the stored ETA against the commitment
    is already comparing post-lunch reality.

    Returns (is_violation: bool, detail: str | None) — detail is always
    populated once a route ETA exists (even within tolerance), so a
    caller that wants to show "on track" context has it; detail is None
    only when there's nothing to compare against yet.
    """
    if str(job_row["schedule_type"] or "").strip().lower() != "hard":
        return False, None
    committed = _parse_hhmm(job_row["start_time"] if "start_time" in job_row.keys() else None)
    if committed is None:
        return False, None

    stop = conn.execute(
        "SELECT eta FROM route_stops WHERE job_id = ? AND route_date = ? "
        "ORDER BY last_edited_at DESC LIMIT 1",
        (job_row["job_id"], job_row["service_date"] if "service_date" in job_row.keys() else None),
    ).fetchone()
    if stop is None or not stop["eta"]:
        return False, None

    actual = _parse_hhmm(stop["eta"])
    if actual is None:
        return False, None

    drift_min = round(abs((actual - committed).total_seconds()) / 60.0)
    tolerance_min = db_read_settings_hard_time_tolerance_min(db_path)
    is_violation = drift_min > tolerance_min
    detail = (
        f"Committed {job_row['start_time']}, route currently arrives {stop['eta']} "
        f"({drift_min} min off, tolerance is {tolerance_min} min)."
    )
    return is_violation, detail


def db_visible_job_ids(db_path: str, restrict: bool = False, crew_name: str = "") -> list:
    """R-045 (was gap G-12, 2026-09-27): every JobID the caller may see right
    now, with EXACTLY the crew rule db_get_jobs_changed_since applies.

    The Job Board's 60-second poll only upserts rows that changed and are
    visible, so a job that stops being visible (re-assigned to another crew,
    or deleted) never came back to tell an open Board to drop it — it stayed
    until a manual refresh. The Board now also asks for this list and drops
    any card not on it. Cheap: one column pair, no row formatting."""
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT job_id, crew FROM jobs").fetchall()
    finally:
        conn.close()
    if restrict:
        rows = [r for r in rows if _crew_name_in_cell(str(r["crew"] or "").strip().lower(), crew_name)]
    return [r["job_id"] for r in rows if r["job_id"]]


def db_get_jobs_changed_since(db_path: str, since_iso: str, sheet_name: str = "",
                               restrict: bool = False, crew_name: str = "") -> list:
    """Job Board Architecture Spec Phase 3 (spec §6.1, §11): backing query
    for the admin Job Board's live-update polling — `WHERE last_edited_at
    > ?`. Returns a list of dicts (canonical display headers, same
    mapping db_read_job_spreadsheet uses) for every row on the sheet
    whose `last_edited_at` is strictly after `since_iso`, so the caller
    can poll every 60 seconds and only receive what actually changed.

    Unlike db_read_job_spreadsheet, this returns raw structured data
    (for a JS client to render into board cards), not a formatted text
    digest, and does NOT trim to the last populated column — a partial
    update (e.g. only Job Status changed) should still return every
    field so the client can refresh a card in place without guessing
    which fields it's missing.

    Crew-scoping matches read_job_spreadsheet exactly: applies to any
    sheet with a crew column in _READ_DISPATCH when the caller passes
    restrict=True (the server enables it for Jobs_Schedule, TimeLog and
    Route_Planner — R-039), never to Customers (send_email/send_sms name lookups
    depend on Customers staying fully readable).
    """
    target_sheet = (sheet_name or "").strip() or "Jobs_Schedule"
    if target_sheet not in _READ_DISPATCH:
        raise ValueError(
            f"'{target_sheet}' is not yet wired to the DB-backed job store. "
            f"Available sheets: {', '.join(_READ_DISPATCH.keys())}"
        )
    table, display_pairs, crew_col = _READ_DISPATCH[target_sheet]

    # Recurring-job auto-generation (2026-09-23) — same hook as
    # db_read_job_spreadsheet above, and the more important of the two: the
    # Job Board polls THIS function (get_board_updates), not
    # db_read_job_spreadsheet, every 60 seconds — without this, a job
    # created by the sweep would only ever show up once someone happened to
    # view the plain Jobs tab, defeating the Board's whole "appears the same
    # as any job an employee or admin added" requirement. Runs at most once
    # per calendar day (the function's own throttle); a job it just created
    # has a last_edited_at newer than any since_iso the poll passes, so it's
    # picked up by this very same call, same as an admin's own edit would be.
    _maybe_normalize_choice_fields(db_path)      # R-057 one-time cleanup (one SELECT after that)
    if target_sheet == "Jobs_Schedule":
        _maybe_sweep_recurring_jobs(db_path)
        _maybe_send_stale_customer_digest(db_path)

    conn = get_connection(db_path)
    try:
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE last_edited_at > ? ORDER BY last_edited_at ASC",
            (since_iso,),
        ).fetchall()

        # Spec §13.5 follow-up: a job whose invoice-owned fields changed
        # (e.g. Payment Status marked Cash on the invoice) doesn't touch
        # jobs.last_edited_at at all — only invoices.last_edited_at moves.
        # Without this, the polling board would never see that change
        # until something else about the job also happened to change.
        # Pull in any job whose linked invoice changed since the last
        # poll, even if the job row itself didn't.
        if table == "jobs":
            seen_ids = {r["job_id"] for r in rows}
            via_invoice = conn.execute(
                "SELECT j.* FROM jobs j "
                "JOIN invoices i ON j.invoice_id = i.invoice_id "
                "WHERE i.last_edited_at > ?",
                (since_iso,),
            ).fetchall()
            for r in via_invoice:
                if r["job_id"] not in seen_ids:
                    rows = list(rows) + [r]
                    seen_ids.add(r["job_id"])

            # Spec §14.8/§14.11 Phase 13 follow-up, same class of gap as
            # the invoice join above: a route approval or reorder writes
            # route_stops, not the job's own row — a HARD job's committed
            # time never moves, so its last_edited_at doesn't either, even
            # though its violation status (§14.8) may have just flipped as
            # a direct side effect of that route-side write. Without this,
            # the board would never learn a hard job started (or stopped)
            # violating its commitment until something else about the job
            # also happened to change. Scoped to hard jobs only — a soft
            # job's route_stops row changes constantly during ordinary
            # route building and carries no board-visible commitment to
            # violate, so pulling it in here would just be noise.
            via_route = conn.execute(
                "SELECT j.* FROM jobs j "
                "JOIN route_stops rs ON rs.job_id = j.job_id "
                "WHERE LOWER(TRIM(COALESCE(j.schedule_type, ''))) = 'hard' AND rs.last_edited_at > ?",
                (since_iso,),
            ).fetchall()
            for r in via_route:
                if r["job_id"] not in seen_ids:
                    rows = list(rows) + [r]
                    seen_ids.add(r["job_id"])

        if restrict and crew_col:
            rows = [r for r in rows
                    if _crew_name_in_cell(str(r[crew_col] or "").strip().lower(), crew_name)]

        # Spec §13: same live-join overlay as db_read_job_spreadsheet —
        # one choke point, so polling and full reads never disagree.
        rows = _apply_live_join_overlays(conn, table, rows)

        # Spec §14.8/§14.11 Phase 13 — standing hard-time-violation badge,
        # computed here (still inside the connection) rather than after
        # `conn` closes below.
        violations = {}
        if table == "jobs":
            for row in rows:
                violations[row["job_id"]] = _compute_hard_time_violation(conn, db_path, row)
    finally:
        conn.close()

    out = []
    for row in rows:
        record = {}
        for db_col, display_name in display_pairs:
            val = row[db_col] if db_col in row.keys() else None
            if val is not None and str(val).strip() != "":
                record[display_name] = val
        record["_last_edited_at"] = row["last_edited_at"] if "last_edited_at" in row.keys() else None
        # Settings has no `version` column at all (see db_schema.py) —
        # omit _version rather than raise, so a Database-tab client can
        # still poll Settings even though there's nothing to conflict-
        # detect against there.
        if "version" in row.keys():
            record["_version"] = row["version"]
        # Spec §14.8/§14.11 Phase 13 — standing hard-time-violation badge.
        # Computed fresh on every poll response (never stored), so a
        # violation that gets resolved (route rebuilt, job re-committed)
        # stops showing on the very next poll with no separate "clear the
        # flag" step anywhere — the same "advisory, live, never a stale
        # copy" posture as every other computed overlay in this system.
        if table == "jobs":
            is_violation, detail = violations.get(row["job_id"], (False, None))
            record["_hard_time_violation"] = is_violation
            record["_hard_time_violation_detail"] = detail
        out.append(record)
    return out


# ── get_ar_aging_report ──────────────────────────────────────────────────

_AR_DATE_FMTS = ("%Y-%m-%d", "%m/%d/%Y", "%m-%d-%Y")


def _parse_ar_date(v) -> "datetime.date | None":
    if not v:
        return None
    s = str(v).strip()[:10]
    for fmt in _AR_DATE_FMTS:
        try:
            return datetime.datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def db_get_ar_aging_report(db_path: str, as_of_date: str = "today") -> str:
    """DB-backed replacement for get_ar_aging_report(). Same bucket
    definitions (Current / 1-30 / 31-60 / 61-90 / 90+ days overdue by
    Due Date), same PAID/zero-balance skip rule, same report layout —
    only the row source changes, from an openpyxl Invoices-sheet scan to
    a SELECT against the `invoices` table. Not crew-scoped, matching the
    original (an AR aging report is an admin-level financial view, not a
    per-technician one)."""
    aod_str = (as_of_date or "").strip().lower()
    if aod_str == "today" or not aod_str:
        as_of = datetime.date.today()
    else:
        as_of = _parse_ar_date(as_of_date)
        if as_of is None:
            return f"❌ Could not parse as_of_date '{as_of_date}'."

    buckets = {
        "current": {"label": "Current (not yet due)", "rows": [], "total": 0.0},
        "1_30":    {"label": "1 – 30 days overdue",   "rows": [], "total": 0.0},
        "31_60":   {"label": "31 – 60 days overdue",  "rows": [], "total": 0.0},
        "61_90":   {"label": "61 – 90 days overdue",  "rows": [], "total": 0.0},
        "over_90": {"label": "90+ days overdue",      "rows": [], "total": 0.0},
    }

    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT * FROM invoices ORDER BY rowid").fetchall()
    finally:
        conn.close()

    total_outstanding = 0.0
    rows_processed = 0

    for row in rows:
        pmt_status = str(row["payment_status"] or "").strip().upper()
        if pmt_status == "PAID":
            continue

        try:
            balance = float(row["balance_due"]) if row["balance_due"] is not None else 0.0
        except (TypeError, ValueError):
            balance = 0.0
        if balance <= 0:
            continue

        due_date = _parse_ar_date(row["due_date"])
        inv_id = str(row["invoice_id"] or "—")
        customer = str(row["customer_name"] or "—")

        if due_date is None:
            bucket_key = "current"
        else:
            days_over = (as_of - due_date).days
            if days_over <= 0:
                bucket_key = "current"
            elif days_over <= 30:
                bucket_key = "1_30"
            elif days_over <= 60:
                bucket_key = "31_60"
            elif days_over <= 90:
                bucket_key = "61_90"
            else:
                bucket_key = "over_90"

        days_str = (f"{(as_of - due_date).days}d overdue" if due_date and (as_of - due_date).days > 0
                    else ("due " + due_date.strftime("%m/%d") if due_date else "no due date"))
        row_line = f"  {inv_id:<12}  {customer:<28}  ${balance:>9,.2f}   {days_str}"

        buckets[bucket_key]["rows"].append(row_line)
        buckets[bucket_key]["total"] += balance
        total_outstanding += balance
        rows_processed += 1

    if rows_processed == 0:
        return (
            f"✅ No outstanding invoices as of {as_of.strftime('%m/%d/%Y')}.\n"
            "   All invoices are paid or have zero balance."
        )

    lines = [
        "💰 AR AGING REPORT",
        f"   As of: {as_of.strftime('%m/%d/%Y')}",
        "═" * 60,
        "",
    ]

    _BUCKET_ORDER = ["over_90", "61_90", "31_60", "1_30", "current"]
    for bkey in _BUCKET_ORDER:
        b = buckets[bkey]
        if not b["rows"]:
            continue
        lines.append(f"  {'⚠️' if bkey != 'current' else '📋'}  {b['label']}")
        lines.append(f"  {'─' * 56}")
        lines.append(f"  {'Invoice':<12}  {'Customer':<28}  {'Balance':>11}   Days")
        for r in b["rows"]:
            lines.append(r)
        lines.append(f"  {'─' * 56}")
        lines.append(f"  {'Subtotal':<42}  ${b['total']:>9,.2f}")
        lines.append("")

    lines += [
        "═" * 60,
        f"  TOTAL OUTSTANDING:              ${total_outstanding:>12,.2f}",
        "═" * 60,
    ]

    if buckets["over_90"]["total"] > 0 or buckets["61_90"]["total"] > 0:
        lines.append("")
        lines.append("  🚨 Action recommended: send payment reminders for 60+ day items.")
        lines.append("     Ask: \"Send payment reminders for all overdue invoices\"")

    return "\n".join(lines)
