"""
db_write_ops.py — Job Board Architecture Spec, Phase 1 (spec §5, §11).

DB-backed replacements for the write tools' *internals*. Per the spec's
governing principle: tool names, arguments, and return-value shapes stay
the same — only "load workbook -> find row -> mutate cell -> save
workbook" becomes "open a transaction -> UPDATE/INSERT the specific
row(s) -> commit." The validation/crew-scoping/ID-generation/audit logic
already living in ai_prowler_mcp.py is preserved as-is; this module only
supplies the storage swap.

Ported from (line numbers as of the V9.1.x work directory inspected on
2026-09-12): _append_sheet_row_impl (create_customer/create_quote's
shared engine, ~4992-5189), create_job, update_job_spreadsheet
(~4368-4732), _job_crew_scope/_crew_name_in_cell/
_server_customer_in_crew_scope (~4146-4293), _actor_display_name
(~19439), _log_time_entry_impl (~9951-10324).

What is copied verbatim vs. re-derived:
- `_crew_name_in_cell` is copied byte-for-byte: it is pure string logic
  with no storage dependency (spec §4.3 — "moves over unchanged").
- `_FIELD_CREW_LOCKED_CUSTOMER_HEADERS` is the same header set as
  `_FIELD_CREW_LOCKED_CUSTOMER_FIELDS`, unchanged.
- `db_customer_in_crew_scope` is the DB-backed replacement for
  `_server_customer_in_crew_scope(wb, ...)` — same rule (a customer is
  in a restricted crew member's scope iff a jobs row links that
  customer_id to a crew cell containing their name), now a SELECT
  against the `jobs` table instead of an openpyxl worksheet scan.
- `_job_crew_scope(ctx, fp)` and `_actor_display_name(ctx)` are NOT
  reimplemented here — they depend on ctx/request-state plumbing that
  belongs in ai_prowler_mcp.py, and per spec §4.3 that logic sits above
  storage and doesn't need to change. This module accepts their outputs
  (restrict/crew_name, actor display name) as plain arguments, so the
  real integration point is: the existing @mcp.tool() function bodies
  call _job_crew_scope()/_actor_display_name() exactly as they do
  today, then hand the results to the functions below instead of doing
  their own openpyxl load/mutate/save.

This module has no dependency on ai_prowler_mcp.py or openpyxl, so it
is independently unit-testable (see tests/mcp_tests/test_db_write_ops_phase1.py).
"""

import calendar
import datetime

import requests

from db_access import get_connection, transaction, utcnow_iso


# ── Header-name -> DB-column maps ───────────────────────────────────────
# Keyed by the NORMALIZED header (real newlines replaced with a single
# space) — the same normalization ai_prowler_mcp.py's header-detection
# code already applies, so callers may pass either "Job\nStatus" or
# "Job Status" and both resolve here exactly as they do against the
# live spreadsheet today. Header text captured directly from
# AI-Prowler_Job_Tracker.xlsx row 2 of each sheet (verified 2026-09-12).

def _normalize_header(raw: str) -> str:
    return " ".join(str(raw).replace("\n", " ").split())


CUSTOMERS_HEADER_MAP = {
    "CustomerID (CUST-####)": "customer_id",
    "CustomerID": "customer_id",
    "Customer Type Comm/Res": "customer_type",
    "Company Name": "company_name",
    "First Name": "first_name",
    "Last Name": "last_name",
    "Phone": "phone",
    "Email": "email",
    "Street Address": "street_address",
    "City": "city",
    "State": "state",
    "ZIP": "zip",
    "Latitude (AI Geocode)": "latitude",
    "Longitude (AI Geocode)": "longitude",
    "Service Type(s) Win/Press/Both": "service_types",
    "Frequency": "frequency",
    "Preferred Day(s)": "preferred_days",
    "Pref. Time Window": "preferred_time_window",
    "Avg Job Duration (min)": "avg_job_duration_min",
    "Standard Quote ($)": "standard_quote",
    "Discount (%)": "discount_pct",
    "Net Price ($)": "net_price",
    "Last Service Date": "last_service_date",
    "Next Sched. Date": "next_scheduled_date",
    "Total Jobs Completed": "total_jobs_completed",
    "Lifetime Revenue ($)": "lifetime_revenue",
    "Gate Code / Access Notes": "gate_code_notes",
    "On-Site Contact": "onsite_contact",
    "Status Active/Inactive": "status",
    "Created By": "created_by",
    "Last Edited By": "last_edited_by",
    "Last Edited At": "last_edited_at",
    # R-034 (2026-09-26, E2E DB-06): shown on reads so the Jobs app's Edit
    # form can send it back as expected_version — without it a stale edit
    # silently overwrote another device's change. Never writable (db_update_row
    # skips "version").
    "Version": "version",
}

JOBS_HEADER_MAP = {
    "JobID (JOB-####)": "job_id",
    "CustomerID (Customers!A)": "customer_id",
    "CustomerID": "customer_id",
    "Customer Name / Company": "customer_name",
    "Customer Type": "customer_type",
    "Street Address": "street_address",
    "City": "city",
    "State": "state",
    "ZIP": "zip",
    "Latitude (AI Geocode)": "latitude",
    "Longitude (AI Geocode)": "longitude",
    "Service Date": "service_date",
    "End Date (blank = single-day job)": "end_date",
    "Day of Week": "day_of_week",
    "Start Time": "start_time",
    "End Time": "end_time",
    "Service Type": "service_type",
    "Service Details / Notes": "service_details",
    "Crew / Technician": "crew",
    "Est. Duration": "est_duration",
    "Est. Duration Unit": "est_duration_unit",
    "Actual Duration": "actual_duration",
    "Actual Duration Unit": "actual_duration_unit",
    "Route Stop #": "route_stop_number",
    "Route Map URL": "route_map_url",
    "Weather Check": "weather_check",
    "Job Status": "job_status",
    "Quote Amount ($)": "quote_amount",
    "Discount Applied ($)": "discount_applied",
    "Actual Amount ($) =Quote-Discount": "actual_amount",
    "Tax (Tax%)": "tax_pct",
    "Invoice Total ($)": "invoice_total",
    "Recurrence": "recurrence",
    "InvoiceID (INV-####)": "invoice_id",
    "Invoice Sent Date": "invoice_sent_date",
    "Payment Status": "payment_status",
    "Schedule Type (Hard/Soft)": "schedule_type",
    "Schedule Type": "schedule_type",
    # Mileage/routing follow-up (2026-09-20): the customer's actually-
    # agreed schedule — an ordinary editable field like any other here,
    # deliberately NOT touched by approve_route_schedule/
    # unapprove_route_schedule (those two read/write Start Time/End Time
    # only). Changed only via a genuine manual edit through this same
    # generic mechanism, or an explicit Claude instruction to update it.
    "Original Start Time": "original_start_time",
    "Original End Time": "original_end_time",
    "Created By": "created_by",
    "Last Edited By": "last_edited_by",
    "Last Edited At": "last_edited_at",
}

QUOTES_HEADER_MAP = {
    "QuoteID (QTE-####)": "quote_id",
    "CustomerID": "customer_id",
    "Customer Name / Company": "customer_name",
    "Customer Type": "customer_type",
    "Address": "address",
    "City": "city",
    "Quote Date": "quote_date",
    "Valid Until": "valid_until",
    "Service Type": "service_type",
    "Service Description": "service_description",
    "Sq Ft / Units": "sq_ft_units",
    "Unit Price ($)": "unit_price",
    "Labor Cost ($)": "labor_cost",
    "Materials ($)": "materials",
    "Subtotal ($)": "subtotal",
    "Discount (%)": "discount_pct",
    "Discount Amt ($)": "discount_amt",
    "Tax (Tax%) ($)": "tax",
    "QUOTE TOTAL ($)": "quote_total",
    "Status (Open/Approved/Declined)": "status",
    "Created By": "created_by",
    "Last Edited By": "last_edited_by",
    "Last Edited At": "last_edited_at",
    "Version": "version",   # R-034 — see CUSTOMERS_HEADER_MAP
}

INVOICES_HEADER_MAP = {
    "InvoiceID (INV-####)": "invoice_id",
    "JobID (JOB-####)": "job_id",
    "CustomerID": "customer_id",
    "Customer Name / Company": "customer_name",
    "Customer Type": "customer_type",
    "Invoice Date": "invoice_date",
    "Due Date (Net 30)": "due_date",
    "Service Date": "service_date",
    "Service Type": "service_type",
    "Description": "description",
    "Subtotal ($)": "subtotal",
    "Discount ($)": "discount",
    "Taxable Amt ($) =K-L": "taxable_amt",
    "Tax 7% ($) =M*0.07": "tax",
    "TOTAL DUE ($) =M+N": "total_due",
    "Amount Paid ($)": "amount_paid",
    "Balance Due ($) =O-P": "balance_due",
    "Payment Status": "payment_status",
    "Payment Date": "payment_date",
    "Payment Method": "payment_method",
    "Days Overdue (AI-AR)": "days_overdue",
    "Created By": "created_by",
    "Last Edited By": "last_edited_by",
    "Last Edited At": "last_edited_at",
    "Version": "version",   # R-034 — see CUSTOMERS_HEADER_MAP
}

TIME_ENTRIES_HEADER_MAP = {
    "EntryID": "entry_id",
    "JobID (JOB-####)": "job_id",
    "JobID": "job_id",
    "Customer Name / Company": "customer_name",
    "Entry Date": "entry_date",
    "Clock In": "clock_in",
    "Clock Out": "clock_out",
    "Elapsed (min)": "elapsed_min",
    "Crew / Technician": "crew",
    "Logged By (User ID)": "crew_user_id",
    "Notes": "notes",
    "Clock In GPS": "clock_in_gps",
    "Clock Out GPS": "clock_out_gps",
    "Clock In Map URL": "clock_in_map_url",
    "Clock Out Map URL": "clock_out_map_url",
    "Created By": "created_by",
    "Last Edited By": "last_edited_by",
    "Last Edited At": "last_edited_at",
    "Version": "version",
}

ROUTE_STOPS_HEADER_MAP = {
    "ID": "id",
    "Route Date": "route_date",
    "Crew / Technician": "crew_id",
    "Stop #": "stop_number",
    "JobID (JOB-####)": "job_id",
    "JobID": "job_id",
    "CustomerID": "customer_id",
    "Address": "address",
    "Latitude": "latitude",
    "Longitude": "longitude",
    "ETA": "eta",
    "Drive Min": "leg_drive_min",
    "Drive Miles": "leg_drive_miles",
    "Map URL": "map_url",
    "Created By": "created_by",
    "Last Edited By": "last_edited_by",
    "Last Edited At": "last_edited_at",
    "Version": "version",
}

# No ID-prefix/digits scheme (settings isn't an auto-numbered business
# record — it's a plain key/value config store, keyed by whatever string
# the caller supplies, e.g. "default_tax_rate"), and correspondingly no
# created_by/version columns either (see db_schema.py) — db_set_setting()
# below is a dedicated upsert, not a db_create_row/db_update_row caller.
SETTINGS_HEADER_MAP = {
    "Setting": "key",
    "Value": "value",
    "Notes": "notes",
    "Last Edited By": "last_edited_by",
    "Last Edited At": "last_edited_at",
}

# service_code is caller-supplied (e.g. "WIN", "PRESS-DRIVE"), not auto-
# numbered — db_create_service_pricing() below handles creation directly
# rather than through db_create_row's ID-generation path. No created_by
# column on this table (see db_schema.py) — only last_edited_by/at and
# version, matching what db_create_service_pricing() actually stamps.
SERVICE_PRICING_HEADER_MAP = {
    "Service Code": "service_code",
    "Category": "category",
    "Name": "name",
    "Base Price ($)": "base_price",
    "Unit Basis": "unit_basis",
    "Min Charge ($)": "min_charge",
    "Commission Multiplier": "comm_multiplier",
    "Tax Category": "tax_category",
    "Notes": "notes",
    "Last Edited By": "last_edited_by",
    "Last Edited At": "last_edited_at",
    "Version": "version",
}

# v9.1.x — Customers-sheet fields a restricted field_crew member may NOT
# write, even for a customer already in their own scope. Copied verbatim
# from _FIELD_CREW_LOCKED_CUSTOMER_FIELDS.
_FIELD_CREW_LOCKED_CUSTOMER_HEADERS = frozenset({
    _normalize_header(h) for h in (
        "CustomerID", "CustomerID (CUST-####)",
        "Frequency",
        "Standard Quote ($)",
        "Discount (%)",
        "Net Price ($)",
        "Total Jobs Completed",
        "Lifetime Revenue ($)",
        "Status Active/Inactive",
    )
})

# ── Field Ownership & Live-Join Policy (spec §13) — silent field drops ──
# Once a row is linked to its owning record, the row's own copy of an
# owned field is silently DROPPED from any write that touches it, rather
# than rejecting the whole update. This is deliberately not a hard
# denial: the Jobs PWA's edit forms resubmit every field they loaded —
# including these now-read-only, overlay-populated ones — even when the
# person only changed something else entirely. The first live test of
# this (JOB-0008 / INV-0003, 2026-09-14) hit exactly this: saving a
# Payment Status / Payment Method change on the invoice was rejected
# outright, purely because the untouched Customer Name field rode along
# in the same form submission. A hard block on the mere PRESENCE of a
# locked header in the payload made ordinary edits to an invoiced job or
# a customer-linked row impossible in the actual app. Case C/D fields
# (the seven dropped columns) don't need any of this — they're already
# handled the same silent-drop way by `_split_computed_only`, since
# those columns don't physically exist to write to in the first place.

# Case A — once jobs.invoice_id is set, these are invoice-only.
_INVOICE_OWNED_JOB_DB_COLS = (
    "payment_status", "quote_amount", "discount_applied",
    "service_type", "service_details",
)

# Case B — once a jobs/invoices/quotes row has a real customer_id, these
# are Customers-only (same two columns across all three tables).
_CUSTOMER_OWNED_DB_COLS = ("customer_name", "customer_type")


def _split_field_ownership(table: str, set_cols: dict, row, header_map: dict) -> list:
    """Spec §13 Cases A/B enforcement. Silently removes any column from
    `set_cols` that is now owned by a different record, given the
    specific row being updated (so "has an invoice_id?" / "has a
    customer_id?" reflects this row, not a blanket rule). Mutates
    `set_cols` in place — the caller's SQL is built from whatever
    remains, so a dropped field is simply never written, and anything
    else legitimately requested in the same call still goes through.

    Returns a list of (header_text, owner_description) pairs for the
    caller to fold into an informational note in its response — this is
    an FYI, not a rejection.
    """
    dropped = []

    def _drop(db_col, owner_desc):
        if db_col in set_cols:
            header_text = next((h for h, c in header_map.items() if c == db_col), db_col)
            dropped.append((header_text, owner_desc))
            del set_cols[db_col]

    if table == "jobs":
        invoice_id = row["invoice_id"] if "invoice_id" in row.keys() else None
        if invoice_id:
            for db_col in _INVOICE_OWNED_JOB_DB_COLS:
                _drop(db_col, f"invoice {invoice_id}")

    if table in ("jobs", "invoices", "quotes"):
        customer_id = row["customer_id"] if "customer_id" in row.keys() else None
        if customer_id:
            for db_col in _CUSTOMER_OWNED_DB_COLS:
                _drop(db_col, f"customer {customer_id}")

    return dropped


def _compose_checks(*fns):
    """Runs several check_fn(conn, row) callables in order, returning the
    first denial string encountered, or None if every check passes.
    Reserved for genuine access-control checks (crew scoping, a linked-
    customer's scope) — field ownership is enforced by silent drop, not
    a hard check_fn denial (see _split_field_ownership above)."""
    fns = [f for f in fns if f is not None]
    def _check(conn, row):
        for f in fns:
            result = f(conn, row)
            if result:
                return result
        return None
    return _check


_ID_PREFIX_DIGITS = {
    "customers": ("customer_id", "CUST", 4),
    "jobs": ("job_id", "JOB", 4),
    "quotes": ("quote_id", "QTE", 4),
    "invoices": ("invoice_id", "INV", 4),
    "time_entries": ("entry_id", "TE", 4),
}


# ── Date coercion ────────────────────────────────────────────────────────
# Same keyword/format list as _append_sheet_row_impl / update_job_
# spreadsheet's _coerce_date, but returns an ISO 'YYYY-MM-DD' string
# rather than a datetime.date object (there's no openpyxl number_format
# to set anymore) — ISO text sorts and filters correctly in SQL WHERE
# clauses, which is the whole point of moving off cell-scanning.
_DATE_KEYWORDS = ("date", "valid until", "due date", "next sched", "last service")
_DATE_FMTS = ("%m/%d/%Y", "%Y-%m-%d", "%m-%d-%Y", "%d/%m/%Y")


def _coerce_date_iso(normalized_header: str, val):
    if val is None or val == "":
        return val
    hl = normalized_header.lower()
    if not any(kw in hl for kw in _DATE_KEYWORDS):
        return val
    if isinstance(val, (datetime.datetime, datetime.date)):
        return val.date().isoformat() if isinstance(val, datetime.datetime) else val.isoformat()
    for fmt in _DATE_FMTS:
        try:
            return datetime.datetime.strptime(str(val).strip(), fmt).date().isoformat()
        except ValueError:
            continue
    return val  # unparseable — write as-is, don't corrupt the value


# Every column across the schema (db_schema.py) declared `REFERENCES
# some_table(some_id)`. A blank/empty-string value for one of these must
# be written as SQL NULL, never as the literal empty string — SQLite's
# FK enforcement only exempts NULL from the "must match an existing row"
# check, so an empty string is treated as a real (non-matching) key value
# and the write fails with a raw, unhelpful "FOREIGN KEY constraint
# failed". This bit the Jobs PWA's edit form directly: every save always
# sends 'InvoiceID (INV-####)': '' for the very common case of a job
# that has no invoice yet, since the openpyxl-era form has no concept of
# "leave this field out entirely" — it always sends every field, blank
# or not. The spreadsheet version tolerated a blank cell here trivially;
# the DB version needs this explicit NULL coercion to keep doing the
# same for every column that is now a real foreign key.
_FK_COLUMNS = {"customer_id", "invoice_id", "job_id", "quote_id", "crew_user_id"}


def _coerce_value(db_col: str, normalized_header: str, val):
    """Single choke point both db_create_row and db_update_row funnel
    every field through before it reaches a SQL parameter — this is
    where the FK-blank-to-NULL fix and the date-string fix both live,
    so any future value-shaping rule only needs to be added in one
    place."""
    if db_col in _FK_COLUMNS and (val is None or str(val).strip() == ""):
        return None
    return _coerce_date_iso(normalized_header, val)


# ── R-057: fixed-choice fields (David 2026-09-28) ─────────────────────────
# In the Jobs app these fields are dropdowns, so only an allowed value can be
# picked. But Claude (voice or chat), imports and direct API calls write
# through the same create/update engine with whatever word they choose — and
# the server used to store it as-is. A job saved "Completed" instead of the
# app's "Complete" looked done but never counted as serviced (customer
# reminders), wasn't protected from deletion and was left out of reports; a
# customer saved "Semi-Annual" (the Jobs app's own Recurrence wording!) was
# never re-scheduled; "2 hrs" was routed as 2 minutes. Now every write of one
# of these fields is mapped to the canonical value, or refused with the list
# of allowed values — nothing is written in that case. Blank still clears.
#
# Matching ignores case, spaces and punctuation ("in-progress" = "In Progress",
# "Bi-Weekly" = "Biweekly"). Each field keeps its own established spelling
# (Customers' Frequency says "Semi-Annually", Jobs' Recurrence "Semi-Annual")
# so no existing data or screen changes; both accept each other's words.

def _squash(v) -> str:
    return "".join(ch for ch in str(v or "").lower() if ch.isalnum())


# Repeat periods — shared by Customers.Frequency and Jobs.Recurrence.
_PERIOD_ALIASES = {
    "onetime":    ("onetime", "once", "oneoff", "single", "ot", "nonrecurring", "norepeat", "none"),
    "weekly":     ("weekly", "w", "everyweek", "eachweek", "onceaweek", "every1week", "1week"),
    "biweekly":   ("biweekly", "bw", "everyotherweek", "every2weeks", "everytwoweeks", "fortnightly",
                   "every2wks", "eow"),
    "monthly":    ("monthly", "m", "everymonth", "eachmonth", "onceamonth", "every1month"),
    "bimonthly":  ("bimonthly", "bm", "everyothermonth", "every2months", "everytwomonths"),
    "quarterly":  ("quarterly", "q", "every3months", "everythreemonths", "fourtimesayear"),
    "semiannual": ("semiannual", "semiannually", "sa", "biannual", "biannually", "twiceayear",
                   "every6months", "everysixmonths", "halfyearly"),
    "annual":     ("annual", "annually", "a", "yearly", "onceayear", "everyyear", "every12months"),
}
_PERIOD_OF = {alias: p for p, aliases in _PERIOD_ALIASES.items() for alias in aliases}

_FREQUENCY_WORDS = {"onetime": "One-time", "weekly": "Weekly", "biweekly": "Biweekly",
                    "monthly": "Monthly", "bimonthly": "Bi-Monthly", "quarterly": "Quarterly",
                    "semiannual": "Semi-Annually", "annual": "Annually"}
_RECURRENCE_WORDS = {"onetime": "One-time", "weekly": "Weekly", "biweekly": "Biweekly",
                     "monthly": "Monthly", "bimonthly": "Bimonthly", "quarterly": "Quarterly",
                     "semiannual": "Semi-Annual", "annual": "Annual"}


def _period_choice(words: dict) -> dict:
    """canonical -> aliases, for a period field spelled with `words`."""
    return {words[p]: aliases for p, aliases in _PERIOD_ALIASES.items()}


_PAYMENT_CHOICES = {
    "Unpaid":  ("unpaid", "notpaid", "owed", "owing", "due", "outstanding", "open", "notyetpaid"),
    "Partial": ("partial", "partiallypaid", "partialpayment", "partpaid", "deposit", "depositpaid"),
    "Paid":    ("paid", "paidinfull", "fullypaid", "paidfull"),
    "Cash":    ("cash", "paidcash", "paidincash", "paidbycash"),
    "Check":   ("check", "cheque", "paidbycheck", "paidcheck"),
    "Zelle":   ("zelle", "paidzelle", "paidbyzelle", "paidviazelle"),
    "Venmo":   ("venmo", "paidvenmo", "paidbyvenmo", "paidviavenmo"),
    "Other":   ("other",),
}
_CUSTOMER_TYPE_CHOICES = {
    "Residential": ("residential", "res", "r", "residence", "home", "house", "homeowner", "resi"),
    "Commercial":  ("commercial", "comm", "com", "c", "business", "office", "commercialproperty"),
}

# (table, db column) -> {canonical value: accepted aliases (squashed)}
_CHOICE_FIELDS = {
    ("jobs", "job_status"): {
        "Scheduled":   ("scheduled", "booked", "pending", "upcoming", "planned", "notstarted"),
        "In Progress": ("inprogress", "started", "working", "ongoing", "underway", "onsite", "wip"),
        "Complete":    ("complete", "completed", "done", "finished", "closed", "compete"),
        "Cancelled":   ("cancelled", "canceled", "cancel", "cancelledbycustomer", "void"),
    },
    ("jobs", "payment_status"): _PAYMENT_CHOICES,
    ("invoices", "payment_status"): _PAYMENT_CHOICES,
    ("jobs", "recurrence"): _period_choice(_RECURRENCE_WORDS),
    ("customers", "frequency"): _period_choice(_FREQUENCY_WORDS),
    ("jobs", "schedule_type"): {
        "Hard": ("hard", "fixed", "firm", "committed", "appointment", "exact", "locked"),
        "Soft": ("soft", "flexible", "flex", "window", "anytime", "loose"),
    },
    ("jobs", "est_duration_unit"): {
        "min":  ("min", "mins", "minute", "minutes", "m"),
        "hour": ("hour", "hours", "hr", "hrs", "h"),
        "day":  ("day", "days", "d"),
    },
    ("jobs", "customer_type"): _CUSTOMER_TYPE_CHOICES,
    ("customers", "customer_type"): _CUSTOMER_TYPE_CHOICES,
    ("quotes", "customer_type"): _CUSTOMER_TYPE_CHOICES,
    ("invoices", "customer_type"): _CUSTOMER_TYPE_CHOICES,
    ("customers", "status"): {
        "Active":   ("active", "current", "enabled"),
        "Inactive": ("inactive", "archived", "former", "notactive", "disabled", "deactivated"),
    },
    ("quotes", "status"): {
        "Open":     ("open", "pending", "sent", "draft", "new", "awaiting", "outstanding"),
        "Approved": ("approved", "accepted", "won", "signed", "yes"),
        "Declined": ("declined", "rejected", "lost", "denied", "turneddown", "no"),
    },
}
_CHOICE_FIELDS[("jobs", "actual_duration_unit")] = _CHOICE_FIELDS[("jobs", "est_duration_unit")]

# Settings rows whose Value is a fixed choice (keyed by the lower-cased setting name).
_TOGGLE = {"Enabled": ("enabled", "enable", "on", "yes", "true", "1", "y"),
           "Disabled": ("disabled", "disable", "off", "no", "false", "0", "n")}
_SETTING_CHOICES = {
    "route origin mode": {
        "Jobs Only":        ("jobsonly", "jobs", "default", "none", "gps", "currentlocation"),
        "Company Location": ("companylocation", "company", "office", "shop", "business",
                             "startendaddress", "startend", "roundtrip", "companyroundtrip"),
    },
    "email route on build": _TOGGLE,
    "customer reminder daily digest": _TOGGLE,
    "customer reminder email enabled": _TOGGLE,
    "customer reminder sms enabled": _TOGGLE,
}


def _match_choice(choices: dict, val):
    """(canonical value or None). Blank -> ('', True) handled by callers."""
    key = _squash(val)
    for canon, aliases in choices.items():
        if key == _squash(canon) or key in aliases:
            return canon
    return None


def _canon_choice(table: str, db_col: str, header: str, val):
    """R-057. Returns (value_to_store, error_or_None). Non-choice fields and
    blank values pass through unchanged."""
    choices = _CHOICE_FIELDS.get((table, db_col))
    if not choices or val is None or str(val).strip() == "":
        return val, None
    canon = _match_choice(choices, val)
    if canon is None:
        return val, (f"❌ '{val}' isn't a valid {header}. Use one of: {', '.join(choices)}. "
                     f"Nothing was saved.")
    return canon, None


def _canon_setting_value(key: str, val):
    """R-057, Settings: the same for the handful of fixed-choice settings."""
    choices = _SETTING_CHOICES.get(str(key or "").strip().lower())
    if not choices or val is None or str(val).strip() == "":
        return val, None
    canon = _match_choice(choices, val)
    if canon is None:
        return val, (f"❌ '{val}' isn't a valid value for the '{key}' setting. Use one of: "
                     f"{', '.join(choices)}. Nothing was saved.")
    return canon, None


def frequency_period(val) -> "str | None":
    """R-057: the repeat period ('weekly', 'semiannual', …) of any Frequency /
    Recurrence wording, or None if it isn't one. Blank -> None."""
    return _PERIOD_OF.get(_squash(val))


# ── R-058: multi-day jobs (David 2026-09-28) ────────────────────────────────
# "10 days" means 10 WORKING days (Mon–Fri) starting on the Service Date, and
# the job is on its assignee's route every one of those days. A day-unit
# duration sets the job's End Date (the field the Calendar, the date filters
# and the route clean-up already honour); every working day from Service Date
# to End Date the job is routed, taking the whole workday (Workday Start→End
# minus lunch; a final part-day — e.g. 2.5 days — takes that share of it).
# Weekends inside a job's span are skipped; the Service Date itself always
# counts, even on a weekend (someone booked it for that day on purpose).

def _iso_date(v):
    try:
        return datetime.date.fromisoformat(str(v or "").strip()[:10])
    except ValueError:
        return None


# ── Working Days setting (Vicki 2026-10-02) ──────────────────────────────────
# R-058's "working day" used to be hard-wired to Mon–Fri. A contractor running
# late on a project may work Saturday and/or Sunday, so the days now come from
# the Settings row "Working Days" (default Mon–Fri = no change for anyone who
# never touches it). Every R-058 helper below takes an optional `days` (a set of
# Python weekday numbers, Mon=0 … Sun=6); callers that have the database pass
# working_days(db_path), anything that passes nothing keeps Mon–Fri.
WORKING_DAYS_KEY = "Working Days"
DEFAULT_WORKING_DAYS_TEXT = "Mon,Tue,Wed,Thu,Fri"
DEFAULT_WORKING_DAYS = frozenset(range(5))
_DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_DAY_ALIASES = {
    "mon": 0, "monday": 0, "tue": 1, "tues": 1, "tuesday": 1, "wed": 2, "weds": 2,
    "wednesday": 2, "thu": 3, "thur": 3, "thurs": 3, "thursday": 3, "fri": 4, "friday": 4,
    "sat": 5, "saturday": 5, "sun": 6, "sunday": 6,
}
_DAY_GROUPS = {
    "all": range(7), "everyday": range(7), "alldays": range(7), "daily": range(7),
    "7days": range(7), "weekdays": range(5), "weekday": range(5),
    "weekends": (5, 6), "weekend": (5, 6),
}


def parse_working_days(text):
    """(days, problem) from a Working Days value. `days` is a frozenset of
    weekday numbers (Mon=0); `problem` is '' when the text was understood, else
    a plain-English reason (then `days` is the Mon–Fri default). Accepts e.g.
    "Mon,Tue,Wed,Thu,Fri", "Mon-Sat", "Fri-Mon" (wraps), "Weekdays, Sat",
    "All", "Monday Wednesday Friday". Blank = the default, no problem."""
    import re
    raw = str(text or "").strip()
    if not raw:
        return DEFAULT_WORKING_DAYS, ""
    s = raw.lower()
    for phrase in ("every day", "all days", "seven days", "7 days", "7-days", "all week"):
        s = s.replace(phrase, "all")
    s = re.sub(r"\s*(?:-|–|—|\bthrough\b|\bthru\b|\bto\b)\s*", "-", s)   # "Mon - Fri" -> "mon-fri"
    days, bad = set(), []
    for tok in re.split(r"[,;/&+\s]+", s):
        t = tok.strip().rstrip(".")
        if not t or t == "and":
            continue
        if t in _DAY_GROUPS:
            days.update(_DAY_GROUPS[t])
            continue
        m = re.fullmatch(r"([a-z]+)-([a-z]+)", t)
        if m and m.group(1) in _DAY_ALIASES and m.group(2) in _DAY_ALIASES:
            a, b = _DAY_ALIASES[m.group(1)], _DAY_ALIASES[m.group(2)]
            i = a
            while True:                     # inclusive, wrapping past Sunday
                days.add(i)
                if i == b:
                    break
                i = (i + 1) % 7
            continue
        if t in _DAY_ALIASES:
            days.add(_DAY_ALIASES[t])
            continue
        bad.append(t)
    if bad:
        return DEFAULT_WORKING_DAYS, (f"didn't recognise {', '.join(repr(b) for b in bad)} — use day "
                                      f"names like Mon,Tue,Wed,Thu,Fri,Sat,Sun or a range like Mon-Sat")
    if not days:
        return DEFAULT_WORKING_DAYS, "no days given"
    return frozenset(days), ""


def format_working_days(days) -> str:
    """Canonical text for a set of weekday numbers, e.g. 'Mon,Tue,Wed,Thu,Fri,Sat'."""
    return ",".join(_DAY_NAMES[i] for i in sorted(days))


def working_days(db_path) -> frozenset:
    """The installed Working Days (Mon=0 … Sun=6). Mon–Fri when the row is
    missing, blank or unreadable — never raises."""
    if not db_path:
        return DEFAULT_WORKING_DAYS
    try:
        conn = get_connection(db_path)
        try:
            return working_days_conn(conn)
        finally:
            conn.close()
    except Exception:
        return DEFAULT_WORKING_DAYS


def working_days_conn(conn) -> frozenset:
    """working_days() through an already-open connection (e.g. inside a
    transaction). Mon–Fri on any problem — never raises."""
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (WORKING_DAYS_KEY,)).fetchone()
        return parse_working_days(row["value"] if row else "")[0]
    except Exception:
        return DEFAULT_WORKING_DAYS


def is_working_day(d: datetime.date, days=None) -> bool:
    return d.weekday() in (DEFAULT_WORKING_DAYS if days is None else days)


def add_workdays(start: datetime.date, n: int, days=None) -> datetime.date:
    """The date `n` working days after `start` (0 -> start). `days` = the
    working weekdays (default Mon–Fri; see working_days())."""
    if days is not None and not days:
        days = DEFAULT_WORKING_DAYS         # never loop forever on an empty set
    d, left = start, int(n)
    while left > 0:
        d += datetime.timedelta(days=1)
        if is_working_day(d, days):
            left -= 1
    return d


def day_unit_end_date(service_date, est_duration, days=None) -> str:
    """End Date (ISO) for a job lasting `est_duration` days from `service_date`;
    '' for a job of one day or less, or when either value is missing/invalid."""
    start = _iso_date(service_date)
    try:
        n = float(est_duration)
    except (TypeError, ValueError):
        return ""
    if not start or n <= 1:
        return ""
    import math
    return add_workdays(start, math.ceil(n) - 1, days).isoformat()


# R-058 overrun (David 2026-09-28): durations are hard to estimate, so ANY job
# (one-day, part-day or multi-day) that is still open after its last planned
# day (End Date, or the Service Date for a one-day job) keeps being worked —
# and routed — on each following working day until it is marked Complete (or
# Cancelled). Looking forward it reaches the "overrun horizon" (today and the
# next working day, so tonight's plan for tomorrow includes it); past working
# days after the planned end count too (the job was still open then).
_CLOSED_JOB_STATUSES = ("complete", "completed", "cancelled", "canceled")


def job_is_open(status) -> bool:
    s = str(status or "").strip()
    if s.lower() in _CLOSED_JOB_STATUSES:
        return False
    canon = _match_choice(_CHOICE_FIELDS[("jobs", "job_status")], s) if s else None
    return canon not in ("Complete", "Cancelled")


def overrun_today() -> datetime.date:
    """Today, for the overrun rule (one place, so tests can pin it)."""
    return datetime.date.today()


def overrun_horizon(today=None, days=None) -> datetime.date:
    """Latest date an overrunning job is carried to: the next working day."""
    return add_workdays(_iso_date(today) or overrun_today(), 1, days)


def job_day_number(service_date, end_date, day, status=None, today=None, days=None) -> "int | None":
    """1-based working-day number of `day` within a job's span, or None when
    the job isn't worked that day (outside the span, or a non-working day inside
    it). `days` = the working weekdays (default Mon–Fri; see working_days()).
    Pass the job's `status` to apply the overrun rule: an open job is also
    worked on working days after its End Date / Service Date (up to the
    overrun horizon), numbered on from its last planned day."""
    s, d = _iso_date(service_date), _iso_date(day)
    if not s or not d:
        return None
    if d == s:
        return 1
    e = _iso_date(end_date) or s
    # Only a job whose last planned day is already PAST is overrunning — today's
    # own jobs aren't late yet, so they don't show up on tomorrow's plan.
    now = _iso_date(today) or overrun_today()
    if d > e and e < now and status is not None and job_is_open(status) \
            and d <= overrun_horizon(now, days):
        e = d                                   # overrun: still being worked
    if d < s or d > e or not is_working_day(d, days):
        return None
    n, cur = 1, s
    while cur < d:
        cur += datetime.timedelta(days=1)
        if is_working_day(cur, days):
            n += 1
    return n


def workday_job_minutes(db_path: str) -> int:
    """Minutes of work in one full day: Workday Start→End minus lunch (≥ 60)."""
    try:
        start = _parse_hhmm(db_read_settings_workday_start(db_path))
        end = _parse_hhmm(db_read_settings_workday_end(db_path))
        lunch = int(db_read_settings_lunch_break_duration_min(db_path) or 0)
        mins = int((end - start).total_seconds() // 60) - lunch
        return max(60, mins)
    except Exception:
        return 540


def per_day_duration(db_path: str, est_duration, unit, day_no: int):
    """(duration, unit) the route engines should use for this job on its
    `day_no`-th working day. Day units become minutes of that day's work;
    minutes/hours are unchanged (for a multi-day job they mean per day)."""
    if str(unit or "").strip().lower() != "day":
        return est_duration, unit
    full = workday_job_minutes(db_path)
    try:
        n = float(est_duration)
    except (TypeError, ValueError):
        n = 1.0
    share = n - (day_no - 1)
    if share <= 0:
        # R-058 overrun day (job still open past its estimate): another day
        # the size of the job's own day — a full day, or ½ day for a ½-day job
        share = min(1.0, n) if n > 0 else 1.0
    elif share >= 1:
        share = 1.0
    return int(round(full * share)), "min"


def _sync_day_unit_end_date(db_path: str, job_ids) -> None:
    """R-058: after a job is saved, a day-unit duration sets its End Date.
    Only ever touches jobs whose unit is 'day'. Never raises."""
    try:
        changed = []
        wd = working_days(db_path)          # the installed Working Days
        with transaction(db_path) as conn:
            for jid in job_ids:
                r = conn.execute("SELECT job_id, service_date, end_date, est_duration, est_duration_unit "
                                 "FROM jobs WHERE job_id = ?", (jid,)).fetchone()
                if not r or str(r["est_duration_unit"] or "").strip().lower() != "day":
                    continue
                want = day_unit_end_date(r["service_date"], r["est_duration"], wd)
                if want != (r["end_date"] or ""):
                    conn.execute("UPDATE jobs SET end_date = ? WHERE job_id = ?", (want or None, jid))
                    changed.append(jid)
        if changed:
            from db_route_ops import db_drop_stale_job_stops
            db_drop_stale_job_stops(db_path, changed)
    except Exception:
        pass


_CHOICE_MARKER_KEY = "internal_choice_fields_normalized_v1"


def db_normalize_choice_fields(db_path: str) -> dict:
    """R-057 one-time cleanup: rewrites every stored value of a fixed-choice
    field that is a recognised variant ("Completed", "hrs", "Semi-Annual" on a
    customer…) to its canonical spelling. Values it can't recognise are left
    exactly as they are (and counted), never guessed. Returns
    {'changed': {field: n}, 'unrecognised': {field: [values]}}."""
    changed, unknown = {}, {}
    with transaction(db_path) as conn:
        for (table, col), choices in _CHOICE_FIELDS.items():
            if col not in _table_columns(conn, table):
                continue
            for r in conn.execute(f"SELECT DISTINCT {col} AS v FROM {table} "
                                  f"WHERE {col} IS NOT NULL AND TRIM({col}) != ''").fetchall():
                old = r["v"]
                canon = _match_choice(choices, old)
                if canon is None:
                    unknown.setdefault(f"{table}.{col}", []).append(old)
                elif canon != old:
                    n = conn.execute(f"UPDATE {table} SET {col} = ? WHERE {col} = ?", (canon, old)).rowcount
                    changed[f"{table}.{col}"] = changed.get(f"{table}.{col}", 0) + (n or 0)
        for r in conn.execute("SELECT key, value FROM settings").fetchall():
            canon, err = _canon_setting_value(r["key"], r["value"])
            if not err and canon not in (None, "") and canon != r["value"]:
                conn.execute("UPDATE settings SET value = ? WHERE key = ?", (canon, r["key"]))
                changed[f"settings.{r['key']}"] = 1
    return {"changed": changed, "unrecognised": unknown}


def _maybe_normalize_choice_fields(db_path: str) -> None:
    """Runs db_normalize_choice_fields once per database (marker row in
    Settings, hidden from the app like every internal_* row). Never raises."""
    try:
        conn = get_connection(db_path)
        try:
            done = conn.execute("SELECT 1 FROM settings WHERE key = ?", (_CHOICE_MARKER_KEY,)).fetchone()
        finally:
            conn.close()
        if done:
            return
        result = db_normalize_choice_fields(db_path)
        note = (f"R-057 one-time cleanup — do not edit by hand. Changed: {result['changed'] or 'nothing'}; "
                f"left as-is (unrecognised): {result['unrecognised'] or 'none'}")
        with transaction(db_path) as conn:
            cols = _table_columns(conn, "settings")
            vals = {"key": _CHOICE_MARKER_KEY, "value": datetime.date.today().isoformat(), "notes": note,
                    "last_edited_by": "system", "last_edited_at": utcnow_iso()}
            use = [c for c in vals if c in cols]
            conn.execute(f"INSERT OR IGNORE INTO settings ({', '.join(use)}) VALUES "
                         f"({', '.join('?' for _ in use)})", [vals[c] for c in use])
    except Exception:
        pass


# ── Crew-scoping primitives ──────────────────────────────────────────────

def _crew_name_in_cell(row_crew_lower: str, crew_name: str) -> bool:
    """Copied verbatim from ai_prowler_mcp.py — pure string logic, no
    storage dependency. Membership-in-comma-list, not equality."""
    if not row_crew_lower or not crew_name:
        return False
    return crew_name in [n.strip() for n in row_crew_lower.split(",")]


def db_customer_in_crew_scope(conn, crew_name: str, customer_id: str) -> bool:
    """DB-backed replacement for _server_customer_in_crew_scope(wb, ...).
    True iff customer_id appears on a `jobs` row whose `crew` field
    includes crew_name. Fails closed (False) on any missing input,
    matching the original's posture."""
    if not customer_id:
        return False
    customer_id_lower = str(customer_id).strip().lower()
    rows = conn.execute(
        "SELECT crew FROM jobs WHERE LOWER(customer_id) = ?", (customer_id_lower,)
    ).fetchall()
    for row in rows:
        row_crew = str(row["crew"] or "").strip().lower()
        if _crew_name_in_cell(row_crew, crew_name):
            return True
    return False


# ── ID generation ────────────────────────────────────────────────────────

def generate_next_id(conn, table: str, id_column: str, prefix: str, digits: int) -> str:
    """Next PREFIX-#### id: one past the highest number EVER issued for this
    prefix — never reused.

    R-044 (was gap G-11, 2026-09-27 — David: "never reuse a job number, that
    way you can review a cancelled job"). This used to be "highest existing
    + 1", so deleting the newest record freed its number and the next record
    got it — along with the old job's JobPhotos\\<JobID> folder and any
    paperwork that mentioned it. Now the highest number issued is kept per
    prefix in `id_counters`, and the next id is one past the larger of that
    and whatever exists in the table (so an install that predates the
    counter, or rows added outside this function, can never collide).
    Numbers deleted BEFORE this counter existed can't be known, so the
    counter starts from what exists on first use.

    Runs on the caller's connection, so the counter bump commits or rolls
    back together with the row being created. `table`/`id_column` are always
    internal constants supplied by this module's own wrappers, never external
    input."""
    assert table in _ID_PREFIX_DIGITS, f"unrecognized table for ID generation: {table}"
    rows = conn.execute(f"SELECT {id_column} FROM {table}").fetchall()
    max_num = 0
    for row in rows:
        val = row[0]
        if val and str(val).startswith(f"{prefix}-"):
            try:
                max_num = max(max_num, int(str(val).split("-")[1]))
            except (ValueError, IndexError):
                pass
    conn.execute("CREATE TABLE IF NOT EXISTS id_counters "
                 "(prefix TEXT PRIMARY KEY, last_num INTEGER NOT NULL)")
    got = conn.execute("SELECT last_num FROM id_counters WHERE prefix = ?", (prefix,)).fetchone()
    issued = int(got[0]) if got else 0
    nxt = max(max_num, issued) + 1
    conn.execute("INSERT INTO id_counters (prefix, last_num) VALUES (?, ?) "
                 "ON CONFLICT(prefix) DO UPDATE SET last_num = excluded.last_num", (prefix, nxt))
    return f"{prefix}-{nxt:0{digits}d}"


# ── Generic create engine (replaces _append_sheet_row_impl) ─────────────

_table_columns_cache = {}


def _table_columns(conn, table: str) -> set:
    """Real column names for `table`, via PRAGMA table_info — cached per
    connection-less call (keyed by table name only; the schema itself
    never changes at runtime, so this is safe to cache process-wide).
    Lets db_create_row/db_update_row stamp whichever audit columns a
    table actually has (created_by, last_edited_by, last_edited_at,
    version) instead of assuming every table has all four — settings is
    the one table missing created_by AND version entirely (it's a plain
    key/value config store, not an audited business record), and this
    keeps that table from ever needing a special-cased exception in the
    write engine itself."""
    if table not in _table_columns_cache:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        _table_columns_cache[table] = {row[1] for row in rows}  # row[1] = column name
    return _table_columns_cache[table]


def _split_computed_only(conn, table: str, set_cols: dict, header_map: dict):
    """Spec §13.6 safety net: a handful of header_map entries (Invoice
    Total, Actual Amount, Tax%, and the four Customers rollups) exist
    for DISPLAY/recognition purposes only — their underlying column has
    been dropped from the schema entirely (spec §13.3/§13.4), and their
    live value comes exclusively from db_read_ops's overlay functions.
    The check_fn layer already blocks a caller from reaching this point
    with one of these in `updates` for db_update_row, but db_create_row
    has no check_fn hook at all — this is the actual backstop there, and
    a second line of defense everywhere else, so a header/schema drift
    can never generate SQL that references a nonexistent column.
    Mutates `set_cols` in place (removing anything not a real column) and
    returns the list of display headers that were dropped, in the same
    order header_map iterates, for the caller to report back cleanly."""
    cols_present = _table_columns(conn, table)
    dropped = []
    for db_col in list(set_cols.keys()):
        if db_col not in cols_present:
            header_text = next((h for h, c in header_map.items() if c == db_col), db_col)
            dropped.append(header_text)
            del set_cols[db_col]
    return dropped


def db_create_row(db_path: str, table: str, header_map: dict, updates: dict, actor: str) -> str:
    """DB-backed replacement for _append_sheet_row_impl. Always
    generates the row's own ID (a caller-supplied value for that column
    is silently ignored, matching the original). Stamps whichever of
    created_by/last_edited_by/last_edited_at actually exist on `table`
    with `actor` — last_edited_by/last_edited_at are new relative to the
    spreadsheet version, added so a freshly created row is immediately
    visible to the Job Board's `last_edited_at > ?` polling query (spec
    §6.1); a brand-new job shouldn't be invisible until someone happens
    to edit it. A table without one of these columns (settings has
    neither created_by nor a real audit trail at all) simply doesn't get
    that column set — see _table_columns().
    """
    id_column, prefix, digits = _ID_PREFIX_DIGITS[table]

    written, not_found, set_cols = [], [], {}
    for header, val in (updates or {}).items():
        norm = _normalize_header(header)
        db_col = header_map.get(norm)
        if db_col is None:
            not_found.append(header)
            continue
        if db_col in (id_column, "version"):
            continue  # auto-generated / starts at 1 — caller-provided value is ignored
        val, bad = _canon_choice(table, db_col, norm, val)          # R-057
        if bad:
            return bad
        set_cols[db_col] = _coerce_value(db_col, norm, val)
        written.append(f"{header} -> {val}")

    now = utcnow_iso()
    with transaction(db_path) as conn:
        cols_present = _table_columns(conn, table)
        computed_only = _split_computed_only(conn, table, set_cols, header_map)
        new_id = generate_next_id(conn, table, id_column, prefix, digits)
        set_cols[id_column] = new_id
        if "created_by" in cols_present:
            set_cols["created_by"] = actor
        if "last_edited_by" in cols_present:
            set_cols["last_edited_by"] = actor
        if "last_edited_at" in cols_present:
            set_cols["last_edited_at"] = now
        cols = list(set_cols.keys())
        conn.execute(
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
            [set_cols[c] for c in cols],
        )

    label = table[:-1] if table.endswith("s") else table
    written = [w for w in written
               if not any(w.startswith(f"{h} ->") for h in computed_only)]
    lines = [
        f"✅ {label} created: {new_id}",
        f"   Set:  {', '.join(written) if written else '(no fields provided)'}",
    ]
    if not_found:
        lines.append(f"   ⚠️  Columns not found (check spelling): {', '.join(not_found)}")
    if computed_only:
        lines.append(f"   ℹ️  Computed live from other records, not stored directly: "
                      f"{', '.join(computed_only)}")
    lines.append(f"NEW_{prefix}_ID={new_id}")
    return "\n".join(lines)


def db_create_customer(db_path: str, updates: dict, actor: str) -> str:
    return db_create_row(db_path, "customers", CUSTOMERS_HEADER_MAP, updates, actor)


def _mapped_value(updates: dict, header_map: dict, target_col: str):
    """Return the first value in `updates` whose header normalizes to
    `target_col` in `header_map` — used to look up a specific field
    (e.g. customer_id) regardless of which recognized header spelling
    the caller used (spec §5.1: create_job accepts "CustomerID",
    "CustomerID (Customers!A)", etc. — all map to the same db column)."""
    for header, val in (updates or {}).items():
        if header_map.get(_normalize_header(header)) == target_col:
            return val
    return None


def db_create_job(db_path: str, updates: dict, actor: str) -> str:
    # Job Board Architecture Spec §5.1 (customer-before-job requirement,
    # added 2026-09-22): create_job requires a valid, existing
    # customer_id. It does NOT accept embedded new-customer fields and
    # does not implicitly create one — the caller must call
    # create_customer first and pass the returned CustomerID here. This
    # is enforced here in application code, not by making
    # jobs.customer_id NOT NULL in the schema — db_schema.py deliberately
    # keeps that column nullable for other reasons (see its own comment
    # on jobs.customer_id); this is a create_job-specific product rule,
    # not a storage-layer constraint.
    #
    # Both failure cases are caught and translated into a clear,
    # tool-layer message here — never a raw FK-constraint stack trace up
    # to the caller (Claude, voice, PWA).
    updates = dict(updates)
    customer_id = _mapped_value(updates, JOBS_HEADER_MAP, "customer_id")
    if not customer_id or not str(customer_id).strip():
        return (
            "❌ customer_id is required — a job cannot be created without "
            "an existing customer. Create the customer first with "
            "create_customer, then pass the CustomerID it returns as "
            "CustomerID here."
        )
    customer_id = str(customer_id).strip()
    conn = get_connection(db_path)
    try:
        found = conn.execute(
            "SELECT 1 FROM customers WHERE customer_id = ?", (customer_id,)
        ).fetchone()
    finally:
        conn.close()
    if not found:
        return (
            f"❌ No customer found with ID {customer_id} — create the "
            f"customer first with create_customer, then retry create_job "
            f"with the CustomerID it returns."
        )

    # Mileage/routing follow-up (2026-09-20): a job's Original Start/End
    # Time defaults to whatever Start/End Time it's created with — a
    # sensible starting baseline until a genuine reschedule deliberately
    # changes it later. Never overrides an Original Start/End Time
    # explicitly given in the same create call.
    if updates.get("Start Time") and not updates.get("Original Start Time"):
        updates["Original Start Time"] = updates["Start Time"]
    if updates.get("End Time") and not updates.get("Original End Time"):
        updates["Original End Time"] = updates["End Time"]

    # Defense-in-depth: even with the pre-check above, translate a raw FK
    # IntegrityError (e.g. a genuine race, or a future caller bypassing
    # this function) into the same friendly message rather than letting
    # it surface as a stack trace.
    import sqlite3 as _sqlite3
    try:
        result = db_create_row(db_path, "jobs", JOBS_HEADER_MAP, updates, actor)
    except _sqlite3.IntegrityError:
        return (
            f"❌ No customer found with ID {customer_id} — create the "
            f"customer first with create_customer, then retry create_job "
            f"with the CustomerID it returns."
        )
    # A new job with an address but no coordinates gets them now (R-022,
    # 2026-09-26) — otherwise it can't be routed at all.
    if (isinstance(result, str) and "NEW_JOB_ID=" in result
            and not (updates.get("Latitude (AI Geocode)") and updates.get("Longitude (AI Geocode)"))):
        new_id = result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
        if _auto_geocode_job(db_path, new_id, actor, force=False):
            result += "\n📍 Map location found for the address."
    # R-058: "N days" -> the job's End Date is its Nth working day
    if isinstance(result, str) and "NEW_JOB_ID=" in result:
        _sync_day_unit_end_date(db_path, [result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()])
    return result


# ── Automatic map location for jobs (R-022, 2026-09-26) ─────────────────────
# Found by the Jobs-app E2E suite: a job added through the app's own + Add form
# was never geocoded, so Route Selected Date / AI Route couldn't place it
# ("None of 1 job(s) have a geocoded address yet"), and editing a job's address
# KEPT its old coordinates (it would be routed to where it used to be). Only
# build_daily_route filled coordinates in, as a side effect. Now every job
# save that needs it looks the address up (best effort — a failed lookup never
# fails the save; the route prescreen still reports a job with no location).
# Off under the test runner (AIPROWLER_TEST_STATE_DIR) so the offline suite
# never calls the internet; tests that cover this switch it on explicitly.
import os as _os_geo
AUTO_GEOCODE_ENABLED = not _os_geo.environ.get("AIPROWLER_TEST_STATE_DIR")
_JOB_ADDRESS_COLS = {"street_address", "city", "state", "zip"}


def _auto_geocode_job(db_path: str, job_id: str, actor: str, force: bool) -> bool:
    """Looks up and stores a job's map location. force=False only fills in a
    MISSING location; force=True replaces it (the address changed). Returns
    True if coordinates were stored. Never raises."""
    if not AUTO_GEOCODE_ENABLED or not job_id:
        return False
    try:
        conn = get_connection(db_path)
        try:
            row = conn.execute("SELECT street_address, city, state, zip, latitude, longitude "
                               "FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        finally:
            conn.close()
        if not row or not str(row["street_address"] or "").strip():
            return False
        if not force and row["latitude"] is not None and row["longitude"] is not None:
            return False
        addr = ", ".join(p for p in [str(row["street_address"] or "").strip(), str(row["city"] or "").strip(),
                                     f"{str(row['state'] or '').strip()} {str(row['zip'] or '').strip()}".strip()]
                         if p)
        coords = _geocode(addr)
        if not coords:
            return False
        from db_route_ops import db_update_job_geocode
        db_update_job_geocode(db_path, job_id, coords[0], coords[1], actor)
        return True
    except Exception:
        return False


def _job_address_snapshot(db_path: str, id_db_column: str, identifier) -> dict:
    """{job_id: (street, city, state, zip)} for the ONE job an edit targets
    (same most-exact-match lookup the edit itself uses); {} if not exactly one."""
    try:
        conn = get_connection(db_path)
        try:
            row, err = _find_row_for_update(conn, "jobs", id_db_column, identifier)
        finally:
            conn.close()
        if err or not row:
            return {}
        norm = lambda v: str(v or "").strip().lower()
        return {row["job_id"]: (norm(row["street_address"]), norm(row["city"]),
                                norm(row["state"]), norm(row["zip"]))}
    except Exception:
        return {}


def db_create_quote(db_path: str, updates: dict, actor: str) -> str:
    return db_create_row(db_path, "quotes", QUOTES_HEADER_MAP, updates, actor)


def db_create_invoice_row(db_path: str, updates: dict, actor: str) -> str:
    """Low-level row insert for invoices, used by db_create_invoice()
    (Subtotal/Tax/TOTAL DUE must already be computed by the caller —
    see that function's docstring, spec §6a category 2)."""
    return db_create_row(db_path, "invoices", INVOICES_HEADER_MAP, updates, actor)


# ── Generic update engine (replaces update_job_spreadsheet's core) ──────

# Price-list number fields (2026-09-25): 'abc' and -50 were accepted as prices
# and stored as-is, which anything doing math on them later (quotes, invoices,
# reports) would choke on or get wrong.
_PRICING_NUMBER_COLS = {
    "base_price": "Base Price ($)",
    "min_charge": "Min Charge ($)",
    "comm_multiplier": "Commission Multiplier",
}


def _validate_pricing_numbers(set_cols: dict):
    """Checks/normalizes the price list's number fields in place. Returns an
    '❌ ...' message (nothing may be written) or None. Blank clears the field;
    '$150' and '1,200' are accepted and stored as numbers."""
    for col, label in _PRICING_NUMBER_COLS.items():
        if col not in set_cols:
            continue
        v = set_cols[col]
        if v is None or str(v).strip() == "":
            set_cols[col] = None
            continue
        try:
            n = float(str(v).strip().replace("$", "").replace(",", ""))
        except (TypeError, ValueError):
            return f"❌ {label} must be a number — got '{v}'. Nothing was changed."
        if n != n or n in (float("inf"), float("-inf")):
            return f"❌ {label} must be a number — got '{v}'. Nothing was changed."
        if n < 0:
            return f"❌ {label} can't be negative — got {v}. Nothing was changed."
        set_cols[col] = n
    return None


def drop_orphan_route_bookends(conn) -> int:
    """Removes Start / End / "Home" route rows (rows with no job_id) from any
    route — one (route_date, crew) — that no longer has a single job stop
    (2026-09-25). Found during the 9/25 database wipe: when every job had left
    a day's route (cancelled, moved, deleted), its "Home" end row stayed behind
    with nothing to belong to — three of them, 9/23-9/25. Runs inside the
    caller's transaction; called by every path that deletes a JOB's stop.
    A route that still has at least one job stop is never touched."""
    return conn.execute(
        """DELETE FROM route_stops
           WHERE COALESCE(job_id, '') = ''
             AND NOT EXISTS (
               SELECT 1 FROM route_stops r2
               WHERE r2.route_date = route_stops.route_date
                 AND COALESCE(r2.crew_id, '') = COALESCE(route_stops.crew_id, '')
                 AND COALESCE(r2.job_id, '') <> '')"""
    ).rowcount

def _find_row_for_update(conn, table: str, id_db_column: str, match_value):
    """Find the ONE row an edit is meant for (2026-09-25). Returns (row, None)
    or (None, "❌ ...").

    Replaces a `LIKE '%value%' ORDER BY rowid LIMIT 1` lookup that silently
    edited the FIRST row whose key merely CONTAINED the text — found live on
    the price list: editing code 'ztest-win' changed 'ZTEST-WIN' instead, with
    no warning. The same lookup serves every sheet the Database tab edits (a
    route stop id '1' could hit stop 10, 11 or 671), and LIKE also treated '_'
    and '%' in a value as wildcards.

    Most-exact match wins, and it never guesses between rows:
      1. exact, case-sensitive          -> that row if exactly one
      2. exact, ignoring case           -> that row if exactly one
      3. contains, ignoring case        -> that row if exactly one
    More than one row at the first tier that matches anything -> refuse and
    list them (with each row's own key), nothing written. Tier 3 keeps typing
    part of a customer name working when it's unambiguous."""
    val = str(match_value if match_value is not None else "").strip()
    if not val:
        return None, f"❌ No value given to find the row by ({id_db_column})."
    pk = None
    try:
        for c in conn.execute(f"PRAGMA table_info({table})").fetchall():
            if c["pk"]:
                pk = c["name"]
                break
    except Exception:
        pk = None
    col = f"CAST({id_db_column} AS TEXT)"   # CAST: route_stops' integer id compares as text too
    base = f"SELECT rowid AS _rowid, * FROM {table} WHERE "
    tiers = (
        (f"{col} = ?", val),
        (f"LOWER({col}) = ?", val.lower()),
        (f"instr(LOWER({col}), ?) > 0", val.lower()),   # instr: no LIKE wildcards
    )
    for where, arg in tiers:
        rows = conn.execute(base + where + " ORDER BY rowid LIMIT 11", (arg,)).fetchall()
        if len(rows) == 1:
            return rows[0], None
        if len(rows) > 1:
            def _label(r):
                key = str(r[id_db_column])
                if pk and pk != id_db_column and r[pk] is not None:
                    return f"{r[pk]} ({key})"
                return key
            shown = ", ".join(_label(r) for r in rows[:10])
            more = " …and more" if len(rows) > 10 else ""
            return None, (f"❌ '{val}' matches more than one row in {id_db_column}: {shown}{more}. "
                          f"Nothing was changed — use the exact "
                          f"{pk if pk and pk != id_db_column else id_db_column} to pick one.")
    return None, f"❌ No row found where {id_db_column} matches '{val}'."


def db_update_row(db_path: str, table: str, header_map: dict, id_db_column: str,
                   match_value: str, updates: dict, actor: str, check_fn=None,
                   expected_version: int = None) -> str:
    """DB-backed replacement for update_job_spreadsheet's find-row ->
    apply-updates -> audit-stamp -> save cycle, minus the row_index
    escape hatch (spec's whole point is that every table now has a
    real, unique key — customers/jobs/quotes/invoices via their ID
    column, route_stops via (route_date, crew_id, stop_number) — so the
    "no column is unique on its own" problem this was a workaround for
    no longer exists; see db_write_ops_route.py for route_stops, which
    is addressed differently since it's keyed by a compound key rather
    than a single id_db_column).

    check_fn(conn, row) -> Optional[str]: an optional crew-scoping/
    field-lock check run AFTER the row is found but BEFORE anything is
    written. Return an error string to deny the write (nothing is
    written), or None to allow it. Building this from
    _job_crew_scope()/db_customer_in_crew_scope()/
    _FIELD_CREW_LOCKED_CUSTOMER_HEADERS is the caller's job (see
    make_jobs_crew_check / make_linked_customer_check below) — this
    function only enforces whatever check_fn decides.

    expected_version: Job Board Architecture Spec Phase 4 (spec §6.2,
    §11) optimistic-concurrency check. When given (not None), the write
    is rejected — with nothing written — if the row's current `version`
    no longer matches, meaning someone else edited it since this caller
    loaded it. The rejection names who and when, matching the spec's
    "reload and try again" UX exactly, and is checked AFTER check_fn so
    an unauthorized caller never learns who edited a row they can't
    touch anyway. Passing None (the default) skips the check entirely —
    every pre-Phase-4 caller that doesn't know about versioning yet
    keeps working exactly as before. Silently ignored (never checked,
    never errors) on a table with no `version` column at all — currently
    only `settings`, which has no audit trail to conflict-detect against
    in the first place.
    """
    updated, not_found, set_cols = [], [], {}
    for header, val in (updates or {}).items():
        norm = _normalize_header(header)
        db_col = header_map.get(norm)
        if db_col is None:
            not_found.append(header)
            continue
        if db_col in ("version", id_db_column):
            continue  # never let a caller overwrite the primary key or version directly
        # R-057: fixed-choice fields -> canonical value, or refused (nothing written)
        if table == "settings" and db_col == "value":
            val, bad = _canon_setting_value(match_value, val)
        else:
            val, bad = _canon_choice(table, db_col, norm, val)
        if bad:
            return bad
        set_cols[db_col] = _coerce_value(db_col, norm, val)
        updated.append(f"{header} -> {val}")

    if table == "service_pricing":
        bad = _validate_pricing_numbers(set_cols)
        if bad:
            return bad

    with transaction(db_path) as conn:
        cols_present = _table_columns(conn, table)
        has_version = "version" in cols_present
        # Spec §13.6 — Case C/D fields have no backing column at all, so
        # this doubles as their enforcement mechanism.
        computed_only = _split_computed_only(conn, table, set_cols, header_map)
        if computed_only:
            updated = [u for u in updated
                       if not any(u.startswith(f"{h} ->") for h in computed_only)]
        row, err = _find_row_for_update(conn, table, id_db_column, match_value)
        if err:
            return err

        # Follow-up fix (2026-09-15, found during manual E2E testing):
        # marking an invoice Paid via a raw payment_status edit left
        # amount_paid at 0 and balance_due at the full total — nothing
        # previously derived amount_paid from payment_status. balance_due
        # itself is now a GENERATED column (db_schema.py, same fix pattern
        # as time_entries.elapsed_min), so it's always mathematically
        # consistent with amount_paid — but amount_paid still has to
        # actually get set. If the caller sets payment_status to "Paid"
        # without ALSO giving an explicit amount_paid, auto-fill
        # amount_paid = total_due (and payment_date = today, if not
        # already given) so the invoice lands in a genuinely consistent
        # state rather than "Paid" with $0 recorded as received.
        #
        # Bug fixed same day, caught immediately on re-test: the first
        # version of this checked only whether THIS call's set_cols
        # included amount_paid/payment_date — not whether the ROW already
        # had one. A caller resubmitting {"Payment Status": "Paid"} on an
        # invoice that was already correctly paid (e.g. re-saving a form,
        # or a person re-confirming payment status) silently overwrote a
        # real recorded payment_date with today's date. Now checks the
        # row's EXISTING value too — only fills a genuine gap, never
        # clobbers a value that's already there, whether that value came
        # from this call or a previous one.
        if table == "invoices" and "payment_status" in set_cols:
            if str(set_cols["payment_status"]).strip().lower() == "paid":
                if ("amount_paid" not in set_cols and not row["amount_paid"]
                        and row["total_due"] is not None):
                    set_cols["amount_paid"] = row["total_due"]
                    updated.append(f"Amount Paid ($) -> {row['total_due']} (auto-filled)")
                if ("payment_date" not in set_cols and "payment_date" in cols_present
                        and not row["payment_date"]):
                    today_iso = datetime.date.today().isoformat()
                    set_cols["payment_date"] = today_iso
                    updated.append(f"Payment Date -> {today_iso} (auto-filled)")

        # Spec §13 Cases A/B — silently drop, never hard-block (see
        # _split_field_ownership's docstring: the Jobs PWA resubmits
        # every field it loaded, including read-only ones, so a hard
        # denial here would break ordinary edits to an invoiced job or
        # a customer-linked row).
        owned_elsewhere = _split_field_ownership(table, set_cols, row, header_map)
        if owned_elsewhere:
            dropped_headers = {h for h, _ in owned_elsewhere}
            updated = [u for u in updated
                       if not any(u.startswith(f"{h} ->") for h in dropped_headers)]

        if check_fn is not None:
            denial = check_fn(conn, row)
            if denial:
                return denial

        if expected_version is not None and has_version and row["version"] != expected_version:
            pk_val = row[id_db_column]
            last_editor = row["last_edited_by"] if "last_edited_by" in row.keys() else None
            last_at = row["last_edited_at"] if "last_edited_at" in row.keys() else "an earlier time"
            return (
                f"❌ Conflict: {pk_val} was updated by {last_editor or 'someone else'} "
                f"at {last_at} (now at version {row['version']}, "
                f"you loaded version {expected_version}) — reload and try again.\n"
                "No changes were written."
            )

        if not set_cols:
            # Everything requested was either unrecognized, or owned
            # elsewhere and silently dropped — the latter is not an
            # error (it's exactly what a PWA whole-form resubmit looks
            # like when the person only touched a read-only field, or
            # touched nothing that survived the drop).
            if owned_elsewhere or computed_only:
                pk_val = row[id_db_column]
                notes = [f"✅ {table} unchanged: {pk_val} — nothing else in this request was writable."]
                if owned_elsewhere:
                    notes.append("   ℹ️  Set elsewhere, not changed here: " +
                                 ", ".join(f"{h} (now set by {d})" for h, d in owned_elsewhere))
                if computed_only:
                    notes.append(f"   ℹ️  Computed live from other records, not stored directly: "
                                  f"{', '.join(computed_only)}")
                return "\n".join(notes)
            return "❌ No recognized columns to update (check spelling)."

        set_parts = [f"{c} = ?" for c in set_cols]
        set_values = list(set_cols.values())
        if has_version:
            set_parts.append("version = version + 1")
        if "last_edited_by" in cols_present:
            set_parts.append("last_edited_by = ?")
            set_values.append(actor)
        if "last_edited_at" in cols_present:
            set_parts.append("last_edited_at = ?")
            set_values.append(utcnow_iso())
        set_values.append(row["_rowid"])
        conn.execute(
            f"UPDATE {table} SET {', '.join(set_parts)} WHERE rowid = ?",
            set_values,
        )
        pk_val = row[id_db_column]
        new_version = (row["version"] + 1) if has_version else None

    lines = [f"✅ {table} updated: {pk_val}",
             f"   Updated: {', '.join(updated) if updated else '(no recognized fields)'}"]
    if not_found:
        lines.append(f"   ⚠️  Columns not found (check spelling): {', '.join(not_found)}")
    if owned_elsewhere:
        lines.append("   ℹ️  Set elsewhere, not changed here: " +
                      ", ".join(f"{h} (now set by {d})" for h, d in owned_elsewhere))
    if computed_only:
        lines.append(f"   ℹ️  Computed live from other records, not stored directly: "
                      f"{', '.join(computed_only)}")
    if new_version is not None:
        lines.append(f"NEW_VERSION={new_version}")
    return "\n".join(lines)


def make_jobs_crew_check(restrict: bool, crew_name: str):
    """Builds the check_fn for db_update_row(table='jobs', ...),
    replicating update_job_spreadsheet's Jobs_Schedule branch exactly."""
    def _check(conn, row):
        if not restrict:
            return None
        row_crew = str(row["crew"] or "").strip().lower()
        if not _crew_name_in_cell(row_crew, crew_name):
            return ("❌ You can only update jobs assigned to you "
                     "(Crew / Technician column). This row is not assigned to you.")
        return None
    return _check


def make_linked_customer_check(restrict: bool, crew_name: str, table: str, requested_headers):
    """Builds the check_fn for db_update_row(table in
    {'customers','invoices','quotes'}, ...), replicating
    update_job_spreadsheet's Customers/Invoices/Quotes branch exactly,
    including the Customers-only locked-fields check."""
    def _check(conn, row):
        if not restrict:
            return None
        customer_id = row["customer_id"]
        if not db_customer_in_crew_scope(conn, crew_name, customer_id):
            return (f"❌ You can only update {table} records for a customer you've "
                     f"actually worked a job for. This CustomerID isn't linked to any "
                     f"job assigned to you.")
        if table == "customers":
            locked = {h for h in requested_headers
                      if _normalize_header(h) in _FIELD_CREW_LOCKED_CUSTOMER_HEADERS}
            if locked:
                return (f"❌ These Customers fields require staff/manager/owner access: "
                         f"{', '.join(sorted(locked))}. Contact info, address, service "
                         f"preferences, and access notes are still fine to update.")
        return None
    return _check


def db_update_job(db_path, job_identifier, updates, actor, restrict=False, crew_name="",
                   id_column="JobID (JOB-####)", expected_version: int = None) -> str:
    id_db_column = JOBS_HEADER_MAP.get(_normalize_header(id_column), "job_id")
    # Spec §13: field-ownership (Cases A/B/C) is enforced inside
    # db_update_row by silently dropping the field (_split_field_
    # ownership / _split_computed_only), not by a hard check_fn denial —
    # see those functions' docstrings for why. Only the crew-scoping
    # permission check remains a hard denial here.
    check_fn = make_jobs_crew_check(restrict, crew_name)
    touched_cols = {JOBS_HEADER_MAP.get(_normalize_header(k)) for k in (updates or {})}
    addr_before = None
    if touched_cols & _JOB_ADDRESS_COLS and not touched_cols & {"latitude", "longitude"}:
        addr_before = _job_address_snapshot(db_path, id_db_column, job_identifier)
    result = db_update_row(db_path, "jobs", JOBS_HEADER_MAP, id_db_column, job_identifier,
                           updates, actor, check_fn=check_fn, expected_version=expected_version)
    # R-058: a day-unit duration keeps the End Date in step (before the stale-
    # stop clean-up below, which then sees the job's real span).
    if str(result).startswith("✅") and touched_cols & {"est_duration", "est_duration_unit", "service_date"}:
        import re as _re58
        _sync_day_unit_end_date(db_path, _re58.findall(r"JOB-\d+", str(result).splitlines()[0]))
    # The job's ADDRESS changed -> its old map location is wrong now (R-022,
    # 2026-09-26): look the new address up. Compared before/after, because the
    # edit form always sends the address fields even when they didn't change.
    try:
        if addr_before and str(result).startswith("✅"):
            for jid, before in addr_before.items():
                after = _job_address_snapshot(db_path, "job_id", jid).get(jid)
                if after and after != before:
                    _auto_geocode_job(db_path, jid, actor, force=True)
    except Exception:
        pass
    # The route follows the job (2026-09-25). Moving a job to another day, or
    # cancelling it, takes its stop off any route it no longer belongs on, so
    # the Route page never shows a stale stop and re-routing is always clean.
    try:
        touched = {JOBS_HEADER_MAP.get(_normalize_header(k)) for k in (updates or {})}
        if str(result).startswith("✅") and touched & {"service_date", "end_date", "job_status"}:
            import re as _re
            job_ids = _re.findall(r"JOB-\d+", str(result).splitlines()[0])
            if job_ids:
                from db_route_ops import db_drop_stale_job_stops, db_drop_cancelled_job_stops
                db_drop_stale_job_stops(db_path, job_ids)
                db_drop_cancelled_job_stops(db_path, job_ids)
    except Exception:
        pass            # the job edit itself already succeeded; never fail it over this
    return result


def db_update_customer(db_path, customer_identifier, updates, actor, restrict=False, crew_name="",
                        id_column="CustomerID (CUST-####)", expected_version: int = None) -> str:
    id_db_column = CUSTOMERS_HEADER_MAP.get(_normalize_header(id_column), "customer_id")
    # Spec §13.4's rollup fields are enforced by _split_computed_only
    # (the columns don't exist) inside db_update_row — no check_fn needed.
    check_fn = make_linked_customer_check(restrict, crew_name, "customers", updates.keys())
    return db_update_row(db_path, "customers", CUSTOMERS_HEADER_MAP, id_db_column,
                          customer_identifier, updates, actor, check_fn=check_fn,
                          expected_version=expected_version)


# ── db_delete_customer ──────────────────────────────────────────────────
# Added 2026-09-15 at the owner's explicit request. This is the ONE
# exception to AI-Prowler's own "never delete, only retire" rule —
# db_schema.py's own comment on customers.status says "Active/Inactive —
# never deleted", and every other write tool in this codebase only edits
# or appends a row. The rule held because deleting a customer with real
# linked Jobs/Invoices either orphans those rows or silently destroys
# financial history. The gap this closes: test and mistaken customer
# records accumulate real linked Jobs/Invoices during normal use and
# testing (the ZTEST convention used throughout this project's own test
# scripts), and previously had NO way to actually be cleaned up — marking
# them Inactive didn't even hide them anywhere in the app until the
# Inactive-filtering fix that shipped alongside this. Two guards make
# this safe to keep in the product long-term:
#
#   1. The customer must ALREADY be Status = Inactive. There is no path
#      to delete an Active customer — mark them Inactive first (a
#      separate, ordinary update_job_spreadsheet call), then delete. This
#      forces a deliberate two-step action instead of a single call that
#      could vaporize a live customer relationship by mistake.
#   2. confirm must be True, same pattern as db_restore_database — a
#      first call without it returns a preview (row counts per table)
#      and changes nothing.
#
# A safety backup of the whole database is taken (reusing
# db_backup_database, same as db_restore_database) before anything is
# deleted, so this is always recoverable from that file even though the
# live row itself is gone for good once this runs.

def _customer_cascade_counts(conn, customer_id: str):
    """Row counts across every table that references customer_id, used
    for both the pre-confirm preview and the final delete report.
    job_ids is returned too since time_entries only references jobs (not
    the customer directly), and route_stops references both."""
    job_ids = [r["job_id"] for r in conn.execute(
        "SELECT job_id FROM jobs WHERE customer_id = ?", (customer_id,)
    ).fetchall()]
    counts = {
        "jobs": len(job_ids),
        "invoices": conn.execute(
            "SELECT COUNT(*) AS n FROM invoices WHERE customer_id = ?", (customer_id,)
        ).fetchone()["n"],
        "quotes": conn.execute(
            "SELECT COUNT(*) AS n FROM quotes WHERE customer_id = ?", (customer_id,)
        ).fetchone()["n"],
    }
    if job_ids:
        placeholders = ",".join("?" for _ in job_ids)
        counts["time_entries"] = conn.execute(
            f"SELECT COUNT(*) AS n FROM time_entries WHERE job_id IN ({placeholders})",
            job_ids,
        ).fetchone()["n"]
        counts["route_stops"] = conn.execute(
            f"SELECT COUNT(*) AS n FROM route_stops WHERE customer_id = ? OR job_id IN ({placeholders})",
            [customer_id] + job_ids,
        ).fetchone()["n"]
    else:
        counts["time_entries"] = 0
        counts["route_stops"] = conn.execute(
            "SELECT COUNT(*) AS n FROM route_stops WHERE customer_id = ?", (customer_id,)
        ).fetchone()["n"]
    return job_ids, counts


def db_delete_customer(db_path: str, customer_identifier: str, confirm: bool = False) -> str:
    """Permanently delete a customer and every row that references them.
    See the module comment above this function for the full safety
    rationale. Returns a preview (confirm=False), a deletion report
    (confirm=True and it succeeded), or a clear error — customer not
    found, ambiguous match, still Active, or a safety-backup failure —
    with nothing deleted in any error case.
    """
    conn = get_connection(db_path)
    try:
        like_pattern = f"%{str(customer_identifier).strip().lower()}%"
        rows = conn.execute(
            "SELECT * FROM customers WHERE "
            "LOWER(customer_id) LIKE ? OR LOWER(IFNULL(company_name,'')) LIKE ? OR "
            "LOWER(IFNULL(first_name,'')) LIKE ? OR LOWER(IFNULL(last_name,'')) LIKE ? OR "
            "LOWER(IFNULL(first_name,'') || ' ' || IFNULL(last_name,'')) LIKE ?",
            (like_pattern,) * 5,
        ).fetchall()

        if not rows:
            return f"❌ No customer found matching '{customer_identifier}'."
        if len(rows) > 1:
            candidates = "\n".join(
                f"  {r['customer_id']} — "
                f"{r['company_name'] or (str(r['first_name'] or '') + ' ' + str(r['last_name'] or '')).strip()}"
                for r in rows
            )
            return (
                f"❌ '{customer_identifier}' matches {len(rows)} customers — use the exact "
                f"CustomerID instead:\n{candidates}"
            )

        row = rows[0]
        customer_id = row["customer_id"]
        display_name = row["company_name"] or f"{row['first_name'] or ''} {row['last_name'] or ''}".strip()

        if str(row["status"] or "").strip().lower() != "inactive":
            return (
                f"❌ {customer_id} ({display_name}) is still Active. Mark them Inactive "
                f"first (update_job_spreadsheet, sheet_name='Customers', "
                f"'Status Active/Inactive' -> 'Inactive'), then delete. An Active "
                f"customer can never be deleted directly — this is a deliberate two-step gate."
            )

        job_ids, counts = _customer_cascade_counts(conn, customer_id)
    finally:
        conn.close()

    preview_lines = [
        f"Customer:      {customer_id} — {display_name}",
        f"Jobs:          {counts['jobs']}",
        f"Invoices:      {counts['invoices']}",
        f"Quotes:        {counts['quotes']}",
        f"Time entries:  {counts['time_entries']}",
        f"Route stops:   {counts['route_stops']}",
    ]

    if not confirm:
        return (
            "❌ This permanently deletes the customer AND every linked row below. "
            "Unlike every other tool in AI-Prowler, this cannot be undone except by "
            "restoring the safety backup this call makes automatically. Pass "
            "confirm=True to proceed.\n\n" + "\n".join(preview_lines)
        )

    # Safety backup before anything is touched — same pattern as db_restore_database.
    from db_backup_ops import db_backup_database
    safety_result = db_backup_database(db_path, destination_path="")
    if not safety_result.startswith("✅"):
        return (
            "❌ Could not safety-backup the database before deleting — aborted, "
            f"nothing changed.\n{safety_result}"
        )
    safety_backup_path = safety_result.splitlines()[0].replace("✅ Backup saved: ", "")

    with transaction(db_path) as conn:
        current = conn.execute(
            "SELECT status FROM customers WHERE customer_id = ?", (customer_id,)
        ).fetchone()
        if current is None:
            return f"❌ {customer_id} no longer exists — nothing to delete."
        if str(current["status"] or "").strip().lower() != "inactive":
            return (
                f"❌ {customer_id} was reactivated (now Active) since this was checked — "
                "aborted, nothing deleted."
            )

        job_ids, counts = _customer_cascade_counts(conn, customer_id)

        if job_ids:
            placeholders = ",".join("?" for _ in job_ids)
            # Break the jobs<->invoices circular FK (jobs.invoice_id ->
            # invoices, invoices.job_id -> jobs) before invoices are removed —
            # foreign_keys=ON (db_access.py) enforces this at commit time.
            conn.execute(
                f"UPDATE jobs SET invoice_id = NULL WHERE job_id IN ({placeholders})",
                job_ids,
            )
            conn.execute(
                f"DELETE FROM time_entries WHERE job_id IN ({placeholders})", job_ids
            )
            conn.execute(
                f"DELETE FROM route_stops WHERE customer_id = ? OR job_id IN ({placeholders})",
                [customer_id] + job_ids,
            )
        else:
            conn.execute("DELETE FROM route_stops WHERE customer_id = ?", (customer_id,))
        drop_orphan_route_bookends(conn)

        conn.execute("DELETE FROM invoices WHERE customer_id = ?", (customer_id,))
        conn.execute("DELETE FROM quotes WHERE customer_id = ?", (customer_id,))
        conn.execute("DELETE FROM jobs WHERE customer_id = ?", (customer_id,))
        conn.execute("DELETE FROM customers WHERE customer_id = ?", (customer_id,))

    return (
        f"✅ Deleted {customer_id} ({display_name}) and all linked records.\n"
        f"   Safety backup saved first: {safety_backup_path}\n\n"
        + "\n".join(preview_lines[1:])
    )


def db_update_invoice(db_path, invoice_identifier, updates, actor, restrict=False, crew_name="",
                       id_column="InvoiceID (INV-####)", expected_version: int = None) -> str:
    id_db_column = INVOICES_HEADER_MAP.get(_normalize_header(id_column), "invoice_id")
    # Spec §13.2's customer-owned fields are enforced by
    # _split_field_ownership inside db_update_row — no check_fn needed.
    check_fn = make_linked_customer_check(restrict, crew_name, "invoices", updates.keys())
    return db_update_row(db_path, "invoices", INVOICES_HEADER_MAP, id_db_column,
                          invoice_identifier, updates, actor, check_fn=check_fn,
                          expected_version=expected_version)


def db_update_quote(db_path, quote_identifier, updates, actor, restrict=False, crew_name="",
                     id_column="QuoteID (QTE-####)", expected_version: int = None) -> str:
    id_db_column = QUOTES_HEADER_MAP.get(_normalize_header(id_column), "quote_id")
    # Spec §13.2's customer-owned fields are enforced by
    # _split_field_ownership inside db_update_row — no check_fn needed.
    check_fn = make_linked_customer_check(restrict, crew_name, "quotes", updates.keys())
    return db_update_row(db_path, "quotes", QUOTES_HEADER_MAP, id_db_column,
                          quote_identifier, updates, actor, check_fn=check_fn,
                          expected_version=expected_version)


def db_delete_quote(db_path: str, quote_identifier: str, confirm: bool = False) -> str:
    """Permanently delete a Quote — any status, not just Declined (spec
    change 2026-09-23, at the owner's request: the original Declined-first
    gate mirrored db_delete_customer's Inactive-first requirement, but
    quotes don't carry the same "still a live business relationship" risk
    a customer record does — an Open or Approved quote the person simply
    wants gone shouldn't need a status change first). No cascade needed:
    nothing in the schema references quotes by foreign key (db_schema.py
    has no "REFERENCES quotes" anywhere), so this is a plain single-row
    delete once confirmed. Still gated by confirm=True (preview-then-
    confirm) with an automatic safety backup, matching every other
    delete_* tool."""
    conn = get_connection(db_path)
    try:
        like_pattern = f"%{str(quote_identifier).strip().lower()}%"
        rows = conn.execute(
            "SELECT * FROM quotes WHERE LOWER(quote_id) LIKE ? OR "
            "LOWER(IFNULL(customer_name,'')) LIKE ?",
            (like_pattern, like_pattern),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return f"❌ No quote found matching '{quote_identifier}'."
    if len(rows) > 1:
        candidates = "\n".join(
            f"  {r['quote_id']} — {r['customer_name'] or ''} ({r['status'] or 'unset'})"
            for r in rows
        )
        return (
            f"❌ '{quote_identifier}' matches {len(rows)} quotes — use the exact "
            f"QuoteID instead:\n{candidates}"
        )

    row = rows[0]
    quote_id = row["quote_id"]
    display_name = row["customer_name"] or quote_id

    amount = row["quote_total"] if row["quote_total"] is not None else row["subtotal"]
    preview = (
        f"QuoteID: {quote_id} — {display_name}"
        + (f" ({row['service_type']})" if row["service_type"] else "")
        + (f" — ${amount}" if amount is not None else "")
        + f" — status: {row['status'] or 'unset'}"
    )

    if not confirm:
        return (
            "❌ This permanently deletes this quote. Nothing else in "
            "AI-Prowler references it, so there's no linked data at risk — "
            "but pass confirm=True to proceed.\n\n" + preview
        )

    from db_backup_ops import db_backup_database
    safety_result = db_backup_database(db_path, destination_path="")
    if not safety_result.startswith("✅"):
        return (
            "❌ Could not safety-backup the database before deleting — aborted, "
            f"nothing changed.\n{safety_result}"
        )
    safety_backup_path = safety_result.splitlines()[0].replace("✅ Backup saved: ", "")

    with transaction(db_path) as conn:
        current = conn.execute(
            "SELECT status FROM quotes WHERE quote_id = ?", (quote_id,)
        ).fetchone()
        if current is None:
            return f"❌ {quote_id} no longer exists — nothing to delete."
        conn.execute("DELETE FROM quotes WHERE quote_id = ?", (quote_id,))

    return (
        f"✅ Deleted quote {quote_id} ({display_name}).\n"
        f"   Safety backup saved first: {safety_backup_path}"
    )


def db_delete_job(db_path: str, job_identifier: str, confirm: bool = False) -> str:
    """Permanently delete a Job. Requires Job Status == 'Cancelled' — same
    deliberate two-step gate as db_delete_customer/db_delete_quote, so a
    Scheduled/In Progress job can never be deleted in one call, and — this
    is the actual point of the gate, not just a formality — a job with
    'Completed' status can NEVER be deleted this way at all, since a
    completed job is what income and accounting are built on (its
    invoice, its payment history, its TimeLog hours). There is no
    "confirm harder" override for a completed job; the only path off a
    completed job is Excel export / the accounting record itself, never
    this tool. Retiring a job the crew no longer wants ACTIVE without
    losing its history is a job_status change (e.g. to 'Completed' or
    'Cancelled'), not a deletion — this function only ever removes rows
    already marked Cancelled.

    Cascade, mirroring db_delete_customer's pattern one level down (jobs
    instead of customers): a cancelled job may still have TimeLog entries
    (the crew may have clocked in before it was cancelled) and a
    route_stops row (it may have been on a built route before
    cancellation) — both are deleted. jobs.invoice_id is cleared first to
    break the jobs<->invoices circular FK before any linked invoice row
    is removed (foreign_keys=ON enforces this at commit time, same
    ordering db_delete_customer already uses). A cancelled job
    legitimately having an invoice would be unusual, but nothing at the
    DB level prevents it, so the cascade covers it defensively rather
    than assuming it never happens.

    Still gated by confirm=True (preview-then-confirm) with an automatic
    safety backup, matching every other delete_* tool in this module.
    """
    conn = get_connection(db_path)
    try:
        like_pattern = f"%{str(job_identifier).strip().lower()}%"
        rows = conn.execute(
            "SELECT * FROM jobs WHERE LOWER(job_id) LIKE ? OR "
            "LOWER(IFNULL(customer_name,'')) LIKE ?",
            (like_pattern, like_pattern),
        ).fetchall()

        if not rows:
            return f"❌ No job found matching '{job_identifier}'."
        if len(rows) > 1:
            candidates = "\n".join(
                f"  {r['job_id']} — {r['customer_name'] or ''} ({r['job_status'] or 'unset'})"
                for r in rows
            )
            return (
                f"❌ '{job_identifier}' matches {len(rows)} jobs — use the exact "
                f"JobID instead:\n{candidates}"
            )

        row = rows[0]
        job_id = row["job_id"]
        display_name = row["customer_name"] or job_id
        status = str(row["job_status"] or "").strip().lower()

        # Real bug found live: the Job Status dropdown's actual value is
        # "Complete" (see jfStatus's <option> list in jobs/index.html),
        # not "Completed" — comparing against the wrong word meant this
        # gate never actually fired for a genuinely completed job.
        if status == "complete":
            return (
                f"❌ {job_id} ({display_name}) is Completed — completed jobs can "
                f"never be deleted, only hidden from view (the Sheet tab's "
                f"\"Hide completed jobs\" toggle). They're linked to income and "
                f"accounting (invoice, payment history, TimeLog hours) and must "
                f"stay in the database permanently."
            )
        if status != "cancelled":
            return (
                f"❌ {job_id} ({display_name}) is still "
                f"{row['job_status'] or 'unset'}, not Cancelled. Mark it Cancelled "
                f"first (update_job_spreadsheet, 'Job Status' -> 'Cancelled'), "
                f"then delete. Only a Cancelled job can be deleted directly — "
                f"this is a deliberate two-step gate."
            )

        counts = {
            "invoices": conn.execute(
                "SELECT COUNT(*) AS n FROM invoices WHERE job_id = ?", (job_id,)
            ).fetchone()["n"],
            "time_entries": conn.execute(
                "SELECT COUNT(*) AS n FROM time_entries WHERE job_id = ?", (job_id,)
            ).fetchone()["n"],
            "route_stops": conn.execute(
                "SELECT COUNT(*) AS n FROM route_stops WHERE job_id = ?", (job_id,)
            ).fetchone()["n"],
        }
    finally:
        conn.close()

    preview_lines = [
        f"Job:          {job_id} — {display_name}",
        f"Invoices:     {counts['invoices']}",
        f"Time entries: {counts['time_entries']}",
        f"Route stops:  {counts['route_stops']}",
    ]

    if not confirm:
        return (
            "❌ This permanently deletes this Cancelled job AND every linked "
            "row below. Pass confirm=True to proceed.\n\n" + "\n".join(preview_lines)
        )

    from db_backup_ops import db_backup_database
    safety_result = db_backup_database(db_path, destination_path="")
    if not safety_result.startswith("✅"):
        return (
            "❌ Could not safety-backup the database before deleting — aborted, "
            f"nothing changed.\n{safety_result}"
        )
    safety_backup_path = safety_result.splitlines()[0].replace("✅ Backup saved: ", "")

    with transaction(db_path) as conn:
        current = conn.execute(
            "SELECT job_status FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        if current is None:
            return f"❌ {job_id} no longer exists — nothing to delete."
        if str(current["job_status"] or "").strip().lower() != "cancelled":
            return (
                f"❌ {job_id} was changed (now {current['job_status']}) since "
                "this was checked — aborted, nothing deleted."
            )

        conn.execute("UPDATE jobs SET invoice_id = NULL WHERE job_id = ?", (job_id,))
        conn.execute("DELETE FROM time_entries WHERE job_id = ?", (job_id,))
        conn.execute("DELETE FROM route_stops WHERE job_id = ?", (job_id,))
        drop_orphan_route_bookends(conn)
        conn.execute("DELETE FROM invoices WHERE job_id = ?", (job_id,))
        conn.execute("DELETE FROM jobs WHERE job_id = ?", (job_id,))

    return (
        f"✅ Deleted job {job_id} ({display_name}) and all linked records.\n"
        f"   Safety backup saved first: {safety_backup_path}\n\n"
        + "\n".join(preview_lines[1:])
    )


# ── TimeLog / Route_Planner / Settings / Services_Pricing ───────────────
# Job Board Architecture Spec — Database-tab expansion (2026-09-12):
# wiring the four tables the Sheet/Database tab could show but couldn't
# actually read or edit yet (they'd previously hit "not yet wired to the
# DB-backed job store"). Crew-scoping choices made here, since none of
# these four had an existing spreadsheet-era rule to replicate exactly:
#   - TimeLog:  a field_crew member may edit only entries recorded under
#     their own name (same comma-list membership rule as everywhere
#     else) — their own clocked time, not a coworker's.
#   - Route_Planner: a field_crew member may edit only stops on their
#     own crew_id — their own route, matching how route_stops was
#     already partitioned by crew at the schema level from day one
#     (spec §6.4) even before anything could edit it directly.
#   - Settings / Services_Pricing: company-wide configuration, not
#     per-job data — locked out entirely for field_crew (same posture as
#     Customers' pricing-fields lock, just applied to the whole table
#     rather than a few fields within it), matching staff+ everywhere
#     else in this codebase gates money/config, not day-to-day job work.

def make_crew_field_check(restrict: bool, crew_name: str, crew_column: str, table_label: str):
    """Generalizes make_jobs_crew_check to any table with its own crew-
    identifying text column (jobs.crew, time_entries.crew,
    route_stops.crew_id) — same comma-list membership rule
    (_crew_name_in_cell), just parameterized by which column and what
    to call the table in the denial message."""
    def _check(conn, row):
        if not restrict:
            return None
        row_crew = str(row[crew_column] or "").strip().lower()
        if not _crew_name_in_cell(row_crew, crew_name):
            return (f"❌ You can only update {table_label} entries assigned to you. "
                     f"This row is not assigned to you.")
        return None
    return _check


def make_staff_only_check(restrict: bool, table_label: str):
    """Locks an entire table to staff/manager/owner — no field_crew
    write at all, regardless of which columns are being touched.
    Company-wide configuration (Settings, Services_Pricing) isn't
    per-job data a crew member could ever legitimately "own" the way a
    job or a clocked time entry is."""
    def _check(conn, row):
        if restrict:
            return (f"❌ {table_label} requires staff/manager/owner access. "
                     f"Field crew cannot edit this table.")
        return None
    return _check


def db_update_time_entry(db_path, entry_identifier, updates, actor, restrict=False, crew_name="",
                          id_column="EntryID", expected_version: int = None) -> str:
    id_db_column = TIME_ENTRIES_HEADER_MAP.get(_normalize_header(id_column), "entry_id")
    check_fn = make_crew_field_check(restrict, crew_name, "crew", "TimeLog")
    return db_update_row(db_path, "time_entries", TIME_ENTRIES_HEADER_MAP, id_db_column,
                          entry_identifier, updates, actor, check_fn=check_fn,
                          expected_version=expected_version)


def db_update_route_stop(db_path, stop_identifier, updates, actor, restrict=False, crew_name="",
                          id_column="ID", expected_version: int = None) -> str:
    id_db_column = ROUTE_STOPS_HEADER_MAP.get(_normalize_header(id_column), "id")
    check_fn = make_crew_field_check(restrict, crew_name, "crew_id", "Route_Planner")
    return db_update_row(db_path, "route_stops", ROUTE_STOPS_HEADER_MAP, id_db_column,
                          stop_identifier, updates, actor, check_fn=check_fn,
                          expected_version=expected_version)


def _normalize_route_date(val: str) -> str:
    """route_stops.route_date is always stored as ISO 'YYYY-MM-DD', but the
    Sheet tab's Route_Planner grid (and its own text-digest source,
    db_read_ops.py's read_job_spreadsheet) displays every date column as
    MM/DD/YYYY — so a caller wiring a "Delete Route" button straight off
    that display value would send "09/19/2026", which never matches any
    stored row and silently reports "No route found" even though the
    route is right there. Accepts either shape (plus the couple of other
    formats _DATE_FMTS already recognizes elsewhere in this file) and
    normalizes to ISO before the lookup; an unparseable value is passed
    through unchanged so it still surfaces as a clear "not found" rather
    than a crash."""
    val = (val or "").strip()
    if not val:
        return val
    for fmt in _DATE_FMTS:
        try:
            return datetime.datetime.strptime(val, fmt).date().isoformat()
        except ValueError:
            continue
    return val


def db_delete_route(db_path: str, route_date: str, crew: str = "", confirm: bool = False,
                     restrict: bool = False, crew_name: str = "") -> str:
    """Permanently delete an ENTIRE day's route — every stop for
    route_date (optionally scoped to one crew) — in one action, added
    2026-09-23 at the owner's request: deleting a route one stop at a
    time never made sense, since a route is one coherent plan, not a
    pile of independent rows. Same no-cascade, no-retire-first posture as
    db_delete_route_stop (nothing in the schema references route_stops by
    foreign key), gated by confirm=True with a preview first, and backed
    up automatically before anything is removed.

    Crew-scoping mirrors db_delete_route_stop: a restricted (field_crew)
    caller may only delete their own day's route, never a coworker's or
    the whole day's if other crews also have stops on it.
    """
    route_date = _normalize_route_date(str(route_date or "").strip())
    crew = str(crew or "").strip()
    if not route_date:
        return "❌ route_date is required."

    conn = get_connection(db_path)
    try:
        if crew:
            rows = conn.execute(
                "SELECT * FROM route_stops WHERE route_date = ? AND crew_id = ? ORDER BY stop_number",
                (route_date, crew),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM route_stops WHERE route_date = ? ORDER BY crew_id, stop_number",
                (route_date,),
            ).fetchall()
    finally:
        conn.close()

    if not rows:
        return f"❌ No route found for {route_date}" + (f" (crew: {crew})" if crew else "") + "."

    if restrict:
        crews_on_route = {str(r["crew_id"] or "").strip().lower() for r in rows}
        if not all(_crew_name_in_cell(c, crew_name) for c in crews_on_route):
            return ("❌ Deleting this route requires every stop on it to be your own. "
                    "Field crew cannot delete a route that includes a coworker's stops.")

    crews_involved = sorted({str(r["crew_id"] or "(unassigned)") for r in rows})
    preview = (
        f"{route_date}" + (f" — crew: {crew}" if crew else f" — crews: {', '.join(crews_involved)}")
        + f" — {len(rows)} stop(s)"
    )

    if not confirm:
        return (
            "❌ This permanently deletes the ENTIRE route for that day (every stop "
            "listed below), not just one — pass confirm=True to proceed.\n\n" + preview
        )

    from db_backup_ops import db_backup_database
    safety_result = db_backup_database(db_path, destination_path="")
    if not safety_result.startswith("✅"):
        return (
            "❌ Could not safety-backup the database before deleting — aborted, "
            f"nothing changed.\n{safety_result}"
        )
    safety_backup_path = safety_result.splitlines()[0].replace("✅ Backup saved: ", "")

    with transaction(db_path) as conn:
        if crew:
            deleted = conn.execute(
                "DELETE FROM route_stops WHERE route_date = ? AND crew_id = ?", (route_date, crew)
            ).rowcount
        else:
            deleted = conn.execute(
                "DELETE FROM route_stops WHERE route_date = ?", (route_date,)
            ).rowcount

    return (
        f"✅ Deleted the route for {route_date}" + (f" (crew: {crew})" if crew else "")
        + f" — {deleted} stop(s) removed.\n"
        f"   Safety backup saved first: {safety_backup_path}"
    )


def db_delete_route_stop(db_path: str, stop_id, confirm: bool = False,
                          restrict: bool = False, crew_name: str = "") -> str:
    """Permanently delete a Route_Planner stop. Unlike Customers/Quotes,
    no status pre-condition gate — a route stop has no "retire first"
    concept, and once a job is done the stop genuinely has no further
    use (added 2026-09-16 at the owner's request, for exactly that
    day-to-day cleanup). No cascade needed either: nothing in the schema
    references route_stops by foreign key (db_schema.py has no
    "REFERENCES route_stops" anywhere) — deleting a stop has zero effect
    on the job/customer it pointed at. Still gated by confirm=True
    (preview-then-confirm) with an automatic safety backup, matching
    every other delete_* tool.

    Crew-scoping mirrors db_update_route_stop exactly (same
    make_crew_field_check on crew_id) rather than the staff+-only
    posture delete_customer/delete_quote/delete_service_pricing use —
    route stops are day-to-day operational data a field_crew member
    already has edit access to their own, so restricting delete to
    staff+ would be an inconsistent, tighter gate than editing the same
    row already has."""
    stop_id = str(stop_id or "").strip()
    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT * FROM route_stops WHERE id = ?", (stop_id,)).fetchone()
    finally:
        conn.close()

    if not row:
        return f"❌ No route stop found with ID '{stop_id}'."

    if restrict:
        row_crew = str(row["crew_id"] or "").strip().lower()
        if not _crew_name_in_cell(row_crew, crew_name):
            return "❌ Deleting this route stop requires it to be on your own route. Field crew cannot delete a coworker's route stop."

    preview = (
        f"ID: {stop_id} — {row['route_date']} stop #{row['stop_number']}"
        + (f" ({row['address']})" if row["address"] else "")
    )

    if not confirm:
        return (
            "❌ This permanently deletes this route stop. Nothing else in "
            "AI-Prowler references it, so there's no linked data at risk — "
            "but pass confirm=True to proceed.\n\n" + preview
        )

    from db_backup_ops import db_backup_database
    safety_result = db_backup_database(db_path, destination_path="")
    if not safety_result.startswith("✅"):
        return (
            "❌ Could not safety-backup the database before deleting — aborted, "
            f"nothing changed.\n{safety_result}"
        )
    safety_backup_path = safety_result.splitlines()[0].replace("✅ Backup saved: ", "")

    with transaction(db_path) as conn:
        current = conn.execute("SELECT 1 FROM route_stops WHERE id = ?", (stop_id,)).fetchone()
        if current is None:
            return f"❌ Route stop {stop_id} no longer exists — nothing to delete."
        conn.execute("DELETE FROM route_stops WHERE id = ?", (stop_id,))
        drop_orphan_route_bookends(conn)

    return (
        f"✅ Deleted route stop {stop_id} ({row['route_date']} stop #{row['stop_number']}).\n"
        f"   Safety backup saved first: {safety_backup_path}"
    )


def _parse_hhmm(s):
    """Parses an 'HH:MM' or 'HH:MM:SS' string into a datetime anchored on
    an arbitrary fixed date (2000-01-01), so route-timeline minute
    arithmetic (adding drive minutes, comparing two times) can just use
    normal datetime subtraction/addition. Returns None if `s` is blank or
    doesn't parse — callers fall back to a default rather than crash."""
    s = (s or "").strip()
    if not s:
        return None
    for fmt in ("%H:%M", "%H:%M:%S"):
        try:
            t = datetime.datetime.strptime(s, fmt)
            return datetime.datetime(2000, 1, 1, t.hour, t.minute)
        except ValueError:
            continue
    return None


def _osrm_leg(lat1, lon1, lat2, lon2):
    """Real drive-time minutes AND drive-distance miles between two points
    via OSRM's public /route endpoint — the exact same free, no-API-key
    service and endpoint shape build_daily_route/optimize_route already
    call elsewhere in this codebase (router.project-osrm.org). One request
    gets both numbers; OSRM's own response already includes distance
    alongside duration, so there's no second round-trip needed to also
    report the Route tab's "Drive Miles" meta line.

    Returns (minutes, miles) as (int, float), or (None, None) — never
    raises — on any network or parsing failure, so a flaky OSRM lookup
    surfaces as an explicit caller-visible warning rather than crashing
    the reorder — see db_reorder_route_stop's DRIVE TIME UNKNOWN handling.

    R-063 (2026-09-29): a dropped connection (the public OSRM server cuts
    some when legs are asked for back-to-back) is retried — up to 3 tries,
    ~1.2 s apart — instead of leaving the leg blank. A blank leg's MILES
    silently fell out of the Route tab's day total. A real OSRM answer that
    isn't "Ok" (e.g. no road between the points) is not retried.
    """
    import time as _t
    try:
        coord_str = f"{lon1},{lat1};{lon2},{lat2}"
        resp = None
        for _attempt in range(3):
            try:
                resp = requests.get(
                    f"http://router.project-osrm.org/route/v1/driving/{coord_str}",
                    params={"overview": "false", "annotations": "false"},
                    timeout=30,
                ).json()
                break
            except Exception:
                if _attempt < 2:
                    _t.sleep(1.2)
                    continue
                return None, None
        if not isinstance(resp, dict) or resp.get("code") != "Ok":
            return None, None
        leg = resp["routes"][0]["legs"][0]
        minutes = round(leg["duration"] / 60.0)
        # .get(), not leg["distance"]: a leg missing "distance" (e.g. a
        # test double, or a genuinely odd OSRM response) must not also
        # kill the duration we already have — that's the whole reason
        # this is a single try/except around both, not two separate ones.
        # A real caller-visible KeyError here silently degraded to
        # "DRIVE TIME UNKNOWN" for a leg whose drive TIME was actually
        # fine, just missing distance (regression caught by
        # test_single_crew_scheduling_treats_all_jobs_as_one_day, whose
        # OSRM mock only ever set "duration").
        miles = round(leg.get("distance", 0) / 1609.344, 2)  # meters -> miles
        return minutes, miles
    except Exception:
        return None, None


def _osrm_leg_minutes(lat1, lon1, lat2, lon2):
    """Back-compat wrapper — minutes only. See _osrm_leg for the combined
    minutes+miles lookup (one OSRM request instead of two when a caller
    needs both, which every route-writing caller now does)."""
    minutes, _miles = _osrm_leg(lat1, lon1, lat2, lon2)
    return minutes


def db_reorder_route_stop(db_path: str, stop_id, new_position, actor: str,
                           restrict: bool = False, crew_name: str = "",
                           is_server_mode: bool = False) -> str:
    """Job Board Architecture Spec §14.7 (Route & Schedule Advisor, Phase
    10). Moves ONE stop to a new position within its own (route_date,
    crew_id) route — distinct from build_daily_route (full-day rebuild
    from scratch) and db_delete_route_stop (single-row removal, no
    reorder). This is the "nudge one stop" primitive both the planned
    Route-tab map widget (spec §14.5) and the Claude-assisted Advisor
    (spec §14.4) call for incremental adjustments, so a same-day tweak
    never forces the whole day's route to be recomputed from zero.

    What actually changes, and — just as importantly — what does NOT:
    - Stop # is renumbered ONLY for the stops between the old and new
      position (inclusive) — every stop outside that span keeps its
      existing stop_number, eta, version, and last_edited_at completely
      untouched. No UPDATE is ever issued for a row outside the span.
    - ETA is recomputed ONLY within that same affected span, chaining
      real OSRM drive times stop-to-stop in the new order, anchored to
      the unaffected stop immediately before the span — or, if the span
      starts at position 1, to the 'Workday Start Time' Setting (spec
      §14.2a), the same "no assumed origin" convention build_daily_route
      already uses when no explicit origin is given.
    - HONEST LIMITATION, matching this phase's deliberately narrow scope
      (spec §14.11 Phase 10): stops AFTER the affected span keep their
      previously stored ETA even though a changed total drive time
      through the span could, in principle, make that stale. This tool
      is a fast, narrow nudge, not a full re-solve — call
      build_daily_route again for a guaranteed-accurate full-day pass.
    - Any schedule_type='hard' job inside the span whose newly-computed
      arrival drifts past its committed start_time by more than the
      'Hard Time Tolerance (min)' Setting comes back as an explicit
      warning in the response — never silently dropped, never
      auto-corrected, and the write still goes through (advisory only,
      matching every other warning in this system).

    Crew-scoping mirrors db_update_route_stop/db_delete_route_stop
    exactly (same crew_id ownership check) — a field_crew member may
    reorder a stop only on their own route.

    Args:
        db_path:      Path to the SQLite job database.
        stop_id:      The route stop's own integer ID (route_stops.id) —
                      the stop being moved. Its route_date/crew_id are
                      read from its own existing row, not passed
                      separately, matching db_delete_route_stop's shape.
        new_position: Target 1-based Stop # position within that same
                      route. Clamped to the route's actual length if
                      given a value past the end.
        actor:        Display name stamped into last_edited_by on every
                      row this call actually writes.
        restrict:     True for a crew-scoped caller (field_crew).
        crew_name:    That caller's own crew name, checked against the
                      stop's crew_id when restrict=True.
        is_server_mode: Whether this install is running server mode
                      (multiple named users) rather than personal mode
                      (spec: 2026-09-19 mileage-tracking follow-up) — NOT
                      the same thing as crew_name above. Only affects the
                      Jobs-Only position-1 home-address fallback: server
                      mode looks up the MOVING STOP's own crew_id in the
                      Admin tab's user records, personal mode uses the
                      single Settings-configured Home address instead.

    Returns:
        A confirmation listing the new order/ETAs for the affected span,
        with any HARD TIME VIOLATION / DRIVE TIME UNKNOWN warnings called
        out explicitly, or a clear ❌ error (stop not found, out of
        scope, already at that position, bad new_position).
    """
    stop_id_str = str(stop_id or "").strip()
    try:
        new_position = int(new_position)
    except (TypeError, ValueError):
        return "❌ new_position must be a whole number (the target Stop # position)."
    if new_position < 1:
        return "❌ new_position must be 1 or greater."

    conn = get_connection(db_path)
    try:
        moving = conn.execute("SELECT * FROM route_stops WHERE id = ?", (stop_id_str,)).fetchone()
        if not moving:
            return f"❌ No route stop found with ID '{stop_id_str}'."

        if restrict:
            row_crew = str(moving["crew_id"] or "").strip().lower()
            if not _crew_name_in_cell(row_crew, crew_name):
                return ("❌ Reordering this route stop requires it to be on your own route. "
                        "Field crew cannot reorder a coworker's route stop.")

        route_date = moving["route_date"]
        crew_id = moving["crew_id"]
        all_stops = conn.execute(
            "SELECT * FROM route_stops WHERE route_date = ? AND crew_id = ? ORDER BY stop_number",
            (route_date, crew_id),
        ).fetchall()

        old_position = moving["stop_number"]
        n = len(all_stops)
        if new_position > n:
            new_position = n
        if new_position == old_position:
            return f"✅ Route stop {stop_id_str} is already at position {old_position} — nothing to change."

        by_id = {r["id"]: r for r in all_stops}
        ordered_ids = [r["id"] for r in all_stops]
        ordered_ids.remove(moving["id"])
        ordered_ids.insert(new_position - 1, moving["id"])

        span_start = min(old_position, new_position)
        span_end = max(old_position, new_position)
        span_ids = ordered_ids[span_start - 1: span_end]

        # Pre-fetch schedule_type/start_time for every job in the span in
        # one query, so the hard-time check below needs no further round
        # trips per stop.
        span_job_ids = [by_id[sid]["job_id"] for sid in span_ids if by_id[sid]["job_id"]]
        job_info = {}
        if span_job_ids:
            placeholders = ",".join("?" * len(span_job_ids))
            for jrow in conn.execute(
                f"SELECT job_id, schedule_type, start_time FROM jobs WHERE job_id IN ({placeholders})",
                span_job_ids,
            ).fetchall():
                # Same case-normalization bug fixed in db_route_ops.py's
                # db_get_jobs_for_route (2026-09-20) — the Jobs sheet
                # stores "Hard"/"Soft" capitalized, but the hard-time
                # check below compares against the lowercase literal
                # "hard". A separate query here duplicated the exact same
                # bug independently: a hard job caught up in a manual
                # reorder's span was silently treated as soft, so it
                # never got the HARD TIME VIOLATION warning it should
                # have if the reorder pushed its arrival past tolerance.
                job_info[jrow["job_id"]] = (str(jrow["schedule_type"] or "").strip().lower(), jrow["start_time"])
    finally:
        conn.close()

    if span_start > 1:
        anchor_row = by_id[ordered_ids[span_start - 2]]
        anchor_dt = _parse_hhmm(anchor_row["eta"]) or _parse_hhmm(db_read_settings_workday_start(db_path))
        anchor_lat, anchor_lon = anchor_row["latitude"], anchor_row["longitude"]
    else:
        anchor_dt = _parse_hhmm(db_read_settings_workday_start(db_path))
        # Real bug found live (2026-09-19): a reorder touching position 1
        # always anchored to nothing, silently dropping the day's very
        # first leg — a manual drag on the Route page has no live GPS to
        # offer (unlike "Get AI Suggestion"/"Run AI Routing", which do),
        # but it can still fall back to whatever address Route Origin
        # Mode already has configured, same as those two tools' own
        # no-GPS fallback: the Company Location business address, or
        # Jobs Only's configured Home Address. Neither configured still
        # correctly falls through to None — unchanged, origin-unaware
        # behavior for an install that's never touched either setting.
        if db_read_route_origin_mode(db_path).strip().lower() == "company location":
            anchor_lat, anchor_lon = _resolve_origin(db_path, None, None) or (None, None)
        else:
            # crew_id here is the MOVING STOP's own crew (extracted above
            # from its existing row) — the person whose home address
            # matters for this particular route, not the calling user's
            # own crew_name param (a different thing — see that param's
            # own docstring entry above).
            anchor_lat, anchor_lon = _resolve_jobs_only_origin(
                None, None, crew_name=crew_id, is_server_mode=is_server_mode) or (None, None)

    tolerance_min = db_read_settings_hard_time_tolerance_min(db_path)
    warnings = []
    row_updates = []  # (id, new_stop_number, new_eta_str, drive_min, drive_miles)

    for i, sid in enumerate(span_ids):
        row = by_id[sid]
        lat, lon = row["latitude"], row["longitude"]
        drive_min = 0
        drive_miles = None
        if anchor_lat is not None and anchor_lon is not None and lat is not None and lon is not None:
            leg_min, leg_miles = _osrm_leg(anchor_lat, anchor_lon, lat, lon)
            if leg_min is None:
                warnings.append(
                    f"⚠️ DRIVE TIME UNKNOWN for stop {sid} — OSRM lookup failed; "
                    f"its ETA below carries the previous stop's time forward unchanged."
                )
            else:
                drive_min = leg_min
                drive_miles = leg_miles

        anchor_dt = anchor_dt + datetime.timedelta(minutes=drive_min)
        new_eta_str = anchor_dt.strftime("%H:%M")
        new_stop_number = span_start + i
        row_updates.append((sid, new_stop_number, new_eta_str, drive_min, drive_miles))
        anchor_lat, anchor_lon = lat, lon

        job_id = row["job_id"]
        if job_id and job_info.get(job_id, (None, None))[0] == "hard":
            committed = _parse_hhmm(job_info[job_id][1])
            if committed is not None:
                drift = abs((anchor_dt - committed).total_seconds()) / 60.0
                if drift > tolerance_min:
                    warnings.append(
                        f"⚠️ HARD TIME VIOLATION — job {job_id} committed to "
                        f"{job_info[job_id][1]} but this reorder puts its arrival at "
                        f"{new_eta_str} ({round(drift)} min off, tolerance is {tolerance_min} min)."
                    )

    now = utcnow_iso()
    with transaction(db_path) as conn:
        # Two-phase write: route_stops has a UNIQUE(route_date, crew_id,
        # stop_number) constraint, and the affected span is being
        # permuted — writing final stop numbers in a single pass can
        # collide with another row in the same span that hasn't been
        # moved out of the way yet (e.g. moving stop 4 to position 2
        # tries to write stop_number=2 while the row currently AT
        # position 2 still holds that value). Phase 1 clears every
        # affected row to a distinct negative placeholder (guaranteed to
        # never collide with a real, positive stop_number) before phase
        # 2 assigns the real final numbers, so no intermediate state ever
        # violates the constraint.
        for placeholder, (sid, _stop_number, _eta_str, _dm, _dmi) in enumerate(row_updates, start=1):
            conn.execute(
                "UPDATE route_stops SET stop_number = ? WHERE id = ?",
                (-placeholder, sid),
            )
        for sid, stop_number, eta_str, drive_min, drive_miles in row_updates:
            conn.execute(
                "UPDATE route_stops SET stop_number = ?, eta = ?, "
                "leg_drive_min = ?, leg_drive_miles = ?, version = version + 1, "
                "last_edited_by = ?, last_edited_at = ? WHERE id = ?",
                (stop_number, eta_str, drive_min, drive_miles, actor, now, sid),
            )

    lines = [f"✅ Moved route stop {stop_id_str} to position {new_position} "
             f"(was {old_position}) — {len(row_updates)} stop(s) affected:"]
    for sid, stop_number, eta_str, _dm, _dmi in row_updates:
        row = by_id[sid]
        marker = " ← moved" if sid == moving["id"] else ""
        label = row["address"] or row["job_id"] or str(sid)
        lines.append(f"   #{stop_number}  {eta_str}  {label}{marker}")
    if warnings:
        lines.append("")
        lines.extend(warnings)
    return "\n".join(lines)


def db_update_settings(db_path, key, updates, actor, restrict=False, crew_name="",
                        id_column="Setting", expected_version: int = None) -> str:
    # crew_name accepted-but-unused: update_job_spreadsheet's dispatch calls
    # every db_fn with the same uniform kwarg set regardless of table, and
    # Settings' lock (make_staff_only_check) only needs `restrict` — there's
    # no per-crew ownership concept for company-wide configuration.
    id_db_column = SETTINGS_HEADER_MAP.get(_normalize_header(id_column), "key")
    check_fn = make_staff_only_check(restrict, "Settings")

    # Working Days (2026-10-02): refuse a value we can't understand instead of
    # silently falling back to Mon–Fri, and store it in one tidy form.
    is_working_days = str(key or "").strip().lower() == WORKING_DAYS_KEY.lower()
    if is_working_days and isinstance(updates, dict):
        updates = dict(updates)
        for hdr in list(updates):
            if SETTINGS_HEADER_MAP.get(_normalize_header(hdr)) == "value":
                days, problem = parse_working_days(updates[hdr])
                if problem:
                    return (f"❌ Working Days not saved: {problem}. "
                            f"Example: Mon,Tue,Wed,Thu,Fri,Sat")
                updates[hdr] = format_working_days(days)

    result = db_update_row(db_path, "settings", SETTINGS_HEADER_MAP, id_db_column,
                           key, updates, actor, check_fn=check_fn,
                           expected_version=expected_version)

    # New working days → re-count the End Date of every OPEN job measured in
    # days (a 10-day job finishes sooner once Saturdays count). Finished and
    # cancelled jobs keep their history.
    if is_working_days and str(result).startswith("✅"):
        try:
            conn = get_connection(db_path)
            try:
                ids = [r["job_id"] for r in conn.execute(
                    "SELECT job_id, job_status FROM jobs "
                    "WHERE LOWER(TRIM(COALESCE(est_duration_unit, ''))) = 'day'").fetchall()
                    if job_is_open(r["job_status"])]
            finally:
                conn.close()
            if ids:
                _sync_day_unit_end_date(db_path, ids)
        except Exception:
            pass
    return result


def db_update_service_pricing(db_path, service_code, updates, actor, restrict=False, crew_name="",
                               id_column="Service Code", expected_version: int = None) -> str:
    # crew_name accepted-but-unused — same reason as db_update_settings above.
    id_db_column = SERVICE_PRICING_HEADER_MAP.get(_normalize_header(id_column), "service_code")
    check_fn = make_staff_only_check(restrict, "Services_Pricing")
    return db_update_row(db_path, "service_pricing", SERVICE_PRICING_HEADER_MAP, id_db_column,
                          service_code, updates, actor, check_fn=check_fn,
                          expected_version=expected_version)


def db_create_setting(db_path: str, updates: dict, actor: str, restrict: bool = False) -> str:
    """Settings has no auto-generated ID and no created_by/version
    columns (see SETTINGS_HEADER_MAP) — a dedicated creator rather than
    a db_create_row() caller. The "Setting" field IS the primary key,
    supplied by the caller directly; fails if that key already exists
    (use update_job_spreadsheet to change an existing setting's value —
    this mirrors every other table's create-vs-update split rather than
    silently upserting)."""
    if restrict:
        return "❌ Settings requires staff/manager/owner access. Field crew cannot create settings."

    key = None
    written, not_found, set_cols = [], [], {}
    for header, val in (updates or {}).items():
        norm = _normalize_header(header)
        db_col = SETTINGS_HEADER_MAP.get(norm)
        if db_col is None:
            not_found.append(header)
            continue
        if db_col == "key":
            key = str(val or "").strip()
            continue
        set_cols[db_col] = val
        written.append(f"{header} -> {val}")

    if not key:
        return "❌ 'Setting' (the key name) is required and cannot be blank."
    if "value" in set_cols:                                           # R-057
        set_cols["value"], bad = _canon_setting_value(key, set_cols["value"])
        if bad:
            return bad
        written = [w if not w.startswith("Value ->") else f"Value -> {set_cols['value']}" for w in written]

    now = utcnow_iso()
    with transaction(db_path) as conn:
        # Case-insensitive (2026-09-25): 'Tax Rate' and 'tax rate' are the same
        # setting to a person — a second one would just shadow the first.
        existing = conn.execute("SELECT key FROM settings WHERE LOWER(key) = LOWER(?)", (key,)).fetchone()
        if existing:
            return (f"❌ Setting '{existing['key']}' already exists — use update_job_spreadsheet "
                     f"(sheet_name='Settings') to change its value instead.")
        set_cols["key"] = key
        cols_present = _table_columns(conn, "settings")
        if "last_edited_by" in cols_present:
            set_cols["last_edited_by"] = actor
        if "last_edited_at" in cols_present:
            set_cols["last_edited_at"] = now
        cols = list(set_cols.keys())
        conn.execute(
            f"INSERT INTO settings ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
            [set_cols[c] for c in cols],
        )

    lines = [f"✅ setting created: {key}",
             f"   Set:  {', '.join(written) if written else '(no fields provided)'}"]
    if not_found:
        lines.append(f"   ⚠️  Columns not found (check spelling): {', '.join(not_found)}")
    lines.append(f"NEW_KEY={key}")
    return "\n".join(lines)


def db_create_service_pricing(db_path: str, updates: dict, actor: str, restrict: bool = False) -> str:
    """service_code is caller-supplied (e.g. "WIN", "PRESS-DRIVE"), not
    auto-numbered like JOB-#### — a dedicated creator rather than a
    db_create_row() caller. Stamps last_edited_by/last_edited_at (the
    only audit columns this table actually has — no created_by, see
    SERVICE_PRICING_HEADER_MAP)."""
    if restrict:
        return "❌ Services_Pricing requires staff/manager/owner access. Field crew cannot create pricing entries."

    service_code = None
    written, not_found, set_cols = [], [], {}
    for header, val in (updates or {}).items():
        norm = _normalize_header(header)
        db_col = SERVICE_PRICING_HEADER_MAP.get(norm)
        if db_col is None:
            not_found.append(header)
            continue
        if db_col == "service_code":
            service_code = str(val or "").strip()
            continue
        set_cols[db_col] = val
        written.append(f"{header} -> {val}")

    if not service_code:
        return "❌ 'Service Code' is required and cannot be blank."
    bad = _validate_pricing_numbers(set_cols)
    if bad:
        return bad

    now = utcnow_iso()
    with transaction(db_path) as conn:
        # Case-insensitive (2026-09-25): 'ztest-win' was accepted beside
        # 'ZTEST-WIN' — two codes a person can't tell apart.
        existing = conn.execute(
            "SELECT service_code FROM service_pricing WHERE LOWER(service_code) = LOWER(?)", (service_code,)
        ).fetchone()
        if existing:
            return (f"❌ Service Code '{existing['service_code']}' already exists — use "
                     f"update_job_spreadsheet (sheet_name='Services_Pricing') to change it instead.")
        set_cols["service_code"] = service_code
        cols_present = _table_columns(conn, "service_pricing")
        if "created_by" in cols_present:
            set_cols["created_by"] = actor
        if "last_edited_by" in cols_present:
            set_cols["last_edited_by"] = actor
        if "last_edited_at" in cols_present:
            set_cols["last_edited_at"] = now
        cols = list(set_cols.keys())
        conn.execute(
            f"INSERT INTO service_pricing ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
            [set_cols[c] for c in cols],
        )

    lines = [f"✅ service_pricing created: {service_code}",
             f"   Set:  {', '.join(written) if written else '(no fields provided)'}"]
    if not_found:
        lines.append(f"   ⚠️  Columns not found (check spelling): {', '.join(not_found)}")
    lines.append(f"NEW_SERVICE_CODE={service_code}")
    return "\n".join(lines)


def db_delete_service_pricing(db_path: str, service_code: str, confirm: bool = False) -> str:
    """Permanently delete a Services_Pricing entry. Unlike db_delete_customer,
    this needs no Inactive-first gate and no cascade — nothing in the schema
    references service_pricing by foreign key (Jobs and Invoices always
    store their own copied Service Type and amount at creation time, never
    a live link back to the price list — see db_schema.py, no
    "REFERENCES service_pricing" anywhere). Deleting a stale price entry
    here has zero effect on any job or invoice that already used it. Still
    gated by confirm=True (preview-then-confirm, same pattern as
    db_delete_customer/restore_database) since it's still a permanent
    removal with no undo except the safety backup this call makes
    automatically."""
    service_code = str(service_code or "").strip()
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM service_pricing WHERE service_code = ?", (service_code,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return f"❌ No pricing entry found with Service Code '{service_code}'."

    display_name = row["name"] or service_code
    price = row["base_price"]
    preview = f"Service Code: {service_code} — {display_name}" + (f" (${price})" if price is not None else "")

    if not confirm:
        return (
            "❌ This permanently deletes this pricing entry. Nothing else in "
            "AI-Prowler references it — any job or invoice that already used "
            "this price keeps its own already-copied number untouched — but "
            "pass confirm=True to proceed.\n\n" + preview
        )

    from db_backup_ops import db_backup_database
    safety_result = db_backup_database(db_path, destination_path="")
    if not safety_result.startswith("✅"):
        return (
            "❌ Could not safety-backup the database before deleting — aborted, "
            f"nothing changed.\n{safety_result}"
        )
    safety_backup_path = safety_result.splitlines()[0].replace("✅ Backup saved: ", "")

    with transaction(db_path) as conn:
        current = conn.execute(
            "SELECT 1 FROM service_pricing WHERE service_code = ?", (service_code,)
        ).fetchone()
        if current is None:
            return f"❌ Service Code '{service_code}' no longer exists — nothing to delete."
        conn.execute("DELETE FROM service_pricing WHERE service_code = ?", (service_code,))

    return (
        f"✅ Deleted pricing entry {service_code} ({display_name}).\n"
        f"   Safety backup saved first: {safety_backup_path}"
    )

# ── log_time_entry ────────────────────────────────────────────────────────

def _find_unique_job(conn, job_identifier: str):
    """Same unambiguous-match requirement as _log_time_entry_impl: the
    identifier must match exactly one job (by job_id or customer_name),
    or this returns an error string as the second element."""
    pattern = f"%{job_identifier.lower()}%"
    rows = conn.execute(
        "SELECT job_id, customer_name, crew FROM jobs "
        "WHERE LOWER(job_id) LIKE ? OR LOWER(customer_name) LIKE ? OR LOWER(customer_id) LIKE ?",
        (pattern, pattern, pattern),
    ).fetchall()
    if not rows:
        return None, (
            f"❌ No job found matching '{job_identifier}' in jobs.\n"
            "Check the JobID or customer name and try again — clocking in/out "
            "requires an exact job, not a guess."
        )
    if len(rows) > 1:
        candidates = "\n".join(f"   • {r['job_id'] or '(no JobID)'} — {r['customer_name']}"
                                for r in rows[:10])
        return None, (
            f"❌ '{job_identifier}' matches {len(rows)} jobs — please specify which one:\n"
            f"{candidates}\n\nTry again with the exact JobID."
        )
    return rows[0], None


def _gps_to_map_url(coords: str) -> str:
    """"lat,lng" -> a Google Maps link centered on that point, or "" for
    blank/malformed input. Used by db_log_time_entry() to store a real,
    clickable location alongside the raw coordinates, so the Jobs PWA can
    render "where the crew clocked in/out" as a tap-through link instead
    of a bare lat,lng string nobody can act on directly.
    """
    coords = (coords or "").strip()
    if not coords or "," not in coords:
        return ""
    try:
        lat_s, lng_s = coords.split(",", 1)
        lat, lng = float(lat_s.strip()), float(lng_s.strip())
    except ValueError:
        return ""
    return f"https://www.google.com/maps?q={lat},{lng}"


def db_log_time_entry(db_path: str, job_identifier: str, action: str,
                       user_id: str, user_display_name: str, gps_coords: str = "") -> str:
    """DB-backed replacement for _log_time_entry_impl.

    Ownership ("is this my open entry?") is now a real `crew_user_id`
    foreign-key match rather than name-matching against a free-text
    "Crew / Technician" cell (spec Phase 1 explicit regression-test
    requirement — the old "Logged By (User ID)" column was optional and
    frequently absent, so equality against it could never hold either
    direction; a real FK column that always exists fixes that
    structurally). `user_id=""` means personal mode: any open entry for
    the job counts as "yours", matching the original's single-user
    posture.

    Also writes Actual Duration back to `jobs` on clock-out, same as
    the spreadsheet version — now a plain UPDATE instead of a second
    worksheet scan.
    """
    action = (action or "").strip().lower()
    if action not in ("start", "stop"):
        return "❌ action must be 'start' or 'stop'."

    with transaction(db_path) as conn:
        job, err = _find_unique_job(conn, job_identifier)
        if err:
            return err
        job_id, cust_name = job["job_id"], job["customer_name"]

        personal_mode = not user_id
        crew_display = user_display_name if not personal_mode else (job["crew"] or "")

        # time_entries.crew_user_id is a FOREIGN KEY REFERENCES users(id) —
        # ensuring ownership matching survives storage swap (spec Phase 1
        # explicit regression-test requirement) means every server-mode
        # caller's id must exist there. The `users` table is otherwise only
        # populated by the one-time users.json importer (spec §4.2), which
        # may not have run yet for a brand-new server-mode user — without
        # this, the very first clock-in for such a user would raise an
        # unhandled sqlite3.IntegrityError instead of recording the entry.
        # A minimal id-only upsert is enough to satisfy the FK; the real
        # importer can still enrich the row later without conflict.
        if not personal_mode:
            conn.execute("INSERT OR IGNORE INTO users (id) VALUES (?)", (user_id,))

        def _is_mine(row) -> bool:
            if personal_mode:
                return True
            return (row["crew_user_id"] or "") == user_id

        open_rows = conn.execute(
            "SELECT entry_id, clock_in, crew_user_id FROM time_entries "
            "WHERE job_id = ? AND clock_out IS NULL",
            (job_id,),
        ).fetchall()

        if action == "start":
            for row in open_rows:
                if _is_mine(row):
                    return (f"⚠️  A clock-in for {job_id} is already open.\n"
                            f"   Clocked in at: {row['clock_in']}\n"
                            "   Call log_time_entry with action='stop' to clock out first.")

            entry_id = generate_next_id(conn, "time_entries", "entry_id", "TE", 4)
            now = datetime.datetime.now()
            now_str = now.strftime("%Y-%m-%d %H:%M:%S")
            actor = user_display_name if not personal_mode else (crew_display or "operator")
            clock_in_gps_clean = (gps_coords or "").strip()
            conn.execute(
                """INSERT INTO time_entries
                   (entry_id, job_id, customer_name, entry_date, clock_in, crew,
                    crew_user_id, clock_in_gps, clock_in_map_url, created_by,
                    last_edited_by, last_edited_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (entry_id, job_id, cust_name, now.strftime("%Y-%m-%d"), now_str,
                 crew_display, user_id or None, clock_in_gps_clean,
                 _gps_to_map_url(clock_in_gps_clean),
                 actor, actor, utcnow_iso()),
            )
            return (
                f"⏱️  Clocked IN\n"
                f"   Entry ID:  {entry_id}\n"
                f"   Job:       {job_id}\n"
                f"   Customer:  {cust_name}\n"
                f"   Clock In:  {now_str}\n"
                f"   Crew:      {crew_display or '(unspecified)'}\n"
                "   Call log_time_entry(action='stop') when finished."
            )

        # action == "stop"
        mine = [r for r in open_rows if _is_mine(r)]
        if not mine:
            if open_rows:
                return (f"❌ No open clock-in found for '{job_identifier}' under your name. "
                         f"Someone else on the crew has an open entry for this job, but you "
                         f"can only clock out your own.")
            return (f"❌ No open clock-in found for '{job_identifier}'.\n"
                     "   Call log_time_entry(action='start') first.")

        open_row = mine[0]
        try:
            clock_in_dt = datetime.datetime.strptime(str(open_row["clock_in"]).strip(),
                                                       "%Y-%m-%d %H:%M:%S")
        except Exception:
            return f"❌ Could not parse Clock In time: {open_row['clock_in']}"

        now = datetime.datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        elapsed_mins = round((now - clock_in_dt).total_seconds() / 60)

        actor = user_display_name if not personal_mode else "operator"
        clock_out_gps_clean = (gps_coords or "").strip()
        conn.execute(
            """UPDATE time_entries SET clock_out = ?, clock_out_gps = ?,
               clock_out_map_url = ?, last_edited_by = ?, last_edited_at = ?,
               version = version + 1
               WHERE entry_id = ?""",
            (now_str, clock_out_gps_clean, _gps_to_map_url(clock_out_gps_clean),
             actor, utcnow_iso(), open_row["entry_id"]),
        )
        # Actual Duration writeback to jobs — plain UPDATE, no second scan needed.
        conn.execute(
            """UPDATE jobs SET actual_duration = ?,
               actual_duration_unit = COALESCE(actual_duration_unit, 'min')
               WHERE job_id = ?""",
            (elapsed_mins, job_id),
        )

        hours, mins = divmod(elapsed_mins, 60)
        elapsed_str = f"{hours}h {mins}m" if hours else f"{mins}m"
        return (
            f"⏱️  Clocked OUT\n"
            f"   Job:          {job_id}\n"
            f"   Customer:     {cust_name}\n"
            f"   Clock In:     {clock_in_dt.strftime('%I:%M %p')}\n"
            f"   Clock Out:    {now.strftime('%I:%M %p')}\n"
            f"   Elapsed:      {elapsed_str}  ({elapsed_mins} min)\n"
            f"   Actual Duration written to Jobs_Schedule ✅"
        )


# ── create_invoice ───────────────────────────────────────────────────────
# Ported from _read_settings_tax_rate (~7141-7173) and _create_invoice_impl
# (~7218-7548). Spec §6a category 2: Subtotal/Tax/TOTAL DUE are computed
# once, here, in Python — and stored as plain numbers, never as live
# formulas or generated columns — exactly like the spreadsheet version.
# If a later edit needs to change a stored total (e.g. a discount
# adjustment on an existing invoice), that edit re-runs this same
# calculation function; nothing here becomes "live" or recalculates on
# its own.

def db_read_settings_tax_rate(db_path: str, fallback: float = 0.07) -> float:
    """DB-backed replacement for _read_settings_tax_rate. Same three
    accepted forms (decimal <=1.0, whole-number percent, or a "7%"
    string), same fallback behavior when the key is missing/unparseable."""
    try:
        conn = get_connection(db_path)
        row = conn.execute("SELECT value FROM settings WHERE key = 'Tax Rate'").fetchone()
        conn.close()
        if row is None or row["value"] is None:
            return fallback
        raw = row["value"]
        if isinstance(raw, (int, float)):
            return float(raw) if float(raw) <= 1.0 else float(raw) / 100.0
        s = str(raw).strip().rstrip("%")
        v = float(s)
        return v if v <= 1.0 else v / 100.0
    except Exception:
        return fallback


def db_read_route_origin_mode(db_path: str, fallback: str = "Jobs Only") -> str:
    """Reads the 'Route Origin Mode' Settings key (2026-09-15 feature —
    company-location round-trip routing). Same read pattern as
    db_read_settings_tax_rate: a missing/unset key silently falls back to
    'Jobs Only', the pre-existing behavior (open path, first/last stop are
    just whichever jobs the route naturally starts/ends at) — this setting
    is additive, never a behavior change for anyone who hasn't touched it."""
    try:
        conn = get_connection(db_path)
        row = conn.execute("SELECT value FROM settings WHERE key = 'Route Origin Mode'").fetchone()
        conn.close()
        if row is None or not row["value"]:
            return fallback
        return str(row["value"]).strip()
    except Exception:
        return fallback


def db_read_settings_workday_start(db_path: str, fallback: str = "07:00") -> str:
    """Reads the 'Workday Start Time' Settings key (spec §14.2a, Route &
    Schedule Advisor, added 2026-09-16). Same read pattern as
    db_read_settings_tax_rate/db_read_route_origin_mode: a missing/unset
    key silently falls back to '07:00', so an install that hasn't touched
    this setting sees no behavior change. Used as (a) the default lower
    bound for a 'soft' job with no Start Time of its own, and (b) the
    route-building day's own start of day for time-budget purposes."""
    try:
        conn = get_connection(db_path)
        row = conn.execute("SELECT value FROM settings WHERE key = 'Workday Start Time'").fetchone()
        conn.close()
        if row is None or not row["value"]:
            return fallback
        return str(row["value"]).strip()
    except Exception:
        return fallback


def db_read_settings_workday_end(db_path: str, fallback: str = "17:00") -> str:
    """Reads the 'Workday End Time' Settings key (spec §14.2a). Mirrors
    db_read_settings_workday_start exactly, defaulting to '17:00'. Used as
    the default upper bound for a 'soft' job with no End Time of its own,
    and the route-building day's own end of day."""
    try:
        conn = get_connection(db_path)
        row = conn.execute("SELECT value FROM settings WHERE key = 'Workday End Time'").fetchone()
        conn.close()
        if row is None or not row["value"]:
            return fallback
        return str(row["value"]).strip()
    except Exception:
        return fallback


def db_read_settings_lunch_break_start(db_path: str, fallback: str = "12:00") -> str:
    """Reads the 'Lunch Break Start' Settings key (spec §14.2a). Mirrors
    db_read_settings_workday_start, defaulting to '12:00'. Marks the point
    in the day the Route & Schedule Advisor (spec §14.4) and
    reorder_route_stop (spec §14.7) insert the daily lunch pause into the
    timeline. Lunch is NOT a stop or a blocking checkpoint a job must avoid
    overlapping — whichever job's occupied time spans this moment simply
    has its effective duration extended by Lunch Break Duration (the crew
    pauses mid-job), and every later stop's computed time shifts back by
    the same amount, same as if that one job had just run long."""
    try:
        conn = get_connection(db_path)
        row = conn.execute("SELECT value FROM settings WHERE key = 'Lunch Break Start'").fetchone()
        conn.close()
        if row is None or not row["value"]:
            return fallback
        return str(row["value"]).strip()
    except Exception:
        return fallback


def db_read_settings_lunch_break_duration_min(db_path: str, fallback: int = 60) -> int:
    """Reads the 'Lunch Break Duration (min)' Settings key (spec §14.2a).
    Same fallback pattern as the other new Settings readers, defaulting to
    60 minutes (a full hour). Unlike the time-of-day settings above, this
    one is numeric — a missing key, an empty value, or a value that
    doesn't parse as a number all fall back to `fallback` rather than
    raising, since a malformed Settings row should never break route
    building."""
    try:
        conn = get_connection(db_path)
        row = conn.execute("SELECT value FROM settings WHERE key = 'Lunch Break Duration (min)'").fetchone()
        conn.close()
        if row is None or row["value"] in (None, ""):
            return fallback
        return int(float(str(row["value"]).strip()))
    except Exception:
        return fallback


def db_read_settings_hard_time_tolerance_min(db_path: str, fallback: int = 10) -> int:
    """Reads the 'Hard Time Tolerance (min)' Settings key (spec §14.2a).
    Advisory-only: how far a schedule_type='hard' job's actual computed
    arrival may drift from its committed start_time before the persistent
    violation flag (spec §14.8) fires. Never changes the scheduling target
    itself — the router still aims for the exact committed time; this only
    governs when a miss gets flagged. Defaults to 10 minutes, matching the
    system's existing (unrelated) LATE ARRIVAL threshold in
    build_daily_route, so a hard job's out-of-the-box behavior feels
    consistent with what build_daily_route already warns about today."""
    try:
        conn = get_connection(db_path)
        row = conn.execute("SELECT value FROM settings WHERE key = 'Hard Time Tolerance (min)'").fetchone()
        conn.close()
        if row is None or row["value"] in (None, ""):
            return fallback
        return int(float(str(row["value"]).strip()))
    except Exception:
        return fallback


def db_read_settings_recurring_job_lead_days(db_path: str, fallback: int = 5) -> int:
    """Reads the 'Recurring Job Lead Time (days)' Settings key (added
    2026-09-23, at the owner's request): how many days BEFORE a recurring
    customer's computed next-due date db_generate_upcoming_recurring_jobs
    should create their next (unscheduled) job. A user-facing control —
    editable like any other Settings row via update_job_spreadsheet or
    create_setting — with no special validation beyond "a number": a
    tiny value (0) means "only once it's actually due," a larger one
    (e.g. 30) surfaces recurring work well ahead of time. Defaults to 5
    days, matching the example the owner gave when asking for this."""
    try:
        conn = get_connection(db_path)
        row = conn.execute("SELECT value FROM settings WHERE key = 'Recurring Job Lead Time (days)'").fetchone()
        conn.close()
        if row is None or row["value"] in (None, ""):
            return fallback
        return int(float(str(row["value"]).strip()))
    except Exception:
        return fallback


def db_read_route_address(db_path: str) -> str:
    """Reads the four Start/End Address COMPONENT Settings keys —
    'Start/End Street Address', 'Start/End City', 'Start/End State',
    'Start/End ZIP' — and joins them into one geocodable address string.
    Kept as four separate Settings rows (not one combined key) so a user
    editing routing origin sees independent boxes for exactly the
    components that actually matter for geocoding success — the same
    Street/City/State/ZIP split already used on every Job and Customer
    address — rather than one freeform text box they could format
    inconsistently. Distinct from 'Business Address' (printed on
    invoices/receipts, read separately by _read_business_info()) and from
    get_home_address()'s config.json-backed 'Home address' field (a
    separate, personal-mode-only concept used for weather lookups).

    Join format matches the "Street, City, State ZIP" pattern already
    used elsewhere in this codebase for job/customer addresses (see e.g.
    the chronological-order check in test_route_scheduling_e2e.py), so
    geocoding behaves identically to a normal job stop. Missing
    components are simply omitted rather than left as blank commas —
    a street with no city/state/zip still returns just the street (best
    effort), the same tolerance Nominatim itself has for partial
    addresses.

    Returns "" if NOTHING is set at all — callers treat that as "can't do
    Company Location mode, fall back to Jobs Only" rather than erroring
    outright."""
    try:
        conn = get_connection(db_path)
        keys = [
            "Start/End Street Address",
            "Start/End City",
            "Start/End State",
            "Start/End ZIP",
        ]
        values = {}
        for k in keys:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (k,)).fetchone()
            values[k] = str(row["value"]).strip() if row and row["value"] else ""
        conn.close()
        street = values["Start/End Street Address"]
        city = values["Start/End City"]
        state_zip = f"{values['Start/End State']} {values['Start/End ZIP']}".strip()
        return ", ".join(filter(None, [street, city, state_zip]))
    except Exception:
        return ""


# ── Origin resolution for route-timeline anchoring (moved here from ─────
# db_route_ops.py 2026-09-19, alongside adding db_reorder_route_stop as a
# third caller): db_route_ops.py imports FROM this module, so these had
# to live wherever ALL THREE route-timeline writers — build_daily_route/
# db_suggest_route_schedule (db_route_ops.py) and db_reorder_route_stop
# (this module) — can reach them without a circular import. This module
# is that shared lower layer.

def _geocode(address: str):
    """Same tiny Nominatim call as the geocode_address() tool in
    ai_prowler_mcp.py (duplicated here rather than cross-imported, since
    that module imports FROM this one, not the reverse) — returns
    (lat, lon) or None on any failure/not-found, never raises.

    R-023 (2026-09-26): Nominatim often drops the connection ("forcibly
    closed by the remote host") when two lookups land close together — the
    E2E suite saw about half of them fail that way, which silently left a
    new job with no map location. A dropped/failed request is retried (up to
    3 tries, ~1.2 s apart, within Nominatim's 1 request/second policy); a
    real "not found" answer is NOT retried.

    R-062 (2026-09-29): successful answers are cached for the life of the
    process. build_daily_route looks up the SAME start/end address for every
    day it routes, and back-to-back day builds were getting their connection
    cut by Nominatim (it was the one lookup R-023 missed). Only hits are
    cached — a miss or an outage is looked up again next time."""
    import time as _t
    _key = " ".join(str(address or "").lower().split())
    if _key in _GEOCODE_CACHE:
        return _GEOCODE_CACHE[_key]
    for attempt in range(3):
        try:
            data = requests.get(
                "https://nominatim.openstreetmap.org/search",
                params={"q": address, "format": "json", "limit": 1},
                headers={"User-Agent": "AI-Prowler/5.0 (field-service-tool)"},
                timeout=10,
            ).json()
        except Exception:
            if attempt < 2:
                _t.sleep(1.2)
                continue
            return None
        try:
            if not data:
                return None
            _hit = (float(data[0]["lat"]), float(data[0]["lon"]))
        except Exception:
            return None
        if _key:
            _GEOCODE_CACHE[_key] = _hit
        return _hit
    return None


_GEOCODE_CACHE = {}   # R-062: normalized address -> (lat, lon), hits only


def _resolve_origin(db_path: str, origin_lat, origin_lon):
    """Resolves the point a route's ordering should start from, for
    spec §6.3/§14's "use current location, else the configured Start/End
    Address" behavior:

    1. An explicit (origin_lat, origin_lon) — live device GPS, passed
       through from the caller — always wins when both are given.
    2. Otherwise, when Settings → "Route Origin Mode" is "Company
       Location", geocode Settings → Start/End Address
       (db_read_route_address) and use that.
    3. Otherwise None — the pre-existing origin-unaware behavior,
       unchanged for any install that hasn't touched either setting.

    Never raises: a bad/unset address or a failed geocode falls through
    to None rather than blocking the route, matching build_daily_route's
    own "can't do Company Location mode, fall back to Jobs Only" posture
    for the exact same setting.
    """
    if origin_lat is not None and origin_lon is not None:
        return (origin_lat, origin_lon)
    try:
        if db_read_route_origin_mode(db_path).strip().lower() == "company location":
            addr = db_read_route_address(db_path)
            if addr:
                return _geocode(addr)
    except Exception:
        pass
    return None


def _state_dir_for_lookup():
    """Mirrors ai_prowler_mcp.py's _state_dir() exactly — env var override
    for test sandboxing (AIPROWLER_TEST_STATE_DIR), else the real
    ~/.ai-prowler — duplicated here for the same reverse-import reason as
    _geocode/db_read_owner_home_address. Used by both that function and
    db_read_user_home_address_by_crew_name below, so a test's sandbox dir
    is honored for either lookup, not just one."""
    import os as _os
    from pathlib import Path as _Path
    td = _os.environ.get("AIPROWLER_TEST_STATE_DIR", "").strip()
    if td:
        return _Path(td)
    return _Path.home() / ".ai-prowler"


def db_read_owner_home_address() -> str:
    """Returns the owner's configured home address (Street, City, State,
    ZIP) as a single geocodable string, or "" if nothing is configured.

    Mirrors ai_prowler_mcp.py's _get_personal_owner_address()/
    get_home_address() — same ~/.ai-prowler/config.json fields
    (owner_street/owner_city/owner_state/owner_zip) — duplicated here
    rather than imported, since ai_prowler_mcp.py imports FROM this
    module and the reverse would be circular. Deliberately skips that
    function's secondary fallback to the in-process _engine.OWNER_*
    globals (this module has no access to _engine without that same
    circular-import problem) — config.json is the normal, expected
    source in practice, so this covers the real case.

    PERSONAL MODE ONLY — see db_read_user_home_address_by_crew_name for
    server mode's per-user equivalent. Used by _resolve_jobs_only_origin
    below, as the fallback home location for Jobs Only mode's symmetric
    round-trip bookend (spec: 2026-09-19 mileage-tracking follow-up) when
    live device GPS isn't available.
    """
    import json as _json
    street = city = state = zip_ = ""
    try:
        cfg_path = _state_dir_for_lookup() / "config.json"
        if cfg_path.exists():
            with open(cfg_path, "r", encoding="utf-8-sig") as f:
                cfg = _json.load(f)
            street = (cfg.get("owner_street") or "").strip()
            city = (cfg.get("owner_city") or "").strip()
            state = (cfg.get("owner_state") or "").strip()
            zip_ = (cfg.get("owner_zip") or "").strip()
    except Exception:
        pass
    if not any([street, city, state, zip_]):
        return ""
    city_state_zip = " ".join(p for p in (city, state) if p)
    if zip_:
        city_state_zip = f"{city_state_zip} {zip_}".strip()
    return ", ".join(p for p in (street, city_state_zip) if p)


def db_read_user_home_address_by_crew_name(crew_name: str) -> str:
    """SERVER MODE's per-user equivalent of db_read_owner_home_address
    above. Looks up crew_name's own configured Home address (Admin tab ->
    Add/Edit User -> "Home address", stored in users.json's home_address
    field) — the same field ai_prowler_mcp.py's _resolve_route_home
    already reads for the "Run AI Routing" start/end picker.

    Real gap found live (2026-09-19): _resolve_jobs_only_origin originally
    only ever checked db_read_owner_home_address (personal mode's single
    config.json address) — in server mode that's the wrong address
    entirely (some OTHER person's home, not this crew member's), so the
    Jobs-Only home bookend never worked correctly for a server-mode
    install with multiple crew members. This is that missing per-user
    lookup, duplicated here (not imported from ai_prowler_mcp.py, which
    imports FROM this module — the reverse would be circular) minus
    _resolve_route_home's ctx-based cross-user permission check: by the
    time this runs, crew_name has already passed through an earlier
    crew-scoping check (the route/suggestion this backs is already
    restricted to crews the calling user may see), so re-checking role
    here would be redundant, not an actual security gap.

    Case-insensitive exact match on the ACTIVE user's own name. Returns
    "" (never raises) if users.json is missing, malformed, or no active
    user matches crew_name — including when crew_name itself is blank,
    since there is no single "the" user to fall back to in server mode
    (unlike personal mode's one implicit owner).
    """
    import json as _json
    crew_name = (crew_name or "").strip()
    if not crew_name:
        return ""
    try:
        path = _state_dir_for_lookup() / "users.json"
        if not path.exists():
            return ""
        data = _json.loads(path.read_text(encoding="utf-8-sig"))
        users = data.get("users") if isinstance(data, dict) else None
        if not isinstance(users, dict):
            return ""
        wanted = crew_name.casefold()
        for rec in users.values():
            if (isinstance(rec, dict)
                    and rec.get("status", "active") == "active"
                    and str(rec.get("name") or "").strip().casefold() == wanted):
                return str(rec.get("home_address") or "").strip()
    except Exception:
        pass
    return ""


def _resolve_jobs_only_origin(origin_lat, origin_lon, crew_name: str = "", is_server_mode: bool = False,
                              db_path: str = ""):
    """Resolves the point Jobs Only mode's symmetric home-office bookend
    (spec: 2026-09-19 mileage-tracking follow-up) should use — same
    live-GPS-first precedence _resolve_origin uses for Company Location,
    but falling back to a HOME address (not a business Start/End Address,
    which Jobs Only mode has none of):

    1. An explicit (origin_lat, origin_lon) — live device GPS, captured
       client-side at the moment "Get AI Suggestion"/"Run AI Routing" was
       tapped — always wins when both are given.
    2. Otherwise, in SERVER mode: crew_name's own configured Home address
       (db_read_user_home_address_by_crew_name) — never the personal-mode
       owner config, which would be some OTHER person's home in server
       mode (the same anti-pattern _resolve_route_home's own comment
       warns against). No match (or blank crew_name) -> falls through to
       step 3 rather than giving up immediately.
    3. Otherwise, in PERSONAL mode: the owner's configured home address
       (db_read_owner_home_address).
    4. Real gap found live (2026-09-23): an install with Route Origin Mode
       left on "Jobs Only" but only a Start/End Address configured (no
       separate personal Home address) got NO bookend at all — the very
       first leg of the day silently came back 0 min/0 mi — even though
       the Route tab's own map preview shows that same Start/End Address
       as a home marker regardless of which mode is active, implying it
       was already "the" configured start point. So when db_path is given
       and steps 2-3 found nothing, fall back to the Start/End Address
       fields (db_read_route_address) before giving up — the mileage rule
       this bookend exists for (home/base-to-first-job is real deductible
       business mileage) applies just the same whichever Settings field
       the address happens to live in.
    5. Otherwise None — no bookend, matching the pre-existing
       origin-unaware behavior for an install with neither GPS access
       nor any configured start address at all.

    Never raises: a bad/unset address or a failed geocode falls through
    to None rather than blocking the route.
    """
    if origin_lat is not None and origin_lon is not None:
        return (origin_lat, origin_lon)
    try:
        addr = (db_read_user_home_address_by_crew_name(crew_name) if (is_server_mode and crew_name)
                else ("" if is_server_mode else db_read_owner_home_address()))
        if not addr and db_path:
            addr = db_read_route_address(db_path)
        if addr:
            return _geocode(addr)
    except Exception:
        pass
    return None


def db_read_email_route_on_build(db_path: str) -> bool:
    """Reads the 'Email Route On Build' Settings key — a persisted toggle
    for build_daily_route's email_link default. When the caller (Claude,
    voice, the Jobs PWA) doesn't explicitly pass email_link=True/False for
    a specific call, THIS setting decides whether a route build emails its
    tap-to-navigate link automatically. An explicit email_link argument on
    a given call always overrides this — same override pattern as Route
    Origin Mode / origin=.

    Recipient resolution is unchanged by this setting and already lives in
    build_daily_route itself: server mode emails the calling user's own
    address (from Admin -> Users), personal mode falls back to the SMTP
    config's default_to/username (Settings -> Email Configuration).

    Missing/unset key defaults to False (disabled) as of 2026-09-21 — flipped
    from the original True default now that "📧 Email Approved Route Now"
    (email_route_now) exists as a manual, on-demand alternative that works
    regardless of this setting. Auto-emailing every route build by default was
    the wrong default for a server-mode install with several crew members:
    an install that's never touched this key now stays quiet until someone
    turns it on, rather than emailing every route to every crew member's
    saved address the first time anyone builds one."""
    try:
        conn = get_connection(db_path)
        row = conn.execute("SELECT value FROM settings WHERE key = 'Email Route On Build'").fetchone()
        conn.close()
        if row is None or not row["value"]:
            return False
        return str(row["value"]).strip().lower() not in ("disabled", "false", "off", "no", "0")
    except Exception:
        return False



def db_create_invoice(db_path: str, job_identifier: str, actor: str,
                       quote_amount=None, discount=None, description: str = "",
                       service_type: str = "", tax_rate: float = -1.0,
                       due_days: int = 30, restrict: bool = False, crew_name: str = "") -> str:
    """DB-backed replacement for _create_invoice_impl. Same contract:
    unambiguous job match required, one invoice per job (refuses if the
    job already has an invoice_id), price/discount fall back to the
    job's own Quote Amount/Discount Applied when omitted, and any
    override is written back onto the job row so the job listing stays
    in sync — not just the new invoice.
    """
    import datetime as _dt

    if tax_rate is None or tax_rate < 0:
        tax_rate = db_read_settings_tax_rate(db_path)

    if not job_identifier or not job_identifier.strip():
        return "❌ job_identifier is required and cannot be blank."

    with transaction(db_path) as conn:
        rows = conn.execute(
            "SELECT rowid AS _rowid, * FROM jobs WHERE "
            "LOWER(job_id) LIKE ? OR LOWER(customer_name) LIKE ? OR LOWER(customer_id) LIKE ?",
            tuple([f"%{job_identifier.lower()}%"] * 3),
        ).fetchall()
        if not rows:
            return f"❌ No job found matching '{job_identifier}' in jobs."
        if len(rows) > 1:
            cand = "\n".join(f"   • {r['job_id'] or '(no JobID)'} — {r['customer_name'] or ''}"
                              for r in rows[:10])
            return (f"❌ '{job_identifier}' matches {len(rows)} jobs — please specify which one:\n"
                     f"{cand}\n\nTry again with the exact JobID.")
        job = rows[0]
        job_id = job["job_id"]

        if restrict:
            row_crew = str(job["crew"] or "").strip().lower()
            if not _crew_name_in_cell(row_crew, crew_name):
                return (f"❌ You can only create invoices for jobs assigned to you "
                         f"(Crew / Technician column). {job_id} is not assigned to you.")

        if job["invoice_id"]:
            return (f"❌ {job_id} already has an invoice: {job['invoice_id']}.\n"
                     "To adjust an existing invoice's amount, update the invoices "
                     "table instead of creating a second one.")

        if quote_amount is None:
            quote_amount = job["quote_amount"]
        if quote_amount is None:
            return ("❌ No price to invoice. Pass quote_amount explicitly, or set "
                     "the job's Quote Amount ($) first.")
        quote_amount = float(quote_amount)
        if quote_amount < 0:
            return "❌ quote_amount cannot be negative."

        if discount is None:
            discount = job["discount_applied"] or 0.0
        discount = float(discount)
        if discount < 0:
            return "❌ discount cannot be negative."
        if discount > quote_amount:
            return "❌ discount cannot exceed quote_amount."

        description = (description or job["service_details"] or "").strip()
        service_type = (service_type or job["service_type"] or "").strip()

        # ── Independently computed — same formula, same rounding, as the
        # spreadsheet version. This is the exact byte-for-byte calculation
        # Phase 1's financial-parity testing requirement checks against.
        subtotal = round(quote_amount, 2)
        discount_amt = round(discount, 2)
        taxable = round(subtotal - discount_amt, 2)
        tax_amt = round(taxable * float(tax_rate), 2)
        total_due = round(taxable + tax_amt, 2)

        today = _dt.date.today()
        due_date = today + _dt.timedelta(days=max(int(due_days), 0))

        new_inv_id = generate_next_id(conn, "invoices", "invoice_id", "INV", 4)
        now = utcnow_iso()

        conn.execute(
            """INSERT INTO invoices
               (invoice_id, job_id, customer_id, customer_name, customer_type,
                invoice_date, due_date, service_date, service_type, description,
                subtotal, discount, taxable_amt, tax, total_due, amount_paid,
                payment_status, days_overdue,
                created_by, last_edited_by, last_edited_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'Unpaid', 0, ?, ?, ?)""",
            (new_inv_id, job_id, job["customer_id"], job["customer_name"], job["customer_type"],
             today.isoformat(), due_date.isoformat(), job["service_date"], service_type, description,
             subtotal, discount_amt, taxable, tax_amt, total_due,
             actor, actor, now),
        )

        # Write overrides back onto the job row, and link the new invoice —
        # same as the spreadsheet version's job-row writeback.
        job_writes = []
        for col, val in (("quote_amount", subtotal), ("discount_applied", discount_amt),
                          ("service_details", description), ("service_type", service_type)):
            if val:
                job_writes.append(col)
        conn.execute(
            """UPDATE jobs SET quote_amount = ?, discount_applied = ?, service_details = ?,
               service_type = ?, invoice_id = ?,
               payment_status = COALESCE(NULLIF(payment_status, ''), 'Unpaid'),
               version = version + 1, last_edited_by = ?, last_edited_at = ?
               WHERE rowid = ?""",
            (subtotal, discount_amt, description, service_type, new_inv_id,
             actor, now, job["_rowid"]),
        )

    lines = [
        f"✅ Invoice created: {new_inv_id}  (Job {job_id})",
        f"   Customer:    {job['customer_name'] or '(none on file)'}",
        f"   Subtotal:    ${subtotal:,.2f}",
        f"   Discount:    ${discount_amt:,.2f}",
        f"   Tax ({tax_rate * 100:g}%):    ${tax_amt:,.2f}",
        f"   TOTAL DUE:   ${total_due:,.2f}",
        f"   Due:         {due_date.isoformat()} (Net {due_days})",
    ]
    if job_writes:
        lines.append(f"   Job row updated: {', '.join(job_writes)}")
    lines.append(f"NEW_INVOICE_ID={new_inv_id}")
    lines.append("💡 Ready to send: email_invoice() or text_invoice() with this InvoiceID.")
    return "\n".join(lines)


# ── schedule_next_recurring_job ──────────────────────────────────────────
# Ported from _schedule_next_recurring_job_impl. Frequency delta mapping
# (_add_months / _FREQ_MAP) is pure calendar arithmetic with no storage
# dependency, carried over verbatim from the spreadsheet version.

def _add_months(d, months):
    """Adds `months` calendar months to date `d`, correctly handling
    year rollover and day-of-month overflow (e.g. Jan 31 + 1 month ->
    Feb 28/29, never a ValueError from constructing a nonexistent
    "Feb 31")."""
    total = d.month - 1 + months
    new_year = d.year + total // 12
    new_month = total % 12 + 1
    max_day = calendar.monthrange(new_year, new_month)[1]
    return d.replace(year=new_year, month=new_month, day=min(d.day, max_day))


# Both short codes (matching the spreadsheet's historical "(W/BW/M/Q/OT)"
# header hint) and full words (the newer Excel dropdown's vocabulary) map
# to the same delta function, so either form works regardless of which
# one a given customer row happens to contain.
_FREQ_MAP = {
    "W":             lambda d: d + datetime.timedelta(weeks=1),
    "WEEKLY":        lambda d: d + datetime.timedelta(weeks=1),
    "BW":            lambda d: d + datetime.timedelta(weeks=2),
    "BIWEEKLY":      lambda d: d + datetime.timedelta(weeks=2),
    "M":             lambda d: _add_months(d, 1),
    "MONTHLY":       lambda d: _add_months(d, 1),
    "BM":            lambda d: _add_months(d, 2),
    "BI-MONTHLY":    lambda d: _add_months(d, 2),
    "BIMONTHLY":     lambda d: _add_months(d, 2),
    "Q":             lambda d: _add_months(d, 3),
    "QUARTERLY":     lambda d: _add_months(d, 3),
    "SA":            lambda d: _add_months(d, 6),
    "SEMI-ANNUALLY": lambda d: _add_months(d, 6),
    "SEMIANNUALLY":  lambda d: _add_months(d, 6),
    "A":             lambda d: _add_months(d, 12),
    "ANNUALLY":      lambda d: _add_months(d, 12),
    "YEARLY":        lambda d: _add_months(d, 12),
}

# R-057: any accepted Frequency wording ("Semi-Annual", "Bi-weekly", "every
# other week", "yearly", …) -> the _FREQ_MAP key for its period. Unrecognised
# text falls back to the old upper-cased form, so the "Unrecognised
# frequency" message is unchanged for anything genuinely unknown.
_FREQ_KEY_OF_PERIOD = {"onetime": "ONE-TIME", "weekly": "WEEKLY", "biweekly": "BIWEEKLY",
                       "monthly": "MONTHLY", "bimonthly": "BIMONTHLY", "quarterly": "QUARTERLY",
                       "semiannual": "SEMIANNUALLY", "annual": "ANNUALLY"}


def _freq_map_key(frequency) -> str:
    raw = str(frequency or "").strip()
    return _FREQ_KEY_OF_PERIOD.get(frequency_period(raw), raw.upper())


def db_schedule_next_recurring_job(db_path: str, job_identifier: str, actor: str,
                                    restrict: bool = False, crew_name: str = "",
                                    range_start: str = None, range_end: str = None) -> str:
    """DB-backed replacement for _schedule_next_recurring_job_impl. Same
    unambiguous-match contract (scoped to a date range and, for a
    restricted crew member, to their own assigned jobs), same customer-
    frequency lookup (by CustomerID first, falling back to a name match
    the way the spreadsheet version did) and W/BW/M/Q/... delta mapping,
    same one-time-customer / unrecognized-frequency messages, same new-
    job field carryover into a fresh row via db_create_job — only the
    storage swapped from an openpyxl double-sheet scan to two SELECTs
    plus that INSERT.

    range_start/range_end are ISO date strings (both None means "any" —
    no date restriction), computed by the caller from the `when` keyword
    via the pure, storage-free _srj_resolve_date_range() in
    ai_prowler_mcp.py.
    """
    conn = get_connection(db_path)
    try:
        pattern = f"%{job_identifier.lower()}%"
        query = ("SELECT * FROM jobs WHERE "
                  "(LOWER(job_id) LIKE ? OR LOWER(customer_name) LIKE ? OR LOWER(customer_id) LIKE ?)")
        params = [pattern, pattern, pattern]
        if range_start is not None:
            query += " AND service_date BETWEEN ? AND ?"
            params += [range_start, range_end]
        rows = conn.execute(query + " ORDER BY rowid", params).fetchall()
    finally:
        conn.close()

    if restrict:
        rows = [r for r in rows if _crew_name_in_cell(str(r["crew"] or "").strip().lower(), crew_name)]

    if not rows:
        scope_note = " assigned to you" if restrict else ""
        when_note = "" if range_start is None else (
            f" scheduled {range_start}" if range_start == range_end
            else f" scheduled {range_start} to {range_end}"
        )
        return (
            f"❌ No job found matching '{job_identifier}'{when_note}{scope_note} in jobs."
            + ("" if range_start is None else " Try when='any' to search all dates.")
        )

    if len(rows) > 1:
        candidates = "\n".join(
            f"   • {r['job_id'] or '?'} — {r['customer_name'] or '?'}" for r in rows[:10]
        )
        return (
            f"❌ '{job_identifier}' matches {len(rows)} jobs — please specify which one:\n"
            f"{candidates}\n\nTry again with the exact JobID."
        )

    job = rows[0]
    cust_id = job["customer_id"] or ""
    cust_name = job["customer_name"] or ""
    cust_type = job["customer_type"] or ""
    crew = job["crew"] or ""
    svc_type = job["service_type"] or ""
    svc_notes = job["service_details"] or ""
    street = job["street_address"] or ""
    city = job["city"] or ""
    state = job["state"] or ""
    zipc = job["zip"] or ""
    est_dur = job["est_duration"]

    svc_date = job["service_date"]
    if not svc_date:
        return "❌ Completed job has no Service Date — cannot compute next date."
    try:
        base_date = datetime.datetime.strptime(str(svc_date)[:10], "%Y-%m-%d").date()
    except ValueError:
        return f"❌ Could not parse service date: {svc_date}"

    # ── Look up customer frequency — CustomerID first, name fallback ───────
    frequency = ""
    conn = get_connection(db_path)
    try:
        crow = None
        if cust_id:
            crow = conn.execute(
                "SELECT frequency FROM customers WHERE customer_id = ?", (cust_id,)
            ).fetchone()
        if crow is None and cust_name:
            crow = conn.execute(
                "SELECT frequency FROM customers WHERE LOWER(company_name) = ? OR LOWER(first_name) = ?",
                (cust_name.lower(), cust_name.lower()),
            ).fetchone()
        if crow is not None:
            frequency = crow["frequency"] or ""
    finally:
        conn.close()

    freq_norm = _freq_map_key(frequency)

    if freq_norm in ("OT", "ONE-TIME", "ONE TIME", "ONETIME", ""):
        return (
            f"ℹ️  No recurring job scheduled — {cust_name} is a one-time customer\n"
            f"   (Frequency: '{frequency or 'not set'}')\n"
            "   To add a recurring schedule, update the Customers sheet first."
        )

    delta_fn = _FREQ_MAP.get(freq_norm)
    if delta_fn is None:
        return (
            f"❌ Unrecognised frequency '{frequency}' for {cust_name}.\n"
            "   Expected: Weekly / Biweekly / Monthly / Bi-Monthly / "
            "Quarterly / Semi-Annually / Annually / One-time"
        )

    next_date = delta_fn(base_date)

    new_job_updates = {
        "CustomerID (Customers!A)": cust_id,
        "Customer Name / Company": cust_name,
        "Customer Type": cust_type,
        "Street Address": street,
        "City": city,
        "State": state,
        "ZIP": zipc,
        "Service Date": next_date.isoformat(),
        "Day of Week": next_date.strftime("%A"),
        "Service Type": svc_type,
        "Service Details / Notes": svc_notes,
        "Crew / Technician": crew,
        "Est. Duration": est_dur,
        "Job Status": "Scheduled",
    }
    create_result = db_create_job(db_path, new_job_updates, actor)
    new_job_id = (create_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
                  if "NEW_JOB_ID=" in create_result else "?")

    return (
        f"✅ Next recurring job scheduled\n"
        f"   New Job ID:   {new_job_id}\n"
        f"   Customer:     {cust_name}\n"
        f"   Frequency:    {frequency}  ({freq_norm})\n"
        f"   Last Service: {base_date.strftime('%m/%d/%Y')}\n"
        f"   Next Service: {next_date.strftime('%m/%d/%Y')} ({next_date.strftime('%A')})\n"
        f"   Crew:         {crew or '(unassigned)'}\n"
        f"   Service:      {svc_type}"
    )


# ── Proactive recurring-job generation (2026-09-23, at the owner's request) ──
# Unlike db_schedule_next_recurring_job above (reactive — fires only when a
# specific completed job is told to advance), this scans every recurring
# customer on its own and creates their next job AHEAD of time, based purely
# on the customer's own data (Frequency + Last Service Date — the same live-
# computed MAX(service_date) compute_customer_rollups already exposes as
# "Last Service Date" in the Customers sheet) — no job needs to be marked
# Complete first. The new job is created with NO Service Date, so it lands
# in the Jobs page / Job Board's existing "Unscheduled" column automatically
# (jobs/index.html's _boardStatus: absence of a Service Date IS what
# "Unscheduled" means — nothing new to build there), indistinguishable from
# a job an employee or admin typed in by hand — same tool (db_create_job),
# same table, same row shape.
def db_generate_upcoming_recurring_jobs(db_path: str, actor: str = "system") -> str:
    """For every Active customer with a recognized recurring Frequency,
    computes their next-due date (Last Service Date + frequency interval)
    and — once today is within the configured lead time of that date —
    creates their next job unscheduled, unless one is already pending.

    "Already pending" = this customer already has a job with a blank
    Service Date and a Job Status other than Cancelled — this is the
    dedupe guard: it stops the same due cycle from generating a second
    job on a later run, while still allowing a fresh one once the
    existing pending job is either scheduled (gets a real Service Date,
    which advances Last Service Date once it's serviced) or cancelled.

    A customer with no job history at all (Last Service Date is None —
    compute_customer_rollups has nothing to compute from) is skipped
    entirely — recurrence needs a real starting point; a brand-new
    customer's first job is still created by hand or via a quote, same
    as today.

    Returns a summary: how many jobs were created (with customer/date),
    and, for visibility, how many recurring customers were checked but
    not yet due. Never raises — a single customer's bad data (unparsable
    date, unrecognized frequency) is skipped and noted, not fatal to the
    whole sweep.
    """
    lead_days = db_read_settings_recurring_job_lead_days(db_path)
    today = datetime.date.today()

    conn = get_connection(db_path)
    try:
        customers = conn.execute(
            "SELECT customer_id, company_name, first_name, last_name, "
            "customer_type, frequency, street_address, city, state, zip "
            "FROM customers "
            "WHERE LOWER(IFNULL(status,'active')) != 'inactive' "
            "AND frequency IS NOT NULL AND TRIM(frequency) != ''"
        ).fetchall()
    finally:
        conn.close()

    created, skipped_not_due, skipped_pending, skipped_no_history, skipped_bad_freq = [], 0, 0, 0, 0

    for cust in customers:
        cust_id = cust["customer_id"]
        cust_name = cust["company_name"] or f"{cust['first_name'] or ''} {cust['last_name'] or ''}".strip()
        freq_norm = _freq_map_key(cust["frequency"])
        if freq_norm in ("OT", "ONE-TIME", "ONE TIME", "ONETIME", ""):
            continue
        delta_fn = _FREQ_MAP.get(freq_norm)
        if delta_fn is None:
            skipped_bad_freq += 1
            continue

        rollups = compute_customer_rollups_for_generation(db_path, cust_id)
        last_service = rollups["last_service_date"]
        if not last_service:
            skipped_no_history += 1
            continue
        try:
            base_date = datetime.datetime.strptime(str(last_service)[:10], "%Y-%m-%d").date()
        except ValueError:
            skipped_bad_freq += 1
            continue

        next_due = delta_fn(base_date)
        if today < (next_due - datetime.timedelta(days=lead_days)):
            skipped_not_due += 1
            continue

        conn = get_connection(db_path)
        try:
            pending = conn.execute(
                "SELECT 1 FROM jobs WHERE customer_id = ? AND "
                "(service_date IS NULL OR TRIM(service_date) = '') AND "
                "LOWER(IFNULL(job_status,'')) != 'cancelled'",
                (cust_id,),
            ).fetchone()
        finally:
            conn.close()
        if pending:
            skipped_pending += 1
            continue

        new_job_updates = {
            "CustomerID (Customers!A)": cust_id,
            "Customer Name / Company": cust_name,
            "Customer Type": cust["customer_type"] or "",
            "Street Address": cust["street_address"] or "",
            "City": cust["city"] or "",
            "State": cust["state"] or "",
            "ZIP": cust["zip"] or "",
            "Job Status": "Scheduled",
            # No Service Date on purpose — lands in Unscheduled until
            # someone (or Route Today/AI Routing) actually schedules it.
            "Service Details / Notes": (
                f"🔁 Auto-generated recurring job — {cust['frequency']} customer, "
                f"due ~{next_due.strftime('%m/%d/%Y')} (last serviced "
                f"{base_date.strftime('%m/%d/%Y')})."
            ),
        }
        result = db_create_job(db_path, new_job_updates, actor)
        new_job_id = (result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
                      if "NEW_JOB_ID=" in result else "?")
        created.append((new_job_id, cust_name, next_due))

    lines = [f"✅ Recurring job sweep complete — {len(created)} new unscheduled job(s) created."]
    for job_id, name, due in created:
        lines.append(f"   {job_id} — {name} (due ~{due.strftime('%m/%d/%Y')})")
    if skipped_not_due:
        lines.append(f"   {skipped_not_due} recurring customer(s) checked, not yet within the lead window.")
    if skipped_pending:
        lines.append(f"   {skipped_pending} customer(s) already have a pending unscheduled job — skipped.")
    if skipped_no_history:
        lines.append(f"   {skipped_no_history} recurring customer(s) have no job history yet — skipped.")
    if skipped_bad_freq:
        lines.append(f"   {skipped_bad_freq} customer(s) skipped — unparsable date or unrecognized frequency.")
    return "\n".join(lines)


def compute_customer_rollups_for_generation(db_path: str, customer_id: str) -> dict:
    """Same MAX(service_date)/MIN(future service_date) computation as
    db_read_ops.py's compute_customer_rollups (Last Service Date / Next
    Sched. Date) — duplicated at the read-connection level rather than
    imported, since db_write_ops.py has no existing dependency on
    db_read_ops.py and this needs only the two date fields, not the
    invoice-revenue rollup. Kept intentionally in lock-step with that
    function; if its query ever changes, mirror the change here too."""
    if not customer_id:
        return {"last_service_date": None, "next_scheduled_date": None}
    today_iso = datetime.date.today().isoformat()
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT MAX(service_date) AS last_service, "
            "MIN(CASE WHEN service_date >= ? THEN service_date END) AS next_sched "
            "FROM jobs WHERE customer_id = ?",
            (today_iso, customer_id),
        ).fetchone()
    finally:
        conn.close()
    return {"last_service_date": row["last_service"], "next_scheduled_date": row["next_sched"]}


# Throttle marker (2026-09-23): the sweep above scans every recurring
# customer, so it's real work — not something to re-run on every single
# board poll (every 60s per spec §6.1) or Jobs-sheet read. Stored as an
# ordinary Settings row (own key, prefixed so it reads clearly as internal
# bookkeeping rather than a user-facing option) holding the ISO date it last
# ran; a read-path hook calls _maybe_sweep_recurring_jobs, which is a no-op
# once it's already run today. This is what makes generation "automatic" —
# it happens the first time anyone opens the Jobs tab or the Board on a
# given day, with no scheduler, no extra setup, and no action required.
_RECURRING_SWEEP_MARKER_KEY = "internal_recurring_job_sweep_last_run"


def _maybe_sweep_recurring_jobs(db_path: str) -> None:
    """Runs db_generate_upcoming_recurring_jobs at most once per real
    calendar day. Swallows all errors — a failed or skipped sweep must
    never block the read that triggered it, same posture as
    db_route_ops.py's _cleanup_stale_route_stops."""
    try:
        today_iso = datetime.date.today().isoformat()
        conn = get_connection(db_path)
        try:
            row = conn.execute(
                "SELECT value FROM settings WHERE key = ?", (_RECURRING_SWEEP_MARKER_KEY,)
            ).fetchone()
        finally:
            conn.close()
        if row is not None and row["value"] == today_iso:
            return
        db_generate_upcoming_recurring_jobs(db_path, actor="system")
        with transaction(db_path) as conn:
            conn.execute(
                "INSERT INTO settings (key, value, last_edited_by, last_edited_at) "
                "VALUES (?, ?, 'system', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, last_edited_at = excluded.last_edited_at",
                (_RECURRING_SWEEP_MARKER_KEY, today_iso, utcnow_iso()),
            )
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# Stale-customer reminders (2026-09-23, at the owner's request)
# ═══════════════════════════════════════════════════════════════════════════
# A "hook" in the same shape as the recurring-job sweep above — deliberately
# NOT the separate scheduler_engine.py/scheduler_jobs.py background-thread
# system (per the owner's explicit instruction): that system is personal-
# mode only (its own module docstring: "automatically suppressed in server
# mode via GUI guard") and only runs while the desktop GUI is open, neither
# of which fits a feature that has to work the same way in server mode too.
# This hook instead runs off a Settings-stored "last ran" marker, checked
# from an ordinary read path — the same mechanism, and the same daily
# cadence, as recurring-job generation.

def db_read_settings_stale_customer_days(db_path: str) -> int:
    """'Stale Customer Reminder Days' Settings key — how many days since a
    customer's last service before they're considered "due for a check-in"
    by find_stale_customers() and the daily digest below. Missing/unset or
    unparseable defaults to 60."""
    try:
        conn = get_connection(db_path)
        row = conn.execute(
            "SELECT value FROM settings WHERE key = 'Stale Customer Reminder Days'"
        ).fetchone()
        conn.close()
        return int(str(row["value"]).strip()) if row and row["value"] else 60
    except Exception:
        return 60


def db_read_settings_customer_digest_enabled(db_path: str) -> bool:
    """'Customer Reminder Daily Digest' Settings key — whether the once-a-day
    hook below emails the OWNER a summary of stale customers. Missing/unset
    defaults to False: this only ever tells the owner who's due, it never
    contacts a customer on its own — but even a daily digest email is an
    opt-in, not something that starts happening the moment this code ships."""
    try:
        conn = get_connection(db_path)
        row = conn.execute(
            "SELECT value FROM settings WHERE key = 'Customer Reminder Daily Digest'"
        ).fetchone()
        conn.close()
        if row is None or not row["value"]:
            return False
        return str(row["value"]).strip().lower() not in ("disabled", "false", "off", "no", "0")
    except Exception:
        return False


def _db_read_bool_setting(db_path: str, key: str, default: bool) -> bool:
    """Shared reader for a plain Enabled/Disabled Settings row. default is
    returned verbatim when the row is missing/blank — callers decide whether
    that means "on until turned off" or "off until turned on"."""
    try:
        conn = get_connection(db_path)
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        conn.close()
        if row is None or not row["value"]:
            return default
        val = str(row["value"]).strip().lower()
        if val in ("disabled", "false", "off", "no", "0"):
            return False
        if val in ("enabled", "true", "on", "yes", "1"):
            return True
        return default
    except Exception:
        return default


def db_read_settings_customer_reminder_email_enabled(db_path: str) -> bool:
    """'Customer Reminder Email Enabled' — whether send_customer_reminders()
    is allowed to actually send on the email channel. Missing/unset defaults
    to True (the feature already worked, unconfigured, before this toggle
    existed — adding the control shouldn't silently turn it off). Checked
    ONLY by the explicit send (find_stale_customers is a search — it's
    always allowed regardless of either toggle, since looking is not
    sending)."""
    return _db_read_bool_setting(db_path, "Customer Reminder Email Enabled", default=True)


def db_read_settings_customer_reminder_sms_enabled(db_path: str) -> bool:
    """'Customer Reminder SMS Enabled' — same as the email version above,
    for the SMS channel. Independent of it: either, both, or neither can be
    on at once."""
    return _db_read_bool_setting(db_path, "Customer Reminder SMS Enabled", default=True)


# ── R-052: default Settings rows ───────────────────────────────────────────
# Every setting below already has a built-in default in its reader above
# (a missing row behaves exactly like one holding the default). But the Jobs
# app's Settings card and the GUI can only show and edit rows that EXIST, and
# nothing ever created them — an install got them only as each feature was
# added by hand. Found 2026-09-28: the server's fresh database showed just the
# 7 invoicing rows, with no Route Origin Mode, workday/lunch hours, reminder
# switches, etc. to edit.
#
# db_seed_default_settings() inserts any MISSING row with the same value its
# reader already falls back to, so seeding changes no behaviour. It never
# overwrites an existing row (ON CONFLICT DO NOTHING). Order = display order.
DEFAULT_SETTINGS = [
    ("Route Origin Mode", "Jobs Only",
     "Jobs Only (default) = the route is your scheduled jobs in order. Your home address "
     "(server mode: your own Home Address, set by an admin in Admin → Users) counts as the "
     "start and end for mileage, but the phone's tap-to-navigate link starts from your live "
     "GPS location (which is not a stop), visits each job, and ends at your home address. "
     "Company Location = the Start/End Address below is added as the first and last stop of "
     "the route; the navigation link starts from your live GPS location, goes to the Start/End "
     "Address, then your jobs, then back to the Start/End Address, and continues on to your "
     "home address (if you decide not to go home, just end the route manually). The Start/End "
     "Address can be different from the Business Address."),
    ("Start/End Street Address", "", "Used when Route Origin Mode is Company Location."),
    ("Start/End City", "", "Used when Route Origin Mode is Company Location."),
    ("Start/End State", "", "Used when Route Origin Mode is Company Location."),
    ("Start/End ZIP", "", "Used when Route Origin Mode is Company Location."),
    ("Email Route On Build", "Disabled",
     "Disabled (default) = no automatic email after Route Today or Run AI Route. Use the "
     "\"📧 Email Approved Route Now\" button on the Jobs page or Route tab to send the currently "
     "saved route on request, any time — that button works regardless of this setting. Enabled = "
     "also email the route results + link automatically every time Route Today or Run AI Route "
     "builds one. Server mode: auto-email goes to the requesting user's own email (Admin → Users). "
     "Personal mode: auto-email uses the SMTP recipient configured in Email Configuration."),
    ("Workday Start Time", "07:00",
     "Route & Schedule Advisor (Route tab). Default lower bound for a soft job with no Start Time "
     "set, and the day's own start of day for routing/time-budget purposes."),
    ("Workday End Time", "17:00",
     "Route & Schedule Advisor (Route tab). Default upper bound for a soft job with no End Time "
     "set, and the day's own end of day for routing/time-budget purposes."),
    (WORKING_DAYS_KEY, DEFAULT_WORKING_DAYS_TEXT,
     "The days your crews work (default Mon,Tue,Wed,Thu,Fri). A multi-day job is routed and "
     "shown on the Calendar only on these days, its End Date counts these days, and a job "
     "still open past its end carries over to the next of these days. Running late on a "
     "project? Add the weekend: Mon,Tue,Wed,Thu,Fri,Sat,Sun (or Mon-Sat, Weekdays,Sat, All). "
     "Jobs booked ON any day are always shown on that day."),
    ("Lunch Break Start", "12:00",
     "Route & Schedule Advisor (Route tab). Not a stop or a hard checkpoint — whichever job is in "
     "progress at this time simply has its duration extended by Lunch Break Duration, and every "
     "later stop shifts back by the same amount."),
    ("Lunch Break Duration (min)", "60",
     "Route & Schedule Advisor (Route tab). Length of the daily lunch pause, applied once "
     "wherever it lands on the day's timeline."),
    ("Hard Time Tolerance (min)", "10",
     "Route & Schedule Advisor (Route tab). Advisory only — how far a hard-committed job's actual "
     "computed arrival may drift from its Start Time before the HARD TIME VIOLATION flag fires on "
     "its Job Board card. Never relaxes the scheduling target itself."),
    ("Recurring Job Lead Time (days)", "5",
     "How many days BEFORE a recurring customer's next-due date (Last Service Date + their "
     "Frequency) their next job is auto-created, unscheduled. Runs at most once a day, the first "
     "time anyone opens the Jobs tab or the Board that day. 0 = only once actually due."),
    ("Stale Customer Reminder Days", "60",
     "How many days since a customer's last COMPLETED job before they show up in Reports → "
     "Customer Reminders as due for a check-in. Also the threshold the daily digest uses."),
    ("Customer Reminder Daily Digest", "Disabled",
     "Disabled (default) = nothing runs automatically. Enabled = once a day the owner gets ONE "
     "email listing customers due for a check-in. Never emails or texts a customer directly."),
    ("Customer Reminder Email Enabled", "Enabled",
     "Enabled (default) = the Reports → Customer Reminders \"Email Selected\" button works. "
     "Disabled = that button is grayed out and the send is refused."),
    ("Customer Reminder SMS Enabled", "Enabled",
     "Enabled (default) = the Reports → Customer Reminders \"Text Selected\" button works. "
     "Disabled = that button is grayed out and the send is refused. Still needs an SMS provider "
     "configured to actually send."),
]


def db_seed_default_settings(db_path: str) -> int:
    """R-052: add any missing DEFAULT_SETTINGS row. Returns how many rows were
    added (0 when everything already exists). Never changes an existing row.
    Best-effort: returns 0 on any error rather than breaking the caller."""
    try:
        conn = get_connection(db_path)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(settings)").fetchall()}
            have = {r[0] for r in conn.execute("SELECT key FROM settings").fetchall()}
        finally:
            conn.close()
        missing = [row for row in DEFAULT_SETTINGS if row[0] not in have]
        if not missing:
            return 0
        now = utcnow_iso()
        use_cols = ["key", "value"] + [c for c in ("notes", "last_edited_by", "last_edited_at") if c in cols]
        sql = (f"INSERT INTO settings ({', '.join(use_cols)}) "
               f"VALUES ({', '.join('?' for _ in use_cols)}) ON CONFLICT(key) DO NOTHING")
        added = 0
        with transaction(db_path) as conn:
            for key, value, note in missing:
                vals = {"key": key, "value": value, "notes": note,
                        "last_edited_by": "system", "last_edited_at": now}
                cur = conn.execute(sql, [vals[c] for c in use_cols])
                added += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        return added
    except Exception:
        return 0


def db_find_stale_customers(db_path: str, days_threshold: "int | None" = None) -> list:
    """Active customers whose most recent COMPLETED job (by Service Date) is
    at least days_threshold days old, or who have never had one at all —
    both are "due for a check-in" the same way. days_threshold defaults to
    the 'Stale Customer Reminder Days' setting (see above) when omitted.

    Last-serviced date comes from the jobs table itself (MAX completed
    service_date per customer), matching compute_customer_rollups_for_
    generation's own source of truth, NOT the Customers sheet's own "Last
    Service Date" column — that column is hand-maintained and can drift out
    of date; the actual job history doesn't.

    Returns a list of dicts, most-overdue first: customer_id, name (Company
    Name, or "First Last" when there's no company — the business-facing
    identity, used for display/logging), contact_name (2026-09-23: the
    actual PERSON to greet in a reminder — First Name when set, else On-Site
    Contact for a commercial account with no named individual on file, else
    falls back to name itself — "Hi Riverside Grill," reads as a form
    letter; "Hi Jane," reads like someone actually wrote it), email, phone,
    last_service_date (None if never serviced), days_since (None if never
    serviced — there's nothing to count days since)."""
    threshold = days_threshold if days_threshold is not None else db_read_settings_stale_customer_days(db_path)
    today = datetime.date.today()
    conn = get_connection(db_path)
    try:
        customers = conn.execute(
            "SELECT customer_id, company_name, first_name, last_name, onsite_contact, email, phone "
            "FROM customers WHERE LOWER(TRIM(status)) = 'active'"
        ).fetchall()
        out = []
        for c in customers:
            row = conn.execute(
                "SELECT MAX(service_date) AS last_service FROM jobs "
                "WHERE customer_id = ? AND LOWER(TRIM(job_status)) = 'complete'",
                (c["customer_id"],),
            ).fetchone()
            last = row["last_service"] if row else None
            if last:
                try:
                    last_date = datetime.date.fromisoformat(str(last)[:10])
                    days_since = (today - last_date).days
                except ValueError:
                    continue   # unparseable date on file — skip rather than guess
                if days_since < threshold:
                    continue
            else:
                days_since = None   # never serviced — always "due"
            name = (c["company_name"] or "").strip() or f"{c['first_name'] or ''} {c['last_name'] or ''}".strip()
            if not name:
                continue
            contact_name = (c["first_name"] or "").strip() or (c["onsite_contact"] or "").strip() or name
            out.append({
                "customer_id": c["customer_id"], "name": name, "contact_name": contact_name,
                "email": (c["email"] or "").strip(), "phone": (c["phone"] or "").strip(),
                "last_service_date": last, "days_since": days_since,
            })
    finally:
        conn.close()
    # Never-serviced customers (days_since=None) sort last, not first — a
    # customer overdue by a year is more urgent than a prospect who was never
    # serviced at all (that one's a sales question, not a check-in reminder).
    out.sort(key=lambda r: (r["days_since"] is None, -(r["days_since"] or 0)))
    return out


_CUSTOMER_DIGEST_MARKER_KEY = "internal_customer_reminder_digest_last_run"


def _maybe_send_stale_customer_digest(db_path: str) -> None:
    """Runs at most once per real calendar day: if 'Customer Reminder Daily
    Digest' is Enabled, emails the OWNER (not the customers — see this
    section's own module comment) a summary of who's due for a check-in,
    using find_stale_customers(). Silent (no email) when the setting is
    Disabled, or when nobody currently qualifies. Swallows all errors — a
    failed or skipped digest must never block the read that triggered it,
    same posture as _maybe_sweep_recurring_jobs above."""
    try:
        today_iso = datetime.date.today().isoformat()
        conn = get_connection(db_path)
        try:
            row = conn.execute(
                "SELECT value FROM settings WHERE key = ?", (_CUSTOMER_DIGEST_MARKER_KEY,)
            ).fetchone()
        finally:
            conn.close()
        if row is not None and row["value"] == today_iso:
            return
        if db_read_settings_customer_digest_enabled(db_path):
            stale = db_find_stale_customers(db_path)
            if stale:
                from ai_prowler_mcp import send_email, _email_config_load
                cfg = _email_config_load()
                to = ((cfg or {}).get("default_to") or (cfg or {}).get("username") or "").strip()
                if to:
                    threshold = db_read_settings_stale_customer_days(db_path)
                    lines = [f"{len(stale)} active customer(s) haven't been serviced in {threshold}+ days:", ""]
                    for c in stale[:50]:
                        when = f"{c['days_since']} days ago" if c["days_since"] is not None else "never serviced"
                        lines.append(f"  \u2022 {c['name']} \u2014 {when}")
                    if len(stale) > 50:
                        lines.append(f"  \u2026 and {len(stale) - 50} more")
                    lines.append("")
                    lines.append("Open Reports \u2192 Customer Reminders in the Jobs app to review and send reminders.")
                    send_email(to, f"\U0001F4C5 {len(stale)} customer(s) due for a check-in", "\n".join(lines))
        with transaction(db_path) as conn:
            conn.execute(
                "INSERT INTO settings (key, value, last_edited_by, last_edited_at) "
                "VALUES (?, ?, 'system', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, last_edited_at = excluded.last_edited_at",
                (_CUSTOMER_DIGEST_MARKER_KEY, today_iso, utcnow_iso()),
            )
    except Exception:
        pass
