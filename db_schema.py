"""
db_schema.py — Job Board Architecture Spec, Phase 0.

Canonical SQLite schema for the Job Board redesign (see
Job_Board_Architecture_Spec.md §4.2). One table per current Excel sheet.
Column names are normalized snake_case derived directly from the real
headers in AI-Prowler_Job_Tracker.xlsx (row 2 of each sheet), confirmed
by inspection on 2026-09-12.

Design notes:
- `version` (INTEGER) on every business table backs the Job Board's
  conflict-detection UX (spec §6.2): a client submits the version it
  loaded, and a write is rejected if the row has moved on. It is bumped
  by application code on every UPDATE, not by a trigger, so the writer
  can see the new value to hand back to the client in one round trip.
- `last_edited_at` also lives on every table (ISO-8601 UTC string) and
  is indexed for the Job Board's 1-minute polling query
  (`WHERE last_edited_at > ?`, spec §6.1).
- `elapsed_min` on time_entries is a real SQLite GENERATED ALWAYS AS
  (...) STORED column (spec §6a category 1: live-derived values).
- Dollar totals (Invoices/Quotes Subtotal/Tax/TOTAL DUE) are plain
  columns, NOT generated — spec §6a category 2: these are frozen at
  creation time by application code (create_invoice/create_quote) and
  must never silently recompute. Do not turn these into generated
  columns; that would reintroduce the exact bug this section warns
  against.
- No DELETE anywhere (spec §9): retirement is `status = 'Inactive'`.
  This module defines no delete helpers on purpose.
- jobs.invoice_total/actual_amount/tax_pct and customers.
  last_service_date/next_scheduled_date/total_jobs_completed/
  lifetime_revenue are retired as stored columns entirely (spec §13,
  Field Ownership & Live-Join Policy). Their live value now comes
  exclusively from db_read_ops.py's read-time overlay functions —
  joined from the linked invoice, or computed from the real jobs/
  invoices rows — never from a column on this table. They are not
  redefined here on purpose; `_drop_column_if_exists` below removes
  them from any database created before this change.
- route_stops is the schema fix from spec §4.2/§6.4: keyed by
  (route_date, crew_id) rather than being a single shared table, so
  building one crew's route can never clobber another crew's rows.
- jobs/invoices/quotes.customer_id is a nullable FK, not NOT NULL:
  the spreadsheet-era create_job/create_invoice/create_quote never
  required a CustomerID either — Customer Name / Company alone was
  always enough (an ad-hoc job, or a customer entered as free text
  with no formal Customers row yet). NOT NULL here would silently
  break that long-standing "customer name is enough" workflow the
  first time anyone created a job without a CustomerID on hand.
  SQLite's FK check is simply skipped when the column is NULL, so
  referential integrity for the rows that DO have a customer_id is
  unaffected (Phase 0 testing requirement, §11 — a non-null customer_id
  pointing at a nonexistent customer still fails cleanly).

Schema creation is idempotent: every statement uses IF NOT EXISTS, so
running `apply_schema()` twice against the same file is a no-op the
second time (see Phase 0 testing requirement in the spec, §11).
"""

SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

-- ── users ────────────────────────────────────────────────────────────
-- Migrated in from users.json (spec §4.2). `extra_json` is a forward-
-- compat catch-all for any users.json fields not modeled as real
-- columns, so the importer never has to drop data it doesn't recognize.
CREATE TABLE IF NOT EXISTS users (
    id                          TEXT PRIMARY KEY,
    email                       TEXT UNIQUE,
    phone                       TEXT,
    first_name                  TEXT,
    last_name                   TEXT,
    display_name                TEXT,
    role                        TEXT,
    scopes_json                 TEXT,   -- JSON-encoded list
    home_address                TEXT,
    private_collection_enabled  INTEGER,
    extra_json                  TEXT,   -- JSON-encoded dict of leftover fields
    created_at                  TEXT,
    updated_at                  TEXT
);

-- ── customers ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS customers (
    customer_id             TEXT PRIMARY KEY,     -- CUST-####
    customer_type           TEXT,                 -- Comm/Res
    company_name            TEXT,
    first_name              TEXT,
    last_name               TEXT,
    phone                   TEXT,
    email                   TEXT,
    street_address          TEXT,
    city                    TEXT,
    state                   TEXT,
    zip                     TEXT,
    latitude                REAL,
    longitude               REAL,
    service_types           TEXT,                 -- Win/Press/Both
    frequency               TEXT,
    schedule_type           TEXT DEFAULT 'Soft', -- Soft/Hard: default schedule type new jobs inherit (2026-10-04)
    preferred_days          TEXT,
    preferred_time_start    TEXT,                 -- preferred window start, H:MM AM/PM or empty
    preferred_time_end      TEXT,                 -- preferred window end, H:MM AM/PM or empty
    avg_job_duration_min    REAL,
    standard_quote          REAL,
    discount_pct            REAL,
    net_price                REAL,
    gate_code_notes         TEXT,
    onsite_contact          TEXT,
    status                  TEXT DEFAULT 'Active', -- Active/Inactive — never deleted
    created_by              TEXT,
    last_edited_by          TEXT,
    last_edited_at          TEXT,
    version                 INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_customers_last_edited_at ON customers(last_edited_at);
CREATE INDEX IF NOT EXISTS idx_customers_status ON customers(status);

-- ── jobs (Jobs_Schedule) ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS jobs (
    job_id                  TEXT PRIMARY KEY,     -- JOB-####
    customer_id             TEXT REFERENCES customers(customer_id),
    customer_name           TEXT,
    customer_type           TEXT,
    street_address          TEXT,
    city                    TEXT,
    state                   TEXT,
    zip                     TEXT,
    latitude                REAL,
    longitude               REAL,
    service_date            TEXT,
    end_date                TEXT,                 -- blank = single-day job
    day_of_week             TEXT,
    preferred_days          TEXT,                 -- job-level Preferred Day(s) (2026-10-04), Monday/Friday notation, blank = no day constraint
    start_time              TEXT,
    end_time                TEXT,
    service_type            TEXT,
    service_details         TEXT,
    crew                    TEXT,                 -- free-text fallback for unregistered names
    crew_user_id            TEXT REFERENCES users(id),
    est_duration            REAL,
    est_duration_unit       TEXT,
    actual_duration         REAL,
    actual_duration_unit    TEXT,
    route_stop_number       INTEGER,
    route_map_url           TEXT,
    weather_check           TEXT,
    job_status              TEXT,
    quote_amount            REAL,
    discount_applied        REAL,
    recurrence              TEXT,
    invoice_id              TEXT REFERENCES invoices(invoice_id),
    invoice_sent_date       TEXT,
    receipt_sent_date       TEXT,
      payment_status          TEXT,
      no_sales_tax            INTEGER DEFAULT 0, -- 1 = tax-exempt job: invoices compute $0 tax (2026-10-08)
    schedule_type           TEXT DEFAULT 'soft',  -- 'hard'|'soft' (spec §14.2, added 2026-09-16). 'hard': start_time/end_time are a committed appointment the router must honor. 'soft' (default): start_time/end_time are the allowable placement window, defaulting to the workday if blank — today's behavior, made explicit.
    original_start_time    TEXT,  -- mileage/routing follow-up (2026-09-20): the customer's actually-agreed schedule. Deliberately an ORDINARY, independently-editable field (same as any other column) — changed only by a genuine manual edit or an explicit Claude, Muse, or Grok instruction to update it, NEVER by approve_route_schedule/unapprove_route_schedule, which read/write start_time/end_time only. Lets a route be approved and un-approved through any number of trial-and-error passes without ever losing track of what the customer was actually told.
    original_end_time      TEXT,  -- see original_start_time above — same rule, paired field.
    created_by              TEXT,
    last_edited_by          TEXT,
    last_edited_at          TEXT,
    version                 INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_jobs_customer_id ON jobs(customer_id);
CREATE INDEX IF NOT EXISTS idx_jobs_invoice_id ON jobs(invoice_id);
CREATE INDEX IF NOT EXISTS idx_jobs_crew_user_id ON jobs(crew_user_id);
CREATE INDEX IF NOT EXISTS idx_jobs_service_date ON jobs(service_date);
CREATE INDEX IF NOT EXISTS idx_jobs_last_edited_at ON jobs(last_edited_at);

-- ── invoices ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS invoices (
    invoice_id              TEXT PRIMARY KEY,     -- INV-####
    job_id                  TEXT REFERENCES jobs(job_id),
    customer_id             TEXT REFERENCES customers(customer_id),
    customer_name           TEXT,
    customer_type           TEXT,
    invoice_date            TEXT,
    due_date                TEXT,                 -- Net 30
    service_date            TEXT,
    service_type            TEXT,
    description             TEXT,
    subtotal                REAL,                 -- frozen at creation, spec §6a cat.2
    discount                REAL,
    taxable_amt             REAL,                 -- = subtotal - discount, frozen
    tax                     REAL,                 -- frozen tax amount, NOT a live rate calc
    total_due               REAL,                 -- frozen = taxable_amt + tax
    amount_paid             REAL DEFAULT 0,
    balance_due             REAL GENERATED ALWAYS AS (total_due - amount_paid) STORED,
    payment_status          TEXT,
    payment_date            TEXT,
    payment_method          TEXT,
    days_overdue            INTEGER,               -- computed by app at query time, not generated (depends on "today")
    created_by              TEXT,
    last_edited_by          TEXT,
    last_edited_at          TEXT,
    version                 INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_invoices_job_id ON invoices(job_id);
CREATE INDEX IF NOT EXISTS idx_invoices_customer_id ON invoices(customer_id);
CREATE INDEX IF NOT EXISTS idx_invoices_last_edited_at ON invoices(last_edited_at);

-- ── quotes ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS quotes (
    quote_id                 TEXT PRIMARY KEY,    -- QTE-####
    customer_id              TEXT REFERENCES customers(customer_id),
    customer_name            TEXT,
    customer_type            TEXT,
    address                  TEXT,
    city                     TEXT,
    quote_date               TEXT,
    valid_until              TEXT,
    service_type             TEXT,
    service_description      TEXT,
    sq_ft_units              REAL,
    unit_price               REAL,
    labor_cost               REAL,
    materials                REAL,
    subtotal                 REAL,                -- frozen at creation
    discount_pct             REAL,
    discount_amt             REAL,
    tax                      REAL,                -- frozen
    quote_total              REAL,                -- frozen
    status                   TEXT DEFAULT 'Open',  -- Open/Approved/Declined
    created_by               TEXT,
    last_edited_by           TEXT,
    last_edited_at           TEXT,
    version                  INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_quotes_customer_id ON quotes(customer_id);
CREATE INDEX IF NOT EXISTS idx_quotes_last_edited_at ON quotes(last_edited_at);

-- ── time_entries (TimeLog) ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS time_entries (
    entry_id                 TEXT PRIMARY KEY,
    job_id                   TEXT NOT NULL REFERENCES jobs(job_id),
    customer_name            TEXT,
    entry_date               TEXT NOT NULL,       -- YYYY-MM-DD, the day this entry belongs to
    clock_in                 TEXT,                -- full 'YYYY-MM-DD HH:MM:SS' (db_write_ops.db_log_time_entry writes datetime.now(), not time-only)
    clock_out                TEXT,                -- full 'YYYY-MM-DD HH:MM:SS', same as clock_in
    elapsed_min              REAL GENERATED ALWAYS AS (
                                 CASE
                                     WHEN clock_in IS NOT NULL AND clock_out IS NOT NULL
                                     THEN (strftime('%s', clock_out)
                                           - strftime('%s', clock_in)) / 60.0
                                     ELSE NULL
                                 END
                             ) STORED,
    crew                     TEXT,
    crew_user_id             TEXT REFERENCES users(id),
    notes                    TEXT,
    clock_in_gps             TEXT,
    clock_out_gps            TEXT,
    clock_in_map_url         TEXT,   -- Google Maps link derived from clock_in_gps
    clock_out_map_url        TEXT,   -- Google Maps link derived from clock_out_gps
    created_by               TEXT,
    last_edited_by           TEXT,
    last_edited_at           TEXT,
    version                  INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_time_entries_job_id ON time_entries(job_id);
CREATE INDEX IF NOT EXISTS idx_time_entries_crew_user_id ON time_entries(crew_user_id);
CREATE INDEX IF NOT EXISTS idx_time_entries_last_edited_at ON time_entries(last_edited_at);

-- ── route_stops (schema fix, spec §4.2 / §6.4) ──────────────────────
-- Keyed by (route_date, crew_id): building one crew's route can never
-- clear or overwrite another crew's stops for the same day, unlike the
-- old single shared Route_Planner sheet.
CREATE TABLE IF NOT EXISTS route_stops (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    route_date                TEXT NOT NULL,
    crew_id                   TEXT NOT NULL,       -- users.id, or free-text crew name fallback
      stop_number               INTEGER NOT NULL,
      fixed_position            INTEGER,
    job_id                    TEXT REFERENCES jobs(job_id),
    customer_id               TEXT REFERENCES customers(customer_id),
    address                   TEXT,
    latitude                  REAL,
    longitude                 REAL,
    eta                       TEXT,
    leg_drive_min             REAL,  -- drive minutes from the PREVIOUS stop (or day's origin) TO this one
    leg_drive_miles           REAL,  -- drive miles for that same leg — both via OSRM, same call that computes eta
    map_url                   TEXT,
    created_by                TEXT,
    last_edited_by            TEXT,
    last_edited_at            TEXT,
    version                   INTEGER NOT NULL DEFAULT 1,
    UNIQUE(route_date, crew_id, stop_number)
);
CREATE INDEX IF NOT EXISTS idx_route_stops_date_crew ON route_stops(route_date, crew_id);
CREATE INDEX IF NOT EXISTS idx_route_stops_last_edited_at ON route_stops(last_edited_at);

-- ── route_approvals (2026-10-05, approval-gated email/links) ─────────
-- One row per approved (route_date, crew_id). Approve sets it; Un-approve
-- deletes it; any route_stops rewrite for the pair deletes it too (a
-- rebuilt route is experimental until re-approved). Email and the
-- Jobs/Calendar route-link views are only served for approved routes.
CREATE TABLE IF NOT EXISTS route_approvals (
route_date                TEXT NOT NULL,
crew_id                   TEXT NOT NULL,
approved_at               TEXT NOT NULL,
approved_by               TEXT,
PRIMARY KEY (route_date, crew_id)
);

-- ── settings ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
    key                       TEXT PRIMARY KEY,
    value                     TEXT,
    notes                     TEXT,
    last_edited_by            TEXT,
    last_edited_at            TEXT
);

-- ── service_pricing (Services_Pricing) ──────────────────────────────
CREATE TABLE IF NOT EXISTS service_pricing (
    service_code              TEXT PRIMARY KEY,
    category                  TEXT,
    name                      TEXT,
    base_price                REAL,
    unit_basis                TEXT,
    min_charge                REAL,
    comm_multiplier           REAL,
    tax_category              TEXT,
    notes                     TEXT,
    last_edited_by            TEXT,
    last_edited_at            TEXT,
    version                   INTEGER NOT NULL DEFAULT 1
);

-- ── Mileage tracker (2026-10-24, MILEAGE spec) ──────────────────────
-- IRS-ready business mileage log (Pub. 463 ch. 4-5, Form 4562 Part V).
-- Trips are never hard-deleted (status='void'), every edit is audited in
-- mileage_trip_edits, and IDs come from generate_next_id (never reused).
CREATE TABLE IF NOT EXISTS vehicles (
    vehicle_id                TEXT PRIMARY KEY,      -- VEH-####
    vin                       TEXT NOT NULL UNIQUE,  -- 17 chars, check digit validated
    year                      INTEGER,
    make                      TEXT,
    model                     TEXT,
    color                     TEXT,
    plate                     TEXT,
    nickname                  TEXT,
    ownership                 TEXT NOT NULL DEFAULT 'business',  -- business | crew
    owner_user_id             TEXT,                  -- users.id (crew-owned)
    owner_name                TEXT,
    default_user_id           TEXT,
    default_user_name         TEXT,
    placed_in_service         TEXT,                  -- YYYY-MM-DD (Form 4562)
    retired_on                TEXT,
    active                    INTEGER NOT NULL DEFAULT 1,
    created_by                TEXT,
    created_at                TEXT,
    last_edited_by            TEXT,
    last_edited_at            TEXT,
    version                   INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS odometer_readings (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    vehicle_id                TEXT NOT NULL REFERENCES vehicles(vehicle_id),
    reading_date              TEXT NOT NULL,         -- YYYY-MM-DD
    odometer                  INTEGER NOT NULL,
    kind                      TEXT NOT NULL DEFAULT 'spot',  -- added | year_start | year_end | retired | spot
    photo                     TEXT,
    entered_by                TEXT,
    entered_at                TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_odometer_vehicle_date ON odometer_readings(vehicle_id, reading_date);

CREATE TABLE IF NOT EXISTS mileage_trips (
    trip_id                   TEXT PRIMARY KEY,      -- TRIP-####, never reused
    trip_date                 TEXT NOT NULL,         -- YYYY-MM-DD
    start_time                TEXT,                  -- HH:MM (local)
    end_time                  TEXT,
    crew_user_id              TEXT,
    crew                      TEXT,
    vehicle_id                TEXT REFERENCES vehicles(vehicle_id),
    from_label                TEXT,
    from_lat                  REAL,
    from_lon                  REAL,
    to_label                  TEXT NOT NULL,         -- IRS: destination
    to_lat                    REAL,
    to_lon                    REAL,
    job_id                    TEXT,                  -- null for bookends / non-job trips
    customer_name             TEXT,
    seq                       INTEGER,               -- order within the day
    miles                     REAL NOT NULL,         -- IRS: amount
    distance_source           TEXT NOT NULL,         -- gps | address | route | manual | odometer
    classification            TEXT NOT NULL,         -- business | commute | personal
    reimbursable              INTEGER NOT NULL DEFAULT 0,
    origin_mode               TEXT,                  -- Jobs Only | Company Location, at build time
    category                  TEXT,                  -- Job | Supplies | Equipment | Bank | ...
    purpose                   TEXT NOT NULL,         -- IRS: business purpose
    parking_usd               REAL,
    tolls_usd                 REAL,
    receipt_photo             TEXT,
    origin                    TEXT NOT NULL,         -- auto | manual | backfill
    build_key                 TEXT,                  -- de-dup key for auto/backfill rebuilds
    manually_edited           INTEGER NOT NULL DEFAULT 0,
    corrected                 INTEGER NOT NULL DEFAULT 0,
    needs_fix                 TEXT,                  -- gap description, NULL when complete
    status                    TEXT NOT NULL DEFAULT 'active',  -- active | void
    void_reason               TEXT,
    locked                    INTEGER NOT NULL DEFAULT 0,
    reimbursement_id          TEXT,
    notes                     TEXT,
    created_at                TEXT NOT NULL,         -- IRS: recorded at or near the time
    created_by                TEXT,
    last_edited_by            TEXT,
    last_edited_at            TEXT,
    version                   INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_mileage_trips_date ON mileage_trips(trip_date);
CREATE INDEX IF NOT EXISTS idx_mileage_trips_crew_date ON mileage_trips(crew_user_id, crew, trip_date);
CREATE INDEX IF NOT EXISTS idx_mileage_trips_build_key ON mileage_trips(build_key);
CREATE INDEX IF NOT EXISTS idx_mileage_trips_last_edited_at ON mileage_trips(last_edited_at);

CREATE TABLE IF NOT EXISTS mileage_trip_edits (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    trip_id                   TEXT NOT NULL REFERENCES mileage_trips(trip_id),
    field                     TEXT NOT NULL,
    old_value                 TEXT,
    new_value                 TEXT,
    edited_by                 TEXT,
    edited_at                 TEXT NOT NULL,
    reason                    TEXT
);
CREATE INDEX IF NOT EXISTS idx_mileage_trip_edits_trip ON mileage_trip_edits(trip_id);

-- Which vehicle a driver used on a given day (Clock-screen picker).
CREATE TABLE IF NOT EXISTS mileage_day_vehicles (
    trip_date                 TEXT NOT NULL,
    user_key                  TEXT NOT NULL,         -- users.id, or lowercased crew name in personal mode
    vehicle_id                TEXT NOT NULL REFERENCES vehicles(vehicle_id),
    set_by                    TEXT,
    set_at                    TEXT,
    PRIMARY KEY (trip_date, user_key)
);

CREATE TABLE IF NOT EXISTS mileage_locks (
    period                    TEXT PRIMARY KEY,      -- YYYY-MM or YYYY
    locked_by                 TEXT,
    locked_at                 TEXT NOT NULL
);

-- Crew mileage reimbursement per pay period (mileage spec FR-23, Phase 5).
-- Submitted -> Approved or Returned -> Paid. Trips link through
-- mileage_trips.reimbursement_id; they can't change while the period is
-- submitted or approved, and are locked once it's paid. Every status change
-- is kept in mileage_reimbursement_events.
CREATE TABLE IF NOT EXISTS mileage_reimbursements (
    reimbursement_id          TEXT PRIMARY KEY,      -- REIM-####, never reused
    user_key                  TEXT NOT NULL,         -- users.id, or lowercased crew name / 'owner'
    crew_user_id              TEXT,
    crew                      TEXT,
    period_start              TEXT NOT NULL,
    period_end                TEXT NOT NULL,
    period_kind               TEXT,                  -- weekly | biweekly | monthly
    status                    TEXT NOT NULL,         -- submitted | returned | approved | paid
    trip_count                INTEGER,
    miles                     REAL,
    amount_usd                REAL,                  -- frozen at approval
    parking_tolls_usd         REAL,
    return_note               TEXT,
    submitted_by              TEXT,
    submitted_at              TEXT,
    approved_by               TEXT,
    approved_at               TEXT,
    paid_date                 TEXT,
    paid_method               TEXT,                  -- check | cash | payroll | transfer
    paid_reference            TEXT,
    paid_by                   TEXT,
    paid_at                   TEXT,
    created_at                TEXT NOT NULL,
    last_edited_by            TEXT,
    last_edited_at            TEXT,
    version                   INTEGER NOT NULL DEFAULT 1,
    UNIQUE(user_key, period_start)
);
CREATE INDEX IF NOT EXISTS idx_mileage_trips_reimb ON mileage_trips(reimbursement_id);

CREATE TABLE IF NOT EXISTS mileage_reimbursement_events (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    reimbursement_id          TEXT NOT NULL REFERENCES mileage_reimbursements(reimbursement_id),
    from_status               TEXT,
    to_status                 TEXT NOT NULL,
    actor                     TEXT,
    at                        TEXT NOT NULL,
    note                      TEXT
);
CREATE INDEX IF NOT EXISTS idx_mileage_reimb_events ON mileage_reimbursement_events(reimbursement_id);

-- Fingerprint of what each built day came from, per driver (FR-21): when a
-- job is moved/cancelled/deleted or a clock entry or route changes, the
-- fingerprint stops matching and the day is rebuilt.
CREATE TABLE IF NOT EXISTS mileage_day_builds (
    trip_date                 TEXT NOT NULL,
    user_key                  TEXT NOT NULL,
    signature                 TEXT NOT NULL,
    built_at                  TEXT NOT NULL,
    PRIMARY KEY (trip_date, user_key)
);

-- AI mileage review (FR-25): findings someone accepted or dismissed, so a
-- dismissed finding isn't raised again.
CREATE TABLE IF NOT EXISTS mileage_review_actions (
    finding_id                TEXT PRIMARY KEY,      -- check:date:target
    action                    TEXT NOT NULL,         -- accepted | dismissed
    acted_by                  TEXT,
    acted_at                  TEXT NOT NULL,
    note                      TEXT
);

-- ── schema metadata (for future migrations) ─────────────────────────
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def _ensure_column(conn, table: str, column: str, coltype: str) -> None:
    """ALTER TABLE ADD COLUMN, but only if the column doesn't already
    exist — SQLite has no native "ADD COLUMN IF NOT EXISTS", so this
    checks PRAGMA table_info first. Needed for columns added to an
    existing table after Phase 0 shipped (CREATE TABLE IF NOT EXISTS in
    SCHEMA_SQL only affects brand-new databases; an install that already
    has the table never sees a new column added there later without an
    explicit migration step like this one).
    """
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


def _drop_column_if_exists(conn, table: str, column: str) -> None:
    """ALTER TABLE ... DROP COLUMN, but only if the column is currently
    present — the mirror image of _ensure_column, for columns REMOVED
    from SCHEMA_SQL after Phase 0 shipped (spec §13, Field Ownership &
    Live-Join Policy). CREATE TABLE IF NOT EXISTS only affects
    brand-new databases, so an existing install's table keeps the old
    column until this migration runs once. DROP COLUMN requires SQLite
    3.35.0+ (bundled with every supported Python 3.11 build); the
    PRAGMA table_info check makes this safe and idempotent to call on
    every startup regardless of whether the column was already dropped.
    """
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column in existing:
        conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}")


def _migrate_preferred_time_window(conn) -> None:
    """One-time data migration for the 2026-10-04 split of
    customers.preferred_time_window into preferred_time_start /
    preferred_time_end (separate start/end columns in the customer
    listing, per David).

    Parses the old combined values ("7:00 AM to 10:00 AM", "before
    10:00 AM", "from 9:00 AM") into the two new columns. Only touches
    rows whose new columns are BOTH still empty, so re-running never
    overwrites a value set deliberately after the split. Unparseable
    old values are left alone (old column keeps them until the DROP
    below) -- nothing is guessed.

    Idempotent: no-op if the old column is already gone, or if every
    remaining old value is blank/unparseable.
    """
    cols = {row[1] for row in conn.execute("PRAGMA table_info(customers)").fetchall()}
    if "preferred_time_window" not in cols:
        return  # already migrated (or fresh DB: SCHEMA_SQL has the new columns)
    if "preferred_time_start" not in cols or "preferred_time_end" not in cols:
        return  # safety: new columns must exist first
    import re
    rows = conn.execute(
        "SELECT customer_id, preferred_time_window, preferred_time_start, preferred_time_end "
        "FROM customers WHERE preferred_time_window IS NOT NULL "
        "AND TRIM(preferred_time_window) != ''"
    ).fetchall()
    for cid, old, ns, ne in rows:
        if (ns or "").strip() or (ne or "").strip():
            continue  # new-style values already present; never overwrite
        s = old.strip()
        start, end, parsed = "", "", False
        m = re.match(r"(.+?)\s+(?:to|-)\s+(.+)", s, re.IGNORECASE)
        if m:
            start, end, parsed = m.group(1).strip(), m.group(2).strip(), True
        else:
            m = re.match(r"^before\s+(.+)", s, re.IGNORECASE)
            if m:
                end, parsed = m.group(1).strip(), True
            else:
                m = re.match(r"^(?:after|from)\s+(.+)", s, re.IGNORECASE)
                if m:
                    start, parsed = m.group(1).strip(), True
        if not parsed:
            continue  # unparseable: leave for manual handling, don't guess
        conn.execute(
            "UPDATE customers SET preferred_time_start = ?, preferred_time_end = ? "
            "WHERE customer_id = ?",
            (start, end, cid),
        )


def _fix_time_entries_elapsed_min(conn) -> None:
    """One-time table rebuild for a stale elapsed_min GENERATED ALWAYS AS
    formula (found via manual E2E testing, 2026-09-15 — TimeLog showed a
    blank Elapsed (min) for every entry).

    time_entries.clock_in/clock_out originally stored TIME-ONLY values
    ('HH:MM:SS'), so the generated column concatenated entry_date onto
    each side: entry_date || ' ' || clock_out. When db_write_ops.
    db_log_time_entry was changed to write the FULL datetime instead
    ('YYYY-MM-DD HH:MM:SS' — see the clock_in/clock_out column comments
    in SCHEMA_SQL above), the generated-column formula here was updated
    to match (clock_out directly, no concatenation) — but SQLite has no
    ALTER TABLE for a generated column's expression, and CREATE TABLE IF
    NOT EXISTS never touches a table that already exists. Any database
    created before this fix kept computing elapsed_min against a
    malformed double-dated string (entry_date || ' ' || 'YYYY-MM-DD
    HH:MM:SS'), which strftime() can't parse — so elapsed_min came back
    NULL for every single clock entry, old and new.

    Idempotent: inspects sqlite_master.sql for the CURRENT on-disk
    definition of time_entries and only rebuilds if it still contains
    the stale concatenation. A no-op on an already-fixed database, and a
    no-op if the table doesn't exist yet at all (SCHEMA_SQL above
    creates it correctly from scratch in that case).

    Rebuilds via SQLite's standard "12-step" ALTER TABLE procedure:
    build a correctly-defined table alongside the old one, copy every
    REAL (non-generated) column across row for row, drop the old table,
    rename the new one into place, recreate its indexes. elapsed_min
    itself is never copied — it isn't stored data, it recomputes for
    every copied row automatically under the corrected formula the
    moment the row lands in the new table.
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='time_entries'"
    ).fetchone()
    if row is None:
        return
    if "entry_date || ' ' || clock_out" not in row[0]:
        return  # already fixed

    conn.executescript("""
        CREATE TABLE time_entries_new (
            entry_id                 TEXT PRIMARY KEY,
            job_id                   TEXT NOT NULL REFERENCES jobs(job_id),
            customer_name            TEXT,
            entry_date               TEXT NOT NULL,
            clock_in                 TEXT,
            clock_out                TEXT,
            elapsed_min              REAL GENERATED ALWAYS AS (
                                         CASE
                                             WHEN clock_in IS NOT NULL AND clock_out IS NOT NULL
                                             THEN (strftime('%s', clock_out)
                                                   - strftime('%s', clock_in)) / 60.0
                                             ELSE NULL
                                         END
                                     ) STORED,
            crew                     TEXT,
            crew_user_id             TEXT REFERENCES users(id),
            notes                    TEXT,
            clock_in_gps             TEXT,
            clock_out_gps            TEXT,
            clock_in_map_url         TEXT,
            clock_out_map_url        TEXT,
            created_by               TEXT,
            last_edited_by           TEXT,
            last_edited_at           TEXT,
            version                  INTEGER NOT NULL DEFAULT 1
        );

        INSERT INTO time_entries_new (
            entry_id, job_id, customer_name, entry_date, clock_in, clock_out,
            crew, crew_user_id, notes, clock_in_gps, clock_out_gps,
            clock_in_map_url, clock_out_map_url,
            created_by, last_edited_by, last_edited_at, version
        )
        SELECT
            entry_id, job_id, customer_name, entry_date, clock_in, clock_out,
            crew, crew_user_id, notes, clock_in_gps, clock_out_gps,
            clock_in_map_url, clock_out_map_url,
            created_by, last_edited_by, last_edited_at, version
        FROM time_entries;

        DROP TABLE time_entries;
        ALTER TABLE time_entries_new RENAME TO time_entries;

        CREATE INDEX IF NOT EXISTS idx_time_entries_job_id ON time_entries(job_id);
        CREATE INDEX IF NOT EXISTS idx_time_entries_crew_user_id ON time_entries(crew_user_id);
        CREATE INDEX IF NOT EXISTS idx_time_entries_last_edited_at ON time_entries(last_edited_at);
    """)


def _fix_invoices_balance_due(conn) -> None:
    """One-time table rebuild: balance_due was a plain REAL column with
    only a comment ("-- = total_due - amount_paid") describing the
    intended relationship — nothing in SQLite actually enforced it, so it
    could (and did) go stale whenever amount_paid changed without
    someone also recomputing balance_due by hand. Found via manual E2E
    testing, 2026-09-15, alongside the payment_status-without-amount_paid
    gap fixed in db_update_row (db_write_ops.py) — that fix handles WHEN
    amount_paid gets set; this one guarantees balance_due can never
    disagree with it once amount_paid is set, the same way
    _fix_time_entries_elapsed_min made elapsed_min a real generated
    column instead of a formula that only lived in a comment.

    Idempotent: inspects sqlite_master.sql for the CURRENT on-disk
    definition of invoices and only rebuilds if balance_due isn't
    already a GENERATED column. No-op if the table doesn't exist yet
    (SCHEMA_SQL above creates it correctly from scratch in that case).

    Same standard SQLite "12-step" ALTER TABLE procedure as
    _fix_time_entries_elapsed_min: build a correctly-defined table
    alongside the old one, copy every real column across (balance_due
    itself excluded — it recomputes automatically the instant each row
    lands in the new table), drop the old table, rename the new one in,
    recreate its indexes.
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='invoices'"
    ).fetchone()
    if row is None:
        return
    if "balance_due" in row[0] and "GENERATED ALWAYS AS (total_due - amount_paid)" in row[0]:
        return  # already fixed

    # jobs.invoice_id REFERENCES invoices(invoice_id) — with foreign_keys
    # enforcement on (the default for every real connection here), DROP
    # TABLE invoices fails outright while any job row still points at it.
    # This is SQLite's own documented "12-step" ALTER TABLE procedure for
    # exactly this situation: disable FK enforcement for the duration of
    # the rebuild, then re-enable it and verify nothing's now dangling
    # before considering the migration done. PRAGMA foreign_keys is a
    # no-op inside an open transaction, so this only works reliably on an
    # autocommit connection (db_access.get_connection() sets
    # isolation_level=None for exactly this kind of reason) — safe here
    # since apply_schema() always receives one of those.
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.executescript("""
        CREATE TABLE invoices_new (
            invoice_id              TEXT PRIMARY KEY,
            job_id                  TEXT REFERENCES jobs(job_id),
            customer_id             TEXT REFERENCES customers(customer_id),
            customer_name           TEXT,
            customer_type           TEXT,
            invoice_date            TEXT,
            due_date                TEXT,
            service_date            TEXT,
            service_type            TEXT,
            description             TEXT,
            subtotal                REAL,
            discount                REAL,
            taxable_amt             REAL,
            tax                     REAL,
            total_due               REAL,
            amount_paid             REAL DEFAULT 0,
            balance_due             REAL GENERATED ALWAYS AS (total_due - amount_paid) STORED,
            payment_status          TEXT,
            payment_date            TEXT,
            payment_method          TEXT,
            days_overdue            INTEGER,
            created_by              TEXT,
            last_edited_by          TEXT,
            last_edited_at          TEXT,
            version                 INTEGER NOT NULL DEFAULT 1
        );

        INSERT INTO invoices_new (
            invoice_id, job_id, customer_id, customer_name, customer_type,
            invoice_date, due_date, service_date, service_type, description,
            subtotal, discount, taxable_amt, tax, total_due, amount_paid,
            payment_status, payment_date, payment_method, days_overdue,
            created_by, last_edited_by, last_edited_at, version
        )
        SELECT
            invoice_id, job_id, customer_id, customer_name, customer_type,
            invoice_date, due_date, service_date, service_type, description,
            subtotal, discount, taxable_amt, tax, total_due, amount_paid,
            payment_status, payment_date, payment_method, days_overdue,
            created_by, last_edited_by, last_edited_at, version
        FROM invoices;

        DROP TABLE invoices;
        ALTER TABLE invoices_new RENAME TO invoices;

        CREATE INDEX IF NOT EXISTS idx_invoices_job_id ON invoices(job_id);
        CREATE INDEX IF NOT EXISTS idx_invoices_customer_id ON invoices(customer_id);
        CREATE INDEX IF NOT EXISTS idx_invoices_last_edited_at ON invoices(last_edited_at);
    """)
    conn.execute("PRAGMA foreign_keys = ON")
    dangling = conn.execute("PRAGMA foreign_key_check").fetchall()
    if dangling:
        raise RuntimeError(
            f"_fix_invoices_balance_due: foreign_key_check found dangling "
            f"references after rebuild — aborting rather than leaving a "
            f"silently-broken database: {dangling}")


def apply_schema(conn):
    """Create every table/index in SCHEMA_SQL if not already present, then
    run any column-level migrations for tables that already existed
    before that column was added or removed (see _ensure_column /
    _drop_column_if_exists).

    Idempotent: safe to call on every startup and in tests. `conn` is an
    existing sqlite3.Connection (see db_access.get_connection).
    """
    conn.executescript(SCHEMA_SQL)

    # 2026-09-13: clock_in_map_url/clock_out_map_url added to time_entries
    # after Phase 0 shipped (Job Board Architecture Spec §12, GPS map-link
    # follow-up) — existing databases need these columns added explicitly.
    _ensure_column(conn, "time_entries", "clock_in_map_url", "TEXT")
    _ensure_column(conn, "time_entries", "clock_out_map_url", "TEXT")

    # 2026-09-14: spec §13 (Field Ownership & Live-Join Policy) — these
    # seven columns are retired as stored values entirely. Their live
    # value now comes exclusively from db_read_ops.py's read-time overlay
    # functions (joined from the linked invoice, or computed from the
    # real jobs/invoices rows) — a stored copy here could only ever go
    # stale, which is the exact bug class (JOB-0007) §13 exists to close.
    # Existing databases created before this change still have these
    # columns until this migration runs once.
    for _col in ("invoice_total", "actual_amount", "tax_pct"):
        _drop_column_if_exists(conn, "jobs", _col)
    for _col in ("last_service_date", "next_scheduled_date",
                 "total_jobs_completed", "lifetime_revenue"):
        _drop_column_if_exists(conn, "customers", _col)

    # 2026-09-15: elapsed_min's generated-column formula fixed to match
    # clock_in/clock_out now being full datetimes, not time-only — see
    # _fix_time_entries_elapsed_min's docstring. A table rebuild (SQLite
    # can't ALTER a generated column's expression), so it's kept as its
    # own step rather than an _ensure_column/_drop_column_if_exists call.
    _fix_time_entries_elapsed_min(conn)

    # 2026-09-15: balance_due's generated-column formula added to match
    # amount_paid actually being kept live now (db_write_ops.db_update_row
    # auto-fills amount_paid when payment_status is set to Paid) — see
    # _fix_invoices_balance_due's docstring. Same table-rebuild reason as
    # the elapsed_min fix just above.
    _fix_invoices_balance_due(conn)

    # 2026-09-16: jobs.schedule_type added (spec §14.2, Route & Schedule
    # Advisor). Existing databases created before this change need the
    # column added explicitly — CREATE TABLE IF NOT EXISTS above only
    # covers brand-new databases. Every existing job silently defaults to
    # 'soft' via the column's own DEFAULT, so this is purely additive: no
    # existing job's start_time/end_time meaning changes, and no other
    # table or column is touched.
    _ensure_column(conn, "jobs", "schedule_type", "TEXT DEFAULT 'soft'")

    # 2026-09-20 (mileage/routing follow-up): jobs.original_start_time /
    # original_end_time added — the customer's actually-agreed schedule,
    # independent of whatever approve_route_schedule/unapprove_route_
    # schedule temporarily write into start_time/end_time while trying
    # different routes. One-time backfill for existing rows: at the
    # moment this migration runs, whatever's currently in start_time/
    # end_time IS the best available baseline (nothing has approved/
    # un-approved anything through the new mechanism yet) — copied over
    # ONLY where original_* is still NULL, so re-running this migration
    # (idempotent, like every other one here) never overwrites a value a
    # user or Claude, Muse, or Grok has already set deliberately after the column
    # existed.
    _ensure_column(conn, "jobs", "original_start_time", "TEXT")
    _ensure_column(conn, "jobs", "original_end_time", "TEXT")
    conn.execute(
        "UPDATE jobs SET original_start_time = start_time, original_end_time = end_time "
        "WHERE original_start_time IS NULL AND start_time IS NOT NULL"
    )

    # 2026-09-17: route_stops.leg_drive_min / leg_drive_miles added (Route
    # tab meta-line expansion — drive time/distance FROM the previous stop
    # (or the day's origin) TO this one). Existing databases need these
    # added explicitly, same as every other post-Phase-0 column above.
    # Both are populated at the same point build_daily_route/
    # db_reorder_route_stop/suggest_route_schedule already call OSRM for
    # this stop's ETA — nothing new is fetched, the existing OSRM response
    # just isn't discarded anymore. NULL on any row written before this
    # change (or for a stop OSRM couldn't reach) — the PWA treats NULL as
    # "unknown" and shows a dash rather than a wrong number.
    _ensure_column(conn, "route_stops", "leg_drive_min", "REAL")
    _ensure_column(conn, "route_stops", "leg_drive_miles", "REAL")

    # 2026-10-05: route_stops.fixed_position added ("Fix stop #" pin, Route
    # tab). 1-based position among the date/crew job stops; NULL = unfixed.
    # Purely additive — existing rows stay NULL (no constraint invented).
    _ensure_column(conn, "route_stops", "fixed_position", "INTEGER")


    # 2026-10-04: customers.preferred_time_window split into
    # preferred_time_start / preferred_time_end (separate start/end
    # columns in the customer listing, per David). Existing databases
    # get the new columns via _ensure_column; old values migrate once
    # via _migrate_preferred_time_window above (only where the new
    # columns are still empty); then the old column is dropped.
    _ensure_column(conn, "customers", "preferred_time_start", "TEXT")
    _ensure_column(conn, "customers", "preferred_time_end", "TEXT")
    _migrate_preferred_time_window(conn)
    _drop_column_if_exists(conn, "customers", "preferred_time_window")

    # 2026-10-04: customers.schedule_type added — per-customer Soft/Hard
    # default that new jobs inherit (Part A). Existing databases get the
    # column via _ensure_column; existing rows take 'Soft' from the
    # column DEFAULT. Purely additive — no other table or column touched.
    _ensure_column(conn, "customers", "schedule_type", "TEXT DEFAULT 'Soft'")

    # 2026-10-04: jobs.preferred_days added -- job-level Preferred Day(s)
    # (Monday/Friday notation, inherited from the customer on new jobs,
    # editable per job; blank = no day constraint). Existing databases get
    # the column via _ensure_column; existing rows stay blank (no constraint
    # -- never invent one). Purely additive.
    _ensure_column(conn, "jobs", "preferred_days", "TEXT")

    # 2026-10-05: jobs.paused added -- pause/resume for in-progress (esp.
    # multi-day) jobs. 1 = paused: the job is never routed until resumed.
    # Existing databases get the column via _ensure_column; existing rows
    # take 0 from the column DEFAULT (routable -- never invent a pause).
    # Purely additive.
    _ensure_column(conn, "jobs", "paused", "INTEGER DEFAULT 0")

    # 2026-10-06: jobs.paused_service_date / jobs.paused_end_date added --
    # pause stash: pausing a dated job stashes its live Service/End dates here
    # and clears the live dates (paused jobs sit on the Unscheduled board until
    # resumed, when the stash is restored). Purely additive; existing rows stay
    # NULL (no data invented; existing paused-with-date jobs keep their dates
    # and resume gracefully with an empty stash leaving dates untouched).
    _ensure_column(conn, "jobs", "paused_service_date", "TEXT")
    _ensure_column(conn, "jobs", "paused_end_date", "TEXT")
    # 2026-10-06: jobs.pause_comment added -- free-text reason for the pause,
    # shown wherever the paused state appears. Purely additive, NULL default.
    _ensure_column(conn, "jobs", "pause_comment", "TEXT")
    # 2026-10-06: jobs.receipt_sent_date added -- stamped (YYYY-MM-DD) when a
    # payment receipt is sent via email_receipt/text_receipt. Purely additive,
    # NULL default; drives the Jobs-page Billing mode "Paid, no receipt" bucket.
    _ensure_column(conn, "jobs", "receipt_sent_date", "TEXT")
    # 2026-10-08: jobs.no_sales_tax added -- per-job tax exemption ("No Sales
    # Tax" checkbox, see COMPLETE_USER_GUIDE.md Jobs_Schedule columns). 1 =
    # tax-exempt: invoices compute $0 tax (total = quote - discount only).
    # Existing databases get the column via _ensure_column; existing rows
    # take 0 from the column DEFAULT (taxable -- never invent an exemption).
    # Purely additive.
    _ensure_column(conn, "jobs", "no_sales_tax", "INTEGER DEFAULT 0")

    conn.execute(
        "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(SCHEMA_VERSION),),
    )
    conn.commit()
