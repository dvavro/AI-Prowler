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
    preferred_days          TEXT,
    preferred_time_window   TEXT,
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
    payment_status          TEXT,
    schedule_type           TEXT DEFAULT 'soft',  -- 'hard'|'soft' (spec §14.2, added 2026-09-16). 'hard': start_time/end_time are a committed appointment the router must honor. 'soft' (default): start_time/end_time are the allowable placement window, defaulting to the workday if blank — today's behavior, made explicit.
    original_start_time    TEXT,  -- mileage/routing follow-up (2026-09-20): the customer's actually-agreed schedule. Deliberately an ORDINARY, independently-editable field (same as any other column) — changed only by a genuine manual edit or an explicit Claude instruction to update it, NEVER by approve_route_schedule/unapprove_route_schedule, which read/write start_time/end_time only. Lets a route be approved and un-approved through any number of trial-and-error passes without ever losing track of what the customer was actually told.
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
    # user or Claude has already set deliberately after the column
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

    conn.execute(
        "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(SCHEMA_VERSION),),
    )
    conn.commit()
