"""Versioned schema migrations for estimator.db.

Rules:
- Migrations are append-only. Never edit a migration that has shipped; add a new one.
- Each migration runs in one transaction and is recorded in schema_migrations.
- Every business table carries company_id, and rows that people create carry the
  user who created them, so Server mode multi-user works without rework.
- Money columns are INTEGER cents; quantities and percentages are TEXT decimals
  (exact, never float).
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "phase0_core", """
CREATE TABLE company_profile (
    company_id      TEXT PRIMARY KEY,
    name            TEXT NOT NULL DEFAULT '',
    logo_path       TEXT,
    address         TEXT,
    phone           TEXT,
    license_no      TEXT,
    colors_json     TEXT,
    service_area_json TEXT,
    tax_rules_json  TEXT,
    crop_sending_enabled INTEGER NOT NULL DEFAULT 1,
    updated_by      TEXT,
    updated_at      TEXT NOT NULL
);

CREATE TABLE setup_progress (
    company_id  TEXT NOT NULL,
    step        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'not_started'
                CHECK (status IN ('not_started', 'done', 'skipped')),
    data_json   TEXT,
    updated_by  TEXT,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (company_id, step)
);

CREATE TABLE markups (
    company_id        TEXT PRIMARY KEY,
    overhead_pct      TEXT NOT NULL DEFAULT '0',
    profit_pct        TEXT NOT NULL DEFAULT '0',
    labor_burden_pct  TEXT NOT NULL DEFAULT '0',
    tax_pct           TEXT NOT NULL DEFAULT '0',
    taxable_kinds     TEXT NOT NULL DEFAULT 'material',
    tax_base          TEXT NOT NULL DEFAULT 'cost' CHECK (tax_base IN ('cost', 'price')),
    min_margin_pct    TEXT NOT NULL DEFAULT '0',
    round_to_cents    INTEGER,
    rounding_mode     TEXT NOT NULL DEFAULT 'half_up',
    minimum_charge_cents INTEGER,
    updated_by        TEXT,
    updated_at        TEXT NOT NULL
);

CREATE TABLE price_book (
    id              INTEGER PRIMARY KEY,
    company_id      TEXT NOT NULL,
    price_key       TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    kind            TEXT NOT NULL CHECK (kind IN ('material', 'labor', 'equipment', 'sub', 'other')),
    unit            TEXT NOT NULL,
    cost_cents      INTEGER NOT NULL CHECK (cost_cents >= 0),
    labor_hours     TEXT,
    supplier        TEXT,
    is_sample       INTEGER NOT NULL DEFAULT 0,
    effective_date  TEXT NOT NULL,
    created_by      TEXT,
    created_at      TEXT NOT NULL,
    UNIQUE (company_id, price_key, effective_date)
);
CREATE INDEX ix_price_book_key ON price_book (company_id, price_key, effective_date);

CREATE TABLE estimates (
    id                 INTEGER PRIMARY KEY,
    company_id         TEXT NOT NULL,
    customer_id        TEXT,
    job_id             TEXT,
    address            TEXT,
    title              TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'draft'
                       CHECK (status IN ('draft', 'in_review', 'approved', 'sent', 'won', 'lost', 'expired', 'archived')),
    rev                INTEGER NOT NULL DEFAULT 1,       -- optimistic-concurrency counter, bumps on every write
    revision           INTEGER NOT NULL DEFAULT 1,       -- estimate revision number (v1, v2…) after finalizing
    parent_estimate_id INTEGER REFERENCES estimates (id),
    change_summary     TEXT,
    due_date           TEXT,
    totals_json        TEXT,
    assigned_to        TEXT,
    created_by         TEXT,
    created_at         TEXT NOT NULL,
    updated_by         TEXT,
    updated_at         TEXT NOT NULL
);
CREATE INDEX ix_estimates_company ON estimates (company_id, status);

CREATE TABLE trade_sections (
    id              INTEGER PRIMARY KEY,
    estimate_id     INTEGER NOT NULL REFERENCES estimates (id) ON DELETE CASCADE,
    module_id       TEXT NOT NULL,
    module_version  TEXT,
    params_json     TEXT,
    needs_reprice   INTEGER NOT NULL DEFAULT 0,
    sort_order      INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT,
    created_at      TEXT NOT NULL,
    UNIQUE (estimate_id, module_id)
);

CREATE TABLE line_items (
    id                INTEGER PRIMARY KEY,
    trade_section_id  INTEGER NOT NULL REFERENCES trade_sections (id) ON DELETE CASCADE,
    assembly_use_id   INTEGER,
    kind              TEXT NOT NULL CHECK (kind IN ('material', 'labor', 'equipment', 'sub', 'other')),
    description       TEXT NOT NULL DEFAULT '',
    quantity          TEXT NOT NULL,
    unit              TEXT NOT NULL,
    unit_cost_cents   INTEGER NOT NULL CHECK (unit_cost_cents >= 0),
    waste_pct         TEXT NOT NULL DEFAULT '0',
    price_key         TEXT,
    calc_json         TEXT,          -- full price breakdown from the pricing stack
    total_cents       INTEGER,
    override_by       TEXT,
    sort_order        INTEGER NOT NULL DEFAULT 0,
    created_by        TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);
CREATE INDEX ix_line_items_section ON line_items (trade_section_id);

CREATE TABLE estimate_events (
    id            INTEGER PRIMARY KEY,
    company_id    TEXT NOT NULL,
    estimate_id   INTEGER,
    actor         TEXT NOT NULL,        -- user id, or 'agent:<role>' with on_behalf_of
    on_behalf_of  TEXT,
    action        TEXT NOT NULL,
    before_json   TEXT,
    after_json    TEXT,
    at            TEXT NOT NULL
);
CREATE INDEX ix_events_estimate ON estimate_events (estimate_id, at);
"""),
    (2, "director", """
CREATE TABLE director_jobs (
    id                  INTEGER PRIMARY KEY,
    company_id          TEXT NOT NULL,
    estimate_id         INTEGER REFERENCES estimates (id),
    customer_id         TEXT,
    lane                TEXT CHECK (lane IN ('quick_quote', 'standard_estimate', 'full_takeoff')),
    module_id           TEXT,
    playbook_id         TEXT,
    playbook_version    TEXT,
    stage               TEXT NOT NULL DEFAULT 'triage',
    state               TEXT NOT NULL DEFAULT 'active'
                        CHECK (state IN ('active', 'waiting_on_user', 'waiting_on_ai', 'waiting_on_customer',
                                         'waiting_on_feature', 'done', 'cancelled')),
    waiting_on          TEXT,
    assigned_to         TEXT,
    due_date            TEXT,
    request_text        TEXT NOT NULL DEFAULT '',
    answers_json        TEXT,
    open_questions_json TEXT,
    next_step_json      TEXT,
    rev                 INTEGER NOT NULL DEFAULT 1,
    created_by          TEXT,
    created_at          TEXT NOT NULL,
    updated_by          TEXT,
    updated_at          TEXT NOT NULL
);
CREATE INDEX ix_director_jobs_company ON director_jobs (company_id, state);

CREATE TABLE director_steps (
    id            INTEGER PRIMARY KEY,
    job_id        INTEGER NOT NULL REFERENCES director_jobs (id) ON DELETE CASCADE,
    stage         TEXT NOT NULL,
    agent_role    TEXT NOT NULL,
    provider      TEXT,
    state         TEXT NOT NULL CHECK (state IN ('queued', 'running', 'done', 'blocked', 'failed', 'skipped')),
    input_summary TEXT,
    result_json   TEXT,
    actor         TEXT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT
);
CREATE INDEX ix_director_steps_job ON director_steps (job_id);

CREATE TABLE playbook_overrides (
    company_id     TEXT NOT NULL,
    playbook_id    TEXT NOT NULL,
    overrides_json TEXT NOT NULL,
    updated_by     TEXT,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (company_id, playbook_id)
);

CREATE TABLE director_settings (
    company_id               TEXT PRIMARY KEY,
    quick_send_limit_cents   INTEGER NOT NULL DEFAULT 10000 CHECK (quick_send_limit_cents >= 0),
    calendar_booking_enabled INTEGER NOT NULL DEFAULT 0,
    customer_intake_enabled  INTEGER NOT NULL DEFAULT 0,
    follow_up_days           INTEGER NOT NULL DEFAULT 5 CHECK (follow_up_days >= 1),
    review_reminder_days     INTEGER NOT NULL DEFAULT 2 CHECK (review_reminder_days >= 1),
    briefing_enabled         INTEGER NOT NULL DEFAULT 1,
    briefing_time            TEXT NOT NULL DEFAULT '07:00',
    briefing_channel         TEXT NOT NULL DEFAULT 'chat' CHECK (briefing_channel IN ('chat', 'pwa', 'email')),
    updated_by               TEXT,
    updated_at               TEXT NOT NULL
);
"""),
    (3, "bids", """
CREATE TABLE bids (
    id             INTEGER PRIMARY KEY,
    company_id     TEXT NOT NULL,
    estimate_id    INTEGER NOT NULL REFERENCES estimates (id),
    version        INTEGER NOT NULL,
    number         TEXT NOT NULL,
    customer_id    TEXT,
    customer_json  TEXT,
    scope_text     TEXT,
    inclusions     TEXT,
    exclusions     TEXT,
    terms          TEXT,
    snapshot_json  TEXT NOT NULL,        -- frozen line items and totals at the time the bid was made
    total_cents    INTEGER NOT NULL,
    html_path      TEXT,
    pdf_path       TEXT,
    status         TEXT NOT NULL DEFAULT 'draft'
                   CHECK (status IN ('draft', 'sent', 'viewed', 'won', 'lost', 'expired', 'void')),
    valid_until    TEXT,
    sent_at        TEXT,
    sent_to        TEXT,
    quote_id       TEXT,                 -- AI-Prowler Quotes row (QTE-####) after conversion
    job_id         TEXT,                 -- AI-Prowler Jobs row (JOB-####) after conversion
    rev            INTEGER NOT NULL DEFAULT 1,
    created_by     TEXT,
    created_at     TEXT NOT NULL,
    updated_by     TEXT,
    updated_at     TEXT NOT NULL,
    UNIQUE (estimate_id, version)
);
CREATE INDEX ix_bids_company ON bids (company_id, status);
ALTER TABLE director_jobs ADD COLUMN customer_json TEXT;
"""),
    (4, "standard lane review limit", """
ALTER TABLE director_settings ADD COLUMN review_required_over_cents INTEGER NOT NULL DEFAULT 50000
    CHECK (review_required_over_cents >= 0);
"""),
    (5, "options and multi-trade jobs", """
CREATE TABLE estimate_scenarios (
    id            INTEGER PRIMARY KEY,
    company_id    TEXT NOT NULL,
    estimate_id   INTEGER NOT NULL REFERENCES estimates (id),
    module_id     TEXT NOT NULL,
    option_id     TEXT NOT NULL,
    label         TEXT NOT NULL,
    answers_json  TEXT NOT NULL,         -- the answers this option changes
    total_cents   INTEGER NOT NULL,      -- whole-estimate total with this option
    totals_json   TEXT NOT NULL,
    uses_samples  INTEGER NOT NULL DEFAULT 0,
    chosen        INTEGER NOT NULL DEFAULT 0,
    created_by    TEXT,
    created_at    TEXT NOT NULL,
    UNIQUE (estimate_id, module_id, option_id)
);
CREATE INDEX ix_scenarios_estimate ON estimate_scenarios (estimate_id);
ALTER TABLE director_jobs ADD COLUMN trades_json TEXT;   -- extra trades on one job: {module_id: answers}
"""),
    (6, "director watcher and notices", """
ALTER TABLE director_settings ADD COLUMN watcher_enabled INTEGER NOT NULL DEFAULT 1;
ALTER TABLE director_settings ADD COLUMN watch_interval_minutes INTEGER NOT NULL DEFAULT 15
    CHECK (watch_interval_minutes BETWEEN 5 AND 240);
ALTER TABLE director_settings ADD COLUMN auto_expire_bids INTEGER NOT NULL DEFAULT 1;
ALTER TABLE director_settings ADD COLUMN due_soon_days INTEGER NOT NULL DEFAULT 2 CHECK (due_soon_days BETWEEN 0 AND 30);
ALTER TABLE director_settings ADD COLUMN briefing_email TEXT;
CREATE TABLE director_notices (
    id                INTEGER PRIMARY KEY,
    company_id        TEXT NOT NULL,
    kind              TEXT NOT NULL,      -- briefing, follow_up, expiring, expired, review_reminder, stuck, due_soon, overdue
    dedupe_key        TEXT NOT NULL,      -- one notice per event (e.g. follow_up:12, briefing:2026-11-07)
    job_id            INTEGER,
    estimate_id       INTEGER,
    bid_id            INTEGER,
    message           TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    delivered_via     TEXT,               -- chat (the inbox) or email
    delivered_at      TEXT,
    delivery_attempts INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT,
    read_at           TEXT,
    UNIQUE (company_id, dedupe_key)
);
CREATE INDEX ix_notices_unread ON director_notices (company_id, read_at);
CREATE TABLE director_watch_runs (
    id           INTEGER PRIMARY KEY,
    company_id   TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    result_json  TEXT
);
CREATE INDEX ix_watch_runs_company ON director_watch_runs (company_id, id);
"""),
    (7, "estimate runner and agent manager", """
CREATE TABLE runs (
    id            INTEGER PRIMARY KEY,
    company_id    TEXT NOT NULL,
    estimate_id   INTEGER NOT NULL REFERENCES estimates (id),
    job_id        INTEGER,                 -- the Director job that started it, if any
    plan_set_id   INTEGER,                 -- plan engine (Coder 2 track), NULL until then
    state         TEXT NOT NULL DEFAULT 'running'
                  CHECK (state IN ('running', 'needs_review', 'completed', 'partial', 'failed', 'cancelled')),
    started_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    finished_at   TEXT
);
CREATE INDEX ix_runs_estimate ON runs (company_id, estimate_id);
CREATE TABLE takeoff_tasks (
    id              INTEGER PRIMARY KEY,
    company_id      TEXT NOT NULL,
    run_id          INTEGER NOT NULL REFERENCES runs (id),
    estimate_id     INTEGER NOT NULL,
    module_id       TEXT NOT NULL,
    position        INTEGER NOT NULL,
    sheet_ids_json  TEXT,
    depends_on_json TEXT NOT NULL DEFAULT '[]',
    state           TEXT NOT NULL DEFAULT 'queued'
                    CHECK (state IN ('queued', 'running', 'needs_review', 'completed', 'blocked', 'failed')),
    progress        INTEGER NOT NULL DEFAULT 0,
    proposed_json   TEXT,                  -- quantities a takeoff agent (or person) submitted
    answers_json    TEXT,                  -- quantities a person approved (only these are priced)
    confidence      INTEGER,               -- 0-100, from the takeoff agent
    submitted_by    TEXT,
    reviewed_by     TEXT,
    error           TEXT,
    note            TEXT,
    started_at      TEXT,
    finished_at     TEXT,
    updated_at      TEXT NOT NULL,
    UNIQUE (run_id, module_id)
);
CREATE INDEX ix_tasks_run ON takeoff_tasks (run_id);
CREATE TABLE agent_configs (
    company_id           TEXT NOT NULL,
    module_id            TEXT NOT NULL,
    enabled              INTEGER NOT NULL DEFAULT 1,
    confidence_threshold INTEGER NOT NULL DEFAULT 85 CHECK (confidence_threshold BETWEEN 0 AND 100),
    auto_advance         INTEGER NOT NULL DEFAULT 0,
    sheet_rules_json     TEXT,
    defaults_json        TEXT,
    updated_by           TEXT,
    updated_at           TEXT,
    PRIMARY KEY (company_id, module_id)
);
"""),
    (8, "api-key agents: roles, budgets, usage, task queue", """
CREATE TABLE agent_roles (
    company_id        TEXT NOT NULL,
    role              TEXT NOT NULL,
    provider          TEXT NOT NULL DEFAULT 'off'
                      CHECK (provider IN ('off', 'chat_only', 'claude_api', 'grok_api')),
    model             TEXT,                   -- NULL = AI-Prowler's agent model for that provider
    fallback_provider TEXT CHECK (fallback_provider IS NULL OR fallback_provider IN ('claude_api', 'grok_api')),
    updated_by        TEXT,
    updated_at        TEXT,
    PRIMARY KEY (company_id, role)
);
CREATE TABLE agent_budgets (
    company_id    TEXT PRIMARY KEY,
    daily_cents   INTEGER NOT NULL DEFAULT 200,
    monthly_cents INTEGER NOT NULL DEFAULT 2000,
    updated_by    TEXT,
    updated_at    TEXT
);
CREATE TABLE agent_tasks (
    id            INTEGER PRIMARY KEY,
    company_id    TEXT NOT NULL,
    role          TEXT NOT NULL,
    dedupe_key    TEXT NOT NULL,
    estimate_id   INTEGER,
    job_id        INTEGER,
    bid_id        INTEGER,
    state         TEXT NOT NULL DEFAULT 'queued'
                  CHECK (state IN ('queued', 'waiting_for_ai', 'paused', 'done', 'failed', 'cancelled')),
    attempts      INTEGER NOT NULL DEFAULT 0,
    provider_used TEXT,
    model_used    TEXT,
    result_json   TEXT,                   -- the actions that were applied, and any drafts
    applied_at    TEXT,                   -- when a person used a draft
    error         TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    finished_at   TEXT,
    UNIQUE (company_id, dedupe_key)
);
CREATE INDEX ix_agent_tasks_state ON agent_tasks (company_id, state, id);
CREATE TABLE agent_usage (
    id            INTEGER PRIMARY KEY,
    company_id    TEXT NOT NULL,
    task_id       INTEGER,
    role          TEXT NOT NULL,
    provider      TEXT NOT NULL,
    model         TEXT,
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_micros   INTEGER NOT NULL DEFAULT 0, -- millionths of a dollar
    ok            INTEGER NOT NULL DEFAULT 1,
    error         TEXT,
    at            TEXT NOT NULL
);
CREATE INDEX ix_agent_usage_company ON agent_usage (company_id, at);
"""),
    (9, "actual job costs for the learning loop", """
CREATE TABLE estimate_actuals (
    id                   INTEGER PRIMARY KEY,
    company_id           TEXT NOT NULL,
    estimate_id          INTEGER NOT NULL REFERENCES estimates (id) ON DELETE CASCADE,
    line_item_id         INTEGER,
    price_key            TEXT,
    module_id            TEXT,
    kind                 TEXT CHECK (kind IS NULL OR kind IN ('material', 'labor', 'equipment', 'sub', 'other')),
    description          TEXT NOT NULL DEFAULT '',
    est_quantity         TEXT,
    est_unit_cost_cents  INTEGER,
    est_total_cents      INTEGER,
    actual_quantity      TEXT,
    actual_cost_cents    INTEGER NOT NULL CHECK (actual_cost_cents >= 0),
    actual_hours         TEXT,
    note                 TEXT,
    recorded_by          TEXT,
    recorded_at          TEXT NOT NULL
);
CREATE INDEX ix_actuals_estimate ON estimate_actuals (company_id, estimate_id);
CREATE INDEX ix_actuals_key ON estimate_actuals (company_id, price_key)
"""),
    (10, "assignments for one person, practice project", """
ALTER TABLE director_notices ADD COLUMN for_user TEXT;
ALTER TABLE estimates ADD COLUMN is_practice INTEGER NOT NULL DEFAULT 0
"""),
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ensure_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )


def current_version(conn: sqlite3.Connection) -> int:
    _ensure_table(conn)
    row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    return int(row[0] or 0)


def migrate(conn: sqlite3.Connection, target: int | None = None) -> list[int]:
    """Apply pending migrations up to target (default: latest). Returns versions applied."""
    _ensure_table(conn)
    have = current_version(conn)
    latest = MIGRATIONS[-1][0] if MIGRATIONS else 0
    target = latest if target is None else target
    if have > latest:
        raise RuntimeError(f"estimator.db is version {have}, newer than this software ({latest}); update AI-Prowler")
    applied = []
    for version, name, sql in MIGRATIONS:
        if version <= have or version > target:
            continue
        conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in _split(sql):
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (version, name, _now()),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        applied.append(version)
    return applied


def _split(sql: str) -> list[str]:
    """Split a migration script into statements (no semicolons inside our DDL strings)."""
    parts = []
    for raw in sql.split(";"):
        lines = [ln for ln in raw.splitlines() if not ln.strip().startswith("--")]
        stmt = "\n".join(lines).strip()
        if stmt:
            parts.append(stmt)
    return parts
