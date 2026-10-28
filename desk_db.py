"""
desk_db.py — AI-Prowler Service Desk.

The tickets database: its own SQLite file (ai_prowler_tickets.db), kept
apart from the jobs database so it can be backed up and restored on its
own and a schema change here can never touch ai_prowler_jobs.db.

SQLite is the system of record (lists, search, SLAs, concurrency). Every
ticket ALSO has its own folder with a ticket.json state file, rewritten
after each committed change — see desk_files.py. The rule is: commit to
SQLite first, then write ticket.json atomically; if the two ever disagree
SQLite wins and the file is regenerated.

Every operation takes the caller (`actor`) and the `edition` and asks
desk_rules.can() before touching anything, so the PWA API, HTTP routes and
MCP tools get exactly the same answers.

Usage:
    import desk_db
    db = desk_db.default_db_path()
    desk_db.init_db(db)
    t = desk_db.create_ticket(db, title="Streaks on front windows",
                              kind="external", contact_id="CT-0001", edition="solo")
    desk_db.change_state(db, t["ticket_id"], "In Progress", edition="solo")
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import sqlite3
from pathlib import Path

import desk_rules as rules
from db_access import get_connection, utcnow_iso

log = logging.getLogger("desk_db")

DEFAULT_DB_FILENAME = "ai_prowler_tickets.db"
DEFAULT_SUBDIR = "tickets_database"
SCHEMA_VERSION = 1


class DeskError(Exception):
    """A rule refused the request (permission, edition or lifecycle)."""


class StaleRowError(DeskError):
    """Someone else changed the ticket since the caller loaded it."""


class NotFoundError(DeskError):
    """No such ticket (or the caller may not know it exists)."""


# ── Paths ────────────────────────────────────────────────────────────────────

def _state_dir() -> Path:
    """Same override as tool_config_store: tests use AIPROWLER_TEST_STATE_DIR."""
    override = os.environ.get("AIPROWLER_TEST_STATE_DIR")
    return Path(override) if override else Path.home() / ".ai-prowler"


def default_root() -> Path:
    """Folder holding the tickets DB, the per-ticket folders and backups."""
    return _state_dir() / DEFAULT_SUBDIR


def default_db_path() -> str:
    return str(default_root() / DEFAULT_DB_FILENAME)


def root_for(db_path: str) -> Path:
    """Ticket folders always live beside the database file."""
    return Path(db_path).resolve().parent


# ── Schema ───────────────────────────────────────────────────────────────────

_STD = ("created_at TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, "
        "last_edited_at TEXT NOT NULL, last_edited_by TEXT NOT NULL")

_STATES_SQL = ", ".join(f"'{s}'" for s in rules.STATES)
_KINDS_SQL = ", ".join(f"'{k}'" for k in rules.KINDS)

SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS desk_settings (
    key            TEXT PRIMARY KEY,
    value          TEXT NOT NULL,
    last_edited_at TEXT NOT NULL,
    last_edited_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    row_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id         TEXT UNIQUE,
    title             TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    kind              TEXT NOT NULL CHECK (kind IN ({_KINDS_SQL})),
    type              TEXT NOT NULL DEFAULT '',
    priority          TEXT NOT NULL DEFAULT 'P3' CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
    state             TEXT NOT NULL DEFAULT 'Open' CHECK (state IN ({_STATES_SQL})),
    queue_id          TEXT,
    assignee          TEXT,
    filed_by          TEXT NOT NULL,
    contact_id        TEXT,
    customer_id       TEXT,
    job_id            TEXT,
    source            TEXT NOT NULL DEFAULT 'pwa',
    visibility        TEXT NOT NULL DEFAULT 'normal' CHECK (visibility IN ('normal', 'private')),
    sms_fallback      INTEGER NOT NULL DEFAULT 0,
    due_response_at   TEXT,
    due_resolve_at    TEXT,
    first_response_at TEXT,
    fixed_at          TEXT,
    closed_at         TEXT,
    close_reason      TEXT,
    csat_score        INTEGER,
    csat_comment      TEXT,
    folder            TEXT,
    hold_started_at   TEXT,
    sla_flags         TEXT NOT NULL DEFAULT '',
    resolution        TEXT,
    {_STD}
);
CREATE INDEX IF NOT EXISTS ix_tickets_state_assignee ON tickets(state, assignee);
CREATE INDEX IF NOT EXISTS ix_tickets_queue_state    ON tickets(queue_id, state);
CREATE INDEX IF NOT EXISTS ix_tickets_customer       ON tickets(customer_id);
CREATE INDEX IF NOT EXISTS ix_tickets_contact        ON tickets(contact_id);
CREATE INDEX IF NOT EXISTS ix_tickets_due_resolve    ON tickets(due_resolve_at);
CREATE INDEX IF NOT EXISTS ix_tickets_last_edited    ON tickets(last_edited_at);

CREATE TABLE IF NOT EXISTS ticket_events (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id   TEXT NOT NULL REFERENCES tickets(ticket_id),
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    approved_by TEXT,
    kind        TEXT NOT NULL,
    from_value  TEXT,
    to_value    TEXT,
    reason      TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ticket ON ticket_events(ticket_id, event_id);

CREATE TABLE IF NOT EXISTS ticket_messages (
    message_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id       TEXT NOT NULL REFERENCES tickets(ticket_id),
    at              TEXT NOT NULL,
    author          TEXT NOT NULL,
    author_kind     TEXT NOT NULL CHECK (author_kind IN ('staff', 'customer', 'subcontractor', 'claude', 'system')),
    visibility      TEXT NOT NULL CHECK (visibility IN ('public', 'internal')),
    channel         TEXT NOT NULL DEFAULT 'pwa',
    body            TEXT NOT NULL,
    delivery_status TEXT,
    provider_msg_id TEXT
);
CREATE INDEX IF NOT EXISTS ix_messages_ticket ON ticket_messages(ticket_id, at);

CREATE TABLE IF NOT EXISTS ticket_attachments (
    attachment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id     TEXT NOT NULL REFERENCES tickets(ticket_id),
    message_id    INTEGER REFERENCES ticket_messages(message_id),
    kind          TEXT NOT NULL CHECK (kind IN ('photo', 'document', 'video')),
    filename      TEXT NOT NULL,
    path          TEXT NOT NULL,
    thumb_path    TEXT,
    mime          TEXT,
    bytes         INTEGER,
    sha256        TEXT,
    taken_at      TEXT,
    uploaded_by   TEXT NOT NULL,
    visibility    TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public', 'internal')),
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_attachments_ticket ON ticket_attachments(ticket_id);

CREATE TABLE IF NOT EXISTS queues (
    queue_id               TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    default_assignee       TEXT,
    members                TEXT NOT NULL DEFAULT '[]',
    round_robin_cursor     INTEGER NOT NULL DEFAULT 0,
    response_sla_minutes   INTEGER,
    resolve_sla_minutes    INTEGER,
    {_STD}
);

CREATE TABLE IF NOT EXISTS ticket_types (
    type_id          TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN ({_KINDS_SQL})),
    default_queue    TEXT,
    default_priority TEXT NOT NULL DEFAULT 'P3',
    form_fields      TEXT NOT NULL DEFAULT '[]',
    {_STD}
);

CREATE TABLE IF NOT EXISTS assignment_rules (
    rule_id    TEXT PRIMARY KEY,
    sort_order INTEGER NOT NULL,
    match_json TEXT NOT NULL DEFAULT '{{}}',
    action_json TEXT NOT NULL DEFAULT '{{}}',
    enabled    INTEGER NOT NULL DEFAULT 1,
    {_STD}
);

CREATE TABLE IF NOT EXISTS customer_contacts (
    contact_id         TEXT PRIMARY KEY,
    contact_type       TEXT NOT NULL DEFAULT 'customer' CHECK (contact_type IN ('customer', 'subcontractor')),
    name               TEXT NOT NULL DEFAULT '',
    phone              TEXT,
    email              TEXT,
    verified_at        TEXT,
    magic_token_hash   TEXT,
    linked_customer_id TEXT,
    {_STD}
);
CREATE INDEX IF NOT EXISTS ix_contacts_phone ON customer_contacts(phone);
CREATE INDEX IF NOT EXISTS ix_contacts_email ON customer_contacts(email);

-- Status links (magic links): a customer or subcontractor sees ONE ticket.
-- Only a SHA-256 of the token is stored; the token itself exists only in the
-- message that carried it.
CREATE TABLE IF NOT EXISTS ticket_links (
    token_hash TEXT PRIMARY KEY,
    ticket_id  TEXT NOT NULL REFERENCES tickets(ticket_id),
    contact_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_links_ticket ON ticket_links(ticket_id);

-- 6-digit codes that verify a phone/email before a portal ticket is accepted.
CREATE TABLE IF NOT EXISTS verify_codes (
    contact_id TEXT PRIMARY KEY,
    code_hash  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    sent_at    TEXT NOT NULL
);

-- "Ask first" SMS mode: a text we asked about, waiting for YES / NO.
CREATE TABLE IF NOT EXISTS sms_pending (
    phone      TEXT PRIMARY KEY,
    body       TEXT NOT NULL,
    asked_at   TEXT NOT NULL
);

-- Links between a ticket and another ticket (duplicate / related) or an invoice.
CREATE TABLE IF NOT EXISTS ticket_relations (
    ticket_id  TEXT NOT NULL REFERENCES tickets(ticket_id),
    kind       TEXT NOT NULL CHECK (kind IN ('duplicate_of', 'related', 'invoice', 'merged_into')),
    target     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY (ticket_id, kind, target)
);

-- Internal people (by email) told whenever a ticket changes state (2026-10-28).
-- Never shown to, or used for, the customer or subcontractor.
CREATE TABLE IF NOT EXISTS ticket_watchers (
    ticket_id  TEXT NOT NULL REFERENCES tickets(ticket_id),
    email      TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    added_at   TEXT NOT NULL,
    added_by   TEXT NOT NULL,
    PRIMARY KEY (ticket_id, email)
);

-- Import batches (undo within 7 days) and scheduler bookkeeping.
CREATE TABLE IF NOT EXISTS import_batches (
    batch_id  TEXT PRIMARY KEY,
    at        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    filename  TEXT NOT NULL,
    count     INTEGER NOT NULL,
    undone_at TEXT
);
CREATE TABLE IF NOT EXISTS push_subscriptions (
    endpoint   TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    p256dh     TEXT NOT NULL,
    auth       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_ok    TEXT
);
CREATE TABLE IF NOT EXISTS desk_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Rate limiting for the public request form (per phone/email/IP).
CREATE TABLE IF NOT EXISTS portal_hits (
    key TEXT NOT NULL,
    at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_portal_hits ON portal_hits(key, at);
"""

# Ordered migrations: (to_version, [sql, ...]). Version 1 is SCHEMA_SQL itself.
MIGRATIONS: list[tuple[int, list[str]]] = []


def apply_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    row = conn.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
    current = int(row[0]) if row else SCHEMA_VERSION
    for to_version, statements in MIGRATIONS:
        if to_version > current:
            for sql in statements:
                conn.execute(sql)
            current = to_version
    conn.execute(
        "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(max(current, SCHEMA_VERSION)),),
    )


def init_db(db_path: str) -> None:
    """Create the folder and schema if missing. Idempotent."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(db_path)
    try:
        apply_schema(conn)
        _seed_ticket_counter(conn, root_for(db_path))
    finally:
        conn.close()


def _seed_ticket_counter(conn: sqlite3.Connection, root: Path) -> None:
    """If ticket folders exist on disk with higher numbers than the database
    knows (the .db was lost or replaced), move the AUTOINCREMENT counter past
    them so a new ticket can never reuse - and overwrite - an existing folder."""
    import desk_files
    on_disk = desk_files.max_ticket_number(root)
    if not on_disk:
        return
    row = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'tickets'").fetchone()
    in_db = (conn.execute("SELECT MAX(row_id) FROM tickets").fetchone() or [0])[0] or 0
    current = max(int(row[0]) if row else 0, int(in_db))
    if on_disk > current:
        if row:
            conn.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = 'tickets'", (on_disk,))
        else:
            conn.execute("INSERT INTO sqlite_sequence (name, seq) VALUES ('tickets', ?)", (on_disk,))


# ── Owner settings (stored in the tickets DB so backups carry them) ──────────

SETTING_DEFAULTS = {
    "own_tickets": True,              # Solo: Owner may file tickets to himself
    "subcontractor_tickets": True,    # Owner may open tickets about a subcontractor
    "sms_fallback_default": False,    # new tickets alert by SMS too
    "alert_email": "",                # Solo: where the Owner's alerts go
    "alert_phone": "",                # Solo: the Owner's mobile for SMS alerts
    "portal_enabled": True,           # public request form at /support/new
    "sms_new_request_mode": "off",    # text that isn't a reply: off | create | ask | link
    "email_new_request_mode": "off",  # email that isn't a reply: off | create
    "email_intake": False,            # poll the server's mailbox (IMAP) for ticket mail
    "csat_enabled": True,             # ask customers to rate a closed ticket
    "auto_close_days": rules.AUTO_CLOSE_DAYS,  # Fixed customer ticket, no reply this long -> Closed (0 = never)
    "customer_status_updates": True,  # tell the customer (one line) when it's In Progress and Closed
    "business_hours": [8, 17],        # SLA clock runs 8:00-17:00 local on working days
    "sla_targets": {},                # {"P2": [respond_min, resolve_min]} overrides
    "digest_hour": 7,                 # morning digest (owner / managers), local hour
    "backup_enabled": True,           # scheduled tickets backup
    "backup_frequency": "daily",      # hourly | daily | weekly
    "backup_hour": 2,                 # local hour for daily/weekly backups
    "backup_keep_daily": 14,
    "backup_keep_weekly": 8,
    "backup_keep_monthly": 12,
    "backup_attachments": True,       # include photos and documents
    "backup_second_dir": "",          # optional second destination (drive, NAS, synced folder)
}

SETTING_CHOICES = {
    "sms_new_request_mode": ("off", "create", "ask", "link"),
    "email_new_request_mode": ("off", "create"),
    "backup_frequency": ("hourly", "daily", "weekly"),
}


def get_settings(db_path: str) -> dict:
    conn = get_connection(db_path)
    try:
        rows = conn.execute("SELECT key, value FROM desk_settings").fetchall()
    finally:
        conn.close()
    out = dict(SETTING_DEFAULTS)
    for r in rows:
        try:
            out[r["key"]] = json.loads(r["value"])
        except ValueError:
            pass
    return out


def set_setting(db_path: str, key: str, value, *, actor=None,
                edition: str = rules.BUSINESS) -> dict:
    d = rules.can(actor, "manage_settings", edition=edition)
    if not d:
        raise DeskError(d.reason)
    if key not in SETTING_DEFAULTS:
        raise DeskError(f"unknown setting {key!r}; settings are: {', '.join(SETTING_DEFAULTS)}")
    if type(value) is not type(SETTING_DEFAULTS[key]):
        raise DeskError(f"{key} must be {type(SETTING_DEFAULTS[key]).__name__}")
    if key in SETTING_CHOICES and value not in SETTING_CHOICES[key]:
        raise DeskError(f"{key} must be one of: {', '.join(SETTING_CHOICES[key])}")
    conn = get_connection(db_path)
    try:
        conn.execute(
            "INSERT INTO desk_settings (key, value, last_edited_at, last_edited_by) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
            "last_edited_at = excluded.last_edited_at, last_edited_by = excluded.last_edited_by",
            (key, json.dumps(value), utcnow_iso(), _actor_id(actor)))
    finally:
        conn.close()
    return get_settings(db_path)


def options_from_settings(settings: dict) -> dict:
    return {k: settings.get(k, v) for k, v in rules.DEFAULT_OPTIONS.items()}


# ── Transactions that keep ticket.json in step ───────────────────────────────

# ticket ids whose ticket.json could not be written after commit; verify()
# reports them and the next successful write clears them.
json_write_failures: dict[str, str] = {}


@contextlib.contextmanager
def ticket_transaction(db_path: str):
    """BEGIN IMMEDIATE ... COMMIT, then rewrite ticket.json for every ticket
    id added to the yielded `touched` set. The JSON is written only after the
    commit succeeds, so a rolled-back change never reaches a file. A failed
    file write does not undo the commit (SQLite is the record); it is logged
    and reported by desk_files.verify()."""
    conn = get_connection(db_path)
    touched: set = set()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn, touched
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        conn.close()
        raise
    try:
        import desk_files
        root = root_for(db_path)
        for tid in touched:
            try:
                desk_files.write_ticket_json(root, conn, tid)
                json_write_failures.pop(tid, None)
            except Exception as e:  # noqa: BLE001 — SQLite already holds the truth
                json_write_failures[tid] = f"{type(e).__name__}: {e}"
                log.warning("ticket.json write failed for %s: %s", tid, e)
    finally:
        conn.close()


# ── Change listeners (alerts) ────────────────────────────────────────────────
# desk_alerts registers here. Called AFTER the commit and outside the database
# lock, once per change, whatever the entry point (MCP tool, app, webhook).
listeners: list = []


def _emit(kind: str, ticket: dict, actor, **info) -> None:
    for fn in list(listeners):
        try:
            fn(kind, ticket, actor, **info)
        except Exception as e:  # noqa: BLE001 — an alert must never undo or fail a change
            log.warning("Service Desk listener %r failed on %s %s: %s",
                        getattr(fn, "__name__", fn), kind, ticket.get("ticket_id"), e)


def _event(conn, ticket_id, actor, kind, from_value=None, to_value=None, reason=None,
           approved_by=None, at=None):
    conn.execute(
        "INSERT INTO ticket_events (ticket_id, at, actor, approved_by, kind, from_value, "
        "to_value, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ticket_id, at or utcnow_iso(), actor, approved_by, kind, from_value, to_value, reason),
    )


def _row(conn, ticket_id) -> dict | None:
    r = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
    return dict(r) if r else None


def _actor_id(actor) -> str:
    return rules.normalize_actor(actor).get("id") or "unknown"


def _check(decision: rules.Decision) -> None:
    if not decision:
        raise DeskError(decision.reason)


def _load_visible(conn, ticket_id, actor, edition) -> dict:
    """Fetch a ticket the actor may see. Unknown and hidden tickets give the
    same answer so an outsider can't probe which ticket numbers exist."""
    row = _row(conn, ticket_id)
    if row is None or not rules.can(actor, "view", row, edition=edition):
        raise NotFoundError(f"no ticket {ticket_id} that you can see")
    return row


def _check_version(row: dict, expected_version) -> None:
    if expected_version is not None and int(expected_version) != int(row["version"]):
        raise StaleRowError(
            f"{row['ticket_id']} was changed by {row['last_edited_by']} at "
            f"{row['last_edited_at']} after you loaded it (version {expected_version}, "
            f"now {row['version']}). Reload and try again.")


def _touch(conn, ticket_id, actor_id):
    conn.execute(
        "UPDATE tickets SET version = version + 1, last_edited_by = ?, last_edited_at = ? "
        "WHERE ticket_id = ?", (actor_id, utcnow_iso(), ticket_id))


def _hold_resume_sets(row: dict, ts: str, edition: str) -> dict:
    """Leaving On Hold: push the SLA due times later by the time spent on hold
    (Business only — in Solo the due date is the owner's own promise)."""
    out = {"hold_started_at": None}
    if edition != rules.BUSINESS or not row.get("hold_started_at"):
        return out
    import desk_sla
    delta = desk_sla.parse(ts) - desk_sla.parse(row["hold_started_at"])
    out["due_resolve_at"] = desk_sla.shift(row.get("due_resolve_at"), delta)
    if not row.get("first_response_at"):
        out["due_response_at"] = desk_sla.shift(row.get("due_response_at"), delta)
    return out


def format_ticket_id(row_id: int) -> str:
    return f"T-{int(row_id):04d}"


# ── Contacts (customers and subcontractors without server accounts) ──────────

def _norm_phone(p):
    if not p:
        return None
    digits = "".join(ch for ch in str(p) if ch.isdigit())
    if len(digits) == 10:
        digits = "1" + digits
    return "+" + digits if digits else None


def upsert_contact(db_path: str, *, name: str = "", phone: str | None = None,
                   email: str | None = None, contact_type: str = "customer",
                   linked_customer_id: str | None = None, actor=None) -> dict:
    """Find a contact by phone or email (same type), or create one."""
    if contact_type not in ("customer", "subcontractor"):
        raise DeskError("contact_type must be 'customer' or 'subcontractor'")
    phone = _norm_phone(phone)
    email = (email or "").strip().lower() or None
    if not (phone or email):
        raise DeskError("a contact needs a phone number or an email address")
    who = _actor_id(actor)
    conn = get_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        r = conn.execute(
            "SELECT * FROM customer_contacts WHERE contact_type = ? AND "
            "((? IS NOT NULL AND phone = ?) OR (? IS NOT NULL AND email = ?))",
            (contact_type, phone, phone, email, email)).fetchone()
        now = utcnow_iso()
        if r:
            cid = r["contact_id"]
            conn.execute(
                "UPDATE customer_contacts SET name = COALESCE(NULLIF(?, ''), name), "
                "phone = COALESCE(?, phone), email = COALESCE(?, email), "
                "linked_customer_id = COALESCE(?, linked_customer_id), version = version + 1, "
                "last_edited_at = ?, last_edited_by = ? WHERE contact_id = ?",
                (name, phone, email, linked_customer_id, now, who, cid))
        else:
            n = conn.execute("SELECT COUNT(*) FROM customer_contacts").fetchone()[0] + 1
            while conn.execute("SELECT 1 FROM customer_contacts WHERE contact_id = ?",
                               (f"CT-{n:04d}",)).fetchone():
                n += 1
            cid = f"CT-{n:04d}"
            conn.execute(
                "INSERT INTO customer_contacts (contact_id, contact_type, name, phone, email, "
                "linked_customer_id, created_at, version, last_edited_at, last_edited_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
                (cid, contact_type, name or "", phone, email, linked_customer_id, now, now, who))
        conn.execute("COMMIT")
        return dict(conn.execute("SELECT * FROM customer_contacts WHERE contact_id = ?",
                                 (cid,)).fetchone())
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def get_contact(db_path: str, contact_id: str) -> dict | None:
    conn = get_connection(db_path)
    try:
        r = conn.execute("SELECT * FROM customer_contacts WHERE contact_id = ?",
                         (contact_id,)).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def find_contact(db_path: str, *, phone: str | None = None, email: str | None = None,
                 contact_type: str | None = None) -> dict | None:
    phone = _norm_phone(phone)
    email = (email or "").strip().lower() or None
    conn = get_connection(db_path)
    try:
        r = conn.execute(
            "SELECT * FROM customer_contacts WHERE (? IS NULL OR contact_type = ?) AND "
            "((? IS NOT NULL AND phone = ?) OR (? IS NOT NULL AND email = ?)) "
            "ORDER BY created_at LIMIT 1",
            (contact_type, contact_type, phone, phone, email, email)).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


# ── Core ticket operations ───────────────────────────────────────────────────

def get_ticket(db_path: str, ticket_id: str, *, actor=None,
               edition: str = rules.BUSINESS) -> dict | None:
    """The ticket row if the actor may see it, else None."""
    conn = get_connection(db_path)
    try:
        row = _row(conn, ticket_id)
        if row is None or not rules.can(actor, "view", row, edition=edition):
            return None
        return row
    finally:
        conn.close()


def get_ticket_detail(db_path: str, ticket_id: str, *, actor=None,
                      edition: str = rules.BUSINESS) -> dict:
    """The full ticket (fields, messages, attachments, events) as the actor may
    see it. Outside parties never get internal notes, internal attachments or
    the event log."""
    import desk_files
    conn = get_connection(db_path)
    try:
        _load_visible(conn, ticket_id, actor, edition)
        doc = desk_files.build_ticket_json(conn, ticket_id)
    finally:
        conn.close()
    if rules.is_external(actor):
        doc["messages"] = [m for m in doc["messages"] if m["visibility"] == "public"]
        doc["attachments"] = [a for a in doc["attachments"] if a["visibility"] == "public"]
        for k in ("events", "state_history", "filed_by", "queue_id", "visibility",
                  "last_edited_by", "folder", "watchers"):
            doc.pop(k, None)
    return doc


# ── Watchers: internal people emailed on every state change (2026-10-28) ─────

_EMAIL_RE = __import__("re").compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")


def list_watchers(db_path: str, ticket_id: str) -> list[dict]:
    conn = get_connection(db_path)
    try:
        return [dict(r) for r in conn.execute(
            "SELECT email, name, added_at, added_by FROM ticket_watchers WHERE ticket_id = ? "
            "ORDER BY added_at, email", (ticket_id,))]
    finally:
        conn.close()


def set_watcher(db_path: str, ticket_id: str, email: str, *, name: str = "", remove: bool = False,
                actor=None, edition: str = rules.BUSINESS) -> list[dict]:
    """Add (or remove) one watcher. The owner, managers and the ticket's
    assignee may add or remove anyone; anyone else on the team who can see the
    ticket may add or remove only themselves. Customers and subcontractors
    can't — and a ticket's own customer/subcontractor address is refused (they
    get their own short updates, never the internal ones). Returns the list."""
    a = rules.normalize_actor(actor)
    email = (email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        raise DeskError(f"{email or '(blank)'} is not an email address")
    if rules.is_external(actor):
        raise DeskError("only the team can add watchers")
    with ticket_transaction(db_path) as (conn, touched):
        row = _load_visible(conn, ticket_id, actor, edition)
        mine = (a.get("email") or "").strip().lower()
        if not (a["role"] in (rules.OWNER, rules.MANAGER) or row.get("assignee") == a["id"]
                or (mine and email == mine)):
            raise DeskError("only the owner, a manager or the assignee can change who watches a ticket "
                            "(you can add or remove yourself)")
        if not remove and row.get("contact_id"):
            c = conn.execute("SELECT email FROM customer_contacts WHERE contact_id = ?",
                             (row["contact_id"],)).fetchone()
            if c and (c["email"] or "").strip().lower() == email:
                raise DeskError("that's this ticket's customer — customers get their own short "
                                "updates (in progress, closed), never the internal ones")
        if remove:
            n = conn.execute("DELETE FROM ticket_watchers WHERE ticket_id = ? AND email = ?",
                             (ticket_id, email)).rowcount
            if n:
                _event(conn, ticket_id, a["id"], "watcher_removed", email, None)
        else:
            n = conn.execute("INSERT OR IGNORE INTO ticket_watchers (ticket_id, email, name, added_at, "
                             "added_by) VALUES (?, ?, ?, ?, ?)",
                             (ticket_id, email, (name or "").strip()[:80], utcnow_iso(), a["id"])).rowcount
            if n:
                _event(conn, ticket_id, a["id"], "watcher_added", None, email)
        if n:
            touched.add(ticket_id)
    return list_watchers(db_path, ticket_id)


def create_ticket(db_path: str, *, title: str, kind: str = rules.EXTERNAL, actor=None,
                  edition: str = rules.BUSINESS, description: str = "", type: str = "",
                  priority: str = "P3", source: str = "pwa", contact_id: str | None = None,
                  customer_id: str | None = None, job_id: str | None = None,
                  visibility: str = "normal", queue_id: str | None = None,
                  assignee: str | None = None, owner_id: str = "owner",
                  due_resolve_at: str | None = None, sms_fallback: bool | None = None,
                  options: dict | None = None) -> dict:
    """File a ticket. Solo: every ticket is assigned to the owner at once.
    Business: Assigned when an assignee is given, otherwise Open."""
    settings = get_settings(db_path)
    if options is None:
        options = options_from_settings(settings)
    _check(rules.can(actor, "create", edition=edition, kind=kind, options=options))
    title = (title or "").strip()
    if not title:
        raise DeskError("a ticket needs a title")
    if priority not in rules.PRIORITIES:
        raise DeskError(f"priority must be one of {', '.join(rules.PRIORITIES)}")
    if visibility not in rules.VISIBILITIES:
        raise DeskError("visibility must be 'normal' or 'private'")
    a = rules.normalize_actor(actor)
    if a["role"] == rules.CUSTOMER:
        contact_id = a.get("contact_id") or contact_id
    if kind == rules.EXTERNAL and not (contact_id or customer_id):
        raise DeskError("a customer ticket needs the customer (contact_id or customer_id)")
    if kind == rules.SUBCONTRACTOR_KIND:
        c = get_contact(db_path, contact_id) if contact_id else None
        if not c or c["contact_type"] != "subcontractor":
            raise DeskError("a subcontractor ticket needs a subcontractor contact (contact_id)")
    if edition == rules.SOLO:
        assignee = owner_id
    elif assignee:
        _check(rules.can(actor, "assign", {"kind": kind, "assignee": None, "filed_by": a["id"],
                                           "queue_id": queue_id, "visibility": visibility,
                                           "contact_id": contact_id},
                         edition=edition, assignee=assignee))
    route_why = None
    if edition == rules.BUSINESS and not assignee:
        import desk_routing
        assignee, queue_id, route_why = desk_routing.choose(db_path, {
            "title": title, "description": description, "kind": kind, "type": type,
            "customer_id": customer_id, "job_id": job_id, "queue_id": queue_id})
    if sms_fallback is None:
        sms_fallback = bool(settings.get("sms_fallback_default")) or priority == "P1"
    state = rules.ASSIGNED if assignee else rules.OPEN
    now = utcnow_iso()
    due_response_at = None
    if rules.feature_enabled(edition, "sla_escalation"):
        import desk_sla
        due_response_at, sla_resolve = desk_sla.due_times(
            priority, desk_sla.parse(now), settings=settings, days=desk_sla.working_days())
        due_resolve_at = due_resolve_at or sla_resolve
    who = a.get("id") or "unknown"
    with ticket_transaction(db_path) as (conn, touched):
        cur = conn.execute(
            "INSERT INTO tickets (title, description, kind, type, priority, state, queue_id, "
            "assignee, filed_by, contact_id, customer_id, job_id, source, visibility, "
            "sms_fallback, due_resolve_at, created_at, version, last_edited_at, last_edited_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (title, description or "", kind, type or "", priority, state, queue_id, assignee,
             who, contact_id, customer_id, job_id, source, visibility, int(bool(sms_fallback)),
             due_resolve_at, now, now, who))
        tid = format_ticket_id(cur.lastrowid)
        folder = f"tickets/{now[:4]}/{tid}"
        conn.execute("UPDATE tickets SET ticket_id = ?, folder = ?, due_response_at = ? "
                     "WHERE row_id = ?", (tid, folder, due_response_at, cur.lastrowid))
        _event(conn, tid, who, "created", to_value=rules.OPEN, at=now)
        if assignee:
            _event(conn, tid, route_why or (who if edition == rules.BUSINESS else "rule:solo-owner"),
                   "assigned", to_value=assignee, at=now)
            _event(conn, tid, who, "state_change", rules.OPEN, rules.ASSIGNED, at=now)
        touched.add(tid)
        row = _row(conn, tid)
    _emit("created", row, actor, edition=edition)
    return row


EDITABLE_FIELDS = ("title", "description", "type", "priority", "due_response_at",
                   "due_resolve_at", "customer_id", "job_id", "visibility", "sms_fallback",
                   "resolution")


def update_ticket(db_path: str, ticket_id: str, fields: dict, *, actor=None,
                  edition: str = rules.BUSINESS, reason: str = "",
                  expected_version=None, via_claude: bool = False) -> dict:
    """Edit ticket fields. A priority change needs a reason; visibility is the
    owner's call. Every changed field is logged as a field_edit event."""
    bad = [k for k in fields if k not in EDITABLE_FIELDS]
    if bad:
        raise DeskError(f"cannot edit {', '.join(bad)}; editable fields: {', '.join(EDITABLE_FIELDS)}")
    if "priority" in fields and fields["priority"] not in rules.PRIORITIES:
        raise DeskError(f"priority must be one of {', '.join(rules.PRIORITIES)}")
    if "visibility" in fields and fields["visibility"] not in rules.VISIBILITIES:
        raise DeskError("visibility must be 'normal' or 'private'")
    if "title" in fields and not str(fields["title"]).strip():
        raise DeskError("a ticket needs a title")
    with ticket_transaction(db_path) as (conn, touched):
        row = _load_visible(conn, ticket_id, actor, edition)
        _check(rules.can(actor, "edit", row, edition=edition))
        _check_version(row, expected_version)
        a = rules.normalize_actor(actor)
        if "visibility" in fields and a["role"] != rules.OWNER and fields["visibility"] != row["visibility"]:
            raise DeskError("only the owner can change a ticket's visibility")
        changes = {}
        for k, v in fields.items():
            if k == "sms_fallback":
                v = int(bool(v))
            if row.get(k) != v:
                changes[k] = v
        if not changes:
            return row
        if "priority" in changes and not (reason or "").strip():
            raise DeskError("changing the priority needs a reason")
        who = a["id"]
        cols = ", ".join(f"{k} = ?" for k in changes)
        conn.execute(f"UPDATE tickets SET {cols} WHERE ticket_id = ?", (*changes.values(), ticket_id))
        for k, v in changes.items():
            _event(conn, ticket_id, "claude" if via_claude else who, "field_edit",
                   f"{k}={row.get(k)}", f"{k}={v}", reason=(reason or "").strip() or None,
                   approved_by=who if via_claude else None)
        _touch(conn, ticket_id, who)
        touched.add(ticket_id)
        return _row(conn, ticket_id)


def assign_ticket(db_path: str, ticket_id: str, assignee: str, *, actor=None,
                  edition: str = rules.BUSINESS, expected_version=None,
                  via_claude: bool = False) -> dict:
    with ticket_transaction(db_path) as (conn, touched):
        row = _load_visible(conn, ticket_id, actor, edition)
        _check(rules.can(actor, "assign", row, edition=edition, assignee=assignee))
        _check_version(row, expected_version)
        who = _actor_id(actor)
        if row["assignee"] == assignee:
            return row
        conn.execute("UPDATE tickets SET assignee = ? WHERE ticket_id = ?", (assignee, ticket_id))
        _event(conn, ticket_id, "claude" if via_claude else who, "assigned", row["assignee"],
               assignee, approved_by=who if via_claude else None)
        if row["state"] == rules.OPEN:
            conn.execute("UPDATE tickets SET state = ? WHERE ticket_id = ?",
                         (rules.ASSIGNED, ticket_id))
            _event(conn, ticket_id, who, "state_change", rules.OPEN, rules.ASSIGNED)
        _touch(conn, ticket_id, who)
        touched.add(ticket_id)
        out = _row(conn, ticket_id)
    _emit("assigned", out, actor, edition=edition, previous=row["assignee"])
    return out


def change_state(db_path: str, ticket_id: str, to_state: str, *, actor=None,
                 edition: str = rules.BUSINESS, reason: str = "", expected_version=None,
                 now=None, approved_by: str | None = None, system: bool = False) -> dict:
    """Move a ticket through the lifecycle, enforcing rules.can().
    system=True: an automatic change (the scheduler's auto-close) made with the
    owner's authority but recorded as "system", so the history shows nobody
    pressed a button."""
    with ticket_transaction(db_path) as (conn, touched):
        row = _load_visible(conn, ticket_id, actor, edition)
        _check(rules.can(actor, "change_state", row, edition=edition, to_state=to_state,
                         reason=reason, now=now))
        _check_version(row, expected_version)
        who = "system" if system else _actor_id(actor)
        ts = utcnow_iso()
        sets = {"state": to_state}
        frm = row["state"]
        if to_state == rules.FIXED:
            sets["fixed_at"] = ts
        if to_state == rules.CLOSED:
            sets["closed_at"] = ts
            sets["close_reason"] = (reason or "").strip() or ("confirmed by customer"
                                                               if frm == rules.FIXED else None)
        if frm == rules.CLOSED:                       # reopen
            sets["closed_at"] = None
            sets["close_reason"] = None
        if to_state == rules.ON_HOLD:                 # SLA clock pauses
            sets["hold_started_at"] = ts
        elif frm == rules.ON_HOLD:
            sets.update(_hold_resume_sets(row, ts, edition))
        cols = ", ".join(f"{k} = ?" for k in sets)
        conn.execute(f"UPDATE tickets SET {cols} WHERE ticket_id = ?",
                     (*sets.values(), ticket_id))
        _event(conn, ticket_id, who, "state_change", frm, to_state,
               reason=(reason or "").strip() or None, approved_by=approved_by, at=ts)
        _touch(conn, ticket_id, who)
        touched.add(ticket_id)
        out = _row(conn, ticket_id)
    _emit("state_changed", out, actor, edition=edition, from_state=frm,
          reason=(reason or "").strip())
    return out


def add_message(db_path: str, ticket_id: str, body: str, *, actor=None,
                edition: str = rules.BUSINESS, visibility: str = "internal",
                channel: str = "pwa", author_kind: str | None = None,
                delivery_status: str | None = None, provider_msg_id: str | None = None) -> dict:
    """Add a message. visibility='internal' is a team note; 'public' goes to (or
    comes from) the ticket's customer or subcontractor. A reply from the outside
    party takes an On Hold ticket back to In Progress (its wait is over)."""
    body = (body or "").strip()
    if not body:
        raise DeskError("a message needs some text")
    if visibility not in ("internal", "public"):
        raise DeskError("visibility must be 'internal' or 'public'")
    a = rules.normalize_actor(actor)
    with ticket_transaction(db_path) as (conn, touched):
        row = _load_visible(conn, ticket_id, actor, edition)
        action = "reply_customer" if visibility == "public" else "note"
        _check(rules.can(actor, action, row, edition=edition))
        if author_kind is None:
            author_kind = a["role"] if a["role"] in rules.EXTERNAL_ROLES else "staff"
        ts = utcnow_iso()
        if visibility == "public" and author_kind in ("staff", "claude") and delivery_status is None:
            delivery_status = "queued"
        cur = conn.execute(
            "INSERT INTO ticket_messages (ticket_id, at, author, author_kind, visibility, channel, "
            "body, delivery_status, provider_msg_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ticket_id, ts, a["id"], author_kind, visibility, channel, body, delivery_status,
             provider_msg_id))
        mid = cur.lastrowid
        if visibility == "public" and author_kind in ("staff", "claude") and not row["first_response_at"]:
            conn.execute("UPDATE tickets SET first_response_at = ? WHERE ticket_id = ?", (ts, ticket_id))
        if a["role"] in rules.EXTERNAL_ROLES and row["state"] == rules.ON_HOLD:
            resume = {"state": rules.IN_PROGRESS, **_hold_resume_sets(row, ts, edition)}
            conn.execute(f"UPDATE tickets SET {', '.join(f'{k} = ?' for k in resume)} "
                         f"WHERE ticket_id = ?", (*resume.values(), ticket_id))
            _event(conn, ticket_id, "system", "state_change", rules.ON_HOLD, rules.IN_PROGRESS,
                   reason=f"{a['role']} replied", at=ts)
        _touch(conn, ticket_id, a["id"])
        touched.add(ticket_id)
        msg = dict(conn.execute("SELECT * FROM ticket_messages WHERE message_id = ?", (mid,)).fetchone())
        out = _row(conn, ticket_id)
    _emit("message", out, actor, edition=edition, message=msg)
    return msg


def set_message_delivery(db_path: str, message_id: int, status: str,
                         provider_msg_id: str | None = None) -> None:
    """Record what the SMS/email provider said about an outgoing message."""
    conn = get_connection(db_path)
    try:
        conn.execute("UPDATE ticket_messages SET delivery_status = ?, "
                     "provider_msg_id = COALESCE(?, provider_msg_id) WHERE message_id = ?",
                     (status, provider_msg_id, message_id))
        r = conn.execute("SELECT ticket_id FROM ticket_messages WHERE message_id = ?",
                         (message_id,)).fetchone()
        if r:
            import desk_files
            desk_files.write_ticket_json(root_for(db_path), conn, r["ticket_id"])
    finally:
        conn.close()


def add_attachment(db_path: str, ticket_id: str, info: dict, *, actor=None,
                   edition: str = rules.BUSINESS, message_id: int | None = None,
                   visibility: str = "public") -> dict:
    """Record a file already saved into the ticket's attachments folder by
    desk_files.store_attachment(). Outside parties always add public files."""
    a = rules.normalize_actor(actor)
    if a["role"] in rules.EXTERNAL_ROLES:
        visibility = "public"
    if visibility not in ("public", "internal"):
        raise DeskError("visibility must be 'public' or 'internal'")
    with ticket_transaction(db_path) as (conn, touched):
        row = _load_visible(conn, ticket_id, actor, edition)
        _check(rules.can(actor, "attach", row, edition=edition))
        ts = utcnow_iso()
        cur = conn.execute(
            "INSERT INTO ticket_attachments (ticket_id, message_id, kind, filename, path, thumb_path, "
            "mime, bytes, sha256, taken_at, uploaded_by, visibility, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ticket_id, message_id, info["kind"], info["filename"], info["path"],
             info.get("thumb_path"), info.get("mime"), info.get("bytes"), info.get("sha256"),
             info.get("taken_at"), a["id"], visibility, ts))
        aid = cur.lastrowid
        _event(conn, ticket_id, a["id"], "attachment_added", to_value=info["filename"], at=ts)
        _touch(conn, ticket_id, a["id"])
        touched.add(ticket_id)
        return dict(conn.execute("SELECT * FROM ticket_attachments WHERE attachment_id = ?",
                                 (aid,)).fetchone())


def get_attachment(db_path: str, attachment_id: int, *, actor=None,
                   edition: str = rules.BUSINESS) -> tuple[dict, Path]:
    """The attachment record and its absolute path, if the actor may see it."""
    import desk_files
    conn = get_connection(db_path)
    try:
        r = conn.execute("SELECT * FROM ticket_attachments WHERE attachment_id = ?",
                         (attachment_id,)).fetchone()
        if r is None:
            raise NotFoundError("no such attachment")
        att = dict(r)
        row = _load_visible(conn, att["ticket_id"], actor, edition)
    finally:
        conn.close()
    if rules.is_external(actor) and att["visibility"] != "public":
        raise NotFoundError("no such attachment")
    return att, desk_files.ticket_folder(root_for(db_path), row) / att["path"]


# ── Lists and live updates ───────────────────────────────────────────────────

OPEN_STATES = tuple(s for s in rules.STATES if s != rules.CLOSED)


def list_tickets(db_path: str, *, actor=None, edition: str = rules.BUSINESS,
                 state: str | None = None, open_only: bool = False, assignee: str | None = None,
                 queue_id: str | None = None, kind: str | None = None,
                 customer_id: str | None = None, contact_id: str | None = None,
                 priority: str | None = None, overdue: bool = False, text: str | None = None,
                 now: str | None = None, limit: int = 200) -> list[dict]:
    """Tickets the actor may see, newest change first, after the filters."""
    where, args = [], []
    for col, val in (("state", state), ("assignee", assignee), ("queue_id", queue_id),
                     ("kind", kind), ("customer_id", customer_id), ("contact_id", contact_id),
                     ("priority", priority)):
        if val:
            where.append(f"{col} = ?")
            args.append(val)
    if open_only:
        where.append(f"state IN ({', '.join('?' for _ in OPEN_STATES)})")
        args.extend(OPEN_STATES)
    if overdue:
        where.append("due_resolve_at IS NOT NULL AND due_resolve_at < ? AND state NOT IN ('Fixed', 'Closed')")
        args.append(now or utcnow_iso())
    if text:
        where.append("(title LIKE ? OR description LIKE ? OR ticket_id LIKE ?)")
        like = f"%{text}%"
        args.extend([like, like, like])
    sql = "SELECT * FROM tickets" + (" WHERE " + " AND ".join(where) if where else "") + \
          " ORDER BY last_edited_at DESC"
    conn = get_connection(db_path)
    try:
        rows = [dict(r) for r in conn.execute(sql, args)]
    finally:
        conn.close()
    seen = [r for r in rows if rules.can(actor, "view", r, edition=edition)]
    return seen[:max(1, int(limit))]


def my_tickets(db_path: str, *, actor=None, edition: str = rules.BUSINESS) -> list[dict]:
    """Open tickets assigned to the actor, soonest due first (undated last)."""
    me = _actor_id(actor)
    rows = list_tickets(db_path, actor=actor, edition=edition, assignee=me, open_only=True,
                        limit=1000)
    return sorted(rows, key=lambda r: (r["due_resolve_at"] is None, r["due_resolve_at"] or "",
                                       r["priority"], r["created_at"]))


def current_cursor(db_path: str) -> str:
    """The newest change time across all tickets — where live updates start."""
    conn = get_connection(db_path)
    try:
        return (conn.execute("SELECT MAX(last_edited_at) FROM tickets").fetchone() or [""])[0] or ""
    finally:
        conn.close()


def get_ticket_updates(db_path: str, since: str = "", *, actor=None,
                       edition: str = rules.BUSINESS, limit: int = 500) -> dict:
    """Tickets changed after `since` (an ISO timestamp cursor) that the actor
    may see, oldest first, plus the cursor to pass next time."""
    conn = get_connection(db_path)
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM tickets WHERE last_edited_at > ? ORDER BY last_edited_at",
            (since or "",))]
    finally:
        conn.close()
    cursor = rows[-1]["last_edited_at"] if rows else (since or "")
    seen = [r for r in rows if rules.can(actor, "view", r, edition=edition)]
    return {"tickets": seen[:limit], "cursor": cursor}
