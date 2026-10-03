"""
db_access.py — Job Board Architecture Spec, Phase 0.

Thin data-access module providing the connect/transaction/row-fetch
primitives every MCP write/read tool will use once ported off openpyxl
(spec §4.1, §4.2, §5). This is the one new piece of shared
infrastructure everything else in the redesign builds on — keep it
small and boring.

Key properties (spec §4.1):
- WAL journal mode: readers never block writers and vice versa. This is
  what lets the admin leave the Job Board open all day with zero impact
  on crew writes (spec §2 goal 1, §6.1).
- Real transactions scoped to the rows touched — no more whole-file
  load/mutate/save cycle, no more _spreadsheet_write_lock.
- foreign_keys=ON every connection, so FK constraints (spec §4.2,
  Phase 0 testing requirement) are actually enforced.

Usage:
    from db_access import get_connection, transaction, init_db

    init_db(db_path)  # once at startup — idempotent

    with transaction(db_path) as conn:
        conn.execute("UPDATE jobs SET job_status = ? WHERE job_id = ?",
                     (status, job_id))
        # commits on clean exit, rolls back on exception
"""

import contextlib
import datetime
import json
import sqlite3

from db_schema import apply_schema

DEFAULT_DB_FILENAME = "ai_prowler_jobs.db"

# 2026-09-16: the live database lives in its own subfolder under
# AI-Prowler's state dir (~/.ai-prowler/jobs_database/), not loose
# alongside config.json/logs/scheduler state — both backup mechanisms
# (_backup_job_db's automatic per-write safety net, and
# db_backup_database's manual/scheduled "Backup Now") already compute
# their own folder relative to wherever the live db file sits, so this
# one change nests both of them inside jobs_database/ too, with no
# further code needed for that part.
DEFAULT_DB_SUBDIR = "jobs_database"


def utcnow_iso() -> str:
    """ISO-8601 UTC timestamp string, used for last_edited_at everywhere.

    Millisecond precision (2026-10-02, E2E BRD-06): with whole seconds, the Job
    Board's `last_edited_at > since` poll silently skipped any change made in the
    SAME second as the newest change it had already seen — e.g. a crew member
    tapping In Progress right after a job was created never showed up on the
    office's board until that job changed again. Old whole-second values still
    compare correctly as text: "…:05+00:00" sorts before "…:05.123+00:00"
    ('+' < '.'), so existing rows and saved cursors keep working.
    """
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def get_connection(db_path: str) -> sqlite3.Connection:
    """Open a connection configured the way every caller needs it.

    WAL mode + foreign_keys=ON + Row factory for dict-like access.
    A short busy_timeout is set so a genuinely concurrent writer to the
    SAME row waits briefly instead of raising immediately — different
    rows never contend under WAL, so this only matters for same-row
    same-instant writes.
    """
    conn = sqlite3.connect(db_path, timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db(db_path: str) -> None:
    """Create the schema if it doesn't exist yet. Idempotent — safe to
    call on every process startup (Phase 0 testing requirement, §11)."""
    conn = get_connection(db_path)
    try:
        apply_schema(conn)
    finally:
        conn.close()


@contextlib.contextmanager
def transaction(db_path: str):
    """Context manager yielding a connection wrapped in a single
    transaction: BEGIN IMMEDIATE on entry, COMMIT on clean exit,
    ROLLBACK on exception. BEGIN IMMEDIATE (rather than plain BEGIN)
    takes the write lock up front, which avoids the "database is
    locked" surprise on upgrade from a deferred read transaction.

    Callers own row-level SQL (SELECT/UPDATE/INSERT) inside the `with`
    block; this function owns only the lifecycle, so it stays reusable
    across every tool without needing to know each tool's queries.
    """
    conn = get_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def touch_row(conn: sqlite3.Connection, table: str, id_column: str, id_value: str,
              actor: str) -> None:
    """Bump `version` and stamp `last_edited_by`/`last_edited_at` on a
    row. Call this as part of the same transaction as the field update
    it belongs to (spec §4.2 row-versioning; §6.2 conflict UX depends
    on `version` actually incrementing on every write).
    """
    conn.execute(
        f"UPDATE {table} SET version = version + 1, last_edited_by = ?, "
        f"last_edited_at = ? WHERE {id_column} = ?",
        (actor, utcnow_iso(), id_value),
    )


# ── users.json importer ────────────────────────────────────────────────

def _split_name(record: dict):
    """Best-effort first/last name extraction from a users.json record
    that may use either separate fields or a single 'name' field."""
    first = record.get("first_name") or record.get("firstName")
    last = record.get("last_name") or record.get("lastName")
    if first or last:
        return first, last
    full = record.get("name") or record.get("display_name") or ""
    parts = full.strip().split(" ", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return (parts[0] if parts and parts[0] else None), None


# Fields modeled as real columns; anything else in a record is preserved
# verbatim in extra_json so the importer never silently drops data.
_KNOWN_USER_FIELDS = {
    "id", "user_id", "username", "email", "phone", "cell_phone",
    "first_name", "firstName", "last_name", "lastName", "name",
    "display_name", "role", "scopes", "home_address",
    "private_collection_enabled", "created_at", "updated_at",
}


def import_users_json(db_path: str, users_json_path: str, actor: str = "migration") -> int:
    """One-time importer: users.json -> users table (spec §4.2, Phase 0
    deliverable). Round-trips every field — known fields land in real
    columns, anything else is preserved in extra_json.

    Accepts either a JSON list of user records, or a dict keyed by user
    id/username (both formats have existed across AI-Prowler versions).
    Upsert semantics: safe to re-run (e.g. after users.json changes).

    Returns the number of users imported/updated.
    """
    with open(users_json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if isinstance(raw, dict):
        records = []
        for key, val in raw.items():
            if isinstance(val, dict):
                val = dict(val)
                val.setdefault("id", key)
                records.append(val)
    elif isinstance(raw, list):
        records = raw
    else:
        raise ValueError(f"Unrecognized users.json shape: {type(raw)}")

    now = utcnow_iso()
    count = 0
    with transaction(db_path) as conn:
        for record in records:
            user_id = str(record.get("id") or record.get("user_id") or record.get("username") or record.get("email"))
            if not user_id or user_id == "None":
                continue
            first, last = _split_name(record)
            extra = {k: v for k, v in record.items() if k not in _KNOWN_USER_FIELDS}
            conn.execute(
                """
                INSERT INTO users (id, email, phone, first_name, last_name, display_name,
                                    role, scopes_json, home_address,
                                    private_collection_enabled, extra_json,
                                    created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    email = excluded.email,
                    phone = excluded.phone,
                    first_name = excluded.first_name,
                    last_name = excluded.last_name,
                    display_name = excluded.display_name,
                    role = excluded.role,
                    scopes_json = excluded.scopes_json,
                    home_address = excluded.home_address,
                    private_collection_enabled = excluded.private_collection_enabled,
                    extra_json = excluded.extra_json,
                    updated_at = excluded.updated_at
                """,
                (
                    user_id,
                    record.get("email"),
                    record.get("phone") or record.get("cell_phone"),
                    first,
                    last,
                    record.get("display_name") or record.get("name"),
                    record.get("role"),
                    json.dumps(record.get("scopes")) if record.get("scopes") is not None else None,
                    record.get("home_address"),
                    int(bool(record.get("private_collection_enabled"))) if "private_collection_enabled" in record else None,
                    json.dumps(extra) if extra else None,
                    record.get("created_at") or now,
                    now,
                ),
            )
            count += 1
    return count
