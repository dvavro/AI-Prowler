"""
desk_files.py — AI-Prowler Service Desk, Phase 0.

Per-ticket folders and the ticket.json state file.

    <root>/                       (~/.ai-prowler/tickets_database)
      ai_prowler_tickets.db
      tickets/<YYYY>/<T-####>/
        ticket.json               complete, human-readable copy of one ticket
        attachments/              photos, documents, videos (Phase 1)

SQLite is the record; ticket.json is rewritten atomically (temp file +
os.replace, via safe_save) after every committed change, so a reader never
sees half a file. verify() checks the two agree and every attachment is
present with the right hash; rebuild_from_files() re-creates missing ticket
rows from the files if the database is ever lost.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from safe_save import atomic_write_json, read_json_retry

JSON_SCHEMA_VERSION = 1
TICKET_JSON = "ticket.json"
ATTACHMENTS_DIR = "attachments"

# tickets columns copied 1:1 into ticket.json (everything except internals)
_TICKET_FIELDS = (
    "ticket_id", "title", "description", "kind", "type", "priority", "state", "queue_id",
    "assignee", "filed_by", "contact_id", "customer_id", "job_id", "source", "visibility",
    "sms_fallback", "fixed_at", "closed_at", "close_reason", "csat_score", "csat_comment", "folder",
    "created_at", "last_edited_at", "last_edited_by", "hold_started_at", "sla_flags",
    "resolution",
)
_SLA_FIELDS = ("due_response_at", "due_resolve_at", "first_response_at")


def ticket_folder(root, ticket_row: dict) -> Path:
    """Absolute folder for a ticket, from its stored relative `folder`."""
    rel = ticket_row.get("folder") or f"tickets/{(ticket_row.get('created_at') or '0000')[:4]}/{ticket_row['ticket_id']}"
    return Path(root) / Path(rel)


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_ticket_json(conn: sqlite3.Connection, ticket_id: str) -> dict:
    """The full ticket.json document for one ticket, read from SQLite."""
    t = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
    if t is None:
        raise KeyError(ticket_id)
    t = dict(t)
    doc = {"schema_version": JSON_SCHEMA_VERSION}
    doc.update({k: t.get(k) for k in _TICKET_FIELDS})
    doc["sla"] = {k: t.get(k) for k in _SLA_FIELDS}
    events = [dict(r) for r in conn.execute(
        "SELECT event_id, at, actor, approved_by, kind, from_value, to_value, reason "
        "FROM ticket_events WHERE ticket_id = ? ORDER BY event_id", (ticket_id,))]
    doc["state_history"] = [
        {"at": e["at"], "from": e["from_value"], "to": e["to_value"], "by": e["actor"],
         **({"reason": e["reason"]} if e["reason"] else {}),
         **({"approved_by": e["approved_by"]} if e["approved_by"] else {})}
        for e in events if e["kind"] in ("created", "state_change")
    ]
    doc["events"] = events
    msgs = [dict(r) for r in conn.execute(
        "SELECT message_id, at, author, author_kind, visibility, channel, body, "
        "delivery_status FROM ticket_messages WHERE ticket_id = ? ORDER BY message_id",
        (ticket_id,))]
    atts = [dict(r) for r in conn.execute(
        "SELECT attachment_id, message_id, kind, filename, path, thumb_path, mime, bytes, "
        "sha256, taken_at, uploaded_by, visibility, created_at FROM ticket_attachments "
        "WHERE ticket_id = ? ORDER BY attachment_id", (ticket_id,))]
    by_msg: dict = {}
    for a in atts:
        if a["message_id"] is not None:
            by_msg.setdefault(a["message_id"], []).append(a["attachment_id"])
    for m in msgs:
        m["attachments"] = by_msg.get(m["message_id"], [])
    doc["messages"] = msgs
    doc["attachments"] = atts
    doc["relations"] = [dict(r) for r in conn.execute(
        "SELECT kind, target, created_at, created_by FROM ticket_relations WHERE ticket_id = ? "
        "ORDER BY created_at", (ticket_id,))]
    doc["updated_at"] = t.get("last_edited_at")
    doc["rev"] = t.get("version")
    return doc


def write_ticket_json(root, conn: sqlite3.Connection, ticket_id: str) -> Path:
    """Rewrite one ticket's ticket.json atomically. Returns its path."""
    doc = build_ticket_json(conn, ticket_id)
    folder = ticket_folder(root, doc)
    (folder / ATTACHMENTS_DIR).mkdir(parents=True, exist_ok=True)
    path = folder / TICKET_JSON
    atomic_write_json(path, doc, indent=2, ensure_ascii=False, newline="\n")
    return path


def read_ticket_json(path) -> dict:
    return read_json_retry(path)


def max_ticket_number(root) -> int:
    """Highest T-#### number that has a folder on disk (0 if none). Used to
    seed a fresh database so it never reissues a number whose folder exists."""
    base = Path(root) / "tickets"
    best = 0
    if base.exists():
        for d in base.glob("*/T-*"):
            try:
                best = max(best, int(d.name.split("-", 1)[1]))
            except (ValueError, IndexError):
                continue
    return best


def iter_ticket_json_files(root):
    base = Path(root) / "tickets"
    if not base.exists():
        return
    yield from sorted(base.glob(f"*/T-*/{TICKET_JSON}"))


def verify(db_path: str) -> list[str]:
    """Compare SQLite, every ticket.json and every attachment. Returns a list
    of human-readable problems; empty means everything agrees."""
    from desk_db import get_connection, json_write_failures, root_for
    root = root_for(db_path)
    problems: list[str] = []
    conn = get_connection(db_path)
    try:
        rows = {r["ticket_id"]: dict(r) for r in conn.execute("SELECT * FROM tickets")}
        for tid, row in rows.items():
            path = ticket_folder(root, row) / TICKET_JSON
            if not path.exists():
                problems.append(f"{tid}: ticket.json missing ({path})")
                continue
            try:
                doc = read_ticket_json(path)
            except Exception as e:  # noqa: BLE001
                problems.append(f"{tid}: ticket.json unreadable ({e})")
                continue
            if doc.get("rev") != row["version"]:
                problems.append(f"{tid}: ticket.json rev {doc.get('rev')} != database version {row['version']}")
            if doc.get("state") != row["state"]:
                problems.append(f"{tid}: ticket.json state {doc.get('state')!r} != database {row['state']!r}")
            for a in conn.execute("SELECT * FROM ticket_attachments WHERE ticket_id = ?", (tid,)):
                f = ticket_folder(root, row) / a["path"]
                if not f.exists():
                    problems.append(f"{tid}: attachment {a['filename']} missing ({f})")
                elif a["sha256"] and sha256_file(f) != a["sha256"]:
                    problems.append(f"{tid}: attachment {a['filename']} hash does not match")
        for path in iter_ticket_json_files(root):
            tid = path.parent.name
            if tid not in rows:
                problems.append(f"{tid}: ticket.json has no database row ({path})")
        for tid, err in json_write_failures.items():
            problems.append(f"{tid}: last ticket.json write failed ({err})")
    finally:
        conn.close()
    return problems


def rebuild_from_files(db_path: str, *, dry_run: bool = True) -> dict:
    """Re-create database rows for every ticket.json whose ticket is missing
    from the database (e.g. the .db was lost and a fresh one created).
    Existing rows are never overwritten. Returns a summary dict."""
    from desk_db import get_connection, init_db, root_for
    init_db(db_path)
    root = root_for(db_path)
    conn = get_connection(db_path)
    summary = {"found": 0, "restored": [], "skipped_existing": [], "errors": [], "dry_run": dry_run}
    try:
        existing = {r[0] for r in conn.execute("SELECT ticket_id FROM tickets")}
        for path in iter_ticket_json_files(root):
            summary["found"] += 1
            try:
                doc = read_ticket_json(path)
                tid = doc["ticket_id"]
            except Exception as e:  # noqa: BLE001
                summary["errors"].append(f"{path}: {e}")
                continue
            if tid in existing:
                summary["skipped_existing"].append(tid)
                continue
            if dry_run:
                summary["restored"].append(tid)
                continue
            try:
                _insert_from_doc(conn, doc)
                summary["restored"].append(tid)
            except Exception as e:  # noqa: BLE001
                summary["errors"].append(f"{tid}: {e}")
    finally:
        conn.close()
    return summary


def _insert_from_doc(conn: sqlite3.Connection, doc: dict) -> None:
    tid = doc["ticket_id"]
    row_id = int(tid.split("-", 1)[1])
    sla = doc.get("sla") or {}
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT INTO tickets (row_id, ticket_id, title, description, kind, type, priority, "
            "state, queue_id, assignee, filed_by, contact_id, customer_id, job_id, source, "
            "visibility, sms_fallback, due_response_at, due_resolve_at, first_response_at, "
            "fixed_at, closed_at, close_reason, csat_score, csat_comment, folder, created_at, "
            "version, last_edited_at, last_edited_by, hold_started_at, sla_flags, resolution) VALUES "
            "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (row_id, tid, doc["title"], doc.get("description") or "", doc["kind"],
             doc.get("type") or "", doc.get("priority") or "P3", doc["state"],
             doc.get("queue_id"), doc.get("assignee"), doc.get("filed_by") or "unknown",
             doc.get("contact_id"), doc.get("customer_id"), doc.get("job_id"),
             doc.get("source") or "pwa", doc.get("visibility") or "normal",
             int(doc.get("sms_fallback") or 0), sla.get("due_response_at"), sla.get("due_resolve_at"), sla.get("first_response_at"),
             doc.get("fixed_at"), doc.get("closed_at"), doc.get("close_reason"),
             doc.get("csat_score"), doc.get("csat_comment"), doc.get("folder"),
             doc.get("created_at"), doc.get("rev") or 1, doc.get("last_edited_at"),
             doc.get("last_edited_by") or "rebuild", doc.get("hold_started_at"),
             doc.get("sla_flags") or "", doc.get("resolution")))
        for rel in doc.get("relations") or []:
            conn.execute("INSERT OR IGNORE INTO ticket_relations (ticket_id, kind, target, created_at, "
                         "created_by) VALUES (?, ?, ?, ?, ?)",
                         (tid, rel["kind"], rel["target"], rel.get("created_at") or doc.get("created_at"),
                          rel.get("created_by") or "rebuild"))
        # Event, message and attachment ids are global counters, so a partial
        # rebuild must not reuse the old numbers: insert with fresh ids and map
        # each old message id to its new one for the attachments that point at it.
        for e in doc.get("events") or []:
            conn.execute(
                "INSERT INTO ticket_events (ticket_id, at, actor, approved_by, kind, "
                "from_value, to_value, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (tid, e["at"], e["actor"], e.get("approved_by"), e["kind"],
                 e.get("from_value"), e.get("to_value"), e.get("reason")))
        msg_map = {}
        for m in doc.get("messages") or []:
            cur = conn.execute(
                "INSERT INTO ticket_messages (ticket_id, at, author, author_kind, "
                "visibility, channel, body, delivery_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (tid, m["at"], m["author"], m["author_kind"], m["visibility"],
                 m.get("channel") or "pwa", m["body"], m.get("delivery_status")))
            msg_map[m.get("message_id")] = cur.lastrowid
        for a in doc.get("attachments") or []:
            conn.execute(
                "INSERT INTO ticket_attachments (ticket_id, message_id, kind, filename, path, "
                "thumb_path, mime, bytes, sha256, taken_at, uploaded_by, visibility, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (tid, msg_map.get(a.get("message_id")), a["kind"], a["filename"], a["path"],
                 a.get("thumb_path"), a.get("mime"), a.get("bytes"), a.get("sha256"),
                 a.get("taken_at"), a["uploaded_by"], a.get("visibility") or "public",
                 a.get("created_at") or doc.get("created_at")))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def dumps_for_display(doc: dict) -> str:
    """Pretty JSON for showing a ticket.json in chat or a log."""
    return json.dumps(doc, indent=2, ensure_ascii=False)
