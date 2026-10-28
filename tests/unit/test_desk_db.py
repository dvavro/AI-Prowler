"""Service Desk Phase 0 — desk_db + desk_files: schema, lifecycle writes,
ticket.json kept in step with SQLite, stale-row protection, verify, rebuild."""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import desk_db  # noqa: E402
import desk_files  # noqa: E402
import desk_rules as r  # noqa: E402

CUST = {"id": "c1", "role": "customer", "contact_id": "C-1"}
OWNER_S = {"id": "dave", "role": "owner"}
MANAGER = {"id": "mgr", "role": "manager", "queues": ["field"]}
CREW = {"id": "cris", "role": "field_crew"}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(path)
    desk_db.json_write_failures.clear()
    return path


def _json(db_path, ticket):
    return json.loads((desk_files.ticket_folder(desk_db.root_for(db_path), ticket)
                       / "ticket.json").read_text(encoding="utf-8"))


def _remove_db(db_path):
    for suffix in ("", "-wal", "-shm"):
        p = Path(db_path + suffix)
        if p.exists():
            p.unlink()


# ── schema ───────────────────────────────────────────────────────────────────

def test_init_is_idempotent_and_records_schema_version(db):
    desk_db.init_db(db)
    desk_db.init_db(db)
    con = sqlite3.connect(db)
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        ver = con.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]
    finally:
        con.close()
    assert {"tickets", "ticket_events", "ticket_messages", "ticket_attachments", "queues",
            "ticket_types", "assignment_rules", "customer_contacts"} <= tables
    assert ver == str(desk_db.SCHEMA_VERSION)


def test_state_check_constraint_rejects_unknown_state(db):
    con = sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            con.execute("INSERT INTO tickets (title, kind, state, filed_by, created_at, "
                        "last_edited_at, last_edited_by) VALUES ('x', 'external', 'Done', 'a', "
                        "'t', 't', 'a')")
    finally:
        con.close()


def test_default_paths_follow_test_state_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    assert desk_db.default_db_path() == str(tmp_path / "tickets_database" / "ai_prowler_tickets.db")


# ── Solo edition ─────────────────────────────────────────────────────────────

def test_solo_customer_ticket_goes_straight_to_owner(db):
    t = desk_db.create_ticket(db, title="Streaks on front windows", actor=CUST, edition=r.SOLO)
    assert t["ticket_id"] == "T-0001"
    assert t["state"] == r.ASSIGNED and t["assignee"] == "owner"
    assert t["contact_id"] == "C-1" and t["filed_by"] == "c1"
    doc = _json(db, t)
    assert doc["rev"] == 1 and doc["state"] == r.ASSIGNED
    assert [(h["from"], h["to"]) for h in doc["state_history"]] == [(None, r.OPEN), (r.OPEN, r.ASSIGNED)]
    assert (desk_files.ticket_folder(desk_db.root_for(db), t) / "attachments").is_dir()


def test_solo_own_ticket_goes_to_owner(db):
    t = desk_db.create_ticket(db, title="Truck tire low", kind="internal", edition=r.SOLO)
    assert t["kind"] == "internal" and t["assignee"] == "owner" and t["state"] == r.ASSIGNED


def test_solo_own_tickets_switched_off_writes_nothing(db):
    desk_db.set_setting(db, "own_tickets", False, edition=r.SOLO)
    with pytest.raises(desk_db.DeskError, match="switched off"):
        desk_db.create_ticket(db, title="Truck tire low", kind="internal", edition=r.SOLO)
    assert desk_db.get_ticket(db, "T-0001") is None
    assert list(desk_files.iter_ticket_json_files(desk_db.root_for(db))) == []


def test_owner_files_for_a_caller_needs_the_customer(db):
    with pytest.raises(desk_db.DeskError, match="needs the customer"):
        desk_db.create_ticket(db, title="Called about gutters", edition=r.SOLO)
    t = desk_db.create_ticket(db, title="Called about gutters", edition=r.SOLO,
                              customer_id="CUST-0187", job_id="JOB-4092", source="claude")
    assert t["customer_id"] == "CUST-0187" and t["job_id"] == "JOB-4092"


def test_solo_full_cycle_customer_confirms(db):
    t = desk_db.create_ticket(db, title="Screen torn", actor=CUST, edition=r.SOLO)
    tid = t["ticket_id"]
    for to in (r.IN_PROGRESS, r.FIXED):
        t = desk_db.change_state(db, tid, to, edition=r.SOLO)
    assert t["fixed_at"]
    t = desk_db.change_state(db, tid, r.CLOSED, actor=CUST, edition=r.SOLO)
    assert t["state"] == r.CLOSED and t["close_reason"] == "confirmed by customer"
    doc = _json(db, t)
    assert doc["rev"] == t["version"] == 4
    assert doc["state_history"][-1]["by"] == "c1"
    assert desk_files.verify(db) == []


# ── Business edition ─────────────────────────────────────────────────────────

def test_business_unassigned_ticket_opens_then_assigns(db):
    t = desk_db.create_ticket(db, title="Pump leaking", kind="internal", actor=CREW,
                              queue_id="field")
    assert t["state"] == r.OPEN and t["assignee"] is None
    t = desk_db.assign_ticket(db, t["ticket_id"], "cris", actor=MANAGER)
    assert t["state"] == r.ASSIGNED and t["assignee"] == "cris"
    kinds = [e["kind"] for e in _json(db, t)["events"]]
    assert kinds == ["created", "assigned", "state_change"]


def test_crew_cannot_close_and_nothing_changes(db):
    t = desk_db.create_ticket(db, title="Pump leaking", kind="internal", actor=CREW,
                              assignee="cris")
    before = _json(db, t)
    with pytest.raises(desk_db.DeskError, match="manager or the owner"):
        desk_db.change_state(db, t["ticket_id"], r.CLOSED, actor=CREW, reason="done")
    assert desk_db.get_ticket(db, t["ticket_id"])["version"] == t["version"]
    assert _json(db, t) == before


def test_stale_version_is_rejected_not_overwritten(db):
    t = desk_db.create_ticket(db, title="Pump leaking", kind="internal", actor=OWNER_S,
                              assignee="cris", queue_id="field")
    v_loaded = t["version"]
    desk_db.change_state(db, t["ticket_id"], r.IN_PROGRESS, actor=CREW, expected_version=v_loaded)
    with pytest.raises(desk_db.StaleRowError, match="Reload"):
        desk_db.change_state(db, t["ticket_id"], r.ON_HOLD, actor=MANAGER,
                             reason="waiting on parts", expected_version=v_loaded)
    assert desk_db.get_ticket(db, t["ticket_id"])["state"] == r.IN_PROGRESS


def test_reopen_clears_closed_fields(db):
    t = desk_db.create_ticket(db, title="Gate", actor=OWNER_S, contact_id="C-9", assignee="dave")
    tid = t["ticket_id"]
    desk_db.change_state(db, tid, r.CLOSED, actor=OWNER_S, reason="customer cancelled")
    t = desk_db.change_state(db, tid, r.ASSIGNED, actor=OWNER_S, reason="customer called back")
    assert t["closed_at"] is None and t["close_reason"] is None


def test_ticket_numbers_increase(db):
    ids = [desk_db.create_ticket(db, title=f"t{i}", edition=r.SOLO, contact_id="C-1")["ticket_id"]
           for i in range(3)]
    assert ids == ["T-0001", "T-0002", "T-0003"]


# ── verify ───────────────────────────────────────────────────────────────────

def test_verify_finds_tampered_missing_and_orphan_files(db):
    a = desk_db.create_ticket(db, title="A", edition=r.SOLO, contact_id="C-1")
    b = desk_db.create_ticket(db, title="B", edition=r.SOLO, contact_id="C-1")
    root = desk_db.root_for(db)
    pa = desk_files.ticket_folder(root, a) / "ticket.json"
    doc = json.loads(pa.read_text(encoding="utf-8"))
    doc["state"] = r.CLOSED
    pa.write_text(json.dumps(doc), encoding="utf-8")
    (desk_files.ticket_folder(root, b) / "ticket.json").unlink()
    orphan = root / "tickets" / "2026" / "T-0099"
    orphan.mkdir(parents=True)
    (orphan / "ticket.json").write_text(json.dumps({"ticket_id": "T-0099"}), encoding="utf-8")
    problems = desk_files.verify(db)
    assert any("T-0001" in p and "state" in p for p in problems)
    assert any("T-0002" in p and "missing" in p for p in problems)
    assert any("T-0099" in p and "no database row" in p for p in problems)


def test_verify_checks_attachment_hashes(db):
    t = desk_db.create_ticket(db, title="Photo", edition=r.SOLO, contact_id="C-1")
    folder = desk_files.ticket_folder(desk_db.root_for(db), t)
    f = folder / "attachments" / "0001_photo.jpg"
    f.write_bytes(b"fake jpeg bytes")
    con = desk_db.get_connection(db)
    try:
        con.execute("INSERT INTO ticket_attachments (ticket_id, kind, filename, path, sha256, "
                    "uploaded_by, created_at) VALUES (?, 'photo', '0001_photo.jpg', "
                    "'attachments/0001_photo.jpg', ?, 'c1', 't')",
                    (t["ticket_id"], desk_files.sha256_file(f)))
    finally:
        con.close()
    assert desk_files.verify(db) == []
    f.write_bytes(b"changed")
    assert any("hash does not match" in p for p in desk_files.verify(db))


# ── rebuild and number safety after losing the database ──────────────────────

def test_rebuild_from_files_restores_lost_database(db):
    a = desk_db.create_ticket(db, title="A", actor=CUST, edition=r.SOLO)
    desk_db.change_state(db, a["ticket_id"], r.IN_PROGRESS, edition=r.SOLO)
    desk_db.create_ticket(db, title="B", actor=CUST, edition=r.SOLO)
    _remove_db(db)

    dry = desk_files.rebuild_from_files(db, dry_run=True)
    assert dry["restored"] == ["T-0001", "T-0002"] and dry["errors"] == []
    assert desk_db.get_ticket(db, "T-0001") is None

    real = desk_files.rebuild_from_files(db, dry_run=False)
    assert real["restored"] == ["T-0001", "T-0002"] and real["errors"] == []
    t = desk_db.get_ticket(db, "T-0001")
    assert t["state"] == r.IN_PROGRESS and t["version"] == 2
    assert desk_files.verify(db) == []

    again = desk_files.rebuild_from_files(db, dry_run=False)
    assert again["restored"] == [] and again["skipped_existing"] == ["T-0001", "T-0002"]

    c = desk_db.create_ticket(db, title="C", actor=CUST, edition=r.SOLO)
    assert c["ticket_id"] == "T-0003"


def test_fresh_database_never_reuses_a_folder_number(db):
    for i in range(3):
        desk_db.create_ticket(db, title=f"t{i}", actor=CUST, edition=r.SOLO)
    _remove_db(db)
    desk_db.init_db(db)                                   # no rebuild, just a new empty db
    t = desk_db.create_ticket(db, title="new", actor=CUST, edition=r.SOLO)
    assert t["ticket_id"] == "T-0004"
    old = desk_files.ticket_folder(desk_db.root_for(db),
                                   {"ticket_id": "T-0001", "folder": f"tickets/{t['created_at'][:4]}/T-0001"})
    assert json.loads((old / "ticket.json").read_text(encoding="utf-8"))["title"] == "t0"


def test_json_write_failure_is_reported_but_commit_stands(db, monkeypatch):
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(desk_files, "write_ticket_json", boom)
    t = desk_db.create_ticket(db, title="A", actor=CUST, edition=r.SOLO)
    assert desk_db.get_ticket(db, t["ticket_id"]) is not None
    monkeypatch.undo()
    problems = desk_files.verify(db)
    assert any("disk full" in p for p in problems)
